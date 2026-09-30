//! Retained file-less win32k source IRPs dispatched to an exact canonical Device.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_io_manager::win32k_source_irp_ioctl_wire as wire;
use nt_kernel_exec::{EventLeaseId, EventLeaseKind, EventObjectId, EventSignalMode};

type Route = nt_component_suspension::peer_registry::PeerRoute;
type Identity = (Route, u64, u64);

enum Target {
    None,
    Stack { va: u64, alias: u64, len: u64 },
    Stable(crate::win32k_subsystem::file_ioctl_target::RootIoctlOutputTarget),
}

impl Target {
    unsafe fn capture(route: Route, va: u64, len: u64) -> Option<Self> {
        if len == 0 {
            return Some(Self::None);
        }
        if let Some(alias) = crate::win32k_glue::win32k_stack_alias_for_route(route, va, len) {
            return Some(Self::Stack { va, alias, len });
        }
        crate::win32k_subsystem::file_ioctl_target::capture_root_output(va, len)
            .map(Self::Stable)
    }

    unsafe fn address_if_live(&self, route: Route) -> Option<u64> {
        match self {
            Self::None => Some(0),
            Self::Stack { va, alias, len } => {
                (crate::win32k_glue::win32k_stack_alias_for_route(route, *va, *len)
                    == Some(*alias))
                    .then_some(*alias)
            }
            Self::Stable(target) => target.is_live().then(|| target.address()),
        }
    }
}

struct CanonicalEvent {
    id: EventObjectId,
    lease: EventLeaseId,
    local: u64,
    provider: nt_provider_wait::ProviderDomainIdentity,
}

struct Work {
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    source_address: u64,
    source: crate::win32k_subsystem::SourceBufferedDispatchLease,
    target: HostedForwardTarget,
    event: Option<CanonicalEvent>,
    packet_lease: crate::win32k_subsystem::ProviderPoolPacketLease,
    packet: Vec<u8>,
    output: Vec<u8>,
    output_target: Target,
    iosb_target: Target,
    irp: Option<IrpId>,
    entered: bool,
    packet_prepared: bool,
    reply_entered: bool,
    reply_acked: bool,
    pending: bool,
    terminal: Option<(u32, u64)>,
    output_captured: bool,
    terminal_claimed: bool,
    terminal_published: bool,
    event_claimed: bool,
    event_signaled: bool,
    ack_claimed: bool,
    cancel_requested: bool,
    cancel_ack_claimed: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static mut ACTIVE: Vec<Identity> = Vec::new();
static mut COMPLETED: Vec<Identity> = Vec::new();
struct CompletionWait {
    identity: Identity,
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    wait_token: u64,
    reply_entered: bool,
    cancelled: bool,
}
static mut COMPLETION_WAITS: Vec<CompletionWait> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static NEXT_WAIT_TOKEN: AtomicU64 = AtomicU64::new(1);
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn wire_status(error: wire::WireError) -> i32 {
    match error {
        wire::WireError::BufferTooSmall | wire::WireError::LengthMismatch =>
            STATUS_INVALID_BUFFER_SIZE as i32,
        wire::WireError::Malformed => STATUS_INVALID_PARAMETER,
    }
}

unsafe fn release_event(handler: *mut ExecNtHandler, event: CanonicalEvent) {
    if let Some(retired) = (*handler)
        .event_objects
        .release_wait(event.lease, EventLeaseKind::Operation)
        .expect("source IOCTL Event operation lease")
    {
        (*handler).finalize_retired_event_object(retired);
    }
}

unsafe fn capture_event(
    handler: *mut ExecNtHandler,
    expected: Option<wire::EventIdentity>,
) -> Result<Option<CanonicalEvent>, i32> {
    let Some(expected) = expected else { return Ok(None) };
    let provider = crate::current_win32k_provider_domain().ok_or(STATUS_DEVICE_NOT_READY)?;
    let id = EventObjectId::from_wire_parts(
        expected.object_slot_plus_one,
        expected.object_generation,
    )
    .ok_or(STATUS_INVALID_PARAMETER)?;
    let (actual, _, _, _) = crate::provider_local_event::LocalEventState::new(
        &mut (*handler).obj_ns,
        &mut (*handler).anon_event_seq,
        &mut (*handler).events,
        &mut (*handler).event_objects,
    )
    .identity(provider, expected.local_id)
    .map_err(|status| status as i32)?;
    if actual != id {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let lease = (*handler)
        .event_objects
        .acquire_wait(id, EventLeaseKind::Operation)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    Ok(Some(CanonicalEvent {
        id,
        lease,
        local: expected.local_id,
        provider,
    }))
}

pub(crate) unsafe fn completion_for_token(
    channel: &crate::spawn_hosts::PumpChannel,
    token: u64,
    source: u64,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    if token == 0 || source == 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let Ok(Some(route)) = runtime::channel_route(channel) else {
        return Some(STATUS_INVALID_HANDLE);
    };
    let identity = (route, source, token);
    if (&*core::ptr::addr_of!(COMPLETED)).contains(&identity) {
        return Some(STATUS_SUCCESS);
    }
    if !(&*core::ptr::addr_of!(ACTIVE)).contains(&identity)
        || (&*core::ptr::addr_of!(COMPLETION_WAITS))
            .iter()
            .any(|wait| wait.identity == identity)
    {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    if (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS))
        .try_reserve(1)
        .is_err()
    {
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let wait_token = match NEXT_WAIT_TOKEN.fetch_update(
        Ordering::Relaxed,
        Ordering::Relaxed,
        |n| n.checked_add(1),
    ) {
        Ok(token) if token != 0 => token,
        _ => return Some(STATUS_INSUFFICIENT_RESOURCES),
    };
    if runtime::park_retained_service(route, wait_token).is_err() {
        return Some(STATUS_DEVICE_NOT_READY);
    }
    (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS)).push(CompletionWait {
        identity,
        route,
        dispatch,
        reply,
        wait_token,
        reply_entered: false,
        cancelled: false,
    });
    None
}

unsafe fn redrive_completion_waits() {
    let mut index = 0;
    while index < (&*core::ptr::addr_of!(COMPLETION_WAITS)).len() {
        let wait = &mut (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS))[index];
        if !wait.cancelled && runtime::retained_service_cancelled(
            wait.route, wait.dispatch, wait.reply, wait.wait_token,
        ) {
            runtime::acknowledge_retained_service_cancellation(
                wait.route, wait.dispatch, wait.reply, wait.wait_token,
            ).expect("source IOCTL completion wait cancellation");
            wait.cancelled = true;
        }
        if wait.cancelled {
            if let Some(completed) = (&*core::ptr::addr_of!(COMPLETED))
                .iter()
                .position(|identity| *identity == wait.identity)
            {
                (&mut *core::ptr::addr_of_mut!(COMPLETED)).swap_remove(completed);
                (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS)).swap_remove(index);
            } else {
                index += 1;
            }
            continue;
        }
        if !(&*core::ptr::addr_of!(COMPLETED)).contains(&wait.identity) {
            index += 1;
            continue;
        }
        if !wait.reply_entered {
            wait.reply_entered = true;
            let _ = runtime::wake_service(
                wait.route, wait.dispatch, wait.reply, wait.wait_token, STATUS_SUCCESS,
            );
        }
        let acknowledged = runtime::reconcile_retained_service_reply(
            wait.route, wait.dispatch, wait.reply, wait.wait_token,
        ).expect("source IOCTL completion wait Reply identity");
        if !acknowledged {
            index += 1;
            continue;
        }
        runtime::retire_stopped_acknowledged_retained_service(
            wait.route, wait.dispatch, wait.reply, wait.wait_token,
        ).expect("source IOCTL completion wait retirement");
        (&mut *core::ptr::addr_of_mut!(COMPLETION_WAITS)).swap_remove(index);
    }
}

pub(crate) unsafe fn release_token(
    channel: &crate::spawn_hosts::PumpChannel,
    token: u64,
    source: u64,
) -> i32 {
    let _durable = crate::allocator::enter_durable();
    if token == 0 || source == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Ok(Some(route)) = runtime::channel_route(channel) else {
        return STATUS_INVALID_HANDLE;
    };
    let identity = (route, source, token);
    // An admitted successor Call on this physical route proves the blocked completion Reply
    // was acknowledged and its lane resumed. An indeterminate Reply leaves the lane suspended.
    redrive_completion_waits();
    if (&*core::ptr::addr_of!(COMPLETION_WAITS))
        .iter()
        .any(|wait| wait.identity == identity)
    {
        return STATUS_PENDING as i32;
    }
    let Some(index) = (&*core::ptr::addr_of!(COMPLETED))
        .iter()
        .position(|row| *row == identity)
    else {
        return STATUS_INVALID_PARAMETER;
    };
    (&mut *core::ptr::addr_of_mut!(COMPLETED)).swap_remove(index);
    STATUS_SUCCESS
}

pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    packet_address: u64,
    packet_length: u64,
    provider_stack_pointer: u64,
    handler: *mut ExecNtHandler,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    if crate::win32k_glue::win32k_stack_alias_for_route(route, provider_stack_pointer, 1)
        .is_none()
    {
        return Some(STATUS_ACCESS_DENIED);
    }
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let Ok(length) = usize::try_from(packet_length) else {
        return Some(STATUS_INVALID_BUFFER_SIZE as i32);
    };
    let (packet_lease, packet) =
        match crate::win32k_subsystem::capture_provider_pool_packet(packet_address, length) {
            Ok(captured) => captured,
            Err(status) => return Some(status as i32),
        };
    let request = match wire::decode_request(&packet) {
        Ok(request) => request,
        Err(error) => return Some(wire_status(error)),
    };
    if (&*core::ptr::addr_of!(ACTIVE))
        .iter()
        .any(|(_, source, _)| *source == request.source_irp_va)
    {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let access = match crate::win32k_device_consumer::authenticate(
        channel,
        reply_cap,
        request.device_object_va,
    ) {
        Ok(access) if access.dispatch() == dispatch => access,
        Ok(_) => return Some(STATUS_ACCESS_DENIED),
        Err(status) => return Some(status),
    };
    let mut target = match HostedForwardTarget::capture(
        io_manager_mut(),
        access.domain(),
        access.address(),
    ) {
        Ok(target) if target.device_id() == access.device() => target,
        Ok(mut target) => {
            target.release(io_manager_mut()).expect("source IOCTL mismatched target");
            return Some(STATUS_INVALID_DEVICE_REQUEST as i32);
        }
        Err(status) => return Some(status.raw() as i32),
    };
    let mut event = match capture_event(handler, request.event) {
        Ok(event) => event,
        Err(status) => {
            target.release(io_manager_mut()).expect("unentered source IOCTL target");
            return Some(status);
        }
    };
    let source = match crate::win32k_subsystem::admit_source_buffered_ioctl_dispatch(
        request.source_irp_va,
        request.device_object_va,
        provider_stack_pointer,
    ) {
        Ok(source) => source,
        Err(status) => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered source IOCTL target");
            return Some(status);
        }
    };
    let matches = source.validate()
        && source.source_address() == request.source_irp_va
        && source.source_ticket_serial() == request.source_ticket_serial
        && source.source_native_generation() == request.native_allocation_generation
        && source.device == request.device_object_va
        && source.code == request.code
        && source.input.as_slice() == request.input
        && source.output_capacity == request.output_capacity
        && source.event == request.event
        && source.event.is_some() == source.event_body().is_some();
    let mut source = source;
    if !matches {
        if !crate::win32k_subsystem::abort_source_buffered_ioctl_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 0]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("mismatched source IOCTL target");
        return Some(STATUS_INVALID_PARAMETER);
    }
    let output_target = Target::capture(route, source.output_va, u64::from(source.output_capacity));
    let iosb_target = Target::capture(route, source.iosb_va, 16);
    let (Some(output_target), Some(iosb_target)) = (output_target, iosb_target) else {
        if !crate::win32k_subsystem::abort_source_buffered_ioctl_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 1]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered source IOCTL target");
        return Some(STATUS_INVALID_PARAMETER);
    };
    let mut output = Vec::new();
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
        });
    if output.try_reserve_exact(request.output_capacity as usize).is_err()
        || (slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err())
        || (&mut *core::ptr::addr_of_mut!(ACTIVE)).try_reserve(1).is_err()
        || (&mut *core::ptr::addr_of_mut!(COMPLETED)).try_reserve(1).is_err()
    {
        if !crate::win32k_subsystem::abort_source_buffered_ioctl_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 2]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered source IOCTL target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    output.resize(request.output_capacity as usize, 0);
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) {
        Ok(token) if token != 0 => token,
        _ => {
            if !crate::win32k_subsystem::abort_source_buffered_ioctl_dispatch(&mut source) {
                crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 3]);
            }
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered source IOCTL target");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let source_address = source.source_address();
    let work = Work {
        route, dispatch, reply, token, source_address, source, target, event,
        packet_lease, packet, output, output_target, iosb_target,
        irp: None, entered: false, packet_prepared: false,
        reply_entered: false, reply_acked: false,
        pending: false, terminal: None, output_captured: false,
        terminal_claimed: false, terminal_published: false,
        event_claimed: false, event_signaled: false, ack_claimed: false,
        cancel_requested: false, cancel_ack_claimed: false,
    };
    let index = if let Some(index) = slot {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .expect("unparked source IOCTL");
        if !crate::win32k_subsystem::abort_source_buffered_ioctl_dispatch(&mut work.source) {
            crate::provider_bugcheck::report(0xc4, [source_address, token, 0, 4]);
        }
        if let Some(event) = work.event.take() { release_event(handler, event); }
        work.target.release(io_manager_mut()).expect("unparked source IOCTL target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    (&mut *core::ptr::addr_of_mut!(ACTIVE)).push((route, source_address, token));
    None
}

impl Work {
    unsafe fn finish_cancelled(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.reply_entered {
            return false;
        }
        if let Some(irp) = self.irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            if self.cancel_ack_claimed || completed_device_control_irp_exact(irp.raw()).is_none() {
                return false;
            }
            self.cancel_ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() {
                return false;
            }
            self.irp = None;
        }
        if !crate::win32k_subsystem::abort_source_buffered_ioctl_dispatch(&mut self.source) {
            return false;
        }
        if let Some(event) = self.event.take() {
            release_event(handler, event);
        }
        self.target
            .release(io_manager_mut())
            .expect("cancelled source IOCTL target");
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("cancelled source IOCTL Reply");
        let identity = (self.route, self.source_address, self.token);
        let index = (&*core::ptr::addr_of!(ACTIVE))
            .iter()
            .position(|row| *row == identity)
            .expect("cancelled source IOCTL identity");
        (&mut *core::ptr::addr_of_mut!(ACTIVE)).swap_remove(index);
        true
    }

    unsafe fn publish_reply(&mut self, status: u32) -> bool {
        if self.reply_entered {
            return true;
        }
        if !self.packet_prepared {
            let result = if status == STATUS_PENDING as u32 {
                wire::publish_pending(&mut self.packet, self.token)
            } else {
                let (_, information) = self.terminal.expect("inline source IOCTL terminal");
                let output_len = if nt_io_completion::file_io_status_copies_output(status) {
                    nt_io_manager::completion_output_transfer_len(
                        information,
                        self.output.len() as u64,
                    ) as usize
                } else {
                    0
                };
                wire::publish_inline_terminal(
                    &mut self.packet,
                    self.token,
                    status,
                    information,
                    &self.output[..output_len],
                )
            };
            if result.is_err() { return false; }
            self.packet_prepared = true;
        }
        if !crate::win32k_subsystem::publish_provider_pool_packet(
            self.packet_lease,
            &self.packet,
        ) {
            return false;
        }
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
            status as i32,
        );
        false
    }

    unsafe fn capture_output(&mut self) -> bool {
        if self.output_captured {
            return true;
        }
        let (status, information) = self.terminal.expect("source IOCTL terminal");
        let length = if nt_io_completion::file_io_status_copies_output(status) {
            nt_io_manager::completion_output_transfer_len(information, self.output.len() as u64) as usize
        } else {
            0
        };
        if let Some(irp) = self.irp {
            if length != 0 {
                match copy_completed_irp_output_exact(irp.raw(), 0, &mut self.output[..length]) {
                    Ok(copied) if copied == length => {}
                    _ => return false,
                }
            }
        }
        self.output_captured = true;
        true
    }

    unsafe fn output_slice(&self) -> &[u8] {
        let (status, information) = self.terminal.expect("source IOCTL terminal");
        let length = if nt_io_completion::file_io_status_copies_output(status) {
            nt_io_manager::completion_output_transfer_len(information, self.output.len() as u64) as usize
        } else { 0 };
        &self.output[..length]
    }

    unsafe fn publish_terminal(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.terminal_published {
            if self.terminal_claimed { return false; }
            let Some(output_address) = self.output_target.address_if_live(self.route) else { return false };
            let Some(iosb_address) = self.iosb_target.address_if_live(self.route) else { return false };
            let (status, information) = self.terminal.expect("source IOCTL terminal");
            self.terminal_claimed = true;
            if !self.source.publish_terminal(
                status, information, self.output_slice(), output_address, iosb_address,
            ) {
                return false;
            }
            self.terminal_published = true;
        }
        if !self.event_signaled {
            if self.event_claimed { return false; }
            if let Some(event) = &self.event {
                let actual = crate::provider_local_event::LocalEventState::new(
                    &mut (*handler).obj_ns,
                    &mut (*handler).anon_event_seq,
                    &mut (*handler).events,
                    &mut (*handler).event_objects,
                ).identity(event.provider, event.local);
                if !matches!(actual, Ok((id, _, _, _)) if id == event.id) {
                    return false;
                }
                self.event_claimed = true;
                let observed = crate::provider_local_event::signal(
                    &mut *handler, event.provider, event.local, EventSignalMode::Set,
                );
                if observed.is_err() {
                    return false;
                }
                if !self.source.mirror_event_signaled() {
                    return false;
                }
            } else {
                self.event_claimed = true;
            }
            self.event_signaled = true;
        }
        true
    }

    unsafe fn retire(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.source.validate() {
            return false;
        }
        if let Some(irp) = self.irp {
            if self.ack_claimed {
                return false;
            }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() {
                return false;
            }
            self.irp = None;
        }
        if !crate::win32k_subsystem::release_source_buffered_ioctl_dispatch(&mut self.source) {
            return false;
        }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("terminal source IOCTL target");
        runtime::retire_stopped_acknowledged_retained_service(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("source IOCTL Reply retirement");
        let identity = (self.route, self.source_address, self.token);
        let index = (&*core::ptr::addr_of!(ACTIVE)).iter().position(|row| *row == identity)
            .expect("active source IOCTL identity");
        (&mut *core::ptr::addr_of_mut!(ACTIVE)).swap_remove(index);
        (&mut *core::ptr::addr_of_mut!(COMPLETED)).push(identity);
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.entered {
            if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
                return self.finish_cancelled(handler);
            }
            if !self.source.validate() || self.target.validate(io_manager_mut()).is_err() {
                return false;
            }
            self.entered = true;
            let result = if self.source.internal {
                io_manager_mut().internal_device_control_exact_device(
                    ClientId(IO_MANAGER_COMPONENT_ID), self.target.device_id(), self.source.code,
                    &self.source.input, &mut self.output,
                )
            } else {
                io_manager_mut().device_control_exact_device(
                    ClientId(IO_MANAGER_COMPONENT_ID), self.target.device_id(), self.source.code,
                    &self.source.input, &mut self.output,
                )
            };
            match result {
                Ok(nt_io_manager::ExternalDispatchResult::Pending { irp_id }) => {
                    self.irp = Some(irp_id);
                    self.pending = true;
                }
                Ok(nt_io_manager::ExternalDispatchResult::Completed { status, information, .. }) => {
                    self.terminal = Some((status.raw() as u32, information));
                }
                Err(status) => self.terminal = Some((status.raw() as u32, 0)),
            }
        }
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token)
            && !self.reply_entered
        {
            return self.finish_cancelled(handler);
        }
        if self.pending && !self.reply_entered {
            return self.publish_reply(STATUS_PENDING as u32);
        }
        if !self.pending && !self.reply_entered {
            if !self.capture_output() || !self.publish_terminal(handler) {
                return false;
            }
            let (status, _) = self.terminal.expect("inline source IOCTL terminal");
            return self.publish_reply(status);
        }
        if !self.reply_acked {
            self.reply_acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("source IOCTL Reply identity");
            if !self.reply_acked { return false; }
        }
        if self.pending && self.terminal.is_none() {
            let Some(irp) = self.irp else { return false };
            let Some(completion) = completed_device_control_irp_exact(irp.raw()) else {
                return false;
            };
            let expected_major = if self.source.internal {
                major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            } else {
                major::IRP_MJ_DEVICE_CONTROL
            };
            if completion.client_id != IO_MANAGER_COMPONENT_ID
                || completion.device_id != self.target.device_id().raw()
                || completion.major != expected_major
            {
                crate::provider_bugcheck::report(0xc4, [self.source_address, irp.raw(), 0, 5]);
            }
            self.terminal = Some((completion.status, completion.information));
        }
        if self.pending && (!self.capture_output() || !self.publish_terminal(handler)) {
            return false;
        }
        self.retire(handler)
    }
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
    redrive_completion_waits();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) { return None; }
        (&mut *core::ptr::addr_of_mut!(WORK))[index].take().map(|work| (index, work))
    }) else { return };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(), Some(index));
    redrive_completion_waits();
}
