//! Retained file-less win32k READ/WRITE IRPs dispatched to an exact canonical Device.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_io_manager::win32k_source_fsd_wire as wire;
use nt_kernel_exec::EventSignalMode;

use super::hosted_kernel_win32k_source_ioctl::{
    cancel_external_source, capture_event, complete_external_source,
    register_external_source, release_event,
    reserve_external_source_token, CanonicalEvent, Target,
};

type Route = nt_component_suspension::peer_registry::PeerRoute;

struct Work {
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    source_address: u64,
    source_ticket: u64,
    source_generation: u64,
    source: crate::win32k_subsystem::SourceFsdDispatchLease,
    target: HostedForwardTarget,
    event: Option<CanonicalEvent>,
    packet_lease: crate::win32k_subsystem::ProviderPoolPacketLease,
    packet: Vec<u8>,
    output: Vec<u8>,
    output_target: Target,
    iosb_target: Target,
    irp: Option<IrpId>,
    entered: bool,
    pending: bool,
    terminal: Option<(u32, u64)>,
    output_captured: bool,
    terminal_claimed: bool,
    terminal_published: bool,
    event_claimed: bool,
    event_signaled: bool,
    packet_prepared: bool,
    reply_entered: bool,
    reply_acked: bool,
    ack_claimed: bool,
    cancel_requested: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    packet_address: u64,
    packet_length: u64,
    stack_pointer: u64,
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
    if crate::win32k_glue::win32k_stack_alias_for_route(route, stack_pointer, 1).is_none() {
        return Some(STATUS_ACCESS_DENIED);
    }
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let Ok(length) = usize::try_from(packet_length) else {
        return Some(STATUS_INVALID_BUFFER_SIZE as i32);
    };
    if !(wire::HEADER_BYTES..=wire::MAX_PACKET_BYTES).contains(&length) {
        return Some(STATUS_INVALID_BUFFER_SIZE as i32);
    }
    let (packet_lease, packet) = match crate::win32k_subsystem::capture_provider_pool_packet(
        packet_address, length,
    ) {
        Ok(captured) => captured,
        Err(status) => return Some(status as i32),
    };
    let request = match wire::decode_request(&packet) {
        Ok(request) => request,
        Err(_) => return Some(STATUS_INVALID_PARAMETER),
    };
    if super::hosted_kernel_win32k_source_admission::contains(request.source_irp_va) {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let access = match crate::win32k_device_consumer::authenticate(
        channel, reply_cap, request.device_object_va,
    ) {
        Ok(access) if access.dispatch() == dispatch => access,
        Ok(_) => return Some(STATUS_ACCESS_DENIED),
        Err(status) => return Some(status),
    };
    let mut target = match HostedForwardTarget::capture(
        io_manager_mut(), access.domain(), access.address(),
    ) {
        Ok(target) if target.device_id() == access.device() => target,
        Ok(mut target) => {
            target.release(io_manager_mut()).expect("mismatched FSD source target");
            return Some(STATUS_INVALID_DEVICE_REQUEST as i32);
        }
        Err(status) => return Some(status.raw()),
    };
    let canonical_mode = match io_manager_mut().device(target.device_id()) {
        Some(device) if device.flags.contains(nt_io_manager::DeviceFlags::BUFFERED_IO) => wire::BUFFERED,
        Some(device) if device.flags.contains(nt_io_manager::DeviceFlags::DIRECT_IO) => wire::DIRECT,
        Some(_) => wire::NEITHER,
        None => {
            target.release(io_manager_mut()).expect("missing FSD source target");
            return Some(STATUS_INVALID_DEVICE_REQUEST as i32);
        }
    };
    let mut event = match capture_event(handler, request.event) {
        Ok(event) => event,
        Err(status) => {
            target.release(io_manager_mut()).expect("unentered FSD source target");
            return Some(status);
        }
    };
    let mut source = match crate::win32k_subsystem::admit_source_fsd_dispatch(
        request.source_irp_va, request.device_object_va, stack_pointer, Some(route),
    ) {
        Ok(source) => source,
        Err(status) => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered FSD source target");
            return Some(status);
        }
    };
    let matches = source.validate()
        && source.source_address() == request.source_irp_va
        && source.source_ticket_serial() == request.source_ticket_serial
        && source.source_native_generation() == request.native_allocation_generation
        && source.device == request.device_object_va
        && source.major == request.major
        && source.transfer_mode == request.transfer_mode
        && source.transfer_mode == canonical_mode
        && source.byte_offset == request.byte_offset
        && source.input.as_slice() == request.input
        && source.output_initial.as_slice() == request.output_initial
        && source.output_capacity == request.output_capacity
        && source.event == request.event
        && source.event.is_some() == source.event_body().is_some();
    if !matches {
        if !crate::win32k_subsystem::abort_source_fsd_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 51]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("mismatched FSD source target");
        return Some(STATUS_INVALID_PARAMETER);
    }
    let output_target = Target::capture(route, source.output_va, u64::from(source.output_capacity));
    let iosb_target = Target::capture(route, source.iosb_va, 16);
    let (Some(output_target), Some(iosb_target)) = (output_target, iosb_target) else {
        if !crate::win32k_subsystem::abort_source_fsd_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 52]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered FSD source target");
        return Some(STATUS_INVALID_PARAMETER);
    };
    let mut output = Vec::new();
    let slot = (&*core::ptr::addr_of!(WORK)).iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
    });
    if output.try_reserve_exact(request.output_capacity as usize).is_err()
        || (slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err())
    {
        if !crate::win32k_subsystem::abort_source_fsd_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 53]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered FSD source target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    output.resize(request.output_capacity as usize, 0);
    if !source.output_initial.is_empty() {
        output.copy_from_slice(&source.output_initial);
    }
    let Some(token) = reserve_external_source_token() else {
        if !crate::win32k_subsystem::abort_source_fsd_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [request.source_irp_va, 0, 0, 54]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered FSD source target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    };
    let source_address = source.source_address();
    let source_ticket = source.source_ticket_serial();
    let source_generation = source.source_native_generation();
    if !super::hosted_kernel_win32k_source_admission::register(
        route, source_address, source_ticket, source_generation,
    ) {
        if !crate::win32k_subsystem::abort_source_fsd_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [source_address, token, 0, 59]);
        }
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered FSD source target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let work = Work {
        route, dispatch, reply, token, source_address, source_ticket, source_generation,
        source, target, event,
        packet_lease, packet, output, output_target, iosb_target, irp: None,
        entered: false, pending: false, terminal: None, output_captured: false,
        terminal_claimed: false, terminal_published: false, event_claimed: false,
        event_signaled: false, packet_prepared: false, reply_entered: false,
        reply_acked: false, ack_claimed: false, cancel_requested: false,
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
        super::hosted_kernel_win32k_source_admission::retire(
            route, source_address, source_ticket, source_generation,
        );
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index].take().unwrap();
        if !crate::win32k_subsystem::abort_source_fsd_dispatch(&mut work.source) {
            crate::provider_bugcheck::report(0xc4, [source_address, token, 0, 55]);
        }
        if let Some(event) = work.event.take() { release_event(handler, event); }
        work.target.release(io_manager_mut()).expect("unparked FSD source target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    register_external_source(route, source_address, token);
    None
}

impl Work {
    unsafe fn output_len(&self) -> usize {
        if self.source.major == major::IRP_MJ_READ {
            let (_, information) = self.terminal.expect("FSD terminal");
            information.min(u64::from(self.source.output_capacity)) as usize
        } else { 0 }
    }

    unsafe fn finish_cancelled_before_entry(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.entered || self.reply_entered { return false; }
        if !crate::win32k_subsystem::abort_source_fsd_dispatch(&mut self.source) { return false; }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("cancelled FSD source target");
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("cancelled FSD source Reply");
        cancel_external_source(self.route, self.source_address, self.token);
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn enter(&mut self) -> bool {
        if self.entered { return true; }
        if !self.source.validate() || self.target.validate(io_manager_mut()).is_err() {
            return false;
        }
        self.entered = true;
        let result = if self.source.major == major::IRP_MJ_READ {
            io_manager_mut().read_exact_device(
                ClientId(IO_MANAGER_COMPONENT_ID), self.target.device_id(),
                self.source.byte_offset, &mut self.output,
            )
        } else {
            io_manager_mut().write_exact_device(
                ClientId(IO_MANAGER_COMPONENT_ID), self.target.device_id(),
                self.source.byte_offset, &self.source.input,
            )
        };
        match result {
            Ok(nt_io_manager::ExternalDispatchResult::Pending { irp_id }) => {
                self.irp = Some(irp_id);
                self.pending = true;
            }
            Ok(nt_io_manager::ExternalDispatchResult::Completed {
                status, information, ..
            }) => self.terminal = Some((status.raw() as u32, information)),
            Err(status) => self.terminal = Some((status.raw() as u32, 0)),
        }
        true
    }

    unsafe fn capture_output(&mut self) -> bool {
        if self.output_captured { return true; }
        let length = self.output_len();
        if length > self.output.len() { return false; }
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

    unsafe fn publish_terminal(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.terminal_published {
            if self.terminal_claimed { return false; }
            let Some(output_address) = self.output_target.address_if_live(self.route) else {
                return false;
            };
            let Some(iosb_address) = self.iosb_target.address_if_live(self.route) else {
                return false;
            };
            let (status, information) = self.terminal.expect("FSD terminal");
            let valid_information = if self.source.major == major::IRP_MJ_READ {
                information <= u64::from(self.source.output_capacity)
            } else {
                information <= self.source.input.len() as u64
            };
            if !valid_information || !self.source.validate() { return false; }
            self.terminal_claimed = true;
            let length = self.output_len();
            if !self.source.publish_terminal(
                status, information, &self.output[..length], output_address, iosb_address,
            ) { return false; }
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
                if !matches!(actual, Ok((id, _, _, _)) if id == event.id) { return false; }
                self.event_claimed = true;
                if crate::provider_local_event::signal(
                    &mut *handler, event.provider, event.local, EventSignalMode::Set,
                ).is_err() || !self.source.mirror_event_signaled() { return false; }
            } else { self.event_claimed = true; }
            self.event_signaled = true;
        }
        true
    }

    unsafe fn publish_reply(&mut self, status: u32) -> bool {
        if self.reply_entered { return true; }
        if !self.packet_prepared {
            let result = if status == STATUS_PENDING as u32 {
                wire::publish_pending(&mut self.packet, self.token)
            } else {
                let (_, information) = self.terminal.expect("inline FSD terminal");
                let length = self.output_len();
                wire::publish_inline_terminal(
                    &mut self.packet, self.token, status, information, &self.output[..length],
                )
            };
            if result.is_err() { return false; }
            self.packet_prepared = true;
        }
        if !crate::win32k_subsystem::publish_provider_pool_packet(
            self.packet_lease, &self.packet,
        ) { return false; }
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token, status as i32,
        );
        false
    }

    unsafe fn retire(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.source.validate() || self.target.validate(io_manager_mut()).is_err() {
            return false;
        }
        if let Some(irp) = self.irp {
            if self.ack_claimed { return false; }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() { return false; }
            self.irp = None;
        }
        if !crate::win32k_subsystem::release_source_fsd_dispatch(&mut self.source) {
            return false;
        }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("terminal FSD source target");
        runtime::retire_stopped_acknowledged_retained_service(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("FSD source Reply retirement");
        complete_external_source(self.route, self.source_address, self.token);
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.entered && runtime::retained_service_cancelled(
            self.route, self.dispatch, self.reply, self.token,
        ) {
            return self.finish_cancelled_before_entry(handler);
        }
        if !self.enter() { return false; }
        if runtime::retained_service_cancelled(
            self.route, self.dispatch, self.reply, self.token,
        ) && !self.reply_entered {
            if let Some(irp) = self.irp {
                if !self.cancel_requested {
                    self.cancel_requested = true;
                    let _ = cancel_irp_if_pending(irp.raw());
                }
            }
            return false;
        }
        if self.pending && !self.reply_entered {
            return self.publish_reply(STATUS_PENDING as u32);
        }
        if !self.pending && !self.reply_entered {
            if !self.capture_output() || !self.publish_terminal(handler) { return false; }
            let (status, _) = self.terminal.expect("inline FSD terminal");
            return self.publish_reply(status);
        }
        if !self.reply_acked {
            self.reply_acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("FSD source Reply identity");
            if !self.reply_acked { return false; }
        }
        if self.pending && self.terminal.is_none() {
            let Some(irp) = self.irp else { return false };
            let Some(completion) = completed_irp_snapshot_exact(irp.raw()) else { return false };
            if completion.id != irp
                || completion.client_id != ClientId(IO_MANAGER_COMPONENT_ID)
                || completion.file_id.is_some()
                || completion.device_id != self.target.device_id()
                || completion.major != self.source.major
                || completion.completion_origin != IrpCompletionOrigin::Driver
            {
                crate::provider_bugcheck::report(0xc4, [self.source_address, irp.raw(), 0, 56]);
            }
            self.terminal = Some((completion.status.raw() as u32, completion.information));
        }
        if self.pending && (!self.capture_output() || !self.publish_terminal(handler)) {
            return false;
        }
        self.retire(handler)
    }
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
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
    super::hosted_kernel_win32k_source_ioctl::redrive_completion_waits();
}
