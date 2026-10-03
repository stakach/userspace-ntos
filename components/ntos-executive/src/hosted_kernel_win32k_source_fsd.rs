//! Retained file-less win32k READ/WRITE IRPs dispatched to an exact canonical Device.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_io_manager::win32k_source_fsd_wire as wire;
use nt_io_manager::kernel_irp_builder::{
    validate_kernel_irp_dispatch_cursor, KernelIrpDispatchHeader,
};
use nt_io_manager::{WdmIoStackParameters, WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE};
use nt_kernel_exec::EventSignalMode;

use super::hosted_kernel_win32k_source_ioctl::{
    capture_event, next_source_reply_token, release_event, CanonicalEvent, Target,
};

type Route = nt_component_suspension::peer_registry::PeerRoute;

struct SourcePhysical {
    lease: crate::win32k_subsystem::ProviderPoolPacketLease,
    system_lease: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    mdl_lease: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    major: u8,
    transfer_mode: u32,
    byte_offset: u64,
    input: Vec<u8>,
    output_initial: Vec<u8>,
    output_capacity: u32,
    output_va: u64,
    iosb_va: u64,
}

impl SourcePhysical {
    unsafe fn validate(&self) -> bool {
        crate::win32k_subsystem::provider_pool_packet_lease_live(self.lease)
            && self.system_lease.is_none_or(|lease| {
                crate::win32k_subsystem::provider_pool_packet_lease_live(lease)
            })
            && self.mdl_lease.is_none_or(|lease| {
                crate::win32k_subsystem::provider_pool_packet_lease_live(lease)
            })
    }
}

unsafe fn capture_source(request: wire::SourceFsdRequest<'_>) -> Result<SourcePhysical, i32> {
    let (header_lease, header) = crate::win32k_subsystem::capture_provider_pool_packet(
        request.source_irp_va, WDM_X64_IRP_SIZE,
    ).map_err(|status| status as i32)?;
    let packet_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let stack_count = header[0x42];
    let expected_size = WDM_X64_IRP_SIZE
        .checked_add(stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if stack_count == 0 || stack_count == u8::MAX || packet_size != expected_size
        || header_lease.native_identity().allocation_generation
            != request.native_allocation_generation
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (lease, packet) = crate::win32k_subsystem::capture_provider_pool_packet(
        request.source_irp_va, packet_size,
    ).map_err(|status| status as i32)?;
    if lease.native_identity() != header_lease.native_identity() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let cursor = validate_kernel_irp_dispatch_cursor(
        request.source_irp_va, packet_size as u64, stack_count,
        KernelIrpDispatchHeader {
            irp_type: u16::from_le_bytes([packet[0], packet[1]]),
            packet_size: packet_size as u16,
            stack_count,
            current_location: packet[0x43],
            current_stack_location: u64::from_le_bytes(packet[0xb8..0xc0].try_into().unwrap()),
        },
    ).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let stack = nt_io_manager::decode_wdm_kernel_built_io_stack(
        &packet[cursor.next_stack_offset
            ..cursor.next_stack_offset + WDM_X64_IO_STACK_LOCATION_SIZE],
    ).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let (length, key, byte_offset) = match stack.parameters {
        WdmIoStackParameters::Read { length, key, byte_offset }
            if stack.major == major::IRP_MJ_READ => (length, key, byte_offset),
        WdmIoStackParameters::Write { length, key, byte_offset }
            if stack.major == major::IRP_MJ_WRITE => (length, key, byte_offset),
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    let read = stack.major == major::IRP_MJ_READ;
    if stack.major != request.major
        || stack.device_object != request.device_object_va
        || stack.file_object != 0 || key != 0 || byte_offset != request.byte_offset
        || length != if read { request.output_capacity } else { request.input.len() as u32 }
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let system_buffer = u64::from_le_bytes(packet[0x18..0x20].try_into().unwrap());
    let mdl_address = u64::from_le_bytes(packet[0x08..0x10].try_into().unwrap());
    let flags = u32::from_le_bytes(packet[0x10..0x14].try_into().unwrap());
    let user_buffer = u64::from_le_bytes(packet[0x70..0x78].try_into().unwrap());
    let iosb_va = u64::from_le_bytes(packet[0x48..0x50].try_into().unwrap());
    let event_va = u64::from_le_bytes(packet[0x50..0x58].try_into().unwrap());
    if iosb_va == 0 || (event_va == 0) != request.event.is_none() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let transfer_len = length as u64;
    let mut system_lease = None;
    let mut mdl_lease = None;
    let output_va = match request.transfer_mode {
        wire::BUFFERED => {
            let expected_flags = nt_io_manager::kernel_irp_builder::IRP_BUFFERED_IO
                | nt_io_manager::kernel_irp_builder::IRP_DEALLOCATE_BUFFER
                | if read { nt_io_manager::kernel_irp_builder::IRP_INPUT_OPERATION } else { 0 };
            if flags != expected_flags || mdl_address != 0
                || (transfer_len == 0) != (system_buffer == 0)
            { return Err(STATUS_INVALID_PARAMETER); }
            if transfer_len != 0 {
                let (lease, bytes) = crate::win32k_subsystem::capture_provider_pool_packet(
                    system_buffer, length as usize,
                ).map_err(|status| status as i32)?;
                if !read && bytes.as_slice() != request.input {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                system_lease = Some(lease);
            }
            if read { user_buffer } else { 0 }
        }
        wire::DIRECT => {
            if flags != 0 || system_buffer != 0 || user_buffer != 0
                || (transfer_len == 0) != (mdl_address == 0)
            { return Err(STATUS_INVALID_PARAMETER); }
            if transfer_len == 0 { 0 } else {
                let (lease, mdl) = crate::win32k_subsystem::capture_provider_pool_packet(
                    mdl_address, nt_mdl::MDL_SIZE,
                ).map_err(|status| status as i32)?;
                let mapped = u64::from_le_bytes(mdl[nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA as usize
                    ..nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA as usize + 8].try_into().unwrap());
                if mapped == 0
                    || i16::from_le_bytes(mdl[nt_mdl::MDL_OFF_SIZE as usize
                        ..nt_mdl::MDL_OFF_SIZE as usize + 2].try_into().unwrap())
                        != nt_mdl::MDL_SIZE as i16
                    || i16::from_le_bytes(mdl[nt_mdl::MDL_OFF_FLAGS as usize
                        ..nt_mdl::MDL_OFF_FLAGS as usize + 2].try_into().unwrap())
                        != (nt_mdl::MDL_MAPPED_TO_SYSTEM_VA | nt_mdl::MDL_PAGES_LOCKED)
                    || u64::from_le_bytes(mdl[nt_mdl::MDL_OFF_START_VA as usize
                        ..nt_mdl::MDL_OFF_START_VA as usize + 8].try_into().unwrap())
                        != mapped & !0xfff
                    || u32::from_le_bytes(mdl[nt_mdl::MDL_OFF_BYTE_COUNT as usize
                        ..nt_mdl::MDL_OFF_BYTE_COUNT as usize + 4].try_into().unwrap()) != length
                    || u32::from_le_bytes(mdl[nt_mdl::MDL_OFF_BYTE_OFFSET as usize
                        ..nt_mdl::MDL_OFF_BYTE_OFFSET as usize + 4].try_into().unwrap())
                        != (mapped & 0xfff) as u32
                { return Err(STATUS_INVALID_PARAMETER); }
                mdl_lease = Some(lease);
                if read { mapped } else { 0 }
            }
        }
        wire::NEITHER => {
            if flags != 0 || system_buffer != 0 || mdl_address != 0
                || (transfer_len == 0) != (user_buffer == 0)
            { return Err(STATUS_INVALID_PARAMETER); }
            if read { user_buffer } else { 0 }
        }
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    let mut input = Vec::new();
    let mut output_initial = Vec::new();
    input.try_reserve_exact(request.input.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    output_initial.try_reserve_exact(request.output_initial.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    input.extend_from_slice(request.input);
    output_initial.extend_from_slice(request.output_initial);
    Ok(SourcePhysical {
        lease, system_lease, mdl_lease,
        major: request.major, transfer_mode: request.transfer_mode,
        byte_offset: request.byte_offset, input, output_initial,
        output_capacity: request.output_capacity, output_va, iosb_va,
    })
}

struct Work {
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    source_address: u64,
    source_ticket: u64,
    source_generation: u64,
    source: SourcePhysical,
    target: HostedForwardTarget,
    event: Option<CanonicalEvent>,
    packet_lease: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    packet: Vec<u8>,
    output: Vec<u8>,
    output_target: Target,
    iosb_target: Target,
    irp: Option<IrpId>,
    entered: bool,
    pending: bool,
    origin_armed: bool,
    terminal: Option<(u32, u64)>,
    output_captured: bool,
    event_claimed: bool,
    event_signaled: bool,
    event_barrier: Option<crate::source_event_completion::Barrier>,
    packet_prepared: bool,
    reply_entered: bool,
    reply_acked: bool,
    ack_claimed: bool,
    cancel_requested: bool,
    nonce: u64,
    terminal_packet: Option<super::hosted_source_terminal_packet::RetainedTerminalPacket>,
    terminal_acknowledged: bool,
    origin_committed: bool,
    discarding: bool,
    indeterminate: bool,
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
    let source = match capture_source(request) {
        Ok(source) => source,
        Err(status) => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered FSD source target");
            return Some(status);
        }
    };
    let matches = source.validate()
        && source.major == request.major
        && source.transfer_mode == request.transfer_mode
        && source.transfer_mode == canonical_mode
        && source.byte_offset == request.byte_offset
        && source.input.as_slice() == request.input
        && source.output_initial.as_slice() == request.output_initial
        && source.output_capacity == request.output_capacity;
    if !matches {
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("mismatched FSD source target");
        return Some(STATUS_INVALID_PARAMETER);
    }
    let output_target = Target::capture(route, source.output_va, u64::from(source.output_capacity));
    let iosb_target = Target::capture(route, source.iosb_va, 16);
    let (Some(output_target), Some(iosb_target)) = (output_target, iosb_target) else {
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
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered FSD source target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    output.resize(request.output_capacity as usize, 0);
    if !source.output_initial.is_empty() {
        output.copy_from_slice(&source.output_initial);
    }
    let token = match next_source_reply_token() {
        Some(token) => token,
        _ => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered FSD source target");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let source_address = request.source_irp_va;
    let source_ticket = request.source_ticket_serial;
    let source_generation = request.native_allocation_generation;
    let nonce = request.nonce;
    if !super::hosted_kernel_win32k_source_admission::register(
        route, source_address, source_ticket, source_generation,
    ) {
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered FSD source target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let work = Work {
        route, dispatch, reply, token, source_address, source_ticket, source_generation,
        source, target, event,
        packet_lease: Some(packet_lease), packet, output, output_target, iosb_target, irp: None,
        entered: false, pending: false, origin_armed: false, terminal: None, output_captured: false,
        event_claimed: false,
        event_signaled: false, event_barrier: None, packet_prepared: false, reply_entered: false,
        reply_acked: false, ack_claimed: false, cancel_requested: false,
        nonce, terminal_packet: None, terminal_acknowledged: false, origin_committed: false, discarding: false,
        indeterminate: false,
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
        if let Some(event) = work.event.take() { release_event(handler, event); }
        work.target.release(io_manager_mut()).expect("unparked FSD source target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    None
}

/// Authenticated broker receipt, not inference from native Reply acknowledgement.
pub(super) unsafe fn arm_pending(
    route: Route,
    identity: nt_io_manager::source_pending_armed::PendingArmedIdentity,
) -> Result<(), i32> {
    use nt_io_manager::source_pending_armed::{PendingArmedIdentity, PendingSourceKind};
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let Some(work) = rows.iter_mut().filter_map(Option::as_mut).find(|work| {
        work.route == route && work.nonce == identity.nonce
    }) else { return Err(STATUS_INVALID_PARAMETER); };
    let expected = PendingArmedIdentity {
        kind: PendingSourceKind::Fsd, nonce: work.nonce, token: work.token,
        source_irp_va: work.source_address, source_ticket_serial: work.source_ticket,
        native_allocation_generation: work.source_generation,
    };
    if identity != expected || !work.pending || !work.reply_entered || work.indeterminate
        || !runtime::retained_service_reply_acknowledged(
            work.route, work.dispatch, work.reply, work.token,
        ).unwrap_or(false)
    { return Err(STATUS_INVALID_PARAMETER); }
    work.origin_armed = true;
    Ok(())
}

impl Work {
    fn observation_kind(&self) -> super::source_observability::Kind {
        if self.source.major == major::IRP_MJ_READ {
            super::source_observability::Kind::Read
        } else {
            super::source_observability::Kind::Write
        }
    }
    unsafe fn terminal_step_ready(&self) -> bool {
        self.terminal_packet.as_ref().is_none_or(|packet| {
            !packet.needs_lane(self.discarding || self.terminal_acknowledged)
                || crate::win32k_glue::source_terminal_dispatch_ready()
        })
    }

    unsafe fn ready_for_nested_step(&self) -> bool {
        use nt_io_manager::retained_source_progress::RetainedSourceProgress as Progress;
        let progress = if self.indeterminate {
            Progress::Indeterminate
        } else if runtime::retained_service_owner_stopped(self.route, self.dispatch, self.reply, self.token) {
            Progress::Stopped {
                cancellation_pending: self.irp.is_some() && !self.cancel_requested,
                completion_ready: self.irp.is_none_or(|irp| nested_irp_completion_ready_exact(irp.raw())),
                broker_stopped: runtime::retained_service_owner_stopped_at_broker(
                    self.route, self.dispatch, self.reply, self.token,
                ) && self.event_barrier.is_none(),
                source_lane_ready: self.terminal_step_ready(),
            }
        } else if !self.entered {
            Progress::AwaitingDispatch { provider_ready:
                super::hosted_kernel_win32k_source_ioctl::target_dispatch_ready(self.target.device_id()) }
        } else if self.pending && !self.reply_entered {
            Progress::PublishReply
        } else if self.reply_entered && !self.reply_acked {
            Progress::AwaitingReply { acknowledged: runtime::retained_service_reply_acknowledged(
                self.route, self.dispatch, self.reply, self.token,
            ).unwrap_or(false) }
        } else if self.pending && !self.origin_armed {
            Progress::AwaitingOriginArmed
        } else if self.pending && self.terminal.is_none() {
            Progress::AwaitingCompletion {
                completion_ready: self.irp.is_some_and(|irp| nested_irp_completion_ready_exact(irp.raw())),
                cancellation_pending: false,
            }
        } else if !self.origin_committed {
            Progress::Terminal { source_lane_ready: self.terminal_step_ready() }
        } else {
            Progress::Retirement
        };
        progress.ready_for_nested_step()
    }

    fn progress_state(&self) -> [u64; 16] {
        [self.entered as u64, self.pending as u64, self.reply_entered as u64,
            self.reply_acked as u64, self.terminal.is_some() as u64, self.output_captured as u64,
            self.terminal_acknowledged as u64, self.terminal_packet.as_ref().map_or(0, |packet| packet.progress()),
            self.origin_committed as u64, self.event_claimed as u64, self.event_signaled as u64,
            self.ack_claimed as u64, self.cancel_requested as u64, self.discarding as u64,
            self.indeterminate as u64, self.terminal_packet.is_some() as u64]
    }

    unsafe fn output_len(&self) -> usize {
        if self.source.major == major::IRP_MJ_READ {
            let (_, information) = self.terminal.expect("FSD terminal");
            information.min(u64::from(self.source.output_capacity)) as usize
        } else { 0 }
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
            }) => {
                if status.is_success() {
                    super::source_observability::terminal(self.observation_kind(), 0);
                }
                super::source_observability::canonical(self.observation_kind());
                self.terminal = Some((status.raw() as u32, information));
            }
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

    unsafe fn deliver_terminal(&mut self) -> bool {
        if self.terminal_acknowledged { return true; }
        if self.indeterminate { return false; }
        let (status, information) = self.terminal.expect("FSD terminal");
        let length = self.output_len();
        if self.terminal_packet.is_none() {
            let valid_information = if self.source.major == major::IRP_MJ_READ {
                information <= u64::from(self.source.output_capacity)
            } else { information <= self.source.input.len() as u64 };
            if !valid_information || !self.source.validate()
                || (!self.discarding && (self.output_target.address_if_live(self.route).is_none()
                    || self.iosb_target.address_if_live(self.route).is_none()))
            { return false; }
            let handoff = wire::SourceFsdTerminalHandoff {
                delivery: if self.pending { wire::TerminalDelivery::Pending } else { wire::TerminalDelivery::Inline },
                nonce: self.nonce, token: self.token, source_irp_va: self.source_address,
                source_ticket_serial: self.source_ticket, native_allocation_generation: self.source_generation,
                status, information, output: &self.output[..length],
            };
            let Ok(packet_len) = wire::terminal_packet_len(length) else { return false };
            let mut packet = Vec::new();
            if packet.try_reserve_exact(packet_len).is_err() { return false; }
            packet.resize(packet_len, 0);
            if wire::encode_terminal_handoff(handoff, &mut packet).is_err() { return false; }
            self.terminal_packet = Some(super::hosted_source_terminal_packet::RetainedTerminalPacket::new(packet));
        }
        let transport = self.terminal_packet.as_mut().expect("retained FSD terminal transport");
        let ready = if self.discarding { transport.publish() }
            else { transport.prepare(crate::win32k_glue::dispatch_source_fsd_terminal) };
        if !ready { self.indeterminate |= transport.indeterminate(); return false; }
        if self.discarding { return true; }
        let valid = matches!(wire::decode_terminal_ack(transport.ack()), Ok(ack) if
            ack.handoff.delivery == (if self.pending { wire::TerminalDelivery::Pending } else { wire::TerminalDelivery::Inline })
                && ack.handoff.nonce == self.nonce && ack.handoff.token == self.token
                && ack.handoff.source_irp_va == self.source_address
                && ack.handoff.source_ticket_serial == self.source_ticket
                && ack.handoff.native_allocation_generation == self.source_generation
                && ack.handoff.status == status && ack.handoff.information == information
                && ack.handoff.output == &self.output[..length]
                && ack.publication == wire::TerminalPublication::Published);
        if !transport.acknowledge_prepare(valid) { self.indeterminate = true; return false; }
        self.terminal_acknowledged = true;
        true
    }

    unsafe fn signal_event(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.terminal_acknowledged { return false; }
        if self.event_signaled { return true; }
        if self.event_claimed { return false; }
        if let Some(event) = &self.event {
            let actual = crate::provider_local_event::LocalEventState::new(
                &mut (*handler).obj_ns,
                &mut (*handler).anon_event_seq,
                &mut (*handler).events,
                &mut (*handler).event_objects,
            ).identity(event.provider, event.local);
            if !matches!(actual, Ok((id, _, _, _)) if id == event.id) { return false; }
            let barrier = match crate::source_event_completion::capture(handler, event.id) {
                    Ok(barrier) => barrier,
                    Err(_) => return false,
                };
                self.event_barrier = Some(barrier);
                self.event_claimed = true;
            } else { self.event_claimed = true; }
        self.event_signaled = true;
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
        let Some(packet_lease) = self.packet_lease else { return false };
        if let Err(error) = crate::win32k_subsystem::try_publish_root_provider_pool_packet(
            packet_lease, &self.packet,
        ) {
            self.indeterminate |= matches!(error, crate::win32k_subsystem::RootPoolError::InvalidIdentity
                | crate::win32k_subsystem::RootPoolError::Indeterminate);
            return false;
        }
        self.reply_entered = true;
        self.packet_lease = None;
        drop(core::mem::take(&mut self.packet));
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token, status as i32,
        );
        false
    }

    unsafe fn commit_canonical(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.terminal_acknowledged { return false; }
        if let Some(irp) = self.irp {
            if self.ack_claimed { return false; }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() { return false; }
            super::source_observability::canonical(self.observation_kind());
            self.irp = None;
        }
        self.signal_event(handler) && self.commit_origin(handler)
    }

    unsafe fn commit_origin(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.indeterminate { return false; }
        if self.origin_committed { return self.event_barrier.is_none(); }
        if !self.terminal_acknowledged || !self.event_signaled { return false; }
        if !self.terminal_packet.as_mut().expect("retained terminal transport").finish(
            64, false, self.event_barrier.map_or(0, |barrier| barrier.sequence()), crate::win32k_glue::dispatch_source_fsd_terminal,
        ) {
            self.indeterminate |= self.terminal_packet.as_ref().is_some_and(|packet| packet.indeterminate());
            return false;
        }
        self.origin_committed = true;
        super::source_observability::origin(self.observation_kind());
        if let Some(barrier) = self.event_barrier {
            if crate::source_event_completion::release(handler, barrier).is_err() {
                self.indeterminate = true;
                return false;
            }
            self.event_barrier = None;
        }
        true
    }

    unsafe fn retire(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.origin_committed || !self.reply_acked || !self.event_signaled
            || self.target.validate(io_manager_mut()).is_err() {
            return false;
        }
        if let Some(irp) = self.irp {
            if self.ack_claimed { return false; }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() { return false; }
            super::source_observability::canonical(self.observation_kind());
            self.irp = None;
        }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("terminal FSD source target");
        runtime::retire_stopped_acknowledged_retained_service(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("FSD source Reply retirement");
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        super::source_observability::retired(self.observation_kind());
        true
    }

    unsafe fn finish_stopped(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.indeterminate { return false; }
        if let Some(irp) = self.irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            let Some(completion) = completed_irp_snapshot_exact(irp.raw()) else { return false };
            if completion.id != irp || completion.client_id != ClientId(IO_MANAGER_COMPONENT_ID)
                || completion.file_id.is_some() || completion.device_id != self.target.device_id()
                || completion.major != self.source.major
                || completion.completion_origin != IrpCompletionOrigin::Driver {
                crate::provider_bugcheck::report(0xc4, [self.source_address, irp.raw(), 0, 94]);
            }
        }
        // Only a sealed stop while physically parked in this broker Call proves local guards
        // cannot be held. A stopped-running or whole-domain owner remains quarantined.
        if !runtime::retained_service_owner_stopped_at_broker(
            self.route, self.dispatch, self.reply, self.token,
        ) { return false; }
        if self.event_barrier.is_some() || self.origin_committed {
            // Canonical transfer/signal preparation already began; do not turn an uncertain
            // committed terminal into a new cancellation transaction.
            return false;
        }
        {
            if let Some(irp) = self.irp {
                if self.ack_claimed { return false; }
                self.ack_claimed = true;
                if acknowledge_completed_irp_strict(irp.raw()).is_err() {
                    self.indeterminate = true;
                    return false;
                }
                self.irp = None;
            }
            if self.terminal_packet.is_none() { self.terminal = Some((0xc000_0120, 0)); }
            self.discarding = true;
            if !self.deliver_terminal() { return false; }
            if !self.terminal_packet.as_mut().expect("retained terminal transport").finish(
                64, true, 0, crate::win32k_glue::dispatch_source_fsd_terminal,
            ) {
                self.indeterminate |= self.terminal_packet.as_ref().is_some_and(|packet| packet.indeterminate());
                return false;
            }
            self.origin_committed = true;
        }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("stopped FSD target");
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("sealed broker-stopped source Reply");
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if runtime::retained_service_owner_stopped(self.route, self.dispatch, self.reply, self.token) {
            return self.finish_stopped(handler);
        }
        if !self.entered && !super::hosted_kernel_win32k_source_ioctl::target_dispatch_ready(self.target.device_id()) {
            return false;
        }
        if !self.enter() { return false; }
        if self.indeterminate { return false; }
        if self.pending && !self.reply_entered {
            return self.publish_reply(STATUS_PENDING as u32);
        }
        if !self.pending && !self.reply_entered {
            if !self.capture_output() || !self.deliver_terminal()
                || !self.commit_canonical(handler) { return false; }
            let (status, _) = self.terminal.expect("inline FSD terminal");
            return self.publish_reply(status);
        }
        if !self.reply_acked {
            self.reply_acked = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("FSD source Reply identity");
            if !self.reply_acked { return false; }
        }
        if self.pending && !self.origin_armed { return false; }
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
            super::source_observability::terminal(self.observation_kind(), 0);
        }
        if self.pending && (!self.capture_output() || !self.deliver_terminal()
            || !self.commit_canonical(handler)) {
            return false;
        }
        self.retire(handler)
    }
}

unsafe fn redrive_one(handler: *mut ExecNtHandler, nested_ready_only: bool) -> bool {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return false; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) { return None; }
        if nested_ready_only && !(&*core::ptr::addr_of!(WORK))[index]
            .as_ref().is_some_and(|work| work.ready_for_nested_step()) { return None; }
        (&mut *core::ptr::addr_of_mut!(WORK))[index].take().map(|work| (index, work))
    }) else { return false };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let before = work.progress_state();
    let done = work.advance(handler);
    let progressed = done || before != work.progress_state();
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(), Some(index));
    progressed
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) -> bool {
    redrive_one(handler, false)
}

pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK)).iter().enumerate().any(|(index, row)| {
        !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)
            && row.as_ref().is_some_and(|work| work.ready_for_nested_step())
    })
}

pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    redrive_one(handler, true)
}
