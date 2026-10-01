//! Retained file-less win32k source IRPs dispatched to an exact canonical Device.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_io_manager::win32k_source_irp_ioctl_wire as wire;
use nt_io_manager::kernel_irp_builder::{
    validate_kernel_irp_dispatch_cursor, KernelIrpDispatchHeader,
};
use nt_io_manager::{WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE};
use nt_kernel_exec::{EventLeaseId, EventLeaseKind, EventObjectId, EventSignalMode};

type Route = nt_component_suspension::peer_registry::PeerRoute;
const STATUS_CANCELLED: u32 = 0xc000_0120;

pub(super) unsafe fn commit_origin_packet(
    packet: &mut Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    length: usize,
    phase_offset: usize,
    requested: &mut bool,
    indeterminate: &mut bool,
    discard: bool,
    signal_sequence: u64,
    dispatch: unsafe fn(u64, u64) -> crate::win32k_glue::SourcePnpTerminalDispatch,
) -> bool {
    use nt_io_manager::source_terminal::{same_terminal_packet, TerminalPublication};
    if *indeterminate { return false; }
    let Some(lease) = *packet else { return false };
    let (actual, mut before) = match crate::win32k_subsystem::capture_provider_pool_packet(lease.address(), length) {
        Ok(captured) => captured,
        Err(_) => { *indeterminate = true; return false; }
    };
    if actual.native_identity() != lease.native_identity() { *indeterminate = true; return false; }
    let command = if discard { TerminalPublication::DiscardRequested } else { TerminalPublication::CommitRequested };
    let stage = u32::from_le_bytes(before[phase_offset..phase_offset + 4].try_into().unwrap());
    let status = u32::from_le_bytes(before[phase_offset + 4..phase_offset + 8].try_into().unwrap());
    let previous = if stage == 0 && status == 0 { None } else { TerminalPublication::decode(stage, status) };
    if !*requested {
        if !command.can_follow(previous) { *indeterminate = true; return false; }
        let (stage, status) = command.words();
        before[phase_offset..phase_offset + 4].copy_from_slice(&stage.to_le_bytes());
        before[phase_offset + 4..phase_offset + 8].copy_from_slice(&status.to_le_bytes());
        before[phase_offset + 8..phase_offset + 16].copy_from_slice(&signal_sequence.to_le_bytes());
        if !crate::win32k_subsystem::publish_provider_pool_packet(lease, &before) { return false; }
        *requested = true;
    } else if previous != Some(command)
        || u64::from_le_bytes(before[phase_offset + 8..phase_offset + 16].try_into().unwrap()) != signal_sequence
    { *indeterminate = true; return false; }
    match dispatch(lease.address(), length as u64) {
        crate::win32k_glue::SourcePnpTerminalDispatch::NotEntered(_) => return false,
        crate::win32k_glue::SourcePnpTerminalDispatch::Returned(0) => {}
        _ => { *indeterminate = true; return false; }
    }
    let (actual, after) = match crate::win32k_subsystem::capture_provider_pool_packet(lease.address(), length) {
        Ok(captured) => captured,
        Err(_) => { *indeterminate = true; return false; }
    };
    let expected = if discard { TerminalPublication::Discarded } else { TerminalPublication::Committed };
    let stage = u32::from_le_bytes(after[phase_offset..phase_offset + 4].try_into().unwrap());
    let status = u32::from_le_bytes(after[phase_offset + 4..phase_offset + 8].try_into().unwrap());
    if actual.native_identity() != lease.native_identity()
        || !same_terminal_packet(&before, &after, phase_offset)
        || TerminalPublication::decode(stage, status) != Some(expected)
        || u64::from_le_bytes(after[phase_offset + 8..phase_offset + 16].try_into().unwrap()) != signal_sequence
        || !crate::win32k_subsystem::retire_root_provider_pool_packet(lease)
    { *indeterminate = true; return false; }
    *packet = None;
    true
}

struct RootSource {
    internal: bool,
    irp: crate::win32k_subsystem::ProviderPoolPacketLease,
    system_buffer: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    mdl: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
}

impl RootSource {
    unsafe fn live(&self) -> bool {
        crate::win32k_subsystem::provider_pool_packet_lease_live(self.irp)
            && self.system_buffer.is_none_or(|lease| {
                crate::win32k_subsystem::provider_pool_packet_lease_live(lease)
            })
            && self.mdl.is_none_or(|lease| {
                crate::win32k_subsystem::provider_pool_packet_lease_live(lease)
            })
    }
}

unsafe fn capture_source(request: &wire::SourceIrpIoctlRequest<'_>) -> Result<RootSource, i32> {
    use nt_io_abi::{ioctl, major};
    let (header_lease, header) = crate::win32k_subsystem::capture_provider_pool_packet(
        request.source_irp_va, WDM_X64_IRP_SIZE,
    ).map_err(|status| status as i32)?;
    let stack_count = header[0x42];
    let packet_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let expected_size = WDM_X64_IRP_SIZE
        .checked_add(stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if stack_count == 0 || stack_count == u8::MAX || packet_size != expected_size
        || header_lease.native_identity().allocation_generation
            != request.native_allocation_generation
    { return Err(STATUS_INVALID_PARAMETER); }
    let (irp, bytes) = crate::win32k_subsystem::capture_provider_pool_packet(
        request.source_irp_va, packet_size,
    ).map_err(|status| status as i32)?;
    if irp.native_identity() != header_lease.native_identity() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let cursor = validate_kernel_irp_dispatch_cursor(
        request.source_irp_va, packet_size as u64, stack_count,
        KernelIrpDispatchHeader {
            irp_type: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            packet_size: packet_size as u16,
            stack_count,
            current_location: bytes[0x43],
            current_stack_location: u64::from_le_bytes(bytes[0xb8..0xc0].try_into().unwrap()),
        },
    ).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let stack = nt_io_manager::decode_wdm_kernel_built_io_stack(
        &bytes[cursor.next_stack_offset
            ..cursor.next_stack_offset + WDM_X64_IO_STACK_LOCATION_SIZE],
    ).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let nt_io_manager::WdmIoStackParameters::DeviceControl {
        output_buffer_length, input_buffer_length, io_control_code, type3_input_buffer,
    } = stack.parameters else { return Err(STATUS_INVALID_PARAMETER) };
    let method = ioctl::method(request.code);
    let input_len = u32::try_from(request.input.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let system_len = if method == ioctl::METHOD_BUFFERED {
        input_len.max(request.output_capacity)
    } else if method == ioctl::METHOD_NEITHER { 0 } else { input_len };
    let flags = u32::from_le_bytes(bytes[0x10..0x14].try_into().unwrap());
    let expected_flags = if system_len == 0 { 0 } else {
        nt_io_manager::kernel_irp_builder::IRP_BUFFERED_IO
            | nt_io_manager::kernel_irp_builder::IRP_DEALLOCATE_BUFFER
            | if method == ioctl::METHOD_BUFFERED && request.output_va != 0 {
                nt_io_manager::kernel_irp_builder::IRP_INPUT_OPERATION
            } else { 0 }
    };
    let mdl_va = u64::from_le_bytes(bytes[0x08..0x10].try_into().unwrap());
    let system_va = u64::from_le_bytes(bytes[0x18..0x20].try_into().unwrap());
    let user_buffer = u64::from_le_bytes(bytes[0x70..0x78].try_into().unwrap());
    let iosb_va = u64::from_le_bytes(bytes[0x48..0x50].try_into().unwrap());
    let event_va = u64::from_le_bytes(bytes[0x50..0x58].try_into().unwrap());
    if !matches!(stack.major, major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL)
        || stack.minor != 0 || stack.device_object != request.device_object_va
        || stack.file_object != 0 || io_control_code != request.code
        || input_buffer_length != input_len || output_buffer_length != request.output_capacity
        || flags != expected_flags || system_va != request.system_buffer_va
        || mdl_va != request.mdl_va || iosb_va != request.iosb_va
        || event_va != request.event_body_va
        || match method {
            ioctl::METHOD_BUFFERED => type3_input_buffer != 0 || user_buffer != request.output_va,
            ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                type3_input_buffer != 0 || user_buffer != 0
            }
            ioctl::METHOD_NEITHER => {
                type3_input_buffer != request.input_va || user_buffer != request.output_va
            }
            _ => true,
        }
    { return Err(STATUS_INVALID_PARAMETER); }
    let system_buffer = if system_len == 0 { None } else {
        let (lease, data) = crate::win32k_subsystem::capture_provider_pool_packet(
            system_va, system_len as usize,
        ).map_err(|status| status as i32)?;
        if lease.native_identity().allocation_generation != request.system_buffer_generation
            || &data[..request.input.len()] != request.input
        { return Err(STATUS_INVALID_PARAMETER); }
        Some(lease)
    };
    let mdl = if mdl_va == 0 { None } else {
        let (lease, data) = crate::win32k_subsystem::capture_provider_pool_packet(
            mdl_va, nt_mdl::MDL_SIZE,
        ).map_err(|status| status as i32)?;
        let i16_at = |offset: usize| i16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
        let u32_at = |offset: usize| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let u64_at = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        if lease.native_identity().allocation_generation != request.mdl_generation
            || i16_at(nt_mdl::MDL_OFF_SIZE as usize) != nt_mdl::MDL_SIZE as i16
            || i16_at(nt_mdl::MDL_OFF_FLAGS as usize)
                != (nt_mdl::MDL_MAPPED_TO_SYSTEM_VA | nt_mdl::MDL_PAGES_LOCKED)
            || u64_at(nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA as usize) != request.output_va
            || u64_at(nt_mdl::MDL_OFF_START_VA as usize) != request.output_va & !0xfff
            || u32_at(nt_mdl::MDL_OFF_BYTE_COUNT as usize) != request.output_capacity
            || u32_at(nt_mdl::MDL_OFF_BYTE_OFFSET as usize) != (request.output_va & 0xfff) as u32
        { return Err(STATUS_INVALID_PARAMETER); }
        Some(lease)
    };
    Ok(RootSource {
        internal: stack.major == major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
        irp, system_buffer, mdl,
    })
}

pub(super) enum Target {
    None,
    Stack { va: u64, alias: u64, len: u64 },
    Stable(crate::win32k_subsystem::file_ioctl_target::RootIoctlOutputTarget),
}

impl Target {
    pub(super) unsafe fn capture(route: Route, va: u64, len: u64) -> Option<Self> {
        if len == 0 {
            return Some(Self::None);
        }
        if let Some(alias) = crate::win32k_glue::win32k_stack_alias_for_route(route, va, len) {
            return Some(Self::Stack { va, alias, len });
        }
        crate::win32k_subsystem::file_ioctl_target::capture_root_output(va, len)
            .map(Self::Stable)
    }

    pub(super) unsafe fn address_if_live(&self, route: Route) -> Option<u64> {
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

pub(super) struct CanonicalEvent {
    pub(super) id: EventObjectId,
    lease: EventLeaseId,
    pub(super) local: u64,
    pub(super) provider: nt_provider_wait::ProviderDomainIdentity,
}

struct Work {
    route: Route,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    source_address: u64,
    source_ticket: u64,
    source_generation: u64,
    nonce: u64,
    code: u32,
    internal: bool,
    output_capacity: u32,
    output_va: u64,
    iosb_va: u64,
    source: RootSource,
    target: HostedForwardTarget,
    event: Option<CanonicalEvent>,
    packet_lease: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    packet: Vec<u8>,
    input: Vec<u8>,
    output: Vec<u8>,
    output_target: Target,
    iosb_target: Target,
    irp: Option<IrpId>,
    entered: bool,
    packet_prepared: bool,
    reply_entered: bool,
    reply_acked: bool,
    pending: bool,
    origin_armed: bool,
    terminal: Option<(u32, u64)>,
    output_captured: bool,
    terminal_claimed: bool,
    terminal_published: bool,
    terminal_handoff: bool,
    terminal_packet: Option<crate::win32k_subsystem::ProviderPoolPacketLease>,
    terminal_acknowledged: bool,
    origin_commit_requested: bool,
    origin_committed: bool,
    discarding: bool,
    event_claimed: bool,
    event_signaled: bool,
    event_barrier: Option<crate::source_event_completion::Barrier>,
    ack_claimed: bool,
    cancel_requested: bool,
    cancellation_terminal: bool,
    resources_claimed: bool,
    resources_committed: bool,
    indeterminate: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

pub(super) fn next_source_reply_token() -> Option<u64> {
    runtime::next_service_wait_token()
        .ok()
        .filter(|token| *token != 0)
}

fn wire_status(error: wire::WireError) -> i32 {
    match error {
        wire::WireError::BufferTooSmall | wire::WireError::LengthMismatch =>
            STATUS_INVALID_BUFFER_SIZE as i32,
        wire::WireError::Malformed => STATUS_INVALID_PARAMETER,
    }
}

pub(super) unsafe fn release_event(handler: *mut ExecNtHandler, event: CanonicalEvent) {
    if let Some(retired) = (*handler)
        .event_objects
        .release_wait(event.lease, EventLeaseKind::Operation)
        .expect("source IOCTL Event operation lease")
    {
        (*handler).finalize_retired_event_object(retired);
    }
}

pub(super) unsafe fn capture_event(
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
    if super::hosted_kernel_win32k_source_admission::contains(request.source_irp_va) {
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
    let source = match capture_source(&request) {
        Ok(source) => source,
        Err(status) => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered source IOCTL target");
            return Some(status);
        }
    };
    let output_target = if nt_io_abi::ioctl::method(request.code)
        == nt_io_abi::ioctl::METHOD_IN_DIRECT {
        Some(Target::None)
    } else {
        Target::capture(route, request.output_va, u64::from(request.output_capacity))
    };
    let iosb_target = Target::capture(route, request.iosb_va, 16);
    let (Some(output_target), Some(iosb_target)) = (output_target, iosb_target) else {
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered source IOCTL target");
        return Some(STATUS_INVALID_PARAMETER);
    };
    let mut input = Vec::new();
    let mut output = Vec::new();
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
        });
    if input.try_reserve_exact(request.input.len()).is_err()
        || output.try_reserve_exact(request.output_capacity as usize).is_err()
        || (slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err())
    {
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered source IOCTL target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    input.extend_from_slice(request.input);
    output.resize(request.output_capacity as usize, 0);
    if !request.output_initial.is_empty() {
        output.copy_from_slice(request.output_initial);
    }
    let token = match next_source_reply_token() {
        Some(token) => token,
        _ => {
            if let Some(event) = event.take() { release_event(handler, event); }
            target.release(io_manager_mut()).expect("unentered source IOCTL target");
            return Some(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let source_address = request.source_irp_va;
    let source_ticket = request.source_ticket_serial;
    let source_generation = request.native_allocation_generation;
    if !super::hosted_kernel_win32k_source_admission::register(
        route, source_address, source_ticket, source_generation,
    ) {
        if let Some(event) = event.take() { release_event(handler, event); }
        target.release(io_manager_mut()).expect("unentered source IOCTL target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let internal = source.internal;
    let work = Work {
        route, dispatch, reply, token, source_address, source_ticket, source_generation,
        nonce: request.nonce, code: request.code,
        internal,
        output_capacity: request.output_capacity, output_va: request.output_va,
        iosb_va: request.iosb_va,
        source, target, event,
        packet_lease: Some(packet_lease), packet, input, output, output_target, iosb_target,
        irp: None, entered: false, packet_prepared: false,
        reply_entered: false, reply_acked: false,
        pending: false, origin_armed: false, terminal: None, output_captured: false,
        terminal_claimed: false, terminal_published: false,
        terminal_handoff: false, terminal_packet: None, terminal_acknowledged: false, origin_commit_requested: false, origin_committed: false, discarding: false,
        event_claimed: false, event_signaled: false, event_barrier: None, ack_claimed: false,
        cancel_requested: false, cancellation_terminal: false,
        resources_claimed: false, resources_committed: false, indeterminate: false,
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
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .expect("unparked source IOCTL");
        if let Some(event) = work.event.take() { release_event(handler, event); }
        work.target.release(io_manager_mut()).expect("unparked source IOCTL target");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    None
}

pub(super) unsafe fn target_dispatch_ready(device_id: nt_io_manager::DeviceId) -> bool {
    let Some((target_index, _, _)) = hosted_driver_device_route_by_device_id(device_id.raw()) else {
        return true;
    };
    let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
        .map_or(target_index, |route| route.provider_instance);
    let Some(route) = hosted_ingress_sources::primary_route(provider_index) else { return true; };
    !matches!(runtime::ready_for_admission(route), Ok(false))
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
        kind: PendingSourceKind::Ioctl, nonce: work.nonce, token: work.token,
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
    unsafe fn ready_for_nested_step(&self) -> bool {
        use nt_io_manager::retained_source_progress::RetainedSourceProgress as Progress;
        let progress = if self.indeterminate {
            Progress::Indeterminate
        } else if runtime::retained_service_owner_stopped(self.route, self.dispatch, self.reply, self.token) {
            Progress::Stopped {
                cancellation_pending: self.irp.is_some() && !self.cancel_requested,
                completion_ready: self.irp.is_none_or(|irp| nested_device_control_completion_ready_exact(irp.raw())),
                broker_stopped: runtime::retained_service_owner_stopped_at_broker(
                    self.route, self.dispatch, self.reply, self.token,
                ) && self.event_barrier.is_none(),
                source_lane_ready: crate::win32k_glue::source_terminal_dispatch_ready(),
            }
        } else if !self.entered {
            Progress::AwaitingDispatch { provider_ready: target_dispatch_ready(self.target.device_id()) }
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
                completion_ready: self.irp.is_some_and(|irp| nested_device_control_completion_ready_exact(irp.raw())),
                cancellation_pending: false,
            }
        } else if !self.origin_committed {
            Progress::Terminal { source_lane_ready: crate::win32k_glue::source_terminal_dispatch_ready() }
        } else {
            Progress::Retirement
        };
        progress.ready_for_nested_step()
    }

    fn progress_state(&self) -> [u64; 16] {
        [self.entered as u64, self.pending as u64, self.reply_entered as u64,
            self.reply_acked as u64, self.terminal.is_some() as u64, self.output_captured as u64,
            self.terminal_acknowledged as u64, self.origin_commit_requested as u64,
            self.origin_committed as u64, self.event_claimed as u64, self.event_signaled as u64,
            self.ack_claimed as u64, self.cancel_requested as u64, self.resources_committed as u64,
            self.indeterminate as u64, self.terminal_packet.is_some() as u64]
    }

    fn completion_matches(&self, completion: &crate::driver_launch::HostedCompletedDeviceControlIrp) -> bool {
        let expected_major = if self.internal {
            major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        } else {
            major::IRP_MJ_DEVICE_CONTROL
        };
        completion.client_id == IO_MANAGER_COMPONENT_ID
            && completion.device_id == self.target.device_id().raw()
            && completion.major == expected_major
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
                let output_len = wire::completion_output_len(
                    self.code, status, information, self.output_capacity,
                );
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
        let Some(packet_lease) = self.packet_lease else { return false };
        if !crate::win32k_subsystem::publish_provider_pool_packet(
            packet_lease,
            &self.packet,
        ) {
            return false;
        }
        self.reply_entered = true;
        self.packet_lease = None;
        drop(core::mem::take(&mut self.packet));
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
        let length = wire::completion_output_len(
            self.code, status, information, self.output_capacity,
        );
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
        let length = wire::completion_output_len(
            self.code, status, information, self.output_capacity,
        );
        &self.output[..length]
    }

    unsafe fn deliver_terminal(&mut self) -> bool {
        if self.terminal_acknowledged { return true; }
        if self.indeterminate { return false; }
        let (status, information) = self.terminal.expect("source IOCTL terminal");
        if !self.terminal_handoff {
            if !self.source.live()
                || (!self.discarding && (self.output_target.address_if_live(self.route).is_none()
                    || self.iosb_target.address_if_live(self.route).is_none()))
            { return false; }
            let output = self.output_slice();
            let Ok(length) = wire::terminal_packet_len(output.len()) else { return false };
            let Some((lease, mut packet)) =
                crate::win32k_subsystem::allocate_root_provider_pool_packet(length)
            else { return false };
            let handoff = wire::SourceIoctlTerminalHandoff {
            delivery: if self.pending { wire::TerminalDelivery::Pending } else { wire::TerminalDelivery::Inline },
                nonce: self.nonce,
                token: self.token,
                source_irp_va: self.source_address,
                source_ticket_serial: self.source_ticket,
                native_allocation_generation: self.source_generation,
                code: self.code,
                iosb_va: self.iosb_va,
                output_va: self.output_va,
                output_capacity: self.output_capacity,
                status,
                information,
                output,
            };
            if wire::encode_terminal_handoff(handoff, &mut packet).is_err()
                || !crate::win32k_subsystem::publish_provider_pool_packet(lease, &packet)
            {
                if !crate::win32k_subsystem::retire_root_provider_pool_packet(lease) {
                    crate::provider_bugcheck::report(0xc4, [self.source_address, self.token, 0, 73]);
                }
                return false;
            }
            self.terminal_handoff = true;
            self.terminal_packet = Some(lease);
        }
        if self.discarding { return true; }
        let lease = self.terminal_packet.expect("retained IOCTL terminal packet");
        match crate::win32k_glue::dispatch_source_ioctl_terminal(
            lease.address(),
            wire::terminal_packet_len(self.output_slice().len()).unwrap() as u64,
        ) {
            crate::win32k_glue::SourceIoctlTerminalDispatch::NotEntered(_) => return false,
            crate::win32k_glue::SourceIoctlTerminalDispatch::Returned(status)
                if status == nt_io_manager::source_terminal::TERMINAL_NOT_READY => return false,
            crate::win32k_glue::SourceIoctlTerminalDispatch::Returned(0) => {}
            _ => { self.indeterminate = true; return false; }
        }
        let length = wire::terminal_packet_len(self.output_slice().len()).unwrap();
        let (actual, packet) = match crate::win32k_subsystem::capture_provider_pool_packet(
            lease.address(), length,
        ) {
            Ok(captured) => captured,
            Err(_) => { self.indeterminate = true; return false; }
        };
        let expected = wire::SourceIoctlTerminalHandoff {
            delivery: if self.pending { wire::TerminalDelivery::Pending } else { wire::TerminalDelivery::Inline },
            nonce: self.nonce, token: self.token,
            source_irp_va: self.source_address,
            source_ticket_serial: self.source_ticket,
            native_allocation_generation: self.source_generation,
            code: self.code, iosb_va: self.iosb_va,
            output_va: self.output_va, output_capacity: self.output_capacity,
            status, information, output: self.output_slice(),
        };
        if actual.native_identity() != lease.native_identity()
            || !matches!(wire::decode_terminal_ack(&packet), Ok(ack) if
                ack.handoff == expected && ack.publication == wire::TerminalPublication::Published)
        { self.indeterminate = true; return false; }
        self.terminal_acknowledged = true;
        true
    }

    unsafe fn accept_terminal_ack(&mut self) -> bool {
        if !self.terminal_acknowledged { return false; }
        if !self.terminal_published {
            if self.terminal_claimed { return false; }
            self.terminal_claimed = true;
            self.terminal_published = true;
        }
        true
    }

    unsafe fn signal_event(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.terminal_published || !self.terminal_acknowledged { return false; }
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
                let barrier = match crate::source_event_completion::capture(handler, event.id) {
                    Ok(barrier) => barrier,
                    Err(_) => return false,
                };
                self.event_barrier = Some(barrier);
                self.event_claimed = true;
            } else {
                self.event_claimed = true;
            }
            self.event_signaled = true;
        }
        true
    }

    unsafe fn commit_origin(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.indeterminate { return false; }
        if self.origin_committed { return self.event_barrier.is_none(); }
        if !self.terminal_acknowledged || !self.event_signaled { return false; }
        let length = wire::terminal_packet_len(self.output_slice().len()).unwrap();
        if !commit_origin_packet(
            &mut self.terminal_packet, length, 88,
            &mut self.origin_commit_requested, &mut self.indeterminate, false,
            self.event_barrier.map_or(0, |barrier| barrier.sequence()),
            crate::win32k_glue::dispatch_source_ioctl_terminal,
        ) { return false; }
        self.origin_committed = true;
        super::source_observability::origin(super::source_observability::Kind::Ioctl);
        if let Some(barrier) = self.event_barrier {
            if crate::source_event_completion::release(handler, barrier).is_err() {
                self.indeterminate = true;
                return false;
            }
            self.event_barrier = None;
        }
        true
    }

    unsafe fn commit_terminal(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.resources_committed { return true; }
        if !self.terminal_acknowledged
            || !self.terminal_published
            || self.target.validate(io_manager_mut()).is_err() { return false; }
        if let Some(irp) = self.irp {
            if self.ack_claimed { return false; }
            self.ack_claimed = true;
            if acknowledge_completed_irp_strict(irp.raw()).is_err() {
                return false;
            }
            super::source_observability::canonical(super::source_observability::Kind::Ioctl);
            self.irp = None;
        }
        if !self.signal_event(handler) || !self.commit_origin(handler) { return false; }
        if let Some(event) = self.event.take() { release_event(handler, event); }
        self.target.release(io_manager_mut()).expect("terminal source IOCTL target");
        self.resources_committed = true;
        true
    }

    unsafe fn retire(&mut self) -> bool {
        if !self.resources_committed || !self.reply_acked { return false; }
        runtime::retire_stopped_acknowledged_retained_service(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("source IOCTL Reply retirement");
        super::hosted_kernel_win32k_source_admission::retire(
            self.route, self.source_address, self.source_ticket, self.source_generation,
        );
        super::source_observability::retired(super::source_observability::Kind::Ioctl);
        true
    }

    unsafe fn finish_stopped(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.indeterminate { return false; }
        if let Some(irp) = self.irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            let Some(completion) = completed_device_control_irp_exact(irp.raw()) else { return false };
            if !self.completion_matches(&completion) {
                crate::provider_bugcheck::report(0xc4, [self.source_address, irp.raw(), 0, 94]);
            }
        }
        // Only a sealed stop while physically parked in this broker Call proves local guards
        // cannot be held. A stopped-running or whole-domain owner remains quarantined.
        if !runtime::retained_service_owner_stopped_at_broker(
            self.route, self.dispatch, self.reply, self.token,
        ) { return false; }
        if self.event_barrier.is_some() || self.resources_committed {
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
            let length = wire::terminal_packet_len(self.output_slice().len()).unwrap();
            if !commit_origin_packet(
                &mut self.terminal_packet, length, 88,
                &mut self.origin_commit_requested, &mut self.indeterminate, true, 0,
                crate::win32k_glue::dispatch_source_ioctl_terminal,
            ) { return false; }
            self.origin_committed = true;
        }
        if !self.resources_committed {
            if let Some(event) = self.event.take() { release_event(handler, event); }
            self.target.release(io_manager_mut()).expect("stopped source target");
            self.resources_committed = true;
        }
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
        if !self.entered {
            if !target_dispatch_ready(self.target.device_id()) { return false; }
            if !self.source.live() || self.target.validate(io_manager_mut()).is_err() {
                return false;
            }
            let aperture = if self.internal { Ok(()) } else {
                super::hosted_video_caller_aperture::prepare(
                    self.route, self.dispatch, self.reply, self.token, &self.target,
                    self.code, &self.input, self.output_capacity,
                )
            };
            self.entered = true;
            let result = if let Err(status) = aperture {
                Err(status)
            } else if self.internal {
                io_manager_mut().internal_device_control_exact_device(
                    ClientId(IO_MANAGER_COMPONENT_ID), self.target.device_id(), self.code,
                    &self.input, &mut self.output,
                )
            } else {
                io_manager_mut().device_control_exact_device(
                    ClientId(IO_MANAGER_COMPONENT_ID), self.target.device_id(), self.code,
                    &self.input, &mut self.output,
                )
            };
            match result {
                Ok(nt_io_manager::ExternalDispatchResult::Pending { irp_id }) => {
                    self.irp = Some(irp_id);
                    self.pending = true;
                }
                Ok(nt_io_manager::ExternalDispatchResult::Completed { status, information, .. }) => {
                    if status.is_success() {
                        super::source_observability::terminal(super::source_observability::Kind::Ioctl, self.code);
                    }
                    super::source_observability::canonical(super::source_observability::Kind::Ioctl);
                    self.terminal = Some((status.raw() as u32, information));
                }
                Err(status) => self.terminal = Some((status.raw() as u32, 0)),
            }
        }
        if self.pending && !self.reply_entered {
            return self.publish_reply(STATUS_PENDING as u32);
        }
        if !self.pending && !self.reply_entered {
            if !self.capture_output() || !self.deliver_terminal()
                || !self.accept_terminal_ack() || !self.commit_terminal(handler) {
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
        if self.pending && !self.origin_armed { return false; }
        if self.pending && self.terminal.is_none() {
            let Some(irp) = self.irp else { return false };
            let Some(completion) = completed_device_control_irp_exact(irp.raw()) else {
                return false;
            };
            if !self.completion_matches(&completion) {
                crate::provider_bugcheck::report(0xc4, [self.source_address, irp.raw(), 0, 5]);
            }
            self.terminal = Some((completion.status, completion.information));
            super::source_observability::terminal(super::source_observability::Kind::Ioctl, self.code);
        }
        if self.pending && (!self.capture_output() || !self.deliver_terminal()
            || !self.accept_terminal_ack() || !self.commit_terminal(handler)) {
            return false;
        }
        self.retire()
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
