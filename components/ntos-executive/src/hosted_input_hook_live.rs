//! Live reverse HOOK routing for i8042's queued CONNECT work item.
//!
//! The port-owned IRP enters a class PortDO. ReactOS class drivers forward that same IRP to
//! their lower port alias, so the two calls are separate source completions. The temporary
//! class Type3InputBuffer stays pinned until its lower-edge source ACK. The original port IRP
//! stays pinned until its own source ACK after the class terminal.

use super::*;
use alloc::boxed::Box;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::detached_file_irp::{
    ExternalFileIrpPumpKey, ExternalFileIrpRequest,
};
use nt_io_manager::hosted_forward_progress::HostedForwardDispatchReply;
use nt_io_manager::{DeviceControlParameters, IoParameters};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;
use nt_types::ClientId;

const INVALID: i32 = 0xc000_0010u32 as i32;
const BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();
static HOOK_PORT_TRACE_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
const HOOK_PORT_TRACE_LIMIT: u64 = 192;

#[derive(Clone, Copy)]
struct ActiveClassDispatch {
    owner_id: u64,
    class_target: nt_io_manager::HostedDevicePointerRegistration,
    class_source: nt_io_manager::HostedDevicePointerRegistration,
    port_device: nt_io_manager::HostedDevicePointerRegistration,
    control_code: u32,
    input_length: usize,
    input: [u8; 48],
}

struct ActivePortDispatch {
    target: nt_io_manager::HostedDevicePointerRegistration,
    control_code: u32,
}

#[derive(Clone, Copy)]
struct PortTerminalCandidate {
    status: nt_status::NtStatus,
    updated: [u8; 48],
    completed: Option<IrpId>,
}

struct PortSource {
    source: hosted_input_hook_dispatch::HookWork,
    instance: DriverInstance,
    irp: u64,
    device: u64,
    owner_id: u64,
    input_length: usize,
    origin: hosted_forward_origin::HostedForwardOrigin,
    caller: nt_process::native_handle::NativeHandleCaller,
    entered: bool,
    pending: Option<IrpId>,
    pump_key: Option<ExternalFileIrpPumpKey>,
    file_owner_row_id: Option<u64>,
    pump_return_consumed: bool,
    class_alias: Option<ActiveClassDispatch>,
    unowned_yield: Option<hosted_file_owners::HookDispatchFailure>,
    terminal_candidate: Option<PortTerminalCandidate>,
    terminal_observed: Option<nt_status::NtStatus>,
    terminal_status: Option<nt_status::NtStatus>,
    published: bool,
    blocked: bool,
    source_retired: bool,
}

struct ClassSource {
    class_index: usize,
    instance: DriverInstance,
    irp: u64,
    device: u64,
    pin: hosted_device_allocations::TemporaryPoolPin,
    source_ticket: nt_io_manager::retained_query_path_forward::SourceIrpTicket,
    source_allocation: nt_io_manager::source_irp_ledger::SourceIrpAllocation,
    owner_id: u64,
    port_device: nt_io_manager::HostedDevicePointerRegistration,
    control_code: u32,
    input_length: usize,
    input: [u8; 48],
    input_pointer: u64,
    origin: hosted_forward_origin::HostedForwardOrigin,
    caller: nt_process::native_handle::NativeHandleCaller,
    entered: bool,
    pending: Option<IrpId>,
    pump_key: Option<ExternalFileIrpPumpKey>,
    file_owner_row_id: Option<u64>,
    pump_return_consumed: bool,
    unowned_yield: Option<hosted_file_owners::HookDispatchFailure>,
    returned_terminal: Option<PortTerminalCandidate>,
    terminal_status: Option<nt_status::NtStatus>,
    published: bool,
    canonical_acknowledged: bool,
    pin_released: bool,
    source_released: bool,
}

static mut ACTIVE_CLASS_DISPATCH: Vec<ActiveClassDispatch> = Vec::new();
static mut ACTIVE_PORT_DISPATCH: Vec<ActivePortDispatch> = Vec::new();
static mut PORT_SOURCES: Vec<Box<PortSource>> = Vec::new();
static mut CLASS_SOURCES: Vec<Box<ClassSource>> = Vec::new();

fn active() -> &'static mut Vec<ActiveClassDispatch> {
    unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE_CLASS_DISPATCH) }
}

fn active_port() -> &'static mut Vec<ActivePortDispatch> {
    unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE_PORT_DISPATCH) }
}

enum HookAliasKind { Class(u64), Port(nt_io_manager::HostedDevicePointerRegistration) }

struct HookAliasGuard(HookAliasKind);

impl Drop for HookAliasGuard {
    fn drop(&mut self) {
        match self.0 {
            HookAliasKind::Class(owner_id) => {
                if active().pop().is_none_or(|alias| alias.owner_id != owner_id) {
                    unsafe { crate::provider_bugcheck::report(0xc4, [owner_id, 0, 0, 0]); }
                }
            }
            HookAliasKind::Port(target) => {
                if active_port().pop().is_none_or(|alias| alias.target != target) {
                    unsafe { crate::provider_bugcheck::report(0xc4, [target.address(), 0, 0, 0]); }
                }
            }
        }
    }
}

/// Restore only the callback alias bound to this exact suspended File IRP and physical pump key.
/// The alias is visible while native receive runs, then removed even on an early return.
pub(super) unsafe fn with_suspended_hook_alias<R>(
    irp_id: IrpId,
    key: ExternalFileIrpPumpKey,
    owner_id: u64,
    device: nt_io_manager::DeviceId,
    resume: impl FnOnce() -> R,
) -> Result<R, nt_status::NtStatus> {
    if let Some(alias) = port_sources().iter().find_map(|work| {
        (work.pending == Some(irp_id) && work.pump_key == Some(key)
            && work.owner_id == owner_id && !work.blocked)
            .then_some(work.class_alias).flatten()
    }) {
        let prepared = hosted_reverse_class_projection::validate(owner_id)
            .map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
        if alias.class_target.device_id() != device
            || alias.class_target != prepared.port_do_registration
            || alias.class_source != prepared.source_port_do_registration
            || hosted_reverse_class_projection::port_source_for_hook(owner_id)
                != Ok(alias.port_device)
            || !active().is_empty()
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        active().try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        active().push(alias);
        let _alias = HookAliasGuard(HookAliasKind::Class(owner_id));
        return Ok(resume());
    }
    if let Some(work) = class_sources().iter().find(|work| {
        work.pending == Some(irp_id) && work.pump_key == Some(key)
            && work.owner_id == owner_id && work.port_device.device_id() == device
    }) {
        let target = work.port_device;
        let control_code = work.control_code;
        if hosted_reverse_class_projection::validate(owner_id).is_err()
            || hosted_reverse_class_projection::port_source_for_hook(owner_id) != Ok(target)
            || !active_port().is_empty()
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        active_port().try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        active_port().push(ActivePortDispatch { target, control_code });
        let _alias = HookAliasGuard(HookAliasKind::Port(target));
        return Ok(resume());
    }
    Err(nt_status::NtStatus::INVALID_HANDLE)
}

pub(super) fn class_dispatch_active(
    target: nt_io_manager::DeviceId, control_code: u64,
) -> bool {
    active().last().is_some_and(|row| {
        row.class_target.device_id() == target && u64::from(row.control_code) == control_code
    }) || active_port().last().is_some_and(|row| {
        row.target.device_id() == target && u64::from(row.control_code) == control_code
    })
}

fn port_sources() -> &'static mut Vec<Box<PortSource>> {
    unsafe { &mut *core::ptr::addr_of_mut!(PORT_SOURCES) }
}

/// Capped source-side evidence for the exact port HOOK owner. Phase bits are
/// entered/pending/candidate/observed/terminal/published/blocked/pump-returned.
fn trace_port_source(stage: u64, work: &PortSource, detail: u64) {
    if HOOK_PORT_TRACE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        >= HOOK_PORT_TRACE_LIMIT
    {
        return;
    }
    let phase = u64::from(work.entered)
        | (u64::from(work.pending.is_some()) << 1)
        | (u64::from(work.terminal_candidate.is_some()) << 2)
        | (u64::from(work.terminal_observed.is_some()) << 3)
        | (u64::from(work.terminal_status.is_some()) << 4)
        | (u64::from(work.published) << 5)
        | (u64::from(work.blocked) << 6)
        | (u64::from(work.pump_return_consumed) << 7);
    print_str(b"[hook-port-source] stage/owner/source-irp/file-irp/phase/status/obs-retry/pub-retry/detail=");
    print_u64(stage);
    print_str(b"/"); print_u64(work.owner_id);
    print_str(b"/0x"); print_hex_u64(work.source.source_irp_address());
    print_str(b"/0x"); print_hex_u64(work.pending.map_or(0, |id| id.raw()));
    print_str(b"/0x"); print_hex_u64(phase);
    print_str(b"/0x"); print_hex_u64(work.terminal_candidate.map_or(0,
        |candidate| candidate.status.raw() as u32 as u64));
    print_str(b"/"); print_u64(u64::from(work.source.terminal_observation_retryable()));
    print_str(b"/"); print_u64(u64::from(work.source.terminal_publication_retryable()));
    print_str(b"/0x"); print_hex_u64(detail);
    print_str(b"\n");
}

/// Dispatch kind: 1 returned, 2 outstanding, 3 suspended, 4 status refusal,
/// 5 unowned yield, 6 unexpected returned shape. A key bit records presence;
/// the exact IRP and owner are printed without inspecting provider-owned memory.
fn trace_port_dispatch(
    stage: u64, work: &PortSource, kind: u64, irp: u64, key: bool,
    status: u64, information: u64,
) {
    if HOOK_PORT_TRACE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
        >= HOOK_PORT_TRACE_LIMIT
    {
        return;
    }
    print_str(b"[hook-port-dispatch] stage/owner/source-irp/irp/kind/key/status/info=");
    print_u64(stage);
    print_str(b"/"); print_u64(work.owner_id);
    print_str(b"/0x"); print_hex_u64(work.source.source_irp_address());
    print_str(b"/0x"); print_hex_u64(irp);
    print_str(b"/"); print_u64(kind);
    print_str(b"/"); print_u64(u64::from(key));
    print_str(b"/0x"); print_hex_u64(status);
    print_str(b"/0x"); print_hex_u64(information);
    print_str(b"\n");
}

fn trace_class_source(stage: u64, work: &ClassSource, target: u64) {
    static CLASS_TRACE_COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if CLASS_TRACE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) >= 96
    {
        return;
    }
    print_str(b"[hook-class-source] stage/owner/source-irp/file-irp/target/published=");
    print_u64(stage);
    print_str(b"/"); print_u64(work.owner_id);
    print_str(b"/0x"); print_hex_u64(work.irp);
    print_str(b"/0x"); print_hex_u64(work.pending.map_or(0, |id| id.raw()));
    print_str(b"/0x"); print_hex_u64(target);
    print_str(b"/"); print_u64(u64::from(work.published));
    print_str(b"\n");
}

fn class_sources() -> &'static mut Vec<Box<ClassSource>> {
    unsafe { &mut *core::ptr::addr_of_mut!(CLASS_SOURCES) }
}

fn same_instance(a: DriverInstance, b: DriverInstance) -> bool {
    a.pml4 == b.pml4
        && a.exec_pool_va == b.exec_pool_va
        && a.hosted_domain_id == b.hosted_domain_id
        && a.hosted_domain_cookie == b.hosted_domain_cookie
}

unsafe fn park_source(
    ch: &crate::spawn_hosts::PumpChannel,
) -> Result<(hosted_forward_origin::HostedForwardOrigin,
    nt_process::native_handle::NativeHandleCaller), nt_status::NtStatus> {
    let route = runtime::channel_route(ch).ok().flatten()
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let dispatch = runtime::dispatch(route).map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
    let reply = runtime::current_reply(route).map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
    let token = runtime::next_service_wait_token()
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let caller = crate::provider_registry_caller::resolve(ch)
        .map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
    runtime::park_retained_service(route, token)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    Ok((hosted_forward_origin::HostedForwardOrigin::new(route, dispatch, reply, token), caller))
}

unsafe fn class_lower_input(
    inst: DriverInstance,
    class_port: u64,
    irp: u64,
    expected_code: u32,
    expected_len: usize,
    expected: &[u8],
) -> Result<(u64, hosted_device_allocations::TemporaryPoolPin), nt_status::NtStatus> {
    let memory = hosted_source_pool_memory::SourcePoolMemory::new(inst)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let packet = memory.read_value::<Irp>(irp)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let stack_count = u64::try_from(packet.stack_count)
        .map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
    let packet_bytes = (WDM_X64_IRP_SIZE as u64)
        .checked_add(stack_count * WDM_X64_IO_STACK_LOCATION_SIZE as u64)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if packet.type_ != WDM_X64_IO_TYPE_IRP as i16
        || stack_count == 0
        || packet_bytes != u64::from(packet.size)
        || packet.current_location < 2
        || u64::try_from(packet.current_location).ok()
            .is_none_or(|location| location > stack_count + 1)
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    // ForwardIrpAndForget calls IoSkipCurrentIrpStackLocation: it advances the IRP's cursor
    // without copying the class frame. At this point the next frame still names the exact
    // class PortDO; IofCallDriver writes the authenticated lower alias after this service ACK.
    let current_location = u64::try_from(packet.current_location)
        .map_err(|_| nt_status::NtStatus::INVALID_HANDLE)?;
    let exact_cursor = irp
        .checked_add(WDM_X64_IRP_SIZE as u64)
        .and_then(|base| base.checked_add(
            (current_location - 1) * WDM_X64_IO_STACK_LOCATION_SIZE as u64,
        ))
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if packet.current_stack_location.0 != exact_cursor {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let stack = exact_cursor
        .checked_sub(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if stack < irp + WDM_X64_IRP_SIZE as u64
        || stack + WDM_X64_IO_STACK_LOCATION_SIZE as u64 > irp + packet_bytes
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let location = memory.read_value::<IoStackLocation>(stack)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let params = location.device_io_control();
    if location.major_function != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        || location.minor_function != 0
        || location.file_object.0 != 0
        || location.device_object.0 != class_port
        || params.io_control_code != expected_code
        || params.input_buffer_length as usize != expected_len
        || params.output_buffer_length != 0
        || params.type3_input_buffer.0 == 0
        || packet.mdl_address.0 != 0
        || packet.associated_irp_system_buffer.0 != 0
        || packet.user_buffer.0 != 0
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let mut bytes = [0u8; 48];
    if !memory.read(params.type3_input_buffer.0, &mut bytes[..expected_len])
        || &bytes[..expected_len] != expected
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    drop(memory);
    let pin = hosted_device_allocations::pin_temporary_pool_range(
        inst, params.type3_input_buffer.0, expected_len as u64,
    )?;
    Ok((params.type3_input_buffer.0, pin))
}

unsafe fn dispatch_class_lower(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    device: u64,
    irp: u64,
) -> Option<(i32, bool)> {
    let (class_index, inst) = instance_for_pump_channel(ch, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    let Ok(Some(port_device)) =
        hosted_upper_filter_projection::entered_lower_origin_registration(domain, device)
    else {
        return Some((INVALID, false));
    };
    let mut candidates = active().iter().filter(|row| {
        row.class_source.domain() == domain && row.port_device == port_device
    });
    let Some(candidate) = candidates.next() else {
        return Some((INVALID, false));
    };
    if candidates.next().is_some() {
        return Some((BUSY, false));
    }
    let owner_id = candidate.owner_id;
    let control_code = candidate.control_code;
    let input_length = candidate.input_length;
    let input = candidate.input;
    let class_port = candidate.class_source.address();
    let class_target = candidate.class_target;
    if !hosted_reverse_class_projection::validate(owner_id).is_ok_and(|prepared| {
        prepared.port_do_registration == class_target
            && prepared.source_port_do_registration == candidate.class_source
    })
        || class_sources().iter().any(|row| same_instance(row.instance, inst) && row.irp == irp)
    {
        return Some((BUSY, false));
    }
    if read_volatile((ch.shared_va + SH_ACTIVE_IRP) as *const u64) != irp {
        return Some((INVALID, false));
    }
    let Some(canonical_id) =
        hosted_file_owners::unique_executing_device_irp(class_target.device_id())
    else {
        return Some((BUSY, false));
    };
    let Some((source_ticket, source_allocation)) =
        hosted_source_irp_ledger::pin(class_index, domain, irp)
    else {
        return Some((INVALID, false));
    };
    if !hosted_source_irp_ledger::active_caller_internal_control_matches(
        class_index, canonical_id.raw(), irp, source_ticket, source_allocation,
    ) {
        let _ = hosted_source_irp_ledger::unpin(source_ticket);
        return Some((INVALID, false));
    }
    let (input_pointer, mut pin) =
        match class_lower_input(inst, class_port, irp, control_code, input_length, &input[..input_length]) {
            Ok(result) => result,
            Err(status) => {
                let _ = hosted_source_irp_ledger::unpin(source_ticket);
                return Some((status.raw(), false));
            }
        };
    if class_sources().try_reserve(1).is_err() {
        let _ = hosted_device_allocations::release_temporary_pool_pin(&mut pin);
        let _ = hosted_source_irp_ledger::unpin(source_ticket);
        return Some((nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw(), false));
    }
    let (origin, caller) = match park_source(ch) {
        Ok(owned) => owned,
        Err(status) => {
            let _ = hosted_device_allocations::release_temporary_pool_pin(&mut pin);
            let _ = hosted_source_irp_ledger::unpin(source_ticket);
            return Some((status.raw(), false));
        }
    };
    class_sources().push(Box::new(ClassSource {
        class_index, instance: inst, irp, device, pin, source_ticket, source_allocation,
        owner_id, port_device, control_code,
        input_length, input,
        input_pointer, origin, caller, entered: false, pending: None,
        pump_key: None, file_owner_row_id: None,
        pump_return_consumed: false, unowned_yield: None,
        returned_terminal: None,
        terminal_status: None, published: false,
        canonical_acknowledged: false, pin_released: false, source_released: false,
    }));
    None
}

unsafe fn dispatch_port_source(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    device: u64,
    irp: u64,
) -> Option<(i32, bool)> {
    let (_, inst) = instance_for_pump_channel(ch, reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    let (owner_id, connect) = hosted_connect_live::lookup_hook_owner(domain, device)?;
    if port_sources().iter().any(|row| same_instance(row.instance, inst) && row.irp == irp) {
        return Some((BUSY, false));
    }
    let mut source = match hosted_input_hook_dispatch::HookWork::capture(
        ch, reply_cap, irp, device, owner_id, connect,
    ) {
        Ok(source) => source,
        Err(_) => return Some((INVALID, false)),
    };
    if active().try_reserve(1).is_err() || port_sources().try_reserve(1).is_err() {
        if source.abort_unentered().is_err() { core::mem::forget(source); }
        return Some((nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw(), false));
    }
    let (origin, caller) = match park_source(ch) {
        Ok(owned) => owned,
        Err(status) => {
            if source.abort_unentered().is_err() { core::mem::forget(source); }
            return Some((status.raw(), false));
        }
    };
    let input_length = match connect.forward.control {
        nt_io_manager::retained_connect_forward::ConnectControl::Keyboard => 48,
        nt_io_manager::retained_connect_forward::ConnectControl::Mouse => 40,
    };
    port_sources().push(Box::new(PortSource {
        source, instance: inst, irp, device, owner_id, input_length, origin, caller, entered: false,
        pending: None, pump_key: None, file_owner_row_id: None,
        pump_return_consumed: false,
        class_alias: None, unowned_yield: None,
        terminal_candidate: None, terminal_observed: None,
        terminal_status: None, published: false,
        blocked: false, source_retired: false,
    }));
    super::mark_hook_source_completion_probe(irp);
    None
}

fn hook_request(
    caller: nt_process::native_handle::NativeHandleCaller,
    device: nt_io_manager::HostedDevicePointerRegistration,
    code: u32,
    length: usize,
) -> ExternalFileIrpRequest {
    ExternalFileIrpRequest {
        client: ClientId(IO_MANAGER_COMPONENT_ID),
        device_id: device.device_id(),
        file_id: None,
        user_data: 0,
        requestor_tid: u64::from(caller.original_thread().thread_id()),
        major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
        parameters: IoParameters::InternalDeviceControl(DeviceControlParameters {
            ioctl_code: code,
            input_len: length as u32,
            output_len: 0,
        }),
        stack_flags: StackFlags::empty(),
        initial_information: 0,
    }
}

unsafe fn class_terminal(
    work: &mut ClassSource,
    status: nt_status::NtStatus,
    bytes: &[u8],
) {
    if status == nt_status::NtStatus::PENDING || bytes.len() != work.input_length {
        return;
    }
    let offset = work.input_pointer - work.pin.allocation().component_address;
    if hosted_device_allocations::write_temporary_pool_pin(&work.pin, offset, bytes).is_err() {
        hosted_device_allocations::retain_temporary_pool_pin_uncertain(&work.pin);
        return;
    }
    let Some(memory) = hosted_source_pool_memory::SourcePoolMemory::new(work.instance) else {
        hosted_device_allocations::retain_temporary_pool_pin_uncertain(&work.pin);
        return;
    };
    if !memory.write(
        work.irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET as u64,
        &(status.raw() as u32).to_le_bytes(),
    ) || !memory.write(
        work.irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET as u64,
        &0u64.to_le_bytes(),
    ) {
        hosted_device_allocations::retain_temporary_pool_pin_uncertain(&work.pin);
        return;
    }
    work.terminal_status = Some(status);
}

unsafe fn advance_class_source(work: &mut ClassSource) {
    if work.published { return; }
    if !work.entered {
        if hosted_reverse_class_projection::validate(work.owner_id).is_err()
            || hosted_reverse_class_projection::port_source_for_hook(work.owner_id)
                != Ok(work.port_device)
        { return; }
        let Some((port_index, port_instance, _)) =
            hosted_driver_device_route_by_device_id(work.port_device.device_id().raw())
        else { return; };
        if instance_domain_identity(port_instance) != Some(work.port_device.domain())
            || hosted_class_irp_lane::prepare(port_index).is_err()
            || hosted_class_irp_lane::select_new(port_index).is_none()
            || active_port().try_reserve(1).is_err()
        { return; }
        work.entered = true;
        active_port().push(ActivePortDispatch {
            target: work.port_device,
            control_code: work.control_code,
        });
        trace_class_source(40, work, work.port_device.device_id().raw());
        let result = hosted_file_owners::dispatch_mutable_method_neither_suspend_aware(
            work.caller,
            hook_request(work.caller, work.port_device, work.control_code, work.input_length),
            &work.input[..work.input_length],
            work.port_device.device_id(), work.owner_id,
        );
        trace_class_source(41, work, work.port_device.device_id().raw());
        assert_eq!(active_port().pop().map(|row| row.target), Some(work.port_device));
        trace_class_source(42, work, work.port_device.device_id().raw());
        match result {
            Ok(hosted_file_owners::HookDispatchResult::Returned(
                hosted_file_owners::DispatchResult::Returned {
                status, information: 0, buffers, ..
            })) => {
                let (updated, _) = buffers.into_parts();
                trace_class_source(43, work, work.port_device.device_id().raw());
                class_terminal(work, status, &updated);
                trace_class_source(44, work, work.port_device.device_id().raw());
            }
            Ok(hosted_file_owners::HookDispatchResult::Returned(
                hosted_file_owners::DispatchResult::Outstanding { irp_id })) => {
                work.pending = Some(irp_id);
            }
            Ok(hosted_file_owners::HookDispatchResult::PumpSuspended { irp_id, key }) => {
                work.pending = Some(irp_id);
                work.pump_key = Some(key);
                work.file_owner_row_id = hosted_file_owners::hook_pump_owner_row_id(
                    irp_id, key, work.owner_id, work.port_device.device_id(),
                ).ok();
            }
            Err(hosted_file_owners::HookDispatchFailure::Status(status)) => {
                // Dispatch errors are pre-entry. Complete the parked lower-edge source with
                // its original input; an accepted or uncertain effect remains Outstanding.
                let input = work.input;
                let length = work.input_length;
                class_terminal(work, status, &input[..length]);
            }
            Err(failure @ hosted_file_owners::HookDispatchFailure::UnownedYield { .. }) => {
                work.unowned_yield = Some(failure);
                return;
            }
            Ok(_) => return,
        }
    }
    if let Some(irp_id) = work.pending {
        if let Some(key) = work.pump_key {
            match hosted_file_owners::hook_pump_state(
                irp_id, key, work.owner_id, work.port_device.device_id(),
            ) {
                Ok(hosted_file_owners::HookPumpState::Suspended) => return,
                Ok(hosted_file_owners::HookPumpState::Blocked) | Err(_) => return,
                Ok(hosted_file_owners::HookPumpState::Pending) => work.pump_key = None,
                Ok(hosted_file_owners::HookPumpState::Returned) => {
                    if work.returned_terminal.is_none() {
                        let mut updated = [0u8; 48];
                        let Ok(Some((status, 0, _))) =
                            hosted_file_owners::peek_returned_hook_pump(
                                irp_id, key, work.owner_id, work.port_device.device_id(),
                                &mut updated[..work.input_length],
                            ) else { return; };
                        work.returned_terminal = Some(PortTerminalCandidate {
                            status, updated, completed: Some(irp_id),
                        });
                    }
                    let candidate = work.returned_terminal.expect("peeked exact Hook terminal");
                    if work.terminal_status.is_none() {
                        class_terminal(work, candidate.status,
                            &candidate.updated[..work.input_length]);
                    }
                    if work.terminal_status != Some(candidate.status)
                        || hosted_file_owners::mark_returned_hook_pump_observed(
                            irp_id, key, work.owner_id, work.port_device.device_id(),
                        ).is_err()
                    { return; }
                    let Ok(Some(hosted_file_owners::DispatchResult::Returned {
                        status, information: 0, buffers, ..
                    })) = hosted_file_owners::take_returned_hook_pump(
                        irp_id, key, work.owner_id, work.port_device.device_id(),
                    ) else { return; };
                    let (updated, _) = buffers.into_parts();
                    work.pump_return_consumed = true;
                    if status != candidate.status
                        || updated.as_slice() != &candidate.updated[..work.input_length]
                    { return; }
                    work.pump_key = None;
                    work.canonical_acknowledged = true;
                }
            }
        }
    }
    if work.terminal_status.is_none() {
        let Some(irp_id) = work.pending else { return; };
        let Ok(completion) = hosted_file_owners::completion(irp_id) else { return; };
        if completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            || completion.device_id != work.port_device.device_id()
            || completion.information != 0
            || completion.status == nt_status::NtStatus::PENDING
        {
            return;
        }
        let mut updated = [0u8; 48];
        if hosted_file_owners::copy_mutable_input(
            irp_id, 0, &mut updated[..work.input_length],
        ) != Ok(work.input_length) {
            return;
        }
        class_terminal(work, completion.status,
            &updated[..work.input_length]);
    }
    if work.pump_key.is_some() { return; }
    if let Some(status) = work.terminal_status {
        // Release the mutable input exclusion before the source Reply. Keep the exact FSD
        // caller IRP ticket until its lower-edge source completion has been acknowledged.
        if !work.pin_released {
            if hosted_device_allocations::release_temporary_pool_pin(&mut work.pin).is_err() {
                return;
            }
            work.pin_released = true;
        }
        trace_class_source(45, work, work.port_device.device_id().raw());
        work.published = work.origin.reply_dispatch(
            HostedForwardDispatchReply::InlineTerminal(status.raw()), true,
        );
        trace_class_source(46, work, work.port_device.device_id().raw());
    }
}

unsafe fn stage_port_terminal(
    work: &mut PortSource,
    status: nt_status::NtStatus,
    updated: &[u8],
    completed: Option<IrpId>,
) {
    trace_port_source(10, work, completed.map_or(0, |id| id.raw()));
    if updated.len() != work.input_length || work.terminal_candidate.is_some() {
        trace_port_source(11, work, updated.len() as u64);
        work.blocked = true;
        return;
    }
    let mut bytes = [0; 48];
    bytes[..updated.len()].copy_from_slice(updated);
    work.terminal_candidate = Some(PortTerminalCandidate {
        status, updated: bytes, completed,
    });
    trace_port_source(12, work, updated.len() as u64);
}

unsafe fn advance_port_terminal(work: &mut PortSource) {
    let Some(candidate) = work.terminal_candidate else { return; };
    trace_port_source(20, work, candidate.completed.map_or(0, |id| id.raw()));
    let status = candidate.status;
    if work.terminal_observed.is_none() {
        trace_port_source(21, work, work.origin.token);
        let outcome = hosted_connect_live::with_hook_sequence(work.owner_id, |_, sequence| {
            work.source.observe_terminal(sequence, status,
                &candidate.updated[..work.input_length], candidate.completed)
        });
        let observation = match &outcome {
            None => 0,
            Some(Ok(_)) => 1,
            Some(Err(hosted_input_hook_dispatch::HookError::WrongCaller)) => 2,
            Some(Err(hosted_input_hook_dispatch::HookError::WrongSource)) => 3,
            Some(Err(hosted_input_hook_dispatch::HookError::WrongAlias)) => 4,
            Some(Err(hosted_input_hook_dispatch::HookError::WrongPayload)) => 5,
            Some(Err(hosted_input_hook_dispatch::HookError::WrongPhase)) => 6,
        };
        trace_port_source(22, work, observation);
        if outcome != Some(Ok((work.source.source_identity(), status))) {
            work.blocked = !work.source.terminal_observation_retryable();
            trace_port_source(23, work, observation);
            return;
        }
        work.terminal_observed = Some(status);
        trace_port_source(24, work, status.raw() as u32 as u64);
    }
    if work.terminal_observed != Some(status) {
        work.blocked = true;
        return;
    }
    if let Some(key) = work.pump_key {
        let Some(irp_id) = work.pending else { work.blocked = true; return; };
        if hosted_file_owners::mark_returned_hook_pump_observed(
            irp_id, key, work.owner_id, work.source.class_target_registration().device_id(),
        ).is_err() { return; }
        let Ok(Some(hosted_file_owners::DispatchResult::Returned {
            irp_id: retired_irp, status: returned_status, information: 0, buffers, ..
        })) = hosted_file_owners::take_returned_hook_pump(
            irp_id, key, work.owner_id, work.source.class_target_registration().device_id(),
        ) else { return; };
        if !work.source.record_returned_file_retirement(retired_irp) {
            work.blocked = true;
            return;
        }
        let (updated, _) = buffers.into_parts();
        work.pump_return_consumed = true;
        if returned_status != status || updated.as_slice() != &candidate.updated[..work.input_length] {
            work.blocked = true;
            return;
        }
        work.pump_key = None;
    }
    trace_port_source(30, work, status.raw() as u32 as u64);
    if work.source.publish_source_terminal().is_err() {
        // A pre-effect lock refusal leaves Phase::Terminal and can be redriven. A failed
        // native write or deferred-free arm is indeterminate and must never be replayed.
        work.blocked = !work.source.terminal_publication_retryable();
        trace_port_source(31, work, u64::from(work.blocked));
        return;
    }
    work.terminal_status = Some(status);
    trace_port_source(32, work, status.raw() as u32 as u64);
}

unsafe fn advance_port_source(work: &mut PortSource) {
    if work.published || work.blocked { return; }
    if !work.entered {
        // Construct and authenticate a separate class worker before committing the HOOK source
        // sequence. Kbdclass's primary AddDevice thread still owns its parked request bank.
        let class_target = work.source.class_target_registration();
        let Ok(prepared) = hosted_reverse_class_projection::validate(work.owner_id)
        else { return; };
        if prepared.port_do_registration != class_target { return; }
        let Some((class_index, class_instance, _)) =
            hosted_driver_device_route_by_device_id(class_target.device_id().raw())
        else { return; };
        if instance_domain_identity(class_instance)
            != Some(prepared.source_port_do_registration.domain())
            || class_target.device_id() != prepared.source_port_do_registration.device_id()
        { return; }
        let Ok(port_device) = hosted_reverse_class_projection::port_source_for_hook(work.owner_id)
        else { return; };
        if hosted_class_irp_lane::prepare(class_index).is_err() { return; }
        // Bootstrap settles the worker's READY protocol, but admission still needs its held
        // Call, replacement Reply capacity, and idle lane. Keep the source unentered until ready.
        if hosted_class_irp_lane::select_new(class_index).is_none() { return; }
        let ticket = match hosted_connect_live::with_hook_sequence(work.owner_id, |forward, sequence| {
            work.source.begin_dispatch(forward, sequence)
        }) {
            Some(Ok(ticket)) => ticket,
            _ => return,
        };
        work.entered = true;
        let class_alias = ActiveClassDispatch {
            owner_id: work.owner_id,
            class_target: ticket.target,
            class_source: prepared.source_port_do_registration,
            port_device,
            control_code: ticket.control_code,
            input_length: ticket.input_length as usize,
            input: ticket.input,
        };
        work.class_alias = Some(class_alias);
        active().push(class_alias);
        trace_port_source(40, work, ticket.target.device_id().raw());
        let result = hosted_file_owners::dispatch_mutable_method_neither_suspend_aware(
            work.caller,
            hook_request(work.caller, ticket.target, ticket.control_code,
                ticket.input_length as usize),
            &ticket.input[..ticket.input_length as usize],
            ticket.target.device_id(), work.owner_id,
        );
        trace_port_source(41, work, ticket.target.device_id().raw());
        assert_eq!(active().pop().map(|row| row.owner_id), Some(work.owner_id));
        trace_port_source(42, work, ticket.target.device_id().raw());
        match result {
            Ok(hosted_file_owners::HookDispatchResult::Returned(
                hosted_file_owners::DispatchResult::Returned {
                irp_id, status, information: 0, buffers, ..
            })) => {
                trace_port_dispatch(43, work, 1, irp_id.raw(), false,
                    status.raw() as u32 as u64, 0);
                let (updated, _) = buffers.into_parts();
                trace_port_source(49, work, updated.len() as u64);
                stage_port_terminal(work, status, &updated, None);
            }
            Ok(hosted_file_owners::HookDispatchResult::Returned(
                hosted_file_owners::DispatchResult::Outstanding { irp_id })) => {
                trace_port_dispatch(43, work, 2, irp_id.raw(), false, 0, 0);
                let recorded = work.source.record_pending(irp_id).is_ok();
                trace_port_dispatch(44, work, 2, irp_id.raw(), false,
                    u64::from(recorded), 0);
                if !recorded { return; }
                work.pending = Some(irp_id);
            }
            Ok(hosted_file_owners::HookDispatchResult::PumpSuspended { irp_id, key }) => {
                trace_port_dispatch(43, work, 3, irp_id.raw(), true, 0, 0);
                let recorded = work.source.record_pending(irp_id).is_ok();
                trace_port_dispatch(44, work, 3, irp_id.raw(), true,
                    u64::from(recorded), 0);
                if !recorded { return; }
                work.pending = Some(irp_id);
                work.pump_key = Some(key);
                work.file_owner_row_id = hosted_file_owners::hook_pump_owner_row_id(
                    irp_id, key, work.owner_id,
                    work.source.class_target_registration().device_id(),
                ).ok();
            }
            Err(hosted_file_owners::HookDispatchFailure::Status(status)) => {
                trace_port_dispatch(43, work, 4, 0, false,
                    status.raw() as u32 as u64, 0);
                // No class provider was entered. Complete this source through the usual
                // sequence so its original Reply and pinned IRP can be retired.
                stage_port_terminal(work, status,
                    &ticket.input[..ticket.input_length as usize], None);
            }
            Err(failure @ hosted_file_owners::HookDispatchFailure::UnownedYield { status, .. }) => {
                trace_port_dispatch(43, work, 5, 0, false,
                    status.raw() as u32 as u64, 0);
                work.unowned_yield = Some(failure);
                work.blocked = true;
                return;
            }
            Ok(hosted_file_owners::HookDispatchResult::Returned(
                hosted_file_owners::DispatchResult::Returned {
                    irp_id, status, information, ..
                })) => {
                trace_port_dispatch(43, work, 6, irp_id.raw(), false,
                    status.raw() as u32 as u64, information);
                return;
            }
        }
        trace_port_dispatch(45, work, 0, work.pending.map_or(0, |id| id.raw()),
            work.pump_key.is_some(), 0, 0);
    }
    if work.terminal_candidate.is_none() {
        if let Some(irp_id) = work.pending {
            if let Some(key) = work.pump_key {
                let device = work.source.class_target_registration().device_id();
                match hosted_file_owners::hook_pump_state(irp_id, key, work.owner_id, device) {
                    Ok(hosted_file_owners::HookPumpState::Suspended) => {
                        trace_port_dispatch(50, work, 3, irp_id.raw(), true, 0, 0);
                        return;
                    }
                    Ok(hosted_file_owners::HookPumpState::Blocked) | Err(_) => {
                        trace_port_dispatch(50, work, 4, irp_id.raw(), true, 0, 0);
                        work.blocked = true;
                        return;
                    }
                    Ok(hosted_file_owners::HookPumpState::Pending) => {
                        trace_port_dispatch(50, work, 2, irp_id.raw(), true, 0, 0);
                        work.pump_key = None;
                    }
                    Ok(hosted_file_owners::HookPumpState::Returned) => {
                        trace_port_dispatch(50, work, 1, irp_id.raw(), true, 0, 0);
                        let mut updated = [0u8; 48];
                        let Ok(Some((status, 0, _))) =
                            hosted_file_owners::peek_returned_hook_pump(
                                irp_id, key, work.owner_id, device,
                                &mut updated[..work.input_length],
                            ) else { return; };
                        stage_port_terminal(work, status,
                            &updated[..work.input_length], Some(irp_id));
                        if work.terminal_candidate.is_none() { return; }
                    }
                }
            }
            if work.terminal_candidate.is_some() {
                advance_port_terminal(work);
                return;
            }
            let Ok(completion) = hosted_file_owners::completion(irp_id) else { return; };
            if completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                || completion.information != 0
                || completion.status == nt_status::NtStatus::PENDING
            {
                return;
            }
            let mut updated = [0u8; 48];
            let length = work.input_length;
            if hosted_file_owners::copy_mutable_input(irp_id, 0, &mut updated[..length])
                != Ok(length) { return; }
            stage_port_terminal(work, completion.status,
                &updated[..length], Some(irp_id));
        }
    }
    if work.terminal_candidate.is_some() && work.terminal_status.is_none() {
        trace_port_source(60, work, 0);
        advance_port_terminal(work);
    }
    if let Some(status) = work.terminal_status {
        trace_port_source(70, work, status.raw() as u32 as u64);
        work.published = work.origin.reply_dispatch(
            HostedForwardDispatchReply::InlineTerminal(status.raw()), true,
        );
        trace_port_source(71, work, u64::from(work.published));
    }
}

/// Stage: 0 entry (index=class count, owner=port count), 1/2 class before/after,
/// 3 class skip, 4/5 port before/after, 6 port skip, 7 function exit.
fn trace_hook_redrive(
    stage: u64, index: u64, owner: u64, entered: bool, published: bool,
    pump_key: bool, unowned: bool,
) {
    static COUNT: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    if COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) >= 96 {
        return;
    }
    print_str(b"[hook-redrive] stage/index/owner/entered/published/key/unowned=");
    print_u64(stage); print_str(b"/");
    print_u64(index); print_str(b"/");
    print_u64(owner); print_str(b"/");
    print_u64(u64::from(entered)); print_str(b"/");
    print_u64(u64::from(published)); print_str(b"/");
    print_u64(u64::from(pump_key)); print_str(b"/");
    print_u64(u64::from(unowned)); print_str(b"\n");
}

static HOOK_REDRIVE_EXIT_PROBE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub(super) fn redrive_exit_probe() -> bool {
    HOOK_REDRIVE_EXIT_PROBE.load(core::sync::atomic::Ordering::Relaxed)
}

pub(super) fn clear_redrive_exit_probe() {
    HOOK_REDRIVE_EXIT_PROBE.store(false, core::sync::atomic::Ordering::Relaxed);
}

pub(super) unsafe fn redrive() {
    let trace = entered_port_source_unpublished();
    let class_count = class_sources().len();
    if trace {
        trace_hook_redrive(0, class_count as u64, port_sources().len() as u64,
            false, false, false, false);
    }
    for index in 0..class_count {
        let ptr = class_sources()[index].as_mut() as *mut ClassSource;
        let owner_id = (*ptr).owner_id;
        if trace {
            trace_hook_redrive(1, index as u64, (*ptr).owner_id, (*ptr).entered,
                (*ptr).published, (*ptr).pump_key.is_some(), (*ptr).unowned_yield.is_some());
        }
        if (*ptr).pump_key.is_some() || (*ptr).unowned_yield.is_some() {
            if trace {
                trace_hook_redrive(3, index as u64, (*ptr).owner_id, (*ptr).entered,
                    (*ptr).published, (*ptr).pump_key.is_some(), (*ptr).unowned_yield.is_some());
            }
            continue;
        }
        advance_class_source(&mut *ptr);
        if trace {
            trace_hook_redrive(2, index as u64, owner_id,
                false, false, false, false);
        }
    }
    let port_count = port_sources().len();
    for index in 0..port_count {
        let ptr = port_sources()[index].as_mut() as *mut PortSource;
        let owner_id = (*ptr).owner_id;
        if trace {
            trace_hook_redrive(4, index as u64, (*ptr).owner_id, (*ptr).entered,
                (*ptr).published, (*ptr).pump_key.is_some(), (*ptr).unowned_yield.is_some());
        }
        if (*ptr).entered && !(*ptr).published
        {
            // State: 0 no pending/key pair, 1 suspended, 2 returned,
            // 3 provider pending, 4 blocked, 5 exact owner/key refusal.
            let state = match ((*ptr).pending, (*ptr).pump_key) {
                (Some(irp_id), Some(key)) => match hosted_file_owners::hook_pump_state(
                    irp_id, key, (*ptr).owner_id,
                    (*ptr).source.class_target_registration().device_id(),
                ) {
                    Ok(hosted_file_owners::HookPumpState::Suspended) => 1,
                    Ok(hosted_file_owners::HookPumpState::Returned) => 2,
                    Ok(hosted_file_owners::HookPumpState::Pending) => 3,
                    Ok(hosted_file_owners::HookPumpState::Blocked) => 4,
                    Err(_) => 5,
                },
                _ => 0,
            };
            trace_port_dispatch(80, &*ptr, 0,
                (*ptr).pending.map_or(0, |id| id.raw()), (*ptr).pump_key.is_some(),
                u64::from((*ptr).unowned_yield.is_some()), state);
        }
        if (*ptr).pump_key.is_some() || (*ptr).unowned_yield.is_some() {
            if trace {
                trace_hook_redrive(6, index as u64, (*ptr).owner_id, (*ptr).entered,
                    (*ptr).published, (*ptr).pump_key.is_some(), (*ptr).unowned_yield.is_some());
            }
            continue;
        }
        if (*ptr).entered && !(*ptr).published {
            trace_port_source(81, &*ptr, 0);
        }
        advance_port_source(&mut *ptr);
        if trace {
            trace_hook_redrive(5, index as u64, owner_id,
                false, false, false, false);
        }
    }
    if trace {
        trace_hook_redrive(7, class_count as u64, port_count as u64,
            false, false, false, false);
        HOOK_REDRIVE_EXIT_PROBE.store(true, core::sync::atomic::Ordering::Relaxed);
    }
}

pub(super) unsafe fn nested_work_ready() -> bool {
    class_sources().iter().any(|row| {
        row.pump_key.is_none() && row.unowned_yield.is_none() && (!row.entered
            || (row.terminal_status.is_some() && !row.published)
            || row.pending.is_some_and(|id| completed_irp_exact(id.raw()).is_some()))
    }) || port_sources().iter().any(|row| {
        row.pump_key.is_none() && row.unowned_yield.is_none() && !row.blocked && (!row.entered
            || (row.terminal_candidate.is_some() && row.terminal_status.is_none())
            || (row.terminal_status.is_some() && !row.published)
            || row.pending.is_some_and(|id| completed_irp_exact(id.raw()).is_some()))
    })
}

pub(super) fn entered_port_source_unpublished() -> bool {
    port_sources().iter().any(|port| port.entered && !port.published)
}

fn returned_hook_state(
    irp_id: Option<IrpId>, key: Option<ExternalFileIrpPumpKey>, owner_id: u64,
    device: nt_io_manager::DeviceId,
) -> Option<hosted_file_owners::HookPumpState> {
    let (Some(irp_id), Some(key)) = (irp_id, key) else { return None; };
    hosted_file_owners::hook_pump_state(irp_id, key, owner_id, device)
        .ok().or(Some(hosted_file_owners::HookPumpState::Blocked))
}

/// Only a returned or lost exact Hook terminal fences the outer CONNECT here. A real
/// provider Pending is handled by the ordinary completion path after the pump has returned.
pub(super) fn returned_hook_pump_ready() -> bool {
    returned_hook_pump_ready_after(0)
}

/// A nested queue may publish only Hook sources created after its File-owner
/// boundary. The retained row ID remains available after the File row retires.
pub(super) fn returned_hook_pump_ready_after(floor: u64) -> bool {
    class_sources().iter().any(|row| source_after_floor(row.file_owner_row_id, floor)
        && (row.unowned_yield.is_some()
            || row.pump_return_consumed && !row.published
            || matches!(returned_hook_state(row.pending, row.pump_key, row.owner_id,
                row.port_device.device_id()),
                Some(hosted_file_owners::HookPumpState::Returned
                    | hosted_file_owners::HookPumpState::Blocked))))
    || port_sources().iter().any(|row| source_after_floor(row.file_owner_row_id, floor)
        && (row.unowned_yield.is_some()
            || row.pump_return_consumed && !row.published
            || matches!(returned_hook_state(row.pending, row.pump_key, row.owner_id,
                row.source.class_target_registration().device_id()),
                Some(hosted_file_owners::HookPumpState::Returned
                    | hosted_file_owners::HookPumpState::Blocked))))
}

fn source_after_floor(file_owner_row_id: Option<u64>, floor: u64) -> bool {
    floor == 0 || file_owner_row_id.is_some_and(|id| id > floor)
}

/// A consumed File terminal is still owned until the original Hook source Reply is published.
/// A provider Pending has not consumed its pump return and remains on the ordinary path.
pub(super) fn hook_source_unsettled() -> bool {
    hook_source_unsettled_after(0)
}

pub(super) fn hook_source_unsettled_after(floor: u64) -> bool {
    class_sources().iter().any(|row| source_after_floor(row.file_owner_row_id, floor)
        && row.pump_return_consumed && !row.published)
        || port_sources().iter().any(|row| source_after_floor(row.file_owner_row_id, floor)
            && row.pump_return_consumed && !row.published)
}

/// Advance only entered Hook work whose real File terminal is held for observation. Never
/// dispatch a fresh Hook from this flat-root settlement phase.
pub(super) unsafe fn redrive_returned_hook_pump() -> bool {
    redrive_returned_hook_pump_after(0)
}

pub(super) unsafe fn redrive_returned_hook_pump_after(floor: u64) -> bool {
    let mut progressed = false;
    let class_count = class_sources().len();
    for index in 0..class_count {
        let ptr = class_sources()[index].as_mut() as *mut ClassSource;
        if source_after_floor((*ptr).file_owner_row_id, floor)
            && ((*ptr).pump_return_consumed && !(*ptr).published
                || returned_hook_state((*ptr).pending, (*ptr).pump_key, (*ptr).owner_id,
                    (*ptr).port_device.device_id()) == Some(hosted_file_owners::HookPumpState::Returned))
        {
            let before = ((*ptr).pump_key, (*ptr).pump_return_consumed,
                (*ptr).returned_terminal.is_some(), (*ptr).terminal_status,
                (*ptr).canonical_acknowledged, (*ptr).pin_released, (*ptr).published);
            advance_class_source(&mut *ptr);
            let after = ((*ptr).pump_key, (*ptr).pump_return_consumed,
                (*ptr).returned_terminal.is_some(), (*ptr).terminal_status,
                (*ptr).canonical_acknowledged, (*ptr).pin_released, (*ptr).published);
            progressed |= before != after;
        }
    }
    let port_count = port_sources().len();
    for index in 0..port_count {
        let ptr = port_sources()[index].as_mut() as *mut PortSource;
        if (*ptr).entered && !(*ptr).published {
            trace_port_dispatch(82, &*ptr, 0,
                (*ptr).pending.map_or(0, |id| id.raw()), (*ptr).pump_key.is_some(),
                u64::from((*ptr).pump_return_consumed), u64::from((*ptr).published));
        }
        if source_after_floor((*ptr).file_owner_row_id, floor)
            && ((*ptr).pump_return_consumed && !(*ptr).published
                || returned_hook_state((*ptr).pending, (*ptr).pump_key, (*ptr).owner_id,
                    (*ptr).source.class_target_registration().device_id())
                    == Some(hosted_file_owners::HookPumpState::Returned))
        {
            let before = ((*ptr).pump_key, (*ptr).pump_return_consumed,
                (*ptr).terminal_candidate.is_some(), (*ptr).terminal_observed,
                (*ptr).terminal_status, (*ptr).published, (*ptr).blocked);
            advance_port_source(&mut *ptr);
            let after = ((*ptr).pump_key, (*ptr).pump_return_consumed,
                (*ptr).terminal_candidate.is_some(), (*ptr).terminal_observed,
                (*ptr).terminal_status, (*ptr).published, (*ptr).blocked);
            progressed |= before != after;
        }
    }
    progressed
}

fn progress_generation() -> u64 {
    let mut generation = (class_sources().len() + port_sources().len()) as u64;
    for row in class_sources() {
        generation += u64::from(row.entered)
            + u64::from(row.pending.is_some())
            + u64::from(row.pump_key.is_some())
            + u64::from(row.returned_terminal.is_some())
            + u64::from(row.terminal_status.is_some())
            + u64::from(row.canonical_acknowledged)
            + u64::from(row.published);
    }
    for row in port_sources() {
        generation += u64::from(row.entered)
            + u64::from(row.pending.is_some())
            + u64::from(row.pump_key.is_some())
            + u64::from(row.terminal_candidate.is_some())
            + u64::from(row.terminal_observed.is_some())
            + u64::from(row.terminal_status.is_some())
            + u64::from(row.published)
            + u64::from(row.blocked);
    }
    generation
}

pub(super) unsafe fn redrive_nested_ready() -> bool {
    let before = progress_generation();
    redrive();
    progress_generation() != before
}

pub(super) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    operation: u64,
    device: u64,
    irp: u64,
) -> Option<(i32, bool)> {
    // Operation 1 carries (target DeviceObject, source IRP). Operation 2 carries
    // (source IRP, retained Reply token), so an address recycled after native completion
    // cannot acknowledge another source generation.
    if device == 0 || irp == 0 {
        return Some((nt_status::NtStatus::INVALID_PARAMETER.raw(), false));
    }
    let (_, inst) = instance_for_pump_channel(ch, reply_cap)?;
    if hosted_driver_pump_caller_tcb(ch, reply_cap, badge).is_none() {
        return Some((nt_status::NtStatus::INVALID_HANDLE.raw(), false));
    }
    if operation == 2 {
        if let Some(index) = class_sources()
            .iter().position(|row| same_instance(row.instance, inst)
                && row.irp == device && row.origin.token == irp)
        {
            let row = &mut class_sources()[index];
            if !row.published {
                return Some((BUSY, false));
            }
            if !row.canonical_acknowledged {
                if let Some(id) = row.pending {
                    if hosted_file_owners::acknowledge(id).is_err() {
                        return Some((BUSY, false));
                    }
                }
                row.canonical_acknowledged = true;
            }
            if !row.pin_released {
                return Some((BUSY, false));
            }
            if !row.source_released {
                if !hosted_source_irp_ledger::matches(
                    row.class_index, row.source_allocation, row.source_ticket,
                ) || !hosted_source_irp_ledger::unpin(row.source_ticket) {
                    return Some((BUSY, false));
                }
                row.source_released = true;
            }
            if !row.origin.retire_receipt() { return Some((BUSY, false)); }
            class_sources().swap_remove(index);
            return Some((STATUS_SUCCESS, false));
        }
        if let Some(index) = port_sources()
            .iter().position(|row| same_instance(row.instance, inst)
                && row.irp == device && row.origin.token == irp)
        {
            let row = &mut port_sources()[index];
            if !row.published { return Some((BUSY, false)); }
            if !row.source_retired
                && row.source.retire_after_source_completion().is_err() {
                return Some((BUSY, false));
            }
            row.source_retired = true;
            if !row.origin.retire_receipt() { return Some((BUSY, false)); }
            port_sources().swap_remove(index);
            return Some((STATUS_SUCCESS, false));
        }
        return Some((INVALID, false));
    }
    if operation != 1 {
        return Some((nt_status::NtStatus::INVALID_PARAMETER.raw(), false));
    }
    let domain = instance_domain_identity(inst)?;
    if hosted_connect_live::lookup_hook_owner(domain, device).is_some() {
        dispatch_port_source(ch, reply_cap, device, irp)
    } else {
        dispatch_class_lower(ch, reply_cap, device, irp)
    }
}
