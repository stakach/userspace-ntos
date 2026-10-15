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
    ExternalFileIrpDispatchPolicy, ExternalFileIrpRequest,
};
use nt_io_manager::hosted_forward_progress::HostedForwardDispatchReply;
use nt_io_manager::{DeviceControlParameters, IoParameters};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;
use nt_types::ClientId;

const INVALID: i32 = 0xc000_0010u32 as i32;
const BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

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
        pending: None, terminal_candidate: None, terminal_observed: None,
        terminal_status: None, published: false,
        blocked: false, source_retired: false,
    }));
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
        let result = hosted_file_owners::dispatch(
            work.caller,
            hook_request(work.caller, work.port_device, work.control_code, work.input_length),
            &work.input[..work.input_length],
            &[],
            ExternalFileIrpDispatchPolicy::MutableMethodNeitherInputAtDevice,
        );
        assert_eq!(active_port().pop().map(|row| row.target), Some(work.port_device));
        match result {
            Ok(hosted_file_owners::DispatchResult::Returned {
                status, information: 0, buffers, ..
            }) => {
                let (updated, _) = buffers.into_parts();
                class_terminal(work, status, &updated);
            }
            Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
                work.pending = Some(irp_id);
            }
            Err(status) => {
                // Dispatch errors are pre-entry. Complete the parked lower-edge source with
                // its original input; an accepted or uncertain effect remains Outstanding.
                let input = work.input;
                let length = work.input_length;
                class_terminal(work, status, &input[..length]);
            }
            Ok(_) => return,
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
    if let Some(status) = work.terminal_status {
        // Release the mutable input exclusion before the source Reply. Keep the exact FSD
        // caller IRP ticket until its lower-edge source completion has been acknowledged.
        if !work.pin_released {
            if hosted_device_allocations::release_temporary_pool_pin(&mut work.pin).is_err() {
                return;
            }
            work.pin_released = true;
        }
        work.published = work.origin.reply_dispatch(
            HostedForwardDispatchReply::InlineTerminal(status.raw()), true,
        );
    }
}

unsafe fn stage_port_terminal(
    work: &mut PortSource,
    status: nt_status::NtStatus,
    updated: &[u8],
    completed: Option<IrpId>,
) {
    if updated.len() != work.input_length || work.terminal_candidate.is_some() {
        work.blocked = true;
        return;
    }
    let mut bytes = [0; 48];
    bytes[..updated.len()].copy_from_slice(updated);
    work.terminal_candidate = Some(PortTerminalCandidate {
        status, updated: bytes, completed,
    });
}

unsafe fn advance_port_terminal(work: &mut PortSource) {
    let Some(candidate) = work.terminal_candidate else { return; };
    let status = candidate.status;
    if work.terminal_observed.is_none() {
        let outcome = hosted_connect_live::with_hook_sequence(work.owner_id, |_, sequence| {
            work.source.observe_terminal(sequence, status,
                &candidate.updated[..work.input_length], candidate.completed)
        });
        if outcome != Some(Ok((work.source.source_identity(), status))) {
            work.blocked = !work.source.terminal_observation_retryable();
            return;
        }
        work.terminal_observed = Some(status);
    }
    if work.terminal_observed != Some(status) {
        work.blocked = true;
        return;
    }
    if work.source.publish_source_terminal().is_err() {
        // A pre-effect lock refusal leaves Phase::Terminal and can be redriven. A failed
        // native write or deferred-free arm is indeterminate and must never be replayed.
        work.blocked = !work.source.terminal_publication_retryable();
        return;
    }
    work.terminal_status = Some(status);
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
        active().push(ActiveClassDispatch {
            owner_id: work.owner_id,
            class_target: ticket.target,
            class_source: prepared.source_port_do_registration,
            port_device,
            control_code: ticket.control_code,
            input_length: ticket.input_length as usize,
            input: ticket.input,
        });
        let result = hosted_file_owners::dispatch(
            work.caller,
            hook_request(work.caller, ticket.target, ticket.control_code,
                ticket.input_length as usize),
            &ticket.input[..ticket.input_length as usize],
            &[],
            ExternalFileIrpDispatchPolicy::MutableMethodNeitherInputAtDevice,
        );
        assert_eq!(active().pop().map(|row| row.owner_id), Some(work.owner_id));
        match result {
            Ok(hosted_file_owners::DispatchResult::Returned {
                status, information: 0, buffers, ..
            }) => {
                let (updated, _) = buffers.into_parts();
                stage_port_terminal(work, status, &updated, None);
            }
            Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
                if work.source.record_pending(irp_id).is_err() { return; }
                work.pending = Some(irp_id);
            }
            Err(status) => {
                // No class provider was entered. Complete this source through the usual
                // sequence so its original Reply and pinned IRP can be retired.
                stage_port_terminal(work, status,
                    &ticket.input[..ticket.input_length as usize], None);
            }
            Ok(hosted_file_owners::DispatchResult::Returned { .. }) => {
                return;
            }
        }
    }
    if work.terminal_candidate.is_none() {
        if let Some(irp_id) = work.pending {
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
        advance_port_terminal(work);
    }
    if let Some(status) = work.terminal_status {
        work.published = work.origin.reply_dispatch(
            HostedForwardDispatchReply::InlineTerminal(status.raw()), true,
        );
    }
}

pub(super) unsafe fn redrive() {
    let class_count = class_sources().len();
    for index in 0..class_count {
        let ptr = class_sources()[index].as_mut() as *mut ClassSource;
        advance_class_source(&mut *ptr);
    }
    let port_count = port_sources().len();
    for index in 0..port_count {
        let ptr = port_sources()[index].as_mut() as *mut PortSource;
        advance_port_source(&mut *ptr);
    }
}

pub(super) unsafe fn nested_work_ready() -> bool {
    class_sources().iter().any(|row| {
        !row.entered
            || (row.terminal_status.is_some() && !row.published)
            || row.pending.is_some_and(|id| completed_irp_exact(id.raw()).is_some())
    }) || port_sources().iter().any(|row| {
        !row.blocked && (!row.entered
            || (row.terminal_candidate.is_some() && row.terminal_status.is_none())
            || (row.terminal_status.is_some() && !row.published)
            || row.pending.is_some_and(|id| completed_irp_exact(id.raw()).is_some()))
    })
}

fn progress_generation() -> u64 {
    let mut generation = (class_sources().len() + port_sources().len()) as u64;
    for row in class_sources() {
        generation += u64::from(row.entered)
            + u64::from(row.pending.is_some())
            + u64::from(row.terminal_status.is_some())
            + u64::from(row.published);
    }
    for row in port_sources() {
        generation += u64::from(row.entered)
            + u64::from(row.pending.is_some())
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
