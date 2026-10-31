//! Exact hosted DEVICE_OBJECT to 32-bit WMI provider identity.
//! Registration and event delivery remain separate contracts: assigning an ID
//! does not advertise GUIDs or accept an event.

use super::*;
use nt_wmi::{RegInfoTicket, WmiDeviceIdentity, WmiEventOwnership, WmiGuid, WmiRegistry};

pub(super) const LABEL: u64 = 0x7E5;
const OP_PROVIDER_ID: u64 = 1;
const OP_REGINFO_BEGIN: u64 = 2;
const OP_REGINFO_DISPATCHED: u64 = 3;
const OP_REGINFO_ABORT_PRE_DISPATCH: u64 = 4;
const OP_REGINFO_CHUNK: u64 = 5;
const OP_REGINFO_COMPLETE: u64 = 6;
const OP_DEREGISTER_GUIDS: u64 = 7;
const OP_WRITE_EVENT: u64 = 8;
const ARG_CHUNK_LENGTH: u64 = 0;
const ARG_CHUNK_BYTES: u64 = 8;
const _: () = assert!(ARG_CHUNK_BYTES < FSD_ARG_BYTES);

// Root pump entry and exact device retirement serialize access to this store.
static mut DEVICE_REGISTRY: WmiRegistry = WmiRegistry::new();

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind(
        "IoWMIDeviceObjectToProviderId",
        device_object_to_provider_id as *const () as usize as u64,
    );
    reg.bind(
        "IoWMIRegistrationControl",
        registration_control as *const () as usize as u64,
    );
    reg.bind(
        "IoWMIWriteEvent",
        write_event as *const () as usize as u64,
    );
}

/// `NTSTATUS IoWMIWriteEvent(PVOID WnodeEventItem)`.
pub(super) extern "win64" fn write_event(wnode: u64) -> i32 {
    if wnode == 0 { return STATUS_INVALID_PARAMETER; }
    ticket_operation(OP_WRITE_EVENT, wnode, 0, 0)
        .map_or_else(|status| status, |_| STATUS_SUCCESS)
}

pub(super) fn plan_device_event(
    provider_id: u32,
    guid: WmiGuid,
    flags: u32,
) -> Result<(WmiDeviceIdentity, WmiEventOwnership), u32> {
    let registry = unsafe { &*core::ptr::addr_of!(DEVICE_REGISTRY) };
    registry.plan_device_event(provider_id, guid, flags)
}

/// `NTSTATUS IoWMIRegistrationControl(PDEVICE_OBJECT, ULONG)`.
pub(super) extern "win64" fn registration_control(device_object: u64, action: u32) -> i32 {
    if device_object == 0 { return STATUS_INVALID_PARAMETER; }
    if action == 2 {
        return ticket_operation(OP_DEREGISTER_GUIDS, device_object, 0, 0)
            .map_or_else(|status| status, |_| STATUS_SUCCESS);
    }
    if !matches!(action, 1 | 3 | 4) {
        return STATUS_NOT_SUPPORTED;
    }
    let mut capacity = 4096u32;
    loop {
        let ticket = match ticket_operation(OP_REGINFO_BEGIN, device_object, 0, 0) {
            Ok(ticket) if ticket != 0 => ticket,
            Ok(_) => unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, OP_REGINFO_BEGIN, device_object, 0]) },
            Err(status) => return status,
        };
        let result = unsafe { hosted_wmi_reginfo::query(device_object, capacity, ticket) };
        let reply = match result {
            Ok(reply) => reply,
            Err(failure) => {
                let terminal_op = if failure.dispatched {
                    OP_REGINFO_COMPLETE
                } else {
                    OP_REGINFO_ABORT_PRE_DISPATCH
                };
                let terminal_status = ticket_operation(
                    terminal_op, device_object, ticket,
                    if failure.dispatched { failure.status as u32 as u64 } else { 0 },
                );
                if terminal_status.is_err_and(|status| status != failure.status) {
                    unsafe { crate::provider_bugcheck::report(
                        0xc4, [LABEL, terminal_op, ticket, failure.status as u32 as u64],
                    ); }
                }
                return failure.status;
            }
        };
        let too_small = matches!(reply.status, STATUS_BUFFER_TOO_SMALL)
            || reply.status as u32 == STATUS_BUFFER_OVERFLOW;
        if too_small {
            let terminal_status = ticket_operation(
                OP_REGINFO_COMPLETE, device_object, ticket, reply.status as u32 as u64,
            );
            if terminal_status.is_err_and(|status| status != reply.status) {
                unsafe { crate::provider_bugcheck::report(
                    0xc4, [LABEL, OP_REGINFO_COMPLETE, ticket, reply.status as u32 as u64],
                ); }
            }
            let Ok(required) = u32::try_from(reply.information) else {
                return STATUS_INVALID_BUFFER_SIZE as i32;
            };
            if required <= capacity { return reply.status; }
            capacity = required;
            continue;
        }
        if reply.status != STATUS_SUCCESS {
            let terminal_status = ticket_operation(
                OP_REGINFO_COMPLETE, device_object, ticket, reply.status as u32 as u64,
            );
            if terminal_status.is_err_and(|status| status != reply.status) {
                unsafe { crate::provider_bugcheck::report(
                    0xc4, [LABEL, OP_REGINFO_COMPLETE, ticket, reply.status as u32 as u64],
                ); }
            }
            return reply.status;
        }
        if let Err(status) = stream_reginfo_bytes(device_object, ticket, &reply.bytes) {
            let _ = ticket_operation(OP_REGINFO_COMPLETE, device_object, ticket, status as u32 as u64);
            return status;
        }
        return ticket_operation(OP_REGINFO_COMPLETE, device_object, ticket, 0)
            .map_or_else(|status| status, |_| STATUS_SUCCESS);
    }
}

fn stream_reginfo_bytes(device_object: u64, ticket: u64, bytes: &[u8]) -> Result<(), i32> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let count = (bytes.len() - offset).min((FSD_ARG_BYTES - ARG_CHUNK_BYTES) as usize);
        let _guard = unsafe { component_device_reply_lock() };
        unsafe {
            write_volatile((FSD_ARG_VADDR + ARG_CHUNK_LENGTH) as *mut u32, count as u32);
            core::ptr::copy_nonoverlapping(
                bytes[offset..offset + count].as_ptr(),
                (FSD_ARG_VADDR + ARG_CHUNK_BYTES) as *mut u8,
                count,
            );
        }
        ticket_operation(OP_REGINFO_CHUNK, device_object, ticket, offset as u64)?;
        offset += count;
    }
    Ok(())
}

/// `ULONG IoWMIDeviceObjectToProviderId(PDEVICE_OBJECT)`.
pub(super) extern "win64" fn device_object_to_provider_id(device_object: u64) -> u32 {
    if device_object == 0 {
        return 0;
    }
    let (words, raw, id, extra_a, extra_b) = unsafe {
        call_on4_raw((LABEL << 12) | 4, OP_PROVIDER_ID, device_object, 0, 0)
    };
    if words != 2 || extra_a != 0 || extra_b != 0
        || (raw as u32 as i32 == STATUS_SUCCESS && id == 0)
    {
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [LABEL, OP_PROVIDER_ID, words, raw],
            );
        }
    }
    if raw as u32 as i32 != STATUS_SUCCESS {
        return 0;
    }
    u32::try_from(id).unwrap_or(0)
}

pub(super) fn ticket_operation(
    op: u64,
    device_object: u64,
    ticket: u64,
    value: u64,
) -> Result<u64, i32> {
    let (words, raw, result, extra_a, extra_b) = unsafe {
        call_on4_raw((LABEL << 12) | 4, op, device_object, ticket, value)
    };
    if words != 2 || extra_a != 0 || extra_b != 0 {
        unsafe {
            crate::provider_bugcheck::report(0xc4, [LABEL, op, words, raw]);
        }
    }
    let status = raw as u32 as i32;
    if status == STATUS_SUCCESS { Ok(result) } else { Err(status) }
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    device_object: u64,
    arg2: u64,
    arg3: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    if op == OP_WRITE_EVENT && device_object != 0 && arg2 == 0 && arg3 == 0 {
        return (hosted_wmi_event::service(ch, device_object, badge, reply_cap), 0);
    }
    if device_object == 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    if matches!(op, OP_REGINFO_CHUNK | OP_REGINFO_COMPLETE) {
        return service_reginfo_terminal(
            ch, op, device_object, arg2, arg3, badge, reply_cap,
        );
    }
    if arg3 != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some(identity) = authenticated_device(ch, device_object, badge, reply_cap) else {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    };
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(DEVICE_REGISTRY) };
    match op {
        OP_PROVIDER_ID if arg2 == 0 => match registry.register_device(identity) {
            Ok(id) => (STATUS_SUCCESS, u64::from(id)),
            Err(status) => (status as i32, 0),
        },
        OP_REGINFO_BEGIN if arg2 == 0 => {
            if let Err(status) = registry.register_device(identity) {
                return (status as i32, 0);
            }
            match registry.begin_reginfo(identity) {
                Ok(ticket) => (STATUS_SUCCESS, ticket.raw()),
                Err(status) => (status as i32, 0),
            }
        }
        OP_REGINFO_DISPATCHED if arg2 != 0 => {
            let ticket = RegInfoTicket::for_authenticated_device(arg2, identity);
            match registry.mark_reginfo_dispatched(ticket) {
                Ok(()) => (STATUS_SUCCESS, 0),
                Err(status) => (status as i32, 0),
            }
        }
        OP_REGINFO_ABORT_PRE_DISPATCH if arg2 != 0 => {
            let ticket = RegInfoTicket::for_authenticated_device(arg2, identity);
            match registry.abort_reginfo_before_dispatch(ticket) {
                Ok(()) => (STATUS_SUCCESS, 0),
                Err(status) => (status as i32, 0),
            }
        }
        OP_DEREGISTER_GUIDS if arg2 == 0 => {
            match registry.deregister_device_guids(identity) {
                Ok(()) => (STATUS_SUCCESS, 0),
                Err(status) => (status as i32, 0),
            }
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    }
}

/// A retired device may still return the terminal result of a dispatched
/// REGINFO IRP. Authenticate its original provider domain and pending ticket,
/// rather than requiring a now-retired canonical DEVICE_OBJECT to be live.
fn service_reginfo_terminal(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    device_object: u64,
    ticket_id: u64,
    value: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return (STATUS_ACCESS_DENIED, 0);
    }
    let Some(domain) = instance_domain_identity(inst) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(DEVICE_REGISTRY) };
    let Some(identity) = registry.pending_reginfo_identity(ticket_id) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    if identity.domain != domain.domain_id.raw() || identity.device_object != device_object {
        return (STATUS_INVALID_HANDLE, 0);
    }
    let ticket = RegInfoTicket::for_authenticated_device(ticket_id, identity);
    let result = match op {
        OP_REGINFO_CHUNK => {
            if inst.exec_arg_va == 0 {
                return (STATUS_INVALID_HANDLE, 0);
            }
            let length = unsafe {
                read_volatile((inst.exec_arg_va + ARG_CHUNK_LENGTH) as *const u32)
            } as u64;
            if length == 0 || length > FSD_ARG_BYTES - ARG_CHUNK_BYTES {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (inst.exec_arg_va + ARG_CHUNK_BYTES) as *const u8,
                    length as usize,
                )
            };
            registry.stage_reginfo_chunk(ticket, value, bytes)
        }
        OP_REGINFO_COMPLETE if value <= u32::MAX as u64 => {
            registry.complete_streamed_reginfo(ticket, value as u32)
        }
        _ => return (STATUS_INVALID_PARAMETER, 0),
    };
    match result {
        Ok(()) => (STATUS_SUCCESS, 0),
        Err(status) => (status as i32, 0),
    }
}

fn authenticated_device(
    ch: &crate::spawn_hosts::PumpChannel,
    device_object: u64,
    badge: u64,
    reply_cap: u64,
) -> Option<WmiDeviceIdentity> {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return None;
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return None;
    }
    let Some(domain) = instance_domain_identity(inst) else {
        return None;
    };
    let registration = unsafe {
        io_manager_mut().hosted_device_pointer_registration(domain, device_object)
    };
    let Some(registration) = registration else {
        return None;
    };
    if registration.address() != device_object
        || registration.domain() != domain
        || hosted_device_binding_by_device_id(registration.device_id().raw()).is_none_or(|binding| {
            binding.device_object != device_object
                || binding.projection_domain != domain
                || binding.instance != index
        })
    {
        return None;
    }
    Some(WmiDeviceIdentity {
        domain: domain.domain_id.raw(),
        generation: registration.generation(),
        device_object,
    })
}

pub(super) fn retire_device(
    registration: nt_io_manager::HostedDevicePointerRegistration,
) -> Result<(), u32> {
    let identity = WmiDeviceIdentity {
        domain: registration.domain().domain_id.raw(),
        generation: registration.generation(),
        device_object: registration.address(),
    };
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(DEVICE_REGISTRY) };
    if registry.device_provider_id(identity).is_ok() {
        registry.unregister_device(identity)
    } else {
        Ok(())
    }
}
