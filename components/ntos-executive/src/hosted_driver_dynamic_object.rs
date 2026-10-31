//! `ObCreateObject` for registered native object types.
//!
//! The component allocates the body in its retained pool, then asks the root to authenticate
//! the physical caller, registered type allocation, and live body allocation before publication.
//! A successful root commit records the creator reference. An uncertain reply is terminal: the
//! body may already be owned by the Object Manager and must never be replayed or recycled.

use super::*;
use nt_object_manager::hosted_dynamic_type::{DynamicHandleOwner, DynamicObjectLease};

pub(super) const LABEL: u64 = 0x7CA;
pub(super) const INSERT_LABEL: u64 = 0x7CB;
pub(super) const REFERENCE_LABEL: u64 = 0x7CC;

/// `NTSTATUS ObCreateObject(KPROCESSOR_MODE, POBJECT_TYPE, POBJECT_ATTRIBUTES,
/// KPROCESSOR_MODE, PVOID, ULONG, ULONG, ULONG, PVOID*)`.
pub(super) extern "win64" fn ob_create_object(
    probe_mode: u64,
    object_type: u64,
    attributes: u64,
    access_mode: u64,
    parse_context: u64,
    object_size: u64,
    paged_charge: u64,
    nonpaged_charge: u64,
    output: *mut u64,
) -> i32 {
    if output.is_null() { return STATUS_ACCESS_VIOLATION; }
    unsafe { write_unaligned(output, 0); }
    if object_type == 0 || object_size == 0 || object_size > u32::MAX as u64
        || probe_mode > 1 || access_mode > 1
    { return STATUS_INVALID_PARAMETER; }
    // The released dxgkrnl call creates an unnamed object with default type charges. Leave
    // other creation policies to their owning Object Manager implementation.
    if attributes != 0 || parse_context != 0 || paged_charge != 0 || nonpaged_charge != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    unsafe {
        if hosted_current_irql() != 0 { return STATUS_INVALID_DEVICE_REQUEST; }
        let _guard = component_device_reply_lock();
        let body = pool_alloc(object_size);
        if body == 0 { return STATUS_INSUFFICIENT_RESOURCES; }
        core::ptr::write_bytes(body as *mut u8, 0, object_size as usize);
        let (words, raw, marker, unused0, unused1) = call_on4_raw(
            (LABEL << 12) | 4, object_type, body, object_size, 0,
        );
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || marker != 0 || unused0 != 0 || unused1 != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, body, words, raw]);
        }
        let status = raw as u32 as i32;
        if status != STATUS_SUCCESS {
            pool_free(body);
            return status;
        }
        write_unaligned(output, body);
        STATUS_SUCCESS
    }
}

pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    type_pointer: u64,
    body: u64,
    body_size: u64,
    reserved: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> i32 {
    if reserved != 0 || type_pointer == 0 || body == 0 || body_size == 0
        || body_size > u32::MAX as u64
    { return STATUS_INVALID_PARAMETER; }
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return STATUS_INVALID_HANDLE;
    };
    if hosted_driver_caller(index, inst, caller_badge).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return status as i32,
    };
    let verified = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)
    }) };
    if let Err(status) = verified { return status as i32; }
    unsafe {
        if hosted_driver_dynamic_type::type_binding_for_instance(index, type_pointer, inst).is_none()
            || hosted_instance_pool_allocation_exec_if_live(inst, body, body_size).is_none()
        { return STATUS_INVALID_PARAMETER; }
        match hosted_driver_dynamic_type::publish_object_for_instance(index, type_pointer, inst, body) {
            Ok(_) => STATUS_SUCCESS,
            Err(status) => status.raw(),
        }
    }
}

/// `NTSTATUS ObInsertObject(PVOID, PACCESS_STATE, ACCESS_MASK, ULONG, PVOID*, PHANDLE)`.
pub(super) extern "win64" fn ob_insert_object(
    body: u64,
    access_state: u64,
    desired_access: u64,
    pointer_bias: u64,
    new_object: *mut u64,
    handle_out: *mut u64,
) -> i32 {
    if handle_out.is_null() { return STATUS_ACCESS_VIOLATION; }
    unsafe {
        write_unaligned(handle_out, 0);
        if !new_object.is_null() { write_unaligned(new_object, 0); }
    }
    if body == 0 { return STATUS_INVALID_PARAMETER; }
    unsafe {
        if hosted_current_irql() != 0 { return STATUS_INVALID_DEVICE_REQUEST; }
        let _guard = component_device_reply_lock();
        let (words, raw, handle, unused0, unused1) = call_on4_raw(
            (INSERT_LABEL << 12) | 4, body, desired_access, access_state, pointer_bias,
        );
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || unused0 != 0 || unused1 != 0
            || (raw as u32 as i32 == STATUS_SUCCESS) != (handle != 0)
        {
            crate::provider_bugcheck::report(0xc4, [INSERT_LABEL, body, words, raw]);
        }
        let status = raw as u32 as i32;
        if status == STATUS_SUCCESS {
            write_unaligned(handle_out, handle);
            if !new_object.is_null() { write_unaligned(new_object, body); }
        }
        status
    }
}

/// Reserve, bind, and publish a real handle in the authenticated effective process. The object
/// ledger transfer occurs while the table slot is invisible, so a handle can never expose a body
/// before the Object Manager owns its reference.
pub(crate) fn insert_service(
    channel: &crate::spawn_hosts::PumpChannel,
    body: u64,
    desired_access: u64,
    reserved0: u64,
    reserved1: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> (i32, u64) {
    if body == 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    if hosted_driver_caller(index, inst, caller_badge).is_none() {
        return (STATUS_INVALID_HANDLE, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0),
    };
    let Some(lease) = (unsafe {
        hosted_driver_dynamic_type::pending_object_for_instance(index, inst, body)
    }) else { return (STATUS_INVALID_PARAMETER, 0); };
    if desired_access > u32::MAX as u64 {
        unsafe { fail_pending_insert(lease); }
        return (STATUS_INVALID_PARAMETER, 0);
    }
    if reserved0 != 0 || reserved1 != 0 {
        unsafe { fail_pending_insert(lease); }
        return (STATUS_NOT_SUPPORTED, 0);
    }
    if unsafe { hosted_instance_pool_allocation_exec_if_live(inst, body, 1) }.is_none() {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some(definition) = (unsafe { hosted_driver_dynamic_type::registry_mut() })
        .and_then(|registry| registry.definition(lease.type_id())) else {
        return (STATUS_INVALID_PARAMETER, 0);
    };
    let mut access = desired_access as u32;
    for (generic, mapped) in [
        (0x8000_0000u32, definition.generic_mapping[0]),
        (0x4000_0000u32, definition.generic_mapping[1]),
        (0x2000_0000u32, definition.generic_mapping[2]),
        (0x1000_0000u32, definition.generic_mapping[3]),
    ] {
        if access & generic != 0 { access = (access & !generic) | mapped; }
    }
    if access & !definition.valid_access_mask != 0 {
        unsafe { fail_pending_insert(lease); }
        return (STATUS_ACCESS_DENIED, 0);
    }
    let reserved = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        let pid = caller.effective_process();
        let process_body = pm.process_kernel_object(pid).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let creation_sequence = pm.process_sequence_for_kernel_process_object(process_body)?;
        let slot = pm.try_reserve_handle_slot(pid)?;
        if let Err(status) = pm.bind_reserved_handle(
            slot,
            nt_process::HandleObject::DynamicObject { body, generation: lease.generation() },
            access,
        ) {
            let _ = pm.cancel_reserved_handle(slot);
            return Err(status);
        }
        Ok::<_, u32>((slot, DynamicHandleOwner { process_id: pid, creation_sequence }))
    }) };
    let (slot, owner) = match reserved {
        Ok(pair) => pair,
        Err(status) => {
            unsafe { fail_pending_insert(lease); }
            return (status as i32, 0);
        }
    };
    let inserted = unsafe { hosted_driver_dynamic_type::registry_mut()
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)
        .and_then(|registry| registry.insert_object(lease, owner, u64::from(slot.handle))) };
    if let Err(status) = inserted {
        let _ = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
            pm.cancel_reserved_handle(slot)
        }) };
        unsafe { fail_pending_insert(lease); }
        return (status.raw(), 0);
    }
    let published = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.publish_reserved_handle(slot)
    }) };
    match published {
        Ok(handle) => (STATUS_SUCCESS, u64::from(handle)),
        Err(status) => {
            let _ = unsafe { hosted_driver_dynamic_type::registry_mut()
                .and_then(|registry| registry.close_handle(owner, u64::from(slot.handle)).ok()) };
            let _ = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.cancel_reserved_handle(slot)
            }) };
            (status as i32, 0)
        }
    }
}

/// Insertion failure consumes the creator reference. The registry retains the ready object and
/// the delete worker later claims its exact callback ticket outside this source Reply.
unsafe fn fail_pending_insert(lease: DynamicObjectLease) {
    let registry = hosted_driver_dynamic_type::registry_mut()
        .expect("registered dynamic object has no Object Manager registry");
    registry.fail_insert(lease)
        .expect("authenticated pending object lost its creator reference");
}

pub(super) extern "win64" fn reference_object_by_handle(
    handle: u64,
    desired_access: u32,
    object_type: u64,
    access_mode: u8,
    object_out: u64,
    handle_information: u64,
) -> i32 {
    if handle == 0 || object_out == 0 || access_mode > 1 {
        return STATUS_INVALID_HANDLE;
    }
    unsafe {
        write_unaligned(object_out as *mut u64, 0);
        let _guard = component_device_reply_lock();
        let (words, raw, body, granted_access, attributes) = call_on4_raw(
            (REFERENCE_LABEL << 12) | 4,
            handle,
            u64::from(desired_access),
            object_type,
            u64::from(access_mode),
        );
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || granted_access > u32::MAX as u64
            || attributes > u32::MAX as u64
            || (raw as u32 as i32 == STATUS_SUCCESS) != (body != 0)
        {
            crate::provider_bugcheck::report(0xc4, [REFERENCE_LABEL, handle, words, raw]);
        }
        let status = raw as u32 as i32;
        if status == STATUS_SUCCESS {
            write_unaligned(object_out as *mut u64, body);
            if handle_information != 0 {
                write_unaligned(handle_information as *mut u32, attributes as u32);
                write_unaligned((handle_information + 4) as *mut u32, granted_access as u32);
            }
        }
        status
    }
}

pub(crate) fn reference_service(
    channel: &crate::spawn_hosts::PumpChannel,
    handle: u64,
    desired_access: u64,
    object_type: u64,
    access_mode: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    if handle == 0 || handle > u32::MAX as u64 || desired_access > u32::MAX as u64
        || access_mode > 1
    { return (STATUS_INVALID_HANDLE, 0, 0, 0); }
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    if hosted_driver_caller(index, inst, caller_badge).is_none() {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let table = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        let pid = caller.effective_process();
        let process_body = pm.process_kernel_object(pid).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let creation_sequence = pm.process_sequence_for_kernel_process_object(process_body)?;
        let handle = handle as u32;
        let nt_process::HandleObject::DynamicObject { body, generation } =
            pm.lookup_handle(pid, handle).ok_or(nt_process::STATUS_INVALID_HANDLE)?
        else { return Err(nt_process::STATUS_INVALID_HANDLE); };
        let access = pm.handle_access(pid, handle).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let flags = pm.handle_flags(pid, handle).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        Ok::<_, u32>((
            DynamicHandleOwner { process_id: pid, creation_sequence },
            body, generation, access,
            u32::from(flags.protect_from_close) | (u32::from(flags.inherit) << 1),
        ))
    }) };
    let (owner, body, generation, granted_access, attributes) = match table {
        Ok(value) => value,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    if access_mode == 1 && (desired_access as u32) & !granted_access != 0 {
        return (STATUS_ACCESS_DENIED, 0, 0, 0);
    }
    let Some(lease) = (unsafe {
        hosted_driver_dynamic_type::object_for_instance(index, inst, body, generation)
    }) else { return (STATUS_INVALID_HANDLE, 0, 0, 0); };
    let expected = if object_type == 0 {
        lease.type_id()
    } else {
        let Some(ty) = (unsafe {
            hosted_driver_dynamic_type::type_binding_for_instance(index, object_type, inst)
        }) else { return (nt_process::native_handle::STATUS_OBJECT_TYPE_MISMATCH as i32, 0, 0, 0); };
        ty
    };
    let Some(registry) = (unsafe { hosted_driver_dynamic_type::registry_mut() }) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    match registry.reference_handle(owner, handle, expected) {
        Ok(referenced) if referenced == lease => (STATUS_SUCCESS, body, u64::from(granted_access), u64::from(attributes)),
        Ok(other) => {
            let _ = registry.dereference_object(other);
            (STATUS_INVALID_HANDLE, 0, 0, 0)
        }
        Err(status) => (status.raw(), 0, 0, 0),
    }
}

/// An ObfDereferenceObject fallback for bodies created through this adapter. The root ledger
/// authenticates the physical instance and releases only an actual borrowed reference; final
/// callback delivery is deferred to the separate delete worker after this source Reply ends.
pub(super) fn dereference_if_dynamic(body: u64) -> Option<u64> {
    if body == 0 || unsafe { component_pool_allocation_capacity(body) }.is_none() {
        return None;
    }
    unsafe {
        let (words, raw, remaining, unused0, unused1) = call_on4_raw(
            (FSD_SERVICE_DYNAMIC_OBJECT_DEREFERENCE_LABEL << 12) | 4,
            body, 0, 0, 0,
        );
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || unused0 != 0 || unused1 != 0 {
            crate::provider_bugcheck::report(
                0xc4, [FSD_SERVICE_DYNAMIC_OBJECT_DEREFERENCE_LABEL, body, words, raw],
            );
        }
        let status = raw as u32 as i32;
        if status == STATUS_INVALID_HANDLE { return None; }
        if status != STATUS_SUCCESS {
            crate::provider_bugcheck::report(
                0xc4, [FSD_SERVICE_DYNAMIC_OBJECT_DEREFERENCE_LABEL, body, remaining, raw],
            );
        }
        Some(remaining)
    }
}
