//! Native `ObCreateObjectType` for exact hosted image and delete-callback ownership.
//!
//! The component captures the name and initializer before IPC and allocates a real, persistent
//! `OBJECT_TYPE` body in its own retained pool. The root authenticates the physical driver, the
//! allocation, and the delete callback's loaded-image generation before committing the type to
//! the Object Manager ledger. No callback is invoked while the ledger is borrowed.

use super::*;
use nt_object_manager::hosted_dynamic_type::{
    DynamicObjectLease, DynamicTypeDefinition, DynamicTypeId, DynamicTypeOwner, HostedDynamicTypeRegistry,
};
use nt_object_manager::object_type::{ObjectType, ObjectTypeInitializer};

pub(super) const LABEL: u64 = 0x7C8;
const NAME_CAP_UNITS: usize = 64;
const ARG_NAME_LENGTH: u64 = 0x80;
const ARG_NAME_UNITS: u64 = 0x88;
const TYPE_BODY_BYTES: u64 = core::mem::size_of::<ObjectType>() as u64;
const TYPE_ALLOCATION_BYTES: u64 = TYPE_BODY_BYTES + (NAME_CAP_UNITS as u64 + 1) * 2;
const _: () = assert!(core::mem::size_of::<ObjectTypeInitializer>() as u64 <= ARG_NAME_LENGTH);
const _: () = assert!(ARG_NAME_UNITS + NAME_CAP_UNITS as u64 * 2 <= FSD_ARG_BYTES);

#[derive(Clone, Copy)]
struct TypeBinding {
    instance: usize,
    pool_pointer: u64,
    type_id: DynamicTypeId,
    owner: DynamicTypeOwner,
}

static mut REGISTRY: Option<HostedDynamicTypeRegistry> = None;
static mut BINDINGS: Vec<TypeBinding> = Vec::new();

/// `NTSTATUS ObCreateObjectType(PUNICODE_STRING, POBJECT_TYPE_INITIALIZER,
/// PSECURITY_DESCRIPTOR, POBJECT_TYPE*)`.
pub(super) extern "win64" fn ob_create_object_type(
    name: u64,
    initializer: u64,
    security_descriptor: u64,
    output: *mut u64,
) -> i32 {
    if output.is_null() { return STATUS_ACCESS_VIOLATION; }
    unsafe { write_unaligned(output, 0); }
    if name == 0 || initializer == 0 { return STATUS_INVALID_PARAMETER; }
    if security_descriptor != 0 { return STATUS_NOT_SUPPORTED; }
    unsafe {
        if hosted_current_irql() != 0 { return STATUS_INVALID_DEVICE_REQUEST; }
        let descriptor = read_unaligned(name as *const nt_ntdll_layout::UnicodeString);
        let length = descriptor.length as usize;
        if length == 0 || length % 2 != 0 || length > NAME_CAP_UNITS * 2
            || descriptor.maximum_length < descriptor.length || descriptor.buffer == 0
        { return STATUS_INVALID_PARAMETER; }
        let init = read_unaligned(initializer as *const ObjectTypeInitializer);
        if init.length as usize != core::mem::size_of::<ObjectTypeInitializer>() {
            return STATUS_INVALID_PARAMETER;
        }
        if !init.supports_hosted_delete() {
            return STATUS_NOT_SUPPORTED;
        }
        let _guard = component_device_reply_lock();
        let type_pointer = pool_alloc(TYPE_ALLOCATION_BYTES);
        if type_pointer == 0 { return STATUS_INSUFFICIENT_RESOURCES; }
        core::ptr::write_bytes(type_pointer as *mut u8, 0, TYPE_ALLOCATION_BYTES as usize);
        let name_pointer = type_pointer + TYPE_BODY_BYTES;
        write_unaligned((type_pointer + core::mem::offset_of!(ObjectType, name) as u64) as *mut u16, descriptor.length);
        write_unaligned((type_pointer + core::mem::offset_of!(ObjectType, name) as u64 + 2) as *mut u16, descriptor.length);
        write_unaligned((type_pointer + core::mem::offset_of!(ObjectType, name) as u64 + 8) as *mut u64, name_pointer);
        core::ptr::copy_nonoverlapping(
            &init as *const ObjectTypeInitializer as *const u8,
            (type_pointer + core::mem::offset_of!(ObjectType, type_info) as u64) as *mut u8,
            core::mem::size_of::<ObjectTypeInitializer>(),
        );
        core::ptr::copy_nonoverlapping(
            &init as *const ObjectTypeInitializer as *const u8,
            FSD_ARG_VADDR as *mut u8,
            core::mem::size_of::<ObjectTypeInitializer>(),
        );
        write_volatile((FSD_ARG_VADDR + ARG_NAME_LENGTH) as *mut u16, descriptor.length);
        for index in 0..length / 2 {
            let unit = read_unaligned((descriptor.buffer + index as u64 * 2) as *const u16);
            if unit == 0 {
                pool_free(type_pointer);
                return STATUS_INVALID_PARAMETER;
            }
            write_unaligned((name_pointer + index as u64 * 2) as *mut u16, unit);
            write_volatile((FSD_ARG_VADDR + ARG_NAME_UNITS + index as u64 * 2) as *mut u16, unit);
        }
        let (words, raw, index, unused0, unused1) = call_on4_raw(
            (LABEL << 12) | 4, type_pointer, 0, 0, 0,
        );
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || unused0 != 0 || unused1 != 0
            || (raw as u32 as i32 == STATUS_SUCCESS) != (index != 0)
        {
            // The root may have committed a permanent type. Neither replay nor pool reuse is safe.
            crate::provider_bugcheck::report(0xc4, [LABEL, type_pointer, words, raw]);
        }
        let status = raw as u32 as i32;
        if status != STATUS_SUCCESS {
            pool_free(type_pointer);
            return status;
        }
        let Ok(native_index) = u8::try_from(index) else {
            crate::provider_bugcheck::report(0xc4, [LABEL, type_pointer, index, raw]);
        };
        write_unaligned((type_pointer + core::mem::offset_of!(ObjectType, index) as u64) as *mut u8, native_index);
        write_unaligned(output, type_pointer);
        STATUS_SUCCESS
    }
}

/// Called from the authenticated pump for the exact four-word request shape. The shared argument
/// page is read through the physical instance's root view, never through a driver supplied VA.
pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    type_pointer: u64,
    reserved0: u64,
    reserved1: u64,
    reserved2: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> (i32, u64) {
    if reserved0 != 0 || reserved1 != 0 || reserved2 != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    if hosted_driver_caller(index, inst, caller_badge).is_none() || inst.exec_arg_va == 0 {
        return (STATUS_INVALID_HANDLE, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0),
    };
    let verified = unsafe { crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)
    }) };
    if let Err(status) = verified { return (status as i32, 0); }
    unsafe {
        let Some(exec_pointer) = hosted_instance_pool_allocation_exec_if_live(
            inst, type_pointer, TYPE_ALLOCATION_BYTES,
        ) else { return (STATUS_INVALID_PARAMETER, 0); };
        let init = read_volatile(inst.exec_arg_va as *const ObjectTypeInitializer);
        let name_length = read_volatile((inst.exec_arg_va + ARG_NAME_LENGTH) as *const u16) as usize;
        if !init.supports_hosted_delete()
            || name_length == 0 || name_length % 2 != 0 || name_length > NAME_CAP_UNITS * 2
        { return (STATUS_INVALID_PARAMETER, 0); }
        let Some(image) = hosted_driver_process_notify::published_image_for_callback(index, inst, init.methods[3])
        else { return (STATUS_INVALID_PARAMETER, 0); };
        let type_info = exec_pointer + core::mem::offset_of!(ObjectType, type_info) as u64;
        // The body and IPC copy must describe one exact initializer. A changed scalar or flag
        // cannot authorize a different permanent type under the same physical allocation.
        if (0..core::mem::size_of::<ObjectTypeInitializer>()).any(|offset| {
            read_volatile((type_info + offset as u64) as *const u8)
                != read_volatile((inst.exec_arg_va + offset as u64) as *const u8)
        }) || read_volatile((exec_pointer + core::mem::offset_of!(ObjectType, name) as u64 + 8) as *const u64)
                != type_pointer + TYPE_BODY_BYTES
        { return (STATUS_INVALID_PARAMETER, 0); }
        let mut name = Vec::new();
        if name.try_reserve_exact(name_length / 2).is_err() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        for offset in (0..name_length).step_by(2) {
            let unit = read_volatile((inst.exec_arg_va + ARG_NAME_UNITS + offset as u64) as *const u16);
            let type_unit = read_volatile((exec_pointer + TYPE_BODY_BYTES + offset as u64) as *const u16);
            if unit == 0 || unit != type_unit { return (STATUS_INVALID_PARAMETER, 0); }
            name.push(unit);
        }
        let owner = DynamicTypeOwner {
            image_base: image.run_base,
            image_len: image.image_len,
            image_generation: image.publication_generation,
            domain_id: inst.hosted_domain_id,
            domain_cookie: inst.hosted_domain_cookie,
        };
        let definition = DynamicTypeDefinition {
            name,
            delete_procedure: init.methods[3],
            invalid_attributes: init.invalid_attributes,
            generic_mapping: [
                init.generic_mapping.generic_read,
                init.generic_mapping.generic_write,
                init.generic_mapping.generic_execute,
                init.generic_mapping.generic_all,
            ],
            valid_access_mask: init.valid_access_mask,
            pool_type: init.pool_type,
            default_nonpaged_pool_charge: init.default_nonpaged_pool_charge,
            use_default_object: init.use_default_object(),
            security_required: init.security_required(),
        };
        let bindings = &mut *core::ptr::addr_of_mut!(BINDINGS);
        if bindings.iter().any(|row| row.instance == index && row.pool_pointer == type_pointer) {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        if bindings.try_reserve(1).is_err() { return (STATUS_INSUFFICIENT_RESOURCES, 0); }
        let registry = (&mut *core::ptr::addr_of_mut!(REGISTRY))
            .get_or_insert_with(HostedDynamicTypeRegistry::new);
        if registry.type_count() >= (u8::MAX as usize - 26) {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        let type_id = match registry.register(owner, definition) {
            Ok(id) => id,
            Err(status) => return (status.raw(), 0),
        };
        bindings.push(TypeBinding {
            instance: index,
            pool_pointer: type_pointer,
            type_id,
            owner,
        });
        // Built-in native type indices end at 26. The ledger sequence never reuses a type.
        (STATUS_SUCCESS, type_id.sequence() + 26)
    }
}

/// A registered type is permanent in NT; its driver image and physical domain cannot be retired
/// while the Object Manager can still call its DeleteProcedure.
pub(super) unsafe fn blocks_instance_retirement(instance_index: usize) -> bool {
    (&*core::ptr::addr_of!(BINDINGS)).iter().any(|row| {
        row.instance == instance_index
            && (&*core::ptr::addr_of!(REGISTRY)).as_ref().is_some_and(|registry| {
                registry.owner(row.type_id) == Some(row.owner)
                    && registry.blocks_owner_retirement(row.owner)
            })
    })
}

/// The native type descriptor must never reenter the component pool free list while its image
/// callback remains registered. The caller checks this before accepting `ExFreePool` retirement.
pub(super) unsafe fn owns_type_allocation(instance_index: usize, pointer: u64) -> bool {
    (&*core::ptr::addr_of!(BINDINGS)).iter().any(|row| {
        row.instance == instance_index && row.pool_pointer == pointer
    })
}

/// A driver's ExFreePool cannot recycle a registered object body before its exact
/// DeleteProcedure ticket completes, including while callback delivery is uncertain.
pub(super) unsafe fn owns_object_allocation(instance_index: usize, pointer: u64) -> bool {
    let Some(inst) = instance(instance_index) else { return false; };
    let Some(registry) = (&*core::ptr::addr_of!(REGISTRY)).as_ref() else { return false; };
    (&*core::ptr::addr_of!(BINDINGS)).iter().any(|row| {
        row.instance == instance_index
            && row.owner.domain_id == inst.hosted_domain_id
            && row.owner.domain_cookie == inst.hosted_domain_cookie
            && registry.owner(row.type_id) == Some(row.owner)
            && registry.owns_live_body(row.type_id, pointer)
    })
}

/// Resolve the exact persistent `OBJECT_TYPE` allocation registered by this physical driver
/// incarnation. The native adapter must not infer type authority from a mutable `Index` field.
pub(super) unsafe fn type_binding_for_instance(
    instance_index: usize,
    type_pointer: u64,
    inst: DriverInstance,
) -> Option<DynamicTypeId> {
    let row = (&*core::ptr::addr_of!(BINDINGS)).iter().find(|row| {
        row.instance == instance_index && row.pool_pointer == type_pointer
            && row.owner.domain_id == inst.hosted_domain_id
            && row.owner.domain_cookie == inst.hosted_domain_cookie
    })?;
    let registry = (&*core::ptr::addr_of!(REGISTRY)).as_ref()?;
    (registry.owner(row.type_id) == Some(row.owner)).then_some(row.type_id)
}

/// The broker calls this only after authenticating the caller and an exact live pool allocation.
pub(super) unsafe fn publish_object_for_instance(
    instance_index: usize,
    type_pointer: u64,
    inst: DriverInstance,
    body: u64,
) -> Result<DynamicObjectLease, nt_status::NtStatus> {
    let ty = type_binding_for_instance(instance_index, type_pointer, inst)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    (&mut *core::ptr::addr_of_mut!(REGISTRY)).as_mut()
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?
        .publish_object(ty, body)
}

pub(super) unsafe fn pending_object_for_instance(
    instance_index: usize,
    inst: DriverInstance,
    body: u64,
) -> Option<DynamicObjectLease> {
    let registry = (&*core::ptr::addr_of!(REGISTRY)).as_ref()?;
    let lease = registry.pending_object_for_body(body)?;
    let owner = registry.owner(lease.type_id())?;
    (&*core::ptr::addr_of!(BINDINGS)).iter().any(|row| {
        row.instance == instance_index && row.type_id == lease.type_id()
            && row.owner == owner
            && owner.domain_id == inst.hosted_domain_id
            && owner.domain_cookie == inst.hosted_domain_cookie
    }).then_some(lease)
}

pub(super) unsafe fn object_for_instance(
    instance_index: usize,
    inst: DriverInstance,
    body: u64,
    generation: u64,
) -> Option<DynamicObjectLease> {
    let registry = (&*core::ptr::addr_of!(REGISTRY)).as_ref()?;
    let lease = registry.object_for_body(body, generation)?;
    let owner = registry.owner(lease.type_id())?;
    (&*core::ptr::addr_of!(BINDINGS)).iter().any(|row| {
        row.instance == instance_index && row.type_id == lease.type_id()
            && row.owner == owner
            && owner.domain_id == inst.hosted_domain_id
            && owner.domain_cookie == inst.hosted_domain_cookie
    }).then_some(lease)
}

pub(super) unsafe fn registry_mut() -> Option<&'static mut HostedDynamicTypeRegistry> {
    (&mut *core::ptr::addr_of_mut!(REGISTRY)).as_mut()
}

/// Bind a pending object generation to the same physical image and domain that registered its
/// type. The numeric callback address alone never selects a driver instance.
pub(super) unsafe fn pending_delete_binding(
    lease: DynamicObjectLease,
) -> Option<(usize, DriverInstance, u64)> {
    let registry = (&*core::ptr::addr_of!(REGISTRY)).as_ref()?;
    let owner = registry.owner(lease.type_id())?;
    let callback = registry.definition(lease.type_id())?.delete_procedure;
    let row = (&*core::ptr::addr_of!(BINDINGS)).iter().find(|row| {
        row.type_id == lease.type_id() && row.owner == owner
    })?;
    let inst = instance(row.instance)?;
    if inst.hosted_domain_id != owner.domain_id
        || inst.hosted_domain_cookie != owner.domain_cookie
        || hosted_driver_process_notify::published_image_for_callback(row.instance, inst, callback)
            .is_none_or(|image| image.run_base != owner.image_base
                || image.publication_generation != owner.image_generation)
    { return None; }
    Some((row.instance, inst, callback))
}
