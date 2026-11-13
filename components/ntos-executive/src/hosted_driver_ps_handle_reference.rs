//! Typed Process/Thread handle references for isolated native drivers.
//!
//! The source handle is decoded only by ProcessManager under the authenticated
//! native caller. The acquired `NativeObjectReference` remains owned here until
//! the driver's exact ObfDereferenceObject or domain retirement releases it.

use super::*;
use nt_process::native_handle::{NativeObjectReference, PsHandleType};

pub(super) const LABEL: u64 = 0x7C9;
const REFERENCE: u64 = 1;
const RELEASE: u64 = 2;
const STATUS_UNOWNED_OBJECT: i32 = STATUS_NOT_SUPPORTED;

struct TypedLease {
    domain: HostedDomainIdentity,
    pml4: u64,
    reference: NativeObjectReference,
}

static mut LEASES: Vec<TypedLease> = Vec::new();

/// `NTSTATUS ObReferenceObjectByHandle` for the two Ps OBJECT_TYPE exports.
/// `OBJECT_HANDLE_INFORMATION` is copied only when ProcessManager supplied a
/// real granted mask; pseudo handles have no synthetic maximum-access grant.
pub(super) extern "win64" fn ob_reference_object_by_handle(
    handle: u64,
    desired_access: u32,
    object_type: u64,
    access_mode: u8,
    object_out: u64,
    handle_information: u64,
) -> i32 {
    if object_out == 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    unsafe { write_unaligned(object_out as *mut u64, 0); }
    if handle == 0 || access_mode > 1 {
        return STATUS_INVALID_HANDLE;
    }
    let expected = match object_type {
        value if value == nt_object_manager::object_type::process_object_type_addr() => 1u64,
        value if value == nt_object_manager::object_type::thread_object_type_addr() => 2u64,
        _ => return nt_process::native_handle::STATUS_OBJECT_TYPE_MISMATCH as i32,
    };
    let packed = expected | (u64::from(access_mode) << 8)
        | (u64::from(handle_information != 0) << 9);
    unsafe {
        let (words, raw, body, attributes, granted_access) = call_on4_raw(
            (LABEL << 12) | 4,
            REFERENCE,
            handle,
            packed,
            u64::from(desired_access),
        );
        let canonical_status = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        let status = raw as u32 as i32;
        if words != 4 || !canonical_status
            || (status == STATUS_SUCCESS && (body == 0 || attributes > u32::MAX as u64
                || granted_access > u32::MAX as u64))
            || (status != STATUS_SUCCESS && (body != 0 || attributes != 0 || granted_access != 0))
        {
            crate::provider_bugcheck::report(0xc4, [LABEL, REFERENCE, words, raw]);
        }
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

/// Called by generic ObfDereferenceObject before the older process-lookup
/// ledger. A canonical Process body without this broker's lease may belong to
/// that ledger. A canonical Thread body without a lease is a contract violation.
pub(super) fn release_if_owned(body: u64) -> Option<u64> {
    unsafe {
        let (words, raw, result, unused0, unused1) =
            call_on4_raw((LABEL << 12) | 4, RELEASE, body, 0, 0);
        let canonical_status = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical_status || unused0 != 0 || unused1 != 0 || result != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, RELEASE, words, raw]);
        }
        let status = raw as u32 as i32;
        if status == STATUS_UNOWNED_OBJECT {
            return None;
        }
        if status != STATUS_SUCCESS {
            crate::provider_bugcheck::report(0xc4, [LABEL, RELEASE, body, raw]);
        }
        Some(0)
    }
}

/// The pump authenticates badge and Reply before this call. Admission is
/// rechecked against the exact driver instance and retained native caller.
pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    op: u64,
    value: u64,
    packed: u64,
    desired_access: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    let Some((_instance, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let domain = match instance_domain_identity(inst) {
        Some(domain) => domain,
        None => return (STATUS_INVALID_HANDLE, 0, 0, 0),
    };
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    unsafe {
        match op {
            REFERENCE => {
                let expected = match packed & 0xff {
                    1 => PsHandleType::Process,
                    2 => PsHandleType::Thread,
                    _ => return (STATUS_INVALID_PARAMETER, 0, 0, 0),
                };
                let mode = (packed >> 8) & 1;
                let wants_info = packed & (1 << 9) != 0;
                if packed & !0x3ff != 0 || desired_access > u32::MAX as u64 {
                    return (STATUS_INVALID_PARAMETER, 0, 0, 0);
                }
                let target = match crate::ps_object_provider::ProviderRoot::hosted(domain, inst.pml4) {
                    Ok(target) => target,
                    Err(status) => return (status as i32, 0, 0, 0),
                };
                let leases = &mut *core::ptr::addr_of_mut!(LEASES);
                if leases.try_reserve(1).is_err() {
                    return (nt_process::STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0);
                }
                let result = crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.validate_native_handle_caller(caller)?;
                    let access_caller = if mode == 0 {
                        caller
                    } else {
                        pm.capture_native_handle_caller(
                            caller.original_thread(),
                            nt_types::AccessMode::UserMode,
                        )?
                    };
                    let mut reference = pm.reference_native_ps_handle(
                        access_caller,
                        value,
                        Some(expected),
                        desired_access as u32,
                    )?;
                    let info = reference.information();
                    if wants_info && info.granted_access.is_none() {
                        reference.release(pm)?;
                        return Err(nt_process::native_handle::STATUS_NOT_SUPPORTED);
                    }
                    let body = reference.body();
                    let body_bytes = match expected {
                        PsHandleType::Process => nt_kernel_abi::ps_hosted_x64::EPROCESS_BODY_BYTES,
                        PsHandleType::Thread => nt_kernel_abi::ps_hosted_x64::ETHREAD_BODY_BYTES,
                    };
                    let projected = if driver_ps_pool_alias::contains(
                        body,
                        body_bytes,
                    ) {
                        driver_ps_pool_alias::grant(
                            inst,
                            body,
                            body_bytes,
                        )
                    } else {
                        crate::ps_object_backing::grant_referenced_body(
                            pm,
                            body,
                            target,
                            crate::ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed),
                        )
                    };
                    if let Err(status) = projected {
                        reference.release(pm)
                            .expect("unpublished typed Ps reference retains its exact owner");
                        return Err(status);
                    }
                    Ok((reference, info))
                });
                match result {
                    Ok((reference, info)) => {
                        let body = reference.body();
                        let attributes = u64::from(info.attributes);
                        let granted = u64::from(info.granted_access.unwrap_or(0));
                        leases.push(TypedLease { domain, pml4: inst.pml4, reference });
                        (STATUS_SUCCESS, body, attributes, granted)
                    }
                    Err(status) => (status as i32, 0, 0, 0),
                }
            }
            RELEASE if packed == 0 && desired_access == 0 => {
                let known = crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.validate_native_handle_caller(caller)?;
                    Ok((pm.pid_for_kernel_process_object(value).is_some(),
                        pm.tid_for_kernel_thread_object(value).is_some()))
                });
                let (process, thread) = match known {
                    Ok(known) => known,
                    Err(status) => return (status as i32, 0, 0, 0),
                };
                if !process && !thread {
                    return (STATUS_UNOWNED_OBJECT, 0, 0, 0);
                }
                let leases = &mut *core::ptr::addr_of_mut!(LEASES);
                let Some(index) = leases.iter().position(|lease| {
                    lease.domain == domain && lease.pml4 == inst.pml4
                        && lease.reference.body() == value
                }) else {
                    return (if process { STATUS_UNOWNED_OBJECT } else { STATUS_INVALID_HANDLE }, 0, 0, 0);
                };
                match crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.validate_native_handle_caller(caller)?;
                    leases[index].reference.release(pm)
                }) {
                    Ok(()) => {
                        leases.swap_remove(index);
                        (STATUS_SUCCESS, 0, 0, 0)
                    }
                    Err(status) => (status as i32, 0, 0, 0),
                }
            }
            _ => (STATUS_INVALID_PARAMETER, 0, 0, 0),
        }
    }
}

/// Release all typed Ps references owned by this exact retiring driver domain.
/// Failed release retains its ledger row and blocks domain reuse.
pub(super) fn retire(inst: DriverInstance) -> Result<(), u32> {
    let domain = instance_domain_identity(inst).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let leases = unsafe { &mut *core::ptr::addr_of_mut!(LEASES) };
    let mut index = 0;
    while index < leases.len() {
        if leases[index].domain != domain || leases[index].pml4 != inst.pml4 {
            index += 1;
            continue;
        }
        unsafe {
            crate::service_sec_image::with_provider_process_manager(|pm| {
                leases[index].reference.release(pm)
            })?;
        }
        leases.swap_remove(index);
    }
    Ok(())
}
