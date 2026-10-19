//! Canonical Ps identity queries and owned process-pointer references for hosted drivers.
//!
//! A numeric EPROCESS pointer is never authority. The service authenticates the
//! physical driver domain, validates the body in ProcessManager, and retains a
//! provider-owned lookup reference until an exact release or domain retirement.

use super::*;

pub(super) const LABEL: u64 = 0x7C4;
const GET_ID: u64 = 1;
const LOOKUP: u64 = 2;
const RELEASE: u64 = 3;
const RETAIN: u64 = 4;
pub(super) const QUERY_PROCESS_EXIT_STATUS: u64 = 5;
pub(super) const QUERY_IS_SYSTEM_PROCESS: u64 = 6;
pub(super) const QUERY_IS_THREAD_TERMINATING: u64 = 7;
pub(super) const QUERY_PROCESS_SESSION_ID: u64 = 8;
const QUERY_PROCESS_CREATE_TIME: u64 = 9;
const STATUS_UNSUPPORTED_OBJECT: i32 = STATUS_NOT_SUPPORTED;

#[derive(Clone, Copy)]
struct ProcessLease {
    domain: HostedDomainIdentity,
    pml4: u64,
    body: u64,
}

static mut PROCESS_LEASES: Vec<ProcessLease> = Vec::new();

fn request(op: u64, value: u64) -> (i32, u64) {
    unsafe {
        let (words, raw, result, unused0, unused1) =
            call_on4_raw((LABEL << 12) | 4, op, value, 0, 0);
        let canonical_status = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical_status || unused0 != 0 || unused1 != 0
            || (raw as u32 as i32 != STATUS_SUCCESS && result != 0)
        {
            crate::provider_bugcheck::report(0xc4, [LABEL, op, words, raw]);
        }
        (raw as u32 as i32, result)
    }
}

/// Share this domain-authenticated Ps transport with the focused state-query
/// adapters. A caller never dereferences a supplied EPROCESS/ETHREAD pointer.
pub(super) fn query_state(op: u64, body: u64) -> u64 {
    let (status, value) = request(op, body);
    if status != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, op, body, status as u32 as u64]); }
    }
    value
}

/// `HANDLE PsGetProcessId(PEPROCESS)`. The pointer must be a live canonical
/// process body, including the initial System process.
pub(super) extern "win64" fn ps_get_process_id(process: u64) -> u64 {
    let (status, id) = request(GET_ID, process);
    if status != STATUS_SUCCESS || id == 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, GET_ID, process, status as u32 as u64]); }
    }
    id
}

pub(super) extern "win64" fn ps_get_process_create_time_quad_part(process: u64) -> i64 {
    query_state(QUERY_PROCESS_CREATE_TIME, process) as i64
}

/// A canonical body belongs to this call only if it is the caller's effective process or a
/// provider-owned Ps lookup reference. A numeric EPROCESS value alone conveys no authority.
pub(super) fn authorized_process(
    pm: &nt_process::ProcessManager,
    caller: nt_process::native_handle::NativeHandleCaller,
    provider: DriverInstance,
    body: u64,
) -> Result<(nt_process::ProcessId, u64), u32> {
    pm.validate_native_handle_caller(caller)?;
    let pid = pm.pid_for_kernel_process_object(body)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let domain = instance_domain_identity(provider).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let owned = pid == caller.effective_process() || unsafe {
        (&*core::ptr::addr_of!(PROCESS_LEASES)).iter().any(|lease| {
            lease.domain == domain && lease.pml4 == provider.pml4 && lease.body == body
        })
    };
    if !owned {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let sequence = pm.process_sequence_for_kernel_process_object(body)?;
    Ok((pid, sequence))
}

/// `NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS*)`.
pub(super) extern "win64" fn ps_lookup_process_by_process_id(
    process_id: u64,
    process_out: *mut u64,
) -> i32 {
    if process_out.is_null() {
        return STATUS_ACCESS_VIOLATION;
    }
    unsafe { write_unaligned(process_out, 0); }
    let (status, body) = request(LOOKUP, process_id);
    if status == STATUS_SUCCESS {
        if body == 0 {
            unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, LOOKUP, process_id, 0]); }
        }
        unsafe { write_unaligned(process_out, body); }
    }
    status
}

/// Used by the generic ObfDereferenceObject adapter only after file/device
/// classification. `None` means the pointer is not a canonical Ps body.
pub(super) fn release_process_if_owned(body: u64) -> Option<u64> {
    let (status, references) = request(RELEASE, body);
    if status == STATUS_UNSUPPORTED_OBJECT {
        return None;
    }
    if status != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, RELEASE, body, status as u32 as u64]); }
    }
    Some(references)
}

/// Used by ObfReferenceObject for canonical Ps bodies. A non-Ps pointer keeps
/// the generic object's separate reference contract.
pub(super) fn retain_process_if_known(body: u64) -> Option<u64> {
    let (status, _references) = request(RETAIN, body);
    if status == STATUS_UNSUPPORTED_OBJECT {
        return None;
    }
    if status != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, RETAIN, body, status as u32 as u64]); }
    }
    Some(body)
}

/// The pump has authenticated badge, exact Reply, and source channel before
/// invoking this service. This function revalidates the driver instance and
/// canonical native caller before any process-manager effect.
pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    value: u64,
    active_reply_cap: u64,
) -> (i32, u64) {
    let Some((_instance, inst)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0);
    };
    let domain = match instance_domain_identity(inst) {
        Some(domain) => domain,
        None => return (STATUS_INVALID_HANDLE, 0),
    };
    let caller = match unsafe { crate::provider_registry_caller::resolve(ch) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0),
    };
    unsafe {
        match op {
            GET_ID => match crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.validate_native_handle_caller(caller)?;
                let pid = pm.pid_for_kernel_process_object(value)
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
                Ok(u64::from(pid))
            }) {
                Ok(pid) => (STATUS_SUCCESS, pid),
                Err(status) => (status as i32, 0),
            },
            LOOKUP => {
                let Ok(pid) = nt_process::ProcessId::try_from(value) else {
                    return (STATUS_INVALID_PARAMETER, 0);
                };
                let target = match crate::ps_object_provider::ProviderRoot::hosted(domain, inst.pml4) {
                    Ok(target) => target,
                    Err(status) => return (status as i32, 0),
                };
                let leases = &mut *core::ptr::addr_of_mut!(PROCESS_LEASES);
                if leases.try_reserve(1).is_err() {
                    return (nt_process::STATUS_INSUFFICIENT_RESOURCES as i32, 0);
                }
                let result = crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.validate_native_handle_caller(caller)?;
                    let (body, _references) = pm.lookup_kernel_process_by_id(pid)?;
                    let projected = if driver_ps_pool_alias::contains(
                        body,
                        nt_kernel_abi::ps_reactos_x64::EPROCESS_BODY_BYTES,
                    ) {
                        driver_ps_pool_alias::grant(
                            inst,
                            body,
                            nt_kernel_abi::ps_reactos_x64::EPROCESS_BODY_BYTES,
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
                        pm.release_kernel_object_pointer(body)
                            .expect("unpublished Ps lookup retains its exact reference");
                        return Err(status);
                    }
                    Ok(body)
                });
                match result {
                    Ok(body) => {
                        leases.push(ProcessLease { domain, pml4: inst.pml4, body });
                        (STATUS_SUCCESS, body)
                    }
                    Err(status) => (status as i32, 0),
                }
            }
            RELEASE => {
                let known = crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.validate_native_handle_caller(caller)?;
                    Ok(pm.pid_for_kernel_process_object(value).is_some())
                });
                match known {
                    Ok(false) => return (STATUS_UNSUPPORTED_OBJECT, 0),
                    Err(status) => return (status as i32, 0),
                    Ok(true) => {}
                }
                let leases = &mut *core::ptr::addr_of_mut!(PROCESS_LEASES);
                let Some(index) = leases.iter().position(|lease| {
                    lease.domain == domain && lease.pml4 == inst.pml4 && lease.body == value
                }) else {
                    return (STATUS_INVALID_HANDLE, 0);
                };
                match crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.validate_native_handle_caller(caller)?;
                    pm.release_kernel_object_pointer(value)
                }) {
                    Ok(references) => {
                        leases.swap_remove(index);
                        (STATUS_SUCCESS, u64::from(references))
                    }
                    Err(status) => (status as i32, 0),
                }
            }
            RETAIN => {
                let leases = &mut *core::ptr::addr_of_mut!(PROCESS_LEASES);
                if leases.try_reserve(1).is_err() {
                    return (nt_process::STATUS_INSUFFICIENT_RESOURCES as i32, 0);
                }
                let result = crate::service_sec_image::with_provider_process_manager(|pm| {
                    pm.validate_native_handle_caller(caller)?;
                    if pm.pid_for_kernel_process_object(value).is_none() {
                        return Ok(None);
                    }
                    pm.retain_kernel_object_pointer(value).map(Some)
                });
                match result {
                    Ok(None) => (STATUS_UNSUPPORTED_OBJECT, 0),
                    Ok(Some(references)) => {
                        leases.push(ProcessLease { domain, pml4: inst.pml4, body: value });
                        (STATUS_SUCCESS, u64::from(references))
                    }
                    Err(status) => (status as i32, 0),
                }
            }
            QUERY_PROCESS_CREATE_TIME => match crate::service_sec_image::with_provider_process_manager(|pm| {
                let (pid, _) = authorized_process(pm, caller, inst, value)?;
                pm.process_times(pid)
                    .map(|times| times.create_time as u64)
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)
            }) {
                Ok(create_time) => (STATUS_SUCCESS, create_time),
                Err(status) => (status as i32, 0),
            },
            QUERY_PROCESS_EXIT_STATUS => match crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.validate_native_handle_caller(caller)?;
                pm.kernel_process_state(value)
                    .map(|state| u64::from(state.exit_status))
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)
            }) {
                Ok(exit_status) => (STATUS_SUCCESS, exit_status),
                Err(status) => (status as i32, 0),
            },
            QUERY_IS_SYSTEM_PROCESS => match crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.validate_native_handle_caller(caller)?;
                let pid = pm.pid_for_kernel_process_object(value)
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
                Ok(u64::from(pm.is_initial_system_process(pid)))
            }) {
                Ok(is_system) => (STATUS_SUCCESS, is_system),
                Err(status) => (status as i32, 0),
            },
            QUERY_IS_THREAD_TERMINATING => match crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.validate_native_handle_caller(caller)?;
                pm.kernel_thread_state(value)
                    .map(|state| u64::from(state.terminating))
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)
            }) {
                Ok(terminating) => (STATUS_SUCCESS, terminating),
                Err(status) => (status as i32, 0),
            },
            QUERY_PROCESS_SESSION_ID => match crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.validate_native_handle_caller(caller)?;
                pm.kernel_process_state(value)
                    .map(|state| u64::from(state.session_id))
                    .ok_or(nt_process::STATUS_INVALID_HANDLE)
            }) {
                Ok(session_id) => (STATUS_SUCCESS, session_id),
                Err(status) => (status as i32, 0),
            },
            _ => (STATUS_INVALID_PARAMETER, 0),
        }
    }
}

/// Retire every process lookup reference owned by the exact hosted domain.
/// A failed release leaves its ledger row intact and blocks domain reuse.
pub(super) fn retire(inst: DriverInstance) -> Result<(), u32> {
    let domain = instance_domain_identity(inst).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let leases = unsafe { &mut *core::ptr::addr_of_mut!(PROCESS_LEASES) };
    let mut index = 0;
    while index < leases.len() {
        let lease = leases[index];
        if lease.domain != domain || lease.pml4 != inst.pml4 {
            index += 1;
            continue;
        }
        unsafe {
            crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.release_kernel_object_pointer(lease.body).map(|_| ())
            })?;
        }
        leases.swap_remove(index);
    }
    Ok(())
}
