//! Root-owned KMUTEX state for hosted drivers.

use super::*;
use nt_kernel_exec::hosted_kmutex::{HostedKmutexManager, KmutexError, KmutexKey, KmutexWait};

pub(super) const LABEL: u64 = 0x7D3;
const STATUS_KMUTEX_BUSY: i32 = 0x8000_0011u32 as i32;
const INITIALIZE: u64 = 1;
const RELEASE: u64 = 2;
const KMUTEX_BYTES: u64 = 0x38;

static mut MANAGER: HostedKmutexManager = HostedKmutexManager::new();

fn domain_key(domain: HostedDomainIdentity) -> (u64, u64) {
    (domain.domain_id.raw(), domain.cookie)
}

fn manager() -> &'static mut HostedKmutexManager {
    // Hosted pump services and waiter wake scans are serialized by the root owner.
    unsafe { &mut *core::ptr::addr_of_mut!(MANAGER) }
}

fn status(error: KmutexError) -> i32 {
    match error {
        KmutexError::Stale => STATUS_INVALID_PARAMETER,
        KmutexError::Busy => STATUS_KMUTEX_BUSY,
        KmutexError::NotOwned => 0xC000_0046u32 as i32, // STATUS_MUTANT_NOT_OWNED
        KmutexError::Exhausted => STATUS_INSUFFICIENT_RESOURCES,
    }
}

unsafe fn publish(exec: u64, count: i32, owner: u64) {
    write_unaligned((exec + 4) as *mut i32, count);
    write_unaligned((exec + 0x28) as *mut u64, owner);
}

unsafe fn initialize_header(exec: u64, component: u64) {
    let header = nt_kernel_exec::hosted_kmutex::initial_header(component);
    core::ptr::copy_nonoverlapping(header.as_ptr(), exec as *mut u8, header.len());
}

pub(super) extern "win64" fn initialize(object: u64, level: u32) {
    if object == 0 || object.checked_add(KMUTEX_BYTES).is_none() {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, INITIALIZE, object, 0]); }
    }
    let (label, status, _, _, _) = unsafe {
        call_on4((LABEL << 12) | 2, INITIALIZE, object, level as u64, 0)
    };
    if label != 0 || status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, INITIALIZE, object, status]); }
    }
}

pub(super) extern "win64" fn release(object: u64, wait: u8) -> i32 {
    if object == 0 { return STATUS_INVALID_PARAMETER; }
    let (label, status, previous, _, _) = unsafe {
        call_on4((LABEL << 12) | 3, RELEASE, object, wait as u64, 0)
    };
    if label != 0 || status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, RELEASE, object, status]); }
    }
    previous as u32 as i32
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    component: u64,
    arg: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    let Some(caller) = hosted_driver_caller(index, inst, badge) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    let Some(domain) = instance_domain_identity(inst) else { return (STATUS_ACCESS_DENIED, 0); };
    let Some(exec) = hosted_driver_component_object_exec_va(index, inst, component, KMUTEX_BYTES)
    else { return (STATUS_INVALID_PARAMETER, 0); };
    match op {
        INITIALIZE => {
            if parked_on(index, exec) { return (STATUS_KMUTEX_BUSY, 0); }
            let pool = if (FSD_POOL_VADDR..FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000)
                .contains(&component) {
                let Some(_guard) = (unsafe { hosted_instance_pool_lock(inst.exec_pool_va) }) else {
                    return (STATUS_INVALID_PARAMETER, 0);
                };
                let Some(identity) = (unsafe {
                    hosted_source_irp_ledger::pool_range_identity_unlocked(inst, component, KMUTEX_BYTES)
                }) else { return (STATUS_INVALID_PARAMETER, 0); };
                Some((identity.component_address, identity.pool_generation))
            } else { None };
            match manager().initialize_with_pool(domain_key(domain), exec, pool) {
                Ok(_) => { unsafe { initialize_header(exec, component); } (STATUS_SUCCESS, 0) }
                Err(error) => (status(error), 0),
            }
        }
        RELEASE if arg == 0 => {
            let Some(key) = manager().key_for(domain_key(domain), exec) else {
                return (STATUS_INVALID_PARAMETER, 0);
            };
            let Some(owner) = owner_body(ch, inst) else { return (STATUS_ACCESS_DENIED, 0); };
            let expected = manager().count(key).expect("live mutex lost state");
            if unsafe { read_unaligned(exec as *const u8) } != 2
                || unsafe { read_unaligned((exec + 4) as *const i32) } != expected
                || unsafe { read_unaligned((exec + 0x28) as *const u64) } != owner {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            let previous = match manager().release(key, caller.thread_handle) {
                Ok(value) => value,
                Err(error) => return (status(error), 0),
            };
            let count = manager().count(key).expect("released live mutex lost its generation");
            unsafe { publish(exec, count, if count == 1 { 0 } else { owner }); }
            if count == 1 { let _ = wake_hosted_driver_waiters_for_instance(index); }
            (STATUS_SUCCESS, previous as u32 as u64)
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    }
}

pub(super) fn owner_body(ch: &crate::spawn_hosts::PumpChannel, inst: DriverInstance) -> Option<u64> {
    let caller = unsafe { crate::provider_registry_caller::resolve(ch).ok()? };
    unsafe { driver_ps_context::project(inst, caller).ok().map(|(_, _, _, thread, _)| thread) }
}

fn parked_on(instance: usize, exec: u64) -> bool {
    unsafe { (*core::ptr::addr_of!(HOSTED_DRIVER_WAITERS)).as_ref() }
        .is_some_and(|rows| rows.iter().any(|row| row.instance == instance
            && row.wake_status.is_none() && row.objects.contains(&exec)))
}

pub(super) fn key_for(domain: HostedDomainIdentity, exec: u64) -> Option<KmutexKey> {
    manager().key_for(domain_key(domain), exec)
}

pub(super) fn ready(exec: u64, key: KmutexKey, thread: u64) -> Result<bool, i32> {
    if !manager().key_matches_object(key, exec)
        || unsafe { read_unaligned(exec as *const u8) } != 2
        || unsafe { read_unaligned((exec + 4) as *const i32) } != manager().count(key).map_err(status)? {
        return Err(STATUS_INVALID_PARAMETER);
    }
    manager().ready(key, thread).map_err(status)
}

pub(super) fn acquire(exec: u64, key: KmutexKey, thread: u64, owner: u64) -> Result<bool, i32> {
    if owner == 0 || !manager().key_matches_object(key, exec)
        || unsafe { read_unaligned(exec as *const u8) } != 2 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    match manager().wait(key, thread).map_err(status)? {
        KmutexWait::Busy => Ok(false),
        KmutexWait::Acquired { count } => {
            unsafe { publish(exec, count, owner); }
            Ok(true)
        }
    }
}

pub(super) fn quiesced(domain: HostedDomainIdentity) -> bool {
    let key = domain_key(domain);
    manager().domain_quiesced(key)
        && unsafe { (*core::ptr::addr_of!(HOSTED_DRIVER_WAITERS)).as_ref() }
            .is_none_or(|waiters| waiters.iter().all(|waiter| waiter.keys.iter().flatten()
                .all(|mutex| !manager().key_in_domain(*mutex, key))))
}

pub(super) fn retire_domain(domain: HostedDomainIdentity) {
    manager().retire_domain(domain_key(domain))
        .expect("hosted mutex owner survived quiesced domain retirement");
}

pub(super) fn pool_free_admission(
    domain: HostedDomainIdentity,
    allocation: (u64, u64),
) -> bool {
    let domain = domain_key(domain);
    manager().pool_free_admission(domain, allocation)
        && unsafe { (*core::ptr::addr_of!(HOSTED_DRIVER_WAITERS)).as_ref() }
            .is_none_or(|waiters| waiters.iter().filter(|waiter| waiter.wake_status.is_none())
                .all(|waiter| waiter.keys.iter().flatten()
                    .all(|key| !manager().key_in_pool(*key, domain, allocation))))
}

pub(super) fn pool_freed(domain: HostedDomainIdentity, allocation: (u64, u64)) {
    manager().retire_pool(domain_key(domain), allocation)
        .expect("admitted pool free lost its mutex generation");
}
