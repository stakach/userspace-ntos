//! Root-owned guarded mutexes for exact hosted driver threads.
//!
//! A contended acquire enters the caller's guarded region before publishing its
//! retained Reply. The gate ticket stays owned until wake delivery is reconciled.

use super::*;
use nt_kernel_exec::executive_sync::{guarded_mutex_layout, ExecutiveSyncError,
    GuardedMutexStore, GuardedMutexWaitAdmission, GuardedMutexWaitTicket};

pub(super) const LABEL: u64 = 0x7ED;
const INITIALIZE: u64 = 1;
const ACQUIRE: u64 = 2;
const RELEASE: u64 = 3;
const MUTEX_BYTES: u64 = guarded_mutex_layout::SIZE_OF as u64;

struct Registered {
    domain: HostedDomainIdentity,
    exec: u64,
    pool: Option<(u64, u64)>,
}

struct Pending {
    instance: usize,
    domain: HostedDomainIdentity,
    exec: u64,
    thread_handle: u64,
    thread_body: u64,
    reply: u64,
    ticket: GuardedMutexWaitTicket,
    acquired: bool,
}

static mut STORE: GuardedMutexStore = GuardedMutexStore::new();
static mut REGISTERED: Vec<Registered> = Vec::new();
static mut PENDING: Vec<Pending> = Vec::new();

fn store() -> &'static mut GuardedMutexStore {
    // All hosted pump and wake paths execute under the serialized root owner.
    unsafe { &mut *core::ptr::addr_of_mut!(STORE) }
}

fn registrations() -> &'static mut Vec<Registered> {
    unsafe { &mut *core::ptr::addr_of_mut!(REGISTERED) }
}

fn pending() -> &'static mut Vec<Pending> {
    unsafe { &mut *core::ptr::addr_of_mut!(PENDING) }
}

fn status(error: ExecutiveSyncError) -> i32 {
    match error {
        ExecutiveSyncError::AllocationFailed => STATUS_INSUFFICIENT_RESOURCES,
        ExecutiveSyncError::NotOwned | ExecutiveSyncError::InvalidOwner =>
            0xC000_0046u32 as i32, // STATUS_MUTANT_NOT_OWNED
        _ => STATUS_INVALID_PARAMETER,
    }
}

fn call(operation: u64, mutex: u64) {
    if mutex == 0 || mutex.checked_add(MUTEX_BYTES).is_none() {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, operation, mutex, 0]); }
    }
    let (label, result, _, _, _) = unsafe {
        call_on4((LABEL << 12) | 2, operation, mutex, 0, 0)
    };
    if label != 0 || result as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, operation, mutex, result]); }
    }
}

pub(super) extern "win64" fn initialize(mutex: u64) { call(INITIALIZE, mutex); }
pub(super) extern "win64" fn acquire(mutex: u64) { call(ACQUIRE, mutex); }
pub(super) extern "win64" fn release(mutex: u64) { call(RELEASE, mutex); }

fn pool_identity(inst: DriverInstance, component: u64) -> Result<Option<(u64, u64)>, i32> {
    if !(FSD_POOL_VADDR..FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000).contains(&component) {
        return Ok(None);
    }
    let Some(_guard) = (unsafe { hosted_instance_pool_lock(inst.exec_pool_va) }) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let Some(identity) = (unsafe {
        hosted_source_irp_ledger::pool_range_identity_unlocked(inst, component, MUTEX_BYTES)
    }) else { return Err(STATUS_INVALID_PARAMETER); };
    Ok(Some((identity.component_address, identity.pool_generation)))
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    operation: u64,
    component: u64,
    badge: u64,
    reply: u64,
) -> HostedDriverWaitServiceResult {
    let Some((instance, inst)) = instance_for_pump_channel(ch, reply) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    let Some(caller) = hosted_driver_caller(instance, inst, badge) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    let Some(exec) = hosted_driver_component_object_exec_va(instance, inst, component, MUTEX_BYTES)
    else { return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER); };
    if exec & 7 != 0 { return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER); }
    let pool = match pool_identity(inst, component) {
        Ok(pool) => pool,
        Err(status) => return HostedDriverWaitServiceResult::Reply(status),
    };
    let existing = registrations().iter().position(|row| row.domain == domain && row.exec == exec);
    if operation == INITIALIZE {
        if let Some(index) = existing {
            if registrations()[index].pool != pool {
                return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER);
            }
        } else if registrations().try_reserve(1).is_err() {
            return HostedDriverWaitServiceResult::Reply(STATUS_INSUFFICIENT_RESOURCES);
        }
        let result = unsafe { store().initialize(exec as *mut u8) };
        return match result {
            Ok(()) => {
                if existing.is_none() { registrations().push(Registered { domain, exec, pool }); }
                HostedDriverWaitServiceResult::Reply(STATUS_SUCCESS)
            }
            Err(error) => HostedDriverWaitServiceResult::Reply(status(error)),
        };
    }
    let Some(index) = existing else {
        return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER);
    };
    if registrations()[index].pool != pool {
        return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER);
    }
    let Some(thread_body) = hosted_driver_kmutex::owner_body(ch, inst) else {
        return HostedDriverWaitServiceResult::Reply(STATUS_ACCESS_DENIED);
    };
    match operation {
        ACQUIRE => {
            if pending().iter().any(|row| row.instance == instance
                && (row.thread_handle == caller.thread_handle || row.reply == reply)) {
                return HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER);
            }
            let mut objects = Vec::new();
            let mut keys = Vec::new();
            if pending().try_reserve(1).is_err()
                || objects.try_reserve_exact(1).is_err()
                || keys.try_reserve_exact(1).is_err() {
                return HostedDriverWaitServiceResult::Reply(STATUS_INSUFFICIENT_RESOURCES);
            }
            let admission = unsafe { store().begin_wait(exec as *mut u8, thread_body,
                thread_body as *mut u8, reply) };
            match admission {
                Ok(GuardedMutexWaitAdmission::Acquired) =>
                    HostedDriverWaitServiceResult::Reply(STATUS_SUCCESS),
                Ok(GuardedMutexWaitAdmission::Queued(ticket)) => {
                    let gate = exec + guarded_mutex_layout::GATE as u64;
                    pending().push(Pending { instance, domain, exec,
                        thread_handle: caller.thread_handle, thread_body, reply, ticket,
                        acquired: false });
                    objects.push(gate);
                    keys.push(None);
                    match park_hosted_driver_wait(instance, caller.thread_handle, caller.route,
                        reply, objects, keys, thread_body, false, false,
                        nt_kernel_exec::Deadline::Infinite) {
                        Some(parked) => parked,
                        None => {
                            cancel_pending(instance, caller.thread_handle, reply);
                            HostedDriverWaitServiceResult::Reply(STATUS_INSUFFICIENT_RESOURCES)
                        }
                    }
                }
                Err(error) => HostedDriverWaitServiceResult::Reply(status(error)),
            }
        }
        RELEASE => {
            let wake = unsafe { store().release(exec as *mut u8, thread_body,
                thread_body as *mut u8) };
            match wake {
                Ok(Some(cookie)) => {
                    if !pending().iter().any(|row| row.domain == domain && row.exec == exec
                        && row.reply == cookie && !row.acquired) {
                        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, RELEASE, exec, cookie]); }
                    }
                    let _ = wake_hosted_driver_waiters_for_instance(instance);
                    HostedDriverWaitServiceResult::Reply(STATUS_SUCCESS)
                }
                Ok(None) => HostedDriverWaitServiceResult::Reply(STATUS_SUCCESS),
                Err(error) => HostedDriverWaitServiceResult::Reply(status(error)),
            }
        }
        _ => HostedDriverWaitServiceResult::Reply(STATUS_INVALID_PARAMETER),
    }
}

pub(super) fn ready(gate: u64, thread_handle: u64) -> Option<Result<bool, i32>> {
    let row = pending().iter().find(|row| row.exec + guarded_mutex_layout::GATE as u64 == gate
        && row.thread_handle == thread_handle && !row.acquired)?;
    Some(store().granted(row.exec as *mut u8, row.thread_body, row.ticket).map_err(status))
}

pub(super) fn consume(gate: u64, thread_handle: u64) -> Option<bool> {
    let index = pending().iter().position(|row| row.exec + guarded_mutex_layout::GATE as u64 == gate
        && row.thread_handle == thread_handle && !row.acquired)?;
    let row = &pending()[index];
    let result = unsafe { store().complete_wait(row.exec as *mut u8, row.thread_body, row.ticket) };
    if result.is_err() { return Some(false); }
    pending()[index].acquired = true;
    Some(true)
}

/// Balance the guarded region before any cancellation status can be delivered.
pub(super) fn cancel_pending(instance: usize, thread_handle: u64, reply: u64) {
    let Some(index) = pending().iter().position(|row| row.instance == instance
        && row.thread_handle == thread_handle && row.reply == reply) else { return; };
    let row = pending().remove(index);
    let wake = if row.acquired {
        unsafe { store().release(row.exec as *mut u8, row.thread_body, row.thread_body as *mut u8) }
    } else {
        unsafe { store().cancel_wait(row.exec as *mut u8, row.thread_body,
            row.thread_body as *mut u8, row.ticket) }
    }.unwrap_or_else(|_| unsafe {
        crate::provider_bugcheck::report(0xc4, [LABEL, ACQUIRE, row.exec, row.reply])
    });
    if wake.is_some() { let _ = wake_hosted_driver_waiters_for_instance(row.instance); }
}

pub(super) fn acknowledged(instance: usize, thread_handle: u64, reply: u64, cancelled: bool) {
    if cancelled { cancel_pending(instance, thread_handle, reply); return; }
    if let Some(index) = pending().iter().position(|row| row.instance == instance
        && row.thread_handle == thread_handle && row.reply == reply && row.acquired) {
        pending().remove(index);
    }
}

pub(super) fn quiesced(domain: HostedDomainIdentity) -> bool {
    pending().iter().all(|row| row.domain != domain)
        && registrations().iter().filter(|row| row.domain == domain)
            .all(|row| store().idle(row.exec as *mut u8) == Ok(true))
}

pub(super) fn retire_domain(domain: HostedDomainIdentity) {
    assert!(quiesced(domain));
    let mut index = registrations().len();
    while index != 0 {
        index -= 1;
        if registrations()[index].domain == domain {
            let row = registrations().remove(index);
            unsafe { store().delete(row.exec as *mut u8).expect("quiesced guarded mutex vanished"); }
        }
    }
}

pub(super) fn pool_free_admission(domain: HostedDomainIdentity, pool: (u64, u64)) -> bool {
    registrations().iter().filter(|row| row.domain == domain && row.pool == Some(pool))
        .all(|row| store().idle(row.exec as *mut u8) == Ok(true))
}

pub(super) fn pool_freed(domain: HostedDomainIdentity, pool: (u64, u64)) {
    assert!(pool_free_admission(domain, pool));
    let mut index = registrations().len();
    while index != 0 {
        index -= 1;
        if registrations()[index].domain == domain && registrations()[index].pool == Some(pool) {
            let row = registrations().remove(index);
            unsafe { store().delete(row.exec as *mut u8).expect("freed guarded mutex vanished"); }
        }
    }
}
