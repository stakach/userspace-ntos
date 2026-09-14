//! Executive scheduling for component-owned FILE_OBJECT retirement receipts.

use super::*;

const RETRY_INTERVAL_100NS: u64 = 10_000_000;
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);
static RETRY_READY: AtomicU64 = AtomicU64::new(0);
static DRAIN_ACTIVE: AtomicU64 = AtomicU64::new(0);

struct DrainGuard;

impl DrainGuard {
    fn enter() -> Option<Self> {
        DRAIN_ACTIVE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        DRAIN_ACTIVE.store(0, Ordering::Release);
    }
}

unsafe fn pending(inst: DriverInstance) -> bool {
    inst.exec_shared_va != 0
        && read_volatile((inst.exec_shared_va + SH_FILE_RETIREMENTS) as *const u64) != 0
}

unsafe fn any_pending() -> bool {
    let count = driver_instances().map(Vec::len).unwrap_or(0);
    (0..count).any(|index| instance(index).is_some_and(|inst| pending(inst)))
}

pub(super) fn instance_quiesced(index: usize) -> bool {
    instance(index).is_none_or(|inst| !unsafe { pending(inst) })
}

fn postpone(now: u64) {
    NEXT_RETRY.store(now.saturating_add(RETRY_INTERVAL_100NS), Ordering::Release);
}

pub(super) fn retry_deadline() -> Option<u64> {
    if !unsafe { any_pending() } {
        NEXT_RETRY.store(0, Ordering::Release);
        RETRY_READY.store(0, Ordering::Release);
        return None;
    }
    let next = NEXT_RETRY.load(Ordering::Acquire);
    if next != 0 {
        return Some(next);
    }
    let next = monotonic_time_100ns().saturating_add(RETRY_INTERVAL_100NS);
    match NEXT_RETRY.compare_exchange(0, next, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(next),
        Err(existing) => Some(existing),
    }
}

pub(super) fn retry_wake_due(now: u64) -> u64 {
    if retry_deadline().is_some_and(|deadline| deadline <= now) {
        // Keep a future wake even if this timer fired inside a nested hosted pump.
        postpone(now);
        return u64::from(RETRY_READY.swap(1, Ordering::AcqRel) == 0);
    }
    0
}

unsafe fn drain_instance(index: usize, inst: DriverInstance) -> Result<u64, nt_status::NtStatus> {
    if !inst.ready
        || inst.exec_shared_va == 0
        || inst.fault_ep == 0
        || inst.pml4 == 0
        || inst.reply_cap == 0
        || instance_domain_identity(inst).is_none()
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    dispatch_device_projection_control_for_instance(
        index,
        inst.driver_object,
        FSD_DISPATCH_DRAIN_FILE_RETIREMENTS,
        0,
        0,
        false,
    )
}

/// One physical-instance snapshot per retry; no canonical manager or instance-table borrow
/// survives the control IPC, whose reverse calls can mutate both tables.
pub(super) unsafe fn drain() -> u64 {
    if HOSTED_COMPONENT_PUMP_DEPTH.load(Ordering::Acquire) != 0 {
        return 0;
    }
    let Some(_drain) = DrainGuard::enter() else {
        return 0;
    };
    let now = monotonic_time_100ns();
    let ready = RETRY_READY.swap(0, Ordering::AcqRel) != 0;
    let next = NEXT_RETRY.load(Ordering::Acquire);
    if !ready && next != 0 && now < next {
        return 0;
    }
    postpone(now);
    let count = driver_instances().map(Vec::len).unwrap_or(0);
    let mut freed = 0u64;
    for index in 0..count {
        let Some(inst) = instance(index) else {
            continue;
        };
        if pending(inst) {
            if let Ok(count) = drain_instance(index, inst) {
                freed = freed.saturating_add(count);
            }
        }
    }
    if !any_pending() {
        NEXT_RETRY.store(0, Ordering::Release);
        RETRY_READY.store(0, Ordering::Release);
    }
    freed
}

/// Unload may retry immediately, but cannot bypass an uncertain or leased retirement.
pub(super) unsafe fn preflight_unload(
    index: usize,
    expected: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    if !pending(expected) {
        return Ok(());
    }
    if HOSTED_COMPONENT_PUMP_DEPTH.load(Ordering::Acquire) != 0 {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let _drain = DrainGuard::enter().ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    postpone(monotonic_time_100ns());
    let result = drain_instance(index, expected);
    let current = instance(index).ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    if instance_domain_identity(current) != instance_domain_identity(expected)
        || current.exec_shared_va != expected.exec_shared_va
        || result.is_err()
        || pending(current)
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    Ok(())
}
