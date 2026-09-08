//! Retained CM snapshot requests, independent of key leases and NT handle namespaces.

use super::*;
use nt_config_client::{CmSnapshotAttempt, CmSnapshotAttempts, CmSnapshotOperation};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reading,
    RetryCleanup,
    Cleaning,
    Closed,
}

struct Row {
    phase: Phase,
    attempt: Option<CmSnapshotAttempt>,
}

static mut ATTEMPTS: CmSnapshotAttempts = CmSnapshotAttempts::new();
static mut ROWS: Vec<Row> = Vec::new();
static PENDING: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static DELAY: AtomicU64 = AtomicU64::new(MIN_DELAY);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static COMPLETED: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
static CLEANUP_FAILURES: AtomicU64 = AtomicU64::new(0);
static RETRIES: AtomicU64 = AtomicU64::new(0);
const MIN_DELAY: u64 = 10_000_000;
const MAX_DELAY: u64 = 30 * MIN_DELAY;
const NO_MEMORY: i32 = 0xc000_009au32 as i32;

unsafe fn row(index: usize) -> &'static mut Row {
    &mut (&mut *core::ptr::addr_of_mut!(ROWS))[index]
}

unsafe fn reserve(path: &str) -> Result<usize, i32> {
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let vacant = rows.iter().position(|row| row.phase == Phase::Closed);
    if vacant.is_none() {
        rows.try_reserve(1).map_err(|_| NO_MEMORY)?;
    }
    let attempt = (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).reserve_active_driver_service(path)?;
    let entry = Row {
        phase: Phase::Reading,
        attempt: Some(attempt),
    };
    if let Some(index) = vacant {
        rows[index] = entry;
        Ok(index)
    } else {
        let index = rows.len();
        rows.push(entry);
        Ok(index)
    }
}

unsafe fn exchange(index: usize, operation: CmSnapshotOperation) -> Result<(), i32> {
    let mut ticket = {
        let attempt = row(index)
            .attempt
            .as_mut()
            .expect("CM snapshot owner disappeared");
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).begin_exchange(attempt, operation)?
    };
    let response = config_manager_exchange_retained_snapshot(&ticket);
    let attempt = row(index)
        .attempt
        .as_mut()
        .expect("inflight CM snapshot owner disappeared");
    (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).complete_exchange(attempt, &mut ticket, response)
}

unsafe fn release(index: usize) -> Result<(), i32> {
    let entry = row(index);
    (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).release(
        entry
            .attempt
            .as_mut()
            .expect("CM snapshot release lost owner"),
    )?;
    entry.attempt = None;
    entry.phase = Phase::Closed;
    Ok(())
}

unsafe fn retain_cleanup(index: usize) {
    row(index).phase = Phase::RetryCleanup;
    if PENDING.fetch_add(1, Ordering::Relaxed) == 0 {
        NEXT.store(
            monotonic_time_100ns().saturating_add(MIN_DELAY),
            Ordering::Relaxed,
        );
    }
}

pub(crate) unsafe fn query_active_driver_service(
    path: &str,
) -> Result<nt_config_client::ActiveDriverServiceBinding, i32> {
    let _durable = allocator::enter_durable();
    let generation = LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
    if generation == 0 || CONFIG_CLIENT_PTR.is_null() {
        return Err(CONFIG_STATUS_DEVICE_NOT_READY);
    }
    let index = reserve(path)?;
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    let outcome = (|| {
        if row(index)
            .attempt
            .as_ref()
            .unwrap()
            .server_nonce()
            .is_none()
        {
            exchange(index, CmSnapshotOperation::Query)?;
        }
        exchange(index, CmSnapshotOperation::Begin)?;
        if let Some(status) = row(index).attempt.as_ref().unwrap().outcome_status() {
            if status != 0 {
                return Err(status);
            }
        }
        while !row(index).attempt.as_ref().unwrap().is_complete() {
            exchange(index, CmSnapshotOperation::Pull)?;
        }
        exchange(index, CmSnapshotOperation::Acknowledge)?;
        if LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire) != generation {
            return Err(CONFIG_STATUS_DEVICE_NOT_READY);
        }
        // Decode enforces the same captured generation. No IPC occurs before publication.
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
            .take_active_driver_service(row(index).attempt.as_mut().unwrap(), generation)
    })();
    match outcome {
        Ok(resolved) => {
            release(index).expect("acknowledged CM snapshot retained an obligation");
            COMPLETED.fetch_add(1, Ordering::Relaxed);
            Ok(resolved)
        }
        Err(status) => {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            let negative_outcome = {
                let attempt = row(index).attempt.as_mut().unwrap();
                let negative = attempt.was_submitted()
                    && !attempt.is_acknowledged()
                    && attempt.outcome_status().is_some_and(|status| status != 0);
                (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
                    .abandon(attempt)
                    .expect("idle CM snapshot could not be abandoned");
                negative
            };
            if negative_outcome {
                // Ordinary missing-service responses should not occupy a retry slot. The
                // original query failure remains primary if acknowledgement must be retried.
                let _ = exchange(index, CmSnapshotOperation::Acknowledge);
            }
            let attempt = row(index).attempt.as_ref().unwrap();
            if !attempt.was_submitted() || attempt.is_acknowledged() {
                release(index).expect("unowned CM snapshot retained an obligation");
            } else {
                // No failed caller can receive a late result. Only request retirement remains.
                retain_cleanup(index);
            }
            Err(status)
        }
    }
}

unsafe fn cleanup(index: usize) -> Result<(), i32> {
    if !row(index).attempt.as_ref().unwrap().is_acknowledged() {
        exchange(index, CmSnapshotOperation::Acknowledge)?;
    }
    release(index)
}

pub(crate) fn next_deadline() -> Option<u64> {
    (PENDING.load(Ordering::Relaxed) != 0 && READY.load(Ordering::Relaxed) == 0)
        .then(|| NEXT.load(Ordering::Relaxed))
}

/// Timer drain only latches work. No CM IPC may run here or in a nested provider pump.
pub(crate) fn wake_due(now: u64) -> u64 {
    if next_deadline().is_some_and(|deadline| now >= deadline) {
        return u64::from(READY.swap(1, Ordering::Relaxed) == 0);
    }
    0
}

pub(crate) unsafe fn retry_cleanup(now: u64) {
    if PENDING.load(Ordering::Relaxed) == 0 {
        NEXT.store(0, Ordering::Relaxed);
        READY.store(0, Ordering::Relaxed);
        DELAY.store(MIN_DELAY, Ordering::Relaxed);
        return;
    }
    if READY.swap(0, Ordering::Relaxed) == 0 && now < NEXT.load(Ordering::Relaxed) {
        return;
    }
    let count = (&*core::ptr::addr_of!(ROWS)).len();
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let selected = (0..count)
        .map(|offset| (start + offset) % count)
        .find(|&index| row(index).phase == Phase::RetryCleanup);
    let Some(index) = selected else { return };
    let _durable = allocator::enter_durable();
    CURSOR.store(((index + 1) % count) as u64, Ordering::Relaxed);
    row(index).phase = Phase::Cleaning;
    PENDING.fetch_sub(1, Ordering::Relaxed);
    RETRIES.fetch_add(1, Ordering::Relaxed);
    let result = cleanup(index);
    if result.is_err() {
        CLEANUP_FAILURES.fetch_add(1, Ordering::Relaxed);
        retain_cleanup(index);
    }
    let delay = if result.is_ok() {
        MIN_DELAY
    } else {
        DELAY
            .load(Ordering::Relaxed)
            .saturating_mul(2)
            .min(MAX_DELAY)
    };
    DELAY.store(delay, Ordering::Relaxed);
    // Backend wait time must not consume the retry cooldown or leave an overdue timer latched.
    NEXT.store(
        monotonic_time_100ns().saturating_add(delay),
        Ordering::Relaxed,
    );
    READY.store(0, Ordering::Relaxed);
}

pub(crate) unsafe fn print_stats() {
    let rows = &*core::ptr::addr_of!(ROWS);
    print_str(b"[cm-snapshot-owners]");
    for (label, value) in [
        (
            &b" inflight="[..],
            rows.iter()
                .filter(|row| matches!(row.phase, Phase::Reading | Phase::Cleaning))
                .count() as u64,
        ),
        (&b" pending="[..], PENDING.load(Ordering::Relaxed)),
        (&b" requests="[..], REQUESTS.load(Ordering::Relaxed)),
        (&b" completed="[..], COMPLETED.load(Ordering::Relaxed)),
        (&b" failures="[..], FAILURES.load(Ordering::Relaxed)),
        (
            &b" cleanup-failures="[..],
            CLEANUP_FAILURES.load(Ordering::Relaxed),
        ),
        (&b" retries="[..], RETRIES.load(Ordering::Relaxed)),
    ] {
        print_str(label);
        print_u64(value);
    }
    print_str(b"\n");
}
