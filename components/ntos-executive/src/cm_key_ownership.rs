//! Cleanup ownership for executive CM leases, independent of every NT handle namespace.

use super::*;
use nt_config_client::{
    OpenedSystemHiveKey, SystemHiveKeyCloseReceipt, SystemHiveKeyLease, SystemHiveKeyOpenAttempt,
    SystemHiveKeyOpenAttempts, SystemHiveKeyOpenOperation,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Opening,
    Active,
    Closing,
    RetryOpen,
    RetryClose,
    Closed,
}

struct Row {
    phase: Phase,
    attempt: Option<SystemHiveKeyOpenAttempt>,
    lease: Option<SystemHiveKeyLease>,
    receipt: Option<SystemHiveKeyCloseReceipt>,
}

static mut ATTEMPTS: SystemHiveKeyOpenAttempts = SystemHiveKeyOpenAttempts::new();
static mut ROWS: Vec<Row> = Vec::new();
static PENDING: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static DELAY: AtomicU64 = AtomicU64::new(MIN_DELAY);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static OPEN_REQUESTS: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
static RETRIES: AtomicU64 = AtomicU64::new(0);
const MIN_DELAY: u64 = 10_000_000;
const MAX_DELAY: u64 = 30 * MIN_DELAY;
const INVALID_HANDLE: i32 = 0xc000_0008u32 as i32;
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
    let attempt = (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).reserve(path)?;
    let entry = Row {
        phase: Phase::Opening,
        attempt: Some(attempt),
        lease: None,
        receipt: None,
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

unsafe fn exchange(index: usize, operation: SystemHiveKeyOpenOperation) -> Result<(), i32> {
    let mut ticket = {
        let attempt = row(index)
            .attempt
            .as_mut()
            .expect("CM OPEN owner disappeared");
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).begin_exchange(attempt, operation)?
    };
    let response = config_manager_exchange_system_hive_key_open(&ticket);
    let attempt = row(index)
        .attempt
        .as_mut()
        .expect("inflight CM OPEN owner disappeared");
    (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).complete_exchange(attempt, &mut ticket, response)
}

unsafe fn resolve_open(index: usize) -> Result<(), i32> {
    if row(index)
        .attempt
        .as_ref()
        .unwrap()
        .server_nonce()
        .is_none()
    {
        exchange(index, SystemHiveKeyOpenOperation::Query)?;
    }
    if !row(index).attempt.as_ref().unwrap().has_outcome() {
        exchange(index, SystemHiveKeyOpenOperation::Begin)?;
    }
    if !row(index).attempt.as_ref().unwrap().is_acknowledged() {
        exchange(index, SystemHiveKeyOpenOperation::Acknowledge)?;
    }
    Ok(())
}

unsafe fn retain_failure(index: usize, phase: Phase) {
    row(index).phase = phase;
    FAILURES.fetch_add(1, Ordering::Relaxed);
    if PENDING.fetch_add(1, Ordering::Relaxed) == 0 {
        NEXT.store(
            monotonic_time_100ns().saturating_add(MIN_DELAY),
            Ordering::Relaxed,
        );
    }
}

pub(crate) unsafe fn open(path: &str) -> Result<OpenedSystemHiveKey, i32> {
    let _durable = allocator::enter_durable();
    let generation = LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
    if generation == 0 || CONFIG_CLIENT_PTR.is_null() {
        return Err(CONFIG_STATUS_DEVICE_NOT_READY);
    }
    let index = reserve(path)?;
    OPEN_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let result = (|| {
        resolve_open(index)?;
        let attempt = row(index).attempt.as_mut().unwrap();
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).take_validated(attempt, generation)
    })();
    match result {
        Ok(opened) => {
            let entry = row(index);
            entry.lease = Some(opened.lease);
            (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
                .release(entry.attempt.as_mut().unwrap())
                .expect("transferred CM OPEN retained an unexpected obligation");
            entry.attempt = None;
            entry.phase = Phase::Active;
            Ok(opened)
        }
        Err(status) => {
            // The failed caller can never receive a late publication. Keep both the OPEN
            // acknowledgement and any acquired lease until maintenance has retired them.
            let attempt = row(index).attempt.as_ref().unwrap();
            if !attempt.was_submitted()
                || (attempt.is_acknowledged() && attempt.known_lease().is_none())
            {
                let entry = row(index);
                (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
                    .release(entry.attempt.as_mut().unwrap())
                    .expect("unowned CM OPEN retained an unexpected obligation");
                entry.attempt = None;
                entry.phase = Phase::Closed;
            } else {
                retain_failure(index, Phase::RetryOpen);
            }
            Err(status)
        }
    }
}

unsafe fn release_lease(index: usize) -> Result<(), i32> {
    let lease = row(index).lease.ok_or(INVALID_HANDLE)?;
    if row(index).receipt.is_none() {
        let receipt = config_manager_prepare_system_hive_key_close(lease)?;
        row(index).receipt = Some(receipt);
    }
    config_manager_acknowledge_system_hive_key_close(row(index).receipt.unwrap())?;
    let entry = row(index);
    entry.lease = None;
    entry.receipt = None;
    entry.phase = Phase::Closed;
    Ok(())
}

/// The caller relinquishes its lease even when the first backend attempt fails. This is cleanup
/// after target retirement, not a retryable NT handle close; subsequent work belongs to this journal.
pub(crate) unsafe fn retire(lease: SystemHiveKeyLease) -> Result<(), i32> {
    let _durable = allocator::enter_durable();
    let index = (&*core::ptr::addr_of!(ROWS))
        .iter()
        .position(|entry| {
            entry.phase == Phase::Active
                && entry.lease.is_some_and(|held| {
                    held.token == lease.token && held.opened_generation == lease.opened_generation
                })
        })
        .ok_or(INVALID_HANDLE)?;
    row(index).phase = Phase::Closing;
    let result = release_lease(index);
    if result.is_err() {
        retain_failure(index, Phase::RetryClose);
    }
    result
}

unsafe fn abandon_open(index: usize) -> Result<(), i32> {
    let attempt = row(index).attempt.as_ref().unwrap();
    let needs_outcome = !attempt.has_outcome()
        || (attempt.validation_status() != Some(0) && attempt.known_lease().is_none());
    if needs_outcome {
        if let Err(status) = exchange(index, SystemHiveKeyOpenOperation::Begin) {
            if row(index).attempt.as_ref().unwrap().known_lease().is_none() {
                return Err(status);
            }
        }
    }
    let lease = row(index).attempt.as_ref().unwrap().known_lease();
    if let Some(lease) = lease.filter(|_| !row(index).attempt.as_ref().unwrap().is_lease_closed()) {
        if row(index).receipt.is_none() {
            let receipt = config_manager_prepare_system_hive_key_close(lease)?;
            row(index).receipt = Some(receipt);
        }
        let receipt = row(index).receipt.unwrap();
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
            .record_close_receipt(row(index).attempt.as_mut().unwrap(), receipt)?;
        let acknowledged = config_manager_acknowledge_system_hive_key_close(receipt)?;
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
            .mark_lease_closed(row(index).attempt.as_mut().unwrap(), acknowledged)?;
    }
    if !row(index).attempt.as_ref().unwrap().is_acknowledged() {
        exchange(index, SystemHiveKeyOpenOperation::Acknowledge)?;
    }
    let entry = row(index);
    (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).release(entry.attempt.as_mut().unwrap())?;
    entry.attempt = None;
    entry.receipt = None;
    entry.phase = Phase::Closed;
    Ok(())
}

pub(crate) fn next_deadline() -> Option<u64> {
    (PENDING.load(Ordering::Relaxed) != 0 && READY.load(Ordering::Relaxed) == 0)
        .then(|| NEXT.load(Ordering::Relaxed))
}

/// No CM call is permitted inside a timer drain or nested provider pump.
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
        .map(|step| (start + step) % count)
        .find(|&index| matches!(row(index).phase, Phase::RetryOpen | Phase::RetryClose));
    let Some(index) = selected else { return };
    CURSOR.store(((index + 1) % count) as u64, Ordering::Relaxed);
    let _durable = allocator::enter_durable();
    PENDING.fetch_sub(1, Ordering::Relaxed);
    RETRIES.fetch_add(1, Ordering::Relaxed);
    let opening = row(index).phase == Phase::RetryOpen;
    row(index).phase = if opening {
        Phase::Opening
    } else {
        Phase::Closing
    };
    let result = if opening {
        abandon_open(index)
    } else {
        release_lease(index)
    };
    if result.is_err() {
        retain_failure(
            index,
            if opening {
                Phase::RetryOpen
            } else {
                Phase::RetryClose
            },
        );
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
    NEXT.store(
        monotonic_time_100ns().saturating_add(delay),
        Ordering::Relaxed,
    );
    READY.store(0, Ordering::Relaxed);
}

pub(crate) unsafe fn print_stats() {
    let rows = &*core::ptr::addr_of!(ROWS);
    print_str(b"[cm-key-owners]");
    for (label, value) in [
        (
            &b" active="[..],
            rows.iter().filter(|row| row.phase == Phase::Active).count() as u64,
        ),
        (
            &b" inflight="[..],
            rows.iter()
                .filter(|row| matches!(row.phase, Phase::Opening | Phase::Closing))
                .count() as u64,
        ),
        (&b" pending="[..], PENDING.load(Ordering::Relaxed)),
        (&b" opens="[..], OPEN_REQUESTS.load(Ordering::Relaxed)),
        (&b" failures="[..], FAILURES.load(Ordering::Relaxed)),
        (&b" retries="[..], RETRIES.load(Ordering::Relaxed)),
    ] {
        print_str(label);
        print_u64(value);
    }
    print_str(b"\n");
}
