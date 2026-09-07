//! Retained lifecycle for the existing driver-registry broker handles.

use super::*;
use nt_config_client::{
    BrokerKeyOwner, BrokerKeyOwnerError, BrokerKeyOwners, BrokerKeyPhase, SystemHiveKeyOpenAttempt,
    SystemHiveKeyOpenAttempts, SystemHiveKeyOpenOperation,
};

#[derive(Clone, Copy)]
enum Authority {
    Generic,
    System {
        lease: nt_config_client::SystemHiveKeyLease,
    },
}

struct Row {
    handle: u64,
    owner: BrokerKeyOwner<Authority, Option<nt_config_client::SystemHiveKeyCloseReceipt>>,
    path: HostedAscii<HOSTED_REGISTRY_PATH_MAX>,
    published: bool,
    open: Option<SystemHiveKeyOpenAttempt>,
    pending: bool,
}

static mut OWNERS: BrokerKeyOwners = BrokerKeyOwners::new();
static mut ROWS: Vec<Row> = Vec::new();
static mut OPEN_ATTEMPTS: SystemHiveKeyOpenAttempts = SystemHiveKeyOpenAttempts::new();
static OPEN_REQUESTS: AtomicU64 = AtomicU64::new(0);
static OPEN_FAILURES: AtomicU64 = AtomicU64::new(0);
static PENDING: AtomicU64 = AtomicU64::new(0);
static CLOSE_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static CLOSE_FAILURES: AtomicU64 = AtomicU64::new(0);
static RETRY_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static RETRY_NEXT: AtomicU64 = AtomicU64::new(0);
static RETRY_DELAY: AtomicU64 = AtomicU64::new(RETRY_MIN);
static RETRY_CURSOR: AtomicU64 = AtomicU64::new(0);
static RETRY_READY: AtomicU64 = AtomicU64::new(0);
const RETRY_MIN: u64 = 10_000_000;
const RETRY_MAX: u64 = 30 * RETRY_MIN;

pub(crate) fn driver_registry_close_retry_deadline() -> Option<u64> {
    (PENDING.load(Ordering::Relaxed) != 0 && RETRY_READY.load(Ordering::Relaxed) == 0)
        .then(|| RETRY_NEXT.load(Ordering::Relaxed))
}

/// Timer drain only latches work; CM IPC runs later at the outer executive boundary.
pub(crate) fn driver_registry_close_retry_wake_due(now_100ns: u64) -> u64 {
    if driver_registry_close_retry_deadline().is_some_and(|deadline| now_100ns >= deadline) {
        return u64::from(RETRY_READY.swap(1, Ordering::Relaxed) == 0);
    }
    0
}

fn owner_error(error: BrokerKeyOwnerError) -> i32 {
    match error {
        BrokerKeyOwnerError::Exhausted => STATUS_INSUFFICIENT_RESOURCES,
        _ => STATUS_INVALID_HANDLE,
    }
}

unsafe fn row_mut(handle: u64) -> Result<&'static mut Row, i32> {
    (&mut *core::ptr::addr_of_mut!(ROWS))
        .iter_mut()
        .find(|row| {
            row.handle == handle
                && (row.owner.phase() != BrokerKeyPhase::Closed || row.open.is_some())
        })
        .ok_or(STATUS_INVALID_HANDLE)
}

unsafe fn reserve() -> Result<u64, i32> {
    let _durable = crate::allocator::enter_durable();
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let vacant = rows
        .iter()
        .position(|row| row.owner.phase() == BrokerKeyPhase::Closed && row.open.is_none());
    if vacant.is_none() {
        rows.try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    }
    let token = DRIVER_REGISTRY_HANDLE_NEXT_TOKEN
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            (next <= DRIVER_REGISTRY_HANDLE_TOKEN_MASK).then_some(next + 1)
        })
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let handle = DRIVER_REGISTRY_HANDLE_BASE | token;
    let owner = (&mut *core::ptr::addr_of_mut!(OWNERS))
        .reserve_with_metadata(None)
        .map_err(owner_error)?;
    let row = Row {
        handle,
        owner,
        path: HostedAscii::empty(),
        published: false,
        open: None,
        pending: false,
    };
    if let Some(index) = vacant {
        rows[index] = row;
    } else {
        rows.push(row);
    }
    Ok(handle)
}

unsafe fn cancel_empty(handle: u64) {
    let row = row_mut(handle).expect("reserved registry row disappeared");
    (&*core::ptr::addr_of!(OWNERS))
        .cancel_reservation(&mut row.owner)
        .expect("empty registry reservation changed while opening");
}

unsafe fn set_pending(handle: u64, pending: bool) {
    let row = row_mut(handle).expect("retained registry row disappeared");
    if row.pending == pending {
        return;
    }
    row.pending = pending;
    if pending {
        if PENDING.fetch_add(1, Ordering::Relaxed) == 0 {
            RETRY_NEXT.store(
                crate::monotonic_time_100ns().saturating_add(RETRY_MIN),
                Ordering::Relaxed,
            );
        }
    } else {
        PENDING.fetch_sub(1, Ordering::Relaxed);
    }
}

unsafe fn open_exchange(handle: u64, operation: SystemHiveKeyOpenOperation) -> Result<(), i32> {
    let mut exchange = {
        let attempt = row_mut(handle)?
            .open
            .as_mut()
            .expect("registry OPEN owner disappeared");
        (&*core::ptr::addr_of!(OPEN_ATTEMPTS)).begin_exchange(attempt, operation)?
    };
    let response = crate::config_manager_exchange_system_hive_key_open(&exchange);
    let attempt = row_mut(handle)?
        .open
        .as_mut()
        .expect("inflight registry OPEN owner disappeared");
    (&*core::ptr::addr_of!(OPEN_ATTEMPTS)).complete_exchange(attempt, &mut exchange, response)
}

unsafe fn resolve_open(handle: u64) -> Result<(), i32> {
    if row_mut(handle)?
        .open
        .as_ref()
        .unwrap()
        .server_nonce()
        .is_none()
    {
        open_exchange(handle, SystemHiveKeyOpenOperation::Query)?;
    }
    let attempt = row_mut(handle)?.open.as_ref().unwrap();
    if !attempt.has_outcome() || attempt.validation_status() != Some(STATUS_SUCCESS) {
        open_exchange(handle, SystemHiveKeyOpenOperation::Begin)?;
    }
    if !row_mut(handle)?.open.as_ref().unwrap().is_acknowledged() {
        open_exchange(handle, SystemHiveKeyOpenOperation::Acknowledge)?;
    }
    Ok(())
}

unsafe fn release_open(handle: u64) -> Result<(), i32> {
    let entry = row_mut(handle)?;
    (&mut *core::ptr::addr_of_mut!(OPEN_ATTEMPTS)).release(
        entry
            .open
            .as_mut()
            .expect("registry OPEN release has no owner"),
    )?;
    entry.open = None;
    Ok(())
}

unsafe fn acquire_system_key(
    handle: u64,
    path: &str,
) -> Result<nt_config_client::OpenedSystemHiveKey, i32> {
    let generation = crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
    if generation == 0 {
        cancel_empty(handle);
        return Err(STATUS_DEVICE_NOT_READY);
    }
    let attempt = match (&mut *core::ptr::addr_of_mut!(OPEN_ATTEMPTS)).reserve(path) {
        Ok(attempt) => attempt,
        Err(status) => {
            cancel_empty(handle);
            return Err(status);
        }
    };
    row_mut(handle)?.open = Some(attempt);
    OPEN_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let outcome = (|| {
        resolve_open(handle)?;
        let attempt = row_mut(handle)?.open.as_mut().unwrap();
        (&*core::ptr::addr_of!(OPEN_ATTEMPTS)).take_validated(attempt, generation)
    })();
    match outcome {
        Ok(opened) => {
            attach(
                handle,
                Authority::System {
                    lease: opened.lease,
                },
            );
            release_open(handle)
                .expect("transferred registry OPEN retained an unexpected obligation");
            Ok(opened)
        }
        Err(status) => {
            OPEN_FAILURES.fetch_add(1, Ordering::Relaxed);
            let attempt = row_mut(handle)?.open.as_ref().unwrap();
            if !attempt.was_submitted()
                || (attempt.is_acknowledged() && attempt.known_lease().is_none())
            {
                release_open(handle)
                    .expect("completed failed registry OPEN retained an obligation");
                cancel_empty(handle);
            } else {
                // The caller receives failure. This row can subsequently only be cleaned up.
                set_pending(handle, true);
            }
            Err(status)
        }
    }
}

unsafe fn attach(handle: u64, authority: Authority) {
    let row = row_mut(handle).expect("reserved registry row disappeared");
    if (&*core::ptr::addr_of!(OWNERS))
        .attach(&mut row.owner, authority)
        .is_err()
    {
        panic!("acquired registry authority could not enter its reserved owner");
    }
}

unsafe fn publish(handle: u64) -> Result<(), i32> {
    let row = row_mut(handle)?;
    let owners = &*core::ptr::addr_of!(OWNERS);
    let mut ticket = owners
        .begin_publication(&mut row.owner)
        .map_err(owner_error)?;
    if let Err(error) = owners.publish(&mut row.owner, &mut ticket) {
        owners
            .cancel_publication(&mut row.owner, &mut ticket)
            .expect("failed registry publication lost its exact ticket");
        return Err(owner_error(error));
    }
    row.published = true;
    Ok(())
}

pub(super) unsafe fn driver_registry_handle_slot(handle: u64) -> Option<DriverRegistryHandleSlot> {
    let row = row_mut(handle).ok()?;
    let authority = (&*core::ptr::addr_of!(OWNERS))
        .active_target(&row.owner)
        .ok()?;
    let target = match *authority {
        Authority::Generic => DriverRegistryHandleTarget::Generic { path: row.path },
        Authority::System { lease, .. } => DriverRegistryHandleTarget::System {
            lease,
            physical_path: row.path,
        },
    };
    Some(DriverRegistryHandleSlot { handle, target })
}

/// Reserve native and wire-request ownership before CM may acquire a lease. No failed caller can
/// acquire a late handle: uncertain requests are retained for acknowledgement and cleanup only.
pub(super) unsafe fn open_driver_registry_handle(
    path: HostedAscii<HOSTED_REGISTRY_PATH_MAX>,
    publish_handle: bool,
) -> Result<DriverRegistryHandleSlot, i32> {
    let _durable = crate::allocator::enter_durable();
    if path.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let handle = reserve()?;
    let target = if hosted_registry_path_is_system(path) {
        let opened = acquire_system_key(handle, path.as_str())?;
        let mut physical_path = HostedAscii::empty();
        if !physical_path.push_str(&opened.physical_path) {
            // A failed cleanup remains in this unpublished row for bounded maintenance.
            let _ = retire_driver_registry_handle(handle);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        row_mut(handle)?.path = physical_path;
        DriverRegistryHandleTarget::System {
            lease: opened.lease,
            physical_path,
        }
    } else {
        if !crate::config_manager_open_key(path.as_str()) {
            cancel_empty(handle);
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        attach(handle, Authority::Generic);
        row_mut(handle)?.path = path;
        DriverRegistryHandleTarget::Generic { path }
    };
    if publish_handle {
        if let Err(status) = publish(handle) {
            let _ = retire_driver_registry_handle(handle);
            return Err(status);
        }
    }
    Ok(DriverRegistryHandleSlot { handle, target })
}

pub(super) unsafe fn close_driver_registry_handle(handle: u64) -> Result<(), i32> {
    if !row_mut(handle)?.published {
        return Err(STATUS_INVALID_HANDLE);
    }
    retire_driver_registry_handle(handle)
}

unsafe fn abandon_open(handle: u64) -> Result<(), i32> {
    let attempt = row_mut(handle)?.open.as_ref().unwrap();
    if attempt.known_lease().is_none() || attempt.validation_status() == Some(STATUS_SUCCESS) {
        resolve_open(handle)?;
    }
    let attempt = row_mut(handle)?.open.as_ref().unwrap();
    if let Some(lease) = attempt.known_lease().filter(|_| !attempt.is_lease_closed()) {
        if row_mut(handle)?.owner.phase() == BrokerKeyPhase::Reserved {
            attach(handle, Authority::System { lease });
        }
        close_bound_registry_owner(handle)?;
    }
    if !row_mut(handle)?.open.as_ref().unwrap().is_acknowledged() {
        open_exchange(handle, SystemHiveKeyOpenOperation::Acknowledge)?;
    }
    let empty_owner = row_mut(handle)?.owner.phase() == BrokerKeyPhase::Reserved;
    release_open(handle)?;
    if empty_owner {
        cancel_empty(handle);
    }
    Ok(())
}

pub(super) unsafe fn retire_driver_registry_handle(handle: u64) -> Result<(), i32> {
    let _durable = crate::allocator::enter_durable();
    let row = row_mut(handle)?;
    if row.owner.phase() == BrokerKeyPhase::ClosingInflight
        || row
            .open
            .as_ref()
            .is_some_and(|attempt| attempt.is_inflight())
    {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    set_pending(handle, false);
    let result = if row_mut(handle)?.open.is_some() {
        abandon_open(handle)
    } else {
        close_bound_registry_owner(handle)
    };
    if result.is_err() {
        set_pending(handle, true);
    }
    result
}

/// No row/table borrow crosses either CM call. A prepared receipt is durable before ACK IPC,
/// and only a validated ACK permits the exact row to become reusable.
unsafe fn close_bound_registry_owner(handle: u64) -> Result<(), i32> {
    let (mut ticket, authority, mut receipt) = {
        let row = row_mut(handle)?;
        let owners = &*core::ptr::addr_of!(OWNERS);
        let ticket = owners.begin_close(&mut row.owner).map_err(owner_error)?;
        let authority = *owners
            .close_target(&row.owner, &ticket)
            .expect("new close ticket rejected");
        let receipt = *owners
            .close_metadata(&row.owner, &ticket)
            .expect("new close metadata ticket rejected");
        (ticket, authority, receipt)
    };
    CLOSE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    abort_hosted_system_registry_sets_for_handle(handle);
    let outcome = (|| {
        if let Authority::System { lease } = authority {
            if receipt.is_none() {
                let prepared = crate::config_manager_prepare_system_hive_key_close(lease)?;
                let row =
                    row_mut(handle).expect("prepared registry receipt lost its retained owner");
                *(&*core::ptr::addr_of!(OWNERS))
                    .close_metadata_mut(&mut row.owner, &ticket)
                    .expect("prepared registry receipt lost its exact close ticket") =
                    Some(prepared);
                receipt = Some(prepared);
            }
            let receipt = receipt.expect("SYSTEM close has no prepared receipt");
            if let Some(attempt) = row_mut(handle)?.open.as_mut() {
                (&*core::ptr::addr_of!(OPEN_ATTEMPTS)).record_close_receipt(attempt, receipt)?;
            }
            let acknowledged = crate::config_manager_acknowledge_system_hive_key_close(receipt)?;
            if let Some(attempt) = row_mut(handle)?.open.as_mut() {
                (&*core::ptr::addr_of!(OPEN_ATTEMPTS)).mark_lease_closed(attempt, acknowledged)?;
            }
        }
        Ok(())
    })();
    let row = row_mut(handle).expect("inflight registry owner disappeared");
    let owners = &*core::ptr::addr_of!(OWNERS);
    match outcome {
        Ok(()) => {
            owners
                .finish_close(&mut row.owner, &mut ticket)
                .expect("acknowledged registry close lost ownership");
            row.path = HostedAscii::empty();
            row.published = false;
            Ok(())
        }
        Err(status) => {
            owners
                .close_failed(&mut row.owner, &mut ticket)
                .expect("failed registry close lost ownership");
            CLOSE_FAILURES.fetch_add(1, Ordering::Relaxed);
            Err(status)
        }
    }
}

/// At most one CM close attempt per eligible event, with fair rotation and bounded backoff.
pub(crate) unsafe fn retry_driver_registry_closes(now_100ns: u64) {
    let _durable = crate::allocator::enter_durable();
    if PENDING.load(Ordering::Relaxed) == 0 {
        RETRY_NEXT.store(0, Ordering::Relaxed);
        RETRY_DELAY.store(RETRY_MIN, Ordering::Relaxed);
        RETRY_READY.store(0, Ordering::Relaxed);
        return;
    }
    if RETRY_READY.load(Ordering::Relaxed) == 0 && now_100ns < RETRY_NEXT.load(Ordering::Relaxed) {
        return;
    }
    let selected = {
        let rows = &*core::ptr::addr_of!(ROWS);
        if rows.is_empty() {
            return;
        }
        let start = RETRY_CURSOR.load(Ordering::Relaxed) as usize % rows.len();
        (0..rows.len())
            .map(|offset| (start + offset) % rows.len())
            .find(|index| rows[*index].pending)
            .map(|index| (index, rows[index].handle))
    };
    let Some((index, handle)) = selected else {
        return;
    };
    let delay = RETRY_DELAY.load(Ordering::Relaxed);
    RETRY_READY.store(0, Ordering::Relaxed);
    RETRY_NEXT.store(now_100ns.saturating_add(delay), Ordering::Relaxed);
    RETRY_CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    RETRY_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let next_delay = if retire_driver_registry_handle(handle).is_ok() {
        RETRY_MIN
    } else {
        core::cmp::min(delay.saturating_mul(2), RETRY_MAX)
    };
    RETRY_DELAY.store(next_delay, Ordering::Relaxed);
    // Time spent waiting for CM must not consume the cooldown or leave an overdue timer latched.
    RETRY_READY.store(0, Ordering::Relaxed);
    RETRY_NEXT.store(
        crate::monotonic_time_100ns().saturating_add(next_delay),
        Ordering::Relaxed,
    );
}

#[derive(Default)]
pub(crate) struct RegistryOwnerStats {
    pub active: usize,
    pub unpublished: usize,
    pub inflight: usize,
    pub pending: u64,
    pub close_attempts: u64,
    pub close_failures: u64,
    pub retry_attempts: u64,
    pub open_pending: usize,
    pub open_inflight: usize,
    pub open_requests: u64,
    pub open_failures: u64,
}

pub(crate) unsafe fn stats() -> RegistryOwnerStats {
    let mut stats = RegistryOwnerStats {
        pending: PENDING.load(Ordering::Relaxed),
        close_attempts: CLOSE_ATTEMPTS.load(Ordering::Relaxed),
        close_failures: CLOSE_FAILURES.load(Ordering::Relaxed),
        retry_attempts: RETRY_ATTEMPTS.load(Ordering::Relaxed),
        open_requests: OPEN_REQUESTS.load(Ordering::Relaxed),
        open_failures: OPEN_FAILURES.load(Ordering::Relaxed),
        ..RegistryOwnerStats::default()
    };
    for row in &*core::ptr::addr_of!(ROWS) {
        if let Some(attempt) = &row.open {
            stats.open_pending += usize::from(row.pending);
            stats.open_inflight += usize::from(attempt.is_inflight());
        }
        match row.owner.phase() {
            BrokerKeyPhase::Active => stats.active += 1,
            BrokerKeyPhase::Reserved | BrokerKeyPhase::BoundUnpublished => stats.unpublished += 1,
            BrokerKeyPhase::ClosingInflight => stats.inflight += 1,
            _ => {}
        }
    }
    stats
}
