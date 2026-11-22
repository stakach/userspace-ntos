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

/// The one retirement control whose provider pump had not returned when its turn ended
/// (#420). Its row keeps it until a later drain collects the true result; no retirement is
/// entered meanwhile, and its instance is not quiesced.
struct Running {
    index: usize,
    control: PendingProjectionControl,
}

static mut RUNNING: Option<Running> = None;

fn running() -> &'static mut Option<Running> {
    unsafe { &mut *core::ptr::addr_of_mut!(RUNNING) }
}

/// One retirement control's outcome for its drain.
enum Drained {
    Done(Result<u64, nt_status::NtStatus>),
    /// Kept in [`RUNNING`].
    Running,
}

impl Drained {
    fn of(index: usize, control: ProjectionControl) -> Self {
        match control {
            ProjectionControl::Done(result) => Self::Done(result),
            ProjectionControl::Pending(control) => {
                *running() = Some(Running { index, control });
                Self::Running
            }
        }
    }
}

/// Continue the running control first. `None` is a turn that may not enter a provider.
unsafe fn resume_running() -> Option<Drained> {
    component_scheduler::service_continuation::RootRow::current()?;
    let Some(Running { index, control }) = running().take() else {
        return Some(Drained::Done(Ok(0)));
    };
    Some(Drained::of(index, control.resume()))
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
    running().as_ref().is_none_or(|row| row.index != index)
        && instance(index).is_none_or(|inst| !unsafe { pending(inst) })
}

fn postpone(now: u64) {
    NEXT_RETRY.store(now.saturating_add(RETRY_INTERVAL_100NS), Ordering::Release);
}

pub(super) fn retry_deadline(now: u64) -> Option<u64> {
    if running().is_none() && !unsafe { any_pending() } {
        NEXT_RETRY.store(0, Ordering::Release);
        RETRY_READY.store(0, Ordering::Release);
        return None;
    }
    let next = NEXT_RETRY.load(Ordering::Acquire);
    if next != 0 {
        return Some(next);
    }
    let next = now.saturating_add(RETRY_INTERVAL_100NS);
    match NEXT_RETRY.compare_exchange(0, next, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(next),
        Err(existing) => Some(existing),
    }
}

pub(super) fn retry_wake_due(now: u64) -> u64 {
    if retry_deadline(now).is_some_and(|deadline| deadline <= now) {
        // Keep a future wake even if this timer fired inside a nested hosted pump.
        postpone(now);
        return u64::from(RETRY_READY.swap(1, Ordering::AcqRel) == 0);
    }
    0
}

unsafe fn drain_instance(
    row: &component_scheduler::service_continuation::RootRow,
    index: usize,
    inst: DriverInstance,
) -> Drained {
    if !inst.ready
        || inst.exec_shared_va == 0
        || inst.fault_ep == 0
        || inst.pml4 == 0
        || inst.reply_cap == 0
        || instance_domain_identity(inst).is_none()
    {
        return Drained::Done(Err(nt_status::NtStatus::DEVICE_BUSY));
    }
    // Deferred retirement runs as executive work; it does not impersonate the old File caller.
    let caller = crate::initial_system_driver_caller();
    Drained::of(index, dispatch_device_projection_control_at_root(
        row,
        index,
        inst.driver_object,
        FSD_DISPATCH_DRAIN_FILE_RETIREMENTS,
        0,
        0,
        caller,
    ))
}

/// One physical-instance snapshot per retry; no canonical manager or instance-table borrow
/// survives the control IPC, whose reverse calls can mutate both tables.
pub(super) unsafe fn drain() -> u64 {
    if hosted_component_dispatch_active() {
        return 0;
    }
    let Some(_drain) = DrainGuard::enter() else {
        return 0;
    };
    let mut freed = match resume_running() {
        None | Some(Drained::Running) => return 0,
        Some(Drained::Done(result)) => result.unwrap_or(0),
    };
    let now = monotonic_time_100ns();
    let ready = RETRY_READY.swap(0, Ordering::AcqRel) != 0;
    let next = NEXT_RETRY.load(Ordering::Acquire);
    if !ready && next != 0 && now < next {
        return freed;
    }
    postpone(now);
    let count = driver_instances().map(Vec::len).unwrap_or(0);
    for index in 0..count {
        let Some(inst) = instance(index) else {
            continue;
        };
        if !pending(inst) { continue; }
        // A root row enters a provider only outside every lane, scheduler scope and step.
        let Some(row) = component_scheduler::service_continuation::RootRow::current() else {
            break;
        };
        match drain_instance(&row, index, inst) {
            Drained::Done(Ok(count)) => freed = freed.saturating_add(count),
            Drained::Done(Err(_)) => {}
            Drained::Running => return freed,
        }
    }
    if !any_pending() {
        NEXT_RETRY.store(0, Ordering::Release);
        RETRY_READY.store(0, Ordering::Release);
    }
    freed
}

/// Unload may retry immediately, but cannot bypass an uncertain, leased or running retirement.
pub(super) unsafe fn preflight_unload(
    index: usize,
    expected: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    if running().is_none() && !pending(expected) {
        return Ok(());
    }
    if hosted_component_dispatch_active() {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let _drain = DrainGuard::enter().ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let result = match resume_running() {
        None | Some(Drained::Running) => return Err(nt_status::NtStatus::DEVICE_BUSY),
        Some(Drained::Done(_)) if !pending(expected) => return Ok(()),
        Some(Drained::Done(_)) => {
            let row = component_scheduler::service_continuation::RootRow::current()
                .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
            postpone(monotonic_time_100ns());
            match drain_instance(&row, index, expected) {
                Drained::Done(result) => result,
                Drained::Running => return Err(nt_status::NtStatus::DEVICE_BUSY),
            }
        }
    };
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
