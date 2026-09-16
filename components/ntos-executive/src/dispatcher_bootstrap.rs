//! Canonical dispatcher storage created before providers and moved once into the live handler.

use super::*;

pub(crate) struct DispatcherBootstrapSeed {
    pub obj_ns: Vec<ObjEntry>,
    pub anon_event_seq: u32,
    pub dispatcher: nt_user_host::dispatcher_state::DispatcherState,
}

enum BootstrapPhase {
    Uninitialized,
    Owned(DispatcherBootstrapSeed),
    Transferred,
}

static mut BOOTSTRAP: BootstrapPhase = BootstrapPhase::Uninitialized;
static mut HOSTED_TIMER_PROGRESS: nt_time::DeferredTimerProgress =
    nt_time::DeferredTimerProgress::new();

unsafe fn pending_timer_snapshot() -> Option<u64> {
    if !matches!(&*core::ptr::addr_of!(BOOTSTRAP), BootstrapPhase::Owned(_)) {
        return None;
    }
    let pending = DELAY_TIMER_TICKS_PENDING.load(Ordering::Relaxed);
    (&*core::ptr::addr_of!(HOSTED_TIMER_PROGRESS))
        .needs_scan(pending)
        .then_some(pending)
}

/// Eligibility only: observing retained ticks neither consumes them nor authorizes rearming.
pub(crate) unsafe fn timer_work_pending() -> bool {
    !TIMER_DELIVERY_GATE.is_active() && pending_timer_snapshot().is_some()
}

/// Called from the retained component scheduler, never the IRQ-lane ACK hook. Driver timer
/// publication can perform IPC, so no bootstrap store reference may cross this call.
pub(crate) unsafe fn service_hosted_timer_work() -> u64 {
    let Some(_delivery) = TIMER_DELIVERY_GATE.try_enter() else {
        return 0;
    };
    let Some(pending) = pending_timer_snapshot() else {
        return 0;
    };
    let work = timer_hosted_driver_wake_due(nt_time_snapshot());
    (&mut *core::ptr::addr_of_mut!(HOSTED_TIMER_PROGRESS)).record_scan(pending);
    work
}

/// Scan only while this phase owns the stores. The pending notification still belongs to the
/// shared timer owner: do not consume it, reprogram the PIT or enter a provider here.
pub(crate) unsafe fn scan_timer_delivery(
    now: nt_delay_execution::TimeSnapshot,
) -> Result<(), nt_user_host::provider_wait_selection::ProviderWaitSelectionError<u32>> {
    let Some(_delivery) = TIMER_DELIVERY_GATE.try_enter() else {
        // The owner retains the pending notification; nested ACK/watchdog handling still runs.
        return Ok(());
    };
    let _durable = allocator::enter_durable();
    {
        let BootstrapPhase::Owned(seed) = &mut *core::ptr::addr_of_mut!(BOOTSTRAP) else {
            return Ok(());
        };
        let mut objects = nt_user_host::provider_dispatcher_backend::ProviderDispatcherObjects {
            events: &mut seed.dispatcher.events,
            event_objects: &mut seed.dispatcher.event_objects,
            timers: seed.dispatcher.provider_timers.as_mut(),
            backing: crate::provider_dispatcher_backend::NativeEventBacking(&mut seed.obj_ns),
            access: None,
        };
        service_sec_image::provider_wait_scan_timed(&mut objects, now)?;
    }
    timer_retry_wake_due(now.monotonic_100ns);
    Ok(())
}

pub(crate) unsafe fn initialize() -> Result<(), u32> {
    if !matches!(
        &*core::ptr::addr_of!(BOOTSTRAP),
        BootstrapPhase::Uninitialized
    ) {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let _durable = allocator::enter_durable();
    service_sec_image::initialize_service_delay_queue_work()?;
    let seed = DispatcherBootstrapSeed {
        obj_ns: exec_handler::build_initial_object_namespace(),
        anon_event_seq: 0,
        dispatcher: nt_user_host::dispatcher_state::DispatcherState::new(192, 192),
    };
    core::ptr::addr_of_mut!(BOOTSTRAP).write(BootstrapPhase::Owned(seed));
    Ok(())
}

pub(crate) unsafe fn take() -> DispatcherBootstrapSeed {
    match core::mem::replace(
        &mut *core::ptr::addr_of_mut!(BOOTSTRAP),
        BootstrapPhase::Transferred,
    ) {
        BootstrapPhase::Owned(seed) => seed,
        BootstrapPhase::Uninitialized => {
            panic!("dispatcher bootstrap must precede handler initialization")
        }
        BootstrapPhase::Transferred => {
            panic!("dispatcher bootstrap storage was already transferred")
        }
    }
}

/// Memory-only access while bootstrap owns the original stores. No borrow may escape into IPC.
/// Once transferred, callers must use the live handler; no replacement seed is constructed.
pub(crate) unsafe fn with_local_events<R>(
    operation: impl FnOnce(&mut crate::provider_local_event::LocalEventState<'_>) -> Result<R, u32>,
) -> Result<R, u32> {
    let BootstrapPhase::Owned(seed) = &mut *core::ptr::addr_of_mut!(BOOTSTRAP) else {
        return Err(0xC000_00A3);
    };
    let mut state = crate::provider_local_event::LocalEventState::new(
        &mut seed.obj_ns,
        &mut seed.anon_event_seq,
        &mut seed.dispatcher.events,
        &mut seed.dispatcher.event_objects,
    );
    operation(&mut state)
}
