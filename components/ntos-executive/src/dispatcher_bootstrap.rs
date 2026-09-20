//! Canonical dispatcher storage created before providers and moved once into the live handler.

use super::*;

pub(crate) struct DispatcherBootstrapSeed {
    pub obj_ns: Vec<ObjEntry>,
    pub anon_event_seq: u32,
    pub dispatcher: nt_user_host::dispatcher_state::DispatcherState,
}

static mut BOOTSTRAP: nt_user_host::bootstrap_store::BootstrapStore<DispatcherBootstrapSeed> =
    nt_user_host::bootstrap_store::BootstrapStore::new();
static mut HOSTED_TIMER_PROGRESS: nt_time::DeferredTimerProgress =
    nt_time::DeferredTimerProgress::new();
static mut REARM: nt_time::DeferredRearm = nt_time::DeferredRearm::new();

/// A completed service reply may publish demand through a shared page, not just a timer API.
pub(crate) unsafe fn request_receive_checkpoint() -> bool {
    if !(&*core::ptr::addr_of!(BOOTSTRAP)).is_owned() {
        return false;
    }
    assert!(
        (&mut *core::ptr::addr_of_mut!(REARM)).request(),
        "bootstrap rearm generation exhausted"
    );
    true
}

unsafe fn rearm_pending() -> bool {
    (&*core::ptr::addr_of!(REARM)).pending().is_some()
}

unsafe fn pending_timer_snapshot() -> Option<u64> {
    if !(&*core::ptr::addr_of!(BOOTSTRAP)).is_owned() {
        return None;
    }
    let pending = DELAY_TIMER_TICKS_PENDING.load(Ordering::Relaxed);
    (&*core::ptr::addr_of!(HOSTED_TIMER_PROGRESS))
        .needs_scan(pending)
        .then_some(pending)
}

/// Eligibility only: observing retained ticks neither consumes them nor authorizes rearming.
pub(crate) unsafe fn timer_work_pending() -> bool {
    !TIMER_DELIVERY_GATE.is_active()
        && (&*core::ptr::addr_of!(BOOTSTRAP)).is_owned()
        && (pending_timer_snapshot().is_some() || rearm_pending())
}

/// Called from the retained component scheduler, never the IRQ-lane ACK hook. Driver timer
/// publication can perform IPC, so no bootstrap store reference may cross this call.
pub(crate) unsafe fn service_hosted_timer_work() -> u64 {
    if !(&*core::ptr::addr_of!(BOOTSTRAP)).is_owned() {
        return 0;
    }
    let Some(_delivery) = TIMER_DELIVERY_GATE.try_enter() else {
        return 0;
    };
    let pending = pending_timer_snapshot();
    if pending.is_none() && !rearm_pending() {
        return 0;
    }
    let now = nt_time_snapshot();
    let work = timer_hosted_driver_wake_due(now);
    let provider_work = scan_owned_timer_work(now)
        .expect("bootstrap timer selection lost its canonical continuation");
    // Observe retained demand only. ACPI acknowledgement and DPC execution have outer owners.
    let deferred_work = driver_launch::hosted_acpi_pci_route_recovery_wake_due(now.monotonic_100ns)
        .saturating_add(driver_launch::hosted_dpc_wake_due(now.monotonic_100ns));
    if let Some(pending) = pending {
        (&mut *core::ptr::addr_of_mut!(HOSTED_TIMER_PROGRESS)).record_scan(pending);
    }
    work.saturating_add(provider_work)
        .saturating_add(deferred_work)
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
    scan_owned_timer_work(now).map(|_| ())
}

/// Both delivery paths hold the gate. Keep all dispatcher references inside this memory-only
/// scan so the retained scheduler can call it after hosted timer IPC has returned.
unsafe fn scan_owned_timer_work(
    now: nt_delay_execution::TimeSnapshot,
) -> Result<u64, nt_user_host::provider_wait_selection::ProviderWaitSelectionError<u32>> {
    let _durable = allocator::enter_durable();
    let Some(scanned) = with_provider_objects(|mut objects| {
        service_sec_image::provider_wait_scan_timed(&mut objects, now)
    }) else {
        return Ok(0);
    };
    let scanned = scanned?;
    Ok(scanned
        .timeouts
        .saturating_add(scanned.expired_timers)
        .saturating_add(scanned.ready)
        .saturating_add(timer_retry_wake_due(now.monotonic_100ns)))
}

/// Collect at a retained scheduler boundary, not the dedicated IRQ ACK hook. The global
/// collector can reconcile retry demand but neither services it nor authorizes hardware rearm.
pub(crate) unsafe fn next_deadline(now: nt_time::TimeSnapshot) -> Result<Option<(u64, u64)>, u32> {
    const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;
    let _delivery = TIMER_DELIVERY_GATE.try_enter().ok_or(STATUS_DEVICE_BUSY)?;
    collect_owned_deadline(now)
}

unsafe fn collect_owned_deadline(now: nt_time::TimeSnapshot) -> Result<Option<(u64, u64)>, u32> {
    let owner = (&*core::ptr::addr_of!(BOOTSTRAP))
        .with_ref(|seed| {
            Ok::<_, u32>(timer_deadline::OwnerDeadlines {
                dispatcher: service_sec_image::bootstrap_dispatcher_deadlines(
                    seed.dispatcher.provider_timers.as_ref(),
                    now,
                )?,
                // These stores are created only after take() transfers the dispatcher to runtime.
                user_timer: None,
                job_time: None,
                component_resume: service_sec_image::component_resume::retained_deadline(),
            })
        })
        .map_err(|_| 0xC000_00A3u32)??;
    Ok(timer_deadline::next(now, owner))
}

/// Called only after the retained scheduler's effects, with no dispatcher/PM references alive.
/// Pending ticks remain owned by the complete delivery owner; programming is not acknowledgment.
pub(crate) unsafe fn prepare_receive() -> Result<(), u32> {
    if !(&*core::ptr::addr_of!(BOOTSTRAP)).is_owned() {
        return Ok(());
    }
    let Some(_delivery) = TIMER_DELIVERY_GATE.try_enter() else {
        return Ok(());
    };
    let Some(request) = (&*core::ptr::addr_of!(REARM)).pending() else {
        return Ok(());
    };
    nt_time::reconcile_rearm(
        || collect_owned_deadline(nt_time_snapshot()),
        || delay_timer_init().then_some(()).ok_or(0xC000_00A3),
        |(deadline, source)| {
            delay_timer_program(deadline, source)
                .then_some(())
                .ok_or(0xC000_0001)
        },
    )?;
    assert!(
        (&mut *core::ptr::addr_of_mut!(REARM)).complete(request),
        "bootstrap rearm lost its request"
    );
    Ok(())
}

pub(crate) unsafe fn initialize() -> Result<(), u32> {
    if !(&*core::ptr::addr_of!(BOOTSTRAP)).is_uninitialized() {
        return Err(nt_process::STATUS_INVALID_PARAMETER);
    }
    let _durable = allocator::enter_durable();
    service_sec_image::initialize_service_delay_queue_work()?;
    let seed = DispatcherBootstrapSeed {
        obj_ns: exec_handler::build_initial_object_namespace(),
        anon_event_seq: 0,
        dispatcher: nt_user_host::dispatcher_state::DispatcherState::new(192, 192),
    };
    (&mut *core::ptr::addr_of_mut!(BOOTSTRAP))
        .initialize(seed)
        .map_err(|_| nt_process::STATUS_INVALID_PARAMETER)
}

pub(crate) unsafe fn take() -> DispatcherBootstrapSeed {
    (&mut *core::ptr::addr_of_mut!(BOOTSTRAP))
        .take()
        .expect("dispatcher bootstrap must transfer its original stores exactly once")
}

/// Memory-only field access. Absence means bootstrap does not own these stores, not empty stores.
/// No dispatcher reference may survive the callback or cross a provider/hardware effect.
pub(crate) unsafe fn with_provider_objects<R>(
    operation: impl FnOnce(
        nt_user_host::provider_dispatcher_backend::ProviderDispatcherObjects<
            '_,
            crate::provider_dispatcher_backend::NativeEventBacking<'_>,
        >,
    ) -> R,
) -> Option<R> {
    (&mut *core::ptr::addr_of_mut!(BOOTSTRAP))
        .with_mut(|seed| {
            operation(
                nt_user_host::provider_dispatcher_backend::ProviderDispatcherObjects {
                    events: &mut seed.dispatcher.events,
                    event_objects: &mut seed.dispatcher.event_objects,
                    timers: seed.dispatcher.provider_timers.as_mut(),
                    backing: crate::provider_dispatcher_backend::NativeEventBacking(
                        &mut seed.obj_ns,
                    ),
                    access: None,
                },
            )
        })
        .ok()
}

/// Memory-only access while bootstrap owns the original stores. No borrow may escape into IPC.
/// Once transferred, callers must use the live handler; no replacement seed is constructed.
pub(crate) unsafe fn with_local_events<R>(
    operation: impl FnOnce(&mut crate::provider_local_event::LocalEventState<'_>) -> Result<R, u32>,
) -> Result<R, u32> {
    (&mut *core::ptr::addr_of_mut!(BOOTSTRAP))
        .with_mut(|seed| {
            let mut state = crate::provider_local_event::LocalEventState::new(
                &mut seed.obj_ns,
                &mut seed.anon_event_seq,
                &mut seed.dispatcher.events,
                &mut seed.dispatcher.event_objects,
            );
            operation(&mut state)
        })
        .map_err(|_| 0xC000_00A3u32)?
}
