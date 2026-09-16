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

/// Scan only while this phase owns the stores. The pending notification still belongs to the
/// shared timer owner: do not consume it, reprogram the PIT or enter a provider here.
pub(crate) unsafe fn scan_timer_delivery(
    now: nt_delay_execution::TimeSnapshot,
) -> Result<(), nt_user_host::provider_wait_selection::ProviderWaitSelectionError<u32>> {
    let BootstrapPhase::Owned(seed) = &mut *core::ptr::addr_of_mut!(BOOTSTRAP) else {
        return Ok(());
    };
    let _durable = allocator::enter_durable();
    let mut objects = nt_user_host::provider_dispatcher_backend::ProviderDispatcherObjects {
        events: &mut seed.dispatcher.events,
        event_objects: &mut seed.dispatcher.event_objects,
        timers: seed.dispatcher.provider_timers.as_mut(),
        backing: crate::provider_dispatcher_backend::NativeEventBacking(&mut seed.obj_ns),
        access: None,
    };
    service_sec_image::provider_wait_scan_timed(&mut objects, now).map(|_| ())
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
