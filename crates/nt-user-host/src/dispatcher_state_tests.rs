use super::*;
use alloc::vec::Vec;
use nt_component_suspension::{LaneHandle, SuspensionCaller, SuspensionOwner};
use nt_kernel_exec::{
    EventKind, EventLeaseKind, EventObjectError, EventObjectId, EventObjectOwner,
    SignalQueueResult, TimeSnapshot,
};
use nt_provider_wait::{ProviderDomainIdentity, ProviderTimerError, ProviderTimerKind};

const PROVIDER: EventObjectOwner = EventObjectOwner::provider(7, 3);
const PROCESS: EventObjectOwner = EventObjectOwner::new(2, 4);

/// Mirrors the native seed's aggregate ownership, not its namespace implementation.
struct OwnedDispatcher {
    state: DispatcherState,
    namespace: Vec<(u64, &'static str)>,
    next_native: u64,
}

impl OwnedDispatcher {
    fn new() -> Self {
        Self {
            state: DispatcherState::new(1, 1),
            namespace: Vec::new(),
            next_native: 101,
        }
    }

    fn backing(&mut self, name: &'static str, kind: EventKind, signaled: bool) -> u64 {
        let native = self.next_native;
        self.next_native += 1;
        self.namespace.push((native, name));
        assert!(self.state.events.try_initialize(native, kind, signaled));
        native
    }

    fn provider_event(&mut self, local: u64, name: &'static str) -> (EventObjectId, u64) {
        let native = self.backing(name, EventKind::Notification, false);
        let id = self
            .state
            .event_objects
            .create_provider_local(PROVIDER, local, native)
            .unwrap();
        (id, native)
    }

    fn remove_backing(&mut self, native: u64) {
        assert!(self.state.events.remove_existing(native));
        let index = self
            .namespace
            .iter()
            .position(|(id, _)| *id == native)
            .unwrap();
        self.namespace.remove(index);
    }
}

fn handoff(source: OwnedDispatcher) -> OwnedDispatcher {
    let OwnedDispatcher {
        state,
        namespace,
        next_native,
    } = source;
    OwnedDispatcher {
        state,
        namespace,
        next_native,
    }
}

fn now(monotonic_100ns: u64) -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns,
        system_time_100ns: 1_000_000 + monotonic_100ns,
        clock_generation: 0,
    }
}

fn timer_owner() -> SuspensionOwner {
    SuspensionOwner {
        provider_domain: 7,
        provider_generation: 3,
        dispatch_id: 11,
        caller: SuspensionCaller::Kernel {
            lane: LaneHandle {
                index: 0,
                generation: 1,
            },
        },
    }
}

#[test]
fn move_keeps_native_and_canonical_ids_namespace_state_and_all_lease_kinds() {
    let mut source = OwnedDispatcher::new();
    let (provider, provider_native) = source.provider_event(41, "provider");
    source.state.events.set_existing(provider_native).unwrap();
    let process_native = source.backing("process", EventKind::Synchronization, true);
    let process = source
        .state
        .event_objects
        .create(PROCESS, process_native)
        .unwrap();
    source
        .state
        .event_objects
        .install_provider_body(process, 0x9000)
        .unwrap();
    source.state.event_objects.retain_handle(process).unwrap();
    source.state.event_objects.retain_pointer(process).unwrap();
    let native_wait = source
        .state
        .event_objects
        .acquire_wait(process, EventLeaseKind::NativeWait)
        .unwrap();
    let gui_wait = source
        .state
        .event_objects
        .acquire_wait(process, EventLeaseKind::GuiWait)
        .unwrap();
    let provider_wait = source
        .state
        .event_objects
        .acquire_wait(provider, EventLeaseKind::ProviderWait)
        .unwrap();
    let process_snapshot = source.state.event_objects.snapshot(process).unwrap();
    let provider_snapshot = source.state.event_objects.snapshot(provider).unwrap();
    let next_native = source.next_native;

    let mut live = handoff(source);
    assert_eq!(live.next_native, next_native);
    assert_eq!(
        live.namespace.as_slice(),
        &[(provider_native, "provider"), (process_native, "process")]
    );
    assert_eq!(
        live.state.event_objects.snapshot(process),
        Ok(process_snapshot)
    );
    assert_eq!(
        live.state.event_objects.snapshot(provider),
        Ok(provider_snapshot)
    );
    assert_eq!(
        live.state.event_objects.id_for_native(process_native),
        Some(process)
    );
    assert_eq!(
        live.state.event_objects.id_for_provider_body(0x9000),
        Some(process)
    );
    assert_eq!(
        live.state.event_objects.id_for_provider_local(PROVIDER, 41),
        Some(provider)
    );
    for (lease, kind, id) in [
        (native_wait, EventLeaseKind::NativeWait, process),
        (gui_wait, EventLeaseKind::GuiWait, process),
        (provider_wait, EventLeaseKind::ProviderWait, provider),
    ] {
        assert_eq!(
            live.state.event_objects.event_for_lease(lease, kind),
            Ok(id)
        );
    }
    assert_eq!(live.state.event_objects.live_lease_count(), 3);
    assert_eq!(
        live.state.events.query_existing(provider_native),
        Some((EventKind::Notification, true))
    );
    assert_eq!(
        live.state.events.query_existing(process_native),
        Some((EventKind::Synchronization, true))
    );
    assert!(live.state.events.consume_existing(provider_native));
    assert!(live.state.events.consume_existing(provider_native));
    assert!(live.state.events.consume_existing(process_native));
    assert!(!live.state.events.consume_existing(process_native));
    assert_eq!(
        live.backing("later", EventKind::Notification, false),
        next_native
    );
    assert_eq!(live.next_native, next_native + 1);
}

#[test]
fn move_preserves_delivering_signal_retrigger_queue_order_and_pending_deletion() {
    let mut source = OwnedDispatcher::new();
    let (first, first_native) = source.provider_event(41, "first");
    let (second, _) = source.provider_event(42, "second");
    let (third, _) = source.provider_event(43, "third");
    source.state.event_objects.queue_signal(first).unwrap();
    source.state.event_objects.queue_signal(second).unwrap();
    let in_flight = source.state.event_objects.take_next_signal().unwrap();
    assert_eq!(in_flight.id, first);
    assert_eq!(
        source.state.event_objects.queue_signal(first),
        Ok(SignalQueueResult::Coalesced)
    );
    assert_eq!(source.state.event_objects.request_delete(first), Ok(None));

    let mut live = handoff(source);
    assert_eq!(in_flight.native_identity, first_native);
    assert_eq!(
        live.state
            .event_objects
            .snapshot(first)
            .unwrap()
            .signal_leases,
        1
    );
    assert_eq!(
        live.state.event_objects.complete_signal(in_flight.id),
        Ok(None)
    );
    live.state.event_objects.queue_signal(third).unwrap();
    assert_eq!(live.state.event_objects.queued_signal_count(), 3);
    let next = live.state.event_objects.take_next_signal().unwrap();
    assert_eq!(next.id, second);
    live.state.event_objects.complete_signal(next.id).unwrap();
    let retrigger = live.state.event_objects.take_next_signal().unwrap();
    assert_eq!(retrigger.id, first);
    assert_eq!(retrigger.native_identity, first_native);
    assert_eq!(
        live.state.events.set_existing(retrigger.native_identity),
        Some(false)
    );
    let retired = live
        .state
        .event_objects
        .complete_signal(retrigger.id)
        .unwrap()
        .unwrap();
    assert_eq!(retired.native_identity, first_native);
    assert_eq!(retired.provider_local_identity, Some(41));
    let last = live.state.event_objects.take_next_signal().unwrap();
    assert_eq!(last.id, third);
    live.state.event_objects.complete_signal(last.id).unwrap();
    assert_eq!(live.state.event_objects.take_next_signal(), None);
    live.remove_backing(retired.native_identity);

    let mut live = handoff(live);
    assert_eq!(
        live.state
            .event_objects
            .pending_provider_local_reclaim(PROVIDER, 41),
        Some(first)
    );
    assert_eq!(live.state.events.query_existing(first_native), None);
    assert_eq!(
        live.state
            .event_objects
            .complete_provider_local_reclaim(first, PROVIDER, 42),
        Err(EventObjectError::InvalidProviderIdentity)
    );
    live.state
        .event_objects
        .complete_provider_local_reclaim(first, PROVIDER, 41)
        .unwrap();
}

#[test]
fn move_keeps_lease_deferred_delete_and_exact_reclaim_tombstones() {
    let mut source = OwnedDispatcher::new();
    let (provider, provider_native) = source.provider_event(41, "provider");
    let process_native = source.backing("process", EventKind::Synchronization, false);
    let process = source
        .state
        .event_objects
        .create(PROCESS, process_native)
        .unwrap();
    source
        .state
        .event_objects
        .install_provider_body(process, 0x9000)
        .unwrap();
    source.state.event_objects.retain_handle(process).unwrap();
    source.state.event_objects.retain_pointer(process).unwrap();
    let lease = source
        .state
        .event_objects
        .acquire_wait(process, EventLeaseKind::ProviderWait)
        .unwrap();
    assert_eq!(source.state.event_objects.request_delete(process), Ok(None));
    source
        .state
        .event_objects
        .request_delete(provider)
        .unwrap()
        .unwrap();
    source.remove_backing(provider_native);

    let mut live = handoff(source);
    assert!(
        live.state
            .event_objects
            .snapshot(process)
            .unwrap()
            .delete_pending
    );
    assert_eq!(live.state.event_objects.release_handle(process), Ok(None));
    assert_eq!(
        live.state.event_objects.release_pointer_by_body(0x9000),
        Ok(None)
    );
    let retired = live
        .state
        .event_objects
        .release_wait(lease, EventLeaseKind::ProviderWait)
        .unwrap()
        .unwrap();
    live.remove_backing(retired.native_identity);
    assert_eq!(
        live.state
            .event_objects
            .release_wait(lease, EventLeaseKind::ProviderWait),
        Err(EventObjectError::StaleLease)
    );
    let mut live = handoff(live);
    assert_eq!(
        live.state.event_objects.pending_provider_reclaim(),
        Some((process, 0x9000))
    );
    assert_eq!(
        live.state
            .event_objects
            .pending_provider_local_reclaim(PROVIDER, 41),
        Some(provider)
    );
    let (unrelated, _) = live.provider_event(42, "unrelated");
    assert_ne!(unrelated.0.slot(), provider.0.slot());
    assert_ne!(unrelated.0.slot(), process.0.slot());
    live.state
        .event_objects
        .complete_provider_local_reclaim(provider, PROVIDER, 41)
        .unwrap();
    let (replacement, _) = live.provider_event(41, "replacement");
    assert_eq!(replacement.0.slot(), provider.0.slot());
    assert_ne!(replacement.0.generation(), provider.0.generation());
    assert_eq!(
        live.state
            .event_objects
            .complete_provider_local_reclaim(provider, PROVIDER, 41),
        Err(EventObjectError::StaleObject)
    );
    assert_eq!(
        live.state
            .event_objects
            .complete_provider_reclaim(process, 0x9001),
        Err(EventObjectError::InvalidProviderBody)
    );
    live.state
        .event_objects
        .complete_provider_reclaim(process, 0x9000)
        .unwrap();
    assert_eq!(live.state.event_objects.pending_provider_reclaim(), None);
}

#[test]
fn provider_timer_move_preserves_deadlines_periods_signal_semantics_and_wait_leases() {
    let mut source = OwnedDispatcher::new();
    let provider = ProviderDomainIdentity {
        domain: 7,
        generation: 3,
    };
    let mut timers = ProviderTimerTable::new(provider).unwrap();
    let notification = timers.publish(51, ProviderTimerKind::Notification).unwrap();
    let synchronization = timers
        .publish(52, ProviderTimerKind::Synchronization)
        .unwrap();
    let notification_lease = timers
        .acquire_wait(timer_owner(), notification.wait_object())
        .unwrap();
    let synchronization_lease = timers
        .acquire_wait(timer_owner(), synchronization.wait_object())
        .unwrap();
    timers.set_local(51, -100, 2, now(10)).unwrap();
    timers.set_local(52, -200, 0, now(10)).unwrap();
    source.state.provider_timers = Some(timers);

    let mut live = handoff(source);
    let timers = live.state.provider_timers.as_mut().unwrap();
    assert_eq!(timers.provider(), provider);
    assert_eq!(timers.id_for_local(51), Some(notification));
    assert_eq!(timers.next_deadline(now(10)), Some(110));
    assert_eq!(timers.expire_next_due(now(109)), None);
    assert!(!timers.is_ready(notification_lease).unwrap());
    assert_eq!(timers.expire_next_due(now(110)).unwrap().id, notification);
    timers.consume_ready(notification_lease).unwrap();
    assert!(timers.is_ready(notification_lease).unwrap());
    assert_eq!(timers.next_deadline(now(110)), Some(210));
    assert_eq!(
        timers.expire_next_due(now(210)).unwrap().id,
        synchronization
    );
    assert!(timers.is_ready(synchronization_lease).unwrap());

    let mut live = handoff(live);
    let timers = live.state.provider_timers.as_mut().unwrap();
    timers.consume_ready(synchronization_lease).unwrap();
    assert!(!timers.is_ready(synchronization_lease).unwrap());
    assert!(timers.is_ready(notification_lease).unwrap());
    assert_eq!(timers.next_deadline(now(210)), Some(20_110));
    assert_eq!(timers.release_wait(notification_lease), Ok(None));
    assert_eq!(timers.release_wait(synchronization_lease), Ok(None));
}

#[test]
fn provider_timer_delete_and_retirement_tickets_survive_move_without_early_reuse() {
    let mut source = OwnedDispatcher::new();
    let mut timers = ProviderTimerTable::new(ProviderDomainIdentity {
        domain: 7,
        generation: 3,
    })
    .unwrap();
    let timer = timers.publish(51, ProviderTimerKind::Notification).unwrap();
    let lease = timers
        .acquire_wait(timer_owner(), timer.wait_object())
        .unwrap();
    timers.set_local(51, -100, 0, now(10)).unwrap();
    assert_eq!(timers.request_retire_local(51), Ok(None));
    source.state.provider_timers = Some(timers);

    let mut live = handoff(source);
    let timers = live.state.provider_timers.as_mut().unwrap();
    assert_eq!(timers.next_deadline(now(10)), None);
    assert_eq!(
        timers.acquire_wait(timer_owner(), timer.wait_object()),
        Err(ProviderTimerError::DeletePending)
    );
    assert_eq!(
        timers.publish(51, ProviderTimerKind::Notification),
        Err(ProviderTimerError::LocalIdentityInUse)
    );
    let retirement = timers.release_wait(lease).unwrap().unwrap();
    assert_eq!(retirement.id, timer);

    let mut live = handoff(live);
    let timers = live.state.provider_timers.as_mut().unwrap();
    let mut wrong = retirement;
    wrong.local_identity += 1;
    assert_eq!(
        timers.ack_retirement(wrong),
        Err(ProviderTimerError::RetirementMismatch)
    );
    assert_eq!(timers.id_for_local(51), Some(timer));
    timers.ack_retirement(retirement).unwrap();
    let replacement = timers
        .publish(51, ProviderTimerKind::Synchronization)
        .unwrap();
    assert_ne!(replacement, timer);
    assert_eq!(
        replacement.wait_object().object_id,
        timer.wait_object().object_id
    );
    assert_eq!(
        timers.read_state(timer),
        Err(ProviderTimerError::StaleIdentity)
    );
    assert_eq!(
        timers.release_wait(lease),
        Err(ProviderTimerError::WrongLease)
    );
    assert_eq!(
        timers.ack_retirement(retirement),
        Err(ProviderTimerError::StaleIdentity)
    );
}
