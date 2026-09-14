use crate::{
    signal_unobserved_provider_event, EventKind, EventLeaseKind, EventObjectId, EventObjectOwner,
    EventObjectRegistry, EventSignalMode, EventStore, SignalQueueResult,
    UnobservedEventSignalError,
};

const PROVIDER: EventObjectOwner = EventObjectOwner::provider(7, 3);
const LOCAL: u64 = 41;
const NATIVE: u64 = 101;

struct Fixture {
    registry: EventObjectRegistry,
    events: EventStore,
    id: EventObjectId,
}

impl Fixture {
    fn new(kind: EventKind, signaled: bool) -> Self {
        let mut registry = EventObjectRegistry::new();
        let id = registry
            .create_provider_local(PROVIDER, LOCAL, NATIVE)
            .unwrap();
        let mut events = EventStore::new();
        assert!(events.try_initialize(NATIVE, kind, signaled));
        Self {
            registry,
            events,
            id,
        }
    }

    fn signal(
        &mut self,
        provider: EventObjectOwner,
        local: u64,
        external: u32,
        mode: EventSignalMode,
    ) -> Result<(bool, bool), UnobservedEventSignalError> {
        let before = self.registry.snapshot(self.id);
        let state = self.events.query_existing(NATIVE);
        let leases = self.registry.live_lease_count();
        let signals = self.registry.queued_signal_count();
        let result = signal_unobserved_provider_event(
            &self.registry,
            &mut self.events,
            self.id,
            provider,
            local,
            external,
            mode,
        );
        assert_eq!(self.registry.snapshot(self.id), before);
        assert_eq!(self.registry.live_lease_count(), leases);
        assert_eq!(self.registry.queued_signal_count(), signals);
        if result.is_err() {
            assert_eq!(self.events.query_existing(NATIVE), state);
        }
        result
    }
}

#[test]
fn unobserved_event_signal_preserves_previous_state_and_applies_exact_final_state() {
    for kind in [EventKind::Notification, EventKind::Synchronization] {
        for previous in [false, true] {
            for mode in [EventSignalMode::Set, EventSignalMode::Pulse] {
                let mut f = Fixture::new(kind, previous);
                let current = mode == EventSignalMode::Set;
                assert_eq!(f.signal(PROVIDER, LOCAL, 0, mode), Ok((previous, current)));
                assert_eq!(f.events.query_existing(NATIVE), Some((kind, current)));
                assert_eq!(f.registry.queued_signal_count(), 0);
                assert_eq!(f.registry.live_lease_count(), 0);
                let snapshot = f.registry.snapshot(f.id).unwrap();
                assert_eq!(snapshot.native_identity, NATIVE);
                assert_eq!(snapshot.provider_local_identity, Some(LOCAL));
                assert_eq!(snapshot.signal_leases, 0);
                assert_eq!(snapshot.operation_leases, 0);
            }
        }
    }
}

#[test]
fn handle_observer_refuses_mutation_until_the_handle_drains() {
    for mode in [EventSignalMode::Set, EventSignalMode::Pulse] {
        let previous = mode == EventSignalMode::Pulse;
        let mut f = Fixture::new(EventKind::Notification, previous);
        f.registry.retain_handle(f.id).unwrap();
        assert_eq!(
            f.signal(PROVIDER, LOCAL, 0, mode),
            Err(UnobservedEventSignalError::Observed)
        );
        assert_eq!(f.registry.snapshot(f.id).unwrap().handle_leases, 1);
        assert_eq!(f.registry.release_handle(f.id), Ok(None));
        assert_eq!(
            f.signal(PROVIDER, LOCAL, 0, mode),
            Ok((previous, !previous))
        );
    }
}

#[test]
fn every_wait_and_operation_lease_blocks_unobserved_signal_until_exact_release() {
    for kind in [
        EventLeaseKind::NativeWait,
        EventLeaseKind::GuiWait,
        EventLeaseKind::ProviderWait,
        EventLeaseKind::Operation,
    ] {
        for mode in [EventSignalMode::Set, EventSignalMode::Pulse] {
            let previous = mode == EventSignalMode::Pulse;
            let mut f = Fixture::new(EventKind::Synchronization, previous);
            let lease = f.registry.acquire_wait(f.id, kind).unwrap();
            assert_eq!(
                f.signal(PROVIDER, LOCAL, 0, mode),
                Err(UnobservedEventSignalError::Observed)
            );
            assert_eq!(f.registry.event_for_lease(lease, kind), Ok(f.id));
            assert_eq!(f.registry.release_wait(lease, kind), Ok(None));
            assert_eq!(
                f.signal(PROVIDER, LOCAL, 0, mode),
                Ok((previous, !previous))
            );
        }
    }
}

#[test]
fn queued_delivering_and_retriggered_signals_keep_their_exact_delivery_state() {
    for phase in 0..3 {
        let mut f = Fixture::new(EventKind::Synchronization, true);
        assert_eq!(f.registry.queue_signal(f.id), Ok(SignalQueueResult::Queued));
        let delivering = (phase != 0).then(|| f.registry.take_next_signal().unwrap());
        if phase == 2 {
            assert_eq!(
                f.registry.queue_signal(f.id),
                Ok(SignalQueueResult::Coalesced)
            );
        }
        assert_eq!(
            f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Pulse),
            Err(UnobservedEventSignalError::Observed)
        );
        assert_eq!(f.registry.snapshot(f.id).unwrap().signal_leases, 1);
        let ticket = delivering.unwrap_or_else(|| f.registry.take_next_signal().unwrap());
        assert_eq!(ticket.id, f.id);
        assert_eq!(ticket.native_identity, NATIVE);
        assert_eq!(f.registry.complete_signal(ticket.id), Ok(None));
        if phase == 2 {
            assert_eq!(f.registry.queued_signal_count(), 1);
            assert_eq!(
                f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Pulse),
                Err(UnobservedEventSignalError::Observed)
            );
            let retriggered = f.registry.take_next_signal().unwrap();
            assert_eq!(retriggered, ticket);
            assert_eq!(f.registry.complete_signal(retriggered.id), Ok(None));
        }
        assert_eq!(
            f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Pulse),
            Ok((true, false))
        );
        assert_eq!(f.registry.take_next_signal(), None);
    }
}

#[test]
fn external_wait_references_are_observers_even_without_registry_leases() {
    let mut f = Fixture::new(EventKind::Notification, false);
    for external in [1, u32::MAX] {
        assert_eq!(
            f.signal(PROVIDER, LOCAL, external, EventSignalMode::Set),
            Err(UnobservedEventSignalError::Observed)
        );
    }
    assert_eq!(
        f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Set),
        Ok((false, true))
    );
}

#[test]
fn wrong_owner_local_and_stale_identity_do_not_signal_existing_backing() {
    let mut f = Fixture::new(EventKind::Notification, false);
    for owner in [
        EventObjectOwner::provider(8, 3),
        EventObjectOwner::provider(7, 4),
        EventObjectOwner::provider(0, 3),
        EventObjectOwner::provider(7, 0),
        EventObjectOwner::new(7, 3),
    ] {
        assert_eq!(
            f.signal(owner, LOCAL, 0, EventSignalMode::Set),
            Err(UnobservedEventSignalError::InvalidIdentity)
        );
    }
    for local in [0, LOCAL + 1, u64::MAX] {
        assert_eq!(
            f.signal(PROVIDER, local, 0, EventSignalMode::Set),
            Err(UnobservedEventSignalError::InvalidIdentity)
        );
    }
    let original = f.id;
    f.id = EventObjectId::NULL;
    assert_eq!(
        f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Set),
        Err(UnobservedEventSignalError::InvalidIdentity)
    );
    f.id = original;
    f.registry.request_delete(original).unwrap().unwrap();
    assert_eq!(
        f.registry.pending_provider_local_reclaim(PROVIDER, LOCAL),
        Some(original)
    );
    assert_eq!(
        f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Set),
        Err(UnobservedEventSignalError::InvalidIdentity)
    );
}

#[test]
fn pending_delete_does_not_become_an_unobserved_signaling_exception() {
    let mut f = Fixture::new(EventKind::Synchronization, true);
    let lease = f
        .registry
        .acquire_wait(f.id, EventLeaseKind::ProviderWait)
        .unwrap();
    assert_eq!(f.registry.request_delete(f.id), Ok(None));
    assert!(f.registry.snapshot(f.id).unwrap().delete_pending);
    assert_eq!(
        f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Pulse),
        Err(UnobservedEventSignalError::InvalidIdentity)
    );
    assert_eq!(
        f.registry
            .event_for_lease(lease, EventLeaseKind::ProviderWait),
        Ok(f.id)
    );
    let retired = f
        .registry
        .release_wait(lease, EventLeaseKind::ProviderWait)
        .unwrap()
        .unwrap();
    assert_eq!(retired.id, f.id);
    assert_eq!(
        f.events.query_existing(NATIVE),
        Some((EventKind::Synchronization, true))
    );
}

#[test]
fn process_or_projected_event_never_qualifies_as_provider_embedded_storage() {
    for owner in [EventObjectOwner::new(2, 4), PROVIDER] {
        for projected in [false, true] {
            let mut f = Fixture::new(EventKind::Notification, false);
            f.registry = EventObjectRegistry::new();
            f.id = f.registry.create(owner, NATIVE).unwrap();
            if projected {
                f.registry.install_provider_body(f.id, 0x9000).unwrap();
                f.registry.retain_pointer(f.id).unwrap();
            }
            assert_eq!(
                f.signal(PROVIDER, LOCAL, 0, EventSignalMode::Set),
                Err(UnobservedEventSignalError::InvalidIdentity)
            );
            assert_eq!(
                f.registry.snapshot(f.id).unwrap().pointer_leases,
                u32::from(projected)
            );
            if projected {
                assert_eq!(f.registry.provider_body(f.id), Ok(Some(0x9000)));
            }
        }
    }
}

#[test]
fn missing_backing_is_not_created_or_replaced_and_other_events_are_untouched() {
    let mut f = Fixture::new(EventKind::Notification, false);
    assert!(f.events.remove_existing(NATIVE));
    assert!(f
        .events
        .try_initialize(NATIVE + 1, EventKind::Synchronization, true));
    for mode in [EventSignalMode::Set, EventSignalMode::Pulse] {
        assert_eq!(
            f.signal(PROVIDER, LOCAL, 0, mode),
            Err(UnobservedEventSignalError::InvalidBacking)
        );
        assert_eq!(f.events.query_existing(NATIVE), None);
        assert_eq!(
            f.events.query_existing(NATIVE + 1),
            Some((EventKind::Synchronization, true))
        );
    }
}
