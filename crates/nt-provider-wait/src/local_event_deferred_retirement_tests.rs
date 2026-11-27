use super::*;

fn provider() -> ProviderDomainIdentity {
    ProviderDomainIdentity {
        domain: 7,
        generation: 3,
    }
}

fn canonical(id: u64) -> ProviderWaitObject {
    ProviderWaitObject::new(ProviderWaitObjectType::Event, id, 1)
}

fn allocation(id: u64, generation: u64) -> ProviderEventStorage {
    ProviderEventStorage {
        backing: ProviderEventBacking::Allocation {
            arena_id: 1,
            arena_generation: 1,
            allocation_id: id,
            allocation_generation: generation,
        },
        offset: 0,
    }
}

/// The root broker may resume the ERESOURCE waiter before the signaling provider returns.
/// The waiter can return only after moving its allocation-backed Event into a deferred owner;
/// the in-flight Signal lease then completes the one exact retirement.
#[test]
fn a_resumed_waiter_defers_retirement_until_the_exact_signal_lease_finishes() {
    let mut events = ProviderLocalEventCatalog::new(provider()).unwrap();
    let storage = allocation(81, 1);
    let id = events
        .initialize(0x8100, storage, ProviderEventKind::Synchronization, false)
        .unwrap();
    events.bind_canonical(id, canonical(81)).unwrap();
    let wait = events
        .acquire_lease(id, ProviderLocalEventLeaseKind::Wait)
        .unwrap();
    let signal = events
        .acquire_lease(id, ProviderLocalEventLeaseKind::Signal)
        .unwrap();

    // The exact Wait lease settles with the successful wait; the Signal lease still owns
    // access to the Event storage and may mirror the broker's published state.
    events.release_lease(wait).unwrap();
    assert!(matches!(
        events.request_retire_after_leases(id, storage),
        Ok(ProviderLocalEventRetireDecision::Draining)
    ));
    let snapshot = events.snapshot(id).unwrap();
    assert!(snapshot.delete_pending);
    assert_eq!((snapshot.wait_leases, snapshot.signal_leases), (0, 1));
    assert_eq!(
        events.resolve_body(0x8100),
        Err(ProviderLocalEventError::DeletePending)
    );
    assert_eq!(
        events.acquire_lease(id, ProviderLocalEventLeaseKind::Wait),
        Err(ProviderLocalEventError::DeletePending)
    );
    assert_eq!(events.observe_state(signal, 1, true), Ok(true));

    // An ordinary release must not silently discard the canonical retirement receipt or
    // free the allocation while a root acknowledgement is still owed.
    assert_eq!(
        events.release_lease(signal),
        Err(ProviderLocalEventError::DeferredRetirementRequired)
    );
    assert_eq!(events.snapshot(id).unwrap().signal_leases, 1);
    let retirement = events
        .release_lease_for_retirement(signal)
        .unwrap()
        .unwrap();
    assert_eq!(retirement.id, id);
    assert_eq!(retirement.canonical, canonical(81));
    assert_eq!(retirement.body, 0x8100);
    assert_eq!(retirement.storage, storage);
    assert_eq!(events.snapshot(id).unwrap().signal_leases, 0);
    assert!(events.release_lease_for_retirement(signal).is_err());
    events.ack_retirement(retirement).unwrap();
    assert_eq!(
        events.snapshot(id),
        Err(ProviderLocalEventError::StaleIdentity)
    );

    // Reusing the same numeric body and allocation ID has a new generation. The stale Signal
    // lease and old retirement cannot consume any ownership belonging to that generation.
    let second = events
        .initialize(
            0x8100,
            allocation(81, 2),
            ProviderEventKind::Synchronization,
            false,
        )
        .unwrap();
    events.bind_canonical(second, canonical(82)).unwrap();
    assert_ne!(id, second);
    let live = events
        .acquire_lease(second, ProviderLocalEventLeaseKind::Signal)
        .unwrap();
    assert_eq!(
        events.release_lease_for_retirement(signal),
        Err(ProviderLocalEventError::StaleIdentity)
    );
    assert_eq!(events.snapshot(second).unwrap().signal_leases, 1);
    events.release_lease(live).unwrap();
}

#[test]
fn deferred_retirement_rejects_crossed_storage_without_consuming_the_event() {
    let mut events = ProviderLocalEventCatalog::new(provider()).unwrap();
    let storage = allocation(83, 1);
    let id = events
        .initialize(0x8300, storage, ProviderEventKind::Synchronization, false)
        .unwrap();
    events.bind_canonical(id, canonical(83)).unwrap();
    let signal = events
        .acquire_lease(id, ProviderLocalEventLeaseKind::Signal)
        .unwrap();
    assert!(matches!(
        events.request_retire_after_leases(id, allocation(84, 1)),
        Err(ProviderLocalEventError::InvalidStorage)
    ));
    assert!(!events.snapshot(id).unwrap().delete_pending);
    assert_eq!(events.snapshot(id).unwrap().signal_leases, 1);
    events.release_lease(signal).unwrap();
    let retirement = match events.request_retire_after_leases(id, storage).unwrap() {
        ProviderLocalEventRetireDecision::Ready(retirement) => retirement,
        ProviderLocalEventRetireDecision::Draining => panic!("no lease remains"),
    };
    assert_eq!(
        events.ack_retirement(ProviderLocalEventRetirement {
            id,
            canonical: canonical(83),
            body: 0x8300,
            storage: allocation(83, 2),
        }),
        Err(ProviderLocalEventError::RetirementMismatch)
    );
    assert_eq!(
        events.ack_retirement(ProviderLocalEventRetirement {
            id,
            canonical: canonical(83),
            body: 0x8301,
            storage,
        }),
        Err(ProviderLocalEventError::RetirementMismatch)
    );
    events.ack_retirement(retirement).unwrap();
}

#[test]
fn deferred_retirement_requires_the_wait_lease_to_settle_first() {
    let mut events = ProviderLocalEventCatalog::new(provider()).unwrap();
    let storage = allocation(85, 1);
    let id = events
        .initialize(0x8500, storage, ProviderEventKind::Synchronization, false)
        .unwrap();
    events.bind_canonical(id, canonical(85)).unwrap();
    let wait = events
        .acquire_lease(id, ProviderLocalEventLeaseKind::Wait)
        .unwrap();
    let signal = events
        .acquire_lease(id, ProviderLocalEventLeaseKind::Signal)
        .unwrap();

    assert!(matches!(
        events.request_retire_after_leases(id, storage),
        Err(ProviderLocalEventError::ActiveLeases)
    ));
    let snapshot = events.resolve_body(0x8500).unwrap();
    assert_eq!(snapshot.id, id);
    assert!(!snapshot.delete_pending);
    assert_eq!((snapshot.wait_leases, snapshot.signal_leases), (1, 1));

    events.release_lease(wait).unwrap();
    assert!(matches!(
        events.request_retire_after_leases(id, storage),
        Ok(ProviderLocalEventRetireDecision::Draining)
    ));
    let retirement = events
        .release_lease_for_retirement(signal)
        .unwrap()
        .unwrap();
    events.ack_retirement(retirement).unwrap();
}

#[test]
fn deferred_retirement_rejects_an_embedded_event_before_changing_its_lifetime() {
    let mut events = ProviderLocalEventCatalog::new(provider()).unwrap();
    let storage = ProviderEventStorage {
        offset: 8,
        ..allocation(87, 1)
    };
    let id = events
        .initialize(0x8708, storage, ProviderEventKind::Synchronization, false)
        .unwrap();
    events.bind_canonical(id, canonical(87)).unwrap();
    assert_eq!(
        events.request_retire_after_leases(id, storage),
        Err(ProviderLocalEventError::InvalidStorage)
    );
    let still_published = events.resolve_body(0x8708).unwrap();
    assert_eq!(still_published.id, id);
    assert!(!still_published.delete_pending);
    assert_eq!(still_published.storage, storage);
}

#[test]
fn stack_storage_cannot_escape_through_deferred_retirement() {
    let mut events = ProviderLocalEventCatalog::new(provider()).unwrap();
    let storage = ProviderEventStorage {
        backing: ProviderEventBacking::Stack {
            lane_id: 2,
            lane_generation: 1,
            dispatch_id: 9,
            activation_generation: 4,
        },
        offset: 0x20,
    };
    let id = events
        .initialize(0x9020, storage, ProviderEventKind::Synchronization, false)
        .unwrap();
    events.bind_canonical(id, canonical(90)).unwrap();
    let signal = events
        .acquire_lease(id, ProviderLocalEventLeaseKind::Signal)
        .unwrap();
    assert!(matches!(
        events.request_retire_after_leases(id, storage),
        Err(ProviderLocalEventError::InvalidStorage)
    ));
    assert!(!events.snapshot(id).unwrap().delete_pending);
    events.release_lease(signal).unwrap();
    let retirement = events.begin_retire_event(id).unwrap();
    events.ack_retirement(retirement).unwrap();
}
