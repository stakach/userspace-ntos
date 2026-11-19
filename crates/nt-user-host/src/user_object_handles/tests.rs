use super::*;

const DOMAIN: u64 = 7;

fn target(body: u64, generation: u64) -> UserObjectTarget {
    UserObjectTarget { domain: DOMAIN, object_type: 0xD000, body, generation }
}

fn published(ledger: &mut UserObjectHandleLedger, target: UserObjectTarget) {
    ledger.prepare_publication(target).unwrap();
    ledger.record_published(target).unwrap();
}

/// Apply every pending change the way the provider does, returning the provider's final count.
fn drain(ledger: &mut UserObjectHandleLedger, mut provider_handles: u32) -> u32 {
    while let Some(delta) = ledger.next_delta(DOMAIN) {
        match delta {
            HandleDelta::Acquired { count, .. } => provider_handles += count,
            HandleDelta::Released { count, .. } => {
                assert!(provider_handles >= count, "a release crossed the live handles");
                provider_handles -= count;
            }
        }
        ledger.acknowledge(DOMAIN, delta).unwrap();
    }
    provider_handles
}

#[test]
fn provider_created_handles_need_no_provider_change() {
    let mut ledger = UserObjectHandleLedger::new();
    let desktop = target(0x7000, 1);
    published(&mut ledger, desktop);
    assert_eq!(ledger.live_handles(desktop), 1);
    assert_eq!(ledger.next_delta(DOMAIN), None);
}

#[test]
fn an_inherited_copy_is_counted_before_the_parent_release() {
    let mut ledger = UserObjectHandleLedger::new();
    let desktop = target(0x7000, 1);
    published(&mut ledger, desktop);
    ledger.acquire(desktop).unwrap();
    // The parent closes its original before the provider drains.
    ledger.release(desktop).unwrap();
    assert_eq!(ledger.next_delta(DOMAIN), Some(HandleDelta::Acquired { target: desktop, count: 1 }));
    assert_eq!(drain(&mut ledger, 1), 1, "the child's copy keeps the body");
    assert_eq!(ledger.live_handles(desktop), 1);
    ledger.release(desktop).unwrap();
    assert_eq!(drain(&mut ledger, 1), 0);
    assert!(ledger.is_empty());
}

#[test]
fn teardown_releases_stay_owned_until_acknowledged() {
    let mut ledger = UserObjectHandleLedger::new();
    let winsta = target(0x5000, 3);
    published(&mut ledger, winsta);
    ledger.release(winsta).unwrap();
    let delta = ledger.next_delta(DOMAIN).unwrap();
    assert_eq!(delta, HandleDelta::Released { target: winsta, count: 1 });
    // Delivery is not acknowledgement: the change stays until the provider applies it.
    assert_eq!(ledger.next_delta(DOMAIN), Some(delta));
    assert!(!ledger.is_empty());
    ledger.acknowledge(DOMAIN, delta).unwrap();
    assert!(ledger.is_empty());
    assert_eq!(ledger.acknowledge(DOMAIN, delta), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn acknowledgements_must_match_the_recorded_change() {
    let mut ledger = UserObjectHandleLedger::new();
    let desktop = target(0x7000, 1);
    published(&mut ledger, desktop);
    ledger.acquire(desktop).unwrap();
    for wrong in [
        HandleDelta::Acquired { target: desktop, count: 2 },
        HandleDelta::Acquired { target: desktop, count: 0 },
        HandleDelta::Released { target: desktop, count: 1 },
        HandleDelta::Acquired { target: target(0x7000, 2), count: 1 },
    ] {
        assert!(ledger.acknowledge(DOMAIN, wrong).is_err());
    }
    assert_eq!(
        ledger.acknowledge(DOMAIN + 1, HandleDelta::Acquired { target: desktop, count: 1 }),
        Err(STATUS_INVALID_PARAMETER),
        "one provider cannot acknowledge another's change"
    );
    assert_eq!(ledger.next_delta(DOMAIN + 1), None);
    assert_eq!(drain(&mut ledger, 1), 2);
}

#[test]
fn a_cancelled_copy_undoes_or_releases_its_acquisition() {
    let mut ledger = UserObjectHandleLedger::new();
    let desktop = target(0x7000, 1);
    published(&mut ledger, desktop);
    ledger.acquire(desktop).unwrap();
    ledger.cancel_acquire(desktop).unwrap();
    assert_eq!(ledger.next_delta(DOMAIN), None);
    assert_eq!(ledger.live_handles(desktop), 1);

    ledger.acquire(desktop).unwrap();
    assert_eq!(drain(&mut ledger, 1), 2);
    ledger.cancel_acquire(desktop).unwrap();
    assert_eq!(ledger.next_delta(DOMAIN), Some(HandleDelta::Released { target: desktop, count: 1 }));
    assert_eq!(drain(&mut ledger, 2), 1);
}

#[test]
fn copies_and_releases_need_a_live_handle() {
    let mut ledger = UserObjectHandleLedger::new();
    let desktop = target(0x7000, 1);
    assert_eq!(ledger.acquire(desktop), Err(STATUS_INVALID_HANDLE));
    assert_eq!(ledger.release(desktop), Err(STATUS_INVALID_HANDLE));
    ledger.prepare_publication(desktop).unwrap();
    assert_eq!(ledger.acquire(desktop), Err(STATUS_INVALID_HANDLE));
    ledger.discard_unpublished(desktop);
    assert!(ledger.is_empty());
}

#[test]
fn a_reused_body_cannot_publish_while_an_older_generation_has_handles() {
    let mut ledger = UserObjectHandleLedger::new();
    let first = target(0x7000, 1);
    published(&mut ledger, first);
    assert_eq!(ledger.prepare_publication(target(0x7000, 2)), Err(STATUS_INVALID_HANDLE));
    ledger.release(first).unwrap();
    assert_eq!(drain(&mut ledger, 1), 0);
    published(&mut ledger, target(0x7000, 2));
    assert_eq!(ledger.live_handles(first), 0);
}

#[test]
fn large_batches_are_delivered_in_bounded_counts() {
    let mut ledger = UserObjectHandleLedger::new();
    let desktop = target(0x7000, 1);
    published(&mut ledger, desktop);
    for _ in 0..MAX_DELTA + 2 {
        ledger.acquire(desktop).unwrap();
    }
    assert_eq!(
        ledger.next_delta(DOMAIN),
        Some(HandleDelta::Acquired { target: desktop, count: MAX_DELTA })
    );
    assert_eq!(drain(&mut ledger, 1), MAX_DELTA + 3);
}
