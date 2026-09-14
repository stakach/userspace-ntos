use super::*;
use crate::EventKind;

const PROVIDER: EventObjectOwner = EventObjectOwner::provider(7, 3);
const CLIENT: EventObjectOwner = EventObjectOwner::new(42, 9);
const NATIVE: u64 = 101;

fn local(kind: EventKind, signaled: bool) -> (EventObjectRegistry, EventStore, EventObjectId) {
    let mut registry = EventObjectRegistry::new();
    let id = registry
        .create_provider_local(PROVIDER, 11, NATIVE)
        .unwrap();
    let mut events = EventStore::new();
    events.initialize(NATIVE, kind, signaled);
    (registry, events, id)
}

#[test]
fn ready_and_consume_preserve_event_kind_semantics() {
    for kind in [EventKind::Notification, EventKind::Synchronization] {
        for signaled in [false, true] {
            let (mut registry, mut events, id) = local(kind, signaled);
            let lease =
                acquire_provider_local_event_wait(&mut registry, &events, id, PROVIDER).unwrap();
            let snapshot = registry.snapshot(id).unwrap();
            assert_eq!(snapshot.provider_wait_leases, 1);
            assert_eq!(
                provider_event_wait_is_ready(&registry, &events, lease),
                Ok(signaled)
            );
            assert_eq!(
                consume_provider_event_wait(&registry, &mut events, lease),
                Ok(signaled)
            );
            assert_eq!(
                events.query_existing(NATIVE),
                Some((kind, signaled && kind == EventKind::Notification))
            );
            assert_eq!(registry.snapshot(id), Ok(snapshot));
            assert_eq!(
                registry.release_wait(lease, EventLeaseKind::ProviderWait),
                Ok(None)
            );
            assert_eq!(registry.live_lease_count(), 0);
        }
    }
}

#[test]
fn missing_backing_refuses_both_admission_paths_without_leases_or_state_changes() {
    let (mut registry, mut events, local) = local(EventKind::Synchronization, true);
    let projected = registry.create(CLIENT, 102).unwrap();
    registry
        .retain_pointer_or_install(projected, 0xD000)
        .unwrap();
    assert!(events.remove_existing(NATIVE));
    events.initialize(103, EventKind::Notification, true);
    let before = [local, projected].map(|id| registry.snapshot(id).unwrap());
    assert_eq!(
        acquire_provider_local_event_wait(&mut registry, &events, local, PROVIDER),
        Err(ProviderEventWaitError::MissingBacking)
    );
    assert_eq!(
        acquire_projected_provider_event_wait(&mut registry, &events, projected, PROVIDER, CLIENT),
        Err(ProviderEventWaitError::MissingBacking)
    );
    for snapshot in before {
        assert_eq!(registry.snapshot(snapshot.id), Ok(snapshot));
    }
    assert_eq!(registry.live_lease_count(), 0);
    assert!(!events.contains(NATIVE));
    assert!(!events.contains(102));
    assert_eq!(
        events.query_existing(103),
        Some((EventKind::Notification, true))
    );
}

#[test]
fn backing_loss_after_admission_is_an_error_not_not_ready() {
    let (mut registry, mut events, id) = local(EventKind::Synchronization, true);
    let lease = acquire_provider_local_event_wait(&mut registry, &events, id, PROVIDER).unwrap();
    let before = registry.snapshot(id).unwrap();
    assert!(events.remove_existing(NATIVE));
    assert_eq!(
        provider_event_wait_is_ready(&registry, &events, lease),
        Err(ProviderEventWaitError::MissingBacking)
    );
    assert_eq!(
        consume_provider_event_wait(&registry, &mut events, lease),
        Err(ProviderEventWaitError::MissingBacking)
    );
    assert!(!events.contains(NATIVE));
    assert_eq!(registry.snapshot(id), Ok(before));
    assert_eq!(registry.live_lease_count(), 1);
    assert_eq!(
        registry.release_wait(lease, EventLeaseKind::ProviderWait),
        Ok(None)
    );
}

#[test]
fn readiness_and_consumption_reject_wrong_kind_null_and_recycled_leases() {
    let (mut registry, mut events, id) = local(EventKind::Synchronization, true);
    for kind in [
        EventLeaseKind::NativeWait,
        EventLeaseKind::GuiWait,
        EventLeaseKind::Operation,
    ] {
        let wrong = registry.acquire_wait(id, kind).unwrap();
        let before = registry.snapshot(id).unwrap();
        let error = Err(ProviderEventWaitError::Registry(
            EventObjectError::WrongLeaseKind,
        ));
        assert_eq!(
            provider_event_wait_is_ready(&registry, &events, wrong),
            error
        );
        assert_eq!(
            consume_provider_event_wait(&registry, &mut events, wrong),
            error
        );
        assert_eq!(registry.snapshot(id), Ok(before));
        assert_eq!(registry.release_wait(wrong, kind), Ok(None));
    }
    let stale = acquire_provider_local_event_wait(&mut registry, &events, id, PROVIDER).unwrap();
    registry
        .release_wait(stale, EventLeaseKind::ProviderWait)
        .unwrap();
    let current = acquire_provider_local_event_wait(&mut registry, &events, id, PROVIDER).unwrap();
    assert_ne!(stale, current);
    for rejected in [EventLeaseId::NULL, stale] {
        let error = Err(ProviderEventWaitError::Registry(
            EventObjectError::StaleLease,
        ));
        assert_eq!(
            provider_event_wait_is_ready(&registry, &events, rejected),
            error
        );
        assert_eq!(
            consume_provider_event_wait(&registry, &mut events, rejected),
            error
        );
    }
    assert_eq!(
        events.query_existing(NATIVE),
        Some((EventKind::Synchronization, true))
    );
    assert_eq!(registry.live_lease_count(), 1);
    assert_eq!(
        consume_provider_event_wait(&registry, &mut events, current),
        Ok(true)
    );
}

#[test]
fn local_admission_rejects_foreign_owner_nonlocal_and_stale_identity() {
    let (mut registry, mut events, id) = local(EventKind::Notification, false);
    let nonlocal = registry.create(PROVIDER, 102).unwrap();
    events.initialize(102, EventKind::Notification, true);
    let snapshots = [id, nonlocal].map(|id| registry.snapshot(id).unwrap());
    for (target, owner, error) in [
        (id, CLIENT, EventObjectError::InvalidOwner),
        (
            id,
            EventObjectOwner::provider(0, 3),
            EventObjectError::InvalidOwner,
        ),
        (
            id,
            EventObjectOwner::provider(7, 0),
            EventObjectError::InvalidOwner,
        ),
        (
            id,
            EventObjectOwner::provider(7, 4),
            EventObjectError::InvalidOwner,
        ),
        (
            id,
            EventObjectOwner::provider(8, 3),
            EventObjectError::InvalidOwner,
        ),
        (
            nonlocal,
            PROVIDER,
            EventObjectError::InvalidProviderIdentity,
        ),
        (EventObjectId::NULL, PROVIDER, EventObjectError::StaleObject),
    ] {
        assert_eq!(
            acquire_provider_local_event_wait(&mut registry, &events, target, owner),
            Err(error.into())
        );
        assert_eq!(registry.live_lease_count(), 0);
        for snapshot in snapshots {
            assert_eq!(registry.snapshot(snapshot.id), Ok(snapshot));
        }
    }
}

#[test]
fn deleting_local_event_closes_admission_but_preserves_existing_wait() {
    let (mut registry, mut events, id) = local(EventKind::Synchronization, true);
    let lease = acquire_provider_local_event_wait(&mut registry, &events, id, PROVIDER).unwrap();
    assert_eq!(registry.request_delete(id), Ok(None));
    let before = registry.snapshot(id).unwrap();
    assert_eq!(
        acquire_provider_local_event_wait(&mut registry, &events, id, PROVIDER),
        Err(EventObjectError::StaleObject.into())
    );
    assert_eq!(registry.snapshot(id), Ok(before));
    assert_eq!(
        provider_event_wait_is_ready(&registry, &events, lease),
        Ok(true)
    );
    assert_eq!(
        consume_provider_event_wait(&registry, &mut events, lease),
        Ok(true)
    );
    let retired = registry
        .release_wait(lease, EventLeaseKind::ProviderWait)
        .unwrap()
        .unwrap();
    assert_eq!(retired.id, id);
    assert_eq!(retired.native_identity, NATIVE);
    assert_eq!(registry.live_lease_count(), 0);
}

#[test]
fn projected_admission_requires_exact_client_valid_provider_and_retained_pointer() {
    let (mut registry, mut events, local) = local(EventKind::Notification, true);
    let projected = registry.create(CLIENT, 102).unwrap();
    events.initialize(102, EventKind::Notification, true);
    registry
        .retain_pointer_or_install(projected, 0xD000)
        .unwrap();
    for (target, provider, client) in [
        (local, PROVIDER, CLIENT),
        (projected, CLIENT, CLIENT),
        (projected, EventObjectOwner::provider(0, 3), CLIENT),
        (projected, EventObjectOwner::provider(7, 0), CLIENT),
        (projected, PROVIDER, PROVIDER),
        (projected, PROVIDER, EventObjectOwner::new(42, 10)),
        (projected, PROVIDER, EventObjectOwner::new(43, 9)),
        (projected, PROVIDER, EventObjectOwner::new(0, 9)),
    ] {
        let before = registry.snapshot(target).unwrap();
        assert_eq!(
            acquire_projected_provider_event_wait(&mut registry, &events, target, provider, client),
            Err(EventObjectError::InvalidOwner.into())
        );
        assert_eq!(registry.snapshot(target), Ok(before));
        assert_eq!(registry.live_lease_count(), 0);
    }
    assert_eq!(registry.release_pointer_by_body(0xD000), Ok(None));
    assert_eq!(
        acquire_projected_provider_event_wait(&mut registry, &events, projected, PROVIDER, CLIENT),
        Err(EventObjectError::InvalidOwner.into())
    );
    assert_eq!(
        events.query_existing(102),
        Some((EventKind::Notification, true))
    );
}

#[test]
fn projected_event_remains_waitable_after_last_handle_closes() {
    let mut registry = EventObjectRegistry::new();
    let mut events = EventStore::new();
    let id = registry.create(CLIENT, NATIVE).unwrap();
    events.initialize(NATIVE, EventKind::Synchronization, true);
    registry.retain_handle(id).unwrap();
    registry.retain_pointer_or_install(id, 0xD000).unwrap();
    assert_eq!(registry.request_delete(id), Ok(None));
    assert_eq!(registry.release_handle(id), Ok(None));
    let lease = acquire_projected_provider_event_wait(&mut registry, &events, id, PROVIDER, CLIENT)
        .unwrap();
    assert_eq!(registry.release_pointer_by_body(0xD000), Ok(None));
    assert_eq!(
        provider_event_wait_is_ready(&registry, &events, lease),
        Ok(true)
    );
    assert_eq!(
        consume_provider_event_wait(&registry, &mut events, lease),
        Ok(true)
    );
    let retired = registry
        .release_wait(lease, EventLeaseKind::ProviderWait)
        .unwrap()
        .unwrap();
    assert_eq!(retired.id, id);
    assert_eq!(retired.provider_body, Some(0xD000));
    assert_eq!(registry.live_lease_count(), 0);
}
