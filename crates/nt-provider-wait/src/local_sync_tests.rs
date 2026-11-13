use super::*;
use crate::{LaneHandle, SuspensionHostedClient};

fn provider() -> ProviderDomainIdentity {
    ProviderDomainIdentity {
        domain: 5,
        generation: 8,
    }
}

fn hosted(tid: u64, dispatch_id: u64) -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: 5,
        provider_generation: 8,
        dispatch_id,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 4,
            client_generation: 2,
            client_tid: tid,
            client_badge: 11,
        }),
    }
}

#[test]
fn semaphore_selection_consumes_once_and_enforces_limit() {
    let mut catalog = ProviderLocalSyncCatalog::new(provider()).unwrap();
    assert!(catalog.is_empty());
    let object = catalog
        .publish(
            0x1000,
            ProviderSyncKind::Semaphore {
                initial_count: 1,
                limit: 2,
            },
        )
        .unwrap();
    assert_eq!(catalog.active_count(), 1);
    assert_eq!(
        catalog.validate_domain_retirement(),
        Err(ProviderLocalSyncError::ActiveObjects)
    );
    let lease = catalog.acquire_wait(hosted(41, 1), object).unwrap();
    assert_eq!(catalog.is_ready(lease), Ok(true));
    assert_eq!(catalog.consume_ready(lease), Ok(true));
    assert_eq!(catalog.is_ready(lease), Ok(false));
    assert_eq!(catalog.release_semaphore(0x1000, 2), Ok(0));
    assert_eq!(
        catalog.release_semaphore(0x1000, 1),
        Err(ProviderLocalSyncError::CountLimit)
    );
    assert_eq!(
        catalog.retire_local(0x1000),
        Err(ProviderLocalSyncError::ActiveLeases)
    );
    catalog.release_wait(lease).unwrap();
    assert_eq!(
        catalog.release_wait(lease),
        Err(ProviderLocalSyncError::WrongLease)
    );
    catalog.retire_local(0x1000).unwrap();
    assert!(catalog.is_empty());
    assert_eq!(catalog.validate_domain_retirement(), Ok(()));
}

#[test]
fn mutant_keeps_owner_across_dispatches_and_blocks_other_caller() {
    let mut catalog = ProviderLocalSyncCatalog::new(provider()).unwrap();
    let object = catalog.publish(0x2000, ProviderSyncKind::Mutant).unwrap();
    let first = catalog.acquire_wait(hosted(41, 1), object).unwrap();
    let other = catalog.acquire_wait(hosted(42, 2), object).unwrap();
    assert_eq!(catalog.consume_ready(first), Ok(true));
    assert_eq!(catalog.consume_ready(first), Ok(true));
    assert_eq!(
        catalog.snapshot_for_canonical(object).unwrap().signal_state,
        -1
    );
    assert_eq!(catalog.is_ready(other), Ok(false));
    assert_eq!(
        catalog.release_mutant(0x2000, hosted(42, 3)),
        Err(ProviderLocalSyncError::WrongCaller)
    );
    assert_eq!(catalog.release_mutant(0x2000, hosted(41, 3)), Ok(-1));
    assert_eq!(catalog.release_mutant(0x2000, hosted(41, 4)), Ok(0));
    assert_eq!(catalog.is_ready(other), Ok(true));
    catalog.release_wait(first).unwrap();
    catalog.release_wait(other).unwrap();
    catalog.retire_local(0x2000).unwrap();
}

#[test]
fn storage_generation_and_live_leases_fence_retirement() {
    let mut catalog = ProviderLocalSyncCatalog::new(provider()).unwrap();
    let id = catalog
        .initialize_stack(0x3000, 3, 4, 5, 6, 0x20, ProviderSyncKind::Mutant)
        .unwrap();
    let canonical = ProviderWaitObject::new(ProviderWaitObjectType::Mutant, 12, 2);
    catalog.bind_canonical(id, canonical).unwrap();
    let lease = catalog.acquire_operation(id).unwrap();
    let backing = catalog.snapshot(id).unwrap().storage.backing;
    assert_eq!(
        catalog.validate_backing_retirement(backing),
        Err(ProviderLocalSyncError::ActiveLeases)
    );
    catalog.release_operation(lease).unwrap();
    let retirement = catalog.begin_retire_backing(backing).unwrap()[0];
    catalog.ack_retirement(retirement).unwrap();
    assert_eq!(
        catalog.snapshot(id),
        Err(ProviderLocalSyncError::StaleIdentity)
    );
    let newer = catalog
        .initialize_stack(0x3000, 3, 4, 5, 7, 0x20, ProviderSyncKind::Mutant)
        .unwrap();
    assert_ne!(id, newer);
    assert_eq!(
        catalog.acquire_operation(id),
        Err(ProviderLocalSyncError::StaleIdentity)
    );
    let kernel = ProviderWaitOwner {
        provider_domain: 5,
        provider_generation: 8,
        dispatch_id: 9,
        caller: SuspensionCaller::Kernel {
            lane: LaneHandle {
                index: 2,
                generation: 1,
            },
        },
    };
    assert!(kernel.is_valid());
}

#[test]
fn canonical_generation_and_physical_storage_are_both_required() {
    let mut catalog = ProviderLocalSyncCatalog::new(provider()).unwrap();
    let first = catalog
        .initialize_stack(
            0x4000,
            3,
            4,
            5,
            6,
            0x20,
            ProviderSyncKind::Semaphore {
                initial_count: 0,
                limit: 1,
            },
        )
        .unwrap();
    let canonical = ProviderWaitObject::new(ProviderWaitObjectType::Semaphore, 18, 7);
    catalog.bind_canonical(first, canonical).unwrap();
    assert_eq!(
        catalog.initialize_stack(0x4000, 3, 4, 5, 6, 0x30, ProviderSyncKind::Mutant),
        Err(ProviderLocalSyncError::AddressInUse)
    );
    assert_eq!(
        catalog.initialize_stack(0x5000, 3, 4, 5, 6, 0x20, ProviderSyncKind::Mutant),
        Err(ProviderLocalSyncError::StorageInUse)
    );
    let stale = ProviderWaitObject::new(ProviderWaitObjectType::Semaphore, 18, 6);
    assert_eq!(
        catalog.acquire_wait(hosted(41, 1), stale),
        Err(ProviderLocalSyncError::NotFound)
    );
    let foreign = ProviderWaitOwner {
        provider_generation: 9,
        ..hosted(41, 1)
    };
    assert_eq!(
        catalog.acquire_wait(foreign, canonical),
        Err(ProviderLocalSyncError::InvalidProvider)
    );
    assert_eq!(
        catalog.snapshot_for_body(0x5000),
        Err(ProviderLocalSyncError::NotFound)
    );
}

#[test]
fn uncertain_retirement_keeps_identity_and_backing_reserved() {
    let mut catalog = ProviderLocalSyncCatalog::new(provider()).unwrap();
    let id = catalog
        .initialize_stack(
            0x6000,
            2,
            4,
            7,
            9,
            0x18,
            ProviderSyncKind::Semaphore {
                initial_count: 0,
                limit: 2,
            },
        )
        .unwrap();
    let canonical = ProviderWaitObject::new(ProviderWaitObjectType::Semaphore, 24, 3);
    catalog.bind_canonical(id, canonical).unwrap();
    let retirement = catalog.begin_retire_sync(id).unwrap();
    let wrong = ProviderLocalSyncRetirement {
        canonical: ProviderWaitObject::new(ProviderWaitObjectType::Semaphore, 24, 4),
        ..retirement
    };
    assert_eq!(
        catalog.ack_retirement(wrong),
        Err(ProviderLocalSyncError::RetirementMismatch)
    );
    assert_eq!(
        catalog.acquire_wait(hosted(41, 2), canonical),
        Err(ProviderLocalSyncError::NotFound)
    );
    assert_eq!(
        catalog.initialize_stack(0x6000, 2, 4, 7, 9, 0x18, ProviderSyncKind::Mutant),
        Err(ProviderLocalSyncError::AddressInUse)
    );
    assert_eq!(
        catalog.begin_retire_sync(id),
        Err(ProviderLocalSyncError::DeletePending)
    );
    catalog.ack_retirement(retirement).unwrap();
    let next = catalog
        .initialize_stack(0x6000, 2, 4, 7, 10, 0x18, ProviderSyncKind::Mutant)
        .unwrap();
    assert_ne!(id, next);
}

#[test]
fn bound_snapshot_reflects_selected_waiter_and_rejects_stale_generation() {
    let mut catalog = ProviderLocalSyncCatalog::new(provider()).unwrap();
    let object = catalog.publish(0x7000, ProviderSyncKind::Semaphore {
        initial_count: 0, limit: 2,
    }).unwrap();
    let waiter = catalog.acquire_wait(hosted(41, 1), object).unwrap();
    assert_eq!(catalog.release_semaphore(0x7000, 1), Ok(0));
    assert_eq!(catalog.consume_ready(waiter), Ok(true));
    assert_eq!(catalog.snapshot_bound(0x7000, object).unwrap().signal_state, 0);
    assert_eq!(catalog.snapshot_bound(0x7000,
        ProviderWaitObject::new(ProviderWaitObjectType::Semaphore,
            object.object_id, object.object_generation + 1)),
        Err(ProviderLocalSyncError::StaleIdentity));
    catalog.release_wait(waiter).unwrap();

    let mutant = catalog.publish(0x7100, ProviderSyncKind::Mutant).unwrap();
    let owner = catalog.acquire_wait(hosted(42, 2), mutant).unwrap();
    assert_eq!(catalog.consume_ready(owner), Ok(true));
    let selected = catalog.snapshot_bound(0x7100, mutant).unwrap();
    assert_eq!(selected.signal_state, 0);
    assert_eq!(selected.mutant_owner, Some(hosted(42, 2).caller));
    assert_eq!(catalog.release_mutant(0x7100, hosted(42, 3)), Ok(0));
    let released = catalog.snapshot_bound(0x7100, mutant).unwrap();
    assert_eq!(released.signal_state, 1);
    assert_eq!(released.mutant_owner, None);
}

#[test]
fn root_catalog_publishes_adjacent_opaque_local_ids_without_physical_overlap() {
    let mut catalog = ProviderLocalSyncCatalog::new(provider()).unwrap();
    let first = catalog.publish(0x0000_0001_0000_0001, ProviderSyncKind::Mutant).unwrap();
    let second = catalog.publish(0x0000_0001_0000_0002, ProviderSyncKind::Mutant).unwrap();
    assert_ne!(first, second);
    assert_eq!(catalog.snapshot_for_body(0x0000_0001_0000_0001).unwrap().canonical, Some(first));
    assert_eq!(catalog.snapshot_for_body(0x0000_0001_0000_0002).unwrap().canonical, Some(second));
    catalog.retire_local(0x0000_0001_0000_0001).unwrap();
    let reused = catalog.publish(0x0000_0002_0000_0001, ProviderSyncKind::Semaphore {
        initial_count: 0, limit: 1,
    }).unwrap();
    assert_eq!(reused.object_id, first.object_id);
    assert!(reused.object_generation > first.object_generation);
    assert_eq!(catalog.snapshot_for_body(0x0000_0001_0000_0002).unwrap().canonical, Some(second));
    assert_eq!(catalog.snapshot_bound(0x0000_0002_0000_0001, first),
        Err(ProviderLocalSyncError::StaleIdentity));
}
