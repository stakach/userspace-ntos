use super::*;
use crate::process_identity::ProcessGeneration;
use crate::thread_construction::{MemoryConstructionProgress, ThreadConstructionInventory};
use crate::thread_resources::ThreadMemoryLayout;
use crate::thread_rollback::{new_rollback_id, ThreadRollbackIdentity};

fn attempt() -> ThreadRollbackId {
    new_rollback_id(ThreadRollbackIdentity {
        pi: 7,
        pid: 28,
        tid: 99,
        process_generation: ProcessGeneration::Hosted(2),
    })
    .unwrap()
}

fn seal<const STACK: usize>(
    progress: MemoryConstructionProgress<STACK>,
    id: ThreadRollbackId,
) -> (MemoryConstructionCoverage<STACK>, ThreadMechanismRetirement) {
    let (coverage, slot) = progress.into_retained();
    (
        coverage,
        ThreadMechanismRetirement::retain(id, ThreadConstructionInventory::empty(), slot),
    )
}

fn fixture() -> (
    ThreadMemoryResources<2>,
    MemoryConstructionProgress<2>,
    ClientFrameRegistry,
) {
    let mut resources = ThreadMemoryResources::new(
        7,
        ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x5000, 0x9000).unwrap(),
    )
    .unwrap();
    resources.stack_owner[0] = 10;
    resources.stack_target[0] = 11;
    resources.teb_owner = 20;
    resources.teb_target = 21;
    let mut progress = MemoryConstructionProgress::empty();
    progress.record_stack(0);
    progress.record_teb(0);
    let mut registry = ClientFrameRegistry::new();
    registry.insert(7, 0x1000, 10, 0, 12, 13, false).unwrap();
    registry.insert(7, 0x5000, 21, 0, 22, 23, false).unwrap();
    (resources, progress, registry)
}

#[test]
fn partial_coverage_captures_registry_only_aliases_without_transferring_rows() {
    let (resources, progress, registry) = fixture();
    let records = registry.records().to_vec();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let (progress, retirement) = seal(progress, id);
    let snapshot = state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .unwrap();
    assert!(state.is_prepared());
    assert_eq!(snapshot.records(), records);
    for cap in [12, 13, 22, 23] {
        assert!(snapshot
            .rollback_resources()
            .iter()
            .any(|resource| resource.cap == cap));
    }
    assert_eq!(registry.records(), records);
    assert!(core::ptr::eq(
        snapshot,
        state
            .reconcile(id, &resources, &progress, &retirement, &registry)
            .unwrap()
    ));
}

#[test]
fn exact_provenance_survives_transfer_without_revalidating_recycled_cap_numbers() {
    let (resources, progress, mut registry) = fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    assert!(state.retained_snapshot(id).is_err());
    let (progress, retirement) = seal(progress, id);
    let snapshot = state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .unwrap();
    let transfer = snapshot
        .prepare_transfer(&resources, &mut registry)
        .unwrap()
        .unwrap();
    let cleared =
        ThreadMemoryResources::new(resources.client_pi, resources.layout().unwrap()).unwrap();
    assert!(snapshot.matches_resources(&resources));
    assert!(!snapshot.matches_resources(&cleared));
    assert!(state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .is_err());
    registry.finish_transfer(transfer).unwrap();
    registry.insert(8, 0xa000, 10, 0, 12, 13, false).unwrap();
    assert!(core::ptr::eq(
        snapshot,
        state.retained_snapshot(id).unwrap()
    ));
    assert!(state.retained_snapshot(attempt()).is_err());
    assert_eq!(registry.get(8, 0xa000).unwrap().frame, 10);
}

#[test]
fn missing_published_page_is_not_inferred_away_and_preparation_can_retry() {
    let (resources, progress, mut registry) = fixture();
    registry.take(7, 0x5000).unwrap();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let (progress, retirement) = seal(progress, id);
    assert!(matches!(
        state.reconcile(id, &resources, &progress, &retirement, &registry),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::MissingRecord { page: 0x5000 }
        ))
    ));
    assert!(!state.is_prepared());
    registry.insert(7, 0x5000, 21, 0, 22, 23, false).unwrap();
    assert!(state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .is_ok());
}

#[test]
fn changed_registry_never_replaces_a_prepared_snapshot() {
    let (resources, progress, mut registry) = fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let (progress, retirement) = seal(progress, id);
    let original = state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .unwrap()
        .records()
        .to_vec();
    registry.take(7, 0x5000).unwrap();
    registry.insert(7, 0x5000, 21, 0, 24, 25, false).unwrap();
    for _ in 0..3 {
        assert!(matches!(
            state.reconcile(id, &resources, &progress, &retirement, &registry),
            Err(ReconciliationError::Registry(
                ThreadRegistryError::StaleRecord { page: 0x5000 }
            ))
        ));
        assert_eq!(state.prepared.get().unwrap().snapshot.records(), original);
    }
}

#[test]
fn another_attempt_or_changed_publication_coverage_is_rejected() {
    let (resources, progress, registry) = fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let (progress, retirement) = seal(progress, id);
    state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .unwrap();
    assert!(matches!(
        state.reconcile(attempt(), &resources, &progress, &retirement, &registry),
        Err(ReconciliationError::AttemptChanged)
    ));
    let mut changed = fixture().1;
    changed.record_teb(1);
    let (changed, _) = seal(changed, id);
    assert!(matches!(
        state.reconcile(id, &resources, &changed, &retirement, &registry),
        Err(ReconciliationError::ProgressChanged)
    ));
}

#[test]
fn empty_slot_cannot_be_hidden_in_live_resources_or_registry() {
    for cap in [10, 11, 22, 99] {
        let (resources, mut progress, mut registry) = fixture();
        if cap == 99 {
            registry.insert(8, 0xa000, 90, 0, 0, cap, false).unwrap();
        }
        progress.retain_empty_slot(cap).unwrap();
        let state = ThreadRegistryReconciliation::empty();
        let id = attempt();
        let (progress, retirement) = seal(progress, id);
        assert!(
            matches!(state.reconcile(id, &resources, &progress, &retirement, &registry),
            Err(ReconciliationError::Registry(ThreadRegistryError::SharedCapability { cap: found })) if found == cap)
        );
        assert!(!state.is_prepared());
    }
}

#[test]
fn registration_outside_the_constructed_layout_is_rejected() {
    let resources = ThreadMemoryResources::<2>::new(
        7,
        ThreadMemoryLayout::new(0x1000, 1, 0x4000, 0x5000, 0x9000).unwrap(),
    )
    .unwrap();
    let mut progress = MemoryConstructionProgress::empty();
    progress.record_stack(1);
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let (progress, retirement) = seal(progress, id);
    assert!(matches!(
        state.reconcile(
            id,
            &resources,
            &progress,
            &retirement,
            &ClientFrameRegistry::new()
        ),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::InvalidCoverage
        ))
    ));
}

#[test]
fn new_unselected_rows_and_shared_caps_invalidate_without_refreshing() {
    for (pi, page, frame) in [(7, 0x6000, 99), (8, 0xa000, 10)] {
        let (resources, progress, mut registry) = fixture();
        let state = ThreadRegistryReconciliation::empty();
        let id = attempt();
        let (progress, retirement) = seal(progress, id);
        state
            .reconcile(id, &resources, &progress, &retirement, &registry)
            .unwrap();
        registry.insert(pi, page, frame, 0, 0, 0, false).unwrap();
        let error = state
            .reconcile(id, &resources, &progress, &retirement, &registry)
            .unwrap_err();
        assert_eq!(
            error,
            ReconciliationError::Registry(if pi == 7 {
                ThreadRegistryError::UnexpectedRecord { page }
            } else {
                ThreadRegistryError::SharedCapability { cap: frame }
            })
        );
        assert!(state.is_prepared());
    }
}

#[test]
fn empty_slot_progress_cannot_change_after_snapshot_admission() {
    let (resources, progress, registry) = fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let (progress, retirement) = seal(progress, id);
    state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .unwrap();
    let mut changed = fixture().1;
    changed.retain_empty_slot(99).unwrap();
    let (changed, changed_retirement) = seal(changed, id);
    assert!(matches!(
        state.reconcile(id, &resources, &changed, &changed_retirement, &registry),
        Err(ReconciliationError::ProgressChanged)
    ));
}

#[test]
fn unregistered_empty_construction_has_explicit_empty_snapshot() {
    let resources = ThreadMemoryResources::<2>::new(
        7,
        ThreadMemoryLayout::new(0x1000, 1, 0x4000, 0x5000, 0x9000).unwrap(),
    )
    .unwrap();
    let mut progress = MemoryConstructionProgress::empty();
    progress.retain_empty_slot(99).unwrap();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let (progress, retirement) = seal(progress, id);
    let registry = ClientFrameRegistry::new();
    let snapshot = state
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .unwrap();
    assert!(snapshot.records().is_empty() && snapshot.rollback_resources().is_empty());
    let mut changed = MemoryConstructionProgress::<2>::empty();
    changed.retain_empty_slot(99).unwrap();
    changed.record_teb(0);
    let (changed, _) = seal(changed, id);
    assert!(matches!(
        state.reconcile(id, &resources, &changed, &retirement, &registry),
        Err(ReconciliationError::ProgressChanged)
    ));
}

#[test]
fn coverage_cannot_borrow_another_failed_slots_retirement_phase() {
    let (resources, progress, registry) = fixture();
    let id = attempt();
    let (coverage, retirement) = seal(progress, id);
    let mut changed = fixture().1;
    changed.retain_empty_slot(99).unwrap();
    let (changed_coverage, changed_retirement) = seal(changed, id);
    let state = ThreadRegistryReconciliation::empty();
    assert!(matches!(
        state.reconcile(id, &resources, &coverage, &changed_retirement, &registry),
        Err(ReconciliationError::ProgressChanged)
    ));
    assert!(!state.is_prepared());
    state
        .reconcile(id, &resources, &coverage, &retirement, &registry)
        .unwrap();
    assert!(matches!(
        state.reconcile(id, &resources, &changed_coverage, &retirement, &registry),
        Err(ReconciliationError::ProgressChanged)
    ));
    assert!(state.is_prepared());
}

fn registered_fixture() -> (ThreadMemoryResources<2>, ClientFrameRegistry) {
    let (mut resources, _, registry) = fixture();
    resources.stack_owner[1] = 30;
    resources.stack_target[1] = 31;
    resources.teb2_owner = 40;
    resources.teb2_target = 41;
    resources.acs_owner = 50;
    resources.acs_target = 51;
    resources.ipc_owner = 60;
    resources.tramp_owner = 70;
    resources.tramp_target = 71;
    (resources, registry)
}

#[test]
fn registered_complete_capture_replays_same_page_set_without_construction_evidence() {
    let (resources, registry) = registered_fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let snapshot = state
        .reconcile_registered(id, &resources, &[0x5000, 0x1000], &registry)
        .unwrap();
    assert!(core::ptr::eq(
        snapshot,
        state
            .reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry)
            .unwrap()
    ));
    for cap in [10, 20, 30, 40, 50, 60, 70] {
        assert!(snapshot
            .rollback_resources()
            .iter()
            .any(|entry| entry.cap == cap
                && entry.kind == crate::thread_rollback::ThreadRollbackResourceKind::Frame));
    }
    assert_eq!(registry.records().len(), 2);
}

#[test]
fn registered_capture_requires_complete_physical_ownership_and_exact_coverage() {
    let (mut resources, registry) = registered_fixture();
    let id = attempt();
    for pages in [
        &[0x1000][..],
        &[0x1000, 0x1000][..],
        &[0x1000, 0x5000, 0x6000][..],
    ] {
        let state = ThreadRegistryReconciliation::empty();
        assert!(state
            .reconcile_registered(id, &resources, pages, &registry)
            .is_err());
        assert!(!state.is_prepared());
    }
    resources.acs_owner = 0;
    resources.acs_target = 0;
    let state = ThreadRegistryReconciliation::empty();
    assert!(matches!(
        state.reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::Resources(_)
        ))
    ));
    assert!(!state.is_prepared());
    resources.acs_owner = 50;
    resources.acs_target = 51;
    state
        .reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry)
        .unwrap();
}

#[test]
fn registered_and_construction_preparation_cannot_change_provenance() {
    let (resources, registry) = registered_fixture();
    let id = attempt();
    let (progress, retirement) = seal(fixture().1, id);
    let registered = ThreadRegistryReconciliation::empty();
    registered
        .reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry)
        .unwrap();
    assert!(matches!(
        registered.reconcile(id, &resources, &progress, &retirement, &registry),
        Err(ReconciliationError::ProvenanceChanged)
    ));
    let construction = ThreadRegistryReconciliation::empty();
    construction
        .reconcile(id, &resources, &progress, &retirement, &registry)
        .unwrap();
    assert!(matches!(
        construction.reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry),
        Err(ReconciliationError::ProvenanceChanged)
    ));
}

#[test]
fn registered_retry_rejects_changed_attempt_coverage_resources_and_registry() {
    let (resources, mut registry) = registered_fixture();
    let id = attempt();
    let state = ThreadRegistryReconciliation::empty();
    state
        .reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry)
        .unwrap();
    assert!(matches!(
        state.reconcile_registered(attempt(), &resources, &[0x1000, 0x5000], &registry),
        Err(ReconciliationError::AttemptChanged)
    ));
    for pages in [&[0x1000][..], &[0x1000, 0x1000][..], &[0x1000, 0x6000][..]] {
        assert!(matches!(
            state.reconcile_registered(id, &resources, pages, &registry),
            Err(ReconciliationError::ProgressChanged)
        ));
    }
    let mut changed = resources;
    changed.stack_target[1] = 32;
    assert!(matches!(
        state.reconcile_registered(id, &changed, &[0x1000, 0x5000], &registry),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::StaleResources
        ))
    ));
    registry.take(7, 0x5000).unwrap();
    registry.insert(7, 0x5000, 21, 0, 24, 25, false).unwrap();
    assert!(matches!(
        state.reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::StaleRecord { page: 0x5000 }
        ))
    ));
    assert_eq!(
        state.retained_snapshot(id).unwrap().records()[1].alias_cap,
        22
    );
}

#[test]
fn registered_terminal_provenance_survives_transfer_and_numeric_cap_reuse() {
    let (resources, mut registry) = registered_fixture();
    let id = attempt();
    let state = ThreadRegistryReconciliation::empty();
    let snapshot = state
        .reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry)
        .unwrap();
    let transfer = snapshot
        .prepare_transfer(&resources, &mut registry)
        .unwrap()
        .unwrap();
    assert!(state
        .reconcile_registered(id, &resources, &[0x1000, 0x5000], &registry)
        .is_err());
    registry.finish_transfer(transfer).unwrap();
    registry.insert(8, 0xa000, 10, 0, 12, 13, false).unwrap();
    assert!(core::ptr::eq(
        snapshot,
        state.retained_snapshot(id).unwrap()
    ));
    assert!(state.retained_snapshot(attempt()).is_err());
    assert_eq!(registry.get(8, 0xa000).unwrap().frame, 10);
}

#[test]
fn registered_coverage_is_explicit_even_for_pi_zero_and_empty_registration() {
    let (mut resources, _) = registered_fixture();
    resources.client_pi = 0;
    let mut identity = attempt().identity();
    identity.pi = 0;
    let id = new_rollback_id(identity).unwrap();
    let state = ThreadRegistryReconciliation::empty();
    let mut registry = ClientFrameRegistry::new();
    assert!(matches!(
        state.reconcile_registered(attempt(), &resources, &[], &registry),
        Err(ReconciliationError::AttemptChanged)
    ));
    assert!(!state.is_prepared());
    let snapshot = state
        .reconcile_registered(id, &resources, &[], &registry)
        .unwrap();
    assert!(snapshot.records().is_empty());
    assert!(!snapshot.rollback_resources().is_empty());
    registry.insert(0, 0x1000, 10, 0, 12, 13, false).unwrap();
    assert!(matches!(
        state.reconcile_registered(id, &resources, &[], &registry),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::UnexpectedRecord { page: 0x1000 }
        ))
    ));
    let with_row = ThreadRegistryReconciliation::empty();
    assert_eq!(
        with_row
            .reconcile_registered(id, &resources, &[0x1000], &registry)
            .unwrap()
            .records()
            .len(),
        1
    );
}
