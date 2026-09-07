use super::*;
use crate::process_identity::ProcessGeneration;
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
    let snapshot = state
        .reconcile(id, &resources, &progress, &registry)
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
            .reconcile(id, &resources, &progress, &registry)
            .unwrap()
    ));
}

#[test]
fn missing_published_page_is_not_inferred_away_and_preparation_can_retry() {
    let (resources, progress, mut registry) = fixture();
    registry.take(7, 0x5000).unwrap();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    assert!(matches!(
        state.reconcile(id, &resources, &progress, &registry),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::MissingRecord { page: 0x5000 }
        ))
    ));
    assert!(!state.is_prepared());
    registry.insert(7, 0x5000, 21, 0, 22, 23, false).unwrap();
    assert!(state
        .reconcile(id, &resources, &progress, &registry)
        .is_ok());
}

#[test]
fn changed_registry_never_replaces_a_prepared_snapshot() {
    let (resources, progress, mut registry) = fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    let original = state
        .reconcile(id, &resources, &progress, &registry)
        .unwrap()
        .records()
        .to_vec();
    registry.take(7, 0x5000).unwrap();
    registry.insert(7, 0x5000, 21, 0, 24, 25, false).unwrap();
    for _ in 0..3 {
        assert!(matches!(
            state.reconcile(id, &resources, &progress, &registry),
            Err(ReconciliationError::Registry(
                ThreadRegistryError::StaleRecord { page: 0x5000 }
            ))
        ));
        assert_eq!(state.prepared.get().unwrap().snapshot.records(), original);
    }
}

#[test]
fn another_attempt_or_changed_publication_coverage_is_rejected() {
    let (resources, mut progress, registry) = fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    state
        .reconcile(id, &resources, &progress, &registry)
        .unwrap();
    assert!(matches!(
        state.reconcile(attempt(), &resources, &progress, &registry),
        Err(ReconciliationError::AttemptChanged)
    ));
    progress.record_teb(1);
    assert!(matches!(
        state.reconcile(id, &resources, &progress, &registry),
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
        assert!(
            matches!(state.reconcile(attempt(), &resources, &progress, &registry),
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
    assert!(matches!(
        state.reconcile(
            attempt(),
            &resources,
            &progress,
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
        state
            .reconcile(id, &resources, &progress, &registry)
            .unwrap();
        registry.insert(pi, page, frame, 0, 0, 0, false).unwrap();
        let error = state
            .reconcile(id, &resources, &progress, &registry)
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
    let (resources, mut progress, registry) = fixture();
    let state = ThreadRegistryReconciliation::empty();
    let id = attempt();
    state
        .reconcile(id, &resources, &progress, &registry)
        .unwrap();
    progress.retain_empty_slot(99).unwrap();
    assert!(matches!(
        state.reconcile(id, &resources, &progress, &registry),
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
    let registry = ClientFrameRegistry::new();
    let snapshot = state
        .reconcile(id, &resources, &progress, &registry)
        .unwrap();
    assert!(snapshot.records().is_empty() && snapshot.rollback_resources().is_empty());
    progress.record_protected_tail();
    assert!(matches!(
        state.reconcile(id, &resources, &progress, &registry),
        Err(ReconciliationError::ProgressChanged)
    ));
}
