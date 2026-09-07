use super::*;
use nt_memory_manager::ClientFrameRegistry;
use nt_user_host::thread_reconciliation::{ReconciliationError, ThreadRegistryReconciliation};
use nt_user_host::thread_registry::{ThreadRegistryError, ThreadRegistrySnapshot};

fn retained(tcb: Option<u64>, built: bool) -> (Slot, ThreadRollbackId, Rc<Cell<usize>>) {
    let (mut slot, ticket, mut partial, drops) = fixture(tcb, built);
    partial.memory_progress.retain_empty_slot(601).unwrap();
    if built {
        partial.memory_progress.record_stack(0);
    }
    let id = without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap();
    (slot, id, drops)
}

fn reconcile<'a>(
    slot: &'a Slot,
    registry: &ClientFrameRegistry,
) -> Result<&'a ThreadRegistrySnapshot<2>, ReconciliationError> {
    let pending = slot.pending().unwrap();
    let runtime = pending.runtime();
    runtime.reconciliation.reconcile(
        pending.id(),
        &runtime.partial.as_ref().unwrap().memory,
        &runtime.coverage,
        pending.construction_retirement().unwrap(),
        registry,
    )
}

#[test]
fn empty_memory_slot_alone_blocks_cleanup_until_checked_recycling() {
    let (mut slot, id, drops) = retained(None, false);
    let mut backend = Backend {
        current: id,
        events: Vec::with_capacity(1),
        fail: Some(0),
    };
    assert_eq!(slot.owner().unwrap().coverage.empty_slot(), Some(601));
    assert!(slot
        .owner()
        .unwrap()
        .partial
        .as_ref()
        .unwrap()
        .memory_progress
        .is_empty());
    for _ in 0..3 {
        assert_eq!(
            without_allocation(|| slot.advance_construction_retirement(id, &mut backend)),
            Err(SlotError::Retirement(RetirementError::MemoryRecycle {
                status: 0xc000009a
            }))
        );
        assert_eq!(
            slot.prepare_cleanup(id, &[]),
            Err(SlotError::Cleanup(ThreadRollbackError::ConstructionPending))
        );
        assert_eq!(
            slot.pending()
                .unwrap()
                .construction_retirement()
                .unwrap()
                .pending_memory_slot(),
            Some(601)
        );
        assert!(backend.events.is_empty());
        assert_protected(&mut slot, id);
        assert_eq!(drops.get(), 0);
    }
    backend.fail = None;
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    assert_eq!(backend.events, [Event::MemoryRecycle(601)]);
    assert_eq!(slot.owner().unwrap().coverage.empty_slot(), Some(601));
    assert!(slot
        .pending()
        .unwrap()
        .construction_retirement()
        .unwrap()
        .is_complete());
    assert_protected(&mut slot, id);
}

#[test]
fn memory_slot_retry_does_not_repeat_mechanism_retirement() {
    let (mut slot, id, drops) = retained(Some(400), true);
    let mut backend = Backend {
        current: id,
        events: Vec::with_capacity(4),
        fail: Some(3),
    };
    for _ in 0..3 {
        assert_eq!(
            without_allocation(|| slot.advance_construction_retirement(id, &mut backend)),
            Err(SlotError::Retirement(RetirementError::MemoryRecycle {
                status: 0xc000009a
            }))
        );
        assert_eq!(
            backend.events,
            [Event::Suspend(400), Event::Delete(400), Event::Recycle(400)]
        );
        assert_protected(&mut slot, id);
        assert_eq!(drops.get(), 0);
    }
    backend.fail = None;
    slot.advance_construction_retirement(id, &mut backend)
        .unwrap();
    assert_eq!(
        backend.events,
        [
            Event::Suspend(400),
            Event::Delete(400),
            Event::Recycle(400),
            Event::MemoryRecycle(601)
        ]
    );
}

#[test]
fn contradictory_memory_slot_returns_ticket_and_all_owners_before_handoff() {
    for cap in [100, 200, 400, 500] {
        let (mut slot, ticket, mut partial, drops) = fixture(Some(400), true);
        partial
            .inventory
            .adopt_empty(ConstructionRole::RawCnode, 500)
            .unwrap();
        partial.memory_progress.retain_empty_slot(cap).unwrap();
        let (error, ticket, partial) =
            without_allocation(|| slot.retain_failed_construction(ticket, partial)).unwrap_err();
        assert_eq!(
            error,
            SlotError::Cleanup(ThreadRollbackError::ConflictingOwnership)
        );
        assert!(slot.publishing_mut(&ticket).is_some());
        assert_eq!(partial.memory_progress.empty_slot(), Some(cap));
        assert_eq!(partial.inventory.live_tcb(), Some(400));
        assert_eq!(partial.memory.stack_owner[0], 200);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn foreign_attempt_cannot_recycle_or_supply_reconciliation_phase() {
    let (mut slot, id, drops) = retained(None, false);
    let (other, foreign, _) = retained(None, false);
    let mut backend = Backend {
        current: foreign,
        events: vec![],
        fail: None,
    };
    assert_eq!(
        slot.advance_construction_retirement(foreign, &mut backend),
        Err(SlotError::OwnerChanged)
    );
    assert_eq!(
        slot.advance_construction_retirement(id, &mut backend),
        Err(SlotError::Retirement(RetirementError::StaleOwner))
    );
    let runtime = slot.owner().unwrap();
    assert!(matches!(
        runtime.reconciliation.reconcile(
            id,
            &runtime.partial.as_ref().unwrap().memory,
            &runtime.coverage,
            other.pending().unwrap().construction_retirement().unwrap(),
            &ClientFrameRegistry::new()
        ),
        Err(ReconciliationError::AttemptChanged)
    ));
    assert!(!runtime.reconciliation.is_prepared());
    assert!(backend.events.is_empty());
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn recycled_slot_reuse_elsewhere_preserves_original_snapshot_but_not_stale_rows() {
    let (mut slot, id, _) = retained(None, true);
    let mut registry = ClientFrameRegistry::new();
    registry.insert(2, 0x1000, 200, 0, 201, 202, false).unwrap();
    registry.insert(3, 0xa000, 601, 0, 0, 0, false).unwrap();
    assert!(matches!(
        reconcile(&slot, &registry),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::SharedCapability { cap: 601 }
        ))
    ));
    assert!(!slot.owner().unwrap().reconciliation.is_prepared());
    registry.take(3, 0xa000).unwrap();
    let original = reconcile(&slot, &registry).unwrap() as *const _;
    let mut backend = Backend {
        current: id,
        events: Vec::with_capacity(1),
        fail: Some(0),
    };
    assert!(slot
        .advance_construction_retirement(id, &mut backend)
        .is_err());
    assert_eq!(
        without_allocation(|| reconcile(&slot, &registry)).unwrap() as *const _,
        original
    );
    backend.fail = None;
    slot.advance_construction_retirement(id, &mut backend)
        .unwrap();
    registry.insert(3, 0xa000, 601, 0, 0, 0, false).unwrap();
    assert_eq!(
        without_allocation(|| reconcile(&slot, &registry)).unwrap() as *const _,
        original
    );
    registry.take(2, 0x1000).unwrap();
    assert!(matches!(
        without_allocation(|| reconcile(&slot, &registry)),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::StaleRecord { page: 0x1000 }
        ))
    ));
    assert!(slot.owner().unwrap().reconciliation.is_prepared());
    assert_eq!(backend.events, [Event::MemoryRecycle(601)]);
}

#[test]
fn recycled_slot_never_becomes_selected_memory_or_generic_cleanup_authority() {
    let (mut slot, id, _) = retained(None, false);
    let mut backend = Backend {
        current: id,
        events: Vec::with_capacity(1),
        fail: None,
    };
    slot.advance_construction_retirement(id, &mut backend)
        .unwrap();
    for kind in [Kind::Alias, Kind::Frame, Kind::Mechanism] {
        assert_eq!(
            without_allocation(
                || slot.prepare_cleanup(id, &[ThreadRollbackResource { cap: 601, kind }])
            ),
            Err(SlotError::Cleanup(
                ThreadRollbackError::ConflictingOwnership
            ))
        );
    }
    let runtime = slot.owner().unwrap();
    let mut resources = runtime.partial.as_ref().unwrap().memory;
    resources.stack_owner[0] = 601;
    let state = ThreadRegistryReconciliation::empty();
    assert!(matches!(
        state.reconcile(
            id,
            &resources,
            &runtime.coverage,
            slot.pending().unwrap().construction_retirement().unwrap(),
            &ClientFrameRegistry::new()
        ),
        Err(ReconciliationError::Registry(
            ThreadRegistryError::SharedCapability { cap: 601 }
        ))
    ));
    assert!(!state.is_prepared());
    assert_protected(&mut slot, id);
}

#[test]
fn journal_oom_after_empty_slot_recycling_never_reconstructs_ownership() {
    let (mut slot, id, _) = retained(None, true);
    let resources = slot
        .owner()
        .unwrap()
        .partial
        .as_ref()
        .unwrap()
        .memory
        .rollback_resources()
        .unwrap();
    let mut backend = Backend {
        current: id,
        events: Vec::with_capacity(1),
        fail: None,
    };
    slot.advance_construction_retirement(id, &mut backend)
        .unwrap();
    FAIL_ALLOCATIONS.with(|flag| flag.set(true));
    let failure = slot.prepare_cleanup(id, &resources);
    FAIL_ALLOCATIONS.with(|flag| flag.set(false));
    assert_eq!(
        failure,
        Err(SlotError::Cleanup(
            ThreadRollbackError::InsufficientResources
        ))
    );
    assert_protected(&mut slot, id);
    slot.prepare_cleanup(id, &resources).unwrap();
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    assert_eq!(backend.events, [Event::MemoryRecycle(601)]);
    assert_eq!(slot.owner().unwrap().coverage.empty_slot(), Some(601));
    assert_eq!(
        slot.pending()
            .unwrap()
            .construction_retirement()
            .unwrap()
            .pending_memory_slot(),
        None
    );
}
