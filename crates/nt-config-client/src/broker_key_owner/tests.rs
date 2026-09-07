use super::*;
use alloc::rc::Rc;
use core::cell::Cell;

#[derive(Debug, Eq, PartialEq)]
struct Target {
    lease: u64,
}

fn target(lease: u64) -> Target {
    Target { lease }
}

fn bound(manager: &mut BrokerKeyOwners, lease: u64) -> BrokerKeyOwner<Target, Option<u64>> {
    let mut owner = manager.reserve_with_metadata(None).unwrap();
    manager.attach(&mut owner, target(lease)).unwrap();
    owner
}

fn activate<C>(manager: &BrokerKeyOwners, owner: &mut BrokerKeyOwner<Target, C>) {
    let mut ticket = manager.begin_publication(owner).unwrap();
    manager.publish(owner, &mut ticket).unwrap();
}

#[test]
fn reserved_and_bound_targets_are_not_queryable_until_exact_publication() {
    let mut manager = BrokerKeyOwners::new();
    let mut owner = manager.reserve().unwrap();
    assert_eq!(owner.phase(), BrokerKeyPhase::Reserved);
    assert_eq!(
        manager.active_target(&owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    manager.attach(&mut owner, target(7)).unwrap();
    assert_eq!(owner.phase(), BrokerKeyPhase::BoundUnpublished);
    assert_eq!(
        manager.active_target(&owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    let mut ticket = manager.begin_publication(&mut owner).unwrap();
    assert!(matches!(
        manager.begin_publication(&mut owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    assert!(matches!(
        manager.begin_close(&mut owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    manager.publish(&mut owner, &mut ticket).unwrap();
    assert_eq!(owner.phase(), BrokerKeyPhase::Active);
    assert_eq!(manager.active_target(&owner), Ok(&target(7)));
    assert_eq!(
        manager.publish(&mut owner, &mut ticket),
        Err(BrokerKeyOwnerError::StaleTicket)
    );
}

#[test]
fn failed_publication_retains_unpublished_target_for_cleanup() {
    let mut manager = BrokerKeyOwners::new();
    let mut owner = bound(&mut manager, 7);
    let mut publication = manager.begin_publication(&mut owner).unwrap();
    manager
        .cancel_publication(&mut owner, &mut publication)
        .unwrap();
    assert_eq!(owner.phase(), BrokerKeyPhase::BoundUnpublished);
    assert_eq!(
        manager.publish(&mut owner, &mut publication),
        Err(BrokerKeyOwnerError::StaleTicket)
    );
    let mut close = manager.begin_close(&mut owner).unwrap();
    assert_eq!(manager.close_target(&owner, &close), Ok(&target(7)));
    assert_eq!(manager.finish_close(&mut owner, &mut close), Ok(target(7)));
    assert_eq!(owner.phase(), BrokerKeyPhase::Closed);
}

#[test]
fn temporary_unpublished_target_closes_without_any_handle_publication() {
    let mut manager = BrokerKeyOwners::default();
    let mut owner = bound(&mut manager, 9);
    let mut close = manager.begin_close(&mut owner).unwrap();
    assert_eq!(owner.phase(), BrokerKeyPhase::ClosingInflight);
    assert_eq!(manager.finish_close(&mut owner, &mut close), Ok(target(9)));
    assert_eq!(
        manager.active_target(&owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    assert_eq!(
        manager.finish_close(&mut owner, &mut close),
        Err(BrokerKeyOwnerError::StaleTicket)
    );
}

#[test]
fn close_failure_retains_receipt_and_prevents_query_or_republication() {
    let mut manager = BrokerKeyOwners::new();
    let mut owner = bound(&mut manager, 7);
    activate(&manager, &mut owner);
    let mut first = manager.begin_close(&mut owner).unwrap();
    assert_eq!(
        manager.active_target(&owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    *manager.close_metadata_mut(&mut owner, &first).unwrap() = Some(81);
    assert_eq!(manager.close_target(&owner, &first), Ok(&target(7)));
    manager.close_failed(&mut owner, &mut first).unwrap();
    assert_eq!(owner.phase(), BrokerKeyPhase::ClosingRetryable);
    assert_eq!(
        manager.active_target(&owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    assert!(matches!(
        manager.begin_publication(&mut owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    assert_eq!(
        manager.cancel_reservation(&mut owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    assert_eq!(
        manager.close_target(&owner, &first),
        Err(BrokerKeyOwnerError::StaleTicket)
    );
    let mut second = manager.begin_close(&mut owner).unwrap();
    assert_eq!(manager.close_metadata(&owner, &second), Ok(&Some(81)));
    assert_eq!(
        manager.finish_close(&mut owner, &mut first),
        Err(BrokerKeyOwnerError::StaleTicket)
    );
    let retired = manager.finish_close(&mut owner, &mut second).unwrap();
    assert_eq!(retired, target(7));
    assert_eq!(owner.phase(), BrokerKeyPhase::Closed);
}

#[test]
fn duplicate_nested_close_is_rejected_without_touching_original_attempt() {
    let mut manager = BrokerKeyOwners::new();
    let mut owner = bound(&mut manager, 7);
    let mut ticket = manager.begin_close(&mut owner).unwrap();
    let epoch = owner.epoch;
    assert!(matches!(
        manager.begin_close(&mut owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    assert_eq!(owner.epoch, epoch);
    assert_eq!(manager.close_target(&owner, &ticket), Ok(&target(7)));
    manager.finish_close(&mut owner, &mut ticket).unwrap();
}

#[test]
fn dropped_inflight_tickets_do_not_make_retained_owners_reusable() {
    let mut manager = BrokerKeyOwners::new();
    let mut closing = bound(&mut manager, 7);
    let ticket = manager.begin_close(&mut closing).unwrap();
    drop(ticket);
    assert_eq!(closing.phase(), BrokerKeyPhase::ClosingInflight);
    assert_eq!(closing.target.as_ref(), Some(&target(7)));
    assert!(matches!(
        manager.begin_close(&mut closing),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    assert_eq!(
        manager.active_target(&closing),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    assert_eq!(
        manager.cancel_reservation(&mut closing),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );

    let mut publishing = bound(&mut manager, 8);
    drop(manager.begin_publication(&mut publishing).unwrap());
    assert_eq!(publishing.phase(), BrokerKeyPhase::BoundUnpublished);
    assert!(matches!(
        manager.begin_publication(&mut publishing),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    assert!(matches!(
        manager.begin_close(&mut publishing),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    assert_eq!(
        manager.active_target(&publishing),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
}

#[test]
fn foreign_owner_tickets_cannot_publish_mutate_or_close_a_sibling() {
    let mut manager = BrokerKeyOwners::new();
    let mut a = bound(&mut manager, 7);
    let mut b = bound(&mut manager, 8);
    let mut a_publish = manager.begin_publication(&mut a).unwrap();
    let mut b_publish = manager.begin_publication(&mut b).unwrap();
    assert_eq!(
        manager.publish(&mut b, &mut a_publish),
        Err(BrokerKeyOwnerError::WrongOwner)
    );
    manager.publish(&mut a, &mut a_publish).unwrap();
    manager.publish(&mut b, &mut b_publish).unwrap();
    let mut a_close = manager.begin_close(&mut a).unwrap();
    let mut b_close = manager.begin_close(&mut b).unwrap();
    assert_eq!(
        manager.close_metadata_mut(&mut b, &a_close),
        Err(BrokerKeyOwnerError::WrongOwner)
    );
    assert_eq!(
        manager.close_failed(&mut b, &mut a_close),
        Err(BrokerKeyOwnerError::WrongOwner)
    );
    assert_eq!(
        manager.finish_close(&mut b, &mut a_close),
        Err(BrokerKeyOwnerError::WrongOwner)
    );
    assert_eq!(manager.finish_close(&mut a, &mut a_close), Ok(target(7)));
    assert_eq!(manager.finish_close(&mut b, &mut b_close), Ok(target(8)));
}

#[test]
fn fresh_managers_with_matching_owner_counters_cannot_alias() {
    let mut first = BrokerKeyOwners::new();
    let mut second = BrokerKeyOwners::default();
    let mut a = bound(&mut first, 7);
    let mut b = bound(&mut second, 7);
    assert_eq!(a.identity.owner, b.identity.owner);
    assert_ne!(a.identity.manager, b.identity.manager);
    let mut a_ticket = first.begin_close(&mut a).unwrap();
    let mut b_ticket = second.begin_close(&mut b).unwrap();
    assert_eq!(
        second.close_target(&a, &a_ticket),
        Err(BrokerKeyOwnerError::WrongManager)
    );
    assert_eq!(
        second.finish_close(&mut b, &mut a_ticket),
        Err(BrokerKeyOwnerError::WrongManager)
    );
    assert_eq!(first.finish_close(&mut a, &mut a_ticket), Ok(target(7)));
    assert_eq!(second.finish_close(&mut b, &mut b_ticket), Ok(target(7)));
}

#[test]
fn closed_slot_replacement_rejects_old_attempts() {
    let mut manager = BrokerKeyOwners::new();
    let mut slot = bound(&mut manager, 7);
    let mut old = manager.begin_close(&mut slot).unwrap();
    manager.finish_close(&mut slot, &mut old).unwrap();
    slot = bound(&mut manager, 7);
    let mut new = manager.begin_close(&mut slot).unwrap();
    assert_eq!(
        manager.finish_close(&mut slot, &mut old),
        Err(BrokerKeyOwnerError::WrongOwner)
    );
    assert_eq!(manager.close_target(&slot, &new), Ok(&target(7)));
    manager.finish_close(&mut slot, &mut new).unwrap();
}

#[test]
fn failed_attach_returns_real_target_and_reservations_cancel_only_before_binding() {
    let mut manager = BrokerKeyOwners::new();
    let mut owner = manager.reserve().unwrap();
    manager.cancel_reservation(&mut owner).unwrap();
    assert_eq!(owner.phase(), BrokerKeyPhase::Closed);
    assert_eq!(
        manager.attach(&mut owner, target(7)),
        Err((BrokerKeyOwnerError::InvalidPhase, target(7)))
    );
    assert!(matches!(
        manager.begin_close(&mut owner),
        Err(BrokerKeyOwnerError::InvalidPhase)
    ));
    let mut bound = bound(&mut manager, 8);
    assert_eq!(
        manager.cancel_reservation(&mut bound),
        Err(BrokerKeyOwnerError::InvalidPhase)
    );
    assert_eq!(
        manager.attach(&mut bound, target(9)),
        Err((BrokerKeyOwnerError::InvalidPhase, target(9)))
    );
    assert_eq!(bound.target.as_ref(), Some(&target(8)));
    let foreign = BrokerKeyOwners::new();
    assert_eq!(
        foreign.attach(&mut bound, target(10)),
        Err((BrokerKeyOwnerError::WrongManager, target(10)))
    );
}

#[test]
fn moving_manager_and_owner_preserves_exact_tickets() {
    let mut manager = BrokerKeyOwners::new();
    let mut owner = bound(&mut manager, 7);
    let mut ticket = manager.begin_close(&mut owner).unwrap();
    let moved_manager = manager;
    let mut moved_owner = owner;
    assert_eq!(
        moved_manager.finish_close(&mut moved_owner, &mut ticket),
        Ok(target(7))
    );
}

#[test]
fn epoch_exhaustion_is_failure_atomic_in_each_admission_phase() {
    let mut manager = BrokerKeyOwners::new();
    let mut owner = bound(&mut manager, 7);
    owner.epoch = u64::MAX;
    assert!(matches!(
        manager.begin_publication(&mut owner),
        Err(BrokerKeyOwnerError::Exhausted)
    ));
    assert!(matches!(
        manager.begin_close(&mut owner),
        Err(BrokerKeyOwnerError::Exhausted)
    ));
    assert_eq!(owner.phase(), BrokerKeyPhase::BoundUnpublished);
    assert!(!owner.publication_pending);
    assert_eq!(owner.target.as_ref(), Some(&target(7)));
    let mut active = bound(&mut manager, 8);
    activate(&manager, &mut active);
    active.epoch = u64::MAX;
    assert!(matches!(
        manager.begin_close(&mut active),
        Err(BrokerKeyOwnerError::Exhausted)
    ));
    assert_eq!(manager.active_target(&active), Ok(&target(8)));
    let mut retry = bound(&mut manager, 9);
    retry.epoch = u64::MAX - 1;
    let mut last = manager.begin_close(&mut retry).unwrap();
    *manager.close_metadata_mut(&mut retry, &last).unwrap() = Some(99);
    manager.close_failed(&mut retry, &mut last).unwrap();
    assert!(matches!(
        manager.begin_close(&mut retry),
        Err(BrokerKeyOwnerError::Exhausted)
    ));
    assert_eq!(retry.phase(), BrokerKeyPhase::ClosingRetryable);
    assert_eq!(retry.metadata, Some(99));
    assert_eq!(retry.target.as_ref(), Some(&target(9)));
}

#[test]
fn owner_and_manager_nonce_exhaustion_do_not_publish_partial_reservations() {
    let counter = AtomicU64::new(u64::MAX);
    let mut manager = BrokerKeyOwners::new();
    assert!(matches!(
        manager.reserve_with_counter::<Target, _>((), &counter),
        Err(BrokerKeyOwnerError::Exhausted)
    ));
    assert_eq!((manager.nonce, manager.last_owner), (0, 0));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    let counter = AtomicU64::new(0);
    manager.last_owner = u64::MAX;
    assert!(matches!(
        manager.reserve_with_counter::<Target, _>((), &counter),
        Err(BrokerKeyOwnerError::Exhausted)
    ));
    assert_eq!((manager.nonce, manager.last_owner), (0, u64::MAX));
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn no_failure_or_ack_retry_implicitly_drops_the_target() {
    struct DropTarget(Rc<Cell<usize>>);
    impl Drop for DropTarget {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut manager = BrokerKeyOwners::new();
    let mut owner = manager.reserve().unwrap();
    assert!(manager
        .attach(&mut owner, DropTarget(drops.clone()))
        .is_ok());
    let mut first = manager.begin_close(&mut owner).unwrap();
    manager.close_failed(&mut owner, &mut first).unwrap();
    assert_eq!(drops.get(), 0);
    let mut retry = manager.begin_close(&mut owner).unwrap();
    assert!(manager.finish_close(&mut owner, &mut first).is_err());
    assert_eq!(drops.get(), 0);
    let target = manager.finish_close(&mut owner, &mut retry).unwrap();
    drop(owner);
    assert_eq!(drops.get(), 0);
    drop(target);
    assert_eq!(drops.get(), 1);
}

#[test]
fn cleanup_metadata_updates_cannot_substitute_or_drop_retained_target() {
    struct DropTarget(Rc<Cell<usize>>);
    impl Drop for DropTarget {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut manager = BrokerKeyOwners::new();
    let mut owner = manager.reserve_with_metadata(None::<u64>).unwrap();
    assert!(manager
        .attach(&mut owner, DropTarget(drops.clone()))
        .is_ok());
    let mut first = manager.begin_close(&mut owner).unwrap();
    *manager.close_metadata_mut(&mut owner, &first).unwrap() = Some(100);
    assert_eq!(drops.get(), 0);
    manager.close_failed(&mut owner, &mut first).unwrap();
    let mut retry = manager.begin_close(&mut owner).unwrap();
    assert_eq!(manager.close_metadata(&owner, &retry), Ok(&Some(100)));
    assert_eq!(
        manager.close_metadata_mut(&mut owner, &first),
        Err(BrokerKeyOwnerError::StaleTicket)
    );
    assert_eq!(drops.get(), 0);
    let target = manager.finish_close(&mut owner, &mut retry).unwrap();
    drop(owner);
    assert_eq!(drops.get(), 0);
    drop(target);
    assert_eq!(drops.get(), 1);
}
