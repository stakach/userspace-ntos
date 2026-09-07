use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::thread_binding::ThreadRuntimeReservations;
use alloc::rc::Rc;
use core::cell::Cell;

#[derive(Debug)]
struct Runtime {
    binding: ThreadBinding<u32>,
    publication: ThreadPublicationSlot,
    drops: Rc<Cell<usize>>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

impl RuntimeIdentity for Runtime {
    type Role = u32;
    fn binding(&self) -> ThreadBinding<u32> {
        self.binding
    }
    fn publication(&self) -> &ThreadPublicationSlot {
        &self.publication
    }
}

fn runtime(tcb: u64, drops: &Rc<Cell<usize>>) -> Runtime {
    Runtime {
        binding: ThreadBinding {
            pi: 2,
            tid: 24,
            tcb,
            badge: 4,
            role: 1,
            process: ProcessIdentity {
                pid: 8,
                generation: ProcessGeneration::Hosted(7),
            },
            reservations: Some(ThreadRuntimeReservations {
                badge: 4,
                pool_slot: 3,
                window_slot: Some(5),
            }),
        },
        publication: ThreadPublicationSlot::empty(),
        drops: drops.clone(),
    }
}

fn slot(tcb: u64) -> (ThreadRuntimeSlot<Runtime>, Rc<Cell<usize>>) {
    let drops = Rc::new(Cell::new(0));
    let mut slot = ThreadRuntimeSlot::empty();
    slot.insert(runtime(tcb, &drops)).unwrap();
    (slot, drops)
}

#[test]
fn ingress_rejects_vacant_and_foreign_badges_without_mutation() {
    let empty = ThreadRuntimeSlot::<Runtime>::empty();
    assert_eq!(
        empty.admit_ingress(0, None).unwrap_err(),
        ThreadIngressError::UnknownBadge
    );
    let (slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    assert_eq!(
        slot.admit_ingress(5, Some(binding.process)).unwrap_err(),
        ThreadIngressError::UnknownBadge
    );
    assert_eq!(slot.owner().unwrap().binding, binding);
    assert_eq!(drops.get(), 0);
}

#[test]
fn ingress_admits_exact_owner_including_badge_zero() {
    let (mut slot, _) = slot(100);
    for badge in [4, 0] {
        let owner = slot.ordinary_mut().unwrap();
        owner.binding.badge = badge;
        owner.binding.reservations.as_mut().unwrap().badge = badge;
        let binding = owner.binding;
        assert_eq!(
            slot.admit_ingress(badge, Some(binding.process))
                .unwrap()
                .binding,
            binding
        );
    }
}

#[test]
fn ingress_rejects_missing_or_replaced_process_authority() {
    let (slot, _) = slot(100);
    let binding = slot.owner().unwrap().binding;
    for current in [
        None,
        Some(ProcessIdentity {
            pid: 9,
            ..binding.process
        }),
        Some(ProcessIdentity {
            generation: ProcessGeneration::Hosted(8),
            ..binding.process
        }),
        Some(ProcessIdentity {
            generation: ProcessGeneration::Temporary(7),
            ..binding.process
        }),
    ] {
        assert_eq!(
            slot.admit_ingress(binding.badge, current).unwrap_err(),
            ThreadIngressError::ProcessChanged
        );
    }
    assert_eq!(slot.owner().unwrap().binding, binding);
}

#[test]
fn ingress_rejects_unbuilt_and_busy_publications() {
    for tcb in [1, 100] {
        let (mut slot, _) = slot(tcb);
        let binding = slot.owner().unwrap().binding;
        if tcb == 1 {
            assert_eq!(
                slot.admit_ingress(binding.badge, Some(binding.process))
                    .unwrap_err(),
                ThreadIngressError::Unbuilt
            );
        }
        let ticket = slot
            .ordinary_mut()
            .unwrap()
            .publication
            .prepare(binding)
            .unwrap();
        assert_eq!(
            slot.admit_ingress(binding.badge, Some(binding.process))
                .unwrap_err(),
            ThreadIngressError::Publishing
        );
        slot.publishing_mut(&ticket)
            .unwrap()
            .publication
            .finish(ticket, &binding)
            .unwrap();
        assert_eq!(
            slot.admit_ingress(binding.badge, Some(binding.process))
                .is_ok(),
            tcb > 1
        );
    }
}

#[test]
fn ingress_stops_at_pending_entry_before_journal_preparation() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    assert!(slot
        .admit_ingress(binding.badge, Some(binding.process))
        .is_ok());
    let id = slot.begin_pending(binding).unwrap();
    assert_eq!(
        slot.admit_ingress(binding.badge, Some(binding.process))
            .unwrap_err(),
        ThreadIngressError::Pending
    );
    assert_eq!(slot.pending().unwrap().id(), id);
    assert_eq!(slot.owner().unwrap().binding, binding);
    assert_eq!(drops.get(), 0);
}

#[test]
fn ingress_stays_rejected_through_failed_and_completed_cleanup() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    let id = slot.begin_pending(binding).unwrap();
    slot.prepare_cleanup(id, &[]).unwrap();
    let mut backend = Backend {
        current: id,
        drops: drops.clone(),
        effects: 0,
        fail_revoke: true,
    };
    assert!(slot.advance_cleanup(id, &mut backend).is_err());
    assert_eq!(
        slot.admit_ingress(binding.badge, Some(binding.process))
            .unwrap_err(),
        ThreadIngressError::Pending
    );
    backend.fail_revoke = false;
    slot.advance_cleanup(id, &mut backend).unwrap();
    assert_eq!(
        slot.admit_ingress(binding.badge, Some(binding.process))
            .unwrap_err(),
        ThreadIngressError::Pending
    );
    let retired = slot.take_retired_payload(id).unwrap();
    assert_eq!(
        slot.admit_ingress(binding.badge, Some(binding.process))
            .unwrap_err(),
        ThreadIngressError::UnknownBadge
    );
    assert_eq!(drops.get(), 0);
    drop(retired);
    assert_eq!(drops.get(), 1);
}

struct Backend {
    current: ThreadRollbackId,
    drops: Rc<Cell<usize>>,
    effects: usize,
    fail_revoke: bool,
}

impl ThreadRollbackIo for Backend {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        self.current == id
    }
    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert_eq!(tcb, 100);
        assert_eq!(self.effects, 0);
        self.effects = 1;
        Ok(())
    }
    fn delete_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert_eq!(tcb, 100);
        assert_eq!(self.effects, 1);
        self.effects = 2;
        Ok(())
    }
    fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
        assert_eq!(id, self.current);
        assert_eq!(self.effects, 2);
        if self.fail_revoke {
            return Err(0xc000_009a);
        }
        self.effects = 3;
        Ok(())
    }
    fn release_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        panic!("empty inventory")
    }
    fn commit_rollback(&mut self, id: ThreadRollbackId) {
        assert_eq!(id, self.current);
        assert_eq!(self.effects, 3);
        assert_eq!(self.drops.get(), 0);
        self.effects = 4;
    }
}

#[test]
fn vacant_and_published_slots_preserve_nonclone_ownership() {
    let (mut slot, drops) = slot(100);
    assert!(!slot.is_empty());
    assert!(!slot.is_protected());
    assert!(slot.executable().is_some());
    let binding = slot.owner().unwrap().binding;
    let rejected = slot.insert(runtime(101, &drops)).err().unwrap();
    assert_eq!(slot.owner().unwrap().binding, binding);
    assert_eq!(drops.get(), 0);
    drop(rejected);
    let owner = slot.release_published().unwrap();
    assert!(slot.is_empty());
    assert!(slot.owner().is_none() && slot.executable().is_none());
    assert!(slot.release_published().is_none());
    assert_eq!(slot.begin_pending(binding), Err(SlotError::Vacant));
    drop(owner);
    assert_eq!(drops.get(), 2);
}

#[test]
fn invalid_or_constructing_payload_is_returned_without_insertion() {
    let drops = Rc::new(Cell::new(0));
    let mut empty = ThreadRuntimeSlot::empty();
    let mut invalid = runtime(0, &drops);
    invalid = empty.insert(invalid).err().unwrap();
    assert_eq!(drops.get(), 0);
    invalid.binding.tcb = 1;
    let ticket = invalid.publication.prepare(invalid.binding).unwrap();
    let mut invalid = empty.insert(invalid).err().unwrap();
    assert!(empty.is_empty());
    assert_eq!(drops.get(), 0);
    invalid
        .publication
        .finish(ticket, &invalid.binding)
        .unwrap();
    empty.insert(invalid).unwrap();
}

#[test]
fn construction_blocks_execution_release_mutation_and_cleanup() {
    let (mut slot, drops) = slot(1);
    assert!(slot.executable().is_none());
    let binding = slot.owner().unwrap().binding;
    let ticket = slot
        .ordinary_mut()
        .unwrap()
        .publication
        .prepare(binding)
        .unwrap();
    assert!(slot.is_protected());
    assert!(slot.ordinary_mut().is_none());
    assert!(slot.release_published().is_none());
    assert_eq!(slot.begin_pending(binding), Err(SlotError::Busy));
    assert_eq!(slot.owner().unwrap().binding, binding);
    let runtime = slot.publishing_mut(&ticket).unwrap();
    runtime.publication.finish(ticket, &binding).unwrap();
    runtime.binding.tcb = 100;
    assert!(slot.executable().is_some());
    assert_eq!(drops.get(), 0);
}

#[test]
fn another_construction_ticket_cannot_mutate_the_slot() {
    let (mut slot, _) = slot(1);
    let binding = slot.owner().unwrap().binding;
    let ticket = slot
        .ordinary_mut()
        .unwrap()
        .publication
        .prepare(binding)
        .unwrap();
    let mut other = ThreadPublicationSlot::empty();
    let foreign = other.prepare(binding).unwrap();
    assert!(slot.publishing_mut(&foreign).is_none());
    assert!(slot.is_protected());
    slot.publishing_mut(&ticket)
        .unwrap()
        .publication
        .finish(ticket, &binding)
        .unwrap();
}

#[test]
fn pending_state_owns_the_slot_and_blocks_ordinary_operations() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    let id = slot.begin_pending(binding).unwrap();
    assert!(slot.is_pending() && slot.is_protected() && !slot.is_empty());
    assert_eq!(slot.owner().unwrap().binding, binding);
    assert!(slot.owner().unwrap().binding.holds_pool_slot(2, 3));
    assert!(slot.owner().unwrap().binding.holds_window_slot(2, 5));
    assert_eq!(slot.pending().unwrap().id(), id);
    assert_eq!(id.identity().pid, binding.process.pid);
    assert_eq!(id.identity().process_generation, binding.process.generation);
    assert!(slot.executable().is_none());
    assert!(slot.ordinary_mut().is_none());
    assert!(slot.release_published().is_none());
    assert!(slot.take_retired_payload(id).is_none());
    assert_eq!(slot.begin_pending(binding), Err(SlotError::AlreadyPending));
    let mut publisher = ThreadPublicationSlot::empty();
    assert!(slot
        .publishing_mut(&publisher.prepare(binding).unwrap())
        .is_none());
    let rejected = slot.insert(runtime(101, &drops)).err().unwrap();
    assert_eq!(slot.pending().unwrap().id(), id);
    assert_eq!(drops.get(), 0);
    drop(rejected);
}

#[test]
fn stale_admission_does_not_move_the_original_runtime() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    let mut stale = binding;
    stale.process.generation = ProcessGeneration::Temporary(7);
    assert_eq!(slot.begin_pending(stale), Err(SlotError::OwnerChanged));
    assert_eq!(slot.owner().unwrap().binding, binding);
    assert!(slot.executable().is_some());
    assert_eq!(drops.get(), 0);
}

#[test]
fn missing_reservations_do_not_transfer_an_external_runtime() {
    let (mut slot, drops) = slot(100);
    slot.ordinary_mut().unwrap().binding.reservations = None;
    let binding = slot.owner().unwrap().binding;
    assert_eq!(
        slot.begin_pending(binding),
        Err(SlotError::MissingReservations)
    );
    assert!(slot.executable().is_some());
    assert_eq!(drops.get(), 0);
}

#[test]
fn retain_failure_restores_the_unbuilt_runtime_in_place() {
    let (mut slot, drops) = slot(1);
    let binding = slot.owner().unwrap().binding;
    assert_eq!(
        slot.begin_pending(binding),
        Err(SlotError::Cleanup(ThreadRollbackError::InvalidCapability))
    );
    assert_eq!(slot.owner().unwrap().binding, binding);
    assert!(!slot.is_pending() && !slot.is_empty());
    assert!(slot.ordinary_mut().is_some());
    assert_eq!(drops.get(), 0);
}

#[test]
fn invalid_cleanup_inventory_preserves_pending_owner_for_retry() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    let id = slot.begin_pending(binding).unwrap();
    assert_eq!(
        slot.prepare_cleanup(
            id,
            &[ThreadRollbackResource {
                cap: 100,
                kind: crate::thread_rollback::ThreadRollbackResourceKind::Frame,
            }]
        ),
        Err(SlotError::Cleanup(
            ThreadRollbackError::ConflictingOwnership
        ))
    );
    assert_eq!(slot.pending().unwrap().id(), id);
    assert!(slot.pending().unwrap().cleanup().is_none());
    assert_eq!(drops.get(), 0);
    slot.prepare_cleanup(id, &[]).unwrap();
    assert_eq!(slot.pending().unwrap().cleanup().unwrap().id(), id);
}

#[test]
fn failed_cleanup_retains_slot_and_completed_cleanup_retires_once() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    let id = slot.begin_pending(binding).unwrap();
    let mut io = Backend {
        current: id,
        drops: drops.clone(),
        effects: 0,
        fail_revoke: true,
    };
    assert_eq!(
        slot.advance_cleanup(id, &mut io),
        Err(SlotError::Cleanup(ThreadRollbackError::NotPrepared))
    );
    slot.prepare_cleanup(id, &[]).unwrap();
    assert!(slot.advance_cleanup(id, &mut io).is_err());
    assert_eq!(io.effects, 2);
    assert!(slot.take_retired_payload(id).is_none());
    assert!(slot.is_pending() && slot.is_protected());
    assert_eq!(slot.owner().unwrap().binding, binding);
    assert_eq!(drops.get(), 0);
    io.fail_revoke = false;
    slot.advance_cleanup(id, &mut io).unwrap();
    slot.advance_cleanup(id, &mut io).unwrap();
    assert_eq!(io.effects, 4);
    assert!(slot.is_pending());
    assert!(slot.release_published().is_none());
    let retired = slot.take_retired_payload(id).unwrap();
    assert!(slot.is_empty());
    assert!(slot.take_retired_payload(id).is_none());
    assert_eq!(slot.prepare_cleanup(id, &[]), Err(SlotError::NotPending));
    assert_eq!(
        slot.advance_cleanup(id, &mut io),
        Err(SlotError::NotPending)
    );
    assert_eq!(drops.get(), 0);
    drop(retired);
    assert_eq!(drops.get(), 1);
}

#[test]
fn stale_cleanup_backend_cannot_affect_the_retained_slot() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    let id = slot.begin_pending(binding).unwrap();
    slot.prepare_cleanup(id, &[]).unwrap();
    let other = crate::thread_rollback::ThreadRollback::prepare(id.identity(), 100, &[]).unwrap();
    let mut io = Backend {
        current: other.id(),
        drops: drops.clone(),
        effects: 0,
        fail_revoke: false,
    };
    assert_eq!(
        slot.advance_cleanup(id, &mut io),
        Err(SlotError::Cleanup(ThreadRollbackError::StaleOwner))
    );
    assert_eq!(slot.pending().unwrap().id(), id);
    assert_eq!(io.effects, 0);
    assert_eq!(drops.get(), 0);
}

#[test]
fn invalid_mutated_binding_is_retained_without_cleanup_admission() {
    let (mut slot, drops) = slot(100);
    slot.ordinary_mut()
        .unwrap()
        .binding
        .reservations
        .as_mut()
        .unwrap()
        .badge = 99;
    let invalid = slot.owner().unwrap().binding;
    assert_eq!(slot.begin_pending(invalid), Err(SlotError::InvalidBinding));
    assert_eq!(slot.owner().unwrap().binding, invalid);
    assert!(!slot.is_pending());
    assert_eq!(drops.get(), 0);
}

#[test]
fn pending_owner_still_blocks_binding_and_reservation_reuse() {
    let (mut slot, _) = slot(100);
    let binding = slot.owner().unwrap().binding;
    slot.begin_pending(binding).unwrap();
    let mut replacement = binding;
    replacement.tid += 1;
    replacement.tcb += 1;
    assert!(admit_thread_binding(replacement, [(0, slot.owner().unwrap().binding)]).is_err());
    replacement.badge += 1;
    replacement.role += 1;
    replacement.reservations.as_mut().unwrap().badge = replacement.badge;
    assert!(admit_thread_binding(replacement, [(0, slot.owner().unwrap().binding)]).is_err());
    replacement.reservations.as_mut().unwrap().pool_slot += 1;
    assert!(admit_thread_binding(replacement, [(0, slot.owner().unwrap().binding)]).is_err());
    replacement.reservations.as_mut().unwrap().window_slot = None;
    replacement.process.generation = ProcessGeneration::Hosted(8);
    assert!(admit_thread_binding(replacement, [(0, slot.owner().unwrap().binding)]).is_err());
}

#[test]
fn stale_attempt_cannot_prepare_drive_or_retire_a_replacement_owner() {
    let (mut slot, drops) = slot(100);
    let binding = slot.owner().unwrap().binding;
    let id = slot.begin_pending(binding).unwrap();
    let foreign = crate::thread_rollback::ThreadRollback::prepare(id.identity(), 100, &[])
        .unwrap()
        .id();
    let mut io = Backend {
        current: id,
        drops,
        effects: 0,
        fail_revoke: false,
    };
    assert_eq!(
        slot.prepare_cleanup(foreign, &[]),
        Err(SlotError::OwnerChanged)
    );
    assert_eq!(
        slot.advance_cleanup(foreign, &mut io),
        Err(SlotError::OwnerChanged)
    );
    assert_eq!(io.effects, 0);
    assert!(slot.pending().unwrap().cleanup().is_none());
    slot.prepare_cleanup(id, &[]).unwrap();
    slot.advance_cleanup(id, &mut io).unwrap();
    assert!(slot.take_retired_payload(foreign).is_none());
    assert_eq!(slot.pending().unwrap().id(), id);
    assert!(slot.take_retired_payload(id).is_some());
}
