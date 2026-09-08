use super::*;
use alloc::vec::Vec;

#[test]
fn memory_progress_retains_failed_empty_slots_without_claiming_live_backing() {
    let mut progress = MemoryConstructionProgress::<2>::empty();
    assert!(progress.is_empty());
    for slot in [0, 1] {
        assert_eq!(
            progress.retain_empty_slot(slot),
            Err(InventoryError::InvalidSlot)
        );
    }
    progress.retain_empty_slot(42).unwrap();
    assert_eq!(progress.empty_slot(), Some(42));
    assert!(!progress.is_empty());
    assert_eq!(
        progress.retain_empty_slot(43),
        Err(InventoryError::Occupied)
    );
    assert_eq!(progress.empty_slot(), Some(42));
}

#[test]
fn registry_publication_coverage_is_independent_of_remaining_registry_rows() {
    let mut progress = MemoryConstructionProgress::<4>::empty();
    progress.record_stack(0);
    progress.record_stack(2);
    progress.record_teb(1);
    assert!(!progress.is_empty());
    for index in 0..4 {
        assert_eq!(progress.stack_registered(index), index == 0 || index == 2);
    }
    assert!(!progress.teb_registered(0));
    assert!(progress.teb_registered(1));
    assert_eq!(progress.empty_slot(), None);
}

#[test]
fn completed_registration_requires_every_observed_stack_and_teb_publication() {
    use crate::thread_resources::{ThreadMemoryLayout, ThreadMemoryResources};
    let layout = ThreadMemoryLayout::new(0x10000, 2, 0x20000, 0x30000, 0x40000).unwrap();
    for pi in [0, 5] {
        let resources = ThreadMemoryResources::<4>::new(pi, layout).unwrap();
        let mut progress = MemoryConstructionProgress::<4>::empty();
        for index in 0..2 {
            assert!(progress.completed_registration(&resources).is_err());
            progress.record_stack(index);
        }
        for index in 0..2 {
            assert!(progress.completed_registration(&resources).is_err());
            progress.record_teb(index);
        }
        let complete = progress.completed_registration(&resources).unwrap();
        assert!(complete.matches(&resources));
        assert_eq!(complete.pages().collect::<Vec<_>>(), [0x10000, 0x11000, 0x30000, 0x31000]);
        assert_eq!(progress.completed_registration(&resources).unwrap(), complete);
        let mut changed = resources;
        changed.client_pi = pi + 1;
        assert!(!complete.matches(&changed));
        let changed = ThreadMemoryResources::<4>::new(pi,
            ThreadMemoryLayout::new(0x10000, 1, 0x20000, 0x30000, 0x40000).unwrap()).unwrap();
        assert!(!complete.matches(&changed));
    }
}

#[test]
fn failed_slot_extra_coverage_and_missing_geometry_cannot_be_successful_registration() {
    use crate::thread_resources::{ThreadMemoryLayout, ThreadMemoryResources};
    let layout = ThreadMemoryLayout::new(0x10000, 2, 0x20000, 0x30000, 0x40000).unwrap();
    let resources = ThreadMemoryResources::<4>::new(0, layout).unwrap();
    let complete = || {
        let mut progress = MemoryConstructionProgress::<4>::empty();
        for index in 0..2 { progress.record_stack(index); progress.record_teb(index); }
        progress
    };
    let mut progress = complete();
    progress.retain_empty_slot(123).unwrap();
    assert!(progress.completed_registration(&resources).is_err());
    assert_eq!(progress.empty_slot(), Some(123));
    let mut progress = complete();
    progress.record_stack(2);
    assert!(progress.completed_registration(&resources).is_err());
    assert!(complete().completed_registration(&ThreadMemoryResources::<4>::empty()).is_err());
}

#[test]
fn completed_mechanism_inventory_transfers_every_live_slot() {
    let mut inventory = ThreadConstructionInventory::empty();
    for (index, role) in ROLES.into_iter().enumerate() {
        inventory.adopt_object(role, 100 + index as u64).unwrap();
    }
    assert_eq!(inventory.into_live_slots().unwrap(), [100, 101, 102, 103]);
}

#[test]
fn live_observation_leaves_completed_inventory_owned_and_retireable() {
    let mut inventory = ThreadConstructionInventory::empty();
    for (index, role) in ROLES.into_iter().enumerate() {
        inventory.adopt_object(role, 100 + index as u64).unwrap();
    }
    let before: Vec<_> = inventory.entries().collect();
    for _ in 0..2 {
        assert_eq!(inventory.live_slots(), Ok([100, 101, 102, 103]));
        assert_eq!(inventory.entries().collect::<Vec<_>>(), before);
    }
    let mut retired = Vec::new();
    while let Some((role, SlotState::LiveObject(slot))) = inventory.next_retirement() {
        inventory.validate_retirement(role, slot).unwrap();
        inventory.acknowledge_delete(role, slot).unwrap();
        inventory.acknowledge_recycle(role, slot).unwrap();
        retired.push(slot);
    }
    assert_eq!(retired, alloc::vec![102, 101, 100, 103]);
    assert!(inventory.is_empty());
    assert_eq!(inventory.live_slots(), Err(InventoryError::InvalidPhase));
}

#[test]
fn observation_rejects_each_incomplete_role_without_consuming_inventory() {
    for incomplete in ROLES {
        for empty in [false, true] {
            let mut inventory = ThreadConstructionInventory::empty();
            for (index, role) in ROLES.into_iter().enumerate() {
                if role != incomplete {
                    inventory.adopt_object(role, 100 + index as u64).unwrap();
                } else if empty {
                    inventory.adopt_empty(role, 100 + index as u64).unwrap();
                }
            }
            let before: Vec<_> = inventory.entries().collect();
            assert_eq!(inventory.live_slots(), Err(InventoryError::InvalidPhase));
            assert_eq!(inventory.entries().collect::<Vec<_>>(), before);
            while let Some((role, state)) = inventory.next_retirement() {
                let slot = state.slot().unwrap();
                if matches!(state, SlotState::LiveObject(_)) {
                    inventory.acknowledge_delete(role, slot).unwrap();
                }
                inventory.acknowledge_recycle(role, slot).unwrap();
            }
            assert!(inventory.is_empty());
        }
    }
}

#[test]
fn observation_rejects_deleted_slot_and_preserves_cleanup_progress() {
    let mut inventory = ThreadConstructionInventory::empty();
    for (index, role) in ROLES.into_iter().enumerate() {
        inventory.adopt_object(role, 100 + index as u64).unwrap();
    }
    inventory.acknowledge_delete(Role::Tcb, 102).unwrap();
    let before: Vec<_> = inventory.entries().collect();
    assert_eq!(inventory.live_slots(), Err(InventoryError::InvalidPhase));
    assert_eq!(inventory.entries().collect::<Vec<_>>(), before);
    inventory.acknowledge_recycle(Role::Tcb, 102).unwrap();
    assert_eq!(
        inventory.next_retirement(),
        Some((Role::GuardedCnode, SlotState::LiveObject(101)))
    );
}

#[test]
fn incomplete_mechanism_transfer_returns_ownership_unchanged() {
    for phase in [
        SlotState::Absent,
        SlotState::AllocatedEmpty(102),
        SlotState::DeleteAcknowledged(102),
    ] {
        let mut inventory = ThreadConstructionInventory::empty();
        inventory.adopt_object(Role::RawCnode, 100).unwrap();
        inventory.adopt_object(Role::GuardedCnode, 101).unwrap();
        inventory.adopt_object(Role::SchedContext, 103).unwrap();
        if phase != SlotState::Absent {
            inventory.adopt_empty(Role::Tcb, 102).unwrap();
            if phase == SlotState::DeleteAcknowledged(102) {
                inventory.acknowledge_object(Role::Tcb, 102).unwrap();
                inventory.acknowledge_delete(Role::Tcb, 102).unwrap();
            }
        }
        let retained = inventory.into_live_slots().unwrap_err();
        assert_eq!(retained.state(Role::Tcb), phase);
        assert_eq!(retained.state(Role::RawCnode), SlotState::LiveObject(100));
        assert_eq!(
            retained.state(Role::GuardedCnode),
            SlotState::LiveObject(101)
        );
        assert_eq!(
            retained.state(Role::SchedContext),
            SlotState::LiveObject(103)
        );
    }
}

#[test]
fn admission_starts_without_fabricated_tcbs_or_slots() {
    let inventory = ThreadConstructionInventory::empty();
    assert!(inventory.is_empty());
    assert_eq!(inventory.live_tcb(), None);
    assert!(inventory.tcb_deleted_or_absent());
    assert_eq!(inventory.next_retirement(), None);
    assert_eq!(inventory.entries().count(), 4);
}

#[test]
fn every_role_retains_empty_live_deleted_and_recycled_phases() {
    for role in ROLES {
        let mut inventory = ThreadConstructionInventory::empty();
        inventory.adopt_empty(role, 100).unwrap();
        assert_eq!(inventory.state(role), SlotState::AllocatedEmpty(100));
        assert_eq!(inventory.live_tcb(), None);
        inventory.acknowledge_object(role, 100).unwrap();
        assert_eq!(inventory.state(role), SlotState::LiveObject(100));
        assert_eq!(
            inventory.live_tcb(),
            if role == Role::Tcb { Some(100) } else { None }
        );
        inventory.acknowledge_delete(role, 100).unwrap();
        assert_eq!(inventory.state(role), SlotState::DeleteAcknowledged(100));
        assert_eq!(inventory.live_tcb(), None);
        assert!(!inventory.is_empty());
        inventory.acknowledge_recycle(role, 100).unwrap();
        assert!(inventory.is_empty());
    }
}

#[test]
fn failed_retype_retires_empty_slots_without_object_deletion() {
    let mut inventory = ThreadConstructionInventory::empty();
    for (index, role) in ROLES.into_iter().enumerate() {
        inventory.adopt_empty(role, 100 + index as u64).unwrap();
    }
    while let Some((role, SlotState::AllocatedEmpty(cap))) = inventory.next_retirement() {
        assert_eq!(
            inventory.acknowledge_delete(role, cap),
            Err(InventoryError::InvalidPhase)
        );
        inventory.acknowledge_recycle(role, cap).unwrap();
    }
    assert!(inventory.is_empty());
}

#[test]
fn role_and_slot_conflicts_do_not_replace_retained_ownership() {
    let mut inventory = ThreadConstructionInventory::empty();
    for invalid in [0, 1] {
        assert_eq!(
            inventory.adopt_empty(Role::Tcb, invalid),
            Err(InventoryError::InvalidSlot)
        );
    }
    inventory.adopt_object(Role::RawCnode, 100).unwrap();
    assert_eq!(
        inventory.adopt_empty(Role::RawCnode, 101),
        Err(InventoryError::Occupied)
    );
    assert_eq!(
        inventory.adopt_object(Role::GuardedCnode, 100),
        Err(InventoryError::DuplicateSlot)
    );
    inventory.acknowledge_delete(Role::RawCnode, 100).unwrap();
    assert_eq!(
        inventory.adopt_empty(Role::Tcb, 100),
        Err(InventoryError::DuplicateSlot)
    );
    inventory.acknowledge_recycle(Role::RawCnode, 100).unwrap();
    inventory.adopt_empty(Role::Tcb, 100).unwrap();
}

#[test]
fn acknowledgement_requires_exact_slot_and_current_phase() {
    let mut inventory = ThreadConstructionInventory::empty();
    inventory.adopt_empty(Role::Tcb, 100).unwrap();
    assert_eq!(
        inventory.acknowledge_object(Role::Tcb, 101),
        Err(InventoryError::StaleSlot)
    );
    inventory.acknowledge_object(Role::Tcb, 100).unwrap();
    assert_eq!(
        inventory.acknowledge_object(Role::Tcb, 100),
        Err(InventoryError::InvalidPhase)
    );
    assert_eq!(
        inventory.acknowledge_recycle(Role::Tcb, 100),
        Err(InventoryError::InvalidPhase)
    );
    assert_eq!(
        inventory.acknowledge_delete(Role::Tcb, 101),
        Err(InventoryError::StaleSlot)
    );
    assert!(!inventory.tcb_deleted_or_absent());
    inventory.acknowledge_delete(Role::Tcb, 100).unwrap();
    assert_eq!(
        inventory.acknowledge_delete(Role::Tcb, 100),
        Err(InventoryError::InvalidPhase)
    );
    assert_eq!(
        inventory.acknowledge_recycle(Role::Tcb, 101),
        Err(InventoryError::StaleSlot)
    );
    assert!(inventory.tcb_deleted_or_absent());
    assert_eq!(
        inventory.state(Role::Tcb),
        SlotState::DeleteAcknowledged(100)
    );
}

#[test]
fn failed_delete_and_recycle_keep_tcb_before_cnode_retirement() {
    let mut inventory = ThreadConstructionInventory::empty();
    for (index, role) in ROLES.into_iter().enumerate() {
        inventory.adopt_object(role, 100 + index as u64).unwrap();
    }
    for _ in 0..3 {
        // A failed backend operation makes no acknowledgement and retains the same next action.
        assert_eq!(
            inventory.next_retirement(),
            Some((Role::Tcb, SlotState::LiveObject(102)))
        );
        assert!(!inventory.tcb_deleted_or_absent());
    }
    inventory.acknowledge_delete(Role::Tcb, 102).unwrap();
    for _ in 0..3 {
        assert_eq!(
            inventory.next_retirement(),
            Some((Role::Tcb, SlotState::DeleteAcknowledged(102)))
        );
    }
    inventory.acknowledge_recycle(Role::Tcb, 102).unwrap();
    let mut retired = Vec::new();
    while let Some((role, SlotState::LiveObject(cap))) = inventory.next_retirement() {
        inventory.acknowledge_delete(role, cap).unwrap();
        inventory.acknowledge_recycle(role, cap).unwrap();
        retired.push(role);
    }
    assert_eq!(
        retired,
        [Role::GuardedCnode, Role::RawCnode, Role::SchedContext,]
    );
    assert!(inventory.is_empty());
}

#[test]
fn transferred_sc_remains_owned_after_tcb_and_cnode_retirement() {
    let mut inventory = ThreadConstructionInventory::empty();
    // A borrowed original PML4 or endpoint has no ownership entry.
    inventory.adopt_object(Role::SchedContext, 201).unwrap();
    assert_eq!(
        inventory
            .entries()
            .filter(|(_, state)| state.slot().is_some())
            .count(),
        1
    );
    assert_eq!(inventory.live_tcb(), None);
    assert_eq!(
        inventory.next_retirement(),
        Some((Role::SchedContext, SlotState::LiveObject(201)))
    );
}
#[test]
fn backend_admission_refuses_out_of_order_cnode_and_frame_dependencies() {
    let mut inventory = ThreadConstructionInventory::empty();
    inventory.adopt_object(Role::RawCnode, 100).unwrap();
    inventory.adopt_object(Role::GuardedCnode, 101).unwrap();
    inventory.adopt_object(Role::Tcb, 102).unwrap();
    for role in [Role::RawCnode, Role::GuardedCnode] {
        let slot = inventory.state(role).slot().unwrap();
        assert_eq!(
            inventory.validate_retirement(role, slot),
            Err(InventoryError::OutOfOrder)
        );
        assert_eq!(
            inventory.acknowledge_delete(role, slot),
            Err(InventoryError::OutOfOrder)
        );
    }
    assert_eq!(
        inventory.validate_retirement(Role::Tcb, 102),
        Ok(SlotState::LiveObject(102))
    );
    inventory.acknowledge_delete(Role::Tcb, 102).unwrap();
    inventory.acknowledge_recycle(Role::Tcb, 102).unwrap();
    assert_eq!(
        inventory.validate_retirement(Role::RawCnode, 100),
        Err(InventoryError::OutOfOrder)
    );
    assert_eq!(
        inventory.validate_retirement(Role::GuardedCnode, 101),
        Ok(SlotState::LiveObject(101))
    );
}
