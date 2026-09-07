use super::*;
use alloc::vec::Vec;

#[test]
fn admission_starts_without_fabricated_tcbs_or_slots() {
    let inventory = ThreadConstructionInventory::empty();
    assert!(inventory.is_empty());
    assert_eq!(inventory.live_tcb(), None);
    assert!(inventory.tcb_deleted_or_absent());
    assert_eq!(inventory.next_retirement(), None);
    assert_eq!(inventory.entries().count(), 5);
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
        [
            Role::GuardedCnode,
            Role::RawCnode,
            Role::SchedContext,
            Role::FaultEndpoint
        ]
    );
    assert!(inventory.is_empty());
}

#[test]
fn transferred_sc_and_owned_endpoint_are_distinct_from_borrowed_inputs() {
    let mut inventory = ThreadConstructionInventory::empty();
    // A borrowed original PML4 or endpoint has no ownership entry.
    inventory.adopt_object(Role::FaultEndpoint, 200).unwrap();
    inventory.adopt_object(Role::SchedContext, 201).unwrap();
    assert_eq!(
        inventory
            .entries()
            .filter(|(_, state)| state.slot().is_some())
            .count(),
        2
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
