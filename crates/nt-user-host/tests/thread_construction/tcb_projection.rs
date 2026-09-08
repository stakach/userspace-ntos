use super::*;
use nt_user_host::thread_binding::{admit_thread_binding, ThreadBindingAdmission, ThreadBindingError};
use nt_user_host::thread_construction::SlotState;

#[test]
fn failed_delete_preserves_projection_until_acknowledged() {
    let (mut slot, ticket, partial, drops) = fixture(Some(400), true);
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let mut backend = Backend { current: id, events: Vec::with_capacity(8), fail: Some(1) };
    assert!(without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).is_err());
    assert_eq!(slot.owner().unwrap().binding.tcb, 400);
    assert_eq!(slot.pending().unwrap().construction_retirement().unwrap().inventory()
        .state(ConstructionRole::Tcb), SlotState::LiveObject(400));
    assert_eq!(backend.events, [Event::Suspend(400)]);
    backend.fail = None;
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    assert_eq!(slot.owner().unwrap().binding.tcb, 1);
    assert_eq!(backend.events, [Event::Suspend(400), Event::Delete(400), Event::Recycle(400)]);
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn failed_recycle_clears_projection_but_retains_empty_slot_and_all_holds() {
    let (mut slot, ticket, partial, drops) = fixture(Some(400), true);
    let held = slot.owner().unwrap().binding.reservations;
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let mut backend = Backend { current: id, events: Vec::with_capacity(8), fail: Some(2) };
    assert!(without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).is_err());
    let pending = slot.pending().unwrap();
    assert_eq!(pending.runtime().binding.tcb, 1);
    assert_eq!(pending.runtime().binding.reservations, held);
    assert!(pending.runtime().partial.as_ref().unwrap().memory.is_live());
    assert_eq!(pending.construction_retirement().unwrap().inventory()
        .state(ConstructionRole::Tcb), SlotState::DeleteAcknowledged(400));
    assert!(pending.cleanup().is_none());
    backend.fail = None;
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    assert_eq!(backend.events, [Event::Suspend(400), Event::Delete(400), Event::Recycle(400)]);
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn wrong_projection_refuses_recycle_without_repeating_acknowledged_delete() {
    let (mut slot, ticket, partial, drops) = fixture(Some(400), true);
    slot.publishing_mut(&ticket).unwrap().projection_override = Some(401);
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let mut backend = Backend { current: id, events: Vec::with_capacity(8), fail: None };
    for _ in 0..2 {
        assert_eq!(without_allocation(|| slot.advance_construction_retirement(id, &mut backend)),
            Err(SlotError::Retirement(RetirementError::Backend {
                role: ConstructionRole::Tcb, operation: Operation::Recycle, status: 0xc000_000d,
            })));
        assert_eq!(slot.owner().unwrap().binding.tcb, 401);
        assert_eq!(slot.pending().unwrap().construction_retirement().unwrap().inventory()
            .state(ConstructionRole::Tcb), SlotState::DeleteAcknowledged(400));
    }
    assert_eq!(backend.events, [Event::Suspend(400), Event::Delete(400)]);
    assert_protected(&mut slot, id);
    assert_eq!(drops.get(), 0);
}

#[test]
fn recycled_tcb_number_can_bind_elsewhere_without_releasing_old_reservations() {
    let (mut slot, ticket, partial, _) = fixture(Some(400), true);
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let before = slot.owner().unwrap().binding;
    let mut replacement = before;
    replacement.tid += 1;
    replacement.badge += 1;
    replacement.role += 1;
    replacement.reservations = None;
    assert_eq!(admit_thread_binding(replacement, [(0, before)]), Err(ThreadBindingError::TcbConflict));
    let mut backend = Backend { current: id, events: Vec::with_capacity(8), fail: None };
    without_allocation(|| slot.advance_construction_retirement(id, &mut backend)).unwrap();
    let after = slot.owner().unwrap().binding;
    assert_eq!(admit_thread_binding(replacement, [(0, after)]), Ok(ThreadBindingAdmission::Insert));
    assert_eq!(after.reservations, before.reservations);
    assert!(after.holds_pool_slot(after.pi, before.reservations.unwrap().pool_slot));
    assert!(after.holds_window_slot(after.pi, before.reservations.unwrap().window_slot.unwrap()));
    assert_protected(&mut slot, id);
}
