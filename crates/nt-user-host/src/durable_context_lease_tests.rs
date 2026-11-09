use super::durable_context_lease::{DurableContextLeaseError, DurableContextLeases};

#[test]
fn durable_context_lease_nested_bind_unbind_preserves_each_owner() {
    let mut leases = DurableContextLeases::<u64, &'static str>::new();
    let outer_reservation = leases.reserve().unwrap();
    let outer = leases.retain(outer_reservation, 17, "outer").unwrap();
    leases.bind(outer).unwrap();
    assert_eq!(leases.active(), Some(&"outer"));

    let inner_reservation = leases.reserve().unwrap();
    let inner = leases.retain(inner_reservation, 19, "inner").unwrap();
    leases.bind(inner).unwrap();
    assert_eq!(leases.active(), Some(&"inner"));
    assert_eq!(leases.unbind(outer), Err(DurableContextLeaseError::NotTop));
    assert_eq!(leases.active(), Some(&"inner"));

    leases.unbind(inner).unwrap();
    assert_eq!(leases.active(), Some(&"outer"));
    assert_eq!(leases.get(inner), Some(&"inner"));
    leases.unbind(outer).unwrap();
    assert_eq!(leases.active(), None);
    assert_eq!(leases.get(outer), Some(&"outer"));
}

#[test]
fn durable_context_lease_rebind_requires_exact_generation() {
    let mut leases = DurableContextLeases::<u64, &'static str>::new();
    let first = leases.reserve().unwrap();
    let old = leases.retain(first, 23, "first").unwrap();
    leases.bind(old).unwrap();
    leases.unbind(old).unwrap();
    assert_eq!(leases.get(old), Some(&"first"));
    assert_eq!(leases.retire(old), Ok("first"));

    let reused = leases.reserve().unwrap();
    let current = leases.retain(reused, 23, "second").unwrap();
    assert_ne!(old, current);
    assert_eq!(leases.bind(old), Err(DurableContextLeaseError::StaleTicket));
    assert_eq!(leases.retire(old), Err(DurableContextLeaseError::StaleTicket));
    assert_eq!(leases.get(current), Some(&"second"));
    leases.bind(current).unwrap();
    assert_eq!(leases.active(), Some(&"second"));
}

#[test]
fn durable_context_lease_refusal_keeps_the_held_bundle() {
    let mut leases = DurableContextLeases::<u64, &'static str>::new();
    let reservation = leases.reserve().unwrap();
    let held = leases.retain(reservation, 29, "held").unwrap();
    leases.bind(held).unwrap();
    assert_eq!(leases.bind(held), Err(DurableContextLeaseError::AlreadyBound));
    assert_eq!(leases.retire(held), Err(DurableContextLeaseError::StillBound));
    assert_eq!(leases.get(held), Some(&"held"));
    assert_eq!(leases.active(), Some(&"held"));
    leases.unbind(held).unwrap();
    assert_eq!(leases.get(held), Some(&"held"));
    assert_eq!(leases.retire(held), Ok("held"));
}

#[test]
fn durable_context_lease_find_active_uses_nearest_matching_nested_binding() {
    let mut leases = DurableContextLeases::<u64, (u64, &'static str)>::new();
    let outer_reservation = leases.reserve().unwrap();
    let outer = leases.retain(outer_reservation, 1, (1, "outer")).unwrap();
    leases.bind(outer).unwrap();
    let other_reservation = leases.reserve().unwrap();
    let other = leases.retain(other_reservation, 2, (2, "other")).unwrap();
    leases.bind(other).unwrap();
    assert_eq!(leases.find_active(|(instance, _)| *instance == 1), Some(&(1, "outer")));
    let inner_reservation = leases.reserve().unwrap();
    let inner = leases.retain(inner_reservation, 3, (1, "inner")).unwrap();
    leases.bind(inner).unwrap();
    assert_eq!(leases.find_active(|(instance, _)| *instance == 1), Some(&(1, "inner")));
    leases.unbind(inner).unwrap();
    assert_eq!(leases.find_active(|(instance, _)| *instance == 1), Some(&(1, "outer")));
    assert_eq!(leases.find_active(|(instance, _)| *instance == 3), None);
}

#[test]
fn retained_shared_bank_remains_exclusive_while_its_transfer_is_unbound() {
    let mut leases = DurableContextLeases::<u64, (usize, &'static str)>::new();
    let first = leases.reserve().unwrap();
    let outer = leases
        .retain_exclusive_by(first, 1, (0x1000, "outer"), |(bank, _)| *bank == 0x1000)
        .unwrap();
    leases.bind(outer).unwrap();
    leases.unbind(outer).unwrap();

    // A suspended parent still owns this physical page even though another transfer can
    // bind a different page. A distinct key or generation cannot authorize its overwrite.
    let duplicate = leases.reserve().unwrap();
    assert_eq!(
        leases.retain_exclusive_by(duplicate, 2, (0x1000, "duplicate"), |(bank, _)| *bank == 0x1000),
        Err((DurableContextLeaseError::ConflictingRetained, (0x1000, "duplicate"))),
    );
    assert_eq!(leases.get(outer), Some(&(0x1000, "outer")));
    assert!(leases.cancel_reservation(duplicate));

    let different = leases.reserve().unwrap();
    let inner = leases
        .retain_exclusive_by(different, 3, (0x2000, "inner"), |(bank, _)| *bank == 0x2000)
        .unwrap();
    leases.bind(inner).unwrap();
    assert_eq!(leases.active(), Some(&(0x2000, "inner")));
    leases.unbind(inner).unwrap();
    assert_eq!(leases.retire(inner), Ok((0x2000, "inner")));

    assert_eq!(leases.retire(outer), Ok((0x1000, "outer")));
    let recycled = leases.reserve().unwrap();
    let replacement = leases
        .retain_exclusive_by(recycled, 2, (0x1000, "replacement"), |(bank, _)| *bank == 0x1000)
        .unwrap();
    assert_ne!(outer, replacement);
    assert_eq!(leases.get(replacement), Some(&(0x1000, "replacement")));
}
