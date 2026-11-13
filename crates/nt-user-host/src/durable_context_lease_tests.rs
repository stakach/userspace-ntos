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

#[test]
fn one_retained_row_excludes_both_add_device_pages_until_exact_retirement() {
    type BankOwner = (usize, Option<usize>, &'static str);
    let mut leases = DurableContextLeases::<u64, BankOwner>::new();
    let reservation = leases.reserve().unwrap();
    let add_device = leases.retain_exclusive_by(
        reservation, 1, (0x1000, Some(0x2000), "AddDevice"), |_| false,
    ).unwrap();
    leases.bind(add_device).unwrap();
    leases.unbind(add_device).unwrap();

    for (key, bank) in [(2, 0x1000), (3, 0x2000)] {
        let reservation = leases.reserve().unwrap();
        assert_eq!(leases.retain_exclusive_by(
            reservation, key, (bank, None, "File"),
            |(primary, secondary, _)| *primary == bank || *secondary == Some(bank),
        ), Err((DurableContextLeaseError::ConflictingRetained, (bank, None, "File"))));
        assert!(leases.cancel_reservation(reservation));
        assert_eq!(leases.get(add_device), Some(&(0x1000, Some(0x2000), "AddDevice")));
    }

    let other_reservation = leases.reserve().unwrap();
    let other = leases.retain_exclusive_by(
        other_reservation, 4, (0x3000, None, "File"),
        |(primary, secondary, _)| *primary == 0x3000 || *secondary == Some(0x3000),
    ).unwrap();
    leases.bind(other).unwrap();
    leases.unbind(other).unwrap();

    // If File already owns the provider page, an AddDevice pair cannot partially claim its
    // primary page and proceed to publish either page.
    assert_eq!(leases.retire(add_device), Ok((0x1000, Some(0x2000), "AddDevice")));
    let reservation = leases.reserve().unwrap();
    let file = leases.retain_exclusive_by(
        reservation, 5, (0x2000, None, "File"),
        |(primary, secondary, _)| *primary == 0x2000 || *secondary == Some(0x2000),
    ).unwrap();
    let pair_reservation = leases.reserve().unwrap();
    assert_eq!(leases.retain_exclusive_by(
        pair_reservation, 6, (0x1000, Some(0x2000), "AddDevice"),
        |(primary, secondary, _)| *primary == 0x1000 || *secondary == Some(0x1000)
            || *primary == 0x2000 || *secondary == Some(0x2000),
    ), Err((DurableContextLeaseError::ConflictingRetained,
        (0x1000, Some(0x2000), "AddDevice"))));
    assert!(leases.cancel_reservation(pair_reservation));
    assert_eq!(leases.retire(file), Ok((0x2000, None, "File")));
    assert_eq!(leases.retire(other), Ok((0x3000, None, "File")));
    let replacement = leases.reserve().unwrap();
    assert!(leases.retain_exclusive_by(
        replacement, 7, (0x1000, Some(0x2000), "AddDevice"), |_| false,
    ).is_ok());
}
