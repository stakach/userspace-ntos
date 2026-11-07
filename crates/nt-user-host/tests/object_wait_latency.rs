use nt_user_host::object_wait::{ObjectWaitLatencyStamp, ObjectWaiterTable};

#[test]
fn exact_wait_owner_retains_first_selection_and_separates_reply_delay() {
    // Monotonic 100 ns units. A retry must not turn a long scheduler wait into
    // a short one by resetting its first selection timestamp.
    let mut table = ObjectWaiterTable::new();
    let owner = table.insert(ObjectWaitLatencyStamp::new(10_000)).unwrap();
    assert_eq!(table.get_exact(owner).unwrap().parked_age_100ns(25_000), Some(15_000));
    assert!(table.update_exact(owner, |stamp| {
        assert!(stamp.mark_selected(30_000));
        assert!(!stamp.mark_selected(60_000));
    }));
    assert_eq!(table.get_exact(owner).unwrap().ages_at_reply(80_000),
        Some((20_000, 50_000)));
    assert_eq!(table.get_exact(owner).unwrap().ages_at_reply(29_999), None);

    // The old slot number is not authority after retirement and reuse. A
    // delayed wake/reply sample cannot attach to the new owner in that slot.
    table.take(owner).unwrap();
    let replacement = table.insert(ObjectWaitLatencyStamp::new(90_000)).unwrap();
    assert_eq!(replacement.slot(), owner.slot());
    assert!(!table.update_exact(owner, |stamp| {
        stamp.mark_selected(100_000);
    }));
    assert!(table.get_exact(owner).is_none());
    assert_eq!(table.get_exact(replacement).unwrap().ages_at_reply(110_000), None);
}
