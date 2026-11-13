//! Behaviour of the generation-protected slot ledger behind the executive's compact
//! object namespace table: a create/close workload keeps the table bounded, a stale
//! index+generation never resolves to the slot's next occupant, and a slot that is still
//! referenced is never handed out again.

use nt_object_manager::slot_ledger::{SlotError, SlotLedger, SlotRef};
use std::collections::VecDeque;

#[test]
fn create_and_close_of_twenty_thousand_objects_with_eight_live_stays_bounded() {
    let mut ledger = SlotLedger::new();
    let mut live: VecDeque<SlotRef> = VecDeque::new();
    for _ in 0..20_000 {
        if live.len() == 8 {
            let oldest = live.pop_front().unwrap();
            assert_eq!(ledger.release(oldest, 0), Ok(()));
        }
        live.push_back(ledger.allocate().unwrap());
        assert!(ledger.census().slots <= 8, "table grew to {}", ledger.census().slots);
    }
    let census = ledger.census();
    assert_eq!(census.slots, 8);
    assert_eq!(census.free, 0);
    assert!(live.iter().all(|slot| ledger.is_current(*slot)));
}

#[test]
fn a_burst_grows_the_table_once_and_later_bursts_reuse_it() {
    let mut ledger = SlotLedger::new();
    for round in 0..50 {
        let burst: Vec<SlotRef> = (0..64).map(|_| ledger.allocate().unwrap()).collect();
        assert_eq!(ledger.census().slots, 64, "round {round}");
        for slot in burst {
            assert_eq!(ledger.release(slot, 0), Ok(()));
        }
        assert_eq!(ledger.census().free, 64);
    }
}

#[test]
fn stale_index_and_generation_are_rejected_after_reuse() {
    let mut ledger = SlotLedger::new();
    let old = ledger.allocate().unwrap();
    assert!(ledger.is_current(old));
    assert_eq!(ledger.release(old, 0), Ok(()));
    assert!(!ledger.is_current(old), "a released slot no longer names its occupant");

    let new = ledger.allocate().unwrap();
    assert_eq!(new.index(), old.index(), "the only free slot is reused");
    assert_ne!(new.generation(), old.generation());
    assert!(ledger.is_current(new));
    assert!(!ledger.is_current(old), "the previous occupant's reference is stale");
    assert_eq!(ledger.current(old.index()), Some(new));

    // A late release through the stale reference must not free the new occupant.
    assert_eq!(ledger.release(old, 0), Err(SlotError::Stale));
    assert!(ledger.is_current(new));
    assert_eq!(ledger.census().free, 0);
}

#[test]
fn a_referenced_slot_is_not_reused_until_its_references_drain() {
    let mut ledger = SlotLedger::new();
    let waited_on = ledger.allocate().unwrap();
    // One waiter (or handle, or provider reference) still names the object.
    assert_eq!(ledger.release(waited_on, 1), Err(SlotError::Referenced));
    assert!(ledger.is_current(waited_on));

    for _ in 0..1_000 {
        let other = ledger.allocate().unwrap();
        assert_ne!(other.index(), waited_on.index());
        assert_eq!(ledger.release(other, 0), Ok(()));
    }
    assert!(ledger.is_current(waited_on));
    assert_eq!(ledger.census().slots, 2);

    // The last reference drains: the slot becomes reusable under a new generation.
    assert_eq!(ledger.release(waited_on, 0), Ok(()));
    let reused: Vec<SlotRef> = (0..2).map(|_| ledger.allocate().unwrap()).collect();
    let successor = reused
        .iter()
        .find(|slot| slot.index() == waited_on.index())
        .expect("the drained slot is reused");
    assert_ne!(successor.generation(), waited_on.generation());
    assert_eq!(ledger.census().slots, 2);
}

#[test]
fn generations_are_unique_across_every_slot_and_never_zero() {
    let mut ledger = SlotLedger::new();
    let mut seen = std::collections::HashSet::new();
    let mut live = Vec::new();
    for step in 0..5_000usize {
        let slot = ledger.allocate().unwrap();
        assert_ne!(slot.generation(), 0);
        assert!(seen.insert(slot.generation()), "generation issued twice");
        live.push(slot);
        if step % 3 != 0 {
            let victim = live.swap_remove(step % live.len());
            assert_eq!(ledger.release(victim, 0), Ok(()));
        }
    }
}

#[test]
fn retired_slots_are_reused_oldest_first() {
    let mut ledger = SlotLedger::new();
    let slots: Vec<SlotRef> = (0..4).map(|_| ledger.allocate().unwrap()).collect();
    for slot in [slots[2], slots[0], slots[3]] {
        assert_eq!(ledger.release(slot, 0), Ok(()));
    }
    // The slot retired longest ago is reused first, so a just-retired index stays
    // vacant for as long as the table allows.
    assert_eq!(ledger.allocate().unwrap().index(), slots[2].index());
    assert_eq!(ledger.allocate().unwrap().index(), slots[0].index());
    assert_eq!(ledger.allocate().unwrap().index(), slots[3].index());
    assert_eq!(ledger.allocate().unwrap().index(), 4);
}

#[test]
fn double_release_and_unknown_slots_are_stale() {
    let mut ledger = SlotLedger::new();
    let slot = ledger.allocate().unwrap();
    assert_eq!(ledger.release(slot, 0), Ok(()));
    assert_eq!(ledger.release(slot, 0), Err(SlotError::Stale));
    assert_eq!(ledger.census().free, 1, "a double release must not free the slot twice");
    assert_eq!(ledger.current(slot.index()), None);
    assert_eq!(ledger.current(99), None);

    let first = ledger.allocate().unwrap();
    let second = ledger.allocate().unwrap();
    assert_ne!(first.index(), second.index(), "one free slot satisfies one allocation");
}

#[test]
fn reservation_covers_the_next_allocations_and_counts_free_slots() {
    let mut ledger = SlotLedger::new();
    let slots: Vec<SlotRef> = (0..3).map(|_| ledger.allocate().unwrap()).collect();
    assert_eq!(ledger.release(slots[1], 0), Ok(()));
    assert_eq!(ledger.appends_needed(1), 0, "the free slot covers one allocation");
    assert_eq!(ledger.appends_needed(3), 2);
    assert_eq!(ledger.reserve(3), Ok(()));
    let census = ledger.census();
    assert_eq!((census.slots, census.free), (3, 1), "reservation does not occupy slots");
    for _ in 0..3 {
        ledger.allocate().unwrap();
    }
    assert_eq!(ledger.census().slots, 5);
}

#[test]
fn a_retired_index_stays_vacant_until_the_reuse_delay_has_passed() {
    let delay = 16;
    let mut ledger = SlotLedger::with_reuse_delay(delay);
    let first = ledger.allocate().unwrap();
    assert_eq!(ledger.release(first, 0), Ok(()));

    // The next `delay` create/close cycles must not hand `first`'s index out again.
    for _ in 0..delay {
        let slot = ledger.allocate().unwrap();
        assert_ne!(slot.index(), first.index(), "retired index reused inside the delay");
        assert_eq!(ledger.release(slot, 0), Ok(()));
    }
    assert_eq!(ledger.allocate().unwrap().index(), first.index());
}

#[test]
fn a_delayed_ledger_under_churn_is_bounded_by_live_plus_delay() {
    let delay = 64;
    let mut ledger = SlotLedger::with_reuse_delay(delay);
    let mut live: VecDeque<SlotRef> = VecDeque::new();
    for _ in 0..20_000 {
        if live.len() == 8 {
            let oldest = live.pop_front().unwrap();
            assert_eq!(ledger.release(oldest, 0), Ok(()));
        }
        live.push_back(ledger.allocate().unwrap());
    }
    let census = ledger.census();
    assert!(census.slots <= 8 + delay + 1, "table grew to {}", census.slots);
    assert_eq!(ledger.appends_needed(1), usize::from(census.free <= delay));
}
