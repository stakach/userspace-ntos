use super::*;
use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use core::cell::Cell;

#[test]
fn equal_payloads_and_reused_slots_do_not_reuse_identity() {
    let mut table = ObjectWaiterTable::new();
    let first = table.insert((20, 50)).unwrap();
    let peer = table.insert((20, 50)).unwrap();
    assert_ne!(first, peer);
    assert_eq!(table.take(first), Some((20, 50)));
    let replacement = table.insert((20, 50)).unwrap();
    assert_eq!(first.slot(), replacement.slot());
    assert_ne!(first, replacement);
    assert_eq!(table.get_exact(first), None);
    assert_eq!(table.take(first), None);
    assert!(!table.update_exact(first, |_| panic!("stale token mutated replacement")));
    assert_eq!(table.get_exact(peer), Some(&(20, 50)));
    assert_eq!(table.get_exact(replacement), Some(&(20, 50)));
}

#[test]
fn foreign_table_tokens_cannot_read_update_or_remove_equal_rows() {
    let mut first = ObjectWaiterTable::new();
    let mut second = ObjectWaiterTable::new();
    let a = first.insert(0u64).unwrap();
    let b = second.insert(0u64).unwrap();
    assert_eq!((a.slot, a.generation), (b.slot, b.generation));
    assert_ne!(a.table, b.table);
    assert_eq!(second.get_exact(a), None);
    assert!(!second.update_exact(a, |_| panic!("foreign update")));
    assert_eq!(second.take(a), None);
    assert_eq!(first.take(b), None);
    assert_eq!(second.get_exact(b), Some(&0));
}

#[test]
fn zero_reply_payload_remains_owned_and_blocks_reset_and_reserve() {
    let mut table = ObjectWaiterTable::new();
    let id = table.insert(77u64).unwrap();
    assert!(table.update_exact(id, |reply_cap| *reply_cap = 0));
    let stats = table.stats();
    assert_eq!(table.len(), 1);
    assert!(!table.is_empty());
    assert!(!table.reset(0));
    assert!(!table.reserve(100));
    assert_eq!(table.stats(), stats);
    assert_eq!(table.get(id.slot()), Some((id, &0)));
    assert_eq!(table.take(id), Some(0));
    assert!(table.is_empty());
    assert!(table.reset(0));
}

#[test]
fn moving_table_and_reset_preserve_identity_history() {
    let mut table = ObjectWaiterTable::new();
    let id = table.insert(String::from("original")).unwrap();
    let mut moved = Box::new(table);
    assert_eq!(moved.get_exact(id).map(String::as_str), Some("original"));
    assert_eq!(moved.take(id).as_deref(), Some("original"));
    assert!(moved.reset(4));
    let replacement = moved.insert(String::from("replacement")).unwrap();
    assert_eq!(replacement.table, id.table);
    assert_eq!(replacement.slot, id.slot);
    assert_ne!(replacement.generation, id.generation);
    assert_eq!(moved.take(id), None);
}

#[test]
fn generic_instantiations_share_unique_table_identity_namespace() {
    let mut numbers = ObjectWaiterTable::new();
    let mut strings = ObjectWaiterTable::new();
    let number = numbers.insert(1).unwrap();
    let string = strings.insert(String::from("one")).unwrap();
    assert_ne!(number.table, string.table);
    assert_eq!(strings.get_exact(number), None);
    assert_eq!(numbers.get_exact(string), None);
}

#[test]
fn iteration_reports_exact_live_rows_without_assuming_slot_order_is_fifo() {
    let mut table = ObjectWaiterTable::new();
    let first = table.insert(10).unwrap();
    let second = table.insert(20).unwrap();
    let third = table.insert(30).unwrap();
    table.take(first).unwrap();
    let newest = table.insert(40).unwrap();
    let records: Vec<_> = table.iter().map(|(id, value)| (id, *value)).collect();
    assert_eq!(records, [(newest, 40), (second, 20), (third, 30)]);
    assert_eq!(table.len(), 3);
    assert_eq!(table.slot_len(), 3);
    table.take(second).unwrap();
    assert_eq!(table.len(), 2);
    assert_eq!(table.slot_len(), 3);
    assert_eq!(table.get(second.slot()), None);
}

#[test]
fn checked_identity_exhaustion_returns_owned_payload_without_publishing_or_dropping() {
    let source = AtomicU64::new(u64::MAX);
    let mut table = ObjectWaiterTable::new();
    let payload = String::from("retained");
    let pointer = payload.as_ptr();
    let returned = table
        .insert_with_identity_source(payload, &source)
        .unwrap_err();
    assert_eq!(returned.as_ptr(), pointer);
    assert_eq!(table.stats(), (0, 0, 0, 0, 1));
    assert_eq!(table.identity, 0);
    assert_eq!(table.next_generation, 1);
    let source = AtomicU64::new(1);
    table.next_generation = 0;
    assert_eq!(
        table
            .insert_with_identity_source(returned, &source)
            .unwrap_err(),
        "retained"
    );
    assert_eq!(source.load(Ordering::Relaxed), 1);
    assert_eq!(table.stats(), (0, 0, 0, 0, 2));
}

#[test]
fn last_generation_is_unique_and_reset_cannot_reopen_exhausted_namespace() {
    let mut table = ObjectWaiterTable::new();
    table.next_generation = u64::MAX;
    let last = table.insert(1).unwrap();
    assert_eq!(last.generation, u64::MAX);
    assert_eq!(table.insert(2), Err(2));
    assert_eq!(table.take(last), Some(1));
    assert!(table.reset(4));
    assert_eq!(table.insert(3), Err(3));
    assert_eq!(table.get_exact(last), None);
}

#[test]
fn invalid_identities_never_invoke_mutation_closure() {
    let mut table = ObjectWaiterTable::new();
    let id = table.insert(1).unwrap();
    for wrong in [
        ObjectWaiterIdentity { table: 0, ..id },
        ObjectWaiterIdentity {
            generation: 0,
            ..id
        },
        ObjectWaiterIdentity {
            generation: id.generation + 1,
            ..id
        },
        ObjectWaiterIdentity {
            slot: usize::MAX,
            ..id
        },
    ] {
        assert_eq!(table.get_exact(wrong), None);
        assert!(!table.update_exact(wrong, |_| panic!("invalid identity called closure")));
        assert_eq!(table.take(wrong), None);
    }
    assert_eq!(table.get_exact(id), Some(&1));
}

#[test]
fn take_and_update_preserve_storage_and_noncopy_payload_ownership() {
    #[derive(Debug)]
    struct Payload {
        value: u64,
        drops: Rc<Cell<usize>>,
    }
    impl Drop for Payload {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut table = ObjectWaiterTable::new();
    assert!(table.reserve(4));
    let id = table
        .insert(Payload {
            value: 1,
            drops: drops.clone(),
        })
        .unwrap();
    let pointer = table.entries.as_ptr();
    let capacity = table.capacity();
    table.update_exact(id, |payload| payload.value = 2);
    let payload = table.take(id).unwrap();
    assert_eq!(payload.value, 2);
    assert_eq!(drops.get(), 0);
    assert_eq!(table.entries.as_ptr(), pointer);
    assert_eq!(table.capacity(), capacity);
    drop(table);
    assert_eq!(drops.get(), 0);
    drop(payload);
    assert_eq!(drops.get(), 1);
}

#[test]
fn impossible_empty_reserve_reports_allocation_failure_without_owners() {
    let mut table = ObjectWaiterTable::<u64>::new();
    assert!(!table.reserve(usize::MAX));
    assert_eq!(table.stats(), (0, 0, 0, 1, 0));
    assert!(table.reserve(2));
    assert!(table.capacity() >= 2);
    assert_eq!(table.slot_len(), 0);
    let id = table.insert(1).unwrap();
    assert_eq!(table.take(id), Some(1));
    assert!(table.reserve(1));
    assert_eq!(table.slot_len(), 1);
    assert!(table.reset(1));
    assert_eq!(table.slot_len(), 0);
}
