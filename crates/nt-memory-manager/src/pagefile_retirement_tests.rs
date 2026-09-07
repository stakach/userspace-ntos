use super::super::{allocate_pagefile_id, PagefileStoreStats};
use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct Io {
    calls: Vec<(&'static str, u64)>,
    fail_unmap: bool,
    fail_revoke: bool,
}

impl PagefileRetirementIo for Io {
    fn unmap(&mut self, backing: u64) -> Result<(), u32> {
        self.calls.push(("unmap", backing));
        if self.fail_unmap {
            Err(41)
        } else {
            Ok(())
        }
    }
    fn revoke(&mut self, backing: u64) -> Result<(), u32> {
        self.calls.push(("revoke", backing));
        if self.fail_revoke {
            Err(42)
        } else {
            Ok(())
        }
    }
}

fn page(owner: u64, address: u64, backing: u64) -> PagefilePage {
    PagefilePage {
        owner,
        page: address,
        protection: 4,
        backing,
    }
}

fn store_with(pages: &[PagefilePage]) -> PagefileStore {
    let mut store = PagefileStore::new();
    for page in pages {
        let plan = store.prepare_publish(*page).unwrap();
        store.commit_publish(plan).unwrap();
    }
    store
}

fn begin(store: &mut PagefileStore, page: PagefilePage) -> PagefileRetirement {
    store
        .begin_retirement(page.owner, page.page)
        .unwrap()
        .unwrap()
}

#[test]
fn begin_retains_description_and_excludes_available_operations() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    let before = store.generation;
    let snapshot = begin(&mut store, original);
    assert_eq!(snapshot.page(), original);
    assert!(!snapshot.cleanup_complete());
    assert_eq!(store.generation, before + 1);
    assert_eq!(begin(&mut store, original), snapshot);
    assert_eq!(store.generation, before + 1);
    assert_eq!(store.retiring_count(), 1);
    assert!(store.contains(2, 0x1000));
    assert_eq!(store.page(2, 0x1000), None);
    assert_eq!(store.first_for_owner(2), Some(original));
    assert_eq!(store.pages_for_owner(2).collect::<Vec<_>>(), [0x1000]);
    assert_eq!(store.take(2, 0x1000), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(store.restore(original), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        store.prepare_publish(original),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn unmap_failure_remains_owned_and_retry_performs_each_acknowledgement_once() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    let snapshot = begin(&mut store, original);
    let mut io = Io {
        fail_unmap: true,
        ..Io::default()
    };
    assert_eq!(store.cleanup_retirement_exact(snapshot, &mut io), Err(41));
    assert_eq!(begin(&mut store, original), snapshot);
    assert_eq!(io.calls, [("unmap", 11)]);
    io.fail_unmap = false;
    let ready = store.cleanup_retirement_exact(snapshot, &mut io).unwrap();
    assert!(ready.cleanup_complete());
    assert_eq!(io.calls, [("unmap", 11), ("unmap", 11), ("revoke", 11)]);
    assert_eq!(store.cleanup_retirement_exact(ready, &mut io), Ok(ready));
    assert_eq!(io.calls.len(), 3);
}

#[test]
fn revoke_failure_retains_unmap_and_stale_phase_is_rejected_before_effects() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    let snapshot = begin(&mut store, original);
    let mut io = Io {
        fail_revoke: true,
        ..Io::default()
    };
    assert_eq!(store.cleanup_retirement_exact(snapshot, &mut io), Err(42));
    let partial = begin(&mut store, original);
    assert!(partial.unmapped);
    assert!(!partial.revoked);
    assert_eq!(
        store.cleanup_retirement_exact(snapshot, &mut io),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(io.calls.len(), 2);
    io.fail_revoke = false;
    let ready = store.cleanup_retirement_exact(partial, &mut io).unwrap();
    assert!(ready.cleanup_complete());
    assert_eq!(io.calls, [("unmap", 11), ("revoke", 11), ("revoke", 11)]);
}

#[test]
fn publication_failure_retains_ready_owner_and_success_removes_exact_record() {
    let original = page(2, 0x1000, 11);
    let other = page(3, 0x1000, 12);
    let mut store = store_with(&[original, other]);
    let snapshot = begin(&mut store, original);
    let ready = store
        .cleanup_retirement_exact(snapshot, &mut Io::default())
        .unwrap();
    let stats = store.stats();
    let generation = store.generation;
    assert_eq!(
        store.complete_retirement_with(ready, |backing| {
            assert_eq!(backing, 11);
            Err(43)
        }),
        Err(43)
    );
    assert_eq!(store.stats(), stats);
    assert_eq!(store.generation, generation);
    assert_eq!(begin(&mut store, original), ready);
    assert_eq!(
        store.complete_retirement_with(ready, |backing| {
            assert_eq!(backing, 11);
            Ok(())
        }),
        Ok(())
    );
    assert!(!store.contains(2, 0x1000));
    assert_eq!(store.page(3, 0x1000), Some(other));
    assert_eq!(store.retiring_count(), 0);
    assert_eq!(store.stats().retirements, 1);
    assert_eq!(store.stats().pages, 1);
    assert_eq!(
        store.complete_retirement_with(ready, |_| panic!("stale publication")),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn incomplete_cleanup_cannot_publish() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    let snapshot = begin(&mut store, original);
    assert_eq!(
        store.complete_retirement_with(snapshot, |_| panic!("premature publication")),
        Err(STATUS_INVALID_PARAMETER)
    );
    let mut io = Io {
        fail_revoke: true,
        ..Io::default()
    };
    assert_eq!(store.cleanup_retirement_exact(snapshot, &mut io), Err(42));
    let partial = begin(&mut store, original);
    assert_eq!(
        store.complete_retirement_with(partial, |_| panic!("premature publication")),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn begin_generation_exhaustion_has_no_effect_and_absent_owner_needs_no_generation() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    store.generation = u64::MAX;
    assert_eq!(
        store.begin_retirement(2, 0x1000),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(store.page(2, 0x1000), Some(original));
    assert_eq!(store.retiring_count(), 0);
    assert_eq!(store.begin_retirement(19, 0x1000), Ok(None));
    assert_eq!(store.generation, u64::MAX);
}

#[test]
fn completion_reserves_generation_before_publication_but_cleanup_can_finish_at_limit() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    store.generation = u64::MAX - 1;
    let snapshot = begin(&mut store, original);
    assert_eq!(store.generation, u64::MAX);
    assert_eq!(begin(&mut store, original), snapshot);
    let ready = store
        .cleanup_retirement_exact(snapshot, &mut Io::default())
        .unwrap();
    assert_eq!(
        store.complete_retirement_with(ready, |_| panic!("generation not reserved")),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(begin(&mut store, original), ready);
    assert_eq!(store.retiring_count(), 1);
}

#[test]
fn final_generation_can_commit_one_ready_retirement() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    store.generation = u64::MAX - 2;
    let snapshot = begin(&mut store, original);
    let ready = store
        .cleanup_retirement_exact(snapshot, &mut Io::default())
        .unwrap();
    store.complete_retirement_with(ready, |_| Ok(())).unwrap();
    assert_eq!(store.generation, u64::MAX);
    assert_eq!(store.retiring_count(), 0);
    assert_eq!(store.begin_retirement(2, 0x1000), Ok(None));
}

#[test]
fn beginning_retirement_invalidates_prepared_publication_and_protection() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    let publish = store.prepare_publish(page(2, 0x2000, 12)).unwrap();
    let protect = store.prepare_protection(2, 0x1000, 2).unwrap().unwrap();
    begin(&mut store, original);
    assert_eq!(store.commit_publish(publish), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        store.commit_protection(protect),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(!store.contains(2, 0x2000));
}

#[test]
fn retirement_blocks_protection_even_for_noop_and_sparse_ranges() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original, page(2, 0x3000, 12), page(3, 0x1000, 13)]);
    begin(&mut store, original);
    for protection in [2, 4] {
        assert_eq!(
            store.prepare_protection(2, 0x1000, protection),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            store.prepare_protection_range(2, 0, 0x4000, protection),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    let unrelated = store.prepare_protection(2, 0x3000, 2).unwrap().unwrap();
    store.commit_protection(unrelated).unwrap();
    let other_owner = store.prepare_protection(3, 0x1000, 2).unwrap().unwrap();
    store.commit_protection(other_owner).unwrap();
    assert_eq!(store.page(2, 0x3000).unwrap().protection, 2);
    assert_eq!(store.page(3, 0x1000).unwrap().protection, 2);
}

#[test]
fn acknowledged_cleanup_does_not_stale_unrelated_plans_or_retirement_snapshots() {
    let first = page(2, 0x1000, 11);
    let second = page(2, 0x3000, 12);
    let mut store = store_with(&[first, second]);
    let snapshot = begin(&mut store, first);
    let plan = store.prepare_protection(2, 0x3000, 2).unwrap().unwrap();
    let publish = store.prepare_publish(page(3, 0x1000, 13)).unwrap();
    let ready = store
        .cleanup_retirement_exact(snapshot, &mut Io::default())
        .unwrap();
    store.commit_protection(plan).unwrap();
    assert_eq!(
        store.cleanup_retirement_exact(ready, &mut Io::default()),
        Ok(ready)
    );
    assert_eq!(store.commit_publish(publish), Err(STATUS_INVALID_PARAMETER));
    let publish = store.prepare_publish(page(3, 0x1000, 13)).unwrap();
    store
        .cleanup_retirement_exact(ready, &mut Io::default())
        .unwrap();
    store.commit_publish(publish).unwrap();
    store.complete_retirement_with(ready, |_| Ok(())).unwrap();
}

#[test]
fn memory_exclusion_is_half_open_owner_scoped_and_removed_only_at_completion() {
    let original = page(2, 0x1000, 11);
    let mut store = store_with(&[original]);
    assert!(store.memory_available(2, 0x1000, 1));
    assert!(!store.memory_available(2, u64::MAX, 1));
    let snapshot = begin(&mut store, original);
    for (base, size) in [(0x1000, 1), (0x1fff, 1), (0xfff, 2), (0, 0x2000)] {
        assert!(!store.memory_available(2, base, size));
        assert!(store.memory_available(3, base, size));
    }
    for (base, size) in [(0, 0x1000), (0x2000, 1), (0x1000, 0), (u64::MAX, 0)] {
        assert!(store.memory_available(2, base, size));
    }
    let ready = store
        .cleanup_retirement_exact(snapshot, &mut Io::default())
        .unwrap();
    assert!(!store.memory_available(2, 0x1000, 1));
    assert_eq!(store.complete_retirement_with(ready, |_| Err(43)), Err(43));
    assert!(!store.memory_available(2, 0x1000, 1));
    store.complete_retirement_with(ready, |_| Ok(())).unwrap();
    assert!(store.memory_available(2, 0x1000, 1));
}

#[test]
fn snapshots_cannot_cross_stores_or_delete_recreated_records() {
    let original = page(2, 0x1000, 11);
    let mut a = store_with(&[original]);
    let mut b = store_with(&[original]);
    let a_snapshot = begin(&mut a, original);
    let b_snapshot = begin(&mut b, original);
    assert_ne!(a_snapshot.record_id, b_snapshot.record_id);
    let mut io = Io::default();
    assert_eq!(
        b.cleanup_retirement_exact(a_snapshot, &mut io),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        b.complete_retirement_with(a_snapshot, |_| panic!("foreign publication")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(io.calls.is_empty());
    let ready = a.cleanup_retirement_exact(a_snapshot, &mut io).unwrap();
    a.complete_retirement_with(ready, |_| Ok(())).unwrap();
    a.restore(original).unwrap();
    let replacement = begin(&mut a, original);
    assert_ne!(replacement.record_id, ready.record_id);
    let calls = io.calls.len();
    assert_eq!(
        a.cleanup_retirement_exact(ready, &mut io),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        a.complete_retirement_with(ready, |_| panic!("replacement publication")),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(io.calls.len(), calls);
    assert_eq!(begin(&mut a, original), replacement);
}

#[test]
fn plans_are_store_bound_even_when_generations_and_capacity_match() {
    let original = page(2, 0x1000, 11);
    let mut a = store_with(&[original]);
    let mut b = store_with(&[original]);
    let publish = a.prepare_publish(page(2, 0x2000, 12)).unwrap();
    let _other = b.prepare_publish(page(2, 0x2000, 12)).unwrap();
    let protect = a.prepare_protection(2, 0x1000, 2).unwrap().unwrap();
    assert_eq!(b.commit_publish(publish), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(b.commit_protection(protect), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(b.page(2, 0x1000), Some(original));
    assert!(!b.contains(2, 0x2000));
    a.commit_publish(publish).unwrap();
}

#[test]
fn partial_rundown_preserves_other_owners_and_each_retained_row() {
    let a = page(2, 0x1000, 11);
    let b = page(2, 0x2000, 12);
    let c = page(3, 0x1000, 13);
    let mut store = store_with(&[a, b, c]);
    let a_snapshot = begin(&mut store, a);
    let b_snapshot = begin(&mut store, b);
    assert_eq!(store.retiring_count(), 2);
    assert_eq!(
        store.retirements().collect::<Vec<_>>(),
        [a_snapshot, b_snapshot]
    );
    let mut io = Io {
        fail_revoke: true,
        ..Io::default()
    };
    assert_eq!(store.cleanup_retirement_exact(a_snapshot, &mut io), Err(42));
    let a_partial = begin(&mut store, a);
    io.fail_revoke = false;
    let b_ready = store.cleanup_retirement_exact(b_snapshot, &mut io).unwrap();
    store.complete_retirement_with(b_ready, |_| Ok(())).unwrap();
    assert_eq!(store.retirements().collect::<Vec<_>>(), [a_partial]);
    assert_eq!(store.retiring_count(), 1);
    assert_eq!(store.first_for_owner(2), Some(a));
    assert_eq!(store.page(3, 0x1000), Some(c));
    let a_ready = store.cleanup_retirement_exact(a_partial, &mut io).unwrap();
    store.complete_retirement_with(a_ready, |_| Ok(())).unwrap();
    assert_eq!(store.first_for_owner(2), None);
    assert_eq!(store.retirements().count(), 0);
    assert_eq!(store.stats().retirements, 2);
}

#[test]
fn empty_and_available_stores_report_no_pending_retirements() {
    let mut store = PagefileStore::new();
    assert_eq!(store.stats(), PagefileStoreStats::default());
    assert_eq!(store.retirements().count(), 0);
    assert_eq!(store.begin_retirement(2, 0x1000), Ok(None));
    store.restore(page(2, 0x1000, 11)).unwrap();
    assert_eq!(store.retiring_count(), 0);
    assert_eq!(store.retirements().count(), 0);
}

#[test]
fn identity_exhaustion_never_wraps_or_publishes_an_unidentified_record() {
    let counter = AtomicU64::new(u64::MAX - 1);
    let mut store = PagefileStore::new();
    assert_eq!(
        store.prepare_publish_with_counter(page(2, 0x1000, 11), &counter),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    assert_ne!(store.identity, 0);
    assert_eq!(store.stats().pages, 0);
    assert_eq!(store.generation, 1);
    assert_eq!(
        store.prepare_publish_with_counter(page(2, 0x1000, 11), &counter),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(
        allocate_pagefile_id(&counter),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    let zero = AtomicU64::new(0);
    assert_eq!(
        allocate_pagefile_id(&zero),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(zero.load(Ordering::Relaxed), 0);
}

#[test]
fn final_allocatable_identity_is_consumed_during_prepare_not_commit() {
    let counter = AtomicU64::new(u64::MAX - 2);
    let mut store = PagefileStore::new();
    let original = page(2, 0x1000, 11);
    let plan = store
        .prepare_publish_with_counter(original, &counter)
        .unwrap();
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    store.commit_publish(plan).unwrap();
    assert_eq!(store.page(2, 0x1000), Some(original));
    assert_eq!(
        store.prepare_publish_with_counter(page(2, 0x2000, 12), &counter),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(store.page(2, 0x1000), Some(original));
}

#[test]
fn invalid_page_bounds_cannot_enter_retirement_overlap_accounting() {
    let mut store = PagefileStore::new();
    for invalid in [
        page(2, 0x1001, 11),
        page(2, u64::MAX & !0xfff, 11),
        page(2, 0x1000, 0),
    ] {
        assert_eq!(
            store.prepare_publish(invalid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(store.restore(invalid), Err(STATUS_INVALID_PARAMETER));
    }
    assert_eq!(store.stats().pages, 0);
    assert_eq!(store.identity, 0);
}
