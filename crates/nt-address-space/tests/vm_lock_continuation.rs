use nt_address_space::{vm_lock_continuation::VmLockPageContinuation, VmResidencyRangePlan};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Owner { process_generation: u64, thread_generation: u64, reply: u64 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Source { section: u64, view: u64, lease: u64 }

#[test]
fn two_page_lock_waits_for_exact_pending_ack_and_page_publication() {
    let owner = Owner { process_generation: 3, thread_generation: 7, reply: 11 };
    let stale = Owner { thread_generation: 6, ..owner };
    let source = Source { section: 13, view: 17, lease: 19 };
    let stale_source = Source { lease: 18, ..source };
    let range = VmResidencyRangePlan::new(0x1000, 0x2000, 0x1_0000).unwrap();
    let mut lock = VmLockPageContinuation::<Owner, Source, u64>::new(owner, range);
    assert_eq!(lock.next_page(owner), Some(0x1000));
    assert!(lock.mark_inline_resident(owner, 0x1000));
    assert_eq!(lock.next_page(owner), Some(0x2000));
    assert!(lock.begin_pending(owner, 0x2000, source, 23));
    assert!(!lock.ready_to_commit(owner));
    assert!(!lock.mark_pending_resident(owner, 0x2000, source, 23),
        "a pending provider read cannot publish page 2 before exact ACK");
    assert!(!lock.acknowledge_pending(stale, 0x2000, source, 23));
    assert!(!lock.acknowledge_pending(owner, 0x2000, stale_source, 23));
    assert!(!lock.acknowledge_pending(owner, 0x2000, source, 24));
    assert!(lock.acknowledge_pending(owner, 0x2000, source, 23));
    assert!(!lock.acknowledge_pending(owner, 0x2000, source, 23));
    assert!(lock.mark_pending_resident(owner, 0x2000, source, 23));
    assert!(lock.ready_to_commit(owner));
    assert!(!lock.begin_pending(owner, 0x2000, source, 23));
    assert!(!lock.ready_to_commit(stale));
}

#[test]
fn cancelled_or_uncertain_page_never_commits_a_lock() {
    let owner = Owner { process_generation: 1, thread_generation: 2, reply: 3 };
    let source = Source { section: 4, view: 5, lease: 6 };
    let range = VmResidencyRangePlan::new(0x1000, 0x1000, 0x1_0000).unwrap();
    let mut cancelled = VmLockPageContinuation::<Owner, Source, u64>::new(owner, range);
    assert!(cancelled.begin_pending(owner, 0x1000, source, 7));
    assert!(cancelled.request_cancel(owner));
    assert!(!cancelled.mark_pending_resident(owner, 0x1000, source, 7));
    assert!(cancelled.acknowledge_pending(owner, 0x1000, source, 7));
    assert!(cancelled.retire_cancelled_pending(owner, 0x1000, source, 7));
    assert!(!cancelled.ready_to_commit(owner));
    let mut uncertain = VmLockPageContinuation::<Owner, Source, u64>::new(owner, range);
    assert!(uncertain.begin_pending(owner, 0x1000, source, 8));
    assert!(uncertain.quarantine(owner, 0x1000, source, 8));
    assert!(!uncertain.acknowledge_pending(owner, 0x1000, source, 8));
    assert!(!uncertain.ready_to_commit(owner));
}
