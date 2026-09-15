use super::*;

fn now(monotonic_100ns: u64, system_time_100ns: u64) -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns,
        system_time_100ns,
        clock_generation: 0,
    }
}

fn waiter(deadline: Deadline, thread_id: u64) -> Waiter {
    Waiter {
        deadline,
        sequence: 0,
        reply_cap: thread_id + 100,
        thread_id,
        badge: thread_id + 200,
    }
}

#[test]
fn growing_nonempty_capacity_preserves_waiters_and_fifo() {
    let mut queue = Queue::new();
    assert!(queue.reserve_capacity(8));
    let first = waiter(due_time(-10, 100, 1_000), 1);
    let mut second = waiter(first.deadline, 2);
    second.sequence = 1;
    queue.insert(first).unwrap();
    queue.insert(second).unwrap();
    let target = queue.capacity() + 1;
    assert!(queue.reserve_capacity(target));
    assert!(queue.capacity() >= target);
    assert_eq!(queue.records(), 2);
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.next_deadline(now(100, 1_000)), Some(110));
    assert_eq!(queue.pop_due(now(110, 1_010)), Some(first));
    assert_eq!(queue.pop_due(now(110, 1_010)), Some(second));
}

#[test]
fn reservation_preserves_holes_and_sequence_for_reused_slots() {
    let mut queue = Queue::new();
    let deadline = due_time(-10, 0, 1_000);
    queue.insert(waiter(deadline, 1)).unwrap();
    queue.insert(waiter(deadline, 2)).unwrap();
    assert_eq!(queue.pop_thread(1).unwrap().sequence, 0);
    for minimum in [0, queue.capacity(), queue.capacity() + 1] {
        assert!(queue.reserve_capacity(minimum));
        assert_eq!(queue.records(), 2);
        assert_eq!(queue.len(), 1);
    }
    queue.insert(waiter(deadline, 3)).unwrap();
    assert_eq!(queue.records(), 2);
    let older = queue.pop_due(now(10, 1_010)).unwrap();
    let newer = queue.pop_due(now(10, 1_010)).unwrap();
    assert_eq!((older.thread_id, older.sequence), (2, 1));
    assert_eq!((newer.thread_id, newer.sequence), (3, 2));
}

#[test]
fn failed_reservation_retains_exact_ownership_and_order() {
    let mut queue = Queue::new();
    let first = waiter(due_time(-10, 0, 1_000), 1);
    queue.insert(first).unwrap();
    let capacity = queue.capacity();
    // Capacity overflow is deterministic and does not ask the allocator for huge memory.
    assert!(!queue.reserve_capacity(usize::MAX));
    assert_eq!(queue.capacity(), capacity);
    assert_eq!(queue.records(), 1);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.allocation_failures(), 1);
    assert_eq!(queue.store_failures(), 0);
    assert!(queue.reserve_capacity(capacity + 1));
    assert_eq!(queue.allocation_failures(), 1);
    queue.insert(waiter(first.deadline, 2)).unwrap();
    assert_eq!(queue.pop_due(now(10, 1_010)), Some(first));
    assert_eq!(queue.pop_due(now(10, 1_010)).unwrap().sequence, 1);
}

#[test]
fn handoff_preserves_timeout_domains_and_infinite_wait_ownership() {
    let mut bootstrap = Queue::new();
    let relative = waiter(due_time(-100, 10, 1_000), 1);
    let mut absolute = waiter(due_time(1_200, 10, 1_000), 2);
    absolute.sequence = 1;
    let mut infinite = waiter(Deadline::Infinite, 3);
    infinite.sequence = 2;
    bootstrap.insert(relative).unwrap();
    bootstrap.insert(absolute).unwrap();
    bootstrap.insert(infinite).unwrap();
    let mut runtime = bootstrap;
    assert!(runtime.reserve_capacity(64));
    // A system-clock jump expires only the absolute waiter, not the monotonic one.
    assert_eq!(runtime.pop_due(now(20, 1_300)), Some(absolute));
    assert_eq!(runtime.next_deadline(now(20, 1_300)), Some(110));
    assert_eq!(runtime.pop_due(now(109, 1_389)), None);
    assert_eq!(runtime.pop_due(now(110, 1_390)), Some(relative));
    assert_eq!(runtime.next_deadline(now(110, 1_390)), None);
    assert_eq!(runtime.pop_due(now(u64::MAX, u64::MAX)), None);
    assert_eq!(runtime.pop_thread(3), Some(infinite));
    assert_eq!(runtime.len(), 0);
}
