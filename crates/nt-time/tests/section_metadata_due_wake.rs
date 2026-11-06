use nt_time::CoalescedRetryWake;

#[test]
fn overdue_retained_work_wakes_once_until_outer_redrive_or_new_publication() {
    let wake = CoalescedRetryWake::new();
    wake.publish(100);
    assert_eq!(wake.next_deadline(true), Some(100));
    assert!(!wake.wake_due(99, true));
    assert!(wake.wake_due(100, true));
    for now in 100..200 {
        assert_eq!(wake.next_deadline(true), None);
        assert!(!wake.wake_due(now, true));
        assert!(wake.begin_redrive(now, true).is_some());
    }
    // The physical work is still retained, but a fresh publication is independent demand.
    wake.publish(150);
    assert_eq!(wake.next_deadline(true), Some(150));
    assert!(wake.wake_due(150, true));
    // Only the outer redrive establishes the next retry deadline.
    wake.publish(250);
    assert_eq!(wake.next_deadline(true), Some(250));
    assert!(!wake.wake_due(249, true));
    wake.publish(170);
    assert_eq!(wake.next_deadline(true), Some(170),
        "new work outranks an existing later retry");
    assert_eq!(wake.next_deadline(false), None);
}

#[test]
fn nested_publication_survives_outer_retry_scheduling() {
    let wake = CoalescedRetryWake::new();
    wake.publish(100);
    assert!(wake.wake_due(100, true));
    let outer = wake.begin_redrive(100, true).expect("due outer owner");
    // A nested provider callback publishes another retained request before the outer owner
    // finishes its attempted redrive.
    wake.publish(120);
    assert!(!outer.retry_at(200),
        "the old attempt cannot overwrite newer earlier demand");
    assert_eq!(wake.next_deadline(true), Some(120));
    assert!(wake.wake_due(120, true));

    let next = wake.begin_redrive(120, true).expect("new due owner");
    assert!(next.retry_at(250));
    assert_eq!(wake.next_deadline(true), Some(250));
}
