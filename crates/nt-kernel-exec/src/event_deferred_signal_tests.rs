use crate::{EventKind, EventStore, IrqlState, WaitResult};

#[test]
fn prepared_completion_is_not_visible_until_exact_commit() {
    let mut events = EventStore::new();
    events.initialize(7, EventKind::Synchronization, false);
    let token = events.begin_deferred_signal(7).unwrap();
    assert_eq!(token.native_identity(), 7);
    assert_eq!(
        events.query_existing(7),
        Some((EventKind::Synchronization, false))
    );
    assert_eq!(events.poll(7, &IrqlState::new()), WaitResult::TimedOut);
    assert!(!events.consume_existing(7));
    assert_eq!(events.commit_deferred_signal(token), Ok(false));
    assert_eq!(events.poll(7, &IrqlState::new()), WaitResult::Signaled);
    assert_eq!(events.poll(7, &IrqlState::new()), WaitResult::TimedOut);
    assert_eq!(events.commit_deferred_signal(token), Err(()));
}

#[test]
fn unrelated_signal_and_wait_are_not_hidden_by_preparation() {
    let mut events = EventStore::new();
    events.initialize(8, EventKind::Synchronization, true);
    let token = events.begin_deferred_signal(8).unwrap();
    assert_eq!(events.poll(8, &IrqlState::new()), WaitResult::Signaled);
    assert!(!events.read_state(8));
    events.set_existing(8).unwrap();
    assert!(events.consume_existing(8));
    assert_eq!(events.commit_deferred_signal(token), Ok(false));
    assert!(events.consume_existing(8));
}

#[test]
fn reset_before_publication_does_not_erase_a_later_completion_signal() {
    let mut events = EventStore::new();
    events.initialize(9, EventKind::Notification, true);
    let token = events.begin_deferred_signal(9).unwrap();
    assert_eq!(events.reset_existing(9), Some(true));
    assert!(!events.read_state(9));
    assert_eq!(events.commit_deferred_signal(token), Ok(false));
    assert_eq!(events.reset_existing(9), Some(true));
    assert!(!events.read_state(9));
}

#[test]
fn pending_completions_pin_backing_and_can_be_cancelled_independently() {
    let mut events = EventStore::new();
    events.initialize(10, EventKind::Notification, false);
    let first = events.begin_deferred_signal(10).unwrap();
    let second = events.begin_deferred_signal(10).unwrap();
    assert!(!events.remove_existing(10));
    assert!(!events.try_initialize(10, EventKind::Synchronization, true));
    assert_eq!(
        events.query_existing(10),
        Some((EventKind::Notification, false))
    );
    assert_eq!(events.cancel_deferred_signal(first), Ok(()));
    assert_eq!(events.cancel_deferred_signal(first), Err(()));
    assert!(!events.remove_existing(10));
    assert_eq!(events.commit_deferred_signal(second), Ok(false));
    assert!(events.remove_existing(10));
    events.initialize(10, EventKind::Notification, false);
    assert_eq!(events.commit_deferred_signal(second), Err(()));
    assert!(!events.read_state(10));
}

#[test]
#[should_panic(expected = "Event reinitialization retains an unpublished completion signal")]
fn infallible_reinitialization_rejects_an_unpublished_completion() {
    let mut events = EventStore::new();
    events.initialize(10, EventKind::Notification, false);
    let _token = events.begin_deferred_signal(10).unwrap();
    events.initialize(10, EventKind::Synchronization, true);
}

#[test]
fn tokens_reject_other_stores_and_missing_events_without_mutation() {
    let mut first = EventStore::new();
    let mut second = EventStore::new();
    first.initialize(11, EventKind::Notification, false);
    second.initialize(11, EventKind::Notification, false);
    let token = first.begin_deferred_signal(11).unwrap();
    let other = second.begin_deferred_signal(11).unwrap();
    assert_eq!(second.commit_deferred_signal(token), Err(()));
    assert_eq!(second.cancel_deferred_signal(token), Err(()));
    assert_eq!(first.begin_deferred_signal(99), Err(()));
    assert!(!second.read_state(11));
    assert_eq!(first.commit_deferred_signal(token), Ok(false));
    assert_eq!(second.commit_deferred_signal(other), Ok(false));
}
