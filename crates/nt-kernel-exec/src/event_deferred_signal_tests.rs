use crate::{EventKind, EventStore, IrqlState, WaitResult};

#[test]
fn prepared_completion_is_not_visible_until_exact_commit() {
    let mut events = EventStore::new();
    events.initialize(7, EventKind::Synchronization, false);
    let before = events.query_with_sequence(7).unwrap();
    let token = events.begin_deferred_signal(7).unwrap();
    assert_eq!(token.native_identity(), 7);
    assert!(token.state_sequence() > before.2);
    assert_eq!(events.query_with_sequence(7), Some(before));
    assert_eq!(
        events.query_existing(7),
        Some((EventKind::Synchronization, false))
    );
    assert_eq!(events.poll(7, &IrqlState::new()), WaitResult::TimedOut);
    assert!(!events.consume_existing(7));
    assert_eq!(events.commit_deferred_signal(token), Ok(false));
    assert_eq!(
        events.query_with_sequence(7).unwrap().2,
        token.state_sequence()
    );
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
    let after_independent_wait = events.query_with_sequence(8).unwrap();
    assert_eq!(events.commit_deferred_signal(token), Ok(false));
    assert_eq!(events.query_with_sequence(8), Some(after_independent_wait));
    assert!(!events.consume_existing(8));
}

#[test]
fn reset_after_preparation_supersedes_the_reserved_completion_signal() {
    let mut events = EventStore::new();
    events.initialize(9, EventKind::Notification, true);
    let token = events.begin_deferred_signal(9).unwrap();
    assert_eq!(events.reset_existing(9), Some(true));
    assert!(!events.read_state(9));
    let reset = events.query_with_sequence(9).unwrap();
    assert!(reset.2 > token.state_sequence());
    assert_eq!(events.commit_deferred_signal(token), Ok(false));
    assert_eq!(events.query_with_sequence(9), Some(reset));
    assert_eq!(events.reset_existing(9), Some(false));
    assert!(!events.read_state(9));
}

#[test]
fn multiple_prepared_signals_commit_in_sequence_order_not_delivery_order() {
    let mut events = EventStore::new();
    events.initialize(12, EventKind::Synchronization, false);
    let older = events.begin_deferred_signal(12).unwrap();
    let newer = events.begin_deferred_signal(12).unwrap();
    assert!(newer.state_sequence() > older.state_sequence());
    assert_eq!(events.commit_deferred_signal(newer), Ok(false));
    assert!(events.consume_existing(12));
    let consumed = events.query_with_sequence(12).unwrap();
    assert_eq!(events.commit_deferred_signal(older), Ok(false));
    assert_eq!(events.query_with_sequence(12), Some(consumed));
}

#[test]
fn unchanged_mutations_still_supersede_prior_completion_reservations() {
    let mut events = EventStore::new();
    events.initialize(13, EventKind::Notification, false);
    let completion = events.begin_deferred_signal(13).unwrap();
    assert_eq!(events.reset_existing(13), Some(false));
    assert_eq!(events.commit_deferred_signal(completion), Ok(false));
    assert!(!events.read_state(13));
    let completion = events.begin_deferred_signal(13).unwrap();
    assert!(events.clear_existing(13));
    assert_eq!(events.commit_deferred_signal(completion), Ok(false));
    assert!(!events.read_state(13));
    events.set_existing(13).unwrap();
    let completion = events.begin_deferred_signal(13).unwrap();
    let before_wait = events.query_with_sequence(13).unwrap().2;
    assert!(events.consume_existing(13));
    assert!(events.query_with_sequence(13).unwrap().2 > before_wait);
    let consumed = events.query_with_sequence(13).unwrap();
    assert_eq!(events.commit_deferred_signal(completion), Ok(true));
    assert_eq!(events.query_with_sequence(13), Some(consumed));
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

#[test]
fn exhausted_state_sequence_refuses_new_effects_but_allows_reserved_commit() {
    let mut events = EventStore::new();
    events.initialize(14, EventKind::Notification, false);
    events.events[0].issued_sequence = u64::MAX - 1;
    let token = events.begin_deferred_signal(14).unwrap();
    assert_eq!(token.state_sequence(), u64::MAX);
    let before = events.query_with_sequence(14);
    assert_eq!(events.begin_deferred_signal(14), Err(()));
    assert_eq!(events.set_existing(14), None);
    assert_eq!(events.reset_existing(14), None);
    assert!(!events.clear_existing(14));
    assert!(!events.try_initialize(14, EventKind::Synchronization, true));
    assert_eq!(events.query_with_sequence(14), before);
    assert_eq!(events.commit_deferred_signal(token), Ok(false));
    let committed = events.query_with_sequence(14);
    assert!(!events.consume_existing(14));
    assert_eq!(events.query_with_sequence(14), committed);
    assert!(!events.wait_ready(14));
}
