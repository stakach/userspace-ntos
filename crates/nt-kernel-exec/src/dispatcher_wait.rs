//! Atomic polling across the dispatcher object kinds shared by native waits.

use crate::{EventStore, MutantAcquire, MutantError, MutantStore, SemaphoreError, SemaphoreStore};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherObject {
    Event(u64),
    Semaphore(u64),
    Mutant { identity: u64, thread: u64 },
}

/// Dispatcher objects accepted by `NtSignalAndWaitForSingleObject` as its signal operand.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherSignalObject {
    Event(u64),
    Semaphore(u64),
    Mutant { identity: u64, thread: u64 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherSignalError {
    InvalidObject,
    SemaphoreLimitExceeded,
    MutantNotOwned,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherWaitResult {
    Signaled(usize),
    Abandoned(usize),
    TimedOut,
    InvalidObject,
    DuplicateObject,
    MutantLimitExceeded,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherConsumeResult {
    Consumed,
    Abandoned,
    NotReady,
    MutantLimitExceeded,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherWaitTimeout {
    /// `Timeout == NULL`: wait forever.
    Infinite,
    /// `Timeout->QuadPart == 0`: poll and return immediately if no object is signaled.
    Poll,
    /// Any non-zero relative or absolute timeout: a real timed wait.
    Blocking,
}

pub fn classify_dispatcher_wait_timeout(timeout: Option<i64>) -> DispatcherWaitTimeout {
    match timeout {
        None => DispatcherWaitTimeout::Infinite,
        Some(0) => DispatcherWaitTimeout::Poll,
        Some(_) => DispatcherWaitTimeout::Blocking,
    }
}

pub fn dispatcher_ready(
    events: &EventStore,
    semaphores: &SemaphoreStore,
    mutants: &MutantStore,
    object: DispatcherObject,
) -> bool {
    match object {
        DispatcherObject::Event(identity) => events.read_state(identity),
        DispatcherObject::Semaphore(identity) => semaphores
            .query(identity)
            .is_some_and(|(current, _maximum)| current > 0),
        DispatcherObject::Mutant { identity, thread } => mutants.ready_for(identity, thread),
    }
}

pub fn consume_dispatcher(
    events: &mut EventStore,
    semaphores: &mut SemaphoreStore,
    mutants: &mut MutantStore,
    object: DispatcherObject,
) -> DispatcherConsumeResult {
    match object {
        DispatcherObject::Event(identity) => events
            .consume_existing(identity)
            .then_some(DispatcherConsumeResult::Consumed)
            .unwrap_or(DispatcherConsumeResult::NotReady),
        DispatcherObject::Semaphore(identity) => (semaphores.try_wait(identity) == Some(true))
            .then_some(DispatcherConsumeResult::Consumed)
            .unwrap_or(DispatcherConsumeResult::NotReady),
        DispatcherObject::Mutant { identity, thread } => match mutants.acquire(identity, thread) {
            Ok(MutantAcquire::Acquired { abandoned: true }) => DispatcherConsumeResult::Abandoned,
            Ok(MutantAcquire::Acquired { abandoned: false }) => DispatcherConsumeResult::Consumed,
            Ok(MutantAcquire::Busy) | Err(MutantError::NotFound) => {
                DispatcherConsumeResult::NotReady
            }
            Err(MutantError::LimitExceeded) => DispatcherConsumeResult::MutantLimitExceeded,
            Err(MutantError::NotOwned) => DispatcherConsumeResult::NotReady,
        },
    }
}

/// Apply the signal half of `NtSignalAndWaitForSingleObject` while the caller holds the dispatcher
/// serialization boundary. The subsequent wait must be evaluated before that boundary is released.
pub fn signal_dispatcher_for_wait(
    events: &mut EventStore,
    semaphores: &mut SemaphoreStore,
    mutants: &mut MutantStore,
    object: DispatcherSignalObject,
) -> Result<(), DispatcherSignalError> {
    match object {
        DispatcherSignalObject::Event(identity) => events
            .set_existing(identity)
            .map(|_| ())
            .ok_or(DispatcherSignalError::InvalidObject),
        DispatcherSignalObject::Semaphore(identity) => semaphores
            .release(identity, 1)
            .map(|_| ())
            .map_err(|error| match error {
                SemaphoreError::LimitExceeded => DispatcherSignalError::SemaphoreLimitExceeded,
                SemaphoreError::InvalidCount | SemaphoreError::NotFound => {
                    DispatcherSignalError::InvalidObject
                }
            }),
        DispatcherSignalObject::Mutant { identity, thread } => mutants
            .release(identity, thread)
            .map(|_| ())
            .map_err(|error| match error {
                MutantError::NotOwned => DispatcherSignalError::MutantNotOwned,
                MutantError::NotFound | MutantError::LimitExceeded => {
                    DispatcherSignalError::InvalidObject
                }
            }),
    }
}

pub fn poll_dispatchers(
    events: &mut EventStore,
    semaphores: &mut SemaphoreStore,
    mutants: &mut MutantStore,
    objects: &[DispatcherObject],
    wait_all: bool,
) -> DispatcherWaitResult {
    if objects.is_empty()
        || objects.iter().any(|object| match object {
            DispatcherObject::Event(identity) => !events.contains(*identity),
            DispatcherObject::Semaphore(identity) => !semaphores.contains(*identity),
            DispatcherObject::Mutant { identity, .. } => !mutants.contains(*identity),
        })
    {
        return DispatcherWaitResult::InvalidObject;
    }
    if wait_all {
        for left in 0..objects.len() {
            if objects[left + 1..].contains(&objects[left]) {
                return DispatcherWaitResult::DuplicateObject;
            }
        }
        if objects
            .iter()
            .any(|object| !dispatcher_ready(events, semaphores, mutants, *object))
        {
            return DispatcherWaitResult::TimedOut;
        }
        if objects.iter().any(|object| match object {
            DispatcherObject::Mutant { identity, thread } => {
                mutants.acquire_would_exceed(*identity, *thread)
            }
            _ => false,
        }) {
            return DispatcherWaitResult::MutantLimitExceeded;
        }
        let mut abandoned = false;
        for object in objects {
            abandoned |= consume_dispatcher(events, semaphores, mutants, *object)
                == DispatcherConsumeResult::Abandoned;
        }
        if abandoned {
            DispatcherWaitResult::Abandoned(0)
        } else {
            DispatcherWaitResult::Signaled(0)
        }
    } else if let Some(index) = objects
        .iter()
        .position(|object| dispatcher_ready(events, semaphores, mutants, *object))
    {
        match consume_dispatcher(events, semaphores, mutants, objects[index]) {
            DispatcherConsumeResult::Consumed => DispatcherWaitResult::Signaled(index),
            DispatcherConsumeResult::Abandoned => DispatcherWaitResult::Abandoned(index),
            DispatcherConsumeResult::MutantLimitExceeded => {
                DispatcherWaitResult::MutantLimitExceeded
            }
            DispatcherConsumeResult::NotReady => DispatcherWaitResult::TimedOut,
        }
    } else {
        DispatcherWaitResult::TimedOut
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventKind;

    fn stores() -> (EventStore, SemaphoreStore, MutantStore) {
        (EventStore::new(), SemaphoreStore::new(), MutantStore::new())
    }

    #[test]
    fn wait_timeout_pointer_shape_distinguishes_poll_from_blocking() {
        assert_eq!(
            classify_dispatcher_wait_timeout(None),
            DispatcherWaitTimeout::Infinite
        );
        assert_eq!(
            classify_dispatcher_wait_timeout(Some(0)),
            DispatcherWaitTimeout::Poll
        );
        assert_eq!(
            classify_dispatcher_wait_timeout(Some(-10_000)),
            DispatcherWaitTimeout::Blocking
        );
        assert_eq!(
            classify_dispatcher_wait_timeout(Some(10_000)),
            DispatcherWaitTimeout::Blocking
        );
    }

    #[test]
    fn wait_any_uses_lowest_ready_index_and_consumes_one_token() {
        let (mut events, mut semaphores, mut mutants) = stores();
        semaphores.initialize(7, 1, 2).unwrap();
        events.initialize(8, EventKind::Notification, true);
        let objects = [DispatcherObject::Semaphore(7), DispatcherObject::Event(8)];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, false),
            DispatcherWaitResult::Signaled(0)
        );
        assert_eq!(semaphores.query(7), Some((0, 2)));
        assert!(events.read_state(8));
    }

    #[test]
    fn wait_all_is_atomic_until_every_object_is_ready() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(3, EventKind::Synchronization, true);
        semaphores.initialize(4, 0, 1).unwrap();
        let objects = [DispatcherObject::Event(3), DispatcherObject::Semaphore(4)];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, true),
            DispatcherWaitResult::TimedOut
        );
        assert!(events.read_state(3));
        semaphores.release(4, 1).unwrap();
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, true),
            DispatcherWaitResult::Signaled(0)
        );
        assert!(!events.read_state(3));
        assert_eq!(semaphores.query(4), Some((0, 1)));
    }

    #[test]
    fn notification_event_remains_set_after_mixed_wait_all() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Notification, true);
        semaphores.initialize(2, 1, 1).unwrap();
        let objects = [DispatcherObject::Event(1), DispatcherObject::Semaphore(2)];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, true),
            DispatcherWaitResult::Signaled(0)
        );
        assert!(events.read_state(1));
        assert_eq!(semaphores.query(2), Some((0, 1)));
    }

    #[test]
    fn wait_all_rejects_duplicate_object_identity() {
        let (mut events, mut semaphores, mut mutants) = stores();
        semaphores.initialize(5, 1, 2).unwrap();
        let objects = [
            DispatcherObject::Semaphore(5),
            DispatcherObject::Semaphore(5),
        ];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, true),
            DispatcherWaitResult::DuplicateObject
        );
        assert_eq!(semaphores.query(5), Some((1, 2)));
    }

    #[test]
    fn one_token_satisfies_only_one_poll() {
        let (mut events, mut semaphores, mut mutants) = stores();
        semaphores.initialize(9, 1, 1).unwrap();
        let objects = [DispatcherObject::Semaphore(9)];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, false),
            DispatcherWaitResult::Signaled(0)
        );
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, false),
            DispatcherWaitResult::TimedOut
        );
    }

    #[test]
    fn mutant_wait_acquires_and_release_wakes_next_thread() {
        let (mut events, mut semaphores, mut mutants) = stores();
        mutants.initialize(12, None);
        let first = [DispatcherObject::Mutant {
            identity: 12,
            thread: 100,
        }];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &first, false),
            DispatcherWaitResult::Signaled(0)
        );
        let second = [DispatcherObject::Mutant {
            identity: 12,
            thread: 101,
        }];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &second, false),
            DispatcherWaitResult::TimedOut
        );
        mutants.release(12, 100).unwrap();
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &second, false),
            DispatcherWaitResult::Signaled(0)
        );
    }

    #[test]
    fn abandoned_mutant_reports_the_selected_wait_index_once() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Notification, false);
        mutants.initialize(2, Some(40));
        assert_eq!(mutants.abandon_thread(40), 1);
        let objects = [
            DispatcherObject::Event(1),
            DispatcherObject::Mutant {
                identity: 2,
                thread: 41,
            },
        ];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, false),
            DispatcherWaitResult::Abandoned(1)
        );
        assert_eq!(mutants.query(2, 41).unwrap().abandoned, false);
    }

    #[test]
    fn wait_all_reports_abandonment_after_consuming_every_ready_object() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Synchronization, true);
        mutants.initialize(2, Some(40));
        assert_eq!(mutants.abandon_thread(40), 1);
        let objects = [
            DispatcherObject::Event(1),
            DispatcherObject::Mutant {
                identity: 2,
                thread: 41,
            },
        ];
        assert_eq!(
            poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, true),
            DispatcherWaitResult::Abandoned(0)
        );
        assert!(!events.read_state(1));
        assert_eq!(mutants.query(2, 41).unwrap().current_count, 0);
        assert!(!mutants.query(2, 41).unwrap().abandoned);
    }

    #[test]
    fn signal_for_wait_supports_each_native_signal_object() {
        let (mut events, mut semaphores, mut mutants) = stores();
        events.initialize(1, EventKind::Notification, false);
        semaphores.initialize(2, 0, 2).unwrap();
        mutants.initialize(3, Some(30));

        assert_eq!(
            signal_dispatcher_for_wait(
                &mut events,
                &mut semaphores,
                &mut mutants,
                DispatcherSignalObject::Event(1),
            ),
            Ok(())
        );
        assert!(events.read_state(1));

        assert_eq!(
            signal_dispatcher_for_wait(
                &mut events,
                &mut semaphores,
                &mut mutants,
                DispatcherSignalObject::Semaphore(2),
            ),
            Ok(())
        );
        assert_eq!(semaphores.query(2), Some((1, 2)));

        assert_eq!(
            signal_dispatcher_for_wait(
                &mut events,
                &mut semaphores,
                &mut mutants,
                DispatcherSignalObject::Mutant {
                    identity: 3,
                    thread: 30,
                },
            ),
            Ok(())
        );
        assert!(mutants.ready_for(3, 31));
    }

    #[test]
    fn signal_for_wait_preserves_native_failure_modes() {
        let (mut events, mut semaphores, mut mutants) = stores();
        semaphores.initialize(2, 1, 1).unwrap();
        mutants.initialize(3, Some(30));

        assert_eq!(
            signal_dispatcher_for_wait(
                &mut events,
                &mut semaphores,
                &mut mutants,
                DispatcherSignalObject::Event(99),
            ),
            Err(DispatcherSignalError::InvalidObject)
        );
        assert_eq!(
            signal_dispatcher_for_wait(
                &mut events,
                &mut semaphores,
                &mut mutants,
                DispatcherSignalObject::Semaphore(2),
            ),
            Err(DispatcherSignalError::SemaphoreLimitExceeded)
        );
        assert_eq!(
            signal_dispatcher_for_wait(
                &mut events,
                &mut semaphores,
                &mut mutants,
                DispatcherSignalObject::Mutant {
                    identity: 3,
                    thread: 31,
                },
            ),
            Err(DispatcherSignalError::MutantNotOwned)
        );
    }
}
