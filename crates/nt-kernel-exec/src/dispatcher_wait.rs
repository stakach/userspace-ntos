//! Atomic polling across the dispatcher object kinds shared by native waits.

use crate::{EventStore, MutantStore, SemaphoreStore};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherObject {
    Event(u64),
    Semaphore(u64),
    Mutant { identity: u64, thread: u64 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatcherWaitResult {
    Signaled(usize),
    TimedOut,
    InvalidObject,
    DuplicateObject,
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
) -> bool {
    match object {
        DispatcherObject::Event(identity) => events.consume_existing(identity),
        DispatcherObject::Semaphore(identity) => semaphores.try_wait(identity) == Some(true),
        DispatcherObject::Mutant { identity, thread } => {
            mutants.acquire(identity, thread) == Some(true)
        }
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
        for object in objects {
            consume_dispatcher(events, semaphores, mutants, *object);
        }
        DispatcherWaitResult::Signaled(0)
    } else if let Some(index) = objects
        .iter()
        .position(|object| dispatcher_ready(events, semaphores, mutants, *object))
    {
        consume_dispatcher(events, semaphores, mutants, objects[index]);
        DispatcherWaitResult::Signaled(index)
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
}
