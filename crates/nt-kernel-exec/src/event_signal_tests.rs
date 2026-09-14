use super::*;
use crate::{
    dispatcher_ready, poll_dispatchers, DispatcherObject, DispatcherWaitResult, EventKind,
    EventStore, MutantStore, SemaphoreStore,
};

struct Waiter {
    source: DispatcherWaitSource,
    sequence: u64,
    objects: alloc::vec::Vec<DispatcherObject>,
    all: bool,
    selected: bool,
}

struct Backend {
    events: EventStore,
    semaphores: SemaphoreStore,
    mutants: MutantStore,
    waiters: alloc::vec::Vec<Waiter>,
    order: alloc::vec::Vec<u64>,
    cleared: bool,
}

impl Backend {
    fn new(kind: EventKind) -> Self {
        let mut events = EventStore::new();
        events.initialize(1, kind, true);
        Self {
            events,
            semaphores: SemaphoreStore::new(),
            mutants: MutantStore::new(),
            waiters: alloc::vec::Vec::new(),
            order: alloc::vec::Vec::new(),
            cleared: false,
        }
    }

    fn add(
        &mut self,
        source: DispatcherWaitSource,
        sequence: u64,
        objects: &[DispatcherObject],
        all: bool,
    ) {
        self.waiters.push(Waiter {
            source,
            sequence,
            objects: objects.to_vec(),
            all,
            selected: false,
        });
    }

    fn consumes_target(&self, waiter: &Waiter) -> bool {
        if waiter.selected {
            return false;
        }
        let ready = |object: &DispatcherObject| {
            dispatcher_ready(&self.events, &self.semaphores, &self.mutants, *object)
        };
        if waiter.all {
            waiter.objects.contains(&DispatcherObject::Event(1)) && waiter.objects.iter().all(ready)
        } else {
            waiter.objects.iter().find(|object| ready(object)) == Some(&DispatcherObject::Event(1))
        }
    }
}

impl EventSignalSelector for Backend {
    fn oldest_ready(&self, source: DispatcherWaitSource) -> Option<u64> {
        self.waiters
            .iter()
            .filter(|waiter| waiter.source == source && self.consumes_target(waiter))
            .map(|waiter| waiter.sequence)
            .min()
    }

    fn select(&mut self, source: DispatcherWaitSource, sequence: u64) {
        assert!(!self.cleared, "pulse selection after clear");
        assert_eq!(self.oldest_ready(source), Some(sequence));
        let waiter = self
            .waiters
            .iter_mut()
            .find(|waiter| waiter.sequence == sequence)
            .unwrap();
        assert!(matches!(
            poll_dispatchers(
                &mut self.events,
                &mut self.semaphores,
                &mut self.mutants,
                &waiter.objects,
                waiter.all
            ),
            DispatcherWaitResult::Signaled(_)
        ));
        waiter.selected = true;
        self.order.push(sequence);
    }

    fn clear(&mut self) {
        assert!(!self.cleared);
        self.events.clear_existing(1);
        self.cleared = true;
    }
}

#[test]
fn notification_pulse_selects_all_families_in_order_before_clearing() {
    use DispatcherWaitSource::*;
    for sources in [
        [Native, Provider, Gui],
        [Provider, Gui, Native],
        [Gui, Native, Provider],
    ] {
        let mut b = Backend::new(EventKind::Notification);
        for (source, sequence) in sources.into_iter().zip([30, 10, 20]) {
            b.add(source, sequence, &[DispatcherObject::Event(1)], false);
        }
        assert_eq!(select_event_signal(&mut b, EventSignalMode::Pulse), 3);
        assert_eq!(b.order, [10, 20, 30]);
        assert!(b.cleared);
        assert!(!b.events.read_state(1));
        b.add(Native, 40, &[DispatcherObject::Event(1)], false);
        assert_eq!(b.oldest_ready(Native), None);
    }
}

#[test]
fn synchronization_signal_has_one_consumer_in_either_mode() {
    use DispatcherWaitSource::*;
    for mode in [EventSignalMode::Set, EventSignalMode::Pulse] {
        for first in [Native, Gui, Provider] {
            let mut b = Backend::new(EventKind::Synchronization);
            b.add(first, 1, &[DispatcherObject::Event(1)], false);
            for (source, sequence) in [Native, Gui, Provider].into_iter().zip([10, 20, 30]) {
                b.add(source, sequence, &[DispatcherObject::Event(1)], false);
            }
            assert_eq!(select_event_signal(&mut b, mode), 1);
            assert_eq!(b.order, [1]);
            assert!(!b.events.read_state(1));
        }
    }
}

#[test]
fn wait_all_recomputes_cross_family_competition_after_each_selection() {
    use DispatcherWaitSource::*;
    for mode in [EventSignalMode::Set, EventSignalMode::Pulse] {
        for (first, middle) in [(Provider, Native), (Native, Provider)] {
            let mut b = Backend::new(EventKind::Notification);
            b.events.initialize(2, EventKind::Synchronization, true);
            b.add(first, 10, &[DispatcherObject::Event(1)], false);
            b.add(
                first,
                30,
                &[DispatcherObject::Event(1), DispatcherObject::Event(2)],
                true,
            );
            b.add(
                middle,
                20,
                &[DispatcherObject::Event(1), DispatcherObject::Event(2)],
                true,
            );
            assert_eq!(select_event_signal(&mut b, mode), 2);
            assert_eq!(b.order, [10, 20]);
            assert!(!b.waiters[1].selected);
            assert!(!b.events.read_state(2));
            assert_eq!(b.events.read_state(1), mode == EventSignalMode::Set);
        }
    }
}

#[test]
fn incomplete_wait_all_and_wait_any_choosing_another_object_do_not_consume_pulse() {
    use DispatcherWaitSource::*;
    let mut b = Backend::new(EventKind::Synchronization);
    b.semaphores.initialize(2, 0, 1).unwrap();
    b.events.initialize(3, EventKind::Notification, true);
    b.add(
        Native,
        1,
        &[DispatcherObject::Event(1), DispatcherObject::Semaphore(2)],
        true,
    );
    b.add(
        Provider,
        2,
        &[DispatcherObject::Event(3), DispatcherObject::Event(1)],
        false,
    );
    b.add(Gui, 3, &[DispatcherObject::Event(1)], false);
    assert_eq!(select_event_signal(&mut b, EventSignalMode::Pulse), 1);
    assert_eq!(b.order, [3]);
    assert!(!b.events.read_state(1));
    assert!(b.events.read_state(3));
    assert_eq!(b.semaphores.query(2), Some((0, 1)));
}

#[test]
fn empty_set_remains_signaled_but_empty_pulse_has_no_late_readiness() {
    for kind in [EventKind::Notification, EventKind::Synchronization] {
        for mode in [EventSignalMode::Set, EventSignalMode::Pulse] {
            let mut b = Backend::new(kind);
            assert_eq!(select_event_signal(&mut b, mode), 0);
            assert_eq!(b.events.read_state(1), mode == EventSignalMode::Set);
            assert_eq!(b.cleared, mode == EventSignalMode::Pulse);
        }
    }
}
