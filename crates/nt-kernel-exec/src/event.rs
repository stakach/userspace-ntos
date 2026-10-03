//! Event dispatcher objects (spec §6.5). A `KEVENT` is opaque driver storage; the
//! runtime keeps its state keyed by the driver's pointer. Notification events are
//! manual-reset; Synchronization events auto-reset when a wait consumes them.
//! Blocking waits integrate at the runtime level; the store provides the poll +
//! signal semantics.

use alloc::vec::Vec;

use crate::event_deferred_signal::{DeferredEventSignal, DeferredEventSignals};
use crate::irql::IrqlState;

/// `KEVENT` type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// Manual-reset: stays signaled until explicitly cleared.
    Notification,
    /// Auto-reset: a successful wait consumes the signal.
    Synchronization,
}

/// Expand Win32 generic access bits into the event object's native access mask.
pub fn map_event_access(mut access: u32) -> u32 {
    const EVENT_QUERY_STATE: u32 = 0x0001;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const EVENT_ALL_ACCESS: u32 = 0x001F_0003;

    if access & 0x8000_0000 != 0 {
        access |= 0x0002_0000 | EVENT_QUERY_STATE;
    }
    if access & 0x4000_0000 != 0 {
        access |= 0x0002_0000 | EVENT_MODIFY_STATE;
    }
    if access & 0x2000_0000 != 0 {
        access |= 0x0002_0000 | SYNCHRONIZE;
    }
    if access & (0x1000_0000 | 0x0200_0000) != 0 {
        access |= EVENT_ALL_ACCESS;
    }
    access & !(0xF000_0000 | 0x0200_0000)
}

/// The result of a wait/poll.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WaitResult {
    /// The object was signaled (a Synchronization event was consumed).
    Signaled,
    /// Not signaled within the timeout.
    TimedOut,
    /// Polling is not permitted above `DISPATCH_LEVEL`.
    BadIrql,
}

/// Result of polling a set of dispatcher events.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WaitManyResult {
    /// The wait condition is satisfied. `WaitAny` returns the lowest matching index;
    /// `WaitAll` returns zero.
    Signaled(usize),
    /// No event currently satisfies the wait.
    TimedOut,
    /// At least one supplied event identity does not exist.
    InvalidEvent,
    /// Polling is not permitted above `DISPATCH_LEVEL`.
    BadIrql,
}

struct Event {
    ptr: u64,
    kind: EventKind,
    signaled: bool,
    generation: u64,
    state_sequence: u64,
    issued_sequence: u64,
}

impl Event {
    fn mutate(&mut self, signaled: bool) -> Option<bool> {
        let sequence = self.issued_sequence.checked_add(1)?;
        let previous = self.signaled;
        self.signaled = signaled;
        self.state_sequence = sequence;
        self.issued_sequence = sequence;
        Some(previous)
    }
}

/// The Driver Host's event store (spec §6.5).
#[derive(Default)]
pub struct EventStore {
    events: Vec<Event>,
    deferred_signals: DeferredEventSignals,
    issued_generation: u64,
}

impl EventStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a store whose backing allocation can be made before a rewindable
    /// executive heap mark. Event operations do not allocate while within capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            deferred_signals: DeferredEventSignals::default(),
            issued_generation: 0,
        }
    }

    fn slot(&mut self, ptr: u64) -> &mut Event {
        if let Some(i) = self.events.iter().position(|e| e.ptr == ptr) {
            return &mut self.events[i];
        }
        let generation = self
            .issued_generation
            .checked_add(1)
            .expect("Event lifetime generation exhausted");
        self.events.push(Event {
            ptr,
            kind: EventKind::Notification,
            signaled: false,
            generation,
            state_sequence: 0,
            issued_sequence: 0,
        });
        self.issued_generation = generation;
        self.events.last_mut().unwrap()
    }

    /// `KeInitializeEvent(Event, Type, State)`.
    pub fn initialize(&mut self, ptr: u64, kind: EventKind, signaled: bool) {
        assert!(
            !self.deferred_signals.contains(ptr),
            "Event reinitialization retains an unpublished completion signal"
        );
        let e = self.slot(ptr);
        e.mutate(signaled).expect("Event state sequence exhausted");
        e.kind = kind;
    }

    /// Fallible `KeInitializeEvent` for executive paths that must return a real NT allocation
    /// failure instead of depending on a late heap grow.
    pub fn try_initialize(&mut self, ptr: u64, kind: EventKind, signaled: bool) -> bool {
        if self.deferred_signals.contains(ptr) {
            return false;
        }
        if let Some(i) = self.events.iter().position(|e| e.ptr == ptr) {
            let e = &mut self.events[i];
            if e.mutate(signaled).is_none() {
                return false;
            }
            e.kind = kind;
            return true;
        }
        if self.events.len() == self.events.capacity() && self.events.try_reserve(16).is_err() {
            return false;
        }
        let Some(generation) = self.issued_generation.checked_add(1) else {
            return false;
        };
        self.events.push(Event {
            ptr,
            kind,
            signaled,
            generation,
            state_sequence: 1,
            issued_sequence: 1,
        });
        self.issued_generation = generation;
        true
    }

    /// Whether an event identity has been initialized.
    pub fn contains(&self, ptr: u64) -> bool {
        self.events.iter().any(|event| event.ptr == ptr)
    }

    /// Remove an initialized event identity. The executive uses this to roll back an object whose
    /// newly-created handle could not be published to its caller.
    pub fn remove_existing(&mut self, ptr: u64) -> bool {
        if self.deferred_signals.contains(ptr) {
            return false;
        }
        let Some(index) = self.events.iter().position(|event| event.ptr == ptr) else {
            return false;
        };
        self.events.remove(index);
        true
    }

    /// Prepare an operation's completion Set without altering independently observable state.
    /// The executive must also retain the canonical Event object and its backing lease.
    pub fn begin_deferred_signal(&mut self, ptr: u64) -> Result<DeferredEventSignal, ()> {
        let event = self
            .events
            .iter_mut()
            .find(|event| event.ptr == ptr)
            .ok_or(())?;
        let sequence = event.issued_sequence.checked_add(1).ok_or(())?;
        let token = self
            .deferred_signals
            .begin(ptr, event.generation, sequence)?;
        event.issued_sequence = sequence;
        Ok(token)
    }

    /// Publish the reserved signal exactly once, after the origin's terminal acknowledgement.
    /// A newer visible mutation supersedes it without replaying or undoing that mutation.
    /// The adapter must arbitrate ready dispatcher waits after this returns.
    pub fn commit_deferred_signal(&mut self, token: DeferredEventSignal) -> Result<bool, ()> {
        let index = self
            .events
            .iter()
            .position(|event| {
                event.ptr == token.native_identity() && event.generation == token.generation()
            })
            .ok_or(())?;
        self.deferred_signals.retire(token)?;
        let event = &mut self.events[index];
        let previous = event.signaled;
        if event.state_sequence < token.state_sequence() {
            event.signaled = true;
            event.state_sequence = token.state_sequence();
        }
        Ok(previous)
    }

    /// Cancel an operation that has not committed a visible completion signal.
    pub fn cancel_deferred_signal(&mut self, token: DeferredEventSignal) -> Result<(), ()> {
        self.deferred_signals.retire(token)
    }

    /// Return the dispatcher type and signal state for an initialized event.
    pub fn query_existing(&self, ptr: u64) -> Option<(EventKind, bool)> {
        self.events
            .iter()
            .find(|event| event.ptr == ptr)
            .map(|event| (event.kind, event.signaled))
    }

    /// Current visible mutation version, excluding unpublished completion reservations.
    pub fn query_with_sequence(&self, ptr: u64) -> Option<(EventKind, bool, u64)> {
        self.events
            .iter()
            .find(|event| event.ptr == ptr)
            .map(|event| (event.kind, event.signaled, event.state_sequence))
    }

    /// Strict `NtSetEvent` state transition. Unlike [`Self::set`], this never
    /// manufactures an event for an invalid handle.
    pub fn set_existing(&mut self, ptr: u64) -> Option<bool> {
        let event = self.events.iter_mut().find(|event| event.ptr == ptr)?;
        event.mutate(true)
    }

    /// Strict `NtResetEvent` state transition.
    pub fn reset_existing(&mut self, ptr: u64) -> Option<bool> {
        let event = self.events.iter_mut().find(|event| event.ptr == ptr)?;
        event.mutate(false)
    }

    /// Strict `NtClearEvent` state transition.
    pub fn clear_existing(&mut self, ptr: u64) -> bool {
        let Some(event) = self.events.iter_mut().find(|event| event.ptr == ptr) else {
            return false;
        };
        event.mutate(false).is_some()
    }

    /// Consume a signaled synchronization event, leaving notification events set.
    pub fn consume_existing(&mut self, ptr: u64) -> bool {
        let Some(event) = self.events.iter_mut().find(|event| event.ptr == ptr) else {
            return false;
        };
        if !event.signaled {
            return false;
        }
        event
            .mutate(event.kind == EventKind::Notification)
            .is_some()
    }

    /// Wait readiness includes admission for the consuming state mutation.
    pub fn wait_ready(&self, ptr: u64) -> bool {
        self.events
            .iter()
            .any(|event| event.ptr == ptr && event.signaled && event.issued_sequence != u64::MAX)
    }

    /// Poll `WaitAny`/`WaitAll` over existing event identities and apply NT
    /// synchronization-event consumption on success. This never blocks and is
    /// permitted through `DISPATCH_LEVEL`.
    pub fn poll_many(&mut self, ptrs: &[u64], wait_all: bool, irql: &IrqlState) -> WaitManyResult {
        if !irql.can_poll() {
            return WaitManyResult::BadIrql;
        }
        if ptrs.is_empty()
            || ptrs
                .iter()
                .any(|ptr| !self.events.iter().any(|event| event.ptr == *ptr))
        {
            return WaitManyResult::InvalidEvent;
        }
        if wait_all {
            if ptrs.iter().any(|ptr| !self.wait_ready(*ptr)) {
                return WaitManyResult::TimedOut;
            }
            for ptr in ptrs {
                self.consume_existing(*ptr);
            }
            WaitManyResult::Signaled(0)
        } else if let Some(index) = ptrs.iter().position(|ptr| self.wait_ready(*ptr)) {
            self.consume_existing(ptrs[index]);
            WaitManyResult::Signaled(index)
        } else {
            WaitManyResult::TimedOut
        }
    }

    /// `KeSetEvent` — signal the event, returning the previous state.
    pub fn set(&mut self, ptr: u64) -> bool {
        let e = self.slot(ptr);
        e.mutate(true).expect("Event state sequence exhausted")
    }

    /// `KeResetEvent` — clear + return the previous state.
    pub fn reset(&mut self, ptr: u64) -> bool {
        let e = self.slot(ptr);
        e.mutate(false).expect("Event state sequence exhausted")
    }

    /// `KeClearEvent` — clear (no return value).
    pub fn clear(&mut self, ptr: u64) {
        self.slot(ptr)
            .mutate(false)
            .expect("Event state sequence exhausted");
    }

    /// `KeReadStateEvent` — the signaled state.
    pub fn read_state(&self, ptr: u64) -> bool {
        self.events.iter().any(|e| e.ptr == ptr && e.signaled)
    }

    /// Attempt a non-blocking wait / poll on the event: if signaled, succeed
    /// (consuming a Synchronization event); otherwise time out. Polling above
    /// `DISPATCH_LEVEL` fails. A runtime that parks a thread must independently
    /// check [`IrqlState::can_wait`] before admitting a blocking wait.
    pub fn poll(&mut self, ptr: u64, irql: &IrqlState) -> WaitResult {
        if !irql.can_poll() {
            return WaitResult::BadIrql;
        }
        self.slot(ptr);
        if self.consume_existing(ptr) {
            WaitResult::Signaled
        } else {
            WaitResult::TimedOut
        }
    }
}

#[cfg(test)]
#[path = "event_deferred_signal_tests.rs"]
mod deferred_signal_tests;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::irql::{IrqlState, DISPATCH_LEVEL};

    #[test]
    fn notification_stays_signaled_until_reset() {
        let irql = IrqlState::new();
        let mut ev = EventStore::new();
        ev.initialize(0xE0, EventKind::Notification, false);
        assert_eq!(ev.poll(0xE0, &irql), WaitResult::TimedOut);
        assert!(!ev.set(0xE0)); // was clear
                                // Manual-reset: repeated polls keep succeeding until reset.
        assert_eq!(ev.poll(0xE0, &irql), WaitResult::Signaled);
        assert_eq!(ev.poll(0xE0, &irql), WaitResult::Signaled);
        assert!(ev.reset(0xE0)); // was set
        assert_eq!(ev.poll(0xE0, &irql), WaitResult::TimedOut);
    }

    #[test]
    fn synchronization_auto_resets() {
        let irql = IrqlState::new();
        let mut ev = EventStore::new();
        ev.initialize(0xE1, EventKind::Synchronization, true);
        assert_eq!(ev.poll(0xE1, &irql), WaitResult::Signaled); // consumes
        assert_eq!(ev.poll(0xE1, &irql), WaitResult::TimedOut); // auto-reset
    }

    #[test]
    fn set_wakes_a_waiter() {
        let irql = IrqlState::new();
        let mut ev = EventStore::new();
        ev.initialize(0xE2, EventKind::Synchronization, false);
        assert_eq!(ev.poll(0xE2, &irql), WaitResult::TimedOut);
        ev.set(0xE2);
        assert_eq!(ev.poll(0xE2, &irql), WaitResult::Signaled);
    }

    #[test]
    fn try_initialize_updates_existing_event() {
        let mut ev = EventStore::with_capacity(1);
        assert!(ev.try_initialize(1, EventKind::Notification, false));
        assert!(ev.try_initialize(1, EventKind::Synchronization, true));
        assert_eq!(
            ev.query_existing(1),
            Some((EventKind::Synchronization, true))
        );
    }

    #[test]
    fn single_poll_irql_limit_preserves_signal_and_identity_on_rejection() {
        for level in 0..=u8::MAX {
            let mut irql = IrqlState::new();
            irql.raise(level);
            let mut events = EventStore::new();
            events.initialize(1, EventKind::Synchronization, true);
            events.initialize(2, EventKind::Notification, true);
            if level <= DISPATCH_LEVEL {
                assert_eq!(events.poll(1, &irql), WaitResult::Signaled);
                assert_eq!(events.poll(1, &irql), WaitResult::TimedOut);
                assert_eq!(events.poll(2, &irql), WaitResult::Signaled);
                assert_eq!(events.poll(2, &irql), WaitResult::Signaled);
                assert!(!events.read_state(1));
            } else {
                assert_eq!(events.poll(1, &irql), WaitResult::BadIrql);
                assert_eq!(events.poll(2, &irql), WaitResult::BadIrql);
                assert_eq!(events.poll(99, &irql), WaitResult::BadIrql);
                assert!(!events.contains(99));
                assert!(events.read_state(1));
            }
            assert!(events.read_state(2));
            assert_eq!(irql.current(), level);
        }
    }

    #[test]
    fn multi_poll_irql_limit_preserves_wait_any_and_wait_all_atomicity() {
        for level in 0..=u8::MAX {
            let mut irql = IrqlState::new();
            irql.raise(level);
            let mut events = EventStore::new();
            events.initialize(1, EventKind::Synchronization, true);
            events.initialize(2, EventKind::Synchronization, false);
            events.initialize(3, EventKind::Notification, true);
            let allowed = level <= DISPATCH_LEVEL;
            assert_eq!(
                events.poll_many(&[1, 2, 3], true, &irql),
                if allowed {
                    WaitManyResult::TimedOut
                } else {
                    WaitManyResult::BadIrql
                }
            );
            assert!(events.read_state(1));
            assert!(!events.read_state(2));
            assert!(events.read_state(3));
            assert_eq!(
                events.poll_many(&[1, 99], false, &irql),
                if allowed {
                    WaitManyResult::InvalidEvent
                } else {
                    WaitManyResult::BadIrql
                }
            );
            assert!(events.read_state(1));
            assert!(!events.contains(99));

            events.set_existing(2);
            assert_eq!(
                events.poll_many(&[2, 1, 3], false, &irql),
                if allowed {
                    WaitManyResult::Signaled(0)
                } else {
                    WaitManyResult::BadIrql
                }
            );
            assert_eq!(events.read_state(2), !allowed);
            assert!(events.read_state(1));
            assert!(events.read_state(3));
            events.set_existing(2);
            assert_eq!(
                events.poll_many(&[1, 2, 3], true, &irql),
                if allowed {
                    WaitManyResult::Signaled(0)
                } else {
                    WaitManyResult::BadIrql
                }
            );
            assert_eq!(events.read_state(1), !allowed);
            assert_eq!(events.read_state(2), !allowed);
            assert!(events.read_state(3));
            assert_eq!(irql.current(), level);
        }
    }

    #[test]
    fn anonymous_identities_are_distinct_and_invalid_is_rejected() {
        let irql = IrqlState::new();
        let mut events = EventStore::with_capacity(2);
        events.initialize(1, EventKind::Notification, false);
        events.initialize(2, EventKind::Notification, true);
        assert!(!events.read_state(1));
        assert!(events.read_state(2));
        assert_eq!(
            events.poll_many(&[1, 99], false, &irql),
            WaitManyResult::InvalidEvent
        );
        assert_eq!(events.set_existing(99), None);
    }

    #[test]
    fn strict_set_reset_report_previous_state() {
        let mut events = EventStore::new();
        events.initialize(7, EventKind::Notification, false);
        assert_eq!(
            events.query_existing(7),
            Some((EventKind::Notification, false))
        );
        assert_eq!(events.set_existing(7), Some(false));
        assert_eq!(events.set_existing(7), Some(true));
        assert_eq!(events.reset_existing(7), Some(true));
        assert_eq!(events.reset_existing(7), Some(false));
        assert_eq!(events.query_existing(99), None);
    }

    #[test]
    fn generic_event_access_maps_to_native_rights() {
        assert_eq!(map_event_access(0x8000_0000) & 0x0001, 0x0001);
        assert_eq!(map_event_access(0x4000_0000) & 0x0002, 0x0002);
        assert_eq!(map_event_access(0x2000_0000) & 0x0010_0000, 0x0010_0000);
        assert_eq!(map_event_access(0x1000_0000), 0x001F_0003);
        assert_eq!(map_event_access(0x0200_0000), 0x001F_0003);
    }

    #[test]
    fn strict_clear_requires_an_existing_event_and_is_idempotent() {
        let mut events = EventStore::new();
        events.initialize(8, EventKind::Notification, true);
        events.initialize(9, EventKind::Synchronization, true);
        assert!(events.clear_existing(8));
        assert!(!events.read_state(8));
        assert!(events.clear_existing(8));
        assert!(events.clear_existing(9));
        assert!(!events.read_state(9));
        assert!(!events.clear_existing(99));
    }

    #[test]
    fn remove_existing_forgets_only_the_requested_identity() {
        let mut events = EventStore::new();
        events.initialize(0xE4, EventKind::Notification, true);
        events.initialize(0xE5, EventKind::Synchronization, false);

        assert!(events.remove_existing(0xE4));
        assert!(!events.contains(0xE4));
        assert!(events.contains(0xE5));
        assert!(!events.remove_existing(0xE4));
    }

    #[test]
    fn wait_any_returns_array_index_and_consumes_only_selected_auto_event() {
        let irql = IrqlState::new();
        let mut events = EventStore::new();
        events.initialize(10, EventKind::Synchronization, false);
        events.initialize(11, EventKind::Synchronization, true);
        assert_eq!(
            events.poll_many(&[10, 11], false, &irql),
            WaitManyResult::Signaled(1)
        );
        assert!(!events.read_state(11));
    }

    #[test]
    fn wait_all_requires_every_event_and_consumes_auto_reset_members() {
        let irql = IrqlState::new();
        let mut events = EventStore::new();
        events.initialize(20, EventKind::Notification, true);
        events.initialize(21, EventKind::Synchronization, false);
        assert_eq!(
            events.poll_many(&[20, 21], true, &irql),
            WaitManyResult::TimedOut
        );
        events.set_existing(21);
        assert_eq!(
            events.poll_many(&[20, 21], true, &irql),
            WaitManyResult::Signaled(0)
        );
        assert!(events.read_state(20));
        assert!(!events.read_state(21));
    }
}
