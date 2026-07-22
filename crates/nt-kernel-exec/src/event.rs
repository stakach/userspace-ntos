//! Event dispatcher objects (spec §6.5). A `KEVENT` is opaque driver storage; the
//! runtime keeps its state keyed by the driver's pointer. Notification events are
//! manual-reset; Synchronization events auto-reset when a wait consumes them.
//! Blocking waits integrate at the runtime level; the store provides the poll +
//! signal semantics.

use alloc::vec::Vec;

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
    /// Waiting is not permitted at the current IRQL (spec §6.1).
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
    /// Waiting is not permitted at the current IRQL.
    BadIrql,
}

struct Event {
    ptr: u64,
    kind: EventKind,
    signaled: bool,
}

/// The Driver Host's event store (spec §6.5).
#[derive(Default)]
pub struct EventStore {
    events: Vec<Event>,
}

impl EventStore {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Construct a store whose backing allocation can be made before a rewindable
    /// executive heap mark. Event operations do not allocate while within capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
        }
    }

    fn slot(&mut self, ptr: u64) -> &mut Event {
        if let Some(i) = self.events.iter().position(|e| e.ptr == ptr) {
            return &mut self.events[i];
        }
        self.events.push(Event {
            ptr,
            kind: EventKind::Notification,
            signaled: false,
        });
        self.events.last_mut().unwrap()
    }

    /// `KeInitializeEvent(Event, Type, State)`.
    pub fn initialize(&mut self, ptr: u64, kind: EventKind, signaled: bool) {
        let e = self.slot(ptr);
        e.kind = kind;
        e.signaled = signaled;
    }

    /// Whether an event identity has been initialized.
    pub fn contains(&self, ptr: u64) -> bool {
        self.events.iter().any(|event| event.ptr == ptr)
    }

    /// Remove an initialized event identity. The executive uses this to roll back an object whose
    /// newly-created handle could not be published to its caller.
    pub fn remove_existing(&mut self, ptr: u64) -> bool {
        let Some(index) = self.events.iter().position(|event| event.ptr == ptr) else {
            return false;
        };
        self.events.remove(index);
        true
    }

    /// Return the dispatcher type and signal state for an initialized event.
    pub fn query_existing(&self, ptr: u64) -> Option<(EventKind, bool)> {
        self.events
            .iter()
            .find(|event| event.ptr == ptr)
            .map(|event| (event.kind, event.signaled))
    }

    /// Strict `NtSetEvent` state transition. Unlike [`Self::set`], this never
    /// manufactures an event for an invalid handle.
    pub fn set_existing(&mut self, ptr: u64) -> Option<bool> {
        let event = self.events.iter_mut().find(|event| event.ptr == ptr)?;
        let previous = event.signaled;
        event.signaled = true;
        Some(previous)
    }

    /// Strict `NtResetEvent` state transition.
    pub fn reset_existing(&mut self, ptr: u64) -> Option<bool> {
        let event = self.events.iter_mut().find(|event| event.ptr == ptr)?;
        let previous = event.signaled;
        event.signaled = false;
        Some(previous)
    }

    /// Strict `NtClearEvent` state transition.
    pub fn clear_existing(&mut self, ptr: u64) -> bool {
        let Some(event) = self.events.iter_mut().find(|event| event.ptr == ptr) else {
            return false;
        };
        event.signaled = false;
        true
    }

    /// Consume a signaled synchronization event, leaving notification events set.
    pub fn consume_existing(&mut self, ptr: u64) -> bool {
        let Some(event) = self.events.iter_mut().find(|event| event.ptr == ptr) else {
            return false;
        };
        if !event.signaled {
            return false;
        }
        if event.kind == EventKind::Synchronization {
            event.signaled = false;
        }
        true
    }

    /// Poll `WaitAny`/`WaitAll` over existing event identities and apply NT
    /// synchronization-event consumption on success.
    pub fn poll_many(&mut self, ptrs: &[u64], wait_all: bool, irql: &IrqlState) -> WaitManyResult {
        if !irql.can_wait() {
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
            if ptrs.iter().any(|ptr| !self.read_state(*ptr)) {
                return WaitManyResult::TimedOut;
            }
            for ptr in ptrs {
                self.consume_existing(*ptr);
            }
            WaitManyResult::Signaled(0)
        } else if let Some(index) = ptrs.iter().position(|ptr| self.read_state(*ptr)) {
            self.consume_existing(ptrs[index]);
            WaitManyResult::Signaled(index)
        } else {
            WaitManyResult::TimedOut
        }
    }

    /// `KeSetEvent` — signal the event, returning the previous state.
    pub fn set(&mut self, ptr: u64) -> bool {
        let e = self.slot(ptr);
        let old = e.signaled;
        e.signaled = true;
        old
    }

    /// `KeResetEvent` — clear + return the previous state.
    pub fn reset(&mut self, ptr: u64) -> bool {
        let e = self.slot(ptr);
        let old = e.signaled;
        e.signaled = false;
        old
    }

    /// `KeClearEvent` — clear (no return value).
    pub fn clear(&mut self, ptr: u64) {
        self.slot(ptr).signaled = false;
    }

    /// `KeReadStateEvent` — the signaled state.
    pub fn read_state(&self, ptr: u64) -> bool {
        self.events.iter().any(|e| e.ptr == ptr && e.signaled)
    }

    /// Attempt a non-blocking wait / poll on the event: if signaled, succeed
    /// (consuming a Synchronization event); otherwise time out. Waiting above
    /// `APC_LEVEL` fails (spec §6.1). Blocking waits are the runtime's job — it
    /// advances the clock / drains work and re-polls.
    pub fn poll(&mut self, ptr: u64, irql: &IrqlState) -> WaitResult {
        if !irql.can_wait() {
            return WaitResult::BadIrql;
        }
        let e = self.slot(ptr);
        if e.signaled {
            if e.kind == EventKind::Synchronization {
                e.signaled = false; // auto-reset consumes the signal
            }
            WaitResult::Signaled
        } else {
            WaitResult::TimedOut
        }
    }
}

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
    fn waits_above_apc_rejected() {
        let mut irql = IrqlState::new();
        irql.raise(DISPATCH_LEVEL);
        let mut ev = EventStore::new();
        ev.initialize(0xE3, EventKind::Notification, true);
        assert_eq!(ev.poll(0xE3, &irql), WaitResult::BadIrql);
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
