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
}
