//! Local IRQL / event / spinlock stubs (spec §14). Single-threaded, simulated —
//! no real scheduler, preemption, or cross-thread wait.

use alloc::vec::Vec;

use nt_kernel_abi::GuestAddr;

pub const PASSIVE_LEVEL: u8 = 0;
pub const APC_LEVEL: u8 = 1;
pub const DISPATCH_LEVEL: u8 = 2;

/// A simulated single-CPU IRQL (spec §14.1).
pub struct Irql {
    level: u8,
    invalid_transitions: u32,
}

impl Default for Irql {
    fn default() -> Self {
        Self {
            level: PASSIVE_LEVEL,
            invalid_transitions: 0,
        }
    }
}

impl Irql {
    pub fn current(&self) -> u8 {
        self.level
    }

    /// `KeRaiseIrql`: raise to `new` (must be `>=` current), returning the old
    /// level. A lowering "raise" is recorded as an invalid transition.
    pub fn raise(&mut self, new: u8) -> u8 {
        let old = self.level;
        if new < old {
            self.invalid_transitions += 1;
        }
        self.level = new;
        old
    }

    /// `KeLowerIrql`: lower to `new` (must be `<=` current).
    pub fn lower(&mut self, new: u8) {
        if new > self.level {
            self.invalid_transitions += 1;
        }
        self.level = new;
    }

    pub fn invalid_transitions(&self) -> u32 {
        self.invalid_transitions
    }
}

/// Local event state keyed by the driver's `PKEVENT` guest address (spec §14.3).
/// We track state runtime-side rather than modelling the `KEVENT` layout.
#[derive(Default)]
pub struct EventTable {
    events: Vec<(GuestAddr, EventState)>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventState {
    pub signaled: bool,
    pub manual_reset: bool,
}

impl EventTable {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    fn slot(&mut self, addr: GuestAddr) -> &mut EventState {
        if let Some(i) = self.events.iter().position(|(a, _)| *a == addr) {
            return &mut self.events[i].1;
        }
        self.events.push((
            addr,
            EventState {
                signaled: false,
                manual_reset: false,
            },
        ));
        &mut self.events.last_mut().unwrap().1
    }

    /// `KeInitializeEvent(addr, manual_reset, initial_state)`.
    pub fn initialize(&mut self, addr: GuestAddr, manual_reset: bool, signaled: bool) {
        *self.slot(addr) = EventState {
            signaled,
            manual_reset,
        };
    }

    /// `KeSetEvent` — returns the previous signaled state.
    pub fn set(&mut self, addr: GuestAddr) -> bool {
        let s = self.slot(addr);
        let old = s.signaled;
        s.signaled = true;
        old
    }

    /// `KeClearEvent`.
    pub fn clear(&mut self, addr: GuestAddr) {
        self.slot(addr).signaled = false;
    }

    /// `KeResetEvent` — clears + returns the previous signaled state.
    pub fn reset(&mut self, addr: GuestAddr) -> bool {
        let s = self.slot(addr);
        let old = s.signaled;
        s.signaled = false;
        old
    }

    pub fn state(&self, addr: GuestAddr) -> Option<EventState> {
        self.events
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, s)| *s)
    }
}
