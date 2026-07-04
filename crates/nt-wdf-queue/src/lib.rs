//! # `nt-wdf-queue` — WDF I/O queue dispatch policy
//!
//! A WDF queue presents requests to a driver's I/O callbacks under a dispatch policy
//! (spec: NT KMDF/WDF Runtime, §15). This crate is the host-testable state machine:
//! sequential (one request in flight), parallel (many), or manual (the driver pulls),
//! with power-managed gating — a power-managed queue holds requests while the device is
//! out of D0 and releases them on D0 entry (spec §15.4). Requests are opaque
//! [`WdfHandle`]s; the runtime maps them to IRPs + invokes the callback. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use nt_wdf_object::WdfHandle;

/// `WDF_IO_QUEUE_DISPATCH_TYPE` (spec §15.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatchType {
    /// One request presented at a time; the next waits until the current completes.
    Sequential,
    /// Every request presented as it arrives.
    Parallel,
    /// Requests held until the driver calls `WdfIoQueueRetrieveNextRequest`.
    Manual,
}

/// A WDF I/O queue's dispatch state.
pub struct WdfIoQueue {
    dispatch: DispatchType,
    power_managed: bool,
    powered: bool,
    in_flight: u32,
    pending: VecDeque<WdfHandle>,
}

impl WdfIoQueue {
    /// Create a queue. A power-managed queue starts un-powered (it releases requests only
    /// after the device reaches D0, spec §15.4); a non-power-managed queue is always ready.
    pub fn new(dispatch: DispatchType, power_managed: bool) -> Self {
        Self {
            dispatch,
            power_managed,
            powered: !power_managed,
            in_flight: 0,
            pending: VecDeque::new(),
        }
    }

    /// Whether the queue may present a request to the driver right now.
    fn can_dispatch(&self) -> bool {
        if self.power_managed && !self.powered {
            return false;
        }
        match self.dispatch {
            DispatchType::Sequential => self.in_flight == 0,
            DispatchType::Parallel => true,
            DispatchType::Manual => false,
        }
    }

    /// A request arrives. Returns `Some(request)` if it should be presented to the driver
    /// now (and marks it in flight), or `None` if it was queued (spec §15.3).
    pub fn present(&mut self, request: WdfHandle) -> Option<WdfHandle> {
        if self.can_dispatch() {
            self.in_flight += 1;
            Some(request)
        } else {
            self.pending.push_back(request);
            None
        }
    }

    /// A presented request completed. Returns the next request to present (sequential), if
    /// any can now dispatch.
    pub fn complete_one(&mut self) -> Option<WdfHandle> {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.dispatch_next()
    }

    fn dispatch_next(&mut self) -> Option<WdfHandle> {
        if self.can_dispatch() {
            if let Some(r) = self.pending.pop_front() {
                self.in_flight += 1;
                return Some(r);
            }
        }
        None
    }

    /// `WdfIoQueueRetrieveNextRequest` — pull the next held request (manual dispatch, or
    /// draining a power-managed queue). Marks it in flight.
    pub fn retrieve_next(&mut self) -> Option<WdfHandle> {
        if self.power_managed && !self.powered {
            return None;
        }
        let r = self.pending.pop_front()?;
        self.in_flight += 1;
        Some(r)
    }

    /// Device power transition (spec §15.4). On D0 entry a power-managed queue releases as
    /// many held requests as its policy allows; on D0 exit it stops presenting. Returns the
    /// requests to present now.
    pub fn set_power(&mut self, on: bool) -> Vec<WdfHandle> {
        let mut released = Vec::new();
        if !self.power_managed {
            return released;
        }
        self.powered = on;
        if !on {
            return released;
        }
        // Drain according to policy: sequential releases one, parallel releases all.
        while let Some(r) = self.dispatch_next() {
            released.push(r);
            if self.dispatch == DispatchType::Sequential {
                break;
            }
        }
        released
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn is_powered(&self) -> bool {
        self.powered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u64) -> WdfHandle {
        // A synthetic request handle (type tag 4 = Request); opaque here.
        WdfHandle((4u64 << 56) | n)
    }

    #[test]
    fn sequential_one_in_flight() {
        let mut q = WdfIoQueue::new(DispatchType::Sequential, false);
        assert_eq!(q.present(h(1)), Some(h(1))); // dispatched
        assert_eq!(q.present(h(2)), None); // queued (one in flight)
        assert_eq!(q.present(h(3)), None);
        assert_eq!(q.pending_count(), 2);
        assert_eq!(q.complete_one(), Some(h(2))); // next released
        assert_eq!(q.complete_one(), Some(h(3)));
        assert_eq!(q.complete_one(), None);
        assert_eq!(q.in_flight(), 0);
    }

    #[test]
    fn parallel_all_dispatched() {
        let mut q = WdfIoQueue::new(DispatchType::Parallel, false);
        assert_eq!(q.present(h(1)), Some(h(1)));
        assert_eq!(q.present(h(2)), Some(h(2)));
        assert_eq!(q.present(h(3)), Some(h(3)));
        assert_eq!(q.in_flight(), 3);
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn manual_holds_until_retrieved() {
        let mut q = WdfIoQueue::new(DispatchType::Manual, false);
        assert_eq!(q.present(h(1)), None);
        assert_eq!(q.present(h(2)), None);
        assert_eq!(q.retrieve_next(), Some(h(1)));
        assert_eq!(q.retrieve_next(), Some(h(2)));
        assert_eq!(q.retrieve_next(), None);
    }

    #[test]
    fn power_managed_holds_until_d0() {
        let mut q = WdfIoQueue::new(DispatchType::Sequential, true);
        // Un-powered: requests are held.
        assert_eq!(q.present(h(1)), None);
        assert_eq!(q.present(h(2)), None);
        assert_eq!(q.in_flight(), 0);
        // D0 entry releases one (sequential).
        let released = q.set_power(true);
        assert_eq!(released, alloc::vec![h(1)]);
        assert_eq!(q.in_flight(), 1);
        // Completing releases the next.
        assert_eq!(q.complete_one(), Some(h(2)));
        // D0 exit: new requests held again.
        q.set_power(false);
        assert_eq!(q.complete_one(), None);
        assert_eq!(q.present(h(3)), None);
    }

    #[test]
    fn parallel_power_managed_releases_all_on_d0() {
        let mut q = WdfIoQueue::new(DispatchType::Parallel, true);
        q.present(h(1));
        q.present(h(2));
        let released = q.set_power(true);
        assert_eq!(released.len(), 2);
        assert_eq!(q.in_flight(), 2);
    }
}
