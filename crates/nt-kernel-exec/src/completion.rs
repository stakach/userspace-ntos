//! Deferred IRP completion tracking (spec §7.7, §12). The I/O Manager remains the
//! canonical owner of IRP state; the Driver Host tracks its **local projected** IRP
//! pointers so it can guarantee a pending IRP is completed **exactly once** and that
//! a cancellation can never double-complete (spec §20 quality gates).
//!
//! The state machine is `Pending → {Completed | Cancelled}`, and both are terminal —
//! whichever of `complete`/`cancel` wins the race makes the other conservative.

use alloc::vec::Vec;

/// The lifecycle of a pending IRP.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompletionState {
    /// Marked pending; a deferred callback owns it.
    Pending,
    /// Completed exactly once (`status`/`information` recorded).
    Completed,
    /// Cancelled before a completion was published.
    Cancelled,
}

/// The outcome of a `complete` attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompleteResult {
    /// This call completed the IRP (the first + only completion).
    Completed,
    /// The IRP was already in a terminal state — the completion is dropped (a
    /// double-complete, or a completion racing a prior cancel).
    AlreadyFinal,
}

/// The outcome of a `cancel` attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CancelResult {
    /// The IRP was pending and is now cancelled.
    Cancelled,
    /// Too late — the IRP was already completed (or cancelled).
    TooLate,
}

struct Pending {
    irp: u64,
    request_id: u64,
    state: CompletionState,
    status: i32,
    information: u64,
}

/// Tracks the Driver Host's in-flight (pending) local IRPs.
#[derive(Default)]
pub struct CompletionTracker {
    irps: Vec<Pending>,
}

impl CompletionTracker {
    pub fn new() -> Self {
        Self { irps: Vec::new() }
    }

    fn find(&mut self, irp: u64) -> Option<&mut Pending> {
        self.irps.iter_mut().find(|p| p.irp == irp)
    }

    /// `IoMarkIrpPending` — record that `irp` (identified to the I/O Manager by
    /// `request_id`) is now pending and a deferred callback owns it.
    pub fn mark_pending(&mut self, irp: u64, request_id: u64) {
        if let Some(p) = self.find(irp) {
            p.state = CompletionState::Pending;
            p.request_id = request_id;
            return;
        }
        self.irps.push(Pending {
            irp,
            request_id,
            state: CompletionState::Pending,
            status: 0,
            information: 0,
        });
    }

    /// `IoCompleteRequest` — complete the IRP exactly once. A second completion, or
    /// one racing a prior cancel, is dropped (`AlreadyFinal`). An unknown IRP is
    /// treated as a fresh synchronous completion (returns `Completed`).
    pub fn complete(&mut self, irp: u64, status: i32, information: u64) -> CompleteResult {
        match self.find(irp) {
            Some(p) if p.state == CompletionState::Pending => {
                p.state = CompletionState::Completed;
                p.status = status;
                p.information = information;
                CompleteResult::Completed
            }
            Some(_) => CompleteResult::AlreadyFinal,
            None => {
                self.irps.push(Pending {
                    irp,
                    request_id: 0,
                    state: CompletionState::Completed,
                    status,
                    information,
                });
                CompleteResult::Completed
            }
        }
    }

    /// Conservatively cancel a pending IRP (spec §12). Wins only if the IRP is still
    /// pending; a completed IRP's result stands (`TooLate`).
    pub fn cancel(&mut self, irp: u64) -> CancelResult {
        match self.find(irp) {
            Some(p) if p.state == CompletionState::Pending => {
                p.state = CompletionState::Cancelled;
                CancelResult::Cancelled
            }
            _ => CancelResult::TooLate,
        }
    }

    pub fn state(&self, irp: u64) -> Option<CompletionState> {
        self.irps.iter().find(|p| p.irp == irp).map(|p| p.state)
    }

    /// The recorded `(status, information)` of a completed IRP.
    pub fn result(&self, irp: u64) -> Option<(i32, u64)> {
        self.irps
            .iter()
            .find(|p| p.irp == irp && p.state == CompletionState::Completed)
            .map(|p| (p.status, p.information))
    }

    /// The `request_id` the IRP was marked pending with (for the I/O Manager).
    pub fn request_id(&self, irp: u64) -> Option<u64> {
        self.irps
            .iter()
            .find(|p| p.irp == irp)
            .map(|p| p.request_id)
    }

    pub fn pending_count(&self) -> usize {
        self.irps
            .iter()
            .filter(|p| p.state == CompletionState::Pending)
            .count()
    }

    /// Drop tracking for a finalised IRP (its completion was published to the I/O
    /// Manager).
    pub fn forget(&mut self, irp: u64) {
        self.irps.retain(|p| p.irp != irp);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const IRP: u64 = 0xABCD_0000;

    #[test]
    fn completes_exactly_once() {
        let mut t = CompletionTracker::new();
        t.mark_pending(IRP, 7);
        assert_eq!(t.state(IRP), Some(CompletionState::Pending));
        assert_eq!(t.complete(IRP, 0, 4), CompleteResult::Completed);
        // A second completion is dropped.
        assert_eq!(t.complete(IRP, -1, 0), CompleteResult::AlreadyFinal);
        assert_eq!(t.result(IRP), Some((0, 4))); // first result stands
        assert_eq!(t.request_id(IRP), Some(7));
    }

    #[test]
    fn complete_before_cancel() {
        let mut t = CompletionTracker::new();
        t.mark_pending(IRP, 1);
        assert_eq!(t.complete(IRP, 0, 8), CompleteResult::Completed);
        // Cancel loses — completion already published.
        assert_eq!(t.cancel(IRP), CancelResult::TooLate);
        assert_eq!(t.state(IRP), Some(CompletionState::Completed));
    }

    #[test]
    fn cancel_before_callback_runs() {
        let mut t = CompletionTracker::new();
        t.mark_pending(IRP, 1);
        assert_eq!(t.cancel(IRP), CancelResult::Cancelled);
        // The deferred callback's later completion is dropped (no double-complete).
        assert_eq!(t.complete(IRP, 0, 8), CompleteResult::AlreadyFinal);
        assert_eq!(t.state(IRP), Some(CompletionState::Cancelled));
    }

    #[test]
    fn cancel_while_dpc_queued_then_callback() {
        // Same as cancel-before-callback: the DPC is queued, we cancel, then the DPC
        // runs and tries to complete — rejected.
        let mut t = CompletionTracker::new();
        t.mark_pending(IRP, 1);
        assert_eq!(t.cancel(IRP), CancelResult::Cancelled);
        assert_eq!(t.cancel(IRP), CancelResult::TooLate); // idempotent-ish
        assert_eq!(t.complete(IRP, 0, 8), CompleteResult::AlreadyFinal);
    }

    #[test]
    fn cancel_after_completion_published() {
        let mut t = CompletionTracker::new();
        t.mark_pending(IRP, 1);
        t.complete(IRP, 0, 8);
        t.forget(IRP); // published to the I/O Manager, tracking dropped
                       // A late cancel for an unknown IRP is conservatively too-late.
        assert_eq!(t.cancel(IRP), CancelResult::TooLate);
    }
}
