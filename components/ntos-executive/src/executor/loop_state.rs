//! State of the hosted service loop (issue #382, loop hoist).
//!
//! The loop in `service_sec_image()` kept its state in function locals captured by local
//! macros. Those locals become the fields of `LoopState`, grouped by concern; each group is
//! also a borrow unit, so a helper takes the groups it needs while its caller still holds a
//! reference into another group.
//!
//! This file is declared from `service_sec_image.rs`: the loop still reaches that module's
//! private helpers, so the hoisted files stay its children until those helpers are ported.

/// The verdict the service loop returns to `_start`, and the working fault counters of the
/// process whose event is being served.
pub(super) struct LoopExit {
    /// Working copies of `procs[pi].{faults, first, ntfaults}`: loaded at event admission
    /// and saved back before each receive.
    pub(super) faults: u64,
    pub(super) first: u64,
    pub(super) ntfaults: u64,
    pub(super) stop: u64,
    pub(super) stop_ssn: u64,
    /// A single terminal receipt identifies which safety gate ended the serialized loop.
    /// The source location is recorded at the branch, before any quiesce checkpoint can fail.
    pub(super) service_loop_exit_site: u32,
    pub(super) service_loop_exit_reason: &'static [u8],
    pub(super) iters: u64,
    pub(super) dbgsvc: u64,
}

impl LoopExit {
    pub(super) fn new() -> Self {
        Self {
            faults: 0,
            first: 0,
            ntfaults: 0,
            stop: 0,
            stop_ssn: 0,
            service_loop_exit_site: 0,
            service_loop_exit_reason: b"unrecorded",
            iters: 0,
            dbgsvc: 0,
        }
    }

    /// Record the branch that ends the loop. The site is the line of the outermost call, as
    /// `line!()` reported it while this was a local macro.
    #[track_caller]
    pub(super) fn record(&mut self, reason: &'static [u8]) {
        self.service_loop_exit_site = core::panic::Location::caller().line();
        self.service_loop_exit_reason = reason;
    }
}

/// Per-process park masks. See the park and quiesce contract in `service_sec_image()`.
pub(super) struct Parks {
    /// Top-level process badges that have hit an unrecoverable crash.
    pub(super) crash_parked: u64,
    /// Which THREAD badges have already logged a `[parked]` fault line (see `park_and_log!`).
    pub(super) crash_logged: u64,
    /// Cooperative-wait owner mask, derived from THREAD_WAIT_PARKED. Each deadline-less park
    /// records the actual hosted thread badge; completion paths clear that badge when they
    /// resume the stolen reply cap. A process contributes to this mask only when every live
    /// hosted thread with a real TCB is parked, so ordinary worker churn no longer clears or
    /// sets process liveness as a side effect.
    pub(super) wait_parked: u64,
}

pub(super) struct LoopState {
    pub(super) exit: LoopExit,
    pub(super) parks: Parks,
}
