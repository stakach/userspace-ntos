//! An ordinary provider dispatch parked in its own service wait (#420, #427 A).
//!
//! The root enters an ordinary IRP dispatch by pumping the provider's lane. A provider that
//! waits inside that dispatch (`KeWaitForSingleObject`, a guarded mutex, a spin wait) stops
//! its lane in a parked service Call. The wake may depend on any other hosted syscall: condrv
//! waits in cmd's DEVICE_CONTROL until conhost answers with its own IRP. If the root kept
//! receiving inside the pump, or awaited the pump in a root progress loop, no hosted syscall
//! would be delivered and that wake could never come.
//!
//! So when an owner outside the pump keeps its continuation (a File row), and no other pump's
//! receive encloses it, the pump yields to the root loop instead. The parked Call, its Reply
//! and the lane's suspension frame stay with the shared ingress owner, the pump's receive half
//! stays with the File row, and the dispatch's caller keeps waiting on its own Reply. The wait's wake (its signal or timeout)
//! acknowledges the parked Call; once the provider's next Call is retained the File row
//! resumes exactly that receive half.

/// What an entered pump knows when its own lane has stopped in a parked service Call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParkedDispatch {
    /// The pump's own lane is suspended in its own parked service Call.
    pub own_wait_parked: bool,
    /// An owner outside the pump keeps an unfinished pump and resumes it at a root boundary.
    pub owner_keeps_continuation: bool,
    /// The pump runs inside another lane's service, whose parent it holds parked.
    pub nested_in_lane: bool,
    /// The pump was entered inside another pump's receive (its nested File work, DPC or IRQ
    /// pass), even one whose own lane is parked rather than running.
    pub enclosing_receive: bool,
}

/// The entered shared receive's next step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParkedDispatchReceive {
    /// Keep receiving on the provider's lane inside this pump.
    Continue,
    /// Unwind the pump to its owner; the root loop delivers other work until the wake.
    YieldToRoot,
}

/// Only an ordinary dispatch with an owner for its continuation, entered at root level, can
/// leave its parked wait at the root. A nested lane's parent is held by this pump, and a pump
/// nobody keeps would have no receive half to resume.
///
/// The owner resumes the receive half only at a root boundary. An enclosing receive keeps the
/// root off that boundary until its own service settles, and that service may be waiting on
/// this very dispatch (partmgr's partition READ to disk in boot 44950677448): a yield there
/// has no resumer. Such a dispatch keeps receiving, and its wake (a DPC completion, a timer,
/// a signal) is serviced by its own receive, as before.
pub const fn parked_dispatch_receive(dispatch: ParkedDispatch) -> ParkedDispatchReceive {
    if dispatch.own_wait_parked && dispatch.owner_keeps_continuation && !dispatch.nested_in_lane
        && !dispatch.enclosing_receive
    {
        ParkedDispatchReceive::YieldToRoot
    } else {
        ParkedDispatchReceive::Continue
    }
}

/// How a File owner settles a pump that came back unfinished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnfinishedSettle {
    /// The File row keeps the continuation; a later root boundary resumes it.
    Keep,
    /// The ordinary service-continuation settlement (which may await the pump at root).
    Settle,
}

/// A pump parked in its own wait is kept even where the root could block: the root progress
/// loop does not deliver hosted syscalls, and the wake may need one.
pub const fn settle_unfinished(
    awaiting_own_wake: bool,
    outer_parent: bool,
    continuing_service: bool,
    scheduler_active: bool,
    root_may_block: bool,
) -> UnfinishedSettle {
    if outer_parent || continuing_service {
        UnfinishedSettle::Settle
    } else if awaiting_own_wake || scheduler_active || !root_may_block {
        UnfinishedSettle::Keep
    } else {
        UnfinishedSettle::Settle
    }
}

/// A kept dispatch pump as its owner sees it at a root boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeptDispatchTurn {
    /// Its continuation is ready: resume it now.
    Resume,
    /// It is parked in its own wait, whose wake has not been acknowledged: keep it unchanged.
    AwaitWake,
    /// Neither: an uncertain stop, fenced and never replayed.
    Fence,
}

/// `ready` is the continuation's exact retry readiness; `awaiting_own_wake` that it stopped
/// in its own parked service wait. A re-parked dispatch is live, not uncertain.
pub const fn kept_dispatch_turn(ready: bool, awaiting_own_wake: bool) -> KeptDispatchTurn {
    if ready {
        KeptDispatchTurn::Resume
    } else if awaiting_own_wake {
        KeptDispatchTurn::AwaitWake
    } else {
        KeptDispatchTurn::Fence
    }
}
