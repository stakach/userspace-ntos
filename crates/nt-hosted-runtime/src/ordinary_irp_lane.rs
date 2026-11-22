//! The lane an ordinary IRP (CREATE, READ, WRITE, DEVICE_CONTROL, CLEANUP, CLOSE, ...) is
//! dispatched on (#427).
//!
//! NT lets a driver have any number of dispatches in flight, one per calling thread. A hosted
//! instance dispatches on its primary lane. When that lane is parked in a provider wait inside
//! an earlier dispatch (condrv's client request waits in KeWaitForSingleObject until conhost's
//! GET_NEXT_REQUEST answers it), the next IRP runs on the instance's idle dispatch-worker lane.
//! A primary that is running rather than waiting is not handed a second dispatch.

/// Where an ordinary IRP is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrdinaryIrpLane {
    /// The instance's primary lane is idle.
    Primary,
    /// The primary lane is parked in a provider wait; an idle worker lane takes the IRP.
    Worker,
    /// No lane can admit it now (`STATUS_DEVICE_BUSY`).
    Busy,
}

/// Choose the lane for an ordinary IRP. `primary_admits`: the primary lane is idle with a
/// stored Call. `primary_waiting`: the primary's current dispatch is parked in a provider wait.
/// `worker_admits`: the instance's dispatch-worker lane is prepared, idle and admissible.
pub const fn select_ordinary_irp_lane(
    primary_admits: bool,
    primary_waiting: bool,
    worker_admits: bool,
) -> OrdinaryIrpLane {
    if primary_admits {
        OrdinaryIrpLane::Primary
    } else if primary_waiting && worker_admits {
        OrdinaryIrpLane::Worker
    } else {
        OrdinaryIrpLane::Busy
    }
}

/// Where a copy, ACK or cancel control of an entered IRP runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlLane {
    Primary,
    Worker,
    /// No lane can run it now; the control is retried.
    Busy,
}

/// Choose the lane for a control of an IRP. A pending IRP's completion lives in the instance's
/// pending list, not a lane bank, so it may run on any admissible lane: the worker whose claim
/// holds the IRP's bank-resident state, else the primary if it admits, else an idle unclaimed
/// worker. A primary parked in a provider wait therefore never blocks another IRP's completion.
pub const fn select_control_lane(
    claimed_by_worker: bool,
    primary_admits: bool,
    idle_worker_admits: bool,
) -> ControlLane {
    if claimed_by_worker {
        ControlLane::Worker
    } else if primary_admits {
        ControlLane::Primary
    } else if idle_worker_admits {
        ControlLane::Worker
    } else {
        ControlLane::Busy
    }
}

/// Whether a worker's claim on the IRP it entered outlives the dispatch's return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimAfterReturn {
    Keep,
    Release,
}

/// Only state resident in the lane's bank (METHOD_NEITHER mutable input, whose copy control
/// reads that bank) keeps the claim; every other IRP frees the worker when its dispatch returns.
pub const fn worker_claim_after_return(bank_resident: bool) -> ClaimAfterReturn {
    if bank_resident { ClaimAfterReturn::Keep } else { ClaimAfterReturn::Release }
}

/// The ordinary IRP a dispatch-worker lane has entered. Its later controls (copy, ACK) must reach
/// this lane, whose bank holds it, so the lane admits no other IRP until the claim is released:
/// by the IRP's ACK on this lane or by the retirement of its File owner, whichever comes first.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkerIrpClaim(Option<u64>);

impl WorkerIrpClaim {
    pub const fn idle() -> Self {
        Self(None)
    }

    pub const fn admits_new(&self) -> bool {
        self.0.is_none()
    }

    pub fn owns(&self, irp: u64) -> bool {
        self.0 == Some(irp)
    }

    /// Claim the lane for `irp`; refused while another IRP holds it.
    pub fn enter(&mut self, irp: u64) -> bool {
        if self.0.is_some() {
            return false;
        }
        self.0 = Some(irp);
        true
    }

    /// End `irp`'s claim. Only that IRP's claim is released, and only once.
    pub fn release(&mut self, irp: u64) -> bool {
        if self.0 != Some(irp) {
            return false;
        }
        self.0 = None;
        true
    }
}

/// An ordinary IRP that no lane admitted, waiting in its owner (#427).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedIrp {
    /// Queue order: a smaller id was queued earlier.
    pub id: u64,
    /// The driver whose lanes must admit it.
    pub driver: u64,
    /// The lane epoch at which it was last refused.
    pub refused_at: u64,
    /// A cancel or abandon is queued; it completes without entry and needs no lane.
    pub cancel_queued: bool,
}

/// The queued IRPs to move now, in order: every one whose cancel is queued, and, once a lane
/// has freed since its refusal, only the oldest waiting IRP of each driver, so none overtakes an
/// earlier one and nothing is retried while no lane has changed.
pub fn queued_admission_candidates(queue: &[QueuedIrp], epoch: u64) -> alloc::vec::Vec<u64> {
    let mut candidates = alloc::vec::Vec::new();
    for irp in queue {
        let oldest = queue.iter()
            .filter(|other| other.driver == irp.driver && !other.cancel_queued)
            .all(|other| other.id >= irp.id);
        if irp.cancel_queued || (oldest && irp.refused_at != epoch) {
            candidates.push(irp.id);
        }
    }
    candidates.sort_unstable();
    candidates
}

/// How far a File caller's IRP has got. The caller's thread is inside IoCallDriver until the
/// driver returns, so a dispatch that is kept (parked in a provider wait) or still queued for a
/// lane is `InFlight`, never a STATUS_PENDING return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchProgress {
    InFlight,
    /// The driver returned STATUS_PENDING; its completion is still to come.
    ReturnedPending,
    /// The IRP's terminal status is published.
    Completed,
}

/// What a File caller's parked Reply receives now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InFlightReply {
    /// Keep the caller blocked.
    Hold,
    /// Release an asynchronous caller with STATUS_PENDING; its row keeps the completion.
    Pending,
    /// Reply with the IRP's own terminal status.
    Completion,
}

/// Whether the syscall parks its caller's Reply: a synchronous File always waits for the
/// completion, and any caller whose dispatch is still in flight waits for the driver's return.
pub const fn parks_file_caller(synchronous: bool, in_flight: bool) -> bool {
    synchronous || in_flight
}

/// The reply a parked File caller is owed at `progress`.
pub const fn in_flight_caller_reply(synchronous: bool, progress: DispatchProgress) -> InFlightReply {
    match progress {
        DispatchProgress::InFlight => InFlightReply::Hold,
        DispatchProgress::ReturnedPending if synchronous => InFlightReply::Hold,
        DispatchProgress::ReturnedPending => InFlightReply::Pending,
        DispatchProgress::Completed => InFlightReply::Completion,
    }
}

/// Asynchronous File callers held only because their dispatch was in flight, each linked to its
/// exact IRP. A driver return readies its caller; a boundary services only ready callers, and
/// with none ready it does nothing.
pub struct InFlightCallers<K> {
    held: alloc::vec::Vec<(K, u64, bool)>,
    ready: usize,
}

impl<K: Copy + PartialEq> InFlightCallers<K> {
    pub const fn new() -> Self {
        Self { held: alloc::vec::Vec::new(), ready: 0 }
    }

    pub fn hold(&mut self, caller: K, irp: u64) {
        self.held.push((caller, irp, false));
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// O(1): whether any held caller's driver has returned.
    pub const fn any_ready(&self) -> bool {
        self.ready != 0
    }

    /// `irp`'s dispatch returned (pending or completed); ready the caller linked to it.
    pub fn dispatch_returned(&mut self, irp: u64) -> bool {
        let mut readied = false;
        for (_, held_irp, ready) in &mut self.held {
            if *held_irp == irp && !*ready {
                *ready = true;
                self.ready += 1;
                readied = true;
            }
        }
        readied
    }

    /// Remove and return the ready callers; held ones are not visited when none is ready.
    pub fn take_ready(&mut self) -> alloc::vec::Vec<(K, u64)> {
        if self.ready == 0 {
            return alloc::vec::Vec::new();
        }
        let mut taken = alloc::vec::Vec::new();
        self.held.retain(|(caller, irp, ready)| {
            if *ready { taken.push((*caller, *irp)); }
            !*ready
        });
        self.ready = 0;
        taken
    }

    /// A ready caller whose reply could not be sent yet stays ready for the next boundary.
    pub fn retry(&mut self, caller: K, irp: u64) {
        self.held.push((caller, irp, true));
        self.ready += 1;
    }
}

impl<K: Copy + PartialEq> Default for InFlightCallers<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Major-function slots in a WDM `DRIVER_OBJECT` (`IRP_MJ_MAXIMUM_FUNCTION + 1`).
const IRP_MAJOR_FUNCTION_COUNT: u64 = 0x1c;

/// Whether a dispatch-worker lane runs an IRP of this major through the driver's MajorFunction
/// table. NT runs a driver's dispatches concurrently whatever their major, so a worker that
/// takes the primary's IRPs dispatches every major the primary does; lane controls (copy, ACK,
/// cancel, callbacks) are handled before this.
pub const fn worker_lane_dispatches_major(major: u64) -> bool {
    major < IRP_MAJOR_FUNCTION_COUNT
}

#[cfg(test)]
mod tests {
    use super::{select_ordinary_irp_lane as select, OrdinaryIrpLane as Lane};

    #[test]
    fn a_waiting_primary_hands_the_next_irp_to_an_idle_worker() {
        // Run 44920424349: condrv's primary lane waited in cmd's console request while
        // conhost's GET_NEXT_REQUEST, which answers it, was refused with STATUS_DEVICE_BUSY.
        assert_eq!(select(false, true, true), Lane::Worker);
    }

    #[test]
    fn an_idle_primary_is_used_and_a_running_or_unserved_one_is_busy() {
        assert_eq!(select(true, false, true), Lane::Primary);
        assert_eq!(select(true, true, true), Lane::Primary);
        // A running primary (not waiting) is not given a concurrent dispatch.
        assert_eq!(select(false, false, true), Lane::Busy);
        // A waiting primary with no idle worker cannot admit it.
        assert_eq!(select(false, true, false), Lane::Busy);
    }
}
