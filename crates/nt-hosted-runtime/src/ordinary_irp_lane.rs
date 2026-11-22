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

/// Major-function slots in a WDM `DRIVER_OBJECT` (`IRP_MJ_MAXIMUM_FUNCTION + 1`).
const IRP_MAJOR_FUNCTION_COUNT: u64 = 0x1c;

/// Whether a dispatch-worker lane runs an IRP of this major through the driver's MajorFunction
/// table. A worker that takes the primary's ordinary IRPs must dispatch every major the
/// primary does; lane controls (copy, ACK, cancel, callbacks) are handled before this.
pub const fn worker_lane_dispatches_major(major: u64) -> bool {
    major < IRP_MAJOR_FUNCTION_COUNT
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
