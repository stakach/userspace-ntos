//! An ordinary IRP that no hosted lane can admit waits, and is admitted later (#427).
//!
//! Boot 44957371959: condrv's primary lane was parked in cmd's first console request and its
//! only worker held another IRP. Every further console request and `Connection` create was
//! completed with STATUS_DEVICE_BUSY, a status NT never returns for that. Such an IRP now
//! waits in its File row and is retried only after a lane frees, oldest first per driver.

use nt_hosted_runtime::{
    queued_admission_candidates, select_ordinary_irp_lane, OrdinaryIrpLane, QueuedIrp,
};

const CONDRV: u64 = 6;
const KBDCLASS: u64 = 9;

fn queued(id: u64, driver: u64, refused_at: u64) -> QueuedIrp {
    QueuedIrp { id, driver, refused_at, cancel_queued: false }
}

#[test]
fn a_third_concurrent_irp_waits_and_is_admitted_once_a_lane_frees() {
    // Primary parked in cmd's request, worker holding conhost's pending request.
    assert_eq!(select_ordinary_irp_lane(false, true, false), OrdinaryIrpLane::Busy);
    let queue = [queued(1, CONDRV, 40)];
    assert!(queued_admission_candidates(&queue, 40).is_empty(), "no lane freed: no retry spin");
    assert_eq!(queued_admission_candidates(&queue, 41), [1], "a freed lane admits it");
}

#[test]
fn queued_irps_for_one_driver_are_admitted_oldest_first() {
    let queue = [queued(7, CONDRV, 40), queued(3, CONDRV, 40), queued(5, KBDCLASS, 40)];
    assert_eq!(queued_admission_candidates(&queue, 41), [3, 5]);
}

#[test]
fn a_cancelled_or_abandoned_queued_irp_completes_without_waiting_for_a_lane() {
    let mut cancelled = queued(9, CONDRV, 40);
    cancelled.cancel_queued = true;
    let queue = [queued(4, CONDRV, 40), cancelled];
    assert_eq!(queued_admission_candidates(&queue, 40), [9]);
    assert_eq!(queued_admission_candidates(&queue, 41), [4, 9]);
}
