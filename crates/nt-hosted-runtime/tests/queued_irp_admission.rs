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

fn queued(id: u64, driver: u64, refused_at: u64, current_epoch: Option<u64>) -> QueuedIrp {
    QueuedIrp { id, driver, refused_at, current_epoch, wake_without_epoch: false,
        cancel_queued: false }
}

#[test]
fn a_third_concurrent_irp_waits_and_is_admitted_once_a_lane_frees() {
    // Primary parked in cmd's request, worker holding conhost's pending request.
    assert_eq!(select_ordinary_irp_lane(false, true, false), OrdinaryIrpLane::Busy);
    let queue = [queued(1, CONDRV, 40, Some(40))];
    assert!(queued_admission_candidates(&queue).is_empty(), "no lane freed: no retry spin");
    let queue = [queued(1, CONDRV, 40, Some(41))];
    assert_eq!(queued_admission_candidates(&queue), [1], "a freed lane admits it");
}

#[test]
fn queued_irps_for_one_driver_are_admitted_oldest_first() {
    let queue = [queued(7, CONDRV, 40, Some(41)), queued(3, CONDRV, 40, Some(41)),
        queued(5, KBDCLASS, 40, Some(41))];
    assert_eq!(queued_admission_candidates(&queue), [3, 5]);
}

#[test]
fn a_cancelled_or_abandoned_queued_irp_completes_without_waiting_for_a_lane() {
    let mut cancelled = queued(9, CONDRV, 40, Some(40));
    cancelled.cancel_queued = true;
    let queue = [queued(4, CONDRV, 40, Some(40)), cancelled];
    assert_eq!(queued_admission_candidates(&queue), [9]);
    let queue = [queued(4, CONDRV, 40, Some(41)), cancelled];
    assert_eq!(queued_admission_candidates(&queue), [4, 9]);
}

#[test]
fn an_owned_startup_or_readiness_wake_retries_once_without_overtaking() {
    let mut oldest = queued(7, CONDRV, 40, Some(40));
    oldest.wake_without_epoch = true;
    let mut newer = queued(8, CONDRV, 40, Some(40));
    newer.wake_without_epoch = true;
    assert_eq!(queued_admission_candidates(&[newer, oldest]), [7]);
    oldest.wake_without_epoch = false;
    assert!(queued_admission_candidates(&[newer, oldest]).is_empty(),
        "a consumed startup probe cannot retry or overtake without another owned event");
}

#[test]
fn a_retired_instance_is_redriven_for_explicit_manager_disposition() {
    let mut row = queued(10, CONDRV, 40, None);
    row.wake_without_epoch = true;
    assert_eq!(queued_admission_candidates(&[row]), [10]);
    row.wake_without_epoch = false;
    assert!(queued_admission_candidates(&[row]).is_empty(),
        "the stale-authority disposition probe is consumed even if redrive cannot enter");
}
