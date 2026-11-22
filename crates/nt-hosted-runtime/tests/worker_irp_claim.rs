//! A dispatch-worker lane's claim on the ordinary IRP it entered (#427).
//!
//! Boot 44957371959: condrv's primary was parked in cmd's first console request, and
//! cmd's second request ran on the worker lane and returned STATUS_INVALID_PARAMETER
//! synchronously. That terminal was retired with no ACK control, the worker's claim on it was
//! never released, and every later console request and `Connection` create was refused with
//! STATUS_DEVICE_BUSY. The claim exists so that an IRP's own later controls (copy, ACK) reach
//! the lane whose bank holds it. It must end when the IRP's File owner retires.

use nt_hosted_runtime::WorkerIrpClaim;

#[test]
fn a_synchronously_returned_irp_frees_the_worker_when_its_owner_retires() {
    let mut claim = WorkerIrpClaim::idle();
    assert!(claim.enter(0x51));
    assert!(!claim.admits_new(), "the entered IRP's controls still target this lane");
    assert!(claim.release(0x51), "retiring its File owner ends the claim");
    assert!(claim.admits_new(), "the next console request is admitted");
    assert!(claim.enter(0x52));
}

#[test]
fn a_pending_irp_keeps_its_lane_for_its_own_controls_until_released() {
    let mut claim = WorkerIrpClaim::idle();
    assert!(claim.enter(0x61));
    assert!(claim.owns(0x61));
    assert!(!claim.enter(0x62), "one IRP at a time per worker bank");
    assert!(!claim.release(0x62), "another IRP's retirement is not this lane's");
    assert!(claim.owns(0x61));
    assert!(claim.release(0x61));
    assert!(!claim.owns(0x61));
    assert!(!claim.release(0x61), "a second release is not a second effect");
}

/// Boot 44963863150: cmd's console requests reached condrv's worker lane while the primary was
/// parked, but the worker's dispatch accepted only the i8042 HOOK and class CREATE majors and
/// answered IRP_MJ_DEVICE_CONTROL with a fabricated STATUS_INVALID_PARAMETER before condrv ran.
#[test]
fn the_worker_lane_dispatches_every_major_the_primary_does() {
    use nt_hosted_runtime::worker_lane_dispatches_major as dispatches;
    for major in 0..0x1cu64 {
        assert!(dispatches(major), "major {major:#x}");
    }
    assert!(!dispatches(0x1c), "not a major function");
    assert!(!dispatches(u64::MAX - 0x7bd), "lane controls are not IRP majors");
}
