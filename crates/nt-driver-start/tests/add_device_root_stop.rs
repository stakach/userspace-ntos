//! A quarantined AddDevice fails its devnode; the root keeps serving (#420).
//!
//! Boot 44999127278: Disk's AddDevice child was quarantined and the root then exited the
//! service loop (`[service-loop-exit] reason=add-device-parent-retained`). On NT a failed
//! AddDevice fails only that devnode (`CM_PROB_FAILED_ADD`) and enumeration continues.

use nt_driver_start::{
    root_add_device_stop_action, BatchError, BatchPhase, DriverStartBatch, RootAddDeviceStop,
    RootAddDeviceStopAction, CM_PROB_FAILED_ADD, DN_HAS_PROBLEM, STATUS_UNSUCCESSFUL,
    UNCERTAIN_ADD_DEVICE,
};

#[test]
fn a_quarantined_add_device_fails_its_devnode_and_the_loop_continues() {
    assert_eq!(root_add_device_stop_action(RootAddDeviceStop::ParentRetained),
        RootAddDeviceStopAction::FailDevnode);
    assert_eq!(UNCERTAIN_ADD_DEVICE.problem, CM_PROB_FAILED_ADD);
    assert_eq!(UNCERTAIN_ADD_DEVICE.devnode_status, DN_HAS_PROBLEM);
    assert_eq!(UNCERTAIN_ADD_DEVICE.status, STATUS_UNSUCCESSFUL);

    // The uncertain devnode's batch keeps its cursor: nothing is released, replayed or
    // dispatched past it, and it never reports completion.
    let mut batch = DriverStartBatch::new(7, 2);
    assert_eq!(batch.fail_entered_add_device(STATUS_UNSUCCESSFUL), Ok(()));
    assert_eq!(batch.phase(), BatchPhase::OwnershipLost { status: STATUS_UNSUCCESSFUL });
    assert_eq!(batch.next_devnode(), 0);
    assert_eq!(batch.begin_next(), Err(BatchError::OwnershipLost));
    assert_eq!(batch.stop(), Err(BatchError::OwnershipLost));
    assert_eq!(batch.fail_entered_add_device(STATUS_UNSUCCESSFUL), Err(BatchError::OwnershipLost));
}

#[test]
fn only_a_devnode_still_at_its_cursor_can_fail_its_add_device() {
    let mut batch = DriverStartBatch::new(7, 1);
    let token = batch.begin_next().unwrap();
    assert_eq!(batch.fail_entered_add_device(STATUS_UNSUCCESSFUL), Err(BatchError::WrongPhase));
    batch.dispatch_terminal(token).unwrap();
    assert_eq!(batch.fail_entered_add_device(STATUS_UNSUCCESSFUL), Err(BatchError::Complete));
}

#[test]
fn a_broken_root_invariant_still_ends_the_service_loop() {
    for stop in [RootAddDeviceStop::IngressChanged, RootAddDeviceStop::Settle,
        RootAddDeviceStop::Notification]
    {
        assert_eq!(root_add_device_stop_action(stop), RootAddDeviceStopAction::Terminal, "{stop:?}");
    }
}
