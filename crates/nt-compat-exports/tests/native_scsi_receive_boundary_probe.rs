//! The final root receive must expose the retained SCSI terminal state before sleeping.

const SERVICE: &str = include_str!(
    "../../../components/ntos-executive/src/service_sec_image.rs"
);
const SCSI: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_scsi_srb_work.rs"
);
const DRIVER: &str = include_str!(
    "../../../components/ntos-executive/src/driver_launch.rs"
);

#[test]
fn final_receive_observes_exact_scsi_owner_after_ordinary_redrive() {
    let start = SERVICE.find("fn finalize_service_loop_state(").unwrap();
    let end = SERVICE[start..].find("fn report_service_finalize_failure(").unwrap() + start;
    let body = &SERVICE[start..end];
    let reconcile = body.find("component_resume::reconcile(nt_handler)").unwrap();
    let observe = body.find("driver_launch::trace_hosted_scsi_receive_boundary()").expect(
        "the exact retained SCSI owner must be observed before root receive");
    let timer = body.find("rearm_requested_mounted_native_timer(nt_handler)").unwrap();
    assert!(reconcile < observe && observe < timer);
    assert!(body.contains("SavedMessageBuffer::capture()"),
        "observation must preserve the current IPC buffer");
    assert!(DRIVER.contains("fn trace_hosted_scsi_receive_boundary()"));
    assert!(DRIVER.contains("hosted_scsi_srb_work::trace_receive_boundary()"));
}

#[test]
fn receive_probe_is_bounded_and_does_not_drive_completion() {
    let start = SCSI.find("pub(super) unsafe fn trace_receive_boundary()").expect(
        "receive probe exists");
    let end = SCSI[start..].find("pub(super) unsafe fn acknowledge(").unwrap() + start;
    let body = &SCSI[start..end];
    for required in [
        "source_irp_address()", "use_ticket().epoch().get()", "canonical_irp",
        "completed_irp(irp)", "nested_device_control_completion_ready_exact(irp.raw())",
        "terminal_status", "pending_wake", "reply_entered", "cancel_requested",
        "SCSI_RECEIVE_BOUNDARY_SEEN", "SCSI_RECEIVE_BOUNDARY_TRACE_COUNT",
    ] {
        assert!(body.contains(required), "missing retained observation: {required}");
    }
    for effect in [".advance(", ".take()", "acknowledge_completed_irp", "wake_after_restore("] {
        assert!(!body.contains(effect), "probe must not enter effect: {effect}");
    }
}
