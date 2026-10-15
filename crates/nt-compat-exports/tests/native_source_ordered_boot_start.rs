//! Boot PnP STARTs wait for earlier retained START and initial bus relations.

#[test]
fn later_boot_batch_cannot_enter_before_retained_predecessor() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let launch = &main[main.find("unsafe fn launch_boot_driver_service(").unwrap()..];
    let launch = &launch[..launch.find("fn report_deferred_generic_hardware_checks(").unwrap()];
    assert!(launch.contains("for earlier_slot in 0..driver_starts.pending.slot_count()"));
    assert!(launch.contains("bootstrap_predecessors: predecessors"));
    assert!(launch.contains("PendingDriverStartOwner::Boot"));
    assert!(launch.contains("OwnedHostedPnpStartProgress::AwaitingCompletion"));

    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let redrive = &service[service.find("unsafe fn pending_driver_start_redrive_all(").unwrap()..];
    let redrive = &redrive[..redrive.find("unsafe fn pending_pnp_operation_redrive_all(").unwrap()];
    assert!(redrive.contains("table.get_exact(*predecessor)"));
    assert!(redrive.contains("PendingDriverStartOwner::Boot"));
    assert!(redrive.contains("pending.batch.drive_after_completion_pump()"));
}
