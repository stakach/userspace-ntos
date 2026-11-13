//! Boot PnP STARTs wait for earlier retained START and initial bus relations.

#[test]
fn later_boot_batch_cannot_enter_before_retained_predecessor() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let prepare = &main[main.find("fn prepare_boot_driver_start(").unwrap()..];
    let prepare = &prepare[..prepare.find("struct DrivenBootDriverStart").unwrap()];
    assert!(prepare.contains("for earlier_slot in 0..pending.slot_count()"));
    assert!(prepare.contains("pending.get(earlier_slot)"));
    assert!(prepare.contains("PendingDriverStartOwner::Boot"));
    assert!(prepare.contains("predecessors.push(earlier.reservation)"));

    let drive = &main[main.find("unsafe fn drive_boot_driver_start(").unwrap()..];
    let drive = &drive[..drive.find("fn publish_boot_driver_start(").unwrap()];
    assert!(drive.contains("if predecessors.is_empty()"));
    assert!(drive.contains("OwnedHostedPnpStartProgress::AwaitingCompletion"));

    let publish = &main[main.find("fn publish_boot_driver_start(").unwrap()..];
    let publish = &publish[..publish.find("unsafe fn launch_boot_driver_service(").unwrap()];
    assert!(publish.contains("bootstrap_predecessors: predecessors"));
    assert!(publish.contains("PendingDriverStartOwner::Boot"));

    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let redrive = &service[service.find("unsafe fn pending_driver_start_redrive_all(").unwrap()..];
    let redrive = &redrive[..redrive.find("unsafe fn pending_pnp_operation_redrive_all(").unwrap()];
    assert!(redrive.contains("table.get_exact(*predecessor)"));
    assert!(redrive.contains("PendingDriverStartOwner::Boot"));
    assert!(redrive.contains("pending.batch.drive_after_completion_pump()"));
}
