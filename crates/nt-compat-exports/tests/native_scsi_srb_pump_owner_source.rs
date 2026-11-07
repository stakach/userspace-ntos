//! The exact admitted SCSI dispatch publishes a bounded, atomic owner snapshot.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn scsi_owner_is_published_after_transfer_admission_and_retires_after_pump() {
    let dispatch = SOURCE.split("unsafe fn dispatch_irp_for_instance_exact(").nth(1).unwrap();
    let admit = dispatch.find("enter_active_hosted_irp_transfer(").unwrap();
    let claim = dispatch.find("SCSI_SRB_PUMP_OWNERS.claim(")
        .expect("RED: exact SCSI owner slot is claimed before provider pump");
    let enter = dispatch.find("scsi_srb_pump_timing.enter_pump()").unwrap();
    let pump = dispatch.find("component_scheduler::hosted_component_pump_with_caller(&ch, caller)").unwrap();
    let exit = dispatch.find("scsi_srb_pump_timing.exit_pump()").unwrap();
    let retire = dispatch.find("drop(scsi_srb_pump_owner)")
        .expect("RED: exact owner slot must retire after the provider pump returns");
    let release = dispatch.find("drop(transfer_guard)").unwrap();
    assert!(admit < claim && claim < enter && enter < pump && pump < exit
        && exit < retire && retire < release);
    assert!(dispatch.contains("canonical_irp_id") && dispatch.contains("request.device_id")
        && dispatch.contains("ch.reply_cap") && dispatch.contains("ingress_route.badge()"));
}

#[test]
fn nested_census_samples_only_atomic_scsi_owner_slots() {
    let print = SOURCE.split("fn print_scsi_srb_pump_timing()").nth(1).unwrap()
        .split("unsafe fn dispatch_irp_for_instance_exact(").next().unwrap();
    assert!(print.contains("SCSI_SRB_PUMP_OWNERS.snapshot_with_stage("),
        "RED: nested census needs stable per-owner atomic snapshots");
    assert!(print.contains("SCSI_SRB_PUMP_OWNERS.overflow_count()"));
    assert!(!print.contains("active_hosted_irp_transfer_mut(")
        && !print.contains("ACTIVE_HOSTED_IRP_TRANSFERS"));
}
