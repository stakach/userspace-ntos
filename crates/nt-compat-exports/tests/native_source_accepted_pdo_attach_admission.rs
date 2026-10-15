//! A bus PDO with a live route-query IRP cannot enter irreversible AddDevice.

#[test]
fn accepted_pdo_waits_for_attachment_admission_before_native_add_device() {
    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let start = &start[start.find("unsafe fn start_one_devnode<").unwrap()..];
    let preflight = start
        .find("driver_launch::hosted_bus_pdo_attach_admission(")
        .expect("accepted PDO attachment admission must precede native AddDevice");
    let add_device = start.find("let add_device = if options.reuse_existing_stack").unwrap();
    assert!(preflight < add_device);
    let gate = &start[preflight..add_device];
    assert!(gate.contains("HostedPnpDevnodeProgress::ResourceAdmissionPending"));
    assert!(gate.contains("resource_plan.release_context_lease()"));

    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(driver.contains("pub(crate) unsafe fn hosted_bus_pdo_attach_admission("));
    assert!(driver.contains(".can_attach_new_device_above(nt_io_manager::DeviceId(pdo_device_id))"));
}
