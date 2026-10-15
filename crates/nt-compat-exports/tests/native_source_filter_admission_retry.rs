//! A transient global PnP query must defer FILTER without reentering native AddDevice.

#[test]
fn filter_admission_retains_attached_stack_and_resource_lease_for_retry() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let filter = &driver[driver
        .find("pub(crate) unsafe fn filter_hosted_device_resource_requirements(")
        .unwrap()..];
    let admission = filter.find("HostedFilterRequirementsOutcome::AdmissionPending").expect(
        "a global query must return a distinct pre-dispatch admission outcome",
    );
    let prepare = filter.find("prepare_external_pnp_owned_to_device(").unwrap();
    assert!(admission < prepare, "admission must precede FILTER IRP allocation");

    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    assert!(start.contains("FilterAdmissionPending {"));
    assert!(start.contains("pending_filter_admission: Option<PendingHostedFilterAdmission>"));
    let retry = &start[start.find("unsafe fn drive_inner(").unwrap()..];
    let retained = retry.find("self.pending_filter_admission.take()").expect(
        "drive must resume from the retained FDO and plan",
    );
    let fresh = retry.find("start_one_devnode(").unwrap();
    assert!(retained < fresh, "retry must not reenter native AddDevice");
    let retry = &retry[retained..fresh];
    assert!(retry.contains("filter_attached_devnode("));
    let continuation = &start[start.find("unsafe fn filter_attached_devnode(").unwrap()..];
    assert!(continuation.contains("filter_hosted_device_resource_requirements("));
    assert!(continuation.contains("start_filtered_devnode("));
}
