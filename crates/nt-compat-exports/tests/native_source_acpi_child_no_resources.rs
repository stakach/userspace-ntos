//! A bus-accepted ACPI child may complete both resource queries with no descriptors.

#[test]
fn accepted_acpi_child_without_resources_still_requires_exact_provider() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = driver
        .find("pub(crate) unsafe fn hosted_accepted_acpi_child_resources(")
        .unwrap();
    let end = driver[start..]
        .find("pub(crate) unsafe fn hosted_acpi_child_interrupt_identity(")
        .unwrap()
        + start;
    let source = &driver[start..end];
    let authority = source.find("hosted_accepted_pdo_provider_catalog()").unwrap();
    let no_resources = source
        .find("PropertyBlobState::KnownNone")
        .expect("completed ACPI resource queries may both report no descriptors");
    assert!(authority < no_resources, "authenticate the accepted provider before admitting no resources");
    assert!(source.contains("hosted_bus_reported_device_id(instance_path)"));
    assert!(source.contains("devnode_identity_for_pdo(pdo_device_id)"));

    let start_source = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let start = start_source.find("unsafe fn prepare_current_hosted_devnode<").unwrap();
    let end = start_source[start..].find("enum HostedPnpDevnodeProgress").unwrap() + start;
    let source = &start_source[start..end];
    assert!(source.contains("PreparedHostedResourcePlan::None"));
    assert!(source.contains("pdo_description: None"));
    assert!(source.contains("AcceptedAcpiChildResources::NoResources"),
        "an authenticated no-resource ACPI child must bypass unrelated resource discovery");
}

#[test]
fn no_resource_child_waits_for_route_admission_before_committing_or_starting() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let start = source.find("unsafe fn filter_attached_devnode(").unwrap();
    let end = source[start..].find("unsafe fn finish_filter_failure(").unwrap() + start;
    let source = &source[start..end];
    let gate = source
        .find("driver_launch::hosted_filter_resource_admission_pending()")
        .expect("the same relation and route gate must cover children with no requirements");
    let filter = source.find("resource_plan.native_property_blobs().1").unwrap();
    let empty_commit = source.find("commit_hosted_no_resource_requirements").unwrap();
    assert!(gate < filter && gate < empty_commit);
    assert!(source.contains("HostedPnpDevnodeProgress::FilterAdmissionPending { device_id, resource_plan }"));
}

#[test]
fn pending_no_resource_child_revalidates_its_accepted_relation_before_commit() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    assert!(source.contains("AcpiChildNoResources { provider, child }"),
        "the pending plan must retain accepted provider and child generations");
    let start = source.find("unsafe fn filter_attached_devnode(").unwrap();
    let end = source[start..].find("unsafe fn finish_filter_failure(").unwrap() + start;
    let filter = &source[start..end];
    let revalidation = filter
        .find("validate_hosted_accepted_acpi_no_resources")
        .expect("recheck current accepted relation on every admission redrive");
    let commit = filter.find("commit_hosted_no_resource_requirements").unwrap();
    assert!(revalidation < commit);
}
