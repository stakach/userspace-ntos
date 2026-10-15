//! A queued bus relation blocks sibling FILTER admission before an IRP is prepared.

#[test]
fn queued_pci_relation_retains_sibling_filter_owner_without_dispatch() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let filter = launch
        .split("pub(crate) unsafe fn filter_hosted_device_resource_requirements(")
        .nth(1)
        .expect("missing hosted FILTER admission");
    let filter = &filter[..filter
        .find("pub(crate) unsafe fn observe_hosted_filter_resource_requirements(")
        .expect("missing hosted FILTER observation boundary")];
    let admission = launch
        .split("pub(crate) unsafe fn hosted_filter_resource_admission_pending() -> bool {")
        .nth(1)
        .expect("missing shared FILTER admission boundary")
        .split('}')
        .next()
        .expect("missing FILTER admission body");
    assert!(admission.contains("hosted_bus_relation_pending()"));
    assert!(admission.contains("HOSTED_ACPI_PCI_ROUTE_QUERY"));
    let pending_relation = filter
        .find("hosted_filter_resource_admission_pending()")
        .expect("a queued PCI BusRelations request must block sibling FILTER admission");
    let pending_return = filter
        .find("HostedFilterRequirementsOutcome::AdmissionPending")
        .expect("busy FILTER admission must retain its caller's owner");
    let prepare_irp = filter
        .find("prepare_external_pnp_owned_to_device(")
        .expect("missing canonical FILTER IRP preparation");
    assert!(pending_relation < pending_return);
    assert!(pending_return < prepare_irp, "no FILTER IRP may be prepared while relations queue");

    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    assert!(start.contains("HostedFilterRequirementsOutcome::AdmissionPending"));
    assert!(start.contains("HostedPnpDevnodeProgress::FilterAdmissionPending { device_id, resource_plan }"));
    assert!(start.contains("self.pending_filter_admission = Some(PendingHostedFilterAdmission"));
    assert!(start.contains("if let Some(pending) = self.pending_filter_admission.take()"));
}
