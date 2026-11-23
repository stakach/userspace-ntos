//! START preflight and grant must reconcile the bus report with the exact child's _CRS.

#[test]
fn acpi_child_start_uses_the_same_firmware_route_for_preflight_and_grant() {
    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let preflight = start
        .split_once("if let Some(driver_launch::AcceptedAcpiChildResources::Present(resources))")
        .unwrap()
        .1
        .split_once("match driver_launch::hosted_accepted_unidentified_bus_no_resources")
        .unwrap()
        .0;
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let grant = main
        .split_once("unsafe fn grant_hosted_acpi_child_devnode_resources(")
        .unwrap()
        .1
        .split_once("fn ")
        .unwrap()
        .0;
    for path in [preflight, grant] {
        assert!(
            path.contains("resolve_hosted_acpi_child_interrupt("),
            "a raw CM line cannot distinguish the direct GSI and legacy IRQ cases"
        );
        assert!(!path.contains("resolve_hosted_legacy_irq("));
    }
    assert!(
        grant.find("hosted_acpi_child_interrupt_identity(").unwrap()
            < grant.find("resolve_hosted_acpi_child_interrupt(").unwrap()
    );
}
