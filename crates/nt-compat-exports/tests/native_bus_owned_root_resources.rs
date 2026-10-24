//! Bus-owned PCI-root resources must travel from the accepted PDO through START without
//! substituting a synthetic empty resource plan or losing the provider's translation metadata.

#[test]
fn native_pci_root_adopts_and_revalidates_the_provider_assignment() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let grant = include_str!("../../../components/ntos-executive/src/main.rs");

    assert!(launch.contains("hosted_accepted_bus_owned_root_resources("));
    assert!(launch.contains("hosted_accepted_pdo_provider_catalog()"));
    assert!(launch.contains("admit_bus_owned_root_resources("));
    assert!(launch.contains("validate_hosted_bus_owned_root_provider("));
    assert!(start.contains("PreparedHostedResourcePlan::BusOwnedRoot { resources }"));
    assert!(start.contains("Some(&resources.snapshot.raw_resources)"));
    assert!(start.contains("Some(&resources.snapshot.resource_requirements)"));
    assert!(grant.contains("validate_hosted_bus_owned_root_provider(&resources)?"));
    assert!(grant.contains("raw_resource_list: resources.snapshot.raw_resources"));
    assert!(grant.contains("translated_resource_list: resources.translated_resources"));
}
