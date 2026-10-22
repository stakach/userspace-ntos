//! LiberNT confines METHOD_EX absolute paths to the receiving ACPI PDO's subtree.
//! A PCI-root PDO cannot evaluate a sibling interrupt link's `_CRS` method.

#[test]
fn link_crs_uses_the_authenticated_busrelations_child_pdo() {
    let relation = include_str!("../../../components/ntos-executive/src/hosted_acpi_pci_relation.rs");
    let discovery = include_str!("../../nt-pnp/src/acpi_pci_routing_discovery.rs");
    let link = include_str!("../../../components/ntos-executive/src/hosted_acpi_pci_route_links.rs");

    // The native producer retains the exact PDO identity from the same BusRelations child
    // whose namespace self-path became the link candidate.
    assert!(
        relation.contains("for (child_index, properties) in query.child_properties.iter().enumerate()")
    );
    assert!(relation.contains("hosted_relation_child_identity(child_index)"));
    assert!(relation.contains("link_candidates.push(nt_pnp::AcpiPciLinkCandidateFact"));
    assert!(relation.contains("device_id: device_id.raw()"));
    assert!(relation.contains("pdo_object,"));
    assert!(relation.contains("if stale_child_identity"));
    assert!(relation.contains("HostedDeviceRelationQueryDisposition::Barrier("));

    // Planning carries that endpoint into the method query, and both initial dispatch and
    // completion authentication resolve it against the current hosted device identity.
    assert!(discovery.contains(".map_or(routing_query.endpoint, |candidate| candidate.endpoint)"));
    assert!(link.contains("hosted_acpi_pci_route_endpoint_device(method_query.endpoint)"));
    assert!(link.contains("hosted_acpi_pci_route_endpoint_device(method.endpoint)"));
}
