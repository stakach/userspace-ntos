//! The route _CRS filter must use the released namespace enumeration contract.

#[test]
fn route_filter_retries_the_provider_minimum_then_exact_reported_length() {
    let filter = include_str!("../../../components/ntos-executive/src/hosted_acpi_pci_route_filters.rs");
    let relation = include_str!("../../../components/ntos-executive/src/hosted_acpi_pci_relation.rs");
    assert!(filter.contains("ACPI_ENUM_CHILDREN_OUTPUT_MIN_LEN"));
    assert!(filter.contains("namespace_children_probe_retry_len("));
    assert!(!filter.contains("let required = (information == 0)"));
    assert!(!relation.contains("return match (information == 0)"));
}
