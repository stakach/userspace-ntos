//! The released ACPI provider returns a fixed 20-byte Information on overflow.

#[test]
fn pci_route_retry_uses_validated_probe_header_length() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_acpi_pci_routes.rs");
    let classify = source.split("fn classify_hosted_acpi_variable_eval_result(").nth(1)
        .expect("PCI route overflow classifier");
    let classify = classify.split("fn classify_hosted_acpi_pci_prt_result(").next().unwrap();
    assert!(classify.contains("eval_output_overflow_retry_len("));
    assert!(!classify.contains("let required = usize::try_from(information)"));
}
