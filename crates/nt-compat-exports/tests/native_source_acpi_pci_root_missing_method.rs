//! An absent optional ACPI PCI root method has no output payload to copy.

#[test]
fn missing_pci_root_method_is_classified_before_payload_copy() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let phase = driver
        .find("HostedDeviceRelationQueryPhase::AwaitingAcpiPciRootMethodCopy {")
        .unwrap();
    let phase = &driver[phase..];
    let phase = &phase[..phase
        .find("HostedDeviceRelationQueryPhase::AwaitingAcpiPciRootMethodAck {")
        .unwrap()];
    assert!(phase.contains(
        "if status == nt_status::NtStatus::OBJECT_NAME_NOT_FOUND {\n                    classify_hosted_acpi_pci_root_method_result(status, information, &[])"
    ));
    assert!(phase.contains(".copy_completed_buffered_device_control_payload(irp_id, 0, &mut payload)"));
    assert!(driver.contains(
        "if status == nt_status::NtStatus::OBJECT_NAME_NOT_FOUND {\n        return if information == 0 {\n            HostedAcpiPciRootMethodDisposition::Value(0)"
    ));
}
