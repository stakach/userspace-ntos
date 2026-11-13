//! An accepted SCSI-style PDO with completed empty resource queries keeps its bus owner.

const START: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const EXEC: &str = include_str!("../../../components/ntos-executive/src/main.rs");

#[test]
fn unknown_bus_empty_child_reaches_exact_no_resource_plan_and_revalidation() {
    assert!(START.contains("PreparedHostedResourcePlan::AcceptedBusNoResources"));
    assert!(START.contains("hosted_accepted_unidentified_bus_no_resources"));
    assert!(START.contains("validate_hosted_accepted_unidentified_bus_no_resources"));
    assert!(LAUNCH.contains("accepted_unidentified_bus_child_no_resources(instance_path, properties)"));
    assert!(LAUNCH.contains("devnode_identity_for_pdo(pdo_device_id)"));
    assert!(LAUNCH.contains("hosted_accepted_pdo_provider_catalog()"));
    let fallback = START.find("if bus_pdo.is_some() {\n        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);")
        .expect("accepted child cannot enter synthetic root fallback");
    let synthetic = START[fallback..].find("resource_plan: PreparedHostedResourcePlan::None")
        .expect("synthetic root fallback remains for no bus PDO");
    assert!(synthetic > 0);
    let grant = EXEC.find("PreparedHostedResourcePlan::AcceptedBusNoResources { .. }")
        .expect("native empty START grant recognizes accepted child");
    assert!(EXEC[grant..].contains("filtered_resource_requirements.is_empty()"));
}

#[test]
fn malformed_accepted_non_pci_child_cannot_fall_through_to_host_inventory() {
    let accepted = START.find("hosted_accepted_unidentified_bus_no_resources(instance_id, pdo)")
        .expect("accepted child classifier");
    let inventory = START[accepted..].find("let context = match hosted_pnp_context_description(&lease)")
        .map(|offset| accepted + offset).expect("host PCI/platform inventory lookup");
    let guard = START[accepted..inventory]
        .find("if bus_pdo.is_some() && nt_pnp::parse_pci_id_pattern(instance_id).is_none()")
        .expect("non-PCI accepted child must fail before synthetic inventory matching");
    assert!(accepted + guard < inventory);
}
