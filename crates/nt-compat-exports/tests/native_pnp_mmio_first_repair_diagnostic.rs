//! The first StartDevice MMIO publication refusal records root-owned gate and resource shape.
//! Repeated repair attempts must not perform additional diagnostic reads.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const MMIO: &str = include_str!("../../../components/ntos-executive/src/hosted_mmio_broker.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source.split_once(start).expect("missing start").1
        .split_once(end).expect("missing end").0
}

#[test]
fn first_mmio_repair_reports_root_owned_gates_without_changing_publication() {
    let repair = between(
        LAUNCH,
        "unsafe fn trace_pnp_publication_repair(",
        "fn note_relation_gate(",
    );
    assert!(repair.contains("if phase == b\"enter\" && next == b\"mmio\""));
    assert!(repair.contains("trace_pnp_mmio_admission(irp_id, binding);"));

    let snapshot = between(
        LAUNCH,
        "unsafe fn trace_pnp_mmio_admission(",
        "unsafe fn trace_pnp_publication_repair(",
    );
    for gate in [
        "instance_by_driver_id(binding.driver_id)",
        "hosted_device_binding_by_device_id(binding.device_id)",
        "hosted_device_resource_state_by_device_id(binding.device_id)",
        "addr_of!(HOSTED_PNP_MANAGER)",
        "devnode_identity_for_pdo(binding.pdo_device_id)",
        "devnode_has_started_empty_assignment",
        "devnode_has_started_bus_number_assignment",
        "has_retained_pnp_device_rows(binding)",
        "boot_resources_raw", "boot_resources_translated",
        "resource_requirements", "filtered_resource_requirements",
        "allocated_resources_raw", "allocated_resources_translated",
        "validate_cm_resource_list_extent", "decode_single_bus_number_resource",
    ] {
        assert!(snapshot.contains(gate), "missing root-owned diagnostic: {gate}");
    }
    assert!(!snapshot.contains("return Err("));
    assert!(!snapshot.contains("hosted_pnp_manager_mut()"));
    assert!(!snapshot.contains("instance.exec_shared_va + SH_RESOURCE_"));

    let retained = between(MMIO, "pub(super) unsafe fn has_retained_pnp_device_rows(", "unsafe fn retained_pnp_state(");
    assert!(retained.contains("ledger.has_pnp_device_rows"));
}
