//! The canonical START IRP may complete at the PDO after the FDO forwards it.
//! Critical-child handoff still belongs to the exact configured FDO binding.

#[test]
fn config_start_handoff_accepts_manager_receipt_from_lower_completion() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("pub(crate) unsafe fn retire_hosted_critical_child_from_config_start(")
        .expect("missing config critical-child handoff");
    let end = source[start..]
        .find("unsafe fn copy_hosted_device_relations_result(")
        .expect("missing end of config handoff");
    let handoff = &source[start..start + end];

    assert!(handoff.contains("binding.driver_id != driver_id"));
    assert!(handoff.contains("binding.device_id != receipt.fdo_device_id()"));
    assert!(handoff.contains("binding.pdo_device_id != receipt.pdo_device_id()"));
    assert!(handoff.contains("retire_reserved_from_start("));
    assert!(
        !handoff.contains("receipt.completion_driver_id() != driver_id")
            && !handoff.contains("receipt.completion_device_id() != receipt.fdo_device_id()"),
        "a lower PDO completion is valid for an exact configured FDO START"
    );
}
