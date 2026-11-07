//! The PCI power import must retain its source IRP until the real lower completion.

use nt_pe_loader::ImportRef;
use std::path::Path;

#[test]
fn pinned_pci_power_request_has_completion_owned_native_binding() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/pci.sys");
    if image.is_file() {
        let bytes = std::fs::read(image).unwrap();
        let pe = nt_pe_loader::PeFile::parse(&bytes).unwrap();
        assert!(pe.imports().unwrap().into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .any(|entry| matches!(entry, ImportRef::ByName { name, .. } if name == "PoRequestPowerIrp")));
    }

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_power_irp.rs");
    assert!(launch.contains("hosted_driver_power_irp::bind_power_irp_export(reg);"));
    assert!(adapter.contains("reg.bind(\"PoRequestPowerIrp\""));
    assert!(adapter.contains("s_io_get_attached_device_reference"));
    assert!(adapter.contains("s_io_allocate_irp"));
    assert!(adapter.contains("s_po_call_driver"));
    assert!(adapter.contains("s_obf_dereference_object"));
    assert!(adapter.contains("s_io_free_irp"));
    assert!(adapter.contains("STATUS_MORE_PROCESSING_REQUIRED"));
}

#[test]
fn foreign_power_publishes_exact_next_stack_target_before_capture() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let forward = launch.split("unsafe fn forward_hosted_power(").nth(1).unwrap()
        .split("/// `NTSTATUS IofCallDriver").next().unwrap();
    let target_write = forward.find(
        "write_unaligned((next + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET)"
    ).unwrap();
    let capture_call = forward.find(
        "(FSD_SERVICE_LOWER_POWER_FORWARD_LABEL << 12) | 4"
    ).unwrap();
    assert!(target_write < capture_call,
        "the source-domain capture must observe the exact target in the forwarded stack");
}

#[test]
fn foreign_power_keeps_system_context_and_shutdown_action_across_host_boundary() {
    let capture = include_str!("../../../components/ntos-executive/src/hosted_lower_power_capture.rs");
    let peer = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let canonical = include_str!("../../../crates/nt-io-manager/src/driver_peer.rs");
    // These are separate x64 POWER union members, not padding: a system shutdown
    // can reach PCI with a nonzero POWER_ACTION.
    assert!(capture.contains("stack.parameters[0] as u32"));
    assert!(capture.contains("stack.parameters[3] as u32"));
    assert!(canonical.contains("power_system_context,"));
    assert!(canonical.contains("power_shutdown_type,"));
    assert!(peer.contains("system_context: request.power_system_context"));
    assert!(peer.contains("shutdown_type: request.power_shutdown_type"));
}
