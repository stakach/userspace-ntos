//! Additional released PCI imports must resolve to source-backed NT kernel contracts.

#[test]
fn released_pci_debug_cpu_and_power_imports_have_native_bindings() {
    let pci = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers/pci.sys"));
    if let Ok(image) = pci {
        let pe = nt_pe_loader::PeFile::parse(&image).expect("pinned released pci.sys");
        let imported: std::collections::BTreeSet<String> = pe.imports().expect("PCI imports")
            .into_iter().filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .filter_map(|item| match item { nt_pe_loader::ImportRef::ByName { name, .. } => Some(name), _ => None })
            .collect();
        for name in ["KdDisableDebugger", "KdEnableDebugger", "KeIpiGenericCall",
                     "KeQueryActiveProcessorCountEx", "PoRequestPowerIrp"] {
            assert!(imported.contains(name), "pinned pci.sys no longer imports {name}");
        }
    }

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_pci_kernel.rs");
    assert!(launch.contains("hosted_driver_pci_kernel::bind_pci_kernel_exports(reg);"));
    for name in ["KdDisableDebugger", "KdEnableDebugger", "KeIpiGenericCall",
                 "KeQueryActiveProcessorCountEx"] {
        assert!(adapter.contains(&format!("reg.bind(\"{name}\",")), "missing real PCI import {name}");
    }
    let power = include_str!("../../../components/ntos-executive/src/hosted_driver_power_irp.rs");
    assert!(launch.contains("hosted_driver_power_irp::bind_power_irp_export(reg);"));
    assert!(power.contains("reg.bind(\"PoRequestPowerIrp\","));
}
