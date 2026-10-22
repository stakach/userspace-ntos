//! The pinned PCI bus driver's HAL frontier must have source-owned bindings.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const REQUIRED: [&str; 3] = [
    "HalQueryPciRoutedInterrupt",
    "HalpGetInterruptTargetInformation",
    "HalpGetMessageRoutingInfo",
];

#[test]
fn pinned_pci_hal_imports_bind_authoritative_routes_and_fail_closed_msi() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt"))
        .expect("pinned LiberNT release manifest");
    assert!(manifest.contains("source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d"));

    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/pci.sys");
    if image.is_file() {
        let bytes = std::fs::read(image).expect("pinned released pci.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("pinned released PCI PE");
        let actual: BTreeSet<String> = pe.imports().expect("PCI imports").into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("hal.dll"))
            .flat_map(|dll| dll.functions)
            .filter_map(|import| match import {
                ImportRef::ByName { name, .. } if REQUIRED.contains(&name.as_str()) => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(actual, REQUIRED.into_iter().map(str::to_owned).collect());
    }

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_hal_pci.rs");
    let topology = include_str!("../../../components/ntos-executive/src/hosted_pci_topology.rs");
    assert!(launch.contains("hosted_driver_hal_pci::bind_pci_hal_exports(reg);"));
    for name in REQUIRED {
        assert!(adapter.contains(&format!("reg.bind(\"{name}\",")), "missing native {name} binding");
    }
    assert!(topology.contains("resolve_pin(") && topology.contains("routes.validate("),
        "routed INTx must use accepted, generation-validated ACPI/PCI route authority");
    let msi_body = adapter.split("fn halp_get_message_routing_info(").nth(1)
        .and_then(|tail| tail.split("pub(crate) fn bind_pci_hal_exports").next())
        .expect("MSI HAL adapter body");
    assert!(msi_body.contains("STATUS_NOT_SUPPORTED") && adapter.contains("X86IRQIssueIRQHandlerMSI")
        && !msi_body.contains("write_unaligned") && !msi_body.contains("s_io_connect_interrupt"),
        "MSI routing must refuse absent kernel MSI delivery without returning a fake vector/address");
}
