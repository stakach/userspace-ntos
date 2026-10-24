//! The pinned PCI driver needs real range-list operations before DriverEntry.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const REQUIRED: [&str; 7] = [
    "RtlAddRange",
    "RtlCopyRangeList",
    "RtlDeleteOwnersRanges",
    "RtlFindRange",
    "RtlFreeRangeList",
    "RtlInitializeRangeList",
    "RtlInvertRangeList",
];

#[test]
fn pinned_pci_range_list_imports_resolve_through_the_kernel_registry() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt"))
        .expect("pinned LiberNT release manifest");
    assert!(manifest.contains("source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d"));

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("fn hosted_kernel_provider_dll(dll: &str) -> bool"));
    assert!(launch.contains("ascii_eq_ignore_case(dll, \"ntoskrnl.exe\")"));
    assert!(launch.contains("if let Some(va) = (*core::ptr::addr_of!(FSD_EXPORTS)).lookup(name)"));
    assert!(launch.contains("hosted_driver_range_list::bind_range_list_exports(reg);"),
        "the actual hosted-driver resolver must publish range-list exports");

    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_range_list.rs");
    for symbol in REQUIRED {
        assert!(adapter.contains(&format!("reg.bind(\"{symbol}\",")),
            "missing source-owned {symbol} binding");
    }

    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/pci.sys");
    if image.is_file() {
        let bytes = std::fs::read(image).expect("pinned released pci.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("pinned released PCI PE");
        let actual: BTreeSet<String> = pe.imports().expect("PCI imports").into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .filter_map(|entry| match entry {
                ImportRef::ByName { name, .. } if name.starts_with("Rtl") && name.contains("Range") => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(actual, REQUIRED.into_iter().map(str::to_owned).collect());
    }
}

#[test]
fn native_copy_and_invert_accept_initialized_nonempty_destinations() {
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_range_list.rs");
    assert!(adapter.contains("dest_ranges.append_from(&source_ranges)"));
    assert!(adapter.contains("dest_ranges.append_from(&gaps)"));
    assert!(adapter.contains("let mut next = (*(header as *const NativeList)).head.next;"),
        "copied and inverted entries must keep the native chain sorted");
    assert!(!adapter.contains("if !dest_ranges.ranges().is_empty()"),
        "the ReactOS copy/invert path accepts initialized nonempty lists");
    assert!(adapter.contains("extern \"win64\" fn(u64, *mut NativeRange) -> u8"),
        "the conflict callback ABI is BOOLEAN NTAPI(PVOID, PRTL_RANGE)");
}
