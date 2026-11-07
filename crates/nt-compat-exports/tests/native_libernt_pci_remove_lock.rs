//! The released PCI bus driver must link real remove-lock lifecycle exports.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const REQUIRED: [&str; 4] = [
    "IoAcquireRemoveLockEx",
    "IoInitializeRemoveLockEx",
    "IoReleaseRemoveLockAndWaitEx",
    "IoReleaseRemoveLockEx",
];

#[test]
fn released_pci_requires_all_four_remove_lock_exports() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt"))
        .expect("pinned LiberNT release manifest");
    assert!(manifest.contains("source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d"));

    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_remove_lock.rs");
    assert!(source.contains("hosted_driver_remove_lock::bind_remove_lock_exports(reg);"));
    // Pinned pci.sys disassembly: 0x126aa stores 0x78 at rsp+0x20 before
    // IoInitializeRemoveLockEx; 0x120ef does the same before Acquire; 0x155e3
    // passes r8d=0x78 to ReleaseAndWait. This is the checked 120-byte ABI.
    assert!(adapter.contains("if size == DEBUG_SIZE { debug_initialize("));
    assert!(adapter.contains("if size == DEBUG_SIZE { debug_acquire("));
    assert!(adapter.contains("if size == DEBUG_SIZE { debug_release_tag("));
    assert!(adapter.contains("debug_release_tag(lock, tag);"));
    for symbol in REQUIRED {
        assert!(adapter.contains(&format!("reg.bind(\"{symbol}\",")), "missing native {symbol} binding");
    }

    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/pci.sys");
    if image.is_file() {
        let bytes = std::fs::read(image).expect("pinned released pci.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("pinned released PCI PE");
        let actual: BTreeSet<String> = pe.imports().expect("PCI imports").into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .filter_map(|import| match import {
                ImportRef::ByName { name, .. } if name.contains("RemoveLock") => Some(name),
                _ => None,
            })
            .collect();
        assert_eq!(actual, REQUIRED.into_iter().map(str::to_owned).collect());
    }
}
