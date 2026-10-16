//! Pinned driver imports must resolve to source-owned generic kernel exports.

use nt_pe_loader::ImportRef;
use std::path::Path;

#[test]
fn released_acpi_and_basicdisplay_imports_have_generic_bindings() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt"))
        .expect("pinned LiberNT manifest");
    assert!(manifest.contains("source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d"));
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for (driver, symbol) in [
        ("acpi.sys", "ExpInterlockedFlushSList"),
        ("basicdisplay.sys", "KeRemoveQueueDpc"),
    ] {
        let bytes = std::fs::read(root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers").join(driver))
            .expect("staged pinned driver");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("pinned driver PE");
        let imported = pe.imports().expect("pinned driver imports")
            .into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .filter_map(|import| match import {
                ImportRef::ByName { name, .. } => Some(name),
                ImportRef::ByOrdinal { .. } => None,
            })
            .any(|name| name == symbol);
        assert!(imported, "pinned {driver} no longer imports {symbol}");
        assert!(launch.contains(&format!("\"{symbol}\",")), "generic export registry lacks {symbol}");
    }
}
