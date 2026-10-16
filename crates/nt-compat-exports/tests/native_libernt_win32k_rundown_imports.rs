//! The pinned LiberNT win32k.sys needs all five NT rundown exports bound to live trampolines.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const RUNDOWN_IMPORTS: [&str; 5] = [
    "ExAcquireRundownProtection",
    "ExInitializeRundownProtection",
    "ExReInitializeRundownProtection",
    "ExReleaseRundownProtection",
    "ExWaitForRundownProtectionRelease",
];

#[test]
fn pinned_win32k_rundown_imports_have_native_export_bindings() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Ok(manifest) = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt")) {
        assert!(manifest.contains("source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d"));
    }

    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if image.exists() {
        let bytes = std::fs::read(&image).expect("staged pinned LiberNT win32k.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("pinned LiberNT win32k PE");
        let imported: BTreeSet<String> = pe
            .imports()
            .expect("pinned LiberNT win32k imports")
            .into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| dll.functions)
            .filter_map(|import| match import {
                ImportRef::ByName { name, .. } => Some(name),
                ImportRef::ByOrdinal { .. } => None,
            })
            .collect();
        for name in RUNDOWN_IMPORTS {
            assert!(imported.contains(name), "pinned win32k.sys must import {name}");
        }
    }

    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    for name in RUNDOWN_IMPORTS {
        assert!(
            source.contains(&format!("reg.bind(\"{name}\","))
                || source.contains(&format!("reg.bind(\n        \"{name}\",")),
            "win32k export registry must bind native {name}"
        );
    }
}
