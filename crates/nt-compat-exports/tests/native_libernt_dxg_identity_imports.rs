//! A released dxgkrnl image must resolve these existing identity and object
//! contracts through the shared hosted-driver kernel registry.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const IMPORTS: [&str; 5] = [
    "PsGetProcessId",
    "PsLookupProcessByProcessId",
    "ZwCreateDirectoryObject",
    "ZwCreateEvent",
    "ZwQueryKey",
];

#[test]
fn released_dxgkrnl_identity_and_object_imports_are_native_driver_bindings() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bytes = std::fs::read(
        root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/dxgkrnl.sys"),
    )
    .expect("pinned released dxgkrnl.sys");
    let pe = nt_pe_loader::PeFile::parse(&bytes).expect("released dxgkrnl PE");
    let imports: BTreeSet<_> = pe
        .imports()
        .expect("released dxgkrnl imports")
        .into_iter()
        .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
        .flat_map(|dll| dll.functions)
        .filter_map(|entry| match entry {
            ImportRef::ByName { name, .. } => Some(name),
            ImportRef::ByOrdinal { .. } => None,
        })
        .collect();

    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let bindings = source
        .split_once("fn register_fsd_trampolines()")
        .expect("shared driver registry")
        .1
        .split_once("pub(crate) fn initialize_fsd_export_registry()")
        .expect("shared driver registry end")
        .0;
    for name in IMPORTS {
        assert!(imports.contains(name), "released dxgkrnl must import {name}");
        assert!(
            nt_compat_exports::module_export_descriptor("ntoskrnl.exe", name).is_some(),
            "kernel provider must declare {name}"
        );
        assert!(
            bindings.contains(&format!("\"{name}\"")),
            "shared native driver registry must bind {name}"
        );
    }
}
