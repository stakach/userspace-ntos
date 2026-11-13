//! A released dxgkrnl image must resolve these existing identity and object
//! contracts through the shared hosted-driver kernel registry.

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

const IMPORTS: [&str; 5] = [
    "PsGetProcessId",
    "PsLookupProcessByProcessId",
    "ZwCreateDirectoryObject",
    "ZwCreateEvent",
    "ZwQueryKey",
];

#[test]
fn released_dxgkrnl_identity_and_object_imports_are_native_driver_bindings() {
    let imports = libernt_driver_imports::imports("dxgkrnl.sys", &["ntoskrnl.exe"]);

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
