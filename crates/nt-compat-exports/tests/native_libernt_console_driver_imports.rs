//! The pinned console-path drivers (ConDrv, Beep) resolve their kernel imports by exact name.

use std::collections::BTreeSet;
use std::path::Path;

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

/// Every `reg.bind("Name", ...)` across the executive's hosted driver export registry,
/// including bindings owned by focused adapter modules.
fn bound_names() -> BTreeSet<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../components/ntos-executive/src");
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(src).expect("executive sources") {
        let path = entry.expect("source entry").path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("executive source");
        for call in source.split("reg.bind(").skip(1) {
            if let Some((name, _)) = call.trim_start().strip_prefix('"').and_then(|rest| rest.split_once('"')) {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

#[test]
fn pinned_beep_imports_are_all_bound() {
    let imports = libernt_driver_imports::imports("beep.sys", &["ntoskrnl.exe", "hal.dll"]);
    assert_eq!(imports.len(), 21, "review beep imports when the release changes");
    let bound = bound_names();
    let missing: Vec<_> = imports.iter().filter(|name| !bound.contains(*name)).collect();
    assert!(missing.is_empty(), "beep.sys imports without a binding: {missing:?}");
}

#[test]
fn pinned_condrv_reader_writer_lock_and_parent_query_are_bound() {
    let imports = libernt_driver_imports::imports("condrv.sys", &["ntoskrnl.exe"]);
    assert_eq!(imports.len(), 43, "review condrv imports when the release changes");
    let bound = bound_names();
    for name in [
        "ExAcquireSpinLockExclusive",
        "ExAcquireSpinLockShared",
        "ExReleaseSpinLockExclusive",
        "ExReleaseSpinLockShared",
        "PsGetProcessInheritedFromUniqueProcessId",
        "ObOpenObjectByPointer",
        "ZwTerminateProcess",
    ] {
        assert!(imports.contains(name), "condrv no longer imports {name}");
        assert!(bound.contains(name), "condrv import {name} has no binding");
    }
    for name in [
        "ExAcquireSpinLockExclusiveAtDpcLevel",
        "ExAcquireSpinLockSharedAtDpcLevel",
        "ExReleaseSpinLockExclusiveFromDpcLevel",
        "ExReleaseSpinLockSharedFromDpcLevel",
        "ExTryAcquireSpinLockSharedAtDpcLevel",
        "ExTryAcquireSpinLockExclusiveAtDpcLevel",
        "ExTryConvertSharedSpinLockExclusive",
    ] {
        assert!(bound.contains(name), "EX_SPIN_LOCK export {name} has no binding");
    }
}
