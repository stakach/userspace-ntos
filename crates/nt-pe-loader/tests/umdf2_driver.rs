//! The PE loader handles a real UMDF v2 driver DLL.
//!
//! `Umdf2LifecycleTest.dll` (built from github.com/stakach/ntdriver) is a genuine
//! UMDF v2 driver: a PE32+ DLL that binds the WDF framework via the function table
//! exactly like the KMDF `.sys` drivers, so the same `nt-pe-loader` + `nt-wdf-kmdf`
//! machinery can host it out-of-process. This proves the loader parses, relocates,
//! and resolves its exports/imports — the loading half of hosting it.

use nt_pe_loader::{ImportRef, PeFile};

fn umdf2_dll() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../nt-driver-test-fixtures/fixtures/Umdf2LifecycleTest.dll"
    ))
    .expect("UMDF v2 fixture present")
}

#[test]
fn umdf2_driver_loads_and_exposes_wdf_entry() {
    let bytes = umdf2_dll();
    let pe = PeFile::parse(&bytes).expect("parses as PE32+");

    // The WDF-stub entry the host calls (UMDF v2's analogue of KMDF's FxDriverEntry).
    // It is also the image entry point.
    assert_eq!(pe.entry_point_rva(), 0x1082, "entry = FxDriverEntryUm");

    let exports = pe.exports().unwrap();
    let fx = exports
        .iter()
        .find(|e| e.name == "FxDriverEntryUm")
        .expect("exports FxDriverEntryUm");
    let de = exports
        .iter()
        .find(|e| e.name == "DriverEntry")
        .expect("exports DriverEntry");
    assert_eq!(fx.rva, 0x1082);
    assert_eq!(de.rva, 0x10b4);

    // It binds the framework at runtime (like KMDF) — no static WUDFx/WdfLdr import;
    // just the user-mode runtime imports the isolated host must stub.
    let imports = pe.imports().unwrap();
    let dll = |n: &str| imports.iter().find(|d| d.name.eq_ignore_ascii_case(n));
    let has = |d: &nt_pe_loader::ImportedDll, f: &str| {
        d.functions.iter().any(|i| matches!(i, ImportRef::ByName { name, .. } if name == f))
    };
    let ntdll = dll("ntdll.dll").expect("imports ntdll");
    assert!(has(ntdll, "RtlLookupFunctionEntry") && has(ntdll, "DbgPrintEx"));
    assert!(dll("KERNEL32.dll").is_some());
    assert!(dll("VCRUNTIME140.dll").is_some());
    assert!(
        !imports
            .iter()
            .any(|d| d.name.to_ascii_lowercase().contains("wudf")),
        "UMDF v2 does not statically import the framework DLL"
    );
}

#[test]
fn umdf2_driver_maps_and_relocates() {
    let bytes = umdf2_dll();
    let pe = PeFile::parse(&bytes).unwrap();

    // Map at the preferred base and at a relocated base; the loader applies base
    // relocations, so the two images must differ (absolute pointers get fixed up).
    let at_pref = pe.map(pe.image_base()).unwrap();
    let rebased = pe.image_base() + 0x2000_0000;
    let at_rebased = pe.map(rebased).unwrap();
    assert_eq!(at_pref.bytes.len() as u32, pe.size_of_image());
    assert_eq!(at_rebased.bytes.len(), at_pref.bytes.len());
    assert_ne!(
        at_pref.bytes, at_rebased.bytes,
        "base relocations must rewrite absolute addresses when rebased"
    );

    // W^X shape: the entry (.text) is executable; .data is writable, not executable.
    assert!(pe.protection_at(pe.entry_point_rva()).executable());
    assert!(pe.protection_at(0x7000).writable()); // .data
    assert!(!pe.protection_at(0x7000).executable());
}
