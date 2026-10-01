use nt_compat_exports::ExportRegistry;
use nt_pe_loader::{
    module_namespace::{resolve_with_core, CoreRole, ImageExports, Symbol},
    ImportRef, PeFile,
};

#[test]
#[ignore = "requires locally staged ReactOS dxg.sys, dxgthk.sys, and win32k.sys"]
fn staged_dxg_import_graph_resolves_against_canonical_core_exports() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../rust-micro/.tmp/simpleboot-esp/reactos/system32/");
    let dxg_bytes = std::fs::read(format!("{root}drivers/dxg.sys")).unwrap();
    let mut images = Vec::new();
    for (name, path, base) in [
        ("dxgthk.sys", "drivers/dxgthk.sys", 0x100100000u64),
        ("win32k.sys", "win32k.sys", 0x100200000u64),
    ] {
        let bytes = std::fs::read(format!("{root}{path}")).unwrap();
        let pe = PeFile::parse(&bytes).unwrap();
        let mapped = pe.map(base).unwrap();
        images.push(ImageExports::from_mapped(name, mapped.load_base, &mapped.bytes).unwrap());
    }
    let registry = ExportRegistry::new();
    let mut core = Vec::new();
    let mut count = 0;
    for dll in PeFile::parse(&dxg_bytes).unwrap().imports().unwrap() {
        for import in dll.functions {
            let symbol = match import {
                ImportRef::ByName { name, .. } => Symbol::Name(name),
                ImportRef::ByOrdinal { ordinal, .. } => Symbol::Ordinal(ordinal),
            };
            resolve_with_core(&images, &dll.name, &symbol, |role, symbol| {
                let module = match role { CoreRole::Kernel => "ntoskrnl.exe", CoreRole::Hal => "hal.dll" };
                let Symbol::Name(name) = symbol else { panic!("unexpected core ordinal") };
                assert!(registry.resolve(module, name).loads(), "missing canonical {module}!{name}");
                core.push(name.clone());
                Some(0x200000)
            }).unwrap();
            count += 1;
        }
    }
    assert_eq!(count, 15, "fixture import contract changed");
    core.sort();
    assert_eq!(core, ["DbgPrint", "ExFreePoolWithTag", "IoGetCurrentProcess",
        "PsGetCurrentProcessId", "PsGetCurrentThreadProcessId", "memcpy", "memmove", "memset"]);
}
