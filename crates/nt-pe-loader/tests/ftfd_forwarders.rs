use nt_pe_loader::{
    module_namespace::{resolve_with_core, CoreRole, ImageExports, Symbol},
    ImportRef, PeFile,
};

#[test]
#[ignore = "requires locally staged ReactOS ftfd.dll and win32k.sys"]
fn staged_ftfd_imports_resolve_through_the_actual_win32k_forwarders() {
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rust-micro/.tmp/simpleboot-esp/reactos/system32/"
    );
    let ftfd_bytes = std::fs::read(format!("{root}ftfd.dll")).unwrap();
    let win32k_bytes = std::fs::read(format!("{root}win32k.sys")).unwrap();
    let ftfd = PeFile::parse(&ftfd_bytes).unwrap();
    let win32k = PeFile::parse(&win32k_bytes).unwrap();
    let mapped = win32k.map(0x1000740000).unwrap();
    let image = ImageExports::from_mapped("win32k.sys", mapped.load_base, &mapped.bytes).unwrap();
    let mut imported = 0;
    let mut forwarded = Vec::new();
    for dll in ftfd.imports().unwrap() {
        assert_eq!(dll.name.to_ascii_lowercase(), "win32k.sys");
        for function in dll.functions {
            let symbol = match function {
                ImportRef::ByName { name, .. } => Symbol::Name(name),
                ImportRef::ByOrdinal { ordinal, .. } => Symbol::Ordinal(ordinal),
            };
            resolve_with_core(
                std::slice::from_ref(&image),
                &dll.name,
                &symbol,
                |role, target| {
                    assert_eq!(role, CoreRole::Kernel);
                    let Symbol::Name(name) = target else {
                        panic!("unexpected ordinal forwarder")
                    };
                    assert!(matches!(
                        name.as_str(),
                        "RtlMultiByteToUnicodeN" | "KeBugCheckEx" | "RtlUnwind"
                    ));
                    forwarded.push(name.clone());
                    Some(0x200000)
                },
            )
            .unwrap();
            imported += 1;
        }
    }
    assert_eq!(imported, 8);
    assert_eq!(
        forwarded,
        ["RtlMultiByteToUnicodeN", "KeBugCheckEx", "RtlUnwind"]
    );
}
