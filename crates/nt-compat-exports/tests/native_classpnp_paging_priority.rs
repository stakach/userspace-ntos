//! The pinned storage class driver consumes native paging priority from IRP flags.

#[cfg(target_arch = "x86_64")]
#[path = "../../../components/ntos-executive/src/io_paging_priority_exports.rs"]
mod io_paging_priority_exports;

#[test]
fn pinned_classpnp_import_has_a_native_binding() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/classpnp.sys");
    if image.exists() {
        let bytes = std::fs::read(image).expect("pinned classpnp image");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("classpnp PE");
        assert!(pe.imports().expect("classpnp imports").iter().any(|dll| {
            dll.name.eq_ignore_ascii_case("ntoskrnl.exe") && dll.functions.iter().any(|entry| {
                matches!(entry, nt_pe_loader::ImportRef::ByName { name, .. }
                    if name.as_str() == "IoGetPagingIoPriority")
            })
        }));
    }
    let exports = include_str!("../../../components/ntos-executive/src/io_paging_priority_exports.rs");
    let registry = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(exports.contains("reg.bind(\"IoGetPagingIoPriority\""));
    assert!(registry.contains("io_paging_priority_exports::bind(reg);"));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn native_export_reads_the_irp_flags_at_the_x64_layout_offset() {
    let mut irp = [0u8; 32];
    let call: extern "win64" fn(u64) -> u32 =
        io_paging_priority_exports::io_get_paging_io_priority;
    let pointer = irp.as_mut_ptr() as u64;
    assert_eq!(call(pointer), 0);
    irp[0x10..0x14].copy_from_slice(&0x0000_0002u32.to_le_bytes());
    assert_eq!(call(pointer), 1);
    irp[0x10..0x14].copy_from_slice(&0x0000_8002u32.to_le_bytes());
    assert_eq!(call(pointer), 2);
}
