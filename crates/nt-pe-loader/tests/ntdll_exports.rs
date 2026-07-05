use nt_pe_loader::PeFile;

#[test]
fn ntdll_exports_and_syscall_numbers() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../references/ntdll.dll"
    ))
    .unwrap();
    let pe = PeFile::parse(&bytes).unwrap();
    let exports = pe.exports().unwrap();
    let nt: Vec<_> = exports
        .iter()
        .filter(|e| e.name.starts_with("Nt"))
        .collect();
    assert!(nt.len() > 300, "found {} Nt* exports", nt.len());
    // Extract the syscall number from NtClose's stub (mov r10,rcx; mov eax,ssn; syscall).
    let img = pe.map(pe.image_base()).unwrap();
    let nt_close = exports.iter().find(|e| e.name == "NtClose").unwrap();
    let stub = &img.bytes[nt_close.rva as usize..nt_close.rva as usize + 8];
    assert_eq!(&stub[0..3], &[0x4c, 0x8b, 0xd1]); // mov r10, rcx
    assert_eq!(stub[3], 0xb8); // mov eax, imm32
    let ssn = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]);
    assert_eq!(ssn, 0x0C, "NtClose syscall number");
}
