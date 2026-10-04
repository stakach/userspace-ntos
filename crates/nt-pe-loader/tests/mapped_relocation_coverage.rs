use nt_pe_loader::{plan_mapped_relocations, DataDirectory, Headers, Section};

fn plan(target: u32) -> nt_pe_loader::MappedRelocationPlan {
    plan_with_alignment(target, 0x1000)
}

fn plan_with_alignment(target: u32, section_alignment: u32) -> nt_pe_loader::MappedRelocationPlan {
    let mut directories = [DataDirectory::default(); 16];
    directories[5] = DataDirectory {
        virtual_address: 0x4000,
        size: 10,
    };
    let headers = Headers {
        nt_offset: 0x80,
        machine: 0x8664,
        number_of_sections: 1,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: 240,
        characteristics: 0x2022,
        magic: 0x20b,
        entry_point_rva: 0,
        image_base: 0x180000000,
        section_alignment,
        file_alignment: 0x200,
        size_of_image: 0x6000,
        size_of_headers: 0x200,
        size_of_stack_reserve: 0,
        size_of_stack_commit: 0,
        subsystem: 3,
        major_subsystem_version: 5,
        minor_subsystem_version: 2,
        number_of_rva_and_sizes: 16,
        data_directories: directories,
    };
    let mut directory = Vec::new();
    directory.extend_from_slice(&(target & !0xfff).to_le_bytes());
    directory.extend_from_slice(&10u32.to_le_bytes());
    directory.extend_from_slice(&(0xa000 | (target & 0xfff) as u16).to_le_bytes());
    plan_mapped_relocations(&headers, &directory, 0x180200000).unwrap()
}

#[test]
fn subpage_writable_section_does_not_authorize_the_canonical_readonly_header_page() {
    let subpage = section(0x200, 0x200, 0x600, true);
    for target in [0x100, 0x250] {
        assert!(plan_with_alignment(target, 0x200)
            .validate_writable_targets(&[subpage]).is_err(),
            "canonical header page stays readonly; writable-section rounding is not permission authority");
    }
    assert!(
        plan_with_alignment(0x1000, 0x200)
            .validate_writable_targets(&[section(0x1000, 0x200, 0x1000, true)])
            .is_ok(),
        "a genuinely writable non-header page remains admitted"
    );
}

fn section(start: u32, raw: u32, virtual_size: u32, writable: bool) -> Section {
    Section {
        name: *b".data\0\0\0",
        virtual_address: start,
        virtual_size,
        size_of_raw_data: raw,
        pointer_to_raw_data: 0x200,
        characteristics: if writable { 0xc0000040 } else { 0x40000040 },
    }
}

#[test]
fn nt5_writable_coverage_is_checked_for_every_full_fixup_before_effects() {
    let readonly = section(0x2000, 0x200, 0x2000, false);
    assert!(
        plan(0x100).validate_writable_targets(&[readonly]).is_err(),
        "NT5 does not broaden readonly image headers for relocation"
    );
    assert!(
        plan(0x2300).validate_writable_targets(&[readonly]).is_ok(),
        "NtProtect rounds the raw extent to the containing page"
    );
    assert!(
        plan(0x3000).validate_writable_targets(&[readonly]).is_err(),
        "readonly zero-fill tail on a new page is not protected by NT5"
    );
    let writable = section(0x2000, 0x200, 0x2000, true);
    assert!(plan(0x3000).validate_writable_targets(&[writable]).is_ok());
    assert!(
        plan(0x2ffc).validate_writable_targets(&[readonly]).is_err(),
        "the entire cross-page DIR64 width requires writable coverage"
    );
    assert!(plan(0x2ffc)
        .validate_writable_targets(&[readonly, section(0x3000, 0x200, 0x1000, false),])
        .is_ok());
    assert!(
        plan(0x2000)
            .validate_writable_targets(&[section(0x2000, 0, 0x1000, false),])
            .is_err(),
        "nonwritable BSS alone is never made writable"
    );
}
