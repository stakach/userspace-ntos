use super::*;
use crate::{
    exception_walk::{ExceptionWalk, WalkMode, WalkOutcome, WalkStep},
    Context, ExceptionRecord, StackReader,
};
use alloc::{vec, vec::Vec};

const BASE: u64 = 0x180_0000_0000;
const OPTIONAL: usize = 0x98;
const SECTIONS: usize = OPTIONAL + 240;
const DIRECTORY: usize = OPTIONAL + 112 + DIRECTORY_ENTRY_EXCEPTION * 8;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn row(bytes: &mut [u8], offset: usize, begin: u32, end: u32, unwind: u32) {
    put32(bytes, offset, begin);
    put32(bytes, offset + 4, end);
    put32(bytes, offset + 8, unwind);
}

fn mapped_pe() -> Box<[u8]> {
    let mut bytes = vec![0u8; 0x4000];
    put16(&mut bytes, 0, 0x5a4d);
    put32(&mut bytes, 0x3c, 0x80);
    put32(&mut bytes, 0x80, 0x4550);
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 3);
    put16(&mut bytes, 0x94, 240);
    put16(&mut bytes, 0x96, 2);
    put16(&mut bytes, OPTIONAL, 0x20b);
    put32(&mut bytes, OPTIONAL + 16, 0x1000);
    put64(&mut bytes, OPTIONAL + 24, 0x140_0000_0000);
    put32(&mut bytes, OPTIONAL + 32, 0x1000);
    put32(&mut bytes, OPTIONAL + 36, 0x200);
    put32(&mut bytes, OPTIONAL + 56, 0x4000);
    put32(&mut bytes, OPTIONAL + 60, 0x400);
    put32(&mut bytes, OPTIONAL + 108, 16);
    put32(&mut bytes, DIRECTORY, 0x2000);
    put32(&mut bytes, DIRECTORY + 4, 24);
    for (index, (name, rva, flags)) in [
        (*b".text\0\0\0", 0x1000, 0x6000_0020),
        (*b".pdata\0\0", 0x2000, 0x4000_0040),
        (*b".xdata\0\0", 0x3000, 0x4000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let at = SECTIONS + index * 40;
        bytes[at..at + 8].copy_from_slice(&name);
        put32(&mut bytes, at + 8, 0x200);
        put32(&mut bytes, at + 12, rva);
        put32(&mut bytes, at + 16, 0x200);
        // These intentionally cannot be used as mapped-image offsets.
        put32(&mut bytes, at + 20, 0xff_0000 + index as u32 * 0x200);
        put32(&mut bytes, at + 36, flags);
    }
    bytes[0x1000..0x1200].fill(0x90);
    row(&mut bytes, 0x2000, 0x1000, 0x1080, 0x3000);
    row(&mut bytes, 0x200c, 0x1080, 0x1100, 0x3010);
    bytes[0x3000] = 1;
    bytes[0x3010] = 1;
    bytes.into_boxed_slice()
}

fn catalog(bytes: Box<[u8]>) -> Result<ExceptionImageCatalog, ImageAdmissionError> {
    ExceptionImageCatalog::new(vec![AdmittedExceptionImage::from_mapped_image(
        BASE, bytes,
    )?])
}

fn scope_table_pe() -> Box<[u8]> {
    let mut bytes = mapped_pe();
    put32(&mut bytes, 0x3030, 2);
    for (index, (begin, end, handler, target)) in
        [(0x1000, 0x1080, 1, 0x1080), (0x1080, 0x1100, 0x1110, 0)]
            .into_iter()
            .enumerate()
    {
        let offset = 0x3034 + index * 16;
        put32(&mut bytes, offset, begin);
        put32(&mut bytes, offset + 4, end);
        put32(&mut bytes, offset + 8, handler);
        put32(&mut bytes, offset + 12, target);
    }
    bytes
}

#[test]
fn c_scope_table_is_owned_and_uses_exact_admitted_image_base() {
    let table = catalog(scope_table_pe()).unwrap();
    assert_eq!(
        table.read_c_scope_table(BASE, BASE + 0x3030),
        Ok(vec![
            ScopeRecord {
                begin: 0x1000,
                end: 0x1080,
                handler: 1,
                target: 0x1080
            },
            ScopeRecord {
                begin: 0x1080,
                end: 0x1100,
                handler: 0x1110,
                target: 0
            },
        ])
    );
    assert_eq!(
        table.read_c_scope_table(BASE + 1, BASE + 0x3030),
        Err(ScopeTableError::UnknownImage)
    );
    assert_eq!(
        table.read_c_scope_table(BASE, BASE + 0x3031),
        Err(ScopeTableError::InvalidAddress)
    );
    assert_eq!(
        table.read_c_scope_table(BASE, BASE + 0x4030),
        Err(ScopeTableError::InvalidAddress)
    );
}

#[test]
fn c_scope_table_rejects_truncated_and_excessive_counts() {
    for (rva, count, expected) in [
        (0x3030, 4097, ScopeTableError::InvalidCount),
        (0x31fc, 1, ScopeTableError::InvalidExtent),
        (0x3030, u32::MAX, ScopeTableError::InvalidCount),
    ] {
        let mut bytes = scope_table_pe();
        put32(&mut bytes, rva, count);
        let table = catalog(bytes).unwrap();
        assert_eq!(
            table.read_c_scope_table(BASE, BASE + rva as u64),
            Err(expected)
        );
    }
}

#[test]
fn empty_c_scope_table_has_no_handlers() {
    let mut bytes = scope_table_pe();
    put32(&mut bytes, 0x3030, 0);
    let table = catalog(bytes).unwrap();
    assert_eq!(table.read_c_scope_table(BASE, BASE + 0x3030), Ok(vec![]));
}

#[test]
fn c_scope_table_requires_executable_ranges_filters_and_targets() {
    for (field_offset, value, expected) in [
        (0, 0x2000, ScopeTableError::InvalidScope),
        (4, 0x1000, ScopeTableError::InvalidScope),
        (8, 0x2000, ScopeTableError::InvalidHandler),
        (12, 0x3000, ScopeTableError::InvalidTarget),
        (16 + 8, 1, ScopeTableError::InvalidHandler),
    ] {
        let mut bytes = scope_table_pe();
        put32(&mut bytes, 0x3034 + field_offset, value);
        let table = catalog(bytes).unwrap();
        assert_eq!(table.read_c_scope_table(BASE, BASE + 0x3030), Err(expected));
    }
}

#[test]
fn mapped_headers_and_directories_use_rvas_not_raw_file_offsets() {
    let catalog = catalog(mapped_pe()).unwrap();
    assert_eq!(catalog.image_count(), 1);
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x1010),
        Ok(ExceptionFunction::Function {
            image_base: BASE,
            function: RuntimeFunction {
                begin: 0x1000,
                end: 0x1080,
                unwind_info: 0x3000
            },
        })
    );
    assert_eq!(catalog.read_u8(BASE, 0x3000), Some(1));
}

#[test]
fn borrowed_mapped_image_matches_owned_lookup_and_scope_records() {
    let bytes = scope_table_pe();
    let borrowed = BorrowedExceptionImage::from_mapped_image(BASE, &bytes).unwrap();
    let owned = catalog(bytes.clone()).unwrap();
    assert_eq!(borrowed.base(), BASE);
    assert_eq!(borrowed.size(), bytes.len());
    for rva in [
        0x1000, 0x1010, 0x107f, 0x1080, 0x10ff, 0x1100, 0x11ff, 0x2000,
    ] {
        assert_eq!(
            borrowed.lookup_exception_function(BASE + rva),
            owned.lookup_exception_function(BASE + rva),
        );
    }
    assert_eq!(borrowed.read_u8(BASE, 0x3000), owned.read_u8(BASE, 0x3000));
    assert_eq!(borrowed.read_u8(BASE + 1, 0x3000), None);
    assert_eq!(
        borrowed
            .read_c_scope_table(BASE + 0x3030)
            .unwrap()
            .collect::<Vec<_>>(),
        owned.read_c_scope_table(BASE, BASE + 0x3030).unwrap(),
    );
    assert!(borrowed.validate_collision_scope(BASE, BASE + 0x3030, 2));
    assert!(!borrowed.validate_collision_scope(BASE, BASE + 0x3030, 3));
    assert!(!borrowed.validate_collision_scope(BASE + 1, BASE + 0x3030, 0));
}

#[test]
fn borrowed_admission_rejects_the_same_malformed_images() {
    for mutate in [
        (0x2000, 0x1100), // Function begins after its end.
        (0x200c, 0x1070), // Function table overlaps the previous row.
        (0x3010, 0x0006), // Unsupported unwind opcode.
    ] {
        let mut bytes = mapped_pe();
        if mutate.0 == 0x3010 {
            bytes[0x3010] = 1;
            bytes[0x3011] = 0;
            bytes[0x3012] = 1;
            bytes[0x3013] = 0;
            bytes[0x3014] = 0;
            bytes[0x3015] = mutate.1 as u8;
        } else {
            put32(&mut bytes, mutate.0, mutate.1);
        }
        assert_eq!(
            BorrowedExceptionImage::from_mapped_image(BASE, &bytes).err(),
            AdmittedExceptionImage::from_mapped_image(BASE, bytes).err(),
        );
    }
}

#[test]
fn borrowed_scope_cursor_rejects_invalid_rows_without_allocating() {
    let mut bytes = scope_table_pe();
    put32(&mut bytes, 0x3034 + 12, 0x3000);
    let borrowed = BorrowedExceptionImage::from_mapped_image(BASE, &bytes).unwrap();
    assert!(matches!(
        borrowed.read_c_scope_table(BASE + 0x3030),
        Err(ScopeTableError::InvalidTarget)
    ));
}

#[test]
fn borrowed_scope_cursor_supports_checked_indexed_replay() {
    let bytes = scope_table_pe();
    let image = BorrowedExceptionImage::from_mapped_image(BASE, &bytes).unwrap();
    let mut scopes = image.read_c_scope_table(BASE + 0x3030).unwrap();
    let first = scopes.get(0).unwrap();
    let second = scopes.get(1).unwrap();
    assert_eq!(scopes.next(), Some(first));
    assert_eq!(scopes.next(), Some(second));
    assert_eq!(scopes.get(2), None);
    assert_eq!(scopes.get(u32::MAX), None);
}

#[test]
fn borrowed_catalog_routes_two_images_and_rejects_gap_or_wrong_base() {
    const SECOND: u64 = BASE + 0x8000;
    let first_bytes = mapped_pe();
    let second_bytes = scope_table_pe();
    let images = [
        BorrowedExceptionImage::from_mapped_image(BASE, &first_bytes).unwrap(),
        BorrowedExceptionImage::from_mapped_image(SECOND, &second_bytes).unwrap(),
    ];
    let catalog = BorrowedExceptionCatalog::new(&images).unwrap();
    assert_eq!(catalog.image_count(), 2);
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x1010),
        images[0].lookup_exception_function(BASE + 0x1010),
    );
    assert_eq!(
        catalog.lookup_exception_function(SECOND + 0x1080),
        images[1].lookup_exception_function(SECOND + 0x1080),
    );
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x5000),
        Err(ExceptionImageError::UnknownImage),
    );
    assert_eq!(catalog.read_u8(SECOND, 0x3000), Some(1));
    assert_eq!(catalog.read_u8(SECOND + 1, 0x3000), None);
    assert_eq!(
        catalog
            .read_c_scope_table(SECOND, SECOND + 0x3030)
            .unwrap()
            .len(),
        2,
    );
    assert!(matches!(
        catalog.read_c_scope_table(SECOND + 1, SECOND + 0x3030),
        Err(ScopeTableError::UnknownImage),
    ));
    assert!(!catalog.validate_collision_scope(SECOND + 1, SECOND + 0x3030, 0));
}

#[test]
fn borrowed_catalog_rejects_empty_unsorted_duplicate_and_overlap() {
    assert!(matches!(
        BorrowedExceptionCatalog::new(&[]),
        Err(ImageAdmissionError::EmptyCatalog),
    ));
    let first_bytes = mapped_pe();
    let second_bytes = mapped_pe();
    let unsorted = [
        BorrowedExceptionImage::from_mapped_image(BASE + 0x8000, &first_bytes).unwrap(),
        BorrowedExceptionImage::from_mapped_image(BASE, &second_bytes).unwrap(),
    ];
    assert!(matches!(
        BorrowedExceptionCatalog::new(&unsorted),
        Err(ImageAdmissionError::ImageOrder),
    ));
    let duplicate = [
        BorrowedExceptionImage::from_mapped_image(BASE, &first_bytes).unwrap(),
        BorrowedExceptionImage::from_mapped_image(BASE, &second_bytes).unwrap(),
    ];
    assert!(matches!(
        BorrowedExceptionCatalog::new(&duplicate),
        Err(ImageAdmissionError::ImageOrder),
    ));
    let overlap = [
        BorrowedExceptionImage::from_mapped_image(BASE, &first_bytes).unwrap(),
        BorrowedExceptionImage::from_mapped_image(BASE + 0x3000, &second_bytes).unwrap(),
    ];
    assert!(matches!(
        BorrowedExceptionCatalog::new(&overlap),
        Err(ImageAdmissionError::ImageOverlap),
    ));
}

#[test]
fn owned_snapshot_is_not_copied_or_publicly_mutable() {
    let bytes = mapped_pe();
    let original_allocation = bytes.as_ptr();
    let image = AdmittedExceptionImage::from_mapped_image(BASE, bytes).unwrap();
    assert_eq!(image.bytes.as_ptr(), original_allocation);
    assert_eq!(image.base(), BASE);
    assert_eq!(image.size(), 0x4000);
    assert_eq!(image.function_count(), 2);
    let moved = ExceptionImageCatalog::new(vec![image]).unwrap();
    assert_eq!(moved.images[0].bytes.as_ptr(), original_allocation);
}

#[test]
fn only_admitted_executable_gaps_are_leaves() {
    let catalog = catalog(mapped_pe()).unwrap();
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x1100),
        Ok(ExceptionFunction::Leaf)
    );
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x11ff),
        Ok(ExceptionFunction::Leaf)
    );
    for pc in [
        BASE - 1,
        BASE,
        BASE + 0x1200,
        BASE + 0x1800,
        BASE + 0x2000,
        BASE + 0x3000,
        BASE + 0x4000,
    ] {
        assert_eq!(
            catalog.lookup_exception_function(pc),
            Err(ExceptionImageError::UnknownImage)
        );
    }
}

#[test]
fn empty_valid_exception_directory_can_describe_real_leaf_code() {
    let mut bytes = mapped_pe();
    put32(&mut bytes, DIRECTORY, 0);
    put32(&mut bytes, DIRECTORY + 4, 0);
    let catalog = catalog(bytes).unwrap();
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x1010),
        Ok(ExceptionFunction::Leaf)
    );
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x2010),
        Err(ExceptionImageError::UnknownImage)
    );
}

#[test]
fn two_load_bases_remain_distinct_and_exact_base_reads_are_required() {
    let first = AdmittedExceptionImage::from_mapped_image(BASE, mapped_pe()).unwrap();
    let mut bytes = mapped_pe();
    bytes[0x1100] = 0xcc;
    let second = AdmittedExceptionImage::from_mapped_image(BASE + 0x4000, bytes).unwrap();
    let catalog = ExceptionImageCatalog::new(vec![second, first]).unwrap();
    assert_eq!(catalog.image_count(), 2);
    assert_eq!(catalog.read_u8(BASE, 0x1100), Some(0x90));
    assert_eq!(catalog.read_u8(BASE + 0x4000, 0x1100), Some(0xcc));
    assert_eq!(catalog.read_u8(BASE + 1, 0x1100), None);
    assert_eq!(catalog.read_u8(BASE, 0x4000), None);
    assert!(
        matches!(catalog.lookup_exception_function(BASE + 0x5010), Ok(ExceptionFunction::Function { image_base, .. }) if image_base == BASE + 0x4000)
    );
}

#[test]
fn image_overlap_and_duplicate_bases_are_rejected() {
    for offset in [0, 0x2000] {
        let first = AdmittedExceptionImage::from_mapped_image(BASE, mapped_pe()).unwrap();
        let second = AdmittedExceptionImage::from_mapped_image(BASE + offset, mapped_pe()).unwrap();
        assert_eq!(
            ExceptionImageCatalog::new(vec![first, second]).unwrap_err(),
            ImageAdmissionError::ImageOverlap
        );
    }
}

#[test]
fn malformed_pe_never_becomes_a_leaf_catalog() {
    let mut bytes = mapped_pe();
    bytes[0] = 0;
    assert_eq!(
        catalog(bytes).unwrap_err(),
        ImageAdmissionError::Pe(PeError::BadDosSignature)
    );
}

#[test]
fn machine_and_executable_characteristics_are_checked() {
    let mut bytes = mapped_pe();
    put16(&mut bytes, 0x84, 0x14c);
    assert_eq!(
        catalog(bytes).unwrap_err(),
        ImageAdmissionError::Pe(PeError::UnsupportedMachine(0x14c))
    );
    let mut bytes = mapped_pe();
    put16(&mut bytes, 0x96, 0);
    assert_eq!(
        catalog(bytes).unwrap_err(),
        ImageAdmissionError::NotExecutable
    );
}

#[test]
fn incomplete_or_oversized_mapped_snapshots_are_rejected() {
    for length in [0x3fff, 0x4001] {
        let mut bytes = mapped_pe().into_vec();
        bytes.resize(length, 0);
        assert_eq!(
            catalog(bytes.into_boxed_slice()).unwrap_err(),
            ImageAdmissionError::SnapshotSize
        );
    }
}

#[test]
fn zero_or_overflowing_load_addresses_are_rejected() {
    for base in [0, u64::MAX - 0x1000] {
        assert_eq!(
            AdmittedExceptionImage::from_mapped_image(base, mapped_pe()).unwrap_err(),
            ImageAdmissionError::AddressRange
        );
    }
}

#[test]
fn headers_must_cover_the_section_table_and_fit_image() {
    for size in [0x180, 0x5000] {
        let mut bytes = mapped_pe();
        put32(&mut bytes, OPTIONAL + 60, size);
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::HeaderExtent
        );
    }
}

#[test]
fn sections_cannot_overlap_headers_each_other_or_image_end() {
    for (rva, expected) in [
        (0x200, ImageAdmissionError::SectionExtent),
        (0x1100, ImageAdmissionError::SectionOverlap),
        (0x3f00, ImageAdmissionError::SectionExtent),
        (u32::MAX - 3, ImageAdmissionError::SectionExtent),
    ] {
        let mut bytes = mapped_pe();
        put32(&mut bytes, SECTIONS + 40 + 12, rva);
        assert_eq!(catalog(bytes).unwrap_err(), expected);
    }
}

#[test]
fn exception_directory_pair_size_alignment_and_extent_are_checked() {
    for (rva, size, expected) in [
        (0, 24, ImageAdmissionError::ExceptionDirectory),
        (0x2000, 0, ImageAdmissionError::ExceptionDirectory),
        (0x2000, 13, ImageAdmissionError::ExceptionDirectory),
        (0x2001, 24, ImageAdmissionError::ExceptionDirectory),
        (0x3ffc, 24, ImageAdmissionError::Pe(PeError::Truncated)),
    ] {
        let mut bytes = mapped_pe();
        put32(&mut bytes, DIRECTORY, rva);
        put32(&mut bytes, DIRECTORY + 4, size);
        assert_eq!(catalog(bytes).unwrap_err(), expected);
    }
}

#[test]
fn unsorted_duplicate_overlapping_empty_and_nonexecutable_rows_are_not_repaired() {
    for (begin, end) in [
        (0x1000, 0x1080),
        (0x1070, 0x1100),
        (0x1080, 0x1080),
        (0x1100, 0x1300),
        (0x2000, 0x2100),
    ] {
        let mut bytes = mapped_pe();
        row(&mut bytes, 0x200c, begin, end, 0x3010);
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::FunctionTable
        );
    }
    let mut bytes = mapped_pe();
    row(&mut bytes, 0x2000, 0x1080, 0x1100, 0x3010);
    row(&mut bytes, 0x200c, 0x1000, 0x1080, 0x3000);
    assert_eq!(
        catalog(bytes).unwrap_err(),
        ImageAdmissionError::FunctionTable
    );
}

#[test]
fn invalid_or_out_of_bounds_unwind_metadata_rejects_the_whole_image() {
    for rva in [0x3002, 0x3ffc, 0x4000] {
        let mut bytes = mapped_pe();
        put32(&mut bytes, 0x2008, rva);
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::UnwindMetadata
        );
    }
    let mut bytes = mapped_pe();
    bytes[0x3000] = 0xff;
    assert_eq!(
        catalog(bytes).unwrap_err(),
        ImageAdmissionError::UnwindMetadata
    );
}

#[test]
fn malformed_operands_fail_admission_even_if_future_control_pc_is_in_prologue() {
    for code in [0x1f, 0x21, 0x2a] {
        let mut bytes = mapped_pe();
        bytes[0x3001] = 20;
        bytes[0x3002] = 1;
        bytes[0x3004] = 20;
        bytes[0x3005] = code;
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::UnwindMetadata
        );
    }
}

#[test]
fn handler_address_must_be_executable() {
    for handler in [0, 0x2000, 0x4000] {
        let mut bytes = mapped_pe();
        bytes[0x3000] = 1 | (1 << 3);
        put32(&mut bytes, 0x3004, handler);
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::UnwindMetadata
        );
    }
    let mut bytes = mapped_pe();
    bytes[0x3000] = 1 | (1 << 3);
    put32(&mut bytes, 0x3004, 0x1140);
    assert!(catalog(bytes).is_ok());
}

#[test]
fn indirect_runtime_entry_outside_exception_directory_is_valid() {
    let mut bytes = mapped_pe();
    put32(&mut bytes, 0x2008, 0x3021);
    row(&mut bytes, 0x3020, 0x1000, 0x1100, 0x3040);
    bytes[0x3040] = 1;
    assert!(catalog(bytes).is_ok());
}

#[test]
fn chaininfo_parent_outside_exception_directory_is_valid() {
    let mut bytes = mapped_pe();
    bytes[0x3000] = 1 | (4 << 3);
    row(&mut bytes, 0x3004, 0x1000, 0x1100, 0x3040);
    bytes[0x3040] = 1;
    assert!(catalog(bytes).is_ok());
}

#[test]
fn unsupported_version_specific_opcodes_are_not_admitted_as_noops() {
    for version in [1, 2] {
        for code in [6, 7] {
            let mut bytes = mapped_pe();
            bytes[0x3000] = version;
            bytes[0x3001] = 1;
            bytes[0x3002] = 1;
            bytes[0x3004] = 1;
            bytes[0x3005] = code;
            assert_eq!(
                catalog(bytes).unwrap_err(),
                ImageAdmissionError::UnwindMetadata
            );
        }
    }
}

#[test]
fn contradictory_frame_pointer_metadata_is_rejected() {
    for (frame, code) in [(0, 3), (0x10, 3), (1, 3), (4, 3), (5, 0x13)] {
        let mut bytes = mapped_pe();
        bytes[0x3001] = 1;
        bytes[0x3002] = 1;
        bytes[0x3003] = frame;
        bytes[0x3004] = 1;
        bytes[0x3005] = code;
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::UnwindMetadata
        );
    }
    let mut bytes = mapped_pe();
    bytes[0x3001..0x3006].copy_from_slice(&[1, 1, 0x15, 1, 3]);
    assert!(catalog(bytes).is_ok());
}

#[test]
fn xmm_save_admission_keeps_its_nonvolatile_register_constraint() {
    for code in [0x08, 0x09] {
        let mut bytes = mapped_pe();
        bytes[0x3001] = 1;
        bytes[0x3002] = 3;
        bytes[0x3004] = 1;
        bytes[0x3005] = code;
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::UnwindMetadata
        );
    }
}

struct StackWords<'a>(&'a [(u64, u64)]);

impl StackReader for StackWords<'_> {
    fn read_u64(&self, address: u64) -> Option<u64> {
        self.0
            .iter()
            .find_map(|&(at, value)| (at == address).then_some(value))
    }
}

#[test]
fn actual_stack_probe_xdata_preserves_volatile_pushes() {
    // Identical xdata occurs in staged win32k [0x1d5690,0x1d56c0) and explorer
    // [0x38c80,0x38cb0): push RCX; push RAX; ...; pop RAX; pop RCX; ret.
    let mut bytes = mapped_pe();
    bytes[0x3000..0x3008].copy_from_slice(&[1, 2, 2, 0, 2, 0, 1, 0x10]);
    let catalog = catalog(bytes).unwrap();
    let mut context = Context::default();
    context.rip = BASE + 0x1010;
    context.set_rsp(0x8000);
    let (_, function) = catalog.lookup_function(context.rip).unwrap();
    let words = [(0x8000, 0x42), (0x8008, 0x43), (0x8010, BASE + 0x1110)];
    crate::virtual_unwind(
        0,
        BASE,
        context.rip,
        function,
        &mut context,
        &catalog,
        &StackWords(&words),
    )
    .unwrap();
    assert_eq!(context.gpr[0], 0x42);
    assert_eq!(context.gpr[1], 0x43);
    assert_eq!(context.rsp(), 0x8018);
    assert_eq!(context.rip, BASE + 0x1110);
}

#[test]
fn explicit_push_and_save_operations_use_all_sixteen_gpr_ordinals() {
    for op in [uwop::PUSH_NONVOL, uwop::SAVE_NONVOL, uwop::SAVE_NONVOL_FAR] {
        for register in 0..16 {
            let mut bytes = mapped_pe();
            let count = match op {
                uwop::PUSH_NONVOL => 1,
                uwop::SAVE_NONVOL => 2,
                _ => 3,
            };
            bytes[0x3000..0x3006].copy_from_slice(&[1, 1, count, 0, 1, register << 4 | op]);
            if op == uwop::SAVE_NONVOL {
                put16(&mut bytes, 0x3006, 2);
            } else if op == uwop::SAVE_NONVOL_FAR {
                put32(&mut bytes, 0x3006, 16);
            }
            let catalog = catalog(bytes).unwrap();
            let mut context = Context::default();
            context.rip = BASE + 0x1010;
            context.set_rsp(0x8000);
            let (_, function) = catalog.lookup_function(context.rip).unwrap();
            let push = op == uwop::PUSH_NONVOL;
            let saved_at = if push { 0x8000 } else { 0x8010 };
            // NT5 writes the encoded register before incrementing RSP for PUSH_NONVOL.
            // An explicitly saved RSP therefore controls the subsequent checked return read.
            let return_at = if register == 4 {
                0x8040 + if push { 8 } else { 0 }
            } else {
                0x8000 + if push { 8 } else { 0 }
            };
            let words = [(saved_at, 0x8040), (return_at, BASE + 0x1110)];
            crate::virtual_unwind(
                0,
                BASE,
                context.rip,
                function,
                &mut context,
                &catalog,
                &StackWords(&words),
            )
            .unwrap();
            if register != 4 {
                assert_eq!(context.gpr[register as usize], 0x8040);
            }
            assert_eq!(context.rsp(), return_at + 8);
            assert_eq!(context.rip, BASE + 0x1110);
        }
    }
}

#[test]
fn explicit_rsp_restore_does_not_bypass_checked_stack_reads() {
    let mut bytes = mapped_pe();
    bytes[0x3000..0x3006].copy_from_slice(&[1, 1, 1, 0, 1, 0x40]);
    let catalog = catalog(bytes).unwrap();
    let mut context = Context::default();
    context.rip = BASE + 0x1010;
    context.set_rsp(0x8000);
    let original = context;
    let (_, function) = catalog.lookup_function(context.rip).unwrap();
    let words = [(0x8000, 0xffff_ffff_ffff_f000)];
    assert!(crate::virtual_unwind(
        0,
        BASE,
        context.rip,
        function,
        &mut context,
        &catalog,
        &StackWords(&words)
    )
    .is_none());
    assert_eq!(context, original);
}

#[test]
fn unwind_code_offsets_must_be_descending_and_within_prologue() {
    for offsets in [(5, 2), (2, 3)] {
        let mut bytes = mapped_pe();
        bytes[0x3001..0x3008].copy_from_slice(&[4, 2, 0, offsets.0, 0x30, offsets.1, 0x50]);
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::UnwindMetadata
        );
    }
}

#[test]
fn chaininfo_headers_must_agree_on_frame_register_and_offset() {
    for frame in [5, 0x15] {
        let mut bytes = mapped_pe();
        bytes[0x3000] = 1 | (4 << 3);
        bytes[0x3003] = frame;
        row(&mut bytes, 0x3004, 0x1000, 0x1100, 0x3040);
        bytes[0x3040] = 1;
        assert_eq!(
            catalog(bytes).unwrap_err(),
            ImageAdmissionError::UnwindMetadata
        );
        let mut bytes = mapped_pe();
        bytes[0x3000] = 1 | (4 << 3);
        bytes[0x3003] = frame;
        row(&mut bytes, 0x3004, 0x1000, 0x1100, 0x3040);
        bytes[0x3040] = 1;
        bytes[0x3043] = frame;
        assert!(catalog(bytes).is_ok());
    }
}

#[test]
fn cyclic_indirect_and_chaininfo_metadata_are_bounded_failures() {
    let mut bytes = mapped_pe();
    put32(&mut bytes, 0x2008, 0x3021);
    row(&mut bytes, 0x3020, 0x1000, 0x1100, 0x3021);
    assert_eq!(
        catalog(bytes).unwrap_err(),
        ImageAdmissionError::UnwindMetadata
    );
    let mut bytes = mapped_pe();
    bytes[0x3000] = 1 | (4 << 3);
    row(&mut bytes, 0x3004, 0x1000, 0x1100, 0x3000);
    assert_eq!(
        catalog(bytes).unwrap_err(),
        ImageAdmissionError::UnwindMetadata
    );
}

#[test]
fn admitted_catalog_drives_real_nonleaf_then_leaf_exception_walk() {
    struct Stack;
    impl StackReader for Stack {
        fn read_u64(&self, address: u64) -> Option<u64> {
            match address {
                0x8000 => Some(BASE + 0x1110),
                0x8008 => Some(BASE + 0x1150),
                _ => None,
            }
        }
    }
    let catalog = catalog(mapped_pe()).unwrap();
    let mut context = Context::default();
    context.rip = BASE + 0x1010;
    context.set_rsp(0x8000);
    let exception = ExceptionRecord {
        code: 0xc000_0005,
        flags: 0,
        address: context.rip,
        information: Vec::new(),
    };
    let mut walk =
        ExceptionWalk::new(WalkMode::Search, exception, context, 0x8000, 0x8010, 4).unwrap();
    for _ in 0..2 {
        walk = match walk.step(&catalog, &Stack).unwrap() {
            WalkStep::Continue(walk) => walk,
            other => panic!("unexpected {other:?}"),
        };
    }
    assert!(matches!(
        walk.step(&catalog, &Stack).unwrap(),
        WalkStep::Complete(WalkOutcome::Unhandled { .. })
    ));
}
