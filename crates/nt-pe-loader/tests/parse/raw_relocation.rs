//! Raw-file transformation must validate the complete plan before any mutation.

use super::{build_pe, put_u16, put_u32, put_u64, Sec, BASE, NT_OFF, OPT_OFF, SECTION_TABLE};
use nt_pe_loader::relocate_file_snapshot;

const LOAD_BASE: u64 = BASE + 0x20_0000;
const DATA_RAW: usize = 0x200;
const RELOC_RAW: usize = 0x400;

fn fixture() -> Vec<u8> {
    let mut data = vec![0; 0x200];
    put_u64(&mut data, 0, BASE + 0x1234);
    let mut reloc = vec![0; 12];
    put_u32(&mut reloc, 0, 0x2000);
    put_u32(&mut reloc, 4, 12);
    put_u16(&mut reloc, 8, 0xa000);
    build_pe(
        BASE,
        0,
        0x4000,
        &[
            Sec { name: *b".data\0\0\0", va: 0x2000, chars: 0xc000_0040, data },
            Sec { name: *b".reloc\0\0", va: 0x3000, chars: 0x4200_0040, data: reloc },
        ],
        &[(5, 0x3000, 12)],
    )
}

fn reject_unchanged(mut bytes: Vec<u8>) {
    let before = bytes.clone();
    assert!(relocate_file_snapshot(&mut bytes, LOAD_BASE).is_err());
    assert_eq!(bytes, before, "a malformed relocation plan cannot partially patch its snapshot");
}

#[test]
fn valid_dir64_and_absolute_transform_only_the_independent_snapshot() {
    let source = fixture();
    let mut snapshot = source.clone();
    relocate_file_snapshot(&mut snapshot, LOAD_BASE).unwrap();
    assert_eq!(u64::from_le_bytes(snapshot[DATA_RAW..DATA_RAW + 8].try_into().unwrap()), LOAD_BASE + 0x1234);
    assert_eq!(u64::from_le_bytes(snapshot[OPT_OFF + 24..OPT_OFF + 32].try_into().unwrap()), LOAD_BASE);
    let mut expected = source.clone();
    put_u64(&mut expected, DATA_RAW, LOAD_BASE + 0x1234);
    put_u64(&mut expected, OPT_OFF + 24, LOAD_BASE);
    assert_eq!(snapshot, expected);
    assert_eq!(source, fixture(), "canonical source bytes remain immutable");
}

#[test]
fn malformed_later_entry_cannot_leave_an_earlier_patch_applied() {
    let mut bytes = fixture();
    put_u16(&mut bytes, RELOC_RAW + 10, 0xa1fc);
    reject_unchanged(bytes);
}

#[test]
fn target_requires_its_complete_eight_bytes_in_one_raw_region() {
    for target in [0xa1fc, 0xa800] {
        let mut bytes = fixture();
        put_u16(&mut bytes, RELOC_RAW + 8, target);
        reject_unchanged(bytes);
    }
    let mut bytes = fixture();
    put_u32(&mut bytes, RELOC_RAW, 0x3000);
    put_u16(&mut bytes, RELOC_RAW + 8, 0xa1fc);
    reject_unchanged(bytes);
}

#[test]
fn block_extent_alignment_and_trailing_bytes_are_not_silently_ignored() {
    for block_size in [0, 7, 11, 14, u32::MAX] {
        let mut bytes = fixture();
        put_u32(&mut bytes, RELOC_RAW + 4, block_size);
        reject_unchanged(bytes);
    }
    for directory_size in [1, 7, 13, 0x201, u32::MAX] {
        let mut bytes = fixture();
        put_u32(&mut bytes, OPT_OFF + 112 + 5 * 8 + 4, directory_size);
        reject_unchanged(bytes);
    }
}

#[test]
fn directory_must_be_wholly_backed_not_read_across_adjacent_raw_sections() {
    let mut bytes = fixture();
    // A directory starting in .data would otherwise read its remaining header/entries from .reloc.
    put_u32(&mut bytes, OPT_OFF + 112 + 5 * 8, 0x21fc);
    put_u32(&mut bytes, DATA_RAW + 0x1fc, 0x2000);
    put_u32(&mut bytes, RELOC_RAW, 12);
    put_u16(&mut bytes, RELOC_RAW + 4, 0xa000);
    put_u16(&mut bytes, RELOC_RAW + 6, 0);
    reject_unchanged(bytes);
}

#[test]
fn target_rva_overflow_and_unsupported_types_are_rejected_atomically() {
    let mut bytes = fixture();
    put_u32(&mut bytes, RELOC_RAW, 0xffff_f000);
    put_u16(&mut bytes, RELOC_RAW + 8, 0xafff);
    // First target remains outside the image, regardless of whether addition itself overflows.
    reject_unchanged(bytes);
    let mut bytes = fixture();
    put_u32(&mut bytes, RELOC_RAW, u32::MAX);
    put_u16(&mut bytes, RELOC_RAW + 8, 0xa001);
    reject_unchanged(bytes);
    let mut bytes = fixture();
    put_u16(&mut bytes, RELOC_RAW + 10, 0x6008); // Reserved, not NT's valid HIGHLOW fixup.
    reject_unchanged(bytes);
}

#[test]
fn malformed_plan_is_rejected_even_when_no_rebase_delta_is_needed() {
    let mut bytes = fixture();
    put_u16(&mut bytes, RELOC_RAW + 10, 0xa1fc);
    let before = bytes.clone();
    assert!(relocate_file_snapshot(&mut bytes, BASE).is_err());
    assert_eq!(bytes, before);
}

#[test]
fn nt_high_low_highlow_fixups_use_their_actual_widths_and_wrapping_delta() {
    // ReactOS rtl/image.c LdrProcessRelocationBlockLongLong admits types 1, 2, 3, 10.
    for (kind, offset, width, before, addend) in [
        (1u16, 0x1feu16, 2usize, 0xfff0u64, 0x20u64),
        (2, 0x1fe, 2, 0xfff0, 0x1234),
        (3, 0x1fc, 4, 0xffff_fff0, 0x20_1234),
    ] {
        let mut bytes = fixture();
        let start = DATA_RAW + offset as usize;
        bytes[start..start + width].copy_from_slice(&before.to_le_bytes()[..width]);
        put_u16(&mut bytes, RELOC_RAW + 8, kind << 12 | offset);
        let target = BASE + 0x20_1234;
        let mut expected = bytes.clone();
        expected[start..start + width].copy_from_slice(&before.wrapping_add(addend).to_le_bytes()[..width]);
        put_u64(&mut expected, OPT_OFF + 24, target);
        relocate_file_snapshot(&mut bytes, target).unwrap();
        assert_eq!(bytes, expected);
    }
    let mut bytes = fixture();
    put_u64(&mut bytes, DATA_RAW, BASE + 0x1234);
    relocate_file_snapshot(&mut bytes, BASE - 0x1000).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[DATA_RAW..DATA_RAW + 8].try_into().unwrap()), BASE + 0x234);
}

#[test]
fn absent_relocations_at_original_base_are_valid_but_stripped_rebase_is_not() {
    let mut bytes = fixture();
    put_u32(&mut bytes, OPT_OFF + 112 + 5 * 8, 0);
    put_u32(&mut bytes, OPT_OFF + 112 + 5 * 8 + 4, 0);
    put_u16(&mut bytes, NT_OFF + 4 + 18, 0x0003); // EXECUTABLE_IMAGE | RELOCS_STRIPPED
    let before = bytes.clone();
    relocate_file_snapshot(&mut bytes, BASE).unwrap();
    assert_eq!(bytes, before);
    assert!(relocate_file_snapshot(&mut bytes, LOAD_BASE).is_err());
    assert_eq!(bytes, before);
}

#[test]
fn narrower_fixups_still_require_their_whole_target_extent() {
    for entry in [0x11ffu16, 0x21ff, 0x31fe] {
        let mut bytes = fixture();
        put_u16(&mut bytes, RELOC_RAW + 8, entry);
        reject_unchanged(bytes);
    }
}

#[test]
fn raw_backing_does_not_admit_relocation_ranges_outside_size_of_image() {
    let mut bytes = fixture();
    // .reloc is inside the declared image, but the raw-backed target is not.
    put_u32(&mut bytes, OPT_OFF + 56, 0x4000);
    put_u32(&mut bytes, SECTION_TABLE + 12, 0x4000);
    put_u32(&mut bytes, RELOC_RAW, 0x4000);
    reject_unchanged(bytes);

    let mut bytes = fixture();
    // The target is inside SizeOfImage; only the raw-backed directory is outside it.
    put_u32(&mut bytes, OPT_OFF + 56, 0x3000);
    reject_unchanged(bytes);
}
