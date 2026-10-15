//! Captured relocation directories are validated completely before native writes.

use nt_pe_loader::{plan_mapped_relocations, Headers, PeError, RelocKind};

const BASE: u64 = 0x1800_0000_0;
const MAPPED: u64 = BASE + 0x20_0000;

fn headers(directory_size: u32) -> Headers {
    let mut bytes = vec![0u8; 0x200];
    bytes[0..2].copy_from_slice(&0x5a4du16.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());
    bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    let opt = 0x98;
    bytes[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[opt + 24..opt + 32].copy_from_slice(&BASE.to_le_bytes());
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    bytes[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    bytes[opt + 152..opt + 156].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[opt + 156..opt + 160].copy_from_slice(&directory_size.to_le_bytes());
    Headers::parse(&bytes).unwrap()
}

fn block(page: u32, entries: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&page.to_le_bytes());
    bytes.extend_from_slice(&(8u32 + entries.len() as u32 * 2).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.to_le_bytes());
    }
    bytes
}

#[test]
fn captured_directory_plans_mapped_rvas_without_reading_image_holes() {
    let directory = block(0x2000, &[0xa008, 0x3010, 0x1014, 0x2016, 0]);
    let original = directory.clone();
    let plan =
        plan_mapped_relocations(&headers(directory.len() as u32), &directory, MAPPED).unwrap();
    assert_eq!(plan.delta(), 0x20_0000);
    assert_eq!(plan.mapped_base(), MAPPED);
    assert_eq!(plan.image_size(), 0x4000);
    let fixups = plan.fixups();
    assert_eq!(fixups[0].rva, 0x2008);
    assert_eq!(fixups[0].kind, RelocKind::Dir64);
    assert_eq!(fixups[1].kind, RelocKind::HighLow);
    assert_eq!(fixups[2].kind, RelocKind::High);
    assert_eq!(fixups[3].kind, RelocKind::Low);
    assert_eq!(
        directory, original,
        "canonical captured bytes stay immutable"
    );
}

#[test]
fn each_full_target_width_must_fit_size_of_image() {
    for (kind, width) in [(10u16, 8u32), (3, 4), (1, 2), (2, 2)] {
        let valid = block(0x3000, &[(kind << 12) | (0x1000 - width) as u16]);
        assert!(plan_mapped_relocations(&headers(valid.len() as u32), &valid, MAPPED).is_ok());
        let invalid = block(0x3000, &[(kind << 12) | (0x1001 - width) as u16]);
        assert!(matches!(
            plan_mapped_relocations(&headers(invalid.len() as u32), &invalid, MAPPED),
            Err(PeError::PatchOutOfBounds)
        ));
    }
    let overflow = block(u32::MAX, &[0xa001]);
    assert!(plan_mapped_relocations(&headers(10), &overflow, MAPPED).is_err());
}

#[test]
fn malformed_or_unsupported_later_entries_never_produce_a_partial_plan() {
    let mut directory = block(0x2000, &[0xa000]);
    directory.extend(block(0x2000, &[0x6008]));
    assert!(matches!(
        plan_mapped_relocations(&headers(directory.len() as u32), &directory, MAPPED),
        Err(PeError::UnsupportedRelocation(6))
    ));
    for size in [0u32, 6, 9, 12] {
        let mut malformed = block(0x2000, &[0xa000]);
        malformed[4..8].copy_from_slice(&size.to_le_bytes());
        assert!(plan_mapped_relocations(&headers(10), &malformed, MAPPED).is_err());
    }
}

#[test]
fn directory_capture_and_virtual_extent_are_exact() {
    let directory = block(0x2000, &[0xa000]);
    for advertised in [8, 12] {
        assert!(plan_mapped_relocations(&headers(advertised), &directory, MAPPED).is_err());
    }
    let mut h = headers(10);
    h.data_directories[5].virtual_address = 0x3ffc;
    assert!(plan_mapped_relocations(&h, &directory, MAPPED).is_err());
    h.data_directories[5].virtual_address = u32::MAX;
    assert!(plan_mapped_relocations(&h, &directory, MAPPED).is_err());
    assert!(plan_mapped_relocations(&headers(10), &directory, u64::MAX - 1).is_err());
}

#[test]
fn stripped_rebase_conflicts_but_empty_directory_is_success() {
    let mut h = headers(0);
    h.data_directories[5].virtual_address = 0;
    assert!(plan_mapped_relocations(&h, &[], MAPPED)
        .unwrap()
        .fixups()
        .is_empty());
    h.characteristics |= 1;
    assert!(matches!(
        plan_mapped_relocations(&h, &[], MAPPED),
        Err(PeError::RelocationsStripped)
    ));
    assert!(plan_mapped_relocations(&h, &[], BASE)
        .unwrap()
        .fixups()
        .is_empty());
}

#[test]
fn shared_fixup_arithmetic_has_checked_width_and_nt_wrapping() {
    for (kind, mut bytes, expected) in [
        (
            RelocKind::Dir64,
            u64::MAX.to_le_bytes().to_vec(),
            1u64.to_le_bytes().to_vec(),
        ),
        (
            RelocKind::HighLow,
            u32::MAX.to_le_bytes().to_vec(),
            1u32.to_le_bytes().to_vec(),
        ),
        (
            RelocKind::High,
            u16::MAX.to_le_bytes().to_vec(),
            1u16.to_le_bytes().to_vec(),
        ),
        (
            RelocKind::Low,
            u16::MAX.to_le_bytes().to_vec(),
            1u16.to_le_bytes().to_vec(),
        ),
    ] {
        let delta = if kind == RelocKind::High { 0x2_0000 } else { 2 };
        kind.apply_delta(&mut bytes, delta).unwrap();
        assert_eq!(bytes, expected);
        let mut short = vec![0x5a; bytes.len() - 1];
        let original = short.clone();
        assert!(kind.apply_delta(&mut short, delta).is_err());
        assert_eq!(short, original);
    }
}
