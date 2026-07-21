//! Host tests for the PE resource-directory walker over a synthetic `.rsrc` blob.

use super::*;
extern crate alloc;
use alloc::vec::Vec;

/// A tiny resource-section builder producing the exact on-disk layout the walker consumes.
///
/// Layout: one type directory (RT_DIALOG=5) → one name directory (id 1000) → one language
/// directory (id 0x409 = en-US) → one data entry. Plus a second type (RT_STRING=6) with a *named*
/// entry "FOO" to exercise the string path.
struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    fn new() -> Self {
        Builder { buf: Vec::new() }
    }
    fn dir_header(&mut self, num_named: u16, num_id: u16) {
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
        self.buf.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // Major
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // Minor
        self.buf.extend_from_slice(&num_named.to_le_bytes());
        self.buf.extend_from_slice(&num_id.to_le_bytes());
    }
    fn entry(&mut self, name: u32, offset: u32) {
        self.buf.extend_from_slice(&name.to_le_bytes());
        self.buf.extend_from_slice(&offset.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn len(&self) -> usize {
        self.buf.len()
    }
}

/// Build: type dir { id 5 -> nameDir1, id 6 -> nameDir2 }, name dir1 { id 1000 -> langDir },
/// lang dir { id 0x409 -> data }, data entry, name dir2 { named "FOO" -> langDir2 }, ...
fn build() -> Vec<u8> {
    // We must know offsets up front; compute a fixed layout.
    // Root type dir at 0: header(16) + 2 entries(16) => 32.
    // nameDir1 at 32: header(16) + 1 entry(8) => 24  (ends 56)
    // langDir1 at 56: header(16) + 1 entry(8) => 24  (ends 80)
    // dataEntry1 at 80: 16 bytes (ends 96)
    // nameDir2 at 96: header(16) + 1 entry(8) => 24 (ends 120)
    // string "FOO" at 120: u16 len=3 + 3*u16 => 8 (ends 128)
    // langDir2 at 128: header(16)+1 entry(8) => 24 (ends 152)
    // dataEntry2 at 152: 16 bytes
    const NAME_DIR1: u32 = 32;
    const LANG_DIR1: u32 = 56;
    const DATA1: u32 = 80;
    const NAME_DIR2: u32 = 96;
    const STR_FOO: u32 = 120;
    const LANG_DIR2: u32 = 128;
    const DATA2: u32 = 152;

    let mut b = Builder::new();
    // Root type dir: 0 named, 2 id (ids 5 and 6, sorted).
    b.dir_header(0, 2);
    b.entry(5, NAME_DIR1 | DATA_IS_DIRECTORY);
    b.entry(6, NAME_DIR2 | DATA_IS_DIRECTORY);
    assert_eq!(b.len(), NAME_DIR1 as usize);

    // nameDir1: id 1000 -> langDir1 (directory).
    b.dir_header(0, 1);
    b.entry(1000, LANG_DIR1 | DATA_IS_DIRECTORY);
    assert_eq!(b.len(), LANG_DIR1 as usize);

    // langDir1: id 0x409 -> data1 (leaf).
    b.dir_header(0, 1);
    b.entry(0x409, DATA1);
    assert_eq!(b.len(), DATA1 as usize);

    // data entry 1: OffsetToData(rva)=0xAAAA, Size=0x11, CodePage=0, Reserved=0.
    b.u32(0xAAAA);
    b.u32(0x11);
    b.u32(0);
    b.u32(0);
    assert_eq!(b.len(), NAME_DIR2 as usize);

    // nameDir2: 1 named "FOO" -> langDir2.
    b.dir_header(1, 0);
    b.entry(STR_FOO | NAME_IS_STRING, LANG_DIR2 | DATA_IS_DIRECTORY);
    assert_eq!(b.len(), STR_FOO as usize);

    // string "FOO": len 3, F O O.
    b.u16(3);
    b.u16(b'F' as u16);
    b.u16(b'O' as u16);
    b.u16(b'O' as u16);
    assert_eq!(b.len(), LANG_DIR2 as usize);

    // langDir2: id 0x409 -> data2.
    b.dir_header(0, 1);
    b.entry(0x409, DATA2);
    assert_eq!(b.len(), DATA2 as usize);

    // data entry 2.
    b.u32(0xBBBB);
    b.u32(0x22);
    b.u32(0);
    b.u32(0);

    b.buf
}

#[test]
fn find_dialog_by_id_level3() {
    let rsrc = build();
    let r = find_entry(
        &rsrc,
        &ResName::Id(5),    // RT_DIALOG
        &ResName::Id(1000), // IDD
        &[0x409],           // en-US
        false,
        3,
        false, // want data entry
    )
    .expect("found");
    let (rva, size) = data_entry(&rsrc, r.offset).unwrap();
    assert_eq!(rva, 0xAAAA);
    assert_eq!(size, 0x11);
}

#[test]
fn find_by_named_entry() {
    let rsrc = build();
    let name: Vec<u16> = "FOO\0".encode_utf16().collect();
    let r = find_entry(
        &rsrc,
        &ResName::Id(6),
        &ResName::Name(&name),
        &[0x409],
        false,
        3,
        false,
    )
    .expect("found named");
    let (rva, size) = data_entry(&rsrc, r.offset).unwrap();
    assert_eq!(rva, 0xBBBB);
    assert_eq!(size, 0x22);
}

#[test]
fn missing_type_is_type_not_found() {
    let rsrc = build();
    let e = find_entry(
        &rsrc,
        &ResName::Id(99),
        &ResName::Id(1000),
        &[0x409],
        false,
        3,
        false,
    )
    .unwrap_err();
    assert_eq!(e, FindStatus::TypeNotFound);
}

#[test]
fn missing_name_is_name_not_found() {
    let rsrc = build();
    let e = find_entry(
        &rsrc,
        &ResName::Id(5),
        &ResName::Id(4242),
        &[0x409],
        false,
        3,
        false,
    )
    .unwrap_err();
    assert_eq!(e, FindStatus::NameNotFound);
}

#[test]
fn missing_lang_neutral_fallback_takes_first() {
    let rsrc = build();
    // Ask for a language not present (0x40C) but with the neutral first-entry fallback → data1.
    let r = find_entry(
        &rsrc,
        &ResName::Id(5),
        &ResName::Id(1000),
        &[0x40C],
        true,
        3,
        false,
    )
    .expect("neutral fallback");
    let (rva, _) = data_entry(&rsrc, r.offset).unwrap();
    assert_eq!(rva, 0xAAAA);
}

#[test]
fn missing_lang_no_fallback_is_lang_not_found() {
    let rsrc = build();
    let e = find_entry(
        &rsrc,
        &ResName::Id(5),
        &ResName::Id(1000),
        &[0x40C],
        false,
        3,
        false,
    )
    .unwrap_err();
    assert_eq!(e, FindStatus::LangNotFound);
}

#[test]
fn level1_returns_type_directory() {
    let rsrc = build();
    let r = find_entry(&rsrc, &ResName::Id(5), &ResName::Id(0), &[], false, 1, true).expect("l1");
    assert_eq!(r.offset, 32); // NAME_DIR1
}

#[test]
fn level2_returns_name_directory() {
    let rsrc = build();
    let r = find_entry(
        &rsrc,
        &ResName::Id(5),
        &ResName::Id(1000),
        &[],
        false,
        2,
        true,
    )
    .expect("l2");
    assert_eq!(r.offset, 56); // LANG_DIR1
}

#[test]
fn named_compare_case_insensitive() {
    let rsrc = build();
    let name: Vec<u16> = "foo\0".encode_utf16().collect(); // lowercase should still match "FOO"
    let r = find_entry(
        &rsrc,
        &ResName::Id(6),
        &ResName::Name(&name),
        &[0x409],
        false,
        3,
        false,
    )
    .expect("case-insensitive");
    let (rva, _) = data_entry(&rsrc, r.offset).unwrap();
    assert_eq!(rva, 0xBBBB);
}

#[test]
fn truncated_section_is_data_not_found() {
    let e = find_entry(
        &[0u8; 4],
        &ResName::Id(5),
        &ResName::Id(1),
        &[0x409],
        false,
        3,
        false,
    )
    .unwrap_err();
    assert_eq!(e, FindStatus::DataNotFound);
}
