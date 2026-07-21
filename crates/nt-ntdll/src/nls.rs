//! NLS code-page table initialization — `RtlInitCodePageTable`'s pointer arithmetic.
//!
//! kernel32's `IntGetCodePageEntry` maps a `\Nls\NlsSectionCP<n>` section (a raw `.nls` file whose
//! layout begins with an `NLS_FILE_HEADER`) then calls `RtlInitCodePageTable(TableBase, &CPTABLEINFO)`
//! to fill a `CPTABLEINFO` descriptor with pointers INTO the mapped table. `IntMultiByteToWideChar` /
//! `IntWideCharToMultiByte` then index `MultiByteTable[]` / `WideCharTable[]`. A stub that leaves
//! `MultiByteTable` NULL makes kernel32 dereference NULL (`movzwl (rdx,rax,2)`; observed at
//! kernel32+0x7167e, cr2=0, during winlogon's codepage init).
//!
//! This module hosts the pure USHORT-index arithmetic (faithful to ReactOS
//! `sdk/lib/rtl/nls.c:RtlInitCodePageTable`) so it is host-testable against real `.nls` bytes; the
//! `nt-ntdll-dll` export applies the same arithmetic to raw pointers.
//!
//! `NLS_FILE_HEADER` (all `USHORT`): `HeaderSize@0`, `CodePage@1`, `MaximumCharacterSize@2`,
//! `DefaultChar@3`, `UniDefaultChar@4`, `TransDefaultChar@5`, `TransUniDefaultChar@6`,
//! `LeadByte[MAXIMUM_LEADBYTES=12]@7`.
//!
//! Category A. Host-tested.

use alloc::vec::Vec;

/// Default ANSI code page used by the current NLS fallback path.
pub const ANSI_CODE_PAGE: u16 = 1252;

/// `MAXIMUM_LEADBYTES` — the DBCS lead-byte range table length (bytes) in the NLS header.
pub const MAXIMUM_LEADBYTES: usize = 12;

/// The scalar header fields + the computed table indices (in USHORT units, relative to the table
/// base) that `RtlInitCodePageTable` derives from a mapped `.nls` view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodePageTableLayout {
    /// `CPTABLEINFO.CodePage`.
    pub code_page: u16,
    /// `CPTABLEINFO.MaximumCharacterSize` (1 = SBCS, 2 = DBCS).
    pub maximum_character_size: u16,
    /// `CPTABLEINFO.DefaultChar`.
    pub default_char: u16,
    /// `CPTABLEINFO.UniDefaultChar`.
    pub uni_default_char: u16,
    /// `CPTABLEINFO.TransDefaultChar`.
    pub trans_default_char: u16,
    /// `CPTABLEINFO.TransUniDefaultChar`.
    pub trans_uni_default_char: u16,
    /// `CPTABLEINFO.DBCSCodePage` (1 iff a DBCS range table is present).
    pub dbcs_code_page: u16,
    /// USHORT index of `MultiByteTable` relative to the table base.
    pub multi_byte_index: usize,
    /// USHORT index of `WideCharTable` relative to the table base.
    pub wide_char_index: usize,
    /// USHORT index of `DBCSRanges` relative to the table base.
    pub dbcs_ranges_index: usize,
    /// USHORT index of `DBCSOffsets` relative to the table base (only valid when
    /// `dbcs_code_page == 1`).
    pub dbcs_offsets_index: usize,
}

/// Compute the `CPTABLEINFO` layout from a mapped `.nls` table viewed as a `USHORT` slice.
///
/// Faithful to `RtlInitCodePageTable`:
/// * `MultiByteTable = base + HeaderSize + 1`
/// * `WideCharTable  = base + HeaderSize + 1 + base[HeaderSize]`
/// * `DBCSRanges     = MultiByteTable + 257` (no glyph table) or `+ 513` (glyph table present,
///   i.e. `MultiByteTable[256] != 0`)
/// * if `*DBCSRanges != 0` → DBCS code page, `DBCSOffsets = DBCSRanges + 1`
///
/// Returns `None` if `table` is too short to hold the header + the derived tables it must read
/// (`base[HeaderSize]`, `MultiByteTable[256]`, `*DBCSRanges`).
pub fn init_code_page_table(table: &[u16]) -> Option<CodePageTableLayout> {
    // Need at least the header + the size word at index HeaderSize.
    let header_size = *table.first()? as usize;
    let size_at_header = *table.get(header_size)? as usize;

    let multi_byte_index = header_size + 1;
    let wide_char_index = header_size + 1 + size_at_header;

    // Glyph-table probe: MultiByteTable[256].
    let glyph_flag = *table.get(multi_byte_index + 256)?;
    let dbcs_ranges_index = if glyph_flag == 0 {
        multi_byte_index + 256 + 1
    } else {
        multi_byte_index + 256 + 1 + 256
    };

    let dbcs_first = *table.get(dbcs_ranges_index)?;
    let (dbcs_code_page, dbcs_offsets_index) = if dbcs_first != 0 {
        (1u16, dbcs_ranges_index + 1)
    } else {
        (0u16, 0usize)
    };

    Some(CodePageTableLayout {
        code_page: table[1],
        maximum_character_size: table[2],
        default_char: table[3],
        uni_default_char: table[4],
        trans_default_char: table[5],
        trans_uni_default_char: table[6],
        dbcs_code_page,
        multi_byte_index,
        wide_char_index,
        dbcs_ranges_index,
        dbcs_offsets_index,
    })
}

/// `RtlCustomCPToUnicodeN`, SBCS core: widen at most `unicode_size` bytes of destination capacity
/// using `CPTABLEINFO.MultiByteTable`.
pub fn custom_cp_to_unicode_n(
    multi_byte_table: &[u16],
    unicode_size: usize,
    custom: &[u8],
) -> Option<Vec<u16>> {
    if multi_byte_table.len() < 256 {
        return None;
    }
    let count = custom.len().min(unicode_size / 2);
    Some(
        custom[..count]
            .iter()
            .map(|&byte| multi_byte_table[byte as usize])
            .collect(),
    )
}

/// `RtlUnicodeToCustomCPN` / `RtlUpcaseUnicodeToCustomCPN`, SBCS core: narrow at most
/// `custom_size` bytes using `CPTABLEINFO.WideCharTable`.
pub fn unicode_to_custom_cp_n(
    wide_char_table: &[u8],
    custom_size: usize,
    unicode: &[u16],
    upcase: bool,
) -> Option<Vec<u8>> {
    let count = unicode.len().min(custom_size);
    let mut out = Vec::with_capacity(count);
    for &unit in &unicode[..count] {
        let unit = if upcase {
            crate::rtl::strings::upcase_char(unit)
        } else {
            unit
        };
        out.push(*wide_char_table.get(unit as usize)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a minimal single-byte (SBCS) `.nls` image shaped like a real code page (e.g. c_20127):
    /// HeaderSize=13, an identity MultiByteTable, no glyph table, no DBCS ranges.
    fn build_sbcs_nls(code_page: u16) -> Vec<u16> {
        let header_size = 13usize;
        let mut t = vec![0u16; header_size + 1 + 1 + 257 + 1 + 4096];
        t[0] = header_size as u16; // HeaderSize
        t[1] = code_page; // CodePage
        t[2] = 1; // MaximumCharacterSize = SBCS
        t[3] = b'?' as u16; // DefaultChar
        t[4] = 0xFFFD; // UniDefaultChar
                       // base[HeaderSize] = size word preceding MultiByteTable (WideCharTable offset delta).
        t[header_size] = 257; // (256 entries + 1 size word), matches real .nls layout
                              // MultiByteTable identity for ASCII.
        let mb = header_size + 1;
        for c in 0..256 {
            t[mb + c] = c as u16;
        }
        // No glyph table, then DBCSRanges first word == 0 → SBCS.
        t[mb + 256] = 0;
        t
    }

    #[test]
    fn sbcs_layout_matches_reactos_arithmetic() {
        let t = build_sbcs_nls(20127);
        let l = init_code_page_table(&t).expect("layout");
        assert_eq!(l.code_page, 20127);
        assert_eq!(l.maximum_character_size, 1);
        assert_eq!(l.default_char, b'?' as u16);
        // MultiByteTable = base + HeaderSize + 1 (USHORTs) = 14 → byte offset 28.
        assert_eq!(l.multi_byte_index, 14);
        // WideCharTable = MultiByteTable + base[HeaderSize] (257) = 14 + 257 = 271.
        assert_eq!(l.wide_char_index, 14 + 257);
        // SBCS: not a DBCS code page.
        assert_eq!(l.dbcs_code_page, 0);
        assert_eq!(l.dbcs_offsets_index, 0);
        // MultiByteTable identity: index 'A' widens to 'A'.
        assert_eq!(t[l.multi_byte_index + b'A' as usize], b'A' as u16);
    }

    #[test]
    fn multibyte_table_pointer_is_non_null_offset() {
        // The regression: a stub left MultiByteTable NULL. Here the derived index must be > 0 so the
        // pointer (base + index*2) is a real address inside the mapped view, never NULL.
        let t = build_sbcs_nls(1252);
        let l = init_code_page_table(&t).unwrap();
        assert!(l.multi_byte_index > 0);
        assert!(l.wide_char_index > l.multi_byte_index);
    }

    #[test]
    fn glyph_table_shifts_dbcs_ranges() {
        let mut t = build_sbcs_nls(932);
        let mb = 14usize;
        t[mb + 256] = 1; // glyph table present
        let l = init_code_page_table(&t).unwrap();
        // With a glyph table, DBCSRanges = MultiByteTable + 256 + 1 + 256.
        assert_eq!(l.dbcs_ranges_index, mb + 256 + 1 + 256);
    }

    #[test]
    fn truncated_table_is_rejected() {
        // A table too short to hold MultiByteTable[256] must not panic — return None.
        let t = vec![13u16, 20127, 1, b'?' as u16];
        assert!(init_code_page_table(&t).is_none());
    }

    #[test]
    fn custom_cp_to_unicode_uses_multibyte_table_and_capacity() {
        let mut mb = vec![0u16; 256];
        for byte in 0..=255 {
            mb[byte] = byte as u16;
        }
        mb[0x80] = 0x20AC;
        assert_eq!(
            custom_cp_to_unicode_n(&mb, 4, &[b'A', 0x80, b'Z']).unwrap(),
            vec![b'A' as u16, 0x20AC]
        );
        assert!(custom_cp_to_unicode_n(&mb[..128], 4, b"AB").is_none());
    }

    #[test]
    fn unicode_to_custom_cp_uses_wide_table_and_optional_upcase() {
        let mut wide = vec![b'?'; 0x10000];
        for byte in 0..=255 {
            wide[byte] = byte as u8;
        }
        wide[0x20AC] = 0x80;
        assert_eq!(
            unicode_to_custom_cp_n(&wide, 8, &[b'a' as u16, 0x20AC], false).unwrap(),
            vec![b'a', 0x80]
        );
        assert_eq!(
            unicode_to_custom_cp_n(&wide, 1, &[b'a' as u16, b'b' as u16], true).unwrap(),
            vec![b'A']
        );
        assert!(unicode_to_custom_cp_n(&wide[..128], 8, &[0x20AC], false).is_none());
    }
}
