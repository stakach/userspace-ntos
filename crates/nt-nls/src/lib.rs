//! Allocation-free primitives for NT NLS code-page and Unicode case tables.
//!
//! The APIs in this crate only borrow mapped table bytes and write into caller-provided buffers.
//! They are suitable for ntdll, the executive, and hosted kernel components without introducing
//! an ownership dependency on any of those layers.

#![no_std]

/// Default ANSI code page used during the current NT bootstrap.
pub const ANSI_CODE_PAGE: u16 = 1252;

/// `MAXIMUM_LEADBYTES` from the native NLS code-page header.
pub const MAXIMUM_LEADBYTES: usize = 12;

/// Scalar fields and table indices derived from a mapped native code-page table.
///
/// Every index is expressed in `u16` units relative to the start of the mapped table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodePageTableLayout {
    /// Native code-page identifier.
    pub code_page: u16,
    /// Maximum encoded character width: one for SBCS, two for DBCS.
    pub maximum_character_size: u16,
    /// Default encoded character.
    pub default_char: u16,
    /// Default Unicode character.
    pub uni_default_char: u16,
    /// Translated default encoded character.
    pub trans_default_char: u16,
    /// Translated default Unicode character.
    pub trans_uni_default_char: u16,
    /// One when a DBCS range table is present, otherwise zero.
    pub dbcs_code_page: u16,
    /// Index of `MultiByteTable` relative to the mapped table base.
    pub multi_byte_index: usize,
    /// Index of `WideCharTable` relative to the mapped table base.
    pub wide_char_index: usize,
    /// Index of `DBCSRanges` relative to the mapped table base.
    pub dbcs_ranges_index: usize,
    /// Index of `DBCSOffsets`, or zero for an SBCS table.
    pub dbcs_offsets_index: usize,
}

/// Validated offsets for the upper- and lower-case maps in a native `l_intl.nls` image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseTableLayout {
    pub upper_index: usize,
    pub upper_len: usize,
    pub lower_index: usize,
    pub lower_len: usize,
}

/// Parse the table indices populated by `RtlInitCodePageTable`.
///
/// This follows the ReactOS/NT arithmetic while validating every word that must be read. Malformed
/// or truncated mappings return `None`; this function never manufactures a pointer outside `table`.
pub fn init_code_page_table(table: &[u16]) -> Option<CodePageTableLayout> {
    // CodePage through TransUniDefaultChar occupy words 1..=6. A smaller HeaderSize cannot describe
    // that fixed prefix even when the backing slice itself is longer.
    let header_size = *table.first()? as usize;
    if header_size < 13 {
        return None;
    }
    let _ = table.get(6)?;

    let size_at_header = *table.get(header_size)? as usize;
    let multi_byte_index = header_size.checked_add(1)?;
    let wide_char_index = multi_byte_index.checked_add(size_at_header)?;
    let _ = table.get(wide_char_index)?;

    // MultiByteTable[256] is the glyph-table-present flag.
    let glyph_index = multi_byte_index.checked_add(256)?;
    let glyph_flag = *table.get(glyph_index)?;
    let dbcs_ranges_index = glyph_index
        .checked_add(1)?
        .checked_add(if glyph_flag == 0 { 0 } else { 256 })?;

    let dbcs_first = *table.get(dbcs_ranges_index)?;
    let (dbcs_code_page, dbcs_offsets_index) = if dbcs_first == 0 {
        (0, 0)
    } else {
        let dbcs_offsets_index = dbcs_ranges_index.checked_add(1)?;
        let _ = table.get(dbcs_offsets_index)?;
        (1, dbcs_offsets_index)
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

/// Validate the complete single-byte code-page shape required by the native RTL conversion APIs.
///
/// Besides the header, the 256-entry byte-to-Unicode table and full 65,536-entry Unicode-to-byte
/// table must both fit in the actual file image. The expected code page is part of the load-time
/// contract; callers must not silently substitute a different table.
pub fn validate_sbcs_code_page(
    table: &[u16],
    expected_code_page: u16,
) -> Option<CodePageTableLayout> {
    let layout = init_code_page_table(table)?;
    if layout.code_page != expected_code_page
        || layout.maximum_character_size != 1
        || layout.dbcs_code_page != 0
    {
        return None;
    }
    layout
        .multi_byte_index
        .checked_add(256)
        .filter(|&end| end <= table.len())?;
    let table_bytes = table.len().checked_mul(core::mem::size_of::<u16>())?;
    layout
        .wide_char_index
        .checked_mul(core::mem::size_of::<u16>())?
        .checked_add(0x1_0000)
        .filter(|&end| end <= table_bytes)?;
    Some(layout)
}

/// Validate the native `l_intl.nls` header and every reachable three-level lookup.
pub fn validate_case_table(table: &[u16]) -> Option<CaseTableLayout> {
    table.get(1)?;
    if table[0] != 1 {
        return None;
    }
    let upper_index = 2usize;
    let upper_len = table[1] as usize;
    let lower_index = upper_index.checked_add(upper_len)?;
    if upper_len == 0 || lower_index >= table.len() {
        return None;
    }
    let upper = table.get(upper_index..lower_index)?;
    let lower = table.get(lower_index..)?;
    if lower.is_empty() {
        return None;
    }
    for unit in 0..=u16::MAX {
        nls_case_map(upper, unit)?;
        nls_case_map(lower, unit)?;
    }
    Some(CaseTableLayout {
        upper_index,
        upper_len,
        lower_index,
        lower_len: lower.len(),
    })
}

/// Widen an SBCS byte string through `CPTABLEINFO.MultiByteTable`.
///
/// The result is bounded by the native destination capacity in bytes, the input length, and
/// `output.len()`. Returns the number of UTF-16 units written, or `None` when the table lacks the
/// required 256 entries.
pub fn custom_cp_to_unicode_into(
    multi_byte_table: &[u16],
    unicode_capacity_bytes: usize,
    custom: &[u8],
    output: &mut [u16],
) -> Option<usize> {
    if multi_byte_table.len() < 256 {
        return None;
    }
    let count = custom
        .len()
        .min(unicode_capacity_bytes / core::mem::size_of::<u16>())
        .min(output.len());
    for (dst, byte) in output.iter_mut().zip(custom.iter()).take(count) {
        *dst = multi_byte_table[*byte as usize];
    }
    Some(count)
}

/// The bootstrap Unicode uppercase mapping used when no mapped case table is supplied.
///
/// This matches the existing ntdll `RtlUpcaseUnicodeChar` ASCII and Latin-1 behavior.
pub const fn simple_upcase(unit: u16) -> u16 {
    match unit {
        0x61..=0x7a => unit - 0x20,
        0x00e0..=0x00fe if unit != 0x00f7 => unit - 0x20,
        _ => unit,
    }
}

/// Narrow UTF-16 units through `CPTABLEINFO.WideCharTable`, applying `map` first.
///
/// The operation is bounded by `custom_capacity`, the source, and `output`. All required table
/// entries are validated before the output is modified, so a malformed table cannot leave a
/// partially converted result. `map` must return the same value for the same input across the
/// validation and conversion passes.
pub fn unicode_to_custom_cp_mapped_into<F>(
    wide_char_table: &[u8],
    custom_capacity: usize,
    unicode: &[u16],
    output: &mut [u8],
    map: F,
) -> Option<usize>
where
    F: Fn(u16) -> u16,
{
    let count = unicode.len().min(custom_capacity).min(output.len());
    for &unit in &unicode[..count] {
        wide_char_table.get(map(unit) as usize)?;
    }
    for (dst, &unit) in output.iter_mut().zip(unicode.iter()).take(count) {
        *dst = wide_char_table[map(unit) as usize];
    }
    Some(count)
}

/// `RtlUnicodeToCustomCPN` / `RtlUpcaseUnicodeToCustomCPN` SBCS core.
pub fn unicode_to_custom_cp_into(
    wide_char_table: &[u8],
    custom_capacity: usize,
    unicode: &[u16],
    upcase: bool,
    output: &mut [u8],
) -> Option<usize> {
    unicode_to_custom_cp_mapped_into(wide_char_table, custom_capacity, unicode, output, |unit| {
        if upcase {
            simple_upcase(unit)
        } else {
            unit
        }
    })
}

/// Decode one entry from an NT three-level Unicode case table.
///
/// Each level contains `u16` offsets into the same table; the leaf is a signed delta from `unit`.
/// A malformed or truncated table returns `None` without an out-of-bounds access.
pub fn nls_case_map(table: &[u16], unit: u16) -> Option<u16> {
    let high = *table.get((unit >> 8) as usize)? as usize;
    let middle_index = high.checked_add(((unit >> 4) & 0x0f) as usize)?;
    let middle = *table.get(middle_index)? as usize;
    let delta_index = middle.checked_add((unit & 0x0f) as usize)?;
    let delta = *table.get(delta_index)? as i16;
    Some((unit as i32 + delta as i32) as u16)
}

/// Apply the native ASCII fast path followed by an uppercase NLS case table.
pub fn wide_upcase_with_table(unit: u16, table: &[u16]) -> u16 {
    if unit < b'a' as u16 {
        unit
    } else if unit <= b'z' as u16 {
        unit - (b'a' - b'A') as u16
    } else {
        nls_case_map(table, unit).unwrap_or(unit)
    }
}

/// Apply the native ASCII fast path followed by a lowercase NLS case table.
pub fn wide_downcase_with_table(unit: u16, table: &[u16]) -> u16 {
    if unit < b'A' as u16 {
        unit
    } else if unit <= b'Z' as u16 {
        unit + (b'a' - b'A') as u16
    } else {
        nls_case_map(table, unit).unwrap_or(unit)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn build_sbcs_nls(code_page: u16) -> Vec<u16> {
        let header_size = 13usize;
        let wide_char_offset = 259usize;
        let mut table = vec![0u16; header_size + 1 + wide_char_offset + 0x8000];
        table[0] = header_size as u16;
        table[1] = code_page;
        table[2] = 1;
        table[3] = b'?' as u16;
        table[4] = 0xfffd;
        table[header_size] = wide_char_offset as u16;
        let multi_byte_index = header_size + 1;
        for byte in 0..=255 {
            table[multi_byte_index + byte] = byte as u16;
        }
        table[multi_byte_index + 256] = 0;
        table
    }

    #[test]
    fn parses_sbcs_layout_with_native_indices() {
        let table = build_sbcs_nls(1252);
        let layout = init_code_page_table(&table).expect("valid SBCS table");
        assert_eq!(layout.code_page, 1252);
        assert_eq!(layout.maximum_character_size, 1);
        assert_eq!(layout.multi_byte_index, 14);
        assert_eq!(layout.wide_char_index, 14 + 259);
        assert_eq!(layout.dbcs_ranges_index, 14 + 257);
        assert_eq!(layout.dbcs_code_page, 0);
        assert_eq!(layout.dbcs_offsets_index, 0);
    }

    #[test]
    fn glyph_table_moves_dbcs_range_and_nonzero_range_marks_dbcs() {
        let mut table = build_sbcs_nls(932);
        let multi_byte_index = 14;
        table[multi_byte_index + 256] = 1;
        table[multi_byte_index + 256 + 1 + 256] = 2;
        let layout = init_code_page_table(&table).unwrap();
        assert_eq!(layout.dbcs_ranges_index, multi_byte_index + 513);
        assert_eq!(layout.dbcs_code_page, 1);
        assert_eq!(layout.dbcs_offsets_index, layout.dbcs_ranges_index + 1);
    }

    #[test]
    fn rejects_short_or_structurally_invalid_tables() {
        assert_eq!(init_code_page_table(&[]), None);
        assert_eq!(init_code_page_table(&[0; 300]), None);
        assert_eq!(init_code_page_table(&[13, 1252, 1, 63]), None);
    }

    #[test]
    fn sbcs_widening_honors_byte_and_slice_capacity() {
        let mut table = [0u16; 256];
        for (index, entry) in table.iter_mut().enumerate() {
            *entry = index as u16;
        }
        table[0x80] = 0x20ac;
        let mut output = [0xdead; 3];
        assert_eq!(
            custom_cp_to_unicode_into(&table, 4, &[b'A', 0x80, b'Z'], &mut output),
            Some(2)
        );
        assert_eq!(output, [b'A' as u16, 0x20ac, 0xdead]);
        assert_eq!(
            custom_cp_to_unicode_into(&table[..128], 4, b"AB", &mut output),
            None
        );
    }

    #[test]
    fn sbcs_narrowing_is_bounded_and_failure_is_atomic() {
        let mut table = vec![b'?'; 0x10000];
        for byte in 0..=255 {
            table[byte] = byte as u8;
        }
        table[0x20ac] = 0x80;
        let mut output = [0xcc; 3];
        assert_eq!(
            unicode_to_custom_cp_into(
                &table,
                2,
                &[b'a' as u16, 0x20ac, b'Z' as u16],
                false,
                &mut output,
            ),
            Some(2)
        );
        assert_eq!(output, [b'a', 0x80, 0xcc]);

        let mut untouched = [0xcc; 2];
        assert_eq!(
            unicode_to_custom_cp_into(
                &table[..128],
                2,
                &[b'a' as u16, 0x20ac],
                true,
                &mut untouched,
            ),
            None
        );
        assert_eq!(untouched, [0xcc; 2]);
    }

    #[test]
    fn three_level_case_tables_decode_signed_deltas() {
        let mut upper = vec![0u16; 300];
        upper[0] = 256;
        upper[256 + 0x0e] = 272;
        upper[272 + 9] = (-0x20i16) as u16;
        assert_eq!(nls_case_map(&upper, 0x00e9), Some(0x00c9));
        assert_eq!(wide_upcase_with_table(0x00e9, &upper), 0x00c9);
        assert_eq!(wide_upcase_with_table(b'q' as u16, &[]), b'Q' as u16);

        let mut lower = vec![0u16; 300];
        lower[0] = 256;
        lower[256 + 0x0c] = 272;
        lower[272 + 9] = 0x20;
        assert_eq!(wide_downcase_with_table(0x00c9, &lower), 0x00e9);
        assert_eq!(nls_case_map(&[0], 0x0100), None);
    }

    #[test]
    fn mapped_conversion_can_use_a_real_case_table() {
        let mut upper = vec![0u16; 300];
        upper[0] = 256;
        upper[256 + 0x0e] = 272;
        upper[272 + 9] = (-0x20i16) as u16;
        let mut wide = vec![b'?'; 0x10000];
        wide[0x00c9] = 0xc9;
        let mut output = [0u8; 1];
        assert_eq!(
            unicode_to_custom_cp_mapped_into(&wide, 1, &[0x00e9], &mut output, |unit| {
                wide_upcase_with_table(unit, &upper)
            }),
            Some(1)
        );
        assert_eq!(output, [0xc9]);
    }

    #[test]
    fn strict_sbcs_validation_rejects_wrong_or_incomplete_tables() {
        let table = build_sbcs_nls(1252);
        assert!(validate_sbcs_code_page(&table, 1252).is_some());
        assert!(validate_sbcs_code_page(&table, 437).is_none());

        let layout = init_code_page_table(&table).unwrap();
        let bytes_needed = layout.wide_char_index * 2 + 0x1_0000;
        assert!(validate_sbcs_code_page(&table[..bytes_needed / 2 - 1], 1252).is_none());
    }

    #[test]
    fn strict_case_validation_checks_every_reachable_offset() {
        let mut upper = vec![0u16; 288];
        upper[..256].fill(256);
        upper[256..272].fill(272);
        let mut lower = upper.clone();
        let mut file = vec![0u16; 2];
        file[0] = 1;
        file[1] = upper.len() as u16;
        file.append(&mut upper);
        file.append(&mut lower);
        let layout = validate_case_table(&file).expect("complete maps");
        assert_eq!(layout.upper_index, 2);
        assert_eq!(layout.upper_len, 288);

        file[2] = 0xffff;
        assert!(validate_case_table(&file).is_none());
    }
}
