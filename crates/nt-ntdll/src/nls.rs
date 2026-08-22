//! ntdll compatibility surface for allocation-free [`nt_nls`] primitives.
//!
//! Pointer arithmetic, table validation, case lookup, and bounded conversion live in the neutral
//! crate so the executive and hosted kernel components can use the same implementation. The two
//! conversion functions here retain ntdll's established allocating, slice-based host API.

use alloc::vec;
use alloc::vec::Vec;

pub use nt_nls::{init_code_page_table, CodePageTableLayout, ANSI_CODE_PAGE, MAXIMUM_LEADBYTES};

/// `RtlCustomCPToUnicodeN`, SBCS core, retaining the existing allocating host API.
pub fn custom_cp_to_unicode_n(
    multi_byte_table: &[u16],
    unicode_size: usize,
    custom: &[u8],
) -> Option<Vec<u16>> {
    let capacity = custom.len().min(unicode_size / core::mem::size_of::<u16>());
    let mut output = vec![0u16; capacity];
    let written =
        nt_nls::custom_cp_to_unicode_into(multi_byte_table, unicode_size, custom, &mut output)?;
    output.truncate(written);
    Some(output)
}

/// `RtlUnicodeToCustomCPN` / `RtlUpcaseUnicodeToCustomCPN`, retaining the existing allocating host
/// API while the neutral implementation writes into a caller-provided buffer.
pub fn unicode_to_custom_cp_n(
    wide_char_table: &[u8],
    custom_size: usize,
    unicode: &[u16],
    upcase: bool,
) -> Option<Vec<u8>> {
    let capacity = unicode.len().min(custom_size);
    let mut output = vec![0u8; capacity];
    let written = nt_nls::unicode_to_custom_cp_into(
        wide_char_table,
        custom_size,
        unicode,
        upcase,
        &mut output,
    )?;
    output.truncate(written);
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn allocating_widening_wrapper_preserves_capacity_contract() {
        let mut multi_byte = vec![0u16; 256];
        for (index, entry) in multi_byte.iter_mut().enumerate() {
            *entry = index as u16;
        }
        multi_byte[0x80] = 0x20ac;
        assert_eq!(
            custom_cp_to_unicode_n(&multi_byte, 4, &[b'A', 0x80, b'Z']).unwrap(),
            vec![b'A' as u16, 0x20ac]
        );
        assert!(custom_cp_to_unicode_n(&multi_byte[..128], 4, b"AB").is_none());
    }

    #[test]
    fn allocating_narrowing_wrapper_preserves_optional_upcase() {
        let mut wide = vec![b'?'; 0x10000];
        for byte in 0..=255 {
            wide[byte] = byte as u8;
        }
        wide[0x20ac] = 0x80;
        assert_eq!(
            unicode_to_custom_cp_n(&wide, 8, &[b'a' as u16, 0x20ac], false).unwrap(),
            vec![b'a', 0x80]
        );
        assert_eq!(
            unicode_to_custom_cp_n(&wide, 1, &[b'a' as u16, b'b' as u16], true).unwrap(),
            vec![b'A']
        );
        assert!(unicode_to_custom_cp_n(&wide[..128], 8, &[0x20ac], false).is_none());
    }
}
