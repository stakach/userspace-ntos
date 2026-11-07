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

#[cfg(test)]
mod locale_file_mapping_tests {
    use crate::nls_file_mapping::{get_nls_section_ptr, initialize_nls_files, NlsFileMappingOps};
    use alloc::vec;
    use alloc::vec::Vec;

    struct Fake {
        bytes: Vec<u8>,
        mappings: Vec<u64>,
        closed: Vec<u64>,
        unmapped: Vec<u64>,
        opened_path: Option<&'static str>,
        fail_section: bool,
    }

    impl Fake {
        fn valid() -> Self {
            let mut bytes = vec![0u8; 0x1000];
            bytes[16..20].copy_from_slice(&0x20u32.to_le_bytes());
            bytes[0x20..0x24].copy_from_slice(&8u32.to_le_bytes());
            bytes[0x2c..0x30].copy_from_slice(&0x5344_534eu32.to_le_bytes());
            Self {
                bytes,
                mappings: Vec::new(),
                closed: Vec::new(),
                unmapped: Vec::new(),
                opened_path: None,
                fail_section: false,
            }
        }

        fn valid_sortdefault() -> Self {
            let mut fake = Self::valid();
            fake.bytes = vec![0u8; 0x4000];
            for (index, offset) in [0x10u32, 0x1800, 0x2000, 0x2800].iter().enumerate() {
                fake.bytes[index * 4..index * 4 + 4].copy_from_slice(&offset.to_le_bytes());
            }
            fake
        }
    }

    impl NlsFileMappingOps for Fake {
        fn system_lcid(&mut self) -> Result<u32, u32> { Ok(0x409) }
        fn open_file(&mut self, path: &'static str) -> Result<u64, u32> {
            self.opened_path = Some(path);
            Ok(11)
        }
        fn create_readonly_section(&mut self, file: u64) -> Result<u64, u32> {
            assert_eq!(file, 11);
            if self.fail_section { Err(0xc000_009a) } else { Ok(22) }
        }
        fn map_readonly_section(&mut self, section: u64) -> Result<(u64, u64), u32> {
            assert_eq!(section, 22);
            let address = 0x1000_0000 + (self.mappings.len() as u64) * 0x10000;
            self.mappings.push(address);
            Ok((address, self.bytes.len() as u64))
        }
        fn mapped_bytes(&self, address: u64, size: u64) -> Option<&[u8]> {
            (self.mappings.contains(&address) && size == self.bytes.len() as u64)
                .then_some(self.bytes.as_slice())
        }
        fn unmap_view(&mut self, address: u64) { self.unmapped.push(address); }
        fn close(&mut self, handle: u64) { self.closed.push(handle); }
    }

    #[test]
    fn maps_installed_locale_bytes_into_independent_views_and_closes_handles() {
        let mut fake = Fake::valid();
        let first = initialize_nls_files(&mut fake).unwrap();
        let second = initialize_nls_files(&mut fake).unwrap();
        assert_eq!(fake.opened_path, Some("\\SystemRoot\\System32\\locale.nls"));
        assert_ne!(first.address, second.address);
        assert_eq!(first.lcid, 0x409);
        assert_eq!(first.size, fake.bytes.len() as u64);
        assert_eq!(fake.closed, vec![11, 22, 11, 22]);
        assert!(fake.unmapped.is_empty());
    }

    #[test]
    fn section_failure_closes_file_and_malformed_mapping_is_unmapped() {
        let mut fake = Fake::valid();
        fake.fail_section = true;
        assert_eq!(initialize_nls_files(&mut fake), Err(0xc000_009a));
        assert_eq!(fake.closed, vec![11]);
        fake.fail_section = false;
        fake.bytes[0x2c..0x30].fill(0);
        assert_eq!(initialize_nls_files(&mut fake), Err(0xc000_007b));
        assert_eq!(fake.closed, vec![11, 11, 22]);
        assert_eq!(fake.unmapped, fake.mappings);
    }

    #[test]
    fn sortdefault_section_maps_exact_installed_file_into_independent_views() {
        let mut fake = Fake::valid_sortdefault();
        let first = get_nls_section_ptr(&mut fake, 9, 0).unwrap();
        let second = get_nls_section_ptr(&mut fake, 9, 0).unwrap();
        assert_eq!(fake.opened_path, Some("\\SystemRoot\\System32\\sortdefault.nls"));
        assert_ne!(first.address, second.address);
        assert_eq!(first.size, fake.bytes.len() as u64);
        assert_eq!(fake.closed, vec![11, 22, 11, 22]);
        assert!(fake.unmapped.is_empty());
    }

    #[test]
    fn sortdefault_rejects_invalid_id_and_malformed_file_without_publishing_a_view() {
        let mut fake = Fake::valid_sortdefault();
        assert_eq!(get_nls_section_ptr(&mut fake, 9, 9999), Err(0xc000_00ef));
        assert_eq!(get_nls_section_ptr(&mut fake, 13, 0), Err(0xc000_00ef));
        assert!(fake.opened_path.is_none());
        fake.bytes[12..16].fill(0);
        assert_eq!(get_nls_section_ptr(&mut fake, 9, 0), Err(0xc000_007b));
        assert_eq!(fake.unmapped, fake.mappings);
        assert_eq!(fake.closed, vec![11, 22]);
    }
}
