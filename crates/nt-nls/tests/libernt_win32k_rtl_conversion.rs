//! Shared NLS size and conversion behavior for the pinned win32k imports.

use nt_nls::{multibyte_to_unicode_size, unicode_to_multibyte_dbcs_into};

#[test]
fn unicode_size_counts_dbcs_pair_as_one_character() {
    let mut leads = [0u16; 256];
    leads[0x81] = 1;
    assert_eq!(multibyte_to_unicode_size(b"abc", None), Some(6));
    assert_eq!(multibyte_to_unicode_size(&[b'A', 0x81, 0x40, b'B'], Some(&leads)), Some(6));
    assert_eq!(multibyte_to_unicode_size(&[0x81], Some(&leads)), Some(2));
}

#[test]
fn unicode_to_dbcs_stops_before_partial_double_byte_character() {
    let mut mapping = [0u16; 65536];
    mapping[0x4e00] = 0x8140;
    let mut short = [0xceu8; 2];
    assert_eq!(unicode_to_multibyte_dbcs_into(&[b'A' as u16, 0x4e00], &mapping, &mut short), Some(1));
    assert_eq!(short, [b'A', 0xce]);
    let mut full = [0u8; 3];
    assert_eq!(unicode_to_multibyte_dbcs_into(&[b'A' as u16, 0x4e00], &mapping, &mut full), Some(3));
    assert_eq!(full, [b'A', 0x81, 0x40]);
}
