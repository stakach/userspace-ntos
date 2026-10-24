//! Shared counted UTF-16 prefix semantics used by ntdll and win32k.

use nt_compat_exports::rtl::prefix_unicode;

#[test]
fn prefix_is_counted_and_respects_case_mode() {
    let prefix: Vec<u16> = "Win".encode_utf16().collect();
    let word: Vec<u16> = "Windows".encode_utf16().collect();
    let lower: Vec<u16> = "windows".encode_utf16().collect();
    assert!(prefix_unicode(&prefix, &word, false));
    assert!(!prefix_unicode(&prefix, &lower, false));
    assert!(prefix_unicode(&prefix, &lower, true));
    assert!(prefix_unicode(&[], &word, true));
    assert!(!prefix_unicode(&word, &prefix, true));
}

#[test]
fn prefix_preserves_counted_null_and_latin_one_case_mapping() {
    assert!(prefix_unicode(&[0x00e9, 0], &[0x00c9, 0, b'x' as u16], true));
    assert!(!prefix_unicode(&[b'a' as u16, 0], &[b'A' as u16, b'x' as u16], true));
}
