//! Pinned win32k assertions must retain bounded diagnostic inputs.

use nt_compat_exports::kernel_assertion::capture_bounded;

#[test]
fn assertion_capture_preserves_all_four_abi_fields_without_unbounded_storage() {
    let record = capture_bounded(
        b"count > 0\0unrelated",
        b"win32k\\object.c\0unrelated",
        0x1234,
        Some(b"invalid object\0unrelated"),
    );
    assert_eq!(record.assertion(), b"count > 0");
    assert_eq!(record.file(), b"win32k\\object.c");
    assert_eq!(record.line(), 0x1234);
    assert_eq!(record.message(), Some(&b"invalid object"[..]));

    let long = [b'x'; 4096];
    let clipped = capture_bounded(&long, &long, u32::MAX, Some(&long));
    assert!(clipped.assertion().len() <= 128);
    assert!(clipped.file().len() <= 128);
    assert!(clipped.message().unwrap().len() <= 128);
    assert!(!clipped.assertion().is_empty());
    assert!(!clipped.file().is_empty());
    assert!(!clipped.message().unwrap().is_empty());
    assert_eq!(clipped.line(), u32::MAX);
    assert!(std::mem::size_of_val(&clipped) <= 512);
}
