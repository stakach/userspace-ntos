//! `Rtl*` string primitives — UNICODE_STRING / ANSI_STRING / UTF-8 counted-string operations.
//!
//! These are pure, in-process library code (no syscall). The counted-string model (byte lengths,
//! not NUL-terminated) is reused from [`nt_compat_exports::rtl::UnicodeString`]; the character
//! folding (upcase/downcase) is authored here and shared with [`super::convert`].
//!
//! Category A (pure/mechanical) of the Step 2b port. Every function is host-tested.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

pub use nt_compat_exports::rtl::UnicodeString;

/// A counted 8-bit string (Windows `ANSI_STRING` / `OEM_STRING`), byte lengths. Mirrors
/// [`UnicodeString`] for the narrow surface.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AnsiString {
    /// Backing bytes.
    pub buffer: Vec<u8>,
    /// Used length in bytes.
    pub length: u16,
    /// Capacity in bytes.
    pub maximum_length: u16,
}

impl AnsiString {
    /// `RtlInitAnsiString` / `RtlInitString`: init from a NUL-terminated byte string. `Length`
    /// excludes the terminator; `MaximumLength` includes it.
    pub fn init(src: &[u8]) -> Self {
        let n = src.iter().position(|&b| b == 0).unwrap_or(src.len());
        AnsiString {
            buffer: src[..n].to_vec(),
            length: n as u16,
            maximum_length: (n + 1) as u16,
        }
    }

    /// The used bytes (excludes any spare capacity / NUL).
    pub fn as_bytes(&self) -> &[u8] {
        let n = (self.length as usize).min(self.buffer.len());
        &self.buffer[..n]
    }

    /// `RtlFreeAnsiString`: release the buffer, zeroing the descriptor.
    pub fn free(&mut self) {
        self.buffer.clear();
        self.length = 0;
        self.maximum_length = 0;
    }
}

// --- character folding -------------------------------------------------------------------------

/// `RtlUpcaseUnicodeChar`: upper-case a single UTF-16 code unit (ASCII + Latin-1 supplement).
pub fn upcase_char(c: u16) -> u16 {
    match c {
        0x61..=0x7A => c - 0x20,              // a-z
        0xE0..=0xFE if c != 0xF7 => c - 0x20, // à-þ (excl. ÷)
        _ => c,
    }
}

/// `RtlDowncaseUnicodeChar`: lower-case a single UTF-16 code unit (ASCII + Latin-1 supplement).
pub fn downcase_char(c: u16) -> u16 {
    match c {
        0x41..=0x5A => c + 0x20,              // A-Z
        0xC0..=0xDE if c != 0xD7 => c + 0x20, // À-Þ (excl. ×)
        _ => c,
    }
}

/// `RtlUpperChar`: upper-case one ANSI/OEM byte for the single-byte boot code-page path.
pub fn upcase_ansi_byte(b: u8) -> u8 {
    let up = upcase_char(b as u16);
    if up <= u8::MAX as u16 {
        up as u8
    } else {
        b
    }
}

// --- RtlInit* ----------------------------------------------------------------------------------

/// `RtlInitUnicodeString`: a read-only counted view (`Length == MaximumLength == byte length`).
pub fn init_unicode_string(src: &[u16]) -> UnicodeString {
    UnicodeString::init(src)
}

/// `RtlInitUnicodeStringEx`: as [`init_unicode_string`] but reports failure if the source exceeds
/// `0xFFFE` bytes (the `UNICODE_STRING` `Length` field is a `u16`). Returns `None` on overflow.
pub fn init_unicode_string_ex(src: &[u16]) -> Option<UnicodeString> {
    if src.len().checked_mul(2)? > 0xFFFE {
        return None;
    }
    Some(UnicodeString::init(src))
}

/// `RtlCreateUnicodeString`: allocate a NUL-terminated copy (`MaximumLength` includes the NUL).
pub fn create_unicode_string(src: &[u16]) -> UnicodeString {
    UnicodeString::create(src)
}

/// `RtlCreateUnicodeStringFromAsciiz`: widen a NUL-terminated ASCII string and allocate a
/// NUL-terminated UTF-16 copy.
pub fn create_unicode_string_from_asciiz(src: &[u8]) -> UnicodeString {
    let n = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    let wide: Vec<u16> = src[..n].iter().map(|&b| b as u16).collect();
    UnicodeString::create(&wide)
}

/// `RtlDuplicateUnicodeString`: allocate a fresh copy of the used units. When `nul_terminate`, the
/// copy is NUL-terminated (`MaximumLength` includes the NUL).
pub fn duplicate_unicode_string(src: &UnicodeString, nul_terminate: bool) -> UnicodeString {
    if nul_terminate {
        UnicodeString::create(src.as_units())
    } else {
        UnicodeString::init(src.as_units())
    }
}

// --- copy / append -----------------------------------------------------------------------------

/// `RtlCopyUnicodeString`: copy `src` into `dst`, truncating to `dst.MaximumLength`. Returns the
/// number of code units copied.
pub fn copy_unicode_string(dst: &mut UnicodeString, src: &UnicodeString) -> usize {
    dst.copy_from(src)
}

/// `RtlAppendUnicodeToString`: append raw UTF-16 units, failing (`false`) on capacity overflow.
pub fn append_unicode_to_string(dst: &mut UnicodeString, extra: &[u16]) -> bool {
    dst.append_units(extra)
}

/// `RtlAppendUnicodeStringToString`: append another counted string, failing on capacity overflow.
pub fn append_unicode_string_to_string(dst: &mut UnicodeString, src: &UnicodeString) -> bool {
    dst.append_units(src.as_units())
}

/// `RtlEraseUnicodeString`: zero the buffer contents and set `Length = 0` (a secure clear).
pub fn erase_unicode_string(s: &mut UnicodeString) {
    for u in s.buffer.iter_mut() {
        *u = 0;
    }
    s.length = 0;
}

// --- compare / equal / prefix ------------------------------------------------------------------

/// `RtlCompareUnicodeString`: lexical comparison, optionally case-insensitive.
pub fn compare_unicode_string(a: &[u16], b: &[u16], case_insensitive: bool) -> Ordering {
    nt_compat_exports::rtl::compare_unicode(a, b, case_insensitive)
}

/// `RtlEqualUnicodeString`: equality wrapper over [`compare_unicode_string`].
pub fn equal_unicode_string(a: &[u16], b: &[u16], case_insensitive: bool) -> bool {
    nt_compat_exports::rtl::equal_unicode(a, b, case_insensitive)
}

/// `RtlCompareString`: lexical comparison of counted 8-bit strings.
pub fn compare_string(a: &[u8], b: &[u8], case_insensitive: bool) -> i32 {
    let n = a.len().min(b.len());
    for i in 0..n {
        let lhs = if case_insensitive {
            upcase_ansi_byte(a[i])
        } else {
            a[i]
        };
        let rhs = if case_insensitive {
            upcase_ansi_byte(b[i])
        } else {
            b[i]
        };
        let diff = lhs as i32 - rhs as i32;
        if diff != 0 {
            return diff;
        }
    }
    a.len() as i32 - b.len() as i32
}

/// `RtlEqualString`: equality wrapper over [`compare_string`].
pub fn equal_string(a: &[u8], b: &[u8], case_insensitive: bool) -> bool {
    a.len() == b.len() && compare_string(a, b, case_insensitive) == 0
}

/// `RtlPrefixString`: `true` if `prefix` is a leading prefix of `s`.
pub fn prefix_string(prefix: &[u8], s: &[u8], case_insensitive: bool) -> bool {
    if prefix.len() > s.len() {
        return false;
    }
    equal_string(prefix, &s[..prefix.len()], case_insensitive)
}

/// `RtlPrefixUnicodeString`: `true` if `prefix` is a leading prefix of `s`.
pub fn prefix_unicode_string(prefix: &[u16], s: &[u16], case_insensitive: bool) -> bool {
    if prefix.len() > s.len() {
        return false;
    }
    equal_unicode_string(prefix, &s[..prefix.len()], case_insensitive)
}

// --- case folding over whole strings -----------------------------------------------------------

/// `RtlUpcaseUnicodeString` (the pure part): upper-case every code unit into a fresh buffer.
pub fn upcase_unicode_string(src: &[u16]) -> Vec<u16> {
    src.iter().copied().map(upcase_char).collect()
}

/// `RtlDowncaseUnicodeString` (the pure part): lower-case every code unit into a fresh buffer.
pub fn downcase_unicode_string(src: &[u16]) -> Vec<u16> {
    src.iter().copied().map(downcase_char).collect()
}

/// `RtlUpperString`: upper-case a counted 8-bit string into a fresh buffer.
pub fn upper_string(src: &[u8]) -> Vec<u8> {
    src.iter().copied().map(upcase_ansi_byte).collect()
}

// --- validation --------------------------------------------------------------------------------

/// `RtlValidateUnicodeString`: a well-formed `UNICODE_STRING` has `Length <= MaximumLength` and an
/// even `Length` (whole code units).
pub fn validate_unicode_string(s: &UnicodeString) -> bool {
    s.length <= s.maximum_length && s.length.is_multiple_of(2)
}

/// `RtlIsTextUnicode`/`RtlIsNameLegalDOS8Dot3`-adjacent helper: whether a name fits the classic
/// 8.3 form (`name` up to 8 chars, optional `.ext` up to 3), ASCII-only, no reserved chars.
pub fn is_name_legal_dos_8dot3(name: &[u16]) -> bool {
    // Reject empty / over-long overall.
    if name.is_empty() {
        return false;
    }
    const RESERVED: &[u8] = b"\"+,;=[]|<>/?*:\\. ";
    let dot = name.iter().position(|&c| c == b'.' as u16);
    let (stem, ext): (&[u16], &[u16]) = match dot {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, &[]),
    };
    if stem.is_empty() || stem.len() > 8 || ext.len() > 3 {
        return false;
    }
    // A second dot is illegal.
    if ext.contains(&(b'.' as u16)) {
        return false;
    }
    let ok_char = |&c: &u16| c < 0x80 && c != 0 && !RESERVED.contains(&(c as u8));
    stem.iter().all(ok_char) && ext.iter().all(ok_char)
}

// --- Rust-string helpers (host convenience, used by tests + the CRT layer) ---------------------

/// UTF-16 length (code units) of a NUL-terminated wide buffer (`wcslen` semantics).
pub fn wcslen(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Widen an ASCII/Latin-1 `str` to a `Vec<u16>` (test/host helper).
pub fn widen(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Narrow a UTF-16 slice to a `String`, replacing non-representable units (test/host helper).
pub fn narrow(s: &[u16]) -> String {
    String::from_utf16_lossy(s)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn init_ex_overflow() {
        assert!(init_unicode_string_ex(&u("ok")).is_some());
        let big = std::vec![b'a' as u16; 0x8000];
        assert!(init_unicode_string_ex(&big).is_none());
    }

    #[test]
    fn ansi_init_len_and_bytes() {
        let a = AnsiString::init(b"BUTTON\0extra");
        assert_eq!(a.length, 6);
        assert_eq!(a.maximum_length, 7);
        assert_eq!(a.as_bytes(), b"BUTTON");
    }

    #[test]
    fn upcase_downcase_roundtrip() {
        for c in ['a', 'z', 'A', 'Z', '5', 'é', 'É'] {
            let w = c as u16;
            assert_eq!(downcase_char(upcase_char(w)), downcase_char(w));
        }
        assert_eq!(upcase_char(0xF7), 0xF7); // ÷ unchanged
        assert_eq!(downcase_char(0xD7), 0xD7); // × unchanged
        assert_eq!(upcase_unicode_string(&u("aB9é")), u("AB9É"));
        assert_eq!(downcase_unicode_string(&u("AB9É")), u("ab9é"));
    }

    #[test]
    fn create_unicode_string_nul_terminated_lengths() {
        // RtlCreateUnicodeString semantics (unicode.c:2306): Size = (len+1)*2; Length = Size-2;
        // MaximumLength = Size; Buffer is a NUL-terminated copy. Mirrors the on-target export
        // (nt-ntdll-dll/src/exports.rs rtl_create_unicode_string) which uses process_heap_alloc.
        let s = create_unicode_string(&u("ntsvcs"));
        assert_eq!(s.length, 12); // 6 units * 2 bytes, excludes the NUL
        assert_eq!(s.maximum_length, 14); // includes the trailing NUL
        assert_eq!(s.as_units(), &u("ntsvcs")[..]);
        assert_eq!(*s.buffer.last().unwrap(), 0); // NUL-terminated

        // Empty source: an empty NUL-terminated string (Length 0, capacity for the NUL only).
        let e = create_unicode_string(&u(""));
        assert_eq!(e.length, 0);
        assert_eq!(e.maximum_length, 2);
        assert_eq!(*e.buffer.last().unwrap(), 0);
    }

    #[test]
    fn create_from_asciiz() {
        let s = create_unicode_string_from_asciiz(b"Btn\0garbage");
        assert_eq!(s.as_units(), &u("Btn")[..]);
        assert_eq!(*s.buffer.last().unwrap(), 0);
    }

    #[test]
    fn create_from_asciiz_edge_cases() {
        // No embedded NUL → the WHOLE slice is widened (position() → None → src.len()).
        let all = create_unicode_string_from_asciiz(b"NoNul");
        assert_eq!(all.as_units(), &u("NoNul")[..]);
        assert_eq!(all.length, 10); // 5 units * 2
        assert_eq!(*all.buffer.last().unwrap(), 0); // still NUL-terminated by create()
                                                    // Leading NUL → empty content, but a valid NUL-terminated empty string.
        let empty = create_unicode_string_from_asciiz(b"\0rest");
        assert_eq!(empty.length, 0);
        assert_eq!(empty.maximum_length, 2); // room for the NUL only
        assert_eq!(*empty.buffer.last().unwrap(), 0);
        // High-bit bytes widen 1:1 (b as u16), NOT sign-extended.
        let hi = create_unicode_string_from_asciiz(&[0xE9, 0x00]); // 'é' in latin1 → U+00E9
        assert_eq!(hi.as_units(), &[0x00E9u16][..]);
    }

    #[test]
    fn duplicate_without_nul_terminate_uses_init_semantics() {
        // nul_terminate=false → RtlDuplicateUnicodeString via init(): MaximumLength == Length, NO
        // trailing NUL reserved (the other branch, only the =true path was covered).
        let src = UnicodeString::create(&u("Path")); // 4 units, NUL-terminated source
        let dup = duplicate_unicode_string(&src, false);
        assert_eq!(dup.as_units(), &u("Path")[..]);
        assert_eq!(dup.length, 8); // 4 units * 2
        assert_eq!(
            dup.maximum_length, 8,
            "init: MaximumLength == Length (no NUL slack)"
        );
        // A NUL-terminated duplicate of the SAME source reserves the extra unit.
        let dup_nul = duplicate_unicode_string(&src, true);
        assert_eq!(
            dup_nul.maximum_length, 10,
            "create: MaximumLength includes the NUL"
        );
        assert_eq!(*dup_nul.buffer.last().unwrap(), 0);
    }

    #[test]
    fn append_and_copy() {
        let mut dst = UnicodeString {
            buffer: Vec::new(),
            length: 0,
            maximum_length: 16,
        };
        assert!(append_unicode_to_string(&mut dst, &u("Foo")));
        let src = UnicodeString::init(&u("Bar"));
        assert!(append_unicode_string_to_string(&mut dst, &src));
        assert_eq!(dst.as_units(), &u("FooBar")[..]);
        let mut d2 = UnicodeString {
            buffer: Vec::new(),
            length: 0,
            maximum_length: 4,
        };
        assert_eq!(copy_unicode_string(&mut d2, &dst), 2); // truncated to 2 units
    }

    #[test]
    fn prefix_and_equal() {
        assert!(prefix_unicode_string(
            &u("\\Device"),
            &u("\\Device\\Foo"),
            false
        ));
        assert!(!prefix_unicode_string(
            &u("\\Devicez"),
            &u("\\Device"),
            false
        ));
        assert!(equal_unicode_string(&u("Foo"), &u("FOO"), true));
    }

    #[test]
    fn counted_ansi_compare_prefix_and_uppercase() {
        assert_eq!(compare_string(b"abc", b"ABC", true), 0);
        assert!(compare_string(b"abc", b"abd", false) < 0);
        assert_eq!(compare_string(b"abc", b"abcd", false), -1);
        assert!(equal_string(b"Service", b"SERVICE", true));
        assert!(prefix_string(b"\\Device", b"\\DEVICE\\Harddisk0", true));
        assert_eq!(upper_string(b"aBz9!"), b"ABZ9!");
        assert_eq!(upcase_ansi_byte(0xE9), 0xC9);
    }

    #[test]
    fn duplicate_and_erase() {
        let src = UnicodeString::init(&u("Hi"));
        let dup = duplicate_unicode_string(&src, true);
        assert_eq!(dup.as_units(), &u("Hi")[..]);
        assert_eq!(*dup.buffer.last().unwrap(), 0);
        let mut m = UnicodeString::create(&u("secret"));
        erase_unicode_string(&mut m);
        assert_eq!(m.length, 0);
        assert!(m.buffer.iter().all(|&c| c == 0));
    }

    #[test]
    fn validate() {
        assert!(validate_unicode_string(&UnicodeString::init(&u("ok"))));
        let bad = UnicodeString {
            buffer: u("x"),
            length: 3, // odd
            maximum_length: 4,
        };
        assert!(!validate_unicode_string(&bad));
    }

    #[test]
    fn dos_8dot3() {
        assert!(is_name_legal_dos_8dot3(&u("CONFIG.SYS")));
        assert!(is_name_legal_dos_8dot3(&u("README")));
        assert!(!is_name_legal_dos_8dot3(&u("TOOLONGNAME.TXT")));
        assert!(!is_name_legal_dos_8dot3(&u("bad.name.ext")));
        assert!(!is_name_legal_dos_8dot3(&u("has space")));
        assert!(!is_name_legal_dos_8dot3(&u("")));
    }

    #[test]
    fn wcslen_stops_at_nul() {
        assert_eq!(wcslen(&[b'a' as u16, b'b' as u16, 0, b'c' as u16]), 2);
        assert_eq!(wcslen(&u("abc")), 3);
    }
}
