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
    match b {
        b'a'..=b'z' => b - 0x20,
        _ => b,
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
        // STRING.Buffer is PCHAR. Preserve the signed-CHAR promotion ReactOS uses rather than
        // comparing the underlying bytes as unsigned values.
        let diff = lhs as i8 as i32 - rhs as i8 as i32;
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

/// The NetBIOS computer-name cap used by `RtlDnsHostNameToComputerName`.
pub const MAX_COMPUTER_NAME_LENGTH: usize = 15;

fn narrow_oem_unit(unit: u16) -> u8 {
    if unit <= u8::MAX as u16 {
        unit as u8
    } else {
        b'?'
    }
}

/// `RtlEqualComputerName`: compare two computer names after uppercasing and narrowing through the
/// single-byte OEM code-page path.
pub fn equal_computer_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter().copied().zip(b.iter().copied()).all(|(lhs, rhs)| {
            narrow_oem_unit(upcase_char(lhs)) == narrow_oem_unit(upcase_char(rhs))
        })
}

/// `RtlEqualDomainName`: same comparison rules as `RtlEqualComputerName`.
pub fn equal_domain_name(a: &[u16], b: &[u16]) -> bool {
    equal_computer_name(a, b)
}

/// `RtlDnsHostNameToComputerName`: take the first DNS label, uppercase it, truncate it to the
/// NetBIOS computer-name limit, and reject unmappable characters. The returned UTF-16 buffer is the
/// content only; callers add the NUL terminator as needed.
pub fn dns_host_name_to_computer_name(dns_host_name: &[u16]) -> Option<Vec<u16>> {
    let label_len = dns_host_name
        .iter()
        .position(|&unit| unit == b'.' as u16)
        .unwrap_or(dns_host_name.len());
    if label_len == 0 {
        return None;
    }

    let mut out = Vec::new();
    for &unit in dns_host_name[..label_len]
        .iter()
        .take(MAX_COMPUTER_NAME_LENGTH)
    {
        let narrowed = narrow_oem_unit(upcase_char(unit));
        if narrowed == b'?' && unit != b'?' as u16 {
            return None;
        }
        out.push(narrowed as u16);
    }
    Some(out)
}

/// `RtlHashUnicodeString`: X65599 hash over the counted UTF-16 units.
pub fn hash_unicode_string(src: &[u16], case_insensitive: bool, algorithm: u32) -> Option<u32> {
    if !matches!(algorithm, 0 | 1) {
        return None;
    }
    let mut hash = 0u32;
    for &unit in src {
        let folded = if case_insensitive {
            upcase_char(unit)
        } else {
            unit
        };
        hash = hash.wrapping_mul(65_599).wrapping_add(folded as u32);
    }
    Some(hash)
}

/// Outcome for `RtlFindCharInUnicodeString`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FindCharInUnicodeString {
    /// A match was found; value is the byte offset written to `Position`.
    Found(u16),
    /// No matching character was found.
    NotFound,
    /// Unsupported flags were supplied.
    InvalidFlags,
}

/// `RtlFindCharInUnicodeString`: scan a counted UTF-16 string for characters in, or outside, a
/// match set. Positions are byte offsets and match the ReactOS/NT contract: forward searches return
/// the offset just after the character; reverse searches return the character offset.
pub fn find_char_in_unicode_string(
    flags: u32,
    search: &[u16],
    matches: &[u16],
) -> FindCharInUnicodeString {
    const START_AT_END: u32 = 0x1;
    const COMPLEMENT_CHAR_SET: u32 = 0x2;
    const CASE_INSENSITIVE: u32 = 0x4;

    if flags & !(START_AT_END | COMPLEMENT_CHAR_SET | CASE_INSENSITIVE) != 0 {
        return FindCharInUnicodeString::InvalidFlags;
    }

    let want_to_find = flags & COMPLEMENT_CHAR_SET == 0;
    let case_insensitive = flags & CASE_INSENSITIVE != 0;
    let contains = |unit: u16| {
        let needle = if case_insensitive {
            upcase_char(unit)
        } else {
            unit
        };
        matches.iter().copied().any(|candidate| {
            let candidate = if case_insensitive {
                upcase_char(candidate)
            } else {
                candidate
            };
            needle == candidate
        })
    };

    if flags & START_AT_END != 0 {
        for (i, &unit) in search.iter().enumerate().rev() {
            if contains(unit) == want_to_find {
                return FindCharInUnicodeString::Found((i * 2) as u16);
            }
        }
    } else {
        for (i, &unit) in search.iter().enumerate() {
            if contains(unit) == want_to_find {
                return FindCharInUnicodeString::Found(((i + 1) * 2) as u16);
            }
        }
    }

    FindCharInUnicodeString::NotFound
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

/// Host convenience for ASCII `RtlIsNameLegalDOS8Dot3` inputs. The target export performs real OEM
/// conversion before calling the byte-level validator.
pub fn is_name_legal_dos_8dot3(name: &[u16]) -> bool {
    let mut oem = Vec::new();
    if oem.try_reserve_exact(name.len()).is_err() {
        return false;
    }
    for &unit in name {
        let upcase = upcase_char(unit);
        let Ok(byte) = u8::try_from(upcase) else {
            return false;
        };
        oem.push(byte);
    }
    super::dos8dot3::legal_dos_8dot3_oem(&oem).is_some()
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
        assert_eq!(upper_string(&[b'a', b'Z', 0xE9, 0xFF, 0]), [b'A', b'Z', 0xE9, 0xFF, 0]);
        for byte in 0x80..=0xff {
            assert_eq!(upcase_ansi_byte(byte), byte);
        }
        assert_eq!(compare_string(&[0x80], &[0], false), -128);
        assert_ne!(compare_string(&[0xE9], &[0xC9], true), 0);
        assert!(!equal_string(&[0xE9], &[0xC9], true));
    }

    #[test]
    fn computer_and_domain_names_use_uppercase_oem_comparison() {
        assert!(equal_computer_name(&u("winlogon"), &u("WINLOGON")));
        assert!(equal_domain_name(&u("domain"), &u("DOMAIN")));
        assert!(!equal_computer_name(&u("host1"), &u("host2")));
        assert!(!equal_computer_name(&u("host"), &u("hostx")));

        // The local boot OEM path maps unmappable UTF-16 units to '?' just like the existing
        // Unicode-to-OEM exports, so equality follows that narrowed representation.
        assert!(equal_computer_name(&[0x0100], &[0x0102]));
    }

    #[test]
    fn dns_host_name_to_computer_name_matches_reactos_shape() {
        assert_eq!(
            dns_host_name_to_computer_name(&u("workstation.example.test")),
            Some(u("WORKSTATION"))
        );
        assert_eq!(
            dns_host_name_to_computer_name(&u("abcdefghijklmnop.example")),
            Some(u("ABCDEFGHIJKLMNO"))
        );
        assert_eq!(dns_host_name_to_computer_name(&u(".example")), None);
        assert_eq!(dns_host_name_to_computer_name(&[]), None);
        assert_eq!(dns_host_name_to_computer_name(&[0x0100]), None);
        assert_eq!(
            dns_host_name_to_computer_name(&u("?host")),
            Some(u("?HOST"))
        );
    }

    #[test]
    fn hash_unicode_string_matches_x65599_vectors() {
        assert_eq!(hash_unicode_string(&u("T"), false, 1), Some(0x0000_0054));
        assert_eq!(hash_unicode_string(&u("Test"), false, 1), Some(0x766b_b952));
        assert_eq!(hash_unicode_string(&u("TeSt"), false, 1), Some(0x764b_b172));
        assert_eq!(hash_unicode_string(&u("test"), false, 1), Some(0x4745_d132));
        assert_eq!(hash_unicode_string(&u("test"), true, 1), Some(0x6689_c132));
        assert_eq!(hash_unicode_string(&u("TEST"), true, 1), Some(0x6689_c132));
        assert_eq!(hash_unicode_string(&u("TEST"), false, 1), Some(0x6689_c132));
        assert_eq!(
            hash_unicode_string(&u("t\u{e9}st"), false, 1),
            Some(0x8845_cfb6)
        );
        assert_eq!(
            hash_unicode_string(&u("t\u{e9}st"), true, 1),
            Some(0xa789_bfb6)
        );
        assert_eq!(
            hash_unicode_string(&u("T\u{c9}ST"), true, 1),
            Some(0xa789_bfb6)
        );
        assert_eq!(
            hash_unicode_string(&u("T\u{c9}ST"), false, 1),
            Some(0xa789_bfb6)
        );
        assert_eq!(
            hash_unicode_string(
                &['T' as u16, 'e' as u16, 's' as u16, 't' as u16, 0, '1' as u16,],
                false,
                1,
            ),
            Some(0x3280_3083)
        );
        assert_eq!(
            hash_unicode_string(&u("abcdef"), false, 0),
            Some(0x9713_18c3)
        );
        assert_eq!(hash_unicode_string(&u("Test"), false, 0xffff_ffff), None);
    }

    #[test]
    fn find_char_in_unicode_string_matches_reactos_vectors() {
        use FindCharInUnicodeString::{Found, InvalidFlags, NotFound};

        let string = u("I am a string");
        assert_eq!(find_char_in_unicode_string(0, &string, &u("a")), Found(6));
        assert_eq!(find_char_in_unicode_string(1, &string, &u("a")), Found(10));
        assert_eq!(find_char_in_unicode_string(2, &string, &u("a")), Found(2));
        assert_eq!(find_char_in_unicode_string(3, &string, &u("G")), Found(24));
        assert_eq!(find_char_in_unicode_string(0, &string, &u("A")), NotFound);
        assert_eq!(find_char_in_unicode_string(4, &string, &u("A")), Found(6));
        assert_eq!(find_char_in_unicode_string(6, &string, &u("i")), Found(4));
        assert_eq!(find_char_in_unicode_string(7, &string, &u("G")), Found(22));
        assert_eq!(
            find_char_in_unicode_string(8, &string, &string),
            InvalidFlags
        );

        let alpha = u("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(find_char_in_unicode_string(0, &alpha, &[]), NotFound);
        assert_eq!(find_char_in_unicode_string(2, &alpha, &[]), Found(2));
        assert_eq!(find_char_in_unicode_string(1, &alpha, &u("rvz")), Found(50));
        assert_eq!(find_char_in_unicode_string(3, &alpha, &u("rvz")), Found(48));
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
        assert!(is_name_legal_dos_8dot3(&u("123 5678")));
        assert!(!is_name_legal_dos_8dot3(&u("has space")));
        assert!(is_name_legal_dos_8dot3(&u(".")));
        assert!(is_name_legal_dos_8dot3(&u("..")));
        assert!(!is_name_legal_dos_8dot3(&u("")));
    }

    #[test]
    fn wcslen_stops_at_nul() {
        assert_eq!(wcslen(&[b'a' as u16, b'b' as u16, 0, b'c' as u16]), 2);
        assert_eq!(wcslen(&u("abc")), 3);
    }
}
