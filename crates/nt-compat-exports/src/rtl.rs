//! Real, host-tested implementations of the `Rtl*` string primitives that
//! `win32k.sys` imports. These are pure (no subsystem dependency) so they can be
//! provided directly by the export surface and unit-tested on the host. Phase 2's
//! win32k component binds these to the corresponding IAT slots.
//!
//! The Windows `UNICODE_STRING`/`ANSI_STRING` are counted (not NUL-terminated):
//! `length` and `maximum_length` are **byte** counts. We model them with borrowed
//! slices; the trampoline layer marshals the real structs.

use alloc::vec::Vec;

/// A counted UTF-16 string (Windows `UNICODE_STRING`), byte lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnicodeString {
    /// Backing UTF-16 code units (up to `maximum_length / 2`).
    pub buffer: Vec<u16>,
    /// Used length in **bytes** (`buffer.len() * 2` for a full buffer).
    pub length: u16,
    /// Capacity in **bytes**.
    pub maximum_length: u16,
}

impl UnicodeString {
    /// `RtlInitUnicodeString`: initialise a counted string from a UTF-16 slice.
    /// `length` = `maximum_length` = the slice's byte length (a read-only view).
    pub fn init(src: &[u16]) -> Self {
        let bytes = (src.len() * 2) as u16;
        UnicodeString {
            buffer: src.to_vec(),
            length: bytes,
            maximum_length: bytes,
        }
    }

    /// `RtlCreateUnicodeString`: allocate a NUL-terminated copy. `maximum_length`
    /// includes room for the trailing NUL.
    pub fn create(src: &[u16]) -> Self {
        let mut buf = src.to_vec();
        buf.push(0);
        UnicodeString {
            length: (src.len() * 2) as u16,
            maximum_length: (buf.len() * 2) as u16,
            buffer: buf,
        }
    }

    /// `RtlFreeUnicodeString`: release the buffer, zeroing the descriptor.
    pub fn free(&mut self) {
        self.buffer.clear();
        self.length = 0;
        self.maximum_length = 0;
    }

    /// The number of used code units (`length` is a byte count).
    pub fn units(&self) -> usize {
        (self.length as usize) / 2
    }

    /// The used code units (excludes any spare capacity / NUL).
    pub fn as_units(&self) -> &[u16] {
        &self.buffer[..self.units().min(self.buffer.len())]
    }

    /// `RtlCopyUnicodeString`: copy `src` into `self`, truncating to
    /// `maximum_length`. Returns the number of code units copied.
    pub fn copy_from(&mut self, src: &UnicodeString) -> usize {
        let cap = (self.maximum_length as usize) / 2;
        let n = src.units().min(cap);
        self.buffer.truncate(0);
        self.buffer.extend_from_slice(&src.as_units()[..n]);
        self.length = (n * 2) as u16;
        n
    }

    /// `RtlAppendUnicodeToString`: append UTF-16 units, failing (returns `false`)
    /// if they would exceed `maximum_length`.
    pub fn append_units(&mut self, extra: &[u16]) -> bool {
        let cap = (self.maximum_length as usize) / 2;
        if self.units() + extra.len() > cap {
            return false;
        }
        // Keep only the used prefix, then append.
        self.buffer.truncate(self.units());
        self.buffer.extend_from_slice(extra);
        self.length = (self.buffer.len() * 2) as u16;
        true
    }
}

/// `RtlCompareUnicodeString`: lexical comparison (`Less`/`Equal`/`Greater`).
/// `case_insensitive` upper-cases ASCII before comparing.
pub fn compare_unicode(a: &[u16], b: &[u16], case_insensitive: bool) -> core::cmp::Ordering {
    let up = |c: u16| -> u16 {
        if case_insensitive {
            upcase_char(c)
        } else {
            c
        }
    };
    let mut ia = a.iter().copied().map(up);
    let mut ib = b.iter().copied().map(up);
    loop {
        match (ia.next(), ib.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                core::cmp::Ordering::Equal => continue,
                ord => return ord,
            },
            (Some(_), None) => return core::cmp::Ordering::Greater,
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (None, None) => return core::cmp::Ordering::Equal,
        }
    }
}

/// `RtlEqualUnicodeString`: equality (a thin wrapper over [`compare_unicode`]).
pub fn equal_unicode(a: &[u16], b: &[u16], case_insensitive: bool) -> bool {
    compare_unicode(a, b, case_insensitive) == core::cmp::Ordering::Equal
}

/// `RtlUpcaseUnicodeChar`: upper-case a single code unit. Covers ASCII a-z and
/// Latin-1 supplement à-þ (the ranges win32k needs for class-name folding);
/// other code units pass through unchanged.
pub fn upcase_char(c: u16) -> u16 {
    match c {
        0x61..=0x7A => c - 0x20,              // a-z
        0xE0..=0xFE if c != 0xF7 => c - 0x20, // à-þ (excl. ÷)
        _ => c,
    }
}

/// `RtlAnsiCharToUnicodeChar`: widen one ANSI (code page 1252 ASCII subset) byte.
pub fn ansi_char_to_unicode(c: u8) -> u16 {
    c as u16
}

/// `RtlCompareMemory`: number of leading bytes that are equal.
pub fn compare_memory(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// `RtlInitAnsiString`: byte length of a NUL-terminated ANSI string (the counted
/// `ANSI_STRING.Length`, excluding the terminator).
pub fn init_ansi_len(bytes_until_nul: &[u8]) -> u16 {
    bytes_until_nul
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(bytes_until_nul.len()) as u16
}

/// `RtlIntegerToUnicodeString`: format an unsigned integer in `base`
/// (2/8/10/16) into UTF-16 units. Returns `None` for an unsupported base.
pub fn integer_to_unicode(value: u32, base: u32) -> Option<Vec<u16>> {
    if !matches!(base, 2 | 8 | 10 | 16) {
        return None;
    }
    if value == 0 {
        return Some(alloc::vec![b'0' as u16]);
    }
    let mut digits = Vec::new();
    let mut v = value;
    while v > 0 {
        let d = (v % base) as u8;
        let ch = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        digits.push(ch as u16);
        v /= base;
    }
    digits.reverse();
    Some(digits)
}

/// `RtlUnicodeStringToInteger`: parse a counted UTF-16 integer in `base`.
///
/// Base zero recognizes the native lowercase `0b`, `0o`, and `0x` prefixes. Arithmetic wraps as a
/// Windows `ULONG`; a valid base with no leading digits produces zero. `None` only denotes an
/// unsupported explicit base.
pub fn unicode_string_to_integer(s: &[u16], mut base: u32) -> Option<u32> {
    let mut i = 0;
    while i < s.len() && s[i] <= b' ' as u16 {
        i += 1;
    }
    let negative = if i < s.len() && s[i] == b'+' as u16 {
        i += 1;
        false
    } else if i < s.len() && s[i] == b'-' as u16 {
        i += 1;
        true
    } else {
        false
    };
    if base == 0 {
        base = 10;
        if i + 1 < s.len() && s[i] == b'0' as u16 {
            base = match s[i + 1] {
                c if c == b'b' as u16 => 2,
                c if c == b'o' as u16 => 8,
                c if c == b'x' as u16 => 16,
                _ => 10,
            };
            if base != 10 {
                i += 2;
            }
        }
    } else if !matches!(base, 2 | 8 | 10 | 16) {
        return None;
    }
    let mut acc: u32 = 0;
    while i < s.len() {
        let c = s[i];
        let d = match c {
            0x30..=0x39 => (c - 0x30) as u32,
            0x41..=0x5a => (c - 0x41 + 10) as u32,
            0x61..=0x7a => (c - 0x61 + 10) as u32,
            _ => break,
        };
        if d >= base {
            break;
        }
        acc = acc.wrapping_mul(base).wrapping_add(d);
        i += 1;
    }
    if negative {
        Some(0u32.wrapping_sub(acc))
    } else {
        Some(acc)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn init_and_copy() {
        let src = UnicodeString::init(&u("Window"));
        assert_eq!(src.length, 12);
        assert_eq!(src.maximum_length, 12);
        assert_eq!(src.as_units(), &u("Window")[..]);

        let mut dst = UnicodeString {
            buffer: Vec::new(),
            length: 0,
            maximum_length: 20,
        };
        assert_eq!(dst.copy_from(&src), 6);
        assert_eq!(dst.as_units(), &u("Window")[..]);
    }

    #[test]
    fn copy_truncates_to_maximum_length() {
        let src = UnicodeString::init(&u("LongClassName"));
        let mut dst = UnicodeString {
            buffer: Vec::new(),
            length: 0,
            maximum_length: 8, // 4 code units
        };
        assert_eq!(dst.copy_from(&src), 4);
        assert_eq!(dst.as_units(), &u("Long")[..]);
    }

    #[test]
    fn create_is_nul_terminated() {
        let s = UnicodeString::create(&u("Btn"));
        assert_eq!(s.length, 6);
        assert_eq!(s.maximum_length, 8); // 3 units + NUL
        assert_eq!(*s.buffer.last().unwrap(), 0);
        assert_eq!(s.as_units(), &u("Btn")[..]);
    }

    #[test]
    fn append_respects_capacity() {
        let mut s = UnicodeString {
            buffer: u("Foo"),
            length: 6,
            maximum_length: 12, // 6 units
        };
        assert!(s.append_units(&u("Bar")));
        assert_eq!(s.as_units(), &u("FooBar")[..]);
        // Now full — a further append fails and leaves the string intact.
        assert!(!s.append_units(&u("X")));
        assert_eq!(s.as_units(), &u("FooBar")[..]);
    }

    #[test]
    fn free_zeroes() {
        let mut s = UnicodeString::create(&u("x"));
        s.free();
        assert_eq!(s.length, 0);
        assert_eq!(s.maximum_length, 0);
        assert!(s.buffer.is_empty());
    }

    #[test]
    fn compare_case_sensitivity() {
        assert_eq!(
            compare_unicode(&u("abc"), &u("abc"), false),
            core::cmp::Ordering::Equal
        );
        assert_ne!(
            compare_unicode(&u("abc"), &u("ABC"), false),
            core::cmp::Ordering::Equal
        );
        assert!(equal_unicode(&u("Button"), &u("BUTTON"), true));
        assert!(!equal_unicode(&u("Button"), &u("BUTTONX"), true));
        // Prefix orders before the longer string.
        assert_eq!(
            compare_unicode(&u("ab"), &u("abc"), false),
            core::cmp::Ordering::Less
        );
    }

    #[test]
    fn upcase() {
        assert_eq!(upcase_char(b'a' as u16), b'A' as u16);
        assert_eq!(upcase_char(b'Z' as u16), b'Z' as u16);
        assert_eq!(upcase_char(0xE9), 0xC9); // é -> É
        assert_eq!(upcase_char(0xF7), 0xF7); // ÷ unchanged
        assert_eq!(upcase_char(b'5' as u16), b'5' as u16);
    }

    #[test]
    fn compare_memory_prefix() {
        assert_eq!(compare_memory(b"hello", b"help"), 3);
        assert_eq!(compare_memory(b"abc", b"abc"), 3);
        assert_eq!(compare_memory(b"", b"x"), 0);
    }

    #[test]
    fn ansi_len() {
        assert_eq!(init_ansi_len(b"BUTTON\0extra"), 6);
        assert_eq!(init_ansi_len(b"nonul"), 5);
    }

    #[test]
    fn integer_roundtrip() {
        assert_eq!(integer_to_unicode(0, 10).unwrap(), u("0"));
        assert_eq!(integer_to_unicode(255, 16).unwrap(), u("ff"));
        assert_eq!(integer_to_unicode(10, 2).unwrap(), u("1010"));
        assert_eq!(integer_to_unicode(64, 8).unwrap(), u("100"));
        assert!(integer_to_unicode(1, 7).is_none());

        assert_eq!(unicode_string_to_integer(&u("255"), 10), Some(255));
        assert_eq!(unicode_string_to_integer(&u("0xFF"), 0), Some(255));
        assert_eq!(unicode_string_to_integer(&u("  42"), 10), Some(42));
        assert_eq!(unicode_string_to_integer(&u("1010"), 2), Some(10));
        assert_eq!(
            unicode_string_to_integer(&u("-0o10"), 0),
            Some(u32::MAX - 7)
        );
        assert_eq!(unicode_string_to_integer(&u("0b1010"), 0), Some(10));
        assert_eq!(unicode_string_to_integer(&u("notanumber"), 10), Some(0));
        assert_eq!(unicode_string_to_integer(&u("1"), 3), None);
    }
}
