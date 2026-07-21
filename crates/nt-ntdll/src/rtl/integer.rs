//! `Rtl*` integer / large-integer formatting + parsing.
//!
//! `RtlIntegerToChar` / `RtlIntegerToUnicodeString` (format), `RtlCharToInteger` /
//! `RtlUnicodeStringToInteger` (parse), plus the `LARGE_INTEGER` arithmetic helpers
//! (`RtlLargeIntegerAdd` etc. — on x64 these are just 64-bit ops, but ntdll still exports them).
//!
//! Category A. Host-tested.

use alloc::vec::Vec;

pub use nt_compat_exports::rtl::{integer_to_unicode, unicode_string_to_integer};

/// `RtlIntegerToChar`: format `value` in `base` (2/8/10/16) into ASCII bytes. Returns `None` for an
/// unsupported base.
pub fn integer_to_char(value: u32, base: u32) -> Option<Vec<u8>> {
    Some(integer_to_unicode(value, base)?.iter().map(|&c| c as u8).collect())
}

/// `RtlCharToInteger`: parse an ASCII unsigned integer in `base` (`0` auto-detects `0x`).
pub fn char_to_integer(s: &[u8], base: u32) -> Option<u32> {
    let wide: Vec<u16> = s.iter().map(|&b| b as u16).collect();
    unicode_string_to_integer(&wide, base)
}

/// `RtlInt64ToUnicodeString`: format a 64-bit `value` in `base` (2/8/10/16) as UTF-16 units.
pub fn int64_to_unicode(value: u64, base: u32) -> Option<Vec<u16>> {
    if !matches!(base, 2 | 8 | 10 | 16) {
        return None;
    }
    if value == 0 {
        return Some(alloc::vec![b'0' as u16]);
    }
    let mut digits = Vec::new();
    let mut v = value;
    let b = base as u64;
    while v > 0 {
        let d = (v % b) as u8;
        let ch = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        digits.push(ch as u16);
        v /= b;
    }
    digits.reverse();
    Some(digits)
}

/// `RtlUshortByteSwap`.
pub const fn ushort_byte_swap(value: u16) -> u16 {
    value.swap_bytes()
}

/// `RtlUlongByteSwap`.
pub const fn ulong_byte_swap(value: u32) -> u32 {
    value.swap_bytes()
}

/// `RtlUlonglongByteSwap`.
pub const fn ulonglong_byte_swap(value: u64) -> u64 {
    value.swap_bytes()
}

// --- LARGE_INTEGER helpers (x64: plain i64/u64 arithmetic, but ntdll exports them) -------------

/// `RtlLargeIntegerAdd`.
pub fn large_integer_add(a: i64, b: i64) -> i64 {
    a.wrapping_add(b)
}

/// `RtlEnlargedIntegerMultiply`: 32×32 → 64 signed.
pub fn enlarged_integer_multiply(a: i32, b: i32) -> i64 {
    (a as i64) * (b as i64)
}

/// `RtlEnlargedUnsignedMultiply`: 32×32 → 64 unsigned.
pub fn enlarged_unsigned_multiply(a: u32, b: u32) -> u64 {
    (a as u64) * (b as u64)
}

/// `RtlEnlargedUnsignedDivide`: 64/32 → 32 quotient + 32 remainder.
pub fn enlarged_unsigned_divide(dividend: u64, divisor: u32) -> Option<(u32, u32)> {
    if divisor == 0 {
        return None;
    }
    let q = dividend / divisor as u64;
    let r = (dividend % divisor as u64) as u32;
    // The quotient must fit in 32 bits (matches the Windows contract).
    if q > u32::MAX as u64 {
        return None;
    }
    Some((q as u32, r))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn char_roundtrip() {
        assert_eq!(integer_to_char(255, 16).unwrap(), b"ff");
        assert_eq!(char_to_integer(b"255", 10), Some(255));
        assert_eq!(char_to_integer(b"0xFF", 0), Some(255));
        assert!(integer_to_char(1, 7).is_none());
    }

    #[test]
    fn int64_format() {
        assert_eq!(int64_to_unicode(0, 10).unwrap(), u("0"));
        assert_eq!(int64_to_unicode(0xDEAD_BEEF_CAFE, 16).unwrap(), u("deadbeefcafe"));
        assert_eq!(int64_to_unicode(1_000_000_000_000, 10).unwrap(), u("1000000000000"));
        assert!(int64_to_unicode(5, 3).is_none());
    }

    #[test]
    fn large_integer_ops() {
        assert_eq!(large_integer_add(5, -3), 2);
        assert_eq!(enlarged_integer_multiply(-3, 7), -21);
        assert_eq!(enlarged_unsigned_multiply(0xFFFF_FFFF, 2), 0x1_FFFF_FFFE);
        assert_eq!(enlarged_unsigned_divide(100, 7), Some((14, 2)));
        assert_eq!(enlarged_unsigned_divide(1, 0), None);
    }

    #[test]
    fn byte_swaps_match_rtl_exports() {
        assert_eq!(ushort_byte_swap(0x1234), 0x3412);
        assert_eq!(ulong_byte_swap(0x1234_5678), 0x7856_3412);
        assert_eq!(ulonglong_byte_swap(0x0123_4567_89AB_CDEF), 0xEFCD_AB89_6745_2301);
    }
}
