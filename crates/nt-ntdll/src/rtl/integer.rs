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
    unsigned_to_char(value as u64, base)
}

/// `RtlLargeIntegerToChar`: format a 64-bit value in `base` (2/8/10/16) into ASCII bytes.
pub fn large_integer_to_char(value: u64, base: u32) -> Option<Vec<u8>> {
    unsigned_to_char(value, base)
}

fn unsigned_to_char(value: u64, base: u32) -> Option<Vec<u8>> {
    if !matches!(base, 2 | 8 | 10 | 16) {
        return None;
    }
    if value == 0 {
        return Some(alloc::vec![b'0']);
    }
    let mut digits = Vec::new();
    let mut v = value;
    let b = base as u64;
    while v > 0 {
        let d = (v % b) as u8;
        digits.push(if d < 10 { b'0' + d } else { b'A' + d - 10 });
        v /= b;
    }
    digits.reverse();
    Some(digits)
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
        let ch = if d < 10 { b'0' + d } else { b'A' + (d - 10) };
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

/// `RtlLargeIntegerSubtract`.
pub fn large_integer_subtract(a: i64, b: i64) -> i64 {
    a.wrapping_sub(b)
}

/// `RtlLargeIntegerDivide`.
pub fn large_integer_divide(dividend: i64, divisor: i64) -> Option<(i64, i64)> {
    if divisor == 0 {
        return None;
    }
    Some((
        dividend.wrapping_div(divisor),
        dividend.wrapping_rem(divisor),
    ))
}

#[inline]
const fn large_integer_shift_count(shift_count: i8) -> u32 {
    (shift_count as u8 as u32) & 0x3f
}

/// `RtlLargeIntegerShiftLeft`: logical left shift by `ShiftCount mod 64`.
pub fn large_integer_shift_left(value: i64, shift_count: i8) -> i64 {
    ((value as u64).wrapping_shl(large_integer_shift_count(shift_count))) as i64
}

/// `RtlLargeIntegerShiftRight`: logical right shift by `ShiftCount mod 64`.
pub fn large_integer_shift_right(value: i64, shift_count: i8) -> i64 {
    ((value as u64).wrapping_shr(large_integer_shift_count(shift_count))) as i64
}

/// `RtlLargeIntegerArithmeticShift`: signed right shift by `ShiftCount mod 64`.
pub fn large_integer_arithmetic_shift(value: i64, shift_count: i8) -> i64 {
    value.wrapping_shr(large_integer_shift_count(shift_count))
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
    Some((q as u32, r))
}

/// `RtlExtendedIntegerMultiply`: 64×32 → 64 signed.
pub fn extended_integer_multiply(a: i64, b: i32) -> i64 {
    a.wrapping_mul(b as i64)
}

/// `RtlExtendedLargeIntegerDivide`: 64 signed / 32 unsigned.
pub fn extended_large_integer_divide(dividend: i64, divisor: u32) -> Option<(i64, u32)> {
    if divisor == 0 {
        return None;
    }
    let divisor = divisor as i64;
    let quotient = dividend.wrapping_div(divisor);
    let remainder = dividend.wrapping_rem(divisor) as u32;
    Some((quotient, remainder))
}

/// `RtlExtendedMagicDivide`: `(Dividend * MagicDivisor) >> (64 + ShiftCount)`, with the dividend's
/// sign applied after the unsigned high-half multiply.
pub fn extended_magic_divide(dividend: i64, magic_divisor: i64, shift_count: i8) -> i64 {
    let positive = dividend >= 0;
    let magnitude = if positive {
        dividend as u64
    } else {
        dividend.wrapping_neg() as u64
    };
    let shift = 64 + large_integer_shift_count(shift_count);
    let quotient = ((magnitude as u128).wrapping_mul(magic_divisor as u64 as u128) >> shift) as u64;
    let signed = quotient as i64;
    if positive {
        signed
    } else {
        signed.wrapping_neg()
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
    fn char_roundtrip() {
        assert_eq!(integer_to_char(255, 16).unwrap(), b"FF");
        assert_eq!(
            large_integer_to_char(0x1234_5678_9ABC_DEF0, 16).unwrap(),
            b"123456789ABCDEF0"
        );
        assert_eq!(char_to_integer(b"255", 10), Some(255));
        assert_eq!(char_to_integer(b"0xFF", 0), Some(255));
        assert!(integer_to_char(1, 7).is_none());
        assert!(integer_to_char(1, 3).is_none());
        assert!(large_integer_to_char(1, 12).is_none());
    }

    #[test]
    fn int64_format() {
        assert_eq!(int64_to_unicode(0, 10).unwrap(), u("0"));
        assert_eq!(
            int64_to_unicode(0xDEAD_BEEF_CAFE, 16).unwrap(),
            u("DEADBEEFCAFE")
        );
        assert_eq!(
            int64_to_unicode(1_000_000_000_000, 10).unwrap(),
            u("1000000000000")
        );
        assert!(int64_to_unicode(5, 3).is_none());
    }

    #[test]
    fn large_integer_ops() {
        assert_eq!(large_integer_add(5, -3), 2);
        assert_eq!(large_integer_subtract(5, -3), 8);
        assert_eq!(large_integer_divide(100, 7), Some((14, 2)));
        assert_eq!(large_integer_divide(1, 0), None);
        assert_eq!(large_integer_shift_left(1, 65), 2);
        assert_eq!(large_integer_shift_right(-1, 1), 0x7fff_ffff_ffff_ffff);
        assert_eq!(large_integer_arithmetic_shift(-2, 1), -1);
        assert_eq!(enlarged_integer_multiply(-3, 7), -21);
        assert_eq!(enlarged_unsigned_multiply(0xFFFF_FFFF, 2), 0x1_FFFF_FFFE);
        assert_eq!(enlarged_unsigned_divide(100, 7), Some((14, 2)));
        assert_eq!(enlarged_unsigned_divide(1, 0), None);
        assert_eq!(extended_integer_multiply(-3, 7), -21);
        assert_eq!(extended_large_integer_divide(100, 7), Some((14, 2)));
        assert_eq!(
            extended_large_integer_divide(-100, 7),
            Some((-14, (-2i32) as u32))
        );
        assert_eq!(extended_large_integer_divide(1, 0), None);
    }

    #[test]
    fn extended_magic_divide_matches_wine_vectors() {
        assert_eq!(
            extended_magic_divide(333_333_333, 0x5555_5555_5555_5555, 0),
            111_111_110
        );
        assert_eq!(
            extended_magic_divide(-333_333_333, 0x5555_5555_5555_5555, 0),
            -111_111_110
        );
        assert_eq!(
            extended_magic_divide(555_555_555, 0x6666_6666_6666_67fe, 1),
            111_111_111
        );
        assert_eq!(
            extended_magic_divide(0x081a_c1b9_c231_0a80, 0x002f_1e28_fd1b_5cca, 33),
            0xbeef
        );
    }

    #[test]
    fn byte_swaps_match_rtl_exports() {
        assert_eq!(ushort_byte_swap(0x1234), 0x3412);
        assert_eq!(ulong_byte_swap(0x1234_5678), 0x7856_3412);
        assert_eq!(
            ulonglong_byte_swap(0x0123_4567_89AB_CDEF),
            0xEFCD_AB89_6745_2301
        );
    }
}
