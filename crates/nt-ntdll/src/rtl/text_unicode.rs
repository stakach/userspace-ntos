//! Heuristic UTF-16 detection used by `RtlIsTextUnicode`.
//!
//! The native routine is deliberately mask-sensitive: callers select which tests affect the
//! returned flags and final Boolean. Keeping the detector over byte slices also preserves odd-length
//! and unaligned-buffer behavior without target pointer assumptions.

pub const IS_TEXT_UNICODE_ASCII16: u32 = 0x0001;
pub const IS_TEXT_UNICODE_STATISTICS: u32 = 0x0002;
pub const IS_TEXT_UNICODE_CONTROLS: u32 = 0x0004;
pub const IS_TEXT_UNICODE_SIGNATURE: u32 = 0x0008;
pub const IS_TEXT_UNICODE_REVERSE_ASCII16: u32 = 0x0010;
pub const IS_TEXT_UNICODE_REVERSE_STATISTICS: u32 = 0x0020;
pub const IS_TEXT_UNICODE_REVERSE_CONTROLS: u32 = 0x0040;
pub const IS_TEXT_UNICODE_REVERSE_SIGNATURE: u32 = 0x0080;
pub const IS_TEXT_UNICODE_ILLEGAL_CHARS: u32 = 0x0100;
pub const IS_TEXT_UNICODE_ODD_LENGTH: u32 = 0x0200;
pub const IS_TEXT_UNICODE_DBCS_LEADBYTE: u32 = 0x0400;
pub const IS_TEXT_UNICODE_NULL_BYTES: u32 = 0x1000;

pub const IS_TEXT_UNICODE_UNICODE_MASK: u32 = 0x000f;
pub const IS_TEXT_UNICODE_REVERSE_MASK: u32 = 0x00f0;
pub const IS_TEXT_UNICODE_NOT_UNICODE_MASK: u32 = 0x0f00;
pub const IS_TEXT_UNICODE_NOT_ASCII_MASK: u32 = 0xf000;

/// Result of the pure `RtlIsTextUnicode` detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextUnicodeResult {
    pub is_unicode: bool,
    pub flags: u32,
}

fn unit(bytes: &[u8], index: usize) -> u16 {
    u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]])
}

/// Apply the ReactOS `RtlIsTextUnicode` tests.
///
/// `requested == None` models a null result pointer. The DBCS predicate is invoked only when the
/// process uses an ANSI DBCS code page and a non-null caller explicitly requests that test.
pub fn is_text_unicode<F>(
    bytes: &[u8],
    requested: Option<u32>,
    dbcs_enabled: bool,
    mut is_dbcs_lead_unit: F,
) -> TextUnicodeResult
where
    F: FnMut(u16) -> bool,
{
    if bytes.len() < 2 {
        return TextUnicodeResult {
            is_unicode: false,
            flags: 0,
        };
    }

    let requested_flags = requested.unwrap_or(u32::MAX);
    let mut out_flags = 0u32;
    if bytes.len() & 1 != 0 {
        out_flags |= IS_TEXT_UNICODE_ODD_LENGTH;
    }

    let first = unit(bytes, 0);
    if first == 0xfeff {
        out_flags |= IS_TEXT_UNICODE_SIGNATURE;
    }
    if first == 0xfffe {
        out_flags |= IS_TEXT_UNICODE_REVERSE_SIGNATURE;
    }

    let mut inspection_bytes = bytes.len();
    if bytes[inspection_bytes - 1] == 0 {
        inspection_bytes -= 1;
    }
    let units = (inspection_bytes / 2).min(256);
    let mut last_low = 0u8;
    let mut last_high = 0u8;
    let mut low_difference = 0u32;
    let mut high_difference = 0u32;

    for index in 0..units {
        let value = unit(bytes, index);
        let low = value as u8;
        let high = (value >> 8) as u8;
        low_difference += low.abs_diff(last_low) as u32;
        high_difference += high.abs_diff(last_high) as u32;
        last_low = low;
        last_high = high;
        if matches!(value, 0xfffe | 0x0000 | 0x0a0d | 0xffff) {
            out_flags |= IS_TEXT_UNICODE_ILLEGAL_CHARS;
        }
    }

    let mut weight = 3u32;
    if dbcs_enabled && requested.is_some() && requested_flags & IS_TEXT_UNICODE_DBCS_LEADBYTE != 0 {
        let mut lead_bytes = 0u32;
        let mut index = 0usize;
        while index < units {
            if is_dbcs_lead_unit(unit(bytes, index)) {
                lead_bytes += 1;
                index += 1;
            }
            index += 1;
        }
        if lead_bytes != 0 {
            let scale = ((units as u32) / 2).wrapping_sub(1);
            weight = if lead_bytes < scale / 3 {
                3
            } else if lead_bytes < scale.wrapping_mul(2) / 3 {
                2
            } else {
                1
            };
            out_flags |= IS_TEXT_UNICODE_DBCS_LEADBYTE;
        }
    }

    if low_difference < 127 && high_difference == 0 {
        out_flags |= IS_TEXT_UNICODE_ASCII16;
    }
    if high_difference != 0 && low_difference == 0 {
        out_flags |= IS_TEXT_UNICODE_REVERSE_ASCII16;
    }
    if weight.wrapping_mul(low_difference) < high_difference {
        out_flags |= IS_TEXT_UNICODE_REVERSE_STATISTICS;
    }
    if requested_flags & IS_TEXT_UNICODE_STATISTICS != 0
        && weight.wrapping_mul(high_difference) < low_difference
    {
        out_flags |= IS_TEXT_UNICODE_STATISTICS;
    }
    if requested_flags & IS_TEXT_UNICODE_NULL_BYTES != 0
        && (0..units).any(|index| {
            let value = unit(bytes, index);
            value & 0xff == 0 || value >> 8 == 0
        })
    {
        out_flags |= IS_TEXT_UNICODE_NULL_BYTES;
    }
    if requested_flags & IS_TEXT_UNICODE_CONTROLS != 0
        && (0..units).any(|index| {
            matches!(
                unit(bytes, index),
                0x000d | 0x000a | 0x0009 | 0x0020 | 0x3000
            )
        })
    {
        out_flags |= IS_TEXT_UNICODE_CONTROLS;
    }
    if requested_flags & IS_TEXT_UNICODE_REVERSE_CONTROLS != 0
        && (0..units).any(|index| matches!(unit(bytes, index), 0x0d00 | 0x0a00 | 0x0900 | 0x2000))
    {
        out_flags |= IS_TEXT_UNICODE_REVERSE_CONTROLS;
    }

    if requested.is_some() {
        out_flags &= requested_flags;
    }
    let is_unicode =
        if out_flags & (IS_TEXT_UNICODE_REVERSE_MASK | IS_TEXT_UNICODE_NOT_UNICODE_MASK) != 0 {
            false
        } else {
            out_flags & (IS_TEXT_UNICODE_NOT_ASCII_MASK | IS_TEXT_UNICODE_UNICODE_MASK) != 0
        };
    TextUnicodeResult {
        is_unicode,
        flags: out_flags,
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;

    fn wide(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    fn detect(bytes: &[u8], requested: Option<u32>) -> TextUnicodeResult {
        is_text_unicode(bytes, requested, false, |_| false)
    }

    #[test]
    fn reactos_ascii_and_unicode_vectors() {
        assert!(!detect(b"A simple string\0", None).is_unicode);

        let unicode = wide(&[
            b'A' as u16,
            b' ' as u16,
            b'U' as u16,
            b'n' as u16,
            b'i' as u16,
            b'c' as u16,
            b'o' as u16,
            b'd' as u16,
            b'e' as u16,
            b' ' as u16,
            b's' as u16,
            b't' as u16,
            b'r' as u16,
            b'i' as u16,
            b'n' as u16,
            b'g' as u16,
            0,
        ]);
        let result = detect(&unicode, Some(IS_TEXT_UNICODE_UNICODE_MASK));
        assert_eq!(
            result,
            TextUnicodeResult {
                is_unicode: true,
                flags: IS_TEXT_UNICODE_STATISTICS | IS_TEXT_UNICODE_CONTROLS,
            }
        );
        let odd = detect(
            &unicode[..unicode.len() - 1],
            Some(IS_TEXT_UNICODE_ODD_LENGTH),
        );
        assert_eq!(odd.flags, IS_TEXT_UNICODE_ODD_LENGTH);
        assert!(!odd.is_unicode);
    }

    #[test]
    fn requested_mask_controls_bom_and_invalid_precedence() {
        let little_bom = wide(&[0xfeff, b'<' as u16]);
        assert_eq!(
            detect(&little_bom, Some(IS_TEXT_UNICODE_SIGNATURE)),
            TextUnicodeResult {
                is_unicode: true,
                flags: IS_TEXT_UNICODE_SIGNATURE,
            }
        );
        let reverse_bom = wide(&[0xfffe, 0x4100]);
        assert_eq!(
            detect(&reverse_bom, Some(IS_TEXT_UNICODE_REVERSE_SIGNATURE)),
            TextUnicodeResult {
                is_unicode: false,
                flags: IS_TEXT_UNICODE_REVERSE_SIGNATURE,
            }
        );
        assert_eq!(detect(&reverse_bom, Some(0)).flags, 0);

        let positive_and_illegal = wide(&[0xfeff, 0xffff]);
        let result = detect(
            &positive_and_illegal,
            Some(IS_TEXT_UNICODE_SIGNATURE | IS_TEXT_UNICODE_ILLEGAL_CHARS),
        );
        assert_eq!(
            result.flags,
            IS_TEXT_UNICODE_SIGNATURE | IS_TEXT_UNICODE_ILLEGAL_CHARS
        );
        assert!(!result.is_unicode);
    }

    #[test]
    fn controls_and_reverse_controls_are_independent() {
        let mixed = wide(&[0x0009, 0x9000, 0x0d00, 0x000a, 0]);
        let result = detect(
            &mixed,
            Some(IS_TEXT_UNICODE_CONTROLS | IS_TEXT_UNICODE_REVERSE_CONTROLS),
        );
        assert_eq!(
            result.flags,
            IS_TEXT_UNICODE_CONTROLS | IS_TEXT_UNICODE_REVERSE_CONTROLS
        );
        assert!(!result.is_unicode);
    }

    #[test]
    fn null_bytes_are_positive_unless_a_negative_test_survives() {
        let ascii16 = wide(&[b'A' as u16, b'B' as u16]);
        let result = detect(&ascii16, Some(IS_TEXT_UNICODE_NULL_BYTES));
        assert_eq!(result.flags, IS_TEXT_UNICODE_NULL_BYTES);
        assert!(result.is_unicode);

        let result = detect(
            &[b'A', 0, b'B'],
            Some(IS_TEXT_UNICODE_NULL_BYTES | IS_TEXT_UNICODE_ODD_LENGTH),
        );
        assert_eq!(
            result.flags,
            IS_TEXT_UNICODE_NULL_BYTES | IS_TEXT_UNICODE_ODD_LENGTH
        );
        assert!(!result.is_unicode);
    }

    #[test]
    fn terminal_nul_and_scan_limit_match_native_mechanics() {
        let terminated = wide(&[b'A' as u16, 0]);
        assert_eq!(
            detect(&terminated, Some(IS_TEXT_UNICODE_ILLEGAL_CHARS)).flags,
            0
        );

        let mut beyond_limit = wide(&alloc::vec![b'A' as u16; 256]);
        beyond_limit.extend_from_slice(&0xffffu16.to_le_bytes());
        assert_eq!(
            detect(&beyond_limit, Some(IS_TEXT_UNICODE_ILLEGAL_CHARS)).flags,
            0
        );
        let mut at_limit = wide(&alloc::vec![b'A' as u16; 255]);
        at_limit.extend_from_slice(&0xffffu16.to_le_bytes());
        assert_eq!(
            detect(&at_limit, Some(IS_TEXT_UNICODE_ILLEGAL_CHARS)).flags,
            IS_TEXT_UNICODE_ILLEGAL_CHARS
        );
    }

    #[test]
    fn dbcs_test_is_explicit_and_skips_trailing_unit() {
        let bytes = wide(&[0x0081, 0x0041, 0x0082, 0x0042]);
        let mut visited = Vec::new();
        let result = is_text_unicode(&bytes, Some(IS_TEXT_UNICODE_DBCS_LEADBYTE), true, |value| {
            visited.push(value);
            matches!(value, 0x0081 | 0x0082)
        });
        assert_eq!(visited, [0x0081, 0x0082]);
        assert_eq!(result.flags, IS_TEXT_UNICODE_DBCS_LEADBYTE);
        assert!(!result.is_unicode);

        let mut called = false;
        let result = is_text_unicode(&bytes, None, true, |_| {
            called = true;
            true
        });
        assert!(!called);
        assert_eq!(result.flags & IS_TEXT_UNICODE_DBCS_LEADBYTE, 0);
    }

    #[test]
    fn short_buffers_clear_the_result() {
        for bytes in [&[][..], &[0u8][..]] {
            assert_eq!(
                detect(bytes, Some(u32::MAX)),
                TextUnicodeResult {
                    is_unicode: false,
                    flags: 0,
                }
            );
        }
    }
}
