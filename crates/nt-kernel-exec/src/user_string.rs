//! Bounded USER syscall string and stack argument validation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredUnicodeString {
    pub buffer: u64,
    pub length: usize,
    pub probe_length: usize,
}

pub fn required_unicode_string(
    raw: &[u8; 16],
    capture_cap: usize,
) -> Option<RequiredUnicodeString> {
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    let probe_length = length.max(2);
    if length & 1 != 0
        || length > maximum
        || length.checked_add(2)? > capture_cap
        || buffer == 0
        || buffer.checked_add(probe_length as u64).is_none()
    {
        return None;
    }
    Some(RequiredUnicodeString {
        buffer,
        length,
        probe_length,
    })
}

pub fn three_stack_tail_addresses(sp: u64) -> Option<[u64; 3]> {
    if sp == 0 {
        return None;
    }
    Some([
        sp.checked_add(0x28)?,
        sp.checked_add(0x30)?,
        sp.checked_add(0x38)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(length: u16, maximum: u16, buffer: u64) -> [u8; 16] {
        let mut raw = [0; 16];
        raw[0..2].copy_from_slice(&length.to_le_bytes());
        raw[2..4].copy_from_slice(&maximum.to_le_bytes());
        raw[8..16].copy_from_slice(&buffer.to_le_bytes());
        raw
    }

    #[test]
    fn required_string_probes_empty_buffer_and_bounds_nonempty_input() {
        assert_eq!(
            required_unicode_string(&descriptor(0, 0, 0x1000), 0x200),
            Some(RequiredUnicodeString {
                buffer: 0x1000,
                length: 0,
                probe_length: 2
            })
        );
        assert_eq!(
            required_unicode_string(&descriptor(8, 10, 0x1000), 0x200),
            Some(RequiredUnicodeString {
                buffer: 0x1000,
                length: 8,
                probe_length: 8
            })
        );
        assert!(required_unicode_string(&descriptor(3, 4, 0x1000), 0x200).is_none());
        assert!(required_unicode_string(&descriptor(8, 6, 0x1000), 0x200).is_none());
        assert!(required_unicode_string(&descriptor(0x200, 0x200, 0x1000), 0x200).is_none());
        assert!(required_unicode_string(&descriptor(2, 2, 0), 0x200).is_none());
        assert!(required_unicode_string(&descriptor(2, 2, u64::MAX), 0x200).is_none());
    }

    #[test]
    fn stack_tail_rejects_null_and_wrapping_stack_pointers() {
        assert_eq!(
            three_stack_tail_addresses(0x1000),
            Some([0x1028, 0x1030, 0x1038])
        );
        assert_eq!(three_stack_tail_addresses(0), None);
        assert_eq!(three_stack_tail_addresses(u64::MAX - 0x30), None);
    }
}
