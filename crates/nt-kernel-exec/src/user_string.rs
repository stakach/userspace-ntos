//! Bounded USER syscall string and stack argument validation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredUnicodeString {
    pub buffer: u64,
    pub length: usize,
    pub probe_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargeStringInput {
    pub buffer: u64,
    pub length: u64,
    pub maximum: u64,
    pub ansi: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeStringInput {
    pub buffer: u64,
    pub length: u64,
    pub maximum: u64,
}

pub fn unicode_string_input(raw: &[u8; 16], capture_cap: u64) -> Option<UnicodeStringInput> {
    let length = u16::from_le_bytes([raw[0], raw[1]]) as u64;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as u64;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if length & 1 != 0
        || maximum < length
        || length.checked_add(2)? > capture_cap
        || (length != 0 && buffer == 0)
        || buffer.checked_add(length).is_none()
    {
        return None;
    }
    Some(UnicodeStringInput {
        buffer,
        length,
        maximum,
    })
}

pub fn large_string_input(raw: &[u8; 16], capture_cap: u64) -> Option<LargeStringInput> {
    let length = u32::from_le_bytes(raw[0..4].try_into().ok()?) as u64;
    let maximum_and_ansi = u32::from_le_bytes(raw[4..8].try_into().ok()?);
    let maximum = (maximum_and_ansi & 0x7fff_ffff) as u64;
    let ansi = maximum_and_ansi & 0x8000_0000 != 0;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    let terminator = if ansi { 1 } else { 2 };
    if (!ansi && length & 1 != 0)
        || maximum < length
        || length.checked_add(terminator)? > capture_cap
        || (length != 0 && buffer == 0)
        || buffer.checked_add(length).is_none()
    {
        return None;
    }
    Some(LargeStringInput {
        buffer,
        length,
        maximum,
        ansi,
    })
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

pub fn four_stack_tail_addresses(sp: u64) -> Option<[u64; 4]> {
    let [first, second, third] = three_stack_tail_addresses(sp)?;
    Some([first, second, third, sp.checked_add(0x40)?])
}

pub fn capture_stack_tail<const N: usize>(
    addresses: [u64; N],
    mut read: impl FnMut(u64) -> Option<u64>,
) -> Option<[u64; N]> {
    let mut tail = [0u64; N];
    for (index, address) in addresses.into_iter().enumerate() {
        tail[index] = read(address)?;
    }
    Some(tail)
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

    fn large_descriptor(length: u32, maximum: u32, ansi: bool, buffer: u64) -> [u8; 16] {
        let mut raw = [0; 16];
        raw[0..4].copy_from_slice(&length.to_le_bytes());
        raw[4..8].copy_from_slice(&(maximum | if ansi { 0x8000_0000 } else { 0 }).to_le_bytes());
        raw[8..16].copy_from_slice(&buffer.to_le_bytes());
        raw
    }

    #[test]
    fn large_string_accepts_bounded_ansi_unicode_and_empty_inputs() {
        assert_eq!(
            large_string_input(&large_descriptor(3, 3, true, 0x1000), 0x200),
            Some(LargeStringInput {
                buffer: 0x1000,
                length: 3,
                maximum: 3,
                ansi: true
            })
        );
        assert_eq!(
            large_string_input(&large_descriptor(0x1fe, 0x1fe, false, 0x1000), 0x200),
            Some(LargeStringInput {
                buffer: 0x1000,
                length: 0x1fe,
                maximum: 0x1fe,
                ansi: false
            })
        );
        assert!(large_string_input(&large_descriptor(0, 0, false, 0), 0x200).is_some());
        assert!(large_string_input(&large_descriptor(3, 3, false, 0x1000), 0x200).is_none());
        assert!(large_string_input(&large_descriptor(4, 2, false, 0x1000), 0x200).is_none());
        assert!(
            large_string_input(&large_descriptor(0x200, 0x200, false, 0x1000), 0x200).is_none()
        );
        assert!(large_string_input(&large_descriptor(2, 2, false, u64::MAX), 0x200).is_none());
    }

    #[test]
    fn unicode_string_covers_reactos_wallpaper_limit_without_truncation() {
        assert_eq!(
            unicode_string_input(&descriptor(520, 520, 0x1000), 0x220),
            Some(UnicodeStringInput {
                buffer: 0x1000,
                length: 520,
                maximum: 520
            })
        );
        assert!(unicode_string_input(&descriptor(520, 520, 0x1000), 0x200).is_none());
        assert!(unicode_string_input(&descriptor(522, 522, 0x1000), 0x220).is_some());
        assert!(unicode_string_input(&descriptor(3, 4, 0x1000), 0x220).is_none());
        assert!(unicode_string_input(&descriptor(4, 2, 0x1000), 0x220).is_none());
        assert!(unicode_string_input(&descriptor(4, 4, u64::MAX), 0x220).is_none());
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
        assert_eq!(
            four_stack_tail_addresses(0x1000),
            Some([0x1028, 0x1030, 0x1038, 0x1040])
        );
        assert_eq!(four_stack_tail_addresses(0), None);
        assert_eq!(four_stack_tail_addresses(u64::MAX - 0x38), None);
    }

    #[test]
    fn stack_tail_stops_at_first_unreadable_word() {
        let addresses = three_stack_tail_addresses(0x1000).unwrap();
        let mut reads = 0;
        assert_eq!(
            capture_stack_tail(addresses, |address| {
                reads += 1;
                (address != 0x1030).then_some(address)
            }),
            None
        );
        assert_eq!(reads, 2);
        assert_eq!(capture_stack_tail(addresses, Some), Some(addresses));
    }
}
