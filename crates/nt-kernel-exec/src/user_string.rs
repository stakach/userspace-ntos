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

/// Read-only object names use the counted bytes in `Length`. `MaximumLength` describes the
/// caller's buffer capacity and is not part of the input name captured by the object manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectNameInput {
    pub buffer: u64,
    pub length: usize,
}

pub fn object_name_input(raw: &[u8; 16]) -> Option<ObjectNameInput> {
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if length & 1 != 0
        || (length != 0 && buffer == 0)
        || buffer.checked_add(length as u64).is_none()
    {
        return None;
    }
    Some(ObjectNameInput { buffer, length })
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

/// Render an already-captured, counted UTF-16 string only when it ends in an ASCII suffix.
/// The suffix is checked against the complete input before any output is written. This keeps a
/// diagnostic receipt bounded without mistaking a truncated prefix for the whole message.
pub fn bounded_utf16_suffix_receipt(
    input: &[u8],
    suffix: &[u8],
    output: &mut [u8],
) -> Option<(usize, bool)> {
    if input.len() & 1 != 0 || suffix.is_empty() || suffix.len() > input.len() / 2 {
        return None;
    }
    let suffix_start = input.len() - suffix.len() * 2;
    for (index, expected) in suffix.iter().copied().enumerate() {
        if !expected.is_ascii() || input[suffix_start + index * 2] != expected
            || input[suffix_start + index * 2 + 1] != 0
        {
            return None;
        }
    }

    let chars = input.len() / 2;
    let written = chars.min(output.len());
    for index in 0..written {
        let value = u16::from_le_bytes([input[index * 2], input[index * 2 + 1]]);
        output[index] = match value {
            0x20..=0x7e => value as u8,
            0x09 | 0x0a | 0x0d => b' ',
            _ => b'?',
        };
    }
    Some((written, chars > output.len()))
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
    use alloc::vec::Vec;

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
    fn object_name_capture_uses_length_even_when_maximum_length_is_smaller() {
        assert_eq!(
            object_name_input(&descriptor(24, 0, 0x1000)),
            Some(ObjectNameInput {
                buffer: 0x1000,
                length: 24,
            })
        );
        assert!(object_name_input(&descriptor(3, 0, 0x1000)).is_none());
        assert!(object_name_input(&descriptor(24, 0, 0)).is_none());
        assert!(object_name_input(&descriptor(24, 0, u64::MAX - 8)).is_none());
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

    fn utf16_bytes(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn bounded_utf16_suffix_receipt_preserves_distinct_fatal_dialogs() {
        let cases = [
            (
                "SetupOpenInfFileW() failed to open 'syssetup.inf' (Error: 2)\n\nRebooting now!",
                "SetupOpenInfFileW() failed to open 'syssetup.inf' (Error: 2)  Rebooting now!",
            ),
            (
                "InstallSysSetupInfDevices() failed!\n\nRebooting now!",
                "InstallSysSetupInfDevices() failed!  Rebooting now!",
            ),
            (
                "InstallSysSetupInfComponents() failed!\n\nRebooting now!",
                "InstallSysSetupInfComponents() failed!  Rebooting now!",
            ),
            (
                "EnableUserModePnpManager() failed!\n\nRebooting now!",
                "EnableUserModePnpManager() failed!  Rebooting now!",
            ),
            (
                "CMP_WaitNoPendingInstallEvents() failed!\n\nRebooting now!",
                "CMP_WaitNoPendingInstallEvents() failed!  Rebooting now!",
            ),
        ];
        for (input, expected) in cases {
            let mut output = [0u8; 128];
            let (written, truncated) = bounded_utf16_suffix_receipt(
                &utf16_bytes(input),
                b"Rebooting now!",
                &mut output,
            )
            .expect("the complete fatal dialog suffix must be recognized");
            assert!(!truncated);
            assert_eq!(&output[..written], expected.as_bytes());
        }
    }

    #[test]
    fn bounded_utf16_suffix_receipt_checks_full_input_before_bounded_rendering() {
        let input = utf16_bytes("A long component failure with a diagnostic code\n\nRebooting now!");
        let mut output = [0u8; 12];
        assert_eq!(
            bounded_utf16_suffix_receipt(&input, b"Rebooting now!", &mut output),
            Some((12, true)),
        );
        assert_eq!(&output, b"A long compo");

        let mut unchanged = [0x5au8; 12];
        assert_eq!(
            bounded_utf16_suffix_receipt(
                &utf16_bytes("Failed to load LiveCD!"),
                b"Rebooting now!",
                &mut unchanged,
            ),
            None,
        );
        assert_eq!(unchanged, [0x5a; 12]);
        assert_eq!(
            bounded_utf16_suffix_receipt(&input[..input.len() - 1], b"Rebooting now!", &mut unchanged),
            None,
        );
    }
}
