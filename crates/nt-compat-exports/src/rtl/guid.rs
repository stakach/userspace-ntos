//! Allocation-free parsing of the native `RtlGUIDFromString` UTF-16 syntax.

/// Parse `{8-4-4-4-12}` into the 16-byte Windows `GUID` memory representation.
///
/// The first three fields are stored little-endian; the final eight bytes keep
/// their textual order. Both uppercase and lowercase hexadecimal are accepted.
pub fn guid_from_string(s: &[u16]) -> Option<[u8; 16]> {
    if s.len() != 38
        || s[0] != b'{' as u16
        || s[9] != b'-' as u16
        || s[14] != b'-' as u16
        || s[19] != b'-' as u16
        || s[24] != b'-' as u16
        || s[37] != b'}' as u16
    {
        return None;
    }
    let mut nibbles = [0u8; 32];
    let mut count = 0usize;
    for (index, &unit) in s.iter().enumerate() {
        if matches!(index, 0 | 9 | 14 | 19 | 24 | 37) {
            continue;
        }
        if unit > 0x7f || count == nibbles.len() {
            return None;
        }
        nibbles[count] = from_hex(unit as u8)?;
        count += 1;
    }
    let byte = |i: usize| (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
    let data1 = u32::from_be_bytes([byte(0), byte(1), byte(2), byte(3)]).to_le_bytes();
    let data2 = u16::from_be_bytes([byte(4), byte(5)]).to_le_bytes();
    let data3 = u16::from_be_bytes([byte(6), byte(7)]).to_le_bytes();
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&data1);
    bytes[4..6].copy_from_slice(&data2);
    bytes[6..8].copy_from_slice(&data3);
    for (i, slot) in bytes[8..].iter_mut().enumerate() {
        *slot = byte(8 + i);
    }
    Some(bytes)
}

fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_endian_windows_guid_bytes() {
        let guid: alloc::vec::Vec<_> = "{11223344-5566-7788-99AA-bbccddeeff10}"
            .encode_utf16()
            .collect();
        assert_eq!(
            guid_from_string(&guid),
            Some([
                0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x10,
            ])
        );
    }

    #[test]
    fn rejects_wrong_shape_non_ascii_and_non_hex() {
        for value in [
            "11223344-5566-7788-99aa-bbccddeeff10",
            "{11223344-5566-7788-99aa-bbccddeeff10}x",
            "{11223344-5566-7788-99aa-bbccddeeff1g}",
            "{11223344_5566-7788-99aa-bbccddeeff10}",
            "{11223344-5566-7788-99aa-bbccddeeff１0}",
        ] {
            let utf16: alloc::vec::Vec<_> = value.encode_utf16().collect();
            assert_eq!(guid_from_string(&utf16), None, "accepted {value}");
        }
    }
}
