//! `Rtl*` GUID formatting / parsing.
//!
//! `RtlGuidToString` renders a `GUID` as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` (braces,
//! lower-case); `RtlGUIDFromString` parses that back. The `GUID` in-memory layout is little-endian
//! `Data1`/`Data2`/`Data3` + a big-endian `Data4[8]` tail (the classic mixed-endian GUID).
//!
//! Category A. Host-tested against a known GUID.

use alloc::vec::Vec;

/// A Windows `GUID` (`{ ULONG Data1; USHORT Data2; USHORT Data3; UCHAR Data4[8]; }`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Guid {
    /// First 32-bit field.
    pub data1: u32,
    /// Second 16-bit field.
    pub data2: u16,
    /// Third 16-bit field.
    pub data3: u16,
    /// Trailing 8 bytes (rendered big-endian, split 2 + 6).
    pub data4: [u8; 8],
}

#[inline]
fn hex_nibble(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

#[inline]
fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn push_hex_u32(out: &mut Vec<u16>, v: u32, digits: usize) {
    for i in (0..digits).rev() {
        let nib = ((v >> (i * 4)) & 0xF) as u8;
        out.push(hex_nibble(nib) as u16);
    }
}

/// `RtlGuidToString`: render as `{8-4-4-4-12}`, lower-case hex, with braces. Returns UTF-16 units.
pub fn guid_to_string(g: &Guid) -> Vec<u16> {
    let mut out = Vec::with_capacity(38);
    out.push(b'{' as u16);
    push_hex_u32(&mut out, g.data1, 8);
    out.push(b'-' as u16);
    push_hex_u32(&mut out, g.data2 as u32, 4);
    out.push(b'-' as u16);
    push_hex_u32(&mut out, g.data3 as u32, 4);
    out.push(b'-' as u16);
    for (i, &b) in g.data4.iter().enumerate() {
        if i == 2 {
            out.push(b'-' as u16);
        }
        out.push(hex_nibble(b >> 4) as u16);
        out.push(hex_nibble(b & 0xF) as u16);
    }
    out.push(b'}' as u16);
    out
}

/// `RtlGUIDFromString`: parse `{8-4-4-4-12}` (braces optional). Returns `None` on any malformed
/// input.
pub fn guid_from_string(s: &[u16]) -> Option<Guid> {
    // Collect the hex nibbles, ignoring braces and dashes; require exactly 32 hex digits.
    let mut nibbles: Vec<u8> = Vec::with_capacity(32);
    for &u in s {
        if u > 0x7F {
            return None;
        }
        let c = u as u8;
        match c {
            b'{' | b'}' | b'-' => {}
            _ => nibbles.push(from_hex(c)?),
        }
    }
    if nibbles.len() != 32 {
        return None;
    }
    let byte = |i: usize| (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
    let data1 =
        ((byte(0) as u32) << 24) | ((byte(1) as u32) << 16) | ((byte(2) as u32) << 8) | byte(3) as u32;
    let data2 = ((byte(4) as u16) << 8) | byte(5) as u16;
    let data3 = ((byte(6) as u16) << 8) | byte(7) as u16;
    let mut data4 = [0u8; 8];
    for (i, slot) in data4.iter_mut().enumerate() {
        *slot = byte(8 + i);
    }
    Some(Guid {
        data1,
        data2,
        data3,
        data4,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn s(v: &[u16]) -> std::string::String {
        std::string::String::from_utf16(v).unwrap()
    }

    #[test]
    fn known_guid_roundtrip() {
        // {6BA7B810-9DAD-11D1-80B4-00C04FD430C8} (namespace DNS)
        let g = Guid {
            data1: 0x6BA7_B810,
            data2: 0x9DAD,
            data3: 0x11D1,
            data4: [0x80, 0xB4, 0x00, 0xC0, 0x4F, 0xD4, 0x30, 0xC8],
        };
        let txt = guid_to_string(&g);
        assert_eq!(s(&txt), "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}");
        let back = guid_from_string(&txt).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn parse_without_braces() {
        let g = guid_from_string(&"00000000-0000-0000-0000-000000000000".encode_utf16().collect::<Vec<_>>());
        assert_eq!(g, Some(Guid::default()));
    }

    #[test]
    fn reject_malformed() {
        assert!(guid_from_string(&"not-a-guid".encode_utf16().collect::<Vec<_>>()).is_none());
        assert!(guid_from_string(&"{6ba7b810}".encode_utf16().collect::<Vec<_>>()).is_none());
    }
}
