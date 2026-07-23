//! `Rtl*` GUID formatting / parsing.
//!
//! `RtlGuidToString` renders a `GUID` as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` (braces,
//! lower-case); `RtlGUIDFromString` parses that back. The `GUID` in-memory layout is little-endian
//! `Data1`/`Data2`/`Data3` + a big-endian `Data4[8]` tail (the classic mixed-endian GUID).
//!
//! Category A. Host-tested against a known GUID.

use alloc::vec::Vec;

/// A Windows `GUID` (`{ ULONG Data1; USHORT Data2; USHORT Data3; UCHAR Data4[8]; }`).
#[repr(C)]
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

const _: () = assert!(core::mem::size_of::<Guid>() == 16);

impl Guid {
    /// Encode the native Windows in-memory representation.
    pub const fn to_windows_bytes(self) -> [u8; 16] {
        let data1 = self.data1.to_le_bytes();
        let data2 = self.data2.to_le_bytes();
        let data3 = self.data3.to_le_bytes();
        [
            data1[0],
            data1[1],
            data1[2],
            data1[3],
            data2[0],
            data2[1],
            data3[0],
            data3[1],
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        ]
    }

    /// Decode the native Windows in-memory representation.
    pub const fn from_windows_bytes(bytes: [u8; 16]) -> Self {
        Self {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ],
        }
    }
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

/// `RtlGUIDFromString`: parse the exact native `{8-4-4-4-12}` syntax.
pub fn guid_from_string(s: &[u16]) -> Option<Guid> {
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
    let data1 = ((byte(0) as u32) << 24)
        | ((byte(1) as u32) << 16)
        | ((byte(2) as u32) << 8)
        | byte(3) as u32;
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
    fn native_byte_layout_roundtrips() {
        let guid = Guid {
            data1: 0x1122_3344,
            data2: 0x5566,
            data3: 0x7788,
            data4: [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10],
        };
        let bytes = [
            0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x10,
        ];
        assert_eq!(guid.to_windows_bytes(), bytes);
        assert_eq!(Guid::from_windows_bytes(bytes), guid);
    }

    #[test]
    fn parser_requires_exact_native_syntax() {
        let upper = "{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}"
            .encode_utf16()
            .collect::<Vec<_>>();
        assert!(guid_from_string(&upper).is_some());
        for malformed in [
            "not-a-guid",
            "{6ba7b810}",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "{6ba7b8109-dad-11d1-80b4-00c04fd430c8}",
            "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}x",
            "{6ba7b810-9dad-11d1-80b4-00c04fd430cg}",
        ] {
            assert!(
                guid_from_string(&malformed.encode_utf16().collect::<Vec<_>>()).is_none(),
                "accepted malformed GUID: {malformed}"
            );
        }
    }
}
