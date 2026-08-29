//! Security identifiers (spec §7.1) + the well-known SIDs.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

const SID_REVISION: u8 = 1;
const SID_HEADER_SIZE: usize = 8;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
pub const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

fn write_ascii_utf16(output: &mut [u16], cursor: &mut usize, value: &[u8]) -> Result<(), u32> {
    let end = cursor
        .checked_add(value.len())
        .ok_or(STATUS_BUFFER_TOO_SMALL)?;
    let target = output
        .get_mut(*cursor..end)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?;
    for (unit, byte) in target.iter_mut().zip(value) {
        *unit = *byte as u16;
    }
    *cursor = end;
    Ok(())
}

fn write_decimal_utf16(output: &mut [u16], cursor: &mut usize, mut value: u64) -> Result<(), u32> {
    let mut reversed = [0u8; 20];
    let mut length = 0usize;
    loop {
        reversed[length] = b'0' + (value % 10) as u8;
        length += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let end = cursor.checked_add(length).ok_or(STATUS_BUFFER_TOO_SMALL)?;
    let target = output
        .get_mut(*cursor..end)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?;
    for (index, unit) in target.iter_mut().enumerate() {
        *unit = reversed[length - index - 1] as u16;
    }
    *cursor = end;
    Ok(())
}

/// Format a native in-memory SID as SDDL UTF-16 without allocating.
///
/// Returns the number of code units written, excluding a terminator. The caller owns termination.
pub fn write_native_sid_sddl_utf16(bytes: &[u8], output: &mut [u16]) -> Result<usize, u32> {
    if bytes.len() < SID_HEADER_SIZE
        || bytes[0] != SID_REVISION
        || bytes[1] > SID_MAX_SUB_AUTHORITIES
    {
        return Err(STATUS_INVALID_SID);
    }
    let count = bytes[1] as usize;
    let sid_len = SID_HEADER_SIZE
        .checked_add(count.checked_mul(4).ok_or(STATUS_INVALID_SID)?)
        .ok_or(STATUS_INVALID_SID)?;
    if sid_len > bytes.len() {
        return Err(STATUS_INVALID_SID);
    }

    let mut cursor = 0usize;
    write_ascii_utf16(output, &mut cursor, b"S-")?;
    write_decimal_utf16(output, &mut cursor, bytes[0] as u64)?;
    write_ascii_utf16(output, &mut cursor, b"-")?;
    if bytes[2] == 0 && bytes[3] == 0 {
        let authority = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        write_decimal_utf16(output, &mut cursor, authority as u64)?;
    } else {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        write_ascii_utf16(output, &mut cursor, b"0x")?;
        for byte in &bytes[2..8] {
            write_ascii_utf16(
                output,
                &mut cursor,
                &[HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]],
            )?;
        }
    }
    for index in 0..count {
        let offset = SID_HEADER_SIZE + index * 4;
        let sub_authority = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        write_ascii_utf16(output, &mut cursor, b"-")?;
        write_decimal_utf16(output, &mut cursor, sub_authority as u64)?;
    }
    Ok(cursor)
}

/// A security identifier (spec §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Build a SID from an authority value + sub-authorities (`S-1-<auth>-<subs…>`).
    pub fn new(authority: u8, sub_authorities: &[u32]) -> Self {
        Sid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, authority],
            sub_authorities: sub_authorities.to_vec(),
        }
    }

    // Well-known SIDs (spec §7.1).
    pub fn null() -> Self {
        Sid::new(0, &[0])
    }
    /// `S-1-1-0` — Everyone / World.
    pub fn everyone() -> Self {
        Sid::new(1, &[0])
    }
    /// `S-1-3-0` — Creator Owner.
    pub fn creator_owner() -> Self {
        Sid::new(3, &[0])
    }
    /// `S-1-5-18` — LocalSystem.
    pub fn local_system() -> Self {
        Sid::new(5, &[18])
    }
    /// `S-1-5-19` — LocalService.
    pub fn local_service() -> Self {
        Sid::new(5, &[19])
    }
    /// `S-1-5-7` — Anonymous Logon.
    pub fn anonymous_logon() -> Self {
        Sid::new(5, &[7])
    }
    /// `S-1-5-10` — Principal Self, substituted by access-check-by-type callers.
    pub fn principal_self() -> Self {
        Sid::new(5, &[10])
    }
    pub(crate) fn is_principal_self(&self) -> bool {
        self.identifier_authority == [0, 0, 0, 0, 0, 5] && self.sub_authorities.as_slice() == [10]
    }
    /// `S-1-5-11` — Authenticated Users.
    pub fn authenticated_users() -> Self {
        Sid::new(5, &[11])
    }
    /// `S-1-5-32-544` — Builtin Administrators.
    pub fn administrators() -> Self {
        Sid::new(5, &[32, 544])
    }
    /// `S-1-5-32-545` — Builtin Users.
    pub fn users() -> Self {
        Sid::new(5, &[32, 545])
    }
    /// `S-1-5-21-<machine>-<rid>` — a local synthetic account (spec §7.1).
    pub fn local_account(machine: u32, rid: u32) -> Self {
        Sid::new(5, &[21, machine, rid])
    }

    /// Decode a native in-memory SID (`SID` header followed by little-endian sub-authorities).
    pub fn from_native_bytes(bytes: &[u8]) -> Result<Self, u32> {
        if bytes.len() < SID_HEADER_SIZE
            || bytes[0] != SID_REVISION
            || bytes[1] > SID_MAX_SUB_AUTHORITIES
        {
            return Err(STATUS_INVALID_SID);
        }
        let count = bytes[1] as usize;
        let sid_len = SID_HEADER_SIZE
            .checked_add(count.checked_mul(4).ok_or(STATUS_INVALID_SID)?)
            .ok_or(STATUS_INVALID_SID)?;
        if sid_len > bytes.len() {
            return Err(STATUS_INVALID_SID);
        }
        let mut sub_authorities = Vec::new();
        if sub_authorities.try_reserve_exact(count).is_err() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        for index in 0..count {
            let offset = SID_HEADER_SIZE + index * 4;
            sub_authorities.push(u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]));
        }
        Ok(Sid {
            revision: bytes[0],
            identifier_authority: bytes[2..8]
                .try_into()
                .expect("identifier authority slice is 6 bytes"),
            sub_authorities,
        })
    }

    /// SDDL string form (`S-1-5-32-544`, spec §18.4).
    pub fn to_sddl(&self) -> String {
        let authority = if self.identifier_authority[0] == 0 && self.identifier_authority[1] == 0 {
            let value = (self.identifier_authority[2] as u32) << 24
                | (self.identifier_authority[3] as u32) << 16
                | (self.identifier_authority[4] as u32) << 8
                | self.identifier_authority[5] as u32;
            format!("{value}")
        } else {
            let mut out = String::from("0x");
            for byte in self.identifier_authority {
                out.push_str(&format!("{byte:02x}"));
            }
            out
        };
        let mut s = format!("S-{}-{authority}", self.revision);
        for sub in &self.sub_authorities {
            s.push_str(&format!("-{sub}"));
        }
        s
    }

    /// Return the byte length of this SID in the native in-memory representation.
    pub fn native_len(&self) -> Option<usize> {
        if self.revision != 1 || self.sub_authorities.len() > 15 {
            return None;
        }
        self.sub_authorities
            .len()
            .checked_mul(4)
            .and_then(|length| length.checked_add(8))
    }

    /// Write this SID in the native in-memory representation.
    pub fn write_native(&self, output: &mut [u8]) -> Option<usize> {
        let length = self.native_len()?;
        let output = output.get_mut(..length)?;
        output[0] = self.revision;
        output[1] = self.sub_authorities.len() as u8;
        output[2..8].copy_from_slice(&self.identifier_authority);
        for (index, sub_authority) in self.sub_authorities.iter().enumerate() {
            let offset = 8 + index * 4;
            output[offset..offset + 4].copy_from_slice(&sub_authority.to_le_bytes());
        }
        Some(length)
    }
}

/// A LUID (locally-unique identifier, spec §7.4).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Luid {
    pub low: u32,
    pub high: i32,
}

impl Luid {
    pub fn new(low: u32) -> Self {
        Luid { low, high: 0 }
    }
}
