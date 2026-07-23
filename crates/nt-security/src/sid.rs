//! Security identifiers (spec §7.1) + the well-known SIDs.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

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

    /// SDDL string form (`S-1-5-32-544`, spec §18.4).
    pub fn to_sddl(&self) -> String {
        let authority = self.identifier_authority[5] as u64
            | (self.identifier_authority[4] as u64) << 8
            | (self.identifier_authority[3] as u64) << 16;
        let mut s = format!("S-{}-{}", self.revision, authority);
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
