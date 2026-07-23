//! Lossless validation and storage for the native `ACL` byte representation.

use alloc::vec::Vec;

const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 4;
const SID_HEADER_SIZE: usize = 8;
const ACL_REVISION: u8 = 2;
const ACL_REVISION_DS: u8 = 4;
const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;

const ACCESS_MAX_MS_V2_ACE_TYPE: u8 = 3;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
const ACE_OBJECT_TYPE_PRESENT: u32 = 1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 2;

pub const STATUS_INVALID_ACL: u32 = 0xC000_0077;

/// Why a native ACL byte sequence failed structural validation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NativeAclError {
    TruncatedHeader,
    InvalidRevision,
    InvalidAclSize,
    TruncatedAce,
    InvalidAceSize,
    InvalidSid,
    ObjectAceRequiresRevisionFour,
}

impl NativeAclError {
    pub const fn status(self) -> u32 {
        STATUS_INVALID_ACL
    }
}

/// A structurally valid native `ACL`, preserving every byte up to `AclSize`.
///
/// This is intentionally distinct from the semantic access-check [`crate::Acl`]. Token default
/// ACL queries and setters must retain revision, ACE flags, object GUIDs, and unused ACL space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAcl {
    bytes: Vec<u8>,
}

impl NativeAcl {
    /// Validate and capture the native ACL prefix identified by `AclSize`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeAclError> {
        if bytes.len() < ACL_HEADER_SIZE {
            return Err(NativeAclError::TruncatedHeader);
        }

        let revision = bytes[0];
        if !(ACL_REVISION..=ACL_REVISION_DS).contains(&revision) {
            return Err(NativeAclError::InvalidRevision);
        }

        let acl_size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        if acl_size < ACL_HEADER_SIZE || acl_size & 1 != 0 || acl_size > bytes.len() {
            return Err(NativeAclError::InvalidAclSize);
        }
        let bytes = &bytes[..acl_size];

        let ace_count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
        let mut offset = ACL_HEADER_SIZE;
        for _ in 0..ace_count {
            let header_end = offset
                .checked_add(ACE_HEADER_SIZE)
                .ok_or(NativeAclError::TruncatedAce)?;
            if header_end > acl_size {
                return Err(NativeAclError::TruncatedAce);
            }

            let ace_type = bytes[offset];
            let ace_size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            let ace_end = offset
                .checked_add(ace_size)
                .ok_or(NativeAclError::InvalidAceSize)?;
            if ace_size & 1 != 0 || ace_size < ACE_HEADER_SIZE || ace_end > acl_size {
                return Err(NativeAclError::InvalidAceSize);
            }

            if ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE {
                if ace_size & 3 != 0 || ace_size < 16 {
                    return Err(NativeAclError::InvalidAceSize);
                }
                validate_sid(&bytes[offset + 8..ace_end])?;
            } else if matches!(
                ace_type,
                ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE
            ) {
                if revision < ACL_REVISION_DS {
                    return Err(NativeAclError::ObjectAceRequiresRevisionFour);
                }
                if ace_size & 3 != 0 || ace_size < 16 {
                    return Err(NativeAclError::InvalidAceSize);
                }
                let flags = u32::from_le_bytes(
                    bytes[offset + 8..offset + 12]
                        .try_into()
                        .expect("object ACE flags are in bounds"),
                );
                let guid_bytes = usize::from(flags & ACE_OBJECT_TYPE_PRESENT != 0) * 16
                    + usize::from(flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0) * 16;
                let sid_offset = offset + 12 + guid_bytes;
                let Some(sid_header_end) = sid_offset.checked_add(SID_HEADER_SIZE) else {
                    return Err(NativeAclError::InvalidAceSize);
                };
                if sid_header_end > ace_end {
                    return Err(NativeAclError::InvalidAceSize);
                }
                validate_sid(&bytes[sid_offset..ace_end])?;
            }

            offset = ace_end;
        }

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Return the complete native ACL bytes, including unused trailing space.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the validated native `AclSize`.
    pub fn acl_size(&self) -> u16 {
        self.bytes.len() as u16
    }

    pub(crate) fn system_default() -> Self {
        // ACL header, LocalSystem GENERIC_ALL ACE, Administrators
        // GENERIC_READ | GENERIC_EXECUTE | READ_CONTROL ACE.
        let bytes = [
            2, 0, 52, 0, 2, 0, 0, 0, // ACL
            0, 0, 20, 0, 0, 0, 0, 16, // ACCESS_ALLOWED_ACE
            1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, // LocalSystem
            0, 0, 24, 0, 0, 0, 2, 160, // ACCESS_ALLOWED_ACE
            1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, // Administrators
        ];
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

fn validate_sid(bytes: &[u8]) -> Result<(), NativeAclError> {
    if bytes.len() < SID_HEADER_SIZE
        || bytes[0] != SID_REVISION
        || bytes[1] > SID_MAX_SUB_AUTHORITIES
    {
        return Err(NativeAclError::InvalidSid);
    }
    let sid_size = SID_HEADER_SIZE + bytes[1] as usize * 4;
    if sid_size > bytes.len() {
        return Err(NativeAclError::InvalidSid);
    }
    Ok(())
}
