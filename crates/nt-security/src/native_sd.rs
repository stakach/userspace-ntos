//! Native `SECURITY_DESCRIPTOR` capture for access checks.
//!
//! The executive reads user buffers through [`crate::ClientMemory`]; host tests plug in a byte-map.
//! This module captures both absolute x64 descriptors and self-relative descriptors, then converts
//! native ACL bytes into the semantic [`crate::Acl`] shape used by [`crate::access_check`].

use alloc::vec::Vec;

use crate::access::{Ace, AceType, Acl, SecurityDescriptor};
use crate::create_token::{
    capture_acl, capture_sid, ClientMemory, STATUS_ACCESS_VIOLATION, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_SID,
};
use crate::native_acl::{NativeAcl, STATUS_INVALID_ACL};
use crate::sid::Sid;

pub const STATUS_UNKNOWN_REVISION: u32 = 0xC000_0058;
pub const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;

const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
const SECURITY_DESCRIPTOR_RELATIVE_SIZE: usize = 20;
const SECURITY_DESCRIPTOR_ABSOLUTE_X64_SIZE: usize = 40;

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;

const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 4;
const SID_HEADER_SIZE: usize = 8;
const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
const INHERIT_ONLY_ACE: u8 = 0x08;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x0000_0001;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x0000_0002;

/// Capture a caller-supplied native `SECURITY_DESCRIPTOR`.
///
/// A self-relative descriptor stores 32-bit offsets from the descriptor base. An absolute x64
/// descriptor stores four pointers at offsets 8, 16, 24, and 32. The returned descriptor keeps only
/// the access-check semantics currently modelled by the crate: owner, group, DACL, and SACL ACEs.
pub fn capture_security_descriptor(
    memory: &dyn ClientMemory,
    va: u64,
) -> Result<SecurityDescriptor, u32> {
    if va == 0 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }

    let mut relative_header = [0u8; SECURITY_DESCRIPTOR_RELATIVE_SIZE];
    if !memory.read(va, &mut relative_header) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if relative_header[0] != SECURITY_DESCRIPTOR_REVISION {
        return Err(STATUS_UNKNOWN_REVISION);
    }

    let control = read_u16(&relative_header, 2);
    let (owner_va, group_va, sacl_va, dacl_va) = if control & SE_SELF_RELATIVE != 0 {
        (
            relative_target(va, read_u32(&relative_header, 4))?,
            relative_target(va, read_u32(&relative_header, 8))?,
            relative_target(va, read_u32(&relative_header, 12))?,
            relative_target(va, read_u32(&relative_header, 16))?,
        )
    } else {
        let mut absolute = [0u8; SECURITY_DESCRIPTOR_ABSOLUTE_X64_SIZE];
        if !memory.read(va, &mut absolute) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        (
            non_null(read_u64(&absolute, 8)),
            non_null(read_u64(&absolute, 16)),
            non_null(read_u64(&absolute, 24)),
            non_null(read_u64(&absolute, 32)),
        )
    };

    let owner = match owner_va {
        Some(owner_va) => Some(capture_sid(memory, owner_va)?),
        None => None,
    };
    let group = match group_va {
        Some(group_va) => Some(capture_sid(memory, group_va)?),
        None => None,
    };
    let sacl = if control & SE_SACL_PRESENT != 0 {
        match sacl_va {
            Some(sacl_va) => Some(capture_access_acl(memory, sacl_va)?),
            None => None,
        }
    } else {
        None
    };
    let dacl = if control & SE_DACL_PRESENT != 0 {
        match dacl_va {
            Some(dacl_va) => Some(capture_access_acl(memory, dacl_va)?),
            None => None,
        }
    } else {
        None
    };

    Ok(SecurityDescriptor {
        owner,
        group,
        dacl,
        sacl,
    })
}

/// Convert a validated native ACL into the semantic ACE list used by the access-check engine.
///
/// Access-allowed, access-denied, and audit ACEs are represented directly. Object allow/deny ACEs
/// contribute their mask and SID to the whole-object check; their GUID fields are skipped until the
/// by-type access-check APIs model object-type lists. Unknown/callback ACEs are preserved by
/// [`NativeAcl`] for token queries but ignored by this semantic evaluator.
pub fn native_acl_to_acl(native: &NativeAcl) -> Result<Acl, u32> {
    let bytes = native.as_bytes();
    if bytes.len() < ACL_HEADER_SIZE {
        return Err(STATUS_INVALID_ACL);
    }
    let ace_count = read_u16(bytes, 4) as usize;
    let mut aces = Vec::new();
    if aces.try_reserve_exact(ace_count).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }

    let mut offset = ACL_HEADER_SIZE;
    for _ in 0..ace_count {
        let header_end = offset
            .checked_add(ACE_HEADER_SIZE)
            .ok_or(STATUS_INVALID_ACL)?;
        if header_end > bytes.len() {
            return Err(STATUS_INVALID_ACL);
        }
        let ace_type = bytes[offset];
        let ace_flags = bytes[offset + 1];
        let ace_size = read_u16(bytes, offset + 2) as usize;
        let ace_end = offset.checked_add(ace_size).ok_or(STATUS_INVALID_ACL)?;
        if ace_end > bytes.len() {
            return Err(STATUS_INVALID_ACL);
        }

        if let Some((semantic_type, sid_offset)) = semantic_ace(ace_type, bytes, offset, ace_end)? {
            let mask = read_u32(bytes, offset + 4);
            aces.push(Ace {
                ace_type: semantic_type,
                mask,
                sid: sid_from_native_bytes(&bytes[sid_offset..ace_end])?,
                inherit_only: ace_flags & INHERIT_ONLY_ACE != 0,
            });
        }

        offset = ace_end;
    }

    Ok(Acl::new(aces))
}

fn capture_access_acl(memory: &dyn ClientMemory, va: u64) -> Result<Acl, u32> {
    let native = capture_acl(memory, va)?;
    native_acl_to_acl(&native)
}

fn semantic_ace(
    ace_type: u8,
    bytes: &[u8],
    offset: usize,
    ace_end: usize,
) -> Result<Option<(AceType, usize)>, u32> {
    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE => Ok(Some((AceType::AccessAllowed, offset + 8))),
        ACCESS_DENIED_ACE_TYPE => Ok(Some((AceType::AccessDenied, offset + 8))),
        SYSTEM_AUDIT_ACE_TYPE => Ok(Some((AceType::SystemAudit, offset + 8))),
        ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE => {
            let flags = read_u32(bytes, offset + 8);
            let guid_bytes = usize::from(flags & ACE_OBJECT_TYPE_PRESENT != 0) * 16
                + usize::from(flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0) * 16;
            let sid_offset = offset
                .checked_add(12)
                .and_then(|base| base.checked_add(guid_bytes))
                .ok_or(STATUS_INVALID_ACL)?;
            if sid_offset
                .checked_add(SID_HEADER_SIZE)
                .is_none_or(|end| end > ace_end)
            {
                return Err(STATUS_INVALID_ACL);
            }
            let semantic_type = if ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE {
                AceType::AccessAllowed
            } else {
                AceType::AccessDenied
            };
            Ok(Some((semantic_type, sid_offset)))
        }
        _ => Ok(None),
    }
}

fn sid_from_native_bytes(bytes: &[u8]) -> Result<Sid, u32> {
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
        sub_authorities.push(read_u32(bytes, offset));
    }
    Ok(Sid {
        revision: bytes[0],
        identifier_authority: bytes[2..8]
            .try_into()
            .expect("identifier authority slice is 6 bytes"),
        sub_authorities,
    })
}

fn relative_target(base: u64, offset: u32) -> Result<Option<u64>, u32> {
    if offset == 0 {
        return Ok(None);
    }
    base.checked_add(offset as u64)
        .map(Some)
        .ok_or(STATUS_ACCESS_VIOLATION)
}

fn non_null(pointer: u64) -> Option<u64> {
    if pointer == 0 {
        None
    } else {
        Some(pointer)
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("u16 field is in bounds"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("u32 field is in bounds"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("u64 field is in bounds"),
    )
}
