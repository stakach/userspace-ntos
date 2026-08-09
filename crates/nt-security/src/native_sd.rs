//! Native `SECURITY_DESCRIPTOR` capture for access checks.
//!
//! The executive reads user buffers through [`crate::ClientMemory`]; host tests plug in a byte-map.
//! This module captures both absolute x64 descriptors and self-relative descriptors, then converts
//! native ACL bytes into the semantic [`crate::Acl`] shape used by [`crate::access_check`].

use alloc::vec::Vec;

use crate::access::{Ace, AceType, Acl, SecurityDescriptor};
use crate::create_token::{
    capture_acl, capture_sid, ClientMemory, STATUS_ACCESS_VIOLATION, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER,
};
use crate::native_acl::{NativeAcl, STATUS_INVALID_ACL};
use crate::sid::Sid;

pub const STATUS_UNKNOWN_REVISION: u32 = 0xC000_0058;
pub const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;

const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
const SECURITY_DESCRIPTOR_RELATIVE_SIZE: usize = 20;
const SECURITY_DESCRIPTOR_ABSOLUTE_X64_SIZE: usize = 40;

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_DEFAULTED: u16 = 0x0008;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SACL_DEFAULTED: u16 = 0x0020;
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SACL_PROTECTED: u16 = 0x2000;
const SE_SELF_RELATIVE: u16 = 0x8000;

pub const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
pub const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
pub const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
pub const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
pub const PROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x4000_0000;
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
pub const UNPROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x1000_0000;

const QUERY_SECURITY_INFORMATION_MASK: u32 = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | SACL_SECURITY_INFORMATION;
const SET_SECURITY_INFORMATION_MASK: u32 = QUERY_SECURITY_INFORMATION_MASK
    | PROTECTED_DACL_SECURITY_INFORMATION
    | PROTECTED_SACL_SECURITY_INFORMATION
    | UNPROTECTED_DACL_SECURITY_INFORMATION
    | UNPROTECTED_SACL_SECURITY_INFORMATION;

pub const DEFAULT_KEY_SECURITY_DESCRIPTOR: [u8; SECURITY_DESCRIPTOR_RELATIVE_SIZE] = [
    SECURITY_DESCRIPTOR_REVISION,
    0,
    0,
    0x80,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 4;
const SID_HEADER_SIZE: usize = 8;
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

/// Capture a caller-supplied native `SECURITY_DESCRIPTOR` into a validated self-relative byte
/// descriptor. Absolute x64 descriptors are normalized by copying their owner/group/SACL/DACL
/// components into one packed self-relative descriptor.
pub fn capture_security_descriptor_bytes(
    memory: &dyn ClientMemory,
    va: u64,
) -> Result<Vec<u8>, u32> {
    capture_security_descriptor(memory, va)?;

    let mut relative_header = [0u8; SECURITY_DESCRIPTOR_RELATIVE_SIZE];
    if !memory.read(va, &mut relative_header) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if relative_header[0] != SECURITY_DESCRIPTOR_REVISION {
        return Err(STATUS_UNKNOWN_REVISION);
    }

    let control = read_u16(&relative_header, 2);
    if control & SE_SELF_RELATIVE != 0 {
        let mut total = SECURITY_DESCRIPTOR_RELATIVE_SIZE;
        for offset in [read_u32(&relative_header, 4), read_u32(&relative_header, 8)] {
            if offset != 0 {
                let component_va = va
                    .checked_add(offset as u64)
                    .ok_or(STATUS_ACCESS_VIOLATION)?;
                total = total.max(
                    (offset as usize)
                        .checked_add(memory_sid_len(memory, component_va)?)
                        .ok_or(STATUS_INVALID_SECURITY_DESCR)?,
                );
            }
        }
        for (present, offset) in [
            (
                control & SE_SACL_PRESENT != 0,
                read_u32(&relative_header, 12),
            ),
            (
                control & SE_DACL_PRESENT != 0,
                read_u32(&relative_header, 16),
            ),
        ] {
            if !present && offset != 0 {
                return Err(STATUS_INVALID_SECURITY_DESCR);
            }
            if present && offset != 0 {
                let component_va = va
                    .checked_add(offset as u64)
                    .ok_or(STATUS_ACCESS_VIOLATION)?;
                total = total.max(
                    (offset as usize)
                        .checked_add(memory_acl_len(memory, component_va)?)
                        .ok_or(STATUS_INVALID_SECURITY_DESCR)?,
                );
            }
        }
        let mut out = Vec::new();
        out.try_reserve_exact(total)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        out.resize(total, 0);
        if !memory.read(va, &mut out) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        parse_self_relative_descriptor(&out)?;
        return Ok(out);
    }

    let mut absolute = [0u8; SECURITY_DESCRIPTOR_ABSOLUTE_X64_SIZE];
    if !memory.read(va, &mut absolute) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let owner = read_optional_sid(memory, read_u64(&absolute, 8))?;
    let group = read_optional_sid(memory, read_u64(&absolute, 16))?;
    let sacl = if control & SE_SACL_PRESENT != 0 {
        Some(read_optional_acl(memory, read_u64(&absolute, 24))?)
    } else {
        None
    };
    let dacl = if control & SE_DACL_PRESENT != 0 {
        Some(read_optional_acl(memory, read_u64(&absolute, 32))?)
    } else {
        None
    };
    build_self_relative_descriptor(DescriptorBuild {
        owner: owner.as_deref(),
        group: group.as_deref(),
        sacl_present: control & SE_SACL_PRESENT != 0,
        sacl: sacl.as_ref().and_then(|s| s.as_deref()),
        dacl_present: control & SE_DACL_PRESENT != 0,
        dacl: dacl.as_ref().and_then(|d| d.as_deref()),
        control: control & !SE_SELF_RELATIVE,
    })
}

/// Build the self-relative descriptor visible to `NtQuerySecurityObject` for the requested
/// `SECURITY_INFORMATION` components.
pub fn query_security_descriptor_bytes(
    object_descriptor: &[u8],
    security_information: u32,
) -> Result<Vec<u8>, u32> {
    if security_information & !QUERY_SECURITY_INFORMATION_MASK != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let current = parse_self_relative_descriptor(object_descriptor)?;
    build_self_relative_descriptor(DescriptorBuild {
        owner: (security_information & OWNER_SECURITY_INFORMATION != 0)
            .then_some(current.owner)
            .flatten(),
        group: (security_information & GROUP_SECURITY_INFORMATION != 0)
            .then_some(current.group)
            .flatten(),
        sacl_present: security_information & SACL_SECURITY_INFORMATION != 0 && current.sacl_present,
        sacl: (security_information & SACL_SECURITY_INFORMATION != 0)
            .then_some(current.sacl)
            .flatten(),
        dacl_present: security_information & DACL_SECURITY_INFORMATION != 0 && current.dacl_present,
        dacl: (security_information & DACL_SECURITY_INFORMATION != 0)
            .then_some(current.dacl)
            .flatten(),
        control: selected_query_control(security_information, current.control),
    })
}

/// Apply the selected `SECURITY_INFORMATION` components from `modification_descriptor` onto
/// `object_descriptor`, returning the updated self-relative descriptor bytes.
pub fn set_security_descriptor_bytes(
    object_descriptor: &[u8],
    security_information: u32,
    modification_descriptor: &[u8],
) -> Result<Vec<u8>, u32> {
    if security_information & !SET_SECURITY_INFORMATION_MASK != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if security_information & PROTECTED_DACL_SECURITY_INFORMATION != 0
        && security_information & UNPROTECTED_DACL_SECURITY_INFORMATION != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if security_information & PROTECTED_SACL_SECURITY_INFORMATION != 0
        && security_information & UNPROTECTED_SACL_SECURITY_INFORMATION != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let current = parse_self_relative_descriptor(object_descriptor)?;
    let modification = parse_self_relative_descriptor(modification_descriptor)?;
    let mut control =
        merge_control_bits(security_information, current.control, modification.control);

    let use_owner = security_information & OWNER_SECURITY_INFORMATION != 0;
    let use_group = security_information & GROUP_SECURITY_INFORMATION != 0;
    let use_sacl = security_information & SACL_SECURITY_INFORMATION != 0;
    let use_dacl = security_information & DACL_SECURITY_INFORMATION != 0;

    let sacl_present = if use_sacl {
        modification.sacl_present
    } else {
        current.sacl_present
    };
    let dacl_present = if use_dacl {
        modification.dacl_present
    } else {
        current.dacl_present
    };
    if sacl_present {
        control |= SE_SACL_PRESENT;
    } else {
        control &= !(SE_SACL_PRESENT | SE_SACL_DEFAULTED);
    }
    if dacl_present {
        control |= SE_DACL_PRESENT;
    } else {
        control &= !(SE_DACL_PRESENT | SE_DACL_DEFAULTED);
    }

    build_self_relative_descriptor(DescriptorBuild {
        owner: if use_owner {
            modification.owner
        } else {
            current.owner
        },
        group: if use_group {
            modification.group
        } else {
            current.group
        },
        sacl_present,
        sacl: if use_sacl {
            modification.sacl
        } else {
            current.sacl
        },
        dacl_present,
        dacl: if use_dacl {
            modification.dacl
        } else {
            current.dacl
        },
        control,
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
                sid: Sid::from_native_bytes(&bytes[sid_offset..ace_end])?,
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

struct ParsedDescriptor<'a> {
    control: u16,
    owner: Option<&'a [u8]>,
    group: Option<&'a [u8]>,
    sacl_present: bool,
    sacl: Option<&'a [u8]>,
    dacl_present: bool,
    dacl: Option<&'a [u8]>,
}

struct DescriptorBuild<'a> {
    owner: Option<&'a [u8]>,
    group: Option<&'a [u8]>,
    sacl_present: bool,
    sacl: Option<&'a [u8]>,
    dacl_present: bool,
    dacl: Option<&'a [u8]>,
    control: u16,
}

fn parse_self_relative_descriptor(bytes: &[u8]) -> Result<ParsedDescriptor<'_>, u32> {
    if bytes.len() < SECURITY_DESCRIPTOR_RELATIVE_SIZE {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    if bytes[0] != SECURITY_DESCRIPTOR_REVISION {
        return Err(STATUS_UNKNOWN_REVISION);
    }
    let control = read_u16(bytes, 2);
    if control & SE_SELF_RELATIVE == 0 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    let owner = component_sid(bytes, read_u32(bytes, 4))?;
    let group = component_sid(bytes, read_u32(bytes, 8))?;
    let sacl_present = control & SE_SACL_PRESENT != 0;
    let dacl_present = control & SE_DACL_PRESENT != 0;
    let sacl_offset = read_u32(bytes, 12);
    let dacl_offset = read_u32(bytes, 16);
    if !sacl_present && sacl_offset != 0 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    if !dacl_present && dacl_offset != 0 {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    let sacl = if sacl_present {
        component_acl(bytes, sacl_offset)?
    } else {
        None
    };
    let dacl = if dacl_present {
        component_acl(bytes, dacl_offset)?
    } else {
        None
    };
    Ok(ParsedDescriptor {
        control,
        owner,
        group,
        sacl_present,
        sacl,
        dacl_present,
        dacl,
    })
}

fn build_self_relative_descriptor(parts: DescriptorBuild<'_>) -> Result<Vec<u8>, u32> {
    validate_component_slices(parts.owner, parts.group, parts.sacl, parts.dacl)?;

    let mut total = SECURITY_DESCRIPTOR_RELATIVE_SIZE;
    for component in [parts.sacl, parts.dacl, parts.owner, parts.group]
        .into_iter()
        .flatten()
    {
        total = round_up4(total)
            .checked_add(component.len())
            .ok_or(STATUS_INVALID_SECURITY_DESCR)?;
    }
    let mut out = Vec::new();
    out.try_reserve_exact(total)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    out.resize(total, 0);
    out[0] = SECURITY_DESCRIPTOR_REVISION;
    let mut control = (parts.control
        & (SE_DACL_PRESENT
            | SE_DACL_DEFAULTED
            | SE_SACL_PRESENT
            | SE_SACL_DEFAULTED
            | SE_DACL_AUTO_INHERIT_REQ
            | SE_SACL_AUTO_INHERIT_REQ
            | SE_DACL_AUTO_INHERITED
            | SE_SACL_AUTO_INHERITED
            | SE_DACL_PROTECTED
            | SE_SACL_PROTECTED))
        | SE_SELF_RELATIVE;
    if parts.sacl_present {
        control |= SE_SACL_PRESENT;
    } else {
        control &= !(SE_SACL_PRESENT | SE_SACL_DEFAULTED);
    }
    if parts.dacl_present {
        control |= SE_DACL_PRESENT;
    } else {
        control &= !(SE_DACL_PRESENT | SE_DACL_DEFAULTED);
    }
    out[2..4].copy_from_slice(&control.to_le_bytes());

    let mut cursor = SECURITY_DESCRIPTOR_RELATIVE_SIZE;
    write_component(&mut out, &mut cursor, 12, parts.sacl)?;
    write_component(&mut out, &mut cursor, 16, parts.dacl)?;
    write_component(&mut out, &mut cursor, 4, parts.owner)?;
    write_component(&mut out, &mut cursor, 8, parts.group)?;
    Ok(out)
}

fn selected_query_control(security_information: u32, control: u16) -> u16 {
    let mut out = 0;
    if security_information & DACL_SECURITY_INFORMATION != 0 {
        out |= control
            & (SE_DACL_PRESENT
                | SE_DACL_DEFAULTED
                | SE_DACL_AUTO_INHERIT_REQ
                | SE_DACL_AUTO_INHERITED
                | SE_DACL_PROTECTED);
    }
    if security_information & SACL_SECURITY_INFORMATION != 0 {
        out |= control
            & (SE_SACL_PRESENT
                | SE_SACL_DEFAULTED
                | SE_SACL_AUTO_INHERIT_REQ
                | SE_SACL_AUTO_INHERITED
                | SE_SACL_PROTECTED);
    }
    out
}

fn merge_control_bits(security_information: u32, current: u16, modification: u16) -> u16 {
    let mut control = current;
    if security_information & DACL_SECURITY_INFORMATION != 0 {
        control &= !(SE_DACL_PRESENT
            | SE_DACL_DEFAULTED
            | SE_DACL_AUTO_INHERIT_REQ
            | SE_DACL_AUTO_INHERITED
            | SE_DACL_PROTECTED);
        control |= modification
            & (SE_DACL_PRESENT
                | SE_DACL_DEFAULTED
                | SE_DACL_AUTO_INHERIT_REQ
                | SE_DACL_AUTO_INHERITED
                | SE_DACL_PROTECTED);
    }
    if security_information & SACL_SECURITY_INFORMATION != 0 {
        control &= !(SE_SACL_PRESENT
            | SE_SACL_DEFAULTED
            | SE_SACL_AUTO_INHERIT_REQ
            | SE_SACL_AUTO_INHERITED
            | SE_SACL_PROTECTED);
        control |= modification
            & (SE_SACL_PRESENT
                | SE_SACL_DEFAULTED
                | SE_SACL_AUTO_INHERIT_REQ
                | SE_SACL_AUTO_INHERITED
                | SE_SACL_PROTECTED);
    }
    if security_information & PROTECTED_DACL_SECURITY_INFORMATION != 0 {
        control |= SE_DACL_PROTECTED;
    }
    if security_information & UNPROTECTED_DACL_SECURITY_INFORMATION != 0 {
        control &= !SE_DACL_PROTECTED;
    }
    if security_information & PROTECTED_SACL_SECURITY_INFORMATION != 0 {
        control |= SE_SACL_PROTECTED;
    }
    if security_information & UNPROTECTED_SACL_SECURITY_INFORMATION != 0 {
        control &= !SE_SACL_PROTECTED;
    }
    control
}

fn write_component(
    out: &mut [u8],
    cursor: &mut usize,
    offset_field: usize,
    component: Option<&[u8]>,
) -> Result<(), u32> {
    let Some(component) = component else {
        return Ok(());
    };
    *cursor = round_up4(*cursor);
    let end = (*cursor)
        .checked_add(component.len())
        .ok_or(STATUS_INVALID_SECURITY_DESCR)?;
    out[*cursor..end].copy_from_slice(component);
    out[offset_field..offset_field + 4].copy_from_slice(&(*cursor as u32).to_le_bytes());
    *cursor = end;
    Ok(())
}

fn validate_component_slices(
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    sacl: Option<&[u8]>,
    dacl: Option<&[u8]>,
) -> Result<(), u32> {
    for sid in [owner, group].into_iter().flatten() {
        sid_len(sid)?;
    }
    for acl in [sacl, dacl].into_iter().flatten() {
        acl_len(acl)?;
    }
    Ok(())
}

fn component_sid(bytes: &[u8], offset: u32) -> Result<Option<&[u8]>, u32> {
    if offset == 0 {
        return Ok(None);
    }
    let offset = offset as usize;
    let tail = bytes.get(offset..).ok_or(STATUS_INVALID_SECURITY_DESCR)?;
    let len = sid_len(tail)?;
    tail.get(..len)
        .map(Some)
        .ok_or(STATUS_INVALID_SECURITY_DESCR)
}

fn component_acl(bytes: &[u8], offset: u32) -> Result<Option<&[u8]>, u32> {
    if offset == 0 {
        return Ok(None);
    }
    let offset = offset as usize;
    let tail = bytes.get(offset..).ok_or(STATUS_INVALID_SECURITY_DESCR)?;
    let len = acl_len(tail)?;
    tail.get(..len)
        .map(Some)
        .ok_or(STATUS_INVALID_SECURITY_DESCR)
}

fn sid_len(bytes: &[u8]) -> Result<usize, u32> {
    let len = sid_len_from_header(bytes)?;
    if len > bytes.len() {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    Ok(len)
}

fn sid_len_from_header(bytes: &[u8]) -> Result<usize, u32> {
    if bytes.len() < SID_HEADER_SIZE {
        return Err(STATUS_INVALID_SECURITY_DESCR);
    }
    SID_HEADER_SIZE
        .checked_add(bytes[1] as usize * 4)
        .ok_or(STATUS_INVALID_SECURITY_DESCR)
}

fn acl_len(bytes: &[u8]) -> Result<usize, u32> {
    let len = acl_len_from_header(bytes)?;
    if len > bytes.len() {
        return Err(STATUS_INVALID_ACL);
    }
    Ok(len)
}

fn acl_len_from_header(bytes: &[u8]) -> Result<usize, u32> {
    if bytes.len() < ACL_HEADER_SIZE {
        return Err(STATUS_INVALID_ACL);
    }
    let len = read_u16(bytes, 2) as usize;
    if len < ACL_HEADER_SIZE {
        return Err(STATUS_INVALID_ACL);
    }
    Ok(len)
}

fn memory_sid_len(memory: &dyn ClientMemory, va: u64) -> Result<usize, u32> {
    let mut header = [0u8; SID_HEADER_SIZE];
    if !memory.read(va, &mut header) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    sid_len_from_header(&header)
}

fn memory_acl_len(memory: &dyn ClientMemory, va: u64) -> Result<usize, u32> {
    let mut header = [0u8; ACL_HEADER_SIZE];
    if !memory.read(va, &mut header) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    acl_len_from_header(&header)
}

fn read_optional_sid(memory: &dyn ClientMemory, va: u64) -> Result<Option<Vec<u8>>, u32> {
    if va == 0 {
        return Ok(None);
    }
    let len = memory_sid_len(memory, va)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    out.resize(len, 0);
    if !memory.read(va, &mut out) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(Some(out))
}

fn read_optional_acl(memory: &dyn ClientMemory, va: u64) -> Result<Option<Vec<u8>>, u32> {
    if va == 0 {
        return Ok(None);
    }
    let len = memory_acl_len(memory, va)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    out.resize(len, 0);
    if !memory.read(va, &mut out) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(Some(out))
}

fn round_up4(v: usize) -> usize {
    (v + 3) & !3
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
