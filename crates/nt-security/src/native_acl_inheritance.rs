//! Parent ACE transformation, separate from descriptor selection and security assignment.
//!
//! Follows NT5 `RtlpGenerateInheritedAce`, `RtlpCopyEffectiveAce`, and `RtlApplyGenericMask`.
//! Input order and opaque trailing ACE bytes are retained; distinct ACEs are not coalesced.
//! Absent/null ACL policy, protected ACLs, explicit child ACEs, and token defaults belong to the
//! caller. In particular, an empty result is an empty ACL, not permission to choose a null ACL.

use crate::{
    GenericMapping, NativeAcl, ObjectTypeGuid, Sid, ACCESS_SYSTEM_SECURITY, STATUS_INVALID_ACL,
    STATUS_INVALID_SID,
};
use alloc::vec::Vec;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const STATUS_BAD_INHERITANCE_ACL: u32 = 0xc000_007d;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const OI: u8 = 1;
const CI: u8 = 2;
const NP: u8 = 4;
const IO: u8 = 8;
const INHERITED: u8 = 16;
const INHERIT_FLAGS: u8 = OI | CI | NP | IO | INHERITED;

#[derive(Clone, Copy)]
pub struct NativeAclInheritance<'a> {
    pub is_container: bool,
    /// NT5 legacy inheritance clears effective inherited flags; automatic inheritance sets them.
    pub auto_inherit: bool,
    pub owner: &'a Sid,
    pub group: &'a Sid,
    /// Absent server identities use the corresponding child identity, as NT5 specifies.
    pub server_owner: Option<&'a Sid>,
    pub server_group: Option<&'a Sid>,
    pub mapping: &'a GenericMapping,
    pub object_type: Option<&'a ObjectTypeGuid>,
}

struct ParsedAce<'a> {
    bytes: &'a [u8],
    mask: u32,
    prefix: &'a [u8],
    server_sid: Option<&'a [u8]>,
    sid: &'a [u8],
    trailer: &'a [u8],
    object_guid: Option<&'a [u8]>,
    inherited_guid: Option<&'a [u8]>,
}

fn sid_prefix(bytes: &[u8]) -> Result<&[u8], u32> {
    if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
        return Err(STATUS_INVALID_ACL);
    }
    bytes
        .get(..8 + bytes[1] as usize * 4)
        .ok_or(STATUS_INVALID_ACL)
}

fn parse_ace(bytes: &[u8], revision: u8) -> Result<ParsedAce<'_>, u32> {
    let kind = bytes[0];
    if kind > 8 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if bytes.len() < 8 || bytes.len() & 3 != 0 {
        return Err(STATUS_INVALID_ACL);
    }
    let mask = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let mut prefix_len = 8;
    let mut object_guid = None;
    let mut inherited_guid = None;
    if kind == 4 {
        if revision < 3 || bytes.len() < 12 {
            return Err(STATUS_INVALID_ACL);
        }
        if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != 1 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        prefix_len = 12;
    } else if kind >= 5 {
        if revision < 4 || bytes.len() < 12 {
            return Err(STATUS_INVALID_ACL);
        }
        let flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if flags & !3 != 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        prefix_len = 12;
        if flags & 1 != 0 {
            object_guid = Some(
                bytes
                    .get(prefix_len..prefix_len + 16)
                    .ok_or(STATUS_INVALID_ACL)?,
            );
            prefix_len += 16;
        }
        if flags & 2 != 0 {
            inherited_guid = Some(
                bytes
                    .get(prefix_len..prefix_len + 16)
                    .ok_or(STATUS_INVALID_ACL)?,
            );
            prefix_len += 16;
        }
    }
    let prefix = bytes.get(..prefix_len).ok_or(STATUS_INVALID_ACL)?;
    let mut remaining = &bytes[prefix_len..];
    let server_sid = if kind == 4 {
        let server = sid_prefix(remaining)?;
        remaining = &remaining[server.len()..];
        Some(server)
    } else {
        None
    };
    let sid = sid_prefix(remaining)?;
    let trailer = &remaining[sid.len()..];
    Ok(ParsedAce {
        bytes,
        mask,
        prefix,
        server_sid,
        sid,
        trailer,
        object_guid,
        inherited_guid,
    })
}

enum SidSource<'a> {
    Original(&'a [u8]),
    Replaced(&'a Sid),
}

impl SidSource<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Original(bytes) => bytes.len(),
            Self::Replaced(sid) => sid.native_len().unwrap(),
        }
    }

    fn replaced(&self) -> bool {
        matches!(self, Self::Replaced(_))
    }

    fn append(&self, output: &mut Vec<u8>) {
        match self {
            Self::Original(bytes) => output.extend_from_slice(bytes),
            Self::Replaced(sid) => {
                let start = output.len();
                output.resize(start + self.len(), 0);
                sid.write_native(&mut output[start..]).unwrap();
            }
        }
    }
}

fn substitute_sid<'a>(sid: &'a [u8], options: &'a NativeAclInheritance<'_>) -> SidSource<'a> {
    if sid.len() == 12 && sid[..8] == [1, 1, 0, 0, 0, 0, 0, 3] {
        let rid = u32::from_le_bytes(sid[8..12].try_into().unwrap());
        let replacement = match rid {
            0 => Some(options.owner),
            1 => Some(options.group),
            2 => Some(options.server_owner.unwrap_or(options.owner)),
            3 => Some(options.server_group.unwrap_or(options.group)),
            _ => None,
        };
        if let Some(sid) = replacement {
            return SidSource::Replaced(sid);
        }
    }
    SidSource::Original(sid)
}

fn effective_ace(
    ace: &ParsedAce<'_>,
    options: &NativeAclInheritance<'_>,
    propagate: bool,
    filter_object_type: bool,
) -> Result<Option<(Vec<u8>, bool)>, u32> {
    if let Some(required) = ace.inherited_guid.filter(|_| filter_object_type) {
        if !options
            .object_type
            .is_some_and(|actual| actual.as_slice() == required)
        {
            return Ok(None);
        }
    }
    let kind = ace.bytes[0];
    let audit = matches!(kind, 2 | 3 | 7 | 8);
    let mask = options.mapping.map(ace.mask)
        & (options.mapping.generic_all | if audit { ACCESS_SYSTEM_SECURITY } else { 0 })
        & 0x011f_ffff;
    if mask == 0 {
        return Ok(None);
    }
    let sid = substitute_sid(ace.sid, options);
    let server = ace.server_sid.map(|sid| substitute_sid(sid, options));
    let mut mapped =
        mask != ace.mask || sid.replaced() || server.as_ref().is_some_and(SidSource::replaced);
    let remove_guid = filter_object_type && ace.inherited_guid.is_some() && (!propagate || mapped);
    let prefix_len = if remove_guid {
        mapped = true;
        if ace.object_guid.is_some() {
            28
        } else {
            8
        }
    } else {
        ace.prefix.len()
    };
    let length =
        prefix_len + sid.len() + server.as_ref().map_or(0, SidSource::len) + ace.trailer.len();
    if length > u16::MAX as usize {
        return Err(STATUS_BAD_INHERITANCE_ACL);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    output.extend_from_slice(&ace.prefix[..prefix_len]);
    if remove_guid {
        if ace.object_guid.is_some() {
            output[8..12].copy_from_slice(&1u32.to_le_bytes());
        } else {
            output[0] = kind - 5;
        }
    }
    if let Some(server) = server {
        server.append(&mut output);
    }
    sid.append(&mut output);
    output.extend_from_slice(ace.trailer);
    output[1] = (ace.bytes[1] & !INHERIT_FLAGS) | if options.auto_inherit { INHERITED } else { 0 };
    output[2..4].copy_from_slice(&(length as u16).to_le_bytes());
    output[4..8].copy_from_slice(&mask.to_le_bytes());
    Ok(Some((output, mapped)))
}

fn append_ace(output: &mut Vec<u8>, count: &mut u16, ace: &[u8], flags: u8) -> Result<(), u32> {
    let length = output
        .len()
        .checked_add(ace.len())
        .ok_or(STATUS_BAD_INHERITANCE_ACL)?;
    if length > u16::MAX as usize {
        return Err(STATUS_BAD_INHERITANCE_ACL);
    }
    let next_count = count.checked_add(1).ok_or(STATUS_BAD_INHERITANCE_ACL)?;
    output
        .try_reserve(ace.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let start = output.len();
    output.extend_from_slice(ace);
    output[start + 1] = flags;
    *count = next_count;
    Ok(())
}

pub fn inherit_native_acl(
    parent: &NativeAcl,
    options: &NativeAclInheritance<'_>,
) -> Result<NativeAcl, u32> {
    inherit_native_acl_with_provenance(parent, options).map(|(acl, _)| acl)
}

pub(crate) fn inherit_native_acl_with_provenance(
    parent: &NativeAcl,
    options: &NativeAclInheritance<'_>,
) -> Result<(NativeAcl, bool), u32> {
    for sid in [
        Some(options.owner),
        Some(options.group),
        options.server_owner,
        options.server_group,
    ]
    .into_iter()
    .flatten()
    {
        if sid.native_len().is_none() {
            return Err(STATUS_INVALID_SID);
        }
    }
    let parent = parent.as_bytes();
    let mut output = Vec::new();
    output
        .try_reserve_exact(8)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    output.extend_from_slice(&[parent[0], 0, 8, 0, 0, 0, 0, 0]);
    let mut count = 0;
    let mut object_specific = false;
    let mut offset = 8;
    for _ in 0..u16::from_le_bytes(parent[4..6].try_into().unwrap()) {
        let size = u16::from_le_bytes(parent[offset + 2..offset + 4].try_into().unwrap()) as usize;
        let ace = parse_ace(&parent[offset..offset + size], parent[0])?;
        offset += size;
        let flags = ace.bytes[1];
        let propagate = options.is_container && flags & (OI | CI) != 0 && flags & NP == 0;
        let effective = if flags & (if options.is_container { CI } else { OI }) != 0 {
            // NT5 records a matched inheritance type even when mapped rights discard the ACE.
            object_specific |= ace.inherited_guid.is_some_and(|required|
                options.object_type.is_some_and(|actual| actual.as_slice() == required));
            effective_ace(&ace, options, propagate, true)?
        } else {
            None
        };
        let mut propagation_needed = propagate;
        if let Some((effective, mapped)) = effective {
            let mut flags = effective[1];
            if propagate && !mapped {
                flags |= ace.bytes[1] & (OI | CI);
                propagation_needed = false;
            }
            append_ace(&mut output, &mut count, &effective, flags)?;
        }
        if propagation_needed && ace.mask != 0 {
            let flags = ace.bytes[1] | IO | if options.auto_inherit { INHERITED } else { 0 };
            append_ace(&mut output, &mut count, ace.bytes, flags)?;
        }
    }
    let length = output.len() as u16;
    output[2..4].copy_from_slice(&length.to_le_bytes());
    output[4..6].copy_from_slice(&count.to_le_bytes());
    NativeAcl::from_owned_bytes(output).map(|acl| (acl, object_specific)).map_err(|error| error.status())
}

/// NT5 explicit-child copying differs from parent inheritance: inherit-only ACEs are not
/// effective, and inherited-object GUIDs never filter an explicit child ACE.
pub(crate) fn copy_explicit_native_acl(source: &NativeAcl, options: &NativeAclInheritance<'_>,
    map_creators: bool, drop_inherited: bool, clear_inherited: bool) -> Result<NativeAcl, u32>
{
    let source = source.as_bytes();
    let mut output = Vec::new();
    output.try_reserve_exact(8).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    output.extend_from_slice(&[source[0], 0, 8, 0, 0, 0, 0, 0]);
    let mut count = 0;
    let mut offset = 8;
    let effective_options = NativeAclInheritance { auto_inherit: false, ..*options };
    for _ in 0..u16::from_le_bytes(source[4..6].try_into().unwrap()) {
        let size = u16::from_le_bytes(source[offset + 2..offset + 4].try_into().unwrap()) as usize;
        let ace = parse_ace(&source[offset..offset + size], source[0])?;
        offset += size;
        if drop_inherited && ace.bytes[1] & INHERITED != 0 { continue; }
        let reset = if clear_inherited { INHERITED } else { 0 };
        if !map_creators {
            let start = output.len();
            append_ace(&mut output, &mut count, ace.bytes, ace.bytes[1] & !reset)?;
            if ace.bytes[1] & IO == 0 {
                let audit = matches!(ace.bytes[0], 2 | 3 | 7 | 8);
                let mask = options.mapping.map(ace.mask)
                    & (options.mapping.generic_all | if audit { ACCESS_SYSTEM_SECURITY } else { 0 });
                output[start + 4..start + 8].copy_from_slice(&mask.to_le_bytes());
            }
            continue;
        }
        let propagate = options.is_container && ace.bytes[1] & (OI | CI) != 0;
        let effective = if ace.bytes[1] & IO == 0 {
            effective_ace(&ace, &effective_options, propagate, false)?
        } else { None };
        let mut propagation_needed = propagate;
        if let Some((effective, mapped)) = effective {
            let mut flags = effective[1];
            if propagate && !mapped {
                flags |= ace.bytes[1] & INHERIT_FLAGS;
                propagation_needed = false;
            }
            append_ace(&mut output, &mut count, &effective, flags & !reset)?;
        }
        if propagation_needed && ace.mask != 0 {
            append_ace(&mut output, &mut count, ace.bytes, (ace.bytes[1] | IO) & !reset)?;
        }
    }
    let length = output.len() as u16;
    output[2..4].copy_from_slice(&length.to_le_bytes());
    output[4..6].copy_from_slice(&count.to_le_bytes());
    NativeAcl::from_owned_bytes(output).map_err(|error| error.status())
}

#[cfg(test)]
#[path = "native_acl_inheritance_tests.rs"]
mod tests;
