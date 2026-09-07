use super::super::{
    ParsedDescriptor, SE_DACL_DEFAULTED, SE_DACL_PROTECTED, SE_SACL_DEFAULTED, SE_SACL_PROTECTED,
};
use crate::native_acl_inheritance::{copy_explicit_native_acl, inherit_native_acl_with_provenance};
use crate::{NativeAcl, NativeAclInheritance, STATUS_INVALID_ACL};
use alloc::vec::Vec;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const STATUS_BAD_INHERITANCE_ACL: u32 = 0xc000_007d;

pub(super) struct Selection {
    pub present: bool,
    pub acl: Option<NativeAcl>,
    pub protected: bool,
    pub explicit: bool,
}

fn capture(bytes: &[u8]) -> Result<NativeAcl, u32> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    owned.extend_from_slice(bytes);
    NativeAcl::from_owned_bytes(owned).map_err(|error| error.status())
}

fn count(acl: &NativeAcl) -> usize {
    u16::from_le_bytes(acl.as_bytes()[4..6].try_into().unwrap()) as usize
}

fn merge(
    first: Option<&NativeAcl>,
    second: Option<&NativeAcl>,
    revision: u8,
) -> Result<NativeAcl, u32> {
    let mut length = 8;
    let mut ace_count = 0;
    for acl in [first, second].into_iter().flatten() {
        length += acl.as_bytes().len() - 8;
        ace_count += count(acl);
    }
    if length > u16::MAX as usize || ace_count > u16::MAX as usize {
        return Err(STATUS_BAD_INHERITANCE_ACL);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    bytes.extend_from_slice(&[revision, 0, 0, 0, 0, 0, 0, 0]);
    for acl in [first, second].into_iter().flatten() {
        bytes.extend_from_slice(&acl.as_bytes()[8..]);
    }
    bytes[2..4].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&(ace_count as u16).to_le_bytes());
    NativeAcl::from_owned_bytes(bytes).map_err(|error| error.status())
}

/// NT5 RtlpInheritAcl2 selection followed by RtlpNewSecurityObject's default fallback.
pub(super) fn select(
    parent: Option<&ParsedDescriptor<'_>>,
    child: Option<&ParsedDescriptor<'_>>,
    default: Option<&NativeAcl>,
    sacl: bool,
    automatic: bool,
    default_for_object: bool,
    inheritance: &NativeAclInheritance<'_>,
) -> Result<Selection, u32> {
    let (present, bytes, defaulted, child_protected) =
        child.map_or((false, None, false, false), |sd| {
            if sacl {
                (
                    sd.sacl_present,
                    sd.sacl,
                    sd.control & SE_SACL_DEFAULTED != 0,
                    sd.control & SE_SACL_PROTECTED != 0,
                )
            } else {
                (
                    sd.dacl_present,
                    sd.dacl,
                    sd.control & SE_DACL_DEFAULTED != 0,
                    sd.control & SE_DACL_PROTECTED != 0,
                )
            }
        });
    let parent_bytes = parent.and_then(|sd| if sacl { sd.sacl } else { sd.dacl });
    let mut protected = false;
    let mut explicit = false;
    let mut null_ok = true;
    let mut child_acl = None;
    let mut parent_acl = None;
    let mut revision = 2;
    if !defaulted {
        protected = child_protected;
        if present || protected {
            explicit = true;
            if let Some(bytes) = bytes {
                let captured = capture(bytes)?;
                revision = revision.max(bytes[0]);
                null_ok = false;
                child_acl = Some(copy_explicit_native_acl(
                    &captured,
                    inheritance,
                    automatic,
                    automatic && !protected,
                    automatic && protected,
                )?);
            } else if automatic && !sacl && present && !protected {
                return Err(STATUS_INVALID_ACL);
            }
        }
    }
    if (!automatic && !present) || defaulted || (automatic && !protected) {
        if let Some(bytes) = parent_bytes {
            let captured = capture(bytes)?;
            revision = revision.max(bytes[0]);
            let options = NativeAclInheritance {
                auto_inherit: automatic,
                ..*inheritance
            };
            let (inherited, object_specific) =
                inherit_native_acl_with_provenance(&captured, &options)?;
            if default_for_object
                && object_specific
                && child_acl.as_ref().is_some_and(|acl| count(acl) != 0)
            {
                child_acl = None;
            }
            parent_acl = Some(inherited);
        }
    }
    let generated = child_acl.as_ref().map_or(0, count) + parent_acl.as_ref().map_or(0, count);
    let mut result = if generated != 0 || explicit {
        Selection {
            present: true,
            protected,
            explicit,
            acl: if generated == 0 && null_ok {
                None
            } else {
                Some(merge(child_acl.as_ref(), parent_acl.as_ref(), revision)?)
            },
        }
    } else if present && defaulted {
        Selection {
            present: true,
            protected: child_protected,
            explicit: true,
            acl: bytes
                .map(|bytes| {
                    capture(bytes).and_then(|acl| {
                        copy_explicit_native_acl(&acl, inheritance, false, false, false)
                    })
                })
                .transpose()?,
        }
    } else if let Some(default) = default {
        Selection {
            present: true,
            protected: false,
            explicit: false,
            acl: Some(copy_explicit_native_acl(
                default,
                inheritance,
                false,
                false,
                false,
            )?),
        }
    } else {
        Selection {
            present: false,
            acl: None,
            protected: false,
            explicit: false,
        }
    };
    if automatic && !sacl && result.acl.is_none() {
        result.protected = true;
    }
    Ok(result)
}
