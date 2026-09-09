//! NT5 IopOpenDeviceParametersSubkey's newly-created-key DACL policy.

use super::{
    build_self_relative_descriptor, parse_self_relative_descriptor, DescriptorBuild, NativeAcl,
    Sid, Vec, SE_DACL_DEFAULTED, SE_DACL_PRESENT, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_ACL,
};

const ADMINISTRATORS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const KEY_ALL_ACCESS: u32 = 0x000f_003f;
const ADMIN_ACE_SIZE: usize = 8 + ADMINISTRATORS.len();

/// Prepare security for a newly created, unprofiled Device Parameters key, after normal Key
/// container security assignment. Existing keys and profile-specific instance keys must not use
/// this transformation. The caller must durably install the result before publishing its handle.
///
/// Replace basic allow/deny Administrators ACEs with one container-inheritable full-control grant.
/// Preserve all other ACEs byte-for-byte and in order, including unknown/object ACEs. Owner, group,
/// SACL and unrelated descriptor control bits are unchanged. Source storage is never modified.
///
/// A present null DACL is rejected rather than silently publishing after the NT5 helper's failed
/// ACL query or converting unrestricted access into an admin-only ACL. Absent and empty DACLs are
/// distinct valid inputs. Malformed descriptors and insufficient capacity fail before publication.
pub fn prepare_device_parameters_security(descriptor: &[u8]) -> Result<Vec<u8>, u32> {
    let parsed = parse_self_relative_descriptor(descriptor)?;
    for sid in [parsed.owner, parsed.group].into_iter().flatten() {
        Sid::from_native_bytes(sid)?;
    }
    for acl in [parsed.sacl, parsed.dacl].into_iter().flatten() {
        NativeAcl::validated_prefix(acl).map_err(|error| error.status())?;
    }
    if parsed.dacl_present && parsed.dacl.is_none() {
        return Err(STATUS_INVALID_ACL);
    }

    let mut size = 8 + ADMIN_ACE_SIZE;
    let mut count = 1usize;
    if let Some(acl) = parsed.dacl {
        for ace in retained_aces(acl) {
            size += ace.len();
            count += 1;
        }
    }
    if size > u16::MAX as usize || count > u16::MAX as usize {
        return Err(STATUS_INVALID_ACL);
    }
    let mut acl = Vec::new();
    acl.try_reserve_exact(size)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    acl.extend_from_slice(&[parsed.dacl.map_or(2, |old| old[0]), 0, 0, 0, 0, 0, 0, 0]);
    acl[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&(count as u16).to_le_bytes());
    if let Some(old) = parsed.dacl {
        for ace in retained_aces(old) {
            acl.extend_from_slice(ace);
        }
    }
    acl.extend_from_slice(&[0, 2, ADMIN_ACE_SIZE as u8, 0]);
    acl.extend_from_slice(&KEY_ALL_ACCESS.to_le_bytes());
    acl.extend_from_slice(&ADMINISTRATORS);
    let control = (parsed.control | SE_DACL_PRESENT) & !SE_DACL_DEFAULTED;
    let mut result = build_self_relative_descriptor(DescriptorBuild {
        owner: parsed.owner,
        group: parsed.group,
        sacl_present: parsed.sacl_present,
        sacl: parsed.sacl,
        dacl_present: true,
        dacl: Some(&acl),
        control,
    })?;
    // The general descriptor builder normalizes control flags. This targeted DACL rewrite must
    // also preserve owner/group defaulting and resource-manager control, not change other policy.
    result[1] = descriptor[1];
    result[2..4].copy_from_slice(&control.to_le_bytes());
    Ok(result)
}

/// Input has already passed the lossless native ACL validator.
fn retained_aces(acl: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut remaining = u16::from_le_bytes([acl[4], acl[5]]);
    let mut offset = 8;
    core::iter::from_fn(move || {
        if remaining == 0 {
            return None;
        }
        remaining -= 1;
        let size = u16::from_le_bytes([acl[offset + 2], acl[offset + 3]]) as usize;
        let ace = &acl[offset..offset + size];
        offset += size;
        Some(ace)
    })
    .filter(|ace| !matches!(ace[0], 0 | 1) || ace.get(8..24) != Some(ADMINISTRATORS.as_slice()))
}

#[cfg(test)]
#[path = "device_parameters_security_tests.rs"]
mod tests;
