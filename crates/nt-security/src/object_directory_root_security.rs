//! Object namespace root initialization (NT5 SePublicDefaultUnrestrictedSd).

use super::{build_self_relative_descriptor, DescriptorBuild, SE_DACL_PRESENT};
use crate::{CapturedSubjectTokens, ProcessorMode, SecurityAssignmentAudit};
use alloc::vec::Vec;

fn root_template() -> Result<Vec<u8>, u32> {
    const WORLD: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    const ADMIN: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
    const RESTRICTED: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];
    let mut acl = [0u8; 92];
    acl[..8].copy_from_slice(&[2, 0, 92, 0, 4, 0, 0, 0]);
    let mut offset = 8;
    for (sid, mask) in [
        (WORLD.as_slice(), crate::GENERIC_EXECUTE),
        (SYSTEM.as_slice(), crate::GENERIC_ALL),
        (ADMIN.as_slice(), crate::GENERIC_ALL),
        (
            RESTRICTED.as_slice(),
            crate::GENERIC_READ | crate::GENERIC_EXECUTE | crate::READ_CONTROL,
        ),
    ] {
        let size = 8 + sid.len();
        acl[offset..offset + 4].copy_from_slice(&[0, 0, size as u8, 0]);
        acl[offset + 4..offset + 8].copy_from_slice(&mask.to_le_bytes());
        acl[offset + 8..offset + size].copy_from_slice(sid);
        offset += size;
    }
    build_self_relative_descriptor(DescriptorBuild {
        owner: None,
        group: None,
        sacl_present: false,
        sacl: None,
        dacl_present: true,
        dacl: Some(&acl),
        control: SE_DACL_PRESENT,
    })
}

/// Assign the Object Manager root's explicit public DACL using the authenticated bootstrap
/// subject's owner/group. This is initialization policy, never ordinary directory inheritance or
/// a substitute for a missing descriptor. The template has no explicit owner or SACL privileges.
pub fn assign_object_directory_root_security(
    subject: &CapturedSubjectTokens<'_>,
    audit: &mut SecurityAssignmentAudit,
) -> Result<Vec<u8>, u32> {
    *audit = SecurityAssignmentAudit::default();
    let creator = root_template()?;
    crate::assign_directory_security(
        subject,
        Some(&creator),
        None,
        ProcessorMode::KernelMode,
        audit,
    )
}
