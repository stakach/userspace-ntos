//! Explicit kernel-created Security and DOS-device directory templates.

use super::{build_self_relative_descriptor, DescriptorBuild, SE_DACL_PRESENT};
use crate::{CapturedSubjectTokens, ProcessorMode, SecurityAssignmentAudit};
use alloc::vec::Vec;

pub(super) const WORLD: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
pub(super) const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
pub(super) const ADMIN: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
pub(super) const RESTRICTED: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];
const CREATOR_OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
const INHERIT_ONLY_OBJECT_AND_CONTAINER: u8 = 0x0b;

/// Fixed kernel templates only; ordinary captured descriptors use the centralized parser.
pub(super) fn directory_template(aces: &[(&[u8], u32, u8)]) -> Result<Vec<u8>, u32> {
    let mut acl = [0u8; 160];
    let mut offset = 8usize;
    for &(sid, mask, flags) in aces {
        let size = 8 + sid.len();
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= acl.len())
            .ok_or(crate::STATUS_INVALID_ACL)?;
        acl[offset..offset + 4].copy_from_slice(&[0, flags, size as u8, 0]);
        acl[offset + 4..offset + 8].copy_from_slice(&mask.to_le_bytes());
        acl[offset + 8..end].copy_from_slice(sid);
        offset = end;
    }
    acl[..2].copy_from_slice(&[2, 0]);
    acl[2..4].copy_from_slice(&(offset as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    build_self_relative_descriptor(DescriptorBuild {
        owner: None,
        group: None,
        sacl_present: false,
        sacl: None,
        dacl_present: true,
        dacl: Some(&acl[..offset]),
        control: SE_DACL_PRESENT,
    })
}

/// Security namespace initialization (NT5/ReactOS SepInitializationPhase1). Never a default
/// descriptor for other directories or a substitute for captured creator security.
pub fn assign_security_directory_security(
    subject: &CapturedSubjectTokens<'_>,
    audit: &mut SecurityAssignmentAudit,
) -> Result<Vec<u8>, u32> {
    *audit = SecurityAssignmentAudit::default();
    let creator = directory_template(&[
        (&SYSTEM, 0x000f_000f, 0),
        (&ADMIN, crate::READ_CONTROL | 3, 0),
        (&WORLD, 2, 0),
    ])?;
    crate::assign_directory_security(
        subject,
        Some(&creator),
        None,
        ProcessorMode::KernelMode,
        audit,
    )
}

/// Global DOS-device directory initialization (ObpGetDosDevicesProtection). The native caller
/// supplies the actual captured ProtectionMode; only its low bit selects the protected policy.
pub fn assign_dos_devices_directory_security(
    subject: &CapturedSubjectTokens<'_>,
    protection_mode: u32,
    audit: &mut SecurityAssignmentAudit,
) -> Result<Vec<u8>, u32> {
    *audit = SecurityAssignmentAudit::default();
    let inherit = INHERIT_ONLY_OBJECT_AND_CONTAINER;
    let creator = if protection_mode & 1 != 0 {
        directory_template(&[
            (&WORLD, crate::GENERIC_READ | crate::GENERIC_EXECUTE, 0),
            (&SYSTEM, crate::GENERIC_ALL, 0),
            (&WORLD, crate::GENERIC_EXECUTE, inherit),
            (&ADMIN, crate::GENERIC_ALL, inherit),
            (&SYSTEM, crate::GENERIC_ALL, inherit),
            (&CREATOR_OWNER, crate::GENERIC_ALL, inherit),
        ])?
    } else {
        directory_template(&[
            (
                &WORLD,
                crate::GENERIC_READ | crate::GENERIC_WRITE | crate::GENERIC_EXECUTE,
                0,
            ),
            (&SYSTEM, crate::GENERIC_ALL, 0),
            (&WORLD, crate::GENERIC_ALL, inherit),
        ])?
    };
    crate::assign_directory_security(
        subject,
        Some(&creator),
        None,
        ProcessorMode::KernelMode,
        audit,
    )
}
