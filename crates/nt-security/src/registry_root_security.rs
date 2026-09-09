//! Security for system-created registry roots (NT5 CmpHiveRootSecurityDescriptor).

use super::{build_self_relative_descriptor, DescriptorBuild, SE_DACL_PRESENT};
use crate::{
    assign_object_security_with_audit, CapturedSubjectTokens, GenericMapping,
    ObjectSecurityAssignment, ProcessorMode, SecurityAssignmentAudit, SecurityAssignmentClient,
    SecurityAssignmentInheritance,
};
use alloc::vec::Vec;

pub const KEY_GENERIC_MAPPING: GenericMapping = GenericMapping {
    generic_read: 0x0002_0019,
    generic_write: 0x0002_0006,
    generic_execute: 0x0002_0019,
    generic_all: 0x000f_003f,
};

fn root_template() -> Result<Vec<u8>, u32> {
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    const ADMIN: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
    const WORLD: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    const RESTRICTED: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0];
    let mut acl = [0u8; 92];
    acl[..8].copy_from_slice(&[2, 0, 92, 0, 4, 0, 0, 0]);
    let mut offset = 8;
    for (sid, access) in [
        (SYSTEM.as_slice(), KEY_GENERIC_MAPPING.generic_all),
        (ADMIN.as_slice(), KEY_GENERIC_MAPPING.generic_all),
        (WORLD.as_slice(), KEY_GENERIC_MAPPING.generic_read),
        (RESTRICTED.as_slice(), KEY_GENERIC_MAPPING.generic_read),
    ] {
        let size = 8 + sid.len();
        acl[offset..offset + 4].copy_from_slice(&[0, 2, size as u8, 0]);
        acl[offset + 4..offset + 8].copy_from_slice(&access.to_le_bytes());
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

/// Assign a bootstrap registry root's explicit inheritable DACL using the authenticated subject's
/// owner/group defaults. This is kernel initialization policy, not an open/create authorization
/// shortcut. Imported hive security and ordinary new-key assignment must not use this template.
/// No explicit owner or SACL is supplied, so this kernel assignment uses no audited privileges.
pub fn assign_registry_root_security(
    subject: &CapturedSubjectTokens<'_>,
    audit: &mut SecurityAssignmentAudit,
) -> Result<Vec<u8>, u32> {
    *audit = SecurityAssignmentAudit::default();
    let creator = root_template()?;
    assign_object_security_with_audit(
        &ObjectSecurityAssignment {
            primary: subject.primary,
            client: subject
                .client
                .as_ref()
                .map(|client| SecurityAssignmentClient {
                    token: client.token,
                    level: client.level,
                }),
            creator: Some(&creator),
            parent: None,
            mapping: &KEY_GENERIC_MAPPING,
            is_container: true,
            mode: ProcessorMode::KernelMode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        },
        audit,
    )
}

#[cfg(test)]
#[path = "registry_root_security_tests.rs"]
mod tests;
