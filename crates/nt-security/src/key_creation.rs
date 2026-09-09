//! Ordinary new-Key security preparation, before mutation and native handle publication.

use crate::{
    AccessCheckResult, CapturedSubjectTokens, Luid, ObjectSecurityAssignment, PrivilegeAdjustment,
    ProcessorMode, SecurityAssignmentAudit, SecurityAssignmentClient,
    SecurityAssignmentInheritance, ACCESS_SYSTEM_SECURITY, KEY_GENERIC_MAPPING, MAXIMUM_ALLOWED,
    STATUS_PRIVILEGE_NOT_HELD,
};
use alloc::vec::Vec;

/// Actual decisions in execution order, retained on both success and failure for caller audit.
#[derive(Default, Debug)]
pub struct KeyCreationAudit {
    pub parent_access: Option<AccessCheckResult>,
    pub assignment: SecurityAssignmentAudit,
    pub handle_security: Option<KeyHandleSecurityAudit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHandleSecurityAudit {
    pub granted: bool,
    /// Returned native privilege attributes distinguish actual use from a KernelMode bypass.
    pub attributes: u32,
}

pub struct PreparedKeyCreationSecurity {
    pub descriptor: Vec<u8>,
    pub granted_access: u32,
}

/// Prepare an ordinary (not link or BACKUP_RESTORE) new Key under an existing parent. The caller
/// must retain the same parent security/generation and captured subject through mutation, audit
/// delivery and handle publication. This value is policy output, not a reusable authorization
/// ticket. Existing-key opens must check their target and must not call this creation-only path.
/// WOW64 view flags are selectors, never granted rights. A new object's assigned DACL is not
/// checked again: the parent authorizes creation even when the creator supplies an empty DACL.
pub fn prepare_key_creation_security(
    subject: &CapturedSubjectTokens<'_>,
    parent: &[u8],
    creator: Option<&[u8]>,
    desired_access: u32,
    mode: ProcessorMode,
    audit: &mut KeyCreationAudit,
) -> Result<PreparedKeyCreationSecurity, u32> {
    *audit = KeyCreationAudit::default();
    let parent_sd = if mode == ProcessorMode::KernelMode {
        None
    } else {
        Some(crate::security_descriptor_bytes_for_access(parent)?)
    };
    let access = subject.check_access(parent_sd.as_ref(), 4, &KEY_GENERIC_MAPPING, mode);
    let status = access.status;
    audit.parent_access = Some(access);
    if status != 0 {
        return Err(status);
    }
    let descriptor = crate::assign_object_security_with_audit(
        &ObjectSecurityAssignment {
            primary: subject.primary,
            client: subject
                .client
                .as_ref()
                .map(|client| SecurityAssignmentClient {
                    token: client.token,
                    level: client.level,
                }),
            creator,
            parent: Some(parent),
            mapping: &KEY_GENERIC_MAPPING,
            is_container: true,
            mode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        },
        &mut audit.assignment,
    )?;
    let desired = desired_access & !0x0300;
    let mapped = KEY_GENERIC_MAPPING.map(
        (desired & !MAXIMUM_ALLOWED)
            | if desired & MAXIMUM_ALLOWED != 0 {
                0x1000_0000
            } else {
                0
            },
    );
    if mapped & ACCESS_SYSTEM_SECURITY != 0 {
        let mut privilege = [PrivilegeAdjustment {
            luid: Luid::new(8),
            attributes: 0,
        }];
        let granted = subject.check_privileges(&mut privilege, true, mode);
        audit.handle_security = Some(KeyHandleSecurityAudit {
            granted,
            attributes: privilege[0].attributes,
        });
        if !granted {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
    }
    Ok(PreparedKeyCreationSecurity {
        descriptor,
        granted_access: mapped & (KEY_GENERIC_MAPPING.generic_all | ACCESS_SYSTEM_SECURITY),
    })
}

#[cfg(test)]
#[path = "key_creation_tests.rs"]
mod tests;
