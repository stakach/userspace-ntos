//! Target-Key opens and NT backup/restore privilege policy, before handle publication.

use crate::{
    AccessCheckResult, CapturedSubjectTokens, KeyHandleSecurityAudit, Luid,
    ObjectSecurityAssignment, PreparedKeyCreationSecurity, PrivilegeAdjustment, ProcessorMode,
    SecurityAssignmentAudit, SecurityAssignmentClient, SecurityAssignmentInheritance,
    ACCESS_SYSTEM_SECURITY, KEY_GENERIC_MAPPING, STATUS_ACCESS_DENIED,
};

/// Access denial is returned as an audited decision; malformed descriptors are admission errors.
/// The caller must retain the exact target and subject until publication. Parent create access
/// never authorizes an existing Key. WOW64 flags select a view and cannot become handle rights.
pub fn authorize_key_open(
    subject: &CapturedSubjectTokens<'_>,
    target: &[u8],
    desired_access: u32,
    mode: ProcessorMode,
) -> Result<AccessCheckResult, u32> {
    let descriptor = if mode == ProcessorMode::KernelMode {
        None
    } else {
        Some(crate::security_descriptor_bytes_for_access(target)?)
    };
    Ok(subject.check_access(
        descriptor.as_ref(),
        desired_access & !0x0300,
        &KEY_GENERIC_MAPPING,
        mode,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyBackupRestoreAudit {
    pub backup: KeyHandleSecurityAudit,
    pub restore: KeyHandleSecurityAudit,
    pub granted_access: u32,
    pub status: u32,
}

/// REG_OPTION_BACKUP_RESTORE ignores requested rights and bypasses the target/parent DACL.
/// Both privileges are evaluated, even when the first succeeds. NT5 CmpDoOpen/CmpDoCreate grant
/// restore operators WRITE_DAC and WRITE_OWNER, but not DELETE or KEY_CREATE_LINK.
pub fn authorize_key_backup_restore(
    subject: &CapturedSubjectTokens<'_>,
    mode: ProcessorMode,
) -> KeyBackupRestoreAudit {
    let check = |number| {
        let mut privilege = [PrivilegeAdjustment {
            luid: Luid::new(number),
            attributes: 0,
        }];
        let granted = subject.check_privileges(&mut privilege, true, mode);
        KeyHandleSecurityAudit {
            granted,
            attributes: privilege[0].attributes,
        }
    };
    let backup = check(17);
    let restore = check(18);
    let granted_access = if backup.granted {
        KEY_GENERIC_MAPPING.generic_read | ACCESS_SYSTEM_SECURITY
    } else {
        0
    } | if restore.granted {
        KEY_GENERIC_MAPPING.generic_write | ACCESS_SYSTEM_SECURITY | 0x000c_0000
    } else {
        0
    };
    KeyBackupRestoreAudit {
        backup,
        restore,
        granted_access,
        status: if granted_access == 0 {
            STATUS_ACCESS_DENIED
        } else {
            0
        },
    }
}

#[derive(Default, Debug)]
pub struct KeyBackupRestoreCreationAudit {
    pub privileges: Option<KeyBackupRestoreAudit>,
    pub assignment: SecurityAssignmentAudit,
}

/// Backup/restore creation still assigns real inherited security. Its privilege-derived handle
/// grant neither authorizes arbitrary creator owner/SACL assignments nor checks the child DACL.
pub fn prepare_key_backup_restore_creation_security(
    subject: &CapturedSubjectTokens<'_>,
    parent: &[u8],
    creator: Option<&[u8]>,
    mode: ProcessorMode,
    audit: &mut KeyBackupRestoreCreationAudit,
) -> Result<PreparedKeyCreationSecurity, u32> {
    *audit = KeyBackupRestoreCreationAudit::default();
    let privileges = authorize_key_backup_restore(subject, mode);
    audit.privileges = Some(privileges);
    if privileges.status != 0 {
        return Err(privileges.status);
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
    Ok(PreparedKeyCreationSecurity {
        descriptor,
        granted_access: privileges.granted_access,
    })
}

#[cfg(test)]
#[path = "key_open_tests.rs"]
mod tests;
