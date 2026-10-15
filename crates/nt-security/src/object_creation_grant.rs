//! New-object handle grants, separate from descriptor assignment and existing-object access.

use crate::{
    CapturedSubjectTokens, GenericMapping, Luid, PrivilegeAdjustment, ProcessorMode,
    ACCESS_SYSTEM_SECURITY, GENERIC_ALL, MAXIMUM_ALLOWED, STATUS_PRIVILEGE_NOT_HELD,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectCreationPrivilegeAudit {
    pub granted: bool,
    /// KernelMode bypass grants without marking SE_PRIVILEGE_USED_FOR_ACCESS.
    pub attributes: u32,
}

/// NT ObCreateHandle grants the mapped requested mask, not a second access check of the newly
/// assigned descriptor. Native callers must already own valid creation/namespace admission,
/// audit this privilege decision, and keep publication ownership independently. Object-specific
/// selector bits must be removed by the caller before this policy sees the access request.
pub fn prepare_object_creation_grant(
    subject: &CapturedSubjectTokens<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    mode: ProcessorMode,
    audit: &mut Option<ObjectCreationPrivilegeAudit>,
) -> Result<u32, u32> {
    *audit = None;
    let mapped = mapping.map(
        (desired_access & !MAXIMUM_ALLOWED)
            | if desired_access & MAXIMUM_ALLOWED != 0 {
                GENERIC_ALL
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
        *audit = Some(ObjectCreationPrivilegeAudit {
            granted,
            attributes: privilege[0].attributes,
        });
        if !granted {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
    }
    Ok(mapped & (mapping.generic_all | ACCESS_SYSTEM_SECURITY))
}
