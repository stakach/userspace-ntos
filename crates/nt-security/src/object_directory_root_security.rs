//! Object namespace root initialization (NT5 SePublicDefaultUnrestrictedSd).

use super::bootstrap_directory_security::{directory_template, ADMIN, RESTRICTED, SYSTEM, WORLD};
use crate::{CapturedSubjectTokens, ProcessorMode, SecurityAssignmentAudit};
use alloc::vec::Vec;

fn root_template() -> Result<Vec<u8>, u32> {
    directory_template(&[
        (WORLD.as_slice(), crate::GENERIC_EXECUTE, 0),
        (SYSTEM.as_slice(), crate::GENERIC_ALL, 0),
        (ADMIN.as_slice(), crate::GENERIC_ALL, 0),
        (
            RESTRICTED.as_slice(),
            crate::GENERIC_READ | crate::GENERIC_EXECUTE | crate::READ_CONTROL,
            0,
        ),
    ])
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
