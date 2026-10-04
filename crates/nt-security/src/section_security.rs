//! Section descriptor assignment and existing-object access; no namespace or handle effects.

use crate::{
    AccessCheckResult, CapturedSubjectTokens, GenericMapping, ObjectSecurityAssignment,
    ProcessorMode, SecurityAssignmentAudit, SecurityAssignmentClient,
    SecurityAssignmentInheritance,
};
use alloc::vec::Vec;

/// NT5 MiSectionMapping: Sections are not synchronizable objects.
pub const SECTION_GENERIC_MAPPING: GenericMapping = GenericMapping {
    generic_read: 0x0002_0005,
    generic_write: 0x0002_0002,
    generic_execute: 0x0002_0008,
    generic_all: 0x000f_001f,
};

/// Assign an owned descriptor using the retained creator subject. Native callers must deliver
/// actual assignment audit decisions even on failure, and validate namespace/handle ownership
/// separately before publication. This does not reopen the new object against its assigned DACL.
pub fn assign_section_security(
    subject: &CapturedSubjectTokens<'_>,
    creator: Option<&[u8]>,
    parent: Option<&[u8]>,
    mode: ProcessorMode,
    audit: &mut SecurityAssignmentAudit,
) -> Result<Vec<u8>, u32> {
    crate::assign_object_security_with_audit(
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
            parent,
            mapping: &SECTION_GENERIC_MAPPING,
            is_container: false,
            mode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        },
        audit,
    )
}

/// Check an existing Section's actual descriptor. The result retains the precise grant and
/// privilege use for native audit; it is not a reusable authorization or a published handle.
pub fn authorize_section_open(
    subject: &CapturedSubjectTokens<'_>,
    descriptor: &[u8],
    desired_access: u32,
    mode: ProcessorMode,
) -> Result<AccessCheckResult, u32> {
    let descriptor = if mode == ProcessorMode::KernelMode {
        None
    } else {
        Some(crate::security_descriptor_bytes_for_access(descriptor)?)
    };
    Ok(subject.check_access(
        descriptor.as_ref(),
        desired_access,
        &SECTION_GENERIC_MAPPING,
        mode,
    ))
}
