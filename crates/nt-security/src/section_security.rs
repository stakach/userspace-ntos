//! Section descriptor assignment and existing-object access; no namespace or handle effects.

use crate::{
    AccessCheckResult, CapturedSubjectTokens, GenericMapping, ProcessorMode,
    SecurityAssignmentAudit,
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
    crate::object_security::assign(
        subject,
        creator,
        parent,
        mode,
        &SECTION_GENERIC_MAPPING,
        false,
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
    crate::object_security::authorize(
        subject,
        descriptor,
        desired_access,
        mode,
        &SECTION_GENERIC_MAPPING,
    )
}
