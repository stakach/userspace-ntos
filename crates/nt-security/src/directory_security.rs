//! Object Directory assignment and access; namespace traversal/publication stays native-owned.

use crate::{
    AccessCheckResult, CapturedSubjectTokens, GenericMapping, ProcessorMode,
    SecurityAssignmentAudit,
};
use alloc::vec::Vec;

/// NT5 ObpDirectoryMapping, without SYNCHRONIZE.
pub const DIRECTORY_GENERIC_MAPPING: GenericMapping = GenericMapping {
    generic_read: 0x0002_0003,
    generic_write: 0x0002_000c,
    generic_execute: 0x0002_0003,
    generic_all: 0x000f_000f,
};

/// Assign a container descriptor from the retained subject and actual captured parent/creator.
/// Native callers deliver audit decisions before publication, including denied assignments.
pub fn assign_directory_security(
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
        &DIRECTORY_GENERIC_MAPPING,
        true,
        audit,
    )
}

/// Check the real Directory descriptor for the precise requested rights and retained subject.
/// The native owner must inspect the returned status and audit privilege use before effects.
pub fn authorize_directory_open(
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
        &DIRECTORY_GENERIC_MAPPING,
    )
}
