//! Shared centralized assignment and access for native object-type policies.

use crate::{
    AccessCheckResult, CapturedSubjectTokens, GenericMapping, ObjectSecurityAssignment,
    ProcessorMode, SecurityAssignmentAudit, SecurityAssignmentClient,
    SecurityAssignmentInheritance,
};
use alloc::vec::Vec;

pub(crate) fn assign(
    subject: &CapturedSubjectTokens<'_>,
    creator: Option<&[u8]>,
    parent: Option<&[u8]>,
    mode: ProcessorMode,
    mapping: &GenericMapping,
    is_container: bool,
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
            mapping,
            is_container,
            mode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        },
        audit,
    )
}

pub(crate) fn authorize(
    subject: &CapturedSubjectTokens<'_>,
    descriptor: &[u8],
    desired_access: u32,
    mode: ProcessorMode,
    mapping: &GenericMapping,
) -> Result<AccessCheckResult, u32> {
    let descriptor = if mode == ProcessorMode::KernelMode {
        None
    } else {
        Some(crate::security_descriptor_bytes_for_access(descriptor)?)
    };
    Ok(subject.check_access(descriptor.as_ref(), desired_access, mapping, mode))
}
