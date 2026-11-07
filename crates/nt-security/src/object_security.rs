//! Shared centralized assignment and access for native object-type policies.

use crate::{
    AccessCheckResult, CapturedSubjectTokens, GenericMapping, ObjectSecurityAssignment,
    ProcessorMode, SecurityAssignmentAudit, SecurityAssignmentClient, STATUS_ACCESS_DENIED,
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

/// Directory mandatory policy is evaluated against concrete rights, after generic mapping and
/// before a DACL grant can authorize an explicit forbidden request. The original descriptor is
/// retained by the caller; only this access-check projection omits the label from the audit ACL.
pub(crate) fn authorize_directory(
    subject: &CapturedSubjectTokens<'_>,
    bytes: &[u8],
    desired_access: u32,
    mode: ProcessorMode,
    mapping: &GenericMapping,
) -> Result<AccessCheckResult, u32> {
    if mode == ProcessorMode::KernelMode {
        return Ok(subject.check_access(None, desired_access, mapping, mode));
    }
    let (descriptor, label) = crate::native_sd::directory_descriptor_for_access(bytes)?;
    let mut denied_rights = 0;
    if let Some(label) = label {
        let (token, _) = subject.effective_token();
        let Some(level) = token.integrity_level else {
            return Ok(denied());
        };
        if level < label.level {
            use crate::access::{DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER};
            // DIRECTORY_QUERY/TRAVERSE are read; CREATE_OBJECT/CREATE_SUBDIRECTORY are write.
            // Traversal is also the directory execute right. Standard write rights are subject
            // to NO_WRITE_UP even when the DACL or a privilege could otherwise grant them.
            if label.policy & 1 != 0 {
                denied_rights |= 0x000c | DELETE | WRITE_DAC | WRITE_OWNER;
            }
            if label.policy & 2 != 0 {
                denied_rights |= 0x0003 | READ_CONTROL;
            }
            if label.policy & 4 != 0 {
                denied_rights |= 0x0002;
            }
        }
    }
    let explicit = mapping.map(desired_access & !crate::access::MAXIMUM_ALLOWED);
    if explicit & denied_rights != 0 {
        return Ok(denied());
    }
    let mut result = subject.check_access(Some(&descriptor), desired_access, mapping, mode);
    if result.granted() && desired_access & crate::access::MAXIMUM_ALLOWED != 0 {
        result.granted_access &= !denied_rights;
        if result.granted_access == 0 {
            result = denied();
        }
    }
    Ok(result)
}

fn denied() -> AccessCheckResult {
    AccessCheckResult {
        status: STATUS_ACCESS_DENIED,
        granted_access: 0,
        privileges_used: Vec::new(),
    }
}
