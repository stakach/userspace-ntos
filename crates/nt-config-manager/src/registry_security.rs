//! Security assignment for Configuration Manager setup-generated registry children.

use alloc::vec::Vec;
use nt_security::{
    assign_object_security_with_audit, AccessToken, ObjectSecurityAssignment, ProcessorMode,
    SecurityAssignmentAudit, SecurityAssignmentInheritance, KEY_GENERIC_MAPPING,
};

/// Validate stored metadata without narrowing it to this service's access-check ACE subset.
pub fn validate_generated_key_security(descriptor: &[u8]) -> Result<(), u32> {
    nt_security::validate_security_descriptor_bytes(descriptor)
}

/// Materialize a generated container's security under its actual secured parent.
/// The setup creator is System; callers cannot use this to replace absent parent authority.
pub fn inherit_generated_key_security(parent: &[u8]) -> Result<Vec<u8>, u32> {
    let system = AccessToken::system();
    assign_object_security_with_audit(
        &ObjectSecurityAssignment {
            primary: &system,
            client: None,
            creator: None,
            parent: Some(parent),
            mapping: &KEY_GENERIC_MAPPING,
            is_container: true,
            mode: ProcessorMode::KernelMode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        },
        &mut SecurityAssignmentAudit::default(),
    )
}
