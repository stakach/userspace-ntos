//! Kernel centralized-security assignment, using authenticated captured token references.
//!
//! This is the kernel `SeAssignSecurity[Ex]` authority surface, not the user-mode RTL authority
//! policy. No token lookup, pool publication, audit delivery, or object mutation occurs here.
//! Server/untrusted DACL conversion and resource-manager descriptors are explicitly unsupported.

use super::{
    build_self_relative_descriptor, parse_self_relative_descriptor, DescriptorBuild,
    ParsedDescriptor, SE_DACL_AUTO_INHERITED, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SE_SACL_AUTO_INHERITED, SE_SACL_PRESENT, SE_SACL_PROTECTED,
};
use crate::{
    AccessToken, GenericMapping, NativeAclInheritance, ObjectTypeGuid, ProcessorMode,
    SecurityImpersonationLevel, Sid, TokenType, SE_RESTORE, SE_SECURITY,
    STATUS_BAD_IMPERSONATION_LEVEL, STATUS_BAD_TOKEN_TYPE, STATUS_INVALID_OWNER,
    STATUS_INVALID_PRIMARY_GROUP, STATUS_PRIVILEGE_NOT_HELD,
};
use alloc::vec::Vec;

#[path = "security_assignment_acl.rs"]
mod acl;

pub const SEF_DACL_AUTO_INHERIT: u32 = 0x01;
pub const SEF_SACL_AUTO_INHERIT: u32 = 0x02;
pub const SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT: u32 = 0x04;
pub const SEF_AVOID_PRIVILEGE_CHECK: u32 = 0x08;
pub const SEF_AVOID_OWNER_CHECK: u32 = 0x10;
pub const SEF_DEFAULT_OWNER_FROM_PARENT: u32 = 0x20;
pub const SEF_DEFAULT_GROUP_FROM_PARENT: u32 = 0x40;
const SUPPORTED_FLAGS: u32 = 0x7f;
const UNSUPPORTED_DESCRIPTOR_CONTROL: u16 = 0x0040 | 0x0080 | 0x4000;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityAssignmentInheritance {
    /// SeAssignSecurity derives auto-inheritance separately for each absent creator ACL.
    Legacy,
    /// SeAssignSecurityEx uses the supplied SEF_* policy bits. Bypass flags are trusted kernel
    /// policy, not flags that object-creation syscalls may accept unchecked from userspace.
    Extended { flags: u32 },
}

#[derive(Clone, Copy)]
pub struct SecurityAssignmentClient<'a> {
    pub token: &'a AccessToken,
    /// The captured subject's effective level, which may be lower than the token's own level.
    pub level: SecurityImpersonationLevel,
}

pub struct ObjectSecurityAssignment<'a> {
    pub primary: &'a AccessToken,
    pub client: Option<SecurityAssignmentClient<'a>>,
    pub creator: Option<&'a [u8]>,
    pub parent: Option<&'a [u8]>,
    pub mapping: &'a GenericMapping,
    pub is_container: bool,
    pub mode: ProcessorMode,
    pub object_type: Option<&'a ObjectTypeGuid>,
    pub inheritance: SecurityAssignmentInheritance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityAssignmentPrivilegeOutcome {
    Granted,
    Denied,
}

/// Actual privilege decisions, including denied attempts. `None` means the check was not reached
/// or was bypassed; ordinary owner membership does not count as using restore privilege.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityAssignmentAudit {
    pub security: Option<SecurityAssignmentPrivilegeOutcome>,
    pub restore: Option<SecurityAssignmentPrivilegeOutcome>,
}

fn descriptor(bytes: Option<&[u8]>) -> Result<Option<ParsedDescriptor<'_>>, u32> {
    let parsed = bytes.map(parse_self_relative_descriptor).transpose()?;
    if parsed
        .as_ref()
        .is_some_and(|sd| sd.control & UNSUPPORTED_DESCRIPTOR_CONTROL != 0)
    {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(parsed)
}

fn sid_bytes(sid: &Sid, invalid: u32) -> Result<Vec<u8>, u32> {
    let length = sid.native_len().ok_or(invalid)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    bytes.resize(length, 0);
    sid.write_native(&mut bytes).ok_or(invalid)?;
    Ok(bytes)
}

/// Pure construction convenience that discards audit decisions; it must not authorize native
/// object publication. Native callers must use `assign_object_security_with_audit` instead.
pub fn assign_object_security(request: &ObjectSecurityAssignment<'_>) -> Result<Vec<u8>, u32> {
    assign_object_security_with_audit(request, &mut SecurityAssignmentAudit::default())
}

/// Build an owned descriptor and record actual privilege decisions without replaying policy.
/// The trace is reset before validation and remains available on failure. Native callers must
/// deliver required audit records for successful and denied attempts, then publish only a
/// successful descriptor. Input token references must come from the authenticated captured subject.
pub fn assign_object_security_with_audit(
    request: &ObjectSecurityAssignment<'_>,
    audit: &mut SecurityAssignmentAudit,
) -> Result<Vec<u8>, u32> {
    *audit = SecurityAssignmentAudit::default();
    if request.primary.token_type != TokenType::Primary {
        return Err(STATUS_BAD_TOKEN_TYPE);
    }
    let effective = if let Some(client) = request.client {
        if client.token.token_type != TokenType::Impersonation {
            return Err(STATUS_BAD_TOKEN_TYPE);
        }
        // Kernel default selection permits anonymous contexts; owner/privilege authorization
        // below enforces its own stronger level. The RTL user-mode minimum is a separate policy.
        if client.level > client.token.impersonation_level {
            return Err(STATUS_BAD_IMPERSONATION_LEVEL);
        }
        client.token
    } else {
        request.primary
    };
    let creator = descriptor(request.creator)?;
    let parent = descriptor(request.parent)?;
    let flags = match request.inheritance {
        SecurityAssignmentInheritance::Extended { flags } => flags,
        SecurityAssignmentInheritance::Legacy => {
            let mut flags = 0;
            for (present, inherited, automatic) in [
                (
                    SE_DACL_PRESENT,
                    SE_DACL_AUTO_INHERITED,
                    SEF_DACL_AUTO_INHERIT,
                ),
                (
                    SE_SACL_PRESENT,
                    SE_SACL_AUTO_INHERITED,
                    SEF_SACL_AUTO_INHERIT,
                ),
            ] {
                if creator.as_ref().is_none_or(|sd| sd.control & present == 0)
                    && parent
                        .as_ref()
                        .is_some_and(|sd| sd.control & inherited != 0)
                {
                    flags |= automatic;
                }
            }
            flags
        }
    };
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let mut owner_source = creator.as_ref().and_then(|sd| sd.owner);
    if owner_source.is_none() && flags & SEF_DEFAULT_OWNER_FROM_PARENT != 0 {
        owner_source = Some(
            parent
                .as_ref()
                .and_then(|sd| sd.owner)
                .ok_or(STATUS_INVALID_OWNER)?,
        );
    }
    let owner_value = owner_source.map(Sid::from_native_bytes).transpose()?;
    let owner = owner_value.as_ref().unwrap_or(&effective.owner);
    let mut group_source = creator.as_ref().and_then(|sd| sd.group);
    if group_source.is_none() && flags & SEF_DEFAULT_GROUP_FROM_PARENT != 0 {
        group_source = Some(
            parent
                .as_ref()
                .and_then(|sd| sd.group)
                .ok_or(STATUS_INVALID_PRIMARY_GROUP)?,
        );
    }
    let group_value = group_source.map(Sid::from_native_bytes).transpose()?;
    let group = group_value.as_ref().unwrap_or(&effective.primary_group);
    let owner_bytes = sid_bytes(owner, STATUS_INVALID_OWNER)?;
    let group_bytes = sid_bytes(group, STATUS_INVALID_PRIMARY_GROUP)?;
    // Compound creator-server substitutions always use the authenticated primary defaults.
    if request.primary.owner.native_len().is_none() {
        return Err(STATUS_INVALID_OWNER);
    }
    if request.primary.primary_group.native_len().is_none() {
        return Err(STATUS_INVALID_PRIMARY_GROUP);
    }
    let inheritance = NativeAclInheritance {
        is_container: request.is_container,
        auto_inherit: false,
        owner,
        group,
        server_owner: Some(&request.primary.owner),
        server_group: Some(&request.primary.primary_group),
        mapping: request.mapping,
        object_type: request.object_type,
    };
    let sacl = acl::select(
        parent.as_ref(),
        creator.as_ref(),
        None,
        true,
        flags & SEF_SACL_AUTO_INHERIT != 0,
        flags & SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT != 0,
        &inheritance,
    )?;
    let dacl = acl::select(
        parent.as_ref(),
        creator.as_ref(),
        effective.default_dacl.as_ref(),
        false,
        flags & SEF_DACL_AUTO_INHERIT != 0,
        flags & SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT != 0,
        &inheritance,
    )?;
    if request.mode == ProcessorMode::UserMode {
        let subject_can_act = request
            .client
            .is_none_or(|client| client.level >= SecurityImpersonationLevel::Impersonation);
        if sacl.explicit && flags & SEF_AVOID_PRIVILEGE_CHECK == 0 {
            let granted = subject_can_act && effective.has_privilege(SE_SECURITY);
            audit.security = Some(if granted {
                SecurityAssignmentPrivilegeOutcome::Granted
            } else {
                SecurityAssignmentPrivilegeOutcome::Denied
            });
            if !granted {
                return Err(STATUS_PRIVILEGE_NOT_HELD);
            }
        }
        if owner_source.is_some() && flags & SEF_AVOID_OWNER_CHECK == 0 {
            let assignable = effective.user == *owner
                || effective
                    .groups
                    .iter()
                    .any(|group| group.is_owner() && group.sid == *owner);
            if !subject_can_act {
                return Err(STATUS_INVALID_OWNER);
            }
            if !assignable {
                let granted = effective.has_privilege(SE_RESTORE);
                audit.restore = Some(if granted {
                    SecurityAssignmentPrivilegeOutcome::Granted
                } else {
                    SecurityAssignmentPrivilegeOutcome::Denied
                });
                if !granted {
                    return Err(STATUS_INVALID_OWNER);
                }
            }
        }
    }
    let mut control = 0;
    if sacl.protected {
        control |= SE_SACL_PROTECTED;
    }
    if dacl.protected {
        control |= SE_DACL_PROTECTED;
    }
    if flags & SEF_SACL_AUTO_INHERIT != 0 {
        control |= SE_SACL_AUTO_INHERITED;
    }
    if flags & SEF_DACL_AUTO_INHERIT != 0 {
        control |= SE_DACL_AUTO_INHERITED;
    }
    build_self_relative_descriptor(DescriptorBuild {
        owner: Some(&owner_bytes),
        group: Some(&group_bytes),
        sacl_present: sacl.present,
        sacl: sacl.acl.as_ref().map(|acl| acl.as_bytes()),
        dacl_present: dacl.present,
        dacl: dacl.acl.as_ref().map(|acl| acl.as_bytes()),
        control,
    })
}

#[cfg(test)]
#[path = "security_assignment_tests.rs"]
mod tests;
