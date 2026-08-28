//! Security descriptors + ACLs/ACEs (spec §7.5-§7.7), access masks (spec §8), and the NT
//! access-check algorithm (spec §9).

use alloc::{vec, vec::Vec};

use crate::sid::Sid;
use crate::token::{
    AccessToken, PrivilegeAdjustment, SE_PRIVILEGE_USED_FOR_ACCESS, SE_SECURITY, SE_TAKE_OWNERSHIP,
};

pub type AccessMask = u32;

// Standard rights (spec §8.2)
pub const DELETE: AccessMask = 0x0001_0000;
pub const READ_CONTROL: AccessMask = 0x0002_0000;
pub const WRITE_DAC: AccessMask = 0x0004_0000;
pub const WRITE_OWNER: AccessMask = 0x0008_0000;
pub const SYNCHRONIZE: AccessMask = 0x0010_0000;
// Special (spec §8.2, §9.7)
pub const ACCESS_SYSTEM_SECURITY: AccessMask = 0x0100_0000;
pub const MAXIMUM_ALLOWED: AccessMask = 0x0200_0000;
// Generic rights (spec §8.1)
pub const GENERIC_ALL: AccessMask = 0x1000_0000;
pub const GENERIC_EXECUTE: AccessMask = 0x2000_0000;
pub const GENERIC_WRITE: AccessMask = 0x4000_0000;
pub const GENERIC_READ: AccessMask = 0x8000_0000;
const GENERIC_MASK: AccessMask = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

// Token object rights and generic mapping (`SepTokenMapping` in ReactOS).
pub const TOKEN_ASSIGN_PRIMARY: AccessMask = 0x0000_0001;
pub const TOKEN_DUPLICATE: AccessMask = 0x0000_0002;
pub const TOKEN_IMPERSONATE: AccessMask = 0x0000_0004;
pub const TOKEN_QUERY: AccessMask = 0x0000_0008;
pub const TOKEN_QUERY_SOURCE: AccessMask = 0x0000_0010;
pub const TOKEN_ADJUST_PRIVILEGES: AccessMask = 0x0000_0020;
pub const TOKEN_ADJUST_GROUPS: AccessMask = 0x0000_0040;
pub const TOKEN_ADJUST_DEFAULT: AccessMask = 0x0000_0080;
pub const TOKEN_ADJUST_SESSIONID: AccessMask = 0x0000_0100;
pub const TOKEN_READ: AccessMask = READ_CONTROL | TOKEN_QUERY;
pub const TOKEN_WRITE: AccessMask =
    READ_CONTROL | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT;
pub const TOKEN_EXECUTE: AccessMask = READ_CONTROL;
pub const TOKEN_ALL_ACCESS: AccessMask = DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER
    | TOKEN_ASSIGN_PRIMARY
    | TOKEN_DUPLICATE
    | TOKEN_IMPERSONATE
    | TOKEN_QUERY
    | TOKEN_QUERY_SOURCE
    | TOKEN_ADJUST_PRIVILEGES
    | TOKEN_ADJUST_GROUPS
    | TOKEN_ADJUST_DEFAULT
    | TOKEN_ADJUST_SESSIONID;

/// Expand a token handle's requested generic access into concrete granted rights. Token object
/// security descriptors are not modelled yet, so `MAXIMUM_ALLOWED` grants the complete token mask,
/// matching the process/thread object policy used by the executive.
pub fn map_token_access(desired: AccessMask) -> AccessMask {
    let mut mapped = desired & !(GENERIC_MASK | MAXIMUM_ALLOWED);
    if desired & GENERIC_READ != 0 {
        mapped |= TOKEN_READ;
    }
    if desired & GENERIC_WRITE != 0 {
        mapped |= TOKEN_WRITE;
    }
    if desired & GENERIC_EXECUTE != 0 {
        mapped |= TOKEN_EXECUTE;
    }
    if desired & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        mapped |= TOKEN_ALL_ACCESS;
    }
    mapped
}

// NTSTATUS
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

pub type ObjectTypeGuid = [u8; 16];
pub const ACCESS_MAX_LEVEL: u16 = 4;

/// One validated object or sub-object in an NT access-check hierarchy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ObjectTypeEntry {
    pub level: u16,
    pub object_type: ObjectTypeGuid,
}

/// Validate the ordering rules shared by native `OBJECT_TYPE_LIST` callers and the access engine.
pub fn validate_object_type_list(entries: &[ObjectTypeEntry]) -> Result<(), u32> {
    for (index, entry) in entries.iter().enumerate() {
        if entry.level > ACCESS_MAX_LEVEL
            || (index == 0 && entry.level != 0)
            || (index != 0 && entry.level == 0)
            || (index != 0 && entry.level > entries[index - 1].level + 1)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    Ok(())
}

/// Maps generic rights to object-specific rights (spec §8.3).
#[derive(Copy, Clone, Debug)]
pub struct GenericMapping {
    pub generic_read: AccessMask,
    pub generic_write: AccessMask,
    pub generic_execute: AccessMask,
    pub generic_all: AccessMask,
}

impl GenericMapping {
    /// Expand any generic bits in `mask` to their specific rights.
    pub fn map(&self, mut mask: AccessMask) -> AccessMask {
        if mask & GENERIC_READ != 0 {
            mask |= self.generic_read;
        }
        if mask & GENERIC_WRITE != 0 {
            mask |= self.generic_write;
        }
        if mask & GENERIC_EXECUTE != 0 {
            mask |= self.generic_execute;
        }
        if mask & GENERIC_ALL != 0 {
            mask |= self.generic_all;
        }
        mask & !GENERIC_MASK
    }
}

/// ACE type (spec §7.7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    SystemAudit,
}

/// An access-control entry (spec §7.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    pub ace_type: AceType,
    pub mask: AccessMask,
    pub sid: Sid,
    pub inherit_only: bool,
    /// Object GUID carried by an object ACE. `None` means the ACE applies to the object generally.
    pub object_type: Option<ObjectTypeGuid>,
}

impl Ace {
    pub fn allow(sid: Sid, mask: AccessMask) -> Self {
        Ace {
            ace_type: AceType::AccessAllowed,
            mask,
            sid,
            inherit_only: false,
            object_type: None,
        }
    }
    pub fn deny(sid: Sid, mask: AccessMask) -> Self {
        Ace {
            ace_type: AceType::AccessDenied,
            mask,
            sid,
            inherit_only: false,
            object_type: None,
        }
    }

    pub fn allow_object(sid: Sid, mask: AccessMask, object_type: ObjectTypeGuid) -> Self {
        Ace {
            ace_type: AceType::AccessAllowed,
            mask,
            sid,
            inherit_only: false,
            object_type: Some(object_type),
        }
    }

    pub fn deny_object(sid: Sid, mask: AccessMask, object_type: ObjectTypeGuid) -> Self {
        Ace {
            ace_type: AceType::AccessDenied,
            mask,
            sid,
            inherit_only: false,
            object_type: Some(object_type),
        }
    }
}

/// An access-control list (spec §7.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acl {
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new(aces: Vec<Ace>) -> Self {
        Acl { aces }
    }
    pub fn empty() -> Self {
        Acl { aces: Vec::new() }
    }
}

/// A security descriptor (spec §7.5). A `None` DACL grants all access; an empty DACL grants none.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SecurityDescriptor {
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

/// The caller's processor mode (spec §9.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessorMode {
    KernelMode,
    UserMode,
}

/// Check a native `PRIVILEGE_SET` capture against a token. Enabled privileges are matched by their
/// complete LUID, and each match used to satisfy the request is marked for the caller's in/out
/// array. Kernel-mode callers bypass the token check without modifying that array.
pub fn check_token_privileges(
    token: &AccessToken,
    required: &mut [PrivilegeAdjustment],
    all_necessary: bool,
    mode: ProcessorMode,
) -> bool {
    if mode == ProcessorMode::KernelMode || required.is_empty() {
        return true;
    }

    let mut remaining = if all_necessary { required.len() } else { 1 };
    for entry in required {
        let enabled = token
            .privileges
            .iter()
            .any(|privilege| privilege.luid == entry.luid && privilege.enabled);
        if enabled {
            entry.attributes |= SE_PRIVILEGE_USED_FOR_ACCESS;
            remaining -= 1;
            if remaining == 0 {
                return true;
            }
        }
    }
    false
}

/// The result of an access check (spec §9.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessCheckResult {
    pub status: u32,
    pub granted_access: AccessMask,
    pub privileges_used: Vec<&'static str>,
}

impl AccessCheckResult {
    pub fn granted(&self) -> bool {
        self.status == STATUS_SUCCESS
    }
}

/// The NT access-check algorithm (spec §9). Evaluates `desired_access` for `token` against `sd`,
/// mapping generic rights, honouring `MAXIMUM_ALLOWED`, evaluating deny-before-allow in ACL order,
/// applying owner rights + privilege overrides, and bypassing the DACL for `KernelMode`.
pub fn access_check(
    sd: &SecurityDescriptor,
    token: &AccessToken,
    desired_access: AccessMask,
    mapping: &GenericMapping,
    mode: ProcessorMode,
) -> AccessCheckResult {
    access_check_internal(sd, token, None, desired_access, mapping, mode, None, false)
}

/// Evaluate access against an object-type hierarchy. The result-list form returns one entry for
/// every object and preserves partial grants; the aggregate form returns one union result, matching
/// the native API that has only one granted-access/status output pair.
pub fn access_check_by_type(
    sd: &SecurityDescriptor,
    token: &AccessToken,
    principal_self: Option<&Sid>,
    desired_access: AccessMask,
    object_types: &[ObjectTypeEntry],
    mapping: &GenericMapping,
    mode: ProcessorMode,
    use_result_list: bool,
) -> Result<Vec<AccessCheckResult>, u32> {
    validate_object_type_list(object_types)?;
    if use_result_list && object_types.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if object_types.is_empty() {
        return Ok(vec![access_check_internal(
            sd,
            token,
            principal_self,
            desired_access,
            mapping,
            mode,
            None,
            false,
        )]);
    }

    let mut per_object = Vec::new();
    per_object
        .try_reserve_exact(object_types.len())
        .map_err(|_| crate::create_token::STATUS_INSUFFICIENT_RESOURCES)?;
    for index in 0..object_types.len() {
        per_object.push(access_check_internal(
            sd,
            token,
            principal_self,
            desired_access,
            mapping,
            mode,
            Some((object_types, index)),
            true,
        ));
    }
    if use_result_list {
        return Ok(per_object);
    }

    let granted = per_object
        .iter()
        .fold(0, |union, result| union | result.granted_access);
    let maximum = desired_access & MAXIMUM_ALLOWED != 0;
    let wanted = mapping.map(desired_access & !MAXIMUM_ALLOWED);
    let success = if maximum {
        granted != 0
    } else {
        desired_access != 0 && wanted & !granted == 0
    };
    let privileges_used = per_object
        .first()
        .map(|result| result.privileges_used.clone())
        .unwrap_or_default();
    Ok(vec![AccessCheckResult {
        status: if success {
            STATUS_SUCCESS
        } else {
            STATUS_ACCESS_DENIED
        },
        granted_access: if success { granted } else { 0 },
        privileges_used,
    }])
}

fn access_check_internal(
    sd: &SecurityDescriptor,
    token: &AccessToken,
    principal_self: Option<&Sid>,
    desired_access: AccessMask,
    mapping: &GenericMapping,
    mode: ProcessorMode,
    object: Option<(&[ObjectTypeEntry], usize)>,
    preserve_partial: bool,
) -> AccessCheckResult {
    if desired_access == 0 {
        return denied();
    }
    let maximum = desired_access & MAXIMUM_ALLOWED != 0;
    let want = mapping.map(desired_access & !MAXIMUM_ALLOWED);
    let mut privileges_used: Vec<&'static str> = Vec::new();

    // ACCESS_SYSTEM_SECURITY always requires SeSecurityPrivilege (spec §9.7).
    if want & ACCESS_SYSTEM_SECURITY != 0 {
        if token.has_privilege(SE_SECURITY) {
            privileges_used.push(SE_SECURITY);
        } else {
            return denied();
        }
    }

    // KernelMode bypasses the DACL for normal opens (spec §9.3).
    if mode == ProcessorMode::KernelMode {
        return AccessCheckResult {
            status: STATUS_SUCCESS,
            granted_access: if maximum {
                mapping.generic_all | want
            } else {
                want
            },
            privileges_used,
        };
    }

    let mut granted: AccessMask = 0;

    // Privilege overrides (spec §9.7).
    if want & WRITE_OWNER != 0 && token.has_privilege(SE_TAKE_OWNERSHIP) {
        granted |= WRITE_OWNER;
        privileges_used.push(SE_TAKE_OWNERSHIP);
    }
    // ACCESS_SYSTEM_SECURITY was privilege-gated above.
    if want & ACCESS_SYSTEM_SECURITY != 0 {
        granted |= ACCESS_SYSTEM_SECURITY;
    }

    // Owner implicitly gets READ_CONTROL. Deny-only identities cannot establish ownership, and a
    // restricted token must also satisfy ownership through its restricting SID set.
    let token_is_owner = sd.owner.as_ref().is_some_and(|owner| {
        token.allow_sids().iter().any(|sid| **sid == *owner)
            && (!token.is_restricted()
                || token
                    .restricted_allow_sids()
                    .iter()
                    .any(|sid| **sid == *owner))
    });
    if token_is_owner {
        let owner_rights = READ_CONTROL | WRITE_DAC;
        granted |= if maximum {
            owner_rights
        } else {
            want & owner_rights
        };
    }

    match &sd.dacl {
        None => {
            // Null DACL grants all access (spec §9.5).
            granted |= if maximum {
                mapping.generic_all | want
            } else {
                want
            };
        }
        Some(acl) => {
            let allow_sids = token.allow_sids();
            let deny_sids = token.deny_sids();
            let ordinary = match evaluate_dacl(
                acl,
                &allow_sids,
                &deny_sids,
                principal_self,
                object,
                want,
                maximum,
                granted,
                mapping,
            ) {
                Ok(result) => result,
                Err(partial) => {
                    return denied_with_partial(partial, privileges_used, preserve_partial)
                }
            };
            if token.is_restricted() {
                let restricted_allow_sids = token.restricted_allow_sids();
                let restricted_deny_sids = token.restricted_deny_sids();
                let restricted = match evaluate_dacl(
                    acl,
                    &restricted_allow_sids,
                    &restricted_deny_sids,
                    principal_self,
                    object,
                    want,
                    maximum,
                    granted,
                    mapping,
                ) {
                    Ok(result) => result,
                    Err(partial) => {
                        return denied_with_partial(partial, privileges_used, preserve_partial)
                    }
                };
                // Privilege and owner grants precede the DACL. Rights granted by the ACL must pass
                // both the ordinary SID set and the restricting SID set.
                granted |= (ordinary & !granted) & (restricted & !granted);
            } else {
                granted = ordinary;
            }
        }
    }

    if maximum {
        if granted != 0 {
            AccessCheckResult {
                status: STATUS_SUCCESS,
                granted_access: granted,
                privileges_used,
            }
        } else {
            denied()
        }
    } else if want & !granted == 0 {
        AccessCheckResult {
            status: STATUS_SUCCESS,
            granted_access: if preserve_partial { granted } else { want },
            privileges_used,
        }
    } else {
        denied_with_partial(granted, privileges_used, preserve_partial)
    }
}

fn evaluate_dacl(
    acl: &Acl,
    allow_sids: &[&Sid],
    deny_sids: &[&Sid],
    principal_self: Option<&Sid>,
    object: Option<(&[ObjectTypeEntry], usize)>,
    want: AccessMask,
    maximum: bool,
    previously_granted: AccessMask,
    mapping: &GenericMapping,
) -> Result<AccessMask, AccessMask> {
    let mut granted = previously_granted;
    let mut denied_bits: AccessMask = 0;
    for ace in &acl.aces {
        if ace.inherit_only || !ace_applies_to_object(ace, object) {
            continue;
        }
        let mask = mapping.map(ace.mask);
        match ace.ace_type {
            AceType::AccessDenied => {
                if sid_matches(deny_sids, &ace.sid, principal_self) {
                    if maximum {
                        denied_bits |= mask & !granted;
                    } else if mask & want & !granted != 0 {
                        return Err(granted);
                    }
                }
            }
            AceType::AccessAllowed => {
                if sid_matches(allow_sids, &ace.sid, principal_self) {
                    let add = mask & !denied_bits;
                    granted |= if maximum { add } else { add & want };
                }
            }
            AceType::SystemAudit => {}
        }
        if !maximum && want & !granted == 0 {
            break;
        }
    }
    Ok(granted)
}

fn sid_matches(candidates: &[&Sid], ace_sid: &Sid, principal_self: Option<&Sid>) -> bool {
    let sid = if ace_sid.is_principal_self() {
        let Some(principal_self) = principal_self else {
            return false;
        };
        principal_self
    } else {
        ace_sid
    };
    candidates.iter().any(|candidate| **candidate == *sid)
}

fn ace_applies_to_object(ace: &Ace, object: Option<(&[ObjectTypeEntry], usize)>) -> bool {
    let Some(guid) = ace.object_type else {
        return true;
    };
    let Some((entries, candidate)) = object else {
        // A by-type object ACE is an ordinary ACE when the caller supplies no type list.
        return true;
    };
    let Some(target) = entries.iter().position(|entry| entry.object_type == guid) else {
        return false;
    };
    if candidate == target {
        return true;
    }
    if candidate < target {
        return false;
    }
    let target_level = entries[target].level;
    entries[target + 1..=candidate]
        .iter()
        .all(|entry| entry.level > target_level)
}

fn denied() -> AccessCheckResult {
    AccessCheckResult {
        status: STATUS_ACCESS_DENIED,
        granted_access: 0,
        privileges_used: Vec::new(),
    }
}

fn denied_with_partial(
    granted_access: AccessMask,
    privileges_used: Vec<&'static str>,
    preserve_partial: bool,
) -> AccessCheckResult {
    AccessCheckResult {
        status: STATUS_ACCESS_DENIED,
        granted_access: if preserve_partial { granted_access } else { 0 },
        privileges_used,
    }
}

/// A privilege-only check (spec §9.7), e.g. `SeLoadDriverPrivilege` for the driver-load path.
pub fn privilege_check(token: &AccessToken, privilege: &str) -> Result<(), u32> {
    if token.has_privilege(privilege) {
        Ok(())
    } else {
        Err(STATUS_PRIVILEGE_NOT_HELD)
    }
}
