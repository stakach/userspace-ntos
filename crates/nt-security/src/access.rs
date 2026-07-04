//! Security descriptors + ACLs/ACEs (spec §7.5-§7.7), access masks (spec §8), and the NT
//! access-check algorithm (spec §9).

use alloc::vec::Vec;

use crate::sid::Sid;
use crate::token::{AccessToken, SE_SECURITY, SE_TAKE_OWNERSHIP};

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

// NTSTATUS
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

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
}

impl Ace {
    pub fn allow(sid: Sid, mask: AccessMask) -> Self {
        Ace {
            ace_type: AceType::AccessAllowed,
            mask,
            sid,
            inherit_only: false,
        }
    }
    pub fn deny(sid: Sid, mask: AccessMask) -> Self {
        Ace {
            ace_type: AceType::AccessDenied,
            mask,
            sid,
            inherit_only: false,
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
            granted_access: if maximum { all_rights() } else { want },
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

    // Owner implicitly gets READ_CONTROL (spec §9.6).
    if sd.owner.as_ref() == Some(&token.user) {
        granted |= READ_CONTROL;
    }

    match &sd.dacl {
        None => {
            // Null DACL grants all access (spec §9.5).
            granted |= if maximum { all_rights() } else { want };
        }
        Some(acl) => {
            let allow_sids = token.allow_sids();
            let deny_sids = token.deny_sids();
            let mut denied_bits: AccessMask = 0;
            for ace in &acl.aces {
                if ace.inherit_only {
                    continue;
                }
                match ace.ace_type {
                    AceType::AccessDenied => {
                        if deny_sids.iter().any(|s| **s == ace.sid) {
                            if maximum {
                                denied_bits |= ace.mask & !granted;
                            } else if ace.mask & want & !granted != 0 {
                                // A still-wanted, not-yet-granted right is explicitly denied.
                                return denied();
                            }
                        }
                    }
                    AceType::AccessAllowed => {
                        if allow_sids.iter().any(|s| **s == ace.sid) {
                            let add = ace.mask & !denied_bits;
                            granted |= if maximum { add } else { add & want };
                        }
                    }
                    AceType::SystemAudit => {} // stored only (spec §7.7)
                }
                if !maximum && want & !granted == 0 {
                    break;
                }
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
            granted_access: want,
            privileges_used,
        }
    } else {
        denied()
    }
}

fn denied() -> AccessCheckResult {
    AccessCheckResult {
        status: STATUS_ACCESS_DENIED,
        granted_access: 0,
        privileges_used: Vec::new(),
    }
}

fn all_rights() -> AccessMask {
    DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE | 0xFFFF
}

/// A privilege-only check (spec §9.7), e.g. `SeLoadDriverPrivilege` for the driver-load path.
pub fn privilege_check(token: &AccessToken, privilege: &str) -> Result<(), u32> {
    if token.has_privilege(privilege) {
        Ok(())
    } else {
        Err(STATUS_PRIVILEGE_NOT_HELD)
    }
}
