//! Access tokens (spec §7.2-§7.4) + the default System/Admin/User tokens (spec §17).

use alloc::vec;
use alloc::vec::Vec;

use crate::sid::{Luid, Sid};

/// Token type (spec §7.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TokenType {
    Primary,
    Impersonation,
}

/// A group in a token (spec §7.3). v0.1 attributes: enabled / deny-only / owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenGroup {
    pub sid: Sid,
    pub enabled: bool,
    pub deny_only: bool,
    pub owner: bool,
}

impl TokenGroup {
    pub fn enabled(sid: Sid) -> Self {
        TokenGroup {
            sid,
            enabled: true,
            deny_only: false,
            owner: false,
        }
    }
    pub fn deny_only(sid: Sid) -> Self {
        TokenGroup {
            sid,
            enabled: false,
            deny_only: true,
            owner: false,
        }
    }
}

/// A privilege in a token (spec §7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPrivilege {
    pub name: &'static str,
    pub luid: Luid,
    pub enabled: bool,
    pub enabled_by_default: bool,
}

pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x0000_0001;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
pub const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;

/// One `LUID_AND_ATTRIBUTES` entry used by the native token APIs.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivilegeAdjustment {
    pub luid: Luid,
    pub attributes: u32,
}

/// Result of planning or applying an `NtAdjustPrivilegesToken` request.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivilegeAdjustmentSummary {
    pub matched: usize,
    pub changed: usize,
}

// Required privilege names (spec §7.4).
pub const SE_CHANGE_NOTIFY: &str = "SeChangeNotifyPrivilege";
pub const SE_DEBUG: &str = "SeDebugPrivilege";
pub const SE_BACKUP: &str = "SeBackupPrivilege";
pub const SE_RESTORE: &str = "SeRestorePrivilege";
pub const SE_LOAD_DRIVER: &str = "SeLoadDriverPrivilege";
pub const SE_SECURITY: &str = "SeSecurityPrivilege";
pub const SE_TAKE_OWNERSHIP: &str = "SeTakeOwnershipPrivilege";
pub const SE_TCB: &str = "SeTcbPrivilege";
pub const SE_IMPERSONATE: &str = "SeImpersonatePrivilege";
pub const SE_SHUTDOWN: &str = "SeShutdownPrivilege";
pub const SE_CREATE_TOKEN: &str = "SeCreateTokenPrivilege";
pub const SE_ASSIGN_PRIMARY_TOKEN: &str = "SeAssignPrimaryTokenPrivilege";
pub const SE_LOCK_MEMORY: &str = "SeLockMemoryPrivilege";
pub const SE_INCREASE_QUOTA: &str = "SeIncreaseQuotaPrivilege";
pub const SE_SYSTEM_TIME: &str = "SeSystemtimePrivilege";
pub const SE_PROFILE_SINGLE_PROCESS: &str = "SeProfileSingleProcessPrivilege";
pub const SE_INCREASE_BASE_PRIORITY: &str = "SeIncreaseBasePriorityPrivilege";
pub const SE_CREATE_PAGEFILE: &str = "SeCreatePagefilePrivilege";
pub const SE_CREATE_PERMANENT: &str = "SeCreatePermanentPrivilege";
pub const SE_AUDIT: &str = "SeAuditPrivilege";
pub const SE_SYSTEM_ENVIRONMENT: &str = "SeSystemEnvironmentPrivilege";
pub const SE_UNDOCK: &str = "SeUndockPrivilege";
pub const SE_MANAGE_VOLUME: &str = "SeManageVolumePrivilege";
pub const SE_CREATE_GLOBAL: &str = "SeCreateGlobalPrivilege";

/// An access token — the subject's security identity (spec §7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessToken {
    pub token_type: TokenType,
    pub user: Sid,
    pub groups: Vec<TokenGroup>,
    pub privileges: Vec<TokenPrivilege>,
    pub owner: Sid,
    pub primary_group: Sid,
    pub session_id: u32,
    pub authentication_id: Luid,
}

impl AccessToken {
    /// Whether the named privilege is present + enabled (spec §9.7).
    pub fn has_privilege(&self, name: &str) -> bool {
        self.privileges.iter().any(|p| p.name == name && p.enabled)
    }

    /// The SIDs that can satisfy an *allow* ACE: the user + enabled, non-deny-only groups.
    pub fn allow_sids(&self) -> Vec<&Sid> {
        let mut sids = vec![&self.user];
        for g in &self.groups {
            if g.enabled && !g.deny_only {
                sids.push(&g.sid);
            }
        }
        sids
    }

    /// The SIDs that can trigger a *deny* ACE: the user + every group (incl. deny-only).
    pub fn deny_sids(&self) -> Vec<&Sid> {
        let mut sids = vec![&self.user];
        for g in &self.groups {
            sids.push(&g.sid);
        }
        sids
    }

    fn privilege(name: &'static str, low: u32, enabled: bool) -> TokenPrivilege {
        TokenPrivilege {
            name,
            luid: Luid::new(low),
            enabled,
            enabled_by_default: enabled,
        }
    }

    fn priv_enabled(name: &'static str, low: u32) -> TokenPrivilege {
        Self::privilege(name, low, true)
    }

    /// Return the native attribute bits for a privilege currently in the token.
    pub fn privilege_attributes(privilege: &TokenPrivilege) -> u32 {
        (if privilege.enabled_by_default {
            SE_PRIVILEGE_ENABLED_BY_DEFAULT
        } else {
            0
        }) | if privilege.enabled {
            SE_PRIVILEGE_ENABLED
        } else {
            0
        }
    }

    /// Count matches and state changes without mutating the token.
    pub fn plan_privilege_adjustment(
        &self,
        disable_all: bool,
        requested: &[PrivilegeAdjustment],
    ) -> PrivilegeAdjustmentSummary {
        let mut summary = PrivilegeAdjustmentSummary::default();
        for privilege in &self.privileges {
            let requested_attributes = if disable_all {
                Some(0)
            } else {
                requested
                    .iter()
                    .find(|entry| entry.luid == privilege.luid)
                    .map(|entry| entry.attributes)
            };
            let Some(attributes) = requested_attributes else {
                continue;
            };
            summary.matched += 1;
            let remove = attributes & SE_PRIVILEGE_REMOVED != 0;
            let enable = attributes & SE_PRIVILEGE_ENABLED != 0;
            if remove || privilege.enabled != enable {
                summary.changed += 1;
            }
        }
        summary
    }

    /// Apply a previously sized privilege adjustment and return the old states that changed.
    /// `previous` must have room for the `changed` count returned by
    /// [`Self::plan_privilege_adjustment`].
    pub fn adjust_privileges(
        &mut self,
        disable_all: bool,
        requested: &[PrivilegeAdjustment],
        previous: &mut [PrivilegeAdjustment],
    ) -> PrivilegeAdjustmentSummary {
        let mut summary = PrivilegeAdjustmentSummary::default();
        let mut index = 0;
        while index < self.privileges.len() {
            let requested_attributes = if disable_all {
                Some(0)
            } else {
                requested
                    .iter()
                    .find(|entry| entry.luid == self.privileges[index].luid)
                    .map(|entry| entry.attributes)
            };
            let Some(attributes) = requested_attributes else {
                index += 1;
                continue;
            };
            summary.matched += 1;
            let remove = attributes & SE_PRIVILEGE_REMOVED != 0;
            let enable = attributes & SE_PRIVILEGE_ENABLED != 0;
            if remove || self.privileges[index].enabled != enable {
                if let Some(slot) = previous.get_mut(summary.changed) {
                    *slot = PrivilegeAdjustment {
                        luid: self.privileges[index].luid,
                        attributes: Self::privilege_attributes(&self.privileges[index]),
                    };
                }
                summary.changed += 1;
                if remove {
                    self.privileges.remove(index);
                    continue;
                }
                self.privileges[index].enabled = enable;
            }
            index += 1;
        }
        summary
    }

    /// The ReactOS `LocalSystem` primary token, including its exact initial privilege states.
    pub fn system() -> Self {
        AccessToken {
            token_type: TokenType::Primary,
            user: Sid::local_system(),
            groups: vec![
                TokenGroup::enabled(Sid::administrators()),
                TokenGroup::enabled(Sid::authenticated_users()),
                TokenGroup::enabled(Sid::everyone()),
            ],
            privileges: vec![
                Self::priv_enabled(SE_TCB, 7),
                Self::privilege(SE_CREATE_TOKEN, 2, false),
                Self::privilege(SE_TAKE_OWNERSHIP, 9, false),
                Self::priv_enabled(SE_CREATE_PAGEFILE, 15),
                Self::priv_enabled(SE_LOCK_MEMORY, 4),
                Self::privilege(SE_ASSIGN_PRIMARY_TOKEN, 3, false),
                Self::privilege(SE_INCREASE_QUOTA, 5, false),
                Self::priv_enabled(SE_INCREASE_BASE_PRIORITY, 14),
                Self::priv_enabled(SE_CREATE_PERMANENT, 16),
                Self::priv_enabled(SE_DEBUG, 20),
                Self::priv_enabled(SE_AUDIT, 21),
                Self::privilege(SE_SECURITY, 8, false),
                Self::privilege(SE_SYSTEM_ENVIRONMENT, 22, false),
                Self::priv_enabled(SE_CHANGE_NOTIFY, 23),
                Self::privilege(SE_BACKUP, 17, false),
                Self::privilege(SE_RESTORE, 18, false),
                Self::privilege(SE_SHUTDOWN, 19, false),
                Self::privilege(SE_LOAD_DRIVER, 10, false),
                Self::priv_enabled(SE_PROFILE_SINGLE_PROCESS, 13),
                Self::privilege(SE_SYSTEM_TIME, 12, false),
                Self::privilege(SE_UNDOCK, 25, false),
                Self::privilege(SE_MANAGE_VOLUME, 28, false),
                Self::priv_enabled(SE_IMPERSONATE, 29),
                Self::priv_enabled(SE_CREATE_GLOBAL, 30),
            ],
            owner: Sid::administrators(),
            primary_group: Sid::local_system(),
            session_id: 0,
            authentication_id: Luid::new(0x3e7), // SYSTEM_LUID
        }
    }

    /// An administrator token (spec §17.2): Administrators + Users groups, load-driver/debug.
    pub fn admin(machine: u32) -> Self {
        AccessToken {
            token_type: TokenType::Primary,
            user: Sid::local_account(machine, 1001),
            groups: vec![
                TokenGroup::enabled(Sid::administrators()),
                TokenGroup::enabled(Sid::users()),
                TokenGroup::enabled(Sid::authenticated_users()),
                TokenGroup::enabled(Sid::everyone()),
            ],
            privileges: vec![
                Self::priv_enabled(SE_LOAD_DRIVER, 10),
                Self::priv_enabled(SE_TAKE_OWNERSHIP, 9),
                Self::priv_enabled(SE_DEBUG, 20),
                Self::priv_enabled(SE_CHANGE_NOTIFY, 23),
            ],
            owner: Sid::local_account(machine, 1001),
            primary_group: Sid::users(),
            session_id: 1,
            authentication_id: Luid::new(0x1_0000),
        }
    }

    /// A standard user token (spec §17.3): Users + Everyone, only change-notify.
    pub fn user(machine: u32) -> Self {
        AccessToken {
            token_type: TokenType::Primary,
            user: Sid::local_account(machine, 1000),
            groups: vec![
                TokenGroup::enabled(Sid::users()),
                TokenGroup::enabled(Sid::authenticated_users()),
                TokenGroup::enabled(Sid::everyone()),
            ],
            privileges: vec![Self::priv_enabled(SE_CHANGE_NOTIFY, 23)],
            owner: Sid::local_account(machine, 1000),
            primary_group: Sid::users(),
            session_id: 1,
            authentication_id: Luid::new(0x2_0000),
        }
    }
}
