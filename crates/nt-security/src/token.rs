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

    fn priv_enabled(name: &'static str, low: u32) -> TokenPrivilege {
        TokenPrivilege {
            name,
            luid: Luid::new(low),
            enabled: true,
        }
    }

    /// The `LocalSystem` token (spec §17.1): all privileges, Administrators + Everyone groups.
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
                Self::priv_enabled(SE_SECURITY, 8),
                Self::priv_enabled(SE_TAKE_OWNERSHIP, 9),
                Self::priv_enabled(SE_LOAD_DRIVER, 10),
                Self::priv_enabled(SE_BACKUP, 17),
                Self::priv_enabled(SE_RESTORE, 18),
                Self::priv_enabled(SE_SHUTDOWN, 19),
                Self::priv_enabled(SE_DEBUG, 20),
                Self::priv_enabled(SE_CHANGE_NOTIFY, 23),
                Self::priv_enabled(SE_IMPERSONATE, 29),
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
