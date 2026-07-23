//! Access tokens (spec §7.2-§7.4) + the default System/Admin/User tokens (spec §17).

use alloc::vec;
use alloc::vec::Vec;

use crate::native_acl::NativeAcl;
use crate::sid::{Luid, Sid};

/// Token type (spec §7.2).
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TokenType {
    Primary = 1,
    Impersonation = 2,
}

/// Native `SECURITY_IMPERSONATION_LEVEL` ordering.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityImpersonationLevel {
    Anonymous = 0,
    Identification = 1,
    Impersonation = 2,
    Delegation = 3,
}

impl TryFrom<u32> for SecurityImpersonationLevel {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Anonymous),
            1 => Ok(Self::Identification),
            2 => Ok(Self::Impersonation),
            3 => Ok(Self::Delegation),
            _ => Err(STATUS_BAD_IMPERSONATION_LEVEL),
        }
    }
}

pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_OWNER: u32 = 0xC000_005A;
pub const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;
pub const STATUS_BAD_TOKEN_TYPE: u32 = 0xC000_00A8;
pub const STATUS_ALLOTTED_SPACE_EXCEEDED: u32 = 0xC000_0099;

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

    pub fn enabled_owner(sid: Sid) -> Self {
        TokenGroup {
            sid,
            enabled: true,
            deny_only: false,
            owner: true,
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
    /// Meaningful for impersonation tokens; primary tokens keep this at `Anonymous`.
    pub impersonation_level: SecurityImpersonationLevel,
    pub user: Sid,
    pub groups: Vec<TokenGroup>,
    pub privileges: Vec<TokenPrivilege>,
    pub owner: Sid,
    pub primary_group: Sid,
    /// Lossless native default ACL. `None` is the distinct null-default-DACL state.
    pub default_dacl: Option<NativeAcl>,
    pub session_id: u32,
    pub authentication_id: Luid,
}

impl AccessToken {
    /// Duplicate this token using the native token type, impersonation-level, and effective-only
    /// rules. The returned token owns independent group and privilege vectors.
    pub fn duplicate(
        &self,
        token_type: TokenType,
        impersonation_level: SecurityImpersonationLevel,
        effective_only: bool,
    ) -> Result<Self, u32> {
        if self.token_type == TokenType::Impersonation {
            if impersonation_level > self.impersonation_level
                || (token_type == TokenType::Primary
                    && self.impersonation_level < SecurityImpersonationLevel::Impersonation)
            {
                return Err(STATUS_BAD_IMPERSONATION_LEVEL);
            }
        }

        let mut duplicate = self.clone();
        duplicate.token_type = token_type;
        duplicate.impersonation_level = if token_type == TokenType::Impersonation {
            impersonation_level
        } else {
            SecurityImpersonationLevel::Anonymous
        };
        if effective_only {
            duplicate.groups.retain(|group| group.enabled);
            duplicate.privileges.retain(|privilege| privilege.enabled);
        }
        Ok(duplicate)
    }

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
            impersonation_level: SecurityImpersonationLevel::Anonymous,
            user: Sid::local_system(),
            groups: vec![
                TokenGroup::enabled_owner(Sid::administrators()),
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
            default_dacl: Some(NativeAcl::system_default()),
            session_id: 0,
            authentication_id: Luid::new(0x3e7), // SYSTEM_LUID
        }
    }

    /// An administrator token (spec §17.2): Administrators + Users groups, load-driver/debug.
    pub fn admin(machine: u32) -> Self {
        AccessToken {
            token_type: TokenType::Primary,
            impersonation_level: SecurityImpersonationLevel::Anonymous,
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
            default_dacl: None,
            session_id: 1,
            authentication_id: Luid::new(0x1_0000),
        }
    }

    /// A standard user token (spec §17.3): Users + Everyone, only change-notify.
    pub fn user(machine: u32) -> Self {
        AccessToken {
            token_type: TokenType::Primary,
            impersonation_level: SecurityImpersonationLevel::Anonymous,
            user: Sid::local_account(machine, 1000),
            groups: vec![
                TokenGroup::enabled(Sid::users()),
                TokenGroup::enabled(Sid::authenticated_users()),
                TokenGroup::enabled(Sid::everyone()),
            ],
            privileges: vec![Self::priv_enabled(SE_CHANGE_NOTIFY, 23)],
            owner: Sid::local_account(machine, 1000),
            primary_group: Sid::users(),
            default_dacl: None,
            session_id: 1,
            authentication_id: Luid::new(0x2_0000),
        }
    }
}

/// Stable identity for one token object in a [`TokenStore`]. Zero is never valid.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenId(u32);

impl TokenId {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    fn slot(self) -> usize {
        self.0 as usize - 1
    }
}

#[derive(Clone, Debug)]
struct TokenObject {
    token: AccessToken,
    references: u32,
    token_luid: Luid,
    modified_luid: Luid,
    expiration_time: i64,
    dynamic_charged: u32,
}

/// The fixed native fields returned for `TokenStatistics`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TokenStatistics {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub expiration_time: i64,
    pub token_type: TokenType,
    pub impersonation_level: SecurityImpersonationLevel,
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
    pub group_count: u32,
    pub privilege_count: u32,
    pub modified_id: Luid,
}

/// Monotonic token-object arena. Process fields, thread impersonation contexts, and handles each
/// hold an explicit reference, so closing the handle used to assign a thread token cannot destroy
/// the thread's effective security context.
#[derive(Clone, Debug)]
pub struct TokenStore {
    objects: Vec<Option<TokenObject>>,
    next_luid: u64,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self {
            objects: Vec::new(),
            next_luid: 1,
        }
    }
}

impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            objects: Vec::with_capacity(capacity),
            next_luid: 1,
        }
    }

    /// Insert a token with one owning reference.
    pub fn insert(&mut self, token: AccessToken) -> TokenId {
        let token_luid = self.allocate_luid();
        let modified_luid = self.allocate_luid();
        let dynamic_charged = dynamic_usage(&token).max(500) as u32;
        self.objects.push(Some(TokenObject {
            token,
            references: 1,
            token_luid,
            modified_luid,
            expiration_time: -1,
            dynamic_charged,
        }));
        TokenId(self.objects.len() as u32)
    }

    pub fn get(&self, id: TokenId) -> Option<&AccessToken> {
        self.objects
            .get(id.slot())?
            .as_ref()
            .map(|entry| &entry.token)
    }

    pub fn reference_count(&self, id: TokenId) -> Option<u32> {
        self.objects
            .get(id.slot())?
            .as_ref()
            .map(|entry| entry.references)
    }

    pub fn retain(&mut self, id: TokenId) -> Result<(), u32> {
        let entry = self
            .objects
            .get_mut(id.slot())
            .and_then(Option::as_mut)
            .ok_or(STATUS_INVALID_HANDLE)?;
        entry.references = entry
            .references
            .checked_add(1)
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(())
    }

    /// Release one reference. Returns `true` when the object was destroyed.
    pub fn release(&mut self, id: TokenId) -> Result<bool, u32> {
        let slot = id.slot();
        let entry = self
            .objects
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if entry.references > 1 {
            entry.references -= 1;
            return Ok(false);
        }
        self.objects[slot] = None;
        Ok(true)
    }

    /// Create an independent token object with one owning reference.
    pub fn duplicate(
        &mut self,
        source: TokenId,
        token_type: TokenType,
        impersonation_level: SecurityImpersonationLevel,
        effective_only: bool,
    ) -> Result<TokenId, u32> {
        let (duplicate, modified_luid, expiration_time, dynamic_charged) = {
            let source = self
                .objects
                .get(source.slot())
                .and_then(Option::as_ref)
                .ok_or(STATUS_INVALID_HANDLE)?;
            (
                source
                    .token
                    .duplicate(token_type, impersonation_level, effective_only)?,
                source.modified_luid,
                source.expiration_time,
                source.dynamic_charged,
            )
        };
        let token_luid = self.allocate_luid();
        self.objects.push(Some(TokenObject {
            token: duplicate,
            references: 1,
            token_luid,
            modified_luid,
            expiration_time,
            dynamic_charged,
        }));
        Ok(TokenId(self.objects.len() as u32))
    }

    /// Apply privilege changes and advance `ModifiedId` only when token state changed.
    pub fn adjust_privileges(
        &mut self,
        id: TokenId,
        disable_all: bool,
        requested: &[PrivilegeAdjustment],
        previous: &mut [PrivilegeAdjustment],
    ) -> Result<PrivilegeAdjustmentSummary, u32> {
        let slot = id.slot();
        let result = self
            .objects
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(STATUS_INVALID_HANDLE)?
            .token
            .adjust_privileges(disable_all, requested, previous);
        if result.changed != 0 {
            let modified_luid = self.allocate_luid();
            self.objects[slot]
                .as_mut()
                .expect("validated token object disappeared")
                .modified_luid = modified_luid;
        }
        Ok(result)
    }

    /// Set the token owner to the user or a group carrying `SE_GROUP_OWNER`.
    pub fn set_owner(&mut self, id: TokenId, owner: Sid) -> Result<(), u32> {
        let slot = id.slot();
        {
            let token = &self
                .objects
                .get(slot)
                .and_then(Option::as_ref)
                .ok_or(STATUS_INVALID_HANDLE)?
                .token;
            let valid = token.user == owner
                || token
                    .groups
                    .iter()
                    .any(|group| group.owner && group.sid == owner);
            if !valid {
                return Err(STATUS_INVALID_OWNER);
            }
        }
        let modified_luid = self.allocate_luid();
        let object = self.objects[slot]
            .as_mut()
            .expect("validated token object disappeared");
        object.token.owner = owner;
        object.modified_luid = modified_luid;
        Ok(())
    }

    /// Replace the token default DACL within its fixed dynamic-space charge.
    pub fn set_default_dacl(
        &mut self,
        id: TokenId,
        default_dacl: Option<NativeAcl>,
    ) -> Result<(), u32> {
        let slot = id.slot();
        let object = self
            .objects
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let usage = object
            .token
            .primary_group
            .native_len()
            .unwrap_or(0)
            .saturating_add(
                default_dacl
                    .as_ref()
                    .map_or(0, |acl| acl.acl_size() as usize),
            );
        if usage > object.dynamic_charged as usize {
            return Err(STATUS_ALLOTTED_SPACE_EXCEEDED);
        }
        if default_dacl.is_none() && object.token.default_dacl.is_none() {
            return Ok(());
        }

        let modified_luid = self.allocate_luid();
        let object = self.objects[slot]
            .as_mut()
            .expect("validated token object disappeared");
        object.token.default_dacl = default_dacl;
        object.modified_luid = modified_luid;
        Ok(())
    }

    /// Return the query-visible metadata and dynamic-space accounting for a token.
    pub fn statistics(&self, id: TokenId) -> Option<TokenStatistics> {
        let object = self.objects.get(id.slot())?.as_ref()?;
        let usage = dynamic_usage(&object.token) as u32;
        Some(TokenStatistics {
            token_id: object.token_luid,
            authentication_id: object.token.authentication_id,
            expiration_time: object.expiration_time,
            token_type: object.token.token_type,
            impersonation_level: object.token.impersonation_level,
            dynamic_charged: object.dynamic_charged,
            dynamic_available: object.dynamic_charged.saturating_sub(usage),
            group_count: object.token.groups.len() as u32,
            privilege_count: object.token.privileges.len() as u32,
            modified_id: object.modified_luid,
        })
    }

    fn allocate_luid(&mut self) -> Luid {
        let value = self.next_luid;
        self.next_luid = self.next_luid.wrapping_add(1);
        if self.next_luid == 0 {
            self.next_luid = 1;
        }
        Luid {
            low: value as u32,
            high: (value >> 32) as i32,
        }
    }
}

fn dynamic_usage(token: &AccessToken) -> usize {
    token.primary_group.native_len().unwrap_or(0)
        + token
            .default_dacl
            .as_ref()
            .map_or(0, |acl| acl.acl_size() as usize)
}
