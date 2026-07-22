//! # `nt-security` — Security Reference Monitor (tokens + access check)
//!
//! The NT Security Reference Monitor (spec: NT Security Reference Monitor + Tokens + Object
//! Access): [`Sid`]s (+ well-known SIDs), [`AccessToken`]s (users/groups/privileges, with default
//! [`AccessToken::system`]/[`AccessToken::admin`]/[`AccessToken::user`] tokens), [`SecurityDescriptor`]s
//! with [`Acl`]/[`Ace`], the access-mask + [`GenericMapping`] model, and the NT [`access_check`]
//! algorithm — deny-before-allow ACE evaluation, `MAXIMUM_ALLOWED`, null/empty DACL, owner rights,
//! privilege overrides, and `KernelMode` bypass. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

mod access;
pub mod se_exports;
mod sid;
mod token;

pub use access::{
    access_check, privilege_check, AccessCheckResult, AccessMask, Ace, AceType, Acl,
    GenericMapping, ProcessorMode, SecurityDescriptor, ACCESS_SYSTEM_SECURITY, DELETE, GENERIC_ALL,
    GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED, READ_CONTROL,
    STATUS_ACCESS_DENIED, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS, SYNCHRONIZE, WRITE_DAC,
    WRITE_OWNER,
};
pub use sid::{Luid, Sid};
pub use token::{
    AccessToken, PrivilegeAdjustment, PrivilegeAdjustmentSummary, SecurityImpersonationLevel,
    TokenGroup, TokenId, TokenPrivilege, TokenStore, TokenType, SE_ASSIGN_PRIMARY_TOKEN, SE_AUDIT,
    SE_BACKUP, SE_CHANGE_NOTIFY, SE_CREATE_GLOBAL, SE_CREATE_PAGEFILE, SE_CREATE_PERMANENT,
    SE_CREATE_TOKEN, SE_DEBUG, SE_IMPERSONATE, SE_INCREASE_BASE_PRIORITY, SE_INCREASE_QUOTA,
    SE_LOAD_DRIVER, SE_LOCK_MEMORY, SE_MANAGE_VOLUME, SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PROFILE_SINGLE_PROCESS, SE_RESTORE,
    SE_SECURITY, SE_SHUTDOWN, SE_SYSTEM_ENVIRONMENT, SE_SYSTEM_TIME, SE_TAKE_OWNERSHIP, SE_TCB,
    SE_UNDOCK, STATUS_BAD_IMPERSONATION_LEVEL, STATUS_BAD_TOKEN_TYPE,
};

#[cfg(test)]
mod tests;
