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
    AccessToken, TokenGroup, TokenPrivilege, TokenType, SE_BACKUP, SE_CHANGE_NOTIFY, SE_DEBUG,
    SE_IMPERSONATE, SE_LOAD_DRIVER, SE_RESTORE, SE_SECURITY, SE_TAKE_OWNERSHIP, SE_TCB,
};

#[cfg(test)]
mod tests;
