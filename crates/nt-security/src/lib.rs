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
pub mod create_token;
mod native_acl;
mod native_sd;
mod port;
pub mod se_exports;
mod sid;
mod token;
mod token_filter;
mod token_info;
mod token_set;

pub use access::{
    access_check, access_check_by_type, check_token_privileges, map_token_access, privilege_check,
    validate_object_type_list, AccessCheckResult, AccessMask, Ace, AceType, Acl, GenericMapping,
    ObjectTypeEntry, ObjectTypeGuid, ProcessorMode, SecurityDescriptor, ACCESS_MAX_LEVEL,
    ACCESS_SYSTEM_SECURITY, DELETE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    MAXIMUM_ALLOWED, READ_CONTROL, STATUS_ACCESS_DENIED, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS,
    SYNCHRONIZE, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ADJUST_SESSIONID, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_EXECUTE,
    TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_QUERY_SOURCE, TOKEN_READ, TOKEN_WRITE, WRITE_DAC,
    WRITE_OWNER,
};
pub use create_token::{
    capture_acl, capture_luid_and_attributes_array, capture_sid, capture_sid_and_attributes_array,
    capture_token, luid_for_privilege_name, CapturedToken, ClientMemory, CreateTokenArgs,
    MAX_CAPTURED_GROUPS, MAX_CAPTURED_PRIVILEGES, TOKEN_GROUPS_ARRAY_OFFSET,
    TOKEN_PRIVILEGES_ARRAY_OFFSET,
};
pub use native_acl::{NativeAcl, NativeAclError, STATUS_INVALID_ACL};
pub use native_sd::{
    capture_object_type_list, capture_security_descriptor, capture_security_descriptor_bytes,
    native_acl_to_acl, query_security_descriptor_bytes, set_security_descriptor_bytes,
    DACL_SECURITY_INFORMATION, DEFAULT_KEY_SECURITY_DESCRIPTOR, GROUP_SECURITY_INFORMATION,
    MAX_CAPTURED_OBJECT_TYPES, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, STATUS_DATATYPE_MISALIGNMENT,
    STATUS_INVALID_SECURITY_DESCR, STATUS_UNKNOWN_REVISION, UNPROTECTED_DACL_SECURITY_INFORMATION,
    UNPROTECTED_SACL_SECURITY_INFORMATION,
};
pub use port::{
    validate_secure_port_connect, SecurePortConnectSecurity, STATUS_SERVER_SID_MISMATCH,
};
pub use sid::{write_native_sid_sddl_utf16, Luid, Sid, STATUS_INVALID_SID};
pub use token::{
    plan_client_impersonation, token_can_impersonate, AccessToken, AnonymousLogonTokenIds,
    ClientImpersonationPlan, GroupAdjustment, GroupAdjustmentPlan, GroupAdjustmentSummary,
    PrivilegeAdjustment, PrivilegeAdjustmentSummary, SecurityContextTrackingMode,
    SecurityImpersonationLevel, SecurityQualityOfService, TokenAuditPolicy, TokenGroup, TokenId,
    TokenPrivilege, TokenSource, TokenStatistics, TokenStore, TokenType, SE_ASSIGN_PRIMARY_TOKEN,
    SE_AUDIT, SE_BACKUP, SE_CHANGE_NOTIFY, SE_CREATE_GLOBAL, SE_CREATE_PAGEFILE,
    SE_CREATE_PERMANENT, SE_CREATE_TOKEN, SE_DEBUG, SE_IMPERSONATE, SE_INCREASE_BASE_PRIORITY,
    SE_INCREASE_QUOTA, SE_LOAD_DRIVER, SE_LOCK_MEMORY, SE_MANAGE_VOLUME, SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SE_PRIVILEGE_USED_FOR_ACCESS,
    SE_PROFILE_SINGLE_PROCESS, SE_RESTORE, SE_SECURITY, SE_SHUTDOWN, SE_SYSTEM_ENVIRONMENT,
    SE_SYSTEM_TIME, SE_TAKE_OWNERSHIP, SE_TCB, SE_UNDOCK, STATUS_ALLOTTED_SPACE_EXCEEDED,
    STATUS_BAD_IMPERSONATION_LEVEL, STATUS_BAD_TOKEN_TYPE, STATUS_CANT_DISABLE_MANDATORY,
    STATUS_CANT_ENABLE_DENY_ONLY, STATUS_INVALID_OWNER, STATUS_INVALID_PARAMETER,
    STATUS_INVALID_PRIMARY_GROUP, TOKEN_AUDIT_CATEGORY_COUNT,
};
pub use token_filter::{
    filter_access_token, TokenFilterRequest, DISABLE_MAX_PRIVILEGE, SANDBOX_INERT,
    TOKEN_FILTER_VALID_FLAGS,
};
pub use token_info::{
    encode_token_default_dacl, encode_token_group_entries, encode_token_groups,
    encode_token_groups_and_privileges, encode_token_owner, encode_token_restricted_sids,
    encode_token_statistics, InvalidTokenSid, TokenInformationEncoding, SID_AND_ATTRIBUTES_LENGTH,
    TOKEN_GROUPS_AND_PRIVILEGES_LENGTH, TOKEN_STATISTICS_LENGTH,
};
pub use token_set::{
    plan_token_information_set, TokenSetInformationClass, TokenSetInformationPlan,
};

#[cfg(test)]
mod tests;
