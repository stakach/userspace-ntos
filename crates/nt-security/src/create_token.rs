//! `NtCreateToken` argument capture — the pure, host-testable half of the service.
//!
//! `NtCreateToken` is a **13-argument** system service whose interesting arguments are *pointers to
//! variable-length structures living in the caller's address space*:
//!
//! ```text
//! TOKEN_USER          { SID_AND_ATTRIBUTES User; }                       // 16 bytes
//! TOKEN_GROUPS        { ULONG GroupCount; SID_AND_ATTRIBUTES Groups[]; } // 8 + 16*GroupCount
//! TOKEN_PRIVILEGES    { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[]; } // 4 + 12*n
//! TOKEN_OWNER         { PSID Owner; }                                    // 8, OPTIONAL
//! TOKEN_PRIMARY_GROUP { PSID PrimaryGroup; }                             // 8
//! TOKEN_DEFAULT_DACL  { PACL DefaultDacl; }                              // 8, OPTIONAL
//! TOKEN_SOURCE        { CHAR SourceName[8]; LUID SourceIdentifier; }     // 16
//! ```
//!
//! Every `PSID`/`PACL` is a *second* indirection into the caller — so capturing a token means a
//! bounded walk of client memory, not one `memcpy`. This module is that walk, expressed against a
//! [`ClientMemory`] reader so the executive can plug in its cross-address-space reader while host
//! tests plug in a plain byte map. It is the analogue of ReactOS' `SeCaptureSidAndAttributesArray` /
//! `SeCaptureLuidAndAttributesArray` / `SepCaptureSid` / `SepCaptureAcl` capture stage
//! (`ntoskrnl/se/tokenlif.c:NtCreateToken`).
//!
//! **Fail closed.** Every read is length-checked, every count is bounded ([`MAX_CAPTURED_GROUPS`] /
//! [`MAX_CAPTURED_PRIVILEGES`]), every SID is structurally validated before its sub-authorities are
//! read, and every allocation goes through `try_reserve_exact`. A garbage `GroupCount` can only
//! produce an error status — never an over-read, never an unbounded allocation.

use alloc::vec::Vec;

use crate::native_acl::NativeAcl;
use crate::sid::{Luid, Sid};
use crate::token::{
    AccessToken, SecurityImpersonationLevel, TokenGroup, TokenPrivilege, TokenSource, TokenType,
    SE_ASSIGN_PRIMARY_TOKEN, SE_AUDIT, SE_BACKUP, SE_CHANGE_NOTIFY, SE_CREATE_GLOBAL,
    SE_CREATE_PAGEFILE, SE_CREATE_PERMANENT, SE_CREATE_TOKEN, SE_DEBUG, SE_ENABLE_DELEGATION,
    SE_IMPERSONATE, SE_INCREASE_BASE_PRIORITY, SE_INCREASE_QUOTA, SE_LOAD_DRIVER, SE_LOCK_MEMORY,
    SE_MACHINE_ACCOUNT, SE_MANAGE_VOLUME, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    SE_PROFILE_SINGLE_PROCESS, SE_REMOTE_SHUTDOWN, SE_RESTORE, SE_SECURITY, SE_SHUTDOWN,
    SE_SYNC_AGENT, SE_SYSTEM_ENVIRONMENT, SE_SYSTEM_PROFILE, SE_SYSTEM_TIME, SE_TAKE_OWNERSHIP,
    SE_TCB, SE_UNDOCK,
};

pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_SID: u32 = 0xC000_0078;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Native `SID_AND_ATTRIBUTES` stride on x64 (`PSID` + `ULONG` + 4 bytes of tail padding).
pub const SID_AND_ATTRIBUTES_SIZE: u64 = 16;
/// Native `LUID_AND_ATTRIBUTES` stride (`LUID` + `ULONG`, alignment 4 — no tail padding).
pub const LUID_AND_ATTRIBUTES_SIZE: u64 = 12;
/// Byte offset of `TOKEN_GROUPS::Groups` (the `ULONG` count is padded up to the array's alignment).
pub const TOKEN_GROUPS_ARRAY_OFFSET: u64 = 8;
/// Byte offset of `TOKEN_PRIVILEGES::Privileges` (alignment 4 — the array follows the count).
pub const TOKEN_PRIVILEGES_ARRAY_OFFSET: u64 = 4;

/// Upper bound on `TOKEN_GROUPS::GroupCount` we will capture. Real logon tokens carry well under a
/// dozen groups; the bound exists so a hostile or corrupt count fails closed instead of driving an
/// unbounded walk of client memory.
pub const MAX_CAPTURED_GROUPS: u32 = 4096;
/// Upper bound on `TOKEN_PRIVILEGES::PrivilegeCount`. See [`MAX_CAPTURED_GROUPS`].
pub const MAX_CAPTURED_PRIVILEGES: u32 = 4096;

// `SE_GROUP_*` attribute bits (`sdk/include/xdk/setypes.h`).
pub const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
pub const SE_GROUP_OWNER: u32 = 0x0000_0008;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
/// `SE_GROUP_LOGON_ID` — marks the logon SID of an interactive logon session (two bits, so a
/// simple `& SE_GROUP_LOGON_ID` test is not enough; the caller must compare the whole mask).
pub const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;

/// A bounded reader over the *calling process'* address space.
///
/// The executive implements this with its cross-address-space copy-in; host tests implement it over
/// a byte map. `read` must return `false` (and leave `dst` untouched or partially written — callers
/// never trust `dst` on `false`) when any byte of the range is not readable.
pub trait ClientMemory {
    fn read(&self, va: u64, dst: &mut [u8]) -> bool;
}

/// The raw pointer arguments of `NtCreateToken`, exactly as they arrive off the wide syscall's
/// register + client-stack argument vector. Nothing here is dereferenced until [`capture_token`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateTokenArgs {
    /// `TokenType` (arg 4) — `1 = TokenPrimary`, `2 = TokenImpersonation`.
    pub token_type: u32,
    /// `PLUID AuthenticationId` (arg 5).
    pub authentication_id: u64,
    /// `PLARGE_INTEGER ExpirationTime` (arg 6).
    pub expiration_time: u64,
    /// `PTOKEN_USER TokenUser` (arg 7).
    pub token_user: u64,
    /// `PTOKEN_GROUPS TokenGroups` (arg 8).
    pub token_groups: u64,
    /// `PTOKEN_PRIVILEGES TokenPrivileges` (arg 9).
    pub token_privileges: u64,
    /// `PTOKEN_OWNER TokenOwner` (arg 10, OPTIONAL — may be 0).
    pub token_owner: u64,
    /// `PTOKEN_PRIMARY_GROUP TokenPrimaryGroup` (arg 11).
    pub token_primary_group: u64,
    /// `PTOKEN_DEFAULT_DACL TokenDefaultDacl` (arg 12, OPTIONAL — may be 0).
    pub token_default_dacl: u64,
    /// `PTOKEN_SOURCE TokenSource` (arg 13).
    pub token_source: u64,
}

/// Everything `NtCreateToken` captured: the token body plus the two fields the token *object*
/// (not the token body) owns — its expiration time and its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedToken {
    pub token: AccessToken,
    pub expiration_time: i64,
    pub source: TokenSource,
    /// `GroupCount` as the caller stated it — captured so the service can report exactly what it
    /// was asked for alongside what it built.
    pub requested_group_count: u32,
    /// `PrivilegeCount` as the caller stated it.
    pub requested_privilege_count: u32,
}

/// Map a well-known privilege LUID (`SE_*_PRIVILEGE`, `sdk/include/ndk/setypes.h:36`) to its name.
///
/// The LUID is a token privilege's authoritative identity; the name is what
/// [`AccessToken::has_privilege`] matches on. A LUID outside the well-known range has no name in
/// this build and captures with an empty one — the LUID itself is still preserved losslessly, so
/// nothing is invented and nothing is dropped.
pub const fn privilege_name_for_luid(luid: Luid) -> Option<&'static str> {
    if luid.high != 0 {
        return None;
    }
    Some(match luid.low {
        2 => SE_CREATE_TOKEN,
        3 => SE_ASSIGN_PRIMARY_TOKEN,
        4 => SE_LOCK_MEMORY,
        5 => SE_INCREASE_QUOTA,
        6 => SE_MACHINE_ACCOUNT,
        7 => SE_TCB,
        8 => SE_SECURITY,
        9 => SE_TAKE_OWNERSHIP,
        10 => SE_LOAD_DRIVER,
        11 => SE_SYSTEM_PROFILE,
        12 => SE_SYSTEM_TIME,
        13 => SE_PROFILE_SINGLE_PROCESS,
        14 => SE_INCREASE_BASE_PRIORITY,
        15 => SE_CREATE_PAGEFILE,
        16 => SE_CREATE_PERMANENT,
        17 => SE_BACKUP,
        18 => SE_RESTORE,
        19 => SE_SHUTDOWN,
        20 => SE_DEBUG,
        21 => SE_AUDIT,
        22 => SE_SYSTEM_ENVIRONMENT,
        23 => SE_CHANGE_NOTIFY,
        24 => SE_REMOTE_SHUTDOWN,
        25 => SE_UNDOCK,
        26 => SE_SYNC_AGENT,
        27 => SE_ENABLE_DELEGATION,
        28 => SE_MANAGE_VOLUME,
        29 => SE_IMPERSONATE,
        30 => SE_CREATE_GLOBAL,
        _ => return None,
    })
}

/// Map a well-known privilege name back to its native LUID.
pub fn luid_for_privilege_name(name: &str) -> Option<Luid> {
    let low = match name {
        SE_CREATE_TOKEN => 2,
        SE_ASSIGN_PRIMARY_TOKEN => 3,
        SE_LOCK_MEMORY => 4,
        SE_INCREASE_QUOTA => 5,
        SE_MACHINE_ACCOUNT => 6,
        SE_TCB => 7,
        SE_SECURITY => 8,
        SE_TAKE_OWNERSHIP => 9,
        SE_LOAD_DRIVER => 10,
        SE_SYSTEM_PROFILE => 11,
        SE_SYSTEM_TIME => 12,
        SE_PROFILE_SINGLE_PROCESS => 13,
        SE_INCREASE_BASE_PRIORITY => 14,
        SE_CREATE_PAGEFILE => 15,
        SE_CREATE_PERMANENT => 16,
        SE_BACKUP => 17,
        SE_RESTORE => 18,
        SE_SHUTDOWN => 19,
        SE_DEBUG => 20,
        SE_AUDIT => 21,
        SE_SYSTEM_ENVIRONMENT => 22,
        SE_CHANGE_NOTIFY => 23,
        SE_REMOTE_SHUTDOWN => 24,
        SE_UNDOCK => 25,
        SE_SYNC_AGENT => 26,
        SE_ENABLE_DELEGATION => 27,
        SE_MANAGE_VOLUME => 28,
        SE_IMPERSONATE => 29,
        SE_CREATE_GLOBAL => 30,
        _ => return None,
    };
    Some(Luid::new(low))
}

/// Read one `PSID` **target** — the SID structure itself, at `va`.
///
/// Validates the fixed 8-byte header (`Revision` must be 1, `SubAuthorityCount` at most 15) BEFORE
/// reading the variable sub-authority tail, so a corrupt header can never widen the read.
pub fn capture_sid(memory: &dyn ClientMemory, va: u64) -> Result<Sid, u32> {
    if va == 0 {
        return Err(STATUS_INVALID_SID);
    }
    let mut header = [0u8; 8];
    if !memory.read(va, &mut header) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if header[0] != SID_REVISION || header[1] > SID_MAX_SUB_AUTHORITIES {
        return Err(STATUS_INVALID_SID);
    }
    let count = header[1] as usize;
    let mut sub_authorities = Vec::new();
    if sub_authorities.try_reserve_exact(count).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let mut tail = [0u8; SID_MAX_SUB_AUTHORITIES as usize * 4];
    let tail = &mut tail[..count * 4];
    if !tail.is_empty() {
        let Some(tail_va) = va.checked_add(8) else {
            return Err(STATUS_ACCESS_VIOLATION);
        };
        if !memory.read(tail_va, tail) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    for index in 0..count {
        sub_authorities.push(u32::from_le_bytes(
            tail[index * 4..index * 4 + 4]
                .try_into()
                .expect("sub-authority slice is 4 bytes"),
        ));
    }
    Ok(Sid {
        revision: header[0],
        identifier_authority: header[2..8]
            .try_into()
            .expect("identifier authority slice is 6 bytes"),
        sub_authorities,
    })
}

/// Read a `PSID` **field** at `va` (an 8-byte pointer) and then the SID it points at.
fn capture_sid_pointer(memory: &dyn ClientMemory, va: u64) -> Result<Sid, u32> {
    capture_sid(memory, read_u64(memory, va)?)
}

/// Read `count` `SID_AND_ATTRIBUTES` entries starting at `va`, dereferencing each `Sid` pointer.
pub fn capture_sid_and_attributes_array(
    memory: &dyn ClientMemory,
    va: u64,
    count: u32,
) -> Result<Vec<(Sid, u32)>, u32> {
    if count > MAX_CAPTURED_GROUPS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut captured = Vec::new();
    if captured.try_reserve_exact(count as usize).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    for index in 0..count as u64 {
        let Some(entry_va) = index
            .checked_mul(SID_AND_ATTRIBUTES_SIZE)
            .and_then(|offset| va.checked_add(offset))
        else {
            return Err(STATUS_ACCESS_VIOLATION);
        };
        let mut entry = [0u8; SID_AND_ATTRIBUTES_SIZE as usize];
        if !memory.read(entry_va, &mut entry) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let sid_pointer = u64::from_le_bytes(entry[0..8].try_into().expect("8-byte pointer"));
        let attributes = u32::from_le_bytes(entry[8..12].try_into().expect("4-byte attributes"));
        captured.push((capture_sid(memory, sid_pointer)?, attributes));
    }
    Ok(captured)
}

/// Read `count` `LUID_AND_ATTRIBUTES` entries starting at `va`. These are inline (no indirection).
pub fn capture_luid_and_attributes_array(
    memory: &dyn ClientMemory,
    va: u64,
    count: u32,
) -> Result<Vec<(Luid, u32)>, u32> {
    if count > MAX_CAPTURED_PRIVILEGES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut captured = Vec::new();
    if captured.try_reserve_exact(count as usize).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    for index in 0..count as u64 {
        let Some(entry_va) = index
            .checked_mul(LUID_AND_ATTRIBUTES_SIZE)
            .and_then(|offset| va.checked_add(offset))
        else {
            return Err(STATUS_ACCESS_VIOLATION);
        };
        let mut entry = [0u8; LUID_AND_ATTRIBUTES_SIZE as usize];
        if !memory.read(entry_va, &mut entry) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        captured.push((
            Luid {
                low: u32::from_le_bytes(entry[0..4].try_into().expect("4-byte LUID low")),
                high: i32::from_le_bytes(entry[4..8].try_into().expect("4-byte LUID high")),
            },
            u32::from_le_bytes(entry[8..12].try_into().expect("4-byte attributes")),
        ));
    }
    Ok(captured)
}

/// Read a `PACL` target at `va`: the 8-byte `ACL` header first (for its `AclSize`), then exactly
/// `AclSize` bytes, which [`NativeAcl::from_bytes`] validates ACE-by-ACE.
pub fn capture_acl(memory: &dyn ClientMemory, va: u64) -> Result<NativeAcl, u32> {
    let mut header = [0u8; 8];
    if va == 0 || !memory.read(va, &mut header) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    if acl_size < 8 {
        return Err(crate::native_acl::STATUS_INVALID_ACL);
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(acl_size).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    bytes.resize(acl_size, 0);
    if !memory.read(va, &mut bytes) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    NativeAcl::from_bytes(&bytes).map_err(|error| error.status())
}

fn read_u32(memory: &dyn ClientMemory, va: u64) -> Result<u32, u32> {
    let mut bytes = [0u8; 4];
    if va == 0 || !memory.read(va, &mut bytes) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(memory: &dyn ClientMemory, va: u64) -> Result<u64, u32> {
    let mut bytes = [0u8; 8];
    if va == 0 || !memory.read(va, &mut bytes) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(u64::from_le_bytes(bytes))
}

/// Translate one captured `SID_AND_ATTRIBUTES` group entry into a [`TokenGroup`].
///
/// `SE_GROUP_MANDATORY` forces the group enabled and enabled-by-default, exactly as
/// `SepCreateToken` does (`ntoskrnl/se/tokenlif.c:134`).
pub fn group_from_attributes(sid: Sid, attributes: u32) -> TokenGroup {
    let mandatory = attributes & SE_GROUP_MANDATORY != 0;
    TokenGroup::from_native_attributes(
        sid,
        attributes
            | if mandatory {
                SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT
            } else {
                0
            },
    )
}

/// Translate one captured `LUID_AND_ATTRIBUTES` privilege entry into a [`TokenPrivilege`].
pub fn privilege_from_attributes(luid: Luid, attributes: u32) -> TokenPrivilege {
    TokenPrivilege {
        name: privilege_name_for_luid(luid).unwrap_or(""),
        luid,
        enabled: attributes & SE_PRIVILEGE_ENABLED != 0,
        enabled_by_default: attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0,
    }
}

/// Capture a complete `NtCreateToken` request out of the caller's address space.
///
/// `impersonation_level` comes from `ObjectAttributes->SecurityQualityOfService` and is captured by
/// the caller (it is a different structure, shared with `NtDuplicateToken`). A primary token stores
/// `Anonymous`, matching [`AccessToken::duplicate`].
pub fn capture_token(
    memory: &dyn ClientMemory,
    args: &CreateTokenArgs,
    impersonation_level: SecurityImpersonationLevel,
) -> Result<CapturedToken, u32> {
    let token_type = match args.token_type {
        1 => TokenType::Primary,
        2 => TokenType::Impersonation,
        _ => return Err(crate::token::STATUS_BAD_TOKEN_TYPE),
    };

    // Fixed-size scalars first — they are the cheapest way to reject a garbage call.
    let authentication_id = Luid {
        low: read_u32(memory, args.authentication_id)?,
        high: read_u32(memory, args.authentication_id.wrapping_add(4))? as i32,
    };
    let expiration_time = read_u64(memory, args.expiration_time)? as i64;

    let mut source_bytes = [0u8; 16];
    if args.token_source == 0 || !memory.read(args.token_source, &mut source_bytes) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let source = TokenSource {
        name: source_bytes[0..8].try_into().expect("8-byte source name"),
        identifier: Luid {
            low: u32::from_le_bytes(source_bytes[8..12].try_into().expect("4-byte LUID low")),
            high: i32::from_le_bytes(source_bytes[12..16].try_into().expect("4-byte LUID high")),
        },
    };

    // TOKEN_USER — a single inline SID_AND_ATTRIBUTES.
    let (user, user_attributes) = capture_sid_and_attributes_array(memory, args.token_user, 1)?
        .pop()
        .ok_or(STATUS_INVALID_PARAMETER)?;

    // TOKEN_GROUPS — the count, then that many SID_AND_ATTRIBUTES.
    let requested_group_count = read_u32(memory, args.token_groups)?;
    let captured_groups = capture_sid_and_attributes_array(
        memory,
        args.token_groups.wrapping_add(TOKEN_GROUPS_ARRAY_OFFSET),
        requested_group_count,
    )?;
    let mut groups = Vec::new();
    if groups.try_reserve_exact(captured_groups.len()).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    for (sid, attributes) in captured_groups {
        groups.push(group_from_attributes(sid, attributes));
    }

    // TOKEN_PRIVILEGES — the count, then that many LUID_AND_ATTRIBUTES.
    let requested_privilege_count = read_u32(memory, args.token_privileges)?;
    let captured_privileges = capture_luid_and_attributes_array(
        memory,
        args.token_privileges
            .wrapping_add(TOKEN_PRIVILEGES_ARRAY_OFFSET),
        requested_privilege_count,
    )?;
    let mut privileges = Vec::new();
    if privileges
        .try_reserve_exact(captured_privileges.len())
        .is_err()
    {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    for (luid, attributes) in captured_privileges {
        privileges.push(privilege_from_attributes(luid, attributes));
    }

    // TOKEN_PRIMARY_GROUP is mandatory; TOKEN_OWNER and TOKEN_DEFAULT_DACL are optional. An absent
    // owner defaults to the user SID (the only SID a token is always allowed to own itself by).
    let primary_group = capture_sid_pointer(memory, args.token_primary_group)?;
    let owner = if args.token_owner == 0 {
        user.clone()
    } else {
        capture_sid_pointer(memory, args.token_owner)?
    };
    let default_dacl = if args.token_default_dacl == 0 {
        None
    } else {
        // TOKEN_DEFAULT_DACL { PACL DefaultDacl; } — a NULL inner pointer is the distinct
        // "null default DACL" state, not an error.
        match read_u64(memory, args.token_default_dacl) {
            Ok(0) => None,
            Ok(acl_va) => Some(capture_acl(memory, acl_va)?),
            Err(status) => return Err(status),
        }
    };

    Ok(CapturedToken {
        token: AccessToken {
            token_type,
            impersonation_level: if token_type == TokenType::Impersonation {
                impersonation_level
            } else {
                SecurityImpersonationLevel::Anonymous
            },
            user,
            user_attributes,
            groups,
            restricted_sids: Vec::new(),
            privileges,
            owner,
            primary_group,
            default_dacl,
            session_id: 0,
            authentication_id,
            // `SepCreateToken` zero-initializes this field. A logon authority may publish the
            // origin later through TokenOrigin; duplication preserves it thereafter.
            originating_logon_session: Luid::new(0),
            audit_policy: crate::TokenAuditPolicy::default(),
            sandbox_inert: false,
        },
        expiration_time,
        source,
        requested_group_count,
        requested_privilege_count,
    })
}
