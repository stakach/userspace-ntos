//! `SeExports` — the kernel's exported security data table (`SE_EXPORTS`) as an allocation-free
//! raw-memory primitive, plus the `SUBJECT_SECURITY_CONTEXT` capture/lock/release helpers.
//!
//! ntoskrnl exports a single `PSE_EXPORTS SeExports` global (`references/nt5/base/ntos/inc/se.h`
//! `struct _SE_EXPORTS`) that drivers read to obtain the well-known SID pointers (`SeWorldSid`,
//! `SeLocalSystemSid`, `SeAliasAdminsSid`, …) and the well-known privilege `LUID`s (`SeTcbPrivilege`,
//! `SeSecurityPrivilege`, …) without hand-encoding them. win32k.sys imports `SeExports` as a data
//! export and dereferences it (e.g. building the default security descriptor for the window-station
//! / desktop objects, and the shared-section ACL). Its subject-context group
//! (`SeCaptureSubjectContext` / `SeLockSubjectContext` / `SeUnlockSubjectContext` /
//! `SeReleaseSubjectContext`) captures the caller's token identity around an access check.
//!
//! Like [`win32k_ob`](../../nt_object_manager/win32k_ob) and
//! [`kevent`](../../nt_kernel_exec/kevent), this is a **const, allocation-free** primitive: the
//! win32k host component's bump heap is spent by the time win32k runs, so the real
//! [`AccessToken`](crate::AccessToken)/[`Sid`](crate::Sid) types (which use `alloc`) cannot be used
//! at win32k runtime. This module instead exposes the well-known SIDs as fixed `const` byte blobs in
//! the exact in-memory SID encoding and lays out the `SE_EXPORTS` struct into caller-owned memory
//! with pointers into a caller-owned SID pool. The *definitions* (SID bytes, LUID values, struct
//! offsets) live here, host-tested; the win32k glue (placing the blobs in the DATA region, pointing
//! win32k's import cell at the struct) stays in the host component.
//!
//! Real semantics reference: `references/nt5/base/ntos/inc/se.h` (`SE_EXPORTS` layout),
//! `references/nt5/base/ntos/se/` (`SeCaptureSubjectContext`), `references/windows-kits/.../km/wdm.h`
//! (`SE_*_PRIVILEGE` LUID values).

use core::mem::size_of;

/// In-memory encoding of a well-known SID: `Revision(1) SubAuthorityCount(1)
/// IdentifierAuthority[6, big-endian] SubAuthority[Count, little-endian u32]`. Fixed 16-byte storage
/// (the largest well-known SID here has 2 sub-authorities = 8+2*4 = 16 bytes); the used length is
/// [`len`](WellKnownSid::len).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WellKnownSid {
    bytes: [u8; 16],
    len: u8,
}

impl WellKnownSid {
    /// Build a well-known SID from its identifier authority + sub-authorities. `subs.len()` must be
    /// `<= 2` (all the SIDs `SE_EXPORTS` carries fit). Encodes the authority big-endian into the low
    /// 6 bytes (byte [7] holds the common small authorities 0..5) and each sub-authority
    /// little-endian, matching the on-disk/in-memory SID format.
    pub const fn new(authority: u8, subs: &[u32]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0] = 1; // Revision
        bytes[1] = subs.len() as u8; // SubAuthorityCount
        bytes[7] = authority; // IdentifierAuthority[5] (big-endian; low byte)
                              // SubAuthority[] little-endian u32 starting at offset 8.
        let mut i = 0;
        while i < subs.len() {
            let s = subs[i];
            let off = 8 + i * 4;
            bytes[off] = s as u8;
            bytes[off + 1] = (s >> 8) as u8;
            bytes[off + 2] = (s >> 16) as u8;
            bytes[off + 3] = (s >> 24) as u8;
            i += 1;
        }
        WellKnownSid {
            bytes,
            len: (8 + subs.len() * 4) as u8,
        }
    }

    /// The encoded SID bytes (only the first [`len`](Self::len) are meaningful).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The encoded SID length in bytes (`8 + 4 * SubAuthorityCount`).
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// A SID is never zero-length (`Revision + Count + Authority` is 8 bytes minimum).
    pub fn is_empty(&self) -> bool {
        false
    }
}

// --- well-known SIDs `SE_EXPORTS` carries (se.h order) ----------------------------------------

/// `S-1-0-0` — the null SID (`SeNullSid`).
pub const NULL_SID: WellKnownSid = WellKnownSid::new(0, &[0]);
/// `S-1-1-0` — Everyone / World (`SeWorldSid`).
pub const WORLD_SID: WellKnownSid = WellKnownSid::new(1, &[0]);
/// `S-1-2-0` — Local (`SeLocalSid`).
pub const LOCAL_SID: WellKnownSid = WellKnownSid::new(2, &[0]);
/// `S-1-3-0` — Creator Owner (`SeCreatorOwnerSid`).
pub const CREATOR_OWNER_SID: WellKnownSid = WellKnownSid::new(3, &[0]);
/// `S-1-3-1` — Creator Group (`SeCreatorGroupSid`).
pub const CREATOR_GROUP_SID: WellKnownSid = WellKnownSid::new(3, &[1]);
/// `S-1-5` — the NT Authority itself (`SeNtAuthoritySid`; no sub-authorities).
pub const NT_AUTHORITY_SID: WellKnownSid = WellKnownSid::new(5, &[]);
/// `S-1-5-11` — Authenticated Users (`SeAuthenticatedUsersSid`).
pub const AUTHENTICATED_USERS_SID: WellKnownSid = WellKnownSid::new(5, &[11]);
/// `S-1-5-18` — Local System (`SeLocalSystemSid`).
pub const LOCAL_SYSTEM_SID: WellKnownSid = WellKnownSid::new(5, &[18]);
/// `S-1-5-19` — Local Service (`SeLocalServiceSid`).
pub const LOCAL_SERVICE_SID: WellKnownSid = WellKnownSid::new(5, &[19]);
/// `S-1-5-20` — Network Service (`SeNetworkServiceSid`).
pub const NETWORK_SERVICE_SID: WellKnownSid = WellKnownSid::new(5, &[20]);
/// `S-1-5-32-544` — Builtin Administrators (`SeAliasAdminsSid`).
pub const ALIAS_ADMINS_SID: WellKnownSid = WellKnownSid::new(5, &[32, 544]);
/// `S-1-5-32-545` — Builtin Users (`SeAliasUsersSid`).
pub const ALIAS_USERS_SID: WellKnownSid = WellKnownSid::new(5, &[32, 545]);

// --- well-known privilege LUID low-parts (wdm.h `SE_*_PRIVILEGE`) -----------------------------

/// `SE_TCB_PRIVILEGE` LUID low-part.
pub const LUID_TCB: u32 = 7;
/// `SE_SECURITY_PRIVILEGE` LUID low-part.
pub const LUID_SECURITY: u32 = 8;
/// `SE_TAKE_OWNERSHIP_PRIVILEGE` LUID low-part.
pub const LUID_TAKE_OWNERSHIP: u32 = 9;
/// `SE_LOAD_DRIVER_PRIVILEGE` LUID low-part.
pub const LUID_LOAD_DRIVER: u32 = 10;
/// `SE_CHANGE_NOTIFY_PRIVILEGE` LUID low-part.
pub const LUID_CHANGE_NOTIFY: u32 = 23;

// --- authentication LUID (logon session id) ---------------------------------------------------

/// `SYSTEM_LUID` — the well-known authentication (logon-session) LUID of the Local System account
/// (`0x000003E7`). `SeQueryAuthenticationIdToken(Token, *AuthenticationId)` returns this for the
/// SYSTEM subject that runs the win32k / smss / csrss init path. Matches
/// [`AccessToken::system`](crate::AccessToken)'s `authentication_id`.
pub const SYSTEM_AUTHENTICATION_LUID_LOW: u32 = 0x3e7;
/// High-part of [`SYSTEM_AUTHENTICATION_LUID_LOW`] (always 0 for the well-known LUIDs).
pub const SYSTEM_AUTHENTICATION_LUID_HIGH: i32 = 0;

// --- SE_EXPORTS struct layout (se.h) ----------------------------------------------------------

/// Byte offsets of the fields win32k / drivers read out of `SE_EXPORTS`. The first 23 members are
/// `LUID`s (8 bytes each, `0x00..0xB8`); the SID pointer members follow (8 bytes each). Values are
/// grounded in `references/nt5/base/ntos/inc/se.h` `struct _SE_EXPORTS`.
pub mod se_exports_offset {
    // Privilege LUIDs (each 8 bytes).
    /// `SeTcbPrivilege` — 6th LUID member.
    pub const TCB_PRIVILEGE: usize = 5 * 8;
    /// `SeSecurityPrivilege` — 7th LUID member.
    pub const SECURITY_PRIVILEGE: usize = 6 * 8;
    /// `SeTakeOwnershipPrivilege` — 8th LUID member.
    pub const TAKE_OWNERSHIP_PRIVILEGE: usize = 7 * 8;
    /// `SeLoadDriverPrivilege` — 9th LUID member.
    pub const LOAD_DRIVER_PRIVILEGE: usize = 8 * 8;
    /// `SeChangeNotifyPrivilege` — 22nd LUID member.
    pub const CHANGE_NOTIFY_PRIVILEGE: usize = 21 * 8;

    /// The 23 privilege `LUID`s occupy `0x00..PSID_BASE`.
    pub const PSID_BASE: usize = 23 * 8; // 0xB8

    // SID pointers (each 8 bytes), in se.h order after the LUIDs.
    /// `PSID SeNullSid`.
    pub const NULL_SID: usize = PSID_BASE; // 0xB8
    /// `PSID SeWorldSid`.
    pub const WORLD_SID: usize = PSID_BASE + 0x08; // 0xC0
    /// `PSID SeLocalSid`.
    pub const LOCAL_SID: usize = PSID_BASE + 0x10; // 0xC8
    /// `PSID SeCreatorOwnerSid`.
    pub const CREATOR_OWNER_SID: usize = PSID_BASE + 0x18; // 0xD0
    /// `PSID SeCreatorGroupSid`.
    pub const CREATOR_GROUP_SID: usize = PSID_BASE + 0x20; // 0xD8
    /// `PSID SeNtAuthoritySid`.
    pub const NT_AUTHORITY_SID: usize = PSID_BASE + 0x28; // 0xE0
    /// `PSID SeLocalSystemSid` (5 universal + 5 nt SIDs precede it: null,world,local,owner,group,
    /// ntauth,dialup,network,batch,interactive → it is the 11th SID pointer).
    pub const LOCAL_SYSTEM_SID: usize = PSID_BASE + 0x50; // 0x108
    /// `PSID SeAliasAdminsSid`.
    pub const ALIAS_ADMINS_SID: usize = PSID_BASE + 0x58; // 0x110
    /// `PSID SeAliasUsersSid`.
    pub const ALIAS_USERS_SID: usize = PSID_BASE + 0x60; // 0x118

    /// Total `SE_EXPORTS` size to reserve (rounded to include all members se.h defines, headroom).
    pub const STRUCT_SIZE: usize = 0x1A0;
}

/// A single (field-offset, SID) mapping the [`build_se_exports`] layout writes.
struct SidPlacement {
    /// The `SE_EXPORTS` field offset that holds the pointer to this SID.
    field_offset: usize,
    sid: WellKnownSid,
}

/// The SID pointer members `SE_EXPORTS` exposes, paired with their struct field offset. The order
/// here determines their placement in the SID pool.
const SID_PLACEMENTS: &[SidPlacement] = &[
    SidPlacement {
        field_offset: se_exports_offset::NULL_SID,
        sid: NULL_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::WORLD_SID,
        sid: WORLD_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::LOCAL_SID,
        sid: LOCAL_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::CREATOR_OWNER_SID,
        sid: CREATOR_OWNER_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::CREATOR_GROUP_SID,
        sid: CREATOR_GROUP_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::NT_AUTHORITY_SID,
        sid: NT_AUTHORITY_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::LOCAL_SYSTEM_SID,
        sid: LOCAL_SYSTEM_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::ALIAS_ADMINS_SID,
        sid: ALIAS_ADMINS_SID,
    },
    SidPlacement {
        field_offset: se_exports_offset::ALIAS_USERS_SID,
        sid: ALIAS_USERS_SID,
    },
];

/// The `(offset, luid_low)` privilege members `build_se_exports` writes (LUID high-part is 0).
const LUID_PLACEMENTS: &[(usize, u32)] = &[
    (se_exports_offset::TCB_PRIVILEGE, LUID_TCB),
    (se_exports_offset::SECURITY_PRIVILEGE, LUID_SECURITY),
    (
        se_exports_offset::TAKE_OWNERSHIP_PRIVILEGE,
        LUID_TAKE_OWNERSHIP,
    ),
    (se_exports_offset::LOAD_DRIVER_PRIVILEGE, LUID_LOAD_DRIVER),
    (
        se_exports_offset::CHANGE_NOTIFY_PRIVILEGE,
        LUID_CHANGE_NOTIFY,
    ),
];

/// Bytes to reserve for the SID pool that [`build_se_exports`] fills (each well-known SID rounded up
/// to its 16-byte slot for simple, aligned placement).
pub const SID_POOL_SIZE: usize = 16 * 16;

/// Lay out a real `SE_EXPORTS` into caller-owned memory.
///
/// `struct_ptr` receives the `SE_EXPORTS` struct ([`STRUCT_SIZE`](se_exports_offset::STRUCT_SIZE)
/// bytes, must be zeroed by the caller). `sid_pool` receives the encoded well-known SID blobs
/// ([`SID_POOL_SIZE`] bytes) and `sid_pool_va` is the address `struct_ptr`'s consumers will see that
/// pool at (so the written `PSID` pointers are correct in the consumer's address space — in this
/// single-AS host it equals `sid_pool as u64`). The privilege `LUID` members are written inline.
///
/// # Safety
/// `struct_ptr` must point to at least [`STRUCT_SIZE`](se_exports_offset::STRUCT_SIZE) writable,
/// zeroed bytes; `sid_pool` to at least [`SID_POOL_SIZE`] writable bytes; `sid_pool_va` must be the
/// address at which `sid_pool`'s bytes are visible to whoever dereferences the struct.
pub unsafe fn build_se_exports(struct_ptr: *mut u8, sid_pool: *mut u8, sid_pool_va: u64) {
    // Privilege LUIDs (low-part = value, high-part = 0).
    for &(off, low) in LUID_PLACEMENTS {
        core::ptr::write_unaligned(struct_ptr.add(off) as *mut u32, low);
        core::ptr::write_unaligned(struct_ptr.add(off + 4) as *mut u32, 0);
    }
    // SID blobs into the pool + their pointers into the struct.
    let mut pool_off = 0usize;
    for p in SID_PLACEMENTS {
        let bytes = p.sid.as_bytes();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), sid_pool.add(pool_off), bytes.len());
        core::ptr::write_unaligned(
            struct_ptr.add(p.field_offset) as *mut u64,
            sid_pool_va + pool_off as u64,
        );
        pool_off += 16; // fixed 16-byte slot per SID
    }
}

// --- SUBJECT_SECURITY_CONTEXT (se.h) ----------------------------------------------------------

/// x64 `SECURITY_SUBJECT_CONTEXT` layout (`references/nt5/base/ntos/inc/se.h`): four pointer/enum
/// members — `{ PVOID ClientToken; SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; PVOID
/// PrimaryToken; PVOID ProcessAuditId; }`. 0x20 bytes.
pub mod subject_context_offset {
    /// `PACCESS_TOKEN ClientToken` (impersonation token, or NULL when not impersonating).
    pub const CLIENT_TOKEN: usize = 0x00;
    /// `SECURITY_IMPERSONATION_LEVEL ImpersonationLevel`.
    pub const IMPERSONATION_LEVEL: usize = 0x08;
    /// `PACCESS_TOKEN PrimaryToken` (the process's primary token).
    pub const PRIMARY_TOKEN: usize = 0x10;
    /// `PVOID ProcessAuditId`.
    pub const PROCESS_AUDIT_ID: usize = 0x18;
    /// Total size of a captured subject context.
    pub const SIZE: usize = 0x20;
}

/// Capture a subject security context into caller-owned memory, modeling the **SYSTEM** subject
/// (the identity of the win32k / smss / csrss init path, which runs as Local System).
///
/// `SeCaptureSubjectContext` snapshots the current thread/process token identity into a
/// `SECURITY_SUBJECT_CONTEXT` for a subsequent access check. Here the init caller is Local System
/// with a primary token and no active impersonation, so `PrimaryToken = primary_token`,
/// `ClientToken = NULL`, `ImpersonationLevel = SecurityAnonymous(0)`. `primary_token` is an opaque
/// token handle/pointer the caller supplies (win32k stores + passes it back to the lock/release
/// helpers; it is never dereferenced by them).
///
/// # Safety
/// `ctx` must point to at least [`SIZE`](subject_context_offset::SIZE) writable bytes.
pub unsafe fn capture_system_subject_context(ctx: *mut u8, primary_token: u64) {
    use subject_context_offset as o;
    core::ptr::write_unaligned(ctx.add(o::CLIENT_TOKEN) as *mut u64, 0);
    core::ptr::write_unaligned(ctx.add(o::IMPERSONATION_LEVEL) as *mut u64, 0);
    core::ptr::write_unaligned(ctx.add(o::PRIMARY_TOKEN) as *mut u64, primary_token);
    core::ptr::write_unaligned(ctx.add(o::PROCESS_AUDIT_ID) as *mut u64, 0);
}

/// The effective client token of a captured subject context: the impersonation `ClientToken` if
/// present, else the `PrimaryToken` (`SeQuerySubjectContextToken` semantics).
///
/// # Safety
/// `ctx` must point to a captured [`SIZE`](subject_context_offset::SIZE)-byte subject context.
pub unsafe fn subject_context_token(ctx: *const u8) -> u64 {
    use subject_context_offset as o;
    let client = core::ptr::read_unaligned(ctx.add(o::CLIENT_TOKEN) as *const u64);
    if client != 0 {
        client
    } else {
        core::ptr::read_unaligned(ctx.add(o::PRIMARY_TOKEN) as *const u64)
    }
}

const _: () = assert!(se_exports_offset::PSID_BASE == 0xB8);
const _: () = assert!(subject_context_offset::SIZE == 0x20);
const _: () = assert!(size_of::<u64>() == 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_sid_encoding_matches_windows_format() {
        // S-1-5-18 (LocalSystem): Rev=1, Count=1, Auth=5, Sub[0]=18.
        let s = LOCAL_SYSTEM_SID;
        assert_eq!(s.len(), 12);
        assert_eq!(
            s.as_bytes(),
            &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            "LocalSystem S-1-5-18 in-memory encoding"
        );
        // S-1-5-32-544 (Administrators): Count=2, Sub={32,544}. 544 = 0x220.
        let a = ALIAS_ADMINS_SID;
        assert_eq!(a.len(), 16);
        assert_eq!(
            a.as_bytes(),
            &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0]
        );
        // S-1-1-0 (World): Count=1, Auth=1, Sub[0]=0.
        assert_eq!(WORLD_SID.as_bytes(), &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        // S-1-5 (NtAuthority): Count=0 → 8 bytes, no sub-authority.
        assert_eq!(NT_AUTHORITY_SID.len(), 8);
        assert_eq!(NT_AUTHORITY_SID.as_bytes(), &[1, 0, 0, 0, 0, 0, 0, 5]);
    }

    #[test]
    fn se_exports_layout_places_sids_and_luids() {
        let mut st = [0u8; se_exports_offset::STRUCT_SIZE];
        let mut pool = [0u8; SID_POOL_SIZE];
        let pool_va = pool.as_ptr() as u64; // single-AS host: pool VA == pool address
        unsafe {
            build_se_exports(st.as_mut_ptr(), pool.as_mut_ptr(), pool_va);
        }
        // Privilege LUIDs are written at their offsets.
        let rd_u32 =
            |off: usize| unsafe { core::ptr::read_unaligned(st.as_ptr().add(off) as *const u32) };
        assert_eq!(rd_u32(se_exports_offset::TCB_PRIVILEGE), LUID_TCB);
        assert_eq!(
            rd_u32(se_exports_offset::TCB_PRIVILEGE + 4),
            0,
            "LUID high-part"
        );
        assert_eq!(rd_u32(se_exports_offset::SECURITY_PRIVILEGE), LUID_SECURITY);
        assert_eq!(
            rd_u32(se_exports_offset::LOAD_DRIVER_PRIVILEGE),
            LUID_LOAD_DRIVER
        );
        assert_eq!(
            rd_u32(se_exports_offset::CHANGE_NOTIFY_PRIVILEGE),
            LUID_CHANGE_NOTIFY
        );

        // Each SID pointer field points at a correctly-encoded SID in the pool.
        let rd_ptr =
            |off: usize| unsafe { core::ptr::read_unaligned(st.as_ptr().add(off) as *const u64) };
        let check = |field: usize, sid: WellKnownSid| {
            let p = rd_ptr(field);
            assert_ne!(p, 0, "SID pointer field 0x{field:x} must be non-null");
            let idx = (p - pool_va) as usize;
            assert_eq!(&pool[idx..idx + sid.len()], sid.as_bytes());
        };
        check(se_exports_offset::WORLD_SID, WORLD_SID);
        check(se_exports_offset::LOCAL_SYSTEM_SID, LOCAL_SYSTEM_SID);
        check(se_exports_offset::ALIAS_ADMINS_SID, ALIAS_ADMINS_SID);
        check(se_exports_offset::CREATOR_OWNER_SID, CREATOR_OWNER_SID);
        check(se_exports_offset::NULL_SID, NULL_SID);
    }

    #[test]
    fn se_exports_offsets_are_distinct_and_ordered() {
        // The SID pointers all live at or above the 23-LUID block and are 8-aligned + distinct.
        let sid_offsets = [
            se_exports_offset::NULL_SID,
            se_exports_offset::WORLD_SID,
            se_exports_offset::LOCAL_SID,
            se_exports_offset::CREATOR_OWNER_SID,
            se_exports_offset::CREATOR_GROUP_SID,
            se_exports_offset::NT_AUTHORITY_SID,
            se_exports_offset::LOCAL_SYSTEM_SID,
            se_exports_offset::ALIAS_ADMINS_SID,
            se_exports_offset::ALIAS_USERS_SID,
        ];
        for (i, &o) in sid_offsets.iter().enumerate() {
            assert!(
                o >= se_exports_offset::PSID_BASE,
                "SID ptr below LUID block"
            );
            assert_eq!(o % 8, 0, "SID ptr not 8-aligned");
            assert!(
                o + 8 <= se_exports_offset::STRUCT_SIZE,
                "SID ptr past struct"
            );
            for &o2 in &sid_offsets[i + 1..] {
                assert_ne!(o, o2, "duplicate SID field offset");
            }
        }
    }

    #[test]
    fn system_authentication_luid_matches_system_token() {
        // SeQueryAuthenticationIdToken must return the SYSTEM logon-session LUID that the SYSTEM
        // access token carries (`AccessToken::system().authentication_id`).
        let sys = crate::AccessToken::system();
        assert_eq!(SYSTEM_AUTHENTICATION_LUID_LOW, sys.authentication_id.low);
        assert_eq!(SYSTEM_AUTHENTICATION_LUID_HIGH, sys.authentication_id.high);
        assert_eq!(SYSTEM_AUTHENTICATION_LUID_LOW, 0x3e7);
    }

    #[test]
    fn subject_context_captures_system_primary_token() {
        let mut ctx = [0u8; subject_context_offset::SIZE];
        let token = 0x1234_5678_9ABC_DEF0u64;
        unsafe {
            capture_system_subject_context(ctx.as_mut_ptr(), token);
            // No impersonation: ClientToken NULL, PrimaryToken set, level anonymous.
            assert_eq!(
                core::ptr::read_unaligned(
                    ctx.as_ptr().add(subject_context_offset::CLIENT_TOKEN) as *const u64
                ),
                0
            );
            assert_eq!(
                core::ptr::read_unaligned(
                    ctx.as_ptr().add(subject_context_offset::PRIMARY_TOKEN) as *const u64
                ),
                token
            );
            // Effective token = primary token when not impersonating.
            assert_eq!(subject_context_token(ctx.as_ptr()), token);
        }
    }

    #[test]
    fn subject_context_token_prefers_impersonation_client_token() {
        let mut ctx = [0u8; subject_context_offset::SIZE];
        unsafe {
            capture_system_subject_context(ctx.as_mut_ptr(), 0xAAAA);
            // Simulate an impersonation client token being present.
            core::ptr::write_unaligned(
                ctx.as_mut_ptr().add(subject_context_offset::CLIENT_TOKEN) as *mut u64,
                0xBBBB,
            );
            assert_eq!(subject_context_token(ctx.as_ptr()), 0xBBBB);
        }
    }
}
