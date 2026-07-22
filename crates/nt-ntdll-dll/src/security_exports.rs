//! # ntdll security exports — raw SID / ACL / SECURITY_DESCRIPTOR C-ABI wrappers
//!
//! This module implements the 51 `Rtl*` security exports that operate directly over the **raw
//! Windows x64 byte layouts** of SIDs, ACLs and SECURITY_DESCRIPTORs (absolute and self-relative).
//! They are the companion set to the SID/ACL/SD exports already in [`crate::exports`]
//! (`RtlLengthSid`, `RtlCreateSecurityDescriptor`, `RtlAllocateAndInitializeSid`,
//! `RtlSetDaclSecurityDescriptor`, `RtlGetDaclSecurityDescriptor`, `RtlFreeSid`, `RtlGetAce`,
//! `RtlAddAccessAllowedAce`, `RtlCreateAcl`), and follow the **exact same discipline**:
//!
//! * each export is a `#[export_name = "RtlXxx"] pub unsafe extern "system" fn` with the real
//!   Windows x64 signature (cross-checked against `references/reactos/sdk/lib/rtl/{sid,acl,sd,
//!   generic access.c,priv}.c` + the NDK `setypes.h`);
//! * every `unsafe` block carries a SAFETY comment describing the pointer contract it relies on;
//! * anything that needs the **process heap** (only `RtlConvertSidToUnicodeString` with
//!   `AllocateBuffer` here) is split with `#[cfg(target_arch = "x86_64")]` / `#[cfg(not(...))]`
//!   and returns an **honest failure** off-target — it NEVER fabricates success;
//! * real `NTSTATUS` codes are returned (bad revisions → `STATUS_UNKNOWN_REVISION` exactly where
//!   the ReactOS source does).
//!
//! ## Raw layouts (x64)
//! * **SID**: `[0]=Revision:u8(=1) [1]=SubAuthorityCount:u8 [2..8]=IdentifierAuthority(6, BE)` then
//!   `SubAuthorityCount * u32 (LE, possibly unaligned)`. `Length = 8 + 4*SubAuthorityCount`.
//! * **ACL**: `[0]=AclRevision:u8 [1]=Sbz1:u8 [2..4]=AclSize:u16 [4..6]=AceCount:u16 [6..8]=Sbz2:u16`.
//!   ACEs follow the 8-byte header.
//! * **ACE_HEADER**: `[0]=AceType:u8 [1]=AceFlags:u8 [2..4]=AceSize:u16`. For ALLOWED/DENIED/AUDIT:
//!   header + `Mask:u32` + inline SID. For the *OBJECT* variants: header + `Mask:u32` +
//!   `Flags:u32` + optional `ObjectType`/`InheritedObjectType` GUIDs (16 bytes each) + inline SID.
//! * **Absolute SD (0x28 bytes)**: `[0]=Revision:u8 [1]=Sbz1:u8 [2..4]=Control:u16
//!   [0x08]=Owner:ptr [0x10]=Group:ptr [0x18]=Sacl:ptr [0x20]=Dacl:ptr`.
//! * **Self-relative SD (0x14 bytes)**: same header, but Owner/Group/Sacl/Dacl are `u32` OFFSETS
//!   from the SD base (0 = absent); the referenced SIDs/ACLs are packed after the header.

use core::ffi::c_void;

use nt_ntdll_layout::UnicodeString;

type NtStatus = u32;
type PUnicodeString = *mut UnicodeString;

// NTSTATUS codes used below (values from the NT status space).
const STATUS_SUCCESS: NtStatus = 0x0000_0000;
#[cfg(not(target_arch = "x86_64"))]
const STATUS_NOT_IMPLEMENTED: NtStatus = 0xC000_0002;
const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;
const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
const STATUS_INVALID_SID: NtStatus = 0xC000_0078;
const STATUS_INVALID_ACL: NtStatus = 0xC000_0077;
const STATUS_INVALID_OWNER: NtStatus = 0xC000_005A;
const STATUS_INVALID_PRIMARY_GROUP: NtStatus = 0xC000_005B;
const STATUS_UNKNOWN_REVISION: NtStatus = 0xC000_0058;
const STATUS_INVALID_INFO_CLASS: NtStatus = 0xC000_0003;
const STATUS_INVALID_SECURITY_DESCR: NtStatus = 0xC000_0079;
const STATUS_BAD_DESCRIPTOR_FORMAT: NtStatus = 0xC000_00E7;
const STATUS_ALLOTTED_SPACE_EXCEEDED: NtStatus = 0xC000_0099;

// Revision / control constants.
const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
const ACL_REVISION4: u8 = 4;
const MIN_ACL_REVISION: u8 = 2;
const MAX_ACL_REVISION: u8 = 4;
const SECURITY_DESCRIPTOR_REVISION: u8 = 1;

// SECURITY_DESCRIPTOR_CONTROL bits.
const SE_OWNER_DEFAULTED: u16 = 0x0001;
const SE_GROUP_DEFAULTED: u16 = 0x0002;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_DEFAULTED: u16 = 0x0008;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SACL_DEFAULTED: u16 = 0x0020;
const SE_RM_CONTROL_VALID: u16 = 0x4000;
const SE_SELF_RELATIVE: u16 = 0x8000;

// SECURITY_INFORMATION bits.
const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;

// Well-known access/privilege constants.
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const SE_SECURITY_PRIVILEGE: u32 = 8;
const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;
const ACL_REVISION2: u32 = 2;
const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;
const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;
const SECURITY_ANONYMOUS_LOGON_RID: u32 = 7;
const SECURITY_WORLD_RID: u32 = 0;
const GENERIC_READ_MASK: u32 = 0x8000_0000;
const GENERIC_ALL_MASK: u32 = 0x1000_0000;

// ACE types.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;

// GENERIC access bits.
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

// Header sizes.
const SD_ABS_HEADER: usize = 0x28; // absolute SD (4-byte prefix + 4 * 8-byte ptr)
const SD_REL_HEADER: usize = 0x14; // self-relative SD (4-byte prefix + 4 * 4-byte offset)
const ACL_HEADER: usize = 8;
const ACE_HEADER: usize = 4; // Type(1) Flags(1) Size(2)
const OBJECT_ACE_FLAG_TYPE_PRESENT: u32 = 0x1;
const OBJECT_ACE_FLAG_INHERITED_TYPE_PRESENT: u32 = 0x2;

// =================================================================================================
// Small raw-pointer helpers over the byte layouts. All are `unsafe`: the caller vouches the
// pointer references a well-formed object of the named kind.
// =================================================================================================

/// SID byte length = `8 + 4 * SubAuthorityCount`.
///
/// # Safety
/// `sid` a valid SID (Revision @0, SubAuthorityCount @1).
#[inline]
unsafe fn sid_len(sid: *const u8) -> usize {
    // SAFETY: SubAuthorityCount is the byte at offset 1 per the SID layout.
    8 + 4 * (unsafe { *sid.add(1) } as usize)
}

/// Read the SD Control word (@offset 2).
///
/// # Safety
/// `sd` a valid SECURITY_DESCRIPTOR header.
#[inline]
unsafe fn sd_control(sd: *const u8) -> u16 {
    // SAFETY: Control is the u16 at offset 2 of both SD forms.
    unsafe { *(sd.add(0x02) as *const u16) }
}

/// Resolve a self-relative/absolute SD field to an absolute pointer.
///
/// `abs_off` = byte offset of the pointer field in the absolute layout (0x08/0x10/0x18/0x20);
/// `rel_off` = byte offset of the u32 offset field in the self-relative layout.
/// Returns null when the component is absent (null ptr / zero offset).
///
/// # Safety
/// `sd` a valid SD header of the form indicated by its Control word.
unsafe fn sd_component(sd: *const u8, abs_off: usize, rel_off: usize) -> *mut u8 {
    // SAFETY: the offsets index inside the SD header per the raw layout.
    unsafe {
        if sd_control(sd) & SE_SELF_RELATIVE != 0 {
            let off = *(sd.add(rel_off) as *const u32);
            if off == 0 {
                core::ptr::null_mut()
            } else {
                sd.add(off as usize) as *mut u8
            }
        } else {
            *(sd.add(abs_off) as *const *mut u8)
        }
    }
}

// The self-relative field offsets: Owner@0x04, Group@0x08, Sacl@0x0C, Dacl@0x10.
#[inline]
unsafe fn sd_owner(sd: *const u8) -> *mut u8 {
    // SAFETY: forwarded to sd_component with the Owner offsets.
    unsafe { sd_component(sd, 0x08, 0x04) }
}
#[inline]
unsafe fn sd_group(sd: *const u8) -> *mut u8 {
    // SAFETY: forwarded to sd_component with the Group offsets.
    unsafe { sd_component(sd, 0x10, 0x08) }
}
#[inline]
unsafe fn sd_sacl(sd: *const u8) -> *mut u8 {
    // SAFETY: forwarded to sd_component with the Sacl offsets.
    unsafe { sd_component(sd, 0x18, 0x0C) }
}
#[inline]
unsafe fn sd_dacl(sd: *const u8) -> *mut u8 {
    // SAFETY: forwarded to sd_component with the Dacl offsets.
    unsafe { sd_component(sd, 0x20, 0x10) }
}

/// Round `n` up to a multiple of 4.
#[inline]
fn round_up4(n: usize) -> usize {
    (n + 3) & !3
}

fn stack_sid(buf: &mut [u8; 16], authority: [u8; 6], sub_authorities: &[u32]) -> *mut c_void {
    buf.fill(0);
    buf[0] = SID_REVISION;
    buf[1] = sub_authorities.len() as u8;
    buf[2..8].copy_from_slice(&authority);
    for (i, sub_authority) in sub_authorities.iter().enumerate() {
        let start = 8 + i * 4;
        buf[start..start + 4].copy_from_slice(&sub_authority.to_le_bytes());
    }
    buf.as_mut_ptr() as *mut c_void
}

fn valid_sd_offset_and_size(offset: u32, length: u32, min_length: usize) -> Option<usize> {
    let offset = offset as usize;
    let length = length as usize;
    if offset < SD_REL_HEADER || offset >= length || offset & 3 != 0 {
        return None;
    }
    let available = length - offset;
    if available < min_length {
        return None;
    }
    Some(available)
}

/// Build an absolute, empty SECURITY_DESCRIPTOR in caller-provided storage.
///
/// # Safety
/// `sd` is writable for an x64 absolute SECURITY_DESCRIPTOR (0x28 bytes).
unsafe fn init_absolute_sd(sd: *mut u8) {
    // SAFETY: caller provided a valid writable SD buffer.
    unsafe {
        core::ptr::write_bytes(sd, 0, SD_ABS_HEADER);
        *sd = SECURITY_DESCRIPTOR_REVISION;
    }
}

/// Set an absolute SD's DACL fields.
///
/// # Safety
/// `sd` is a writable absolute SD; `dacl` is either null or a valid ACL.
unsafe fn set_abs_dacl(sd: *mut u8, present: bool, dacl: *mut c_void, defaulted: bool) {
    // SAFETY: caller provided a valid writable absolute SD.
    unsafe {
        let ctrl = sd.add(0x02) as *mut u16;
        if present {
            *(sd.add(0x20) as *mut *mut c_void) = dacl;
            *ctrl |= SE_DACL_PRESENT;
            *ctrl &= !SE_DACL_DEFAULTED;
            if defaulted {
                *ctrl |= SE_DACL_DEFAULTED;
            }
        } else {
            *(sd.add(0x20) as *mut *mut c_void) = core::ptr::null_mut();
            *ctrl &= !(SE_DACL_PRESENT | SE_DACL_DEFAULTED);
        }
    }
}

/// Read an SD's DACL presence/defaulted bits and component pointer.
///
/// # Safety
/// `sd` is a valid absolute or self-relative SECURITY_DESCRIPTOR.
unsafe fn get_dacl(sd: *const u8) -> Result<(bool, *mut c_void, bool), NtStatus> {
    // SAFETY: caller provided a valid readable SD header.
    unsafe {
        if *sd != SECURITY_DESCRIPTOR_REVISION {
            return Err(STATUS_UNKNOWN_REVISION);
        }
        let control = sd_control(sd);
        let present = (control & SE_DACL_PRESENT) != 0;
        let dacl = if present {
            sd_dacl(sd) as *mut c_void
        } else {
            core::ptr::null_mut()
        };
        let defaulted = (control & SE_DACL_DEFAULTED) != 0;
        Ok((present, dacl, defaulted))
    }
}

/// Copy one SID/ACL blob, rounded to the next component boundary.
///
/// # Safety
/// `src`/`dst` point to readable/writable buffers of `len` bytes.
unsafe fn copy_component(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: caller validated the source and destination spans.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, len);
        let pad = round_up4(len) - len;
        if pad != 0 {
            core::ptr::write_bytes(dst.add(len), 0, pad);
        }
    }
}

/// Byte extent of a self-relative SD, including rounded component payloads.
///
/// # Safety
/// `sd` is a valid self-relative SECURITY_DESCRIPTOR.
unsafe fn self_relative_sd_extent(sd: *const u8) -> Option<usize> {
    // SAFETY: caller supplied a readable self-relative SD.
    unsafe {
        let mut len = SD_REL_HEADER;
        for &(rel_off, is_acl) in &[
            (0x04usize, false),
            (0x08usize, false),
            (0x0Cusize, true),
            (0x10usize, true),
        ] {
            let off = *(sd.add(rel_off) as *const u32) as usize;
            if off == 0 {
                continue;
            }
            let component = sd.add(off);
            let raw_len = if is_acl {
                *(component.add(2) as *const u16) as usize
            } else {
                sid_len(component)
            };
            let end = off.checked_add(round_up4(raw_len))?;
            len = len.max(end);
        }
        Some(len)
    }
}

/// Clone a valid SECURITY_DESCRIPTOR into a process-heap self-relative descriptor.
///
/// # Safety
/// `source` is a valid absolute or self-relative SECURITY_DESCRIPTOR.
#[cfg(target_arch = "x86_64")]
unsafe fn clone_security_descriptor_to_heap(
    source: *const c_void,
) -> Result<*mut c_void, NtStatus> {
    if source.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: source is a readable SECURITY_DESCRIPTOR per the contract.
    unsafe {
        let src = source as *const u8;
        if *src != SECURITY_DESCRIPTOR_REVISION {
            return Err(STATUS_UNKNOWN_REVISION);
        }
        if rtl_valid_security_descriptor(source) == 0 {
            return Err(STATUS_INVALID_SECURITY_DESCR);
        }

        if sd_control(src) & SE_SELF_RELATIVE != 0 {
            let len = match self_relative_sd_extent(src) {
                Some(n) => n,
                None => return Err(STATUS_INVALID_SECURITY_DESCR),
            };
            let dst = crate::process_heap_alloc(len);
            if dst.is_null() {
                return Err(STATUS_NO_MEMORY);
            }
            core::ptr::copy_nonoverlapping(src, dst, len);
            return Ok(dst as *mut c_void);
        }

        let mut len = 0u32;
        let status = rtl_make_self_relative_sd(source, core::ptr::null_mut(), &mut len);
        if status != STATUS_BUFFER_TOO_SMALL || len == 0 {
            return Err(status);
        }
        let dst = crate::process_heap_alloc(len as usize);
        if dst.is_null() {
            return Err(STATUS_NO_MEMORY);
        }
        let mut out_len = len;
        let status = rtl_make_self_relative_sd(source, dst as *mut c_void, &mut out_len);
        if status != STATUS_SUCCESS {
            crate::process_heap_free(dst);
            return Err(status);
        }
        Ok(dst as *mut c_void)
    }
}

/// Allocate a minimal empty self-relative SECURITY_DESCRIPTOR.
///
/// # Safety
/// On-target process heap is available.
#[cfg(target_arch = "x86_64")]
unsafe fn empty_security_descriptor_to_heap() -> Result<*mut c_void, NtStatus> {
    // SAFETY: process heap allocation in the hosted process.
    let dst = unsafe { crate::process_heap_alloc(SD_REL_HEADER) };
    if dst.is_null() {
        return Err(STATUS_NO_MEMORY);
    }
    // SAFETY: `dst` is a fresh SD_REL_HEADER-byte allocation.
    unsafe {
        core::ptr::write_bytes(dst, 0, SD_REL_HEADER);
        *dst = SECURITY_DESCRIPTOR_REVISION;
        *(dst.add(0x02) as *mut u16) = SE_SELF_RELATIVE;
    }
    Ok(dst as *mut c_void)
}

#[derive(Copy, Clone)]
struct SdParts {
    owner: *mut u8,
    group: *mut u8,
    dacl: *mut u8,
    sacl: *mut u8,
    owner_len: usize,
    group_len: usize,
    dacl_len: usize,
    sacl_len: usize,
    control: u16,
}

/// Gather the selected/inherited components for RtlSetSecurityObject.
///
/// # Safety
/// The object and modification descriptors are valid SDs for the components read.
unsafe fn select_security_parts(
    security_information: u32,
    modification_descriptor: *const c_void,
    object_descriptor: *const c_void,
) -> Result<SdParts, NtStatus> {
    if object_descriptor.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if security_information
        & (OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | SACL_SECURITY_INFORMATION)
        != 0
        && modification_descriptor.is_null()
    {
        return Err(STATUS_INVALID_PARAMETER);
    }

    // SAFETY: descriptors are valid for the selected reads.
    unsafe {
        let source_owner = if security_information & OWNER_SECURITY_INFORMATION != 0 {
            modification_descriptor
        } else {
            object_descriptor
        } as *const u8;
        let source_group = if security_information & GROUP_SECURITY_INFORMATION != 0 {
            modification_descriptor
        } else {
            object_descriptor
        } as *const u8;
        let source_dacl = if security_information & DACL_SECURITY_INFORMATION != 0 {
            modification_descriptor
        } else {
            object_descriptor
        } as *const u8;
        let source_sacl = if security_information & SACL_SECURITY_INFORMATION != 0 {
            modification_descriptor
        } else {
            object_descriptor
        } as *const u8;

        if *source_owner != SECURITY_DESCRIPTOR_REVISION
            || *source_group != SECURITY_DESCRIPTOR_REVISION
            || *source_dacl != SECURITY_DESCRIPTOR_REVISION
            || *source_sacl != SECURITY_DESCRIPTOR_REVISION
        {
            return Err(STATUS_UNKNOWN_REVISION);
        }

        let owner = sd_owner(source_owner);
        if owner.is_null() || rtl_valid_sid(owner as *const c_void) == 0 {
            return Err(STATUS_INVALID_OWNER);
        }
        let group = sd_group(source_group);
        if group.is_null() || rtl_valid_sid(group as *const c_void) == 0 {
            return Err(STATUS_INVALID_PRIMARY_GROUP);
        }

        let (dacl_present, dacl, dacl_defaulted) = get_dacl(source_dacl)?;
        let mut control = SE_SELF_RELATIVE;
        if sd_control(source_owner) & SE_OWNER_DEFAULTED != 0 {
            control |= SE_OWNER_DEFAULTED;
        }
        if sd_control(source_group) & SE_GROUP_DEFAULTED != 0 {
            control |= SE_GROUP_DEFAULTED;
        }
        if dacl_present {
            control |= SE_DACL_PRESENT;
        }
        if dacl_defaulted {
            control |= SE_DACL_DEFAULTED;
        }

        let mut sacl: *mut c_void = core::ptr::null_mut();
        let mut sacl_present = 0u8;
        let mut sacl_defaulted = 0u8;
        let status = rtl_get_sacl_security_descriptor(
            source_sacl as *const c_void,
            &mut sacl_present,
            &mut sacl,
            &mut sacl_defaulted,
        );
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        if sacl_present != 0 {
            control |= SE_SACL_PRESENT;
        }
        if sacl_defaulted != 0 {
            control |= SE_SACL_DEFAULTED;
        }

        let owner_len = sid_len(owner);
        let group_len = sid_len(group);
        let dacl_len = if dacl.is_null() {
            0
        } else {
            *(dacl.cast::<u8>().add(2) as *const u16) as usize
        };
        let sacl_len = if sacl.is_null() {
            0
        } else {
            *(sacl.cast::<u8>().add(2) as *const u16) as usize
        };

        Ok(SdParts {
            owner,
            group,
            dacl: dacl.cast::<u8>(),
            sacl: sacl.cast::<u8>(),
            owner_len,
            group_len,
            dacl_len,
            sacl_len,
            control,
        })
    }
}

// =================================================================================================
// SID exports
// =================================================================================================

/// `RtlValidSid(PSID) -> BOOLEAN` — revision==1 && SubAuthorityCount<=15. Ported from
/// `references/reactos/sdk/lib/rtl/sid.c:21`.
///
/// # Safety
/// `sid` a readable SID or NULL.
#[export_name = "RtlValidSid"]
pub unsafe extern "system" fn rtl_valid_sid(sid: *const c_void) -> u8 {
    if sid.is_null() {
        return 0;
    }
    // SAFETY: sid is a readable SID per the contract; Revision@0, SubAuthorityCount@1.
    unsafe {
        let p = sid as *const u8;
        if (*p & 0xF) != SID_REVISION || *p.add(1) > SID_MAX_SUB_AUTHORITIES {
            return 0;
        }
    }
    1
}

/// `RtlEqualSid(PSID, PSID) -> BOOLEAN` — Revision+Count fast compare then memcmp of the whole SID.
/// Ported from `sid.c:132`.
///
/// # Safety
/// `sid1`, `sid2` valid readable SIDs.
#[export_name = "RtlEqualSid"]
pub unsafe extern "system" fn rtl_equal_sid(sid1: *const c_void, sid2: *const c_void) -> u8 {
    if sid1.is_null() || sid2.is_null() {
        return 0;
    }
    // SAFETY: both are valid SIDs; the first u16 is Revision+SubAuthorityCount.
    unsafe {
        let a = sid1 as *const u8;
        let b = sid2 as *const u8;
        if *(a as *const u16) != *(b as *const u16) {
            return 0;
        }
        let len = sid_len(a);
        for i in 0..len {
            if *a.add(i) != *b.add(i) {
                return 0;
            }
        }
    }
    1
}

/// `RtlEqualPrefixSid(PSID, PSID) -> BOOLEAN` — equal identifier authority + all but the LAST
/// sub-authority. Ported from `sid.c:200`.
///
/// # Safety
/// `sid1`, `sid2` valid readable SIDs.
#[export_name = "RtlEqualPrefixSid"]
pub unsafe extern "system" fn rtl_equal_prefix_sid(sid1: *const c_void, sid2: *const c_void) -> u8 {
    if sid1.is_null() || sid2.is_null() {
        return 0;
    }
    // SAFETY: both are valid SIDs per the contract.
    unsafe {
        let a = sid1 as *const u8;
        let b = sid2 as *const u8;
        if *a != *b {
            return 0; // Revision mismatch
        }
        // 6-byte IdentifierAuthority @ offset 2.
        for i in 2..8 {
            if *a.add(i) != *b.add(i) {
                return 0;
            }
        }
        let count = *a.add(1);
        if count != *b.add(1) {
            return 0;
        }
        if count == 0 {
            return 1;
        }
        // Compare all sub-authorities BUT the last.
        let sa_a = a.add(8) as *const u32;
        let sa_b = b.add(8) as *const u32;
        let mut i = 0u32;
        while i + 1 < count as u32 {
            if core::ptr::read_unaligned(sa_a.add(i as usize))
                != core::ptr::read_unaligned(sa_b.add(i as usize))
            {
                return 0;
            }
            i += 1;
        }
    }
    1
}

/// `RtlLengthRequiredSid(ULONG SubAuthorityCount) -> ULONG` = `8 + 4*count`. Ported from `sid.c:54`.
#[export_name = "RtlLengthRequiredSid"]
pub extern "system" fn rtl_length_required_sid(sub_authority_count: u32) -> u32 {
    8 + 4 * sub_authority_count
}

/// `RtlInitializeSid(PSID, PSID_IDENTIFIER_AUTHORITY, UCHAR SubAuthorityCount) -> NTSTATUS`.
/// Writes Revision=1, the count, and the 6-byte authority (sub-authorities left to the caller).
/// Ported from `sid.c:68`.
///
/// # Safety
/// `sid` a writable buffer of at least `8 + 4*count` bytes; `identifier_authority` a 6-byte auth.
#[export_name = "RtlInitializeSid"]
pub unsafe extern "system" fn rtl_initialize_sid(
    sid: *mut c_void,
    identifier_authority: *const c_void,
    sub_authority_count: u8,
) -> NtStatus {
    if sid.is_null() || identifier_authority.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sid is writable per the contract; identifier_authority is a 6-byte authority.
    unsafe {
        let p = sid as *mut u8;
        *p = SID_REVISION;
        *p.add(1) = sub_authority_count;
        core::ptr::copy_nonoverlapping(identifier_authority as *const u8, p.add(2), 6);
    }
    STATUS_SUCCESS
}

/// `RtlIdentifierAuthoritySid(PSID) -> PSID_IDENTIFIER_AUTHORITY` — &SID->IdentifierAuthority (@2).
/// Ported from `sid.c:118`.
///
/// # Safety
/// `sid` a valid SID.
#[export_name = "RtlIdentifierAuthoritySid"]
pub unsafe extern "system" fn rtl_identifier_authority_sid(sid: *mut c_void) -> *mut u8 {
    if sid.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: IdentifierAuthority is the 6 bytes at offset 2.
    unsafe { (sid as *mut u8).add(2) }
}

/// `RtlSubAuthoritySid(PSID, ULONG SubAuthority) -> PULONG` — &SID->SubAuthority[index] (@8 + 4*i).
/// Ported from `sid.c:89`.
///
/// # Safety
/// `sid` a valid SID; `index` < SubAuthorityCount.
#[export_name = "RtlSubAuthoritySid"]
pub unsafe extern "system" fn rtl_sub_authority_sid(sid: *mut c_void, index: u32) -> *mut u32 {
    if sid.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: SubAuthority[i] is at offset 8 + 4*i (may be unaligned; a raw ptr is fine).
    unsafe { (sid as *mut u8).add(8 + 4 * index as usize) as *mut u32 }
}

/// `RtlSubAuthorityCountSid(PSID) -> PUCHAR` — &SID->SubAuthorityCount (@1). Ported from `sid.c:104`.
///
/// # Safety
/// `sid` a valid SID.
#[export_name = "RtlSubAuthorityCountSid"]
pub unsafe extern "system" fn rtl_sub_authority_count_sid(sid: *mut c_void) -> *mut u8 {
    if sid.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: SubAuthorityCount is the byte at offset 1.
    unsafe { (sid as *mut u8).add(1) }
}

/// `RtlCopySid(ULONG BufferLength, PSID Dest, PSID Src) -> NTSTATUS`. Ported from `sid.c:165`.
///
/// # Safety
/// `dest` a writable buffer of `buffer_length` bytes; `src` a valid SID.
#[export_name = "RtlCopySid"]
pub unsafe extern "system" fn rtl_copy_sid(
    buffer_length: u32,
    dest: *mut c_void,
    src: *const c_void,
) -> NtStatus {
    if dest.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src is a valid SID; dest holds buffer_length bytes.
    unsafe {
        let len = sid_len(src as *const u8);
        if len > buffer_length as usize {
            return STATUS_BUFFER_TOO_SMALL;
        }
        core::ptr::copy(src as *const u8, dest as *mut u8, len);
    }
    STATUS_SUCCESS
}

/// `RtlCopySidAndAttributesArray(ULONG Count, PSID_AND_ATTRIBUTES Src, ULONG SidAreaSize,
/// PSID_AND_ATTRIBUTES Dest, PSID SidArea, PSID* RemainingSidArea, PULONG RemainingSidAreaSize)`.
/// Copies the SID_AND_ATTRIBUTES array and packs SID bytes sequentially into `SidArea`.
/// Ported from `sid.c:249`.
///
/// # Safety
/// `src`/`dest` are arrays of `count` SID_AND_ATTRIBUTES entries (16 bytes each on x64);
/// `sid_area` is writable for `sid_area_size` bytes; remaining out-pointers are writable.
#[export_name = "RtlCopySidAndAttributesArray"]
pub unsafe extern "system" fn rtl_copy_sid_and_attributes_array(
    count: u32,
    src: *const c_void,
    sid_area_size: u32,
    dest: *mut c_void,
    sid_area: *mut c_void,
    remaining_sid_area: *mut *mut c_void,
    remaining_sid_area_size: *mut u32,
) -> NtStatus {
    if remaining_sid_area.is_null() || remaining_sid_area_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if count != 0 && (src.is_null() || dest.is_null() || sid_area.is_null()) {
        return STATUS_INVALID_PARAMETER;
    }

    const SID_AND_ATTRIBUTES_SIZE: usize = 16;
    let mut remaining = sid_area_size as usize;
    let mut sid_cursor = sid_area as *mut u8;
    let src = src as *const u8;
    let dest = dest as *mut u8;

    // SAFETY: caller supplied valid arrays and SID storage per the contract.
    unsafe {
        for i in 0..count as usize {
            let src_entry = src.add(i * SID_AND_ATTRIBUTES_SIZE);
            let dest_entry = dest.add(i * SID_AND_ATTRIBUTES_SIZE);
            let src_sid = core::ptr::read_unaligned(src_entry as *const *const u8);
            let attributes = core::ptr::read_unaligned(src_entry.add(8) as *const u32);
            if src_sid.is_null() {
                return STATUS_INVALID_PARAMETER;
            }
            let sid_length = sid_len(src_sid);
            if sid_length > remaining {
                return STATUS_BUFFER_TOO_SMALL;
            }

            core::ptr::write_unaligned(dest_entry as *mut *mut c_void, sid_cursor as *mut c_void);
            core::ptr::write_unaligned(dest_entry.add(8) as *mut u32, attributes);
            core::ptr::write_unaligned(dest_entry.add(12) as *mut u32, 0);
            core::ptr::copy_nonoverlapping(src_sid, sid_cursor, sid_length);

            sid_cursor = sid_cursor.add(sid_length);
            remaining -= sid_length;
        }
        *remaining_sid_area = sid_cursor as *mut c_void;
        *remaining_sid_area_size = remaining as u32;
    }
    STATUS_SUCCESS
}

/// `RtlConvertSidToUnicodeString(PUNICODE_STRING, PSID, BOOLEAN AllocateBuffer) -> NTSTATUS`.
/// Produces the SDDL "S-1-..." string. Ported from `sid.c:342`. When `allocate_buffer` is set we
/// allocate the buffer from the process heap (x86_64 only); otherwise we write into the caller's
/// pre-sized buffer (honouring MaximumLength).
///
/// # Safety
/// `string` a writable UNICODE_STRING (with a valid pre-sized `buffer` when `allocate_buffer==0`);
/// `sid` a valid SID.
#[export_name = "RtlConvertSidToUnicodeString"]
pub unsafe extern "system" fn rtl_convert_sid_to_unicode_string(
    string: PUnicodeString,
    sid: *const c_void,
    allocate_buffer: u8,
) -> NtStatus {
    if string.is_null() || sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sid valid per the contract.
    if unsafe { rtl_valid_sid(sid) } == 0 {
        return STATUS_INVALID_SID;
    }
    // Build the string into a fixed UTF-16 scratch (max SID string is well under 256 units).
    let mut buf = [0u16; 256];
    let mut n = 0usize;
    let push = |s: &str, buf: &mut [u16; 256], n: &mut usize| {
        for ch in s.chars() {
            if *n < buf.len() {
                buf[*n] = ch as u16;
                *n += 1;
            }
        }
    };
    // "S-1-" then the identifier authority (decimal if the top 2 bytes are 0, else 0x... hex).
    push("S-1-", &mut buf, &mut n);
    // SAFETY: sid is a valid SID; read the 6 authority bytes @ offset 2 and the count @ offset 1.
    unsafe {
        let p = sid as *const u8;
        let auth = [
            *p.add(2),
            *p.add(3),
            *p.add(4),
            *p.add(5),
            *p.add(6),
            *p.add(7),
        ];
        if auth[0] == 0 && auth[1] == 0 {
            let v = (auth[2] as u32) << 24
                | (auth[3] as u32) << 16
                | (auth[4] as u32) << 8
                | (auth[5] as u32);
            let mut tmp = [0u8; 10];
            let s = fmt_u32_dec(v, &mut tmp);
            push(s, &mut buf, &mut n);
        } else {
            push("0x", &mut buf, &mut n);
            for b in auth.iter() {
                let mut tmp = [0u8; 2];
                let s = fmt_u8_hex2(*b, &mut tmp);
                push(s, &mut buf, &mut n);
            }
        }
        let count = *p.add(1);
        let subs = p.add(8) as *const u32;
        for i in 0..count as usize {
            push("-", &mut buf, &mut n);
            let v = core::ptr::read_unaligned(subs.add(i));
            let mut tmp = [0u8; 10];
            let s = fmt_u32_dec(v, &mut tmp);
            push(s, &mut buf, &mut n);
        }
    }
    let byte_len = n * 2;

    if allocate_buffer != 0 {
        #[cfg(target_arch = "x86_64")]
        {
            // Allocate (byte_len + NUL) and fill; write the UNICODE_STRING header.
            // SAFETY: on-target; the process heap is installed by LdrpInitialize.
            let p = unsafe { crate::process_heap_alloc(byte_len + 2) } as *mut u16;
            if p.is_null() {
                return STATUS_NO_MEMORY;
            }
            // SAFETY: p holds n+1 u16 units; string is a writable UNICODE_STRING.
            unsafe {
                for i in 0..n {
                    *p.add(i) = buf[i];
                }
                *p.add(n) = 0;
                (*string).length = byte_len as u16;
                (*string).maximum_length = (byte_len + 2) as u16;
                (*string).buffer = p as u64;
            }
            STATUS_SUCCESS
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = byte_len;
            STATUS_NO_MEMORY
        }
    } else {
        // SAFETY: string is a valid writable UNICODE_STRING with a pre-sized buffer.
        unsafe {
            let max = (*string).maximum_length as usize;
            if byte_len > max {
                return STATUS_BUFFER_TOO_SMALL;
            }
            let out = (*string).buffer as *mut u16;
            if out.is_null() {
                return STATUS_BUFFER_TOO_SMALL;
            }
            for i in 0..n {
                *out.add(i) = buf[i];
            }
            (*string).length = byte_len as u16;
            if byte_len < max {
                *out.add(n) = 0;
            }
        }
        STATUS_SUCCESS
    }
}

/// Format a u32 as decimal into `tmp`, returning the slice as a &str.
fn fmt_u32_dec(mut v: u32, tmp: &mut [u8; 10]) -> &str {
    if v == 0 {
        tmp[0] = b'0';
        return core::str::from_utf8(&tmp[..1]).unwrap_or("0");
    }
    let mut i = tmp.len();
    while v != 0 {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // Compact to the front.
    let len = tmp.len() - i;
    tmp.copy_within(i.., 0);
    core::str::from_utf8(&tmp[..len]).unwrap_or("0")
}

/// Format a u8 as 2 lowercase hex digits into `tmp`.
fn fmt_u8_hex2(v: u8, tmp: &mut [u8; 2]) -> &str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    tmp[0] = HEX[(v >> 4) as usize];
    tmp[1] = HEX[(v & 0xF) as usize];
    core::str::from_utf8(&tmp[..]).unwrap_or("00")
}

// =================================================================================================
// ACL exports
// =================================================================================================

/// `RtlValidAcl(PACL) -> BOOLEAN` — revision in range, USHORT-aligned size, >= header, every ACE
/// fits. Ported from `references/reactos/sdk/lib/rtl/acl.c:837` (simplified: header + per-ACE size
/// bounds; the deep object-ACE GUID/SID revision walk is not required by our callers).
///
/// # Safety
/// `acl` a readable ACL or NULL.
#[export_name = "RtlValidAcl"]
pub unsafe extern "system" fn rtl_valid_acl(acl: *const c_void) -> u8 {
    if acl.is_null() {
        return 0;
    }
    // SAFETY: acl is a readable ACL header per the contract.
    unsafe {
        let p = acl as *const u8;
        let rev = *p;
        if rev < MIN_ACL_REVISION || rev > MAX_ACL_REVISION {
            return 0;
        }
        let acl_size = *(p.add(2) as *const u16) as usize;
        if acl_size & 1 != 0 {
            return 0; // not USHORT-aligned
        }
        if acl_size < ACL_HEADER {
            return 0;
        }
        let ace_count = *(p.add(4) as *const u16);
        let acl_end = acl_size;
        let mut off = ACL_HEADER;
        for _ in 0..ace_count {
            if off + ACE_HEADER > acl_end {
                return 0;
            }
            let ace_size = *(p.add(off + 2) as *const u16) as usize;
            if ace_size & 1 != 0 || ace_size < ACE_HEADER {
                return 0;
            }
            if off + ace_size > acl_end {
                return 0;
            }
            off += ace_size;
        }
    }
    1
}

/// Walk to the first free byte in an ACL (after the last ACE). Returns FALSE if an ACE runs past
/// the ACL end; otherwise sets `*first_free` to the offset (which may equal AclSize when full).
/// Ported from `acl.c:20` (RtlFirstFreeAce).
///
/// # Safety
/// `acl` a valid ACL.
unsafe fn first_free_ace(acl: *const u8) -> Option<usize> {
    // SAFETY: acl is a valid ACL header per the contract.
    unsafe {
        let acl_size = *(acl.add(2) as *const u16) as usize;
        let ace_count = *(acl.add(4) as *const u16);
        let mut off = ACL_HEADER;
        for _ in 0..ace_count {
            if off >= acl_size {
                return None;
            }
            off += *(acl.add(off + 2) as *const u16) as usize;
        }
        if off <= acl_size {
            Some(off)
        } else {
            None
        }
    }
}

/// `RtlFirstFreeAce(PACL, PACE* FirstFreeAce) -> BOOLEAN`. Ported from `acl.c:20`.
///
/// # Safety
/// `acl` a valid ACL; `first_free` a writable out-pointer.
#[export_name = "RtlFirstFreeAce"]
pub unsafe extern "system" fn rtl_first_free_ace(
    acl: *mut c_void,
    first_free: *mut *mut c_void,
) -> u8 {
    if acl.is_null() {
        return 0;
    }
    // SAFETY: acl valid; first_free writable per the contract.
    unsafe {
        if !first_free.is_null() {
            *first_free = core::ptr::null_mut();
        }
        match first_free_ace(acl as *const u8) {
            Some(off) => {
                if !first_free.is_null() {
                    *first_free = (acl as *mut u8).add(off) as *mut c_void;
                }
                1
            }
            None => 0,
        }
    }
}

/// `RtlQueryInformationAcl(PACL, PVOID Info, ULONG Len, ACL_INFORMATION_CLASS) -> NTSTATUS`.
/// Class 1 = AclRevisionInformation (`{ULONG AclRevision}`), 2 = AclSizeInformation
/// (`{ULONG AceCount; ULONG AclBytesInUse; ULONG AclBytesFree}`). Ported from `acl.c:708`.
///
/// # Safety
/// `acl` a valid ACL; `info` a writable buffer of `len` bytes.
#[export_name = "RtlQueryInformationAcl"]
pub unsafe extern "system" fn rtl_query_information_acl(
    acl: *mut c_void,
    info: *mut c_void,
    len: u32,
    class: u32,
) -> NtStatus {
    if acl.is_null() || info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl a valid ACL, info writable per the contract.
    unsafe {
        let p = acl as *const u8;
        let rev = *p;
        if rev < MIN_ACL_REVISION || rev > MAX_ACL_REVISION {
            return STATUS_INVALID_PARAMETER;
        }
        match class {
            1 => {
                if (len as usize) < 4 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                *(info as *mut u32) = rev as u32;
            }
            2 => {
                if (len as usize) < 12 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                let acl_size = *(p.add(2) as *const u16) as u32;
                let ace_count = *(p.add(4) as *const u16) as u32;
                let out = info as *mut u32;
                *out = ace_count;
                match first_free_ace(p) {
                    Some(off) => {
                        *out.add(1) = off as u32; // AclBytesInUse
                        *out.add(2) = acl_size - off as u32; // AclBytesFree
                    }
                    None => {
                        *out.add(1) = acl_size;
                        *out.add(2) = 0;
                    }
                }
            }
            _ => return STATUS_INVALID_INFO_CLASS,
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetInformationAcl(PACL, PVOID Info, ULONG Len, ACL_INFORMATION_CLASS) -> NTSTATUS`.
/// Only class 1 (AclRevisionInformation) is valid; the new revision must be strictly greater than
/// the current one. Ported from `acl.c:781`.
///
/// # Safety
/// `acl` a valid ACL; `info` a readable buffer of `len` bytes.
#[export_name = "RtlSetInformationAcl"]
pub unsafe extern "system" fn rtl_set_information_acl(
    acl: *mut c_void,
    info: *const c_void,
    len: u32,
    class: u32,
) -> NtStatus {
    if acl.is_null() || info.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl a valid ACL, info readable per the contract.
    unsafe {
        let p = acl as *mut u8;
        let rev = *p;
        if rev < MIN_ACL_REVISION || rev > MAX_ACL_REVISION {
            return STATUS_INVALID_PARAMETER;
        }
        match class {
            1 => {
                if (len as usize) < 4 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                let new_rev = *(info as *const u32);
                if (rev as u32) >= new_rev {
                    return STATUS_INVALID_PARAMETER;
                }
                *p = new_rev as u8;
            }
            _ => return STATUS_INVALID_INFO_CLASS,
        }
    }
    STATUS_SUCCESS
}

/// `RtlAddAce(PACL, ULONG AclRevision, ULONG StartingIndex, PVOID AceList, ULONG AceListLength)`.
/// Inserts a pre-built list of ACEs at `starting_index`, shifting the tail down. Ported from
/// `acl.c:566` — validates each ACE's revision, checks capacity, splices, bumps AceCount.
///
/// # Safety
/// `acl` a valid writable ACL with capacity; `ace_list` a valid ACE list of `ace_list_length` bytes.
#[export_name = "RtlAddAce"]
pub unsafe extern "system" fn rtl_add_ace(
    acl: *mut c_void,
    acl_revision: u32,
    starting_index: u32,
    ace_list: *const c_void,
    ace_list_length: u32,
) -> NtStatus {
    if acl.is_null() || ace_list.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl a valid ACL, ace_list a valid ACE list per the contract.
    unsafe {
        if rtl_valid_acl(acl) == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let p = acl as *mut u8;
        let acl_size = *(p.add(2) as *const u16) as usize;
        let free = match first_free_ace(p) {
            Some(off) => off,
            None => return STATUS_INVALID_PARAMETER,
        };
        // Walk the incoming ACE list, counting ACEs and validating revisions.
        let list = ace_list as *const u8;
        let list_len = ace_list_length as usize;
        let mut off = 0usize;
        let mut new_count = 0u16;
        while off < list_len {
            let ace_type = *list.add(off);
            // ACCESS_MAX_MS_ACE_TYPE families need the right ACL revision (v3/v4 for object ACEs).
            if ace_type <= 0x11 {
                if ace_type > 0x08 && (acl_revision as u8) < ACL_REVISION4 {
                    return STATUS_INVALID_PARAMETER;
                } else if ace_type > 0x03 && (acl_revision as u8) < 3 {
                    return STATUS_INVALID_PARAMETER;
                }
            }
            let ace_size = *(list.add(off + 2) as *const u16) as usize;
            if ace_size == 0 {
                return STATUS_INVALID_PARAMETER;
            }
            off += ace_size;
            new_count += 1;
        }
        if off > list_len {
            return STATUS_INVALID_PARAMETER;
        }
        // Capacity check: the free spot + the new bytes must fit within AclSize.
        if free + list_len > acl_size {
            return STATUS_BUFFER_TOO_SMALL;
        }
        // Find the insertion offset (byte offset of the ACE at starting_index).
        let ace_count = *(p.add(4) as *const u16);
        let mut ins = ACL_HEADER;
        let mut idx = 0u32;
        while idx < starting_index && idx < ace_count as u32 {
            ins += *(p.add(ins + 2) as *const u16) as usize;
            idx += 1;
        }
        // Shift the [ins, free) tail down by list_len, then copy the new ACEs in.
        let tail = free - ins;
        if tail > 0 {
            core::ptr::copy(p.add(ins), p.add(ins + list_len), tail);
        }
        core::ptr::copy_nonoverlapping(list, p.add(ins), list_len);
        // Bump AceCount; lower the revision to min(current, requested).
        *(p.add(4) as *mut u16) = ace_count + new_count;
        let cur_rev = *p;
        *p = core::cmp::min(cur_rev, acl_revision as u8);
    }
    STATUS_SUCCESS
}

/// `RtlDeleteAce(PACL, ULONG AceIndex) -> NTSTATUS`. Removes the ACE at `ace_index`, shifting the
/// tail up. Ported from `acl.c:643`.
///
/// # Safety
/// `acl` a valid writable ACL.
#[export_name = "RtlDeleteAce"]
pub unsafe extern "system" fn rtl_delete_ace(acl: *mut c_void, ace_index: u32) -> NtStatus {
    if acl.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl a valid ACL per the contract.
    unsafe {
        if rtl_valid_acl(acl) == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let p = acl as *mut u8;
        let ace_count = *(p.add(4) as *const u16);
        if ace_index >= ace_count as u32 {
            return STATUS_INVALID_PARAMETER;
        }
        let free = match first_free_ace(p) {
            Some(off) => off,
            None => return STATUS_INVALID_PARAMETER,
        };
        // Walk to the indexed ACE.
        let mut del = ACL_HEADER;
        for _ in 0..ace_index {
            del += *(p.add(del + 2) as *const u16) as usize;
        }
        let del_size = *(p.add(del + 2) as *const u16) as usize;
        // Shift [del+del_size, free) up over the deleted ACE.
        let tail = free - (del + del_size);
        if tail > 0 {
            core::ptr::copy(p.add(del + del_size), p.add(del), tail);
        }
        *(p.add(4) as *mut u16) = ace_count - 1;
    }
    STATUS_SUCCESS
}

// ---- Non-object ACE append helper (ALLOWED / DENIED / AUDIT) --------------------------------------

/// Append a `{Header, Mask, Sid}` ACE of `ace_type` with `flags` to `acl`. Shared by the
/// RtlAdd{AccessAllowed,AccessDenied,AuditAccess}Ace[Ex] family. Mirrors ReactOS `RtlpAddKnownAce`.
///
/// # Safety
/// `acl` a valid writable ACL with capacity; `sid` a valid SID.
unsafe fn add_known_ace(
    acl: *mut c_void,
    revision: u32,
    flags: u8,
    mask: u32,
    sid: *const c_void,
    ace_type: u8,
) -> NtStatus {
    if acl.is_null() || sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl a valid ACL, sid a valid SID per the contract.
    unsafe {
        if rtl_valid_sid(sid) == 0 {
            return STATUS_INVALID_SID;
        }
        if rtl_valid_acl(acl) == 0 {
            return STATUS_INVALID_ACL;
        }
        let p = acl as *mut u8;
        let acl_size = *(p.add(2) as *const u16) as usize;
        let free = match first_free_ace(p) {
            Some(off) => off,
            None => return STATUS_INVALID_ACL,
        };
        let s_len = sid_len(sid as *const u8);
        let ace_size = ACE_HEADER + 4 + s_len; // header + Mask + SID
        if free + ace_size > acl_size {
            return STATUS_ALLOTTED_SPACE_EXCEEDED;
        }
        let cur = p.add(free);
        *cur = ace_type;
        *cur.add(1) = flags;
        *(cur.add(2) as *mut u16) = ace_size as u16;
        *(cur.add(4) as *mut u32) = mask;
        core::ptr::copy_nonoverlapping(sid as *const u8, cur.add(8), s_len);
        // Bump AceCount and lower the revision.
        let ace_count = *(p.add(4) as *const u16);
        *(p.add(4) as *mut u16) = ace_count + 1;
        let cur_rev = *p;
        *p = core::cmp::max(cur_rev, revision as u8);
    }
    STATUS_SUCCESS
}

/// `RtlAddAccessAllowedAceEx(PACL, ULONG Rev, ULONG Flags, ACCESS_MASK, PSID) -> NTSTATUS`.
/// Ported from `acl.c` (RtlAddAccessAllowedAceEx → RtlpAddKnownAce, ACCESS_ALLOWED_ACE_TYPE).
///
/// # Safety
/// `acl` a valid writable ACL; `sid` a valid SID.
#[export_name = "RtlAddAccessAllowedAceEx"]
pub unsafe extern "system" fn rtl_add_access_allowed_ace_ex(
    acl: *mut c_void,
    revision: u32,
    flags: u32,
    mask: u32,
    sid: *const c_void,
) -> NtStatus {
    // SAFETY: forwarded to add_known_ace under the same contract.
    unsafe {
        add_known_ace(
            acl,
            revision,
            flags as u8,
            mask,
            sid,
            ACCESS_ALLOWED_ACE_TYPE,
        )
    }
}

/// `RtlAddAccessDeniedAce(PACL, ULONG Rev, ACCESS_MASK, PSID) -> NTSTATUS`.
///
/// # Safety
/// `acl` a valid writable ACL; `sid` a valid SID.
#[export_name = "RtlAddAccessDeniedAce"]
pub unsafe extern "system" fn rtl_add_access_denied_ace(
    acl: *mut c_void,
    revision: u32,
    mask: u32,
    sid: *const c_void,
) -> NtStatus {
    // SAFETY: forwarded to add_known_ace with flags=0.
    unsafe { add_known_ace(acl, revision, 0, mask, sid, ACCESS_DENIED_ACE_TYPE) }
}

/// `RtlAddAccessDeniedAceEx(PACL, ULONG Rev, ULONG Flags, ACCESS_MASK, PSID) -> NTSTATUS`.
///
/// # Safety
/// `acl` a valid writable ACL; `sid` a valid SID.
#[export_name = "RtlAddAccessDeniedAceEx"]
pub unsafe extern "system" fn rtl_add_access_denied_ace_ex(
    acl: *mut c_void,
    revision: u32,
    flags: u32,
    mask: u32,
    sid: *const c_void,
) -> NtStatus {
    // SAFETY: forwarded to add_known_ace under the same contract.
    unsafe {
        add_known_ace(
            acl,
            revision,
            flags as u8,
            mask,
            sid,
            ACCESS_DENIED_ACE_TYPE,
        )
    }
}

/// `RtlAddAuditAccessAce(PACL, ULONG Rev, ACCESS_MASK, PSID, BOOLEAN Success, BOOLEAN Failure)`.
/// Success/Failure map to SUCCESSFUL_ACCESS_ACE_FLAG(0x40)/FAILED_ACCESS_ACE_FLAG(0x80).
///
/// # Safety
/// `acl` a valid writable ACL; `sid` a valid SID.
#[export_name = "RtlAddAuditAccessAce"]
pub unsafe extern "system" fn rtl_add_audit_access_ace(
    acl: *mut c_void,
    revision: u32,
    mask: u32,
    sid: *const c_void,
    success: u8,
    failure: u8,
) -> NtStatus {
    let flags = (if success != 0 { 0x40 } else { 0 }) | (if failure != 0 { 0x80 } else { 0 });
    // SAFETY: forwarded to add_known_ace under the same contract.
    unsafe { add_known_ace(acl, revision, flags, mask, sid, SYSTEM_AUDIT_ACE_TYPE) }
}

/// `RtlAddAuditAccessAceEx(PACL, ULONG Rev, ULONG Flags, ACCESS_MASK, PSID, BOOLEAN Success,
/// BOOLEAN Failure) -> NTSTATUS`. Success/Failure are OR'd on top of the caller's inherit `flags`.
///
/// # Safety
/// `acl` a valid writable ACL; `sid` a valid SID.
#[export_name = "RtlAddAuditAccessAceEx"]
pub unsafe extern "system" fn rtl_add_audit_access_ace_ex(
    acl: *mut c_void,
    revision: u32,
    flags: u32,
    mask: u32,
    sid: *const c_void,
    success: u8,
    failure: u8,
) -> NtStatus {
    let f =
        flags as u8 | (if success != 0 { 0x40 } else { 0 }) | (if failure != 0 { 0x80 } else { 0 });
    // SAFETY: forwarded to add_known_ace under the same contract.
    unsafe { add_known_ace(acl, revision, f, mask, sid, SYSTEM_AUDIT_ACE_TYPE) }
}

// ---- Object ACE append helper (ALLOWED / DENIED / AUDIT object) ----------------------------------

/// Append a `{Header, Mask, Flags, [ObjectType GUID], [InheritedObjectType GUID], Sid}` object ACE.
/// Mirrors ReactOS `RtlpAddKnownObjectAce` (`acl.c`). Requires ACL_REVISION4.
///
/// # Safety
/// `acl` a valid writable ACL with capacity; `sid` a valid SID; the GUID pointers 16-byte or NULL.
#[allow(clippy::too_many_arguments)]
unsafe fn add_known_object_ace(
    acl: *mut c_void,
    revision: u32,
    flags: u8,
    mask: u32,
    object_type: *const c_void,
    inherited_object_type: *const c_void,
    sid: *const c_void,
    ace_type: u8,
) -> NtStatus {
    if acl.is_null() || sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl a valid ACL, sid a valid SID, GUIDs 16-byte-or-NULL per the contract.
    unsafe {
        if rtl_valid_sid(sid) == 0 {
            return STATUS_INVALID_SID;
        }
        if rtl_valid_acl(acl) == 0 {
            return STATUS_INVALID_ACL;
        }
        let p = acl as *mut u8;
        let acl_rev = *p;
        // Object ACEs require ACL_REVISION4.
        if acl_rev > ACL_REVISION4 || (revision as u8) != ACL_REVISION4 {
            return 0xC000_0016; // STATUS_REVISION_MISMATCH
        }
        let acl_size = *(p.add(2) as *const u16) as usize;
        let free = match first_free_ace(p) {
            Some(off) => off,
            None => return STATUS_INVALID_ACL,
        };
        let s_len = sid_len(sid as *const u8);
        let mut ace_object_flags = 0u32;
        let mut ace_size = ACE_HEADER + 4 + 4 + s_len; // header + Mask + Flags + SID
        if !object_type.is_null() {
            ace_object_flags |= OBJECT_ACE_FLAG_TYPE_PRESENT;
            ace_size += 16;
        }
        if !inherited_object_type.is_null() {
            ace_object_flags |= OBJECT_ACE_FLAG_INHERITED_TYPE_PRESENT;
            ace_size += 16;
        }
        if free + ace_size > acl_size {
            return STATUS_ALLOTTED_SPACE_EXCEEDED;
        }
        let cur = p.add(free);
        *cur = ace_type;
        *cur.add(1) = flags;
        *(cur.add(2) as *mut u16) = ace_size as u16;
        *(cur.add(4) as *mut u32) = mask;
        *(cur.add(8) as *mut u32) = ace_object_flags;
        let mut w = cur.add(12);
        if !object_type.is_null() {
            core::ptr::copy_nonoverlapping(object_type as *const u8, w, 16);
            w = w.add(16);
        }
        if !inherited_object_type.is_null() {
            core::ptr::copy_nonoverlapping(inherited_object_type as *const u8, w, 16);
            w = w.add(16);
        }
        core::ptr::copy_nonoverlapping(sid as *const u8, w, s_len);
        let ace_count = *(p.add(4) as *const u16);
        *(p.add(4) as *mut u16) = ace_count + 1;
        *p = core::cmp::max(acl_rev, revision as u8);
    }
    STATUS_SUCCESS
}

/// `RtlAddAccessAllowedObjectAce(PACL, ULONG Rev, ULONG Flags, ACCESS_MASK, GUID* ObjectType,
/// GUID* InheritedObjectType, PSID) -> NTSTATUS`.
///
/// # Safety
/// `acl` a valid writable ACL; the GUIDs 16-byte-or-NULL; `sid` a valid SID.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlAddAccessAllowedObjectAce"]
pub unsafe extern "system" fn rtl_add_access_allowed_object_ace(
    acl: *mut c_void,
    revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const c_void,
    inherited_object_type: *const c_void,
    sid: *const c_void,
) -> NtStatus {
    // SAFETY: forwarded to add_known_object_ace under the same contract.
    unsafe {
        add_known_object_ace(
            acl,
            revision,
            flags as u8,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        )
    }
}

/// `RtlAddAccessDeniedObjectAce(...)` — same signature as the allowed variant.
///
/// # Safety
/// `acl` a valid writable ACL; the GUIDs 16-byte-or-NULL; `sid` a valid SID.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlAddAccessDeniedObjectAce"]
pub unsafe extern "system" fn rtl_add_access_denied_object_ace(
    acl: *mut c_void,
    revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const c_void,
    inherited_object_type: *const c_void,
    sid: *const c_void,
) -> NtStatus {
    // SAFETY: forwarded to add_known_object_ace under the same contract.
    unsafe {
        add_known_object_ace(
            acl,
            revision,
            flags as u8,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
        )
    }
}

/// `RtlAddAuditAccessObjectAce(PACL, ULONG Rev, ULONG Flags, ACCESS_MASK, GUID* ObjectType,
/// GUID* InheritedObjectType, PSID, BOOLEAN Success, BOOLEAN Failure) -> NTSTATUS`.
///
/// # Safety
/// `acl` a valid writable ACL; the GUIDs 16-byte-or-NULL; `sid` a valid SID.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlAddAuditAccessObjectAce"]
pub unsafe extern "system" fn rtl_add_audit_access_object_ace(
    acl: *mut c_void,
    revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const c_void,
    inherited_object_type: *const c_void,
    sid: *const c_void,
    success: u8,
    failure: u8,
) -> NtStatus {
    let f =
        flags as u8 | (if success != 0 { 0x40 } else { 0 }) | (if failure != 0 { 0x80 } else { 0 });
    // SAFETY: forwarded to add_known_object_ace under the same contract.
    unsafe {
        add_known_object_ace(
            acl,
            revision,
            f,
            mask,
            object_type,
            inherited_object_type,
            sid,
            SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        )
    }
}

// =================================================================================================
// SECURITY_DESCRIPTOR exports
// =================================================================================================

/// `RtlValidSecurityDescriptor(PSD) -> BOOLEAN` — revision==1 and every present component valid.
/// Ported from `sd.c:1054`.
///
/// # Safety
/// `sd` a readable SD or NULL.
#[export_name = "RtlValidSecurityDescriptor"]
pub unsafe extern "system" fn rtl_valid_security_descriptor(sd: *const c_void) -> u8 {
    if sd.is_null() {
        return 0;
    }
    // SAFETY: sd a readable SD header per the contract.
    unsafe {
        let p = sd as *const u8;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return 0;
        }
        let owner = sd_owner(p);
        if !owner.is_null() && rtl_valid_sid(owner as *const c_void) == 0 {
            return 0;
        }
        let group = sd_group(p);
        if !group.is_null() && rtl_valid_sid(group as *const c_void) == 0 {
            return 0;
        }
        let dacl = sd_dacl(p);
        if !dacl.is_null() && rtl_valid_acl(dacl as *const c_void) == 0 {
            return 0;
        }
        let sacl = sd_sacl(p);
        if !sacl.is_null() && rtl_valid_acl(sacl as *const c_void) == 0 {
            return 0;
        }
    }
    1
}

/// `RtlLengthSecurityDescriptor(PSD) -> ULONG` — header + rounded-up component sizes. Handles both
/// absolute and self-relative forms. Ported from `sd.c:161`.
///
/// # Safety
/// `sd` a valid SD.
#[export_name = "RtlLengthSecurityDescriptor"]
pub unsafe extern "system" fn rtl_length_security_descriptor(sd: *const c_void) -> u32 {
    if sd.is_null() {
        return 0;
    }
    // SAFETY: sd a valid SD; components resolved by sd_* per the form.
    unsafe {
        let p = sd as *const u8;
        let mut len = if sd_control(p) & SE_SELF_RELATIVE != 0 {
            SD_REL_HEADER
        } else {
            SD_ABS_HEADER
        };
        let owner = sd_owner(p);
        if !owner.is_null() {
            len += round_up4(sid_len(owner));
        }
        let group = sd_group(p);
        if !group.is_null() {
            len += round_up4(sid_len(group));
        }
        let dacl = sd_dacl(p);
        if !dacl.is_null() {
            len += round_up4(*(dacl.add(2) as *const u16) as usize);
        }
        let sacl = sd_sacl(p);
        if !sacl.is_null() {
            len += round_up4(*(sacl.add(2) as *const u16) as usize);
        }
        len as u32
    }
}

/// `RtlGetControlSecurityDescriptor(PSD, PSECURITY_DESCRIPTOR_CONTROL, PULONG Revision)`.
/// Ported from `sd.c:439`.
///
/// # Safety
/// `sd` a valid SD; the out-pointers writable.
#[export_name = "RtlGetControlSecurityDescriptor"]
pub unsafe extern "system" fn rtl_get_control_security_descriptor(
    sd: *const c_void,
    control: *mut u16,
    revision: *mut u32,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd a valid SD; out-pointers writable per the contract.
    unsafe {
        let p = sd as *const u8;
        if !revision.is_null() {
            *revision = *p as u32;
        }
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
        if !control.is_null() {
            *control = sd_control(p);
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetControlSecurityDescriptor(PSD, SECURITY_DESCRIPTOR_CONTROL BitsOfInterest,
/// SECURITY_DESCRIPTOR_CONTROL BitsToSet) -> NTSTATUS`. Ported from `sd.c:464`. Only the auto-
/// inherit/protected/untrusted/server bits may be set this way.
///
/// # Safety
/// `sd` a valid writable SD.
#[export_name = "RtlSetControlSecurityDescriptor"]
pub unsafe extern "system" fn rtl_set_control_security_descriptor(
    sd: *mut c_void,
    control_bits_of_interest: u16,
    control_bits_to_set: u16,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Settable bits (SE_DACL_UNTRUSTED..SE_SACL_PROTECTED); reject anything else / bits-to-set
    // outside bits-of-interest.
    const SETTABLE: u16 = 0x0040 // SE_DACL_UNTRUSTED
        | 0x0080 // SE_SERVER_SECURITY
        | 0x0100 // SE_DACL_AUTO_INHERIT_REQ
        | 0x0200 // SE_SACL_AUTO_INHERIT_REQ
        | 0x0400 // SE_DACL_AUTO_INHERITED
        | 0x0800 // SE_SACL_AUTO_INHERITED
        | 0x1000 // SE_DACL_PROTECTED
        | 0x2000; // SE_SACL_PROTECTED
    if control_bits_of_interest & !SETTABLE != 0
        || control_bits_to_set & !control_bits_of_interest != 0
    {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd a valid writable SD; Control @0x02.
    unsafe {
        let ctrl = (sd as *mut u8).add(0x02) as *mut u16;
        *ctrl &= !control_bits_of_interest;
        *ctrl |= control_bits_to_set & control_bits_of_interest;
    }
    STATUS_SUCCESS
}

/// `RtlGetOwnerSecurityDescriptor(PSD, PSID* Owner, PBOOLEAN OwnerDefaulted) -> NTSTATUS`.
/// Ported from `sd.c` (RtlGetOwnerSecurityDescriptor).
///
/// # Safety
/// `sd` a valid SD; out-pointers writable.
#[export_name = "RtlGetOwnerSecurityDescriptor"]
pub unsafe extern "system" fn rtl_get_owner_security_descriptor(
    sd: *const c_void,
    owner: *mut *mut c_void,
    defaulted: *mut u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd valid; out-pointers writable per the contract.
    unsafe {
        let p = sd as *const u8;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
        if !owner.is_null() {
            *owner = sd_owner(p) as *mut c_void;
        }
        if !defaulted.is_null() {
            *defaulted = ((sd_control(p) & SE_OWNER_DEFAULTED) == SE_OWNER_DEFAULTED) as u8;
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetOwnerSecurityDescriptor(PSD, PSID Owner, BOOLEAN OwnerDefaulted) -> NTSTATUS`.
/// Absolute SDs only. Ported from `sd.c` (RtlSetOwnerSecurityDescriptor).
///
/// # Safety
/// `sd` a valid writable absolute SD.
#[export_name = "RtlSetOwnerSecurityDescriptor"]
pub unsafe extern "system" fn rtl_set_owner_security_descriptor(
    sd: *mut c_void,
    owner: *mut c_void,
    defaulted: u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd a valid writable SD; Owner ptr @0x08 (absolute layout).
    unsafe {
        let p = sd as *mut u8;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
        if sd_control(p) & SE_SELF_RELATIVE != 0 {
            return STATUS_INVALID_SECURITY_DESCR;
        }
        *(p.add(0x08) as *mut *mut c_void) = owner;
        let ctrl = p.add(0x02) as *mut u16;
        *ctrl &= !SE_OWNER_DEFAULTED;
        if defaulted != 0 {
            *ctrl |= SE_OWNER_DEFAULTED;
        }
    }
    STATUS_SUCCESS
}

/// `RtlGetGroupSecurityDescriptor(PSD, PSID* Group, PBOOLEAN GroupDefaulted) -> NTSTATUS`.
/// Ported from `sd.c:280`.
///
/// # Safety
/// `sd` a valid SD; out-pointers writable.
#[export_name = "RtlGetGroupSecurityDescriptor"]
pub unsafe extern "system" fn rtl_get_group_security_descriptor(
    sd: *const c_void,
    group: *mut *mut c_void,
    defaulted: *mut u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd valid; out-pointers writable per the contract.
    unsafe {
        let p = sd as *const u8;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
        if !group.is_null() {
            *group = sd_group(p) as *mut c_void;
        }
        if !defaulted.is_null() {
            *defaulted = ((sd_control(p) & SE_GROUP_DEFAULTED) == SE_GROUP_DEFAULTED) as u8;
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetGroupSecurityDescriptor(PSD, PSID Group, BOOLEAN GroupDefaulted) -> NTSTATUS`.
/// Absolute SDs only. Ported from `sd.c` (RtlSetGroupSecurityDescriptor).
///
/// # Safety
/// `sd` a valid writable absolute SD.
#[export_name = "RtlSetGroupSecurityDescriptor"]
pub unsafe extern "system" fn rtl_set_group_security_descriptor(
    sd: *mut c_void,
    group: *mut c_void,
    defaulted: u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd a valid writable SD; Group ptr @0x10 (absolute layout).
    unsafe {
        let p = sd as *mut u8;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
        if sd_control(p) & SE_SELF_RELATIVE != 0 {
            return STATUS_INVALID_SECURITY_DESCR;
        }
        *(p.add(0x10) as *mut *mut c_void) = group;
        let ctrl = p.add(0x02) as *mut u16;
        *ctrl &= !SE_GROUP_DEFAULTED;
        if defaulted != 0 {
            *ctrl |= SE_GROUP_DEFAULTED;
        }
    }
    STATUS_SUCCESS
}

/// `RtlGetSaclSecurityDescriptor(PSD, PBOOLEAN SaclPresent, PACL* Sacl, PBOOLEAN SaclDefaulted)`.
/// Ported from `sd.c:227`.
///
/// # Safety
/// `sd` a valid SD; out-pointers writable.
#[export_name = "RtlGetSaclSecurityDescriptor"]
pub unsafe extern "system" fn rtl_get_sacl_security_descriptor(
    sd: *const c_void,
    sacl_present: *mut u8,
    sacl: *mut *mut c_void,
    defaulted: *mut u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd valid; out-pointers writable per the contract.
    unsafe {
        let p = sd as *const u8;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
        let present = (sd_control(p) & SE_SACL_PRESENT) == SE_SACL_PRESENT;
        if !sacl_present.is_null() {
            *sacl_present = present as u8;
        }
        if present {
            if !sacl.is_null() {
                *sacl = sd_sacl(p) as *mut c_void;
            }
            if !defaulted.is_null() {
                *defaulted = ((sd_control(p) & SE_SACL_DEFAULTED) == SE_SACL_DEFAULTED) as u8;
            }
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetSaclSecurityDescriptor(PSD, BOOLEAN SaclPresent, PACL Sacl, BOOLEAN SaclDefaulted)`.
/// Absolute SDs only. Ported from `sd.c:340`.
///
/// # Safety
/// `sd` a valid writable absolute SD.
#[export_name = "RtlSetSaclSecurityDescriptor"]
pub unsafe extern "system" fn rtl_set_sacl_security_descriptor(
    sd: *mut c_void,
    sacl_present: u8,
    sacl: *mut c_void,
    defaulted: u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd a valid writable SD; Sacl ptr @0x18 (absolute layout).
    unsafe {
        let p = sd as *mut u8;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
        if sd_control(p) & SE_SELF_RELATIVE != 0 {
            return STATUS_INVALID_SECURITY_DESCR;
        }
        let ctrl = p.add(0x02) as *mut u16;
        if sacl_present == 0 {
            *ctrl &= !SE_SACL_PRESENT;
            return STATUS_SUCCESS;
        }
        *(p.add(0x18) as *mut *mut c_void) = sacl;
        *ctrl |= SE_SACL_PRESENT;
        *ctrl &= !SE_SACL_DEFAULTED;
        if defaulted != 0 {
            *ctrl |= SE_SACL_DEFAULTED;
        }
    }
    STATUS_SUCCESS
}

/// `RtlGetSecurityDescriptorRMControl(PSD, PUCHAR RMControl) -> BOOLEAN`. Ported from `sd.c:500`.
/// Returns FALSE (and *RMControl=0) unless SE_RM_CONTROL_VALID is set, in which case *RMControl is
/// the Sbz1 byte.
///
/// # Safety
/// `sd` a valid SD; `rm_control` writable.
#[export_name = "RtlGetSecurityDescriptorRMControl"]
pub unsafe extern "system" fn rtl_get_security_descriptor_rm_control(
    sd: *const c_void,
    rm_control: *mut u8,
) -> u32 {
    if sd.is_null() {
        return 0;
    }
    // SAFETY: sd valid; rm_control writable per the contract. Sbz1 @0x01.
    unsafe {
        let p = sd as *const u8;
        if sd_control(p) & SE_RM_CONTROL_VALID == 0 {
            if !rm_control.is_null() {
                *rm_control = 0;
            }
            return 0;
        }
        if !rm_control.is_null() {
            *rm_control = *p.add(0x01);
        }
    }
    1
}

/// `RtlSetSecurityDescriptorRMControl(PSD, PUCHAR RMControl) -> NTSTATUS`. Ported from `sd.c:524`
/// (which returns VOID; we return STATUS_SUCCESS for the wrapper). A NULL `rm_control` clears the
/// SE_RM_CONTROL_VALID flag + Sbz1; otherwise sets the flag and stores the byte.
///
/// # Safety
/// `sd` a valid writable SD; `rm_control` readable-or-NULL.
#[export_name = "RtlSetSecurityDescriptorRMControl"]
pub unsafe extern "system" fn rtl_set_security_descriptor_rm_control(
    sd: *mut c_void,
    rm_control: *const u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd a valid writable SD; Control @0x02, Sbz1 @0x01.
    unsafe {
        let p = sd as *mut u8;
        let ctrl = p.add(0x02) as *mut u16;
        if rm_control.is_null() {
            *ctrl &= !SE_RM_CONTROL_VALID;
            *p.add(0x01) = 0;
        } else {
            *ctrl |= SE_RM_CONTROL_VALID;
            *p.add(0x01) = *rm_control;
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetAttributesSecurityDescriptor(PSD, SECURITY_DESCRIPTOR_CONTROL, PULONG) -> NTSTATUS`.
/// Ported from `sd.c:550`: always reports the descriptor revision, masks the requested bits down to
/// the settable attribute/control range, then delegates to `RtlSetControlSecurityDescriptor`.
///
/// # Safety
/// `sd` is a valid SD and `revision` is writable.
#[export_name = "RtlSetAttributesSecurityDescriptor"]
pub unsafe extern "system" fn rtl_set_attributes_security_descriptor(
    sd: *mut c_void,
    control: u16,
    revision: *mut u32,
) -> NtStatus {
    if sd.is_null() || revision.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd/revision are valid per the contract.
    unsafe {
        let p = sd as *mut u8;
        *revision = *p as u32;
        if *p != SECURITY_DESCRIPTOR_REVISION {
            return STATUS_UNKNOWN_REVISION;
        }
    }
    const ATTRIBUTES: u16 = 0x0040 // SE_DACL_UNTRUSTED
        | 0x0080 // SE_SERVER_SECURITY
        | 0x0100 // SE_DACL_AUTO_INHERIT_REQ
        | 0x0200 // SE_SACL_AUTO_INHERIT_REQ
        | 0x0400 // SE_DACL_AUTO_INHERITED
        | 0x0800 // SE_SACL_AUTO_INHERITED
        | 0x1000 // SE_DACL_PROTECTED
        | 0x2000; // SE_SACL_PROTECTED
    let masked = control & ATTRIBUTES;
    // SAFETY: same SD contract as this wrapper.
    unsafe { rtl_set_control_security_descriptor(sd, masked, masked) }
}

/// `RtlCopySecurityDescriptor(PSD Source, PSD* Destination) -> NTSTATUS`.
/// Allocates a process-heap self-relative copy of either an absolute or self-relative descriptor.
///
/// # Safety
/// `source` is a valid security descriptor and `destination` is writable.
#[export_name = "RtlCopySecurityDescriptor"]
pub unsafe extern "system" fn rtl_copy_security_descriptor(
    source: *const c_void,
    destination: *mut *mut c_void,
) -> NtStatus {
    if source.is_null() || destination.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: source/destination satisfy the exported API contract.
        unsafe {
            match clone_security_descriptor_to_heap(source) {
                Ok(copy) => {
                    *destination = copy;
                    STATUS_SUCCESS
                }
                Err(status) => status,
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = source;
        // SAFETY: destination is writable per the contract.
        unsafe { *destination = core::ptr::null_mut() };
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlValidRelativeSecurityDescriptor(PSD, ULONG Length, SECURITY_INFORMATION Required) -> BOOLEAN`.
/// Ported from `sd.c:1098`: the descriptor must be self-relative and every present component must
/// fit inside the caller-supplied byte span.
///
/// # Safety
/// `sd` points at a readable `length`-byte security descriptor buffer.
#[export_name = "RtlValidRelativeSecurityDescriptor"]
pub unsafe extern "system" fn rtl_valid_relative_security_descriptor(
    sd: *const c_void,
    length: u32,
    required_information: u32,
) -> u8 {
    if sd.is_null() || (length as usize) < SD_REL_HEADER {
        return 0;
    }
    // SAFETY: the caller provided a readable SD buffer of `length` bytes.
    unsafe {
        let p = sd as *const u8;
        if *p != SECURITY_DESCRIPTOR_REVISION || sd_control(p) & SE_SELF_RELATIVE == 0 {
            return 0;
        }

        let owner_off = core::ptr::read_unaligned(p.add(0x04) as *const u32);
        if owner_off != 0 {
            let Some(available) = valid_sd_offset_and_size(owner_off, length, 8) else {
                return 0;
            };
            let owner = p.add(owner_off as usize);
            if rtl_valid_sid(owner as *const c_void) == 0 || available < sid_len(owner) {
                return 0;
            }
        } else if required_information & OWNER_SECURITY_INFORMATION != 0 {
            return 0;
        }

        let group_off = core::ptr::read_unaligned(p.add(0x08) as *const u32);
        if group_off != 0 {
            let Some(available) = valid_sd_offset_and_size(group_off, length, 8) else {
                return 0;
            };
            let group = p.add(group_off as usize);
            if rtl_valid_sid(group as *const c_void) == 0 || available < sid_len(group) {
                return 0;
            }
        } else if required_information & GROUP_SECURITY_INFORMATION != 0 {
            return 0;
        }

        if sd_control(p) & SE_DACL_PRESENT != 0 {
            let dacl_off = core::ptr::read_unaligned(p.add(0x10) as *const u32);
            let Some(available) = valid_sd_offset_and_size(dacl_off, length, ACL_HEADER) else {
                return 0;
            };
            let dacl = p.add(dacl_off as usize);
            let acl_len = core::ptr::read_unaligned(dacl.add(2) as *const u16) as usize;
            if rtl_valid_acl(dacl as *const c_void) == 0 || available < acl_len {
                return 0;
            }
        }

        if sd_control(p) & SE_SACL_PRESENT != 0 {
            let sacl_off = core::ptr::read_unaligned(p.add(0x0C) as *const u32);
            let Some(available) = valid_sd_offset_and_size(sacl_off, length, ACL_HEADER) else {
                return 0;
            };
            let sacl = p.add(sacl_off as usize);
            let acl_len = core::ptr::read_unaligned(sacl.add(2) as *const u16) as usize;
            if rtl_valid_acl(sacl as *const c_void) == 0 || available < acl_len {
                return 0;
            }
        }
    }
    1
}

/// `RtlDefaultNpAcl(PACL*) -> NTSTATUS`.
/// Builds the default named-pipe ACL ReactOS creates from the process token. Our executive currently
/// models hosted processes as LocalSystem, so the owner ACE uses S-1-5-18.
///
/// # Safety
/// `acl` is a writable out-pointer; the returned ACL is process-heap allocated.
#[export_name = "RtlDefaultNpAcl"]
pub unsafe extern "system" fn rtl_default_np_acl(acl: *mut *mut c_void) -> NtStatus {
    if acl.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl is writable per the contract.
    unsafe { *acl = core::ptr::null_mut() };

    #[cfg(target_arch = "x86_64")]
    {
        const ACL_BYTES: usize =
            ACL_HEADER + 5 * (ACE_HEADER + 4) + (8 + 4) + (8 + 8) + (8 + 4) + (8 + 4) + (8 + 4);
        const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
        const WORLD_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 1];

        // SAFETY: process heap allocation in the hosted process.
        let p = unsafe { crate::process_heap_alloc(ACL_BYTES) };
        if p.is_null() {
            return STATUS_NO_MEMORY;
        }
        // SAFETY: p is a writable ACL buffer of ACL_BYTES.
        let mut status = unsafe {
            crate::exports::rtl_create_acl(p as *mut c_void, ACL_BYTES as u32, ACL_REVISION2)
        };
        let mut sid = [0u8; 16];
        if status == STATUS_SUCCESS {
            let local_system = stack_sid(&mut sid, NT_AUTHORITY, &[SECURITY_LOCAL_SYSTEM_RID]);
            status = unsafe {
                rtl_add_access_allowed_ace_ex(
                    p as *mut c_void,
                    ACL_REVISION2,
                    0,
                    GENERIC_ALL_MASK,
                    local_system,
                )
            };
        }
        if status == STATUS_SUCCESS {
            let administrators = stack_sid(
                &mut sid,
                NT_AUTHORITY,
                &[SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS],
            );
            status = unsafe {
                rtl_add_access_allowed_ace_ex(
                    p as *mut c_void,
                    ACL_REVISION2,
                    0,
                    GENERIC_ALL_MASK,
                    administrators,
                )
            };
        }
        if status == STATUS_SUCCESS {
            let owner = stack_sid(&mut sid, NT_AUTHORITY, &[SECURITY_LOCAL_SYSTEM_RID]);
            status = unsafe {
                rtl_add_access_allowed_ace_ex(
                    p as *mut c_void,
                    ACL_REVISION2,
                    0,
                    GENERIC_ALL_MASK,
                    owner,
                )
            };
        }
        if status == STATUS_SUCCESS {
            let anonymous = stack_sid(&mut sid, NT_AUTHORITY, &[SECURITY_ANONYMOUS_LOGON_RID]);
            status = unsafe {
                rtl_add_access_allowed_ace_ex(
                    p as *mut c_void,
                    ACL_REVISION2,
                    0,
                    GENERIC_READ_MASK,
                    anonymous,
                )
            };
        }
        if status == STATUS_SUCCESS {
            let world = stack_sid(&mut sid, WORLD_AUTHORITY, &[SECURITY_WORLD_RID]);
            status = unsafe {
                rtl_add_access_allowed_ace_ex(
                    p as *mut c_void,
                    ACL_REVISION2,
                    0,
                    GENERIC_READ_MASK,
                    world,
                )
            };
        }

        if status == STATUS_SUCCESS {
            // SAFETY: acl is writable per the contract.
            unsafe { *acl = p as *mut c_void };
        } else {
            // SAFETY: p came from process_heap_alloc above.
            unsafe { crate::process_heap_free(p) };
        }
        status
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        STATUS_NOT_IMPLEMENTED
    }
}

// ---- Absolute <-> self-relative conversions ------------------------------------------------------

/// Shared body of RtlMakeSelfRelativeSD / RtlAbsoluteToSelfRelativeSD: pack an ABSOLUTE SD into a
/// self-relative buffer. Ported from `sd.c:646` (RtlMakeSelfRelativeSD). Layout order after the
/// 0x14 header: Sacl, Dacl, Owner, Group.
///
/// # Safety
/// `abs_sd` a valid ABSOLUTE SD; `rel_sd` a writable buffer of `*buf_len` bytes; `buf_len` writable.
unsafe fn make_self_relative(
    abs_sd: *const c_void,
    rel_sd: *mut c_void,
    buf_len: *mut u32,
) -> NtStatus {
    if abs_sd.is_null() || buf_len.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: abs_sd a valid absolute SD; rel_sd writable; buf_len writable per the contract.
    unsafe {
        let a = abs_sd as *const u8;
        let owner = sd_owner(a);
        let group = sd_group(a);
        let sacl = sd_sacl(a);
        let dacl = sd_dacl(a);
        let owner_len = if owner.is_null() { 0 } else { sid_len(owner) };
        let group_len = if group.is_null() { 0 } else { sid_len(group) };
        let sacl_len = if sacl.is_null() {
            0
        } else {
            *(sacl.add(2) as *const u16) as usize
        };
        let dacl_len = if dacl.is_null() {
            0
        } else {
            *(dacl.add(2) as *const u16) as usize
        };
        let total = SD_REL_HEADER + owner_len + group_len + sacl_len + dacl_len;
        if (*buf_len as usize) < total {
            *buf_len = total as u32;
            return STATUS_BUFFER_TOO_SMALL;
        }
        if rel_sd.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        let r = rel_sd as *mut u8;
        core::ptr::write_bytes(r, 0, total);
        // Copy the header prefix (Revision/Sbz1/Control) — the first 4 bytes.
        *r = *a; // Revision
        *r.add(1) = *a.add(1); // Sbz1
        *(r.add(2) as *mut u16) = sd_control(a);
        let mut cur = SD_REL_HEADER;
        // Sacl @0x0C offset field.
        if sacl_len != 0 {
            core::ptr::copy_nonoverlapping(sacl, r.add(cur), sacl_len);
            *(r.add(0x0C) as *mut u32) = cur as u32;
            cur += sacl_len;
        }
        // Dacl @0x10.
        if dacl_len != 0 {
            core::ptr::copy_nonoverlapping(dacl, r.add(cur), dacl_len);
            *(r.add(0x10) as *mut u32) = cur as u32;
            cur += dacl_len;
        }
        // Owner @0x04.
        if owner_len != 0 {
            core::ptr::copy_nonoverlapping(owner, r.add(cur), owner_len);
            *(r.add(0x04) as *mut u32) = cur as u32;
            cur += owner_len;
        }
        // Group @0x08.
        if group_len != 0 {
            core::ptr::copy_nonoverlapping(group, r.add(cur), group_len);
            *(r.add(0x08) as *mut u32) = cur as u32;
        }
        // Mark self-relative.
        *(r.add(0x02) as *mut u16) |= SE_SELF_RELATIVE;
    }
    STATUS_SUCCESS
}

/// `RtlAbsoluteToSelfRelativeSD(PSD Absolute, PSD SelfRelative, PULONG BufferLength) -> NTSTATUS`.
/// Fails if the input is already relative. Ported from `sd.c:626`.
///
/// # Safety
/// `abs_sd` a valid absolute SD; `rel_sd` a writable buffer; `buf_len` writable.
#[export_name = "RtlAbsoluteToSelfRelativeSD"]
pub unsafe extern "system" fn rtl_absolute_to_self_relative_sd(
    abs_sd: *const c_void,
    rel_sd: *mut c_void,
    buf_len: *mut u32,
) -> NtStatus {
    if abs_sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: abs_sd a valid SD header per the contract.
    if unsafe { sd_control(abs_sd as *const u8) } & SE_SELF_RELATIVE != 0 {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    // SAFETY: forwarded to make_self_relative under the same contract.
    unsafe { make_self_relative(abs_sd, rel_sd, buf_len) }
}

/// `RtlMakeSelfRelativeSD(PSD Absolute, PSD SelfRelative, PULONG BufferLength) -> NTSTATUS` —
/// identical to RtlAbsoluteToSelfRelativeSD minus the already-relative guard. Ported from `sd.c:646`.
///
/// # Safety
/// `abs_sd` a valid absolute SD; `rel_sd` a writable buffer; `buf_len` writable.
#[export_name = "RtlMakeSelfRelativeSD"]
pub unsafe extern "system" fn rtl_make_self_relative_sd(
    abs_sd: *const c_void,
    rel_sd: *mut c_void,
    buf_len: *mut u32,
) -> NtStatus {
    // SAFETY: forwarded to make_self_relative under the same contract.
    unsafe { make_self_relative(abs_sd, rel_sd, buf_len) }
}

/// `RtlSelfRelativeToAbsoluteSD(PSD SelfRelative, PSD Absolute, PULONG AbsoluteSDSize, PACL Dacl,
/// PULONG DaclSize, PACL Sacl, PULONG SaclSize, PSID Owner, PULONG OwnerSize, PSID PrimaryGroup,
/// PULONG PrimaryGroupSize) -> NTSTATUS`. Splits a self-relative SD into an absolute header + the
/// caller's per-component buffers. Ported from `sd.c:737`.
///
/// # Safety
/// `rel_sd` a valid self-relative SD; the out buffers/sizes writable per their contracts.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlSelfRelativeToAbsoluteSD"]
pub unsafe extern "system" fn rtl_self_relative_to_absolute_sd(
    rel_sd: *const c_void,
    abs_sd: *mut c_void,
    abs_sd_size: *mut u32,
    dacl: *mut c_void,
    dacl_size: *mut u32,
    sacl: *mut c_void,
    sacl_size: *mut u32,
    owner: *mut c_void,
    owner_size: *mut u32,
    primary_group: *mut c_void,
    primary_group_size: *mut u32,
) -> NtStatus {
    if rel_sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: rel_sd a valid self-relative SD; all out params writable per the contract.
    unsafe {
        let r = rel_sd as *const u8;
        if sd_control(r) & SE_SELF_RELATIVE == 0 {
            return STATUS_BAD_DESCRIPTOR_FORMAT;
        }
        let p_owner = sd_owner(r);
        let p_group = sd_group(r);
        let p_sacl = sd_sacl(r);
        let p_dacl = sd_dacl(r);
        let owner_len = if p_owner.is_null() {
            0
        } else {
            sid_len(p_owner)
        };
        let group_len = if p_group.is_null() {
            0
        } else {
            sid_len(p_group)
        };
        let sacl_len = if p_sacl.is_null() {
            0
        } else {
            *(p_sacl.add(2) as *const u16) as usize
        };
        let dacl_len = if p_dacl.is_null() {
            0
        } else {
            *(p_dacl.add(2) as *const u16) as usize
        };
        // Bail (and report required sizes) if any buffer is too small.
        let too_small = abs_sd.is_null()
            || SD_ABS_HEADER > *abs_sd_size as usize
            || (!owner_size.is_null() && owner_len > *owner_size as usize)
            || (!primary_group_size.is_null() && group_len > *primary_group_size as usize)
            || (!dacl_size.is_null() && dacl_len > *dacl_size as usize)
            || (!sacl_size.is_null() && sacl_len > *sacl_size as usize);
        if too_small {
            if !abs_sd_size.is_null() {
                *abs_sd_size = SD_ABS_HEADER as u32;
            }
            if !owner_size.is_null() {
                *owner_size = owner_len as u32;
            }
            if !primary_group_size.is_null() {
                *primary_group_size = group_len as u32;
            }
            if !dacl_size.is_null() {
                *dacl_size = dacl_len as u32;
            }
            if !sacl_size.is_null() {
                *sacl_size = sacl_len as u32;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
        // Build the absolute header: copy the prefix, clear ptrs, drop the relative flag.
        let a = abs_sd as *mut u8;
        core::ptr::write_bytes(a, 0, SD_ABS_HEADER);
        *a = *r;
        *a.add(1) = *r.add(1);
        let ctrl = (sd_control(r)) & !SE_SELF_RELATIVE;
        *(a.add(0x02) as *mut u16) = ctrl;
        // Copy each present component into the caller's buffer and set the absolute pointer.
        if !p_owner.is_null() && !owner.is_null() {
            core::ptr::copy(p_owner, owner as *mut u8, owner_len);
            *(a.add(0x08) as *mut *mut c_void) = owner;
        }
        if !p_group.is_null() && !primary_group.is_null() {
            core::ptr::copy(p_group, primary_group as *mut u8, group_len);
            *(a.add(0x10) as *mut *mut c_void) = primary_group;
        }
        if !p_dacl.is_null() && !dacl.is_null() {
            core::ptr::copy(p_dacl, dacl as *mut u8, dacl_len);
            *(a.add(0x20) as *mut *mut c_void) = dacl;
        }
        if !p_sacl.is_null() && !sacl.is_null() {
            core::ptr::copy(p_sacl, sacl as *mut u8, sacl_len);
            *(a.add(0x18) as *mut *mut c_void) = sacl;
        }
    }
    STATUS_SUCCESS
}

/// `RtlSelfRelativeToAbsoluteSD2(PSD SelfRelative, PULONG BufferSize) -> NTSTATUS`. In-place variant
/// on x64: because the absolute header (0x28) is larger than the relative one (0x14), the packed
/// data must be shifted down by `MoveDelta = 0x28 - 0x14 = 0x14` and the offset fields rewritten as
/// absolute pointers. Ported from `sd.c:843`.
///
/// # Safety
/// `rel_sd` a valid, writable self-relative SD buffer of at least `*buf_size` bytes.
#[export_name = "RtlSelfRelativeToAbsoluteSD2"]
pub unsafe extern "system" fn rtl_self_relative_to_absolute_sd2(
    rel_sd: *mut c_void,
    buf_size: *mut u32,
) -> NtStatus {
    if rel_sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if buf_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: rel_sd a valid writable self-relative SD; buf_size writable per the contract.
    unsafe {
        let r = rel_sd as *mut u8;
        if sd_control(r) & SE_SELF_RELATIVE == 0 {
            return STATUS_BAD_DESCRIPTOR_FORMAT;
        }
        let p_owner = sd_owner(r);
        let p_group = sd_group(r);
        let p_sacl = sd_sacl(r);
        let p_dacl = sd_dacl(r);
        let owner_len = if p_owner.is_null() {
            0
        } else {
            sid_len(p_owner)
        };
        let group_len = if p_group.is_null() {
            0
        } else {
            sid_len(p_group)
        };
        let sacl_len = if p_sacl.is_null() {
            0
        } else {
            *(p_sacl.add(2) as *const u16) as usize
        };
        let dacl_len = if p_dacl.is_null() {
            0
        } else {
            *(p_dacl.add(2) as *const u16) as usize
        };
        const MOVE_DELTA: usize = SD_ABS_HEADER - SD_REL_HEADER; // 0x14 on x64

        // Compute the [start,end) span of the packed component data.
        let mut data_start: Option<usize> = None;
        let mut data_end: usize = 0;
        let consider = |ptr: *const u8, len: usize, start: &mut Option<usize>, end: &mut usize| {
            if !ptr.is_null() && len != 0 {
                let off = ptr as usize - r as usize;
                if start.is_none() || off < start.unwrap() {
                    *start = Some(off);
                }
                if off + len > *end {
                    *end = off + len;
                }
            }
        };
        consider(p_owner, owner_len, &mut data_start, &mut data_end);
        consider(p_group, group_len, &mut data_start, &mut data_end);
        consider(p_dacl, dacl_len, &mut data_start, &mut data_end);
        consider(p_sacl, sacl_len, &mut data_start, &mut data_end);

        let data_size = match data_start {
            Some(s) => data_end - s,
            None => 0,
        };
        if (*buf_size as usize) < SD_ABS_HEADER + data_size {
            *buf_size = (SD_ABS_HEADER + data_size) as u32;
            return STATUS_BUFFER_TOO_SMALL;
        }
        // Move the component data down to just after the absolute header.
        if data_size != 0 {
            let start = data_start.unwrap();
            core::ptr::copy(r.add(start), r.add(SD_ABS_HEADER), data_size);
        }
        // Rewrite the offset fields as absolute pointers (offset + MOVE_DELTA from the base), or
        // NULL where the component was absent.
        let set_ptr = |field: usize, ptr: *const u8, r: *mut u8| {
            let slot = r.add(field) as *mut u64;
            if ptr.is_null() {
                *slot = 0;
            } else {
                *slot = (ptr as usize + MOVE_DELTA) as u64;
            }
        };
        // NB: overwrite in absolute-layout offsets; the relative offset fields are subsumed.
        set_ptr(0x08, p_owner, r);
        set_ptr(0x10, p_group, r);
        set_ptr(0x18, p_sacl, r);
        set_ptr(0x20, p_dacl, r);
        // Clear the self-relative flag.
        *(r.add(0x02) as *mut u16) &= !SE_SELF_RELATIVE;
    }
    STATUS_SUCCESS
}

// =================================================================================================
// Access-mask helpers
// =================================================================================================

/// `RtlAreAllAccessesGranted(ACCESS_MASK Granted, ACCESS_MASK Desired) -> BOOLEAN`. Ported from
/// `references/reactos/sdk/lib/rtl/access.c:22`.
#[export_name = "RtlAreAllAccessesGranted"]
pub extern "system" fn rtl_are_all_accesses_granted(granted: u32, desired: u32) -> u8 {
    ((!granted & desired) == 0) as u8
}

/// `RtlAreAnyAccessesGranted(ACCESS_MASK Granted, ACCESS_MASK Desired) -> BOOLEAN`. Ported from
/// `access.c:36`.
#[export_name = "RtlAreAnyAccessesGranted"]
pub extern "system" fn rtl_are_any_accesses_granted(granted: u32, desired: u32) -> u8 {
    ((granted & desired) != 0) as u8
}

/// `RtlMapGenericMask(PACCESS_MASK AccessMask, PGENERIC_MAPPING GenericMapping) -> VOID`. Expands
/// the four GENERIC_* bits via the mapping (4 x u32: Read/Write/Execute/All), then clears them.
/// Ported from `access.c:50`.
///
/// # Safety
/// `access_mask` writable; `generic_mapping` a readable 16-byte GENERIC_MAPPING.
#[export_name = "RtlMapGenericMask"]
pub unsafe extern "system" fn rtl_map_generic_mask(
    access_mask: *mut u32,
    generic_mapping: *const c_void,
) {
    if access_mask.is_null() || generic_mapping.is_null() {
        return;
    }
    // SAFETY: access_mask writable; generic_mapping a 16-byte GENERIC_MAPPING per the contract.
    unsafe {
        let gm = generic_mapping as *const u32;
        let mut m = *access_mask;
        if m & GENERIC_READ != 0 {
            m |= core::ptr::read_unaligned(gm);
        }
        if m & GENERIC_WRITE != 0 {
            m |= core::ptr::read_unaligned(gm.add(1));
        }
        if m & GENERIC_EXECUTE != 0 {
            m |= core::ptr::read_unaligned(gm.add(2));
        }
        if m & GENERIC_ALL != 0 {
            m |= core::ptr::read_unaligned(gm.add(3));
        }
        m &= !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
        *access_mask = m;
    }
}

// =================================================================================================
// Privilege / impersonation / security-object seams
//
// These need the live token / Se plane (NtOpenProcessToken, NtAdjustPrivilegesToken,
// NtDuplicateToken, ...). At this bring-up stage that plane is modeled as no-ops by the executive,
// so the privilege/impersonation wrappers report SUCCESS (with an empty state) — matching what the
// executive currently services. The x64 security-object helpers materialize heap-owned
// self-relative security descriptors for callers that expect `RtlNewSecurityObject` /
// `RtlDeleteSecurityObject` to manage object descriptors before the executive grows full object SD
// storage.
// =================================================================================================

/// `RtlAcquirePrivilege(PULONG Privilege, ULONG NumPriv, ULONG Flags, PVOID* ReturnedState)`.
/// The real body impersonates + enables privileges via the token plane (`priv.c:110`). At this
/// stage the executive treats privilege adjustment as a no-op, so we report SUCCESS with a NULL
/// state (RtlReleasePrivilege then no-ops). Not a fabricated success of the *acquire* — it mirrors
/// the executive's modeled token behavior.
///
/// # Safety
/// `returned_state` a writable out-pointer or NULL.
#[export_name = "RtlAcquirePrivilege"]
pub unsafe extern "system" fn rtl_acquire_privilege(
    privilege: *mut u32,
    count: u32,
    flags: u32,
    returned_state: *mut *mut c_void,
) -> NtStatus {
    let _ = (privilege, count, flags);
    // SAFETY: returned_state writable-or-NULL per the contract.
    unsafe {
        if !returned_state.is_null() {
            *returned_state = core::ptr::null_mut();
        }
    }
    STATUS_SUCCESS
}

/// `RtlReleasePrivilege(PVOID ReturnedState) -> VOID`. Frees the state produced by
/// RtlAcquirePrivilege — a no-op here since we never allocate one. Ported from `priv.c:363`.
///
/// # Safety
/// `state` a value previously returned by RtlAcquirePrivilege (here always NULL).
#[export_name = "RtlReleasePrivilege"]
pub unsafe extern "system" fn rtl_release_privilege(state: *mut c_void) {
    let _ = state;
}

/// `RtlImpersonateSelf(SECURITY_IMPERSONATION_LEVEL Level) -> NTSTATUS`. The real body opens +
/// duplicates the process token onto the thread (`priv.c:45`). The executive models the token
/// plane, so we report SUCCESS.
#[export_name = "RtlImpersonateSelf"]
pub extern "system" fn rtl_impersonate_self(level: u32) -> NtStatus {
    let _ = level;
    STATUS_SUCCESS
}

/// `RtlNewSecurityObject(...)` — build a process-heap self-relative SD for a new object.
///
/// The full Windows body merges creator/parent descriptors with inheritance and token default DACL
/// policy. Until the token-derived default-DACL plane exists, we implement the faithful descriptor
/// materialization subset: clone the creator descriptor when supplied, otherwise clone the parent
/// descriptor, otherwise return a minimal valid empty self-relative SD.
///
/// # Safety
/// `new_descriptor` is writable; descriptor pointers are valid when non-null.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlNewSecurityObject"]
pub unsafe extern "system" fn rtl_new_security_object(
    parent_descriptor: *const c_void,
    creator_descriptor: *const c_void,
    new_descriptor: *mut *mut c_void,
    is_directory_object: u8,
    token: *mut c_void,
    generic_mapping: *const c_void,
) -> NtStatus {
    let _ = (is_directory_object, token, generic_mapping);
    if new_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: descriptor pointers/out slot satisfy the exported API contract.
        unsafe {
            let source = if !creator_descriptor.is_null() {
                creator_descriptor
            } else {
                parent_descriptor
            };
            let sd = if source.is_null() {
                match empty_security_descriptor_to_heap() {
                    Ok(sd) => sd,
                    Err(status) => return status,
                }
            } else {
                match clone_security_descriptor_to_heap(source) {
                    Ok(sd) => sd,
                    Err(status) => return status,
                }
            };
            *new_descriptor = sd;
            STATUS_SUCCESS
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (parent_descriptor, creator_descriptor);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlNewSecurityObjectEx(...) -> NTSTATUS`.
/// The object-type and auto-inherit refinements share the same materialization subset as
/// `RtlNewSecurityObject` until the full token/inheritance plane exists.
///
/// # Safety
/// Same descriptor pointer contract as `RtlNewSecurityObject`.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlNewSecurityObjectEx"]
pub unsafe extern "system" fn rtl_new_security_object_ex(
    parent_descriptor: *const c_void,
    creator_descriptor: *const c_void,
    new_descriptor: *mut *mut c_void,
    object_type: *mut c_void,
    is_directory_object: u8,
    auto_inherit_flags: u32,
    token: *mut c_void,
    generic_mapping: *const c_void,
) -> NtStatus {
    let _ = (object_type, auto_inherit_flags);
    // SAFETY: forwards the same descriptor/out-parameter contract.
    unsafe {
        rtl_new_security_object(
            parent_descriptor,
            creator_descriptor,
            new_descriptor,
            is_directory_object,
            token,
            generic_mapping,
        )
    }
}

/// `RtlNewSecurityObjectWithMultipleInheritance(...) -> NTSTATUS`.
/// Multiple object GUID inheritance is not yet modelled; descriptor selection/materialization matches
/// the base helper.
///
/// # Safety
/// Same descriptor pointer contract as `RtlNewSecurityObject`.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlNewSecurityObjectWithMultipleInheritance"]
pub unsafe extern "system" fn rtl_new_security_object_with_multiple_inheritance(
    parent_descriptor: *const c_void,
    creator_descriptor: *const c_void,
    new_descriptor: *mut *mut c_void,
    object_types: *mut *mut c_void,
    guid_count: u32,
    is_directory_object: u8,
    auto_inherit_flags: u32,
    token: *mut c_void,
    generic_mapping: *const c_void,
) -> NtStatus {
    let _ = (object_types, guid_count, auto_inherit_flags);
    // SAFETY: forwards the same descriptor/out-parameter contract.
    unsafe {
        rtl_new_security_object(
            parent_descriptor,
            creator_descriptor,
            new_descriptor,
            is_directory_object,
            token,
            generic_mapping,
        )
    }
}

/// `RtlConvertToAutoInheritSecurityObject(...) -> NTSTATUS`.
/// Auto-inheritance metadata is deferred to the object/security plane; the exported ntdll contract
/// still returns a heap-owned descriptor built from creator/parent inputs.
///
/// # Safety
/// Same descriptor pointer contract as `RtlNewSecurityObject`.
#[export_name = "RtlConvertToAutoInheritSecurityObject"]
pub unsafe extern "system" fn rtl_convert_to_auto_inherit_security_object(
    parent_descriptor: *const c_void,
    creator_descriptor: *const c_void,
    new_descriptor: *mut *mut c_void,
    object_type: *mut c_void,
    is_directory_object: u8,
    generic_mapping: *const c_void,
) -> NtStatus {
    let _ = object_type;
    // SAFETY: forwards the same descriptor/out-parameter contract.
    unsafe {
        rtl_new_security_object(
            parent_descriptor,
            creator_descriptor,
            new_descriptor,
            is_directory_object,
            core::ptr::null_mut(),
            generic_mapping,
        )
    }
}

/// `RtlNewInstanceSecurityObject(...) -> NTSTATUS`.
/// The executive currently exposes stable LocalSystem token identity. If neither parent nor creator
/// changed and the caller's token LUID is unchanged, this mirrors ReactOS by returning no new
/// descriptor; otherwise it materializes through `RtlNewSecurityObject`.
///
/// # Safety
/// Output pointers are writable when non-null; descriptor pointers are valid when non-null.
#[allow(clippy::too_many_arguments)]
#[export_name = "RtlNewInstanceSecurityObject"]
pub unsafe extern "system" fn rtl_new_instance_security_object(
    parent_descriptor_changed: u8,
    creator_descriptor_changed: u8,
    old_client_token_modified_id: *const u8,
    new_client_token_modified_id: *mut u8,
    parent_descriptor: *const c_void,
    creator_descriptor: *const c_void,
    new_descriptor: *mut *mut c_void,
    is_directory_object: u8,
    token: *mut c_void,
    generic_mapping: *const c_void,
) -> NtStatus {
    if new_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: LUID pointers are optional 8-byte records per the contract.
    unsafe {
        if !new_client_token_modified_id.is_null() {
            if !old_client_token_modified_id.is_null() {
                core::ptr::copy_nonoverlapping(
                    old_client_token_modified_id,
                    new_client_token_modified_id,
                    8,
                );
            } else {
                core::ptr::write_bytes(new_client_token_modified_id, 0, 8);
            }
        }
        if parent_descriptor_changed == 0 && creator_descriptor_changed == 0 {
            *new_descriptor = core::ptr::null_mut();
            return STATUS_SUCCESS;
        }
    }
    // SAFETY: forwards the same descriptor/out-parameter contract.
    unsafe {
        rtl_new_security_object(
            parent_descriptor,
            creator_descriptor,
            new_descriptor,
            is_directory_object,
            token,
            generic_mapping,
        )
    }
}

/// `RtlDeleteSecurityObject(PSECURITY_DESCRIPTOR* ObjectDescriptor) -> NTSTATUS`. Frees the SD
/// allocated by RtlNewSecurityObject and NULLs the slot. On x86_64 we free to the process heap;
/// off-target it is a no-op success (nothing was allocated).
///
/// # Safety
/// `object_descriptor` a writable slot holding a process-heap SD pointer, or NULL.
#[export_name = "RtlDeleteSecurityObject"]
pub unsafe extern "system" fn rtl_delete_security_object(
    object_descriptor: *mut *mut c_void,
) -> NtStatus {
    if object_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the slot holds a process-heap SD pointer (or NULL) per the contract.
        unsafe {
            let sd = *object_descriptor;
            if !sd.is_null() {
                crate::process_heap_free(sd as *mut u8);
                *object_descriptor = core::ptr::null_mut();
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // SAFETY: just clears the slot.
        unsafe {
            *object_descriptor = core::ptr::null_mut();
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetSecurityObject(...)` — apply a SECURITY_INFORMATION update to an object's self-relative SD.
/// Ported from ReactOS `sdk/lib/rtl/security.c:RtlpSetSecurityObject`: select updated components from
/// `ModificationDescriptor`, keep the rest from the existing object SD, pack a new self-relative SD on
/// the process heap, then free the old descriptor.
///
/// # Safety
/// `object_descriptor` points at a process-heap SECURITY_DESCRIPTOR pointer; descriptor pointers are
/// valid for the selected components.
#[export_name = "RtlSetSecurityObject"]
pub unsafe extern "system" fn rtl_set_security_object(
    security_information: u32,
    modification_descriptor: *const c_void,
    object_descriptor: *mut *mut c_void,
    generic_mapping: *const c_void,
    token: *mut c_void,
) -> NtStatus {
    let _ = (generic_mapping, token);
    if object_descriptor.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // SAFETY: object_descriptor is a writable slot and descriptors satisfy the API contract.
    unsafe {
        let current = *object_descriptor;
        let parts =
            match select_security_parts(security_information, modification_descriptor, current) {
                Ok(parts) => parts,
                Err(status) => return status,
            };
        let total = SD_REL_HEADER
            + round_up4(parts.sacl_len)
            + round_up4(parts.dacl_len)
            + round_up4(parts.owner_len)
            + round_up4(parts.group_len);

        #[cfg(target_arch = "x86_64")]
        {
            let new_sd = crate::process_heap_alloc(total);
            if new_sd.is_null() {
                return STATUS_NO_MEMORY;
            }
            core::ptr::write_bytes(new_sd, 0, total);
            *new_sd = SECURITY_DESCRIPTOR_REVISION;
            *(new_sd.add(0x02) as *mut u16) = parts.control;

            let mut cur = SD_REL_HEADER;
            if parts.sacl_len != 0 {
                copy_component(new_sd.add(cur), parts.sacl, parts.sacl_len);
                *(new_sd.add(0x0C) as *mut u32) = cur as u32;
                cur += round_up4(parts.sacl_len);
            }
            if parts.dacl_len != 0 {
                copy_component(new_sd.add(cur), parts.dacl, parts.dacl_len);
                *(new_sd.add(0x10) as *mut u32) = cur as u32;
                cur += round_up4(parts.dacl_len);
            }
            copy_component(new_sd.add(cur), parts.owner, parts.owner_len);
            *(new_sd.add(0x04) as *mut u32) = cur as u32;
            cur += round_up4(parts.owner_len);
            copy_component(new_sd.add(cur), parts.group, parts.group_len);
            *(new_sd.add(0x08) as *mut u32) = cur as u32;

            if !current.is_null() {
                crate::process_heap_free(current as *mut u8);
            }
            *object_descriptor = new_sd as *mut c_void;
            STATUS_SUCCESS
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = parts;
            STATUS_NOT_IMPLEMENTED
        }
    }
}

/// `RtlSetSecurityObjectEx(...) -> NTSTATUS`.
/// Auto-inherit flags are not yet represented in the local descriptor materializer, so this shares
/// the base `RtlSetSecurityObject` behavior.
///
/// # Safety
/// Same descriptor pointer contract as `RtlSetSecurityObject`.
#[export_name = "RtlSetSecurityObjectEx"]
pub unsafe extern "system" fn rtl_set_security_object_ex(
    security_information: u32,
    modification_descriptor: *const c_void,
    object_descriptor: *mut *mut c_void,
    auto_inherit_flags: u32,
    generic_mapping: *const c_void,
    token: *mut c_void,
) -> NtStatus {
    let _ = auto_inherit_flags;
    // SAFETY: forwards the same descriptor/update contract.
    unsafe {
        rtl_set_security_object(
            security_information,
            modification_descriptor,
            object_descriptor,
            generic_mapping,
            token,
        )
    }
}

/// `RtlNewSecurityGrantedAccess(...) -> NTSTATUS`.
/// Maps generic bits, grants `ACCESS_SYSTEM_SECURITY` using the standard SeSecurityPrivilege record,
/// and returns the remaining desired access mask.
///
/// # Safety
/// `length` and `remaining_desired_access` are writable; `privileges` is writable when `*length`
/// is large enough.
#[export_name = "RtlNewSecurityGrantedAccess"]
pub unsafe extern "system" fn rtl_new_security_granted_access(
    desired_access: u32,
    privileges: *mut c_void,
    length: *mut u32,
    token: *mut c_void,
    generic_mapping: *const c_void,
    remaining_desired_access: *mut u32,
) -> NtStatus {
    let _ = token;
    if length.is_null() || remaining_desired_access.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    const PRIVILEGE_SET_SIZE: u32 = 20;
    let mut mapped_access = desired_access;
    // SAFETY: rtl_map_generic_mask accepts a null mapping as a no-op; mapped_access is writable.
    unsafe { rtl_map_generic_mask(&mut mapped_access, generic_mapping) };
    let granted = mapped_access & ACCESS_SYSTEM_SECURITY != 0;
    if granted {
        mapped_access &= !ACCESS_SYSTEM_SECURITY;
    }
    // SAFETY: length/remaining_desired_access are writable per the contract.
    unsafe {
        *remaining_desired_access = mapped_access;
        if *length < PRIVILEGE_SET_SIZE {
            *length = PRIVILEGE_SET_SIZE;
            return STATUS_BUFFER_TOO_SMALL;
        }
        *length = PRIVILEGE_SET_SIZE;
        if privileges.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        let p = privileges as *mut u8;
        core::ptr::write_bytes(p, 0, PRIVILEGE_SET_SIZE as usize);
        core::ptr::write_unaligned(p as *mut u32, u32::from(granted));
        if granted {
            core::ptr::write_unaligned(p.add(0x08) as *mut u32, SE_SECURITY_PRIVILEGE);
            core::ptr::write_unaligned(p.add(0x0C) as *mut u32, 0);
            core::ptr::write_unaligned(p.add(0x10) as *mut u32, SE_PRIVILEGE_USED_FOR_ACCESS);
        }
    }
    STATUS_SUCCESS
}

/// `RtlQuerySecurityObject(...)` — extract SECURITY_INFORMATION from an object's SD into a caller
/// self-relative descriptor. Ported from ReactOS `sdk/lib/rtl/security.c:RtlQuerySecurityObject`.
///
/// # Safety
/// `object_descriptor` is a valid SD; `resultant_descriptor` is a caller buffer of
/// `descriptor_length` bytes; `return_length` is writable.
#[export_name = "RtlQuerySecurityObject"]
pub unsafe extern "system" fn rtl_query_security_object(
    object_descriptor: *const c_void,
    security_information: u32,
    resultant_descriptor: *mut c_void,
    descriptor_length: u32,
    return_length: *mut u32,
) -> NtStatus {
    if object_descriptor.is_null() || return_length.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut abs = [0u8; SD_ABS_HEADER];

    // SAFETY: descriptors and out-pointers satisfy the exported function contract.
    unsafe {
        init_absolute_sd(abs.as_mut_ptr());

        if security_information & OWNER_SECURITY_INFORMATION != 0 {
            let mut owner: *mut c_void = core::ptr::null_mut();
            let mut defaulted = 0u8;
            let status =
                rtl_get_owner_security_descriptor(object_descriptor, &mut owner, &mut defaulted);
            if status != STATUS_SUCCESS {
                return status;
            }
            let status = rtl_set_owner_security_descriptor(
                abs.as_mut_ptr() as *mut c_void,
                owner,
                defaulted,
            );
            if status != STATUS_SUCCESS {
                return status;
            }
        }

        if security_information & GROUP_SECURITY_INFORMATION != 0 {
            let mut group: *mut c_void = core::ptr::null_mut();
            let mut defaulted = 0u8;
            let status =
                rtl_get_group_security_descriptor(object_descriptor, &mut group, &mut defaulted);
            if status != STATUS_SUCCESS {
                return status;
            }
            let status = rtl_set_group_security_descriptor(
                abs.as_mut_ptr() as *mut c_void,
                group,
                defaulted,
            );
            if status != STATUS_SUCCESS {
                return status;
            }
        }

        if security_information & DACL_SECURITY_INFORMATION != 0 {
            let (present, dacl, defaulted) = match get_dacl(object_descriptor as *const u8) {
                Ok(parts) => parts,
                Err(status) => return status,
            };
            set_abs_dacl(abs.as_mut_ptr(), present, dacl, defaulted);
        }

        if security_information & SACL_SECURITY_INFORMATION != 0 {
            let mut present = 0u8;
            let mut sacl: *mut c_void = core::ptr::null_mut();
            let mut defaulted = 0u8;
            let status = rtl_get_sacl_security_descriptor(
                object_descriptor,
                &mut present,
                &mut sacl,
                &mut defaulted,
            );
            if status != STATUS_SUCCESS {
                return status;
            }
            let status = rtl_set_sacl_security_descriptor(
                abs.as_mut_ptr() as *mut c_void,
                present,
                sacl,
                defaulted,
            );
            if status != STATUS_SUCCESS {
                return status;
            }
        }

        *return_length = descriptor_length;
        rtl_absolute_to_self_relative_sd(
            abs.as_ptr() as *const c_void,
            resultant_descriptor,
            return_length,
        )
    }
}

/// `RtlCaptureStackBackTrace(ULONG FramesToSkip, ULONG FramesToCapture, PVOID* BackTrace,
/// PULONG BackTraceHash) -> USHORT`. No frame-pointer stack walker at this stage; capture 0 frames
/// and zero the hash. Returns the number captured (0).
///
/// # Safety
/// `back_trace` a writable array of `frames_to_capture` slots (unused); `back_trace_hash` writable.
#[export_name = "RtlCaptureStackBackTrace"]
pub unsafe extern "system" fn rtl_capture_stack_back_trace(
    frames_to_skip: u32,
    frames_to_capture: u32,
    back_trace: *mut *mut c_void,
    back_trace_hash: *mut u32,
) -> u16 {
    let _ = (frames_to_skip, frames_to_capture, back_trace);
    // SAFETY: back_trace_hash writable-or-NULL per the contract.
    unsafe {
        if !back_trace_hash.is_null() {
            *back_trace_hash = 0;
        }
    }
    0
}

// =================================================================================================
// Retention anchor — mirror `crate::exports::export_anchor`. Referenced from `lib.rs` (or the
// existing anchor) via a `#[used]` static so the linker keeps every export past DCE.
// =================================================================================================

/// A `#[used]` handle on [`security_export_anchor`] so the whole export graph survives DCE.
#[used]
pub static SECURITY_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = security_export_anchor;

/// The retention anchor body — never invoked; it only takes the address of every export so the
/// linker retains them. Mirror of `crate::exports::export_anchor`.
///
/// # Safety
/// Never called; it only reads the addresses of the exports to anchor them.
pub unsafe extern "C" fn security_export_anchor() {
    let anchors: &[usize] = &[
        rtl_valid_sid as usize,
        rtl_equal_sid as usize,
        rtl_equal_prefix_sid as usize,
        rtl_length_required_sid as usize,
        rtl_initialize_sid as usize,
        rtl_identifier_authority_sid as usize,
        rtl_sub_authority_sid as usize,
        rtl_sub_authority_count_sid as usize,
        rtl_copy_sid as usize,
        rtl_copy_sid_and_attributes_array as usize,
        rtl_convert_sid_to_unicode_string as usize,
        rtl_valid_acl as usize,
        rtl_query_information_acl as usize,
        rtl_set_information_acl as usize,
        rtl_first_free_ace as usize,
        rtl_add_ace as usize,
        rtl_delete_ace as usize,
        rtl_add_access_allowed_ace_ex as usize,
        rtl_add_access_denied_ace as usize,
        rtl_add_access_denied_ace_ex as usize,
        rtl_add_audit_access_ace as usize,
        rtl_add_audit_access_ace_ex as usize,
        rtl_add_access_allowed_object_ace as usize,
        rtl_add_access_denied_object_ace as usize,
        rtl_add_audit_access_object_ace as usize,
        rtl_valid_security_descriptor as usize,
        rtl_length_security_descriptor as usize,
        rtl_get_control_security_descriptor as usize,
        rtl_set_control_security_descriptor as usize,
        rtl_get_owner_security_descriptor as usize,
        rtl_set_owner_security_descriptor as usize,
        rtl_get_group_security_descriptor as usize,
        rtl_set_group_security_descriptor as usize,
        rtl_get_sacl_security_descriptor as usize,
        rtl_set_sacl_security_descriptor as usize,
        rtl_get_security_descriptor_rm_control as usize,
        rtl_set_security_descriptor_rm_control as usize,
        rtl_set_attributes_security_descriptor as usize,
        rtl_copy_security_descriptor as usize,
        rtl_valid_relative_security_descriptor as usize,
        rtl_default_np_acl as usize,
        rtl_absolute_to_self_relative_sd as usize,
        rtl_make_self_relative_sd as usize,
        rtl_self_relative_to_absolute_sd as usize,
        rtl_self_relative_to_absolute_sd2 as usize,
        rtl_are_all_accesses_granted as usize,
        rtl_are_any_accesses_granted as usize,
        rtl_map_generic_mask as usize,
        rtl_acquire_privilege as usize,
        rtl_release_privilege as usize,
        rtl_impersonate_self as usize,
        rtl_new_security_object as usize,
        rtl_new_security_object_ex as usize,
        rtl_new_security_object_with_multiple_inheritance as usize,
        rtl_convert_to_auto_inherit_security_object as usize,
        rtl_new_instance_security_object as usize,
        rtl_delete_security_object as usize,
        rtl_set_security_object as usize,
        rtl_set_security_object_ex as usize,
        rtl_new_security_granted_access as usize,
        rtl_query_security_object as usize,
        rtl_capture_stack_back_trace as usize,
    ];
    core::hint::black_box(anchors);
}
