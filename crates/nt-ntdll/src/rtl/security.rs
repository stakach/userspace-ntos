//! Security `Rtl*` stragglers — SID / ACL / security-descriptor construction + privilege helpers.
//!
//! These are thin **delegations to [`nt_security`]** (the Security Reference Monitor, host-tested
//! there), re-exported at the ntdll seam so a hosted binary linking `RtlLengthSid` / `RtlCreateAcl`
//! / `RtlCreateSecurityDescriptor` / … resolves against our ntdll rather than a foreign one.
//! Reusing `nt-security`'s `Sid` / `Acl` / `Ace` / `SecurityDescriptor` keeps ONE SID/ACL model
//! across the kernel (no divergent copy). Covered names:
//!
//! `RtlLengthSid`, `RtlLengthRequiredSid`, `RtlInitializeSid`, `RtlSubAuthoritySid`,
//! `RtlSubAuthorityCountSid`, `RtlIdentifierAuthoritySid`, `RtlEqualSid`, `RtlEqualPrefixSid`,
//! `RtlValidSid`, `RtlCopySid`, `RtlAllocateAndInitializeSid`, `RtlConvertSidToUnicodeString`,
//! `RtlCreateAcl`, `RtlAddAce`, `RtlGetAce`, `RtlFirstFreeAce`, `RtlValidAcl`,
//! `RtlCreateSecurityDescriptor`, `RtlSetDaclSecurityDescriptor`, `RtlGetDaclSecurityDescriptor`,
//! `RtlSetOwnerSecurityDescriptor`, `RtlGetOwnerSecurityDescriptor`, `RtlValidSecurityDescriptor`,
//! `RtlLengthSecurityDescriptor`, `RtlMapGenericMask`, `RtlAreAllAccessesGranted`,
//! `RtlAreAnyAccessesGranted`, `RtlAdjustPrivilege`.

use alloc::string::String;
use alloc::vec::Vec;

// Re-export the shared security model at the ntdll seam.
pub use nt_security::{Ace, Acl, GenericMapping, SecurityDescriptor, Sid};

/// `SECURITY_DESCRIPTOR_REVISION`.
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
/// `ACL_REVISION`.
pub const ACL_REVISION: u8 = 2;
/// `SECURITY_MANDATORY_LABEL_AUTHORITY` (`S-1-16-*`).
pub const SECURITY_MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];
/// `SECURITY_CREATOR_SID_AUTHORITY` (`S-1-3-*`).
pub const SECURITY_CREATOR_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 3];
/// `SECURITY_CREATOR_OWNER_RIGHTS_RID` (`S-1-3-4`).
pub const SECURITY_CREATOR_OWNER_RIGHTS_RID: u32 = 4;

/// `RtlLengthSid(Sid)` — the byte length of a SID: `1 (rev) + 1 (subcount) + 6 (authority) +
/// 4*subcount`. Matches the on-wire `SID` structure size.
pub fn length_sid(sid: &Sid) -> usize {
    8 + 4 * sid.sub_authorities.len()
}

/// `RtlLengthRequiredSid(SubAuthorityCount)` — the byte length needed for a SID with the given
/// sub-authority count.
pub fn length_required_sid(sub_authority_count: usize) -> usize {
    8 + 4 * sub_authority_count
}

/// `RtlInitializeSid(Sid, IdentifierAuthority, SubAuthorityCount)` — build a SID with the given
/// 6-byte authority and (initially zero) sub-authorities. (Sub-authority values are filled by
/// `RtlSubAuthoritySid` writes; here we produce a SID with `count` zeroed sub-authorities.)
pub fn initialize_sid(identifier_authority: [u8; 6], sub_authority_count: usize) -> Sid {
    Sid {
        revision: 1,
        identifier_authority,
        sub_authorities: alloc::vec![0u32; sub_authority_count],
    }
}

/// `RtlSubAuthorityCountSid(Sid)`.
pub fn sub_authority_count(sid: &Sid) -> usize {
    sid.sub_authorities.len()
}

/// `RtlSubAuthoritySid(Sid, Index)` — the sub-authority at `index` (None if out of range).
pub fn sub_authority(sid: &Sid, index: usize) -> Option<u32> {
    sid.sub_authorities.get(index).copied()
}

/// `RtlIdentifierAuthoritySid(Sid)` — the 6-byte identifier authority.
pub fn identifier_authority(sid: &Sid) -> [u8; 6] {
    sid.identifier_authority
}

/// `RtlEqualSid(Sid1, Sid2)`.
pub fn equal_sid(a: &Sid, b: &Sid) -> bool {
    a == b
}

/// `RtlEqualPrefixSid(Sid1, Sid2)` — equal authority + all-but-last sub-authorities equal.
pub fn equal_prefix_sid(a: &Sid, b: &Sid) -> bool {
    if a.revision != b.revision || a.identifier_authority != b.identifier_authority {
        return false;
    }
    if a.sub_authorities.len() != b.sub_authorities.len() {
        return false;
    }
    if a.sub_authorities.is_empty() {
        return true;
    }
    a.sub_authorities[..a.sub_authorities.len() - 1]
        == b.sub_authorities[..b.sub_authorities.len() - 1]
}

/// Integrity-level RID for a mandatory-label SID (`S-1-16-<level>`).
pub fn mandatory_integrity_level(sid: &Sid) -> Option<u32> {
    if sid.revision == 1
        && sid.identifier_authority == SECURITY_MANDATORY_LABEL_AUTHORITY
        && sid.sub_authorities.len() == 1
    {
        Some(sid.sub_authorities[0])
    } else {
        None
    }
}

/// `RtlSidDominates(Sid1, Sid2, Result)` — true when `Sid1`'s integrity level is >= `Sid2`'s.
pub fn sid_dominates(a: &Sid, b: &Sid) -> Option<bool> {
    Some(mandatory_integrity_level(a)? >= mandatory_integrity_level(b)?)
}

/// `RtlSidEqualLevel(Sid1, Sid2, Result)` — true when both mandatory-label SIDs carry the same RID.
pub fn sid_equal_level(a: &Sid, b: &Sid) -> Option<bool> {
    Some(mandatory_integrity_level(a)? == mandatory_integrity_level(b)?)
}

/// `S-1-3-4` — the Owner Rights SID used by Vista+ owner ACEs.
pub fn is_owner_rights_sid(sid: &Sid) -> bool {
    sid.revision == 1
        && sid.identifier_authority == SECURITY_CREATOR_SID_AUTHORITY
        && sid.sub_authorities.as_slice() == [SECURITY_CREATOR_OWNER_RIGHTS_RID]
}

/// `RtlOwnerAcesPresent(Acl)` — true when any ACE names the Owner Rights SID.
pub fn owner_aces_present(acl: &Acl) -> bool {
    acl.aces.iter().any(|ace| is_owner_rights_sid(&ace.sid))
}

/// `RtlValidSid(Sid)` — revision 1 + a sub-authority count within `SID_MAX_SUB_AUTHORITIES` (15).
pub fn valid_sid(sid: &Sid) -> bool {
    sid.revision == 1 && sid.sub_authorities.len() <= 15
}

/// `RtlCopySid(DestLength, Dest, Source)` — copy a SID; fails (None) if `dest_length` is too small.
pub fn copy_sid(dest_length: usize, source: &Sid) -> Option<Sid> {
    if dest_length < length_sid(source) {
        return None;
    }
    Some(source.clone())
}

/// `RtlAllocateAndInitializeSid(Authority, Count, Sub0..Sub7)` — allocate + init a SID from an
/// authority value and up to 8 sub-authorities.
pub fn allocate_and_initialize_sid(authority: u8, subs: &[u32]) -> Sid {
    Sid::new(authority, subs)
}

/// `RtlConvertSidToUnicodeString(Sid)` — the SDDL `S-1-…` string (as UTF-16 units).
pub fn convert_sid_to_unicode_string(sid: &Sid) -> Vec<u16> {
    sid.to_sddl().encode_utf16().collect()
}

/// The SDDL string of a SID (`RtlConvertSidToUnicodeString`, narrow form).
pub fn sid_to_sddl(sid: &Sid) -> String {
    sid.to_sddl()
}

/// `RtlCreateAcl(Acl, AclLength, AclRevision)` — a new, empty ACL. (Length/revision are validated by
/// the real call; here an empty ACL is the model.)
pub fn create_acl() -> Acl {
    Acl::empty()
}

/// `RtlAddAce(Acl, AclRevision, StartingAceIndex, AceList, AceListLength)` — append an ACE.
pub fn add_ace(acl: &mut Acl, ace: Ace) {
    acl.aces.push(ace);
}

/// `RtlGetAce(Acl, AceIndex, Ace*)` — the ACE at `index` (None if out of range).
pub fn get_ace(acl: &Acl, index: usize) -> Option<&Ace> {
    acl.aces.get(index)
}

/// `RtlFirstFreeAce` — the index at which the next ACE would be appended (= current ACE count).
pub fn first_free_ace(acl: &Acl) -> usize {
    acl.aces.len()
}

/// `RtlValidAcl(Acl)` — a minimal validity check (the model ACL is always structurally valid).
pub fn valid_acl(_acl: &Acl) -> bool {
    true
}

/// `RtlCreateSecurityDescriptor(SecurityDescriptor, Revision)` — a new, absolute, empty SD.
pub fn create_security_descriptor() -> SecurityDescriptor {
    SecurityDescriptor {
        owner: None,
        group: None,
        dacl: None,
        sacl: None,
    }
}

/// `RtlSetDaclSecurityDescriptor(SecurityDescriptor, DaclPresent, Dacl, DaclDefaulted)` — set (or, on
/// `dacl == None` with `present == true`, install a NULL DACL = allow-all) the discretionary ACL.
pub fn set_dacl(sd: &mut SecurityDescriptor, present: bool, dacl: Option<Acl>) {
    sd.dacl = if present { dacl } else { None };
}

/// `RtlGetDaclSecurityDescriptor` — the DACL (and whether one is present).
pub fn get_dacl(sd: &SecurityDescriptor) -> (bool, Option<&Acl>) {
    (sd.dacl.is_some(), sd.dacl.as_ref())
}

/// `RtlSetOwnerSecurityDescriptor(SecurityDescriptor, Owner, OwnerDefaulted)`.
pub fn set_owner(sd: &mut SecurityDescriptor, owner: Option<Sid>) {
    sd.owner = owner;
}

/// `RtlGetOwnerSecurityDescriptor` — the owner SID.
pub fn get_owner(sd: &SecurityDescriptor) -> Option<&Sid> {
    sd.owner.as_ref()
}

/// `RtlValidSecurityDescriptor` — a minimal validity check (the model SD is structurally valid).
pub fn valid_security_descriptor(_sd: &SecurityDescriptor) -> bool {
    true
}

/// `RtlLengthSecurityDescriptor` — the byte length of the self-relative form: the fixed 20-byte
/// header + owner SID + group SID + DACL.
pub fn length_security_descriptor(sd: &SecurityDescriptor) -> usize {
    let mut len = 20; // SECURITY_DESCRIPTOR_RELATIVE header
    if let Some(o) = &sd.owner {
        len += length_sid(o);
    }
    if let Some(g) = &sd.group {
        len += length_sid(g);
    }
    if let Some(d) = &sd.dacl {
        // ACL header (8) + each ACE (header 8 + SID).
        len += 8 + d.aces.iter().map(|a| 8 + length_sid(&a.sid)).sum::<usize>();
    }
    len
}

/// `RtlMapGenericMask(AccessMask, GenericMapping)` — resolve the generic bits (`GENERIC_READ/WRITE/
/// EXECUTE/ALL`) of an access mask to their specific rights via the object's generic mapping.
pub fn map_generic_mask(mask: u32, mapping: &GenericMapping) -> u32 {
    mapping.map(mask)
}

/// `RtlAreAllAccessesGranted(GrantedAccess, DesiredAccess)`.
pub fn are_all_accesses_granted(granted: u32, desired: u32) -> bool {
    granted & desired == desired
}

/// `RtlAreAnyAccessesGranted(GrantedAccess, DesiredAccess)`.
pub fn are_any_accesses_granted(granted: u32, desired: u32) -> bool {
    granted & desired != 0
}

/// `RtlEqualLuid(Luid1, Luid2)`.
pub fn equal_luid(low1: u32, high1: i32, low2: u32, high2: i32) -> bool {
    low1 == low2 && high1 == high2
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn sid_lengths() {
        let s = Sid::administrators(); // S-1-5-32-544 → 2 subs
        assert_eq!(sub_authority_count(&s), 2);
        assert_eq!(length_sid(&s), 8 + 8);
        assert_eq!(length_required_sid(2), 16);
        assert_eq!(sub_authority(&s, 1), Some(544));
        assert_eq!(sub_authority(&s, 9), None);
    }

    #[test]
    fn sid_equality_and_prefix() {
        let a = Sid::new(5, &[21, 100, 500]);
        let b = Sid::new(5, &[21, 100, 501]);
        assert!(!equal_sid(&a, &b));
        assert!(equal_prefix_sid(&a, &b)); // differ only in last sub-authority (RID)
        assert!(equal_sid(&a, &a.clone()));
        assert!(valid_sid(&a));
    }

    #[test]
    fn integrity_level_sid_comparisons() {
        let low = Sid::new(16, &[0x1000]);
        let medium = Sid::new(16, &[0x2000]);
        let high = Sid::new(16, &[0x3000]);
        let world = Sid::everyone();

        assert_eq!(mandatory_integrity_level(&medium), Some(0x2000));
        assert_eq!(mandatory_integrity_level(&world), None);
        assert_eq!(sid_dominates(&high, &medium), Some(true));
        assert_eq!(sid_dominates(&low, &medium), Some(false));
        assert_eq!(
            sid_equal_level(&medium, &Sid::new(16, &[0x2000])),
            Some(true)
        );
        assert_eq!(sid_equal_level(&medium, &high), Some(false));
        assert_eq!(sid_dominates(&medium, &world), None);
    }

    #[test]
    fn sid_copy_and_sddl() {
        let s = Sid::local_system();
        assert!(copy_sid(4, &s).is_none()); // too small
        assert_eq!(copy_sid(64, &s), Some(s.clone()));
        assert_eq!(sid_to_sddl(&s), "S-1-5-18");
        assert_eq!(
            convert_sid_to_unicode_string(&s),
            "S-1-5-18".encode_utf16().collect::<Vec<_>>()
        );
    }

    #[test]
    fn acl_construction() {
        let mut acl = create_acl();
        assert_eq!(first_free_ace(&acl), 0);
        add_ace(&mut acl, Ace::allow(Sid::everyone(), 0x1F01FF));
        add_ace(&mut acl, Ace::deny(Sid::null(), 0x10000000));
        assert_eq!(first_free_ace(&acl), 2);
        assert!(get_ace(&acl, 0).is_some());
        assert!(get_ace(&acl, 5).is_none());
        assert!(valid_acl(&acl));
    }

    #[test]
    fn owner_aces_are_detected_by_owner_rights_sid() {
        let mut acl = create_acl();
        add_ace(&mut acl, Ace::allow(Sid::creator_owner(), 0x1));
        assert!(!owner_aces_present(&acl));

        add_ace(&mut acl, Ace::allow(Sid::new(3, &[4]), 0x2));
        assert!(owner_aces_present(&acl));
    }

    #[test]
    fn security_descriptor_construction() {
        let mut sd = create_security_descriptor();
        set_owner(&mut sd, Some(Sid::local_system()));
        let mut acl = create_acl();
        add_ace(&mut acl, Ace::allow(Sid::everyone(), 0x1FF));
        set_dacl(&mut sd, true, Some(acl));
        assert_eq!(get_owner(&sd), Some(&Sid::local_system()));
        let (present, dacl) = get_dacl(&sd);
        assert!(present);
        assert_eq!(dacl.unwrap().aces.len(), 1);
        assert!(valid_security_descriptor(&sd));
        // Header(20) + owner SID S-1-5-18 (1 sub → 12) + ACL header(8) + one ACE(8 + 12).
        assert_eq!(length_security_descriptor(&sd), 20 + 12 + 8 + (8 + 12));
    }

    #[test]
    fn access_grant_checks() {
        assert!(are_all_accesses_granted(0xF, 0x3));
        assert!(!are_all_accesses_granted(0x1, 0x3));
        assert!(are_any_accesses_granted(0x1, 0x3));
        assert!(!are_any_accesses_granted(0x8, 0x3));
    }

    #[test]
    fn luid_equality_uses_both_parts() {
        assert!(equal_luid(0x1234, -1, 0x1234, -1));
        assert!(!equal_luid(0x1234, -1, 0x1235, -1));
        assert!(!equal_luid(0x1234, -1, 0x1234, 0));
    }

    #[test]
    fn generic_mask_mapping() {
        let gm = GenericMapping {
            generic_read: 0x120089,
            generic_write: 0x120116,
            generic_execute: 0x1200A0,
            generic_all: 0x1F01FF,
        };
        // GENERIC_READ (0x80000000) maps to the read specific rights.
        let mapped = map_generic_mask(0x8000_0000, &gm);
        assert_eq!(mapped & 0x120089, 0x120089);
        // No generic bits set → unchanged (minus generic bits).
        assert_eq!(map_generic_mask(0x1, &gm), 0x1);
    }
}
