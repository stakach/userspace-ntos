//! Additional released ntdll security/SID entry points.
//!
//! Keep SID shape checks here and leave token mutation and descriptor construction
//! unavailable until the native security service can own their effects.

use core::ffi::c_void;
use nt_ntdll_layout::UnicodeString;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_SID: u32 = 0xC000_0078;

/// Reads only the fixed SID header. The caller must provide a readable SID.
unsafe fn sid_shape(sid: *const c_void) -> Option<(u8, u8)> {
    if sid.is_null() {
        return None;
    }
    let bytes = sid.cast::<u8>();
    // SAFETY: caller provides at least the fixed eight-byte SID header.
    unsafe {
        if *bytes != 1 || *bytes.add(1) > 15 || *bytes.add(2) != 0
            || *bytes.add(3) != 0 || *bytes.add(4) != 0
            || *bytes.add(5) != 0 || *bytes.add(6) != 0
        {
            return None;
        }
        Some((*bytes.add(7), *bytes.add(1)))
    }
}

/// A capability SID has App Package authority and starts with RID 3.
#[export_name = "RtlIsCapabilitySid"]
pub unsafe extern "system" fn rtl_is_capability_sid(sid: *const c_void) -> u8 {
    if !matches!(unsafe { sid_shape(sid) }, Some((15, count)) if count >= 2) {
        return 0;
    }
    // SAFETY: the two SID subauthorities exist after the count guard.
    (unsafe { core::ptr::read_unaligned(sid.cast::<u8>().add(8).cast::<u32>()) } == 3) as u8
}

fn package_kind(authority: u8, count: u8, first_rid: u32) -> u32 {
    if authority != 15 || first_rid != 2 {
        0
    } else if count == 8 {
        2 // ParentAppContainerSidType
    } else if count == 12 {
        1 // ChildAppContainerSidType
    } else {
        3 // InvalidAppContainerSidType
    }
}

/// Classify parent/child package SIDs. `kind` uses APPCONTAINER_SID_TYPE values.
#[export_name = "RtlGetAppContainerSidType"]
pub unsafe extern "system" fn rtl_get_app_container_sid_type(
    sid: *const c_void,
    kind: *mut u32,
) -> u32 {
    if kind.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let Some((authority, count)) = (unsafe { sid_shape(sid) }) else {
        return STATUS_INVALID_SID;
    };
    let first_rid = if count == 0 { 0 } else {
        // SAFETY: the SID's count guarantees the first subauthority is present.
        unsafe { core::ptr::read_unaligned(sid.cast::<u8>().add(8).cast::<u32>()) }
    };
    // SAFETY: the caller supplied a writable out parameter.
    unsafe { *kind = package_kind(authority, count, first_rid) };
    STATUS_SUCCESS
}

/// Verify the eight parent RIDs exactly match a twelve-RID child package SID.
#[export_name = "RtlIsParentOfChildAppContainer"]
pub unsafe extern "system" fn rtl_is_parent_of_child_app_container(
    parent: *const c_void,
    child: *const c_void,
) -> u8 {
    let (Some((15, 8)), Some((15, 12))) =
        (unsafe { sid_shape(parent) }, unsafe { sid_shape(child) })
    else {
        return 0;
    };
    let parent = parent.cast::<u8>();
    let child = child.cast::<u8>();
    // SAFETY: both SIDs have the required counts, so their authority and
    // first eight subauthorities are readable. The count bytes intentionally differ.
    let parent_bytes = unsafe { core::slice::from_raw_parts(parent, 40) };
    let child_bytes = unsafe { core::slice::from_raw_parts(child, 40) };
    (parent_bytes[2..8] == child_bytes[2..8]
        && parent_bytes[8..40] == child_bytes[8..40]
        && u32::from_le_bytes(parent_bytes[8..12].try_into().unwrap()) == 2) as u8
}

/// Windows service SID = S-1-5-80 plus SHA-1 of the uppercase UTF-16LE name.
#[export_name = "RtlCreateServiceSid"]
pub unsafe extern "system" fn rtl_create_service_sid(
    name: *const UnicodeString,
    sid: *mut c_void,
    length: *mut u32,
) -> u32 {
    if name.is_null() || length.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: caller supplied valid descriptor/length pointers.
    let name = unsafe { &*name };
    if name.length % 2 != 0 || name.length > name.maximum_length ||
        (name.length != 0 && name.buffer == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    let capacity = unsafe { *length };
    unsafe { *length = 32 };
    if capacity < 32 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut hash = nt_ntdll::crypto::ShaContext::zeroed();
    nt_ntdll::crypto::a_sha_init(&mut hash);
    // SHA-1 consumes the uppercase UTF-16LE representation, in bounded chunks.
    let mut chunk = [0u8; 128];
    let mut used = 0;
    for index in 0..(name.length as usize / 2) {
        // SAFETY: descriptor states this UTF-16 code unit is readable.
        let unit = unsafe { core::ptr::read_unaligned((name.buffer as *const u16).add(index)) };
        let up = crate::exports::rtl_upcase_unicode_char(unit).to_le_bytes();
        chunk[used..used + 2].copy_from_slice(&up);
        used += 2;
        if used == chunk.len() {
            nt_ntdll::crypto::a_sha_update(&mut hash, &chunk);
            used = 0;
        }
    }
    nt_ntdll::crypto::a_sha_update(&mut hash, &chunk[..used]);
    let mut digest = [0u32; 5];
    nt_ntdll::crypto::a_sha_final(&mut hash, &mut digest);
    // SAFETY: `capacity >= 32`, and the caller supplied a writable SID buffer.
    let output = unsafe { core::slice::from_raw_parts_mut(sid.cast::<u8>(), 32) };
    output[..8].copy_from_slice(&[1, 6, 0, 0, 0, 0, 0, 5]);
    output[8..12].copy_from_slice(&80u32.to_le_bytes());
    for (index, word) in digest.iter().enumerate() {
        output[12 + index * 4..16 + index * 4].copy_from_slice(&word.to_le_bytes());
    }
    STATUS_SUCCESS
}

/// Token membership is enforced by the native security service; unavailable until
/// its AppContainer flags and effective-token selection are implemented.
#[export_name = "RtlCheckTokenMembershipEx"]
pub unsafe extern "system" fn rtl_check_token_membership_ex(
    _token: *mut c_void,
    sid: *const c_void,
    flags: u32,
    is_member: *mut u8,
) -> u32 {
    if sid.is_null() || is_member.is_null() || flags & !3 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_NOT_IMPLEMENTED
}

/// Descriptor ownership must be allocated and tracked by the native security layer.
#[export_name = "RtlCreateAndSetSD"]
pub unsafe extern "system" fn rtl_create_and_set_sd(
    _aces: *const c_void,
    _ace_count: u32,
    _owner: *const c_void,
    _group: *const c_void,
    descriptor: *mut *mut c_void,
) -> u32 {
    if descriptor.is_null() { STATUS_INVALID_PARAMETER } else { STATUS_NOT_IMPLEMENTED }
}

#[export_name = "RtlCreateUserSecurityObject"]
pub unsafe extern "system" fn rtl_create_user_security_object(
    _aces: *const c_void,
    _ace_count: u32,
    _owner: *const c_void,
    _group: *const c_void,
    _directory: u8,
    _generic_mapping: *const c_void,
    descriptor: *mut *mut c_void,
) -> u32 {
    if descriptor.is_null() { STATUS_INVALID_PARAMETER } else { STATUS_NOT_IMPLEMENTED }
}

#[export_name = "RtlDeriveCapabilitySidsFromName"]
pub unsafe extern "system" fn rtl_derive_capability_sids_from_name(
    name: *const UnicodeString,
    group_sid: *mut c_void,
    capability_sid: *mut c_void,
) -> u32 {
    if name.is_null() || group_sid.is_null() || capability_sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: caller supplied a readable UNICODE_STRING descriptor.
    let name = unsafe { &*name };
    if name.length % 2 != 0 || name.length > name.maximum_length
        || (name.length != 0 && name.buffer == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    let mut hash = Sha256::new();
    for index in 0..name.length as usize / 2 {
        // SAFETY: the descriptor covers this UTF-16 code unit.
        let unit = unsafe { core::ptr::read_unaligned((name.buffer as *const u16).add(index)) };
        hash.update(&crate::exports::rtl_upcase_unicode_char(unit).to_le_bytes());
    }
    let digest = hash.finish();
    // SAFETY: per RtlDeriveCapabilitySidsFromName ABI the caller provides 44
    // bytes for the group SID and 48 bytes for the capability SID.
    let group = unsafe { core::slice::from_raw_parts_mut(group_sid.cast::<u8>(), 44) };
    let capability = unsafe { core::slice::from_raw_parts_mut(capability_sid.cast::<u8>(), 48) };
    group[..8].copy_from_slice(&[1, 9, 0, 0, 0, 0, 0, 5]);
    group[8..12].copy_from_slice(&32u32.to_le_bytes());
    group[12..].copy_from_slice(&digest);
    capability[..8].copy_from_slice(&[1, 10, 0, 0, 0, 0, 0, 15]);
    capability[8..12].copy_from_slice(&3u32.to_le_bytes());
    capability[12..16].copy_from_slice(&0x400u32.to_le_bytes());
    capability[16..].copy_from_slice(&digest);
    STATUS_SUCCESS
}

/// Bounded SHA-256 state for capability SID derivation; no heap or global state.
struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    used: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            block: [0; 64],
            used: 0,
            total: 0,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.block[self.used] = byte;
            self.used += 1;
            self.total += 1;
            if self.used == 64 {
                self.transform();
                self.used = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.total * 8;
        self.update(&[0x80]);
        if self.used > 56 {
            while self.used != 0 {
                self.update(&[0]);
            }
        }
        while self.used < 56 {
            self.update(&[0]);
        }
        self.update(&bit_len.to_be_bytes());
        let mut digest = [0u8; 32];
        for (word, bytes) in self.state.iter().zip(digest.chunks_exact_mut(4)) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn transform(&mut self) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for (word, bytes) in w[..16].iter_mut().zip(self.block.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut s = self.state;
        for i in 0..64 {
            let s1 = s[4].rotate_right(6) ^ s[4].rotate_right(11) ^ s[4].rotate_right(25);
            let choice = (s[4] & s[5]) ^ (!s[4] & s[6]);
            let t1 = s[7].wrapping_add(s1).wrapping_add(choice).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = s[0].rotate_right(2) ^ s[0].rotate_right(13) ^ s[0].rotate_right(22);
            let majority = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
            let t2 = s0.wrapping_add(majority);
            s = [t1.wrapping_add(t2), s[0], s[1], s[2], s[3].wrapping_add(t1), s[4], s[5], s[6]];
        }
        for (dest, value) in self.state.iter_mut().zip(s) {
            *dest = dest.wrapping_add(value);
        }
    }
}

#[export_name = "RtlGetAppContainerParent"]
pub unsafe extern "system" fn rtl_get_app_container_parent(
    sid: *const c_void,
    parent: *mut *mut c_void,
) -> u32 {
    if sid.is_null() || parent.is_null() { STATUS_INVALID_PARAMETER } else { STATUS_NOT_IMPLEMENTED }
}

#[export_name = "RtlRemovePrivileges"]
pub unsafe extern "system" fn rtl_remove_privileges(
    _token: *mut c_void,
    keep: *const u32,
    count: u32,
) -> u32 {
    if count != 0 && keep.is_null() { STATUS_INVALID_PARAMETER } else { STATUS_NOT_IMPLEMENTED }
}

/// Match a UTF-16 filename against NT/DOS wildcard tokens. The case-insensitive
/// form uses the supplied upcase table or the existing NLS uppercase mapping.
#[export_name = "RtlIsNameInExpression"]
pub unsafe extern "system" fn rtl_is_name_in_expression(
    expression: *const UnicodeString,
    name: *const UnicodeString,
    ignore_case: u8,
    upcase_table: *const u16,
) -> u8 {
    if expression.is_null() || name.is_null() {
        return 0;
    }
    // SAFETY: the caller supplied readable string descriptors and their buffers.
    let (expression, name) = unsafe { (&*expression, &*name) };
    if expression.length % 2 != 0 || name.length % 2 != 0
        || expression.length > expression.maximum_length || name.length > name.maximum_length
        || (expression.length != 0 && expression.buffer == 0)
        || (name.length != 0 && name.buffer == 0)
    {
        return 0;
    }
    // SAFETY: validated counted UTF-16 descriptors provide these readable slices.
    let expr = if expression.length == 0 { &[] } else {
        unsafe { core::slice::from_raw_parts(expression.buffer as *const u16, expression.length as usize / 2) }
    };
    let name = if name.length == 0 { &[] } else {
        unsafe { core::slice::from_raw_parts(name.buffer as *const u16, name.length as usize / 2) }
    };
    match_expression(expr, name, ignore_case != 0, upcase_table) as u8
}

fn folded(unit: u16, ignore_case: bool, upcase_table: *const u16) -> u16 {
    if !ignore_case {
        unit
    } else if !upcase_table.is_null() {
        // SAFETY: the caller provides a full 65536-entry NT upcase table.
        unsafe { *upcase_table.add(unit as usize) }
    } else {
        crate::exports::rtl_upcase_unicode_char(unit)
    }
}

fn match_expression(expr: &[u16], name: &[u16], ignore_case: bool, table: *const u16) -> bool {
    if expr.is_empty() || name.is_empty() {
        return expr.is_empty() && name.is_empty();
    }
    if expr == [b'*' as u16] || expr == [b'*' as u16, b'.' as u16, b'*' as u16] {
        return true;
    }
    let (mut e, mut n) = (0usize, 0usize);
    let (mut star_e, mut star_n) = (None::<usize>, 0usize);
    loop {
        if e == expr.len() && n == name.len() {
            return true;
        }
        let ec = expr.get(e).copied().unwrap_or(0);
        let nc = name.get(n).copied().unwrap_or(0);
        let ec_folded = folded(ec, ignore_case, table);
        let nc_folded = folded(nc, ignore_case, table);
        if (ec == b'?' as u16 && n < name.len())
            || (ec != b'*' as u16 && ec != b'<' as u16 && ec != b'?' as u16
                && ec != b'>' as u16 && ec_folded == nc_folded && e < expr.len())
        {
            e += 1;
            n += 1;
            continue;
        }
        if ec == b'*' as u16 || ec == b'<' as u16 {
            star_e = Some(e);
            star_n = n;
            e += 1;
            continue;
        }
        if ec == b'>' as u16 {
            if n == name.len() || nc == b'.' as u16 {
                while e < expr.len() && expr[e] == b'>' as u16 {
                    e += 1;
                }
            } else {
                n += 1;
                e += 1;
            }
            continue;
        }
        if ec == b'"' as u16 {
            if n == name.len() {
                e += 1;
                continue;
            }
            if nc == b'.' as u16 {
                e += 1;
                n += 1;
                continue;
            }
        }
        if let Some(star) = star_e {
            if expr[star] == b'<' as u16 && e >= expr.len()
                && name[star_n..].contains(&(b'.' as u16))
            {
                return false;
            }
            if star_n < name.len() {
                star_n += 1;
                n = star_n;
                e = star + 1;
                continue;
            }
        }
        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(authority: u8, rids: &[u32]) -> [u8; 56] {
        let mut result = [0u8; 56];
        result[0] = 1;
        result[1] = rids.len() as u8;
        result[7] = authority;
        for (index, rid) in rids.iter().enumerate() {
            result[8 + index * 4..12 + index * 4].copy_from_slice(&rid.to_le_bytes());
        }
        result
    }

    #[test]
    fn distinguishes_capability_and_package_sids() {
        let capability = sid(15, &[3, 1]);
        let package = sid(15, &[2, 1]);
        assert_eq!(unsafe { rtl_is_capability_sid(capability.as_ptr().cast()) }, 1);
        assert_eq!(unsafe { rtl_is_capability_sid(package.as_ptr().cast()) }, 0);
        assert_eq!(unsafe { rtl_is_capability_sid(core::ptr::null()) }, 0);
    }

    #[test]
    fn classifies_parent_child_and_non_package_sids() {
        let parent = sid(15, &[2, 1, 2, 3, 4, 5, 6, 7]);
        let child = sid(15, &[2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let unrelated = sid(5, &[18]);
        let mut kind = u32::MAX;
        assert_eq!(unsafe { rtl_get_app_container_sid_type(parent.as_ptr().cast(), &mut kind) }, STATUS_SUCCESS);
        assert_eq!(kind, 2);
        assert_eq!(unsafe { rtl_get_app_container_sid_type(child.as_ptr().cast(), &mut kind) }, STATUS_SUCCESS);
        assert_eq!(kind, 1);
        assert_eq!(unsafe { rtl_get_app_container_sid_type(unrelated.as_ptr().cast(), &mut kind) }, STATUS_SUCCESS);
        assert_eq!(kind, 0);
        assert_eq!(unsafe { rtl_is_parent_of_child_app_container(parent.as_ptr().cast(), child.as_ptr().cast()) }, 1);
    }

    #[test]
    fn service_sid_reports_required_length_and_matches_reference_vector() {
        let name: Vec<u16> = "TestService".encode_utf16().collect();
        let mut descriptor = UnicodeString::default();
        descriptor.length = (name.len() * 2) as u16;
        descriptor.maximum_length = descriptor.length;
        descriptor.buffer = name.as_ptr() as u64;
        let mut length = 0;
        assert_eq!(unsafe { rtl_create_service_sid(&descriptor, core::ptr::null_mut(), &mut length) }, STATUS_BUFFER_TOO_SMALL);
        assert_eq!(length, 32);
        let mut output = [0u8; 32];
        assert_eq!(unsafe { rtl_create_service_sid(&descriptor, output.as_mut_ptr().cast(), &mut length) }, STATUS_SUCCESS);
        assert_eq!(output[0..8], [1, 6, 0, 0, 0, 0, 0, 5]);
        let rids = [80, 3892056402, 659729507, 4115993473, 1921682939, 1565901394];
        for (index, rid) in rids.iter().enumerate() {
            assert_eq!(u32::from_le_bytes(output[8 + index * 4..12 + index * 4].try_into().unwrap()), *rid);
        }
    }

    #[test]
    fn capability_sid_matches_wine_uppercase_hash_vector() {
        let name: Vec<u16> = "__ab".encode_utf16().collect();
        let mut descriptor = UnicodeString::default();
        descriptor.length = (name.len() * 2) as u16;
        descriptor.maximum_length = descriptor.length;
        descriptor.buffer = name.as_ptr() as u64;
        let mut group = [0u8; 44];
        let mut capability = [0u8; 48];
        assert_eq!(unsafe { rtl_derive_capability_sids_from_name(
            &descriptor, group.as_mut_ptr().cast(), capability.as_mut_ptr().cast()
        ) }, STATUS_SUCCESS);
        assert_eq!(&group[..12], &[1, 9, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0]);
        assert_eq!(&capability[..16], &[1, 10, 0, 0, 0, 0, 0, 15, 3, 0, 0, 0, 0, 4, 0, 0]);
        let expected = [0xddd798eb, 0x367bd9d0, 0x1c9e610a, 0x0c43dc7e,
                        0xe91d8625, 0x395e7cf8, 0xe6e7c3d2, 0x2661e620];
        for (bytes, value) in capability[16..].chunks_exact(4).zip(expected) {
            assert_eq!(u32::from_le_bytes(bytes.try_into().unwrap()), value);
        }
        assert_eq!(&group[12..], &capability[16..]);
    }

    #[test]
    fn nt_filename_wildcards_and_case_mapping() {
        let expr: Vec<u16> = "*.TXT".encode_utf16().collect();
        let name: Vec<u16> = "notes.txt".encode_utf16().collect();
        assert!(match_expression(&expr, &name, true, core::ptr::null()));
        assert!(!match_expression(&expr, &name, false, core::ptr::null()));
        assert!(match_expression(&"A?C".encode_utf16().collect::<Vec<_>>(),
                                  &"ABC".encode_utf16().collect::<Vec<_>>(), false, core::ptr::null()));
        assert!(!match_expression(&"A?C".encode_utf16().collect::<Vec<_>>(),
                                   &"AC".encode_utf16().collect::<Vec<_>>(), false, core::ptr::null()));
    }
}
