use super::*;
use crate::create_token::STATUS_ACCESS_VIOLATION;
use alloc::{vec, vec::Vec};

const BASE: u64 = 0x1000;
const NOT_SUPPORTED: u32 = 0xc000_00bb;
const INVALID_ACL: u32 = 0xc000_0077;
const SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

struct Memory(Vec<u8>);
impl ClientMemory for Memory {
    fn read(&self, va: u64, dst: &mut [u8]) -> bool {
        let Some(offset) = va.checked_sub(BASE).and_then(|n| usize::try_from(n).ok()) else {
            return false;
        };
        let Some(end) = offset.checked_add(dst.len()) else { return false };
        let Some(source) = self.0.get(offset..end) else { return false };
        dst.copy_from_slice(source);
        true
    }
}

fn ace(kind: u8) -> Vec<u8> {
    let mut bytes = vec![kind, 0, 0, 0];
    bytes.extend_from_slice(&0x8000_0041u32.to_le_bytes());
    if kind == 4 {
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes.extend_from_slice(&SID);
    } else if (5..=8).contains(&kind) {
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    bytes.extend_from_slice(&SID);
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![4, 0, 0, 0, 0, 0, 0, 0];
    bytes[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    for ace in aces { bytes.extend_from_slice(ace); }
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn relative(dacl: Option<&[u8]>, sacl: Option<&[u8]>) -> Memory {
    let mut bytes = vec![0; 20];
    bytes[0] = 1;
    let mut control = 0x8000u16;
    for (value, present, field) in [(dacl, 4, 16), (sacl, 16, 12)] {
        if let Some(value) = value {
            control |= present;
            let offset = bytes.len() as u32;
            bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(value);
        }
    }
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    Memory(bytes)
}

#[test]
fn all_known_and_extension_types_have_explicit_authorization_policy() {
    for kind in 0..=255 {
        let bytes = acl(&[ace(kind)]);
        let native = NativeAcl::from_bytes(&bytes).unwrap();
        let result = native_acl_to_access_acl(&native);
        if matches!(kind, 0 | 1 | 2 | 5 | 6) {
            let result = result.unwrap();
            assert_eq!(result.aces.len(), 1);
            assert_eq!(result.aces[0].mask, 0x8000_0041);
            assert_eq!(result.aces[0].sid, Sid::local_system());
        } else {
            assert_eq!(result, Err(NOT_SUPPORTED), "ACE type {kind}");
        }
    }
}

#[test]
fn unsupported_aces_are_rejected_in_either_acl_even_when_inherit_only() {
    for kind in [3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 255] {
        let mut raw = ace(kind);
        raw[1] = 8;
        let bytes = acl(&[ace(0), raw]);
        for memory in [relative(Some(&bytes), None), relative(None, Some(&bytes))] {
            assert_eq!(capture_security_descriptor_for_access(&memory, BASE), Err(NOT_SUPPORTED));
        }
    }
}

#[test]
fn known_malformed_ace_payloads_fail_before_authority() {
    for kind in 0..=8 {
        let bytes = acl(&[vec![kind, 0, 4, 0]]);
        let memory = relative(Some(&bytes), None);
        assert_eq!(capture_security_descriptor_for_access(&memory, BASE), Err(INVALID_ACL), "ACE type {kind}");
    }
}

#[test]
fn malformed_compound_second_sid_is_not_accepted_as_opaque() {
    let mut raw = ace(4);
    raw.truncate(raw.len() - 4);
    let size = raw.len() as u16;
    raw[2..4].copy_from_slice(&size.to_le_bytes());
    let bytes = acl(&[raw]);
    assert_eq!(native_acl_to_access_acl(&NativeAcl::from_bytes(&bytes).unwrap()), Err(INVALID_ACL));
}

#[test]
fn unknown_object_flags_fail_instead_of_ignoring_payload_semantics() {
    let mut raw = ace(6);
    raw[8..12].copy_from_slice(&4u32.to_le_bytes());
    let bytes = acl(&[raw]);
    assert_eq!(native_acl_to_access_acl(&NativeAcl::from_bytes(&bytes).unwrap()), Err(NOT_SUPPORTED));
}

#[test]
fn supported_flags_guid_and_order_survive_conversion() {
    let mut raw = ace(6);
    raw[1] = 8 | 0x10;
    raw[8..12].copy_from_slice(&3u32.to_le_bytes());
    raw.splice(12..12, [0x51; 16].into_iter().chain([0x62; 16]));
    let size = raw.len() as u16;
    raw[2..4].copy_from_slice(&size.to_le_bytes());
    let bytes = acl(&[raw, ace(0), ace(2)]);
    let result = native_acl_to_access_acl(&NativeAcl::from_bytes(&bytes).unwrap()).unwrap();
    assert_eq!(result.aces[0].ace_type, AceType::AccessDenied);
    assert_eq!(result.aces[0].object_type, Some([0x51; 16]));
    assert!(result.aces[0].inherit_only);
    assert_eq!(result.aces[1].ace_type, AceType::AccessAllowed);
    assert_eq!(result.aces[2].ace_type, AceType::SystemAudit);
}

#[test]
fn absent_null_and_empty_dacl_keep_distinct_authority_semantics() {
    let absent = relative(None, None);
    let mut null = relative(None, None);
    null.0[2] |= 4;
    let empty_acl = acl(&[]);
    let empty = relative(Some(&empty_acl), None);
    assert_eq!(capture_security_descriptor_for_access(&absent, BASE).unwrap().dacl, None);
    assert_eq!(capture_security_descriptor_for_access(&null, BASE).unwrap().dacl, None);
    assert_eq!(capture_security_descriptor_for_access(&empty, BASE).unwrap().dacl, Some(Acl::empty()));
}

#[test]
fn absolute_descriptor_uses_same_strict_acl_gate() {
    let bytes = acl(&[ace(10), ace(0)]);
    let mut memory = Memory(vec![0; 40]);
    memory.0[0] = 1;
    memory.0[2] = 4;
    memory.0[32..40].copy_from_slice(&(BASE + 40).to_le_bytes());
    memory.0.extend_from_slice(&bytes);
    assert_eq!(capture_security_descriptor_for_access(&memory, BASE), Err(NOT_SUPPORTED));
}

#[test]
fn unsupported_deny_before_supported_allow_is_rejected_before_evaluation() {
    for kind in [10, 12] {
        let bytes = acl(&[ace(kind), ace(0)]);
        let memory = relative(Some(&bytes), None);
        assert_eq!(capture_security_descriptor_for_access(&memory, BASE), Err(NOT_SUPPORTED));
        let native = NativeAcl::from_bytes(&bytes).unwrap();
        assert_eq!(native_acl_to_access_acl(&native), Err(NOT_SUPPORTED));
    }
}

#[test]
fn raw_capture_preserves_opaque_aces_but_authorization_never_skips() {
    let bytes = acl(&[ace(0), ace(10)]);
    let native = NativeAcl::from_bytes(&bytes).unwrap();
    assert_eq!(native_acl_to_access_acl(&native), Err(NOT_SUPPORTED));
    let memory = relative(Some(&bytes), None);
    assert_eq!(capture_security_descriptor_bytes(&memory, BASE).unwrap(), memory.0);
    assert_eq!(capture_security_descriptor_for_access(&memory, BASE), Err(NOT_SUPPORTED));
}

#[test]
fn unreadable_acl_never_returns_a_partial_descriptor() {
    let bytes = acl(&[ace(0)]);
    let mut memory = relative(Some(&bytes), None);
    memory.0.pop();
    assert_eq!(capture_security_descriptor_for_access(&memory, BASE), Err(STATUS_ACCESS_VIOLATION));
}
