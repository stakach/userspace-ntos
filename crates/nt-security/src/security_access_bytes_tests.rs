use super::*;
use crate::{AccessToken, CapturedSubjectTokens, SecurityAssignmentAudit};

fn root() -> Vec<u8> {
    assign_registry_root_security(
        &CapturedSubjectTokens {
            primary: &AccessToken::system(),
            client: None,
            process_audit_id: 0,
        },
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap()
}

struct Memory(Vec<u8>);
impl ClientMemory for Memory {
    fn read(&self, address: u64, out: &mut [u8]) -> bool {
        let Some(start) = address
            .checked_sub(0x1000)
            .and_then(|n| usize::try_from(n).ok())
        else {
            return false;
        };
        let Some(end) = start.checked_add(out.len()) else {
            return false;
        };
        let Some(bytes) = self.0.get(start..end) else {
            return false;
        };
        out.copy_from_slice(bytes);
        true
    }
}

#[test]
fn owned_descriptor_matches_strict_native_capture_without_a_second_acl_copy() {
    let bytes = root();
    let direct = security_descriptor_bytes_for_access(&bytes).unwrap();
    let captured = capture_security_descriptor_for_access(&Memory(bytes), 0x1000).unwrap();
    assert_eq!(direct, captured);
}

#[test]
fn empty_null_and_absent_dacls_remain_distinct_from_a_missing_descriptor() {
    for (present, acl) in [
        (false, None),
        (true, None),
        (true, Some(&[2, 0, 8, 0, 0, 0, 0, 0][..])),
    ] {
        let bytes = build_self_relative_descriptor(DescriptorBuild {
            owner: None,
            group: None,
            sacl_present: false,
            sacl: None,
            dacl_present: present,
            dacl: acl,
            control: 0,
        })
        .unwrap();
        let parsed = security_descriptor_bytes_for_access(&bytes).unwrap();
        assert_eq!(parsed.dacl.is_some(), acl.is_some());
        let result = crate::access_check(
            &parsed,
            &AccessToken::user(1),
            2,
            &KEY_GENERIC_MAPPING,
            crate::ProcessorMode::UserMode,
        );
        assert_eq!(result.granted(), acl.is_none());
    }
    assert!(security_descriptor_bytes_for_access(&[]).is_err());
}

#[test]
fn rejects_unknown_aces_in_either_acl_instead_of_discarding_security() {
    let unknown = [2, 0, 12, 0, 1, 0, 0, 0, 42, 0, 4, 0];
    for sacl in [true, false] {
        let bytes = build_self_relative_descriptor(DescriptorBuild {
            owner: None,
            group: None,
            sacl_present: sacl,
            sacl: sacl.then_some(&unknown),
            dacl_present: !sacl,
            dacl: (!sacl).then_some(&unknown),
            control: 0,
        })
        .unwrap();
        assert_eq!(
            security_descriptor_bytes_for_access(&bytes),
            Err(0xc000_00bb)
        );
        assert_eq!(
            capture_security_descriptor_for_access(&Memory(bytes), 0x1000),
            Err(0xc000_00bb)
        );
    }
}

#[test]
fn malformed_headers_offsets_sids_and_aces_fail_closed() {
    let original = root();
    for kind in 0..6 {
        let mut bytes = original.clone();
        let owner = read_u32(&bytes, 4) as usize;
        let dacl = read_u32(&bytes, 16) as usize;
        match kind {
            0 => bytes.truncate(19),
            1 => bytes[3] &= !0x80,
            2 => bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes()),
            3 => bytes[owner] = 2,
            4 => bytes[dacl + 4..dacl + 6].copy_from_slice(&u16::MAX.to_le_bytes()),
            5 => bytes[dacl + 10..dacl + 12].copy_from_slice(&0u16.to_le_bytes()),
            _ => unreachable!(),
        }
        assert!(
            security_descriptor_bytes_for_access(&bytes).is_err(),
            "case {kind}"
        );
    }
}
