use nt_security::validate_security_descriptor_bytes;

fn descriptor(control: u16) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&(control | 0x8000).to_le_bytes());
    bytes
}

fn with_dacl(acl: &[u8]) -> Vec<u8> {
    let mut bytes = descriptor(4);
    bytes[16..20].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(acl);
    bytes
}

fn with_owner(revision: u8, count: u8, offset: usize) -> Vec<u8> {
    let mut bytes = descriptor(0);
    bytes[4..8].copy_from_slice(&(offset as u32).to_le_bytes());
    bytes.resize(offset + 8 + usize::from(count) * 4, 0);
    bytes[offset] = revision;
    bytes[offset + 1] = count;
    bytes[offset + 7] = 5;
    bytes
}

#[test]
fn acl_revision_and_declared_ace_count_are_admitted_structurally() {
    for acl in [
        [1, 0, 8, 0, 0, 0, 0, 0],
        [5, 0, 8, 0, 0, 0, 0, 0],
        [2, 0, 8, 0, 1, 0, 0, 0],
    ] {
        assert!(validate_security_descriptor_bytes(&with_dacl(&acl)).is_err(), "{acl:?}");
    }
}

#[test]
fn opaque_ace_headers_cannot_escape_the_declared_acl_extent() {
    for ace_size in [0u16, 3, 5, 8] {
        let mut acl = [2, 0, 12, 0, 1, 0, 0, 0, 0x7f, 0, 0, 0];
        acl[10..12].copy_from_slice(&ace_size.to_le_bytes());
        assert!(validate_security_descriptor_bytes(&with_dacl(&acl)).is_err(),
            "ACE size {ace_size} must not be admitted in a four-byte slot");
    }
}

#[test]
fn owner_and_group_sids_require_native_revision_and_subauthority_bounds() {
    for (revision, count) in [(0, 1), (2, 1), (1, 16)] {
        let owner = with_owner(revision, count, 20);
        assert!(validate_security_descriptor_bytes(&owner).is_err(),
            "owner SID revision {revision}, count {count}");
        let mut group = owner;
        group[4..8].copy_from_slice(&0u32.to_le_bytes());
        group[8..12].copy_from_slice(&20u32.to_le_bytes());
        assert!(validate_security_descriptor_bytes(&group).is_err(),
            "group SID revision {revision}, count {count}");
    }
}

#[test]
fn nonzero_component_offsets_cannot_point_into_the_relative_header() {
    // ReactOS sdk/lib/rtl/sd.c:RtlpValidateSDOffsetAndSize rejects offsets below 20.
    // This overlapping SID has a valid revision and zero subauthorities, so its SID header alone
    // cannot establish a valid component location.
    let mut bytes = descriptor(0);
    bytes[1] = 1;
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    assert!(validate_security_descriptor_bytes(&bytes).is_err());
}

#[test]
fn nonzero_component_offsets_require_ulong_alignment() {
    // RtlpValidateSDOffsetAndSize also requires ULONG alignment, independently of extent.
    assert!(validate_security_descriptor_bytes(&with_owner(1, 1, 21)).is_err());
    let mut bytes = descriptor(4);
    bytes[16..20].copy_from_slice(&21u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    assert!(validate_security_descriptor_bytes(&bytes).is_err());
}

#[test]
fn valid_null_acls_and_aligned_sids_remain_admissible() {
    assert_eq!(validate_security_descriptor_bytes(&descriptor(4 | 0x10)), Ok(()));
    assert_eq!(validate_security_descriptor_bytes(&with_owner(1, 1, 20)), Ok(()));
    for revision in [2, 4] {
        assert_eq!(validate_security_descriptor_bytes(&with_dacl(
            &[revision, 0, 8, 0, 0, 0, 0, 0],
        )), Ok(()));
    }
}

#[test]
fn structurally_valid_opaque_aces_are_preserved_without_access_policy_admission() {
    let bytes = with_dacl(&[2, 0, 16, 0, 1, 0, 0, 0, 0x7f, 0, 8, 0, 1, 2, 3, 4]);
    let before = bytes.clone();
    assert_eq!(validate_security_descriptor_bytes(&bytes), Ok(()));
    assert_eq!(bytes, before);
    assert!(nt_security::security_descriptor_bytes_for_access(&bytes).is_err());
}
