use nt_security::{validate_security_descriptor_bytes, STATUS_INVALID_ACL, STATUS_INVALID_SECURITY_DESCR};

#[test]
fn structural_validation_preserves_opaque_aces_without_authorizing_them() {
    let mut descriptor = [0u8; 32];
    descriptor[0] = 1;
    descriptor[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    descriptor[16..20].copy_from_slice(&20u32.to_le_bytes());
    descriptor[20] = 2;
    descriptor[22..24].copy_from_slice(&12u16.to_le_bytes());
    descriptor[24..26].copy_from_slice(&1u16.to_le_bytes());
    descriptor[28] = 0x7f;
    descriptor[30..32].copy_from_slice(&4u16.to_le_bytes());
    assert_eq!(validate_security_descriptor_bytes(&descriptor), Ok(()));
    assert!(nt_security::security_descriptor_bytes_for_access(&descriptor).is_err());
    descriptor[16..20].copy_from_slice(&32u32.to_le_bytes());
    assert_eq!(validate_security_descriptor_bytes(&descriptor), Err(STATUS_INVALID_ACL));
    assert_eq!(validate_security_descriptor_bytes(&[]), Err(STATUS_INVALID_SECURITY_DESCR));
}
