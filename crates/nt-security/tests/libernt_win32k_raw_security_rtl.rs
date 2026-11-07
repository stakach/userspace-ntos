//! Raw SID and absolute security-descriptor contracts shared by ntdll and win32k.

use nt_security::raw_rtl::{set_absolute_sacl, sub_authority_offset};

#[test]
fn sub_authority_pointer_offset_uses_the_sid_header() {
    assert_eq!(sub_authority_offset(0), Some(8));
    assert_eq!(sub_authority_offset(3), Some(20));
    assert_eq!(sub_authority_offset(u32::MAX), None);
}

#[test]
fn absolute_sacl_update_preserves_other_control_bits() {
    let mut sd = [0u8; 0x28];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x0004u16.to_le_bytes());
    assert_eq!(set_absolute_sacl(&mut sd, true, 0x1234_5678, true), Ok(()));
    assert_eq!(u16::from_le_bytes([sd[2], sd[3]]), 0x0034);
    assert_eq!(u64::from_le_bytes(sd[0x18..0x20].try_into().unwrap()), 0x1234_5678);
    assert_eq!(set_absolute_sacl(&mut sd, false, 0, false), Ok(()));
    assert_eq!(u16::from_le_bytes([sd[2], sd[3]]), 0x0024);
}

#[test]
fn sacl_update_rejects_relative_and_unknown_revision() {
    let mut sd = [0u8; 0x28];
    sd[0] = 2;
    assert_eq!(set_absolute_sacl(&mut sd, true, 1, false), Err(0xc000_0058));
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
    assert_eq!(set_absolute_sacl(&mut sd, true, 1, false), Err(0xc000_0079));
}
