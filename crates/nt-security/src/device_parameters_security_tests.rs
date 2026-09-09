use super::super::{SE_DACL_PROTECTED, SE_SELF_RELATIVE};
use super::*;
use alloc::vec;

const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

fn ace(kind: u8, flags: u8, sid: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, flags, 0, 0];
    bytes.extend_from_slice(&0x20019u32.to_le_bytes());
    if matches!(kind, 5 | 6) {
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[0x23; 32]);
    }
    bytes.extend_from_slice(sid);
    let len = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&len.to_le_bytes());
    bytes
}

fn acl(aces: &[Vec<u8>], slack: usize) -> Vec<u8> {
    let mut bytes = vec![4, 0, 0, 0, 0, 0, 0, 0];
    bytes[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes.resize(bytes.len() + slack, 0x55);
    let len = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&len.to_le_bytes());
    bytes
}

fn descriptor(dacl: Option<&[u8]>, present: bool) -> Vec<u8> {
    build_self_relative_descriptor(DescriptorBuild {
        owner: Some(&SYSTEM),
        group: Some(&ADMINISTRATORS),
        sacl: None,
        sacl_present: false,
        dacl,
        dacl_present: present,
        control: SE_SELF_RELATIVE | SE_DACL_DEFAULTED | SE_DACL_PROTECTED,
    })
    .unwrap()
}

fn admin_grant() -> Vec<u8> {
    let mut grant = ace(0, 2, &ADMINISTRATORS);
    grant[4..8].copy_from_slice(&KEY_ALL_ACCESS.to_le_bytes());
    grant
}

#[test]
fn replaces_only_basic_admin_aces_and_preserves_every_other_ace_byte_in_order() {
    let kept = vec![
        ace(1, 0, &SYSTEM),
        ace(2, 0xc0, &ADMINISTRATORS),
        ace(5, 0x12, &ADMINISTRATORS),
        ace(6, 0x13, &ADMINISTRATORS),
        ace(42, 0x57, &ADMINISTRATORS),
        ace(0, 0x02, &SYSTEM),
    ];
    let mut input = kept.clone();
    input.insert(0, ace(1, 0x10, &ADMINISTRATORS));
    input.insert(3, ace(0, 0x08, &ADMINISTRATORS));
    input.push(ace(0, 0, &ADMINISTRATORS));
    let source = descriptor(Some(&acl(&input, 32)), true);
    let before = source.clone();
    let result = prepare_device_parameters_security(&source).unwrap();
    assert_eq!(source, before);
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    let mut expected = kept;
    expected.push(admin_grant());
    assert_eq!(parsed.dacl.unwrap(), acl(&expected, 0));
    NativeAcl::from_bytes(parsed.dacl.unwrap()).unwrap();
    assert_eq!(prepare_device_parameters_security(&result).unwrap(), result);
}

#[test]
fn preserves_owner_group_sacl_resource_manager_and_unrelated_control_bits() {
    let old_acl = acl(&[ace(0, 0, &SYSTEM)], 0);
    let sacl = acl(&[ace(2, 0xc0, &ADMINISTRATORS)], 12);
    let mut source = build_self_relative_descriptor(DescriptorBuild {
        owner: Some(&SYSTEM),
        group: Some(&ADMINISTRATORS),
        sacl: Some(&sacl),
        sacl_present: true,
        dacl: Some(&old_acl),
        dacl_present: true,
        control: 0xffff,
    })
    .unwrap();
    source[1] = 0xa5;
    source[2..4].copy_from_slice(&0xfdffu16.to_le_bytes());
    let result = prepare_device_parameters_security(&source).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(parsed.owner, Some(SYSTEM.as_slice()));
    assert_eq!(parsed.group, Some(ADMINISTRATORS.as_slice()));
    assert_eq!(parsed.sacl, Some(sacl.as_slice()));
    assert_eq!(
        parsed.control,
        (0xfdff | SE_DACL_PRESENT) & !SE_DACL_DEFAULTED
    );
    assert_eq!(result[1], 0xa5);
}

#[test]
fn absent_and_empty_dacls_gain_admin_but_present_null_dacl_is_not_silently_narrowed() {
    for source in [
        descriptor(None, false),
        descriptor(Some(&acl(&[], 0)), true),
    ] {
        let result = prepare_device_parameters_security(&source).unwrap();
        let parsed = parse_self_relative_descriptor(&result).unwrap();
        assert!(parsed.dacl_present);
        assert_eq!(parsed.control & SE_DACL_DEFAULTED, 0);
        let dacl = parsed.dacl.unwrap();
        assert_eq!(&dacl[8..], admin_grant());
        assert_eq!(dacl[4..6], [1, 0]);
    }
    assert_eq!(
        prepare_device_parameters_security(&descriptor(None, true)),
        Err(STATUS_INVALID_ACL)
    );
}

#[test]
fn malformed_acl_and_sid_fail_without_modifying_the_source() {
    let valid = descriptor(Some(&acl(&[ace(0, 0, &SYSTEM)], 0)), true);
    let dacl = u32::from_le_bytes(valid[16..20].try_into().unwrap()) as usize;
    for (offset, byte) in [(dacl, 1), (dacl + 4, 255), (dacl + 10, 2), (dacl + 16, 2)] {
        let mut source = valid.clone();
        source[offset] = byte;
        let before = source.clone();
        assert_eq!(
            prepare_device_parameters_security(&source),
            Err(STATUS_INVALID_ACL)
        );
        assert_eq!(source, before);
    }
    let mut bad_owner = valid.clone();
    let owner = u32::from_le_bytes(valid[4..8].try_into().unwrap()) as usize;
    bad_owner[owner] = 2;
    assert_eq!(
        prepare_device_parameters_security(&bad_owner),
        Err(crate::STATUS_INVALID_SID)
    );
    assert!(prepare_device_parameters_security(&valid[..19]).is_err());
}

#[test]
fn output_acl_size_is_bounded_after_removing_replaced_aces() {
    // A valid opaque ACE fills almost the entire native ACL. Adding the admin grant cannot fit.
    let mut huge = vec![0x5a; 65524];
    huge[..4].copy_from_slice(&[42, 0, 0xf4, 0xff]);
    let source = descriptor(Some(&acl(&[huge], 0)), true);
    assert_eq!(
        prepare_device_parameters_security(&source),
        Err(STATUS_INVALID_ACL)
    );

    // A similarly full ACL consisting entirely of replaced Admin ACEs needs only 32 output bytes.
    let crowded = vec![ace(0, 0, &ADMINISTRATORS); 2730];
    let result =
        prepare_device_parameters_security(&descriptor(Some(&acl(&crowded, 0)), true)).unwrap();
    assert_eq!(
        parse_self_relative_descriptor(&result)
            .unwrap()
            .dacl
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn resulting_basic_dacl_grants_admin_full_key_access_but_not_an_ordinary_user() {
    let source = descriptor(
        Some(&acl(&[ace(1, 0, &ADMINISTRATORS), ace(0, 0, &SYSTEM)], 0)),
        true,
    );
    let result = prepare_device_parameters_security(&source).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    let native = NativeAcl::from_bytes(parsed.dacl.unwrap()).unwrap();
    let sd = crate::SecurityDescriptor {
        dacl: Some(crate::native_acl_to_access_acl(&native).unwrap()),
        ..Default::default()
    };
    let mapping = crate::GenericMapping {
        generic_read: 0x20019,
        generic_write: 0x20006,
        generic_execute: 0x20019,
        generic_all: KEY_ALL_ACCESS,
    };
    assert!(crate::access_check(
        &sd,
        &crate::AccessToken::admin(123),
        KEY_ALL_ACCESS,
        &mapping,
        crate::ProcessorMode::UserMode
    )
    .granted());
    assert!(!crate::access_check(
        &sd,
        &crate::AccessToken::user(123),
        KEY_ALL_ACCESS,
        &mapping,
        crate::ProcessorMode::UserMode
    )
    .granted());
}
