use super::super::{parse_self_relative_descriptor, SE_DACL_DEFAULTED, SE_SELF_RELATIVE};
use super::*;
use crate::{AccessToken, NativeAcl, Sid};

fn root(token: &AccessToken) -> Vec<u8> {
    let subject = CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 0,
    };
    let mut audit = SecurityAssignmentAudit::default();
    let bytes = assign_registry_root_security(&subject, &mut audit).unwrap();
    assert_eq!(audit, SecurityAssignmentAudit::default());
    bytes
}

#[test]
fn root_template_is_exact_ordered_nt5_container_policy() {
    let bytes = root_template().unwrap();
    let sd = parse_self_relative_descriptor(&bytes).unwrap();
    assert_eq!(sd.control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
    assert!(sd.owner.is_none() && sd.group.is_none() && sd.sacl.is_none());
    let acl = sd.dacl.unwrap();
    NativeAcl::from_bytes(acl).unwrap();
    assert_eq!(&acl[..8], &[2, 0, 92, 0, 4, 0, 0, 0]);
    let mut offset = 8;
    for (sid, mask) in [
        (Sid::local_system(), 0xf003fu32),
        (Sid::administrators(), 0xf003f),
        (Sid::everyone(), 0x20019),
        (Sid::new(5, &[12]), 0x20019),
    ] {
        let size = u16::from_le_bytes(acl[offset + 2..offset + 4].try_into().unwrap()) as usize;
        assert_eq!(&acl[offset..offset + 2], &[0, 2]);
        assert_eq!(&acl[offset + 4..offset + 8], &mask.to_le_bytes());
        assert_eq!(
            Sid::from_native_bytes(&acl[offset + 8..offset + size]).unwrap(),
            sid
        );
        offset += size;
    }
    assert_eq!(offset, acl.len());
}

#[test]
fn assignment_uses_subject_defaults_but_not_its_default_dacl() {
    for token in [AccessToken::system(), AccessToken::user(321)] {
        let bytes = root(&token);
        let sd = parse_self_relative_descriptor(&bytes).unwrap();
        assert_eq!(
            Sid::from_native_bytes(sd.owner.unwrap()).unwrap(),
            token.owner
        );
        assert_eq!(
            Sid::from_native_bytes(sd.group.unwrap()).unwrap(),
            token.primary_group
        );
        assert_eq!(sd.control & SE_DACL_DEFAULTED, 0);
        let template = root_template().unwrap();
        assert_eq!(
            sd.dacl,
            parse_self_relative_descriptor(&template).unwrap().dacl
        );
    }
}

#[test]
fn root_access_is_read_only_for_users_and_restricted_subjects() {
    let bytes = root(&AccessToken::system());
    let parsed = parse_self_relative_descriptor(&bytes).unwrap();
    let sd = crate::SecurityDescriptor {
        owner: Some(Sid::from_native_bytes(parsed.owner.unwrap()).unwrap()),
        dacl: Some(
            crate::native_acl_to_access_acl(&NativeAcl::from_bytes(parsed.dacl.unwrap()).unwrap())
                .unwrap(),
        ),
        ..Default::default()
    };
    let mut restricted = AccessToken::admin(456);
    restricted
        .restricted_sids
        .push(crate::TokenGroup::enabled(Sid::new(5, &[12])));
    for (token, writable) in [
        (AccessToken::system(), true),
        (AccessToken::admin(123), true),
        (AccessToken::user(123), false),
        (restricted, false),
    ] {
        assert!(crate::access_check(
            &sd,
            &token,
            0x20019,
            &KEY_GENERIC_MAPPING,
            ProcessorMode::UserMode
        )
        .granted());
        assert_eq!(
            crate::access_check(
                &sd,
                &token,
                2,
                &KEY_GENERIC_MAPPING,
                ProcessorMode::UserMode
            )
            .granted(),
            writable
        );
    }
}

#[test]
fn ordinary_container_assignment_propagates_the_root_dacl_without_a_template_reset() {
    let parent = root(&AccessToken::system());
    let token = AccessToken::user(123);
    let mut audit = SecurityAssignmentAudit::default();
    let child = assign_object_security_with_audit(
        &ObjectSecurityAssignment {
            primary: &token,
            client: None,
            creator: None,
            parent: Some(&parent),
            mapping: &KEY_GENERIC_MAPPING,
            is_container: true,
            mode: ProcessorMode::UserMode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        },
        &mut audit,
    )
    .unwrap();
    let parsed = parse_self_relative_descriptor(&child).unwrap();
    assert_eq!(
        Sid::from_native_bytes(parsed.owner.unwrap()).unwrap(),
        token.owner
    );
    assert_eq!(
        parsed.dacl,
        parse_self_relative_descriptor(&parent).unwrap().dacl
    );
    assert_eq!(audit, SecurityAssignmentAudit::default());
}
