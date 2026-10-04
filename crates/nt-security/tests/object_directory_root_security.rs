use nt_security::{
    assign_object_directory_root_security, authorize_directory_open, AccessToken,
    CapturedSubjectTokens, ProcessorMode, SecurityAssignmentAudit, Sid, TokenGroup,
    STATUS_ACCESS_DENIED,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 1,
    }
}

fn root() -> Vec<u8> {
    assign_object_directory_root_security(
        &subject(&AccessToken::system()),
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap()
}

#[test]
fn bootstrap_root_uses_actual_noninheritable_public_unrestricted_dacl() {
    let descriptor = root();
    let parsed = nt_security::security_descriptor_bytes_for_access(&descriptor).unwrap();
    let acl = parsed.dacl.unwrap();
    let restricted = Sid::from_native_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]).unwrap();
    let system = AccessToken::system();
    assert_eq!(acl.aces.len(), 4);
    assert_eq!(
        acl.aces
            .iter()
            .map(|ace| (&ace.sid, ace.mask))
            .collect::<Vec<_>>(),
        vec![
            (&Sid::everyone(), 0x20003),
            (&system.user, 0xf000f),
            (&Sid::administrators(), 0xf000f),
            (&restricted, 0x20003),
        ]
    );
    let offset = u32::from_le_bytes(descriptor[16..20].try_into().unwrap()) as usize;
    let mut cursor = offset + 8;
    for _ in 0..4 {
        assert_eq!(
            descriptor[cursor + 1],
            0,
            "bootstrap ACE is not inheritable"
        );
        cursor +=
            u16::from_le_bytes(descriptor[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
    }
}

#[test]
fn root_access_world_restricted_and_system_administrator_are_not_null_dacl() {
    let descriptor = root();
    let mut user = AccessToken::user(31);
    let restricted = Sid::from_native_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]).unwrap();
    user.restricted_sids.push(TokenGroup::enabled(restricted));
    for caller in [&AccessToken::user(31), &user] {
        let result =
            authorize_directory_open(&subject(caller), &descriptor, 3, ProcessorMode::UserMode)
                .unwrap();
        assert_eq!((result.status, result.granted_access), (0, 3));
        let denied =
            authorize_directory_open(&subject(caller), &descriptor, 4, ProcessorMode::UserMode)
                .unwrap();
        assert_eq!(
            (denied.status, denied.granted_access),
            (STATUS_ACCESS_DENIED, 0)
        );
    }
    for caller in [&AccessToken::system(), &AccessToken::admin(31)] {
        let result = authorize_directory_open(
            &subject(caller),
            &descriptor,
            0xf000f,
            ProcessorMode::UserMode,
        )
        .unwrap();
        assert_eq!((result.status, result.granted_access), (0, 0xf000f));
    }
}

#[test]
fn bootstrap_owner_group_are_assigned_from_real_subject_without_privilege_use() {
    let token = AccessToken::system();
    let mut audit = SecurityAssignmentAudit::default();
    let descriptor = assign_object_directory_root_security(&subject(&token), &mut audit).unwrap();
    let parsed = nt_security::security_descriptor_bytes_for_access(&descriptor).unwrap();
    assert_eq!(parsed.owner, Some(token.owner));
    assert_eq!(parsed.group, Some(token.primary_group));
    assert_eq!(audit, SecurityAssignmentAudit::default());
}
