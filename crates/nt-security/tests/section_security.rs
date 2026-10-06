use nt_security::{
    assign_section_security, authorize_section_open, AccessToken, CapturedClientToken,
    CapturedSubjectTokens, ProcessorMode, SecurityAssignmentAudit,
    SecurityAssignmentPrivilegeOutcome, SecurityImpersonationLevel, Sid, TokenType, GENERIC_ALL,
    GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, SECTION_GENERIC_MAPPING, STATUS_ACCESS_DENIED,
    STATUS_BAD_IMPERSONATION_LEVEL, STATUS_PRIVILEGE_NOT_HELD,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 19,
    }
}

fn world_descriptor(mask: u32) -> Vec<u8> {
    let world = Sid::everyone();
    let mut sid = vec![0; world.native_len().unwrap()];
    world.write_native(&mut sid).unwrap();
    let ace_size = 8 + sid.len();
    let acl_size = 8 + ace_size;
    let mut bytes = vec![
        1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
    ];
    bytes.extend_from_slice(&[2, 0]);
    bytes.extend_from_slice(&(acl_size as u16).to_le_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&(ace_size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&sid);
    bytes
}

#[test]
fn assigned_world_read_descriptor_authorizes_read_not_write() {
    let token = AccessToken::user(19);
    let mut audit = SecurityAssignmentAudit::default();
    let assigned = assign_section_security(
        &subject(&token),
        Some(&world_descriptor(4)),
        None,
        ProcessorMode::UserMode,
        &mut audit,
    )
    .unwrap();
    let parsed = nt_security::security_descriptor_bytes_for_access(&assigned).unwrap();
    assert_eq!(parsed.owner, Some(token.owner.clone()));
    assert_eq!(parsed.group, Some(token.primary_group.clone()));
    let reader = AccessToken::user(20);
    let read =
        authorize_section_open(&subject(&reader), &assigned, 4, ProcessorMode::UserMode).unwrap();
    assert_eq!((read.status, read.granted_access), (0, 4));
    let write =
        authorize_section_open(&subject(&reader), &assigned, 2, ProcessorMode::UserMode).unwrap();
    assert_eq!(
        (write.status, write.granted_access),
        (STATUS_ACCESS_DENIED, 0)
    );
    assert_eq!(audit, SecurityAssignmentAudit::default());
}

#[test]
fn generic_section_rights_use_nt5_mapping_and_actual_grant() {
    assert_eq!(SECTION_GENERIC_MAPPING.generic_read, 0x20005);
    assert_eq!(SECTION_GENERIC_MAPPING.generic_write, 0x20002);
    assert_eq!(SECTION_GENERIC_MAPPING.generic_execute, 0x20008);
    assert_eq!(SECTION_GENERIC_MAPPING.generic_all, 0xf001f);
    let token = AccessToken::user(19);
    let descriptor = assign_section_security(
        &subject(&token),
        Some(&world_descriptor(GENERIC_ALL)),
        None,
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    for (requested, granted) in [
        (GENERIC_READ, 0x20005),
        (GENERIC_WRITE, 0x20002),
        (GENERIC_EXECUTE, 0x20008),
        (GENERIC_ALL, 0xf001f),
    ] {
        let access = authorize_section_open(
            &subject(&token),
            &descriptor,
            requested,
            ProcessorMode::UserMode,
        )
        .unwrap();
        assert_eq!((access.status, access.granted_access), (0, granted));
    }
}

#[test]
fn open_uses_captured_impersonation_level_not_tokens_higher_level() {
    let primary = AccessToken::system();
    let client = AccessToken::user(20)
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();
    let captured = CapturedSubjectTokens {
        primary: &primary,
        client: Some(CapturedClientToken {
            token: &client,
            level: SecurityImpersonationLevel::Identification,
        }),
        process_audit_id: 19,
    };
    let assigned = assign_section_security(
        &captured,
        Some(&world_descriptor(4)),
        None,
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let parsed = nt_security::security_descriptor_bytes_for_access(&assigned).unwrap();
    assert_eq!(parsed.owner, Some(client.owner.clone()));
    let access = authorize_section_open(&captured, &assigned, 4, ProcessorMode::UserMode).unwrap();
    assert_eq!(
        (access.status, access.granted_access),
        (STATUS_BAD_IMPERSONATION_LEVEL, 0)
    );
}

#[test]
fn malformed_descriptor_refuses_assignment_and_open_without_grant() {
    let token = AccessToken::user(19);
    let mut audit = SecurityAssignmentAudit::default();
    assert!(assign_section_security(
        &subject(&token),
        Some(&[1]),
        None,
        ProcessorMode::UserMode,
        &mut audit
    )
    .is_err());
    assert_eq!(audit, SecurityAssignmentAudit::default());
    assert!(authorize_section_open(&subject(&token), &[1], 4, ProcessorMode::UserMode).is_err());
}

#[test]
fn sacl_assignment_reports_actual_denied_privilege() {
    let token = AccessToken::user(19);
    let mut creator = world_descriptor(4);
    let sacl = creator.len() as u32;
    creator[2] |= 0x10;
    creator[12..16].copy_from_slice(&sacl.to_le_bytes());
    creator.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    let mut audit = SecurityAssignmentAudit::default();
    assert_eq!(
        assign_section_security(
            &subject(&token),
            Some(&creator),
            None,
            ProcessorMode::UserMode,
            &mut audit
        ),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
    assert_eq!(
        audit.security,
        Some(SecurityAssignmentPrivilegeOutcome::Denied)
    );
}

#[test]
fn existing_section_maximum_allowed_is_not_the_new_creation_grant() {
    let owner = AccessToken::user(19);
    let descriptor = assign_section_security(
        &subject(&owner),
        Some(&world_descriptor(4)),
        None,
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let reader = AccessToken::user(20);
    let captured = subject(&reader);
    let existing = authorize_section_open(
        &captured,
        &descriptor,
        nt_security::MAXIMUM_ALLOWED,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert_eq!((existing.status, existing.granted_access), (0, 4));

    let created = nt_security::prepare_object_creation_grant(
        &captured,
        nt_security::MAXIMUM_ALLOWED,
        &SECTION_GENERIC_MAPPING,
        ProcessorMode::UserMode,
        &mut None,
    )
    .unwrap();
    assert_eq!(created, SECTION_GENERIC_MAPPING.generic_all);
    let incorrect_reopen =
        authorize_section_open(&captured, &descriptor, created, ProcessorMode::UserMode).unwrap();
    assert_eq!(
        (incorrect_reopen.status, incorrect_reopen.granted_access),
        (STATUS_ACCESS_DENIED, 0)
    );
}
