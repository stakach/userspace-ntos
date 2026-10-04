use nt_security::{
    assign_directory_security, authorize_directory_open, AccessToken, CapturedClientToken,
    CapturedSubjectTokens, ProcessorMode, SecurityAssignmentAudit,
    SecurityAssignmentPrivilegeOutcome, SecurityImpersonationLevel, Sid, TokenType,
    DIRECTORY_GENERIC_MAPPING, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    STATUS_ACCESS_DENIED, STATUS_BAD_IMPERSONATION_LEVEL, STATUS_PRIVILEGE_NOT_HELD,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 31,
    }
}

fn world_descriptor(mask: u32, flags: u8) -> Vec<u8> {
    let world = Sid::everyone();
    let mut sid = vec![0; world.native_len().unwrap()];
    world.write_native(&mut sid).unwrap();
    let ace_size = 8 + sid.len();
    let mut bytes = vec![
        1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
    ];
    bytes.extend_from_slice(&[2, 0]);
    bytes.extend_from_slice(&((8 + ace_size) as u16).to_le_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, flags]);
    bytes.extend_from_slice(&(ace_size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&sid);
    bytes
}

#[test]
fn directory_mapping_matches_nt5_without_synchronize() {
    assert_eq!(DIRECTORY_GENERIC_MAPPING.generic_read, 0x20003);
    assert_eq!(DIRECTORY_GENERIC_MAPPING.generic_write, 0x2000c);
    assert_eq!(DIRECTORY_GENERIC_MAPPING.generic_execute, 0x20003);
    assert_eq!(DIRECTORY_GENERIC_MAPPING.generic_all, 0xf000f);
    let token = AccessToken::user(31);
    let descriptor = assign_directory_security(
        &subject(&token),
        Some(&world_descriptor(GENERIC_ALL, 0)),
        None,
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    for (request, grant) in [
        (GENERIC_READ, 0x20003),
        (GENERIC_WRITE, 0x2000c),
        (GENERIC_EXECUTE, 0x20003),
        (GENERIC_ALL, 0xf000f),
    ] {
        let result = authorize_directory_open(
            &subject(&token),
            &descriptor,
            request,
            ProcessorMode::UserMode,
        )
        .unwrap();
        assert_eq!((result.status, result.granted_access), (0, grant));
    }
}

#[test]
fn actual_directory_descriptor_allows_traverse_but_denies_creation() {
    let token = AccessToken::user(31);
    let mut audit = SecurityAssignmentAudit::default();
    let descriptor = assign_directory_security(
        &subject(&token),
        Some(&world_descriptor(3, 0)),
        None,
        ProcessorMode::UserMode,
        &mut audit,
    )
    .unwrap();
    let reader = AccessToken::user(32);
    let read = authorize_directory_open(&subject(&reader), &descriptor, 3, ProcessorMode::UserMode)
        .unwrap();
    assert_eq!((read.status, read.granted_access), (0, 3));
    for right in [4, 8] {
        let denied = authorize_directory_open(
            &subject(&reader),
            &descriptor,
            right,
            ProcessorMode::UserMode,
        )
        .unwrap();
        assert_eq!(
            (denied.status, denied.granted_access),
            (STATUS_ACCESS_DENIED, 0)
        );
    }
    assert_eq!(audit, SecurityAssignmentAudit::default());
}

#[test]
fn container_inherit_ace_is_applied_to_real_child_directory() {
    let token = AccessToken::user(31);
    let parent = world_descriptor(4, 2);
    let descriptor = assign_directory_security(
        &subject(&token),
        None,
        Some(&parent),
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let parsed = nt_security::security_descriptor_bytes_for_access(&descriptor).unwrap();
    assert_eq!(parsed.owner, Some(token.owner.clone()));
    assert_eq!(parsed.group, Some(token.primary_group.clone()));
    let child_caller = AccessToken::user(32);
    let result = authorize_directory_open(
        &subject(&child_caller),
        &descriptor,
        4,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert_eq!((result.status, result.granted_access), (0, 4));
}

#[test]
fn lowered_captured_client_level_cannot_open_directory() {
    let primary = AccessToken::system();
    let client = AccessToken::user(32)
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
        process_audit_id: 31,
    };
    let descriptor = assign_directory_security(
        &captured,
        Some(&world_descriptor(3, 0)),
        None,
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let result =
        authorize_directory_open(&captured, &descriptor, 3, ProcessorMode::UserMode).unwrap();
    assert_eq!(
        (result.status, result.granted_access),
        (STATUS_BAD_IMPERSONATION_LEVEL, 0)
    );
}

#[test]
fn malformed_descriptor_never_grants_directory_access() {
    let token = AccessToken::user(31);
    let mut audit = SecurityAssignmentAudit::default();
    assert!(assign_directory_security(
        &subject(&token),
        Some(&[1]),
        None,
        ProcessorMode::UserMode,
        &mut audit
    )
    .is_err());
    assert_eq!(audit, SecurityAssignmentAudit::default());
    assert!(authorize_directory_open(&subject(&token), &[1], 4, ProcessorMode::UserMode).is_err());
}

#[test]
fn explicit_sacl_assignment_retains_denied_privilege_audit() {
    let token = AccessToken::user(31);
    let mut creator = world_descriptor(3, 0);
    let sacl = creator.len() as u32;
    creator[2] |= 0x10;
    creator[12..16].copy_from_slice(&sacl.to_le_bytes());
    creator.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    let mut audit = SecurityAssignmentAudit::default();
    assert_eq!(
        assign_directory_security(
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
