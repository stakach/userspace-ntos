use super::*;
use crate::{AccessToken, CapturedClientToken, SecurityImpersonationLevel, TokenType};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 0,
    }
}

fn parent(subject: &CapturedSubjectTokens<'_>) -> Vec<u8> {
    crate::assign_registry_root_security(subject, &mut SecurityAssignmentAudit::default()).unwrap()
}

fn empty_dacl() -> Vec<u8> {
    let mut bytes = alloc::vec![1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0];
    bytes.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    bytes
}

#[test]
fn denied_parent_stops_before_creator_assignment_and_handle_privileges() {
    let token = AccessToken::user(123);
    let subject = subject(&token);
    let mut audit = KeyCreationAudit::default();
    assert!(matches!(
        prepare_key_creation_security(
            &subject,
            &parent(&subject),
            Some(&[1]),
            ACCESS_SYSTEM_SECURITY,
            ProcessorMode::UserMode,
            &mut audit
        ),
        Err(crate::STATUS_ACCESS_DENIED)
    ));
    assert!(!audit.parent_access.unwrap().granted());
    assert_eq!(audit.assignment, SecurityAssignmentAudit::default());
    assert_eq!(audit.handle_security, None);
}

#[test]
fn creation_grant_is_not_a_second_open_of_the_child_dacl() {
    let token = AccessToken::admin(123);
    let subject = subject(&token);
    let parent = parent(&subject);
    for (desired, granted) in [
        (0, 0),
        (2, 2),
        (MAXIMUM_ALLOWED | 0x0300 | 0x0010_0000, 0xf003f),
        (0x4000_0000, 0x20006),
    ] {
        let prepared = prepare_key_creation_security(
            &subject,
            &parent,
            Some(&empty_dacl()),
            desired,
            ProcessorMode::UserMode,
            &mut KeyCreationAudit::default(),
        )
        .unwrap();
        assert_eq!(prepared.granted_access, granted);
        let sd = crate::security_descriptor_bytes_for_access(&prepared.descriptor).unwrap();
        assert!(!subject
            .check_access(Some(&sd), 2, &KEY_GENERIC_MAPPING, ProcessorMode::UserMode)
            .granted());
    }
}

#[test]
fn inherited_descriptor_uses_effective_owner_and_parent_acl() {
    let primary = AccessToken::system();
    let parent = parent(&subject(&primary));
    let client = AccessToken::admin(123)
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();
    let subject = CapturedSubjectTokens {
        primary: &primary,
        client: Some(CapturedClientToken {
            token: &client,
            level: SecurityImpersonationLevel::Impersonation,
        }),
        process_audit_id: 0,
    };
    let prepared = prepare_key_creation_security(
        &subject,
        &parent,
        None,
        2,
        ProcessorMode::UserMode,
        &mut KeyCreationAudit::default(),
    )
    .unwrap();
    let sd = crate::security_descriptor_bytes_for_access(&prepared.descriptor).unwrap();
    assert_eq!(sd.owner, Some(client.owner.clone()));
    assert_eq!(
        sd.dacl,
        crate::security_descriptor_bytes_for_access(&parent)
            .unwrap()
            .dacl
    );
}

#[test]
fn handle_security_privilege_outcome_survives_denial_and_is_separate_from_assignment() {
    for enabled in [false, true] {
        let mut token = AccessToken::system();
        token
            .privileges
            .iter_mut()
            .find(|p| p.name == crate::SE_SECURITY)
            .unwrap()
            .enabled = enabled;
        let subject = subject(&token);
        let mut audit = KeyCreationAudit::default();
        let result = prepare_key_creation_security(
            &subject,
            &parent(&subject),
            None,
            ACCESS_SYSTEM_SECURITY,
            ProcessorMode::UserMode,
            &mut audit,
        );
        assert_eq!(result.is_ok(), enabled);
        if !enabled {
            assert!(matches!(result, Err(STATUS_PRIVILEGE_NOT_HELD)));
        }
        assert_eq!(
            audit.handle_security,
            Some(KeyHandleSecurityAudit {
                granted: enabled,
                attributes: if enabled { 0x8000_0000 } else { 0 },
            })
        );
        assert_eq!(audit.assignment, SecurityAssignmentAudit::default());
        assert!(audit.parent_access.unwrap().granted());
    }
}

#[test]
fn kernel_parent_bypass_does_not_bypass_captured_level_for_handle_privileges() {
    let primary = AccessToken::system();
    let client = AccessToken::user(123)
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();
    let subject = CapturedSubjectTokens {
        primary: &primary,
        client: Some(CapturedClientToken {
            token: &client,
            level: SecurityImpersonationLevel::Identification,
        }),
        process_audit_id: 0,
    };
    let parent = parent(&subject);
    let mut audit = KeyCreationAudit::default();
    assert!(prepare_key_creation_security(
        &subject,
        &parent,
        None,
        2,
        ProcessorMode::KernelMode,
        &mut audit
    )
    .is_ok());
    assert!(matches!(
        prepare_key_creation_security(
            &subject,
            &parent,
            None,
            ACCESS_SYSTEM_SECURITY,
            ProcessorMode::KernelMode,
            &mut audit
        ),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    ));
    assert!(audit.parent_access.as_ref().unwrap().granted());
    assert_eq!(
        audit.handle_security,
        Some(KeyHandleSecurityAudit {
            granted: false,
            attributes: 0
        })
    );
    assert!(matches!(
        prepare_key_creation_security(
            &subject,
            &parent,
            None,
            2,
            ProcessorMode::UserMode,
            &mut audit
        ),
        Err(crate::STATUS_BAD_IMPERSONATION_LEVEL)
    ));
    assert_eq!(audit.handle_security, None);
}

#[test]
fn missing_security_and_invalid_creator_never_prepare_a_grant() {
    let token = AccessToken::system();
    let subject = subject(&token);
    let mut audit = KeyCreationAudit::default();
    assert!(prepare_key_creation_security(
        &subject,
        &[],
        None,
        2,
        ProcessorMode::KernelMode,
        &mut audit
    )
    .is_err());
    assert!(audit.parent_access.as_ref().unwrap().granted());
    assert!(prepare_key_creation_security(
        &subject,
        &parent(&subject),
        Some(&[1]),
        2,
        ProcessorMode::UserMode,
        &mut audit
    )
    .is_err());
    assert!(audit.parent_access.unwrap().granted());
    assert_eq!(audit.handle_security, None);
}

#[test]
fn kernel_handle_privilege_bypass_does_not_report_actual_privilege_use() {
    let token = AccessToken::system();
    assert!(!token.has_privilege(crate::SE_SECURITY));
    let subject = subject(&token);
    let mut audit = KeyCreationAudit::default();
    let prepared = prepare_key_creation_security(
        &subject,
        &parent(&subject),
        None,
        ACCESS_SYSTEM_SECURITY,
        ProcessorMode::KernelMode,
        &mut audit,
    )
    .unwrap();
    assert_eq!(prepared.granted_access, ACCESS_SYSTEM_SECURITY);
    assert_eq!(
        audit.handle_security,
        Some(KeyHandleSecurityAudit {
            granted: true,
            attributes: 0
        })
    );
}

#[test]
fn kernel_parent_bypass_allows_assignment_supported_audit_object_aces() {
    let token = AccessToken::system();
    let subject = subject(&token);
    let mut bytes = parent(&subject);
    let offset = bytes.len() as u32;
    bytes[2] |= 0x10;
    bytes[12..16].copy_from_slice(&offset.to_le_bytes());
    // Revision-four ACL containing one container-inheritable SYSTEM_AUDIT_OBJECT_ACE.
    bytes.extend_from_slice(&[4, 0, 32, 0, 1, 0, 0, 0, 7, 0x42, 24, 0]);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    assert!(crate::security_descriptor_bytes_for_access(&bytes).is_err());
    let result = prepare_key_creation_security(
        &subject,
        &bytes,
        None,
        2,
        ProcessorMode::KernelMode,
        &mut KeyCreationAudit::default(),
    )
    .unwrap();
    assert_eq!(result.granted_access, 2);
    let sacl = u32::from_le_bytes(result.descriptor[12..16].try_into().unwrap()) as usize;
    assert_ne!(sacl, 0);
    assert_eq!(result.descriptor[sacl + 8], 7);
}
