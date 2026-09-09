use super::*;
use crate::{ProcessorMode, SecurityDescriptor, KEY_GENERIC_MAPPING, MAXIMUM_ALLOWED};

fn store(
    level: SecurityImpersonationLevel,
) -> (TokenStore, TokenId, TokenId, CapturedSubjectContext) {
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::system());
    let client = tokens.insert(
        AccessToken::user(42)
            .duplicate(
                TokenType::Impersonation,
                SecurityImpersonationLevel::Impersonation,
                false,
            )
            .unwrap(),
    );
    let capture = CapturedSubjectContext::capture(
        &mut tokens,
        primary,
        Some(SubjectClientIdentity {
            token: client,
            level,
        }),
        0,
    )
    .unwrap();
    (tokens, primary, client, capture)
}

#[test]
fn kernel_bypass_precedes_missing_security_low_level_zero_access_and_privilege_checks() {
    let (mut tokens, _, _, mut capture) = store(SecurityImpersonationLevel::Identification);
    let subject = capture.resolve(&tokens).unwrap();
    for (request, expected) in [
        (0, 0),
        (0x0100_0000, 0x0100_0000),
        (MAXIMUM_ALLOWED | 2, 0xf003f),
    ] {
        let result = subject.check_access(
            None,
            request,
            &KEY_GENERIC_MAPPING,
            ProcessorMode::KernelMode,
        );
        assert!(result.granted());
        assert_eq!(result.granted_access, expected);
        assert!(result.privileges_used.is_empty());
    }
    capture.release(&mut tokens).unwrap();
}

#[test]
fn missing_security_denial_precedes_low_level_which_precedes_zero_access_denial() {
    let sd = SecurityDescriptor::default();
    for level in [
        SecurityImpersonationLevel::Anonymous,
        SecurityImpersonationLevel::Identification,
    ] {
        let (mut tokens, _, _, mut capture) = store(level);
        let subject = capture.resolve(&tokens).unwrap();
        assert_eq!(
            subject
                .check_access(None, 0, &KEY_GENERIC_MAPPING, ProcessorMode::UserMode)
                .status,
            crate::STATUS_ACCESS_DENIED
        );
        for access in [0, 2, MAXIMUM_ALLOWED] {
            let result = subject.check_access(
                Some(&sd),
                access,
                &KEY_GENERIC_MAPPING,
                ProcessorMode::UserMode,
            );
            assert_eq!(result.status, STATUS_BAD_IMPERSONATION_LEVEL);
            assert_eq!(result.granted_access, 0);
            assert!(result.privileges_used.is_empty());
        }
        capture.release(&mut tokens).unwrap();
    }
    let (mut tokens, _, _, mut capture) = store(SecurityImpersonationLevel::Impersonation);
    assert_eq!(
        capture
            .resolve(&tokens)
            .unwrap()
            .check_access(Some(&sd), 0, &KEY_GENERIC_MAPPING, ProcessorMode::UserMode)
            .status,
        crate::STATUS_ACCESS_DENIED
    );
    capture.release(&mut tokens).unwrap();
}

#[test]
fn retained_client_not_primary_or_replacement_controls_access_and_privileges() {
    let (mut tokens, primary, client, mut capture) =
        store(SecurityImpersonationLevel::Impersonation);
    tokens.release(primary).unwrap();
    tokens.release(client).unwrap();
    let replacement = tokens.insert(AccessToken::admin(42));
    let subject = capture.resolve(&tokens).unwrap();
    let root = crate::assign_registry_root_security(
        &subject,
        &mut crate::SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let sd = crate::security_descriptor_bytes_for_access(&root).unwrap();
    assert!(subject
        .check_access(
            Some(&sd),
            0x20019,
            &KEY_GENERIC_MAPPING,
            ProcessorMode::UserMode
        )
        .granted());
    for request in [2, 0x0100_0000] {
        assert!(!subject
            .check_access(
                Some(&sd),
                request,
                &KEY_GENERIC_MAPPING,
                ProcessorMode::UserMode
            )
            .granted());
    }
    capture.release(&mut tokens).unwrap();
    assert!(tokens.get(primary).is_none() && tokens.get(client).is_none());
    assert_eq!(tokens.reference_count(replacement), Some(1));
}

#[test]
fn primary_subject_reports_privilege_use_for_caller_audit() {
    let mut tokens = TokenStore::new();
    let mut system = AccessToken::system();
    system
        .privileges
        .iter_mut()
        .find(|privilege| privilege.name == crate::SE_SECURITY)
        .unwrap()
        .enabled = true;
    let primary = tokens.insert(system);
    let mut capture = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let subject = capture.resolve(&tokens).unwrap();
    let result = subject.check_access(
        Some(&SecurityDescriptor::default()),
        0x0100_0000,
        &KEY_GENERIC_MAPPING,
        ProcessorMode::UserMode,
    );
    assert!(result.granted());
    assert_eq!(result.privileges_used.as_slice(), &[crate::SE_SECURITY]);
    capture.release(&mut tokens).unwrap();
}
