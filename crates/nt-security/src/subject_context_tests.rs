use super::*;

fn store() -> (TokenStore, TokenId, TokenId) {
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::system());
    let mut user = AccessToken::user(42);
    user.token_type = TokenType::Impersonation;
    user.impersonation_level = SecurityImpersonationLevel::Impersonation;
    let client = tokens.insert(user);
    (tokens, primary, client)
}

fn client(token: TokenId) -> SubjectClientIdentity {
    SubjectClientIdentity {
        token,
        level: SecurityImpersonationLevel::Identification,
    }
}

#[test]
fn subject_privilege_level_guard_precedes_kernel_and_empty_set_bypasses() {
    use crate::{Luid, PrivilegeAdjustment, ProcessorMode};
    for level in [
        SecurityImpersonationLevel::Anonymous,
        SecurityImpersonationLevel::Identification,
    ] {
        let (mut tokens, primary, token) = store();
        let mut context = CapturedSubjectContext::capture(
            &mut tokens,
            primary,
            Some(SubjectClientIdentity { token, level }),
            0,
        )
        .unwrap();
        let subject = context.resolve(&tokens).unwrap();
        for mode in [ProcessorMode::KernelMode, ProcessorMode::UserMode] {
            let mut required = [PrivilegeAdjustment {
                luid: Luid::new(23),
                attributes: 0x40,
            }];
            assert!(!subject.check_privileges(&mut required, true, mode));
            assert_eq!(required[0].attributes, 0x40);
            assert!(!subject.check_privileges(&mut [], true, mode));
        }
        context.release(&mut tokens).unwrap();
    }
}

#[test]
fn subject_privileges_use_retained_client_not_replacement_or_primary() {
    use crate::{Luid, PrivilegeAdjustment, ProcessorMode};
    let (mut tokens, primary, token) = store();
    let mut context = CapturedSubjectContext::capture(
        &mut tokens,
        primary,
        Some(SubjectClientIdentity {
            token,
            level: SecurityImpersonationLevel::Impersonation,
        }),
        0,
    )
    .unwrap();
    tokens.release(token).unwrap();
    let replacement = tokens.insert(AccessToken::system());
    let subject = context.resolve(&tokens).unwrap();
    let mut required = [PrivilegeAdjustment {
        luid: Luid::new(7),
        attributes: 0x40,
    }];
    assert!(tokens
        .get(replacement)
        .unwrap()
        .privileges
        .iter()
        .any(|p| p.luid == required[0].luid && p.enabled));
    assert!(!subject.check_privileges(&mut required, true, ProcessorMode::UserMode));
    assert_eq!(required[0].attributes, 0x40);
    assert!(subject.check_privileges(&mut required, true, ProcessorMode::KernelMode));
    assert_eq!(required[0].attributes, 0x40);
    context.release(&mut tokens).unwrap();
    assert!(tokens.get(token).is_none());
}

#[test]
fn subject_privilege_set_has_no_fixed_eight_entry_limit() {
    use crate::{Luid, PrivilegeAdjustment, ProcessorMode, SE_PRIVILEGE_USED_FOR_ACCESS};
    let (mut tokens, primary, _) = store();
    let mut context = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let subject = context.resolve(&tokens).unwrap();
    let mut required =
        alloc::vec![PrivilegeAdjustment { luid: Luid::new(19), attributes: 0x40 }; 12];
    required[11].luid = Luid::new(23);
    assert!(subject.check_privileges(&mut required, false, ProcessorMode::UserMode));
    assert!(required[..11].iter().all(|entry| entry.attributes == 0x40));
    assert_eq!(required[11].attributes, 0x40 | SE_PRIVILEGE_USED_FOR_ACCESS);
    required[11].luid.high = 1;
    required[11].attributes = 0x40;
    assert!(!subject.check_privileges(&mut required, false, ProcessorMode::UserMode));
    assert!(required.iter().all(|entry| entry.attributes == 0x40));
    context.release(&mut tokens).unwrap();
}

#[test]
fn primary_capture_owns_a_reference_after_process_replacement() {
    let (mut tokens, primary, _) = store();
    let mut subject = CapturedSubjectContext::capture(&mut tokens, primary, None, 77).unwrap();
    assert_eq!(tokens.reference_count(primary), Some(2));
    assert_eq!(tokens.release(primary), Ok(false));
    let resolved = subject.resolve(&tokens).unwrap();
    assert_eq!(resolved.primary.user, AccessToken::system().user);
    assert_eq!(resolved.effective_token().0.user, resolved.primary.user);
    assert_eq!(resolved.effective_token().1, None);
    assert!(resolved.client.is_none());
    assert_eq!(resolved.process_audit_id, 77);
    subject.release(&mut tokens).unwrap();
    assert!(tokens.get(primary).is_none());
}

#[test]
fn captured_client_keeps_its_identity_and_lowered_level() {
    let (mut tokens, primary, token) = store();
    let mut subject =
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(token)), 0).unwrap();
    assert_eq!(tokens.reference_count(primary), Some(2));
    assert_eq!(tokens.reference_count(token), Some(2));
    tokens.release(token).unwrap();
    let replacement = tokens.insert(AccessToken::admin(91));
    let resolved = subject.resolve(&tokens).unwrap();
    assert_eq!(
        resolved.client.as_ref().unwrap().level,
        SecurityImpersonationLevel::Identification
    );
    assert_eq!(
        resolved.effective_token().0.user,
        AccessToken::user(42).user
    );
    assert_eq!(
        resolved.effective_token().1,
        Some(SecurityImpersonationLevel::Identification)
    );
    assert_ne!(
        resolved.effective_token().0.user,
        tokens.get(replacement).unwrap().user
    );
    subject.release(&mut tokens).unwrap();
    assert!(tokens.get(token).is_none());
    assert_eq!(tokens.reference_count(primary), Some(1));
}

#[test]
fn anonymous_client_does_not_fall_back_to_privileged_primary() {
    let (mut tokens, primary, token) = store();
    let mut subject = CapturedSubjectContext::capture(
        &mut tokens,
        primary,
        Some(SubjectClientIdentity {
            token,
            level: SecurityImpersonationLevel::Anonymous,
        }),
        0,
    )
    .unwrap();
    let resolved = subject.resolve(&tokens).unwrap();
    assert_eq!(
        resolved.client.as_ref().unwrap().level,
        SecurityImpersonationLevel::Anonymous
    );
    assert_eq!(
        resolved.effective_token().0.user,
        AccessToken::user(42).user
    );
    assert_eq!(
        resolved.effective_token().1,
        Some(SecurityImpersonationLevel::Anonymous)
    );
    subject.release(&mut tokens).unwrap();
}

#[test]
fn cannot_escalate_captured_level_above_token_level() {
    let (mut tokens, primary, token) = store();
    let result = CapturedSubjectContext::capture(
        &mut tokens,
        primary,
        Some(SubjectClientIdentity {
            token,
            level: SecurityImpersonationLevel::Delegation,
        }),
        0,
    );
    assert_eq!(result.unwrap_err(), STATUS_BAD_IMPERSONATION_LEVEL);
    assert_eq!(tokens.reference_count(primary), Some(1));
    assert_eq!(tokens.reference_count(token), Some(1));
}

#[test]
fn invalid_primary_or_client_leaves_both_counts_unchanged() {
    let (mut tokens, primary, token) = store();
    let missing = TokenId::from_raw(99).unwrap();
    assert_eq!(
        CapturedSubjectContext::capture(&mut tokens, missing, Some(client(token)), 0).unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    assert_eq!(
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(missing)), 0)
            .unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    assert_eq!(tokens.reference_count(primary), Some(1));
    assert_eq!(tokens.reference_count(token), Some(1));
}

#[test]
fn token_roles_are_validated_before_reference_changes() {
    let (mut tokens, primary, token) = store();
    assert_eq!(
        CapturedSubjectContext::capture(&mut tokens, token, None, 0).unwrap_err(),
        STATUS_BAD_TOKEN_TYPE
    );
    assert_eq!(
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(primary)), 0)
            .unwrap_err(),
        STATUS_BAD_TOKEN_TYPE
    );
    assert_eq!(tokens.reference_count(primary), Some(1));
    assert_eq!(tokens.reference_count(token), Some(1));
}

#[test]
fn each_capture_retains_independently_and_release_cannot_repeat() {
    let (mut tokens, primary, token) = store();
    let mut first =
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(token)), 1).unwrap();
    let mut second =
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(token)), 2).unwrap();
    assert_eq!(tokens.reference_count(token), Some(3));
    first.release(&mut tokens).unwrap();
    assert_eq!(first.release(&mut tokens), Err(STATUS_INVALID_PARAMETER));
    assert!(matches!(
        first.resolve(&tokens),
        Err(STATUS_INVALID_PARAMETER)
    ));
    assert_eq!(tokens.reference_count(token), Some(2));
    assert_eq!(second.resolve(&tokens).unwrap().process_audit_id, 2);
    second.release(&mut tokens).unwrap();
    assert_eq!(tokens.reference_count(token), Some(1));
    assert_eq!(tokens.reference_count(primary), Some(1));
}

#[test]
fn equal_token_indices_in_another_store_are_not_authority() {
    let (mut tokens, primary, token) = store();
    let (mut other, other_primary, other_client) = store();
    assert_eq!(primary, other_primary);
    let mut subject =
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(token)), 0).unwrap();
    let mut other_subject =
        CapturedSubjectContext::capture(&mut other, other_primary, Some(client(other_client)), 0)
            .unwrap();
    assert!(matches!(
        subject.resolve(&other),
        Err(STATUS_INVALID_HANDLE)
    ));
    assert_eq!(subject.release(&mut other), Err(STATUS_INVALID_HANDLE));
    assert_eq!(other.reference_count(other_primary), Some(2));
    subject.release(&mut tokens).unwrap();
    other_subject.release(&mut other).unwrap();
}

#[test]
fn cloned_store_cannot_release_original_subject() {
    let (mut tokens, primary, _) = store();
    let mut subject = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let mut cloned = tokens.clone();
    assert_eq!(subject.release(&mut cloned), Err(STATUS_INVALID_HANDLE));
    let mut clone_subject = CapturedSubjectContext::capture(&mut cloned, primary, None, 0).unwrap();
    assert_eq!(subject.release(&mut cloned), Err(STATUS_INVALID_HANDLE));
    clone_subject.release(&mut cloned).unwrap();
    subject.release(&mut tokens).unwrap();
}

#[test]
fn token_store_can_move_without_invalidating_captured_identity() {
    let (mut tokens, primary, token) = store();
    let mut subject =
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(token)), 0).unwrap();
    let mut moved = alloc::boxed::Box::new(tokens);
    assert!(subject.resolve(&moved).is_ok());
    subject.release(&mut moved).unwrap();
}

#[test]
fn missing_retained_token_is_reported_before_releasing_other_reference() {
    let (mut tokens, primary, token) = store();
    let mut subject =
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(token)), 0).unwrap();
    // Simulate an external ownership violation; release must not compound it.
    tokens.release(token).unwrap();
    tokens.release(token).unwrap();
    assert_eq!(subject.release(&mut tokens), Err(STATUS_INVALID_HANDLE));
    assert_eq!(tokens.reference_count(primary), Some(2));
}

#[test]
fn assignment_uses_captured_subject_after_both_original_owners_release_tokens() {
    use crate::{
        assign_object_security, GenericMapping, ObjectSecurityAssignment, ProcessorMode,
        SecurityAssignmentClient, SecurityAssignmentInheritance, Sid,
    };
    let (mut tokens, primary, token) = store();
    let mut context =
        CapturedSubjectContext::capture(&mut tokens, primary, Some(client(token)), 0).unwrap();
    tokens.release(primary).unwrap();
    tokens.release(token).unwrap();
    let replacement = tokens.insert(AccessToken::system());
    let subject = context.resolve(&tokens).unwrap();
    let mapping = GenericMapping {
        generic_read: 1,
        generic_write: 2,
        generic_execute: 4,
        generic_all: 7,
    };
    let descriptor = assign_object_security(&ObjectSecurityAssignment {
        primary: subject.primary,
        client: subject
            .client
            .as_ref()
            .map(|client| SecurityAssignmentClient {
                token: client.token,
                level: client.level,
            }),
        creator: None,
        parent: None,
        mapping: &mapping,
        is_container: false,
        mode: ProcessorMode::UserMode,
        object_type: None,
        inheritance: SecurityAssignmentInheritance::Legacy,
    })
    .unwrap();
    let offset = u32::from_le_bytes(descriptor[4..8].try_into().unwrap()) as usize;
    let owner_len = 8 + descriptor[offset + 1] as usize * 4;
    let owner = Sid::from_native_bytes(&descriptor[offset..offset + owner_len]).unwrap();
    assert_eq!(owner, AccessToken::user(42).owner);
    assert_ne!(owner, tokens.get(replacement).unwrap().owner);
    context.release(&mut tokens).unwrap();
    assert!(tokens.get(primary).is_none());
    assert!(tokens.get(token).is_none());
    assert_eq!(tokens.reference_count(replacement), Some(1));
}

#[test]
fn assignment_uses_captured_level_for_explicit_owner_authority() {
    use crate::{
        assign_object_security, GenericMapping, ObjectSecurityAssignment, ProcessorMode,
        SecurityAssignmentClient, SecurityAssignmentInheritance,
    };
    let (mut tokens, primary, token) = store();
    let mut context = CapturedSubjectContext::capture(
        &mut tokens,
        primary,
        Some(SubjectClientIdentity {
            token,
            level: SecurityImpersonationLevel::Anonymous,
        }),
        0,
    )
    .unwrap();
    let subject = context.resolve(&tokens).unwrap();
    let owner = crate::AccessToken::user(42).owner;
    let mut descriptor = alloc::vec![0; 20 + owner.native_len().unwrap()];
    descriptor[0] = 1;
    descriptor[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
    descriptor[4..8].copy_from_slice(&20u32.to_le_bytes());
    owner.write_native(&mut descriptor[20..]).unwrap();
    let mapping = GenericMapping {
        generic_read: 1,
        generic_write: 2,
        generic_execute: 4,
        generic_all: 7,
    };
    assert_eq!(
        assign_object_security(&ObjectSecurityAssignment {
            primary: subject.primary,
            client: subject
                .client
                .as_ref()
                .map(|client| SecurityAssignmentClient {
                    token: client.token,
                    level: client.level,
                }),
            creator: Some(&descriptor),
            parent: None,
            mapping: &mapping,
            is_container: false,
            mode: ProcessorMode::UserMode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        }),
        Err(crate::STATUS_INVALID_OWNER)
    );
    context.release(&mut tokens).unwrap();
}
