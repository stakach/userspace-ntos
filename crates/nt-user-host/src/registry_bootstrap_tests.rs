use super::*;
use crate::ps_bootstrap::PsBootstrapState;
use nt_security::{AccessToken, SecurityImpersonationLevel, Sid, TokenType};

fn sid_at(bytes: &[u8], field: usize) -> Sid {
    let offset = u32::from_le_bytes(bytes[field..field + 4].try_into().unwrap()) as usize;
    let length = 8 + usize::from(bytes[offset + 1]) * 4;
    Sid::from_native_bytes(&bytes[offset..offset + length]).unwrap()
}

#[test]
fn roots_are_independent_and_capture_leaves_original_token_references_intact() {
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let (pm, tokens) = state.managers_mut();
    let identity = pm.initial_system_identity().unwrap();
    let primary = pm.process_primary_token(identity.process_id()).unwrap();
    let mut roots = prepare_registry_root_security(pm, tokens).unwrap();
    assert_eq!(roots.machine, roots.user);
    assert_eq!(
        sid_at(&roots.machine, 4),
        tokens.get(primary).unwrap().owner
    );
    assert_eq!(
        sid_at(&roots.machine, 8),
        tokens.get(primary).unwrap().primary_group
    );
    assert_eq!(tokens.reference_count(primary), Some(1));
    roots.machine[1] = 1;
    assert_eq!(roots.user[1], 0);
}

#[test]
fn current_primary_not_a_reconstructed_system_token_supplies_defaults() {
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let (pm, tokens) = state.managers_mut();
    let identity = pm.initial_system_identity().unwrap();
    let primary = tokens.insert(AccessToken::user(123));
    let old = pm
        .replace_process_primary_token(identity.process_id(), Some(primary))
        .unwrap()
        .unwrap();
    tokens.release(old).unwrap();
    let roots = prepare_registry_root_security(pm, tokens).unwrap();
    assert_eq!(
        sid_at(&roots.machine, 4),
        tokens.get(primary).unwrap().owner
    );
    assert_ne!(sid_at(&roots.machine, 4), AccessToken::system().owner);
    assert_eq!(tokens.reference_count(primary), Some(1));
}

#[test]
fn captured_impersonation_supplies_defaults_even_at_lowered_level() {
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let (pm, tokens) = state.managers_mut();
    let identity = pm.initial_system_identity().unwrap();
    let token = tokens.insert(
        AccessToken::user(456)
            .duplicate(
                TokenType::Impersonation,
                SecurityImpersonationLevel::Impersonation,
                false,
            )
            .unwrap(),
    );
    pm.replace_thread_impersonation(
        identity.thread_id(),
        Some(nt_process::ImpersonationContext {
            token,
            level: SecurityImpersonationLevel::Identification,
            copy_on_open: false,
            effective_only: false,
        }),
    )
    .unwrap();
    let roots = prepare_registry_root_security(pm, tokens).unwrap();
    assert_eq!(sid_at(&roots.user, 4), tokens.get(token).unwrap().owner);
    assert_eq!(tokens.reference_count(token), Some(1));
}

#[test]
fn missing_or_unretained_bootstrap_authority_cannot_publish_roots() {
    assert!(matches!(
        prepare_registry_root_security(&ProcessManager::new(), &mut TokenStore::new()),
        Err(STATUS_INVALID_HANDLE)
    ));
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let (pm, tokens) = state.managers_mut();
    let identity = pm.initial_system_identity().unwrap();
    pm.release_initial_system_references(identity).unwrap();
    assert!(matches!(
        prepare_registry_root_security(pm, tokens),
        Err(STATUS_INVALID_HANDLE)
    ));
}

#[test]
fn absent_or_wrong_type_primary_fails_without_leaking_capture_references() {
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let (pm, tokens) = state.managers_mut();
    let identity = pm.initial_system_identity().unwrap();
    let old = pm
        .replace_process_primary_token(identity.process_id(), None)
        .unwrap()
        .unwrap();
    tokens.release(old).unwrap();
    assert!(matches!(
        prepare_registry_root_security(pm, tokens),
        Err(STATUS_NO_TOKEN)
    ));
    let token = tokens.insert(
        AccessToken::user(456)
            .duplicate(
                TokenType::Impersonation,
                SecurityImpersonationLevel::Impersonation,
                false,
            )
            .unwrap(),
    );
    pm.replace_process_primary_token(identity.process_id(), Some(token))
        .unwrap();
    assert!(matches!(
        prepare_registry_root_security(pm, tokens),
        Err(0xc000_00a8)
    ));
    assert_eq!(tokens.reference_count(token), Some(1));
}

#[test]
fn assignment_failure_releases_the_successfully_captured_subject() {
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let (pm, tokens) = state.managers_mut();
    let identity = pm.initial_system_identity().unwrap();
    let mut invalid = AccessToken::user(123);
    invalid.owner = Sid::new(5, &[0; 16]);
    let token = tokens.insert(invalid);
    let old = pm
        .replace_process_primary_token(identity.process_id(), Some(token))
        .unwrap()
        .unwrap();
    tokens.release(old).unwrap();
    assert!(prepare_registry_root_security(pm, tokens).is_err());
    assert_eq!(tokens.reference_count(token), Some(1));
}
