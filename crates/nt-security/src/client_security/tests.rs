use super::*;

fn qos(
    tracking_mode: SecurityContextTrackingMode,
    effective_only: bool,
) -> SecurityQualityOfService {
    SecurityQualityOfService {
        impersonation_level: SecurityImpersonationLevel::Impersonation,
        tracking_mode,
        effective_only,
    }
}

fn source(
    token: TokenId,
    level: SecurityImpersonationLevel,
    effective_only: bool,
) -> EffectiveClientTokenSource {
    EffectiveClientTokenSource::Impersonating {
        token,
        level,
        effective_only,
    }
}

#[test]
fn dynamic_context_retains_original_primary_with_independent_server_ownership() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::system());
    let mut context = ClientSecurityContext::create(
        &mut tokens,
        EffectiveClientTokenSource::Primary { token },
        qos(SecurityContextTrackingMode::Dynamic, true),
        false,
    )
    .unwrap();
    assert_eq!(context.token_id(), token);
    assert!(context.directly_access_client_token());
    assert!(context.direct_access_effective_only());
    assert_eq!(
        context.token(&tokens).unwrap().token_type,
        TokenType::Primary
    );
    assert_eq!(tokens.reference_count(token), Some(2));
    let mut server = context.retain_for_impersonation(&mut tokens).unwrap();
    assert!(server.copy_on_open());
    assert!(server.effective_only());
    assert_eq!(server.level(), SecurityImpersonationLevel::Impersonation);
    assert_eq!(tokens.reference_count(token), Some(3));
    context.release(&mut tokens).unwrap();
    assert_eq!(tokens.reference_count(token), Some(2));
    assert!(server.token(&tokens).is_ok());
    assert_eq!(context.release(&mut tokens), Err(STATUS_INVALID_PARAMETER));
    assert!(context.retain_for_impersonation(&mut tokens).is_err());
    tokens.release(token).unwrap();
    server.release(&mut tokens).unwrap();
    assert!(tokens.get(token).is_none());
}

#[test]
fn static_context_duplicates_all_attributes_and_uses_qos_effective_only() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::system());
    let original = tokens.get(token).unwrap().clone();
    let mut context = ClientSecurityContext::create(
        &mut tokens,
        source(token, SecurityImpersonationLevel::Impersonation, true),
        qos(SecurityContextTrackingMode::Static, false),
        false,
    )
    .unwrap();
    assert_ne!(context.token_id(), token);
    assert_eq!(tokens.reference_count(token), Some(1));
    assert!(!context.directly_access_client_token());
    assert!(context.direct_access_effective_only());
    let duplicated = context.token(&tokens).unwrap();
    assert_eq!(duplicated.token_type, TokenType::Impersonation);
    assert_eq!(duplicated.groups, original.groups);
    assert_eq!(duplicated.privileges, original.privileges);
    let mut server = context.retain_for_impersonation(&mut tokens).unwrap();
    assert!(!server.effective_only());
    let duplicate = context.token_id();
    context.release(&mut tokens).unwrap();
    assert!(tokens.get(duplicate).is_some());
    server.release(&mut tokens).unwrap();
    assert!(tokens.get(duplicate).is_none());
    assert!(tokens.get(token).is_some());
}

#[test]
fn effective_only_static_copy_does_not_remove_disabled_privileges() {
    let mut tokens = TokenStore::new();
    let mut value = AccessToken::system();
    assert!(!value.privileges.is_empty());
    value.privileges[0].enabled = false;
    let expected = value.privileges.clone();
    let token = tokens.insert(value);
    let mut context = ClientSecurityContext::create(
        &mut tokens,
        EffectiveClientTokenSource::Primary { token },
        qos(SecurityContextTrackingMode::Static, true),
        false,
    )
    .unwrap();
    assert_eq!(context.token(&tokens).unwrap().privileges, expected);
    let mut server = context.retain_for_impersonation(&mut tokens).unwrap();
    assert!(server.effective_only());
    server.release(&mut tokens).unwrap();
    context.release(&mut tokens).unwrap();
}

#[test]
fn remote_dynamic_control_uses_real_ids_and_is_immutable() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::system());
    let stats = tokens.statistics(token).unwrap();
    let expected = ClientTokenControl {
        token_id: stats.token_id,
        authentication_id: stats.authentication_id,
        modified_id: stats.modified_id,
        source: tokens.source(token).unwrap(),
    };
    let mut context = ClientSecurityContext::create(
        &mut tokens,
        source(token, SecurityImpersonationLevel::Delegation, false),
        qos(SecurityContextTrackingMode::Dynamic, false),
        true,
    )
    .unwrap();
    assert!(context.server_is_remote());
    assert_eq!(context.token_control(), Some(expected));
    tokens.set_session_id(token, 17).unwrap();
    assert_eq!(context.token_control(), Some(expected));
    assert_eq!(context.token(&tokens).unwrap().session_id, 17);
    context.release(&mut tokens).unwrap();
}

#[test]
fn remote_static_and_local_dynamic_do_not_fabricate_control_snapshots() {
    for (mode, remote) in [
        (SecurityContextTrackingMode::Static, true),
        (SecurityContextTrackingMode::Dynamic, false),
    ] {
        let mut tokens = TokenStore::new();
        let token = tokens.insert(AccessToken::system());
        let mut context = ClientSecurityContext::create(
            &mut tokens,
            EffectiveClientTokenSource::Primary { token },
            qos(mode, false),
            remote,
        )
        .unwrap();
        assert_eq!(context.token_control(), None);
        context.release(&mut tokens).unwrap();
    }
}

#[test]
fn thread_role_applies_even_when_underlying_token_is_primary() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::system());
    for level in [
        SecurityImpersonationLevel::Anonymous,
        SecurityImpersonationLevel::Identification,
    ] {
        assert_eq!(
            ClientSecurityContext::create(
                &mut tokens,
                source(token, level, false),
                qos(SecurityContextTrackingMode::Dynamic, false),
                false
            )
            .unwrap_err(),
            STATUS_BAD_IMPERSONATION_LEVEL
        );
    }
    assert_eq!(
        ClientSecurityContext::create(
            &mut tokens,
            source(token, SecurityImpersonationLevel::Impersonation, false),
            qos(SecurityContextTrackingMode::Dynamic, false),
            true
        )
        .unwrap_err(),
        STATUS_BAD_IMPERSONATION_LEVEL
    );
    let mut requested = qos(SecurityContextTrackingMode::Dynamic, false);
    requested.impersonation_level = SecurityImpersonationLevel::Delegation;
    assert_eq!(
        ClientSecurityContext::create(
            &mut tokens,
            source(token, SecurityImpersonationLevel::Impersonation, false),
            requested,
            false
        )
        .unwrap_err(),
        STATUS_BAD_IMPERSONATION_LEVEL
    );
    assert_eq!(tokens.reference_count(token), Some(1));
}

#[test]
fn source_role_and_level_cannot_exceed_actual_token_authority() {
    let mut tokens = TokenStore::new();
    let mut value = AccessToken::user(42);
    value.token_type = TokenType::Impersonation;
    value.impersonation_level = SecurityImpersonationLevel::Impersonation;
    let token = tokens.insert(value);
    assert_eq!(
        ClientSecurityContext::create(
            &mut tokens,
            EffectiveClientTokenSource::Primary { token },
            qos(SecurityContextTrackingMode::Static, false),
            false
        )
        .unwrap_err(),
        STATUS_BAD_TOKEN_TYPE
    );
    assert_eq!(
        ClientSecurityContext::create(
            &mut tokens,
            source(token, SecurityImpersonationLevel::Delegation, false),
            qos(SecurityContextTrackingMode::Dynamic, false),
            true
        )
        .unwrap_err(),
        STATUS_BAD_IMPERSONATION_LEVEL
    );
    assert_eq!(tokens.reference_count(token), Some(1));
}

#[test]
fn cloned_store_cannot_resolve_release_or_extend_owned_contexts() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::system());
    let mut context = ClientSecurityContext::create(
        &mut tokens,
        EffectiveClientTokenSource::Primary { token },
        qos(SecurityContextTrackingMode::Dynamic, false),
        false,
    )
    .unwrap();
    let mut server = context.retain_for_impersonation(&mut tokens).unwrap();
    let mut wrong = tokens.clone();
    assert_eq!(context.token(&wrong).unwrap_err(), STATUS_INVALID_HANDLE);
    assert_eq!(context.release(&mut wrong), Err(STATUS_INVALID_HANDLE));
    assert_eq!(
        context.retain_for_impersonation(&mut wrong).unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    assert_eq!(server.release(&mut wrong), Err(STATUS_INVALID_HANDLE));
    assert!(context.is_held());
    assert!(server.is_held());
    assert_eq!(tokens.reference_count(token), Some(3));
    context.release(&mut tokens).unwrap();
    server.release(&mut tokens).unwrap();
}

#[test]
fn dynamic_capture_survives_replacement_and_source_owner_release() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::user(42));
    let mut context = ClientSecurityContext::create(
        &mut tokens,
        EffectiveClientTokenSource::Primary { token },
        qos(SecurityContextTrackingMode::Dynamic, false),
        false,
    )
    .unwrap();
    let replacement = tokens.insert(AccessToken::user(43));
    tokens.release(token).unwrap();
    assert_ne!(context.token_id(), replacement);
    assert_ne!(
        context.token(&tokens).unwrap().user,
        tokens.get(replacement).unwrap().user
    );
    context.release(&mut tokens).unwrap();
    assert!(tokens.get(token).is_none());
}

#[test]
fn local_plan_static_effective_only_uses_qos_not_source_flag() {
    let static_qos = qos(SecurityContextTrackingMode::Static, false);
    let plan = plan_client_impersonation(
        TokenType::Impersonation,
        SecurityImpersonationLevel::Impersonation,
        true,
        static_qos,
    )
    .unwrap();
    assert!(!plan.effective_only);
    assert!(plan.static_tracking);
    let dynamic_qos = qos(SecurityContextTrackingMode::Dynamic, false);
    assert!(
        plan_client_impersonation(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            true,
            dynamic_qos
        )
        .unwrap()
        .effective_only
    );
}
