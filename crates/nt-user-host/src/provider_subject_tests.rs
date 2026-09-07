use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::ps_bootstrap::{PsBootstrapParts, PsBootstrapState};
use nt_process::ImpersonationContext;
use nt_security::{AccessToken, SecurityImpersonationLevel, TokenId, TokenType};

fn fixture() -> (
    PsBootstrapParts,
    ProviderDomainCatalog,
    ProviderDomainIdentity,
    ThreadBinding<()>,
    ProviderLogicalCaller,
) {
    let mut parts = PsBootstrapState::try_new(0x1000, 0).unwrap().into_parts();
    let mut catalog = ProviderDomainCatalog::new();
    let provider = catalog.register().unwrap();
    let pid = parts.pm.create_process("client.exe", None, None);
    let primary = parts.token_store.insert(AccessToken::user(7));
    parts
        .pm
        .replace_process_primary_token(pid, Some(primary))
        .unwrap();
    let tid = parts.pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 2,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(3),
        },
        tid: u64::from(tid),
        badge: 0,
        role: (),
        tcb: 9,
        reservations: None,
    };
    let caller =
        ProviderLogicalCaller::capture(binding, parts.pm.thread_lifetime(tid).unwrap()).unwrap();
    (parts, catalog, provider, binding, caller)
}

fn primary(parts: &PsBootstrapParts, caller: ProviderLogicalCaller) -> TokenId {
    parts
        .pm
        .process_primary_token(caller.process().pid)
        .unwrap()
}

fn prepare(
    registry: &mut ProviderSubjectRegistry,
    parts: &mut PsBootstrapParts,
    catalog: &ProviderDomainCatalog,
    provider: ProviderDomainIdentity,
    binding: ThreadBinding<()>,
    caller: ProviderLogicalCaller,
) -> ProviderSubjectLeaseId {
    registry
        .prepare_hosted(
            provider,
            catalog,
            caller,
            Some(binding),
            &parts.pm,
            &mut parts.token_store,
        )
        .unwrap()
}

#[test]
fn prepared_lease_is_owned_but_not_visible_until_exact_publication() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let token = primary(&parts, caller);
    let mut registry = ProviderSubjectRegistry::new();
    let id = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        provider,
        binding,
        caller,
    );
    assert_eq!(parts.token_store.reference_count(token), Some(2));
    assert_eq!(registry.len(), 1);
    assert!(matches!(
        registry.resolve(provider, &catalog, id, &parts.token_store),
        Err(ProviderSubjectError::WrongPhase)
    ));
    assert_eq!(
        registry.release(provider, &catalog, id, &mut parts.token_store),
        Err(ProviderSubjectError::WrongPhase)
    );
    registry.publish(provider, &catalog, id).unwrap();
    assert_eq!(
        registry
            .resolve(provider, &catalog, id, &parts.token_store)
            .unwrap()
            .primary
            .user,
        AccessToken::user(7).user
    );
    assert_eq!(
        registry.publish(provider, &catalog, id),
        Err(ProviderSubjectError::WrongPhase)
    );
    assert_eq!(
        registry.abort_prepared(provider, &catalog, id, &mut parts.token_store),
        Err(ProviderSubjectError::WrongPhase)
    );
    registry
        .release(provider, &catalog, id, &mut parts.token_store)
        .unwrap();
    assert_eq!(parts.token_store.reference_count(token), Some(1));
    assert!(registry.is_empty());
    assert_eq!(
        registry.release(provider, &catalog, id, &mut parts.token_store),
        Err(ProviderSubjectError::InvalidLease)
    );
}

#[test]
fn output_publication_abort_returns_exact_references() {
    let (mut parts, mut catalog, provider, binding, caller) = fixture();
    let other = catalog.register().unwrap();
    let token = primary(&parts, caller);
    let mut registry = ProviderSubjectRegistry::new();
    let id = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        provider,
        binding,
        caller,
    );
    assert_eq!(
        registry.publish(other, &catalog, id),
        Err(ProviderSubjectError::OwnerMismatch)
    );
    assert_eq!(parts.token_store.reference_count(token), Some(2));
    registry
        .abort_prepared(provider, &catalog, id, &mut parts.token_store)
        .unwrap();
    assert_eq!(parts.token_store.reference_count(token), Some(1));
    assert!(registry.is_empty());
    assert_eq!(
        registry.abort_prepared(provider, &catalog, id, &mut parts.token_store),
        Err(ProviderSubjectError::InvalidLease)
    );
}

#[test]
fn captured_primary_and_lowered_client_survive_replacement_revert_and_process_deletion() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let original_primary = primary(&parts, caller);
    let mut client_token = AccessToken::user(99);
    client_token.token_type = TokenType::Impersonation;
    client_token.impersonation_level = SecurityImpersonationLevel::Delegation;
    let client = parts.token_store.insert(client_token);
    parts
        .pm
        .replace_thread_impersonation(
            caller.thread().thread_id(),
            Some(ImpersonationContext {
                token: client,
                copy_on_open: false,
                effective_only: false,
                level: SecurityImpersonationLevel::Identification,
            }),
        )
        .unwrap();
    let mut registry = ProviderSubjectRegistry::new();
    let id = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        provider,
        binding,
        caller,
    );
    let new_primary = parts.token_store.insert(AccessToken::system());
    let old = parts
        .pm
        .replace_process_primary_token(caller.process().pid, Some(new_primary))
        .unwrap()
        .unwrap();
    assert_eq!(old, original_primary);
    parts.token_store.release(old).unwrap();
    let old_client = parts
        .pm
        .replace_thread_impersonation(caller.thread().thread_id(), None)
        .unwrap()
        .unwrap();
    parts.token_store.release(old_client.token).unwrap();
    parts.pm.terminate_process(caller.process().pid, 0).unwrap();
    let deletion = parts
        .pm
        .delete_process_object_if_unreferenced(caller.process().pid)
        .unwrap();
    parts
        .token_store
        .release(deletion.primary_token.unwrap())
        .unwrap();
    registry.publish(provider, &catalog, id).unwrap();
    let captured = registry
        .resolve(provider, &catalog, id, &parts.token_store)
        .unwrap();
    assert_eq!(captured.primary.user, AccessToken::user(7).user);
    let captured_client = captured.client.as_ref().unwrap();
    assert_eq!(captured_client.token.user, AccessToken::user(99).user);
    assert_eq!(
        captured_client.level,
        SecurityImpersonationLevel::Identification
    );
    assert_eq!(
        captured_client.token.impersonation_level,
        SecurityImpersonationLevel::Delegation
    );
    assert!(!captured.check_privileges(&mut [], true, nt_security::ProcessorMode::KernelMode));
    registry
        .release(provider, &catalog, id, &mut parts.token_store)
        .unwrap();
    assert_eq!(parts.token_store.reference_count(original_primary), None);
    assert_eq!(parts.token_store.reference_count(client), None);
}

#[test]
fn stale_hosted_process_and_thread_lifetimes_are_not_recaptured() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let mut registry = ProviderSubjectRegistry::new();
    let changed = ThreadBinding {
        process: ProcessIdentity {
            generation: ProcessGeneration::Hosted(4),
            ..binding.process
        },
        ..binding
    };
    assert!(matches!(
        registry.prepare_hosted(
            provider,
            &catalog,
            caller,
            Some(changed),
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::Caller(
            ProviderCallerError::BindingChanged
        ))
    ));
    assert!(matches!(
        registry.prepare_hosted::<()>(
            provider,
            &catalog,
            caller,
            None,
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::Caller(
            ProviderCallerError::MissingRuntime
        ))
    ));
    let sibling = parts
        .pm
        .create_thread(caller.process().pid, 0x3000, 0, false)
        .unwrap();
    let tid = caller.thread().thread_id();
    parts.pm.terminate_thread(tid, 0).unwrap();
    let plan = parts
        .pm
        .prepare_thread_activation(tid, 0x4000, 0, false, 0x7000, 0, false)
        .unwrap();
    parts.pm.commit_thread_activation(plan).unwrap();
    assert!(parts.pm.thread(sibling).is_some());
    assert_eq!(
        registry.prepare_hosted(
            provider,
            &catalog,
            caller,
            Some(binding),
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::Caller(
            ProviderCallerError::LifetimeChanged
        ))
    );
    assert!(registry.is_empty());
    assert_eq!(
        parts.token_store.reference_count(primary(&parts, caller)),
        Some(1)
    );
}

#[test]
fn missing_primary_or_bad_client_never_falls_back_to_system() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let mut registry = ProviderSubjectRegistry::new();
    let token = parts
        .pm
        .replace_process_primary_token(caller.process().pid, None)
        .unwrap()
        .unwrap();
    assert_eq!(
        registry.prepare_hosted(
            provider,
            &catalog,
            caller,
            Some(binding),
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::NoToken)
    );
    parts
        .pm
        .replace_process_primary_token(caller.process().pid, Some(token))
        .unwrap();
    parts
        .pm
        .replace_thread_impersonation(
            caller.thread().thread_id(),
            Some(ImpersonationContext {
                token: TokenId::from_raw(u32::MAX).unwrap(),
                copy_on_open: false,
                effective_only: false,
                level: SecurityImpersonationLevel::Anonymous,
            }),
        )
        .unwrap();
    assert!(matches!(
        registry.prepare_hosted(
            provider,
            &catalog,
            caller,
            Some(binding),
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::Security(_))
    ));
    assert_eq!(parts.token_store.reference_count(token), Some(1));
    assert!(registry.is_empty());
}

#[test]
fn initial_system_requires_exact_designation_and_captures_actual_impersonation() {
    let (mut parts, catalog, provider, _, _) = fixture();
    let initial = parts.pm.initial_system_identity().unwrap();
    let foreign = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let foreign_initial = foreign.process_manager().initial_system_identity().unwrap();
    let mut registry = ProviderSubjectRegistry::new();
    assert_eq!(
        registry.prepare_initial_system(
            provider,
            &catalog,
            foreign_initial,
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::InvalidCaller)
    );
    let mut token = AccessToken::user(88);
    token.token_type = TokenType::Impersonation;
    token.impersonation_level = SecurityImpersonationLevel::Impersonation;
    let client = parts.token_store.insert(token);
    parts
        .pm
        .replace_thread_impersonation(
            initial.thread_id(),
            Some(ImpersonationContext {
                token: client,
                copy_on_open: false,
                effective_only: false,
                level: SecurityImpersonationLevel::Anonymous,
            }),
        )
        .unwrap();
    let id = registry
        .prepare_initial_system(
            provider,
            &catalog,
            initial,
            &parts.pm,
            &mut parts.token_store,
        )
        .unwrap();
    registry.publish(provider, &catalog, id).unwrap();
    let subject = registry
        .resolve(provider, &catalog, id, &parts.token_store)
        .unwrap();
    assert_eq!(
        subject.client.as_ref().unwrap().level,
        SecurityImpersonationLevel::Anonymous
    );
    assert_eq!(subject.effective_token().0.user, AccessToken::user(88).user);
    parts.pm.release_initial_system_references(initial).unwrap();
    assert_eq!(
        registry.prepare_initial_system(
            provider,
            &catalog,
            initial,
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::InvalidCaller)
    );
    registry
        .release(provider, &catalog, id, &mut parts.token_store)
        .unwrap();
}

#[test]
fn retired_provider_cannot_request_but_trusted_drain_releases_old_generation_only() {
    let (mut parts, mut catalog, provider, binding, caller) = fixture();
    let token = primary(&parts, caller);
    let mut registry = ProviderSubjectRegistry::new();
    let published = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        provider,
        binding,
        caller,
    );
    registry.publish(provider, &catalog, published).unwrap();
    let _prepared = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        provider,
        binding,
        caller,
    );
    catalog.retire(provider, 0).unwrap();
    let replacement = catalog.register().unwrap();
    assert_eq!(replacement.domain, provider.domain);
    assert_ne!(replacement.generation, provider.generation);
    assert!(matches!(
        registry.resolve(provider, &catalog, published, &parts.token_store),
        Err(ProviderSubjectError::StaleProvider)
    ));
    assert_eq!(
        registry.release(provider, &catalog, published, &mut parts.token_store),
        Err(ProviderSubjectError::StaleProvider)
    );
    assert_eq!(
        registry.release(replacement, &catalog, published, &mut parts.token_store),
        Err(ProviderSubjectError::OwnerMismatch)
    );
    assert_eq!(
        registry.prepare_hosted(
            provider,
            &catalog,
            caller,
            Some(binding),
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::StaleProvider)
    );
    let current = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        replacement,
        binding,
        caller,
    );
    registry.publish(replacement, &catalog, current).unwrap();
    assert_eq!(
        registry.drain_provider(
            provider,
            catalog.identity().unwrap(),
            &mut parts.token_store
        ),
        Ok(2)
    );
    assert_eq!(
        registry.count_for_provider(replacement, catalog.identity().unwrap()),
        1
    );
    assert_eq!(
        registry.count_for_provider(provider, catalog.identity().unwrap()),
        0
    );
    assert_eq!(parts.token_store.reference_count(token), Some(2));
    registry
        .release(replacement, &catalog, current, &mut parts.token_store)
        .unwrap();
}

#[test]
fn wrong_token_store_retains_owner_on_resolve_release_and_rundown_failures() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let mut registry = ProviderSubjectRegistry::new();
    let id = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        provider,
        binding,
        caller,
    );
    registry.publish(provider, &catalog, id).unwrap();
    let token = primary(&parts, caller);
    let mut wrong = parts.token_store.clone();
    assert!(matches!(
        registry.resolve(provider, &catalog, id, &wrong),
        Err(ProviderSubjectError::Security(_))
    ));
    assert!(matches!(
        registry.release(provider, &catalog, id, &mut wrong),
        Err(ProviderSubjectError::Security(_))
    ));
    assert!(matches!(
        registry.drain_provider(provider, catalog.identity().unwrap(), &mut wrong),
        Err(ProviderSubjectError::Security(_))
    ));
    assert_eq!(registry.len(), 1);
    assert_eq!(parts.token_store.reference_count(token), Some(2));
    assert_eq!(
        registry.drain_provider(
            provider,
            catalog.identity().unwrap(),
            &mut parts.token_store
        ),
        Ok(1)
    );
    assert_eq!(parts.token_store.reference_count(token), Some(1));
}

#[test]
fn lease_ids_do_not_alias_across_registries_or_release_and_reuse() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let mut first = ProviderSubjectRegistry::new();
    let mut second = ProviderSubjectRegistry::new();
    let old = prepare(&mut first, &mut parts, &catalog, provider, binding, caller);
    let other = prepare(&mut second, &mut parts, &catalog, provider, binding, caller);
    assert_ne!(old, other);
    assert_eq!(
        second.publish(provider, &catalog, old),
        Err(ProviderSubjectError::InvalidLease)
    );
    first
        .abort_prepared(provider, &catalog, old, &mut parts.token_store)
        .unwrap();
    let new = prepare(&mut first, &mut parts, &catalog, provider, binding, caller);
    assert_ne!(old, new);
    assert_eq!(
        first.publish(provider, &catalog, old),
        Err(ProviderSubjectError::InvalidLease)
    );
    assert_eq!(ProviderSubjectLeaseId::from_raw(new.raw()), Some(new));
    assert_eq!(ProviderSubjectLeaseId::from_raw(0), None);
    first
        .abort_prepared(provider, &catalog, new, &mut parts.token_store)
        .unwrap();
    second
        .abort_prepared(provider, &catalog, other, &mut parts.token_store)
        .unwrap();
}

#[test]
fn storage_limit_and_lease_exhaustion_precede_token_reference_capture() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let token = primary(&parts, caller);
    let mut registry = ProviderSubjectRegistry::with_limit(0);
    assert_eq!(
        registry.prepare_hosted(
            provider,
            &catalog,
            caller,
            Some(binding),
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::Capacity)
    );
    assert_eq!(parts.token_store.reference_count(token), Some(1));
    registry.limit = usize::MAX;
    for value in [0, u64::MAX] {
        let counter = AtomicU64::new(value);
        assert_eq!(
            registry.prepare(
                provider,
                catalog.identity().unwrap(),
                caller.process().pid,
                caller.thread().thread_id(),
                &parts.pm,
                &mut parts.token_store,
                &counter
            ),
            Err(ProviderSubjectError::IdentityExhausted)
        );
        assert_eq!(counter.load(Ordering::Relaxed), value);
        assert_eq!(parts.token_store.reference_count(token), Some(1));
        assert!(registry.is_empty());
    }
}

#[test]
fn replacement_catalog_cannot_resurrect_retired_provider_leases() {
    let (mut parts, mut original, provider, binding, caller) = fixture();
    let mut registry = ProviderSubjectRegistry::new();
    let published = prepare(
        &mut registry,
        &mut parts,
        &original,
        provider,
        binding,
        caller,
    );
    registry.publish(provider, &original, published).unwrap();
    let unpublished = prepare(
        &mut registry,
        &mut parts,
        &original,
        provider,
        binding,
        caller,
    );
    let original_identity = original.identity().unwrap();
    original.retire(provider, 0).unwrap();
    assert_eq!(
        registry.publish(provider, &original, unpublished),
        Err(ProviderSubjectError::StaleProvider)
    );
    let mut replacement = ProviderDomainCatalog::new();
    let replacement_provider = replacement.register().unwrap();
    assert_eq!(provider, replacement_provider);
    assert_ne!(original_identity, replacement.identity().unwrap());
    assert_eq!(
        registry.publish(provider, &replacement, unpublished),
        Err(ProviderSubjectError::CatalogMismatch)
    );
    assert!(matches!(
        registry.resolve(provider, &replacement, published, &parts.token_store),
        Err(ProviderSubjectError::CatalogMismatch)
    ));
    assert_eq!(
        registry.release(provider, &replacement, published, &mut parts.token_store),
        Err(ProviderSubjectError::CatalogMismatch)
    );
    assert_eq!(
        registry.abort_prepared(provider, &replacement, unpublished, &mut parts.token_store),
        Err(ProviderSubjectError::CatalogMismatch)
    );
    let new = prepare(
        &mut registry,
        &mut parts,
        &replacement,
        provider,
        binding,
        caller,
    );
    let moved = alloc::boxed::Box::new(original);
    assert_eq!(moved.identity(), Some(original_identity));
    assert_eq!(
        registry.drain_provider(provider, moved.identity().unwrap(), &mut parts.token_store),
        Ok(2)
    );
    assert_eq!(
        registry.count_for_provider(provider, replacement.identity().unwrap()),
        1
    );
    registry
        .abort_prepared(provider, &replacement, new, &mut parts.token_store)
        .unwrap();
    assert!(registry.is_empty());
}

#[test]
fn moving_live_catalog_preserves_published_lease_authority() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let mut registry = ProviderSubjectRegistry::new();
    let id = prepare(
        &mut registry,
        &mut parts,
        &catalog,
        provider,
        binding,
        caller,
    );
    let moved = alloc::boxed::Box::new(catalog);
    registry.publish(provider, &moved, id).unwrap();
    assert!(registry
        .resolve(provider, &moved, id, &parts.token_store)
        .is_ok());
    registry
        .release(provider, &moved, id, &mut parts.token_store)
        .unwrap();
}

#[test]
fn changed_badge_tcb_and_terminated_thread_do_not_capture_references() {
    let (mut parts, catalog, provider, binding, caller) = fixture();
    let token = primary(&parts, caller);
    let mut registry = ProviderSubjectRegistry::new();
    for changed in [
        ThreadBinding {
            badge: 5,
            ..binding
        },
        ThreadBinding { tcb: 10, ..binding },
    ] {
        assert_eq!(
            registry.prepare_hosted(
                provider,
                &catalog,
                caller,
                Some(changed),
                &parts.pm,
                &mut parts.token_store
            ),
            Err(ProviderSubjectError::Caller(
                ProviderCallerError::BindingChanged
            ))
        );
        assert_eq!(parts.token_store.reference_count(token), Some(1));
    }
    parts
        .pm
        .terminate_thread(caller.thread().thread_id(), 0)
        .unwrap();
    assert!(parts.pm.validate_thread_lifetime(caller.thread()));
    assert_eq!(
        registry.prepare_hosted(
            provider,
            &catalog,
            caller,
            Some(binding),
            &parts.pm,
            &mut parts.token_store
        ),
        Err(ProviderSubjectError::InvalidCaller)
    );
    assert_eq!(parts.token_store.reference_count(token), Some(1));
    assert!(registry.is_empty());
}
