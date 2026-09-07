use super::*;
use nt_security::{CapturedSubjectContext, TokenType};

#[test]
fn creates_real_running_system_objects_without_native_projections() {
    let state = PsBootstrapState::try_new(0x1000, 0x55).unwrap();
    let pm = state.process_manager();
    let identity = pm.initial_system_identity().unwrap();
    let process = pm.process(identity.process_id()).unwrap();
    let thread = pm.thread(identity.thread_id()).unwrap();
    assert_eq!(process.main_thread, Some(identity.thread_id()));
    assert_eq!(thread.process_id, identity.process_id());
    assert!(thread.is_system_thread);
    assert_eq!(thread.start_address, 0x1000);
    assert_eq!(thread.parameter, 0x55);
    assert_eq!(thread.state, ThreadState::Running);
    assert_eq!(thread.teb_base, 0);
    assert_eq!(
        pm.query_process_basic(identity.process_id(), u64::MAX)
            .unwrap()
            .peb_base_address,
        0
    );
    assert_eq!(thread.kernel_thread_object, None);
    assert_eq!(process.kernel_process_object, None);
    assert!(pm.initial_system_references_held());
    let primary = pm.process_primary_token(identity.process_id()).unwrap();
    assert_eq!(state.token_store().reference_count(primary), Some(1));
    let token = state.token_store().get(primary).unwrap();
    assert_eq!(token.token_type, TokenType::Primary);
    assert_eq!(token.user, AccessToken::system().user);
}

#[test]
fn zero_start_is_rejected_before_publishing_an_aggregate() {
    assert!(matches!(
        PsBootstrapState::try_new(0, 0x55),
        Err(STATUS_INVALID_PARAMETER)
    ));
}

#[test]
fn moving_and_consuming_preserve_designation_and_precaptured_token_references() {
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let identity = state.process_manager().initial_system_identity().unwrap();
    let (pm, tokens) = state.managers_mut();
    let primary = pm.process_primary_token(identity.process_id()).unwrap();
    let mut captured =
        CapturedSubjectContext::capture(tokens, primary, None, identity.process_id() as u64)
            .unwrap();
    assert_eq!(tokens.reference_count(primary), Some(2));
    let boxed = alloc::boxed::Box::new(state);
    assert_eq!(
        boxed.process_manager().initial_system_identity(),
        Some(identity)
    );
    assert!(captured.resolve(boxed.token_store()).is_ok());
    let mut parts = (*boxed).into_parts();
    assert_eq!(parts.pm.initial_system_identity(), Some(identity));
    assert!(parts.pm.validate_thread_lifetime(identity.thread()));
    assert_eq!(parts.token_store.reference_count(primary), Some(2));
    assert_eq!(
        captured
            .resolve(&parts.token_store)
            .unwrap()
            .process_audit_id,
        identity.process_id() as u64
    );
    captured.release(&mut parts.token_store).unwrap();
    assert_eq!(parts.token_store.reference_count(primary), Some(1));
}

#[test]
fn seeded_child_and_its_primary_reference_survive_transfer() {
    let mut state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let initial = state.process_manager().initial_system_identity().unwrap();
    let (pm, tokens) = state.managers_mut();
    let child_token = tokens.insert(AccessToken::system());
    let child = pm.create_process("smss.exe", Some(initial.process_id()), None);
    assert_eq!(
        pm.replace_process_primary_token(child, Some(child_token)),
        Ok(None)
    );
    let child_thread = pm.create_thread(child, 0x4000, 0x66, false).unwrap();
    let lifetime = pm.thread_lifetime(child_thread).unwrap();
    let parts = state.into_parts();
    assert_eq!(parts.pm.initial_system_identity(), Some(initial));
    assert_eq!(
        parts.pm.process(child).unwrap().parent,
        Some(initial.process_id())
    );
    assert_eq!(parts.pm.process_primary_token(child), Some(child_token));
    assert_eq!(parts.token_store.reference_count(child_token), Some(1));
    assert!(parts.pm.validate_thread_lifetime(lifetime));
    assert_eq!(parts.pm.thread(child_thread).unwrap().parameter, 0x66);
    assert!(!parts.pm.is_initial_system_process(child));
}

#[test]
fn anonymous_token_pair_retains_two_distinct_subsystem_owned_references() {
    let state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let parts = state.into_parts();
    let ids = parts.anonymous_logon_tokens;
    assert_ne!(ids.with_everyone(), ids.without_everyone());
    for (id, everyone) in [(ids.with_everyone(), true), (ids.without_everyone(), false)] {
        assert_eq!(parts.token_store.reference_count(id), Some(1));
        assert_eq!(
            parts.token_store.get(id),
            Some(&AccessToken::anonymous_logon(everyone))
        );
    }
}

#[test]
fn retained_capture_rejects_a_reconstructed_store_despite_matching_primary_ids() {
    let mut first = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let second = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let first_identity = first.process_manager().initial_system_identity().unwrap();
    let second_identity = second.process_manager().initial_system_identity().unwrap();
    let (pm, tokens) = first.managers_mut();
    let primary = pm
        .process_primary_token(first_identity.process_id())
        .unwrap();
    let mut captured = CapturedSubjectContext::capture(tokens, primary, None, 0).unwrap();
    assert_eq!(
        second
            .process_manager()
            .process_primary_token(second_identity.process_id()),
        Some(primary)
    );
    assert!(captured.resolve(second.token_store()).is_err());
    let mut parts = first.into_parts();
    assert!(captured.resolve(&parts.token_store).is_ok());
    captured.release(&mut parts.token_store).unwrap();
    assert_eq!(parts.token_store.reference_count(primary), Some(1));
}

#[test]
fn primary_reference_is_released_by_normal_process_teardown_after_handoff() {
    let state = PsBootstrapState::try_new(0x1000, 0).unwrap();
    let mut parts = state.into_parts();
    let initial = parts.pm.initial_system_identity().unwrap();
    let primary = parts
        .pm
        .process_primary_token(initial.process_id())
        .unwrap();
    parts.pm.terminate_process(initial.process_id(), 0).unwrap();
    assert!(parts
        .pm
        .delete_process_object_if_unreferenced(initial.process_id())
        .is_none());
    parts.pm.release_initial_system_references(initial).unwrap();
    let deletion = parts
        .pm
        .delete_process_object_if_unreferenced(initial.process_id())
        .unwrap();
    assert_eq!(deletion.primary_token, Some(primary));
    assert_eq!(parts.token_store.release(primary), Ok(true));
    assert_eq!(parts.token_store.get(primary), None);
    assert_eq!(
        parts
            .token_store
            .reference_count(parts.anonymous_logon_tokens.with_everyone()),
        Some(1)
    );
}
