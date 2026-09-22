use super::*;
use crate::ps_bootstrap::{PsBootstrapParts, PsBootstrapState};
use nt_process::ImpersonationContext;
use nt_security::{AccessToken, SecurityImpersonationLevel, TokenType};

fn fixture(mode: AccessMode) -> (PsBootstrapParts, NativeHandleCaller) {
    let mut parts = PsBootstrapState::try_new(0x1000, 0).unwrap().into_parts();
    let pid = parts.pm.create_process("registry-client", None, None);
    let token = parts.token_store.insert(AccessToken::user(7));
    parts
        .pm
        .replace_process_primary_token(pid, Some(token))
        .unwrap();
    let tid = parts.pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let caller = parts
        .pm
        .capture_native_handle_caller(parts.pm.thread_lifetime(tid).unwrap(), mode)
        .unwrap();
    (parts, caller)
}

#[test]
fn capture_retains_exact_actor_token_and_mode_until_explicit_release() {
    for mode in [AccessMode::UserMode, AccessMode::KernelMode] {
        let (mut parts, caller) = fixture(mode);
        let primary = parts
            .pm
            .process_primary_token(caller.original_thread().process_id())
            .unwrap();
        let mut captured =
            RegistrySubject::capture(&parts.pm, &mut parts.token_store, caller).unwrap();
        assert_eq!(captured.caller(), caller);
        assert_eq!(
            captured.mode(),
            if mode == AccessMode::UserMode {
                ProcessorMode::UserMode
            } else {
                ProcessorMode::KernelMode
            }
        );
        assert_eq!(parts.token_store.reference_count(primary), Some(2));
        assert_eq!(
            captured
                .resolve(&parts.token_store)
                .unwrap()
                .process_audit_id,
            u64::from(caller.original_thread().process_id())
        );
        captured.release(&mut parts.token_store).unwrap();
        assert_eq!(parts.token_store.reference_count(primary), Some(1));
        assert!(captured.resolve(&parts.token_store).is_err());
        assert!(captured.release(&mut parts.token_store).is_err());
    }
}

#[test]
fn reassignment_revert_and_exit_do_not_change_captured_subject() {
    let (mut parts, caller) = fixture(AccessMode::UserMode);
    let actor = caller.original_thread();
    let primary = parts.pm.process_primary_token(actor.process_id()).unwrap();
    let client = parts.token_store.insert(
        AccessToken::user(99)
            .duplicate(
                TokenType::Impersonation,
                SecurityImpersonationLevel::Delegation,
                false,
            )
            .unwrap(),
    );
    parts
        .pm
        .replace_thread_impersonation(
            actor.thread_id(),
            Some(ImpersonationContext {
                token: client,
                copy_on_open: false,
                effective_only: false,
                level: SecurityImpersonationLevel::Identification,
            }),
        )
        .unwrap();
    let mut captured = RegistrySubject::capture(&parts.pm, &mut parts.token_store, caller).unwrap();
    let replacement = parts.token_store.insert(AccessToken::system());
    parts
        .pm
        .replace_process_primary_token(actor.process_id(), Some(replacement))
        .unwrap();
    parts.token_store.release(primary).unwrap();
    parts
        .pm
        .replace_thread_impersonation(actor.thread_id(), None)
        .unwrap();
    parts.token_store.release(client).unwrap();
    parts.pm.terminate_thread(actor.thread_id(), 0).unwrap();
    let subject = captured.resolve(&parts.token_store).unwrap();
    assert_eq!(subject.primary.user, AccessToken::user(7).user);
    let impersonation = subject.client.unwrap();
    assert_eq!(impersonation.token.user, AccessToken::user(99).user);
    assert_eq!(
        impersonation.level,
        SecurityImpersonationLevel::Identification
    );
    assert!(parts
        .pm
        .validate_native_handle_caller(captured.caller())
        .is_err());
    captured.release(&mut parts.token_store).unwrap();
    assert!(parts.token_store.get(primary).is_none());
    assert!(parts.token_store.get(client).is_none());
}

#[test]
fn foreign_or_stale_caller_cannot_retain_tokens() {
    let (mut parts, caller) = fixture(AccessMode::KernelMode);
    let (foreign, _) = fixture(AccessMode::KernelMode);
    let token = parts
        .pm
        .process_primary_token(caller.original_thread().process_id())
        .unwrap();
    assert!(RegistrySubject::capture(&foreign.pm, &mut parts.token_store, caller).is_err());
    assert_eq!(parts.token_store.reference_count(token), Some(1));
    parts
        .pm
        .terminate_thread(caller.original_thread().thread_id(), 0)
        .unwrap();
    assert!(RegistrySubject::capture(&parts.pm, &mut parts.token_store, caller).is_err());
    assert_eq!(parts.token_store.reference_count(token), Some(1));
}

#[test]
fn foreign_store_cannot_resolve_or_release_the_capture() {
    let (mut parts, caller) = fixture(AccessMode::UserMode);
    let (mut foreign, _) = fixture(AccessMode::UserMode);
    let mut captured = RegistrySubject::capture(&parts.pm, &mut parts.token_store, caller).unwrap();
    assert!(captured.resolve(&foreign.token_store).is_err());
    assert!(captured.release(&mut foreign.token_store).is_err());
    captured.release(&mut parts.token_store).unwrap();
}

#[test]
fn missing_primary_token_is_not_an_implicit_system_subject() {
    let (mut parts, caller) = fixture(AccessMode::KernelMode);
    parts
        .pm
        .replace_process_primary_token(caller.original_thread().process_id(), None)
        .unwrap();
    assert!(RegistrySubject::capture(&parts.pm, &mut parts.token_store, caller).is_err());
}
