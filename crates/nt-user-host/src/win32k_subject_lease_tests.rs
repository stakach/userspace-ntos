use super::*;
use crate::ps_bootstrap::{PsBootstrapParts, PsBootstrapState};
use nt_security::AccessToken;
use nt_types::AccessMode;

type Owner = Win32kSubjectOwner<u64, u64>;

fn fixture() -> (PsBootstrapParts, Owner) {
    let mut parts = PsBootstrapState::try_new(0x1000, 0).unwrap().into_parts();
    let pid = parts.pm.create_process("win32k-client", None, None);
    let token = parts.token_store.insert(AccessToken::user(7));
    parts
        .pm
        .replace_process_primary_token(pid, Some(token))
        .unwrap();
    let tid = parts.pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let caller = parts
        .pm
        .capture_native_handle_caller(parts.pm.thread_lifetime(tid).unwrap(), AccessMode::UserMode)
        .unwrap();
    (
        parts,
        Owner {
            route: 11,
            dispatch: 22,
            caller,
        },
    )
}

fn projection() -> Win32kSubjectProjection {
    Win32kSubjectProjection {
        access_state: 0x1000,
        primary_token: 0x2000,
        client_token: 0,
    }
}

#[test]
fn exact_owner_and_projection_are_required_for_resolution_and_release() {
    let (mut parts, owner) = fixture();
    let mut leases = Win32kSubjectLeases::new();
    let id = leases
        .admit(&parts.pm, &mut parts.token_store, owner, Some(projection()))
        .unwrap();
    let primary = parts
        .pm
        .process_primary_token(owner.caller.original_thread().process_id())
        .unwrap();
    assert_eq!(parts.token_store.reference_count(primary), Some(2));

    for wrong in [
        Owner { route: 12, ..owner },
        Owner {
            dispatch: 23,
            ..owner
        },
    ] {
        assert!(leases
            .resolve(&parts.token_store, id, wrong, Some(projection()))
            .is_err());
        assert!(leases
            .release(&mut parts.token_store, id, wrong, Some(projection()))
            .is_err());
    }
    let other_tid = parts
        .pm
        .create_thread(
            owner.caller.original_thread().process_id(),
            0x3000,
            0,
            false,
        )
        .unwrap();
    let other_caller = parts
        .pm
        .capture_native_handle_caller(
            parts.pm.thread_lifetime(other_tid).unwrap(),
            AccessMode::UserMode,
        )
        .unwrap();
    let wrong_caller = Owner {
        caller: other_caller,
        ..owner
    };
    assert!(leases
        .resolve(&parts.token_store, id, wrong_caller, Some(projection()))
        .is_err());
    assert!(leases
        .release(&mut parts.token_store, id, wrong_caller, Some(projection()))
        .is_err());
    let wrong_projection = Win32kSubjectProjection {
        primary_token: 0x3000,
        ..projection()
    };
    assert!(leases
        .resolve(&parts.token_store, id, owner, Some(wrong_projection))
        .is_err());
    assert!(leases
        .release(&mut parts.token_store, id, owner, Some(wrong_projection))
        .is_err());
    assert!(leases.resolve(&parts.token_store, id, owner, None).is_err());
    assert_eq!(parts.token_store.reference_count(primary), Some(2));
    leases
        .release(&mut parts.token_store, id, owner, Some(projection()))
        .unwrap();
    assert_eq!(parts.token_store.reference_count(primary), Some(1));
}

#[test]
fn token_reassignment_does_not_change_retained_subject() {
    let (mut parts, owner) = fixture();
    let mut leases = Win32kSubjectLeases::new();
    let id = leases
        .admit(&parts.pm, &mut parts.token_store, owner, None)
        .unwrap();
    let pid = owner.caller.original_thread().process_id();
    let old = parts.pm.process_primary_token(pid).unwrap();
    let replacement = parts.token_store.insert(AccessToken::system());
    parts
        .pm
        .replace_process_primary_token(pid, Some(replacement))
        .unwrap();
    parts.token_store.release(old).unwrap();
    assert_eq!(
        leases
            .resolve(&parts.token_store, id, owner, None)
            .unwrap()
            .primary
            .user,
        AccessToken::user(7).user
    );
    leases
        .release(&mut parts.token_store, id, owner, None)
        .unwrap();
    assert!(parts.token_store.get(old).is_none());
}

#[test]
fn nested_jobs_have_distinct_ids_and_independent_retained_references() {
    let (mut parts, owner) = fixture();
    let mut leases = Win32kSubjectLeases::new();
    let primary = parts
        .pm
        .process_primary_token(owner.caller.original_thread().process_id())
        .unwrap();
    let outer = leases
        .admit(&parts.pm, &mut parts.token_store, owner, None)
        .unwrap();
    let inner = leases
        .admit(&parts.pm, &mut parts.token_store, owner, None)
        .unwrap();
    assert_ne!(outer, inner);
    assert_eq!(parts.token_store.reference_count(primary), Some(3));
    leases
        .release(&mut parts.token_store, inner, owner, None)
        .unwrap();
    assert_eq!(parts.token_store.reference_count(primary), Some(2));
    assert!(leases
        .resolve(&parts.token_store, outer, owner, None)
        .is_ok());
    let next = leases
        .admit(&parts.pm, &mut parts.token_store, owner, None)
        .unwrap();
    assert_ne!(next, inner);
    assert_eq!(leases.drain_dispatch(&mut parts.token_store, 11, 22), Ok(2));
    assert_eq!(parts.token_store.reference_count(primary), Some(1));
    assert!(leases
        .resolve(&parts.token_store, outer, owner, None)
        .is_err());
}

#[test]
fn foreign_token_store_cannot_resolve_release_or_drain() {
    let (mut parts, owner) = fixture();
    let (mut foreign, _) = fixture();
    let mut leases = Win32kSubjectLeases::new();
    let id = leases
        .admit(&parts.pm, &mut parts.token_store, owner, None)
        .unwrap();
    let primary = parts
        .pm
        .process_primary_token(owner.caller.original_thread().process_id())
        .unwrap();
    assert!(leases
        .resolve(&foreign.token_store, id, owner, None)
        .is_err());
    assert!(leases
        .release(&mut foreign.token_store, id, owner, None)
        .is_err());
    assert!(leases
        .drain_dispatch(&mut foreign.token_store, owner.route, owner.dispatch)
        .is_err());
    assert_eq!(parts.token_store.reference_count(primary), Some(2));
    assert_eq!(leases.drain_dispatch(&mut parts.token_store, 11, 22), Ok(1));
    assert_eq!(parts.token_store.reference_count(primary), Some(1));
}

#[test]
fn terminal_drain_only_releases_its_exact_dispatch() {
    let (mut parts, owner) = fixture();
    let mut leases = Win32kSubjectLeases::new();
    assert!(leases.is_empty());
    let other = Owner {
        dispatch: 23,
        ..owner
    };
    let first = leases
        .admit(&parts.pm, &mut parts.token_store, owner, None)
        .unwrap();
    let second = leases
        .admit(&parts.pm, &mut parts.token_store, other, None)
        .unwrap();
    assert!(!leases.is_empty());
    assert_eq!(leases.drain_dispatch(&mut parts.token_store, 11, 22), Ok(1));
    assert!(leases
        .resolve(&parts.token_store, first, owner, None)
        .is_err());
    assert!(leases
        .resolve(&parts.token_store, second, other, None)
        .is_ok());
    assert_eq!(leases.drain_dispatch(&mut parts.token_store, 11, 22), Ok(0));
    assert_eq!(leases.drain_dispatch(&mut parts.token_store, 11, 23), Ok(1));
    assert!(leases.is_empty());
}
