use super::*;
use crate::{AccessToken, SecurityImpersonationLevel, TokenStore, TokenType};

fn identities() -> (SourceCreateSecurityTicket, SourceCreateSecurityKey) {
    (
        SourceCreateSecurityTicket::new(7, 3).unwrap(),
        SourceCreateSecurityKey::new(11, 2, 19, 5, 0x1000).unwrap(),
    )
}

fn tokens() -> (TokenStore, TokenId, TokenId) {
    let mut store = TokenStore::new();
    let primary = store.insert(AccessToken::system());
    let mut client = AccessToken::user(42);
    client.token_type = TokenType::Impersonation;
    client.impersonation_level = SecurityImpersonationLevel::Impersonation;
    let client = store.insert(client);
    (store, primary, client)
}

#[test]
fn source_and_ticket_components_must_be_nonzero() {
    assert!(SourceCreateSecurityTicket::new(0, 1).is_none());
    assert!(SourceCreateSecurityTicket::new(1, 0).is_none());
    for key in [
        SourceCreateSecurityKey::new(0, 2, 19, 5, 0x1000),
        SourceCreateSecurityKey::new(11, 0, 19, 5, 0x1000),
        SourceCreateSecurityKey::new(11, 2, 0, 5, 0x1000),
        SourceCreateSecurityKey::new(11, 2, 19, 0, 0x1000),
        SourceCreateSecurityKey::new(11, 2, 19, 5, 0),
    ] {
        assert!(key.is_none());
    }
}

#[test]
fn wrong_source_or_ticket_cannot_resolve_subject() {
    let (mut store, primary, _) = tokens();
    let (ticket, key) = identities();
    let mut owner =
        SourceCreateSecurityOwner::capture(&mut store, ticket, key, primary, None, 17).unwrap();
    for bad in [
        SourceCreateSecurityKey::new(12, 2, 19, 5, 0x1000).unwrap(),
        SourceCreateSecurityKey::new(11, 3, 19, 5, 0x1000).unwrap(),
        SourceCreateSecurityKey::new(11, 2, 20, 5, 0x1000).unwrap(),
        SourceCreateSecurityKey::new(11, 2, 19, 6, 0x1000).unwrap(),
        SourceCreateSecurityKey::new(11, 2, 19, 5, 0x2000).unwrap(),
    ] {
        assert!(owner.resolve(&store, ticket, bad).is_err());
    }
    assert!(owner
        .resolve(&store, SourceCreateSecurityTicket::new(7, 4).unwrap(), key)
        .is_err());
    assert!(owner
        .resolve(&store, SourceCreateSecurityTicket::new(8, 3).unwrap(), key)
        .is_err());
    assert_eq!(
        owner.resolve(&store, ticket, key).unwrap().process_audit_id,
        17
    );
    owner.mark_terminal();
    owner.release(&mut store).unwrap();
}

#[test]
fn retained_client_wins_over_primary_and_replacement() {
    let (mut store, primary, client) = tokens();
    let (ticket, key) = identities();
    let mut owner = SourceCreateSecurityOwner::capture(
        &mut store,
        ticket,
        key,
        primary,
        Some(SubjectClientIdentity {
            token: client,
            level: SecurityImpersonationLevel::Identification,
        }),
        0,
    )
    .unwrap();
    store.release(client).unwrap();
    let _replacement = store.insert(AccessToken::system());
    let resolved = owner.resolve(&store, ticket, key).unwrap();
    let (effective, level) = resolved.effective_token();
    assert_eq!(effective.user, AccessToken::user(42).user);
    assert_eq!(level, Some(SecurityImpersonationLevel::Identification));
    owner.mark_pending();
    owner.mark_indeterminate();
    assert!(owner.release(&mut store).is_err());
    assert!(store.get(client).is_some());
    owner.mark_terminal();
    owner.release(&mut store).unwrap();
    assert!(store.get(client).is_none());
    assert!(owner.release(&mut store).is_err());
    assert!(owner.resolve(&store, ticket, key).is_err());
}

#[test]
fn retained_primary_survives_process_replacement() {
    let (mut store, primary, _) = tokens();
    let (ticket, key) = identities();
    let mut owner =
        SourceCreateSecurityOwner::capture(&mut store, ticket, key, primary, None, 0).unwrap();
    store.release(primary).unwrap();
    let _replacement = store.insert(AccessToken::user(99));
    let resolved = owner.resolve(&store, ticket, key).unwrap();
    let (effective, level) = resolved.effective_token();
    assert_eq!(effective.user, AccessToken::system().user);
    assert_eq!(level, None);
    owner.mark_terminal();
    owner.release(&mut store).unwrap();
    assert!(store.get(primary).is_none());
}

#[test]
fn another_token_store_cannot_resolve_or_release_owner() {
    let (mut store, primary, _) = tokens();
    let (mut other, _, _) = tokens();
    let (ticket, key) = identities();
    let mut owner =
        SourceCreateSecurityOwner::capture(&mut store, ticket, key, primary, None, 0).unwrap();
    assert!(owner.resolve(&other, ticket, key).is_err());
    owner.mark_terminal();
    assert!(owner.release(&mut other).is_err());
    assert_eq!(owner.phase(), SourceCreateSecurityPhase::Terminal);
    owner.release(&mut store).unwrap();
}
