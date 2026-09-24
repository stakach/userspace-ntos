use super::*;
use crate::AccessToken;

fn domain(id: u64, cookie: u64) -> HostedTokenProjectionDomain {
    HostedTokenProjectionDomain::new(id, cookie).unwrap()
}

#[test]
fn binding_owns_token_reference_until_exact_retirement() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::user(42));
    let mut registry = HostedTokenProjectionRegistry::new();
    let projection = registry.bind(&mut tokens, domain(7, 11), 0x5000, token).unwrap();
    assert_eq!(tokens.reference_count(token), Some(2));
    tokens.release(token).unwrap();
    assert_eq!(tokens.reference_count(token), Some(1));
    assert_eq!(registry.resolve(&tokens, projection).unwrap().session_id, 1);
    assert_eq!(registry.registration(domain(7, 11), 0x5000), Some(projection));

    registry.reference(&tokens, projection).unwrap();
    assert_eq!(registry.retire(&mut tokens, projection), Err(HostedTokenProjectionError::Busy));
    registry.dereference(projection).unwrap();
    registry.retire(&mut tokens, projection).unwrap();
    assert_eq!(tokens.reference_count(token), None);
    assert_eq!(registry.registration(domain(7, 11), 0x5000), None);
}

#[test]
fn same_pointer_in_other_domain_is_distinct_and_cookie_is_checked() {
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::system());
    let client = tokens.insert(AccessToken::user(88));
    let mut registry = HostedTokenProjectionRegistry::new();
    let first = registry.bind(&mut tokens, domain(1, 10), 0x6000, primary).unwrap();
    let second = registry.bind(&mut tokens, domain(2, 20), 0x6000, client).unwrap();
    assert_eq!(registry.registration(domain(1, 10), 0x6000), Some(first));
    assert_eq!(registry.registration(domain(2, 20), 0x6000), Some(second));
    assert_eq!(registry.registration(domain(1, 20), 0x6000), None);
    assert_eq!(registry.bind(&mut tokens, domain(1, 10), 0x6000, client),
        Err(HostedTokenProjectionError::AddressInUse));
    assert_eq!(registry.resolve(&tokens, first).unwrap().token_type,
        crate::TokenType::Primary);
    registry.retire(&mut tokens, first).unwrap();
    assert_eq!(registry.registration(domain(2, 20), 0x6000), Some(second));
    registry.retire(&mut tokens, second).unwrap();
}

#[test]
fn reused_address_cannot_resolve_or_retire_with_stale_generation() {
    let mut tokens = TokenStore::new();
    let first_token = tokens.insert(AccessToken::system());
    let second_token = tokens.insert(AccessToken::user(9));
    let mut registry = HostedTokenProjectionRegistry::new();
    let owner = domain(3, 4);
    let old = registry.bind(&mut tokens, owner, 0x7000, first_token).unwrap();
    registry.retire(&mut tokens, old).unwrap();
    let new = registry.bind(&mut tokens, owner, 0x7000, second_token).unwrap();
    assert_ne!(old.generation(), new.generation());
    assert_eq!(registry.resolve(&tokens, old).err(),
        Some(HostedTokenProjectionError::StaleProjection));
    assert_eq!(registry.retire(&mut tokens, old),
        Err(HostedTokenProjectionError::StaleProjection));
    assert_eq!(registry.registration(owner, 0x7000), Some(new));
    registry.retire(&mut tokens, new).unwrap();
}

#[test]
fn cloned_store_and_exhausted_generation_do_not_authorize_a_projection() {
    let mut tokens = TokenStore::new();
    let token = tokens.insert(AccessToken::system());
    let mut registry = HostedTokenProjectionRegistry::new();
    let projection = registry.bind(&mut tokens, domain(5, 6), 0x8000, token).unwrap();
    let other_store = tokens.clone();
    assert_eq!(registry.resolve(&other_store, projection).err(),
        Some(HostedTokenProjectionError::WrongStore));

    registry.next_generation = u64::MAX;
    let references = tokens.reference_count(token);
    assert_eq!(registry.bind(&mut tokens, domain(5, 6), 0x9000, token),
        Err(HostedTokenProjectionError::InsufficientResources));
    assert_eq!(tokens.reference_count(token), references);
    registry.retire(&mut tokens, projection).unwrap();
}
