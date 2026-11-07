use super::*;
use crate::{
    NestedRestoreChain, NestedRestoreResultError as Error, NestedRestoreResultKey,
    NestedRestoreResultPhase as Phase,
};

fn parent(fixture: &mut Fixture, domain: u64) -> NestedRestoreResultKey {
    let (route, dispatch) = fixture.parent(domain);
    let scope = fixture.receiver.suspend_for_nested_execution(
        route, dispatch, &mut fixture.lanes, &fixture.peers, bound,
    ).unwrap();
    let reply = fixture.lanes.binding(dispatch.lane()).unwrap().reply_object;
    NestedRestoreResultKey::new(scope.identity(), reply).unwrap()
}

fn parents() -> (NestedRestoreResultKey, NestedRestoreResultKey) {
    let mut fixture = Fixture::new();
    let inner = parent(&mut fixture, 1);
    let outer = parent(&mut fixture, 2);
    (inner, outer)
}

#[test]
fn two_distinct_parents_restore_inner_then_outer_before_result_handoff() {
    let (inner, outer) = parents();
    assert_ne!(inner.scope().route(), outer.scope().route());
    assert_ne!(inner.parent_reply(), outer.parent_reply());
    let mut chain = NestedRestoreChain::retain(inner, Some(outer), 0x1234_u64).unwrap();
    assert_eq!(chain.begin_outer(outer), Err(Error::InvalidPhase));
    assert_eq!(chain.take(inner, Some(outer)), Err(Error::InvalidPhase));
    chain.begin_inner(inner).unwrap();
    chain.acknowledge_inner(inner).unwrap();
    assert_eq!(chain.take(inner, Some(outer)), Err(Error::InvalidPhase));
    chain.begin_outer(outer).unwrap();
    assert_eq!(chain.take(inner, Some(outer)), Err(Error::InvalidPhase));
    chain.acknowledge_outer(outer).unwrap();
    assert_eq!(chain.take(inner, Some(outer)), Ok(0x1234));
    assert_eq!(chain.take(inner, Some(outer)), Err(Error::InvalidPhase));
}

#[test]
fn certified_no_effect_refusal_retries_exact_inner_and_outer_tickets() {
    let (inner, outer) = parents();
    let wrong_reply = NestedRestoreResultKey::new(inner.scope(), inner.parent_reply() + 9).unwrap();
    let stale_scope = parent(&mut Fixture::new(), 3);
    let mut chain = NestedRestoreChain::retain(inner, Some(outer), 42_u64).unwrap();
    assert_eq!(chain.begin_inner(wrong_reply), Err(Error::InvalidIdentity));
    assert_eq!(chain.begin_inner(stale_scope), Err(Error::InvalidIdentity));
    chain.begin_inner(inner).unwrap();
    assert_eq!(chain.refuse_inner_no_effects(wrong_reply), Err(Error::InvalidIdentity));
    chain.refuse_inner_no_effects(inner).unwrap();
    assert_eq!(chain.inner_phase(), Phase::Retained);
    chain.begin_inner(inner).unwrap();
    chain.acknowledge_inner(inner).unwrap();
    chain.begin_outer(outer).unwrap();
    chain.refuse_outer_no_effects(outer).unwrap();
    assert_eq!(chain.outer_phase(), Some(Phase::Retained));
    chain.begin_outer(outer).unwrap();
    chain.acknowledge_outer(outer).unwrap();
    assert_eq!(chain.take(inner, Some(stale_scope)), Err(Error::InvalidIdentity));
    assert_eq!(chain.take(inner, Some(outer)), Ok(42));
}

#[test]
fn indeterminate_inner_or_outer_restore_quarantines_the_result() {
    let (inner, outer) = parents();
    let mut inner_uncertain = NestedRestoreChain::retain(inner, Some(outer), 10_u64).unwrap();
    inner_uncertain.begin_inner(inner).unwrap();
    inner_uncertain.quarantine_inner(inner).unwrap();
    assert_eq!(inner_uncertain.inner_phase(), Phase::Quarantined);
    assert_eq!(*inner_uncertain.result_ref(inner).unwrap(), 10);
    assert_eq!(inner_uncertain.begin_inner(inner), Err(Error::InvalidPhase));
    assert_eq!(inner_uncertain.begin_outer(outer), Err(Error::InvalidPhase));
    assert_eq!(inner_uncertain.take(inner, Some(outer)), Err(Error::InvalidPhase));

    let mut outer_uncertain = NestedRestoreChain::retain(inner, Some(outer), 20_u64).unwrap();
    outer_uncertain.begin_inner(inner).unwrap();
    outer_uncertain.acknowledge_inner(inner).unwrap();
    outer_uncertain.begin_outer(outer).unwrap();
    outer_uncertain.quarantine_outer(outer).unwrap();
    assert_eq!(outer_uncertain.outer_phase(), Some(Phase::Quarantined));
    assert_eq!(*outer_uncertain.result_ref(inner).unwrap(), 20);
    assert_eq!(outer_uncertain.begin_outer(outer), Err(Error::InvalidPhase));
    assert_eq!(outer_uncertain.take(inner, Some(outer)), Err(Error::InvalidPhase));
}

#[test]
fn only_exact_distinct_physical_parents_can_form_a_chain() {
    let (inner, outer) = parents();
    assert!(matches!(NestedRestoreChain::retain(inner, Some(inner), 1_u64), Err(Error::InvalidIdentity)));
    let duplicate_reply = NestedRestoreResultKey::new(outer.scope(), inner.parent_reply()).unwrap();
    assert!(matches!(NestedRestoreChain::retain(inner, Some(duplicate_reply), 1_u64), Err(Error::InvalidIdentity)));
    let duplicate_route = NestedRestoreResultKey::new(inner.scope(), outer.parent_reply()).unwrap();
    assert!(matches!(NestedRestoreChain::retain(inner, Some(duplicate_route), 1_u64), Err(Error::InvalidIdentity)));
    let mut no_outer = NestedRestoreChain::retain(inner, None, 7_u64).unwrap();
    assert_eq!(no_outer.begin_outer(outer), Err(Error::InvalidIdentity));
    no_outer.begin_inner(inner).unwrap();
    no_outer.acknowledge_inner(inner).unwrap();
    assert_eq!(no_outer.take(inner, Some(outer)), Err(Error::InvalidIdentity));
    assert_eq!(no_outer.take(inner, None), Ok(7));
}
