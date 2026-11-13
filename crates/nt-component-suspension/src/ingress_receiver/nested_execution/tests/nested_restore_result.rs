use super::*;
use crate::{NestedRestoreResult, NestedRestoreResultError as Error,
    NestedRestoreResultKey, NestedRestoreResultPhase as Phase};

fn keys() -> (NestedRestoreResultKey, NestedRestoreResultKey, NestedRestoreResultKey) {
    let mut fixture = Fixture::new();
    let (route, dispatch) = fixture.parent(1);
    let scope = fixture.receiver.suspend_for_nested_execution(
        route, dispatch, &mut fixture.lanes, &fixture.peers, bound,
    ).unwrap();
    let reply = fixture.lanes.binding(dispatch.lane()).unwrap().reply_object;
    let exact = NestedRestoreResultKey::new(scope.identity(), reply).unwrap();
    let wrong_reply = NestedRestoreResultKey::new(scope.identity(), reply + 1).unwrap();
    let mut other = Fixture::new();
    let (other_route, other_dispatch) = other.parent(2);
    let other_scope = other.receiver.suspend_for_nested_execution(
        other_route, other_dispatch, &mut other.lanes, &other.peers, bound,
    ).unwrap();
    let wrong_scope = NestedRestoreResultKey::new(other_scope.identity(), reply).unwrap();
    (exact, wrong_reply, wrong_scope)
}

#[test]
fn exact_restore_acknowledgement_releases_result_once() {
    let (key, wrong_reply, wrong_scope) = keys();
    let mut result = NestedRestoreResult::retain(key, 0x1234_u64);
    assert_eq!(result.take(key), Err(Error::InvalidPhase));
    assert_eq!(result.begin_restore(wrong_reply), Err(Error::InvalidIdentity));
    assert_eq!(result.begin_restore(wrong_scope), Err(Error::InvalidIdentity));
    result.begin_restore(key).unwrap();
    assert_eq!(result.take(key), Err(Error::InvalidPhase));
    result.refuse_no_effects(key).unwrap();
    assert_eq!(result.phase(), Phase::Retained);
    assert_eq!(*result.result_ref(key).unwrap(), 0x1234);
    result.begin_restore(key).unwrap();
    assert_eq!(result.acknowledge_restored(wrong_reply), Err(Error::InvalidIdentity));
    result.acknowledge_restored(key).unwrap();
    assert_eq!(result.take(wrong_scope), Err(Error::InvalidIdentity));
    assert_eq!(result.take(key), Ok(0x1234));
    assert_eq!(result.take(key), Err(Error::InvalidPhase));
    assert_eq!(result.phase(), Phase::Consumed);
}

#[test]
fn uncertain_restore_retains_result_without_retry_or_completion() {
    let (key, _, _) = keys();
    let mut result = NestedRestoreResult::retain(key, 0x5678_u64);
    result.begin_restore(key).unwrap();
    result.quarantine(key).unwrap();
    assert_eq!(result.phase(), Phase::Quarantined);
    assert_eq!(*result.result_ref(key).unwrap(), 0x5678);
    assert_eq!(result.begin_restore(key), Err(Error::InvalidPhase));
    assert_eq!(result.refuse_no_effects(key), Err(Error::InvalidPhase));
    assert_eq!(result.acknowledge_restored(key), Err(Error::InvalidPhase));
    assert_eq!(result.take(key), Err(Error::InvalidPhase));
}

#[test]
fn zero_reply_cannot_form_an_exact_restore_result_key() {
    let (key, _, _) = keys();
    assert!(NestedRestoreResultKey::new(key.scope(), 0).is_none());
}
