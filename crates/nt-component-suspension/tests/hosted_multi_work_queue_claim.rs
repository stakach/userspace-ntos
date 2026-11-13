//! Two callbacks from one provider need separate physical owners while one is parked.
//! A queue index, ring position, or numeric Reply alone cannot select a callback.

use nt_component_suspension::{HostedWorkQueueClaims, RetainedChildDispatch};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry { routine: u64, context: u64 }

#[test]
fn newer_same_provider_callback_uses_an_independent_worker_and_keeps_older_claim() {
    // Queue key: provider domain, generation, ring head, work item.
    let older = (11_u64, 31_u64, 101_u64, 501_u64);
    let newer = (11_u64, 31_u64, 102_u64, 502_u64);
    let recycled_generation = (11_u64, 32_u64, 101_u64, 501_u64);
    // Physical worker: route, dispatch, Reply, TCB, request bank.
    let first_worker = (701_u64, 801_u64, 901_u64, 1001_u64, 1101_u64);
    let second_worker = (702_u64, 802_u64, 902_u64, 1002_u64, 1102_u64);
    let stale_reply = (702_u64, 802_u64, 901_u64, 1002_u64, 1102_u64);
    let aliased_bank = (702_u64, 802_u64, 902_u64, 1002_u64, 1101_u64);
    let old_entry = Entry { routine: 2001, context: 3001 };
    let new_entry = Entry { routine: 2002, context: 3002 };
    let mut claims = HostedWorkQueueClaims::new();

    claims.claim(older, first_worker, old_entry).unwrap();
    assert_eq!(claims.enter(older, first_worker), Ok(old_entry));
    assert!(claims.claim(newer, first_worker, new_entry).is_err(),
        "a parked primary worker cannot run another callback");
    assert!(claims.claim(newer, aliased_bank, new_entry).is_err(),
        "a new route with the same request bank is not independent");
    claims.claim(newer, second_worker, new_entry).unwrap();
    assert_eq!(claims.enter(newer, second_worker), Ok(new_entry));
    assert_eq!(claims.entered(older, first_worker), Ok(true));
    assert_eq!(claims.entered(newer, second_worker), Ok(true));
    assert_eq!(claims.retained_entry(older, first_worker), Ok(&old_entry));
    assert_eq!(claims.retained_entry(newer, second_worker), Ok(&new_entry));
    assert!(claims.retained_entry(recycled_generation, first_worker).is_err());
    assert!(claims.acknowledge_return(newer, stale_reply).is_err());
    assert!(claims.acknowledge_return(older, second_worker).is_err());
    // Independent physical workers may return in either order. A queue parent
    // dependency requires its own exact relationship outside this claim table.
    claims.acknowledge_return(older, first_worker).unwrap();
    assert_eq!(claims.retained_entry(newer, second_worker), Ok(&new_entry));
    assert!(claims.acknowledge_return(older, first_worker).is_err(),
        "a callback terminal advances its claim exactly once");
    claims.acknowledge_return(newer, second_worker).unwrap();
    assert!(claims.entered(newer, second_worker).is_err());
}

#[test]
fn each_parked_worker_keeps_a_move_only_child_receipt() {
    let older = (11_u64, 31_u64, 101_u64, 501_u64);
    let newer = (11_u64, 31_u64, 102_u64, 502_u64);
    let first_worker = (701_u64, 801_u64, 901_u64, 1001_u64, 1101_u64);
    let second_worker = (702_u64, 802_u64, 902_u64, 1002_u64, 1102_u64);
    let old_key = (older, first_worker);
    let new_key = (newer, second_worker);
    let mut old_callback = RetainedChildDispatch::retain(old_key, Box::new(41_u64));
    let mut new_callback = RetainedChildDispatch::retain(new_key, Box::new(42_u64));
    old_callback.park_for_child(old_key).unwrap();
    new_callback.park_for_child(new_key).unwrap();

    let (_, wrong_step) = old_callback.record_child_step(new_key, Box::new(51_u64))
        .unwrap_err();
    assert_eq!(*wrong_step, 51);
    new_callback.record_child_step(new_key, wrong_step).unwrap();
    assert!(new_callback.record_child_step(new_key, Box::new(52_u64)).is_err());
    new_callback.begin_restore(new_key).unwrap();
    assert_eq!(*new_callback.take_child_step_for_native_restore(new_key).unwrap(), 51);
    assert!(new_callback.take_child_step_for_native_restore(new_key).is_err());
    assert!(old_callback.take_child_step_for_native_restore(old_key).is_err(),
        "the newer worker's receipt never authorizes the older worker");
    new_callback.acknowledge_restore(new_key).unwrap();
    let (owner, terminal) = new_callback.finish_terminal(new_key, Box::new(61_u64)).unwrap();
    assert_eq!((*owner, *terminal), (42, 61));
    assert_eq!(old_callback.phase(),
        nt_component_suspension::RetainedChildDispatchPhase::Parked);
}
