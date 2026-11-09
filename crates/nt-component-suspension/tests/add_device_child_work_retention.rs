//! An AddDevice pump can park for a nested CONNECT child without ending its own dispatch.
//! The native adapter must authenticate route, dispatch, Reply, and epoch before each transition.

use nt_component_suspension::RetainedChildDispatch;

#[derive(Debug)]
struct AddDeviceOwners {
    continuation: Box<u64>,
    rollback: Box<u64>,
    registry_identity: Box<u64>,
}

#[test]
fn add_device_retains_its_parent_and_tokens_until_exact_child_restore_and_terminal() {
    // The tuple is the adapter's exact (route, dispatch, Reply, epoch) witness. A numeric
    // slot or a Reply alone cannot select the parked parent after a lane is recycled.
    let key = (11, 22, 33, 44);
    let stale_epoch = (11, 22, 33, 45);
    let foreign_reply = (11, 22, 34, 44);
    let mut owner = RetainedChildDispatch::retain(key, AddDeviceOwners {
        continuation: Box::new(101),
        rollback: Box::new(202),
        registry_identity: Box::new(303),
    });
    owner.park_for_child(key).unwrap();

    // A pending CONNECT is neither AddDevice completion nor permission to reissue its Reply.
    let terminal = Box::new(404);
    let (_, terminal) = owner.finish_terminal(key, terminal).unwrap_err();
    let step = Box::new(505);
    let (_, step) = owner.record_child_step(stale_epoch, step).unwrap_err();
    owner.record_child_step(key, step).unwrap();
    let (_, duplicate) = owner.record_child_step(key, Box::new(606)).unwrap_err();
    assert_eq!(*duplicate, 606, "a second child step must remain with its caller");
    owner.begin_restore(key).unwrap();
    owner.refuse_restore_no_effects(key).unwrap();

    let held = owner.owners(key).unwrap();
    assert_eq!((*held.continuation, *held.rollback, *held.registry_identity), (101, 202, 303));
    assert!(owner.owners_mut(stale_epoch).is_err());
    *owner.owners_mut(key).unwrap().continuation = 111;
    assert!(owner.begin_restore(foreign_reply).is_err());
    let (_, terminal) = owner.finish_terminal(key, terminal).unwrap_err();
    owner.begin_restore(key).unwrap();
    let step = owner.take_child_step_for_native_restore(key).unwrap();
    assert_eq!(*step, 505);
    assert!(owner.take_child_step_for_native_restore(key).is_err(),
        "native may consume this child receipt only once");
    // Native still owns this already-run step on a certified restore refusal. The parent
    // remains retryable, but a second child cannot be selected or run for this attempt.
    owner.refuse_restore_no_effects(key).unwrap();
    assert!(owner.record_child_step(key, Box::new(707)).is_err());
    assert!(owner.repark_after_native_yield(key).is_err());
    owner.begin_restore(key).unwrap();
    let (_, terminal) = owner.finish_terminal(key, terminal).unwrap_err();
    // The native resume can yield another child before a Restored terminal result. This
    // rearms the existing parent directly from Restoring, without falsely acknowledging it.
    owner.repark_after_native_yield(key).unwrap();
    let (_, terminal) = owner.finish_terminal(key, terminal).unwrap_err();
    owner.record_child_step(key, Box::new(808)).unwrap();
    owner.begin_restore(key).unwrap();
    assert_eq!(*owner.take_child_step_for_native_restore(key).unwrap(), 808);
    owner.acknowledge_restore(key).unwrap();

    // A later resumed receive may also yield after a successful physical restore.
    owner.repark_after_native_yield(key).unwrap();
    owner.record_child_step(key, Box::new(909)).unwrap();
    owner.begin_restore(key).unwrap();
    assert_eq!(*owner.take_child_step_for_native_restore(key).unwrap(), 909);
    owner.acknowledge_restore(key).unwrap();

    let (_, terminal) = owner.finish_terminal(stale_epoch, terminal).unwrap_err();
    let (owners, terminal) = owner.finish_terminal(key, terminal).unwrap();
    assert_eq!((*owners.continuation, *owners.rollback, *owners.registry_identity),
        (111, 202, 303));
    assert_eq!(*terminal, 404);
}
