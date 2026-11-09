//! A queue-owned callback can encounter nested Hook File work that suspends.
//! The outer physical Call must leave the provider stack before root settles that File pump.

use nt_component_suspension::{
    nested_file_work_path, NestedFileWorkPath, RetainedChildDispatch,
    RetainedChildDispatchPhase,
};

#[derive(Debug)]
struct OuterConnectOwners {
    continuation: Box<u64>,
    reply: Box<u64>,
    type3_buffer: Box<[u8; 4]>,
}

#[test]
fn queue_owned_nested_file_requires_flat_root_handoff_before_callback_continues() {
    // The tuple represents the native adapter's exact route, dispatch, Reply and epoch.
    // The two nearby keys must never select this entered invocation.
    let exact = (11_u64, 22_u64, 33_u64, 44_u64);
    let foreign_reply = (11, 22, 34, 44);
    let recycled_epoch = (11, 22, 33, 45);
    let mut outer = RetainedChildDispatch::retain(exact, OuterConnectOwners {
        continuation: Box::new(101),
        reply: Box::new(33),
        type3_buffer: Box::new([1, 2, 3, 4]),
    });
    outer.park_for_child(exact).unwrap();

    // The queue row retains the exact callback, physical Reply and owner before entry.
    // Its copied receive channel can therefore carry child-work authority. A nested
    // Hook File pump must unwind the callback stack for flat-root settlement.
    assert_eq!(
        nested_file_work_path(true, true),
        NestedFileWorkPath::RetainForRoot,
        "nested File suspension must transfer its exact outer owner to flat root",
    );

    assert_eq!(outer.phase(), RetainedChildDispatchPhase::Parked);
    assert!(outer.owners(foreign_reply).is_err());
    assert!(outer.owners(recycled_epoch).is_err());
    let held = outer.owners(exact).unwrap();
    assert_eq!((*held.continuation, *held.reply, *held.type3_buffer),
        (101, 33, [1, 2, 3, 4]));
    let (_, early_terminal) = outer.finish_terminal(exact, Box::new(900)).unwrap_err();

    // Root settles the exact nested File pump and deposits one observed child receipt.
    let (_, wrong_step) = outer.record_child_step(foreign_reply, Box::new(501)).unwrap_err();
    outer.record_child_step(exact, wrong_step).unwrap();
    let (_, duplicate) = outer.record_child_step(exact, Box::new(502)).unwrap_err();
    assert_eq!(*duplicate, 502);
    outer.begin_restore(exact).unwrap();
    assert_eq!(*outer.take_child_step_for_native_restore(exact).unwrap(), 501);
    assert!(outer.take_child_step_for_native_restore(exact).is_err());
    let (_, still_early) = outer.finish_terminal(exact, early_terminal).unwrap_err();
    outer.acknowledge_restore(exact).unwrap();
    let (owners, terminal) = outer.finish_terminal(exact, still_early).unwrap();
    assert_eq!((*owners.continuation, *owners.reply, *owners.type3_buffer),
        (101, 33, [1, 2, 3, 4]));
    assert_eq!(*terminal, 900);
}

#[test]
fn idle_receive_has_no_child_and_unowned_receive_keeps_inline_policy() {
    assert_eq!(nested_file_work_path(false, false), NestedFileWorkPath::NoWork);
    assert_eq!(nested_file_work_path(false, true), NestedFileWorkPath::NoWork);
    assert_eq!(nested_file_work_path(true, true), NestedFileWorkPath::RetainForRoot);
    assert_eq!(nested_file_work_path(true, false), NestedFileWorkPath::Inline);
}
