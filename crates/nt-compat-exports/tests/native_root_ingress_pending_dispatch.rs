//! The pending root child is selected only with its exact retained physical parent.

const PENDING: &str = include_str!("../../../components/ntos-executive/src/win32k_pending_dispatch.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const NESTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_nested.rs");

#[test]
fn root_dispatch_take_authenticates_ticket_child_and_held_parent_before_removal() {
    let take = PENDING
        .split_once("unsafe fn take_pending_root_ingress_dispatch(")
        .expect("ticketed root ingress take")
        .1
        .split_once("unsafe fn restore_pending_root_ingress_dispatch(")
        .expect("root ingress restore boundary")
        .0;
    assert!(take.contains("RootIngressYield::ParkedUnbound"));
    assert!(take.contains("prepared_root_ingress_child_is_current"));
    assert!(take.contains("parked_unbound_root_parent"));
    let parent = take.find("parked_unbound_root_parent").unwrap();
    let removed = take.find("core::ptr::replace").expect("one-shot slot transfer");
    assert!(parent < removed);
    assert!(HOSTED.contains("fn prepared_root_ingress_child_is_current("));
    assert!(NESTED.contains("parent.physical.held()"));
}

#[test]
fn rejected_restore_returns_dispatch_and_move_only_parent() {
    let restore = PENDING
        .split_once("unsafe fn restore_pending_root_ingress_dispatch(")
        .expect("root ingress restore")
        .1;
    assert!(restore.contains("Result<(), TakenRootIngressDispatch>"));
    assert!(restore.contains("Err(taken)"));
    assert!(!PENDING.contains("unsafe fn take_pending_root_ingress_dispatch()"));
}
