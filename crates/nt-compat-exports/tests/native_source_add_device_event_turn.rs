//! A parked AddDevice parent owns the root ingress boundary until exact settlement.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const INGRESS: &str = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");
const RESUME: &str = include_str!("../../../components/ntos-executive/src/component_resume.rs");
const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const PNP: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");

#[test]
fn parked_parent_retains_original_call_and_receives_real_notifications() {
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    let child = root.find("run_one_pending_add_device_child_step(").unwrap();
    let ordinary = root.find("redrive_hosted_driver_io_create_file(").unwrap();
    let exclusive = &root[child..ordinary];
    let hold = exclusive.find("defer_hosted_delivery_for_add_device(").unwrap();
    let arm = exclusive.find("prepare_parked_add_device_receive(&mut root_add_device_turn)").unwrap();
    let receive = exclusive.find("component_recv!(fault_ep").unwrap();
    assert!(hold < arm && arm < receive);
    assert!(exclusive.contains("service_parked_add_device_notification("));
    assert!(exclusive.contains("root_event_consumed"));
    assert!(!exclusive.contains("crate::yield_now()"));
}

#[test]
fn central_receive_defers_unrelated_calls_but_allows_exact_selected_child() {
    let selection = HOSTED.split_once("pub(crate) unsafe fn take_hosted_with(").unwrap().1
        .split_once("oldest_external_ingress(").unwrap().0;
    assert!(selection.contains("root_add_device_exclusive_pending() && !pending_receive"));
    let receive = INGRESS.split_once("pub(crate) unsafe fn receive(").unwrap().1;
    assert!(receive.contains("!crate::service_sec_image::root_add_device_exclusive_pending()"),
        "autonomous ingress must not bypass the parked parent");
    let outer = RESUME.split_once("pub(super) unsafe fn run_outer(").unwrap().1;
    assert!(outer.contains("root_add_device_exclusive_pending()"));
}

#[test]
fn one_shot_retry_is_registered_with_shared_timer_owner() {
    assert!(TIMER.contains("owner.root_add_device, DELAY_TIMER_SOURCE_ROOT_ADD_DEVICE_RETRY"));
    assert!(SERVICE.contains("root_add_device_retry_wake_due"));
    assert!(SERVICE.contains("ROOT_ADD_DEVICE_RETRY_DEADLINE.store(u64::MAX"));
}

#[test]
fn selected_receive_child_may_finish_parent_before_next_root_turn() {
    let no_selected = SERVICE
        .split_once("let Some((reservation, ran_child)) = selected else {").unwrap().1
        .split_once("// Ordinary redrives may reach Ready").unwrap().0;
    assert!(no_selected.contains("root_add_device_still_parked(&nt_handler, turn.owner())"),
        "a selected Receive child can finish AddDevice while the root is servicing its fault");
    assert!(no_selected.contains("turn.settle("),
        "the exact owner must release its retained ingress after that completion");
}

#[test]
fn irq_dispatch_defers_only_a_connection_whose_shared_bank_is_retained() {
    let dispatch = DRIVER
        .split_once("unsafe fn dispatch_hosted_irq_connection(").unwrap().1
        .split_once("enum HostedIrqServiceOutcome").unwrap().0;
    let held = dispatch.find("retained_hosted_irp_bank_conflicts(sh)")
        .expect("IRQ must check both retained shared pages, including suspended owners");
    let projection = dispatch.find("restore_hosted_device_resource_state(binding, sh, false)")
        .unwrap();
    assert!(held < projection,
        "a conflicting IRQ must defer before writing the parked AddDevice bank");
    assert!(dispatch[held..projection].contains("DeferredBusy"),
        "an unrelated IRQ may still dispatch, while the conflicting line is retried later");
    let line = DRIVER
        .split_once("unsafe fn service_hosted_irq_event(").unwrap().1
        .split_once("unsafe fn drain_pending_hosted_irqs_snapshot()").unwrap().0;
    let preflight = line.find("retained_hosted_irq_line_bank_conflict(&leased)")
        .expect("all connections on a shared line must be checked before any ISR runs");
    let first_isr = line.find("while let Some(ready) = scan.next_isr()").unwrap();
    assert!(preflight < first_isr,
        "a later conflicting connection cannot be discovered after an earlier ISR effect");
}

#[test]
fn parked_timer_ack_preserves_other_due_owners_until_bank_release() {
    let notification = SERVICE
        .split_once("unsafe fn service_parked_add_device_notification(").unwrap().1
        .split_once("pub(crate) struct ParkedRootAddDevicePermit").unwrap().0;
    assert!(notification.contains("ack_parked_add_device_retry_timer()"));
    assert!(!notification.contains("delay_timer_interrupt(queue, handler)"),
        "full due drain can write a retained AddDevice shared page");
    let ack = MAIN.split_once("unsafe fn ack_parked_add_device_retry_timer()").unwrap().1
        .split_once("unsafe fn delay_timer_interrupt_claimed(").unwrap().0;
    assert!(ack.contains("root_add_device_retry_wake_due")
        && ack.contains("delay_timer_ack_irq()"));
    assert!(!ack.contains("delay_timer_drain_due_work"),
        "other timer owners must remain queued for a post-parent root turn");
}

#[test]
fn parent_settlement_rearms_deferred_global_due_owners_before_receive() {
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    let resumed = root.split_once("if root_event_consumed {").unwrap().1
        .split_once("// Bound notifications do not bind").unwrap().0;
    let rearm = resumed.find("delay_timer_rearm(&*delay_queue, &nt_handler)")
        .expect("deferred timer owners need a fresh physical shot after AddDevice releases its bank");
    let receive = resumed.find("component_recv!(fault_ep").unwrap();
    assert!(rearm < receive);
}

#[test]
fn retry_deadline_is_published_from_the_exact_move_only_turn() {
    let receive = SERVICE
        .split_once("unsafe fn prepare_parked_add_device_receive(").unwrap().1
        .split_once("unsafe fn service_parked_add_device_notification(").unwrap().0;
    assert!(receive.contains("turn.arm_retry(turn.owner()"),
        "a new physical one-shot must derive from the exact retained parent turn");
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    assert!(root.contains("prepare_parked_add_device_receive(&mut root_add_device_turn)"));
}

#[test]
fn ordinary_pnp_redrive_cannot_retire_the_parked_root_parent() {
    let pending = PNP
        .split_once("if let Some(pending) = self.pending_add_device.as_ref() {").unwrap().1
        .split_once("let pending = self.pending_add_device.take()").unwrap().0;
    assert!(pending.contains("if !flat_root_add_device_permit"),
        "only the selected flat root turn may resume or retire a pending AddDevice parent");
}

#[test]
fn irq_line_preflight_quarantines_uncertain_lease_release() {
    let deferred = DRIVER
        .split_once("unsafe fn defer_hosted_irq_line_delivery(").unwrap().1
        .split_once("unsafe fn complete_hosted_irq_connection_leases(").unwrap().0;
    assert!(deferred.contains("complete_hosted_irq_connection_leases(leased)"));
    assert!(deferred.contains("quarantine_hosted_irq_delivery("),
        "failed lease release must mask and quarantine the line before returning");
}

#[test]
fn exact_ingress_is_prevalidated_before_move_only_turn_is_consumed() {
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    let first_settle = root.find("turn.settle(").unwrap();
    let first_validate = root.find("deferred_add_device_ingress_is_exact(ticket)").unwrap();
    assert!(first_validate < first_settle,
        "a failed exact physical Reply check must leave the whole turn retained");
    let second_settle = root[first_settle + 1..].find("turn.settle(").unwrap() + first_settle + 1;
    let second_validate = root[first_validate + 1..]
        .find("deferred_add_device_ingress_is_exact(ticket)").unwrap() + first_validate + 1;
    assert!(second_validate < second_settle,
        "both root completion paths must retain the turn on validation refusal");
}
