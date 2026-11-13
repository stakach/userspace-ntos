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

