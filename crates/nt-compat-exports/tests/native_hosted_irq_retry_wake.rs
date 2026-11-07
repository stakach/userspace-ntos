//! A level IRQ deferred behind an actual lock must wake without another device notification.

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const RESUME: &str = include_str!("../../../components/ntos-executive/src/component_resume.rs");
const SCHEDULER: &str = include_str!("../../../components/ntos-executive/src/component_scheduler.rs");

#[test]
fn deferred_level_irq_owns_a_stable_autonomous_retry_deadline() {
    let drain = DRIVER.split("unsafe fn drain_pending_hosted_irqs_snapshot()").nth(1)
        .expect("physical IRQ drain");
    assert!(drain.contains("HOSTED_IRQ_RETRY_WAKE.publish("),
        "an actual-lock refusal must publish a retained retry deadline");
    assert!(drain.contains("HOSTED_IRQ_PENDING_EVENTS.fetch_or(deferred"),
        "the deferred event must keep its exact physical bit");
    assert!(DRIVER.contains("HOSTED_IRQ_RETRY_WAKE.next_deadline(hosted_irq_work_pending())"),
        "deadline collection must read the published deadline, not slide now forward");
    assert!(TIMER.contains("driver_launch::hosted_irq_retry_next_deadline()"),
        "an idle shared PIT still needs the deferred IRQ as an owner");
    let reconcile = RESUME.split("unsafe fn reconcile_runtime(").nth(1)
        .expect("receive-boundary timer reconciliation");
    assert!(reconcile.contains("driver_launch::hosted_irq_retry_next_deadline().is_none()"),
        "the root receive gate must not skip rearm for an IRQ-only dispatch");
    let nested = SCHEDULER.split("pub(crate) unsafe fn service_irq_yield(").nth(1)
        .expect("nested retained-IRP scheduler");
    assert!(nested.contains("arm_hosted_irq_retry_before_nested_receive()"),
        "a nested pump can block before root reconciliation; it must arm the retained retry");
}
