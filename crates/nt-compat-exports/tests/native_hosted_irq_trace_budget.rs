//! A physical IRQ's serial sample budget spans scheduler drain invocations.

#[path = "../../../components/ntos-executive/src/hosted_irq_service_trace.rs"]
mod hosted_irq_service_trace;

use hosted_irq_service_trace::HostedIrqServiceTrace;

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn separate_one_event_drains_share_one_trace_budget() {
    let trace = HostedIrqServiceTrace::new();
    for drain in 1..=20 {
        assert_eq!(trace.record(1), drain <= 16);
        assert_eq!(trace.total(), drain);
    }
    assert!(!trace.record(0), "unclaimed delivery has no detail line");
    assert_eq!(trace.total(), 21, "unclaimed delivery still advances authoritative census");
    assert!(!trace.record(1), "an unclaimed event cannot reset the detail budget");
    assert_eq!(trace.total(), 22);
}

#[test]
fn native_drain_and_census_use_the_same_authoritative_policy() {
    let drain = DRIVER.split("unsafe fn drain_pending_hosted_irqs_snapshot() -> u64 {")
        .nth(1).expect("physical IRQ drain");
    let drain = drain.split("\npub(crate) unsafe fn drain_pending_hosted_irqs()").next()
        .expect("drain boundary");
    assert!(drain.contains("HOSTED_IRQ_SERVICE_TRACE.record(claimed)"));
    assert!(drain.contains("serviced += 1;"), "per-drain progress remains separate");
    let census = DRIVER.split("pub(crate) fn hosted_irq_delivery_census()").nth(1)
        .expect("delivery census").split("\npub(crate) fn hosted_irq_work_pending()").next().unwrap();
    assert!(census.contains("HOSTED_IRQ_SERVICE_TRACE.total()"));
}
