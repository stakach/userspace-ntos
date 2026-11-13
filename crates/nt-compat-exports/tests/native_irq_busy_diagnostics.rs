//! A deferred physical IRQ must identify the exact contention owner before retry policy changes.

const BROKER: &str = include_str!("../../../components/ntos-executive/src/hosted_irq_broker.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn deferred_irq_distinguishes_actual_lock_from_arena_transaction() {
    let dispatch = &BROKER[BROKER.find("pub(super) unsafe fn dispatch_interrupt(").unwrap()..];
    let dispatch = &dispatch[..dispatch.find("unsafe fn dispatch_next_dpc(").unwrap()];
    assert!(dispatch.contains("trace_irq_contention(b\"actual-lock\""));
    assert!(dispatch.contains("trace_irq_contention(b\"arena-transaction\""));
    assert!(dispatch.contains("held_lease(connection.actual_lock)"));
    assert!(dispatch.contains("root_contention_snapshot(lane.identity)"));

    let arena_busy = &dispatch[dispatch.find("Err(nt_hosted_runtime::HostedIrqArenaError::Busy) => {").unwrap()..];
    let arena_busy = &arena_busy[..arena_busy.find("Err(error) => {").unwrap()];
    assert!(
        arena_busy.find("release_hosted_irq_actual_lock_lease(outer_lock)?").unwrap()
            < arena_busy.find("trace_irq_contention(b\"arena-transaction\"").unwrap(),
        "diagnostics must not prolong the actual-lock lease after arena contention"
    );
    assert!(BROKER.contains("attempt-lock="));
    assert!(BROKER.contains("active-arena="));

    let drain = &DRIVER[DRIVER.find("unsafe fn drain_pending_hosted_irqs_snapshot()").unwrap()..];
    let drain = &drain[..drain.find("pub(crate) unsafe fn drain_pending_hosted_irqs()").unwrap()];
    assert!(drain.contains("deferred busy arena event="));
    assert!(drain.contains("HOSTED_IRQ_PENDING_EVENTS.fetch_or(deferred"));
}
