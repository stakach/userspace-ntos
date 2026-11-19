//! Every hosted IRQ delivery ends in an acknowledgement or a redrive (boot 44463332736).

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn section<'a>(start: &str, end: &str) -> &'a str {
    let tail = LAUNCH.split(start).nth(1).unwrap_or_else(|| panic!("{start}"));
    tail.split(end).next().unwrap()
}

#[test]
fn an_acknowledged_latched_line_that_claimed_is_rescanned_without_a_new_edge() {
    let ack = section("crate::acknowledge_ioapic_irq_handler_checked(handler_cap)",
        "Ok(HostedIrqServiceOutcome::Serviced(claimed))");
    let confirm = ack.find("confirm_acknowledgement(ack)").expect("acknowledgement confirmed");
    let rescan = ack.find("nt_kernel_exec::rescan_after_acknowledgement(").expect("policy");
    let requeue = ack.find("HOSTED_IRQ_PENDING_EVENTS.fetch_or(1u64 << line.event_bit")
        .expect("the line is redriven");
    let wake = ack.find("HOSTED_IRQ_RETRY_WAKE.publish(").expect("a wake follows");
    assert!(confirm < rescan && rescan < requeue && requeue < wake);
    assert!(ack.contains("trace_hosted_irq_line_outcome(line.event_bit, b\"acknowledged\""));
}

#[test]
fn a_deferred_line_is_requeued_and_woken_and_traced_per_line() {
    let drain = section("unsafe fn drain_pending_hosted_irqs_snapshot() -> u64 {",
        "pub(crate) unsafe fn drain_pending_hosted_irqs()");
    let deferred = drain.find("Ok(HostedIrqServiceOutcome::DeferredBusy)").unwrap();
    assert!(drain[deferred..].contains("trace_hosted_irq_line_outcome(event_bit, b\"deferred-busy\""));
    let requeue = drain.find("HOSTED_IRQ_PENDING_EVENTS.fetch_or(deferred").expect("requeue");
    assert!(drain[requeue..].contains("HOSTED_IRQ_RETRY_WAKE.publish("));
    let trace = section("fn trace_hosted_irq_line_outcome(", "\n}\n");
    assert!(trace.contains("PER_LINE"), "each line has its own trace budget");
}
