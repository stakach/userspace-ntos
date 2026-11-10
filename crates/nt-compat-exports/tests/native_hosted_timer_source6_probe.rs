//! A source-6 timer census must observe the same physical expiry as the selected deadline.
//! Nested provider census reads only a copied record; it cannot walk root-owned timer queues.

const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const PROBE: &str =
    include_str!("../../../components/ntos-executive/src/hosted_timer_source6_probe.rs");
const BOOTSTRAP: &str =
    include_str!("../../../components/ntos-executive/src/dispatcher_bootstrap.rs");

fn body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source
        .find(start)
        .unwrap_or_else(|| panic!("missing {start}"));
    let body = &source[start..];
    &body[..body.find(end).unwrap_or_else(|| panic!("missing {end}"))]
}

#[test]
fn nested_census_reads_a_copied_timer_record() {
    let census = body(
        MAIN,
        "fn print_timer_deadline_census()",
        "fn print_periodic_census_heartbeat(",
    );
    assert!(
        !census.contains("hosted_driver_earliest_timer_snapshot("),
        "nested census must not scan the root-owned timer queues"
    );
    assert!(
        census.contains("hosted_timer_source6_probe::snapshot()"),
        "the timer-delivery owner must publish a copied diagnostic record"
    );
}

#[test]
fn root_timer_delivery_matches_selected_source_to_exact_expiry() {
    let interrupt = body(
        MAIN,
        "unsafe fn delay_timer_interrupt_claimed(",
        "unsafe fn delay_timer_shutdown(",
    );
    let selected = interrupt
        .find("let selected = delay_timer_next_deadline(")
        .unwrap();
    let probe = interrupt
        .find("hosted_timer_source6_probe::select(")
        .expect("capture the source-6 candidate before draining due work");
    let drain = interrupt.find("delay_timer_drain_due_work(").unwrap();
    assert!(selected < probe && probe < drain);

    let expiry = body(
        DRIVER,
        "pub(crate) unsafe fn hosted_driver_timer_wake_due(",
        "pub(crate) fn hosted_driver_dpc_activation_pending(",
    );
    let match_expiry = body(
        PROBE,
        "fn matches_expiry(",
        "pub(crate) fn missing_instance(",
    );
    assert!(
        match_expiry.contains("expiry.generation"),
        "a reused timer pointer must not be attributed to an old set generation"
    );
    assert!(
        expiry.contains("probe.observe_expiry("),
        "record the signal, waiter wake, and DPC queue result from this exact expiry"
    );
}

#[test]
fn source_six_observation_is_bounded_before_timer_queue_scan() {
    let select = body(PROBE, "pub(crate) fn select(", "impl Scan {");
    let gate = select
        .find("scan > 8 && !scan.is_power_of_two()")
        .expect("keep only initial and exponential source-6 samples");
    let queue = select
        .find("hosted_driver_earliest_timer_snapshot(")
        .expect("selected timer comes from the root-owned queue");
    assert!(
        gate < queue,
        "unsampled source-6 ticks must not walk every driver timer queue"
    );
}

#[test]
fn bootstrap_timer_delivery_does_not_invent_a_source_six_selection() {
    let service = body(
        BOOTSTRAP,
        "pub(crate) unsafe fn service_hosted_timer_work()",
        "let provider_work = scan_owned_timer_work(now)",
    );
    assert!(service.contains("timer_hosted_driver_wake_due(now, None)"));
}
