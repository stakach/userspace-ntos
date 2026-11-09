//! A no-effect refusal to restore a typed AddDevice parent keeps its exact physical ticket.

const ADD_DEVICE: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_add_device_continuation.rs"
);
const SCHEDULER: &str = include_str!(
    "../../../components/ntos-executive/src/component_scheduler.rs"
);

fn between(source: &'static str, start: &str, end: &str) -> &'static str {
    source.split_once(start).expect("native start boundary").1
        .split_once(end).expect("native end boundary").0
}

#[test]
fn retryable_retained_parent_is_redriven_by_exact_ticket_without_new_child_or_reply_request() {
    let admission = between(ADD_DEVICE, "fn retry_without_new_child(&self) -> bool {",
        "fn record_child_step(");
    assert!(admission.contains("HostedPumpRestore::Retained")
        && admission.contains("retryable"),
        "a retryable retained physical parent must be eligible for root redrive");

    let resume = between(ADD_DEVICE, "unsafe fn resume(mut self) -> AddDevicePumpProgress {",
        "unsafe fn into_progress(");
    assert!(resume.contains("HostedPumpRestore::Retained"),
        "retry the retained restore ticket rather than treating it as permanent refusal");
    assert!(!resume.contains("hosted_component_pump_with_caller"),
        "retry must not issue another AddDevice or projection ReplyRequest");

    assert!(SCHEDULER.contains("retry_retained_add_device_restore"),
        "scheduler must own the exact-ticket physical restore retry boundary");
}
