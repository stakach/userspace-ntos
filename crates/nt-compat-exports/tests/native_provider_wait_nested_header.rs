//! A nested dispatch may replace the shared callback header while an older hosted
//! win32k stack is suspended in a service wait.

#[test]
fn hosted_provider_wait_uses_its_retained_dispatch_header() {
    let subsystem = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let context = include_str!("../../../components/ntos-executive/src/win32k_provider_wait_context.rs");

    let begin = subsystem
        .split("unsafe fn begin_provider_stack_event_activation(")
        .nth(1)
        .expect("stack activation begin");
    assert!(begin.contains("retain_hosted_wait_header"));
    let finish = subsystem
        .split("unsafe fn finish_provider_stack_event_activation(")
        .nth(1)
        .expect("stack activation finish");
    assert!(finish.contains("retire_hosted_wait_header"));
    assert!(context.contains("retained_hosted_wait_header"));
    assert!(context.contains("active_provider_stack_event_activation"));
    assert!(context.contains("request.owner"));
    assert!(context.contains("callback_request_context_for_request(&header)"));
    assert!(subsystem.contains("refresh_hosted_wait_header(reply)"),
        "a completed callback must retain its validated Reply header for a later nested wait");
}
