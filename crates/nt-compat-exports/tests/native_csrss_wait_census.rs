//! CSRSS startup timing observes copied exact owners; it never grants a wake.

const ALPC: &str = include_str!("../../../components/ntos-executive/src/native_alpc_send_receive_work.rs");
const OBJECT: &str = include_str!("../../../components/ntos-executive/src/object_wait_reply.rs");
const DELAY: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const INGRESS: &str = include_str!("../../../components/ntos-executive/src/ingress_observation.rs");

#[test]
fn startup_waits_sample_captured_generations_without_new_wake_authority() {
    let alpc_begin = ALPC.split("pub(crate) unsafe fn begin(").nth(1).unwrap()
        .split("enum RingStep").next().unwrap();
    assert!(alpc_begin.contains("hosted_process_generation(pi)"));
    assert!(alpc_begin.contains("HostedProcessRole::Win32Subsystem"));
    assert!(alpc_begin.contains("StartupWaitObservation::new("));
    assert!(ALPC.contains("mark_selected(") && ALPC.contains("mark_replied("));
    assert!(ALPC.contains("CSRSS_WAIT_FINAL_LOGS.fetch_add(1")
        && INGRESS.contains("CSRSS_ALPC_SAMPLES.fetch_add(1"));

    let object_finish = OBJECT.split("unsafe fn finish(").nth(1).unwrap()
        .split("unsafe fn drive(").next().unwrap();
    assert!(object_finish.contains("validate_provider_logical_caller(record.caller)"));
    assert!(object_finish.contains("record.caller.process().generation"));
    assert!(object_finish.contains("record.caller.thread().generation()"));
    assert!(object_finish.contains("CSRSS_OBJECT_WAIT_SAMPLES.fetch_add(1"));

    let delay_park = DELAY.split("unsafe fn delay_park(").nth(1).unwrap()
        .split("unsafe fn delay_wake_due(").next().unwrap();
    for required in ["hosted_thread_pi_for_badge", "hosted_thread_tid_for_badge",
        "hosted_process_generation", "thread_lifetime", "HostedProcessRole::Win32Subsystem"] {
        assert!(delay_park.contains(required), "delay park lacks exact {required}");
    }
    assert!(delay_park.find("observation:").unwrap() < delay_park.find("queue.insert(waiter)").unwrap());
    let wake = DELAY.split("unsafe fn delay_wake_due(").nth(1).unwrap()
        .split("unsafe fn delay_timer_drain_due_work(").next().unwrap();
    assert!(wake.contains("trace_subsystem_delay_observation(waiter"));
    assert!(DELAY.contains("SAMPLES.fetch_add(1")
        && DELAY.contains("let Some(observation) = waiter.observation"));
}
