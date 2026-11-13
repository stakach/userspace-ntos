//! A yielded nested AddDevice receive returns to its retained root owner after one service pass.

const SCHEDULER: &str = include_str!(
    "../../../components/ntos-executive/src/component_scheduler.rs"
);

#[test]
fn repeated_scheduler_yields_retain_the_exact_receive_instead_of_spinning_inside_child_work() {
    let body = SCHEDULER
        .split_once("unsafe fn resume_pending_child_work(")
        .expect("retained child-work resume")
        .1
        .split_once("unsafe fn retain_uncertain_receive(")
        .expect("end of child-work resume")
        .0;
    assert!(body.contains("PendingReceiveMode::SchedulerYield"),
        "a resumed scheduler yield must skip the already consumed child receive");
    assert!(!body.contains("while result.scheduler_yielded"),
        "the nested receive may not monopolize its retained parent while timer demand renews");
    assert!(body.contains("component_pump_continue_receive_after_scheduler_service"));
    assert!(body.contains("pending.result = result") && body.contains("pending.channel = channel"),
        "retain the latest receive result and physical channel across the root turn");
    assert!(body.contains("HostedPumpRestore::ChildWorkPending(pending)"),
        "a second yield must return to the exact AddDevice owner");
}
