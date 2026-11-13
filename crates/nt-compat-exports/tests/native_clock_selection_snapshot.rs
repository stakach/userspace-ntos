#[test]
fn component_reconcile_reuses_its_clock_snapshot_for_timer_selection() {
    let resume = include_str!("../../../components/ntos-executive/src/component_resume.rs");
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let reconcile = resume
        .split_once("unsafe fn reconcile_runtime(")
        .and_then(|(_, tail)| tail.split_once("unsafe fn drain_terminals("))
        .map(|(body, _)| body)
        .expect("focused component reconcile path");
    assert_eq!(reconcile.matches("monotonic_time_100ns()").count(), 1);
    assert!(reconcile.contains("delay_timer_rearm_at(&*queue, handler, nt_time_snapshot_at(now))"));

    let program = main
        .split_once("unsafe fn delay_timer_program(")
        .and_then(|(_, tail)| tail.split_once("unsafe fn arm_hosted_irq_retry_before_nested_receive("))
        .map(|(body, _)| body)
        .expect("physical timer programming path");
    assert!(program.contains("let now = monotonic_time_100ns()"),
        "physical timer programming must use fresh time after selection");

    let rearm = main
        .split_once("unsafe fn delay_timer_rearm_with_snapshot(")
        .and_then(|(_, tail)| tail.split_once("unsafe fn delay_timer_rearm_and_drain_overdue("))
        .map(|(body, _)| body)
        .expect("lazy rearm selection path");
    let availability = rearm.find("DELAY_TIMER_HANDLER.load(").unwrap();
    let sample = rearm.find("selection_time()").unwrap();
    assert!(availability < sample, "an unavailable timer must not read the clock");
}
