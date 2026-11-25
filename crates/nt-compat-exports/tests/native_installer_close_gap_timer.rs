//! Keep the diagnostic Close return's one-shot timer, due receipt and owned
//! maintenance probe connected across native source boundaries.

const LEDGER: &str = include_str!("../../nt-hosted-runtime/src/installer_syscall_span.rs");
const SPAN: &str = include_str!("../../../components/ntos-executive/src/installer_child_span_census.rs");
const SYSCALL: &str = include_str!("../../../components/ntos-executive/src/executor/syscall_nt.rs");
const SELECTOR: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const ROOT: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const MAINTENANCE: &str = include_str!("../../../components/ntos-executive/src/executor/maintenance.rs");
const FLOW: &str = include_str!("../../../components/ntos-executive/src/executor/flow.rs");

#[test]
fn terminal_close_publishes_a_one_shot_before_physical_rearm() {
    let returned = SPAN.split_once("pub(crate) fn returned(").unwrap().1
        .split_once("fn claim_gap_sample(").unwrap().0;
    assert!(returned.contains("ssn == SSN_NT_CLOSE")
        && returned.contains("status != nt_user_callback::STATUS_PENDING as u32")
        && returned.contains(".can_sample(owner)")
        && returned.contains(".arm_open_close_gap_deadline(owner)"));

    let route = SYSCALL.split_once("let installer_gap_timer_rearm =").unwrap().1
        .split_once("sc.result = res.status as u64;").unwrap().0;
    assert!(route.contains("installer_child_span_census::returned(")
        && route.contains("if installer_gap_timer_rearm")
        && route.contains("SavedMessageBuffer::capture()")
        && route.contains("delay_timer_rearm(&*delay_queue, &nt_handler)"));
    assert!(LEDGER.contains("last.at_100ns.checked_add(OPEN_CLOSE_GAP_THRESHOLD_100NS)"));
}

#[test]
fn shared_timer_delivers_once_before_owned_maintenance_and_quiesce() {
    assert!(SELECTOR.contains("installer_child_span_census::next_gap_deadline()")
        && SELECTOR.contains("DELAY_TIMER_SOURCE_INSTALLER_CLOSE_GAP"));
    let drain = ROOT.split_once("unsafe fn delay_timer_drain_due_work(").unwrap().1
        .split_once("pub(crate) unsafe fn delay_timer_drain_overdue_without_badge(").unwrap().0;
    assert!(drain.contains("installer_child_span_census::consume_due_gap_deadlines(now_100ns)"));
    let maintenance = MAINTENANCE.find("delay_timer_drain_overdue_without_badge(").unwrap();
    let sample = MAINTENANCE.find("installer_child_span_census::maybe_sample_gap(").unwrap();
    assert!(maintenance < sample, "due drain must precede the owned maintenance probe");
    assert!(SPAN.contains(".has_due_open_close_gap()")
        && SPAN.contains(".take_due_open_close_gap(owner, now)")
        && SPAN.contains(".open_close_gap(owner, now)"));
    let probe = SPAN.split_once("pub(crate) fn maybe_sample_gap(").unwrap().1
        .split_once("/// Sparse 30-second sample").unwrap().0;
    let due_claim = probe.find(".take_due_open_close_gap(owner, now)").unwrap();
    let badge_lookup = probe.find("handler.hosted_thread_badge_for_tid(owner.thread_id)").unwrap();
    let tcb_lookup = probe.find("handler.hosted_thread_tcb_for_badge(badge)").unwrap();
    assert!(due_claim < badge_lookup && badge_lookup < tcb_lookup,
        "an unavailable native identity must not retain a consumed one-shot due marker");
    assert!(FLOW.contains("!installer_child_span_census::has_pending_gap_observation()"));
    assert!(SPAN.contains(".has_pending_gap_observation()")
        && LEDGER.contains("row.close_probe_deadline_100ns.is_some()")
        && LEDGER.contains("|| row.close_probe_due"));
}
