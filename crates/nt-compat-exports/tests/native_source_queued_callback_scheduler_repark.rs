//! A queued callback's exact child may yield again after its timer/IRQ service pass.
//! That retryable continuation must retain its physical Reply at the root;
//! it must not be confused with an uncertain or nonretryable retained callback.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const QUEUE: &str = include_str!("../../../components/ntos-executive/src/hosted_work_queue_owner.rs");
const SCHEDULER: &str = include_str!("../../../components/ntos-executive/src/component_scheduler.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing boundary: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing boundary: {end}"))
        .0
}

#[test]
fn retryable_queued_scheduler_yield_waits_at_the_root_with_its_original_reply() {
    let resumed_child = between(
        SCHEDULER,
        "trace_connect_child_result(4, &result);",
        "if let Some(crate::spawn_hosts::NestedChildWorkState::Ready(_))",
    );
    assert!(
        resumed_child.contains("if result.scheduler_yielded")
            && resumed_child.contains("channel.reply_cap = result.reply_cap")
            && resumed_child.contains("pending.mode = PendingReceiveMode::SchedulerYield")
            && resumed_child.contains("pending.retryable = true")
            && resumed_child.contains("HostedPumpRestore::ChildWorkPending(pending)"),
        "the second scheduler yield must keep the exact physical Reply in a retryable child owner"
    );

    let retained = between(QUEUE, "unsafe fn retain_result(", "unsafe fn terminal_physical_bound(");
    assert!(
        retained.contains("HostedPumpRestore::ChildWorkPending(pending)")
            && retained.contains("pending.retryable")
            && retained.contains("QueuedCallbackProgress::PendingRestore")
            && retained.contains("row.pump = Some(pump)"),
        "PendingRestore must remain in the selected queue row, not release or replay its Reply"
    );

    let callback_turn = between(
        SERVICE,
        "unsafe fn settle_queued_callback_turn()",
        "unsafe fn settle_queued_callbacks()",
    );
    assert!(
        callback_turn.contains("Progress::PendingRestore => FilePumpTurn::RetryableRestore"),
        "a retryable restore needs a typed result distinct from uncertain Retained"
    );
    let callback_settlement = between(
        SERVICE,
        "unsafe fn settle_queued_callbacks()",
        "unsafe fn settle_one_generic_file_pump_after(",
    );
    assert!(
        callback_settlement.contains(
            "FilePumpTurn::RetryableRestore => return ConnectPumpSettlement::RetryableRestore"
        ),
        "the typed retryable state must reach the AddDevice root boundary"
    );

    let root = between(
        SERVICE,
        "// A callback reached by the preceding AddDevice child",
        "let selected = {",
    );
    let retryable = between(
        root,
        "ConnectPumpSettlement::RetryableRestore =>",
        "ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked",
    );
    assert!(
        retryable.contains("park_queued_callback_root_receive!(root_event_consumed, 'queued_callback_settlement)")
            && !retryable.contains("break 'service_loop"),
        "the exact queued callback owner must retain this root event through its retry"
    );
    let parked = between(SERVICE, "macro_rules! park_queued_callback_root_receive", "macro_rules! reject_hosted_ingress");
    assert!(parked.contains("$root_event_consumed = true;")
        && parked.contains("continue $retry_label;"),
        "an active child must retry inside the same settlement loop after retaining the root event");
    let uncertain = root
        .split_once("ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked")
        .expect("nonretryable callback settlement")
        .1;
    assert!(
        uncertain.contains("break 'service_loop"),
        "uncertain or blocked callback ownership must remain fail-closed"
    );
}
