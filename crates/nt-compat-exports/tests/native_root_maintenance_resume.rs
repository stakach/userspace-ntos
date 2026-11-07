//! Native maintenance resume ownership. Pure lane tests cover the phase transitions; these
//! assertions keep the live pump and terminal attached to the same retained physical dispatch.

const PUMP: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");
const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
const RESUME: &str = include_str!("../../../components/ntos-executive/src/component_resume_maintenance.rs");
const TERMINAL: &str = include_str!("../../../components/ntos-executive/src/component_terminal.rs");
const SCHEDULER: &str = include_str!("../../../components/ntos-executive/src/component_resume.rs");

#[test]
fn returned_receive_half_classifies_and_captures_output_in_one_typed_tail() {
    let runner = RECEIVE.split("pub(crate) unsafe fn resume_suspended_root_maintenance_component(")
        .nth(1).expect("maintenance receive runner")
        .split("pub(crate) unsafe fn resume_suspended_receive_component(").next().unwrap();
    assert!(runner.contains("classify_returned_win32k_pump("),
        "returned pump must enter the shared typed classifier");
    let tail = RECEIVE.split("unsafe fn classify_returned_win32k_pump(")
        .nth(1).expect("shared returned-pump classifier")
        .split("pub(crate) unsafe fn resume_suspended_receive_component(").next().unwrap();
    let capture = tail.find("capture_win32k_dispatch_return(").unwrap();
    let wall = tail.find("retire_win32k_on_wall(&pump)").unwrap();
    let provider = tail.find("pump.provider_wait_suspended").unwrap();
    let lpc = tail.find("pump.lpc_wait_suspended").unwrap();
    let callback = tail.find("pump.callback_suspended").unwrap();
    let completed = tail.find("complete_resumed_dispatch(").unwrap();
    assert!(capture < wall && wall < provider && provider < lpc
        && lpc < callback && callback < completed);
    assert!(tail.contains("capture_lpc_wait_repark(")
        && tail.contains("ProviderWaitPumpCompletion::Reparked")
        && tail.contains("ProviderWaitPumpCompletion::UserCallbackSuspended"));
    let completed = GLUE.split("unsafe fn complete_resumed_dispatch(").nth(1)
        .expect("typed dispatch completion")
        .split("pub(crate) unsafe fn resume_suspended_lpc_wait_component(").next().unwrap();
    for output in ["capture_paint_dispatch_output(", "published_win32k_output_length(",
        "capture_resumed_userconnect_snapshot("] {
        assert!(completed.contains(output), "completed result must retain {output}");
    }
}

#[test]
fn timer_only_outer_pass_retries_ready_maintenance_without_generic_provider_completion() {
    let outer = SCHEDULER.split("pub(super) unsafe fn run_outer(").nth(1)
        .expect("timer driven outer continuation pass");
    let returned = outer.find("root_maintenance_owner::next_returned_ticket()")
        .expect("timer pass revisits a retained returned pump result");
    let returned_run = outer[returned..].find("run_root_maintenance(handler, ticket)")
        .map(|offset| returned + offset).expect("returned result is reconciled");
    let scan = outer.find("root_maintenance_owner::next_ready_ticket()")
        .expect("timer pass scans exact ready maintenance owner");
    let run = outer[scan..].find("run_root_maintenance(handler, ticket)")
        .map(|offset| scan + offset).expect("ready owner runs the typed receive half");
    let generic = outer.find("next_in_pass(&(*handler).pm, &mut pass)").unwrap();
    assert!(returned < returned_run && returned_run < scan && scan < run && run < generic,
        "maintenance retries before generic provider candidate selection");
}

#[test]
fn maintenance_receive_half_requires_exact_live_yield_and_never_resends_request() {
    let wrapper = PUMP
        .split("pub(crate) unsafe fn component_pump_continue_root_maintenance(")
        .nth(1).expect("distinct maintenance receive continuation")
        .split("unsafe fn component_pump_continue_receive_half(").next().unwrap();
    assert!(wrapper.contains("previous.maintenance_yield"));
    assert!(wrapper.contains("maintenance_continuation_is_current"));
    assert!(wrapper.contains("previous.reply_cap"));
    assert!(wrapper.contains("component_pump_continue_receive_half"));
    assert!(!wrapper.contains("component_pump_inner"));
    assert!(!wrapper.contains("component_pump_enter"));
}

#[test]
fn maintenance_resume_retains_ticket_through_physical_release_and_shared_restore() {
    for required in [
        "root_maintenance_owner::pending(ticket)",
        "root_maintenance_owner::with_physical(ticket",
        "begin_root_maintenance_resume",
        "restore_shared_resume_snapshot",
        "component_pump_continue_root_maintenance",
    ] {
        assert!(RESUME.contains(required) || RECEIVE.contains(required),
            "missing exact resume step: {required}");
    }
    assert!(!RESUME.contains("ComponentSuspensionCompletion::receive_ready()"));
    assert!(!RESUME.contains("component_pump(ch"));
}

#[test]
fn shared_maintenance_terminal_uses_typed_ack_retirement() {
    assert!(TERMINAL.contains("finish_shared_root_maintenance_terminal"));
    assert!(TERMINAL.contains("root_maintenance_owner::retire"));
    assert!(!TERMINAL.contains("RootMaintenance => ComponentSuspensionCompletion::provider"));
}

#[test]
fn maintenance_shared_return_is_reserved_before_semantic_finish_and_not_drained_until_owner_retires() {
    let terminal = TERMINAL.split("TerminalPhase::Acknowledged { .. } => {").nth(1)
        .expect("acknowledged terminal branch");
    let reserve = terminal.find("reserve_root_maintenance_shared_return")
        .expect("reserve exact shared return before semantic retirement");
    let finish = terminal.find("finish_shared_root_maintenance_terminal")
        .expect("typed maintenance terminal finish");
    let retire = terminal.find("root_maintenance_owner::retire")
        .expect("retire physical maintenance owner after pure finish");
    let publish = terminal.find("publish_root_maintenance_shared_return")
        .expect("publish ready only after owner retirement");
    assert!(reserve < finish && finish < retire && retire < publish);
    let drain = TERMINAL.split("pub(super) unsafe fn drain_shared_returns()").nth(1)
        .expect("shared-return drain");
    assert!(drain.contains("if !pending.ready"), "unready reserved record must not complete");
}

#[test]
fn maintenance_callback_has_reserved_transfer_and_typed_external_terminal() {
    assert!(RESUME.contains("CallbackTransfer::reserve()"),
        "reserve callback ownership before entering the continued receive half");
    assert!(RESUME.contains("callback_transfer.capture("),
        "capture the actual suspended callback token");
    assert!(TERMINAL.contains("retain_shared_root_maintenance_external_terminal_running"),
        "retain the callback payload under the maintenance terminal kind");
    assert!(TERMINAL.contains("SharedReturn::Repark(token)"),
        "callback handoff must repark the exact external token");
}

#[test]
fn callback_capacity_refusal_leaves_maintenance_ready_and_retryable() {
    let run = RESUME.split("pub(crate) unsafe fn run_root_maintenance(").nth(1)
        .expect("typed maintenance runner")
        .split("unsafe fn repark_service(").next().unwrap();
    let reserve = run.find("CallbackTransfer::reserve()")
        .expect("capacity reservation before native continuation");
    let store = run.find("root_maintenance_owner::store_callback")
        .expect("durable transfer owner");
    let begin = run.find("begin_root_maintenance_resume")
        .expect("typed maintenance transition");
    assert!(reserve < store && store < begin,
        "a no-effect allocation refusal must leave the Ready frame retryable");
}

#[test]
fn returned_pump_result_is_durable_before_terminal_or_repark_transfer() {
    let run = RESUME.split("pub(crate) unsafe fn run_root_maintenance(").nth(1)
        .expect("typed maintenance runner")
        .split("unsafe fn repark_service(").next().unwrap();
    assert!(run.contains("root_maintenance_owner::result(ticket)"),
        "an already returned result must bypass the native receive half");
    let pump = run.find("resume_suspended_root_maintenance_component(pending)").unwrap();
    let store = run.find("root_maintenance_owner::store_result(ticket")
        .expect("retained returned-result owner");
    let transfer = run.find("match pump {").unwrap();
    assert!(pump < store && store < transfer,
        "the result must be owned before fallible terminal or repark semantics");
}

#[test]
fn callback_token_is_durable_before_typed_terminal_admission() {
    let run = RESUME.split("pub(crate) unsafe fn run_root_maintenance(").nth(1)
        .expect("typed maintenance runner")
        .split("unsafe fn repark_service(").next().unwrap();
    let capture = run.find("callback_transfer.capture(").unwrap();
    let store = run.find("root_maintenance_owner::store_callback_token(ticket")
        .expect("exact captured callback token retained by owner");
    let terminal = run.find("retain_maintenance_callback_transfer(ticket")
        .expect("typed callback terminal admission");
    assert!(capture < store && store < terminal);
}

#[test]
fn no_effect_terminal_and_repark_refusals_keep_returned_result_retryable() {
    let terminal = RESUME.split("ProviderWaitPumpCompletion::Completed(dispatch)").nth(1)
        .expect("real completed dispatch branch")
        .split("ProviderWaitPumpCompletion::Reparked(next)").next().unwrap();
    assert!(terminal.contains("begin_result_transfer"));
    assert!(terminal.contains("pure_transfer_refused"));
    let repark = RESUME.split("unsafe fn repark_service(").nth(1)
        .expect("typed next-wait transfer");
    assert!(repark.contains("need_pure_frame_transfer"));
    assert!(repark.contains("pure_transfer_refused"));
    assert!(RESUME.contains("root_maintenance_owner::refuse_result_transfer_no_effects(ticket)"));
}

#[test]
fn accepted_transfer_retries_only_retirement_and_backend_work() {
    let repark = RESUME.split("unsafe fn repark_provider(").nth(1)
        .expect("provider repark")
        .split("unsafe fn repark_lpc(").next().unwrap();
    assert!(repark.contains("need_pure_frame_transfer(ticket"),
        "accepted pure rearm must be discovered before attempting it again");
    assert!(RESUME.contains("Some(TransferPhase::Transferred"));
    assert!(repark.contains("retire_after_repark(ticket, next_key)"));
    assert!(repark.contains("admit_provider_after_transfer"),
        "backend effect follows durable accepted-transfer and owner retirement");
}

#[test]
fn timer_selects_stored_returned_result_before_generic_busy_gate() {
    let outer = SCHEDULER.split("pub(super) unsafe fn run_outer(").nth(1).unwrap();
    let result = outer.find("next_returned_ticket()")
        .expect("exact returned-result scanner");
    let busy = outer.find("if component_execution_is_busy()")
        .expect("generic busy-lane gate");
    assert!(result < busy, "stored returned result must be considered before busy suppression");
}

#[test]
fn captured_callback_token_is_reused_without_recapture_after_terminal_refusal() {
    let branch = RESUME.split("if matches!(&pump, win32k_glue::RootMaintenancePumpCompletion::Restored(")
        .nth(1).expect("maintenance callback branch")
        .split("// No callback was yielded").next().unwrap();
    let held = branch.find("root_maintenance_owner::callback_token(ticket)").unwrap();
    let capture = branch.find("callback_transfer.capture(").unwrap();
    let transfer = branch.find("retain_maintenance_callback_transfer(ticket").unwrap();
    assert!(held < capture && capture < transfer);
    assert!(branch.contains("begin_result_transfer"));
    assert!(branch.contains("pure_transfer_refused"));
    assert!(RESUME.contains("root_maintenance_owner::refuse_result_transfer_no_effects(ticket)"));
}
