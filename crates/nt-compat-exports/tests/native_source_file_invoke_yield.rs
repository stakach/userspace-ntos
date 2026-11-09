//! A File dispatch yield must return its original manager invocation, not a fabricated result.

const DISPATCH: &str = include_str!("../../../components/ntos-executive/src/hosted_file_dispatch.rs");
const CONNECT: &str = include_str!("../../../components/ntos-executive/src/hosted_input_connect_dispatch.rs");
const LIVE: &str = include_str!("../../../components/ntos-executive/src/hosted_connect_live.rs");

#[test]
fn invoke_result_distinguishes_terminal_return_from_child_work_yield() {
    let contract = DISPATCH
        .split_once("enum InvokeResult {")
        .expect("typed File invoke result")
        .1
        .split_once("pub(super) fn invoke_suspend_aware(")
        .expect("suspend-aware File invoke entry")
        .0;
    assert!(contract.contains("Returned(ExternalFileIrpReturn)"));
    assert!(contract.contains("ChildWorkYield"));
    assert!(contract.contains("ExternalFileIrpInvocation"));
    assert!(contract.contains("ExternalFileIrpPumpKey"));
    assert!(contract.contains("FileDispatchContinuation"));
    assert!(DISPATCH.contains("native: FileIrpPumpContinuation"));

    let invoke = DISPATCH
        .split_once("pub(super) fn invoke_suspend_aware(")
        .expect("suspend-aware File invoke entry")
        .1
        .split_once("fn trace_port_connect_execute(")
        .expect("suspend-aware File invoke boundary")
        .0;
    assert!(invoke.contains("-> InvokeResult"));
    assert!(invoke.contains("InvokeResult::ChildWorkYield"));
    assert!(invoke.contains("InvokeResult::ChildWorkYield { invocation, key, continuation }"));
    assert!(invoke.contains("finish_invoke_result(invocation, projection"));
    assert!(!invoke.contains("finish_external_file_irp"));
}

#[test]
fn suspended_port_connect_keeps_source_reply_unissued_until_provider_return() {
    assert!(CONNECT.contains("PumpSuspended"));
    assert!(CONNECT.contains("PortConnectDispatchResult::PumpSuspended"));
    let drive = LIVE
        .split_once("let phase = {")
        .expect("port CONNECT dispatch")
        .1
        .split_once("let work = &mut *work_ptr;")
        .expect("dispatch return boundary")
        .0;
    assert!(drive.contains("port.dispatch(permit, caller)"));
    let returned = LIVE
        .split_once("fn observe_port_dispatch_result(")
        .expect("CONNECT dispatch observation")
        .1
        .split_once("fn redrive_inner(")
        .expect("CONNECT observation boundary")
        .0;
    assert!(returned.contains("PortConnectPhase::PumpSuspended"));
    assert!(returned.contains("return false;"));
    assert!(returned.find("PortConnectPhase::PumpSuspended").unwrap()
        < returned.find("origin_mut().reply_dispatch").unwrap());
}

#[test]
fn root_selects_only_an_exact_retained_port_connect_pump() {
    assert!(CONNECT.contains("fn claim_suspended_pump_step("));
    assert!(CONNECT.contains("PumpStepClaimed"));
    let selector = LIVE
        .split_once("fn claim_suspended_port_connect_pump(")
        .expect("root suspended CONNECT claim")
        .1
        .split_once("fn ")
        .expect("claim boundary")
        .0;
    assert!(selector.contains("reverse_owner_id"));
    assert!(selector.contains("source_irp_address()"));
    assert!(selector.contains("claim_suspended_pump_step()"));
    assert!(selector.contains("if work.blocked"));
}

#[test]
fn root_deposits_one_use_child_step_before_native_resume() {
    let resume = LIVE
        .split_once("fn redrive_suspended_connect_pump(")
        .expect("root suspended CONNECT redrive")
        .1
        .split_once("fn ")
        .expect("redrive boundary")
        .0;
    let deposit = resume.find("retain_child_step(step)").expect("durable child step deposit");
    let native = resume.find("resume_pump_after_child").expect("native resume");
    assert!(deposit < native);
}

#[test]
fn unowned_native_yield_remains_in_the_port_work_row() {
    assert!(CONNECT.contains("unowned_yield: Option<hosted_file_owners::PortConnectDispatchFailure>"));
    assert!(CONNECT.contains("self.unowned_yield = Some(failure)"));
    assert!(CONNECT.contains("self.phase = PortConnectPhase::PumpBlocked"));
    let returned = LIVE
        .split_once("fn observe_port_dispatch_result(")
        .expect("CONNECT dispatch observation")
        .1
        .split_once("fn redrive_inner(")
        .expect("observation boundary")
        .0;
    assert!(returned.contains("PortConnectPhase::PumpBlocked"));
    let blocked = returned.find("PortConnectPhase::PumpBlocked").unwrap();
    let refusal = returned[blocked..].find("return false;").unwrap() + blocked;
    let reply = returned.find("origin_mut().reply_dispatch").unwrap();
    assert!(blocked < refusal && refusal < reply);
}

#[test]
fn nonretryable_native_restore_blocks_the_port_parent() {
    let owners = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
    let resume = owners
        .split_once("fn resume_suspended_port_connect_pump(")
        .expect("exact File resume")
        .1
        .split_once("pub(super) enum DispatchResult")
        .expect("resume boundary")
        .0;
    assert!(resume.contains("continuation.retry_without_new_child()"));
    assert!(resume.contains("quarantine_dispatch_pump"));
    assert!(resume.contains("PortConnectPumpDrive::Blocked"));
}

#[test]
fn every_unsettled_port_parent_is_visible_to_root_gate() {
    let gate = LIVE
        .split_once("fn unsettled_suspended_connect_pump(")
        .expect("root retained parent gate")
        .1
        .split_once("fn ")
        .expect("gate boundary")
        .0;
    for phase in ["PumpSuspended", "PumpStepClaimed", "PumpRestoreRetry", "PumpBlocked"] {
        assert!(gate.contains(phase), "missing retained {phase} phase");
    }
    assert!(gate.contains("ORPHANED_CONNECT_PUMP_STEPS"));
}

#[test]
fn suspended_parent_is_not_its_own_nested_child() {
    let ready = LIVE
        .split_once("fn nested_ready(&self) -> bool {")
        .expect("CONNECT child readiness")
        .1
        .split_once("fn port_thunk(")
        .expect("child readiness boundary")
        .0;
    for phase in ["PumpSuspended", "PumpStepClaimed", "PumpRestoreRetry", "PumpBlocked"] {
        assert!(ready.contains(phase), "parent {phase} must not be selected as child");
    }
    assert!(ready.contains("nested_connect_ready("));
}
