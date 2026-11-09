//! The intentional nested child handoff is distinct from a failed parent restore.

const SCHEDULER: &str = include_str!("../../../components/ntos-executive/src/component_scheduler.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const PHYSICAL: &str = include_str!("../../../components/ntos-executive/src/component_ingress_nested.rs");
const CLASS: &str = include_str!("../../../components/ntos-executive/src/hosted_class_irp_lane.rs");
const SOURCE: &str = include_str!("../../../components/ntos-executive/src/hosted_source_completion_lane.rs");
const WIN32K: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
const SHARED: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
const REGISTRY: &str = include_str!("../../../components/ntos-executive/src/provider_registry_caller.rs");

#[test]
fn primary_driver_file_pump_can_admit_a_retained_child_handoff() {
    let gate = SCHEDULER
        .split_once("unsafe fn owned_child_work_channel(")
        .expect("typed owned pump route gate")
        .1
        .split_once("pub(super) unsafe fn hosted_component_pump_with_caller_child_work(")
        .expect("end of route gate")
        .0;
    assert!(gate.contains("PhysicalSourceKind::Primary"),
        "a main driver TCB is a valid physical File pump source");
    assert!(gate.contains("PhysicalSourceKind::DispatchWorker"),
        "a registered dispatch worker remains eligible");
}

#[test]
fn scheduler_yields_before_completion_or_parent_restore() {
    assert!(SCHEDULER.contains("ChildWorkReady {"), "intentional child work needs a typed result");
    let body = SCHEDULER
        .split_once("unsafe fn hosted_component_pump_inner(")
        .expect("scheduler entry").1;
    let child = body.find("HostedPumpRestore::ChildWorkReady {").expect("child handoff");
    let completion = body.find("if result.completed {").expect("completion boundary");
    let restore = body.find("runtime::nested::restore(&mut parent)").expect("parent restore");
    assert!(child < completion && child < restore,
        "child must run outside the parent stack before completion or restore");
}

#[test]
fn scheduler_handoff_keeps_the_post_admission_reply_channel() {
    let variant = SCHEDULER
        .split_once("ChildWorkReady {")
        .expect("typed child-work result").1
        .split_once("},")
        .expect("result fields").0;
    assert!(variant.contains("channel: crate::spawn_hosts::PumpChannel"),
        "the caller's original channel may have a stale Reply after admission");
    let body = SCHEDULER
        .split_once("unsafe fn hosted_component_pump_inner(")
        .expect("scheduler entry").1;
    assert!(body.contains("result, parent, channel: *channel, dispatch, caller,"),
        "handoff must snapshot the scheduler's post-admission channel");
    let handoff = body
        .split_once("match result.nested_child_work {")
        .expect("intentional handoff").1
        .split_once("if result.completed {")
        .expect("completion boundary").0;
    assert!(handoff.contains("runtime::current_reply(route)"),
        "a shared Call may replace the Reply after initial admission");
    assert!(handoff.contains("channel.reply_cap = canonical_reply"),
        "continuation must carry the latest authenticated Reply");
}

#[test]
fn observed_scsi_pump_can_return_the_retained_child_handoff() {
    let entry = SCHEDULER
        .split_once("fn hosted_component_pump_observed_retained(")
        .expect("observed SCSI pump must expose the typed retained result").1
        .split_once("unsafe fn hosted_component_pump_inner(")
        .expect("scheduler inner boundary").0;
    assert!(entry.contains("-> HostedPumpRestore"));
    assert!(entry.contains("hosted_component_pump_inner(channel, caller, Some(owner))"));
    assert!(!entry.contains(".legacy()"), "the retained SCSI caller must not panic on child work");
}

#[test]
fn only_a_typed_owner_entry_can_admit_child_work() {
    assert!(PUMP.contains("child_work_capable: bool"),
        "capability travels with the copied pump channel through enter and loop");
    let entry = SCHEDULER
        .split_once("fn hosted_component_pump_observed_child_work(")
        .expect("separate typed File entry").1
        .split_once("unsafe fn hosted_component_pump_inner(")
        .expect("scheduler inner boundary").0;
    assert!(SCHEDULER.contains("channel.child_work_capable = true"));
    assert!(entry.contains("owned_child_work_channel(channel)"),
        "typed entry must perform exact physical-route preflight");
    assert!(entry.contains("hosted_component_pump_inner(&channel, caller, Some(owner))"));
    for (name, source) in [("class", CLASS), ("source", SOURCE), ("win32k", WIN32K)] {
        assert!(source.contains("child_work_capable: false"),
            "{name} channels must begin without File child-work authority");
    }
}

#[test]
fn add_device_child_entry_preserves_the_typed_result() {
    let entry = SCHEDULER
        .split_once("fn hosted_component_pump_with_caller_add_device_child_work(")
        .expect("AddDevice owns a separate child-capable entry").1
        .split_once("unsafe fn hosted_component_pump_inner(")
        .expect("scheduler inner boundary").0;
    assert!(entry.contains("owned_child_work_channel(channel)"));
    assert!(entry.contains("-> HostedPumpRestore"));
    assert!(entry.contains("hosted_component_pump_inner(&channel, Some(caller), None)"));
    assert!(!entry.contains(".legacy()"));
}

#[test]
fn child_work_continuation_uses_exact_receive_only_authority() {
    let body = PUMP
        .split_once("fn component_pump_continue_nested_child_work_receive(")
        .expect("intentional child receive continuation").1
        .split_once("unsafe fn component_pump_continue_receive_half(")
        .expect("receive boundary").0;
    for proof in ["NestedChildWorkState::Ready", "runtime::channel_route(ch)",
        "runtime::dispatch(route)", "runtime::current_reply(route)",
        "component_pump_continue_receive_half("] {
        assert!(body.contains(proof), "missing exact continuation proof: {proof}");
    }
    assert!(!body.contains("component_pump(ch)"), "never replay ReplyRequest");
}

#[test]
fn physical_parent_is_retained_before_unwind_and_restored_once() {
    let retain = PHYSICAL
        .split_once("fn retain_child_work_parent(")
        .expect("intentional child parent retention").1
        .split_once("fn restore_child_work_parent(")
        .expect("child parent restore boundary").0;
    assert!(retain.contains("ParentPhase::RestorePending"));
    assert!(retain.contains("parent.physical.held()"));
    assert!(!retain.contains("restore_stages("), "retention must have no native effect");
    let restore = PHYSICAL
        .split_once("fn restore_child_work_parent(")
        .expect("exact child parent restore").1
        .split_once("fn ")
        .expect("restore boundary").0;
    assert!(restore.contains("restore_pending_ticket(ticket)"));
    assert!(restore.contains("ChildWorkParentRestored"));
}

#[test]
fn resumed_child_step_restores_both_parents_before_receive_and_completion() {
    let body = SCHEDULER
        .split_once("fn resume_child_work(")
        .expect("typed scheduler child-work resume").1;
    let inner = body.find("restore_child_work_parent(").expect("inner parent restore");
    let outer = body.find("restore_or_retain(&mut parent)").expect("outer parent restore");
    let receive = body.find("component_pump_continue_nested_child_work_receive(")
        .expect("receive-only continuation");
    let complete = body.find("authenticate_component_completion(")
        .expect("authenticated final completion");
    assert!(inner < outer && outer < receive && receive < complete);
    assert!(body.contains("step.into_decision()"),
        "an uncertain child effect cannot restore or replay the parent");
    assert!(body.contains("while result.scheduler_yielded"),
        "resumed receive must service IRQ yields before completion");
    let completion_contract = SCHEDULER
        .split_once("fn authenticate_component_completion(")
        .expect("shared exact completion contract").1
        .split_once("fn resume_child_work(")
        .expect("resume boundary").0;
    assert!(completion_contract.contains("runtime::complete("));
}

#[test]
fn uncertain_child_step_fences_the_exact_physical_parent() {
    let quarantine = PHYSICAL
        .split_once("fn quarantine_child_work_parent(")
        .expect("exact physical child-work quarantine").1
        .split_once("fn ")
        .expect("quarantine boundary").0;
    assert!(quarantine.contains("ParentPhase::RestorePending"));
    assert!(quarantine.contains("ParentPhase::Quarantined"));
    assert!(quarantine.contains("ticket_matches(ticket, parent)"));
    let resume = SCHEDULER
        .split_once("fn resume_child_work(")
        .expect("scheduler child-work resume").1
        .split_once("fn retry_child_work(")
        .expect("retry boundary").0;
    assert!(resume.contains("quarantine_child_work_parent(ticket)"),
        "uncertain child effect must revoke physical restore eligibility");
}

#[test]
fn file_capable_nested_work_unwinds_before_running_its_child() {
    let branch = SHARED
        .split_once("if nested_file_path != NestedFileWorkPath::NoWork {")
        .expect("nested File readiness gate").1
        .split_once("trace_ps_create_receive(ch, b\"retained-services\"")
        .expect("nested File branch boundary").0;
    let capability = branch.find("if nested_file_path == NestedFileWorkPath::RetainForRoot {")
        .expect("typed child-work selection");
    let retain = branch.find("runtime::nested::retain_child_work_parent(&mut parent)")
        .expect("physical parent retained before unwind");
    let yield_out = branch.find("PumpMessage::nested_child_work_yield(ticket)")
        .expect("typed intentional child-work yield");
    let inline = branch.find("redrive_nested_hosted_file_work()")
        .expect("legacy inline child runner");
    assert!(capability < retain && retain < yield_out && yield_out < inline,
        "File-capable path must unwind before running any child");
}

#[test]
fn resumed_pump_reuses_the_retained_registry_caller() {
    let body = SCHEDULER
        .split_once("unsafe fn resume_pending_child_work(")
        .expect("resumed scheduler").1
        .split_once("unsafe fn retain_uncertain_receive(")
        .expect("resumed scheduler boundary").0;
    assert!(body.contains("provider_registry_caller::resolve_retained("),
        "the initial File pump still owns its registry caller row");
    assert!(!body.contains("provider_registry_caller::Scope::enter"),
        "recapturing the same route/dispatch always rejects before receive");
    let retained = REGISTRY
        .split_once("fn resolve_retained(")
        .expect("exact retained caller lookup").1
        .split_once("fn retire_completed(")
        .expect("retained caller boundary").0;
    assert!(retained.contains("OWNERS)).resolve(pm, route, dispatch, address_space)"));
}

#[test]
fn nested_restore_yield_stays_owned_until_its_parent_is_restored() {
    let initial = SCHEDULER
        .split_once("unsafe fn hosted_component_pump_inner(")
        .expect("initial scheduler").1
        .split_once("if result.completed {")
        .expect("initial completion boundary").0;
    assert!(initial.contains("result.nested_restore_yield"),
        "initial restore refusal must not become a File terminal wall");
    let resumed = SCHEDULER
        .split_once("unsafe fn resume_pending_child_work(")
        .expect("resumed scheduler").1
        .split_once("unsafe fn retain_uncertain_receive(")
        .expect("resumed scheduler boundary").0;
    assert!(resumed.contains("component_pump_continue_nested_restore_receive("),
        "nested restore must continue the existing receive half");
    assert!(resumed.contains("result.nested_restore_yield"),
        "a later restore refusal must remain in the durable File continuation");
    assert!(resumed.contains("result.nested_restore_quarantined"),
        "uncertain restoration must be fenced, not retired as a wall");
}
