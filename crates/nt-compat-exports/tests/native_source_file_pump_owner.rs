//! A nested native pump may unwind only after the File IRP invocation has a durable owner.

const OWNERS: &str = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HOOK: &str = include_str!("../../../components/ntos-executive/src/hosted_input_hook_live.rs");

#[test]
fn hook_work_keeps_exact_pump_key_and_restores_callback_alias_during_resume() {
    assert!(HOOK.contains("dispatch_mutable_method_neither_suspend_aware("),
        "both Hook sources must enter the typed File pump");
    assert!(HOOK.contains("pump_key: Option<")
        && HOOK.contains("fn with_suspended_hook_alias<"),
        "the exact Hook owner must retain its File pump key and scoped callback alias");
    assert!(HOOK.contains("take_returned_hook_pump("),
        "the Hook source must consume the exact mutable Type3 input after native resume");
}

#[test]
fn returned_hook_progress_and_unpublished_source_are_tracked_exactly() {
    let redrive = HOOK.split_once("unsafe fn redrive_returned_hook_pump() -> bool")
        .expect("flat-root returned Hook redrive").1
        .split_once("fn progress_generation()")
        .expect("returned Hook redrive boundary").0;
    assert!(redrive.contains("let before = (") && redrive.contains("before != after"),
        "independent phase transitions must not cancel in an additive progress count");
    assert!(!redrive.contains("progress_generation() != before"),
        "a consumed File pump can progress even when boolean counts cancel");
    assert!(HOOK.contains("fn hook_source_unsettled() -> bool")
        && HOOK.contains("pump_return_consumed"),
        "a returned Hook keeps CONNECT parked until its exact source Reply is published");
}

#[test]
fn ordinary_mutable_method_neither_dispatch_retains_child_work_for_flat_root() {
    let hook = OWNERS.split_once("fn dispatch_mutable_method_neither_suspend_aware(")
        .expect("typed Hook File dispatch").1
        .split_once("pub(super) fn dispatch_port_connect(")
        .expect("port CONNECT boundary").0;
    assert!(hook.contains("MutableMethodNeitherInputAtDevice")
        && hook.contains("invoke_suspend_aware")
        && hook.contains("suspend_dispatch_for_pump"),
        "ordinary class-hook METHOD_NEITHER must retain its File invocation on child yield");
    let root = SERVICE.split_once("'service_loop: loop {")
        .expect("flat root loop").1;
    assert!(root.contains("settle_suspended_file_pumps()"),
        "root must select and resume a generic File child after the parent stack unwinds");
}

#[test]
fn resumed_mutable_hook_result_waits_in_exact_file_row_until_hook_takes_it() {
    assert!(OWNERS.contains("PumpReturned") && OWNERS.contains("HookReturned"),
        "root must not discard the mutable Type3 input before its Hook owner observes it");
    assert!(OWNERS.contains("take_returned_hook_pump"),
        "only the exact Hook source may take the returned buffers and retire the File row");
}

#[test]
fn root_settles_hook_file_child_before_resuming_its_connect_parent() {
    let connect = SERVICE.split_once("unsafe fn settle_suspended_connect_pumps()")
        .expect("flat CONNECT settlement").1
        .split_once("unsafe fn pending_driver_start_redrive_all")
        .expect("CONNECT function boundary").0;
    let fresh_child = connect.split_once("let step = drive_one_nested_file_child_step();")
        .expect("fresh CONNECT child boundary").1;
    let hook = fresh_child.find("settle_suspended_file_pumps()")
        .expect("nested Hook File pump settlement");
    let deposit = fresh_child.find("record_suspended_connect_pump_child_step(selector, step)")
        .expect("CONNECT child receipt deposited before Hook settlement");
    let parent = fresh_child.find("redrive_recorded_connect_pump(selector)")
        .expect("CONNECT parent resume");
    assert!(deposit < hook && hook < parent,
        "the Hook child must finish its retained pump before CONNECT resumes its physical parent");
}

#[test]
fn generic_file_parent_never_skips_newer_unsettled_hook_row() {
    let selector = OWNERS.split_once("fn claim_suspended_generic_file_pump()")
        .expect("generic File selector").1
        .split_once("fn exact_generic_pump(").expect("selector boundary").0;
    assert!(selector.contains("max_by_key")
        && selector.contains("Flight::PumpReturned")
        && selector.contains("Flight::Blocked"),
        "claim must inspect the newest unsettled Hook row before an older parent");
    let retry = OWNERS.split_once("fn redrive_retryable_generic_file_pump()")
        .expect("generic File retry").1
        .split_once("pub(super) enum DispatchResult").expect("retry boundary").0;
    assert!(retry.contains("inner.id > owner.id")
        && retry.contains("Flight::PumpReturned")
        && retry.contains("Flight::Blocked"),
        "retry must not restore a parent ahead of a newer blocked or returned child");
}

#[test]
fn suspended_file_dispatch_keeps_its_move_only_invocation_in_the_exact_row() {
    assert!(OWNERS.contains("PumpSuspended(SuspendedFilePumpOwner)"));
    assert!(OWNERS.contains("struct SuspendedFilePumpOwner"));
    assert!(OWNERS.contains("invocation: SuspendedExternalFileIrpInvocation"));
    assert!(OWNERS.contains("continuation: FileDispatchContinuation"));
    assert!(OWNERS.contains("Flight::PumpSuspended"));

    let park = OWNERS
        .split_once("fn suspend_dispatch_for_pump(")
        .expect("durable File pump suspension entry")
        .1
        .split_once("fn resume_dispatch_from_pump(")
        .expect("File pump resume boundary")
        .0;
    assert!(park.contains("find(irp_id)"));
    assert!(park.contains("Flight::Dispatch"));
    assert!(park.contains("suspend_for_pump(key)"));
    assert!(park.contains("Payload::PumpSuspended(SuspendedFilePumpOwner"));
    assert!(!park.contains("finish_external_file_irp"));
    assert!(!park.contains("ExternalFileIrpOutcome::Returned"));

    let resume = OWNERS
        .split_once("fn resume_dispatch_from_pump(")
        .expect("exact File pump resume entry")
        .1
        .split_once("fn quarantine_dispatch_pump(")
        .expect("File pump quarantine boundary")
        .0;
    assert!(resume.contains("find(irp_id)"));
    assert!(resume.contains("Flight::PumpSuspended"));
    assert!(resume.contains("resume(key)"));
    assert!(resume.contains("Flight::Dispatch"));
    assert!(!resume.contains("finish_external_file_irp"));
    assert!(!resume.contains("ExternalFileIrpOutcome::Returned"));
}

#[test]
fn uncertain_pump_effect_retains_the_file_owner_without_replay() {
    let quarantine = OWNERS
        .split_once("fn quarantine_dispatch_pump(")
        .expect("File pump quarantine entry")
        .1
        .split_once("fn ")
        .expect("quarantine boundary")
        .0;
    assert!(quarantine.contains("quarantine(key)"));
    assert!(quarantine.contains("Payload::PumpSuspended"));
    assert!(!quarantine.contains("hosted_file_dispatch::invoke"));
    assert!(!quarantine.contains("finish_external_file_irp"));
}
