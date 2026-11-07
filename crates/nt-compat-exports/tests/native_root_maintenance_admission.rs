//! Native admission checks for a yielded syscall whose Reply must survive root maintenance.

const ROOT: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const OWNER: &str = include_str!("../../../components/ntos-executive/src/root_maintenance_owner.rs");

#[test]
fn maintenance_snapshot_is_durable_before_any_physical_hold_effect() {
    let admit = ROOT.split("unsafe fn admit_pending_win32k_dispatch(").nth(1)
        .expect("win32k handoff").split("unsafe fn component_suspension_cancel_scope(")
        .next().unwrap();
    for required in [
        "pending_root_maintenance_dispatch_is_some",
        "root_maintenance_owner::reserve_capacity",
        "take_pending_root_maintenance_dispatch",
        "RootReplyPark::prepare",
        "root_maintenance_owner::retain",
        "physical.acquire()",
        "admit_root_maintenance_owned",
        "reply_park.try_commit()",
    ] {
        assert!(admit.contains(required), "missing retained maintenance admission step: {required}");
    }
    assert!(admit.find("root_maintenance_owner::retain").unwrap()
        < admit.find("physical.acquire()").unwrap(),
        "the physical effect must follow the durable owner record");
    assert!(admit.find("admit_root_maintenance_owned").unwrap()
        < admit.find("reply_park.try_commit()").unwrap(),
        "the root Reply must park only after the typed continuation owns it");
}

#[test]
fn maintenance_handoff_retains_failure_and_rejects_callout_destination() {
    let handoff = ROOT.split("struct PendingWin32kHandoff {").nth(1)
        .expect("handoff result").split("unsafe fn component_suspension_cancel_scope(")
        .next().unwrap();
    assert!(handoff.contains("maintenance_ticket"));
    assert!(handoff.contains("retained_failure"));
    assert!(handoff.contains("HostedContinuationDestination::Win32k"));
    assert!(handoff.contains("root_maintenance_owner::retain"));
    assert!(handoff.contains("RootReplyPark::prepare"));
}

#[test]
fn durable_ticket_authenticates_route_dispatch_reply_and_owner() {
    for required in [
        "struct RootMaintenanceTicket",
        "route:",
        "dispatch:",
        "reply:",
        "owner:",
        "static mut ROWS",
        "fn pending(",
        "fn with_physical",
        "fn mark_admitted(",
    ] {
        assert!(OWNER.contains(required), "missing durable owner contract: {required}");
    }
}

#[test]
fn maintenance_repark_uses_a_fresh_exact_physical_owner() {
    let transfer = OWNER.split("pub(crate) unsafe fn retire_after_maintenance_repark(")
        .nth(1).expect("typed same-frame maintenance transfer");
    for required in [
        "old.index == new.index",
        "old.route != new.route",
        "old.dispatch != new.dispatch",
        "old.reply != new.reply",
        "old.root_reply != new.root_reply",
        "old.owner != new.owner",
        "can_retire(old)",
        "new_row.physical.held()",
        "State::Admitted",
        "MaintenanceWaiting",
        "retire(old)",
    ] {
        assert!(transfer.contains(required), "maintenance transfer missing exact guard: {required}");
    }
    assert!(transfer.find("MaintenanceWaiting").unwrap() < transfer.rfind("retire(old)").unwrap());
}

#[test]
fn recycled_slot_cannot_authorize_a_stale_maintenance_ticket() {
    for required in [
        "generation: u64",
        "NEXT_GENERATION",
        "checked_add(1)",
        "row.generation == ticket.generation",
        "old.generation == new.generation",
    ] {
        assert!(OWNER.contains(required), "stale maintenance ticket guard missing: {required}");
    }
}

#[test]
fn resumed_callback_remains_in_exact_owner_until_terminal_accepts_it() {
    for required in [
        "callback: Option<CallbackTransfer>",
        "fn store_callback(",
        "fn with_callback<",
        "fn take_callback(",
        "State::Resuming",
    ] {
        assert!(OWNER.contains(required), "callback owner contract missing: {required}");
    }
}

#[test]
fn deferred_maintenance_retry_selects_only_an_exact_ready_owner() {
    let scan = OWNER.split("pub(crate) unsafe fn next_ready_ticket(")
        .nth(1).expect("durable ready-ticket scan");
    for required in [
        "State::Admitted",
        "MaintenanceReady",
        "row.physical.held()",
        "active_dispatch_identity",
        "binding.reply_object",
        "frame.owner",
        "frame.key",
        "row.generation",
    ] {
        assert!(scan.contains(required), "ready scan missing exact guard: {required}");
    }
}

#[test]
fn returned_pump_has_one_typed_durable_transfer_phase() {
    for required in [
        "enum RootMaintenanceTransferPhase",
        "Returned",
        "Entering",
        "Transferred",
        "Indeterminate",
        "fn begin_result_transfer(",
        "fn refuse_result_transfer_no_effects(",
        "fn accept_result_transfer(",
        "fn mark_result_transfer_indeterminate(",
        "fn transfer_phase(",
    ] {
        assert!(OWNER.contains(required), "missing post-pump phase contract: {required}");
    }
    let store = OWNER.split("pub(crate) unsafe fn store_result(").nth(1)
        .expect("durable returned result").split("pub(crate) unsafe fn callback_token(")
        .next().unwrap();
    assert!(store.contains("RootMaintenanceTransferPhase::Returned"),
        "the one retained result must enter Returned before any pure transfer");
}

#[test]
fn accepted_or_indeterminate_transfer_cannot_reenter_returned_phase() {
    let refusal = OWNER.split("pub(crate) unsafe fn refuse_result_transfer_no_effects(")
        .nth(1).expect("typed no-effect refusal")
        .split("pub(crate) unsafe fn accept_result_transfer(").next().unwrap();
    assert!(refusal.contains("RootMaintenanceTransferPhase::Entering"));
    assert!(refusal.contains("RootMaintenanceTransferPhase::Returned"));
    let accepted = OWNER.split("pub(crate) unsafe fn accept_result_transfer(")
        .nth(1).expect("accepted pure transfer")
        .split("pub(crate) unsafe fn mark_result_transfer_indeterminate(").next().unwrap();
    assert!(accepted.contains("RootMaintenanceTransferPhase::Entering"));
    assert!(accepted.contains("RootMaintenanceTransferPhase::Transferred"));
    let uncertain = OWNER.split("pub(crate) unsafe fn mark_result_transfer_indeterminate(")
        .nth(1).expect("uncertain pure transfer")
        .split("pub(crate) unsafe fn ").next().unwrap();
    assert!(uncertain.contains("RootMaintenanceTransferPhase::Indeterminate"));
}

#[test]
fn entered_receive_keeps_its_owner_row_until_the_return_is_stored() {
    let resuming = OWNER.split("pub(crate) unsafe fn mark_resuming(").nth(1)
        .expect("receive entry keeps an admitted owner")
        .split("pub(crate) unsafe fn ").next().unwrap();
    assert!(resuming.contains("row.state = State::Resuming"));
    let store = OWNER.split("pub(crate) unsafe fn store_result(").nth(1)
        .expect("returned result is written into that owner")
        .split("fn result_kind(").next().unwrap();
    assert!(store.contains("row.state != State::Resuming || row.post_pump.is_some()"));
    assert!(store.contains("row.post_pump = Some(PostPump { result"));
    let retire = OWNER.split("pub(crate) unsafe fn can_retire(").nth(1)
        .expect("retirement gate after native return")
        .split("pub(crate) unsafe fn ").next().unwrap();
    assert!(retire.contains("RootMaintenanceTransferPhase::Transferred"),
        "the row cannot retire between receive entry and result storage");
}

#[test]
fn repeated_same_frame_repark_prepares_one_generation_bound_owner_before_acquire() {
    let prepare = OWNER.split("pub(crate) unsafe fn prepare_next_repark(").nth(1)
        .expect("atomic fresh maintenance owner preparation")
        .split("pub(crate) unsafe fn ").next().unwrap();
    for required in [
        "next_repark",
        "reserve_capacity()",
        "retain(",
        "root_reply",
    ] {
        assert!(prepare.contains(required), "fresh owner preparation missing {required}");
    }
    assert!(prepare.find("retain(").unwrap() < prepare.find("next_repark = Some(").unwrap(),
        "new owner must be durable before old owner records its exact ticket");
    assert!(!prepare.contains("physical.acquire()"),
        "native acquisition must be attempted only after both durable owners agree");
    assert!(OWNER.contains("generation: u64")
        && OWNER.contains("generation = NEXT_GENERATION.fetch_update(")
        && OWNER.contains("row.generation == ticket.generation"),
        "the retained fresh ticket must be bound to its exact generation");
}

#[test]
fn returned_result_is_selected_for_retry_without_reentering_native_receive() {
    let scan = OWNER.split("pub(crate) unsafe fn next_returned_ticket(").nth(1)
        .expect("single exact returned-result timer selector")
        .split("pub(crate) unsafe fn ").next().unwrap();
    assert!(scan.contains("State::Resuming"),
        "timer must revisit a returned row after a no-effect transfer refusal");
    assert!(scan.contains("RootMaintenanceTransferPhase::Returned"),
        "only an owned, returned pump result is retryable");
    assert!(scan.contains("RootMaintenanceTransferPhase::Transferred"),
        "an accepted transfer may still need owner retirement or backend continuation");
    assert!(scan.contains("RootMaintenanceTransferPhase::Indeterminate => false"),
        "uncertain transfer effects are never selected for replay");
}

#[test]
fn returned_service_wait_retries_only_with_exact_suspended_external_token() {
    let guard = OWNER.split("fn returned_service_wait_external_is_exact(").nth(1)
        .expect("service wait returned-result shape guard")
        .split("pub(crate) unsafe fn ").next().unwrap();
    for required in [
        "RootMaintenancePumpCompletion::ServiceReparked",
        "LanePhase::Suspended",
        "external_top",
        "yielded.token",
        "yielded.route",
        "yielded.dispatch",
        "yielded.reply",
    ] {
        assert!(guard.contains(required), "service wait guard missing {required}");
    }
    for method in [
        "pub(crate) unsafe fn next_returned_ticket(",
        "pub(crate) unsafe fn begin_result_transfer(",
        "pub(crate) unsafe fn refuse_result_transfer_no_effects(",
    ] {
        let body = OWNER.split(method).nth(1).expect("post-pump method")
            .split("pub(crate) unsafe fn ").next().unwrap();
        assert!(body.contains("returned_service_wait_external_is_exact"),
            "{method} must use the exact external service-wait shape");
    }
}

#[test]
fn returned_receive_retries_only_with_exact_nested_parent() {
    let guard = OWNER.split("fn returned_receive_parent_is_exact(").nth(1)
        .expect("receive returned-result nested parent guard")
        .split("pub(crate) unsafe fn ").next().unwrap();
    for required in [
        "RootMaintenancePumpCompletion::ReceiveReparked",
        "LanePhase::NestedExecution",
        "yielded.parent",
        "parent.route()",
        "parent.dispatch()",
        "MaintenanceResuming",
    ] {
        assert!(guard.contains(required), "receive parent guard missing {required}");
    }
    for method in [
        "pub(crate) unsafe fn next_returned_ticket(",
        "pub(crate) unsafe fn begin_result_transfer(",
        "pub(crate) unsafe fn refuse_result_transfer_no_effects(",
    ] {
        let body = OWNER.split(method).nth(1).expect("post-pump method")
            .split("pub(crate) unsafe fn ").next().unwrap();
        assert!(body.contains("returned_receive_parent_is_exact"),
            "{method} must preserve the exact nested receive parent");
    }
}
