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
