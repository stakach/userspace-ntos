//! Source contract for the exact root-maintenance pump handoff. The pure lane/Reply lifetime
//! behavior is tested in nt-component-suspension; this guards the native message boundary.

const PENDING: &str = include_str!(
    "../../../components/ntos-executive/src/win32k_pending_dispatch.rs"
);
const PUMP: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const WIN32K: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");

#[test]
fn maintenance_yield_carries_one_exact_owner_and_shared_snapshot() {
    let yield_type = PENDING
        .split("pub(crate) struct RootMaintenanceYield {")
        .nth(1)
        .expect("distinct root-maintenance yield")
        .split('}')
        .next()
        .unwrap();
    for field in ["route:", "dispatch:", "reply:", "owner:", "captured_pass:"] {
        assert!(yield_type.contains(field), "maintenance yield must retain {field}");
    }
    let pending_type = PENDING
        .split("pub(crate) struct PendingRootMaintenanceDispatch {")
        .nth(1)
        .expect("separate retained maintenance dispatch")
        .split('}')
        .next()
        .unwrap();
    assert!(pending_type.contains("yielded: RootMaintenanceYield"));
    assert!(pending_type.contains("snapshot: SuspendedPumpSnapshot"));
    assert!(PENDING.contains("ROOT_MAINTENANCE_PENDING_DISPATCH"));
}

#[test]
fn maintenance_yield_survives_each_pump_result_layer_without_becoming_completion() {
    for boundary in ["struct PumpMessage", "struct PumpLoopOutcome", "struct PumpResult"] {
        let fields = PUMP.split(boundary).nth(1).expect(boundary).split('}').next().unwrap();
        assert!(fields.contains("maintenance_yield:"), "missing {boundary} handoff");
    }
    assert!(PUMP.contains("fn hosted_root_maintenance_yield("));
    let loop_body = PUMP.split("unsafe fn component_pump_loop(").nth(1).unwrap();
    assert!(loop_body.contains("msg.maintenance_yield"));
    assert!(loop_body.contains("outcome.maintenance_yield = Some(yielded)"));
    assert!(PUMP.contains("maintenance_yield: outcome.maintenance_yield"));
    assert!(PUMP.contains("outcome.maintenance_yield.is_some()"),
        "a checkpoint must not be reported as a completed dispatch");
}

#[test]
fn initial_win32k_dispatch_owns_maintenance_snapshot_until_root_transfer() {
    assert!(WIN32K.contains("if let Some(yielded) = pr.maintenance_yield"));
    assert!(WIN32K.contains("ROOT_MAINTENANCE_PENDING_DISPATCH"));
    assert!(WIN32K.contains("Some(PendingRootMaintenanceDispatch {"));
    assert!(WIN32K.contains("snapshot: SuspendedPumpSnapshot {"));
    assert!(WIN32K.contains("pr.maintenance_yield.is_none()"),
        "suspended maintenance dispatch must retain its registered client");
}
