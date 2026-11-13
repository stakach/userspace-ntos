//! Native yield preflight for an overdue independent root service pass. The pure suspension
//! tests cover Reply lifetime; this checks the live pump boundary before its blocking Receive.

const RECEIVE: &str = include_str!(
    "../../../components/ntos-executive/src/win32k_receive.rs"
);
const PUMP: &str = include_str!(
    "../../../components/ntos-executive/src/component_shared_pump.rs"
);

#[test]
fn maintenance_yield_requires_due_outer_work_and_an_unencumbered_hosted_syscall() {
    let preflight = RECEIVE
        .split("pub(crate) unsafe fn prepare_root_maintenance_yield(")
        .nth(1)
        .expect("distinct root-maintenance preflight")
        .split("pub(crate) unsafe fn ")
        .next()
        .unwrap();
    for required in [
        "process_image_snapshot_work::due_for_outer",
        "ReqKind::Syscall",
        "channel.kernel_caller.is_some()",
        "registry_journal::owns_volume()",
        "snapshot.oldest.is_some()",
        "receive_child_pending()",
        "snapshot.running",
        "channel.caps.hosted_receive_yield",
    ] {
        assert!(preflight.contains(required), "missing maintenance exclusion: {required}");
    }
}

#[test]
fn maintenance_preflight_authenticates_exact_physical_and_reply_ownership() {
    let preflight = RECEIVE
        .split("pub(crate) unsafe fn prepare_root_maintenance_yield(")
        .nth(1)
        .expect("distinct root-maintenance preflight")
        .split("pub(crate) unsafe fn ")
        .next()
        .unwrap();
    for required in [
        "runtime::channel_route(channel)",
        "runtime::dispatch(route)",
        "running.dispatch",
        "running.binding",
        "runtime::physical_source(route)",
        "query_component_reply_binding",
        "binding.reply_object",
        "channel.tcb",
        "channel.fault_ep",
        "channel.pml4",
        "channel.client_generation",
        "WIN32K_DISPATCH_CLIENT_REGISTRY",
        "SuspensionOwner",
        "root_maintenance_pass()",
    ] {
        assert!(preflight.contains(required), "missing exact maintenance owner check: {required}");
    }
}

#[test]
fn maintenance_yields_after_existing_preflights_without_replaying_request() {
    let receive = PUMP
        .split("pub(super) unsafe fn receive(")
        .nth(1)
        .unwrap()
        .split("// A native SYSTEM fold")
        .next()
        .unwrap();
    let child = receive.find("prepare_receive_yield(ch)").unwrap();
    let service = receive.find("prepare_service_wait_yield(ch)").unwrap();
    let maintenance = receive.find("prepare_root_maintenance_yield(ch)")
        .expect("maintenance preflight before blocking Receive");
    assert!(child < service && service < maintenance);
    assert!(receive.contains("PumpMessage::hosted_root_maintenance_yield(yielded)"));
    assert!(!receive.contains("PumpMessage::scheduler_yield()"));
}
