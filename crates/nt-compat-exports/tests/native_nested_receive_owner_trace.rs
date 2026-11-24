//! The stationary nested receive trace must name retained owners without changing their state.

const PUMP: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
const ROOT: &str = include_str!("../../../components/ntos-executive/src/main.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let tail = source.split_once(start).unwrap_or_else(|| panic!("missing {start}")).1;
    tail.split_once(end).unwrap_or_else(|| panic!("missing {end}")).0
}

#[test]
fn enclosed_wait_traces_exact_parked_reply_and_read_only_receive_candidates() {
    let receive = between(PUMP, "unsafe fn parked_dispatch_wait_yield(",
        "static PARKED_DISPATCH_YIELDS:");
    assert!(receive.contains("runtime::parked_service_wait_identity(route, dispatch)"));
    assert!(receive.contains("trace_enclosed_dispatch_wait(ch, route, dispatch, wait)"));
    let trace = between(PUMP, "unsafe fn trace_enclosed_dispatch_wait(",
        "static PARKED_DISPATCH_YIELDS:");
    for required in ["parked.0", "parked.1", "ch.tcb", "ch.reply_cap",
        "dispatch.lane().generation", "runtime::hold_snapshot().running",
        "trace_enclosed_receive_candidates(n)", "TRACED.fetch_add(1"] {
        assert!(trace.contains(required), "missing retained wait evidence: {required}");
    }
    assert!(trace.contains("if n > 16 && !n.is_power_of_two() { return; }"));
    let candidates = between(PUMP, "fn trace_enclosed_receive_candidates(",
        "static PARKED_DISPATCH_YIELDS:");
    assert!(candidates.contains("ACTIVE_IRP_SNAPSHOTS.iter()"));
    assert!(candidates.contains("ACTIVE_SYSCALL_SNAPSHOTS.iter()"));
    assert!(candidates.contains("slot.sequence.load(Ordering::Acquire) != sequence"));
    assert!(!trace.contains("resume_service_wait"));
}

#[test]
fn directory_request_trace_retains_ring_identity_without_borrowing_ingress() {
    let helper = between(ROOT, "fn trace_ob_owned_directory(",
        "impl nt_object_client::Backend for ObChan");
    for required in ["channel.completion_inbox.active_request()",
        "channel.completion_inbox.has_parked_owned()", "channel.owned_capture.is_some()"] {
        assert!(helper.contains(required), "missing owned request context: {required}");
    }
    assert!(!helper.contains("hold_snapshot()"));
    let owned = between(ROOT, "impl nt_object_client::OwnedBackend for ObChan", 
        "static mut OBJECT_CLIENT_PTR:");
    assert!(owned.contains("OB_OP_CREATE_DIRECTORY_HANDLE"));
    assert!(owned.contains("OB_OP_OPEN_DIRECTORY_HANDLE"));
    assert!(owned.contains("OB_DIRECTORY_TRACE_REQUEST.store(request_id"));
    assert!(owned.contains("OB_DIRECTORY_TRACE_REQUEST.load(Ordering::Acquire) == request_id"));
    assert!(owned.contains("trace_ob_owned_directory(&self.0, request_id, 0, b\"poll\""));
    assert!(owned.contains("if result.is_some()"));
    assert!(!owned.contains("request_id == 167"));
}
