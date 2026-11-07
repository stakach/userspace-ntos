//! The diagnostic must identify the exact selected Call at the serialized outer boundary.

const PUMP: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const CAPTURE: &str = include_str!("../../../components/ntos-executive/src/exec_file_capture.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");

#[test]
fn initial_receive_can_yield_one_exact_root_child() {
    let receive = PUMP.split("pub(super) unsafe fn receive(").nth(1).unwrap();
    let preflight = receive.split("let wal_ack_pending").next().unwrap();
    assert!(preflight.contains("win32k_glue::prepare_root_ingress_yield(ch)"));
    assert!(preflight.contains("PumpMessage::hosted_root_ingress_yield(yielded)"));
    assert!(preflight.contains("root_route_probe_admission() != 0"));
    let root = RECEIVE.split("pub(crate) unsafe fn prepare_root_ingress_yield(").nth(1).unwrap()
        .split("pub(crate) unsafe fn receive_continuation_is_current").next().unwrap();
    assert!(root.contains("child.admission_sequence != runtime::root_route_probe_admission()"));
    assert!(HOSTED.contains("ROOT_ROUTE_PROBE_ADMISSION.store(probe_admission, Ordering::Release)"));
}

#[test]
fn outer_probe_observes_selected_call_without_transferring_owners() {
    let branch = SERVICE.split("if win32k_glue::pending_root_ingress_dispatch_is_some() {")
        .nth(1).unwrap().split("if win32k_glue::pending_root_maintenance_dispatch_is_some()").next().unwrap();
    assert!(branch.contains("pending_root_ingress_selector()"));
    assert!(branch.contains("selected_root_read_request(child, table)"));
    assert!(branch.contains("probe_root_ingress_read_route"));
    for forbidden in ["take_pending_root_ingress_dispatch", "import_selected_root_child",
        "bind_root_ingress", "root_reply_park", "restore_pending_root_ingress_dispatch"] {
        assert!(!branch.contains(forbidden), "diagnostic transferred an owner: {forbidden}");
    }
    let probe = CAPTURE.split("fn probe_root_ingress_read_route(").nth(1).unwrap();
    assert!(probe.contains("lookup_handle(pid, typed_handle)"));
    assert!(probe.contains("hosted_file_route_for_pid(pid, handle)"));
}
