//! A restored, undelivered root child may resume only its saved Win32k receive half.

const OWNER: &str = include_str!("../../../components/ntos-executive/src/root_ingress_owner.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");

#[test]
fn unwind_receive_is_one_shot_and_retains_typed_output() {
    let owner = OWNER.split("fn continue_restored_cancelled_root_ingress(").nth(1)
        .expect("exact restored-child continuation");
    let enter = owner.find("Bundle::UnwindReceiveEntering").unwrap();
    let receive = owner.find("resume_root_ingress_after_unwind_receive(").unwrap();
    let raw = owner.find("Bundle::UnwindReceiveReturnedRaw").unwrap();
    let classify = owner.find("classify_root_ingress_unwind_result(").unwrap();
    let typed = owner.find("Bundle::UnwindReceiveReturnedTyped").unwrap();
    assert!(enter < receive && receive < raw && raw < classify && classify < typed);
    assert!(owner.contains("Bundle::UnwindReceiveQuarantined"));
    assert!(!owner.contains("component_pump_continue_receive("));
    assert!(!owner.contains("reply_hosted("));
}

#[test]
fn distinct_receive_half_checks_physical_identity_and_never_resends() {
    let wrapper = PUMP.split("fn component_pump_continue_root_ingress_after_unwind(").nth(1)
        .expect("distinct root unwind receive continuation")
        .split("unsafe fn component_pump_continue_receive_half(").next().unwrap();
    assert!(wrapper.contains("root_ingress_unwind_continuation_is_current"));
    assert!(wrapper.contains("component_pump_continue_receive_half(ch, previous, false, false, true)"));
    assert!(!wrapper.contains("component_pump_inner("));
    let preflight = RECEIVE.split("fn root_ingress_unwind_continuation_is_current(").nth(1)
        .expect("physical continuation gate");
    for required in ["channel_route", "dispatch(", "current_reply", "physical_source",
        "active_dispatch_identity", "binding(", "initial_root_dispatch.is_some_and",
        "owner.dispatch_id != expected_dispatch_id"] {
        assert!(preflight.contains(required), "missing exact gate: {required}");
    }
    let resume = RECEIVE.split("fn resume_root_ingress_after_unwind_receive(").nth(1)
        .expect("saved pump continuation");
    assert!(resume.find("root_ingress_unwind_continuation_is_current(").unwrap()
        < resume.find("select_win32k_client_window(").unwrap(),
        "physical identity must be checked before shared-client effects");
}
