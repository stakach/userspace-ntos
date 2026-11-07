//! Native diagnostics must observe the exact parked callback owner without changing its state.

const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");

#[test]
fn periodic_census_reads_pure_oldest_owner_snapshot() {
    let census = GLUE.split("pub(crate) fn print_callback_owner_census()").nth(1).unwrap()
        .split("unsafe fn callback_frame_can_resume").next().unwrap();
    assert!(census.contains("nt_user_callback::oldest_active_callback_owner("));
    assert!(census.contains("top-state="));
    assert!(census.contains("owner.lane.generation"));
    assert!(!census.contains("callback_frame_can_resume("));
    assert!(!census.contains("USER_CALLBACK_ACTIVE).top()"));
    assert!(MAIN.split("pub(crate) fn census_tick_static(").nth(1).unwrap()
        .split("fn print_add_device_rollback_census").next().unwrap()
        .contains("win32k_glue::print_callback_owner_census()"));
}

#[test]
fn selected_wm_create_gate_trace_is_bounded_and_diagnostic_only() {
    let trace = GLUE.split("if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC\n                && window_message == 0x0001\n                && USER_CALLBACK_WM_CREATE_GATE_TRACES").nth(1).unwrap()
        .split("if callback_trace {").next().unwrap();
    assert!(trace.contains("fetch_add(1, Ordering::Relaxed) < 16"));
    assert!(trace.contains("request.payload_reference_offset"));
    assert!(trace.contains("request.input_length"));
    assert!(trace.contains("sas_session_before"));
    assert!(!trace.contains("core::ptr::write"));
    assert!(!trace.contains("abort_controlled_user_callbacks"));
}
