//! The outer service loop must run a retained CONNECT child after its File frames unwind.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const LIVE: &str = include_str!("../../../components/ntos-executive/src/hosted_connect_live.rs");

#[test]
fn unresolved_connect_parent_fences_later_provider_work() {
    let maintenance = SERVICE.split_once("unsafe fn settle_suspended_connect_pumps()")
        .expect("shared flat-root CONNECT settlement").1;
    let gate = maintenance
        .find("unsettled_suspended_connect_pump()")
        .expect("unresolved parked CONNECT must fence later providers");
    assert!(maintenance[gate..].contains("ConnectPumpSettlement::Retained"),
        "unresolved parent must retain its exact Reply and fence later providers");
    assert!(maintenance.contains("Progress::Blocked")
        && maintenance.contains("ConnectPumpSettlement::Blocked"),
        "uncertain or blocked pump must remain distinct from retryable child absence");
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    assert!(root.contains("ConnectPumpSettlement::Retained")
        && root.contains("ConnectPumpSettlement::Blocked"));
    assert!(root.contains("break 'service_loop"));
}

#[test]
fn repeated_yield_without_a_child_cannot_spin_the_root_loop() {
    let maintenance = SERVICE.split_once("unsafe fn settle_suspended_connect_pumps_inner()")
        .expect("shared flat-root CONNECT settlement").1;
    let maintenance = maintenance.split_once("unsafe fn pending_driver_start_redrive_all")
        .expect("CONNECT settlement function boundary").0;
    let deposited = maintenance.find("record_suspended_connect_pump_child_step(selector, step)")
        .expect("exact CONNECT selector and sealed child observation are retained before parking");
    let await_child = maintenance.find("ConnectPumpSettlement::AwaitingLocalChild")
        .expect("an empty local child pass must await a bounded root event");
    assert!(deposited < await_child, "never park with a claimed but undeposited child step");
    assert!(!maintenance.contains("consecutive_no_child_yields >= 2 { return Err(()) }"),
        "retryable local child absence must not fail-stop the exact parked owner");
}

#[test]
fn recorded_connect_receipt_is_reselected_without_running_a_new_child() {
    let selector = LIVE.split_once("fn recorded_suspended_connect_pump()")
        .expect("recorded CONNECT selector").1
        .split_once("fn ").expect("selector boundary").0;
    assert!(selector.contains("recorded_pump_selector()")
        && selector.contains("ORPHANED_CONNECT_PUMP_STEPS"),
        "only an exact Work with its sealed child receipt can be reselected");
    let settle = SERVICE.split_once("unsafe fn settle_suspended_connect_pumps()")
        .expect("root CONNECT settlement").1
        .split_once("unsafe fn pending_driver_start_redrive_all")
        .expect("CONNECT settlement boundary").0;
    assert!(settle.contains("recorded_suspended_connect_pump()")
        && settle.contains("redrive_recorded_connect_pump(selector)"),
        "a later root turn must restore an already recorded parent without running a new child");
}

