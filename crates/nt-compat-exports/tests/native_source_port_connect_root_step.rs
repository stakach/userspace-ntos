//! The outer service loop must run a retained CONNECT child after its File frames unwind.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const LIVE: &str = include_str!("../../../components/ntos-executive/src/hosted_connect_live.rs");

#[test]
fn root_claims_and_runs_one_connect_child_before_other_provider_work() {
    let maintenance = SERVICE.split_once("unsafe fn settle_suspended_connect_pumps()")
        .expect("shared flat-root CONNECT settlement").1;
    let claim = maintenance
        .find("claim_suspended_port_connect_pump()")
        .expect("claim exact suspended CONNECT before child work");
    let child = maintenance
        .find("drive_one_nested_file_child_step()")
        .expect("one child step after File frames unwind");
    let fresh_child = maintenance.split_once("let step = drive_one_nested_file_child_step();")
        .expect("fresh CONNECT child boundary").1;
    let resume = fresh_child
        .find("redrive_recorded_connect_pump(")
        .expect("resume the exact CONNECT continuation");
    let deposit = fresh_child.find("record_suspended_connect_pump_child_step(")
        .expect("deposit the sealed child before any early root exit");
    let hook = fresh_child.find("settle_suspended_file_pumps()")
        .expect("settle nested Hook File before parent restore");
    assert!(claim < child && deposit < hook && hook < resume);
    let root = SERVICE.split_once("'service_loop: loop {").unwrap().1;
    let settle = root.find("settle_suspended_connect_pumps()")
        .expect("CONNECT settlement must run at root");
    let later = root.find("redrive_hosted_hook_forward()")
        .expect("HOOK redrive after CONNECT settlement");
    assert!(settle < later);
}

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
    let maintenance = SERVICE.split_once("unsafe fn settle_suspended_connect_pumps()")
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

#[test]
fn parked_add_device_receives_a_bounded_event_for_retryable_connect_child() {
    let root = SERVICE.split_once("'service_loop: loop {")
        .expect("root service loop").1;
    let early = root.split_once("// A nested provider can select a Receive child")
        .expect("exclusive AddDevice phase boundary").0;
    assert!(early.contains("ConnectPumpSettlement::AwaitingLocalChild"),
        "early AddDevice phase must distinguish retryable CONNECT absence from uncertainty");
    assert!(early.contains("prepare_parked_add_device_receive(&mut root_add_device_turn)"),
        "exact AddDevice turn must arm its one-shot retry before blocking");
    assert!(early.contains("defer_hosted_delivery_for_add_device"),
        "current hosted Call and Reply must remain owned while awaiting CONNECT child work");
    assert!(early.contains("component_recv!(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed))"),
        "parked root must receive timer or IRQ and retry the exact CONNECT owner");
}
