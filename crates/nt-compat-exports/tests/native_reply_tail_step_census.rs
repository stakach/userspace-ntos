//! Exercise the actual native reply-tail step census.
use std::sync::Mutex;

static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().extend_from_slice(bytes); }
fn disk_census_ticks() -> u64 { 0 }
mod serial_records { pub fn is_root_executor() -> bool { true } }

#[allow(dead_code)] // The root glue is exercised only through its census print.
#[path = "../../../components/ntos-executive/src/reply_tail_step_census.rs"]
mod census;

use census::{Step, StepCensus, StepCost};

#[test]
fn idle_ticks_are_the_calls_that_reported_no_progress() {
    let mut steps = StepCensus::new();
    steps.record(Step::IoManager, 700, Some(false));
    steps.record(Step::IoManager, 300, Some(true));
    steps.record(Step::IoManager, 200, Some(false));
    assert_eq!(steps.cost(Step::IoManager),
        StepCost { calls: 3, progressed: 1, ticks: 1_200, idle_ticks: 900 });
}

#[test]
fn a_step_without_a_progress_result_reports_only_calls_and_ticks() {
    let mut steps = StepCensus::new();
    steps.record(Step::DirectoryWork, 40, None);
    assert_eq!(steps.cost(Step::DirectoryWork),
        StepCost { calls: 1, progressed: 0, ticks: 40, idle_ticks: 0 });
}

#[test]
fn the_census_names_only_steps_that_ran_in_mtick() {
    let mut steps = StepCensus::new();
    steps.record(Step::LifecyclePump, 3_000_000, Some(false));
    steps.record(Step::IrpDrain, 5_000_000, Some(true));
    let mut out = String::new();
    steps.write_census(&mut out).unwrap();
    assert_eq!(out, "[census] reply-tail-step calls/progressed/Mtick/idle-Mtick: \
        lifecycle-pump=1/0/3/3 irp-drain=1/1/5/0\n");
}

#[test]
fn the_root_glue_hands_back_each_step_result() {
    let started = census::begin();
    assert_eq!(census::end(Step::Backends, started, 7usize), 7);
    assert!(census::end(Step::ReinitCallbacks, started, true));
    census::end(Step::HostedReady, started, ());
    census::print_census();
    let output = String::from_utf8(OUTPUT.lock().unwrap().clone()).unwrap();
    assert!(output.contains(" backends=1/1/0/0") && output.contains(" reinit-callbacks=1/1/0/0")
        && output.contains(" hosted-ready=1/0/0/0"), "{output}");
}
