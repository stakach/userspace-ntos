//! A pump returns to the root only with its lane parked, terminated, or as a typed
//! continuation the root drives (boot 44542922018).
//!
//! Sequence: `hook-file-resume` 14 (alias invocation returned), 15 (exit), 18 (retryable
//! refusal), 3 (recorded redrive returned). The pump's child receive had yielded twice for
//! scheduler work, so its continuation was `ChildWorkPending { SchedulerYield }` with dispatch
//! worker lane 40 still running. Settlement reported Retained, the root took an idle receive, and
//! ingress refused it (`ownership-ingress-execution-busy`) and the loop exited (`ingress-retained`).

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Turn { Progressed, Retained }

/// Model: the File pump's continuation either parked its lane (true Retained) or yielded for
/// scheduler work with the lane running. `classify` is the settlement mapping under test.
fn run(classify: impl Fn(bool) -> Turn) -> Result<(), &'static str> {
    let mut lane_running = true; // after stage 14/15/18/3
    let mut scheduler_yields_left = 2;
    for _ in 0..16 {
        if !lane_running { return Ok(()); }
        match classify(lane_running) {
            Turn::Progressed => {
                // The root drives the continuation: scheduler service, then the lane's receive.
                if scheduler_yields_left > 0 { scheduler_yields_left -= 1; } else { lane_running = false; }
            }
            Turn::Retained => return Err("idle receive refused: ownership-ingress-execution-busy"),
        }
    }
    Err("no progress")
}

#[test]
fn reporting_a_scheduler_yield_as_retained_reproduces_the_exit() {
    assert!(run(|_| Turn::Retained).is_err());
}

#[test]
fn a_scheduler_yielded_continuation_is_driven_until_the_lane_parks() {
    assert_eq!(run(|running| if running { Turn::Progressed } else { Turn::Retained }), Ok(()));
}

#[test]
fn the_native_mapping_drives_scheduler_yielded_continuations() {
    let owners = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
    let resume = owners
        .split("unsafe fn resume_generic_file_pump(")
        .nth(1)
        .unwrap()
        .split("\n/// Seal one selected child observation")
        .next()
        .unwrap();
    assert!(resume.contains("scheduler_yielded = continuation.scheduler_yield_pending();"));
    assert!(resume.contains("GenericFilePumpDrive::SchedulerYielded"));
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    assert!(service.contains("| Progress::SchedulerYielded =>\n            FilePumpTurn::Progressed"));
    let scheduler = include_str!("../../../components/ntos-executive/src/component_scheduler.rs");
    assert!(scheduler.contains("self.retryable && self.mode == PendingReceiveMode::SchedulerYield"));
    let flow = include_str!("../../../components/ntos-executive/src/executor/flow.rs");
    let wait = flow.split("pub(super) unsafe fn wait_retained_settlement(").nth(1).unwrap();
    let running = wait.find("hold_snapshot().running.is_some()").expect("running-lane guard");
    let receive = wait.find("let received = match receive(").unwrap();
    assert!(running < receive, "never an idle receive while a lane runs");
}
