//! The video-port START intercept runs the miniport's HwFindAdapter on a hosted pump (#420).
//! When that pump stops unfinished where its caller cannot wait, the START IRP must answer
//! pending and keep the pump, and its true result must be published later as the IRP's
//! ordinary completion. A legacy settle instead fenced the pump, retired the instance and
//! answered an uncertain result for a FindAdapter that was still running.

#[path = "support/executive_call_graph.rs"]
mod executive_call_graph;

use executive_call_graph::{exact_chain, executive_functions, Functions};

const INTERCEPT: &str = "dispatch_video_pnp_irp_for_instance";

/// Entered pumps: their native servicing is not the intercept's settle.
const PUMP_DRIVES: &[&str] = &["hosted_component_pump_inner", "retry_child_work",
    "resume_child_work", "root_progress_pass"];

fn chain(functions: &Functions, target: &str) -> Option<Vec<String>> {
    exact_chain(functions, "driver_launch.rs", INTERCEPT, target, PUMP_DRIVES)
}

#[test]
fn the_video_start_intercept_never_settles_its_pump_without_an_owner() {
    let functions = executive_functions();
    // The legacy entries settle an unfinished pump with no owner: a root wait, or a fence and
    // an uncertain result.
    for legacy in ["hosted_component_pump", "hosted_component_pump_with_caller",
        "settle_without_step"]
    {
        assert!(functions.0.contains_key(legacy), "{legacy} still exists");
        assert_eq!(chain(&functions, legacy), None,
            "the video START intercept reaches the legacy pump settle {legacy}");
    }
}

#[test]
fn the_video_start_intercept_keeps_its_pump_with_the_backend_irp_operation() {
    // nt-video-miniport find_adapter proves the START answer for each pump outcome; this pins
    // that the intercept keeps an unfinished pump where the backend publishes its return.
    let functions = executive_functions();
    let reaches = |file: &str, name: &str| chain(&functions, name)
        .is_some_and(|path| path.last().is_some_and(|last| last == &format!("{file}:{name}")));
    assert!(reaches("hosted_backend_irp_operations.rs", "dispatch"),
        "the START IRP is admitted, kept and published as a backend IRP operation");
    assert!(reaches("hosted_backend_pumps.rs", "keep_channel"),
        "an unfinished FindAdapter pump is kept for the backend's redrive");
}
