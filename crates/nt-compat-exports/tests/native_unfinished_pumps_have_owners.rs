//! A hosted pump that stops before its dispatch returns must never give its caller an
//! uncertain result (#420). A lane service keeps it as a typed step; a root row keeps it as a
//! typed retained state its next turn completes. The general settle instead waits at root, or
//! fences the pump for a root turn with no owner ("root-turn-unowned") or for a scheduler scope
//! ("scheduler-scope"), and the legacy pump entries settle with no owner at all. None of these
//! callers may reach them.

#[path = "support/executive_call_graph.rs"]
mod executive_call_graph;

use executive_call_graph::{executive_functions, scoped_chain, Functions};

/// An entered pump's own servicing, and the passes of a root wait for its true result, reach
/// nearly every executive service: they are not the caller's settle.
const PUMP_DRIVES: &[&str] = &["hosted_component_pump_inner", "retry_child_work",
    "resume_child_work", "root_progress_pass", "resume_scheduler_yield", "component_pump",
    "drive_entered_pump", "await_root_unguarded"];

/// Settles with no owner for an unfinished pump.
const UNOWNED: &[&str] = &["settle", "settle_parked", "settle_without_step",
    "hosted_component_pump", "hosted_component_pump_with_caller",
    "hosted_component_pump_observed"];

fn assert_owned(functions: &Functions, file: &str, start: &str) {
    for unowned in UNOWNED {
        assert!(functions.0.contains_key(*unowned), "{unowned} still exists");
        assert_eq!(scoped_chain(functions, file, start, unowned, PUMP_DRIVES), None,
            "{file}:{start} reaches the unowned settle {unowned}");
    }
}

fn reaches(functions: &Functions, file: &str, start: &str, target_file: &str, target: &str) -> bool {
    scoped_chain(functions, file, start, target, PUMP_DRIVES).is_some_and(|path|
        path.last().is_some_and(|last| last == &format!("{target_file}:{target}")))
}

#[test]
fn the_process_exit_callback_is_kept_by_its_root_row() {
    let functions = executive_functions();
    assert_owned(&functions, "hosted_driver_process_notify.rs", "dispatch_exit_notification");
    assert!(reaches(&functions, "hosted_driver_process_notify.rs", "dispatch_exit_notification",
        "hosted_service_continuation.rs", "settle_at_root"));
}

#[test]
fn lane_service_projection_controls_are_kept_for_their_service() {
    let functions = executive_functions();
    for (file, start) in [
        ("driver_launch.rs", "begin_pdo_projection"),
        ("driver_launch.rs", "create_hosted_pdo_projection"),
        ("driver_launch.rs", "dispatch_hosted_component_target"),
        ("hosted_reverse_class_projection.rs", "dispatch_configure"),
    ] {
        assert_owned(&functions, file, start);
        assert!(reaches(&functions, file, start, "hosted_service_continuation.rs", "settle_in_service"),
            "{file}:{start} keeps its pump for its lane service");
    }
}

#[test]
fn the_file_retirement_drain_keeps_its_running_control() {
    let functions = executive_functions();
    for start in ["drain", "preflight_unload"] {
        assert_owned(&functions, "hosted_file_retirements.rs", start);
        assert!(reaches(&functions, "hosted_file_retirements.rs", start,
            "hosted_service_continuation.rs", "settle_at_root"));
    }
}

#[test]
fn irq_arena_provider_services_settle_no_pump_without_an_owner() {
    // The IRQ broker serves a DPC lane in place, with keep mode off: its only owner is the
    // arena transaction, which keeps nothing. The pumps reachable under it (a DXG AddDevice
    // alias projection, a DXG worker lane's startup) refuse before entry there.
    let functions = executive_functions();
    for start in ["service_hosted_provider_callback_with_dispatch",
        "service_hosted_provider_export_returning"]
    {
        assert_owned(&functions, "driver_launch.rs", start);
    }
}
