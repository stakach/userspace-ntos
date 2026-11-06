//! A retained class DeleteProcedure has its own outer retry when no unrelated IRQ arrives.
//! The pure selection and wake contracts have behavioral tests; these checks cover native wiring.

const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const DELETE: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_delete.rs");
const LANE: &str = include_str!("../../../components/ntos-executive/src/hosted_class_irp_lane.rs");

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(name).unwrap_or_else(|| panic!("missing {name}"));
    let rest = &source[start..];
    &rest[..rest.find("\n}").unwrap_or_else(|| panic!("unterminated {name}"))]
}

#[test]
fn retained_class_delete_has_an_autonomous_timer_and_outer_rearm() {
    let deadline = function_body(TIMER, "pub(super) unsafe fn next(");
    let due = function_body(MAIN, "unsafe fn timer_retry_wake_due(");
    let outer = function_body(SERVICE, "fn finalize_service_loop_work(");
    let drain = function_body(DELETE, "pub(crate) unsafe fn drain(");

    assert!(deadline.contains("hosted_driver_dynamic_delete::next_deadline("),
        "retained class delete must own a finite timer source");
    assert!(due.contains("hosted_driver_dynamic_delete::wake_due("),
        "the timer must announce retained class delete readiness");
    assert!(outer.contains("rearm_registered_active_delay_timer_with_handler(nt_handler)"),
        "outer drain must rearm after publishing its retry demand");
    assert!(drain.contains("WAKE.begin_redrive(") && drain.contains("retry_at("),
        "one service attempt must preserve a later wake without replaying a callback");
}

#[test]
fn class_delete_selection_uses_the_tested_ready_lane_policy() {
    let selection = function_body(LANE, "pub(super) unsafe fn next_pending_delete(");
    assert!(selection.contains("next_ready_pending_lane("),
        "a blocked first class worker must not hide a later ready delete");
}
