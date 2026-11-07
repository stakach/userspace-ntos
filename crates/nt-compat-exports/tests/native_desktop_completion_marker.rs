#[path = "../../../components/ntos-executive/src/desktop_completion_marker.rs"]
mod desktop_completion_marker;

#[test]
fn partial_startup_snapshot_cannot_terminate_the_acceptance_boot() {
    assert!(!desktop_completion_marker::complete(191, 260));
    assert!(!desktop_completion_marker::complete(0, 0));
    assert!(desktop_completion_marker::complete(260, 260));
}
