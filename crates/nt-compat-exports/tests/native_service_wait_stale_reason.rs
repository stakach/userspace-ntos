//! A refused service-wait continuation must name the exact authority that changed.
//!
//! Boot 44235934294: Explorer's dispatch 68241, nested nine callbacks deep, failed its
//! service-wait resume with only `current=0`. That trace could not say which identity
//! (route, dispatch, Reply, frame phase, running lane or external top) had moved.

const SPAWN_HOSTS: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");

#[test]
fn service_wait_authority_reports_its_failing_predicate() {
    let check = &RECEIVE[RECEIVE.find("pub(crate) unsafe fn service_wait_continuation_is_current(")
        .expect("service-wait authority check")..];
    let check = &check[..check.find("pub(crate) unsafe fn trace_service_wait_stale(")
        .expect("stale trace follows the check")];
    assert!(check.contains("-> Result<(), ServiceWaitStale>"));
    for reason in ["ChannelRoute", "Dispatch", "Binding", "Reply", "FrameNotResuming",
        "NotRunning", "StillExternalTop"] {
        assert!(check.contains(&format!("ServiceWaitStale::{reason}")),
            "authority check must name {reason}");
    }
    let resume = &SPAWN_HOSTS[SPAWN_HOSTS.find("pub(crate) unsafe fn service_wait_continuation_authority(")
        .expect("service-wait continuation authority")..];
    let resume = &resume[..resume.find("\n}\n").expect("function end")];
    assert!(resume.contains("trace_service_wait_stale"),
        "a refused continuation must print the failing predicate");
}

const RESUME_EXECUTE: &str =
    include_str!("../../../components/ntos-executive/src/component_resume_execute.rs");

/// A refused resume must be contained to its own lane and client, not retained as an
/// uncertain `Resuming` terminal that fences fresh dispatch for every client.
#[test]
fn a_refused_service_wait_resume_is_quarantined_and_fails_only_its_client() {
    let resume = &RECEIVE[RECEIVE.find("pub(crate) unsafe fn resume_suspended_service_wait_component(")
        .expect("service-wait resume")..];
    let authority = resume.find("service_wait_continuation_authority(")
        .expect("authority checked by the resume itself");
    let restore = resume.find("select_and_restore_shared_resume_snapshot(")
        .expect("shared snapshot restore");
    assert!(authority < restore, "refuse before any client-window or shared-page effect");
    assert!(resume[..restore].contains("ServiceWaitPumpCompletion::ResumeRefused("));

    let arm = &RESUME_EXECUTE[RESUME_EXECUTE.find("ComponentPumpCompletion::ResumeRefused(status) => {")
        .expect("refused resume arm")..];
    let arm = &arm[..arm.find("ComponentPumpCompletion::Failed(status) =>").expect("next arm")];
    assert!(arm.contains(".refuse_resume_no_effects("), "quarantine only the refused lane");
    assert!(arm.contains("component_terminal::fail_refused_client("), "fail only its client");
    assert!(!arm.contains("retain_incomplete_provider"),
        "an uncertain Resuming terminal would fence every client");
}
