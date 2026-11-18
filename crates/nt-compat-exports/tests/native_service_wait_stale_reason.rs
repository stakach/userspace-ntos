//! A refused service-wait continuation is contained to its own lane and client.
//!
//! Boot 44235934294: Explorer's dispatch 68241, nested nine callbacks deep, failed its
//! service-wait resume with only `current=0`. That trace could not say which identity
//! (route, dispatch, Reply, frame phase, running lane or external top) had moved.

const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");

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
