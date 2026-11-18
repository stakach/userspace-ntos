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
    let resume = &SPAWN_HOSTS[SPAWN_HOSTS.find("pub(crate) unsafe fn component_pump_continue_service_wait(")
        .expect("service-wait continuation")..];
    let resume = &resume[..resume.find("\n}\n").expect("function end")];
    assert!(resume.contains("trace_service_wait_stale"),
        "a refused continuation must print the failing predicate");
}
