//! #419 stage 1: every write-to-dispatch transition of the singleton win32k shared page goes
//! through the authority (audited, not yet enforcing).

const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
const PENDING: &str = include_str!("../../../components/ntos-executive/src/win32k_pending_dispatch.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");
const NESTED: &str = include_str!("../../../components/ntos-executive/src/nested_restore_owner.rs");
const ROOT: &str = include_str!("../../../components/ntos-executive/src/executor/syscall_win32k.rs");
const AUTHORITY: &str =
    include_str!("../../../components/ntos-executive/src/win32k_shared_page_authority.rs");

fn compact(source: &str) -> String {
    source.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[test]
fn the_funnel_enters_before_its_first_publish_and_parks_or_finishes_at_its_end() {
    let glue = compact(GLUE);
    let enter = glue.find("audit_enter(").expect("funnel enters the authority");
    let publish = glue.find("letprevious_dispatch=publish_initial_win32k_request(")
        .expect("first request publish");
    assert!(enter < publish, "the page is held before its request is written");
    assert!(glue.contains("b\"funnel-yield\""), "a yielding dispatch parks its exact page");
    assert!(glue.contains("b\"funnel-return\""), "a returned dispatch frees the page");
    assert!(glue.contains("b\"resumed-return\""), "a resumed dispatch frees the page on return");
    assert!(glue.contains("b\"kernel-job-complete\""));
}

#[test]
fn every_resume_reacquires_and_every_repark_parks() {
    let pending = compact(PENDING);
    let restore = pending.find("pub(crate)unsafefnselect_and_restore_shared_resume_snapshot(").unwrap();
    let body = &pending[restore..];
    let reacquire = body.find("audit_reacquire(").expect("resume reacquires the page");
    let select = body.find("select_win32k_client_window(client)").unwrap();
    assert!(reacquire < select, "the page is held before the client window is selected");
    let restore = body.find("restore_shared_resume_snapshot_effect(").expect("resume restores the page");
    assert!(select < restore, "the exact client window is selected before its page is restored");
    assert!(body.contains("audit_restored("), "the restore's physical evidence is acknowledged");
    // A resumed pump that yields again records the park at the pending record it builds.
    assert!(!RECEIVE.contains("shared_resume: capture_shared_resume_snapshot("),
        "every re-park in the receive paths goes through reparked()");
    assert!(!RECEIVE.contains("shared_resume: try_capture_exact_shared_resume_snapshot("),
        "every exact re-park in the receive paths goes through reparked_exact()");
    assert!(NESTED.contains("b\"nested-displace\""), "a displaced parent parks before its child");
    assert!(ROOT.contains("audit_root_free("), "root ingress stages only into a free page");
    assert!(AUTHORITY.contains("pub(crate) const ENFORCING: bool"));
}
