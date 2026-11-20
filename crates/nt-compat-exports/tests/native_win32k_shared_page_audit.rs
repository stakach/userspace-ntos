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
fn the_funnel_enters_before_its_first_publish() {
    let glue = compact(GLUE);
    let enter = glue.find("audit_enter(").expect("funnel enters the authority");
    let publish = glue.find("letprevious_dispatch=publish_initial_win32k_request(")
        .expect("first request publish");
    assert!(enter < publish, "the page is held before its request is written");
    assert!(glue.contains("b\"kernel-job-complete\""));
}

#[test]
fn every_resume_reacquires_before_it_selects_and_restores() {
    let pending = compact(PENDING);
    let restore = pending.find("pub(crate)unsafefnselect_and_restore_shared_resume_snapshot(").unwrap();
    let body = &pending[restore..];
    let reacquire = body.find("audit_reacquire(").expect("resume reacquires the page");
    let select = body.find("select_win32k_client_window(client)").unwrap();
    assert!(reacquire < select, "the page is held before the client window is selected");
    let restore = body.find("restore_shared_resume_snapshot_effect(").expect("resume restores the page");
    assert!(select < restore, "the exact client window is selected before its page is restored");
    assert!(body.contains("audit_restored("), "the restore's physical evidence is acknowledged");
    assert!(NESTED.contains("b\"nested-displace\""), "a displaced parent parks before its child");
    assert!(ROOT.contains("audit_root_free("), "root ingress stages only into a free page");
    assert!(AUTHORITY.contains("pub(crate) const ENFORCING: bool"));
}

/// The body of the function that contains `needle`, from its `fn` to the next top-level `fn`.
fn enclosing_fn<'a>(source: &'a str, needle: &str) -> &'a str {
    let at = source.find(needle).unwrap_or_else(|| panic!("{needle} is present"));
    let start = source[..at].rfind("\nunsafe fn ").into_iter()
        .chain(source[..at].rfind("\npub(crate) unsafe fn "))
        .max().expect("enclosing fn");
    let end = source[at..].find("\n}\n").map_or(source.len(), |offset| at + offset);
    &source[start..end]
}

// #419 boot 44647857225: provider-wait, LPC-wait and callback resumes built their pending records
// without parking (591k not-top/empty violations). The page settles once per pump return, right
// where the pump returns, before any classification can pick an exit.
#[test]
fn every_win32k_pump_return_settles_the_page_once() {
    for (source, pump) in [
        (GLUE, "crate::spawn_hosts::component_pump(&ch);"),
        (GLUE, "component_pump_resume_user_callback(&channel);"),
        (GLUE, "component_pump_resume_provider_wait(&channel);"),
        (GLUE, "component_pump_resume_lpc_wait(&channel);"),
        (RECEIVE, "component_pump_continue_nested_restore_receive("),
        (RECEIVE, "component_pump_continue_root_maintenance("),
        (RECEIVE, "component_pump_continue_root_ingress_after_unwind("),
        (RECEIVE, "component_pump_continue_receive(&channel"),
        (RECEIVE, "component_pump_continue_service_wait("),
    ] {
        let body = enclosing_fn(source, pump);
        let after = &body[body.find(pump).unwrap()..];
        assert_eq!(after.matches("settle_pump_page(").count(), 1,
            "{pump} settles the shared page exactly once after it returns");
    }
    let pending = compact(PENDING);
    assert!(!pending.contains("fnreparked("), "no exit-by-exit park wrapper remains");
}

// The callback paths write the callback header: a reply after NtCallbackReturn, a failure reply
// on cancel or dead-client unwind. Each takes the page back first.
#[test]
fn callback_replies_are_written_only_after_the_page_is_reacquired() {
    for failure in ["write_callback_failure_reply(request, STATUS_UNSUCCESSFUL);",
        "write_callback_failure_reply(request, STATUS_THREAD_IS_TERMINATING);"] {
        let at = GLUE.find(failure).unwrap();
        let before = &GLUE[at.saturating_sub(400)..at];
        assert!(before.contains("reacquire_parked_callback_page("), "{failure} follows a reacquire");
    }
    let reply = GLUE.find("if !publish_callback_reply(").unwrap();
    let restore = GLUE[..reply].rfind("select_and_restore_shared_resume_snapshot(").unwrap();
    assert!(reply - restore < 2000, "the NtCallbackReturn reply follows its page restore");
    assert!(PENDING.contains("with_parked_payload(parked)"),
        "a payload-less callback publication restores the exact parked page");
}
