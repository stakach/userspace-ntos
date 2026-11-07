//! The live Winlogon callback can park an executive-owned service wait inside a nested SSDT.
//! Keep that yield distinct from general hosted receive and preserve the callback token.

const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");
const HOSTS: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn nested_callback_gets_only_exact_service_wait_yield() {
    let setup = GLUE
        .split("ch.caps.hosted_receive_yield =")
        .nth(1)
        .unwrap()
        .split("let nested_restore_owner")
        .next()
        .unwrap();
    assert!(setup.contains("ch.caps.nested_service_wait_yield"));
    assert!(setup.contains("nested_user_callback && outer_callback.is_some()"));
    assert!(setup.contains("ch.initial_root_dispatch = ch.caps.hosted_receive_yield"));
    let preflight = RECEIVE
        .split("pub(crate) unsafe fn prepare_service_wait_yield(")
        .nth(1)
        .unwrap()
        .split("pub(crate) unsafe fn ")
        .next()
        .unwrap();
    assert!(preflight.contains("channel.caps.nested_service_wait_yield"));
    assert!(preflight.contains("runtime::parked_service_wait_identity(route, dispatch)"));
    assert!(HOSTS.contains("pub nested_service_wait_yield: bool"));
}

#[test]
fn nested_service_wait_keeps_callback_and_root_reply_owned() {
    let finish = GLUE
        .split("if let Some(yielded) = pr.service_wait_yield {")
        .last()
        .unwrap()
        .split("if let Some(yielded) = pr.maintenance_yield")
        .next()
        .unwrap();
    assert!(finish.contains("callback_token: outer_callback.map(|(_, token)| token)"));
    let nested = GLUE
        .split("if nested_user_callback {")
        .last()
        .unwrap()
        .split("if registered_client")
        .next()
        .unwrap();
    assert!(nested.contains("pr.service_wait_yield.is_some()"));
    let admission = SERVICE
        .split("unsafe fn service_wait_admit_current(")
        .nth(1)
        .unwrap()
        .split("unsafe fn ")
        .next()
        .unwrap();
    assert!(admission.contains("NestedWaitTransfer::InCallback"));
    assert!(admission.contains("service_wait_admit_with_transfer"));
    assert!(admission.contains("reply_park.try_commit()"));
    let handoff = SERVICE
        .split("} else if let Some(pending) = win32k_glue::take_pending_service_wait_dispatch() {")
        .nth(1)
        .unwrap()
        .split("} else if let Some(pending)")
        .next()
        .unwrap();
    assert!(handoff.contains("restore_pending_service_wait_dispatch(pending)"));
    assert!(handoff.contains("RetainedWaitAdmission::Indeterminate => retained_failure = true"));
}

#[test]
fn resumed_nested_wait_keeps_its_exact_callback_origin() {
    let authority = RECEIVE
        .split("pub(crate) unsafe fn service_wait_continuation_is_current(")
        .nth(1)
        .unwrap()
        .split("pub(crate) unsafe fn ")
        .next()
        .unwrap();
    assert!(authority.contains("channel.caps.nested_service_wait_yield"));
    assert!(authority.contains("runtime::service_wait_resume_completed_exact("));
    let resume = RECEIVE
        .split("pub(crate) unsafe fn resume_suspended_service_wait_component(")
        .nth(1)
        .unwrap()
        .split("pub(crate) unsafe fn ")
        .next()
        .unwrap();
    assert!(resume.contains("let nested = pending.snapshot.callback_token.is_some()"));
    assert!(resume.contains("callback_token: pending.snapshot.callback_token"));
    assert!(resume.contains("nested_user_callback: nested"));
    for call in ["capture_lpc_wait_repark(", "complete_resumed_dispatch("] {
        let argument = resume.split(call).nth(1).unwrap();
        assert!(
            argument.contains("pending.snapshot.client,\n            nested,"),
            "{call} must preserve the nested callback origin"
        );
    }
}
