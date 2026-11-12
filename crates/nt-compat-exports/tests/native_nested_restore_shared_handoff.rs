//! Boot 42474924020: dispatch 92 replaced dispatch 91's callback header during a yielded
//! nested receive. The old owner must retain its full shared publication before the overwrite.

fn source(name: &str) -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src")
            .join(name),
    ).unwrap()
}

#[test]
fn nested_receive_retains_shared_publication_before_foreign_header_write() {
    let dispatch = source("win32k_glue.rs");
    let scope = dispatch.find("unsafe fn win32k_dispatch_wide_observed_inner(")
        .expect("single win32k dispatch funnel exists");
    let publish = dispatch[scope..].find("publish_initial_win32k_request(")
        .map(|offset| offset + scope)
        .expect("new dispatch publishes through the single fresh-page writer");
    let handoff = dispatch[scope..publish].find("capture_displaced_shared_resume(")
        .expect("old owner must retain its full shared page before the first mutation") + scope;
    let client_window = dispatch[scope..publish].find("select_win32k_client_window(client)")
        .expect("new client window selection exists") + scope;
    assert!(scope < handoff && handoff < client_window && client_window < publish);
    assert!(dispatch[scope..publish].contains("begin_displacing_child(ticket, dispatch, client)"));
    assert!(dispatch[publish..].contains("finish_displacing_child("));
    let writer = dispatch.find("unsafe fn publish_initial_win32k_request(").unwrap();
    let writer_body = &dispatch[writer..scope];
    let clear = writer_body.find("clear_published_win32k_context();").unwrap();
    let header = writer_body.find("CallbackHeader::idle(dispatch_id, client.pi, client.tid, client.badge)").unwrap();
    assert!(clear < header && writer_body.contains("SH_REQ_SSN"));

    let owner = source("nested_restore_owner.rs");
    assert!(owner.contains("fn capture_displaced_shared_resume("),
        "the exact receiving row must own the displaced snapshot");
    assert!(owner.contains("next.snapshot.shared_resume"),
        "the returned receive must use its retained snapshot");
    assert!(owner.contains("row.shared_leases.displace(identity"));
    assert!(owner.contains("row.shared_leases.acknowledge_restore("));
}

#[test]
fn nested_restore_settlement_does_not_recapture_mutable_shared_page() {
    let receive = source("win32k_receive.rs");
    let start = receive.find("fn settle_nested_restore_result(").unwrap();
    let end = receive[start..].find("fn resume_suspended_nested_restore_receive(").unwrap() + start;
    assert!(!receive[start..end].contains("capture_shared_resume_snapshot("),
        "settlement after nested dispatch may only use the exact retained snapshot");
}

#[test]
fn uncertain_parent_restore_retains_child_without_a_pending_pump_owner() {
    let dispatch = source("win32k_glue.rs");
    let scope = dispatch.find("if let Some(ticket) = displaced_parent {\n        let child_suspended")
        .expect("child handoff follows all durable pending publications");
    let end = dispatch[scope..].find("if nested_user_callback {").unwrap() + scope;
    let handoff = &dispatch[scope..end];
    assert!(handoff.contains("let child_has_durable_pump ="),
        "only yield paths with a full pending PumpResult can own it outside the row");
    assert!(handoff.contains("if !child_has_durable_pump {\n                crate::nested_restore_owner::retain_quarantined_child_pump("),
        "terminal, callback, provider-wait and LPC-wait children need a retained receipt");
    assert!(!handoff.contains("if !terminal && !child_suspended"),
        "terminal does not mean its returned pump receipt may be dropped");
}

#[test]
fn uncertain_parent_restore_retains_early_kernel_job_result() {
    let dispatch = source("win32k_glue.rs");
    let start = dispatch.find("if let Some(execute) = kernel_job {").unwrap();
    let end = dispatch[start..].find("ch.caps.hosted_receive_yield").unwrap() + start;
    let job = &dispatch[start..end];
    let compact: String = job.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(compact.contains("retain_quarantined_child_job_result(ticket,result,dispatch,client,)"),
        "a completed kernel job has no PumpResult pending slot if parent restore refuses");

    let owner = source("nested_restore_owner.rs");
    assert!(owner.contains("quarantined_child_job_result: Option<QuarantinedChildJobResult>"));
}

#[test]
fn fresh_win32k_dispatch_waits_for_returned_receive_page_capture() {
    let dispatch = source("win32k_glue.rs");
    let start = dispatch.find("unsafe fn win32k_dispatch_wide_observed_inner(").unwrap();
    let end = dispatch[start..].find("let active_parent =").unwrap() + start;
    assert!(dispatch[start..end].contains("component_shared_publication_is_busy()"),
        "a parked physical lane can still have an unsettled Receive page and Reply");

    let service = source("service_sec_image.rs");
    assert!(service.contains("fn component_shared_publication_is_busy()"));
    assert!(service.contains(".fresh_dispatch_busy()"));
}

#[test]
fn resumed_wait_restores_exact_callback_page_before_reentering_pump() {
    let pending = source("win32k_pending_dispatch.rs");
    let dispatch = source("win32k_glue.rs");
    for (kind, pending_type, suspend, pending_store, resume, pump) in [
        ("provider", "PendingProviderWaitDispatch", "if pr.provider_wait_suspended {\n        let page =",
            "PROVIDER_WAIT_LAST_PUMP_SUSPENDED.store", "resume_suspended_provider_wait_component(",
            "component_pump_resume_provider_wait(&channel)"),
        ("LPC", "PendingLpcWaitDispatch", "if pr.lpc_wait_suspended {\n        let Some(request) =",
            "LPC_WAIT_LAST_PUMP_SUSPENDED.store", "resume_suspended_lpc_wait_component(",
            "component_pump_resume_lpc_wait(&channel)"),
    ] {
        let declaration = pending.split_once(&format!("struct {pending_type} {{"))
            .and_then(|(_, rest)| rest.split_once("\n}").map(|(body, _)| body))
            .expect("retained wait dispatch type");
        assert!(declaration.contains("shared_resume: Option<SharedResumeSnapshot>"),
            "{kind} wait must retain its complete callback header, payload and request owner before another dispatch can overwrite the singleton page");

        let suspend_body = dispatch.rsplit_once(suspend)
            .and_then(|(_, rest)| rest.split_once(pending_store).map(|(body, _)| body))
            .expect("wait suspension publishes a pending owner");
        assert!(suspend_body.contains("try_capture_exact_shared_resume_snapshot(")
            && suspend_body.contains("shared_resume"),
            "{kind} wait must capture its exact shared page before publishing a suspended owner");

        let resume_body = dispatch.split_once(resume)
            .and_then(|(_, rest)| rest.split_once(pump).map(|(before_pump, _)| before_pump))
            .expect("wait resume enters the existing pump");
        assert!(resume_body.contains("pending.shared_resume")
            && resume_body.contains("select_and_restore_shared_resume_snapshot("),
            "{kind} wait must restore its exact retained page before the pump may yield a nested receive");
        assert!(!resume_body.contains("CallbackHeader::idle("),
            "a resumed wait cannot synthesize a callback header from request cells");
        assert!(!resume_body.contains("PumpCompletion::Failed("),
            "pre-entry identity or channel refusal must retain its pending wait record");
    }
}

#[test]
fn refused_wait_page_restore_retains_the_exact_pending_owner() {
    let pending = source("win32k_pending_dispatch.rs");
    let execute = source("component_resume_execute.rs");
    assert!(pending.contains("RetainedFailure(PendingProviderWaitDispatch, i32)")
        && pending.contains("RetainedFailure(PendingLpcWaitDispatch, i32)"),
        "a refused page restore must carry its original pending wait instead of dropping it into a status");
    assert!(execute.contains("ComponentPumpCompletion::FailedRetained(")
        && execute.contains("Some(next),"),
        "the blocked terminal must retain the exact pending snapshot alongside its lane and Reply");
}
