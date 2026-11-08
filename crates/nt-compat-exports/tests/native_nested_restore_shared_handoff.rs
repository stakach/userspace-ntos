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
    let clear = dispatch[scope..].find("clear_published_win32k_context();")
        .map(|offset| offset + scope)
        .expect("new dispatch clears the prior shared context");
    let header = dispatch[clear..].find("CallbackHeader::idle(dispatch_id, client.pi, client.tid, client.badge)")
        .expect("new dispatch publishes its callback header") + clear;
    let handoff = dispatch[scope..clear].find("capture_displaced_shared_resume(")
        .expect("old owner must retain its full shared page before the first mutation") + scope;
    let client_window = dispatch[scope..clear].find("select_win32k_client_window(client)")
        .expect("new client window selection exists") + scope;
    assert!(scope < handoff && handoff < client_window && client_window < clear && clear < header);
    assert!(dispatch[scope..clear].contains("begin_displacing_child(ticket, dispatch, client)"));
    assert!(dispatch[clear..].contains("finish_displacing_child("));

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
