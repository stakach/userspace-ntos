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
