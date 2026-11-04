//! Keep provider MDL retirement behind the same exact caller-graph lifetime
//! fence that protects ordinary pool frees.

#[test]
fn native_mdl_free_checks_the_retained_caller_graph() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let start = source.find("pub(super) fn mdl_release_allowed(").unwrap();
    let end = source[start..].find("\npub(super) fn unpin(").unwrap() + start;
    let admission = &source[start..end];
    assert!(
        admission.contains("caller_graph_protects_current_member_unlocked"),
        "IoFreeMdl must retain an exact source graph member until its terminal ACK"
    );
}
