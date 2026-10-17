//! A child START must retain bus-relation admission through terminal completion.

#[test]
fn deferred_bus_child_never_falls_through_after_relation_terminal() {
    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let batch = start
        .split("pub(crate) struct OwnedHostedPnpStartBatch {")
        .nth(1)
        .expect("missing owned START batch")
        .split("pub(crate) enum SingleStartEvidence")
        .next()
        .unwrap();
    let prepare = start
        .split("unsafe fn prepare_current_hosted_devnode<")
        .nth(1)
        .expect("missing hosted devnode resource preparation")
        .split("enum HostedPnpDevnodeProgress")
        .next()
        .unwrap();

    assert!(
        start.contains("hosted_bus_reported_device_id(devnode.instance_id)"),
        "bus-reported PDO must remain the authority for child START"
    );
    assert!(
        batch.contains("pending_bus_relation_devnode: Option<usize>"),
        "the batch must retain which devnode was deferred by a bus relation"
    );
    assert!(
        start.contains("HostedPnpDevnodeProgress::BusRelationPending")
            && start.contains("self.pending_bus_relation_devnode = Some(devnode_index)"),
        "a pending relation must keep the same START owner until terminal observation"
    );
    assert!(
        start.contains("self.pending_bus_relation_devnode == Some(devnode_index)"),
        "a retried START must carry the retained bus-PDO requirement"
    );
    let missing_after_terminal = prepare
        .find("require_accepted_bus_pdo && bus_pdo.is_none()")
        .expect("a completed relation without the accepted child PDO must fail closed");
    let empty_fallback = prepare
        .find("resource_plan: PreparedHostedResourcePlan::None")
        .expect("root device fallback must be explicit");

    assert!(missing_after_terminal < empty_fallback);
    assert!(prepare.contains("NtStatus::INVALID_DEVICE_REQUEST"));
    assert!(start.contains("driver_launch::hosted_bus_relation_pending()"));
}

#[test]
fn unrelated_pending_relation_does_not_turn_a_root_devnode_into_a_bus_child() {
    let start = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
    let pending = start
        .split("HostedPnpDevnodeProgress::BusRelationPending { require_accepted_bus_pdo } => {")
        .nth(1)
        .expect("missing pending relation handling");
    let pending = &pending[..pending.find("return Some(").unwrap()];
    assert!(
        pending.contains("if require_accepted_bus_pdo"),
        "a global relation wait must retain a PDO requirement only for an actual bus child"
    );

    let start_one = start
        .split("unsafe fn start_one_devnode<")
        .nth(1)
        .expect("missing hosted devnode START")
        .split("let prepared = match prepare_current_hosted_devnode(")
        .next()
        .unwrap();
    assert!(
        start_one.contains("BusRelationPending { require_accepted_bus_pdo }"),
        "the deferred owner must carry its preexisting bus dependency through the wait"
    );
}
