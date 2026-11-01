//! The native replay preflight must admit the coherent kind it validates in its match arm.

#[test]
fn coherent_dma_record_reaches_its_authenticated_replay_arm() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source.find("unsafe fn replay_hosted_dma_allocation_records(")
        .expect("native DMA replay function");
    let end = source[start..].find("\nunsafe fn ")
        .map(|offset| start + offset).unwrap_or(source.len());
    let replay = &source[start..end];
    syn::parse_str::<syn::ItemFn>(replay).expect("complete native DMA replay function");

    let preflight_start = replay.find("|| (kind != HOSTED_DMA_RECORD_KIND_COMMON")
        .expect("record kind preflight");
    let preflight_end = replay[preflight_start..].find("\n            {")
        .map(|offset| preflight_start + offset)
        .expect("end of record preflight");
    let preflight = &replay[preflight_start..preflight_end];
    assert!(preflight.contains("kind != HOSTED_DMA_RECORD_KIND_MAP_TRANSFER"));
    assert!(replay.contains("HOSTED_DMA_RECORD_KIND_COHERENT_MAP =>"),
        "coherent records need an authenticated replay arm");
    assert!(preflight.contains("kind != HOSTED_DMA_RECORD_KIND_COHERENT_MAP"),
        "coherent records must pass preflight before their authenticated replay arm");
}

#[test]
fn scsi_controller_window_comes_from_its_pnp_lease_not_instance_shared_slots() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_scsi_dma_reservation.rs");
    let start = source.find("unsafe fn controller_for_scsi_child(")
        .expect("SCSI controller selector");
    let end = source[start..].find("\n/// Reserve one non-overlapping")
        .map(|offset| start + offset).expect("end of controller selector");
    let selector = &source[start..end];
    syn::parse_str::<syn::ItemFn>(selector).expect("complete controller selector");
    assert!(selector.contains("hosted_pnp_pci_window_by_lease("),
        "the exact PnP context lease must supply the existing DMA window");
    assert!(selector.contains("lease.grant == Some(grant)"),
        "a live adapter lease must bind the selected window to this controller");
    for shared_slot in ["SH_DMA_COMMON_VA", "SH_DMA_COMMON_LEN", "SH_DMA_COMMON_LOGICAL"] {
        assert!(!selector.contains(shared_slot),
            "per-instance shared slots can describe a different nested device: {shared_slot}");
    }
}

#[test]
fn dma_conflict_hint_is_bound_to_exact_owner_and_adapter() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source.find("if operation == HOSTED_DMA_SERVICE_CHECK_CONFLICT {")
        .expect("root DMA conflict query");
    let end = source[start..].find("\n    if operation == HOSTED_DMA_SERVICE_QUERY_SCSI_RESERVATION")
        .map(|offset| start + offset).expect("end of conflict query");
    let query = &source[start..end];
    syn::parse_str::<syn::ExprIf>(query).expect("complete root conflict query");
    assert!(query.contains("lease.consumer_domain == domain"));
    assert!(query.contains("lease.adapter_address == Some(pdo_object)"));
    assert!(query.contains("conflicting_logical_end(")
        && query.contains("lease.owner, lease.adapter_id, words[1], words[2]"),
        "the root manager must check the exact owner's adapter, not a global reservation list");
}
