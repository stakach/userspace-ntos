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

#[test]
fn native_disk_proof_can_authenticate_its_retained_precommit_child() {
    let reservation = include_str!("../../../components/ntos-executive/src/hosted_scsi_dma_reservation.rs");
    let selector_start = reservation.find("unsafe fn controller_for_scsi_child(")
        .expect("SCSI controller selector");
    let selector_end = reservation[selector_start..].find("\n/// Reserve one non-overlapping")
        .map(|offset| selector_start + offset).expect("end of controller selector");
    let selector = &reservation[selector_start..selector_end];
    syn::parse_str::<syn::ItemFn>(selector).expect("complete SCSI controller selector");
    assert!(selector.contains("pending_scsi_proof_relation("),
        "native disk proof runs before BusRelations commit; the accepted-only lookup refuses its child");
    assert!(selector.contains("parent_relation_for_pdo("),
        "later SCSI requests must keep the accepted-relation authority path");

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let issuer_start = launch.find("unsafe fn prepare_pending_scsi_proof_authority(")
        .expect("retained prepared relation authority issuer");
    let issuer_end = launch[issuer_start..].find("\n}\n")
        .map(|offset| issuer_start + offset + 2).expect("end of authority issuer");
    let issuer = &launch[issuer_start..issuer_end];
    syn::parse_str::<syn::ItemFn>(issuer).expect("complete authority issuer");
    for evidence in [
        "HostedRelationPublicationPhase::ProveNativeDisk",
        "prepared_relations",
        "prepared.children()",
        "owner.providers",
        "devnode_identity_is_started",
        "hosted_device_pointer_registration(",
    ] {
        assert!(issuer.contains(evidence),
            "authority must come from the exact retained prepared relation and provider: {evidence}");
    }

    let resolver_start = launch.find("unsafe fn pending_scsi_proof_relation(")
        .expect("one-shot precommit SCSI authority resolver");
    let resolver_end = launch[resolver_start..].find("\n}\n")
        .map(|offset| resolver_start + offset + 2).expect("end of authority resolver");
    let resolver = &launch[resolver_start..resolver_end];
    syn::parse_str::<syn::ItemFn>(resolver).expect("complete precommit SCSI resolver");
    for evidence in [
        "pending_scsi_proof_slot()", "slot.as_mut()?.claimed",
        "active.irp_id.map(IrpId::raw) != Some(request.irp_id)",
        "request.scsi_relation_generation", "request.device_id",
        "request.target_domain_id", "request.target_domain_cookie", "provider_pdo",
        "hosted_device_pointer_registration(",
    ] {
        assert!(resolver.contains(evidence),
            "one-shot resolver must bind the exact SCSI request and provider: {evidence}");
    }
    assert!(!resolver.contains("HOSTED_DEVICE_RELATION_QUERY"),
        "nested dispatch must not alias the mutably borrowed publication");

    let binder_start = launch.find("unsafe fn bind_pending_scsi_proof_irp(")
        .expect("prepared proof IRP binding");
    let binder_end = launch[binder_start..].find("\n}\n")
        .map(|offset| binder_start + offset + 2).expect("end of proof IRP binding");
    let binder = &launch[binder_start..binder_end];
    syn::parse_str::<syn::ItemFn>(binder).expect("complete proof IRP binding");
    for evidence in ["ScsiAtDevice", "prepared.irp_id()", "projection.device_id",
        "params.route.pdo", "params.route.relation_generation", "params.route.provider",
        "params.route.provider_pdo", "slot.as_mut().unwrap().irp_id"] {
        assert!(binder.contains(evidence), "prepared proof binding omitted {evidence}");
    }
    let file = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
    let bind = file.find("bind_pending_scsi_proof_irp(policy, &prepared)")
        .expect("hosted File owner binds the prepared proof IRP");
    let capture = file[bind..].find("capture_route(id, &prepared)")
        .expect("route capture follows exact proof IRP binding");
    assert!(capture > 0);

    let proof = include_str!("../../../components/ntos-executive/src/native_disk_relation.rs");
    let activate = proof.find("activate_pending_scsi_proof_authority(self.pending_authority)")
        .expect("proof activates its scoped authority");
    let dispatch = proof[activate..].find("hosted_file_owners::dispatch(")
        .expect("proof dispatch follows scoped authority activation");
    assert!(dispatch > 0);
}

#[test]
fn nested_proof_child_registration_uses_scoped_authority_before_publication_query() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source.find("unsafe fn hosted_provider_child_registration(")
        .expect("provider child registration resolver");
    let end = source[start..].find("\n/// Route a relation-owned provider child")
        .map(|offset| start + offset).expect("end of child registration resolver");
    let resolver = &source[start..end];
    syn::parse_str::<syn::ItemFn>(resolver).expect("complete child registration resolver");

    let active = resolver.find("pending_scsi_proof_slot()")
        .expect("scoped native proof registration must be considered first");
    let query = resolver.find("HOSTED_DEVICE_RELATION_QUERY")
        .expect("ordinary pending relation route remains available");
    assert!(active < query,
        "nested proof must resolve before touching the mutably borrowed publication query");
    let scoped = &resolver[active..query];
    for identity in ["child_pdo", "provider_domain", "provider.address()",
        "hosted_device_pointer_registration("] {
        assert!(scoped.contains(identity), "scoped proof route omitted {identity}");
    }
    assert!(scoped.contains("return None") || scoped.contains("then_some("),
        "an active proof with a mismatched child/provider must fail closed");
    assert!(resolver[query..].contains("hosted_accepted_pdo_provider_catalog()"),
        "ordinary accepted children must retain their catalog authority path");
}

#[test]
fn transient_proof_slot_lock_contention_cannot_refuse_the_disk_candidate() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source.find("unsafe fn pending_scsi_proof_slot()")
        .expect("proof slot snapshot");
    let end = source[start..].find("\n}")
        .map(|offset| start + offset + 2).expect("end of snapshot");
    let snapshot = &source[start..end];
    syn::parse_str::<syn::ItemFn>(snapshot).expect("complete proof slot snapshot");
    assert!(snapshot.contains("PendingScsiProofSlotLock::acquire()"),
        "the short slot snapshot must wait for its lock; None is reserved for no authority");
    assert!(!snapshot.contains("PendingScsiProofSlotLock::try_acquire()"),
        "transient contention must not be mistaken for an absent precommit relation");
}

#[test]
fn temporary_precommit_child_route_requires_the_bound_proof_irp() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = launch.find("unsafe fn hosted_provider_child_registration(")
        .expect("child registration resolver");
    let end = launch[start..].find("\n/// Route a relation-owned provider child")
        .map(|offset| start + offset).expect("end of child resolver");
    let resolver = &launch[start..end];
    assert!(resolver.contains("exact_irp: Option<IrpId>"),
        "a global child/domain lookup cannot authorize a scoped proof route by itself");
    let active = resolver.find("pending_scsi_proof_slot()")
        .expect("scoped proof lookup");
    let query = resolver.find("HOSTED_DEVICE_RELATION_QUERY")
        .expect("ordinary query fallback");
    assert!(resolver[active..query].contains("active.irp_id != exact_irp"),
        "the precommit provider registration must match the exact prepared proof IRP");

    let generic = &launch[launch.find("unsafe fn hosted_provider_child_route_by_device_id(")
        .expect("generic child route")..];
    assert!(generic.contains("hosted_provider_child_registration(device_id, route.provider_domain,"),
        "the child route must forward the exact proof IRP");
    assert!(generic.contains("hosted_driver_device_route_by_device_id_for_irp(device_id, None)"),
        "generic device routing must never inherit the temporary proof authority");
    assert!(launch.contains("request.device_id, Some(IrpId(request.irp_id))"),
        "the canonical dispatched request must carry its own IRP identity");
    let owners = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
    assert!(owners.contains("hosted_provider_child_registration(device, physical.domain,"),
        "the retained File owner must use the scoped child resolver");
    assert!(owners.contains("Some(exact_irp)"),
        "the retained proof dispatch must present its own prepared IRP identity");
    assert!(owners.contains("provider_route.is_some(),\n            prepared.irp_id(),"),
        "route capture must pass the prepared IRP identity to registration lookup");
}
