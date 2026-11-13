//! An initial native relation's WAL may use only its retained, prepublication SCSI child.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const DISK: &str = include_str!("../../../components/ntos-executive/src/native_disk_relation.rs");
const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source.find(start).expect("start marker");
    let tail = &source[from..];
    &tail[..tail.find(end).expect("end marker")]
}

#[test]
fn initial_relation_wal_dispatch_uses_its_exact_retained_scsi_authority() {
    let resolver = section(LAUNCH,
        "unsafe fn retained_native_storage_relation_publication_mut()",
        "pub(crate) unsafe fn native_storage_relation_recheck_id()");
    assert!(resolver.contains("proof.route() == route"),
        "a retained proof must belong to the exact mounted route");

    let authority = section(LAUNCH,
        "unsafe fn retained_native_storage_wal_scsi_authority(",
        "pub(crate) unsafe fn native_storage_relation_recheck_id()");
    syn::parse_str::<syn::ItemFn>(authority).expect("complete WAL authority resolver");
    for evidence in ["publication.native_disk_proof", "proof.route() != route",
        "proof.pending_authority()", "publication.parent_relation", "publication.claim",
        "native_disk_relation::initial_native_storage_route() != Some(route)"] {
        assert!(authority.contains(evidence), "missing retained relation evidence: {evidence}");
    }
    assert!(!authority.contains("hosted_accepted_pdo_provider_catalog()"),
        "an unpublished child cannot borrow generic accepted-catalog authority");

    let proof = section(DISK, "impl NativeDiskProof {", "pub(crate) fn native_storage_route()");
    assert!(proof.contains("fn pending_authority(&self) -> Option<PendingScsiProofAuthority>"));
    assert!(proof.contains("HandoffPhase::NativeMounted"));
    assert!(proof.contains("self.entered.is_none()") && proof.contains("self.reserved.is_none()"));
    assert!(proof.contains("fn route(&self) -> NativeStorageRoute"));

    let dispatch = &BLOCK[BLOCK.find("pub(super) unsafe fn service() -> usize {")
        .expect("mounted block service")..];
    assert!(dispatch.contains("retained_native_storage_wal_scsi_authority(route)"));
    assert!(dispatch.contains("activate_pending_scsi_proof_authority("));
    assert!(dispatch.find("activate_pending_scsi_proof_authority(").unwrap()
        < dispatch.find("hosted_file_owners::dispatch(").unwrap(),
        "the exact scope must be active before File route capture");
    assert!(dispatch.find("hosted_file_owners::dispatch(").unwrap()
        < dispatch.find("drop(_authority_guard)").unwrap(),
        "the scoped authority must survive only the nested dispatch");
    assert!(dispatch.contains("claim.release_unentered()"),
        "an unavailable authority must retain the unentered WAL work");
}

#[test]
fn refreshing_relation_keeps_previous_generation_for_accepted_scsi_route() {
    let authority = section(LAUNCH,
        "unsafe fn retained_native_storage_wal_scsi_authority(",
        "pub(crate) unsafe fn native_storage_relation_recheck_id()");
    let initial = authority.find("if let Some(proof) = publication.native_disk_proof.as_ref()")
        .expect("initial relation branch");
    let refresh = authority.find("publication.native_disk_refresh")
        .expect("refresh branch");
    let generation = authority.find("route.key.relation.generation")
        .expect("relation generation comparison");
    assert!(initial < generation && generation < refresh,
        "only Initial must require the route's generation to equal the new publication; \
         Refreshing routes retain the previous accepted SCSI generation");
    let refresh_branch = &authority[refresh..];
    assert!(refresh_branch.contains("previous == route")
        && refresh_branch.contains("next.key.relation.generation")
        && refresh_branch.contains(".then_some(None)"),
        "Refresh must bind previous accepted route and new publication, without a pending child scope");
}

#[test]
fn initial_wal_scope_cannot_authorize_a_different_child_provider_or_generation() {
    let binder = section(LAUNCH, "unsafe fn bind_pending_scsi_proof_irp(",
        "/// Consume the exact one-shot proof authority");
    for evidence in ["active.irp_id.is_some()", "params.route.pdo.raw() == authority.child_pdo",
        "params.route.provider == provider.domain()",
        "params.route.relation_generation == authority.relation.relation().generation()",
        "params.route.provider_pdo == provider.address()"] {
        assert!(binder.contains(evidence), "WAL scope must reuse exact IRP binding: {evidence}");
    }
    let resolver = section(LAUNCH, "unsafe fn pending_scsi_proof_relation(",
        "/// The in-flight relation owns its children");
    for evidence in ["active.claimed", "active.irp_id.map(IrpId::raw) != Some(request.irp_id)",
        "authority.child_pdo != request.device_id", "request.scsi_relation_generation",
        "authority.provider.domain() != provider", "authority.provider.address() != provider_pdo",
        "hosted_device_relation_owner_is_current(authority.relation_owner)",
        "devnode_identity_is_started(authority.relation.parent())",
        "hosted_device_pointer_registration(provider, provider_pdo)"] {
        assert!(resolver.contains(evidence), "WAL scope must fail closed on {evidence}");
    }
}
