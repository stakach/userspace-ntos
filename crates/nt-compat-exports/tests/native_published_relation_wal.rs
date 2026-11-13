//! An active relation keeps its exact WAL owner after the mounted route is published.

const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const SNAPSHOT: &str = include_str!("../../../components/ntos-executive/src/writable_fs/native_snapshot_io.rs");
const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let tail = &source[source.find(start).expect("start marker")..];
    &tail[..tail.find(end).expect("end marker")]
}

#[test]
fn published_route_claims_the_active_relation_wal_through_the_normal_snapshot_turn() {
    let claims = section(SNAPSHOT, "pub(crate) unsafe fn claim_next_native_snapshot_io()", "pub(crate) unsafe fn claim_relation_header_recheck(");
    assert!(claims.contains("claim_retained_relation_wal_io()"),
        "published native route must include the active relation WAL in ordinary snapshot scheduling");
    for evidence in ["RELATION_WAL_FIRST", "relation().or_else(generic)",
        "generic().or_else(relation)"] {
        assert!(claims.contains(evidence), "snapshot turn must fairly select {evidence}");
    }

    let service = &BLOCK[BLOCK.find("pub(super) unsafe fn service()").expect("block service")..];
    assert!(service.contains("native_disk_relation::native_storage_route()"));
    assert!(service.contains("next_claim()"));
    assert!(service.contains("claim.mount() != route.mount.value()"));
}

#[test]
fn relation_wal_callbacks_bind_the_same_active_invalidation_and_native_mount() {
    let resolver = section(LAUNCH, "unsafe fn relation_wal_publication_mut()", "pub(crate) unsafe fn active_relation_wal_retained()");
    for evidence in ["native_disk_relation::native_storage_route()", "active_relation_publication_mut()",
        "retained_native_storage_relation_publication_mut()", "native_wal_mut()?.mount() != route.mount"] {
        assert!(resolver.contains(evidence), "relation resolver must retain {evidence}");
    }
    let active = section(LAUNCH, "unsafe fn active_relation_publication_mut()", "/// Copy the retained initial child authority");
    assert!(active.contains("publication.claim != query.claim"));
    assert!(active.contains("devnode_identity_for_pdo(query.claim.pdo_device_id)"));
    assert!(active.contains("Some(query.claim.parent)"));

    let claimant = section(LAUNCH, "pub(crate) unsafe fn claim_native_relation_wal_io()", "unsafe fn relation_wal_for(");
    assert!(claimant.contains("relation_wal_publication_mut()"));
    assert!(claimant.contains("publication.persistence.claim_native_wal_io()"));
    assert!(claimant.contains("publication.claim"));
    assert!(claimant.contains("from_relation_wal("));

    let callbacks = section(LAUNCH, "unsafe fn relation_wal_for(", "/// An uncommitted relation");
    assert!(callbacks.contains("relation_wal_publication_mut()"));
    assert!(callbacks.contains("publication.claim != claim"));
    for callback in ["mark_native_io_entered(request)", "release_unentered_native_io(request)",
        "refuse_unentered_native_io(request)", "complete_native_io(request, result)"] {
        assert!(callbacks.contains(callback), "callback must retain exact WAL request: {callback}");
    }

    let service = &BLOCK[BLOCK.find("pub(super) unsafe fn service()").expect("block service")..];
    assert!(service.contains("claim.mount() != route.mount.value()"));
    assert!(service.contains("completed_device_control_irp_exact(pending.irp.raw())")
        || BLOCK.contains("completed_device_control_irp_exact(pending.irp.raw())"));
    assert!(BLOCK.contains("acknowledge_completed_irp_strict(pending.irp.raw())"));
}

#[test]
fn no_signaler_gate_retains_only_the_exact_active_relation_wal() {
    let retained = section(LAUNCH, "pub(crate) unsafe fn active_relation_wal_retained()", "pub(crate) unsafe fn claim_native_relation_wal_io()");
    assert!(retained.contains("active_relation_publication_mut()"));
    assert!(retained.contains("publication.persistence.native_wal_mut()"));
    assert!(SERVICE.matches("driver_launch::active_relation_wal_retained()").count() >= 2);
}
