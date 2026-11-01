//! The native storage cutover must not strand a prepared CM relation behind its own drain.

const HANDOFF: &str = include_str!("../../../components/ntos-executive/src/boot_storage_dma_handoff.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const START: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");

#[test]
fn native_drain_waits_for_the_current_relation_owner() {
    let start = HANDOFF.split_once("pub(crate) fn begin_native_start_after_preload(")
        .expect("native start").1.split_once("pub(crate) fn finish_boot_io(")
        .expect("native start boundary").0;
    let active_check = start.find("hosted_nonstorage_relation_query_active(accepted_pdo)")
        .expect("the active relation owner must be checked before native drain");
    let drain = start.find(".begin_drain(").expect("controller drain");
    assert!(active_check < drain, "the CM relation must finish before irreversible drain");
    assert!(start.contains("NativeStartAdmission::WaitingForRelation"),
        "a retained Start admission must retry without claiming a drain occurred");
    assert!(START.contains("NativeStartAdmission::WaitingForRelation"),
        "the PnP Start owner must retain admission while the relation finishes");
}

#[test]
fn draining_route_claims_only_the_authenticated_storage_relation() {
    let schedule = DRIVER.split_once("unsafe fn start_hosted_device_relation_query()")
        .expect("relation scheduler").1.split_once("let relation_owner =")
        .expect("scheduler boundary").0;
    assert!(schedule.contains("pending_native_storage_relation_parent()")
        && schedule.contains("claim_parent("),
        "while draining, claim only the accepted controller's exact queued relation");
    assert!(schedule.contains("claim_front()"),
        "ordinary FIFO scheduling resumes after native route publication");
    let priority = HANDOFF.split_once("pub(crate) fn pending_native_storage_relation_parent(")
        .expect("storage priority query").1.split_once("pub(crate) fn relation_parent_requires_native_disk_proof(")
        .expect("priority query boundary").0;
    assert!(priority.contains("accepted_pdo") && priority.contains("BlockSourceKind::Draining"),
        "priority must use accepted physical identity and the actual draining mount");
    assert!(priority.contains("exec_fs_mount_identity()")
        && priority.contains("Err(nt_status::NtStatus::DEVICE_NOT_READY)"),
        "a draining mount with missing expected-disk authority must not reopen FIFO");
}
