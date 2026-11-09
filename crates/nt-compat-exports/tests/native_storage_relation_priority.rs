//! The native storage cutover must not strand a prepared CM relation behind its own drain.

const HANDOFF: &str = include_str!("../../../components/ntos-executive/src/boot_storage_dma_handoff.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const START: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
const VIDEO: &str = include_str!("../../../components/ntos-executive/src/video_device.rs");

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

#[test]
fn native_drain_waits_for_entered_lifecycle_and_video_create() {
    let start = HANDOFF.split_once("pub(crate) fn begin_native_start_after_preload(")
        .expect("native start").1.split_once("pub(crate) fn finish_boot_io(")
        .expect("native start boundary").0;
    let drain = start.find(".begin_drain(").expect("controller drain");
    let lifecycle = start.find("hosted_pnp_lifecycle_dispatch_active()")
        .expect("an entered unrelated FILTER/START must finish before drain");
    let video = start.find("video_publication_active()")
        .expect("post-START native video CREATE remains active after PnP terminal");
    assert!(lifecycle < drain && video < drain,
        "both entered owners must finish while boot storage still admits durable writes");
    assert!(VIDEO.contains("VIDEO_PUBLICATION_ACTIVE.load("),
        "the publication guard, rather than a diagnostic census or persistent File owner, is authority");
    assert!(start.contains("NativeStartAdmission::WaitingForRelation"),
        "a refused drain must retain the exact controller grant owner");
}

#[test]
fn draining_mount_defers_unentered_nonstorage_start_owners() {
    let drive = START.split_once("unsafe fn drive_inner(&mut self, pump_before_observe: bool,")
        .expect("retained Start batch").1.split_once("enum HostedPnpRebalanceStage")
        .expect("Start batch boundary").0;
    for branch in ["pending_filter_admission.take()", "pending_grant_admission.take()",
        "nt_driver_start::BatchPhase::Ready =>"] {
        assert!(drive.contains(branch), "missing retained admission branch {branch}");
    }
    assert!(drive.matches("defer_unrelated_start_during_native_drain(").count() >= 3,
        "Ready, pending FILTER, and pending grant must all defer before creating a PnP transaction");
    assert!(START.contains("is_boot_storage_controller()"),
        "the current controller grant is admitted through authenticated resource metadata");
    assert!(START.contains("pending_filter_admission = Some(pending)")
        && START.contains("pending_grant_admission = Some(pending)"),
        "a deferred owner must retain its original prepared resource plan and lease");
}

#[test]
fn post_start_video_open_waits_for_exact_native_publication() {
    let finish = START.split_once("unsafe fn finish_started_devnode(")
        .expect("START terminal handling").1.split_once("fn hosted_display_service_registry_path(")
        .expect("START terminal boundary").0;
    assert!(!finish.contains("try_publish_hosted_video_route("),
        "START terminal handling must not enter synchronous video CREATE during the storage drain");
    assert!(START.contains("pending_video_publication"),
        "the device identity and report must remain owned while video publication is deferred");
    assert!(START.contains("matches_current(driver_launch::hosted_video_publication_identity(device_id))")
        && DRIVER.contains("pub(crate) struct HostedVideoPublicationIdentity")
        && DRIVER.contains("projection_domain: binding.projection_domain")
        && DRIVER.contains("pdo_object: binding.pdo_object"),
        "the retained callback must revalidate the registered device and physical generation");
    assert!(DRIVER.contains("pdo_generation: HostedDmaPdoGeneration")
        && DRIVER.contains("hosted_dma_pdo_generation(binding.pdo_device_id)")
        && START.contains("hosted_video_publication_identity_is_live"),
        "the callback must also retain and recheck the exact PnP relation generation");
    assert!(START.contains("native_storage_cutover_phase().admit_video_create()")
        && HANDOFF.contains("published_native_storage_mount()")
        && DRIVER.contains("native_storage_route()")
        && HANDOFF.contains("exec_block_route_kind("),
        "video CREATE resumes only after the matching mounted route becomes Native");
    let drive = START.split_once("unsafe fn drive_inner(&mut self, pump_before_observe: bool,")
        .expect("retained Start batch").1.split_once("enum HostedPnpRebalanceStage")
        .expect("Start batch boundary").0;
    assert!(drive.find("if let Some((devnode_index, owner)) = self.pending_video_publication")
        .expect("deferred video branch")
        < drive.find("nt_driver_start::BatchPhase::Complete =>")
            .expect("completed batch branch"),
        "the video callback must run before the completed batch can be released");
    let redrive = START.split_once("pub(crate) fn needs_completion_redrive(&self) -> bool")
        .expect("completion redrive").1.split_once("pub(crate) unsafe fn drive(&mut self)")
        .expect("redrive boundary").0;
    assert!(redrive.contains("self.pending_video_publication.is_some()"),
        "a deferred video owner must remain scheduled without replaying START");
}
