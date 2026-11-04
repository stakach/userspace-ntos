//! Native metadata copies may become authoritative only after the shared SCSI route fences writes.

const FILE_OWNERS: &str = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
const NATIVE_BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");

#[test]
fn canonical_scsi_owner_fences_media_before_provider_entry() {
    let owner = FILE_OWNERS
        .split_once("fn dispatch_with_port_connect(")
        .expect("shared File IRP dispatch")
        .1;
    let capture = owner.find("capture_route(id, &prepared)").expect("exact route capture");
    let fence = owner.find("mounted_native_block::before_external_scsi_effect(&prepared, &row(id).stack)")
        .expect("Executive metadata media fence");
    let begin = owner.find("begin_prepared_external_file_irp(prepared)")
        .expect("provider entry owner");
    assert!(capture < fence && fence < begin);
    assert!(NATIVE_BLOCK.contains("PossibleScsiEffect::from_legacy_srb"));
    assert!(NATIVE_BLOCK.contains("fence.before_effect"));
}

#[test]
fn refresh_recheck_cannot_hide_a_possible_write_before_abort_to_old_route() {
    let hook = NATIVE_BLOCK
        .split_once("pub(super) unsafe fn before_external_scsi_effect(")
        .expect("Executive pre-effect hook")
        .1
        .split_once("unsafe fn observe_metadata_shadow(")
        .expect("hook boundary")
        .0;
    assert!(hook.contains("retained_native_storage_recheck_route()"),
        "a temporarily unpublished route must still poison its old cache");
}
