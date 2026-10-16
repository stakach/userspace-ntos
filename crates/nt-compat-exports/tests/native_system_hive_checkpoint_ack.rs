//! Native v1 SYSTEM checkpoint ACK keeps the exact CM preparation after a lost reply.

use std::path::Path;

#[test]
fn v1_checkpoint_retries_exact_ack_before_starting_another_image() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let checkpoint = &source[source.find("fn checkpoint_system_hive_from_config_manager(")
        .expect("checkpoint caller")..
        source.find("fn checkpoint_non_system_boot_mutable_hive(")
            .expect("next checkpoint caller")];

    let retry = checkpoint.find("retry_retained_system_hive_checkpoint_ack(")
        .expect("exact retained ACK redrive");
    let prepare = checkpoint.find("config_manager_prepare_system_hive_checkpoint()")
        .expect("new CM preparation");
    assert!(retry < prepare, "retry retained ACK before beginning another image");
    assert!(checkpoint.contains("retain_system_hive_checkpoint_for_persistence("),
        "uncertain ACK must leave its token and image metadata with an owner");
    let retry_helper = &source[source.find("fn retry_retained_system_hive_checkpoint_ack(")
        .expect("ACK retry helper")..
        source.find("fn retain_system_hive_checkpoint_for_persistence(")
            .expect("ACK owner installation")];
    let ack = retry_helper.find("config_manager_acknowledge_system_hive_checkpoint(&retained.prepared)")
        .expect("same prepared ACK token");
    let release = retry_helper.find("RETAINED_V1_SYSTEM_CHECKPOINT_ACK)).take()")
        .expect("release after confirmed reply");
    assert!(ack < release);
    assert!(!retry_helper.contains("config_manager_abort_system_hive_checkpoint"),
        "an uncertain ACK cannot be followed by ABORT");
}

#[test]
fn v1_checkpoint_write_uncertainty_retains_cm_and_physical_reserve() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let handler = std::fs::read_to_string(root.join("exec_handler.rs")).unwrap();
    let checkpoint = &handler[handler.find("fn checkpoint_system_hive_from_config_manager(")
        .expect("checkpoint caller")..
        handler.find("fn checkpoint_non_system_boot_mutable_hive(")
            .expect("next checkpoint caller")];
    let retain = checkpoint.find("retain_system_hive_checkpoint_for_persistence(")
        .expect("CM checkpoint owner before first file effect");
    let write = checkpoint.find("write_primary_image_atomic_owned(&mut provider")
        .expect("first image effect");
    assert!(retain < write);
    let failure = &checkpoint[write..];
    assert!(failure.contains("block_uncertain_system_checkpoint()"),
        "ambiguous file or snapshot error must fence the mount");
    assert!(!failure.contains("config_manager_abort_system_hive_checkpoint(&prepared)"),
        "effect ambiguity cannot release the CM preparation");

    let writable = std::fs::read_to_string(root.join("writable_fs.rs")).unwrap();
    let generic = &writable[writable.find("pub(crate) unsafe fn checkpoint_dirty_volume()")
        .expect("generic snapshot checkpoint")..
        writable.find("pub(crate) enum BootSystemPersistence")
            .expect("next storage section")];
    assert!(generic.contains("if WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire)"),
        "all snapshot formats must refuse a blocked mount before writes");
    assert!(generic.contains("core::mem::forget(dev)"),
        "an uncertain snapshot error retains its exact physical reserve");
}
