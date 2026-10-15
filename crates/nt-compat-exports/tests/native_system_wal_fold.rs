//! Native v2 SYSTEM checkpoint keeps one physical reserve through fold and reclamation.

use std::path::Path;

fn source(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn v2_fold_owns_cm_checkpoint_and_exact_reserve_until_two_slots_and_rollover() {
    let fold = source("writable_fs/system_wal_fold.rs");
    for contract in [
        "PreparedSystemHiveCheckpoint",
        "snapshot_storage::Lease",
        "static mut FOLD_WORK",
        "base_serial: manifest.high_water_serial",
        "replace_boot_file(",
        "CONFIG_SYSTEM_HIVE_PATH",
        "WalSnapshotEpochRollover::admit(",
        "publish_resetting()",
        "finish()",
    ] {
        assert!(fold.contains(contract), "native fold lost {contract}");
    }
    let image = fold.find("replace_boot_file(").unwrap();
    let first = fold.find("commit_volume_snapshot_with_wal_manifest(").unwrap();
    let second = fold[first + 1..].find("commit_volume_snapshot_with_wal_manifest(")
        .expect("second folded snapshot slot") + first + 1;
    let rollover = fold.find("WalSnapshotEpochRollover::admit(").unwrap();
    let ack = fold.find("config_manager_acknowledge_system_hive_checkpoint(").unwrap();
    assert!(image < first && first < second && second < rollover && rollover < ack,
        "CM image fold, two slots, epoch rollover and CM ACK must retain one order");
    assert!(!fold.contains("config_manager_abort_system_hive_checkpoint("),
        "an uncertain physical fold cannot abandon its CM checkpoint");
}

#[test]
fn uncertain_fold_keeps_owner_and_dirty_state_for_boot_recovery() {
    let fold = source("writable_fs/system_wal_fold.rs");
    assert!(fold.contains("WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED"));
    assert!(fold.contains("WRITABLE_FS_SNAPSHOT_DIRTY"));
    assert!(fold.contains("FOLD_WORK"));
    assert!(fold.contains("core::mem::forget") || fold.contains("Phase::Blocked"),
        "uncertain effects cannot drop the exact lease");

    let writable = source("writable_fs.rs");
    assert!(writable.contains("mod system_wal_fold;"));
    assert!(writable.contains("fold_system_wal_if_dirty"),
        "flush policy needs a narrow fold entry point");
}

#[test]
fn lazy_writer_and_shutdown_fold_without_changing_explicit_flush_fence() {
    let service = source("service_sec_image.rs");
    assert!(service.contains("fold_system_wal_if_dirty()"),
        "the active service loop must schedule CM image folds independently of file dirty bits");
    assert!(service.contains("SYSTEM_WAL_FOLD_INTERVAL_100NS")
        && service.contains("monotonic_time_100ns()"),
        "background folds must coalesce mutations over a bounded interval");
    let timer = source("timer_deadline.rs");
    assert!(timer.contains("system_wal_fold_next_deadline()"),
        "an idle service loop must wake for its fold deadline");
    assert!(service.contains("rearm_registered_active_delay_timer()"),
        "installing a fold interval must program the live one-shot timer");

    let handler = source("exec_handler.rs");
    let flush = &handler[handler.find("fn checkpoint_system_hive_from_config_manager(").unwrap()
        ..handler.find("fn checkpoint_non_system_boot_mutable_hive(").unwrap()];
    assert!(flush.contains("verify_durable_system_wal()"),
        "explicit NtFlushKey proves the per-mutation WAL barrier");
    assert!(handler.contains("fold_system_wal_if_dirty()"),
        "shutdown must fold the CM image before returning durability success");
}

#[test]
fn pending_cm_ack_redrives_before_generic_snapshot_or_timer_gate() {
    let fold = source("writable_fs/system_wal_fold.rs");
    assert!(fold.contains("system_wal_fold_ack_pending()"));
    assert!(fold.contains("Phase::Acknowledging"));
    let writable = source("writable_fs.rs");
    assert!(writable.contains("system_wal_fold_ack_pending"));

    let service = source("service_sec_image.rs");
    let start = service.find("fn finalize_service_loop_work(").unwrap();
    let body = &service[start..];
    let pending = body.find("system_wal_fold_ack_pending()").expect("pending ACK gate");
    let redrive = body.find("fold_system_wal_if_dirty()").expect("exact ACK redrive");
    let generic = body.find("checkpoint_dirty_volume()").expect("generic snapshot");
    assert!(pending < redrive && redrive < generic,
        "an ACK held under the reserve must redrive before generic snapshot acquisition");
    let early = &body[pending..generic];
    assert!(early.contains("SYSTEM_WAL_LAST_FOLD_100NS.store(monotonic_time_100ns()")
        && early.contains("rearm_registered_active_delay_timer()"),
        "a refused ACK must move its timer deadline forward instead of rearming a past deadline");
}
