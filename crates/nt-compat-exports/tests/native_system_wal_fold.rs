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
    let native = source("writable_fs/system_wal_fold/native.rs");
    let entry = &fold[fold.find("pub(crate) unsafe fn fold_system_wal_if_dirty()").unwrap()..];
    assert!(entry.find("BlockSourceKind::Native").unwrap()
        < entry.find("ensure_mounted()?").unwrap(),
        "native cutover must enter the retained fold before any synchronous mount I/O");
    let stage = &native[native.find("unsafe fn advance_recheck()").unwrap()
        ..native.find("pub(super) unsafe fn fold_system_wal_native()").unwrap()];
    assert!(stage.contains("take_rechecked_wal_continuation(id)")
        && stage.contains("FileSystem::from_volume_snapshot(baseline.as_slice())")
        && stage.contains("stage_prepared_checkpoint(&mut staged, &prepared)")
        && stage.contains("CapturedSnapshot::capture(&lease, &staged)")
        && stage.contains("cursor: Some(Cursor::First(commit))"),
        "the exact rechecked lease must retain a private prepared image for native writes");
    assert!(!stage.contains("apply_prepared_checkpoint(fs,"),
        "pending native effects must not expose the prepared SYSTEM image in the live overlay");
    let complete = &native[native.find("pub(crate) unsafe fn complete(").unwrap()
        ..native.find("fn stall(").unwrap()];
    let first = complete.find("Cursor::First(commit) =>").unwrap();
    let reused = complete[first..].find("finish_with_payload_and_paired_proof()").unwrap() + first;
    let second = complete.find("Cursor::Second(commit) =>").unwrap();
    let rollover = complete.find("AsyncWalEpochRollover::admit(").unwrap();
    let ready = complete.find("Cursor::Rollover(cursor) =>").unwrap();
    assert!(first < reused && reused < second && second < rollover && rollover < ready,
        "both slots must use the same owned capture before optional rollover");
    assert!(complete.contains("AsyncSnapshotCommit::new(active.lease.store(), image,")
        && complete.contains("publish_ready(active, None, pair)")
        && complete.contains("publish_ready(active, Some(next), pair)"),
        "small and rollover folds must retain the exact pair until CM acknowledgement");
    let acknowledge = &fold[fold.find("unsafe fn acknowledge_retained()").unwrap()..];
    assert!(native.contains("phase: Phase::Acknowledging")
        && acknowledge.contains("config_manager_acknowledge_system_hive_checkpoint(prepared)")
        && acknowledge.contains("install_retained()"),
        "the CM ACK follows native proof completion while FOLD_WORK owns the lease");
    assert!(!native.contains("config_manager_abort_system_hive_checkpoint("),
        "an uncertain native fold cannot abandon its CM checkpoint");
}

#[test]
fn uncertain_fold_keeps_owner_and_dirty_state_for_boot_recovery() {
    let fold = source("writable_fs/system_wal_fold.rs");
    let native = source("writable_fs/system_wal_fold/native.rs");
    assert!(fold.contains("WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED"));
    assert!(fold.contains("WRITABLE_FS_SNAPSHOT_DIRTY"));
    assert!(fold.contains("FOLD_WORK"));
    assert!(fold.contains("core::mem::forget") || fold.contains("Phase::Blocked"),
        "uncertain effects cannot drop the exact lease");
    assert!(native.contains("Work::Stalled") && native.contains("active.failed = true")
        && native.contains("mark_snapshot_dirty()"),
        "native uncertainty must retain the exact lease and leave dirty work visible");

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

#[test]
fn small_fold_keeps_anchored_epoch_and_reserves_rollover_for_capacity() {
    let fold = source("writable_fs/system_wal_fold.rs");
    let native = source("writable_fs/system_wal_fold/native.rs");
    let first = fold.find("commit_next_with_wal_manifest(").unwrap();
    let second = fold[first + 1..].find("commit_next_with_wal_manifest(").unwrap() + first + 1;
    let decision = fold.find("if needs_epoch_rollover(manifest.high_water_end_lba, sectors)")
        .expect("capacity gate after two folded slots");
    let rollover = fold.find("WalSnapshotEpochRollover::admit(").unwrap();
    assert!(first < second && second < decision && decision < rollover);
    assert!(fold.contains("wal_sectors.saturating_sub(wal_sectors / 4)"),
        "routine small folds must not erase the WAL epoch");
    assert!(fold.contains("work.old_continuation.take()")
        && fold.contains("work.next_continuation.is_some()"),
        "no rollover reuses the exact anchored token after CM ACK");
    assert!(native.contains("if needs_epoch_rollover(active.manifest.high_water_end_lba, sectors)")
        && native.contains("publish_ready(active, None, pair)")
        && native.contains("publish_ready(active, Some(next), pair)"),
        "native small fold retains its anchored token and rolls only at the capacity gate");
}

#[test]
fn fold_lease_preserves_batched_reserve_io() {
    let fold = source("writable_fs/system_wal_fold.rs");
    let adapter = &fold[fold.find("impl SnapshotBlockDevice for FoldLease").unwrap()
        ..fold.find("fn block(").unwrap()];
    assert!(adapter.contains("fn write_sectors(") && adapter.contains("self.0.write_sectors(lba, data)"),
        "epoch erase must use the reserve's batched AHCI write path");
    assert!(adapter.contains("fn read_sectors(") && adapter.contains("self.0.read_sectors(lba, out)"),
        "WAL reads must preserve the reserve's batched AHCI read path");
}
