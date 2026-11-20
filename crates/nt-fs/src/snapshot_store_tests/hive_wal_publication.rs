use crate::snapshot_test_device::CachedDisk;
use crate::{
    publish_anchored_hive_child, publish_anchored_hive_delete_key,
    publish_anchored_hive_delete_value, publish_anchored_hive_security,
    publish_anchored_hive_value, AnchoredWalPublication, AsyncSnapshotHeaderRecheck,
    AsyncSnapshotIoKind, AsyncWalSnapshotAnchorUpdate, HiveLogWalPayload, OwnedBoundedBlockRange,
    RegistryWal, SnapshotBlockDevice, SnapshotBlockStore, WalSnapshotAnchorUpdate,
    WalSnapshotManifest, HiveWalPublicationError,
};
use nt_hive_core::{Hive, HiveKind, MutableHiveSet, RegistryValueType};

const LOG: &str = r"\Registry\User\Retained.LOG";
const SECURITY_LOG: &str = r"\Registry\Machine\Security.LOG";

fn anchored_payload(payload: alloc::vec::Vec<u8>) -> (CachedDisk, AnchoredWalPublication) {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    let manifest = WalSnapshotManifest { incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0 };
    store.commit_next_with_wal_manifest(&mut disk, b"old", manifest).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"new", manifest).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let mut recheck = AsyncSnapshotHeaderRecheck::new(store, pair, 512, 32).ok().unwrap();
    while let Some(request) = recheck.enter_next().unwrap() {
        let mut sector = [0; 512];
        disk.read_sector(request.lba, &mut sector).unwrap();
        recheck.complete_read(request, &sector).unwrap();
    }
    let range = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(payload).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = AsyncWalSnapshotAnchorUpdate::admit_verified_wal_pair(
        store, verified, unsafe { recheck.finish_proven() }.ok().unwrap()).ok().unwrap();
    while let Some(request) = update.enter_next().unwrap() {
        match request.kind {
            AsyncSnapshotIoKind::Write => {
                let bytes = update.write_bytes(request).unwrap().to_vec();
                update.device_for_test().write_sector(request.lba, &bytes).unwrap();
            }
            AsyncSnapshotIoKind::Flush => update.device_for_test().flush().unwrap(),
            AsyncSnapshotIoKind::Read => unreachable!(),
        }
        unsafe { update.complete(request, true) }.unwrap();
    }
    update.into_anchored_publication().ok().unwrap()
}

#[test]
fn boot_anchor_mints_new_hive_record_only_after_both_durable_headers() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    let manifest = WalSnapshotManifest { incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0 };
    store.commit_next_with_wal_manifest(&mut disk, b"old", manifest).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"new", manifest).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let range = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    let payload = alloc::vec![0x5a; 600];
    wal.begin(payload.clone()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = WalSnapshotAnchorUpdate::admit_verified_wal_pair(store, verified, pair)
        .ok().unwrap();
    update.advance().unwrap();
    let (mut disk, receipt) = update.into_anchored_publication().ok().unwrap();
    assert_eq!(receipt.payload(), payload);
    let (continuation, pair, _) = receipt.into_parts();
    assert_eq!(continuation.anchor(), pair.anchor());
    disk.power_cut();
    assert_eq!(store.read_latest_wal(&mut disk).unwrap().unwrap().anchor, pair.anchor());
}

#[test]
fn failed_second_header_flush_cannot_mint_hive_publication() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut disk = CachedDisk::with_sectors(32);
    let manifest = WalSnapshotManifest { incarnation: 77, base_serial: 0,
        high_water_serial: 0, high_water_end_lba: 0 };
    store.commit_next_with_wal_manifest(&mut disk, b"old", manifest).unwrap();
    store.commit_next_with_wal_manifest(&mut disk, b"new", manifest).unwrap();
    let pair = store.verify_paired_wal_snapshot(&mut disk).unwrap();
    let range = OwnedBoundedBlockRange::new(disk, 16, 16).ok().unwrap();
    let mut wal = RegistryWal::recover(range, 77).unwrap();
    wal.begin(alloc::vec![0x5a; 600]).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let verified = wal.into_verified_device().unwrap().into_full_device();
    let mut update = WalSnapshotAnchorUpdate::admit_verified_wal_pair(store, verified, pair)
        .ok().unwrap();
    // The two barriers are write, flush, write, flush. A failed final flush may
    // have persisted the second header, so neither owner nor receipt can escape.
    let second_flush = update.device_for_test().events.len() + 3;
    update.device_for_test().fail_event = Some(second_flush);
    assert_eq!(update.advance(), Err(crate::SnapshotBlockStoreError::Io));
    let mut update = update.into_anchored_publication().err().unwrap();
    assert_eq!(update.device_for_test().events.last(), Some(&crate::snapshot_test_device::Event::Flush));
    core::mem::forget(update);
}

#[test]
fn exact_anchored_hive_record_publishes_reserved_value_once() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let key = hive.create_key("Target");
    hive.finish_clean_import();
    set.mount(r"\Registry\User\Retained", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_value(
        7, key, "Target", "Value", RegistryValueType::Binary, alloc::vec![2]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"), None);
    let (_value, continuation, pair) = publish_anchored_hive_value(
        &mut set, prepared, receipt, 9, 0, LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"),
        Some((RegistryValueType::Binary, &[2][..])));
}

#[test]
fn foreign_log_identity_retains_owner_and_cannot_publish() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let key = hive.create_key("Target");
    hive.finish_clean_import();
    set.mount(r"\Registry\User\Retained", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_value(
        7, key, "Target", "Value", RegistryValueType::Binary, alloc::vec![2]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (_, prepared, receipt) = publish_anchored_hive_value(
        &mut set, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(set.hive(7).unwrap().query_value(key, "Value"), None);
    assert!(set.release_unentered_owned_set_value(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn exact_anchored_security_child_replays_only_after_publication() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let root = hive.root();
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_create_child(
        7, root, "", "Policy", None, alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), None);
    let (child, continuation, pair) = publish_anchored_hive_child(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), Some(child));
}

#[test]
fn foreign_anchored_child_record_keeps_original_hive_owner_pinned() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let root = hive.root();
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_create_child(
        7, root, "", "Policy", None, alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (_, prepared, receipt) = publish_anchored_hive_child(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).err().unwrap();
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Policy"), None);
    assert!(set.release_unentered_owned_create_child(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn exact_anchored_security_repair_publishes_after_durable_record() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let policy = hive.create_key("Policy");
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_key_security(
        7, policy, "Policy", alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), None);
    let (continuation, pair) = publish_anchored_hive_security(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), Some(&[1, 2, 3][..]));
}

#[test]
fn foreign_anchored_security_record_keeps_descriptor_unpublished() {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Security);
    let policy = hive.create_key("Policy");
    hive.finish_clean_import();
    set.mount(r"\Registry\Machine\Security", 7, hive).unwrap();
    let prepared = set.prepare_owned_set_key_security(
        7, policy, "Policy", alloc::vec![1, 2, 3]).unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: SECURITY_LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (_, prepared, receipt) = publish_anchored_hive_security(
        &mut set, prepared, receipt, 9, 0, SECURITY_LOG).err().unwrap();
    assert_eq!(set.hive(7).unwrap().key_security_descriptor(policy), None);
    assert!(set.release_unentered_owned_set_key_security(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

fn mounted_leaf_for_deletion() -> (MutableHiveSet, nt_hive_core::CellId, nt_hive_core::CellId) {
    let mut set = MutableHiveSet::new();
    let mut hive = Hive::new(HiveKind::Software);
    let root = hive.root();
    let leaf = hive.create_key("Leaf");
    assert!(hive.set_value(leaf, "Obsolete", RegistryValueType::Binary, alloc::vec![4]));
    hive.finish_clean_import();
    set.mount(r"\Registry\User\Retained", 7, hive).unwrap();
    (set, root, leaf)
}

#[test]
fn exact_anchor_publishes_delete_value_only_after_paired_headers() {
    let (mut set, _, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_value(7, leaf, "Leaf", "Obsolete").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert!(set.hive(7).unwrap().query_value(leaf, "Obsolete").is_some());
    let (continuation, pair) = publish_anchored_hive_delete_value(
        &mut set, prepared, receipt, 9, 0, LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "Obsolete"), None);
}

#[test]
fn wrong_delete_value_payload_retains_both_move_only_owners() {
    let (mut set, _, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_value(7, leaf, "Leaf", "Obsolete").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_value(
        &mut set, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongPayload);
    assert!(set.hive(7).unwrap().query_value(leaf, "Obsolete").is_some());
    assert!(set.release_unentered_owned_delete_value(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn wrong_delete_value_hive_retains_both_move_only_owners() {
    let (mut set, _, leaf) = mounted_leaf_for_deletion();
    let mut other = MutableHiveSet::new();
    let prepared = set.prepare_owned_delete_value(7, leaf, "Leaf", "Obsolete").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_value(
        &mut other, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongHiveOwner);
    assert!(set.hive(7).unwrap().query_value(leaf, "Obsolete").is_some());
    assert!(set.release_unentered_owned_delete_value(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn exact_anchor_publishes_delete_key_and_its_values_only_after_paired_headers() {
    let (mut set, root, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (_disk, receipt) = anchored_payload(payload);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), Some(leaf));
    let (continuation, pair) = publish_anchored_hive_delete_key(
        &mut set, prepared, receipt, 9, 0, LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), None);
    assert_eq!(set.hive(7).unwrap().query_value(leaf, "Obsolete"), None);
}

#[test]
fn wrong_delete_key_payload_retains_both_move_only_owners() {
    let (mut set, root, leaf) = mounted_leaf_for_deletion();
    let prepared = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 10, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_key(
        &mut set, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongPayload);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), Some(leaf));
    assert!(set.release_unentered_owned_delete_key(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

#[test]
fn wrong_delete_key_hive_retains_both_move_only_owners() {
    let (mut set, root, leaf) = mounted_leaf_for_deletion();
    let mut other = MutableHiveSet::new();
    let prepared = set.prepare_owned_delete_key(7, leaf, "Leaf").unwrap();
    let payload = crate::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: 9, expected_log_len: 0, path: LOG, record: prepared.record(),
    }).unwrap();
    let (disk, receipt) = anchored_payload(payload);
    let (error, prepared, receipt) = publish_anchored_hive_delete_key(
        &mut other, prepared, receipt, 9, 0, LOG).err().unwrap();
    assert_eq!(error, HiveWalPublicationError::WrongHiveOwner);
    assert_eq!(set.hive(7).unwrap().open_subkey(root, "Leaf"), Some(leaf));
    assert!(set.release_unentered_owned_delete_key(prepared).is_err());
    assert!(set.hive_mut(7).is_none());
    core::mem::forget(receipt);
    core::mem::forget(disk);
}

// #422: Explorer deletes each RunOnce value, and iernonce each RunOnceEx section, before running
// it. A deletion anchored in the WAL must still be absent after the volume is reloaded and the
// hive log is replayed over the installed hive.
const SOFTWARE_LOG: &str = r"\??\C:\Windows\System32\Config\SOFTWARE.LOG";
const RUN_ONCE: &str = r"Microsoft\Windows\CurrentVersion\RunOnce";
const RUN_ONCE_EX: &str = r"Microsoft\Windows\CurrentVersion\RunOnceEx";
const FINALIZE: &str = r"Microsoft\Windows\CurrentVersion\RunOnceEx\Finalize";

fn installed_software() -> Hive {
    let mut hive = Hive::new(HiveKind::Software);
    let run_once = hive.create_key(RUN_ONCE);
    assert!(hive.set_value(run_once, "GuiRunOnce", RegistryValueType::Sz, alloc::vec![b'x', 0]));
    let finalize = hive.create_key(FINALIZE);
    assert!(hive.set_value(finalize, "1", RegistryValueType::Sz, alloc::vec![b'y', 0]));
    hive.finish_clean_import();
    hive
}

/// Anchor one prepared record, then fold it into the volume's hive log as boot recovery would.
fn anchor_into_volume(volume: &mut crate::FileSystem, log_len: &mut u64, record: &[u8])
    -> (CachedDisk, AnchoredWalPublication, u64, u64)
{
    let file_id = volume.existing_file_id(SOFTWARE_LOG).unwrap();
    let payload = HiveLogWalPayload { file_id, expected_log_len: *log_len, path: SOFTWARE_LOG, record };
    let (disk, receipt) = anchored_payload(crate::encode_hive_log_wal_payload(payload).unwrap());
    assert_eq!(volume.replay_hive_log_wal_payload(payload), Ok(crate::HiveLogWalReplay::Appended));
    let expected = *log_len;
    *log_len += record.len() as u64;
    (disk, receipt, file_id, expected)
}

#[test]
fn anchored_run_once_deletions_stay_deleted_after_volume_reload() {
    let mut set = MutableHiveSet::new();
    set.mount(r"\Registry\Machine\SOFTWARE", 2, installed_software()).unwrap();
    let mut volume = crate::FileSystem::new(crate::MemFs::new());
    assert!(volume.provision_file(SOFTWARE_LOG, b""));
    let mut log_len = 0;
    let (run_once, finalize) = {
        let hive = set.hive(2).unwrap();
        (hive.open_key(RUN_ONCE).unwrap(), hive.open_key(FINALIZE).unwrap())
    };

    let prepared = set.prepare_owned_delete_value(2, run_once, RUN_ONCE, "GuiRunOnce").unwrap();
    let (_disk, receipt, file_id, expected) =
        anchor_into_volume(&mut volume, &mut log_len, prepared.record());
    let (continuation, pair) =
        publish_anchored_hive_delete_value(&mut set, prepared, receipt, file_id, expected, SOFTWARE_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    let prepared = set.prepare_owned_delete_value(2, finalize, FINALIZE, "1").unwrap();
    let (_disk, receipt, file_id, expected) =
        anchor_into_volume(&mut volume, &mut log_len, prepared.record());
    let (continuation, pair) =
        publish_anchored_hive_delete_value(&mut set, prepared, receipt, file_id, expected, SOFTWARE_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    let prepared = set.prepare_owned_delete_key(2, finalize, FINALIZE).unwrap();
    let (_disk, receipt, file_id, expected) =
        anchor_into_volume(&mut volume, &mut log_len, prepared.record());
    let (continuation, pair) =
        publish_anchored_hive_delete_key(&mut set, prepared, receipt, file_id, expected, SOFTWARE_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());
    let live = set.hive(2).unwrap();
    assert_eq!(live.query_value(run_once, "GuiRunOnce"), None);
    assert_eq!(live.open_key(FINALIZE), None);

    // The next boot: restore the published volume and replay its log over the installed hive.
    let snapshot = volume.export_volume_snapshot().unwrap();
    let restored = crate::FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let log = restored.file_bytes_owned(SOFTWARE_LOG).unwrap();
    let mut rebooted = installed_software();
    let base = rebooted.sequence;
    assert_eq!(nt_hive_core::try_replay_log(&mut rebooted, &log, base), Ok(base + 3));
    let run_once = rebooted.open_key(RUN_ONCE).expect("RunOnce key stays");
    assert_eq!(rebooted.query_value(run_once, "GuiRunOnce"), None);
    assert_eq!(rebooted.open_key(FINALIZE), None);
    assert!(rebooted.open_key(RUN_ONCE_EX).is_some());
}

// #424: a kernel driver's `ZwSetValueKey` and win32k's writes reach the same hive log as a
// hosted caller's, and a delete made on the Boot route of a WAL volume is anchored as an exact
// record too. Both must survive the volume reload and hive log replay of the next boot.
#[test]
fn driver_written_value_and_boot_route_delete_survive_volume_reload() {
    let mut set = MutableHiveSet::new();
    set.mount(r"\Registry\Machine\SOFTWARE", 2, installed_software()).unwrap();
    let mut volume = crate::FileSystem::new(crate::MemFs::new());
    assert!(volume.provision_file(SOFTWARE_LOG, b""));
    let mut log_len = 0;
    let run_once = set.hive(2).unwrap().open_key(RUN_ONCE).unwrap();

    // The Boot-route delete: anchored first, before the volume moves to the native stack.
    let prepared = set.prepare_owned_delete_value(2, run_once, RUN_ONCE, "GuiRunOnce").unwrap();
    let (_disk, receipt, file_id, expected) =
        anchor_into_volume(&mut volume, &mut log_len, prepared.record());
    let (continuation, pair) =
        publish_anchored_hive_delete_value(&mut set, prepared, receipt, file_id, expected, SOFTWARE_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());

    // The driver's value, anchored later on the native stack.
    let data = alloc::vec![1, 0, 0, 0];
    let prepared = set.prepare_owned_set_value(
        2, run_once, RUN_ONCE, "DriverWritten", RegistryValueType::Dword, data.clone(),
    ).unwrap();
    let (_disk, receipt, file_id, expected) =
        anchor_into_volume(&mut volume, &mut log_len, prepared.record());
    let (_, continuation, pair) =
        publish_anchored_hive_value(&mut set, prepared, receipt, file_id, expected, SOFTWARE_LOG).ok().unwrap();
    assert_eq!(continuation.anchor(), pair.anchor());

    let snapshot = volume.export_volume_snapshot().unwrap();
    let restored = crate::FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let log = restored.file_bytes_owned(SOFTWARE_LOG).unwrap();
    let mut rebooted = installed_software();
    let base = rebooted.sequence;
    assert_eq!(nt_hive_core::try_replay_log(&mut rebooted, &log, base), Ok(base + 2));
    let run_once = rebooted.open_key(RUN_ONCE).expect("RunOnce key stays");
    assert_eq!(rebooted.query_value(run_once, "GuiRunOnce"), None);
    assert_eq!(rebooted.query_value(run_once, "DriverWritten"),
        Some((RegistryValueType::Dword, &data[..])));
}
