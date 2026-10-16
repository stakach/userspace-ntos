use super::*;
use crate::snapshot_test_device::CachedDisk;
use crate::WalSnapshotManifest;
use alloc::{boxed::Box, rc::Rc};
use core::cell::Cell;

const PATH: &str = r"\??\C:\Config\Hive.LOG";

struct Caller(Rc<Cell<usize>>);
impl Drop for Caller {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn filesystem(existing: bool) -> FileSystem {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    if existing {
        assert!(fs.provision_file(PATH, b"base"));
    }
    fs
}

fn store() -> SnapshotBlockStore {
    SnapshotBlockStore::new(0, 16)
}

fn empty_wal_manifest() -> WalSnapshotManifest {
    WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 0,
        high_water_end_lba: 0,
    }
}

fn wal_baseline(fs: &FileSystem, disk: &mut CachedDisk) {
    for _ in 0..2 {
        fs.commit_volume_snapshot_with_wal_manifest(&store(), disk, empty_wal_manifest())
            .unwrap();
    }
    disk.events.clear();
}

#[test]
fn owned_storage_returns_only_after_authorized_terminal_release() {
    let drops = Rc::new(Cell::new(0));
    let mut work = OwnedSnapshotJournal::open(
        filesystem(true),
        CachedDisk::new(),
        store(),
        PATH,
        b"tail".to_vec(),
        Caller(drops.clone()),
    )
    .unwrap_or_else(|_| panic!("admission"));
    work = match work.release_after_publication() {
        Err(work) => work,
        Ok(_) => panic!("premature release"),
    };
    work.make_durable().unwrap();
    work = match work.release_after_publication() {
        Err(work) => work,
        Ok(_) => panic!("durable is not published"),
    };
    work.begin_publication().unwrap();
    let (fs, mut disk, caller) = work
        .release_after_publication()
        .unwrap_or_else(|_| panic!("release"));
    assert_eq!(fs.try_file_bytes_owned(PATH).unwrap().unwrap(), b"basetail");
    assert_eq!(drops.get(), 0);
    disk.power_cut();
    let (restored, _, _) = FileSystem::restore_volume_snapshot_from_store(&store(), &mut disk)
        .unwrap()
        .unwrap();
    assert_eq!(
        restored.try_file_bytes_owned(PATH).unwrap().unwrap(),
        b"basetail"
    );
    drop(caller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn failed_barrier_retains_exact_extent_and_retries_without_duplicate_append() {
    let mut disk = CachedDisk::new();
    disk.fail_event = Some(0);
    let mut work =
        OwnedSnapshotJournal::open(filesystem(true), disk, store(), PATH, b"tail".to_vec(), 17)
            .unwrap_or_else(|_| panic!("admission"));
    assert!(work.make_durable().is_err());
    assert_eq!(work.phase(), SnapshotJournalPhase::FlushPending);
    assert_eq!(work.context(), &17);
    // Failure injection only: production callers have no mutable access to owned storage.
    work.inner.dev.fail_event = None;
    work.make_durable().unwrap();
    work.begin_publication().unwrap();
    let (fs, _, context) = work
        .release_after_publication()
        .unwrap_or_else(|_| panic!("release"));
    assert_eq!(context, 17);
    assert_eq!(fs.try_file_bytes_owned(PATH).unwrap().unwrap(), b"basetail");
}

#[test]
fn first_journal_rollback_restores_durable_absence_before_release() {
    let mut work = OwnedSnapshotJournal::create(
        filesystem(false),
        CachedDisk::new(),
        store(),
        PATH,
        b"first".to_vec(),
        9,
    )
    .unwrap_or_else(|_| panic!("admission"));
    work.make_durable().unwrap();
    work.rollback().unwrap();
    let (fs, mut disk, context) = work
        .release_rolled_back()
        .unwrap_or_else(|_| panic!("release"));
    assert_eq!(context, 9);
    assert_eq!(fs.try_file_len(PATH), Ok(None));
    disk.power_cut();
    let (restored, _, _) = FileSystem::restore_volume_snapshot_from_store(&store(), &mut disk)
        .unwrap()
        .unwrap();
    assert_eq!(restored.try_file_len(PATH), Ok(None));
}

#[test]
fn admission_failure_returns_all_storage_and_inputs() {
    let error = match OwnedSnapshotJournal::create(
        filesystem(true),
        CachedDisk::new(),
        store(),
        PATH,
        b"new".to_vec(),
        71,
    ) {
        Err(error) => error,
        Ok(_) => panic!("collision accepted"),
    };
    assert_eq!(error.status, STATUS_OBJECT_NAME_COLLISION);
    assert_eq!(error.journal, b"new");
    assert_eq!(error.context, 71);
    assert!(error.device.events.is_empty());
    assert_eq!(
        error
            .filesystem
            .try_file_bytes_owned(PATH)
            .unwrap()
            .unwrap(),
        b"base"
    );
}

#[test]
fn dropping_unresolved_owned_work_does_not_unlock_reserve_or_drop_caller() {
    let reserve = Box::leak(Box::new(crate::SnapshotReserve::new(
        CachedDisk::new(),
        99,
        store(),
    )));
    let lease = reserve.try_acquire().unwrap();
    let drops = Rc::new(Cell::new(0));
    let work = OwnedSnapshotJournal::open(
        filesystem(true),
        lease,
        store(),
        PATH,
        b"tail".to_vec(),
        Caller(drops.clone()),
    )
    .unwrap_or_else(|_| panic!("admission"));
    drop(work);
    assert!(reserve.try_acquire().is_none());
    assert_eq!(drops.get(), 0);
}

#[test]
fn confirmed_release_returns_the_exact_reserve_lease_still_locked() {
    let reserve = Box::leak(Box::new(crate::SnapshotReserve::new(
        CachedDisk::new(),
        101,
        store(),
    )));
    let lease = reserve.try_acquire().unwrap();
    let mut work =
        OwnedSnapshotJournal::open(filesystem(true), lease, store(), PATH, b"tail".to_vec(), ())
            .unwrap_or_else(|_| panic!("admission"));
    work.rollback().unwrap();
    let (_, lease, ()) = work
        .release_rolled_back()
        .unwrap_or_else(|_| panic!("release"));
    assert_eq!(*lease.identity(), 101);
    assert!(reserve.try_acquire().is_none());
    drop(lease);
    assert!(reserve.try_acquire().is_some());
}

#[test]
fn owned_wal_journal_append_keeps_v2_headers_and_exact_lease_until_publication() {
    let reserve = Box::leak(Box::new(crate::SnapshotReserve::new(
        CachedDisk::new(),
        103,
        store(),
    )));
    let fs = filesystem(true);
    let mut lease = reserve.try_acquire().unwrap();
    wal_baseline(&fs, lease.test_device_mut());
    let mut work = OwnedSnapshotJournal::open_with_wal_manifest(
        fs,
        lease,
        store(),
        PATH,
        b"tail".to_vec(),
        31,
        empty_wal_manifest(),
    )
    .unwrap_or_else(|_| panic!("v2 journal admission"));
    assert!(reserve.try_acquire().is_none());
    work.make_durable().unwrap();
    assert_eq!(work.phase(), SnapshotJournalPhase::Durable);
    assert_eq!(work.context(), &31);
    assert!(reserve.try_acquire().is_none());
    work.begin_publication().unwrap();
    let (_, mut lease, caller) = work.release_after_publication().unwrap_or_else(|_| panic!("v2 release"));
    assert_eq!(caller, 31);
    assert_eq!(*lease.identity(), 103);
    assert!(reserve.try_acquire().is_none());
    lease.test_device_mut().power_cut();
    let selected = store().read_latest_wal(&mut lease).unwrap().unwrap();
    assert_eq!(selected.anchor.incarnation, 77);
    assert_eq!(selected.anchor.serial, 0);
    let restored = FileSystem::from_volume_snapshot(&selected.snapshot.payload).unwrap();
    assert_eq!(restored.try_file_bytes_owned(PATH).unwrap().unwrap(), b"basetail");
    drop(lease);
    assert!(reserve.try_acquire().is_some());
}

#[test]
fn owned_wal_journal_rollback_preserves_v2_baseline_and_original_extent() {
    let reserve = Box::leak(Box::new(crate::SnapshotReserve::new(
        CachedDisk::new(),
        105,
        store(),
    )));
    let fs = filesystem(true);
    let mut lease = reserve.try_acquire().unwrap();
    wal_baseline(&fs, lease.test_device_mut());
    let mut work = OwnedSnapshotJournal::open_with_wal_manifest(
        fs,
        lease,
        store(),
        PATH,
        b"tail".to_vec(),
        37,
        empty_wal_manifest(),
    )
    .unwrap_or_else(|_| panic!("v2 journal admission"));
    work.make_durable().unwrap();
    work.rollback().unwrap();
    let (_, mut lease, caller) = work.release_rolled_back().unwrap_or_else(|_| panic!("v2 rollback"));
    assert_eq!(caller, 37);
    assert_eq!(*lease.identity(), 105);
    assert!(reserve.try_acquire().is_none());
    lease.test_device_mut().power_cut();
    let selected = store().read_latest_wal(&mut lease).unwrap().unwrap();
    assert_eq!(selected.anchor.incarnation, 77);
    assert_eq!(selected.anchor.serial, 0);
    let restored = FileSystem::from_volume_snapshot(&selected.snapshot.payload).unwrap();
    assert_eq!(restored.try_file_bytes_owned(PATH).unwrap().unwrap(), b"base");
    drop(lease);
    assert!(reserve.try_acquire().is_some());
}

#[test]
fn owned_wal_first_journal_rollback_preserves_durable_absence() {
    let fs = filesystem(false);
    let mut disk = CachedDisk::new();
    wal_baseline(&fs, &mut disk);
    let mut work = OwnedSnapshotJournal::create_with_wal_manifest(
        fs,
        disk,
        store(),
        PATH,
        b"first".to_vec(),
        41,
        empty_wal_manifest(),
    )
    .unwrap_or_else(|_| panic!("v2 first journal admission"));
    work.make_durable().unwrap();
    work.rollback().unwrap();
    let (_, mut disk, caller) = work.release_rolled_back().unwrap_or_else(|_| panic!("v2 first journal rollback"));
    assert_eq!(caller, 41);
    disk.power_cut();
    let selected = store().read_latest_wal(&mut disk).unwrap().unwrap();
    let restored = FileSystem::from_volume_snapshot(&selected.snapshot.payload).unwrap();
    assert_eq!(restored.try_file_len(PATH), Ok(None));
}

#[test]
fn failed_wal_journal_barrier_retains_the_same_reserve_and_caller() {
    let reserve = Box::leak(Box::new(crate::SnapshotReserve::new(
        CachedDisk::new(),
        107,
        store(),
    )));
    let fs = filesystem(true);
    let mut lease = reserve.try_acquire().unwrap();
    wal_baseline(&fs, lease.test_device_mut());
    lease.test_device_mut().fail_event = Some(1);
    lease.test_device_mut().partial_flush = true;
    let drops = Rc::new(Cell::new(0));
    let mut work = OwnedSnapshotJournal::open_with_wal_manifest(
        fs,
        lease,
        store(),
        PATH,
        b"tail".to_vec(),
        Caller(drops.clone()),
        empty_wal_manifest(),
    )
    .unwrap_or_else(|_| panic!("v2 journal admission"));
    assert!(matches!(work.make_durable(), Err(SnapshotJournalError::Snapshot(_))));
    assert_eq!(work.phase(), SnapshotJournalPhase::FlushPending);
    assert!(work.durability().is_none());
    assert_eq!(drops.get(), 0);
    assert!(reserve.try_acquire().is_none());
    assert_eq!(work.begin_publication().err(), Some(SnapshotJournalError::InvalidPhase));
    drop(work);
    assert_eq!(drops.get(), 0);
    assert!(reserve.try_acquire().is_none());
}

#[test]
fn mixed_legacy_wal_slots_refuse_journal_before_append() {
    let fs = filesystem(true);
    let mut disk = CachedDisk::new();
    fs.commit_volume_snapshot(&store(), &mut disk).unwrap();
    fs.commit_volume_snapshot_with_wal_manifest(&store(), &mut disk, empty_wal_manifest())
        .unwrap();
    disk.events.clear();
    let error = match OwnedSnapshotJournal::open_with_wal_manifest(
        fs,
        disk,
        store(),
        PATH,
        b"tail".to_vec(),
        43,
        empty_wal_manifest(),
    ) {
        Ok(_) => panic!("mixed baseline admitted"),
        Err(error) => error,
    };
    assert_eq!(error.status, STATUS_DATA_ERROR);
    assert_eq!(error.journal, b"tail");
    assert_eq!(error.context, 43);
    assert!(error.device.events.is_empty());
    assert_eq!(error.filesystem.try_file_bytes_owned(PATH).unwrap().unwrap(), b"base");
}

#[test]
fn owned_wal_journal_refuses_unproven_anchored_base_before_append() {
    let anchored = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 1,
        high_water_end_lba: 3,
    };
    for proposed_base in [0, 1] {
        let fs = filesystem(true);
        let mut disk = CachedDisk::new();
        for _ in 0..2 {
            fs.commit_volume_snapshot_with_wal_manifest(&store(), &mut disk, anchored)
                .unwrap();
        }
        disk.events.clear();
        let error = match OwnedSnapshotJournal::open_with_wal_manifest(
            fs,
            disk,
            store(),
            PATH,
            b"tail".to_vec(),
            47,
            WalSnapshotManifest { base_serial: proposed_base, ..anchored },
        ) {
            Ok(_) => panic!("unproven WAL fold admitted"),
            Err(error) => error,
        };
        assert_eq!(error.status, STATUS_DATA_ERROR);
        assert_eq!(error.journal, b"tail");
        assert_eq!(error.context, 47);
        assert!(error.device.events.is_empty());
        assert_eq!(error.filesystem.try_file_bytes_owned(PATH).unwrap().unwrap(), b"base");
    }
}

#[test]
fn owned_legacy_journal_refuses_v2_slots_before_file_effects() {
    for existing in [false, true] {
        let fs = filesystem(existing);
        let mut disk = CachedDisk::new();
        wal_baseline(&fs, &mut disk);
        let result = if existing {
            OwnedSnapshotJournal::open(fs, disk, store(), PATH, b"tail".to_vec(), 53)
        } else {
            OwnedSnapshotJournal::create(fs, disk, store(), PATH, b"first".to_vec(), 53)
        };
        let error = match result {
            Ok(_) => panic!("legacy journal admitted on v2 volume"),
            Err(error) => error,
        };
        assert_eq!(error.status, STATUS_DATA_ERROR);
        assert_eq!(error.context, 53);
        assert!(error.device.events.is_empty());
        assert_eq!(error.filesystem.try_file_len(PATH).unwrap().is_some(), existing);
    }
}

#[test]
fn owned_wal_journal_refuses_base_older_than_newer_durable_slot() {
    let fs = filesystem(true);
    let mut disk = CachedDisk::new();
    let older = WalSnapshotManifest {
        incarnation: 77,
        base_serial: 0,
        high_water_serial: 2,
        high_water_end_lba: 6,
    };
    let newer = WalSnapshotManifest { base_serial: 1, ..older };
    fs.commit_volume_snapshot_with_wal_manifest(&store(), &mut disk, older)
        .unwrap();
    fs.commit_volume_snapshot_with_wal_manifest(&store(), &mut disk, newer)
        .unwrap();
    disk.events.clear();
    let error = match OwnedSnapshotJournal::open_with_wal_manifest(
        fs,
        disk,
        store(),
        PATH,
        b"tail".to_vec(),
        61,
        older,
    ) {
        Ok(_) => panic!("older WAL base admitted"),
        Err(error) => error,
    };
    assert_eq!(error.status, STATUS_DATA_ERROR);
    assert!(error.device.events.is_empty());
    assert_eq!(error.context, 61);
}
