use super::*;
use crate::snapshot_test_device::CachedDisk;
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
