use super::*;
use crate::snapshot_test_device::CachedDisk;
use alloc::rc::Rc;
use core::cell::Cell;

const PATH: &str = r"\??\C:\Config\First.LOG";
const BYTES: &[u8] = b"the first complete journal";

struct Caller(Rc<Cell<usize>>);
impl Drop for Caller {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn fixture() -> (FileSystem, CachedDisk, SnapshotBlockStore) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    let mut disk = CachedDisk::new();
    let store = SnapshotBlockStore::new(0, disk.sector_count());
    fs.commit_volume_snapshot(&store, &mut disk).unwrap();
    disk.events.clear();
    (fs, disk, store)
}

fn create<'a>(
    fs: &'a mut FileSystem,
    disk: &'a mut CachedDisk,
    store: SnapshotBlockStore,
    drops: &Rc<Cell<usize>>,
) -> SnapshotJournal<'a, CachedDisk, Caller> {
    match SnapshotJournal::create(fs, disk, store, PATH, BYTES.to_vec(), Caller(drops.clone())) {
        Ok(work) => work,
        Err(_) => panic!("creation admission failed"),
    }
}

fn reboot(disk: &mut CachedDisk) -> Option<Vec<u8>> {
    disk.power_cut();
    let store = SnapshotBlockStore::new(0, disk.sector_count());
    let (fs, _, _) = FileSystem::restore_volume_snapshot_from_store(&store, disk)
        .unwrap()
        .unwrap();
    fs.try_file_bytes_owned(PATH).unwrap()
}

fn cancel(mut work: SnapshotJournal<'_, CachedDisk, Caller>) -> Caller {
    work.rollback().unwrap();
    match work.release_rolled_back() {
        Ok(caller) => caller,
        Err(_) => panic!("rollback incomplete"),
    }
}

#[test]
fn reservation_is_effect_free_and_first_snapshot_contains_complete_journal() {
    let (mut fs, mut disk, store) = fixture();
    let drops = Rc::new(Cell::new(0));
    let mut work = create(&mut fs, &mut disk, store, &drops);
    assert_eq!(work.phase(), SnapshotJournalPhase::CreatePending);
    assert_eq!(work.fs.try_file_len(PATH), Ok(None));
    assert!(work.dev.events.is_empty());
    assert!(work.begin_publication().is_err());
    let pointer = work.journal.as_ptr();
    work.make_durable().unwrap();
    let id = work.file_id;
    assert_ne!(id, 0);
    assert_eq!(work.journal.as_ptr(), pointer);
    assert_eq!(work.durability().unwrap().original_end(), 0);
    assert_eq!(work.durability().unwrap().final_end(), BYTES.len());
    assert_eq!(
        work.fs.zw_query_metadata(work.handle).unwrap().attributes & FILE_ATTRIBUTE_READONLY,
        0
    );
    let events = work.dev.events.len();
    work.make_durable().unwrap();
    assert_eq!(work.dev.events.len(), events);
    assert_eq!(work.file_id, id);
    work.begin_publication().unwrap();
    assert!(work.rollback().is_err());
    let caller = match work.release_after_publication() {
        Ok(caller) => caller,
        Err(_) => panic!("publication incomplete"),
    };
    assert_eq!(drops.get(), 0);
    assert_eq!(reboot(&mut disk), Some(BYTES.to_vec()));
    drop(caller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn cancelling_before_create_persists_absence_without_creating_a_file() {
    let (mut fs, mut disk, store) = fixture();
    let drops = Rc::new(Cell::new(0));
    let work = create(&mut fs, &mut disk, store, &drops);
    drop(cancel(work));
    assert_eq!(drops.get(), 1);
    assert!(!disk.events.is_empty());
    assert_eq!(fs.try_file_len(PATH), Ok(None));
    assert_eq!(reboot(&mut disk), None);
}

#[test]
fn cancelling_before_create_does_not_resurrect_a_previously_deleted_file() {
    let (mut fs, mut disk, store) = fixture();
    assert!(fs.provision_file(PATH, b"old persisted journal"));
    fs.commit_volume_snapshot(&store, &mut disk).unwrap();
    let opened = fs.zw_create_file(PATH, DELETE, 0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(opened.handle, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_SUCCESS
    );
    assert_eq!(fs.zw_close(opened.handle), STATUS_SUCCESS);
    assert_eq!(fs.try_file_len(PATH), Ok(None));
    let mut work = create(&mut fs, &mut disk, store, &Rc::new(Cell::new(0)));
    work.dev.fail_event = Some(work.dev.events.len());
    assert!(work.rollback().is_err());
    assert_eq!(work.phase(), SnapshotJournalPhase::RemoveFlushPending);
    assert_eq!(work.handle, INVALID_HANDLE);
    assert!(work.make_durable().is_err());
    assert!(work.begin_publication().is_err());
    assert!(work.durability().is_none());
    work.dev.fail_event = None;
    drop(cancel(work));
    assert_eq!(reboot(&mut disk), None);
}

#[test]
fn creation_admission_returns_inputs_for_collision_wrong_volume_parent_directory_or_empty_bytes() {
    for path in [
        PATH,
        r"\??\D:\Config\First.LOG",
        r"\??\C:\Missing\First.LOG",
        r"\??\C:\Config",
    ] {
        let (mut fs, mut disk, store) = fixture();
        assert!(fs.provision_file(PATH, b"unrelated"));
        let journal = BYTES.to_vec();
        let pointer = journal.as_ptr();
        let error = match SnapshotJournal::create(&mut fs, &mut disk, store, path, journal, 7) {
            Ok(_) => panic!("invalid admission succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.journal.as_ptr(), pointer);
        assert_eq!(error.context, 7);
        assert_eq!(
            fs.try_file_bytes_owned(PATH).unwrap(),
            Some(b"unrelated".to_vec())
        );
        assert!(disk.events.is_empty());
    }
    let (mut fs, mut disk, store) = fixture();
    let error = match SnapshotJournal::create(&mut fs, &mut disk, store, PATH, Vec::new(), 9) {
        Ok(_) => panic!("empty journal accepted"),
        Err(error) => error,
    };
    assert_eq!(error.status, STATUS_INVALID_PARAMETER);
    assert_eq!(error.context, 9);
    assert_eq!(fs.try_file_len(PATH), Ok(None));
}

#[test]
fn file_acquisition_allocation_failures_retain_absence_then_retry_or_cancel() {
    for stage in 0..7 {
        for cancel_after_error in [false, true] {
            let (mut fs, mut disk, store) = fixture();
            let drops = Rc::new(Cell::new(0));
            let mut work = create(&mut fs, &mut disk, store, &drops);
            let file_id = work.fs.volume.next_file_id;
            let entry_id = work.fs.volume.next_entry_id;
            work.fs.create_fail_at = Some(stage);
            assert_eq!(
                work.make_durable(),
                Err(SnapshotJournalError::File(STATUS_INSUFFICIENT_RESOURCES))
            );
            assert_eq!(work.phase(), SnapshotJournalPhase::CreatePending);
            assert_eq!(work.fs.try_file_len(PATH), Ok(None));
            assert_eq!(work.handle, INVALID_HANDLE);
            assert_eq!(work.fs.volume.next_file_id, file_id);
            assert_eq!(work.fs.volume.next_entry_id, entry_id);
            assert!(work.dev.events.is_empty());
            assert_eq!(drops.get(), 0);
            if cancel_after_error {
                drop(cancel(work));
                assert_eq!(reboot(&mut disk), None);
            } else {
                work.make_durable().unwrap();
                assert_eq!(work.file_id, file_id);
                work.begin_publication().unwrap();
                drop(match work.release_after_publication() {
                    Ok(caller) => caller,
                    Err(_) => panic!(),
                });
                assert_eq!(reboot(&mut disk), Some(BYTES.to_vec()));
            }
            assert_eq!(drops.get(), 1);
        }
    }
}

#[test]
fn uncertain_create_never_adopts_or_deletes_a_colliding_file() {
    let (mut fs, mut disk, store) = fixture();
    let drops = Rc::new(Cell::new(0));
    let mut work = create(&mut fs, &mut disk, store, &drops);
    // Model a namespace effect without a published handle before the create completion.
    assert!(work.fs.provision_file(PATH, b"foreign"));
    assert_eq!(
        work.make_durable(),
        Err(SnapshotJournalError::File(STATUS_OBJECT_NAME_COLLISION))
    );
    assert_eq!(work.phase(), SnapshotJournalPhase::CreateInFlight);
    assert!(work.make_durable().is_err());
    assert!(work.rollback().is_err());
    assert!(work.durability().is_none());
    assert_eq!(
        work.fs.try_file_bytes_owned(PATH).unwrap(),
        Some(b"foreign".to_vec())
    );
    assert_eq!(drops.get(), 0);
    assert!(work.dev.events.is_empty());
}

#[test]
fn every_creation_snapshot_failure_retries_same_file_without_reappend() {
    let events = {
        let (mut fs, mut disk, store) = fixture();
        let mut work = create(&mut fs, &mut disk, store, &Rc::new(Cell::new(0)));
        work.make_durable().unwrap();
        work.dev.events.len()
    };
    for partial in [false, true] {
        for fail in 0..events {
            let (mut fs, mut disk, store) = fixture();
            disk.fail_event = Some(fail);
            disk.partial_flush = partial;
            let drops = Rc::new(Cell::new(0));
            let mut work = create(&mut fs, &mut disk, store, &drops);
            assert!(matches!(
                work.make_durable(),
                Err(SnapshotJournalError::Snapshot(_))
            ));
            assert_eq!(work.phase(), SnapshotJournalPhase::FlushPending);
            assert!(work.durability().is_none());
            let id = work.file_id;
            assert_eq!(work.observed_tail(), Ok(BYTES.len()));
            work.dev.fail_event = Some(work.dev.events.len());
            assert!(work.make_durable().is_err());
            work.dev.fail_event = None;
            work.make_durable().unwrap();
            assert_eq!(work.file_id, id);
            assert_eq!(work.observed_tail(), Ok(BYTES.len()));
            work.begin_publication().unwrap();
            let caller = match work.release_after_publication() {
                Ok(c) => c,
                Err(_) => panic!(),
            };
            assert_eq!(drops.get(), 0);
            assert_eq!(reboot(&mut disk), Some(BYTES.to_vec()));
            drop(caller);
            assert_eq!(drops.get(), 1);
        }
    }
}

#[test]
fn every_deletion_snapshot_failure_retains_absence_and_retries_only_barrier() {
    let events = {
        let (mut fs, mut disk, store) = fixture();
        let mut work = create(&mut fs, &mut disk, store, &Rc::new(Cell::new(0)));
        work.make_durable().unwrap();
        work.dev.events.clear();
        work.rollback().unwrap();
        work.dev.events.len()
    };
    for partial in [false, true] {
        for fail in 0..events {
            let (mut fs, mut disk, store) = fixture();
            let drops = Rc::new(Cell::new(0));
            let mut work = create(&mut fs, &mut disk, store, &drops);
            work.make_durable().unwrap();
            work.dev.events.clear();
            work.dev.fail_event = Some(fail);
            work.dev.partial_flush = partial;
            assert!(matches!(
                work.rollback(),
                Err(SnapshotJournalError::Snapshot(_))
            ));
            assert_eq!(work.phase(), SnapshotJournalPhase::RemoveFlushPending);
            assert_eq!(work.handle, INVALID_HANDLE);
            assert_eq!(work.fs.try_file_len(PATH), Ok(None));
            assert!(work.durability().is_none());
            assert!(work.make_durable().is_err());
            assert!(work.begin_publication().is_err());
            let mut work = match work.release_rolled_back() {
                Err(w) => w,
                Ok(_) => panic!(),
            };
            assert_eq!(drops.get(), 0);
            work.dev.fail_event = Some(work.dev.events.len());
            assert!(work.rollback().is_err());
            work.dev.fail_event = None;
            drop(cancel(work));
            assert_eq!(drops.get(), 1);
            assert_eq!(reboot(&mut disk), None);
        }
    }
}

#[test]
fn failed_create_snapshot_can_cancel_to_durable_absence() {
    let (mut fs, mut disk, store) = fixture();
    disk.fail_event = Some(0);
    let mut work = create(&mut fs, &mut disk, store, &Rc::new(Cell::new(0)));
    assert!(work.make_durable().is_err());
    work.dev.fail_event = None;
    drop(cancel(work));
    assert_eq!(reboot(&mut disk), None);
}

#[test]
fn removal_failure_stays_sticky_and_never_releases_an_unremoved_file() {
    let (mut fs, mut disk, store) = fixture();
    let mut work = create(&mut fs, &mut disk, store, &Rc::new(Cell::new(0)));
    work.make_durable().unwrap();
    let mut info = [0; 40];
    info[32..36].copy_from_slice(&FILE_ATTRIBUTE_READONLY.to_le_bytes());
    assert_eq!(
        work.fs
            .zw_set_information_file(work.handle, FILE_BASIC_INFORMATION, &info),
        STATUS_SUCCESS
    );
    assert!(work.rollback().is_err());
    assert_eq!(work.phase(), SnapshotJournalPhase::RollbackPending);
    assert!(work.make_durable().is_err());
    assert!(work.begin_publication().is_err());
    info[32..36].copy_from_slice(&FILE_ATTRIBUTE_NORMAL.to_le_bytes());
    assert_eq!(
        work.fs
            .zw_set_information_file(work.handle, FILE_BASIC_INFORMATION, &info),
        STATUS_SUCCESS
    );
    // Simulate close accepting a handle but failing to unlink its entry. No path-based deletion
    // may compensate, and no snapshot may be called evidence of successful cancellation.
    work.fs.obj_mut(work.handle).unwrap().entry_id = 0;
    let events = work.dev.events.len();
    assert_eq!(work.rollback(), Err(SnapshotJournalError::ChangedExtent));
    assert_eq!(work.phase(), SnapshotJournalPhase::RemoveFlushPending);
    assert_eq!(work.dev.events.len(), events);
    assert!(work.rollback().is_err());
    assert_eq!(
        work.fs.try_file_bytes_owned(PATH).unwrap(),
        Some(BYTES.to_vec())
    );
}

#[test]
fn dropped_owner_does_not_implicitly_delete_or_confirm_creation() {
    let (mut fs, mut disk, store) = fixture();
    disk.fail_event = Some(0);
    let drops = Rc::new(Cell::new(0));
    let mut work = create(&mut fs, &mut disk, store, &drops);
    assert!(work.make_durable().is_err());
    drop(work);
    assert_eq!(drops.get(), 1);
    assert_eq!(fs.try_file_bytes_owned(PATH).unwrap(), Some(BYTES.to_vec()));
    assert_eq!(reboot(&mut disk), None);
}
