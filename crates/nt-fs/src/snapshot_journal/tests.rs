use super::*;
use crate::snapshot_test_device::CachedDisk;
use alloc::rc::Rc;
use core::cell::Cell;

const PATH: &str = r"\??\C:\Config\Hive.LOG";
const BASE: &[u8] = b"original journal";

struct Caller(Rc<Cell<usize>>);
impl Drop for Caller {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn fixture() -> (FileSystem, CachedDisk, SnapshotBlockStore) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    assert!(fs.provision_file(PATH, BASE));
    let mut disk = CachedDisk::new();
    let store = SnapshotBlockStore::new(0, disk.sector_count());
    fs.commit_volume_snapshot(&store, &mut disk).unwrap();
    disk.events.clear();
    (fs, disk, store)
}

fn open<'a>(
    fs: &'a mut FileSystem,
    disk: &'a mut CachedDisk,
    store: SnapshotBlockStore,
    bytes: &[u8],
    drops: &Rc<Cell<usize>>,
) -> SnapshotJournal<'a, CachedDisk, Caller> {
    match SnapshotJournal::open(fs, disk, store, PATH, bytes.to_vec(), Caller(drops.clone())) {
        Ok(owner) => owner,
        Err(_) => panic!("journal admission failed"),
    }
}

fn release(mut work: SnapshotJournal<'_, CachedDisk, Caller>) -> Caller {
    work.begin_publication().unwrap();
    match work.release_after_publication() {
        Ok(caller) => caller,
        Err(_) => panic!("publication owner not released"),
    }
}

fn reboot_bytes(disk: &mut CachedDisk) -> Vec<u8> {
    disk.power_cut();
    let store = SnapshotBlockStore::new(0, disk.sector_count());
    let (fs, _, _) = FileSystem::restore_volume_snapshot_from_store(&store, disk)
        .unwrap()
        .unwrap();
    fs.try_file_bytes_owned(PATH).unwrap().unwrap()
}

fn legacy_v2_admission_status(
    fs: &mut FileSystem,
    disk: &mut CachedDisk,
    store: SnapshotBlockStore,
    existing: bool,
) -> (u32, u32) {
    let result = if existing {
        SnapshotJournal::open(fs, disk, store, PATH, b"tail".to_vec(), 59)
    } else {
        SnapshotJournal::create(fs, disk, store, PATH, b"first".to_vec(), 59)
    };
    match result {
        Ok(work) => {
            drop(work);
            panic!("borrowed legacy journal admitted on v2 volume");
        }
        Err(error) => (error.status, error.context),
    }
}

fn unavailable_read_admission(
    fs: &mut FileSystem,
    disk: &mut CachedDisk,
    store: SnapshotBlockStore,
    drops: &Rc<Cell<usize>>,
) -> SnapshotJournalOpenError<Caller> {
    match SnapshotJournal::open(
        fs,
        disk,
        store,
        PATH,
        b"new".to_vec(),
        Caller(drops.clone()),
    ) {
        Ok(work) => {
            drop(work);
            panic!("unreadable snapshot header admitted");
        }
        Err(error) => error,
    }
}

#[test]
fn borrowed_legacy_journal_refuses_v2_slots_before_file_effects() {
    for existing in [false, true] {
        let mut fs = FileSystem::new(MemFs::new());
        assert!(fs.provision_directory(r"\??\C:\Config"));
        if existing {
            assert!(fs.provision_file(PATH, BASE));
        }
        let mut disk = CachedDisk::new();
        let store = SnapshotBlockStore::new(0, disk.sector_count());
        let manifest = WalSnapshotManifest {
            incarnation: 77,
            base_serial: 0,
            high_water_serial: 0,
            high_water_end_lba: 0,
        };
        for _ in 0..2 {
            fs.commit_volume_snapshot_with_wal_manifest(&store, &mut disk, manifest)
                .unwrap();
        }
        disk.events.clear();
        let (status, context) = legacy_v2_admission_status(&mut fs, &mut disk, store, existing);
        assert_eq!(status, STATUS_DATA_ERROR);
        assert_eq!(context, 59);
        assert!(disk.events.is_empty());
        assert_eq!(fs.try_file_len(PATH).unwrap().is_some(), existing);
    }
}

#[test]
fn snapshot_is_durable_before_publication_and_keeps_complete_caller() {
    let (mut fs, mut disk, store) = fixture();
    let drops = Rc::new(Cell::new(0));
    let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
    assert_eq!(
        work.begin_publication().err(),
        Some(SnapshotJournalError::InvalidPhase)
    );
    assert!(work.durability().is_none());
    work.make_durable().unwrap();
    assert_eq!(work.phase(), SnapshotJournalPhase::Durable);
    let receipt = work.durability().unwrap();
    assert_eq!(receipt.snapshot_generation, 2);
    assert_eq!(receipt.original_end, BASE.len());
    assert_eq!(receipt.final_end, BASE.len() + 3);
    let events = work.dev.events.len();
    work.make_durable().unwrap();
    assert_eq!(work.dev.events.len(), events);
    assert_eq!(work.context().0.get(), 0);
    work.begin_publication().unwrap();
    assert_eq!(work.rollback(), Err(SnapshotJournalError::InvalidPhase));
    assert_eq!(work.make_durable(), Err(SnapshotJournalError::InvalidPhase));
    let caller = release(work);
    assert_eq!(drops.get(), 0);
    assert_eq!(reboot_bytes(&mut disk), [BASE, b"new"].concat());
    drop(caller);
    assert_eq!(drops.get(), 1);
    let opened = fs.zw_create_file(PATH, FILE_WRITE_DATA, 0, 0, FILE_OPEN, 0);
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_close(opened.handle), STATUS_SUCCESS);
}

#[test]
fn every_snapshot_write_and_barrier_error_retains_tail_then_retries_without_reappend() {
    let drops = Rc::new(Cell::new(0));
    let events = {
        let (mut fs, mut disk, store) = fixture();
        let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
        work.make_durable().unwrap();
        work.dev.events.len()
    };
    for partial in [false, true] {
        for fail in 0..events {
            let (mut fs, mut disk, store) = fixture();
            disk.fail_event = Some(fail);
            disk.partial_flush = partial;
            let drops = Rc::new(Cell::new(0));
            let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
            assert!(matches!(
                work.make_durable(),
                Err(SnapshotJournalError::Snapshot(_))
            ));
            assert_eq!(work.phase(), SnapshotJournalPhase::FlushPending);
            assert!(work.durability().is_none());
            assert_eq!(drops.get(), 0);
            assert_eq!(work.observed_tail(), Ok(3));
            assert_eq!(
                work.begin_publication().err(),
                Some(SnapshotJournalError::InvalidPhase)
            );
            // A second barrier failure must still retain exactly the same journal and caller.
            work.dev.fail_event = Some(work.dev.events.len());
            assert!(work.make_durable().is_err());
            work.dev.fail_event = None;
            work.make_durable().unwrap();
            assert_eq!(work.observed_tail(), Ok(3));
            drop(release(work));
            assert_eq!(drops.get(), 1);
            assert_eq!(reboot_bytes(&mut disk), [BASE, b"new"].concat());
        }
    }
}

#[test]
fn every_observed_partial_prefix_appends_only_the_missing_suffix() {
    let journal: Vec<u8> = (0..1100).map(|n| (n % 251) as u8).collect();
    for prefix in 0..=journal.len() {
        let (mut fs, mut disk, store) = fixture();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut fs, &mut disk, store, &journal, &drops);
        // Model an append whose completion was lost after this many bytes became visible.
        assert_eq!(
            work.fs.zw_append_file(work.handle, &journal[..prefix]),
            (STATUS_SUCCESS, prefix)
        );
        work.make_durable().unwrap();
        assert_eq!(work.observed_tail(), Ok(journal.len()));
        drop(release(work));
        assert_eq!(reboot_bytes(&mut disk), [BASE, journal.as_slice()].concat());
    }
}

#[test]
fn mismatched_excess_shortened_and_wrong_identity_extents_fail_without_effects() {
    for case in 0..4 {
        let (mut fs, mut disk, store) = fixture();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
        match case {
            0 => {
                work.fs.zw_append_file(work.handle, b"bad");
            }
            1 => {
                work.fs.zw_append_file(work.handle, b"new-extra");
            }
            2 => {
                assert_eq!(
                    work.fs.zw_set_information_file(
                        work.handle,
                        FILE_END_OF_FILE_INFORMATION,
                        &1u64.to_le_bytes()
                    ),
                    STATUS_SUCCESS
                );
            }
            _ => {
                work.file_id += 1;
            }
        }
        let before = work.fs.export_volume_snapshot().unwrap();
        assert_eq!(
            work.make_durable(),
            Err(SnapshotJournalError::ChangedExtent)
        );
        assert!(work.dev.events.is_empty());
        assert_eq!(work.fs.export_volume_snapshot().unwrap(), before);
        assert_eq!(drops.get(), 0);
        assert!(work.durability().is_none());
        // Failed rollback also retains the owner and cannot switch back to append.
        assert_eq!(work.rollback(), Err(SnapshotJournalError::ChangedExtent));
        assert_eq!(work.phase(), SnapshotJournalPhase::RollbackPending);
        assert_eq!(work.make_durable(), Err(SnapshotJournalError::InvalidPhase));
    }
}

#[test]
fn uncertain_rollback_keeps_caller_and_cannot_restart_publication() {
    let events = {
        let (mut fs, mut disk, store) = fixture();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
        work.make_durable().unwrap();
        work.dev.events.clear();
        work.rollback().unwrap();
        work.dev.events.len()
    };
    for (partial, fail) in [false, true]
        .into_iter()
        .flat_map(|partial| (0..events).map(move |fail| (partial, fail)))
    {
        let (mut fs, mut disk, store) = fixture();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
        work.make_durable().unwrap();
        work.dev.events.clear();
        work.dev.fail_event = Some(fail);
        work.dev.partial_flush = partial;
        assert!(work.rollback().is_err());
        assert_eq!(work.phase(), SnapshotJournalPhase::RollbackPending);
        assert_eq!(work.observed_tail(), Ok(0));
        assert!(work.durability().is_none());
        assert_eq!(
            work.begin_publication().err(),
            Some(SnapshotJournalError::InvalidPhase)
        );
        assert_eq!(work.make_durable(), Err(SnapshotJournalError::InvalidPhase));
        work = match work.release_rolled_back() {
            Err(work) => work,
            Ok(_) => panic!("early release"),
        };
        work.dev.fail_event = Some(work.dev.events.len());
        assert!(work.rollback().is_err());
        assert_eq!(work.phase(), SnapshotJournalPhase::RollbackPending);
        assert_eq!(work.observed_tail(), Ok(0));
        assert_eq!(drops.get(), 0);
        work.dev.fail_event = None;
        work.rollback().unwrap();
        assert_eq!(work.phase(), SnapshotJournalPhase::RolledBack);
        let caller = match work.release_rolled_back() {
            Ok(c) => c,
            Err(_) => panic!("rollback incomplete"),
        };
        assert_eq!(reboot_bytes(&mut disk), BASE);
        drop(caller);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn writer_conflict_retains_unwritten_inputs() {
    let (mut fs, mut disk, store) = fixture();
    let handle = fs.zw_create_file(
        PATH,
        FILE_WRITE_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0,
        FILE_OPEN,
        0,
    );
    assert_eq!(handle.status, STATUS_SUCCESS);
    let error = match SnapshotJournal::open(&mut fs, &mut disk, store, PATH, b"new".to_vec(), 7) {
        Err(error) => error,
        Ok(_) => panic!("competing writer admitted"),
    };
    assert_eq!(error.status, STATUS_SHARING_VIOLATION);
    assert_eq!(error.context, 7);
    assert_eq!(error.journal, b"new");
    assert!(disk.events.is_empty());
    assert_eq!(fs.try_file_bytes_owned(PATH).unwrap().unwrap(), BASE);
    assert_eq!(fs.zw_close(handle.handle), STATUS_SUCCESS);
}

#[test]
fn unavailable_snapshot_header_at_admission_retains_all_inputs_without_effects() {
    let (mut fs, mut disk, store) = fixture();
    let drops = Rc::new(Cell::new(0));
    disk.fail_read = Some(0);
    let error = unavailable_read_admission(&mut fs, &mut disk, store, &drops);
    assert_eq!(error.status, STATUS_DEVICE_NOT_READY);
    assert_eq!(error.journal, b"new");
    assert_eq!(drops.get(), 0);
    assert!(disk.events.is_empty());
    assert_eq!(fs.try_file_bytes_owned(PATH).unwrap().unwrap(), BASE);
    drop(error.context);
    assert_eq!(drops.get(), 1);
}

#[test]
fn unavailable_snapshot_reads_do_not_count_as_durable_or_repeat_append() {
    let (mut fs, mut disk, store) = fixture();
    let drops = Rc::new(Cell::new(0));
    let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
    work.dev.fail_read = Some(0);
    assert!(matches!(
        work.make_durable(),
        Err(SnapshotJournalError::Snapshot(_))
    ));
    assert_eq!(work.phase(), SnapshotJournalPhase::FlushPending);
    assert_eq!(work.observed_tail(), Ok(3));
    assert!(work.durability().is_none());
    work.dev.fail_read = None;
    work.make_durable().unwrap();
    drop(release(work));
    assert_eq!(reboot_bytes(&mut disk), [BASE, b"new"].concat());
}

#[test]
fn rollback_before_append_is_durable_and_cannot_be_published() {
    let (mut fs, mut disk, store) = fixture();
    let drops = Rc::new(Cell::new(0));
    let mut work = open(&mut fs, &mut disk, store, b"new", &drops);
    work = match work.release_after_publication() {
        Err(work) => work,
        Ok(_) => panic!("unpublished caller released"),
    };
    work.rollback().unwrap();
    assert!(work.durability().is_none());
    assert_eq!(
        work.begin_publication().err(),
        Some(SnapshotJournalError::InvalidPhase)
    );
    let events = work.dev.events.len();
    work.rollback().unwrap();
    assert_eq!(work.dev.events.len(), events);
    let caller = match work.release_rolled_back() {
        Ok(c) => c,
        Err(_) => panic!("rollback incomplete"),
    };
    assert_eq!(reboot_bytes(&mut disk), BASE);
    drop(caller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn admission_errors_return_inputs_without_writes_or_resource_loss() {
    for (path, bytes, status) in [
        (
            r"\??\C:\Config\Missing.LOG",
            b"new".as_slice(),
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            r"\??\Z:\Config\Hive.LOG",
            b"new".as_slice(),
            STATUS_OBJECT_PATH_NOT_FOUND,
        ),
        (
            r"\??\C:\Config",
            b"new".as_slice(),
            STATUS_FILE_IS_A_DIRECTORY,
        ),
        (PATH, b"".as_slice(), STATUS_INVALID_PARAMETER),
    ] {
        let (mut fs, mut disk, store) = fixture();
        let drops = Rc::new(Cell::new(0));
        let error = match SnapshotJournal::open(
            &mut fs,
            &mut disk,
            store,
            path,
            bytes.to_vec(),
            Caller(drops.clone()),
        ) {
            Err(e) => e,
            Ok(_) => panic!("invalid admission"),
        };
        assert_eq!(error.status, status);
        assert_eq!(error.journal, bytes);
        assert_eq!(drops.get(), 0);
        assert!(disk.events.is_empty());
        drop(error.context);
        assert_eq!(drops.get(), 1);
    }
}
