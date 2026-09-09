extern crate std;

use super::*;
use crate::mutation_commit::test_support::{client, image, prepare, Direct, PARENT};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::Cell;
use nt_config_abi::hive_mutation_commit_operation as operation;
use nt_fs::{MemFs, SnapshotBlockStoreError};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PRIMARY: &str = r"\??\C:\Config\SYSTEM";
const LOG: &str = r"\??\C:\Config\SYSTEM.LOG";

#[derive(Default)]
struct Controls {
    flushes: Cell<usize>,
    writes: Cell<usize>,
    fail_flush: Cell<Option<usize>>,
    persist_before_error: Cell<bool>,
    panic_flush: Cell<bool>,
}

struct Disk {
    stable: Vec<u8>,
    cache: Vec<u8>,
    controls: Rc<Controls>,
}

impl SnapshotBlockDevice for Disk {
    fn sector_size(&self) -> usize {
        512
    }
    fn sector_count(&self) -> u64 {
        (self.cache.len() / 512) as u64
    }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        out.copy_from_slice(&self.cache[lba as usize * 512..(lba as usize + 1) * 512]);
        Ok(())
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.cache[lba as usize * 512..(lba as usize + 1) * 512].copy_from_slice(data);
        self.controls.writes.set(self.controls.writes.get() + 1);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        assert!(!self.controls.panic_flush.get(), "injected storage unwind");
        let count = self.controls.flushes.get() + 1;
        self.controls.flushes.set(count);
        let fail = self.controls.fail_flush.get() == Some(count);
        if !fail || self.controls.persist_before_error.get() {
            self.stable.copy_from_slice(&self.cache);
        }
        if fail {
            Err(SnapshotBlockStoreError::Io)
        } else {
            Ok(())
        }
    }
}

struct Caller {
    drops: Rc<Cell<usize>>,
    publications: usize,
}
impl Drop for Caller {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

type Work<'a> = SnapshotSystemHivePublication<'a, Direct, Disk, Caller, u64>;

fn disk() -> (FileSystem, Disk, Rc<Controls>) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    assert!(fs.provision_file(PRIMARY, &image()));
    assert!(fs.provision_file(LOG, &[]));
    let controls = Rc::new(Controls::default());
    let mut dev = Disk {
        stable: vec![0; 64 * 512],
        cache: vec![0; 64 * 512],
        controls: controls.clone(),
    };
    fs.commit_volume_snapshot(&SnapshotBlockStore::new(0, 64), &mut dev)
        .unwrap();
    (fs, dev, controls)
}

fn open<'a>(
    client: &'a mut ConfigClient<Direct>,
    fs: &'a mut FileSystem,
    dev: &'a mut Disk,
    prepared: PreparedSystemHiveMutation,
    drops: &Rc<Cell<usize>>,
) -> Work<'a> {
    match Work::open(
        client,
        fs,
        dev,
        SnapshotBlockStore::new(0, 64),
        LOG,
        prepared,
        Caller {
            drops: drops.clone(),
            publications: 0,
        },
    ) {
        Ok(work) => work,
        Err(_) => panic!("admission failed"),
    }
}

fn publish(work: &mut Work<'_>) {
    work.publish_local(|caller, outcome| {
        caller.publications += 1;
        outcome.generation
    })
    .unwrap();
}

fn recovered(dev: &mut Disk, expected: &[u8]) {
    dev.cache.copy_from_slice(&dev.stable);
    let (fs, _, _) =
        FileSystem::restore_volume_snapshot_from_store(&SnapshotBlockStore::new(0, 64), dev)
            .unwrap()
            .unwrap();
    let bytes = fs.try_file_bytes_owned(LOG).unwrap().unwrap();
    assert_eq!(bytes, expected);
    let primary = fs.try_file_bytes_owned(PRIMARY).unwrap().unwrap();
    let mut hive = nt_hive_core::decode_image(&primary).unwrap();
    let sequence = hive.sequence;
    nt_hive_core::try_replay_log(&mut hive, &bytes, sequence).unwrap();
    assert!(hive.open_key(r"ControlSet001\Services\Child").is_some());
}

#[test]
fn repeated_storage_failure_blocks_commit_until_real_durability() {
    for (persist, barrier) in [false, true]
        .into_iter()
        .flat_map(|persist| (1..=3).map(move |barrier| (persist, barrier)))
    {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Child");
        let expected = prepared.durable_journal().to_vec();
        let before = client.backend.calls;
        let (mut fs, mut dev, controls) = disk();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
        controls.persist_before_error.set(persist);
        for attempt in 0..2 {
            let offset = if attempt == 0 { barrier } else { 1 };
            controls
                .fail_flush
                .set(Some(controls.flushes.get() + offset));
            assert!(work.make_durable().is_err());
            assert_eq!(
                work.phase(),
                SnapshotSystemHivePublicationPhase::StoragePending
            );
            assert_eq!(
                work.commit(),
                Err(SnapshotSystemHivePublicationError::InvalidPhase)
            );
            assert_eq!(work.client.backend.calls, before);
            assert_eq!(drops.get(), 0);
            assert!(work.take_completion().is_none());
        }
        controls.fail_flush.set(None);
        work.make_durable().unwrap();
        work.commit().unwrap();
        publish(&mut work);
        work.acknowledge().unwrap();
        let (caller, generation) = work.take_completion().unwrap();
        assert_eq!(caller.publications, 1);
        assert_eq!(generation, 2);
        assert!(work.take_completion().is_none());
        drop(work);
        recovered(&mut dev, &expected);
        drop(caller);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn lost_and_malformed_replies_never_repeat_local_publication_or_storage() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let expected = prepared.durable_journal().to_vec();
    let (mut fs, mut dev, controls) = disk();
    let drops = Rc::new(Cell::new(0));
    let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
    work.make_durable().unwrap();
    let writes = controls.writes.get();
    let flushes = controls.flushes.get();
    for corruption in 0..=14 {
        work.client.backend.corrupt = Some((operation::COMMIT, corruption));
        assert!(matches!(
            work.commit(),
            Err(SnapshotSystemHivePublicationError::Protocol(_))
        ));
        assert_eq!(
            work.phase(),
            SnapshotSystemHivePublicationPhase::CommitRetry
        );
        assert_eq!(work.continuation().unwrap().publications, 0);
        assert_eq!(
            work.acknowledge(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert!(work.take_completion().is_none());
        assert_eq!(drops.get(), 0);
    }
    work.commit().unwrap();
    assert_eq!(
        work.acknowledge(),
        Err(SnapshotSystemHivePublicationError::InvalidPhase)
    );
    publish(&mut work);
    for corruption in 0..=16 {
        work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, corruption));
        assert!(matches!(
            work.acknowledge(),
            Err(SnapshotSystemHivePublicationError::Protocol(_))
        ));
        assert_eq!(
            work.phase(),
            SnapshotSystemHivePublicationPhase::AcknowledgeRetry
        );
        assert_eq!(
            work.publish_local(|_, _| panic!("repeated local effect")),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.commit(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert!(work.take_completion().is_none());
    }
    work.acknowledge().unwrap();
    assert_eq!(controls.writes.get(), writes);
    assert_eq!(controls.flushes.get(), flushes);
    let (caller, generation) = work.take_completion().unwrap();
    assert_eq!(caller.publications, 1);
    assert_eq!(generation, 2);
    assert!(work.take_completion().is_none());
    drop(work);
    assert!(client
        .query_system_hive_key(&alloc::format!("{PARENT}\\Child"))
        .is_ok());
    recovered(&mut dev, &expected);
    drop(caller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn storage_commit_local_and_ack_unwinds_stay_inflight_without_implicit_retry() {
    use SnapshotSystemHivePublicationPhase::*;
    for expected_phase in [
        StorageInFlight,
        CommitInFlight,
        LocalInFlight,
        AcknowledgeInFlight,
    ] {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Child");
        let (mut fs, mut dev, controls) = disk();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
        let result = catch_unwind(AssertUnwindSafe(|| {
            if expected_phase == StorageInFlight {
                controls.panic_flush.set(true);
            }
            work.make_durable().unwrap();
            if expected_phase == CommitInFlight {
                work.client.backend.corrupt = Some((operation::COMMIT, 17));
            }
            work.commit().unwrap();
            work.publish_local(|caller, outcome| {
                caller.publications += 1;
                assert_ne!(
                    expected_phase, LocalInFlight,
                    "injected partial local effect"
                );
                outcome.generation
            })
            .unwrap();
            work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, 17));
            work.acknowledge().unwrap();
        }));
        assert!(result.is_err());
        assert_eq!(work.phase(), expected_phase);
        let calls = work.client.backend.calls;
        let writes = controls.writes.get();
        assert_eq!(
            work.make_durable(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.commit(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.publish_local(|_, _| panic!("second invocation")),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.acknowledge(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert!(work.take_completion().is_none());
        assert_eq!(work.client.backend.calls, calls);
        assert_eq!(controls.writes.get(), writes);
        assert_eq!(drops.get(), 0);
        assert_eq!(
            work.continuation().unwrap().publications,
            usize::from(matches!(
                expected_phase,
                LocalInFlight | AcknowledgeInFlight
            ))
        );
    }
}

#[test]
fn failed_admission_returns_original_preparation_and_caller_without_copying_journal() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let address = prepared.durable_journal().as_ptr();
    let expected = prepared.durable_journal().to_vec();
    let before = client.backend.calls;
    let (mut fs, mut dev, controls) = disk();
    let drops = Rc::new(Cell::new(0));
    let error = match Work::open(
        &mut client,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        r"\??\C:\Config\Missing.LOG",
        prepared,
        Caller {
            drops: drops.clone(),
            publications: 0,
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("missing log accepted"),
    };
    assert_eq!(error.prepared.durable_journal().as_ptr(), address);
    assert_eq!(error.prepared.durable_journal(), expected);
    assert_eq!(client.backend.calls, before);
    assert_eq!(drops.get(), 0);
    let mut work = Work::open(
        &mut client,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        LOG,
        error.prepared,
        error.continuation,
    )
    .ok()
    .unwrap();
    let writes = controls.writes.get();
    assert_eq!(
        work.acknowledge(),
        Err(SnapshotSystemHivePublicationError::InvalidPhase)
    );
    assert_eq!(
        work.publish_local(|_, _| panic!("early local effect")),
        Err(SnapshotSystemHivePublicationError::InvalidPhase)
    );
    assert_eq!(controls.writes.get(), writes);
    work.make_durable().unwrap();
    work.commit().unwrap();
    publish(&mut work);
    work.acknowledge().unwrap();
    let completion = work.take_completion().unwrap();
    drop(work);
    drop(completion);
    assert_eq!(drops.get(), 1);
}

#[test]
fn local_result_and_caller_survive_lost_ack_until_one_completion() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let (mut fs, mut dev, _) = disk();
    let caller_drops = Rc::new(Cell::new(0));
    let result_drops = Rc::new(Cell::new(0));
    let mut work = SnapshotSystemHivePublication::open(
        &mut client,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        LOG,
        prepared,
        Caller {
            drops: caller_drops.clone(),
            publications: 0,
        },
    )
    .ok()
    .unwrap();
    work.make_durable().unwrap();
    work.commit().unwrap();
    work.publish_local(|caller, _| {
        caller.publications += 1;
        Caller {
            drops: result_drops.clone(),
            publications: 0,
        }
    })
    .unwrap();
    work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, 0));
    assert!(work.acknowledge().is_err());
    assert!(work.take_completion().is_none());
    assert_eq!(caller_drops.get(), 0);
    assert_eq!(result_drops.get(), 0);
    work.acknowledge().unwrap();
    let completion = work.take_completion().unwrap();
    assert!(work.take_completion().is_none());
    drop(work);
    assert_eq!(caller_drops.get(), 0);
    assert_eq!(result_drops.get(), 0);
    drop(completion);
    assert_eq!(caller_drops.get(), 1);
    assert_eq!(result_drops.get(), 1);
}
