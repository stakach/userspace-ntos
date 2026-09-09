use super::*;
use crate::mutation_commit::test_support::{image, Direct};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::Cell;
use nt_fs::{MemFs, SnapshotBlockStoreError};

pub(super) const PRIMARY: &str = r"\??\C:\Config\SYSTEM";
pub(super) const LOG: &str = r"\??\C:\Config\SYSTEM.LOG";

#[derive(Default)]
pub(super) struct Controls {
    pub(super) flushes: Cell<usize>,
    pub(super) writes: Cell<usize>,
    pub(super) fail_flush: Cell<Option<usize>>,
    pub(super) persist_before_error: Cell<bool>,
    pub(super) panic_flush: Cell<bool>,
}

pub(super) struct Disk {
    pub(super) stable: Vec<u8>,
    pub(super) cache: Vec<u8>,
    pub(super) controls: Rc<Controls>,
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

pub(super) struct Caller {
    pub(super) drops: Rc<Cell<usize>>,
    pub(super) publications: usize,
}
impl Drop for Caller {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

pub(super) type Work<'a> = SnapshotSystemHivePublication<'a, Direct, Disk, Caller, u64>;

pub(super) fn disk() -> (FileSystem, Disk, Rc<Controls>) {
    disk_with_log(true)
}

pub(super) fn disk_without_log() -> (FileSystem, Disk, Rc<Controls>) {
    disk_with_log(false)
}

fn disk_with_log(existing: bool) -> (FileSystem, Disk, Rc<Controls>) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    assert!(fs.provision_file(PRIMARY, &image()));
    if existing {
        assert!(fs.provision_file(LOG, &[]));
    }
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

pub(super) fn open<'a>(
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

pub(super) fn publish(work: &mut Work<'_>) {
    work.publish_local(|caller, outcome| {
        caller.publications += 1;
        outcome.generation
    })
    .unwrap();
}

pub(super) fn recovered(dev: &mut Disk, expected: &[u8]) {
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
