extern crate std;

use super::*;
use crate::snapshot_test_device::{CachedDisk, Event};
use crate::{FileSystem, MemFs, SnapshotJournal, SnapshotJournalPhase};
use alloc::string::String;
use core::cell::Cell;
use core::sync::atomic::AtomicUsize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Barrier;

const PATH: &str = r"\??\C:\Config\Hive.LOG";
const BASE: &[u8] = b"original journal";

fn reserve() -> SnapshotReserve<CachedDisk, (u64, String)> {
    SnapshotReserve::new(
        CachedDisk::new(),
        (37, String::from("backing reserve")),
        SnapshotBlockStore::new(0, 16),
    )
}

#[test]
fn one_reserve_excludes_competing_readers_and_writers_without_effects() {
    let reserve = reserve();
    let mut reader = reserve.try_acquire().unwrap();
    assert!(reserve.try_acquire().is_none());
    let store = reader.store();
    assert!(
        FileSystem::restore_volume_snapshot_from_store(&store, &mut reader)
            .unwrap()
            .is_none()
    );
    assert!(reader.device().events.is_empty());
    assert!(reserve.try_acquire().is_none());
    drop(reader);

    let mut writer = reserve.try_acquire().unwrap();
    assert!(reserve.try_acquire().is_none());
    writer.write_sector(2, &[0x71; 512]).unwrap();
    assert_eq!(writer.device().events, [Event::Write(2)]);
    assert!(reserve.try_acquire().is_none());
    writer.flush().unwrap();
    drop(writer);
    assert!(reserve.try_acquire().is_some());
}

#[test]
fn independent_reserves_preserve_exact_identity_geometry_and_backend() {
    let first = reserve();
    let second = SnapshotReserve::new(
        CachedDisk::new(),
        (91, String::from("other backing")),
        SnapshotBlockStore::new(2, 12),
    );
    let mut a = first.try_acquire().unwrap();
    let mut b = second.try_acquire().unwrap();
    assert_eq!(a.identity(), &(37, String::from("backing reserve")));
    assert_eq!(b.identity(), &(91, String::from("other backing")));
    assert_eq!(a.store(), SnapshotBlockStore::new(0, 16));
    assert_eq!(b.store(), SnapshotBlockStore::new(2, 12));
    assert_eq!((a.sector_size(), a.sector_count()), (512, 16));
    a.write_sectors(2, &[0x14; 1024]).unwrap();
    b.write_sector(2, &[0x28; 512]).unwrap();
    a.flush().unwrap();
    b.flush().unwrap();
    drop(a);
    drop(b);

    for (owner, value, store) in [
        (&first, 0x14, SnapshotBlockStore::new(0, 16)),
        (&second, 0x28, SnapshotBlockStore::new(2, 12)),
    ] {
        let mut lease = owner.try_acquire().unwrap();
        let mut sector = [0; 512];
        lease.device_mut().power_cut();
        lease.read_sector(2, &mut sector).unwrap();
        assert_eq!(sector, [value; 512]);
        assert_eq!(lease.store(), store);
    }
}

#[test]
fn read_write_and_barrier_failures_retain_exclusive_access_for_retry() {
    let reserve = reserve();
    let mut lease = reserve.try_acquire().unwrap();
    let mut sector = [0; 512];
    lease.device_mut().fail_read = Some(0);
    assert_eq!(
        lease.read_sector(0, &mut sector),
        Err(SnapshotBlockStoreError::Io)
    );
    assert!(reserve.try_acquire().is_none());
    lease.device_mut().fail_read = None;
    lease.read_sector(0, &mut sector).unwrap();

    lease.device_mut().fail_event = Some(0);
    assert_eq!(
        lease.write_sector(0, &[0x39; 512]),
        Err(SnapshotBlockStoreError::Io)
    );
    assert!(reserve.try_acquire().is_none());
    assert!(lease.device().pending.is_empty());
    lease.device_mut().fail_event = None;
    lease.write_sector(0, &[0x39; 512]).unwrap();

    lease.device_mut().fail_event = Some(2);
    assert_eq!(lease.flush(), Err(SnapshotBlockStoreError::Io));
    assert!(reserve.try_acquire().is_none());
    assert_eq!(lease.device().pending.len(), 1);
    assert!(lease.device().stable.iter().all(|&byte| byte == 0));
    lease.device_mut().fail_event = None;
    lease.flush().unwrap();
    lease.device_mut().power_cut();
    lease.read_sector(0, &mut sector).unwrap();
    assert_eq!(sector, [0x39; 512]);
}

#[test]
fn drop_releases_access_without_flushing_or_discarding_pending_bytes() {
    let reserve = reserve();
    let mut lease = reserve.try_acquire().unwrap();
    lease.write_sector(3, &[0x52; 512]).unwrap();
    drop(lease);

    let mut next = reserve.try_acquire().unwrap();
    assert_eq!(next.device().events, [Event::Write(3)]);
    assert_eq!(next.device().pending.len(), 1);
    assert!(next.device().stable.iter().all(|&byte| byte == 0));
    next.device_mut().power_cut();
    let mut sector = [0xff; 512];
    next.read_sector(3, &mut sector).unwrap();
    assert_eq!(sector, [0; 512]);
}

#[test]
fn unwind_releases_only_access_and_does_not_fabricate_a_barrier() {
    let reserve = reserve();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut lease = reserve.try_acquire().unwrap();
        lease.write_sector(4, &[0x73; 512]).unwrap();
        assert!(reserve.try_acquire().is_none());
        panic!("interrupted snapshot owner");
    }));
    assert!(result.is_err());
    let mut next = reserve.try_acquire().unwrap();
    assert_eq!(next.device().events, [Event::Write(4)]);
    assert_eq!(next.device().pending.len(), 1);
    next.device_mut().power_cut();
    let mut sector = [0xff; 512];
    next.read_sector(4, &mut sector).unwrap();
    assert_eq!(sector, [0; 512]);
}

fn mounted_fixture() -> (FileSystem, SnapshotReserve<CachedDisk, (u64, String)>) {
    let reserve = reserve();
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    assert!(fs.provision_file(PATH, BASE));
    let mut lease = reserve.try_acquire().unwrap();
    let store = lease.store();
    fs.commit_volume_snapshot(&store, &mut lease).unwrap();
    drop(lease);
    (fs, reserve)
}

#[test]
fn retained_journal_publication_uses_one_lease_then_restores_durable_bytes() {
    let (mut fs, reserve) = mounted_fixture();
    let mut lease = reserve.try_acquire().unwrap();
    let store = lease.store();
    let mut journal = SnapshotJournal::open(
        &mut fs,
        &mut lease,
        store,
        PATH,
        b" appended".to_vec(),
        0x1234u64,
    )
    .unwrap_or_else(|_| panic!("journal admission failed"));
    assert!(reserve.try_acquire().is_none());
    journal.make_durable().unwrap();
    assert_eq!(journal.phase(), SnapshotJournalPhase::Durable);
    assert_eq!(journal.durability().unwrap().snapshot_generation(), 2);
    assert!(reserve.try_acquire().is_none());
    assert_eq!(*journal.begin_publication().unwrap(), 0x1234);
    assert_eq!(journal.release_after_publication().ok(), Some(0x1234));
    assert!(reserve.try_acquire().is_none());
    drop(lease);

    let mut reader = reserve.try_acquire().unwrap();
    reader.device_mut().power_cut();
    let (restored, generation, _) =
        FileSystem::restore_volume_snapshot_from_store(&reader.store(), &mut reader)
            .unwrap()
            .unwrap();
    assert_eq!(generation, 2);
    assert_eq!(
        restored.try_file_bytes_owned(PATH).unwrap().unwrap(),
        [BASE, b" appended"].concat()
    );
}

#[test]
fn durable_journal_rollback_holds_the_same_reserve_until_caller_release() {
    let (mut fs, reserve) = mounted_fixture();
    let mut lease = reserve.try_acquire().unwrap();
    let store = lease.store();
    let mut journal = SnapshotJournal::open(
        &mut fs,
        &mut lease,
        store,
        PATH,
        b" rolled back".to_vec(),
        0x5678u64,
    )
    .unwrap_or_else(|_| panic!("journal admission failed"));
    journal.make_durable().unwrap();
    assert!(reserve.try_acquire().is_none());
    journal.rollback().unwrap();
    assert_eq!(journal.phase(), SnapshotJournalPhase::RolledBack);
    assert!(reserve.try_acquire().is_none());
    assert_eq!(journal.release_rolled_back().ok(), Some(0x5678));
    assert!(reserve.try_acquire().is_none());
    drop(lease);

    let mut reader = reserve.try_acquire().unwrap();
    reader.device_mut().power_cut();
    let (restored, generation, _) =
        FileSystem::restore_volume_snapshot_from_store(&reader.store(), &mut reader)
            .unwrap()
            .unwrap();
    assert_eq!(generation, 3);
    assert_eq!(restored.try_file_bytes_owned(PATH).unwrap().unwrap(), BASE);
}

struct CellDisk(Cell<u64>);

impl SnapshotBlockDevice for CellDisk {
    fn sector_size(&self) -> usize {
        8
    }
    fn sector_count(&self) -> u64 {
        1
    }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        assert_eq!(lba, 0);
        out.copy_from_slice(&self.0.get().to_le_bytes());
        Ok(())
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        assert_eq!(lba, 0);
        self.0.set(u64::from_le_bytes(data.try_into().unwrap()));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        Ok(())
    }
}

#[test]
fn backend_need_not_be_sync_but_shared_lease_must_not_expose_it_concurrently() {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    assert_send_sync::<SnapshotReserve<CellDisk, u64>>();
    assert_send::<SnapshotReserveLease<'static, CellDisk, u64>>();

    // This becomes ambiguous (and fails to compile) if the Cell-backed lease ever becomes Sync.
    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    let _ = <SnapshotReserveLease<'static, CellDisk, u64> as AmbiguousIfSync<_>>::check;
}

#[test]
fn threaded_contenders_serialize_a_send_but_not_sync_backend() {
    let reserve =
        SnapshotReserve::new(CellDisk(Cell::new(0)), 37u64, SnapshotBlockStore::new(0, 1));
    let barrier = Barrier::new(5);
    let active = AtomicUsize::new(0);
    let initial = reserve.try_acquire().unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                barrier.wait();
                assert!(reserve.try_acquire().is_none());
                barrier.wait();
                for _ in 0..128 {
                    let mut lease = loop {
                        if let Some(lease) = reserve.try_acquire() {
                            break lease;
                        }
                        std::thread::yield_now();
                    };
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    assert_eq!(*lease.identity(), 37);
                    let mut bytes = [0; 8];
                    lease.read_sector(0, &mut bytes).unwrap();
                    let next = u64::from_le_bytes(bytes) + 1;
                    lease.write_sector(0, &next.to_le_bytes()).unwrap();
                    assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                    drop(lease);
                }
            });
        }
        barrier.wait();
        barrier.wait();
        drop(initial);
    });
    assert_eq!(active.load(Ordering::SeqCst), 0);
    let mut lease = reserve.try_acquire().unwrap();
    let mut bytes = [0; 8];
    lease.read_sector(0, &mut bytes).unwrap();
    assert_eq!(u64::from_le_bytes(bytes), 512);
}
