//! Fold a CM-owned SYSTEM checkpoint into both snapshot slots before retiring its WAL epoch.
//!
//! The physical reserve and CM preparation remain installed together through every effect. A
//! failed write or an uncertain CM acknowledgement blocks later writers; boot recovery can use
//! the old folded slot until RESETTING is published.

use super::*;
use nt_fs::SnapshotBlockDevice;

struct FoldWork {
    prepared: nt_config_client::PreparedSystemHiveCheckpoint,
    lease: snapshot_storage::Lease,
    old_continuation: Option<nt_fs::RegistryWalContinuation>,
    next_continuation: Option<nt_fs::RegistryWalContinuation>,
    phase: Phase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Folding,
    Acknowledging,
    Installing,
}

// An uncertain physical fold remains here until restart and boot recovery. CM retains the exact
// ACK result, so an uncertain ACK may be retried with this preparation and without replaying I/O.
static mut FOLD_WORK: Option<FoldWork> = None;

/// The service loop must redrive this exact CM ACK before trying another reserve owner.
pub(crate) fn system_wal_fold_ack_pending() -> bool {
    unsafe { (*core::ptr::addr_of!(FOLD_WORK)).as_ref()
        .is_some_and(|work| matches!(work.phase, Phase::Acknowledging | Phase::Installing)) }
}

/// Borrow the retained physical lease without transferring it to a recover/rollover operation
/// whose error type does not return the device. The lease itself always stays in FOLD_WORK.
struct FoldLease<'a>(&'a mut snapshot_storage::Lease);

impl SnapshotBlockDevice for FoldLease<'_> {
    fn sector_size(&self) -> usize { self.0.sector_size() }
    fn sector_count(&self) -> u64 { self.0.sector_count() }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        self.0.read_sector(lba, out)
    }
    fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        self.0.read_sectors(lba, out)
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        self.0.write_sector(lba, data)
    }
    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), nt_fs::SnapshotBlockStoreError> {
        self.0.write_sectors(lba, data)
    }
    fn flush(&mut self) -> Result<(), nt_fs::SnapshotBlockStoreError> { self.0.flush() }
}

fn block(status: u32) -> u32 {
    WRITABLE_FS_SNAPSHOT_DIRTY.store(true, Ordering::Release);
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
    WRITABLE_FS_SNAPSHOT_FAILURES.fetch_add(1, Ordering::Relaxed);
    status
}

/// Reclaim a WAL epoch only when its used region reaches three quarters of the reserve. A
/// routine CM fold advances the payload base without rewriting the whole WAL; the old typed
/// continuation still names the same anchored prefix for the next mutation.
fn needs_epoch_rollover(high_water_end_lba: u64, wal_sectors: u64) -> bool {
    high_water_end_lba != 0
        && high_water_end_lba >= wal_sectors.saturating_sub(wal_sectors / 4)
}

/// Background/shutdown checkpoint boundary. A clean CM observation has no image to fold.
/// An ambiguous ACK may be retried; an uncertain physical fold refuses reentry.
pub(crate) unsafe fn fold_system_wal_if_dirty() -> Result<bool, u32> {
    if let Some(work) = (*core::ptr::addr_of!(FOLD_WORK)).as_ref() {
        return match work.phase {
            Phase::Acknowledging => acknowledge_retained(),
            Phase::Installing => install_retained(),
            Phase::Folding => Err(nt_fs::STATUS_DEVICE_NOT_READY),
        };
    }
    ensure_mounted()?;
    if legacy_snapshot_writes_allowed() || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let mut lease = snapshot_storage::acquire()?;
    let store = lease.store();
    let manifest = store.current_paired_wal_journal_manifest(&mut lease)
        .map_err(|error| {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            snapshot_store_error_status(error)
        })?;
    let prepared = match crate::config_manager_prepare_system_hive_checkpoint() {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return Ok(false),
        Err(status) => return Err(status as u32),
    };
    let anchored = nt_fs::WalSnapshotAnchor {
        incarnation: manifest.incarnation,
        serial: manifest.high_water_serial,
        end_lba: manifest.high_water_end_lba,
    };
    let old = snapshot_storage::take_wal_continuation(&lease, anchored);
    let refused = old.as_ref().err().copied();
    *core::ptr::addr_of_mut!(FOLD_WORK) = Some(FoldWork {
        prepared, lease, old_continuation: old.ok(), next_continuation: None,
        phase: Phase::Folding,
    });
    if let Some(status) = refused {
        return Err(block(status));
    }
    mark_snapshot_dirty();

    let result = fold_retained(store, manifest);
    if let Err(status) = result {
        return Err(block(status));
    }
    (&mut *core::ptr::addr_of_mut!(FOLD_WORK)).as_mut()
        .expect("retained fold owner").phase = Phase::Acknowledging;
    acknowledge_retained()
}

unsafe fn fold_retained(
    store: nt_fs::SnapshotBlockStore,
    manifest: nt_fs::WalSnapshotManifest,
) -> Result<(), u32> {
    let work = (&mut *core::ptr::addr_of_mut!(FOLD_WORK))
        .as_mut().ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let fs = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS))
        .as_mut().ok_or(nt_fs::STATUS_INVALID_HANDLE)?;

    // The CM image is the full post-WAL state. Keep its exact preparation token in FOLD_WORK.
    let image = core::mem::take(&mut work.prepared.image);
    replace_boot_file(fs, CONFIG_SYSTEM_HIVE_PATH, image)?;
    let log_path = alloc::format!("{}.LOG", CONFIG_SYSTEM_HIVE_PATH);
    replace_boot_file(fs, &log_path, alloc::vec::Vec::new())?;

    let folded = nt_fs::WalSnapshotManifest {
        incarnation: manifest.incarnation,
        base_serial: manifest.high_water_serial,
        high_water_serial: manifest.high_water_serial,
        high_water_end_lba: manifest.high_water_end_lba,
    };
    // Both folded slots must contain the same CM image. Capture before the first disk write so
    // native I/O reentry cannot change the live tree between CRC and payload serialization.
    let snapshot_bytes = fs.export_volume_snapshot().map_err(|error| match error {
        nt_fs::MemFsSnapshotError::OutOfMemory => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        _ => 0xC000_0001,
    })?;
    let bytes = snapshot_bytes.len();
    let generation = store.commit_next_with_wal_manifest(&mut work.lease, &snapshot_bytes, folded)
        .map_err(snapshot_store_error_status)?;
    WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
    WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
    WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(bytes as u64, Ordering::Relaxed);
    // The second commit replaces the other slot. Both must carry the folded base before the
    // rollover can publish a RESETTING header or erase any old WAL sectors.
    let generation = store.commit_next_with_wal_manifest(&mut work.lease, &snapshot_bytes, folded)
        .map_err(snapshot_store_error_status)?;
    WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
    WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
    WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(bytes as u64, Ordering::Relaxed);

    let (start, sectors) = snapshot_storage::wal_bounds(&work.lease)?;
    if needs_epoch_rollover(manifest.high_water_end_lba, sectors) {
        let expected = nt_fs::WalSnapshotAnchor {
            incarnation: manifest.incarnation,
            serial: manifest.high_water_serial,
            end_lba: manifest.high_water_end_lba,
        };
        let borrowed = FoldLease(&mut work.lease);
        let range = nt_fs::OwnedBoundedBlockRange::new(borrowed, start, sectors)
            .map_err(|(error, _borrowed)| snapshot_store_error_status(error))?;
        let prior = work.old_continuation.take()
            .ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
        // Boot performed the full WAL scan. The token was minted only after both headers were
        // anchored and remained bound to this exact mounted reserve until fold admission.
        let wal = match unsafe { nt_fs::RegistryWal::resume_from_continuation(range, prior, expected) } {
            Ok(wal) => wal,
            Err((_error, range, prior)) => {
                drop(range);
                work.old_continuation = Some(prior);
                return Err(nt_fs::STATUS_DATA_ERROR);
            }
        };
        let verified = wal.into_verified_device().map_err(|wal| {
            core::mem::forget(wal);
            nt_fs::STATUS_DATA_ERROR
        })?;
        let next = manifest.incarnation.checked_add(1).ok_or(nt_fs::STATUS_DATA_ERROR)?;
        let mut rollover = nt_fs::WalSnapshotEpochRollover::admit(store, verified, next)
            .map_err(|(error, _verified)| snapshot_store_error_status(error))?;
        if let Err(error) = rollover.publish_resetting() {
            core::mem::forget(rollover);
            return Err(snapshot_store_error_status(error));
        }
        if let Err(error) = rollover.finish() {
            core::mem::forget(rollover);
            return Err(snapshot_store_error_status(error));
        }
        let (_borrowed, token) = rollover.into_continuation().map_err(|rollover| {
            core::mem::forget(rollover);
            nt_fs::STATUS_DATA_ERROR
        })?;
        drop(_borrowed);
        // The rollover's completed READY/erase barriers mint the empty next-incarnation token.
        // It stays private until the exact CM checkpoint ACK has been observed.
        work.next_continuation = Some(token);
    }
    Ok(())
}

unsafe fn acknowledge_retained() -> Result<bool, u32> {
    let work = (&*core::ptr::addr_of!(FOLD_WORK)).as_ref()
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    debug_assert!(work.phase == Phase::Acknowledging);
    if let Err(status) = crate::config_manager_acknowledge_system_hive_checkpoint(&work.prepared) {
        return Err(block(status as u32));
    }
    (&mut *core::ptr::addr_of_mut!(FOLD_WORK)).as_mut()
        .expect("acknowledged fold owner").phase = Phase::Installing;
    install_retained()
}

unsafe fn install_retained() -> Result<bool, u32> {
    let work = (&mut *core::ptr::addr_of_mut!(FOLD_WORK)).as_mut()
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    debug_assert!(work.phase == Phase::Installing);
    let rollover = work.next_continuation.is_some();
    let token = if rollover {
        work.next_continuation.take()
    } else {
        work.old_continuation.take()
    }.ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    if let Err((status, token)) = snapshot_storage::install_wal_continuation(&work.lease, token) {
        if rollover {
            work.next_continuation = Some(token);
        } else {
            work.old_continuation = Some(token);
        }
        return Err(block(status));
    }
    // The two folded slots are already durable. Keep any unrelated mounted-volume dirty work
    // visible to the ordinary snapshot checkpoint; a boolean cannot prove there was no writer
    // while CM processed the ACK.
    *core::ptr::addr_of_mut!(FOLD_WORK) = None;
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(false, Ordering::Release);
    Ok(true)
}
