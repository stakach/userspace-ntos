//! Synchronous v2 hive WAL publication while the exact mounted disk still uses Boot AHCI.

use super::*;
use alloc::{string::String, vec::Vec};
use nt_fs::{
    AnchoredWalPublication, OwnedBoundedBlockRange, RegistryWalState, RegistryWalVerifiedDevice,
    VerifiedPairedWalSnapshot, WalSnapshotAnchorUpdate,
};

type Wal = RegistryWal<OwnedBoundedBlockRange<snapshot_storage::Lease>>;
type Verified = RegistryWalVerifiedDevice<snapshot_storage::Lease>;
type Anchor = WalSnapshotAnchorUpdate<snapshot_storage::Lease>;

enum Phase {
    Baseline,
    ReadyToEnter {
        wal: Wal,
        pair: VerifiedPairedWalSnapshot,
        store: nt_fs::SnapshotBlockStore,
    },
    EnteredWal {
        wal: Wal,
        pair: VerifiedPairedWalSnapshot,
        store: nt_fs::SnapshotBlockStore,
    },
    Verified {
        verified: Verified,
        pair: VerifiedPairedWalSnapshot,
        store: nt_fs::SnapshotBlockStore,
    },
    Anchoring(Anchor),
    Anchored {
        lease: snapshot_storage::Lease,
        publication: Option<AnchoredWalPublication>,
    },
    AwaitInstall(snapshot_storage::Lease),
    Released,
    Failed,
}

struct Journal {
    id: u64,
    path: String,
    record: Vec<u8>,
    encoded: Vec<u8>,
    new_log_len: u64,
    baseline: Baseline,
    phase: Phase,
    failed: Option<u32>,
}

static mut JOURNAL: Option<Journal> = None;
static mut NEXT_ID: u64 = 1;

pub(crate) unsafe fn has_retained_boot_hive_journal() -> bool {
    (&*core::ptr::addr_of!(JOURNAL)).is_some()
}

/// A Boot admission owns no WAL effect. A failure before `enter_boot_hive_journal` can release
/// the matching prepared CM edit after `abort_unentered_boot_hive_journal` succeeds.
pub(crate) unsafe fn begin_boot_hive_journal(path: &str, record: &[u8]) -> Result<u64, u32> {
    let _durable = crate::allocator::enter_durable();
    if (&*core::ptr::addr_of!(JOURNAL)).is_some() || native::has_retained_native_hive_journal() {
        return Err(snapshot_storage::BUSY);
    }
    ensure_mounted()?;
    let mount = crate::fs_loader::exec_fs_mount_identity().ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    if crate::fs_loader::exec_block_route_kind(mount) != Some(nt_fs::BlockSourceKind::Boot)
        || record.is_empty()
        || legacy_snapshot_writes_allowed()
        || WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.load(Ordering::Acquire)
    {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let path = clone_path(path)?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(record.len())
        .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    owned.extend_from_slice(record);
    let baseline = inspect_baseline(&path, &owned)?;
    let new_log_len = baseline
        .length
        .checked_add(u64::try_from(owned.len()).map_err(|_| nt_fs::STATUS_INVALID_PARAMETER)?)
        .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
    let encoded = nt_fs::encode_hive_log_wal_payload(HiveLogWalPayload {
        file_id: baseline.file_id,
        expected_log_len: baseline.length,
        path: &path,
        record: &owned,
    })
    .map_err(|error| match error {
        nt_fs::VolumeWalPayloadError::OutOfMemory => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        _ => nt_fs::STATUS_INVALID_PARAMETER,
    })?;
    let id = *core::ptr::addr_of!(NEXT_ID);
    let next = id
        .checked_add(1)
        .ok_or(nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    writable_fs()?.protect_wal_log(&path, baseline.file_id)?;
    *core::ptr::addr_of_mut!(NEXT_ID) = next;
    *core::ptr::addr_of_mut!(JOURNAL) = Some(Journal {
        id,
        path,
        record: owned,
        encoded,
        new_log_len,
        baseline,
        phase: Phase::Baseline,
        failed: None,
    });
    Ok(id)
}

fn restore_unentered(
    lease: snapshot_storage::Lease,
    token: nt_fs::RegistryWalContinuation,
    pair: VerifiedPairedWalSnapshot,
    status: u32,
) -> (u32, bool) {
    match snapshot_storage::install_wal_continuation(&lease, token, pair) {
        Ok(()) => {
            drop(lease);
            (status, true)
        }
        Err((error, token, pair)) => {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            core::mem::forget(lease);
            core::mem::forget(token);
            core::mem::forget(pair);
            (error, false)
        }
    }
}

fn restore_unentered_wal(
    mut wal: Wal,
    pair: VerifiedPairedWalSnapshot,
    status: u32,
) -> (u32, bool) {
    if wal.state() == RegistryWalState::PendingPrepare && wal.cancel_pending().is_err() {
        core::mem::forget(wal);
        core::mem::forget(pair);
        return (block(nt_fs::STATUS_DATA_ERROR), false);
    }
    let (range, token) = match wal.into_continuation() {
        Ok(parts) => parts,
        Err(wal) => {
            core::mem::forget(wal);
            core::mem::forget(pair);
            return (block(nt_fs::STATUS_DATA_ERROR), false);
        }
    };
    restore_unentered(range.into_device(), token, pair, status)
}

/// Complete the initial sidecar baseline and retain a WAL reservation without entering its
/// first physical write. Success allows the caller to mark its prepared CM edit entered.
pub(crate) unsafe fn prepare_boot_hive_journal(id: u64) -> Result<(), u32> {
    let _durable = crate::allocator::enter_durable();
    let journal = (&mut *core::ptr::addr_of_mut!(JOURNAL))
        .as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != id {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    if let Some(status) = journal.failed {
        return Err(status);
    }
    if matches!(journal.phase, Phase::ReadyToEnter { .. }) {
        return Ok(());
    }
    if !matches!(journal.phase, Phase::Baseline) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    let mount = crate::fs_loader::exec_fs_mount_identity().ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    if crate::fs_loader::exec_block_route_kind(mount) != Some(nt_fs::BlockSourceKind::Boot) {
        return Err(snapshot_storage::BUSY);
    }
    if journal.baseline.needs_checkpoint {
        checkpoint_dirty_volume()?;
        finish_baseline(&journal.path, &journal.record, &mut journal.baseline)?;
    }
    let mut lease = snapshot_storage::acquire()?;
    let (token, pair, manifest) =
        snapshot_storage::take_wal_continuation(&mut lease).map_err(block)?;
    let store = lease.store();
    let range = match snapshot_storage::owned_wal_region(lease) {
        Ok(range) => range,
        Err((status, lease)) => {
            let (status, restored) = restore_unentered(lease, token, pair, status);
            journal.phase = if restored {
                Phase::Released
            } else {
                Phase::Failed
            };
            journal.failed = Some(status);
            return Err(status);
        }
    };
    let expected = nt_fs::WalSnapshotAnchor {
        incarnation: manifest.incarnation,
        serial: manifest.high_water_serial,
        end_lba: manifest.high_water_end_lba,
    };
    let mut wal = match unsafe { RegistryWal::resume_from_continuation(range, token, expected) } {
        Ok(wal) => wal,
        Err((error, range, token)) => {
            let (status, restored) =
                restore_unentered(range.into_device(), token, pair, wal_status(error));
            journal.phase = if restored {
                Phase::Released
            } else {
                Phase::Failed
            };
            journal.failed = Some(status);
            return Err(status);
        }
    };
    if let Err(error) = wal.begin(core::mem::take(&mut journal.encoded)) {
        let (status, restored) = restore_unentered_wal(wal, pair, wal_status(error));
        journal.phase = if restored {
            Phase::Released
        } else {
            Phase::Failed
        };
        journal.failed = Some(status);
        return Err(status);
    }
    journal.phase = Phase::ReadyToEnter { wal, pair, store };
    Ok(())
}

/// The caller must first mark its exact prepared hive edit entered and retain it on failure.
/// Every failure after this call begins keeps the physical owner pinned and blocks new writers.
pub(crate) unsafe fn enter_boot_hive_journal(id: u64) -> Result<NativeHiveJournalReceipt, u32> {
    let _durable = crate::allocator::enter_durable();
    let journal = (&mut *core::ptr::addr_of_mut!(JOURNAL))
        .as_mut()
        .ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != id {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    if let Some(status) = journal.failed {
        return Err(status);
    }
    let mount = crate::fs_loader::exec_fs_mount_identity().ok_or(nt_fs::STATUS_DEVICE_NOT_READY)?;
    if crate::fs_loader::exec_block_route_kind(mount) != Some(nt_fs::BlockSourceKind::Boot) {
        return Err(snapshot_storage::BUSY);
    }
    // Allocate the receipt path before the first physical WAL effect.
    let receipt_path = clone_path(&journal.path)?;
    let Phase::ReadyToEnter { wal, pair, store } =
        core::mem::replace(&mut journal.phase, Phase::Failed)
    else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    journal.phase = Phase::EnteredWal { wal, pair, store };
    let Phase::EnteredWal { wal, .. } = &mut journal.phase else {
        unreachable!()
    };
    if let Err(error) = wal.prepare() {
        let status = block(wal_status(error));
        journal.failed = Some(status);
        return Err(status);
    }
    if let Err(error) = wal.commit() {
        let status = block(wal_status(error));
        journal.failed = Some(status);
        return Err(status);
    }
    let Phase::EnteredWal { wal, pair, store } =
        core::mem::replace(&mut journal.phase, Phase::Failed)
    else {
        unreachable!()
    };
    let verified = match wal.into_verified_device() {
        Ok(verified) => verified.into_full_device(),
        Err(wal) => {
            journal.phase = Phase::EnteredWal { wal, pair, store };
            journal.failed = Some(block(nt_fs::STATUS_DATA_ERROR));
            return Err(journal.failed.unwrap());
        }
    };
    journal.phase = Phase::Verified {
        verified,
        pair,
        store,
    };
    let Phase::Verified {
        verified,
        pair,
        store,
    } = core::mem::replace(&mut journal.phase, Phase::Failed)
    else {
        unreachable!()
    };
    let mut update = match WalSnapshotAnchorUpdate::admit_verified_wal_pair(store, verified, pair) {
        Ok(update) => update,
        Err((error, verified, pair)) => {
            journal.phase = Phase::Verified {
                verified,
                pair,
                store,
            };
            journal.failed = Some(block(snapshot_store_error_status(error)));
            return Err(journal.failed.unwrap());
        }
    };
    // The update retains the exact lease even if a header write or flush is uncertain.
    if let Err(error) = update.advance() {
        journal.phase = Phase::Anchoring(update);
        journal.failed = Some(block(snapshot_store_error_status(error)));
        return Err(journal.failed.unwrap());
    }
    let (lease, publication) = match update.into_anchored_publication() {
        Ok(parts) => parts,
        Err(update) => {
            journal.phase = Phase::Anchoring(update);
            journal.failed = Some(block(nt_fs::STATUS_DATA_ERROR));
            return Err(journal.failed.unwrap());
        }
    };
    journal.phase = Phase::Anchored {
        lease,
        publication: Some(publication),
    };
    if let Err(status) = replay_anchored_record(
        &journal.path,
        &journal.record,
        &journal.baseline,
        journal.new_log_len,
        ReplayMountError::AsReported,
    ) {
        journal.failed = Some(status);
        return Err(status);
    }
    let Phase::Anchored { lease, publication } =
        core::mem::replace(&mut journal.phase, Phase::Failed)
    else {
        unreachable!()
    };
    let anchored = publication.expect("newly anchored record receipt");
    journal.phase = Phase::AwaitInstall(lease);
    Ok(NativeHiveJournalReceipt {
        id,
        file_id: journal.baseline.file_id,
        expected_log_len: journal.baseline.length,
        log_path: receipt_path,
        anchored,
    })
}

pub(crate) unsafe fn abort_unentered_boot_hive_journal(id: u64) -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(JOURNAL);
    let journal = slot.as_ref().ok_or(nt_fs::STATUS_INVALID_DEVICE_REQUEST)?;
    if journal.id != id {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    match &journal.phase {
        Phase::Baseline | Phase::Released => {
            *slot = None;
            Ok(())
        }
        Phase::ReadyToEnter { .. } => {
            let journal = slot.take().expect("checked Boot hive journal");
            let Phase::ReadyToEnter { wal, pair, .. } = journal.phase else {
                unreachable!()
            };
            let (status, restored) = restore_unentered_wal(wal, pair, 0);
            if restored {
                Ok(())
            } else {
                Err(status)
            }
        }
        _ => Err(snapshot_storage::BUSY),
    }
}

/// Install the move-only continuation only after the matching CM edit was published.
pub(crate) unsafe fn install_boot_hive_publication(
    id: u64,
    token: nt_fs::RegistryWalContinuation,
    pair: VerifiedPairedWalSnapshot,
) -> Result<
    (),
    (
        u32,
        nt_fs::RegistryWalContinuation,
        VerifiedPairedWalSnapshot,
    ),
> {
    let slot = &mut *core::ptr::addr_of_mut!(JOURNAL);
    let Some(journal) = slot.as_ref() else {
        return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, token, pair));
    };
    if journal.id != id {
        return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, token, pair));
    }
    let Phase::AwaitInstall(lease) = &journal.phase else {
        return Err((nt_fs::STATUS_INVALID_DEVICE_REQUEST, token, pair));
    };
    if let Err((status, token, pair)) =
        snapshot_storage::install_wal_continuation(lease, token, pair)
    {
        return Err((block(status), token, pair));
    }
    let journal = slot.take().expect("checked Boot hive publication");
    let Phase::AwaitInstall(lease) = journal.phase else {
        unreachable!()
    };
    drop(lease);
    OVERLAY_WRITES.fetch_add(1, Ordering::Relaxed);
    OVERLAY_BYTES_WRITTEN.fetch_add(journal.record.len() as u64, Ordering::Relaxed);
    mark_runtime_dirty();
    Ok(())
}
