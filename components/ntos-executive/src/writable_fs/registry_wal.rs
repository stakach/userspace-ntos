//! Physical v2 SYSTEM WAL ownership. CM chooses when each phase may advance.

use super::*;
use nt_fs::{
    OwnedBoundedBlockRange, RegistryWal, RegistryWalError, RegistryWalState,
    RegistryWalContinuation, RegistryWalVerifiedDevice, WalSnapshotAnchor,
    WalSnapshotAnchorUpdate,
};

type WalDevice = OwnedBoundedBlockRange<snapshot_storage::Lease>;

enum Stage {
    Wal(RegistryWal<WalDevice>),
    Verified(RegistryWalVerifiedDevice<snapshot_storage::Lease>),
    Anchoring(WalSnapshotAnchorUpdate<snapshot_storage::Lease>),
    Anchored(snapshot_storage::Lease, RegistryWalContinuation),
    Aborted(snapshot_storage::Lease, RegistryWalContinuation),
}

/// Keeps the exact reserve unavailable until both header barriers and the matching CM ACK.
/// The retained CM worker owns this value across every uncertain result.
#[must_use = "retain the WAL owner through CM COMMIT, both anchors, and exact ACK"]
pub(crate) struct Journal {
    store: nt_fs::SnapshotBlockStore,
    binding: nt_config_client::SystemHiveMutationStorageBinding,
    stage: Option<Stage>,
    commit_receipt: Option<nt_config_client::SystemHiveMutationCommitReceipt>,
    abort_receipt: Option<nt_config_client::SystemHiveMutationAbortReceipt>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        if let Some(stage) = self.stage.take() {
            core::mem::forget(stage);
            panic!("dropping unresolved native SYSTEM WAL owner");
        }
    }
}

fn status(error: RegistryWalError) -> u32 {
    match error {
        RegistryWalError::OutOfSpace
        | RegistryWalError::OutOfMemory
        | RegistryWalError::GenerationExhausted => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
        RegistryWalError::Storage(error) => snapshot_store_error_status(error),
        RegistryWalError::InvalidGeometry
        | RegistryWalError::WrongIncarnation
        | RegistryWalError::Corrupt
        | RegistryWalError::InvalidState => nt_fs::STATUS_DATA_ERROR,
        RegistryWalError::Uncertain => nt_fs::STATUS_DEVICE_NOT_READY,
    }
}

/// Return an untouched live proof to its exact mounted reserve. If that identity has changed,
/// retain the lease and proof instead of permitting a fresh scan to hide the contradiction.
fn restore_continuation(
    lease: snapshot_storage::Lease,
    continuation: RegistryWalContinuation,
) -> Result<(), u32> {
    match snapshot_storage::install_wal_continuation(&lease, continuation) {
        Ok(()) => {
            drop(lease);
            Ok(())
        }
        Err((status, continuation)) => {
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            core::mem::forget(continuation);
            core::mem::forget(lease);
            Err(status)
        }
    }
}

impl Journal {
    /// Admit only the mounted v2 pair whose exact anchored WAL prefix was recovered.
    /// This performs no sector write; on any ambiguous prefix, the lease stays closed.
    pub(crate) unsafe fn admit(
        prepared: &nt_config_client::PreparedSystemHiveMutation,
        bytes: Vec<u8>,
    ) -> Result<Self, u32> {
        if bytes.as_slice() != prepared.durable_journal()
            || crate::LIVE_CONFIG_MANAGER_SYSTEM_MOUNT != Some(prepared.mount())
        {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        let binding = prepared.storage_binding();
        ensure_mounted()?;
        if legacy_snapshot_writes_allowed() {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        let mut lease = snapshot_storage::acquire()?;
        let store = lease.store();
        // A WAL marker needs two intact payloads for its later two-header anchor.
        let manifest = store.current_paired_wal_journal_manifest(&mut lease)
            .map_err(snapshot_store_error_status)?;
        let expected = WalSnapshotAnchor {
            incarnation: manifest.incarnation,
            serial: manifest.high_water_serial,
            end_lba: manifest.high_water_end_lba,
        };
        let continuation = snapshot_storage::take_wal_continuation(&lease, expected)?;
        let range = match snapshot_storage::owned_wal_region(lease) {
            Ok(range) => range,
            Err((error, lease)) => {
                restore_continuation(lease, continuation)?;
                return Err(error);
            }
        };
        // Boot's full scan and paired-header barrier minted this one-use, mount-bound proof.
        // No physical WAL writer can intervene while the reserve lease is held here.
        let mut wal = match RegistryWal::resume_from_continuation(range, continuation, expected) {
            Ok(wal) => wal,
            Err((error, range, continuation)) => {
                restore_continuation(range.into_device(), continuation)?;
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                return Err(status(error));
            }
        };
        if let Err(error) = wal.begin(bytes) {
            // BEGIN is reservation only. Its failure leaves no physical effect.
            let (range, continuation) = wal.into_continuation()
                .expect("failed WAL reservation has no effect");
            restore_continuation(range.into_device(), continuation)?;
            return Err(status(error));
        }
        Ok(Self {
            store,
            binding,
            stage: Some(Stage::Wal(wal)),
            commit_receipt: None,
            abort_receipt: None,
        })
    }

    /// Durable PREPARE plus payload. A failure leaves this owner and lease unchanged.
    pub(crate) fn prepare(&mut self) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        wal.prepare().map_err(status)
    }

    /// Only a retained receipt for this CM preparation may authorize the marker barrier.
    pub(crate) fn commit_marker(
        &mut self,
        receipt: nt_config_client::SystemHiveMutationCommitReceipt,
    ) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        if wal.state() != RegistryWalState::Prepared
            || !receipt.matches_storage_binding(self.binding)
            || self.abort_receipt.is_some()
            || self.commit_receipt.is_some_and(|previous| previous != receipt)
        {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        self.commit_receipt = Some(receipt);
        wal.commit().map_err(status)?;
        let Some(Stage::Wal(wal)) = self.stage.take() else { unreachable!() };
        let verified = wal.into_verified_device()
            .expect("settled marker has a verified prefix")
            .into_full_device();
        self.stage = Some(Stage::Verified(verified));
        Ok(())
    }

    /// Advance both v2 headers from the same verified WAL device. An uncertain barrier
    /// stays in `Anchoring` and cannot be retried as a fresh write or released.
    pub(crate) fn anchor(&mut self) -> Result<(), u32> {
        if matches!(self.stage.as_ref(), Some(Stage::Verified(_))) {
            let Some(Stage::Verified(verified)) = self.stage.take() else { unreachable!() };
            let update = match WalSnapshotAnchorUpdate::admit_verified_wal(self.store, verified) {
                Ok(update) => update,
                Err((error, verified)) => {
                    self.stage = Some(Stage::Verified(verified));
                    return Err(snapshot_store_error_status(error));
                }
            };
            self.stage = Some(Stage::Anchoring(update));
        }
        let Some(Stage::Anchoring(update)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        update.advance().map_err(snapshot_store_error_status)?;
        SYSTEM_WAL_FOLD_REQUIRED.store(true, Ordering::Release);
        let Some(Stage::Anchoring(update)) = self.stage.take() else { unreachable!() };
        let (lease, continuation) = update.into_continuation()
            .expect("both WAL anchors durably advanced");
        self.stage = Some(Stage::Anchored(lease, continuation));
        Ok(())
    }

    /// Clear a prepared, uncommitted frame after CM confirms exact ABORT. A reservation
    /// that never entered PREPARE has no physical effect and can simply be cancelled.
    pub(crate) fn abort_prepared(
        &mut self,
        receipt: nt_config_client::SystemHiveMutationAbortReceipt,
    ) -> Result<(), u32> {
        let Some(Stage::Wal(wal)) = self.stage.as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        if self.commit_receipt.is_some()
            || !receipt.matches_storage_binding(self.binding)
            || self.abort_receipt.is_some_and(|previous| previous != receipt)
        {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        self.abort_receipt = Some(receipt);
        match wal.state() {
            RegistryWalState::PendingPrepare => wal.cancel_pending(),
            RegistryWalState::Prepared => wal.abort_prepared(),
            _ => Err(RegistryWalError::InvalidState),
        }
        .map_err(status)
    }

    pub(crate) fn release_after_ack(
        mut self,
        ack: nt_config_client::SystemHiveMutationAcknowledgement,
    ) -> Result<(), Self> {
        if !matches!(self.stage.as_ref(), Some(Stage::Anchored(_, _)))
            || self.commit_receipt != Some(ack.receipt())
        {
            return Err(self);
        }
        let Some(Stage::Anchored(lease, continuation)) = self.stage.take() else { unreachable!() };
        match snapshot_storage::install_wal_continuation(&lease, continuation) {
            Ok(()) => {
                drop(lease);
                Ok(())
            }
            Err((_status, continuation)) => {
                self.stage = Some(Stage::Anchored(lease, continuation));
                Err(self)
            }
        }
    }

    pub(crate) fn release_after_abort(
        mut self,
        ack: nt_config_client::SystemHiveMutationAbortAcknowledgement,
    ) -> Result<(), Self> {
        if self.abort_receipt != Some(ack.receipt()) {
            return Err(self);
        }
        if matches!(self.stage.as_ref(), Some(Stage::Wal(wal)) if wal.state() == RegistryWalState::Ready) {
            let Some(Stage::Wal(wal)) = self.stage.take() else { unreachable!() };
            let (range, continuation) = wal.into_continuation()
                .expect("confirmed WAL abort is settled");
            self.stage = Some(Stage::Aborted(range.into_device(), continuation));
        }
        let Some(Stage::Aborted(lease, continuation)) = self.stage.take() else {
            return Err(self);
        };
        match snapshot_storage::install_wal_continuation(&lease, continuation) {
            Ok(()) => {
                drop(lease);
                Ok(())
            }
            Err((_status, continuation)) => {
                // The exact abort was acknowledged, but native authority publication failed.
                // Keep the lease and proof in this owner for the same terminal redrive.
                self.stage = Some(Stage::Aborted(lease, continuation));
                Err(self)
            }
        }
    }
}
