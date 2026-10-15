//! Physical v2 SYSTEM WAL ownership. CM chooses when each phase may advance.

use super::*;
use nt_fs::{
    OwnedBoundedBlockRange, RegistryWal, RegistryWalError, RegistryWalState,
    RegistryWalVerifiedDevice, WalSnapshotAnchor, WalSnapshotAnchorUpdate,
};

type WalDevice = OwnedBoundedBlockRange<snapshot_storage::Lease>;

enum Stage {
    Wal(RegistryWal<WalDevice>),
    Verified(RegistryWalVerifiedDevice<snapshot_storage::Lease>),
    Anchoring(WalSnapshotAnchorUpdate<snapshot_storage::Lease>),
    Anchored(snapshot_storage::Lease),
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
        let manifest = store.current_wal_checkpoint_manifest(&mut lease)
            .map_err(snapshot_store_error_status)?;
        // The generic checkpoint may repair a same-anchor torn companion payload.
        // A WAL marker cannot: its subsequent two-header anchor needs both payloads.
        store.validate_wal_journal_manifest(&mut lease, manifest)
            .map_err(snapshot_store_error_status)?;
        let expected = WalSnapshotAnchor {
            incarnation: manifest.incarnation,
            serial: manifest.high_water_serial,
            end_lba: manifest.high_water_end_lba,
        };
        let range = snapshot_storage::owned_wal_region(lease)
            .map_err(|(status, _lease)| status)?;
        let mut wal = RegistryWal::recover(range, manifest.incarnation).map_err(status)?;
        if wal.state() != RegistryWalState::Ready || wal.settled_anchor() != Some(expected) {
            // A committed but unanchored prefix or a recovered unmarked tail needs the
            // boot replay/repair owner. Letting another writer proceed could recycle it.
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            core::mem::forget(wal);
            return Err(nt_fs::STATUS_DATA_ERROR);
        }
        if let Err(error) = wal.begin(bytes) {
            // BEGIN is reservation only. Its failure leaves no physical effect.
            let range = wal.into_device().expect("failed WAL reservation has no effect");
            drop(range);
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
        let Some(Stage::Anchoring(update)) = self.stage.take() else { unreachable!() };
        let lease = update.into_device().expect("both WAL anchors durably advanced");
        self.stage = Some(Stage::Anchored(lease));
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
        if !matches!(self.stage.as_ref(), Some(Stage::Anchored(_)))
            || self.commit_receipt != Some(ack.receipt())
        {
            return Err(self);
        }
        let Some(Stage::Anchored(lease)) = self.stage.take() else { unreachable!() };
        drop(lease);
        Ok(())
    }

    pub(crate) fn release_after_abort(
        mut self,
        ack: nt_config_client::SystemHiveMutationAbortAcknowledgement,
    ) -> Result<(), Self> {
        if self.abort_receipt != Some(ack.receipt()) {
            return Err(self);
        }
        let Some(Stage::Wal(wal)) = self.stage.as_ref() else {
            return Err(self);
        };
        if wal.state() != RegistryWalState::Ready {
            return Err(self);
        }
        let Some(Stage::Wal(wal)) = self.stage.take() else { unreachable!() };
        let range = wal.into_device().expect("confirmed WAL abort is settled");
        drop(range);
        Ok(())
    }
}
