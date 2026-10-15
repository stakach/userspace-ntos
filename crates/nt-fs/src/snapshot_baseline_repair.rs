//! Exact-lease repair of an interrupted empty-WAL snapshot baseline migration.

use crate::{
    FileSystem, RegistryWalVerifiedDevice, SnapshotBlockDevice, SnapshotBlockStore,
    SnapshotBlockStoreError, WalSnapshotManifest,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Ready,
    Complete,
    Uncertain,
}

/// Carries a verified empty WAL prefix and its physical lease through both snapshot slots.
/// The caller must supply a WAL view made from the same reserve lease and must not publish
/// the mounted filesystem until this repair has produced two valid v2 slots.
#[must_use = "retain the exact device when baseline repair has an uncertain storage effect"]
pub struct WalSnapshotBaselineRepair<D: SnapshotBlockDevice> {
    verified: Option<RegistryWalVerifiedDevice<D>>,
    store: SnapshotBlockStore,
    phase: Phase,
}

impl<D: SnapshotBlockDevice> core::fmt::Debug for WalSnapshotBaselineRepair<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalSnapshotBaselineRepair")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl<D: SnapshotBlockDevice> Drop for WalSnapshotBaselineRepair<D> {
    fn drop(&mut self) {
        if self.phase == Phase::Uncertain {
            if let Some(verified) = self.verified.take() {
                core::mem::forget(verified);
            }
            panic!("dropping uncertain WAL baseline repair");
        }
    }
}

impl<D: SnapshotBlockDevice> WalSnapshotBaselineRepair<D> {
    /// Admission performs no writes and returns the unchanged owner on refusal.
    pub fn admit(
        store: SnapshotBlockStore,
        verified: RegistryWalVerifiedDevice<D>,
    ) -> Result<Self, (SnapshotBlockStoreError, RegistryWalVerifiedDevice<D>)> {
        let anchor = verified.anchor();
        if anchor.incarnation == 0 || anchor.serial != 0 || anchor.end_lba != 0 {
            return Err((SnapshotBlockStoreError::Corrupt, verified));
        }
        Ok(Self {
            verified: Some(verified),
            store,
            phase: Phase::Ready,
        })
    }

    /// Repair the companion of a valid zero-WAL v2 checkpoint. `None` means both slots are
    /// still legacy, so the caller must first commit a v2 image under this same lease.
    /// Any error retains the lease because a storage barrier may have started an effect.
    pub fn repair(&mut self) -> Result<Option<u64>, SnapshotBlockStoreError> {
        if self.phase != Phase::Ready {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let verified = self.verified.as_mut().expect("retained verified WAL lease");
        let incarnation = verified.anchor().incarnation;
        let result = self.store.repair_empty_wal_baseline(verified.device_mut(), incarnation);
        self.phase = if result.is_ok() {
            Phase::Complete
        } else {
            Phase::Uncertain
        };
        result
    }

    /// Migrate a mounted legacy volume and finish both empty-WAL v2 slots under one lease.
    /// The caller must hold the filesystem exclusively until this returns: its current tree
    /// becomes the durable baseline. A reboot after any error must recover the storage state
    /// before the lease can be reused; this owner cannot replay an uncertain snapshot write.
    pub fn migrate(&mut self, fs: &FileSystem) -> Result<u64, SnapshotBlockStoreError> {
        if self.phase != Phase::Ready {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let verified = self.verified.as_mut().expect("retained verified WAL lease");
        let incarnation = verified.anchor().incarnation;
        let result = (|| {
            let state = self
                .store
                .repair_empty_wal_baseline(verified.device_mut(), incarnation)?;
            if let Some(generation) = state {
                return Ok(generation);
            }
            let manifest = WalSnapshotManifest {
                incarnation,
                base_serial: 0,
                high_water_serial: 0,
                high_water_end_lba: 0,
            };
            fs.commit_volume_snapshot_for_empty_wal_migration(
                &self.store,
                verified.device_mut(),
                manifest,
            )?;
            self.store
                .repair_empty_wal_baseline(verified.device_mut(), incarnation)?
                .ok_or(SnapshotBlockStoreError::Corrupt)
        })();
        self.phase = if result.is_ok() {
            Phase::Complete
        } else {
            Phase::Uncertain
        };
        result
    }

    /// Establish the first durable v2 volume on a proven empty reserve. A committed first
    /// slot is boot-repairable if the second slot or its barrier is interrupted.
    pub fn initialize(&mut self, fs: &FileSystem) -> Result<u64, SnapshotBlockStoreError> {
        if self.phase != Phase::Ready {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let verified = self.verified.as_mut().expect("retained verified WAL lease");
        let incarnation = verified.anchor().incarnation;
        let result = (|| {
            if self.store.read_latest(verified.device_mut())?.is_some() {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            let empty = WalSnapshotManifest {
                incarnation,
                base_serial: 0,
                high_water_serial: 0,
                high_water_end_lba: 0,
            };
            fs.commit_volume_snapshot_for_empty_wal_migration(
                &self.store, verified.device_mut(), empty,
            )?;
            self.store.repair_empty_wal_baseline(verified.device_mut(), incarnation)?
                .ok_or(SnapshotBlockStoreError::Corrupt)
        })();
        self.phase = if result.is_ok() { Phase::Complete } else { Phase::Uncertain };
        result
    }

    pub fn into_verified_device(mut self) -> Result<RegistryWalVerifiedDevice<D>, Self> {
        if self.phase == Phase::Complete {
            Ok(self.verified.take().expect("completed baseline repair"))
        } else {
            Err(self)
        }
    }
}
