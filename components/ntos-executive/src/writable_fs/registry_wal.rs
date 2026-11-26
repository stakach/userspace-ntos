//! CM mutation ownership over the physical SYSTEM WAL reserve.
//!
//! The journal matches exact CM storage bindings and receipts. Its physical owner retains the
//! mount lease, WAL continuation, paired snapshot proof, and all uncertain native I/O.

use super::*;
use nt_fs::RegistryWalContinuation;

#[path = "registry_wal/physical.rs"]
mod physical;
use physical::{Owner as PhysicalWalOwner, PairAuthority, restore_continuation};

#[path = "registry_wal/batch.rs"]
mod batch;
pub(crate) use batch::{BatchOwner, BatchReservation};

/// Keep the exact physical owner until CM acknowledges the matching publication or abort.
#[must_use = "retain the WAL owner through CM COMMIT, both anchors, and exact ACK"]
pub(crate) struct Journal {
    physical: PhysicalWalOwner,
    binding: nt_config_client::SystemHiveMutationStorageBinding,
    commit_receipt: Option<nt_config_client::SystemHiveMutationCommitReceipt>,
    abort_receipt: Option<nt_config_client::SystemHiveMutationAbortReceipt>,
    abort_done: bool,
}

impl Journal {
    pub(crate) fn mount(&self) -> nt_memory_manager::SectionMountId { self.physical.mount() }

    pub(crate) fn native_io_active(&self) -> bool { self.physical.native_io_active() }

    pub(crate) fn claim_native_io(&mut self) -> Result<Option<(nt_fs::AsyncWalIoRequest, nt_fs::BlockOperation, Vec<u8>)>, u32> {
        self.physical.claim_native_io()
    }

    pub(crate) fn mark_native_io_entered(&mut self, request: nt_fs::AsyncWalIoRequest) -> Result<(), u32> {
        self.physical.mark_native_io_entered(request)
    }

    pub(crate) fn release_unentered_native_io(&mut self, request: nt_fs::AsyncWalIoRequest) -> Result<(), u32> {
        self.physical.release_unentered_native_io(request)
    }

    pub(crate) fn refuse_unentered_native_io(&mut self, request: nt_fs::AsyncWalIoRequest) -> Result<nt_fs::AsyncWalRefusal, u32> {
        self.physical.refuse_unentered_native_io(request)
    }

    pub(crate) fn complete_native_io(&mut self, request: nt_fs::AsyncWalIoRequest,
        result: Result<&[u8], nt_status::NtStatus>) -> Result<super::native_snapshot_io::SnapshotCompletion, u32> {
        self.physical.complete_native_io(request, result)
    }

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
        ensure_mounted()?;
        if legacy_snapshot_writes_allowed() {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        let mut lease = snapshot_storage::acquire()?;
        let (continuation, pair, manifest) = snapshot_storage::take_wal_continuation(&mut lease)
            .map_err(|status| {
                WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
                status
            })?;
        Self::admit_authority(prepared, bytes, lease, continuation,
            PairAuthority::Plain(pair), manifest)
    }

    /// Continue admission after the exact two-header native recheck has completed and its
    /// physical lease and move-only proofs have been returned by the storage owner.
    pub(crate) unsafe fn admit_rechecked(
        prepared: &nt_config_client::PreparedSystemHiveMutation,
        bytes: Vec<u8>,
        lease: snapshot_storage::Lease,
        continuation: RegistryWalContinuation,
        rechecked: nt_fs::RecheckedPairedWalSnapshot,
    ) -> Result<Self, u32> {
        let manifest = rechecked.manifest();
        Self::admit_authority(prepared, bytes, lease, continuation,
            PairAuthority::Rechecked(rechecked), manifest)
    }

    unsafe fn admit_authority(
        prepared: &nt_config_client::PreparedSystemHiveMutation,
        bytes: Vec<u8>,
        lease: snapshot_storage::Lease,
        continuation: RegistryWalContinuation,
        authority: PairAuthority,
        manifest: nt_fs::WalSnapshotManifest,
    ) -> Result<Self, u32> {
        if bytes.as_slice() != prepared.durable_journal()
            || crate::LIVE_CONFIG_MANAGER_SYSTEM_MOUNT != Some(prepared.mount())
            || Some(*lease.identity()) != crate::fs_loader::exec_fs_mount_identity()
        {
            restore_continuation(lease, continuation, authority.into_pair())?;
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        let binding = prepared.storage_binding();
        // SAFETY: the exact mount and journal binding were checked above; the
        // retained authority proves the paired headers under this reserve lease.
        let physical = unsafe { PhysicalWalOwner::admit_authority(
            bytes, lease, continuation, authority, manifest,
        )? };
        Ok(Self { physical, binding, commit_receipt: None, abort_receipt: None, abort_done: false })
    }

    /// Durable PREPARE plus payload. A failure leaves this owner and lease unchanged.
    pub(crate) fn prepare(&mut self) -> Result<(), u32> { self.physical.prepare() }

    /// Only a retained receipt for this CM preparation may authorize the marker barrier.
    pub(crate) fn commit_marker(
        &mut self,
        receipt: nt_config_client::SystemHiveMutationCommitReceipt,
    ) -> Result<(), u32> {
        if !receipt.matches_storage_binding(self.binding)
            || self.abort_receipt.is_some()
            || self.commit_receipt.is_some_and(|previous| previous != receipt)
        {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        self.physical.can_commit_marker(self.commit_receipt == Some(receipt))?;
        self.commit_receipt = Some(receipt);
        self.physical.commit_marker()
    }

    /// Advance both v2 headers from the same verified WAL device.
    pub(crate) fn anchor(&mut self) -> Result<(), u32> { self.physical.anchor() }

    /// Clear a prepared, uncommitted frame after CM confirms exact ABORT.
    pub(crate) fn abort_prepared(
        &mut self,
        receipt: nt_config_client::SystemHiveMutationAbortReceipt,
    ) -> Result<(), u32> {
        if !self.physical.has_wal_stage()
            || self.commit_receipt.is_some()
            || !receipt.matches_storage_binding(self.binding)
            || self.abort_receipt.is_some_and(|previous| previous != receipt)
        {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        self.abort_receipt = Some(receipt);
        if self.abort_done { return Ok(()); }
        self.physical.abort_prepared()?;
        self.abort_done = true;
        Ok(())
    }

    pub(crate) fn release_after_ack(
        mut self,
        ack: nt_config_client::SystemHiveMutationAcknowledgement,
    ) -> Result<(), Self> {
        if self.commit_receipt != Some(ack.receipt()) {
            return Err(self);
        }
        match self.physical.release_anchored() {
            Ok(()) => Ok(()),
            Err(_) => Err(self),
        }
    }

    pub(crate) fn release_after_abort(
        mut self,
        ack: nt_config_client::SystemHiveMutationAbortAcknowledgement,
    ) -> Result<(), Self> {
        if self.abort_receipt != Some(ack.receipt()) {
            return Err(self);
        }
        match self.physical.release_aborted() {
            Ok(()) => Ok(()),
            Err(_) => Err(self),
        }
    }
}
