//! Exclusive, owned storage for a pending CM journal. An absent global slot while work owns
//! the volume is contention, never permission to mount a replacement filesystem.

use super::*;
use alloc::vec::Vec;
use nt_fs::{OwnedSnapshotJournal, SnapshotJournalError};

#[must_use = "retain journal work until confirmed publication or rollback"]
pub(crate) struct Journal<C> {
    storage: OwnedSnapshotJournal<snapshot_storage::Lease, C>,
    owner: nt_fs::VolumeOwner<'static>,
    mount: nt_memory_manager::SectionMountId,
    journal_bytes: usize,
}

impl<C> Journal<C> {
    /// Capture the actual mounted filesystem and its published device reserve before any write.
    /// Admission errors return every caller input and restore the same filesystem instance.
    pub(crate) unsafe fn admit(
        journal: Vec<u8>,
        context: C,
    ) -> Result<Self, (u32, Vec<u8>, C)> {
        let _durable = crate::allocator::enter_durable();
        let admission = (|| {
            ensure_mounted()?;
            if !legacy_snapshot_writes_allowed() {
                return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
            }
            let device = snapshot_storage::acquire()?;
            let path = alloc::format!("{}.LOG", CONFIG_SYSTEM_HIVE_PATH);
            let exists = writable_fs()?.try_file_len(&path)?.is_some();
            Ok::<_, u32>((device, path, exists))
        })();
        let (device, path, exists) = match admission {
            Ok(admitted) => admitted,
            Err(status) => return Err((status, journal, context)),
        };
        let mount = *device.identity();
        let journal_bytes = journal.len();
        // No IPC occurs between this admission and the move. All public access checks this gate.
        let owner = match volume_owner::claim() {
            Ok(owner) => owner,
            Err(status) => return Err((status, journal, context)),
        };
        let Some(filesystem) = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS)).take() else {
            // The admitted FileSystem vanished. There is no exact instance to restore, so the
            // gate must remain claimed instead of authorizing a replacement mount.
            WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
            drop(owner);
            return Err((nt_fs::STATUS_DEVICE_NOT_READY, journal, context));
        };
        let store = device.store();
        let result = if exists {
            OwnedSnapshotJournal::open(filesystem, device, store, &path, journal, context)
        } else {
            OwnedSnapshotJournal::create(filesystem, device, store, &path, journal, context)
        };
        match result {
            Ok(storage) => Ok(Self { storage, owner, mount, journal_bytes }),
            Err(error) => {
                restore(error.filesystem, owner);
                drop(error.device);
                Err((error.status, error.journal, error.context))
            }
        }
    }

    pub(crate) fn context(&self) -> &C {
        self.storage.context()
    }

    pub(crate) fn make_durable(&mut self) -> Result<(), u32> {
        let _durable = crate::allocator::enter_durable();
        let phase_before = self.storage.phase();
        let window = nt_ahci::CommandWindow::start(&crate::AHCI_CENSUS, crate::diagnostic_time_100ns());
        let result = self.storage.make_durable().map_err(status);
        let delta = window.finish(crate::diagnostic_time_100ns());
        let phase_after = self.storage.phase();
        let durability = self.storage.durability().map(|proof| {
            (proof.snapshot_generation(), proof.snapshot_bytes())
        });
        crate::registry_checkpoint_audit::system_journal(
            self.mount, self.journal_bytes, phase_before, phase_after, durability, result, delta,
        );
        result
    }

    pub(crate) fn begin_publication(&mut self) -> Result<&mut C, u32> {
        self.storage.begin_publication().map_err(status)
    }

    pub(crate) fn rollback(&mut self) -> Result<(), u32> {
        let _durable = crate::allocator::enter_durable();
        self.storage.rollback().map_err(status)
    }

    /// The retained protocol owner calls this only after COMMIT, local publication and exact ACK.
    pub(crate) unsafe fn release_after_publication(self) -> Result<C, Self> {
        let _durable = crate::allocator::enter_durable();
        let evidence = self.storage.durability().map(|proof| {
            (proof.snapshot_generation(), proof.snapshot_bytes())
        });
        match self.storage.release_after_publication() {
            Ok((filesystem, device, context)) => {
                debug_assert!(legacy_snapshot_writes_allowed());
                if let Some((generation, bytes)) = evidence {
                    WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
                    WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
                    WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(bytes as u64, Ordering::Relaxed);
                }
                SNAPSHOT_PUBLICATION.clear_after_legacy_journal();
                restore(filesystem, self.owner);
                drop(device);
                Ok(context)
            }
            Err(storage) => Err(Self { storage, owner: self.owner,
                mount: self.mount, journal_bytes: self.journal_bytes }),
        }
    }

    pub(crate) unsafe fn release_rolled_back(self) -> Result<C, Self> {
        let _durable = crate::allocator::enter_durable();
        match self.storage.release_rolled_back() {
            Ok((filesystem, device, context)) => {
                debug_assert!(legacy_snapshot_writes_allowed());
                SNAPSHOT_PUBLICATION.clear_after_legacy_journal();
                restore(filesystem, self.owner);
                drop(device);
                Ok(context)
            }
            Err(storage) => Err(Self { storage, owner: self.owner,
                mount: self.mount, journal_bytes: self.journal_bytes }),
        }
    }
}

unsafe fn restore(filesystem: nt_fs::FileSystem, owner: nt_fs::VolumeOwner<'static>) {
    let slot = &mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS);
    assert!(slot.is_none() && volume_owner::owns_volume(), "owned writable volume restore");
    *slot = Some(filesystem);
    if unsafe { owner.release() }.is_err() {
        // An exact-token mismatch is not permission to admit another volume owner.
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
    }
    mark_runtime_dirty();
}

fn status(error: SnapshotJournalError) -> u32 {
    match error {
        SnapshotJournalError::File(status) => status,
        SnapshotJournalError::Snapshot(error) => snapshot_store_error_status(error),
        SnapshotJournalError::InvalidPhase => nt_fs::STATUS_INVALID_PARAMETER,
        SnapshotJournalError::ChangedExtent => nt_fs::STATUS_DATA_ERROR,
    }
}
