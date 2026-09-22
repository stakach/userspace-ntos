//! Exclusive, owned storage for a pending CM journal. An absent global slot while work owns
//! the volume is contention, never permission to mount a replacement filesystem.

use super::*;
use alloc::vec::Vec;
use nt_fs::{OwnedSnapshotJournal, SnapshotJournalError};

static OWNED: AtomicBool = AtomicBool::new(false);

pub(super) fn owns_volume() -> bool {
    OWNED.load(Ordering::Acquire)
}

#[must_use = "retain journal work until confirmed publication or rollback"]
pub(crate) struct Journal<C> {
    storage: OwnedSnapshotJournal<snapshot_storage::Lease, C>,
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
            let device = snapshot_storage::acquire()?;
            let path = alloc::format!("{}.LOG", CONFIG_SYSTEM_HIVE_PATH);
            let exists = writable_fs()?.try_file_len(&path)?.is_some();
            Ok::<_, u32>((device, path, exists))
        })();
        let (device, path, exists) = match admission {
            Ok(admitted) => admitted,
            Err(status) => return Err((status, journal, context)),
        };
        // No IPC occurs between this admission and the move. All public access checks this gate.
        if OWNED.swap(true, Ordering::AcqRel) {
            return Err((snapshot_storage::BUSY, journal, context));
        }
        let filesystem = (&mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS))
            .take()
            .expect("admitted writable volume");
        let store = device.store();
        let result = if exists {
            OwnedSnapshotJournal::open(filesystem, device, store, &path, journal, context)
        } else {
            OwnedSnapshotJournal::create(filesystem, device, store, &path, journal, context)
        };
        match result {
            Ok(storage) => Ok(Self { storage }),
            Err(error) => {
                restore(error.filesystem);
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
        self.storage.make_durable().map_err(status)
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
                if let Some((generation, bytes)) = evidence {
                    WRITABLE_FS_SNAPSHOT_COMMITS.fetch_add(1, Ordering::Relaxed);
                    WRITABLE_FS_SNAPSHOT_COMMIT_GENERATION.store(generation, Ordering::Relaxed);
                    WRITABLE_FS_SNAPSHOT_COMMIT_BYTES.store(bytes as u64, Ordering::Relaxed);
                }
                WRITABLE_FS_SNAPSHOT_DIRTY.store(false, Ordering::Release);
                restore(filesystem);
                drop(device);
                publish_staged_profile();
                Ok(context)
            }
            Err(storage) => Err(Self { storage }),
        }
    }

    pub(crate) unsafe fn release_rolled_back(self) -> Result<C, Self> {
        let _durable = crate::allocator::enter_durable();
        match self.storage.release_rolled_back() {
            Ok((filesystem, device, context)) => {
                WRITABLE_FS_SNAPSHOT_DIRTY.store(false, Ordering::Release);
                restore(filesystem);
                drop(device);
                publish_staged_profile();
                Ok(context)
            }
            Err(storage) => Err(Self { storage }),
        }
    }
}

unsafe fn restore(filesystem: nt_fs::FileSystem) {
    let slot = &mut *core::ptr::addr_of_mut!(EXEC_WRITABLE_FS);
    assert!(slot.is_none() && owns_volume(), "registry journal volume ownership");
    *slot = Some(filesystem);
    OWNED.store(false, Ordering::Release);
    mark_runtime_dirty();
}

unsafe fn publish_staged_profile() {
    if let Some(image) = (&mut *core::ptr::addr_of_mut!(SETUP_DEFAULT_USER_NTUSER_IMAGE)).take() {
        let _ = set_default_user_ntuser_dat_image(image);
    }
}

fn status(error: SnapshotJournalError) -> u32 {
    match error {
        SnapshotJournalError::File(status) => status,
        SnapshotJournalError::Snapshot(error) => snapshot_store_error_status(error),
        SnapshotJournalError::InvalidPhase => nt_fs::STATUS_INVALID_PARAMETER,
        SnapshotJournalError::ChangedExtent => nt_fs::STATUS_DATA_ERROR,
    }
}
