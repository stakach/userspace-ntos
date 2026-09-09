//! Retained creation/append and real snapshot barriers for an internal journal.
//!
//! Exclusive volume/device borrows bind every retry to the same storage authority. Native adapters
//! must retain this owner AND their complete caller continuation before any effect. This is not a
//! CM protocol owner or an NTFS persistence implementation.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotJournalPhase {
    CreatePending,
    CreateInFlight,
    AppendPending,
    FlushPending,
    Durable,
    PublicationStarted,
    RollbackPending,
    RemoveInFlight,
    RemoveFlushPending,
    RolledBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotJournalError {
    File(u32),
    Snapshot(SnapshotBlockStoreError),
    InvalidPhase,
    ChangedExtent,
}

/// Returned before any journal write. Neither the input journal nor caller state is lost.
#[derive(Debug)]
pub struct SnapshotJournalOpenError<C> {
    pub status: u32,
    pub journal: Vec<u8>,
    pub context: C,
}

/// Borrowed evidence, not a detachable authority to publish some other journal or mount.
#[derive(Debug)]
pub struct SnapshotJournalDurability {
    snapshot_generation: u64,
    snapshot_bytes: usize,
    file_id: u64,
    original_end: usize,
    final_end: usize,
}

impl SnapshotJournalDurability {
    pub fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }
    pub fn snapshot_bytes(&self) -> usize {
        self.snapshot_bytes
    }
    pub fn file_id(&self) -> u64 {
        self.file_id
    }
    pub fn original_end(&self) -> usize {
        self.original_end
    }
    pub fn final_end(&self) -> usize {
        self.final_end
    }
}

/// Owns the journal, its admitted file open, and all caller state across uncertain storage results.
/// No retry accepts a replacement volume, device, path, or byte buffer. The caller must keep this
/// value in retained work storage on error; dropping it is not a rollback or a durable completion.
///
/// ```compile_fail
/// use nt_fs::{FileSystem, SnapshotBlockDevice, SnapshotBlockStore, SnapshotJournal};
/// fn cannot_replace_volume<D: SnapshotBlockDevice>(fs: &mut FileSystem, dev: &mut D) {
///     let mut work = SnapshotJournal::open(fs, dev, SnapshotBlockStore::new(0, 16),
///         r"\??\C:\Hive.LOG", vec![1], ()).unwrap();
///     *fs = FileSystem::new(nt_fs::MemFs::new());
///     work.make_durable().unwrap();
/// }
/// ```
#[must_use = "retain unresolved journal work; an I/O error does not release its ownership"]
pub struct SnapshotJournal<'a, D: SnapshotBlockDevice, C> {
    fs: &'a mut FileSystem,
    dev: &'a mut D,
    store: SnapshotBlockStore,
    handle: u64,
    file_id: u64,
    original_end: usize,
    final_end: usize,
    journal: Vec<u8>,
    context: Option<C>,
    phase: SnapshotJournalPhase,
    durability: Option<SnapshotJournalDurability>,
    creation_path: Option<String>,
}

impl<'a, D: SnapshotBlockDevice, C> SnapshotJournal<'a, D, C> {
    /// Admit an existing journal with exclusive sharing. Missing files require explicit `create`
    /// admission, never an error-triggered fallback. File admission and length arithmetic precede
    /// append; snapshot/device errors can occur afterwards and retain the pending journal.
    pub fn open(
        fs: &'a mut FileSystem,
        dev: &'a mut D,
        store: SnapshotBlockStore,
        path: &str,
        journal: Vec<u8>,
        context: C,
    ) -> Result<Self, SnapshotJournalOpenError<C>> {
        let admit = (|| {
            if journal.is_empty() {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let original_end = fs.try_file_len(path)?.ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            let original_end = usize::try_from(original_end).map_err(|_| STATUS_DATA_ERROR)?;
            let final_end = original_end
                .checked_add(journal.len())
                .ok_or(STATUS_DATA_ERROR)?;
            u64::try_from(final_end).map_err(|_| STATUS_DATA_ERROR)?;
            let opened = fs.zw_create_file(
                path,
                FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                0,
                0,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            );
            if opened.status != STATUS_SUCCESS {
                return Err(opened.status);
            }
            // This exact open cannot disappear while the exclusive FileSystem borrow is held.
            let file_id = fs
                .zw_query_metadata(opened.handle)
                .expect("admitted journal")
                .file_id;
            Ok((opened.handle, file_id, original_end, final_end))
        })();
        match admit {
            Err(status) => Err(SnapshotJournalOpenError {
                status,
                journal,
                context,
            }),
            Ok((handle, file_id, original_end, final_end)) => Ok(Self {
                fs,
                dev,
                store,
                handle,
                file_id,
                original_end,
                final_end,
                journal,
                context: Some(context),
                phase: SnapshotJournalPhase::AppendPending,
                durability: None,
                creation_path: None,
            }),
        }
    }

    pub fn phase(&self) -> SnapshotJournalPhase {
        self.phase
    }
    pub fn context(&self) -> &C {
        self.context.as_ref().expect("retained caller")
    }
    pub fn durability(&self) -> Option<&SnapshotJournalDurability> {
        self.durability.as_ref()
    }

    // Check the entire observed tail, not just its length. Only our own append/truncate can alter
    // this exclusively borrowed file; the original prefix is never rewritten by this owner.
    fn observed_tail(&self) -> Result<usize, SnapshotJournalError> {
        let object = self
            .fs
            .obj(self.handle)
            .ok_or(SnapshotJournalError::ChangedExtent)?;
        let node = self
            .fs
            .volume
            .node(object.node_id)
            .ok_or(SnapshotJournalError::ChangedExtent)?;
        if self.fs.zw_query_metadata(self.handle).map(|m| m.file_id) != Some(self.file_id) {
            return Err(SnapshotJournalError::ChangedExtent);
        }
        let len = node
            .data
            .checked_len(&self.fs.volume.blobs)
            .map_err(SnapshotJournalError::File)?;
        if len < self.original_end || len > self.final_end {
            return Err(SnapshotJournalError::ChangedExtent);
        }
        let tail = len - self.original_end;
        let mut scratch = [0u8; 512];
        let mut offset = 0;
        while offset < tail {
            let count = core::cmp::min(scratch.len(), tail - offset);
            let read = node.data.read_into(
                &self.fs.volume.blobs,
                (self.original_end + offset) as u64,
                &mut scratch[..count],
            );
            if read != count || scratch[..count] != self.journal[offset..offset + count] {
                return Err(SnapshotJournalError::ChangedExtent);
            }
            offset += count;
        }
        Ok(tail)
    }

    /// Reconcile any partial append, append only its missing suffix, and publish a real snapshot.
    /// Every failure keeps the caller, exact bytes and phase. Once append is complete, retries
    /// perform only the barrier. A clean-bit observation or an earlier generation is never proof.
    pub fn make_durable(&mut self) -> Result<(), SnapshotJournalError> {
        use SnapshotJournalPhase::*;
        if self.phase == CreatePending {
            self.create_file()?;
        }
        if self.phase == Durable {
            return Ok(());
        }
        if !matches!(self.phase, AppendPending | FlushPending) {
            return Err(SnapshotJournalError::InvalidPhase);
        }
        let observed = self.observed_tail()?;
        if self.phase == AppendPending {
            if observed < self.journal.len() {
                let (status, count) = self
                    .fs
                    .zw_append_file(self.handle, &self.journal[observed..]);
                if status != STATUS_SUCCESS {
                    return Err(SnapshotJournalError::File(status));
                }
                if count != self.journal.len() - observed {
                    return Err(SnapshotJournalError::File(STATUS_DATA_ERROR));
                }
            }
            if self.observed_tail()? != self.journal.len() {
                return Err(SnapshotJournalError::ChangedExtent);
            }
            self.phase = FlushPending;
        } else if observed != self.journal.len() {
            return Err(SnapshotJournalError::ChangedExtent);
        }
        let (snapshot_generation, snapshot_bytes) = self
            .fs
            .commit_volume_snapshot(&self.store, self.dev)
            .map_err(SnapshotJournalError::Snapshot)?;
        self.durability = Some(SnapshotJournalDurability {
            snapshot_generation,
            snapshot_bytes,
            file_id: self.file_id,
            original_end: self.original_end,
            final_end: self.final_end,
        });
        self.phase = Durable;
        Ok(())
    }

    /// Cross the point after which CM may commit. The caller's retained protocol state can now be
    /// advanced, but storage rollback is permanently forbidden, including after any COMMIT error.
    pub fn begin_publication(&mut self) -> Result<&mut C, SnapshotJournalError> {
        if !matches!(
            self.phase,
            SnapshotJournalPhase::Durable | SnapshotJournalPhase::PublicationStarted
        ) {
            return Err(SnapshotJournalError::InvalidPhase);
        }
        self.phase = SnapshotJournalPhase::PublicationStarted;
        Ok(self.context.as_mut().expect("retained caller"))
    }

    /// Before publication only: restore the original EOF, or absence for a newly created journal,
    /// and durably publish rollback. Errors retain cleanup direction, never append/publication.
    pub fn rollback(&mut self) -> Result<(), SnapshotJournalError> {
        use SnapshotJournalPhase::*;
        if self.phase == RolledBack {
            return Ok(());
        }
        if self.phase == PublicationStarted {
            return Err(SnapshotJournalError::InvalidPhase);
        }
        if self.creation_path.is_some() {
            return self.rollback_creation();
        }
        self.phase = RollbackPending;
        self.durability = None;
        self.observed_tail()?;
        let status = self.fs.zw_set_information_file(
            self.handle,
            FILE_END_OF_FILE_INFORMATION,
            &(self.original_end as u64).to_le_bytes(),
        );
        if status != STATUS_SUCCESS {
            return Err(SnapshotJournalError::File(status));
        }
        self.fs
            .commit_volume_snapshot(&self.store, self.dev)
            .map_err(SnapshotJournalError::Snapshot)?;
        self.phase = RolledBack;
        Ok(())
    }

    /// Release caller resources only after a confirmed durable rollback. Failure returns the owner.
    pub fn release_rolled_back(mut self) -> Result<C, Self> {
        if self.phase != SnapshotJournalPhase::RolledBack {
            return Err(self);
        }
        Ok(self.context.take().expect("retained caller"))
    }

    /// Called by the protocol owner AFTER exact COMMIT reconciliation, local publication and ACK.
    /// Storage cannot verify those protocol effects; this is not an ACK proof or a native cutover.
    /// Before begin_publication this returns the complete owner unchanged.
    pub fn release_after_publication(mut self) -> Result<C, Self> {
        if self.phase != SnapshotJournalPhase::PublicationStarted {
            return Err(self);
        }
        Ok(self.context.take().expect("retained caller"))
    }
}

impl<D: SnapshotBlockDevice, C> Drop for SnapshotJournal<'_, D, C> {
    fn drop(&mut self) {
        // The private handle is held in an exclusively borrowed table and is closed exactly once.
        if self.handle != INVALID_HANDLE {
            let status = self.fs.zw_close(self.handle);
            debug_assert_eq!(status, STATUS_SUCCESS);
        }
    }
}

#[path = "snapshot_journal/creation.rs"]
mod creation;

#[cfg(test)]
#[path = "snapshot_journal/tests.rs"]
mod tests;
