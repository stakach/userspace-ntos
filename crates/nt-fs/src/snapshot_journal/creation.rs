//! Explicit first-journal admission. Creation and its absent baseline stay with the append owner.

use super::*;

impl<'a, D: SnapshotBlockDevice, C> SnapshotJournal<'a, D, C> {
    /// Reserve a genuinely absent journal and all caller inputs before creating anything. The
    /// first make_durable performs FILE_CREATE, append and the existing ordered snapshot barrier.
    /// A collision is never opened or overwritten. Cancellation restores durable absence, not an
    /// empty file. Dropping the owner is neither cancellation nor confirmation of durability.
    pub fn create(
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
            u64::try_from(journal.len()).map_err(|_| STATUS_DATA_ERROR)?;
            if fs.try_file_len(path)?.is_some() {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
            let mut owned = String::new();
            owned
                .try_reserve_exact(path.len())
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            owned.push_str(path);
            Ok(owned)
        })();
        match admit {
            Err(status) => Err(SnapshotJournalOpenError {
                status,
                journal,
                context,
            }),
            Ok(path) => Ok(Self {
                fs,
                dev,
                store,
                handle: INVALID_HANDLE,
                file_id: 0,
                original_end: 0,
                final_end: journal.len(),
                journal,
                context: Some(context),
                phase: SnapshotJournalPhase::CreatePending,
                durability: None,
                creation_path: Some(path),
            }),
        }
    }

    pub(super) fn create_file(&mut self) -> Result<(), SnapshotJournalError> {
        use SnapshotJournalPhase::*;
        let path = self.creation_path.as_ref().expect("retained creation path");
        self.phase = CreateInFlight;
        let opened = self.fs.zw_create_file(
            path,
            FILE_READ_DATA | FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
            0,
            0,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
        );
        if opened.status != STATUS_SUCCESS {
            // Creation can mutate the namespace before file-object allocation fails. Only proved
            // absence permits retry/cancellation; never adopt a file from an uncertain create.
            if self.fs.try_file_len(path) == Ok(None) {
                self.phase = CreatePending;
            }
            return Err(SnapshotJournalError::File(opened.status));
        }
        self.handle = opened.handle;
        if opened.information != FILE_CREATED {
            return Err(SnapshotJournalError::ChangedExtent);
        }
        self.file_id = self
            .fs
            .zw_query_metadata(self.handle)
            .ok_or(SnapshotJournalError::ChangedExtent)?
            .file_id;
        self.observed_tail()?;
        self.phase = AppendPending;
        Ok(())
    }

    pub(super) fn rollback_creation(&mut self) -> Result<(), SnapshotJournalError> {
        use SnapshotJournalPhase::*;
        if matches!(
            self.phase,
            CreateInFlight | RemoveInFlight | PublicationStarted
        ) {
            return Err(SnapshotJournalError::InvalidPhase);
        }
        self.durability = None;
        if self.phase == CreatePending {
            // Live absence may be a prior, unflushed deletion. Even without a create effect,
            // establish the absent baseline on disk before claiming durable rollback.
            self.phase = RemoveFlushPending;
        }
        if self.phase != RemoveFlushPending {
            self.phase = RollbackPending;
            self.observed_tail()?;
            self.phase = RemoveInFlight;
            let status =
                self.fs
                    .zw_set_information_file(self.handle, FILE_DISPOSITION_INFORMATION, &[1]);
            if status != STATUS_SUCCESS {
                self.phase = RollbackPending;
                return Err(SnapshotJournalError::File(status));
            }
            let status = self.fs.zw_close(self.handle);
            if status != STATUS_SUCCESS {
                return Err(SnapshotJournalError::File(status));
            }
            self.handle = INVALID_HANDLE;
            self.phase = RemoveFlushPending;
        }
        // Delete-pending is not removal. Verify the namespace after the one close before a
        // barrier, and retain that phase so retries never delete by path or recreate the file.
        match self.fs.try_file_len(self.creation_path.as_ref().unwrap()) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(SnapshotJournalError::ChangedExtent),
            Err(status) => return Err(SnapshotJournalError::File(status)),
        }
        self.fs
            .commit_volume_snapshot(&self.store, self.dev)
            .map_err(SnapshotJournalError::Snapshot)?;
        self.phase = RolledBack;
        Ok(())
    }
}

#[cfg(test)]
#[path = "creation/tests.rs"]
mod tests;
