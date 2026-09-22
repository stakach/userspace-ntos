//! Storage ownership forms share the journal's single extent and durability state machine.

use super::*;
use core::ops::{Deref, DerefMut};

pub(super) enum StorageOwner<'a, T> {
    Borrowed(&'a mut T),
    Owned(T),
    Released,
}

impl<T> StorageOwner<'_, T> {
    pub(super) fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }
    fn take_owned(&mut self) -> T {
        match core::mem::replace(self, Self::Released) {
            Self::Owned(value) => value,
            _ => unreachable!("owned journal storage"),
        }
    }
}

impl<T> Deref for StorageOwner<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
            Self::Released => panic!("released journal storage"),
        }
    }
}
impl<T> DerefMut for StorageOwner<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        match self {
            Self::Borrowed(value) => value,
            Self::Owned(value) => value,
            Self::Released => panic!("released journal storage"),
        }
    }
}

pub(super) struct StorageAdmissionError<'a, D, C> {
    pub status: u32,
    pub fs: StorageOwner<'a, FileSystem>,
    pub dev: StorageOwner<'a, D>,
    pub journal: Vec<u8>,
    pub context: C,
}

/// Admission has performed no journal write; every input remains available to the caller.
pub struct OwnedSnapshotJournalOpenError<D, C> {
    pub status: u32,
    pub filesystem: FileSystem,
    pub device: D,
    pub journal: Vec<u8>,
    pub context: C,
}

/// Owns the actual filesystem and backing device, not reconstructed handles or borrowed globals.
/// All operations use the same implementation as SnapshotJournal. Failed operations retain this
/// owner. An unresolved Drop deliberately leaks storage and context rather than unlock a reserve
/// or make an uncertain journal available to another writer. Native owners must retain and drive
/// this value to an explicit terminal release; this type does not prove CM completion.
#[must_use = "retain owned journal until confirmed rollback or protocol-authorized publication"]
pub struct OwnedSnapshotJournal<D: SnapshotBlockDevice + 'static, C> {
    inner: SnapshotJournal<'static, D, C>,
    release_entered: bool,
}

impl<D: SnapshotBlockDevice + 'static, C> OwnedSnapshotJournal<D, C> {
    pub fn open(
        filesystem: FileSystem,
        device: D,
        store: SnapshotBlockStore,
        path: &str,
        journal: Vec<u8>,
        context: C,
    ) -> Result<Self, OwnedSnapshotJournalOpenError<D, C>> {
        Self::admitted(SnapshotJournal::open_storage(
            StorageOwner::Owned(filesystem),
            StorageOwner::Owned(device),
            store,
            path,
            journal,
            context,
        ))
    }

    pub fn create(
        filesystem: FileSystem,
        device: D,
        store: SnapshotBlockStore,
        path: &str,
        journal: Vec<u8>,
        context: C,
    ) -> Result<Self, OwnedSnapshotJournalOpenError<D, C>> {
        Self::admitted(SnapshotJournal::create_storage(
            StorageOwner::Owned(filesystem),
            StorageOwner::Owned(device),
            store,
            path,
            journal,
            context,
        ))
    }

    fn admitted(
        result: Result<SnapshotJournal<'static, D, C>, StorageAdmissionError<'static, D, C>>,
    ) -> Result<Self, OwnedSnapshotJournalOpenError<D, C>> {
        match result {
            Ok(inner) => Ok(Self {
                inner,
                release_entered: false,
            }),
            Err(mut error) => Err(OwnedSnapshotJournalOpenError {
                status: error.status,
                filesystem: error.fs.take_owned(),
                device: error.dev.take_owned(),
                journal: error.journal,
                context: error.context,
            }),
        }
    }

    pub fn phase(&self) -> SnapshotJournalPhase {
        self.inner.phase()
    }
    pub fn context(&self) -> &C {
        self.inner.context()
    }
    pub fn durability(&self) -> Option<&SnapshotJournalDurability> {
        self.inner.durability()
    }
    pub fn make_durable(&mut self) -> Result<(), SnapshotJournalError> {
        self.inner.make_durable()
    }
    pub fn begin_publication(&mut self) -> Result<&mut C, SnapshotJournalError> {
        self.inner.begin_publication()
    }
    pub fn rollback(&mut self) -> Result<(), SnapshotJournalError> {
        self.inner.rollback()
    }

    pub fn release_rolled_back(self) -> Result<(FileSystem, D, C), Self> {
        self.release(SnapshotJournalPhase::RolledBack)
    }

    /// The protocol owner must first reconcile COMMIT, local publication, and exact ACK.
    /// Storage phase alone is not proof of those effects, just as with the borrowed wrapper.
    pub fn release_after_publication(self) -> Result<(FileSystem, D, C), Self> {
        self.release(SnapshotJournalPhase::PublicationStarted)
    }

    fn release(mut self, required: SnapshotJournalPhase) -> Result<(FileSystem, D, C), Self> {
        if self.release_entered || self.inner.phase != required {
            return Err(self);
        }
        self.release_entered = true;
        if self.inner.handle != INVALID_HANDLE {
            // A failed close retains all authority and cannot be blindly replayed.
            if self.inner.fs.zw_close(self.inner.handle) != STATUS_SUCCESS {
                return Err(self);
            }
            self.inner.handle = INVALID_HANDLE;
        }
        let fs = self.inner.fs.take_owned();
        let dev = self.inner.dev.take_owned();
        let context = self.inner.context.take().expect("retained caller");
        Ok((fs, dev, context))
    }
}

#[cfg(test)]
mod tests;
