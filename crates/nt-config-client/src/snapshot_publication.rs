//! Concrete post-PREPARE storage/CM publication ownership. No receipt or mutable preparation is
//! exposed while work is pending. First-journal creation has explicit retained admission; native
//! storage authority and reserve serialization still precede executive publication.

use crate::{
    Backend, ConfigClient, PreparedSystemHiveMutation, SystemHiveMutationAbortReceipt,
    SystemHiveMutationCommitReceipt, SystemHivePublishOutcome,
};
use nt_fs::{
    FileSystem, SnapshotBlockDevice, SnapshotBlockStore, SnapshotJournal, SnapshotJournalError,
};

mod cancellation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotSystemHivePublicationPhase {
    StoragePending,
    StorageInFlight,
    CommitReady,
    CommitInFlight,
    CommitRetry,
    LocalReady,
    LocalInFlight,
    AcknowledgeReady,
    AcknowledgeInFlight,
    AcknowledgeRetry,
    RollbackInFlight,
    RollbackRetry,
    AbortReady,
    AbortInFlight,
    AbortRetry,
    AbortAcknowledgeReady,
    AbortAcknowledgeInFlight,
    AbortAcknowledgeRetry,
    Cancelled,
    Complete,
    Taken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotSystemHivePublicationError {
    Storage(SnapshotJournalError),
    Protocol(i32),
    InvalidPhase,
}

#[derive(Debug)]
pub struct SnapshotSystemHivePublicationOpenError<C> {
    pub status: u32,
    pub prepared: PreparedSystemHiveMutation,
    pub continuation: C,
}

/// Owns exact journal bytes, preparation, caller continuation and local result until confirmed ACK.
/// The exclusive client borrow also prevents redirecting retries to a different transport.
/// All returned errors retain the owner. An unwind leaves the current operation InFlight, never
/// implicitly retryable: caller-specific reconciliation is required before that work can complete.
///
/// C must contain ALL caller preparations needed after CM commits. The type cannot establish that
/// a native adapter supplied every handle/PnP reservation. Dropping this owner is not cancellation.
///
/// ```compile_fail
/// use nt_config_client::{Backend, ConfigClient, PreparedSystemHiveMutation, SnapshotSystemHivePublication};
/// use nt_fs::{FileSystem, SnapshotBlockDevice, SnapshotBlockStore};
/// fn bypass<B: Backend, D: SnapshotBlockDevice>(client: &mut ConfigClient<B>, fs: &mut FileSystem,
///     dev: &mut D, prepared: PreparedSystemHiveMutation) {
///     let mut work = SnapshotSystemHivePublication::<B, D, (), ()>::open(client, fs, dev,
///         SnapshotBlockStore::new(0, 64), r"\??\C:\Config\SYSTEM.LOG", prepared, ()).unwrap();
///     let _ = client.import_system_hive(&[]);
///     work.make_durable().unwrap();
/// }
/// ```
#[must_use = "retain pending publication across storage, protocol or local-publication failures"]
pub struct SnapshotSystemHivePublication<'a, B: Backend, D: SnapshotBlockDevice, C, R> {
    client: &'a mut ConfigClient<B>,
    storage: SnapshotJournal<'a, D, ()>,
    prepared: PreparedSystemHiveMutation,
    continuation: Option<C>,
    publication: Option<R>,
    receipt: Option<SystemHiveMutationCommitReceipt>,
    abort_receipt: Option<SystemHiveMutationAbortReceipt>,
    phase: SnapshotSystemHivePublicationPhase,
}

impl<'a, B: Backend, D: SnapshotBlockDevice, C, R> SnapshotSystemHivePublication<'a, B, D, C, R> {
    /// Move the exact prepared bytes into storage without a second journal allocation. Failed
    /// admission restores the preparation and returns all caller state without a CM operation.
    /// Admission must select this CM SYSTEM hive's actual backing log; storage borrows alone cannot
    /// prove that mapping. The log must already exist. Volatile-only preparations are not handled.
    pub fn open(
        client: &'a mut ConfigClient<B>,
        fs: &'a mut FileSystem,
        dev: &'a mut D,
        store: SnapshotBlockStore,
        log_path: &str,
        prepared: PreparedSystemHiveMutation,
        continuation: C,
    ) -> Result<Self, SnapshotSystemHivePublicationOpenError<C>> {
        Self::admit(
            client,
            fs,
            dev,
            store,
            log_path,
            prepared,
            continuation,
            false,
        )
    }

    /// Reserve explicit creation of a genuinely absent backing log before filesystem effects.
    /// No collision/error falls back to open. The same retained owner creates, appends and makes
    /// the first journal durable; pre-COMMIT cancellation restores durable absence before CM ABORT.
    /// Native admission must still bind this exact path, mount and store to the CM authority.
    pub fn create(
        client: &'a mut ConfigClient<B>,
        fs: &'a mut FileSystem,
        dev: &'a mut D,
        store: SnapshotBlockStore,
        log_path: &str,
        prepared: PreparedSystemHiveMutation,
        continuation: C,
    ) -> Result<Self, SnapshotSystemHivePublicationOpenError<C>> {
        Self::admit(
            client,
            fs,
            dev,
            store,
            log_path,
            prepared,
            continuation,
            true,
        )
    }

    fn admit(
        client: &'a mut ConfigClient<B>,
        fs: &'a mut FileSystem,
        dev: &'a mut D,
        store: SnapshotBlockStore,
        log_path: &str,
        mut prepared: PreparedSystemHiveMutation,
        continuation: C,
        create: bool,
    ) -> Result<Self, SnapshotSystemHivePublicationOpenError<C>> {
        let journal = core::mem::take(&mut prepared.durable_journal);
        let admitted = if create {
            SnapshotJournal::create(fs, dev, store, log_path, journal, ())
        } else {
            SnapshotJournal::open(fs, dev, store, log_path, journal, ())
        };
        let storage = match admitted {
            Ok(storage) => storage,
            Err(error) => {
                prepared.durable_journal = error.journal;
                return Err(SnapshotSystemHivePublicationOpenError {
                    status: error.status,
                    prepared,
                    continuation,
                });
            }
        };
        Ok(Self {
            client,
            storage,
            prepared,
            continuation: Some(continuation),
            publication: None,
            receipt: None,
            abort_receipt: None,
            phase: SnapshotSystemHivePublicationPhase::StoragePending,
        })
    }

    pub fn phase(&self) -> SnapshotSystemHivePublicationPhase {
        self.phase
    }
    pub fn continuation(&self) -> Option<&C> {
        self.continuation.as_ref()
    }

    pub fn make_durable(&mut self) -> Result<(), SnapshotSystemHivePublicationError> {
        use SnapshotSystemHivePublicationPhase::*;
        if self.phase == CommitReady {
            return Ok(());
        }
        if self.phase != StoragePending {
            return Err(SnapshotSystemHivePublicationError::InvalidPhase);
        }
        self.phase = StorageInFlight;
        match self.storage.make_durable() {
            Ok(()) => {
                self.phase = CommitReady;
                Ok(())
            }
            Err(error) => {
                self.phase = StoragePending;
                Err(SnapshotSystemHivePublicationError::Storage(error))
            }
        }
    }

    /// Each returned protocol error allows only exact COMMIT replay, never storage rollback/ABORT.
    pub fn commit(&mut self) -> Result<(), SnapshotSystemHivePublicationError> {
        use SnapshotSystemHivePublicationPhase::*;
        if !matches!(self.phase, CommitReady | CommitRetry) {
            return Err(SnapshotSystemHivePublicationError::InvalidPhase);
        }
        self.storage
            .begin_publication()
            .map_err(SnapshotSystemHivePublicationError::Storage)?;
        self.phase = CommitInFlight;
        match self
            .client
            .commit_system_hive_mutation_retained(&self.prepared)
        {
            Ok(receipt) => {
                self.receipt = Some(receipt);
                self.phase = LocalReady;
                Ok(())
            }
            Err(status) => {
                self.phase = CommitRetry;
                Err(SnapshotSystemHivePublicationError::Protocol(status))
            }
        }
    }

    /// Complete an infallible, purely local publication exactly once and retain its result for ACK.
    /// Set LocalInFlight BEFORE caller code. Unwinding cannot rerun the callback or authorize ACK.
    /// Multi-step/fallible native publication and post-COMMIT CM lease acquisition need a retained
    /// staged adapter; a Result returned as R is just data, not an instruction to retry publication.
    pub fn publish_local<F>(&mut self, publish: F) -> Result<(), SnapshotSystemHivePublicationError>
    where
        F: FnOnce(&mut C, SystemHivePublishOutcome) -> R,
    {
        use SnapshotSystemHivePublicationPhase::*;
        if self.phase != LocalReady {
            return Err(SnapshotSystemHivePublicationError::InvalidPhase);
        }
        let outcome = self.receipt.expect("confirmed commit").outcome();
        self.phase = LocalInFlight;
        let result = publish(
            self.continuation.as_mut().expect("retained caller"),
            outcome,
        );
        self.publication = Some(result);
        self.phase = AcknowledgeReady;
        Ok(())
    }

    pub fn acknowledge(&mut self) -> Result<(), SnapshotSystemHivePublicationError> {
        use SnapshotSystemHivePublicationPhase::*;
        if !matches!(self.phase, AcknowledgeReady | AcknowledgeRetry) {
            return Err(SnapshotSystemHivePublicationError::InvalidPhase);
        }
        let receipt = self.receipt.expect("confirmed commit");
        self.phase = AcknowledgeInFlight;
        match self.client.acknowledge_system_hive_mutation_commit(receipt) {
            Ok(proof) => {
                debug_assert_eq!(proof.receipt(), receipt);
                self.phase = Complete;
                Ok(())
            }
            Err(status) => {
                self.phase = AcknowledgeRetry;
                Err(SnapshotSystemHivePublicationError::Protocol(status))
            }
        }
    }

    /// Take published completion once, after exact ACK. Cancellation has a separate take_cancelled
    /// result and cannot be mistaken for publication. Drop the owner to release storage/client borrows.
    pub fn take_completion(&mut self) -> Option<(C, R)> {
        if self.phase != SnapshotSystemHivePublicationPhase::Complete {
            return None;
        }
        self.phase = SnapshotSystemHivePublicationPhase::Taken;
        Some((
            self.continuation.take().expect("retained caller"),
            self.publication
                .take()
                .expect("completed local publication"),
        ))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_support;
