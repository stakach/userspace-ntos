//! Before-COMMIT cancellation: durable tail removal, retained preparation release, then exact ACK.

use super::*;

impl<B: Backend, D: SnapshotBlockDevice, C, R> SnapshotSystemHivePublication<'_, B, D, C, R> {
    /// Latch cancellation before touching storage. Even a returned COMMIT error permanently
    /// forbids this path: the server may already have published the mutation.
    pub fn rollback_storage(&mut self) -> Result<(), SnapshotSystemHivePublicationError> {
        use SnapshotSystemHivePublicationPhase::*;
        if !matches!(self.phase, StoragePending | CommitReady | RollbackRetry) {
            return Err(SnapshotSystemHivePublicationError::InvalidPhase);
        }
        self.phase = RollbackInFlight;
        match self.storage.rollback() {
            Ok(()) => {
                self.phase = AbortReady;
                Ok(())
            }
            Err(error) => {
                self.phase = RollbackRetry;
                Err(SnapshotSystemHivePublicationError::Storage(error))
            }
        }
    }

    /// Release only the exact preparation after its tail has been durably removed. Reply loss
    /// keeps the caller and original identity; it cannot restart storage or publication.
    pub fn abort(&mut self) -> Result<(), SnapshotSystemHivePublicationError> {
        use SnapshotSystemHivePublicationPhase::*;
        if !matches!(self.phase, AbortReady | AbortRetry) {
            return Err(SnapshotSystemHivePublicationError::InvalidPhase);
        }
        self.phase = AbortInFlight;
        match self
            .client
            .abort_prepared_system_hive_mutation_retained(&self.prepared)
        {
            Ok(receipt) => {
                self.abort_receipt = Some(receipt);
                self.phase = AbortAcknowledgeReady;
                Ok(())
            }
            Err(status) => {
                self.phase = AbortRetry;
                Err(SnapshotSystemHivePublicationError::Protocol(status))
            }
        }
    }

    pub fn acknowledge_abort(&mut self) -> Result<(), SnapshotSystemHivePublicationError> {
        use SnapshotSystemHivePublicationPhase::*;
        if !matches!(self.phase, AbortAcknowledgeReady | AbortAcknowledgeRetry) {
            return Err(SnapshotSystemHivePublicationError::InvalidPhase);
        }
        let receipt = self.abort_receipt.expect("confirmed prepared abort");
        self.phase = AbortAcknowledgeInFlight;
        match self.client.acknowledge_system_hive_mutation_abort(receipt) {
            Ok(proof) => {
                debug_assert_eq!(proof.receipt(), receipt);
                self.phase = Cancelled;
                Ok(())
            }
            Err(status) => {
                self.phase = AbortAcknowledgeRetry;
                Err(SnapshotSystemHivePublicationError::Protocol(status))
            }
        }
    }

    /// Only durable rollback AND acknowledged remote cleanup permit cancellation completion.
    pub fn take_cancelled(&mut self) -> Option<C> {
        if self.phase != SnapshotSystemHivePublicationPhase::Cancelled {
            return None;
        }
        self.phase = SnapshotSystemHivePublicationPhase::Taken;
        Some(self.continuation.take().expect("retained cancelled caller"))
    }
}

#[cfg(test)]
mod tests;
