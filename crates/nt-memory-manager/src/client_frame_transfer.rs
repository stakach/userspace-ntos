//! Exact multirow handoff to an external, retained cleanup journal.
use super::{ClientFrameRecord, ClientFrameRegistry};
use alloc::vec::Vec;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_TRANSFER_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientFrameTransferError {
    EmptySelection,
    DuplicateRecord,
    StaleRecord,
    Reclaiming,
    InsufficientResources,
    IdentityExhausted,
}

/// The registry keeps terminal placeholder rows until this owner acknowledges final cleanup.
/// No capability operation is performed here. Before acquiring a transfer, the caller must retain
/// its physical-owner inventory, external alias journals and memory-access exclusions. Registry
/// `owns_frame` flags alone cannot establish physical ownership for hosted thread resources.
///
/// Dropping this non-cloneable owner does not release its rows or permit address reuse. Keep it
/// through every backend failure, and call `finish_transfer` only after checked cleanup completes.
#[must_use = "retain the transfer until its external cleanup journal has completed"]
#[derive(Debug)]
pub struct ClientFrameTransfer {
    id: NonZeroU64,
    records: Vec<ClientFrameRecord>,
}

impl ClientFrameTransfer {
    /// Exact retained records, unavailable through ordinary resident-access or mutation methods.
    /// These snapshots describe the captured caps; the external journal owns per-cap progress.
    pub fn records(&self) -> &[ClientFrameRecord] {
        &self.records
    }
}

impl ClientFrameRegistry {
    /// Preallocate and validate the entire selection before changing any row. Duplicate keys,
    /// stale snapshots and existing reclamation refuse the whole handoff without mutation.
    pub fn prepare_transfer_exact(
        &mut self,
        expected: &[ClientFrameRecord],
    ) -> Result<ClientFrameTransfer, ClientFrameTransferError> {
        self.prepare_transfer_with(expected, &NEXT_TRANSFER_ID, |count| {
            let mut records = Vec::new();
            records
                .try_reserve(count)
                .map_err(|_| ClientFrameTransferError::InsufficientResources)?;
            Ok(records)
        })
    }

    fn prepare_transfer_with(
        &mut self,
        expected: &[ClientFrameRecord],
        counter: &AtomicU64,
        allocate: impl FnOnce(usize) -> Result<Vec<ClientFrameRecord>, ClientFrameTransferError>,
    ) -> Result<ClientFrameTransfer, ClientFrameTransferError> {
        if expected.is_empty() {
            return Err(ClientFrameTransferError::EmptySelection);
        }
        for (index, record) in expected.iter().enumerate() {
            if expected[..index]
                .iter()
                .any(|prior| prior.pi == record.pi && prior.page == record.page)
            {
                return Err(ClientFrameTransferError::DuplicateRecord);
            }
            if self.get(record.pi, record.page) != Some(*record) {
                return Err(ClientFrameTransferError::StaleRecord);
            }
            if record.is_reclaiming() || record.transfer_id.is_some() {
                return Err(ClientFrameTransferError::Reclaiming);
            }
        }
        let mut records = allocate(expected.len())?;
        if !records.is_empty() || records.capacity() < expected.len() {
            return Err(ClientFrameTransferError::InsufficientResources);
        }
        let id = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| ClientFrameTransferError::IdentityExhausted)?;
        let id = NonZeroU64::new(id).ok_or(ClientFrameTransferError::IdentityExhausted)?;

        // No fallible allocation or lookup remains after the first ownership change.
        for &record in expected {
            let row = self.exact_mut(record).expect("prevalidated transfer row");
            row.transfer_id = Some(id);
            records.push(*row);
        }
        self.reclaiming += expected.len();
        Ok(ClientFrameTransfer { id, records })
    }

    /// After all external capability cleanup is acknowledged, retire the exact placeholders
    /// together. This does not delete caps or release commitment. Failure returns the unchanged
    /// owner and leaves every row intact; success allocates nothing and consumes the owner once.
    pub fn finish_transfer(
        &mut self,
        transfer: ClientFrameTransfer,
    ) -> Result<(), (ClientFrameTransferError, ClientFrameTransfer)> {
        if transfer.records.iter().any(|record| {
            record.transfer_id != Some(transfer.id)
                || self.get(record.pi, record.page) != Some(*record)
        }) {
            return Err((ClientFrameTransferError::StaleRecord, transfer));
        }
        for record in &transfer.records {
            let index = self
                .index_for(record.pi, record.page)
                .expect("prevalidated transfer row");
            self.records.swap_remove(index);
        }
        self.reclaiming -= transfer.records.len();
        Ok(())
    }
}

#[cfg(test)]
#[path = "client_frame_transfer_tests.rs"]
mod tests;
