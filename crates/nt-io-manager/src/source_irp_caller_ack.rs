//! Receipts for consumed caller-IRP terminal acknowledgements.
//!
//! A hosted provider disposes the root-side receipt of a projected caller IRP with one
//! acknowledgement. If the reply to that acknowledgement is lost the provider repeats it, and
//! the repeat must succeed only for the exact ticket that was consumed. This ledger records
//! what was consumed so that a repeat is authenticated and nothing else is.

use alloc::vec::Vec;

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::source_irp_ledger::SourceIrpOwner;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerTerminalAckError {
    NoCapacity,
}

#[derive(Clone, Copy, Debug)]
struct Row {
    owner: SourceIrpOwner,
    consumed: SourceIrpTicket,
}

pub struct CallerTerminalAcks {
    rows: Vec<Row>,
}

impl Default for CallerTerminalAcks {
    fn default() -> Self {
        Self::new()
    }
}

impl CallerTerminalAcks {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Record that `owner` acknowledged `ticket`. Nothing is recorded when this fails; the
    /// caller must then keep the projection.
    pub fn consume(
        &mut self,
        owner: SourceIrpOwner,
        ticket: SourceIrpTicket,
    ) -> Result<(), CallerTerminalAckError> {
        self.rows
            .try_reserve(1)
            .map_err(|_| CallerTerminalAckError::NoCapacity)?;
        self.rows.push(Row { owner, consumed: ticket });
        Ok(())
    }

    /// Whether a repeated acknowledgement of `ticket` by `owner` names a consumed ticket.
    pub fn authenticates(&self, owner: SourceIrpOwner, ticket: SourceIrpTicket) -> bool {
        self.rows
            .iter()
            .any(|row| row.owner == owner && row.consumed == ticket)
    }

    /// Forget every receipt of a retiring owner.
    pub fn drain_owner(&mut self, owner: SourceIrpOwner) {
        self.rows.retain(|row| row.owner != owner);
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Heap bytes held by the table, for the periodic census.
    pub fn retained_bytes(&self) -> usize {
        self.rows.capacity() * core::mem::size_of::<Row>()
    }
}
