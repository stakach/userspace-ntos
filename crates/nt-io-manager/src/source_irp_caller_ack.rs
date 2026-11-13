//! Receipts for consumed caller-IRP terminal acknowledgements.
//!
//! A hosted provider disposes the root-side receipt of a projected caller IRP with one
//! acknowledgement. If the reply to that acknowledgement is lost the provider repeats it, and
//! the repeat must succeed only for the exact ticket that was consumed. This ledger records
//! what was consumed so that a repeat is authenticated and nothing else is.
//!
//! # How long a receipt is kept
//!
//! One receipt is kept per pending-IRP node of each owner: the last ticket consumed on it.
//!
//! The provider sends the acknowledgement, and its single repeat, from the release of the
//! pending-IRP node that carried the caller IRP. It tombstones the node only after that
//! release has returned, and reuses only tombstoned nodes. So once the node carries another
//! caller IRP, the repeat window of the earlier ticket is closed and its receipt can never be
//! consulted again. Until then the receipt stays, however many acknowledgements arrive on
//! other nodes from other provider threads or from callbacks nested in the first one.
//!
//! The table therefore holds at most one row per pending node an owner has ever linked. The
//! provider never unlinks a node and takes a new one only when none is free, so that is its
//! peak number of nodes in use (pending IRPs, plus any node a failed driver left
//! quarantined), not the number of IRPs it completes.
//!
//! This rests on the provider releasing before it tombstones. If it ever reused a node
//! first, a repeat would be refused, which fails closed; nothing would be wrongly accepted,
//! because every receipt here was also a receipt of the unbounded table this replaced.
//!
//! # Where allocation can be refused
//!
//! [`CallerTerminalAcks::reserve`] makes the row when the caller IRP is projected, where a
//! refusal fails that one request. [`CallerTerminalAcks::consume`] then finds the row and
//! allocates nothing, so the acknowledgement itself cannot run out of memory.

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
    /// The owner's pending-IRP node. Hosted components share one address layout, so the
    /// address identifies a node only together with its owner.
    node: u64,
    consumed: Option<SourceIrpTicket>,
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

    fn row(
        &mut self,
        owner: SourceIrpOwner,
        node: u64,
    ) -> Result<&mut Row, CallerTerminalAckError> {
        let index = match self
            .rows
            .iter()
            .position(|row| row.owner == owner && row.node == node)
        {
            Some(index) => index,
            None => {
                self.rows
                    .try_reserve(1)
                    .map_err(|_| CallerTerminalAckError::NoCapacity)?;
                self.rows.push(Row { owner, node, consumed: None });
                self.rows.len() - 1
            }
        };
        Ok(&mut self.rows[index])
    }

    /// `owner` is projecting a caller IRP on its pending node `node`. This makes room for the
    /// eventual receipt and forgets the ticket last consumed on the node: the provider reused
    /// the node, so it has finished releasing the IRP that ticket belonged to.
    pub fn reserve(
        &mut self,
        owner: SourceIrpOwner,
        node: u64,
    ) -> Result<(), CallerTerminalAckError> {
        self.row(owner, node)?.consumed = None;
        Ok(())
    }

    /// Record that `owner` acknowledged `ticket`, which was projected on its pending node
    /// `node`. Nothing is recorded when this fails; the caller must then keep the projection.
    /// It cannot fail for a node that was reserved.
    pub fn consume(
        &mut self,
        owner: SourceIrpOwner,
        node: u64,
        ticket: SourceIrpTicket,
    ) -> Result<(), CallerTerminalAckError> {
        self.row(owner, node)?.consumed = Some(ticket);
        Ok(())
    }

    /// Whether a repeated acknowledgement of `ticket` by `owner` names the ticket last
    /// consumed on one of its pending nodes.
    pub fn authenticates(&self, owner: SourceIrpOwner, ticket: SourceIrpTicket) -> bool {
        self.rows
            .iter()
            .any(|row| row.owner == owner && row.consumed == Some(ticket))
    }

    /// Forget every receipt of a retiring owner.
    pub fn drain_owner(&mut self, owner: SourceIrpOwner) {
        self.rows.retain(|row| row.owner != owner);
    }

    /// Rows held: one per pending node that has carried a caller IRP.
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
