//! How much durable heap an allocation above the bump mark can still be given.
//!
//! The root heap commits pages on demand, so the mapped end trails the reservation. Headroom
//! measured to the mapped end reads as exhaustion a few megabytes after every commitment step.

/// One durable heap's three ends, as addresses or as offsets from one base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableExtent {
    /// End of the highest live durable allocation.
    pub bump_end: usize,
    /// End of the pages mapped now.
    pub committed_end: usize,
    /// End of what the heap may ever commit. Equal to `committed_end` for a heap mapped whole.
    pub reservation_end: usize,
}

impl DurableExtent {
    /// Mapped bytes above the bump mark.
    pub fn committed_free(&self) -> usize {
        self.committed_end.saturating_sub(self.bump_end)
    }

    /// Reserved bytes not mapped yet.
    pub fn growable(&self) -> usize {
        self.reservation_end.saturating_sub(self.committed_end)
    }

    /// Bytes an allocation above the bump mark can obtain: mapped and free, plus growable.
    pub fn obtainable(&self) -> usize {
        self.committed_free().saturating_add(self.growable())
    }
}
