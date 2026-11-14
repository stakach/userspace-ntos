//! How much durable heap an allocation above the bump mark can still be given.
//!
//! The root heap commits pages on demand, so the mapped end trails the reservation. Headroom
//! measured to the mapped end reads as exhaustion a few megabytes after every commitment step;
//! headroom measured to the reservation end promises pages that Untyped memory may not have.

/// One durable heap's three ends, as addresses or as offsets from one base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableExtent {
    /// End of the highest live durable allocation.
    pub bump_end: usize,
    /// End of the pages mapped now.
    pub committed_end: usize,
    /// End of what the heap may ever commit. Equal to `committed_end` for a heap mapped whole.
    pub reservation_end: usize,
    /// Physical memory still available to back uncommitted pages. A reservation is address
    /// space; only this much of it can become storage.
    pub backing_free: usize,
}

impl DurableExtent {
    /// Mapped bytes above the bump mark.
    pub fn committed_free(&self) -> usize {
        self.committed_end.saturating_sub(self.bump_end)
    }

    /// Reserved bytes not mapped yet that physical memory can still back.
    pub fn growable(&self) -> usize {
        self.reservation_end.saturating_sub(self.committed_end).min(self.backing_free)
    }

    /// Bytes an allocation above the bump mark can obtain: mapped and free, plus growable.
    pub fn obtainable(&self) -> usize {
        self.committed_free().saturating_add(self.growable())
    }
}

/// The fewest committed frames that cover `requested_bytes` of heap, when that is more than
/// `current_frames` and no more than `reserved_frames`. Commitment normally advances in larger
/// steps; this is what is left to try when a whole step cannot be backed.
pub fn commit_floor(current_frames: u64, requested_bytes: usize, reserved_frames: u64) -> Option<u64> {
    let requested_frames = (requested_bytes as u64).div_ceil(0x1000);
    (requested_frames > current_frames && requested_frames <= reserved_frames)
        .then_some(requested_frames)
}
