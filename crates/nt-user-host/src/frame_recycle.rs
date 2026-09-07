//! Checked publication of a retained, unmapped 4 KiB frame into the reusable frame pool.
use nt_address_space::{FramePoolError, RecycledFramePool, PAGE_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameRecycleError {
    InvalidSlot,
    UntrackedSlot,
    NotOwned,
    Pinned,
    WrongRetypeSize,
    AccountingUnderflow,
    CorruptSlotCount,
    EmptySlotPublished,
    Pool(FramePoolError),
}

/// Read-only allocator view, never an independent frame owner. Exact frame provenance, removal
/// of external aliases, and successful unmap/revoke come from the caller's retained cleanup phases.
/// In particular, 4096-byte accounting alone does not distinguish a frame from a page table.
/// No allocator mutation/reentrancy may occur between validation, publication and acknowledgement.
pub struct FrameRecycleState<'a> {
    pub start: u64,
    pub end: u64,
    pub live: &'a [u64],
    pub pinned: &'a [u64],
    pub retype_bytes: &'a [u32],
    pub free_slots: &'a [u64],
    pub free_slot_count: u64,
    pub live_bytes: u64,
}

impl FrameRecycleState<'_> {
    pub fn validate_owner(&self, frame: u64) -> Result<(), FrameRecycleError> {
        if frame <= 1 || frame < self.start || frame >= self.end {
            return Err(FrameRecycleError::InvalidSlot);
        }
        let index =
            usize::try_from(frame - self.start).map_err(|_| FrameRecycleError::UntrackedSlot)?;
        let word = index / 64;
        let bit = 1u64 << (index % 64);
        let live = *self
            .live
            .get(word)
            .ok_or(FrameRecycleError::UntrackedSlot)?;
        let pinned = *self
            .pinned
            .get(word)
            .ok_or(FrameRecycleError::UntrackedSlot)?;
        let bytes = *self
            .retype_bytes
            .get(index)
            .ok_or(FrameRecycleError::UntrackedSlot)?;
        if pinned & bit != 0 {
            return Err(FrameRecycleError::Pinned);
        }
        if live & bit == 0 {
            return Err(FrameRecycleError::NotOwned);
        }
        if u64::from(bytes) != PAGE_SIZE {
            return Err(FrameRecycleError::WrongRetypeSize);
        }
        if self.live_bytes < PAGE_SIZE {
            return Err(FrameRecycleError::AccountingUnderflow);
        }
        let count = usize::try_from(self.free_slot_count)
            .map_err(|_| FrameRecycleError::CorruptSlotCount)?;
        let published = self
            .free_slots
            .get(..count)
            .ok_or(FrameRecycleError::CorruptSlotCount)?;
        if published.contains(&frame) {
            return Err(FrameRecycleError::EmptySlotPublished);
        }
        Ok(())
    }

    pub fn check_reserved(
        &self,
        frame: u64,
        pool: &RecycledFramePool,
    ) -> Result<(), FrameRecycleError> {
        self.validate_owner(frame)?;
        pool.check_reserved(frame).map_err(FrameRecycleError::Pool)
    }

    /// Keep the live slot and all retype accounting: the physical frame still exists in the pool.
    /// Failure performs no deletion, allocation or fallback publication.
    pub fn publish_reserved(
        &self,
        frame: u64,
        pool: &mut RecycledFramePool,
    ) -> Result<(), FrameRecycleError> {
        self.validate_owner(frame)?;
        pool.publish_reserved(frame)
            .map_err(FrameRecycleError::Pool)
    }
}

#[cfg(test)]
#[path = "frame_recycle_tests.rs"]
mod tests;
