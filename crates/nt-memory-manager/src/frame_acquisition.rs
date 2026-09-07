//! Retained ownership while acquiring one zeroed frame. No operation allocates metadata.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFrameAcquisition {
    EmptySlot(u64),
    CachedFrame { frame: u64, owner_unmapped: bool },
}

impl PendingFrameAcquisition {
    pub const fn root_cap(self) -> u64 {
        match self {
            Self::EmptySlot(slot) | Self::CachedFrame { frame: slot, .. } => slot,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAcquisitionError {
    InvalidCapability,
    Backend(u32),
}

pub trait FrameAcquisitionIo {
    /// Transfer the cache's exclusive frame ownership. None means no frame was acquired.
    fn acquire_cached(&mut self) -> Option<u64>;
    /// Success transfers a uniquely reserved empty root slot. Failure acquires nothing.
    fn reserve_slot(&mut self) -> Result<u64, u32>;
    /// Success creates a zeroed frame. Failure must leave the retained destination slot empty.
    fn retype_frame(&mut self, slot: u64) -> Result<(), u32>;
    /// Publish an exclusively owned empty slot through the checked root-slot allocator.
    fn recycle_empty(&mut self, slot: u64) -> Result<(), u32>;
    /// Validate the acquired canonical owner and remove its previous mapping before creating a
    /// zeroing alias. Failure retains the frame and leaves this phase unacknowledged.
    fn unmap_cached(&mut self, frame: u64) -> Result<(), u32>;
    /// Success acknowledges both zeroing and complete temporary-alias cleanup. On failure the
    /// canonical frame remains owned by this acquisition; backend scratch ownership must persist.
    fn zero_cached(&mut self, frame: u64) -> Result<(), u32>;
}

/// Nonclone release authority for an unfinished acquisition. The containing runtime must retain
/// this owner after failure and exclude backend reentry. A successful acquire transfers the sole
/// frame owner to its caller; no destructor, implicit deletion or alternate acquisition bypasses
/// pending cleanup. Snapshot values describe ownership but do not grant its mutation authority.
#[derive(Debug, Default)]
pub struct FrameAcquisition {
    pending: Option<PendingFrameAcquisition>,
}

impl FrameAcquisition {
    pub const fn new() -> Self {
        Self { pending: None }
    }

    pub const fn pending(&self) -> Option<PendingFrameAcquisition> {
        self.pending
    }

    pub fn owns_root_cap(&self, cap: u64) -> bool {
        cap != 0
            && self
                .pending
                .is_some_and(|pending| pending.root_cap() == cap)
    }

    pub fn acquire(
        &mut self,
        io: &mut impl FrameAcquisitionIo,
    ) -> Result<u64, FrameAcquisitionError> {
        // A failed retype owns an empty slot, not a preference for another fresh frame. Complete
        // its publication first, then reconsider the current cache rather than starving new entries.
        if let Some(PendingFrameAcquisition::EmptySlot(slot)) = self.pending {
            io.recycle_empty(slot)
                .map_err(FrameAcquisitionError::Backend)?;
            self.pending = None;
        }
        if self.pending.is_none() {
            if let Some(frame) = io.acquire_cached() {
                if frame == 0 {
                    return Err(FrameAcquisitionError::InvalidCapability);
                }
                self.pending = Some(PendingFrameAcquisition::CachedFrame {
                    frame,
                    owner_unmapped: false,
                });
            }
        }
        if let Some(PendingFrameAcquisition::CachedFrame {
            frame,
            owner_unmapped,
        }) = self.pending
        {
            if !owner_unmapped {
                io.unmap_cached(frame)
                    .map_err(FrameAcquisitionError::Backend)?;
                self.pending = Some(PendingFrameAcquisition::CachedFrame {
                    frame,
                    owner_unmapped: true,
                });
            }
            io.zero_cached(frame)
                .map_err(FrameAcquisitionError::Backend)?;
            self.pending = None;
            return Ok(frame);
        }

        let slot = io.reserve_slot().map_err(FrameAcquisitionError::Backend)?;
        if slot == 0 {
            return Err(FrameAcquisitionError::InvalidCapability);
        }
        self.pending = Some(PendingFrameAcquisition::EmptySlot(slot));
        io.retype_frame(slot)
            .map_err(FrameAcquisitionError::Backend)?;
        self.pending = None;
        Ok(slot)
    }
}

#[cfg(test)]
#[path = "frame_acquisition_tests.rs"]
mod tests;
