//! Checked publication of an exclusively owned empty capability slot.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecycleError {
    InvalidSlot,
    UntrackedSlot,
    NotOwned,
    Pinned,
    CorruptCount,
    Full,
    AlreadyPublished,
    AccountingUnderflow,
    AccountingOverflow,
}

/// A serialized, allocation-free view of the allocator's existing storage, not a second owner.
/// Callers must exclude concurrent access/reentrancy through the whole operation and publication
/// of the resulting counters. Empty-slot provenance comes from checked construction/retirement
/// phases; the allocator live bit means allocated, not that a kernel object exists in the slot.
pub struct SlotRecycleState<'a> {
    pub start: u64,
    pub end: u64,
    pub live: &'a mut [u64],
    pub pinned: &'a [u64],
    pub retype_bytes: &'a mut [u32],
    pub free: &'a mut [u64],
    pub count: u64,
    pub live_bytes: u64,
    pub released_bytes: u64,
}

impl SlotRecycleState<'_> {
    /// All rejection precedes mutation. Success acknowledges allocator publication only, not
    /// deletion, revocation, physical-frame release or completion of the containing thread owner.
    pub fn publish_empty(&mut self, slot: u64) -> Result<(), RecycleError> {
        if slot <= 1 || slot < self.start || slot >= self.end {
            return Err(RecycleError::InvalidSlot);
        }
        let index = usize::try_from(slot - self.start).map_err(|_| RecycleError::UntrackedSlot)?;
        let word = index / 64;
        let bit = 1u64 << (index % 64);
        let live = *self.live.get(word).ok_or(RecycleError::UntrackedSlot)?;
        let pinned = *self.pinned.get(word).ok_or(RecycleError::UntrackedSlot)?;
        let bytes = *self
            .retype_bytes
            .get(index)
            .ok_or(RecycleError::UntrackedSlot)? as u64;
        if pinned & bit != 0 {
            return Err(RecycleError::Pinned);
        }
        if live & bit == 0 {
            return Err(RecycleError::NotOwned);
        }
        let count = usize::try_from(self.count).map_err(|_| RecycleError::CorruptCount)?;
        if count > self.free.len() {
            return Err(RecycleError::CorruptCount);
        }
        if count == self.free.len() {
            return Err(RecycleError::Full);
        }
        // Inactive cells may retain popped entries; only the published prefix owns free slots.
        if self.free[..count].contains(&slot) {
            return Err(RecycleError::AlreadyPublished);
        }
        let live_bytes = self
            .live_bytes
            .checked_sub(bytes)
            .ok_or(RecycleError::AccountingUnderflow)?;
        let released_bytes = self
            .released_bytes
            .checked_add(bytes)
            .ok_or(RecycleError::AccountingOverflow)?;

        self.free[count] = slot;
        self.live[word] = live & !bit;
        self.retype_bytes[index] = 0;
        self.live_bytes = live_bytes;
        self.released_bytes = released_bytes;
        self.count += 1;
        Ok(())
    }
}

#[cfg(test)]
#[path = "slot_recycle_tests.rs"]
mod tests;
