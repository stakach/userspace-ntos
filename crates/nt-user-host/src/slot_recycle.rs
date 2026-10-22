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
    CorruptMembership,
    AccountingUnderflow,
    AccountingOverflow,
    UnexpectedRetypeAccounting,
}

/// A serialized, allocation-free view of the allocator's existing storage, not a second owner.
/// Callers must exclude concurrent access/reentrancy through the whole operation and publication
/// of the resulting counters. Empty-slot provenance comes from checked construction/retirement
/// phases; the allocator live bit means allocated, not that a kernel object exists in the slot.
/// `free_membership` indexes only the active `free[..count]` prefix and must be updated by every
/// acquisition, publication, and exceptional occupied-slot removal.
pub struct SlotRecycleState<'a> {
    pub start: u64,
    pub end: u64,
    pub live: &'a mut [u64],
    pub pinned: &'a [u64],
    pub retype_bytes: &'a mut [u32],
    pub free: &'a mut [u64],
    pub free_membership: &'a mut [u64],
    pub count: u64,
    pub live_bytes: u64,
    pub released_bytes: u64,
}

impl SlotRecycleState<'_> {
    /// All rejection precedes mutation. Success acknowledges allocator publication only, not
    /// deletion, revocation, physical-frame release or completion of the containing thread owner.
    pub fn publish_empty(&mut self, slot: u64) -> Result<(), RecycleError> {
        self.publish(slot, false)
    }

    /// Failed retype/copy destinations and copied alias slots own no retype accounting. Reject
    /// contradictory accounting rather than releasing bytes belonging to an unexpected object.
    pub fn publish_unretyped(&mut self, slot: u64) -> Result<(), RecycleError> {
        self.publish(slot, true)
    }

    fn publish(&mut self, slot: u64, unretyped: bool) -> Result<(), RecycleError> {
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
        if unretyped && bytes != 0 {
            return Err(RecycleError::UnexpectedRetypeAccounting);
        }
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
        let mut recycled = RecycledSlotStack {
            start: self.start,
            end: self.end,
            free: &mut *self.free,
            membership: &mut *self.free_membership,
            count: self.count,
        };
        recycled.check_push(slot).map_err(RecycleError::from)?;
        let live_bytes = self
            .live_bytes
            .checked_sub(bytes)
            .ok_or(RecycleError::AccountingUnderflow)?;
        let released_bytes = self
            .released_bytes
            .checked_add(bytes)
            .ok_or(RecycleError::AccountingOverflow)?;

        // All fallible checks precede both ownership changes and stack publication.
        recycled.push_checked(slot);
        self.live[word] = live & !bit;
        self.retype_bytes[index] = 0;
        self.live_bytes = live_bytes;
        self.released_bytes = released_bytes;
        self.count = recycled.count;
        Ok(())
    }
}

/// The active prefix of a recycled root-slot stack and its exact membership index. Inactive
/// cells are deliberately ignored: popping a slot need not erase its old stack cell. The caller
/// serializes every operation with all other root-slot allocator operations.
pub struct RecycledSlotStack<'a> {
    pub start: u64,
    pub end: u64,
    pub free: &'a mut [u64],
    pub membership: &'a mut [u64],
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecycledSlotError {
    InvalidSlot,
    UntrackedSlot,
    CorruptCount,
    Full,
    AlreadyPublished,
    CorruptMembership,
}

impl From<RecycledSlotError> for RecycleError {
    fn from(error: RecycledSlotError) -> Self {
        match error {
            RecycledSlotError::InvalidSlot => Self::InvalidSlot,
            RecycledSlotError::UntrackedSlot => Self::UntrackedSlot,
            RecycledSlotError::CorruptCount => Self::CorruptCount,
            RecycledSlotError::Full => Self::Full,
            RecycledSlotError::AlreadyPublished => Self::AlreadyPublished,
            RecycledSlotError::CorruptMembership => Self::CorruptMembership,
        }
    }
}

pub(crate) fn recycled_slot_bit(
    start: u64,
    end: u64,
    membership: &[u64],
    slot: u64,
) -> Result<(usize, u64), RecycledSlotError> {
    if slot <= 1 || slot < start || slot >= end {
        return Err(RecycledSlotError::InvalidSlot);
    }
    let index = usize::try_from(slot - start).map_err(|_| RecycledSlotError::UntrackedSlot)?;
    let word = index / 64;
    if word >= membership.len() {
        return Err(RecycledSlotError::UntrackedSlot);
    }
    Ok((word, 1u64 << (index % 64)))
}

impl RecycledSlotStack<'_> {
    fn checked_count(&self) -> Result<usize, RecycledSlotError> {
        let count = usize::try_from(self.count).map_err(|_| RecycledSlotError::CorruptCount)?;
        if count > self.free.len() {
            return Err(RecycledSlotError::CorruptCount);
        }
        Ok(count)
    }

    pub fn contains(&self, slot: u64) -> Result<bool, RecycledSlotError> {
        self.checked_count()?;
        let (word, bit) = recycled_slot_bit(self.start, self.end, self.membership, slot)?;
        Ok(self.membership[word] & bit != 0)
    }

    pub fn check_push(&self, slot: u64) -> Result<(), RecycledSlotError> {
        let count = self.checked_count()?;
        if count == self.free.len() {
            return Err(RecycledSlotError::Full);
        }
        if self.contains(slot)? {
            return Err(RecycledSlotError::AlreadyPublished);
        }
        Ok(())
    }

    /// Caller has already checked capacity, membership, and all surrounding accounting.
    fn push_checked(&mut self, slot: u64) {
        let (word, bit) = recycled_slot_bit(self.start, self.end, self.membership, slot)
            .expect("checked recycled slot must remain tracked");
        self.free[self.count as usize] = slot;
        self.membership[word] |= bit;
        self.count += 1;
    }

    pub fn push(&mut self, slot: u64) -> Result<(), RecycledSlotError> {
        self.check_push(slot)?;
        self.push_checked(slot);
        Ok(())
    }

    /// Removes the last active slot. A missing membership bit means the stack and index disagree;
    /// no counter or owner changes occur in that case.
    pub fn pop(&mut self) -> Result<Option<u64>, RecycledSlotError> {
        let count = self.checked_count()?;
        if count == 0 {
            return Ok(None);
        }
        let slot = self.free[count - 1];
        let (word, bit) = recycled_slot_bit(self.start, self.end, self.membership, slot)?;
        if self.membership[word] & bit == 0 {
            return Err(RecycledSlotError::CorruptMembership);
        }
        self.membership[word] &= !bit;
        self.count -= 1;
        Ok(Some(slot))
    }

    /// A successful kernel operation may occupy a slot from the active free prefix without
    /// acquiring it through `pop`. Search the cold path so a false-negative index cannot leave a
    /// duplicate stack owner behind; reject disagreements without changing either representation.
    pub fn remove(&mut self, slot: u64) -> Result<bool, RecycledSlotError> {
        let count = self.checked_count()?;
        let (word, bit) = recycled_slot_bit(self.start, self.end, self.membership, slot)?;
        let mut found = None;
        for i in 0..count {
            if self.free[i] == slot {
                if found.is_some() {
                    return Err(RecycledSlotError::CorruptMembership);
                }
                found = Some(i);
            }
        }
        let indexed = self.membership[word] & bit != 0;
        if indexed != found.is_some() {
            return Err(RecycledSlotError::CorruptMembership);
        }
        let Some(i) = found else {
            return Ok(false);
        };
        let last = count - 1;
        if i != last {
            self.free[i] = self.free[last];
        }
        self.free[last] = 0;
        self.membership[word] &= !bit;
        self.count -= 1;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "slot_recycle_tests.rs"]
mod tests;
