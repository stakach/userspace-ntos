//! Slot and generation policy for an index-addressed object table.
//!
//! The executive's compact object namespace hands out table indices as object identities.
//! This ledger decides which index an allocation receives and when a retired index may be
//! handed out again:
//!
//! - every occupant gets a generation that is never issued twice, so a reference recorded as
//!   index plus generation cannot resolve to a later occupant of the same index;
//! - an index returns to the free queue only through [`SlotLedger::release`], which refuses
//!   while the caller still counts references to the occupant. A refused slot stays occupied;
//! - free indices are reused oldest first, and the table is extended only when none is
//!   reusable. With a reuse delay of `n`, the `n` most recently released indices are held
//!   back, so an index stays vacant for at least `n` further releases. The delay bounds how
//!   soon an index can name a new occupant; it is a margin for references that carry no
//!   generation, not a substitute for the release check.
//!
//! The free queue is threaded through the slot records, so releasing never allocates.

use alloc::vec::Vec;

/// One occupant of one table slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SlotRef {
    index: usize,
    generation: u64,
}

impl SlotRef {
    pub const fn index(self) -> usize {
        self.index
    }

    /// Unique across the whole ledger and never zero.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotError {
    OutOfMemory,
    GenerationExhausted,
    /// The reference does not name the slot's current occupant.
    Stale,
    /// The occupant is still referenced, so its index cannot be handed out again.
    Referenced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotCensus {
    /// Table length: every index ever handed out.
    pub slots: usize,
    /// Slots waiting to be reused.
    pub free: usize,
}

#[derive(Clone, Copy)]
enum Slot {
    Occupied { generation: u64 },
    /// Queued for reuse; `next` is the slot released after this one.
    Free { next: Option<usize> },
}

#[derive(Default)]
pub struct SlotLedger {
    slots: Vec<Slot>,
    /// Oldest released slot: the next one reused.
    free_head: Option<usize>,
    /// Most recently released slot.
    free_tail: Option<usize>,
    free: usize,
    reuse_delay: usize,
    issued: u64,
}

impl SlotLedger {
    pub const fn new() -> Self {
        Self::with_reuse_delay(0)
    }

    /// A ledger that keeps the `reuse_delay` most recently released indices vacant.
    pub const fn with_reuse_delay(reuse_delay: usize) -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            free_tail: None,
            free: 0,
            reuse_delay,
            issued: 0,
        }
    }

    /// Free slots old enough to be handed out again.
    fn reusable(&self) -> usize {
        self.free.saturating_sub(self.reuse_delay)
    }

    /// How many of the next `allocations` would extend the table.
    pub fn appends_needed(&self, allocations: usize) -> usize {
        allocations.saturating_sub(self.reusable())
    }

    /// Make the next `allocations` infallible with respect to ledger memory.
    pub fn reserve(&mut self, allocations: usize) -> Result<(), SlotError> {
        self.slots
            .try_reserve(self.appends_needed(allocations))
            .map_err(|_| SlotError::OutOfMemory)
    }

    pub fn allocate(&mut self) -> Result<SlotRef, SlotError> {
        let generation = self
            .issued
            .checked_add(1)
            .ok_or(SlotError::GenerationExhausted)?;
        let index = match self.free_head.filter(|_| self.reusable() != 0) {
            Some(index) => {
                let Slot::Free { next } = self.slots[index] else {
                    unreachable!("the free queue names an occupied slot");
                };
                self.free_head = next;
                if next.is_none() {
                    self.free_tail = None;
                }
                self.free -= 1;
                self.slots[index] = Slot::Occupied { generation };
                index
            }
            None => {
                self.reserve(1)?;
                self.slots.push(Slot::Occupied { generation });
                self.slots.len() - 1
            }
        };
        self.issued = generation;
        Ok(SlotRef { index, generation })
    }

    /// Retire `slot`'s occupant and queue its index for reuse. `outstanding_references` is the
    /// number of handles, waiters and provider references that still name the occupant; while
    /// it is not zero the release is refused and the slot stays occupied.
    pub fn release(
        &mut self,
        slot: SlotRef,
        outstanding_references: usize,
    ) -> Result<(), SlotError> {
        if !self.is_current(slot) {
            return Err(SlotError::Stale);
        }
        if outstanding_references != 0 {
            return Err(SlotError::Referenced);
        }
        self.slots[slot.index] = Slot::Free { next: None };
        match self.free_tail {
            Some(tail) => self.slots[tail] = Slot::Free { next: Some(slot.index) },
            None => self.free_head = Some(slot.index),
        }
        self.free_tail = Some(slot.index);
        self.free += 1;
        Ok(())
    }

    /// The occupant of `index`, if the slot exists and is occupied.
    pub fn current(&self, index: usize) -> Option<SlotRef> {
        match self.slots.get(index) {
            Some(Slot::Occupied { generation }) => Some(SlotRef {
                index,
                generation: *generation,
            }),
            Some(Slot::Free { .. }) | None => None,
        }
    }

    pub fn is_current(&self, slot: SlotRef) -> bool {
        self.current(slot.index) == Some(slot)
    }

    pub fn census(&self) -> SlotCensus {
        SlotCensus {
            slots: self.slots.len(),
            free: self.free,
        }
    }
}
