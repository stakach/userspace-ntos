//! In-place client alias construction, rights changes and backing replacement.
use crate::retained_alias::AliasRetirementIo;

const INVALID: u32 = crate::STATUS_INVALID_HANDLE;
const RESOURCES: u32 = 0xc000_009a;

pub trait AliasTransitionIo: AliasRetirementIo {
    /// Transfer every allocated destination slot, including an empty slot on copy failure.
    fn copy(&mut self) -> (u64, u32);
    /// Map at the owner's fixed VA. Failure must leave the cap unmapped.
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32>;
}

#[derive(Default)]
struct Cap {
    slot: u64,
    mapped: bool,
}

impl Cap {
    fn unmap(&mut self, io: &mut impl AliasRetirementIo) -> Result<(), u32> {
        if self.mapped {
            io.unmap(self.slot)?;
            self.mapped = false;
        }
        Ok(())
    }

    fn release(&mut self, io: &mut impl AliasRetirementIo) -> Result<(), u32> {
        self.unmap(io)?;
        if self.slot != 0 {
            io.delete(self.slot)?;
            self.slot = 0;
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
enum Phase {
    Empty,
    Live,
    Rollback,
    Commit,
    Retiring,
}

/// Non-cloneable owner. Its containing row must be reserved before construction and retained
/// until empty; backend calls may not reenter that row/table. No operation allocates metadata.
pub struct AliasTransition {
    old: Cap,
    new: Cap,
    rights: u64,
    new_rights: u64,
    phase: Phase,
}

impl AliasTransition {
    pub const fn empty() -> Self {
        Self {
            old: Cap {
                slot: 0,
                mapped: false,
            },
            new: Cap {
                slot: 0,
                mapped: false,
            },
            rights: 0,
            new_rights: 0,
            phase: Phase::Empty,
        }
    }

    pub fn live(&self) -> Option<(u64, u64)> {
        (self.phase == Phase::Live).then_some((self.old.slot, self.rights))
    }

    pub fn is_empty(&self) -> bool {
        self.phase == Phase::Empty
    }

    /// Install into an empty reserved row, or replace the live backing. Capture the new copy
    /// before detaching the old mapping, and retain both until deletion/rollback is acknowledged.
    pub fn replace(&mut self, rights: u64, io: &mut impl AliasTransitionIo) -> Result<(), u32> {
        if !matches!(self.phase, Phase::Empty | Phase::Live) {
            return Err(INVALID);
        }
        self.phase = Phase::Rollback;
        self.new_rights = rights;
        let (cap, status) = io.copy();
        self.new.slot = cap;
        let result = if status != 0 {
            Err(status)
        } else if cap == 0 {
            Err(RESOURCES)
        } else {
            self.old.unmap(io).and_then(|()| io.map(cap, rights))
        };
        if let Err(status) = result {
            let _ = self.recover(io);
            return Err(status);
        }
        self.new.mapped = true;
        self.phase = Phase::Commit;
        self.recover(io)
    }

    /// Reuse the exact existing cap, preserving old rights for rollback without another copy.
    pub fn remap(&mut self, rights: u64, io: &mut impl AliasTransitionIo) -> Result<(), u32> {
        if self.phase != Phase::Live {
            return Err(INVALID);
        }
        self.phase = Phase::Rollback;
        let result = self
            .old
            .unmap(io)
            .and_then(|()| io.map(self.old.slot, rights));
        if let Err(status) = result {
            let _ = self.recover(io);
            return Err(status);
        }
        self.old.mapped = true;
        self.rights = rights;
        self.phase = Phase::Live;
        Ok(())
    }

    /// Retry only the retained stage. A mapped replacement commits by deleting the old cap;
    /// rollback releases the candidate then restores the old cap and rights, never recopying.
    pub fn recover(&mut self, io: &mut impl AliasTransitionIo) -> Result<(), u32> {
        match self.phase {
            Phase::Rollback => {
                self.new.release(io)?;
                if self.old.slot == 0 {
                    self.phase = Phase::Empty;
                } else {
                    if !self.old.mapped {
                        io.map(self.old.slot, self.rights)?;
                        self.old.mapped = true;
                    }
                    self.phase = Phase::Live;
                }
            }
            Phase::Commit => {
                self.old.release(io)?;
                self.old = core::mem::take(&mut self.new);
                self.rights = self.new_rights;
                self.phase = Phase::Live;
            }
            Phase::Retiring => self.retire(io)?,
            Phase::Live | Phase::Empty => {}
        }
        Ok(())
    }

    /// Explicit teardown may cancel either recovery direction, but retains each failed cap.
    pub fn retire(&mut self, io: &mut impl AliasRetirementIo) -> Result<(), u32> {
        self.phase = Phase::Retiring;
        self.new.release(io)?;
        self.old.release(io)?;
        self.phase = Phase::Empty;
        Ok(())
    }
}

impl Default for AliasTransition {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
#[path = "alias_transition_tests.rs"]
mod tests;
