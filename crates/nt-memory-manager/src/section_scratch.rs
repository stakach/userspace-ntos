//! Prepared canonical aliases with batch identity and retry-owned capability cleanup.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const RESOURCES: u32 = 0xc000_009a;
const INVALID_PARAMETER: u32 = 0xc000_000d;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionAliasAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionAliasHandle {
    owner: u64,
    generation: u64,
    index: usize,
}

pub trait SectionScratchIo {
    /// Transfer any reserved destination, including an allocated-empty slot on copy failure.
    /// Nonzero status means the returned slot is empty; zero status means a populated copy.
    fn copy_frame(&mut self, frame: u64) -> (u64, u32);
    fn map_alias(
        &mut self,
        alias: u64,
        address: u64,
        access: SectionAliasAccess,
    ) -> Result<(), u32>;
    /// Delete the exact cap and its mapping without recycling its slot. An already-revoked
    /// (empty) slot still needs acknowledgement. Failed deletion retains both cap and VA ownership.
    fn delete_alias(&mut self, alias: u64) -> Result<(), u32>;
    /// Publish only this empty copied-cap slot, rejecting unexpected retype-byte ownership.
    /// Failure must leave allocator ownership unchanged and must not repeat deletion.
    fn recycle_alias_slot(&mut self, slot: u64) -> Result<(), u32>;
}

struct Entry {
    cap: u64,
    address: u64,
    access: SectionAliasAccess,
    mapped: bool,
    populated: bool,
}

/// Persistent cleanup owner. Dropping it cannot perform backend deletion; it must outlive all
/// retained entries, including failed cleanup. Runtime integrations must use durable storage.
pub struct SectionScratch {
    owner: u64,
    generation: u64,
    active: bool,
    entries: Vec<Entry>,
}

impl SectionScratch {
    pub const fn new() -> Self {
        Self {
            owner: 0,
            generation: 0,
            active: false,
            entries: Vec::new(),
        }
    }

    /// Refuse reentry; retained cleanup must complete before a new batch can own any addresses.
    pub fn begin(&mut self, io: &mut impl SectionScratchIo) -> Result<(), u32> {
        if self.active {
            return Err(RESOURCES);
        }
        self.drain(io)?;
        let generation = self.generation.checked_add(1).ok_or(RESOURCES)?;
        if self.owner == 0 {
            self.owner = NEXT_OWNER
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| RESOURCES)?;
        }
        self.generation = generation;
        self.active = true;
        Ok(())
    }

    /// The caller owns a disjoint virtual region for this batch. Reserve metadata before acquiring
    /// a cap, then adopt it before mapping, so every failure path retains exact cleanup ownership.
    pub fn prepare(
        &mut self,
        frame: u64,
        address: u64,
        access: SectionAliasAccess,
        io: &mut impl SectionScratchIo,
    ) -> Result<SectionAliasHandle, u32> {
        if !self.active || frame == 0 {
            return Err(crate::STATUS_INVALID_HANDLE);
        }
        if address & 0xfff != 0
            || address.checked_add(0x1000).is_none()
            || self.entries.iter().any(|entry| entry.address == address)
        {
            return Err(INVALID_PARAMETER);
        }
        self.entries.try_reserve(1).map_err(|_| RESOURCES)?;
        let (cap, status) = io.copy_frame(frame);
        if cap == 0 {
            return Err(if status == 0 { RESOURCES } else { status });
        }
        let index = self.entries.len();
        self.entries.push(Entry {
            cap,
            address,
            access,
            mapped: false,
            populated: status == 0,
        });
        if status != 0 {
            return Err(status);
        }
        io.map_alias(cap, address, access)?;
        self.entries[index].mapped = true;
        Ok(SectionAliasHandle {
            owner: self.owner,
            generation: self.generation,
            index,
        })
    }

    pub fn resolve(
        &self,
        handle: SectionAliasHandle,
        offset: usize,
        length: usize,
        access: SectionAliasAccess,
    ) -> Result<u64, u32> {
        if !self.active || handle.owner != self.owner || handle.generation != self.generation {
            return Err(crate::STATUS_INVALID_HANDLE);
        }
        let entry = self
            .entries
            .get(handle.index)
            .filter(|entry| entry.mapped)
            .ok_or(crate::STATUS_INVALID_HANDLE)?;
        if access == SectionAliasAccess::ReadWrite && entry.access != access {
            return Err(crate::STATUS_ACCESS_VIOLATION);
        }
        if offset.checked_add(length).is_none_or(|end| end > 0x1000) {
            return Err(INVALID_PARAMETER);
        }
        Ok(entry.address + offset as u64)
    }

    /// Invalidate all handles before cleanup, even when the first deletion fails.
    pub fn finish(&mut self, io: &mut impl SectionScratchIo) -> Result<(), u32> {
        self.active = false;
        self.drain(io)
    }

    pub fn drain(&mut self, io: &mut impl SectionScratchIo) -> Result<(), u32> {
        if self.active {
            return Err(RESOURCES);
        }
        while let Some(entry) = self.entries.last_mut() {
            if entry.populated {
                io.delete_alias(entry.cap)?;
                entry.populated = false;
                entry.mapped = false;
            }
            io.recycle_alias_slot(entry.cap)?;
            self.entries.pop();
        }
        Ok(())
    }

    /// Ordinary one-page writeback uses the same batch owner as prepared multi-page I/O.
    pub fn with_frame<I: SectionScratchIo>(
        &mut self,
        frame: u64,
        address: u64,
        io: &mut I,
        transfer: impl FnOnce(&mut I) -> (u32, usize),
    ) -> (u32, usize) {
        if frame == 0 {
            return (crate::STATUS_INVALID_HANDLE, 0);
        }
        if let Err(status) = self.begin(io) {
            return (status, 0);
        }
        let result = match self.prepare(frame, address, SectionAliasAccess::ReadOnly, io) {
            Ok(_) => transfer(io),
            Err(status) => (status, 0),
        };
        match (result, self.finish(io)) {
            ((0, bytes), Err(status)) => (status, bytes),
            (result, _) => result,
        }
    }
}

impl Default for SectionScratch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "section_mapping_tests.rs"]
mod mapping_tests;
#[cfg(test)]
#[path = "section_scratch_tests.rs"]
mod tests;
