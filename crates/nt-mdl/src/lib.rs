//! # `nt-mdl` — Memory Descriptor List support for DMA
//!
//! The WDK `MDL` x64 layout constants a driver reads via WDK macros, plus a
//! canonical MDL registry (spec: NT DMA/MDL/IOMMU, Milestone 14, §8). v0.1 supports
//! single-buffer nonpaged MDLs only; the registry tracks active DMA mappings so an
//! MDL cannot be freed while a transfer references it. `no_std` + `alloc`; holds no
//! raw pointers across a service boundary — only IDs + address values.
//!
//! ## Driver-visible `MDL` layout (x64)
//!
//! ```text
//! Next@0  Size@8:i16  MdlFlags@10:i16  Process@16  MappedSystemVa@24
//! StartVa@32  ByteCount@40:u32  ByteOffset@44:u32
//! ```
//!
//! `MmGetSystemAddressForMdlSafe` is an inline macro: with
//! `MDL_SOURCE_IS_NONPAGED_POOL` set (by `MmBuildMdlForNonPagedPool`) it returns
//! `MappedSystemVa` directly, so a Driver Host that fills those fields needs no
//! `MmMapLockedPagesSpecifyCache` call.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

// --- driver-visible MDL layout (x64) -----------------------------------------

pub const MDL_OFF_NEXT: u64 = 0;
pub const MDL_OFF_SIZE: u64 = 8;
pub const MDL_OFF_FLAGS: u64 = 10;
pub const MDL_OFF_PROCESS: u64 = 16;
pub const MDL_OFF_MAPPED_SYSTEM_VA: u64 = 24;
pub const MDL_OFF_START_VA: u64 = 32;
pub const MDL_OFF_BYTE_COUNT: u64 = 40;
pub const MDL_OFF_BYTE_OFFSET: u64 = 44;
/// A generous fixed MDL projection size (the real WDK MDL header is 48 bytes; a
/// single-page MDL adds a PFN array, but v0.1 doesn't populate it).
pub const MDL_SIZE: usize = 48;

// --- MdlFlags bits (WDK) -----------------------------------------------------

pub const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
pub const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x0004;
pub const MDL_PAGES_LOCKED: i16 = 0x0002;

/// Why an MDL operation was rejected (spec §8.4, §25).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MdlError {
    /// The MDL ID is unknown or stale.
    StaleId,
    /// The MDL still has active DMA mappings (cannot free, spec §8.4).
    ActiveMappings,
    /// The requested slice is outside the MDL's byte range.
    OutOfRange,
}

struct MdlRecord {
    id: u64,
    generation: u32,
    virtual_address: u64,
    byte_count: u32,
    byte_offset: u32,
    locked: bool,
    active_mappings: u32,
}

/// The canonical MDL registry.
#[derive(Default)]
pub struct MdlRegistry {
    mdls: Vec<MdlRecord>,
    next_id: u64,
    next_gen: u32,
}

impl MdlRegistry {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_gen: 1,
            ..Default::default()
        }
    }

    fn find(&self, id: u64) -> Option<&MdlRecord> {
        self.mdls.iter().find(|m| m.id == id)
    }
    fn find_mut(&mut self, id: u64) -> Option<&mut MdlRecord> {
        self.mdls.iter_mut().find(|m| m.id == id)
    }

    /// `IoAllocateMdl` — register a single-buffer MDL over `[virtual_address,
    /// virtual_address+length)`. `ByteOffset` = low 12 bits of the address.
    pub fn allocate(&mut self, virtual_address: u64, length: u32) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let generation = self.next_gen;
        self.next_gen += 1;
        self.mdls.push(MdlRecord {
            id,
            generation,
            virtual_address,
            byte_count: length,
            byte_offset: (virtual_address & 0xFFF) as u32,
            locked: false,
            active_mappings: 0,
        });
        id
    }

    /// `MmBuildMdlForNonPagedPool` — mark the MDL as backed by locked nonpaged pool.
    pub fn build_for_nonpaged(&mut self, id: u64) -> Result<(), MdlError> {
        self.find_mut(id).ok_or(MdlError::StaleId)?.locked = true;
        Ok(())
    }

    pub fn is_locked(&self, id: u64) -> bool {
        self.find(id).map(|m| m.locked).unwrap_or(false)
    }

    pub fn virtual_address(&self, id: u64) -> Option<u64> {
        self.find(id).map(|m| m.virtual_address)
    }
    pub fn byte_count(&self, id: u64) -> Option<u32> {
        self.find(id).map(|m| m.byte_count)
    }
    pub fn byte_offset(&self, id: u64) -> Option<u32> {
        self.find(id).map(|m| m.byte_offset)
    }
    pub fn generation(&self, id: u64) -> Option<u32> {
        self.find(id).map(|m| m.generation)
    }
    pub fn active_mappings(&self, id: u64) -> u32 {
        self.find(id).map(|m| m.active_mappings).unwrap_or(0)
    }

    /// Validate a `[offset, offset+length)` slice lies within a locked MDL — the
    /// precondition for a DMA map (spec §12.2).
    pub fn validate_slice(&self, id: u64, offset: u64, length: u64) -> Result<(), MdlError> {
        let m = self.find(id).ok_or(MdlError::StaleId)?;
        if !m.locked {
            return Err(MdlError::StaleId);
        }
        if length == 0 || offset + length > m.byte_count as u64 {
            return Err(MdlError::OutOfRange);
        }
        Ok(())
    }

    /// Record a DMA mapping against the MDL (bumps `active_mappings`).
    pub fn add_mapping(&mut self, id: u64) -> Result<(), MdlError> {
        self.find_mut(id).ok_or(MdlError::StaleId)?.active_mappings += 1;
        Ok(())
    }

    /// Release a DMA mapping against the MDL.
    pub fn remove_mapping(&mut self, id: u64) -> Result<(), MdlError> {
        let m = self.find_mut(id).ok_or(MdlError::StaleId)?;
        m.active_mappings = m.active_mappings.saturating_sub(1);
        Ok(())
    }

    /// `IoFreeMdl` — release the MDL. Fails if it still has active DMA mappings
    /// (spec §8.4).
    pub fn free(&mut self, id: u64) -> Result<(), MdlError> {
        let m = self.find(id).ok_or(MdlError::StaleId)?;
        if m.active_mappings > 0 {
            return Err(MdlError::ActiveMappings);
        }
        self.mdls.retain(|m| m.id != id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_records_range() {
        let mut r = MdlRegistry::new();
        let id = r.allocate(0x1_2340, 128);
        assert_eq!(r.byte_count(id), Some(128));
        assert_eq!(r.byte_offset(id), Some(0x340)); // low 12 bits
        assert_eq!(r.virtual_address(id), Some(0x1_2340));
        assert!(!r.is_locked(id));
    }

    #[test]
    fn build_for_nonpaged_locks() {
        let mut r = MdlRegistry::new();
        let id = r.allocate(0x2000, 64);
        r.build_for_nonpaged(id).unwrap();
        assert!(r.is_locked(id));
        r.validate_slice(id, 0, 64).unwrap();
        assert_eq!(r.validate_slice(id, 0, 128), Err(MdlError::OutOfRange));
    }

    #[test]
    fn free_with_active_mapping_rejected() {
        let mut r = MdlRegistry::new();
        let id = r.allocate(0x3000, 256);
        r.build_for_nonpaged(id).unwrap();
        r.add_mapping(id).unwrap();
        assert_eq!(r.free(id), Err(MdlError::ActiveMappings));
        r.remove_mapping(id).unwrap();
        r.free(id).unwrap();
    }

    #[test]
    fn stale_id_rejected() {
        let mut r = MdlRegistry::new();
        let id = r.allocate(0x4000, 32);
        r.free(id).unwrap();
        assert_eq!(r.build_for_nonpaged(id), Err(MdlError::StaleId));
        assert_eq!(r.validate_slice(id, 0, 8), Err(MdlError::StaleId));
    }
}
