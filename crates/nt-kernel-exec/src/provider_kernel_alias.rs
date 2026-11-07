//! Bounded provider backing above the exported NT user-probe boundary.
//!
//! The embedding component maps a dedicated physical arena in the upper canonical user VSpace.
//! Only exact allocations from that arena can acquire a provider pointer above the NT probe bound.

use crate::provider_pool::{self, PoolMemory};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelAliasError {
    InvalidWindow,
    OutsideWindow,
    NotAllocated,
    OutOfMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelAliasAllocation {
    pub address: u64,
    pub capacity: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelAliasWindow {
    base: u64,
    bytes: u64,
}

impl KernelAliasWindow {
    pub fn new(base: u64, bytes: u64, probe: u64) -> Result<Self, KernelAliasError> {
        // Keep the final canonical page free for the component's own upper-address conventions.
        const LAST_RESERVED_PAGE: u64 = 0x0000_7fff_ffff_f000;
        let end = base.checked_add(bytes).ok_or(KernelAliasError::InvalidWindow)?;
        if base & 0xfff != 0
            || bytes & 0xfff != 0
            || bytes <= provider_pool::DATA_OFFSET + provider_pool::HEADER_SIZE
            || base <= probe
            || end > LAST_RESERVED_PAGE
        {
            return Err(KernelAliasError::InvalidWindow);
        }
        Ok(Self { base, bytes })
    }

    /// A client-page alias may never replace provider-owned cursor backing.
    pub fn contains_page(&self, page: u64) -> bool {
        page & 0xfff == 0 && (self.base..self.base + self.bytes).contains(&page)
    }

    pub fn initialize<M: PoolMemory>(&self, memory: &mut M) -> Result<(), KernelAliasError> {
        if memory.len() != self.bytes { return Err(KernelAliasError::InvalidWindow); }
        provider_pool::initialize(memory).map_err(|_| KernelAliasError::InvalidWindow)
    }

    pub fn allocate<M: PoolMemory>(
        &self,
        memory: &mut M,
        size: u64,
    ) -> Result<KernelAliasAllocation, KernelAliasError> {
        if memory.len() != self.bytes { return Err(KernelAliasError::InvalidWindow); }
        let allocation = provider_pool::allocate(memory, size, false)
            .map_err(|_| KernelAliasError::OutOfMemory)?;
        // PoolMemory.len is the validated window size, so the allocator's checked offset and
        // capacity are inside the window. No fallible step follows the allocation effect.
        let address = self.base + allocation.payload_offset;
        debug_assert!(address + allocation.capacity <= self.base + self.bytes);
        Ok(KernelAliasAllocation {
            address,
            capacity: allocation.capacity,
        })
    }

    pub fn allocation_capacity<M: PoolMemory>(
        &self,
        memory: &M,
        address: u64,
    ) -> Result<u64, KernelAliasError> {
        if memory.len() != self.bytes { return Err(KernelAliasError::InvalidWindow); }
        let offset = address.checked_sub(self.base).filter(|offset| *offset < self.bytes)
            .ok_or(KernelAliasError::OutsideWindow)?;
        provider_pool::allocation_capacity(memory, offset).map_err(|_| KernelAliasError::NotAllocated)
    }

    pub fn free<M: PoolMemory>(
        &self,
        memory: &mut M,
        address: u64,
    ) -> Result<(), KernelAliasError> {
        if memory.len() != self.bytes { return Err(KernelAliasError::InvalidWindow); }
        let offset = address.checked_sub(self.base).filter(|offset| *offset < self.bytes)
            .ok_or(KernelAliasError::OutsideWindow)?;
        provider_pool::free(memory, offset).map(|_| ()).map_err(|_| KernelAliasError::NotAllocated)
    }
}
