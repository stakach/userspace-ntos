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

pub mod page_lock;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_READ_LEASE_ID: AtomicU64 = AtomicU64::new(1);

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
    /// A caller supplied a null domain identity, generation, or MDL address.
    InvalidKey,
    /// The exact domain-generation and MDL address already names a live record.
    AlreadyExists,
    /// The MDL ID is unknown or stale.
    StaleId,
    /// The MDL still has active DMA mappings (cannot free, spec §8.4).
    ActiveMappings,
    /// The requested slice is outside the MDL's byte range.
    OutOfRange,
    /// A retained reader still owns a range of this MDL.
    ActiveReadLeases,
    /// A lease identifier cannot be allocated without reusing an old one.
    LeaseIdsExhausted,
    /// A read lease could not reserve registry storage.
    InsufficientResources,
}

/// A driver-visible MDL's canonical identity outside the public `MDL` fields.
///
/// Component virtual addresses may be reused after a hosted domain restarts, so the address alone
/// is not an identity. The domain cookie fences that reuse without consuming `MDL.Next`, which is
/// an ordinary driver-owned chain link in the NT ABI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MdlKey {
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub component_va: u64,
}

impl MdlKey {
    pub const fn new(domain_id: u64, domain_cookie: u64, component_va: u64) -> Option<Self> {
        if domain_id == 0 || domain_cookie == 0 || component_va == 0 {
            return None;
        }
        Some(Self {
            domain_id,
            domain_cookie,
            component_va,
        })
    }
}

/// Exact, generation-bearing retention of a locked hosted MDL descriptor range.
///
/// This is an owned value, not a pointer into the driver's address space. The
/// The caller must separately prove that the backing pages are readable and stable. Retain
/// this value until reads and provider effects finish, then release it through the originating
/// registry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MdlReadLease {
    lease_id: u64,
    key: MdlKey,
    mdl_id: u64,
    generation: u32,
    virtual_address: u64,
    length: u32,
}

impl MdlReadLease {
    pub const fn virtual_address(self) -> u64 {
        self.virtual_address
    }

    pub const fn length(self) -> u32 {
        self.length
    }

    pub const fn key(self) -> MdlKey {
        self.key
    }
}

struct MdlRecord {
    id: u64,
    key: Option<MdlKey>,
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
    read_leases: Vec<MdlReadLease>,
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

    fn find_key(&self, key: MdlKey) -> Option<&MdlRecord> {
        self.mdls.iter().find(|m| m.key == Some(key))
    }

    fn has_read_lease(&self, id: u64) -> bool {
        self.read_leases.iter().any(|lease| lease.mdl_id == id)
    }

    fn allocate_record(&mut self, key: Option<MdlKey>, virtual_address: u64, length: u32) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let generation = self.next_gen;
        self.next_gen += 1;
        self.mdls.push(MdlRecord {
            id,
            key,
            generation,
            virtual_address,
            byte_count: length,
            byte_offset: (virtual_address & 0xFFF) as u32,
            locked: false,
            active_mappings: 0,
        });
        id
    }

    /// `IoAllocateMdl` — register a single-buffer MDL over `[virtual_address,
    /// virtual_address+length)`. `ByteOffset` = low 12 bits of the address.
    pub fn allocate(&mut self, virtual_address: u64, length: u32) -> u64 {
        self.allocate_record(None, virtual_address, length)
    }

    /// Register a driver-visible MDL under its authenticated hosted-domain identity.
    pub fn register(
        &mut self,
        key: MdlKey,
        virtual_address: u64,
        length: u32,
    ) -> Result<u64, MdlError> {
        if key.domain_id == 0 || key.domain_cookie == 0 || key.component_va == 0 {
            return Err(MdlError::InvalidKey);
        }
        if self.find_key(key).is_some() {
            return Err(MdlError::AlreadyExists);
        }
        Ok(self.allocate_record(Some(key), virtual_address, length))
    }

    pub fn id_for(&self, key: MdlKey) -> Option<u64> {
        self.find_key(key).map(|record| record.id)
    }

    pub fn build_for_nonpaged_key(&mut self, key: MdlKey) -> Result<(), MdlError> {
        let id = self.id_for(key).ok_or(MdlError::StaleId)?;
        self.build_for_nonpaged(id)
    }

    /// Update the described range before the MDL is published or mapped, as required by
    /// `IoBuildPartialMdl`.
    pub fn update_key(
        &mut self,
        key: MdlKey,
        virtual_address: u64,
        length: u32,
    ) -> Result<(), MdlError> {
        let id = self.id_for(key).ok_or(MdlError::StaleId)?;
        if self.has_read_lease(id) {
            return Err(MdlError::ActiveReadLeases);
        }
        let record = self.find_mut(id).ok_or(MdlError::StaleId)?;
        if record.active_mappings != 0 {
            return Err(MdlError::ActiveMappings);
        }
        record.virtual_address = virtual_address;
        record.byte_count = length;
        record.byte_offset = (virtual_address & 0xFFF) as u32;
        record.locked = false;
        Ok(())
    }

    pub fn unlock_key(&mut self, key: MdlKey) -> Result<(), MdlError> {
        let id = self.id_for(key).ok_or(MdlError::StaleId)?;
        if self.has_read_lease(id) {
            return Err(MdlError::ActiveReadLeases);
        }
        let record = self.find_mut(id).ok_or(MdlError::StaleId)?;
        if record.active_mappings != 0 {
            return Err(MdlError::ActiveMappings);
        }
        record.locked = false;
        Ok(())
    }

    pub fn can_free_key(&self, key: MdlKey) -> Result<(), MdlError> {
        let record = self.find_key(key).ok_or(MdlError::StaleId)?;
        if self.has_read_lease(record.id) {
            return Err(MdlError::ActiveReadLeases);
        }
        if record.active_mappings != 0 {
            return Err(MdlError::ActiveMappings);
        }
        Ok(())
    }

    pub fn free_key(&mut self, key: MdlKey) -> Result<(), MdlError> {
        let id = self.id_for(key).ok_or(MdlError::StaleId)?;
        self.free(id)
    }

    /// Retire every driver-visible MDL owned by one exact hosted-domain generation.
    pub fn revoke_domain(&mut self, domain_id: u64, domain_cookie: u64) -> Result<usize, MdlError> {
        if domain_id == 0 || domain_cookie == 0 {
            return Err(MdlError::InvalidKey);
        }
        if self.mdls.iter().any(|record| {
            record.key.is_some_and(|key| {
                key.domain_id == domain_id
                    && key.domain_cookie == domain_cookie
                    && record.active_mappings != 0
            })
        }) {
            return Err(MdlError::ActiveMappings);
        }
        if self.read_leases.iter().any(|lease| {
            lease.key.domain_id == domain_id && lease.key.domain_cookie == domain_cookie
        }) {
            return Err(MdlError::ActiveReadLeases);
        }
        let before = self.mdls.len();
        self.mdls.retain(|record| {
            !record
                .key
                .is_some_and(|key| key.domain_id == domain_id && key.domain_cookie == domain_cookie)
        });
        Ok(before - self.mdls.len())
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
        if length == 0
            || offset
                .checked_add(length)
                .is_none_or(|end| end > m.byte_count as u64)
        {
            return Err(MdlError::OutOfRange);
        }
        Ok(())
    }

    /// Retain an exact range of a locked hosted MDL for read-side projection.
    /// The returned virtual address is only an address value; the host must
    /// authenticate and copy bytes through its own source-memory boundary.
    pub fn acquire_read_lease(
        &mut self,
        key: MdlKey,
        offset: u64,
        length: u64,
    ) -> Result<MdlReadLease, MdlError> {
        let record = self.find_key(key).ok_or(MdlError::StaleId)?;
        self.validate_slice(record.id, offset, length)?;
        let virtual_address = record
            .virtual_address
            .checked_add(offset)
            .ok_or(MdlError::OutOfRange)?;
        virtual_address
            .checked_add(length - 1)
            .ok_or(MdlError::OutOfRange)?;
        let length = u32::try_from(length).map_err(|_| MdlError::OutOfRange)?;
        let mdl_id = record.id;
        let generation = record.generation;
        self.read_leases
            .try_reserve(1)
            .map_err(|_| MdlError::InsufficientResources)?;
        let lease_id = NEXT_READ_LEASE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| MdlError::LeaseIdsExhausted)?;
        let lease = MdlReadLease {
            lease_id,
            key,
            mdl_id,
            generation,
            virtual_address,
            length,
        };
        self.read_leases.push(lease);
        Ok(lease)
    }

    /// Release only the exact lease issued by this registry. A failed release
    /// leaves the original lease in place for retry or explicit recovery.
    pub fn release_read_lease(&mut self, lease: MdlReadLease) -> Result<(), MdlError> {
        let position = self
            .read_leases
            .iter()
            .position(|held| *held == lease)
            .ok_or(MdlError::StaleId)?;
        let record = self.find(lease.mdl_id).ok_or(MdlError::StaleId)?;
        if record.key != Some(lease.key) || record.generation != lease.generation {
            return Err(MdlError::StaleId);
        }
        self.read_leases.remove(position);
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
        if self.has_read_lease(id) {
            return Err(MdlError::ActiveReadLeases);
        }
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

    #[test]
    fn keyed_identity_fences_domain_generations_and_address_reuse() {
        let mut r = MdlRegistry::new();
        let first = MdlKey::new(7, 11, 0x20_0100).unwrap();
        let replacement = MdlKey::new(7, 12, 0x20_0100).unwrap();
        let first_id = r.register(first, 0x40_0123, 128).unwrap();
        assert_eq!(r.id_for(first), Some(first_id));
        assert_eq!(
            r.register(first, 0x50_0000, 64),
            Err(MdlError::AlreadyExists)
        );
        assert!(r.register(replacement, 0x50_0000, 64).is_ok());
        r.free_key(first).unwrap();
        assert_eq!(r.id_for(first), None);
        assert!(r.id_for(replacement).is_some());
    }

    #[test]
    fn keyed_update_lock_and_free_preserve_mapping_rules() {
        let mut r = MdlRegistry::new();
        let key = MdlKey::new(2, 3, 0x20_0200).unwrap();
        let id = r.register(key, 0x3000, 256).unwrap();
        r.update_key(key, 0x4123, 96).unwrap();
        assert_eq!(r.virtual_address(id), Some(0x4123));
        assert_eq!(r.byte_count(id), Some(96));
        r.build_for_nonpaged_key(key).unwrap();
        r.add_mapping(id).unwrap();
        assert_eq!(r.unlock_key(key), Err(MdlError::ActiveMappings));
        assert_eq!(r.can_free_key(key), Err(MdlError::ActiveMappings));
        r.remove_mapping(id).unwrap();
        r.unlock_key(key).unwrap();
        r.free_key(key).unwrap();
        assert_eq!(r.id_for(key), None);
    }

    #[test]
    fn domain_revoke_is_generation_scoped_and_mapping_safe() {
        let mut r = MdlRegistry::new();
        let old = MdlKey::new(9, 4, 0x200100).unwrap();
        let current = MdlKey::new(9, 5, 0x200100).unwrap();
        let old_id = r.register(old, 0x1000, 64).unwrap();
        r.register(current, 0x2000, 64).unwrap();
        r.add_mapping(old_id).unwrap();
        assert_eq!(r.revoke_domain(9, 4), Err(MdlError::ActiveMappings));
        r.remove_mapping(old_id).unwrap();
        assert_eq!(r.revoke_domain(9, 4), Ok(1));
        assert_eq!(r.id_for(old), None);
        assert!(r.id_for(current).is_some());
    }

    #[test]
    fn read_lease_retains_exact_locked_range_until_release() {
        let mut r = MdlRegistry::new();
        let key = MdlKey::new(15, 7, 0x300100).unwrap();
        let id = r.register(key, 0x8123, 128).unwrap();
        assert_eq!(r.acquire_read_lease(key, 4, 8), Err(MdlError::StaleId));
        r.build_for_nonpaged_key(key).unwrap();
        let lease = r.acquire_read_lease(key, 4, 8).unwrap();
        assert_eq!(lease.virtual_address(), 0x8127);
        assert_eq!(lease.length(), 8);
        assert_eq!(lease.key(), key);
        assert_eq!(
            r.update_key(key, 0x9000, 16),
            Err(MdlError::ActiveReadLeases)
        );
        assert_eq!(r.unlock_key(key), Err(MdlError::ActiveReadLeases));
        assert_eq!(r.can_free_key(key), Err(MdlError::ActiveReadLeases));
        assert_eq!(r.free_key(key), Err(MdlError::ActiveReadLeases));
        assert_eq!(r.free(id), Err(MdlError::ActiveReadLeases));
        assert_eq!(r.revoke_domain(15, 7), Err(MdlError::ActiveReadLeases));
        assert_eq!(r.virtual_address(id), Some(0x8123));
        r.release_read_lease(lease).unwrap();
        assert_eq!(r.release_read_lease(lease), Err(MdlError::StaleId));
        r.update_key(key, 0x9000, 16).unwrap();
        r.free_key(key).unwrap();
    }

    #[test]
    fn failed_release_preserves_exact_lease_and_other_readers() {
        let mut r = MdlRegistry::new();
        let key = MdlKey::new(20, 2, 0x400100).unwrap();
        let other_generation = MdlKey::new(20, 3, 0x400100).unwrap();
        r.register(key, 0x10000, 32).unwrap();
        r.register(other_generation, 0x20000, 32).unwrap();
        r.build_for_nonpaged_key(key).unwrap();
        r.build_for_nonpaged_key(other_generation).unwrap();
        let first = r.acquire_read_lease(key, 0, 16).unwrap();
        let second = r.acquire_read_lease(key, 16, 16).unwrap();
        let altered = MdlReadLease {
            key: other_generation,
            ..first
        };
        assert_eq!(r.release_read_lease(altered), Err(MdlError::StaleId));
        assert_eq!(r.free_key(key), Err(MdlError::ActiveReadLeases));
        r.release_read_lease(first).unwrap();
        assert_eq!(r.free_key(key), Err(MdlError::ActiveReadLeases));
        r.release_read_lease(second).unwrap();
        r.free_key(key).unwrap();
        assert_eq!(r.acquire_read_lease(key, 0, 1), Err(MdlError::StaleId));
        assert!(r.id_for(other_generation).is_some());
    }

    #[test]
    fn lease_from_another_registry_cannot_release_same_key_and_range() {
        let key = MdlKey::new(25, 9, 0x410000).unwrap();
        let mut first = MdlRegistry::new();
        let mut second = MdlRegistry::new();
        first.register(key, 0x12000, 16).unwrap();
        second.register(key, 0x12000, 16).unwrap();
        first.build_for_nonpaged_key(key).unwrap();
        second.build_for_nonpaged_key(key).unwrap();
        let first_lease = first.acquire_read_lease(key, 0, 8).unwrap();
        let second_lease = second.acquire_read_lease(key, 0, 8).unwrap();
        assert_eq!(
            second.release_read_lease(first_lease),
            Err(MdlError::StaleId)
        );
        assert_eq!(second.free_key(key), Err(MdlError::ActiveReadLeases));
        first.release_read_lease(first_lease).unwrap();
        second.release_read_lease(second_lease).unwrap();
    }

    #[test]
    fn read_lease_rejects_offset_length_and_address_overflow() {
        let mut r = MdlRegistry::new();
        let key = MdlKey::new(30, 1, 0x500100).unwrap();
        let id = r.register(key, u64::MAX - 3, 16).unwrap();
        r.build_for_nonpaged_key(key).unwrap();
        assert_eq!(r.validate_slice(id, u64::MAX, 8), Err(MdlError::OutOfRange));
        assert_eq!(r.acquire_read_lease(key, 0, 0), Err(MdlError::OutOfRange));
        assert_eq!(r.acquire_read_lease(key, 16, 1), Err(MdlError::OutOfRange));
        assert_eq!(r.acquire_read_lease(key, 0, 16), Err(MdlError::OutOfRange));
        assert_eq!(r.acquire_read_lease(key, 4, 1), Err(MdlError::OutOfRange));
        let lease = r.acquire_read_lease(key, 3, 1).unwrap();
        assert_eq!(lease.virtual_address(), u64::MAX);
        r.release_read_lease(lease).unwrap();
    }
}
