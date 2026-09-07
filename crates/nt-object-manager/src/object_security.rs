//! Referenced immutable descriptors for modeled default-security objects.
//!
//! `ObGetObjectSecurity` returns a reference to cached storage with `MemoryAllocated = FALSE`;
//! `ObReleaseObjectSecurity` drops that reference. The provider pool owns the underlying allocation
//! until the final checked release. This is not a custom object-type security procedure dispatcher.

use alloc::vec::Vec;

const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;

/// The backend must return a fresh, non-null allocation containing an immutable exact copy.
/// An allocation failure retains no allocation; a free failure leaves the allocation intact.
/// Operations must not reenter the cache. All live cache entries must be released before teardown.
pub trait ObjectSecurityCacheIo {
    fn allocate_copy(&mut self, descriptor: &[u8]) -> Result<u64, u32>;
    fn free(&mut self, pointer: u64) -> Result<(), u32>;
}

struct DescriptorEntry {
    pointer: u64,
    descriptor: Vec<u8>,
    references: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectSecurityCacheStats {
    /// Successful non-null acquisitions, including deduplicated references.
    pub acquisitions: u64,
    /// Consumed non-null caller references, including final releases awaiting a failed free.
    pub releases: u64,
    pub live_references: u64,
    pub entries: usize,
    pub retiring: usize,
    /// Fresh-copy admissions rejected by metadata reservation or backend allocation.
    pub allocation_failures: u64,
    /// Final releases for which the backend could not free the allocation.
    pub release_failures: u64,
    /// Non-null releases without an outstanding caller reference at that exact allocation base.
    pub invalid_releases: u64,
}

/// Content-deduplicated default-security references. Pointer references are fungible, as in the
/// native API; release accepts only an exact live allocation base, never an interior pointer.
pub struct ObjectSecurityCache {
    entries: Vec<DescriptorEntry>,
    stats: ObjectSecurityCacheStats,
}

impl ObjectSecurityCache {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            stats: ObjectSecurityCacheStats {
                acquisitions: 0,
                releases: 0,
                live_references: 0,
                entries: 0,
                retiring: 0,
                allocation_failures: 0,
                release_failures: 0,
                invalid_releases: 0,
            },
        }
    }

    /// Acquire default-security storage; `None` is a valid object with no security descriptor.
    /// Object validity and type-method dispatch must be established before calling this method.
    pub fn acquire(
        &mut self,
        descriptor: Option<&[u8]>,
        io: &mut impl ObjectSecurityCacheIo,
    ) -> Result<u64, u32> {
        let Some(descriptor) = descriptor else {
            return Ok(0);
        };
        if descriptor.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let live_references = self
            .stats
            .live_references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.references != 0 && entry.descriptor == descriptor)
        {
            let references = entry
                .references
                .checked_add(1)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            entry.references = references;
            self.stats.live_references = live_references;
            self.stats.acquisitions = self.stats.acquisitions.saturating_add(1);
            return Ok(entry.pointer);
        }

        let pointer = self.allocate_entry(descriptor, io).map_err(|status| {
            self.stats.allocation_failures = self.stats.allocation_failures.saturating_add(1);
            status
        })?;
        self.stats.live_references = live_references;
        self.stats.entries = self.entries.len();
        self.stats.acquisitions = self.stats.acquisitions.saturating_add(1);
        Ok(pointer)
    }

    fn allocate_entry(
        &mut self,
        descriptor: &[u8],
        io: &mut impl ObjectSecurityCacheIo,
    ) -> Result<u64, u32> {
        self.entries
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(descriptor.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        owned.extend_from_slice(descriptor);
        let pointer = io.allocate_copy(&owned)?;
        if pointer == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        // The backend's fresh-allocation contract ensures the pointer is not already cache-owned.
        // Both metadata buffers are reserved before the external allocation is acquired.
        self.entries.push(DescriptorEntry {
            pointer,
            descriptor: owned,
            references: 1,
        });
        Ok(pointer)
    }

    /// Consume one caller reference. A failed final free remains owned as a retirement; it must be
    /// retried through `retry_retirements`, not by releasing the already consumed reference again.
    pub fn release(
        &mut self,
        pointer: u64,
        io: &mut impl ObjectSecurityCacheIo,
    ) -> Result<(), u32> {
        if pointer == 0 {
            return Ok(());
        }
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.pointer == pointer && entry.references != 0)
        else {
            self.stats.invalid_releases = self.stats.invalid_releases.saturating_add(1);
            return Err(STATUS_INVALID_PARAMETER);
        };
        self.entries[index].references -= 1;
        self.stats.live_references -= 1;
        self.stats.releases = self.stats.releases.saturating_add(1);
        if self.entries[index].references == 0 {
            self.stats.retiring += 1;
            self.free_retirement(index, io)?;
        }
        Ok(())
    }

    fn free_retirement(
        &mut self,
        index: usize,
        io: &mut impl ObjectSecurityCacheIo,
    ) -> Result<(), u32> {
        io.free(self.entries[index].pointer).map_err(|status| {
            self.stats.release_failures = self.stats.release_failures.saturating_add(1);
            status
        })?;
        self.entries.swap_remove(index);
        self.stats.retiring -= 1;
        self.stats.entries = self.entries.len();
        Ok(())
    }

    /// Retry each retained final free at most once. Other failures do not starve later entries.
    /// Returns the number freed; failures remain visible in `release_failures` and `retiring`.
    pub fn retry_retirements(&mut self, io: &mut impl ObjectSecurityCacheIo) -> usize {
        if self.stats.retiring == 0 {
            return 0;
        }
        let mut index = 0;
        let mut freed = 0;
        while index < self.entries.len() {
            if self.entries[index].references == 0 && self.free_retirement(index, io).is_ok() {
                freed += 1;
            } else {
                index += 1;
            }
        }
        freed
    }

    pub fn contains(&self, pointer: u64) -> bool {
        self.entries.iter().any(|entry| entry.pointer == pointer)
    }

    pub fn retiring_count(&self) -> usize {
        self.stats.retiring
    }

    pub fn reference_count(&self, pointer: u64) -> Option<u32> {
        self.entries
            .iter()
            .find(|entry| entry.pointer == pointer)
            .map(|entry| entry.references)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn stats(&self) -> ObjectSecurityCacheStats {
        self.stats
    }
}

impl Default for ObjectSecurityCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "object_security_tests.rs"]
mod tests;
