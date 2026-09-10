//! Exclusive access to one published snapshot backend and its immutable store/identity.

use crate::{SnapshotBlockDevice, SnapshotBlockStore, SnapshotBlockStoreError};
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

/// Construct one owner for the actual backing reserve, then share that owner among every reader
/// and writer. Independently reconstructed device wrappers are not independent storage authority.
/// The backend cannot be extracted or replaced through this API. This is access exclusion, not
/// journal durability, caller completion, or exclusion of mutations to a separate FileSystem.
pub struct SnapshotReserve<D, I> {
    device: UnsafeCell<D>,
    identity: I,
    store: SnapshotBlockStore,
    held: AtomicBool,
}

// The atomic gate serializes every backend access, including geometry reads. Identity is immutable.
unsafe impl<D: Send, I: Sync> Sync for SnapshotReserve<D, I> {}

impl<D, I> SnapshotReserve<D, I> {
    pub const fn new(device: D, identity: I, store: SnapshotBlockStore) -> Self {
        Self {
            device: UnsafeCell::new(device),
            identity,
            store,
            held: AtomicBool::new(false),
        }
    }

    /// Nonblocking admission. A refused caller owns no lease and must retain its pending work.
    pub fn try_acquire(&self) -> Option<SnapshotReserveLease<'_, D, I>> {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(SnapshotReserveLease {
            reserve: self,
            exclusive: PhantomData,
        })
    }
}

/// Keep the lease in retained work for as long as the operation requires exclusive storage access.
/// Drop releases access only: an error or dropped lease never proves durability or cancellation.
///
/// ```compile_fail
/// use nt_fs::SnapshotReserveLease;
/// fn duplicate<D, I>(lease: SnapshotReserveLease<'_, D, I>) { let _ = lease.clone(); }
/// ```
#[must_use = "retain the reserve lease until exclusive storage access is no longer required"]
pub struct SnapshotReserveLease<'a, D, I> {
    reserve: &'a SnapshotReserve<D, I>,
    // In particular, a shared lease cannot expose &D concurrently when D is Send but not Sync.
    exclusive: PhantomData<&'a mut D>,
}

impl<D, I> SnapshotReserveLease<'_, D, I> {
    pub fn identity(&self) -> &I {
        &self.reserve.identity
    }
    pub fn store(&self) -> SnapshotBlockStore {
        self.reserve.store
    }

    fn device(&self) -> &D {
        // A lease is only constructed after acquiring the gate, and cannot be cloned.
        unsafe { &*self.reserve.device.get() }
    }
    fn device_mut(&mut self) -> &mut D {
        unsafe { &mut *self.reserve.device.get() }
    }
}

impl<D: SnapshotBlockDevice, I> SnapshotBlockDevice for SnapshotReserveLease<'_, D, I> {
    fn sector_size(&self) -> usize {
        self.device().sector_size()
    }
    fn sector_count(&self) -> u64 {
        self.device().sector_count()
    }
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        self.device_mut().read_sector(lba, out)
    }
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.device_mut().write_sector(lba, data)
    }
    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.device_mut().write_sectors(lba, data)
    }
    fn flush(&mut self) -> Result<(), SnapshotBlockStoreError> {
        self.device_mut().flush()
    }
}

impl<D, I> Drop for SnapshotReserveLease<'_, D, I> {
    fn drop(&mut self) {
        self.reserve.held.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
