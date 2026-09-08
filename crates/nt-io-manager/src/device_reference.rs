//! Explicit ownership of canonical Device records, independent of hosted pointer mappings.
//!
//! A projection owner acquires a reference before publication and releases it only after its native
//! pointer consumers and mappings have retired. Domain unbinding does not consume this reference.
//! Releasing through the wrong manager, stale device, or already-released token changes no counts.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_status::NtStatus;

use crate::{DeviceId, DriverId, DriverUnloadState, HostedDomainIdentity, IoManager};

static NEXT_MANAGER_IDENTITY: AtomicU64 = AtomicU64::new(1);

/// Counted strong references to one exact canonical Device record. This is not an Object Manager handle or
/// a WDM address. Dropping it does not release the reference: the owner must perform checked release
/// through the originating I/O Manager, retaining this token when teardown cannot complete.
///
/// ```compile_fail
/// use nt_io_manager::DeviceReference;
/// fn duplicate(reference: DeviceReference) {
///     let second = reference;
///     let _ = reference.is_held();
/// }
/// ```
#[derive(Debug)]
#[must_use = "retain the device reference until checked release succeeds"]
pub struct DeviceReference {
    manager_identity: u64,
    device: DeviceId,
    count: u64,
}

impl DeviceReference {
    pub const fn device_id(&self) -> DeviceId {
        self.device
    }

    pub const fn is_held(&self) -> bool {
        self.count != 0
    }

    pub const fn count(&self) -> u64 {
        self.count
    }
}

struct DeviceReferenceCount {
    device: DeviceId,
    driver: DriverId,
    count: u64,
}

#[derive(Default)]
pub(crate) struct DeviceReferenceStore {
    manager_identity: u64,
    counts: Vec<DeviceReferenceCount>,
}

fn allocate_manager_identity(counter: &AtomicU64) -> Result<u64, NtStatus> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            if next == 0 {
                None
            } else {
                next.checked_add(1)
            }
        })
        .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)
}

impl<P> IoManager<P> {
    pub(crate) fn ownership_identity(&self) -> u64 {
        self.device_references.manager_identity
    }

    pub(crate) fn ensure_ownership_identity(&mut self) -> Result<u64, NtStatus> {
        if self.device_references.manager_identity == 0 {
            self.device_references.manager_identity =
                allocate_manager_identity(&NEXT_MANAGER_IDENTITY)?;
        }
        Ok(self.device_references.manager_identity)
    }

    /// Retain the canonical device independently of any hosted address binding. A pending delete or
    /// driver unload denies new acquisition, while existing references remain releasable.
    pub fn retain_device_reference(
        &mut self,
        device: DeviceId,
    ) -> Result<DeviceReference, NtStatus> {
        let record = self.device(device).ok_or(NtStatus::INVALID_PARAMETER)?;
        if record.delete_pending {
            return Err(NtStatus::DELETE_PENDING);
        }
        let driver = record.driver_id;
        if self
            .driver(driver)
            .is_none_or(|driver| driver.unload_state != DriverUnloadState::Loaded)
        {
            return Err(NtStatus::DELETE_PENDING);
        }
        let store = &mut self.device_references;
        if let Some(entry) = store.counts.iter_mut().find(|entry| entry.device == device) {
            if entry.driver != driver {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let count = entry
                .count
                .checked_add(1)
                .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
            entry.count = count;
        } else {
            store
                .counts
                .try_reserve(1)
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            if store.manager_identity == 0 {
                store.manager_identity = allocate_manager_identity(&NEXT_MANAGER_IDENTITY)?;
            }
            store.counts.push(DeviceReferenceCount {
                device,
                driver,
                count: 1,
            });
        }
        Ok(DeviceReference {
            manager_identity: store.manager_identity,
            device,
            count: 1,
        })
    }

    /// Authenticate both parts of the hosted domain identity and its pointer binding before taking
    /// a canonical reference. This does not turn the binding itself into a lifetime claim.
    pub fn retain_hosted_device_reference(
        &mut self,
        identity: HostedDomainIdentity,
        address: u64,
    ) -> Result<DeviceReference, NtStatus> {
        let device = self
            .hosted_device_by_identity(identity, address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        self.retain_device_reference(device)
    }

    fn device_reference_index(&self, reference: &DeviceReference) -> Result<usize, NtStatus> {
        if reference.count == 0
            || reference.manager_identity == 0
            || reference.manager_identity != self.ownership_identity()
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let device = self
            .device(reference.device)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        self.device_references
            .counts
            .iter()
            .position(|entry| {
                entry.device == reference.device
                    && entry.driver == device.driver_id
                    && entry.count >= reference.count
            })
            .ok_or(NtStatus::INVALID_PARAMETER)
    }

    /// Add one reference through existing ownership, even after delete or unload was requested.
    /// Unlike a fresh lookup, this cannot resurrect a dead device and requires no allocation.
    pub fn retain_device_reference_owned(
        &mut self,
        reference: &mut DeviceReference,
    ) -> Result<(), NtStatus> {
        let index = self.device_reference_index(reference)?;
        let owned = reference
            .count
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        let canonical = self.device_references.counts[index]
            .count
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.device_references.counts[index].count = canonical;
        reference.count = owned;
        Ok(())
    }

    /// Release one owned reference. The token remains live until its last reference is released.
    pub fn release_device_reference_one(
        &mut self,
        reference: &mut DeviceReference,
    ) -> Result<(), NtStatus> {
        self.release_device_reference_count(reference, 1)
    }

    /// Transfer one already-counted reference into a distinct non-clone owner. No allocation or
    /// canonical count change occurs; splitting the last reference leaves the source empty.
    pub fn split_device_reference_one(
        &self,
        reference: &mut DeviceReference,
    ) -> Result<DeviceReference, NtStatus> {
        self.device_reference_index(reference)?;
        reference.count -= 1;
        Ok(DeviceReference {
            manager_identity: reference.manager_identity,
            device: reference.device,
            count: 1,
        })
    }

    /// Move all source references into another live owner of the exact same device. Failure leaves
    /// both owners unchanged. The canonical count is unchanged, and the source becomes empty.
    pub fn merge_device_references(
        &self,
        target: &mut DeviceReference,
        source: &mut DeviceReference,
    ) -> Result<(), NtStatus> {
        let target_index = self.device_reference_index(target)?;
        let source_index = self.device_reference_index(source)?;
        if target_index != source_index {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let count = target
            .count
            .checked_add(source.count)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        if count > self.device_references.counts[target_index].count {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        target.count = count;
        source.count = 0;
        Ok(())
    }

    /// Release all references owned by this token, only through the originating manager. Failure
    /// preserves ownership for retry. No hosted domain lookup is needed after its owner unbinds.
    pub fn release_device_reference(
        &mut self,
        reference: &mut DeviceReference,
    ) -> Result<(), NtStatus> {
        let count = reference.count;
        self.release_device_reference_count(reference, count)
    }

    fn release_device_reference_count(
        &mut self,
        reference: &mut DeviceReference,
        count: u64,
    ) -> Result<(), NtStatus> {
        let index = self.device_reference_index(reference)?;
        let owned = reference
            .count
            .checked_sub(count)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let store = &mut self.device_references;
        let remaining = store.counts[index]
            .count
            .checked_sub(count)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if remaining == 0 {
            store.counts.swap_remove(index);
        } else {
            store.counts[index].count = remaining;
        }
        reference.count = owned;
        Ok(())
    }

    pub fn device_reference_count(&self, device: DeviceId) -> u64 {
        self.device_references
            .counts
            .iter()
            .find(|entry| entry.device == device)
            .map_or(0, |entry| entry.count)
    }

    pub(crate) fn driver_has_device_references(&self, driver: DriverId) -> bool {
        self.device_references
            .counts
            .iter()
            .any(|entry| entry.driver == driver && entry.count != 0)
    }
}

#[cfg(test)]
mod tests;
