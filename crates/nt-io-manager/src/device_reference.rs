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

/// A strong reference to one exact canonical Device record. This is not an Object Manager handle or
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
    held: bool,
}

impl DeviceReference {
    pub const fn device_id(&self) -> DeviceId {
        self.device
    }

    pub const fn is_held(&self) -> bool {
        self.held
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
            held: true,
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

    /// Release once, only through the exact originating manager. Failure leaves the held token and
    /// reference count intact for retry. No hosted domain lookup is needed after its owner unbinds.
    pub fn release_device_reference(
        &mut self,
        reference: &mut DeviceReference,
    ) -> Result<(), NtStatus> {
        if !reference.held
            || reference.manager_identity == 0
            || reference.manager_identity != self.device_references.manager_identity
            || self.device(reference.device).is_none()
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let store = &mut self.device_references;
        let index = store
            .counts
            .iter()
            .position(|entry| entry.device == reference.device)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let remaining = store.counts[index]
            .count
            .checked_sub(1)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if remaining == 0 {
            store.counts.swap_remove(index);
        } else {
            store.counts[index].count = remaining;
        }
        reference.held = false;
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
