//! Counted caller references to an admitted hosted DEVICE_OBJECT projection.
//!
//! The canonical hosted binding remains the address authority. A registration adds one lifetime
//! anchor before native publication; caller references are separate and can be transferred without
//! changing canonical counts. Native adapters must drain and unregister before unbinding/freeing.

use crate::{DeviceId, DeviceReference, HostedDomainIdentity, IoManager};
use alloc::vec::Vec;
use nt_status::NtStatus;

/// An exact registration observation, not an additional owned pointer reference.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HostedDevicePointerRegistration {
    manager: u64,
    sequence: u64,
    domain: HostedDomainIdentity,
    address: u64,
    device: DeviceId,
}

impl HostedDevicePointerRegistration {
    pub const fn domain(self) -> HostedDomainIdentity {
        self.domain
    }
    pub const fn address(self) -> u64 {
        self.address
    }
    pub const fn device_id(self) -> DeviceId {
        self.device
    }
}

/// One returned object reference. Failed adoption or release leaves this owner intact.
#[derive(Debug)]
#[must_use = "adopt or explicitly release the returned device reference"]
pub struct HostedDevicePointerReference {
    reference: DeviceReference,
}

impl HostedDevicePointerReference {
    pub fn device_id(&self) -> DeviceId {
        self.reference.device_id()
    }
    pub fn is_held(&self) -> bool {
        self.reference.is_held()
    }
    pub fn release<P>(&mut self, io: &mut IoManager<P>) -> Result<(), NtStatus> {
        io.release_device_reference(&mut self.reference)
    }
}

struct Row {
    registration: HostedDevicePointerRegistration,
    anchor: DeviceReference,
    callers: Option<DeviceReference>,
}

#[derive(Default)]
pub(crate) struct HostedDevicePointerStore {
    sequence: u64,
    rows: Vec<Row>,
}

impl HostedDevicePointerStore {
    pub(crate) fn retains_domain(&self, domain: HostedDomainIdentity) -> bool {
        self.rows
            .iter()
            .any(|row| row.registration.domain == domain)
    }
    pub(crate) fn retains_address(&self, domain: HostedDomainIdentity, address: u64) -> bool {
        self.rows
            .iter()
            .any(|row| row.registration.domain == domain && row.registration.address == address)
    }
}

impl<P> IoManager<P> {
    /// Admit before publishing a native projection. Repeating the exact live registration is
    /// idempotent, while the canonical anchor survives zero outstanding caller references.
    pub fn register_hosted_device_pointer(
        &mut self,
        domain: HostedDomainIdentity,
        address: u64,
    ) -> Result<HostedDevicePointerRegistration, NtStatus> {
        let device = self
            .hosted_device_by_identity(domain, address)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if let Some(row) =
            self.hosted_device_pointers.rows.iter().find(|row| {
                row.registration.domain == domain && row.registration.address == address
            })
        {
            return if row.registration.device == device {
                Ok(row.registration)
            } else {
                Err(NtStatus::INVALID_PARAMETER)
            };
        }
        let sequence = self
            .hosted_device_pointers
            .sequence
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.hosted_device_pointers
            .rows
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let anchor = self.retain_device_reference(device)?;
        let registration = HostedDevicePointerRegistration {
            manager: self.ownership_identity(),
            sequence,
            domain,
            address,
            device,
        };
        self.hosted_device_pointers.rows.push(Row {
            registration,
            anchor,
            callers: None,
        });
        self.hosted_device_pointers.sequence = sequence;
        Ok(registration)
    }

    fn pointer_row_index(
        &self,
        registration: HostedDevicePointerRegistration,
    ) -> Result<usize, NtStatus> {
        if registration.manager == 0 || registration.manager != self.ownership_identity() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.hosted_device_pointers
            .rows
            .iter()
            .position(|row| row.registration == registration)
            .ok_or(NtStatus::INVALID_PARAMETER)
    }

    fn live_pointer_row_index(
        &self,
        registration: HostedDevicePointerRegistration,
    ) -> Result<usize, NtStatus> {
        let index = self.pointer_row_index(registration)?;
        if self.hosted_device_by_identity(registration.domain, registration.address)
            != Some(registration.device)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(index)
    }

    // No external callbacks run while the row is outside its Vec; push cannot allocate after remove.
    fn update_pointer_row<T>(
        &mut self,
        index: usize,
        update: impl FnOnce(&mut Self, &mut Row) -> Result<T, NtStatus>,
    ) -> Result<T, NtStatus> {
        let mut row = self.hosted_device_pointers.rows.swap_remove(index);
        let result = update(self, &mut row);
        self.hosted_device_pointers.rows.push(row);
        result
    }

    pub fn hosted_device_pointer_count(
        &self,
        registration: HostedDevicePointerRegistration,
    ) -> Result<u64, NtStatus> {
        let index = self.pointer_row_index(registration)?;
        Ok(self.hosted_device_pointers.rows[index]
            .callers
            .as_ref()
            .map_or(0, DeviceReference::count))
    }

    /// Retain one existing projected pointer without allocation after registration admission.
    pub fn reference_hosted_device_pointer(
        &mut self,
        registration: HostedDevicePointerRegistration,
    ) -> Result<u64, NtStatus> {
        let index = self.live_pointer_row_index(registration)?;
        self.update_pointer_row(index, |io, row| {
            if let Some(callers) = row.callers.as_mut() {
                io.retain_device_reference_owned(callers)?;
            } else {
                io.retain_device_reference_owned(&mut row.anchor)?;
                // The exact held anchor now has two references; splitting cannot allocate.
                let caller = io
                    .split_device_reference_one(&mut row.anchor)
                    .expect("validated registration anchor must split after retain");
                row.callers = Some(caller);
            }
            Ok(row.callers.as_ref().unwrap().count())
        })
    }

    pub fn dereference_hosted_device_pointer(
        &mut self,
        registration: HostedDevicePointerRegistration,
    ) -> Result<u64, NtStatus> {
        let index = self.pointer_row_index(registration)?;
        self.update_pointer_row(index, |io, row| {
            let callers = row.callers.as_mut().ok_or(NtStatus::INVALID_PARAMETER)?;
            io.release_device_reference_one(callers)?;
            let remaining = callers.count();
            if remaining == 0 {
                row.callers = None;
            }
            Ok(remaining)
        })
    }

    /// Detach exactly one already-owned caller reference for result publication or rollback.
    pub fn take_hosted_device_pointer_reference(
        &mut self,
        registration: HostedDevicePointerRegistration,
    ) -> Result<HostedDevicePointerReference, NtStatus> {
        let index = self.live_pointer_row_index(registration)?;
        self.update_pointer_row(index, |io, row| {
            let callers = row.callers.as_mut().ok_or(NtStatus::INVALID_PARAMETER)?;
            let reference = io.split_device_reference_one(callers)?;
            if !callers.is_held() {
                row.callers = None;
            }
            Ok(HostedDevicePointerReference { reference })
        })
    }

    /// Adopt an existing returned reference into an exact same-device destination projection.
    /// The source owner remains held on every error; no extra canonical reference is manufactured.
    pub fn adopt_hosted_device_pointer_reference(
        &mut self,
        registration: HostedDevicePointerRegistration,
        owner: &mut HostedDevicePointerReference,
    ) -> Result<u64, NtStatus> {
        let index = self.live_pointer_row_index(registration)?;
        if !owner.is_held()
            || owner.reference.count() != 1
            || owner.device_id() != registration.device
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.update_pointer_row(index, |io, row| {
            if let Some(callers) = row.callers.as_mut() {
                io.merge_device_references(callers, &mut owner.reference)?;
            } else {
                io.merge_device_references(&mut row.anchor, &mut owner.reference)?;
                row.callers = Some(
                    io.split_device_reference_one(&mut row.anchor)
                        .expect("validated registration anchor must split after adoption"),
                );
            }
            Ok(row.callers.as_ref().unwrap().count())
        })
    }

    /// Retire only the registration anchor after every local caller reference has been drained.
    /// Detached result owners remain independent and continue protecting the canonical device.
    pub fn unregister_hosted_device_pointer(
        &mut self,
        registration: HostedDevicePointerRegistration,
    ) -> Result<(), NtStatus> {
        let index = self.pointer_row_index(registration)?;
        if self.hosted_device_pointers.rows[index].callers.is_some() {
            return Err(NtStatus::DEVICE_BUSY);
        }
        self.update_pointer_row(index, |io, row| {
            io.release_device_reference(&mut row.anchor)
        })?;
        let index = self.pointer_row_index(registration)?;
        self.hosted_device_pointers.rows.swap_remove(index);
        Ok(())
    }
}

#[cfg(test)]
#[path = "hosted_device_pointer/tests.rs"]
mod tests;
