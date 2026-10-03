//! Per-File leases on one exact consumer-domain Device projection allocation owner.

use crate::{FileId, HostedDevicePointerRegistration, IoManager};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_status::NtStatus;

static LAST_OWNER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
#[must_use = "release this File's shared Device allocation lease"]
pub struct ConsumerDeviceLease {
    owner: u64,
    registration: HostedDevicePointerRegistration,
    sequence: u64,
    file: FileId,
    held: bool,
}

impl ConsumerDeviceLease {
    pub fn registration(&self) -> HostedDevicePointerRegistration {
        self.registration
    }
    pub fn is_held(&self) -> bool {
        self.held
    }
}

pub struct ConsumerDeviceProjection {
    owner: u64,
    registration: HostedDevicePointerRegistration,
    sequence: u64,
    leases: Vec<(u64, FileId)>,
    retired: bool,
}

impl ConsumerDeviceProjection {
    pub fn new<P>(
        io: &IoManager<P>,
        registration: HostedDevicePointerRegistration,
    ) -> Result<Self, NtStatus> {
        if io.hosted_device_pointer_registration(registration.domain(), registration.address())
            != Some(registration)
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let owner = LAST_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?
            + 1;
        Ok(Self {
            owner,
            registration,
            sequence: 0,
            leases: Vec::new(),
            retired: false,
        })
    }

    pub fn acquire<P>(
        &mut self,
        io: &mut IoManager<P>,
        file: FileId,
    ) -> Result<ConsumerDeviceLease, NtStatus> {
        if self.retired {
            return Err(NtStatus::DELETE_PENDING);
        }
        if io.hosted_device_pointer_registration(
            self.registration.domain(),
            self.registration.address(),
        ) != Some(self.registration)
            || io
                .file(file)
                .is_none_or(|file| file.device_id != self.registration.device_id())
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        self.leases
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        io.reference_hosted_device_pointer(self.registration)?;
        self.leases.push((sequence, file));
        self.sequence = sequence;
        Ok(ConsumerDeviceLease {
            owner: self.owner,
            registration: self.registration,
            sequence,
            file,
            held: true,
        })
    }

    pub fn release<P>(
        &mut self,
        io: &mut IoManager<P>,
        lease: &mut ConsumerDeviceLease,
    ) -> Result<(), NtStatus> {
        if !lease.held
            || lease.owner != self.owner
            || lease.registration != self.registration
            || self.retired
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let index = self
            .leases
            .iter()
            .position(|entry| *entry == (lease.sequence, lease.file))
            .ok_or(NtStatus::INVALID_HANDLE)?;
        io.dereference_hosted_device_pointer(self.registration)?;
        self.leases.swap_remove(index);
        lease.held = false;
        Ok(())
    }

    pub fn lease_count(&self) -> usize {
        self.leases.len()
    }
    pub fn is_retired(&self) -> bool {
        self.retired
    }

    /// Canonical unregistration is local and acknowledged before native allocation retirement.
    pub fn begin_retirement<P>(&mut self, io: &mut IoManager<P>) -> Result<(), NtStatus> {
        if self.retired {
            return Err(NtStatus::DELETE_PENDING);
        }
        if !self.leases.is_empty() {
            return Err(NtStatus::DEVICE_BUSY);
        }
        io.retire_hosted_device_pointer(self.registration)?;
        self.retired = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "consumer_device_projection/tests.rs"]
mod tests;
