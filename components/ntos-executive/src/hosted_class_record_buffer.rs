//! Preallocated class-domain storage for one bounded ClassService record batch.
//!
//! Root stages bytes before class dispatch into the class driver's own pool mapping. A retained
//! exact-generation pin prevents every generic free of this allocation while callbacks execute.
//! The source port pointer is never exposed to class code. One buffer is occupied by at most one
//! callback until its real terminal acknowledgement; uncertainty keeps it quarantined.

use super::*;

#[must_use = "retain class-domain bytes through callback ACK and exact physical retirement"]
pub(super) struct ClassRecordBuffer {
    instance_index: usize,
    domain: HostedDomainIdentity,
    pool_exec_va: u64,
    pool_frame_base: u64,
    pml4: u64,
    pin: hosted_device_allocations::TemporaryPoolPin,
    occupied: bool,
    uncertain: bool,
    retired: bool,
    length: usize,
}

impl ClassRecordBuffer {
    /// Allocate the full 24 KiB contract before admitting an IRQ callback. The component never
    /// allocates on the callback path; root reserves pool storage while the class instance is
    /// live, then immediately publishes a free-interlocked generation-bound pin.
    pub(super) unsafe fn preallocate(instance_index: usize) -> Result<Self, nt_status::NtStatus> {
        let inst = instance(instance_index).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        let domain =
            instance_domain_identity(inst).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        let capacity = hosted_class_callback_lane::MAX_RECORD_BYTES as u64;
        let address = hosted_instance_pool_alloc(inst, capacity)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        let pin = match hosted_device_allocations::pin_temporary_pool_range(inst, address, capacity)
        {
            Ok(pin) => pin,
            Err(status) => {
                if !free_hosted_instance_pool_allocation_exact(inst, address) {
                    crate::provider_bugcheck::report(
                        0xc4,
                        [
                            0x434c4153,
                            instance_index as u64,
                            address,
                            status.raw() as u32 as u64,
                        ],
                    );
                }
                return Err(status);
            }
        };
        if pin.allocation().component_address != address || pin.allocation().capacity < capacity {
            let mut pin = pin;
            if hosted_device_allocations::retire_owned_temporary_pool_allocation(&mut pin).is_err()
            {
                crate::provider_bugcheck::report(
                    0xc4,
                    [0x434c4153, instance_index as u64, address, 1],
                );
            }
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        Ok(Self {
            instance_index,
            domain,
            pool_exec_va: inst.exec_pool_va,
            pool_frame_base: inst.pool_frame_base,
            pml4: inst.pml4,
            pin,
            occupied: false,
            uncertain: false,
            retired: false,
            length: 0,
        })
    }

    fn generation_live(&self) -> bool {
        instance(self.instance_index).is_some_and(|inst| {
            instance_domain_identity(inst) == Some(self.domain)
                && inst.exec_pool_va == self.pool_exec_va
                && inst.pool_frame_base == self.pool_frame_base
                && inst.pml4 == self.pml4
        })
    }

    pub(super) fn domain(&self) -> HostedDomainIdentity {
        self.domain
    }

    /// Copy the already-authenticated record bytes into class-domain storage. The exact physical
    /// generation is rechecked under the allocator lock for each stage. Any ambiguous write
    /// keeps the allocation pinned and unavailable for another callback.
    pub(super) unsafe fn stage(&mut self, bytes: &[u8]) -> Result<(u64, u64), nt_status::NtStatus> {
        if self.retired || self.uncertain || self.occupied || !self.generation_live() {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        if bytes.is_empty() || bytes.len() > hosted_class_callback_lane::MAX_RECORD_BYTES {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        let start = self.pin.allocation().component_address;
        let end = start
            .checked_add(bytes.len() as u64)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        self.occupied = true;
        if let Err(status) =
            hosted_device_allocations::write_temporary_pool_pin(&self.pin, 0, bytes)
        {
            if hosted_device_allocations::temporary_pool_pin_uncertain(&self.pin) {
                self.retain_uncertain();
            } else {
                self.occupied = false;
            }
            return Err(status);
        }
        self.length = bytes.len();
        Ok((start, end))
    }

    /// Invoke only after the class callback's output copyback, source continuation, and Reply
    /// acknowledgement have all completed. This method does not itself prove those events.
    pub(super) fn acknowledge_callback(&mut self) -> Result<(), nt_status::NtStatus> {
        if !self.occupied || self.uncertain || self.retired || !self.generation_live() {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        self.occupied = false;
        self.length = 0;
        Ok(())
    }

    /// A lost dispatch or copyback leaves the original allocation excluded from reuse.
    pub(super) fn retain_uncertain(&mut self) {
        self.uncertain = true;
        let _ = hosted_device_allocations::retain_temporary_pool_pin_uncertain(&self.pin);
    }

    /// Retire only while idle and after the final callback ACK. The physical free and pin
    /// retirement happen under one catalog→pool lock chain; no generic free can interleave.
    pub(super) unsafe fn retire(&mut self) -> Result<(), nt_status::NtStatus> {
        if self.retired || self.occupied || self.uncertain || !self.generation_live() {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        if let Err(status) =
            hosted_device_allocations::retire_owned_temporary_pool_allocation(&mut self.pin)
        {
            self.uncertain = hosted_device_allocations::temporary_pool_pin_uncertain(&self.pin);
            return Err(status);
        }
        self.retired = true;
        Ok(())
    }
}
