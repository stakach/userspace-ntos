//! Source-domain ownership for a class FDO's forwarded PnP FILTER request.

use super::hosted_device_allocations::TemporaryPoolPin;
use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, source_irp_ledger::SourceIrpAllocation,
    HostedDomainIdentity,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

const MAX_REQUIREMENTS_BYTES: usize = 64 * 1024;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSource,
    InvalidTarget,
    InvalidRequirements,
    InsufficientResources,
}

/// Owns the source allocation pin and an independent copy of the borrowed input list.
/// The pin cannot be released until the source completion routine has finished or the
/// source domain has stopped and its completion can no longer run.
#[must_use = "retain through source completion and exact provider ACK"]
pub(super) struct CapturedFilterFdo {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    ticket: SourceIrpTicket,
    canonical_source_irp: IrpId,
    upper_device_id: nt_io_manager::DeviceId,
    upper_device_address: u64,
    next_stack_address: u64,
    target_device_address: u64,
    input_address: u64,
    input_hash: u64,
    requirements: Vec<u8>,
    input_pin: Option<TemporaryPoolPin>,
    pinned: bool,
}

impl CapturedFilterFdo {
    pub(super) const fn source_irp_address(&self) -> u64 {
        self.allocation.component_address
    }

    pub(super) const fn source_ticket(&self) -> SourceIrpTicket {
        self.ticket
    }

    pub(super) const fn source_domain(&self) -> HostedDomainIdentity {
        self.allocation.domain
    }

    pub(super) const fn target_device_address(&self) -> u64 {
        self.target_device_address
    }

    pub(super) const fn upper_device_address(&self) -> u64 {
        self.upper_device_address
    }

    pub(super) fn validate_source(&self) -> Result<(), CaptureError> {
        self.validate_pin()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        if instance_domain_identity(inst) != Some(self.allocation.domain) {
            return Err(CaptureError::InvalidSource);
        }
        let memory = unsafe { SourcePoolMemory::new(inst) }.ok_or(CaptureError::InvalidSource)?;
        let irp = memory
            .read_value::<Irp>(self.source_irp_address())
            .ok_or(CaptureError::InvalidSource)?;
        let next_address = next_stack_address(self.allocation, &irp)?;
        let next = memory
            .read_value::<IoStackLocation>(next_address)
            .ok_or(CaptureError::InvalidSource)?;
        let input_hash = hash_bytes(&memory, self.input_address, self.requirements.len())?;
        drop(memory);
        if next_address != self.next_stack_address
            || next.major_function != major::IRP_MJ_PNP
            || next.minor_function != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
            || next.device_object.0 != self.upper_device_address
            || next.file_object.0 != 0
            || next.parameters[0] != self.input_address
            || input_hash != self.input_hash
            || io_manager_mut()
                .hosted_device_by_identity(self.allocation.domain, self.upper_device_address)
                != Some(self.upper_device_id)
            || io_manager_mut()
                .irp(self.canonical_source_irp)
                .and_then(|source| source.current_stack())
                .map(|stack| stack.device_id)
                != Some(self.upper_device_id)
        {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    pub(super) fn validate_pin(&self) -> Result<(), CaptureError> {
        if self.pinned
            && hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.ticket)
            && self.input_pin.as_ref().is_some_and(|pin| {
                !hosted_device_allocations::temporary_pool_pin_uncertain(pin)
                    && pin.allocation().component_address <= self.input_address
                    && self
                        .input_address
                        .checked_add(self.requirements.len() as u64)
                        .is_some_and(|end| {
                            end <= pin
                                .allocation()
                                .component_address
                                .saturating_add(pin.allocation().capacity)
                        })
            })
        {
            Ok(())
        } else {
            Err(CaptureError::InvalidSource)
        }
    }

    pub(super) fn caller_terminal_ready(&self) -> bool {
        self.validate_pin().is_ok()
            && hosted_source_irp_ledger::caller_terminal_ready(self.ticket, self.allocation)
    }

    pub(super) fn input_copy(&self) -> Result<Vec<u8>, CaptureError> {
        self.validate_source()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.requirements.len())
            .map_err(|_| CaptureError::InsufficientResources)?;
        bytes.extend_from_slice(&self.requirements);
        Ok(bytes)
    }

    pub(super) fn original_information(&self) -> u64 {
        self.input_address
    }

    pub(super) fn input_len(&self) -> usize {
        self.requirements.len()
    }

    /// The output pointer is source-domain owned. A successful changed list must first
    /// be copied into a separately owned source pool allocation by the worker.
    pub(super) fn publish_terminal(
        &self,
        status: nt_status::NtStatus,
        information: u64,
    ) -> Result<(), CaptureError> {
        self.validate_source()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        let memory = unsafe { SourcePoolMemory::new(inst) }.ok_or(CaptureError::InvalidSource)?;
        let status_address = self
            .source_irp_address()
            .checked_add(WDM_X64_IRP_IO_STATUS_STATUS_OFFSET)
            .ok_or(CaptureError::InvalidSource)?;
        let info_address = self
            .source_irp_address()
            .checked_add(WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET)
            .ok_or(CaptureError::InvalidSource)?;
        if !memory.write(status_address, &status.raw().to_le_bytes())
            || !memory.write(info_address, &information.to_le_bytes())
        {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    pub(super) fn release_unentered(&mut self) -> Result<(), CaptureError> {
        if let Some(pin) = self.input_pin.as_mut() {
            unsafe { hosted_device_allocations::release_temporary_pool_pin(pin) }
                .map_err(|_| CaptureError::InvalidSource)?;
            self.input_pin = None;
        }
        if !self.pinned || !hosted_source_irp_ledger::unpin(self.ticket) {
            return Err(CaptureError::InvalidSource);
        }
        self.pinned = false;
        Ok(())
    }

    pub(super) fn release_terminal(&mut self) -> Result<(), CaptureError> {
        if let Some(pin) = self.input_pin.as_mut() {
            unsafe { hosted_device_allocations::release_temporary_pool_pin(pin) }
                .map_err(|_| CaptureError::InvalidSource)?;
            self.input_pin = None;
        }
        if !self.pinned
            || !hosted_source_irp_ledger::release_pending_terminal(self.ticket, self.allocation)
        {
            return Err(CaptureError::InvalidSource);
        }
        self.pinned = false;
        Ok(())
    }
}

fn next_stack_address(allocation: SourceIrpAllocation, irp: &Irp) -> Result<u64, CaptureError> {
    if irp.type_ != WDM_X64_IO_TYPE_IRP as i16
        || irp.size as u64 != allocation.bytes
        || irp.stack_count != allocation.stack_count as i8
    {
        return Err(CaptureError::InvalidSource);
    }
    let location = u8::try_from(irp.current_location).map_err(|_| CaptureError::InvalidSource)?;
    if location < 2 || location > allocation.stack_count.saturating_add(1) {
        return Err(CaptureError::InvalidSource);
    }
    let stack_base = allocation
        .component_address
        .checked_add(WDM_X64_IRP_SIZE as u64)
        .ok_or(CaptureError::InvalidSource)?;
    let current = stack_base
        .checked_add(
            (location as u64 - 1)
                .checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
                .ok_or(CaptureError::InvalidSource)?,
        )
        .ok_or(CaptureError::InvalidSource)?;
    if irp.current_stack_location.0 != current {
        return Err(CaptureError::InvalidSource);
    }
    current
        .checked_sub(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
        .ok_or(CaptureError::InvalidSource)
}

fn allocation_prefix(memory: &SourcePoolMemory, address: u64) -> Option<usize> {
    if address == 0 || !memory.contains(address, 1) {
        return None;
    }
    let mut low = 1usize;
    let mut high = MAX_REQUIREMENTS_BYTES + 1;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if memory.contains(address, middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    Some(low)
}

fn hash_bytes(memory: &SourcePoolMemory, address: u64, length: usize) -> Result<u64, CaptureError> {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut offset = 0usize;
    let mut chunk = [0u8; 256];
    while offset < length {
        let count = (length - offset).min(chunk.len());
        let at = address
            .checked_add(offset as u64)
            .ok_or(CaptureError::InvalidRequirements)?;
        if !memory.read(at, &mut chunk[..count]) {
            return Err(CaptureError::InvalidRequirements);
        }
        for byte in &chunk[..count] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        offset += count;
    }
    Ok(hash)
}

pub(super) unsafe fn capture(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    source_irp_address: u64,
    target_device_address: u64,
    canonical_source_irp: IrpId,
) -> Result<CapturedFilterFdo, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(channel, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    let domain = instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (ticket, allocation) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address).ok_or_else(
            || {
                CaptureError::InvalidSource
            },
        )?;
    let result = (|| {
        let upper_device_id = io_manager_mut()
            .irp(canonical_source_irp)
            .and_then(|source| source.current_stack())
            .map(|stack| stack.device_id)
            .ok_or(CaptureError::InvalidSource)?;
        if io_manager_mut()
            .hosted_device_by_identity(domain, target_device_address)
            .is_none()
        {
            return Err(CaptureError::InvalidTarget);
        }
        let memory = SourcePoolMemory::new(inst).ok_or_else(|| {
            CaptureError::InvalidSource
        })?;
        let irp = memory
            .read_value::<Irp>(source_irp_address)
            .ok_or_else(|| {
                CaptureError::InvalidSource
            })?;
        let next_address = next_stack_address(allocation, &irp).map_err(|error| {
            error
        })?;
        let next = memory
            .read_value::<IoStackLocation>(next_address)
            .ok_or_else(|| {
                CaptureError::InvalidSource
            })?;
        let input = next.parameters[0];
        drop(memory);
        if next.major_function != major::IRP_MJ_PNP
            || next.minor_function != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
            || next.device_object.0 == 0
            || next.file_object.0 != 0
            || input == 0
            || irp.io_status.information != input
            || io_manager_mut().hosted_device_by_identity(domain, next.device_object.0)
                != Some(upper_device_id)
        {
            let mismatch = (u64::from(next.device_object.0 == 0) << 3)
                | (u64::from(next.major_function != major::IRP_MJ_PNP) << 4)
                | (u64::from(
                    next.minor_function != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
                ) << 5)
                | (u64::from(next.file_object.0 != 0) << 6)
                | (u64::from(input == 0) << 7)
                | (u64::from(irp.io_status.information != input) << 8)
                | (u64::from(
                    io_manager_mut().hosted_device_by_identity(domain, next.device_object.0)
                        != Some(upper_device_id),
                ) << 9);
            return Err(CaptureError::InvalidSource);
        }
        let mut input_pin = hosted_device_allocations::pin_temporary_pool_range(inst, input, 1)
            .map_err(|_| CaptureError::InvalidRequirements)?;
        let copied = (|| {
            let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
            let capacity =
                allocation_prefix(&memory, input).ok_or(CaptureError::InvalidRequirements)?;
            let mut requirements = Vec::new();
            requirements
                .try_reserve_exact(capacity)
                .map_err(|_| CaptureError::InsufficientResources)?;
            requirements.resize(capacity, 0);
            if !memory.read(input, &mut requirements) {
                return Err(CaptureError::InvalidRequirements);
            }
            let extent =
                nt_cm_resources::validate_io_resource_requirements_list_extent(&requirements)
                    .map_err(|_| CaptureError::InvalidRequirements)?;
            requirements.truncate(extent);
            let input_hash = hash_bytes(&memory, input, extent)?;
            Ok((requirements, input_hash))
        })();
        let (requirements, input_hash) = match copied {
            Ok(value) => value,
            Err(error) => {
                hosted_device_allocations::release_temporary_pool_pin(&mut input_pin)
                    .expect("new FILTER input pin rollback");
                return Err(error);
            }
        };
        if input
            .checked_add(requirements.len() as u64)
            .is_none_or(|end| {
                end > input_pin
                    .allocation()
                    .component_address
                    .saturating_add(input_pin.allocation().capacity)
            })
        {
            hosted_device_allocations::release_temporary_pool_pin(&mut input_pin)
                .expect("out-of-range FILTER input pin rollback");
            return Err(CaptureError::InvalidRequirements);
        }
        Ok(CapturedFilterFdo {
            instance_index,
            allocation,
            ticket,
            canonical_source_irp,
            upper_device_id,
            upper_device_address: next.device_object.0,
            next_stack_address: next_address,
            target_device_address,
            input_address: input,
            input_hash,
            requirements,
            input_pin: Some(input_pin),
            pinned: true,
        })
    })();
    if result.is_err() {
        assert!(
            hosted_source_irp_ledger::unpin(ticket),
            "unentered FILTER source rollback"
        );
    }
    result
}
