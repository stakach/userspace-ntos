//! Source-domain ownership for an upper FDO's forwarded START packet.

use super::hosted_device_allocations::TemporaryPoolPin;
use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, source_irp_ledger::SourceIrpAllocation,
    HostedDomainIdentity,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

const MAX_LIST_BYTES: usize = 64 * 1024;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSource,
    InvalidTarget,
    InvalidResources,
    InsufficientResources,
}

#[must_use = "retain the source and both resource allocations through source completion"]
pub(super) struct CapturedStartFdo {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    ticket: SourceIrpTicket,
    canonical_source_irp: IrpId,
    upper_device_id: nt_io_manager::DeviceId,
    upper_address: u64,
    target_address: u64,
    stack_address: u64,
    raw_address: u64,
    translated_address: u64,
    raw_hash: u64,
    translated_hash: u64,
    raw: Option<Vec<u8>>,
    translated: Option<Vec<u8>>,
    raw_len: usize,
    translated_len: usize,
    raw_pin: Option<TemporaryPoolPin>,
    translated_pin: Option<TemporaryPoolPin>,
    pinned: bool,
}

impl CapturedStartFdo {
    pub(super) const fn source_irp_address(&self) -> u64 {
        self.allocation.component_address
    }
    pub(super) const fn source_ticket(&self) -> SourceIrpTicket {
        self.ticket
    }
    pub(super) const fn source_allocation(&self) -> SourceIrpAllocation {
        self.allocation
    }
    pub(super) const fn source_domain(&self) -> HostedDomainIdentity {
        self.allocation.domain
    }
    pub(super) const fn target_device_address(&self) -> u64 {
        self.target_address
    }
    pub(super) const fn upper_device_address(&self) -> u64 {
        self.upper_address
    }

    fn valid_pin(pin: &Option<TemporaryPoolPin>, address: u64, length: usize) -> bool {
        if length == 0 {
            return address == 0 && pin.is_none();
        }
        pin.as_ref().is_some_and(|pin| {
            !hosted_device_allocations::temporary_pool_pin_uncertain(pin)
                && pin.allocation().component_address <= address
                && address.checked_add(length as u64).is_some_and(|end| {
                    end <= pin
                        .allocation()
                        .component_address
                        .saturating_add(pin.allocation().capacity)
                })
        })
    }

    pub(super) fn validate_pin(&self) -> Result<(), CaptureError> {
        if self.pinned
            && hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.ticket)
            && Self::valid_pin(&self.raw_pin, self.raw_address, self.raw_len)
            && Self::valid_pin(
                &self.translated_pin,
                self.translated_address,
                self.translated_len,
            )
        {
            Ok(())
        } else {
            Err(CaptureError::InvalidSource)
        }
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
        let stack_address = forwarded_stack_address(self.allocation, &irp)?;
        let current = memory
            .read_value::<IoStackLocation>(irp.current_stack_location.0)
            .ok_or(CaptureError::InvalidSource)?;
        let stack = memory
            .read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSource)?;
        if stack_address != self.stack_address
            || current.major_function != major::IRP_MJ_PNP
            || current.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE
            || current.device_object.0 != self.upper_address
            || current.file_object.0 != 0
            || current.parameters[0] != self.raw_address
            || current.parameters[1] != self.translated_address
            || stack.major_function != major::IRP_MJ_PNP
            || stack.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE
            || stack.device_object.0 != self.target_address
            || stack.file_object.0 != 0
            || stack.parameters[0] != self.raw_address
            || stack.parameters[1] != self.translated_address
            || resource_hash(&memory, self.raw_address, self.raw_len)? != self.raw_hash
            || resource_hash(&memory, self.translated_address, self.translated_len)?
                != self.translated_hash
            || io_manager_mut()
                .hosted_device_by_identity(self.allocation.domain, self.upper_address)
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

    pub(super) fn take_lists(&mut self) -> Result<(Vec<u8>, Vec<u8>), CaptureError> {
        self.validate_source()?;
        let raw = self.raw.take().ok_or(CaptureError::InvalidResources)?;
        let translated = self
            .translated
            .take()
            .ok_or(CaptureError::InvalidResources)?;
        Ok((raw, translated))
    }

    pub(super) fn publish_terminal(
        &self,
        status: nt_status::NtStatus,
        information: u64,
    ) -> Result<(), CaptureError> {
        if information != 0 {
            return Err(CaptureError::InvalidSource);
        }
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

    pub(super) fn caller_terminal_ready(&self) -> bool {
        self.validate_pin().is_ok()
            && hosted_source_irp_ledger::caller_terminal_ready(self.ticket, self.allocation)
    }

    fn release_pins(&mut self) -> Result<(), CaptureError> {
        if let Some(pin) = self.raw_pin.as_mut() {
            unsafe { hosted_device_allocations::release_temporary_pool_pin(pin) }
                .map_err(|_| CaptureError::InvalidSource)?;
            self.raw_pin = None;
        }
        if let Some(pin) = self.translated_pin.as_mut() {
            unsafe { hosted_device_allocations::release_temporary_pool_pin(pin) }
                .map_err(|_| CaptureError::InvalidSource)?;
            self.translated_pin = None;
        }
        Ok(())
    }

    pub(super) fn release_unentered(&mut self) -> Result<(), CaptureError> {
        self.release_pins()?;
        if !self.pinned || !hosted_source_irp_ledger::unpin(self.ticket) {
            return Err(CaptureError::InvalidSource);
        }
        self.pinned = false;
        Ok(())
    }

    pub(super) fn release_terminal(&mut self) -> Result<(), CaptureError> {
        self.release_pins()?;
        if !self.pinned
            || !hosted_source_irp_ledger::release_pending_terminal(self.ticket, self.allocation)
        {
            return Err(CaptureError::InvalidSource);
        }
        self.pinned = false;
        Ok(())
    }
}

fn forwarded_stack_address(
    allocation: SourceIrpAllocation,
    irp: &Irp,
) -> Result<u64, CaptureError> {
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
    let current = allocation
        .component_address
        .checked_add(WDM_X64_IRP_SIZE as u64)
        .and_then(|base| {
            base.checked_add(
                (location as u64 - 1).checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)?,
            )
        })
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
    let (mut low, mut high) = (1usize, MAX_LIST_BYTES + 1);
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

fn copy_list(memory: &SourcePoolMemory, address: u64) -> Result<Vec<u8>, CaptureError> {
    let capacity = allocation_prefix(memory, address).ok_or(CaptureError::InvalidResources)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| CaptureError::InsufficientResources)?;
    bytes.resize(capacity, 0);
    if !memory.read(address, &mut bytes) {
        return Err(CaptureError::InvalidResources);
    }
    let extent = nt_cm_resources::validate_cm_resource_list_extent(&bytes)
        .map_err(|_| CaptureError::InvalidResources)?;
    bytes.truncate(extent);
    Ok(bytes)
}

fn resource_hash(
    memory: &SourcePoolMemory,
    address: u64,
    length: usize,
) -> Result<u64, CaptureError> {
    if length == 0 {
        return (address == 0)
            .then_some(0xcbf2_9ce4_8422_2325)
            .ok_or(CaptureError::InvalidResources);
    }
    if address == 0 || !memory.contains(address, length) {
        return Err(CaptureError::InvalidResources);
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut offset = 0usize;
    let mut chunk = [0u8; 256];
    while offset < length {
        let count = (length - offset).min(chunk.len());
        let at = address
            .checked_add(offset as u64)
            .ok_or(CaptureError::InvalidResources)?;
        if !memory.read(at, &mut chunk[..count]) {
            return Err(CaptureError::InvalidResources);
        }
        for &byte in &chunk[..count] {
            hash ^= u64::from(byte);
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
    target_address: u64,
    canonical_source_irp: IrpId,
) -> Result<CapturedStartFdo, CaptureError> {
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
            .ok_or_else(|| {
                CaptureError::InvalidSource
            })?;
        if io_manager_mut()
            .hosted_device_by_identity(domain, target_address)
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
        let stack_address = forwarded_stack_address(allocation, &irp).map_err(|error| {
            error
        })?;
        let stack = memory
            .read_value::<IoStackLocation>(stack_address)
            .ok_or_else(|| {
                CaptureError::InvalidSource
            })?;
        let current = memory
            .read_value::<IoStackLocation>(irp.current_stack_location.0)
            .ok_or_else(|| {
                CaptureError::InvalidSource
            })?;
        let upper_address = current.device_object.0;
        let raw_address = stack.parameters[0];
        let translated_address = stack.parameters[1];
        let mismatch = u64::from(current.major_function != major::IRP_MJ_PNP)
            | (u64::from(current.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE) << 1)
            | (u64::from(upper_address == 0) << 2)
            | (u64::from(current.file_object.0 != 0) << 3)
            | (u64::from(
                current.parameters[0] != raw_address || current.parameters[1] != translated_address,
            ) << 4)
            | (u64::from(stack.major_function != major::IRP_MJ_PNP) << 5)
            | (u64::from(stack.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE) << 6)
            | (u64::from(stack.device_object.0 != target_address) << 7)
            | (u64::from(stack.file_object.0 != 0) << 8)
            | (u64::from(
                io_manager_mut().hosted_device_by_identity(domain, upper_address)
                    != Some(upper_device_id),
            ) << 9)
            | (u64::from((raw_address == 0) != (translated_address == 0)) << 10);
        if mismatch != 0 {
            return Err(CaptureError::InvalidSource);
        }
        // SourcePoolMemory holds the pool lock. Pool pins take that same lock, so
        // release it before acquiring either allocation's free-exclusion pin.
        drop(memory);
        let mut raw_pin = if raw_address == 0 {
            None
        } else {
            Some(
                hosted_device_allocations::pin_temporary_pool_range(inst, raw_address, 1)
                    .map_err(|_| CaptureError::InvalidResources)?,
            )
        };
        let mut translated_pin = if translated_address == 0 {
            None
        } else {
            match hosted_device_allocations::pin_temporary_pool_range(inst, translated_address, 1) {
                Ok(pin) => Some(pin),
                Err(_) => {
                    if let Some(pin) = raw_pin.as_mut() {
                        hosted_device_allocations::release_temporary_pool_pin(pin)
                            .expect("new START raw pin rollback");
                    }
                    return Err(CaptureError::InvalidResources);
                }
            }
        };
        let copied = (|| {
            let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
            let observed_irp = memory
                .read_value::<Irp>(source_irp_address)
                .ok_or(CaptureError::InvalidSource)?;
            let observed_stack_address = forwarded_stack_address(allocation, &observed_irp)?;
            let observed_current = memory
                .read_value::<IoStackLocation>(observed_irp.current_stack_location.0)
                .ok_or(CaptureError::InvalidSource)?;
            let observed_next = memory
                .read_value::<IoStackLocation>(observed_stack_address)
                .ok_or(CaptureError::InvalidSource)?;
            if observed_stack_address != stack_address
                || observed_current.major_function != major::IRP_MJ_PNP
                || observed_current.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE
                || observed_current.device_object.0 != upper_address
                || observed_current.file_object.0 != 0
                || observed_current.parameters[0] != raw_address
                || observed_current.parameters[1] != translated_address
                || observed_next.major_function != major::IRP_MJ_PNP
                || observed_next.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE
                || observed_next.device_object.0 != target_address
                || observed_next.file_object.0 != 0
                || observed_next.parameters[0] != raw_address
                || observed_next.parameters[1] != translated_address
            {
                return Err(CaptureError::InvalidSource);
            }
            let raw = if raw_address == 0 {
                Vec::new()
            } else {
                copy_list(&memory, raw_address)?
            };
            let translated = if translated_address == 0 {
                Vec::new()
            } else {
                copy_list(&memory, translated_address)?
            };
            let raw_hash = resource_hash(&memory, raw_address, raw.len())?;
            let translated_hash = resource_hash(&memory, translated_address, translated.len())?;
            Ok((raw, translated, raw_hash, translated_hash))
        })()
        .and_then(|(raw, translated, raw_hash, translated_hash)| {
            // The SourcePoolMemory lock is released before consulting pin state.
            if !CapturedStartFdo::valid_pin(&raw_pin, raw_address, raw.len())
                || !CapturedStartFdo::valid_pin(
                    &translated_pin,
                    translated_address,
                    translated.len(),
                )
            {
                return Err(CaptureError::InvalidResources);
            }
            Ok((raw, translated, raw_hash, translated_hash))
        });
        let (raw, translated, raw_hash, translated_hash) = match copied {
            Ok(value) => value,
            Err(error) => {
                if let Some(pin) = raw_pin.as_mut() {
                    hosted_device_allocations::release_temporary_pool_pin(pin)
                        .expect("new START raw pin rollback");
                }
                if let Some(pin) = translated_pin.as_mut() {
                    hosted_device_allocations::release_temporary_pool_pin(pin)
                        .expect("new START translated pin rollback");
                }
                return Err(error);
            }
        };
        Ok(CapturedStartFdo {
            instance_index,
            allocation,
            ticket,
            canonical_source_irp,
            upper_device_id,
            upper_address,
            target_address,
            stack_address,
            raw_address,
            translated_address,
            raw_hash,
            translated_hash,
            raw_len: raw.len(),
            translated_len: translated.len(),
            raw: Some(raw),
            translated: Some(translated),
            raw_pin,
            translated_pin,
            pinned: true,
        })
    })();
    if result.is_err() {
        assert!(
            hosted_source_irp_ledger::unpin(ticket),
            "unentered START source rollback"
        );
    }
    result
}
