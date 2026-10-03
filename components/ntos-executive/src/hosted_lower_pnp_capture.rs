//! Source-domain capture for one hosted lower-edge `IRP_MN_START_DEVICE` forward.

use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, source_irp_ledger::SourceIrpAllocation,
    HostedDomainIdentity, StackFlags,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

const MAX_RESOURCE_LIST_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSourceIrp,
    InvalidTarget,
    InvalidResources,
    InsufficientResources,
}

#[must_use = "retain until the local lower-edge completion has run"]
pub(super) struct CapturedLowerPnpStart {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    source: SourceIrpTicket,
    source_stack_address: u64,
    target_device_address: u64,
    stack_flags: StackFlags,
    raw_address: u64,
    translated_address: u64,
    raw_len: u32,
    translated_len: u32,
    raw_hash: u64,
    translated_hash: u64,
    payload: Option<Vec<u8>>,
    pinned: bool,
}

impl CapturedLowerPnpStart {
    pub(super) const fn source_irp_address(&self) -> u64 {
        self.allocation.component_address
    }

    pub(super) const fn source_ticket(&self) -> SourceIrpTicket {
        self.source
    }

    pub(super) const fn consumer_domain(&self) -> HostedDomainIdentity {
        self.allocation.domain
    }

    pub(super) const fn target_device_address(&self) -> u64 {
        self.target_device_address
    }

    pub(super) fn validate_source(&self) -> Result<(), CaptureError> {
        if !self.pinned
            || !hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.source)
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        if instance_domain_identity(inst) != Some(self.allocation.domain) {
            return Err(CaptureError::InvalidSourceIrp);
        }
        Ok(())
    }

    fn validate_packet_shape(&self) -> Result<SourcePoolMemory, CaptureError> {
        self.validate_source()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        let memory =
            unsafe { SourcePoolMemory::new(inst) }.ok_or(CaptureError::InvalidSourceIrp)?;
        let irp = memory
            .read_value::<Irp>(self.allocation.component_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let stack_address = source_stack_address(self.allocation, &irp)?;
        let stack = memory
            .read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        if stack_address != self.source_stack_address
            || stack.major_function != major::IRP_MJ_PNP
            || stack.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE
            || stack.device_object.0 != self.target_device_address
            || stack.file_object.0 != 0
            || stack.parameters[0] != self.raw_address
            || stack.parameters[1] != self.translated_address
            || StackFlags::from_bits_retain(stack.flags) != self.stack_flags
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        Ok(memory)
    }

    /// Revalidate the source resources, then transfer their broker-owned copy to the canonical
    /// provider IRP. No consumer pointer is retained in that payload.
    pub(super) fn take_payload(&mut self) -> Result<(u32, u32, Vec<u8>), CaptureError> {
        let memory = self.validate_packet_shape()?;
        if resource_hash(&memory, self.raw_address, self.raw_len as usize)? != self.raw_hash
            || resource_hash(
                &memory,
                self.translated_address,
                self.translated_len as usize,
            )? != self.translated_hash
        {
            return Err(CaptureError::InvalidResources);
        }
        let payload = self.payload.take().ok_or(CaptureError::InvalidResources)?;
        Ok((self.raw_len, self.translated_len, payload))
    }

    pub(super) fn publish_terminal(
        &self,
        status: nt_status::NtStatus,
        information: u64,
    ) -> Result<(), CaptureError> {
        if information != 0 {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let memory = self.validate_packet_shape()?;
        let status_address = self
            .allocation
            .component_address
            .checked_add(WDM_X64_IRP_IO_STATUS_STATUS_OFFSET)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let information_address = self
            .allocation
            .component_address
            .checked_add(WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        if !memory.write(status_address, &status.raw().to_le_bytes())
            || !memory.write(information_address, &information.to_le_bytes())
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        Ok(())
    }

    pub(super) fn release(&mut self) -> Result<(), CaptureError> {
        if !self.pinned {
            return Err(CaptureError::InvalidSourceIrp);
        }
        self.payload = None;
        if !hosted_source_irp_ledger::unpin(self.source) {
            return Err(CaptureError::InvalidSourceIrp);
        }
        self.pinned = false;
        Ok(())
    }
}

fn source_stack_address(allocation: SourceIrpAllocation, irp: &Irp) -> Result<u64, CaptureError> {
    if irp.type_ != WDM_X64_IO_TYPE_IRP as i16 || irp.size as u64 != allocation.bytes {
        return Err(CaptureError::InvalidSourceIrp);
    }
    let location =
        u8::try_from(irp.current_location).map_err(|_| CaptureError::InvalidSourceIrp)?;
    if location < 2
        || location > allocation.stack_count.saturating_add(1)
        || irp.stack_count != allocation.stack_count as i8
    {
        return Err(CaptureError::InvalidSourceIrp);
    }
    let stack_base = allocation
        .component_address
        .checked_add(WDM_X64_IRP_SIZE as u64)
        .ok_or(CaptureError::InvalidSourceIrp)?;
    let current_stack = stack_base
        .checked_add(
            (location as u64 - 1)
                .checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
                .ok_or(CaptureError::InvalidSourceIrp)?,
        )
        .ok_or(CaptureError::InvalidSourceIrp)?;
    if irp.current_stack_location.0 != current_stack {
        return Err(CaptureError::InvalidSourceIrp);
    }
    current_stack
        .checked_sub(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
        .ok_or(CaptureError::InvalidSourceIrp)
}

fn allocation_prefix(memory: &SourcePoolMemory, address: u64) -> Option<usize> {
    if address == 0 || !memory.contains(address, 1) {
        return None;
    }
    let mut low = 1usize;
    let mut high = MAX_RESOURCE_LIST_BYTES.saturating_add(1);
    while low.saturating_add(1) < high {
        let middle = low + (high - low) / 2;
        if memory.contains(address, middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    Some(low)
}

fn capture_resource_list(memory: &SourcePoolMemory, address: u64) -> Result<Vec<u8>, CaptureError> {
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
        let take = (length - offset).min(chunk.len());
        let at = address
            .checked_add(offset as u64)
            .ok_or(CaptureError::InvalidResources)?;
        if !memory.read(at, &mut chunk[..take]) {
            return Err(CaptureError::InvalidResources);
        }
        for &byte in &chunk[..take] {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        offset += take;
    }
    Ok(hash)
}

pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    source_irp_address: u64,
    target_device_address: u64,
) -> Result<CapturedLowerPnpStart, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    let domain = instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (source, allocation) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
    let result = (|| {
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
        let irp = memory
            .read_value::<Irp>(source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let stack_address = source_stack_address(allocation, &irp)?;
        let stack = memory
            .read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        if stack.major_function != major::IRP_MJ_PNP
            || stack.minor_function != nt_pnp_abi::IRP_MN_START_DEVICE
            || stack.device_object.0 != target_device_address
            || stack.file_object.0 != 0
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let raw_address = stack.parameters[0];
        let translated_address = stack.parameters[1];
        if (raw_address == 0) != (translated_address == 0) {
            return Err(CaptureError::InvalidResources);
        }
        let (raw, translated) = if raw_address == 0 {
            (Vec::new(), Vec::new())
        } else {
            (
                capture_resource_list(&memory, raw_address)?,
                capture_resource_list(&memory, translated_address)?,
            )
        };
        let raw_len = u32::try_from(raw.len()).map_err(|_| CaptureError::InvalidResources)?;
        let translated_len =
            u32::try_from(translated.len()).map_err(|_| CaptureError::InvalidResources)?;
        let total_len = raw
            .len()
            .checked_add(translated.len())
            .ok_or(CaptureError::InvalidResources)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(total_len)
            .map_err(|_| CaptureError::InsufficientResources)?;
        payload.extend_from_slice(&raw);
        payload.extend_from_slice(&translated);
        Ok(CapturedLowerPnpStart {
            instance_index,
            allocation,
            source,
            source_stack_address: stack_address,
            target_device_address,
            stack_flags: StackFlags::from_bits_retain(stack.flags),
            raw_address,
            translated_address,
            raw_len,
            translated_len,
            raw_hash: resource_hash(&memory, raw_address, raw.len())?,
            translated_hash: resource_hash(&memory, translated_address, translated.len())?,
            payload: Some(payload),
            pinned: true,
        })
    })();
    if result.is_err() {
        assert!(
            hosted_source_irp_ledger::unpin(source),
            "unentered lower PnP source rollback"
        );
    }
    result
}
