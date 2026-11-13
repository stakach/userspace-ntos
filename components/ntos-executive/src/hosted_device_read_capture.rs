//! Exact source ownership for a fileless READ sent to a foreign lower device.

use super::*;
use super::hosted_source_pool_memory::SourcePoolMemory;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    kernel_irp_builder::{validate_kernel_irp_dispatch_cursor, KernelIrpDispatchHeader},
    retained_query_path_forward::SourceIrpTicket,
    source_device_read::{admit_source_device_read, SourceDeviceRead, SourceDeviceReadRequest},
    source_irp_auxiliary::SourceIrpAuxiliaryPhase,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpOwner},
    HostedDomainIdentity,
};
use nt_kernel_abi::{IoStackLocation, Irp};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSource,
    InvalidTarget,
    Unsupported,
}

#[must_use = "retain the source IRP and its output until completion and ACK"]
pub(super) struct CapturedDeviceRead {
    instance_index: usize,
    instance: DriverInstance,
    ticket: SourceIrpTicket,
    allocation: SourceIrpAllocation,
    target: Option<HostedForwardTarget>,
    read: SourceDeviceRead,
    pinned: bool,
}

impl CapturedDeviceRead {
    pub(super) fn identity(&self) -> SourceIrpForwardIdentity {
        SourceIrpForwardIdentity::new(self.ticket, self.allocation)
            .expect("pinned source READ")
    }
    pub(super) fn address(&self) -> u64 { self.allocation.component_address }
    pub(super) fn device_id(&self) -> nt_io_manager::DeviceId {
        self.target.as_ref().expect("retained READ target").device_id()
    }
    pub(super) fn request(&self) -> SourceDeviceRead { self.read }
    pub(super) fn completion_finished(&self) -> bool {
        hosted_source_irp_ledger::deferred_free_requested(self.ticket)
    }
    pub(super) fn validate(&self) -> Result<(), CaptureError> {
        if !self.pinned
            || !hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.ticket)
        { return Err(CaptureError::InvalidSource); }
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        if inst.pml4 != self.instance.pml4
            || inst.exec_pool_va != self.instance.exec_pool_va
            || inst.driver_id != self.instance.driver_id
            || inst.tcb != self.instance.tcb
            || instance_domain_identity(inst) != Some(self.allocation.domain)
        { return Err(CaptureError::InvalidSource); }
        self.target.as_ref().ok_or(CaptureError::InvalidTarget)?
            .validate(io_manager_mut()).map_err(|_| CaptureError::InvalidTarget)?;
        Ok(())
    }

    /// Recheck mutable source fields and physical child identities before the
    /// canonical provider request enters. After entry, only the retained
    /// auxiliary and source pin authorize output publication.
    pub(super) unsafe fn validate_before_entry(&self) -> Result<(), CaptureError> {
        self.validate()?;
        let auxiliary = hosted_source_irp_ledger::protected_auxiliary(
            self.instance_index, self.allocation, self.ticket,
        ).ok_or(CaptureError::InvalidSource)?;
        let memory = SourcePoolMemory::new(self.instance).ok_or(CaptureError::InvalidSource)?;
        let irp = memory.read_value::<Irp>(self.address()).ok_or(CaptureError::InvalidSource)?;
        let stack_address = source_stack_address(self.allocation, &irp)
            .ok_or(CaptureError::InvalidSource)?;
        let stack = memory.read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSource)?;
        let current = admit_source_device_read(request_from_packet(
            self.allocation, self.ticket, &irp, &stack, self.read.device_object,
        ), auxiliary).ok_or(CaptureError::InvalidSource)?;
        (current == self.read).then_some(()).ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn write_result(&self, status: i32, information: u64, output: &[u8]) -> Result<(), CaptureError> {
        self.validate()?;
        hosted_source_irp_ledger::publish_device_read_result(
            self.instance_index, self.read, status, information, output,
        ).then_some(()).ok_or(CaptureError::InvalidSource)
    }

    pub(super) unsafe fn write_refusal(&self, status: i32) -> Result<(), CaptureError> {
        self.validate_before_entry()?;
        let memory = SourcePoolMemory::new(self.instance).ok_or(CaptureError::InvalidSource)?;
        if !memory.write(self.address() + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET, &status.to_le_bytes())
            || !memory.write(self.address() + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET,
                &0u64.to_le_bytes())
        { return Err(CaptureError::InvalidSource); }
        Ok(())
    }

    pub(super) fn release(&mut self, pending_terminal: bool) -> Result<(), CaptureError> {
        if self.pinned {
            self.validate()?;
            let done = if pending_terminal {
                hosted_source_irp_ledger::release_pending_terminal(self.ticket, self.allocation)
            } else {
                hosted_source_irp_ledger::unpin(self.ticket)
            };
            if !done { return Err(CaptureError::InvalidSource); }
            self.pinned = false;
        }
        if let Some(target) = self.target.as_mut() {
            target.release(io_manager_mut()).map_err(|_| CaptureError::InvalidTarget)?;
            self.target = None;
        }
        Ok(())
    }
}

fn source_stack_address(allocation: SourceIrpAllocation, irp: &Irp) -> Option<u64> {
    let cursor = validate_kernel_irp_dispatch_cursor(
        allocation.component_address, allocation.bytes, allocation.stack_count,
        KernelIrpDispatchHeader {
            irp_type: irp.type_ as u16,
            packet_size: irp.size,
            stack_count: irp.stack_count as u8,
            current_location: irp.current_location as u8,
            current_stack_location: irp.current_stack_location.0,
        },
    ).ok()?;
    allocation.component_address
        .checked_add(u64::try_from(cursor.next_stack_offset).ok()?)
}

fn request_from_packet(
    allocation: SourceIrpAllocation,
    ticket: SourceIrpTicket,
    irp: &Irp,
    stack: &IoStackLocation,
    target_address: u64,
) -> SourceDeviceReadRequest {
    let read = stack.read_write();
    SourceDeviceReadRequest {
        source: allocation,
        ticket,
        phase: SourceIrpAuxiliaryPhase::Protected,
        major: stack.major_function,
        minor: stack.minor_function,
        device_object: stack.device_object.0,
        target_device_object: target_address,
        file_object: stack.file_object.0,
        length: read.length,
        key: read.key,
        byte_offset: read.byte_offset,
        stack_flags: stack.flags,
        irp_flags: irp.flags,
        system_buffer: irp.associated_irp_system_buffer.0,
        mdl: irp.mdl_address.0,
        user_buffer: irp.user_buffer.0,
    }
}

pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_address: u64,
    target_address: u64,
) -> Result<CapturedDeviceRead, CaptureError> {
    let (index, inst) = instance_for_pump_channel(ch, reply_cap)
        .ok_or(CaptureError::InvalidCaller)?;
    hosted_driver_pump_caller_tcb(ch, reply_cap, badge)
        .ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity = instance_domain_identity(inst)
        .ok_or(CaptureError::InvalidCaller)?;
    let (ticket, allocation) = hosted_source_irp_ledger::pin(index, domain, source_address)
        .ok_or(CaptureError::InvalidSource)?;
    if allocation.owner != SourceIrpOwner::HostedDriver(index) {
        assert!(hosted_source_irp_ledger::unpin(ticket), "wrong-owner READ rollback");
        return Err(CaptureError::InvalidSource);
    }
    let result = (|| {
        let auxiliary = hosted_source_irp_ledger::protected_auxiliary(index, allocation, ticket)
            .ok_or(CaptureError::InvalidSource)?;
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
        let irp = memory.read_value::<Irp>(source_address).ok_or(CaptureError::InvalidSource)?;
        let stack_address = source_stack_address(allocation, &irp)
            .ok_or(CaptureError::InvalidSource)?;
        let stack = memory.read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSource)?;
        let read = admit_source_device_read(request_from_packet(
            allocation, ticket, &irp, &stack, target_address,
        ), auxiliary).ok_or(CaptureError::Unsupported)?;
        drop(memory);
        let target = HostedForwardTarget::capture(io_manager_mut(), domain, target_address)
            .map_err(|_| CaptureError::InvalidTarget)?;
        Ok(CapturedDeviceRead {
            instance_index: index, instance: inst, ticket, allocation,
            target: Some(target), read, pinned: true,
        })
    })();
    if result.is_err() {
        assert!(hosted_source_irp_ledger::unpin(ticket), "unentered READ rollback");
    }
    result
}
