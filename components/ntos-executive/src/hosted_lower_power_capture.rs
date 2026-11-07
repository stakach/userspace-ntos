//! Retained source-domain packet for a foreign lower POWER dispatch.

use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner},
    power_irp_request::PowerParameters,
    HostedDomainIdentity,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSource,
    InvalidTarget,
}

#[must_use = "retain the source ticket through local callback and ACK"]
pub(super) struct CapturedLowerPower {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    ticket: SourceIrpTicket,
    source_stack_address: u64,
    upper_address: u64,
    upper_device_id: nt_io_manager::DeviceId,
    lower_device_id: nt_io_manager::DeviceId,
    target_address: u64,
    parameters: PowerParameters,
    pinned: bool,
}

impl CapturedLowerPower {
    pub(super) fn source_irp_address(&self) -> u64 { self.allocation.component_address }
    pub(super) fn source_domain(&self) -> HostedDomainIdentity { self.allocation.domain }
    pub(super) fn target_address(&self) -> u64 { self.target_address }
    pub(super) fn lower_device_id(&self) -> nt_io_manager::DeviceId { self.lower_device_id }
    pub(super) fn parameters(&self) -> PowerParameters { self.parameters }
    pub(super) fn source_ticket(&self) -> SourceIrpTicket { self.ticket }

    pub(super) fn validate_source(&self) -> Result<(), CaptureError> {
        if !self.pinned || !hosted_source_irp_ledger::matches(
            self.instance_index, self.allocation, self.ticket) {
            return Err(CaptureError::InvalidSource);
        }
        let instance = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        if instance_domain_identity(instance) != Some(self.allocation.domain) {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    fn validate_packet(&self) -> Result<SourcePoolMemory, CaptureError> {
        self.validate_source()?;
        let instance = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        let memory = unsafe { SourcePoolMemory::new(instance) }.ok_or(CaptureError::InvalidSource)?;
        let irp = memory.read_value::<Irp>(self.source_irp_address())
            .ok_or(CaptureError::InvalidSource)?;
        let next = super::hosted_source_irp_stack::next_stack_address(self.allocation, &irp)
            .ok_or(CaptureError::InvalidSource)?;
        let stack = memory.read_value::<IoStackLocation>(next)
            .ok_or(CaptureError::InvalidSource)?;
        let current = memory.read_value::<IoStackLocation>(irp.current_stack_location.0)
            .ok_or(CaptureError::InvalidSource)?;
        if next != self.source_stack_address || stack.major_function != major::IRP_MJ_POWER
            || stack.minor_function != self.parameters.minor()
            || stack.device_object.0 != self.target_address || stack.file_object.0 != 0
            || decode_power(&stack) != Some(self.parameters)
            || current.major_function != major::IRP_MJ_POWER
            || current.device_object.0 != self.upper_address
            || io_manager_mut().hosted_device_by_identity(self.allocation.domain,
                self.upper_address) != Some(self.upper_device_id)
            || io_manager_mut().hosted_device_by_identity(self.allocation.domain,
                self.target_address) != Some(self.lower_device_id)
            || io_manager_mut().device(self.upper_device_id)
                .and_then(|device| device.attached_to) != Some(self.lower_device_id) {
            return Err(CaptureError::InvalidSource);
        }
        Ok(memory)
    }

    pub(super) fn publish_terminal(&self, status: nt_status::NtStatus,
        information: u64) -> Result<(), CaptureError> {
        let memory = self.validate_packet()?;
        let status_address = self.source_irp_address()
            .checked_add(WDM_X64_IRP_IO_STATUS_STATUS_OFFSET)
            .ok_or(CaptureError::InvalidSource)?;
        let information_address = self.source_irp_address()
            .checked_add(WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET)
            .ok_or(CaptureError::InvalidSource)?;
        if !memory.write(status_address, &status.raw().to_le_bytes())
            || !memory.write(information_address, &information.to_le_bytes()) {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    pub(super) fn release(&mut self) -> Result<(), CaptureError> {
        if !self.pinned { return Err(CaptureError::InvalidSource); }
        if !hosted_source_irp_ledger::unpin(self.ticket) {
            return Err(CaptureError::InvalidSource);
        }
        self.pinned = false;
        Ok(())
    }

    pub(super) fn caller_terminal_ready(&self) -> bool {
        self.validate_source().is_ok()
            && hosted_source_irp_ledger::caller_terminal_ready(self.ticket, self.allocation)
    }

    pub(super) fn release_terminal(&mut self) -> Result<(), CaptureError> {
        if !self.pinned || !hosted_source_irp_ledger::release_pending_terminal(
            self.ticket, self.allocation) {
            return Err(CaptureError::InvalidSource);
        }
        self.pinned = false;
        Ok(())
    }

    /// PoRequestPowerIrp's completion routine may call IoFreeIrp while this forward still owns
    /// the packet. Only an authenticated hosted-driver allocation needs a deferred-free arm.
    pub(super) fn arm_callback_free(&self) -> Result<(), CaptureError> {
        self.validate_source()?;
        if matches!(self.allocation.owner, SourceIrpOwner::HostedDriver(_))
            && !hosted_source_irp_ledger::arm_deferred_free(self.ticket) {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    pub(super) fn release_after_native_completion(&mut self) -> Result<(), CaptureError> {
        self.validate_source()?;
        if matches!(self.allocation.owner, SourceIrpOwner::HostedDriver(_))
            && hosted_source_irp_ledger::deferred_free_requested(self.ticket) {
            self.release_terminal()
        } else {
            self.release()
        }
    }
}

fn decode_power(stack: &IoStackLocation) -> Option<PowerParameters> {
    match stack.minor_function {
        nt_power_types::IRP_MN_WAIT_WAKE =>
            PowerParameters::wait_wake(stack.parameters[0] as u32).ok(),
        nt_power_types::IRP_MN_SET_POWER | nt_power_types::IRP_MN_QUERY_POWER => {
            let state_type = stack.parameters[1] as u32;
            let state = stack.parameters[2] as u32;
            match state_type {
                nt_power_types::POWER_STATE_TYPE_DEVICE =>
                    PowerParameters::device(stack.minor_function, state).ok(),
                nt_power_types::POWER_STATE_TYPE_SYSTEM =>
                    PowerParameters::system(stack.minor_function, state).ok(),
                _ => None,
            }.and_then(|parameters| parameters.with_forwarded_context(
                stack.parameters[0] as u32, stack.parameters[3] as u32).ok())
        }
        _ => None,
    }
}

pub(super) unsafe fn capture(ch: &crate::spawn_hosts::PumpChannel, reply_cap: u64,
    source_address: u64, target_address: u64)
    -> Result<CapturedLowerPower, CaptureError> {
    let (instance_index, instance) = instance_for_pump_channel(ch, reply_cap)
        .ok_or(CaptureError::InvalidCaller)?;
    let domain = instance_domain_identity(instance).ok_or(CaptureError::InvalidCaller)?;
    let (ticket, allocation) = hosted_source_irp_ledger::pin(instance_index, domain, source_address)
        .ok_or(CaptureError::InvalidSource)?;
    let result = (|| {
        let memory = SourcePoolMemory::new(instance).ok_or(CaptureError::InvalidSource)?;
        let irp = memory.read_value::<Irp>(source_address).ok_or(CaptureError::InvalidSource)?;
        let next = super::hosted_source_irp_stack::next_stack_address(allocation, &irp)
            .ok_or(CaptureError::InvalidSource)?;
        let stack = memory.read_value::<IoStackLocation>(next).ok_or(CaptureError::InvalidSource)?;
        let current = memory.read_value::<IoStackLocation>(irp.current_stack_location.0)
            .ok_or(CaptureError::InvalidSource)?;
        if stack.major_function != major::IRP_MJ_POWER || stack.device_object.0 != target_address
            || stack.file_object.0 != 0 || target_address == 0 {
            return Err(CaptureError::InvalidTarget);
        }
        let parameters = decode_power(&stack).ok_or(CaptureError::InvalidSource)?;
        let upper_address = current.device_object.0;
        let upper_device_id = io_manager_mut().hosted_device_by_identity(domain, upper_address)
            .ok_or(CaptureError::InvalidTarget)?;
        let lower_device_id = io_manager_mut().hosted_device_by_identity(domain, target_address)
            .ok_or(CaptureError::InvalidTarget)?;
        if current.major_function != major::IRP_MJ_POWER || current.file_object.0 != 0
            || io_manager_mut().device(upper_device_id).and_then(|d| d.attached_to)
                != Some(lower_device_id) {
            return Err(CaptureError::InvalidTarget);
        }
        Ok(CapturedLowerPower { instance_index, allocation, ticket,
            source_stack_address: next, upper_address, upper_device_id, lower_device_id,
            target_address, parameters, pinned: true })
    })();
    if result.is_err() {
        assert!(hosted_source_irp_ledger::unpin(ticket), "unentered POWER capture rollback");
    }
    result
}
