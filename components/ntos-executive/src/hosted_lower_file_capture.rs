//! Exact source-domain capture for a forwarded lower File lifecycle IRP.

use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    retained_query_path_forward::SourceIrpTicket,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpOwner},
    FileId, FileReference, HostedDevicePointerRegistration, HostedFileIdentity,
    HostedFilePublicationLease,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSourceIrp,
    InvalidFile,
    InvalidTarget,
}

#[must_use = "retain until exact source completion and lower provider retirement"]
pub(super) struct CapturedLowerFileLifecycle {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    source: SourceIrpTicket,
    stack_address: u64,
    source_file_address: u64,
    source_device: HostedDevicePointerRegistration,
    lower_device: HostedDevicePointerRegistration,
    file_identity: HostedFileIdentity,
    file_lease: Option<HostedFilePublicationLease>,
    file_reference: Option<FileReference>,
    target: Option<HostedForwardTarget>,
    major: u8,
    pinned: bool,
}

impl CapturedLowerFileLifecycle {
    pub(super) fn source_identity(&self) -> SourceIrpForwardIdentity {
        SourceIrpForwardIdentity::new(self.source, self.allocation)
            .expect("captured source allocation and ticket")
    }

    pub(super) const fn source_irp_address(&self) -> u64 {
        self.allocation.component_address
    }

    pub(super) const fn major(&self) -> u8 {
        self.major
    }

    pub(super) const fn file_id(&self) -> FileId {
        self.file_identity.file_id()
    }

    pub(super) fn canonical_outer_irp(&self) -> Result<nt_io_manager::IrpId, CaptureError> {
        self.validate_source()?;
        let nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedCaller(index) =
            self.allocation.owner
        else { return Err(CaptureError::InvalidSourceIrp); };
        if index != self.instance_index {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let outer = hosted_source_irp_ledger::active_caller_file_lifecycle_outer(
            index, self.source, self.allocation, self.major, self.file_id(),
        ).ok_or(CaptureError::InvalidSourceIrp)?;
        let io = io_manager_mut();
        let record = io.irp(outer).ok_or(CaptureError::InvalidSourceIrp)?;
        if record.file_id != Some(self.file_id())
            || record.origin_major != self.major
            || io.top_of_device_stack(record.origin_device_id).ok()
                != Some(self.source_device.device_id())
            || record.current_stack().is_none_or(|stack| {
                stack.major != self.major || stack.file_id != Some(self.file_id())
                    || stack.device_id != self.source_device.device_id()
            })
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        Ok(outer)
    }

    pub(super) const fn source_device_registration(&self) -> HostedDevicePointerRegistration {
        self.source_device
    }

    pub(super) const fn lower_device_registration(&self) -> HostedDevicePointerRegistration {
        self.lower_device
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
        let io = io_manager_mut();
        if io.hosted_file_identity_at_address(self.allocation.domain, self.source_file_address)
            .map_err(|_| CaptureError::InvalidFile)? != Some(self.file_identity)
            || self.file_lease.as_ref().is_none_or(|lease| !lease.is_held())
            || io.hosted_device_pointer_registration(
                self.allocation.domain, self.source_device.address(),
            ) != Some(self.source_device)
            || io.hosted_device_pointer_registration(
                self.allocation.domain, self.lower_device.address(),
            ) != Some(self.lower_device)
            || io.device(self.source_device.device_id())
                .is_none_or(|device| device.attached_to != Some(self.lower_device.device_id()))
        {
            return Err(CaptureError::InvalidFile);
        }
        if let Some(target) = self.target.as_ref() {
            target.validate(io).map_err(|_| CaptureError::InvalidTarget)?;
        }
        Ok(())
    }

    /// Check mutable native packet fields only before the lower provider is entered. Completion
    /// legitimately advances CurrentStackLocation and may alter the stack bytes afterward.
    pub(super) fn validate_packet(&self) -> Result<(), CaptureError> {
        self.validate_source()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        let memory = unsafe { SourcePoolMemory::new(inst) }.ok_or(CaptureError::InvalidSourceIrp)?;
        let irp = memory.read_value::<Irp>(self.allocation.component_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let next_stack = source_stack_address(self.allocation, &irp)?;
        // IoSkipCurrentIrpStackLocation leaves the source slot as "next". Once
        // IofCallDriver accepts it, CurrentStackLocation moves into that slot.
        if next_stack != self.stack_address
            && next_stack.checked_add(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
                != Some(self.stack_address)
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let stack = memory.read_value::<IoStackLocation>(self.stack_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        if stack.major_function != self.major
            || stack.file_object.0 != self.source_file_address
            || !matches!(stack.device_object.0, address
                if address == self.source_device.address() || address == self.lower_device.address())
            || !memory.contains(self.source_file_address, WDM_X64_FILE_OBJECT_SIZE)
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        Ok(())
    }

    pub(super) unsafe fn source_irp_exec(&self) -> Result<u64, CaptureError> {
        self.validate_source()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        hosted_instance_pool_allocation_exec_if_live(
            inst, self.allocation.component_address, self.allocation.bytes,
        ).ok_or(CaptureError::InvalidSourceIrp)
    }

    pub(super) fn completion_command(
        &self, token: u64,
    ) -> Result<hosted_source_completion_lane::SourceCompletionCommand, CaptureError> {
        self.validate_source()?;
        Ok(hosted_source_completion_lane::SourceCompletionCommand {
            ticket: self.source, allocation: self.allocation, token,
        })
    }

    pub(super) fn arm_callback_free(&self) -> Result<(), CaptureError> {
        self.validate_source()?;
        hosted_source_irp_ledger::arm_deferred_free(self.source)
            .then_some(()).ok_or(CaptureError::InvalidSourceIrp)
    }

    pub(super) fn completion_finished(&self) -> bool {
        match self.allocation.owner {
            SourceIrpOwner::HostedDriver(_) =>
                hosted_source_irp_ledger::deferred_free_requested(self.source),
            SourceIrpOwner::HostedCaller(_) =>
                hosted_source_irp_ledger::caller_terminal_ready(self.source, self.allocation),
            SourceIrpOwner::Win32k => false,
        }
    }

    pub(super) fn take_forward_owners(
        &mut self,
    ) -> Result<(HostedForwardTarget, Option<FileReference>), CaptureError> {
        self.validate_source()?;
        let target = self.target.take().ok_or(CaptureError::InvalidTarget)?;
        let file = self.file_reference.take();
        if file.is_none() && self.major != major::IRP_MJ_CLOSE {
            self.target = Some(target);
            return Err(CaptureError::InvalidFile);
        }
        Ok((target, file))
    }

    pub(super) fn release(&mut self) -> Result<(), CaptureError> {
        self.release_owned(false)
    }

    pub(super) fn release_pending_terminal(&mut self) -> Result<(), CaptureError> {
        self.release_owned(true)
    }

    fn release_owned(&mut self, pending_terminal: bool) -> Result<(), CaptureError> {
        if !self.pinned { return Err(CaptureError::InvalidSourceIrp); }
        if let Some(target) = self.target.as_mut() {
            target.release(io_manager_mut()).map_err(|_| CaptureError::InvalidTarget)?;
            self.target = None;
        }
        if let Some(file) = self.file_reference.as_mut() {
            io_manager_mut().release_file_reference(file).map_err(|_| CaptureError::InvalidFile)?;
            self.file_reference = None;
        }
        if let Some(lease) = self.file_lease.as_mut() {
            io_manager_mut().release_hosted_file_publication(lease)
                .map_err(|_| CaptureError::InvalidFile)?;
            self.file_lease = None;
        }
        let released = if pending_terminal {
            hosted_source_irp_ledger::release_pending_terminal(self.source, self.allocation)
        } else {
            hosted_source_irp_ledger::unpin(self.source)
        };
        if !released { return Err(CaptureError::InvalidSourceIrp); }
        self.pinned = false;
        Ok(())
    }
}

fn source_stack_address(allocation: SourceIrpAllocation, irp: &Irp) -> Result<u64, CaptureError> {
    if irp.type_ != WDM_X64_IO_TYPE_IRP as i16 || irp.size as u64 != allocation.bytes {
        return Err(CaptureError::InvalidSourceIrp);
    }
    let location = u8::try_from(irp.current_location).map_err(|_| CaptureError::InvalidSourceIrp)?;
    if location < 2 || location > allocation.stack_count.saturating_add(1)
        || irp.stack_count != allocation.stack_count as i8
    {
        return Err(CaptureError::InvalidSourceIrp);
    }
    let stack_base = allocation.component_address.checked_add(WDM_X64_IRP_SIZE as u64)
        .ok_or(CaptureError::InvalidSourceIrp)?;
    let current_stack = stack_base.checked_add(
        (location as u64 - 1).checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
            .ok_or(CaptureError::InvalidSourceIrp)?,
    ).ok_or(CaptureError::InvalidSourceIrp)?;
    if irp.current_stack_location.0 != current_stack {
        return Err(CaptureError::InvalidSourceIrp);
    }
    current_stack.checked_sub(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
        .ok_or(CaptureError::InvalidSourceIrp)
}

pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    source_irp_address: u64,
    lower_device_address: u64,
) -> Result<CapturedLowerFileLifecycle, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    let domain = instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (source, allocation) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
    let result = (|| {
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
        let irp = memory.read_value::<Irp>(source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let stack_address = source_stack_address(allocation, &irp)?;
        let stack = memory.read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        if !matches!(stack.major_function,
            major::IRP_MJ_CREATE | major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE)
            || stack.file_object.0 == 0
            || !memory.contains(stack.file_object.0, WDM_X64_FILE_OBJECT_SIZE)
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let source_device = io_manager_mut()
            .hosted_device_pointer_registration(domain, stack.device_object.0)
            .ok_or(CaptureError::InvalidTarget)?;
        let mut target = HostedForwardTarget::capture(
            io_manager_mut(), domain, lower_device_address,
        ).map_err(|_| CaptureError::InvalidTarget)?;
        let captured = (|| {
            if io_manager_mut().device(source_device.device_id())
                .is_none_or(|device| device.attached_to != Some(target.device_id()))
            {
                return Err(CaptureError::InvalidTarget);
            }
            let file_identity = io_manager_mut()
                .hosted_file_identity_at_address(domain, stack.file_object.0)
                .map_err(|_| CaptureError::InvalidFile)?
                .ok_or(CaptureError::InvalidFile)?;
            let io = io_manager_mut();
            let file_device = io.file(file_identity.file_id())
                .map(|file| file.device_id).ok_or(CaptureError::InvalidFile)?;
            if io.top_of_device_stack(file_device).ok() != Some(source_device.device_id()) {
                return Err(CaptureError::InvalidFile);
            }
            let mut lease = io_manager_mut().lease_hosted_file_identity(file_identity)
                .map_err(|_| CaptureError::InvalidFile)?;
            let reference = match io_manager_mut().retain_file_reference(file_identity.file_id()) {
                Ok(reference) => Some(reference),
                Err(_) if stack.major_function == major::IRP_MJ_CLOSE => None,
                Err(_) => {
                    io_manager_mut().release_hosted_file_publication(&mut lease)
                        .expect("unentered lower File publication rollback");
                    return Err(CaptureError::InvalidFile);
                }
            };
            Ok((file_identity, lease, reference))
        })();
        let (file_identity, lease, reference) = match captured {
            Ok(value) => value,
            Err(error) => {
                target.release(io_manager_mut())
                    .expect("unentered lower File target rollback");
                return Err(error);
            }
        };
        let result = CapturedLowerFileLifecycle {
            instance_index, allocation, source, stack_address,
            source_file_address: stack.file_object.0, source_device,
            lower_device: target.registration(), file_identity,
            file_lease: Some(lease), file_reference: reference, target: Some(target),
            major: stack.major_function, pinned: true,
        };
        Ok(result)
    })();
    if result.is_err() {
        assert!(hosted_source_irp_ledger::unpin(source), "unentered lower File source rollback");
    }
    result
}
