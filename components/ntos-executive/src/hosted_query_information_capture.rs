//! Source-domain ownership and buffered output for a hosted QUERY_INFORMATION forward.

use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    retained_query_information_forward::{
        CapturedQueryInformation, PreparedQueryInformationForward, QueryInformationCompletion,
        QueryInformationForwardIdentity, TerminalQueryInformationForward,
    },
    retained_query_path_forward::SourceIrpTicket,
    source_irp_ledger::SourceIrpAllocation,
    HostedDomainIdentity, StackFlags,
};
use nt_kernel_abi::{IoStackLocation, Irp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSourceIrp,
    InvalidSourceBuffer,
    InvalidFile,
    InvalidTarget,
}

#[must_use = "retain until source-local completion and exact target retirement"]
pub(super) struct CapturedSourceQueryInformation {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    source: SourceIrpTicket,
    source_stack_address: u64,
    system_buffer: u64,
    source_file_address: u64,
    target_device_address: u64,
    length: u32,
    information_class: u32,
    stack_flags: StackFlags,
    stack_parameters: [u64; 4],
    source_file: Option<hosted_consumer_file_objects::ForwardFileOwner>,
    target: Option<HostedForwardTarget>,
    pinned: bool,
    forward_identity: Option<QueryInformationForwardIdentity>,
    target_retired: bool,
}

impl CapturedSourceQueryInformation {
    pub(super) fn source_irp_address(&self) -> u64 {
        self.allocation.component_address
    }
    pub(super) fn file_id(&self) -> nt_io_manager::FileId {
        self.source_file
            .as_ref()
            .expect("source File released")
            .file_id()
    }
    pub(super) fn device_id(&self) -> nt_io_manager::DeviceId {
        self.source_file
            .as_ref()
            .expect("source File released")
            .device_id()
    }
    pub(super) fn length(&self) -> u32 {
        self.length
    }
    pub(super) fn information_class(&self) -> u32 {
        self.information_class
    }
    pub(super) fn stack_flags(&self) -> StackFlags {
        self.stack_flags
    }

    pub(super) fn validate_source(&self) -> Result<(), CaptureError> {
        if !hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.source) {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        if instance_domain_identity(inst) != Some(self.allocation.domain) {
            return Err(CaptureError::InvalidSourceIrp);
        }
        self.source_file
            .as_ref()
            .ok_or(CaptureError::InvalidFile)?
            .validate()
            .map_err(|_| CaptureError::InvalidFile)?;
        if let Some(target) = self.target.as_ref() {
            target
                .validate(io_manager_mut())
                .map_err(|_| CaptureError::InvalidTarget)?;
        }
        Ok(())
    }

    pub(super) unsafe fn source_irp_exec(&self) -> Result<u64, CaptureError> {
        self.validate_source()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        hosted_instance_pool_allocation_exec_if_live(
            inst,
            self.allocation.component_address,
            self.allocation.bytes,
        )
        .ok_or(CaptureError::InvalidSourceIrp)
    }

    pub(super) unsafe fn write_output(
        &self,
        completion: &QueryInformationCompletion,
    ) -> Result<(), CaptureError> {
        self.validate_source()?;
        if completion.information() > u64::from(self.length)
            || completion.bytes().len() as u64 != completion.information()
        {
            return Err(CaptureError::InvalidSourceBuffer);
        }
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
        let irp = memory
            .read_value::<Irp>(self.allocation.component_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let stack = memory
            .read_value::<IoStackLocation>(self.source_stack_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        if irp.type_ != WDM_X64_IO_TYPE_IRP as i16
            || irp.size as u64 != self.allocation.bytes
            || irp.associated_irp_system_buffer.0 != self.system_buffer
            || irp._tail_post[..8] != self.source_file_address.to_le_bytes()
            || stack.major_function != major::IRP_MJ_QUERY_INFORMATION
            || stack.file_object.0 != self.source_file_address
            || stack.device_object.0 != self.target_device_address
            || stack.parameters != self.stack_parameters
            || StackFlags::from_bits_retain(stack.flags) != self.stack_flags
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        if !completion.bytes().is_empty() && !memory.write(self.system_buffer, completion.bytes()) {
            return Err(CaptureError::InvalidSourceBuffer);
        }
        Ok(())
    }

    pub(super) fn arm_callback_free(&self) -> Result<(), CaptureError> {
        self.validate_source()?;
        hosted_source_irp_ledger::arm_deferred_free(self.source)
            .then_some(())
            .ok_or(CaptureError::InvalidSourceIrp)
    }

    pub(super) fn callback_requested_free(&self) -> bool {
        hosted_source_irp_ledger::deferred_free_requested(self.source)
    }

    pub(super) fn prepare(&mut self) -> Result<PreparedQueryInformationForward, CaptureError> {
        self.validate_source()?;
        let target = self.target.take().ok_or(CaptureError::InvalidTarget)?;
        let query =
            CapturedQueryInformation::new(self.information_class, self.length, self.stack_flags);
        let prepared =
            PreparedQueryInformationForward::new(self.source, target, self.file_id(), query);
        self.forward_identity = Some(prepared.identity());
        Ok(prepared)
    }

    pub(super) fn retire_target_after_source_completion(
        &mut self,
        terminal: TerminalQueryInformationForward,
    ) -> Result<QueryInformationCompletion, (CaptureError, TerminalQueryInformationForward)> {
        if self.forward_identity != Some(terminal.identity())
            || self.target_retired
            || !self.callback_requested_free()
        {
            return Err((CaptureError::InvalidTarget, terminal));
        }
        match terminal.retire(io_manager_mut()) {
            Ok(completion) => {
                self.target_retired = true;
                Ok(completion)
            }
            Err((_, terminal)) => Err((CaptureError::InvalidTarget, terminal)),
        }
    }

    pub(super) fn retire_target_after_source_stop(
        &mut self,
        terminal: TerminalQueryInformationForward,
    ) -> Result<QueryInformationCompletion, (CaptureError, TerminalQueryInformationForward)> {
        if self.forward_identity != Some(terminal.identity())
            || self.target_retired
            || self.callback_requested_free()
        {
            return Err((CaptureError::InvalidTarget, terminal));
        }
        match terminal.retire(io_manager_mut()) {
            Ok(completion) => {
                self.target_retired = true;
                Ok(completion)
            }
            Err((_, terminal)) => Err((CaptureError::InvalidTarget, terminal)),
        }
    }

    pub(super) fn release(&mut self) -> Result<(), CaptureError> {
        if !self.pinned {
            return Err(CaptureError::InvalidSourceIrp);
        }
        if self.forward_identity.is_some() && !self.target_retired {
            return Err(CaptureError::InvalidTarget);
        }
        if let Some(file) = self.source_file.as_mut() {
            file.release().map_err(|_| CaptureError::InvalidFile)?;
            self.source_file = None;
        }
        if let Some(target) = self.target.as_mut() {
            target
                .release(io_manager_mut())
                .map_err(|_| CaptureError::InvalidTarget)?;
            self.target = None;
        }
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
    let stack_base = allocation.component_address + WDM_X64_IRP_SIZE as u64;
    let current_stack = stack_base + (location as u64 - 1) * WDM_X64_IO_STACK_LOCATION_SIZE as u64;
    if irp.current_stack_location.0 != current_stack {
        return Err(CaptureError::InvalidSourceIrp);
    }
    Ok(current_stack - WDM_X64_IO_STACK_LOCATION_SIZE as u64)
}

pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    source_irp_address: u64,
    target_device_address: u64,
) -> Result<CapturedSourceQueryInformation, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity =
        instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (source, allocation) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
    let result = (|| {
        let (initial_irp, initial_stack, stack_address) = {
            let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
            let irp = memory
                .read_value::<Irp>(source_irp_address)
                .ok_or(CaptureError::InvalidSourceIrp)?;
            let stack_address = source_stack_address(allocation, &irp)?;
            let stack = memory
                .read_value::<IoStackLocation>(stack_address)
                .ok_or(CaptureError::InvalidSourceIrp)?;
            (irp, stack, stack_address)
        };
        if initial_stack.major_function != major::IRP_MJ_QUERY_INFORMATION
            || initial_stack.device_object.0 != target_device_address
            || initial_stack.file_object.0 == 0
            || initial_irp._tail_post[..8] != initial_stack.file_object.0.to_le_bytes()
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let mut source_file = hosted_consumer_file_objects::capture_forward_file(
            ch,
            reply_cap,
            initial_stack.file_object.0,
            target_device_address,
        )
        .map_err(|_| CaptureError::InvalidFile)?;
        let mut target =
            match HostedForwardTarget::capture(io_manager_mut(), domain, target_device_address) {
                Ok(target) => target,
                Err(_) => {
                    source_file
                        .release()
                        .expect("unentered QUERY_INFORMATION File rollback");
                    return Err(CaptureError::InvalidTarget);
                }
            };
        let captured = (|| {
            if target.device_id() != source_file.device_id() {
                return Err(CaptureError::InvalidTarget);
            }
            let length = initial_stack.parameters[0] as u32;
            let information_class = initial_stack.parameters[1] as u32;
            let buffer = initial_irp.associated_irp_system_buffer.0;
            let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
            if length != 0 && (buffer == 0 || !memory.contains(buffer, length as usize)) {
                return Err(CaptureError::InvalidSourceBuffer);
            }
            let irp = memory
                .read_value::<Irp>(source_irp_address)
                .ok_or(CaptureError::InvalidSourceIrp)?;
            let stack = memory
                .read_value::<IoStackLocation>(stack_address)
                .ok_or(CaptureError::InvalidSourceIrp)?;
            if irp != initial_irp || stack != initial_stack {
                return Err(CaptureError::InvalidSourceIrp);
            }
            Ok((buffer, length, information_class))
        })();
        let (system_buffer, length, information_class) = match captured {
            Ok(value) => value,
            Err(error) => {
                target
                    .release(io_manager_mut())
                    .expect("unentered QUERY_INFORMATION target rollback");
                source_file
                    .release()
                    .expect("unentered QUERY_INFORMATION File rollback");
                return Err(error);
            }
        };
        Ok(CapturedSourceQueryInformation {
            instance_index,
            allocation,
            source,
            source_stack_address: stack_address,
            system_buffer,
            source_file_address: initial_stack.file_object.0,
            target_device_address,
            length,
            information_class,
            stack_flags: StackFlags::from_bits_retain(initial_stack.flags),
            stack_parameters: initial_stack.parameters,
            source_file: Some(source_file),
            target: Some(target),
            pinned: true,
            forward_identity: None,
            target_retired: false,
        })
    })();
    if result.is_err() {
        assert!(
            hosted_source_irp_ledger::unpin(source),
            "unentered QUERY_INFORMATION source rollback"
        );
    }
    result
}
