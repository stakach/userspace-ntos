//! Source-domain ownership and buffered-byte capture for a hosted WRITE forward.

use super::*;
use super::hosted_source_pool_memory::SourcePoolMemory;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    retained_query_path_forward::SourceIrpTicket,
    retained_write_forward::{
        select_write_buffer_source, CapturedWrite, PreparedWriteForward, TerminalWriteForward,
        WriteBufferSource, WriteCompletion, WriteForwardIdentity,
    },
    source_irp_ledger::SourceIrpAllocation,
    DeviceFlags, HostedDomainIdentity, StackFlags,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSourceIrp,
    InvalidSourceBuffer,
    InvalidFile,
    InvalidTarget,
    UnsupportedBuffer,
    InsufficientResources,
}

#[must_use = "retain until source-local completion and exact target retirement"]
pub(super) struct CapturedSourceWrite {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    source: SourceIrpTicket,
    source_file: Option<hosted_consumer_file_objects::ForwardFileOwner>,
    target: Option<HostedForwardTarget>,
    write: Option<CapturedWrite>,
    pinned: bool,
    forward_identity: Option<WriteForwardIdentity>,
    target_retired: bool,
}

impl CapturedSourceWrite {
    pub(super) fn source_ticket(&self) -> SourceIrpTicket { self.source }
    pub(super) fn source_irp_address(&self) -> u64 { self.allocation.component_address }
    pub(super) fn file_id(&self) -> nt_io_manager::FileId {
        self.source_file.as_ref().expect("source File released").file_id()
    }
    pub(super) fn device_id(&self) -> nt_io_manager::DeviceId {
        self.source_file.as_ref().expect("source File released").device_id()
    }
    pub(super) fn write(&self) -> &CapturedWrite {
        self.write.as_ref().expect("WRITE bytes prepared")
    }

    pub(super) fn validate_source(&self) -> Result<(), CaptureError> {
        if !hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.source) {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        if instance_domain_identity(inst) != Some(self.allocation.domain) {
            return Err(CaptureError::InvalidSourceIrp);
        }
        self.source_file.as_ref().ok_or(CaptureError::InvalidFile)?
            .validate().map_err(|_| CaptureError::InvalidFile)?;
        if let Some(target) = self.target.as_ref() {
            target.validate(io_manager_mut()).map_err(|_| CaptureError::InvalidTarget)?;
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

    pub(super) fn arm_callback_free(&self) -> Result<(), CaptureError> {
        self.validate_source()?;
        hosted_source_irp_ledger::arm_deferred_free(self.source)
            .then_some(()).ok_or(CaptureError::InvalidSourceIrp)
    }

    pub(super) fn callback_requested_free(&self) -> bool {
        hosted_source_irp_ledger::deferred_free_requested(self.source)
    }

    pub(super) fn prepare(&mut self) -> Result<PreparedWriteForward, CaptureError> {
        self.validate_source()?;
        let target = self.target.take().ok_or(CaptureError::InvalidTarget)?;
        let write = self.write.take().ok_or(CaptureError::InvalidSourceIrp)?;
        let prepared = PreparedWriteForward::new(self.source, target, self.file_id(), write);
        self.forward_identity = Some(prepared.identity());
        Ok(prepared)
    }

    pub(super) fn retire_target_after_source_completion(
        &mut self, terminal: TerminalWriteForward,
    ) -> Result<WriteCompletion, (CaptureError, TerminalWriteForward)> {
        if self.forward_identity != Some(terminal.identity())
            || self.target_retired || !self.callback_requested_free()
        {
            return Err((CaptureError::InvalidTarget, terminal));
        }
        match terminal.retire(io_manager_mut()) {
            Ok(completion) => { self.target_retired = true; Ok(completion) }
            Err((_, terminal)) => Err((CaptureError::InvalidTarget, terminal)),
        }
    }

    pub(super) fn retire_target_after_source_stop(
        &mut self, terminal: TerminalWriteForward,
    ) -> Result<WriteCompletion, (CaptureError, TerminalWriteForward)> {
        if self.forward_identity != Some(terminal.identity())
            || self.target_retired || self.callback_requested_free()
        {
            return Err((CaptureError::InvalidTarget, terminal));
        }
        match terminal.retire(io_manager_mut()) {
            Ok(completion) => { self.target_retired = true; Ok(completion) }
            Err((_, terminal)) => Err((CaptureError::InvalidTarget, terminal)),
        }
    }

    pub(super) fn release(&mut self) -> Result<(), CaptureError> {
        if !self.pinned { return Err(CaptureError::InvalidSourceIrp); }
        if self.forward_identity.is_some() && !self.target_retired {
            return Err(CaptureError::InvalidTarget);
        }
        if let Some(file) = self.source_file.as_mut() {
            file.release().map_err(|_| CaptureError::InvalidFile)?;
            self.source_file = None;
        }
        if let Some(target) = self.target.as_mut() {
            target.release(io_manager_mut()).map_err(|_| CaptureError::InvalidTarget)?;
            self.target = None;
        }
        if !hosted_source_irp_ledger::unpin(self.source) {
            return Err(CaptureError::InvalidSourceIrp);
        }
        self.pinned = false;
        Ok(())
    }
}

fn source_stack_address(
    allocation: SourceIrpAllocation, irp: &Irp,
) -> Result<u64, CaptureError> {
    if irp.type_ != WDM_X64_IO_TYPE_IRP as i16
        || irp.size as u64 != allocation.bytes
    {
        return Err(CaptureError::InvalidSourceIrp);
    }
    let location = u8::try_from(irp.current_location)
        .map_err(|_| CaptureError::InvalidSourceIrp)?;
    if location < 2 || location > allocation.stack_count
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
) -> Result<CapturedSourceWrite, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity =
        instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (source, allocation) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
    let result = (|| {
        let (initial_irp, initial_stack) = {
            let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
            let irp = memory.read_value::<Irp>(source_irp_address)
                .ok_or(CaptureError::InvalidSourceIrp)?;
            let stack = memory.read_value::<IoStackLocation>(source_stack_address(allocation, &irp)?)
                .ok_or(CaptureError::InvalidSourceIrp)?;
            (irp, stack)
        };
        if initial_stack.major_function != major::IRP_MJ_WRITE
            || initial_stack.device_object.0 != target_device_address
            || initial_stack.file_object.0 == 0
            || initial_irp._tail_post[..8] != initial_stack.file_object.0.to_le_bytes()
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let mut source_file = hosted_consumer_file_objects::capture_forward_file(
            ch, reply_cap, initial_stack.file_object.0, target_device_address,
        ).map_err(|_| CaptureError::InvalidFile)?;
        let mut target = match HostedForwardTarget::capture(
            io_manager_mut(), domain, target_device_address,
        ) {
            Ok(target) => target,
            Err(_) => {
                source_file.release().expect("unentered WRITE File rollback");
                return Err(CaptureError::InvalidTarget);
            }
        };
        let captured = (|| {
            if target.device_id() != source_file.device_id() {
                return Err(CaptureError::InvalidTarget);
            }
            let flags: DeviceFlags = io_manager_mut().device(target.device_id())
                .ok_or(CaptureError::InvalidTarget)?.flags;
            let params = initial_stack.read_write();
            let buffer = select_write_buffer_source(
                flags, params.length, initial_irp.associated_irp_system_buffer.0,
                initial_irp.mdl_address.0, initial_irp.user_buffer.0,
            ).map_err(|_| CaptureError::InvalidSourceBuffer)?;
            // Direct and neither I/O require authenticated process-backed reads. Never
            // interpret their virtual addresses as executive or provider pointers.
            let mut bytes = Vec::new();
            match buffer {
                WriteBufferSource::Empty => {}
                WriteBufferSource::SystemBuffer(address) => {
                    bytes.try_reserve_exact(params.length as usize)
                        .map_err(|_| CaptureError::InsufficientResources)?;
                    bytes.resize(params.length as usize, 0);
                    let memory = SourcePoolMemory::new(inst)
                        .ok_or(CaptureError::InvalidSourceIrp)?;
                    let irp = memory.read_value::<Irp>(source_irp_address)
                        .ok_or(CaptureError::InvalidSourceIrp)?;
                    let stack = memory.read_value::<IoStackLocation>(
                        source_stack_address(allocation, &irp)?,
                    ).ok_or(CaptureError::InvalidSourceIrp)?;
                    if irp != initial_irp || stack != initial_stack
                        || !memory.read(address, &mut bytes)
                    {
                        return Err(CaptureError::InvalidSourceBuffer);
                    }
                }
                WriteBufferSource::Mdl(_) | WriteBufferSource::UserBuffer(_) => {
                    return Err(CaptureError::UnsupportedBuffer);
                }
            }
            CapturedWrite::capture(
                &bytes, params.length, params.key, params.byte_offset,
                StackFlags::from_bits_retain(initial_stack.flags),
            ).map_err(|status| if status == nt_status::NtStatus::INSUFFICIENT_RESOURCES {
                CaptureError::InsufficientResources
            } else { CaptureError::InvalidSourceBuffer })
        })();
        let write = match captured {
            Ok(write) => write,
            Err(error) => {
                target.release(io_manager_mut()).expect("unentered WRITE target rollback");
                source_file.release().expect("unentered WRITE File rollback");
                return Err(error);
            }
        };
        Ok(CapturedSourceWrite {
            instance_index, allocation, source,
            source_file: Some(source_file), target: Some(target), write: Some(write),
            pinned: true, forward_identity: None, target_retired: false,
        })
    })();
    if result.is_err() {
        assert!(hosted_source_irp_ledger::unpin(source), "unentered WRITE source rollback");
    }
    result
}
