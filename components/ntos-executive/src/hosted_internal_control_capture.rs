//! File-less, source-owned internal control IRP capture.
//!
//! The source pool owns the IRP, while `IoBuildDeviceIoControlRequest` may put its eight-byte
//! output in the calling worker's stack. Pin the IRP and target, bind that stack to the physical
//! calling TCB, and keep all of them until the source-local completion has run.

use super::*;
use super::hosted_source_pool_memory::SourcePoolMemory;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    internal_device_control_forward::{InternalControlCapture, InternalControlError},
    retained_query_path_forward::SourceIrpTicket,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity},
    HostedDomainIdentity,
};
use nt_kernel_abi::{IoStackLocation, Irp};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSourceIrp,
    InvalidOutput,
    InvalidTarget,
    Unsupported(InternalControlError),
}

#[must_use = "retain source IRP and target through source-local completion"]
pub(super) struct CapturedSourceInternalControl {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    source: SourceIrpTicket,
    source_instance: DriverInstance,
    source_stack_address: u64,
    target_address: u64,
    target: Option<HostedForwardTarget>,
    request: InternalControlCapture,
    output_address: u64,
    caller_tcb: u64,
    pinned: bool,
}

impl CapturedSourceInternalControl {
    pub(super) fn source_identity(&self) -> SourceIrpForwardIdentity {
        SourceIrpForwardIdentity::new(self.source, self.allocation)
            .expect("pinned source IRP identity")
    }

    pub(super) fn source_irp_address(&self) -> u64 {
        self.allocation.component_address
    }

    pub(super) fn source_pin_owned(&self) -> bool {
        self.pinned
    }

    pub(super) fn device_id(&self) -> nt_io_manager::DeviceId {
        self.target.as_ref().expect("target retained").device_id()
    }

    pub(super) fn request(&self) -> InternalControlCapture {
        self.request
    }

    pub(super) fn completion_command(
        &self,
        token: u64,
    ) -> Result<hosted_source_completion_lane::SourceCompletionCommand, CaptureError> {
        self.validate_source()?;
        Ok(hosted_source_completion_lane::SourceCompletionCommand {
            ticket: self.source,
            allocation: self.allocation,
            token,
        })
    }

    pub(super) fn completion_finished(&self) -> bool {
        hosted_source_irp_ledger::deferred_free_requested(self.source)
    }

    pub(super) fn validate_source(&self) -> Result<(), CaptureError> {
        if !self.pinned
            || !hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.source)
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        if inst.pml4 != self.source_instance.pml4
            || inst.exec_pool_va != self.source_instance.exec_pool_va
            || instance_domain_identity(inst) != Some(self.allocation.domain)
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        if let Some(target) = self.target.as_ref() {
            target.validate(io_manager_mut()).map_err(|_| CaptureError::InvalidTarget)?;
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

    /// The output is intentionally validated but not exposed. It may contain a provider VA,
    /// which requires a typed, generation-bound callable thunk before publication.
    pub(super) unsafe fn validate_output(&self) -> Result<(), CaptureError> {
        self.validate_source()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
        let irp = memory
            .read_value::<Irp>(self.allocation.component_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let stack = memory
            .read_value::<IoStackLocation>(self.source_stack_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let control = stack.device_io_control();
        if irp.user_buffer.0 != self.output_address
            || stack.major_function != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            || stack.device_object.0 != self.target_address
            || stack.file_object.0 != 0
            || control.io_control_code != self.request.code()
            || control.output_buffer_length != self.request.output_length()
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        if memory.contains(self.output_address, 8) {
            return Ok(());
        }
        drop(memory);
        if self.caller_tcb == inst.tcb
            && self.output_address >= FSD_STACK_VADDR
            && self.output_address.checked_add(8).is_some_and(|end| end <= FSD_STACK_VADDR + FSD_STACK_BYTES)
            && component_to_exec_va_for_instance(self.instance_index, inst, self.output_address, 8)
                .is_some()
        {
            return Ok(());
        }
        let runtime = hosted_driver_runtime_for_worker_component_range(
            self.instance_index,
            self.output_address,
            8,
        )
        .ok_or(CaptureError::InvalidOutput)?;
        if runtime.tcb != self.caller_tcb || runtime.domain != self.allocation.domain {
            return Err(CaptureError::InvalidOutput);
        }
        hosted_worker_component_to_exec_va(runtime, self.output_address, 8)
            .ok_or(CaptureError::InvalidOutput)?;
        Ok(())
    }

    pub(super) fn arm_callback_free(&self) -> Result<(), CaptureError> {
        self.validate_source()?;
        hosted_source_irp_ledger::arm_deferred_free(self.source)
            .then_some(())
            .ok_or(CaptureError::InvalidSourceIrp)
    }

    pub(super) fn release(&mut self, pending_terminal: bool) -> Result<(), CaptureError> {
        // Keep the target reference if the exact source cannot yet retire. The target is the
        // authority needed to reconcile a late provider terminal; releasing it first would
        // strand an uncertain source IRP with no checked route.
        if self.pinned {
            self.validate_source()?;
            let released = if pending_terminal {
                hosted_source_irp_ledger::release_pending_terminal(self.source, self.allocation)
            } else {
                hosted_source_irp_ledger::unpin(self.source)
            };
            if !released {
                return Err(CaptureError::InvalidSourceIrp);
            }
            self.pinned = false;
        }
        if let Some(target) = self.target.as_mut() {
            target.release(io_manager_mut()).map_err(|_| CaptureError::InvalidTarget)?;
            self.target = None;
        }
        Ok(())
    }
}

fn next_stack_address(allocation: SourceIrpAllocation, irp: &Irp) -> Option<u64> {
    if irp.type_ != WDM_X64_IO_TYPE_IRP as i16
        || irp.size as u64 != allocation.bytes
        || irp.stack_count != allocation.stack_count as i8
    {
        return None;
    }
    let location = u8::try_from(irp.current_location).ok()?;
    if location < 2 || location > allocation.stack_count.checked_add(1)? {
        return None;
    }
    let base = allocation.component_address.checked_add(WDM_X64_IRP_SIZE as u64)?;
    let current = base.checked_add((location as u64 - 1).checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)?)?;
    (irp.current_stack_location.0 == current)
        .then_some(current - WDM_X64_IO_STACK_LOCATION_SIZE as u64)
}

pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
    target_device_address: u64,
) -> Result<CapturedSourceInternalControl, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    let caller_tcb = hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge)
        .ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity =
        instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (source, allocation) = hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
        .ok_or(CaptureError::InvalidSourceIrp)?;
    let result = (|| {
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSourceIrp)?;
        let irp = memory.read_value::<Irp>(source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let stack_address = next_stack_address(allocation, &irp)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let stack = memory.read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
        let control = stack.device_io_control();
        if stack.device_object.0 != target_device_address
            || stack.file_object.0 != 0
            || irp.mdl_address.0 != 0
            || irp.associated_irp_system_buffer.0 != 0
            || control.type3_input_buffer.0 != 0
        {
            return Err(CaptureError::InvalidSourceIrp);
        }
        let request = InternalControlCapture::new(
            stack.major_function,
            stack.minor_function,
            control.io_control_code,
            irp.requestor_mode == 0,
            control.input_buffer_length,
            control.output_buffer_length,
        ).map_err(CaptureError::Unsupported)?;
        let output_address = irp.user_buffer.0;
        if output_address == 0 {
            return Err(CaptureError::InvalidOutput);
        }
        drop(memory);
        let target = HostedForwardTarget::capture(io_manager_mut(), domain, target_device_address)
            .map_err(|_| CaptureError::InvalidTarget)?;
        let captured = CapturedSourceInternalControl {
            instance_index,
            allocation,
            source,
            source_instance: inst,
            source_stack_address: stack_address,
            target_address: target_device_address,
            target: Some(target),
            request,
            output_address,
            caller_tcb,
            pinned: true,
        };
        if let Err(error) = captured.validate_output() {
            let mut captured = captured;
            captured.target.as_mut().expect("captured target")
                .release(io_manager_mut())
                .expect("unentered internal-control target rollback");
            return Err(error);
        }
        Ok(captured)
    })();
    if result.is_err() {
        assert!(hosted_source_irp_ledger::unpin(source), "unentered internal-control source rollback");
    }
    result
}
