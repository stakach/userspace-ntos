//! Exact source ownership for a file-less, buffered lower device-control IRP.
//!
//! Class drivers can allocate their own IRP and SystemBuffer, then send it to a
//! foreign PDO. Neither source pointer is meaningful in the provider domain.

use super::*;
use super::hosted_source_pool_memory::SourcePoolMemory;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    retained_query_path_forward::SourceIrpTicket,
    source_irp_auxiliary::SourcePoolAllocationIdentity,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity},
    HostedDomainIdentity,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSource,
    InvalidTarget,
    Unsupported,
}

#[derive(Clone, Copy)]
pub(super) struct BufferedControlRequest {
    pub code: u32,
    pub input_len: u32,
    pub output_len: u32,
    pub initial_information: u64,
}

#[must_use = "keep the source IRP and its exact buffer until completion and ACK"]
pub(super) struct CapturedBufferedControl {
    instance_index: usize,
    instance: DriverInstance,
    source: SourceIrpTicket,
    allocation: SourceIrpAllocation,
    stack_address: u64,
    target_address: u64,
    target: Option<HostedForwardTarget>,
    system_address: u64,
    system_identity: Option<SourcePoolAllocationIdentity>,
    request: BufferedControlRequest,
    input: Vec<u8>,
    pinned: bool,
}

impl CapturedBufferedControl {
    pub(super) fn identity(&self) -> SourceIrpForwardIdentity {
        SourceIrpForwardIdentity::new(self.source, self.allocation)
            .expect("pinned source IRP")
    }

    pub(super) fn address(&self) -> u64 { self.allocation.component_address }
    pub(super) fn device_id(&self) -> nt_io_manager::DeviceId {
        self.target.as_ref().expect("retained target").device_id()
    }
    pub(super) fn request(&self) -> BufferedControlRequest { self.request }
    pub(super) fn input(&self) -> &[u8] { &self.input }
    pub(super) fn completion_finished(&self) -> bool {
        hosted_source_irp_ledger::deferred_free_requested(self.source)
    }
    pub(super) fn validate(&self) -> Result<(), CaptureError> {
        if !self.pinned
            || !hosted_source_irp_ledger::matches(self.instance_index, self.allocation, self.source)
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

    /// Check mutable packet fields before provider entry. After entry the native
    /// stack location and IoStatus may legitimately change.
    pub(super) unsafe fn validate_before_entry(&self) -> Result<(), CaptureError> {
        self.validate()?;
        let memory = SourcePoolMemory::new(self.instance).ok_or(CaptureError::InvalidSource)?;
        let irp = memory.read_value::<Irp>(self.address()).ok_or(CaptureError::InvalidSource)?;
        let stack = memory.read_value::<IoStackLocation>(self.stack_address)
            .ok_or(CaptureError::InvalidSource)?;
        let control = stack.device_io_control();
        if stack.major_function != major::IRP_MJ_DEVICE_CONTROL
            || stack.device_object.0 != self.target_address
            || stack.file_object.0 != 0
            || control.io_control_code != self.request.code
            || control.input_buffer_length != self.request.input_len
            || control.output_buffer_length != self.request.output_len
            || irp.associated_irp_system_buffer.0 != self.system_address
            || irp.mdl_address.0 != 0
            || (self.system_identity.is_some() && hosted_source_irp_ledger::pool_range_identity_unlocked(
                self.instance,
                self.system_address,
                u64::from(self.request.input_len.max(self.request.output_len)),
            ) != self.system_identity)
        { return Err(CaptureError::InvalidSource); }
        Ok(())
    }

    pub(super) unsafe fn write_result(
        &self,
        status: i32,
        information: u64,
        output: &[u8],
    ) -> Result<(), CaptureError> {
        self.validate()?;
        if output.len() != self.request.output_len as usize {
            return Err(CaptureError::InvalidSource);
        }
        let memory = SourcePoolMemory::new(self.instance).ok_or(CaptureError::InvalidSource)?;
        if self.system_identity.is_some() && hosted_source_irp_ledger::pool_range_identity_unlocked(
            self.instance,
            self.system_address,
            u64::from(self.request.input_len.max(self.request.output_len)),
        ) != self.system_identity {
            return Err(CaptureError::InvalidSource);
        }
        let irp = memory.read_value::<Irp>(self.address()).ok_or(CaptureError::InvalidSource)?;
        if irp.associated_irp_system_buffer.0 != self.system_address {
            return Err(CaptureError::InvalidSource);
        }
        if !output.is_empty() && !memory.write(self.system_address, output) {
            return Err(CaptureError::InvalidSource);
        }
        if !memory.write(self.address() + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET, &status.to_le_bytes())
            || !memory.write(self.address() + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET, &information.to_le_bytes())
        {
            return Err(CaptureError::InvalidSource);
        }
        drop(memory);
        hosted_source_irp_ledger::arm_deferred_free(self.source)
            .then_some(()).ok_or(CaptureError::InvalidSource)
    }

    /// A known refusal before the lower driver enters must still update the
    /// caller-owned IoStatus. Classpnp reads that field even when IoCallDriver
    /// returns an error directly, and no local completion callback runs here.
    pub(super) unsafe fn write_refusal(&self, status: i32) -> Result<(), CaptureError> {
        self.validate_before_entry()?;
        let memory = SourcePoolMemory::new(self.instance).ok_or(CaptureError::InvalidSource)?;
        if !memory.write(self.address() + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET, &status.to_le_bytes())
            || !memory.write(self.address() + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET, &0u64.to_le_bytes())
        {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    pub(super) fn release(&mut self, pending_terminal: bool) -> Result<(), CaptureError> {
        if self.pinned {
            self.validate()?;
            let done = if pending_terminal {
                hosted_source_irp_ledger::release_pending_terminal(self.source, self.allocation)
            } else {
                hosted_source_irp_ledger::unpin(self.source)
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

fn next_stack_address(allocation: SourceIrpAllocation, irp: &Irp) -> Option<u64> {
    if irp.type_ != WDM_X64_IO_TYPE_IRP as i16
        || irp.size as u64 != allocation.bytes
        || irp.stack_count != allocation.stack_count as i8
    { return None; }
    let location = u8::try_from(irp.current_location).ok()?;
    if location < 2 || location > allocation.stack_count.checked_add(1)? { return None; }
    let base = allocation.component_address.checked_add(WDM_X64_IRP_SIZE as u64)?;
    let current = base.checked_add((location as u64 - 1).checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)?)?;
    (irp.current_stack_location.0 == current).then_some(current - WDM_X64_IO_STACK_LOCATION_SIZE as u64)
}

pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    source_address: u64,
    target_address: u64,
) -> Result<CapturedBufferedControl, CaptureError> {
    let (index, inst) = instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    hosted_driver_pump_caller_tcb(ch, reply_cap, badge).ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity = instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (ticket, allocation) = hosted_source_irp_ledger::pin(index, domain, source_address)
        .ok_or(CaptureError::InvalidSource)?;
    if allocation.owner != nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedDriver(index) {
        assert!(hosted_source_irp_ledger::unpin(ticket), "wrong-owner buffered control rollback");
        return Err(CaptureError::InvalidSource);
    }
    let result = (|| {
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
        let irp = memory.read_value::<Irp>(source_address).ok_or(CaptureError::InvalidSource)?;
        let stack_address = next_stack_address(allocation, &irp).ok_or(CaptureError::InvalidSource)?;
        let stack = memory.read_value::<IoStackLocation>(stack_address).ok_or(CaptureError::InvalidSource)?;
        let control = stack.device_io_control();
        if stack.major_function != major::IRP_MJ_DEVICE_CONTROL
            || stack.device_object.0 != target_address
            || stack.file_object.0 != 0
            || irp.mdl_address.0 != 0
            || control.io_control_code & 3 != ioctl::METHOD_BUFFERED
        { return Err(CaptureError::Unsupported); }
        let system_address = irp.associated_irp_system_buffer.0;
        let capacity = control.input_buffer_length.max(control.output_buffer_length);
        let identity = if capacity == 0 {
            if system_address != 0 { return Err(CaptureError::InvalidSource); }
            None
        } else {
            Some(hosted_source_irp_ledger::pool_range_identity_unlocked(inst, system_address, u64::from(capacity))
                .ok_or(CaptureError::InvalidSource)?)
        };
        let mut input = Vec::new();
        input.try_reserve_exact(control.input_buffer_length as usize).map_err(|_| CaptureError::InvalidSource)?;
        input.resize(control.input_buffer_length as usize, 0);
        if !input.is_empty() && !memory.read(system_address, &mut input) {
            return Err(CaptureError::InvalidSource);
        }
        drop(memory);
        let target = HostedForwardTarget::capture(io_manager_mut(), domain, target_address)
            .map_err(|_| CaptureError::InvalidTarget)?;
        Ok(CapturedBufferedControl {
            instance_index: index, instance: inst, source: ticket, allocation,
            stack_address, target_address, target: Some(target), system_address,
            system_identity: identity,
            request: BufferedControlRequest {
                code: control.io_control_code,
                input_len: control.input_buffer_length,
                output_len: control.output_buffer_length,
                initial_information: irp.io_status.information,
            },
            input, pinned: true,
        })
    })();
    if result.is_err() {
        assert!(hosted_source_irp_ledger::unpin(ticket), "unentered buffered control rollback");
    }
    result
}
