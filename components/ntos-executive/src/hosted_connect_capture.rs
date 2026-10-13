//! Captured class-driver CONNECT source before the foreign port driver is entered.

use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    retained_connect_forward::{
        ConnectBufferSource, ConnectControl, ConnectPayloadIdentity, RetainedConnectForward,
    },
    retained_query_path_forward::SourceIrpTicket,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity},
    HostedDomainIdentity,
};
use nt_kernel_abi::{IoStackLocation, Irp};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSource,
    InvalidTarget,
    InvalidPayload,
}

#[must_use = "retain through source completion and exact target release"]
pub(super) struct CapturedConnect {
    instance_index: usize,
    source_ticket: SourceIrpTicket,
    source_allocation: SourceIrpAllocation,
    source_irp_address: u64,
    source_stack_address: u64,
    source_stack: IoStackLocation,
    source_pinned: bool,
    stack_lease: hosted_source_stack_lease::SourceStackLeaseId,
    stack_released: bool,
    target_retired: bool,
    payload: ConnectPayloadIdentity,
    forward: Option<RetainedConnectForward>,
}

impl CapturedConnect {
    pub(super) fn source_irp_address(&self) -> u64 {
        self.source_irp_address
    }

    pub(super) fn source_identity(&self) -> SourceIrpForwardIdentity {
        self.payload.forward.source
    }

    pub(super) fn payload(&self) -> ConnectPayloadIdentity {
        self.payload
    }

    pub(super) fn forward_mut(&mut self) -> Option<&mut RetainedConnectForward> {
        self.forward.as_mut()
    }

    pub(super) fn source_pin_owned(&self) -> bool {
        self.source_pinned
    }

    pub(super) fn completion_command(
        &self,
        token: u64,
    ) -> Result<hosted_source_completion_lane::SourceCompletionCommand, CaptureError> {
        self.validate_pin()?;
        Ok(hosted_source_completion_lane::SourceCompletionCommand {
            ticket: self.source_ticket,
            allocation: self.source_allocation,
            token,
        })
    }

    pub(super) unsafe fn source_irp_exec(&self) -> Result<u64, CaptureError> {
        self.validate_pin()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        hosted_instance_pool_allocation_exec_if_live(
            inst,
            self.source_irp_address,
            self.source_allocation.bytes,
        )
        .ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn arm_callback_free(&self) -> Result<(), CaptureError> {
        self.validate_pin()?;
        hosted_source_irp_ledger::arm_deferred_free(self.source_ticket)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn completion_finished(&self) -> bool {
        match self.source_allocation.owner {
            nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedDriver(_) => {
                hosted_source_irp_ledger::deferred_free_requested(self.source_ticket)
            }
            nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedCaller(_) => {
                hosted_source_irp_ledger::caller_terminal_ready(
                    self.source_ticket,
                    self.source_allocation,
                )
            }
            nt_io_manager::source_irp_ledger::SourceIrpOwner::Win32k => false,
        }
    }

    /// Source completion must be observed separately from the provider's terminal return.
    /// Retire the exact target, stack and source only after both facts are proved.
    pub(super) unsafe fn retire_after_source_completion(&mut self) -> Result<(), CaptureError> {
        if !self.source_pinned {
            return Ok(());
        }
        if !self.completion_finished() {
            return Err(CaptureError::InvalidSource);
        }
        if !self.stack_released {
            let forward = self.forward.as_ref().ok_or(CaptureError::InvalidTarget)?;
            if !hosted_source_stack_lease::release_terminal(self.stack_lease, forward) {
                return Err(CaptureError::InvalidPayload);
            }
            self.stack_released = true;
        }
        if !self.target_retired {
            let owned = self.forward.take().ok_or(CaptureError::InvalidTarget)?;
            if let Err((_, retained)) = owned.retire_after_source_completion(io_manager_mut()) {
                self.forward = Some(retained);
                return Err(CaptureError::InvalidTarget);
            }
            self.target_retired = true;
        }
        if !hosted_source_irp_ledger::release_pending_terminal(
            self.source_ticket,
            self.source_allocation,
        ) {
            return Err(CaptureError::InvalidSource);
        }
        self.source_pinned = false;
        Ok(())
    }

    pub(super) unsafe fn retain_indeterminate(&mut self) -> Result<(), CaptureError> {
        let forward = self.forward.as_ref().ok_or(CaptureError::InvalidTarget)?;
        hosted_source_stack_lease::retain_indeterminate(self.stack_lease, forward)
            .then_some(())
            .ok_or(CaptureError::InvalidPayload)
    }

    /// Revalidate the generation-bearing source IRP and its immutable next-stack CONNECT fields
    /// before entering any foreign provider effect.
    pub(super) unsafe fn validate_source(&self) -> Result<(), CaptureError> {
        self.validate_pin()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
        let irp = memory
            .read_value::<Irp>(self.source_irp_address)
            .ok_or(CaptureError::InvalidSource)?;
        let stack = memory
            .read_value::<IoStackLocation>(self.source_stack_address)
            .ok_or(CaptureError::InvalidSource)?;
        if irp.type_ != WDM_X64_IO_TYPE_IRP as i16
            || irp.size as u64 != self.source_allocation.bytes
            || irp.stack_count != self.source_allocation.stack_count as i8
            || stack != self.source_stack
            || stack.device_io_control().type3_input_buffer.0 != self.payload.input_pointer
        {
            return Err(CaptureError::InvalidSource);
        }
        let forward = self.forward.as_ref().ok_or(CaptureError::InvalidTarget)?;
        forward
            .validate_payload(io_manager_mut(), self.payload)
            .map_err(|_| CaptureError::InvalidPayload)
    }

    fn validate_pin(&self) -> Result<(), CaptureError> {
        if !self.source_pinned
            || !hosted_source_irp_ledger::matches(
                self.instance_index,
                self.source_allocation,
                self.source_ticket,
            )
        {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    /// Cancel only a forward that has not entered the port. Every failed physical release keeps
    /// its exact receipt, so a caller must retain this object and retry retirement later.
    pub(super) unsafe fn abort_unentered(&mut self) -> Result<(), CaptureError> {
        if !self.stack_released {
            let forward = self.forward.as_ref().ok_or(CaptureError::InvalidTarget)?;
            if !hosted_source_stack_lease::release_unentered(self.stack_lease, forward) {
                return Err(CaptureError::InvalidPayload);
            }
            self.stack_released = true;
        }
        if let Some(owned) = self.forward.take() {
            let identity = owned.identity();
            if let Err((_, retained)) = owned.abort_before_enter(io_manager_mut(), identity) {
                self.forward = Some(retained);
                return Err(CaptureError::InvalidTarget);
            }
        }
        if !self.source_pinned {
            return Ok(());
        }
        if !hosted_source_irp_ledger::unpin(self.source_ticket) {
            return Err(CaptureError::InvalidSource);
        }
        self.source_pinned = false;
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
    let base = allocation
        .component_address
        .checked_add(WDM_X64_IRP_SIZE as u64)?;
    let current = base
        .checked_add((location as u64 - 1).checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)?)?;
    (irp.current_stack_location.0 == current)
        .then(|| current - WDM_X64_IO_STACK_LOCATION_SIZE as u64)
}

pub(super) unsafe fn capture(
    channel: &crate::spawn_hosts::PumpChannel,
    reply: u64,
    source_irp_address: u64,
    target_device_address: u64,
    expected_stack_device: u64,
    expected_class_driver: nt_io_manager::DriverId,
) -> Result<CapturedConnect, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(channel, reply).ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity =
        instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (source_ticket, source_allocation) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
            .ok_or(CaptureError::InvalidSource)?;
    let result = (|| {
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
        let irp = memory
            .read_value::<Irp>(source_irp_address)
            .ok_or(CaptureError::InvalidSource)?;
        let stack_address =
            next_stack_address(source_allocation, &irp).ok_or(CaptureError::InvalidSource)?;
        let stack = memory
            .read_value::<IoStackLocation>(stack_address)
            .ok_or(CaptureError::InvalidSource)?;
        let params = stack.device_io_control();
        let control = match params.io_control_code {
            code if code == ConnectControl::Keyboard.code() => ConnectControl::Keyboard,
            code if code == ConnectControl::Mouse.code() => ConnectControl::Mouse,
            _ => return Err(CaptureError::InvalidPayload),
        };
        if stack.major_function != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            || stack.minor_function != 0
            || stack.file_object.0 != 0
            || stack.device_object.0 != expected_stack_device
            || params.input_buffer_length != 16
            || params.output_buffer_length != 0
            || params.type3_input_buffer.0 == 0
            || irp.mdl_address.0 != 0
            || irp.associated_irp_system_buffer.0 != 0
            || irp.user_buffer.0 != 0
            || irp.flags & IRP_BUFFERED_IO != 0
        {
            return Err(CaptureError::InvalidSource);
        }
        drop(memory);
        let source_identity = SourceIrpForwardIdentity::new(source_ticket, source_allocation)
            .ok_or(CaptureError::InvalidSource)?;
        let target = HostedForwardTarget::capture(io_manager_mut(), domain, target_device_address)
            .map_err(|_| CaptureError::InvalidTarget)?;
        let mut forward = RetainedConnectForward::new(source_identity, target, control);
        let identity = forward.identity();
        let stack_capture = hosted_source_stack_lease::capture(
            channel,
            reply,
            identity,
            params.type3_input_buffer.0,
        );
        let Some((stack_lease, stack_range, snapshot)) = stack_capture else {
            if let Err((_, retained)) = forward.abort_before_enter(io_manager_mut(), identity) {
                core::mem::forget(retained);
            }
            return Err(CaptureError::InvalidPayload);
        };
        let class_address = u64::from_le_bytes(snapshot[..8].try_into().unwrap());
        let class_service = u64::from_le_bytes(snapshot[8..].try_into().unwrap());
        let class_registration =
            io_manager_mut().hosted_device_pointer_registration(domain, class_address);
        let image_end = inst
            .image_frames
            .checked_mul(0x1000)
            .and_then(|length| FSD_CODE_VA.checked_add(length))
            .unwrap_or(0);
        let payload = class_registration.map(|class_device| ConnectPayloadIdentity {
            forward: identity,
            buffer: ConnectBufferSource::Stack(stack_range),
            input_pointer: params.type3_input_buffer.0,
            input_length: 16,
            snapshot,
            class_device,
            class_service,
        });
        let expected_class_device = class_registration.map(|registration| registration.device_id());
        let class_owned = expected_class_device.is_some_and(|device_id| {
            io_manager_mut().device(device_id).is_some_and(|device| {
                device.driver_id == expected_class_driver && device.attached_to.is_none()
            })
        });
        if !(FSD_CODE_VA..image_end).contains(&class_service)
            || !class_owned
            || hosted_device_allocations::capture_allocation(inst, class_address).is_err()
            || payload.is_none_or(|payload| {
                forward
                    .capture_payload(io_manager_mut(), payload, expected_class_device.unwrap())
                    .is_err()
            })
        {
            let _ = hosted_source_stack_lease::release_unentered(stack_lease, &forward);
            if let Err((_, retained)) = forward.abort_before_enter(io_manager_mut(), identity) {
                core::mem::forget(retained);
            }
            return Err(CaptureError::InvalidPayload);
        }
        Ok(CapturedConnect {
            instance_index,
            source_ticket,
            source_allocation,
            source_irp_address,
            source_stack_address: stack_address,
            source_stack: stack,
            source_pinned: true,
            stack_lease,
            stack_released: false,
            target_retired: false,
            payload: payload.unwrap(),
            forward: Some(forward),
        })
    })();
    if result.is_err() {
        assert!(
            hosted_source_irp_ledger::unpin(source_ticket),
            "unentered CONNECT source pin rollback"
        );
    }
    result
}
