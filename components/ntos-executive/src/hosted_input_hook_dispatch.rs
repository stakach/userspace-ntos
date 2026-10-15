//! Source ownership for i8042's queued reverse HOOK after a pending CONNECT.
//!
//! The work item builds a second, port-owned METHOD_NEITHER IRP and sends it to the attached
//! class PortDO. Its input is a mutable 48/40-byte struct inside the port FDO extension. A
//! provider may change that struct. The caller must dispatch through the exact class alias and
//! return the actual mutated bytes; a generic immutable-input IOCTL path is insufficient.

use super::hosted_source_pool_memory::SourcePoolMemory;
use super::*;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    retained_connect_forward::{
        ConnectControl, ConnectPayloadIdentity, HookBufferSource, HookDeviceExtensionRange,
        HookPayloadIdentity, I8042ConnectHookSequence, RetainedConnectForward,
    },
    retained_query_path_forward::SourceIrpTicket,
    source_irp_auxiliary::SourcePoolAllocationIdentity,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpOwner},
    HostedDevicePointerRegistration,
};
use nt_kernel_abi::{IoStackLocation, Irp};
use nt_security::ClientMemory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HookError {
    WrongCaller,
    WrongSource,
    WrongAlias,
    WrongPayload,
    WrongPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Captured,
    Entered,
    Pending,
    SequenceTerminal(nt_status::NtStatus),
    Terminal(nt_status::NtStatus),
    SourcePublished(nt_status::NtStatus),
    Retired,
    Blocked,
}

/// A source IRP pin, target reference, immutable stack snapshot and mutable payload owner.
/// Neither a pending class result nor a lost dispatch reply releases these references.
#[must_use = "retain through exact class terminal and port source completion"]
pub(super) struct HookWork {
    instance_index: usize,
    source_instance: DriverInstance,
    source_ticket: SourceIrpTicket,
    source_allocation: SourceIrpAllocation,
    source_irp: u64,
    source_stack_address: u64,
    source_stack: IoStackLocation,
    source_pinned: bool,
    target_released: bool,
    reverse_owner_id: u64,
    source_device: HostedDevicePointerRegistration,
    source_device_allocation: SourcePoolAllocationIdentity,
    class_target: HostedForwardTarget,
    payload: HookPayloadIdentity,
    pending_irp: Option<IrpId>,
    phase: Phase,
}

/// The immutable dispatch command. The caller supplies the actual class dispatch and returns
/// its terminal or pending result to this owner; this token never authorizes a second entry.
#[derive(Clone, Copy)]
pub(super) struct HookDispatchTicket {
    pub(super) target: HostedDevicePointerRegistration,
    pub(super) source: SourceIrpForwardIdentity,
    pub(super) control_code: u32,
    pub(super) input_length: u32,
    pub(super) input: [u8; 48],
}

fn next_stack(allocation: SourceIrpAllocation, irp: &Irp) -> Option<u64> {
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
        .then_some(current - WDM_X64_IO_STACK_LOCATION_SIZE as u64)
}

impl HookWork {
    pub(super) fn class_target_registration(&self) -> HostedDevicePointerRegistration {
        self.class_target.registration()
    }

    pub(super) fn source_identity(&self) -> SourceIrpForwardIdentity {
        self.payload.source
    }

    pub(super) fn reverse_owner_id(&self) -> u64 {
        self.reverse_owner_id
    }

    pub(super) fn source_irp_address(&self) -> u64 {
        self.source_irp
    }

    pub(super) unsafe fn capture(
        ch: &crate::spawn_hosts::PumpChannel,
        reply_cap: u64,
        source_irp: u64,
        target_alias: u64,
        reverse_owner_id: u64,
        connect: ConnectPayloadIdentity,
    ) -> Result<Self, HookError> {
        let (instance_index, inst) =
            instance_for_pump_channel(ch, reply_cap).ok_or(HookError::WrongCaller)?;
        let domain = instance_domain_identity(inst).ok_or(HookError::WrongCaller)?;
        let prepared = hosted_reverse_class_projection::validate(reverse_owner_id)
            .map_err(|_| HookError::WrongAlias)?;
        let source_device = hosted_reverse_class_projection::port_source_for_hook(reverse_owner_id)
            .map_err(|_| HookError::WrongAlias)?;
        if source_device.domain() != domain
            || target_alias != prepared.port_domain_port_do
            || prepared.port_do_registration.domain() != domain
            || connect.forward.target.device_id() != source_device.device_id()
        {
            return Err(HookError::WrongAlias);
        }
        let (source_ticket, source_allocation) =
            hosted_source_irp_ledger::pin(instance_index, domain, source_irp)
                .ok_or(HookError::WrongSource)?;
        let result = (|| {
            let source_alloc =
                hosted_device_allocations::capture_allocation(inst, source_device.address())
                    .map_err(|_| HookError::WrongSource)?;
            let memory = SourcePoolMemory::new(inst).ok_or(HookError::WrongSource)?;
            let irp = memory
                .read_value::<Irp>(source_irp)
                .ok_or(HookError::WrongSource)?;
            let stack_address =
                next_stack(source_allocation, &irp).ok_or(HookError::WrongSource)?;
            let stack = memory
                .read_value::<IoStackLocation>(stack_address)
                .ok_or(HookError::WrongSource)?;
            let params = stack.device_io_control();
            let length = match connect.forward.control {
                ConnectControl::Keyboard => 48,
                ConnectControl::Mouse => 40,
            };
            let code = nt_io_abi::ioctl::ctl_code(
                match connect.forward.control {
                    ConnectControl::Keyboard => 0x0b,
                    ConnectControl::Mouse => 0x0f,
                },
                0x0ff0,
                nt_io_abi::ioctl::METHOD_NEITHER,
                0,
            );
            if stack.major_function != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                || stack.minor_function != 0
                || stack.file_object.0 != 0
                || stack.device_object.0 != target_alias
                || params.io_control_code != code
                || params.input_buffer_length != length as u32
                || params.output_buffer_length != 0
                || params.type3_input_buffer.0 == 0
                || irp.mdl_address.0 != 0
                || irp.associated_irp_system_buffer.0 != 0
                || irp.user_buffer.0 != 0
            {
                return Err(HookError::WrongPayload);
            }
            let device_exec = memory
                .read_value::<u64>(source_device.address() + 0x40)
                .ok_or(HookError::WrongSource)?;
            let end = source_alloc
                .component_address
                .checked_add(source_alloc.capacity)
                .ok_or(HookError::WrongSource)?;
            if device_exec < source_alloc.component_address
                || device_exec >= end
                || params.type3_input_buffer.0 < device_exec
                || params
                    .type3_input_buffer
                    .0
                    .checked_add(length)
                    .is_none_or(|tail| tail > end)
            {
                return Err(HookError::WrongPayload);
            }
            let mut snapshot = [0; 48];
            if !memory.read(
                params.type3_input_buffer.0,
                &mut snapshot[..length as usize],
            ) {
                return Err(HookError::WrongPayload);
            }
            drop(memory);
            let source_identity = SourceIrpForwardIdentity::new(source_ticket, source_allocation)
                .ok_or(HookError::WrongSource)?;
            let class_target = HostedForwardTarget::capture(io_manager_mut(), domain, target_alias)
                .map_err(|_| HookError::WrongAlias)?;
            if class_target.registration() != prepared.port_do_registration {
                let mut class_target = class_target;
                if class_target.release(io_manager_mut()).is_err() {
                    core::mem::forget(class_target);
                }
                return Err(HookError::WrongAlias);
            }
            let payload = HookPayloadIdentity {
                connect,
                source: source_identity,
                buffer: HookBufferSource::DeviceExtension(HookDeviceExtensionRange {
                    owner: source_device,
                    base: device_exec,
                    bytes: end - device_exec,
                    generation: source_alloc.pool_generation,
                }),
                input_pointer: params.type3_input_buffer.0,
                input_length: length,
                snapshot,
                class_target: prepared.port_do_registration,
            };
            Ok(Self {
                instance_index,
                source_instance: inst,
                source_ticket,
                source_allocation,
                source_irp,
                source_stack_address: stack_address,
                source_stack: stack,
                source_pinned: true,
                target_released: false,
                reverse_owner_id,
                source_device,
                source_device_allocation: source_alloc,
                class_target,
                payload,
                pending_irp: None,
                phase: Phase::Captured,
            })
        })();
        if result.is_err() && !hosted_source_irp_ledger::unpin(source_ticket) {
            crate::provider_bugcheck::report(0xc4, [source_irp, reverse_owner_id, 0, 0]);
        }
        result
    }

    /// Enter the pure ordering contract immediately before actual class dispatch. The caller
    /// retains this owner and may never replay after this point, including on transport loss.
    pub(super) unsafe fn begin_dispatch(
        &mut self,
        connect: &RetainedConnectForward,
        sequence: &mut I8042ConnectHookSequence,
    ) -> Result<HookDispatchTicket, HookError> {
        if self.phase != Phase::Captured
            || !self.validate_source()
            || !self.original_payload_matches()
            || hosted_reverse_class_projection::validate(self.reverse_owner_id).is_err()
        {
            return Err(HookError::WrongPhase);
        }
        sequence
            .enter_hook(
                io_manager_mut(),
                connect,
                self.payload,
                &self.class_target,
                self.payload.source,
                self.source_device,
            )
            .map_err(|_| HookError::WrongPayload)?;
        self.phase = Phase::Entered;
        Ok(HookDispatchTicket {
            target: self.class_target.registration(),
            source: self.payload.source,
            control_code: self.payload.code(),
            input_length: self.payload.input_length as u32,
            input: self.payload.snapshot,
        })
    }

    pub(super) fn record_pending(&mut self, irp_id: IrpId) -> Result<(), HookError> {
        if self.phase != Phase::Entered || irp_id.raw() == 0 {
            return Err(HookError::WrongPhase);
        }
        self.pending_irp = Some(irp_id);
        self.phase = Phase::Pending;
        Ok(())
    }

    /// Observe a real class terminal, including the mutable METHOD_NEITHER bytes. The original
    /// port IRP remains pinned until its separate completion is acknowledged.
    pub(super) unsafe fn observe_terminal(
        &mut self,
        sequence: &mut I8042ConnectHookSequence,
        status: nt_status::NtStatus,
        updated: &[u8],
        completed_irp: Option<IrpId>,
    ) -> Result<(SourceIrpForwardIdentity, nt_status::NtStatus), HookError> {
        if !matches!(self.phase, Phase::Entered | Phase::Pending | Phase::SequenceTerminal(_))
            || status == nt_status::NtStatus::PENDING
            || updated.len() != self.payload.input_length as usize
            || completed_irp != self.pending_irp
            || !self.validate_source()
        {
            return Err(HookError::WrongPhase);
        }
        if let Some(irp_id) = completed_irp {
            let completion =
                completed_device_control_irp_exact(irp_id.raw()).ok_or(HookError::WrongSource)?;
            let class_device = self.class_target.device_id();
            let class_driver = io_manager_mut()
                .device(class_device)
                .ok_or(HookError::WrongAlias)?
                .driver_id;
            if completion.client_id != IO_MANAGER_COMPONENT_ID
                || completion.device_id != class_device.raw()
                || completion.driver_id != class_driver.raw()
                || completion.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                || completion.status != status.raw() as u32
                || completion.information != 0
            {
                self.phase = Phase::Blocked;
                return Err(HookError::WrongSource);
            }
        }
        if let Phase::SequenceTerminal(previous) = self.phase {
            if previous != status {
                self.phase = Phase::Blocked;
                return Err(HookError::WrongPhase);
            }
        } else {
            if sequence
                .observe_hook_terminal(self.payload.source, status)
                .is_err()
            {
                self.phase = Phase::Blocked;
                return Err(HookError::WrongPhase);
            }
            self.phase = Phase::SequenceTerminal(status);
        }
        let memory = SourcePoolMemory::new(self.source_instance).ok_or(HookError::WrongSource)?;
        if !memory.write(self.payload.input_pointer, updated) {
            return Err(HookError::WrongSource);
        }
        self.phase = Phase::Terminal(status);
        Ok((self.payload.source, status))
    }

    /// Only a work item that never entered class dispatch can cancel its source capture.
    pub(super) unsafe fn abort_unentered(&mut self) -> Result<(), HookError> {
        if self.phase != Phase::Captured {
            return Err(HookError::WrongPhase);
        }
        if self.class_target.release(io_manager_mut()).is_err() {
            self.phase = Phase::Blocked;
            return Err(HookError::WrongAlias);
        }
        if !hosted_source_irp_ledger::unpin(self.source_ticket) {
            self.phase = Phase::Blocked;
            return Err(HookError::WrongSource);
        }
        self.source_pinned = false;
        self.phase = Phase::Retired;
        Ok(())
    }

    /// Publish terminal IoStatus before the port's IoCompleteRequest unwinds this source IRP.
    pub(super) unsafe fn publish_source_terminal(
        &mut self,
    ) -> Result<nt_status::NtStatus, HookError> {
        let Phase::Terminal(status) = self.phase else {
            return Err(HookError::WrongPhase);
        };
        if !self.validate_source() {
            return Err(HookError::WrongSource);
        }
        let memory = SourcePoolMemory::new(self.source_instance).ok_or(HookError::WrongSource)?;
        let status_bytes = (status.raw() as u32).to_le_bytes();
        if !memory.write(
            self.source_irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET as u64,
            &status_bytes,
        ) {
            return Err(HookError::WrongSource);
        }
        if !memory.write(
            self.source_irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET as u64,
            &0u64.to_le_bytes(),
        ) {
            // The status write already happened; never replay an uncertain partial publish.
            self.phase = Phase::Blocked;
            return Err(HookError::WrongSource);
        }
        drop(memory);
        if !hosted_source_irp_ledger::arm_deferred_free(self.source_ticket) {
            self.phase = Phase::Blocked;
            return Err(HookError::WrongSource);
        }
        self.phase = Phase::SourcePublished(status);
        Ok(status)
    }

    /// Only a failure before publication's first native write leaves terminal publication
    /// retryable. An uncertain write or deferred-free arm moves the work to Blocked instead.
    pub(super) fn terminal_publication_retryable(&self) -> bool {
        matches!(self.phase, Phase::Terminal(_))
    }

    pub(super) fn terminal_observation_retryable(&self) -> bool {
        matches!(self.phase, Phase::Entered | Phase::Pending | Phase::SequenceTerminal(_))
    }

    /// Called only after the port component's exact source completion and retained reply ACK.
    pub(super) unsafe fn retire_after_source_completion(&mut self) -> Result<(), HookError> {
        if !matches!(self.phase, Phase::SourcePublished(_)) || !self.source_pinned {
            return Err(HookError::WrongPhase);
        }
        let completed = match self.source_allocation.owner {
            SourceIrpOwner::HostedDriver(_) => {
                hosted_source_irp_ledger::deferred_free_requested(self.source_ticket)
            }
            SourceIrpOwner::HostedCaller(_) => hosted_source_irp_ledger::caller_terminal_ready(
                self.source_ticket,
                self.source_allocation,
            ),
            SourceIrpOwner::Win32k => false,
        };
        if !completed {
            return Err(HookError::WrongSource);
        }
        if let Some(irp_id) = self.pending_irp {
            if acknowledge_completed_irp_strict(irp_id.raw()).is_err() {
                return Err(HookError::WrongSource);
            }
            self.pending_irp = None;
        }
        if !self.target_released {
            if self.class_target.release(io_manager_mut()).is_err() {
                return Err(HookError::WrongAlias);
            }
            self.target_released = true;
        }
        if !hosted_source_irp_ledger::release_pending_terminal(
            self.source_ticket,
            self.source_allocation,
        ) {
            return Err(HookError::WrongSource);
        }
        self.source_pinned = false;
        self.phase = Phase::Retired;
        Ok(())
    }

    unsafe fn validate_source(&self) -> bool {
        if !self.source_pinned
            || !hosted_source_irp_ledger::matches(
                self.instance_index,
                self.source_allocation,
                self.source_ticket,
            )
            || hosted_device_allocations::capture_allocation(
                self.source_instance,
                self.source_device.address(),
            )
            .ok()
                != Some(self.source_device_allocation)
        {
            return false;
        }
        let Some(memory) = SourcePoolMemory::new(self.source_instance) else {
            return false;
        };
        let Some(irp) = memory.read_value::<Irp>(self.source_irp) else {
            return false;
        };
        let Some(stack) = memory.read_value::<IoStackLocation>(self.source_stack_address) else {
            return false;
        };
        irp.type_ == WDM_X64_IO_TYPE_IRP as i16
            && irp.size as u64 == self.source_allocation.bytes
            && irp.stack_count == self.source_allocation.stack_count as i8
            && stack == self.source_stack
            && stack.device_io_control().type3_input_buffer.0 == self.payload.input_pointer
            && self.class_target.validate(io_manager_mut()).ok()
                == Some(self.payload.class_target.device_id())
    }

    unsafe fn original_payload_matches(&self) -> bool {
        let Some(memory) = SourcePoolMemory::new(self.source_instance) else {
            return false;
        };
        let mut current = [0; 48];
        memory.read(
            self.payload.input_pointer,
            &mut current[..self.payload.input_length as usize],
        ) && current == self.payload.snapshot
    }
}
