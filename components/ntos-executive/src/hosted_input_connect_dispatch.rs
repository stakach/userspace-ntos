//! Port-local i8042 CONNECT packet and its retained provider completion.
//!
//! The class source's METHOD_NEITHER pointer belongs to a different address space. The
//! exact-device detached IRP owner allocates a new port-domain CONNECT_DATA and IRP before
//! entering i8042prt. Its pending node, including the Type3InputBuffer allocation, remains
//! owned by `hosted_file_owners` until the real provider completion is acknowledged.

use super::*;
use nt_io_abi::major;
use nt_io_manager::detached_file_irp::ExternalFileIrpRequest;
use nt_io_manager::retained_connect_forward::ConnectPayloadIdentity;
use nt_io_manager::{DeviceControlParameters, HostedDevicePointerRegistration, IoParameters};
use nt_types::ClientId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PortConnectPhase {
    Prepared,
    Entered,
    Rejected(nt_status::NtStatus),
    AwaitingCompletion(nt_io_manager::IrpId),
    Terminal(nt_status::NtStatus),
    Acknowledged,
}

/// The matching source `RetainedConnectWork`, reverse aliases, and callback thunk must remain
/// owned by the caller throughout this object's lifetime. Dropping an outstanding packet never
/// authorizes a second dispatch or frees the detached IRP's physical graph.
#[must_use = "retain through exact provider completion and source completion acknowledgement"]
pub(super) struct PortLocalConnect {
    source: ConnectPayloadIdentity,
    reverse_owner_id: u64,
    port_device: HostedDevicePointerRegistration,
    class_alias: HostedDevicePointerRegistration,
    thunk: hosted_class_callback_thunk::PublishedClassServiceThunk,
    pending_irp: Option<nt_io_manager::IrpId>,
    returned_input: Option<[u8; 16]>,
    phase: PortConnectPhase,
}

impl PortLocalConnect {
    /// `port_device` is the real i8042 device behind the class-domain lower alias. The class
    /// alias and executable thunk are both generation-bound to the published reverse owner.
    pub(super) unsafe fn prepare(
        source: ConnectPayloadIdentity,
        reverse_owner_id: u64,
        port_device: HostedDevicePointerRegistration,
        thunk: hosted_class_callback_thunk::PublishedClassServiceThunk,
    ) -> Result<Self, nt_status::NtStatus> {
        let aliases = hosted_reverse_class_projection::validate(reverse_owner_id)?;
        let class_alias = aliases.class_do_registration;
        let (_, _, admitted_alias, admitted_class, admitted_service, admitted_control) =
            hosted_class_callback_thunk::validate_pre_entry(
                thunk.cookie,
                source.forward.source.allocation().domain,
                class_alias.address(),
            )?;
        if source.forward.target.device_id() != port_device.device_id()
            || source.forward.target.domain() == port_device.domain()
            || port_device.domain() != class_alias.domain()
            || class_alias.device_id() != source.class_device.device_id()
            || thunk.port_class_alias != class_alias
            || admitted_alias != class_alias
            || admitted_class != source.class_device
            || admitted_service != source.class_service
            || admitted_control != source.forward.control
            || thunk.cookie == 0
            || thunk.port_address == 0
            || thunk.class_service.domain != source.forward.source.allocation().domain
            || thunk.class_service.address != source.class_service
            || io_manager_mut()
                .hosted_device_pointer_registration(port_device.domain(), port_device.address())
                != Some(port_device)
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        Ok(Self {
            source,
            reverse_owner_id,
            port_device,
            class_alias,
            thunk,
            pending_irp: None,
            returned_input: None,
            phase: PortConnectPhase::Prepared,
        })
    }

    pub(super) const fn phase(&self) -> PortConnectPhase {
        self.phase
    }
    pub(super) const fn source(&self) -> ConnectPayloadIdentity {
        self.source
    }
    pub(super) const fn reverse_owner_id(&self) -> u64 {
        self.reverse_owner_id
    }

    pub(super) const fn thunk(&self) -> hosted_class_callback_thunk::PublishedClassServiceThunk {
        self.thunk
    }

    /// The permit is deliberately sealed until the IRQ callback service and both physical
    /// record-buffer leases have a working completion path. The packet itself is a real WDM
    /// METHOD_NEITHER internal-control request with a port-local Type3InputBuffer.
    pub(super) unsafe fn dispatch(
        &mut self,
        permit: &hosted_class_callback_lane::ClassCallbackExecutionPermit,
        caller: nt_process::native_handle::NativeHandleCaller,
    ) -> Result<PortConnectPhase, nt_status::NtStatus> {
        if self.phase != PortConnectPhase::Prepared {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        let aliases = hosted_reverse_class_projection::validate(self.reverse_owner_id)?;
        if aliases.class_do_registration != self.class_alias
            || io_manager_mut().hosted_device_pointer_registration(
                self.port_device.domain(),
                self.port_device.address(),
            ) != Some(self.port_device)
            || !hosted_class_callback_thunk::verify_permit(permit, self.thunk)
            || hosted_class_callback_thunk::admit_irq_request(
                self.thunk.cookie,
                self.source.forward.source.allocation().domain,
                self.class_alias.address(),
            )
            .is_err()
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        let mut input = [0u8; ConnectPayloadIdentity::CONNECT_DATA_BYTES as usize];
        input[..8].copy_from_slice(&self.class_alias.address().to_le_bytes());
        input[8..].copy_from_slice(&self.thunk.port_address.to_le_bytes());
        let request = ExternalFileIrpRequest {
            client: ClientId(IO_MANAGER_COMPONENT_ID),
            device_id: self.port_device.device_id(),
            file_id: None,
            user_data: 0,
            requestor_tid: u64::from(caller.original_thread().thread_id()),
            major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
            parameters: IoParameters::InternalDeviceControl(DeviceControlParameters {
                ioctl_code: self.source.forward.control.code(),
                input_len: input.len() as u32,
                output_len: 0,
            }),
            stack_flags: StackFlags::empty(),
            initial_information: 0,
        };
        // Mark possible entry before invoking the detached owner. An uncertain transport result
        // cannot put this object back in Prepared or authorize a replay.
        self.phase = PortConnectPhase::Entered;
        match hosted_file_owners::dispatch_port_connect(
            caller,
            request,
            &input,
            self.port_device.device_id(),
        ) {
            Ok(hosted_file_owners::DispatchResult::Returned { status, buffers, .. }) => {
                if status == nt_status::NtStatus::PENDING {
                    return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                }
                let mut returned = [0u8; 16];
                assert_eq!(buffers.input().len(), returned.len(),
                    "validated CONNECT input length changed");
                returned.copy_from_slice(buffers.input());
                self.returned_input = Some(returned);
                self.phase = PortConnectPhase::Terminal(status);
            }
            Ok(hosted_file_owners::DispatchResult::Outstanding { irp_id }) => {
                self.pending_irp = Some(irp_id);
                self.phase = PortConnectPhase::AwaitingCompletion(irp_id);
            }
            Err(status) => {
                // The detached owner returns an error only for known pre-entry rejection. The
                // source caller still decides whether its own retained work may be aborted.
                self.phase = PortConnectPhase::Rejected(status);
            }
        }
        Ok(self.phase)
    }

    /// A pending CONNECT remains pending until IoCompleteRequest has produced an exact canonical
    /// completion. The reverse HOOK owner reports its own source and terminal independently.
    pub(super) fn poll_terminal(
        &mut self,
    ) -> Result<Option<nt_status::NtStatus>, nt_status::NtStatus> {
        let PortConnectPhase::AwaitingCompletion(irp_id) = self.phase else {
            return Ok(match self.phase {
                PortConnectPhase::Terminal(status) => Some(status),
                _ => None,
            });
        };
        // A nested HOOK source may have finished while the outer CONNECT pump is parked.
        // Drive the I/O Manager before observing this exact canonical IRP.
        pump_io_manager();
        if unsafe { io_manager_mut().completed_irp(irp_id) }.is_none() {
            return Ok(None);
        }
        let completion = hosted_file_owners::completion(irp_id)?;
        if completion.status == nt_status::NtStatus::PENDING {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        self.phase = PortConnectPhase::Terminal(completion.status);
        Ok(Some(completion.status))
    }

    /// Only the caller that has completed the class source may release the provider's pending
    /// node. An ACK is transport/resource retirement; it does not stand in for HOOK completion.
    pub(super) fn acknowledge_after_source_completion(
        &mut self,
        source: &hosted_connect_work::RetainedConnectWork,
    ) -> Result<(), nt_status::NtStatus> {
        if source.acknowledged_source_payload() != Some(self.source) {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        match self.phase {
            PortConnectPhase::Terminal(_) => {
                if let Some(irp_id) = self.pending_irp {
                    self.returned_input = Some(hosted_file_owners::acknowledge_port_connect(irp_id)?);
                    self.pending_irp = None;
                }
                if self.returned_input.is_none() {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                // A synchronous terminal was retired by detached dispatch itself.
                self.phase = PortConnectPhase::Acknowledged;
                Ok(())
            }
            _ => Err(nt_status::NtStatus::DEVICE_BUSY),
        }
    }
}
