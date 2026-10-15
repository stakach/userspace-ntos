//! Retained class-to-port CONNECT ownership.
//!
//! A class-domain CONNECT_DATA contains a class DEVICE_OBJECT pointer and a class code
//! pointer. Neither is meaningful in the port driver's address space. Provider entry is
//! unavailable until an owner retains an exact port-domain device alias and an executable
//! callback thunk that routes to this class generation. Keep this gate closed meanwhile.

use super::*;
use nt_io_manager::retained_connect_forward::{
    ConnectDispatchReturn, ConnectForwardPhase, ConnectPayloadIdentity,
};

/// Only the reverse-projection owner may construct this witness after it has retained the
/// port-domain class alias and callback thunk. There is deliberately no constructor here.
#[must_use = "retain the projection and thunk through source completion and port ACK"]
pub(super) struct ProviderConnectProjection {
    _sealed: (),
}

impl ProviderConnectProjection {
    pub(super) unsafe fn admitted(
        reverse_owner_id: u64,
        thunk: hosted_class_callback_thunk::PublishedClassServiceThunk,
        permit: &hosted_class_callback_lane::ClassCallbackExecutionPermit,
    ) -> Result<Self, nt_status::NtStatus> {
        let aliases = hosted_reverse_class_projection::validate(reverse_owner_id)?;
        if aliases.class_do_registration != thunk.port_class_alias
            || !hosted_class_callback_thunk::verify_permit(permit, thunk)
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        Ok(Self { _sealed: () })
    }
}

#[must_use = "retain the source Reply, IRP, stack, target and projection through terminal ACK"]
pub(super) struct RetainedConnectWork {
    source: hosted_connect_capture::CapturedConnect,
    origin: hosted_forward_origin::HostedForwardOrigin,
    projection: Option<ProviderConnectProjection>,
    published: bool,
    terminal_status: Option<nt_status::NtStatus>,
    terminal_consumed: bool,
    source_retired: bool,
    completion_acknowledged: bool,
}

impl RetainedConnectWork {
    pub(super) fn new(
        source: hosted_connect_capture::CapturedConnect,
        origin: hosted_forward_origin::HostedForwardOrigin,
    ) -> Self {
        Self {
            source,
            origin,
            projection: None,
            published: false,
            terminal_status: None,
            terminal_consumed: false,
            source_retired: false,
            completion_acknowledged: false,
        }
    }

    pub(super) fn payload(&self) -> ConnectPayloadIdentity {
        self.source.payload()
    }

    pub(super) fn source_identity(&self) -> nt_io_manager::source_irp_ledger::SourceIrpForwardIdentity {
        self.source.source_identity()
    }

    pub(super) fn source_irp_address(&self) -> u64 {
        self.source.source_irp_address()
    }

    pub(super) fn source_pin_owned(&self) -> bool {
        self.source.source_pin_owned()
    }

    pub(super) unsafe fn completion_command(&self) -> Result<hosted_source_completion_lane::SourceCompletionCommand, hosted_connect_capture::CaptureError> {
        self.source.completion_command(self.origin.token)
    }

    pub(super) unsafe fn validate_source(&self) -> Result<(), hosted_connect_capture::CaptureError> {
        self.source.validate_source()
    }

    pub(super) fn origin_mut(&mut self) -> &mut hosted_forward_origin::HostedForwardOrigin {
        &mut self.origin
    }

    pub(super) fn forward(&self) -> Option<&nt_io_manager::retained_connect_forward::RetainedConnectForward> {
        self.source.forward_ref()
    }

    pub(super) fn forward_mut(&mut self) -> Option<&mut nt_io_manager::retained_connect_forward::RetainedConnectForward> {
        self.source.forward_mut()
    }

    pub(super) fn set_terminal_after_hook(&mut self, status: nt_status::NtStatus) {
        self.terminal_status = Some(status);
    }

    /// The source allocation and stack snapshot are checked again immediately before the
    /// provider effect. An unprojected class callback is never sent across domains.
    pub(super) unsafe fn enter(
        &mut self,
        projection: ProviderConnectProjection,
    ) -> Result<(), hosted_connect_capture::CaptureError> {
        self.source.validate_source()?;
        if self.projection.is_some() {
            return Err(hosted_connect_capture::CaptureError::InvalidPayload);
        }
        let forward = self
            .source
            .forward_mut()
            .ok_or(hosted_connect_capture::CaptureError::InvalidTarget)?;
        forward
            .enter(io_manager_mut(), forward.identity())
            .map_err(|_| hosted_connect_capture::CaptureError::InvalidTarget)?;
        self.projection = Some(projection);
        Ok(())
    }

    /// Record the actual port dispatch result once. Pending or uncertain results keep every
    /// owner pinned; a second entry is impossible after the first observation.
    pub(super) unsafe fn observe_dispatch(
        &mut self,
        result: ConnectDispatchReturn,
    ) -> Result<ConnectForwardPhase, hosted_connect_capture::CaptureError> {
        if self.projection.is_none() {
            return Err(hosted_connect_capture::CaptureError::InvalidTarget);
        }
        let forward = self
            .source
            .forward_mut()
            .ok_or(hosted_connect_capture::CaptureError::InvalidTarget)?;
        let phase = forward
            .observe_dispatch(io_manager_mut(), forward.identity(), result)
            .map_err(|_| hosted_connect_capture::CaptureError::InvalidTarget)?;
        if matches!(phase, ConnectForwardPhase::Indeterminate(_)) {
            self.source.retain_indeterminate()?;
        }
        if let ConnectForwardPhase::Terminal(status) = phase {
            self.terminal_status = Some(status);
        }
        Ok(phase)
    }

    pub(super) fn terminal_status(&self) -> Option<nt_status::NtStatus> {
        self.terminal_status
    }

    /// An exact source continuation and its origin receipt have both completed. A provider
    /// terminal alone cannot authorize retirement of the port-local pending IRP.
    pub(super) fn acknowledged_source_payload(&self) -> Option<ConnectPayloadIdentity> {
        self.completion_acknowledged.then_some(self.payload())
    }

    /// A provider terminal is only one input to source completion. The source lane must run
    /// and acknowledge the class completion stack before any physical owner is retired.
    pub(super) unsafe fn complete_terminal(&mut self) -> bool {
        if self.completion_acknowledged {
            return true;
        }
        let Some(status) = self.terminal_status() else {
            return false;
        };
        let Ok(command) = self.source.completion_command(self.origin.token) else {
            return false;
        };
        if !self.published {
            if !self.origin.terminal_ready(command) {
                return false;
            }
            let Ok(irp) = self.source.source_irp_exec() else {
                return false;
            };
            core::ptr::write_unaligned(
                (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut u32,
                status.raw() as u32,
            );
            core::ptr::write_unaligned(
                (irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64,
                0,
            );
            if self.source.arm_callback_free().is_err() {
                return false;
            }
            self.published = true;
        }
        if !self.origin.begin_terminal(command) || !self.origin.completed() {
            return false;
        }
        if !self.terminal_consumed {
            let Some(forward) = self.source.forward_mut() else {
                return false;
            };
            if forward
                .consume_terminal(io_manager_mut(), forward.identity())
                .is_err()
            {
                return false;
            }
            self.terminal_consumed = true;
        }
        if !self.source_retired {
            if self.source.retire_after_source_completion().is_err() {
                return false;
            }
            self.source_retired = true;
        }
        self.completion_acknowledged = self.origin.retire_receipt();
        self.completion_acknowledged
    }

    /// Only the prepared state can be rolled back. A failed physical release leaves this
    /// object owned by its caller for exact retry, not by a fresh CONNECT attempt.
    pub(super) unsafe fn abort_unentered(&mut self) -> bool {
        self.projection.is_none() && self.source.abort_unentered().is_ok()
    }
}
