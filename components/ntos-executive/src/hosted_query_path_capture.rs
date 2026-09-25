//! Source-domain capture for Mup's forwarded `IOCTL_REDIR_QUERY_PATH` IRP.
//!
//! Driver addresses below are only checked lookup keys in the authenticated source VSpace.
//! Dispatch authority is the generation-bearing source ticket, canonical File reference, and
//! retained target registration. The outer CREATE owns the security graph separately.

use super::*;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget,
    redir_query_path::{
        capture_query_path, CapturedQueryPath, QueryPathError, QueryPathStack,
        QUERY_PATH_REQUEST_X64_SIZE,
    },
    retained_query_path_forward::{
        PreparedQueryPathForward, QueryPathForwardIdentity, SourceIrpTicket,
        TerminalQueryPathForward,
    },
    source_irp_ledger::SourceIrpAllocation,
    HostedDomainIdentity,
};

const IRP_REQUESTOR_MODE_OFFSET: u64 = 0x40;
const IRP_CURRENT_LOCATION_OFFSET: u64 = 0x43;
const IRP_CURRENT_STACK_OFFSET: u64 = 0xb8;
const IRP_ORIGINAL_FILE_OFFSET: u64 = 0xc0;
const IRP_USER_BUFFER_OFFSET: u64 = 0x70;
const MAX_INPUT_BYTES: u64 = QUERY_PATH_REQUEST_X64_SIZE as u64 + 65_532;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CaptureError {
    InvalidCaller,
    MissingSecurityContext,
    InvalidSourceIrp,
    InvalidSourceBuffer,
    InvalidFile,
    InvalidTarget,
    QueryPath(QueryPathError),
}

/// Retained source-side owners. `prepare` moves target ownership to the no-replay forwarding
/// protocol; the caller must keep this owner pinned until its source-local completion has run.
#[must_use = "retain through source-domain completion and release exact owners"]
pub(super) struct CapturedSourceForward {
    instance_index: usize,
    allocation: SourceIrpAllocation,
    source: SourceIrpTicket,
    source_file: Option<hosted_consumer_file_objects::ForwardFileOwner>,
    target: Option<HostedForwardTarget>,
    request: Option<CapturedQueryPath>,
    input_buffer: u64,
    output_buffer: u64,
    output_length: u32,
    pinned: bool,
    forward_identity: Option<QueryPathForwardIdentity>,
    target_retired: bool,
}

impl CapturedSourceForward {
    pub(super) fn source_ticket(&self) -> SourceIrpTicket {
        self.source
    }
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
    pub(super) fn request(&self) -> &CapturedQueryPath {
        self.request.as_ref().expect("query-path request prepared")
    }
    pub(super) fn source_input_address(&self) -> u64 {
        self.input_buffer
    }
    pub(super) fn source_output_address(&self) -> u64 {
        self.output_buffer
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

    pub(super) unsafe fn source_output_exec(&self) -> Result<u64, CaptureError> {
        self.validate_source()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSourceIrp)?;
        hosted_instance_pool_allocation_exec_if_live(
            inst,
            self.output_buffer,
            self.output_length as u64,
        )
        .ok_or(CaptureError::InvalidSourceBuffer)
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

    /// This pointer is usable only in the executive's source-pool mapping, never as a provider
    /// transport identity. Revalidate the generation-bearing ledger before every use.
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

    /// Move the target into the retained no-replay protocol immediately before provider entry.
    /// The source File and IRP remain pinned here through Mup's local completion routine.
    pub(super) fn prepare(&mut self) -> Result<PreparedQueryPathForward, CaptureError> {
        self.validate_source()?;
        let request = self.request.take().ok_or(CaptureError::InvalidSourceIrp)?;
        let target = self.target.take().ok_or(CaptureError::InvalidTarget)?;
        let prepared = PreparedQueryPathForward::new(self.source, target, request);
        self.forward_identity = Some(prepared.identity());
        Ok(prepared)
    }

    /// The source-domain completion routine must have run before this target retirement.
    pub(super) fn retire_target_after_source_completion(
        &mut self,
        terminal: TerminalQueryPathForward,
    ) -> Result<
        nt_io_manager::redir_query_path::QueryPathCompletion,
        (CaptureError, TerminalQueryPathForward),
    > {
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

    /// A sealed stop of the parked source Call prevents its local completion routine from
    /// running. The caller must hold that exact cancellation receipt and a provider terminal;
    /// no source-domain output or IRP status may be published on this path.
    pub(super) fn retire_target_after_source_stop(
        &mut self,
        terminal: TerminalQueryPathForward,
    ) -> Result<
        nt_io_manager::redir_query_path::QueryPathCompletion,
        (CaptureError, TerminalQueryPathForward),
    > {
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

    /// Release only after the prepared/terminal forward has retired its target. A failed step
    /// leaves its owner here for exact redrive and never silently frees source memory.
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

unsafe fn source_stack(
    inst: DriverInstance,
    allocation: SourceIrpAllocation,
) -> Result<(u64, u64), CaptureError> {
    let irp = hosted_instance_pool_allocation_exec_if_live(
        inst,
        allocation.component_address,
        allocation.bytes,
    )
    .ok_or(CaptureError::InvalidSourceIrp)?;
    let location = read_unaligned((irp + IRP_CURRENT_LOCATION_OFFSET) as *const u8);
    if location < 2 || location > allocation.stack_count {
        return Err(CaptureError::InvalidSourceIrp);
    }
    let stack_base = allocation.component_address + WDM_X64_IRP_SIZE as u64;
    let current_stack = stack_base + (location as u64 - 1) * WDM_X64_IO_STACK_LOCATION_SIZE as u64;
    if read_unaligned((irp + IRP_CURRENT_STACK_OFFSET) as *const u64) != current_stack {
        return Err(CaptureError::InvalidSourceIrp);
    }
    let next_stack = current_stack - WDM_X64_IO_STACK_LOCATION_SIZE as u64;
    let stack_exec = irp + next_stack - allocation.component_address;
    Ok((irp, stack_exec))
}

/// Capture only an authenticated source-domain `IofCallDriver` invocation. The request's raw
/// security pointer is only a lookup key for the retained outer CREATE owner; absence is an
/// explicit dependency rather than a fabricated context.
pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    source_irp_address: u64,
    target_device_address: u64,
) -> Result<CapturedSourceForward, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity =
        instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (source, allocation) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
            .ok_or(CaptureError::InvalidSourceIrp)?;
    let result = (|| {
        let (irp, stack) = source_stack(inst, allocation)?;
        let stack = read_unaligned(stack as *const nt_kernel_abi::IoStackLocation);
        let control = stack.device_io_control();
        let input_len = control.input_buffer_length as u64;
        let output_len = control.output_buffer_length;
        let input_buffer = control.type3_input_buffer.0;
        let output_buffer = read_unaligned((irp + IRP_USER_BUFFER_OFFSET) as *const u64);
        if !(QUERY_PATH_REQUEST_X64_SIZE as u64..=MAX_INPUT_BYTES).contains(&input_len)
            || input_buffer == 0
            || output_buffer == 0
            || hosted_instance_pool_allocation_exec_if_live(inst, output_buffer, output_len as u64)
                .is_none()
        {
            return Err(CaptureError::InvalidSourceBuffer);
        }
        let input_exec = hosted_instance_pool_allocation_exec_if_live(inst, input_buffer, input_len)
            .ok_or(CaptureError::InvalidSourceBuffer)?;
        let stack_descriptor = QueryPathStack {
            major: stack.major_function,
            minor: stack.minor_function,
            requestor_kernel_mode: read_unaligned((irp + IRP_REQUESTOR_MODE_OFFSET) as *const u8)
                == 0,
            io_control_code: control.io_control_code,
            input_buffer_length: input_len as u32,
            output_buffer_length: output_len,
        };
        let bytes = core::slice::from_raw_parts(input_exec as *const u8, input_len as usize);
        let security_address = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let security = hosted_source_create_security::lookup_context(inst, security_address)
            .ok_or(CaptureError::MissingSecurityContext)?;
        let request = capture_query_path(stack_descriptor, bytes, Some(security))
            .map_err(CaptureError::QueryPath)?;
        let stack_device = stack.device_object.0;
        if stack_device == 0 || stack_device != target_device_address {
            return Err(CaptureError::InvalidTarget);
        }
        let stack_file = stack.file_object.0;
        if stack_file == 0
            || read_unaligned((irp + IRP_ORIGINAL_FILE_OFFSET) as *const u64) != stack_file
        {
            return Err(CaptureError::InvalidFile);
        }
        let mut source_file = hosted_consumer_file_objects::capture_forward_file(
            ch,
            reply_cap,
            stack_file,
            stack_device,
        )
        .map_err(|_| CaptureError::InvalidFile)?;
        let target =
            match HostedForwardTarget::capture(io_manager_mut(), domain, target_device_address) {
                Ok(target) => target,
                Err(_) => {
                    source_file
                        .release()
                        .expect("unentered query-path File capture rollback");
                    return Err(CaptureError::InvalidTarget);
                }
            };
        if target.device_id() != source_file.device_id() {
            let mut target = target;
            target
                .release(io_manager_mut())
                .expect("unentered query-path target rollback");
            source_file
                .release()
                .expect("unentered query-path File rollback");
            return Err(CaptureError::InvalidTarget);
        }
        Ok(CapturedSourceForward {
            instance_index,
            allocation,
            source,
            source_file: Some(source_file),
            target: Some(target),
            request: Some(request),
            input_buffer,
            output_buffer,
            output_length: output_len,
            pinned: true,
            forward_identity: None,
            target_retired: false,
        })
    })();
    if result.is_err() {
        assert!(
            hosted_source_irp_ledger::unpin(source),
            "unentered query-path source rollback"
        );
    }
    result
}
