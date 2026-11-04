//! Admission of a retained, fileless kernel READ at an exact device.
//!
//! The native adapter obtains `auxiliary` from the protected source ledger and
//! revalidates its physical allocations before copying provider output. This
//! contract binds the source packet, output mode, and completion owner before
//! any provider effect can occur.

use nt_io_abi::major;

use crate::kernel_irp_builder::{
    IRP_BUFFERED_IO, IRP_DEALLOCATE_BUFFER, IRP_INPUT_OPERATION,
    SL_OVERRIDE_VERIFY_VOLUME,
};
use crate::retained_query_path_forward::SourceIrpTicket;
use crate::source_irp_auxiliary::{
    SourceIrpAuxiliary, SourceIrpAuxiliaryPhase, SourceIrpCompletionOwner,
    SourceMdlAllocationIdentity, SourceMemoryIdentity, SourcePoolAllocationIdentity,
};
use crate::source_irp_ledger::SourceIrpAllocation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDeviceReadRequest {
    pub source: SourceIrpAllocation,
    pub ticket: SourceIrpTicket,
    pub phase: SourceIrpAuxiliaryPhase,
    pub major: u8,
    pub minor: u8,
    pub device_object: u64,
    pub target_device_object: u64,
    pub file_object: u64,
    pub length: u32,
    pub key: u32,
    pub byte_offset: u64,
    pub stack_flags: u8,
    pub irp_flags: u32,
    pub system_buffer: u64,
    pub mdl: u64,
    pub user_buffer: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDeviceRead {
    pub source: SourceIrpAllocation,
    pub ticket: SourceIrpTicket,
    pub device_object: u64,
    pub length: u32,
    pub byte_offset: u64,
    pub stack_flags: u8,
    pub output: SourceMemoryIdentity,
    pub system_buffer: Option<SourcePoolAllocationIdentity>,
    pub mdl: Option<SourceMdlAllocationIdentity>,
    pub completion: SourceIrpCompletionOwner,
}

pub fn admit_source_device_read(
    request: SourceDeviceReadRequest,
    auxiliary: SourceIrpAuxiliary,
) -> Option<SourceDeviceRead> {
    if request.source != auxiliary.source
        || request.ticket != auxiliary.ticket
        || request.phase != SourceIrpAuxiliaryPhase::Protected
        || request.major != major::IRP_MJ_READ
        || request.minor != 0
        || request.device_object == 0
        || request.device_object != request.target_device_object
        || request.file_object != 0
        || request.length == 0
        || request.key != 0
        || request.byte_offset.checked_add(u64::from(request.length)).is_none()
        || request.stack_flags & !SL_OVERRIDE_VERIFY_VOLUME != 0
        || auxiliary.buffered_control.is_some()
    {
        return None;
    }
    let output = auxiliary.transfer_buffer?;
    let (output_address, output_bytes) = match output {
        SourceMemoryIdentity::Pool { component_address, bytes, .. }
        | SourceMemoryIdentity::MappedRange { component_address, bytes, .. } => {
            (component_address, bytes)
        }
    };
    if output_bytes != u64::from(request.length) {
        return None;
    }
    let expected_buffered = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
    let valid_mode = match (auxiliary.system_buffer, auxiliary.mdl) {
        (Some(system), None) => {
            request.irp_flags == expected_buffered
                && request.system_buffer == system.component_address
                && system.capacity >= u64::from(request.length)
                && request.mdl == 0
                && request.user_buffer == output_address
        }
        (None, Some(mdl)) => {
            request.irp_flags == 0
                && request.system_buffer == 0
                && request.mdl == mdl.pool.component_address
                && request.user_buffer == 0
        }
        (None, None) => {
            request.irp_flags == 0
                && request.system_buffer == 0
                && request.mdl == 0
                && request.user_buffer == output_address
        }
        (Some(_), Some(_)) => false,
    };
    if !valid_mode {
        return None;
    }
    Some(SourceDeviceRead {
        source: request.source,
        ticket: request.ticket,
        device_object: request.device_object,
        length: request.length,
        byte_offset: request.byte_offset,
        stack_flags: request.stack_flags,
        output,
        system_buffer: auxiliary.system_buffer,
        mdl: auxiliary.mdl,
        completion: auxiliary.completion,
    })
}
