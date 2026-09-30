//! WDM IRP plans for kernel consumers outside the Driver Host.
//!
//! The caller owns allocations, pointer authentication, MDL pinning, and
//! dispatch. This contract determines sizes and layout without assuming that
//! the caller shares the FSD host's pool or address space.

use nt_io_abi::{ioctl, major};

use crate::{
    WdmIoStackLocationInit, WdmIoStackParameters, WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE,
};

pub const DO_BUFFERED_IO: u32 = 0x0000_0004;
pub const DO_DIRECT_IO: u32 = 0x0000_0010;
pub const IRP_BUFFERED_IO: u32 = 0x0000_0010;
pub const IRP_DEALLOCATE_BUFFER: u32 = 0x0000_0020;
pub const IRP_INPUT_OPERATION: u32 = 0x0000_0040;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelIrpPlanError {
    InvalidStackSize,
    UnsupportedMajor,
    MissingStartingOffset,
    InvalidIrpHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelIrpDispatchHeader {
    pub irp_type: u16,
    pub packet_size: u16,
    pub stack_count: u8,
    pub current_location: u8,
    pub current_stack_location: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelIrpDispatchCursor {
    pub current_location: u8,
    pub next_stack_offset: usize,
}

/// Validate the cursor before IofCallDriver consumes the next stack. Unlike
/// fresh-allocation validation, a forwarded IRP may already be inside its stack.
pub fn validate_kernel_irp_dispatch_cursor(
    base: u64,
    allocation_bytes: u64,
    expected_stack_count: u8,
    header: KernelIrpDispatchHeader,
) -> Result<KernelIrpDispatchCursor, KernelIrpPlanError> {
    if base == 0 || expected_stack_count == 0 || expected_stack_count == u8::MAX {
        return Err(KernelIrpPlanError::InvalidStackSize);
    }
    let packet_size =
        WDM_X64_IRP_SIZE + expected_stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE;
    let current = header.current_location;
    if header.irp_type != 6
        || header.packet_size as usize != packet_size
        || allocation_bytes != packet_size as u64
        || header.stack_count != expected_stack_count
        || current < 2
        || current > expected_stack_count + 1
    {
        return Err(KernelIrpPlanError::InvalidIrpHeader);
    }
    let next_stack_offset =
        WDM_X64_IRP_SIZE + (current as usize - 2) * WDM_X64_IO_STACK_LOCATION_SIZE;
    let cursor = base
        .checked_add(next_stack_offset as u64)
        .and_then(|next| next.checked_add(WDM_X64_IO_STACK_LOCATION_SIZE as u64))
        .ok_or(KernelIrpPlanError::InvalidIrpHeader)?;
    if header.current_stack_location != cursor {
        return Err(KernelIrpPlanError::InvalidIrpHeader);
    }
    Ok(KernelIrpDispatchCursor {
        current_location: current,
        next_stack_offset,
    })
}

/// Admit only a freshly allocated IRP packet with the cursor still above its
/// stack. The provider may later mutate the next stack before `IofCallDriver`;
/// this validation is for registration, not dispatch authorization.
pub fn validate_new_kernel_irp_packet(
    base: u64,
    bytes: &[u8],
    stack_count: u8,
) -> Result<(), KernelIrpPlanError> {
    if base == 0 || stack_count == 0 || stack_count == u8::MAX {
        return Err(KernelIrpPlanError::InvalidStackSize);
    }
    let size = WDM_X64_IRP_SIZE + stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE;
    let end = base
        .checked_add(size as u64)
        .ok_or(KernelIrpPlanError::InvalidIrpHeader)?;
    if bytes.len() != size
        || u16::from_le_bytes(bytes[0..2].try_into().unwrap()) != 6
        || u16::from_le_bytes(bytes[2..4].try_into().unwrap()) as usize != size
        || bytes[0x42] != stack_count
        || bytes[0x43] != stack_count + 1
        || u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap()) != base + 0x20
        || u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()) != base + 0x20
        || u64::from_le_bytes(bytes[0xb8..0xc0].try_into().unwrap()) != end
    {
        return Err(KernelIrpPlanError::InvalidIrpHeader);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdlAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MdlPlan {
    pub buffer: u64,
    pub length: u32,
    pub access: MdlAccess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelBuiltIrpPlan {
    pub packet_size: u16,
    pub stack_count: u8,
    /// Byte offset of IoGetNextIrpStackLocation from the allocated IRP base.
    pub next_stack_offset: usize,
    pub stack: WdmIoStackLocationInit,
    pub irp_flags: u32,
    /// Zero-initialized storage size; `system_buffer_input` is copied into it.
    pub system_buffer_len: u32,
    pub system_buffer_input: u64,
    pub system_buffer_input_len: u32,
    pub mdl: Option<MdlPlan>,
    pub user_buffer: u64,
}

impl KernelBuiltIrpPlan {
    fn empty(stack_size: u8, major: u8, device_object: u64) -> Result<Self, KernelIrpPlanError> {
        if stack_size == 0 || stack_size == u8::MAX {
            return Err(KernelIrpPlanError::InvalidStackSize);
        }
        let packet_size = WDM_X64_IRP_SIZE + stack_size as usize * WDM_X64_IO_STACK_LOCATION_SIZE;
        Ok(Self {
            packet_size: packet_size as u16,
            stack_count: stack_size,
            next_stack_offset: packet_size - WDM_X64_IO_STACK_LOCATION_SIZE,
            stack: WdmIoStackLocationInit {
                major,
                device_object,
                ..WdmIoStackLocationInit::default()
            },
            irp_flags: 0,
            system_buffer_len: 0,
            system_buffer_input: 0,
            system_buffer_input_len: 0,
            mdl: None,
            user_buffer: 0,
        })
    }
}

/// Plan IoBuildSynchronousFsdRequest for supported parameter unions. PnP
/// callers fill the minor and parameters in the next stack after construction.
pub fn plan_synchronous_fsd_request(
    major: u8,
    stack_size: u8,
    device_flags: u32,
    device_object: u64,
    buffer: u64,
    length: u32,
    starting_offset: Option<u64>,
) -> Result<KernelBuiltIrpPlan, KernelIrpPlanError> {
    if !matches!(
        major,
        major::IRP_MJ_READ
            | major::IRP_MJ_WRITE
            | major::IRP_MJ_FLUSH_BUFFERS
            | major::IRP_MJ_SHUTDOWN
            | major::IRP_MJ_PNP
            | major::IRP_MJ_POWER
    ) {
        return Err(KernelIrpPlanError::UnsupportedMajor);
    }
    let mut plan = KernelBuiltIrpPlan::empty(stack_size, major, device_object)?;
    if matches!(major, major::IRP_MJ_READ | major::IRP_MJ_WRITE) {
        let offset = starting_offset.ok_or(KernelIrpPlanError::MissingStartingOffset)?;
        plan.stack.parameters = if major == major::IRP_MJ_READ {
            WdmIoStackParameters::Read {
                length,
                key: 0,
                byte_offset: offset,
            }
        } else {
            WdmIoStackParameters::Write {
                length,
                key: 0,
                byte_offset: offset,
            }
        };
        if device_flags & DO_BUFFERED_IO != 0 {
            plan.system_buffer_len = length;
            plan.irp_flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
            if major == major::IRP_MJ_READ {
                plan.irp_flags |= IRP_INPUT_OPERATION;
                plan.user_buffer = buffer;
            } else {
                plan.system_buffer_input = buffer;
                plan.system_buffer_input_len = length;
            }
        } else if device_flags & DO_DIRECT_IO != 0 {
            if length != 0 {
                plan.mdl = Some(MdlPlan {
                    buffer,
                    length,
                    access: if major == major::IRP_MJ_READ {
                        MdlAccess::Write
                    } else {
                        MdlAccess::Read
                    },
                });
            }
        } else {
            plan.user_buffer = buffer;
        }
    }
    Ok(plan)
}

/// Plan IoBuildDeviceIoControlRequest. Complete allocation and pointer capture
/// before registering the IRP or making it visible to IofCallDriver.
pub fn plan_device_io_control_request(
    code: u32,
    internal: bool,
    stack_size: u8,
    device_object: u64,
    input_buffer: u64,
    input_len: u32,
    output_buffer: u64,
    output_len: u32,
) -> Result<KernelBuiltIrpPlan, KernelIrpPlanError> {
    let major = if internal {
        major::IRP_MJ_INTERNAL_DEVICE_CONTROL
    } else {
        major::IRP_MJ_DEVICE_CONTROL
    };
    let mut plan = KernelBuiltIrpPlan::empty(stack_size, major, device_object)?;
    let method = ioctl::method(code);
    plan.stack.parameters = WdmIoStackParameters::DeviceControl {
        output_buffer_length: output_len,
        input_buffer_length: input_len,
        io_control_code: code,
        type3_input_buffer: if method == ioctl::METHOD_NEITHER {
            input_buffer
        } else {
            0
        },
    };
    match method {
        ioctl::METHOD_BUFFERED => {
            plan.system_buffer_len = input_len.max(output_len);
            if plan.system_buffer_len != 0 {
                plan.irp_flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
                if output_buffer != 0 {
                    plan.irp_flags |= IRP_INPUT_OPERATION;
                }
                plan.system_buffer_input = input_buffer;
                if input_buffer != 0 {
                    plan.system_buffer_input_len = input_len;
                }
                plan.user_buffer = output_buffer;
            }
        }
        ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
            if input_buffer != 0 {
                plan.system_buffer_len = input_len;
                plan.system_buffer_input = input_buffer;
                plan.system_buffer_input_len = input_len;
                plan.irp_flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
            }
            if output_buffer != 0 {
                plan.mdl = Some(MdlPlan {
                    buffer: output_buffer,
                    length: output_len,
                    access: if method == ioctl::METHOD_IN_DIRECT {
                        MdlAccess::Read
                    } else {
                        MdlAccess::Write
                    },
                });
            }
        }
        ioctl::METHOD_NEITHER => plan.user_buffer = output_buffer,
        _ => unreachable!("CTL_CODE method has only two bits"),
    }
    Ok(plan)
}

#[cfg(test)]
mod tests;
