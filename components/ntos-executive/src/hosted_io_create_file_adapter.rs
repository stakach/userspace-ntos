//! Driver-side capture for the ordinary kernel IoCreateFile contract.

use super::*;
use nt_io_manager::io_create_file_capture::{
    capture_ordinary, DriverMemoryReader, RawIoCreateFileArguments,
};
use nt_io_manager::io_create_file_wire::{encode_into, encoded_len, IoCreateFileWireError};
use nt_types::AccessMode;

const STATUS_PENDING: u32 = 0x0000_0103;
const STATUS_PROTOCOL_ERROR: u32 = 0xc000_0010;
const COMPLETION_VALID: u64 = 1 << 32;

struct DriverMemory;

impl DriverMemoryReader for DriverMemory {
    fn read(&self, address: u64, destination: &mut [u8]) -> bool {
        if address == 0 || address.checked_add(destination.len() as u64).is_none() {
            return false;
        }
        // The copy executes in the caller's VSpace. An unmapped address takes the driver's
        // normal fault path; an executive never dereferences a transmitted driver pointer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                address as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        true
    }
}

fn previous_mode() -> Result<AccessMode, u32> {
    let thread = current_ps_value(3);
    if thread == 0 {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    let mode = unsafe {
        read_unaligned(
            (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_PREVIOUS_MODE as u64) as *const u8,
        )
    };
    match mode {
        0 => Ok(AccessMode::KernelMode),
        1 => Ok(AccessMode::UserMode),
        _ => Err(STATUS_PROTOCOL_ERROR),
    }
}

fn wire_status(error: IoCreateFileWireError) -> u32 {
    match error {
        IoCreateFileWireError::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES as u32,
        IoCreateFileWireError::TooLarge | IoCreateFileWireError::BufferTooSmall => {
            STATUS_INVALID_BUFFER_SIZE as u32
        }
        IoCreateFileWireError::Malformed | IoCreateFileWireError::UnsupportedVersion => {
            STATUS_INVALID_PARAMETER as u32
        }
    }
}

/// The complete Win64 kernel ABI, including its six stack arguments after the first four.
pub(super) extern "win64" fn s_io_create_file(
    file_handle_out: u64,
    desired_access: u32,
    object_attributes: u64,
    io_status_block_out: u64,
    allocation_size: u64,
    file_attributes: u32,
    share_access: u32,
    disposition: u32,
    create_options: u32,
    ea_buffer: u64,
    ea_length: u32,
    create_file_type: u32,
    extra_create_parameters: u64,
    io_options: u32,
) -> i32 {
    let mode = match previous_mode() {
        Ok(mode) => mode,
        Err(status) => return status as i32,
    };
    let captured = match capture_ordinary(
        &DriverMemory,
        RawIoCreateFileArguments {
            file_handle_out,
            desired_access,
            object_attributes,
            io_status_block_out,
            allocation_size,
            file_attributes,
            share_access,
            disposition,
            create_options,
            ea_buffer,
            ea_length,
            create_file_type,
            extra_create_parameters,
            io_options,
        },
        mode,
    ) {
        Ok(captured) => captured,
        Err(status) => return status as i32,
    };
    let length = match encoded_len(&captured.request) {
        Ok(length) => length,
        Err(error) => return wire_status(error) as i32,
    };
    let frame = unsafe { pool_alloc(length as u64) };
    if frame == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let encoded = unsafe {
        encode_into(
            &captured.request,
            core::slice::from_raw_parts_mut(frame as *mut u8, length),
        )
    };
    if let Err(error) = encoded {
        unsafe { pool_free(frame) };
        return wire_status(error) as i32;
    }

    // The root owns a copied request before replying. Keep this unique pool allocation alive
    // across the parked Call; the caller's output addresses never cross the service boundary.
    let (label, status_word, iosb_status, information, handle) = unsafe {
        call_on4(
            (FSD_SERVICE_IO_CREATE_FILE_LABEL << 12) | 4,
            frame,
            length as u64,
            0,
            0,
        )
    };
    unsafe { pool_free(frame) };
    if label != 0 || status_word & !(COMPLETION_VALID | u32::MAX as u64) != 0 {
        return STATUS_PROTOCOL_ERROR as i32;
    }
    let status = status_word as u32;
    if status == STATUS_PENDING || iosb_status > u32::MAX as u64 {
        return STATUS_PROTOCOL_ERROR as i32;
    }
    if status_word & COMPLETION_VALID != 0 {
        if (status as i32) >= 0 {
            if (iosb_status as u32 as i32) < 0 || handle == 0 {
                return STATUS_PROTOCOL_ERROR as i32;
            }
        } else if handle != 0 {
            return STATUS_PROTOCOL_ERROR as i32;
        }
        unsafe {
            write_unaligned(
                captured.outputs.io_status_block as *mut u32,
                iosb_status as u32,
            );
            write_unaligned(
                (captured.outputs.io_status_block + 8) as *mut u64,
                information,
            );
            if handle != 0 {
                write_unaligned(captured.outputs.file_handle as *mut u64, handle);
            }
        }
    } else if (status as i32) >= 0 || handle != 0 || iosb_status != 0 || information != 0 {
        return STATUS_PROTOCOL_ERROR as i32;
    }
    status as i32
}
