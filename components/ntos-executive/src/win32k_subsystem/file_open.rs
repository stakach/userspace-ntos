//! Win64 file-open capture for the win32k provider lane.

use super::*;
use nt_io_manager::io_create_file_capture::{
    capture_nt_open_file, capture_ordinary, CapturedDriverCreate, DriverMemoryReader,
    RawIoCreateFileArguments, RawNtOpenFileArguments,
};
use nt_io_manager::io_create_file_reply::IoCreateFileReply;
use nt_io_manager::io_create_file_wire::{encode_into, encoded_len, IoCreateFileWireError};
use nt_types::AccessMode;

struct KernelMemory;

impl DriverMemoryReader for KernelMemory {
    fn read(&self, address: u64, destination: &mut [u8]) -> bool {
        if address == 0 || address.checked_add(destination.len() as u64).is_none() {
            return false;
        }
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

fn wire_status(error: IoCreateFileWireError) -> i32 {
    match error {
        IoCreateFileWireError::InsufficientResources => 0xC000_009Au32 as i32,
        IoCreateFileWireError::TooLarge | IoCreateFileWireError::BufferTooSmall => {
            0xC000_0206u32 as i32
        }
        IoCreateFileWireError::Malformed | IoCreateFileWireError::UnsupportedVersion => {
            STATUS_INVALID_PARAMETER_I32
        }
    }
}

unsafe fn free_packet(packet: u64) {
    if !provider_pool_free(packet) {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_CREATE_LABEL, packet, 0, 0]);
    }
}

fn dispatch(captured: CapturedDriverCreate) -> i32 {
    let length = match encoded_len(&captured.request) {
        Ok(length) => length,
        Err(error) => return wire_status(error),
    };
    unsafe {
        let packet = pool_alloc(length as u64);
        if packet == 0 {
            return 0xC000_009Au32 as i32;
        }
        let encoded = encode_into(
            &captured.request,
            core::slice::from_raw_parts_mut(packet as *mut u8, length),
        );
        if let Err(error) = encoded {
            free_packet(packet);
            return wire_status(error);
        }
        let (words, status, iosb_status, information, handle) = crate::driver_launch::call_on4_raw(
            (W32_FILE_CREATE_LABEL << 12) | 4,
            packet,
            length as u64,
            0,
            0,
        );
        free_packet(packet);
        if words != 4 {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_CREATE_LABEL, packet, words, status]);
        }
        let reply = match IoCreateFileReply::decode([status, iosb_status, information, handle]) {
            Ok(reply) => reply,
            Err(_) => crate::provider_bugcheck::report(
                0xc4,
                [W32_FILE_CREATE_LABEL, packet, status, handle],
            ),
        };
        match reply {
            IoCreateFileReply::Rejected { status } => status as i32,
            IoCreateFileReply::Completed {
                status,
                iosb_status,
                information,
                handle,
            } => {
                write_unaligned(captured.outputs.io_status_block as *mut u32, iosb_status);
                write_unaligned(
                    (captured.outputs.io_status_block + 8) as *mut u64,
                    information,
                );
                if handle != 0 {
                    write_unaligned(captured.outputs.file_handle as *mut u64, handle);
                }
                status as i32
            }
        }
    }
}

pub(super) extern "win64" fn create(
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
) -> i32 {
    let captured = capture_ordinary(
        &KernelMemory,
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
            create_file_type: 0,
            extra_create_parameters: 0,
            io_options: 0,
        },
        AccessMode::KernelMode,
    );
    match captured {
        Ok(captured) => dispatch(captured),
        Err(status) => status as i32,
    }
}

pub(super) extern "win64" fn open(
    file_handle_out: u64,
    desired_access: u32,
    object_attributes: u64,
    io_status_block_out: u64,
    share_access: u32,
    open_options: u32,
) -> i32 {
    let captured = capture_nt_open_file(
        &KernelMemory,
        RawNtOpenFileArguments {
            file_handle_out,
            desired_access,
            object_attributes,
            io_status_block_out,
            share_access,
            open_options,
        },
        AccessMode::KernelMode,
    );
    match captured {
        Ok(captured) => dispatch(captured),
        Err(status) => status as i32,
    }
}
