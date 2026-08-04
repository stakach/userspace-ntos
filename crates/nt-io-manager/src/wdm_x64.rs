//! NT5 x64 WDM compatibility object layouts used by hosted Driver Host peers.
//!
//! The canonical I/O Manager owns ids and records. A hosted ReactOS driver still
//! expects local WDM-shaped `DRIVER_OBJECT`, `DEVICE_OBJECT`, `FILE_OBJECT`, IRP,
//! and `IO_STACK_LOCATION` memory. This module centralizes those compatibility
//! layouts as pure byte writers so the executive transport does not open-code
//! offsets.

pub const WDM_X64_DRIVER_OBJECT_SIZE: usize = 0x150;
pub const WDM_X64_DRIVER_EXTENSION_OFFSET: usize = 0x68;
pub const WDM_X64_DRIVER_EXTENSION_SIZE: usize = 0x50;
pub const WDM_X64_DRIVER_MAJOR_FUNCTION_OFFSET: usize = 0x70;

pub const WDM_X64_DEVICE_OBJECT_SIZE: usize = 0x150;
pub const WDM_X64_FILE_OBJECT_SIZE: usize = 0x100;
pub const WDM_X64_IRP_SIZE: usize = 0x120;
pub const WDM_X64_IO_STACK_LOCATION_SIZE: usize = 0x48;

pub const WDM_X64_IO_TYPE_DRIVER: i16 = 4;
pub const WDM_X64_IO_TYPE_DEVICE: i16 = 3;
pub const WDM_X64_IO_TYPE_FILE: i16 = 5;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdmLayoutError {
    BufferTooSmall,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmDriverObjectInit {
    pub size_field: u16,
    pub device_object: u64,
    pub driver_extension_offset: usize,
    pub driver_extension: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmDeviceObjectInit {
    pub driver_object: u64,
    pub next_device: u64,
    pub device_extension: u64,
    pub device_type: u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmFileObjectInit {
    pub device_object: u64,
    pub fs_context: u64,
    pub file_name_len: u16,
    pub file_name_max_len: u16,
    pub file_name_buffer: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmIrpInit {
    pub system_buffer: u64,
    pub user_buffer: u64,
    pub current_stack_location: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdmIoStackParameters {
    None,
    Create {
        security_context: u64,
        options: u32,
        share_access: u16,
        named_pipe_parameters: Option<u64>,
    },
    Read {
        length: u32,
    },
    Write {
        length: u32,
    },
    SetInformation {
        length: u32,
        information_class: u32,
    },
    DeviceControl {
        output_buffer_length: u32,
        input_buffer_length: u32,
        io_control_code: u32,
    },
}

impl Default for WdmIoStackParameters {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmIoStackLocationInit {
    pub major: u8,
    pub minor: u8,
    pub device_object: u64,
    pub file_object: u64,
    pub parameters: WdmIoStackParameters,
}

pub fn write_wdm_driver_object(
    bytes: &mut [u8],
    init: WdmDriverObjectInit,
) -> Result<(), WdmLayoutError> {
    require(bytes, 4)?;
    require(bytes, init.driver_extension_offset.saturating_add(8))?;
    zero(bytes);
    put_i16(bytes, 0x00, WDM_X64_IO_TYPE_DRIVER);
    put_u16(bytes, 0x02, init.size_field);
    put_u64(bytes, 0x08, init.device_object);
    put_u64(bytes, init.driver_extension_offset, init.driver_extension);
    Ok(())
}

pub fn write_wdm_device_object(
    bytes: &mut [u8],
    init: WdmDeviceObjectInit,
) -> Result<(), WdmLayoutError> {
    require(bytes, WDM_X64_DEVICE_OBJECT_SIZE)?;
    zero(bytes);
    put_i16(bytes, 0x00, WDM_X64_IO_TYPE_DEVICE);
    put_u16(bytes, 0x02, WDM_X64_DEVICE_OBJECT_SIZE as u16);
    put_u64(bytes, 0x08, init.driver_object);
    put_u64(bytes, 0x10, init.next_device);
    put_u64(bytes, 0x40, init.device_extension);
    put_u32(bytes, 0x48, init.device_type);
    Ok(())
}

pub fn write_wdm_file_object(
    bytes: &mut [u8],
    init: WdmFileObjectInit,
) -> Result<(), WdmLayoutError> {
    require(bytes, WDM_X64_FILE_OBJECT_SIZE)?;
    zero(bytes);
    put_i16(bytes, 0x00, WDM_X64_IO_TYPE_FILE);
    put_u16(bytes, 0x02, WDM_X64_FILE_OBJECT_SIZE as u16);
    put_u64(bytes, 0x08, init.device_object);
    put_u64(bytes, 0x18, init.fs_context);
    put_u16(bytes, 0x58, init.file_name_len);
    put_u16(bytes, 0x5a, init.file_name_max_len);
    put_u64(bytes, 0x60, init.file_name_buffer);
    Ok(())
}

pub fn write_wdm_irp(bytes: &mut [u8], init: WdmIrpInit) -> Result<(), WdmLayoutError> {
    require(bytes, WDM_X64_IRP_SIZE)?;
    zero(bytes);
    put_u64(bytes, 0x18, init.system_buffer);
    put_u8(bytes, 0x42, 1);
    put_u8(bytes, 0x43, 1);
    put_u64(bytes, 0x70, init.user_buffer);
    put_u64(bytes, 0xb8, init.current_stack_location);
    Ok(())
}

pub fn write_wdm_io_stack_location(
    bytes: &mut [u8],
    init: WdmIoStackLocationInit,
) -> Result<(), WdmLayoutError> {
    require(bytes, WDM_X64_IO_STACK_LOCATION_SIZE)?;
    zero(bytes);
    put_u8(bytes, 0x00, init.major);
    put_u8(bytes, 0x01, init.minor);
    put_u64(bytes, 0x20, init.device_object);
    put_u64(bytes, 0x30, init.file_object);
    match init.parameters {
        WdmIoStackParameters::None => {}
        WdmIoStackParameters::Create {
            security_context,
            options,
            share_access,
            named_pipe_parameters,
        } => {
            put_u64(bytes, 0x08, security_context);
            put_u32(bytes, 0x10, options);
            put_u16(bytes, 0x1a, share_access);
            if let Some(parameters) = named_pipe_parameters {
                put_u64(bytes, 0x20, parameters);
            }
        }
        WdmIoStackParameters::Read { length } | WdmIoStackParameters::Write { length } => {
            put_u32(bytes, 0x08, length);
        }
        WdmIoStackParameters::SetInformation {
            length,
            information_class,
        } => {
            put_u32(bytes, 0x08, length);
            put_u32(bytes, 0x10, information_class);
        }
        WdmIoStackParameters::DeviceControl {
            output_buffer_length,
            input_buffer_length,
            io_control_code,
        } => {
            put_u32(bytes, 0x08, output_buffer_length);
            put_u32(bytes, 0x10, input_buffer_length);
            put_u32(bytes, 0x18, io_control_code);
        }
    }
    Ok(())
}

fn require(bytes: &[u8], len: usize) -> Result<(), WdmLayoutError> {
    if bytes.len() < len {
        Err(WdmLayoutError::BufferTooSmall)
    } else {
        Ok(())
    }
}

fn zero(bytes: &mut [u8]) {
    for b in bytes {
        *b = 0;
    }
}

fn put_u8(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset] = value;
}

fn put_i16(bytes: &mut [u8], offset: usize, value: i16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
