//! NT5 x64 WDM compatibility object layouts used by hosted Driver Host peers.
//!
//! The canonical I/O Manager owns ids and records. A hosted ReactOS driver still
//! expects local WDM-shaped `DRIVER_OBJECT`, `DEVICE_OBJECT`, `FILE_OBJECT`, IRP,
//! and `IO_STACK_LOCATION` memory. This module centralizes those compatibility
//! layouts as pure byte writers so the executive transport does not open-code
//! offsets.

pub const WDM_X64_DRIVER_OBJECT_SIZE: usize = 0x150;
pub const WDM_X64_DRIVER_EXTENSION_OFFSET: usize = 0x30;
pub const WDM_X64_DRIVER_EXTENSION_SIZE: usize = 0x50;
pub const WDM_X64_DRIVER_UNLOAD_OFFSET: usize = 0x68;
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
    InvalidField,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmDriverObjectInit {
    pub size_field: u16,
    pub device_object: u64,
    pub driver_extension: u64,
    pub driver_unload: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmDeviceObjectInit {
    pub driver_object: u64,
    pub next_device: u64,
    pub device_extension: u64,
    pub device_type: u32,
    pub stack_size: u8,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmFileObjectInit {
    pub device_object: u64,
    pub fs_context: u64,
    pub related_file_object: u64,
    pub file_name_len: u16,
    pub file_name_max_len: u16,
    pub file_name_buffer: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmOpenDeviceProjectionInit {
    pub driver_object: u64,
    pub driver_extension: u64,
    pub device_object: u64,
    pub file_object_context: u64,
    pub device_type: u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WdmIrpInit {
    /// Total bytes in the contiguous IRP plus stack-location packet.
    pub packet_size: u16,
    pub mdl_address: u64,
    pub flags: u32,
    pub system_buffer: u64,
    pub user_buffer: u64,
    /// `IRP.Tail.Overlay.Thread`; NPFS uses this for client-security capture.
    pub thread: u64,
    /// `IRP.Tail.Overlay.AuxiliaryBuffer`.
    pub auxiliary_buffer: u64,
    pub stack_count: u8,
    pub current_location: u8,
    pub current_stack_location: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdmIoStackParameters {
    None,
    Create {
        security_context: u64,
        options: u32,
        file_attributes: u16,
        share_access: u16,
        ea_length: u32,
        named_pipe_parameters: Option<u64>,
    },
    Read {
        length: u32,
    },
    Write {
        length: u32,
    },
    QueryInformation {
        length: u32,
        information_class: u32,
    },
    SetInformation {
        length: u32,
        information_class: u32,
        target_file_object: u64,
        control: crate::SetInformationControl,
    },
    QueryEa {
        length: u32,
        ea_list: u64,
        ea_list_length: u32,
        ea_index: u32,
    },
    SetEa {
        length: u32,
    },
    QueryQuota {
        length: u32,
        sid_list: u64,
        sid_list_length: u32,
        start_sid: u64,
    },
    SetQuota {
        length: u32,
    },
    DeviceControl {
        output_buffer_length: u32,
        input_buffer_length: u32,
        io_control_code: u32,
        type3_input_buffer: u64,
    },
    PnpStartDevice {
        allocated_resources: u64,
        allocated_resources_translated: u64,
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
    pub flags: u8,
    pub control: u8,
    pub device_object: u64,
    pub file_object: u64,
    pub parameters: WdmIoStackParameters,
}

pub fn write_wdm_driver_object(
    bytes: &mut [u8],
    init: WdmDriverObjectInit,
) -> Result<(), WdmLayoutError> {
    require(bytes, 4)?;
    require(bytes, WDM_X64_DRIVER_MAJOR_FUNCTION_OFFSET)?;
    zero(bytes);
    put_i16(bytes, 0x00, WDM_X64_IO_TYPE_DRIVER);
    put_u16(bytes, 0x02, init.size_field);
    put_u64(bytes, 0x08, init.device_object);
    put_u64(
        bytes,
        WDM_X64_DRIVER_EXTENSION_OFFSET,
        init.driver_extension,
    );
    put_u64(bytes, WDM_X64_DRIVER_UNLOAD_OFFSET, init.driver_unload);
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
    put_u8(bytes, 0x4c, init.stack_size);
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
    put_u64(bytes, 0x40, init.related_file_object);
    put_u16(bytes, 0x58, init.file_name_len);
    put_u16(bytes, 0x5a, init.file_name_max_len);
    put_u64(bytes, 0x60, init.file_name_buffer);
    Ok(())
}

pub fn write_wdm_open_device_projection(
    driver_bytes: &mut [u8],
    device_bytes: &mut [u8],
    file_bytes: &mut [u8],
    init: WdmOpenDeviceProjectionInit,
) -> Result<(), WdmLayoutError> {
    write_wdm_driver_object(
        driver_bytes,
        WdmDriverObjectInit {
            size_field: WDM_X64_DRIVER_OBJECT_SIZE as u16,
            device_object: init.device_object,
            driver_extension: init.driver_extension,
            driver_unload: 0,
        },
    )?;
    write_wdm_device_object(
        device_bytes,
        WdmDeviceObjectInit {
            driver_object: init.driver_object,
            next_device: 0,
            device_extension: 0,
            device_type: init.device_type,
            stack_size: 1,
        },
    )?;
    write_wdm_file_object(
        file_bytes,
        WdmFileObjectInit {
            device_object: init.device_object,
            fs_context: init.file_object_context,
            related_file_object: 0,
            file_name_len: 0,
            file_name_max_len: 0,
            file_name_buffer: 0,
        },
    )
}

pub fn write_wdm_irp(bytes: &mut [u8], init: WdmIrpInit) -> Result<(), WdmLayoutError> {
    require(bytes, WDM_X64_IRP_SIZE)?;
    let required_packet_size = WDM_X64_IRP_SIZE
        .checked_add(init.stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE)
        .ok_or(WdmLayoutError::InvalidField)?;
    let terminal_location = init
        .stack_count
        .checked_add(1)
        .ok_or(WdmLayoutError::InvalidField)?;
    if init.stack_count == 0
        || init.current_location == 0
        || init.current_location > terminal_location
        || (init.packet_size as usize) < required_packet_size
    {
        return Err(WdmLayoutError::InvalidField);
    }
    zero(bytes);
    put_u16(bytes, 0x00, 6);
    put_u16(bytes, 0x02, init.packet_size);
    put_u64(bytes, 0x08, init.mdl_address);
    put_u32(bytes, 0x10, init.flags);
    put_u64(bytes, 0x18, init.system_buffer);
    put_u8(bytes, 0x42, init.stack_count);
    put_u8(bytes, 0x43, init.current_location);
    put_u64(bytes, 0x70, init.user_buffer);
    put_u64(bytes, 0xa8, init.thread);
    put_u64(bytes, 0xb0, init.auxiliary_buffer);
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
    put_u8(bytes, 0x02, init.flags);
    put_u8(bytes, 0x03, init.control);
    put_u64(bytes, 0x28, init.device_object);
    put_u64(bytes, 0x30, init.file_object);
    match init.parameters {
        WdmIoStackParameters::None => {}
        WdmIoStackParameters::Create {
            security_context,
            options,
            file_attributes,
            share_access,
            ea_length,
            named_pipe_parameters,
        } => {
            put_u64(bytes, 0x08, security_context);
            put_u32(bytes, 0x10, options);
            put_u16(bytes, 0x18, file_attributes);
            put_u16(bytes, 0x1a, share_access);
            put_u32(bytes, 0x1c, ea_length);
            if let Some(parameters) = named_pipe_parameters {
                put_u64(bytes, 0x20, parameters);
            }
        }
        WdmIoStackParameters::Read { length } | WdmIoStackParameters::Write { length } => {
            put_u32(bytes, 0x08, length);
        }
        WdmIoStackParameters::QueryInformation {
            length,
            information_class,
        } => {
            put_u32(bytes, 0x08, length);
            put_u32(bytes, 0x10, information_class);
        }
        WdmIoStackParameters::SetInformation {
            length,
            information_class,
            target_file_object,
            control,
        } => {
            put_u32(bytes, 0x08, length);
            put_u32(bytes, 0x10, information_class);
            put_u64(bytes, 0x18, target_file_object);
            put_u32(bytes, 0x20, control.wire_value());
        }
        WdmIoStackParameters::QueryEa {
            length,
            ea_list,
            ea_list_length,
            ea_index,
        } => {
            put_u32(bytes, 0x08, length);
            put_u64(bytes, 0x10, ea_list);
            put_u32(bytes, 0x18, ea_list_length);
            put_u32(bytes, 0x1c, ea_index);
        }
        WdmIoStackParameters::SetEa { length } => {
            put_u32(bytes, 0x08, length);
        }
        WdmIoStackParameters::QueryQuota {
            length,
            sid_list,
            sid_list_length,
            start_sid,
        } => {
            put_u32(bytes, 0x08, length);
            put_u64(bytes, 0x10, sid_list);
            put_u32(bytes, 0x18, sid_list_length);
            put_u64(bytes, 0x20, start_sid);
        }
        WdmIoStackParameters::SetQuota { length } => {
            put_u32(bytes, 0x08, length);
        }
        WdmIoStackParameters::DeviceControl {
            output_buffer_length,
            input_buffer_length,
            io_control_code,
            type3_input_buffer,
        } => {
            put_u32(bytes, 0x08, output_buffer_length);
            put_u32(bytes, 0x10, input_buffer_length);
            put_u32(bytes, 0x18, io_control_code);
            put_u64(bytes, 0x20, type3_input_buffer);
        }
        WdmIoStackParameters::PnpStartDevice {
            allocated_resources,
            allocated_resources_translated,
        } => {
            put_u64(bytes, 0x08, allocated_resources);
            put_u64(bytes, 0x10, allocated_resources_translated);
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
