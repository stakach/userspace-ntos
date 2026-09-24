//! Authenticated capture of a hosted kernel IoCreateFile request.

use super::*;
use nt_io_manager::io_create_file_wire::{decode, IoCreateFileWireError};

const STATUS_OBJECT_NAME_INVALID: u32 = 0xc000_0033;

fn copy_name(name: &[u16]) -> Result<Vec<u16>, u32> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(name.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    owned.extend_from_slice(name);
    Ok(owned)
}

pub(super) struct CapturedCreate {
    pub caller: nt_process::native_handle::NativeHandleCaller,
    pub request: nt_io_manager::io_create_file::OwnedIoCreateFileRequest,
    pub device_id: u64,
    pub related_file_id: Option<u64>,
    pub related_file: Option<crate::driver_launch::hosted_file_capture::Capture>,
    pub relative_name: Vec<u16>,
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

/// The source pool allocation is used only to copy an exact packet. No driver pointer survives
/// this function; caller and device authority come from the physical ingress and canonical tables.
pub(super) fn capture(
    channel: &crate::spawn_hosts::PumpChannel,
    active_reply_cap: u64,
    component_packet: u64,
    packet_length: u64,
) -> Result<CapturedCreate, u32> {
    let _durable = crate::allocator::enter_durable();
    let (_, instance) =
        instance_for_pump_channel(channel, active_reply_cap).ok_or(STATUS_ACCESS_DENIED as u32)?;
    let caller = unsafe { crate::provider_registry_caller::resolve(channel)? };
    let length = usize::try_from(packet_length).map_err(|_| STATUS_INVALID_BUFFER_SIZE as u32)?;
    if length < nt_io_manager::io_create_file_wire::IO_CREATE_FILE_WIRE_HEADER_BYTES
        || packet_length >= FSD_POOL_FRAMES * 0x1000
    {
        return Err(STATUS_INVALID_BUFFER_SIZE as u32);
    }
    let exec_packet = unsafe {
        hosted_instance_pool_allocation_exec_if_live(instance, component_packet, packet_length)
    }
    .ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let packet = unsafe { core::slice::from_raw_parts(exec_packet as *const u8, length) };
    let request = decode(packet).map_err(wire_status)?;
    let case_insensitive = request.object_attributes & 0x40 != 0;
    let (device_id, related_file_id, related_file, relative_name) = if request.root_directory == 0 {
        let (device_id, prefix) = io_manager_mut()
            .device_prefix_for_file_name(&request.name, case_insensitive)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND as u32)?;
        (device_id.raw(), None, None, copy_name(&request.name[prefix..])?)
    } else {
        let (file_id, device_id) = unsafe {
            crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.lookup_native_routed_file_handle(caller, request.root_directory, 0)
            })?
        };
        if request.name.first() == Some(&(b'\\' as u16)) {
            return Err(STATUS_OBJECT_NAME_INVALID as u32);
        }
        let related_file = crate::driver_launch::hosted_file_capture::capture(file_id, device_id, 0)?;
        (device_id, Some(file_id), Some(related_file), copy_name(&request.name)?)
    };
    Ok(CapturedCreate {
        caller,
        request,
        device_id,
        related_file_id,
        related_file,
        relative_name,
    })
}
