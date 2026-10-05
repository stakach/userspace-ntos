//! Unpublished x64 WDM device-body construction.

use super::*;
use crate::device_queue::{
    initialize_device_queue, DeviceQueueEdits, DeviceQueueEntrySnapshot, DeviceQueueSnapshot,
    DeviceQueueWrite, LockedDeviceQueueMemory, DEVICE_QUEUE_SIZE,
};

const DEVICE_QUEUE_OFFSET: usize = 0xa0;
const QUEUE_LIST_OFFSET: usize = 0x50;
pub const WDM_X64_DEVICE_OBJECT_EXTENSION_SIZE: usize = 0x50;

/// ReactOS x64 pool alignment; logical DEVICE_OBJECT.Size excludes this padding and kernel body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WdmDeviceObjectAllocationLayout {
    driver_size: u32,
    size_field: u16,
    kernel_offset: usize,
    allocation_size: usize,
}

impl WdmDeviceObjectAllocationLayout {
    pub const fn plan(driver_size: u32) -> Result<Self, WdmLayoutError> {
        // Keep the supported logical Size representable, independently of allocation padding.
        if driver_size > u16::MAX as u32 - WDM_X64_DEVICE_OBJECT_SIZE as u32 {
            return Err(WdmLayoutError::InvalidField);
        }
        let logical = WDM_X64_DEVICE_OBJECT_SIZE + driver_size as usize;
        let kernel_offset = (logical + 15) & !15;
        Ok(Self {
            driver_size,
            size_field: logical as u16,
            kernel_offset,
            allocation_size: kernel_offset + WDM_X64_DEVICE_OBJECT_EXTENSION_SIZE,
        })
    }
    pub const fn allocation_size(self) -> usize {
        self.allocation_size
    }
    pub const fn size_field(self) -> u16 {
        self.size_field
    }
    pub const fn driver_extension_offset(self) -> Option<usize> {
        if self.driver_size == 0 {
            None
        } else {
            Some(WDM_X64_DEVICE_OBJECT_SIZE)
        }
    }
    pub const fn kernel_extension_offset(self) -> usize {
        self.kernel_offset
    }
}

enum QueueInitialization {
    Device([u8; DEVICE_QUEUE_SIZE]),
    FileSystem([u8; 16]),
}

pub(super) struct PreparedDeviceObject {
    init: WdmDeviceObjectInit,
    layout: WdmDeviceObjectAllocationLayout,
    queue: QueueInitialization,
}

/// A fresh construction encoding, not a live queue or an object-authority registry.
struct QueueEncoding {
    address: u64,
    bytes: [u8; DEVICE_QUEUE_SIZE],
}

impl LockedDeviceQueueMemory for QueueEncoding {
    type Error = WdmLayoutError;

    fn validate_unpublished_queue_storage(&self, address: u64) -> Result<(), Self::Error> {
        if address == self.address {
            Ok(())
        } else {
            Err(WdmLayoutError::InvalidField)
        }
    }

    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error> {
        self.validate_unpublished_queue_storage(address)?;
        DeviceQueueSnapshot::read(&self.bytes).map_err(|_| WdmLayoutError::InvalidField)
    }

    fn entry(&self, _address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> {
        Err(WdmLayoutError::InvalidField)
    }

    fn apply(&mut self, edits: &DeviceQueueEdits) {
        // The core initializer emits only admitted fields within this exclusively owned encoding.
        for edit in edits.writes() {
            let (address, value, length) = match *edit {
                DeviceQueueWrite::U8 { address, value } => (address, value as u64, 1),
                DeviceQueueWrite::U16 { address, value } => (address, value as u64, 2),
                DeviceQueueWrite::U32 { address, value } => (address, value as u64, 4),
                DeviceQueueWrite::U64 { address, value } => (address, value, 8),
            };
            let offset = usize::try_from(address - self.address).unwrap();
            self.bytes[offset..offset + length].copy_from_slice(&value.to_le_bytes()[..length]);
        }
    }
}

pub(super) fn prepare_device_object(
    output_len: usize,
    init: WdmDeviceObjectInit,
) -> Result<PreparedDeviceObject, WdmLayoutError> {
    let layout = WdmDeviceObjectAllocationLayout::plan(init.driver_extension_size)?;
    if output_len < layout.allocation_size() {
        return Err(WdmLayoutError::BufferTooSmall);
    }
    if init.device_object_address == 0
        || init.device_object_address & 15 != 0
        || u64::try_from(output_len)
            .ok()
            .and_then(|length| init.device_object_address.checked_add(length))
            .is_none()
    {
        return Err(WdmLayoutError::InvalidField);
    }
    // NT5 IoCreateDevice initializes the filesystem registration list instead of a device queue.
    let queue = if matches!(init.device_type, 0x03 | 0x08 | 0x09 | 0x14 | 0x20) {
        let head = init.device_object_address + QUEUE_LIST_OFFSET as u64;
        let mut bytes = [0; 16];
        put_u64(&mut bytes, 0, head);
        put_u64(&mut bytes, 8, head);
        QueueInitialization::FileSystem(bytes)
    } else {
        let address = init.device_object_address + DEVICE_QUEUE_OFFSET as u64;
        let mut encoding = QueueEncoding {
            address,
            bytes: [0; DEVICE_QUEUE_SIZE],
        };
        initialize_device_queue(&mut encoding, address).map_err(|_| WdmLayoutError::InvalidField)?;
        QueueInitialization::Device(encoding.bytes)
    };
    Ok(PreparedDeviceObject { init, layout, queue })
}

pub fn write_wdm_device_object(
    bytes: &mut [u8],
    init: WdmDeviceObjectInit,
) -> Result<(), WdmLayoutError> {
    let prepared = prepare_device_object(bytes.len(), init)?;
    commit_device_object(bytes, prepared);
    Ok(())
}

pub(super) fn commit_device_object(bytes: &mut [u8], prepared: PreparedDeviceObject) {
    let init = prepared.init;
    let layout = prepared.layout;
    zero(bytes);
    put_i16(bytes, 0x00, WDM_X64_IO_TYPE_DEVICE);
    put_u16(bytes, 0x02, layout.size_field());
    put_u64(bytes, 0x08, init.driver_object);
    put_u64(bytes, 0x10, init.next_device);
    put_u32(bytes, 0x30, init.flags);
    put_u32(bytes, 0x34, init.characteristics);
    put_u64(bytes, 0x40, layout.driver_extension_offset()
        .map_or(0, |offset| init.device_object_address + offset as u64));
    let kernel_offset = layout.kernel_extension_offset();
    put_u64(bytes, 0x138, init.device_object_address + kernel_offset as u64);
    put_u16(bytes, kernel_offset, 13);
    put_u16(bytes, kernel_offset + 2, 0);
    put_u64(bytes, kernel_offset + 8, init.device_object_address);
    put_u32(bytes, 0x48, init.device_type);
    put_u8(bytes, 0x4c, init.stack_size);
    match prepared.queue {
        QueueInitialization::Device(queue) => {
            bytes[DEVICE_QUEUE_OFFSET..DEVICE_QUEUE_OFFSET + DEVICE_QUEUE_SIZE]
                .copy_from_slice(&queue);
        }
        QueueInitialization::FileSystem(list) => {
            bytes[QUEUE_LIST_OFFSET..QUEUE_LIST_OFFSET + list.len()].copy_from_slice(&list);
        }
    }
}
