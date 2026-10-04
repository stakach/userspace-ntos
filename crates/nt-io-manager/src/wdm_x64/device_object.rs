//! Unpublished x64 WDM device-body construction.

use super::*;
use crate::device_queue::{
    initialize_device_queue, DeviceQueueEdits, DeviceQueueEntrySnapshot, DeviceQueueSnapshot,
    DeviceQueueWrite, LockedDeviceQueueMemory, DEVICE_QUEUE_SIZE,
};

const DEVICE_QUEUE_OFFSET: usize = 0xa0;
const QUEUE_LIST_OFFSET: usize = 0x50;

enum QueueInitialization {
    Device([u8; DEVICE_QUEUE_SIZE]),
    FileSystem([u8; 16]),
}

pub(super) struct PreparedDeviceObject {
    init: WdmDeviceObjectInit,
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
    if output_len < WDM_X64_DEVICE_OBJECT_SIZE {
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
    Ok(PreparedDeviceObject { init, queue })
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
    zero(bytes);
    put_i16(bytes, 0x00, WDM_X64_IO_TYPE_DEVICE);
    put_u16(bytes, 0x02, init.size_field);
    put_u64(bytes, 0x08, init.driver_object);
    put_u64(bytes, 0x10, init.next_device);
    put_u32(bytes, 0x30, init.flags);
    put_u32(bytes, 0x34, init.characteristics);
    put_u64(bytes, 0x40, init.device_extension);
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
