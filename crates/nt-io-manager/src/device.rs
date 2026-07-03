//! Device records (spec §11).

use nt_io_abi::{DeviceId, DriverId};
use nt_types::{NtPath, ObjectId};

/// An NT device type (`FILE_DEVICE_*`). A `u32` on the wire; a few common values
/// are named here.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct DeviceType(pub u32);

impl DeviceType {
    pub const BEEP: DeviceType = DeviceType(0x0000_0001);
    pub const DISK: DeviceType = DeviceType(0x0000_0007);
    pub const KEYBOARD: DeviceType = DeviceType(0x0000_000b);
    pub const NULL: DeviceType = DeviceType(0x0000_0015);
    pub const SERIAL_PORT: DeviceType = DeviceType(0x0000_001b);
    pub const UNKNOWN: DeviceType = DeviceType(0x0000_0022);
}

bitflags::bitflags! {
    /// `FILE_*` device characteristics.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct DeviceCharacteristics: u32 {
        const REMOVABLE_MEDIA = 0x0000_0001;
        const READ_ONLY_DEVICE = 0x0000_0002;
        const FLOPPY_DISKETTE = 0x0000_0004;
        const WRITE_ONCE_MEDIA = 0x0000_0008;
        const DEVICE_SECURE_OPEN = 0x0000_0100;
    }
}

bitflags::bitflags! {
    /// `DO_*` device-object flags. `DO_BUFFERED_IO` / `DO_DIRECT_IO` select the
    /// transfer model for reads/writes (v0.1 honours buffered).
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct DeviceFlags: u32 {
        const BUFFERED_IO = 0x0000_0004;
        const EXCLUSIVE = 0x0000_0008;
        const DIRECT_IO = 0x0000_0010;
        const DEVICE_INITIALIZING = 0x0000_0080;
    }
}

/// Canonical I/O Manager device record (spec §11.1). `object_id` points at the
/// Object Manager `Device` object. For v0.1 there are no attachment stacks:
/// `top_of_stack == id` and `attached_to == None`.
pub struct DeviceRecord {
    pub id: DeviceId,
    pub object_id: ObjectId,
    pub driver_id: DriverId,
    pub name: Option<NtPath>,
    pub device_type: DeviceType,
    pub characteristics: DeviceCharacteristics,
    pub flags: DeviceFlags,
    pub stack_size: u8,
    pub alignment_requirement: u32,
    pub extension_size: u32,
    pub attached_to: Option<DeviceId>,
    pub top_of_stack: DeviceId,
    pub delete_pending: bool,
}

impl DeviceRecord {
    /// A newly-created device (id/top_of_stack filled in by the caller once the
    /// store assigns the id).
    pub fn new(
        object_id: ObjectId,
        driver_id: DriverId,
        name: Option<NtPath>,
        device_type: DeviceType,
        characteristics: DeviceCharacteristics,
        flags: DeviceFlags,
        extension_size: u32,
    ) -> Self {
        Self {
            id: DeviceId::NULL,
            object_id,
            driver_id,
            name,
            device_type,
            characteristics,
            flags,
            stack_size: 1,
            alignment_requirement: 0,
            extension_size,
            attached_to: None,
            top_of_stack: DeviceId::NULL,
            delete_pending: false,
        }
    }

    /// True if reads/writes on this device use the buffered model.
    pub fn is_buffered_io(&self) -> bool {
        self.flags.contains(DeviceFlags::BUFFERED_IO)
    }
}
