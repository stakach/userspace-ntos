//! `DEVICE_OBJECT` projection (spec §7.1).

use bytemuck::{Pod, Zeroable};

use crate::GuestAddr;

/// `DO_*` device-object flags (subset).
pub mod device_flags {
    pub const DO_BUFFERED_IO: u32 = 0x0000_0004;
    pub const DO_EXCLUSIVE: u32 = 0x0000_0008;
    pub const DO_DIRECT_IO: u32 = 0x0000_0010;
    pub const DO_DEVICE_INITIALIZING: u32 = 0x0000_0080;
}

/// `FILE_DEVICE_*` device types (subset).
pub mod device_type {
    pub const FILE_DEVICE_BEEP: u32 = 0x0000_0001;
    pub const FILE_DEVICE_DISK: u32 = 0x0000_0007;
    pub const FILE_DEVICE_NULL: u32 = 0x0000_0015;
    pub const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
}

/// `DEVICE_OBJECT` (x64, 336 bytes, 16-byte aligned). The driver reads `flags`,
/// `characteristics`, `device_extension`, `device_type`, `stack_size`; the tail
/// (device queue, DPC, event, …) is opaque for the v0.1 software-driver target.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct DeviceObject {
    pub type_: i16,
    pub size: u16,
    pub reference_count: i32,
    pub driver_object: GuestAddr,
    pub next_device: GuestAddr,
    pub attached_device: GuestAddr,
    pub current_irp: GuestAddr,
    pub timer: GuestAddr,
    pub flags: u32,
    pub characteristics: u32,
    pub vpb: GuestAddr,
    pub device_extension: GuestAddr,
    pub device_type: u32,
    pub stack_size: i8,
    pub _pad: [u8; 3],
    /// Queue union / alignment / device queue / DPC / lock / … — opaque tail.
    pub _reserved_tail: [u8; 256],
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<DeviceObject>() == 336);
    assert!(align_of::<DeviceObject>() == 16);
    assert!(offset_of!(DeviceObject, driver_object) == 8);
    assert!(offset_of!(DeviceObject, flags) == 48);
    assert!(offset_of!(DeviceObject, characteristics) == 52);
    assert!(offset_of!(DeviceObject, device_extension) == 64);
    assert!(offset_of!(DeviceObject, device_type) == 72);
    assert!(offset_of!(DeviceObject, stack_size) == 76);
};
