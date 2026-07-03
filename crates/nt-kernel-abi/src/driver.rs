//! `DRIVER_OBJECT` projection + IRP major-function codes (spec §7.1).

use bytemuck::{Pod, Zeroable};

use crate::{GuestAddr, UnicodeString};

/// The highest IRP major-function code (`IRP_MJ_MAXIMUM_FUNCTION`, WDK `wdm.h`).
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1b;
/// Number of major-function dispatch slots.
pub const MAJOR_FUNCTION_COUNT: usize = IRP_MJ_MAXIMUM_FUNCTION + 1;

/// IRP major-function codes (public WDK values).
pub mod major {
    pub const IRP_MJ_CREATE: u8 = 0x00;
    pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
    pub const IRP_MJ_CLOSE: u8 = 0x02;
    pub const IRP_MJ_READ: u8 = 0x03;
    pub const IRP_MJ_WRITE: u8 = 0x04;
    pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
    pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
    pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
    pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0e;
    pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0f;
    pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
    pub const IRP_MJ_CLEANUP: u8 = 0x12;
    pub const IRP_MJ_POWER: u8 = 0x16;
    pub const IRP_MJ_SYSTEM_CONTROL: u8 = 0x17;
    pub const IRP_MJ_PNP: u8 = 0x1b;
}

/// `DRIVER_OBJECT` (x64, 336 bytes). The loaded driver's `DriverEntry` fills
/// `major_function[major]` (offset 112) with its dispatch routines and optionally
/// `driver_unload`; `IoCreateDevice` links devices onto `device_object`. Pointer
/// fields are guest addresses in the Driver Host address space.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct DriverObject {
    pub type_: i16,
    pub size: i16,
    pub _pad0: u32,
    pub device_object: GuestAddr,
    pub flags: u32,
    pub _pad1: u32,
    pub driver_start: GuestAddr,
    pub driver_size: u32,
    pub _pad2: u32,
    pub driver_section: GuestAddr,
    pub driver_extension: GuestAddr,
    pub driver_name: UnicodeString,
    pub hardware_database: GuestAddr,
    pub fast_io_dispatch: GuestAddr,
    pub driver_init: GuestAddr,
    pub driver_start_io: GuestAddr,
    pub driver_unload: GuestAddr,
    pub major_function: [GuestAddr; MAJOR_FUNCTION_COUNT],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<DriverObject>() == 336);
    assert!(offset_of!(DriverObject, device_object) == 8);
    assert!(offset_of!(DriverObject, flags) == 16);
    assert!(offset_of!(DriverObject, driver_name) == 56);
    assert!(offset_of!(DriverObject, driver_unload) == 104);
    assert!(offset_of!(DriverObject, major_function) == 112);
};
