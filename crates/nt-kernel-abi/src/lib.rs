//! # `nt-kernel-abi` — driver-visible NT kernel structure projections
//!
//! The fixed-layout `#[repr(C)]` structures a loaded WDM driver sees inside a
//! Driver Host — `DRIVER_OBJECT`, `DEVICE_OBJECT`, `IRP`, `IO_STACK_LOCATION`,
//! `UNICODE_STRING`, `IO_STATUS_BLOCK` — laid out at the **exact WDK x86_64 field
//! offsets** so a driver's unmodified machine code accesses the right fields
//! (e.g. `DriverObject->MajorFunction[major]`). These are **local Driver Host
//! projections**, not canonical kernel objects, and are **not** a cross-component
//! ABI (cross-component messages carry ids). Reference: the public WDK
//! `km/wdm.h`. `no_std`, no seL4 / executive dependency.

#![no_std]

mod device;
mod driver;
mod irp;
mod string;

pub use device::{device_flags, device_type, DeviceObject};
pub use driver::{major, DriverObject, IRP_MJ_MAXIMUM_FUNCTION, MAJOR_FUNCTION_COUNT};
pub use irp::{
    DeviceIoControlParams, IoStackLocation, IoStatusBlock, Irp, ListEntry, ReadWriteParams,
};
pub use string::UnicodeString;

use bytemuck::{Pod, Zeroable};

/// An address in the Driver Host's own address space — a "guest" pointer the
/// loaded driver sees. Meaningful only inside the Driver Host; never canonical
/// and never used as authority (spec §19.3).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default, Pod, Zeroable)]
pub struct GuestAddr(pub u64);

impl GuestAddr {
    pub const NULL: GuestAddr = GuestAddr(0);

    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Debug for GuestAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GuestAddr(0x{:016x})", self.0)
    }
}

/// A typed guest pointer, for call-gate function signatures (spec §8.1). Not part
/// of any `#[repr(C)]` projection layout — the layouts use [`GuestAddr`].
#[repr(transparent)]
pub struct GuestPtr<T> {
    pub addr: u64,
    _marker: core::marker::PhantomData<T>,
}

impl<T> GuestPtr<T> {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self {
            addr,
            _marker: core::marker::PhantomData,
        }
    }
    #[inline]
    pub const fn null() -> Self {
        Self::new(0)
    }
    #[inline]
    pub const fn is_null(self) -> bool {
        self.addr == 0
    }
    #[inline]
    pub const fn addr(self) -> GuestAddr {
        GuestAddr(self.addr)
    }
}

impl<T> Copy for GuestPtr<T> {}
impl<T> Clone for GuestPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::offset_of;

    #[test]
    fn guest_ptr_and_addr() {
        assert!(GuestAddr::NULL.is_null());
        assert!(!GuestAddr(0x1000).is_null());
        let p: GuestPtr<u32> = GuestPtr::new(0x2000);
        assert_eq!(p.addr(), GuestAddr(0x2000));
        assert!(GuestPtr::<u8>::null().is_null());
    }

    #[test]
    fn driver_object_dispatch_table_layout() {
        // A driver writes MajorFunction[major] = routine; check the slot address
        // matches the WDK offset (112 + major*8).
        let mut drv = DriverObject::zeroed();
        drv.major_function[major::IRP_MJ_DEVICE_CONTROL as usize] = GuestAddr(0xDEAD);
        let base = &drv as *const _ as usize;
        let slot = &drv.major_function[major::IRP_MJ_DEVICE_CONTROL as usize] as *const _ as usize;
        assert_eq!(slot - base, 112 + major::IRP_MJ_DEVICE_CONTROL as usize * 8);
        assert_eq!(
            drv.major_function[major::IRP_MJ_DEVICE_CONTROL as usize],
            GuestAddr(0xDEAD)
        );
    }

    #[test]
    fn unicode_string_byte_lengths() {
        let s = UnicodeString::new(GuestAddr(0x1000), 12); // "\Device\Test0"-ish
        assert_eq!(s.length, 24); // bytes
        assert_eq!(s.code_units(), 12);
        assert_eq!(offset_of!(UnicodeString, buffer), 8);
    }

    #[test]
    fn ioctl_parameters_roundtrip() {
        let mut sl = IoStackLocation::zeroed();
        sl.major_function = major::IRP_MJ_DEVICE_CONTROL;
        sl.set_device_io_control(DeviceIoControlParams {
            output_buffer_length: 64,
            input_buffer_length: 32,
            io_control_code: 0x2200_0800,
            ..Default::default()
        });
        let p = sl.device_io_control();
        assert_eq!(p.output_buffer_length, 64);
        assert_eq!(p.input_buffer_length, 32);
        assert_eq!(p.io_control_code, 0x2200_0800);
        // io_control_code lives at IO_STACK_LOCATION offset 24 (parameters + 16).
        let base = &sl as *const _ as usize;
        let code = &sl.parameters[2] as *const _ as usize; // parameters[2] == +16
        assert_eq!(code - base, 24);
    }

    #[test]
    fn irp_status_and_stack_location() {
        let mut irp = Irp::zeroed();
        irp.io_status = IoStatusBlock {
            status: 0,
            information: 42,
            ..Default::default()
        };
        irp.current_stack_location = GuestAddr(0x3000);
        assert_eq!(irp.io_status.information, 42);
        let base = &irp as *const _ as usize;
        assert_eq!(&irp.current_stack_location as *const _ as usize - base, 184);
    }
}
