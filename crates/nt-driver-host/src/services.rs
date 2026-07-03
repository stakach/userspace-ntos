//! Driver-callable kernel services (spec §11): the `Io*` / `Rtl*` exports a
//! driver invokes (through trampolines on the kernel; directly from the mock
//! `DriverEntry` in host tests), plus the I/O Manager bridge they call.
//!
//! Every driver-provided pointer is validated against the runtime tables before
//! use (spec §19.2); a valid-looking pointer grants access only to the local
//! projection, never canonical authority (§19.3).

use alloc::string::String;

use nt_driver_runtime::{DriverRuntime, ObjectKind};
use nt_kernel_abi::{device_flags, GuestAddr, UnicodeString};
use nt_status::NtStatus;

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

/// A device-creation request the Driver Host forwards to the I/O Manager.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeCreateDevice {
    pub name: Option<String>,
    pub device_type: u32,
    pub characteristics: u32,
    pub flags: u32,
    pub extension_size: u32,
}

/// The canonical ids the I/O Manager assigns to a created device.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeDeviceIds {
    pub device_id: u64,
    pub object_id: u64,
}

/// The bridge to the I/O Manager (`DH_OP_CREATE_DEVICE` etc., spec §11). In-process
/// here; a SURT transport in the component (M9).
pub trait IoManagerBridge {
    fn create_device(&mut self, req: &BridgeCreateDevice) -> Result<BridgeDeviceIds, NtStatus>;
    fn delete_device(&mut self, device_id: u64) -> NtStatus;
    fn create_symbolic_link(&mut self, link: &str, target: &str) -> NtStatus;
    fn delete_symbolic_link(&mut self, link: &str) -> NtStatus;
}

/// A bridge that satisfies nothing — for drivers that create no devices.
pub struct NullBridge;

impl IoManagerBridge for NullBridge {
    fn create_device(&mut self, _req: &BridgeCreateDevice) -> Result<BridgeDeviceIds, NtStatus> {
        Err(NtStatus(STATUS_INVALID_PARAMETER))
    }
    fn delete_device(&mut self, _device_id: u64) -> NtStatus {
        NtStatus(STATUS_INVALID_PARAMETER)
    }
    fn create_symbolic_link(&mut self, _link: &str, _target: &str) -> NtStatus {
        NtStatus(STATUS_INVALID_PARAMETER)
    }
    fn delete_symbolic_link(&mut self, _link: &str) -> NtStatus {
        NtStatus(STATUS_INVALID_PARAMETER)
    }
}

/// The services a driver sees during a call — the runtime it lives in + the I/O
/// Manager bridge. Passed to the driver's `DriverEntry` / dispatch routines.
pub struct DriverServices<'a> {
    runtime: &'a mut DriverRuntime,
    bridge: &'a mut dyn IoManagerBridge,
}

impl<'a> DriverServices<'a> {
    pub fn new(runtime: &'a mut DriverRuntime, bridge: &'a mut dyn IoManagerBridge) -> Self {
        Self { runtime, bridge }
    }

    pub fn runtime(&self) -> &DriverRuntime {
        self.runtime
    }
    pub fn runtime_mut(&mut self) -> &mut DriverRuntime {
        self.runtime
    }
    pub fn arena_mut(&mut self) -> &mut nt_driver_runtime::Arena {
        self.runtime.arena_mut()
    }

    // --- IoCreateDevice (spec §11.1) ---------------------------------------

    /// `IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName, DeviceType,
    /// DeviceCharacteristics, Exclusive, DeviceObjectOut)`.
    #[allow(clippy::too_many_arguments)]
    pub fn io_create_device(
        &mut self,
        driver_object: GuestAddr,
        extension_size: u32,
        device_name: GuestAddr,
        device_type: u32,
        characteristics: u32,
        _exclusive: bool,
        device_object_out: GuestAddr,
    ) -> i32 {
        if !self.runtime.validate_driver_object(driver_object) {
            return STATUS_INVALID_PARAMETER;
        }
        if !self.runtime.validate_writable(device_object_out, 8) {
            return STATUS_INVALID_PARAMETER;
        }
        let name = if device_name.is_null() {
            None
        } else {
            match self.runtime.read_unicode_string(device_name) {
                Some(s) => Some(s),
                None => return STATUS_INVALID_PARAMETER,
            }
        };

        // Local DEVICE_OBJECT projection (buffered I/O is the v0.1 target).
        let flags = device_flags::DO_BUFFERED_IO;
        let dev = match self.runtime.create_device_object(
            device_type,
            characteristics,
            flags,
            extension_size as usize,
        ) {
            Some(d) => d,
            None => return STATUS_INSUFFICIENT_RESOURCES,
        };

        let req = BridgeCreateDevice {
            name,
            device_type,
            characteristics,
            flags,
            extension_size,
        };
        match self.bridge.create_device(&req) {
            Ok(ids) => {
                self.runtime
                    .objects_mut()
                    .set_canonical_id(dev, ids.device_id);
                if !self.runtime.arena_mut().write(device_object_out, dev) {
                    return STATUS_INVALID_PARAMETER;
                }
                STATUS_SUCCESS
            }
            Err(status) => {
                self.runtime.objects_mut().retire(dev);
                status.raw()
            }
        }
    }

    // --- IoDeleteDevice (spec §11.2) ---------------------------------------

    pub fn io_delete_device(&mut self, device: GuestAddr) -> i32 {
        let device_id = match self.runtime.validate(device, ObjectKind::DeviceObject) {
            Some(e) => e.canonical_id,
            None => return STATUS_INVALID_PARAMETER,
        };
        let status = self.bridge.delete_device(device_id);
        self.runtime.objects_mut().retire(device);
        status.raw()
    }

    // --- IoCreateSymbolicLink / IoDeleteSymbolicLink (spec §11.3/§11.4) -----

    pub fn io_create_symbolic_link(
        &mut self,
        symlink_name: GuestAddr,
        device_name: GuestAddr,
    ) -> i32 {
        let link = match self.runtime.read_unicode_string(symlink_name) {
            Some(s) => s,
            None => return STATUS_INVALID_PARAMETER,
        };
        let target = match self.runtime.read_unicode_string(device_name) {
            Some(s) => s,
            None => return STATUS_INVALID_PARAMETER,
        };
        self.bridge.create_symbolic_link(&link, &target).raw()
    }

    pub fn io_delete_symbolic_link(&mut self, symlink_name: GuestAddr) -> i32 {
        let link = match self.runtime.read_unicode_string(symlink_name) {
            Some(s) => s,
            None => return STATUS_INVALID_PARAMETER,
        };
        self.bridge.delete_symbolic_link(&link).raw()
    }

    // --- RtlInitUnicodeString ----------------------------------------------

    /// `RtlInitUnicodeString(DestinationString, SourceString)` — point `dest` at a
    /// NUL-terminated UTF-16 string at `source`, computing its length.
    pub fn rtl_init_unicode_string(&mut self, dest: GuestAddr, source: GuestAddr) -> i32 {
        if source.is_null() {
            let empty = UnicodeString {
                length: 0,
                maximum_length: 0,
                _reserved: 0,
                buffer: GuestAddr::NULL,
            };
            return if self.runtime.arena_mut().write(dest, empty) {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_PARAMETER
            };
        }
        let mut units: u32 = 0;
        loop {
            let at = GuestAddr(source.0 + units as u64 * 2);
            match self.runtime.arena().read::<u16>(at) {
                Some(0) => break,
                Some(_) => {
                    units += 1;
                    if units > 32767 {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                None => return STATUS_INVALID_PARAMETER,
            }
        }
        let us = UnicodeString {
            length: (units * 2) as u16,
            maximum_length: ((units + 1) * 2) as u16,
            _reserved: 0,
            buffer: source,
        };
        if self.runtime.arena_mut().write(dest, us) {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_PARAMETER
        }
    }
}
