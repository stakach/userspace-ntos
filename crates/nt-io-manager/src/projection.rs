//! Build Driver Host projections from the canonical records (spec §4.3).
//!
//! A projection is the **local** view a Driver Host peer receives — ids + scalars
//! only, never a canonical pointer (spec §4.2). The wire structs live in
//! `nt-io-abi`; these builders derive them from the I/O Manager's records.

use nt_io_abi::{DeviceObjectProjection, DriverObjectProjection, FileObjectProjection};

use crate::{DeviceId, DriverId, FileId, IoManager};

impl<P> IoManager<P> {
    /// Project a driver for a Driver Host peer.
    pub fn project_driver(&self, driver: DriverId) -> Option<DriverObjectProjection> {
        let d = self.driver(driver)?;
        Some(DriverObjectProjection {
            driver_id: driver.0,
            flags: d.flags.bits(),
            device_count: d.devices.len() as u32,
        })
    }

    /// Project a device for a Driver Host peer.
    pub fn project_device(&self, device: DeviceId) -> Option<DeviceObjectProjection> {
        let d = self.device(device)?;
        Some(DeviceObjectProjection {
            device_id: device.0,
            driver_id: d.driver_id.0,
            device_type: d.device_type.0,
            characteristics: d.characteristics.bits(),
            flags: d.flags.bits(),
            extension_size: d.extension_size,
            alignment_requirement: d.alignment_requirement,
            stack_size: d.stack_size as u32,
        })
    }

    /// Project a file for a Driver Host peer.
    pub fn project_file(&self, file: FileId) -> Option<FileObjectProjection> {
        let f = self.file(file)?;
        Some(FileObjectProjection {
            file_id: file.0,
            device_id: f.device_id.0,
            flags: f.flags.bits(),
            _reserved: 0,
        })
    }
}
