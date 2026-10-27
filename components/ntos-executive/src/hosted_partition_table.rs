//! Native `IoReadPartitionTableEx` over the caller's exact device stack.
//!
//! Every geometry or sector request owns a source IRP until terminal completion. The returned
//! layout is an ordinary component pool allocation, transferred to the driver only on success.

use super::*;

const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00a0;
const DISK_GEOMETRY_EX_BYTES: u32 = 40;
const DISK_CORRUPT_ERROR: i32 = 0xc000_0032u32 as i32;
const IO_DEVICE_ERROR: i32 = 0xc000_0185u32 as i32;

/// Keep the exact canonical device incarnation alive across geometry, all sector reads, and
/// result publication. The root reference service validates domain, generation, and type.
struct ReferencedDevice(u64);

impl ReferencedDevice {
    fn acquire(device: u64) -> Result<Self, i32> {
        let status = hosted_driver_object_reference::ob_reference_object_by_pointer(
            device, 0, 0, 0,
        );
        (status == STATUS_SUCCESS).then_some(Self(device)).ok_or(status)
    }
}

impl Drop for ReferencedDevice {
    fn drop(&mut self) {
        let _ = s_obf_dereference_object(self.0);
    }
}

struct PartitionIo {
    buffer: u64,
    event: u64,
    iosb: u64,
    capacity: u32,
}

impl PartitionIo {
    unsafe fn new(capacity: u32) -> Option<Self> {
        if capacity == 0 { return None; }
        let buffer = pool_alloc_zeroed(u64::from(capacity));
        if buffer == 0 { return None; }
        let event = pool_alloc_zeroed(24);
        if event == 0 {
            pool_free(buffer);
            return None;
        }
        let iosb = pool_alloc_zeroed(16);
        if iosb == 0 {
            pool_free(event);
            pool_free(buffer);
            return None;
        }
        Some(Self { buffer, event, iosb, capacity })
    }

    /// The source packet owns its own transferred buffers. `self` stays live during a parked
    /// wait and is not dropped until its IOSB receives an exact terminal status.
    unsafe fn prepare(&mut self) {
        s_ke_initialize_event(self.event, 0, 0);
        write_unaligned(self.iosb as *mut i32, STATUS_PENDING as i32);
        write_unaligned((self.iosb + 8) as *mut u64, 0);
    }

    unsafe fn dispatch(&mut self, device: u64, irp: u64) -> Result<u64, i32> {
        let direct = s_iof_call_driver(device, irp);
        if direct == STATUS_PENDING as i32 {
            let wait = s_ke_wait_for_single_object(self.event, 5, 0, 0, 0);
            if wait != STATUS_SUCCESS {
                crate::provider_bugcheck::report(
                    0xc4, [device, irp, self.event, wait as u32 as u64],
                );
            }
        }
        let terminal = read_unaligned(self.iosb as *const i32);
        if terminal == STATUS_PENDING as i32 {
            // A returned non-pending dispatch must have completed. Reusing the source packet
            // or its buffers after an uncertain completion would violate native ownership.
            crate::provider_bugcheck::report(
                0xc4, [device, irp, self.iosb, direct as u32 as u64],
            );
        }
        if terminal < 0 { return Err(terminal); }
        Ok(read_unaligned((self.iosb + 8) as *const u64))
    }

    unsafe fn geometry(&mut self, device: u64) -> Result<(u32, u64), i32> {
        self.prepare();
        let irp = hosted_synchronous_fsd_request::build_control(
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, device,
            self.buffer, self.capacity, self.event, self.iosb,
        );
        if irp == 0 { return Err(STATUS_INSUFFICIENT_RESOURCES); }
        let information = self.dispatch(device, irp)?;
        if information < 32 { return Err(IO_DEVICE_ERROR); }
        let sector_bytes = read_unaligned((self.buffer + 20) as *const u32);
        let disk_bytes = read_unaligned((self.buffer + 24) as *const u64);
        if !(512..=65_536).contains(&sector_bytes)
            || !sector_bytes.is_power_of_two()
            || disk_bytes < u64::from(sector_bytes) * 2
        {
            return Err(STATUS_DEVICE_NOT_READY);
        }
        Ok((sector_bytes, disk_bytes / u64::from(sector_bytes)))
    }

    unsafe fn read_sector(
        &mut self, device: u64, lba: u64, out: &mut [u8],
    ) -> Result<(), i32> {
        if out.len() != self.capacity as usize { return Err(STATUS_INVALID_PARAMETER); }
        let offset = lba.checked_mul(u64::from(self.capacity))
            .ok_or(STATUS_INVALID_PARAMETER)?;
        self.prepare();
        let irp = hosted_synchronous_fsd_request::build(
            u32::from(major::IRP_MJ_READ), device, self.buffer, self.capacity,
            &offset as *const u64 as u64, self.event, self.iosb,
        );
        if irp == 0 { return Err(STATUS_INSUFFICIENT_RESOURCES); }
        let information = self.dispatch(device, irp)?;
        if information != u64::from(self.capacity) { return Err(IO_DEVICE_ERROR); }
        core::ptr::copy_nonoverlapping(self.buffer as *const u8, out.as_mut_ptr(), out.len());
        Ok(())
    }
}

impl Drop for PartitionIo {
    fn drop(&mut self) {
        unsafe {
            pool_free(self.iosb);
            pool_free(self.event);
            pool_free(self.buffer);
        }
    }
}

pub(super) extern "win64" fn read(device: u64, output: u64) -> i32 {
    unsafe {
        if output == 0 { return STATUS_INVALID_PARAMETER; }
        write_unaligned(output as *mut u64, 0);
        if hosted_synchronous_fsd_request::device_contract(device).is_none() {
            return STATUS_INVALID_PARAMETER;
        }
        let _device_reference = match ReferencedDevice::acquire(device) {
            Ok(reference) => reference,
            Err(status) => return status,
        };
        let Some(mut geometry_io) = PartitionIo::new(DISK_GEOMETRY_EX_BYTES) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        let (sector_bytes, sectors) = match geometry_io.geometry(device) {
            Ok(geometry) => geometry,
            Err(status) => return status,
        };
        drop(geometry_io);
        let Some(mut sector_io) = PartitionIo::new(sector_bytes) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        let layout = match nt_fs::read_drive_layout_ex(sector_bytes, sectors, |lba, out| {
            sector_io.read_sector(device, lba, out)
        }) {
            Ok(layout) => layout,
            Err(nt_fs::DriveLayoutReadError::Io(status)) => return status,
            Err(nt_fs::DriveLayoutReadError::OutOfMemory) => return STATUS_INSUFFICIENT_RESOURCES,
            Err(nt_fs::DriveLayoutReadError::InvalidGeometry) => return STATUS_DEVICE_NOT_READY,
            Err(nt_fs::DriveLayoutReadError::InvalidPartitionTable) => return DISK_CORRUPT_ERROR,
        };
        let result = pool_alloc(layout.len() as u64);
        if result == 0 { return STATUS_INSUFFICIENT_RESOURCES; }
        core::ptr::copy_nonoverlapping(layout.as_ptr(), result as *mut u8, layout.len());
        write_unaligned(output as *mut u64, result);
        STATUS_SUCCESS
    }
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind("IoReadPartitionTableEx", read as *const () as usize as u64);
}
