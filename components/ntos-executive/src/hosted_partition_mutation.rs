//! Native partition metadata mutations on the caller's exact lower device stack.
//!
//! The domain crate validates the layout before dispatch. Each sector operation uses a
//! source-ledger IRP, and the device reference spans the entire mutation.

use super::hosted_partition_table::{PartitionIo, ReferencedDevice};
use super::*;
use alloc::vec::Vec;

const DISK_CORRUPT_ERROR: i32 = 0xc000_0032u32 as i32;

struct NativeDisk {
    device: u64,
    io: PartitionIo,
}

impl nt_fs::SectorIo for NativeDisk {
    type Error = i32;

    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), Self::Error> {
        unsafe { self.io.read_sector(self.device, lba, out) }
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), Self::Error> {
        unsafe { self.io.write_sector(self.device, lba, data) }
    }
}

fn mutation_status(error: nt_fs::MutationError<i32>) -> i32 {
    match error {
        nt_fs::MutationError::InvalidGeometry => STATUS_DEVICE_NOT_READY,
        nt_fs::MutationError::InvalidLayout => DISK_CORRUPT_ERROR,
        nt_fs::MutationError::InvalidPartition => STATUS_INVALID_PARAMETER,
        nt_fs::MutationError::OutOfMemory => STATUS_INSUFFICIENT_RESOURCES,
        nt_fs::MutationError::Io(status) => status,
    }
}

unsafe fn with_disk(
    device: u64,
    operation: impl FnOnce(&mut NativeDisk, u32, u64) -> Result<(), nt_fs::MutationError<i32>>,
) -> i32 {
    if hosted_synchronous_fsd_request::device_contract(device).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    let _reference = match ReferencedDevice::acquire(device) {
        Ok(reference) => reference,
        Err(status) => return status,
    };
    let Some(mut geometry_io) = PartitionIo::new(40) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let (sector_bytes, disk_sectors) = match geometry_io.geometry(device) {
        Ok(geometry) => geometry,
        Err(status) => return status,
    };
    drop(geometry_io);
    let Some(io) = PartitionIo::new(sector_bytes) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let mut disk = NativeDisk { device, io };
    match operation(&mut disk, sector_bytes, disk_sectors) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => mutation_status(error),
    }
}

/// `CREATE_DISK` is optional and may live in partmgr's stack frame. Copy its
/// branch fields synchronously before the first sector I/O can park the caller.
pub(super) extern "win64" fn create_disk(device: u64, disk: u64) -> i32 {
    unsafe {
        let request = if disk == 0 {
            nt_fs::CreateDisk::Raw
        } else {
            match read_unaligned(disk as *const u32) {
                0 => nt_fs::CreateDisk::Mbr {
                    signature: read_unaligned((disk + 4) as *const u32),
                },
                1 => {
                    let mut disk_guid = [0; 16];
                    core::ptr::copy_nonoverlapping(
                        (disk + 4) as *const u8,
                        disk_guid.as_mut_ptr(),
                        16,
                    );
                    nt_fs::CreateDisk::Gpt {
                        disk_guid,
                        max_partitions: read_unaligned((disk + 20) as *const u32),
                    }
                }
                2 => nt_fs::CreateDisk::Raw,
                _ => return STATUS_NOT_SUPPORTED,
            }
        };
        with_disk(device, |io, sector_bytes, disk_sectors| {
            nt_fs::create_disk(io, sector_bytes, disk_sectors, request)
        })
    }
}

/// Legacy MBR type update. The explicit caller sector size is checked against
/// actual geometry so an EBR can never be addressed with a stale offset.
pub(super) extern "win64" fn set_partition_information(
    device: u64,
    caller_sector_bytes: u32,
    partition_number: u32,
    partition_type: u8,
) -> i32 {
    unsafe {
        with_disk(device, |io, sector_bytes, disk_sectors| {
            if sector_bytes != caller_sector_bytes {
                return Err(nt_fs::MutationError::InvalidGeometry);
            }
            nt_fs::set_mbr_partition_type(
                io,
                sector_bytes,
                disk_sectors,
                partition_number,
                partition_type,
            )
        })
    }
}

/// Partmgr passes an IRP system buffer. Snapshot the selected branch before any
/// wait so the parser never observes a mutable caller buffer across callbacks.
pub(super) extern "win64" fn set_partition_information_ex(
    device: u64,
    partition_number: u32,
    information: u64,
) -> i32 {
    unsafe {
        if information == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(capacity) = component_pool_allocation_capacity(information) else {
            return STATUS_INVALID_PARAMETER;
        };
        if capacity < 9 {
            return STATUS_INVALID_PARAMETER;
        }
        let style = read_unaligned(information as *const u32);
        match style {
            0 => {
                let partition_type = read_unaligned((information + 8) as *const u8);
                with_disk(device, |io, sector_bytes, disk_sectors| {
                    nt_fs::set_mbr_partition_type(
                        io,
                        sector_bytes,
                        disk_sectors,
                        partition_number,
                        partition_type,
                    )
                })
            }
            1 => {
                if capacity < 120 {
                    return STATUS_INVALID_PARAMETER;
                }
                let mut payload = [0u8; 112];
                core::ptr::copy_nonoverlapping(
                    (information + 8) as *const u8,
                    payload.as_mut_ptr(),
                    payload.len(),
                );
                with_disk(device, |io, sector_bytes, disk_sectors| {
                    nt_fs::set_gpt_partition_information(
                        io,
                        sector_bytes,
                        disk_sectors,
                        partition_number,
                        &payload,
                    )
                })
            }
            _ => STATUS_NOT_SUPPORTED,
        }
    }
}

/// The variable length layout is a pool-owned partmgr allocation. Validate its
/// exact extent, then snapshot the bytes before the first disk operation.
pub(super) extern "win64" fn write_partition_table_ex(device: u64, layout: u64) -> i32 {
    unsafe {
        if layout == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(capacity) = component_pool_allocation_capacity(layout) else {
            return STATUS_INVALID_PARAMETER;
        };
        if capacity < nt_fs::DRIVE_LAYOUT_EX_HEADER_BYTES as u64 {
            return STATUS_INVALID_PARAMETER;
        }
        let count = read_unaligned((layout + 4) as *const u32);
        let Some(length) = (count as usize)
            .checked_mul(nt_fs::PARTITION_INFORMATION_EX_BYTES)
            .and_then(|bytes| bytes.checked_add(nt_fs::DRIVE_LAYOUT_EX_HEADER_BYTES))
        else {
            return STATUS_INVALID_PARAMETER;
        };
        if length as u64 > capacity {
            return STATUS_INVALID_PARAMETER;
        }
        let mut snapshot = Vec::new();
        if snapshot.try_reserve_exact(length).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        snapshot.resize(length, 0);
        core::ptr::copy_nonoverlapping(layout as *const u8, snapshot.as_mut_ptr(), length);
        with_disk(device, |io, sector_bytes, disk_sectors| {
            nt_fs::write_drive_layout_ex(io, sector_bytes, disk_sectors, &snapshot)
        })
    }
}
