//! Native disk-signature imports over the caller's exact lower device stack.
//!
//! Reuses the partition-table adapter's retained device reference and source IRP ownership.

use super::*;
use super::hosted_partition_table::{PartitionIo, ReferencedDevice};
use alloc::vec::Vec;

const DISK_CORRUPT_ERROR: i32 = 0xc000_0032u32 as i32;

fn read_capacity(bytes_per_sector: u32) -> Option<u32> {
    let capacity = bytes_per_sector.max(512);
    (capacity <= 65_536).then_some(capacity)
}

/// `HalExamineMBR` returns an owned pool buffer only for a matching legacy partition type.
/// The caller frees it with `ExFreePool`; all other paths leave the output null.
pub(super) extern "win64" fn examine_mbr(
    device: u64, bytes_per_sector: u32, partition_type: u32, output: u64,
) {
    unsafe {
        if output == 0 { return; }
        write_unaligned(output as *mut u64, 0);
        let Some(capacity) = read_capacity(bytes_per_sector) else { return; };
        if hosted_synchronous_fsd_request::device_contract(device).is_none() { return; }
        let Ok(_device_reference) = ReferencedDevice::acquire(device) else { return; };
        let Some(mut io) = PartitionIo::new(capacity) else { return; };
        let mut sector = Vec::new();
        if sector.try_reserve_exact(capacity as usize).is_err() { return; }
        sector.resize(capacity as usize, 0);
        if io.read_sector(device, 0, &mut sector).is_err() { return; }
        let Some(kind) = nt_fs::examine_mbr(&sector, partition_type) else { return; };
        let size = u64::from(capacity.max(4096));
        let buffer = pool_alloc_zeroed(size);
        if buffer == 0 { return; }
        core::ptr::copy_nonoverlapping(sector.as_ptr(), buffer as *mut u8, sector.len());
        if let nt_fs::MbrExamination::DiskManager { skew_sectors } = kind {
            write_unaligned(buffer as *mut u32, skew_sectors);
        }
        write_unaligned(output as *mut u64, buffer);
    }
}

/// Write the x64 `DISK_SIGNATURE` (ULONG style followed by a 16-byte union) only after
/// all physical reads and GPT-header validation have completed.
pub(super) extern "win64" fn read_disk_signature(
    device: u64, bytes_per_sector: u32, output: u64,
) -> i32 {
    unsafe {
        if output == 0 { return STATUS_INVALID_PARAMETER; }
        let Some(capacity) = read_capacity(bytes_per_sector) else { return STATUS_INVALID_PARAMETER; };
        if hosted_synchronous_fsd_request::device_contract(device).is_none() {
            return STATUS_INVALID_PARAMETER;
        }
        let _device_reference = match ReferencedDevice::acquire(device) {
            Ok(reference) => reference,
            Err(status) => return status,
        };
        let Some(mut io) = PartitionIo::new(capacity) else { return STATUS_INSUFFICIENT_RESOURCES; };
        let signature = match nt_fs::read_disk_signature(capacity, |lba, sector| {
            io.read_sector(device, lba, sector)
        }) {
            Ok(signature) => signature,
            Err(nt_fs::DiskSignatureReadError::Io(status)) => return status,
            Err(nt_fs::DiskSignatureReadError::InvalidSectorSize) => return STATUS_INVALID_PARAMETER,
            Err(nt_fs::DiskSignatureReadError::InvalidGptHeader) => return DISK_CORRUPT_ERROR,
            Err(nt_fs::DiskSignatureReadError::OutOfMemory) => return STATUS_INSUFFICIENT_RESOURCES,
        };
        let mut result = [0u8; 20];
        match signature {
            nt_fs::DiskSignature::Mbr { signature, checksum } => {
                result[4..8].copy_from_slice(&signature.to_le_bytes());
                result[8..12].copy_from_slice(&checksum.to_le_bytes());
            }
            nt_fs::DiskSignature::Gpt { disk_id } => {
                result[0..4].copy_from_slice(&1u32.to_le_bytes());
                result[4..20].copy_from_slice(&disk_id);
            }
        }
        core::ptr::copy_nonoverlapping(result.as_ptr(), output as *mut u8, result.len());
        STATUS_SUCCESS
    }
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind("HalExamineMBR", examine_mbr as *const () as usize as u64);
    reg.bind("IoReadDiskSignature", read_disk_signature as *const () as usize as u64);
}
