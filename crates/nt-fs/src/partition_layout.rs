//! Checked x64 `DRIVE_LAYOUT_INFORMATION_EX` projection from validated GPT metadata.
//!
//! The caller must read and authenticate the complete GPT entry array, including its CRC,
//! through the exact disk device stack before passing partitions to this module.

use alloc::vec::Vec;

use crate::{GptHeader, GptPartition};

pub const DRIVE_LAYOUT_EX_HEADER_BYTES: usize = 48;
pub const PARTITION_INFORMATION_EX_BYTES: usize = 144;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveLayoutError {
    InvalidSectorSize,
    TooManyPartitions,
    OutOfMemory,
    ArithmeticOverflow,
}

/// Projects the live GPT's occupied entries into the layout returned by
/// `IoReadPartitionTableEx`. The result is an owned byte image; native publication must
/// copy it to an `ExAllocatePool` allocation, which the driver may free with `ExFreePool`.
pub fn gpt_drive_layout_ex(
    header: GptHeader,
    partitions: &[GptPartition],
    sector_bytes: u32,
) -> Result<Vec<u8>, DriveLayoutError> {
    if sector_bytes < 512 || !sector_bytes.is_power_of_two() {
        return Err(DriveLayoutError::InvalidSectorSize);
    }
    if partitions.len() > header.partition_entry_count as usize {
        return Err(DriveLayoutError::TooManyPartitions);
    }
    let count = u32::try_from(partitions.len()).map_err(|_| DriveLayoutError::TooManyPartitions)?;
    let usable_sectors = header.last_usable_lba.checked_sub(header.first_usable_lba)
        .and_then(|span| span.checked_add(1))
        .ok_or(DriveLayoutError::ArithmeticOverflow)?;
    let start = header.first_usable_lba.checked_mul(u64::from(sector_bytes))
        .ok_or(DriveLayoutError::ArithmeticOverflow)?;
    let length = usable_sectors.checked_mul(u64::from(sector_bytes))
        .ok_or(DriveLayoutError::ArithmeticOverflow)?;
    let bytes = partitions.len().checked_mul(PARTITION_INFORMATION_EX_BYTES)
        .and_then(|entries| entries.checked_add(DRIVE_LAYOUT_EX_HEADER_BYTES))
        .ok_or(DriveLayoutError::ArithmeticOverflow)?;
    let mut output = Vec::new();
    output.try_reserve_exact(bytes).map_err(|_| DriveLayoutError::OutOfMemory)?;
    output.resize(bytes, 0);
    put_u32(&mut output, 0, 1); // PARTITION_STYLE_GPT
    put_u32(&mut output, 4, count);
    output[8..24].copy_from_slice(&header.disk_guid);
    put_u64(&mut output, 24, start);
    put_u64(&mut output, 32, length);
    put_u32(&mut output, 40, header.partition_entry_count);
    for (index, partition) in partitions.iter().enumerate() {
        let offset = DRIVE_LAYOUT_EX_HEADER_BYTES + index * PARTITION_INFORMATION_EX_BYTES;
        let start = partition.first_lba.checked_mul(u64::from(sector_bytes))
            .ok_or(DriveLayoutError::ArithmeticOverflow)?;
        let length = partition.sector_count()
            .and_then(|sectors| sectors.checked_mul(u64::from(sector_bytes)))
            .ok_or(DriveLayoutError::ArithmeticOverflow)?;
        put_u32(&mut output, offset, 1);
        put_u64(&mut output, offset + 8, start);
        put_u64(&mut output, offset + 16, length);
        put_u32(&mut output, offset + 24, index as u32 + 1);
        output[offset + 32..offset + 48].copy_from_slice(&partition.type_guid);
        output[offset + 48..offset + 64].copy_from_slice(&partition.unique_guid);
        put_u64(&mut output, offset + 64, partition.attributes);
        for (name_index, unit) in partition.name.iter().enumerate() {
            output[offset + 72 + name_index * 2..offset + 74 + name_index * 2]
                .copy_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(output)
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> GptHeader {
        GptHeader {
            current_lba: 1,
            backup_lba: 4095,
            first_usable_lba: 34,
            last_usable_lba: 4062,
            disk_guid: [0x12; 16],
            partition_entries_lba: 2,
            partition_entry_count: 128,
            partition_entry_size: 128,
            partition_entries_crc32: 0,
        }
    }

    fn partition() -> GptPartition {
        let mut name = [0; 36];
        name[0] = 'O' as u16;
        name[1] = 'S' as u16;
        GptPartition {
            type_guid: [0x34; 16], unique_guid: [0x56; 16],
            first_lba: 40, last_lba: 103, attributes: 0x1122_3344_5566_7788, name,
        }
    }

    #[test]
    fn gpt_layout_uses_real_sector_geometry_and_x64_offsets() {
        let bytes = gpt_drive_layout_ex(header(), &[partition()], 4096).unwrap();
        assert_eq!(bytes.len(), 48 + 144);
        assert_eq!(&bytes[0..8], &[1, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&bytes[8..24], &[0x12; 16]);
        assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 34 * 4096);
        assert_eq!(u64::from_le_bytes(bytes[32..40].try_into().unwrap()), (4062 - 34 + 1) * 4096);
        assert_eq!(u32::from_le_bytes(bytes[40..44].try_into().unwrap()), 128);
        assert_eq!(u32::from_le_bytes(bytes[48..52].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[56..64].try_into().unwrap()), 40 * 4096);
        assert_eq!(u64::from_le_bytes(bytes[64..72].try_into().unwrap()), 64 * 4096);
        assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 1);
        assert_eq!(&bytes[80..96], &[0x34; 16]);
        assert_eq!(&bytes[96..112], &[0x56; 16]);
        assert_eq!(u64::from_le_bytes(bytes[112..120].try_into().unwrap()), 0x1122_3344_5566_7788);
        assert_eq!(&bytes[120..124], &[b'O', 0, b'S', 0]);
    }

    #[test]
    fn overflow_or_invalid_sector_geometry_cannot_publish_a_layout() {
        assert_eq!(gpt_drive_layout_ex(header(), &[partition()], 0), Err(DriveLayoutError::InvalidSectorSize));
        let mut bad = header();
        bad.first_usable_lba = u64::MAX / 512;
        bad.last_usable_lba = u64::MAX;
        assert_eq!(gpt_drive_layout_ex(bad, &[], 512), Err(DriveLayoutError::ArithmeticOverflow));
    }
}
