//! Checked x64 `DRIVE_LAYOUT_INFORMATION_EX` projection from disk sectors.
//!
//! The caller owns the exact device stack and supplies its sector reader and real geometry.

use alloc::vec::Vec;

use crate::{GptCrc32, GptHeader, GptPartition, parse_gpt_header, parse_gpt_partition_entry};

pub const DRIVE_LAYOUT_EX_HEADER_BYTES: usize = 48;
pub const PARTITION_INFORMATION_EX_BYTES: usize = 144;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveLayoutError {
    InvalidSectorSize,
    InvalidPartition,
    TooManyPartitions,
    OutOfMemory,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriveLayoutReadError<E> {
    Io(E),
    InvalidGeometry,
    InvalidPartitionTable,
    OutOfMemory,
}

/// Read and authenticate a disk layout. Every read goes through `read_sector`, which the
/// native caller must bind to the supplied device object, not a mounted-disk singleton.
pub fn read_drive_layout_ex<E>(
    sector_bytes: u32,
    disk_sectors: u64,
    mut read_sector: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<Vec<u8>, DriveLayoutReadError<E>> {
    if !(512..=65_536).contains(&sector_bytes)
        || !sector_bytes.is_power_of_two()
        || disk_sectors < 2
        || disk_sectors.checked_mul(u64::from(sector_bytes)).is_none()
    {
        return Err(DriveLayoutReadError::InvalidGeometry);
    }
    let mut sector = Vec::new();
    sector.try_reserve_exact(sector_bytes as usize)
        .map_err(|_| DriveLayoutReadError::OutOfMemory)?;
    sector.resize(sector_bytes as usize, 0);
    read_sector(0, &mut sector).map_err(DriveLayoutReadError::Io)?;
    if sector[510..512] != [0x55, 0xaa] {
        return raw_drive_layout_ex();
    }
    let protective = sector[446 + 4] == 0xee
        && (1..4).all(|index| sector[446 + index * 16 + 4] == 0);
    if protective {
        match read_gpt_layout(1, disk_sectors, sector_bytes, &mut sector, &mut read_sector) {
            Ok(layout) => return Ok(layout),
            Err(DriveLayoutReadError::OutOfMemory) => return Err(DriveLayoutReadError::OutOfMemory),
            Err(_) => {} // independent backup metadata may recover a bad primary read
        }
        return read_gpt_layout(disk_sectors - 1, disk_sectors, sector_bytes, &mut sector, &mut read_sector);
    }
    read_mbr_layout(&sector, disk_sectors, sector_bytes, &mut read_sector)
}

fn raw_drive_layout_ex<E>() -> Result<Vec<u8>, DriveLayoutReadError<E>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(DRIVE_LAYOUT_EX_HEADER_BYTES)
        .map_err(|_| DriveLayoutReadError::OutOfMemory)?;
    bytes.resize(DRIVE_LAYOUT_EX_HEADER_BYTES, 0);
    put_u32(&mut bytes, 0, 2); // PARTITION_STYLE_RAW
    Ok(bytes)
}

fn read_gpt_layout<E>(
    header_lba: u64,
    disk_sectors: u64,
    sector_bytes: u32,
    sector: &mut [u8],
    read_sector: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<Vec<u8>, DriveLayoutReadError<E>> {
    read_sector(header_lba, sector).map_err(DriveLayoutReadError::Io)?;
    let header = parse_gpt_header(sector, header_lba)
        .map_err(|_| DriveLayoutReadError::InvalidPartitionTable)?;
    if header.current_lba >= disk_sectors
        || header.backup_lba >= disk_sectors
        || header.last_usable_lba >= disk_sectors
    {
        return Err(DriveLayoutReadError::InvalidPartitionTable);
    }
    let total = header.partition_entries_bytes()
        .ok_or(DriveLayoutReadError::InvalidPartitionTable)?;
    let sectors = total.checked_add(u64::from(sector_bytes) - 1)
        .map(|bytes| bytes / u64::from(sector_bytes))
        .ok_or(DriveLayoutReadError::InvalidPartitionTable)?;
    if header.partition_entries_lba.checked_add(sectors).is_none_or(|end| end > disk_sectors) {
        return Err(DriveLayoutReadError::InvalidPartitionTable);
    }
    let mut partitions = Vec::new();
    let mut entry = Vec::new();
    entry.try_reserve_exact(header.partition_entry_size as usize)
        .map_err(|_| DriveLayoutReadError::OutOfMemory)?;
    let mut crc = GptCrc32::new();
    let mut remaining = total;
    let mut entries_seen = 0u32;
    for sector_index in 0..sectors {
        read_sector(header.partition_entries_lba + sector_index, sector)
            .map_err(DriveLayoutReadError::Io)?;
        let valid = remaining.min(u64::from(sector_bytes)) as usize;
        crc.update(&sector[..valid]);
        let mut cursor = 0usize;
        while cursor < valid {
            let needed = header.partition_entry_size as usize - entry.len();
            let take = needed.min(valid - cursor);
            entry.extend_from_slice(&sector[cursor..cursor + take]);
            cursor += take;
            if entry.len() == header.partition_entry_size as usize {
                match parse_gpt_partition_entry(&entry, header)
                    .map_err(|_| DriveLayoutReadError::InvalidPartitionTable)? {
                    Some(partition) => {
                        partitions.try_reserve(1).map_err(|_| DriveLayoutReadError::OutOfMemory)?;
                        partitions.push(partition);
                    }
                    None => {}
                }
                entries_seen += 1;
                entry.clear();
            }
        }
        remaining -= valid as u64;
    }
    if entries_seen != header.partition_entry_count
        || !entry.is_empty()
        || crc.finish() != header.partition_entries_crc32
    {
        return Err(DriveLayoutReadError::InvalidPartitionTable);
    }
    gpt_drive_layout_ex(header, &partitions, sector_bytes).map_err(|error| match error {
        DriveLayoutError::OutOfMemory => DriveLayoutReadError::OutOfMemory,
        _ => DriveLayoutReadError::InvalidPartitionTable,
    })
}

#[derive(Clone, Copy)]
struct MbrPartition {
    first_lba: u64,
    sectors: u64,
    kind: u8,
    boot: u8,
    hidden: u32,
}

fn read_mbr_layout<E>(
    mbr: &[u8],
    disk_sectors: u64,
    sector_bytes: u32,
    read_sector: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<Vec<u8>, DriveLayoutReadError<E>> {
    let signature = u32::from_le_bytes(mbr[440..444].try_into().unwrap());
    let mut partitions = Vec::new();
    let mut extended = None;
    for index in 0..4 {
        let offset = 446 + index * 16;
        let raw = &mbr[offset..offset + 16];
        let kind = raw[4];
        let start = u64::from(u32::from_le_bytes(raw[8..12].try_into().unwrap()));
        let sectors = u64::from(u32::from_le_bytes(raw[12..16].try_into().unwrap()));
        if kind == 0 || sectors == 0 { continue; }
        if is_extended(kind) {
            if extended.replace((start, sectors)).is_some()
                || start == 0
                || start.checked_add(sectors).is_none_or(|end| end > disk_sectors)
            {
                return Err(DriveLayoutReadError::InvalidPartitionTable);
            }
            continue;
        }
        checked_mbr_partition(&mut partitions, start, sectors, kind, raw[0], start as u32, disk_sectors)?;
    }
    if let Some((base, extent)) = extended {
        let limit = base + extent;
        if partitions.iter().any(|partition: &MbrPartition| {
            partition.first_lba < limit && base < partition.first_lba + partition.sectors
        }) {
            return Err(DriveLayoutReadError::InvalidPartitionTable);
        }
        let mut next = base;
        let mut visited = Vec::new();
        let mut sector = Vec::new();
        sector.try_reserve_exact(sector_bytes as usize).map_err(|_| DriveLayoutReadError::OutOfMemory)?;
        sector.resize(sector_bytes as usize, 0);
        loop {
            if next >= limit || visited.contains(&next) {
                return Err(DriveLayoutReadError::InvalidPartitionTable);
            }
            visited.try_reserve(1).map_err(|_| DriveLayoutReadError::OutOfMemory)?;
            visited.push(next);
            read_sector(next, &mut sector).map_err(DriveLayoutReadError::Io)?;
            if sector[510..512] != [0x55, 0xaa] {
                return Err(DriveLayoutReadError::InvalidPartitionTable);
            }
            let first = &sector[446..462];
            let relative = u64::from(u32::from_le_bytes(first[8..12].try_into().unwrap()));
            let count = u64::from(u32::from_le_bytes(first[12..16].try_into().unwrap()));
            if first[4] != 0 && count != 0 {
                if is_extended(first[4]) { return Err(DriveLayoutReadError::InvalidPartitionTable); }
                let start = next.checked_add(relative).ok_or(DriveLayoutReadError::InvalidPartitionTable)?;
                if start.checked_add(count).is_none_or(|end| end > limit) {
                    return Err(DriveLayoutReadError::InvalidPartitionTable);
                }
                checked_mbr_partition(&mut partitions, start, count, first[4], first[0], relative as u32, disk_sectors)?;
            }
            let link = &sector[462..478];
            if link[4] == 0 { break; }
            if !is_extended(link[4]) {
                return Err(DriveLayoutReadError::InvalidPartitionTable);
            }
            let relative = u64::from(u32::from_le_bytes(link[8..12].try_into().unwrap()));
            let link_len = u64::from(u32::from_le_bytes(link[12..16].try_into().unwrap()));
            if link_len == 0 || relative.checked_add(link_len).is_none_or(|end| end > extent) {
                return Err(DriveLayoutReadError::InvalidPartitionTable);
            }
            next = base.checked_add(relative).ok_or(DriveLayoutReadError::InvalidPartitionTable)?;
        }
    }
    let bytes = partitions.len().checked_mul(PARTITION_INFORMATION_EX_BYTES)
        .and_then(|entries| entries.checked_add(DRIVE_LAYOUT_EX_HEADER_BYTES))
        .ok_or(DriveLayoutReadError::InvalidPartitionTable)?;
    let count = u32::try_from(partitions.len()).map_err(|_| DriveLayoutReadError::InvalidPartitionTable)?;
    let mut output = Vec::new();
    output.try_reserve_exact(bytes).map_err(|_| DriveLayoutReadError::OutOfMemory)?;
    output.resize(bytes, 0);
    put_u32(&mut output, 0, 0); // PARTITION_STYLE_MBR
    put_u32(&mut output, 4, count);
    put_u32(&mut output, 8, signature);
    for (index, partition) in partitions.iter().enumerate() {
        let offset = DRIVE_LAYOUT_EX_HEADER_BYTES + index * PARTITION_INFORMATION_EX_BYTES;
        let start = partition.first_lba.checked_mul(u64::from(sector_bytes))
            .ok_or(DriveLayoutReadError::InvalidPartitionTable)?;
        let length = partition.sectors.checked_mul(u64::from(sector_bytes))
            .ok_or(DriveLayoutReadError::InvalidPartitionTable)?;
        put_u64(&mut output, offset + 8, start);
        put_u64(&mut output, offset + 16, length);
        put_u32(&mut output, offset + 24, index as u32 + 1);
        output[offset + 32] = partition.kind;
        output[offset + 33] = (partition.boot == 0x80) as u8;
        output[offset + 34] = is_recognized_partition(partition.kind) as u8;
        put_u32(&mut output, offset + 36, partition.hidden);
    }
    Ok(output)
}

fn is_extended(kind: u8) -> bool { matches!(kind, 0x05 | 0x0f | 0x85) }

fn is_recognized_partition(kind: u8) -> bool {
    matches!(kind, 0x01 | 0x04 | 0x06 | 0x07 | 0x0b | 0x0c | 0x0e
        | 0x43 | 0x83 | 0x96 | 0xa5 | 0xa6 | 0xa9)
        || kind & 0x80 != 0 && matches!(kind & !0xc0, 0x06 | 0x07 | 0x0b | 0x0c)
}

fn checked_mbr_partition<E>(
    partitions: &mut Vec<MbrPartition>, first_lba: u64, sectors: u64,
    kind: u8, boot: u8, hidden: u32, disk_sectors: u64,
) -> Result<(), DriveLayoutReadError<E>> {
    if boot != 0 && boot != 0x80
        || first_lba == 0
        || first_lba.checked_add(sectors).is_none_or(|end| end > disk_sectors)
        || partitions.iter().any(|previous| {
            let end = previous.first_lba + previous.sectors;
            let next_end = first_lba + sectors;
            first_lba < end && previous.first_lba < next_end
        })
    {
        return Err(DriveLayoutReadError::InvalidPartitionTable);
    }
    partitions.try_reserve(1).map_err(|_| DriveLayoutReadError::OutOfMemory)?;
    partitions.push(MbrPartition { first_lba, sectors, kind, boot, hidden });
    Ok(())
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
    for (index, partition) in partitions.iter().enumerate() {
        if partition.type_guid == [0; 16]
            || partition.unique_guid == [0; 16]
            || partition.first_lba < header.first_usable_lba
            || partition.last_lba > header.last_usable_lba
            || partition.first_lba > partition.last_lba
            || partitions[..index].iter().any(|previous| {
                previous.unique_guid == partition.unique_guid
                    || partition.first_lba <= previous.last_lba
                        && previous.first_lba <= partition.last_lba
            })
        {
            return Err(DriveLayoutError::InvalidPartition);
        }
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
    use crate::gpt_crc32;

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

    #[test]
    fn overlapping_gpt_extents_cannot_publish_a_layout() {
        let first = partition();
        let mut overlapping = partition();
        overlapping.first_lba = 100;
        overlapping.last_lba = 120;
        overlapping.unique_guid = [0x78; 16];
        assert_eq!(
            gpt_drive_layout_ex(header(), &[first, overlapping], 512),
            Err(DriveLayoutError::InvalidPartition),
        );
    }

    fn gpt_disk() -> alloc::vec::Vec<[u8; 512]> {
        let mut disk = alloc::vec![[0u8; 512]; 128];
        disk[0][510..512].copy_from_slice(&[0x55, 0xaa]);
        disk[0][446 + 4] = 0xee;
        disk[0][446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        disk[0][446 + 12..446 + 16].copy_from_slice(&127u32.to_le_bytes());
        let mut entry = [0u8; 512];
        entry[0..16].fill(0x34);
        entry[16..32].fill(0x56);
        entry[32..40].copy_from_slice(&8u64.to_le_bytes());
        entry[40..48].copy_from_slice(&15u64.to_le_bytes());
        entry[56..58].copy_from_slice(&(b'O' as u16).to_le_bytes());
        disk[2] = entry;
        disk[126] = entry;
        for (header_lba, alternate_lba, entries_lba) in [(1usize, 127u64, 2u64), (127, 1, 126)] {
            let mut sector = [0u8; 512];
            sector[0..8].copy_from_slice(b"EFI PART");
            sector[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            sector[12..16].copy_from_slice(&92u32.to_le_bytes());
            sector[24..32].copy_from_slice(&(header_lba as u64).to_le_bytes());
            sector[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
            sector[40..48].copy_from_slice(&4u64.to_le_bytes());
            sector[48..56].copy_from_slice(&120u64.to_le_bytes());
            sector[56..72].fill(0x12);
            sector[72..80].copy_from_slice(&entries_lba.to_le_bytes());
            sector[80..84].copy_from_slice(&4u32.to_le_bytes());
            sector[84..88].copy_from_slice(&128u32.to_le_bytes());
            sector[88..92].copy_from_slice(&gpt_crc32(&entry).to_le_bytes());
            let header_crc = gpt_crc32(&sector[..92]);
            sector[16..20].copy_from_slice(&header_crc.to_le_bytes());
            disk[header_lba] = sector;
        }
        disk
    }

    #[test]
    fn reads_gpt_entries_with_crc_from_exact_sectors_and_recovers_backup() {
        let mut disk = gpt_disk();
        let layout = read_drive_layout_ex(512, 128, |lba, output| {
            output.copy_from_slice(&disk[lba as usize]); Ok::<_, ()>(())
        }).unwrap();
        assert_eq!(u32::from_le_bytes(layout[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(layout[4..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(layout[56..64].try_into().unwrap()), 8 * 512);

        disk[2][0] ^= 1; // primary array CRC fails; backup is independently valid
        let recovered = read_drive_layout_ex(512, 128, |lba, output| {
            output.copy_from_slice(&disk[lba as usize]); Ok::<_, ()>(())
        }).unwrap();
        assert_eq!(recovered, layout);

        disk[126][0] ^= 1;
        assert_eq!(read_drive_layout_ex(512, 128, |lba, output| {
            output.copy_from_slice(&disk[lba as usize]); Ok::<_, ()>(())
        }), Err(DriveLayoutReadError::InvalidPartitionTable));
    }

    #[test]
    fn valid_mbr_and_unsigned_raw_media_project_distinct_styles() {
        let mut disk = alloc::vec![[0u8; 512]; 128];
        let raw = read_drive_layout_ex(512, 128, |lba, output| {
            output.copy_from_slice(&disk[lba as usize]); Ok::<_, ()>(())
        }).unwrap();
        assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(raw[4..8].try_into().unwrap()), 0);

        disk[0][510..512].copy_from_slice(&[0x55, 0xaa]);
        disk[0][440..444].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        disk[0][446] = 0x80;
        disk[0][450] = 0x07;
        disk[0][454..458].copy_from_slice(&8u32.to_le_bytes());
        disk[0][458..462].copy_from_slice(&16u32.to_le_bytes());
        let mbr = read_drive_layout_ex(512, 128, |lba, output| {
            output.copy_from_slice(&disk[lba as usize]); Ok::<_, ()>(())
        }).unwrap();
        assert_eq!(u32::from_le_bytes(mbr[0..4].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(mbr[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(mbr[8..12].try_into().unwrap()), 0x1234_5678);
        assert_eq!(u64::from_le_bytes(mbr[56..64].try_into().unwrap()), 8 * 512);
        assert_eq!(mbr[80..84], [7, 1, 1, 0]);
    }

    #[test]
    fn gpt_backup_recovers_a_primary_media_read_error() {
        let disk = gpt_disk();
        let layout = read_drive_layout_ex(512, 128, |lba, output| {
            if lba == 1 { return Err(0xc000_0185u32); }
            output.copy_from_slice(&disk[lba as usize]);
            Ok(())
        }).unwrap();
        assert_eq!(u32::from_le_bytes(layout[0..4].try_into().unwrap()), 1);
    }

    #[test]
    fn overlapping_mbr_partitions_and_cyclic_ebr_links_are_refused() {
        let mut disk = alloc::vec![[0u8; 512]; 128];
        disk[0][510..512].copy_from_slice(&[0x55, 0xaa]);
        for (slot, first) in [(0usize, 8u32), (1, 16)] {
            let offset = 446 + slot * 16;
            disk[0][offset + 4] = 0x07;
            disk[0][offset + 8..offset + 12].copy_from_slice(&first.to_le_bytes());
            disk[0][offset + 12..offset + 16].copy_from_slice(&16u32.to_le_bytes());
        }
        assert_eq!(read_drive_layout_ex(512, 128, |lba, output| {
            output.copy_from_slice(&disk[lba as usize]); Ok::<_, ()>(())
        }), Err(DriveLayoutReadError::InvalidPartitionTable));

        disk[0][462..478].fill(0);
        disk[0][446 + 4] = 0x0f;
        disk[0][446 + 8..446 + 12].copy_from_slice(&32u32.to_le_bytes());
        disk[0][446 + 12..446 + 16].copy_from_slice(&64u32.to_le_bytes());
        disk[32][510..512].copy_from_slice(&[0x55, 0xaa]);
        disk[32][462 + 4] = 0x0f;
        // A zero relative link points back to the same EBR.
        assert_eq!(read_drive_layout_ex(512, 128, |lba, output| {
            output.copy_from_slice(&disk[lba as usize]); Ok::<_, ()>(())
        }), Err(DriveLayoutReadError::InvalidPartitionTable));
    }
}
