//! Checked on-disk partition mutations over an exact sector provider.

use alloc::vec;
use alloc::vec::Vec;

use crate::{
    gpt_crc32, parse_gpt_header, read_drive_layout_ex, DriveLayoutReadError, GptHeader,
    GptPartition,
};

/// A sector operation remains owned by its caller until exact terminal completion.
/// Implementations must not return an uncertain write as an ordinary error.
pub trait SectorIo {
    type Error;
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), Self::Error>;
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDisk {
    Raw,
    Mbr {
        signature: u32,
    },
    Gpt {
        disk_guid: [u8; 16],
        max_partitions: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationError<E> {
    InvalidGeometry,
    InvalidLayout,
    InvalidPartition,
    OutOfMemory,
    Io(E),
}

struct Geometry {
    bytes: usize,
    sectors: u64,
}
impl Geometry {
    fn new(bytes: u32, sectors: u64) -> Result<Self, MutationError<()>> {
        if !(512..=65536).contains(&bytes)
            || !bytes.is_power_of_two()
            || sectors < 2
            || sectors.checked_mul(u64::from(bytes)).is_none()
        {
            return Err(MutationError::InvalidGeometry);
        }
        Ok(Self {
            bytes: bytes as usize,
            sectors,
        })
    }
    fn sector<E>(&self) -> Result<Vec<u8>, MutationError<E>> {
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(self.bytes)
            .map_err(|_| MutationError::OutOfMemory)?;
        sector.resize(self.bytes, 0);
        Ok(sector)
    }
}
fn geometry<E>(bytes: u32, sectors: u64) -> Result<Geometry, MutationError<E>> {
    Geometry::new(bytes, sectors).map_err(|_| MutationError::InvalidGeometry)
}
fn read<S: SectorIo>(io: &mut S, lba: u64, buf: &mut [u8]) -> Result<(), MutationError<S::Error>> {
    io.read_sector(lba, buf).map_err(MutationError::Io)
}
fn write<S: SectorIo>(io: &mut S, lba: u64, buf: &[u8]) -> Result<(), MutationError<S::Error>> {
    io.write_sector(lba, buf).map_err(MutationError::Io)
}

/// Create an empty partition scheme. All geometry and GPT capacity checks precede writes.
/// A failed sector write can leave partial metadata; the caller must invalidate its layout cache.
pub fn create_disk<S: SectorIo>(
    io: &mut S,
    sector_bytes: u32,
    disk_sectors: u64,
    request: CreateDisk,
) -> Result<(), MutationError<S::Error>> {
    let geo = geometry(sector_bytes, disk_sectors)?;
    let mut sector = geo.sector()?;
    match request {
        CreateDisk::Mbr { signature } => {
            read(io, 0, &mut sector)?;
            sector[440..444].copy_from_slice(&signature.to_le_bytes());
            sector[446..510].fill(0);
            sector[510..512].copy_from_slice(&[0x55, 0xaa]);
            write(io, 0, &sector)
        }
        CreateDisk::Raw => {
            read(io, 0, &mut sector)?;
            let old_gpt = sector[510..512] == [0x55, 0xaa] && sector[450] == 0xee;
            sector[440..444].fill(0);
            sector[446..512].fill(0);
            write(io, 0, &sector)?;
            if old_gpt {
                sector.fill(0);
                write(io, 1, &sector)?;
                write(io, disk_sectors - 1, &sector)?;
            }
            Ok(())
        }
        CreateDisk::Gpt {
            disk_guid,
            max_partitions,
        } => {
            let entries = vec![];
            write_gpt(io, geo, disk_guid, max_partitions, &entries)
        }
    }
}

/// Change only the type byte of the numbered occupied MBR partition, including EBRs.
/// Container entries never consume a partition number.
pub fn set_mbr_partition_type<S: SectorIo>(
    io: &mut S,
    sector_bytes: u32,
    disk_sectors: u64,
    partition_number: u32,
    partition_type: u8,
) -> Result<(), MutationError<S::Error>> {
    let geo = geometry(sector_bytes, disk_sectors)?;
    if partition_number == 0 {
        return Err(MutationError::InvalidPartition);
    }
    let mut sector = geo.sector()?;
    read(io, 0, &mut sector)?;
    if sector[510..512] != [0x55, 0xaa] || sector[450] == 0xee {
        return Err(MutationError::InvalidLayout);
    }
    let mut current = 0;
    let mut extended = None;
    for slot in 0..4 {
        let p = 446 + slot * 16;
        let kind = sector[p + 4];
        if is_extended(kind) {
            if extended.is_some() {
                return Err(MutationError::InvalidLayout);
            }
            let start = u32::from_le_bytes(sector[p + 8..p + 12].try_into().unwrap()) as u64;
            let len = u32::from_le_bytes(sector[p + 12..p + 16].try_into().unwrap()) as u64;
            if start == 0 || len == 0 || start.checked_add(len).is_none_or(|end| end > geo.sectors)
            {
                return Err(MutationError::InvalidLayout);
            }
            extended = Some((start, len));
        } else if kind != 0 {
            current += 1;
            if current == partition_number {
                sector[p + 4] = partition_type;
                return write(io, 0, &sector);
            }
        }
    }
    if let Some((base, extent)) = extended {
        let mut next = base;
        let mut visited = Vec::new();
        loop {
            if next >= base + extent || visited.contains(&next) {
                return Err(MutationError::InvalidLayout);
            }
            visited
                .try_reserve(1)
                .map_err(|_| MutationError::OutOfMemory)?;
            visited.push(next);
            read(io, next, &mut sector)?;
            if sector[510..512] != [0x55, 0xaa] {
                return Err(MutationError::InvalidLayout);
            }
            let kind = sector[450];
            if is_extended(kind) {
                return Err(MutationError::InvalidLayout);
            }
            if kind != 0 {
                current += 1;
                if current == partition_number {
                    sector[450] = partition_type;
                    return write(io, next, &sector);
                }
            }
            let link = sector[466];
            if link == 0 {
                break;
            }
            if !is_extended(link) {
                return Err(MutationError::InvalidLayout);
            }
            let relative = u32::from_le_bytes(sector[470..474].try_into().unwrap()) as u64;
            let length = u32::from_le_bytes(sector[474..478].try_into().unwrap()) as u64;
            if relative == 0
                || length == 0
                || relative.checked_add(length).is_none_or(|end| end > extent)
            {
                return Err(MutationError::InvalidLayout);
            }
            next = base + relative;
        }
    }
    Err(MutationError::InvalidPartition)
}

fn is_extended(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0f | 0x85)
}

fn get_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}
fn get_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// Write an x64 `DRIVE_LAYOUT_INFORMATION_EX` image. The whole input is checked
/// before any sector is changed. GPT entries are compacted as ReactOS does.
pub fn write_drive_layout_ex<S: SectorIo>(
    io: &mut S,
    sector_bytes: u32,
    disk_sectors: u64,
    layout: &[u8],
) -> Result<(), MutationError<S::Error>> {
    let geo = geometry(sector_bytes, disk_sectors)?;
    if layout.len() < 48 {
        return Err(MutationError::InvalidLayout);
    }
    let count = get_u32(layout, 4) as usize;
    let needed = count
        .checked_mul(144)
        .and_then(|n| n.checked_add(48))
        .ok_or(MutationError::InvalidLayout)?;
    if layout.len() < needed {
        return Err(MutationError::InvalidLayout);
    }
    match get_u32(layout, 0) {
        0 => write_mbr_layout(io, geo, &layout[..needed], count),
        1 => {
            let mut parts = Vec::new();
            parts
                .try_reserve_exact(count)
                .map_err(|_| MutationError::OutOfMemory)?;
            for index in 0..count {
                let p = 48 + index * 144;
                if get_u32(layout, p) != 1 {
                    return Err(MutationError::InvalidPartition);
                }
                let start = get_u64(layout, p + 8);
                let len = get_u64(layout, p + 16);
                if start % sector_bytes as u64 != 0 || len % sector_bytes as u64 != 0 || len == 0 {
                    return Err(MutationError::InvalidPartition);
                }
                let first_lba = start / sector_bytes as u64;
                let last_lba = first_lba
                    .checked_add(len / sector_bytes as u64)
                    .and_then(|n| n.checked_sub(1))
                    .ok_or(MutationError::InvalidPartition)?;
                let mut name = [0u16; 36];
                for (i, unit) in name.iter_mut().enumerate() {
                    *unit = u16::from_le_bytes(
                        layout[p + 72 + i * 2..p + 74 + i * 2].try_into().unwrap(),
                    );
                }
                parts.push(GptPartition {
                    type_guid: layout[p + 32..p + 48].try_into().unwrap(),
                    unique_guid: layout[p + 48..p + 64].try_into().unwrap(),
                    first_lba,
                    last_lba,
                    attributes: get_u64(layout, p + 64),
                    name,
                });
            }
            write_existing_gpt(io, geo, &parts)
        }
        _ => Err(MutationError::InvalidLayout),
    }
}

fn write_mbr_layout<S: SectorIo>(
    io: &mut S,
    geo: Geometry,
    layout: &[u8],
    count: usize,
) -> Result<(), MutationError<S::Error>> {
    let groups = count.checked_add(3).ok_or(MutationError::InvalidLayout)? / 4;
    let mut staged = Vec::new();
    staged
        .try_reserve_exact(groups.max(1))
        .map_err(|_| MutationError::OutOfMemory)?;
    let mut next_lba = 0u64;
    let mut extended_base = None;
    let mut visited = Vec::new();
    for group in 0..groups.max(1) {
        if next_lba >= geo.sectors || visited.contains(&next_lba) {
            return Err(MutationError::InvalidLayout);
        }
        visited
            .try_reserve(1)
            .map_err(|_| MutationError::OutOfMemory)?;
        visited.push(next_lba);
        let mut sector = geo.sector()?;
        read(io, next_lba, &mut sector)?;
        let mut next = None;
        for slot in 0..4 {
            let index = group * 4 + slot;
            if index >= count {
                continue;
            }
            let p = 48 + index * 144;
            if get_u32(layout, p) != 0 {
                return Err(MutationError::InvalidPartition);
            }
            let off = 446 + slot * 16;
            if layout[p + 28] != 0 {
                let kind = layout[p + 32];
                let start = get_u64(layout, p + 8);
                let len = get_u64(layout, p + 16);
                if layout[p + 33] > 1
                    || start % geo.bytes as u64 != 0
                    || len % geo.bytes as u64 != 0
                {
                    return Err(MutationError::InvalidPartition);
                }
                let absolute = start / geo.bytes as u64;
                let sectors = len / geo.bytes as u64;
                if kind != 0
                    && (absolute == 0
                        || sectors == 0
                        || absolute
                            .checked_add(sectors)
                            .is_none_or(|end| end > geo.sectors))
                {
                    return Err(MutationError::InvalidPartition);
                }
                let origin = if group > 0 && is_extended(kind) {
                    extended_base.ok_or(MutationError::InvalidLayout)?
                } else {
                    next_lba
                };
                let entry = &mut sector[off..off + 16];
                entry.fill(0);
                if kind != 0 {
                    let relative = absolute
                        .checked_sub(origin)
                        .ok_or(MutationError::InvalidPartition)?;
                    if relative > u32::MAX as u64 || sectors > u32::MAX as u64 {
                        return Err(MutationError::InvalidPartition);
                    }
                    entry[0] = if layout[p + 33] != 0 { 0x80 } else { 0 };
                    entry[1..4].copy_from_slice(&[0xfe, 0xff, 0xff]);
                    entry[4] = kind;
                    entry[5..8].copy_from_slice(&[0xfe, 0xff, 0xff]);
                    entry[8..12].copy_from_slice(&(relative as u32).to_le_bytes());
                    entry[12..16].copy_from_slice(&(sectors as u32).to_le_bytes());
                }
            }
            let kind = sector[off + 4];
            if is_extended(kind) {
                if next.is_some() {
                    return Err(MutationError::InvalidLayout);
                }
                let relative = get_u32(&sector, off + 8) as u64;
                let target = if group == 0 {
                    relative
                } else {
                    extended_base.ok_or(MutationError::InvalidLayout)? + relative
                };
                if target == 0 || target >= geo.sectors {
                    return Err(MutationError::InvalidLayout);
                }
                next = Some(target);
                if group == 0 {
                    extended_base = Some(target);
                }
            }
        }
        if group == 0 {
            sector[440..444].copy_from_slice(&layout[8..12]);
        }
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        staged.push((next_lba, sector));
        if group + 1 < groups {
            next_lba = next.ok_or(MutationError::InvalidLayout)?;
        }
    }
    // Validate the resulting MBR/EBR chain, overlaps and ranges before the first write.
    read_drive_layout_ex(geo.bytes as u32, geo.sectors, |lba, out| {
        if let Some((_, sector)) = staged.iter().find(|(candidate, _)| *candidate == lba) {
            out.copy_from_slice(sector);
            Ok(())
        } else {
            io.read_sector(lba, out)
        }
    })
    .map_err(|error| match error {
        DriveLayoutReadError::Io(error) => MutationError::Io(error),
        DriveLayoutReadError::OutOfMemory => MutationError::OutOfMemory,
        DriveLayoutReadError::InvalidGeometry => MutationError::InvalidGeometry,
        DriveLayoutReadError::InvalidPartitionTable => MutationError::InvalidLayout,
    })?;
    for (lba, sector) in staged {
        write(io, lba, &sector)?;
    }
    Ok(())
}

/// Apply the `IoSetPartitionInformationEx` GPT payload to the numbered occupied
/// partition. MBR callers use `set_mbr_partition_type` after checking style.
pub fn set_gpt_partition_information<S: SectorIo>(
    io: &mut S,
    sector_bytes: u32,
    disk_sectors: u64,
    partition_number: u32,
    gpt_payload: &[u8],
) -> Result<(), MutationError<S::Error>> {
    let geo = geometry(sector_bytes, disk_sectors)?;
    if partition_number == 0 || gpt_payload.len() < 112 {
        return Err(MutationError::InvalidPartition);
    }
    let primary = read_gpt_copy(io, &geo, 1);
    let (header, header_sector, mut table, source_primary) = match primary {
        Ok((header, sector, table)) => (header, sector, table, true),
        Err(_) => {
            let (header, sector, table) = read_gpt_copy(io, &geo, disk_sectors - 1)?;
            (header, sector, table, false)
        }
    };
    let entry_size = header.partition_entry_size as usize;
    let mut occupied = 0u32;
    let at = (0..header.partition_entry_count as usize)
        .map(|slot| slot * entry_size)
        .find(|&at| {
            if table[at..at + 16] == [0; 16] {
                return false;
            }
            occupied += 1;
            occupied == partition_number
        })
        .ok_or(MutationError::InvalidPartition)?;
    table[at..at + 32].copy_from_slice(&gpt_payload[..32]);
    table[at + 48..at + 56].copy_from_slice(&gpt_payload[32..40]);
    table[at + 56..at + 128].copy_from_slice(&gpt_payload[40..112]);
    let table_bytes = header
        .partition_entries_bytes()
        .ok_or(MutationError::InvalidLayout)? as usize;
    let crc = gpt_crc32(&table[..table_bytes]);
    let table_sectors = table.len() / geo.bytes;
    let first_usable = header.first_usable_lba;
    let last_usable = header.last_usable_lba;
    if first_usable < 2 + table_sectors as u64
        || last_usable
            .checked_add(1 + table_sectors as u64)
            .is_none_or(|end| end >= geo.sectors)
    {
        return Err(MutationError::InvalidLayout);
    }
    let other = read_gpt_copy(io, &geo, if source_primary { geo.sectors - 1 } else { 1 })
        .ok()
        .filter(|(other, _, _)| {
            other.disk_guid == header.disk_guid
                && other.partition_entry_count == header.partition_entry_count
                && other.partition_entry_size == header.partition_entry_size
                && other.first_usable_lba == header.first_usable_lba
                && other.last_usable_lba == header.last_usable_lba
        });
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(2)
        .map_err(|_| MutationError::OutOfMemory)?;
    let roles = if source_primary {
        [false, true]
    } else {
        [true, false]
    };
    for primary_role in roles {
        let header_lba = if primary_role { 1 } else { geo.sectors - 1 };
        let existing = if primary_role == source_primary {
            Some((header, header_sector.clone()))
        } else {
            other.as_ref().map(|(h, s, _)| (*h, s.clone()))
        };
        let entries_lba = existing
            .as_ref()
            .map(|(h, _)| h.partition_entries_lba)
            .unwrap_or(if primary_role {
                2
            } else {
                geo.sectors - 1 - table_sectors as u64
            });
        let alternate_lba = if primary_role { geo.sectors - 1 } else { 1 };
        let mut updated = existing
            .map(|(_, sector)| sector)
            .unwrap_or_else(|| header_sector.clone());
        updated[24..32].copy_from_slice(&header_lba.to_le_bytes());
        updated[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
        updated[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        updated[88..92].copy_from_slice(&crc.to_le_bytes());
        updated[16..20].fill(0);
        let header_bytes = get_u32(&updated, 12) as usize;
        let header_crc = gpt_crc32(&updated[..header_bytes]);
        updated[16..20].copy_from_slice(&header_crc.to_le_bytes());
        parse_gpt_header(&updated, header_lba).map_err(|_| MutationError::InvalidLayout)?;
        headers.push((header_lba, entries_lba, updated));
    }
    for (header_lba, entries_lba, updated) in headers {
        for (i, chunk) in table.chunks_exact(geo.bytes).enumerate() {
            write(io, entries_lba + i as u64, chunk)?;
        }
        write(io, header_lba, &updated)?;
    }
    Ok(())
}

fn read_gpt_copy<S: SectorIo>(
    io: &mut S,
    geo: &Geometry,
    lba: u64,
) -> Result<(GptHeader, Vec<u8>, Vec<u8>), MutationError<S::Error>> {
    let mut sector = geo.sector()?;
    read(io, lba, &mut sector)?;
    let header = parse_gpt_header(&sector, lba).map_err(|_| MutationError::InvalidLayout)?;
    let bytes = header
        .partition_entries_bytes()
        .ok_or(MutationError::InvalidLayout)?;
    let sectors = bytes
        .checked_add(geo.bytes as u64 - 1)
        .ok_or(MutationError::InvalidLayout)?
        / geo.bytes as u64;
    if header.backup_lba >= geo.sectors
        || header.current_lba >= geo.sectors
        || header
            .partition_entries_lba
            .checked_add(sectors)
            .is_none_or(|end| end > geo.sectors)
    {
        return Err(MutationError::InvalidLayout);
    }
    let table_len = usize::try_from(
        sectors
            .checked_mul(geo.bytes as u64)
            .ok_or(MutationError::InvalidLayout)?,
    )
    .map_err(|_| MutationError::InvalidLayout)?;
    let mut table = Vec::new();
    table
        .try_reserve_exact(table_len)
        .map_err(|_| MutationError::OutOfMemory)?;
    table.resize(table_len, 0);
    for (i, chunk) in table.chunks_exact_mut(geo.bytes).enumerate() {
        read(io, header.partition_entries_lba + i as u64, chunk)?;
    }
    if gpt_crc32(&table[..bytes as usize]) != header.partition_entries_crc32 {
        return Err(MutationError::InvalidLayout);
    }
    Ok((header, sector, table))
}

fn write_existing_gpt<S: SectorIo>(
    io: &mut S,
    geo: Geometry,
    partitions: &[GptPartition],
) -> Result<(), MutationError<S::Error>> {
    let primary = read_gpt_copy(io, &geo, 1);
    let backup = read_gpt_copy(io, &geo, geo.sectors - 1);
    let source_primary = primary.is_ok();
    let (source, source_sector, mut table) = match primary {
        Ok(copy) => copy,
        Err(primary_error) => match &backup {
            Ok((header, sector, table)) => (*header, sector.clone(), table.clone()),
            Err(_) => {
                return Err(if matches!(&primary_error, MutationError::Io(_)) {
                    primary_error
                } else {
                    backup.err().unwrap()
                });
            }
        },
    };
    if partitions.len() > source.partition_entry_count as usize {
        return Err(MutationError::InvalidPartition);
    }
    for (i, partition) in partitions.iter().enumerate() {
        if partition.type_guid == [0; 16]
            || partition.unique_guid == [0; 16]
            || partition.first_lba < source.first_usable_lba
            || partition.last_lba > source.last_usable_lba
            || partition.first_lba > partition.last_lba
            || partitions[..i].iter().any(|prior| {
                prior.unique_guid == partition.unique_guid
                    || partition.first_lba <= prior.last_lba
                        && prior.first_lba <= partition.last_lba
            })
        {
            return Err(MutationError::InvalidPartition);
        }
    }
    let entry_size = source.partition_entry_size as usize;
    let old_table = table.clone();
    table.fill(0);
    for (i, partition) in partitions.iter().enumerate() {
        let at = i * entry_size;
        if entry_size > 128 {
            if let Some(old_slot) = (0..source.partition_entry_count as usize).find(|slot| {
                old_table[slot * entry_size + 16..slot * entry_size + 32] == partition.unique_guid
            }) {
                let old = old_slot * entry_size;
                table[at + 128..at + entry_size]
                    .copy_from_slice(&old_table[old + 128..old + entry_size]);
            }
        }
        table[at..at + 16].copy_from_slice(&partition.type_guid);
        table[at + 16..at + 32].copy_from_slice(&partition.unique_guid);
        table[at + 32..at + 40].copy_from_slice(&partition.first_lba.to_le_bytes());
        table[at + 40..at + 48].copy_from_slice(&partition.last_lba.to_le_bytes());
        table[at + 48..at + 56].copy_from_slice(&partition.attributes.to_le_bytes());
        for (n, unit) in partition.name.iter().enumerate() {
            table[at + 56 + n * 2..at + 58 + n * 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let table_bytes = source
        .partition_entries_bytes()
        .ok_or(MutationError::InvalidLayout)? as usize;
    let table_crc = gpt_crc32(&table[..table_bytes]);
    let table_sectors = table.len() / geo.bytes;
    let compatible_backup = backup.ok().filter(|(header, _, _)| {
        header.disk_guid == source.disk_guid
            && header.partition_entry_count == source.partition_entry_count
            && header.partition_entry_size == source.partition_entry_size
            && header.first_usable_lba == source.first_usable_lba
            && header.last_usable_lba == source.last_usable_lba
    });
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(2)
        .map_err(|_| MutationError::OutOfMemory)?;
    for is_primary in [true, false] {
        let header_lba = if is_primary { 1 } else { geo.sectors - 1 };
        let existing = if is_primary {
            if source_primary {
                Some((source, source_sector.clone()))
            } else {
                None
            }
        } else {
            compatible_backup
                .as_ref()
                .map(|(h, s, _)| (*h, s.clone()))
                .or_else(|| (!source_primary).then(|| (source, source_sector.clone())))
        };
        let entries_lba = existing
            .as_ref()
            .map(|(h, _)| h.partition_entries_lba)
            .unwrap_or(if is_primary {
                2
            } else {
                geo.sectors - 1 - table_sectors as u64
            });
        if entries_lba
            .checked_add(table_sectors as u64)
            .is_none_or(|end| end > geo.sectors)
        {
            return Err(MutationError::InvalidLayout);
        }
        let mut sector = existing
            .map(|(_, sector)| sector)
            .unwrap_or_else(|| source_sector.clone());
        sector[24..32].copy_from_slice(&header_lba.to_le_bytes());
        sector[32..40]
            .copy_from_slice(&(if is_primary { geo.sectors - 1 } else { 1u64 }).to_le_bytes());
        sector[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        sector[88..92].copy_from_slice(&table_crc.to_le_bytes());
        sector[16..20].fill(0);
        let header_bytes = get_u32(&sector, 12) as usize;
        let crc = gpt_crc32(&sector[..header_bytes]);
        sector[16..20].copy_from_slice(&crc.to_le_bytes());
        parse_gpt_header(&sector, header_lba).map_err(|_| MutationError::InvalidLayout)?;
        headers.push((header_lba, entries_lba, sector));
    }
    let order = if source_primary { [1usize, 0] } else { [0, 1] };
    for index in order {
        let (header_lba, entries_lba, sector) = &headers[index];
        for (i, chunk) in table.chunks_exact(geo.bytes).enumerate() {
            write(io, entries_lba + i as u64, chunk)?;
        }
        write(io, *header_lba, sector)?;
    }
    Ok(())
}

fn write_gpt<S: SectorIo>(
    io: &mut S,
    geo: Geometry,
    disk_guid: [u8; 16],
    max_partitions: u32,
    partitions: &[GptPartition],
) -> Result<(), MutationError<S::Error>> {
    if disk_guid == [0; 16] {
        return Err(MutationError::InvalidLayout);
    }
    let max_partitions = max_partitions.max(128);
    let entries_per_sector = geo.bytes / 128;
    let max_partitions = (max_partitions as usize)
        .checked_add(entries_per_sector - 1)
        .and_then(|n| n.checked_div(entries_per_sector))
        .and_then(|n| n.checked_mul(entries_per_sector))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(MutationError::InvalidLayout)?;
    if partitions.len() > max_partitions as usize {
        return Err(MutationError::InvalidLayout);
    }
    let count = u64::from(max_partitions);
    let table_bytes = count.checked_mul(128).ok_or(MutationError::InvalidLayout)?;
    let table_sectors = table_bytes
        .checked_add(geo.bytes as u64 - 1)
        .ok_or(MutationError::InvalidLayout)?
        / geo.bytes as u64;
    let first_usable = table_sectors
        .checked_add(2)
        .ok_or(MutationError::InvalidLayout)?;
    let last_usable = geo
        .sectors
        .checked_sub(table_sectors + 2)
        .ok_or(MutationError::InvalidLayout)?;
    if first_usable > last_usable {
        return Err(MutationError::InvalidLayout);
    }
    for (i, p) in partitions.iter().enumerate() {
        if p.type_guid == [0; 16]
            || p.unique_guid == [0; 16]
            || p.first_lba < first_usable
            || p.last_lba > last_usable
            || p.first_lba > p.last_lba
            || partitions[..i].iter().any(|q| {
                q.unique_guid == p.unique_guid
                    || p.first_lba <= q.last_lba && q.first_lba <= p.last_lba
            })
        {
            return Err(MutationError::InvalidPartition);
        }
    }
    let bytes = usize::try_from(
        table_sectors
            .checked_mul(geo.bytes as u64)
            .ok_or(MutationError::InvalidLayout)?,
    )
    .map_err(|_| MutationError::InvalidLayout)?;
    let mut table = Vec::new();
    table
        .try_reserve_exact(bytes)
        .map_err(|_| MutationError::OutOfMemory)?;
    table.resize(bytes, 0);
    for (i, p) in partitions.iter().enumerate() {
        let off = i * 128;
        table[off..off + 16].copy_from_slice(&p.type_guid);
        table[off + 16..off + 32].copy_from_slice(&p.unique_guid);
        table[off + 32..off + 40].copy_from_slice(&p.first_lba.to_le_bytes());
        table[off + 40..off + 48].copy_from_slice(&p.last_lba.to_le_bytes());
        table[off + 48..off + 56].copy_from_slice(&p.attributes.to_le_bytes());
        for (n, unit) in p.name.iter().enumerate() {
            table[off + 56 + n * 2..off + 58 + n * 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let crc = gpt_crc32(&table[..table_bytes as usize]);
    let mut header = geo.sector()?;
    // Publish backup metadata first, then primary, then the protective MBR.
    for (header_lba, entries_lba, alternate) in [
        (geo.sectors - 1, geo.sectors - 1 - table_sectors, 1),
        (1, 2, geo.sectors - 1),
    ] {
        for (index, chunk) in table.chunks_exact(geo.bytes).enumerate() {
            write(io, entries_lba + index as u64, chunk)?;
        }
        header.fill(0);
        header[..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&header_lba.to_le_bytes());
        header[32..40].copy_from_slice(&alternate.to_le_bytes());
        header[40..48].copy_from_slice(&first_usable.to_le_bytes());
        header[48..56].copy_from_slice(&last_usable.to_le_bytes());
        header[56..72].copy_from_slice(&disk_guid);
        header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        header[80..84].copy_from_slice(&max_partitions.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        header[88..92].copy_from_slice(&crc.to_le_bytes());
        let header_crc = gpt_crc32(&header[..92]);
        header[16..20].copy_from_slice(&header_crc.to_le_bytes());
        write(io, header_lba, &header)?;
    }
    read(io, 0, &mut header)?;
    header[446..510].fill(0);
    header[450] = 0xee;
    header[454..458].copy_from_slice(&1u32.to_le_bytes());
    header[458..462]
        .copy_from_slice(&((geo.sectors - 1).min(u32::MAX as u64) as u32).to_le_bytes());
    header[510..512].copy_from_slice(&[0x55, 0xaa]);
    write(io, 0, &header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct Disk(vec::Vec<vec::Vec<u8>>);
    impl Disk {
        fn new(sectors: usize, sector_bytes: usize) -> Self {
            Self(vec![vec![0xa5; sector_bytes]; sectors])
        }
    }
    impl SectorIo for Disk {
        type Error = ();
        fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), Self::Error> {
            out.copy_from_slice(&self.0[lba as usize]);
            Ok(())
        }
        fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.0[lba as usize].copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn create_mbr_preserves_boot_code_and_sector_tail() {
        let mut disk = Disk::new(128, 4096);
        create_disk(
            &mut disk,
            4096,
            128,
            CreateDisk::Mbr {
                signature: 0x12345678,
            },
        )
        .unwrap();
        assert_eq!(&disk.0[0][..440], &[0xa5; 440]);
        assert_eq!(&disk.0[0][440..444], &0x12345678u32.to_le_bytes());
        assert_eq!(&disk.0[0][446..510], &[0; 64]);
        assert_eq!(&disk.0[0][510..512], &[0x55, 0xaa]);
        assert_eq!(&disk.0[0][512..], &[0xa5; 3584]);
    }

    #[test]
    fn invalid_geometry_cannot_mutate_media() {
        let mut disk = Disk::new(128, 512);
        assert_eq!(
            create_disk(&mut disk, 513, 128, CreateDisk::Mbr { signature: 1 }),
            Err(MutationError::InvalidGeometry)
        );
        assert_eq!(disk.0[0], vec![0xa5; 512]);
    }

    #[test]
    fn create_gpt_emits_two_crc_valid_copies_and_protective_mbr() {
        let mut disk = Disk::new(128, 512);
        create_disk(
            &mut disk,
            512,
            128,
            CreateDisk::Gpt {
                disk_guid: [0x33; 16],
                max_partitions: 128,
            },
        )
        .unwrap();
        assert_eq!(disk.0[0][450], 0xee);
        assert_eq!(&disk.0[0][510..512], &[0x55, 0xaa]);
        for header_lba in [1usize, 127] {
            let header = &disk.0[header_lba];
            assert_eq!(&header[..8], b"EFI PART");
            let crc = u32::from_le_bytes(header[16..20].try_into().unwrap());
            let mut copy = header.clone();
            copy[16..20].fill(0);
            assert_eq!(crc, gpt_crc32(&copy[..92]));
        }
        let layout = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(u32::from_le_bytes(layout[..4].try_into().unwrap()), 1);
    }

    #[test]
    fn mbr_type_edit_preserves_all_other_bytes() {
        let mut disk = Disk::new(128, 512);
        create_disk(&mut disk, 512, 128, CreateDisk::Mbr { signature: 7 }).unwrap();
        disk.0[0][450] = 7;
        disk.0[0][454..458].copy_from_slice(&8u32.to_le_bytes());
        disk.0[0][458..462].copy_from_slice(&16u32.to_le_bytes());
        let before = disk.0[0].clone();
        set_mbr_partition_type(&mut disk, 512, 128, 1, 0x0b).unwrap();
        assert_eq!(disk.0[0][450], 0x0b);
        disk.0[0][450] = 7;
        assert_eq!(disk.0[0], before);
    }

    #[test]
    fn drive_layout_write_and_gpt_info_edit_round_trip() {
        let mut disk = Disk::new(128, 512);
        create_disk(
            &mut disk,
            512,
            128,
            CreateDisk::Gpt {
                disk_guid: [0x33; 16],
                max_partitions: 0,
            },
        )
        .unwrap();
        let mut layout = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        layout.resize(48 + 144, 0);
        layout[4..8].copy_from_slice(&1u32.to_le_bytes());
        layout[48..52].copy_from_slice(&1u32.to_le_bytes());
        layout[56..64].copy_from_slice(&(40u64 * 512).to_le_bytes());
        layout[64..72].copy_from_slice(&(16u64 * 512).to_le_bytes());
        layout[80..96].fill(0x11);
        layout[96..112].fill(0x22);
        write_drive_layout_ex(&mut disk, 512, 128, &layout).unwrap();
        let reread = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(reread[80..112], layout[80..112]);
        let mut payload = [0u8; 112];
        payload[..16].fill(0x44);
        payload[16..32].fill(0x22);
        set_gpt_partition_information(&mut disk, 512, 128, 1, &payload).unwrap();
        let edited = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(&edited[80..96], &[0x44; 16]);
    }

    #[test]
    fn gpt_set_ex_preserves_sparse_on_disk_slot_numbers() {
        let mut disk = Disk::new(128, 512);
        create_disk(
            &mut disk,
            512,
            128,
            CreateDisk::Gpt {
                disk_guid: [0x33; 16],
                max_partitions: 128,
            },
        )
        .unwrap();
        let mut layout = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        layout.resize(192, 0);
        layout[4..8].copy_from_slice(&1u32.to_le_bytes());
        layout[48..52].copy_from_slice(&1u32.to_le_bytes());
        layout[56..64].copy_from_slice(&(40u64 * 512).to_le_bytes());
        layout[64..72].copy_from_slice(&(16u64 * 512).to_le_bytes());
        layout[80..96].fill(0x11);
        layout[96..112].fill(0x22);
        write_drive_layout_ex(&mut disk, 512, 128, &layout).unwrap();
        for (header_lba, array_lba) in [(1usize, 2usize), (127, 95)] {
            let entry = disk.0[array_lba][..128].to_vec();
            disk.0[array_lba][..128].fill(0);
            disk.0[array_lba][384..512].copy_from_slice(&entry);
            let mut crc = crate::GptCrc32::new();
            for sector in &disk.0[array_lba..array_lba + 32] {
                crc.update(sector);
            }
            disk.0[header_lba][88..92].copy_from_slice(&crc.finish().to_le_bytes());
            disk.0[header_lba][16..20].fill(0);
            let crc = gpt_crc32(&disk.0[header_lba][..92]);
            disk.0[header_lba][16..20].copy_from_slice(&crc.to_le_bytes());
        }
        let mut payload = [0u8; 112];
        payload[..16].fill(0x44);
        payload[16..32].fill(0x22);
        set_gpt_partition_information(&mut disk, 512, 128, 1, &payload).unwrap();
        assert_eq!(&disk.0[2][..16], &[0; 16]);
        assert_eq!(&disk.0[2][384..400], &[0x44; 16]);
        assert_eq!(&disk.0[95][384..400], &[0x44; 16]);
        let layout = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(&layout[80..96], &[0x44; 16]);
    }

    #[test]
    fn extended_mbr_layout_writes_ebr_and_type_edit_targets_logical_entry() {
        let mut disk = Disk::new(128, 512);
        create_disk(&mut disk, 512, 128, CreateDisk::Mbr { signature: 7 }).unwrap();
        let mut layout = vec![0u8; 48 + 8 * 144];
        layout[4..8].copy_from_slice(&8u32.to_le_bytes());
        layout[8..12].copy_from_slice(&7u32.to_le_bytes());
        for (slot, kind, start, len) in [(0, 0x0f, 32, 64), (1, 7, 8, 16), (4, 7, 40, 16)] {
            let p = 48 + slot * 144;
            layout[p + 28] = 1;
            layout[p + 32] = kind;
            layout[p + 8..p + 16].copy_from_slice(&(start as u64 * 512).to_le_bytes());
            layout[p + 16..p + 24].copy_from_slice(&(len as u64 * 512).to_le_bytes());
        }
        for slot in [2, 3, 5, 6, 7] {
            layout[48 + slot * 144 + 28] = 1;
        }
        write_drive_layout_ex(&mut disk, 512, 128, &layout).unwrap();
        assert_eq!(disk.0[0][450], 0x0f);
        assert_eq!(disk.0[32][450], 7);
        assert_eq!(
            u32::from_le_bytes(disk.0[32][454..458].try_into().unwrap()),
            8
        );
        set_mbr_partition_type(&mut disk, 512, 128, 2, 0x0b).unwrap();
        assert_eq!(disk.0[32][450], 0x0b);
        assert_eq!(disk.0[0][466], 7);
        let reread = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(u32::from_le_bytes(reread[4..8].try_into().unwrap()), 8);
        let before = disk.0.clone();
        write_drive_layout_ex(&mut disk, 512, 128, &reread).unwrap();
        assert_eq!(disk.0, before);
    }

    #[test]
    fn full_gpt_write_preserves_valid_nonstandard_entry_size_and_locations() {
        let mut disk = Disk::new(128, 512);
        disk.0[0].fill(0);
        disk.0[0][450] = 0xee;
        disk.0[0][454..458].copy_from_slice(&1u32.to_le_bytes());
        disk.0[0][458..462].copy_from_slice(&127u32.to_le_bytes());
        disk.0[0][510..512].copy_from_slice(&[0x55, 0xaa]);
        let mut entries = vec![0u8; 1024];
        entries[..16].fill(0x11);
        entries[16..32].fill(0x22);
        entries[32..40].copy_from_slice(&8u64.to_le_bytes());
        entries[40..48].copy_from_slice(&15u64.to_le_bytes());
        entries[128..256].fill(0x66);
        let array_crc = gpt_crc32(&entries);
        for (header_lba, backup_lba, array_lba) in [(1usize, 127u64, 3usize), (127, 1, 124)] {
            disk.0[array_lba].copy_from_slice(&entries[..512]);
            disk.0[array_lba + 1].copy_from_slice(&entries[512..]);
            let mut header = vec![0u8; 512];
            header[..8].copy_from_slice(b"EFI PART");
            header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
            header[12..16].copy_from_slice(&92u32.to_le_bytes());
            header[24..32].copy_from_slice(&(header_lba as u64).to_le_bytes());
            header[32..40].copy_from_slice(&backup_lba.to_le_bytes());
            header[40..48].copy_from_slice(&5u64.to_le_bytes());
            header[48..56].copy_from_slice(&123u64.to_le_bytes());
            header[56..72].fill(0x33);
            header[72..80].copy_from_slice(&(array_lba as u64).to_le_bytes());
            header[80..84].copy_from_slice(&4u32.to_le_bytes());
            header[84..88].copy_from_slice(&256u32.to_le_bytes());
            header[88..92].copy_from_slice(&array_crc.to_le_bytes());
            let crc = gpt_crc32(&header[..92]);
            header[16..20].copy_from_slice(&crc.to_le_bytes());
            disk.0[header_lba] = header;
        }
        let mut layout = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        layout[80..96].fill(0x44);
        write_drive_layout_ex(&mut disk, 512, 128, &layout).unwrap();
        for (header_lba, array_lba) in [(1usize, 3u64), (127, 124)] {
            assert_eq!(get_u64(&disk.0[header_lba], 72), array_lba);
            assert_eq!(get_u32(&disk.0[header_lba], 84), 256);
        }
        assert_eq!(&disk.0[3][..16], &[0x44; 16]);
        assert_eq!(&disk.0[124][..16], &[0x44; 16]);
        assert_eq!(&disk.0[3][128..256], &[0x66; 128]);
        assert_eq!(&disk.0[124][128..256], &[0x66; 128]);
        let mut payload = [0u8; 112];
        payload[..16].fill(0x55);
        payload[16..32].fill(0x22);
        set_gpt_partition_information(&mut disk, 512, 128, 1, &payload).unwrap();
        assert_eq!(&disk.0[3][..16], &[0x55; 16]);
        assert_eq!(&disk.0[124][..16], &[0x55; 16]);
        assert_eq!(&disk.0[3][128..256], &[0x66; 128]);
        let reread = crate::read_drive_layout_ex(512, 128, |lba, out| {
            out.copy_from_slice(&disk.0[lba as usize]);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(&reread[80..96], &[0x55; 16]);
    }

    #[test]
    fn full_gpt_write_preserves_header_read_io_failure() {
        struct FailedReads;
        impl SectorIo for FailedReads {
            type Error = u32;
            fn read_sector(&mut self, _: u64, _: &mut [u8]) -> Result<(), Self::Error> {
                Err(0xc000_0185)
            }
            fn write_sector(&mut self, _: u64, _: &[u8]) -> Result<(), Self::Error> {
                panic!("metadata must not be written after failed header reads")
            }
        }
        let mut layout = vec![0u8; 48 + 144];
        layout[0..4].copy_from_slice(&1u32.to_le_bytes());
        layout[4..8].copy_from_slice(&1u32.to_le_bytes());
        layout[48..52].copy_from_slice(&1u32.to_le_bytes());
        layout[56..64].copy_from_slice(&(40u64 * 512).to_le_bytes());
        layout[64..72].copy_from_slice(&(16u64 * 512).to_le_bytes());
        layout[80..96].fill(0x11);
        layout[96..112].fill(0x22);
        assert_eq!(
            write_drive_layout_ex(&mut FailedReads, 512, 128, &layout),
            Err(MutationError::Io(0xc000_0185)),
        );
    }
}
