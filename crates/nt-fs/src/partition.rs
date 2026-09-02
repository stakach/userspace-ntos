//! Read-only GPT discovery used by storage providers before mounting a filesystem.

pub const DISK_SECTOR_BYTES: usize = 512;
pub const GPT_ENTRY_MIN_BYTES: u32 = 128;
pub const EFI_SYSTEM_PARTITION_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GptError {
    Truncated,
    InvalidProtectiveMbr,
    InvalidSignature,
    InvalidHeader,
    HeaderChecksum,
    InvalidEntry,
    InvalidFat32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptHeader {
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub partition_entries_lba: u64,
    pub partition_entry_count: u32,
    pub partition_entry_size: u32,
    pub partition_entries_crc32: u32,
}

impl GptHeader {
    pub fn partition_entries_bytes(self) -> Option<u64> {
        u64::from(self.partition_entry_count).checked_mul(u64::from(self.partition_entry_size))
    }

    pub fn disk_sectors(self) -> Option<u64> {
        self.backup_lba.checked_add(1)
    }

    pub fn partition_entries_sectors(self) -> Option<u64> {
        self.partition_entries_bytes()?
            .checked_add(DISK_SECTOR_BYTES as u64 - 1)
            .map(|bytes| bytes / DISK_SECTOR_BYTES as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptPartition {
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
}

impl GptPartition {
    pub fn sector_count(self) -> Option<u64> {
        self.last_lba.checked_sub(self.first_lba)?.checked_add(1)
    }

    pub fn is_efi_system_partition(self) -> bool {
        self.type_guid == EFI_SYSTEM_PARTITION_GUID
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GptCrc32(u32);

impl GptCrc32 {
    pub const fn new() -> Self {
        Self(u32::MAX)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u32::from(*byte);
            for _ in 0..8 {
                self.0 = (self.0 >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(self.0 & 1)));
            }
        }
    }

    pub const fn finish(self) -> u32 {
        !self.0
    }
}

impl Default for GptCrc32 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn gpt_crc32(bytes: &[u8]) -> u32 {
    let mut crc = GptCrc32::new();
    crc.update(bytes);
    crc.finish()
}

pub fn validate_protective_mbr(sector: &[u8]) -> Result<(), GptError> {
    if sector.len() < DISK_SECTOR_BYTES {
        return Err(GptError::Truncated);
    }
    if sector[510] != 0x55 || sector[511] != 0xaa {
        return Err(GptError::InvalidProtectiveMbr);
    }
    let protective = (0..4).any(|index| sector[446 + index * 16 + 4] == 0xee);
    protective
        .then_some(())
        .ok_or(GptError::InvalidProtectiveMbr)
}

pub fn parse_gpt_header(sector: &[u8], expected_lba: u64) -> Result<GptHeader, GptError> {
    if sector.len() < DISK_SECTOR_BYTES {
        return Err(GptError::Truncated);
    }
    if sector.get(..8) != Some(b"EFI PART") {
        return Err(GptError::InvalidSignature);
    }
    let revision = le_u32(sector, 8)?;
    let header_size = le_u32(sector, 12)? as usize;
    if revision < 0x0001_0000 || !(92..=DISK_SECTOR_BYTES).contains(&header_size) {
        return Err(GptError::InvalidHeader);
    }
    let stored_crc = le_u32(sector, 16)?;
    let mut crc = GptCrc32::new();
    crc.update(&sector[..16]);
    crc.update(&[0; 4]);
    crc.update(&sector[20..header_size]);
    if crc.finish() != stored_crc {
        return Err(GptError::HeaderChecksum);
    }

    let header = GptHeader {
        current_lba: le_u64(sector, 24)?,
        backup_lba: le_u64(sector, 32)?,
        first_usable_lba: le_u64(sector, 40)?,
        last_usable_lba: le_u64(sector, 48)?,
        partition_entries_lba: le_u64(sector, 72)?,
        partition_entry_count: le_u32(sector, 80)?,
        partition_entry_size: le_u32(sector, 84)?,
        partition_entries_crc32: le_u32(sector, 88)?,
    };
    if header.current_lba != expected_lba
        || header.backup_lba == header.current_lba
        || header.first_usable_lba > header.last_usable_lba
        || header.last_usable_lba >= header.backup_lba
        || header.partition_entries_lba == 0
        || header.partition_entry_count == 0
        || header.partition_entry_size < GPT_ENTRY_MIN_BYTES
        || header.partition_entry_size as usize > DISK_SECTOR_BYTES
        || header.partition_entry_size % 8 != 0
        || header.partition_entries_bytes().is_none()
        || header
            .partition_entries_sectors()
            .and_then(|sectors| header.partition_entries_lba.checked_add(sectors))
            .is_none_or(|end| end > header.first_usable_lba)
    {
        return Err(GptError::InvalidHeader);
    }
    Ok(header)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fat32Geometry {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub total_sectors: u32,
    pub fs_info_sector: u32,
    pub volume_serial: u32,
    pub volume_label: [u8; 11],
    pub fat_start_sector: u32,
    pub data_start_sector: u32,
    pub root_cluster: u32,
}

impl Fat32Geometry {
    pub fn parse(sector: &[u8], partition_sectors: u64) -> Result<Self, GptError> {
        if sector.len() < DISK_SECTOR_BYTES {
            return Err(GptError::Truncated);
        }
        let bytes_per_sector = u32::from(le_u16(sector, 0x0b)?);
        let sectors_per_cluster = u32::from(sector[0x0d]);
        let reserved = u32::from(le_u16(sector, 0x0e)?);
        let fat_count = u32::from(sector[0x10]);
        let total16 = u32::from(le_u16(sector, 0x13)?);
        let total32 = le_u32(sector, 0x20)?;
        let total_sectors = if total16 == 0 { total32 } else { total16 };
        let sectors_per_fat = le_u32(sector, 0x24)?;
        let root_cluster = le_u32(sector, 0x2c)?;
        let fs_info_sector = u32::from(le_u16(sector, 0x30)?);
        let volume_serial = le_u32(sector, 0x43)?;
        let fat_sectors = fat_count
            .checked_mul(sectors_per_fat)
            .ok_or(GptError::InvalidFat32)?;
        let data_start_sector = reserved
            .checked_add(fat_sectors)
            .ok_or(GptError::InvalidFat32)?;
        if sector[510..512] != [0x55, 0xaa]
            || sector.get(0x52..0x57) != Some(b"FAT32")
            || bytes_per_sector != DISK_SECTOR_BYTES as u32
            || sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || reserved == 0
            || fat_count == 0
            || sectors_per_fat == 0
            || root_cluster < 2
            || fs_info_sector == 0
            || fs_info_sector >= reserved
            || total_sectors == 0
            || u64::from(total_sectors) > partition_sectors
            || data_start_sector >= total_sectors
        {
            return Err(GptError::InvalidFat32);
        }
        let mut volume_label = [0; 11];
        volume_label.copy_from_slice(&sector[0x47..0x52]);
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            fs_info_sector,
            volume_serial,
            volume_label,
            fat_start_sector: reserved,
            data_start_sector,
            root_cluster,
        })
    }
}

pub fn checked_partition_lba(partition_start: u64, relative_sector: u32) -> Option<u64> {
    partition_start.checked_add(u64::from(relative_sector))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, GptError> {
    let value = bytes.get(offset..offset + 2).ok_or(GptError::Truncated)?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

pub fn parse_gpt_partition_entry(
    bytes: &[u8],
    header: GptHeader,
) -> Result<Option<GptPartition>, GptError> {
    let entry_size = header.partition_entry_size as usize;
    if bytes.len() < entry_size {
        return Err(GptError::Truncated);
    }
    if bytes[..16].iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let mut type_guid = [0; 16];
    type_guid.copy_from_slice(&bytes[..16]);
    let mut unique_guid = [0; 16];
    unique_guid.copy_from_slice(&bytes[16..32]);
    let partition = GptPartition {
        type_guid,
        unique_guid,
        first_lba: le_u64(bytes, 32)?,
        last_lba: le_u64(bytes, 40)?,
        attributes: le_u64(bytes, 48)?,
    };
    if partition.first_lba < header.first_usable_lba
        || partition.last_lba > header.last_usable_lba
        || partition.first_lba > partition.last_lba
    {
        return Err(GptError::InvalidEntry);
    }
    Ok(Some(partition))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, GptError> {
    let value = bytes.get(offset..offset + 4).ok_or(GptError::Truncated)?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, GptError> {
    let value = bytes.get(offset..offset + 8).ok_or(GptError::Truncated)?;
    Ok(u64::from_le_bytes(value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_sector() -> [u8; DISK_SECTOR_BYTES] {
        let mut sector = [0; DISK_SECTOR_BYTES];
        sector[..8].copy_from_slice(b"EFI PART");
        sector[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        sector[12..16].copy_from_slice(&92u32.to_le_bytes());
        sector[24..32].copy_from_slice(&1u64.to_le_bytes());
        sector[32..40].copy_from_slice(&4095u64.to_le_bytes());
        sector[40..48].copy_from_slice(&34u64.to_le_bytes());
        sector[48..56].copy_from_slice(&4062u64.to_le_bytes());
        sector[72..80].copy_from_slice(&2u64.to_le_bytes());
        sector[80..84].copy_from_slice(&128u32.to_le_bytes());
        sector[84..88].copy_from_slice(&128u32.to_le_bytes());
        sector[88..92].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        let crc = gpt_crc32(&sector[..92]);
        sector[16..20].copy_from_slice(&crc.to_le_bytes());
        sector
    }

    #[test]
    fn validates_protective_mbr() {
        let mut sector = [0; DISK_SECTOR_BYTES];
        sector[446 + 4] = 0xee;
        sector[510..].copy_from_slice(&[0x55, 0xaa]);
        assert_eq!(validate_protective_mbr(&sector), Ok(()));
        sector[446 + 4] = 0;
        assert_eq!(
            validate_protective_mbr(&sector),
            Err(GptError::InvalidProtectiveMbr)
        );
    }

    #[test]
    fn validates_header_crc_and_geometry() {
        let sector = header_sector();
        let header = parse_gpt_header(&sector, 1).unwrap();
        assert_eq!(header.disk_sectors(), Some(4096));
        assert_eq!(header.partition_entries_bytes(), Some(16_384));

        let mut corrupt = sector;
        corrupt[40] ^= 1;
        assert_eq!(parse_gpt_header(&corrupt, 1), Err(GptError::HeaderChecksum));
    }

    #[test]
    fn parses_efi_partition_and_rejects_out_of_range_entry() {
        let header = parse_gpt_header(&header_sector(), 1).unwrap();
        let mut entry = [0; 128];
        entry[..16].copy_from_slice(&EFI_SYSTEM_PARTITION_GUID);
        entry[16..32].copy_from_slice(&[7; 16]);
        entry[32..40].copy_from_slice(&2048u64.to_le_bytes());
        entry[40..48].copy_from_slice(&3071u64.to_le_bytes());
        let partition = parse_gpt_partition_entry(&entry, header).unwrap().unwrap();
        assert!(partition.is_efi_system_partition());
        assert_eq!(partition.sector_count(), Some(1024));

        entry[40..48].copy_from_slice(&4090u64.to_le_bytes());
        assert_eq!(
            parse_gpt_partition_entry(&entry, header),
            Err(GptError::InvalidEntry)
        );
    }

    #[test]
    fn crc_stream_matches_one_shot() {
        let bytes = b"123456789";
        let mut stream = GptCrc32::new();
        stream.update(&bytes[..4]);
        stream.update(&bytes[4..]);
        assert_eq!(stream.finish(), 0xcbf4_3926);
        assert_eq!(stream.finish(), gpt_crc32(bytes));
    }

    fn fat32_sector() -> [u8; DISK_SECTOR_BYTES] {
        let mut sector = [0u8; DISK_SECTOR_BYTES];
        sector[0x0b..0x0d].copy_from_slice(&512u16.to_le_bytes());
        sector[0x0d] = 8;
        sector[0x0e..0x10].copy_from_slice(&32u16.to_le_bytes());
        sector[0x10] = 2;
        sector[0x20..0x24].copy_from_slice(&65_536u32.to_le_bytes());
        sector[0x24..0x28].copy_from_slice(&64u32.to_le_bytes());
        sector[0x2c..0x30].copy_from_slice(&2u32.to_le_bytes());
        sector[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
        sector[0x43..0x47].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        sector[0x47..0x52].copy_from_slice(b"SIMPLEBOOT ");
        sector[0x52..0x57].copy_from_slice(b"FAT32");
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        sector
    }

    #[test]
    fn validates_partition_contained_fat32_geometry() {
        let geometry = Fat32Geometry::parse(&fat32_sector(), 65_536).unwrap();
        assert_eq!(geometry.fat_start_sector, 32);
        assert_eq!(geometry.data_start_sector, 160);
        assert_eq!(geometry.root_cluster, 2);
        assert_eq!(geometry.volume_label, *b"SIMPLEBOOT ");

        assert_eq!(
            Fat32Geometry::parse(&fat32_sector(), 65_535),
            Err(GptError::InvalidFat32)
        );
        let mut invalid = fat32_sector();
        invalid[0x0d] = 3;
        assert_eq!(
            Fat32Geometry::parse(&invalid, 65_536),
            Err(GptError::InvalidFat32)
        );
    }

    #[test]
    fn translates_partition_relative_lbas_with_overflow_checks() {
        assert_eq!(checked_partition_lba(2048, 7), Some(2055));
        assert_eq!(checked_partition_lba(u64::MAX, 1), None);
    }
}
