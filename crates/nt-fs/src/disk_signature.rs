//! Disk identity read from the caller's sector source, with no mounted-volume shortcut.

use alloc::vec::Vec;

use crate::gpt_crc32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskSignature {
    Mbr { signature: u32, checksum: u32 },
    Gpt { disk_id: [u8; 16] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskSignatureReadError<E> {
    Io(E),
    InvalidSectorSize,
    InvalidGptHeader,
    OutOfMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MbrExamination {
    DiskManager { skew_sectors: u32 },
    EzDrive,
}

/// Examine a sector already read from the specified device stack. The legacy 0x54
/// disk-manager record reports a 63-sector skew, while 0x55 returns the MBR itself.
pub fn examine_mbr(sector: &[u8], partition_type: u32) -> Option<MbrExamination> {
    if sector.len() < 512 || sector[510..512] != [0x55, 0xaa]
        || sector[450] != partition_type as u8 || partition_type > u8::MAX as u32
    {
        return None;
    }
    match partition_type {
        0x54 => Some(MbrExamination::DiskManager { skew_sectors: 63 }),
        0x55 => Some(MbrExamination::EzDrive),
        _ => None,
    }
}

/// Read sector zero and, for a protective MBR, sector one from the caller's device.
/// The signature structure is returned as values so the native adapter controls its ABI.
pub fn read_disk_signature<E>(
    sector_bytes: u32,
    mut read_sector: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<DiskSignature, DiskSignatureReadError<E>> {
    if !(512..=65_536).contains(&sector_bytes) {
        return Err(DiskSignatureReadError::InvalidSectorSize);
    }
    let mut sector = Vec::new();
    sector.try_reserve_exact(sector_bytes as usize)
        .map_err(|_| DiskSignatureReadError::OutOfMemory)?;
    sector.resize(sector_bytes as usize, 0);
    read_sector(0, &mut sector).map_err(DiskSignatureReadError::Io)?;
    let protective = sector[450] == 0xee && [466, 482, 498].iter().all(|&offset| sector[offset] == 0);
    if protective {
        read_sector(1, &mut sector).map_err(DiskSignatureReadError::Io)?;
        if &sector[0..8] != b"EFI PART"
            || u32::from_le_bytes(sector[8..12].try_into().unwrap()) != 0x0001_0000
            || u32::from_le_bytes(sector[12..16].try_into().unwrap()) != 92
        {
            return Err(DiskSignatureReadError::InvalidGptHeader);
        }
        let expected = u32::from_le_bytes(sector[16..20].try_into().unwrap());
        sector[16..20].fill(0);
        if gpt_crc32(&sector[..92]) != expected {
            return Err(DiskSignatureReadError::InvalidGptHeader);
        }
        let mut disk_id = [0; 16];
        disk_id.copy_from_slice(&sector[56..72]);
        return Ok(DiskSignature::Gpt { disk_id });
    }
    let signature = u32::from_le_bytes(sector[440..444].try_into().unwrap());
    let checksum = sector[..512].chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_le_bytes(word.try_into().unwrap()))
    });
    Ok(DiskSignature::Mbr { signature, checksum: 0u32.wrapping_sub(checksum) })
}
