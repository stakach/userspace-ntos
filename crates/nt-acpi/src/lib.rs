//! Checked ACPI table and fixed-event policy for the NT executive.
//!
//! Physical mapping, I/O-port capabilities, IRQ objects, and acknowledgement remain executive
//! mechanisms. This crate validates firmware bytes and describes only the exact resources those
//! mechanisms may access.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub const SDT_HEADER_LEN: usize = 36;
pub const FADT_SIGNATURE: [u8; 4] = *b"FACP";
pub const DSDT_SIGNATURE: [u8; 4] = *b"DSDT";

pub const ADDRESS_SPACE_SYSTEM_MEMORY: u8 = 0;
pub const ADDRESS_SPACE_SYSTEM_IO: u8 = 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiError {
    Truncated,
    InvalidLength,
    InvalidChecksum,
    InvalidSignature,
    InvalidRootEntryWidth,
    NullTableAddress,
    DuplicateTableAddress,
    Allocation,
    MissingSciInterrupt,
    InvalidRegisterBlock,
    UnsupportedAddressSpace(u8),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
}

pub fn validate_sdt(bytes: &[u8]) -> Result<SdtHeader, AcpiError> {
    if bytes.len() < SDT_HEADER_LEN {
        return Err(AcpiError::Truncated);
    }
    let length = read_u32(bytes, 4)? as usize;
    if length < SDT_HEADER_LEN || length > bytes.len() {
        return Err(AcpiError::InvalidLength);
    }
    if bytes[..length].iter().copied().fold(0u8, u8::wrapping_add) != 0 {
        return Err(AcpiError::InvalidChecksum);
    }
    Ok(SdtHeader {
        signature: bytes[0..4].try_into().unwrap(),
        length: length as u32,
        revision: bytes[8],
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiRootTable {
    pub header: SdtHeader,
    pub entries: Vec<u64>,
}

impl AcpiRootTable {
    pub fn parse(bytes: &[u8]) -> Result<Self, AcpiError> {
        let header = validate_sdt(bytes)?;
        let entry_width = match &header.signature {
            b"RSDT" => 4,
            b"XSDT" => 8,
            _ => return Err(AcpiError::InvalidSignature),
        };
        let payload_len = header.length as usize - SDT_HEADER_LEN;
        if payload_len % entry_width != 0 {
            return Err(AcpiError::InvalidRootEntryWidth);
        }
        let count = payload_len / entry_width;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| AcpiError::Allocation)?;
        for index in 0..count {
            let offset = SDT_HEADER_LEN + index * entry_width;
            let address = if entry_width == 4 {
                read_u32(bytes, offset)? as u64
            } else {
                read_u64(bytes, offset)?
            };
            if address == 0 {
                return Err(AcpiError::NullTableAddress);
            }
            if entries.contains(&address) {
                return Err(AcpiError::DuplicateTableAddress);
            }
            entries.push(address);
        }
        Ok(Self { header, entries })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GenericAddress {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

impl GenericAddress {
    fn parse(bytes: &[u8], offset: usize) -> Result<Self, AcpiError> {
        Ok(Self {
            address_space: read_u8(bytes, offset)?,
            bit_width: read_u8(bytes, offset + 1)?,
            bit_offset: read_u8(bytes, offset + 2)?,
            access_size: read_u8(bytes, offset + 3)?,
            address: read_u64(bytes, offset + 4)?,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegisterBlock {
    pub address_space: u8,
    pub address: u64,
    pub length: u8,
}

impl RegisterBlock {
    pub fn split_status_enable(self) -> Result<(Self, Self), AcpiError> {
        if self.length == 0 || self.length & 1 != 0 {
            return Err(AcpiError::InvalidRegisterBlock);
        }
        let half = self.length / 2;
        let enable_address = self
            .address
            .checked_add(half as u64)
            .ok_or(AcpiError::InvalidRegisterBlock)?;
        Ok((
            Self {
                length: half,
                ..self
            },
            Self {
                address: enable_address,
                length: half,
                ..self
            },
        ))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventRegisterPair {
    pub status: RegisterBlock,
    pub enable: RegisterBlock,
    /// First AML GPE number represented by this block.
    pub base_event: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedAcpiDescription {
    pub revision: u8,
    pub sci_interrupt: u16,
    pub dsdt_address: u64,
    pub pm1a_event: Option<EventRegisterPair>,
    pub pm1b_event: Option<EventRegisterPair>,
    pub gpe0: Option<EventRegisterPair>,
    pub gpe1: Option<EventRegisterPair>,
}

impl FixedAcpiDescription {
    pub fn parse(bytes: &[u8]) -> Result<Self, AcpiError> {
        let header = validate_sdt(bytes)?;
        if header.signature != FADT_SIGNATURE {
            return Err(AcpiError::InvalidSignature);
        }
        let table = &bytes[..header.length as usize];
        let sci_interrupt = read_u16(table, 46)?;
        if sci_interrupt == 0 {
            return Err(AcpiError::MissingSciInterrupt);
        }
        let legacy_dsdt = read_u32(table, 40)? as u64;
        let extended_dsdt = read_optional_u64(table, 140).unwrap_or(0);
        let dsdt_address = if extended_dsdt != 0 {
            extended_dsdt
        } else {
            legacy_dsdt
        };
        if dsdt_address == 0 {
            return Err(AcpiError::NullTableAddress);
        }

        let pm1_event_len = read_u8(table, 88)?;
        let gpe0_len = read_u8(table, 92)?;
        let gpe1_len = read_u8(table, 93)?;
        let gpe1_base = read_u8(table, 94)?;
        let pm1a_event = parse_event_pair(table, 56, 148, pm1_event_len, 0)?;
        let pm1b_event = parse_event_pair(table, 60, 160, pm1_event_len, 0)?;
        let gpe0 = parse_event_pair(table, 80, 220, gpe0_len, 0)?;
        let gpe1 = parse_event_pair(table, 84, 232, gpe1_len, gpe1_base)?;

        Ok(Self {
            revision: header.revision,
            sci_interrupt,
            dsdt_address,
            pm1a_event,
            pm1b_event,
            gpe0,
            gpe1,
        })
    }
}

fn parse_event_pair(
    table: &[u8],
    legacy_offset: usize,
    extended_offset: usize,
    length: u8,
    base_event: u8,
) -> Result<Option<EventRegisterPair>, AcpiError> {
    if length == 0 {
        return Ok(None);
    }
    let extended = (extended_offset + 12 <= table.len())
        .then(|| GenericAddress::parse(table, extended_offset))
        .transpose()?;
    let block = if let Some(address) = extended.filter(|address| address.address != 0) {
        if !matches!(
            address.address_space,
            ADDRESS_SPACE_SYSTEM_MEMORY | ADDRESS_SPACE_SYSTEM_IO
        ) {
            return Err(AcpiError::UnsupportedAddressSpace(address.address_space));
        }
        if address.bit_offset != 0 || address.bit_width != 0 && address.bit_width != length * 8 {
            return Err(AcpiError::InvalidRegisterBlock);
        }
        RegisterBlock {
            address_space: address.address_space,
            address: address.address,
            length,
        }
    } else {
        let address = read_u32(table, legacy_offset)? as u64;
        if address == 0 {
            return Ok(None);
        }
        RegisterBlock {
            address_space: ADDRESS_SPACE_SYSTEM_IO,
            address,
            length,
        }
    };
    let (status, enable) = block.split_status_enable()?;
    Ok(Some(EventRegisterPair {
        status,
        enable,
        base_event,
    }))
}

pub fn active_event_bits(status: &[u8], enable: &[u8]) -> Result<Vec<u16>, AcpiError> {
    if status.len() != enable.len() {
        return Err(AcpiError::InvalidRegisterBlock);
    }
    let mut active = Vec::new();
    active
        .try_reserve_exact(status.len().saturating_mul(8))
        .map_err(|_| AcpiError::Allocation)?;
    for (byte_index, (&status, &enable)) in status.iter().zip(enable).enumerate() {
        let mut bits = status & enable;
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            let event = byte_index
                .checked_mul(8)
                .and_then(|base| base.checked_add(bit))
                .and_then(|event| u16::try_from(event).ok())
                .ok_or(AcpiError::InvalidRegisterBlock)?;
            active.push(event);
            bits &= !(1 << bit);
        }
    }
    Ok(active)
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, AcpiError> {
    bytes.get(offset).copied().ok_or(AcpiError::Truncated)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AcpiError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(AcpiError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(AcpiError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AcpiError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(AcpiError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_optional_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .map(|value| u64::from_le_bytes(value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn finish_table(mut table: Vec<u8>, signature: &[u8; 4]) -> Vec<u8> {
        table[0..4].copy_from_slice(signature);
        let length = table.len() as u32;
        table[4..8].copy_from_slice(&length.to_le_bytes());
        table[8] = 6;
        table[9] = 0;
        let sum = table.iter().copied().fold(0u8, u8::wrapping_add);
        table[9] = 0u8.wrapping_sub(sum);
        table
    }

    fn write_u16(table: &mut [u8], offset: usize, value: u16) {
        table[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(table: &mut [u8], offset: usize, value: u32) {
        table[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(table: &mut [u8], offset: usize, value: u64) {
        table[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_gas(table: &mut [u8], offset: usize, space: u8, width: u8, address: u64) {
        table[offset] = space;
        table[offset + 1] = width;
        table[offset + 2] = 0;
        table[offset + 3] = 1;
        write_u64(table, offset + 4, address);
    }

    #[test]
    fn xsdt_entries_are_checked_and_preserve_physical_addresses() {
        let mut xsdt = vec![0; SDT_HEADER_LEN + 16];
        write_u64(&mut xsdt, SDT_HEADER_LEN, 0x7ffe_1000);
        write_u64(&mut xsdt, SDT_HEADER_LEN + 8, 0x7ffe_3000);
        let root = AcpiRootTable::parse(&finish_table(xsdt, b"XSDT")).unwrap();
        assert_eq!(root.entries, vec![0x7ffe_1000, 0x7ffe_3000]);
    }

    #[test]
    fn fadt_prefers_extended_blocks_and_splits_status_from_enable() {
        let mut fadt = vec![0; 244];
        write_u16(&mut fadt, 46, 9);
        write_u32(&mut fadt, 40, 0x1234_5000);
        write_u64(&mut fadt, 140, 0x1_2345_6000);
        fadt[88] = 4;
        fadt[92] = 8;
        fadt[93] = 4;
        fadt[94] = 32;
        write_gas(&mut fadt, 148, ADDRESS_SPACE_SYSTEM_IO, 32, 0x600);
        write_gas(&mut fadt, 220, ADDRESS_SPACE_SYSTEM_MEMORY, 64, 0xfed8_0000);
        write_gas(&mut fadt, 232, ADDRESS_SPACE_SYSTEM_IO, 32, 0x620);
        let parsed = FixedAcpiDescription::parse(&finish_table(fadt, b"FACP")).unwrap();
        assert_eq!(parsed.sci_interrupt, 9);
        assert_eq!(parsed.dsdt_address, 0x1_2345_6000);
        assert_eq!(parsed.pm1a_event.unwrap().status.length, 2);
        assert_eq!(parsed.pm1a_event.unwrap().enable.address, 0x602);
        assert_eq!(
            parsed.gpe0.unwrap().status.address_space,
            ADDRESS_SPACE_SYSTEM_MEMORY
        );
        assert_eq!(parsed.gpe0.unwrap().enable.address, 0xfed8_0004);
        assert_eq!(parsed.gpe1.unwrap().base_event, 32);
    }

    #[test]
    fn fadt_uses_legacy_io_blocks_when_extended_addresses_are_absent() {
        let mut fadt = vec![0; 116];
        write_u16(&mut fadt, 46, 9);
        write_u32(&mut fadt, 40, 0x7ffe_4000);
        write_u32(&mut fadt, 56, 0x600);
        write_u32(&mut fadt, 80, 0x620);
        fadt[88] = 4;
        fadt[92] = 8;
        let parsed = FixedAcpiDescription::parse(&finish_table(fadt, b"FACP")).unwrap();
        assert_eq!(parsed.pm1a_event.unwrap().enable.address, 0x602);
        assert_eq!(parsed.gpe0.unwrap().enable.address, 0x624);
        assert!(parsed.gpe1.is_none());
    }

    #[test]
    fn active_event_bits_require_both_status_and_enable() {
        assert_eq!(
            active_event_bits(&[0b1010_0100], &[0b1110_0001]).unwrap(),
            vec![5, 7]
        );
        assert_eq!(
            active_event_bits(&[0], &[0, 0]),
            Err(AcpiError::InvalidRegisterBlock)
        );
    }

    #[test]
    fn checksum_and_register_shapes_fail_closed() {
        let mut bad = finish_table(vec![0; SDT_HEADER_LEN], b"XSDT");
        bad[12] ^= 1;
        assert_eq!(validate_sdt(&bad), Err(AcpiError::InvalidChecksum));

        let block = RegisterBlock {
            address_space: ADDRESS_SPACE_SYSTEM_IO,
            address: 0x600,
            length: 3,
        };
        assert_eq!(
            block.split_status_enable(),
            Err(AcpiError::InvalidRegisterBlock)
        );
    }
}
