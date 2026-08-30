//! Checked decoding of ACPI MADT interrupt-source overrides.

use alloc::vec::Vec;

use crate::{validate_sdt, LegacyIrqOverride, MADT_SIGNATURE, SDT_HEADER_LEN};

const MADT_FIXED_BODY_LEN: usize = 8;
const MADT_ENTRY_HEADER_LEN: usize = 2;
const MADT_INTERRUPT_SOURCE_OVERRIDE: u8 = 2;
const MADT_INTERRUPT_SOURCE_OVERRIDE_LEN: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadtError {
    InvalidTable,
    TruncatedEntry,
    InvalidEntry,
    DuplicateInterruptOverride,
    Allocation,
}

/// Decode the ISA interrupt-source overrides from a validated Multiple APIC Description Table.
///
/// Bus-conforming polarity/trigger values remain `None`; the consuming bus resource supplies those
/// electrical attributes. Explicit MADT values are retained and must agree with that resource
/// before a physical route can be published.
pub fn parse_madt_interrupt_overrides(bytes: &[u8]) -> Result<Vec<LegacyIrqOverride>, MadtError> {
    let header = validate_sdt(bytes).map_err(|_| MadtError::InvalidTable)?;
    let table_len = header.length as usize;
    let entries_start = SDT_HEADER_LEN
        .checked_add(MADT_FIXED_BODY_LEN)
        .ok_or(MadtError::InvalidTable)?;
    if header.signature != MADT_SIGNATURE || table_len < entries_start {
        return Err(MadtError::InvalidTable);
    }
    let flags = read_u32(bytes, SDT_HEADER_LEN + 4)?;
    if flags & !1 != 0 {
        return Err(MadtError::InvalidTable);
    }

    let mut overrides = Vec::new();
    let mut cursor = entries_start;
    while cursor < table_len {
        let kind = *bytes.get(cursor).ok_or(MadtError::TruncatedEntry)?;
        let length = *bytes.get(cursor + 1).ok_or(MadtError::TruncatedEntry)? as usize;
        if length < MADT_ENTRY_HEADER_LEN {
            return Err(MadtError::InvalidEntry);
        }
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= table_len)
            .ok_or(MadtError::TruncatedEntry)?;
        if kind == MADT_INTERRUPT_SOURCE_OVERRIDE {
            if length != MADT_INTERRUPT_SOURCE_OVERRIDE_LEN || bytes[cursor + 2] != 0 {
                return Err(MadtError::InvalidEntry);
            }
            let irq = bytes[cursor + 3];
            if irq >= 16 {
                return Err(MadtError::InvalidEntry);
            }
            let gsi = read_u32(bytes, cursor + 4)?;
            let flags = read_u16(bytes, cursor + 8)?;
            if flags & !0x000f != 0 {
                return Err(MadtError::InvalidEntry);
            }
            let active_low = decode_polarity(flags & 0x0003)?;
            let level_sensitive = decode_trigger((flags >> 2) & 0x0003)?;
            if overrides
                .iter()
                .any(|existing: &LegacyIrqOverride| existing.irq == irq || existing.gsi == gsi)
            {
                return Err(MadtError::DuplicateInterruptOverride);
            }
            overrides
                .try_reserve(1)
                .map_err(|_| MadtError::Allocation)?;
            overrides.push(LegacyIrqOverride {
                irq,
                gsi,
                level_sensitive,
                active_low,
            });
        }
        cursor = end;
    }
    Ok(overrides)
}

fn decode_polarity(value: u16) -> Result<Option<bool>, MadtError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(false)),
        3 => Ok(Some(true)),
        _ => Err(MadtError::InvalidEntry),
    }
}

fn decode_trigger(value: u16) -> Result<Option<bool>, MadtError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(false)),
        3 => Ok(Some(true)),
        _ => Err(MadtError::InvalidEntry),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, MadtError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(MadtError::TruncatedEntry)?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, MadtError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(MadtError::TruncatedEntry)?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn madt(entries: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; SDT_HEADER_LEN + MADT_FIXED_BODY_LEN];
        bytes[..4].copy_from_slice(b"APIC");
        bytes[8] = 5;
        bytes[SDT_HEADER_LEN + 4..SDT_HEADER_LEN + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(entries);
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[9] = 0u8.wrapping_sub(bytes.iter().copied().fold(0u8, u8::wrapping_add));
        bytes
    }

    fn iso(irq: u8, gsi: u32, flags: u16) -> [u8; 10] {
        let mut bytes = [2, 10, 0, irq, 0, 0, 0, 0, 0, 0];
        bytes[4..8].copy_from_slice(&gsi.to_le_bytes());
        bytes[8..10].copy_from_slice(&flags.to_le_bytes());
        bytes
    }

    #[test]
    fn interrupt_overrides_preserve_explicit_and_conforming_attributes() {
        let mut entries = vec![0, 8, 0, 0, 1, 0, 0, 0];
        entries.extend_from_slice(&iso(0, 2, 0x0005));
        entries.extend_from_slice(&iso(9, 20, 0));
        assert_eq!(
            parse_madt_interrupt_overrides(&madt(&entries)).unwrap(),
            vec![
                LegacyIrqOverride {
                    irq: 0,
                    gsi: 2,
                    level_sensitive: Some(false),
                    active_low: Some(false),
                },
                LegacyIrqOverride {
                    irq: 9,
                    gsi: 20,
                    level_sensitive: None,
                    active_low: None,
                },
            ]
        );
    }

    #[test]
    fn malformed_and_ambiguous_overrides_fail_closed() {
        let mut duplicate = iso(0, 2, 0).to_vec();
        duplicate.extend_from_slice(&iso(0, 3, 0));
        assert_eq!(
            parse_madt_interrupt_overrides(&madt(&duplicate)),
            Err(MadtError::DuplicateInterruptOverride)
        );
        assert_eq!(
            parse_madt_interrupt_overrides(&madt(&iso(16, 20, 0))),
            Err(MadtError::InvalidEntry)
        );
        assert_eq!(
            parse_madt_interrupt_overrides(&madt(&iso(1, 20, 0x0002))),
            Err(MadtError::InvalidEntry)
        );
        assert_eq!(
            parse_madt_interrupt_overrides(&madt(&[2, 10, 0, 1])),
            Err(MadtError::TruncatedEntry)
        );
    }
}
