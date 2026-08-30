//! Checked decoding of ACPI MADT interrupt-controller topology.

use alloc::vec::Vec;

use crate::{validate_sdt, LegacyIrqOverride, MADT_SIGNATURE, SDT_HEADER_LEN};

const MADT_FIXED_BODY_LEN: usize = 8;
const MADT_ENTRY_HEADER_LEN: usize = 2;
const MADT_LOCAL_APIC: u8 = 0;
const MADT_LOCAL_APIC_LEN: usize = 8;
const MADT_IO_APIC: u8 = 1;
const MADT_IO_APIC_LEN: usize = 12;
const MADT_INTERRUPT_SOURCE_OVERRIDE: u8 = 2;
const MADT_INTERRUPT_SOURCE_OVERRIDE_LEN: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadtError {
    InvalidTable,
    TruncatedEntry,
    InvalidEntry,
    MissingIoApic,
    DuplicateIoApic,
    DuplicateInterruptOverride,
    Allocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MadtIoApic {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MadtInterruptTopology {
    pub io_apics: Vec<MadtIoApic>,
    pub interrupt_overrides: Vec<LegacyIrqOverride>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoApicRouteExtent {
    pub gsi_base: u32,
    pub redirection_entries: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedIoApicRoute {
    pub controller_ordinal: u16,
    pub local_pin: u16,
    pub gsi: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoApicRouteError {
    TopologyMismatch,
    InvalidExtent,
    UnroutableGsi,
    AmbiguousGsi,
}

pub fn validate_ioapic_route_extents(
    firmware: &[MadtIoApic],
    hardware: &[IoApicRouteExtent],
) -> Result<(), IoApicRouteError> {
    if firmware.is_empty() || firmware.len() != hardware.len() || hardware.len() > u16::MAX as usize
    {
        return Err(IoApicRouteError::TopologyMismatch);
    }
    for (left_index, (madt, left)) in firmware.iter().zip(hardware).enumerate() {
        if madt.gsi_base != left.gsi_base || left.redirection_entries == 0 {
            return Err(IoApicRouteError::TopologyMismatch);
        }
        let left_end = left
            .gsi_base
            .checked_add(left.redirection_entries as u32)
            .ok_or(IoApicRouteError::InvalidExtent)?;
        for right in &hardware[left_index + 1..] {
            let right_end = right
                .gsi_base
                .checked_add(right.redirection_entries as u32)
                .ok_or(IoApicRouteError::InvalidExtent)?;
            if left.gsi_base < right_end && right.gsi_base < left_end {
                return Err(IoApicRouteError::InvalidExtent);
            }
        }
    }
    Ok(())
}

pub fn resolve_ioapic_gsi(
    hardware: &[IoApicRouteExtent],
    gsi: u32,
) -> Result<ResolvedIoApicRoute, IoApicRouteError> {
    let mut resolved = None;
    for (ordinal, controller) in hardware.iter().enumerate() {
        if controller.redirection_entries == 0 || ordinal > u16::MAX as usize {
            return Err(IoApicRouteError::InvalidExtent);
        }
        let end = controller
            .gsi_base
            .checked_add(controller.redirection_entries as u32)
            .ok_or(IoApicRouteError::InvalidExtent)?;
        if gsi < controller.gsi_base || gsi >= end {
            continue;
        }
        if resolved.is_some() {
            return Err(IoApicRouteError::AmbiguousGsi);
        }
        resolved = Some(ResolvedIoApicRoute {
            controller_ordinal: ordinal as u16,
            local_pin: (gsi - controller.gsi_base) as u16,
            gsi,
        });
    }
    resolved.ok_or(IoApicRouteError::UnroutableGsi)
}

/// Decode the IOAPIC catalog and ISA interrupt-source overrides from a validated MADT.
///
/// Bus-conforming polarity/trigger values remain `None`; the consuming bus resource supplies those
/// electrical attributes. Explicit MADT values are retained and must agree with that resource
/// before a physical route can be published.
pub fn parse_madt_interrupt_topology(bytes: &[u8]) -> Result<MadtInterruptTopology, MadtError> {
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

    let mut io_apics = Vec::new();
    let mut interrupt_overrides = Vec::new();
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
        match kind {
            MADT_LOCAL_APIC => {
                if length != MADT_LOCAL_APIC_LEN || read_u32(bytes, cursor + 4)? & !0x3 != 0 {
                    return Err(MadtError::InvalidEntry);
                }
            }
            MADT_IO_APIC => {
                if length != MADT_IO_APIC_LEN || bytes[cursor + 3] != 0 {
                    return Err(MadtError::InvalidEntry);
                }
                let id = bytes[cursor + 2];
                let address = read_u32(bytes, cursor + 4)?;
                let gsi_base = read_u32(bytes, cursor + 8)?;
                if id > 0x0f || address == 0 || address & 0x0fff != 0 {
                    return Err(MadtError::InvalidEntry);
                }
                if io_apics.iter().any(|existing: &MadtIoApic| {
                    existing.id == id
                        || existing.address == address
                        || existing.gsi_base == gsi_base
                }) {
                    return Err(MadtError::DuplicateIoApic);
                }
                io_apics.try_reserve(1).map_err(|_| MadtError::Allocation)?;
                io_apics.push(MadtIoApic {
                    id,
                    address,
                    gsi_base,
                });
            }
            MADT_INTERRUPT_SOURCE_OVERRIDE => {
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
                if interrupt_overrides
                    .iter()
                    .any(|existing: &LegacyIrqOverride| existing.irq == irq || existing.gsi == gsi)
                {
                    return Err(MadtError::DuplicateInterruptOverride);
                }
                interrupt_overrides
                    .try_reserve(1)
                    .map_err(|_| MadtError::Allocation)?;
                interrupt_overrides.push(LegacyIrqOverride {
                    irq,
                    gsi,
                    level_sensitive,
                    active_low,
                });
            }
            _ => {}
        }
        cursor = end;
    }
    if io_apics.is_empty() {
        return Err(MadtError::MissingIoApic);
    }
    Ok(MadtInterruptTopology {
        io_apics,
        interrupt_overrides,
    })
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

    fn ioapic(id: u8, address: u32, gsi_base: u32) -> [u8; 12] {
        let mut bytes = [1, 12, id, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes[4..8].copy_from_slice(&address.to_le_bytes());
        bytes[8..12].copy_from_slice(&gsi_base.to_le_bytes());
        bytes
    }

    #[test]
    fn interrupt_overrides_preserve_explicit_and_conforming_attributes() {
        let mut entries = vec![0, 8, 0, 0, 1, 0, 0, 0];
        entries.extend_from_slice(&ioapic(0, 0xfec0_0000, 0));
        entries.extend_from_slice(&ioapic(1, 0xfec0_1000, 24));
        entries.extend_from_slice(&iso(0, 2, 0x0005));
        entries.extend_from_slice(&iso(9, 20, 0));
        let topology = parse_madt_interrupt_topology(&madt(&entries)).unwrap();
        assert_eq!(
            topology.io_apics,
            vec![
                MadtIoApic {
                    id: 0,
                    address: 0xfec0_0000,
                    gsi_base: 0,
                },
                MadtIoApic {
                    id: 1,
                    address: 0xfec0_1000,
                    gsi_base: 24,
                },
            ]
        );
        assert_eq!(
            topology.interrupt_overrides,
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
        let mut duplicate = ioapic(0, 0xfec0_0000, 0).to_vec();
        duplicate.extend_from_slice(&iso(0, 2, 0));
        duplicate.extend_from_slice(&iso(0, 3, 0));
        assert_eq!(
            parse_madt_interrupt_topology(&madt(&duplicate)),
            Err(MadtError::DuplicateInterruptOverride)
        );
        let mut bad = ioapic(0, 0xfec0_0000, 0).to_vec();
        bad.extend_from_slice(&iso(16, 20, 0));
        assert_eq!(
            parse_madt_interrupt_topology(&madt(&bad)),
            Err(MadtError::InvalidEntry)
        );
        let mut bad = ioapic(0, 0xfec0_0000, 0).to_vec();
        bad.extend_from_slice(&iso(1, 20, 0x0002));
        assert_eq!(
            parse_madt_interrupt_topology(&madt(&bad)),
            Err(MadtError::InvalidEntry)
        );
        let mut bad = ioapic(0, 0xfec0_0000, 0).to_vec();
        bad.extend_from_slice(&[2, 10, 0, 1]);
        assert_eq!(
            parse_madt_interrupt_topology(&madt(&bad)),
            Err(MadtError::TruncatedEntry)
        );
    }

    #[test]
    fn missing_duplicate_and_malformed_ioapics_fail_closed() {
        assert_eq!(
            parse_madt_interrupt_topology(&madt(&[0, 8, 0, 0, 1, 0, 0, 0])),
            Err(MadtError::MissingIoApic)
        );
        let mut duplicate = ioapic(0, 0xfec0_0000, 0).to_vec();
        duplicate.extend_from_slice(&ioapic(1, 0xfec0_1000, 0));
        assert_eq!(
            parse_madt_interrupt_topology(&madt(&duplicate)),
            Err(MadtError::DuplicateIoApic)
        );
        assert_eq!(
            parse_madt_interrupt_topology(&madt(&ioapic(16, 0xfec0_0000, 0))),
            Err(MadtError::InvalidEntry)
        );
    }

    #[test]
    fn hardware_extents_resolve_sparse_multi_controller_gsis() {
        let firmware = [
            MadtIoApic {
                id: 0,
                address: 0xfec0_0000,
                gsi_base: 0,
            },
            MadtIoApic {
                id: 1,
                address: 0xfec0_1000,
                gsi_base: 48,
            },
        ];
        let hardware = [
            IoApicRouteExtent {
                gsi_base: 0,
                redirection_entries: 24,
            },
            IoApicRouteExtent {
                gsi_base: 48,
                redirection_entries: 32,
            },
        ];
        validate_ioapic_route_extents(&firmware, &hardware).unwrap();
        assert_eq!(
            resolve_ioapic_gsi(&hardware, 63),
            Ok(ResolvedIoApicRoute {
                controller_ordinal: 1,
                local_pin: 15,
                gsi: 63,
            })
        );
        assert_eq!(
            resolve_ioapic_gsi(&hardware, 24),
            Err(IoApicRouteError::UnroutableGsi)
        );

        let overlap = [
            hardware[0],
            IoApicRouteExtent {
                gsi_base: 16,
                redirection_entries: 24,
            },
        ];
        assert_eq!(
            resolve_ioapic_gsi(&overlap, 20),
            Err(IoApicRouteError::AmbiguousGsi)
        );
    }
}
