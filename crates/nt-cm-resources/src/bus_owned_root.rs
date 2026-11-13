use alloc::vec::Vec;

use super::{
    select_complete_io_resource_assignment, validate_cm_resource_list_extent,
    validate_io_resource_requirements_list_extent, BusNumberDescriptor, CmResourceDescriptor,
    InterruptDescriptor, IoResourceAssignmentError, MemoryDescriptor, MemoryLargeDescriptor,
    NativeResourceListError,
    PortDescriptor, CM_RESOURCE_TYPE_BUS_NUMBER, CM_RESOURCE_TYPE_DEVICE_PRIVATE,
    CM_RESOURCE_TYPE_INTERRUPT, CM_RESOURCE_TYPE_MEMORY, CM_RESOURCE_TYPE_MEMORY_LARGE,
    CM_RESOURCE_TYPE_PORT,
    IO_RESOURCE_REQUIREMENTS_FIXED_SIZE, PARTIAL_DESCRIPTOR_SIZE,
};

/// Failure to adopt a bus PDO's current assignment. The caller must not invent a replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusOwnedRootResourceError {
    Malformed(NativeResourceListError),
    UnsupportedDescriptor,
    UnsatisfiedRequirements,
    OutOfMemory,
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, BusOwnedRootResourceError> {
    super::read_u32(bytes, offset).map_err(BusOwnedRootResourceError::Malformed)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, BusOwnedRootResourceError> {
    super::read_u64(bytes, offset).map_err(BusOwnedRootResourceError::Malformed)
}

/// Validate a bus-owned PCI-root current assignment against the provider's possible resources.
///
/// The native ACPI provider places parent-address translation data in a DevicePrivate partial
/// descriptor directly after each translated address window (NT ACPI res_bios.c/translate.c).
/// Preserve the provider's descriptor order and metadata, changing only the corresponding
/// address in the translated START list. A bare or ambiguous translation is rejected.
pub fn admit_bus_owned_root_resources(
    raw: &[u8],
    requirements: &[u8],
    published_bus_number: u32,
) -> Result<Vec<u8>, BusOwnedRootResourceError> {
    if validate_cm_resource_list_extent(raw).map_err(BusOwnedRootResourceError::Malformed)? != raw.len()
        || validate_io_resource_requirements_list_extent(requirements)
            .map_err(BusOwnedRootResourceError::Malformed)? != requirements.len()
        || u32_at(raw, 0)? != 1
        || u32_at(raw, 8)? != published_bus_number
        || u32_at(requirements, 4)? != u32_at(raw, 4)?
        || u32_at(requirements, 8)? != published_bus_number
        || u32_at(requirements, 12)? != 0
        || requirements.len() < IO_RESOURCE_REQUIREMENTS_FIXED_SIZE
    {
        return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
    }
    let count = u32_at(raw, 16)? as usize;
    let mut translated = Vec::new();
    translated.try_reserve_exact(raw.len())
        .map_err(|_| BusOwnedRootResourceError::OutOfMemory)?;
    translated.extend_from_slice(raw);
    let mut candidates = Vec::new();
    candidates.try_reserve_exact(count)
        .map_err(|_| BusOwnedRootResourceError::OutOfMemory)?;
    let mut bus_count = 0usize;
    let mut previous_address = None;
    for index in 0..count {
        let offset = 20 + index * PARTIAL_DESCRIPTOR_SIZE;
        let resource_type = raw[offset];
        let share = raw[offset + 1];
        let flags = u16::from_le_bytes([raw[offset + 2], raw[offset + 3]]);
        match resource_type {
            CM_RESOURCE_TYPE_BUS_NUMBER => {
                let start = u32_at(raw, offset + 4)?;
                let length = u32_at(raw, offset + 8)?;
                if length == 0 || !start.checked_add(length)
                    .is_some_and(|end| (start..end).contains(&published_bus_number))
                {
                    return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
                }
                bus_count += 1;
                candidates.push(CmResourceDescriptor::BusNumber(BusNumberDescriptor {
                    start, length, flags, share,
                }));
                previous_address = None;
            }
            CM_RESOURCE_TYPE_MEMORY | CM_RESOURCE_TYPE_PORT => {
                let start = u64_at(raw, offset + 4)?;
                let length = u32_at(raw, offset + 12)?;
                if length == 0 || start.checked_add(u64::from(length) - 1).is_none() {
                    return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
                }
                if resource_type == CM_RESOURCE_TYPE_MEMORY {
                    candidates.push(CmResourceDescriptor::Memory(MemoryDescriptor {
                        start, length, flags, share,
                    }));
                } else {
                    candidates.push(CmResourceDescriptor::Port(PortDescriptor {
                        start, length, flags, share,
                    }));
                }
                previous_address = Some((offset, resource_type, u64::from(length)));
            }
            CM_RESOURCE_TYPE_MEMORY_LARGE => {
                let start = u64_at(raw, offset + 4)?;
                let shift = super::memory_large_shift(flags)
                    .ok_or(BusOwnedRootResourceError::UnsupportedDescriptor)?;
                let length = u64::from(u32_at(raw, offset + 12)?) << shift;
                if length == 0 || start.checked_add(length - 1).is_none() {
                    return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
                }
                candidates.push(CmResourceDescriptor::MemoryLarge(MemoryLargeDescriptor {
                    start, length, flags, share,
                }));
                previous_address = Some((offset, resource_type, length));
            }
            CM_RESOURCE_TYPE_INTERRUPT => {
                candidates.push(CmResourceDescriptor::Interrupt(InterruptDescriptor {
                    level: u32_at(raw, offset + 4)?,
                    vector: u32_at(raw, offset + 8)?,
                    affinity: u64_at(raw, offset + 12)?, flags, share,
                }));
                previous_address = None;
            }
            CM_RESOURCE_TYPE_DEVICE_PRIVATE => {
                if flags == 0x6000 {
                    let Some((parent_offset, parent_type, length)) = previous_address.take() else {
                        return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
                    };
                    if u32_at(raw, offset + 4)? != u32::from(parent_type) {
                        return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
                    }
                    let translated_start = u64::from(u32_at(raw, offset + 8)?)
                        | (u64::from(u32_at(raw, offset + 12)?) << 32);
                    if translated_start.checked_add(length - 1).is_none() {
                        return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
                    }
                    translated[parent_offset + 4..parent_offset + 12]
                        .copy_from_slice(&translated_start.to_le_bytes());
                } else if flags == 1 {
                    previous_address = None;
                } else {
                    return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
                }
            }
            _ => return Err(BusOwnedRootResourceError::UnsupportedDescriptor),
        }
    }
    if bus_count != 1 {
        return Err(BusOwnedRootResourceError::UnsupportedDescriptor);
    }
    match select_complete_io_resource_assignment(
        requirements,
        u32_at(raw, 4)? as i32,
        published_bus_number,
        0,
        &candidates,
    ) {
        Ok(Some(_)) => Ok(translated),
        Ok(None) => Err(BusOwnedRootResourceError::UnsatisfiedRequirements),
        Err(IoResourceAssignmentError::OutOfMemory) => Err(BusOwnedRootResourceError::OutOfMemory),
        Err(IoResourceAssignmentError::Malformed(error)) => Err(BusOwnedRootResourceError::Malformed(error)),
        Err(_) => Err(BusOwnedRootResourceError::UnsupportedDescriptor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn provider_pair() -> (Vec<u8>, Vec<u8>) {
        // LiberNT ACPI PCI roots publish BusNumber, then each address window followed by
        // DevicePrivate parent-address data and an end marker (buspdo.c / NT translate.c).
        let mut raw = alloc::vec![0u8; 100];
        w32(&mut raw, 0, 1);
        w32(&mut raw, 4, 5); // PCIBus
        w32(&mut raw, 8, 0);
        w32(&mut raw, 16, 4);
        raw[20] = CM_RESOURCE_TYPE_BUS_NUMBER;
        raw[21] = 1;
        w32(&mut raw, 24, 0);
        w32(&mut raw, 28, 1);
        raw[40] = CM_RESOURCE_TYPE_PORT;
        raw[41] = 1;
        w32(&mut raw, 44, 0x2000);
        w32(&mut raw, 52, 0x100);
        raw[60] = CM_RESOURCE_TYPE_DEVICE_PRIVATE;
        raw[62..64].copy_from_slice(&0x6000u16.to_le_bytes());
        w32(&mut raw, 64, u32::from(CM_RESOURCE_TYPE_PORT));
        w32(&mut raw, 68, 0x3000);
        raw[80] = CM_RESOURCE_TYPE_DEVICE_PRIVATE;
        raw[82..84].copy_from_slice(&1u16.to_le_bytes());

        let mut req = alloc::vec![0u8; 104];
        w32(&mut req, 0, 104);
        w32(&mut req, 4, 5);
        w32(&mut req, 8, 0);
        w32(&mut req, 28, 1);
        w32(&mut req, 36, 2);
        req[40] = 0; // required
        req[41] = CM_RESOURCE_TYPE_BUS_NUMBER;
        req[42] = 1;
        w32(&mut req, 48, 1); // length
        w32(&mut req, 52, 0); // minimum
        w32(&mut req, 56, 0); // maximum
        req[72] = 0;
        req[73] = CM_RESOURCE_TYPE_PORT;
        req[74] = 1;
        w32(&mut req, 80, 0x100);
        w32(&mut req, 84, 1);
        w32(&mut req, 88, 0x2000);
        w32(&mut req, 96, 0x20ff);
        (raw, req)
    }

    #[test]
    fn root_assignment_preserves_provider_raw_and_translates_parent_window() {
        let (raw, req) = provider_pair();
        let translated = admit_bus_owned_root_resources(&raw, &req, 0).unwrap();
        assert_eq!(u64::from_le_bytes(translated[44..52].try_into().unwrap()), 0x3000);
        assert_eq!(u64::from_le_bytes(raw[44..52].try_into().unwrap()), 0x2000);
        assert_eq!(&translated[60..], &raw[60..]);
    }

    #[test]
    fn root_assignment_rejects_unmatched_or_unowned_translation() {
        let (raw, mut req) = provider_pair();
        w32(&mut req, 88, 0x3000);
        w32(&mut req, 96, 0x30ff);
        assert_eq!(
            admit_bus_owned_root_resources(&raw, &req, 0),
            Err(BusOwnedRootResourceError::UnsatisfiedRequirements),
        );
        let (mut raw, req) = provider_pair();
        w32(&mut raw, 64, u32::from(CM_RESOURCE_TYPE_MEMORY));
        assert_eq!(
            admit_bus_owned_root_resources(&raw, &req, 0),
            Err(BusOwnedRootResourceError::UnsupportedDescriptor),
        );
    }

    #[test]
    fn released_libernt_pci_root_memory_large_assignment_is_admitted() {
        // Exact 480/296-byte QUERY_RESOURCES / QUERY_RESOURCE_REQUIREMENTS pair captured
        // from released LiberNT acpi.sys during the one-CPU issue-310 diagnostic boot.
        let fixture = include_str!("libernt_pci_root_resources.hex");
        let mut lines = fixture.lines();
        let decode = |hex: &str| -> Vec<u8> {
            hex.as_bytes().chunks_exact(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        let raw = decode(lines.next().unwrap());
        let requirements = decode(lines.next().unwrap());
        assert_eq!((raw.len(), requirements.len()), (480, 296));
        let translated = admit_bus_owned_root_resources(&raw, &requirements, 0).unwrap();
        assert_eq!(translated.len(), 480);
        assert_eq!(&translated[420..440], &raw[420..440]); // MemoryLarge window
    }
}
