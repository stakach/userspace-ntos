//! Validation of resource lists returned by an accepted PCI PDO.

use crate::{Bar, PciDevice, PCI_HEADER_TYPE_DEVICE};
use nt_cm_resources::{
    validate_cm_resource_list_extent, validate_io_resource_requirements_list_extent,
    CM_RESOURCE_INTERRUPT_LATCHED, CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
    CM_RESOURCE_INTERRUPT_MESSAGE, CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN,
    CM_RESOURCE_MEMORY_BAR, CM_RESOURCE_MEMORY_PREFETCHABLE,
    CM_RESOURCE_PORT_16_BIT_DECODE, CM_RESOURCE_PORT_BAR, CM_RESOURCE_PORT_IO,
    CM_RESOURCE_PORT_POSITIVE_DECODE, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, CM_RESOURCE_SHARE_SHARED,
    CM_RESOURCE_TYPE_DEVICE_PRIVATE, CM_RESOURCE_TYPE_INTERRUPT, CM_RESOURCE_TYPE_MEMORY,
    CM_RESOURCE_TYPE_PORT, INTERFACE_TYPE_PCI_BUS, IO_RESOURCE_ALTERNATIVE,
    IO_RESOURCE_DESCRIPTOR_SIZE, IO_RESOURCE_PREFERRED, IO_RESOURCE_REQUIRED,
    IO_RESOURCE_REQUIREMENTS_HEADER_SIZE, PARTIAL_DESCRIPTOR_SIZE,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciBusResourceError {
    UnsupportedDevice,
    Malformed,
    Identity,
    ResourceMismatch,
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, PciBusResourceError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(PciBusResourceError::Malformed)?
            .try_into()
            .unwrap(),
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, PciBusResourceError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(PciBusResourceError::Malformed)?
            .try_into()
            .unwrap(),
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, PciBusResourceError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(PciBusResourceError::Malformed)?
            .try_into()
            .unwrap(),
    ))
}

fn bar_type(bar: &Bar) -> u8 {
    if bar.is_io {
        CM_RESOURCE_TYPE_PORT
    } else {
        CM_RESOURCE_TYPE_MEMORY
    }
}

fn native_flags(bar: &Bar) -> u16 {
    if bar.is_io {
        CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_16_BIT_DECODE | CM_RESOURCE_PORT_POSITIVE_DECODE
    } else if bar.prefetchable {
        CM_RESOURCE_MEMORY_PREFETCHABLE
    } else {
        0
    }
}

fn check_raw_bar(bytes: &[u8], offset: usize, bar: &Bar) -> Result<(), PciBusResourceError> {
    let length = u32::try_from(bar.size).map_err(|_| PciBusResourceError::UnsupportedDevice)?;
    let flags = u16_at(bytes, offset + 2)?;
    let optional_bar_flag = if bar.is_io {
        CM_RESOURCE_PORT_BAR
    } else {
        CM_RESOURCE_MEMORY_BAR
    };
    if bytes[offset] != bar_type(bar)
        || bytes[offset + 1] != CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE
        || flags & !optional_bar_flag != native_flags(bar)
        || u64_at(bytes, offset + 4)? != bar.base
        || u32_at(bytes, offset + 12)? != length
        || u32_at(bytes, offset + 16)? != 0
    {
        return Err(PciBusResourceError::ResourceMismatch);
    }
    Ok(())
}

fn check_requirement_bar(
    bytes: &[u8],
    offset: usize,
    bar: &Bar,
    preferred: bool,
) -> Result<(), PciBusResourceError> {
    let length = u32::try_from(bar.size).map_err(|_| PciBusResourceError::UnsupportedDevice)?;
    let expected_maximum = if preferred {
        bar.base
            .checked_add(bar.size - 1)
            .ok_or(PciBusResourceError::UnsupportedDevice)?
    } else {
        bar.maximum_address
    };
    let optional_bar_flag = if bar.is_io {
        CM_RESOURCE_PORT_BAR
    } else {
        CM_RESOURCE_MEMORY_BAR
    };
    if bytes[offset]
        != if preferred {
            IO_RESOURCE_PREFERRED
        } else {
            IO_RESOURCE_ALTERNATIVE
        }
        || bytes[offset + 1] != bar_type(bar)
        || bytes[offset + 2] != CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE
        || bytes[offset + 3] != 0
        || u16_at(bytes, offset + 4)? & !optional_bar_flag != native_flags(bar)
        || u16_at(bytes, offset + 6)? != 0
        || u32_at(bytes, offset + 8)? != length
        || u32_at(bytes, offset + 12)? != if preferred { 1 } else { length }
        || u64_at(bytes, offset + 16)? != if preferred { bar.base } else { 0 }
        || u64_at(bytes, offset + 24)? != expected_maximum
    {
        return Err(PciBusResourceError::ResourceMismatch);
    }
    Ok(())
}

fn check_raw_private(bytes: &[u8], offset: usize, bar: &Bar) -> Result<(), PciBusResourceError> {
    if bytes[offset] != CM_RESOURCE_TYPE_DEVICE_PRIVATE
        || bytes[offset + 1] != CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE
        || bytes[offset + 2..offset + 4] != [0; 2]
        || u32_at(bytes, offset + 4)? != 1 // PciPrivateBar
        || u32_at(bytes, offset + 8)? != u32::from(bar.index)
        || bytes[offset + 12..offset + PARTIAL_DESCRIPTOR_SIZE] != [0; 8]
    {
        return Err(PciBusResourceError::ResourceMismatch);
    }
    Ok(())
}

fn check_native_requirement_bar(
    bytes: &[u8],
    offset: usize,
    bar: &Bar,
    preferred: bool,
) -> Result<(), PciBusResourceError> {
    let length = u32::try_from(bar.size).map_err(|_| PciBusResourceError::UnsupportedDevice)?;
    let optional_bar_flag = if bar.is_io {
        CM_RESOURCE_PORT_BAR
    } else {
        CM_RESOURCE_MEMORY_BAR
    };
    let minimum = u64_at(bytes, offset + 16)?;
    let maximum = u64_at(bytes, offset + 24)?;
    let alignment = u32_at(bytes, offset + 12)?;
    let preferred_end = bar
        .base
        .checked_add(bar.size - 1)
        .ok_or(PciBusResourceError::UnsupportedDevice)?;
    if bytes[offset]
        != if preferred {
            IO_RESOURCE_PREFERRED
        } else {
            IO_RESOURCE_ALTERNATIVE
        }
        || bytes[offset + 1] != bar_type(bar)
        || bytes[offset + 2] != CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE
        || bytes[offset + 3] != 0
        || u16_at(bytes, offset + 4)? & !optional_bar_flag != native_flags(bar)
        || u16_at(bytes, offset + 6)? != 0
        || u32_at(bytes, offset + 8)? != length
        || alignment == 0
        || minimum
            .checked_add(bar.size - 1)
            .is_none_or(|end| end > maximum)
        || maximum > bar.maximum_address
        || (preferred && (alignment != 1 || minimum != bar.base || maximum != preferred_end))
    {
        return Err(PciBusResourceError::ResourceMismatch);
    }
    Ok(())
}

fn check_native_requirement_private(
    bytes: &[u8],
    offset: usize,
    bar: &Bar,
) -> Result<(), PciBusResourceError> {
    if bytes[offset] != 0
        || bytes[offset + 1] != CM_RESOURCE_TYPE_DEVICE_PRIVATE
        || bytes[offset + 2] != CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE
        || bytes[offset + 3..offset + 8] != [0; 5]
        || u32_at(bytes, offset + 8)? != 1 // PciPrivateBar
        || u32_at(bytes, offset + 12)? != u32::from(bar.index)
        || bytes[offset + 16..offset + IO_RESOURCE_DESCRIPTOR_SIZE] != [0; 16]
    {
        return Err(PciBusResourceError::ResourceMismatch);
    }
    Ok(())
}

/// Bind a native PCI PDO's resource reports to one scanned type-0 function.
/// The raw interrupt line is observational; it does not authorize a routed IRQ grant.
pub fn validate_pci_bus_reported_resources(
    device: &PciDevice,
    raw: &[u8],
    requirements: &[u8],
) -> Result<(), PciBusResourceError> {
    if device.header_type != PCI_HEADER_TYPE_DEVICE
        || device.dev >= 32
        || device.func >= 8
        || device.irq_pin > 4
        || device.bars.len() > 6
        || device
            .bars
            .iter()
            .any(|bar| !bar.is_assigned() || bar.size > u32::MAX as u64)
        || device.bars.iter().enumerate().any(|(index, bar)| {
            bar.index >= 6
                || bar.is_io && bar.is_64bit
                || bar.is_64bit && bar.index == 5
                || index > 0
                    && device.bars[index - 1].index + u8::from(device.bars[index - 1].is_64bit)
                        >= bar.index
        })
    {
        return Err(PciBusResourceError::UnsupportedDevice);
    }
    // InterruptLine may be programmed after the inventory scan. It is an observation, never
    // routing authority; accept a well-formed native raw IRQ without equating the two samples.
    let native_private = !device.bars.is_empty()
        && raw.get(20 + PARTIAL_DESCRIPTOR_SIZE) == Some(&CM_RESOURCE_TYPE_DEVICE_PRIVATE);
    let bar_descriptor_count = device.bars.len() * if native_private { 2 } else { 1 };
    let raw_irq = device.irq_pin != 0
        && raw.len() == 20 + (bar_descriptor_count + 1) * PARTIAL_DESCRIPTOR_SIZE;
    let raw_count = bar_descriptor_count + usize::from(raw_irq);
    if raw_count == 0 {
        if !raw.is_empty() {
            return Err(PciBusResourceError::ResourceMismatch);
        }
    } else {
        if validate_cm_resource_list_extent(raw).map_err(|_| PciBusResourceError::Malformed)?
            != raw.len()
            || raw.len() != 20 + raw_count * PARTIAL_DESCRIPTOR_SIZE
        {
            return Err(PciBusResourceError::Malformed);
        }
        if u32_at(raw, 0)? != 1
            || u32_at(raw, 4)? as i32 != INTERFACE_TYPE_PCI_BUS
            || u32_at(raw, 8)? != device.bus as u32
        {
            return Err(PciBusResourceError::Identity);
        }
        if u16_at(raw, 12)? != 1 || u16_at(raw, 14)? != 1 || u32_at(raw, 16)? as usize != raw_count
        {
            return Err(PciBusResourceError::Malformed);
        }
        for (index, bar) in device.bars.iter().enumerate() {
            let offset =
                20 + index * (if native_private { 2 } else { 1 }) * PARTIAL_DESCRIPTOR_SIZE;
            check_raw_bar(raw, offset, bar)?;
            if native_private {
                check_raw_private(raw, offset + PARTIAL_DESCRIPTOR_SIZE, bar)?;
            }
        }
        if raw_irq {
            let offset = 20 + bar_descriptor_count * PARTIAL_DESCRIPTOR_SIZE;
            if raw[offset] != CM_RESOURCE_TYPE_INTERRUPT
                || raw[offset + 1] != CM_RESOURCE_SHARE_SHARED
                || u16_at(raw, offset + 2)? != CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
                || !matches!(u32_at(raw, offset + 4)?, 1..=254)
                || u32_at(raw, offset + 8)? != u32_at(raw, offset + 4)?
                || u64_at(raw, offset + 12)? != 0xffff_ffff
            {
                return Err(PciBusResourceError::ResourceMismatch);
            }
        }
    }

    let requirement_count = device.bars.len() * 2 + usize::from(device.irq_pin != 0);
    if requirement_count == 0 {
        return if requirements.is_empty() {
            Ok(())
        } else {
            Err(PciBusResourceError::ResourceMismatch)
        };
    }
    if validate_io_resource_requirements_list_extent(requirements)
        .map_err(|_| PciBusResourceError::Malformed)?
        != requirements.len()
    {
        return Err(PciBusResourceError::Malformed);
    }
    let native_requirements = native_private;
    if !native_requirements
        && requirements.len()
            != IO_RESOURCE_REQUIREMENTS_HEADER_SIZE
                + requirement_count * IO_RESOURCE_DESCRIPTOR_SIZE
    {
        return Err(PciBusResourceError::Malformed);
    }
    if u32_at(requirements, 4)? as i32 != INTERFACE_TYPE_PCI_BUS
        || u32_at(requirements, 8)? != device.bus as u32
        || u32_at(requirements, 12)? != device.slot_number()
    {
        return Err(PciBusResourceError::Identity);
    }
    if requirements[16..28].iter().any(|byte| *byte != 0)
        || u32_at(requirements, 28)? != 1
        || u16_at(requirements, 32)? != 1
        || u16_at(requirements, 34)? != 1
        || (!native_requirements && u32_at(requirements, 36)? as usize != requirement_count)
    {
        return Err(PciBusResourceError::Malformed);
    }
    let mut descriptor_index = 0;
    let declared_count = u32_at(requirements, 36)? as usize;
    for bar in &device.bars {
        let offset =
            IO_RESOURCE_REQUIREMENTS_HEADER_SIZE + descriptor_index * IO_RESOURCE_DESCRIPTOR_SIZE;
        if native_requirements {
            check_native_requirement_bar(requirements, offset, bar, true)?;
            descriptor_index += 1;
            let mut alternatives = 0;
            while descriptor_index < declared_count {
                let offset = IO_RESOURCE_REQUIREMENTS_HEADER_SIZE
                    + descriptor_index * IO_RESOURCE_DESCRIPTOR_SIZE;
                if requirements[offset + 1] == CM_RESOURCE_TYPE_DEVICE_PRIVATE {
                    break;
                }
                check_native_requirement_bar(requirements, offset, bar, false)?;
                alternatives += 1;
                if alternatives > 8 {
                    return Err(PciBusResourceError::ResourceMismatch);
                }
                descriptor_index += 1;
            }
            if alternatives == 0 || descriptor_index >= declared_count {
                return Err(PciBusResourceError::ResourceMismatch);
            }
            let offset = IO_RESOURCE_REQUIREMENTS_HEADER_SIZE
                + descriptor_index * IO_RESOURCE_DESCRIPTOR_SIZE;
            check_native_requirement_private(requirements, offset, bar)?;
            descriptor_index += 1;
        } else {
            check_requirement_bar(requirements, offset, bar, true)?;
            check_requirement_bar(
                requirements,
                offset + IO_RESOURCE_DESCRIPTOR_SIZE,
                bar,
                false,
            )?;
            descriptor_index += 2;
        }
    }
    if device.irq_pin != 0 {
        if descriptor_index >= declared_count {
            return Err(PciBusResourceError::ResourceMismatch);
        }
        // The native PCI PDO may offer an MSI token before its legacy INTx
        // alternative. This is only a proposal; it never authorizes a routed
        // interrupt until the platform grant is selected independently.
        let message_alternative = native_requirements
            && declared_count.checked_sub(descriptor_index) == Some(2);
        if message_alternative {
            let offset = IO_RESOURCE_REQUIREMENTS_HEADER_SIZE
                + descriptor_index * IO_RESOURCE_DESCRIPTOR_SIZE;
            if requirements[offset] != IO_RESOURCE_REQUIRED
                || requirements[offset + 1] != CM_RESOURCE_TYPE_INTERRUPT
                || requirements[offset + 2] != CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE
                || requirements[offset + 3] != 0
                || u16_at(requirements, offset + 4)?
                    != (CM_RESOURCE_INTERRUPT_LATCHED | CM_RESOURCE_INTERRUPT_MESSAGE)
                || u16_at(requirements, offset + 6)? != 0
                || u32_at(requirements, offset + 8)? != CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN
                || u32_at(requirements, offset + 12)? != CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN
                || requirements[offset + 16..offset + IO_RESOURCE_DESCRIPTOR_SIZE]
                    .iter().any(|byte| *byte != 0)
            {
                return Err(PciBusResourceError::ResourceMismatch);
            }
            descriptor_index += 1;
        }
        let offset =
            IO_RESOURCE_REQUIREMENTS_HEADER_SIZE + descriptor_index * IO_RESOURCE_DESCRIPTOR_SIZE;
        if requirements[offset] != if message_alternative { IO_RESOURCE_ALTERNATIVE } else { IO_RESOURCE_REQUIRED }
            || requirements[offset + 1] != CM_RESOURCE_TYPE_INTERRUPT
            || requirements[offset + 2] != CM_RESOURCE_SHARE_SHARED
            || requirements[offset + 3] != 0
            || u16_at(requirements, offset + 4)? != CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
            || u16_at(requirements, offset + 6)? != 0
            || u32_at(requirements, offset + 8)? != 0
            || u32_at(requirements, offset + 12)? != 0xff
            || requirements[offset + 16..offset + IO_RESOURCE_DESCRIPTOR_SIZE]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(PciBusResourceError::ResourceMismatch);
        }
        descriptor_index += 1;
    }
    if descriptor_index != declared_count {
        return Err(PciBusResourceError::ResourceMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_cm_resources::{
        build_cm_resource_list, build_io_resource_requirements_list, cm_resource_list_size,
        io_resource_requirements_list_size, CmResourceDescriptor, InterruptDescriptor,
        IoAddressRequirement, IoInterruptRequirement, IoResourceRequirement, MemoryDescriptor,
        CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, CM_RESOURCE_MEMORY_PREFETCHABLE,
        CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, CM_RESOURCE_SHARE_SHARED, INTERFACE_TYPE_PCI_BUS,
        IO_RESOURCE_ALTERNATIVE, IO_RESOURCE_PREFERRED, IO_RESOURCE_REQUIRED,
    };

    fn device() -> PciDevice {
        PciDevice {
            bus: 0,
            dev: 1,
            func: 0,
            vendor: 0x1234,
            device: 0x1111,
            class: 0x030000,
            header_type: PCI_HEADER_TYPE_DEVICE,
            bridge: None,
            irq_line: 10,
            irq_pin: 1,
            bars: alloc::vec![Bar {
                index: 0,
                is_io: false,
                is_64bit: false,
                prefetchable: true,
                base: 0xe000_0000,
                size: 0x1000,
                maximum_address: u32::MAX as u64,
            }],
        }
    }

    #[test]
    fn accepted_pci_no_resource_report_requires_zero_bars_and_no_interrupt_pin() {
        let mut function = device();
        function.bars.clear();
        function.irq_pin = 0;
        function.irq_line = 255;
        assert_eq!(validate_pci_bus_reported_resources(&function, &[], &[]), Ok(()));

        function.irq_pin = 1;
        assert!(validate_pci_bus_reported_resources(&function, &[], &[]).is_err());
        function.irq_pin = 0;
        function.bars = device().bars;
        assert!(validate_pci_bus_reported_resources(&function, &[], &[]).is_err());
    }

    fn provider_lists(device: &PciDevice) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
        let raw_descriptors = [
            CmResourceDescriptor::Memory(MemoryDescriptor {
                start: 0xe000_0000,
                length: 0x1000,
                flags: CM_RESOURCE_MEMORY_PREFETCHABLE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            }),
            CmResourceDescriptor::Interrupt(InterruptDescriptor {
                level: 10,
                vector: 10,
                affinity: 0xffff_ffff,
                flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
                share: CM_RESOURCE_SHARE_SHARED,
            }),
        ];
        let mut raw = alloc::vec![0; cm_resource_list_size(raw_descriptors.len()).unwrap()];
        build_cm_resource_list(
            &mut raw,
            INTERFACE_TYPE_PCI_BUS,
            device.bus as u32,
            &raw_descriptors,
        )
        .unwrap();
        let requirements = [
            IoResourceRequirement::Memory(IoAddressRequirement {
                option: IO_RESOURCE_PREFERRED,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
                flags: CM_RESOURCE_MEMORY_PREFETCHABLE,
                length: 0x1000,
                alignment: 1,
                minimum: 0xe000_0000,
                maximum: 0xe000_0fff,
            }),
            IoResourceRequirement::Memory(IoAddressRequirement {
                option: IO_RESOURCE_ALTERNATIVE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
                flags: CM_RESOURCE_MEMORY_PREFETCHABLE,
                length: 0x1000,
                alignment: 0x1000,
                minimum: 0,
                maximum: u32::MAX as u64,
            }),
            IoResourceRequirement::Interrupt(IoInterruptRequirement {
                option: IO_RESOURCE_REQUIRED,
                share: CM_RESOURCE_SHARE_SHARED,
                flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
                minimum_vector: 0,
                maximum_vector: 0xff,
                affinity_policy: 0,
                priority_policy: 0,
                targeted_processors: 0,
            }),
        ];
        let mut req =
            alloc::vec![0; io_resource_requirements_list_size(requirements.len()).unwrap()];
        build_io_resource_requirements_list(
            &mut req,
            INTERFACE_TYPE_PCI_BUS,
            device.bus as u32,
            device.slot_number(),
            &requirements,
        )
        .unwrap();
        (raw, req)
    }

    #[test]
    fn libernt_pci_display_bar_metadata_and_alternatives_are_accepted() {
        let captured = include_str!("../tests/fixtures/libernt_pci_display_resources.txt");
        let mut lists = captured.lines().filter(|line| !line.starts_with('#'));
        let decode = |hex: &str| -> alloc::vec::Vec<u8> {
            hex.as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        let raw = decode(lists.next().unwrap());
        let requirements = decode(lists.next().unwrap());
        let device = PciDevice {
            bus: 0,
            dev: 1,
            func: 0,
            vendor: 0x1234,
            device: 0x1111,
            class: 0x030000,
            header_type: PCI_HEADER_TYPE_DEVICE,
            bridge: None,
            irq_line: 0xff,
            irq_pin: 0,
            bars: alloc::vec![
                Bar {
                    index: 0,
                    is_io: false,
                    is_64bit: false,
                    prefetchable: true,
                    base: 0x8000_0000,
                    size: 0x0100_0000,
                    maximum_address: u32::MAX as u64,
                },
                Bar {
                    index: 2,
                    is_io: false,
                    is_64bit: false,
                    prefetchable: false,
                    base: 0x8106_2000,
                    size: 0x1000,
                    maximum_address: u32::MAX as u64,
                },
            ],
        };
        assert_eq!(
            validate_pci_bus_reported_resources(&device, &raw, &requirements),
            Ok(())
        );
        let available = crate::assign_resources(&device, None, 0).unwrap().unwrap();
        let assigned = crate::select_resource_assignment(
            &available,
            &requirements,
            INTERFACE_TYPE_PCI_BUS,
            u32::from(device.bus),
            device.slot_number(),
        )
        .unwrap();
        assert_eq!(
            assigned.resources(crate::ResourceView::Raw).len(),
            device.bars.len()
        );
        let mut wrong_raw_owner = raw.clone();
        wrong_raw_owner[20 + PARTIAL_DESCRIPTOR_SIZE + 8] = 2;
        assert!(
            validate_pci_bus_reported_resources(&device, &wrong_raw_owner, &requirements).is_err()
        );
        let mut wrong_requirement_owner = requirements.clone();
        wrong_requirement_owner
            [IO_RESOURCE_REQUIREMENTS_HEADER_SIZE + 3 * IO_RESOURCE_DESCRIPTOR_SIZE + 12] = 2;
        assert!(
            validate_pci_bus_reported_resources(&device, &raw, &wrong_requirement_owner).is_err()
        );
        let mut wrong_alternative = requirements.clone();
        wrong_alternative
            [IO_RESOURCE_REQUIREMENTS_HEADER_SIZE + IO_RESOURCE_DESCRIPTOR_SIZE + 11] = 0;
        assert!(validate_pci_bus_reported_resources(&device, &raw, &wrong_alternative).is_err());
    }

    #[test]
    fn libernt_pci_ahci_native_bar_report_matches_scanned_function() {
        let captured = include_str!("../tests/fixtures/libernt_pci_ahci_resources.txt");
        let mut lists = captured.lines().filter(|line| !line.starts_with('#'));
        let decode = |hex: &str| -> alloc::vec::Vec<u8> {
            hex.as_bytes().chunks_exact(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        let raw = decode(lists.next().unwrap());
        let requirements = decode(lists.next().unwrap());
        let device = PciDevice {
            bus: 0, dev: 2, func: 0,
            vendor: 0x8086, device: 0x2922, class: 0x010601,
            header_type: PCI_HEADER_TYPE_DEVICE, bridge: None,
            irq_line: 22, irq_pin: 1,
            bars: alloc::vec![
                Bar { index: 4, is_io: true, is_64bit: false, prefetchable: false,
                    base: 0x60a0, size: 0x20, maximum_address: 0xffff },
                Bar { index: 5, is_io: false, is_64bit: false, prefetchable: false,
                    base: 0x8106_1000, size: 0x1000, maximum_address: u32::MAX as u64 },
            ],
        };
        assert_eq!(validate_pci_bus_reported_resources(&device, &raw, &requirements), Ok(()));
        let mut invalid_message = requirements.clone();
        let message = IO_RESOURCE_REQUIREMENTS_HEADER_SIZE + 8 * IO_RESOURCE_DESCRIPTOR_SIZE;
        invalid_message[message + 8] ^= 1;
        assert_eq!(
            validate_pci_bus_reported_resources(&device, &raw, &invalid_message),
            Err(PciBusResourceError::ResourceMismatch),
        );
        let mut invalid_legacy = requirements.clone();
        let legacy = IO_RESOURCE_REQUIREMENTS_HEADER_SIZE + 9 * IO_RESOURCE_DESCRIPTOR_SIZE;
        invalid_legacy[legacy + 2] = CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE;
        assert_eq!(
            validate_pci_bus_reported_resources(&device, &raw, &invalid_legacy),
            Err(PciBusResourceError::ResourceMismatch),
        );
    }

    #[test]
    fn accepted_pci_pdo_resources_bind_native_bar_and_observational_irq() {
        let device = device();
        let (raw, req) = provider_lists(&device);
        assert_eq!(
            validate_pci_bus_reported_resources(&device, &raw, &req),
            Ok(())
        );
        let mut earlier_scan = device.clone();
        earlier_scan.irq_line = 0xff;
        assert_eq!(
            validate_pci_bus_reported_resources(&earlier_scan, &raw, &req),
            Ok(())
        );
        let mut wrong_bus = req.clone();
        wrong_bus[8] = 1;
        assert!(validate_pci_bus_reported_resources(&device, &raw, &wrong_bus).is_err());
        let mut wrong_slot = req.clone();
        wrong_slot[12] ^= 1;
        assert!(validate_pci_bus_reported_resources(&device, &raw, &wrong_slot).is_err());
        let mut wrong_bar = raw.clone();
        wrong_bar[24] ^= 0x10;
        assert!(validate_pci_bus_reported_resources(&device, &wrong_bar, &req).is_err());
        let mut wrong_irq = raw.clone();
        wrong_irq[44] ^= 1;
        assert!(validate_pci_bus_reported_resources(&device, &wrong_irq, &req).is_err());
        let mut extra_bar = req.clone();
        extra_bar[0] += 32;
        extra_bar[36] += 1;
        extra_bar.extend_from_slice(&req[40..72]);
        assert!(validate_pci_bus_reported_resources(&device, &raw, &extra_bar).is_err());
        let mut truncated = raw.clone();
        truncated.pop();
        assert!(validate_pci_bus_reported_resources(&device, &truncated, &req).is_err());
    }

    #[test]
    fn native_requirements_admit_the_matching_scanned_bar_with_broker_marker() {
        let device = device();
        let (_, requirements) = provider_lists(&device);
        let candidate = [
            CmResourceDescriptor::Memory(MemoryDescriptor {
                start: device.bars[0].base,
                length: device.bars[0].size as u32,
                flags: CM_RESOURCE_MEMORY_PREFETCHABLE | CM_RESOURCE_MEMORY_BAR,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            }),
            CmResourceDescriptor::Interrupt(InterruptDescriptor {
                level: 10,
                vector: 10,
                affinity: 0xffff_ffff,
                flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
                share: CM_RESOURCE_SHARE_SHARED,
            }),
        ];
        assert_eq!(
            nt_cm_resources::select_io_resource_assignment(
                &requirements,
                INTERFACE_TYPE_PCI_BUS,
                device.bus as u32,
                device.slot_number(),
                &candidate,
            ),
            Ok(Some(alloc::vec![0, 1])),
        );
    }
}
