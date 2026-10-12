//! Validation of resource lists returned by an accepted PCI PDO.

use crate::{Bar, PciDevice, PCI_HEADER_TYPE_DEVICE};
use nt_cm_resources::{
    validate_cm_resource_list_extent, validate_io_resource_requirements_list_extent,
    CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, CM_RESOURCE_MEMORY_BAR, CM_RESOURCE_MEMORY_PREFETCHABLE,
    CM_RESOURCE_PORT_16_BIT_DECODE, CM_RESOURCE_PORT_BAR, CM_RESOURCE_PORT_IO,
    CM_RESOURCE_PORT_POSITIVE_DECODE, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, CM_RESOURCE_SHARE_SHARED,
    CM_RESOURCE_TYPE_INTERRUPT, CM_RESOURCE_TYPE_MEMORY, CM_RESOURCE_TYPE_PORT,
    INTERFACE_TYPE_PCI_BUS, IO_RESOURCE_ALTERNATIVE, IO_RESOURCE_DESCRIPTOR_SIZE,
    IO_RESOURCE_PREFERRED, IO_RESOURCE_REQUIRED, IO_RESOURCE_REQUIREMENTS_HEADER_SIZE,
    PARTIAL_DESCRIPTOR_SIZE,
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
    let raw_irq =
        device.irq_pin != 0 && raw.len() == 20 + (device.bars.len() + 1) * PARTIAL_DESCRIPTOR_SIZE;
    let raw_count = device.bars.len() + usize::from(raw_irq);
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
            check_raw_bar(raw, 20 + index * PARTIAL_DESCRIPTOR_SIZE, bar)?;
        }
        if raw_irq {
            let offset = 20 + device.bars.len() * PARTIAL_DESCRIPTOR_SIZE;
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
        || requirements.len()
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
        || u32_at(requirements, 36)? as usize != requirement_count
    {
        return Err(PciBusResourceError::Malformed);
    }
    for (index, bar) in device.bars.iter().enumerate() {
        let offset = IO_RESOURCE_REQUIREMENTS_HEADER_SIZE + index * 2 * IO_RESOURCE_DESCRIPTOR_SIZE;
        check_requirement_bar(requirements, offset, bar, true)?;
        check_requirement_bar(
            requirements,
            offset + IO_RESOURCE_DESCRIPTOR_SIZE,
            bar,
            false,
        )?;
    }
    if device.irq_pin != 0 {
        let offset = IO_RESOURCE_REQUIREMENTS_HEADER_SIZE
            + device.bars.len() * 2 * IO_RESOURCE_DESCRIPTOR_SIZE;
        if requirements[offset] != IO_RESOURCE_REQUIRED
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
