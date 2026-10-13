use alloc::vec::Vec;

use nt_cm_resources::{
    CmResourceDescriptor, InterruptDescriptor, PortDescriptor, CM_RESOURCE_INTERRUPT_LATCHED,
    CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, CM_RESOURCE_PORT_IO,
    CM_RESOURCE_PORT_16_BIT_DECODE, CM_RESOURCE_PORT_POSITIVE_DECODE,
    CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, CM_RESOURCE_SHARE_DRIVER_EXCLUSIVE,
    CM_RESOURCE_SHARE_SHARED, CM_RESOURCE_TYPE_INTERRUPT, CM_RESOURCE_TYPE_PORT,
    INTERFACE_TYPE_INTERNAL,
    IO_RESOURCE_DESCRIPTOR_SIZE, IO_RESOURCE_LIST_HEADER_SIZE,
    IO_RESOURCE_REQUIREMENTS_FIXED_SIZE, PARTIAL_DESCRIPTOR_SIZE,
};

use crate::{PlatformInterruptResource, PlatformPortResource};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusReportedPlatformResourceError {
    Invalid,
}

/// An accepted bus PDO's exact native property bytes and the physical resources they name.
pub struct BusReportedPlatformResources<'a> {
    pub raw_resources: &'a [u8],
    pub resource_requirements: &'a [u8],
    pub ports: Vec<PortDescriptor>,
    pub raw_interrupt: InterruptDescriptor,
    pub translated_interrupt: InterruptDescriptor,
}

pub fn admit_bus_reported_platform_resources<'a>(
    raw_resources: &'a [u8],
    resource_requirements: &'a [u8],
    authorized_ports: &[PlatformPortResource],
    authorized_interrupt: PlatformInterruptResource,
) -> Result<BusReportedPlatformResources<'a>, BusReportedPlatformResourceError> {
    let invalid = BusReportedPlatformResourceError::Invalid;
    if nt_cm_resources::validate_cm_resource_list_extent(raw_resources).map_err(|_| invalid)?
        != raw_resources.len()
        || field_u32(raw_resources, 0)? != 1
        || authorized_interrupt.level == 0
        || authorized_interrupt.vector == 0
        || authorized_interrupt.affinity == 0
    {
        return Err(invalid);
    }

    let descriptor_count = field_u32(raw_resources, 16)? as usize;
    if descriptor_count == 0 {
        return Err(invalid);
    }
    let interface_type = field_u32(raw_resources, 4)? as i32;
    let bus_number = field_u32(raw_resources, 8)?;
    let slot_number = field_u32(resource_requirements, 12)?;

    let mut ports = Vec::new();
    ports.try_reserve_exact(descriptor_count.saturating_sub(1)).map_err(|_| invalid)?;
    let mut candidates = Vec::new();
    candidates.try_reserve_exact(descriptor_count).map_err(|_| invalid)?;
    let mut raw_interrupt = None;
    for index in 0..descriptor_count {
        let offset = 20usize
            .checked_add(index.checked_mul(PARTIAL_DESCRIPTOR_SIZE).ok_or(invalid)?)
            .ok_or(invalid)?;
        let descriptor = raw_resources
            .get(offset..offset + PARTIAL_DESCRIPTOR_SIZE)
            .ok_or(invalid)?;
        let share = descriptor[1];
        let flags = u16::from_le_bytes([descriptor[2], descriptor[3]]);
        match descriptor[0] {
            CM_RESOURCE_TYPE_PORT => {
                let port = PortDescriptor {
                    start: field_u64(descriptor, 4)?,
                    length: field_u32(descriptor, 12)?,
                    flags,
                    share,
                };
                let end = port.start.checked_add(u64::from(port.length)).ok_or(invalid)?;
                if port.length == 0
                    || end == 0
                    || end - 1 > u16::MAX as u64
                    || port.flags & CM_RESOURCE_PORT_IO == 0
                    || port.flags
                        & !(CM_RESOURCE_PORT_IO
                            | CM_RESOURCE_PORT_16_BIT_DECODE
                            | CM_RESOURCE_PORT_POSITIVE_DECODE)
                        != 0
                    || !matches!(port.share, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE | CM_RESOURCE_SHARE_DRIVER_EXCLUSIVE)
                    || !authorized_ports.iter().any(|window| {
                        window.start <= port.start
                            && window.length != 0
                            && window.start
                                .checked_add(u64::from(window.length))
                                .is_some_and(|window_end| {
                                    end <= window_end && window_end <= u16::MAX as u64 + 1
                                })
                    })
                    || ports.iter().any(|previous: &PortDescriptor| {
                        let previous_end = previous.start + u64::from(previous.length);
                        port.start < previous_end && previous.start < end
                    })
                {
                    return Err(invalid);
                }
                ports.push(port);
                candidates.push(CmResourceDescriptor::Port(port));
            }
            CM_RESOURCE_TYPE_INTERRUPT if raw_interrupt.is_none() => {
                let interrupt = InterruptDescriptor {
                    level: field_u32(descriptor, 4)?,
                    vector: field_u32(descriptor, 8)?,
                    affinity: field_u64(descriptor, 12)?,
                    flags,
                    share,
                };
                if interrupt.level != authorized_interrupt.level
                    || interrupt.vector != authorized_interrupt.level
                    || interrupt.affinity == 0
                    || interrupt.flags
                        != if authorized_interrupt.latched {
                            CM_RESOURCE_INTERRUPT_LATCHED
                        } else {
                            CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
                        }
                    || (interrupt.share == CM_RESOURCE_SHARE_SHARED)
                        != authorized_interrupt.shared
                    || !matches!(interrupt.share, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE | CM_RESOURCE_SHARE_DRIVER_EXCLUSIVE | CM_RESOURCE_SHARE_SHARED)
                {
                    return Err(invalid);
                }
                raw_interrupt = Some(interrupt);
                candidates.push(CmResourceDescriptor::Interrupt(interrupt));
            }
            _ => return Err(invalid),
        }
    }
    let raw_interrupt = raw_interrupt.ok_or(invalid)?;
    // ReactOS ACPI buspdo allocates the requirements list without clearing it and fills only
    // the interrupt's minimum/maximum line. An impossible policy enum proves its entire
    // unwritten policy tail is pool residue, even when targeted processors is nonzero.
    // Normalize only that copy for selection; preserve accepted bytes and real policies.
    let selector_requirements = normalized_interrupt_requirements(
        resource_requirements,
        interface_type,
        bus_number,
        raw_interrupt,
    )?;
    let selected = nt_cm_resources::select_complete_io_resource_assignment(
        &selector_requirements,
        interface_type,
        bus_number,
        slot_number,
        &candidates,
    )
    .map_err(|_| invalid)?
    .ok_or(invalid)?;
    if selected.len() != candidates.len() {
        return Err(invalid);
    }
    let translated_interrupt = InterruptDescriptor {
        level: authorized_interrupt.vector,
        vector: authorized_interrupt.vector,
        affinity: authorized_interrupt.affinity,
        flags: raw_interrupt.flags,
        share: raw_interrupt.share,
    };
    Ok(BusReportedPlatformResources {
        raw_resources,
        resource_requirements,
        ports,
        raw_interrupt,
        translated_interrupt,
    })
}

fn normalized_interrupt_requirements(
    bytes: &[u8],
    interface_type: i32,
    bus_number: u32,
    raw_interrupt: InterruptDescriptor,
) -> Result<Vec<u8>, BusReportedPlatformResourceError> {
    let invalid = BusReportedPlatformResourceError::Invalid;
    if nt_cm_resources::validate_io_resource_requirements_list_extent(bytes)
        .map_err(|_| invalid)? != bytes.len()
    {
        return Err(invalid);
    }
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|_| invalid)?;
    copy.extend_from_slice(bytes);
    let alternatives = field_u32(bytes, 28)? as usize;
    let mut list_offset = IO_RESOURCE_REQUIREMENTS_FIXED_SIZE;
    for _ in 0..alternatives {
        let count = field_u32(bytes, list_offset + 4)? as usize;
        let descriptors = list_offset.checked_add(IO_RESOURCE_LIST_HEADER_SIZE).ok_or(invalid)?;
        for index in 0..count {
            let descriptor = descriptors
                .checked_add(index.checked_mul(IO_RESOURCE_DESCRIPTOR_SIZE).ok_or(invalid)?)
                .ok_or(invalid)?;
            if interface_type == INTERFACE_TYPE_INTERNAL
                && bus_number == 0
                && bytes.get(descriptor + 1).copied() == Some(CM_RESOURCE_TYPE_INTERRUPT)
                && bytes.get(descriptor + 2).copied() == Some(raw_interrupt.share)
                && field_u16(bytes, descriptor + 4)? == raw_interrupt.flags
                && field_u32(bytes, descriptor + 8)? == raw_interrupt.level
                && field_u32(bytes, descriptor + 12)? == raw_interrupt.level
                && (field_u32(bytes, descriptor + 16)? > 5
                    || field_u32(bytes, descriptor + 20)? > 3)
            {
                copy.get_mut(descriptor + 16..descriptor + IO_RESOURCE_DESCRIPTOR_SIZE)
                    .ok_or(invalid)?
                    .fill(0);
            }
        }
        list_offset = descriptors
            .checked_add(count.checked_mul(IO_RESOURCE_DESCRIPTOR_SIZE).ok_or(invalid)?)
            .ok_or(invalid)?;
    }
    Ok(copy)
}

fn field_u16(bytes: &[u8], offset: usize) -> Result<u16, BusReportedPlatformResourceError> {
    let field = bytes.get(offset..offset + 2).ok_or(BusReportedPlatformResourceError::Invalid)?;
    Ok(u16::from_le_bytes(field.try_into().expect("two-byte field")))
}

fn field_u32(bytes: &[u8], offset: usize) -> Result<u32, BusReportedPlatformResourceError> {
    let field = bytes.get(offset..offset + 4).ok_or(BusReportedPlatformResourceError::Invalid)?;
    Ok(u32::from_le_bytes(field.try_into().expect("four-byte field")))
}

fn field_u64(bytes: &[u8], offset: usize) -> Result<u64, BusReportedPlatformResourceError> {
    let field = bytes.get(offset..offset + 8).ok_or(BusReportedPlatformResourceError::Invalid)?;
    Ok(u64::from_le_bytes(field.try_into().expect("eight-byte field")))
}
