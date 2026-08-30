use alloc::vec::Vec;

pub const PNP_BUS_INFORMATION_X64_SIZE: usize = 24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusInformationValue {
    pub bus_type_guid: [u8; 16],
    pub legacy_bus_type: u32,
    pub bus_number: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusPropertyCopyError {
    Truncated,
    Malformed,
    InsufficientResources,
}

/// Copy the fixed native `PNP_BUS_INFORMATION` prefix from provider allocation capacity.
pub fn copy_pnp_bus_information_x64(
    bytes: &[u8],
) -> Result<BusInformationValue, BusPropertyCopyError> {
    let prefix = bytes
        .get(..PNP_BUS_INFORMATION_X64_SIZE)
        .ok_or(BusPropertyCopyError::Truncated)?;
    let mut bus_type_guid = [0u8; 16];
    bus_type_guid.copy_from_slice(&prefix[..16]);
    if bus_type_guid == [0; 16] {
        return Err(BusPropertyCopyError::Malformed);
    }
    Ok(BusInformationValue {
        bus_type_guid,
        legacy_bus_type: u32::from_le_bytes(prefix[16..20].try_into().unwrap()),
        bus_number: u32::from_le_bytes(prefix[20..24].try_into().unwrap()),
    })
}

fn copy_validated_prefix(
    bytes: &[u8],
    validate: fn(&[u8]) -> Result<usize, nt_cm_resources::NativeResourceListError>,
) -> Result<Vec<u8>, BusPropertyCopyError> {
    let extent = validate(bytes).map_err(|_| BusPropertyCopyError::Malformed)?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(extent)
        .map_err(|_| BusPropertyCopyError::InsufficientResources)?;
    owned.extend_from_slice(&bytes[..extent]);
    Ok(owned)
}

/// Copy exactly the counted native `CM_RESOURCE_LIST` prefix.
pub fn copy_cm_resource_list(bytes: &[u8]) -> Result<Vec<u8>, BusPropertyCopyError> {
    copy_validated_prefix(bytes, nt_cm_resources::validate_cm_resource_list_extent)
}

/// Copy exactly the self-described native `IO_RESOURCE_REQUIREMENTS_LIST` prefix.
pub fn copy_io_resource_requirements_list(bytes: &[u8]) -> Result<Vec<u8>, BusPropertyCopyError> {
    copy_validated_prefix(
        bytes,
        nt_cm_resources::validate_io_resource_requirements_list_extent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_cm_resources::{
        build_io_resource_requirements_list, build_memory_interrupt_list, InterruptDescriptor,
        IoAddressRequirement, IoResourceRequirement, MemoryDescriptor,
        CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, INTERFACE_TYPE_PCI_BUS, IO_RESOURCE_REQUIRED,
    };

    #[test]
    fn bus_information_uses_only_the_native_prefix() {
        let mut bytes = [0xa5; 40];
        bytes[..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        bytes[16..20].copy_from_slice(&5u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            copy_pnp_bus_information_x64(&bytes),
            Ok(BusInformationValue {
                bus_type_guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                legacy_bus_type: 5,
                bus_number: 7,
            })
        );
        assert_eq!(
            copy_pnp_bus_information_x64(&bytes[..23]),
            Err(BusPropertyCopyError::Truncated)
        );
        bytes[..16].fill(0);
        assert_eq!(
            copy_pnp_bus_information_x64(&bytes),
            Err(BusPropertyCopyError::Malformed)
        );
    }

    #[test]
    fn resource_copies_drop_allocator_capacity_and_reject_truncation() {
        let mut cm = [0xcc; 96];
        let cm_len = build_memory_interrupt_list(
            &mut cm,
            INTERFACE_TYPE_PCI_BUS,
            0,
            MemoryDescriptor {
                start: 0x1000,
                length: 0x1000,
                flags: 0,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
            InterruptDescriptor {
                level: 5,
                vector: 5,
                affinity: 1,
                flags: 0,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
        )
        .unwrap();
        assert_eq!(copy_cm_resource_list(&cm).unwrap(), cm[..cm_len]);
        assert_eq!(
            copy_cm_resource_list(&cm[..cm_len - 1]),
            Err(BusPropertyCopyError::Malformed)
        );

        let requirement = [IoResourceRequirement::Memory(IoAddressRequirement {
            option: IO_RESOURCE_REQUIRED,
            share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            flags: 0,
            length: 0x1000,
            alignment: 0x1000,
            minimum: 0x1000,
            maximum: 0x1fff,
        })];
        let mut req = [0xdd; 96];
        let req_len = build_io_resource_requirements_list(
            &mut req,
            INTERFACE_TYPE_PCI_BUS,
            0,
            0,
            &requirement,
        )
        .unwrap();
        assert_eq!(
            copy_io_resource_requirements_list(&req).unwrap(),
            req[..req_len]
        );
    }
}
