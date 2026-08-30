use alloc::vec::Vec;

pub const PNP_BUS_INFORMATION_X64_SIZE: usize = 24;

const DEVICE_CAPABILITIES_FLAGS_OFFSET: usize = 4;
const DEVICE_CAPABILITIES_ADDRESS_OFFSET: usize = 8;
const DEVICE_CAPABILITIES_UI_NUMBER_OFFSET: usize = 12;

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

/// Build the native input image required by `IRP_MN_QUERY_CAPABILITIES`.
pub fn initialized_device_capabilities_x64() -> [u8; nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE] {
    let mut bytes = [0u8; nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE];
    bytes[..2].copy_from_slice(&(nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
    bytes[DEVICE_CAPABILITIES_ADDRESS_OFFSET..DEVICE_CAPABILITIES_ADDRESS_OFFSET + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[DEVICE_CAPABILITIES_UI_NUMBER_OFFSET..DEVICE_CAPABILITIES_UI_NUMBER_OFFSET + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    bytes
}

/// Decode the capability fields currently owned by the PnP devnode model from a driver-mutated
/// native x64 `DEVICE_CAPABILITIES` image.
pub fn copy_device_capabilities_x64(
    bytes: &[u8],
) -> Result<crate::PdoCapabilities, BusPropertyCopyError> {
    let prefix = bytes
        .get(..nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE)
        .ok_or(BusPropertyCopyError::Truncated)?;
    let size = u16::from_le_bytes(prefix[..2].try_into().unwrap()) as usize;
    let version = u16::from_le_bytes(prefix[2..4].try_into().unwrap());
    if size != nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE || version != 1 {
        return Err(BusPropertyCopyError::Malformed);
    }
    let flags = u32::from_le_bytes(
        prefix[DEVICE_CAPABILITIES_FLAGS_OFFSET..DEVICE_CAPABILITIES_FLAGS_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    Ok(crate::PdoCapabilities {
        eject_supported: flags & (1 << 3) != 0,
        removable: flags & (1 << 4) != 0,
        surprise_removal_ok: flags & (1 << 9) != 0,
        address: u32::from_le_bytes(
            prefix[DEVICE_CAPABILITIES_ADDRESS_OFFSET..DEVICE_CAPABILITIES_ADDRESS_OFFSET + 4]
                .try_into()
                .unwrap(),
        ),
    })
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
    fn device_capabilities_round_trip_native_header_and_owned_fields() {
        let initialized = initialized_device_capabilities_x64();
        assert_eq!(&initialized[..4], &[64, 0, 1, 0]);
        assert_eq!(
            u32::from_le_bytes(initialized[8..12].try_into().unwrap()),
            u32::MAX
        );
        assert_eq!(
            u32::from_le_bytes(initialized[12..16].try_into().unwrap()),
            u32::MAX
        );

        let mut returned = initialized;
        returned[4..8].copy_from_slice(&((1u32 << 3) | (1 << 4) | (1 << 9)).to_le_bytes());
        returned[8..12].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            copy_device_capabilities_x64(&returned),
            Ok(crate::PdoCapabilities {
                removable: true,
                eject_supported: true,
                surprise_removal_ok: true,
                address: 7,
            })
        );
        assert_eq!(
            copy_device_capabilities_x64(&returned[..63]),
            Err(BusPropertyCopyError::Truncated)
        );
        returned[2..4].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            copy_device_capabilities_x64(&returned),
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
