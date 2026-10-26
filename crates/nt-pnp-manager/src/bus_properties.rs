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

/// The released and legacy ACPI PDOs report distinct, exact bus GUID/type pairs.
pub fn is_acpi_child_bus_information(bus: &crate::PnpBusInformation) -> bool {
    const LIBERNT_ACPI: [u8; 16] = [
        0x95, 0x68, 0xb4, 0xd7, 0x1a, 0x00, 0x42, 0x49, 0x89, 0x1f, 0xa7, 0xd4, 0x66, 0x10,
        0xa8, 0x43,
    ];
    const REACTOS_ACPI: [u8; 16] = [
        0x8a, 0xa0, 0x91, 0xb0, 0x97, 0xba, 0xd0, 0x11, 0xbd, 0x14, 0x00, 0xaa, 0x00, 0xb7,
        0xb3, 0x2a,
    ];
    (bus.bus_type_guid == LIBERNT_ACPI && bus.legacy_bus_type == 0)
        || (bus.bus_type_guid == REACTOS_ACPI && bus.legacy_bus_type == 13)
}

#[cfg(test)]
mod acpi_bus_identity_tests {
    use super::*;

    #[test]
    fn released_and_legacy_acpi_child_bus_pairs_are_exact() {
        let released = crate::PnpBusInformation {
            bus_type_guid: [0x95, 0x68, 0xb4, 0xd7, 0x1a, 0x00, 0x42, 0x49,
                0x89, 0x1f, 0xa7, 0xd4, 0x66, 0x10, 0xa8, 0x43],
            legacy_bus_type: 0,
            bus_number: 0,
        };
        let legacy = crate::PnpBusInformation {
            bus_type_guid: [0x8a, 0xa0, 0x91, 0xb0, 0x97, 0xba, 0xd0, 0x11,
                0xbd, 0x14, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a],
            legacy_bus_type: 13,
            bus_number: 0,
        };
        assert!(is_acpi_child_bus_information(&released));
        assert!(is_acpi_child_bus_information(&legacy));
        assert!(!is_acpi_child_bus_information(&crate::PnpBusInformation {
            legacy_bus_type: 13, ..released.clone()
        }));
        assert!(is_acpi_child_bus_information(&crate::PnpBusInformation {
            bus_number: 1, ..legacy
        }));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusPropertyCopyError {
    Truncated,
    Malformed,
    InsufficientResources,
}

/// Copy a provider-owned `IRP_MN_QUERY_DEVICE_TEXT` description before its pool allocation is
/// retired. The resulting REG_SZ preserves the provider's UTF-16 units, including its terminator.
pub fn copy_pnp_device_text_x64(bytes: &[u8]) -> Result<Vec<u8>, BusPropertyCopyError> {
    const MAX_DESCRIPTION_UNITS: usize = 512;
    let mut end = None;
    for index in 0..MAX_DESCRIPTION_UNITS.min(bytes.len() / 2) {
        let unit = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
        if unit == 0 {
            end = Some(index);
            break;
        }
    }
    let units = end.ok_or(BusPropertyCopyError::Truncated)?;
    if units == 0 {
        return Err(BusPropertyCopyError::Malformed);
    }
    if core::char::decode_utf16(
        bytes[..units * 2]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    )
    .any(|result| result.is_err())
    {
        return Err(BusPropertyCopyError::Malformed);
    }
    let length = (units + 1) * 2;
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(length)
        .map_err(|_| BusPropertyCopyError::InsufficientResources)?;
    copied.extend_from_slice(&bytes[..length]);
    Ok(copied)
}

/// The mandatory DeviceDesc path also accepts a provider's empty string, so PiSetDevNodeText
/// can apply its reference-defined fallback after the physical allocation has been copied.
pub fn copy_pnp_required_device_text_x64(bytes: &[u8]) -> Result<Vec<u8>, BusPropertyCopyError> {
    if bytes.len() >= 2 && bytes[..2] == [0, 0] {
        let mut empty = Vec::new();
        empty
            .try_reserve_exact(2)
            .map_err(|_| BusPropertyCopyError::InsufficientResources)?;
        empty.extend_from_slice(&[0, 0]);
        Ok(empty)
    } else {
        copy_pnp_device_text_x64(bytes)
    }
}

/// An immutable bus-owned boot resource assignment that needs no HAL translation.
///
/// Some bus PDOs report one `CmResourceTypeBusNumber` boot descriptor and no resource
/// requirements. NT preserves that descriptor byte-for-byte in both raw and translated
/// START_DEVICE lists. PDOs with additional resources or present requirements use a separate
/// checked assignment path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusReportedBusNumberStart {
    pub raw_resources: Vec<u8>,
    pub translated_resources: Vec<u8>,
}

/// Exact bus-owned current resources and possible-resource requirements. The boot list is an
/// assignment reported by the bus; the requirements still need checked admission before START.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusReportedResourceSnapshot {
    pub raw_resources: Vec<u8>,
    pub resource_requirements: Vec<u8>,
}

/// A successful PCI bus query may report no descriptors at all. Require all three query
/// results to agree; an unqueried or one-sided result cannot authorize an empty START.
pub fn pci_bus_reports_no_resources(properties: &crate::PdoProperties) -> bool {
    matches!(properties.boot_resources_raw, crate::PropertyBlobState::KnownNone)
        && matches!(properties.boot_resources_translated, crate::PropertyBlobState::KnownNone)
        && matches!(properties.resource_requirements, crate::PropertyBlobState::KnownNone)
}

/// Retain a complete resource pair from an accepted bus PDO without replacing it with a
/// synthetic no-resource plan. One-sided and unqueried pairs cannot authorize START.
pub fn prepare_bus_reported_resource_snapshot(
    properties: &crate::PdoProperties,
) -> Result<Option<BusReportedResourceSnapshot>, BusPropertyCopyError> {
    use crate::PropertyBlobState::{KnownNone, Present, Unqueried};
    match (
        &properties.boot_resources_raw,
        &properties.boot_resources_translated,
        &properties.resource_requirements,
    ) {
        (Unqueried, _, _) | (_, Unqueried, _) | (_, _, Unqueried) => {
            Err(BusPropertyCopyError::Malformed)
        }
        (KnownNone, KnownNone, KnownNone) | (Present(_), KnownNone, KnownNone) => Ok(None),
        (Present(raw), KnownNone, Present(requirements)) => Ok(Some(
            BusReportedResourceSnapshot {
                raw_resources: copy_cm_resource_list(raw)?,
                resource_requirements: copy_io_resource_requirements_list(requirements)?,
            },
        )),
        _ => Err(BusPropertyCopyError::Malformed),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusReportedBusNumberStartError {
    Unqueried,
    InvalidPropertyState,
    MalformedBootResources,
    InsufficientResources,
}

fn clone_resource_bytes(bytes: &[u8]) -> Result<Vec<u8>, BusReportedBusNumberStartError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| BusReportedBusNumberStartError::InsufficientResources)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

/// Prepare the exact boot-only BusNumber resources of a bus-reported PDO.
///
/// `Ok(None)` means that the PDO either has no boot resources or has requirements which must use
/// the normal resource-arbitration path. Once a bus has published a boot-only resource list, an
/// unqueried or malformed snapshot is an authority error rather than permission to invent a
/// replacement list.
pub fn prepare_bus_reported_bus_number_start(
    properties: &crate::PdoProperties,
) -> Result<Option<BusReportedBusNumberStart>, BusReportedBusNumberStartError> {
    match &properties.resource_requirements {
        crate::PropertyBlobState::Unqueried => {
            return Err(BusReportedBusNumberStartError::Unqueried)
        }
        crate::PropertyBlobState::Present(_) => return Ok(None),
        crate::PropertyBlobState::KnownNone => {}
    }

    let raw = match &properties.boot_resources_raw {
        crate::PropertyBlobState::Unqueried => {
            return Err(BusReportedBusNumberStartError::Unqueried)
        }
        crate::PropertyBlobState::KnownNone => return Ok(None),
        crate::PropertyBlobState::Present(raw) => raw,
    };
    match &properties.boot_resources_translated {
        crate::PropertyBlobState::Unqueried => {
            return Err(BusReportedBusNumberStartError::Unqueried)
        }
        crate::PropertyBlobState::Present(_) => {
            return Err(BusReportedBusNumberStartError::InvalidPropertyState)
        }
        crate::PropertyBlobState::KnownNone => {}
    }

    nt_cm_resources::decode_single_bus_number_resource(raw)
        .map_err(|_| BusReportedBusNumberStartError::MalformedBootResources)?;
    Ok(Some(BusReportedBusNumberStart {
        raw_resources: clone_resource_bytes(raw)?,
        translated_resources: clone_resource_bytes(raw)?,
    }))
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
        raw_device_ok: flags & (1 << 8) != 0,
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
    use alloc::vec;
    use nt_cm_resources::{
        build_io_resource_requirements_list, build_memory_interrupt_list, InterruptDescriptor,
        IoAddressRequirement, IoResourceRequirement, MemoryDescriptor,
        CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, CM_RESOURCE_TYPE_BUS_NUMBER, INTERFACE_TYPE_INTERNAL,
        INTERFACE_TYPE_PCI_BUS, IO_RESOURCE_REQUIRED,
    };

    fn exact_bus_number_resources(start: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 40];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(INTERFACE_TYPE_INTERNAL as u32).to_le_bytes());
        bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
        bytes[14..16].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20] = CM_RESOURCE_TYPE_BUS_NUMBER;
        bytes[21] = CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE;
        bytes[24..28].copy_from_slice(&start.to_le_bytes());
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    fn bus_properties(
        raw: crate::PropertyBlobState,
        translated: crate::PropertyBlobState,
        requirements: crate::PropertyBlobState,
    ) -> crate::PdoProperties {
        crate::PdoProperties::from_bus_queries(None, None, raw, translated, requirements)
    }

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
        returned[4..8].copy_from_slice(&((1u32 << 3) | (1 << 4) | (1 << 8) | (1 << 9)).to_le_bytes());
        returned[8..12].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            copy_device_capabilities_x64(&returned),
            Ok(crate::PdoCapabilities {
                removable: true,
                eject_supported: true,
                surprise_removal_ok: true,
                raw_device_ok: true,
                address: 7,
            })
        );
        returned[4..8].copy_from_slice(&((1u32 << 3) | (1 << 4) | (1 << 6) | (1 << 9)).to_le_bytes());
        assert!(!copy_device_capabilities_x64(&returned).unwrap().raw_device_ok);
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
    fn native_raw_device_ok_is_distinct_from_unique_id() {
        let mut returned = initialized_device_capabilities_x64();
        returned[DEVICE_CAPABILITIES_FLAGS_OFFSET..DEVICE_CAPABILITIES_FLAGS_OFFSET + 4]
            .copy_from_slice(&(1u32 << 8).to_le_bytes());
        assert!(copy_device_capabilities_x64(&returned).unwrap().raw_device_ok);

        returned[DEVICE_CAPABILITIES_FLAGS_OFFSET..DEVICE_CAPABILITIES_FLAGS_OFFSET + 4]
            .copy_from_slice(&(1u32 << 6).to_le_bytes());
        assert!(!copy_device_capabilities_x64(&returned).unwrap().raw_device_ok);
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

    #[test]
    fn bus_number_boot_resources_are_preserved_as_both_start_lists() {
        let resources = exact_bus_number_resources(7);
        let properties = bus_properties(
            crate::PropertyBlobState::Present(resources.clone()),
            crate::PropertyBlobState::KnownNone,
            crate::PropertyBlobState::KnownNone,
        );

        let prepared = prepare_bus_reported_bus_number_start(&properties)
            .unwrap()
            .unwrap();
        assert_eq!(prepared.raw_resources, resources);
        assert_eq!(prepared.translated_resources, resources);
    }

    #[test]
    fn bus_number_start_rejects_unqueried_authority() {
        for properties in [
            bus_properties(
                crate::PropertyBlobState::Unqueried,
                crate::PropertyBlobState::KnownNone,
                crate::PropertyBlobState::KnownNone,
            ),
            bus_properties(
                crate::PropertyBlobState::Present(exact_bus_number_resources(0)),
                crate::PropertyBlobState::Unqueried,
                crate::PropertyBlobState::KnownNone,
            ),
            bus_properties(
                crate::PropertyBlobState::Present(exact_bus_number_resources(0)),
                crate::PropertyBlobState::KnownNone,
                crate::PropertyBlobState::Unqueried,
            ),
        ] {
            assert_eq!(
                prepare_bus_reported_bus_number_start(&properties),
                Err(BusReportedBusNumberStartError::Unqueried)
            );
        }
    }

    #[test]
    fn bus_number_start_rejects_malformed_or_conflicting_boot_state() {
        let mut truncated = exact_bus_number_resources(0);
        truncated.pop();
        let malformed = bus_properties(
            crate::PropertyBlobState::Present(truncated),
            crate::PropertyBlobState::KnownNone,
            crate::PropertyBlobState::KnownNone,
        );
        assert_eq!(
            prepare_bus_reported_bus_number_start(&malformed),
            Err(BusReportedBusNumberStartError::MalformedBootResources)
        );

        let conflicting = bus_properties(
            crate::PropertyBlobState::Present(exact_bus_number_resources(0)),
            crate::PropertyBlobState::Present(exact_bus_number_resources(0)),
            crate::PropertyBlobState::KnownNone,
        );
        assert_eq!(
            prepare_bus_reported_bus_number_start(&conflicting),
            Err(BusReportedBusNumberStartError::InvalidPropertyState)
        );
    }

    #[test]
    fn bus_number_start_leaves_no_resource_and_arbitrated_pdos_to_their_paths() {
        let no_resources = bus_properties(
            crate::PropertyBlobState::KnownNone,
            crate::PropertyBlobState::KnownNone,
            crate::PropertyBlobState::KnownNone,
        );
        assert_eq!(
            prepare_bus_reported_bus_number_start(&no_resources),
            Ok(None)
        );

        let arbitrated = bus_properties(
            crate::PropertyBlobState::Present(exact_bus_number_resources(0)),
            crate::PropertyBlobState::KnownNone,
            crate::PropertyBlobState::Present(vec![1]),
        );
        assert_eq!(prepare_bus_reported_bus_number_start(&arbitrated), Ok(None));
    }

    #[test]
    fn pci_no_resource_report_requires_exact_completed_bus_queries() {
        use crate::PropertyBlobState::{KnownNone, Present, Unqueried};

        let no_resources = bus_properties(KnownNone, KnownNone, KnownNone);
        assert!(pci_bus_reports_no_resources(&no_resources));
        for (raw, translated, requirements) in [
            (Unqueried, KnownNone, KnownNone),
            (KnownNone, Unqueried, KnownNone),
            (KnownNone, KnownNone, Unqueried),
            (Present(Vec::new()), KnownNone, KnownNone),
            (KnownNone, Present(Vec::new()), KnownNone),
            (KnownNone, KnownNone, Present(Vec::new())),
        ] {
            assert!(!pci_bus_reports_no_resources(&bus_properties(
                raw, translated, requirements,
            )));
        }
    }

    #[test]
    fn bus_owned_multi_resource_snapshot_preserves_raw_and_requirements() {
        let mut raw_storage = [0u8; 96];
        let raw_len = build_memory_interrupt_list(
            &mut raw_storage,
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
        let requirement = [IoResourceRequirement::Memory(IoAddressRequirement {
            option: IO_RESOURCE_REQUIRED,
            share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            flags: 0,
            length: 0x1000,
            alignment: 0x1000,
            minimum: 0x1000,
            maximum: 0x1fff,
        })];
        let mut req_storage = [0u8; 96];
        let req_len = build_io_resource_requirements_list(
            &mut req_storage,
            INTERFACE_TYPE_PCI_BUS,
            0,
            0,
            &requirement,
        )
        .unwrap();
        let raw = raw_storage[..raw_len].to_vec();
        let requirements = req_storage[..req_len].to_vec();
        let properties = bus_properties(
            crate::PropertyBlobState::Present(raw.clone()),
            crate::PropertyBlobState::KnownNone,
            crate::PropertyBlobState::Present(requirements.clone()),
        );

        // This is an accepted bus PDO with real requirements. A no-resource plan would pass
        // `None`/`None` to native property validation and reject both provider-owned blobs.
        let snapshot = prepare_bus_reported_resource_snapshot(&properties)
            .unwrap()
            .expect("present bus-owned resources");
        assert_eq!(snapshot.raw_resources, raw);
        assert_eq!(snapshot.resource_requirements, requirements);
        assert_eq!(prepare_bus_reported_bus_number_start(&properties), Ok(None));
    }

    #[test]
    fn native_device_text_copy_preserves_provider_utf16_and_bounds() {
        let source: Vec<u8> = "PCI Interrupt Link\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0xaa, 0xbb])
            .collect();
        let copied = copy_pnp_device_text_x64(&source).expect("terminated provider text");
        assert_eq!(copied, &source[..source.len() - 2]);
        assert_eq!(
            copy_pnp_device_text_x64(&source[..source.len() - 4]),
            Err(BusPropertyCopyError::Truncated)
        );
        assert_eq!(
            copy_pnp_device_text_x64(&[0, 0]),
            Err(BusPropertyCopyError::Malformed)
        );
        assert_eq!(
            copy_pnp_device_text_x64(&[0x00, 0xd8, 0, 0]),
            Err(BusPropertyCopyError::Malformed)
        );
    }
}
