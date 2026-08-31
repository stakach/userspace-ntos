//! Allocation-free helpers for the NT loader configuration tree.

pub const CM_PARTIAL_RESOURCE_LIST_HEADER_BYTES: usize = 8;
pub const CM_PARTIAL_RESOURCE_DESCRIPTOR_BYTES: usize = 20;
pub const ACPI_BIOS_MULTI_NODE_HEADER_BYTES: usize = 16;
pub const ACPI_E820_ENTRY_BYTES: usize = 24;
pub const LOADER_ACPI_CONFIGURATION_FIXED_BYTES: usize = CM_PARTIAL_RESOURCE_LIST_HEADER_BYTES
    + CM_PARTIAL_RESOURCE_DESCRIPTOR_BYTES
    + ACPI_BIOS_MULTI_NODE_HEADER_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderFirmwareMemoryRange {
    pub base: u64,
    pub length: u64,
    pub e820_type: u32,
    pub extended_attributes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderAcpiConfigurationError {
    MissingRootTable,
    MissingMemoryMap,
    InvalidMemoryRange,
    SizeOverflow,
    BufferTooSmall,
}

pub const fn loader_acpi_configuration_size(entry_count: usize) -> Option<usize> {
    match entry_count.checked_mul(ACPI_E820_ENTRY_BYTES) {
        Some(entries_bytes) => LOADER_ACPI_CONFIGURATION_FIXED_BYTES.checked_add(entries_bytes),
        None => None,
    }
}

/// Encode the amd64 NT 5.2 loader's `CM_PARTIAL_RESOURCE_LIST` and trailing
/// `ACPI_BIOS_MULTI_NODE`. The descriptor is 20 bytes on this ABI, so the node begins at `+0x1c`;
/// treating it as a 16-byte descriptor shifts every firmware field and fails the real driver.
pub fn encode_loader_acpi_configuration(
    output: &mut [u8],
    root_table_paddr: u64,
    memory_map: &[LoaderFirmwareMemoryRange],
) -> Result<usize, LoaderAcpiConfigurationError> {
    if root_table_paddr == 0 {
        return Err(LoaderAcpiConfigurationError::MissingRootTable);
    }
    if memory_map.is_empty() {
        return Err(LoaderAcpiConfigurationError::MissingMemoryMap);
    }
    if memory_map.iter().any(|entry| {
        entry.length == 0
            || entry.base.checked_add(entry.length).is_none()
            || !(1..=4).contains(&entry.e820_type)
            || entry.extended_attributes & 1 == 0
    }) {
        return Err(LoaderAcpiConfigurationError::InvalidMemoryRange);
    }
    let required = loader_acpi_configuration_size(memory_map.len())
        .ok_or(LoaderAcpiConfigurationError::SizeOverflow)?;
    if output.len() < required {
        return Err(LoaderAcpiConfigurationError::BufferTooSmall);
    }
    output[..required].fill(0);

    // CM_PARTIAL_RESOURCE_LIST: Version, Revision, Count.
    output[4..8].copy_from_slice(&1u32.to_le_bytes());
    // CM_PARTIAL_RESOURCE_DESCRIPTOR: Type, ShareDisposition, Flags, and DeviceSpecificData.
    output[8] = 5; // CmResourceTypeDeviceSpecific
    let data_size = ACPI_BIOS_MULTI_NODE_HEADER_BYTES
        .checked_add(memory_map.len() * ACPI_E820_ENTRY_BYTES)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or(LoaderAcpiConfigurationError::SizeOverflow)?;
    output[12..16].copy_from_slice(&data_size.to_le_bytes());

    let node = CM_PARTIAL_RESOURCE_LIST_HEADER_BYTES + CM_PARTIAL_RESOURCE_DESCRIPTOR_BYTES;
    output[node..node + 8].copy_from_slice(&root_table_paddr.to_le_bytes());
    output[node + 8..node + 16].copy_from_slice(&(memory_map.len() as u64).to_le_bytes());
    for (index, entry) in memory_map.iter().enumerate() {
        let offset = node + ACPI_BIOS_MULTI_NODE_HEADER_BYTES + index * ACPI_E820_ENTRY_BYTES;
        output[offset..offset + 8].copy_from_slice(&entry.base.to_le_bytes());
        output[offset + 8..offset + 16].copy_from_slice(&entry.length.to_le_bytes());
        output[offset + 16..offset + 20].copy_from_slice(&entry.e820_type.to_le_bytes());
        output[offset + 20..offset + 24].copy_from_slice(&entry.extended_attributes.to_le_bytes());
    }
    Ok(required)
}

/// Test whether one `CONFIGURATION_COMPONENT` has the class, type, and optional key requested by
/// `KeFindConfigurationNextEntry`.
pub fn component_matches(
    component_class: u32,
    component_type: u32,
    component_key: u32,
    requested_class: u32,
    requested_type: u32,
    requested_key: Option<u32>,
) -> bool {
    component_class == requested_class
        && component_type == requested_type
        && requested_key.is_none_or(|key| component_key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_key_matches_the_nt_configuration_contract() {
        assert!(component_matches(3, 12, 7, 3, 12, None));
        assert!(component_matches(3, 12, 7, 3, 12, Some(7)));
        assert!(!component_matches(3, 12, 7, 3, 12, Some(8)));
        assert!(!component_matches(2, 12, 7, 3, 12, None));
        assert!(!component_matches(3, 11, 7, 3, 12, None));
    }

    #[test]
    fn acpi_loader_configuration_uses_the_amd64_descriptor_extent() {
        let ranges = [
            LoaderFirmwareMemoryRange {
                base: 0,
                length: 0x9f000,
                e820_type: 1,
                extended_attributes: 1,
            },
            LoaderFirmwareMemoryRange {
                base: 0x9f000,
                length: 0x1000,
                e820_type: 2,
                extended_attributes: 1,
            },
        ];
        let mut output = [0xa5; 96];
        let used = encode_loader_acpi_configuration(&mut output, 0x7ffe_0040, &ranges).unwrap();
        assert_eq!(used, 92);
        assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()), 1);
        assert_eq!(output[8], 5);
        assert_eq!(u32::from_le_bytes(output[12..16].try_into().unwrap()), 64);
        assert_eq!(
            u64::from_le_bytes(output[28..36].try_into().unwrap()),
            0x7ffe_0040
        );
        assert_eq!(u64::from_le_bytes(output[36..44].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(output[44..52].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(output[52..60].try_into().unwrap()),
            0x9f000
        );
        assert_eq!(u32::from_le_bytes(output[60..64].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(output[64..68].try_into().unwrap()), 1);
        assert_eq!(output[92..], [0xa5; 4]);
    }

    #[test]
    fn acpi_loader_configuration_rejects_missing_or_truncated_firmware_facts() {
        let range = LoaderFirmwareMemoryRange {
            base: 0,
            length: 0x1000,
            e820_type: 1,
            extended_attributes: 1,
        };
        let mut output = [0; LOADER_ACPI_CONFIGURATION_FIXED_BYTES + ACPI_E820_ENTRY_BYTES];
        assert_eq!(
            encode_loader_acpi_configuration(&mut output, 0, &[range]),
            Err(LoaderAcpiConfigurationError::MissingRootTable)
        );
        assert_eq!(
            encode_loader_acpi_configuration(&mut output, 0x1000, &[]),
            Err(LoaderAcpiConfigurationError::MissingMemoryMap)
        );
        let output_len = output.len();
        assert_eq!(
            encode_loader_acpi_configuration(&mut output[..output_len - 1], 0x1000, &[range]),
            Err(LoaderAcpiConfigurationError::BufferTooSmall)
        );
    }
}
