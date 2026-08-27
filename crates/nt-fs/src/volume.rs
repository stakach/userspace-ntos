//! Pure `FS_INFORMATION_CLASS` encoders for filesystem-owned volume metadata.

use crate::{
    QueryInformationResult, STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_INFO_CLASS, STATUS_SUCCESS,
};

pub const FILE_FS_VOLUME_INFORMATION: u32 = 1;
pub const FILE_FS_LABEL_INFORMATION: u32 = 2;
pub const FILE_FS_SIZE_INFORMATION: u32 = 3;
pub const FILE_FS_DEVICE_INFORMATION: u32 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
pub const FILE_FS_CONTROL_INFORMATION: u32 = 6;
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;
pub const FILE_FS_OBJECTID_INFORMATION: u32 = 8;
pub const FILE_FS_DRIVER_PATH_INFORMATION: u32 = 9;

pub const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
pub const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
pub const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;
pub const FILE_DEVICE_DISK: u32 = 0x0000_0007;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VolumeSizeInformation {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VolumeControlInformation {
    pub free_space_start_filtering: i64,
    pub free_space_threshold: i64,
    pub free_space_stop_filtering: i64,
    pub default_quota_threshold: i64,
    pub default_quota_limit: i64,
    pub file_system_control_flags: u32,
}

/// Metadata owned by one mounted filesystem volume. Optional facilities remain
/// absent until the filesystem has a real implementation for them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VolumeMetadata<'a> {
    pub creation_time: i64,
    pub serial_number: u32,
    pub supports_objects: bool,
    pub label: &'a [u16],
    pub device_type: u32,
    pub device_characteristics: u32,
    pub file_system_attributes: u32,
    pub maximum_component_name_length: u32,
    pub file_system_name: &'a [u16],
    pub size: Option<VolumeSizeInformation>,
    pub control: Option<VolumeControlInformation>,
    pub object_id: Option<&'a [u8; 64]>,
}

fn write_utf16_prefix(units: &[u16], output: &mut [u8]) -> usize {
    let count = units.len().min(output.len() / 2);
    for (index, unit) in units[..count].iter().enumerate() {
        output[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    count * 2
}

/// Encode an FSD-owned query-volume result. `FileFsDriverPathInformation` is
/// intentionally excluded because NT5 answers it in the I/O Manager.
pub fn encode_query_volume_information(
    class: u32,
    metadata: VolumeMetadata<'_>,
    output: &mut [u8],
) -> Result<QueryInformationResult, u32> {
    let minimum = match class {
        FILE_FS_VOLUME_INFORMATION => 24,
        FILE_FS_SIZE_INFORMATION => 24,
        FILE_FS_DEVICE_INFORMATION => 8,
        FILE_FS_ATTRIBUTE_INFORMATION => 16,
        FILE_FS_CONTROL_INFORMATION => 48,
        FILE_FS_FULL_SIZE_INFORMATION => 32,
        FILE_FS_OBJECTID_INFORMATION => 64,
        FILE_FS_DRIVER_PATH_INFORMATION => return Err(STATUS_INVALID_DEVICE_REQUEST),
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    if output.len() < minimum {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    output[..minimum].fill(0);

    let (status, information) = match class {
        FILE_FS_VOLUME_INFORMATION => {
            const LABEL_OFFSET: usize = 18;
            output[0..8].copy_from_slice(&metadata.creation_time.to_le_bytes());
            output[8..12].copy_from_slice(&metadata.serial_number.to_le_bytes());
            let label_length = metadata
                .label
                .len()
                .checked_mul(2)
                .and_then(|length| u32::try_from(length).ok())
                .ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
            output[12..16].copy_from_slice(&label_length.to_le_bytes());
            output[16] = metadata.supports_objects as u8;
            let copied = write_utf16_prefix(metadata.label, &mut output[LABEL_OFFSET..]);
            (
                if copied == label_length as usize {
                    STATUS_SUCCESS
                } else {
                    STATUS_BUFFER_OVERFLOW
                },
                LABEL_OFFSET + copied,
            )
        }
        FILE_FS_SIZE_INFORMATION => {
            let size = metadata.size.ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
            output[0..8].copy_from_slice(&size.total_allocation_units.to_le_bytes());
            output[8..16].copy_from_slice(&size.available_allocation_units.to_le_bytes());
            output[16..20].copy_from_slice(&size.sectors_per_allocation_unit.to_le_bytes());
            output[20..24].copy_from_slice(&size.bytes_per_sector.to_le_bytes());
            (STATUS_SUCCESS, 24)
        }
        FILE_FS_DEVICE_INFORMATION => {
            output[0..4].copy_from_slice(&metadata.device_type.to_le_bytes());
            output[4..8].copy_from_slice(&metadata.device_characteristics.to_le_bytes());
            (STATUS_SUCCESS, 8)
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            const NAME_OFFSET: usize = 12;
            output[0..4].copy_from_slice(&metadata.file_system_attributes.to_le_bytes());
            output[4..8].copy_from_slice(&metadata.maximum_component_name_length.to_le_bytes());
            let name_length = metadata
                .file_system_name
                .len()
                .checked_mul(2)
                .and_then(|length| u32::try_from(length).ok())
                .ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
            let copied = write_utf16_prefix(metadata.file_system_name, &mut output[NAME_OFFSET..]);
            output[8..12].copy_from_slice(&name_length.to_le_bytes());
            (
                if copied == name_length as usize {
                    STATUS_SUCCESS
                } else {
                    STATUS_BUFFER_OVERFLOW
                },
                NAME_OFFSET + copied,
            )
        }
        FILE_FS_CONTROL_INFORMATION => {
            let control = metadata.control.ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
            output[0..8].copy_from_slice(&control.free_space_start_filtering.to_le_bytes());
            output[8..16].copy_from_slice(&control.free_space_threshold.to_le_bytes());
            output[16..24].copy_from_slice(&control.free_space_stop_filtering.to_le_bytes());
            output[24..32].copy_from_slice(&control.default_quota_threshold.to_le_bytes());
            output[32..40].copy_from_slice(&control.default_quota_limit.to_le_bytes());
            output[40..44].copy_from_slice(&control.file_system_control_flags.to_le_bytes());
            (STATUS_SUCCESS, 48)
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            let size = metadata.size.ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
            output[0..8].copy_from_slice(&size.total_allocation_units.to_le_bytes());
            output[8..16].copy_from_slice(&size.available_allocation_units.to_le_bytes());
            output[16..24].copy_from_slice(&size.available_allocation_units.to_le_bytes());
            output[24..28].copy_from_slice(&size.sectors_per_allocation_unit.to_le_bytes());
            output[28..32].copy_from_slice(&size.bytes_per_sector.to_le_bytes());
            (STATUS_SUCCESS, 32)
        }
        FILE_FS_OBJECTID_INFORMATION => {
            let object_id = metadata.object_id.ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
            output[..64].copy_from_slice(object_id);
            (STATUS_SUCCESS, 64)
        }
        _ => unreachable!(),
    };
    Ok(QueryInformationResult {
        status,
        information,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: [u16; 5] = [
        b'S' as u16,
        b'Y' as u16,
        b'S' as u16,
        b'T' as u16,
        b'M' as u16,
    ];
    const FS_NAME: [u16; 5] = [
        b'F' as u16,
        b'A' as u16,
        b'T' as u16,
        b'3' as u16,
        b'2' as u16,
    ];

    fn metadata<'a>() -> VolumeMetadata<'a> {
        VolumeMetadata {
            creation_time: 0,
            serial_number: 0x1234_5678,
            supports_objects: false,
            label: &LABEL,
            device_type: FILE_DEVICE_DISK,
            device_characteristics: FILE_DEVICE_IS_MOUNTED,
            file_system_attributes: FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK,
            maximum_component_name_length: 255,
            file_system_name: &FS_NAME,
            size: Some(VolumeSizeInformation {
                total_allocation_units: 4096,
                available_allocation_units: 1024,
                sectors_per_allocation_unit: 8,
                bytes_per_sector: 512,
            }),
            control: None,
            object_id: None,
        }
    }

    #[test]
    fn encodes_volume_identity_and_reports_full_label_length() {
        let mut output = [0xaa; 32];
        let result = encode_query_volume_information(1, metadata(), &mut output).unwrap();
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(result.information, 28);
        assert_eq!(
            u32::from_le_bytes(output[8..12].try_into().unwrap()),
            0x1234_5678
        );
        assert_eq!(u32::from_le_bytes(output[12..16].try_into().unwrap()), 10);
        assert_eq!(&output[18..28], b"S\0Y\0S\0T\0M\0");

        let mut short = [0u8; 24];
        let result = encode_query_volume_information(1, metadata(), &mut short).unwrap();
        assert_eq!(result.status, STATUS_BUFFER_OVERFLOW);
        assert_eq!(result.information, 24);
        assert_eq!(u32::from_le_bytes(short[12..16].try_into().unwrap()), 10);
    }

    #[test]
    fn encodes_real_size_device_and_attributes() {
        let mut output = [0u8; 32];
        assert_eq!(
            encode_query_volume_information(3, metadata(), &mut output)
                .unwrap()
                .information,
            24
        );
        assert_eq!(u64::from_le_bytes(output[0..8].try_into().unwrap()), 4096);
        assert_eq!(u64::from_le_bytes(output[8..16].try_into().unwrap()), 1024);

        let result = encode_query_volume_information(4, metadata(), &mut output).unwrap();
        assert_eq!(result.information, 8);
        assert_eq!(u32::from_le_bytes(output[0..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()), 0x20);

        let result = encode_query_volume_information(5, metadata(), &mut output).unwrap();
        assert_eq!(result.information, 22);
        assert_eq!(u32::from_le_bytes(output[8..12].try_into().unwrap()), 10);
        assert_eq!(&output[12..22], b"F\0A\0T\03\02\0");

        let mut short = [0u8; 16];
        let result = encode_query_volume_information(5, metadata(), &mut short).unwrap();
        assert_eq!(result.status, STATUS_BUFFER_OVERFLOW);
        assert_eq!(result.information, 16);
        assert_eq!(u32::from_le_bytes(short[8..12].try_into().unwrap()), 10);
    }

    #[test]
    fn optional_facilities_fail_instead_of_synthesizing_data() {
        let mut output = [0u8; 64];
        assert_eq!(
            encode_query_volume_information(6, metadata(), &mut output),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
        assert_eq!(
            encode_query_volume_information(8, metadata(), &mut output),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
        assert_eq!(
            encode_query_volume_information(9, metadata(), &mut output),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
    }

    #[test]
    fn rejects_short_and_invalid_query_buffers() {
        assert_eq!(
            encode_query_volume_information(4, metadata(), &mut [0u8; 7]),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(
            encode_query_volume_information(2, metadata(), &mut [0u8; 8]),
            Err(STATUS_INVALID_INFO_CLASS)
        );
    }
}
