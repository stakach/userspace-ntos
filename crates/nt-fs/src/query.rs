//! Pure FILE_INFORMATION_CLASS encoders used by NtQueryInformationFile.

/// `FILE_BASIC_INFORMATION` is the class `kernel32!CreateDirectoryExW` queries on its TEMPLATE
/// directory handle (`dll/win32/kernel32/client/file/dir.c:246`) before it can create the copy —
/// the same class `NtSetInformationFile` already accepted, so it is shared from `status`.
use crate::{
    FILE_ACCESS_INFORMATION, FILE_ALIGNMENT_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFORMATION,
    FILE_BASIC_INFORMATION, FILE_DELETE_ON_CLOSE, FILE_INTERNAL_INFORMATION, FILE_MODE_INFORMATION,
    FILE_NETWORK_OPEN_INFORMATION, FILE_NO_INTERMEDIATE_BUFFERING, FILE_POSITION_INFORMATION,
    FILE_SEQUENTIAL_ONLY, FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT,
    FILE_WRITE_THROUGH, STATUS_BUFFER_OVERFLOW, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_INFO_CLASS, STATUS_SUCCESS,
};

pub const FILE_STANDARD_INFORMATION: u32 = 5;
/// `FileEaInformation` — the second class `CreateDirectoryExW` queries (`dir.c:381`), to size the
/// extended-attribute buffer it will hand `NtCreateFile`.
pub const FILE_EA_INFORMATION: u32 = 7;
pub const FILE_NAME_INFORMATION: u32 = 9;
pub const FILE_ALL_INFORMATION: u32 = 18;
pub const FILE_ALTERNATE_NAME_INFORMATION: u32 = 21;
pub const FILE_STREAM_INFORMATION: u32 = 22;
pub const FILE_COMPRESSION_INFORMATION: u32 = 28;
pub const FILE_OBJECT_ID_INFORMATION: u32 = 29;
pub const FILE_QUOTA_INFORMATION: u32 = 32;
pub const FILE_REPARSE_POINT_INFORMATION: u32 = 33;

pub const FILE_NAME_INFORMATION_MINIMUM_LENGTH: usize = 8;
pub const FILE_ALL_INFORMATION_MINIMUM_LENGTH: usize = 104;
pub const FILE_ALTERNATE_NAME_INFORMATION_MINIMUM_LENGTH: usize = 8;
pub const FILE_STREAM_INFORMATION_MINIMUM_LENGTH: usize = 32;
pub const FILE_COMPRESSION_INFORMATION_LENGTH: usize = 16;
pub const FILE_REPARSE_POINT_INFORMATION_LENGTH: usize = 16;
const FILE_ALL_NAME_LENGTH_OFFSET: usize = 96;
const FILE_ALL_NAME_OFFSET: usize = 100;
const FILE_STREAM_NAME_OFFSET: usize = 24;
const UNNAMED_DATA_STREAM: [u16; 7] = [
    b':' as u16,
    b':' as u16,
    b'$' as u16,
    b'D' as u16,
    b'A' as u16,
    b'T' as u16,
    b'A' as u16,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueryInformationResult {
    pub status: u32,
    pub information: usize,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryMetadata {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_id: u64,
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub current_byte_offset: u64,
    pub access_flags: u32,
    pub mode: u32,
    pub alignment_requirement: u32,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub directory: bool,
}

pub fn encode_query_information(
    class: u32,
    metadata: QueryMetadata,
    output: &mut [u8],
) -> Result<usize, u32> {
    let required = match class {
        FILE_BASIC_INFORMATION => 40,
        FILE_STANDARD_INFORMATION => 24,
        FILE_INTERNAL_INFORMATION => 8,
        FILE_EA_INFORMATION => 4,
        FILE_ACCESS_INFORMATION => 4,
        FILE_POSITION_INFORMATION => 8,
        FILE_MODE_INFORMATION => 4,
        FILE_ALIGNMENT_INFORMATION => 4,
        FILE_COMPRESSION_INFORMATION => FILE_COMPRESSION_INFORMATION_LENGTH,
        FILE_NETWORK_OPEN_INFORMATION => 56,
        FILE_ATTRIBUTE_TAG_INFORMATION => 8,
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    if output.len() < required {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    output[..required].fill(0);
    match class {
        // FILE_BASIC_INFORMATION { LARGE_INTEGER Creation/LastAccess/LastWrite/ChangeTime;
        //                          ULONG FileAttributes; ULONG (implicit x64 tail padding) }.
        FILE_BASIC_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.creation_time.to_le_bytes());
            output[8..16].copy_from_slice(&metadata.last_access_time.to_le_bytes());
            output[16..24].copy_from_slice(&metadata.last_write_time.to_le_bytes());
            output[24..32].copy_from_slice(&metadata.change_time.to_le_bytes());
            let attributes = normalized_file_attributes(metadata);
            output[32..36].copy_from_slice(&attributes.to_le_bytes());
        }
        FILE_STANDARD_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.allocation_size.to_le_bytes());
            output[8..16].copy_from_slice(&metadata.end_of_file.to_le_bytes());
            output[16..20].copy_from_slice(&metadata.number_of_links.to_le_bytes());
            output[20] = metadata.delete_pending as u8;
            output[21] = metadata.directory as u8;
        }
        // FILE_INTERNAL_INFORMATION { LARGE_INTEGER IndexNumber } is the filesystem's stable file
        // identity, not a process handle or FILE_OBJECT-table slot.
        FILE_INTERNAL_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.file_id.to_le_bytes());
        }
        // FILE_EA_INFORMATION { ULONG EaSize }. The volume genuinely carries no extended
        // attributes, so 0 is the true answer — and it is what makes `CreateDirectoryExW` skip its
        // `NtQueryEaFile` loop entirely rather than fail.
        FILE_EA_INFORMATION => {}
        // These three fields belong to the I/O Manager, not the filesystem driver: the handle's
        // grant, FILE_OBJECT mode flags, and related DEVICE_OBJECT alignment requirement.
        FILE_ACCESS_INFORMATION => {
            output[0..4].copy_from_slice(&metadata.access_flags.to_le_bytes());
        }
        // FILE_POSITION_INFORMATION { LARGE_INTEGER CurrentByteOffset }.
        FILE_POSITION_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.current_byte_offset.to_le_bytes());
        }
        FILE_MODE_INFORMATION => {
            output[0..4].copy_from_slice(&metadata.mode.to_le_bytes());
        }
        FILE_ALIGNMENT_INFORMATION => {
            output[0..4].copy_from_slice(&metadata.alignment_requirement.to_le_bytes());
        }
        // Local FAT and MemFs have no compressed backing. For an ordinary file the physical
        // representation is therefore its logical EOF; directories carry no data bytes.
        FILE_COMPRESSION_INFORMATION => {
            let compressed_size = if metadata.directory {
                0
            } else {
                metadata.end_of_file
            };
            output[0..8].copy_from_slice(&compressed_size.to_le_bytes());
            // CompressionFormat, all shifts, and Reserved remain zero (COMPRESSION_FORMAT_NONE).
        }
        FILE_NETWORK_OPEN_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.creation_time.to_le_bytes());
            output[8..16].copy_from_slice(&metadata.last_access_time.to_le_bytes());
            output[16..24].copy_from_slice(&metadata.last_write_time.to_le_bytes());
            output[24..32].copy_from_slice(&metadata.change_time.to_le_bytes());
            output[32..40].copy_from_slice(&metadata.allocation_size.to_le_bytes());
            output[40..48].copy_from_slice(&metadata.end_of_file.to_le_bytes());
            output[48..52].copy_from_slice(&normalized_file_attributes(metadata).to_le_bytes());
        }
        FILE_ATTRIBUTE_TAG_INFORMATION => {
            let attributes = normalized_file_attributes(metadata);
            let reparse_tag = if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                metadata.reparse_tag
            } else {
                0
            };
            output[0..4].copy_from_slice(&attributes.to_le_bytes());
            output[4..8].copy_from_slice(&reparse_tag.to_le_bytes());
        }
        _ => unreachable!(),
    }
    Ok(required)
}

/// Encode the single unnamed data stream supported by the local filesystems.
///
/// Stream information is a record list, so an undersized buffer cannot receive a partial record.
/// Directories have no data stream and truthfully return an empty list.
pub fn encode_stream_information(
    metadata: QueryMetadata,
    output: &mut [u8],
) -> Result<QueryInformationResult, u32> {
    if output.len() < FILE_STREAM_INFORMATION_MINIMUM_LENGTH {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    if metadata.directory {
        return Ok(QueryInformationResult {
            status: STATUS_SUCCESS,
            information: 0,
        });
    }

    let name_bytes = UNNAMED_DATA_STREAM.len() * 2;
    let required = FILE_STREAM_NAME_OFFSET + name_bytes;
    if output.len() < required {
        return Ok(QueryInformationResult {
            status: STATUS_BUFFER_OVERFLOW,
            information: 0,
        });
    }
    output[..required].fill(0);
    output[4..8].copy_from_slice(&(name_bytes as u32).to_le_bytes());
    output[8..16].copy_from_slice(&metadata.end_of_file.to_le_bytes());
    output[16..24].copy_from_slice(&metadata.allocation_size.to_le_bytes());
    for (index, unit) in UNNAMED_DATA_STREAM.iter().enumerate() {
        let offset = FILE_STREAM_NAME_OFFSET + index * 2;
        output[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(QueryInformationResult {
        status: STATUS_SUCCESS,
        information: required,
    })
}

/// Encode a reparse-point identity only when the filesystem metadata describes one.
pub fn encode_reparse_point_information(
    metadata: QueryMetadata,
    output: &mut [u8],
) -> Result<usize, u32> {
    if output.len() < FILE_REPARSE_POINT_INFORMATION_LENGTH {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    if metadata.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 || metadata.reparse_tag == 0 {
        return Err(crate::STATUS_NOT_A_REPARSE_POINT);
    }
    output[..FILE_REPARSE_POINT_INFORMATION_LENGTH].fill(0);
    output[0..8].copy_from_slice(&metadata.file_id.to_le_bytes());
    output[8..12].copy_from_slice(&metadata.reparse_tag.to_le_bytes());
    Ok(FILE_REPARSE_POINT_INFORMATION_LENGTH)
}

/// Return the filesystem completion for an optional query facility absent from local FAT/MemFs.
///
/// These are valid native information classes, so `STATUS_INVALID_INFO_CLASS` would incorrectly
/// attribute the failure to the I/O Manager contract. FastFAT rejects an unsupported query class
/// after dispatch with `STATUS_INVALID_PARAMETER`; neither local filesystem has the persistent
/// object-ID namespace or quota ledger required to return data instead.
pub const fn absent_optional_query_facility_status(class: u32) -> Option<u32> {
    match class {
        FILE_OBJECT_ID_INFORMATION | FILE_QUOTA_INFORMATION => {
            Some(crate::STATUS_INVALID_PARAMETER)
        }
        _ => None,
    }
}

/// Encode the variable-length file-name query classes.
///
/// `name` is the filesystem's volume-relative name including its leading `\`. The length field
/// always describes the complete UTF-16 name. When the caller's valid minimum-size buffer cannot
/// contain all of it, NT returns the prefix that fits with `STATUS_BUFFER_OVERFLOW` and reports the
/// number of bytes actually initialized.
pub fn encode_named_query_information(
    class: u32,
    metadata: QueryMetadata,
    name: &[u16],
    output: &mut [u8],
) -> Result<QueryInformationResult, u32> {
    let (minimum, name_length_offset, name_offset) = match class {
        FILE_NAME_INFORMATION => (FILE_NAME_INFORMATION_MINIMUM_LENGTH, 0, 4),
        FILE_ALTERNATE_NAME_INFORMATION => (FILE_ALTERNATE_NAME_INFORMATION_MINIMUM_LENGTH, 0, 4),
        FILE_ALL_INFORMATION => (
            FILE_ALL_INFORMATION_MINIMUM_LENGTH,
            FILE_ALL_NAME_LENGTH_OFFSET,
            FILE_ALL_NAME_OFFSET,
        ),
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    if output.len() < minimum {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }

    let name_bytes = name
        .len()
        .checked_mul(2)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
    let required = name_offset
        .checked_add(name_bytes as usize)
        .ok_or(STATUS_INFO_LENGTH_MISMATCH)?;
    let information = output.len().min(required);
    output[..information].fill(0);

    if class == FILE_ALL_INFORMATION {
        encode_query_information(FILE_BASIC_INFORMATION, metadata, &mut output[0..40])?;
        encode_query_information(FILE_STANDARD_INFORMATION, metadata, &mut output[40..64])?;
        encode_query_information(FILE_INTERNAL_INFORMATION, metadata, &mut output[64..72])?;
        encode_query_information(FILE_EA_INFORMATION, metadata, &mut output[72..76])?;
        encode_query_information(FILE_POSITION_INFORMATION, metadata, &mut output[80..88])?;
        encode_file_all_io_manager_information(metadata, output)?;
    }
    output[name_length_offset..name_length_offset + 4].copy_from_slice(&name_bytes.to_le_bytes());

    let mut cursor = name_offset;
    for unit in name {
        for byte in unit.to_le_bytes() {
            if cursor == information {
                break;
            }
            output[cursor] = byte;
            cursor += 1;
        }
        if cursor == information {
            break;
        }
    }

    Ok(QueryInformationResult {
        status: if information < required {
            STATUS_BUFFER_OVERFLOW
        } else {
            STATUS_SUCCESS
        },
        information,
    })
}

/// Seed the fields which the I/O Manager, rather than the filesystem provider, owns inside a
/// caller's `FILE_ALL_INFORMATION` buffer. The provider fills every other field through its real
/// `IRP_MJ_QUERY_INFORMATION` dispatch.
pub fn encode_file_all_io_manager_information(
    metadata: QueryMetadata,
    output: &mut [u8],
) -> Result<(), u32> {
    if output.len() < FILE_ALL_INFORMATION_MINIMUM_LENGTH {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    encode_query_information(FILE_ACCESS_INFORMATION, metadata, &mut output[76..80])?;
    encode_query_information(FILE_MODE_INFORMATION, metadata, &mut output[88..92])?;
    encode_query_information(FILE_ALIGNMENT_INFORMATION, metadata, &mut output[92..96])?;
    Ok(())
}

const fn normalized_file_attributes(metadata: QueryMetadata) -> u32 {
    if metadata.file_attributes != 0 {
        metadata.file_attributes
    } else if metadata.directory {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    }
}

/// Derive the `FILE_MODE_INFORMATION.Mode` value from the create options retained by the
/// `FILE_OBJECT`. This matches NT5's `IopGetFileMode`: options that do not become persistent
/// `FO_*` mode flags are intentionally omitted.
pub const fn file_mode_from_create_options(create_options: u32) -> u32 {
    create_options
        & (FILE_WRITE_THROUGH
            | FILE_SEQUENTIAL_ONLY
            | FILE_NO_INTERMEDIATE_BUFFERING
            | FILE_SYNCHRONOUS_IO_ALERT
            | FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_DELETE_ON_CLOSE)
}
