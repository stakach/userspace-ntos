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
    FILE_WRITE_THROUGH, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS,
};

pub const FILE_STANDARD_INFORMATION: u32 = 5;
/// `FileEaInformation` — the second class `CreateDirectoryExW` queries (`dir.c:381`), to size the
/// extended-attribute buffer it will hand `NtCreateFile`.
pub const FILE_EA_INFORMATION: u32 = 7;

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
