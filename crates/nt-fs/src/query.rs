//! Pure FILE_INFORMATION_CLASS encoders used by NtQueryInformationFile.

/// `FILE_BASIC_INFORMATION` is the class `kernel32!CreateDirectoryExW` queries on its TEMPLATE
/// directory handle (`dll/win32/kernel32/client/file/dir.c:246`) before it can create the copy —
/// the same class `NtSetInformationFile` already accepted, so it is shared from `status`.
use crate::{
    FILE_BASIC_INFORMATION, FILE_POSITION_INFORMATION, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_INFO_CLASS,
};

pub const FILE_STANDARD_INFORMATION: u32 = 5;
/// `FileEaInformation` — the second class `CreateDirectoryExW` queries (`dir.c:381`), to size the
/// extended-attribute buffer it will hand `NtCreateFile`.
pub const FILE_EA_INFORMATION: u32 = 7;

/// `FILE_ATTRIBUTE_DIRECTORY` / `FILE_ATTRIBUTE_NORMAL` — the only two attribute shapes a volume
/// with no read-only/hidden/system metadata can honestly report.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryMetadata {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub current_byte_offset: u64,
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
        FILE_EA_INFORMATION => 4,
        FILE_POSITION_INFORMATION => 8,
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    if output.len() < required {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    output[..required].fill(0);
    match class {
        // FILE_BASIC_INFORMATION { LARGE_INTEGER Creation/LastAccess/LastWrite/ChangeTime;
        //                          ULONG FileAttributes; ULONG (implicit x64 tail padding) }.
        // The four timestamps stay ZERO — a zero time in this structure means "no value" to every
        // NT caller (`NtSetInformationFile` documents it as "do not change"), which is the honest
        // answer for a volume that does not track them. The ATTRIBUTES are real.
        FILE_BASIC_INFORMATION => {
            let attributes = if metadata.directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            output[32..36].copy_from_slice(&attributes.to_le_bytes());
        }
        FILE_STANDARD_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.allocation_size.to_le_bytes());
            output[8..16].copy_from_slice(&metadata.end_of_file.to_le_bytes());
            output[16..20].copy_from_slice(&metadata.number_of_links.to_le_bytes());
            output[20] = metadata.delete_pending as u8;
            output[21] = metadata.directory as u8;
        }
        // FILE_EA_INFORMATION { ULONG EaSize }. The volume genuinely carries no extended
        // attributes, so 0 is the true answer — and it is what makes `CreateDirectoryExW` skip its
        // `NtQueryEaFile` loop entirely rather than fail.
        FILE_EA_INFORMATION => {}
        // FILE_POSITION_INFORMATION { LARGE_INTEGER CurrentByteOffset }.
        FILE_POSITION_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.current_byte_offset.to_le_bytes());
        }
        _ => unreachable!(),
    }
    Ok(required)
}
