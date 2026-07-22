//! Pure FILE_INFORMATION_CLASS encoders used by NtQueryInformationFile.

use crate::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

pub const FILE_STANDARD_INFORMATION: u32 = 5;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryMetadata {
    pub allocation_size: u64,
    pub end_of_file: u64,
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
        FILE_STANDARD_INFORMATION => 24,
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    };
    if output.len() < required {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    output[..required].fill(0);
    match class {
        FILE_STANDARD_INFORMATION => {
            output[0..8].copy_from_slice(&metadata.allocation_size.to_le_bytes());
            output[8..16].copy_from_slice(&metadata.end_of_file.to_le_bytes());
            output[16..20].copy_from_slice(&metadata.number_of_links.to_le_bytes());
            output[20] = metadata.delete_pending as u8;
            output[21] = metadata.directory as u8;
        }
        _ => unreachable!(),
    }
    Ok(required)
}
