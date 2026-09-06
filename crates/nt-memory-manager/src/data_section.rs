//! File-backed section admission and exact EOF-bounded page reads.

use crate::{STATUS_INVALID_PAGE_PROTECTION, STATUS_SECTION_TOO_BIG};

pub const STATUS_MAPPED_FILE_SIZE_ZERO: u32 = 0xc000_011e;
pub const STATUS_INVALID_FILE_FOR_SECTION: u32 = 0xc000_0020;
pub const STATUS_IO_DEVICE_ERROR: u32 = 0xc000_0185;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
const STATUS_END_OF_FILE: u32 = 0xc000_0011;
pub const DATA_PAGE_SIZE: usize = 0x1000;
/// NT5's data-section extent bound, independent of the size of any individual mapped view.
pub const MAX_DATA_SECTION_SIZE: u64 = (1u64 << 54) - DATA_PAGE_SIZE as u64;

/// NT5 MmMakeFileAccess: private copy-on-write needs no write access to the file.
pub fn data_section_file_access(protection: u32) -> Result<u32, u32> {
    match protection {
        0x02 | 0x08 => Ok(0x01),
        0x04 => Ok(0x03),
        0x10 => Ok(0x20),
        0x20 | 0x80 => Ok(0x21),
        0x40 => Ok(0x23),
        _ => Err(STATUS_INVALID_PAGE_PROTECTION),
    }
}

pub fn check_data_section_file_access(protection: u32, mut granted: u32) -> Result<(), u32> {
    let required = data_section_file_access(protection)?;
    // Expand only the data/execute rights needed by this operation. Generic write does not read.
    if granted & 0x1000_0000 != 0 {
        granted |= 0x23;
    }
    if granted & 0x8000_0000 != 0 {
        granted |= 0x01;
    }
    if granted & 0x4000_0000 != 0 {
        granted |= 0x02;
    }
    if granted & 0x2000_0000 != 0 {
        granted |= 0x20;
    }
    if granted & required != required {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataSectionFileInfo {
    pub end_of_file: u64,
    pub is_directory: bool,
    pub read_only_volume: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataSectionFileExtent {
    pub section_size: u64,
    pub file_size: u64,
}

pub trait DataSectionFileIo {
    fn query_file(&mut self) -> Result<DataSectionFileInfo, u32>;
    fn extend_file(&mut self, size: u64) -> Result<(), u32>;
}

/// Complete real file sizing before the caller can publish a section object or retain its backing.
pub fn prepare_data_section_file(
    maximum_size: u64,
    protection: u32,
    granted_access: u32,
    io: &mut impl DataSectionFileIo,
) -> Result<DataSectionFileExtent, u32> {
    check_data_section_file_access(protection, granted_access)?;
    let mut info = io.query_file()?;
    if info.is_directory {
        return Err(STATUS_INVALID_FILE_FOR_SECTION);
    }
    if info.read_only_volume && matches!(protection, 0x04 | 0x40) {
        return Err(0xc000_00a2); // STATUS_MEDIA_WRITE_PROTECTED
    }
    if info.end_of_file > MAX_DATA_SECTION_SIZE {
        return Err(STATUS_SECTION_TOO_BIG);
    }
    let section_size = if maximum_size == 0 {
        info.end_of_file
    } else {
        maximum_size
    };
    if section_size == 0 {
        return Err(STATUS_MAPPED_FILE_SIZE_ZERO);
    }
    if section_size > MAX_DATA_SECTION_SIZE && section_size <= i64::MAX as u64 {
        return Err(STATUS_SECTION_TOO_BIG);
    }
    if section_size > info.end_of_file {
        if !matches!(protection, 0x04 | 0x40) {
            return Err(STATUS_SECTION_TOO_BIG);
        }
        if section_size > i64::MAX as u64 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        io.extend_file(section_size)?;
        info = io.query_file()?;
        if info.is_directory
            || info.read_only_volume
            || info.end_of_file < section_size
            || info.end_of_file > MAX_DATA_SECTION_SIZE
        {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
    }
    Ok(DataSectionFileExtent {
        section_size,
        file_size: info.end_of_file,
    })
}

pub trait DataSectionReadIo {
    /// Return actual accepted bytes. Only a complete successful prefix may become a resident page.
    fn read(&mut self, offset: u64, output: &mut [u8]) -> (u32, usize);
}

/// Read the file prefix exactly; zero only the remainder of its final partial page. A whole page
/// past current EOF is an error (for example after truncation), not an anonymous zero-page fallback.
pub fn read_data_section_page(
    page_index: u64,
    section_size: u64,
    file_size: u64,
    output: &mut [u8; DATA_PAGE_SIZE],
    io: &mut impl DataSectionReadIo,
) -> Result<(), u32> {
    let offset = page_index
        .checked_mul(DATA_PAGE_SIZE as u64)
        .filter(|offset| *offset < section_size)
        .ok_or(crate::STATUS_INVALID_VIEW_SIZE)?;
    let length = file_size
        .checked_sub(offset)
        .filter(|length| *length != 0)
        .ok_or(STATUS_END_OF_FILE)?
        .min(DATA_PAGE_SIZE as u64) as usize;
    output.fill(0);
    let (status, read) = io.read(offset, &mut output[..length]);
    if status != 0 {
        return Err(status);
    }
    if read != length {
        return Err(STATUS_IO_DEVICE_ERROR);
    }
    Ok(())
}

#[cfg(test)]
#[path = "data_section_tests.rs"]
mod tests;
