//! DOS + PE/COFF + optional-header + section-table parsing (spec §7.2).

use crate::{u16_at, u32_at, u64_at, PeError};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;

pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;

/// Data-directory indices.
pub const DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;

/// Section characteristics (subset).
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
#[allow(dead_code)] // documented PE constant, not consulted yet
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const MAX_SECTIONS: u16 = 96;

/// An `IMAGE_DATA_DIRECTORY` entry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// The validated PE headers.
#[derive(Clone, Debug)]
pub struct Headers {
    pub nt_offset: usize,
    pub machine: u16,
    pub number_of_sections: u16,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
    pub magic: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: [DataDirectory; 16],
}

impl Headers {
    /// Parse + validate the DOS, NT, and optional headers of `b`.
    pub fn parse(b: &[u8]) -> Result<Headers, PeError> {
        if u16_at(b, 0)? != IMAGE_DOS_SIGNATURE {
            return Err(PeError::BadDosSignature);
        }
        let nt_offset = u32_at(b, 0x3C)? as usize;
        if u32_at(b, nt_offset)? != IMAGE_NT_SIGNATURE {
            return Err(PeError::BadNtSignature);
        }

        // File (COFF) header at nt_offset + 4.
        let fh = nt_offset.checked_add(4).ok_or(PeError::Truncated)?;
        let machine = u16_at(b, fh)?;
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeError::UnsupportedMachine(machine));
        }
        let number_of_sections = u16_at(b, fh + 2)?;
        if number_of_sections > MAX_SECTIONS {
            return Err(PeError::TooManySections(number_of_sections));
        }
        let size_of_optional_header = u16_at(b, fh + 16)?;
        let characteristics = u16_at(b, fh + 18)?;

        // Optional header (PE32+) at fh + 20.
        let oh = fh.checked_add(20).ok_or(PeError::Truncated)?;
        let magic = u16_at(b, oh)?;
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(PeError::NotPe32Plus(magic));
        }
        let entry_point_rva = u32_at(b, oh + 16)?;
        let image_base = u64_at(b, oh + 24)?;
        let section_alignment = u32_at(b, oh + 32)?;
        let file_alignment = u32_at(b, oh + 36)?;
        let size_of_image = u32_at(b, oh + 56)?;
        let size_of_headers = u32_at(b, oh + 60)?;
        let subsystem = u16_at(b, oh + 68)?;
        let number_of_rva_and_sizes = u32_at(b, oh + 108)?;

        let mut data_directories = [DataDirectory::default(); 16];
        let count = (number_of_rva_and_sizes as usize).min(16);
        for (i, dir) in data_directories.iter_mut().enumerate().take(count) {
            let dd = oh + 112 + i * 8;
            *dir = DataDirectory {
                virtual_address: u32_at(b, dd)?,
                size: u32_at(b, dd + 4)?,
            };
        }

        Ok(Headers {
            nt_offset,
            machine,
            number_of_sections,
            size_of_optional_header,
            characteristics,
            magic,
            entry_point_rva,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem,
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    /// The data directory at `index` (empty if out of range).
    pub fn data_directory(&self, index: usize) -> DataDirectory {
        self.data_directories
            .get(index)
            .copied()
            .unwrap_or_default()
    }

    /// File offset of the section table (after the optional header).
    pub fn section_table_offset(&self) -> usize {
        self.nt_offset + 24 + self.size_of_optional_header as usize
    }

    /// True if the file is marked executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0
    }
}

/// An `IMAGE_SECTION_HEADER` (40 bytes).
#[derive(Copy, Clone, Debug)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn parse(b: &[u8], offset: usize) -> Result<Section, PeError> {
        let name_bytes = crate::bytes_at(b, offset, 8)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(name_bytes);
        Ok(Section {
            name,
            virtual_size: u32_at(b, offset + 8)?,
            virtual_address: u32_at(b, offset + 12)?,
            size_of_raw_data: u32_at(b, offset + 16)?,
            pointer_to_raw_data: u32_at(b, offset + 20)?,
            characteristics: u32_at(b, offset + 36)?,
        })
    }

    /// The section name (trailing NULs trimmed).
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("<?>")
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
    pub fn is_uninitialized(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }
}
