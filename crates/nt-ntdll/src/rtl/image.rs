//! Image-helper `Rtl*` stragglers — **reuse** [`nt_pe_loader`].
//!
//! `RtlImageNtHeader` / `RtlImageDirectoryEntryToData` / `RtlImageRvaToVa` /
//! `RtlImageRvaToSection` / `RtlPcToFileHeader` parse a mapped PE image. These map directly onto
//! [`nt_pe_loader::PeFile`] (host-tested there) — we provide the ntdll-named wrappers so binaries
//! resolve them against our ntdll without a second PE parser. Operates over the mapped image bytes;
//! the RVA→VA helpers take the mapped base.

use nt_pe_loader::{PeError, PeFile};

/// The PE data-directory indices (`IMAGE_DIRECTORY_ENTRY_*`) used by `RtlImageDirectoryEntryToData`.
pub mod directory {
    /// `IMAGE_DIRECTORY_ENTRY_EXPORT`.
    pub const EXPORT: usize = 0;
    /// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
    pub const IMPORT: usize = 1;
    /// `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
    pub const RESOURCE: usize = 2;
    /// `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (`.pdata`).
    pub const EXCEPTION: usize = 3;
    /// `IMAGE_DIRECTORY_ENTRY_BASERELOC`.
    pub const BASERELOC: usize = 5;
    /// `IMAGE_DIRECTORY_ENTRY_TLS`.
    pub const TLS: usize = 9;
    /// `IMAGE_DIRECTORY_ENTRY_IAT`.
    pub const IAT: usize = 12;
}

/// A parsed image header view — the ntdll `RtlImageNtHeader` result over an image's bytes.
#[derive(Clone, Debug)]
pub struct ImageInfo {
    /// The preferred image base.
    pub image_base: u64,
    /// The AddressOfEntryPoint RVA.
    pub entry_point_rva: u32,
    /// The virtual size of the mapped image.
    pub size_of_image: u32,
    /// The subsystem id.
    pub subsystem: u16,
}

/// `RtlImageNtHeader(Base)` — validate + parse the PE headers, returning the load-bearing header
/// fields. `None` if `bytes` is not a valid PE32+ image.
pub fn image_nt_header(bytes: &[u8]) -> Option<ImageInfo> {
    let pe = PeFile::parse(bytes).ok()?;
    Some(ImageInfo {
        image_base: pe.image_base(),
        entry_point_rva: pe.entry_point_rva(),
        size_of_image: pe.size_of_image(),
        subsystem: pe.subsystem(),
    })
}

/// `RtlImageDirectoryEntryToData(Base, MappedAsImage, DirectoryEntry, Size*)` — the `(rva, size)` of
/// a data directory (e.g. `directory::EXPORT`, `directory::EXCEPTION`). `None` if the directory is
/// absent (rva == 0) or the index is out of range.
pub fn image_directory_entry(bytes: &[u8], index: usize) -> Option<(u32, u32)> {
    if index >= 16 {
        return None;
    }
    let pe = PeFile::parse(bytes).ok()?;
    let d = pe.headers().data_directory(index);
    if d.virtual_address == 0 || d.size == 0 {
        None
    } else {
        Some((d.virtual_address, d.size))
    }
}

/// `RtlImageRvaToVa(NtHeaders, Base, Rva)` — resolve an RVA to a mapped virtual address given the
/// image's load base. For a mapped image this is simply `load_base + rva` when the RVA is within the
/// image; `None` if the RVA is past the image size.
pub fn image_rva_to_va(bytes: &[u8], load_base: u64, rva: u32) -> Option<u64> {
    let pe = PeFile::parse(bytes).ok()?;
    if rva < pe.size_of_image() {
        Some(load_base + rva as u64)
    } else {
        None
    }
}

/// `RtlImageRvaToSection` — the section name covering `rva`, if any.
pub fn image_rva_to_section(bytes: &[u8], rva: u32) -> Option<alloc::string::String> {
    let pe = PeFile::parse(bytes).ok()?;
    for s in pe.sections() {
        let end = s.virtual_address + s.virtual_size.max(s.size_of_raw_data);
        if rva >= s.virtual_address && rva < end {
            return Some(s.name_str().into());
        }
    }
    None
}

/// `RtlPcToFileHeader(PcValue, BaseOfImage*)` — given a control PC and the image's `[base, base+size)`
/// range, return the image base if the PC falls within it (the caller supplies the candidate image).
/// Returns `None` if the PC is outside the image.
pub fn pc_to_file_header(bytes: &[u8], load_base: u64, pc: u64) -> Option<u64> {
    let pe = PeFile::parse(bytes).ok()?;
    let end = load_base + pe.size_of_image() as u64;
    if pc >= load_base && pc < end {
        Some(load_base)
    } else {
        None
    }
}

/// Parse a PE image, surfacing the [`PeError`] (for callers that want the error, not `Option`).
pub fn parse(bytes: &[u8]) -> Result<PeFile<'_>, PeError> {
    PeFile::parse(bytes)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec::Vec;

    /// Build a minimal valid PE32+ image: DOS stub + NT headers + one section, enough for the
    /// nt-pe-loader parser (which is exercised in its own crate; here we just confirm the wrappers
    /// route + return the header fields).
    fn minimal_pe() -> Vec<u8> {
        // 4 KiB buffer.
        let mut b = alloc::vec![0u8; 0x400];
        // DOS header: "MZ" + e_lfanew at 0x3C -> 0x80.
        b[0] = b'M';
        b[1] = b'Z';
        let nt = 0x80usize;
        b[0x3C..0x40].copy_from_slice(&(nt as u32).to_le_bytes());
        // PE signature.
        b[nt..nt + 4].copy_from_slice(b"PE\0\0");
        // COFF header @ nt+4: Machine (0x8664), NumberOfSections=1, SizeOfOptionalHeader=0xF0,
        // Characteristics.
        let coff = nt + 4;
        b[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        b[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes()); // EXECUTABLE|LARGE_ADDR
        // Optional header @ coff+20.
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        b[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // ImageBase
        b[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        b[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        b[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        b[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem = CONSOLE
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        // Section table @ opt + 0xF0.
        let sec = opt + 0xF0;
        b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        b[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        b[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ
        b
    }

    #[test]
    fn nt_header_fields() {
        let img = minimal_pe();
        let info = image_nt_header(&img).expect("valid PE");
        assert_eq!(info.image_base, 0x1_4000_0000);
        assert_eq!(info.entry_point_rva, 0x1000);
        assert_eq!(info.size_of_image, 0x4000);
        assert_eq!(info.subsystem, 3);
    }

    #[test]
    fn rejects_non_pe() {
        assert!(image_nt_header(b"not a pe").is_none());
    }

    #[test]
    fn rva_to_va_and_section() {
        let img = minimal_pe();
        assert_eq!(image_rva_to_va(&img, 0x1_4000_0000, 0x1000), Some(0x1_4000_1000));
        // Past the image size → None.
        assert!(image_rva_to_va(&img, 0x1_4000_0000, 0x9000).is_none());
        assert_eq!(image_rva_to_section(&img, 0x1000).as_deref(), Some(".text"));
        assert!(image_rva_to_section(&img, 0x8000).is_none());
    }

    #[test]
    fn pc_to_file_header_range() {
        let img = minimal_pe();
        assert_eq!(pc_to_file_header(&img, 0x1_4000_0000, 0x1_4000_1500), Some(0x1_4000_0000));
        assert!(pc_to_file_header(&img, 0x1_4000_0000, 0x1_5000_0000).is_none());
    }
}
