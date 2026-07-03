//! # `nt-pe-loader` — a checked PE32+/x86_64 kernel-image loader
//!
//! Parse, validate, map, relocate, and list the imports of a Windows kernel-mode
//! PE image (a `.sys` driver), so a Driver Host can load it. **Every** access is
//! bounds-checked and every failure is a structured [`PeError`] — a malformed
//! image returns an error, never panics or executes (spec §7.2). `no_std` +
//! `alloc`, no `unsafe`. PE32+/x86_64 only; x86/ARM64, TLS, resources, packed
//! images, and unsupported relocations are rejected.

#![no_std]

extern crate alloc;

mod headers;
mod image;
mod imports;
mod relocs;
mod rva;

pub use headers::{DataDirectory, Headers, Section};
pub use image::MappedImage;
pub use imports::{ImportRef, ImportedDll};
pub use relocs::{RelocKind, Relocation};

/// A structured PE-loader error. No parse path panics; every failure is one of
/// these.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeError {
    /// A read ran past the end of the buffer.
    Truncated,
    /// The DOS `MZ` signature is missing.
    BadDosSignature,
    /// The PE `PE\0\0` signature is missing.
    BadNtSignature,
    /// The machine type is not `IMAGE_FILE_MACHINE_AMD64`.
    UnsupportedMachine(u16),
    /// The optional header is not `PE32+`.
    NotPe32Plus(u16),
    /// An implausible section count.
    TooManySections(u16),
    /// A section's raw/virtual extents are out of bounds.
    SectionOutOfBounds,
    /// An RVA does not fall within any section.
    BadRva(u32),
    /// `SizeOfImage` is implausible / would overflow.
    BadImageSize,
    /// The import table is malformed.
    ImportTableInvalid,
    /// The base-relocation table is malformed.
    RelocationInvalid,
    /// A base-relocation type this loader does not implement (only `DIR64` +
    /// `ABSOLUTE` are supported).
    UnsupportedRelocation(u16),
    /// A relocation / IAT patch target is out of the mapped image.
    PatchOutOfBounds,
}

// --- bounded readers (never panic) -----------------------------------------

pub(crate) fn u16_at(b: &[u8], off: usize) -> Result<u16, PeError> {
    let s = b.get(off..off.checked_add(2).ok_or(PeError::Truncated)?);
    s.map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(PeError::Truncated)
}

pub(crate) fn u32_at(b: &[u8], off: usize) -> Result<u32, PeError> {
    let s = b.get(off..off.checked_add(4).ok_or(PeError::Truncated)?);
    s.map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(PeError::Truncated)
}

pub(crate) fn u64_at(b: &[u8], off: usize) -> Result<u64, PeError> {
    let s = b.get(off..off.checked_add(8).ok_or(PeError::Truncated)?);
    s.map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or(PeError::Truncated)
}

pub(crate) fn bytes_at(b: &[u8], off: usize, len: usize) -> Result<&[u8], PeError> {
    let end = off.checked_add(len).ok_or(PeError::Truncated)?;
    b.get(off..end).ok_or(PeError::Truncated)
}

/// A parsed (but not yet mapped) PE image, borrowing the raw file bytes.
pub struct PeFile<'a> {
    bytes: &'a [u8],
    headers: Headers,
    sections: alloc::vec::Vec<Section>,
}

impl core::fmt::Debug for PeFile<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeFile")
            .field("entry_point_rva", &self.headers.entry_point_rva)
            .field("image_base", &self.headers.image_base)
            .field("size_of_image", &self.headers.size_of_image)
            .field("sections", &self.sections.len())
            .finish()
    }
}

impl<'a> PeFile<'a> {
    /// Parse + validate the headers and section table of `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<PeFile<'a>, PeError> {
        let headers = Headers::parse(bytes)?;
        let mut sections = alloc::vec::Vec::with_capacity(headers.number_of_sections as usize);
        let table = headers.section_table_offset();
        for i in 0..headers.number_of_sections as usize {
            sections.push(Section::parse(bytes, table + i * 40)?);
        }
        Ok(PeFile {
            bytes,
            headers,
            sections,
        })
    }

    /// The raw file bytes.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
    pub fn headers(&self) -> &Headers {
        &self.headers
    }
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }
    /// The preferred load address from the optional header.
    pub fn image_base(&self) -> u64 {
        self.headers.image_base
    }
    /// The virtual size of the mapped image.
    pub fn size_of_image(&self) -> u32 {
        self.headers.size_of_image
    }
    /// The entry-point RVA (`DriverEntry`).
    pub fn entry_point_rva(&self) -> u32 {
        self.headers.entry_point_rva
    }

    /// Parse the import table (spec §7.2). Returns one [`ImportedDll`] per imported
    /// module with its named/ordinal functions + IAT slot RVAs.
    pub fn imports(&self) -> Result<alloc::vec::Vec<ImportedDll>, PeError> {
        imports::parse_imports(self.bytes, &self.headers, &self.sections)
    }

    /// Parse the base-relocation table (spec §7.2).
    pub fn relocations(&self) -> Result<alloc::vec::Vec<Relocation>, PeError> {
        relocs::parse_relocations(self.bytes, &self.headers, &self.sections)
    }

    /// Map the image into a fresh buffer at `load_base`, copying headers +
    /// sections and applying base relocations (spec §7.2, §9). The result is ready
    /// for import patching + execution.
    pub fn map(&self, load_base: u64) -> Result<MappedImage, PeError> {
        MappedImage::build(self, load_base)
    }
}
