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

mod exports;
mod headers;
mod image;
mod imports;
mod relocs;
mod rva;

pub use exports::ExportedSymbol;
pub use headers::{
    DataDirectory, Headers, Section, DIRECTORY_ENTRY_EXPORT, DIRECTORY_ENTRY_RESOURCE,
    DIRECTORY_ENTRY_TLS,
};
pub use image::MappedImage;
pub use imports::{ImportRef, ImportedDll};
pub use relocs::{RelocKind, Relocation};

/// A valid `__security_cookie` (`/GS`) seed. MSVC's x64 `__security_check_cookie`
/// validates that the cookie's **top 16 bits are zero** (`rol rcx,0x10; test cx,0xffff`)
/// — the invariant `__security_init_cookie` guarantees by masking a generated cookie to
/// 48 bits. A seed with non-zero top bits (e.g. `0x1234_...`) makes every `/GS` epilogue
/// `__fastfail(2)`, but only on images whose codegen emits the high-bits check, so the
/// bug hides until a driver that has it runs. `GsDriverEntry` won't fix a non-default
/// seed (`__security_init_cookie` only generates when the value is still the CRT default).
pub const SECURITY_COOKIE_SEED: u64 = 0x0000_5678_9abc_def0;

/// The memory protection a mapped page should carry, for a W^X mapping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protection {
    /// Read-only data.
    ReadOnly,
    /// Writable data (never executable).
    ReadWrite,
    /// Executable code (read + execute, never writable).
    ReadExecute,
}

impl Protection {
    /// True if a page with this protection must be writable.
    pub fn writable(self) -> bool {
        matches!(self, Protection::ReadWrite)
    }
    /// True if a page with this protection is executable.
    pub fn executable(self) -> bool {
        matches!(self, Protection::ReadExecute)
    }
}

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
    /// The image subsystem (IMAGE_SUBSYSTEM_*: 1=NATIVE, 2=WINDOWS_GUI, 3=WINDOWS_CUI, …).
    pub fn subsystem(&self) -> u16 {
        self.headers.subsystem
    }
    /// The required subsystem version `(major, minor)`.
    pub fn subsystem_version(&self) -> (u16, u16) {
        (
            self.headers.major_subsystem_version,
            self.headers.minor_subsystem_version,
        )
    }

    /// Parse the import table (spec §7.2). Returns one [`ImportedDll`] per imported
    /// module with its named/ordinal functions + IAT slot RVAs.
    pub fn imports(&self) -> Result<alloc::vec::Vec<ImportedDll>, PeError> {
        imports::parse_imports(self.bytes, &self.headers, &self.sections)
    }

    /// Parse the export directory (spec §13.6). Returns the module's named exports with RVAs.
    pub fn exports(&self) -> Result<alloc::vec::Vec<ExportedSymbol>, PeError> {
        exports::parse_exports(self.bytes, &self.headers, &self.sections)
    }

    /// Read a NUL-terminated ASCII string at `rva` (via the section table). Used by the loader to
    /// read forwarder strings (`"TARGETDLL.func"`) out of the export directory.
    pub fn cstr_at_rva(&self, rva: u32) -> Result<alloc::string::String, PeError> {
        let raw = self.cstr_bytes_at_rva(rva)?;
        Ok(alloc::string::String::from_utf8_lossy(raw).into_owned())
    }

    /// Borrow a NUL-terminated byte string at `rva`, excluding the terminator. The returned slice
    /// points into the raw file and is followed by the validated NUL byte, which lets loader APIs
    /// pass the original ANSI import name to a callback without changing non-UTF-8 bytes.
    pub fn cstr_bytes_at_rva(&self, rva: u32) -> Result<&'a [u8], PeError> {
        if rva < self.headers.size_of_headers {
            const MAX_NAME_LEN: usize = 512;
            let start = rva as usize;
            let header_end = (self.headers.size_of_headers as usize).min(self.bytes.len());
            let bytes = self.bytes.get(start..header_end).ok_or(PeError::Truncated)?;
            let end = bytes
                .iter()
                .take(MAX_NAME_LEN + 1)
                .position(|byte| *byte == 0)
                .ok_or(PeError::ImportTableInvalid)?;
            return Ok(&bytes[..end]);
        }
        rva::cstr_at_rva(self.bytes, &self.sections, rva)
    }

    /// True if the image has a TLS directory (data dir 9) — its TLS callbacks must run around
    /// `DLL_PROCESS_ATTACH`. The loader records this; invoking the callbacks is a live seam.
    pub fn has_tls_directory(&self) -> bool {
        let dir = self.headers.data_directory(headers::DIRECTORY_ENTRY_TLS);
        dir.virtual_address != 0 && dir.size != 0
    }

    /// Read `len` raw file bytes at `rva` (via the section table), without materialising a full
    /// mapped image — enough to inspect an export's code (e.g. a syscall stub).
    pub fn bytes_at_rva(&self, rva: u32, len: usize) -> Option<&'a [u8]> {
        let length = u32::try_from(len).ok()?;
        let end_rva = rva.checked_add(length)?;
        if rva < self.headers.size_of_headers && end_rva <= self.headers.size_of_headers {
            return self.bytes.get(rva as usize..end_rva as usize);
        }
        let section = self.sections.iter().find(|section| {
            let delta = rva.checked_sub(section.virtual_address);
            delta.is_some_and(|delta| {
                delta <= section.size_of_raw_data
                    && length <= section.size_of_raw_data.saturating_sub(delta)
            })
        })?;
        let delta = rva - section.virtual_address;
        let off = (section.pointer_to_raw_data as usize).checked_add(delta as usize)?;
        let end = off.checked_add(len)?;
        self.bytes.get(off..end)
    }

    /// Parse the base-relocation table (spec §7.2).
    pub fn relocations(&self) -> Result<alloc::vec::Vec<Relocation>, PeError> {
        relocs::parse_relocations(self.bytes, &self.headers, &self.sections)
    }

    /// The RVA of the image's `__security_cookie` (`/GS`), read from the load-config
    /// data directory's `SecurityCookie` VA (offset 88). `None` if the image has no
    /// load config / cookie. The MSVC `GsDriverEntry` wrapper fastfails if this word
    /// is left 0, so a loader must seed it before calling `DriverEntry`.
    pub fn security_cookie_rva(&self) -> Option<u32> {
        let dir = self
            .headers
            .data_directory(headers::DIRECTORY_ENTRY_LOAD_CONFIG);
        if dir.virtual_address == 0 || dir.size < 96 {
            return None;
        }
        let cookie_va =
            rva::u64_at_rva(self.bytes, &self.sections, dir.virtual_address + 88).ok()?;
        if cookie_va == 0 {
            return None;
        }
        u32::try_from(cookie_va.checked_sub(self.headers.image_base)?).ok()
    }

    /// Seed the image's `__security_cookie` at `code_vaddr + security_cookie_rva()` with
    /// a valid `/GS` cookie ([`SECURITY_COOKIE_SEED`]), the last step before calling
    /// `DriverEntry`. Returns `true` if the image had a cookie to seed. Centralizing this
    /// keeps the cookie's top-16-bits-zero invariant in one place — a hand-written seed
    /// with non-zero top bits fastfails only on the MSVC codegen that emits the high-bits
    /// check, so the drift is otherwise invisible.
    ///
    /// # Safety
    /// `code_vaddr` must be the base of the image's mapped, writable code region.
    pub unsafe fn seed_security_cookie(&self, code_vaddr: u64) -> bool {
        match self.security_cookie_rva() {
            Some(rva) => {
                core::ptr::write_unaligned(
                    (code_vaddr + rva as u64) as *mut u64,
                    SECURITY_COOKIE_SEED,
                );
                true
            }
            None => false,
        }
    }

    /// The memory protection a page at `rva` should get (from its section's
    /// characteristics) — the basis for a W^X mapping (executable code + read-only
    /// data are not writable; only writable data stays writable).
    pub fn protection_at(&self, rva: u32) -> Protection {
        for s in &self.sections {
            let start = s.virtual_address;
            let size = s.virtual_size.max(s.size_of_raw_data);
            if rva >= start && rva - start < size {
                if s.is_executable() {
                    return Protection::ReadExecute;
                }
                if s.is_writable() {
                    return Protection::ReadWrite;
                }
                return Protection::ReadOnly;
            }
        }
        Protection::ReadOnly // headers / gaps
    }

    /// Map the image into a fresh buffer at `load_base`, copying headers +
    /// sections and applying base relocations (spec §7.2, §9). The result is ready
    /// for import patching + execution.
    pub fn map(&self, load_base: u64) -> Result<MappedImage, PeError> {
        MappedImage::build(self, load_base)
    }
}
