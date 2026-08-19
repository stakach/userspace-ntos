//! Export-directory parsing (spec §13.6). Lists a module's named exports with their RVAs +
//! ordinals — enough to locate `ntdll`'s `Nt*` syscall stubs.

use alloc::string::String;
use alloc::vec::Vec;

use crate::headers::{Headers, Section, DIRECTORY_ENTRY_EXPORT};
use crate::rva::{cstr_at_rva, u16_at_rva, u32_at_rva};
use crate::PeError;

const MAX_EXPORTS: u32 = 65_536;

/// One named export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedSymbol {
    pub name: String,
    /// The export's RVA (a function/forwarder address within the image).
    pub rva: u32,
    pub ordinal: u16,
}

/// Parse the export directory (IMAGE_EXPORT_DIRECTORY, data dir 0). Returns the named exports in
/// name order. Forwarders (RVA inside the export directory range) are included with their RVA.
pub fn parse_exports(
    bytes: &[u8],
    headers: &Headers,
    sections: &[Section],
) -> Result<Vec<ExportedSymbol>, PeError> {
    let dir = headers.data_directory(DIRECTORY_ENTRY_EXPORT);
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(Vec::new());
    }
    let base = dir.virtual_address;
    // IMAGE_EXPORT_DIRECTORY layout.
    let ordinal_base = u32_at_rva(bytes, sections, base + 16)?;
    let number_of_functions = u32_at_rva(bytes, sections, base + 20)?;
    let number_of_names = u32_at_rva(bytes, sections, base + 24)?;
    let address_of_functions = u32_at_rva(bytes, sections, base + 28)?;
    let address_of_names = u32_at_rva(bytes, sections, base + 32)?;
    let address_of_name_ordinals = u32_at_rva(bytes, sections, base + 36)?;

    if number_of_names > MAX_EXPORTS || number_of_functions > MAX_EXPORTS {
        return Err(PeError::ImportTableInvalid);
    }

    let mut out = Vec::with_capacity(number_of_names as usize);
    for i in 0..number_of_names {
        let name_rva = u32_at_rva(bytes, sections, address_of_names + i * 4)?;
        let name = cstr_at_rva(bytes, sections, name_rva)?;
        // The name's index into AddressOfNameOrdinals gives the function-table index.
        let func_index = u16_at_rva(bytes, sections, address_of_name_ordinals + i * 2)?;
        let func_rva = u32_at_rva(
            bytes,
            sections,
            address_of_functions + func_index as u32 * 4,
        )?;
        out.push(ExportedSymbol {
            name: String::from_utf8_lossy(name).into_owned(),
            rva: func_rva,
            ordinal: (ordinal_base as u16).wrapping_add(func_index),
        });
    }
    Ok(out)
}

/// Look up one named export without materializing the full export table.
///
/// This is the path the kernel should use when it needs a handful of loader entry points from a
/// large user-mode DLL. It walks the same AddressOfNames/AddressOfNameOrdinals/AddressOfFunctions
/// tables as [`parse_exports`], but borrows each export name directly from the image.
pub fn export_rva_by_name(
    bytes: &[u8],
    headers: &Headers,
    sections: &[Section],
    target: &str,
) -> Result<Option<u32>, PeError> {
    let dir = headers.data_directory(DIRECTORY_ENTRY_EXPORT);
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(None);
    }
    let base = dir.virtual_address;
    let number_of_functions = u32_at_rva(bytes, sections, base + 20)?;
    let number_of_names = u32_at_rva(bytes, sections, base + 24)?;
    let address_of_functions = u32_at_rva(bytes, sections, base + 28)?;
    let address_of_names = u32_at_rva(bytes, sections, base + 32)?;
    let address_of_name_ordinals = u32_at_rva(bytes, sections, base + 36)?;

    if number_of_names > MAX_EXPORTS || number_of_functions > MAX_EXPORTS {
        return Err(PeError::ImportTableInvalid);
    }

    let target = target.as_bytes();
    for i in 0..number_of_names {
        let name_rva = u32_at_rva(bytes, sections, address_of_names + i * 4)?;
        let name = cstr_at_rva(bytes, sections, name_rva)?;
        if name != target {
            continue;
        }
        let func_index = u16_at_rva(bytes, sections, address_of_name_ordinals + i * 2)?;
        if func_index as u32 >= number_of_functions {
            return Err(PeError::ImportTableInvalid);
        }
        return Ok(Some(u32_at_rva(
            bytes,
            sections,
            address_of_functions + func_index as u32 * 4,
        )?));
    }
    Ok(None)
}
