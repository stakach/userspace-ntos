//! Import-descriptor parsing (spec §7.2). Lists imported DLLs + their named /
//! ordinal functions and each function's IAT slot RVA (for later patching).

use alloc::string::String;
use alloc::vec::Vec;

use crate::headers::{Headers, Section, DIRECTORY_ENTRY_IMPORT};
use crate::rva::{cstr_at_rva, u16_at_rva, u32_at_rva, u64_at_rva};
use crate::PeError;

const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
const MAX_DLLS: usize = 256;
const MAX_FUNCS: u32 = 8192;

/// One imported function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportRef {
    /// Imported by name (`Hint`/`Name`); `iat_slot_rva` is where the resolved
    /// address is written.
    ByName {
        name: String,
        hint: u16,
        iat_slot_rva: u32,
    },
    /// Imported by ordinal.
    ByOrdinal { ordinal: u16, iat_slot_rva: u32 },
}

impl ImportRef {
    pub fn iat_slot_rva(&self) -> u32 {
        match self {
            ImportRef::ByName { iat_slot_rva, .. } | ImportRef::ByOrdinal { iat_slot_rva, .. } => {
                *iat_slot_rva
            }
        }
    }
}

/// One imported module + its functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedDll {
    pub name: String,
    pub functions: Vec<ImportRef>,
}

pub fn parse_imports(
    b: &[u8],
    headers: &Headers,
    sections: &[Section],
) -> Result<Vec<ImportedDll>, PeError> {
    let dir = headers.data_directory(DIRECTORY_ENTRY_IMPORT);
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut desc_rva = dir.virtual_address;
    loop {
        // IMAGE_IMPORT_DESCRIPTOR (20 bytes).
        let original_first_thunk = u32_at_rva(b, sections, desc_rva)?;
        let name_rva = u32_at_rva(
            b,
            sections,
            desc_rva
                .checked_add(12)
                .ok_or(PeError::ImportTableInvalid)?,
        )?;
        let first_thunk = u32_at_rva(
            b,
            sections,
            desc_rva
                .checked_add(16)
                .ok_or(PeError::ImportTableInvalid)?,
        )?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break; // null terminator
        }

        let name = String::from_utf8_lossy(cstr_at_rva(b, sections, name_rva)?).into_owned();
        // Prefer the import lookup table; fall back to the (bound) IAT.
        let thunk_table = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        let mut functions = Vec::new();
        let mut i: u32 = 0;
        loop {
            let thunk_rva = thunk_table + i * 8;
            let iat_slot_rva = first_thunk + i * 8;
            let thunk = u64_at_rva(b, sections, thunk_rva)?;
            if thunk == 0 {
                break;
            }
            if thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                functions.push(ImportRef::ByOrdinal {
                    ordinal: (thunk & 0xffff) as u16,
                    iat_slot_rva,
                });
            } else {
                // IMAGE_IMPORT_BY_NAME: Hint (u16) + NUL-terminated Name.
                let by_name_rva = thunk as u32;
                let hint = u16_at_rva(b, sections, by_name_rva)?;
                let fn_name = cstr_at_rva(b, sections, by_name_rva + 2)?;
                functions.push(ImportRef::ByName {
                    name: String::from_utf8_lossy(fn_name).into_owned(),
                    hint,
                    iat_slot_rva,
                });
            }
            i += 1;
            if i > MAX_FUNCS {
                return Err(PeError::ImportTableInvalid);
            }
        }

        out.push(ImportedDll { name, functions });
        desc_rva = desc_rva
            .checked_add(20)
            .ok_or(PeError::ImportTableInvalid)?;
        if out.len() > MAX_DLLS {
            return Err(PeError::ImportTableInvalid);
        }
    }
    Ok(out)
}
