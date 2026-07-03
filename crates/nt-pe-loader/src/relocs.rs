//! Base-relocation parsing (spec §7.2). Only `DIR64` (applied) and `ABSOLUTE`
//! (padding) are supported; any other type is rejected.

use alloc::vec::Vec;

use crate::headers::{Headers, Section, DIRECTORY_ENTRY_BASERELOC};
use crate::rva::rva_to_file_offset;
use crate::{u16_at, u32_at, PeError};

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RelocKind {
    /// Add the image delta to the 64-bit value at `rva`.
    Dir64,
    /// Padding entry (no-op).
    Absolute,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub rva: u32,
    pub kind: RelocKind,
}

pub fn parse_relocations(
    b: &[u8],
    headers: &Headers,
    sections: &[Section],
) -> Result<Vec<Relocation>, PeError> {
    let dir = headers.data_directory(DIRECTORY_ENTRY_BASERELOC);
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(Vec::new());
    }
    let base_off = rva_to_file_offset(sections, dir.virtual_address)?;
    let total = dir.size as usize;

    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= total {
        let block_off = base_off
            .checked_add(pos)
            .ok_or(PeError::RelocationInvalid)?;
        let page_va = u32_at(b, block_off)?;
        let block_size = u32_at(b, block_off + 4)? as usize;
        if block_size < 8 || pos + block_size > total {
            return Err(PeError::RelocationInvalid);
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry = u16_at(b, block_off + 8 + i * 2)?;
            let kind = (entry >> 12) & 0xf;
            let offset = (entry & 0x0fff) as u32;
            let rva = page_va
                .checked_add(offset)
                .ok_or(PeError::RelocationInvalid)?;
            match kind {
                IMAGE_REL_BASED_ABSOLUTE => out.push(Relocation {
                    rva,
                    kind: RelocKind::Absolute,
                }),
                IMAGE_REL_BASED_DIR64 => out.push(Relocation {
                    rva,
                    kind: RelocKind::Dir64,
                }),
                other => return Err(PeError::UnsupportedRelocation(other)),
            }
        }
        pos += block_size;
    }
    Ok(out)
}
