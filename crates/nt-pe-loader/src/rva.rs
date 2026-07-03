//! RVA (relative virtual address) → file-offset translation (spec §7.2).

use crate::headers::Section;
use crate::{u16_at, u32_at, u64_at, PeError};

const MAX_NAME_LEN: usize = 512;

/// Translate an RVA to a file offset via the section table. An RVA that falls in
/// a section's uninitialised (BSS) tail, or in no section, is [`PeError::BadRva`].
pub fn rva_to_file_offset(sections: &[Section], rva: u32) -> Result<usize, PeError> {
    for s in sections {
        let start = s.virtual_address;
        let vsize = s.virtual_size.max(s.size_of_raw_data);
        if rva >= start && rva - start < vsize {
            let delta = rva - start;
            if delta >= s.size_of_raw_data {
                return Err(PeError::BadRva(rva)); // no backing file data
            }
            return (s.pointer_to_raw_data as usize)
                .checked_add(delta as usize)
                .ok_or(PeError::BadRva(rva));
        }
    }
    Err(PeError::BadRva(rva))
}

pub fn u16_at_rva(b: &[u8], sections: &[Section], rva: u32) -> Result<u16, PeError> {
    u16_at(b, rva_to_file_offset(sections, rva)?)
}
pub fn u32_at_rva(b: &[u8], sections: &[Section], rva: u32) -> Result<u32, PeError> {
    u32_at(b, rva_to_file_offset(sections, rva)?)
}
pub fn u64_at_rva(b: &[u8], sections: &[Section], rva: u32) -> Result<u64, PeError> {
    u64_at(b, rva_to_file_offset(sections, rva)?)
}

/// Read a NUL-terminated ASCII string at `rva` (bounded).
pub fn cstr_at_rva<'a>(b: &'a [u8], sections: &[Section], rva: u32) -> Result<&'a [u8], PeError> {
    let off = rva_to_file_offset(sections, rva)?;
    let slice = b.get(off..).ok_or(PeError::Truncated)?;
    let end = slice
        .iter()
        .take(MAX_NAME_LEN + 1)
        .position(|&c| c == 0)
        .ok_or(PeError::ImportTableInvalid)?;
    Ok(&slice[..end])
}
