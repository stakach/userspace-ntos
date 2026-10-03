//! Checked base-relocation parsing and NT fixup arithmetic.

use alloc::vec::Vec;

use crate::headers::{Headers, Section, DIRECTORY_ENTRY_BASERELOC};
use crate::rva::rva_to_file_offset;
use crate::{u16_at, u32_at, PeError};

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RelocKind {
    High,
    Low,
    HighLow,
    /// Add the image delta to the 64-bit value at `rva`.
    Dir64,
    /// Padding entry (no-op).
    Absolute,
}

impl RelocKind {
    pub(crate) const fn width(self) -> usize {
        match self {
            Self::Absolute => 0,
            Self::High | Self::Low => 2,
            Self::HighLow => 4,
            Self::Dir64 => 8,
        }
    }

    pub(crate) fn apply(self, target: &mut [u8], delta: u64) {
        match self {
            Self::Absolute => {}
            Self::High | Self::Low => {
                let value = u16::from_le_bytes(target.try_into().unwrap());
                let addend = if self == Self::High { (delta >> 16) as u16 } else { delta as u16 };
                target.copy_from_slice(&value.wrapping_add(addend).to_le_bytes());
            }
            Self::HighLow => {
                let value = u32::from_le_bytes(target.try_into().unwrap());
                target.copy_from_slice(&value.wrapping_add(delta as u32).to_le_bytes());
            }
            Self::Dir64 => {
                let value = u64::from_le_bytes(target.try_into().unwrap());
                target.copy_from_slice(&value.wrapping_add(delta).to_le_bytes());
            }
        }
    }
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
    let directory_end = dir.virtual_address.checked_add(dir.size)
        .ok_or(PeError::RelocationInvalid)?;
    if directory_end > headers.size_of_image {
        return Err(PeError::RelocationInvalid);
    }
    let base_off = rva_to_file_offset(sections, dir.virtual_address)?;
    let total = dir.size as usize;
    let section = sections.iter().find(|section| {
        dir.virtual_address.checked_sub(section.virtual_address).is_some_and(|offset| {
            offset <= section.size_of_raw_data && dir.size <= section.size_of_raw_data - offset
        })
    }).ok_or(PeError::RelocationInvalid)?;
    let expected_off = (section.pointer_to_raw_data as usize)
        .checked_add((dir.virtual_address - section.virtual_address) as usize)
        .ok_or(PeError::RelocationInvalid)?;
    if base_off != expected_off { return Err(PeError::RelocationInvalid); }
    let end = base_off.checked_add(total).ok_or(PeError::RelocationInvalid)?;
    let directory = b.get(base_off..end).ok_or(PeError::RelocationInvalid)?;

    let mut out = Vec::new();
    out.try_reserve_exact(total / 2).map_err(|_| PeError::InsufficientResources)?;
    let mut pos = 0usize;
    while pos < total {
        if total - pos < 8 { return Err(PeError::RelocationInvalid); }
        let page_va = u32_at(directory, pos)?;
        let block_size = u32_at(directory, pos + 4)? as usize;
        if block_size < 8 || block_size % 2 != 0 || block_size > total - pos {
            return Err(PeError::RelocationInvalid);
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry = u16_at(directory, pos + 8 + i * 2)?;
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
                1 => out.push(Relocation { rva, kind: RelocKind::High }),
                2 => out.push(Relocation { rva, kind: RelocKind::Low }),
                3 => out.push(Relocation { rva, kind: RelocKind::HighLow }),
                other => return Err(PeError::UnsupportedRelocation(other)),
            }
        }
        pos += block_size;
    }
    Ok(out)
}

fn rva_range_intersects_page(rva: u32, len: u32, page_start: u32) -> bool {
    let Some(end) = rva.checked_add(len) else {
        return true;
    };
    let Some(page_end) = page_start.checked_add(0x1000) else {
        return true;
    };
    rva < page_end && end > page_start
}

/// True when any relocation target lives on the 4 KiB page containing `page_rva`.
///
/// This avoids allocating a full relocation vector in the SEC_IMAGE fault path. The real relocation
/// applier remains stricter through [`parse_relocations`]; this predicate only classifies pages the
/// loader may write, so an otherwise unsupported relocation kind still makes its own page private
/// without poisoning unrelated pages.
pub fn page_has_relocation(
    b: &[u8],
    headers: &Headers,
    sections: &[Section],
    page_rva: u32,
) -> Result<bool, PeError> {
    let dir = headers.data_directory(DIRECTORY_ENTRY_BASERELOC);
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(false);
    }
    let base_off = rva_to_file_offset(sections, dir.virtual_address)?;
    let total = dir.size as usize;
    let page_start = page_rva & !0x0fffu32;

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
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => {
                    if rva_range_intersects_page(rva, 8, page_start) {
                        return Ok(true);
                    }
                }
                _ => {
                    if rva_range_intersects_page(rva, 8, page_start) {
                        return Ok(true);
                    }
                }
            }
        }
        pos += block_size;
    }
    Ok(false)
}
