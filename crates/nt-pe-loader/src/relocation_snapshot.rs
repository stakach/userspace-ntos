//! Atomic checked relocation of an independently owned raw-file snapshot.

use alloc::vec::Vec;
use crate::{PeError, PeFile, RelocKind};

/// Validate every fixup before changing any bytes, then relocate the raw snapshot
/// and publish its new ImageBase. The canonical source must be copied by the caller.
pub fn relocate_file_snapshot(bytes: &mut [u8], load_base: u64) -> Result<(), PeError> {
    let pe = PeFile::parse(bytes)?;
    let delta = load_base.wrapping_sub(pe.image_base());
    if delta != 0 && pe.headers().characteristics & 1 != 0 {
        return Err(PeError::RelocationInvalid);
    }
    let base_offset = pe.headers().nt_offset.checked_add(48).ok_or(PeError::Truncated)?;
    let base_end = base_offset.checked_add(8).ok_or(PeError::Truncated)?;
    if base_end > pe.headers().size_of_headers as usize
        || base_end > pe.headers().size_of_image as usize
    {
        return Err(PeError::PatchOutOfBounds);
    }
    bytes.get(base_offset..base_end).ok_or(PeError::Truncated)?;
    let relocations = pe.relocations()?;
    let mut plan: Vec<(usize, RelocKind)> = Vec::new();
    plan.try_reserve_exact(relocations.len()).map_err(|_| PeError::InsufficientResources)?;
    for relocation in relocations {
        let width = relocation.kind.width();
        if width == 0 { continue; }
        let virtual_end = relocation.rva.checked_add(width as u32)
            .ok_or(PeError::PatchOutOfBounds)?;
        if virtual_end > pe.headers().size_of_image {
            return Err(PeError::PatchOutOfBounds);
        }
        let raw = pe.bytes_at_rva(relocation.rva, width).ok_or(PeError::PatchOutOfBounds)?;
        let offset = (raw.as_ptr() as usize).checked_sub(bytes.as_ptr() as usize)
            .ok_or(PeError::PatchOutOfBounds)?;
        let end = offset.checked_add(width).ok_or(PeError::PatchOutOfBounds)?;
        bytes.get(offset..end).ok_or(PeError::PatchOutOfBounds)?;
        plan.push((offset, relocation.kind));
    }
    // All parsing, range checks, and allocations precede this infallible write phase.
    for (offset, kind) in plan {
        kind.apply(&mut bytes[offset..offset + kind.width()], delta);
    }
    bytes[base_offset..base_end].copy_from_slice(&load_base.to_le_bytes());
    Ok(())
}
