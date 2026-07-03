//! The image-mapping model (spec §7.2, §9): allocate `SizeOfImage`, copy headers
//! + sections into their virtual addresses, and apply base relocations.

use alloc::vec;
use alloc::vec::Vec;

use crate::relocs::RelocKind;
use crate::{PeError, PeFile};

const MAX_IMAGE_SIZE: usize = 256 * 1024 * 1024;

/// A PE image mapped into a fresh buffer at `load_base`, sections placed at their
/// virtual addresses + base relocations applied. Ready for IAT patching + (in the
/// Driver Host) execution.
pub struct MappedImage {
    pub bytes: Vec<u8>,
    pub load_base: u64,
    pub entry_rva: u32,
}

impl MappedImage {
    pub(crate) fn build(pe: &PeFile, load_base: u64) -> Result<MappedImage, PeError> {
        let size = pe.size_of_image() as usize;
        if size == 0 || size > MAX_IMAGE_SIZE {
            return Err(PeError::BadImageSize);
        }
        let mut bytes = vec![0u8; size];

        // Headers.
        let hdr_len = (pe.headers().size_of_headers as usize)
            .min(pe.bytes().len())
            .min(size);
        bytes[..hdr_len].copy_from_slice(&pe.bytes()[..hdr_len]);

        // Sections (uninitialised / no-raw-data sections stay zeroed).
        for s in pe.sections() {
            if s.is_uninitialized() || s.size_of_raw_data == 0 {
                continue;
            }
            let raw = crate::bytes_at(
                pe.bytes(),
                s.pointer_to_raw_data as usize,
                s.size_of_raw_data as usize,
            )?;
            let va = s.virtual_address as usize;
            let end = va
                .checked_add(raw.len())
                .ok_or(PeError::SectionOutOfBounds)?;
            let dst = bytes.get_mut(va..end).ok_or(PeError::SectionOutOfBounds)?;
            dst.copy_from_slice(raw);
        }

        let mut img = MappedImage {
            bytes,
            load_base,
            entry_rva: pe.entry_point_rva(),
        };
        img.apply_relocations(pe)?;
        Ok(img)
    }

    fn apply_relocations(&mut self, pe: &PeFile) -> Result<(), PeError> {
        let delta = self.load_base.wrapping_sub(pe.image_base());
        if delta == 0 {
            return Ok(());
        }
        for r in pe.relocations()? {
            if r.kind != RelocKind::Dir64 {
                continue;
            }
            let off = r.rva as usize;
            let end = off.checked_add(8).ok_or(PeError::PatchOutOfBounds)?;
            let cur = {
                let s = self.bytes.get(off..end).ok_or(PeError::PatchOutOfBounds)?;
                u64::from_le_bytes(s.try_into().unwrap())
            };
            self.bytes[off..end].copy_from_slice(&cur.wrapping_add(delta).to_le_bytes());
        }
        Ok(())
    }

    /// The absolute entry point (`load_base + entry_rva`) — `DriverEntry`.
    pub fn entry_point(&self) -> u64 {
        self.load_base.wrapping_add(self.entry_rva as u64)
    }

    /// Patch an IAT slot at `slot_rva` to a resolved trampoline `addr` (spec §9
    /// step 8). Called by the Driver Host once exports are resolved.
    pub fn patch_iat(&mut self, slot_rva: u32, addr: u64) -> Result<(), PeError> {
        let off = slot_rva as usize;
        let end = off.checked_add(8).ok_or(PeError::PatchOutOfBounds)?;
        let dst = self
            .bytes
            .get_mut(off..end)
            .ok_or(PeError::PatchOutOfBounds)?;
        dst.copy_from_slice(&addr.to_le_bytes());
        Ok(())
    }

    /// Read the 64-bit value at `rva` (for tests / verification).
    pub fn u64_at_rva(&self, rva: u32) -> Result<u64, PeError> {
        crate::u64_at(&self.bytes, rva as usize)
    }
}
