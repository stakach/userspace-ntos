//! Driver-facing PE image directory queries.

use super::*;

/// `PVOID RtlImageDirectoryEntryToData(PVOID, BOOLEAN, USHORT, PULONG)`.
/// The driver image and its linked support images occupy the component's
/// mapped code aperture. The PE parser bounds the directory to the mapped
/// image; a raw-file view is not an owned image in this aperture.
pub(super) extern "win64" fn image_directory_entry_to_data(
    tagged_base: u64,
    mapped_as_image: u8,
    directory: u16,
    size: u64,
) -> u64 {
    if size == 0 || size.checked_add(4).is_none() || mapped_as_image == 0 || tagged_base & 1 != 0 {
        return 0;
    }
    let base = tagged_base;
    if base & 0xfff != 0 || base < FSD_CODE_VA || base >= FSD_POOL_VADDR {
        return 0;
    }
    let aperture = (FSD_POOL_VADDR - base) as usize;
    if aperture < 4096 {
        return 0;
    }
    let header = unsafe { core::slice::from_raw_parts(base as *const u8, 4096) };
    let Ok(pe) = nt_pe_loader::PeFile::parse(header) else {
        return 0;
    };
    let image_len = pe.size_of_image() as usize;
    if image_len < 4096 || image_len > aperture {
        return 0;
    }
    let image = unsafe { core::slice::from_raw_parts(base as *const u8, image_len) };
    let Ok(Some((offset, length))) =
        nt_pe_loader::image_directory_entry(image, true, directory as usize)
    else {
        return 0;
    };
    let Some(address) = base.checked_add(offset as u64) else {
        return 0;
    };
    unsafe { write_unaligned(size as *mut u32, length); }
    address
}
