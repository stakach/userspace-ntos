//! Resident image lookup for the hosted `MmPageEntireDriver` export.

use super::hosted_exception_images;

/// Hosted driver images are already resident for their exact component-domain lifetime. The
/// sealed, read-only snapshot is mapped only into that domain and retains admitted image extents
/// for the same lifetime as the image frame caps. A missing image returns NULL, as on NT.
pub(super) unsafe fn page_entire_driver(address_within_section: u64) -> u64 {
    unsafe {
        hosted_exception_images::with_component_view(|view| {
            view.image_base_containing(address_within_section)
        })
        .flatten()
        .unwrap_or(0)
    }
}

fn image_base_at(base: u64) -> bool {
    unsafe {
        hosted_exception_images::with_component_view(|view| {
            view.image_base_containing(base) == Some(base)
        })
        .unwrap_or(false)
    }
}

fn invalid_section(address: u64, phase: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [0x4d4d_4c4b, address, phase, 0]); }
}

/// `PVOID MmLockPagableDataSection(PVOID AddressWithinSection)` (also the code-section form).
/// The resident image is already locked for its domain lifetime; the handle names that image.
/// An address outside every loaded image has no section to lock.
pub(super) extern "win64" fn lock_pagable_data_section(address_within_section: u64) -> u64 {
    match unsafe { page_entire_driver(address_within_section) } {
        0 => invalid_section(address_within_section, 1),
        base => base,
    }
}

/// `VOID MmLockPagableSectionByHandle(PVOID ImageSectionHandle)`.
pub(super) extern "win64" fn lock_pagable_section_by_handle(handle: u64) {
    if !image_base_at(handle) { invalid_section(handle, 2); }
}

/// `VOID MmUnlockPagableImageSection(PVOID ImageSectionHandle)`. The image stays resident for
/// its domain lifetime, so only a handle naming a loaded image is accepted.
pub(super) extern "win64" fn unlock_pagable_image_section(handle: u64) {
    if !image_base_at(handle) { invalid_section(handle, 3); }
}
