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
