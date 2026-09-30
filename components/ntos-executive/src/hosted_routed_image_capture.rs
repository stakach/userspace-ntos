//! Exact routed FILE_OBJECT ownership for native image areas.

use crate::driver_launch::hosted_file_capture::Capture;
use nt_memory_manager::image_section::ImageAreaId;
use nt_memory_manager::RoutedSectionLease;
use nt_user_host::routed_section_owner::RoutedSectionOwners;

static mut OWNERS: RoutedSectionOwners<Capture, ImageAreaId> = RoutedSectionOwners::new();

pub(crate) unsafe fn reserve(capture: Capture) -> Result<RoutedSectionLease, Capture> {
    let _durable = crate::allocator::enter_durable();
    (&mut *core::ptr::addr_of_mut!(OWNERS)).reserve(capture)
}

pub(crate) unsafe fn bind(lease: RoutedSectionLease, area: ImageAreaId) -> bool {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).bind(lease, area)
}

pub(crate) unsafe fn route(lease: RoutedSectionLease, area: ImageAreaId) -> Option<(u64, u64, u64, u32)> {
    (&*core::ptr::addr_of!(OWNERS))
        .get(lease, area)
        .map(|capture| (capture.file_id(), capture.device_id(), capture.fs_context(), capture.granted_access()))
}

pub(crate) unsafe fn cancel_unbound(lease: RoutedSectionLease) -> Option<Capture> {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).cancel_unbound(lease)
}

pub(crate) unsafe fn release(lease: RoutedSectionLease, area: ImageAreaId) -> Result<(), u32> {
    let capture = (&mut *core::ptr::addr_of_mut!(OWNERS))
        .release(lease, area)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    drop(capture);
    Ok(())
}
