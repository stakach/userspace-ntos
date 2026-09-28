//! Exact FILE_OBJECT reference ownership for routed data sections.

use crate::driver_launch::hosted_file_capture::Capture;
use nt_memory_manager::{RoutedSectionLease, SectionIdentity};
use nt_user_host::routed_section_owner::RoutedSectionOwners;

static mut OWNERS: RoutedSectionOwners<Capture> = RoutedSectionOwners::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub file_id: u64,
    pub device_id: u64,
    pub fs_context: u64,
    pub granted_access: u32,
}

/// Reserve the section's non-Copy file reference before publishing any section state.
pub(crate) unsafe fn reserve(capture: Capture) -> Result<RoutedSectionLease, Capture> {
    let _durable = crate::allocator::enter_durable();
    (&mut *core::ptr::addr_of_mut!(OWNERS)).reserve(capture)
}

pub(crate) unsafe fn bind(lease: RoutedSectionLease, section: SectionIdentity) -> bool {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).bind(lease, section)
}

/// A route is valid only for the exact section incarnation that owns the capture.
pub(crate) unsafe fn route(lease: RoutedSectionLease, section: SectionIdentity) -> Option<Route> {
    (&*core::ptr::addr_of!(OWNERS))
        .get(lease, section)
        .map(|capture| Route {
            file_id: capture.file_id(),
            device_id: capture.device_id(),
            fs_context: capture.fs_context(),
            granted_access: capture.granted_access(),
        })
}

/// Return an unpublished reference to its creator. Bound owners retire with their section.
pub(crate) unsafe fn cancel_unbound(lease: RoutedSectionLease) -> Option<Capture> {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).cancel_unbound(lease)
}

/// Drop only the exact bound reference; Capture retains refused canonical releases for redrive.
pub(crate) unsafe fn release(lease: RoutedSectionLease, section: SectionIdentity) -> Result<(), u32> {
    let capture = (&mut *core::ptr::addr_of_mut!(OWNERS))
        .release(lease, section)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    drop(capture);
    Ok(())
}
