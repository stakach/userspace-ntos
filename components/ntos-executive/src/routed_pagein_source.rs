//! Exact routed page source identity shared by retained syscall coordinators.

use crate::exec_handler::native_image_view::NativeImageViewDescriptor;
use nt_memory_manager::{GenericSectionView, RoutedSectionLease, SectionIdentity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoutedPageInSource {
    Mapped {
        section: SectionIdentity,
        view: GenericSectionView,
        lease: RoutedSectionLease,
    },
    Image {
        view: NativeImageViewDescriptor,
        lease: RoutedSectionLease,
    },
}
