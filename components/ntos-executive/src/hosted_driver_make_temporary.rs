//! Kernel-mode `ZwMakeTemporaryObject` for a hosted driver's typed directory handle.

use super::*;

pub(super) extern "win64" fn zw_make_temporary_object(handle: u64) -> i32 {
    crate::win32k_subsystem::directory_object::make_temporary_with_label(
        hosted_driver_directory_object::LABEL, handle,
    )
}
