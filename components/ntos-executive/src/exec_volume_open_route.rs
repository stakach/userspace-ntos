//! Exact Object Manager volume File admission for the mounted filesystem owner.

use alloc::vec::Vec;

/// An empty device-relative FileName denotes the volume File. A root directory (`\`)
/// or child name remains a distinct File object, even when it resolves to the same device.
/// The caller supplies the live registered kernel-filesystem check for that exact device.
pub(crate) fn route_exact_volume_file_target<IsKernelFilesystem>(
    resolved: Option<&Result<(u64, Vec<u16>), u32>>,
    is_kernel_filesystem: IsKernelFilesystem,
) -> bool
where
    IsKernelFilesystem: FnOnce(u64) -> bool,
{
    let Some(Ok((device_id, remaining_name))) = resolved else {
        return false;
    };
    remaining_name.is_empty() && is_kernel_filesystem(*device_id)
}
