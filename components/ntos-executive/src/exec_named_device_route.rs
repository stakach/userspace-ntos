//! Exact object namespace resolution for native opens of named driver devices.

use alloc::vec::Vec;

/// Keep name resolution distinct from device dispatch classification: an unknown object is an
/// error, while a valid file-system device is simply outside this driver-peer route.
pub(crate) fn resolve_named_driver_peer<Device, Resolve, IsPeer>(
    name: &[u16],
    case_insensitive: bool,
    resolve: Resolve,
    is_peer: IsPeer,
) -> Result<Option<(Device, Vec<u16>)>, u32>
where
    Resolve: FnOnce(&[u16], bool) -> Result<(Device, Vec<u16>), u32>,
    IsPeer: FnOnce(&Device) -> Result<bool, u32>,
{
    let resolved = resolve(name, case_insensitive);
    if classify_resolved_named_driver_peer(&resolved, is_peer)? {
        resolved.map(Some)
    } else {
        Ok(None)
    }
}

/// Classify an already resolved canonical Device without repeating its namespace traversal.
/// The caller keeps ownership of the exact suffix for either peer or filesystem dispatch.
pub(crate) fn classify_resolved_named_driver_peer<Device, Name, IsPeer>(
    resolved: &Result<(Device, Name), u32>,
    is_peer: IsPeer,
) -> Result<bool, u32>
where
    IsPeer: FnOnce(&Device) -> Result<bool, u32>,
{
    let (device, _) = resolved.as_ref().map_err(|status| *status)?;
    is_peer(device)
}
