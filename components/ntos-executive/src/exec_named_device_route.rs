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
    let (device, remaining_name) = resolve(name, case_insensitive)?;
    if is_peer(&device)? {
        Ok(Some((device, remaining_name)))
    } else {
        Ok(None)
    }
}
