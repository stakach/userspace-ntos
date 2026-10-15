//! Shared physical FDO adjacency proof for cross-domain PnP forwarding.

use nt_io_manager::{HostedDevicePointerRegistration, IoManager};

use crate::PnpManager;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FdoForwardPathError {
    SameDomain,
    WrongStack,
}

pub(crate) fn validate_fdo_forward_path<P>(
    pnp: &PnpManager,
    io: &IoManager<P>,
    upper: HostedDevicePointerRegistration,
    lower: HostedDevicePointerRegistration,
    devnode: u64,
) -> Result<(), FdoForwardPathError> {
    if upper.domain() == lower.domain() || upper.device_id() == lower.device_id() {
        return Err(FdoForwardPathError::SameDomain);
    }
    if io
        .device(upper.device_id())
        .and_then(|device| device.attached_to)
        != Some(lower.device_id())
        || pnp.fdo(devnode) != Some(lower.device_id().raw())
    {
        return Err(FdoForwardPathError::WrongStack);
    }
    Ok(())
}
