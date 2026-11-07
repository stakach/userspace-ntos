//! Admission for `IoSetHardErrorOrVerifyDevice` on a hosted driver's IRP.
//!
//! The native adapter supplies the exact source-IRP ticket from its retained ownership ledger,
//! the ETHREAD resolved by the canonical Ps owner, and the device resolved in the source's
//! generation-bearing hosted domain. None of those addresses grants authority by itself. This
//! pure preflight does not own the physical projection locks; its caller must retain those locks
//! from resolution through the ETHREAD write.

use crate::source_irp_ledger::{SourceIrpForwardIdentity, SourceIrpLedger, SourceIrpOwner};
use crate::DeviceId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardErrorVerifyError {
    StaleIrp,
    InvalidThread,
    InvalidDevice,
}

/// Return the exact `(ETHREAD, DEVICE_OBJECT)` write, or no write for a threadless IRP.
///
/// ReactOS ignores an IRP with no requestor thread. A nonzero device must have been resolved by
/// `IoManager::hosted_device_by_identity(source.allocation().domain, device_address)`; a caller
/// must not supply a device resolved in another domain. `canonical_thread` must come from a live
/// ProcessManager lookup, not the IRP's untrusted thread field.
pub fn plan_hard_error_verify_device(
    ledger: &SourceIrpLedger,
    source: SourceIrpForwardIdentity,
    irp_thread: u64,
    canonical_thread: Option<u64>,
    device_address: u64,
    canonical_device: Option<DeviceId>,
) -> Result<Option<(u64, u64)>, HardErrorVerifyError> {
    let allocation = source.allocation();
    if !matches!(allocation.owner, SourceIrpOwner::HostedDriver(_) | SourceIrpOwner::HostedCaller(_))
        || !ledger.admits_forward(source.ticket(), allocation)
    {
        return Err(HardErrorVerifyError::StaleIrp);
    }
    if irp_thread == 0 {
        return Ok(None);
    }
    if canonical_thread != Some(irp_thread) {
        return Err(HardErrorVerifyError::InvalidThread);
    }
    if device_address != 0 && canonical_device.is_none() {
        return Err(HardErrorVerifyError::InvalidDevice);
    }
    Ok(Some((irp_thread, device_address)))
}
