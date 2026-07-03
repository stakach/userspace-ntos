//! The cancellation engine (spec §18): best-effort, race-aware cancellation.
//!
//! A cancel of a pending IRP moves it to `CancelRequested`, asks the driver
//! backend to cancel, and finalizes it as `STATUS_CANCELLED` — but only if a real
//! completion (via `pump`) has not already won the race. The two finalizers
//! (`finalize_pending` and `finalize_cancelled`) each guard on the IRP state, so
//! the IRP is finalized exactly once with either its original completion or
//! `STATUS_CANCELLED`, never both, and its resources are freed exactly once.

use nt_status::NtStatus;
use nt_types::ClientId;

use crate::irp::{CancelState, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, IoManager, IrpId};

impl<P: ObjectManagerPort> IoManager<P> {
    /// Cancel an in-flight IRP owned by `client` (best-effort, spec §18). A cancel
    /// of an unknown/already-final IRP is a successful no-op (the completion won);
    /// cancelling another client's IRP is `STATUS_ACCESS_DENIED`.
    pub fn cancel(&mut self, client: ClientId, irp_id: IrpId) -> Result<(), NtStatus> {
        let (state, device_id, owner) = match self.irp(irp_id) {
            Some(i) => (i.state, i.device_id, i.client_id),
            None => return Ok(()), // already completed/freed — nothing to cancel
        };
        if owner != client {
            return Err(NtStatus::ACCESS_DENIED);
        }
        if !matches!(state, IrpState::Pending) {
            // Not cancellable now (dispatching / completing / terminal): a
            // completion is winning the race.
            return Ok(());
        }

        // Arm cancellation + notify the backend.
        if let Some(irp) = self.irp_mut(irp_id) {
            irp.cancel = CancelState::CancelRequested;
            irp.transition(IrpState::CancelRequested);
        }
        if let Some(idx) = self.driver_backend_index(device_id) {
            let _ = self.backends[idx].cancel_irp(irp_id);
        }
        // Finalize as cancelled — unless a completion already finalized it (then
        // this is a no-op).
        self.finalize_cancelled(irp_id);
        Ok(())
    }

    /// Finalize a cancel-requested IRP as `Cancelled`, exactly once.
    fn finalize_cancelled(&mut self, irp_id: IrpId) -> bool {
        let irp = match self.irp_mut(irp_id) {
            Some(i) => i,
            None => return false,
        };
        if !matches!(irp.state, IrpState::CancelRequested) {
            return false;
        }
        irp.transition(IrpState::Cancelled);
        irp.status = NtStatus::CANCELLED;
        irp.cancel = CancelState::Cancelled;
        self.free_irp(irp_id);
        true
    }

    /// The registry index of the backend owning `device_id`'s driver.
    fn driver_backend_index(&self, device_id: DeviceId) -> Option<usize> {
        let driver_id = self.device(device_id)?.driver_id;
        Some(self.driver(driver_id)?.backend.0 as usize)
    }
}
