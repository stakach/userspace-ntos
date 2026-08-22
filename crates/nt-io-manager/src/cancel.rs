//! The cancellation engine (spec section 18): best-effort, race-aware
//! cancellation.
//!
//! Cancellation transfers no ownership. The IRP moves to `CancelRequested` and
//! remains live until its driver publishes exactly one terminal completion. This
//! is the same completion path used when an already-ready result wins the race.

use nt_status::NtStatus;
use nt_types::ClientId;

use crate::irp::{CancelState, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{DriverId, IoManager, IrpId};

impl<P: ObjectManagerPort> IoManager<P> {
    /// Request cancellation of an in-flight IRP owned by `client`. Unknown or
    /// already-terminal requests are successful no-ops; a different owner is
    /// denied.
    pub fn cancel(&mut self, client: ClientId, irp_id: IrpId) -> Result<(), NtStatus> {
        let (state, driver_id, owner) = match self.irp(irp_id) {
            Some(irp) => (irp.state, irp.driver_id, irp.client_id),
            None => return Ok(()),
        };
        if owner != client {
            return Err(NtStatus::ACCESS_DENIED);
        }
        if state != IrpState::Pending {
            return Ok(());
        }

        if let Some(irp) = self.irp_mut(irp_id) {
            irp.cancel = CancelState::CancelRequested;
            irp.transition(IrpState::CancelRequested);
        }
        if let Some(idx) = self.driver_backend_index(driver_id) {
            let _ = self.backends[idx].cancel_irp(irp_id);
        }
        Ok(())
    }

    fn driver_backend_index(&self, driver_id: DriverId) -> Option<usize> {
        Some(self.driver(driver_id)?.backend.0 as usize)
    }
}
