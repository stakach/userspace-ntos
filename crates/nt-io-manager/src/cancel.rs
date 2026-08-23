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
        if !matches!(state, IrpState::Pending | IrpState::CancelRequested) {
            return Ok(());
        }
        let idx = self
            .driver_backend_index(driver_id)
            .filter(|index| *index < self.backends.len())
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if state == IrpState::Pending {
            if let Some(irp) = self.irp_mut(irp_id) {
                irp.cancel = CancelState::CancelRequested;
                irp.transition(IrpState::CancelRequested);
            }
        }
        if self.backends[idx].cancel_irp(irp_id).is_err() {
            if !self.cancel_dispatch_retries.contains(&irp_id) {
                self.cancel_dispatch_retries.push(irp_id);
            }
        } else if let Some(index) = self
            .cancel_dispatch_retries
            .iter()
            .position(|candidate| *candidate == irp_id)
        {
            self.cancel_dispatch_retries.swap_remove(index);
        }
        Ok(())
    }

    /// Relinquish delivery of one exact IRP. Pending work is cancelled through
    /// its owning backend; whichever terminal result wins is acknowledged and
    /// reclaimed automatically instead of being exposed to a departed consumer.
    pub fn abandon_irp_delivery(
        &mut self,
        client: ClientId,
        irp_id: IrpId,
    ) -> Result<(), NtStatus> {
        let owner = match self.irp(irp_id) {
            Some(irp) => irp.client_id,
            None => return Ok(()),
        };
        if owner != client {
            return Err(NtStatus::ACCESS_DENIED);
        }
        if !self.abandoned_irps.contains(&irp_id) {
            self.abandoned_irps.push(irp_id);
        }
        self.cancel(client, irp_id)?;
        self.reap_abandoned_completions();
        Ok(())
    }

    fn driver_backend_index(&self, driver_id: DriverId) -> Option<usize> {
        Some(self.driver(driver_id)?.backend.0 as usize)
    }
}
