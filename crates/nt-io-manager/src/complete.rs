//! The completion engine (spec §19): drive pending IRPs to exactly one final
//! completion.
//!
//! A request whose backend returned `Pending` stays parked in the `Pending`
//! state. `pump` drains the ready completions the backends report and finalizes
//! the matching IRPs — exactly once, so a completion that races a cancellation
//! (see `cancel`) never double-finalizes. `pending_irps` is the stuck-IRP
//! detector: no request may sit `Pending` unless a live driver owns it.

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::irp::IrpState;
use crate::object_port::ObjectManagerPort;
use crate::{IoManager, IrpId};

impl<P: ObjectManagerPort> IoManager<P> {
    /// Drain every driver backend's ready completions, finalizing the matching
    /// pending IRPs. Returns how many IRPs were finalized.
    pub fn pump(&mut self) -> usize {
        let mut finalized = 0;
        for idx in 0..self.backends.len() {
            while let Some(c) = self.backends[idx].poll_completion() {
                if self.finalize_pending(c.irp_id, c.status, c.information) {
                    finalized += 1;
                }
            }
        }
        finalized
    }

    /// The IRPs currently pending or cancel-requested — the stuck-IRP detector
    /// (spec §19). An empty result (with no live pending owners) means nothing is
    /// stuck.
    pub fn pending_irps(&self) -> Vec<IrpId> {
        self.irps
            .iter()
            .filter(|(_, i)| matches!(i.state, IrpState::Pending | IrpState::CancelRequested))
            .map(|(id, _)| id)
            .collect()
    }

    /// Finalize a pending IRP as completed, exactly once. A no-op (returns
    /// `false`) if the IRP is no longer pending — e.g. it was already cancelled or
    /// completed in a race.
    pub(crate) fn finalize_pending(
        &mut self,
        irp_id: IrpId,
        status: NtStatus,
        information: u64,
    ) -> bool {
        let irp = match self.irp_mut(irp_id) {
            Some(i) => i,
            None => return false,
        };
        if !matches!(irp.state, IrpState::Pending | IrpState::CancelRequested) {
            return false;
        }
        irp.transition(IrpState::Completing);
        irp.transition(IrpState::Completed);
        irp.status = status;
        irp.information = information;
        self.free_irp(irp_id);
        true
    }
}
