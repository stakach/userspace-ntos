//! Shared local completion retirement, after an actual acknowledged foreign operation.

use crate::completion_ack::CompletionAckReservation;
use crate::object_port::ObjectManagerPort;
use crate::{CompletedIrp, IoManager};
use nt_status::NtStatus;

impl<P: ObjectManagerPort> IoManager<P> {
    /// Called only after backend ACK. Revalidate and find the queue entry now, never carry its
    /// pre-call index across foreign execution. This method performs no backend call; File
    /// lifecycle dispatch remains the legacy caller's responsibility after retirement.
    pub(crate) fn retire_acknowledged_completion(
        &mut self,
        expected: &CompletedIrp,
        reservation: Option<CompletionAckReservation>,
    ) -> Result<CompletedIrp, NtStatus> {
        let irp = self.irp(expected.id).ok_or(NtStatus::INVALID_PARAMETER)?;
        if irp.detached_file_owner {
            return Err(NtStatus::DELETE_PENDING);
        }
        if irp.completion_ack_reservation != reservation
            || reservation
                .is_some_and(|owner| !owner.matches(self.ownership_identity(), expected.id))
            || self.completed_irp_snapshot(expected.id).as_ref() != Some(expected)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let index = self
            .completed_irps
            .iter()
            .position(|id| *id == expected.id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        // No foreign call occurs between exact validation and canonical retirement.
        self.irps
            .get_mut(expected.id)
            .unwrap()
            .completion_ack_reservation = None;
        self.completed_irps.remove(index);
        self.free_irp(expected.id)
            .expect("validated acknowledged completion owner");
        Ok(*expected)
    }
}
