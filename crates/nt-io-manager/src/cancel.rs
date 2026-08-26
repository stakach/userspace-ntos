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
use crate::{DriverId, FileId, IoManager, IrpId};

/// Canonical state of one thread's IRPs for one exact File generation. Terminal records remain in
/// the drain until their completion owner acknowledges them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileThreadIrpDrainState {
    pub total: usize,
    pub cancel_requested: usize,
    pub terminal_unacknowledged: usize,
}

impl FileThreadIrpDrainState {
    pub const fn is_drained(self) -> bool {
        self.total == 0
    }
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Request cancellation of every IRP issued by `requestor_tid` for one exact File. This is the
    /// canonical `NtCancelIoFile` selection rule: other threads and other File generations are not
    /// affected. Terminal, unacknowledged IRPs are counted but do not receive another cancellation
    /// request, allowing the caller to drain through final completion publication and ACK.
    pub fn cancel_file_thread_io(
        &mut self,
        client: ClientId,
        file_id: FileId,
        requestor_tid: u64,
    ) -> Result<FileThreadIrpDrainState, NtStatus> {
        if requestor_tid == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        if file.client_id != client {
            return Err(NtStatus::INVALID_HANDLE);
        }
        // Validate every target before the first state transition. Iteratively finding one Pending
        // record avoids a per-syscall allocation; CancelRequested records already own their retry.
        for (_, irp) in self.irps.iter().filter(|(_, irp)| {
            irp.client_id == client
                && irp.file_id == Some(file_id)
                && irp.requestor_tid == requestor_tid
                && matches!(irp.state, IrpState::Pending | IrpState::CancelRequested)
        }) {
            self.driver_backend_index(
                irp.current_stack()
                    .ok_or(NtStatus::INVALID_PARAMETER)?
                    .driver_id,
            )
            .filter(|index| *index < self.backends.len())
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        }
        loop {
            let next = {
                self.irps.iter().find_map(|(irp_id, irp)| {
                    (irp.client_id == client
                        && irp.file_id == Some(file_id)
                        && irp.requestor_tid == requestor_tid
                        && irp.state == IrpState::Pending)
                        .then_some(irp_id)
                })
            };
            let Some(irp_id) = next else {
                break;
            };
            self.cancel(client, irp_id)?;
        }
        Ok(self.file_thread_io_drain_state(client, file_id, requestor_tid))
    }

    /// Whether an exact current-thread File IRP still exists. Completed IRPs remain visible until
    /// their owner acknowledges terminal delivery, which is the drain boundary required by
    /// `NtCancelIoFile`.
    pub fn file_thread_io_drain_state(
        &self,
        client: ClientId,
        file_id: FileId,
        requestor_tid: u64,
    ) -> FileThreadIrpDrainState {
        let mut state = FileThreadIrpDrainState::default();
        for (_, irp) in self.irps.iter() {
            if irp.client_id != client
                || irp.file_id != Some(file_id)
                || irp.requestor_tid != requestor_tid
            {
                continue;
            }
            state.total += 1;
            state.cancel_requested += usize::from(irp.state == IrpState::CancelRequested);
            state.terminal_unacknowledged += usize::from(irp.state.is_final());
        }
        state
    }

    /// Request cancellation of an in-flight IRP owned by `client`. Unknown or
    /// already-terminal requests are successful no-ops; a different owner is
    /// denied.
    pub fn cancel(&mut self, client: ClientId, irp_id: IrpId) -> Result<(), NtStatus> {
        let (state, driver_id, owner) = match self.irp(irp_id) {
            Some(irp) => (
                irp.state,
                irp.current_stack()
                    .ok_or(NtStatus::INVALID_PARAMETER)?
                    .driver_id,
                irp.client_id,
            ),
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
                let capacity = self.cancel_dispatch_retries.capacity();
                self.cancel_dispatch_retries.push(irp_id);
                if self.cancel_dispatch_retries.capacity() != capacity {
                    self.mark_durable_storage_dirty();
                }
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

    /// Request cancellation only when this exact IRP is still in flight. The
    /// boolean distinguishes a selected pending owner from an unknown or
    /// already-terminal generation, and an existing CancelRequested owner is
    /// not redispatched to its backend.
    pub fn cancel_if_pending(&mut self, client: ClientId, irp_id: IrpId) -> Result<bool, NtStatus> {
        let (owner, state) = match self.irp(irp_id) {
            Some(irp) => (irp.client_id, irp.state),
            None => return Ok(false),
        };
        if owner != client {
            return Err(NtStatus::ACCESS_DENIED);
        }
        match state {
            IrpState::Pending => {
                self.cancel(client, irp_id)?;
                Ok(true)
            }
            IrpState::CancelRequested => Ok(true),
            _ => Ok(false),
        }
    }

    /// Relinquish delivery of one exact IRP. Pending work is cancelled through
    /// its owning backend; whichever terminal result wins is acknowledged and
    /// reclaimed automatically instead of being exposed to a departed consumer.
    pub fn abandon_irp_delivery(
        &mut self,
        client: ClientId,
        irp_id: IrpId,
    ) -> Result<(), NtStatus> {
        self.claim_manager_owned_irp(client, irp_id)?;
        self.cancel(client, irp_id)?;
        self.reap_manager_owned_completions();
        Ok(())
    }

    /// Transfer terminal-delivery ownership for one exact IRP to the manager.
    /// This does not request cancellation; lifecycle IRPs use it so pending
    /// CLEANUP/CLOSE work can finish normally without a user-facing consumer.
    pub(crate) fn claim_manager_owned_irp(
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
        if !self.manager_owned_irps.contains(&irp_id) {
            self.manager_owned_irps
                .try_reserve(1)
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            self.manager_owned_irps.push(irp_id);
        }
        Ok(())
    }

    pub(crate) fn reserve_manager_owned_irp_slot(&mut self) -> Result<(), NtStatus> {
        let capacity = self.manager_owned_irps.capacity();
        self.manager_owned_irps
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        if self.manager_owned_irps.capacity() != capacity {
            self.mark_durable_storage_dirty();
        }
        Ok(())
    }

    fn driver_backend_index(&self, driver_id: DriverId) -> Option<usize> {
        Some(self.driver(driver_id)?.backend.0 as usize)
    }
}
