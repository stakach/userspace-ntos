//! The completion engine (spec section 19): drive pending IRPs to exactly one
//! terminal result and retain that result until its owner acknowledges delivery.
//!
//! A backend returning `Pending` continues to own the request. Cancellation only
//! requests that the backend stop it; the normal completion path decides whether
//! cancellation or an already-ready completion won the race. Completed IRPs keep
//! their FILE_OBJECT reference until acknowledgement, so close cannot invalidate
//! state still needed by an asynchronous completion consumer.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::dispatch::DriverCompletion;
use crate::irp::{CancelState, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, DriverId, FileId, IoManager, IrpId};

/// Stable terminal projection delivered to an I/O Manager consumer. The
/// canonical IRP remains live until [`IoManager::acknowledge_completed_irp`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CompletedIrp {
    pub id: IrpId,
    pub client_id: ClientId,
    pub driver_id: DriverId,
    pub file_id: Option<FileId>,
    pub device_id: DeviceId,
    pub major: u8,
    pub user_data: u64,
    pub requestor_tid: u64,
    pub status: NtStatus,
    pub information: u64,
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Drain every driver backend's ready completions. Terminal records are
    /// published in arrival order and are not reclaimed here.
    pub fn pump(&mut self) -> usize {
        let mut published = 0;
        for idx in 0..self.backends.len() {
            while let Some(completion) = self.backends[idx].poll_completion() {
                if self.publish_backend_completion(idx, completion) {
                    published += 1;
                }
            }
        }
        published + self.detect_driver_faults()
    }

    /// The IRPs currently pending or cancel-requested. Completed-but-unconsumed
    /// requests intentionally do not appear in the stuck-IRP detector.
    pub fn pending_irps(&self) -> Vec<IrpId> {
        self.irps
            .iter()
            .filter(|(_, irp)| matches!(irp.state, IrpState::Pending | IrpState::CancelRequested))
            .map(|(id, _)| id)
            .collect()
    }

    /// Publish a terminal completion from a driver exactly once.
    pub fn publish_driver_completion(
        &mut self,
        driver_id: DriverId,
        completion: DriverCompletion,
    ) -> bool {
        if self
            .irp(completion.irp_id)
            .map(|irp| irp.driver_id != driver_id)
            .unwrap_or(true)
        {
            return false;
        }
        self.publish_verified_completion(completion)
    }

    fn publish_backend_completion(
        &mut self,
        backend_index: usize,
        completion: DriverCompletion,
    ) -> bool {
        let driver_id = match self.irp(completion.irp_id) {
            Some(irp) => irp.driver_id,
            None => return false,
        };
        if self
            .driver(driver_id)
            .map(|driver| driver.backend.0 as usize != backend_index)
            .unwrap_or(true)
        {
            return false;
        }
        self.publish_verified_completion(completion)
    }

    fn publish_verified_completion(&mut self, completion: DriverCompletion) -> bool {
        if completion.status == NtStatus::PENDING {
            return false;
        }
        let irp = match self.irp_mut(completion.irp_id) {
            Some(irp) => irp,
            None => return false,
        };
        if !matches!(
            irp.state,
            IrpState::Dispatched | IrpState::Pending | IrpState::CancelRequested
        ) {
            return false;
        }
        irp.status = completion.status;
        irp.information = completion.information;
        if completion.status == NtStatus::CANCELLED {
            irp.cancel = CancelState::Cancelled;
        }
        if !irp.transition(IrpState::Completing) || !irp.transition(IrpState::Completed) {
            return false;
        }
        self.completed_irps.push_back(completion.irp_id);
        true
    }

    /// Peek at the oldest completion awaiting delivery acknowledgement.
    pub fn next_completed_irp(&self) -> Option<CompletedIrp> {
        self.completed_irps
            .front()
            .and_then(|id| self.completed_irp_snapshot(*id))
    }

    /// Acknowledge a published completion, reclaim its canonical IRP, and resume
    /// any FILE_OBJECT close that was waiting for this reference. Consumers may
    /// acknowledge independent ready requests out of enumeration order.
    pub fn acknowledge_completed_irp(&mut self, irp_id: IrpId) -> Result<CompletedIrp, NtStatus> {
        let queue_index = self
            .completed_irps
            .iter()
            .position(|queued| *queued == irp_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let completed = self
            .completed_irp_snapshot(irp_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        self.completed_irps.remove(queue_index);
        self.free_irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;

        if let Some(file_id) = completed.file_id {
            if completed.major == major::IRP_MJ_CLEANUP {
                if let Some(file) = self.file_mut(file_id) {
                    if file.state == crate::FileState::CleanupPending {
                        file.transition(crate::FileState::CleanupComplete);
                    }
                }
            }
            self.finish_deferred_file_close(file_id)?;
        }
        Ok(completed)
    }

    fn completed_irp_snapshot(&self, irp_id: IrpId) -> Option<CompletedIrp> {
        let irp = self.irp(irp_id)?;
        if irp.state != IrpState::Completed {
            return None;
        }
        Some(CompletedIrp {
            id: irp.id,
            client_id: irp.client_id,
            driver_id: irp.driver_id,
            file_id: irp.file_id,
            device_id: irp.device_id,
            major: irp.major,
            user_data: irp.user_data,
            requestor_tid: irp.requestor_tid,
            status: irp.status,
            information: irp.information,
        })
    }
}
