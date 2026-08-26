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
use crate::irp::{CancelState, IrpCompletionOrigin, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, DriverId, FileId, IoManager, IrpId};

/// Stable terminal projection delivered to an I/O Manager consumer. The
/// canonical IRP remains live until [`IoManager::acknowledge_completed_irp`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CompletedIrp {
    pub id: IrpId,
    pub client_id: ClientId,
    /// Immutable request-origin identities.
    pub driver_id: DriverId,
    pub file_id: Option<FileId>,
    pub device_id: DeviceId,
    pub major: u8,
    pub minor: u8,
    /// Exact backend/device that owned terminal completion and retained output.
    pub completion_driver_id: DriverId,
    pub completion_device_id: DeviceId,
    pub user_data: u64,
    pub requestor_tid: u64,
    pub status: NtStatus,
    pub information: u64,
    pub file_context: Option<u64>,
    pub completion_origin: IrpCompletionOrigin,
}

/// Result of one completion-engine pump.
///
/// `storage_grew` reports manager-owned queue capacity growth. Embedders that place the I/O
/// Manager in a rewindable arena must retain those allocations before the next rewind, even when
/// the pump did not publish a caller-visible completion.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IoPumpReport {
    pub progress: usize,
    pub storage_grew: bool,
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct PumpStorageCapacity {
    completed_irps: usize,
    manager_owned_irps: usize,
    cancel_dispatch_retries: usize,
    rejected_completion_acks: usize,
    deferred_file_close_retries: usize,
    disconnected_client_retries: usize,
}

impl<P: ObjectManagerPort> IoManager<P> {
    fn pump_storage_capacity(&self) -> PumpStorageCapacity {
        PumpStorageCapacity {
            completed_irps: self.completed_irps.capacity(),
            manager_owned_irps: self.manager_owned_irps.capacity(),
            cancel_dispatch_retries: self.cancel_dispatch_retries.capacity(),
            rejected_completion_acks: self.rejected_completion_acks.capacity(),
            deferred_file_close_retries: self.deferred_file_close_retries.capacity(),
            disconnected_client_retries: self.disconnected_client_retries.capacity(),
        }
    }

    /// Drain every driver backend's ready completions. Deliverable records are
    /// published in arrival order; manager-owned records are ACKed and
    /// reclaimed after their terminal result arrives.
    pub fn pump(&mut self) -> usize {
        self.pump_with_report().progress
    }

    /// Drain ready completions and report whether manager-owned queue storage grew.
    pub fn pump_with_report(&mut self) -> IoPumpReport {
        let storage_before = self.pump_storage_capacity();
        let progress = self.pump_inner();
        IoPumpReport {
            progress,
            storage_grew: self.pump_storage_capacity() != storage_before,
        }
    }

    fn pump_inner(&mut self) -> usize {
        let mut progress = self.retry_cancel_dispatches()
            + self.retry_rejected_completion_acks()
            + self.retry_deferred_file_closes();
        for idx in 0..self.backends.len() {
            while let Some(completion) = self.backends[idx].poll_completion() {
                let irp_id = completion.irp_id;
                if self.publish_backend_completion(idx, completion) {
                    progress += 1;
                } else {
                    // Poll transfers one retained backend completion to the manager. If its
                    // canonical identity is stale, foreign, or already terminal, it has no valid
                    // consumer; release that exact backend owner instead of stranding it in a
                    // backend-specific published state.
                    if self.backends[idx].acknowledge_completion(irp_id).is_ok() {
                        progress += 1;
                    } else if !self.rejected_completion_acks.contains(&(idx, irp_id)) {
                        let capacity = self.rejected_completion_acks.capacity();
                        self.rejected_completion_acks.push((idx, irp_id));
                        if self.rejected_completion_acks.capacity() != capacity {
                            self.mark_durable_storage_dirty();
                        }
                    }
                }
            }
        }
        progress += self.detect_driver_faults();
        self.reap_manager_owned_completions();
        progress += self.retry_disconnected_clients();
        progress
    }

    fn retry_disconnected_clients(&mut self) -> usize {
        let mut retired = 0;
        let mut index = 0;
        while index < self.disconnected_client_retries.len() {
            let client = self.disconnected_client_retries[index];
            let owns_irps = self.irps.iter().any(|(_, irp)| irp.client_id == client);
            let owns_files = self.files.iter().any(|(_, file)| file.client_id == client);
            if !owns_irps && !owns_files && self.port.close_client(client).is_ok() {
                self.disconnected_client_retries.swap_remove(index);
                retired += 1;
            } else {
                index += 1;
            }
        }
        retired
    }

    fn retry_cancel_dispatches(&mut self) -> usize {
        let mut dispatched = 0;
        let mut index = 0;
        while index < self.cancel_dispatch_retries.len() {
            let irp_id = self.cancel_dispatch_retries[index];
            let (state, driver_id) = match self.irp(irp_id) {
                Some(irp) => match irp.current_stack() {
                    Some(stack) => (irp.state, stack.driver_id),
                    None => {
                        self.cancel_dispatch_retries.swap_remove(index);
                        continue;
                    }
                },
                None => {
                    self.cancel_dispatch_retries.swap_remove(index);
                    continue;
                }
            };
            if state != IrpState::CancelRequested {
                self.cancel_dispatch_retries.swap_remove(index);
                continue;
            }
            let backend_index = self
                .driver(driver_id)
                .map(|driver| driver.backend.0 as usize);
            let complete = backend_index
                .and_then(|backend_index| self.backends.get_mut(backend_index))
                .is_some_and(|backend| backend.is_faulted() || backend.cancel_irp(irp_id).is_ok());
            if complete {
                self.cancel_dispatch_retries.swap_remove(index);
                dispatched += 1;
            } else {
                index += 1;
            }
        }
        dispatched
    }

    fn retry_rejected_completion_acks(&mut self) -> usize {
        let mut acknowledged = 0;
        let mut index = 0;
        while index < self.rejected_completion_acks.len() {
            let (backend_index, irp_id) = self.rejected_completion_acks[index];
            let complete = self.backends.get_mut(backend_index).is_some_and(|backend| {
                backend.is_faulted() || backend.acknowledge_completion(irp_id).is_ok()
            });
            if complete {
                self.rejected_completion_acks.swap_remove(index);
                acknowledged += 1;
            } else {
                index += 1;
            }
        }
        acknowledged
    }

    fn retry_deferred_file_closes(&mut self) -> usize {
        let mut completed = 0;
        let mut index = 0;
        while index < self.deferred_file_close_retries.len() {
            let file_id = self.deferred_file_close_retries[index];
            if self.file(file_id).is_none() || self.finish_deferred_file_close(file_id).is_ok() {
                self.deferred_file_close_retries.swap_remove(index);
                completed += 1;
            } else {
                index += 1;
            }
        }
        completed
    }

    pub(crate) fn schedule_deferred_file_close(&mut self, file_id: FileId) {
        if !self.deferred_file_close_retries.contains(&file_id) {
            let capacity = self.deferred_file_close_retries.capacity();
            self.deferred_file_close_retries.push(file_id);
            if self.deferred_file_close_retries.capacity() != capacity {
                self.mark_durable_storage_dirty();
            }
        }
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
            .map(|irp| {
                irp.current_stack()
                    .map(|stack| stack.driver_id != driver_id)
                    .unwrap_or(true)
            })
            .unwrap_or(true)
        {
            return false;
        }
        self.publish_verified_completion(completion, IrpCompletionOrigin::Driver)
    }

    fn publish_backend_completion(
        &mut self,
        backend_index: usize,
        completion: DriverCompletion,
    ) -> bool {
        let driver_id = match self.irp(completion.irp_id) {
            Some(irp) => match irp.current_stack() {
                Some(stack) => stack.driver_id,
                None => return false,
            },
            None => return false,
        };
        if self
            .driver(driver_id)
            .map(|driver| driver.backend.0 as usize != backend_index)
            .unwrap_or(true)
        {
            return false;
        }
        self.publish_verified_completion(completion, IrpCompletionOrigin::Driver)
    }

    pub(crate) fn publish_transport_fault_completion(
        &mut self,
        driver_id: DriverId,
        completion: DriverCompletion,
    ) -> bool {
        if self
            .irp(completion.irp_id)
            .and_then(|irp| irp.current_stack())
            .map(|stack| stack.driver_id != driver_id)
            .unwrap_or(true)
        {
            return false;
        }
        self.publish_verified_completion(completion, IrpCompletionOrigin::TransportFault)
    }

    fn publish_verified_completion(
        &mut self,
        completion: DriverCompletion,
        origin: IrpCompletionOrigin,
    ) -> bool {
        if completion.status == NtStatus::PENDING {
            return false;
        }
        let (major, file_id) = {
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
            irp.completion_file_context = completion.file_context;
            irp.completion_origin = Some(origin);
            if completion.status == NtStatus::CANCELLED {
                irp.cancel = CancelState::Cancelled;
            }
            if !irp.transition(IrpState::Completing) || !irp.transition(IrpState::Completed) {
                return false;
            }
            (irp.origin_major, irp.file_id)
        };

        // Terminal CREATE publication, rather than transport acknowledgement, makes the File
        // usable. Completion consumers must be able to publish the new handle before ACK releases
        // the retained driver payload. A cancelled owner can lose the race to a successful CREATE;
        // preserve that driver's context while leaving its File on the deferred-close path.
        if crate::is_create_major(major) {
            if let Some(file) = file_id.and_then(|file_id| self.file_mut(file_id)) {
                if completion.status.is_success() {
                    file.driver_context = completion.file_context;
                    if file.state == crate::FileState::CreateIrpDispatched {
                        file.transition(crate::FileState::Open);
                    }
                } else if file.state == crate::FileState::CreateIrpDispatched {
                    file.transition(crate::FileState::Closed);
                }
            }
        }
        let capacity = self.completed_irps.capacity();
        self.completed_irps.push_back(completion.irp_id);
        if self.completed_irps.capacity() != capacity {
            self.mark_durable_storage_dirty();
        }
        true
    }

    /// Peek at the oldest completion awaiting delivery acknowledgement.
    pub fn next_completed_irp(&self) -> Option<CompletedIrp> {
        self.completed_irps
            .front()
            .and_then(|id| self.completed_irp_snapshot(*id))
    }

    /// Resolve one exact terminal completion without changing enumeration or
    /// ownership. Unknown, stale, pending, and already-acknowledged ids fail.
    pub fn completed_irp(&self, irp_id: IrpId) -> Option<CompletedIrp> {
        self.completed_irp_snapshot(irp_id)
    }

    /// Copy the retained output of one exact terminal completion. Output stays
    /// owned by the backend until acknowledgement, so a failed client copy can
    /// be retried without redispatching or losing the terminal result.
    pub fn copy_completed_irp_output(
        &mut self,
        irp_id: IrpId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        let (driver_id, information, output_capacity) = {
            let irp = self.irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            if irp.state != IrpState::Completed {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            (
                irp.current_stack()
                    .ok_or(NtStatus::INVALID_PARAMETER)?
                    .driver_id,
                usize::try_from(irp.information).map_err(|_| NtStatus::INVALID_PARAMETER)?,
                irp.buffer
                    .map(|buffer| buffer.output_len as usize)
                    .unwrap_or(0),
            )
        };
        if information > output_capacity {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let offset = usize::try_from(offset).map_err(|_| NtStatus::INVALID_PARAMETER)?;
        if offset > information {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let copy_capacity = output.len().min(information - offset);
        if copy_capacity == 0 {
            return Ok(0);
        }
        let backend_index = self
            .driver(driver_id)
            .map(|driver| driver.backend.0 as usize)
            .filter(|index| *index < self.backends.len())
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let copied = self.backends[backend_index].copy_completion_output(
            irp_id,
            offset as u64,
            &mut output[..copy_capacity],
        )?;
        if copied > copy_capacity {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(copied)
    }

    /// Acknowledge a published completion, reclaim its canonical IRP, and resume
    /// any FILE_OBJECT close that was waiting for this reference. Consumers may
    /// acknowledge independent ready requests out of enumeration order.
    pub fn acknowledge_completed_irp(&mut self, irp_id: IrpId) -> Result<CompletedIrp, NtStatus> {
        self.acknowledge_completed_irp_inner(irp_id, true)
    }

    /// Require a live backend acknowledgement before reclaiming a published completion.
    ///
    /// Lifecycle consumers use this stronger operation because reclaiming an IRP after its backend
    /// faulted proves cleanup, not that the driver accepted the exact completion acknowledgement.
    /// A faulted backend leaves the completion and canonical IRP retained for the caller's
    /// indeterminate-state barrier.
    pub fn acknowledge_completed_irp_strict(
        &mut self,
        irp_id: IrpId,
    ) -> Result<CompletedIrp, NtStatus> {
        self.acknowledge_completed_irp_inner(irp_id, false)
    }

    fn acknowledge_completed_irp_inner(
        &mut self,
        irp_id: IrpId,
        reclaim_faulted_backend: bool,
    ) -> Result<CompletedIrp, NtStatus> {
        let queue_index = self
            .completed_irps
            .iter()
            .position(|queued| *queued == irp_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let completed = self
            .completed_irp_snapshot(irp_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let backend_index = self
            .driver(completed.completion_driver_id)
            .map(|driver| driver.backend.0 as usize)
            .filter(|index| *index < self.backends.len())
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        if self.backends[backend_index].is_faulted() {
            if !reclaim_faulted_backend {
                return Err(NtStatus::DEVICE_NOT_CONNECTED);
            }
        } else {
            self.backends[backend_index].acknowledge_completion(irp_id)?;
        }
        self.completed_irps.remove(queue_index);
        self.free_irp(irp_id)
            .expect("validated completed IRP disappeared after backend acknowledgement");

        if let Some(file_id) = completed.file_id {
            if completed.major == major::IRP_MJ_CLEANUP {
                if let Some(file) = self.file_mut(file_id) {
                    if file.state == crate::FileState::CleanupPending {
                        file.transition(crate::FileState::CleanupComplete);
                    }
                }
            }
            if self.finish_deferred_file_close(file_id).is_err() {
                self.schedule_deferred_file_close(file_id);
            }
        }
        Ok(completed)
    }

    pub(crate) fn reap_manager_owned_completions(&mut self) {
        let mut index = 0;
        while index < self.manager_owned_irps.len() {
            let irp_id = self.manager_owned_irps[index];
            let terminal = self
                .irp(irp_id)
                .is_none_or(|irp| irp.state == IrpState::Completed);
            if terminal
                && (self.irp(irp_id).is_none() || self.acknowledge_completed_irp(irp_id).is_ok())
            {
                self.manager_owned_irps.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    fn completed_irp_snapshot(&self, irp_id: IrpId) -> Option<CompletedIrp> {
        let irp = self.irp(irp_id)?;
        if irp.state != IrpState::Completed {
            return None;
        }
        Some(CompletedIrp {
            id: irp.id,
            client_id: irp.client_id,
            driver_id: irp.origin_driver_id,
            file_id: irp.file_id,
            device_id: irp.origin_device_id,
            major: irp.origin_major,
            minor: irp.origin_minor,
            completion_driver_id: irp.current_stack()?.driver_id,
            completion_device_id: irp.current_stack()?.device_id,
            user_data: irp.user_data,
            requestor_tid: irp.requestor_tid,
            status: irp.status,
            information: irp.information,
            file_context: irp.completion_file_context,
            completion_origin: irp.completion_origin?,
        })
    }
}
