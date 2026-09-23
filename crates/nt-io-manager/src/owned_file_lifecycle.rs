//! Owned CLEANUP/CLOSE dispatch preparation. Native driver entry runs after the
//! issuing manager borrow ends; the exact generation-bearing IRP remains canonical.

use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::dispatch::IrpProjection;
use crate::driver::DispatchTarget;
use crate::irp::{IoParameters, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{CompletedIrp, FileId, FileState, IoManager, IrpCompletionOrigin, IrpId};

#[derive(Debug)]
struct Owner {
    manager: u64,
    client: ClientId,
    file_id: FileId,
    projection: IrpProjection,
    target: DispatchTarget,
}

#[derive(Debug)]
#[must_use = "begin or discard through the issuing I/O Manager"]
pub struct PreparedFileLifecycle(Owner);

#[derive(Debug)]
#[must_use = "return the exact invocation to the issuing I/O Manager"]
pub struct FileLifecycleInvocation(Owner);

#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct FileLifecycleReturn {
    owner: Owner,
    outcome: FileLifecycleOutcome,
}

#[derive(Debug)]
#[must_use = "retain until the exact driver completion resolves this lifecycle IRP"]
pub struct RetainedFileLifecycle {
    owner: Owner,
    indeterminate: bool,
    ack_uncertain: bool,
}

#[derive(Debug)]
#[must_use = "acknowledge outside the issuing I/O Manager borrow"]
pub struct FileLifecycleAckInvocation {
    owner: Owner,
    completion: CompletedIrp,
}

#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct FileLifecycleAckReturn {
    invocation: FileLifecycleAckInvocation,
    outcome: FileLifecycleAckOutcome,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileLifecycleAckOutcome {
    Acknowledged,
    NotEntered { status: NtStatus },
    Rejected { status: NtStatus },
    Indeterminate { transport_status: NtStatus },
}

#[derive(Debug)]
pub enum FileLifecycleAckResult {
    Acknowledged { completion: CompletedIrp },
    Retained(RetainedFileLifecycle),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileLifecycleOutcome {
    /// The transport proves that the driver was never entered.
    NotEntered {
        status: NtStatus,
    },
    Returned {
        status: NtStatus,
        information: u64,
    },
    Pending,
    /// Driver entry may have happened; the effect must never be replayed.
    Indeterminate {
        transport_status: NtStatus,
    },
}

#[derive(Debug)]
pub enum FileLifecycleResult {
    NotEntered {
        status: NtStatus,
        prepared: PreparedFileLifecycle,
    },
    Returned {
        status: NtStatus,
        information: u64,
    },
    Outstanding(RetainedFileLifecycle),
}

#[derive(Debug)]
#[must_use = "recover the unchanged owner"]
pub struct FileLifecycleRejection<T> {
    status: NtStatus,
    owner: T,
}

impl<T> FileLifecycleRejection<T> {
    pub fn status(&self) -> NtStatus {
        self.status
    }
    pub fn into_parts(self) -> (NtStatus, T) {
        (self.status, self.owner)
    }
}

macro_rules! owner_accessors {
    ($ty:ty, $field:tt) => {
        impl $ty {
            pub fn file_id(&self) -> FileId {
                self.$field.file_id
            }
            pub fn irp_id(&self) -> IrpId {
                self.$field.projection.irp_id
            }
            pub fn projection(&self) -> &IrpProjection {
                &self.$field.projection
            }
            pub fn target(&self) -> DispatchTarget {
                self.$field.target
            }
        }
    };
}
owner_accessors!(PreparedFileLifecycle, 0);
owner_accessors!(FileLifecycleInvocation, 0);
owner_accessors!(RetainedFileLifecycle, owner);
owner_accessors!(FileLifecycleAckInvocation, owner);

impl FileLifecycleInvocation {
    pub fn returned(self, outcome: FileLifecycleOutcome) -> FileLifecycleReturn {
        FileLifecycleReturn {
            owner: self.0,
            outcome,
        }
    }
}

impl RetainedFileLifecycle {
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }
    pub fn acknowledgement_is_uncertain(&self) -> bool {
        self.ack_uncertain
    }
}

impl FileLifecycleAckInvocation {
    pub fn completion(&self) -> CompletedIrp {
        self.completion
    }
    pub fn returned(self, outcome: FileLifecycleAckOutcome) -> FileLifecycleAckReturn {
        FileLifecycleAckReturn {
            invocation: self,
            outcome,
        }
    }
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Take one ready hosted lifecycle operation without entering its backend.
    /// The returned preparation owns the exact File/IRP until it is begun or
    /// explicitly requeued; a second pump cannot select the same File. The
    /// integration host supplies the retained caller's TID for each File; this
    /// scalar is IRP metadata, not authority to reconstruct that caller.
    pub fn prepare_next_queued_peer_file_lifecycle(
        &mut self,
        mut requestor_tid: impl FnMut(FileId) -> Option<u64>,
    ) -> Result<Option<PreparedFileLifecycle>, NtStatus> {
        if !self.owned_peer_file_lifecycle {
            return Ok(None);
        }
        let mut ready = None;
        for (file_id, file) in self.files.iter() {
            if !file.close_retry_queued || !file.close_deferred {
                continue;
            }
            let major = match file.state {
                FileState::CleanupPending if !file.cleanup_dispatched => major::IRP_MJ_CLEANUP,
                FileState::ClosePending
                    if !file.close_dispatched
                        && file.outstanding_irp_refs == 0
                        && self.file_reference_count(file_id) == 0 => major::IRP_MJ_CLOSE,
                _ => continue,
            };
            if self.lifecycle_uses_driver_peer(file_id, major)? {
                let Some(tid) = requestor_tid(file_id).filter(|tid| *tid != 0) else {
                    continue;
                };
                ready = Some((file.client_id, file_id, tid));
                break;
            }
        }
        let Some((client, file_id, tid)) = ready else {
            return Ok(None);
        };
        let prepared = self.prepare_file_lifecycle_owned(client, file_id, tid)?;
        assert!(self.take_deferred_file_close(file_id));
        Ok(Some(prepared))
    }

    /// Give a preparation back to the close pump when native dispatch could
    /// not reserve its owner or physical route before driver entry.
    pub fn requeue_prepared_file_lifecycle(
        &mut self,
        prepared: PreparedFileLifecycle,
    ) -> Result<(), FileLifecycleRejection<PreparedFileLifecycle>> {
        let file_id = prepared.file_id();
        self.discard_prepared_file_lifecycle(prepared)?;
        self.queue_deferred_file_close(file_id);
        Ok(())
    }

    /// Reserve one exact lifecycle IRP. The caller must begin it before yielding
    /// control; preparation itself performs no external driver effect.
    pub fn prepare_file_lifecycle_owned(
        &mut self,
        client: ClientId,
        file_id: FileId,
        requestor_tid: u64,
    ) -> Result<PreparedFileLifecycle, NtStatus> {
        if requestor_tid == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        if file.client_id != client || !file.close_deferred {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let (major, parameters) = match file.state {
            FileState::CleanupPending if !file.cleanup_dispatched => {
                (major::IRP_MJ_CLEANUP, IoParameters::Cleanup)
            }
            FileState::ClosePending
                if !file.close_dispatched
                    && file.outstanding_irp_refs == 0
                    && self.file_reference_count(file_id) == 0 =>
            {
                (major::IRP_MJ_CLOSE, IoParameters::Close)
            }
            _ => return Err(NtStatus::DELETE_PENDING),
        };
        if self.irps.iter().any(|(_, irp)| {
            irp.file_id == Some(file_id)
                && irp.detached_file_owner
                && matches!(
                    irp.origin_major,
                    major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE
                )
        }) {
            return Err(NtStatus::DELETE_PENDING);
        }
        let device_id = file.device_id;
        let driver_id = self
            .device(device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .driver_id;
        let mut record = self.build_irp_record(
            client,
            driver_id,
            device_id,
            Some(file_id),
            major,
            parameters,
        )?;
        record.requestor_tid = requestor_tid;
        record.user_data = self
            .file(file_id)
            .and_then(|file| file.driver_context)
            .unwrap_or(0);
        let projection = IrpProjection::from_record(&record)?;
        let target = self
            .driver(projection.driver_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .dispatch
            .get(major);
        target
            .mock_id()
            .map(|id| id.0 as usize)
            .or_else(|| target.kernel_id().map(|id| id.0 as usize))
            .or_else(|| target.driver_peer_id().map(|id| id.0 as usize))
            .filter(|index| *index < self.backends.len())
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        let manager = self.ensure_ownership_identity()?;
        let irp_id = self.allocate_irp(record)?;
        let irp = self.irp_mut(irp_id).expect("allocated lifecycle IRP");
        assert!(irp.transition(IrpState::Initialized));
        irp.detached_file_owner = true;
        let mut projection = projection;
        projection.irp_id = irp_id;
        Ok(PreparedFileLifecycle(Owner {
            manager,
            client,
            file_id,
            projection,
            target,
        }))
    }

    fn validate_lifecycle_owner(&self, owner: &Owner, state: IrpState) -> Result<(), NtStatus> {
        if owner.manager == 0 || owner.manager != self.ownership_identity() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let file = self.file(owner.file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        let irp = self
            .irp(owner.projection.irp_id)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        let mut live_projection = IrpProjection::from_record(irp)?;
        live_projection.status = owner.projection.status;
        live_projection.information = owner.projection.information;
        if file.client_id != owner.client
            || irp.client_id != owner.client
            || irp.file_id != Some(owner.file_id)
            || irp.state != state
            || !irp.detached_file_owner
            || live_projection != owner.projection
            || self
                .driver(owner.projection.driver_id)
                .map(|driver| driver.dispatch.get(owner.projection.major))
                != Some(owner.target)
            || self
                .device(owner.projection.device_id)
                .map(|device| device.driver_id)
                != Some(owner.projection.driver_id)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    /// Publish the in-flight owner before the native driver effect. A second
    /// lifecycle operation on this File is barred while this owner is away.
    pub fn begin_prepared_file_lifecycle(
        &mut self,
        prepared: PreparedFileLifecycle,
    ) -> Result<FileLifecycleInvocation, FileLifecycleRejection<PreparedFileLifecycle>> {
        let valid = (|| {
            self.validate_lifecycle_owner(&prepared.0, IrpState::Initialized)?;
            let file = self
                .file(prepared.file_id())
                .ok_or(NtStatus::INVALID_HANDLE)?;
            if !file.close_deferred
                || match prepared.projection().major {
                    major::IRP_MJ_CLEANUP => {
                        file.state != FileState::CleanupPending || file.cleanup_dispatched
                    }
                    major::IRP_MJ_CLOSE => {
                        file.state != FileState::ClosePending
                            || file.close_dispatched
                            || file.outstanding_irp_refs != 1
                            || self.file_reference_count(prepared.file_id()) != 0
                    }
                    _ => true,
                }
            {
                return Err(NtStatus::DELETE_PENDING);
            }
            Ok(())
        })();
        if let Err(status) = valid {
            return Err(FileLifecycleRejection {
                status,
                owner: prepared,
            });
        }
        if !self
            .irp_mut(prepared.irp_id())
            .unwrap()
            .transition(IrpState::Dispatched)
        {
            return Err(FileLifecycleRejection {
                status: NtStatus::INVALID_PARAMETER,
                owner: prepared,
            });
        }
        let major = prepared.projection().major;
        let file = self
            .file_mut(prepared.file_id())
            .expect("validated lifecycle File");
        if major == major::IRP_MJ_CLEANUP {
            file.cleanup_dispatched = true;
        } else {
            file.close_dispatched = true;
        }
        Ok(FileLifecycleInvocation(prepared.0))
    }

    pub fn finish_file_lifecycle(
        &mut self,
        returned: FileLifecycleReturn,
    ) -> Result<FileLifecycleResult, FileLifecycleRejection<FileLifecycleReturn>> {
        let valid = (|| {
            let state = self
                .irp(returned.owner.projection.irp_id)
                .ok_or(NtStatus::INVALID_HANDLE)?
                .state;
            if !matches!(
                state,
                IrpState::Dispatched | IrpState::Completed | IrpState::Indeterminate
            ) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            self.validate_lifecycle_owner(&returned.owner, state)?;
            if state == IrpState::Completed
                && self
                    .completed_irp(returned.owner.projection.irp_id)
                    .is_none_or(|completion| {
                        completion.completion_origin != IrpCompletionOrigin::Driver
                    })
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if matches!(
                returned.outcome,
                FileLifecycleOutcome::Returned {
                    status: NtStatus::PENDING,
                    ..
                }
            ) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let target_state = match returned.outcome {
                FileLifecycleOutcome::Pending => Some(IrpState::Pending),
                FileLifecycleOutcome::Indeterminate { .. } => Some(IrpState::Indeterminate),
                _ => None,
            };
            if state == IrpState::Dispatched
                && target_state.is_some_and(|target| !state.can_transition_to(target))
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let file = self.file(returned.owner.file_id).unwrap();
            if match returned.owner.projection.major {
                major::IRP_MJ_CLEANUP => {
                    file.state != FileState::CleanupPending || !file.cleanup_dispatched
                }
                major::IRP_MJ_CLOSE => {
                    file.state != FileState::ClosePending || !file.close_dispatched
                }
                _ => true,
            } {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(state)
        })();
        let state = match valid {
            Ok(state) => state,
            Err(status) => {
                return Err(FileLifecycleRejection {
                    status,
                    owner: returned,
                })
            }
        };
        let FileLifecycleReturn { owner, outcome } = returned;
        let irp_id = owner.projection.irp_id;
        let file_id = owner.file_id;
        if matches!(state, IrpState::Completed | IrpState::Indeterminate) {
            return Ok(FileLifecycleResult::Outstanding(RetainedFileLifecycle {
                owner,
                indeterminate: state == IrpState::Indeterminate,
                ack_uncertain: false,
            }));
        }
        Ok(match outcome {
            FileLifecycleOutcome::NotEntered { status } => {
                self.irp_mut(irp_id).unwrap().state = IrpState::Initialized;
                let file = self.file_mut(file_id).unwrap();
                if owner.projection.major == major::IRP_MJ_CLEANUP {
                    file.cleanup_dispatched = false;
                } else {
                    file.close_dispatched = false;
                }
                FileLifecycleResult::NotEntered {
                    status,
                    prepared: PreparedFileLifecycle(owner),
                }
            }
            FileLifecycleOutcome::Returned {
                status,
                information,
            } => {
                self.irp_mut(irp_id).unwrap().detached_file_owner = false;
                let completed = self.complete_sync(
                    irp_id,
                    Ok(crate::DispatchOutcome::Completed {
                        status,
                        information,
                        file_context: None,
                    }),
                );
                let expected = if status.is_success() {
                    Ok(information)
                } else {
                    Err(status)
                };
                if completed != expected {
                    unreachable!("validated synchronous lifecycle IRP failed to complete");
                }
                if owner.projection.major == major::IRP_MJ_CLEANUP {
                    self.file_mut(file_id)
                        .unwrap()
                        .transition(FileState::CleanupComplete);
                }
                self.queue_deferred_file_close(file_id);
                FileLifecycleResult::Returned {
                    status,
                    information,
                }
            }
            FileLifecycleOutcome::Pending => {
                self.irp_mut(irp_id).unwrap().transition(IrpState::Pending);
                FileLifecycleResult::Outstanding(RetainedFileLifecycle {
                    owner,
                    indeterminate: false,
                    ack_uncertain: false,
                })
            }
            FileLifecycleOutcome::Indeterminate { transport_status } => {
                let irp = self.irp_mut(irp_id).unwrap();
                irp.status = transport_status;
                irp.transition(IrpState::Indeterminate);
                FileLifecycleResult::Outstanding(RetainedFileLifecycle {
                    owner,
                    indeterminate: true,
                    ack_uncertain: false,
                })
            }
        })
    }

    /// Abort a prepared operation that has not crossed the driver boundary.
    pub fn discard_prepared_file_lifecycle(
        &mut self,
        prepared: PreparedFileLifecycle,
    ) -> Result<(), FileLifecycleRejection<PreparedFileLifecycle>> {
        if let Err(status) = self.validate_lifecycle_owner(&prepared.0, IrpState::Initialized) {
            return Err(FileLifecycleRejection {
                status,
                owner: prepared,
            });
        }
        self.irp_mut(prepared.irp_id()).unwrap().detached_file_owner = false;
        self.free_irp(prepared.irp_id())
            .expect("validated prepared lifecycle IRP");
        Ok(())
    }

    /// Transfer only the exact, genuinely published driver completion to an
    /// ACK executor. The backend call itself must occur without `&mut self`.
    pub fn begin_retained_file_lifecycle_ack(
        &mut self,
        retained: RetainedFileLifecycle,
    ) -> Result<FileLifecycleAckInvocation, FileLifecycleRejection<RetainedFileLifecycle>> {
        let valid = (|| {
            if retained.ack_uncertain {
                return Err(NtStatus::DELETE_PENDING);
            }
            self.validate_lifecycle_owner(&retained.owner, IrpState::Completed)?;
            let completion = self
                .completed_irp(retained.irp_id())
                .ok_or(NtStatus::INVALID_PARAMETER)?;
            if completion.completion_origin != IrpCompletionOrigin::Driver
                || completion.file_id != Some(retained.file_id())
                || completion.major != retained.projection().major
                || completion.completion_driver_id != retained.projection().driver_id
                || completion.completion_device_id != retained.projection().device_id
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(completion)
        })();
        match valid {
            Ok(completion) => Ok(FileLifecycleAckInvocation {
                owner: retained.owner,
                completion,
            }),
            Err(status) => Err(FileLifecycleRejection {
                status,
                owner: retained,
            }),
        }
    }

    /// Commit a proven ACK once. Rejected/non-entered ACKs retain the owner;
    /// ambiguous ACKs retain a no-replay barrier until external reconciliation.
    pub fn finish_retained_file_lifecycle_ack(
        &mut self,
        returned: FileLifecycleAckReturn,
    ) -> Result<FileLifecycleAckResult, FileLifecycleRejection<FileLifecycleAckReturn>> {
        let valid = (|| {
            self.validate_lifecycle_owner(&returned.invocation.owner, IrpState::Completed)?;
            if self.completed_irp(returned.invocation.irp_id())
                != Some(returned.invocation.completion)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        })();
        if let Err(status) = valid {
            return Err(FileLifecycleRejection {
                status,
                owner: returned,
            });
        }
        let FileLifecycleAckReturn {
            invocation,
            outcome,
        } = returned;
        let FileLifecycleAckInvocation { owner, completion } = invocation;
        let irp_id = owner.projection.irp_id;
        Ok(match outcome {
            FileLifecycleAckOutcome::Acknowledged => {
                self.irp_mut(irp_id).unwrap().detached_file_owner = false;
                self.free_irp(irp_id)
                    .expect("validated acknowledged lifecycle IRP");
                if owner.projection.major == major::IRP_MJ_CLEANUP {
                    let file = self.file_mut(owner.file_id).unwrap();
                    if file.state == FileState::CleanupPending {
                        file.transition(FileState::CleanupComplete);
                    }
                }
                self.queue_deferred_file_close(owner.file_id);
                FileLifecycleAckResult::Acknowledged { completion }
            }
            FileLifecycleAckOutcome::Indeterminate { .. } => {
                FileLifecycleAckResult::Retained(RetainedFileLifecycle {
                    owner,
                    indeterminate: false,
                    ack_uncertain: true,
                })
            }
            FileLifecycleAckOutcome::NotEntered { .. }
            | FileLifecycleAckOutcome::Rejected { .. } => {
                FileLifecycleAckResult::Retained(RetainedFileLifecycle {
                    owner,
                    indeterminate: false,
                    ack_uncertain: false,
                })
            }
        })
    }
}

#[cfg(test)]
mod tests;
