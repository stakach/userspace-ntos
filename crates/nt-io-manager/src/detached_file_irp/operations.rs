//! Consuming cancellation, immutable output capture, and terminal ACK admission.
use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExternalFileIrpCancelPhase {
    #[default]
    None,
    Queued,
    Invoking,
    Accepted,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExternalFileIrpIntent {
    pub cancel: ExternalFileIrpCancelPhase,
    pub abandoned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalFileIrpOutputCapture {
    Information,
    BufferedDeviceControlCapacity,
}
impl ExternalFileIrpOutputCapture {
    pub(super) fn required_len(
        self,
        owner: &Owner,
        completion: &CompletedIrp,
    ) -> Result<usize, NtStatus> {
        let capacity = owner.buffers.output.len();
        match self {
            Self::Information => Ok(crate::completion_output_transfer_len(
                completion.information,
                capacity as u64,
            ) as usize),
            Self::BufferedDeviceControlCapacity => {
                if !matches!(
                    owner.projection.major,
                    major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL
                ) {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
                match &owner.projection.parameters {
                    IoParameters::DeviceControl(p) | IoParameters::InternalDeviceControl(p)
                        if nt_io_abi::ioctl::method(p.ioctl_code)
                            == nt_io_abi::ioctl::METHOD_BUFFERED =>
                    {
                        Ok(capacity)
                    }
                    _ => Err(NtStatus::INVALID_PARAMETER),
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalFileIrpCancelOutcome {
    Accepted,
    NotEntered { status: NtStatus },
    Rejected { status: NtStatus },
    Indeterminate { transport_status: NtStatus },
}
#[derive(Debug)]
#[must_use = "return the exact cancellation invocation"]
pub struct ExternalFileIrpCancelInvocation {
    retained: RetainedExternalFileIrp,
}
#[derive(Debug)]
#[must_use = "finish through the issuing manager without repeating accepted cancellation"]
pub struct ExternalFileIrpCancelReturn {
    invocation: ExternalFileIrpCancelInvocation,
    outcome: ExternalFileIrpCancelOutcome,
}
#[derive(Debug)]
#[must_use = "retain the IRP until its genuine completion"]
pub struct ExternalFileIrpCancelResult {
    retained: RetainedExternalFileIrp,
    outcome: ExternalFileIrpCancelOutcome,
}
impl ExternalFileIrpCancelInvocation {
    pub fn irp_id(&self) -> IrpId {
        self.retained.irp_id()
    }
    pub fn route(&self) -> ExternalFileIrpRoute {
        self.retained.route()
    }
    pub fn returned(self, outcome: ExternalFileIrpCancelOutcome) -> ExternalFileIrpCancelReturn {
        ExternalFileIrpCancelReturn {
            invocation: self,
            outcome,
        }
    }
}
impl ExternalFileIrpCancelReturn {
    pub fn outcome(&self) -> ExternalFileIrpCancelOutcome {
        self.outcome
    }
}
impl ExternalFileIrpCancelResult {
    pub fn outcome(&self) -> ExternalFileIrpCancelOutcome {
        self.outcome
    }
    pub fn into_parts(self) -> (RetainedExternalFileIrp, ExternalFileIrpCancelOutcome) {
        (self.retained, self.outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalFileIrpCopyOutcome {
    Copied { bytes: usize },
    NotEntered { status: NtStatus },
    Rejected { status: NtStatus },
    Indeterminate { transport_status: NtStatus },
}
#[derive(Debug)]
#[must_use = "return the read-only copy invocation"]
pub struct ExternalFileIrpCopyInvocation {
    completion: ExternalFileIrpCompletionInvocation,
    staging: Vec<u8>,
}
#[derive(Debug)]
#[must_use = "commit or retry this exact immutable output range"]
pub struct ExternalFileIrpCopyReturn {
    invocation: ExternalFileIrpCopyInvocation,
    outcome: ExternalFileIrpCopyOutcome,
}
impl ExternalFileIrpCopyInvocation {
    pub fn irp_id(&self) -> IrpId {
        self.completion.irp_id()
    }
    pub fn route(&self) -> ExternalFileIrpRoute {
        self.completion.route()
    }
    pub fn completion(&self) -> &CompletedIrp {
        &self.completion.completion
    }
    pub fn offset(&self) -> usize {
        self.completion.captured
    }
    pub fn staging_mut(&mut self) -> &mut [u8] {
        &mut self.staging
    }
    pub fn requested_len(&self) -> usize {
        self.staging.len()
    }
    pub fn returned(self, outcome: ExternalFileIrpCopyOutcome) -> ExternalFileIrpCopyReturn {
        ExternalFileIrpCopyReturn {
            invocation: self,
            outcome,
        }
    }
}
impl ExternalFileIrpCopyReturn {
    /// This is an immutable read, never a mutating cancel or terminal acknowledgement.
    pub fn retry(self) -> ExternalFileIrpCopyInvocation {
        self.invocation
    }
    /// Discard only the uncommitted staging bytes, retaining the original completion owner.
    pub fn into_completion(self) -> ExternalFileIrpCompletionInvocation {
        self.invocation.completion
    }
    pub fn outcome(&self) -> ExternalFileIrpCopyOutcome {
        self.outcome
    }
}

#[derive(Debug)]
#[must_use = "retain exact ACK evidence through local retirement"]
/// ```compile_fail
/// use nt_io_manager::detached_file_irp::{ExternalFileIrpAckInvocation, ExternalFileIrpAcknowledgement};
/// fn duplicate(owner: ExternalFileIrpAckInvocation) {
///     let first = owner.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged);
///     let second = owner.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged);
/// }
/// ```
pub struct ExternalFileIrpAckInvocation {
    pub(super) owner: Owner,
    pub(super) completion: CompletedIrp,
}
owner_accessors!(ExternalFileIrpAckInvocation, owner);
impl ExternalFileIrpAckInvocation {
    pub fn completion(&self) -> &CompletedIrp {
        &self.completion
    }
    pub fn acknowledged(
        self,
        acknowledgement: ExternalFileIrpAcknowledgement,
    ) -> ExternalFileIrpCompletionReturn {
        ExternalFileIrpCompletionReturn {
            invocation: self,
            acknowledgement,
        }
    }
}

impl<P: ObjectManagerPort> IoManager<P> {
    pub fn detached_file_irp_intent(
        &self,
        client: ClientId,
        id: IrpId,
    ) -> Result<ExternalFileIrpIntent, NtStatus> {
        let record = self.irp(id).ok_or(NtStatus::INVALID_HANDLE)?;
        if record.client_id != client {
            return Err(NtStatus::ACCESS_DENIED);
        }
        if !record.detached_file_owner {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(record.detached_file_intent)
    }

    pub(crate) fn queue_detached_file_irp_intent(
        &mut self,
        client: ClientId,
        id: IrpId,
        abandon: bool,
    ) -> Result<bool, NtStatus> {
        self.detached_file_irp_intent(client, id)?;
        let record = self.irp_mut(id).unwrap();
        record.detached_file_intent.abandoned |= abandon;
        if record.state.is_final() {
            return Ok(false);
        }
        if !matches!(
            record.state,
            IrpState::Initialized
                | IrpState::Dispatched
                | IrpState::Pending
                | IrpState::CancelRequested
                | IrpState::Indeterminate
        ) {
            return Ok(false);
        }
        if record.detached_file_intent.cancel == ExternalFileIrpCancelPhase::None {
            record.detached_file_intent.cancel = ExternalFileIrpCancelPhase::Queued;
        }
        record.cancel = crate::CancelState::CancelRequested;
        if record.state == IrpState::Pending {
            assert!(record.transition(IrpState::CancelRequested));
        }
        Ok(true)
    }

    pub fn begin_external_file_irp_cancel(
        &mut self,
        retained: RetainedExternalFileIrp,
    ) -> Result<ExternalFileIrpCancelInvocation, ExternalFileIrpRejection<RetainedExternalFileIrp>>
    {
        let valid = (|| {
            self.validate_detached_owner(&retained.owner)?;
            self.validate_detached_route(&retained.owner)?;
            let record = self.irp(retained.irp_id()).unwrap();
            if record.detached_file_intent.cancel != ExternalFileIrpCancelPhase::Queued
                || !matches!(
                    record.state,
                    IrpState::Pending | IrpState::CancelRequested | IrpState::Indeterminate
                )
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        })();
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: retained,
            });
        }
        self.irp_mut(retained.irp_id())
            .unwrap()
            .detached_file_intent
            .cancel = ExternalFileIrpCancelPhase::Invoking;
        Ok(ExternalFileIrpCancelInvocation { retained })
    }

    pub fn finish_external_file_irp_cancel(
        &mut self,
        returned: ExternalFileIrpCancelReturn,
    ) -> Result<ExternalFileIrpCancelResult, ExternalFileIrpRejection<ExternalFileIrpCancelReturn>>
    {
        let valid = self
            .validate_detached_owner(&returned.invocation.retained.owner)
            .and_then(|_| {
                let record = self.irp(returned.invocation.irp_id()).unwrap();
                if record.detached_file_intent.cancel != ExternalFileIrpCancelPhase::Invoking {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
                if record.state == IrpState::Completed {
                    if !self.completed_irps.contains(&record.id)
                        || record.completion_origin != Some(IrpCompletionOrigin::Driver)
                    {
                        return Err(NtStatus::INVALID_PARAMETER);
                    }
                } else if !matches!(
                    record.state,
                    IrpState::Pending | IrpState::CancelRequested | IrpState::Indeterminate
                ) {
                    return Err(NtStatus::INVALID_PARAMETER);
                }
                Ok(())
            });
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: returned,
            });
        }
        self.irp_mut(returned.invocation.irp_id())
            .unwrap()
            .detached_file_intent
            .cancel = match returned.outcome {
            ExternalFileIrpCancelOutcome::Accepted => ExternalFileIrpCancelPhase::Accepted,
            ExternalFileIrpCancelOutcome::Indeterminate { .. } => {
                ExternalFileIrpCancelPhase::Indeterminate
            }
            ExternalFileIrpCancelOutcome::NotEntered { .. }
            | ExternalFileIrpCancelOutcome::Rejected { .. } => ExternalFileIrpCancelPhase::Queued,
        };
        Ok(ExternalFileIrpCancelResult {
            retained: returned.invocation.retained,
            outcome: returned.outcome,
        })
    }

    fn validate_detached_completion_operation(
        &self,
        invocation: &ExternalFileIrpCompletionInvocation,
    ) -> Result<(), NtStatus> {
        self.validate_detached_owner(&invocation.owner)?;
        if self.completed_irp_snapshot(invocation.irp_id()).as_ref() != Some(&invocation.completion)
            || !self.completed_irps.contains(&invocation.irp_id())
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn begin_external_file_irp_copy(
        &mut self,
        completion: ExternalFileIrpCompletionInvocation,
        max_bytes: usize,
    ) -> Result<
        ExternalFileIrpCopyInvocation,
        ExternalFileIrpRejection<ExternalFileIrpCompletionInvocation>,
    > {
        let result = (|| {
            self.validate_detached_completion_operation(&completion)?;
            if max_bytes == 0 || completion.capture_complete() {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let length = max_bytes.min(completion.capture_len - completion.captured);
            let mut staging = Vec::new();
            staging
                .try_reserve_exact(length)
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            staging.resize(length, 0);
            Ok(staging)
        })();
        match result {
            Ok(staging) => Ok(ExternalFileIrpCopyInvocation {
                completion,
                staging,
            }),
            Err(status) => Err(ExternalFileIrpRejection {
                status,
                owner: completion,
            }),
        }
    }

    pub fn finish_external_file_irp_copy(
        &mut self,
        returned: ExternalFileIrpCopyReturn,
    ) -> Result<
        ExternalFileIrpCompletionInvocation,
        ExternalFileIrpRejection<ExternalFileIrpCopyReturn>,
    > {
        let result = self
            .validate_detached_completion_operation(&returned.invocation.completion)
            .and_then(|_| match returned.outcome {
                ExternalFileIrpCopyOutcome::Copied { bytes }
                    if bytes == returned.invocation.staging.len() =>
                {
                    Ok(())
                }
                ExternalFileIrpCopyOutcome::Copied { .. } => Err(NtStatus::INVALID_PARAMETER),
                ExternalFileIrpCopyOutcome::NotEntered { status }
                | ExternalFileIrpCopyOutcome::Rejected { status } => Err(status),
                ExternalFileIrpCopyOutcome::Indeterminate { transport_status } => {
                    Err(transport_status)
                }
            });
        if let Err(status) = result {
            return Err(ExternalFileIrpRejection {
                status,
                owner: returned,
            });
        }
        let ExternalFileIrpCopyInvocation {
            mut completion,
            staging,
        } = returned.invocation;
        let end = completion.captured + staging.len();
        completion.owner.buffers.output[completion.captured..end].copy_from_slice(&staging);
        completion.captured = end;
        Ok(completion)
    }

    /// Abandonment suppresses delivery, not the driver's obligation to complete and ACK.
    pub fn begin_external_file_irp_acknowledgement(
        &mut self,
        completion: ExternalFileIrpCompletionInvocation,
    ) -> Result<
        ExternalFileIrpAckInvocation,
        ExternalFileIrpRejection<ExternalFileIrpCompletionInvocation>,
    > {
        let valid = self
            .validate_detached_completion_operation(&completion)
            .and_then(|_| {
                if !completion.capture_complete()
                    && !self
                        .irp(completion.irp_id())
                        .unwrap()
                        .detached_file_intent
                        .abandoned
                {
                    return Err(NtStatus::DELETE_PENDING);
                }
                Ok(())
            });
        if let Err(status) = valid {
            return Err(ExternalFileIrpRejection {
                status,
                owner: completion,
            });
        }
        Ok(ExternalFileIrpAckInvocation {
            owner: completion.owner,
            completion: completion.completion,
        })
    }
}
