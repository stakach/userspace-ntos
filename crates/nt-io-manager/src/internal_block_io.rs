//! Canonical File IRP admission for internal block storage.
//!
//! Dispatch, pending buffers, uncertain entry, output copy, and completion acknowledgement
//! remain owned by `detached_file_irp`. The caller carries this small completion contract beside
//! that consuming owner; an unacknowledged or uncertain operation must not be replayed.

use crate::detached_file_irp::{
    ExternalFileIrpAckInvocation, ExternalFileIrpAcknowledgement, ExternalFileIrpBuffers,
    ExternalFileIrpCompletionInvocation, ExternalFileIrpCompletionReturn,
    ExternalFileIrpCopyInvocation, ExternalFileIrpCopyOutcome, ExternalFileIrpCopyReturn,
    ExternalFileIrpInvocation, ExternalFileIrpOutcome, ExternalFileIrpRequest,
    ExternalFileIrpResult, ExternalFileIrpReturn, ExternalFileIrpRoute, ExternalFileIrpTerminal,
    ExternalFileIrpTerminalReceipt, PreparedExternalFileIrp, RetainedExternalFileIrp,
};
use crate::{
    CompletedIrp, DeviceId, FileId, FileState, IoManager, IoParameters, IrpId, IrpProjection,
    ObjectManagerPort, ReadWriteParameters, StackFlags,
};
use alloc::vec::Vec;
use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::ClientId;

/// The exact opened File and Device stack that authorizes one internal I/O request.
/// `top_device_id` includes its generation and must still be the live stack top.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalBlockRoute {
    pub file_id: FileId,
    pub device_id: DeviceId,
    pub top_device_id: DeviceId,
    /// Authenticated logical sector size of the opened disk route.
    pub logical_block_bytes: u32,
    /// Provider/DMA transport limit for one request on this route.
    pub max_transfer_bytes: u32,
}

fn validate_raw_transfer(
    route: InternalBlockRoute,
    offset: u64,
    length: u32,
) -> Result<(), NtStatus> {
    let block = route.logical_block_bytes;
    if block == 0
        || route.max_transfer_bytes < block
        || length == 0
        || length > route.max_transfer_bytes
        || length % block != 0
        || offset % u64::from(block) != 0
        || offset.checked_add(u64::from(length)).is_none()
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(())
}

#[derive(Debug)]
pub enum InternalBlockOperation {
    Read { offset: u64, length: u32 },
    Write { offset: u64, bytes: Vec<u8> },
    Flush,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalBlockCompletionContract {
    client: ClientId,
    route: InternalBlockRoute,
    irp_id: IrpId,
    major: u8,
    max_transfer: u32,
}

impl InternalBlockCompletionContract {
    pub fn irp_id(self) -> IrpId {
        self.irp_id
    }

    /// Check terminal identity and the exact number of bytes the provider reported. A malformed
    /// terminal must remain owned; callers check before copy or ACK, while a pending request is
    /// still retained by its detached File IRP owner.
    pub fn validate_completion(self, completion: &CompletedIrp) -> Result<usize, NtStatus> {
        if completion.id != self.irp_id
            || completion.client_id != self.client
            || completion.file_id != Some(self.route.file_id)
            || completion.device_id != self.route.device_id
            || completion.major != self.major
            || completion.status == NtStatus::PENDING
            || completion.information > u64::from(self.max_transfer)
            || completion.status.is_success()
                && self.major != major::IRP_MJ_FLUSH_BUFFERS
                && completion.information != u64::from(self.max_transfer)
            || self.major == major::IRP_MJ_FLUSH_BUFFERS && completion.information != 0
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(completion.information as usize)
    }

    /// A receipt is valid only after the issuing manager retired the exact IRP. Pending and
    /// indeterminate requests cannot mint this receipt without genuine completion/ACK.
    pub fn validate_receipt<P: ObjectManagerPort>(
        self,
        io: &IoManager<P>,
        receipt: &ExternalFileIrpTerminalReceipt,
    ) -> Result<usize, NtStatus> {
        if !io.accepts_external_file_irp_receipt(receipt) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.validate_completion(receipt.completion())
    }
}

#[derive(Debug)]
#[must_use = "dispatch or discard the owned internal block IRP"]
pub struct PreparedInternalBlockIrp {
    owner: PreparedExternalFileIrp,
    contract: InternalBlockCompletionContract,
}

impl PreparedInternalBlockIrp {
    pub fn irp_id(&self) -> IrpId {
        self.owner.irp_id()
    }
    pub fn projection(&self) -> &IrpProjection {
        self.owner.projection()
    }
    pub fn buffers(&self) -> &ExternalFileIrpBuffers {
        self.owner.buffers()
    }
}

#[derive(Debug)]
#[must_use = "return the exact native block invocation"]
pub struct InternalBlockInvocation {
    owner: ExternalFileIrpInvocation,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockInvocation {
    pub fn irp_id(&self) -> IrpId {
        self.owner.irp_id()
    }
    pub fn route(&self) -> ExternalFileIrpRoute {
        self.owner.route()
    }
    pub fn projection(&self) -> &IrpProjection {
        self.owner.projection()
    }
    pub fn buffers_mut(&mut self) -> crate::detached_file_irp::ExternalFileIrpBufferView<'_> {
        self.owner.buffers_mut()
    }
    pub fn returned(self, outcome: ExternalFileIrpOutcome) -> InternalBlockReturn {
        InternalBlockReturn {
            owner: self.owner.returned(outcome),
            contract: self.contract,
        }
    }
}

#[derive(Debug)]
#[must_use = "finish through the issuing I/O Manager"]
pub struct InternalBlockReturn {
    owner: ExternalFileIrpReturn,
    contract: InternalBlockCompletionContract,
}

#[derive(Debug)]
pub enum InternalBlockResult {
    NotEntered {
        status: NtStatus,
        prepared: PreparedInternalBlockIrp,
    },
    Returned(InternalBlockTerminal),
    Pending(InternalBlockPending),
    Indeterminate {
        transport_status: NtStatus,
        retained: InternalBlockPending,
    },
}

#[derive(Debug)]
#[must_use = "retire only after the exact block completion validates"]
pub struct InternalBlockTerminal {
    owner: ExternalFileIrpTerminal,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockTerminal {
    pub fn completion(&self) -> &CompletedIrp {
        self.owner.completion()
    }
    pub fn irp_id(&self) -> IrpId {
        self.owner.irp_id()
    }
}

#[derive(Debug)]
#[must_use = "retain until genuine provider completion"]
pub struct InternalBlockPending {
    owner: RetainedExternalFileIrp,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockPending {
    pub fn irp_id(&self) -> IrpId {
        self.owner.irp_id()
    }
    pub fn route(&self) -> ExternalFileIrpRoute {
        self.owner.route()
    }
    pub fn is_indeterminate(&self) -> bool {
        self.owner.is_indeterminate()
    }
    pub fn buffers(&self) -> &ExternalFileIrpBuffers {
        self.owner.buffers()
    }
}

#[derive(Debug)]
#[must_use = "capture output then acknowledge exact completion"]
pub struct InternalBlockCompletion {
    owner: ExternalFileIrpCompletionInvocation,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockCompletion {
    pub fn completion(&self) -> &CompletedIrp {
        self.owner.completion()
    }
    pub fn capture_complete(&self) -> bool {
        self.owner.capture_complete()
    }
    pub fn capture_len(&self) -> usize {
        self.owner.capture_len()
    }
}

#[derive(Debug)]
#[must_use = "return copied bytes through the issuing manager"]
pub struct InternalBlockCopy {
    owner: ExternalFileIrpCopyInvocation,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockCopy {
    pub fn irp_id(&self) -> IrpId {
        self.owner.irp_id()
    }
    pub fn route(&self) -> ExternalFileIrpRoute {
        self.owner.route()
    }
    pub fn offset(&self) -> usize {
        self.owner.offset()
    }
    pub fn staging_mut(&mut self) -> &mut [u8] {
        self.owner.staging_mut()
    }
    pub fn requested_len(&self) -> usize {
        self.owner.requested_len()
    }
    pub fn returned(self, outcome: ExternalFileIrpCopyOutcome) -> InternalBlockCopyReturn {
        InternalBlockCopyReturn {
            owner: self.owner.returned(outcome),
            contract: self.contract,
        }
    }
}

#[derive(Debug)]
pub struct InternalBlockCopyReturn {
    owner: ExternalFileIrpCopyReturn,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockCopyReturn {
    pub fn retry(self) -> InternalBlockCopy {
        InternalBlockCopy {
            owner: self.owner.retry(),
            contract: self.contract,
        }
    }
    pub fn into_completion(self) -> InternalBlockCompletion {
        InternalBlockCompletion {
            owner: self.owner.into_completion(),
            contract: self.contract,
        }
    }
}

#[derive(Debug)]
#[must_use = "acknowledge the exact provider completion"]
pub struct InternalBlockAck {
    owner: ExternalFileIrpAckInvocation,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockAck {
    pub fn irp_id(&self) -> IrpId {
        self.owner.irp_id()
    }
    pub fn route(&self) -> ExternalFileIrpRoute {
        self.owner.route()
    }
    pub fn completion(&self) -> &CompletedIrp {
        self.owner.completion()
    }
    pub fn acknowledged(
        self,
        acknowledgement: ExternalFileIrpAcknowledgement,
    ) -> InternalBlockAckReturn {
        InternalBlockAckReturn {
            owner: self.owner.acknowledged(acknowledgement),
            contract: self.contract,
        }
    }
}

#[derive(Debug)]
pub struct InternalBlockAckReturn {
    owner: ExternalFileIrpCompletionReturn,
    contract: InternalBlockCompletionContract,
}
impl InternalBlockAckReturn {
    pub fn retry(self) -> Result<InternalBlockAck, Self> {
        match self.owner.retry() {
            Ok(owner) => Ok(InternalBlockAck {
                owner,
                contract: self.contract,
            }),
            Err(owner) => Err(Self {
                owner,
                contract: self.contract,
            }),
        }
    }
    pub fn acknowledgement(&self) -> ExternalFileIrpAcknowledgement {
        self.owner.acknowledgement()
    }
}

#[derive(Debug)]
#[must_use = "recover the unchanged block owner"]
pub struct InternalBlockRejection<T> {
    status: NtStatus,
    owner: T,
}
impl<T> InternalBlockRejection<T> {
    pub fn status(&self) -> NtStatus {
        self.status
    }
    pub fn into_owner(self) -> T {
        self.owner
    }
}

impl<P: ObjectManagerPort> IoManager<P> {
    pub fn prepare_internal_block_irp_owned(
        &mut self,
        client: ClientId,
        route: InternalBlockRoute,
        requestor_tid: u64,
        operation: InternalBlockOperation,
    ) -> Result<PreparedInternalBlockIrp, NtStatus> {
        let file = self.file(route.file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        if file.client_id != client
            || file.device_id != route.device_id
            || file.state != FileState::Open
            || file.close_deferred
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        if self.top_of_device_stack(route.device_id)? != route.top_device_id {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if route.logical_block_bytes == 0 || route.max_transfer_bytes < route.logical_block_bytes {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let (major, parameters, buffers, max_transfer) = match operation {
            InternalBlockOperation::Read { offset, length } => {
                validate_raw_transfer(route, offset, length)?;
                let mut output = Vec::new();
                output
                    .try_reserve_exact(length as usize)
                    .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
                output.resize(length as usize, 0);
                (
                    major::IRP_MJ_READ,
                    IoParameters::Read(ReadWriteParameters {
                        length,
                        key: 0,
                        offset,
                    }),
                    ExternalFileIrpBuffers::new(Vec::new(), output),
                    length,
                )
            }
            InternalBlockOperation::Write { offset, bytes } => {
                let length = u32::try_from(bytes.len()).map_err(|_| NtStatus::INVALID_PARAMETER)?;
                validate_raw_transfer(route, offset, length)?;
                (
                    major::IRP_MJ_WRITE,
                    IoParameters::Write(ReadWriteParameters {
                        length,
                        key: 0,
                        offset,
                    }),
                    ExternalFileIrpBuffers::new(bytes, Vec::new()),
                    length,
                )
            }
            InternalBlockOperation::Flush => (
                major::IRP_MJ_FLUSH_BUFFERS,
                IoParameters::FlushBuffers,
                ExternalFileIrpBuffers::new(Vec::new(), Vec::new()),
                0,
            ),
        };
        let owner = self.prepare_external_file_irp_owned(
            ExternalFileIrpRequest {
                client,
                device_id: route.device_id,
                file_id: Some(route.file_id),
                user_data: 0,
                requestor_tid,
                major,
                parameters,
                stack_flags: StackFlags::empty(),
                initial_information: 0,
            },
            buffers,
        )?;
        let contract = InternalBlockCompletionContract {
            client,
            route,
            irp_id: owner.irp_id(),
            major,
            max_transfer,
        };
        Ok(PreparedInternalBlockIrp { owner, contract })
    }

    pub fn discard_prepared_internal_block_irp(
        &mut self,
        prepared: PreparedInternalBlockIrp,
    ) -> Result<ExternalFileIrpBuffers, InternalBlockRejection<PreparedInternalBlockIrp>> {
        let PreparedInternalBlockIrp { owner, contract } = prepared;
        self.discard_prepared_external_file_irp(owner)
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: PreparedInternalBlockIrp {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn begin_prepared_internal_block_irp(
        &mut self,
        prepared: PreparedInternalBlockIrp,
    ) -> Result<InternalBlockInvocation, InternalBlockRejection<PreparedInternalBlockIrp>> {
        let PreparedInternalBlockIrp { owner, contract } = prepared;
        self.begin_prepared_external_file_irp(owner)
            .map(|owner| InternalBlockInvocation { owner, contract })
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: PreparedInternalBlockIrp {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn finish_internal_block_irp(
        &mut self,
        returned: InternalBlockReturn,
    ) -> Result<InternalBlockResult, InternalBlockRejection<InternalBlockReturn>> {
        let InternalBlockReturn { owner, contract } = returned;
        self.finish_external_file_irp(owner)
            .map(|result| match result {
                ExternalFileIrpResult::NotEntered { status, prepared } => {
                    InternalBlockResult::NotEntered {
                        status,
                        prepared: PreparedInternalBlockIrp {
                            owner: prepared,
                            contract,
                        },
                    }
                }
                ExternalFileIrpResult::Returned(owner) => {
                    InternalBlockResult::Returned(InternalBlockTerminal { owner, contract })
                }
                ExternalFileIrpResult::Pending(owner) => {
                    InternalBlockResult::Pending(InternalBlockPending { owner, contract })
                }
                ExternalFileIrpResult::Indeterminate {
                    transport_status,
                    retained,
                } => InternalBlockResult::Indeterminate {
                    transport_status,
                    retained: InternalBlockPending {
                        owner: retained,
                        contract,
                    },
                },
            })
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: InternalBlockReturn {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn retire_internal_block_terminal(
        &mut self,
        terminal: InternalBlockTerminal,
    ) -> Result<
        (ExternalFileIrpTerminalReceipt, ExternalFileIrpBuffers),
        InternalBlockRejection<InternalBlockTerminal>,
    > {
        if let Err(status) = terminal
            .contract
            .validate_completion(terminal.owner.completion())
        {
            return Err(InternalBlockRejection {
                status,
                owner: terminal,
            });
        }
        let InternalBlockTerminal { owner, contract } = terminal;
        self.retire_external_file_irp_terminal(owner)
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: InternalBlockTerminal {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn prepare_internal_block_completion(
        &mut self,
        retained: InternalBlockPending,
    ) -> Result<InternalBlockCompletion, InternalBlockRejection<InternalBlockPending>> {
        if let Some(completion) = self.completed_irp_snapshot(retained.irp_id()) {
            if let Err(status) = retained.contract.validate_completion(&completion) {
                return Err(InternalBlockRejection {
                    status,
                    owner: retained,
                });
            }
        }
        let InternalBlockPending { owner, contract } = retained;
        self.prepare_external_file_irp_completion(owner)
            .map(|owner| InternalBlockCompletion { owner, contract })
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: InternalBlockPending {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn begin_internal_block_copy(
        &mut self,
        completion: InternalBlockCompletion,
        max_bytes: usize,
    ) -> Result<InternalBlockCopy, InternalBlockRejection<InternalBlockCompletion>> {
        let InternalBlockCompletion { owner, contract } = completion;
        self.begin_external_file_irp_copy(owner, max_bytes)
            .map(|owner| InternalBlockCopy { owner, contract })
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: InternalBlockCompletion {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn finish_internal_block_copy(
        &mut self,
        returned: InternalBlockCopyReturn,
    ) -> Result<InternalBlockCompletion, InternalBlockRejection<InternalBlockCopyReturn>> {
        let InternalBlockCopyReturn { owner, contract } = returned;
        self.finish_external_file_irp_copy(owner)
            .map(|owner| InternalBlockCompletion { owner, contract })
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: InternalBlockCopyReturn {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn begin_internal_block_ack(
        &mut self,
        completion: InternalBlockCompletion,
    ) -> Result<InternalBlockAck, InternalBlockRejection<InternalBlockCompletion>> {
        if let Err(status) = completion
            .contract
            .validate_completion(completion.owner.completion())
        {
            return Err(InternalBlockRejection {
                status,
                owner: completion,
            });
        }
        let InternalBlockCompletion { owner, contract } = completion;
        self.begin_external_file_irp_acknowledgement(owner)
            .map(|owner| InternalBlockAck { owner, contract })
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: InternalBlockCompletion {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }

    pub fn finish_internal_block_completion(
        &mut self,
        returned: InternalBlockAckReturn,
    ) -> Result<
        (ExternalFileIrpTerminalReceipt, ExternalFileIrpBuffers),
        InternalBlockRejection<InternalBlockAckReturn>,
    > {
        let InternalBlockAckReturn { owner, contract } = returned;
        self.finish_external_file_irp_completion(owner)
            .map_err(|rejected| InternalBlockRejection {
                status: rejected.status(),
                owner: InternalBlockAckReturn {
                    owner: rejected.into_owner(),
                    contract,
                },
            })
    }
}
