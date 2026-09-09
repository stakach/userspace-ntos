//! Exact upload/preparation progress and acknowledged cancellation before any durable publication.

use super::{Identity, SystemHiveMutationUpload};
use crate::mutation_commit::{decode_mutation_reply, validate_acknowledgement};
use crate::{
    Backend, ConfigClient, PreparedSystemHiveMutation, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use alloc::vec::Vec;
use nt_config_abi::{
    hive_mount, hive_mutation_commit_disposition as disposition,
    hive_mutation_commit_operation as terminal, hive_mutation_transfer as transfer, opcode,
    CmHiveMutationCommitReply, CmHiveMutationCommitRequest, CmHiveMutationRequest, CmReply,
    CM_ABI_VERSION, CM_HIVE_MUTATION_CHUNK_BYTES,
};

const REQUEST_BYTES: usize =
    core::mem::size_of::<CmHiveMutationRequest>() + CM_HIVE_MUTATION_CHUNK_BYTES;
const TERMINAL_REPLY_BYTES: usize = core::mem::size_of::<CmHiveMutationCommitReply>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmMutationPreparationOperation {
    Append,
    Prepare,
    Pull,
    Cancel,
    AcknowledgeCancellation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmMutationPreparationPhase {
    Appending,
    Preparing,
    Allocating,
    Pulling,
    Prepared,
    Cancelling,
    AcknowledgingCancellation,
    Cancelled,
    Taken,
}

struct CancellationReceipt {
    bank: u64,
    generation: u64,
}

/// Retains caller state, exact bytes, original CM authority and every unresolved exchange.
/// Dropping an owner or an in-flight ticket does not cancel the server writer. Only acknowledged
/// cancellation or transfer of the complete preparation permits releasing this continuation.
/// No storage or COMMIT can be issued through this pre-publication owner.
///
/// ```compile_fail
/// use nt_config_client::SystemHiveMutationPreparation;
/// fn duplicate<C>(owner: SystemHiveMutationPreparation<C>) { let _ = owner.clone(); }
/// ```
#[must_use]
pub struct SystemHiveMutationPreparation<C> {
    upload: Option<SystemHiveMutationUpload<C>>,
    phase: CmMutationPreparationPhase,
    epoch: u64,
    inflight: Option<CmMutationPreparationOperation>,
    uploaded: usize,
    durable_len: Option<u32>,
    durable: Vec<u8>,
    cancel_receipt: Option<CancellationReceipt>,
}

/// A detached, allocation-free exchange; no owner borrow crosses component IPC.
///
/// ```compile_fail
/// use nt_config_client::CmMutationPreparationExchange;
/// fn duplicate(ticket: CmMutationPreparationExchange) { let _ = ticket.clone(); }
/// ```
#[must_use]
pub struct CmMutationPreparationExchange {
    identity: Identity,
    server: u64,
    epoch: u64,
    operation: CmMutationPreparationOperation,
    live: bool,
    bytes: [u8; REQUEST_BYTES],
    len: usize,
    reply_len: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ResponseBinding {
    identity: Identity,
    server: u64,
    epoch: u64,
    operation: CmMutationPreparationOperation,
}

impl CmMutationPreparationExchange {
    fn binding(&self) -> ResponseBinding {
        ResponseBinding {
            identity: self.identity,
            server: self.server,
            epoch: self.epoch,
            operation: self.operation,
        }
    }
}

pub struct CmMutationPreparationResponse {
    binding: Option<ResponseBinding>,
    reply: CmReply,
    bytes: [u8; CM_HIVE_MUTATION_CHUNK_BYTES],
}

impl CmMutationPreparationResponse {
    pub fn transport_error(status: i32) -> Self {
        Self {
            binding: None,
            reply: CmReply {
                status: if status == STATUS_SUCCESS {
                    STATUS_INVALID_PARAMETER
                } else {
                    status
                },
                ..CmReply::default()
            },
            bytes: [0; CM_HIVE_MUTATION_CHUNK_BYTES],
        }
    }
}

impl<C> SystemHiveMutationUpload<C> {
    /// Ownership transfer cannot fail or discard a caller, even if the captured generation is
    /// exhausted. Such an upload still needs exact acknowledged cancellation.
    pub fn into_preparation(self) -> SystemHiveMutationPreparation<C> {
        SystemHiveMutationPreparation {
            upload: Some(self),
            phase: CmMutationPreparationPhase::Appending,
            epoch: 0,
            inflight: None,
            uploaded: 0,
            durable_len: None,
            durable: Vec::new(),
            cancel_receipt: None,
        }
    }
}

impl<B: Backend> ConfigClient<B> {
    pub fn exchange_system_hive_mutation_preparation(
        &mut self,
        exchange: &CmMutationPreparationExchange,
    ) -> CmMutationPreparationResponse {
        if !exchange.live {
            return CmMutationPreparationResponse::transport_error(STATUS_INVALID_PARAMETER);
        }
        let opcode = if matches!(
            exchange.operation,
            CmMutationPreparationOperation::Cancel
                | CmMutationPreparationOperation::AcknowledgeCancellation
        ) {
            opcode::CM_OP_SYSTEM_HIVE_MUTATION_COMMIT
        } else {
            opcode::CM_OP_MUTATE_SYSTEM_HIVE
        };
        let mut bytes = [0; CM_HIVE_MUTATION_CHUNK_BYTES];
        let reply = self.backend.call(
            opcode,
            &exchange.bytes[..exchange.len],
            &mut bytes[..exchange.reply_len],
        );
        CmMutationPreparationResponse {
            binding: Some(exchange.binding()),
            reply,
            bytes,
        }
    }
}

impl<C> SystemHiveMutationPreparation<C> {
    pub fn phase(&self) -> CmMutationPreparationPhase {
        self.phase
    }
    pub fn is_inflight(&self) -> bool {
        self.inflight.is_some()
    }
    pub fn uploaded_len(&self) -> usize {
        self.uploaded
    }
    pub fn collected_len(&self) -> usize {
        self.durable.len()
    }
    pub fn continuation(&self) -> Option<&C> {
        self.upload.as_ref().map(|upload| &upload.continuation)
    }

    /// Keep the validated PREPARE result even if local allocation fails. This operation never
    /// repeats PREPARE or changes the accepted byte count; cancellation remains available.
    pub fn allocate_journal(&mut self) -> Result<(), i32> {
        self.allocate_journal_with_reserve(|bytes, length| {
            bytes
                .try_reserve_exact(length)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
        })
    }

    fn allocate_journal_with_reserve(
        &mut self,
        reserve: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), i32>,
    ) -> Result<(), i32> {
        if self.phase != CmMutationPreparationPhase::Allocating || self.is_inflight() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let length = self.durable_len.ok_or(STATUS_INVALID_PARAMETER)? as usize;
        reserve(&mut self.durable, length)?;
        if self.durable.capacity() < length || !self.durable.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.phase = if length == 0 {
            CmMutationPreparationPhase::Prepared
        } else {
            CmMutationPreparationPhase::Pulling
        };
        Ok(())
    }

    pub fn begin_exchange(
        &mut self,
        operation: CmMutationPreparationOperation,
    ) -> Result<CmMutationPreparationExchange, i32> {
        use CmMutationPreparationOperation::*;
        use CmMutationPreparationPhase as Phase;
        if self.is_inflight() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let upload = self.upload.as_ref().ok_or(STATUS_INVALID_PARAMETER)?;
        let valid = match operation {
            Append => self.phase == Phase::Appending,
            Prepare => self.phase == Phase::Preparing,
            Pull => self.phase == Phase::Pulling,
            Cancel => matches!(
                self.phase,
                Phase::Appending
                    | Phase::Preparing
                    | Phase::Allocating
                    | Phase::Pulling
                    | Phase::Prepared
                    | Phase::Cancelling
            ),
            AcknowledgeCancellation => self.phase == Phase::AcknowledgingCancellation,
        };
        if !valid {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let mut bytes = [0; REQUEST_BYTES];
        let (len, reply_len) = if matches!(operation, Cancel | AcknowledgeCancellation) {
            let mut request = CmHiveMutationCommitRequest {
                abi_size: core::mem::size_of::<CmHiveMutationCommitRequest>() as u16,
                abi_version: CM_ABI_VERSION,
                mount: hive_mount::SYSTEM,
                ..CmHiveMutationCommitRequest::default()
            };
            if operation == Cancel {
                request.operation = terminal::ABORT_UNPUBLISHED;
                request.mutation_token = upload.mutation_token;
                request.expected_generation = upload.expected_generation;
                request.semantic_journal_len = upload.journal.len() as u32;
            } else {
                let receipt = self
                    .cancel_receipt
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER)?;
                request.operation = terminal::ACKNOWLEDGE;
                request.receipt_bank = receipt.bank;
                request.receipt_generation = receipt.generation;
            }
            let size = request.as_bytes().len();
            bytes[..size].copy_from_slice(request.as_bytes());
            (size, TERMINAL_REPLY_BYTES)
        } else {
            let header = core::mem::size_of::<CmHiveMutationRequest>();
            let mut request = CmHiveMutationRequest {
                abi_size: header as u16,
                abi_version: CM_ABI_VERSION,
                mount: hive_mount::SYSTEM,
                lease_token: upload.mutation_token,
                expected_generation: upload.expected_generation,
                journal_len_bytes: upload.journal.len() as u32,
                ..CmHiveMutationRequest::default()
            };
            let (payload, capacity) = match operation {
                Append => {
                    let remaining = upload
                        .journal
                        .len()
                        .checked_sub(self.uploaded)
                        .ok_or(STATUS_INVALID_PARAMETER)?;
                    let length = remaining.min(CM_HIVE_MUTATION_CHUNK_BYTES);
                    if length == 0 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    request.operation = transfer::APPEND;
                    request.journal_offset = self.uploaded as u32;
                    request.chunk_offset = header as u32;
                    request.chunk_len_bytes = length as u32;
                    bytes[header..header + length]
                        .copy_from_slice(&upload.journal[self.uploaded..self.uploaded + length]);
                    (length, 0)
                }
                Prepare => {
                    request.operation = transfer::PREPARE;
                    request.journal_offset = upload.journal.len() as u32;
                    (0, 0)
                }
                Pull => {
                    let total = self.durable_len.ok_or(STATUS_INVALID_PARAMETER)? as usize;
                    let capacity = total
                        .checked_sub(self.durable.len())
                        .ok_or(STATUS_INVALID_PARAMETER)?
                        .min(CM_HIVE_MUTATION_CHUNK_BYTES);
                    if capacity == 0 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    request.operation = transfer::PULL;
                    request.journal_offset = self.durable.len() as u32;
                    request.chunk_len_bytes = capacity as u32;
                    (0, capacity)
                }
                _ => unreachable!(),
            };
            bytes[..header].copy_from_slice(request.as_bytes());
            (header + payload, capacity)
        };
        if operation == Cancel {
            self.phase = Phase::Cancelling;
        }
        self.epoch = epoch;
        self.inflight = Some(operation);
        Ok(CmMutationPreparationExchange {
            identity: upload.identity,
            server: upload.server,
            epoch,
            operation,
            live: true,
            bytes,
            len,
            reply_len,
        })
    }

    pub fn complete_exchange(
        &mut self,
        exchange: &mut CmMutationPreparationExchange,
        response: CmMutationPreparationResponse,
    ) -> Result<(), i32> {
        use CmMutationPreparationOperation::*;
        use CmMutationPreparationPhase as Phase;
        let upload = self.upload.as_ref().ok_or(STATUS_INVALID_PARAMETER)?;
        if !exchange.live
            || exchange.identity != upload.identity
            || exchange.server != upload.server
            || exchange.epoch != self.epoch
            || self.inflight != Some(exchange.operation)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if response
            .binding
            .is_some_and(|binding| binding != exchange.binding())
            || (response.binding.is_none() && response.reply.status == STATUS_SUCCESS)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        exchange.live = false;
        self.inflight = None;
        if response.reply.status != STATUS_SUCCESS {
            return Err(response.reply.status);
        }
        match exchange.operation {
            Append => {
                let request = CmHiveMutationRequest::from_bytes(&exchange.bytes).unwrap();
                if response.reply.detail0 != upload.expected_generation
                    || response.reply.detail1 != upload.mutation_token
                    || response.reply.information != request.chunk_len_bytes
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.uploaded += request.chunk_len_bytes as usize;
                if self.uploaded == upload.journal.len() {
                    self.phase = Phase::Preparing;
                }
            }
            Prepare => {
                if upload.expected_generation.checked_add(1) != Some(response.reply.detail0)
                    || response.reply.detail1 != upload.mutation_token
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.durable_len = Some(response.reply.information);
                self.phase = if response.reply.information == 0 {
                    Phase::Prepared
                } else {
                    Phase::Allocating
                };
            }
            Pull => {
                if response.reply.detail0
                    != u64::from(self.durable_len.ok_or(STATUS_INVALID_PARAMETER)?)
                    || response.reply.detail1 != upload.mutation_token
                    || response.reply.information as usize != exchange.reply_len
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.durable
                    .extend_from_slice(&response.bytes[..exchange.reply_len]);
                if Some(self.durable.len() as u32) == self.durable_len {
                    self.phase = Phase::Prepared;
                }
            }
            Cancel => {
                let body =
                    decode_mutation_reply(response.reply, &response.bytes[..TERMINAL_REPLY_BYTES])?;
                if body.disposition != disposition::UNPUBLISHED_ABORTED
                    || body.mutation_token != upload.mutation_token
                    || body.expected_generation != upload.expected_generation
                    || body.semantic_journal_len as usize != upload.journal.len()
                    || body.next_generation != 0
                    || body.has_pending_device_action != 0
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.cancel_receipt = Some(CancellationReceipt {
                    bank: body.receipt_bank,
                    generation: body.receipt_generation,
                });
                self.phase = Phase::AcknowledgingCancellation;
            }
            AcknowledgeCancellation => {
                let body =
                    decode_mutation_reply(response.reply, &response.bytes[..TERMINAL_REPLY_BYTES])?;
                let receipt = self
                    .cancel_receipt
                    .as_ref()
                    .ok_or(STATUS_INVALID_PARAMETER)?;
                let _ = validate_acknowledgement(&body, receipt.bank, receipt.generation)?;
                self.phase = Phase::Cancelled;
            }
        }
        Ok(())
    }

    pub fn take_prepared(&mut self) -> Result<(PreparedSystemHiveMutation, C), i32> {
        if self.phase != CmMutationPreparationPhase::Prepared || self.is_inflight() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let upload = self.upload.take().expect("retained preparation owner");
        self.phase = CmMutationPreparationPhase::Taken;
        Ok((
            PreparedSystemHiveMutation {
                expected_generation: upload.expected_generation,
                next_generation: upload
                    .expected_generation
                    .checked_add(1)
                    .expect("validated PREPARE generation"),
                lease_token: upload.mutation_token,
                semantic_journal_len: upload.journal.len() as u32,
                durable_journal: core::mem::take(&mut self.durable),
            },
            upload.continuation,
        ))
    }

    pub fn take_cancelled(&mut self) -> Result<C, i32> {
        if self.phase != CmMutationPreparationPhase::Cancelled || self.is_inflight() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.phase = CmMutationPreparationPhase::Taken;
        Ok(self
            .upload
            .take()
            .expect("retained cancelled caller")
            .continuation)
    }
}

#[cfg(test)]
mod tests;
