//! Exact replay of publication/prepared cleanup and explicit receipt acknowledgement. No operation infers
//! success from a transport failure, a newer mount generation, or a missing server identity.

use crate::{
    Backend, ConfigClient, PreparedSystemHiveMutation, SystemHivePublishOutcome,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use nt_config_abi::{
    hive_mount, hive_mutation_commit_disposition as disposition,
    hive_mutation_commit_operation as operation, opcode, CmHiveMutationCommitReply,
    CmHiveMutationCommitRequest, CM_ABI_VERSION,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "retain the publication result until its exact receipt is acknowledged"]
pub struct SystemHiveMutationCommitReceipt {
    mutation_token: u64,
    expected_generation: u64,
    semantic_journal_len: u32,
    outcome: SystemHivePublishOutcome,
    bank: u64,
    generation: u64,
}

impl SystemHiveMutationCommitReceipt {
    pub const fn outcome(self) -> SystemHivePublishOutcome {
        self.outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemHiveMutationAcknowledgementDisposition {
    Acknowledged,
    AlreadyAcknowledged,
}

/// Proof for exactly one retained result, created only from a validated ACK response.
///
/// ```compile_fail
/// use nt_config_client::SystemHiveMutationAcknowledgement;
/// let proof = SystemHiveMutationAcknowledgement { receipt: todo!(), disposition: todo!() };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct SystemHiveMutationAcknowledgement {
    receipt: SystemHiveMutationCommitReceipt,
    disposition: SystemHiveMutationAcknowledgementDisposition,
}

impl SystemHiveMutationAcknowledgement {
    pub const fn receipt(self) -> SystemHiveMutationCommitReceipt {
        self.receipt
    }
    pub const fn disposition(self) -> SystemHiveMutationAcknowledgementDisposition {
        self.disposition
    }
}

/// Evidence of exact prepared cleanup, never a published hive generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "retain the abort receipt until its exact acknowledgement"]
pub struct SystemHiveMutationAbortReceipt {
    mutation_token: u64,
    expected_generation: u64,
    semantic_journal_len: u32,
    bank: u64,
    generation: u64,
}

/// Typed proof that this abort result was acknowledged; commit receipts cannot substitute for it.
///
/// ```compile_fail
/// use nt_config_client::{Backend, ConfigClient, SystemHiveMutationCommitReceipt};
/// fn wrong<B: Backend>(client: &mut ConfigClient<B>, receipt: SystemHiveMutationCommitReceipt) {
///     client.acknowledge_system_hive_mutation_abort(receipt);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct SystemHiveMutationAbortAcknowledgement {
    receipt: SystemHiveMutationAbortReceipt,
    disposition: SystemHiveMutationAcknowledgementDisposition,
}

impl SystemHiveMutationAbortAcknowledgement {
    pub const fn receipt(self) -> SystemHiveMutationAbortReceipt {
        self.receipt
    }
    pub const fn disposition(self) -> SystemHiveMutationAcknowledgementDisposition {
        self.disposition
    }
}

impl<B: Backend> ConfigClient<B> {
    /// Publish after the prepared journal is durable. On every error retain that journal,
    /// the exact preparation, and the caller's pending publication state, then repeat this request.
    /// A Backend status can represent transport failure, not server rejection: COMMIT may already
    /// have run. This Result deliberately gives no error-based permission to truncate or abort.
    /// After success retain the receipt and complete caller publication before acknowledging it.
    pub fn commit_system_hive_mutation_retained(
        &mut self,
        prepared: &PreparedSystemHiveMutation,
    ) -> Result<SystemHiveMutationCommitReceipt, i32> {
        if prepared.lease_token == 0
            || prepared.expected_generation == 0
            || prepared.semantic_journal_len == 0
            || prepared.expected_generation.checked_add(1) != Some(prepared.next_generation)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let body = self.exchange_system_hive_mutation_commit(CmHiveMutationCommitRequest {
            operation: operation::COMMIT,
            mutation_token: prepared.lease_token,
            expected_generation: prepared.expected_generation,
            semantic_journal_len: prepared.semantic_journal_len,
            ..CmHiveMutationCommitRequest::default()
        })?;
        if body.disposition != disposition::RETAINED
            || body.mutation_token != prepared.lease_token
            || body.expected_generation != prepared.expected_generation
            || body.next_generation != prepared.next_generation
            || body.semantic_journal_len != prepared.semantic_journal_len
            || body.has_pending_device_action > 1
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(SystemHiveMutationCommitReceipt {
            mutation_token: body.mutation_token,
            expected_generation: body.expected_generation,
            semantic_journal_len: body.semantic_journal_len,
            outcome: SystemHivePublishOutcome {
                generation: body.next_generation,
                has_pending_device_action: body.has_pending_device_action != 0,
            },
            bank: body.receipt_bank,
            generation: body.receipt_generation,
        })
    }

    /// Retry this exact ACK after an uncertain response, even after remount or slot reuse.
    /// A failure never authorizes rolling back an already published mutation's durable journal.
    pub fn acknowledge_system_hive_mutation_commit(
        &mut self,
        receipt: SystemHiveMutationCommitReceipt,
    ) -> Result<SystemHiveMutationAcknowledgement, i32> {
        let disposition = self.acknowledge_mutation_receipt(receipt.bank, receipt.generation)?;
        Ok(SystemHiveMutationAcknowledgement {
            receipt,
            disposition,
        })
    }

    /// Call only after durable rollback and before any COMMIT attempt. Every error is uncertain:
    /// retain the preparation/caller and repeat the exact request, never infer cleanup from absence.
    pub fn abort_prepared_system_hive_mutation_retained(
        &mut self,
        prepared: &PreparedSystemHiveMutation,
    ) -> Result<SystemHiveMutationAbortReceipt, i32> {
        if prepared.lease_token == 0
            || prepared.expected_generation == 0
            || prepared.semantic_journal_len == 0
            || prepared.expected_generation.checked_add(1) != Some(prepared.next_generation)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let body = self.exchange_system_hive_mutation_commit(CmHiveMutationCommitRequest {
            operation: operation::ABORT,
            mutation_token: prepared.lease_token,
            expected_generation: prepared.expected_generation,
            semantic_journal_len: prepared.semantic_journal_len,
            ..CmHiveMutationCommitRequest::default()
        })?;
        if body.disposition != disposition::ABORTED
            || body.mutation_token != prepared.lease_token
            || body.expected_generation != prepared.expected_generation
            || body.semantic_journal_len != prepared.semantic_journal_len
            || body.next_generation != 0
            || body.has_pending_device_action != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(SystemHiveMutationAbortReceipt {
            mutation_token: body.mutation_token,
            expected_generation: body.expected_generation,
            semantic_journal_len: body.semantic_journal_len,
            bank: body.receipt_bank,
            generation: body.receipt_generation,
        })
    }

    pub fn acknowledge_system_hive_mutation_abort(
        &mut self,
        receipt: SystemHiveMutationAbortReceipt,
    ) -> Result<SystemHiveMutationAbortAcknowledgement, i32> {
        let disposition = self.acknowledge_mutation_receipt(receipt.bank, receipt.generation)?;
        Ok(SystemHiveMutationAbortAcknowledgement {
            receipt,
            disposition,
        })
    }

    fn acknowledge_mutation_receipt(
        &mut self,
        bank: u64,
        generation: u64,
    ) -> Result<SystemHiveMutationAcknowledgementDisposition, i32> {
        let body = self.exchange_system_hive_mutation_commit(CmHiveMutationCommitRequest {
            operation: operation::ACKNOWLEDGE,
            receipt_bank: bank,
            receipt_generation: generation,
            ..CmHiveMutationCommitRequest::default()
        })?;
        validate_acknowledgement(&body, bank, generation)
    }

    fn exchange_system_hive_mutation_commit(
        &mut self,
        mut request: CmHiveMutationCommitRequest,
    ) -> Result<CmHiveMutationCommitReply, i32> {
        request.abi_size = core::mem::size_of::<CmHiveMutationCommitRequest>() as u16;
        request.abi_version = CM_ABI_VERSION;
        request.mount = hive_mount::SYSTEM;
        let mut output = [0u8; core::mem::size_of::<CmHiveMutationCommitReply>()];
        let response = self.backend.call(
            opcode::CM_OP_SYSTEM_HIVE_MUTATION_COMMIT,
            request.as_bytes(),
            &mut output,
        );
        decode_mutation_reply(response, &output)
    }
}

pub(crate) fn decode_mutation_reply(
    response: nt_config_abi::CmReply,
    output: &[u8],
) -> Result<CmHiveMutationCommitReply, i32> {
    if response.status != STATUS_SUCCESS {
        return Err(response.status);
    }
    if output.len() != core::mem::size_of::<CmHiveMutationCommitReply>()
        || response.information as usize != output.len()
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let body = CmHiveMutationCommitReply::from_bytes(output).ok_or(STATUS_INVALID_PARAMETER)?;
    if body.abi_size as usize != output.len()
        || body.abi_version != CM_ABI_VERSION
        || body.reserved != 0
        || body.receipt_bank == 0
        || body.receipt_generation == 0
        || response.detail0 != body.receipt_bank
        || response.detail1 != body.receipt_generation
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(body)
}

pub(crate) fn validate_acknowledgement(
    body: &CmHiveMutationCommitReply,
    bank: u64,
    generation: u64,
) -> Result<SystemHiveMutationAcknowledgementDisposition, i32> {
    if body.receipt_bank != bank
        || body.receipt_generation != generation
        || body.mutation_token != 0
        || body.expected_generation != 0
        || body.next_generation != 0
        || body.semantic_journal_len != 0
        || body.has_pending_device_action != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    match body.disposition {
        disposition::ACKNOWLEDGED => Ok(SystemHiveMutationAcknowledgementDisposition::Acknowledged),
        disposition::ALREADY_ACKNOWLEDGED => {
            Ok(SystemHiveMutationAcknowledgementDisposition::AlreadyAcknowledged)
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod abort_tests;

#[cfg(test)]
pub(crate) mod test_support;
