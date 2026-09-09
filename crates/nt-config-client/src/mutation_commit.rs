//! Exact replay of publication and explicit receipt acknowledgement. Neither operation infers
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
        let body = self.exchange_system_hive_mutation_commit(CmHiveMutationCommitRequest {
            operation: operation::ACKNOWLEDGE,
            receipt_bank: receipt.bank,
            receipt_generation: receipt.generation,
            ..CmHiveMutationCommitRequest::default()
        })?;
        if body.receipt_bank != receipt.bank
            || body.receipt_generation != receipt.generation
            || body.mutation_token != 0
            || body.expected_generation != 0
            || body.next_generation != 0
            || body.semantic_journal_len != 0
            || body.has_pending_device_action != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let disposition = match body.disposition {
            disposition::ACKNOWLEDGED => SystemHiveMutationAcknowledgementDisposition::Acknowledged,
            disposition::ALREADY_ACKNOWLEDGED => {
                SystemHiveMutationAcknowledgementDisposition::AlreadyAcknowledged
            }
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        Ok(SystemHiveMutationAcknowledgement {
            receipt,
            disposition,
        })
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
        if response.status != STATUS_SUCCESS {
            return Err(response.status);
        }
        if response.information as usize != output.len() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let body =
            CmHiveMutationCommitReply::from_bytes(&output).ok_or(STATUS_INVALID_PARAMETER)?;
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
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_support;
