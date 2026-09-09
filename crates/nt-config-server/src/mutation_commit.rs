//! One retained terminal outcome for the sole SYSTEM writer. Receipt generations count acknowledged
//! commits and prepared aborts, never upload tokens, failed attempts, or abandoned uploads.

use super::*;
use nt_config_abi::{
    hive_mutation_commit_disposition as disposition, hive_mutation_commit_operation as operation,
    CmHiveMutationCommitReply, CmHiveMutationCommitRequest,
};

#[derive(Default)]
pub(crate) struct MutationOutcomeJournal {
    bank: u64,
    acknowledged: u64,
    pending: Option<CmHiveMutationCommitReply>,
}

impl MutationOutcomeJournal {
    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn reserve(&mut self, identities: &CmIdentitySource) -> Result<(u64, u64), i32> {
        let generation = self
            .acknowledged
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if self.bank == 0 {
            self.bank = identities.take().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        }
        Ok((self.bank, generation))
    }

    fn acknowledge(&mut self, bank: u64, generation: u64) -> Result<u16, i32> {
        if bank == 0 || bank != self.bank || generation == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        if generation <= self.acknowledged {
            return Ok(disposition::ALREADY_ACKNOWLEDGED);
        }
        if !self
            .pending
            .is_some_and(|result| result.receipt_generation == generation)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.pending = None;
        self.acknowledged = generation;
        Ok(disposition::ACKNOWLEDGED)
    }
}

impl CmServer {
    pub(crate) fn op_system_hive_mutation_commit(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> CmReply {
        let Some(request) = CmHiveMutationCommitRequest::from_bytes(input) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if input.len() != core::mem::size_of::<CmHiveMutationCommitRequest>()
            || request.abi_size as usize != input.len()
            || request.abi_version != CM_ABI_VERSION
            || request.mount != hive_mount::SYSTEM
            || request.reserved != 0
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        match request.operation {
            operation::COMMIT | operation::ABORT
                if request.mutation_token != 0
                    && request.expected_generation != 0
                    && request.semantic_journal_len != 0
                    && request.receipt_bank == 0
                    && request.receipt_generation == 0 => {}
            operation::ACKNOWLEDGE
                if request.mutation_token == 0
                    && request.expected_generation == 0
                    && request.semantic_journal_len == 0
                    && request.receipt_bank != 0
                    && request.receipt_generation != 0 => {}
            _ => return reply(STATUS_INVALID_PARAMETER, 0),
        }
        let size = core::mem::size_of::<CmHiveMutationCommitReply>();
        if output.len() < size {
            return reply_with_info(STATUS_BUFFER_TOO_SMALL, size as u32, 0, 0);
        }
        let mut body = CmHiveMutationCommitReply {
            abi_size: size as u16,
            abi_version: CM_ABI_VERSION,
            ..CmHiveMutationCommitReply::default()
        };
        if request.operation == operation::ACKNOWLEDGE {
            body.disposition = match self
                .system_mutation_outcomes
                .acknowledge(request.receipt_bank, request.receipt_generation)
            {
                Ok(disposition) => disposition,
                Err(status) => return reply(status, 0),
            };
            body.receipt_bank = request.receipt_bank;
            body.receipt_generation = request.receipt_generation;
        } else if let Some(retained) = self.system_mutation_outcomes.pending {
            // Match the terminal kind as well as identity before inspecting current authority.
            // Neither a committed mutation nor an aborted preparation can change its outcome.
            let expected_disposition = if request.operation == operation::ABORT {
                disposition::ABORTED
            } else {
                disposition::RETAINED
            };
            if retained.disposition != expected_disposition
                || retained.mutation_token != request.mutation_token
                || retained.expected_generation != request.expected_generation
                || retained.semantic_journal_len != request.semantic_journal_len
            {
                return reply(STATUS_INVALID_PARAMETER, 0);
            }
            body = retained;
        } else {
            let validation = if request.operation == operation::ABORT {
                self.validate_prepared_system_mutation_identity(
                    request.mutation_token,
                    request.expected_generation,
                    request.semantic_journal_len as usize,
                )
            } else {
                self.validate_prepared_system_mutation(
                    request.mutation_token,
                    request.expected_generation,
                    request.semantic_journal_len as usize,
                )
            };
            if let Err(status) = validation {
                return reply(status, 0);
            }
            // This fixed slot needs no allocation after publication or preparation release.
            let (bank, generation) = match self.system_mutation_outcomes.reserve(&self.identities) {
                Ok(identity) => identity,
                Err(status) => return reply(status, 0),
            };
            if request.operation == operation::ABORT {
                self.prepared_system_mutation = None;
                body.disposition = disposition::ABORTED;
            } else {
                let (next_generation, pending_action) = match self.publish_prepared_system_mutation(
                    request.mutation_token,
                    request.expected_generation,
                    request.semantic_journal_len as usize,
                ) {
                    Ok(outcome) => outcome,
                    Err(status) => return reply(status, 0),
                };
                body.disposition = disposition::RETAINED;
                body.next_generation = next_generation;
                body.has_pending_device_action = u32::from(pending_action);
            }
            body.mutation_token = request.mutation_token;
            body.expected_generation = request.expected_generation;
            body.semantic_journal_len = request.semantic_journal_len;
            body.receipt_bank = bank;
            body.receipt_generation = generation;
            self.system_mutation_outcomes.pending = Some(body);
        }
        output[..size].copy_from_slice(body.as_bytes());
        reply_with_info(
            STATUS_SUCCESS,
            size as u32,
            body.receipt_bank,
            body.receipt_generation,
        )
    }

    fn validate_prepared_system_mutation(
        &self,
        token: u64,
        expected: u64,
        len: usize,
    ) -> Result<(), i32> {
        let current = self
            .system_hive
            .as_ref()
            .ok_or(STATUS_DEVICE_NOT_READY)?
            .generation;
        if expected != current {
            return Err(STATUS_REVISION_MISMATCH);
        }
        self.validate_prepared_system_mutation_identity(token, expected, len)
    }

    // Cleanup must remain possible for the exact preparation even if live authority has moved.
    // An absent preparation is not evidence of a successful abort.
    fn validate_prepared_system_mutation_identity(
        &self,
        token: u64,
        expected: u64,
        len: usize,
    ) -> Result<(), i32> {
        let prepared = self
            .prepared_system_mutation
            .as_ref()
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if prepared.token != token
            || prepared.expected_generation != expected
            || prepared.semantic_journal_len != len
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    /// Shared publication mechanics for the retained protocol and the not-yet-migrated native
    /// one-shot caller. Failed application leaves its exact preparation available for recovery.
    pub(crate) fn publish_prepared_system_mutation(
        &mut self,
        token: u64,
        expected: u64,
        len: usize,
    ) -> Result<(u64, bool), i32> {
        self.validate_prepared_system_mutation(token, expected, len)?;
        let prepared = self.prepared_system_mutation.take().unwrap();
        match self.commit_system_hive_mutations(&prepared.mutations, prepared.next_generation) {
            Ok(pending) => Ok((prepared.next_generation, pending)),
            Err(status) => {
                self.prepared_system_mutation = Some(prepared);
                Err(status)
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod abort_tests;
#[cfg(test)]
mod test_support;
