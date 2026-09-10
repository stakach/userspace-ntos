//! Replayable writer acquisition. Reserve outcome ownership before allocating the real upload.

use super::*;
use nt_config_abi::mutation_begin::{disposition, operation, Reply, Request, MAX_SLOTS};

pub(super) mod journal;

impl CmServer {
    pub(super) fn op_system_hive_mutation_begin(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> CmReply {
        let Some(request) = Request::from_bytes(input) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if input.len() != core::mem::size_of::<Request>()
            || request.abi_size as usize != input.len()
            || request.abi_version != CM_ABI_VERSION
            || request.mount != hive_mount::SYSTEM
            || request.requester_nonce == 0
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let valid = match request.operation {
            operation::QUERY => {
                request.slot_count != 0
                    && request.slot_count as usize <= MAX_SLOTS
                    && request.server_nonce == 0
                    && request.request_slot == 0
                    && request.request_generation == 0
                    && request.expected_generation == 0
                    && request.expected_mount == 0
                    && request.semantic_journal_len == 0
                    && request.mutation_token == 0
            }
            operation::BEGIN => {
                request.slot_count == 0
                    && request.mutation_token == 0
                    && request.expected_generation != 0
                    && request.expected_mount != 0
                    && request.semantic_journal_len != 0
            }
            operation::ACKNOWLEDGE => {
                request.slot_count == 0
                    && request.expected_generation == 0
                    && request.expected_mount == 0
                    && request.semantic_journal_len == 0
            }
            _ => false,
        };
        if !valid {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let size = core::mem::size_of::<Reply>();
        if output.len() < size {
            return reply_with_info(STATUS_BUFFER_TOO_SMALL, size as u32, 0, 0);
        }
        let mut body = Reply {
            abi_size: size as u16,
            abi_version: CM_ABI_VERSION,
            mount: hive_mount::SYSTEM,
            server_nonce: request.server_nonce,
            requester_nonce: request.requester_nonce,
            request_slot: request.request_slot,
            request_generation: request.request_generation,
            ..Reply::default()
        };
        match request.operation {
            operation::QUERY => {
                body.server_nonce = match self.system_mutation_begins.grant(
                    request.requester_nonce,
                    request.slot_count as usize,
                    &self.identities,
                ) {
                    Ok(authority) => authority,
                    Err(status) => return reply(status, 0),
                };
                body.disposition = disposition::AUTHORITY;
                body.slot_count = request.slot_count;
            }
            operation::BEGIN => {
                let (position, fresh) = match self.system_mutation_begins.claim(&request) {
                    Ok(claim) => claim,
                    Err(status) => return reply(status, 0),
                };
                if fresh {
                    let outcome = self.acquire_system_mutation_upload(
                        request.expected_mount,
                        request.expected_generation,
                        request.semantic_journal_len as usize,
                    );
                    self.system_mutation_begins.finish(position, outcome);
                }
                let (status, token) = match self.system_mutation_begins.outcome(&request) {
                    Ok(outcome) => outcome,
                    Err(status) => return reply(status, 0),
                };
                body.disposition = disposition::OUTCOME;
                body.outcome_status = status;
                body.mutation_token = token;
                body.expected_generation = request.expected_generation;
                body.expected_mount = request.expected_mount;
                body.semantic_journal_len = request.semantic_journal_len;
            }
            operation::ACKNOWLEDGE => {
                body.disposition = match self.system_mutation_begins.acknowledge(&request) {
                    Ok(disposition) => disposition,
                    Err(status) => return reply(status, 0),
                };
            }
            _ => unreachable!(),
        }
        output[..size].copy_from_slice(body.as_bytes());
        reply_with_info(
            STATUS_SUCCESS,
            size as u32,
            body.server_nonce,
            body.request_generation,
        )
    }

    /// Shared acquisition semantics for legacy BEGIN and requester-owned BEGIN. The retained
    /// caller reserves its result slot before this final fallible writer allocation.
    pub(super) fn acquire_system_mutation_upload(
        &mut self,
        expected_mount: u64,
        expected: u64,
        len: usize,
    ) -> Result<u64, i32> {
        let mounted = self.system_hive.as_ref().ok_or(STATUS_DEVICE_NOT_READY)?;
        if expected_mount == 0 || expected == 0 || len == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if expected_mount != mounted.identity {
            return Err(STATUS_INVALID_HANDLE);
        }
        if expected != mounted.generation {
            return Err(STATUS_REVISION_MISMATCH);
        }
        if self.prepared_system_mutation.is_some()
            || self.prepared_system_checkpoint.is_some()
            || self.system_mutation_outcomes.is_pending()
        {
            return Err(STATUS_DEVICE_BUSY);
        }
        self.system_mutation_leases
            .begin(expected, len)
            .map_err(|error| match error {
                MutationLeaseError::Busy => STATUS_DEVICE_BUSY,
                MutationLeaseError::Exhausted => STATUS_INSUFFICIENT_RESOURCES,
                _ => STATUS_INVALID_PARAMETER,
            })
    }
}

#[cfg(test)]
mod tests;
