//! SYSTEM mutation upload, validation and prepared-journal transfer.

use super::*;

impl CmServer {
    pub(super) fn op_mutate_system_hive(&mut self, buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let Some(req) = CmHiveMutationRequest::from_bytes(buf) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header_size = core::mem::size_of::<CmHiveMutationRequest>();
        let Ok(journal_len) = usize::try_from(req.journal_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let Ok(chunk_len) = usize::try_from(req.chunk_len_bytes) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        if req.abi_size as usize != header_size
            || req.abi_version != CM_ABI_VERSION
            || req.mount != hive_mount::SYSTEM
            || chunk_len > CM_HIVE_MUTATION_CHUNK_BYTES
            || matches!(
                req.operation,
                hive_mutation_transfer::BEGIN | hive_mutation_transfer::VALIDATE_PREPARED
            ) != (req.expected_mount != 0)
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        if self.system_mutation_begins.blocks_transfer(req.lease_token) {
            return reply(STATUS_DEVICE_BUSY, 0);
        }
        let Some(current_generation) = self.system_hive.as_ref().map(|hive| hive.generation) else {
            return reply(STATUS_DEVICE_NOT_READY, 0);
        };

        match req.operation {
            hive_mutation_transfer::VALIDATE_PREPARED => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || journal_len == 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let mounted = self.system_hive.as_ref().unwrap();
                if req.expected_mount != mounted.identity {
                    return reply(STATUS_INVALID_HANDLE, current_generation);
                }
                if req.expected_generation != current_generation {
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                // Admission observes an existing preparation only. In particular, a complete
                // upload must not become prepared, and a retired token must not acquire authority.
                let Some(prepared) = self.prepared_system_mutation.as_ref() else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if prepared.token != req.lease_token
                    || prepared.expected_generation != req.expected_generation
                    || prepared.semantic_journal_len != journal_len
                    || prepared.durable_journal.len() != req.journal_offset as usize
                    || Some(prepared.next_generation) != current_generation.checked_add(1)
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                reply_with_info(STATUS_SUCCESS, 0, prepared.next_generation, prepared.token)
            }
            hive_mutation_transfer::BEGIN => {
                if req.lease_token != 0
                    || req.expected_generation == 0
                    || req.expected_generation != current_generation
                    || req.journal_offset != 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(
                        if req.expected_generation != 0
                            && req.expected_generation != current_generation
                        {
                            STATUS_REVISION_MISMATCH
                        } else {
                            STATUS_INVALID_PARAMETER
                        },
                        current_generation,
                    );
                }
                match self.acquire_system_mutation_upload(
                    req.expected_mount,
                    current_generation,
                    journal_len,
                ) {
                    Ok(token) => reply_with_info(STATUS_SUCCESS, 0, current_generation, token),
                    Err(status) => reply(status, current_generation),
                }
            }
            hive_mutation_transfer::APPEND => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.chunk_offset as usize != header_size
                    || chunk_len == 0
                    || header_size.checked_add(chunk_len) != Some(buf.len())
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if req.expected_generation != current_generation {
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                let chunk = &buf[header_size..];
                match self.system_mutation_leases.append(
                    req.lease_token,
                    req.expected_generation,
                    journal_len,
                    req.journal_offset as usize,
                    chunk,
                ) {
                    Ok(()) => reply_with_info(
                        STATUS_SUCCESS,
                        chunk_len as u32,
                        current_generation,
                        req.lease_token,
                    ),
                    Err(_) => reply(STATUS_INVALID_PARAMETER, current_generation),
                }
            }
            hive_mutation_transfer::PREPARE => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.journal_offset as usize != journal_len
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if let Some(prepared) = self.prepared_system_mutation.as_ref() {
                    if prepared.token != req.lease_token
                        || prepared.expected_generation != req.expected_generation
                        || prepared.semantic_journal_len != journal_len
                    {
                        return reply(STATUS_INVALID_PARAMETER, current_generation);
                    }
                    // Replay the captured result, not a validation against newer authority.
                    return reply_with_info(
                        STATUS_SUCCESS,
                        prepared.durable_journal.len() as u32,
                        prepared.next_generation,
                        prepared.token,
                    );
                }
                if req.expected_generation != current_generation {
                    return reply(STATUS_REVISION_MISMATCH, current_generation);
                }
                let journal = match self.system_mutation_leases.complete_bytes(
                    req.lease_token,
                    req.expected_generation,
                    journal_len,
                ) {
                    Ok(journal) => journal,
                    Err(MutationLeaseError::Incomplete) => {
                        return reply(STATUS_INVALID_PARAMETER, current_generation);
                    }
                    Err(_) => return reply(STATUS_INVALID_PARAMETER, current_generation),
                };
                let Some(mut mutations) = decode_mutation_journal(journal) else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if let Err(status) = self
                    .system_hive
                    .as_ref()
                    .unwrap()
                    .resolve_mutation_paths(&mut mutations)
                {
                    return reply(status, current_generation);
                }
                let Some(next_generation) = current_generation.checked_add(1) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                let durable_journal = match self.prepare_system_hive_mutations(&mutations) {
                    Ok(journal) => journal,
                    Err(status) => return reply(status, current_generation),
                };
                let Ok(durable_len) = u32::try_from(durable_journal.len()) else {
                    return reply(STATUS_INSUFFICIENT_RESOURCES, current_generation);
                };
                let _ = self
                    .system_mutation_leases
                    .take_complete(req.lease_token, req.expected_generation, journal_len)
                    .expect("validated upload retained through preparation");
                self.prepared_system_mutation = Some(PreparedSystemHiveMutation {
                    token: req.lease_token,
                    expected_generation: current_generation,
                    next_generation,
                    semantic_journal_len: journal_len,
                    mutations,
                    durable_journal,
                });
                reply_with_info(
                    STATUS_SUCCESS,
                    durable_len,
                    next_generation,
                    req.lease_token,
                )
            }
            hive_mutation_transfer::PULL => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.chunk_offset != 0
                    || chunk_len == 0
                    || chunk_len > out_buf.len()
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let Some(prepared) = self.prepared_system_mutation.as_ref() else {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                };
                if prepared.token != req.lease_token
                    || prepared.expected_generation != req.expected_generation
                    || prepared.semantic_journal_len != journal_len
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let offset = req.journal_offset as usize;
                if offset > prepared.durable_journal.len() {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let end = core::cmp::min(
                    offset.saturating_add(chunk_len),
                    prepared.durable_journal.len(),
                );
                let written = end - offset;
                out_buf[..written].copy_from_slice(&prepared.durable_journal[offset..end]);
                reply_with_info(
                    STATUS_SUCCESS,
                    written as u32,
                    prepared.durable_journal.len() as u64,
                    prepared.token,
                )
            }
            hive_mutation_transfer::COMMIT => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.journal_offset as usize != journal_len
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                if self.system_mutation_outcomes.is_pending() {
                    return reply(STATUS_DEVICE_BUSY, current_generation);
                }
                let (next_generation, has_pending_device_action) = match self
                    .publish_prepared_system_mutation(
                        req.lease_token,
                        req.expected_generation,
                        journal_len,
                    ) {
                    Ok(outcome) => outcome,
                    Err(status) => return reply(status, current_generation),
                };
                reply_with_info(
                    STATUS_SUCCESS,
                    u32::from(has_pending_device_action),
                    next_generation,
                    req.lease_token,
                )
            }
            hive_mutation_transfer::ABORT => {
                if req.lease_token == 0
                    || req.expected_generation == 0
                    || req.journal_offset != 0
                    || req.chunk_offset != 0
                    || req.chunk_len_bytes != 0
                    || buf.len() != header_size
                {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                let prepared_matches =
                    self.prepared_system_mutation
                        .as_ref()
                        .is_some_and(|prepared| {
                            prepared.token == req.lease_token
                                && prepared.expected_generation == req.expected_generation
                                && prepared.semantic_journal_len == journal_len
                        });
                let aborted = if prepared_matches {
                    self.prepared_system_mutation = None;
                    true
                } else {
                    self.system_mutation_leases.abort(
                        req.lease_token,
                        req.expected_generation,
                        journal_len,
                    )
                };
                if !aborted {
                    return reply(STATUS_INVALID_PARAMETER, current_generation);
                }
                reply(STATUS_SUCCESS, current_generation)
            }
            _ => reply(STATUS_INVALID_PARAMETER, current_generation),
        }
    }
}

#[cfg(test)]
mod tests;
