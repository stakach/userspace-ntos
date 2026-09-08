//! Immutable query outcomes with pre-granted requester slots and explicit retirement.
//!
//! Bank metadata lasts for this CM authority, not one query: requester registration retries reuse
//! the same grant, and ACK watermarks fence delayed messages after slot reuse. No grant is reclaimed
//! without retiring the authority after root quiescence. At most 256 slots retain 1024 request bytes
//! each, independently of the 8 MiB immutable outcome budget. There is no eviction of live readers.

use super::*;
use nt_config_abi::{
    retained_snapshot_disposition as disposition, retained_snapshot_kind as kind,
    retained_snapshot_operation as operation, CmRetainedSnapshotReply, CmRetainedSnapshotRequest,
    CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES, CM_RETAINED_SNAPSHOT_CHUNK_BYTES,
    CM_RETAINED_SNAPSHOT_MAX_BYTES, CM_RETAINED_SNAPSHOT_MAX_SLOTS,
    CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES,
};

struct Outcome {
    status: i32,
    bytes: Vec<u8>,
}

struct Pending {
    generation: u64,
    kind: u16,
    request: Vec<u8>,
    outcome: Option<Outcome>,
}

struct Slot {
    acknowledged: u64,
    pending: Option<Pending>,
}

struct Requester {
    nonce: u64,
    slots: Vec<Slot>,
}

pub(crate) struct RetainedSnapshotJournal {
    nonce: u64,
    requesters: Vec<Requester>,
    granted_slots: usize,
    retained_bytes: usize,
    max_slots: usize,
    max_bytes: usize,
}

impl RetainedSnapshotJournal {
    pub(crate) const fn new() -> Self {
        Self {
            nonce: 0,
            requesters: Vec::new(),
            granted_slots: 0,
            retained_bytes: 0,
            max_slots: CM_RETAINED_SNAPSHOT_MAX_SLOTS,
            max_bytes: CM_RETAINED_SNAPSHOT_MAX_BYTES,
        }
    }

    fn grant(
        &mut self,
        requester: u64,
        count: usize,
        source: &CmIdentitySource,
    ) -> Result<u64, i32> {
        if requester == 0 || count == 0 || count > self.max_slots {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(existing) = self.requesters.iter().find(|bank| bank.nonce == requester) {
            return if existing.slots.len() == count {
                Ok(self.nonce)
            } else {
                Err(STATUS_INVALID_PARAMETER)
            };
        }
        let total = self
            .granted_slots
            .checked_add(count)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if total > self.max_slots {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        slots.resize_with(count, || Slot {
            acknowledged: 0,
            pending: None,
        });
        self.requesters
            .try_reserve_exact(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let nonce = if self.nonce == 0 {
            source.take().ok_or(STATUS_INSUFFICIENT_RESOURCES)?
        } else {
            self.nonce
        };
        self.requesters.push(Requester {
            nonce: requester,
            slots,
        });
        self.granted_slots = total;
        self.nonce = nonce;
        Ok(nonce)
    }

    fn locate(&self, request: &CmRetainedSnapshotRequest) -> Result<(usize, usize), i32> {
        if self.nonce == 0 || request.server_nonce != self.nonce || request.request_generation == 0
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let bank = self
            .requesters
            .iter()
            .position(|bank| bank.nonce == request.requester_nonce)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = usize::try_from(request.request_slot).map_err(|_| STATUS_INVALID_HANDLE)?;
        if slot >= self.requesters[bank].slots.len() {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok((bank, slot))
    }

    fn claim(
        &mut self,
        request: &CmRetainedSnapshotRequest,
        payload: &[u8],
    ) -> Result<((usize, usize), bool), i32> {
        if payload.len() > CM_MAX_HIVE_PATH_UNITS * 2 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let position = self.locate(request)?;
        let slot = &mut self.requesters[position.0].slots[position.1];
        if let Some(pending) = &slot.pending {
            if pending.generation != request.request_generation {
                return Err(STATUS_INVALID_HANDLE);
            }
            if pending.kind != request.query_kind || pending.request != payload {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if pending.outcome.is_none() {
                return Err(STATUS_DEVICE_NOT_READY);
            }
            return Ok((position, false));
        }
        if slot.acknowledged.checked_add(1) != Some(request.request_generation) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let mut captured = Vec::new();
        captured
            .try_reserve_exact(payload.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        captured.extend_from_slice(payload);
        slot.pending = Some(Pending {
            generation: request.request_generation,
            kind: request.query_kind,
            request: captured,
            outcome: None,
        });
        Ok((position, true))
    }

    fn finish(&mut self, position: (usize, usize), result: Result<Vec<u8>, i32>) {
        let outcome = match result {
            Ok(bytes)
                if bytes.len() <= u32::MAX as usize
                    && self
                        .retained_bytes
                        .checked_add(bytes.capacity())
                        .is_some_and(|total| total <= self.max_bytes) =>
            {
                self.retained_bytes += bytes.capacity();
                Outcome {
                    status: STATUS_SUCCESS,
                    bytes,
                }
            }
            Ok(_) => Outcome {
                status: STATUS_INSUFFICIENT_RESOURCES,
                bytes: Vec::new(),
            },
            Err(status) => Outcome {
                status,
                bytes: Vec::new(),
            },
        };
        let pending = self.requesters[position.0].slots[position.1]
            .pending
            .as_mut()
            .expect("reserved snapshot attempt missing");
        assert!(
            pending.outcome.is_none(),
            "snapshot outcome cannot be replaced"
        );
        pending.outcome = Some(outcome);
    }

    fn outcome(&self, request: &CmRetainedSnapshotRequest) -> Result<&Outcome, i32> {
        let (bank, slot) = self.locate(request)?;
        let pending = self.requesters[bank].slots[slot]
            .pending
            .as_ref()
            .ok_or(STATUS_INVALID_HANDLE)?;
        if pending.generation != request.request_generation || pending.kind != request.query_kind {
            return Err(STATUS_INVALID_HANDLE);
        }
        pending.outcome.as_ref().ok_or(STATUS_DEVICE_NOT_READY)
    }

    fn acknowledge(&mut self, request: &CmRetainedSnapshotRequest) -> Result<u16, i32> {
        let (bank, slot) = self.locate(request)?;
        let slot = &mut self.requesters[bank].slots[slot];
        if request.request_generation <= slot.acknowledged {
            return Ok(disposition::ALREADY_ACKNOWLEDGED);
        }
        if slot.acknowledged.checked_add(1) != Some(request.request_generation) {
            return Err(STATUS_INVALID_HANDLE);
        }
        if let Some(pending) = &slot.pending {
            if pending.generation != request.request_generation
                || pending.kind != request.query_kind
            {
                return Err(STATUS_INVALID_HANDLE);
            }
            let outcome = pending.outcome.as_ref().ok_or(STATUS_DEVICE_NOT_READY)?;
            self.retained_bytes -= outcome.bytes.capacity();
        }
        // Even an unexecuted BEGIN is fenced. QUERY preallocated this watermark, so cleanup
        // never needs to allocate and cannot be blocked by another request filling the bank.
        slot.pending = None;
        slot.acknowledged = request.request_generation;
        Ok(disposition::ACKNOWLEDGED)
    }
}

impl CmServer {
    pub(super) fn op_retained_snapshot(&mut self, input: &[u8], output: &mut [u8]) -> CmReply {
        let Some(request) = CmRetainedSnapshotRequest::from_bytes(input) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header = core::mem::size_of::<CmRetainedSnapshotRequest>();
        if request.abi_size as usize != header || request.abi_version != CM_ABI_VERSION {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let payload = match request.operation {
            operation::QUERY => {
                if input.len() != header
                    || request.query_kind != 0
                    || request.server_nonce != 0
                    || request.request_slot != 0
                    || request.request_generation != 0
                    || request.value_offset != 0
                    || request.request_offset != 0
                    || request.request_len_bytes != 0
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                &[][..]
            }
            operation::BEGIN => {
                if request.query_kind != kind::ACTIVE_DRIVER_SERVICE
                    || request.value_offset != 0
                    || request.chunk_capacity != 0
                    || request.request_offset as usize != header
                    || request.request_len_bytes == 0
                    || request.request_len_bytes % 2 != 0
                    || request.request_len_bytes as usize > CM_MAX_HIVE_PATH_UNITS * 2
                    || header.checked_add(request.request_len_bytes as usize) != Some(input.len())
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                &input[header..]
            }
            operation::PULL | operation::ACKNOWLEDGE => {
                if input.len() != header
                    || request.query_kind != kind::ACTIVE_DRIVER_SERVICE
                    || request.request_offset != 0
                    || request.request_len_bytes != 0
                    || (request.operation == operation::ACKNOWLEDGE
                        && (request.value_offset != 0 || request.chunk_capacity != 0))
                    || (request.operation == operation::PULL
                        && (request.chunk_capacity == 0
                            || request.chunk_capacity as usize > CM_RETAINED_SNAPSHOT_CHUNK_BYTES))
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                &[][..]
            }
            _ => return reply(STATUS_INVALID_PARAMETER, 0),
        };
        let needed = CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES
            + if request.operation == operation::PULL {
                request.chunk_capacity as usize
            } else {
                0
            };
        if output.len() < needed {
            return reply_with_info(STATUS_BUFFER_TOO_SMALL, needed as u32, 0, 0);
        }
        let mut body = CmRetainedSnapshotReply {
            abi_size: CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES as u16,
            abi_version: CM_ABI_VERSION,
            query_kind: request.query_kind,
            server_nonce: request.server_nonce,
            requester_nonce: request.requester_nonce,
            request_slot: request.request_slot,
            request_generation: request.request_generation,
            ..CmRetainedSnapshotReply::default()
        };
        match request.operation {
            operation::QUERY => {
                body.server_nonce = match self.retained_snapshots.grant(
                    request.requester_nonce,
                    request.chunk_capacity as usize,
                    &self.identities,
                ) {
                    Ok(nonce) => nonce,
                    Err(status) => return reply(status, 0),
                };
                body.disposition = disposition::AUTHORITY;
                body.total_bytes = request.chunk_capacity;
            }
            operation::BEGIN => {
                let units = payload
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
                if core::char::decode_utf16(units).any(|value| value.is_err() || value == Ok('\0'))
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let (position, fresh) = match self.retained_snapshots.claim(&request, payload) {
                    Ok(claim) => claim,
                    Err(status) => return reply(status, 0),
                };
                if fresh {
                    let result = (|| {
                        let remaining = self
                            .retained_snapshots
                            .max_bytes
                            .checked_sub(self.retained_snapshots.retained_bytes)
                            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
                        if remaining < CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES {
                            return Err(STATUS_INSUFFICIENT_RESOURCES);
                        }
                        let mut path = String::new();
                        path.try_reserve_exact(payload.len() / 2 * 3)
                            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                        let units = payload
                            .chunks_exact(2)
                            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
                        for value in core::char::decode_utf16(units) {
                            path.push(value.map_err(|_| STATUS_INVALID_PARAMETER)?);
                        }
                        let mounted = self.system_hive.as_ref().ok_or(STATUS_DEVICE_NOT_READY)?;
                        active_driver_service::capture(mounted, &path, remaining)
                    })();
                    self.retained_snapshots.finish(position, result);
                }
                let outcome = match self.retained_snapshots.outcome(&request) {
                    Ok(outcome) => outcome,
                    Err(status) => return reply(status, 0),
                };
                body.disposition = disposition::OUTCOME;
                body.outcome_status = outcome.status;
                body.total_bytes = outcome.bytes.len() as u32;
            }
            operation::PULL => {
                let outcome = match self.retained_snapshots.outcome(&request) {
                    Ok(outcome) => outcome,
                    Err(status) => return reply(status, 0),
                };
                let offset = request.value_offset as usize;
                if outcome.status != STATUS_SUCCESS || offset > outcome.bytes.len() {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let length = core::cmp::min(
                    request.chunk_capacity as usize,
                    outcome.bytes.len() - offset,
                );
                output[CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES
                    ..CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES + length]
                    .copy_from_slice(&outcome.bytes[offset..offset + length]);
                body.disposition = disposition::CHUNK;
                body.total_bytes = outcome.bytes.len() as u32;
                body.value_offset = request.value_offset;
                body.chunk_bytes = length as u32;
            }
            operation::ACKNOWLEDGE => {
                body.disposition = match self.retained_snapshots.acknowledge(&request) {
                    Ok(disposition) => disposition,
                    Err(status) => return reply(status, 0),
                };
            }
            _ => unreachable!(),
        }
        output[..CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES].copy_from_slice(body.as_bytes());
        reply_with_info(
            STATUS_SUCCESS,
            CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES as u32 + body.chunk_bytes,
            body.server_nonce,
            body.request_generation,
        )
    }
}

#[cfg(test)]
mod tests;
