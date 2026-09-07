//! Retained OPEN outcomes, keyed by a requester-owned reusable slot and exact attempt generation.

use super::*;
use nt_config_abi::{
    hive_key_open_disposition as disposition, hive_key_open_operation as operation,
    CmHiveKeyOpenReply, CmHiveKeyOpenRequest, CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES,
    CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES,
};

struct OpenOutcome {
    status: i32,
    lease: u64,
    opened_generation: u64,
    physical_path: String,
}

impl OpenOutcome {
    fn failed(status: i32) -> Self {
        Self {
            status,
            lease: 0,
            opened_generation: 0,
            physical_path: String::new(),
        }
    }
}

struct PendingOpen {
    generation: u64,
    path: Vec<u16>,
    outcome: Option<OpenOutcome>,
}

struct RequestSlot {
    requester: u64,
    slot: u64,
    acknowledged: u64,
    pending: Option<PendingOpen>,
}

pub(crate) struct OpenJournal {
    nonce: u64,
    slots: Vec<RequestSlot>,
}

impl OpenJournal {
    pub(crate) const fn new() -> Self {
        Self {
            nonce: 0,
            slots: Vec::new(),
        }
    }

    fn authority(&mut self, source: &CmIdentitySource) -> Result<u64, i32> {
        if self.nonce == 0 {
            self.nonce = source.take().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        }
        Ok(self.nonce)
    }

    fn validate(&self, request: &CmHiveKeyOpenRequest) -> Result<(), i32> {
        if self.nonce == 0
            || request.server_nonce != self.nonce
            || request.requester_nonce == 0
            || request.request_generation == 0
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    /// Reserve every journal allocation before the caller can acquire a real key lease. A claimed
    /// attempt is never replaced until its outcome has been acknowledged.
    fn claim(
        &mut self,
        request: &CmHiveKeyOpenRequest,
        path: &[u16],
        slot_limit: usize,
    ) -> Result<(usize, bool), i32> {
        self.validate(request)?;
        let existing = self.slots.iter().position(|slot| {
            slot.requester == request.requester_nonce && slot.slot == request.request_slot
        });
        let acknowledged = if let Some(index) = existing {
            let slot = &self.slots[index];
            if let Some(pending) = &slot.pending {
                if pending.generation != request.request_generation {
                    return Err(STATUS_INVALID_HANDLE);
                }
                if pending.path != path {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if pending.outcome.is_none() {
                    return Err(STATUS_DEVICE_NOT_READY);
                }
                return Ok((index, false));
            }
            slot.acknowledged
        } else {
            0
        };
        if acknowledged.checked_add(1) != Some(request.request_generation) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let mut captured = Vec::new();
        captured
            .try_reserve_exact(path.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        captured.extend_from_slice(path);
        if existing.is_none() {
            if self.slots.len() >= slot_limit {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            self.slots
                .try_reserve_exact(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let index = existing.unwrap_or(self.slots.len());
        if existing.is_none() {
            self.slots.push(RequestSlot {
                requester: request.requester_nonce,
                slot: request.request_slot,
                acknowledged: 0,
                pending: None,
            });
        }
        self.slots[index].pending = Some(PendingOpen {
            generation: request.request_generation,
            path: captured,
            outcome: None,
        });
        Ok((index, true))
    }

    fn finish(&mut self, index: usize, outcome: OpenOutcome) {
        let pending = self.slots[index]
            .pending
            .as_mut()
            .expect("reserved OPEN attempt missing");
        assert!(pending.outcome.is_none(), "OPEN outcome cannot be replaced");
        pending.outcome = Some(outcome);
    }

    fn acknowledge(&mut self, request: &CmHiveKeyOpenRequest) -> Result<u16, i32> {
        self.validate(request)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| {
                slot.requester == request.requester_nonce && slot.slot == request.request_slot
            })
            .ok_or(STATUS_INVALID_HANDLE)?;
        if request.request_generation <= slot.acknowledged {
            return Ok(disposition::ALREADY_ACKNOWLEDGED);
        }
        if !slot.pending.as_ref().is_some_and(|pending| {
            pending.generation == request.request_generation && pending.outcome.is_some()
        }) {
            return Err(STATUS_INVALID_HANDLE);
        }
        slot.pending = None;
        slot.acknowledged = request.request_generation;
        Ok(disposition::ACKNOWLEDGED)
    }
}

fn decoded_path(units: &[u16]) -> Result<String, i32> {
    let mut path = String::new();
    path.try_reserve_exact(units.len() * 3)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for value in core::char::decode_utf16(units.iter().copied()) {
        let value = value.map_err(|_| STATUS_INVALID_PARAMETER)?;
        if value == '\0' {
            return Err(STATUS_INVALID_PARAMETER);
        }
        path.push(value);
    }
    Ok(path)
}

fn acquire(
    mounted: Option<&MountedSystemHive>,
    leases: &mut SystemKeyLeaseBank,
    path: &str,
) -> Result<OpenOutcome, i32> {
    let mounted = mounted.ok_or(STATUS_DEVICE_NOT_READY)?;
    let mut relative = String::new();
    relative
        .try_reserve_exact(path.len() + mounted.current_control_set.as_str().len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    if !system_hive_relative_path_into(path, &mounted.current_control_set, &mut relative) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let key = mounted
        .hive
        .open_key(&relative)
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let mut physical_path = String::new();
    physical_path
        .try_reserve_exact(SYSTEM_HIVE_PATH.len() + 1 + relative.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    physical_path.push_str(SYSTEM_HIVE_PATH);
    if !relative.is_empty() {
        physical_path.push('\\');
        physical_path.push_str(&relative);
    }
    if physical_path.len() > CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES - CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut leased_path = String::new();
    leased_path
        .try_reserve_exact(physical_path.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    leased_path.push_str(&physical_path);
    // Lease storage and its globally unique token are the final fallible acquisition. The journal
    // row, both physical-path owners, and full reply bank are already reserved.
    let lease = leases.open(key, leased_path).map_err(|error| match error {
        SystemKeyLeaseError::Exhausted => STATUS_INSUFFICIENT_RESOURCES,
        SystemKeyLeaseError::Invalid => STATUS_INVALID_PARAMETER,
    })?;
    Ok(OpenOutcome {
        status: STATUS_SUCCESS,
        lease,
        opened_generation: mounted.generation,
        physical_path,
    })
}

impl CmServer {
    pub(crate) fn op_system_hive_key_open(&mut self, input: &[u8], output: &mut [u8]) -> CmReply {
        let Some(request) = CmHiveKeyOpenRequest::from_bytes(input) else {
            return reply(STATUS_INVALID_PARAMETER, 0);
        };
        let header = core::mem::size_of::<CmHiveKeyOpenRequest>();
        if request.abi_size as usize != header
            || request.abi_version != CM_ABI_VERSION
            || request.mount != hive_mount::SYSTEM
        {
            return reply(STATUS_INVALID_PARAMETER, 0);
        }
        let mut units = [0u16; CM_MAX_HIVE_PATH_UNITS];
        let path = match request.operation {
            operation::QUERY => {
                if input.len() != header
                    || request.server_nonce != 0
                    || request.requester_nonce != 0
                    || request.request_slot != 0
                    || request.request_generation != 0
                    || request.path_offset != 0
                    || request.path_len_bytes != 0
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                None
            }
            operation::BEGIN => {
                if request.path_offset as usize != header
                    || request.path_len_bytes == 0
                    || request.path_len_bytes % 2 != 0
                    || request.path_len_bytes as usize > CM_MAX_HIVE_PATH_UNITS * 2
                    || header.checked_add(request.path_len_bytes as usize) != Some(input.len())
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let Some(count) = read_utf16(
                    input,
                    request.path_offset,
                    request.path_len_bytes,
                    &mut units,
                ) else {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                };
                Some(count)
            }
            operation::ACKNOWLEDGE => {
                if input.len() != header || request.path_offset != 0 || request.path_len_bytes != 0
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                None
            }
            _ => return reply(STATUS_INVALID_PARAMETER, 0),
        };
        let needed = if request.operation == operation::BEGIN {
            CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES
        } else {
            CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES
        };
        if output.len() < needed {
            return reply_with_info(STATUS_BUFFER_TOO_SMALL, needed as u32, 0, 0);
        }
        let mut body = CmHiveKeyOpenReply {
            abi_size: CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES as u16,
            abi_version: CM_ABI_VERSION,
            server_nonce: request.server_nonce,
            requester_nonce: request.requester_nonce,
            request_slot: request.request_slot,
            request_generation: request.request_generation,
            ..CmHiveKeyOpenReply::default()
        };
        match request.operation {
            operation::QUERY => {
                body.server_nonce = match self.system_key_opens.authority(&self.identities) {
                    Ok(nonce) => nonce,
                    Err(status) => return reply(status, 0),
                };
                body.disposition = disposition::AUTHORITY;
            }
            operation::BEGIN => {
                let units = &units[..path.unwrap()];
                if core::char::decode_utf16(units.iter().copied())
                    .any(|value| value.is_err() || value == Ok('\0'))
                {
                    return reply(STATUS_INVALID_PARAMETER, 0);
                }
                let (index, fresh) = match self.system_key_opens.claim(&request, units, usize::MAX)
                {
                    Ok(claim) => claim,
                    Err(status) => return reply(status, 0),
                };
                if fresh {
                    let outcome = decoded_path(units)
                        .and_then(|decoded| {
                            acquire(
                                self.system_hive.as_ref(),
                                &mut self.system_key_leases,
                                &decoded,
                            )
                        })
                        .unwrap_or_else(OpenOutcome::failed);
                    self.system_key_opens.finish(index, outcome);
                }
                let outcome = self.system_key_opens.slots[index]
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.outcome.as_ref())
                    .expect("completed OPEN outcome missing");
                body.disposition = disposition::OUTCOME;
                body.outcome_status = outcome.status;
                body.lease_token = outcome.lease;
                body.opened_generation = outcome.opened_generation;
                body.path_len_bytes = outcome.physical_path.len() as u32;
                let end = CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES + outcome.physical_path.len();
                output[CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES..end]
                    .copy_from_slice(outcome.physical_path.as_bytes());
            }
            operation::ACKNOWLEDGE => {
                body.disposition = match self.system_key_opens.acknowledge(&request) {
                    Ok(disposition) => disposition,
                    Err(status) => return reply(status, 0),
                };
            }
            _ => unreachable!(),
        }
        output[..CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES].copy_from_slice(body.as_bytes());
        reply_with_info(
            STATUS_SUCCESS,
            CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES as u32 + body.path_len_bytes,
            body.server_nonce,
            body.request_generation,
        )
    }
}

#[cfg(test)]
mod tests;
