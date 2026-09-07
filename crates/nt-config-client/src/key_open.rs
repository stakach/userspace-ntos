//! Retained OPEN attempts with allocation-free exchange and explicit acknowledgement/cleanup.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{Backend, ConfigClient, OpenedSystemHiveKey, SystemHiveKeyLease,
    SystemHiveKeyCloseReceipt, SystemHiveKeyCloseAcknowledgement,
    STATUS_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_INSUFFICIENT_RESOURCES, STATUS_DEVICE_NOT_READY};
use nt_config_abi::{CmReply, CmHiveKeyOpenRequest, CmHiveKeyOpenReply, CM_ABI_VERSION,
    CM_MAX_HIVE_PATH_UNITS, CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES, CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES,
    hive_mount, hive_key_open_operation as operation, hive_key_open_disposition as disposition, opcode};

static LAST_REQUESTER: AtomicU64 = AtomicU64::new(0);
const REQUEST_MAX: usize = core::mem::size_of::<CmHiveKeyOpenRequest>() + CM_MAX_HIVE_PATH_UNITS * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemHiveKeyOpenOperation { Query, Begin, Acknowledge }

struct Slot { sequence: u64, active: bool }

pub struct SystemHiveKeyOpenAttempts {
    requester: u64,
    slots: Vec<Slot>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity { requester: u64, slot: u64, sequence: u64 }

/// Store this owner before submitting OPEN. Errors never consume it. Dropping it does not release
/// its manager slot, acknowledge its server outcome, or close an acquired lease.
#[must_use]
pub struct SystemHiveKeyOpenAttempt {
    identity: Identity,
    server: u64,
    epoch: u64,
    inflight: Option<SystemHiveKeyOpenOperation>,
    submitted: bool,
    request_path: Vec<u8>,
    physical_path: String,
    outcome: Option<i32>,
    validation: Option<i32>,
    lease: Option<SystemHiveKeyLease>,
    receipt: Option<SystemHiveKeyCloseReceipt>,
    acknowledged: bool,
    lease_closed: bool,
    transferred: bool,
    released: bool,
}

impl SystemHiveKeyOpenAttempt {
    pub fn server_nonce(&self) -> Option<u64> { (self.server != 0).then_some(self.server) }
    pub fn has_outcome(&self) -> bool { self.outcome.is_some() }
    pub fn outcome_status(&self) -> Option<i32> { self.outcome }
    pub fn validation_status(&self) -> Option<i32> { self.validation }
    /// An immutable cleanup identity, not an ownership transfer or permission to publish a handle.
    pub fn known_lease(&self) -> Option<SystemHiveKeyLease> { self.lease }
    pub fn close_receipt(&self) -> Option<SystemHiveKeyCloseReceipt> { self.receipt }
    pub fn is_acknowledged(&self) -> bool { self.acknowledged }
    pub fn is_lease_closed(&self) -> bool { self.lease_closed }
    pub fn is_transferred(&self) -> bool { self.transferred }
    pub fn is_released(&self) -> bool { self.released }
    pub fn is_inflight(&self) -> bool { self.inflight.is_some() }
    pub fn was_submitted(&self) -> bool { self.submitted }
}

/// An exact exchange ticket owns its request bytes independently of the retained attempt. No
/// attempt or manager borrow needs to span transport IPC. A dropped ticket leaves the attempt busy.
#[must_use]
pub struct SystemHiveKeyOpenExchange {
    identity: Identity,
    epoch: u64,
    operation: SystemHiveKeyOpenOperation,
    live: bool,
    bytes: [u8; REQUEST_MAX],
    len: usize,
}

pub struct SystemHiveKeyOpenResponse {
    reply: CmReply,
    bytes: [u8; CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES],
}

impl SystemHiveKeyOpenResponse {
    /// Complete a ticket even when no backend is available. Submitted attempts remain ambiguous
    /// and must retry their exact identity; this response is not evidence of a failed OPEN outcome.
    pub fn transport_error(status: i32) -> Self {
        Self {
            reply: CmReply { status: if status == STATUS_SUCCESS { STATUS_INVALID_PARAMETER } else { status },
                information: 0, detail0: 0, detail1: 0 },
            bytes: [0; CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES],
        }
    }
}

impl<B: Backend> ConfigClient<B> {
    pub fn exchange_system_hive_key_open(&mut self, exchange: &SystemHiveKeyOpenExchange) -> SystemHiveKeyOpenResponse {
        if !exchange.live { return SystemHiveKeyOpenResponse::transport_error(STATUS_INVALID_PARAMETER); }
        let mut bytes = [0; CM_HIVE_KEY_OPEN_REPLY_MAX_BYTES];
        let reply = self.backend.call(opcode::CM_OP_SYSTEM_HIVE_KEY_OPEN, &exchange.bytes[..exchange.len], &mut bytes);
        SystemHiveKeyOpenResponse { reply, bytes }
    }
}

impl Default for SystemHiveKeyOpenAttempts { fn default() -> Self { Self::new() } }

impl SystemHiveKeyOpenAttempts {
    pub const fn new() -> Self { Self { requester: 0, slots: Vec::new() } }

    pub fn reserve(&mut self, path: &str) -> Result<SystemHiveKeyOpenAttempt, i32> {
        let units = path.encode_utf16().count();
        if units == 0 || units > CM_MAX_HIVE_PATH_UNITS || path.contains('\0') { return Err(STATUS_INVALID_PARAMETER); }
        let mut request_path = Vec::new();
        request_path.try_reserve_exact(units * 2).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for unit in path.encode_utf16() { request_path.extend_from_slice(&unit.to_le_bytes()); }
        let mut physical_path = String::new();
        physical_path.try_reserve_exact(CM_MAX_HIVE_PATH_UNITS * 4).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let vacant = self.slots.iter().position(|slot| !slot.active && slot.sequence != u64::MAX);
        if vacant.is_none() { self.slots.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?; }
        let requester = if self.requester == 0 {
            LAST_REQUESTER.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| last.checked_add(1))
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)? + 1
        } else { self.requester };
        let index = vacant.unwrap_or(self.slots.len());
        let sequence = vacant.map_or(1, |index| self.slots[index].sequence + 1);
        self.requester = requester;
        let slot = Slot { sequence, active: true };
        if vacant.is_some() { self.slots[index] = slot; } else { self.slots.push(slot); }
        Ok(SystemHiveKeyOpenAttempt {
            identity: Identity { requester, slot: index as u64, sequence }, server: 0, epoch: 0,
            inflight: None, submitted: false, request_path, physical_path, outcome: None,
            validation: None, lease: None, receipt: None, acknowledged: false,
            lease_closed: false, transferred: false, released: false,
        })
    }

    fn validate(&self, attempt: &SystemHiveKeyOpenAttempt) -> Result<(), i32> {
        if self.requester == 0 || self.requester != attempt.identity.requester || attempt.released
            || !self.slots.get(attempt.identity.slot as usize).is_some_and(|slot| slot.active && slot.sequence == attempt.identity.sequence)
        { return Err(STATUS_INVALID_PARAMETER); }
        Ok(())
    }

    pub fn begin_exchange(&self, attempt: &mut SystemHiveKeyOpenAttempt, op: SystemHiveKeyOpenOperation)
        -> Result<SystemHiveKeyOpenExchange, i32>
    {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || attempt.acknowledged || attempt.transferred { return Err(STATUS_INVALID_PARAMETER); }
        match op {
            SystemHiveKeyOpenOperation::Query if attempt.server == 0 && !attempt.submitted => {}
            SystemHiveKeyOpenOperation::Begin if attempt.server != 0 && !attempt.lease_closed && attempt.receipt.is_none() => {}
            SystemHiveKeyOpenOperation::Acknowledge if attempt.server != 0 && attempt.has_outcome()
                && (attempt.validation == Some(STATUS_SUCCESS) || attempt.lease_closed) => {}
            _ => return Err(STATUS_INVALID_PARAMETER),
        }
        let epoch = attempt.epoch.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let header_size = core::mem::size_of::<CmHiveKeyOpenRequest>();
        let mut request = CmHiveKeyOpenRequest {
            abi_size: header_size as u16, abi_version: CM_ABI_VERSION, mount: hive_mount::SYSTEM,
            ..CmHiveKeyOpenRequest::default()
        };
        request.operation = match op {
            SystemHiveKeyOpenOperation::Query => operation::QUERY,
            SystemHiveKeyOpenOperation::Begin => operation::BEGIN,
            SystemHiveKeyOpenOperation::Acknowledge => operation::ACKNOWLEDGE,
        };
        if op != SystemHiveKeyOpenOperation::Query {
            request.server_nonce = attempt.server;
            request.requester_nonce = attempt.identity.requester;
            request.request_slot = attempt.identity.slot;
            request.request_generation = attempt.identity.sequence;
        }
        let mut bytes = [0; REQUEST_MAX];
        let len = if op == SystemHiveKeyOpenOperation::Begin {
            request.path_offset = header_size as u32;
            request.path_len_bytes = attempt.request_path.len() as u32;
            bytes[header_size..header_size + attempt.request_path.len()].copy_from_slice(&attempt.request_path);
            header_size + attempt.request_path.len()
        } else { header_size };
        bytes[..header_size].copy_from_slice(request.as_bytes());
        attempt.epoch = epoch;
        attempt.inflight = Some(op);
        if op == SystemHiveKeyOpenOperation::Begin { attempt.submitted = true; }
        Ok(SystemHiveKeyOpenExchange { identity: attempt.identity, epoch, operation: op, live: true, bytes, len })
    }

    pub fn complete_exchange(&self, attempt: &mut SystemHiveKeyOpenAttempt, exchange: &mut SystemHiveKeyOpenExchange,
        response: SystemHiveKeyOpenResponse) -> Result<(), i32>
    {
        self.validate(attempt)?;
        if !exchange.live || exchange.identity != attempt.identity || exchange.epoch != attempt.epoch
            || attempt.inflight != Some(exchange.operation) { return Err(STATUS_INVALID_PARAMETER); }
        attempt.inflight = None;
        exchange.live = false;
        let body = CmHiveKeyOpenReply::from_bytes(&response.bytes).ok_or(STATUS_INVALID_PARAMETER)?;
        let prefix_valid = response.reply.information as usize >= CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES
            && body.abi_size as usize == CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES
            && body.abi_version == CM_ABI_VERSION && body.reserved == 0 && body.server_nonce != 0
            && response.reply.detail0 == body.server_nonce && response.reply.detail1 == body.request_generation;
        let error = if response.reply.status == STATUS_SUCCESS { STATUS_INVALID_PARAMETER } else { response.reply.status };
        if !prefix_valid { return Err(error); }
        match exchange.operation {
            SystemHiveKeyOpenOperation::Query => {
                if response.reply.status != STATUS_SUCCESS || body.disposition != disposition::AUTHORITY
                    || response.reply.information as usize != CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES
                    || body.requester_nonce != 0 || body.request_slot != 0 || body.request_generation != 0
                    || body.outcome_status != 0 || body.path_len_bytes != 0 || body.lease_token != 0 || body.opened_generation != 0
                { return Err(error); }
                attempt.server = body.server_nonce;
                Ok(())
            }
            SystemHiveKeyOpenOperation::Begin => {
                if body.server_nonce != attempt.server || body.requester_nonce != attempt.identity.requester
                    || body.request_slot != attempt.identity.slot || body.request_generation != attempt.identity.sequence
                    || body.disposition != disposition::OUTCOME { return Err(error); }
                // Capture authenticated acquisition evidence before interpreting generation/path.
                if let Some(lease) = attempt.lease {
                    if body.lease_token != lease.token || body.opened_generation != lease.opened_generation {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                }
                let already_validated = attempt.validation == Some(STATUS_SUCCESS);
                if already_validated && attempt.outcome != Some(body.outcome_status) { return Err(STATUS_INVALID_PARAMETER); }
                if !already_validated {
                    if body.lease_token != 0 {
                        attempt.lease = Some(SystemHiveKeyLease { token: body.lease_token, opened_generation: body.opened_generation });
                    }
                    attempt.outcome = Some(body.outcome_status);
                    attempt.validation = Some(STATUS_INVALID_PARAMETER);
                }
                if response.reply.status != STATUS_SUCCESS { return Err(response.reply.status); }
                let path_len = body.path_len_bytes as usize;
                if path_len > CM_MAX_HIVE_PATH_UNITS * 4
                    || response.reply.information as usize != CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES + path_len
                { return Err(STATUS_INVALID_PARAMETER); }
                if body.outcome_status == STATUS_SUCCESS {
                    if body.lease_token == 0 || body.opened_generation == 0 || path_len == 0 { return Err(STATUS_INVALID_PARAMETER); }
                    let path = core::str::from_utf8(&response.bytes[CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES..CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES + path_len])
                        .map_err(|_| STATUS_INVALID_PARAMETER)?;
                    if path.contains('\0') { return Err(STATUS_INVALID_PARAMETER); }
                    if already_validated && path != attempt.physical_path { return Err(STATUS_INVALID_PARAMETER); }
                    attempt.physical_path.clear();
                    attempt.physical_path.push_str(path);
                } else if body.lease_token != 0 || body.opened_generation != 0 || path_len != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                attempt.validation = Some(STATUS_SUCCESS);
                Ok(())
            }
            SystemHiveKeyOpenOperation::Acknowledge => {
                if response.reply.status != STATUS_SUCCESS
                    || !matches!(body.disposition, disposition::ACKNOWLEDGED | disposition::ALREADY_ACKNOWLEDGED)
                    || response.reply.information as usize != CM_HIVE_KEY_OPEN_REPLY_HEADER_BYTES
                    || body.server_nonce != attempt.server || body.requester_nonce != attempt.identity.requester
                    || body.request_slot != attempt.identity.slot || body.request_generation != attempt.identity.sequence
                    || body.outcome_status != 0 || body.path_len_bytes != 0 || body.lease_token != 0 || body.opened_generation != 0
                { return Err(error); }
                attempt.acknowledged = true;
                Ok(())
            }
        }
    }

    pub fn record_close_receipt(&self, attempt: &mut SystemHiveKeyOpenAttempt, receipt: SystemHiveKeyCloseReceipt) -> Result<(), i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || attempt.transferred || attempt.lease_closed
            || !attempt.lease.is_some_and(|lease| lease.token == receipt.lease_token())
            || attempt.receipt.is_some_and(|existing| existing != receipt) { return Err(STATUS_INVALID_PARAMETER); }
        attempt.receipt = Some(receipt);
        Ok(())
    }

    pub fn mark_lease_closed(&self, attempt: &mut SystemHiveKeyOpenAttempt, ack: SystemHiveKeyCloseAcknowledgement) -> Result<(), i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || attempt.transferred || attempt.lease_closed || attempt.receipt != Some(ack.receipt()) { return Err(STATUS_INVALID_PARAMETER); }
        attempt.lease_closed = true;
        Ok(())
    }

    pub fn take_validated(&self, attempt: &mut SystemHiveKeyOpenAttempt, expected_generation: u64) -> Result<OpenedSystemHiveKey, i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || !attempt.acknowledged || attempt.validation != Some(STATUS_SUCCESS)
            || attempt.transferred || attempt.lease_closed || attempt.receipt.is_some() { return Err(STATUS_INVALID_PARAMETER); }
        let status = attempt.outcome.ok_or(STATUS_INVALID_PARAMETER)?;
        if status != STATUS_SUCCESS { return Err(status); }
        let lease = attempt.lease.ok_or(STATUS_INVALID_PARAMETER)?;
        if expected_generation == 0 || lease.opened_generation != expected_generation { return Err(STATUS_DEVICE_NOT_READY); }
        attempt.lease = None;
        attempt.transferred = true;
        Ok(OpenedSystemHiveKey { lease, physical_path: core::mem::take(&mut attempt.physical_path) })
    }

    pub fn release(&mut self, attempt: &mut SystemHiveKeyOpenAttempt) -> Result<(), i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || (attempt.submitted && (!attempt.acknowledged
            || (attempt.lease.is_some() && !attempt.lease_closed && !attempt.transferred))) { return Err(STATUS_INVALID_PARAMETER); }
        let slot = &mut self.slots[attempt.identity.slot as usize];
        if !attempt.submitted { slot.sequence -= 1; }
        slot.active = false;
        attempt.released = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration;
