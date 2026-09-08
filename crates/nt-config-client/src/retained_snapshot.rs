//! Explicit client ownership for replayable CM snapshots and their acknowledged cancellation.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{ActiveDriverServiceBinding, Backend, ConfigClient, STATUS_SUCCESS,
    STATUS_INVALID_PARAMETER, STATUS_DEVICE_NOT_READY, STATUS_INSUFFICIENT_RESOURCES};
use nt_config_abi::{CmReply, CmRetainedSnapshotRequest, CmRetainedSnapshotReply,
    CM_ABI_VERSION, CM_MAX_HIVE_PATH_UNITS, CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES,
    CM_RETAINED_SNAPSHOT_CHUNK_BYTES, CM_RETAINED_SNAPSHOT_MAX_SLOTS,
    CM_RETAINED_SNAPSHOT_MAX_BYTES, retained_snapshot_operation as operation,
    retained_snapshot_disposition as disposition, retained_snapshot_kind as kind, opcode};

static LAST_REQUESTER: AtomicU64 = AtomicU64::new(0);
const REQUEST_MAX: usize = core::mem::size_of::<CmRetainedSnapshotRequest>() + CM_MAX_HIVE_PATH_UNITS * 2;
const REPLY_MAX: usize = CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES + CM_RETAINED_SNAPSHOT_CHUNK_BYTES;
const DEFAULT_SLOTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmSnapshotOperation { Query, Begin, Pull, Acknowledge }

struct Slot { sequence: u64, active: bool }

/// Owns one persistent requester registration for the lifetime of a CM connection. The server
/// pre-admits all slot watermarks at QUERY, so every admitted attempt can ACK without allocation.
/// Keep this manager across individual queries and cancellations; dropping it does not unregister
/// its bank. Only connection retirement/quiescence can end the server registration's lifetime.
pub struct CmSnapshotAttempts {
    requester: u64,
    server: Option<u64>,
    grant: usize,
    slots: Vec<Slot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity { requester: u64, slot: u64, sequence: u64 }

/// Errors preserve this owner. Dropping it neither releases a server snapshot nor makes its slot
/// reusable. Abandonment is sticky, and an abandoned owner can never publish a late reply.
///
/// ```compile_fail
/// use nt_config_client::CmSnapshotAttempt;
/// fn duplicate(attempt: CmSnapshotAttempt) { let _ = attempt.clone(); }
/// ```
#[must_use]
pub struct CmSnapshotAttempt {
    identity: Identity,
    server: Option<u64>,
    query_kind: u16,
    payload: Vec<u8>,
    epoch: u64,
    inflight: Option<CmSnapshotOperation>,
    submitted: bool,
    abandoned: bool,
    acknowledged: bool,
    transferred: bool,
    released: bool,
    outcome: Option<i32>,
    total: Option<u32>,
    bytes: Vec<u8>,
}

impl CmSnapshotAttempt {
    pub fn server_nonce(&self) -> Option<u64> { self.server }
    pub fn outcome_status(&self) -> Option<i32> { self.outcome }
    pub fn total_len(&self) -> Option<u32> { self.total }
    pub fn collected_len(&self) -> usize { self.bytes.len() }
    pub fn is_complete(&self) -> bool {
        self.outcome.is_some_and(|status| status != STATUS_SUCCESS || self.total == Some(self.bytes.len() as u32))
    }
    pub fn is_acknowledged(&self) -> bool { self.acknowledged }
    pub fn is_abandoned(&self) -> bool { self.abandoned }
    pub fn is_inflight(&self) -> bool { self.inflight.is_some() }
    pub fn was_submitted(&self) -> bool { self.submitted }
    pub fn is_released(&self) -> bool { self.released }
    pub fn is_transferred(&self) -> bool { self.transferred }
}

/// One detached exchange owns its exact request bytes. No manager/attempt borrow crosses IPC.
///
/// ```compile_fail
/// use nt_config_client::CmSnapshotExchange;
/// fn duplicate(exchange: CmSnapshotExchange) { let _ = exchange.clone(); }
/// ```
#[must_use]
pub struct CmSnapshotExchange {
    identity: Identity,
    epoch: u64,
    operation: CmSnapshotOperation,
    offset: u32,
    capacity: u32,
    live: bool,
    bytes: [u8; REQUEST_MAX],
    len: usize,
}

pub struct CmSnapshotResponse {
    reply: CmReply,
    bytes: [u8; REPLY_MAX],
}

impl CmSnapshotResponse {
    pub fn transport_error(status: i32) -> Self {
        Self { reply: CmReply { status: if status == STATUS_SUCCESS { STATUS_INVALID_PARAMETER } else { status },
            information: 0, detail0: 0, detail1: 0 }, bytes: [0; REPLY_MAX] }
    }
}

impl<B: Backend> ConfigClient<B> {
    pub fn exchange_retained_snapshot(&mut self, exchange: &CmSnapshotExchange) -> CmSnapshotResponse {
        if !exchange.live { return CmSnapshotResponse::transport_error(STATUS_INVALID_PARAMETER); }
        let mut bytes = [0; REPLY_MAX];
        let reply = self.backend.call(opcode::CM_OP_RETAINED_SNAPSHOT, &exchange.bytes[..exchange.len], &mut bytes);
        CmSnapshotResponse { reply, bytes }
    }
}

impl Default for CmSnapshotAttempts { fn default() -> Self { Self::new() } }

impl CmSnapshotAttempts {
    pub const fn new() -> Self { Self { requester: 0, server: None, grant: DEFAULT_SLOTS, slots: Vec::new() } }

    pub fn with_slot_limit(grant: usize) -> Result<Self, i32> {
        if grant == 0 || grant > CM_RETAINED_SNAPSHOT_MAX_SLOTS { return Err(STATUS_INVALID_PARAMETER); }
        Ok(Self { requester: 0, server: None, grant, slots: Vec::new() })
    }

    pub fn reserve_active_driver_service(&mut self, path: &str) -> Result<CmSnapshotAttempt, i32> {
        let units = path.encode_utf16().count();
        if units == 0 || units > CM_MAX_HIVE_PATH_UNITS || path.contains('\0') { return Err(STATUS_INVALID_PARAMETER); }
        let mut payload = Vec::new();
        payload.try_reserve_exact(units * 2).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for unit in path.encode_utf16() { payload.extend_from_slice(&unit.to_le_bytes()); }
        let vacant = self.slots.iter().position(|slot| !slot.active && slot.sequence != u64::MAX);
        if vacant.is_none() {
            if self.slots.len() >= self.grant { return Err(STATUS_INSUFFICIENT_RESOURCES); }
            self.slots.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let requester = if self.requester == 0 {
            LAST_REQUESTER.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| last.checked_add(1))
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)? + 1
        } else { self.requester };
        let index = vacant.unwrap_or(self.slots.len());
        let sequence = vacant.map_or(1, |index| self.slots[index].sequence + 1);
        let slot = Slot { sequence, active: true };
        self.requester = requester;
        if vacant.is_some() { self.slots[index] = slot; } else { self.slots.push(slot); }
        Ok(CmSnapshotAttempt { identity: Identity { requester, slot: index as u64, sequence }, server: self.server,
            query_kind: kind::ACTIVE_DRIVER_SERVICE, payload, epoch: 0, inflight: None, submitted: false,
            abandoned: false, acknowledged: false, transferred: false, released: false,
            outcome: None, total: None, bytes: Vec::new() })
    }

    fn validate(&self, attempt: &CmSnapshotAttempt) -> Result<(), i32> {
        if self.requester == 0 || self.requester != attempt.identity.requester || attempt.released
            || !self.slots.get(attempt.identity.slot as usize).is_some_and(|slot| slot.active && slot.sequence == attempt.identity.sequence)
        { return Err(STATUS_INVALID_PARAMETER); }
        Ok(())
    }

    pub fn abandon(&self, attempt: &mut CmSnapshotAttempt) -> Result<(), i32> {
        self.validate(attempt)?;
        attempt.abandoned = true;
        Ok(())
    }

    pub fn begin_exchange(&self, attempt: &mut CmSnapshotAttempt, op: CmSnapshotOperation) -> Result<CmSnapshotExchange, i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || attempt.acknowledged || attempt.transferred { return Err(STATUS_INVALID_PARAMETER); }
        match op {
            CmSnapshotOperation::Query if attempt.server.is_none() && !attempt.submitted && !attempt.abandoned => {}
            CmSnapshotOperation::Begin if attempt.server.is_some() && !attempt.abandoned && attempt.bytes.is_empty() => {}
            CmSnapshotOperation::Pull if attempt.server.is_some() && !attempt.abandoned
                && attempt.outcome == Some(STATUS_SUCCESS) && !attempt.is_complete()
                && attempt.total.is_some_and(|total| attempt.bytes.capacity() >= total as usize) => {}
            CmSnapshotOperation::Acknowledge if attempt.server.is_some() && attempt.submitted
                && (attempt.abandoned || attempt.is_complete()) => {}
            _ => return Err(STATUS_INVALID_PARAMETER),
        }
        let epoch = attempt.epoch.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let size = core::mem::size_of::<CmRetainedSnapshotRequest>();
        let mut request = CmRetainedSnapshotRequest { abi_size: size as u16, abi_version: CM_ABI_VERSION,
            requester_nonce: attempt.identity.requester, ..CmRetainedSnapshotRequest::default() };
        request.operation = match op { CmSnapshotOperation::Query => operation::QUERY, CmSnapshotOperation::Begin => operation::BEGIN,
            CmSnapshotOperation::Pull => operation::PULL, CmSnapshotOperation::Acknowledge => operation::ACKNOWLEDGE };
        if op == CmSnapshotOperation::Query {
            request.chunk_capacity = self.grant as u32;
        } else {
            request.query_kind = attempt.query_kind;
            request.server_nonce = attempt.server.ok_or(STATUS_INVALID_PARAMETER)?;
            request.request_slot = attempt.identity.slot;
            request.request_generation = attempt.identity.sequence;
        }
        let mut bytes = [0; REQUEST_MAX];
        let len = if op == CmSnapshotOperation::Begin {
            request.request_offset = size as u32;
            request.request_len_bytes = attempt.payload.len() as u32;
            bytes[size..size + attempt.payload.len()].copy_from_slice(&attempt.payload);
            size + attempt.payload.len()
        } else { size };
        if op == CmSnapshotOperation::Pull {
            request.value_offset = attempt.bytes.len() as u32;
            request.chunk_capacity = CM_RETAINED_SNAPSHOT_CHUNK_BYTES as u32;
        }
        bytes[..size].copy_from_slice(request.as_bytes());
        attempt.epoch = epoch;
        attempt.inflight = Some(op);
        if op == CmSnapshotOperation::Begin { attempt.submitted = true; }
        Ok(CmSnapshotExchange { identity: attempt.identity, epoch, operation: op, offset: request.value_offset,
            capacity: request.chunk_capacity, live: true, bytes, len })
    }

    pub fn complete_exchange(&mut self, attempt: &mut CmSnapshotAttempt, exchange: &mut CmSnapshotExchange, response: CmSnapshotResponse) -> Result<(), i32> {
        self.complete_exchange_with_reserve(attempt, exchange, response, |bytes, total| {
            bytes.try_reserve_exact(total).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
        })
    }

    fn complete_exchange_with_reserve(&mut self, attempt: &mut CmSnapshotAttempt, exchange: &mut CmSnapshotExchange,
        response: CmSnapshotResponse, reserve: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), i32>) -> Result<(), i32>
    {
        self.validate(attempt)?;
        if !exchange.live || exchange.identity != attempt.identity || exchange.epoch != attempt.epoch
            || attempt.inflight != Some(exchange.operation) { return Err(STATUS_INVALID_PARAMETER); }
        attempt.inflight = None;
        exchange.live = false;
        if response.reply.status != STATUS_SUCCESS { return Err(response.reply.status); }
        let information = response.reply.information as usize;
        if information < CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES || information > response.bytes.len() { return Err(STATUS_INVALID_PARAMETER); }
        let body = CmRetainedSnapshotReply::from_bytes(&response.bytes).ok_or(STATUS_INVALID_PARAMETER)?;
        if body.abi_size as usize != CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES || body.abi_version != CM_ABI_VERSION
            || body._reserved != 0 || body.server_nonce == 0 || body.requester_nonce != attempt.identity.requester
            || response.reply.detail0 != body.server_nonce || response.reply.detail1 != body.request_generation
        { return Err(STATUS_INVALID_PARAMETER); }
        if exchange.operation == CmSnapshotOperation::Query {
            if body.disposition != disposition::AUTHORITY || body.query_kind != 0 || body.request_slot != 0
                || body.request_generation != 0 || body.outcome_status != 0 || body.total_bytes as usize != self.grant
                || body.value_offset != 0 || body.chunk_bytes != 0 || information != CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES
                || self.server.is_some_and(|server| server != body.server_nonce)
            { return Err(STATUS_INVALID_PARAMETER); }
            self.server = Some(body.server_nonce);
            attempt.server = self.server;
            return Ok(());
        }
        if Some(body.server_nonce) != attempt.server || body.query_kind != attempt.query_kind
            || body.request_slot != attempt.identity.slot || body.request_generation != attempt.identity.sequence
        { return Err(STATUS_INVALID_PARAMETER); }
        match exchange.operation {
            CmSnapshotOperation::Begin => {
                if body.disposition != disposition::OUTCOME || body.value_offset != 0 || body.chunk_bytes != 0
                    || information != CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES
                    || body.total_bytes as usize > CM_RETAINED_SNAPSHOT_MAX_BYTES
                    || (body.outcome_status != STATUS_SUCCESS && body.total_bytes != 0)
                    || attempt.outcome.is_some_and(|status| status != body.outcome_status)
                    || attempt.total.is_some_and(|total| total != body.total_bytes)
                { return Err(STATUS_INVALID_PARAMETER); }
                attempt.outcome = Some(body.outcome_status);
                attempt.total = Some(body.total_bytes);
                if !attempt.abandoned && body.outcome_status == STATUS_SUCCESS {
                    reserve(&mut attempt.bytes, body.total_bytes as usize)?;
                }
                Ok(())
            }
            CmSnapshotOperation::Pull => {
                if body.disposition != disposition::CHUNK || body.outcome_status != STATUS_SUCCESS
                    || Some(body.total_bytes) != attempt.total || body.value_offset != exchange.offset
                    || body.chunk_bytes == 0 || body.chunk_bytes > exchange.capacity
                    || body.value_offset.checked_add(body.chunk_bytes).is_none_or(|end| end > body.total_bytes)
                    || information != CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES + body.chunk_bytes as usize
                    || attempt.bytes.len() != exchange.offset as usize
                { return Err(STATUS_INVALID_PARAMETER); }
                if !attempt.abandoned {
                    attempt.bytes.extend_from_slice(&response.bytes[CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES..information]);
                }
                Ok(())
            }
            CmSnapshotOperation::Acknowledge => {
                if !matches!(body.disposition, disposition::ACKNOWLEDGED | disposition::ALREADY_ACKNOWLEDGED)
                    || body.outcome_status != 0 || body.total_bytes != 0 || body.value_offset != 0 || body.chunk_bytes != 0
                    || information != CM_RETAINED_SNAPSHOT_REPLY_HEADER_BYTES { return Err(STATUS_INVALID_PARAMETER); }
                attempt.acknowledged = true;
                Ok(())
            }
            CmSnapshotOperation::Query => unreachable!(),
        }
    }

    pub fn take_active_driver_service(&self, attempt: &mut CmSnapshotAttempt, expected_generation: u64) -> Result<ActiveDriverServiceBinding, i32> {
        self.validate(attempt)?;
        if attempt.abandoned || attempt.inflight.is_some() || !attempt.acknowledged || !attempt.is_complete()
            || attempt.transferred || attempt.query_kind != kind::ACTIVE_DRIVER_SERVICE { return Err(STATUS_INVALID_PARAMETER); }
        let status = attempt.outcome.ok_or(STATUS_INVALID_PARAMETER)?;
        if status != STATUS_SUCCESS { return Err(status); }
        let value = crate::active_driver_service::decode(&attempt.bytes)?;
        if expected_generation == 0 || value.mount_generation != expected_generation { return Err(STATUS_DEVICE_NOT_READY); }
        attempt.transferred = true;
        Ok(value)
    }

    pub fn release(&mut self, attempt: &mut CmSnapshotAttempt) -> Result<(), i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || (attempt.submitted && !attempt.acknowledged) { return Err(STATUS_INVALID_PARAMETER); }
        let slot = &mut self.slots[attempt.identity.slot as usize];
        if !attempt.submitted { slot.sequence -= 1; }
        slot.active = false;
        attempt.released = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
