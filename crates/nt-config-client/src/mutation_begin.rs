//! Retained ownership of SYSTEM mutation acquisition, including lost BEGIN and ACK replies.
//! The handoff still owns a live upload; APPEND/PREPARE and its cancellation are separate work.

use crate::{
    encode_hive_mutation_journal, Backend, ConfigClient, SystemHiveMutation,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_config_abi::mutation_begin::{disposition, operation, Reply, Request, MAX_SLOTS};
use nt_config_abi::{hive_mount, opcode, CmReply, CM_ABI_VERSION};

static LAST_REQUESTER: AtomicU64 = AtomicU64::new(0);
const REQUEST_BYTES: usize = core::mem::size_of::<Request>();
const REPLY_BYTES: usize = core::mem::size_of::<Reply>();
const DEFAULT_SLOTS: usize = 64;

mod upload;
pub use upload::{
    CmMutationPreparationExchange, CmMutationPreparationOperation, CmMutationPreparationPhase,
    CmMutationPreparationResponse, SystemHiveMutationPreparation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmMutationBeginOperation {
    Query,
    Begin,
    Acknowledge,
}

struct Slot {
    sequence: u64,
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    requester: u64,
    slot: u64,
    sequence: u64,
}

/// One pregranted requester bank. Keep it for the lifetime of the CM connection: dropping it
/// does not unregister its server bank. Only an acknowledged outcome can release a used slot.
pub struct CmMutationBeginAttempts {
    requester: u64,
    server: Option<u64>,
    grant: usize,
    slots: Vec<Slot>,
}

/// Owns the exact semantic bytes and complete caller while acquisition is unresolved. Errors
/// never release either. Dropping a detached exchange leaves this attempt in flight; losing a
/// ticket is not permission to submit another request, cancel the writer, or replace authority.
///
/// ```compile_fail
/// use nt_config_client::CmMutationBeginAttempt;
/// fn duplicate<C>(attempt: CmMutationBeginAttempt<C>) { let _ = attempt.clone(); }
/// ```
#[must_use]
pub struct CmMutationBeginAttempt<C> {
    identity: Identity,
    server: Option<u64>,
    expected_generation: u64,
    journal: Vec<u8>,
    continuation: Option<C>,
    epoch: u64,
    inflight: Option<CmMutationBeginOperation>,
    submitted: bool,
    acknowledged: bool,
    released: bool,
    outcome: Option<i32>,
    mutation_token: Option<u64>,
}

impl<C> CmMutationBeginAttempt<C> {
    pub fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    pub fn journal(&self) -> &[u8] {
        &self.journal
    }
    pub fn continuation(&self) -> Option<&C> {
        self.continuation.as_ref()
    }
    pub fn server_nonce(&self) -> Option<u64> {
        self.server
    }
    pub fn outcome_status(&self) -> Option<i32> {
        self.outcome
    }
    pub fn is_inflight(&self) -> bool {
        self.inflight.is_some()
    }
    pub fn was_submitted(&self) -> bool {
        self.submitted
    }
    pub fn is_acknowledged(&self) -> bool {
        self.acknowledged
    }
    pub fn is_released(&self) -> bool {
        self.released
    }
}

/// Exact detached request ticket; its identity and epoch must match the retained attempt.
///
/// ```compile_fail
/// use nt_config_client::CmMutationBeginExchange;
/// fn duplicate(exchange: CmMutationBeginExchange) { let _ = exchange.clone(); }
/// ```
#[must_use]
pub struct CmMutationBeginExchange {
    identity: Identity,
    epoch: u64,
    operation: CmMutationBeginOperation,
    live: bool,
    bytes: [u8; REQUEST_BYTES],
}

pub struct CmMutationBeginResponse {
    reply: CmReply,
    bytes: [u8; REPLY_BYTES],
}

impl CmMutationBeginResponse {
    pub fn transport_error(status: i32) -> Self {
        Self {
            reply: CmReply {
                status: if status == STATUS_SUCCESS {
                    STATUS_INVALID_PARAMETER
                } else {
                    status
                },
                information: 0,
                detail0: 0,
                detail1: 0,
            },
            bytes: [0; REPLY_BYTES],
        }
    }
}

/// Acknowledged BEGIN ownership, not a prepared mutation or a completed caller. The server still
/// owns the live upload. No raw token or mutable journal is exposed, and dropping this value does
/// not abort that upload. Consume it with `into_preparation` to retain APPEND/PREPARE progress.
///
/// ```compile_fail
/// use nt_config_client::SystemHiveMutationUpload;
/// fn duplicate<C>(upload: SystemHiveMutationUpload<C>) { let _ = upload.clone(); }
/// ```
#[must_use]
pub struct SystemHiveMutationUpload<C> {
    identity: Identity,
    server: u64,
    mutation_token: u64,
    expected_generation: u64,
    journal: Vec<u8>,
    continuation: C,
}

impl<C> SystemHiveMutationUpload<C> {
    pub fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    pub fn journal(&self) -> &[u8] {
        &self.journal
    }
    pub fn continuation(&self) -> &C {
        &self.continuation
    }
}

impl<B: Backend> ConfigClient<B> {
    pub fn exchange_system_hive_mutation_begin(
        &mut self,
        exchange: &CmMutationBeginExchange,
    ) -> CmMutationBeginResponse {
        if !exchange.live {
            return CmMutationBeginResponse::transport_error(STATUS_INVALID_PARAMETER);
        }
        let mut bytes = [0; REPLY_BYTES];
        let reply = self.backend.call(
            opcode::CM_OP_SYSTEM_HIVE_MUTATION_BEGIN,
            &exchange.bytes,
            &mut bytes,
        );
        CmMutationBeginResponse { reply, bytes }
    }
}

impl Default for CmMutationBeginAttempts {
    fn default() -> Self {
        Self::new()
    }
}

impl CmMutationBeginAttempts {
    pub const fn new() -> Self {
        Self {
            requester: 0,
            server: None,
            grant: DEFAULT_SLOTS,
            slots: Vec::new(),
        }
    }

    pub fn with_slot_limit(grant: usize) -> Result<Self, i32> {
        if grant == 0 || grant > MAX_SLOTS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self {
            requester: 0,
            server: None,
            grant,
            slots: Vec::new(),
        })
    }

    /// Reserve and encode before any IPC. Failed admission returns the complete caller unchanged.
    pub fn reserve<C>(
        &mut self,
        expected_generation: u64,
        mutations: &[SystemHiveMutation<'_>],
        continuation: C,
    ) -> Result<CmMutationBeginAttempt<C>, (i32, C)> {
        let admission = (|| {
            if expected_generation == 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let journal = encode_hive_mutation_journal(mutations)?;
            u32::try_from(journal.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let vacant = self
                .slots
                .iter()
                .position(|slot| !slot.active && slot.sequence != u64::MAX);
            if vacant.is_none() {
                if self.slots.len() >= self.grant {
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                self.slots
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            }
            let requester = if self.requester == 0 {
                LAST_REQUESTER
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                        last.checked_add(1)
                    })
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?
                    + 1
            } else {
                self.requester
            };
            let index = vacant.unwrap_or(self.slots.len());
            let sequence = vacant.map_or(1, |index| self.slots[index].sequence + 1);
            let slot = Slot {
                sequence,
                active: true,
            };
            self.requester = requester;
            if vacant.is_some() {
                self.slots[index] = slot;
            } else {
                self.slots.push(slot);
            }
            Ok((
                journal,
                Identity {
                    requester,
                    slot: index as u64,
                    sequence,
                },
            ))
        })();
        let (journal, identity) = match admission {
            Ok(value) => value,
            Err(status) => return Err((status, continuation)),
        };
        Ok(CmMutationBeginAttempt {
            identity,
            server: self.server,
            expected_generation,
            journal,
            continuation: Some(continuation),
            epoch: 0,
            inflight: None,
            submitted: false,
            acknowledged: false,
            released: false,
            outcome: None,
            mutation_token: None,
        })
    }

    fn validate<C>(&self, attempt: &CmMutationBeginAttempt<C>) -> Result<(), i32> {
        if self.requester == 0
            || self.requester != attempt.identity.requester
            || attempt.released
            || !self
                .slots
                .get(attempt.identity.slot as usize)
                .is_some_and(|slot| slot.active && slot.sequence == attempt.identity.sequence)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn begin_exchange<C>(
        &self,
        attempt: &mut CmMutationBeginAttempt<C>,
        op: CmMutationBeginOperation,
    ) -> Result<CmMutationBeginExchange, i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || attempt.acknowledged {
            return Err(STATUS_INVALID_PARAMETER);
        }
        match op {
            CmMutationBeginOperation::Query if attempt.server.is_none() && !attempt.submitted => {}
            CmMutationBeginOperation::Begin
                if attempt.server.is_some() && attempt.outcome.is_none() => {}
            CmMutationBeginOperation::Acknowledge
                if attempt.server.is_some()
                    && attempt.submitted
                    && attempt.outcome.is_some()
                    && attempt.mutation_token.is_some() => {}
            _ => return Err(STATUS_INVALID_PARAMETER),
        }
        let epoch = attempt
            .epoch
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let mut request = Request {
            abi_size: REQUEST_BYTES as u16,
            abi_version: CM_ABI_VERSION,
            mount: hive_mount::SYSTEM,
            requester_nonce: attempt.identity.requester,
            ..Request::default()
        };
        request.operation = match op {
            CmMutationBeginOperation::Query => operation::QUERY,
            CmMutationBeginOperation::Begin => operation::BEGIN,
            CmMutationBeginOperation::Acknowledge => operation::ACKNOWLEDGE,
        };
        if op == CmMutationBeginOperation::Query {
            request.slot_count = self.grant as u32;
        } else {
            request.server_nonce = attempt.server.ok_or(STATUS_INVALID_PARAMETER)?;
            request.request_slot = attempt.identity.slot;
            request.request_generation = attempt.identity.sequence;
        }
        if op == CmMutationBeginOperation::Begin {
            request.expected_generation = attempt.expected_generation;
            request.semantic_journal_len = attempt.journal.len() as u32;
        } else if op == CmMutationBeginOperation::Acknowledge {
            request.mutation_token = attempt.mutation_token.ok_or(STATUS_INVALID_PARAMETER)?;
        }
        let mut bytes = [0; REQUEST_BYTES];
        bytes.copy_from_slice(request.as_bytes());
        attempt.epoch = epoch;
        attempt.inflight = Some(op);
        if op == CmMutationBeginOperation::Begin {
            attempt.submitted = true;
        }
        Ok(CmMutationBeginExchange {
            identity: attempt.identity,
            epoch,
            operation: op,
            live: true,
            bytes,
        })
    }

    /// Returned transport/protocol errors retain ownership and permit an exact retry. A lost
    /// ticket cannot call this method, so its in-flight epoch remains permanently reserved.
    pub fn complete_exchange<C>(
        &mut self,
        attempt: &mut CmMutationBeginAttempt<C>,
        exchange: &mut CmMutationBeginExchange,
        response: CmMutationBeginResponse,
    ) -> Result<(), i32> {
        self.validate(attempt)?;
        if !exchange.live
            || exchange.identity != attempt.identity
            || exchange.epoch != attempt.epoch
            || attempt.inflight != Some(exchange.operation)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        attempt.inflight = None;
        exchange.live = false;
        if response.reply.status != STATUS_SUCCESS {
            return Err(response.reply.status);
        }
        if response.reply.information as usize != REPLY_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let body = Reply::from_bytes(&response.bytes).ok_or(STATUS_INVALID_PARAMETER)?;
        if body.abi_size as usize != REPLY_BYTES
            || body.abi_version != CM_ABI_VERSION
            || body.mount != hive_mount::SYSTEM
            || body.reserved != 0
            || body.server_nonce == 0
            || body.requester_nonce != attempt.identity.requester
            || response.reply.detail0 != body.server_nonce
            || response.reply.detail1 != body.request_generation
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if exchange.operation == CmMutationBeginOperation::Query {
            if body.disposition != disposition::AUTHORITY
                || body.slot_count as usize != self.grant
                || body.request_slot != 0
                || body.request_generation != 0
                || body.outcome_status != 0
                || body.expected_generation != 0
                || body.mutation_token != 0
                || body.semantic_journal_len != 0
                || self
                    .server
                    .is_some_and(|server| server != body.server_nonce)
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            self.server = Some(body.server_nonce);
            attempt.server = self.server;
            return Ok(());
        }
        if Some(body.server_nonce) != attempt.server
            || body.request_slot != attempt.identity.slot
            || body.request_generation != attempt.identity.sequence
            || body.slot_count != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        match exchange.operation {
            CmMutationBeginOperation::Begin => {
                if body.disposition != disposition::OUTCOME
                    || body.outcome_status > STATUS_SUCCESS
                    || body.expected_generation != attempt.expected_generation
                    || body.semantic_journal_len as usize != attempt.journal.len()
                    || (body.outcome_status == STATUS_SUCCESS) != (body.mutation_token != 0)
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                attempt.outcome = Some(body.outcome_status);
                attempt.mutation_token = Some(body.mutation_token);
                Ok(())
            }
            CmMutationBeginOperation::Acknowledge => {
                if !matches!(
                    body.disposition,
                    disposition::ACKNOWLEDGED | disposition::ALREADY_ACKNOWLEDGED
                ) || body.outcome_status != 0
                    || body.expected_generation != 0
                    || body.semantic_journal_len != 0
                    || body.mutation_token != 0
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                attempt.acknowledged = true;
                Ok(())
            }
            CmMutationBeginOperation::Query => unreachable!(),
        }
    }

    /// Release only the BEGIN receipt slot, moving the still-live writer and caller together.
    pub fn take_upload<C>(
        &mut self,
        attempt: &mut CmMutationBeginAttempt<C>,
    ) -> Result<SystemHiveMutationUpload<C>, i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some()
            || !attempt.acknowledged
            || attempt.outcome != Some(STATUS_SUCCESS)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let server = attempt.server.ok_or(STATUS_INVALID_PARAMETER)?;
        let mutation_token = attempt
            .mutation_token
            .filter(|token| *token != 0)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let continuation = attempt
            .continuation
            .take()
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let journal = core::mem::take(&mut attempt.journal);
        self.slots[attempt.identity.slot as usize].active = false;
        attempt.released = true;
        Ok(SystemHiveMutationUpload {
            identity: attempt.identity,
            server,
            mutation_token,
            expected_generation: attempt.expected_generation,
            journal,
            continuation,
        })
    }

    pub fn take_failure<C>(
        &mut self,
        attempt: &mut CmMutationBeginAttempt<C>,
    ) -> Result<(i32, C), i32> {
        self.validate(attempt)?;
        if attempt.inflight.is_some() || !attempt.acknowledged || attempt.mutation_token != Some(0)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let status = attempt
            .outcome
            .filter(|status| *status != STATUS_SUCCESS)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let continuation = attempt
            .continuation
            .take()
            .ok_or(STATUS_INVALID_PARAMETER)?;
        self.slots[attempt.identity.slot as usize].active = false;
        attempt.released = true;
        Ok((status, continuation))
    }
}

#[cfg(test)]
mod tests;
