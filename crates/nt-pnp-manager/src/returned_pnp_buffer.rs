//! Retained ownership of pool buffers returned by PnP QueryId/QueryDeviceText.
//!
//! Native adapters must prepare before driver entry and capture terminal allocation identity
//! under the authenticated physical allocator's lock, before packet/graph retirement or reentry.
//! Arena fields must come from the real provider/pool owner, not a logical caller or raw pointer.
//! Copied source identities are provenance, not an owning IRP pin. The adapter must retain its
//! existing source/device owners until capture succeeds, and fence free/unload using this catalog.
//! The target registration is also an observation, not a pin or proof of current liveness. Native
//! must validate the full live manager registration and non-delete-pending device before effects,
//! retaining source/device owners and an active IRP/projection retirement fence or registered
//! caller reference. A detached DeviceReference keeps the Device alive, not its projection.
//! Parent identity names the relation claim, not an unpublished child.
//! Expected allocator identity is independent of the PDO's projection domain. Cross-provider
//! returned storage requires an explicit authenticated ownership transfer, not a domain guess.
//! Source-graph child transfer is deliberately unsupported: refusal requires the adapter to keep
//! its original graph owner and refuse graph retirement, not retry with a different origin tag.
//! A native release may run once after begin_release; only its exact acknowledged result retires
//! the buffer. Neither a transport Reply nor this catalog's destruction frees physical storage.
//! The native owner must keep this catalog alive, without replacement, while any row is retained.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::source_irp_ledger::SourceIrpAllocation;
use nt_io_manager::{HostedDevicePointerRegistration, HostedDomainId, HostedDomainIdentity};

static NEXT_CATALOG: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalPoolArena {
    pub domain: HostedDomainIdentity,
    pub pml4: u64,
    pub pool_frame_base: u64,
    pub exec_pool_va: u64,
}

impl PhysicalPoolArena {
    fn valid(self) -> bool {
        valid_domain(self.domain)
            && self.pml4 != 0
            && self.pool_frame_base != 0
            && self.exec_pool_va != 0
            && self.exec_pool_va.checked_add(1).is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnedPnpQuery {
    QueryId { id_type: u32 },
    DeviceText { text_type: u32, locale_id: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReturnedPnpRequest {
    pub source_ticket: SourceIrpTicket,
    pub source: SourceIrpAllocation,
    pub source_arena: PhysicalPoolArena,
    pub expected_allocator: PhysicalPoolArena,
    pub parent_devnode: u64,
    pub parent_generation: u64,
    pub target: HostedDevicePointerRegistration,
    pub canonical_irp_id: u64,
    pub query: ReturnedPnpQuery,
}

impl ReturnedPnpRequest {
    fn valid(self) -> bool {
        valid_domain(self.source.domain)
            && self.source_ticket.domain == self.source.domain
            && valid_range(self.source.component_address, self.source.bytes)
            && self.source.pool_generation != 0
            && self.source.stack_count != 0
            && self.source_arena.valid()
            && self.source_arena.domain == self.source.domain
            && self.expected_allocator.valid()
            && self
                .source_arena
                .exec_pool_va
                .checked_add(self.source.bytes)
                .is_some()
            && self.parent_devnode != 0
            && self.parent_generation != 0
            && self.canonical_irp_id != 0
            && valid_domain(self.target.domain())
            && self.target.address() != 0
            && !self.target.device_id().is_null()
            && self.target.generation() != 0
    }
}

/// Trusted native graph classification, never a provider-supplied ownership claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferOrigin {
    IndependentPool,
    SourceGraphChild { source_ticket: SourceIrpTicket },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReturnedAllocation {
    pub arena: PhysicalPoolArena,
    pub pool: SourcePoolAllocationIdentity,
    pub origin: BufferOrigin,
}

impl ReturnedAllocation {
    fn valid(self) -> bool {
        self.arena.valid()
            && valid_range(self.pool.component_address, self.pool.capacity)
            && self.pool.pool_generation != 0
            && self
                .arena
                .exec_pool_va
                .checked_add(self.pool.capacity)
                .is_some()
    }
}

/// Only this catalog can issue a ticket; copying it does not create a second owning row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReturnedPnpBufferTicket {
    catalog: u64,
    serial: u64,
}

/// A single release intent, tied to the issuing catalog and exact retained allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseToken {
    ticket: ReturnedPnpBufferTicket,
    allocation: ReturnedAllocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferPhase {
    Prepared,
    Published,
    Releasing,
    TerminalNoBuffer { status: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferSnapshot {
    pub request: ReturnedPnpRequest,
    pub phase: BufferPhase,
    pub allocation: Option<ReturnedAllocation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    Published(ReturnedPnpBufferTicket),
    NoBuffer,
    Failed(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseResult {
    Acknowledged,
    Uncertain,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnedPnpBufferError {
    Exhausted,
    NoCapacity,
    InvalidRequest,
    AlreadyLive,
    ForeignTicket,
    NotFound,
    WrongIdentity,
    WrongPhase,
    NotTerminal,
    InvalidAllocation,
    ConflictingAllocation,
    RequiresSourceTransfer,
}

struct Row {
    ticket: ReturnedPnpBufferTicket,
    snapshot: BufferSnapshot,
}

/// No Clone implementation: local tickets and release tokens belong to one catalog incarnation.
pub struct ReturnedPnpBufferCatalog {
    identity: u64,
    next_serial: u64,
    rows: Vec<Row>,
}

impl ReturnedPnpBufferCatalog {
    pub fn new() -> Result<Self, ReturnedPnpBufferError> {
        let identity = NEXT_CATALOG
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| ReturnedPnpBufferError::Exhausted)?;
        Ok(Self {
            identity,
            next_serial: 1,
            rows: Vec::new(),
        })
    }

    /// The only allocation frontier. Call before any native driver entry or effect.
    pub fn prepare(
        &mut self,
        request: ReturnedPnpRequest,
    ) -> Result<ReturnedPnpBufferTicket, ReturnedPnpBufferError> {
        if !request.valid() {
            return Err(ReturnedPnpBufferError::InvalidRequest);
        }
        if self.rows.iter().any(|row| {
            row.snapshot.request == request
                || row.snapshot.request.source_ticket == request.source_ticket
                || row.snapshot.request.canonical_irp_id == request.canonical_irp_id
        }) {
            return Err(ReturnedPnpBufferError::AlreadyLive);
        }
        let next = self
            .next_serial
            .checked_add(1)
            .ok_or(ReturnedPnpBufferError::Exhausted)?;
        self.rows
            .try_reserve(1)
            .map_err(|_| ReturnedPnpBufferError::NoCapacity)?;
        let ticket = ReturnedPnpBufferTicket {
            catalog: self.identity,
            serial: self.next_serial,
        };
        self.rows.push(Row {
            ticket,
            snapshot: BufferSnapshot {
                request,
                phase: BufferPhase::Prepared,
                allocation: None,
            },
        });
        self.next_serial = next;
        Ok(ticket)
    }

    /// No allocation or native effects. Any rejection leaves the prepared owner unchanged.
    pub fn publish_terminal(
        &mut self,
        ticket: ReturnedPnpBufferTicket,
        request: ReturnedPnpRequest,
        status: u32,
        information: u64,
        allocation: Option<ReturnedAllocation>,
    ) -> Result<TerminalOutcome, ReturnedPnpBufferError> {
        let index = self.index(ticket)?;
        let before = self.rows[index].snapshot;
        if before.request != request {
            return Err(ReturnedPnpBufferError::WrongIdentity);
        }
        if before.phase != BufferPhase::Prepared {
            return Err(ReturnedPnpBufferError::WrongPhase);
        }
        if status == 0x103 {
            return Err(ReturnedPnpBufferError::NotTerminal);
        }
        if status & 0x80000000 != 0 {
            // An error Information field is not allocation authority, even if it looks valid.
            self.rows[index].snapshot.phase = BufferPhase::TerminalNoBuffer { status };
            return Ok(TerminalOutcome::Failed(status));
        }
        if information == 0 {
            if allocation.is_some() {
                return Err(ReturnedPnpBufferError::InvalidAllocation);
            }
            self.rows[index].snapshot.phase = BufferPhase::TerminalNoBuffer { status };
            return Ok(TerminalOutcome::NoBuffer);
        }
        let allocation = allocation.ok_or(ReturnedPnpBufferError::InvalidAllocation)?;
        if !allocation.valid()
            || allocation.arena != request.expected_allocator
            || information != allocation.pool.component_address
        {
            return Err(ReturnedPnpBufferError::InvalidAllocation);
        }
        if !matches!(allocation.origin, BufferOrigin::IndependentPool)
            || (allocation.arena == request.source_arena
                && overlaps(
                    allocation.pool.component_address,
                    allocation.pool.capacity,
                    request.source.component_address,
                    request.source.bytes,
                ))
        {
            return Err(ReturnedPnpBufferError::RequiresSourceTransfer);
        }
        if self.rows.iter().any(|row| {
            row.snapshot.allocation.is_some_and(|owned| {
                owned.arena == allocation.arena
                    && overlaps(
                        owned.pool.component_address,
                        owned.pool.capacity,
                        allocation.pool.component_address,
                        allocation.pool.capacity,
                    )
            })
        }) {
            return Err(ReturnedPnpBufferError::ConflictingAllocation);
        }
        self.rows[index].snapshot.allocation = Some(allocation);
        self.rows[index].snapshot.phase = BufferPhase::Published;
        Ok(TerminalOutcome::Published(ticket))
    }

    pub fn snapshot(
        &self,
        ticket: ReturnedPnpBufferTicket,
    ) -> Result<BufferSnapshot, ReturnedPnpBufferError> {
        Ok(self.rows[self.index(ticket)?].snapshot)
    }

    /// Publish the sole release intent before calling the native free broker.
    pub fn begin_release(
        &mut self,
        ticket: ReturnedPnpBufferTicket,
        allocation: ReturnedAllocation,
    ) -> Result<ReleaseToken, ReturnedPnpBufferError> {
        let index = self.index(ticket)?;
        let snapshot = &mut self.rows[index].snapshot;
        if snapshot.allocation != Some(allocation) {
            return Err(ReturnedPnpBufferError::WrongIdentity);
        }
        if snapshot.phase != BufferPhase::Published {
            return Err(ReturnedPnpBufferError::WrongPhase);
        }
        snapshot.phase = BufferPhase::Releasing;
        Ok(ReleaseToken { ticket, allocation })
    }

    /// Refused/uncertain outcomes retain the same intent; a late exact ACK is not a replay.
    pub fn observe_release(
        &mut self,
        token: ReleaseToken,
        result: ReleaseResult,
    ) -> Result<(), ReturnedPnpBufferError> {
        let index = self.index(token.ticket)?;
        let snapshot = self.rows[index].snapshot;
        if snapshot.allocation != Some(token.allocation) {
            return Err(ReturnedPnpBufferError::WrongIdentity);
        }
        if snapshot.phase != BufferPhase::Releasing {
            return Err(ReturnedPnpBufferError::WrongPhase);
        }
        if result == ReleaseResult::Acknowledged {
            self.rows.swap_remove(index);
        }
        Ok(())
    }

    /// Retire a consumed NULL/error terminal. This never issues native pool-free authority.
    pub fn retire_no_buffer(
        &mut self,
        ticket: ReturnedPnpBufferTicket,
    ) -> Result<(), ReturnedPnpBufferError> {
        let index = self.index(ticket)?;
        if !matches!(
            self.rows[index].snapshot.phase,
            BufferPhase::TerminalNoBuffer { .. }
        ) {
            return Err(ReturnedPnpBufferError::WrongPhase);
        }
        self.rows.swap_remove(index);
        Ok(())
    }

    pub fn blocks_pool_free(&self, arena: PhysicalPoolArena, address: u64) -> bool {
        self.rows.iter().any(|row| {
            row.snapshot.allocation.is_some_and(|owned| {
                owned.arena == arena
                    && address >= owned.pool.component_address
                    && address < owned.pool.component_address + owned.pool.capacity
            })
        })
    }

    pub fn blocks_arena_teardown(&self, arena: PhysicalPoolArena) -> bool {
        self.rows.iter().any(|row| {
            if let Some(allocation) = row.snapshot.allocation {
                allocation.arena == arena
            } else {
                row.snapshot.request.source_arena == arena
                    || row.snapshot.request.expected_allocator == arena
            }
        })
    }

    fn index(&self, ticket: ReturnedPnpBufferTicket) -> Result<usize, ReturnedPnpBufferError> {
        if ticket.catalog != self.identity {
            return Err(ReturnedPnpBufferError::ForeignTicket);
        }
        self.rows
            .iter()
            .position(|row| row.ticket == ticket)
            .ok_or(ReturnedPnpBufferError::NotFound)
    }
}

fn valid_domain(domain: HostedDomainIdentity) -> bool {
    domain.domain_id != HostedDomainId::NULL && domain.cookie != 0
}

fn valid_range(base: u64, bytes: u64) -> bool {
    base != 0 && bytes != 0 && base.checked_add(bytes).is_some()
}

fn overlaps(first: u64, first_bytes: u64, second: u64, second_bytes: u64) -> bool {
    // Both ranges are validated before becoming owned catalog state.
    first < second + second_bytes && second < first + first_bytes
}
