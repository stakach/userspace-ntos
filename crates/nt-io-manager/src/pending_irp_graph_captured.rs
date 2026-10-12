//! Immutable allocation identities and terminal handoff bookkeeping for one IRP graph.
//!
//! This is not an allocator authority, a source pin, or a native completion receipt. The
//! adapter must authenticate the source arena and every allocation, exclude other owners,
//! and retain actual resources separately. In particular, an independently allocated reclaim
//! buffer requires real adoption admission; merely finding live pool storage is insufficient.
//! All addresses here are interpreted in that one authenticated physical source arena.
//!
//! The same non-Copy graph moves through preparation, entered handoff and settlement. Before
//! entry it can be recovered unchanged. After entry, uncertainty must retain the entered value;
//! it cannot be aborted or prepared again. Settlement confirms only the adapter's acknowledged
//! handoff bookkeeping, not a physical free. Initial identities remain unchanged in every state.

use super::{GraphReleaseKind, PendingIrpAllocationGraph, PendingIrpGraphPointers};
use crate::source_irp_auxiliary::SourcePoolAllocationIdentity;
use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity};

const INITIAL_CAPACITY: usize = 10;
const TERMINAL_CAPACITY: usize = INITIAL_CAPACITY + 1;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GraphRoles: u16 {
        const MDL = 1 << 0;
        const AUX_DATA = 1 << 1;
        const DATA = 1 << 2;
        const CREATE_PARAMETERS = 1 << 3;
        const CREATE_ACCESS_STATE = 1 << 4;
        const CREATE_SECURITY_CONTEXT = 1 << 5;
        const PNP_RESOURCE_LIST = 1 << 6;
        const IRP = 1 << 7;
        const FILE_OBJECT = 1 << 8;
        const FILE_NAME = 1 << 9;
        const RECLAIM = 1 << 10;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturedMember {
    pub allocation: SourcePoolAllocationIdentity,
    pub roles: GraphRoles,
}

const EMPTY: CapturedMember = CapturedMember {
    allocation: SourcePoolAllocationIdentity {
        component_address: 0,
        capacity: 0,
        pool_generation: 0,
    },
    roles: GraphRoles::empty(),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    InvalidAllocation,
    Overlap,
    MissingAllocation,
    UnexpectedAllocation,
    SourceMismatch,
    BorrowedFileName,
    PrematureReclaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalError {
    InvalidAllocation,
    ChangedAllocation,
    Overlap,
    WrongTransfer,
    StructuralAlias,
    ConflictingDisposition,
}

/// Copy observations only; these fields do not transfer a native allocation by themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalChanges {
    pub reclaim: Option<SourcePoolAllocationIdentity>,
    pub transfer_data: Option<SourcePoolAllocationIdentity>,
}

#[derive(Debug)]
#[must_use = "retain the prepared inventory until source registration is bound or abandoned before effects"]
pub struct PreparedInventory {
    source: SourceIrpAllocation,
    initial: [CapturedMember; INITIAL_CAPACITY],
    len: usize,
}

impl PreparedInventory {
    /// Capture constructor-owned allocations before entering the provider.
    ///
    /// `file_name` is the original owned File name buffer, captured alongside the File,
    /// never a later reread of driver-mutable FILE_OBJECT fields. A registered File belongs
    /// to its independent File owner and must be excluded with `owns_file == false`.
    /// The supplied identities contain each unique allocation exactly once.
    pub fn prepare(
        source: SourceIrpAllocation,
        pointers: PendingIrpGraphPointers,
        file_name: u64,
        allocations: &[SourcePoolAllocationIdentity],
    ) -> Result<Self, CaptureError> {
        if pointers.reclaim != 0 {
            return Err(CaptureError::PrematureReclaim);
        }
        if file_name != 0 && !pointers.owns_file {
            return Err(CaptureError::BorrowedFileName);
        }
        if !source.valid()
            || pointers.irp != source.component_address
            || pointers.owns_file && pointers.file_object == 0
        {
            return Err(CaptureError::SourceMismatch);
        }
        if allocations.len() > INITIAL_CAPACITY {
            return Err(CaptureError::UnexpectedAllocation);
        }
        for (index, allocation) in allocations.iter().copied().enumerate() {
            if !valid(allocation) {
                return Err(CaptureError::InvalidAllocation);
            }
            if allocations[..index]
                .iter()
                .copied()
                .any(|previous| overlaps(previous, allocation))
            {
                return Err(CaptureError::Overlap);
            }
        }

        let mut graph = Self {
            source,
            initial: [EMPTY; INITIAL_CAPACITY],
            len: 0,
        };
        for candidate in PendingIrpAllocationGraph::new(pointers).allocations() {
            if candidate.release_kind == GraphReleaseKind::FileStorage && file_name != 0 {
                graph.capture_member(file_name, GraphRoles::FILE_NAME, allocations)?;
            }
            graph.capture_member(
                candidate.pointer,
                roles_for(pointers, candidate.pointer),
                allocations,
            )?;
        }
        if graph.len != allocations.len() {
            return Err(CaptureError::UnexpectedAllocation);
        }
        let packet = graph
            .initial_members()
            .iter()
            .find(|member| member.roles.contains(GraphRoles::IRP))
            .ok_or(CaptureError::SourceMismatch)?;
        if packet.allocation.pool_generation != source.pool_generation
            || packet.allocation.capacity < source.bytes
        {
            return Err(CaptureError::SourceMismatch);
        }
        Ok(graph)
    }

    fn capture_member(
        &mut self,
        address: u64,
        roles: GraphRoles,
        allocations: &[SourcePoolAllocationIdentity],
    ) -> Result<(), CaptureError> {
        if let Some(member) = self.initial[..self.len]
            .iter_mut()
            .find(|member| member.allocation.component_address == address)
        {
            member.roles |= roles;
            return Ok(());
        }
        let allocation = allocations
            .iter()
            .copied()
            .find(|allocation| allocation.component_address == address)
            .ok_or(CaptureError::MissingAllocation)?;
        let slot = self
            .initial
            .get_mut(self.len)
            .ok_or(CaptureError::UnexpectedAllocation)?;
        *slot = CapturedMember { allocation, roles };
        self.len += 1;
        Ok(())
    }

    pub fn source_allocation(&self) -> SourceIrpAllocation {
        self.source
    }

    pub fn initial_members(&self) -> &[CapturedMember] {
        &self.initial[..self.len]
    }

    /// Attach the actual registration after ticket-independent preparation. This performs
    /// no allocation or physical effect. A mismatch returns the original inventory and the
    /// supplied registration observation; it does not cancel or retire that registration.
    pub fn bind(self, source: SourceIrpForwardIdentity) -> Result<CapturedGraph, BindRejection> {
        if source.allocation() != self.source {
            return Err(BindRejection {
                inventory: self,
                source,
            });
        }
        Ok(CapturedGraph {
            source,
            initial: self.initial,
            len: self.len,
        })
    }
}

#[derive(Debug)]
#[must_use = "retain the rejected inventory and independently retain the actual source registration"]
pub struct BindRejection {
    inventory: PreparedInventory,
    source: SourceIrpForwardIdentity,
}

impl BindRejection {
    pub fn source(&self) -> SourceIrpForwardIdentity {
        self.source
    }

    pub fn into_inventory(self) -> PreparedInventory {
        self.inventory
    }
}

#[derive(Debug)]
#[must_use = "retain the captured graph until its allocation bookkeeping is settled"]
pub struct CapturedGraph {
    source: SourceIrpForwardIdentity,
    initial: [CapturedMember; INITIAL_CAPACITY],
    len: usize,
}

impl CapturedGraph {
    /// Convenience for an already registered source; native pre-entry construction should
    /// use `PreparedInventory::prepare` before registering, then bind the actual result.
    pub fn capture(
        source: SourceIrpForwardIdentity,
        pointers: PendingIrpGraphPointers,
        file_name: u64,
        allocations: &[SourcePoolAllocationIdentity],
    ) -> Result<Self, CaptureError> {
        PreparedInventory::prepare(source.allocation(), pointers, file_name, allocations)?
            .bind(source)
            .map_err(|_| CaptureError::SourceMismatch)
    }

    pub fn source(&self) -> SourceIrpForwardIdentity {
        self.source
    }

    pub fn initial_members(&self) -> &[CapturedMember] {
        &self.initial[..self.len]
    }

    /// Validate all changes without modifying the immutable initial capture.
    ///
    /// A refusal returns this same graph and the proposed metadata. The native caller must
    /// retain any corresponding external ownership; these copied identities cannot release it.
    pub fn prepare_terminal(
        self,
        changes: TerminalChanges,
    ) -> Result<PreparedTerminal, TerminalRejection> {
        if let Err(error) = self.validate_terminal(changes) {
            return Err(TerminalRejection {
                graph: self,
                changes,
                error,
            });
        }
        Ok(PreparedTerminal {
            graph: self,
            changes,
        })
    }

    fn validate_terminal(&self, changes: TerminalChanges) -> Result<(), TerminalError> {
        let buffer_roles = GraphRoles::DATA | GraphRoles::AUX_DATA;
        if let Some(reclaim) = changes.reclaim {
            if !valid(reclaim) {
                return Err(TerminalError::InvalidAllocation);
            }
            for member in self.initial_members() {
                if member.allocation.component_address == reclaim.component_address {
                    if member.allocation != reclaim {
                        return Err(TerminalError::ChangedAllocation);
                    }
                    if !buffer_roles.contains(member.roles) {
                        return Err(TerminalError::StructuralAlias);
                    }
                } else if overlaps(member.allocation, reclaim) {
                    return Err(TerminalError::Overlap);
                }
            }
        }
        if let Some(transfer) = changes.transfer_data {
            let member = self
                .initial_members()
                .iter()
                .find(|member| member.allocation == transfer)
                .ok_or(TerminalError::WrongTransfer)?;
            if !member.roles.contains(GraphRoles::DATA) {
                return Err(TerminalError::WrongTransfer);
            }
            if !buffer_roles.contains(member.roles) {
                return Err(TerminalError::StructuralAlias);
            }
            if changes.reclaim == Some(transfer) {
                return Err(TerminalError::ConflictingDisposition);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
#[must_use = "a rejected transition retains the original graph; recover it explicitly"]
pub struct TerminalRejection {
    graph: CapturedGraph,
    changes: TerminalChanges,
    error: TerminalError,
}

impl TerminalRejection {
    pub fn error(&self) -> TerminalError {
        self.error
    }

    pub fn changes(&self) -> TerminalChanges {
        self.changes
    }

    pub fn into_graph(self) -> CapturedGraph {
        self.graph
    }
}

#[derive(Debug)]
#[must_use = "either abort this preparation or retain its entered transition"]
pub struct PreparedTerminal {
    graph: CapturedGraph,
    changes: TerminalChanges,
}

impl PreparedTerminal {
    pub fn abort(self) -> CapturedGraph {
        self.graph
    }

    /// Enter before any adoption/transfer effect. Uncertainty must retain the returned owner.
    pub fn enter(self) -> EnteredTerminal {
        EnteredTerminal {
            graph: self.graph,
            changes: self.changes,
        }
    }
}

#[derive(Debug)]
#[must_use = "retain entered bookkeeping across uncertain effects; do not discard or replay it"]
pub struct EnteredTerminal {
    graph: CapturedGraph,
    changes: TerminalChanges,
}

impl EnteredTerminal {
    pub fn source(&self) -> SourceIrpForwardIdentity {
        self.graph.source()
    }

    pub fn initial_members(&self) -> &[CapturedMember] {
        self.graph.initial_members()
    }

    pub fn changes(&self) -> TerminalChanges {
        self.changes
    }

    /// Confirm handoff bookkeeping only after the adapter has acknowledged every requested
    /// adoption/transfer. This consumes the entered state and cannot be replayed through it.
    /// It performs no native release and supplies no allocator or destination-owner authority.
    pub fn settle(self) -> SettledGraph {
        let mut retained = [EMPTY; TERMINAL_CAPACITY];
        let mut retained_len = 0;
        let mut transferred = [EMPTY; 1];
        let mut transferred_len = 0;
        if let Some(reclaim) = self.changes.reclaim {
            let initial_roles = self
                .initial_members()
                .iter()
                .find(|member| member.allocation == reclaim)
                .map_or(GraphRoles::empty(), |member| member.roles);
            retained[retained_len] = CapturedMember {
                allocation: reclaim,
                roles: initial_roles | GraphRoles::RECLAIM,
            };
            retained_len += 1;
        }
        for member in self.initial_members() {
            if self.changes.transfer_data == Some(member.allocation) {
                transferred[transferred_len] = *member;
                transferred_len += 1;
            } else if self.changes.reclaim != Some(member.allocation) {
                retained[retained_len] = *member;
                retained_len += 1;
            }
        }
        SettledGraph {
            graph: self.graph,
            retained,
            retained_len,
            transferred,
            transferred_len,
        }
    }
}

/// Settled metadata, not a native free acknowledgement or permission to free these addresses.
#[derive(Debug)]
#[must_use = "settled bookkeeping is not a physical free acknowledgement; retain it for retirement"]
pub struct SettledGraph {
    graph: CapturedGraph,
    retained: [CapturedMember; TERMINAL_CAPACITY],
    retained_len: usize,
    transferred: [CapturedMember; 1],
    transferred_len: usize,
}

impl SettledGraph {
    pub fn source(&self) -> SourceIrpForwardIdentity {
        self.graph.source()
    }

    pub fn initial_members(&self) -> &[CapturedMember] {
        self.graph.initial_members()
    }

    pub fn retained_members(&self) -> &[CapturedMember] {
        &self.retained[..self.retained_len]
    }

    pub fn transferred_members(&self) -> &[CapturedMember] {
        &self.transferred[..self.transferred_len]
    }
}

fn valid(allocation: SourcePoolAllocationIdentity) -> bool {
    allocation.component_address != 0
        && allocation.capacity != 0
        && allocation.pool_generation != 0
        && allocation
            .component_address
            .checked_add(allocation.capacity)
            .is_some()
}

fn overlaps(left: SourcePoolAllocationIdentity, right: SourcePoolAllocationIdentity) -> bool {
    left.component_address < right.component_address + right.capacity
        && right.component_address < left.component_address + left.capacity
}

fn roles_for(pointers: PendingIrpGraphPointers, address: u64) -> GraphRoles {
    let mut roles = GraphRoles::empty();
    for (candidate, role) in [
        (pointers.mdl, GraphRoles::MDL),
        (pointers.aux_data, GraphRoles::AUX_DATA),
        (pointers.data, GraphRoles::DATA),
        (pointers.create_parameters, GraphRoles::CREATE_PARAMETERS),
        (
            pointers.create_access_state,
            GraphRoles::CREATE_ACCESS_STATE,
        ),
        (
            pointers.create_security_context,
            GraphRoles::CREATE_SECURITY_CONTEXT,
        ),
        (pointers.pnp_resource_list, GraphRoles::PNP_RESOURCE_LIST),
        (pointers.irp, GraphRoles::IRP),
    ] {
        if candidate == address {
            roles |= role;
        }
    }
    if pointers.owns_file && pointers.file_object == address {
        roles |= GraphRoles::FILE_OBJECT;
    }
    roles
}

#[cfg(test)]
#[path = "pending_irp_graph_capture_tests.rs"]
mod tests;
