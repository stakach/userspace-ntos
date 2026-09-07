//! Exact root-slot inventory retained with a partially constructed thread's memory and holds.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    RawCnode,
    GuardedCnode,
    Tcb,
    SchedContext,
}

const ROLES: [Role; 4] = [
    Role::RawCnode,
    Role::GuardedCnode,
    Role::Tcb,
    Role::SchedContext,
];

/// A read-only description, not release authority. Acknowledged deletion still owns the empty
/// allocator slot until checked free-list publication succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Absent,
    AllocatedEmpty(u64),
    LiveObject(u64),
    DeleteAcknowledged(u64),
}

impl SlotState {
    pub fn slot(self) -> Option<u64> {
        match self {
            Self::Absent => None,
            Self::AllocatedEmpty(slot)
            | Self::LiveObject(slot)
            | Self::DeleteAcknowledged(slot) => Some(slot),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryError {
    InvalidSlot,
    Occupied,
    DuplicateSlot,
    StaleSlot,
    InvalidPhase,
    OutOfOrder,
}

/// Non-cloneable ownership. Keep this inside the original publication row together with the
/// partial memory bundle and process/pool/window reservations before driving any cleanup. It must
/// not live in an independent retirement queue: TCB references do not keep backing memory alive.
/// Borrowed PML4/endpoint sources are not inventory; their child copies belong to the CNode.
/// No method allocates or invokes the backend, and Drop is not a cleanup operation.
#[derive(Debug)]
#[must_use = "retain construction slots with their thread memory and reservations"]
pub struct ThreadConstructionInventory {
    slots: [SlotState; 4],
}

/// Constructor publication coverage must survive failure even if registry rows subsequently
/// disappear. Stop on the first failed allocation/copy, retaining its empty root slot separately
/// from live frame caps. This state moves with the memory bundle, never independently.
#[derive(Debug)]
pub struct MemoryConstructionProgress<const STACK: usize> {
    empty_slot: Option<FailedMemorySlot>,
    stack_registered: [bool; STACK],
    teb_registered: [bool; 2],
    protected_tail_registered: bool,
}

/// Exclusive allocated-empty slot from a failed memory retype or copy. No object was created.
/// Only handoff to the sealed pending actor transfers release authority; Drop does not recycle.
#[derive(Debug)]
#[must_use = "retain the failed memory slot until checked recycling"]
pub struct FailedMemorySlot {
    slot: u64,
}

impl FailedMemorySlot {
    pub(crate) fn slot(&self) -> u64 {
        self.slot
    }
}

/// Immutable constructor provenance, not slot ownership or release authority.
#[derive(Debug)]
pub struct MemoryConstructionCoverage<const STACK: usize> {
    empty_slot: Option<u64>,
    stack_registered: [bool; STACK],
    teb_registered: [bool; 2],
    protected_tail_registered: bool,
}

impl<const STACK: usize> MemoryConstructionCoverage<STACK> {
    pub const fn empty() -> Self {
        Self {
            empty_slot: None,
            stack_registered: [false; STACK],
            teb_registered: [false; 2],
            protected_tail_registered: false,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.empty_slot.is_none()
            && !self.stack_registered.iter().any(|&v| v)
            && !self.teb_registered.iter().any(|&v| v)
            && !self.protected_tail_registered
    }
    /// Original slot number only; checked recycling never changes this provenance.
    pub fn empty_slot(&self) -> Option<u64> {
        self.empty_slot
    }
    pub fn stack_registered(&self, index: usize) -> bool {
        self.stack_registered[index]
    }
    pub fn teb_registered(&self, index: usize) -> bool {
        self.teb_registered[index]
    }
    pub fn protected_tail_registered(&self) -> bool {
        self.protected_tail_registered
    }
}

impl<const STACK: usize> MemoryConstructionProgress<STACK> {
    pub const fn empty() -> Self {
        Self {
            empty_slot: None,
            stack_registered: [false; STACK],
            teb_registered: [false; 2],
            protected_tail_registered: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.empty_slot.is_none()
            && !self.stack_registered.iter().any(|&registered| registered)
            && !self.teb_registered.iter().any(|&registered| registered)
            && !self.protected_tail_registered
    }

    pub fn retain_empty_slot(&mut self, slot: u64) -> Result<(), InventoryError> {
        if slot <= 1 {
            return Err(InventoryError::InvalidSlot);
        }
        if self.empty_slot.is_some() {
            return Err(InventoryError::Occupied);
        }
        self.empty_slot = Some(FailedMemorySlot { slot });
        Ok(())
    }

    pub fn empty_slot(&self) -> Option<u64> {
        self.empty_slot.as_ref().map(FailedMemorySlot::slot)
    }

    /// Allocation-free separation of immutable provenance from sole recycling authority.
    pub fn into_retained(self) -> (MemoryConstructionCoverage<STACK>, Option<FailedMemorySlot>) {
        let coverage = MemoryConstructionCoverage {
            empty_slot: self.empty_slot(),
            stack_registered: self.stack_registered,
            teb_registered: self.teb_registered,
            protected_tail_registered: self.protected_tail_registered,
        };
        (coverage, self.empty_slot)
    }

    /// Reject contradictory slot ownership before consuming a constructor's publication ticket.
    /// Registry-only/external aliases are reconciled separately before any backend cleanup.
    pub fn validate_failed_slot(
        &self,
        inventory: &ThreadConstructionInventory,
        resources: &crate::thread_resources::ThreadMemoryResources<STACK>,
    ) -> Result<(), crate::thread_rollback::ThreadRollbackError> {
        let Some(slot) = self.empty_slot() else {
            return Ok(());
        };
        if resources.has_unlocated_capabilities() {
            return Err(crate::thread_rollback::ThreadRollbackError::InvalidIdentity);
        }
        if inventory
            .entries()
            .any(|(_, state)| state.slot() == Some(slot))
            || resources
                .backing_pages()
                .any(|(_, owner, aliases)| owner == slot || aliases.contains(&slot))
        {
            return Err(crate::thread_rollback::ThreadRollbackError::ConflictingOwnership);
        }
        Ok(())
    }

    pub fn record_stack(&mut self, index: usize) {
        assert!(!self.stack_registered[index]);
        self.stack_registered[index] = true;
    }

    pub fn record_teb(&mut self, index: usize) {
        assert!(!self.teb_registered[index]);
        self.teb_registered[index] = true;
    }

    pub fn stack_registered(&self, index: usize) -> bool {
        self.stack_registered[index]
    }
    pub fn teb_registered(&self, index: usize) -> bool {
        self.teb_registered[index]
    }

    /// Records successful metadata registration, not exclusive ownership of a shared VA entry.
    pub fn record_protected_tail(&mut self) {
        self.protected_tail_registered = true;
    }
    pub fn protected_tail_registered(&self) -> bool {
        self.protected_tail_registered
    }
}

impl ThreadConstructionInventory {
    pub const fn empty() -> Self {
        Self {
            slots: [SlotState::Absent; 4],
        }
    }

    /// Transfer fully constructed mechanism ownership to the published runtime representation.
    /// Incomplete/deleted inventories are returned intact; this is never a rollback operation.
    pub fn into_live_slots(self) -> Result<[u64; 4], Self> {
        let mut caps = [0; 4];
        for (index, state) in self.slots.iter().enumerate() {
            let SlotState::LiveObject(cap) = *state else {
                return Err(self);
            };
            caps[index] = cap;
        }
        Ok(caps)
    }

    pub fn state(&self, role: Role) -> SlotState {
        self.slots[role as usize]
    }
    pub fn entries(&self) -> impl Iterator<Item = (Role, SlotState)> + '_ {
        ROLES.into_iter().map(|role| (role, self.state(role)))
    }
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(|slot| *slot == SlotState::Absent)
    }

    /// Allocated-but-unretyped TCB slots must never be supplied to TCB backend operations.
    pub fn live_tcb(&self) -> Option<u64> {
        match self.state(Role::Tcb) {
            SlotState::LiveObject(cap) => Some(cap),
            _ => None,
        }
    }

    /// No CNode, endpoint, SC or frame cleanup may begin while a TCB object remains. After TCB
    /// deletion, its slot may still await recycling, but it can no longer reference that memory.
    pub fn tcb_deleted_or_absent(&self) -> bool {
        self.live_tcb().is_none()
    }

    /// Required mechanism retirement order. Suspend any potentially runnable TCB first. Its
    /// checked deletion precedes CNodes and bound SCs; guarded CNode precedes its raw alias.
    pub fn next_retirement(&self) -> Option<(Role, SlotState)> {
        [
            Role::Tcb,
            Role::GuardedCnode,
            Role::RawCnode,
            Role::SchedContext,
        ]
        .into_iter()
        .find_map(|role| {
            let state = self.state(role);
            (state != SlotState::Absent).then_some((role, state))
        })
    }

    pub fn adopt_empty(&mut self, role: Role, slot: u64) -> Result<(), InventoryError> {
        self.adopt(role, slot, SlotState::AllocatedEmpty(slot))
    }

    /// Check exact role/slot and retirement order BEFORE invoking the backend. The caller must
    /// retain exclusive access until acknowledgement; acknowledgement alone is too late to guard
    /// an unsafe out-of-order syscall. Returned state selects deletion versus empty-slot recycling.
    pub fn validate_retirement(&self, role: Role, slot: u64) -> Result<SlotState, InventoryError> {
        let state = self.state(role);
        if state.slot() != Some(slot) {
            return Err(InventoryError::StaleSlot);
        }
        if self.next_retirement() != Some((role, state)) {
            return Err(InventoryError::OutOfOrder);
        }
        Ok(state)
    }

    /// Receive an already-created owned cap, such as a successful SC attachment. Failed SC
    /// attachment remains with its separate unbound SC owner.
    pub fn adopt_object(&mut self, role: Role, cap: u64) -> Result<(), InventoryError> {
        self.adopt(role, cap, SlotState::LiveObject(cap))
    }

    fn adopt(&mut self, role: Role, slot: u64, state: SlotState) -> Result<(), InventoryError> {
        if slot <= 1 {
            return Err(InventoryError::InvalidSlot);
        }
        if self.state(role) != SlotState::Absent {
            return Err(InventoryError::Occupied);
        }
        if self.slots.iter().any(|entry| entry.slot() == Some(slot)) {
            return Err(InventoryError::DuplicateSlot);
        }
        self.slots[role as usize] = state;
        Ok(())
    }

    /// Invoke only after successful retype/mint. Rejection leaves the original owner unchanged.
    pub fn acknowledge_object(&mut self, role: Role, slot: u64) -> Result<(), InventoryError> {
        self.transition(
            role,
            slot,
            SlotState::AllocatedEmpty(slot),
            SlotState::LiveObject(slot),
        )
    }

    /// Invoke only after checked deletion. Recycling failure must not replay that deletion.
    pub fn acknowledge_delete(&mut self, role: Role, slot: u64) -> Result<(), InventoryError> {
        self.validate_retirement(role, slot)?;
        self.transition(
            role,
            slot,
            SlotState::LiveObject(slot),
            SlotState::DeleteAcknowledged(slot),
        )
    }

    /// Invoke only after successful empty-slot publication. A live object can never be recycled.
    pub fn acknowledge_recycle(&mut self, role: Role, slot: u64) -> Result<(), InventoryError> {
        let state = self.validate_retirement(role, slot)?;
        if !matches!(
            state,
            SlotState::AllocatedEmpty(_) | SlotState::DeleteAcknowledged(_)
        ) {
            return Err(InventoryError::InvalidPhase);
        }
        self.slots[role as usize] = SlotState::Absent;
        Ok(())
    }

    fn transition(
        &mut self,
        role: Role,
        slot: u64,
        from: SlotState,
        to: SlotState,
    ) -> Result<(), InventoryError> {
        let state = self.state(role);
        if state.slot() != Some(slot) {
            return Err(InventoryError::StaleSlot);
        }
        if state != from {
            return Err(InventoryError::InvalidPhase);
        }
        self.slots[role as usize] = to;
        Ok(())
    }
}

#[cfg(test)]
#[path = "thread_construction_tests.rs"]
mod tests;
