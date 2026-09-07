//! Exact root-slot inventory retained with a partially constructed thread's memory and holds.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    RawCnode,
    GuardedCnode,
    Tcb,
    SchedContext,
    /// Only a caller-owned root endpoint copy. Borrowed PML4/endpoint arguments are not inventory;
    /// their child CNode copies are destroyed with the final CNode capability.
    FaultEndpoint,
}

const ROLES: [Role; 5] = [
    Role::RawCnode,
    Role::GuardedCnode,
    Role::Tcb,
    Role::SchedContext,
    Role::FaultEndpoint,
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
/// No method allocates or invokes the backend, and Drop is not a cleanup operation.
#[derive(Debug)]
#[must_use = "retain construction slots with their thread memory and reservations"]
pub struct ThreadConstructionInventory {
    slots: [SlotState; 5],
}

impl ThreadConstructionInventory {
    pub const fn empty() -> Self {
        Self {
            slots: [SlotState::Absent; 5],
        }
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
            Role::FaultEndpoint,
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

    /// Receive an already-created owned cap (for example successful SC attachment or an owned
    /// badged root endpoint). Failed SC attachment remains with its separate unbound SC owner.
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
