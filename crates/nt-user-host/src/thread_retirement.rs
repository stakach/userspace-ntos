//! Sealed mechanism retirement for an exact pending thread construction.
use crate::thread_construction::{Role, SlotState, ThreadConstructionInventory};
use crate::thread_rollback::{
    ThreadRollbackId, ThreadRollbackResource, ThreadRollbackResourceKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Suspend,
    Delete,
    Recycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementError {
    StaleOwner,
    NotConstruction,
    Backend {
        role: Role,
        operation: Operation,
        status: u32,
    },
}

pub trait ThreadRetirementIo {
    /// Match the exact protected attempt and its held reservations. Before driving retirement,
    /// the adapter must retain complete memory/external-alias journals and access exclusions.
    /// Backend methods must not reenter this owner or release its memory/reservations.
    fn is_current(&self, id: ThreadRollbackId) -> bool;
    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32>;
    /// Checked deletion only. Do not publish the root slot to an allocator here.
    fn delete_cap(&mut self, role: Role, cap: u64) -> Result<(), u32>;
    /// Checked empty-slot publication. Failure retains the slot. Before publication, clear any
    /// mutable native release references; immutable attribution must never authorize reuse/delete.
    fn recycle_slot(&mut self, role: Role, slot: u64) -> Result<(), u32>;
}

/// Consumes constructor mutation authority. Only this actor may suspend/delete/recycle these
/// slots; neither the inventory nor a completion token can be extracted or replaced.
#[derive(Debug)]
#[must_use = "retain sealed retirement with its pending thread memory and reservations"]
pub struct ThreadConstructionRetirement {
    id: ThreadRollbackId,
    inventory: ThreadConstructionInventory,
    original_slots: [Option<u64>; 4],
    suspended: bool,
}

impl ThreadConstructionRetirement {
    pub(crate) fn retain(id: ThreadRollbackId, inventory: ThreadConstructionInventory) -> Self {
        let mut original_slots = [None; 4];
        for (role, state) in inventory.entries() {
            original_slots[role as usize] = state.slot();
        }
        Self {
            id,
            inventory,
            original_slots,
            suspended: false,
        }
    }

    pub fn inventory(&self) -> &ThreadConstructionInventory {
        &self.inventory
    }

    pub fn is_complete(&self) -> bool {
        self.inventory.is_empty()
    }

    /// Retired numeric slots may already have new owners. Never admit their replay through a
    /// subsequent memory journal, even after this inventory has become empty.
    pub(crate) fn conflicts(&self, resources: &[ThreadRollbackResource]) -> bool {
        resources.iter().any(|resource| {
            resource.cap != 0
                && (resource.kind == ThreadRollbackResourceKind::Mechanism
                    || self.original_slots.contains(&Some(resource.cap)))
        })
    }

    pub(crate) fn advance(
        &mut self,
        io: &mut impl ThreadRetirementIo,
    ) -> Result<(), RetirementError> {
        if !io.is_current(self.id) {
            return Err(RetirementError::StaleOwner);
        }
        while let Some((role, state)) = self.inventory.next_retirement() {
            let slot = state.slot().expect("selected retained slot");
            if let SlotState::LiveObject(_) = state {
                if role == Role::Tcb && !self.suspended {
                    io.suspend_tcb(slot)
                        .map_err(|status| RetirementError::Backend {
                            role,
                            operation: Operation::Suspend,
                            status,
                        })?;
                    self.suspended = true;
                }
                io.delete_cap(role, slot)
                    .map_err(|status| RetirementError::Backend {
                        role,
                        operation: Operation::Delete,
                        status,
                    })?;
                self.inventory
                    .acknowledge_delete(role, slot)
                    .expect("exclusive sealed retirement acknowledged its selected live slot");
            }
            io.recycle_slot(role, slot)
                .map_err(|status| RetirementError::Backend {
                    role,
                    operation: Operation::Recycle,
                    status,
                })?;
            self.inventory
                .acknowledge_recycle(role, slot)
                .expect("exclusive sealed retirement acknowledged its selected empty slot");
        }
        Ok(())
    }
}
