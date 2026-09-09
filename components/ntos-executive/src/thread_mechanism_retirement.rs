//! Checked mechanism operations for an exclusively borrowed pending thread owner.
use super::*;
use nt_user_host::thread_construction::Role;
use nt_user_host::thread_retirement::{RetirementError, ThreadRetirementIo};
use nt_user_host::thread_rollback::ThreadRollbackId;
use nt_user_host::thread_slot::{SlotError, ThreadRuntimeSlot};

#[derive(Clone, Copy)]
pub(crate) enum Provenance {
    Construction,
    Registered,
}

/// # Safety
/// Root has revalidated the exact pending process/reservations and completed registry/external
/// alias reconciliation before entry. The exclusive slot borrow and synchronous operations must
/// outlive every invocation; no component IPC may reenter the runtime table. Memory and target
/// reservations remain owned by the pending row even after all mechanisms have been retired.
/// Registered retirement additionally requires completed lifecycle prerequisites and an exact
/// registered mechanism handoff; it cannot borrow construction provenance to bypass admission.
pub(crate) unsafe fn advance(
    slot: &mut ThreadRuntimeSlot<HostedThreadRuntimeOwner>,
    id: ThreadRollbackId,
    provenance: Provenance,
) -> Result<(), u32> {
    let mut io = Io { id };
    let result = match provenance {
        Provenance::Construction => slot.advance_construction_retirement(id, &mut io),
        Provenance::Registered => slot.advance_registered_mechanism_retirement(id, &mut io),
    };
    result.map_err(|error| match error {
        SlotError::Retirement(
            RetirementError::Backend { status, .. } | RetirementError::MemoryRecycle { status },
        ) => status,
        _ => nt_address_space::STATUS_INVALID_PARAMETER,
    })
}

struct Io {
    id: ThreadRollbackId,
}

impl ThreadRetirementIo for Io {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        self.id == id
    }

    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        status(unsafe { tcb_suspend_r(tcb) })
    }

    fn delete_cap(&mut self, _: Role, cap: u64) -> Result<(), u32> {
        status(unsafe { cnode_delete_r(cap) })
    }

    fn recycle_slot(&mut self, _: Role, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_empty(slot) }
            .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
    }

    fn recycle_failed_memory_slot(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(slot) }
            .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
    }
}

fn status(error: u64) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(u32::try_from(error).unwrap_or(nt_address_space::STATUS_INVALID_PARAMETER))
    }
}
