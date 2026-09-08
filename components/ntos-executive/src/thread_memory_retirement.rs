//! Pending construction memory ownership, after its original mechanisms have been retired.
use super::*;
use core::cell::{Cell, RefCell};
use nt_memory_manager::ClientFrameTransfer;
use nt_user_host::thread_pending::RuntimeMemoryHandoff;
use nt_user_host::thread_rollback::{
    ThreadRollbackError, ThreadRollbackId, ThreadRollbackIo, ThreadRollbackResource, ThreadRollbackResourceKind,
};
use nt_user_host::thread_slot::SlotError;

const INVALID: u32 = nt_address_space::STATUS_INVALID_PARAMETER;

#[derive(Debug)]
pub(super) struct MemoryRetirement {
    id: ThreadRollbackId,
    transfer: RefCell<Option<ClientFrameTransfer>>,
    finished: Cell<bool>,
    committed: Cell<bool>,
}

/// All preparation occurs with the pending slot and its geometry protected. The transfer and
/// journal must both be retained before copied resource fields can stop claiming their caps.
pub(super) unsafe fn prepare(slot: &mut RuntimeSlot, id: ThreadRollbackId) -> Result<(), u32> {
    let pending = slot
        .pending()
        .filter(|pending| pending.id() == id)
        .ok_or(INVALID)?;
    if pending.runtime().memory_retirement.get().is_some() {
        return slot.commit_memory_handoff(id).map_err(slot_status);
    }
    let snapshot = pending
        .runtime()
        .registry_preparation
        .retained_snapshot(id)
        .map_err(|_| INVALID)?;
    if pending.cleanup().is_none() {
        // Snapshot borrowing ends before the slot's mutable journal preparation.
        let mut inventory = Vec::new();
        inventory
            .try_reserve(snapshot.rollback_resources().len())
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
        inventory.extend_from_slice(snapshot.rollback_resources());
        slot.prepare_cleanup(id, &inventory).map_err(slot_status)?;
    }
    let owner = slot.pending().ok_or(INVALID)?.runtime();
    let snapshot = owner
        .registry_preparation
        .retained_snapshot(id)
        .map_err(|_| INVALID)?;
    let transfer = snapshot
        .prepare_transfer(
            &owner.resources,
            &mut *core::ptr::addr_of_mut!(CLIENT_FRAME_REGISTRY),
        )
        .map_err(|_| INVALID)?;
    assert!(owner
        .memory_retirement
        .set(MemoryRetirement {
            id,
            transfer: RefCell::new(transfer),
            finished: Cell::new(false),
            committed: Cell::new(false),
        })
        .is_ok());
    slot.commit_memory_handoff(id).map_err(slot_status)
}

impl RuntimeMemoryHandoff for HostedThreadRuntimeOwner {
    fn clear_memory_projections(
        &mut self,
        id: ThreadRollbackId,
        inventory: &[ThreadRollbackResource],
    ) -> Result<(), u32> {
        let retirement = self
            .memory_retirement
            .get()
            .filter(|owner| owner.id == id)
            .ok_or(INVALID)?;
        let snapshot = self
            .registry_preparation
            .retained_snapshot(id)
            .map_err(|_| INVALID)?;
        let layout = self.resources.layout().ok_or(INVALID)?;
        if retirement.finished.get()
            || self.tcb != 1
            || self.mechanism.is_live()
            || !snapshot.matches_resources(&self.resources)
            || snapshot.rollback_resources() != inventory
        {
            return Err(INVALID);
        }
        let empty = HostedThreadResources::new(self.pi, layout).ok_or(INVALID)?;
        self.runtime.resources = empty;
        self.runtime.teb_alias = 0;
        Ok(())
    }
}

/// Caller holds exact PM/reservation authority and does not pump component code during this
/// exclusive slot borrow. Pending geometry keeps fault/copy/VM admission closed across retries.
pub(super) unsafe fn advance(slot: &mut RuntimeSlot, id: ThreadRollbackId) -> Result<(), u32> {
    slot.advance_cleanup_with(id, |owner| Io { id, owner })
        .map_err(slot_status)
}

struct Io<'a> {
    id: ThreadRollbackId,
    owner: &'a HostedThreadRuntimeOwner,
}

impl ThreadRollbackIo for Io<'_> {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        id == self.id
            && self
                .owner
                .memory_retirement
                .get()
                .is_some_and(|owner| owner.id == id)
    }
    fn suspend_tcb(&mut self, _: u64) -> Result<(), u32> {
        Err(INVALID)
    }
    fn delete_tcb(&mut self, _: u64) -> Result<(), u32> {
        Err(INVALID)
    }

    fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
        if !self.is_current(id) {
            return Err(INVALID);
        }
        let aliases = self.owner.alias_preparation.get().ok_or(INVALID)?;
        let prefetch = self.owner.prefetch_preparation.get().ok_or(INVALID)?;
        let provider = self.owner.provider_preparation.get().ok_or(INVALID)?;
        unsafe {
            if !temporary_frame_alias::backing_release_available()
                || !service_sec_image::section_scratch_is_quiescent()
            {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            let provider_effects = aliases.needs_quiescence() || provider.needs_quiescence();
            if provider_effects
                && (!win32k_glue::win32k_physical_lanes_quiescent()
                    || win32k_glue::client_has_active_callback_frames(self.owner.pi as u32)
                    || service_sec_image::client_has_vm_continuations(self.owner.pi as u32))
            {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            aliases.retire(id)?;
            prefetch.retire(id)?;
            provider.retire(id)?;
        }
        Ok(())
    }

    fn unmap_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        if resource.kind == ThreadRollbackResourceKind::Mechanism {
            return Err(INVALID);
        }
        if resource.kind == ThreadRollbackResourceKind::Frame {
            unsafe {
                frame_recycle::prepare(resource.cap)?;
            }
        }
        kernel_status(unsafe { page_unmap_r(resource.cap) })
    }

    fn delete_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        if resource.kind == ThreadRollbackResourceKind::Frame {
            return Err(INVALID);
        }
        kernel_status(unsafe { cnode_delete_r(resource.cap) })
    }

    fn recycle_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        unsafe {
            match resource.kind {
                ThreadRollbackResourceKind::Frame => {
                    frame_recycle::prepare(resource.cap)?;
                    frame_recycle::publish(resource.cap)
                }
                ThreadRollbackResourceKind::Alias => {
                    root_slot_recycle::publish_unretyped(resource.cap).map_err(|_| INVALID)
                }
                ThreadRollbackResourceKind::Mechanism => {
                    root_slot_recycle::publish_empty(resource.cap).map_err(|_| INVALID)
                }
            }
        }
    }

    fn finish_memory_transfers(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
        if !self.is_current(id) {
            return Err(INVALID);
        }
        let owner = self.owner.memory_retirement.get().ok_or(INVALID)?;
        let mut held = owner.transfer.try_borrow_mut().map_err(|_| INVALID)?;
        if let Some(transfer) = held.take() {
            if let Err((_, transfer)) = unsafe {
                (&mut *core::ptr::addr_of_mut!(CLIENT_FRAME_REGISTRY)).finish_transfer(transfer)
            } {
                *held = Some(transfer);
                return Err(INVALID);
            }
        }
        owner.finished.set(true);
        Ok(())
    }

    fn commit_rollback(&mut self, id: ThreadRollbackId) {
        let owner = self
            .owner
            .memory_retirement
            .get()
            .expect("retained memory owner");
        assert!(owner.id == id && owner.finished.get() && !owner.committed.replace(true));
        // The slot can now return the bookkeeping payload. Root releases its prevalidated
        // reservations immediately afterward, without IPC or a second commitment release.
    }
}

fn kernel_status(error: u64) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(u32::try_from(error).unwrap_or(INVALID))
    }
}

fn slot_status(error: SlotError) -> u32 {
    match error {
        SlotError::Cleanup(ThreadRollbackError::Backend { status, .. })
        | SlotError::MemoryHandoff(nt_user_host::thread_pending::MemoryHandoffError::Projection(status)) => status,
        SlotError::Cleanup(ThreadRollbackError::InsufficientResources) =>
            nt_address_space::STATUS_INSUFFICIENT_RESOURCES,
        _ => INVALID,
    }
}
