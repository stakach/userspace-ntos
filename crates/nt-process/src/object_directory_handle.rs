//! Typed, staged publication of an executive-owned object-directory reference.

use crate::{
    HandleFlags, HandleObject, HandleReservation, HandleSlot, ProcessId, ProcessManager,
    ProcessState, STATUS_INVALID_HANDLE, STATUS_PROCESS_IS_TERMINATING,
};
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Bound { directory: u64, granted_access: u32 },
    Published,
    Aborted,
}

/// An invisible slot retained across namespace work and output delivery. The executive owns the
/// directory body and must clean up the returned identity after abort or close.
#[must_use = "directory publication must be explicitly published or aborted"]
pub struct ObjectDirectoryHandlePublication {
    manager: u64,
    reservation: HandleReservation,
    value: u64,
    flags: HandleFlags,
    phase: Phase,
}

fn admit_owner(pm: &ProcessManager, pid: ProcessId) -> Result<(), u32> {
    let process = pm.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
    if matches!(
        process.state,
        ProcessState::Exiting | ProcessState::Terminated
    ) {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    Ok(())
}

impl ProcessManager {
    /// Reserve before acquiring a namespace reference or performing provider effects.
    pub fn reserve_object_directory_handle(
        &mut self,
        pid: ProcessId,
    ) -> Result<ObjectDirectoryHandlePublication, u32> {
        admit_owner(self, pid)?;
        if self.directory_publication_identity == 0 {
            self.directory_publication_identity = NEXT_IDENTITY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| crate::STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let reservation = self.try_reserve_handle_slot(pid)?;
        Ok(ObjectDirectoryHandlePublication {
            manager: self.directory_publication_identity,
            reservation,
            value: reservation.handle as u64,
            flags: HandleFlags::default(),
            phase: Phase::Reserved,
        })
    }
}

impl ObjectDirectoryHandlePublication {
    fn validate_manager(&self, pm: &ProcessManager) -> Result<(), u32> {
        if self.manager == 0 || self.manager != pm.directory_publication_identity {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    pub const fn value(&self) -> u64 {
        self.value
    }

    pub const fn process_id(&self) -> ProcessId {
        self.reservation.process_id
    }

    /// Binding transfers the typed target reference into the unpublished transaction.
    pub fn bind(
        &mut self,
        pm: &mut ProcessManager,
        directory: u64,
        granted_access: u32,
    ) -> Result<(), u32> {
        self.validate_manager(pm)?;
        if self.phase != Phase::Reserved {
            return Err(STATUS_INVALID_HANDLE);
        }
        admit_owner(pm, self.reservation.process_id)?;
        pm.bind_reserved_handle(
            self.reservation,
            HandleObject::ObjectDirectory(directory),
            granted_access,
        )?;
        let slot =
            crate::handle_to_slot(self.reservation.handle).expect("reserved directory handle");
        let HandleSlot::Bound { entry, .. } = &mut pm
            .processes
            .get_mut(&self.reservation.process_id)
            .expect("reserved directory owner")
            .handles[slot]
        else {
            unreachable!("new directory binding remains bound")
        };
        entry.flags = self.flags;
        self.phase = Phase::Bound {
            directory,
            granted_access,
        };
        Ok(())
    }

    fn validate_bound(&self, pm: &ProcessManager) -> Result<u64, u32> {
        self.validate_manager(pm)?;
        let Phase::Bound {
            directory,
            granted_access,
        } = self.phase
        else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let process = pm
            .process(self.reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = crate::handle_to_slot(self.reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        match process.handles.get(slot) {
            Some(HandleSlot::Bound { generation, entry })
                if *generation == self.reservation.generation
                    && entry.object == HandleObject::ObjectDirectory(directory)
                    && entry.granted_access == granted_access
                    && entry.flags == self.flags =>
            {
                Ok(directory)
            }
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// Install an executive-authorized grant while the target remains invisible.
    pub fn authorize_bound_grant(
        &mut self,
        pm: &mut ProcessManager,
        granted_access: u32,
    ) -> Result<(), u32> {
        let directory = self.validate_bound(pm)?;
        admit_owner(pm, self.reservation.process_id)?;
        let slot = crate::handle_to_slot(self.reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        let HandleSlot::Bound { entry, .. } = &mut pm
            .processes
            .get_mut(&self.reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?
            .handles[slot]
        else {
            return Err(STATUS_INVALID_HANDLE);
        };
        entry.granted_access = granted_access;
        self.phase = Phase::Bound {
            directory,
            granted_access,
        };
        Ok(())
    }

    /// Publish after successful output delivery; failure retains the bound target.
    pub fn publish(&mut self, pm: &mut ProcessManager) -> Result<u64, u32> {
        self.validate_bound(pm)?;
        admit_owner(pm, self.reservation.process_id)?;
        pm.publish_reserved_handle(self.reservation)?;
        self.phase = Phase::Published;
        Ok(self.value)
    }

    /// Cancel an invisible slot, returning any bound identity for executive cleanup.
    pub fn abort(&mut self, pm: &mut ProcessManager) -> Result<Option<u64>, u32> {
        self.validate_manager(pm)?;
        let directory = match self.phase {
            Phase::Reserved => {
                pm.cancel_reserved_handle(self.reservation)?;
                None
            }
            Phase::Bound { .. } => {
                let directory = self.validate_bound(pm)?;
                pm.cancel_bound_handle(self.reservation)?;
                Some(directory)
            }
            Phase::Published | Phase::Aborted => return Err(STATUS_INVALID_HANDLE),
        };
        self.phase = Phase::Aborted;
        Ok(directory)
    }
}

mod native;
