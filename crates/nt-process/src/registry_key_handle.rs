//! Canonical publication of an already-authorized registry Key grant.

use crate::{
    HandleFlags, HandleObject, HandleReservation, HandleSlot, ProcessId, ProcessManager,
    ProcessState, STATUS_INVALID_HANDLE, STATUS_PROCESS_IS_TERMINATING,
};
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Bound { key: u32, granted_access: u32 },
    Published,
    Aborted,
}

/// Owns an invisible PM slot across provider work and caller output delivery. Binding transfers
/// cleanup responsibility for the Key target to this transaction; errors never discard it.
/// This is not an access check and does not create an object body.
#[must_use = "registry publication must be explicitly published or aborted"]
pub struct RegistryKeyHandlePublication {
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
    /// Reserve storage before acquiring a CM lease or performing another provider effect.
    pub fn reserve_registry_key_handle(
        &mut self,
        pid: ProcessId,
    ) -> Result<RegistryKeyHandlePublication, u32> {
        admit_owner(self, pid)?;
        if self.registry_publication_identity == 0 {
            self.registry_publication_identity = NEXT_IDENTITY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map_err(|_| crate::STATUS_INSUFFICIENT_RESOURCES)?;
        }
        let reservation = self.try_reserve_handle_slot(pid)?;
        Ok(RegistryKeyHandlePublication {
            manager: self.registry_publication_identity,
            value: reservation.handle as u64,
            flags: HandleFlags {
                inherit: false,
                protect_from_close: false,
            },
            reservation,
            phase: Phase::Reserved,
        })
    }
}

impl RegistryKeyHandlePublication {
    fn validate_manager(&self, pm: &ProcessManager) -> Result<(), u32> {
        if self.manager == 0 || self.manager != pm.registry_publication_identity {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    /// The future handle value may be copied out while the slot remains invisible.
    pub const fn value(&self) -> u64 {
        self.value
    }

    pub const fn process_id(&self) -> ProcessId {
        self.reservation.process_id
    }

    /// On failure the caller still owns `key`; on success only publish or abort may release it.
    pub fn bind(
        &mut self,
        pm: &mut ProcessManager,
        key: u32,
        granted_access: u32,
    ) -> Result<(), u32> {
        self.validate_manager(pm)?;
        if self.phase != Phase::Reserved {
            return Err(STATUS_INVALID_HANDLE);
        }
        admit_owner(pm, self.reservation.process_id)?;
        pm.bind_reserved_handle(
            self.reservation,
            HandleObject::RegistryKey(key),
            granted_access,
        )?;
        let slot = crate::handle_to_slot(self.reservation.handle).expect("reserved Key handle");
        let HandleSlot::Bound { entry, .. } = &mut pm
            .processes
            .get_mut(&self.reservation.process_id)
            .expect("reserved Key owner")
            .handles[slot]
        else {
            unreachable!("new Key binding remains bound")
        };
        entry.flags = self.flags;
        self.phase = Phase::Bound {
            key,
            granted_access,
        };
        Ok(())
    }

    fn validate_bound(&self, pm: &ProcessManager) -> Result<u32, u32> {
        self.validate_manager(pm)?;
        let Phase::Bound {
            key,
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
                    && entry.object == HandleObject::RegistryKey(key)
                    && entry.granted_access == granted_access
                    && entry.flags == self.flags =>
            {
                Ok(key)
            }
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// Install a security decision while the retained target is still invisible. Binding zero
    /// rights before a CM access check keeps shared targets alive across reentrant provider IPC.
    /// This is not an access check; only the native policy owner may supply the authorized grant.
    pub fn authorize_bound_grant(
        &mut self,
        pm: &mut ProcessManager,
        granted_access: u32,
    ) -> Result<(), u32> {
        let key = self.validate_bound(pm)?;
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
            key,
            granted_access,
        };
        Ok(())
    }

    /// Publish only after successful output delivery. Failed admission retains the bound target.
    pub fn publish(&mut self, pm: &mut ProcessManager) -> Result<u64, u32> {
        self.validate_bound(pm)?;
        admit_owner(pm, self.reservation.process_id)?;
        pm.publish_reserved_handle(self.reservation)?;
        self.phase = Phase::Published;
        Ok(self.value)
    }

    /// Return the bound Key for external cleanup, or cancel an empty reservation. Teardown does
    /// not prevent cleanup; a stale generation never cancels another transaction's slot.
    pub fn abort(&mut self, pm: &mut ProcessManager) -> Result<Option<u32>, u32> {
        self.validate_manager(pm)?;
        let key = match self.phase {
            Phase::Reserved => {
                pm.cancel_reserved_handle(self.reservation)?;
                None
            }
            Phase::Bound { .. } => {
                let key = self.validate_bound(pm)?;
                pm.cancel_bound_handle(self.reservation)?;
                Some(key)
            }
            Phase::Published | Phase::Aborted => return Err(STATUS_INVALID_HANDLE),
        };
        self.phase = Phase::Aborted;
        Ok(key)
    }
}

#[cfg(test)]
mod tests;

mod native;
