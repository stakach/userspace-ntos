//! Exact process-table ownership for a service-backed ALPC port.

use core::sync::atomic::{AtomicU64, Ordering};
use nt_types::AccessMode;

use crate::native_handle::{NativeCloseError, NativeHandleCaller, NativeHandleScope,
    INVALID_KERNEL_HANDLE_BUGCHECK};
use crate::{handle_to_slot, HandleObject, HandleReservation, HandleSlot, ProcessId,
    ProcessManager, ProcessState, STATUS_ACCESS_DENIED, STATUS_HANDLE_NOT_CLOSABLE,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_PROCESS_IS_TERMINATING};

static NEXT_MANAGER_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlpcPortIdentity {
    pub service_handle: u64,
    pub owner_process: ProcessId,
    pub owner_generation: u64,
    pub invocation_hi: u64,
    pub invocation_lo: u64,
}

impl AlpcPortIdentity {
    fn object(self) -> HandleObject {
        HandleObject::AlpcPort { service_handle: self.service_handle,
            owner_generation: self.owner_generation, invocation_hi: self.invocation_hi,
            invocation_lo: self.invocation_lo }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationPhase { Reserved, Bound(AlpcPortIdentity), Published, Aborted }

/// Invisible process handle reserved before the create service effect.
#[must_use = "publish or abort this exact process handle"]
pub struct NativeAlpcPortPublication {
    manager: u64,
    reservation: HandleReservation,
    owner_generation: u64,
    token: (u64, u64),
    phase: PublicationPhase,
}

/// Exact occupied handle hidden while a checked close is in flight.
#[must_use = "retain the handle slot until exact service completion"]
pub struct NativeAlpcPortClose {
    manager: u64,
    reservation: HandleReservation,
    identity: AlpcPortIdentity,
    value: u64,
    pending: bool,
}

fn admit_running_owner(pm: &ProcessManager, pid: ProcessId) -> Result<(), u32> {
    let process = pm.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
    if process.state != ProcessState::Running {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    Ok(())
}

impl ProcessManager {
    fn alpc_manager_identity(&mut self) -> Result<u64, u32> {
        if self.alpc_publication_identity == 0 {
            self.alpc_publication_identity = NEXT_MANAGER_IDENTITY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        }
        Ok(self.alpc_publication_identity)
    }

    pub fn reserve_native_alpc_port_handle(&mut self, caller: NativeHandleCaller,
        owner_generation: u64, token: (u64, u64)) -> Result<NativeAlpcPortPublication, u32> {
        self.validate_native_handle_caller(caller)?;
        if owner_generation == 0 || token == (0, 0) { return Err(STATUS_INVALID_PARAMETER); }
        let owner = caller.effective_process();
        admit_running_owner(self, owner)?;
        let manager = self.alpc_manager_identity()?;
        let reservation = self.try_reserve_handle_slot(owner)?;
        Ok(NativeAlpcPortPublication { manager, reservation, owner_generation, token,
            phase: PublicationPhase::Reserved })
    }

    /// Hide the exact table entry until a checked service close is known.
    pub fn begin_native_alpc_port_close(&mut self, caller: NativeHandleCaller,
        value: u64, owner_generation: u64) -> Result<NativeAlpcPortClose, NativeCloseError> {
        let target = self.inspect_native_close_target(caller, value)
            .map_err(NativeCloseError::Status)?;
        let NativeHandleScope::Table { owner, handle, kernel: false } =
            self.decode_native_handle(caller, value).map_err(NativeCloseError::Status)?
        else { return Err(NativeCloseError::Status(STATUS_INVALID_HANDLE)); };
        if owner != caller.effective_process() {
            return Err(NativeCloseError::Status(STATUS_ACCESS_DENIED));
        }
        let HandleObject::AlpcPort { service_handle,
            owner_generation: bound_generation, invocation_hi, invocation_lo } = target.object()
        else { return Err(NativeCloseError::Status(STATUS_INVALID_HANDLE)); };
        if owner_generation == 0 || owner_generation != bound_generation {
            return Err(NativeCloseError::Status(STATUS_INVALID_HANDLE));
        }
        let flags = self.handle_flags(owner, handle)
            .ok_or(NativeCloseError::Status(STATUS_INVALID_HANDLE))?;
        if flags.protect_from_close {
            return Err(if caller.mode() == AccessMode::KernelMode {
                NativeCloseError::BugCheck { code: INVALID_KERNEL_HANDLE_BUGCHECK,
                    parameters: [value, 0, 0, 0] }
            } else { NativeCloseError::Status(STATUS_HANDLE_NOT_CLOSABLE) });
        }
        let manager = self.alpc_manager_identity().map_err(NativeCloseError::Status)?;
        let process = self.processes.get_mut(&owner)
            .ok_or(NativeCloseError::Status(STATUS_INVALID_HANDLE))?;
        let slot = handle_to_slot(handle)
            .ok_or(NativeCloseError::Status(STATUS_INVALID_HANDLE))?;
        let generation = process.next_handle_reservation_generation;
        let next = generation.checked_add(1).filter(|_| generation != 0)
            .ok_or(NativeCloseError::Status(STATUS_INSUFFICIENT_RESOURCES))?;
        let entry = process.handles.get_mut(slot)
            .ok_or(NativeCloseError::Status(STATUS_INVALID_HANDLE))?;
        let HandleSlot::Occupied(occupied) = entry else {
            return Err(NativeCloseError::Status(STATUS_INVALID_HANDLE));
        };
        if occupied.object != target.object() || occupied.flags != flags {
            return Err(NativeCloseError::Status(STATUS_INVALID_HANDLE));
        }
        let HandleSlot::Occupied(occupied) = core::mem::replace(entry, HandleSlot::Free)
        else { unreachable!("validated ALPC close target remains occupied") };
        *entry = HandleSlot::Bound { generation, entry: occupied };
        process.next_handle_reservation_generation = next;
        Ok(NativeAlpcPortClose { manager,
            reservation: HandleReservation { process_id: owner, handle, generation },
            identity: AlpcPortIdentity { service_handle, owner_process: owner,
                owner_generation, invocation_hi, invocation_lo },
            value, pending: true })
    }
}

impl NativeAlpcPortPublication {
    fn validate_manager(&self, pm: &ProcessManager) -> Result<(), u32> {
        if self.manager == 0 || self.manager != pm.alpc_publication_identity {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }
    pub const fn value(&self) -> u64 { self.reservation.handle as u64 }
    pub const fn owner_process(&self) -> ProcessId { self.reservation.process_id }

    pub fn bind(&mut self, pm: &mut ProcessManager, service_handle: u64) -> Result<(), u32> {
        self.validate_manager(pm)?;
        if self.phase != PublicationPhase::Reserved || service_handle == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        admit_running_owner(pm, self.owner_process())?;
        let identity = AlpcPortIdentity { service_handle, owner_process: self.owner_process(),
            owner_generation: self.owner_generation, invocation_hi: self.token.0,
            invocation_lo: self.token.1 };
        pm.bind_reserved_handle(self.reservation, identity.object(), 0)?;
        self.phase = PublicationPhase::Bound(identity);
        Ok(())
    }

    fn validate_bound(&self, pm: &ProcessManager) -> Result<AlpcPortIdentity, u32> {
        self.validate_manager(pm)?;
        let PublicationPhase::Bound(identity) = self.phase else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let process = pm.process(self.owner_process()).ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(self.reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        match process.handles.get(slot) {
            Some(HandleSlot::Bound { generation, entry })
                if *generation == self.reservation.generation
                    && entry.object == identity.object() && entry.granted_access == 0 => Ok(identity),
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// Call only after the handle value was copied to the original caller.
    pub fn publish(&mut self, pm: &mut ProcessManager) -> Result<u64, u32> {
        self.validate_bound(pm)?;
        admit_running_owner(pm, self.owner_process())?;
        pm.publish_reserved_handle(self.reservation)?;
        self.phase = PublicationPhase::Published;
        Ok(self.value())
    }

    /// Return the service identity for exact checked close on failed copyout.
    pub fn abort(&mut self, pm: &mut ProcessManager) -> Result<Option<AlpcPortIdentity>, u32> {
        self.validate_manager(pm)?;
        let identity = match self.phase {
            PublicationPhase::Reserved => { pm.cancel_reserved_handle(self.reservation)?; None }
            PublicationPhase::Bound(_) => {
                let identity = self.validate_bound(pm)?;
                let object = pm.cancel_bound_handle(self.reservation)?;
                assert_eq!(object, identity.object(), "validated ALPC binding changed");
                Some(identity)
            }
            PublicationPhase::Published | PublicationPhase::Aborted => return Err(STATUS_INVALID_HANDLE),
        };
        self.phase = PublicationPhase::Aborted;
        Ok(identity)
    }
}

impl NativeAlpcPortClose {
    pub const fn identity(&self) -> AlpcPortIdentity { self.identity }
    pub const fn value(&self) -> u64 { self.value }

    /// None is uncertain: retain the hidden slot. Exact failure restores the
    /// original handle, and exact success retires that one table reference.
    pub fn reconcile(&mut self, pm: &mut ProcessManager,
        status: Option<i32>) -> Result<Option<i32>, u32> {
        if !self.pending || self.manager == 0 || self.manager != pm.alpc_publication_identity {
            return Err(STATUS_INVALID_HANDLE);
        }
        let Some(status) = status else { return Ok(None) };
        let process = pm.process(self.identity.owner_process).ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(self.reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        if !matches!(process.handles.get(slot),
            Some(HandleSlot::Bound { generation, entry })
                if *generation == self.reservation.generation && entry.object == self.identity.object())
        { return Err(STATUS_INVALID_HANDLE); }
        if status == 0 {
            let object = pm.cancel_bound_handle(self.reservation)?;
            assert_eq!(object, self.identity.object(), "validated ALPC close changed");
        } else {
            pm.publish_reserved_handle(self.reservation)?;
        }
        self.pending = false;
        Ok(Some(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (ProcessManager, NativeHandleCaller, ProcessId) {
        let mut pm = ProcessManager::new();
        let system = pm.create_process("kernel", None, None);
        let system_tid = pm.create_thread(system, 0, 0, true).unwrap();
        pm.designate_initial_system(system, system_tid).unwrap();
        assert!(pm.publish_process_kernel_object(system, 0x1000));
        assert!(pm.publish_thread_kernel_object(system_tid, 0x2000));
        let pid = pm.create_process("client", None, None);
        let tid = pm.create_thread(pid, 0, 0, false).unwrap();
        assert!(pm.publish_process_kernel_object(pid, 0x3000));
        assert!(pm.publish_thread_kernel_object(tid, 0x4000));
        let caller = pm.capture_native_handle_caller(
            pm.thread_lifetime(tid).unwrap(), AccessMode::UserMode).unwrap();
        (pm, caller, pid)
    }

    #[test]
    fn publication_is_invisible_until_copyout_and_returns_cleanup_identity_on_abort() {
        let (mut pm, caller, pid) = fixture();
        let mut publication = pm.reserve_native_alpc_port_handle(caller, 7, (11, 13)).unwrap();
        let value = publication.value();
        publication.bind(&mut pm, 0x4c50_0001).unwrap();
        assert_eq!(pm.lookup_handle(pid, value as u32), None);
        assert_eq!(publication.abort(&mut pm), Ok(Some(AlpcPortIdentity {
            service_handle: 0x4c50_0001, owner_process: pid, owner_generation: 7,
            invocation_hi: 11, invocation_lo: 13,
        })));
        assert_eq!(pm.handle_reservation_count(pid), 0);
        let mut publication = pm.reserve_native_alpc_port_handle(caller, 7, (17, 19)).unwrap();
        publication.bind(&mut pm, 0x4c50_0002).unwrap();
        let value = publication.value();
        assert_eq!(publication.publish(&mut pm), Ok(value));
        assert_eq!(pm.lookup_handle(pid, value as u32), Some(HandleObject::AlpcPort {
            service_handle: 0x4c50_0002, owner_generation: 7,
            invocation_hi: 17, invocation_lo: 19,
        }));
    }

    #[test]
    fn close_retains_exact_slot_across_uncertainty_and_rejects_stale_generation() {
        let (mut pm, caller, pid) = fixture();
        let mut publication = pm.reserve_native_alpc_port_handle(caller, 7, (11, 13)).unwrap();
        publication.bind(&mut pm, 0x4c50_0001).unwrap();
        let value = publication.publish(&mut pm).unwrap();
        assert!(matches!(pm.begin_native_alpc_port_close(caller, value, 8),
            Err(NativeCloseError::Status(STATUS_INVALID_HANDLE))));
        let mut close = pm.begin_native_alpc_port_close(caller, value, 7).unwrap();
        assert_eq!(close.identity().service_handle, 0x4c50_0001);
        assert_eq!(pm.lookup_handle(pid, value as u32), None);
        assert_eq!(close.reconcile(&mut pm, None), Ok(None));
        assert_eq!(pm.lookup_handle(pid, value as u32), None);
        assert_eq!(close.reconcile(&mut pm, Some(0)), Ok(Some(0)));
        assert_eq!(pm.lookup_handle(pid, value as u32), None);
        assert_eq!(pm.handle_reservation_count(pid), 0);
    }

    #[test]
    fn failed_service_close_restores_exact_handle_and_object() {
        let (mut pm, caller, pid) = fixture();
        let mut publication = pm.reserve_native_alpc_port_handle(caller, 7, (11, 13)).unwrap();
        publication.bind(&mut pm, 0x4c50_0001).unwrap();
        let value = publication.publish(&mut pm).unwrap();
        let mut close = pm.begin_native_alpc_port_close(caller, value, 7).unwrap();
        let failure = 0xC000_0001u32 as i32;
        assert_eq!(close.reconcile(&mut pm, Some(failure)), Ok(Some(failure)));
        assert_eq!(pm.lookup_handle(pid, value as u32), Some(close.identity().object()));
    }
}
