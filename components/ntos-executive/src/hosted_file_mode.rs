//! Preflight every exact File projection before a memory-only mode publication.

use super::*;

const MUTABLE_MODE_FLAGS: u32 = 0x34;
const FLAGS_OFFSET: u64 = 0x50;

struct Target {
    lease: nt_io_manager::HostedFilePublicationLease,
    alias: u64,
}

pub(crate) enum PreparationError {
    Busy,
    Status(u32),
}

impl From<u32> for PreparationError {
    fn from(status: u32) -> Self { Self::Status(status) }
}

struct PoolGuard {
    pool: u64,
    _guard: ExecutivePoolLockGuard,
}

unsafe fn driver_projection_alias(
    instance: DriverInstance,
    identity: nt_io_manager::HostedFileIdentity,
    guards: &mut Vec<PoolGuard>,
) -> Result<u64, PreparationError> {
    let lock_address = instance.exec_pool_va.checked_add(COMPONENT_POOL_LOCK_OFF)
        .filter(|_| instance.exec_pool_va != 0).ok_or(STATUS_INVALID_HANDLE as u32)?;
    if !guards.iter().any(|guard| guard.pool == instance.exec_pool_va) {
        let lock = &*(lock_address as *const AtomicU64);
        lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| PreparationError::Busy)?;
        // Storage was reserved before acquiring any guard. Keep one physical pool lock
        // through the complete non-reentrant commit, including all aliases of that pool.
        guards.push(PoolGuard { pool: instance.exec_pool_va,
            _guard: ExecutivePoolLockGuard(lock as *const AtomicU64) });
    }
    if hosted_instance_pool_allocation_is_free_unlocked(instance, identity.address()) != Some(false) {
        return Err(PreparationError::Status(STATUS_INVALID_HANDLE as u32));
    }
    hosted_pool_allocation_exec_va(instance.exec_pool_va, identity.address(),
        WDM_X64_FILE_OBJECT_SIZE as u64).ok_or(PreparationError::Status(STATUS_INVALID_HANDLE as u32))
}

pub(crate) struct Prepared {
    file: FileId,
    device: nt_io_manager::DeviceId,
    previous: nt_io_manager::FileModeState,
    next: nt_io_manager::FileModeState,
    requested: u32,
    targets: Vec<Target>,
    guards: Vec<PoolGuard>,
}

impl Prepared {
    pub(crate) fn previous_io_mode(&self) -> Result<nt_io_completion::FileIoMode, u32> {
        self.previous.io_mode().map_err(|status| status.raw() as u32)
    }

    pub(crate) fn next_io_mode(&self) -> Result<nt_io_completion::FileIoMode, u32> {
        self.next.io_mode().map_err(|status| status.raw() as u32)
    }

    /// All aliases are already resident and leased. This performs no IPC, page mapping,
    /// allocation or reentry; no fallible operation follows the canonical mutation.
    pub(crate) fn set_owned_file_mode(&mut self) -> Result<(), u32> {
        let io = io_manager_mut();
        if io.file(self.file).is_none_or(|file| file.mode_state() != self.previous) {
            return Err(STATUS_INVALID_PARAMETER as u32);
        }
        let flags = self.next.wdm_mode_flags().map_err(|status| status.raw() as u32)?;
        io.set_owned_file_mode(ClientId(IO_MANAGER_COMPONENT_ID), self.file, self.device,
            self.requested).map_err(|status| status.raw() as u32)?;
        for target in &self.targets {
            unsafe {
                let address = (target.alias + FLAGS_OFFSET) as *mut u32;
                let current = read_volatile(address);
                write_volatile(address, (current & !MUTABLE_MODE_FLAGS) | (flags & MUTABLE_MODE_FLAGS));
            }
        }
        Ok(())
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        for target in &mut self.targets {
            io_manager_mut().release_hosted_file_publication(&mut target.lease)
                .expect("mode publication lost its exact projection lease");
        }
    }
}

pub(crate) fn prepare(file_id: u64, device_id: u64, requested: u32) -> Result<Prepared, PreparationError> {
    let file = FileId(file_id);
    let device = nt_io_manager::DeviceId(device_id);
    io_manager_mut().owned_file_metadata(ClientId(IO_MANAGER_COMPONENT_ID), file)
        .map_err(|status| status.raw() as u32)?;
    let record = io_manager_mut().file(file).ok_or(STATUS_INVALID_HANDLE as u32)?;
    if record.device_id != device { return Err(PreparationError::Status(STATUS_INVALID_HANDLE as u32)); }
    let previous = record.mode_state();
    let next = previous.transition(requested).map_err(|status| status.raw() as u32)?;
    let identities = io_manager_mut().hosted_file_identities(file)
        .map_err(|status| status.raw() as u32)?;
    let mut prepared = Prepared { file, device, previous, next, requested,
        targets: Vec::new(), guards: Vec::new() };
    prepared.targets.try_reserve_exact(identities.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    prepared.guards.try_reserve_exact(identities.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    for identity in identities {
        let lease = io_manager_mut().lease_hosted_file_identity(identity)
            .map_err(|status| status.raw() as u32)?;
        prepared.targets.push(Target { lease, alias: 0 });
        let alias = unsafe {
            if let Some(alias) = crate::win32k_file_owners::mode_projection_address(identity)? {
                alias
            } else {
                let instance = driver_instances().and_then(|instances| instances.iter().copied()
                    .find(|instance| instance.used && instance_domain_identity(*instance) == Some(identity.domain())))
                    .ok_or(STATUS_INVALID_HANDLE as u32)?;
                driver_projection_alias(instance, identity, &mut prepared.guards)?
            }
        };
        if alias & 7 != 0 || alias.checked_add(WDM_X64_FILE_OBJECT_SIZE as u64).is_none()
            || unsafe { read_unaligned(alias as *const i16) } != nt_io_manager::WDM_X64_IO_TYPE_FILE
            || unsafe { read_unaligned((alias + 2) as *const u16) } != WDM_X64_FILE_OBJECT_SIZE as u16
        {
            return Err(PreparationError::Status(STATUS_INVALID_HANDLE as u32));
        }
        prepared.targets.last_mut().unwrap().alias = alias;
    }
    Ok(prepared)
}
