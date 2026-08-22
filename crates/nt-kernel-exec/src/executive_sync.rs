//! Native x64 `ERESOURCE`, critical-region, and `FAST_MUTEX` mechanics.
//!
//! Hosted kernel personalities share the ownership rules here and provide only current-thread
//! identity plus blocking/wake transport. An acquire that cannot complete immediately returns
//! [`AcquireResult::WouldBlock`]; callers must park through their real dispatcher rather than
//! reporting success before ownership has transferred.

use alloc::vec::Vec;

/// Native x64 `ERESOURCE` offsets (NT 5.x / ReactOS ABI).
pub mod eresource_layout {
    pub const SYSTEM_RESOURCES_LIST: usize = 0x00;
    pub const OWNER_TABLE: usize = 0x10;
    pub const ACTIVE_COUNT: usize = 0x18;
    pub const FLAG: usize = 0x1a;
    pub const SHARED_WAITERS: usize = 0x20;
    pub const EXCLUSIVE_WAITERS: usize = 0x28;
    pub const OWNER_ENTRY: usize = 0x30;
    pub const ACTIVE_ENTRIES: usize = 0x40;
    pub const CONTENTION_COUNT: usize = 0x44;
    pub const NUMBER_OF_SHARED_WAITERS: usize = 0x48;
    pub const NUMBER_OF_EXCLUSIVE_WAITERS: usize = 0x4c;
    pub const RESERVED2: usize = 0x50;
    pub const ADDRESS: usize = 0x58;
    pub const SPIN_LOCK: usize = 0x60;
    pub const SIZE_OF: usize = 0x68;
}

/// Native x64 `OWNER_ENTRY` offsets.
pub mod owner_entry_layout {
    pub const OWNER_THREAD: usize = 0x00;
    pub const OWNER_COUNT_OR_TABLE_SIZE: usize = 0x08;
    pub const SIZE_OF: usize = 0x10;
}

/// Native x64 `FAST_MUTEX` offsets.
pub mod fast_mutex_layout {
    pub const COUNT: usize = 0x00;
    pub const OWNER: usize = 0x08;
    pub const CONTENTION: usize = 0x10;
    pub const EVENT: usize = 0x18;
    pub const OLD_IRQL: usize = 0x30;
    pub const SIZE_OF: usize = 0x38;
}

/// Native x64 `KTHREAD` fields used by critical/guarded regions.
pub mod kthread_layout {
    pub const KERNEL_APC_DISABLE: usize = 0x1b4;
    pub const SPECIAL_APC_DISABLE: usize = 0x1b6;
    pub const WIN32_THREAD: usize = 0x250;
}

pub const RESOURCE_OWNED_EXCLUSIVE: u16 = 0x0080;
const OWNER_COUNT_MASK: u32 = 0x3fff_ffff;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutiveSyncError {
    InvalidAddress,
    InvalidOwner,
    NotInitialized,
    ResourceBusy,
    NotOwned,
    RecursionOverflow,
    AllocationFailed,
    ApcDisableOverflow,
    ApcDisableUnderflow,
    FastMutexCorrupt,
    FastMutexRecursiveAcquire,
    BlockingWaitRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceMode {
    Shared,
    Exclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquireResult {
    Acquired,
    WouldBlock,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeOwnerEntry {
    owner_thread: u64,
    owner_count_or_table_size: u32,
    reserved: u32,
}

const _: () = assert!(core::mem::size_of::<NativeOwnerEntry>() == owner_entry_layout::SIZE_OF);

#[derive(Clone, Copy, Debug)]
struct ResourceOwner {
    thread: u64,
    recursion: u32,
}

struct ExecutiveResource {
    address: u64,
    exclusive: bool,
    owners: Vec<ResourceOwner>,
    /// Entry zero is the native table header; actual secondary owners start at entry one.
    owner_table: Vec<NativeOwnerEntry>,
    contention_count: u32,
    shared_waiters: u32,
    exclusive_waiters: u32,
}

impl ExecutiveResource {
    fn is_active(&self) -> bool {
        !self.owners.is_empty()
    }

    fn owner_index(&self, thread: u64) -> Option<usize> {
        self.owners.iter().position(|owner| owner.thread == thread)
    }

    fn ensure_owner_table(&mut self) -> Result<(), ExecutiveSyncError> {
        if self.owners.len() <= 1 {
            return Ok(());
        }
        let required_owner_slots = self.owners.len() - 1;
        let mut table_size = self.owner_table.len().max(3);
        while table_size.saturating_sub(1) < required_owner_slots {
            table_size = table_size
                .checked_add(4)
                .ok_or(ExecutiveSyncError::AllocationFailed)?;
        }
        if self.owner_table.len() < table_size {
            self.owner_table
                .try_reserve_exact(table_size - self.owner_table.len())
                .map_err(|_| ExecutiveSyncError::AllocationFailed)?;
            self.owner_table
                .resize(table_size, NativeOwnerEntry::default());
        }
        Ok(())
    }

    unsafe fn project_native(&mut self) -> Result<(), ExecutiveSyncError> {
        self.ensure_owner_table()?;
        let resource = self.address as *mut u8;

        let mut flags =
            core::ptr::read_unaligned(resource.add(eresource_layout::FLAG) as *const u16);
        if self.exclusive {
            flags |= RESOURCE_OWNED_EXCLUSIVE;
        } else {
            flags &= !RESOURCE_OWNED_EXCLUSIVE;
        }
        core::ptr::write_unaligned(resource.add(eresource_layout::FLAG) as *mut u16, flags);
        core::ptr::write_unaligned(
            resource.add(eresource_layout::ACTIVE_COUNT) as *mut i16,
            if self.is_active() { 1 } else { 0 },
        );
        core::ptr::write_unaligned(
            resource.add(eresource_layout::ACTIVE_ENTRIES) as *mut u32,
            self.owners.len() as u32,
        );
        core::ptr::write_unaligned(
            resource.add(eresource_layout::CONTENTION_COUNT) as *mut u32,
            self.contention_count,
        );
        core::ptr::write_unaligned(
            resource.add(eresource_layout::NUMBER_OF_SHARED_WAITERS) as *mut u32,
            self.shared_waiters,
        );
        core::ptr::write_unaligned(
            resource.add(eresource_layout::NUMBER_OF_EXCLUSIVE_WAITERS) as *mut u32,
            self.exclusive_waiters,
        );

        let embedded = self.owners.first().copied().unwrap_or(ResourceOwner {
            thread: 0,
            recursion: 0,
        });
        core::ptr::write_unaligned(
            resource.add(eresource_layout::OWNER_ENTRY + owner_entry_layout::OWNER_THREAD)
                as *mut u64,
            embedded.thread,
        );
        core::ptr::write_unaligned(
            resource
                .add(eresource_layout::OWNER_ENTRY + owner_entry_layout::OWNER_COUNT_OR_TABLE_SIZE)
                as *mut u32,
            embedded.recursion & OWNER_COUNT_MASK,
        );

        if !self.owner_table.is_empty() {
            self.owner_table.fill(NativeOwnerEntry::default());
            self.owner_table[0].owner_count_or_table_size = self.owner_table.len() as u32;
            for (entry, owner) in self.owner_table[1..]
                .iter_mut()
                .zip(self.owners.iter().skip(1))
            {
                entry.owner_thread = owner.thread;
                entry.owner_count_or_table_size = owner.recursion & OWNER_COUNT_MASK;
            }
        }
        let owner_table = if self.owner_table.is_empty() {
            0
        } else {
            self.owner_table.as_mut_ptr() as u64
        };
        core::ptr::write_unaligned(
            resource.add(eresource_layout::OWNER_TABLE) as *mut u64,
            owner_table,
        );
        Ok(())
    }
}

#[derive(Default)]
pub struct ExecutiveResourceStore {
    resources: Vec<ExecutiveResource>,
}

impl ExecutiveResourceStore {
    pub const fn new() -> Self {
        Self {
            resources: Vec::new(),
        }
    }

    fn index_of(&self, address: u64) -> Option<usize> {
        self.resources
            .iter()
            .position(|resource| resource.address == address)
    }

    /// Initializes caller-owned native `ERESOURCE` storage and registers its ownership state.
    ///
    /// # Safety
    /// `resource` must be aligned and writable for [`eresource_layout::SIZE_OF`] bytes for the
    /// lifetime of this store entry.
    pub unsafe fn initialize(&mut self, resource: *mut u8) -> Result<(), ExecutiveSyncError> {
        if resource.is_null() || (resource as usize & 7) != 0 {
            return Err(ExecutiveSyncError::InvalidAddress);
        }
        let address = resource as u64;
        let index = if let Some(index) = self.index_of(address) {
            if self.resources[index].is_active() {
                return Err(ExecutiveSyncError::ResourceBusy);
            }
            index
        } else {
            self.resources
                .try_reserve(1)
                .map_err(|_| ExecutiveSyncError::AllocationFailed)?;
            self.resources.push(ExecutiveResource {
                address,
                exclusive: false,
                owners: Vec::new(),
                owner_table: Vec::new(),
                contention_count: 0,
                shared_waiters: 0,
                exclusive_waiters: 0,
            });
            self.resources.len() - 1
        };

        core::ptr::write_bytes(resource, 0, eresource_layout::SIZE_OF);
        let list_head = resource.add(eresource_layout::SYSTEM_RESOURCES_LIST) as u64;
        core::ptr::write_unaligned(resource as *mut u64, list_head);
        core::ptr::write_unaligned(resource.add(8) as *mut u64, list_head);
        let state = &mut self.resources[index];
        state.exclusive = false;
        state.owners.clear();
        state.owner_table.clear();
        state.contention_count = 0;
        state.shared_waiters = 0;
        state.exclusive_waiters = 0;
        state.project_native()
    }

    /// Deletes an idle resource. An owned resource is rejected instead of silently discarding
    /// ownership.
    ///
    /// # Safety
    /// `resource` must still refer to the registered native storage.
    pub unsafe fn delete(&mut self, resource: *mut u8) -> Result<(), ExecutiveSyncError> {
        if resource.is_null() {
            return Err(ExecutiveSyncError::InvalidAddress);
        }
        let index = self
            .index_of(resource as u64)
            .ok_or(ExecutiveSyncError::NotInitialized)?;
        if self.resources[index].is_active()
            || self.resources[index].shared_waiters != 0
            || self.resources[index].exclusive_waiters != 0
        {
            return Err(ExecutiveSyncError::ResourceBusy);
        }
        core::ptr::write_unaligned(resource.add(eresource_layout::OWNER_TABLE) as *mut u64, 0);
        self.resources.swap_remove(index);
        Ok(())
    }

    /// Attempts to acquire a resource. `WouldBlock` never grants or records ownership.
    ///
    /// # Safety
    /// `resource` must refer to registered native storage.
    pub unsafe fn acquire(
        &mut self,
        resource: *mut u8,
        thread: u64,
        mode: ResourceMode,
    ) -> Result<AcquireResult, ExecutiveSyncError> {
        if resource.is_null() {
            return Err(ExecutiveSyncError::InvalidAddress);
        }
        if thread == 0 {
            return Err(ExecutiveSyncError::InvalidOwner);
        }
        let index = self
            .index_of(resource as u64)
            .ok_or(ExecutiveSyncError::NotInitialized)?;
        let state = &mut self.resources[index];

        if let Some(owner_index) = state.owner_index(thread) {
            if mode == ResourceMode::Exclusive && !state.exclusive {
                return Ok(AcquireResult::WouldBlock);
            }
            let recursion = state.owners[owner_index]
                .recursion
                .checked_add(1)
                .filter(|count| *count <= OWNER_COUNT_MASK)
                .ok_or(ExecutiveSyncError::RecursionOverflow)?;
            state.owners[owner_index].recursion = recursion;
            state.project_native()?;
            return Ok(AcquireResult::Acquired);
        }

        if state.exclusive || (mode == ResourceMode::Exclusive && state.is_active()) {
            return Ok(AcquireResult::WouldBlock);
        }

        state
            .owners
            .try_reserve(1)
            .map_err(|_| ExecutiveSyncError::AllocationFailed)?;
        state.owners.push(ResourceOwner {
            thread,
            recursion: 1,
        });
        state.exclusive = mode == ResourceMode::Exclusive;
        state.project_native()?;
        Ok(AcquireResult::Acquired)
    }

    /// Releases one recursive acquisition held by `thread`.
    ///
    /// # Safety
    /// `resource` must refer to registered native storage.
    pub unsafe fn release(
        &mut self,
        resource: *mut u8,
        thread: u64,
    ) -> Result<(), ExecutiveSyncError> {
        if resource.is_null() {
            return Err(ExecutiveSyncError::InvalidAddress);
        }
        if thread == 0 {
            return Err(ExecutiveSyncError::InvalidOwner);
        }
        let index = self
            .index_of(resource as u64)
            .ok_or(ExecutiveSyncError::NotInitialized)?;
        let state = &mut self.resources[index];
        let owner_index = state
            .owner_index(thread)
            .ok_or(ExecutiveSyncError::NotOwned)?;
        if state.owners[owner_index].recursion > 1 {
            state.owners[owner_index].recursion -= 1;
        } else {
            state.owners.remove(owner_index);
            if state.owners.is_empty() {
                state.exclusive = false;
            }
        }
        state.project_native()
    }

    pub fn is_acquired_exclusive(
        &self,
        resource: u64,
        thread: u64,
    ) -> Result<bool, ExecutiveSyncError> {
        let state = self
            .resources
            .iter()
            .find(|resource_state| resource_state.address == resource)
            .ok_or(ExecutiveSyncError::NotInitialized)?;
        Ok(state.exclusive && state.owner_index(thread).is_some())
    }

    pub fn acquired_count(&self, resource: u64, thread: u64) -> Result<u32, ExecutiveSyncError> {
        let state = self
            .resources
            .iter()
            .find(|resource_state| resource_state.address == resource)
            .ok_or(ExecutiveSyncError::NotInitialized)?;
        Ok(state
            .owner_index(thread)
            .map(|index| state.owners[index].recursion)
            .unwrap_or(0))
    }
}

/// Disables normal kernel APC delivery for the current thread.
///
/// # Safety
/// `thread` must point to a writable native x64 `KTHREAD` projection.
pub unsafe fn enter_critical_region(thread: *mut u8) -> Result<i16, ExecutiveSyncError> {
    if thread.is_null() {
        return Err(ExecutiveSyncError::InvalidOwner);
    }
    let field = thread.add(kthread_layout::KERNEL_APC_DISABLE) as *mut i16;
    let current = core::ptr::read_unaligned(field);
    let next = current
        .checked_sub(1)
        .ok_or(ExecutiveSyncError::ApcDisableOverflow)?;
    core::ptr::write_unaligned(field, next);
    Ok(next)
}

/// Re-enables one level of normal kernel APC delivery.
///
/// # Safety
/// `thread` must point to a writable native x64 `KTHREAD` projection.
pub unsafe fn leave_critical_region(thread: *mut u8) -> Result<i16, ExecutiveSyncError> {
    if thread.is_null() {
        return Err(ExecutiveSyncError::InvalidOwner);
    }
    let field = thread.add(kthread_layout::KERNEL_APC_DISABLE) as *mut i16;
    let current = core::ptr::read_unaligned(field);
    if current >= 0 {
        return Err(ExecutiveSyncError::ApcDisableUnderflow);
    }
    let next = current
        .checked_add(1)
        .ok_or(ExecutiveSyncError::ApcDisableUnderflow)?;
    core::ptr::write_unaligned(field, next);
    Ok(next)
}

/// Disables both normal and special kernel APC delivery for the current thread.
///
/// # Safety
/// `thread` must point to a writable native x64 `KTHREAD` projection.
pub unsafe fn enter_guarded_region(thread: *mut u8) -> Result<i16, ExecutiveSyncError> {
    if thread.is_null() {
        return Err(ExecutiveSyncError::InvalidOwner);
    }
    let field = thread.add(kthread_layout::SPECIAL_APC_DISABLE) as *mut i16;
    let current = core::ptr::read_unaligned(field);
    let next = current
        .checked_sub(1)
        .ok_or(ExecutiveSyncError::ApcDisableOverflow)?;
    core::ptr::write_unaligned(field, next);
    Ok(next)
}

/// Re-enables one level of special kernel APC delivery.
///
/// # Safety
/// `thread` must point to a writable native x64 `KTHREAD` projection.
pub unsafe fn leave_guarded_region(thread: *mut u8) -> Result<i16, ExecutiveSyncError> {
    if thread.is_null() {
        return Err(ExecutiveSyncError::InvalidOwner);
    }
    let field = thread.add(kthread_layout::SPECIAL_APC_DISABLE) as *mut i16;
    let current = core::ptr::read_unaligned(field);
    if current >= 0 {
        return Err(ExecutiveSyncError::ApcDisableUnderflow);
    }
    let next = current
        .checked_add(1)
        .ok_or(ExecutiveSyncError::ApcDisableUnderflow)?;
    core::ptr::write_unaligned(field, next);
    Ok(next)
}

/// Initializes inline `FAST_MUTEX` storage, including its synchronization event.
///
/// # Safety
/// `mutex` must point to [`fast_mutex_layout::SIZE_OF`] writable bytes.
pub unsafe fn initialize_fast_mutex(mutex: *mut u8) -> Result<(), ExecutiveSyncError> {
    if mutex.is_null() || (mutex as usize & 7) != 0 {
        return Err(ExecutiveSyncError::InvalidAddress);
    }
    core::ptr::write_bytes(mutex, 0, fast_mutex_layout::SIZE_OF);
    core::ptr::write_unaligned(mutex.add(fast_mutex_layout::COUNT) as *mut i32, 1);
    crate::kevent::init_kevent(
        mutex.add(fast_mutex_layout::EVENT),
        crate::EventKind::Synchronization,
        false,
    );
    Ok(())
}

/// Attempts an unsafe fast-mutex acquire without changing IRQL or APC state.
///
/// # Safety
/// `mutex` must contain initialized native `FAST_MUTEX` storage.
pub unsafe fn acquire_fast_mutex_unsafe(
    mutex: *mut u8,
    thread: u64,
) -> Result<AcquireResult, ExecutiveSyncError> {
    if mutex.is_null() || (mutex as usize & 7) != 0 {
        return Err(ExecutiveSyncError::InvalidAddress);
    }
    if thread == 0 {
        return Err(ExecutiveSyncError::InvalidOwner);
    }
    let count = core::ptr::read_unaligned(mutex.add(fast_mutex_layout::COUNT) as *const i32);
    let owner = core::ptr::read_unaligned(mutex.add(fast_mutex_layout::OWNER) as *const u64);
    if owner == thread {
        return Err(ExecutiveSyncError::FastMutexRecursiveAcquire);
    }
    if count == 1 && owner == 0 {
        core::ptr::write_unaligned(mutex.add(fast_mutex_layout::COUNT) as *mut i32, 0);
        core::ptr::write_unaligned(mutex.add(fast_mutex_layout::OWNER) as *mut u64, thread);
        return Ok(AcquireResult::Acquired);
    }
    if count > 1 || (count == 1 && owner != 0) || (count <= 0 && owner == 0) {
        return Err(ExecutiveSyncError::FastMutexCorrupt);
    }
    Ok(AcquireResult::WouldBlock)
}

/// Releases an unsafe fast mutex owned by `thread`.
///
/// # Safety
/// `mutex` must contain initialized native `FAST_MUTEX` storage.
pub unsafe fn release_fast_mutex_unsafe(
    mutex: *mut u8,
    thread: u64,
) -> Result<(), ExecutiveSyncError> {
    if mutex.is_null() || (mutex as usize & 7) != 0 {
        return Err(ExecutiveSyncError::InvalidAddress);
    }
    if thread == 0 {
        return Err(ExecutiveSyncError::InvalidOwner);
    }
    let count = core::ptr::read_unaligned(mutex.add(fast_mutex_layout::COUNT) as *const i32);
    let owner = core::ptr::read_unaligned(mutex.add(fast_mutex_layout::OWNER) as *const u64);
    if owner != thread || count != 0 {
        return Err(ExecutiveSyncError::NotOwned);
    }
    core::ptr::write_unaligned(mutex.add(fast_mutex_layout::OWNER) as *mut u64, 0);
    core::ptr::write_unaligned(mutex.add(fast_mutex_layout::COUNT) as *mut i32, 1);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(align(8))]
    struct Aligned<const N: usize>([u8; N]);

    unsafe fn read_u64(base: *const u8, offset: usize) -> u64 {
        core::ptr::read_unaligned(base.add(offset) as *const u64)
    }

    unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
        core::ptr::read_unaligned(base.add(offset) as *const u32)
    }

    unsafe fn read_i16(base: *const u8, offset: usize) -> i16 {
        core::ptr::read_unaligned(base.add(offset) as *const i16)
    }

    #[test]
    fn native_layout_constants_match_x64_contract() {
        assert_eq!(eresource_layout::OWNER_TABLE, 0x10);
        assert_eq!(eresource_layout::ACTIVE_COUNT, 0x18);
        assert_eq!(eresource_layout::OWNER_ENTRY, 0x30);
        assert_eq!(eresource_layout::ACTIVE_ENTRIES, 0x40);
        assert_eq!(eresource_layout::SPIN_LOCK, 0x60);
        assert_eq!(eresource_layout::SIZE_OF, 0x68);
        assert_eq!(fast_mutex_layout::EVENT, 0x18);
        assert_eq!(fast_mutex_layout::SIZE_OF, 0x38);
    }

    #[test]
    fn exclusive_recursion_projects_and_unwinds() {
        let mut bytes = Aligned([0xaau8; eresource_layout::SIZE_OF]);
        let resource = bytes.0.as_mut_ptr();
        let mut store = ExecutiveResourceStore::new();
        unsafe {
            store.initialize(resource).unwrap();
            assert_eq!(
                store.acquire(resource, 0x1000, ResourceMode::Exclusive),
                Ok(AcquireResult::Acquired)
            );
            assert_eq!(
                store.acquire(resource, 0x1000, ResourceMode::Exclusive),
                Ok(AcquireResult::Acquired)
            );
            assert!(store
                .is_acquired_exclusive(resource as u64, 0x1000)
                .unwrap());
            assert_eq!(store.acquired_count(resource as u64, 0x1000), Ok(2));
            assert_eq!(read_i16(resource, eresource_layout::ACTIVE_COUNT), 1);
            assert_eq!(read_u32(resource, eresource_layout::ACTIVE_ENTRIES), 1);
            assert_eq!(read_u64(resource, eresource_layout::OWNER_ENTRY), 0x1000);
            assert_ne!(
                read_u32(resource, eresource_layout::FLAG) & RESOURCE_OWNED_EXCLUSIVE as u32,
                0
            );
            store.release(resource, 0x1000).unwrap();
            assert_eq!(store.acquired_count(resource as u64, 0x1000), Ok(1));
            store.release(resource, 0x1000).unwrap();
            assert_eq!(read_i16(resource, eresource_layout::ACTIVE_COUNT), 0);
            assert_eq!(read_u32(resource, eresource_layout::ACTIVE_ENTRIES), 0);
        }
    }

    #[test]
    fn multiple_readers_get_a_native_owner_table() {
        let mut bytes = Aligned([0u8; eresource_layout::SIZE_OF]);
        let resource = bytes.0.as_mut_ptr();
        let mut store = ExecutiveResourceStore::new();
        unsafe {
            store.initialize(resource).unwrap();
            store
                .acquire(resource, 0x1000, ResourceMode::Shared)
                .unwrap();
            store
                .acquire(resource, 0x2000, ResourceMode::Shared)
                .unwrap();
            assert_eq!(read_u32(resource, eresource_layout::ACTIVE_ENTRIES), 2);
            assert_eq!(read_u64(resource, eresource_layout::OWNER_ENTRY), 0x1000);
            let table = read_u64(resource, eresource_layout::OWNER_TABLE) as *const u8;
            assert!(!table.is_null());
            assert_eq!(
                read_u32(table, owner_entry_layout::OWNER_COUNT_OR_TABLE_SIZE),
                3
            );
            assert_eq!(read_u64(table, owner_entry_layout::SIZE_OF), 0x2000);
            store.release(resource, 0x2000).unwrap();
            assert_eq!(read_u32(resource, eresource_layout::ACTIVE_ENTRIES), 1);
        }
    }

    #[test]
    fn contention_never_fabricates_ownership() {
        let mut bytes = Aligned([0u8; eresource_layout::SIZE_OF]);
        let resource = bytes.0.as_mut_ptr();
        let mut store = ExecutiveResourceStore::new();
        unsafe {
            store.initialize(resource).unwrap();
            store
                .acquire(resource, 0x1000, ResourceMode::Shared)
                .unwrap();
            assert_eq!(
                store.acquire(resource, 0x2000, ResourceMode::Exclusive),
                Ok(AcquireResult::WouldBlock)
            );
            assert_eq!(store.acquired_count(resource as u64, 0x2000), Ok(0));
            assert_eq!(read_u32(resource, eresource_layout::ACTIVE_ENTRIES), 1);
            assert_eq!(
                store.acquire(resource, 0x1000, ResourceMode::Exclusive),
                Ok(AcquireResult::WouldBlock)
            );
            assert_eq!(store.acquired_count(resource as u64, 0x1000), Ok(1));
        }
    }

    #[test]
    fn release_and_delete_are_owner_checked() {
        let mut bytes = Aligned([0u8; eresource_layout::SIZE_OF]);
        let resource = bytes.0.as_mut_ptr();
        let mut store = ExecutiveResourceStore::new();
        unsafe {
            store.initialize(resource).unwrap();
            store
                .acquire(resource, 0x1000, ResourceMode::Exclusive)
                .unwrap();
            assert_eq!(
                store.release(resource, 0x2000),
                Err(ExecutiveSyncError::NotOwned)
            );
            assert_eq!(
                store.delete(resource),
                Err(ExecutiveSyncError::ResourceBusy)
            );
            store.release(resource, 0x1000).unwrap();
            store.delete(resource).unwrap();
            assert_eq!(
                store.acquire(resource, 0x1000, ResourceMode::Shared),
                Err(ExecutiveSyncError::NotInitialized)
            );
        }
    }

    #[test]
    fn critical_regions_balance_native_apc_disable() {
        let mut thread = Aligned([0u8; 0x280]);
        unsafe {
            assert_eq!(enter_critical_region(thread.0.as_mut_ptr()), Ok(-1));
            assert_eq!(enter_critical_region(thread.0.as_mut_ptr()), Ok(-2));
            assert_eq!(
                read_i16(thread.0.as_ptr(), kthread_layout::KERNEL_APC_DISABLE),
                -2
            );
            assert_eq!(leave_critical_region(thread.0.as_mut_ptr()), Ok(-1));
            assert_eq!(leave_critical_region(thread.0.as_mut_ptr()), Ok(0));
            assert_eq!(
                leave_critical_region(thread.0.as_mut_ptr()),
                Err(ExecutiveSyncError::ApcDisableUnderflow)
            );
            assert_eq!(enter_guarded_region(thread.0.as_mut_ptr()), Ok(-1));
            assert_eq!(
                read_i16(thread.0.as_ptr(), kthread_layout::SPECIAL_APC_DISABLE),
                -1
            );
            assert_eq!(leave_guarded_region(thread.0.as_mut_ptr()), Ok(0));
            assert_eq!(
                leave_guarded_region(thread.0.as_mut_ptr()),
                Err(ExecutiveSyncError::ApcDisableUnderflow)
            );
        }
    }

    #[test]
    fn fast_mutex_records_owner_and_rejects_recursion() {
        let mut bytes = Aligned([0xaau8; fast_mutex_layout::SIZE_OF]);
        let mutex = bytes.0.as_mut_ptr();
        unsafe {
            initialize_fast_mutex(mutex).unwrap();
            assert_eq!(read_u32(mutex, fast_mutex_layout::COUNT), 1);
            assert_eq!(
                acquire_fast_mutex_unsafe(mutex, 0x1000),
                Ok(AcquireResult::Acquired)
            );
            assert_eq!(read_u32(mutex, fast_mutex_layout::COUNT), 0);
            assert_eq!(read_u64(mutex, fast_mutex_layout::OWNER), 0x1000);
            assert_eq!(
                acquire_fast_mutex_unsafe(mutex, 0x1000),
                Err(ExecutiveSyncError::FastMutexRecursiveAcquire)
            );
            assert_eq!(
                acquire_fast_mutex_unsafe(mutex, 0x2000),
                Ok(AcquireResult::WouldBlock)
            );
            assert_eq!(
                release_fast_mutex_unsafe(mutex, 0x2000),
                Err(ExecutiveSyncError::NotOwned)
            );
            release_fast_mutex_unsafe(mutex, 0x1000).unwrap();
            assert_eq!(read_u32(mutex, fast_mutex_layout::COUNT), 1);
            assert_eq!(read_u64(mutex, fast_mutex_layout::OWNER), 0);
        }
    }
}
