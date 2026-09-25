//! Lock-held reads from one live hosted driver's pool allocation.

use super::*;
use nt_security::ClientMemory;

pub(super) struct SourcePoolMemory {
    source: DriverInstance,
    used: u64,
    _lock: ExecutivePoolLockGuard,
}

pub(super) fn live_source(inst: DriverInstance) -> bool {
    inst.driver_id != 0
        && inst.pml4 != 0
        && inst.exec_pool_va != 0
        && inst.hosted_domain_id != 0
        && inst.hosted_domain_cookie != 0
        && instance_by_driver_id(inst.driver_id).is_some_and(|(_, current)| {
            current.pml4 == inst.pml4
                && current.exec_pool_va == inst.exec_pool_va
                && current.hosted_domain_id == inst.hosted_domain_id
                && current.hosted_domain_cookie == inst.hosted_domain_cookie
        })
}

impl SourcePoolMemory {
    pub(super) unsafe fn new(source: DriverInstance) -> Option<Self> {
        if !live_source(source) {
            return None;
        }
        let lock = hosted_instance_pool_lock(source.exec_pool_va)?;
        let used = read_volatile(source.exec_pool_va as *const u64);
        if used < POOL_DATA_OFF || used > FSD_POOL_FRAMES.checked_mul(0x1000)? {
            return None;
        }
        Some(Self {
            source,
            used,
            _lock: lock,
        })
    }

    pub(super) fn read_value<T: Copy>(&self, address: u64) -> Option<T> {
        let mut value = core::mem::MaybeUninit::<T>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                value.as_mut_ptr() as *mut u8,
                core::mem::size_of::<T>(),
            )
        };
        self.read(address, bytes)
            .then(|| unsafe { value.assume_init() })
    }
}

impl ClientMemory for SourcePoolMemory {
    fn read(&self, address: u64, dst: &mut [u8]) -> bool {
        let Some(offset) = address.checked_sub(FSD_POOL_VADDR) else {
            return false;
        };
        let Ok(length) = u64::try_from(dst.len()) else {
            return false;
        };
        let allocation = nt_io_manager::hosted_pool_range::walk_hosted_pool_allocation(
            self.used,
            POOL_DATA_OFF,
            offset,
            length,
            |header| {
                let at = self.source.exec_pool_va.checked_add(header)?;
                Some(unsafe { read_volatile(at as *const u64) })
            },
        );
        let Some(allocation) = allocation else {
            return false;
        };
        let Some(base) = FSD_POOL_VADDR.checked_add(allocation.base) else {
            return false;
        };
        if unsafe { hosted_instance_pool_allocation_is_free_unlocked(self.source, base) }
            != Some(false)
        {
            return false;
        }
        let Some(exec) = self.source.exec_pool_va.checked_add(offset) else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(exec as *const u8, dst.as_mut_ptr(), dst.len());
        }
        true
    }
}
