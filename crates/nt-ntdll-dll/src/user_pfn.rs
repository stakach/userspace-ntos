//! Process-local USER client procedure table registration.

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

type NtStatus = u32;
const STATUS_SUCCESS: NtStatus = 0;
const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 0xff;
const INITIALIZED: u8 = 1;

struct UserPfnRegistry {
    state: AtomicU8,
    client_a: AtomicPtr<c_void>,
    client_w: AtomicPtr<c_void>,
    client_worker: AtomicPtr<c_void>,
}

impl UserPfnRegistry {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(UNINITIALIZED),
            client_a: AtomicPtr::new(core::ptr::null_mut()),
            client_w: AtomicPtr::new(core::ptr::null_mut()),
            client_worker: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    fn initialize(
        &self,
        client_a: *const c_void,
        client_a_size: u32,
        client_w: *const c_void,
        client_w_size: u32,
        client_worker: *const c_void,
        client_worker_size: u32,
    ) -> NtStatus {
        if client_a.is_null()
            || client_w.is_null()
            || client_worker.is_null()
            || client_a_size == 0
            || client_w_size == 0
            || client_worker_size == 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        if self
            .state
            .compare_exchange(
                UNINITIALIZED,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return STATUS_INVALID_PARAMETER;
        }

        self.client_a.store(client_a.cast_mut(), Ordering::Relaxed);
        self.client_w.store(client_w.cast_mut(), Ordering::Relaxed);
        self.client_worker
            .store(client_worker.cast_mut(), Ordering::Relaxed);
        self.state.store(INITIALIZED, Ordering::Release);
        STATUS_SUCCESS
    }

    fn retrieve(
        &self,
        client_a: &mut *const c_void,
        client_w: &mut *const c_void,
        client_worker: &mut *const c_void,
    ) -> NtStatus {
        if self.state.load(Ordering::Acquire) != INITIALIZED {
            return STATUS_INVALID_PARAMETER;
        }
        *client_a = self.client_a.load(Ordering::Relaxed);
        *client_w = self.client_w.load(Ordering::Relaxed);
        *client_worker = self.client_worker.load(Ordering::Relaxed);
        STATUS_SUCCESS
    }

    fn reset(&self) -> NtStatus {
        if self
            .state
            .compare_exchange(
                INITIALIZED,
                UNINITIALIZED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            STATUS_INVALID_PARAMETER
        } else {
            STATUS_SUCCESS
        }
    }
}

static USER_PFN: UserPfnRegistry = UserPfnRegistry::new();

/// Register the released USER client procedure tables once per process.
///
/// # Safety
/// Each non-null input points to a readable table of its stated byte length and remains live while
/// registered. The pointers are stored, not dereferenced here.
#[export_name = "RtlInitializeNtUserPfn"]
pub unsafe extern "system" fn rtl_initialize_nt_user_pfn(
    client_a: *const c_void,
    client_a_size: u32,
    client_w: *const c_void,
    client_w_size: u32,
    client_worker: *const c_void,
    client_worker_size: u32,
) -> NtStatus {
    USER_PFN.initialize(
        client_a,
        client_a_size,
        client_w,
        client_w_size,
        client_worker,
        client_worker_size,
    )
}

/// Return the currently registered USER client procedure tables.
///
/// # Safety
/// All three output pointers must be writable, as required by the pinned LiberNT contract.
#[export_name = "RtlRetrieveNtUserPfn"]
pub unsafe extern "system" fn rtl_retrieve_nt_user_pfn(
    client_a: *mut *const c_void,
    client_w: *mut *const c_void,
    client_worker: *mut *const c_void,
) -> NtStatus {
    if USER_PFN.state.load(Ordering::Acquire) != INITIALIZED {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller supplies three writable pointers; LiberNT does not accept null outputs.
    unsafe { USER_PFN.retrieve(&mut *client_a, &mut *client_w, &mut *client_worker) }
}

/// Make the USER client procedure table registry available for another initialization.
#[export_name = "RtlResetNtUserPfn"]
pub extern "system" fn rtl_reset_nt_user_pfn() -> NtStatus {
    USER_PFN.reset()
}

#[used]
pub static USER_PFN_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = user_pfn_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// This routine is only stored in a `#[used]` static.
pub unsafe extern "C" fn user_pfn_export_anchor() {
    core::hint::black_box([
        rtl_initialize_nt_user_pfn as *const () as usize,
        rtl_retrieve_nt_user_pfn as *const () as usize,
        rtl_reset_nt_user_pfn as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_is_single_owner_until_reset() {
        let registry = UserPfnRegistry::new();
        let a = 1usize as *const c_void;
        let w = 2usize as *const c_void;
        let worker = 3usize as *const c_void;
        let mut out_a = core::ptr::null();
        let mut out_w = core::ptr::null();
        let mut out_worker = core::ptr::null();

        assert_eq!(
            registry.retrieve(&mut out_a, &mut out_w, &mut out_worker),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(registry.reset(), STATUS_INVALID_PARAMETER);
        assert_eq!(
            registry.initialize(core::ptr::null(), 1, w, 1, worker, 1),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            registry.initialize(a, 0, w, 1, worker, 1),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(registry.initialize(a, 1, w, 1, worker, 1), STATUS_SUCCESS);
        assert_eq!(
            registry.initialize(a, 1, w, 1, worker, 1),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            registry.retrieve(&mut out_a, &mut out_w, &mut out_worker),
            STATUS_SUCCESS
        );
        assert_eq!((out_a, out_w, out_worker), (a, w, worker));
        assert_eq!(registry.reset(), STATUS_SUCCESS);
        assert_eq!(
            registry.retrieve(&mut out_a, &mut out_w, &mut out_worker),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(registry.initialize(a, 1, w, 1, worker, 1), STATUS_SUCCESS);
    }
}
