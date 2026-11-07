//! Caller-owned cache-aware rundown layout and per-processor lifetime for classpnp.sys.

use nt_kernel_exec::ExCacheAwareRundownRef;
use std::alloc::{alloc_zeroed, dealloc, Layout};

#[repr(C)]
struct NativeHeader {
    run_refs: *mut u8,
    pool_to_free: *mut u8,
    run_ref_size: u32,
    number: u32,
}

struct AlignedStorage {
    ptr: *mut u8,
    layout: Layout,
}

impl AlignedStorage {
    fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 64).expect("valid cache-aware allocation");
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "cache-aware allocation");
        Self { ptr, layout }
    }
}

impl Drop for AlignedStorage {
    fn drop(&mut self) { unsafe { dealloc(self.ptr, self.layout) } }
}

#[test]
fn cache_aware_size_and_header_match_the_pinned_classpnp_abi() {
    assert_eq!(core::mem::size_of::<NativeHeader>(), 24);
    assert_eq!(ExCacheAwareRundownRef::required_size(1, 64), Some(32));
    assert_eq!(ExCacheAwareRundownRef::required_size(2, 64), Some(24 + 3 * 64));
    assert_eq!(ExCacheAwareRundownRef::required_size(4, 64), Some(24 + 5 * 64));
    assert_eq!(ExCacheAwareRundownRef::required_size(0, 64), None);
    assert_eq!(ExCacheAwareRundownRef::required_size(2, 0), None);

    let size = ExCacheAwareRundownRef::required_size(2, 64).unwrap();
    let storage = AlignedStorage::new(size);
    let descriptor = storage.ptr.cast::<ExCacheAwareRundownRef>();
    assert!(unsafe { ExCacheAwareRundownRef::initialize_in_place(descriptor, size, 2, 64) });
    let header = unsafe { &*storage.ptr.cast::<NativeHeader>() };
    assert_eq!(header.number, 2);
    assert_eq!(header.run_ref_size, 64);
    assert!(!header.run_refs.is_null());
    assert!(header.run_refs as usize >= storage.ptr as usize + 24);
    assert_eq!((header.run_refs as usize) % 64, 0);
    assert!((header.run_refs as usize) + 64 + 8 <= (storage.ptr as usize) + size);
}

#[test]
fn cache_aware_wait_drains_each_processor_then_reinitialize_reopens_admission() {
    let size = ExCacheAwareRundownRef::required_size(2, 64).unwrap();
    let storage = AlignedStorage::new(size);
    let descriptor = storage.ptr.cast::<ExCacheAwareRundownRef>();
    assert!(unsafe { ExCacheAwareRundownRef::initialize_in_place(descriptor, size, 2, 64) });
    let owner = unsafe { &*descriptor };
    assert!(owner.acquire(0));
    assert!(owner.acquire(1));

    std::thread::scope(|scope| {
        let address = descriptor as usize;
        let waiter = scope.spawn(move || unsafe {
            (&*(address as *const ExCacheAwareRundownRef))
                .wait_for_release_with(std::thread::yield_now);
        });
        unsafe { owner.release(0); }
        unsafe { owner.release(1); }
        waiter.join().expect("both processor references must drain");
    });

    assert!(!owner.acquire(0));
    assert!(!owner.acquire(1));
    assert!(owner.reinitialize());
    assert!(owner.acquire(0));
    unsafe { owner.release(0); }
}
