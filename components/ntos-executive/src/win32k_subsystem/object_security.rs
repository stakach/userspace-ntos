//! Referenced security descriptors for the provider's centralized USER object owner.

use super::*;
use core::sync::atomic::AtomicBool;
use nt_object_manager::object_security::{
    ObjectSecurityCache, ObjectSecurityCacheIo, ObjectSecurityCacheStats,
};

static BUSY: AtomicBool = AtomicBool::new(false);
static mut CACHE: ObjectSecurityCache = ObjectSecurityCache::new();

struct CacheGuard;

impl CacheGuard {
    fn acquire() -> Option<Self> {
        BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

struct PoolIo;

impl ObjectSecurityCacheIo for PoolIo {
    fn allocate_copy(&mut self, bytes: &[u8]) -> Result<u64, u32> {
        unsafe {
            let pointer = provider_pool_alloc(bytes.len() as u64, false);
            if pointer == 0 {
                return Err(STATUS_INSUFFICIENT_RESOURCES_I32 as u32);
            }
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len());
            Ok(pointer)
        }
    }

    fn free(&mut self, pointer: u64) -> Result<(), u32> {
        if unsafe { provider_pool_free(pointer) } {
            Ok(())
        } else {
            Err(STATUS_INVALID_PARAMETER_I32 as u32)
        }
    }
}

pub(crate) fn census() -> Option<ObjectSecurityCacheStats> {
    let _guard = CacheGuard::acquire()?;
    Some(unsafe { (&*core::ptr::addr_of!(CACHE)).stats() })
}

pub(super) unsafe fn retry_retirements() {
    let Some(_guard) = CacheGuard::acquire() else {
        return;
    };
    (&mut *core::ptr::addr_of_mut!(CACHE)).retry_retirements(&mut PoolIo);
}

pub(super) extern "win64" fn get(
    object: u64,
    descriptor_out: *mut u64,
    allocated_out: *mut u8,
) -> i32 {
    if descriptor_out.is_null() || allocated_out.is_null() {
        return 0xC000_0005u32 as i32;
    }
    unsafe {
        write_unaligned(descriptor_out, 0);
        write_volatile(allocated_out, 0);
        // The table borrow ends before any pool operation can yield or enter the broker.
        let mut captured = CapturedUserObjectSecurityDescriptor::empty();
        let kind = {
            let table = &*core::ptr::addr_of!(OBJ_TABLE);
            let Some((kind, descriptor)) = table.security_descriptor_by_body(object) else {
                return STATUS_INVALID_HANDLE_I32;
            };
            if let Some(bytes) = descriptor {
                captured.bytes[..bytes.len()].copy_from_slice(bytes);
                captured.len = bytes.len();
            }
            kind
        };
        let object_type = match kind {
            ObKind::Desktop => nt_object_manager::object_type::desktop_object_type_addr(),
            ObKind::WindowStation => {
                nt_object_manager::object_type::window_station_object_type_addr()
            }
            ObKind::Other => return STATUS_NOT_SUPPORTED_I32,
        } as *const nt_object_manager::object_type::ObjectType;
        // Only these two registered owners implement centralized security here. A custom
        // SecurityProcedure is a separate callout contract, never an implicit default method.
        if read_volatile(core::ptr::addr_of!((*object_type).type_info.methods[5])) != 0 {
            return STATUS_NOT_SUPPORTED_I32;
        }
        let Some(_guard) = CacheGuard::acquire() else {
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        let descriptor = (captured.len != 0).then_some(captured.as_slice());
        match (&mut *core::ptr::addr_of_mut!(CACHE)).acquire(descriptor, &mut PoolIo) {
            Ok(pointer) => {
                write_unaligned(descriptor_out, pointer);
                0
            }
            Err(status) => status as i32,
        }
    }
}

pub(super) extern "win64" fn release(descriptor: u64, allocated: u8) {
    if descriptor == 0 {
        return;
    }
    let Some(_guard) = CacheGuard::acquire() else {
        print_str(b"[object-security] reentrant descriptor release\n");
        park();
    };
    unsafe {
        let cache = &mut *core::ptr::addr_of_mut!(CACHE);
        if allocated != 0 {
            // An allocated-query release must never bypass a live cache reference.
            if cache.contains(descriptor) || !provider_pool_free(descriptor) {
                print_str(b"[object-security] invalid allocated descriptor release\n");
                park();
            }
            return;
        }
        if let Err(status) = cache.release(descriptor, &mut PoolIo) {
            print_str(b"[object-security] descriptor release status=");
            print_hex(status);
            print_str(b"\n");
        }
    }
}
