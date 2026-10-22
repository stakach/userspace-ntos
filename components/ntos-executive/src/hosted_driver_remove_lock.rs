//! Native `IO_REMOVE_LOCK` ABI for hosted WDM drivers.
//!
//! The lock and embedded event stay in the provider's memory. The existing KEVENT broker owns
//! blocked wait replies across callbacks, and a final release signals that exact event.

use super::*;
use nt_io_manager::remove_lock::{valid_remove_lock_size, Acquire, RemoveLockState};

const EVENT_OFFSET: u64 = 8;
const DEBUG_SIZE: u32 = 120;
const DEBUG_TAIL_OFFSET: u64 = 32;
const DEBUG_TAIL_SIZE: usize = 88;
const DEBUG_HIGH_WATERMARK_OFFSET: u64 = 36;
const DEBUG_MAX_TICKS_OFFSET: u64 = 40;
const DEBUG_TAG_OFFSET: u64 = 48;
const DEBUG_SPIN_OFFSET: u64 = 72;
const DEBUG_LOW_MEMORY_OFFSET: u64 = 80;
const DEBUG_BLOCKS_OFFSET: u64 = 112;
const TRACKING_BLOCK_SIZE: u64 = 40;
const STATUS_DELETE_PENDING: i32 = nt_status::NtStatus::DELETE_PENDING.raw();

fn valid(lock: u64, size: u32) -> bool {
    lock != 0 && lock & 7 == 0 && lock.checked_add(size as u64).is_some()
        && valid_remove_lock_size(size)
}

fn invalid(lock: u64, size: u32, operation: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [lock, size as u64, operation, 0]); }
}

fn descriptor(lock: u64, size: u32, operation: u64) -> &'static RemoveLockState {
    if !valid(lock, size) { invalid(lock, size, operation); }
    // SAFETY: a hosted WDM caller owns the aligned descriptor in its private address space.
    // Initialize constructed this exact common prefix before any concurrent use.
    unsafe { &*(lock as *const RemoveLockState) }
}

fn tick_count() -> u64 {
    // The shared TSC frequency belongs to this isolated provider component. Do not consult
    // executive-local clock state from a direct native import.
    let frequency = unsafe { read_volatile((FSD_SHARED_VADDR + SH_TSC_FREQUENCY_HZ) as *const u64) };
    if frequency == 0 { invalid(0, DEBUG_SIZE, 10); }
    let increment = s_ke_query_time_increment() as u128;
    ((read_ordered_tsc() as u128) * 10_000_000u128 / ((frequency as u128) * increment)) as u64
}

fn debug_initialize(lock: u64, tag: u32, minutes: u32, high_watermark: u32) {
    // SAFETY: initialization exclusively owns the checked 120-byte descriptor.
    unsafe {
        core::ptr::write_bytes((lock + DEBUG_TAIL_OFFSET) as *mut u8, 0, DEBUG_TAIL_SIZE);
        write_unaligned((lock + DEBUG_TAIL_OFFSET) as *mut u32, 0x434f_4c52); // 'COLR'
        write_unaligned((lock + DEBUG_HIGH_WATERMARK_OFFSET) as *mut u32, high_watermark);
        let max_ticks = (minutes as u64).saturating_mul(60).saturating_mul(10_000_000)
            / s_ke_query_time_increment() as u64;
        write_unaligned((lock + DEBUG_MAX_TICKS_OFFSET) as *mut u64, max_ticks);
        write_unaligned((lock + DEBUG_TAG_OFFSET) as *mut u32, tag);
    }
    hosted_driver_spin_lock::initialize(lock + DEBUG_SPIN_OFFSET);
}

fn debug_acquire(lock: u64, tag: u64, file: u64, line: u32) {
    let high_watermark = unsafe { read_unaligned((lock + DEBUG_HIGH_WATERMARK_OFFSET) as *const u32) };
    if high_watermark != 0 && descriptor(lock, DEBUG_SIZE, 6).outstanding() > high_watermark {
        invalid(lock, DEBUG_SIZE, 6);
    }
    let alloc_tag = unsafe { read_unaligned((lock + DEBUG_TAG_OFFSET) as *const u32) };
    let block = s_ex_alloc_pool_tag(0, TRACKING_BLOCK_SIZE, alloc_tag as u64);
    if block == 0 {
        let low_memory = unsafe { &*((lock + DEBUG_LOW_MEMORY_OFFSET) as *const core::sync::atomic::AtomicI32) };
        low_memory.fetch_add(1, Ordering::SeqCst);
        return;
    }
    unsafe {
        write_unaligned((block + 8) as *mut u64, tag);
        write_unaligned((block + 16) as *mut u64, tick_count());
        write_unaligned((block + 24) as *mut u64, file);
        write_unaligned((block + 32) as *mut u32, line);
    }
    let old_irql = hosted_driver_spin_lock::acquire_raise_to_dpc(lock + DEBUG_SPIN_OFFSET);
    unsafe {
        let head = read_unaligned((lock + DEBUG_BLOCKS_OFFSET) as *const u64);
        write_unaligned(block as *mut u64, head);
        write_unaligned((lock + DEBUG_BLOCKS_OFFSET) as *mut u64, block);
    }
    hosted_driver_spin_lock::release_restore_irql(lock + DEBUG_SPIN_OFFSET, old_irql);
}

fn debug_release_tag(lock: u64, tag: u64) {
    let old_irql = hosted_driver_spin_lock::acquire_raise_to_dpc(lock + DEBUG_SPIN_OFFSET);
    let max_ticks = unsafe { read_unaligned((lock + DEBUG_MAX_TICKS_OFFSET) as *const u64) };
    let now = tick_count();
    let mut link = lock + DEBUG_BLOCKS_OFFSET;
    let mut found = 0;
    loop {
        let block = unsafe { read_unaligned(link as *const u64) };
        if block == 0 { break; }
        let moment = unsafe { read_unaligned((block + 16) as *const u64) };
        if max_ticks != 0 && now.saturating_sub(moment) > max_ticks {
            hosted_driver_spin_lock::release_restore_irql(lock + DEBUG_SPIN_OFFSET, old_irql);
            invalid(lock, DEBUG_SIZE, 7);
        }
        let block_tag = unsafe { read_unaligned((block + 8) as *const u64) };
        if block_tag == tag && found == 0 {
            let next = unsafe { read_unaligned(block as *const u64) };
            unsafe { write_unaligned(link as *mut u64, next); }
            found = block;
            continue;
        }
        link = block;
    }
    hosted_driver_spin_lock::release_restore_irql(lock + DEBUG_SPIN_OFFSET, old_irql);
    if found != 0 {
        let alloc_tag = unsafe { read_unaligned((lock + DEBUG_TAG_OFFSET) as *const u32) };
        s_ex_free_pool_tag(found, alloc_tag as u64);
    } else {
        let low_memory = unsafe { &*((lock + DEBUG_LOW_MEMORY_OFFSET) as *const core::sync::atomic::AtomicI32) };
        let mut misses = low_memory.load(Ordering::SeqCst);
        loop {
            if misses <= 0 { invalid(lock, DEBUG_SIZE, 8); }
            match low_memory.compare_exchange_weak(misses, misses - 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(current) => misses = current,
            }
        }
    }
}

/// `VOID IoInitializeRemoveLockEx(PIO_REMOVE_LOCK, ULONG, ULONG, ULONG, ULONG)`.
pub(super) extern "win64" fn initialize(lock: u64, tag: u32, minutes: u32, high_watermark: u32, size: u32) {
    if !valid(lock, size) { invalid(lock, size, 1); }
    // SAFETY: initialization is exclusive to the driver's descriptor lifetime. Only the
    // common prefix is written; the optional DBG tail remains the driver's own storage.
    unsafe { core::ptr::write(lock as *mut RemoveLockState, RemoveLockState::new()); }
    s_ke_initialize_event(lock + EVENT_OFFSET, 1, 0);
    if size == DEBUG_SIZE { debug_initialize(lock, tag, minutes, high_watermark); }
}

/// `NTSTATUS IoAcquireRemoveLockEx(PIO_REMOVE_LOCK, PVOID, LPCSTR, ULONG, ULONG)`.
pub(super) extern "win64" fn acquire(lock: u64, tag: u64, file: u64, line: u32, size: u32) -> i32 {
    if !valid(lock, size) { return STATUS_INVALID_PARAMETER; }
    match descriptor(lock, size, 2).acquire() {
        Acquire::Acquired => {
            if size == DEBUG_SIZE { debug_acquire(lock, tag, file, line); }
            0
        }
        Acquire::DeletePending { wake_remove_waiter } => {
            if wake_remove_waiter { let _ = s_ke_set_event(lock + EVENT_OFFSET, 0, 0); }
            STATUS_DELETE_PENDING
        }
    }
}

/// `VOID IoReleaseRemoveLockEx(PIO_REMOVE_LOCK, PVOID, ULONG)`.
pub(super) extern "win64" fn release(lock: u64, tag: u64, size: u32) {
    let state = descriptor(lock, size, 3);
    if !state.has_live_reference() { invalid(lock, size, 3); }
    if size == DEBUG_SIZE { debug_release_tag(lock, tag); }
    if state.release() {
        let _ = s_ke_set_event(lock + EVENT_OFFSET, 0, 0);
    }
}

/// `VOID IoReleaseRemoveLockAndWaitEx(PIO_REMOVE_LOCK, PVOID, ULONG)`.
pub(super) extern "win64" fn release_and_wait(lock: u64, tag: u64, size: u32) {
    let state = descriptor(lock, size, 4);
    if !state.has_live_reference() { invalid(lock, size, 4); }
    if !state.begin_remove_and_wait() {
        let status = s_ke_wait_for_single_object(lock + EVENT_OFFSET, 0, 0, 0, 0);
        if status != 0 { invalid(lock, size, 5); }
    }
    if size == DEBUG_SIZE {
        debug_release_tag(lock, tag);
        if unsafe { read_unaligned((lock + DEBUG_BLOCKS_OFFSET) as *const u64) } != 0 {
            invalid(lock, size, 9);
        }
    }
}

pub(crate) fn bind_remove_lock_exports(reg: &mut nt_compat_exports::DriverExportRegistry) {
    reg.bind("IoInitializeRemoveLockEx", initialize as usize as u64);
    reg.bind("IoAcquireRemoveLockEx", acquire as usize as u64);
    reg.bind("IoReleaseRemoveLockEx", release as usize as u64);
    reg.bind("IoReleaseRemoveLockAndWaitEx", release_and_wait as usize as u64);
}
