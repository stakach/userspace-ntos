//! A minimal bump global allocator for the spawned components.
//!
//! Unlike the in-process M7b component, these components' image `.bss` is mapped
//! **read-only** (shared image frames), so the bump counter can't be a static.
//! Instead it lives in the first bytes of the **RW heap region** the broker maps
//! at [`HEAP_BASE`]; allocations start past it. Each component has its own heap
//! frames at the same vaddr, and each is single-threaded, so no atomics are
//! needed. The retype-zeroed heap gives counter = 0, so there is no init step.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{null_mut, read_volatile, write_volatile};

/// Base of the RW heap region the broker maps into each component.
pub const HEAP_BASE: usize = 0x0000_0100_0048_0000;
/// Heap size in 4 KiB frames (128 KiB).
pub const HEAP_FRAMES: u64 = 64;

const HEAP_SIZE: usize = (HEAP_FRAMES as usize) * 0x1000;
const CTR: usize = HEAP_BASE; // 8-byte bump offset, in the RW heap
const DATA: usize = HEAP_BASE + 64; // allocations start past the counter
const END: usize = HEAP_BASE + HEAP_SIZE;

struct Bump;

// SAFETY: single-threaded per component; the counter (in RW heap) only advances,
// so allocations never alias. Alignment is applied to each returned pointer.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ctr = CTR as *mut usize;
        let cur = read_volatile(ctr); // 0 on a freshly-zeroed heap frame
        let start = (DATA + cur + layout.align() - 1) & !(layout.align() - 1);
        let end = match start.checked_add(layout.size()) {
            Some(e) if e <= END => e,
            _ => return null_mut(),
        };
        write_volatile(ctr, end - DATA);
        start as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOC: Bump = Bump;
