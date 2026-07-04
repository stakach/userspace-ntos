//! A minimal, thread-safe **bump** global allocator over a static heap.
//!
//! The NT crates need `alloc` (Vec, Rc, …). This provides just enough heap to
//! run the object model on the kernel: an atomic bump pointer over a fixed
//! static region, with no reclamation (`dealloc` is a no-op). That is fine for a
//! bounded bring-up run; a real deployment would use a reclaiming allocator over
//! a runtime-mapped heap. The bump pointer is atomic so the two seL4 threads
//! can't corrupt it if the timer preempts mid-allocation.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{addr_of_mut, null_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 128 * 1024;

#[repr(align(16))]
#[allow(dead_code)] // accessed only via a raw pointer (`addr_of_mut!`)
struct Heap([u8; HEAP_SIZE]);

static mut HEAP: Heap = Heap([0; HEAP_SIZE]);
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Bump;

// SAFETY: `alloc` hands out non-overlapping, correctly-aligned regions of the
// static HEAP via an atomic bump pointer that only ever advances, so no two live
// allocations alias. `dealloc` does nothing (no reuse). The base is 16-aligned,
// covering every `layout.align()` the NT crates request.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = addr_of_mut!(HEAP) as *mut u8 as usize;
        let align = layout.align();
        let size = layout.size();
        loop {
            let cur = NEXT.load(Ordering::Relaxed);
            let aligned = (cur + align - 1) & !(align - 1);
            let end = match aligned.checked_add(size) {
                Some(e) if e <= HEAP_SIZE => e,
                _ => return null_mut(),
            };
            if NEXT
                .compare_exchange_weak(cur, end, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return (base + aligned) as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOC: Bump = Bump;
