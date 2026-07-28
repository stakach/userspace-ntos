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

/// Base of the RW heap region the broker maps into each component. Sits just past the executive
/// ELF + rust-micro's rootserver aux pages (guard + stack + IPC + BootInfo + extra-BootInfo), which
/// float RIGHT AFTER the loaded image; the release profile is size-optimised so the image stays
/// well below this base (if it grows into the aux zone the RO extra-BootInfo page can land on
/// HEAP_BASE and `map_own_heap`'s RW map silently fails → first heap write faults RO at 0x480000).
/// Relocated FAR above the executive ELF (its own dedicated 2 MiB page table at 0x2000_0000 =
/// 256 MiB past IMAGE_BASE), so the ELF + rootserver aux pages (which float RIGHT AFTER the loaded
/// image) have the full 64 MiB reserve to grow into without ever reaching the heap. It used to sit
/// only 512 KiB above IMAGE_BASE, so a growing image pushed the RO extra-BootInfo aux page onto
/// HEAP_BASE and the first heap write faulted RO at 0x480000.
pub const HEAP_BASE: usize = 0x0000_0100_2000_0000;
/// Heap size in 4 KiB frames — the allocator's hard cap. Now that the VA layout is roomy, the
/// executive gets a generous 2 MiB (was a cramped 128 KiB that OOM'd during registry enum, forcing
/// per-syscall mark/reset). Spawned services map only [`SERVICE_HEAP_FRAMES`] to spare the boot
/// frame budget; they never allocate near this cap.
/// ★ RAISED 512 -> 1536 (2 MiB -> 6 MiB). The 2 MiB cap was measured at **1953957/2097152 = 93%**
/// at the winlogon profile frontier: the CM overlay, the writable volume and every `*_dirty`
/// mark-pin move the permanent floor, and a no-free bump heap that reaches its cap does not panic
/// — allocations start returning null and callers quietly take their error paths, which is what a
/// mysteriously slow, never-quiescing boot looks like from outside. The materialised profile tree
/// and the per-user hive load need headroom above that, so the executive gets it.
pub const HEAP_FRAMES: u64 = 1536;
/// Heap frames mapped into a spawned service's VSpace. **Deliberately NOT raised with
/// [`HEAP_FRAMES`]** — a service's heap is per-VSpace, so tracking the executive would cost
/// `services x 1024` extra frames of boot budget for heaps that never exceed a few KiB (the
/// recorded lesson: growing the shared value starves spawns). The documented consequence is that a
/// spawned service allocating past its own 2 MiB now FAULTS instead of returning null; nothing
/// comes remotely close (the old shared 32-frame heap sufficed for them).
pub const SERVICE_HEAP_FRAMES: u64 = 512;

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

/// Current bump offset — a heap "high-water mark".
///
/// The bump allocator never reclaims on `dealloc`, so a hot loop that allocates
/// transient `Vec`/`String` per iteration (e.g. servicing thousands of registry
/// syscalls) walks the counter to `END` and the next alloc fails. A caller that
/// knows a region of work allocates only *transient* objects can snapshot the
/// mark before it and [`reset_to`] after, reclaiming everything allocated in
/// between. SAFETY CONTRACT: nothing allocated after the mark may still be live
/// when `reset_to` runs (it would be handed out again).
pub fn mark() -> usize {
    unsafe { read_volatile(CTR as *const usize) }
}

/// Rewind the bump counter to a [`mark`], reclaiming everything allocated since.
///
/// # Safety
/// All allocations made after `m` must be dead (unreferenced) at this point.
pub unsafe fn reset_to(m: usize) {
    write_volatile(CTR as *mut usize, m);
}
