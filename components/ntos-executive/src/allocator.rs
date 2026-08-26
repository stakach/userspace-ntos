//! A small global allocator for the spawned components.
//!
//! Unlike the in-process M7b component, these components' image `.bss` is mapped
//! **read-only** (shared image frames), so allocator metadata can't be ordinary
//! mutable statics. The bump counter and free-list head live in the first bytes
//! of the **RW heap region** the broker maps at [`HEAP_BASE`]; allocations start
//! past them. Each component has its own heap frames at the same vaddr, and each
//! is single-threaded, so no locks are needed. The retype-zeroed heap gives empty
//! metadata. Spawned components must publish the number of mapped heap frames
//! before their first allocation; the initial executive retains the full arena.

use core::alloc::{GlobalAlloc, Layout};
use core::mem::{align_of, size_of};
use core::ptr::{copy_nonoverlapping, null_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

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
/// executive gets a dedicated desktop-sized arena (was a cramped 128 KiB that OOM'd during registry
/// enum, forcing per-syscall mark/reset). Spawned services map a declared subset of this address
/// range; ordinary components use [`DEFAULT_SERVICE_HEAP_FRAMES`].
/// ★ RAISED 512 -> 1536 (2 MiB -> 6 MiB). The 2 MiB cap was measured at **1953957/2097152 = 93%**
/// at the winlogon profile frontier: the CM overlay, the writable volume and every `*_dirty`
/// mark-pin move the permanent floor, and a heap that reaches its cap does not panic — allocations
/// start returning null and callers quietly take their error paths, which is what a mysteriously
/// slow, never-quiescing boot looks like from outside. The materialised profile tree and the
/// per-user hive load need headroom above that, so the executive gets it.
/// ★ RAISED 1536 -> 1792 (6 MiB -> 7 MiB) once Dbgk stopped allocating late and instead precharged
/// bounded `DEBUG_OBJECT` slots/event queues before the service-loop reset mark. That is durable NT
/// object state, not transient proof scaffolding, and the previous full boot ended with only a few
/// KiB free under the 6 MiB cap.
/// ★ RAISED 1792 -> 2048 (7 MiB -> 8 MiB) when the live mutable-hive authority started owning
/// installed setup state and shell COM class provisioning directly in mounted hives. The prior green
/// boot measured 6.82 MiB used under the 7 MiB cap, leaving too little room for that durable CM
/// state before the service-loop reset mark. Spawned service heaps remain capped separately below.
/// ★ RAISED 2048 -> 4096 (8 MiB -> 16 MiB) after the growable PnP launch/status cleanup produced a
/// real desktop proof with only about 128 KiB left under the executive bump cap while the measured
/// root-Untyped pool still had about 59 MiB free. This is a local executive-arena ceiling, not a
/// BOOTBOOT/initrd or general VM-memory limit.
/// ★ RAISED 4096 -> 6144 (16 MiB -> 24 MiB) when real boot-hive checkpoints replaced the
/// journal-only acknowledgement. Retaining the five primary images raised the measured live floor
/// to 14.24 MiB and left only 861 KiB contiguous, causing Explorer process-parameter construction
/// to fail. The extra 8 MiB is mapped from root Untyped at runtime and does not enlarge the loaded
/// executable or initrd. Isolated-service heap profiles remain independently bounded.
pub const HEAP_FRAMES: u64 = 6144;
/// Default heap frames mapped into an isolated component. Services that own larger durable state
/// declare a larger profile at spawn time instead of charging every component for that capacity.
pub const DEFAULT_SERVICE_HEAP_FRAMES: u64 = 128;

const HEAP_SIZE: usize = (HEAP_FRAMES as usize) * 0x1000;
const CTR: usize = HEAP_BASE; // 8-byte bump offset, in the RW heap
const FREE_HEAD: usize = HEAP_BASE + 8; // 8-byte address of the first free-list node
/// Component-local metadata words available to modules that cannot use mutable image statics.
pub const COMPONENT_LOCAL_WORD_BASE: usize = HEAP_BASE + 16;
pub const COMPONENT_LOCAL_WORDS: usize = 6;
const MAPPED_HEAP_BYTES: usize =
    COMPONENT_LOCAL_WORD_BASE + (COMPONENT_LOCAL_WORDS - 1) * size_of::<usize>();
const DATA: usize = HEAP_BASE + 64; // allocations start past allocator/local metadata
const _: () = assert!(MAPPED_HEAP_BYTES + size_of::<usize>() <= DATA);
const WORD: usize = size_of::<usize>();
const ALLOC_GRANULE: usize = align_of::<usize>();
const FREE_NODE_SIZE: usize = WORD * 2; // { size, next } stored inside the freed block

struct Bump;

static OOM_REPORTED: AtomicBool = AtomicBool::new(false);
static OOM_CONTEXT: AtomicU32 = AtomicU32::new(0);
static OOM_SCOPE_PTR: AtomicUsize = AtomicUsize::new(0);
static OOM_SCOPE_LEN: AtomicUsize = AtomicUsize::new(0);

pub const ALLOC_CTX_REGF_IMPORT: u32 = 1;
pub const ALLOC_CTX_HIVE_ENCODE: u32 = 2;
pub const ALLOC_CTX_WRITABLE_SNAPSHOT: u32 = 3;
pub const ALLOC_CTX_WRITABLE_ATOMIC_WRITE: u32 = 4;
pub const ALLOC_CTX_NT_LOAD_KEY: u32 = 5;

pub struct AllocContext {
    previous: u32,
}

pub struct AllocScope {
    previous_ptr: usize,
    previous_len: usize,
}

impl Drop for AllocContext {
    fn drop(&mut self) {
        OOM_CONTEXT.store(self.previous, Ordering::Relaxed);
    }
}

impl Drop for AllocScope {
    fn drop(&mut self) {
        OOM_SCOPE_PTR.store(self.previous_ptr, Ordering::Relaxed);
        OOM_SCOPE_LEN.store(self.previous_len, Ordering::Relaxed);
    }
}

pub fn enter_context(context: u32) -> AllocContext {
    let previous = OOM_CONTEXT.swap(context, Ordering::Relaxed);
    AllocContext { previous }
}

pub fn enter_scope(scope: &'static [u8]) -> AllocScope {
    let previous_ptr = OOM_SCOPE_PTR.swap(scope.as_ptr() as usize, Ordering::Relaxed);
    let previous_len = OOM_SCOPE_LEN.swap(scope.len(), Ordering::Relaxed);
    AllocScope {
        previous_ptr,
        previous_len,
    }
}

fn debug_bytes(bytes: &[u8]) {
    for &byte in bytes {
        crate::debug_put_char(byte);
    }
}

fn debug_usize(mut value: usize) {
    let mut buf = [b'0'; 20];
    let mut i = buf.len();
    if value == 0 {
        crate::debug_put_char(b'0');
        return;
    }
    while value != 0 && i != 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    debug_bytes(&buf[i..]);
}

fn debug_context(context: u32) {
    let label: &[u8] = match context {
        ALLOC_CTX_REGF_IMPORT => b"regf-import",
        ALLOC_CTX_HIVE_ENCODE => b"hive-encode",
        ALLOC_CTX_WRITABLE_SNAPSHOT => b"writable-snapshot",
        ALLOC_CTX_WRITABLE_ATOMIC_WRITE => b"writable-atomic-write",
        ALLOC_CTX_NT_LOAD_KEY => b"nt-load-key",
        _ => b"unknown",
    };
    debug_bytes(label);
}

fn report_oom(size: usize, align: usize, cur: usize, start: usize, requested_end: usize) {
    if OOM_REPORTED.swap(true, Ordering::Relaxed) {
        return;
    }
    debug_bytes(b"[alloc-oom] size=");
    debug_usize(size);
    debug_bytes(b" align=");
    debug_usize(align);
    debug_bytes(b" cur=");
    debug_usize(cur);
    debug_bytes(b" start=");
    debug_usize(start);
    debug_bytes(b" requested-end=");
    debug_usize(requested_end);
    debug_bytes(b" cap=");
    debug_usize(heap_size());
    let context = OOM_CONTEXT.load(Ordering::Relaxed);
    if context != 0 {
        debug_bytes(b" ctx=");
        debug_context(context);
    }
    let scope_ptr = OOM_SCOPE_PTR.load(Ordering::Relaxed);
    let scope_len = OOM_SCOPE_LEN.load(Ordering::Relaxed);
    if scope_ptr != 0 && scope_len != 0 {
        debug_bytes(b" scope=");
        // SAFETY: scopes are static byte strings installed through `enter_scope`.
        debug_bytes(unsafe { core::slice::from_raw_parts(scope_ptr as *const u8, scope_len) });
    }
    crate::debug_put_char(b'\n');
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    Some(value.checked_add(align - 1)? & !(align - 1))
}

fn block_size(size: usize) -> Option<usize> {
    align_up(size.max(FREE_NODE_SIZE), ALLOC_GRANULE)
}

unsafe fn read_word(addr: usize) -> usize {
    unsafe { read_volatile(addr as *const usize) }
}

unsafe fn write_word(addr: usize, value: usize) {
    unsafe { write_volatile(addr as *mut usize, value) };
}

/// Publish the heap mapping installed by the component broker.
///
/// This must be the first operation performed by a spawned executive-image component. A zero
/// frame count is valid for components that never map or use the global heap. The initial
/// executive does not call this function and therefore retains [`HEAP_FRAMES`].
pub unsafe fn initialize_mapped_heap(frames: u64) -> bool {
    if frames == 0 {
        return true;
    }
    if frames > HEAP_FRAMES
        || unsafe { read_word(CTR) } != 0
        || unsafe { read_word(FREE_HEAD) } != 0
    {
        return false;
    }
    let bytes = frames as usize * 0x1000;
    let current = unsafe { read_word(MAPPED_HEAP_BYTES) };
    if current != 0 && current != bytes {
        return false;
    }
    unsafe { write_word(MAPPED_HEAP_BYTES, bytes) };
    true
}

#[inline]
fn heap_size() -> usize {
    let configured = unsafe { read_word(MAPPED_HEAP_BYTES) };
    if configured == 0 {
        HEAP_SIZE
    } else {
        configured.min(HEAP_SIZE)
    }
}

#[inline]
fn heap_end() -> usize {
    HEAP_BASE + heap_size()
}

unsafe fn free_node_size(node: usize) -> usize {
    unsafe { read_word(node) }
}

unsafe fn free_node_next(node: usize) -> usize {
    unsafe { read_word(node + WORD) }
}

unsafe fn set_free_node(node: usize, size: usize, next: usize) {
    unsafe {
        write_word(node, size);
        write_word(node + WORD, next);
    }
}

unsafe fn insert_free_block(start: usize, size: usize) {
    if size < FREE_NODE_SIZE
        || start < DATA
        || start.checked_add(size).is_none_or(|end| end > heap_end())
    {
        return;
    }

    let mut prev = 0usize;
    let mut prev_link = FREE_HEAD;
    let mut cur = unsafe { read_word(FREE_HEAD) };
    while cur != 0 && cur < start {
        prev = cur;
        prev_link = cur + WORD;
        cur = unsafe { free_node_next(cur) };
    }
    if cur == start {
        return;
    }

    unsafe {
        set_free_node(start, size, cur);
        write_word(prev_link, start);
    }

    let block = start;
    let mut block_size = size;
    if cur != 0 && block.checked_add(block_size) == Some(cur) {
        let merged_size = block_size.saturating_add(unsafe { free_node_size(cur) });
        let merged_next = unsafe { free_node_next(cur) };
        unsafe { set_free_node(block, merged_size, merged_next) };
        block_size = merged_size;
    }

    if prev != 0 {
        let prev_size = unsafe { free_node_size(prev) };
        if prev.checked_add(prev_size) == Some(block) {
            let merged_size = prev_size.saturating_add(block_size);
            let merged_next = unsafe { free_node_next(block) };
            unsafe { set_free_node(prev, merged_size, merged_next) };
        }
    }
}

unsafe fn release_top_free_blocks() {
    loop {
        let top = DATA + unsafe { read_word(CTR) };
        let mut prev_link = FREE_HEAD;
        let mut cur = unsafe { read_word(FREE_HEAD) };
        let mut released = false;
        while cur != 0 {
            let size = unsafe { free_node_size(cur) };
            let next = unsafe { free_node_next(cur) };
            if cur.checked_add(size) == Some(top) {
                unsafe {
                    write_word(prev_link, next);
                    write_word(CTR, cur - DATA);
                }
                released = true;
                break;
            }
            prev_link = cur + WORD;
            cur = next;
        }
        if !released {
            break;
        }
    }
}

unsafe fn trim_free_list_to(limit: usize) {
    let mut prev_link = FREE_HEAD;
    let mut cur = unsafe { read_word(FREE_HEAD) };
    while cur != 0 {
        let size = unsafe { free_node_size(cur) };
        let next = unsafe { free_node_next(cur) };
        if cur >= limit {
            unsafe { write_word(prev_link, next) };
            cur = next;
            continue;
        }
        if cur.checked_add(size).is_some_and(|end| end > limit) {
            let trimmed = limit - cur;
            if trimmed >= FREE_NODE_SIZE {
                unsafe { set_free_node(cur, trimmed, next) };
                prev_link = cur + WORD;
            } else {
                unsafe { write_word(prev_link, next) };
            }
            cur = next;
            continue;
        }
        prev_link = cur + WORD;
        cur = next;
    }
}

unsafe fn alloc_from_free_list(layout: Layout, needed: usize) -> *mut u8 {
    let align = layout.align().max(ALLOC_GRANULE);
    let mut prev_link = FREE_HEAD;
    let mut cur = unsafe { read_word(FREE_HEAD) };
    while cur != 0 {
        let size = unsafe { free_node_size(cur) };
        let next = unsafe { free_node_next(cur) };
        let mut start = match align_up(cur, align) {
            Some(start) => start,
            None => return null_mut(),
        };
        let mut prefix = start - cur;
        if prefix != 0 && prefix < FREE_NODE_SIZE {
            start = match align_up(cur + FREE_NODE_SIZE, align) {
                Some(start) => start,
                None => return null_mut(),
            };
            prefix = start - cur;
        }
        if prefix
            .checked_add(needed)
            .is_some_and(|total| total <= size)
        {
            unsafe { write_word(prev_link, next) };
            if prefix >= FREE_NODE_SIZE {
                unsafe { insert_free_block(cur, prefix) };
            }
            let suffix_start = start + needed;
            let suffix = cur + size - suffix_start;
            if suffix >= FREE_NODE_SIZE {
                unsafe { insert_free_block(suffix_start, suffix) };
            }
            return start as *mut u8;
        }
        prev_link = cur + WORD;
        cur = next;
    }
    null_mut()
}

unsafe fn grow_in_place_from_adjacent_free(start: usize, old_size: usize, new_size: usize) -> bool {
    let adjacent = match start.checked_add(old_size) {
        Some(adjacent) => adjacent,
        None => return false,
    };
    let need = new_size - old_size;
    let mut prev_link = FREE_HEAD;
    let mut cur = unsafe { read_word(FREE_HEAD) };
    while cur != 0 {
        let size = unsafe { free_node_size(cur) };
        let next = unsafe { free_node_next(cur) };
        if cur == adjacent && size >= need {
            if size - need >= FREE_NODE_SIZE {
                let new_free = cur + need;
                unsafe {
                    set_free_node(new_free, size - need, next);
                    write_word(prev_link, new_free);
                }
            } else {
                unsafe { write_word(prev_link, next) };
            }
            return true;
        }
        prev_link = cur + WORD;
        cur = next;
    }
    false
}

// SAFETY: single-threaded per component; allocator metadata lives in the component-local RW heap
// and is accessed only by this allocator. Free blocks are returned to the list only through
// `dealloc`/`realloc` for dead allocations, and alignment is applied to each returned pointer.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(size) = block_size(layout.size()) else {
            report_oom(
                layout.size(),
                layout.align(),
                unsafe { read_word(CTR) },
                0,
                usize::MAX,
            );
            return null_mut();
        };
        let from_free = unsafe { alloc_from_free_list(layout, size) };
        if !from_free.is_null() {
            return from_free;
        }

        let cur = unsafe { read_word(CTR) }; // 0 on a freshly-zeroed heap frame
        let start = match align_up(DATA + cur, layout.align().max(ALLOC_GRANULE)) {
            Some(start) => start,
            None => {
                report_oom(layout.size(), layout.align(), cur, cur, usize::MAX);
                return null_mut();
            }
        };
        let requested_end = start.saturating_add(layout.size());
        let end = match start.checked_add(size) {
            Some(e) if e <= heap_end() => e,
            _ => {
                report_oom(
                    layout.size(),
                    layout.align(),
                    cur,
                    start - DATA,
                    requested_end - DATA,
                );
                return null_mut();
            }
        };
        unsafe { write_word(CTR, end - DATA) };
        start as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() || layout.size() == 0 {
            return;
        }
        let start = ptr as usize;
        let Some(size) = block_size(layout.size()) else {
            return;
        };
        unsafe {
            insert_free_block(start, size);
            release_top_free_blocks();
        };
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            let Ok(layout) = Layout::from_size_align(new_size, old_layout.align()) else {
                return null_mut();
            };
            return unsafe { self.alloc(layout) };
        }
        if new_size == 0 {
            unsafe { self.dealloc(ptr, old_layout) };
            return null_mut();
        }

        let start = ptr as usize;
        let old_size = old_layout.size();
        let Some(old_block_size) = block_size(old_size) else {
            return null_mut();
        };
        let Some(new_block_size) = block_size(new_size) else {
            return null_mut();
        };

        if new_block_size <= old_block_size {
            let tail = old_block_size - new_block_size;
            if tail >= FREE_NODE_SIZE {
                unsafe {
                    insert_free_block(start + new_block_size, tail);
                    release_top_free_blocks();
                }
            }
            return ptr;
        }

        let old_end = match start.checked_add(old_block_size) {
            Some(end) => end,
            None => return null_mut(),
        };
        let cur_end = DATA + unsafe { read_word(CTR) };
        let heap_end = heap_end();
        if start >= DATA && old_end <= heap_end && old_end == cur_end {
            let Some(new_end) = start.checked_add(new_block_size) else {
                report_oom(
                    new_size,
                    old_layout.align(),
                    start - DATA,
                    start - DATA,
                    usize::MAX,
                );
                return null_mut();
            };
            if new_end <= heap_end {
                unsafe { write_word(CTR, new_end - DATA) };
                return ptr;
            }
            report_oom(
                new_size,
                old_layout.align(),
                old_end - DATA,
                start - DATA,
                new_end - DATA,
            );
            return null_mut();
        }

        if unsafe { grow_in_place_from_adjacent_free(start, old_block_size, new_block_size) } {
            return ptr;
        }

        let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
            return null_mut();
        };
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            unsafe { copy_nonoverlapping(ptr, new_ptr, old_size.min(new_size)) };
            unsafe { self.dealloc(ptr, old_layout) };
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: Bump = Bump;

/// Current bump offset — a heap "high-water mark".
///
/// The allocator reuses dropped blocks, but `mark`/[`reset_to`] is still the syscall loop's bulk
/// transient reclamation tool. A caller that knows a region of work allocates only *transient*
/// objects can snapshot the mark before it and reset after, reclaiming everything above the mark in
/// one operation. SAFETY CONTRACT: nothing allocated after the mark may still be live when
/// `reset_to` runs; it may be handed out again.
pub fn mark() -> usize {
    unsafe { read_word(CTR) }
}

/// Bytes still available above the current bump mark.
pub fn remaining() -> usize {
    heap_size()
        .saturating_sub(DATA - HEAP_BASE)
        .saturating_sub(mark())
}

#[derive(Copy, Clone)]
pub struct HeapUsage {
    pub bump: usize,
    pub allocated: usize,
    pub reusable: usize,
    pub largest_reusable: usize,
    pub top_reusable: usize,
}

/// Snapshot bump occupancy and reusable free-list storage.
///
/// `bump` is an address-space watermark, not live allocation bytes. Dropped allocations below a
/// later durable object remain reusable through the free list even when they cannot lower it.
pub fn usage() -> HeapUsage {
    let bump = mark();
    let top_reusable = remaining();
    let mut free_bytes = 0usize;
    let mut largest_free = 0usize;
    let mut node = unsafe { read_word(FREE_HEAD) };
    let mut guard = 0usize;
    let max_nodes = heap_size() / FREE_NODE_SIZE;
    while node != 0 && guard < max_nodes {
        let size = unsafe { free_node_size(node) };
        free_bytes = free_bytes.saturating_add(size);
        largest_free = largest_free.max(size);
        node = unsafe { free_node_next(node) };
        guard += 1;
    }
    HeapUsage {
        bump,
        allocated: bump.saturating_sub(free_bytes),
        reusable: top_reusable.saturating_add(free_bytes),
        largest_reusable: top_reusable.max(largest_free),
        top_reusable,
    }
}

const fn rewind_target(requested: usize, current: usize, capacity: usize) -> usize {
    let target = if requested < current {
        requested
    } else {
        current
    };
    if target < capacity {
        target
    } else {
        capacity
    }
}

const _: () = assert!(rewind_target(12, 8, 16) == 8);
const _: () = assert!(rewind_target(4, 8, 16) == 4);
const _: () = assert!(rewind_target(20, 24, 16) == 16);

/// Rewind the bump counter to a [`mark`], reclaiming everything allocated since.
///
/// # Safety
/// All allocations made after `m` must be dead (unreferenced) at this point.
pub unsafe fn reset_to(m: usize) {
    let current = unsafe { read_word(CTR) };
    let bounded = rewind_target(m, current, heap_size().saturating_sub(DATA - HEAP_BASE));
    unsafe {
        write_word(CTR, bounded);
        trim_free_list_to(DATA + bounded);
    }
}
