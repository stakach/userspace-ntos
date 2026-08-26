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
/// Root-executive-only transient lane. It shares the existing heap mapping but grows downward from
/// its top, so dispatch-local buffers can never fragment durable objects growing upward below it.
/// Spawned components retain their complete declared heap as durable storage.
pub const EXECUTIVE_TRANSIENT_HEAP_FRAMES: u64 = 1024;
const EXECUTIVE_TRANSIENT_HEAP_SIZE: usize = (EXECUTIVE_TRANSIENT_HEAP_FRAMES as usize) * 0x1000;
const _: () = assert!(EXECUTIVE_TRANSIENT_HEAP_FRAMES < HEAP_FRAMES);
const CTR: usize = HEAP_BASE; // 8-byte bump offset, in the RW heap
const FREE_HEAD: usize = HEAP_BASE + 8; // 8-byte address of the first free-list node
/// Component-local metadata words available to modules that cannot use mutable image statics.
pub const COMPONENT_LOCAL_WORD_BASE: usize = HEAP_BASE + 16;
pub const COMPONENT_LOCAL_WORDS: usize = 6;
const MAPPED_HEAP_BYTES: usize =
    COMPONENT_LOCAL_WORD_BASE + (COMPONENT_LOCAL_WORDS - 1) * size_of::<usize>();
const TRANSIENT_CTR: usize = HEAP_BASE + 64; // bytes consumed downward from the mapped heap end
const TRANSIENT_DEPTH: usize = HEAP_BASE + 72; // nested transient allocation scopes
const TRANSIENT_HIGH_WATER: usize = HEAP_BASE + 80; // peak transient bytes consumed
const DURABLE_FLOOR: usize = HEAP_BASE + 88; // bump watermark protected from bulk rewind
const DATA: usize = HEAP_BASE + 128; // allocations start past allocator/local metadata
const _: () = assert!(MAPPED_HEAP_BYTES + size_of::<usize>() <= TRANSIENT_CTR);
const _: () = assert!(TRANSIENT_HIGH_WATER + size_of::<usize>() <= DURABLE_FLOOR);
const _: () = assert!(DURABLE_FLOOR + size_of::<usize>() <= DATA);
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

/// Scoped routing of global allocations into the root executive's rewindable transient lane.
///
/// The guard is deliberately not exposed as a mark/reset pair: nested scopes rewind in LIFO order,
/// and values allocated while it is live must be dropped before the guard. Durable objects must not
/// be created inside this scope.
pub struct TransientAllocScope {
    previous_mark: usize,
    previous_depth: usize,
    active: bool,
}

/// Temporarily preserve durable allocation routing inside an outer transient scope.
pub struct DurableAllocScope {
    previous_transient_depth: usize,
    active: bool,
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

impl Drop for TransientAllocScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        debug_assert_eq!(
            unsafe { read_word(TRANSIENT_DEPTH) },
            self.previous_depth + 1
        );
        unsafe {
            write_word(TRANSIENT_CTR, self.previous_mark);
            write_word(TRANSIENT_DEPTH, self.previous_depth);
        }
    }
}

impl Drop for DurableAllocScope {
    fn drop(&mut self) {
        if self.active {
            unsafe { write_word(TRANSIENT_DEPTH, self.previous_transient_depth) };
        }
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

/// Route allocations to the root executive's transient lane until the returned guard is dropped.
/// Spawned services have no transient lane and continue using their declared durable heap.
pub fn enter_transient() -> TransientAllocScope {
    let active = transient_heap_size() != 0;
    let previous_mark = if active {
        unsafe { read_word(TRANSIENT_CTR) }
    } else {
        0
    };
    let previous_depth = if active {
        unsafe { read_word(TRANSIENT_DEPTH) }
    } else {
        0
    };
    if active {
        unsafe { write_word(TRANSIENT_DEPTH, previous_depth + 1) };
    }
    TransientAllocScope {
        previous_mark,
        previous_depth,
        active,
    }
}

/// Route allocations to durable storage while an outer transient scope remains live.
///
/// This is for publication operations, such as minting a handle after transient name lookup. The
/// returned guard must not outlive the surrounding transient guard.
pub fn enter_durable() -> DurableAllocScope {
    let active = transient_heap_size() != 0;
    let previous_transient_depth = if active {
        unsafe { read_word(TRANSIENT_DEPTH) }
    } else {
        0
    };
    if active {
        unsafe { write_word(TRANSIENT_DEPTH, 0) };
    }
    DurableAllocScope {
        previous_transient_depth,
        active,
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

fn debug_hex_usize(value: usize) {
    debug_bytes(b"0x");
    let mut shift = usize::BITS;
    let mut started = false;
    while shift != 0 {
        shift -= 4;
        let nibble = ((value >> shift) & 0xf) as u8;
        if nibble != 0 || started || shift == 0 {
            started = true;
            crate::debug_put_char(if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            });
        }
    }
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
fn mapped_heap_end() -> usize {
    HEAP_BASE + heap_size()
}

#[inline]
fn transient_heap_size() -> usize {
    // A zero configured size identifies the initial/root executive. Every spawned component must
    // publish its mapped size before allocating and retains that complete profile as durable heap.
    if unsafe { read_word(MAPPED_HEAP_BYTES) } == 0 {
        EXECUTIVE_TRANSIENT_HEAP_SIZE.min(heap_size())
    } else {
        0
    }
}

#[inline]
fn transient_heap_start() -> usize {
    mapped_heap_end() - transient_heap_size()
}

#[inline]
fn durable_heap_end() -> usize {
    transient_heap_start()
}

#[inline]
fn durable_heap_capacity() -> usize {
    durable_heap_end().saturating_sub(DATA)
}

#[inline]
fn is_transient_pointer(ptr: usize) -> bool {
    transient_heap_size() != 0 && ptr >= transient_heap_start() && ptr < mapped_heap_end()
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

#[cold]
#[inline(never)]
fn allocator_corruption(
    operation: &'static [u8],
    owner_start: usize,
    owner_size: usize,
    node: usize,
    node_size: usize,
    next: usize,
) -> ! {
    debug_bytes(b"[alloc-corrupt] op=");
    debug_bytes(operation);
    debug_bytes(b" owner=");
    debug_hex_usize(owner_start);
    debug_bytes(b" owner-size=");
    debug_usize(owner_size);
    debug_bytes(b" node=");
    debug_hex_usize(node);
    debug_bytes(b" node-size=");
    debug_usize(node_size);
    debug_bytes(b" next=");
    debug_hex_usize(next);
    debug_bytes(b" bump=");
    debug_usize(unsafe { read_word(CTR) });
    let scope_ptr = OOM_SCOPE_PTR.load(Ordering::Relaxed);
    let scope_len = OOM_SCOPE_LEN.load(Ordering::Relaxed);
    if scope_ptr != 0 && scope_len != 0 {
        debug_bytes(b" scope=");
        // SAFETY: scopes are static byte strings installed through `enter_scope`.
        debug_bytes(unsafe { core::slice::from_raw_parts(scope_ptr as *const u8, scope_len) });
    }
    crate::debug_put_char(b'\n');
    panic!("allocator free-list corruption");
}

/// Validate the complete address-ordered free list before following any link. A damaged node must
/// fail at the first allocator boundary instead of being copied into `FREE_HEAD` and surfacing later
/// as an unrelated low-address rootserver page fault.
unsafe fn validate_free_list(operation: &'static [u8], owner_start: usize, owner_size: usize) {
    let top = DATA + unsafe { read_word(CTR) };
    let mut previous_end = DATA;
    let mut node = unsafe { read_word(FREE_HEAD) };
    let mut guard = 0usize;
    let max_nodes = durable_heap_capacity() / FREE_NODE_SIZE;
    while node != 0 {
        if node < DATA
            || node >= top
            || node % ALLOC_GRANULE != 0
            || guard >= max_nodes
        {
            allocator_corruption(operation, owner_start, owner_size, node, 0, 0);
        }
        let size = unsafe { free_node_size(node) };
        let next = unsafe { free_node_next(node) };
        let Some(end) = node.checked_add(size) else {
            allocator_corruption(operation, owner_start, owner_size, node, size, next);
        };
        if node < previous_end
            || size < FREE_NODE_SIZE
            || size % ALLOC_GRANULE != 0
            || end > top
            || (next != 0
                && (next <= node
                    || next < end
                    || next >= top
                    || next % ALLOC_GRANULE != 0))
        {
            allocator_corruption(operation, owner_start, owner_size, node, size, next);
        }
        previous_end = end;
        node = next;
        guard += 1;
    }
}

unsafe fn insert_free_block(start: usize, size: usize) {
    let allocated_end = DATA + unsafe { read_word(CTR) };
    if size < FREE_NODE_SIZE
        || start < DATA
        || start
            .checked_add(size)
            .is_none_or(|end| end > allocated_end)
    {
        allocator_corruption(b"insert", start, size, start, size, 0);
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
    let end = start + size;
    if (prev != 0
        && prev
            .checked_add(unsafe { free_node_size(prev) })
            .is_none_or(|prev_end| prev_end > start))
        || (cur != 0 && end > cur)
    {
        allocator_corruption(b"insert-overlap", start, size, cur, 0, 0);
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

impl Bump {
    unsafe fn alloc_durable(&self, layout: Layout) -> *mut u8 {
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
            Some(e) if e <= durable_heap_end() => e,
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

    unsafe fn alloc_transient(&self, layout: Layout) -> *mut u8 {
        let Some(size) = block_size(layout.size()) else {
            return null_mut();
        };
        let used = unsafe { read_word(TRANSIENT_CTR) };
        let top = mapped_heap_end().saturating_sub(used);
        let Some(unrounded) = top.checked_sub(size) else {
            report_oom(layout.size(), layout.align(), used, 0, usize::MAX);
            return null_mut();
        };
        let start = unrounded & !(layout.align().max(ALLOC_GRANULE) - 1);
        if start < transient_heap_start() {
            report_oom(
                layout.size(),
                layout.align(),
                used,
                start.saturating_sub(transient_heap_start()),
                transient_heap_size(),
            );
            return null_mut();
        }
        let consumed = mapped_heap_end() - start;
        unsafe {
            write_word(TRANSIENT_CTR, consumed);
            if consumed > read_word(TRANSIENT_HIGH_WATER) {
                write_word(TRANSIENT_HIGH_WATER, consumed);
            }
        }
        start as *mut u8
    }
}

// SAFETY: single-threaded per component; allocator metadata lives in the component-local RW heap
// and is accessed only by this allocator. Free blocks are returned to the list only through
// `dealloc`/`realloc` for dead allocations, and alignment is applied to each returned pointer.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if transient_heap_size() != 0 && unsafe { read_word(TRANSIENT_DEPTH) } != 0 {
            unsafe { self.alloc_transient(layout) }
        } else {
            unsafe { self.alloc_durable(layout) }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() || layout.size() == 0 {
            return;
        }
        let start = ptr as usize;
        if is_transient_pointer(start) {
            return;
        }
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
        if is_transient_pointer(start) {
            if new_size <= old_size {
                return ptr;
            }
            let Ok(new_layout) = Layout::from_size_align(new_size, old_layout.align()) else {
                return null_mut();
            };
            let new_ptr = unsafe { self.alloc_transient(new_layout) };
            if !new_ptr.is_null() {
                unsafe { copy_nonoverlapping(ptr, new_ptr, old_size) };
            }
            return new_ptr;
        }
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
        let durable_heap_end = durable_heap_end();
        if start >= DATA && old_end <= durable_heap_end && old_end == cur_end {
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
            if new_end <= durable_heap_end {
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
        // Reallocation preserves the original allocation's arena even when a transient scope is
        // active. Growing a durable Vec in a transient scope must not make it rewindable.
        let new_ptr = unsafe { self.alloc_durable(new_layout) };
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

/// Permanently retain every durable allocation made up to the current bump watermark.
///
/// Raw-pointer registries call this immediately after acquiring storage. Unlike the service-loop
/// dirty finalizer, this floor is part of the allocator's own rewind contract and therefore cannot
/// be skipped by an unusual reply, park, or teardown control path.
pub fn pin_current() {
    let current = mark();
    let floor = unsafe { read_word(DURABLE_FLOOR) };
    if current > floor {
        unsafe { write_word(DURABLE_FLOOR, current) };
    }
}

/// Bytes still available above the current bump mark.
pub fn remaining() -> usize {
    durable_heap_capacity().saturating_sub(mark())
}

#[derive(Copy, Clone)]
pub struct HeapUsage {
    pub bump: usize,
    pub allocated: usize,
    pub reusable: usize,
    pub largest_reusable: usize,
    pub top_reusable: usize,
    pub durable_capacity: usize,
    pub transient_used: usize,
    pub transient_high_water: usize,
    pub transient_capacity: usize,
}

/// Snapshot bump occupancy and reusable free-list storage.
///
/// `bump` is an address-space watermark, not live allocation bytes. Dropped allocations below a
/// later durable object remain reusable through the free list even when they cannot lower it.
pub fn usage() -> HeapUsage {
    unsafe { validate_free_list(b"usage", 0, 0) };
    let bump = mark();
    let top_reusable = remaining();
    let mut free_bytes = 0usize;
    let mut largest_free = 0usize;
    let mut node = unsafe { read_word(FREE_HEAD) };
    let mut guard = 0usize;
    let max_nodes = durable_heap_capacity() / FREE_NODE_SIZE;
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
        durable_capacity: durable_heap_capacity(),
        transient_used: unsafe { read_word(TRANSIENT_CTR) },
        transient_high_water: unsafe { read_word(TRANSIENT_HIGH_WATER) },
        transient_capacity: transient_heap_size(),
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

const fn rewind_target_with_floor(
    requested: usize,
    floor: usize,
    current: usize,
    capacity: usize,
) -> usize {
    let retained = if requested > floor { requested } else { floor };
    rewind_target(retained, current, capacity)
}

const _: () = assert!(rewind_target(12, 8, 16) == 8);
const _: () = assert!(rewind_target(4, 8, 16) == 4);
const _: () = assert!(rewind_target(20, 24, 16) == 16);
const _: () = assert!(rewind_target_with_floor(4, 12, 16, 32) == 12);
const _: () = assert!(rewind_target_with_floor(20, 12, 16, 32) == 16);

/// Rewind the bump counter to a [`mark`], reclaiming everything allocated since.
///
/// # Safety
/// All allocations made after `m` must be dead (unreferenced) at this point.
pub unsafe fn reset_to(m: usize) {
    let current = unsafe { read_word(CTR) };
    let floor = unsafe { read_word(DURABLE_FLOOR) };
    let bounded = rewind_target_with_floor(m, floor, current, durable_heap_capacity());
    unsafe {
        trim_free_list_to(DATA + bounded);
        write_word(CTR, bounded);
    }
}
