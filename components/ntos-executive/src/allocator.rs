//! A small global allocator for the spawned components.
//!
//! Unlike the in-process M7b component, these components' image `.bss` is mapped
//! **read-only** (shared image frames), so allocator metadata can't be ordinary
//! mutable statics. The bump counter and free-list head live in the first bytes
//! of the **RW heap region** the broker maps at [`HEAP_BASE`]; allocations start
//! past them. Each component has its own heap frames at the same vaddr, while
//! win32k lanes share one component heap and may allocate concurrently. The
//! retype-zeroed heap gives empty metadata and a heap-resident allocator lock.
//! Spawned components publish their allocation limit before their first allocation. An eager
//! heap maps that entire limit; a reserved heap commits missing pages through the authenticated
//! root pager. The initial executive retains its separate root commitment protocol.
//!
//! The one piece of allocator state outside the heap is the root executive's transient lane (its
//! rewind mark, scope depth and high-water mark). It exists only in root, where the image is
//! writable, and belongs to the executor whose stack holds the scope guards, so it lives in the
//! executor-local block.

use core::alloc::{GlobalAlloc, Layout};
use core::mem::{align_of, size_of};
use core::ptr::{copy_nonoverlapping, null_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::executor::TransientLane;

#[path = "allocator_headroom.rs"]
mod headroom;
#[path = "allocator_oom_budget.rs"]
mod oom_budget;
#[path = "allocator_free_list.rs"]
mod free_list;
use free_list::align_up;
#[path = "allocator_walk_observation.rs"]
mod walk_observation;
use walk_observation::WalkCounter;
pub use walk_observation::WalkSample;

/// The component-local heap VA. The root reserves an 88 MiB band before the scratch
/// base; its lower 32 MiB is mapped initially and later durable pages are committed on demand.
/// This band is above the executive image and worker mirrors. Isolated components have separate
/// VSpaces and retain their declared heap profiles at the same VA.
pub const HEAP_BASE: usize = 0x0000_0100_1e00_0000;
/// Maximum VA reservation in 4 KiB frames, including the root transient lane. Physical pages
/// beyond the initial root commitment are retyped and mapped only when allocations need them.
/// Spawned services map a separately declared subset, ordinarily [`DEFAULT_SERVICE_HEAP_FRAMES`].
pub const HEAP_FRAMES: u64 = 22528;
/// Frames committed before the root executive starts serving requests. Further durable pages are
/// mapped only as allocations require them; isolated services still use their declared profiles.
pub const EXECUTIVE_INITIAL_HEAP_FRAMES: u64 = 8192;
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
pub const EXECUTIVE_DURABLE_HEAP_FRAMES: u64 = HEAP_FRAMES - EXECUTIVE_TRANSIENT_HEAP_FRAMES;
const _: () = assert!(EXECUTIVE_INITIAL_HEAP_FRAMES < EXECUTIVE_DURABLE_HEAP_FRAMES);
const CTR: usize = HEAP_BASE; // 8-byte bump offset, in the RW heap
const FREE_HEAD: usize = HEAP_BASE + 8; // 8-byte address of the first free-list node
/// Component-local metadata words available to modules that cannot use mutable image statics.
pub const COMPONENT_LOCAL_WORD_BASE: usize = HEAP_BASE + 16;
pub const COMPONENT_LOCAL_WORDS: usize = 5;
const COMPONENT_HEAP_LIMIT_BYTES: usize =
    COMPONENT_LOCAL_WORD_BASE + COMPONENT_LOCAL_WORDS * size_of::<usize>();
const OOM_REPORTED: usize = HEAP_BASE + 64;
const OOM_CONTEXT: usize = HEAP_BASE + 72;
const OOM_SCOPE_PTR: usize = HEAP_BASE + 80;
const OOM_SCOPE_LEN: usize = HEAP_BASE + 88;
const LARGE_REPORTED: usize = HEAP_BASE + 96; // `[alloc-large]` counts per size class
// HEAP_BASE + 104..120 is reserved. With the word above it held the root transient lane's mark,
// depth and high-water words, which now live in the executor-local block
// (`executor::TransientLane`).
const ALLOC_LOCK: usize = HEAP_BASE + 120; // shared across lanes mapping the same heap frames
const ROOT_COMMITTED_BYTES: usize = HEAP_BASE + 128; // root-only durable pages mapped from Untyped
const DCERPC_TRACE_STATE: usize = HEAP_BASE + 136; // component-local tracing state pointer
const DRIVER_OBJECT_EXTENSIONS_STATE: usize = HEAP_BASE + 144; // component-local append-only extension head
const ALLOC_UNLOCKED: usize = 0;
const ALLOC_HELD: usize = 1;
const ALLOC_POISONED: usize = 2;
const DATA: usize = HEAP_BASE + 152; // allocations start past allocator/local metadata
const _: () = assert!(COMPONENT_HEAP_LIMIT_BYTES + size_of::<usize>() <= OOM_REPORTED);
const _: () = assert!(OOM_SCOPE_LEN + size_of::<usize>() <= LARGE_REPORTED);
const _: () = assert!(LARGE_REPORTED + size_of::<usize>() <= ALLOC_LOCK);
const _: () = assert!(ALLOC_LOCK + size_of::<usize>() <= DATA);
const _: () = assert!(ROOT_COMMITTED_BYTES + size_of::<usize>() <= DATA);
const _: () = assert!(DCERPC_TRACE_STATE + size_of::<usize>() <= DATA);
const _: () = assert!(DRIVER_OBJECT_EXTENSIONS_STATE + size_of::<usize>() <= DATA);
const WORD: usize = size_of::<usize>();
const ALLOC_GRANULE: usize = align_of::<usize>();
const FREE_NODE_SIZE: usize = WORD * 2; // { size, next } stored inside the freed block

static ALLOC_WALK: WalkCounter = WalkCounter::new();
static INSERT_WALK: WalkCounter = WalkCounter::new();
static GROW_WALK: WalkCounter = WalkCounter::new();

/// Approximate cumulative root-only walk counts; concurrent lanes may advance between loads.
pub fn walk_samples() -> [WalkSample; 3] {
    let root_heap = transient_heap_size() != 0;
    [
        ALLOC_WALK.sample(root_heap),
        INSERT_WALK.sample(root_heap),
        GROW_WALK.sample(root_heap),
    ]
}

pub(crate) fn dcerpc_trace_state_anchor() -> &'static AtomicUsize {
    unsafe { &*(DCERPC_TRACE_STATE as *const AtomicUsize) }
}

pub(crate) fn driver_object_extensions_anchor() -> &'static AtomicUsize {
    unsafe { &*(DRIVER_OBJECT_EXTENSIONS_STATE as *const AtomicUsize) }
}

struct Bump;

struct HeapLockGuard;

impl HeapLockGuard {
    fn acquire() -> Self {
        let lock = unsafe { &*(ALLOC_LOCK as *const AtomicUsize) };
        loop {
            match lock.compare_exchange_weak(
                ALLOC_UNLOCKED,
                ALLOC_HELD,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Self,
                Err(ALLOC_POISONED) => crate::park(),
                Err(_) => core::hint::spin_loop(),
            }
        }
    }
}

impl Drop for HeapLockGuard {
    fn drop(&mut self) {
        let lock = unsafe { &*(ALLOC_LOCK as *const AtomicUsize) };
        let _ = lock.compare_exchange(
            ALLOC_HELD,
            ALLOC_UNLOCKED,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}

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
/// be created inside this scope. Scope routing and the rewind mark are the calling executor's
/// [`TransientLane`]: the guard must be dropped on the executor that created it. Shared win32k
/// lanes have no transient arena and must not use it as thread-local storage.
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
        unsafe { write_word(OOM_CONTEXT, self.previous as usize) };
    }
}

impl Drop for AllocScope {
    fn drop(&mut self) {
        unsafe {
            write_word(OOM_SCOPE_PTR, self.previous_ptr);
            write_word(OOM_SCOPE_LEN, self.previous_len);
        }
    }
}

impl Drop for TransientAllocScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let lane = root_transient_lane();
        debug_assert_eq!(lane.depth.load(Ordering::Relaxed), self.previous_depth + 1);
        lane.used.store(self.previous_mark, Ordering::Relaxed);
        lane.depth.store(self.previous_depth, Ordering::Relaxed);
    }
}

impl Drop for DurableAllocScope {
    fn drop(&mut self) {
        if self.active {
            root_transient_lane().depth.store(self.previous_transient_depth, Ordering::Relaxed);
        }
    }
}

pub fn enter_context(context: u32) -> AllocContext {
    let previous = unsafe { read_word(OOM_CONTEXT) } as u32;
    unsafe { write_word(OOM_CONTEXT, context as usize) };
    AllocContext { previous }
}

pub fn enter_scope(scope: &'static [u8]) -> AllocScope {
    let previous_ptr = unsafe { read_word(OOM_SCOPE_PTR) };
    let previous_len = unsafe { read_word(OOM_SCOPE_LEN) };
    unsafe {
        write_word(OOM_SCOPE_PTR, scope.as_ptr() as usize);
        write_word(OOM_SCOPE_LEN, scope.len());
    }
    AllocScope {
        previous_ptr,
        previous_len,
    }
}

/// Route allocations to the root executive's transient lane until the returned guard is dropped.
/// Spawned services have no transient lane and continue using their declared durable heap.
pub fn enter_transient() -> TransientAllocScope {
    let Some(lane) = transient_lane() else {
        return TransientAllocScope {
            previous_mark: 0,
            previous_depth: 0,
            active: false,
        };
    };
    let previous_mark = lane.used.load(Ordering::Relaxed);
    let previous_depth = lane.depth.load(Ordering::Relaxed);
    lane.depth.store(previous_depth + 1, Ordering::Relaxed);
    TransientAllocScope {
        previous_mark,
        previous_depth,
        active: true,
    }
}

/// Route allocations to durable storage while an outer transient scope remains live.
///
/// This is for publication operations, such as minting a handle after transient name lookup. The
/// returned guard must not outlive the surrounding transient guard.
pub fn enter_durable() -> DurableAllocScope {
    let Some(lane) = transient_lane() else {
        return DurableAllocScope {
            previous_transient_depth: 0,
            active: false,
        };
    };
    let previous_transient_depth = lane.depth.load(Ordering::Relaxed);
    lane.depth.store(0, Ordering::Relaxed);
    DurableAllocScope {
        previous_transient_depth,
        active: true,
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
    let Some(emission) = oom_budget::next_oom_emission(unsafe { read_word(OOM_REPORTED) }) else {
        return;
    };
    unsafe { write_word(OOM_REPORTED, emission) };
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
    debug_bytes(b" durable-committed-cap=");
    debug_usize(durable_heap_capacity());
    debug_bytes(b" durable-reserved-cap=");
    debug_usize(transient_heap_start().saturating_sub(DATA));
    debug_bytes(b" transient-cap=");
    debug_usize(transient_heap_size());
    debug_bytes(b" receipt=");
    debug_usize(emission);
    debug_bytes(b"/");
    debug_usize(oom_budget::OOM_EMISSION_LIMIT);
    let context = unsafe { read_word(OOM_CONTEXT) } as u32;
    if context != 0 {
        debug_bytes(b" ctx=");
        debug_context(context);
    }
    let scope_ptr = unsafe { read_word(OOM_SCOPE_PTR) };
    let scope_len = unsafe { read_word(OOM_SCOPE_LEN) };
    if scope_ptr != 0 && scope_len != 0 {
        debug_bytes(b" scope=");
        // SAFETY: scopes are static byte strings installed through `enter_scope`.
        debug_bytes(unsafe { core::slice::from_raw_parts(scope_ptr as *const u8, scope_len) });
    }
    crate::debug_put_char(b'\n');
}

/// Name a large durable allocation and the scope that made it. A table that grows without
/// bound shows up here as a run of doublings long before it exhausts the heap.
fn report_large(size: usize) {
    if size < oom_budget::LARGE_ALLOCATION_BYTES {
        return;
    }
    let Some(state) = oom_budget::next_large_emission(unsafe { read_word(LARGE_REPORTED) }, size)
    else {
        return;
    };
    unsafe { write_word(LARGE_REPORTED, state) };
    debug_bytes(b"[alloc-large] size=");
    debug_usize(size);
    debug_bytes(b" scope=");
    let scope_ptr = unsafe { read_word(OOM_SCOPE_PTR) };
    let scope_len = unsafe { read_word(OOM_SCOPE_LEN) };
    if scope_ptr != 0 && scope_len != 0 {
        // SAFETY: scopes are static byte strings installed through `enter_scope`.
        debug_bytes(unsafe { core::slice::from_raw_parts(scope_ptr as *const u8, scope_len) });
    } else {
        debug_bytes(b"none");
    }
    crate::debug_put_char(b'\n');
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

/// Publish the allocation limit of an eagerly mapped component heap.
///
/// This must be the first operation performed by a spawned executive-image component. A zero
/// frame count is valid for components that never map or use the global heap. The initial
/// executive does not call this function and therefore retains [`HEAP_FRAMES`].
pub unsafe fn initialize_mapped_heap(frames: u64) -> bool {
    unsafe { initialize_heap_limit(frames) }
}

unsafe fn initialize_heap_limit(frames: u64) -> bool {
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
    let current = unsafe { read_word(COMPONENT_HEAP_LIMIT_BYTES) };
    if current != 0 && current != bytes {
        return false;
    }
    unsafe { write_word(COMPONENT_HEAP_LIMIT_BYTES, bytes) };
    true
}

/// Spawn passes a reservation limit, not a claim that all reserved pages are mapped. Missing
/// pages are committed by the authenticated root pager without reentering this allocator.
pub unsafe fn initialize_reserved_heap(frames: u64) -> bool {
    unsafe { initialize_heap_limit(frames) }
}

/// Publish root heap pages only after their frame caps and RW mappings are installed. Called at
/// boot and by the root's allocation path while the heap lock is held.
pub(crate) unsafe fn publish_root_heap_commit(frames: u64) {
    let current = (unsafe { read_word(ROOT_COMMITTED_BYTES) } / 0x1000) as u64;
    assert!(unsafe { read_word(COMPONENT_HEAP_LIMIT_BYTES) } == 0);
    assert!(frames >= EXECUTIVE_INITIAL_HEAP_FRAMES);
    assert!(frames <= EXECUTIVE_DURABLE_HEAP_FRAMES);
    assert!(frames >= current);
    unsafe { write_word(ROOT_COMMITTED_BYTES, frames as usize * 0x1000) };
}

pub(crate) fn root_heap_committed_frames() -> u64 {
    (unsafe { read_word(ROOT_COMMITTED_BYTES) } / 0x1000) as u64
}

/// Round a requested root allocation up to a 2 MiB commitment step. The terminal 4 MiB remains
/// permanently reserved for transient allocations and can never become durable storage.
pub(crate) fn root_commit_target(current_frames: u64, requested_end: usize) -> Option<u64> {
    let requested_bytes = requested_end.checked_sub(HEAP_BASE)?;
    let requested_frames = (requested_bytes as u64).div_ceil(0x1000);
    if current_frames < EXECUTIVE_INITIAL_HEAP_FRAMES
        || current_frames > EXECUTIVE_DURABLE_HEAP_FRAMES
        || requested_frames > EXECUTIVE_DURABLE_HEAP_FRAMES
    {
        return None;
    }
    if requested_frames <= current_frames {
        return Some(current_frames);
    }
    let next_window = current_frames.checked_add(512)?;
    let requested_window = requested_frames.div_ceil(512) * 512;
    Some(
        requested_window
            .max(next_window)
            .min(EXECUTIVE_DURABLE_HEAP_FRAMES),
    )
}

#[inline]
fn heap_size() -> usize {
    let configured = unsafe { read_word(COMPONENT_HEAP_LIMIT_BYTES) };
    if configured == 0 {
        HEAP_SIZE
    } else {
        configured.min(HEAP_SIZE)
    }
}

#[inline]
fn heap_limit_end() -> usize {
    HEAP_BASE + heap_size()
}

#[inline]
fn transient_heap_size() -> usize {
    // A zero configured size identifies the initial/root executive. Every spawned component must
    // publish its allocation limit before allocating; demand heaps commit pages independently.
    if unsafe { read_word(COMPONENT_HEAP_LIMIT_BYTES) } == 0 {
        EXECUTIVE_TRANSIENT_HEAP_SIZE.min(heap_size())
    } else {
        0
    }
}

/// The calling executor's transient lane. Only the root executive has one: a spawned component
/// sees the executor-local block read-only, so every caller first establishes, through
/// [`transient_heap_size`] or a pointer inside the transient reservation, that this is root.
#[inline]
fn root_transient_lane() -> &'static TransientLane {
    &crate::executor::local().transient
}

/// The calling executor's transient lane, or `None` in a spawned component.
#[inline]
fn transient_lane() -> Option<&'static TransientLane> {
    (transient_heap_size() != 0).then(root_transient_lane)
}

/// Whether the calling executor has a live transient scope that routes new allocations.
#[inline]
fn routes_transient() -> bool {
    transient_lane().is_some_and(|lane| lane.depth.load(Ordering::Relaxed) != 0)
}

#[inline]
fn transient_heap_start() -> usize {
    heap_limit_end() - transient_heap_size()
}

#[inline]
fn durable_heap_end() -> usize {
    if transient_heap_size() != 0 {
        HEAP_BASE + unsafe { read_word(ROOT_COMMITTED_BYTES) }
    } else {
        heap_limit_end()
    }
}

#[inline]
fn durable_heap_capacity() -> usize {
    durable_heap_end().saturating_sub(DATA)
}

#[inline]
fn ensure_durable_end(end: usize) -> bool {
    if end <= durable_heap_end() {
        return true;
    }
    transient_heap_size() != 0 && unsafe { crate::grow_own_heap(end) }
}

#[inline]
fn is_transient_pointer(ptr: usize) -> bool {
    transient_heap_size() != 0 && ptr >= transient_heap_start() && ptr < heap_limit_end()
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
    let scope_ptr = unsafe { read_word(OOM_SCOPE_PTR) };
    let scope_len = unsafe { read_word(OOM_SCOPE_LEN) };
    if scope_ptr != 0 && scope_len != 0 {
        debug_bytes(b" scope=");
        // SAFETY: scopes are static byte strings installed through `enter_scope`.
        debug_bytes(unsafe { core::slice::from_raw_parts(scope_ptr as *const u8, scope_len) });
    }
    crate::debug_put_char(b'\n');
    unsafe { &*(ALLOC_LOCK as *const AtomicUsize) }.store(ALLOC_POISONED, Ordering::Release);
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
        if node < DATA || node >= top || node % ALLOC_GRANULE != 0 || guard >= max_nodes {
            allocator_corruption(operation, owner_start, owner_size, node, 0, 0);
        }
        let size = unsafe { free_node_size(node) };
        let next = unsafe { free_node_next(node) };
        let Some(end) = node.checked_add(size) else {
            allocator_corruption(operation, owner_start, owner_size, node, size, next);
        };
        if (guard != 0 && node <= previous_end)
            || size < FREE_NODE_SIZE
            || size % ALLOC_GRANULE != 0
            || end > top
            || (next != 0
                && (next <= end || next >= top || next % ALLOC_GRANULE != 0))
        {
            allocator_corruption(operation, owner_start, owner_size, node, size, next);
        }
        previous_end = end;
        node = next;
        guard += 1;
    }
}

unsafe fn insert_free_block(start: usize, size: usize) {
    let list = free_list::FreeList {
        data: DATA,
        counter: CTR,
        head: FREE_HEAD,
    };
    match unsafe { list.insert(start, size) } {
        Ok(visits) => INSERT_WALK.record(transient_heap_size() != 0, visits),
        Err(corruption) => allocator_corruption(
            corruption.operation,
            start,
            size,
            corruption.node,
            corruption.size,
            corruption.next,
        ),
    }
}

unsafe fn alloc_from_free_list(layout: Layout, needed: usize) -> *mut u8 {
    let list = free_list::FreeList {
        data: DATA,
        counter: CTR,
        head: FREE_HEAD,
    };
    match unsafe { list.take_fit(layout.align(), needed) } {
        Ok(taken) => {
            let root_heap = transient_heap_size() != 0;
            if let Some(visits) = taken.prefix_reinsert_visits {
                INSERT_WALK.record(root_heap, visits);
            }
            if let Some(visits) = taken.suffix_reinsert_visits {
                INSERT_WALK.record(root_heap, visits);
            }
            ALLOC_WALK.record(root_heap, taken.inspected);
            taken.address.map_or(null_mut(), |address| address as *mut u8)
        }
        Err(error) => allocator_corruption(
            error.corruption.operation,
            error.owner_start,
            error.owner_size,
            error.corruption.node,
            error.corruption.size,
            error.corruption.next,
        ),
    }
}

unsafe fn grow_in_place_from_adjacent_free(start: usize, old_size: usize, new_size: usize) -> bool {
    let list = free_list::FreeList {
        data: DATA,
        counter: CTR,
        head: FREE_HEAD,
    };
    let result = unsafe { list.grow_adjacent(start, old_size, new_size) };
    GROW_WALK.record(transient_heap_size() != 0, result.inspected);
    result.grown
}

impl Bump {
    unsafe fn dealloc_unlocked(&self, ptr: *mut u8, layout: Layout) {
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
        };
    }

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
            Some(e) if ensure_durable_end(e) => e,
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
        let lane = root_transient_lane();
        let used = lane.used.load(Ordering::Relaxed);
        let top = heap_limit_end().saturating_sub(used);
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
        let consumed = heap_limit_end() - start;
        lane.used.store(consumed, Ordering::Relaxed);
        if consumed > lane.high_water.load(Ordering::Relaxed) {
            lane.high_water.store(consumed, Ordering::Relaxed);
        }
        start as *mut u8
    }
}

// SAFETY: allocator metadata and its lock live in the same component-local RW heap frames. Lanes
// sharing a heap serialize all free-list and bump mutations. Free blocks return through
// `dealloc`/`realloc` only for dead allocations; each returned pointer retains its alignment.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _guard = HeapLockGuard::acquire();
        if routes_transient() {
            unsafe { self.alloc_transient(layout) }
        } else {
            let allocated = unsafe { self.alloc_durable(layout) };
            if !allocated.is_null() {
                report_large(layout.size());
            }
            allocated
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _guard = HeapLockGuard::acquire();
        unsafe { self.dealloc_unlocked(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        let _guard = HeapLockGuard::acquire();
        let resized = unsafe { self.realloc_locked(ptr, old_layout, new_size) };
        if !resized.is_null()
            && !is_transient_pointer(resized as usize)
            && (ptr.is_null() || new_size > old_layout.size())
        {
            report_large(new_size);
        }
        resized
    }
}

impl Bump {
    unsafe fn realloc_locked(&self, ptr: *mut u8, old_layout: Layout, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            let Ok(layout) = Layout::from_size_align(new_size, old_layout.align()) else {
                return null_mut();
            };
            return if routes_transient() {
                unsafe { self.alloc_transient(layout) }
            } else {
                unsafe { self.alloc_durable(layout) }
            };
        }
        if new_size == 0 {
            unsafe { self.dealloc_unlocked(ptr, old_layout) };
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
                }
            }
            return ptr;
        }

        let old_end = match start.checked_add(old_block_size) {
            Some(end) => end,
            None => return null_mut(),
        };
        let cur_end = DATA + unsafe { read_word(CTR) };
        if start >= DATA && old_end <= durable_heap_end() && old_end == cur_end {
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
            if ensure_durable_end(new_end) {
                unsafe { write_word(CTR, new_end - DATA) };
                return ptr;
            }
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
            unsafe { self.dealloc_unlocked(ptr, old_layout) };
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: Bump = Bump;

/// Current durable bump offset. Dropped allocations are reused through the address-ordered free
/// list; dispatch-local bulk scratch belongs in the independent transient lane.
pub fn mark() -> usize {
    let _guard = HeapLockGuard::acquire();
    unsafe { read_word(CTR) }
}

/// Mapped bytes above the current bump mark. The root heap maps more on demand, so this is
/// not what an allocation can obtain; see [`obtainable`].
pub fn remaining() -> usize {
    let _guard = HeapLockGuard::acquire();
    durable_extent().committed_free()
}

/// Bytes an allocation above the bump mark can still obtain: mapped and free, plus the pages
/// the root heap may still commit below its transient lane.
pub fn obtainable() -> usize {
    let _guard = HeapLockGuard::acquire();
    durable_extent().obtainable()
}

/// Call with the heap lock held.
fn durable_extent() -> headroom::DurableExtent {
    headroom::DurableExtent {
        bump_end: DATA + unsafe { read_word(CTR) },
        committed_end: durable_heap_end(),
        // Only the root heap has a transient lane, and only the root heap grows.
        reservation_end: transient_heap_start(),
    }
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
    let _lock = HeapLockGuard::acquire();
    unsafe { validate_free_list(b"usage", 0, 0) };
    let bump = unsafe { read_word(CTR) };
    let top_reusable = durable_heap_capacity().saturating_sub(bump);
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
    let lane = transient_lane();
    HeapUsage {
        bump,
        allocated: bump.saturating_sub(free_bytes),
        reusable: top_reusable.saturating_add(free_bytes),
        largest_reusable: top_reusable.max(largest_free),
        top_reusable,
        durable_capacity: durable_heap_capacity(),
        transient_used: lane.map_or(0, |lane| lane.used.load(Ordering::Relaxed)),
        transient_high_water: lane.map_or(0, |lane| lane.high_water.load(Ordering::Relaxed)),
        transient_capacity: transient_heap_size(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_commitment_crosses_initial_boundary_without_touching_transient_lane() {
        let initial_end = HEAP_BASE + EXECUTIVE_INITIAL_HEAP_FRAMES as usize * 0x1000;
        assert_eq!(
            root_commit_target(EXECUTIVE_INITIAL_HEAP_FRAMES, initial_end),
            Some(EXECUTIVE_INITIAL_HEAP_FRAMES)
        );
        assert_eq!(
            root_commit_target(EXECUTIVE_INITIAL_HEAP_FRAMES, initial_end + 1),
            Some(EXECUTIVE_INITIAL_HEAP_FRAMES + 512)
        );
        assert_eq!(
            root_commit_target(
                EXECUTIVE_INITIAL_HEAP_FRAMES,
                initial_end + 513 * 0x1000,
            ),
            Some(EXECUTIVE_INITIAL_HEAP_FRAMES + 1024)
        );
        let durable_end = HEAP_BASE + EXECUTIVE_DURABLE_HEAP_FRAMES as usize * 0x1000;
        assert_eq!(
            root_commit_target(EXECUTIVE_INITIAL_HEAP_FRAMES, durable_end),
            Some(EXECUTIVE_DURABLE_HEAP_FRAMES)
        );
        assert_eq!(
            root_commit_target(EXECUTIVE_DURABLE_HEAP_FRAMES, durable_end + 1),
            None
        );
    }
}
