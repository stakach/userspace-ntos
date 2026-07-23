//! `RtlCreateHeap` / `RtlAllocateHeap` / `RtlFreeHeap` / `RtlReAllocateHeap` / `RtlSizeHeap` /
//! `RtlDestroyHeap` — a **real** allocator.
//!
//! This is Category B: load-bearing (the loader + every DLL allocates through it), and portable, so
//! it is implemented properly rather than stubbed. The allocator is a classic **first-fit
//! free-list with boundary tags and coalescing** over a byte region. The region itself is abstract
//! (a [`Backing`]): in the real process it is committed via `NtAllocateVirtualMemory`; in tests it
//! is a plain `Vec<u8>`. Everything is therefore host-tested (alloc / free / realloc / coalesce /
//! size / exhaustion) with no target dependency.
//!
//! Layout — each block carries a boundary tag before its payload:
//! ```text
//!   [ BlockHeader | payload ... ] [ BlockHeader | payload ... ] ...
//! ```
//! `BlockHeader` holds boundary sizes, live/free state, and the allocation's optional user metadata.
//! `size`/`prev_size` are payload+header sizes in bytes; `prev_size == 0` marks the first block. Free
//! blocks are found by a linear walk (first-fit) -- adequate and simple; a size-class free-list is a
//! later optimisation, not correctness.

use core::mem::{align_of, size_of};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapLockAcquire {
    Acquired,
    Recursed,
    Contended,
    Bypassed,
    InvalidHandle,
    InvalidThread,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapLockRelease {
    Released,
    StillHeld,
    NotOwner,
}

/// Allocation-free policy model for the process heap registry's recursive exclusion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeapLockState {
    owner: u64,
    depth: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapLockPolicy {
    Internal,
    NoSerialize,
    Custom(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeapLockEntry {
    handle: u64,
    policy: HeapLockPolicy,
    state: HeapLockState,
}

/// Bounded per-heap lock policy used to verify handle-specific recursive ownership.
pub struct HeapLockTable<const N: usize> {
    entries: [Option<HeapLockEntry>; N],
}

impl<const N: usize> Default for HeapLockTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HeapLockTable<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn register(&mut self, handle: u64, policy: HeapLockPolicy) -> bool {
        if handle == 0
            || self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.handle == handle)
        {
            return false;
        }
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return false;
        };
        *slot = Some(HeapLockEntry {
            handle,
            policy,
            state: HeapLockState::new(),
        });
        true
    }

    pub fn acquire(&mut self, handle: u64, thread_id: u64) -> HeapLockAcquire {
        let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.handle == handle)
        else {
            return HeapLockAcquire::InvalidHandle;
        };
        if entry.policy == HeapLockPolicy::NoSerialize {
            HeapLockAcquire::Bypassed
        } else {
            entry.state.try_acquire(thread_id)
        }
    }

    pub fn release(&mut self, handle: u64, thread_id: u64) -> HeapLockRelease {
        let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.handle == handle)
        else {
            return HeapLockRelease::NotOwner;
        };
        if entry.policy == HeapLockPolicy::NoSerialize {
            HeapLockRelease::Released
        } else {
            entry.state.release(thread_id)
        }
    }
}

impl HeapLockState {
    pub const fn new() -> Self {
        Self { owner: 0, depth: 0 }
    }

    pub const fn owner(&self) -> u64 {
        self.owner
    }

    pub const fn depth(&self) -> u32 {
        self.depth
    }

    pub fn try_acquire(&mut self, thread_id: u64) -> HeapLockAcquire {
        if thread_id == 0 {
            return HeapLockAcquire::InvalidThread;
        }
        if self.owner == thread_id {
            if self.depth == u32::MAX {
                return HeapLockAcquire::Overflow;
            }
            self.depth += 1;
            return HeapLockAcquire::Recursed;
        }
        if self.owner != 0 {
            return HeapLockAcquire::Contended;
        }
        self.owner = thread_id;
        self.depth = 1;
        HeapLockAcquire::Acquired
    }

    pub fn release(&mut self, thread_id: u64) -> HeapLockRelease {
        if thread_id == 0 || self.owner != thread_id || self.depth == 0 {
            return HeapLockRelease::NotOwner;
        }
        self.depth -= 1;
        if self.depth != 0 {
            HeapLockRelease::StillHeld
        } else {
            self.owner = 0;
            HeapLockRelease::Released
        }
    }
}

/// Every allocation is rounded up to this alignment (the Windows heap guarantees 16-byte alignment
/// on x64, matching `MEMORY_ALLOCATION_ALIGNMENT`).
pub const HEAP_ALIGN: usize = 16;
/// Zero newly allocated or grown payload bytes.
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

/// Request per-allocation storage for `RtlSetUserValueHeap`.
pub const HEAP_SETTABLE_USER_VALUE: u32 = 0x0000_0100;
/// The three caller-controlled heap-entry flags returned by `RtlGetUserInfoHeap`.
pub const HEAP_SETTABLE_USER_FLAGS: u32 = 0x0000_0e00;

/// Native `RTL_HEAP_WALK_ENTRY` flags.
pub const RTL_HEAP_BUSY: u16 = 0x0001;
pub const RTL_HEAP_SEGMENT: u16 = 0x0002;
pub const RTL_HEAP_SETTABLE_VALUE: u16 = 0x0010;
pub const RTL_HEAP_SETTABLE_FLAGS: u16 = 0x00e0;
pub const RTL_HEAP_UNCOMMITTED_RANGE: u16 = 0x0100;

/// Block-specific arm of `RTL_HEAP_WALK_ENTRY`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlHeapWalkBlock {
    pub settable: usize,
    pub tag_index: u16,
    pub allocator_back_trace_index: u16,
    pub reserved: [u32; 2],
}

/// Segment-specific arm of `RTL_HEAP_WALK_ENTRY`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlHeapWalkSegment {
    pub committed_size: usize,
    pub uncommitted_size: usize,
    pub first_entry: *mut u8,
    pub last_entry: *mut u8,
}

/// Native union carried by `RTL_HEAP_WALK_ENTRY`.
#[repr(C)]
#[derive(Copy, Clone)]
pub union RtlHeapWalkDetails {
    pub block: RtlHeapWalkBlock,
    pub segment: RtlHeapWalkSegment,
}

/// ABI-compatible x64 heap-walk cursor and output record.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlHeapWalkEntry {
    pub data_address: *mut u8,
    pub data_size: usize,
    pub overhead_bytes: u8,
    pub segment_index: u8,
    pub flags: u16,
    pub details: RtlHeapWalkDetails,
}

impl RtlHeapWalkEntry {
    /// A zero-address cursor restarts enumeration from the heap's segment descriptor.
    pub const fn restart() -> Self {
        Self {
            data_address: core::ptr::null_mut(),
            data_size: 0,
            overhead_bytes: 0,
            segment_index: 0,
            flags: 0,
            details: RtlHeapWalkDetails {
                block: RtlHeapWalkBlock {
                    settable: 0,
                    tag_index: 0,
                    allocator_back_trace_index: 0,
                    reserved: [0; 2],
                },
            },
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HeapWalkOutcome {
    Entry,
    NoMoreEntries,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HeapWalkError {
    InvalidAddress,
    InvalidParameter,
}

/// Allocation-free summary used by `RtlQueryProcessHeapInformation`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HeapDebugSummary {
    pub base_address: *mut u8,
    pub entry_overhead: u16,
    pub bytes_committed: usize,
    pub bytes_allocated: usize,
    /// Segment descriptors plus physical busy/free block records.
    pub number_of_entries: u32,
}

/// User metadata associated with one live heap allocation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HeapUserInfo {
    /// Whether the allocation requested storage for a user value.
    pub has_user_value: bool,
    /// The stored opaque user value. Meaningful only when [`Self::has_user_value`] is true.
    pub user_value: usize,
    /// The allocation's `HEAP_SETTABLE_USER_FLAG{1,2,3}` bits.
    pub user_flags: u32,
}

/// A backing byte region for a heap. The real process commits pages via `NtAllocateVirtualMemory`;
/// the host test uses a `Vec<u8>`. The heap only needs a base pointer + length.
///
/// # Safety
/// Implementors must return a pointer valid for reads+writes over `[base, base+len)` for the
/// lifetime of the heap, with at least [`HEAP_ALIGN`] alignment.
pub unsafe trait Backing {
    /// The region base pointer.
    fn base(&self) -> *mut u8;
    /// The region length in bytes.
    fn len(&self) -> usize;
    /// Whether the region is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A boundary-tagged block header (kept in-band, immediately before each payload).
#[repr(C)]
#[derive(Copy, Clone)]
struct BlockHeader {
    /// Total block size (header + payload) in bytes.
    size: usize,
    /// The previous (physically-adjacent) block's total size, or `0` for the first block. Enables
    /// backward coalescing without a global list.
    prev_size: usize,
    /// Opaque value stored by `RtlSetUserValueHeap`.
    user_value: usize,
    /// Caller-controlled `HEAP_SETTABLE_USER_FLAGS` bits.
    user_flags: u32,
    /// Integer state bits keep corrupted in-band metadata safe to inspect.
    state: u8,
    /// Physical payload capacity not included in the caller's requested allocation size.
    unused_bytes: u8,
    /// Must remain zero; catches overwritten header padding during validation.
    reserved: u16,
}

const BLOCK_FREE: u8 = 0x01;
const BLOCK_HAS_USER_VALUE: u8 = 0x02;
const BLOCK_STATE_MASK: u8 = BLOCK_FREE | BLOCK_HAS_USER_VALUE;

impl BlockHeader {
    fn is_free(self) -> bool {
        self.state & BLOCK_FREE != 0
    }

    fn has_user_value(self) -> bool {
        self.state & BLOCK_HAS_USER_VALUE != 0
    }
}

#[inline]
const fn round_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

/// The in-band header size, rounded up to [`HEAP_ALIGN`] so every payload (which sits at
/// `block + HDR`) lands [`HEAP_ALIGN`]-aligned when the block itself is aligned.
const HDR: usize = round_up(size_of::<BlockHeader>(), HEAP_ALIGN);
const MIN_BLOCK_SIZE: usize = HDR + HEAP_ALIGN;

fn checked_block_size(payload_size: usize) -> Option<usize> {
    HDR.checked_add(payload_size.max(1))?
        .checked_add(HEAP_ALIGN - 1)
        .map(|size| size & !(HEAP_ALIGN - 1))
}

/// A first-fit free-list heap over a [`Backing`] region.
pub struct Heap<B: Backing> {
    backing: B,
    /// Aligned prefix of the backing used for physical blocks.
    region_len: usize,
    /// Whether the region has been formatted into an initial free block.
    formatted: bool,
    /// Front-end type returned by `RtlQueryHeapInformation` class 0.
    compatibility_mode: u32,
}

impl<B: Backing> Heap<B> {
    /// `RtlCreateHeap`: format `backing` into a single free block spanning the whole region.
    /// Returns `None` if the region is too small to hold even a header.
    pub fn create(backing: B) -> Option<Self> {
        let region_len = backing.len() & !(HEAP_ALIGN - 1);
        if region_len < MIN_BLOCK_SIZE {
            return None;
        }
        // The header must be at least HEAP_ALIGN-aligned so payloads land aligned.
        debug_assert!(align_of::<BlockHeader>() <= HEAP_ALIGN);
        let mut h = Heap {
            backing,
            region_len,
            formatted: false,
            compatibility_mode: 0,
        };
        // SAFETY: region is >= HDR+HEAP_ALIGN and valid per the Backing contract.
        unsafe {
            let base = h.backing.base();
            core::ptr::write(
                base as *mut BlockHeader,
                BlockHeader {
                    size: h.region_len,
                    prev_size: 0,
                    user_value: 0,
                    user_flags: 0,
                    state: BLOCK_FREE,
                    unused_bytes: 0,
                    reserved: 0,
                },
            );
        }
        h.formatted = true;
        Some(h)
    }

    /// `RtlDestroyHeap`: consume the heap, returning the backing region (the caller frees it — in
    /// the real process via `NtFreeVirtualMemory`).
    pub fn destroy(self) -> B {
        self.backing
    }

    /// Stable native heap handle. RTL heap handles identify the heap header at the start of its
    /// backing region, so distinct backing regions naturally produce distinct handles.
    pub fn handle(&self) -> *mut u8 {
        self.backing.base()
    }

    /// Current `HeapCompatibilityInformation` value.
    pub fn compatibility_mode(&self) -> u32 {
        self.compatibility_mode
    }

    /// Enable the low-fragmentation front end. Native RTL only accepts value 2 and does not
    /// support switching a heap back to the standard front end.
    pub fn enable_low_fragmentation(&mut self) {
        self.compatibility_mode = 2;
    }

    #[inline]
    fn region_end(&self) -> usize {
        self.backing.base() as usize + self.region_len
    }

    /// The block header at `ptr`, as a raw pointer (callers read/write fields through it).
    #[inline]
    fn hdr(&self, ptr: *mut u8) -> *mut BlockHeader {
        ptr as *mut BlockHeader
    }

    fn header_at_offset(&self, offset: usize) -> Option<BlockHeader> {
        if !self.formatted
            || offset % HEAP_ALIGN != 0
            || offset.checked_add(HDR)? > self.region_len
        {
            return None;
        }
        // SAFETY: the checked offset leaves a complete, aligned header inside the backing region.
        Some(unsafe { core::ptr::read(self.hdr(self.backing.base().add(offset))) })
    }

    fn validate_header(
        &self,
        offset: usize,
        expected_prev_size: usize,
        header: BlockHeader,
    ) -> Option<usize> {
        if header.size < MIN_BLOCK_SIZE
            || header.size % HEAP_ALIGN != 0
            || header.prev_size != expected_prev_size
            || header.state & !BLOCK_STATE_MASK != 0
            || header.reserved != 0
            || header.user_flags & !HEAP_SETTABLE_USER_FLAGS != 0
        {
            return None;
        }
        let next = offset.checked_add(header.size)?;
        if next > self.region_len {
            return None;
        }
        let capacity = header.size - HDR;
        if header.is_free() {
            if header.state != BLOCK_FREE
                || header.unused_bytes != 0
                || header.user_flags != 0
                || header.user_value != 0
            {
                return None;
            }
        } else if header.unused_bytes as usize > capacity {
            return None;
        }
        Some(next)
    }

    fn find_physical_block(&self, payload: *const u8) -> Option<(usize, BlockHeader)> {
        if payload.is_null() {
            return None;
        }
        let relative = (payload as usize).checked_sub(self.backing.base() as usize)?;
        if relative < HDR || relative >= self.region_len {
            return None;
        }
        let mut offset = 0usize;
        let mut previous_size = 0usize;
        while offset < self.region_len {
            let header = self.header_at_offset(offset)?;
            let next = self.validate_header(offset, previous_size, header)?;
            if offset.checked_add(HDR)? == relative {
                return Some((offset, header));
            }
            previous_size = header.size;
            offset = next;
        }
        None
    }

    fn find_block(&self, payload: *const u8) -> Option<(usize, BlockHeader)> {
        self.find_physical_block(payload)
            .filter(|(_, header)| !header.is_free())
    }

    /// Validate either the complete physical block chain or one exact live allocation.
    pub fn validate(&self, payload: Option<*const u8>) -> bool {
        if let Some(payload) = payload {
            return self.find_block(payload).is_some();
        }
        let mut offset = 0usize;
        let mut previous_size = 0usize;
        let mut previous_was_free = false;
        while offset < self.region_len {
            let Some(header) = self.header_at_offset(offset) else {
                return false;
            };
            let Some(next) = self.validate_header(offset, previous_size, header) else {
                return false;
            };
            if previous_was_free && header.is_free() {
                return false;
            }
            previous_was_free = header.is_free();
            previous_size = header.size;
            offset = next;
        }
        self.formatted && offset == self.region_len
    }

    /// Capture the native heap-debug summary from a validated physical block chain.
    ///
    /// The committed backing is one segment. Native `BytesAllocated` counts committed bytes not
    /// represented by free physical blocks, so it includes busy-block headers and alignment
    /// overhead. The caller must provide the same exclusion required by [`Self::walk_next`] when
    /// concurrent heap operations are possible.
    pub fn debug_summary(&self) -> Option<HeapDebugSummary> {
        let entry_overhead = u16::try_from(HDR).ok()?;
        let mut offset = 0usize;
        let mut previous_size = 0usize;
        let mut previous_was_free = false;
        let mut free_bytes = 0usize;
        let mut number_of_entries = 1u32;

        while offset < self.region_len {
            let header = self.header_at_offset(offset)?;
            let next = self.validate_header(offset, previous_size, header)?;
            if previous_was_free && header.is_free() {
                return None;
            }
            if header.is_free() {
                free_bytes = free_bytes.checked_add(header.size)?;
            }
            number_of_entries = number_of_entries.checked_add(1)?;
            previous_was_free = header.is_free();
            previous_size = header.size;
            offset = next;
        }
        if !self.formatted || offset != self.region_len {
            return None;
        }

        Some(HeapDebugSummary {
            base_address: self.handle(),
            entry_overhead,
            bytes_committed: self.region_len,
            bytes_allocated: self.region_len.checked_sub(free_bytes)?,
            number_of_entries,
        })
    }

    /// Return the largest currently available free payload extent.
    ///
    /// Free neighbours are coalesced eagerly by [`Self::free`], so compaction itself requires no
    /// mutation. `None` reports corrupt physical metadata; a full but valid heap returns `Some(0)`.
    pub fn compact(&self) -> Option<usize> {
        if !self.validate(None) {
            return None;
        }
        let mut largest = 0usize;
        let mut offset = 0usize;
        let mut previous_size = 0usize;
        while offset < self.region_len {
            let header = self.header_at_offset(offset)?;
            let next = self.validate_header(offset, previous_size, header)?;
            if header.is_free() {
                largest = largest.max(header.size - HDR);
            }
            previous_size = header.size;
            offset = next;
        }
        Some(largest)
    }

    fn segment_walk_entry(&self) -> RtlHeapWalkEntry {
        RtlHeapWalkEntry {
            data_address: self.backing.base(),
            data_size: 0,
            overhead_bytes: 0,
            segment_index: 0,
            flags: RTL_HEAP_SEGMENT,
            details: RtlHeapWalkDetails {
                segment: RtlHeapWalkSegment {
                    committed_size: self.region_len,
                    uncommitted_size: 0,
                    // SAFETY: a formatted heap always has a complete first header.
                    first_entry: unsafe { self.backing.base().add(HDR) },
                    last_entry: self.region_end() as *mut u8,
                },
            },
        }
    }

    fn block_walk_entry(
        &self,
        offset: usize,
        header: BlockHeader,
    ) -> Result<RtlHeapWalkEntry, HeapWalkError> {
        let capacity = header.size - HDR;
        // SAFETY: the validated block offset and header leave a complete payload in the region.
        let payload = unsafe { self.backing.base().add(offset + HDR) };
        let (data_size, overhead_bytes, flags, block) = if header.is_free() {
            (
                capacity,
                u8::try_from(HDR).map_err(|_| HeapWalkError::InvalidParameter)?,
                0,
                RtlHeapWalkBlock {
                    settable: 0,
                    tag_index: 0,
                    allocator_back_trace_index: 0,
                    reserved: [0; 2],
                },
            )
        } else {
            let unused = usize::from(header.unused_bytes);
            let mut flags =
                RTL_HEAP_BUSY | ((header.user_flags >> 4) as u16 & RTL_HEAP_SETTABLE_FLAGS);
            let settable = if header.has_user_value() {
                flags |= RTL_HEAP_SETTABLE_VALUE;
                header.user_value
            } else {
                0
            };
            (
                capacity - unused,
                u8::try_from(HDR + unused).map_err(|_| HeapWalkError::InvalidParameter)?,
                flags,
                RtlHeapWalkBlock {
                    settable,
                    tag_index: 0,
                    allocator_back_trace_index: 0,
                    reserved: [0; 2],
                },
            )
        };
        Ok(RtlHeapWalkEntry {
            data_address: payload,
            data_size,
            overhead_bytes,
            segment_index: 0,
            flags,
            details: RtlHeapWalkDetails { block },
        })
    }

    /// Advance a native heap-walk cursor through the segment descriptor and physical blocks.
    ///
    /// A caller that needs a stable multi-call snapshot must retain `RtlLockHeap`, matching native
    /// RTL. End-of-enumeration and validation errors leave the caller's entry unchanged.
    pub fn walk_next(
        &self,
        entry: &mut RtlHeapWalkEntry,
    ) -> Result<HeapWalkOutcome, HeapWalkError> {
        if !self.validate(None) {
            return Err(HeapWalkError::InvalidParameter);
        }
        let previous = *entry;
        if previous.data_address.is_null() {
            *entry = self.segment_walk_entry();
            return Ok(HeapWalkOutcome::Entry);
        }
        if previous.segment_index != 0 {
            return Err(HeapWalkError::InvalidAddress);
        }

        let next_offset = if previous.flags == RTL_HEAP_SEGMENT {
            if previous.data_address != self.backing.base() {
                return Err(HeapWalkError::InvalidAddress);
            }
            0
        } else {
            if previous.flags & !(RTL_HEAP_BUSY | RTL_HEAP_SETTABLE_VALUE | RTL_HEAP_SETTABLE_FLAGS)
                != 0
            {
                return Err(HeapWalkError::InvalidParameter);
            }
            let (offset, header) = self
                .find_physical_block(previous.data_address)
                .ok_or(HeapWalkError::InvalidAddress)?;
            let cursor_says_busy = previous.flags & RTL_HEAP_BUSY != 0;
            if cursor_says_busy == header.is_free() || (header.is_free() && previous.flags != 0) {
                return Err(HeapWalkError::InvalidParameter);
            }
            offset + header.size
        };

        if next_offset == self.region_len {
            return Ok(HeapWalkOutcome::NoMoreEntries);
        }
        let header = self
            .header_at_offset(next_offset)
            .ok_or(HeapWalkError::InvalidParameter)?;
        *entry = self.block_walk_entry(next_offset, header)?;
        Ok(HeapWalkOutcome::Entry)
    }

    /// Split `block` so it holds exactly `need` bytes total, returning the tail to the free pool if
    /// the remainder is large enough to be its own block.
    ///
    /// # Safety
    /// `block` must be a valid block header with `block.size >= need`.
    unsafe fn split(&mut self, block: *mut u8, need: usize) {
        let bh = self.hdr(block);
        let total = (*bh).size;
        let remainder = total - need;
        if remainder >= MIN_BLOCK_SIZE {
            // Carve a trailing free block.
            (*bh).size = need;
            let tail = block.add(need);
            core::ptr::write(
                tail as *mut BlockHeader,
                BlockHeader {
                    size: remainder,
                    prev_size: need,
                    user_value: 0,
                    user_flags: 0,
                    state: BLOCK_FREE,
                    unused_bytes: 0,
                    reserved: 0,
                },
            );
            // Fix the following block's prev_size, if any.
            let after = tail.add(remainder);
            if (after as usize) < self.region_end() {
                (*self.hdr(after)).prev_size = remainder;
            }
        }
    }

    /// `RtlAllocateHeap(size)`: first-fit allocate `size` payload bytes. Returns a payload pointer,
    /// or `None` on exhaustion.
    pub fn allocate(&mut self, size: usize) -> Option<*mut u8> {
        self.allocate_with_flags(size, 0)
    }

    /// Allocate a block and capture the per-allocation user metadata requested in `flags`.
    pub fn allocate_with_flags(&mut self, size: usize, flags: u32) -> Option<*mut u8> {
        if !self.validate(None) {
            return None;
        }
        let need = checked_block_size(size)?;
        let base = self.backing.base();
        let mut offset = 0usize;
        let mut previous_size = 0usize;
        // SAFETY: checked header snapshots constrain every physical step to the backing region.
        unsafe {
            while offset < self.region_len {
                let header = self.header_at_offset(offset)?;
                let next = self.validate_header(offset, previous_size, header)?;
                let cur = base.add(offset);
                let (bsize, bfree) = (header.size, header.is_free());
                if bfree && bsize >= need {
                    let retained = if bsize - need >= MIN_BLOCK_SIZE {
                        need
                    } else {
                        bsize
                    };
                    let unused = retained - HDR - size;
                    debug_assert!(unused <= u8::MAX as usize);
                    self.split(cur, need);
                    let allocated = self.hdr(cur);
                    (*allocated).user_value = 0;
                    (*allocated).user_flags = flags & HEAP_SETTABLE_USER_FLAGS;
                    (*allocated).state = if flags & HEAP_SETTABLE_USER_VALUE != 0 {
                        BLOCK_HAS_USER_VALUE
                    } else {
                        0
                    };
                    (*allocated).unused_bytes = unused as u8;
                    (*allocated).reserved = 0;
                    let payload = cur.add(HDR);
                    if flags & HEAP_ZERO_MEMORY != 0 && size != 0 {
                        core::ptr::write_bytes(payload, 0, size);
                    }
                    return Some(payload);
                }
                previous_size = bsize;
                offset = next;
            }
        }
        None
    }

    /// The payload size of an allocation (`RtlSizeHeap`). Returns `None` if `payload` is not a live
    /// allocation from this heap.
    ///
    /// # Safety
    /// `payload` must be a pointer previously returned by [`Self::allocate`]/[`Self::reallocate`] on
    /// this heap, or null. (The real ntdll `RtlSizeHeap` trusts the caller's pointer identically.)
    pub unsafe fn size_of(&self, payload: *mut u8) -> Option<usize> {
        let (_, header) = self.find_block(payload)?;
        Some(header.size - HDR - header.unused_bytes as usize)
    }

    /// Validate + recover the block header for a payload pointer.
    fn block_of(&self, payload: *mut u8) -> Option<*mut u8> {
        if payload.is_null() || !self.validate(None) {
            return None;
        }
        let (offset, _) = self.find_block(payload)?;
        // SAFETY: find_block proved this offset names a complete live block in the backing.
        Some(unsafe { self.backing.base().add(offset) })
    }

    /// Return the user metadata for a live allocation.
    ///
    /// # Safety
    /// `payload` follows the same contract as [`Self::size_of`].
    pub unsafe fn user_info(&self, payload: *mut u8) -> Option<HeapUserInfo> {
        let block = self.block_of(payload)?;
        let header = &*self.hdr(block);
        Some(HeapUserInfo {
            has_user_value: header.has_user_value(),
            user_value: header.user_value,
            user_flags: header.user_flags,
        })
    }

    /// Store an opaque user value when the allocation requested user-value metadata.
    ///
    /// # Safety
    /// `payload` follows the same contract as [`Self::size_of`].
    pub unsafe fn set_user_value(&mut self, payload: *mut u8, value: usize) -> bool {
        let Some(block) = self.block_of(payload) else {
            return false;
        };
        let header = &mut *self.hdr(block);
        if !(*header).has_user_value() {
            return false;
        }
        header.user_value = value;
        true
    }

    /// Reset and set the three caller-controlled per-allocation user flags.
    ///
    /// # Safety
    /// `payload` follows the same contract as [`Self::size_of`].
    pub unsafe fn set_user_flags(&mut self, payload: *mut u8, reset: u32, set: u32) -> bool {
        if (reset | set) & !HEAP_SETTABLE_USER_FLAGS != 0 {
            return false;
        }
        let Some(block) = self.block_of(payload) else {
            return false;
        };
        let header = &mut *self.hdr(block);
        header.user_flags = (header.user_flags & !reset) | set;
        true
    }

    /// `RtlFreeHeap(payload)`: free an allocation and coalesce with free neighbours. Returns `false`
    /// if `payload` is invalid or already free.
    ///
    /// # Safety
    /// `payload` must be a pointer previously returned by [`Self::allocate`]/[`Self::reallocate`] on
    /// this heap, or null (matching the real `RtlFreeHeap` contract).
    pub unsafe fn free(&mut self, payload: *mut u8) -> bool {
        let Some(block) = self.block_of(payload) else {
            return false;
        };
        let header = &mut *self.hdr(block);
        header.state = BLOCK_FREE;
        header.user_value = 0;
        header.user_flags = 0;
        header.unused_bytes = 0;
        header.reserved = 0;
        self.coalesce(block);
        true
    }

    /// Merge `block` with its physically-adjacent free predecessor and successor.
    ///
    /// # Safety
    /// `block` must be a valid, now-free block header.
    unsafe fn coalesce(&mut self, block: *mut u8) {
        let end = self.region_end();
        let mut start = block;

        // Merge backward if the predecessor is free.
        let prev_size = (*self.hdr(start)).prev_size;
        if prev_size != 0 {
            let prev = start.sub(prev_size);
            if (*self.hdr(prev)).is_free() {
                (*self.hdr(prev)).size += (*self.hdr(start)).size;
                start = prev;
            }
        }

        // Merge forward if the successor is free.
        let next = start.add((*self.hdr(start)).size);
        if (next as usize) < end && (*self.hdr(next)).is_free() {
            (*self.hdr(start)).size += (*self.hdr(next)).size;
        }

        // Fix the (possibly new) following block's prev_size.
        let after = start.add((*self.hdr(start)).size);
        if (after as usize) < end {
            (*self.hdr(after)).prev_size = (*self.hdr(start)).size;
        }
    }

    /// `RtlReAllocateHeap(payload, new_size)`: grow/shrink in place when possible, else allocate +
    /// copy + free. Returns the (possibly new) payload pointer, or `None` on exhaustion (the
    /// original allocation is left intact on failure, matching the Windows contract).
    ///
    /// # Safety
    /// `payload` must be a live allocation from this heap (see [`Self::allocate`]).
    pub unsafe fn reallocate(&mut self, payload: *mut u8, new_size: usize) -> Option<*mut u8> {
        let block = self.block_of(payload)?;
        let header = &*self.hdr(block);
        let flags = header.user_flags
            | if header.has_user_value() {
                HEAP_SETTABLE_USER_VALUE
            } else {
                0
            };
        self.reallocate_with_flags(payload, new_size, flags, false)
    }

    /// Reallocate with the native heap flags that affect user metadata and relocation. Shrinking
    /// preserves user flags; in-place growth replaces them with the supplied bits; relocation of a
    /// block with user-value storage preserves its old flags. The stored user value always survives.
    ///
    /// # Safety
    /// `payload` must be a live allocation from this heap.
    pub unsafe fn reallocate_with_flags(
        &mut self,
        payload: *mut u8,
        new_size: usize,
        flags: u32,
        in_place_only: bool,
    ) -> Option<*mut u8> {
        let old_size = self.size_of(payload)?;
        let need = checked_block_size(new_size)?;
        let block = self.block_of(payload)?;

        let cur_total = (*self.hdr(block)).size;
        // Shrink, same-size, or logical growth within existing alignment padding.
        if need <= cur_total {
            let retained = if cur_total - need >= MIN_BLOCK_SIZE {
                need
            } else {
                cur_total
            };
            let unused = retained - HDR - new_size;
            debug_assert!(unused <= u8::MAX as usize);
            self.split(block, need);
            if (*self.hdr(block)).size != cur_total {
                self.coalesce(block.add(need));
            }
            (*self.hdr(block)).unused_bytes = unused as u8;
            if new_size > old_size {
                (*self.hdr(block)).user_flags = flags & HEAP_SETTABLE_USER_FLAGS;
                if flags & HEAP_ZERO_MEMORY != 0 {
                    core::ptr::write_bytes(payload.add(old_size), 0, new_size - old_size);
                }
            }
            return Some(payload);
        }
        // Try to grow into a free successor.
        let next = block.add(cur_total);
        if (next as usize) < self.region_end()
            && (*self.hdr(next)).is_free()
            && cur_total + (*self.hdr(next)).size >= need
        {
            let merged = cur_total + (*self.hdr(next)).size;
            (*self.hdr(block)).size = merged;
            // Fix the block after `next`.
            let after = block.add(merged);
            if (after as usize) < self.region_end() {
                (*self.hdr(after)).prev_size = merged;
            }
            self.split(block, need);
            let unused = (*self.hdr(block)).size - HDR - new_size;
            debug_assert!(unused <= u8::MAX as usize);
            (*self.hdr(block)).unused_bytes = unused as u8;
            (*self.hdr(block)).user_flags = flags & HEAP_SETTABLE_USER_FLAGS;
            if flags & HEAP_ZERO_MEMORY != 0 && new_size > old_size {
                core::ptr::write_bytes(payload.add(old_size), 0, new_size - old_size);
            }
            return Some(payload);
        }

        // Fall back to allocate + copy + free.
        if in_place_only {
            return None;
        }
        let old_header = *self.hdr(block);
        let allocation_flags = if old_header.has_user_value() {
            (flags & !HEAP_SETTABLE_USER_FLAGS) | HEAP_SETTABLE_USER_VALUE | old_header.user_flags
        } else {
            flags
        };
        let dst = self.allocate_with_flags(new_size, allocation_flags)?;
        let dst_block = self.block_of(dst)?;
        (*self.hdr(dst_block)).user_value = old_header.user_value;
        core::ptr::copy_nonoverlapping(payload, dst, old_size.min(new_size));
        self.free(payload);
        Some(dst)
    }
}

/// Result of attempting to remove a private heap from a [`HeapRegistry`].
pub enum HeapRemoval<B: Backing> {
    /// A private heap was removed and ownership is returned to the caller.
    Removed(Heap<B>),
    /// The handle names the distinguished process heap, which cannot be removed.
    ProcessHeap,
    /// The handle is null or does not name a registered heap.
    NotFound,
}

/// Allocation-free per-process heap registry. The process heap is always enumerated first and
/// private heaps retain creation order; removing one compacts the private portion.
pub struct HeapRegistry<B: Backing, const N: usize> {
    process: Option<Heap<B>>,
    private: [Option<Heap<B>>; N],
    private_len: usize,
}

impl<B: Backing, const N: usize> Default for HeapRegistry<B, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Backing, const N: usize> HeapRegistry<B, N> {
    /// Create an empty registry without allocating.
    pub fn new() -> Self {
        Self {
            process: None,
            private: core::array::from_fn(|_| None),
            private_len: 0,
        }
    }

    /// Install the one process heap. Returns its handle, or the supplied heap unchanged if a
    /// process heap is already installed or its handle duplicates a registered private heap.
    pub fn install_process(&mut self, heap: Heap<B>) -> Result<*mut u8, Heap<B>> {
        let handle = heap.handle();
        if self.process.is_some() || self.find(handle).is_some() {
            return Err(heap);
        }
        self.process = Some(heap);
        Ok(handle)
    }

    /// Register a private heap, preserving creation order.
    pub fn insert_private(&mut self, heap: Heap<B>) -> Result<*mut u8, Heap<B>> {
        let handle = heap.handle();
        if self.private_len == N || self.find(handle).is_some() {
            return Err(heap);
        }
        self.private[self.private_len] = Some(heap);
        self.private_len += 1;
        Ok(handle)
    }

    /// Number of registered heaps, including the process heap when installed.
    pub fn len(&self) -> usize {
        usize::from(self.process.is_some()) + self.private_len
    }

    /// Whether no heap has been installed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The distinguished process-heap handle.
    pub fn process_handle(&self) -> Option<*mut u8> {
        self.process.as_ref().map(Heap::handle)
    }

    /// Look up a heap by its exact native handle.
    pub fn find(&self, handle: *mut u8) -> Option<&Heap<B>> {
        if handle.is_null() {
            return None;
        }
        if let Some(heap) = self.process.as_ref() {
            if heap.handle() == handle {
                return Some(heap);
            }
        }
        self.private[..self.private_len]
            .iter()
            .filter_map(Option::as_ref)
            .find(|heap| heap.handle() == handle)
    }

    /// Mutable lookup by exact native handle.
    pub fn find_mut(&mut self, handle: *mut u8) -> Option<&mut Heap<B>> {
        if handle.is_null() {
            return None;
        }
        if self
            .process
            .as_ref()
            .is_some_and(|heap| heap.handle() == handle)
        {
            return self.process.as_mut();
        }
        self.private[..self.private_len]
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|heap| heap.handle() == handle)
    }

    /// Remove a private heap. The process heap is deliberately retained for the process lifetime.
    pub fn remove_private(&mut self, handle: *mut u8) -> HeapRemoval<B> {
        if handle.is_null() {
            return HeapRemoval::NotFound;
        }
        if self
            .process
            .as_ref()
            .is_some_and(|heap| heap.handle() == handle)
        {
            return HeapRemoval::ProcessHeap;
        }
        let Some(index) = self.private[..self.private_len]
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|heap| heap.handle() == handle))
        else {
            return HeapRemoval::NotFound;
        };
        let removed = self.private[index].take().expect("occupied registry entry");
        for slot in index..self.private_len - 1 {
            self.private[slot] = self.private[slot + 1].take();
        }
        self.private_len -= 1;
        self.private[self.private_len] = None;
        HeapRemoval::Removed(removed)
    }

    /// Copy as many handles as fit while returning the total number available, matching
    /// `RtlGetProcessHeaps` truncation semantics.
    pub fn copy_handles(&self, output: &mut [*mut u8]) -> usize {
        let mut written = 0usize;
        if let Some(heap) = self.process.as_ref() {
            if let Some(slot) = output.get_mut(written) {
                *slot = heap.handle();
            }
            written += 1;
        }
        for heap in self.private[..self.private_len]
            .iter()
            .filter_map(Option::as_ref)
        {
            if let Some(slot) = output.get_mut(written) {
                *slot = heap.handle();
            }
            written += 1;
        }
        written
    }

    /// Validate every registered heap's complete physical block chain.
    pub fn validate_all(&self) -> bool {
        self.process
            .iter()
            .chain(
                self.private[..self.private_len]
                    .iter()
                    .filter_map(Option::as_ref),
            )
            .all(|heap| heap.validate(None))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn heap_lock_is_recursive_and_releases_at_final_depth() {
        let mut lock = HeapLockState::new();
        assert_eq!(lock.try_acquire(7), HeapLockAcquire::Acquired);
        assert_eq!(lock.try_acquire(7), HeapLockAcquire::Recursed);
        assert_eq!(lock.owner(), 7);
        assert_eq!(lock.depth(), 2);
        assert_eq!(lock.release(7), HeapLockRelease::StillHeld);
        assert_eq!(lock.release(7), HeapLockRelease::Released);
        assert_eq!(lock, HeapLockState::new());
    }

    #[test]
    fn heap_lock_rejects_contention_wrong_owner_and_zero_tid() {
        let mut lock = HeapLockState::new();
        assert_eq!(lock.try_acquire(0), HeapLockAcquire::InvalidThread);
        assert_eq!(lock.try_acquire(7), HeapLockAcquire::Acquired);
        assert_eq!(lock.try_acquire(8), HeapLockAcquire::Contended);
        assert_eq!(lock.release(8), HeapLockRelease::NotOwner);
        assert_eq!(lock.owner(), 7);
        assert_eq!(lock.depth(), 1);
    }

    #[test]
    fn heap_lock_table_keeps_handles_independent_and_honors_no_serialize() {
        let mut locks = HeapLockTable::<3>::new();
        assert!(locks.register(0x1000, HeapLockPolicy::Internal));
        assert!(locks.register(0x2000, HeapLockPolicy::Internal));
        assert!(locks.register(0x3000, HeapLockPolicy::NoSerialize));
        assert_eq!(locks.acquire(0x1000, 7), HeapLockAcquire::Acquired);
        assert_eq!(locks.release(0x2000, 7), HeapLockRelease::NotOwner);
        assert_eq!(locks.acquire(0x2000, 8), HeapLockAcquire::Acquired);
        assert_eq!(locks.release(0x1000, 7), HeapLockRelease::Released);
        assert_eq!(locks.release(0x2000, 8), HeapLockRelease::Released);
        assert_eq!(locks.acquire(0x3000, 0), HeapLockAcquire::Bypassed);
        assert_eq!(locks.release(0x3000, 0), HeapLockRelease::Released);
        assert_eq!(locks.acquire(0x4000, 7), HeapLockAcquire::InvalidHandle);
    }

    /// A host-test backing region: an owned `Vec<u8>`.
    struct VecBacking {
        buf: Vec<u8>,
    }
    // SAFETY: the Vec's buffer is valid for its whole length for the lifetime of the backing, and
    // `Vec<u8>` guarantees at least 1-byte alignment; we over-allocate to HEAP_ALIGN below.
    unsafe impl Backing for VecBacking {
        fn base(&self) -> *mut u8 {
            // Align the base up to HEAP_ALIGN by leaking the misaligned prefix (test-only).
            let raw = self.buf.as_ptr() as usize;
            round_up(raw, HEAP_ALIGN) as *mut u8
        }
        fn len(&self) -> usize {
            let raw = self.buf.as_ptr() as usize;
            let aligned = round_up(raw, HEAP_ALIGN);
            self.buf.len() - (aligned - raw)
        }
    }

    fn heap(bytes: usize) -> Heap<VecBacking> {
        Heap::create(VecBacking {
            buf: vec![0u8; bytes + HEAP_ALIGN],
        })
        .unwrap()
    }

    fn next_walk_entry(heap: &Heap<VecBacking>, entry: &mut RtlHeapWalkEntry) -> RtlHeapWalkEntry {
        assert_eq!(heap.walk_next(entry), Ok(HeapWalkOutcome::Entry));
        *entry
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn heap_walk_entry_matches_native_x64_abi() {
        assert_eq!(size_of::<RtlHeapWalkEntry>(), 0x38);
        assert_eq!(align_of::<RtlHeapWalkEntry>(), 8);
        assert_eq!(core::mem::offset_of!(RtlHeapWalkEntry, data_address), 0);
        assert_eq!(core::mem::offset_of!(RtlHeapWalkEntry, data_size), 8);
        assert_eq!(
            core::mem::offset_of!(RtlHeapWalkEntry, overhead_bytes),
            0x10
        );
        assert_eq!(core::mem::offset_of!(RtlHeapWalkEntry, flags), 0x12);
        assert_eq!(core::mem::offset_of!(RtlHeapWalkEntry, details), 0x18);
        assert_eq!(size_of::<RtlHeapWalkBlock>(), 0x18);
        assert_eq!(size_of::<RtlHeapWalkSegment>(), 0x20);
    }

    #[test]
    fn heap_walk_reports_segment_fresh_free_block_and_stable_end() {
        let heap = heap(1024);
        let mut entry = RtlHeapWalkEntry::restart();

        let segment = next_walk_entry(&heap, &mut entry);
        assert_eq!(segment.data_address, heap.handle());
        assert_eq!(segment.data_size, 0);
        assert_eq!(segment.overhead_bytes, 0);
        assert_eq!(segment.segment_index, 0);
        assert_eq!(segment.flags, RTL_HEAP_SEGMENT);
        // SAFETY: the segment flag selects the segment union arm.
        let details = unsafe { segment.details.segment };
        assert_eq!(details.committed_size, heap.region_len);
        assert_eq!(details.uncommitted_size, 0);
        assert_eq!(details.first_entry, unsafe { heap.handle().add(HDR) });
        assert_eq!(details.last_entry, heap.region_end() as *mut u8);

        let block = next_walk_entry(&heap, &mut entry);
        assert_eq!(block.data_address, unsafe { heap.handle().add(HDR) });
        assert_eq!(block.data_size, heap.region_len - HDR);
        assert_eq!(block.overhead_bytes, HDR as u8);
        assert_eq!(block.flags, 0);
        // SAFETY: a block row selects the block union arm.
        let block_details = unsafe { block.details.block };
        assert_eq!(block_details.settable, 0);
        assert_eq!(block_details.reserved, [0; 2]);

        assert_eq!(
            heap.walk_next(&mut entry),
            Ok(HeapWalkOutcome::NoMoreEntries)
        );
        assert_eq!(entry.data_address, block.data_address);
        assert_eq!(entry.data_size, block.data_size);
        assert_eq!(entry.flags, block.flags);
    }

    #[test]
    fn debug_summary_counts_segment_and_physical_blocks() {
        let mut heap = heap(2048);
        let first = heap.allocate(17).unwrap();
        let middle = heap.allocate(33).unwrap();
        let _last = heap.allocate(49).unwrap();
        // SAFETY: middle is an exact live allocation from this heap.
        assert!(unsafe { heap.free(middle) });

        let summary = heap.debug_summary().unwrap();
        assert_eq!(summary.base_address, heap.handle());
        assert_eq!(summary.entry_overhead, HDR as u16);
        assert_eq!(summary.bytes_committed, heap.region_len);

        let mut cursor = RtlHeapWalkEntry::restart();
        let mut expected_entries = 0u32;
        let mut expected_allocated = 0usize;
        loop {
            match heap.walk_next(&mut cursor).unwrap() {
                HeapWalkOutcome::Entry => {
                    expected_entries += 1;
                    if cursor.flags & RTL_HEAP_BUSY != 0 {
                        expected_allocated += cursor.data_size + usize::from(cursor.overhead_bytes);
                    }
                }
                HeapWalkOutcome::NoMoreEntries => break,
            }
        }
        assert_eq!(summary.number_of_entries, expected_entries);
        assert_eq!(summary.bytes_allocated, expected_allocated);
        assert!(heap.validate(Some(first)));
    }

    #[test]
    fn debug_summary_reports_empty_heap_and_rejects_corruption() {
        let heap = heap(1024);
        assert_eq!(
            heap.debug_summary(),
            Some(HeapDebugSummary {
                base_address: heap.handle(),
                entry_overhead: HDR as u16,
                bytes_committed: heap.region_len,
                bytes_allocated: 0,
                number_of_entries: 2,
            })
        );

        // SAFETY: corrupt the first in-band header without forming an invalid Rust value.
        unsafe { (*heap.hdr(heap.handle())).reserved = 1 };
        assert_eq!(heap.debug_summary(), None);
    }

    #[test]
    fn heap_walk_reports_physical_order_requested_sizes_and_user_metadata() {
        let mut heap = heap(2048);
        let first = heap
            .allocate_with_flags(17, HEAP_SETTABLE_USER_VALUE | 0x0a00)
            .unwrap();
        let middle = heap.allocate(33).unwrap();
        let last = heap.allocate(49).unwrap();
        // SAFETY: first/middle are exact live allocations from this heap.
        unsafe {
            assert!(heap.set_user_value(first, 0x1234_5678));
            assert!(heap.free(middle));
        }

        let mut entry = RtlHeapWalkEntry::restart();
        next_walk_entry(&heap, &mut entry);
        let first_row = next_walk_entry(&heap, &mut entry);
        assert_eq!(first_row.data_address, first);
        assert_eq!(first_row.data_size, 17);
        assert_eq!(
            first_row.flags,
            RTL_HEAP_BUSY | RTL_HEAP_SETTABLE_VALUE | 0x00a0
        );
        // SAFETY: the busy row selects the block union arm.
        assert_eq!(unsafe { first_row.details.block }.settable, 0x1234_5678);

        let free_row = next_walk_entry(&heap, &mut entry);
        assert_eq!(free_row.data_address, middle);
        assert_eq!(free_row.flags, 0);
        assert!(free_row.data_size >= 33);

        let last_row = next_walk_entry(&heap, &mut entry);
        assert_eq!(last_row.data_address, last);
        assert_eq!(last_row.data_size, 49);
        assert_eq!(last_row.flags, RTL_HEAP_BUSY);

        let tail = next_walk_entry(&heap, &mut entry);
        assert_eq!(tail.flags, 0);
        assert_eq!(
            heap.walk_next(&mut entry),
            Ok(HeapWalkOutcome::NoMoreEntries)
        );
    }

    #[test]
    fn heap_walk_restarts_and_rejects_stale_or_contradictory_cursors() {
        let mut heap = heap(1024);
        let allocation = heap.allocate(32).unwrap();
        let mut entry = RtlHeapWalkEntry::restart();
        next_walk_entry(&heap, &mut entry);
        next_walk_entry(&heap, &mut entry);

        let saved_address = entry.data_address;
        entry.segment_index = 1;
        assert_eq!(
            heap.walk_next(&mut entry),
            Err(HeapWalkError::InvalidAddress)
        );
        assert_eq!(entry.data_address, saved_address);

        entry = RtlHeapWalkEntry::restart();
        next_walk_entry(&heap, &mut entry);
        entry.data_address = unsafe { allocation.add(1) };
        entry.flags = RTL_HEAP_BUSY;
        assert_eq!(
            heap.walk_next(&mut entry),
            Err(HeapWalkError::InvalidAddress)
        );

        entry.data_address = allocation;
        entry.flags = 0;
        assert_eq!(
            heap.walk_next(&mut entry),
            Err(HeapWalkError::InvalidParameter)
        );

        entry = RtlHeapWalkEntry::restart();
        // SAFETY: corrupt the first in-band header without forming an invalid Rust value.
        unsafe { (*heap.hdr(heap.handle())).reserved = 1 };
        assert_eq!(
            heap.walk_next(&mut entry),
            Err(HeapWalkError::InvalidParameter)
        );
        assert!(entry.data_address.is_null());
    }

    #[test]
    fn payload_is_aligned() {
        let mut h = heap(4096);
        for sz in [1usize, 7, 16, 100, 300] {
            let p = h.allocate(sz).unwrap();
            assert_eq!(p as usize % HEAP_ALIGN, 0, "payload for {sz} unaligned");
        }
    }

    #[test]
    fn alloc_size_free_roundtrip() {
        let mut h = heap(4096);
        let p = h.allocate(100).unwrap();
        // SAFETY: p is a live allocation from this heap for the whole reported extent.
        unsafe {
            assert_eq!(h.size_of(p), Some(100));
            let n = h.size_of(p).unwrap();
            core::ptr::write_bytes(p, 0xAB, n); // write the whole extent — must not overlap
            assert!(h.free(p));
            assert!(!h.free(p)); // double-free rejected
            assert!(h.size_of(p).is_none()); // freed -> no size
        }
    }

    #[test]
    fn size_reports_exact_requested_bytes_across_alignment_boundaries() {
        let mut h = heap(4096);
        for requested in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            let p = h.allocate(requested).unwrap();
            // SAFETY: p is the live allocation returned above.
            unsafe {
                assert_eq!(h.size_of(p), Some(requested));
                assert!(h.free(p));
            }
        }
    }

    #[test]
    fn validation_checks_whole_heap_and_exact_live_blocks() {
        let mut h = heap(1024);
        assert!(h.validate(None));
        let p = h.allocate(17).unwrap();
        let other = heap(512);
        assert!(h.validate(None));
        assert!(h.validate(Some(p)));
        assert!(!h.validate(Some(unsafe { p.add(1) })));
        assert!(!h.validate(Some(h.handle())));
        assert!(!h.validate(Some(other.handle())));
        // SAFETY: p is live for this heap.
        unsafe { assert!(h.free(p)) };
        assert!(h.validate(None));
        assert!(!h.validate(Some(p)));
    }

    #[test]
    fn validation_rejects_corrupted_integer_headers_without_invalid_values() {
        fn rejects(change: impl FnOnce(&mut BlockHeader)) {
            let h = heap(512);
            // SAFETY: the fresh heap starts with one complete header at its aligned base.
            unsafe { change(&mut *h.hdr(h.handle())) };
            assert!(!h.validate(None));
        }

        rejects(|header| header.size = 0);
        rejects(|header| header.size -= 1);
        rejects(|header| header.size = usize::MAX & !(HEAP_ALIGN - 1));
        rejects(|header| header.state = 0xff);
        rejects(|header| header.state = BLOCK_FREE | BLOCK_HAS_USER_VALUE);
        rejects(|header| header.unused_bytes = 1);
        rejects(|header| header.user_flags = 0x10);
        rejects(|header| header.user_value = 1);
        rejects(|header| header.reserved = 1);

        let short_tail = heap(512);
        let region_len = short_tail.region_len;
        // SAFETY: this deliberately leaves an aligned suffix too short for a block header.
        unsafe { (*short_tail.hdr(short_tail.handle())).size = region_len - HEAP_ALIGN };
        assert!(!short_tail.validate(None));

        let mut broken_link = heap(512);
        let first = broken_link.allocate(32).unwrap();
        let second = broken_link.allocate(32).unwrap();
        // SAFETY: both pointers are live; block_of returns the exact second in-band header.
        unsafe { (*broken_link.hdr(broken_link.block_of(second).unwrap())).prev_size += HEAP_ALIGN };
        assert!(!broken_link.validate(None));
        assert!(broken_link.validate(Some(first)));
        assert!(!broken_link.validate(Some(second)));
    }

    #[test]
    fn mutations_reject_a_corrupt_successor_before_dereferencing_it() {
        let mut h = heap(512);
        let pointer = h.allocate(32).unwrap();
        let block = h.block_of(pointer).unwrap();
        // SAFETY: allocation split the fresh region, so its physical successor starts at block+size.
        unsafe {
            let next = block.add((*h.hdr(block)).size);
            (*h.hdr(next)).size = usize::MAX & !(HEAP_ALIGN - 1);
            assert!(!h.free(pointer));
        }
    }

    #[test]
    fn whole_heap_validation_rejects_adjacent_free_blocks() {
        let h = heap(512);
        let first_size = MIN_BLOCK_SIZE;
        let second_size = h.region_len - first_size;
        // SAFETY: both synthetic headers are complete, aligned, in-range free blocks.
        unsafe {
            (*h.hdr(h.handle())).size = first_size;
            core::ptr::write(
                h.hdr(h.handle().add(first_size)),
                BlockHeader {
                    size: second_size,
                    prev_size: first_size,
                    user_value: 0,
                    user_flags: 0,
                    state: BLOCK_FREE,
                    unused_bytes: 0,
                    reserved: 0,
                },
            );
        }
        assert!(!h.validate(None));
    }

    #[test]
    fn realloc_tracks_exact_size_and_zeros_logically_exposed_padding() {
        let mut h = heap(4096);
        let p = h.allocate(17).unwrap();
        // SAFETY: the physical aligned block has capacity beyond the requested 17 bytes.
        unsafe {
            core::ptr::write_bytes(p, 0x5a, 17);
            core::ptr::write_bytes(p.add(17), 0xaa, 14);
            let grown = h
                .reallocate_with_flags(p, 31, HEAP_ZERO_MEMORY, true)
                .unwrap();
            assert_eq!(grown, p);
            assert_eq!(h.size_of(grown), Some(31));
            assert!(core::slice::from_raw_parts(grown, 17)
                .iter()
                .all(|byte| *byte == 0x5a));
            assert!(core::slice::from_raw_parts(grown.add(17), 14)
                .iter()
                .all(|byte| *byte == 0));
            let shrunk = h.reallocate(grown, 3).unwrap();
            assert_eq!(h.size_of(shrunk), Some(3));
            assert!(h.validate(None));
        }
    }

    #[test]
    fn allocation_churn_preserves_contents_and_physical_chain() {
        let mut h = heap(64 * 1024);
        let mut slots = [None; 64];
        let mut random = 0x6d2b_79f5u32;
        for step in 0..10_000usize {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let index = random as usize % slots.len();
            let requested = ((random >> 8) as usize % 768) + usize::from(step % 29 == 0);
            match (random >> 29, slots[index]) {
                (0..=2, None) => {
                    if let Some(pointer) = h.allocate(requested) {
                        // SAFETY: pointer is live for exactly requested bytes.
                        unsafe { core::ptr::write_bytes(pointer, index as u8, requested) };
                        slots[index] = Some((pointer, requested));
                    }
                }
                (0..=4, Some((pointer, old_size))) => {
                    // SAFETY: pointer is the current live allocation in this slot.
                    if let Some(next) = unsafe { h.reallocate(pointer, requested) } {
                        let preserved = old_size.min(requested);
                        // SAFETY: next is live for requested bytes and reallocation preserves prefix.
                        unsafe {
                            assert!(core::slice::from_raw_parts(next, preserved)
                                .iter()
                                .all(|byte| *byte == index as u8));
                            core::ptr::write_bytes(next, index as u8, requested);
                        }
                        slots[index] = Some((next, requested));
                    }
                }
                (_, Some((pointer, _))) => {
                    // SAFETY: pointer is the current live allocation in this slot.
                    assert!(unsafe { h.free(pointer) });
                    slots[index] = None;
                }
                (_, None) => {}
            }
            assert!(h.validate(None), "invalid heap after churn step {step}");
        }
        for (pointer, _) in slots.into_iter().flatten() {
            // SAFETY: every remaining slot holds one live allocation.
            assert!(unsafe { h.free(pointer) });
        }
        assert!(h.validate(None));
    }

    #[test]
    fn distinct_allocations_do_not_overlap() {
        let mut h = heap(4096);
        let a = h.allocate(64).unwrap();
        let b = h.allocate(64).unwrap();
        let c = h.allocate(64).unwrap();
        let sz = 64usize;
        // No two payloads overlap.
        for (x, y) in [(a, b), (a, c), (b, c)] {
            let (xs, ys) = (x as usize, y as usize);
            assert!(xs + sz <= ys || ys + sz <= xs, "overlap");
        }
    }

    #[test]
    fn free_coalesces_and_reuses() {
        let mut h = heap(1024);
        let a = h.allocate(200).unwrap();
        let b = h.allocate(200).unwrap();
        let c = h.allocate(200).unwrap();
        // SAFETY: a/b/c are live allocations from this heap.
        unsafe {
            h.free(b);
            h.free(a); // a+b coalesce backward
            h.free(c); // ...eventually the whole region is one free block again
        }
        // A single large alloc that only fits if coalescing worked.
        let big = h.allocate(600);
        assert!(big.is_some(), "coalescing failed to reclaim space");
    }

    #[test]
    fn compact_reports_largest_coalesced_free_payload() {
        let mut h = heap(1024);
        assert_eq!(h.compact(), Some(h.region_len - HDR));
        let first = h.allocate(100).unwrap();
        let middle = h.allocate(200).unwrap();
        let last = h.allocate(100).unwrap();
        let after_allocations = h.compact().unwrap();
        assert!(after_allocations < h.region_len - HDR);

        // SAFETY: first/middle/last are exact live allocations from this heap.
        unsafe {
            assert!(h.free(middle));
            let middle_extent = h.compact().unwrap();
            assert!(middle_extent >= 200);
            assert!(h.free(first));
            assert!(h.compact().unwrap() >= middle_extent);
            assert!(h.free(last));
        }
        assert_eq!(h.compact(), Some(h.region_len - HDR));
    }

    #[test]
    fn compact_distinguishes_full_heap_from_corrupt_heap() {
        let mut h = heap(256);
        let mut allocations = Vec::new();
        while let Some(pointer) = h.allocate(1) {
            allocations.push(pointer);
        }
        assert_eq!(h.compact(), Some(0));

        let corrupt = heap(256);
        // SAFETY: deliberately corrupt a plain integer field in the first header.
        unsafe { (*corrupt.hdr(corrupt.handle())).reserved = 1 };
        assert_eq!(corrupt.compact(), None);
    }

    #[test]
    fn exhaustion_returns_none_then_recovers() {
        let mut h = heap(256);
        let mut ptrs = Vec::new();
        // Allocate until exhausted.
        while let Some(p) = h.allocate(32) {
            ptrs.push(p);
        }
        assert!(!ptrs.is_empty());
        assert!(h.allocate(32).is_none());
        // Free one and re-allocate succeeds.
        // SAFETY: the popped pointer is a live allocation from this heap.
        unsafe { h.free(ptrs.pop().unwrap()) };
        assert!(h.allocate(32).is_some());
    }

    #[test]
    fn realloc_grow_in_place_and_relocate() {
        let mut h = heap(4096);
        let p = h.allocate(64).unwrap();
        // SAFETY: p/p2/r are live allocations from this heap for the extents accessed.
        unsafe {
            core::ptr::write_bytes(p, 0x5A, 64);
            // Grow into the trailing free space (in place — the next block is free).
            let g = h.reallocate(p, 128).unwrap();
            assert_eq!(g, p, "expected in-place grow into trailing free block");
            assert_eq!(h.size_of(g), Some(128));
            assert!(core::slice::from_raw_parts(g, 64)
                .iter()
                .all(|&x| x == 0x5A)); // preserved

            // Now block a successor so the next grow must relocate.
            let _blocker = h.allocate(64).unwrap();
            let p2 = h.allocate(32).unwrap();
            core::ptr::write_bytes(p2, 0x33, 32);
            let r = h.reallocate(p2, 512).unwrap();
            assert_eq!(h.size_of(r), Some(512));
            assert!(core::slice::from_raw_parts(r, 32)
                .iter()
                .all(|&x| x == 0x33)); // preserved
        }
    }

    #[test]
    fn realloc_shrink_frees_tail() {
        let mut h = heap(1024);
        let p = h.allocate(400).unwrap();
        // SAFETY: p is a live allocation from this heap.
        let r = unsafe { h.reallocate(p, 32).unwrap() };
        assert_eq!(r, p);
        // The freed tail is reusable.
        assert!(h.allocate(300).is_some());
    }

    #[test]
    fn user_metadata_requires_live_exact_allocation() {
        let mut h = heap(1024);
        let plain = h.allocate_with_flags(64, 0x400).unwrap();
        let with_value = h
            .allocate_with_flags(64, HEAP_SETTABLE_USER_VALUE | 0x200)
            .unwrap();
        // SAFETY: both pointers are live allocations; the interior pointer is deliberately invalid.
        unsafe {
            assert_eq!(
                h.user_info(plain),
                Some(HeapUserInfo {
                    has_user_value: false,
                    user_value: 0,
                    user_flags: 0x400,
                })
            );
            assert!(!h.set_user_value(plain, 0x1234));
            assert!(h.set_user_value(with_value, 0x1234));
            assert_eq!(h.user_info(with_value).unwrap().user_value, 0x1234);
            assert!(h.user_info(plain.add(1)).is_none());
            assert!(h.free(plain));
            assert!(h.user_info(plain).is_none());
        }
    }

    #[test]
    fn set_user_flags_validates_mask_and_applies_reset_before_set() {
        let mut h = heap(1024);
        let p = h.allocate_with_flags(64, 0x600).unwrap();
        // SAFETY: p is a live allocation from this heap.
        unsafe {
            assert!(h.set_user_flags(p, 0x600, 0x800));
            assert_eq!(h.user_info(p).unwrap().user_flags, 0x800);
            assert!(!h.set_user_flags(p, HEAP_SETTABLE_USER_VALUE, 0));
            assert!(!h.set_user_flags(p, 0, 0x1000));
            assert_eq!(h.user_info(p).unwrap().user_flags, 0x800);
        }
    }

    #[test]
    fn realloc_preserves_value_and_updates_flags_only_when_growing() {
        let mut h = heap(4096);
        let p = h
            .allocate_with_flags(256, HEAP_SETTABLE_USER_VALUE | 0x400)
            .unwrap();
        // SAFETY: each pointer used below is the current live allocation from this heap.
        unsafe {
            assert!(h.set_user_value(p, 0xfeed));
            let shrunk = h.reallocate_with_flags(p, 128, 0x200, true).unwrap();
            assert_eq!(shrunk, p);
            assert_eq!(
                h.user_info(shrunk).unwrap(),
                HeapUserInfo {
                    has_user_value: true,
                    user_value: 0xfeed,
                    user_flags: 0x400,
                }
            );

            let grown = h.reallocate_with_flags(shrunk, 192, 0x200, true).unwrap();
            assert_eq!(grown, p);
            assert_eq!(
                h.user_info(grown).unwrap(),
                HeapUserInfo {
                    has_user_value: true,
                    user_value: 0xfeed,
                    user_flags: 0x200,
                }
            );

            let blocker = h.allocate(64).unwrap();
            assert!(h.reallocate_with_flags(grown, 1024, 0x800, true).is_none());
            assert_eq!(h.user_info(grown).unwrap().user_value, 0xfeed);
            let relocated = h.reallocate_with_flags(grown, 1024, 0x800, false).unwrap();
            assert_ne!(relocated, grown);
            assert_eq!(
                h.user_info(relocated).unwrap(),
                HeapUserInfo {
                    has_user_value: true,
                    user_value: 0xfeed,
                    user_flags: 0x200,
                }
            );
            assert!(h.free(blocker));
        }
    }

    #[test]
    fn create_rejects_tiny_region() {
        assert!(Heap::create(VecBacking { buf: vec![0u8; 4] }).is_none());
    }

    #[test]
    fn oversized_alloc_and_realloc_fail_without_mutating_the_heap() {
        let mut h = heap(1024);
        let p = h.allocate(64).unwrap();
        assert!(h.allocate(usize::MAX).is_none());
        // SAFETY: p remains a live allocation after the failed reallocation.
        unsafe {
            assert!(h.reallocate(p, usize::MAX).is_none());
            assert!(h.size_of(p).is_some());
            assert!(h.free(p));
        }
    }

    #[test]
    fn zero_memory_covers_reused_allocations_and_grown_tails() {
        let mut h = heap(4096);
        let dirty = h.allocate(64).unwrap();
        // SAFETY: every pointer below is live for the byte range accessed.
        unsafe {
            core::ptr::write_bytes(dirty, 0xaa, 64);
            assert!(h.free(dirty));
        }
        let reused = h.allocate_with_flags(64, HEAP_ZERO_MEMORY).unwrap();
        // SAFETY: reused is live for at least 64 bytes.
        unsafe {
            assert!(core::slice::from_raw_parts(reused, 64)
                .iter()
                .all(|byte| *byte == 0));
            core::ptr::write_bytes(reused, 0x5a, 64);
            let grown = h
                .reallocate_with_flags(reused, 128, HEAP_ZERO_MEMORY, true)
                .unwrap();
            assert!(core::slice::from_raw_parts(grown, 64)
                .iter()
                .all(|byte| *byte == 0x5a));
            assert!(core::slice::from_raw_parts(grown.add(64), 64)
                .iter()
                .all(|byte| *byte == 0));
            let _blocker = h.allocate(64).unwrap();
            let relocated = h
                .reallocate_with_flags(grown, 512, HEAP_ZERO_MEMORY, false)
                .unwrap();
            assert_ne!(relocated, grown);
            assert!(core::slice::from_raw_parts(relocated, 64)
                .iter()
                .all(|byte| *byte == 0x5a));
            assert!(core::slice::from_raw_parts(relocated.add(64), 512 - 64)
                .iter()
                .all(|byte| *byte == 0));
        }
    }

    #[test]
    fn destroy_returns_backing() {
        let h = heap(256);
        let b = h.destroy();
        assert!(b.len() >= 256);
    }

    #[test]
    fn registry_routes_distinct_heaps_and_rejects_cross_heap_pointers() {
        let mut registry = HeapRegistry::<VecBacking, 3>::new();
        let process = registry.install_process(heap(1024)).ok().unwrap();
        let private = registry.insert_private(heap(1024)).ok().unwrap();
        assert_ne!(process, private);

        let p = registry.find_mut(private).unwrap().allocate(64).unwrap();
        // SAFETY: p belongs to `private`; using it against `process` deliberately tests rejection.
        unsafe {
            assert!(registry.find_mut(process).unwrap().free(p) == false);
            assert!(registry.find_mut(private).unwrap().free(p));
        }
    }

    #[test]
    fn registry_enumerates_process_first_and_reports_truncated_total() {
        let mut registry = HeapRegistry::<VecBacking, 3>::new();
        let process = registry.install_process(heap(512)).ok().unwrap();
        let first = registry.insert_private(heap(512)).ok().unwrap();
        let second = registry.insert_private(heap(512)).ok().unwrap();
        let mut one = [core::ptr::null_mut(); 1];
        assert_eq!(registry.copy_handles(&mut one), 3);
        assert_eq!(one, [process]);
        let mut all = [core::ptr::null_mut(); 3];
        assert_eq!(registry.copy_handles(&mut all), 3);
        assert_eq!(all, [process, first, second]);
    }

    #[test]
    fn registry_validates_every_process_heap() {
        let mut registry = HeapRegistry::<VecBacking, 3>::new();
        assert!(registry.validate_all());
        let process = registry.install_process(heap(512)).ok().unwrap();
        let first = registry.insert_private(heap(512)).ok().unwrap();
        let second = registry.insert_private(heap(512)).ok().unwrap();
        assert!(registry.validate_all());

        // SAFETY: deliberately corrupt one private heap's integer header metadata.
        unsafe { (*registry.find_mut(first).unwrap().hdr(first)).reserved = 1 };
        assert!(!registry.validate_all());
        assert!(matches!(
            registry.remove_private(first),
            HeapRemoval::Removed(_)
        ));
        assert!(registry.validate_all());

        // SAFETY: deliberately corrupt the distinguished process heap.
        unsafe { (*registry.find_mut(process).unwrap().hdr(process)).size = 0 };
        assert!(!registry.validate_all());
        assert!(registry.find(second).is_some());
    }

    #[test]
    fn registry_removal_compacts_and_refuses_process_heap() {
        let mut registry = HeapRegistry::<VecBacking, 3>::new();
        let process = registry.install_process(heap(512)).ok().unwrap();
        let first = registry.insert_private(heap(512)).ok().unwrap();
        let second = registry.insert_private(heap(512)).ok().unwrap();
        assert!(matches!(
            registry.remove_private(process),
            HeapRemoval::ProcessHeap
        ));
        assert!(matches!(
            registry.remove_private(first),
            HeapRemoval::Removed(_)
        ));
        let mut handles = [core::ptr::null_mut(); 3];
        assert_eq!(registry.copy_handles(&mut handles), 2);
        assert_eq!(&handles[..2], &[process, second]);
        assert!(matches!(
            registry.remove_private(first),
            HeapRemoval::NotFound
        ));
    }

    #[test]
    fn registry_capacity_failure_returns_the_unregistered_heap() {
        let mut registry = HeapRegistry::<VecBacking, 1>::new();
        registry.install_process(heap(512)).ok().unwrap();
        registry.insert_private(heap(512)).ok().unwrap();
        let rejected = registry.insert_private(heap(512)).unwrap_err();
        assert_eq!(registry.len(), 2);
        assert!(rejected.handle().is_null() == false);
    }

    #[test]
    fn heap_compatibility_mode_is_per_heap_and_one_way() {
        let mut standard = heap(512);
        let low_fragmentation = heap(512);
        assert_eq!(standard.compatibility_mode(), 0);
        assert_eq!(low_fragmentation.compatibility_mode(), 0);
        standard.enable_low_fragmentation();
        assert_eq!(standard.compatibility_mode(), 2);
        assert_eq!(low_fragmentation.compatibility_mode(), 0);
    }
}
