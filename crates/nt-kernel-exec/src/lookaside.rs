//! Lookaside lists (`ExInitialize{,N}PagedLookasideList`) — the x64 `nt!_GENERAL_LOOKASIDE`
//! layout + initialization semantics as a raw-memory primitive.
//!
//! A lookaside list is a per-type object cache: a driver hands the executive a `GENERAL_LOOKASIDE`
//! descriptor (in its own memory) and the executive fills in the SLIST free-list header, the
//! object `Size`/`Tag`/pool `Type`, and the `Allocate`/`Free` callbacks the driver invokes on a
//! cache miss/free. Because the descriptor lives in the caller's (driver's) memory, this is a
//! layout-over-raw-pointer primitive rather than a runtime-side table — but the field offsets and
//! init rules are real NT semantics, unit-tested here and reused by every hosted kernel binary
//! (win32k.sys is the current forcing function).

/// x64 `nt!_GENERAL_LOOKASIDE` field offsets (verified against the public symbols / WDK layout).
pub mod general_lookaside {
    /// `SLIST_HEADER ListHead` — the interlocked free-list head (16 bytes).
    pub const LIST_HEAD: usize = 0x00;
    /// `USHORT Depth` — current cached-object count.
    pub const DEPTH: usize = 0x10;
    /// `USHORT MaximumDepth` — cap on cached objects.
    pub const MAXIMUM_DEPTH: usize = 0x12;
    /// `ULONG TotalAllocates`.
    pub const TOTAL_ALLOCATES: usize = 0x14;
    /// `ULONG AllocateHits` (union AllocateMisses).
    pub const ALLOCATE_HITS: usize = 0x18;
    /// `ULONG TotalFrees`.
    pub const TOTAL_FREES: usize = 0x1c;
    /// `ULONG FreeHits` (union FreeMisses).
    pub const FREE_HITS: usize = 0x20;
    /// `POOL_TYPE Type` (ULONG).
    pub const TYPE: usize = 0x24;
    /// `ULONG Tag`.
    pub const TAG: usize = 0x28;
    /// `ULONG Size`.
    pub const SIZE: usize = 0x2c;
    /// `PALLOCATE_FUNCTION Allocate` — `PVOID(POOL_TYPE, SIZE_T, ULONG Tag)`.
    pub const ALLOCATE: usize = 0x30;
    /// `PFREE_FUNCTION Free` — `VOID(PVOID)`.
    pub const FREE: usize = 0x38;
    /// `LIST_ENTRY ListEntry` — links this list into the global lookaside list (16 bytes).
    pub const LIST_ENTRY: usize = 0x40;
    /// `ULONG LastTotalAllocates`.
    pub const LAST_TOTAL_ALLOCATES: usize = 0x50;
    /// Total structure size to zero on init.
    pub const SIZE_OF: usize = 0x60;
}

/// `POOL_TYPE` values (the subset a lookaside records for its `Allocate` callback).
pub const POOL_TYPE_NONPAGED: u32 = 0;
pub const POOL_TYPE_PAGED: u32 = 1;

/// The `MaximumDepth` NT uses when the caller passes 0.
pub const DEFAULT_MAXIMUM_DEPTH: u16 = 256;

/// Initialize a `GENERAL_LOOKASIDE` at `base` (the descriptor in the driver's memory), mirroring
/// `ExpInitializeLookasideList`: zero the structure, set the pool `Type`/`Tag`/object `Size`, the
/// `Allocate`/`Free` callbacks, `MaximumDepth` (defaulting to [`DEFAULT_MAXIMUM_DEPTH`]), and an
/// empty self-linked `ListEntry`. The free-list starts empty, so the driver's first allocation
/// misses and calls `Allocate`.
///
/// `self_va` is the virtual address of `base` in the *target's* address space (used for the
/// self-linked `ListEntry`). In a same-address-space host this equals `base as u64`.
///
/// # Safety
/// `base` must point to at least [`general_lookaside::SIZE_OF`] writable bytes; `allocate` /
/// `free` must be valid `PALLOCATE_FUNCTION` / `PFREE_FUNCTION` pointers.
pub unsafe fn init_general_lookaside(
    base: *mut u8,
    self_va: u64,
    allocate: u64,
    free: u64,
    size: u32,
    tag: u32,
    depth: u16,
    pool_type: u32,
) {
    use general_lookaside as o;
    core::ptr::write_bytes(base, 0, o::SIZE_OF);
    core::ptr::write_unaligned(base.add(o::DEPTH) as *mut u16, 0);
    core::ptr::write_unaligned(
        base.add(o::MAXIMUM_DEPTH) as *mut u16,
        if depth == 0 { DEFAULT_MAXIMUM_DEPTH } else { depth },
    );
    core::ptr::write_unaligned(base.add(o::TYPE) as *mut u32, pool_type);
    core::ptr::write_unaligned(base.add(o::TAG) as *mut u32, tag);
    core::ptr::write_unaligned(base.add(o::SIZE) as *mut u32, size);
    core::ptr::write_unaligned(base.add(o::ALLOCATE) as *mut u64, allocate);
    core::ptr::write_unaligned(base.add(o::FREE) as *mut u64, free);
    // An empty circular list (Flink = Blink = &ListEntry) so a global-lookaside walk is safe.
    let le = self_va + o::LIST_ENTRY as u64;
    core::ptr::write_unaligned(base.add(o::LIST_ENTRY) as *mut u64, le);
    core::ptr::write_unaligned(base.add(o::LIST_ENTRY + 8) as *mut u64, le);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::general_lookaside as o;
    use super::*;

    #[test]
    fn lays_out_general_lookaside() {
        let mut buf = [0xAAu8; o::SIZE_OF];
        let base = buf.as_mut_ptr();
        let va = base as u64;
        unsafe {
            init_general_lookaside(base, va, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888, 0x40, 0x6b736157, 0, POOL_TYPE_PAGED);
        }
        let r32 = |off: usize| u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let r16 = |off: usize| u16::from_le_bytes(buf[off..off + 2].try_into().unwrap());
        let r64 = |off: usize| u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        // ListHead zeroed (empty free-list).
        assert_eq!(r64(o::LIST_HEAD), 0);
        assert_eq!(r64(o::LIST_HEAD + 8), 0);
        assert_eq!(r16(o::DEPTH), 0);
        assert_eq!(r16(o::MAXIMUM_DEPTH), DEFAULT_MAXIMUM_DEPTH); // depth 0 -> default
        assert_eq!(r32(o::TOTAL_ALLOCATES), 0);
        assert_eq!(r32(o::TYPE), POOL_TYPE_PAGED);
        assert_eq!(r32(o::TAG), 0x6b736157);
        assert_eq!(r32(o::SIZE), 0x40);
        assert_eq!(r64(o::ALLOCATE), 0x1111_2222_3333_4444);
        assert_eq!(r64(o::FREE), 0x5555_6666_7777_8888);
        // Self-linked empty ListEntry.
        assert_eq!(r64(o::LIST_ENTRY), va + o::LIST_ENTRY as u64);
        assert_eq!(r64(o::LIST_ENTRY + 8), va + o::LIST_ENTRY as u64);
    }

    #[test]
    fn honors_explicit_depth_and_nonpaged() {
        let mut buf = [0u8; o::SIZE_OF];
        let base = buf.as_mut_ptr();
        unsafe {
            init_general_lookaside(base, base as u64, 0xDEAD, 0xBEEF, 0x20, 0x1234, 32, POOL_TYPE_NONPAGED);
        }
        let r16 = |off: usize| u16::from_le_bytes(buf[off..off + 2].try_into().unwrap());
        let r32 = |off: usize| u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        assert_eq!(r16(o::MAXIMUM_DEPTH), 32);
        assert_eq!(r32(o::TYPE), POOL_TYPE_NONPAGED);
    }
}
