//! # `nt-address-space` — Memory Manager address space + fault handling
//!
//! The demand-paging layer beneath the section objects (spec: NT Memory Manager Address Space +
//! Fault Handling): an [`AddressSpace`] with a VAD tree (64 KiB allocation granularity, 4 KiB
//! pages, first-fit VA allocation + overlap detection, commit accounting), demand-mode section /
//! anonymous view reservation, a page-**fault resolver** ([`AddressSpace::fault`]) that
//! materialises section-backed pages from the Cache Manager and zero-fills anonymous pages
//! (with protection + access-violation checks), dirty writeback on unmap, and
//! `MmProbeAndLockPages` MDL locking.
//!
//! Unlike the eager M24 view, a reserved view's pages start `CommittedNotResident` and only
//! become `Resident` on first touch (a fault) — real demand paging. The resolved page's bytes are
//! a host-side buffer; the Driver Host projects it into a real VA. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use nt_cache_manager::{CachedStreamBacking, SharedCacheMap};

pub const PAGE_SIZE: u64 = 4096;
pub const ALLOCATION_GRANULARITY: u64 = 64 * 1024;

/// One contiguous part of a byte range that lies within a single native page.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PageChunk {
    pub page_base: u64,
    pub page_offset: usize,
    pub length: usize,
}

/// Allocation-free iterator over the pages touched by a byte range.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PageChunks {
    next_address: u64,
    remaining: usize,
}

/// Split `[address, address + length)` into page-bounded chunks.
///
/// Returns `None` when the byte range would overflow the native address space.
pub fn page_chunks(address: u64, length: usize) -> Option<PageChunks> {
    let length_u64 = u64::try_from(length).ok()?;
    address.checked_add(length_u64)?;
    Some(PageChunks {
        next_address: address,
        remaining: length,
    })
}

impl Iterator for PageChunks {
    type Item = PageChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let page_base = self.next_address & !(PAGE_SIZE - 1);
        let page_offset = (self.next_address - page_base) as usize;
        let length = (PAGE_SIZE as usize - page_offset).min(self.remaining);
        self.next_address += length as u64;
        self.remaining -= length;
        Some(PageChunk {
            page_base,
            page_offset,
            length,
        })
    }
}

// NTSTATUS
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_INVALID_PAGE_PROTECTION: u32 = 0xC000_0045;
pub const STATUS_COMMITMENT_LIMIT: u32 = 0xC000_012D;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_UNABLE_TO_FREE_VM: u32 = 0xC000_001A;
pub const STATUS_FREE_VM_NOT_AT_BASE: u32 = 0xC000_009F;
pub const STATUS_MEMORY_NOT_ALLOCATED: u32 = 0xC000_00A0;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
pub const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
pub const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
pub const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
pub const STATUS_INVALID_PARAMETER_6: u32 = 0xC000_00F4;
pub const STATUS_NOT_COMMITTED: u32 = 0xC000_002D;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_DECOMMIT: u32 = 0x4000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_FREE: u32 = 0x0001_0000;
pub const MEM_PRIVATE: u32 = 0x0002_0000;
pub const MEM_MAPPED: u32 = 0x0004_0000;
pub const MEM_RESET: u32 = 0x0008_0000;
pub const MEM_TOP_DOWN: u32 = 0x0010_0000;
pub const MEM_WRITE_WATCH: u32 = 0x0020_0000;
pub const MEM_PHYSICAL: u32 = 0x0040_0000;
pub const MEM_IMAGE: u32 = 0x0100_0000;
pub const MEM_LARGE_PAGES: u32 = 0x2000_0000;

// Page protection
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;
pub const VM_PROTECTION_OVERRIDE_CAPACITY: usize = 128;
pub const MEMORY_BASIC_INFORMATION_X64_SIZE: usize = 0x30;

fn base_protection(p: u32) -> u32 {
    p & 0xff
}

fn readable(p: u32) -> bool {
    matches!(
        base_protection(p),
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

fn writable(p: u32) -> bool {
    matches!(base_protection(p), PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
}

fn executable(p: u32) -> bool {
    matches!(
        base_protection(p),
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

fn protection_allows_fault_access(protection: u32, access: FaultAccess) -> bool {
    if protection & PAGE_GUARD != 0 || base_protection(protection) == PAGE_NOACCESS {
        return false;
    }
    match access {
        FaultAccess::Read | FaultAccess::Lock => readable(protection),
        FaultAccess::Write => writable(protection),
        FaultAccess::Execute => executable(protection),
    }
}

fn mapped_protection_allows_fault_access(protection: u32, access: FaultAccess) -> bool {
    if protection & PAGE_GUARD != 0 || base_protection(protection) == PAGE_NOACCESS {
        return false;
    }
    match access {
        FaultAccess::Read | FaultAccess::Lock => readable(protection),
        FaultAccess::Write => matches!(
            base_protection(protection),
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY
        ),
        FaultAccess::Execute => executable(protection),
    }
}

fn image_protection_allows_fault_access(protection: u32, access: FaultAccess) -> bool {
    if protection & PAGE_GUARD != 0 || base_protection(protection) == PAGE_NOACCESS {
        return false;
    }
    match access {
        FaultAccess::Read | FaultAccess::Lock => readable(protection),
        FaultAccess::Write => matches!(
            base_protection(protection),
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY
        ),
        FaultAccess::Execute => executable(protection),
    }
}
fn valid_prot(p: u32) -> bool {
    valid_allocate_protection(p)
}

fn valid_allocate_protection(protection: u32) -> bool {
    const BASE_MASK: u32 = 0xff;
    const MODIFIER_MASK: u32 = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    let base = protection & BASE_MASK;
    let valid_base = matches!(
        base,
        PAGE_NOACCESS
            | PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    );
    valid_base
        && protection & !(BASE_MASK | MODIFIER_MASK) == 0
        && !(base == PAGE_NOACCESS && protection & MODIFIER_MASK != 0)
        && !(protection & PAGE_NOCACHE != 0
            && protection & (PAGE_NOACCESS | PAGE_WRITECOMBINE) != 0)
        && !(protection & PAGE_WRITECOMBINE != 0 && base == PAGE_NOACCESS)
}

/// Validate the argument-only protection mask accepted by ReactOS `NtProtectVirtualMemory`.
pub fn validate_protect_parameters(protection: u32) -> Result<(), u32> {
    let base = protection & !(PAGE_GUARD | PAGE_NOCACHE);
    if matches!(
        base,
        PAGE_NOACCESS
            | PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    ) {
        Ok(())
    } else {
        Err(STATUS_INVALID_PAGE_PROTECTION)
    }
}

/// Validate the argument-only part of ReactOS `NtAllocateVirtualMemory`, before user-pointer
/// probing or process-handle lookup. Mechanism-dependent unsupported flags are rejected later,
/// after the handle check, at the same point ReactOS rejects them.
pub fn validate_allocate_parameters(
    zero_bits: u64,
    allocation_type: u32,
    protection: u32,
) -> Result<(), u32> {
    const MI_MAX_ZERO_BITS: u64 = 53;
    const ALLOWED: u32 = MEM_COMMIT
        | MEM_RESERVE
        | MEM_RESET
        | MEM_PHYSICAL
        | MEM_TOP_DOWN
        | MEM_WRITE_WATCH
        | MEM_LARGE_PAGES;

    if zero_bits > MI_MAX_ZERO_BITS {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    if allocation_type & !ALLOWED != 0
        || allocation_type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET) == 0
        || allocation_type & MEM_RESET != 0 && allocation_type != MEM_RESET
    {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    if allocation_type & MEM_LARGE_PAGES != 0 {
        if allocation_type & MEM_COMMIT == 0
            || allocation_type & (MEM_PHYSICAL | MEM_RESET | MEM_WRITE_WATCH) != 0
        {
            return Err(STATUS_INVALID_PARAMETER_5);
        }
    }
    if allocation_type & MEM_WRITE_WATCH != 0 && allocation_type & MEM_RESERVE == 0 {
        return Err(STATUS_INVALID_PARAMETER_5);
    }
    if allocation_type & MEM_PHYSICAL != 0 {
        if allocation_type & MEM_RESERVE == 0
            || allocation_type & !(MEM_RESERVE | MEM_TOP_DOWN | MEM_PHYSICAL) != 0
        {
            return Err(STATUS_INVALID_PARAMETER_5);
        }
        if protection != PAGE_READWRITE {
            return Err(STATUS_INVALID_PARAMETER_6);
        }
    }
    if !valid_allocate_protection(protection) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    Ok(())
}

/// Reservation state for one private-memory extent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmExtentState {
    Reserved,
    Committed,
}

/// One contiguous part of a private allocation. Splitting an allocation preserves its original
/// `allocation_base`, which lets release/decommit apply ReactOS VAD rules without heap allocation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmExtent {
    pub base: u64,
    pub size: u64,
    pub allocation_base: u64,
    pub protection: u32,
    pub state: VmExtentState,
}

impl VmExtent {
    pub const fn end(self) -> u64 {
        self.base + self.size
    }
}

/// The normalized range produced after a successful reserve/commit policy mutation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmAllocatePlan {
    pub base: u64,
    pub size: u64,
}

/// The normalized range whose committed pages must be unmapped after a successful policy mutation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmFreePlan {
    pub base: u64,
    pub size: u64,
    pub free_type: u32,
}

/// The normalized private-memory range changed by `NtProtectVirtualMemory`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmProtectPlan {
    pub base: u64,
    pub size: u64,
    pub old_protection: u32,
    pub new_protection: u32,
}

/// The x64 `MEMORY_BASIC_INFORMATION` payload returned by `NtQueryVirtualMemory`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmBasicInformation {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub type_: u32,
}

impl VmBasicInformation {
    pub fn encode_x64(self) -> [u8; MEMORY_BASIC_INFORMATION_X64_SIZE] {
        let mut out = [0u8; MEMORY_BASIC_INFORMATION_X64_SIZE];
        out[0x00..0x08].copy_from_slice(&self.base_address.to_le_bytes());
        out[0x08..0x10].copy_from_slice(&self.allocation_base.to_le_bytes());
        out[0x10..0x14].copy_from_slice(&self.allocation_protect.to_le_bytes());
        out[0x18..0x20].copy_from_slice(&self.region_size.to_le_bytes());
        out[0x20..0x24].copy_from_slice(&self.state.to_le_bytes());
        out[0x24..0x28].copy_from_slice(&self.protect.to_le_bytes());
        out[0x28..0x2c].copy_from_slice(&self.type_.to_le_bytes());
        out
    }
}

/// A committed user mapping that is not owned by the private VAD allocator.
///
/// This records process-lifetime runtime pages, mapped sections, and other fixed VA mappings at
/// the point the kernel actually maps them. It is deliberately separate from `VmRegionMap`: those
/// maps own the allocatable private heap range, while these ranges can live anywhere in user space.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmCommittedRange {
    pub base: u64,
    pub size: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub protect: u32,
    pub type_: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmImageAllocation {
    pub allocation_base: u64,
    pub allocation_end: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmCommittedProtectPlan {
    pub base: u64,
    pub size: u64,
    pub old_protection: u32,
    pub new_protection: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmMappedViewFaultPlan {
    pub map_protection: u32,
    pub mark_dirty: bool,
    pub copy_on_write: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmImageViewFaultPlan {
    pub map_protection: u32,
    pub copy_on_write: bool,
}

pub fn mapped_view_fault_plan(protection: u32, write_fault: bool) -> VmMappedViewFaultPlan {
    let base = protection & 0xff;
    let modifiers = protection & !0xff;
    match base {
        PAGE_READWRITE => VmMappedViewFaultPlan {
            map_protection: if write_fault {
                protection
            } else {
                PAGE_READONLY | modifiers
            },
            mark_dirty: write_fault,
            copy_on_write: false,
        },
        PAGE_EXECUTE_READWRITE => VmMappedViewFaultPlan {
            map_protection: if write_fault {
                protection
            } else {
                PAGE_EXECUTE_READ | modifiers
            },
            mark_dirty: write_fault,
            copy_on_write: false,
        },
        PAGE_WRITECOPY => VmMappedViewFaultPlan {
            map_protection: if write_fault {
                PAGE_READWRITE | modifiers
            } else {
                PAGE_READONLY | modifiers
            },
            mark_dirty: false,
            copy_on_write: write_fault,
        },
        PAGE_EXECUTE_WRITECOPY => VmMappedViewFaultPlan {
            map_protection: if write_fault {
                PAGE_EXECUTE_READWRITE | modifiers
            } else {
                PAGE_EXECUTE_READ | modifiers
            },
            mark_dirty: false,
            copy_on_write: write_fault,
        },
        _ => VmMappedViewFaultPlan {
            map_protection: protection,
            mark_dirty: false,
            copy_on_write: false,
        },
    }
}

pub fn mapped_view_fault_access_status(protection: u32, access: FaultAccess) -> Result<(), u32> {
    if !mapped_protection_allows_fault_access(protection, access) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

pub fn image_view_fault_access_status(protection: u32, access: FaultAccess) -> Result<(), u32> {
    if !image_protection_allows_fault_access(protection, access) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

pub fn private_guard_page_fault_plan(protection: u32, access: FaultAccess) -> Option<u32> {
    if protection & PAGE_GUARD == 0 {
        return None;
    }
    let unguarded = protection & !PAGE_GUARD;
    protection_allows_fault_access(unguarded, access).then_some(unguarded)
}

pub fn image_view_fault_plan(protection: u32, write_fault: bool) -> VmImageViewFaultPlan {
    let base = protection & 0xff;
    let modifiers = protection & !0xff;
    match base {
        PAGE_WRITECOPY => VmImageViewFaultPlan {
            map_protection: if write_fault {
                PAGE_READWRITE | modifiers
            } else {
                PAGE_READONLY | modifiers
            },
            copy_on_write: write_fault,
        },
        PAGE_EXECUTE_WRITECOPY => VmImageViewFaultPlan {
            map_protection: if write_fault {
                PAGE_EXECUTE_READWRITE | modifiers
            } else {
                PAGE_EXECUTE_READ | modifiers
            },
            copy_on_write: write_fault,
        },
        _ => VmImageViewFaultPlan {
            map_protection: protection,
            copy_on_write: false,
        },
    }
}

/// True when a SEC_IMAGE page can be backed by one immutable shared cache frame for the current
/// fault plan. Plain write-copy data is intentionally excluded: ReactOS loader fixups and winsrv
/// initialization still require per-process ownership for those pages. Execute-writecopy read faults
/// remain cacheable because their read plan maps executable text as execute-read; a later write fault
/// promotes through the normal image COW path.
pub fn image_view_shared_cacheable(protection: u32, map_protection: u32) -> bool {
    if protection & PAGE_GUARD != 0 {
        return false;
    }
    matches!(
        base_protection(protection),
        PAGE_READONLY | PAGE_EXECUTE | PAGE_EXECUTE_READ
    ) || matches!(
        base_protection(map_protection),
        PAGE_EXECUTE | PAGE_EXECUTE_READ
    )
}

impl VmCommittedRange {
    pub const fn private(base: u64, size: u64, protect: u32) -> Self {
        Self {
            base,
            size,
            allocation_base: base,
            allocation_protect: protect,
            protect,
            type_: MEM_PRIVATE,
        }
    }

    pub const fn mapped(base: u64, size: u64, protect: u32) -> Self {
        Self {
            base,
            size,
            allocation_base: base,
            allocation_protect: protect,
            protect,
            type_: MEM_MAPPED,
        }
    }

    pub const fn image(base: u64, size: u64, protect: u32) -> Self {
        Self::image_region(base, size, base, protect)
    }

    pub const fn image_region(base: u64, size: u64, allocation_base: u64, protect: u32) -> Self {
        Self {
            base,
            size,
            allocation_base,
            allocation_protect: PAGE_EXECUTE_WRITECOPY,
            protect,
            type_: MEM_IMAGE,
        }
    }

    pub fn end(self) -> u64 {
        self.base.saturating_add(self.size)
    }

    fn contains(self, page: u64) -> bool {
        page >= self.base && page < self.end()
    }

    fn contiguous_with(self, next: Self) -> bool {
        self.end() == next.base
            && self.allocation_base == next.allocation_base
            && self.allocation_protect == next.allocation_protect
            && self.protect == next.protect
            && self.type_ == next.type_
    }

    fn info_at(self, page: u64) -> VmBasicInformation {
        VmBasicInformation {
            base_address: page,
            allocation_base: self.allocation_base,
            allocation_protect: self.allocation_protect,
            region_size: self.end() - page,
            state: MEM_COMMIT,
            protect: self.protect,
            type_: self.type_,
        }
    }
}

#[derive(Copy, Clone)]
pub struct VmCommittedRangeTable<const N: usize> {
    ranges: [Option<VmCommittedRange>; N],
}

impl<const N: usize> VmCommittedRangeTable<N> {
    pub const fn new() -> Self {
        Self { ranges: [None; N] }
    }

    pub fn range_count(&self) -> usize {
        self.ranges.iter().filter(|range| range.is_some()).count()
    }

    pub fn register(&mut self, range: VmCommittedRange) -> Result<(), u32> {
        let Some(end) = range.base.checked_add(range.size) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if range.base & (PAGE_SIZE - 1) != 0
            || range.size == 0
            || range.size & (PAGE_SIZE - 1) != 0
            || end <= range.base
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.ranges.iter().flatten().any(|current| {
            range.base < current.end() && current.base < range.end() && *current != range
        }) {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        if self
            .ranges
            .iter()
            .flatten()
            .any(|current| *current == range)
        {
            return Ok(());
        }
        let slot = self
            .ranges
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        *slot = Some(range);
        self.normalize();
        Ok(())
    }

    pub fn overlaps_range(&self, base: u64, size: u64) -> Result<bool, u32> {
        let Some(end) = base.checked_add(size) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if base & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 || end <= base {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(self
            .ranges
            .iter()
            .flatten()
            .any(|range| base < range.end() && range.base < end))
    }

    pub fn first_overlap_range(
        &self,
        base: u64,
        size: u64,
    ) -> Result<Option<VmCommittedRange>, u32> {
        let Some(end) = base.checked_add(size) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if base & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 || end <= base {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(self
            .ranges
            .iter()
            .flatten()
            .copied()
            .filter(|range| base < range.end() && range.base < end)
            .min_by_key(|range| range.base))
    }

    pub fn unregister_base(&mut self, base: u64) -> Option<VmCommittedRange> {
        let slot = self
            .ranges
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|range| range.base == base))?;
        let removed = slot.take();
        self.normalize();
        removed
    }

    pub fn unregister_range(&mut self, base: u64, size: u64) -> Result<usize, u32> {
        let Some(end) = base.checked_add(size) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        if base & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 || end <= base {
            return Err(STATUS_INVALID_PARAMETER);
        }

        let mut replacement = [None; N];
        let mut used = 0usize;
        let mut removed = 0usize;
        for range in self.ranges.iter().flatten().copied() {
            if range.end() <= base || range.base >= end {
                push_committed_range(&mut replacement, &mut used, range)?;
                continue;
            }
            removed += 1;
            if range.base < base {
                let mut left = range;
                left.size = base - range.base;
                push_committed_range(&mut replacement, &mut used, left)?;
            }
            if range.end() > end {
                let mut right = range;
                right.base = end;
                right.size = range.end() - end;
                push_committed_range(&mut replacement, &mut used, right)?;
            }
        }
        self.ranges = replacement;
        if removed != 0 {
            self.normalize();
        }
        Ok(removed)
    }

    pub fn unregister_allocation_base(&mut self, allocation_base: u64) -> usize {
        let mut removed = 0usize;
        for slot in &mut self.ranges {
            if slot
                .as_ref()
                .is_some_and(|range| range.allocation_base == allocation_base)
            {
                *slot = None;
                removed += 1;
            }
        }
        if removed != 0 {
            self.normalize();
        }
        removed
    }

    pub fn query_basic(&self, address: u64) -> Option<VmBasicInformation> {
        let page = address & !(PAGE_SIZE - 1);
        self.ranges
            .iter()
            .flatten()
            .copied()
            .find(|range| range.contains(page))
            .map(|range| range.info_at(page))
    }

    pub fn image_allocation_for_page(&self, address: u64) -> Option<VmImageAllocation> {
        let page = address & !(PAGE_SIZE - 1);
        let allocation_base = self
            .ranges
            .iter()
            .flatten()
            .find(|range| range.type_ == MEM_IMAGE && range.contains(page))?
            .allocation_base;
        let allocation_end = self
            .ranges
            .iter()
            .flatten()
            .filter(|range| range.type_ == MEM_IMAGE && range.allocation_base == allocation_base)
            .map(|range| range.end())
            .max()?;
        Some(VmImageAllocation {
            allocation_base,
            allocation_end,
        })
    }

    pub fn protect(
        &mut self,
        address: u64,
        size: u64,
        new_protection: u32,
    ) -> Result<VmCommittedProtectPlan, u32> {
        validate_protect_parameters(new_protection)?;
        let base = address & !(PAGE_SIZE - 1);
        let Some(end_unrounded) = address.checked_add(size) else {
            return Err(STATUS_INVALID_PARAMETER_3);
        };
        let end = end_unrounded
            .checked_add(PAGE_SIZE - 1)
            .map(|value| value & !(PAGE_SIZE - 1))
            .ok_or(STATUS_INVALID_PARAMETER_3)?;
        if size == 0 || end <= base {
            return Err(STATUS_INVALID_PARAMETER_3);
        }
        let first = self
            .ranges
            .iter()
            .flatten()
            .copied()
            .find(|range| range.contains(base))
            .ok_or(STATUS_CONFLICTING_ADDRESSES)?;
        if first.type_ != MEM_PRIVATE && new_protection & (PAGE_NOCACHE | PAGE_WRITECOMBINE) != 0 {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        let new_base_protection = new_protection & 0xff;
        if first.type_ == MEM_PRIVATE
            && matches!(new_base_protection, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)
        {
            return Err(STATUS_INVALID_PARAMETER_4);
        }

        let mut cursor = base;
        while cursor < end {
            let range = self
                .ranges
                .iter()
                .flatten()
                .copied()
                .find(|range| range.contains(cursor))
                .ok_or(STATUS_NOT_COMMITTED)?;
            if range.allocation_base != first.allocation_base || range.type_ != first.type_ {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            cursor = range.end().min(end);
        }

        let mut replacement = [None; N];
        let mut used = 0usize;
        for range in self.ranges.iter().flatten().copied() {
            if range.end() <= base || range.base >= end {
                push_committed_range(&mut replacement, &mut used, range)?;
                continue;
            }
            if range.base < base {
                let mut left = range;
                left.size = base - range.base;
                push_committed_range(&mut replacement, &mut used, left)?;
            }
            let overlap_base = range.base.max(base);
            let overlap_end = range.end().min(end);
            let mut middle = range;
            middle.base = overlap_base;
            middle.size = overlap_end - overlap_base;
            middle.protect = new_protection;
            push_committed_range(&mut replacement, &mut used, middle)?;
            if range.end() > end {
                let mut right = range;
                right.base = end;
                right.size = range.end() - end;
                push_committed_range(&mut replacement, &mut used, right)?;
            }
        }
        self.ranges = replacement;
        self.normalize();
        Ok(VmCommittedProtectPlan {
            base,
            size: end - base,
            old_protection: first.protect,
            new_protection,
        })
    }

    pub fn next_base_after(&self, address: u64) -> Option<u64> {
        self.ranges
            .iter()
            .flatten()
            .filter(|range| range.base > address)
            .map(|range| range.base)
            .min()
    }

    fn normalize(&mut self) {
        for left in 0..N {
            for right in left + 1..N {
                let swap = match (self.ranges[left], self.ranges[right]) {
                    (None, Some(_)) => true,
                    (Some(a), Some(b)) => b.base < a.base,
                    _ => false,
                };
                if swap {
                    self.ranges.swap(left, right);
                }
            }
        }
        let mut read = 0usize;
        let mut write = 0usize;
        while read < N {
            let Some(mut current) = self.ranges[read] else {
                break;
            };
            read += 1;
            while read < N {
                let Some(next) = self.ranges[read] else {
                    break;
                };
                if !current.contiguous_with(next) {
                    break;
                }
                current.size += next.size;
                read += 1;
            }
            self.ranges[write] = Some(current);
            write += 1;
        }
        self.ranges[write..].fill(None);
    }
}

fn push_committed_range<const N: usize>(
    ranges: &mut [Option<VmCommittedRange>; N],
    used: &mut usize,
    range: VmCommittedRange,
) -> Result<(), u32> {
    if range.size == 0 {
        return Ok(());
    }
    if *used >= N {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    ranges[*used] = Some(range);
    *used += 1;
    Ok(())
}

/// A per-private-page protection override. ReactOS `MiProtectVirtualMemory` changes PTE
/// protections for private pages; it does not split the VAD node for every protected subrange.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct VmProtectionOverride {
    page: u64,
    protection: u32,
}

/// Fixed-capacity private VAD policy for the executive. This deliberately owns no `Vec` or
/// `BTreeMap`: syscall dispatch rewinds its transient bump heap after every call.
#[derive(Copy, Clone)]
pub struct VmRegionMap<const N: usize> {
    lower_bound: u64,
    upper_bound: u64,
    extents: [Option<VmExtent>; N],
    protection_overrides: [Option<VmProtectionOverride>; VM_PROTECTION_OVERRIDE_CAPACITY],
}

impl<const N: usize> VmRegionMap<N> {
    pub const fn new(lower_bound: u64, upper_bound: u64) -> Self {
        Self {
            lower_bound,
            upper_bound,
            extents: [None; N],
            protection_overrides: [None; VM_PROTECTION_OVERRIDE_CAPACITY],
        }
    }

    pub fn extent_count(&self) -> usize {
        self.extents
            .iter()
            .filter(|extent| extent.is_some())
            .count()
    }

    pub fn extent_at(&self, address: u64) -> Option<VmExtent> {
        self.extents
            .iter()
            .flatten()
            .copied()
            .find(|extent| address >= extent.base && address < extent.end())
    }

    pub fn next_extent_base_after(&self, address: u64) -> Option<u64> {
        self.extents
            .iter()
            .flatten()
            .filter(|extent| extent.base > address)
            .map(|extent| extent.base)
            .min()
    }

    pub fn protection_override_count(&self) -> usize {
        self.protection_overrides
            .iter()
            .filter(|override_slot| override_slot.is_some())
            .count()
    }

    fn protection_override_index(&self, page: u64) -> Option<usize> {
        self.protection_overrides
            .iter()
            .position(|override_slot| override_slot.is_some_and(|entry| entry.page == page))
    }

    fn override_protection_at(&self, address: u64) -> Option<u32> {
        let page = address & !(PAGE_SIZE - 1);
        self.protection_override_index(page)
            .and_then(|index| self.protection_overrides[index].map(|entry| entry.protection))
    }

    pub fn protection_at(&self, address: u64) -> Option<u32> {
        let extent = self.extent_at(address)?;
        (extent.state == VmExtentState::Committed).then(|| {
            self.override_protection_at(address)
                .unwrap_or(extent.protection)
        })
    }

    pub fn is_committed(&self, address: u64) -> bool {
        self.extent_at(address)
            .is_some_and(|extent| extent.state == VmExtentState::Committed)
    }

    pub fn permits_read(&self, address: u64) -> bool {
        self.protection_at(address)
            .is_some_and(|protection| protection_allows_fault_access(protection, FaultAccess::Read))
    }

    pub fn permits_write(&self, address: u64) -> bool {
        self.protection_at(address).is_some_and(|protection| {
            protection_allows_fault_access(protection, FaultAccess::Write)
        })
    }

    fn align_up(value: u64, alignment: u64) -> Option<u64> {
        value
            .checked_add(alignment - 1)
            .map(|value| value & !(alignment - 1))
    }

    fn basic_state_and_protection(&self, address: u64) -> Option<(u32, u32)> {
        let extent = self.extent_at(address)?;
        Some(match extent.state {
            VmExtentState::Reserved => (MEM_RESERVE, 0),
            VmExtentState::Committed => (
                MEM_COMMIT,
                self.override_protection_at(address)
                    .unwrap_or(extent.protection),
            ),
        })
    }

    /// Query private VAD state for `address`, returning a ReactOS-compatible
    /// `MEMORY_BASIC_INFORMATION` view. `address_space_end` is the exclusive user VA ceiling used
    /// to size free gaps after the final VAD.
    pub fn query_basic(
        &self,
        address: u64,
        address_space_end: u64,
    ) -> Result<VmBasicInformation, u32> {
        let base = address & !(PAGE_SIZE - 1);
        if base >= address_space_end {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(extent) = self.extent_at(base) {
            let (state, protect) = self.basic_state_and_protection(base).unwrap();
            let mut end = (base + PAGE_SIZE).min(extent.end()).min(address_space_end);
            while end < extent.end() && end < address_space_end {
                match self.basic_state_and_protection(end) {
                    Some((next_state, next_protect))
                        if next_state == state && next_protect == protect =>
                    {
                        end = (end + PAGE_SIZE).min(extent.end()).min(address_space_end);
                    }
                    _ => break,
                }
            }
            Ok(VmBasicInformation {
                base_address: base,
                allocation_base: extent.allocation_base,
                allocation_protect: extent.protection,
                region_size: end - base,
                state,
                protect,
                type_: MEM_PRIVATE,
            })
        } else {
            let next = self
                .next_extent_base_after(base)
                .unwrap_or(address_space_end)
                .min(address_space_end);
            Ok(VmBasicInformation {
                base_address: base,
                allocation_base: 0,
                allocation_protect: 0,
                region_size: next.saturating_sub(base),
                state: MEM_FREE,
                protect: PAGE_NOACCESS,
                type_: 0,
            })
        }
    }

    fn overlaps(&self, base: u64, end: u64) -> bool {
        self.extents
            .iter()
            .flatten()
            .any(|extent| base < extent.end() && extent.base < end)
    }

    fn insert(&mut self, extent: VmExtent) -> Result<(), u32> {
        let slot = self
            .extents
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        *slot = Some(extent);
        Ok(())
    }

    fn normalize(&mut self) {
        for left in 0..N {
            for right in left + 1..N {
                let swap = match (self.extents[left], self.extents[right]) {
                    (None, Some(_)) => true,
                    (Some(a), Some(b)) => b.base < a.base,
                    _ => false,
                };
                if swap {
                    self.extents.swap(left, right);
                }
            }
        }
        let mut read = 0usize;
        let mut write = 0usize;
        while read < N {
            let Some(mut current) = self.extents[read] else {
                break;
            };
            read += 1;
            while read < N {
                let Some(next) = self.extents[read] else {
                    break;
                };
                if current.end() != next.base
                    || current.allocation_base != next.allocation_base
                    || current.protection != next.protection
                    || current.state != next.state
                {
                    break;
                }
                current.size += next.size;
                read += 1;
            }
            self.extents[write] = Some(current);
            write += 1;
        }
        self.extents[write..].fill(None);
    }

    fn push_normalized_extent(extents: &mut Vec<VmExtent>, extent: VmExtent) -> Result<(), u32> {
        if let Some(last) = extents.last_mut() {
            if last.end() == extent.base
                && last.allocation_base == extent.allocation_base
                && last.protection == extent.protection
                && last.state == extent.state
            {
                last.size += extent.size;
                return Ok(());
            }
        }
        if extents.len() == N {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        extents.push(extent);
        Ok(())
    }

    fn commit_rewritten_extents(&mut self, extents: Vec<VmExtent>) {
        self.extents.fill(None);
        for (slot, extent) in self.extents.iter_mut().zip(extents.into_iter()) {
            *slot = Some(extent);
        }
    }

    fn clear_protection_overrides(&mut self, base: u64, end: u64) {
        for override_slot in &mut self.protection_overrides {
            if override_slot.is_some_and(|entry| entry.page >= base && entry.page < end) {
                *override_slot = None;
            }
        }
    }

    fn set_page_protection_override(
        &mut self,
        page: u64,
        default_protection: u32,
        new_protection: u32,
    ) -> Result<(), u32> {
        if let Some(index) = self.protection_override_index(page) {
            self.protection_overrides[index] =
                (new_protection != default_protection).then_some(VmProtectionOverride {
                    page,
                    protection: new_protection,
                });
            return Ok(());
        }
        if new_protection == default_protection {
            return Ok(());
        }
        let slot = self
            .protection_overrides
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        *slot = Some(VmProtectionOverride {
            page,
            protection: new_protection,
        });
        Ok(())
    }

    fn find_free_between(
        &self,
        size: u64,
        lower_bound: u64,
        upper_bound: u64,
        top_down: bool,
    ) -> Option<u64> {
        let lower_bound = lower_bound.max(self.lower_bound);
        let upper_bound = upper_bound.min(self.upper_bound);
        if lower_bound >= upper_bound {
            return None;
        }
        if top_down {
            let mut candidate = upper_bound.checked_sub(size)? & !(ALLOCATION_GRANULARITY - 1);
            loop {
                if candidate < lower_bound {
                    return None;
                }
                let end = candidate.checked_add(size)?;
                let conflict = self
                    .extents
                    .iter()
                    .flatten()
                    .filter(|extent| candidate < extent.end() && extent.base < end)
                    .map(|extent| extent.base)
                    .min();
                match conflict {
                    Some(base) => {
                        candidate = base.checked_sub(size)? & !(ALLOCATION_GRANULARITY - 1);
                    }
                    None => return Some(candidate),
                }
            }
        }
        let mut candidate = Self::align_up(lower_bound, ALLOCATION_GRANULARITY)?;
        loop {
            let end = candidate.checked_add(size)?;
            if end > upper_bound {
                return None;
            }
            let mut next = None;
            for extent in self.extents.iter().flatten() {
                if candidate < extent.end() && extent.base < end {
                    next = Some(Self::align_up(extent.end(), ALLOCATION_GRANULARITY)?);
                    break;
                }
            }
            match next {
                Some(address) => candidate = address,
                None => return Some(candidate),
            }
        }
    }

    fn allocation_for_range(&self, base: u64, end: u64) -> Result<u64, u32> {
        let first = self.extent_at(base).ok_or(STATUS_MEMORY_NOT_ALLOCATED)?;
        let allocation_base = first.allocation_base;
        let mut position = base;
        while position < end {
            let extent = self.extent_at(position).ok_or(STATUS_UNABLE_TO_FREE_VM)?;
            if extent.allocation_base != allocation_base {
                return Err(STATUS_UNABLE_TO_FREE_VM);
            }
            position = extent.end().min(end);
        }
        Ok(allocation_base)
    }

    fn allocation_end(&self, allocation_base: u64) -> Option<u64> {
        self.extents
            .iter()
            .flatten()
            .filter(|extent| extent.allocation_base == allocation_base)
            .map(|extent| extent.end())
            .max()
    }

    fn rewrite_range(
        &mut self,
        base: u64,
        end: u64,
        replacement: Option<(VmExtentState, Option<u32>)>,
    ) -> Result<(), u32> {
        let mut next = Vec::new();
        next.try_reserve_exact(N)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for extent in self.extents.iter().flatten().copied() {
            if extent.end() <= base || extent.base >= end {
                Self::push_normalized_extent(&mut next, extent)?;
                continue;
            }
            if extent.base < base {
                Self::push_normalized_extent(
                    &mut next,
                    VmExtent {
                        size: base - extent.base,
                        ..extent
                    },
                )?;
            }
            if let Some((state, protection)) = replacement {
                let middle_base = extent.base.max(base);
                let middle_end = extent.end().min(end);
                Self::push_normalized_extent(
                    &mut next,
                    VmExtent {
                        base: middle_base,
                        size: middle_end - middle_base,
                        protection: protection.unwrap_or(extent.protection),
                        state,
                        ..extent
                    },
                )?;
            }
            if extent.end() > end {
                Self::push_normalized_extent(
                    &mut next,
                    VmExtent {
                        base: end,
                        size: extent.end() - end,
                        ..extent
                    },
                )?;
            }
        }
        self.commit_rewritten_extents(next);
        Ok(())
    }

    /// Apply `MEM_RESERVE`/`MEM_COMMIT` policy and return the page-normalized range to map.
    pub fn allocate(
        &mut self,
        requested_base: Option<u64>,
        requested_size: u64,
        allocation_type: u32,
        protection: u32,
    ) -> Result<VmAllocatePlan, u32> {
        self.allocate_below(
            requested_base,
            requested_size,
            allocation_type,
            protection,
            self.upper_bound,
        )
    }

    /// Allocate beneath an optional `ZeroBits` ceiling. The syscall layer performs the ordered
    /// argument validation first; this method owns range normalization and VAD mutation.
    pub fn allocate_below(
        &mut self,
        requested_base: Option<u64>,
        requested_size: u64,
        allocation_type: u32,
        protection: u32,
        upper_bound: u64,
    ) -> Result<VmAllocatePlan, u32> {
        self.allocate_between(
            requested_base,
            requested_size,
            allocation_type,
            protection,
            self.lower_bound,
            upper_bound,
        )
    }

    /// Allocate beneath `upper_bound` while starting automatic placement at `lower_bound`. The
    /// syscall layer uses this to retry around fixed-address authorities outside the private VAD
    /// map without teaching this crate about those authorities.
    pub fn allocate_between(
        &mut self,
        requested_base: Option<u64>,
        requested_size: u64,
        allocation_type: u32,
        protection: u32,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<VmAllocatePlan, u32> {
        validate_allocate_parameters(0, allocation_type, protection)?;
        let lower_bound = lower_bound.max(self.lower_bound);
        let upper_bound = upper_bound.min(self.upper_bound);
        if requested_base.is_some_and(|address| address < lower_bound || address >= upper_bound) {
            return Err(STATUS_CONFLICTING_ADDRESSES);
        }
        let available = match requested_base {
            Some(address) => upper_bound - address,
            None => upper_bound,
        };
        if requested_size > available || requested_size == 0 {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        if allocation_type == MEM_RESET && requested_base.is_some() {
            let address = requested_base.unwrap();
            let base = address & !(PAGE_SIZE - 1);
            let end = Self::align_up(
                address
                    .checked_add(requested_size)
                    .ok_or(STATUS_INVALID_PARAMETER_4)?,
                PAGE_SIZE,
            )
            .ok_or(STATUS_INVALID_PARAMETER_4)?;
            if !self
                .extents
                .iter()
                .flatten()
                .any(|extent| base < extent.end() && extent.base < end)
            {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            return Ok(VmAllocatePlan {
                base,
                size: end - base,
            });
        }
        if allocation_type & MEM_RESERVE != 0 || requested_base.is_none() {
            let (base, end) = match requested_base {
                Some(address) => {
                    let base = address & !(ALLOCATION_GRANULARITY - 1);
                    let end = Self::align_up(
                        address
                            .checked_add(requested_size)
                            .ok_or(STATUS_INVALID_PARAMETER_4)?,
                        PAGE_SIZE,
                    )
                    .ok_or(STATUS_INVALID_PARAMETER_4)?;
                    (base, end)
                }
                None => {
                    let size = Self::align_up(requested_size, PAGE_SIZE)
                        .ok_or(STATUS_INVALID_PARAMETER_4)?;
                    let base = self
                        .find_free_between(
                            size,
                            lower_bound,
                            upper_bound,
                            allocation_type & MEM_TOP_DOWN != 0,
                        )
                        .ok_or(STATUS_NO_MEMORY)?;
                    (base, base + size)
                }
            };
            if end > upper_bound || end <= base {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            if base < self.lower_bound || self.overlaps(base, end) {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            self.insert(VmExtent {
                base,
                size: end - base,
                allocation_base: base,
                protection,
                state: if allocation_type & MEM_COMMIT != 0 {
                    VmExtentState::Committed
                } else {
                    VmExtentState::Reserved
                },
            })?;
            self.normalize();
            self.clear_protection_overrides(base, end);
            Ok(VmAllocatePlan {
                base,
                size: end - base,
            })
        } else {
            let address = requested_base.unwrap();
            let base = address & !(PAGE_SIZE - 1);
            let end = Self::align_up(
                address
                    .checked_add(requested_size)
                    .ok_or(STATUS_INVALID_PARAMETER_4)?,
                PAGE_SIZE,
            )
            .ok_or(STATUS_INVALID_PARAMETER_4)?;
            if end > upper_bound || end <= base {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            if self.allocation_for_range(base, end).is_err() {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            self.rewrite_range(
                base,
                end,
                Some((VmExtentState::Committed, Some(protection))),
            )?;
            self.clear_protection_overrides(base, end);
            Ok(VmAllocatePlan {
                base,
                size: end - base,
            })
        }
    }

    /// Apply ReactOS private-VAD release/decommit policy and return the normalized pages to unmap.
    pub fn free(
        &mut self,
        requested_base: u64,
        requested_size: u64,
        free_type: u32,
    ) -> Result<VmFreePlan, u32> {
        if free_type != MEM_RELEASE && free_type != MEM_DECOMMIT {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        let base = requested_base & !(PAGE_SIZE - 1);
        let first = self.extent_at(base).ok_or(STATUS_MEMORY_NOT_ALLOCATED)?;
        let allocation_base = first.allocation_base;
        let end = if requested_size == 0 {
            if base != first.base || first.base != allocation_base {
                return Err(STATUS_FREE_VM_NOT_AT_BASE);
            }
            self.allocation_end(allocation_base)
                .ok_or(STATUS_MEMORY_NOT_ALLOCATED)?
        } else {
            Self::align_up(
                requested_base
                    .checked_add(requested_size)
                    .ok_or(STATUS_UNABLE_TO_FREE_VM)?,
                PAGE_SIZE,
            )
            .ok_or(STATUS_UNABLE_TO_FREE_VM)?
        };
        self.allocation_for_range(base, end)?;
        self.rewrite_range(
            base,
            end,
            (free_type == MEM_DECOMMIT).then_some((VmExtentState::Reserved, None)),
        )?;
        self.clear_protection_overrides(base, end);
        if free_type == MEM_RELEASE {
            for extent in self.extents.iter_mut().flatten() {
                if extent.allocation_base == allocation_base && extent.base >= end {
                    extent.allocation_base = end;
                }
            }
            self.normalize();
        }
        Ok(VmFreePlan {
            base,
            size: end - base,
            free_type,
        })
    }

    /// Apply ReactOS private-VAD protection policy and return the normalized pages to reprotect.
    pub fn protect(
        &mut self,
        requested_base: u64,
        requested_size: u64,
        new_protection: u32,
    ) -> Result<VmProtectPlan, u32> {
        validate_protect_parameters(new_protection)?;
        let new_base_protection = new_protection & 0xff;
        if matches!(new_base_protection, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY) {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        if requested_size == 0 {
            return Err(STATUS_INVALID_PARAMETER_3);
        }
        let base = requested_base & !(PAGE_SIZE - 1);
        let end = Self::align_up(
            requested_base
                .checked_add(requested_size)
                .ok_or(STATUS_INVALID_PARAMETER_3)?,
            PAGE_SIZE,
        )
        .ok_or(STATUS_INVALID_PARAMETER_3)?;
        if end <= base {
            return Err(STATUS_INVALID_PARAMETER_3);
        }
        let first = self.extent_at(base).ok_or(STATUS_CONFLICTING_ADDRESSES)?;
        let allocation_base = first.allocation_base;
        let old_protection = self.protection_at(base).unwrap_or(first.protection);
        let mut position = base;
        while position < end {
            let extent = self
                .extent_at(position)
                .ok_or(STATUS_CONFLICTING_ADDRESSES)?;
            if extent.allocation_base != allocation_base {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            if extent.state != VmExtentState::Committed {
                return Err(STATUS_NOT_COMMITTED);
            }
            position = extent.end().min(end);
        }
        let mut next = *self;
        let mut page = base;
        while page < end {
            let default_protection = self.extent_at(page).unwrap().protection;
            next.set_page_protection_override(page, default_protection, new_protection)?;
            page += PAGE_SIZE;
        }
        *self = next;
        Ok(VmProtectPlan {
            base,
            size: end - base,
            old_protection,
            new_protection,
        })
    }
}

/// The kind of access that raised a fault (spec §12.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FaultAccess {
    Read,
    Write,
    Execute,
    Lock,
}

/// Which access rights an MDL lock requires (spec §15.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LockAccess {
    Read,
    Write,
}

/// What a VAD maps (spec §7.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ViewType {
    PrivateAnonymous,
    MappedDataSection,
    SystemMappedSection,
}

/// A page's residency state (spec §7.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageState {
    CommittedNotResident,
    Resident,
}

pub type VadId = u32;
pub type SectionId = u32;

struct VadRegion {
    base: u64,
    size: u64,
    protection: u32,
    view_type: ViewType,
    section: Option<SectionId>,
    section_offset: u64,
}

impl VadRegion {
    fn end(&self) -> u64 {
        self.base + self.size
    }
    fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

struct VirtualPage {
    state: PageState,
    data: Vec<u8>, // PAGE_SIZE bytes once resident
    dirty: bool,
    locked_count: u32,
}

/// A locked page list returned by `MmProbeAndLockPages` (spec §15).
pub struct Mdl {
    base: u64,
    length: u64,
    locked: bool,
}

impl Mdl {
    pub fn is_locked(&self) -> bool {
        self.locked
    }
    pub fn page_count(&self) -> u64 {
        self.length.div_ceil(PAGE_SIZE)
    }
}

/// A process/system/driver-host virtual address space (spec §7.1).
pub struct AddressSpace {
    lower_bound: u64,
    upper_bound: u64,
    vads: Vec<Option<VadRegion>>,
    pages: BTreeMap<u64, VirtualPage>, // keyed by virtual page number
    commit_charge: u64,
    commit_limit: u64,
}

impl AddressSpace {
    /// A synthetic test/driver-host address space spanning `[lower, upper)` with a commit limit.
    pub fn new(lower_bound: u64, upper_bound: u64, commit_limit: u64) -> Self {
        AddressSpace {
            lower_bound,
            upper_bound,
            vads: Vec::new(),
            pages: BTreeMap::new(),
            commit_charge: 0,
            commit_limit,
        }
    }

    pub fn commit_charge(&self) -> u64 {
        self.commit_charge
    }
    pub fn resident_page_count(&self) -> usize {
        self.pages
            .values()
            .filter(|p| p.state == PageState::Resident)
            .count()
    }
    pub fn vad_count(&self) -> usize {
        self.vads.iter().filter(|v| v.is_some()).count()
    }
    /// The section a VAD maps (spec §7.2), or `None` for a private-anonymous VAD.
    pub fn vad_section(&self, vad: VadId) -> Option<SectionId> {
        self.vads.get(vad as usize)?.as_ref()?.section
    }

    fn vad_at(&self, addr: u64) -> Option<&VadRegion> {
        self.vads
            .iter()
            .filter_map(|v| v.as_ref())
            .find(|v| v.contains(addr))
    }
    fn overlaps(&self, base: u64, size: u64) -> bool {
        self.vads
            .iter()
            .filter_map(|v| v.as_ref())
            .any(|v| base < v.end() && v.base < base + size)
    }

    /// First-fit free-region search (spec §9.3), aligned to the allocation granularity.
    fn find_free(&self, size: u64) -> Option<u64> {
        let aligned = size.div_ceil(ALLOCATION_GRANULARITY) * ALLOCATION_GRANULARITY;
        let mut base = self.lower_bound.div_ceil(ALLOCATION_GRANULARITY) * ALLOCATION_GRANULARITY;
        while base + aligned <= self.upper_bound {
            if !self.overlaps(base, aligned) {
                return Some(base);
            }
            base += ALLOCATION_GRANULARITY;
        }
        None
    }

    fn push_vad(&mut self, v: VadRegion) -> VadId {
        let id = self.vads.len() as VadId;
        self.vads.push(Some(v));
        id
    }

    /// Reserve a VA region + create a VAD for a mapped view (spec §9.2, §10.2). Demand mode:
    /// pages start `CommittedNotResident`. `base = None` finds a free region. Charges commit.
    pub fn reserve_view(
        &mut self,
        base: Option<u64>,
        size: u64,
        protection: u32,
        view_type: ViewType,
        section: Option<SectionId>,
        section_offset: u64,
    ) -> Result<(VadId, u64), u32> {
        if !valid_prot(protection) || size == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let base = match base {
            Some(b) => {
                let aligned = b / ALLOCATION_GRANULARITY * ALLOCATION_GRANULARITY;
                if aligned != b {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if b < self.lower_bound || b + size > self.upper_bound || self.overlaps(b, size) {
                    return Err(STATUS_CONFLICTING_ADDRESSES);
                }
                b
            }
            None => self.find_free(size).ok_or(STATUS_NO_MEMORY)?,
        };
        // Commit accounting (spec §17): charge the whole reserved view.
        if self.commit_charge + size > self.commit_limit {
            return Err(STATUS_COMMITMENT_LIMIT);
        }
        self.commit_charge += size;
        let id = self.push_vad(VadRegion {
            base,
            size,
            protection,
            view_type,
            section,
            section_offset,
        });
        Ok((id, base))
    }

    fn page_valid_len(vad: &VadRegion, page_base: u64) -> usize {
        let off_in_vad = page_base - vad.base;
        (vad.size - off_in_vad).min(PAGE_SIZE) as usize
    }

    /// The page-fault resolver for a **section-backed** page (spec §12.2-§12.3): find the VAD,
    /// check protection, and materialise the page from the Cache Manager if not resident. Marks
    /// the page dirty on a write fault (spec §12.4).
    pub fn fault<B: CachedStreamBacking>(
        &mut self,
        addr: u64,
        access: FaultAccess,
        cache: &mut SharedCacheMap<B>,
    ) -> u32 {
        let page_base = addr / PAGE_SIZE * PAGE_SIZE;
        let (prot, vt, sec_off, valid) = match self.vad_at(addr) {
            None => return STATUS_ACCESS_VIOLATION, // no VAD (spec §12.2)
            Some(v) => (
                v.protection,
                v.view_type,
                v.section_offset + (page_base - v.base),
                Self::page_valid_len(v, page_base),
            ),
        };
        if !protection_allows_fault_access(prot, access) {
            return STATUS_ACCESS_VIOLATION;
        }
        let vpn = page_base / PAGE_SIZE;
        let resident = self
            .pages
            .get(&vpn)
            .map(|p| p.state == PageState::Resident)
            .unwrap_or(false);
        if !resident {
            let mut data = vec![0u8; PAGE_SIZE as usize];
            if vt != ViewType::PrivateAnonymous {
                cache.cc_copy_read(sec_off, valid, &mut data); // materialise from cache
            }
            self.pages.insert(
                vpn,
                VirtualPage {
                    state: PageState::Resident,
                    data,
                    dirty: false,
                    locked_count: self.pages.get(&vpn).map(|p| p.locked_count).unwrap_or(0),
                },
            );
        }
        if access == FaultAccess::Write {
            self.pages.get_mut(&vpn).unwrap().dirty = true;
        }
        STATUS_SUCCESS
    }

    /// The fault resolver for an **anonymous** page (spec §12.2): zero-fill on first touch.
    pub fn fault_anonymous(&mut self, addr: u64, access: FaultAccess) -> u32 {
        let page_base = addr / PAGE_SIZE * PAGE_SIZE;
        let prot = match self.vad_at(addr) {
            None => return STATUS_ACCESS_VIOLATION,
            Some(v) => v.protection,
        };
        if !protection_allows_fault_access(prot, access) {
            return STATUS_ACCESS_VIOLATION;
        }
        let vpn = page_base / PAGE_SIZE;
        self.pages.entry(vpn).or_insert_with(|| VirtualPage {
            state: PageState::Resident,
            data: vec![0u8; PAGE_SIZE as usize],
            dirty: false,
            locked_count: 0,
        });
        if access == FaultAccess::Write {
            self.pages.get_mut(&vpn).unwrap().dirty = true;
        }
        STATUS_SUCCESS
    }

    /// Demand read `len` bytes at `addr`, faulting section pages in as needed (spec §12).
    pub fn read<B: CachedStreamBacking>(
        &mut self,
        addr: u64,
        len: usize,
        cache: &mut SharedCacheMap<B>,
    ) -> Result<Vec<u8>, u32> {
        let mut out = Vec::with_capacity(len);
        let mut pos = addr;
        while out.len() < len {
            let st = self.fault(pos, FaultAccess::Read, cache);
            if st != STATUS_SUCCESS {
                return Err(st);
            }
            let vpn = pos / PAGE_SIZE;
            let off = (pos % PAGE_SIZE) as usize;
            let page = self.pages.get(&vpn).unwrap();
            let n = (PAGE_SIZE as usize - off).min(len - out.len());
            out.extend_from_slice(&page.data[off..off + n]);
            pos += n as u64;
        }
        Ok(out)
    }

    /// Demand write `bytes` at `addr`, faulting pages in for write + marking them dirty (spec §12.4).
    pub fn write<B: CachedStreamBacking>(
        &mut self,
        addr: u64,
        bytes: &[u8],
        cache: &mut SharedCacheMap<B>,
    ) -> Result<(), u32> {
        let mut written = 0;
        let mut pos = addr;
        while written < bytes.len() {
            let st = self.fault(pos, FaultAccess::Write, cache);
            if st != STATUS_SUCCESS {
                return Err(st);
            }
            let vpn = pos / PAGE_SIZE;
            let off = (pos % PAGE_SIZE) as usize;
            let page = self.pages.get_mut(&vpn).unwrap();
            let n = (PAGE_SIZE as usize - off).min(bytes.len() - written);
            page.data[off..off + n].copy_from_slice(&bytes[written..written + n]);
            page.dirty = true;
            written += n;
            pos += n as u64;
        }
        Ok(())
    }

    /// `ZwUnmapViewOfSection` for a file-backed VAD (spec §11.1-§11.2): write dirty resident pages
    /// back through the cache (`CcCopyWrite`), release the pages, and free the VAD (releasing
    /// commit). A `CcFlushCache` after this reaches the file.
    pub fn unmap_view<B: CachedStreamBacking>(
        &mut self,
        vad: VadId,
        cache: &mut SharedCacheMap<B>,
    ) -> Result<(), u32> {
        let region = self
            .vads
            .get_mut(vad as usize)
            .and_then(|v| v.take())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let first = region.base / PAGE_SIZE;
        let last = (region.end() - 1) / PAGE_SIZE;
        for vpn in first..=last {
            if let Some(page) = self.pages.remove(&vpn) {
                if page.dirty && writable(region.protection) {
                    let page_base = vpn * PAGE_SIZE;
                    let valid = Self::page_valid_len(&region, page_base);
                    let sec_off = region.section_offset + (page_base - region.base);
                    cache.cc_copy_write(sec_off, &page.data[..valid], false);
                }
            }
        }
        self.commit_charge = self.commit_charge.saturating_sub(region.size);
        Ok(())
    }

    /// Free an anonymous VAD (no writeback; releases commit).
    pub fn unmap_anonymous(&mut self, vad: VadId) -> Result<(), u32> {
        let region = self
            .vads
            .get_mut(vad as usize)
            .and_then(|v| v.take())
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let first = region.base / PAGE_SIZE;
        let last = (region.end() - 1) / PAGE_SIZE;
        for vpn in first..=last {
            self.pages.remove(&vpn);
        }
        self.commit_charge = self.commit_charge.saturating_sub(region.size);
        Ok(())
    }

    /// `MmProbeAndLockPages` (spec §15.2): fault in + lock the pages spanning `[base, base+len)`,
    /// verifying the access right. Returns a locked [`Mdl`].
    pub fn mm_probe_and_lock_pages<B: CachedStreamBacking>(
        &mut self,
        base: u64,
        length: u64,
        access: LockAccess,
        cache: &mut SharedCacheMap<B>,
    ) -> Result<Mdl, u32> {
        let fa = match access {
            LockAccess::Read => FaultAccess::Read,
            LockAccess::Write => FaultAccess::Write,
        };
        let mut pos = base / PAGE_SIZE * PAGE_SIZE;
        let end = base + length;
        while pos < end {
            let st = self.fault(pos, fa, cache);
            if st != STATUS_SUCCESS {
                return Err(st);
            }
            self.pages.get_mut(&(pos / PAGE_SIZE)).unwrap().locked_count += 1;
            pos += PAGE_SIZE;
        }
        Ok(Mdl {
            base,
            length,
            locked: true,
        })
    }

    /// `MmUnlockPages` (spec §15.3): decrement the lock count on the MDL's pages.
    pub fn mm_unlock_pages(&mut self, mdl: &mut Mdl) {
        let mut pos = mdl.base / PAGE_SIZE * PAGE_SIZE;
        let end = mdl.base + mdl.length;
        while pos < end {
            if let Some(p) = self.pages.get_mut(&(pos / PAGE_SIZE)) {
                p.locked_count = p.locked_count.saturating_sub(1);
            }
            pos += PAGE_SIZE;
        }
        mdl.locked = false;
    }

    /// The lock count of the page containing `addr` (for MDL tests).
    pub fn page_locked_count(&self, addr: u64) -> u32 {
        self.pages
            .get(&(addr / PAGE_SIZE))
            .map(|p| p.locked_count)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests;
