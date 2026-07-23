//! Layout and checked allocation policy for `RTL_DEBUG_INFORMATION`.

use core::ffi::c_void;

use crate::heap::{
    RtlHeapWalkEntry, RTL_HEAP_BUSY, RTL_HEAP_SEGMENT, RTL_HEAP_SETTABLE_FLAGS,
    RTL_HEAP_SETTABLE_VALUE,
};

pub const DEBUG_INFORMATION_SIZE: usize = 0xd0;
pub const DEFAULT_VIEW_SIZE: usize = 0x400000;
pub const PAGE_SIZE: usize = 0x1000;
pub const QUERY_MODULES: u32 = 0x01;
pub const QUERY_HEAPS: u32 = 0x04;
pub const QUERY_HEAP_TAGS: u32 = 0x08;
pub const QUERY_HEAP_BLOCKS: u32 = 0x10;
pub const SUPPORTED_QUERY_MASK: u32 = QUERY_MODULES | QUERY_HEAPS | QUERY_HEAP_BLOCKS;

/// Fixed header preceding the variable `RTL_HEAP_INFORMATION` array.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlProcessHeaps {
    pub number_of_heaps: u32,
    pub _padding: u32,
    pub heaps: [RtlHeapInformation; 0],
}

/// Block-specific arm of `RTL_HEAP_ENTRY`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlHeapEntryBlock {
    pub settable: usize,
    pub tag: u32,
    pub _padding: u32,
}

/// Segment-specific arm of `RTL_HEAP_ENTRY`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlHeapEntrySegment {
    pub committed_size: usize,
    pub first_block: *mut c_void,
}

/// Native union carried by `RTL_HEAP_ENTRY`.
#[repr(C)]
#[derive(Copy, Clone)]
pub union RtlHeapEntryDetails {
    pub block: RtlHeapEntryBlock,
    pub segment: RtlHeapEntrySegment,
}

/// ABI-compatible x64 heap record returned in `RTL_PROCESS_HEAPS`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlHeapEntry {
    pub size: usize,
    pub flags: u16,
    pub allocator_back_trace_index: u16,
    pub _padding: u32,
    pub details: RtlHeapEntryDetails,
}

/// ABI-compatible x64 summary for one process heap.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlHeapInformation {
    pub base_address: *mut c_void,
    pub flags: u32,
    pub entry_overhead: u16,
    pub creator_back_trace_index: u16,
    pub bytes_allocated: usize,
    pub bytes_committed: usize,
    pub number_of_tags: u32,
    pub number_of_entries: u32,
    pub number_of_pseudo_tags: u32,
    pub pseudo_tag_granularity: u32,
    pub reserved: [u32; 5],
    pub _padding: u32,
    pub tags: *mut c_void,
    pub entries: *mut RtlHeapEntry,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HeapSnapshotPlan {
    pub heap_information_offset: usize,
    pub entries_offset: usize,
    pub total_size: usize,
}

#[repr(C)]
pub struct DebugInformation {
    pub section_handle_client: *mut c_void,
    pub view_base_client: *mut c_void,
    pub view_base_target: *mut c_void,
    pub view_base_delta: u32,
    pub _padding0: u32,
    pub event_pair_client: *mut c_void,
    pub event_pair_target: *mut c_void,
    pub target_process_id: *mut c_void,
    pub target_thread_handle: *mut c_void,
    pub flags: u32,
    pub _padding1: u32,
    pub offset_free: usize,
    pub commit_size: usize,
    pub view_size: usize,
    pub modules: *mut c_void,
    pub back_traces: *mut c_void,
    pub heaps: *mut c_void,
    pub locks: *mut c_void,
    pub specific_heap: *mut c_void,
    pub target_process_handle: *mut c_void,
    pub verifier_options: *mut c_void,
    pub process_heap: *mut c_void,
    pub critical_section_handle: *mut c_void,
    pub critical_section_owner_thread: *mut c_void,
    pub reserved: [*mut c_void; 4],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CommitPlan {
    pub result_offset: usize,
    pub commit_offset: usize,
    pub commit_size: usize,
    pub new_commit_size: usize,
    pub new_offset_free: usize,
}

/// Preflight one contiguous heap-debug payload before committing or publishing pointers.
pub fn plan_heap_snapshot(
    number_of_heaps: usize,
    number_of_entries: usize,
) -> Option<HeapSnapshotPlan> {
    let heap_information_offset = core::mem::size_of::<RtlProcessHeaps>();
    let entries_offset = heap_information_offset
        .checked_add(number_of_heaps.checked_mul(core::mem::size_of::<RtlHeapInformation>())?)?;
    let total_size = entries_offset
        .checked_add(number_of_entries.checked_mul(core::mem::size_of::<RtlHeapEntry>())?)?;
    Some(HeapSnapshotPlan {
        heap_information_offset,
        entries_offset,
        total_size,
    })
}

/// Convert a validated `RtlWalkHeap` row into the compact debug-buffer representation.
pub fn heap_entry_from_walk(entry: &RtlHeapWalkEntry) -> Option<RtlHeapEntry> {
    if entry.flags == RTL_HEAP_SEGMENT {
        // SAFETY: the segment flag selects the initialized segment union arm.
        let segment = unsafe { entry.details.segment };
        return Some(RtlHeapEntry {
            size: segment
                .committed_size
                .checked_add(segment.uncommitted_size)?,
            flags: RTL_HEAP_SEGMENT,
            allocator_back_trace_index: 0,
            _padding: 0,
            details: RtlHeapEntryDetails {
                segment: RtlHeapEntrySegment {
                    committed_size: segment.committed_size,
                    first_block: segment.first_entry.cast(),
                },
            },
        });
    }

    if entry.flags & !(RTL_HEAP_BUSY | RTL_HEAP_SETTABLE_VALUE | RTL_HEAP_SETTABLE_FLAGS) != 0 {
        return None;
    }
    // SAFETY: a non-segment walk row selects the initialized block union arm.
    let block = unsafe { entry.details.block };
    Some(RtlHeapEntry {
        size: entry
            .data_size
            .checked_add(usize::from(entry.overhead_bytes))?,
        flags: entry.flags,
        allocator_back_trace_index: block.allocator_back_trace_index,
        _padding: 0,
        details: RtlHeapEntryDetails {
            block: RtlHeapEntryBlock {
                settable: block.settable,
                tag: u32::from(block.tag_index),
                _padding: 0,
            },
        },
    })
}

fn align_page(value: usize) -> Option<usize> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|size| size & !(PAGE_SIZE - 1))
}

pub fn reservation_size(requested: u32) -> Option<usize> {
    align_page(if requested == 0 {
        DEFAULT_VIEW_SIZE
    } else {
        requested as usize
    })
}

pub fn initial_information(base: *mut c_void, view_size: usize) -> DebugInformation {
    DebugInformation {
        section_handle_client: core::ptr::null_mut(),
        view_base_client: base,
        view_base_target: core::ptr::null_mut(),
        view_base_delta: 0,
        _padding0: 0,
        event_pair_client: core::ptr::null_mut(),
        event_pair_target: core::ptr::null_mut(),
        target_process_id: core::ptr::null_mut(),
        target_thread_handle: core::ptr::null_mut(),
        flags: 0,
        _padding1: 0,
        offset_free: DEBUG_INFORMATION_SIZE,
        commit_size: PAGE_SIZE,
        view_size,
        modules: core::ptr::null_mut(),
        back_traces: core::ptr::null_mut(),
        heaps: core::ptr::null_mut(),
        locks: core::ptr::null_mut(),
        specific_heap: core::ptr::null_mut(),
        target_process_handle: core::ptr::null_mut(),
        verifier_options: core::ptr::null_mut(),
        process_heap: core::ptr::null_mut(),
        critical_section_handle: core::ptr::null_mut(),
        critical_section_owner_thread: core::ptr::null_mut(),
        reserved: [core::ptr::null_mut(); 4],
    }
}

pub fn plan_commit(
    offset_free: usize,
    commit_size: usize,
    view_size: usize,
    size: usize,
) -> Option<CommitPlan> {
    let end = offset_free.checked_add(size)?;
    if end > view_size || offset_free > commit_size || commit_size > view_size {
        return None;
    }
    let new_commit_size = if end > commit_size {
        align_page(end)?.min(view_size)
    } else {
        commit_size
    };
    Some(CommitPlan {
        result_offset: offset_free,
        commit_offset: commit_size,
        commit_size: new_commit_size - commit_size,
        new_commit_size,
        new_offset_free: end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x64_debug_information_layout_matches_reactos() {
        assert_eq!(
            core::mem::size_of::<DebugInformation>(),
            DEBUG_INFORMATION_SIZE
        );
        assert_eq!(
            core::mem::offset_of!(DebugInformation, view_base_client),
            0x08
        );
        assert_eq!(core::mem::offset_of!(DebugInformation, flags), 0x40);
        assert_eq!(core::mem::offset_of!(DebugInformation, offset_free), 0x48);
        assert_eq!(core::mem::offset_of!(DebugInformation, modules), 0x60);
        assert_eq!(core::mem::offset_of!(DebugInformation, reserved), 0xb0);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn x64_heap_debug_layouts_match_nt5() {
        assert_eq!(core::mem::size_of::<RtlProcessHeaps>(), 0x08);
        assert_eq!(core::mem::offset_of!(RtlProcessHeaps, number_of_heaps), 0);
        assert_eq!(core::mem::offset_of!(RtlProcessHeaps, heaps), 0x08);
        assert_eq!(core::mem::size_of::<RtlHeapInformation>(), 0x58);
        assert_eq!(
            core::mem::offset_of!(RtlHeapInformation, bytes_allocated),
            0x10
        );
        assert_eq!(
            core::mem::offset_of!(RtlHeapInformation, number_of_entries),
            0x24
        );
        assert_eq!(core::mem::offset_of!(RtlHeapInformation, tags), 0x48);
        assert_eq!(core::mem::offset_of!(RtlHeapInformation, entries), 0x50);
        assert_eq!(core::mem::size_of::<RtlHeapEntry>(), 0x20);
        assert_eq!(core::mem::offset_of!(RtlHeapEntry, flags), 0x08);
        assert_eq!(core::mem::offset_of!(RtlHeapEntry, details), 0x10);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn heap_snapshot_plan_checks_all_record_arithmetic() {
        assert_eq!(
            plan_heap_snapshot(2, 5),
            Some(HeapSnapshotPlan {
                heap_information_offset: 0x08,
                entries_offset: 0xb8,
                total_size: 0x158,
            })
        );
        assert_eq!(plan_heap_snapshot(usize::MAX, 0), None);
        assert_eq!(plan_heap_snapshot(0, usize::MAX), None);
    }

    #[test]
    fn heap_walk_segment_converts_to_debug_segment() {
        let walk = RtlHeapWalkEntry {
            data_address: 0x1000usize as *mut u8,
            data_size: 0,
            overhead_bytes: 0,
            segment_index: 0,
            flags: RTL_HEAP_SEGMENT,
            details: crate::heap::RtlHeapWalkDetails {
                segment: crate::heap::RtlHeapWalkSegment {
                    committed_size: 0x3000,
                    uncommitted_size: 0x1000,
                    first_entry: 0x1040usize as *mut u8,
                    last_entry: 0x5000usize as *mut u8,
                },
            },
        };

        let converted = heap_entry_from_walk(&walk).unwrap();
        assert_eq!(converted.size, 0x4000);
        assert_eq!(converted.flags, RTL_HEAP_SEGMENT);
        assert_eq!(converted.allocator_back_trace_index, 0);
        // SAFETY: the segment flag selects the segment union arm.
        let details = unsafe { converted.details.segment };
        assert_eq!(details.committed_size, 0x3000);
        assert_eq!(details.first_block, 0x1040usize as *mut c_void);
    }

    #[test]
    fn heap_walk_busy_and_free_rows_convert_to_debug_blocks() {
        let mut walk = RtlHeapWalkEntry {
            data_address: 0x2040usize as *mut u8,
            data_size: 17,
            overhead_bytes: 47,
            segment_index: 0,
            flags: RTL_HEAP_BUSY | RTL_HEAP_SETTABLE_VALUE | 0x00a0,
            details: crate::heap::RtlHeapWalkDetails {
                block: crate::heap::RtlHeapWalkBlock {
                    settable: 0x1234,
                    tag_index: 7,
                    allocator_back_trace_index: 9,
                    reserved: [0; 2],
                },
            },
        };

        let busy = heap_entry_from_walk(&walk).unwrap();
        assert_eq!(busy.size, 64);
        assert_eq!(busy.flags, walk.flags);
        assert_eq!(busy.allocator_back_trace_index, 9);
        // SAFETY: a non-segment row selects the block union arm.
        let details = unsafe { busy.details.block };
        assert_eq!(details.settable, 0x1234);
        assert_eq!(details.tag, 7);

        walk.data_size = 96;
        walk.overhead_bytes = 32;
        walk.flags = 0;
        walk.details = crate::heap::RtlHeapWalkDetails {
            block: crate::heap::RtlHeapWalkBlock {
                settable: 0,
                tag_index: 0,
                allocator_back_trace_index: 0,
                reserved: [0; 2],
            },
        };
        let free = heap_entry_from_walk(&walk).unwrap();
        assert_eq!(free.size, 128);
        assert_eq!(free.flags, 0);
        assert_eq!(unsafe { free.details.block }.settable, 0);

        walk.flags = RTL_HEAP_SEGMENT | RTL_HEAP_BUSY;
        assert!(heap_entry_from_walk(&walk).is_none());
    }

    #[test]
    fn reservation_sizes_match_native_rounding() {
        assert_eq!(reservation_size(0), Some(DEFAULT_VIEW_SIZE));
        assert_eq!(reservation_size(1), Some(PAGE_SIZE));
        assert_eq!(reservation_size(0x1000), Some(PAGE_SIZE));
        assert_eq!(reservation_size(0x1001), Some(0x2000));
    }

    #[test]
    fn initial_header_owns_the_first_committed_page() {
        let base = 0x1234_0000usize as *mut c_void;
        let info = initial_information(base, DEFAULT_VIEW_SIZE);
        assert_eq!(info.view_base_client, base);
        assert_eq!(info.offset_free, DEBUG_INFORMATION_SIZE);
        assert_eq!(info.commit_size, PAGE_SIZE);
        assert_eq!(info.view_size, DEFAULT_VIEW_SIZE);
        assert_eq!(info.flags, 0);
        assert!(info.modules.is_null());
    }

    #[test]
    fn commit_plan_grows_by_pages_but_advances_by_requested_bytes() {
        let plan = plan_commit(0xff0, 0x1000, 0x4000, 0x30).unwrap();
        assert_eq!(
            plan,
            CommitPlan {
                result_offset: 0xff0,
                commit_offset: 0x1000,
                commit_size: 0x1000,
                new_commit_size: 0x2000,
                new_offset_free: 0x1020,
            }
        );
        assert_eq!(
            plan_commit(0xd0, 0x1000, 0x1000, 0x20).unwrap().commit_size,
            0
        );
    }

    #[test]
    fn commit_plan_rejects_view_and_integer_overflow() {
        assert_eq!(plan_commit(0xff0, 0x1000, 0x1000, 0x20), None);
        assert_eq!(plan_commit(usize::MAX, usize::MAX, usize::MAX, 1), None);
        assert_eq!(plan_commit(0x2000, 0x1000, 0x4000, 1), None);
    }
}
