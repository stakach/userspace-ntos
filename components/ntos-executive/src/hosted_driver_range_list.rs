//! Native `RTL_RANGE_LIST` ABI for hosted PCI/resource-arbiter drivers.
//!
//! The guest owns its 32-byte list header; each intrusive node is allocated in
//! the same component pool. The pure range policy lives in `nt-compat-exports`.

use super::*;
use alloc::vec::Vec;
use nt_compat_exports::range_list::{Range, RangeList, RangeListError, ADD_IF_CONFLICT, ADD_SHARED};

const STATUS_RANGE_LIST_CONFLICT: i32 = 0xC000_0282u32 as i32;
const STATUS_RANGE_NOT_FOUND: i32 = 0xC000_028Cu32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
const MAX_RANGES: usize = 65_536;
const RANGE_SHARED: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct Link { next: u64, previous: u64 }

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeList { head: Link, flags: u32, count: u32, stamp: u32 }

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeRange {
    start: u64, end: u64, user_data: u64, owner: u64,
    attributes: u8, flags: u8, padding: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeNode { link: Link, range: NativeRange }

const _: [(); 32] = [(); core::mem::size_of::<NativeList>()];
const _: [(); 40] = [(); core::mem::size_of::<NativeRange>()];
const _: [(); 56] = [(); core::mem::size_of::<NativeNode>()];

fn status(error: RangeListError) -> i32 {
    match error {
        RangeListError::InvalidParameter => STATUS_INVALID_PARAMETER,
        RangeListError::Conflict => STATUS_RANGE_LIST_CONFLICT,
        RangeListError::NotFound => STATUS_RANGE_NOT_FOUND,
        RangeListError::InsufficientResources => STATUS_INSUFFICIENT_RESOURCES,
    }
}

fn valid_header(address: u64) -> bool { address != 0 && address & 7 == 0 }

fn invalid_void_call(address: u64, operation: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [0x5241_4e47, address, operation, 0]); }
}

unsafe fn list(address: u64) -> Option<&'static mut NativeList> {
    if !valid_header(address) { return None; }
    Some(&mut *(address as *mut NativeList))
}

fn to_pure(native: NativeRange) -> Range {
    Range { start: native.start, end: native.end, owner: native.owner,
        user_data: native.user_data, attributes: native.attributes,
        shared: native.flags & RANGE_SHARED != 0 }
}

fn to_native(range: Range) -> NativeRange {
    NativeRange { start: range.start, end: range.end, user_data: range.user_data,
        owner: range.owner, attributes: range.attributes,
        flags: if range.shared { RANGE_SHARED } else { 0 }, padding: [0; 6] }
}

/// Snapshot the whole link chain before any effect. A damaged backlink, forged
/// pool address, count mismatch or cycle is rejected instead of reused.
unsafe fn snapshot(address: u64) -> Option<(RangeList, Vec<u64>)> {
    let header = list(address)?;
    let count = usize::try_from(header.count).ok()?;
    if count > MAX_RANGES { return None; }
    if header.head.next == address && header.head.previous == address && count == 0 {
        return Some((RangeList::new(), Vec::new()));
    }
    if count == 0 { return None; }
    let mut ranges = RangeList::new();
    let mut nodes = Vec::new();
    nodes.try_reserve(count).ok()?;
    let mut current = header.head.next;
    let mut previous = address;
    for _ in 0..count {
        if current == address || current & 15 != 0
            || component_pool_allocation_capacity(current)? < core::mem::size_of::<NativeNode>() as u64
        { return None; }
        let node = &*(current as *const NativeNode);
        if node.link.previous != previous || node.range.start > node.range.end { return None; }
        let range = to_pure(node.range);
        if ranges.ranges().last().is_some_and(|old| old.start > range.start) { return None; }
        ranges.add(range, ADD_IF_CONFLICT | if range.shared { ADD_SHARED } else { 0 }).ok()?;
        nodes.push(current);
        previous = current;
        current = node.link.next;
    }
    if current != address || header.head.previous != previous { return None; }
    Some((ranges, nodes))
}

unsafe fn allocate_node(range: Range) -> Option<u64> {
    let address = pool_alloc(core::mem::size_of::<NativeNode>() as u64);
    if address == 0 { return None; }
    core::ptr::write(address as *mut NativeNode, NativeNode {
        link: Link { next: 0, previous: 0 }, range: to_native(range),
    });
    Some(address)
}

unsafe fn insert_before(header: u64, next: u64, node: u64) {
    let previous = if next == header { (*(header as *const NativeList)).head.previous }
        else { (*(next as *const NativeNode)).link.previous };
    (*(node as *mut NativeNode)).link = Link { next, previous };
    if previous == header { (*(header as *mut NativeList)).head.next = node; }
    else { (*(previous as *mut NativeNode)).link.next = node; }
    if next == header { (*(header as *mut NativeList)).head.previous = node; }
    else { (*(next as *mut NativeNode)).link.previous = node; }
    let list = &mut *(header as *mut NativeList);
    list.count += 1;
    list.stamp = list.stamp.wrapping_add(1);
}

unsafe fn unlink(header: u64, node: u64) {
    let link = (*(node as *const NativeNode)).link;
    if link.previous == header { (*(header as *mut NativeList)).head.next = link.next; }
    else { (*(link.previous as *mut NativeNode)).link.next = link.next; }
    if link.next == header { (*(header as *mut NativeList)).head.previous = link.previous; }
    else { (*(link.next as *mut NativeNode)).link.previous = link.previous; }
    let list = &mut *(header as *mut NativeList);
    list.count -= 1;
    list.stamp = list.stamp.wrapping_add(1);
    pool_free(node);
}

unsafe fn append_ranges(header: u64, ranges: &[Range]) -> i32 {
    // Keep the list sorted even when copying/inverting into a nonempty header.
    // The ReactOS implementation appends copies at the tail; its nonempty case
    // can leave an unsorted chain that later RtlFindRange searches incorrectly.
    // The NT5 reference requires an empty destination. LiberNT accepts the
    // ReactOS call shape here while retaining the range-list search invariant.
    let count = (*(header as *const NativeList)).count as usize;
    if ranges.len() > MAX_RANGES.saturating_sub(count) { return STATUS_INSUFFICIENT_RESOURCES; }
    // Reserve every guest node first. Partial allocation has no visible list effect.
    let mut nodes = Vec::new();
    if nodes.try_reserve(ranges.len()).is_err() { return STATUS_INSUFFICIENT_RESOURCES; }
    for &range in ranges {
        let Some(node) = allocate_node(range) else {
            for node in nodes { pool_free(node); }
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        nodes.push(node);
    }
    for node in nodes {
        let start = (*(node as *const NativeNode)).range.start;
        let mut next = (*(header as *const NativeList)).head.next;
        while next != header && (*(next as *const NativeNode)).range.start <= start {
            next = (*(next as *const NativeNode)).link.next;
        }
        insert_before(header, next, node);
    }
    STATUS_SUCCESS
}

/// `VOID RtlInitializeRangeList(PRTL_RANGE_LIST)`.
extern "win64" fn initialize(address: u64) {
    let Some(list) = (unsafe { list(address) }) else { invalid_void_call(address, 1); };
    *list = NativeList { head: Link { next: address, previous: address },
        flags: 0, count: 0, stamp: 0 };
}

/// `VOID RtlFreeRangeList(PRTL_RANGE_LIST)`.
extern "win64" fn free(address: u64) {
    let Some((_, nodes)) = (unsafe { snapshot(address) }) else { invalid_void_call(address, 2); };
    let stamp = unsafe { (*(address as *const NativeList)).stamp };
    for node in nodes { unsafe { unlink(address, node); } }
    unsafe {
        (*(address as *mut NativeList)).flags = 0;
        (*(address as *mut NativeList)).stamp = stamp;
    }
}

/// `NTSTATUS RtlAddRange(PRTL_RANGE_LIST, ULONGLONG, ULONGLONG, UCHAR, ULONG, PVOID, PVOID)`.
extern "win64" fn add(address: u64, start: u64, end: u64, attributes: u8, flags: u32,
                       user_data: u64, owner: u64) -> i32 {
    let Some((mut policy, nodes)) = (unsafe { snapshot(address) }) else { return STATUS_INVALID_PARAMETER; };
    let range = Range { start, end, attributes, owner, user_data, shared: false };
    let position = policy.ranges().partition_point(|candidate| candidate.start <= start);
    if let Err(error) = policy.add(range, flags) { return status(error); }
    let next = nodes.get(position).copied().unwrap_or(address);
    let Some(node) = (unsafe { allocate_node(Range { shared: flags & 2 != 0, ..range }) })
        else { return STATUS_INSUFFICIENT_RESOURCES; };
    unsafe { insert_before(address, next, node); }
    STATUS_SUCCESS
}

/// `NTSTATUS RtlCopyRangeList(PRTL_RANGE_LIST, PRTL_RANGE_LIST)`.
extern "win64" fn copy(destination: u64, source: u64) -> i32 {
    if destination == source { return STATUS_INVALID_PARAMETER; }
    let Some((source_ranges, _)) = (unsafe { snapshot(source) }) else { return STATUS_INVALID_PARAMETER; };
    let Some((mut dest_ranges, _)) = (unsafe { snapshot(destination) }) else { return STATUS_INVALID_PARAMETER; };
    if let Err(error) = dest_ranges.append_from(&source_ranges) { return status(error); }
    let stamp = unsafe { (*(destination as *const NativeList)).stamp };
    let result = unsafe { append_ranges(destination, source_ranges.ranges()) };
    if result == STATUS_SUCCESS {
        unsafe {
            (*(destination as *mut NativeList)).flags = (*(source as *const NativeList)).flags;
            // ReactOS increments the destination stamp once for a copy.
            (*(destination as *mut NativeList)).stamp = stamp.wrapping_add(1);
        }
    }
    result
}

/// `NTSTATUS RtlDeleteOwnersRanges(PRTL_RANGE_LIST, PVOID)`.
extern "win64" fn delete_owners(address: u64, owner: u64) -> i32 {
    let Some((policy, nodes)) = (unsafe { snapshot(address) }) else { return STATUS_INVALID_PARAMETER; };
    for (&node, range) in nodes.iter().zip(policy.ranges()) {
        if range.owner == owner { unsafe { unlink(address, node); } }
    }
    STATUS_SUCCESS
}

/// `NTSTATUS RtlFindRange(..., PRTL_CONFLICT_RANGE_CALLBACK, PULONGLONG)`.
extern "win64" fn find(address: u64, minimum: u64, maximum: u64, length: u64,
                       alignment: u64, flags: u32, attributes: u8, context: u64,
                       callback: u64, out: u64) -> i32 {
    if out == 0 { return STATUS_INVALID_PARAMETER; }
    let Some((policy, _)) = (unsafe { snapshot(address) }) else { return STATUS_INVALID_PARAMETER; };
    let found = policy.find(minimum, maximum, length, alignment, flags, attributes, |range| {
        if callback == 0 { return false; }
        let invoke: extern "win64" fn(u64, *mut NativeRange) -> u8 = unsafe { core::mem::transmute(callback as usize) };
        let mut native = to_native(*range);
        invoke(context, &mut native) != 0
    });
    match found {
        Ok(start) => { unsafe { write_unaligned(out as *mut u64, start); } STATUS_SUCCESS },
        Err(error) => status(error),
    }
}

/// `NTSTATUS RtlInvertRangeList(PRTL_RANGE_LIST, PRTL_RANGE_LIST)`.
extern "win64" fn invert(destination: u64, source: u64) -> i32 {
    if destination == source { return STATUS_INVALID_PARAMETER; }
    let Some((source_ranges, _)) = (unsafe { snapshot(source) }) else { return STATUS_INVALID_PARAMETER; };
    let Some((mut dest_ranges, _)) = (unsafe { snapshot(destination) }) else { return STATUS_INVALID_PARAMETER; };
    let gaps = match source_ranges.invert() { Ok(gaps) => gaps, Err(error) => return status(error) };
    if let Err(error) = dest_ranges.append_from(&gaps) { return status(error); }
    unsafe { append_ranges(destination, gaps.ranges()) }
}

pub(crate) fn bind_range_list_exports(reg: &mut nt_compat_exports::DriverExportRegistry) {
    reg.bind("RtlAddRange", add as *const () as usize as u64);
    reg.bind("RtlCopyRangeList", copy as *const () as usize as u64);
    reg.bind("RtlDeleteOwnersRanges", delete_owners as *const () as usize as u64);
    reg.bind("RtlFindRange", find as *const () as usize as u64);
    reg.bind("RtlFreeRangeList", free as *const () as usize as u64);
    reg.bind("RtlInitializeRangeList", initialize as *const () as usize as u64);
    reg.bind("RtlInvertRangeList", invert as *const () as usize as u64);
}
