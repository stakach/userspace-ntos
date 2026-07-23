//! Layout and checked allocation policy for `RTL_DEBUG_INFORMATION`.

use core::ffi::c_void;

use crate::heap::{
    RtlHeapWalkEntry, RTL_HEAP_BUSY, RTL_HEAP_SEGMENT, RTL_HEAP_SETTABLE_FLAGS,
    RTL_HEAP_SETTABLE_VALUE,
};
use crate::NtStatus;

pub const DEBUG_INFORMATION_SIZE: usize = 0xd0;
pub const DEFAULT_VIEW_SIZE: usize = 0x400000;
pub const PAGE_SIZE: usize = 0x1000;
pub const QUERY_MODULES: u32 = 0x01;
pub const QUERY_HEAPS: u32 = 0x04;
pub const QUERY_HEAP_TAGS: u32 = 0x08;
pub const QUERY_HEAP_BLOCKS: u32 = 0x10;
pub const SUPPORTED_QUERY_MASK: u32 = QUERY_MODULES | QUERY_HEAPS | QUERY_HEAP_BLOCKS;
pub const RTL_PROCESS_MODULES_HEADER_SIZE: usize = 0x08;
pub const RTL_PROCESS_MODULE_INFORMATION_SIZE: usize = 0x128;
pub const REMOTE_MODULE_LIMIT: usize = 4096;

const HIGHEST_USER_ADDRESS: u64 = 0x0000_07ff_fffe_ffff;
const PEB_LDR_OFFSET: u64 = 0x18;
const LDR_IN_LOAD_ORDER_LIST_OFFSET: u64 = 0x10;
const LDR_ENTRY_SIZE: usize = 0x98;
const LDR_DLL_BASE_OFFSET: usize = 0x30;
const LDR_SIZE_OF_IMAGE_OFFSET: usize = 0x40;
const LDR_FULL_DLL_NAME_OFFSET: usize = 0x48;
const LDR_FLAGS_OFFSET: usize = 0x68;
const LDR_LOAD_COUNT_OFFSET: usize = 0x6c;

/// Structural failures from walking a remote process's x64 PEB loader list.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RemoteModuleLayoutError {
    InvalidAddress,
    InvalidList,
    InvalidModule,
    InvalidUnicodeString,
    ModuleLimitExceeded,
    RequiredSizeOverflow,
    SnapshotChanged,
}

/// A remote-memory read status is kept separate from malformed data and caller capacity.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RemoteModuleSnapshotError {
    Read(NtStatus),
    Malformed(RemoteModuleLayoutError),
    BufferTooSmall { required: usize },
}

/// Successful size or encoding result for one remote `RTL_PROCESS_MODULES` snapshot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RemoteModuleSnapshot {
    pub module_count: u32,
    pub required_size: usize,
}

fn checked_remote_range(address: u64, length: usize) -> bool {
    address != 0
        && length != 0
        && address
            .checked_add(length as u64 - 1)
            .is_some_and(|last| last <= HIGHEST_USER_ADDRESS)
}

fn checked_remote_pointer(address: u64, length: usize, alignment: u64) -> bool {
    address & (alignment - 1) == 0 && checked_remote_range(address, length)
}

fn remote_read<R>(
    reader: &mut R,
    address: u64,
    output: &mut [u8],
) -> Result<(), RemoteModuleSnapshotError>
where
    R: FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
{
    if !checked_remote_range(address, output.len()) {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::InvalidAddress,
        ));
    }
    reader(address, output).map_err(RemoteModuleSnapshotError::Read)
}

fn read_remote_u64<R>(reader: &mut R, address: u64) -> Result<u64, RemoteModuleSnapshotError>
where
    R: FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
{
    let mut bytes = [0u8; 8];
    remote_read(reader, address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_list_entry<R>(reader: &mut R, address: u64) -> Result<(u64, u64), RemoteModuleSnapshotError>
where
    R: FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
{
    if !checked_remote_pointer(address, 16, 8) {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::InvalidAddress,
        ));
    }
    let mut bytes = [0u8; 16];
    remote_read(reader, address, &mut bytes)?;
    Ok((
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
    ))
}

fn entry_u16(entry: &[u8; LDR_ENTRY_SIZE], offset: usize) -> u16 {
    u16::from_le_bytes(entry[offset..offset + 2].try_into().unwrap())
}

fn entry_u32(entry: &[u8; LDR_ENTRY_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes(entry[offset..offset + 4].try_into().unwrap())
}

fn entry_u64(entry: &[u8; LDR_ENTRY_SIZE], offset: usize) -> u64 {
    u64::from_le_bytes(entry[offset..offset + 8].try_into().unwrap())
}

fn validate_and_copy_remote_name<R>(
    reader: &mut R,
    descriptor: &[u8],
    path: Option<&mut [u8]>,
) -> Result<u16, RemoteModuleSnapshotError>
where
    R: FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
{
    let length = u16::from_le_bytes(descriptor[0..2].try_into().unwrap()) as usize;
    let maximum_length = u16::from_le_bytes(descriptor[2..4].try_into().unwrap()) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if length & 1 != 0
        || maximum_length & 1 != 0
        || length > maximum_length
        || (maximum_length != 0 && !checked_remote_pointer(buffer, maximum_length, 2))
        || (maximum_length == 0 && buffer != 0 && !checked_remote_pointer(buffer, 1, 2))
    {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::InvalidUnicodeString,
        ));
    }
    if length == 0 {
        return Ok(0);
    }

    let mut path = path;
    if let Some(output) = path.as_deref_mut() {
        output.fill(0);
    }
    let mut offset_to_file = 0u16;
    let mut byte_offset = 0usize;
    let mut scratch = [0u8; 64];
    while byte_offset < length {
        let chunk = (length - byte_offset).min(scratch.len());
        remote_read(reader, buffer + byte_offset as u64, &mut scratch[..chunk])?;
        for pair in 0..chunk / 2 {
            let unit = u16::from_le_bytes([scratch[pair * 2], scratch[pair * 2 + 1]]);
            let unit_index = byte_offset / 2 + pair;
            if unit_index < 255 {
                let narrowed = if unit <= 0x7f { unit as u8 } else { b'?' };
                if narrowed == b'\\' || narrowed == b'/' {
                    offset_to_file = (unit_index + 1) as u16;
                }
                if let Some(output) = path.as_deref_mut() {
                    output[unit_index] = narrowed;
                }
            }
        }
        byte_offset += chunk;
    }
    Ok(offset_to_file)
}

fn encode_remote_module_row<R>(
    reader: &mut R,
    entry: &[u8; LDR_ENTRY_SIZE],
    load_index: u16,
    row: Option<&mut [u8]>,
) -> Result<(), RemoteModuleSnapshotError>
where
    R: FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
{
    let image_base = entry_u64(entry, LDR_DLL_BASE_OFFSET);
    let image_size = entry_u32(entry, LDR_SIZE_OF_IMAGE_OFFSET);
    if image_size == 0 || !checked_remote_pointer(image_base, image_size as usize, 0x1000) {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::InvalidModule,
        ));
    }

    let mut row = row;
    if let Some(output) = row.as_deref_mut() {
        output.fill(0);
        output[0x10..0x18].copy_from_slice(&image_base.to_le_bytes());
        output[0x18..0x1c].copy_from_slice(&image_size.to_le_bytes());
        output[0x1c..0x20].copy_from_slice(&entry_u32(entry, LDR_FLAGS_OFFSET).to_le_bytes());
        output[0x20..0x22].copy_from_slice(&load_index.to_le_bytes());
        output[0x24..0x26].copy_from_slice(&entry_u16(entry, LDR_LOAD_COUNT_OFFSET).to_le_bytes());
    }
    let offset_to_file = validate_and_copy_remote_name(
        reader,
        &entry[LDR_FULL_DLL_NAME_OFFSET..LDR_FULL_DLL_NAME_OFFSET + 16],
        row.as_deref_mut().map(|output| &mut output[0x28..0x128]),
    )?;
    if let Some(output) = row {
        output[0x26..0x28].copy_from_slice(&offset_to_file.to_le_bytes());
    }
    Ok(())
}

fn walk_remote_process_modules<R>(
    peb_address: u64,
    reader: &mut R,
    mut output: Option<&mut [u8]>,
) -> Result<RemoteModuleSnapshot, RemoteModuleSnapshotError>
where
    R: FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
{
    if !checked_remote_pointer(peb_address, (PEB_LDR_OFFSET + 8) as usize, 8) {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::InvalidAddress,
        ));
    }
    let ldr = read_remote_u64(reader, peb_address + PEB_LDR_OFFSET)?;
    if !checked_remote_pointer(ldr, (LDR_IN_LOAD_ORDER_LIST_OFFSET + 16) as usize, 8) {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::InvalidAddress,
        ));
    }
    let head = ldr.checked_add(LDR_IN_LOAD_ORDER_LIST_OFFSET).ok_or(
        RemoteModuleSnapshotError::Malformed(RemoteModuleLayoutError::InvalidAddress),
    )?;
    let (head_flink, head_blink) = read_list_entry(reader, head)?;
    if head_flink == head || head_blink == head {
        if head_flink != head || head_blink != head {
            return Err(RemoteModuleSnapshotError::Malformed(
                RemoteModuleLayoutError::InvalidList,
            ));
        }
        return Ok(RemoteModuleSnapshot {
            module_count: 0,
            required_size: RTL_PROCESS_MODULES_HEADER_SIZE,
        });
    }
    if !checked_remote_pointer(head_flink, LDR_ENTRY_SIZE, 8)
        || !checked_remote_pointer(head_blink, LDR_ENTRY_SIZE, 8)
    {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::InvalidList,
        ));
    }

    let mut current = head_flink;
    let mut previous = head;
    let mut count = 0usize;
    loop {
        if count == REMOTE_MODULE_LIMIT {
            return Err(RemoteModuleSnapshotError::Malformed(
                RemoteModuleLayoutError::ModuleLimitExceeded,
            ));
        }
        let mut entry = [0u8; LDR_ENTRY_SIZE];
        remote_read(reader, current, &mut entry)?;
        let flink = entry_u64(&entry, 0);
        let blink = entry_u64(&entry, 8);
        if blink != previous || (flink != head && !checked_remote_pointer(flink, LDR_ENTRY_SIZE, 8))
        {
            return Err(RemoteModuleSnapshotError::Malformed(
                RemoteModuleLayoutError::InvalidList,
            ));
        }

        let row = output.as_deref_mut().map(|buffer| {
            let start =
                RTL_PROCESS_MODULES_HEADER_SIZE + count * RTL_PROCESS_MODULE_INFORMATION_SIZE;
            let end = start + RTL_PROCESS_MODULE_INFORMATION_SIZE;
            buffer
                .get_mut(start..end)
                .ok_or(RemoteModuleSnapshotError::Malformed(
                    RemoteModuleLayoutError::SnapshotChanged,
                ))
        });
        encode_remote_module_row(reader, &entry, count as u16, row.transpose()?)?;
        count += 1;
        if flink == head {
            if current != head_blink {
                return Err(RemoteModuleSnapshotError::Malformed(
                    RemoteModuleLayoutError::InvalidList,
                ));
            }
            break;
        }
        previous = current;
        current = flink;
    }

    let required_size = count
        .checked_mul(RTL_PROCESS_MODULE_INFORMATION_SIZE)
        .and_then(|rows| rows.checked_add(RTL_PROCESS_MODULES_HEADER_SIZE))
        .ok_or(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::RequiredSizeOverflow,
        ))?;
    Ok(RemoteModuleSnapshot {
        module_count: count as u32,
        required_size,
    })
}

/// Validate and optionally encode a remote process's x64 loader list as `RTL_PROCESS_MODULES`.
///
/// The callback must copy exactly `output.len()` bytes from the target address or return the native
/// read status. Passing no output performs a sizing/validation query. Encoding performs a fresh
/// second traversal so no temporary allocation is required.
pub fn query_remote_process_modules<R>(
    peb_address: u64,
    output: Option<&mut [u8]>,
    mut reader: R,
) -> Result<RemoteModuleSnapshot, RemoteModuleSnapshotError>
where
    R: FnMut(u64, &mut [u8]) -> Result<(), NtStatus>,
{
    let planned = walk_remote_process_modules(peb_address, &mut reader, None)?;
    let Some(output) = output else {
        return Ok(planned);
    };
    if output.len() < planned.required_size {
        return Err(RemoteModuleSnapshotError::BufferTooSmall {
            required: planned.required_size,
        });
    }
    output[..planned.required_size].fill(0);
    let encoded = walk_remote_process_modules(
        peb_address,
        &mut reader,
        Some(&mut output[..planned.required_size]),
    )?;
    if encoded != planned {
        return Err(RemoteModuleSnapshotError::Malformed(
            RemoteModuleLayoutError::SnapshotChanged,
        ));
    }
    output[0..4].copy_from_slice(&encoded.module_count.to_le_bytes());
    Ok(encoded)
}

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
    use alloc::vec;
    use alloc::vec::Vec;

    const TEST_READ_FAILURE: NtStatus = 0xc123_4567;

    struct RemoteMemory {
        base: u64,
        bytes: Vec<u8>,
        fail_at: Option<u64>,
    }

    impl RemoteMemory {
        fn new(base: u64, size: usize) -> Self {
            Self {
                base,
                bytes: vec![0; size],
                fail_at: None,
            }
        }

        fn offset(&self, address: u64, length: usize) -> usize {
            let offset = usize::try_from(address - self.base).unwrap();
            assert!(offset.checked_add(length).unwrap() <= self.bytes.len());
            offset
        }

        fn write(&mut self, address: u64, bytes: &[u8]) {
            let offset = self.offset(address, bytes.len());
            self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        }

        fn write_u16(&mut self, address: u64, value: u16) {
            self.write(address, &value.to_le_bytes());
        }

        fn write_u32(&mut self, address: u64, value: u32) {
            self.write(address, &value.to_le_bytes());
        }

        fn write_u64(&mut self, address: u64, value: u64) {
            self.write(address, &value.to_le_bytes());
        }

        fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), NtStatus> {
            let end = address.checked_add(output.len() as u64).unwrap();
            if self
                .fail_at
                .is_some_and(|failure| address <= failure && failure < end)
            {
                return Err(TEST_READ_FAILURE);
            }
            let Some(relative) = address.checked_sub(self.base) else {
                return Err(TEST_READ_FAILURE);
            };
            let Ok(offset) = usize::try_from(relative) else {
                return Err(TEST_READ_FAILURE);
            };
            let Some(bytes) = self.bytes.get(offset..offset.saturating_add(output.len())) else {
                return Err(TEST_READ_FAILURE);
            };
            output.copy_from_slice(bytes);
            Ok(())
        }
    }

    struct RemoteModulesFixture {
        memory: RemoteMemory,
        peb: u64,
        entries: Vec<u64>,
        names: Vec<u64>,
    }

    fn utf16(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn remote_modules_fixture(module_names: &[Vec<u16>]) -> RemoteModulesFixture {
        let base = 0x1000_0000;
        let peb = base + 0x100;
        let ldr = base + 0x400;
        let head = ldr + LDR_IN_LOAD_ORDER_LIST_OFFSET;
        let mut memory = RemoteMemory::new(base, 0x20_000);
        memory.write_u64(peb + PEB_LDR_OFFSET, ldr);

        let entries: Vec<u64> = (0..module_names.len())
            .map(|index| base + 0x1000 + index as u64 * 0x200)
            .collect();
        let names: Vec<u64> = (0..module_names.len())
            .map(|index| base + 0x8000 + index as u64 * 0x4000)
            .collect();
        let first = entries.first().copied().unwrap_or(head);
        let last = entries.last().copied().unwrap_or(head);
        memory.write_u64(head, first);
        memory.write_u64(head + 8, last);

        for (index, name) in module_names.iter().enumerate() {
            let entry = entries[index];
            let flink = entries.get(index + 1).copied().unwrap_or(head);
            let blink = index
                .checked_sub(1)
                .and_then(|previous| entries.get(previous).copied())
                .unwrap_or(head);
            let image_base = 0x2000_0000 + index as u64 * 0x10_0000;
            let name_bytes = name.len() * 2;

            memory.write_u64(entry, flink);
            memory.write_u64(entry + 8, blink);
            memory.write_u64(entry + LDR_DLL_BASE_OFFSET as u64, image_base);
            memory.write_u32(
                entry + LDR_SIZE_OF_IMAGE_OFFSET as u64,
                0x12_000 + index as u32 * 0x1000,
            );
            memory.write_u16(entry + LDR_FULL_DLL_NAME_OFFSET as u64, name_bytes as u16);
            memory.write_u16(
                entry + LDR_FULL_DLL_NAME_OFFSET as u64 + 2,
                name_bytes as u16,
            );
            memory.write_u64(entry + LDR_FULL_DLL_NAME_OFFSET as u64 + 8, names[index]);
            memory.write_u32(entry + LDR_FLAGS_OFFSET as u64, 0x1000_0000 | index as u32);
            memory.write_u16(entry + LDR_LOAD_COUNT_OFFSET as u64, 3 + index as u16);
            for (unit_index, unit) in name.iter().enumerate() {
                memory.write_u16(names[index] + unit_index as u64 * 2, *unit);
            }
        }

        RemoteModulesFixture {
            memory,
            peb,
            entries,
            names,
        }
    }

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

    #[test]
    fn remote_module_snapshot_handles_empty_loader_list() {
        let mut fixture = remote_modules_fixture(&[]);
        let sizing = query_remote_process_modules(fixture.peb, None, |address, output| {
            fixture.memory.read(address, output)
        })
        .unwrap();
        assert_eq!(
            sizing,
            RemoteModuleSnapshot {
                module_count: 0,
                required_size: RTL_PROCESS_MODULES_HEADER_SIZE,
            }
        );

        let mut output = [0xaa; RTL_PROCESS_MODULES_HEADER_SIZE];
        let encoded =
            query_remote_process_modules(fixture.peb, Some(&mut output), |address, bytes| {
                fixture.memory.read(address, bytes)
            })
            .unwrap();
        assert_eq!(encoded, sizing);
        assert_eq!(output, [0; RTL_PROCESS_MODULES_HEADER_SIZE]);
    }

    #[test]
    fn remote_module_snapshot_encodes_exact_x64_row_fields() {
        let name = utf16(r"\SystemRoot\system32\kernel32.dll");
        let expected_offset = name.iter().rposition(|unit| *unit == b'\\' as u16).unwrap() + 1;
        let mut fixture = remote_modules_fixture(&[name.clone()]);
        let required = RTL_PROCESS_MODULES_HEADER_SIZE + RTL_PROCESS_MODULE_INFORMATION_SIZE;
        let mut output = vec![0xcc; required];
        let snapshot =
            query_remote_process_modules(fixture.peb, Some(&mut output), |address, bytes| {
                fixture.memory.read(address, bytes)
            })
            .unwrap();

        assert_eq!(snapshot.module_count, 1);
        assert_eq!(snapshot.required_size, required);
        assert_eq!(u32::from_le_bytes(output[0..4].try_into().unwrap()), 1);
        let row = &output[RTL_PROCESS_MODULES_HEADER_SIZE..];
        assert_eq!(u64::from_le_bytes(row[0..8].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(row[8..16].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(row[0x10..0x18].try_into().unwrap()),
            0x2000_0000
        );
        assert_eq!(
            u32::from_le_bytes(row[0x18..0x1c].try_into().unwrap()),
            0x12_000
        );
        assert_eq!(
            u32::from_le_bytes(row[0x1c..0x20].try_into().unwrap()),
            0x1000_0000
        );
        assert_eq!(u16::from_le_bytes(row[0x20..0x22].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(row[0x22..0x24].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(row[0x24..0x26].try_into().unwrap()), 3);
        assert_eq!(
            u16::from_le_bytes(row[0x26..0x28].try_into().unwrap()),
            expected_offset as u16
        );
        let expected_path: Vec<u8> = name.iter().map(|unit| *unit as u8).collect();
        assert_eq!(&row[0x28..0x28 + expected_path.len()], &expected_path);
        assert_eq!(row[0x28 + expected_path.len()], 0);
    }

    #[test]
    fn remote_module_snapshot_sizes_and_indexes_two_modules() {
        let mut fixture = remote_modules_fixture(&[
            utf16(r"\SystemRoot\system32\ntdll.dll"),
            utf16(r"\SystemRoot\system32\kernel32.dll"),
        ]);
        let required = RTL_PROCESS_MODULES_HEADER_SIZE + 2 * RTL_PROCESS_MODULE_INFORMATION_SIZE;
        let sizing = query_remote_process_modules(fixture.peb, None, |address, output| {
            fixture.memory.read(address, output)
        })
        .unwrap();
        assert_eq!(sizing.module_count, 2);
        assert_eq!(sizing.required_size, required);

        let mut output = vec![0; required];
        query_remote_process_modules(fixture.peb, Some(&mut output), |address, bytes| {
            fixture.memory.read(address, bytes)
        })
        .unwrap();
        let second = RTL_PROCESS_MODULES_HEADER_SIZE + RTL_PROCESS_MODULE_INFORMATION_SIZE;
        assert_eq!(
            u16::from_le_bytes(output[second + 0x20..second + 0x22].try_into().unwrap()),
            1
        );
        assert_eq!(
            u16::from_le_bytes(output[second + 0x24..second + 0x26].try_into().unwrap()),
            4
        );
    }

    #[test]
    fn remote_module_snapshot_truncates_path_and_keeps_stored_filename_offset() {
        let mut name = vec![b'a' as u16; 300];
        name[200] = b'\\' as u16;
        name[270] = b'\\' as u16;
        let mut fixture = remote_modules_fixture(&[name]);
        let required = RTL_PROCESS_MODULES_HEADER_SIZE + RTL_PROCESS_MODULE_INFORMATION_SIZE;
        let mut output = vec![0; required];
        query_remote_process_modules(fixture.peb, Some(&mut output), |address, bytes| {
            fixture.memory.read(address, bytes)
        })
        .unwrap();

        let row = &output[RTL_PROCESS_MODULES_HEADER_SIZE..];
        assert_eq!(u16::from_le_bytes(row[0x26..0x28].try_into().unwrap()), 201);
        assert_eq!(row[0x28 + 200], b'\\');
        assert_eq!(row[0x28 + 254], b'a');
        assert_eq!(row[0x28 + 255], 0);
    }

    #[test]
    fn remote_module_snapshot_distinguishes_output_capacity() {
        let mut fixture = remote_modules_fixture(&[utf16("ntdll.dll")]);
        let required = RTL_PROCESS_MODULES_HEADER_SIZE + RTL_PROCESS_MODULE_INFORMATION_SIZE;
        let mut output = vec![0; required - 1];
        assert_eq!(
            query_remote_process_modules(fixture.peb, Some(&mut output), |address, bytes| {
                fixture.memory.read(address, bytes)
            }),
            Err(RemoteModuleSnapshotError::BufferTooSmall { required })
        );
    }

    #[test]
    fn remote_module_snapshot_rejects_null_cycle_broken_link_and_name() {
        let mut null_ldr = remote_modules_fixture(&[]);
        null_ldr.memory.write_u64(null_ldr.peb + PEB_LDR_OFFSET, 0);
        assert!(matches!(
            query_remote_process_modules(null_ldr.peb, None, |address, bytes| {
                null_ldr.memory.read(address, bytes)
            }),
            Err(RemoteModuleSnapshotError::Malformed(
                RemoteModuleLayoutError::InvalidAddress
            ))
        ));

        let mut cycle = remote_modules_fixture(&[utf16("one.dll")]);
        cycle.memory.write_u64(cycle.entries[0], cycle.entries[0]);
        assert!(matches!(
            query_remote_process_modules(cycle.peb, None, |address, bytes| {
                cycle.memory.read(address, bytes)
            }),
            Err(RemoteModuleSnapshotError::Malformed(
                RemoteModuleLayoutError::InvalidList
            ))
        ));

        let mut broken_link = remote_modules_fixture(&[utf16("one.dll")]);
        broken_link.memory.write_u64(broken_link.entries[0] + 8, 0);
        assert!(matches!(
            query_remote_process_modules(broken_link.peb, None, |address, bytes| {
                broken_link.memory.read(address, bytes)
            }),
            Err(RemoteModuleSnapshotError::Malformed(
                RemoteModuleLayoutError::InvalidList
            ))
        ));

        let mut invalid_name = remote_modules_fixture(&[utf16("one.dll")]);
        invalid_name
            .memory
            .write_u16(invalid_name.entries[0] + LDR_FULL_DLL_NAME_OFFSET as u64, 3);
        assert!(matches!(
            query_remote_process_modules(invalid_name.peb, None, |address, bytes| {
                invalid_name.memory.read(address, bytes)
            }),
            Err(RemoteModuleSnapshotError::Malformed(
                RemoteModuleLayoutError::InvalidUnicodeString
            ))
        ));
    }

    #[test]
    fn remote_module_snapshot_preserves_reader_status() {
        let mut fixture = remote_modules_fixture(&[utf16("ntdll.dll")]);
        fixture.memory.fail_at = Some(fixture.names[0]);
        assert_eq!(
            query_remote_process_modules(fixture.peb, None, |address, output| {
                fixture.memory.read(address, output)
            }),
            Err(RemoteModuleSnapshotError::Read(TEST_READ_FAILURE))
        );
    }
}
