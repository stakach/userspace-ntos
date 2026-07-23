//! Pure layout and arithmetic support for the user-mode RTL trace database.

use core::ffi::c_void;

pub const TRACE_BLOCK_MAGIC: u32 = 0xabcd_aaaa;
pub const TRACE_SEGMENT_MAGIC: u32 = 0xabcd_bbbb;
pub const TRACE_DATABASE_MAGIC: u32 = 0xabcd_cccc;
pub const TRACE_IN_USER_MODE: u32 = 0x0000_0001;
pub const SEGMENT_SIZE: usize = 0x1_0000;

pub type TraceHashFunction =
    unsafe extern "system" fn(count: u32, trace: *mut *mut c_void) -> u32;

/// ReactOS's public x64 `RTL_TRACE_BLOCK`.
///
/// ReactOS declares `UserCount` and `UserSize` as `ULONG`, producing this 0x30-byte layout rather
/// than the older NT5 0x38-byte layout that used `SIZE_T`. ReactOS consumers directly access these
/// fields, so the ReactOS ABI is authoritative for this kernel.
#[repr(C)]
pub struct TraceBlock {
    pub magic: u32,
    pub count: u32,
    pub size: u32,
    pub user_count: u32,
    pub user_size: u32,
    pub _padding: u32,
    pub user_context: *mut c_void,
    pub next: *mut TraceBlock,
    pub trace: *mut *mut c_void,
}

#[repr(C)]
pub struct TraceDatabase {
    pub magic: u32,
    pub flags: u32,
    pub tag: u32,
    pub _padding0: u32,
    pub segment_list: *mut TraceSegment,
    pub maximum_size: usize,
    pub current_size: usize,
    pub owner: *mut c_void,
    pub lock: [u8; 40],
    pub number_of_buckets: u32,
    pub _padding1: u32,
    pub buckets: *mut *mut TraceBlock,
    pub hash_function: Option<TraceHashFunction>,
    pub number_of_traces: usize,
    pub number_of_hits: usize,
    pub hash_counter: [u32; 16],
}

#[repr(C)]
pub struct TraceSegment {
    pub magic: u32,
    pub _padding: u32,
    pub database: *mut TraceDatabase,
    pub next_segment: *mut TraceSegment,
    pub total_size: usize,
    pub segment_start: *mut u8,
    pub segment_end: *mut u8,
    pub segment_free: *mut u8,
}

#[repr(C)]
pub struct TraceEnumerate {
    pub database: *mut TraceDatabase,
    pub index: u32,
    pub _padding: u32,
    pub block: *mut TraceBlock,
}

pub fn initial_allocation_size(buckets: u32) -> Option<usize> {
    if buckets == 0 {
        return None;
    }
    let metadata = core::mem::size_of::<TraceDatabase>()
        .checked_add(core::mem::size_of::<TraceSegment>())?
        .checked_add((buckets as usize).checked_mul(core::mem::size_of::<*mut TraceBlock>())?)?;
    metadata
        .checked_add(SEGMENT_SIZE - 1)
        .map(|size| size & !(SEGMENT_SIZE - 1))
}

pub fn trace_block_allocation_size(count: u32) -> Option<usize> {
    core::mem::size_of::<TraceBlock>()
        .checked_add((count as usize).checked_mul(core::mem::size_of::<*mut c_void>())?)
}

pub fn can_grow(current_size: usize, maximum_size: usize) -> bool {
    current_size
        .checked_add(SEGMENT_SIZE)
        .is_some_and(|next| maximum_size == 0 || next <= maximum_size)
}

pub fn bucket_index(hash: u32, buckets: u32) -> Option<usize> {
    (buckets != 0).then_some((hash % buckets) as usize)
}

/// Select one of the 16 public histogram bins without the divide-by-zero/OOB bugs in the NT5
/// insertion path.
pub fn hash_counter_index(bucket: usize, buckets: u32) -> Option<usize> {
    if buckets == 0 || bucket >= buckets as usize {
        return None;
    }
    Some(
        bucket
            .saturating_mul(16)
            .checked_div(buckets as usize)?
            .min(15),
    )
}

/// Default RTL trace hash: XOR adjacent 16-bit halves of each pointer and add the pairs.
pub fn standard_hash(trace: &[usize]) -> u32 {
    let mut value = 0usize;
    for pointer in trace {
        let pointer = *pointer;
        value = value.wrapping_add((pointer as u16 ^ (pointer >> 16) as u16) as usize);
        if usize::BITS > 32 {
            value =
                value.wrapping_add(((pointer >> 32) as u16 ^ (pointer >> 48) as u16) as usize);
        }
    }
    value as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reactos_x64_layouts_match_public_headers() {
        assert_eq!(core::mem::size_of::<TraceBlock>(), 0x30);
        assert_eq!(core::mem::offset_of!(TraceBlock, user_context), 0x18);
        assert_eq!(core::mem::offset_of!(TraceBlock, trace), 0x28);

        assert_eq!(core::mem::size_of::<TraceDatabase>(), 0xc0);
        assert_eq!(core::mem::offset_of!(TraceDatabase, lock), 0x30);
        assert_eq!(
            core::mem::offset_of!(TraceDatabase, number_of_buckets),
            0x58
        );
        assert_eq!(core::mem::offset_of!(TraceDatabase, buckets), 0x60);
        assert_eq!(core::mem::offset_of!(TraceDatabase, hash_counter), 0x80);

        assert_eq!(core::mem::size_of::<TraceSegment>(), 0x38);
        assert_eq!(core::mem::offset_of!(TraceSegment, segment_free), 0x30);
        assert_eq!(core::mem::size_of::<TraceEnumerate>(), 0x18);
    }

    #[test]
    fn allocation_sizes_are_checked_and_segment_aligned() {
        assert_eq!(initial_allocation_size(1), Some(SEGMENT_SIZE));
        assert_eq!(initial_allocation_size(8_200), Some(0x2_0000));
        assert_eq!(initial_allocation_size(0), None);
        assert_eq!(trace_block_allocation_size(0), Some(0x30));
        assert_eq!(trace_block_allocation_size(4), Some(0x50));
    }

    #[test]
    fn growth_honors_the_next_complete_segment() {
        assert!(can_grow(SEGMENT_SIZE, 0));
        assert!(can_grow(SEGMENT_SIZE, 2 * SEGMENT_SIZE));
        assert!(!can_grow(SEGMENT_SIZE, SEGMENT_SIZE));
        assert!(!can_grow(usize::MAX, 0));
    }

    #[test]
    fn standard_hash_covers_every_pointer_half() {
        if usize::BITS == 64 {
            assert_eq!(
                standard_hash(&[0x1122_3344_5566_7788usize]),
                (0x7788u16 ^ 0x5566) as u32 + (0x3344u16 ^ 0x1122) as u32
            );
        }
        assert_eq!(standard_hash(&[]), 0);
    }

    #[test]
    fn histogram_bins_are_bounded_for_small_and_prime_bucket_counts() {
        assert_eq!(hash_counter_index(0, 1), Some(0));
        assert_eq!(hash_counter_index(0, 8), Some(0));
        assert_eq!(hash_counter_index(7, 8), Some(14));
        assert_eq!(hash_counter_index(6_262, 6_263), Some(15));
        assert_eq!(hash_counter_index(1, 0), None);
    }
}
