//! Size validation for a caller-supplied MDL span.

const PAGE_BYTES: u64 = 4096;
const MDL_HEADER_BYTES: u64 = 48;
const PFN_BYTES: u64 = 8;

/// Returns the x64 MDL header plus capacity for each page spanned by the
/// original virtual range. The MDL Size field is signed 16-bit, and ByteCount
/// is 32-bit in the native ABI.
pub fn mdl_size_for_range(base: u64, length: u64) -> Option<usize> {
    let byte_count = u32::try_from(length).ok()?;
    let pages = if byte_count == 0 {
        0
    } else {
        base.checked_add(length - 1)?;
        let offset = base & (PAGE_BYTES - 1);
        offset.checked_add(length - 1)? / PAGE_BYTES + 1
    };
    let bytes = pages.checked_mul(PFN_BYTES)?.checked_add(MDL_HEADER_BYTES)?;
    (bytes <= i16::MAX as u64).then_some(bytes as usize)
}
