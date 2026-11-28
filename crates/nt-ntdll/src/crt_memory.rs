//! Intrinsic-free byte operations used by ntdll's CRT exports.
//!
//! LLVM may lower `copy_nonoverlapping` or `write_bytes` inside an exported `memcpy` or
//! `memset` back to that very symbol. The x86-64 bodies use explicit string instructions, and
//! the other-architecture implementation uses volatile bytes to keep the same property.

/// Copy in increasing-address order. This also permits overlap when `dst <= src`.
///
/// # Safety
/// Both spans must be valid for `len` bytes. If they overlap, `dst` must start at or before
/// `src`; otherwise an earlier store could overwrite a later source byte.
#[inline]
unsafe fn forward_bytes(dst: *mut u8, src: *const u8, len: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: caller owns both valid spans. `cld` keeps the ABI's forward direction and
        // `rep movsb` copies exactly `len` bytes without an LLVM memory intrinsic.
        unsafe {
            core::arch::asm!(
                "cld",
                "rep movsb",
                inout("rdi") dst => _,
                inout("rsi") src => _,
                inout("rcx") len => _,
                options(nostack),
            );
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        for offset in 0..len {
            // SAFETY: caller owns spans of at least `len` bytes. Volatile
            // operations prevent this fallback from becoming an intrinsic call.
            unsafe {
                dst.add(offset)
                    .write_volatile(src.add(offset).read_volatile())
            };
        }
    }
}

/// Copy `len` bytes between valid, non-overlapping regions.
///
/// # Safety
/// `src` must be readable and `dst` writable for `len` bytes, with no overlap.
#[inline]
pub unsafe fn copy_nonoverlapping_bytes(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: disjoint spans satisfy the forward-copy contract.
    unsafe { forward_bytes(dst, src, len) };
}

/// Fill a valid region with the low byte of `value`.
///
/// # Safety
/// `dst` must be writable for `len` bytes.
#[inline]
pub unsafe fn set_bytes(dst: *mut u8, value: u8, len: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: caller owns the destination span. `rep stosb` fills exactly `len` bytes
        // without an LLVM memory intrinsic.
        unsafe {
            core::arch::asm!(
                "cld",
                "rep stosb",
                inout("rdi") dst => _,
                inout("rcx") len => _,
                in("al") value,
                options(nostack),
            );
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        for offset in 0..len {
            // SAFETY: caller owns a writable span of at least `len` bytes.
            unsafe { dst.add(offset).write_volatile(value) };
        }
    }
}

/// Copy `len` bytes between valid regions that may overlap.
///
/// # Safety
/// `src` must be readable and `dst` writable for `len` bytes.
#[inline]
pub unsafe fn move_bytes(dst: *mut u8, src: *const u8, len: usize) {
    let dst_addr = dst as usize;
    let src_addr = src as usize;
    if dst_addr > src_addr && dst_addr - src_addr < len {
        for offset in (0..len).rev() {
            // SAFETY: the caller owns both spans; reverse order preserves overlapping source
            // bytes. Volatile access prevents LLVM from replacing this with `memmove`.
            unsafe {
                dst.add(offset)
                    .write_volatile(src.add(offset).read_volatile())
            };
        }
    } else {
        // SAFETY: these regions are non-overlapping or the destination starts at or before the
        // source; a forward byte copy is overlap-safe in the latter case.
        unsafe { forward_bytes(dst, src, len) };
    }
}

/// Compare exactly `len` readable bytes without calling the compiler's `memcmp` intrinsic.
///
/// # Safety
/// Both source spans must be readable for `len` bytes.
#[inline]
pub unsafe fn compare_bytes(a: *const u8, b: *const u8, len: usize) -> core::cmp::Ordering {
    for offset in 0..len {
        // SAFETY: the caller owns both readable spans. Volatile loads keep this loop from
        // becoming a call back into the exported `memcmp` symbol.
        let (left, right) =
            unsafe { (a.add(offset).read_volatile(), b.add(offset).read_volatile()) };
        match left.cmp(&right) {
            core::cmp::Ordering::Equal => {}
            order => return order,
        }
    }
    core::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{compare_bytes, copy_nonoverlapping_bytes, move_bytes, set_bytes};

    #[test]
    fn copy_and_fill_preserve_edges_across_small_and_page_sized_spans() {
        for len in [0, 1, 7, 8, 63, 64, 4096] {
            let source: Vec<u8> = (0..len)
                .map(|index| (index as u8).wrapping_mul(17))
                .collect();
            let mut target = vec![0xa5; len + 2];
            // SAFETY: source and target are separate allocations with the requested spans.
            unsafe { copy_nonoverlapping_bytes(target.as_mut_ptr().add(1), source.as_ptr(), len) };
            assert_eq!(target[0], 0xa5);
            assert_eq!(&target[1..1 + len], &source);
            assert_eq!(target[len + 1], 0xa5);
            // SAFETY: the inner target span is valid and writable for `len` bytes.
            unsafe { set_bytes(target.as_mut_ptr().add(1), 0x5c, len) };
            assert_eq!(&target[1..1 + len], vec![0x5c; len]);
            assert_eq!((target[0], target[len + 1]), (0xa5, 0xa5));
        }
    }

    #[test]
    fn compare_reports_the_first_unequal_byte_without_touching_the_tail() {
        let left = [0x10, 0x20, 0x30, 0xee];
        let right = [0x10, 0x21, 0x00, 0x11];
        // SAFETY: both arrays have at least the compared number of bytes.
        assert_eq!(
            unsafe { compare_bytes(left.as_ptr(), right.as_ptr(), 0) },
            core::cmp::Ordering::Equal
        );
        assert_eq!(
            unsafe { compare_bytes(left.as_ptr(), right.as_ptr(), 1) },
            core::cmp::Ordering::Equal
        );
        assert_eq!(
            unsafe { compare_bytes(left.as_ptr(), right.as_ptr(), 3) },
            core::cmp::Ordering::Less
        );
        assert_eq!(
            unsafe { compare_bytes(right.as_ptr(), left.as_ptr(), 3) },
            core::cmp::Ordering::Greater
        );
    }

    #[test]
    fn move_handles_both_overlap_directions_and_identity() {
        let input = b"0123456789abcdef";
        let mut right = *input;
        // SAFETY: both spans are inside `right`; the destination starts after the source.
        unsafe { move_bytes(right.as_mut_ptr().add(3), right.as_ptr(), 10) };
        assert_eq!(&right, b"0120123456789def");

        let mut left = *input;
        // SAFETY: both spans are inside `left`; the destination starts before the source.
        unsafe { move_bytes(left.as_mut_ptr(), left.as_ptr().add(3), 10) };
        assert_eq!(&left, b"3456789abcabcdef");

        let mut same = *input;
        // SAFETY: identical source and destination spans are valid for all bytes.
        unsafe { move_bytes(same.as_mut_ptr(), same.as_ptr(), same.len()) };
        assert_eq!(&same, input);

        let mut page: Vec<u8> = (0..4098).map(|index| index as u8).collect();
        let mut expected = page.clone();
        expected.copy_within(0..4096, 2);
        // SAFETY: both 4096-byte spans are within `page`; the destination starts later.
        unsafe { move_bytes(page.as_mut_ptr().add(2), page.as_ptr(), 4096) };
        assert_eq!(page, expected);
    }
}
