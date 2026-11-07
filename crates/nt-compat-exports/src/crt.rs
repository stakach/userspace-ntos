//! Pure CRT primitives shared by kernel and ntdll export adapters.

use core::cmp::Ordering;

/// First matching byte within exactly `n` bytes, if any.
pub fn memchr(haystack: &[u8], target: u8, n: usize) -> Option<usize> {
    haystack[..n.min(haystack.len())]
        .iter()
        .position(|&byte| byte == target)
}

/// First matching byte in a C string, including its terminating NUL when requested.
pub fn strchr(string: &[u8], target: u8) -> Option<usize> {
    for (index, &byte) in string.iter().enumerate() {
        if byte == target {
            return Some(index);
        }
        if byte == 0 {
            return None;
        }
    }
    None
}

/// Compare two NUL-terminated UTF-16 strings inside their supplied readable bounds.
/// An unterminated input is invalid even when an earlier code unit differs.
pub fn compare_wide_z(left: &[u16], right: &[u16]) -> Option<Ordering> {
    let left_end = left.iter().position(|&unit| unit == 0)?;
    let right_end = right.iter().position(|&unit| unit == 0)?;
    Some(left[..left_end].cmp(&right[..right_end]))
}

/// Find the last matching UTF-16 code unit before the terminator, or the
/// terminator's index when the requested code unit is NUL.
pub fn rfind_wide_z(string: &[u16], target: u16) -> Option<usize> {
    let end = string.iter().position(|&unit| unit == 0)?;
    if target == 0 {
        Some(end)
    } else {
        string[..end].iter().rposition(|&unit| unit == target)
    }
}

/// Sort opaque fixed-size records in place with no allocation. The byte slice
/// is the complete writable extent; incomplete records and zero-sized records
/// are rejected before any comparator call or mutation.
pub fn sort_opaque_elements(
    bytes: &mut [u8],
    record_size: usize,
    mut compare: impl FnMut(&[u8], &[u8]) -> Ordering,
) -> bool {
    if record_size == 0 || bytes.len() % record_size != 0 {
        return false;
    }
    let count = bytes.len() / record_size;
    if count < 2 {
        return true;
    }

    fn compare_at(
        bytes: &[u8],
        size: usize,
        left: usize,
        right: usize,
        compare: &mut impl FnMut(&[u8], &[u8]) -> Ordering,
    ) -> Ordering {
        compare(
            &bytes[left * size..(left + 1) * size],
            &bytes[right * size..(right + 1) * size],
        )
    }

    fn swap_at(bytes: &mut [u8], size: usize, left: usize, right: usize) {
        for offset in 0..size {
            bytes.swap(left * size + offset, right * size + offset);
        }
    }

    fn sift_down(
        bytes: &mut [u8],
        size: usize,
        mut root: usize,
        end: usize,
        compare: &mut impl FnMut(&[u8], &[u8]) -> Ordering,
    ) {
        while let Some(left) = root.checked_mul(2).and_then(|index| index.checked_add(1)) {
            if left > end {
                break;
            }
            let right = left + usize::from(left < end);
            let larger = if compare_at(bytes, size, left, right, compare) == Ordering::Less {
                right
            } else {
                left
            };
            if compare_at(bytes, size, root, larger, compare) != Ordering::Less {
                break;
            }
            swap_at(bytes, size, root, larger);
            root = larger;
        }
    }

    for root in (0..count / 2).rev() {
        sift_down(bytes, record_size, root, count - 1, &mut compare);
    }
    for end in (1..count).rev() {
        swap_at(bytes, record_size, 0, end);
        sift_down(bytes, record_size, 0, end - 1, &mut compare);
    }
    true
}
