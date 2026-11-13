//! Driver CRT wide-string and opaque-record operations shared with ntdll semantics.

use super::*;

const MAX_WSTRING_UNITS: usize = 4096;

fn wide_z(address: u64) -> &'static [u16] {
    if address == 0 || address & 1 != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5753_5452, address, 0, 0]); }
    }
    for index in 0..MAX_WSTRING_UNITS {
        let Some(unit_address) = address.checked_add((index as u64) * 2) else {
            unsafe { crate::provider_bugcheck::report(0xc4, [0x5753_5452, address, index as u64, 1]); }
        };
        if unsafe { read_unaligned(unit_address as *const u16) } == 0 {
            return unsafe { core::slice::from_raw_parts(address as *const u16, index + 1) };
        }
    }
    unsafe { crate::provider_bugcheck::report(0xc4, [0x5753_5452, address, MAX_WSTRING_UNITS as u64, 2]); }
}

/// `int wcscmp(const wchar_t *left, const wchar_t *right)`.
pub(super) extern "win64" fn wcscmp(left: u64, right: u64) -> i32 {
    use core::cmp::Ordering as Cmp;
    match nt_compat_exports::crt::compare_wide_z(wide_z(left), wide_z(right)) {
        Some(Cmp::Less) => -1,
        Some(Cmp::Equal) => 0,
        Some(Cmp::Greater) => 1,
        None => unsafe { crate::provider_bugcheck::report(0xc4, [0x5753_5452, left, right, 3]); },
    }
}

/// `wchar_t *wcsrchr(const wchar_t *string, wchar_t target)`.
pub(super) extern "win64" fn wcsrchr(string: u64, target: u16) -> u64 {
    nt_compat_exports::crt::rfind_wide_z(wide_z(string), target)
        .map(|index| string + (index as u64) * 2)
        .unwrap_or(0)
}

type Comparator = extern "win64" fn(u64, u64) -> i32;

/// `void qsort(void *base, size_t count, size_t size, int (*compare)(...))`.
pub(super) extern "win64" fn qsort(base: u64, count: usize, size: usize, comparator: u64) {
    let Some(bytes) = count.checked_mul(size) else {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5153_4f52, count as u64, size as u64, 0]); }
    };
    if base == 0 || comparator == 0 || count == 0 || size == 0
        || bytes > isize::MAX as usize || base.checked_add(bytes as u64).is_none()
    {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5153_4f52, base, bytes as u64, comparator]); }
    }
    let compare: Comparator = unsafe { core::mem::transmute(comparator as usize) };
    let elements = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, bytes) };
    let sorted = nt_compat_exports::crt::sort_opaque_elements(elements, size, |left, right| {
        compare(left.as_ptr() as u64, right.as_ptr() as u64).cmp(&0)
    });
    if !sorted {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x5153_4f52, base, count as u64, size as u64]); }
    }
}
