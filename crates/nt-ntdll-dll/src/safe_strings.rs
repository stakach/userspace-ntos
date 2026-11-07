//! CRT safe-string exports used by optional installed binaries.

use core::ffi::c_char;

const EINVAL: i32 = 22;
const ERANGE: i32 = 34;
const STRUNCATE: i32 = 80;

/// `strcpy_s(dst, size, src) -> errno_t`.
///
/// # Safety
/// `dst` is writable for `size` bytes and `src` is NUL terminated.
#[export_name = "strcpy_s"]
pub unsafe extern "C" fn strcpy_s(dst: *mut c_char, size: usize, src: *const c_char) -> i32 {
    if dst.is_null() || size == 0 {
        return EINVAL;
    }
    if src.is_null() {
        unsafe { *dst = 0 };
        return EINVAL;
    }
    for index in 0..size {
        let value = unsafe { *src.add(index) };
        unsafe { *dst.add(index) = value };
        if value == 0 {
            return 0;
        }
    }
    unsafe { *dst = 0 };
    ERANGE
}

/// `strcat_s(dst, size, src) -> errno_t`.
///
/// # Safety
/// `dst` is writable for `size` bytes and `src` is NUL terminated.
#[export_name = "strcat_s"]
pub unsafe extern "C" fn strcat_s(dst: *mut c_char, size: usize, src: *const c_char) -> i32 {
    if dst.is_null() || size == 0 {
        return EINVAL;
    }
    if src.is_null() {
        unsafe { *dst = 0 };
        return EINVAL;
    }
    let mut used = 0;
    while used < size && unsafe { *dst.add(used) } != 0 {
        used += 1;
    }
    if used == size {
        unsafe { *dst = 0 };
        return ERANGE;
    }
    for index in 0..(size - used) {
        let value = unsafe { *src.add(index) };
        unsafe { *dst.add(used + index) = value };
        if value == 0 {
            return 0;
        }
    }
    unsafe { *dst = 0 };
    ERANGE
}

/// `strncpy_s(dst, size, src, count) -> errno_t`.
///
/// # Safety
/// `dst` is writable for `size` bytes and `src` is NUL terminated or readable
/// for `count` bytes, whichever is shorter.
#[export_name = "strncpy_s"]
pub unsafe extern "C" fn strncpy_s(
    dst: *mut c_char,
    size: usize,
    src: *const c_char,
    count: usize,
) -> i32 {
    if count == 0 {
        if !dst.is_null() && size != 0 {
            unsafe { *dst = 0 };
        }
        return 0;
    }
    if dst.is_null() || size == 0 {
        return EINVAL;
    }
    if src.is_null() {
        unsafe { *dst = 0 };
        return EINVAL;
    }
    let end = if count != usize::MAX && count < size {
        count
    } else {
        size - 1
    };
    for index in 0..end {
        let value = unsafe { *src.add(index) };
        unsafe { *dst.add(index) = value };
        if value == 0 {
            return 0;
        }
    }
    if count == usize::MAX {
        unsafe { *dst.add(end) = 0 };
        return STRUNCATE;
    }
    if end == count {
        unsafe { *dst.add(end) = 0 };
        return 0;
    }
    unsafe { *dst = 0 };
    ERANGE
}

/// `wcsnlen(s, maxlen) -> size_t`.
///
/// # Safety
/// `s` is readable for `maxlen` UTF-16 units or until its first NUL.
#[export_name = "wcsnlen"]
pub unsafe extern "C" fn wcsnlen(s: *const u16, maxlen: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut count = 0;
    while count < maxlen && unsafe { *s.add(count) } != 0 {
        count += 1;
    }
    count
}

#[used]
pub static SAFE_STRINGS_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = safe_strings_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn safe_strings_export_anchor() {
    core::hint::black_box([
        strcpy_s as *const () as usize,
        strcat_s as *const () as usize,
        strncpy_s as *const () as usize,
        wcsnlen as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_and_concat_fail_closed_on_capacity() {
        let mut dst = [0i8; 5];
        assert_eq!(
            unsafe { strcpy_s(dst.as_mut_ptr(), dst.len(), b"hi\0".as_ptr().cast()) },
            0
        );
        assert_eq!(
            unsafe { strcat_s(dst.as_mut_ptr(), dst.len(), b"!\0".as_ptr().cast()) },
            0
        );
        assert_eq!(&dst[..4], &[b'h' as i8, b'i' as i8, b'!' as i8, 0]);
        assert_eq!(
            unsafe { strcat_s(dst.as_mut_ptr(), dst.len(), b"toolong\0".as_ptr().cast()) },
            ERANGE
        );
        assert_eq!(dst[0], 0);
        assert_eq!(
            unsafe { strcpy_s(dst.as_mut_ptr(), dst.len(), b"toolong\0".as_ptr().cast()) },
            ERANGE
        );
        assert_eq!(dst[0], 0);
    }

    #[test]
    fn bounded_copy_reports_truncation_and_zero_count() {
        let mut dst = [0i8; 4];
        assert_eq!(
            unsafe {
                strncpy_s(
                    dst.as_mut_ptr(),
                    dst.len(),
                    b"longer\0".as_ptr().cast(),
                    usize::MAX,
                )
            },
            STRUNCATE
        );
        assert_eq!(&dst, &[b'l' as i8, b'o' as i8, b'n' as i8, 0]);
        assert_eq!(
            unsafe { strncpy_s(dst.as_mut_ptr(), dst.len(), b"longer\0".as_ptr().cast(), 0) },
            0
        );
        assert_eq!(dst[0], 0);
        assert_eq!(
            unsafe { strncpy_s(dst.as_mut_ptr(), dst.len(), b"longer\0".as_ptr().cast(), 4) },
            ERANGE
        );
        assert_eq!(dst[0], 0);
    }

    #[test]
    fn utf16_length_stops_at_limit_or_terminator() {
        let units = [1u16, 2, 0, 3];
        assert_eq!(unsafe { wcsnlen(units.as_ptr(), 2) }, 2);
        assert_eq!(unsafe { wcsnlen(units.as_ptr(), 4) }, 2);
    }
}
