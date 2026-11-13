//! Bounds-aware CRT formatting exports from the released ntdll.

use core::ffi::VaList;

/// Match Wine's secure formatting rule: render at most `min(size, count)`
/// units, clear the destination when it cannot hold a terminator, and return
/// `-1` on overflow.  `_TRUNCATE` is represented by `usize::MAX`.
unsafe fn narrow(
    dst: *mut u8,
    size: usize,
    count: usize,
    format: *const u8,
    args: VaList<'_>,
) -> i32 {
    if dst.is_null() || size == 0 || format.is_null() {
        return -1;
    }
    let rendered = unsafe { crate::exports::format_narrow_va(dst, size.min(count), format, args) };
    if rendered < 0 || rendered as usize >= size {
        unsafe { dst.write(0) };
        return -1;
    }
    unsafe { dst.add(rendered as usize).write(0) };
    rendered
}

unsafe fn wide(
    dst: *mut u16,
    size: usize,
    count: usize,
    format: *const u16,
    args: VaList<'_>,
) -> i32 {
    if dst.is_null() || size == 0 || format.is_null() {
        return -1;
    }
    let rendered = unsafe { crate::exports::format_wide_va(dst, size.min(count), format, args) };
    if rendered < 0 || rendered as usize >= size {
        unsafe { dst.write(0) };
        return -1;
    }
    unsafe { dst.add(rendered as usize).write(0) };
    rendered
}

#[export_name = "_vsnprintf_s"]
pub unsafe extern "C" fn vsnprintf_s(
    dst: *mut u8,
    size: usize,
    count: usize,
    format: *const u8,
    args: VaList<'_>,
) -> i32 {
    unsafe { narrow(dst, size, count, format, args) }
}

#[export_name = "_vsnwprintf_s"]
pub unsafe extern "C" fn vsnwprintf_s(
    dst: *mut u16,
    size: usize,
    count: usize,
    format: *const u16,
    args: VaList<'_>,
) -> i32 {
    unsafe { wide(dst, size, count, format, args) }
}

#[export_name = "_snprintf_s"]
pub unsafe extern "C" fn snprintf_s(
    dst: *mut u8,
    size: usize,
    count: usize,
    format: *const u8,
    args: ...,
) -> i32 {
    unsafe { narrow(dst, size, count, format, args) }
}

#[export_name = "_snwprintf_s"]
pub unsafe extern "C" fn snwprintf_s(
    dst: *mut u16,
    size: usize,
    count: usize,
    format: *const u16,
    args: ...,
) -> i32 {
    unsafe { wide(dst, size, count, format, args) }
}
