//! Lookup of a named export in a mapped image.

use core::ffi::{c_char, c_void};

#[repr(C)]
struct AnsiString {
    length: u16,
    maximum_length: u16,
    buffer: *const c_char,
}

/// `RtlFindExportedRoutineByName(ImageBase, ExportName) -> PVOID`.
///
/// # Safety
/// `image_base` must name a mapped image and `export_name` a terminated ANSI string.
#[export_name = "RtlFindExportedRoutineByName"]
pub unsafe extern "system" fn rtl_find_exported_routine_by_name(
    image_base: *mut c_void,
    export_name: *const c_char,
) -> *mut c_void {
    if image_base.is_null() || export_name.is_null() {
        return core::ptr::null_mut();
    }
    let mut length = 0usize;
    // SAFETY: the caller supplies a NUL-terminated ANSI export name. The
    // counted loader API cannot represent names longer than u16::MAX.
    while length < u16::MAX as usize && unsafe { *export_name.add(length) } != 0 {
        length += 1;
    }
    if length == u16::MAX as usize {
        return core::ptr::null_mut();
    }
    let name = AnsiString {
        length: length as u16,
        maximum_length: (length + 1) as u16,
        buffer: export_name,
    };
    let mut address = core::ptr::null_mut();
    // SAFETY: both descriptors live across the loader's synchronous lookup.
    let status = unsafe {
        crate::exports::ldr_get_procedure_address(
            image_base,
            &name as *const AnsiString as *const c_void,
            0,
            &mut address,
        )
    };
    if status & 0x8000_0000 == 0 { address } else { core::ptr::null_mut() }
}

#[used]
pub static FIND_EXPORTED_ROUTINE_ANCHOR_FN: unsafe extern "C" fn() =
    find_exported_routine_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn find_exported_routine_anchor() {
    core::hint::black_box(rtl_find_exported_routine_by_name as *const () as usize);
}
