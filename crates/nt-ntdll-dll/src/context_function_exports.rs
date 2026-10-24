//! Additional x64 context and dynamic unwind-table exports.
//!
//! The context helpers use the same 0x4d0-byte CONTEXT layout as `extended_context` and `seh`.

use core::{ffi::c_void, ptr};

use nt_ntdll::rtl::dynamic_function_table::dynamic_function_tables;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_NO_MEMORY: u32 = 0xc000_0017;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const STATUS_NOT_IMPLEMENTED: u32 = 0xc000_0002;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_XSTATE: u32 = 0x40;
const FLAGS_OFFSET: usize = 0x30;

// Each register group's end is the next group's start. These are the tested
// Windows/Wine CONTEXT_COPY_RANGES for AMD64.
const COPY_RANGES: &[(usize, u32)] = &[
    (0x38, 0x1),
    (0x3a, 0x4),
    (0x42, 0x1),
    (0x48, 0x10),
    (0x78, 0x2),
    (0x98, 0x1),
    (0xa0, 0x2),
    (0xf8, 0x1),
    (0x100, 0x8),
    (0x2a0, 0),
    (0x4b0, 0x10),
    (0x4d0, 0),
];

/// Copy the requested register groups from one x64 CONTEXT to another.
///
/// # Safety
/// Both pointers name readable/writable 0x4d0-byte AMD64 CONTEXT records.
#[export_name = "RtlCopyContext"]
pub unsafe extern "system" fn rtl_copy_context(
    dst: *mut c_void,
    flags: u32,
    src: *const c_void,
) -> u32 {
    if flags & CONTEXT_XSTATE != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    if flags & CONTEXT_AMD64 == 0
        || flags & !(0xd800_0000 | CONTEXT_AMD64 | 0x5f) != 0
        || dst.is_null()
        || src.is_null()
    {
        return STATUS_INVALID_PARAMETER;
    }
    let dst = dst.cast::<u8>();
    let src = src.cast::<u8>();
    let dst_flags = unsafe { ptr::read_unaligned(dst.add(FLAGS_OFFSET).cast::<u32>()) };
    let src_flags = unsafe { ptr::read_unaligned(src.add(FLAGS_OFFSET).cast::<u32>()) };
    if dst_flags & CONTEXT_AMD64 == 0 || src_flags & CONTEXT_AMD64 == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let available = flags & src_flags;
    for (index, &(start, group)) in COPY_RANGES.iter().enumerate() {
        if group != 0 && available & group != 0 {
            let end = COPY_RANGES[index + 1].0;
            unsafe { ptr::copy(src.add(start), dst.add(start), end - start) };
        }
    }
    STATUS_SUCCESS
}

/// Resolve the legacy CONTEXT described by CONTEXT_EX.
///
/// # Safety
/// `context_ex` is a valid CONTEXT_EX; `length` is null or writable.
#[export_name = "RtlLocateLegacyContext"]
pub unsafe extern "system" fn rtl_locate_legacy_context(
    context_ex: *const crate::extended_context::ContextEx,
    length: *mut u32,
) -> *mut c_void {
    if context_ex.is_null() {
        return ptr::null_mut();
    }
    let chunk = unsafe { (*context_ex).legacy };
    if !length.is_null() {
        unsafe { ptr::write(length, chunk.length) };
    }
    unsafe { (context_ex as *const u8).offset(chunk.offset as isize) as *mut c_void }
}

/// Explicit XState locator. The hosted executive advertises no enabled XState features.
/// A custom XSTATE_CONFIGURATION cannot be interpreted against a context we never saved.
#[export_name = "RtlLocateExtendedFeature2"]
pub unsafe extern "system" fn rtl_locate_extended_feature2(
    _context_ex: *const crate::extended_context::ContextEx,
    _feature_id: u32,
    _xstate_configuration: *const c_void,
    length: *mut u32,
) -> *mut c_void {
    if !length.is_null() {
        unsafe { ptr::write(length, 0) };
    }
    ptr::null_mut()
}

/// Construct the start register state specified by the ReactOS AMD64 contract.
///
/// # Safety
/// `context` names a writable 0x4d0-byte AMD64 CONTEXT.
#[export_name = "RtlInitializeContext"]
pub unsafe extern "system" fn rtl_initialize_context(
    _process_handle: *mut c_void,
    context: *mut c_void,
    start_parameter: *mut c_void,
    start_address: *mut c_void,
    stack_base: *mut c_void,
) {
    if stack_base as usize & 15 != 0 {
        unsafe { crate::exports::rtl_raise_status(0xc000_0009) };
        return;
    }
    let context = context.cast::<u8>();
    unsafe {
        ptr::write_unaligned(context.add(0x30).cast::<u32>(), CONTEXT_AMD64 | 0xb);
        ptr::write_unaligned(context.add(0x34).cast::<u32>(), 0x1f80);
        ptr::write_unaligned(context.add(0x44).cast::<u32>(), 0x200);
        ptr::write_unaligned(context.add(0x78).cast::<u64>(), 0);
        ptr::write_unaligned(context.add(0x80).cast::<u64>(), start_parameter as u64);
        ptr::write_unaligned(context.add(0x90).cast::<u64>(), 1);
        ptr::write_unaligned(context.add(0x98).cast::<u64>(), stack_base as u64);
        ptr::write_unaligned(context.add(0xa0).cast::<u64>(), 0);
        ptr::write_unaligned(context.add(0xa8).cast::<u64>(), 4);
        ptr::write_unaligned(context.add(0xb0).cast::<u64>(), 5);
        for (offset, value) in [
            (0xb8, 8),
            (0xc0, 0xf0e0_d0c0_a090_8070),
            (0xc8, 10),
            (0xd0, 11),
            (0xd8, 12),
            (0xe0, 13),
            (0xe8, 14),
            (0xf0, 15),
        ] {
            ptr::write_unaligned(context.add(offset).cast::<u64>(), value);
        }
        ptr::write_unaligned(context.add(0xf8).cast::<u64>(), start_address as u64);
        ptr::write_bytes(context.add(0x100), 0, 0x200);
        ptr::write_unaligned(context.add(0x100).cast::<u16>(), 0x027f);
        ptr::write_unaligned(context.add(0x118).cast::<u32>(), 0x1f80);
    }
}

/// Register a growable unwind table and return its process-local opaque handle.
///
/// # Safety
/// The caller owns `functions` for every subsequently published row.
#[export_name = "RtlAddGrowableFunctionTable"]
pub unsafe extern "system" fn rtl_add_growable_function_table(
    table: *mut *mut c_void,
    functions: *mut c_void,
    count: u32,
    maximum_count: u32,
    base: usize,
    end: usize,
) -> u32 {
    if table.is_null()
        || count > maximum_count
        || base >= end
        || (maximum_count != 0 && functions.is_null())
    {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(handle) = (unsafe {
        dynamic_function_tables().add_growable(
            functions.cast(),
            count,
            maximum_count,
            base as u64,
            end as u64,
        )
    }) else {
        return STATUS_NO_MEMORY;
    };
    unsafe { ptr::write(table, handle) };
    STATUS_SUCCESS
}

#[export_name = "RtlGrowFunctionTable"]
pub extern "system" fn rtl_grow_function_table(table: *mut c_void, count: u32) {
    dynamic_function_tables().grow(table, count);
}

#[export_name = "RtlDeleteGrowableFunctionTable"]
pub extern "system" fn rtl_delete_growable_function_table(table: *mut c_void) {
    dynamic_function_tables().delete_growable(table);
}

/// Extended unwind includes machine-frame and stack-limit outputs. The current live
/// unwinder cannot report these atomically, so fail instead of publishing a partial frame.
#[export_name = "RtlVirtualUnwind2"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_virtual_unwind2(
    _handler_type: u32,
    _image_base: usize,
    _control_pc: usize,
    _function_entry: *const c_void,
    _context: *mut c_void,
    _machine_frame_unwound: *mut u8,
    _handler_data: *mut *mut c_void,
    _establisher_frame: *mut usize,
    _context_pointers: *mut c_void,
    _low_limit: *mut usize,
    _high_limit: *mut usize,
    _handler: *mut *mut c_void,
    _flags: u32,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

#[used]
pub static CONTEXT_FUNCTION_EXPORT_ANCHOR_FN: unsafe extern "C" fn() =
    context_function_export_anchor;

pub unsafe extern "C" fn context_function_export_anchor() {
    core::hint::black_box(rtl_copy_context as *const () as usize);
    core::hint::black_box(rtl_locate_legacy_context as *const () as usize);
    core::hint::black_box(rtl_locate_extended_feature2 as *const () as usize);
    core::hint::black_box(rtl_initialize_context as *const () as usize);
    core::hint::black_box(rtl_add_growable_function_table as *const () as usize);
    core::hint::black_box(rtl_grow_function_table as *const () as usize);
    core::hint::black_box(rtl_delete_growable_function_table as *const () as usize);
    core::hint::black_box(rtl_virtual_unwind2 as *const () as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_context_only_moves_requested_available_groups() {
        let mut dst = [0x11u8; 0x4d0];
        let mut src = [0x22u8; 0x4d0];
        dst[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&(CONTEXT_AMD64 | 0xb).to_le_bytes());
        src[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&(CONTEXT_AMD64 | 0x1).to_le_bytes());
        assert_eq!(
            unsafe {
                rtl_copy_context(
                    dst.as_mut_ptr().cast(),
                    CONTEXT_AMD64 | 0x3,
                    src.as_ptr().cast(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(dst[0x98], 0x22);
        assert_eq!(dst[0x78], 0x11);
    }

    #[test]
    fn legacy_locator_uses_context_ex_offset_and_length() {
        #[repr(align(16))]
        struct Aligned([u8; 0x500]);
        let mut storage = Aligned([0u8; 0x500]);
        let extended = unsafe {
            storage
                .0
                .as_mut_ptr()
                .add(0x4d0)
                .cast::<crate::extended_context::ContextEx>()
        };
        unsafe {
            ptr::write(
                extended,
                crate::extended_context::ContextEx {
                    all: crate::extended_context::ContextChunk {
                        offset: -0x4d0,
                        length: 0x4e8,
                    },
                    legacy: crate::extended_context::ContextChunk {
                        offset: -0x4d0,
                        length: 0x4d0,
                    },
                    xstate: crate::extended_context::ContextChunk {
                        offset: 25,
                        length: 0,
                    },
                    alignment: 0,
                },
            );
        }
        let mut length = 0;
        assert_eq!(
            unsafe { rtl_locate_legacy_context(extended, &mut length) },
            storage.0.as_mut_ptr().cast()
        );
        assert_eq!(length, 0x4d0);
    }

    #[test]
    fn initialize_context_sets_only_documented_amd64_start_fields() {
        let mut context = [0xccu8; 0x4d0];
        unsafe {
            rtl_initialize_context(
                ptr::null_mut(),
                context.as_mut_ptr().cast(),
                0x1234usize as *mut c_void,
                0x5678usize as *mut c_void,
                0x10000usize as *mut c_void,
            );
        }
        assert_eq!(
            u32::from_le_bytes(context[0x30..0x34].try_into().unwrap()),
            CONTEXT_AMD64 | 0xb
        );
        assert_eq!(
            u64::from_le_bytes(context[0x80..0x88].try_into().unwrap()),
            0x1234
        );
        assert_eq!(
            u64::from_le_bytes(context[0x98..0xa0].try_into().unwrap()),
            0x10000
        );
        assert_eq!(
            u64::from_le_bytes(context[0xf8..0x100].try_into().unwrap()),
            0x5678
        );
        assert_eq!(
            u16::from_le_bytes(context[0x100..0x102].try_into().unwrap()),
            0x027f
        );
        assert_eq!(context[0], 0xcc);
        assert_eq!(context[0x300], 0xcc);
    }
}
