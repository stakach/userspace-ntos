//! x64 `CONTEXT_EX` construction and legacy-context copy.
//!
//! The executive does not yet save extended processor state and publishes zero
//! enabled XState features. Requests for `CONTEXT_XSTATE` therefore fail with
//! `STATUS_NOT_SUPPORTED`, as the reference ntdll does when no features are
//! enabled. The ordinary x64 context layout and copy contract remain usable.

use core::{ffi::c_void, ptr};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_XSTATE: u32 = 0x40;
const SUPPORTED_FLAGS: u32 = 0xd800_0000 | CONTEXT_AMD64 | 0x5f;
const CONTEXT_SIZE: usize = 0x4d0;
const CONTEXT_EX_SIZE: usize = 0x20;
const ALIGNMENT_SLACK: usize = 7;
const FLAGS_OFFSET: usize = 0x30;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextChunk {
    pub offset: i32,
    pub length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextEx {
    pub all: ContextChunk,
    pub legacy: ContextChunk,
    pub xstate: ContextChunk,
    pub alignment: u64,
}

const _: () = assert!(core::mem::size_of::<ContextEx>() == CONTEXT_EX_SIZE);

fn valid_flags(flags: u32) -> bool {
    flags & CONTEXT_AMD64 != 0 && flags & !SUPPORTED_FLAGS == 0
}

fn requested_length(flags: u32, enabled_features: u64) -> Result<u32, u32> {
    if !valid_flags(flags) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if flags & CONTEXT_XSTATE != 0 && enabled_features == 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    // The native host does not currently publish any enabled features. Keep
    // this path honest if that changes before the context contract is added.
    if flags & CONTEXT_XSTATE != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok((CONTEXT_SIZE + CONTEXT_EX_SIZE + ALIGNMENT_SLACK) as u32)
}

fn enabled_features() -> u64 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        crate::extended_features::rtl_get_enabled_extended_features(u64::MAX)
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        0
    }
}

/// `RtlGetExtendedContextLength2` computes the required caller-owned buffer.
#[export_name = "RtlGetExtendedContextLength2"]
pub unsafe extern "system" fn rtl_get_extended_context_length2(
    flags: u32,
    length: *mut u32,
    _compaction_mask: u64,
) -> u32 {
    match requested_length(flags, enabled_features()) {
        Ok(required) => {
            if length.is_null() {
                return STATUS_INVALID_PARAMETER;
            }
            unsafe { ptr::write(length, required) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

#[export_name = "RtlGetExtendedContextLength"]
pub unsafe extern "system" fn rtl_get_extended_context_length(flags: u32, length: *mut u32) -> u32 {
    unsafe { rtl_get_extended_context_length2(flags, length, u64::MAX) }
}

#[export_name = "RtlInitializeExtendedContext2"]
pub unsafe extern "system" fn rtl_initialize_extended_context2(
    context: *mut c_void,
    flags: u32,
    context_ex: *mut *mut ContextEx,
    _compaction_mask: u64,
) -> u32 {
    if let Err(status) = requested_length(flags, enabled_features()) {
        return status;
    }
    if context.is_null() || context_ex.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let aligned = ((context as usize) + 15) & !15usize;
    let context_ptr = aligned as *mut u8;
    let extended = unsafe { context_ptr.add(CONTEXT_SIZE) as *mut ContextEx };
    unsafe {
        ptr::write(context_ptr.add(FLAGS_OFFSET) as *mut u32, flags);
        ptr::addr_of_mut!((*extended).all).write(ContextChunk {
            offset: -(CONTEXT_SIZE as i32),
            length: (CONTEXT_SIZE + 24) as u32,
        });
        ptr::addr_of_mut!((*extended).legacy).write(ContextChunk {
            offset: -(CONTEXT_SIZE as i32),
            length: CONTEXT_SIZE as u32,
        });
        // Windows leaves the XState chunk absent with this characteristic offset.
        // Do not write the final eight reserved alignment bytes.
        ptr::addr_of_mut!((*extended).xstate).write(ContextChunk {
            offset: 25,
            length: 0,
        });
        ptr::write(context_ex, extended);
    }
    STATUS_SUCCESS
}

#[export_name = "RtlInitializeExtendedContext"]
pub unsafe extern "system" fn rtl_initialize_extended_context(
    context: *mut c_void,
    flags: u32,
    context_ex: *mut *mut ContextEx,
) -> u32 {
    unsafe { rtl_initialize_extended_context2(context, flags, context_ex, u64::MAX) }
}

#[export_name = "RtlGetExtendedFeaturesMask"]
pub unsafe extern "system" fn rtl_get_extended_features_mask(context_ex: *const ContextEx) -> u64 {
    if context_ex.is_null() || unsafe { (*context_ex).xstate.length } < 64 {
        return 0;
    }
    let offset = unsafe { (*context_ex).xstate.offset };
    let xstate = unsafe { (context_ex as *const u8).offset(offset as isize) };
    (unsafe { ptr::read_unaligned(xstate as *const u64) }) & !3
}

#[export_name = "RtlSetExtendedFeaturesMask"]
pub unsafe extern "system" fn rtl_set_extended_features_mask(
    context_ex: *mut ContextEx,
    mask: u64,
) {
    if context_ex.is_null() || unsafe { (*context_ex).xstate.length } < 64 {
        return;
    }
    let offset = unsafe { (*context_ex).xstate.offset };
    let xstate = unsafe { (context_ex as *mut u8).offset(offset as isize) };
    unsafe { ptr::write_unaligned(xstate as *mut u64, mask & enabled_features() & !3) };
}

#[export_name = "RtlLocateExtendedFeature"]
pub unsafe extern "system" fn rtl_locate_extended_feature(
    _context_ex: *const ContextEx,
    _feature_id: u32,
    length: *mut u32,
) -> *mut c_void {
    if !length.is_null() {
        unsafe { ptr::write(length, 0) };
    }
    ptr::null_mut()
}

// Start and flag for each contiguous register group in the Windows x64 CONTEXT.
// A group's end is the next entry's start. Offsets match Wine's tested ABI.
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

#[export_name = "RtlCopyExtendedContext"]
pub unsafe extern "system" fn rtl_copy_extended_context(
    destination: *mut ContextEx,
    flags: u32,
    source: *const ContextEx,
) -> u32 {
    if !valid_flags(flags) || destination.is_null() || source.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & CONTEXT_XSTATE != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    let dst = unsafe { (destination as *mut u8).offset((*destination).legacy.offset as isize) };
    let src = unsafe { (source as *const u8).offset((*source).legacy.offset as isize) };
    let dst_flags = unsafe { ptr::read(dst.add(FLAGS_OFFSET) as *const u32) };
    unsafe { ptr::write(dst.add(FLAGS_OFFSET) as *mut u32, dst_flags | flags) };
    for (index, &(start, flag)) in COPY_RANGES.iter().enumerate() {
        if flag != 0 && flags & flag != 0 {
            let end = COPY_RANGES[index + 1].0;
            unsafe { ptr::copy_nonoverlapping(src.add(start), dst.add(start), end - start) };
        }
    }
    STATUS_SUCCESS
}

#[used]
pub static EXTENDED_CONTEXT_EXPORT_ANCHOR_FN: unsafe extern "C" fn() =
    extended_context_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// This routine is only stored in a `#[used]` static.
pub unsafe extern "C" fn extended_context_export_anchor() {
    core::hint::black_box(rtl_get_extended_context_length2 as *const () as usize);
    core::hint::black_box(rtl_get_extended_context_length as *const () as usize);
    core::hint::black_box(rtl_initialize_extended_context2 as *const () as usize);
    core::hint::black_box(rtl_initialize_extended_context as *const () as usize);
    core::hint::black_box(rtl_get_extended_features_mask as *const () as usize);
    core::hint::black_box(rtl_set_extended_features_mask as *const () as usize);
    core::hint::black_box(rtl_locate_extended_feature as *const () as usize);
    core::hint::black_box(rtl_copy_extended_context as *const () as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_length_and_initialization_match_x64_layout() {
        let flags = CONTEXT_AMD64 | 0x0b;
        assert_eq!(requested_length(flags, 0), Ok(0x4f7));
        let mut buffer = [0xccu8; 0x500];
        let mut context_ex = ptr::null_mut();
        let status = unsafe {
            rtl_initialize_extended_context(buffer.as_mut_ptr().cast(), flags, &mut context_ex)
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(unsafe { (*context_ex).legacy.length }, 0x4d0);
        assert_eq!(unsafe { (*context_ex).all.length }, 0x4e8);
        assert_eq!(
            unsafe { (*context_ex).xstate },
            ContextChunk {
                offset: 25,
                length: 0
            }
        );
        assert_eq!(unsafe { ptr::read(context_ex.cast::<u8>().add(24)) }, 0xcc);
    }

    #[test]
    fn unsupported_xstate_does_not_change_output_length() {
        let mut length = 0xdead_beef;
        assert_eq!(
            unsafe { rtl_get_extended_context_length(CONTEXT_AMD64 | CONTEXT_XSTATE, &mut length) },
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(length, 0xdead_beef);
    }

    #[test]
    fn copy_uses_requested_context_register_groups() {
        let mut source = [0u8; 0x500];
        let mut destination = [0u8; 0x500];
        let mut source_ex = ptr::null_mut();
        let mut destination_ex = ptr::null_mut();
        let flags = CONTEXT_AMD64 | 0x03;
        assert_eq!(
            unsafe {
                rtl_initialize_extended_context(source.as_mut_ptr().cast(), flags, &mut source_ex)
            },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe {
                rtl_initialize_extended_context(
                    destination.as_mut_ptr().cast(),
                    CONTEXT_AMD64,
                    &mut destination_ex,
                )
            },
            STATUS_SUCCESS
        );
        let source_context =
            unsafe { (source_ex as *mut u8).offset((*source_ex).legacy.offset as isize) };
        let destination_context =
            unsafe { (destination_ex as *mut u8).offset((*destination_ex).legacy.offset as isize) };
        unsafe {
            ptr::write(source_context.add(0x38), 0x12);
            ptr::write(source_context.add(0x78), 0x34);
            ptr::write(source_context.add(0x48), 0x56);
        }
        assert_eq!(
            unsafe { rtl_copy_extended_context(destination_ex, flags, source_ex) },
            STATUS_SUCCESS
        );
        assert_eq!(unsafe { ptr::read(destination_context.add(0x38)) }, 0x12);
        assert_eq!(unsafe { ptr::read(destination_context.add(0x78)) }, 0x34);
        assert_eq!(unsafe { ptr::read(destination_context.add(0x48)) }, 0);
        assert_eq!(
            unsafe { ptr::read(destination_context.add(FLAGS_OFFSET) as *const u32) },
            flags
        );
    }
}
