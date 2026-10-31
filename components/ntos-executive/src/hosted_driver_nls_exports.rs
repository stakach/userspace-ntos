//! Native ANSI RTL imports for isolated hosted drivers.
//!
//! The storage host supplies the installed CP1252 image. The executive validates its actual byte
//! length and table shape before publishing a small descriptor in each driver's DATA frames. The
//! code-page frames must be aliased read-only into that driver's VSpace at `NLS_ANSI_VADDR` before
//! DriverEntry. A per-driver DATA descriptor avoids relying on executive statics being shared.

use core::ptr::{read_unaligned, read_volatile, write_unaligned};
use nt_compat_exports::DriverExportRegistry;
use nt_nls::ValidatedAnsiSbcs;

const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATE_MAGIC: u32 = u32::from_le_bytes(*b"ANLS");

/// Reserved in the first hosted-driver DATA page, after the loader ACPI identifier and before
/// HalPrivateDispatchTable. The launcher must assert the neighboring layout bounds when wiring
/// publication. The component uses the fixed DATA VA; the executive uses its instance alias.
pub(crate) const FSD_NLS_STATE_OFFSET: u64 = 0xA00;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlsState {
    magic: u32,
    ansi_size: u32,
}

pub(crate) const FSD_NLS_STATE_BYTES: u64 = core::mem::size_of::<NlsState>() as u64;

/// Validate the installed ANSI image and publish its size to one suspended driver's DATA frame.
///
/// `exec_data_va` is the executive-side alias for this particular driver. `ansi_size` must be the
/// actual byte count reported by the storage host, not the mapped frame capacity. Publication is
/// complete before that driver's TCB can run.
///
/// # Safety
/// The DATA alias and installed NLS frames must be mapped in the executive, and no producer may
/// mutate the NLS image after validation. The destination DATA range is owned by this driver.
pub(crate) unsafe fn publish_validated_page(exec_data_va: u64, ansi_size: usize) -> bool {
    if ansi_size == 0
        || ansi_size & 1 != 0
        || ansi_size as u64 > crate::NLS_ANSI_FRAMES * 0x1000
        || ansi_size > u32::MAX as usize
    {
        return false;
    }
    let words = unsafe {
        core::slice::from_raw_parts(crate::NLS_ANSI_VADDR as *const u16, ansi_size / 2)
    };
    if ValidatedAnsiSbcs::from_cp1252_words(words).is_none() {
        return false;
    }
    unsafe {
        write_unaligned(
            (exec_data_va + FSD_NLS_STATE_OFFSET) as *mut NlsState,
            NlsState {
                magic: STATE_MAGIC,
                ansi_size: ansi_size as u32,
            },
        );
    }
    true
}

/// Reconstruct a checked view from the descriptor in this driver's DATA frames. Rechecking the
/// table is constant-time and keeps raw code-page offsets out of the native ABI wrappers.
unsafe fn ansi_page() -> ValidatedAnsiSbcs<'static> {
    let state = unsafe {
        read_unaligned((crate::driver_launch::FSD_DATA_VADDR + FSD_NLS_STATE_OFFSET) as *const NlsState)
    };
    if state.magic != STATE_MAGIC
        || state.ansi_size == 0
        || state.ansi_size & 1 != 0
        || state.ansi_size as u64 > crate::NLS_ANSI_FRAMES * 0x1000
    {
        panic!("hosted driver ANSI page was not published");
    }
    let words = unsafe {
        core::slice::from_raw_parts(
            crate::NLS_ANSI_VADDR as *const u16,
            state.ansi_size as usize / 2,
        )
    };
    ValidatedAnsiSbcs::from_cp1252_words(words)
        .expect("hosted driver ANSI page changed after publication")
}

/// `WCHAR RtlAnsiCharToUnicodeChar(PUCHAR *SourceCharacter)`.
extern "win64" fn rtl_ansi_char_to_unicode_char(source_character: *mut u64) -> u16 {
    assert!(!source_character.is_null(), "RtlAnsiCharToUnicodeChar null source pointer");
    let source = unsafe { read_unaligned(source_character) };
    assert!(source != 0 && source != u64::MAX, "RtlAnsiCharToUnicodeChar invalid source");
    let ansi = unsafe { ansi_page() };
    let unit = ansi.ansi_char_to_unicode(unsafe { read_volatile(source as *const u8) });
    unsafe { write_unaligned(source_character, source + 1) };
    unit
}

/// `NTSTATUS RtlMultiByteToUnicodeN(PWCH, ULONG, PULONG, PCSTR, ULONG)`.
extern "win64" fn rtl_multibyte_to_unicode_n(
    destination: *mut u16,
    destination_capacity_bytes: u32,
    bytes_written: *mut u32,
    source: *const u8,
    source_bytes: u32,
) -> i32 {
    let units = source_bytes.min(destination_capacity_bytes / 2);
    if (units != 0 && (source.is_null() || destination.is_null()))
        || (source_bytes != 0 && source.is_null())
    {
        return STATUS_ACCESS_VIOLATION;
    }
    let ansi = unsafe { ansi_page() };
    // Raw sequential accesses match the native RTL and avoid forming overlapping Rust slices when
    // a caller supplies aliased source and destination ranges.
    for index in 0..units as usize {
        let byte = unsafe { read_volatile(source.wrapping_add(index)) };
        unsafe { write_unaligned(destination.wrapping_add(index), ansi.ansi_char_to_unicode(byte)) };
    }
    if !bytes_written.is_null() {
        unsafe { write_unaligned(bytes_written, units * 2) };
    }
    0
}

/// `NTSTATUS RtlMultiByteToUnicodeSize(PULONG, PCSTR, ULONG)`.
extern "win64" fn rtl_multibyte_to_unicode_size(
    output_bytes: *mut u32,
    source: *const u8,
    source_bytes: u32,
) -> i32 {
    if output_bytes.is_null() || (source_bytes != 0 && source.is_null()) {
        return STATUS_ACCESS_VIOLATION;
    }
    let ansi = unsafe { ansi_page() };
    let Some(size) = ansi.multibyte_to_unicode_size(source_bytes) else {
        return STATUS_INVALID_PARAMETER;
    };
    unsafe { write_unaligned(output_bytes, size) };
    0
}

/// `NTSTATUS RtlUnicodeToMultiByteSize(PULONG, PCWCH, ULONG)`.
extern "win64" fn rtl_unicode_to_multibyte_size(
    output_bytes: *mut u32,
    _source: *const u16,
    source_bytes: u32,
) -> i32 {
    if output_bytes.is_null() {
        return STATUS_ACCESS_VIOLATION;
    }
    let ansi = unsafe { ansi_page() };
    unsafe { write_unaligned(output_bytes, ansi.unicode_to_multibyte_size(source_bytes)) };
    0
}

pub(crate) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind("RtlAnsiCharToUnicodeChar", rtl_ansi_char_to_unicode_char as usize as u64);
    reg.bind("RtlMultiByteToUnicodeN", rtl_multibyte_to_unicode_n as usize as u64);
    reg.bind("RtlMultiByteToUnicodeSize", rtl_multibyte_to_unicode_size as usize as u64);
    reg.bind("RtlUnicodeToMultiByteSize", rtl_unicode_to_multibyte_size as usize as u64);
}
