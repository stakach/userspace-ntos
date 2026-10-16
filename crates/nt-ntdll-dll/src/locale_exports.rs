//! Process UI language overrides and the native NLS locale-file mapping.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

const STATUS_SUCCESS: u32 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const MUI_LANGUAGE_ID: u32 = 0x0004;
const MUI_LANGUAGE_NAME: u32 = 0x0008;
const MAX_UI_LANGS: usize = 5; // Wine's maximum for one MULTI_SZ UI list.
const MAX_LOCALE_UNITS: usize = 85; // LOCALE_NAME_MAX_LENGTH.
const MAX_LIST_UNITS: usize = MAX_UI_LANGS * MAX_LOCALE_UNITS + 1;

struct LanguageList {
    format: u32,
    count: u32,
    len: usize,
    units: [u16; MAX_LIST_UNITS],
}

impl LanguageList {
    const fn empty() -> Self {
        Self {
            format: 0,
            count: 0,
            len: 2,
            units: [0; MAX_LIST_UNITS],
        }
    }
}

struct ProcessList {
    locked: AtomicBool,
    value: UnsafeCell<LanguageList>,
}

// SAFETY: every access to the UnsafeCell is protected by `locked`.
unsafe impl Sync for ProcessList {}

static PROCESS_LIST: ProcessList = ProcessList {
    locked: AtomicBool::new(false),
    value: UnsafeCell::new(LanguageList::empty()),
};

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct LocaleMapping {
    address: *mut u8,
    lcid: u32,
    size: i64,
}

#[cfg(target_arch = "x86_64")]
struct MappingCell {
    locked: AtomicBool,
    value: UnsafeCell<LocaleMapping>,
}

#[cfg(target_arch = "x86_64")]
unsafe impl Sync for MappingCell {}

#[cfg(target_arch = "x86_64")]
static LOCALE_MAPPING: MappingCell = MappingCell {
    locked: AtomicBool::new(false),
    value: UnsafeCell::new(LocaleMapping {
        address: core::ptr::null_mut(),
        lcid: 0,
        size: 0,
    }),
};

struct ProcessListGuard;

impl ProcessListGuard {
    fn lock() -> Self {
        while PROCESS_LIST
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }

    fn value(&mut self) -> &mut LanguageList {
        // SAFETY: this guard holds the unique spin lock until drop.
        unsafe { &mut *PROCESS_LIST.value.get() }
    }
}

impl Drop for ProcessListGuard {
    fn drop(&mut self) {
        PROCESS_LIST.locked.store(false, Ordering::Release);
    }
}

fn language_format(flags: u32) -> Result<u32, u32> {
    if flags & !(MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME) != 0
        || flags & (MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME) == MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME
    {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        let selected = flags & (MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME);
        Ok(if selected == 0 {
            MUI_LANGUAGE_NAME
        } else {
            selected
        })
    }
}

fn valid_language_unit(format: u32, unit: u16) -> bool {
    if format == MUI_LANGUAGE_ID {
        (b'0' as u16..=b'9' as u16).contains(&unit)
            || (b'A' as u16..=b'F' as u16).contains(&unit)
            || (b'a' as u16..=b'f' as u16).contains(&unit)
    } else {
        (b'0' as u16..=b'9' as u16).contains(&unit)
            || (b'A' as u16..=b'Z' as u16).contains(&unit)
            || (b'a' as u16..=b'z' as u16).contains(&unit)
            || unit == b'-' as u16
            || unit == b'_' as u16
    }
}

/// Capture the caller's entire multi-string before publication, with bounds on each name and on
/// the number of names. Keep the caller's spelling and order; no fabricated locale conversion.
unsafe fn capture_languages(format: u32, buffer: *const u16) -> Result<LanguageList, u32> {
    let mut list = LanguageList::empty();
    list.format = format;
    if buffer.is_null() || unsafe { *buffer } == 0 {
        return Ok(list);
    }
    let mut pos = 0usize;
    while (list.count as usize) < MAX_UI_LANGS {
        let start = pos;
        while pos - start < MAX_LOCALE_UNITS {
            let unit = unsafe { *buffer.add(pos) };
            if unit == 0 {
                break;
            }
            if !valid_language_unit(format, unit) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            list.units[pos] = unit;
            pos += 1;
        }
        if pos - start == MAX_LOCALE_UNITS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if format == MUI_LANGUAGE_ID && pos - start != 4 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if pos == start {
            return Err(STATUS_INVALID_PARAMETER);
        }
        list.count += 1;
        list.units[pos] = 0;
        pos += 1;
        if unsafe { *buffer.add(pos) } == 0 {
            list.units[pos] = 0;
            list.len = pos + 1;
            return Ok(list);
        }
    }
    Err(STATUS_INVALID_PARAMETER)
}

/// `RtlSetProcessPreferredUILanguages(DWORD, PCZZWSTR, PULONG) -> NTSTATUS`.
///
/// # Safety
/// `buffer`, when non-null, is a terminated UTF-16 multi-string. `count`, when non-null, is writable.
#[export_name = "RtlSetProcessPreferredUILanguages"]
pub unsafe extern "system" fn rtl_set_process_preferred_ui_languages(
    flags: u32,
    buffer: *const u16,
    count: *mut u32,
) -> u32 {
    let format = match language_format(flags) {
        Ok(format) => format,
        Err(status) => return status,
    };
    let list = match unsafe { capture_languages(format, buffer) } {
        Ok(list) => list,
        Err(status) => return status,
    };
    let installed_count = list.count;
    *ProcessListGuard::lock().value() = list;
    if !count.is_null() && installed_count != 0 {
        unsafe { *count = installed_count };
    }
    STATUS_SUCCESS
}

/// `RtlGetProcessPreferredUILanguages(DWORD, PULONG, PWSTR, PULONG) -> NTSTATUS`.
///
/// # Safety
/// `size` is writable; `count` is writable when non-null. `buffer`, when non-null, holds `*size`
/// UTF-16 units.
#[export_name = "RtlGetProcessPreferredUILanguages"]
pub unsafe extern "system" fn rtl_get_process_preferred_ui_languages(
    flags: u32,
    count: *mut u32,
    buffer: *mut u16,
    size: *mut u32,
) -> u32 {
    let format = match language_format(flags) {
        Ok(format) => format,
        Err(status) => return status,
    };
    if size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let capacity = unsafe { *size };
    if buffer.is_null() && capacity != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut guard = ProcessListGuard::lock();
    let list = guard.value();
    if list.format == 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    if list.count != 0 && format != list.format {
        return STATUS_NOT_IMPLEMENTED;
    }
    let required = list.len as u32;
    if !buffer.is_null() && capacity < required {
        unsafe { *size = required };
        return STATUS_BUFFER_TOO_SMALL;
    }
    if !buffer.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(list.units.as_ptr(), buffer, list.len) };
    }
    if !count.is_null() {
        unsafe { *count = list.count };
    }
    unsafe { *size = required };
    STATUS_SUCCESS
}

/// The pinned LiberNT ntdll spec declares this entry as a stub.
#[export_name = "RtlSetThreadPreferredUILanguages"]
pub extern "system" fn rtl_set_thread_preferred_ui_languages(
    _flags: u32,
    _buffer: *const u16,
    _count: *mut u32,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// `RtlGetLocaleFileMappingAddress(void **, LCID *, LARGE_INTEGER *) -> NTSTATUS`.
///
/// # Safety
/// All three output pointers are writable.
#[export_name = "RtlGetLocaleFileMappingAddress"]
pub unsafe extern "system" fn rtl_get_locale_file_mapping_address(
    address: *mut *mut u8,
    lcid: *mut u32,
    size: *mut i64,
) -> u32 {
    if address.is_null() || lcid.is_null() || size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // The ntdll wrapper opens and maps the installed locale file through ordinary native
    // file/section services. Preserve its exact status; callers index the returned table.
    #[cfg(target_arch = "x86_64")]
    {
        while LOCALE_MAPPING
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: this thread holds the unique mapping lock until the release store below.
        let mapping = unsafe { &mut *LOCALE_MAPPING.value.get() };
        let status = if mapping.address.is_null() {
            let mut candidate = LocaleMapping {
                address: core::ptr::null_mut(),
                lcid: 0,
                size: 0,
            };
            let status = unsafe {
                nt_ntdll::trap_stubs::nt_initialize_nls_files(
                    (&mut candidate.address as *mut *mut u8) as u64,
                    (&mut candidate.lcid as *mut u32) as u64,
                    (&mut candidate.size as *mut i64) as u64,
                ) as u32
            };
            if status == STATUS_SUCCESS && !candidate.address.is_null() {
                *mapping = candidate;
            }
            if status == STATUS_SUCCESS && candidate.address.is_null() {
                STATUS_UNSUCCESSFUL
            } else {
                status
            }
        } else {
            STATUS_SUCCESS
        };
        if status == STATUS_SUCCESS {
            unsafe {
                *address = mapping.address;
                *lcid = mapping.lcid;
                *size = mapping.size;
            }
        }
        LOCALE_MAPPING.locked.store(false, Ordering::Release);
        status
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        STATUS_NOT_IMPLEMENTED
    }
}

#[used]
pub static LOCALE_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = locale_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn locale_export_anchor() {
    core::hint::black_box(rtl_set_process_preferred_ui_languages as *const () as usize);
    core::hint::black_box(rtl_get_process_preferred_ui_languages as *const () as usize);
    core::hint::black_box(rtl_set_thread_preferred_ui_languages as *const () as usize);
    core::hint::black_box(rtl_get_locale_file_mapping_address as *const () as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_name_list_round_trips_and_bounds_are_reported() {
        let mut uninitialized_size = 0;
        assert_eq!(
            unsafe {
                rtl_get_process_preferred_ui_languages(
                    MUI_LANGUAGE_NAME,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut uninitialized_size,
                )
            },
            STATUS_NOT_IMPLEMENTED
        );
        let input = [
            b'f' as u16,
            b'r' as u16,
            b'-' as u16,
            b'F' as u16,
            b'R' as u16,
            0,
            b'd' as u16,
            b'e' as u16,
            b'-' as u16,
            b'D' as u16,
            b'E' as u16,
            0,
            0,
        ];
        let mut count = 0;
        assert_eq!(
            unsafe {
                rtl_set_process_preferred_ui_languages(
                    MUI_LANGUAGE_NAME,
                    input.as_ptr(),
                    &mut count,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(count, 2);
        let mut size = 1;
        let mut output = [0u16; 13];
        assert_eq!(
            unsafe {
                rtl_get_process_preferred_ui_languages(
                    MUI_LANGUAGE_NAME,
                    &mut count,
                    output.as_mut_ptr(),
                    &mut size,
                )
            },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(size, 13);
        assert_eq!(
            unsafe {
                rtl_get_process_preferred_ui_languages(
                    MUI_LANGUAGE_NAME,
                    &mut count,
                    output.as_mut_ptr(),
                    &mut size,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!((count, output), (2, input));
        assert_eq!(
            unsafe {
                rtl_get_process_preferred_ui_languages(
                    MUI_LANGUAGE_ID,
                    &mut count,
                    output.as_mut_ptr(),
                    &mut size,
                )
            },
            STATUS_NOT_IMPLEMENTED
        );
        let invalid = [b'@' as u16, 0, 0];
        assert_eq!(
            unsafe {
                rtl_set_process_preferred_ui_languages(
                    MUI_LANGUAGE_NAME,
                    invalid.as_ptr(),
                    core::ptr::null_mut(),
                )
            },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe {
                rtl_get_process_preferred_ui_languages(
                    MUI_LANGUAGE_NAME,
                    core::ptr::null_mut(),
                    output.as_mut_ptr(),
                    &mut size,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(output, input);
        assert_eq!(
            unsafe {
                rtl_set_process_preferred_ui_languages(
                    MUI_LANGUAGE_NAME,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                )
            },
            STATUS_SUCCESS
        );
        size = 0;
        assert_eq!(
            unsafe {
                rtl_get_process_preferred_ui_languages(
                    MUI_LANGUAGE_ID,
                    &mut count,
                    core::ptr::null_mut(),
                    &mut size,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!((count, size), (0, 2));
    }
}
