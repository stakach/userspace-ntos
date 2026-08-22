//! Shared, driver-agnostic `ntoskrnl.exe` trampolines.
//!
//! These are the PURE, stateless import trampolines — no per-component arena or
//! per-class behavior — that every hosted `.sys` (FSD/npfs, Subsystem/win32k,
//! KMDF) needs identically. They live here ONCE, in the executive image, and are
//! registered by name into each driver class's [`DriverExportRegistry`]
//! ([`crate::driver_launch`]'s `FSD_EXPORTS`, [`crate::win32k_subsystem`]'s
//! `WIN32K_EXPORTS`). Because they run as executive `.text` mapped into each
//! component's isolated VSpace (RWX-shared code), a single definition resolves to
//! one VA reachable in every component.
//!
//! Only genuinely-pure primitives belong here. Trampolines with per-class state
//! (pool arenas bound to a component-specific VA, DbgPrint→serial forwarding,
//! the subtly-different Rtl string-init semantics on the win32k paint path) stay
//! in their owning module — moving them would change behavior, not share logic.
//! Where a pure primitive has real host-tested crate logic, the trampoline calls
//! it (`nt_compat_exports::rtl`): a trampoline that just calls real crate logic
//! is the convergence target from `feedback_implement_kernel_api_for_real.md`.

/// `void* memcpy(void* dst, const void* src, size_t n)` — byte copy.
/// Volatile byte-at-a-time (never elided/reordered); overlap not handled (use memmove).
pub extern "win64" fn s_memcpy(dst: u64, src: u64, n: u64) -> u64 {
    unsafe {
        let mut i = 0u64;
        while i < n {
            core::ptr::write_volatile(
                (dst + i) as *mut u8,
                core::ptr::read_volatile((src + i) as *const u8),
            );
            i += 1;
        }
    }
    dst
}

/// `void* memmove(void* dst, const void* src, size_t n)` — overlap-safe byte copy.
pub extern "win64" fn s_memmove(dst: u64, src: u64, n: u64) -> u64 {
    unsafe {
        if dst < src || dst >= src + n {
            let mut i = 0u64;
            while i < n {
                core::ptr::write_volatile(
                    (dst + i) as *mut u8,
                    core::ptr::read_volatile((src + i) as *const u8),
                );
                i += 1;
            }
        } else {
            let mut i = n;
            while i > 0 {
                i -= 1;
                core::ptr::write_volatile(
                    (dst + i) as *mut u8,
                    core::ptr::read_volatile((src + i) as *const u8),
                );
            }
        }
    }
    dst
}

/// `void* memset(void* dst, int c, size_t n)` — byte fill.
pub extern "win64" fn s_memset(dst: u64, c: u64, n: u64) -> u64 {
    unsafe {
        let b = c as u8;
        let mut i = 0u64;
        while i < n {
            core::ptr::write_volatile((dst + i) as *mut u8, b);
            i += 1;
        }
    }
    dst
}

/// `SIZE_T RtlCompareMemory(const void*, const void*, SIZE_T)` — count of leading equal bytes.
pub extern "win64" fn s_rtl_compare_memory(a: u64, b: u64, n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    if a == 0 || b == 0 {
        return 0;
    }
    // Real, host-tested slice logic in nt-compat-exports::rtl.
    unsafe {
        let sa = core::slice::from_raw_parts(a as *const u8, n as usize);
        let sb = core::slice::from_raw_parts(b as *const u8, n as usize);
        nt_compat_exports::rtl::compare_memory(sa, sb) as u64
    }
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const UNICODE_STRING_LENGTH: u64 = 0;
const UNICODE_STRING_MAXIMUM_LENGTH: u64 = 2;
const UNICODE_STRING_BUFFER: u64 = 8;

/// `NTSTATUS RtlIntegerToUnicodeString(ULONG, ULONG, PUNICODE_STRING)`.
pub extern "win64" fn s_rtl_integer_to_unicode_string(value: u32, base: u32, dst: u64) -> i32 {
    if dst == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let radix = if base == 0 { 10 } else { base };
    let mut units = [0u16; 32];
    let Some(unit_count) =
        nt_compat_exports::rtl::integer_to_unicode_into(value, radix, &mut units)
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let bytes = unit_count * 2;
    unsafe {
        let maximum = core::ptr::read_unaligned(
            (dst + UNICODE_STRING_MAXIMUM_LENGTH) as *const u16,
        ) as usize;
        let buffer = core::ptr::read_unaligned((dst + UNICODE_STRING_BUFFER) as *const u64);
        if bytes > maximum {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if buffer == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        for (index, unit) in units[..unit_count].iter().copied().enumerate() {
            core::ptr::write_unaligned((buffer + index as u64 * 2) as *mut u16, unit);
        }
        core::ptr::write_unaligned((dst + UNICODE_STRING_LENGTH) as *mut u16, bytes as u16);
        if bytes + 2 <= maximum {
            core::ptr::write_unaligned((buffer + bytes as u64) as *mut u16, 0);
        }
    }
    STATUS_SUCCESS
}

/// `NTSTATUS RtlUnicodeStringToInteger(PCUNICODE_STRING, ULONG, PULONG)`.
pub extern "win64" fn s_rtl_unicode_string_to_integer(src: u64, base: u32, out: u64) -> i32 {
    if src == 0 || out == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let bytes = core::ptr::read_unaligned((src + UNICODE_STRING_LENGTH) as *const u16) as usize;
        let buffer = core::ptr::read_unaligned((src + UNICODE_STRING_BUFFER) as *const u64);
        if bytes & 1 != 0 || (bytes != 0 && buffer == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        let units = if bytes == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(buffer as *const u16, bytes / 2)
        };
        let Some(value) = nt_compat_exports::rtl::unicode_string_to_integer(units, base) else {
            return STATUS_INVALID_PARAMETER;
        };
        core::ptr::write_unaligned(out as *mut u32, value);
    }
    STATUS_SUCCESS
}

/// `WCHAR RtlUpcaseUnicodeChar(WCHAR)`.
pub extern "win64" fn s_rtl_upcase_unicode_char(unit: u16) -> u16 {
    nt_compat_exports::rtl::upcase_char(unit)
}

/// `VOID RtlTimeToTimeFields(PLARGE_INTEGER, PTIME_FIELDS)`.
pub extern "win64" fn s_rtl_time_to_time_fields(time: *const i64, fields: *mut i16) {
    if time.is_null() || fields.is_null() {
        return;
    }
    let value = unsafe { core::ptr::read_unaligned(time) };
    let fields_value = nt_kernel_exec::rtl_time::time_to_time_fields(value);
    unsafe {
        for (index, value) in [
            fields_value.year,
            fields_value.month,
            fields_value.day,
            fields_value.hour,
            fields_value.minute,
            fields_value.second,
            fields_value.milliseconds,
            fields_value.weekday,
        ]
        .into_iter()
        .enumerate()
        {
            core::ptr::write_unaligned(fields.add(index), value);
        }
    }
}

/// `LARGE_INTEGER KeQueryPerformanceCounter(PLARGE_INTEGER Frequency)`.
pub extern "win64" fn s_ke_query_performance_counter(frequency: *mut u64) -> u64 {
    if !frequency.is_null() {
        unsafe { core::ptr::write_unaligned(frequency, 10_000_000) };
    }
    crate::monotonic_time_100ns()
}

/// `PSLIST_ENTRY ExpInterlockedPushEntrySList(PSLIST_HEADER, PSLIST_ENTRY)`.
pub extern "win64" fn s_exp_interlocked_push_entry_slist(head: *mut u8, entry: u64) -> u64 {
    unsafe { nt_kernel_exec::slist::push(head, entry) }
}

/// `PSLIST_ENTRY ExpInterlockedPopEntrySList(PSLIST_HEADER)`.
pub extern "win64" fn s_exp_interlocked_pop_entry_slist(head: *mut u8) -> u64 {
    unsafe { nt_kernel_exec::slist::pop(head) }
}

/// `USHORT ExQueryDepthSList(PSLIST_HEADER)`.
pub extern "win64" fn s_ex_query_depth_slist(head: *const u8) -> u16 {
    if head.is_null() {
        0
    } else {
        unsafe { nt_kernel_exec::slist::query_depth(head) }
    }
}

/// `size_t wcslen(const wchar_t*)` — NUL-terminated UTF-16 length (bounded).
pub extern "win64" fn s_wcslen(s: u64) -> u64 {
    if s == 0 {
        return 0;
    }
    let mut n = 0u64;
    unsafe {
        while core::ptr::read_unaligned((s + n * 2) as *const u16) != 0 && n < 32768 {
            n += 1;
        }
    }
    n
}

fn downcase_utf16(unit: u16) -> u16 {
    match unit {
        0x0041..=0x005A => unit + 0x20,
        0x00C0..=0x00D6 | 0x00D8..=0x00DE => unit + 0x20,
        _ => unit,
    }
}

/// `_wcsicmp(const wchar_t*, const wchar_t*)` — case-insensitive UTF-16 compare (bounded).
pub extern "win64" fn s_wcsicmp(left: u64, right: u64) -> i32 {
    let mut i = 0u64;
    unsafe {
        while i < 32768 {
            let a = if left == 0 {
                0
            } else {
                core::ptr::read_unaligned((left + i * 2) as *const u16)
            };
            let b = if right == 0 {
                0
            } else {
                core::ptr::read_unaligned((right + i * 2) as *const u16)
            };
            let fa = downcase_utf16(a);
            let fb = downcase_utf16(b);
            if fa != fb || a == 0 || b == 0 {
                return fa as i32 - fb as i32;
            }
            i += 1;
        }
    }
    0
}
