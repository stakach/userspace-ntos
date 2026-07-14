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
    // Real, host-tested slice logic in nt-compat-exports::rtl.
    unsafe {
        let sa = core::slice::from_raw_parts(a as *const u8, n as usize);
        let sb = core::slice::from_raw_parts(b as *const u8, n as usize);
        nt_compat_exports::rtl::compare_memory(sa, sb) as u64
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
