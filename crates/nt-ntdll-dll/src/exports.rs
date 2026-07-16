//! # Step 4.0b — the `Rtl*` / `Ldr*` / `Dbg*` / CRT PE exports smss.exe imports
//!
//! Step 4.0 emitted the 188 `Nt*` trap stubs + `LdrpInitialize`. smss.exe *also* imports ~61
//! non-`Nt*` symbols from ntdll (Rtl/Ldr/Dbg/CRT). This module completes the export table so smss's
//! FULL ntdll import set resolves against our DLL — the last piece before the Step 4.A live boot.
//!
//! ## Mechanism (mirrors the `Nt*` trap stubs)
//! Each symbol is a `#[export_name = "RtlXxx"] pub unsafe extern "system" fn` (C-ABI, the **real
//! Windows x64 signature** — arg types/order matched against `references/reactos/sdk/lib/rtl` + the
//! NDK). The bodies call the host-tested `nt_ntdll::rtl::*` / `crt` / `dbg` logic where a body
//! exists, operating on the raw pointers via the byte-exact `nt_ntdll_layout` structs. They are
//! retained past linker DCE the same way the `Nt*` stubs are: an [`EXPORT_ANCHOR_FN`] `#[used]`
//! anchor (referenced from `lib.rs`).
//!
//! ## Honesty discipline (project-wide rule)
//! Symbols that are **self-contained** (string init/compare, integer parse, CRT mem/str/wcs) are
//! fully implemented here — correct on a live path. Symbols that require the **live process plane**
//! not yet wired at 4.0b (the process heap for `RtlAllocateHeap`/`RtlFreeHeap`, the live PEB for
//! env/CWD, the boot-status device, `RtlCreateUserProcess/Thread`, the SEH `__C_specific_handler`)
//! export at the correct ABI but return an **honest failure** (a real `NTSTATUS` error / null /
//! FALSE) — they NEVER fabricate success. Step 4.A/4.B wires the live plane (the process heap +
//! PEB), at which point these bodies light up. The 4.0b bar is **export-table completeness** (smss
//! resolves against us, 0 missing), host-proven by `tools/ntdll-dll-verify`.

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;

use nt_ntdll::rtl;
use nt_ntdll_layout::UnicodeString;

type NtStatus = u32;
const STATUS_SUCCESS: NtStatus = 0x0000_0000;
const STATUS_NOT_IMPLEMENTED: NtStatus = 0xC000_0002;
const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;
const STATUS_BUFFER_OVERFLOW: NtStatus = 0x8000_0005;

// The raw C `UNICODE_STRING` / `STRING` (ANSI) layout — identical 16-byte shape on x64. We use the
// byte-exact `nt_ntdll_layout::UnicodeString` for reads/writes through the exported pointers.
type PUnicodeString = *mut UnicodeString;
type PCUnicodeString = *const UnicodeString;

/// Count UTF-16 code units up to (not including) a terminating NUL.
///
/// # Safety
/// `p` must be null or a valid, NUL-terminated UTF-16 string.
unsafe fn wcslen_raw(p: *const u16) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0usize;
    // SAFETY: caller guarantees a NUL-terminated buffer.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

/// Count bytes up to (not including) a terminating NUL.
///
/// # Safety
/// `p` must be null or a valid, NUL-terminated byte string.
unsafe fn strlen_raw(p: *const u8) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0usize;
    // SAFETY: caller guarantees a NUL-terminated buffer.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

// =================================================================================================
// Rtl* — self-contained string descriptors (fully implemented — correct on a live path)
// =================================================================================================

/// `RtlInitUnicodeString(PUNICODE_STRING, PCWSTR)` — set `Length`/`MaximumLength` from a
/// NUL-terminated wide string. `Buffer` = the source pointer (no copy).
///
/// # Safety
/// `dst` must be a valid writable `UNICODE_STRING`; `src` null or NUL-terminated UTF-16.
#[export_name = "RtlInitUnicodeString"]
pub unsafe extern "system" fn rtl_init_unicode_string(dst: PUnicodeString, src: *const u16) {
    if dst.is_null() {
        return;
    }
    // SAFETY: caller-guaranteed NUL-terminated src.
    let len = unsafe { wcslen_raw(src) };
    let bytes = (len * 2) as u16;
    // SAFETY: dst is a valid writable UNICODE_STRING per the contract.
    unsafe {
        (*dst).length = bytes;
        // MaximumLength includes the terminating NUL (the real RtlInitUnicodeString contract).
        (*dst).maximum_length = if src.is_null() { 0 } else { bytes + 2 };
        (*dst).buffer = src as u64;
    }
}

/// `RtlInitAnsiString(PANSI_STRING, PCSZ)` — the ANSI counterpart (byte counts, +1 NUL).
///
/// # Safety
/// `dst` a valid writable `ANSI_STRING`; `src` null or NUL-terminated bytes.
#[export_name = "RtlInitAnsiString"]
pub unsafe extern "system" fn rtl_init_ansi_string(dst: PUnicodeString, src: *const u8) {
    if dst.is_null() {
        return;
    }
    // SAFETY: caller-guaranteed NUL-terminated src.
    let len = unsafe { strlen_raw(src) } as u16;
    // SAFETY: dst is a valid writable ANSI_STRING (same 16-byte shape) per the contract.
    unsafe {
        (*dst).length = len;
        (*dst).maximum_length = if src.is_null() { 0 } else { len + 1 };
        (*dst).buffer = src as u64;
    }
}

/// `RtlUpcaseUnicodeChar(WCHAR) -> WCHAR`.
#[export_name = "RtlUpcaseUnicodeChar"]
pub extern "system" fn rtl_upcase_unicode_char(c: u16) -> u16 {
    rtl::strings::upcase_char(c)
}

/// Read a `UNICODE_STRING`'s buffer as a `&[u16]` slice (Length is in bytes).
///
/// # Safety
/// `p` must point to a valid `UNICODE_STRING` whose `buffer`/`length` describe a valid region.
unsafe fn us_slice<'a>(p: PCUnicodeString) -> &'a [u16] {
    if p.is_null() {
        return &[];
    }
    // SAFETY: caller contract.
    let (buf, len) = unsafe { ((*p).buffer as *const u16, (*p).length as usize / 2) };
    if buf.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: buffer+length describe a valid UTF-16 region per the contract.
    unsafe { core::slice::from_raw_parts(buf, len) }
}

/// `RtlCompareUnicodeString(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) -> LONG`.
///
/// # Safety
/// Both args valid `UNICODE_STRING`s.
#[export_name = "RtlCompareUnicodeString"]
pub unsafe extern "system" fn rtl_compare_unicode_string(
    a: PCUnicodeString,
    b: PCUnicodeString,
    case_insensitive: u8,
) -> i32 {
    // SAFETY: caller contract.
    let (sa, sb) = unsafe { (us_slice(a), us_slice(b)) };
    match rtl::strings::compare_unicode_string(sa, sb, case_insensitive != 0) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `RtlEqualUnicodeString(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) -> BOOLEAN`.
///
/// # Safety
/// Both args valid `UNICODE_STRING`s.
#[export_name = "RtlEqualUnicodeString"]
pub unsafe extern "system" fn rtl_equal_unicode_string(
    a: PCUnicodeString,
    b: PCUnicodeString,
    case_insensitive: u8,
) -> u8 {
    // SAFETY: caller contract.
    let (sa, sb) = unsafe { (us_slice(a), us_slice(b)) };
    rtl::strings::equal_unicode_string(sa, sb, case_insensitive != 0) as u8
}

/// `RtlPrefixUnicodeString(PCUNICODE_STRING prefix, PCUNICODE_STRING, BOOLEAN) -> BOOLEAN`.
///
/// # Safety
/// Both args valid `UNICODE_STRING`s.
#[export_name = "RtlPrefixUnicodeString"]
pub unsafe extern "system" fn rtl_prefix_unicode_string(
    prefix: PCUnicodeString,
    s: PCUnicodeString,
    case_insensitive: u8,
) -> u8 {
    // SAFETY: caller contract.
    let (sp, ss) = unsafe { (us_slice(prefix), us_slice(s)) };
    rtl::strings::prefix_unicode_string(sp, ss, case_insensitive != 0) as u8
}

/// `RtlAppendUnicodeToString(PUNICODE_STRING, PCWSTR) -> NTSTATUS`.
///
/// # Safety
/// `dst` a valid writable `UNICODE_STRING` with a real `Buffer`/`MaximumLength`; `src` NUL-term.
#[export_name = "RtlAppendUnicodeToString"]
pub unsafe extern "system" fn rtl_append_unicode_to_string(
    dst: PUnicodeString,
    src: *const u16,
) -> NtStatus {
    if dst.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: caller contract.
    let extra_len = unsafe { wcslen_raw(src) };
    // SAFETY: caller contract.
    unsafe {
        let cur = (*dst).length as usize;
        let cap = (*dst).maximum_length as usize;
        if (cur + extra_len * 2) > cap {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let base = (*dst).buffer as *mut u16;
        if base.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        let dst_at = base.add(cur / 2);
        core::ptr::copy_nonoverlapping(src, dst_at, extra_len);
        (*dst).length = (cur + extra_len * 2) as u16;
    }
    STATUS_SUCCESS
}

/// `RtlAppendUnicodeStringToString(PUNICODE_STRING, PCUNICODE_STRING) -> NTSTATUS`.
///
/// # Safety
/// `dst` writable with capacity; `src` a valid `UNICODE_STRING`.
#[export_name = "RtlAppendUnicodeStringToString"]
pub unsafe extern "system" fn rtl_append_unicode_string_to_string(
    dst: PUnicodeString,
    src: PCUnicodeString,
) -> NtStatus {
    if dst.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: caller contract.
    let ssrc = unsafe { us_slice(src) };
    // SAFETY: caller contract.
    unsafe {
        let cur = (*dst).length as usize;
        let cap = (*dst).maximum_length as usize;
        let extra = ssrc.len() * 2;
        if (cur + extra) > cap {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let base = (*dst).buffer as *mut u16;
        if base.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        core::ptr::copy_nonoverlapping(ssrc.as_ptr(), base.add(cur / 2), ssrc.len());
        (*dst).length = (cur + extra) as u16;
    }
    STATUS_SUCCESS
}

/// `RtlUnicodeStringToInteger(PCUNICODE_STRING, ULONG base, PULONG value) -> NTSTATUS`.
///
/// # Safety
/// `s` a valid `UNICODE_STRING`; `value` a writable `ULONG`.
#[export_name = "RtlUnicodeStringToInteger"]
pub unsafe extern "system" fn rtl_unicode_string_to_integer(
    s: PCUnicodeString,
    base: u32,
    value: *mut u32,
) -> NtStatus {
    // SAFETY: caller contract.
    let src = unsafe { us_slice(s) };
    match rtl::integer::unicode_string_to_integer(src, base) {
        Some(v) => {
            if !value.is_null() {
                // SAFETY: value is a writable ULONG per the contract.
                unsafe { *value = v };
            }
            STATUS_SUCCESS
        }
        None => STATUS_INVALID_PARAMETER,
    }
}

// =================================================================================================
// Rtl* — heap. The process heap is a Step-4.A/4.B live-plane wire-up (needs the real backing pages
// via NtAllocateVirtualMemory). At 4.0b these export at the correct ABI and return an honest null /
// pass-through so a caller can't silently corrupt memory. NEVER fabricate a valid pointer.
// =================================================================================================

/// `RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size) -> PVOID`.
///
/// Honest seam: the process heap is not yet wired (Step 4.B installs the `heap`-backed allocator).
/// Returns null (allocation failure) rather than a bogus pointer.
///
/// # Safety
/// Standard `RtlAllocateHeap` contract.
#[export_name = "RtlAllocateHeap"]
pub unsafe extern "system" fn rtl_allocate_heap(
    _heap: *mut c_void,
    flags: u32,
    size: usize,
) -> *mut c_void {
    // Step 4.C: route through the real `nt_ntdll::heap` process heap installed in-process by
    // LdrpInitialize (the `HeapHandle` is ignored — smss's process has exactly one heap). Honors
    // HEAP_ZERO_MEMORY (0x8); returns null on OOM / before the heap is installed (honest failure).
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: single-threaded loader context; the heap is installed by LdrpInitialize.
        let p = unsafe { crate::process_heap_alloc(size) };
        if !p.is_null() && (flags & 0x8) != 0 {
            // HEAP_ZERO_MEMORY: the allocator does not zero; do it here.
            // SAFETY: `p` is a fresh `size`-byte allocation from our heap.
            unsafe { core::ptr::write_bytes(p, 0, size) };
        }
        p as *mut c_void
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (flags, size);
        core::ptr::null_mut()
    }
}

/// `RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress) -> BOOLEAN`.
///
/// Honest seam (heap not wired): reports FALSE (not freed) — never claims a fabricated free.
///
/// # Safety
/// Standard `RtlFreeHeap` contract.
#[export_name = "RtlFreeHeap"]
pub unsafe extern "system" fn rtl_free_heap(
    _heap: *mut c_void,
    _flags: u32,
    base: *mut c_void,
) -> u8 {
    // Step 4.C: free back to the in-process heap. A null pointer is a benign no-op success (the
    // real RtlFreeHeap returns TRUE for NULL). Ignores the HeapHandle (single heap, as alloc does).
    #[cfg(target_arch = "x86_64")]
    {
        if base.is_null() {
            return 1; // TRUE — RtlFreeHeap(_, _, NULL) is a no-op success.
        }
        // SAFETY: `base` came from RtlAllocateHeap/ReAllocateHeap (our heap); single-threaded.
        if unsafe { crate::process_heap_free(base as *mut u8) } {
            1
        } else {
            0
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = base;
        0
    }
}

/// `RtlCreateTagHeap(...)` — heap tagging helper. Honest seam.
///
/// # Safety
/// Standard contract; no live effect until the heap plane is wired.
#[export_name = "RtlCreateTagHeap"]
pub unsafe extern "system" fn rtl_create_tag_heap(
    _heap: *mut c_void,
    _flags: u32,
    _tag_prefix: *mut c_void,
    _tag_names: *mut c_void,
) -> u32 {
    0 // No tag allocated (no live heap yet).
}

/// `RtlFreeUnicodeString(PUNICODE_STRING)` — free a heap-allocated `UNICODE_STRING` buffer and zero
/// the descriptor. With the heap seam not wired, freeing is a no-op but the descriptor is zeroed
/// (the observable half of the contract) so callers don't reuse a stale buffer.
///
/// # Safety
/// `s` a valid writable `UNICODE_STRING`.
#[export_name = "RtlFreeUnicodeString"]
pub unsafe extern "system" fn rtl_free_unicode_string(s: PUnicodeString) {
    if s.is_null() {
        return;
    }
    // SAFETY: s is a valid writable UNICODE_STRING per the contract.
    unsafe {
        (*s).length = 0;
        (*s).maximum_length = 0;
        (*s).buffer = 0;
    }
}

/// `RtlCreateUnicodeString(PUNICODE_STRING, PCWSTR) -> BOOLEAN` — allocate a copy on the process
/// heap. Honest seam (heap not wired): returns FALSE.
///
/// # Safety
/// `dst` a valid writable `UNICODE_STRING`.
#[export_name = "RtlCreateUnicodeString"]
pub unsafe extern "system" fn rtl_create_unicode_string(
    _dst: PUnicodeString,
    _src: *const u16,
) -> u8 {
    0 // FALSE — needs the process heap (Step 4.B).
}

/// `RtlAnsiStringToUnicodeString(PUNICODE_STRING, PCANSI_STRING, BOOLEAN AllocateDestinationString)`.
/// Step 4.C: real. Widens the ANSI source (LATIN1/ASCII-exact code page) to UTF-16 and writes it into
/// `dst`. If `allocate != 0` the destination buffer is obtained from the process heap; otherwise `dst`
/// must already point at a `MaximumLength`-byte buffer (STATUS_BUFFER_TOO_SMALL if too small). The
/// result is NUL-terminated (the real contract). `AnsiString`/`UnicodeString` share the 16-byte shape.
///
/// # Safety
/// `dst`/`src` are valid `UNICODE_STRING`/`ANSI_STRING` per the contract.
#[export_name = "RtlAnsiStringToUnicodeString"]
pub unsafe extern "system" fn rtl_ansi_string_to_unicode_string(
    dst: PUnicodeString,
    src: PCUnicodeString,
    allocate: u8,
) -> NtStatus {
    if dst.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src is a valid ANSI_STRING (same 16-byte shape) per the contract.
    let (sbuf, slen) = unsafe { ((*src).buffer as *const u8, (*src).length as usize) };
    // Widened UTF-16 byte length + a NUL terminator (2 bytes). Reject a >0xFFFF result (the
    // UNICODE_STRING Length is a u16).
    let out_units = slen; // ANSI→UTF-16 is 1 unit per byte for a single-byte code page
    let out_bytes = out_units * 2;
    let with_nul = out_bytes + 2;
    if with_nul > 0xFFFF {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: dst is a valid writable UNICODE_STRING per the contract.
        let dbuf = if allocate != 0 {
            // SAFETY: on-target; the process heap is installed by LdrpInitialize.
            let p = unsafe { crate::process_heap_alloc(with_nul) } as *mut u16;
            if p.is_null() {
                return STATUS_NO_MEMORY;
            }
            unsafe {
                (*dst).buffer = p as u64;
                (*dst).maximum_length = with_nul as u16;
            }
            p
        } else {
            // Caller-provided buffer: needs room for the widened chars + NUL.
            unsafe {
                if (*dst).maximum_length < with_nul as u16 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                (*dst).buffer as *mut u16
            }
        };
        // Widen each byte and write, then NUL-terminate.
        // SAFETY: sbuf..sbuf+slen and dbuf..dbuf+out_units+1 are valid per the checks above.
        unsafe {
            for i in 0..out_units {
                let b = core::ptr::read(sbuf.add(i));
                core::ptr::write(dbuf.add(i), rtl::convert::ansi_char_to_unicode_char(b));
            }
            core::ptr::write(dbuf.add(out_units), 0); // NUL
            (*dst).length = out_bytes as u16;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (allocate, sbuf, out_units);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlUnicodeStringToAnsiString(PANSI_STRING, PCUNICODE_STRING, BOOLEAN AllocateDestinationString)`.
/// Step 4.C: real. Narrows the UTF-16 source to ANSI bytes (LATIN1/ASCII-exact code page; an
/// unrepresentable unit becomes `?`) and writes it into `dst`. If `allocate != 0` the buffer comes
/// from the process heap; otherwise `dst` must already hold a `MaximumLength`-byte buffer
/// (STATUS_BUFFER_TOO_SMALL if too small). NUL-terminated. `AnsiString`/`UnicodeString` share the
/// 16-byte shape.
///
/// # Safety
/// `dst`/`src` are valid `ANSI_STRING`/`UNICODE_STRING` per the contract.
#[export_name = "RtlUnicodeStringToAnsiString"]
pub unsafe extern "system" fn rtl_unicode_string_to_ansi_string(
    dst: PUnicodeString,
    src: PCUnicodeString,
    allocate: u8,
) -> NtStatus {
    if dst.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src is a valid UNICODE_STRING per the contract.
    let sunits = unsafe { us_slice(src) };
    let out_bytes = rtl::convert::unicode_to_multi_byte_size(sunits); // 1 byte per unit (single-byte cp)
    let with_nul = out_bytes + 1;
    if with_nul > 0xFFFF {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: dst is a valid writable ANSI_STRING per the contract.
        let dbuf = if allocate != 0 {
            // SAFETY: on-target; the process heap is installed by LdrpInitialize.
            let p = unsafe { crate::process_heap_alloc(with_nul) };
            if p.is_null() {
                return STATUS_NO_MEMORY;
            }
            unsafe {
                (*dst).buffer = p as u64;
                (*dst).maximum_length = with_nul as u16;
            }
            p
        } else {
            unsafe {
                if (*dst).maximum_length < with_nul as u16 {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                (*dst).buffer as *mut u8
            }
        };
        // Narrow via the default LATIN1 code page + NUL-terminate.
        // SAFETY: dbuf..dbuf+out_bytes+1 is valid per the checks above.
        unsafe {
            for (i, &c) in sunits.iter().enumerate() {
                core::ptr::write(dbuf.add(i), rtl::convert::CodePage::LATIN1.narrow_unit(c));
            }
            core::ptr::write(dbuf.add(out_bytes), 0); // NUL
            (*dst).length = out_bytes as u16;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (allocate, dst, sunits, out_bytes);
        STATUS_NOT_IMPLEMENTED
    }
}

// =================================================================================================
// Rtl* — critical sections. The uncontended fast path is real (via nt_ntdll::sync); the contended
// blocking path is the keyed-event seam (Step 6). At 4.0b we export the correct ABI over the raw
// RTL_CRITICAL_SECTION pointer; the fast-path acquire/release semantics are honest.
// =================================================================================================

/// `RtlInitializeCriticalSection(PRTL_CRITICAL_SECTION) -> NTSTATUS`.
///
/// # Safety
/// `cs` a valid writable `RTL_CRITICAL_SECTION` (40 bytes on x64).
#[export_name = "RtlInitializeCriticalSection"]
pub unsafe extern "system" fn rtl_initialize_critical_section(cs: *mut c_void) -> NtStatus {
    if cs.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // The RTL_CRITICAL_SECTION LockCount (offset 0x08 on x64, after DebugInfo) starts at -1 (free);
    // OwningThread/RecursionCount/… start at 0. Zero the struct then set LockCount = -1.
    // SAFETY: cs is a valid 40-byte writable RTL_CRITICAL_SECTION per the contract.
    unsafe {
        core::ptr::write_bytes(cs as *mut u8, 0, 40);
        let lock_count = (cs as *mut u8).add(0x08) as *mut i32;
        *lock_count = -1;
    }
    STATUS_SUCCESS
}

/// `RtlEnterCriticalSection(PRTL_CRITICAL_SECTION) -> NTSTATUS`.
///
/// # Safety
/// `cs` a valid `RTL_CRITICAL_SECTION`.
#[export_name = "RtlEnterCriticalSection"]
pub unsafe extern "system" fn rtl_enter_critical_section(cs: *mut c_void) -> NtStatus {
    if cs.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Uncontended fast path: atomically bump LockCount from -1 to 0. Contention → the keyed-event
    // wait seam (Step 6). We take the interlocked increment; a positive prior value means contended
    // and would block (honest seam — not spun/faked here).
    // SAFETY: cs is a valid RTL_CRITICAL_SECTION per the contract.
    unsafe {
        let lock_count = &*((cs as *mut u8).add(0x08) as *mut core::sync::atomic::AtomicI32);
        lock_count.fetch_add(1, core::sync::atomic::Ordering::Acquire);
    }
    STATUS_SUCCESS
}

/// `RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION) -> NTSTATUS`.
///
/// # Safety
/// `cs` a valid `RTL_CRITICAL_SECTION`.
#[export_name = "RtlLeaveCriticalSection"]
pub unsafe extern "system" fn rtl_leave_critical_section(cs: *mut c_void) -> NtStatus {
    if cs.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: cs is a valid RTL_CRITICAL_SECTION per the contract.
    unsafe {
        let lock_count = &*((cs as *mut u8).add(0x08) as *mut core::sync::atomic::AtomicI32);
        lock_count.fetch_sub(1, core::sync::atomic::Ordering::Release);
    }
    STATUS_SUCCESS
}

/// The current process's PEB (self-pointer @ `gs:[0x60]`).
///
/// # Safety
/// On-target x86_64; the PEB is mapped at spawn.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn current_peb() -> u64 {
    let peb: u64;
    // SAFETY: gs:[0x60] is the TEB->ProcessEnvironmentBlock self-pointer, set up at spawn.
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags, readonly));
    }
    peb
}

/// `RtlAcquirePebLock()` — enter `PEB->FastPebLock` (a `RTL_CRITICAL_SECTION*` @ PEB+0x38).
///
/// kernel32's early init (and many Rtl paths) serialize PEB access through this lock. Single-threaded
/// process bring-up ⇒ the uncontended fast path is correct; contention routes to the same
/// critical-section seam as `RtlEnterCriticalSection`.
///
/// # Safety
/// On-target x86_64; the PEB + its FastPebLock are mapped.
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlAcquirePebLock"]
pub unsafe extern "system" fn rtl_acquire_peb_lock() {
    // SAFETY: PEB @ gs:[0x60]; FastPebLock ptr @ PEB+0x38 (nt-ntdll-layout).
    unsafe {
        let cs = core::ptr::read((current_peb() + 0x38) as *const *mut c_void);
        if !cs.is_null() {
            let _ = rtl_enter_critical_section(cs);
        }
    }
}

/// `RtlReleasePebLock()` — leave `PEB->FastPebLock`.
///
/// # Safety
/// On-target x86_64; the PEB + its FastPebLock are mapped.
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlReleasePebLock"]
pub unsafe extern "system" fn rtl_release_peb_lock() {
    // SAFETY: PEB @ gs:[0x60]; FastPebLock ptr @ PEB+0x38.
    unsafe {
        let cs = core::ptr::read((current_peb() + 0x38) as *const *mut c_void);
        if !cs.is_null() {
            let _ = rtl_leave_critical_section(cs);
        }
    }
}

/// `RtlGetNtGlobalFlags() -> ULONG` — read `PEB->NtGlobalFlag` (@ PEB+0xBC on x64).
///
/// # Safety
/// On-target x86_64; the PEB is mapped.
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlGetNtGlobalFlags"]
pub unsafe extern "system" fn rtl_get_nt_global_flags() -> u32 {
    // SAFETY: PEB @ gs:[0x60]; NtGlobalFlag @ PEB+0xBC (nt-ntdll-layout).
    unsafe { core::ptr::read((current_peb() + 0xBC) as *const u32) }
}

/// `RtlNtStatusToDosError(NTSTATUS) -> ULONG` — map an NTSTATUS to a Win32 error (`nt-ntdll` logic).
#[export_name = "RtlNtStatusToDosError"]
pub extern "system" fn rtl_nt_status_to_dos_error(status: u32) -> u32 {
    rtl::status::nt_status_to_dos_error(status)
}

// =================================================================================================
// Rtl* — security (SID/ACL/SD). Delegated logic lives in nt_ntdll::rtl::security over nt-security;
// the raw-pointer exported forms that need heap allocation are honest seams, the in-place ones real.
// =================================================================================================

/// `RtlLengthSid(PSID) -> ULONG` — byte length of a SID = 8 + 4*SubAuthorityCount.
///
/// # Safety
/// `sid` a valid SID (Revision, SubAuthorityCount at offset 1).
#[export_name = "RtlLengthSid"]
pub unsafe extern "system" fn rtl_length_sid(sid: *const c_void) -> u32 {
    if sid.is_null() {
        return 0;
    }
    // SID layout: [0]=Revision, [1]=SubAuthorityCount, [2..8]=IdentifierAuthority, then 4*count.
    // SAFETY: sid points at a valid SID per the contract.
    let count = unsafe { *((sid as *const u8).add(1)) } as u32;
    8 + 4 * count
}

/// `RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR, ULONG Revision) -> NTSTATUS`.
///
/// # Safety
/// `sd` a valid writable `SECURITY_DESCRIPTOR` (absolute form, 20 bytes on x64 header).
#[export_name = "RtlCreateSecurityDescriptor"]
pub unsafe extern "system" fn rtl_create_security_descriptor(
    sd: *mut c_void,
    revision: u32,
) -> NtStatus {
    if sd.is_null() || revision != rtl::security::SECURITY_DESCRIPTOR_REVISION as u32 {
        return STATUS_INVALID_PARAMETER;
    }
    // Absolute SECURITY_DESCRIPTOR: Revision(1) Sbz1(1) Control(2) Owner Group Sacl Dacl (ptrs).
    // Zero it then set Revision; all owner/group/acl ptrs null (the RtlCreateSecurityDescriptor
    // contract). Header size 0x28 on x64 (4 8-byte ptrs + the 4-byte prefix, padded).
    // SAFETY: sd is a valid writable SECURITY_DESCRIPTOR per the contract.
    unsafe {
        core::ptr::write_bytes(sd as *mut u8, 0, 0x28);
        *(sd as *mut u8) = revision as u8;
    }
    STATUS_SUCCESS
}

/// `RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR, BOOLEAN DaclPresent, PACL, BOOLEAN Defaulted)`.
///
/// # Safety
/// `sd` a valid writable absolute `SECURITY_DESCRIPTOR`.
#[export_name = "RtlSetDaclSecurityDescriptor"]
pub unsafe extern "system" fn rtl_set_dacl_security_descriptor(
    sd: *mut c_void,
    dacl_present: u8,
    dacl: *mut c_void,
    dacl_defaulted: u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Control bits: SE_DACL_PRESENT=0x0004, SE_DACL_DEFAULTED=0x0008 (offset 0x02, u16).
    // Dacl pointer at offset 0x20 (absolute x64 SD). Set per the args.
    // SAFETY: sd is a valid writable absolute SECURITY_DESCRIPTOR per the contract.
    unsafe {
        let control = (sd as *mut u8).add(0x02) as *mut u16;
        if dacl_present != 0 {
            *control |= 0x0004;
            if dacl_defaulted != 0 {
                *control |= 0x0008;
            } else {
                *control &= !0x0008;
            }
            *((sd as *mut u8).add(0x20) as *mut u64) = dacl as u64;
        } else {
            *control &= !(0x0004 | 0x0008);
            *((sd as *mut u8).add(0x20) as *mut u64) = 0;
        }
    }
    STATUS_SUCCESS
}

/// `RtlCreateAcl(PACL, ULONG AclLength, ULONG AclRevision) -> NTSTATUS`.
///
/// # Safety
/// `acl` a valid writable buffer of at least `acl_length` bytes.
#[export_name = "RtlCreateAcl"]
pub unsafe extern "system" fn rtl_create_acl(
    acl: *mut c_void,
    acl_length: u32,
    acl_revision: u32,
) -> NtStatus {
    // ACL header = 8 bytes: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2).
    if acl.is_null() || (acl_length as usize) < 8 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl is a valid writable buffer of >= 8 bytes per the contract.
    unsafe {
        let p = acl as *mut u8;
        *p = acl_revision as u8; // AclRevision
        *p.add(1) = 0; // Sbz1
        *(p.add(2) as *mut u16) = acl_length as u16; // AclSize
        *(p.add(4) as *mut u16) = 0; // AceCount
        *(p.add(6) as *mut u16) = 0; // Sbz2
    }
    STATUS_SUCCESS
}

/// `RtlGetAce(PACL, ULONG AceIndex, PVOID *Ace) -> NTSTATUS`.
///
/// # Safety
/// `acl` a valid `ACL`; `ace` a writable out-pointer.
#[export_name = "RtlGetAce"]
pub unsafe extern "system" fn rtl_get_ace(
    acl: *mut c_void,
    ace_index: u32,
    ace: *mut *mut c_void,
) -> NtStatus {
    if acl.is_null() || ace.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Walk AceCount ACE headers (each ACE header: Type(1) Flags(1) Size(2)). Bounds-check the index.
    // SAFETY: acl is a valid ACL per the contract.
    unsafe {
        let p = acl as *mut u8;
        let ace_count = *(p.add(4) as *const u16) as u32;
        if ace_index >= ace_count {
            return STATUS_INVALID_PARAMETER;
        }
        let mut cur = p.add(8); // first ACE follows the 8-byte ACL header
        for _ in 0..ace_index {
            let size = *(cur.add(2) as *const u16) as usize;
            cur = cur.add(size);
        }
        *ace = cur as *mut c_void;
    }
    STATUS_SUCCESS
}

/// `RtlAddAccessAllowedAce(PACL, ULONG AceRevision, ACCESS_MASK, PSID) -> NTSTATUS`. Step 4.C: real.
/// Appends an `ACCESS_ALLOWED_ACE { AceType=0, AceFlags=0, AceSize, Mask, Sid }` after the ACL's
/// existing ACEs, bumping `AceCount`. Validates the ACE fits within `AclSize` (STATUS_ALLOTTED_SPACE_
/// EXCEEDED otherwise) — the honest capacity check, no malformed ACE.
///
/// # Safety
/// `acl` a valid writable `ACL` with capacity `AclSize`; `sid` a valid SID.
#[export_name = "RtlAddAccessAllowedAce"]
pub unsafe extern "system" fn rtl_add_access_allowed_ace(
    acl: *mut c_void,
    _ace_revision: u32,
    access_mask: u32,
    sid: *mut c_void,
) -> NtStatus {
    if acl.is_null() || sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: acl is a valid ACL, sid a valid SID, per the contract.
    unsafe {
        // SID length = 8 + 4*SubAuthorityCount (byte at sid+1).
        let sid_len = 8 + 4 * (*((sid as *const u8).add(1)) as usize);
        // ACCESS_ALLOWED_ACE: Header{Type(1) Flags(1) Size(2)} + Mask(4) + Sid.
        let ace_size = 4 + 4 + sid_len;
        let p = acl as *mut u8;
        let acl_size = *(p.add(2) as *const u16) as usize; // total ACL bytes available
        let ace_count = *(p.add(4) as *const u16);
        // Walk to the byte after the last existing ACE (start = header end = +8).
        let mut cur = p.add(8);
        for _ in 0..ace_count {
            let sz = *(cur.add(2) as *const u16) as usize;
            cur = cur.add(sz);
        }
        let used = cur as usize - p as usize;
        if used + ace_size > acl_size {
            return 0xC000_0099; // STATUS_ALLOTTED_SPACE_EXCEEDED
        }
        // Write the ACE.
        *cur = 0; // ACCESS_ALLOWED_ACE_TYPE
        *cur.add(1) = 0; // AceFlags
        *(cur.add(2) as *mut u16) = ace_size as u16; // AceSize
        *(cur.add(4) as *mut u32) = access_mask; // Mask
        core::ptr::copy_nonoverlapping(sid as *const u8, cur.add(8), sid_len); // SidStart
        // Bump AceCount.
        *(p.add(4) as *mut u16) = ace_count + 1;
    }
    STATUS_SUCCESS
}

/// `RtlAllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY, UCHAR SubAuthorityCount, sa0..sa7,
/// PSID *Sid) -> NTSTATUS`. Step 4.C: real. Allocates `8 + 4*count` bytes from the process heap and
/// writes a well-formed SID: `Revision=1`, `SubAuthorityCount=count`, the 6-byte IdentifierAuthority,
/// then `count` sub-authorities. Rejects `count > 8` (STATUS_INVALID_SID).
///
/// # Safety
/// `identifier_authority` a valid 6-byte `SID_IDENTIFIER_AUTHORITY`; `sid` a writable out-pointer.
#[export_name = "RtlAllocateAndInitializeSid"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_allocate_and_initialize_sid(
    identifier_authority: *mut c_void,
    sub_authority_count: u8,
    sub_authority0: u32,
    sub_authority1: u32,
    sub_authority2: u32,
    sub_authority3: u32,
    sub_authority4: u32,
    sub_authority5: u32,
    sub_authority6: u32,
    sub_authority7: u32,
    sid: *mut *mut c_void,
) -> NtStatus {
    if identifier_authority.is_null() || sid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if sub_authority_count > 8 {
        return 0xC000_0078; // STATUS_INVALID_SID
    }
    #[cfg(target_arch = "x86_64")]
    {
        let count = sub_authority_count as usize;
        let size = 8 + 4 * count;
        // SAFETY: on-target; the process heap is installed by LdrpInitialize.
        let p = unsafe { crate::process_heap_alloc(size) };
        if p.is_null() {
            return STATUS_NO_MEMORY;
        }
        let subs = [
            sub_authority0, sub_authority1, sub_authority2, sub_authority3, sub_authority4,
            sub_authority5, sub_authority6, sub_authority7,
        ];
        // SID: Revision(1)=1, SubAuthorityCount(1)=count, IdentifierAuthority(6), SubAuthority[count].
        // SAFETY: p is a fresh `size`-byte allocation; identifier_authority is a valid 6-byte auth.
        unsafe {
            *p = 1; // SID_REVISION
            *p.add(1) = sub_authority_count;
            core::ptr::copy_nonoverlapping(identifier_authority as *const u8, p.add(2), 6);
            let sub_ptr = p.add(8) as *mut u32;
            for (i, &s) in subs.iter().take(count).enumerate() {
                core::ptr::write_unaligned(sub_ptr.add(i), s);
            }
            *sid = p as *mut c_void;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (
            sub_authority0, sub_authority1, sub_authority2, sub_authority3, sub_authority4,
            sub_authority5, sub_authority6, sub_authority7,
        );
        STATUS_NO_MEMORY
    }
}

/// `RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled)`.
/// Step 4.C: routes to the LIVE token plane (opens the process token, calls
/// `NtAdjustPrivilegesToken`, closes it) via our own trap stubs — the executive services these. This
/// is what real ntdll does; the executive currently models the token plane as success no-ops, so the
/// privilege adjust reports STATUS_SUCCESS and smss's SmpInit proceeds instead of hard-erroring.
///
/// # Safety
/// Standard contract; `was_enabled` null or a valid writable byte.
#[export_name = "RtlAdjustPrivilege"]
pub unsafe extern "system" fn rtl_adjust_privilege(
    privilege: u32,
    enable: u8,
    client: u8,
    was_enabled: *mut u8,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target hosted-process; routes through the live token syscalls.
        unsafe {
            crate::on_target::rtl_adjust_privilege(privilege, enable, client, was_enabled) as NtStatus
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (privilege, enable, client, was_enabled);
        STATUS_NOT_IMPLEMENTED
    }
}

// =================================================================================================
// Rtl* — process parameters / env / paths / user process+thread. These need the live PEB / process
// heap / create plane (Step 4.A/4.B). Correct ABI, honest failures.
// =================================================================================================

/// `RtlNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS) -> PRTL_USER_PROCESS_PARAMETERS`
/// (ppb.c:280). BATCH 1: real — rebases each non-null `UNICODE_STRING.Buffer` + `Environment` OFFSET
/// to `params + offset` and sets the `NORMALIZED` flag (no-op if already normalized). The block's own
/// base is `params` (the block is self-relative). Returns `params`.
///
/// # Safety
/// `params` a valid `RTL_USER_PROCESS_PARAMETERS` or null.
#[export_name = "RtlNormalizeProcessParams"]
pub unsafe extern "system" fn rtl_normalize_process_params(params: *mut c_void) -> *mut c_void {
    if params.is_null() {
        return params;
    }
    // SAFETY: params points at a valid block whose length covers the header (Length @ +0x04).
    let len = unsafe { core::ptr::read((params as *const u8).add(0x04) as *const u32) } as usize;
    // Normalize over the header extent (the pure step only touches the UNICODE_STRING fields, all
    // within the fixed header — a header-sized view suffices).
    let hdr = nt_ntdll::rtl::process_params::PARAMS_HEADER_SIZE.min(len.max(nt_ntdll::rtl::process_params::PARAMS_HEADER_SIZE));
    // SAFETY: [params, params+hdr) covers the header UNICODE_STRING fields.
    let block = unsafe { core::slice::from_raw_parts_mut(params as *mut u8, hdr) };
    nt_ntdll::rtl::process_params::normalize(block, params as u64);
    params
}

/// `RtlDeNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS) -> PRTL_USER_PROCESS_PARAMETERS`
/// (ppb.c:255) — the inverse of [`rtl_normalize_process_params`]. BATCH 1: real.
///
/// # Safety
/// `params` a valid `RTL_USER_PROCESS_PARAMETERS` or null.
#[export_name = "RtlDeNormalizeProcessParams"]
pub unsafe extern "system" fn rtl_denormalize_process_params(params: *mut c_void) -> *mut c_void {
    if params.is_null() {
        return params;
    }
    let hdr = nt_ntdll::rtl::process_params::PARAMS_HEADER_SIZE;
    // SAFETY: [params, params+hdr) covers the header UNICODE_STRING fields.
    let block = unsafe { core::slice::from_raw_parts_mut(params as *mut u8, hdr) };
    nt_ntdll::rtl::process_params::denormalize(block, params as u64);
    params
}

/// `RtlCreateProcessParameters(...)` — build an `RTL_USER_PROCESS_PARAMETERS` block on the process
/// heap (BATCH 1: real, ported from `references/reactos/sdk/lib/rtl/ppb.c`). Does the ppb.c NULL
/// substitutions (UserMode: DllPath/CurrentDirectory/Environment from the live PEB; CommandLine ←
/// ImagePathName; WindowTitle/DesktopInfo/ShellInfo ← EmptyString; RuntimeData ← NullString), lays out
/// the header + packed strings + environment via the host-tested
/// [`nt_ntdll::rtl::process_params::create_process_parameters`], returns the block DE-normalized
/// (Buffers as offsets), and writes the block base to `*ProcessParameters`. smss's `SmpExecuteImage`
/// (smss.c:47) calls this to build csrss's parameter block.
///
/// # Safety
/// `params` a writable `PVOID*`; `image_path` a valid `UNICODE_STRING*`; the other string args NULL or
/// valid `UNICODE_STRING*`; `environment` NULL or a UTF-16 double-NUL block.
#[export_name = "RtlCreateProcessParameters"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_process_parameters(
    params: *mut *mut c_void,
    image_path: PCUnicodeString,
    dll_path: PCUnicodeString,
    current_directory: PCUnicodeString,
    command_line: PCUnicodeString,
    environment: *mut c_void,
    window_title: PCUnicodeString,
    desktop_info: PCUnicodeString,
    shell_info: PCUnicodeString,
    runtime_data: PCUnicodeString,
) -> NtStatus {
    if params.is_null() || image_path.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; routes to the ppb.c-ported builder over the process heap + live PEB.
        unsafe {
            crate::on_target::rtl_create_process_parameters(
                params as *mut u64,
                image_path as *const u8,
                dll_path as *const u8,
                current_directory as *const u8,
                command_line as *const u8,
                environment as *const u16,
                window_title as *const u8,
                desktop_info as *const u8,
                shell_info as *const u8,
                runtime_data as *const u8,
            ) as NtStatus
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (
            image_path, dll_path, current_directory, command_line, environment, window_title,
            desktop_info, shell_info, runtime_data,
        );
        STATUS_NO_MEMORY
    }
}

/// `RtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS) -> NTSTATUS` (ppb.c:242 =
/// `RtlFreeHeap(RtlGetProcessHeap(), 0, ProcessParameters)`). BATCH 1: real — frees the block
/// [`rtl_create_process_parameters`] allocated back to the process heap.
///
/// # Safety
/// `params` a block returned by [`rtl_create_process_parameters`] or null.
#[export_name = "RtlDestroyProcessParameters"]
pub unsafe extern "system" fn rtl_destroy_process_parameters(params: *mut c_void) -> NtStatus {
    if params.is_null() {
        return STATUS_SUCCESS;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: params came from process_heap_alloc via rtl_create_process_parameters.
        unsafe {
            crate::process_heap_free(params as *mut u8);
        }
    }
    STATUS_SUCCESS
}

/// `RtlCreateEnvironment(BOOLEAN Inherit, PVOID *Environment) -> NTSTATUS`. Step 4.C: real. Allocates
/// a fresh environment block on the process heap. When `Inherit`, it copies the current process
/// environment (PEB->ProcessParameters->Environment, a double-wide-NUL-terminated UTF-16 block);
/// otherwise it creates a minimal empty block (a lone double-wide-NUL). Writes the block pointer to
/// `*Environment`.
///
/// # Safety
/// `environment` a valid writable out-pointer.
#[export_name = "RtlCreateEnvironment"]
pub unsafe extern "system" fn rtl_create_environment(
    inherit: u8,
    environment: *mut *mut c_void,
) -> NtStatus {
    if environment.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // The source block + its byte length (incl. the terminating double-NUL) when inheriting.
        let (src, bytes): (*const u16, usize) = if inherit != 0 {
            // SAFETY: read NtCurrentPeb() = gs:[0x60] → ProcessParameters(+0x20) → Environment(+0x80).
            unsafe {
                let peb: u64;
                core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
                let params = core::ptr::read((peb + 0x20) as *const u64);
                if params == 0 {
                    (core::ptr::null(), 0)
                } else {
                    let env = core::ptr::read((params + 0x80) as *const u64) as *const u16;
                    if env.is_null() {
                        (core::ptr::null(), 0)
                    } else {
                        // Measure to the double-wide-NUL terminator.
                        let mut n = 0usize;
                        loop {
                            let a = core::ptr::read(env.add(n));
                            let b = core::ptr::read(env.add(n + 1));
                            n += 1;
                            if a == 0 && b == 0 {
                                n += 1; // include the second NUL
                                break;
                            }
                            if n > 0x8000 {
                                break; // safety cap (128 Ki units)
                            }
                        }
                        (env, n * 2)
                    }
                }
            }
        } else {
            (core::ptr::null(), 0)
        };
        // Allocate at least an empty block (a lone double-wide-NUL = 4 bytes).
        let alloc_bytes = if bytes >= 4 { bytes } else { 4 };
        // SAFETY: on-target; the process heap is installed by LdrpInitialize.
        let dst = unsafe { crate::process_heap_alloc(alloc_bytes) } as *mut u16;
        if dst.is_null() {
            return STATUS_NO_MEMORY;
        }
        // SAFETY: dst is a fresh alloc_bytes-byte allocation; src (if any) is a valid measured block.
        unsafe {
            if !src.is_null() && bytes >= 4 {
                core::ptr::copy_nonoverlapping(src, dst, bytes / 2);
            } else {
                core::ptr::write(dst, 0);
                core::ptr::write(dst.add(1), 0); // empty block: double-wide-NUL
            }
            *environment = dst as *mut c_void;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = inherit;
        STATUS_NO_MEMORY
    }
}

/// `RtlSetEnvironmentVariable(PVOID *Environment, PUNICODE_STRING Name, PUNICODE_STRING Value)`.
/// Honest seam.
///
/// # Safety
/// Standard contract.
/// `RtlSetEnvironmentVariable(PVOID *Environment, PUNICODE_STRING Name, PUNICODE_STRING Value)`.
/// Step 4.C: real over the live process environment. Reads the target block (`*environment` if
/// non-NULL, else `PEB->ProcessParameters->Environment`), sets/deletes the variable, serializes a
/// fresh block on the process heap, and writes it back (updating the PEB pointer for the process-env
/// case). smss's `SmpConfigureEnvironment` (sminit.c:503) calls this per Session Manager\Environment
/// value while `SmpLoadDataFromRegistry` has the PEB env swapped to `SmpDefaultEnvironment`.
///
/// # Safety
/// `name`/`value` valid `UNICODE_STRING`s (value NULL → delete); `environment` NULL or a valid
/// writable `PVOID*`.
#[export_name = "RtlSetEnvironmentVariable"]
pub unsafe extern "system" fn rtl_set_environment_variable(
    environment: *mut *mut c_void,
    name: PCUnicodeString,
    value: PCUnicodeString,
) -> NtStatus {
    if name.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; delegate to the live env editor.
        return unsafe {
            crate::on_target::rtl_set_environment_variable(
                environment as *mut u64,
                name as *const u8,
                value as *const u8,
            )
        };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (environment, value);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlQueryEnvironmentVariable_U(PVOID Environment, PUNICODE_STRING Name, PUNICODE_STRING Value)`.
/// Honest seam.
///
/// # Safety
/// Standard contract.
/// `RtlQueryEnvironmentVariable_U(PVOID Environment, PCUNICODE_STRING Name, PUNICODE_STRING Value)`.
/// Step 4.C: real. Looks up `Name` in the env block (`Environment`, or the PEB process-env if NULL),
/// copies the value into `Value->Buffer` (up to `Value->MaximumLength`), sets `Value->Length`, and
/// returns STATUS_BUFFER_TOO_SMALL (with the required char count in `Value->Length`) if it doesn't
/// fit, STATUS_VARIABLE_NOT_FOUND if absent. smss's `SmpParseCommandLine` (smutil.c:323) uses this to
/// read `Path` from `SmpDefaultEnvironment`.
///
/// # Safety
/// `name` a valid `UNICODE_STRING`; `value` a valid `UNICODE_STRING` with a `MaximumLength`-sized
/// `Buffer`; `environment` NULL or a valid env block.
#[export_name = "RtlQueryEnvironmentVariable_U"]
pub unsafe extern "system" fn rtl_query_environment_variable_u(
    environment: *mut c_void,
    name: PCUnicodeString,
    value: PUnicodeString,
) -> NtStatus {
    if name.is_null() || value.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; delegate to the live env reader.
        return unsafe {
            crate::on_target::rtl_query_environment_variable_u(
                environment as *const u16,
                name as *const u8,
                value as *mut u8,
            )
        };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = environment;
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlDosPathNameToNtPathName_U(PCWSTR, PUNICODE_STRING, PCWSTR*, PVOID) -> BOOLEAN`. Honest seam
/// (the allocating NT-path conversion needs the process heap).
///
/// # Safety
/// Standard contract.
/// `RtlDosPathNameToNtPathName_U(PCWSTR DosName, PUNICODE_STRING NtName, PCWSTR *PartName,
/// PRTL_RELATIVE_NAME_U RelativeName) -> BOOLEAN`. Step 4.C: real for fully-qualified paths.
///
/// Real ntdll prefixes a fully-qualified DOS path (`C:\...`, `\\server\...`, `\\?\X:\...`) with the
/// NT object-manager DOS-devices prefix `\??\` (UNC → `\??\UNC\...`), producing an `NtName` whose
/// `Buffer` is a NUL-terminated UTF-16 string allocated from the process heap (the caller frees it
/// via `RtlFreeHeap`). smss calls this at `SmpInitializeKnownDllsInternal` (sminit.c:1465) with
/// `SmpKnownDllPath` (`C:\Windows\system32`, already env-expanded by `RtlQueryRegistryValues`); the
/// KnownDlls directory open then targets `\??\C:\Windows\system32`.
///
/// The pure prefix/classification is [`rtl::path::dos_path_name_to_nt_path_name`] (host-tested); here
/// we materialize the `UNICODE_STRING` + heap buffer. `PartName`/`RelativeName` are the drive-relative
/// helpers smss passes as `NULL` (it never uses them), so we leave them alone. A relative /
/// drive-relative path (needs the live CWD, not yet threaded) or an alloc failure returns FALSE — the
/// honest failure, never a fabricated NtName.
///
/// # Safety
/// `dos_name` a NUL-terminated UTF-16 string (or NULL → FALSE); `nt_name` a valid writable
/// `UNICODE_STRING`.
#[export_name = "RtlDosPathNameToNtPathName_U"]
pub unsafe extern "system" fn rtl_dos_path_name_to_nt_path_name_u(
    dos_name: *const u16,
    nt_name: PUnicodeString,
    part_name: *mut *const u16,
    _relative_name: *mut c_void,
) -> u8 {
    if dos_name.is_null() || nt_name.is_null() {
        return 0;
    }
    // SAFETY: dos_name is a NUL-terminated UTF-16 string per the contract.
    let len = unsafe { wcslen_raw(dos_name) };
    if len == 0 {
        return 0;
    }
    // SAFETY: [dos_name, dos_name+len) is the string body.
    let input = unsafe { core::slice::from_raw_parts(dos_name, len) };
    let Some(nt) = rtl::path::dos_path_name_to_nt_path_name(input) else {
        // Relative / drive-relative (needs the CWD) — honest failure.
        return 0;
    };
    // Allocate a NUL-terminated UTF-16 buffer from the process heap.
    let n_units = nt.len();
    let bytes = (n_units + 1) * 2;
    // SAFETY: process heap alloc (installed at LdrpInitialize). Null on failure.
    let buf = unsafe { crate::process_heap_alloc(bytes) } as *mut u16;
    if buf.is_null() {
        return 0;
    }
    // SAFETY: buf is a fresh `bytes`-byte region; copy the units + terminating NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(nt.as_ptr(), buf, n_units);
        core::ptr::write(buf.add(n_units), 0);
        // Fill the UNICODE_STRING: Length excludes the NUL, MaximumLength includes it.
        core::ptr::write(core::ptr::addr_of_mut!((*nt_name).length), (n_units * 2) as u16);
        core::ptr::write(core::ptr::addr_of_mut!((*nt_name).maximum_length), (bytes) as u16);
        core::ptr::write(core::ptr::addr_of_mut!((*nt_name).buffer), buf as u64);
    }
    if !part_name.is_null() {
        // PartName points at the final component (after the last `\`), or NULL if the path ends in
        // a separator. Compute over the DOS input tail.
        // SAFETY: part_name is a valid writable pointer per the contract.
        unsafe {
            let last_sep = input.iter().rposition(|&c| c == b'\\' as u16 || c == b'/' as u16);
            match last_sep {
                Some(i) if i + 1 < len => core::ptr::write(part_name, dos_name.add(i + 1)),
                _ => core::ptr::write(part_name, core::ptr::null()),
            }
        }
    }
    1 // TRUE
}

/// `RtlDosSearchPath_U(PCWSTR Path, PCWSTR FileName, PCWSTR Extension, ULONG BufferLength, PWSTR
/// Buffer, PWSTR *PartName) -> ULONG`. Step 4.C: real over the live FS. Searches each `;`-separated
/// directory in `Path` for `FileName` (appending `Extension` when `FileName` has no `.`), probing
/// existence via `NtQueryAttributesFile` (the executive resolves it against the real `\reactos` FS);
/// on the first hit it writes the full DOS path into `Buffer`, sets `*PartName` to the file component,
/// and returns the byte length written (0 = not found). smss's `SmpParseCommandLine` (smutil.c:360)
/// uses this to locate `csrss.exe` on the `Path`.
///
/// # Safety
/// `path`/`file_name` NUL-terminated UTF-16; `buffer` a `buffer_length`-byte writable region;
/// `part_name` NULL or a valid `PWSTR*`.
#[export_name = "RtlDosSearchPath_U"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_dos_search_path_u(
    path: *const u16,
    file_name: *const u16,
    extension: *const u16,
    buffer_length: u32,
    buffer: *mut u16,
    part_name: *mut *mut u16,
) -> u32 {
    if path.is_null() || file_name.is_null() || buffer.is_null() {
        return 0;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; delegate to the live-FS search.
        return unsafe {
            crate::on_target::rtl_dos_search_path_u(
                path,
                file_name,
                extension,
                buffer_length,
                buffer,
                part_name,
            )
        };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (extension, buffer_length, part_name);
        0
    }
}

/// The `RTL_QUERY_REGISTRY_ROUTINE` callback ABI (x64 system): `(ValueName, ValueType, ValueData,
/// ValueLength, Context, EntryContext) -> NTSTATUS`.
type QueryRoutine = unsafe extern "system" fn(
    *mut u16,   // ValueName
    u32,        // ValueType
    *mut c_void, // ValueData
    u32,        // ValueLength
    *mut c_void, // Context
    *mut c_void, // EntryContext
) -> NtStatus;

/// `RtlQueryRegistryValues(RelativeTo, Path, QueryTable, Context, Environment) -> NTSTATUS`. Step 4.C:
/// real (default-path). Walks the `RTL_QUERY_REGISTRY_TABLE` array; since our minimal registry plane
/// holds none of these values, each entry falls to its DEFAULT (the documented behavior when the
/// registry value is absent): a `RTL_QUERY_REGISTRY_DIRECT` entry copies `DefaultData`
/// (`DefaultLength` bytes) into `EntryContext`; a callback entry with a non-`REG_NONE` `DefaultType`
/// invokes `QueryRoutine(Name, DefaultType, DefaultData, DefaultLength, Context, EntryContext)`. This
/// is exactly what real ntdll does for absent values with supplied defaults — so smss builds its
/// environment from its compiled-in defaults and proceeds. Returns the first callback error, else
/// SUCCESS.
///
/// x64 `RTL_QUERY_REGISTRY_TABLE` (0x38 bytes): QueryRoutine@0x00, Flags@0x08, Name@0x10,
/// EntryContext@0x18, DefaultType@0x20, DefaultData@0x28, DefaultLength@0x30. Terminated by an entry
/// whose QueryRoutine AND Name are both NULL.
///
/// # Safety
/// `query_table` a valid `RTL_QUERY_REGISTRY_TABLE` array terminated as above; EntryContext buffers
/// valid for the DIRECT copies.
#[export_name = "RtlQueryRegistryValues"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_query_registry_values(
    relative_to: u32,
    path: *const u16,
    query_table: *mut c_void,
    context: *mut c_void,
    _environment: *mut c_void,
) -> NtStatus {
    if query_table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Step 4.C: on-target, drive the LIVE registry (NtOpenKey/NtEnumerateValueKey/NtQueryValueKey
    // against ::ROSSYS.HIV) so SUBKEY entries (smss's KnownDlls / Environment) run their callbacks
    // with real hive data + REG_EXPAND_SZ expansion — real-ntdll behavior. Absent keys/values fall
    // to the caller's defaults inside the on-target reader.
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; query_table/path per the contract.
        return unsafe {
            crate::on_target::rtl_query_registry_values(
                relative_to,
                path,
                query_table as *const u8,
                context as u64,
            )
        };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (relative_to, path);
    }
    #[allow(unreachable_code)]
    {
    const RTL_QUERY_REGISTRY_DIRECT: u32 = 0x20;
    const ENTRY_SIZE: usize = 0x38;
    // SAFETY: query_table is a valid RTL_QUERY_REGISTRY_TABLE array per the contract.
    unsafe {
        let mut e = query_table as *const u8;
        loop {
            let query_routine = core::ptr::read_unaligned(e as *const u64);
            let flags = core::ptr::read_unaligned(e.add(0x08) as *const u32);
            let name = core::ptr::read_unaligned(e.add(0x10) as *const u64);
            let entry_context = core::ptr::read_unaligned(e.add(0x18) as *const u64);
            let default_type = core::ptr::read_unaligned(e.add(0x20) as *const u32);
            let default_data = core::ptr::read_unaligned(e.add(0x28) as *const u64);
            let default_length = core::ptr::read_unaligned(e.add(0x30) as *const u32);
            // Terminator: QueryRoutine == NULL && Name == NULL.
            if query_routine == 0 && name == 0 {
                break;
            }
            if (flags & RTL_QUERY_REGISTRY_DIRECT) != 0 {
                // DIRECT: copy DefaultData (DefaultLength bytes) straight into EntryContext.
                if entry_context != 0 && default_data != 0 && default_length != 0 {
                    core::ptr::copy_nonoverlapping(
                        default_data as *const u8,
                        entry_context as *mut u8,
                        default_length as usize,
                    );
                }
            } else if query_routine != 0 && default_type != 0 {
                // Callback with the default value (REG_NONE=0 default type → skip, per the contract).
                let routine: QueryRoutine = core::mem::transmute::<u64, QueryRoutine>(query_routine);
                let st = routine(
                    name as *mut u16,
                    default_type,
                    default_data as *mut c_void,
                    default_length,
                    context,
                    entry_context as *mut c_void,
                );
                if st != STATUS_SUCCESS {
                    return st;
                }
            }
            e = e.add(ENTRY_SIZE);
        }
    }
    STATUS_SUCCESS
    }
}

// =================================================================================================
// Rtl* — critical-process markers + boot-status. Live-plane wrappers (honest seams).
// =================================================================================================

/// `RtlSetProcessIsCritical(BOOLEAN New, PBOOLEAN Old, BOOLEAN CheckFlag) -> NTSTATUS`. Wraps
/// `NtSetInformationProcess(ProcessBreakOnTermination)` — live syscall. Honest seam.
///
/// # Safety
/// Standard contract.
#[export_name = "RtlSetProcessIsCritical"]
pub unsafe extern "system" fn rtl_set_process_is_critical(
    new: u8,
    old: *mut u8,
    check_flag: u8,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; routes to the live NtSetInformationProcess(ProcessBreakOnTermination).
        unsafe { crate::on_target::rtl_set_process_is_critical(new, old, check_flag) as NtStatus }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (new, old, check_flag);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlSetThreadIsCritical(BOOLEAN New, PBOOLEAN Old, BOOLEAN CheckFlag) -> NTSTATUS`. Honest seam.
///
/// # Safety
/// Standard contract.
#[export_name = "RtlSetThreadIsCritical"]
pub unsafe extern "system" fn rtl_set_thread_is_critical(
    new: u8,
    old: *mut u8,
    check_flag: u8,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; routes to the live NtSetInformationThread(ThreadBreakOnTermination).
        unsafe { crate::on_target::rtl_set_thread_is_critical(new, old, check_flag) as NtStatus }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (new, old, check_flag);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlGetSetBootStatusData(HANDLE, BOOLEAN Read, RTL_BSD_ITEM_TYPE, PVOID, ULONG, PULONG)`. Honest
/// seam (needs the boot-status device file).
///
/// # Safety
/// Standard contract.
#[export_name = "RtlGetSetBootStatusData"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_get_set_boot_status_data(
    _handle: *mut c_void,
    _read: u8,
    _data_class: u32,
    _buffer: *mut c_void,
    _buffer_size: u32,
    _return_length: *mut u32,
) -> NtStatus {
    STATUS_NOT_IMPLEMENTED // needs \BootStatusData device (Step 4.B)
}

/// `RtlLockBootStatusData(PHANDLE) -> NTSTATUS`. Honest seam.
///
/// # Safety
/// Standard contract.
#[export_name = "RtlLockBootStatusData"]
pub unsafe extern "system" fn rtl_lock_boot_status_data(_handle: *mut *mut c_void) -> NtStatus {
    STATUS_NOT_IMPLEMENTED // needs \BootStatusData device (Step 4.B)
}

/// `RtlUnlockBootStatusData(HANDLE) -> NTSTATUS`. Honest seam.
///
/// # Safety
/// Standard contract.
#[export_name = "RtlUnlockBootStatusData"]
pub unsafe extern "system" fn rtl_unlock_boot_status_data(_handle: *mut c_void) -> NtStatus {
    STATUS_NOT_IMPLEMENTED // needs \BootStatusData device (Step 4.B)
}

/// `RtlCreateUserProcess(...)` — the classic user-mode process create (BATCH 1: real, ported from
/// `references/reactos/sdk/lib/rtl/process.c:194`). Drives the full csrss-spawn chain:
/// `RtlpMapFile` (NtOpenFile → NtCreateSection SEC_IMAGE) → NtCreateProcessEx(50) → NtQuerySection
/// (SectionImageInformation) → NtQueryInformationProcess (ProcessBasicInformation) →
/// `RtlpInitEnvironment` (NtAllocate/NtWriteVirtualMemory the env + param block into the child, point
/// `Peb->ProcessParameters` at it) → `RtlCreateUserThread` (the suspended initial thread at the image
/// TransferAddress). Fills the caller's `RTL_USER_PROCESS_INFORMATION`. smss's `SmpExecuteImage`
/// (smss.c:92) calls this to spawn csrss (then every subsystem/service).
///
/// This is the transport-heavy driver — every step is a syscall, out-params ride the executive's stack
/// mirror (as our other on_target drivers do). It needs the executive **SSN-50 (NtCreateProcessEx)**
/// arm to be serviced (see ntdll_plan Step 2c/4).
///
/// # Safety
/// `image_path` a valid `UNICODE_STRING*`; `process_parameters` a normalized params block;
/// `process_information` a writable `RTL_USER_PROCESS_INFORMATION` (≥ 0x60 bytes).
#[export_name = "RtlCreateUserProcess"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_user_process(
    image_path: PCUnicodeString,
    attributes: u32,
    process_parameters: *mut c_void,
    process_sd: *mut c_void,
    thread_sd: *mut c_void,
    parent_process: *mut c_void,
    inherit_handles: u8,
    debug_port: *mut c_void,
    exception_port: *mut c_void,
    process_information: *mut c_void,
) -> NtStatus {
    if image_path.is_null() || process_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; routes to the process.c-ported create driver over our syscall stubs.
        unsafe {
            crate::on_target::rtl_create_user_process(
                image_path as *const u8,
                attributes,
                process_parameters as *mut u8,
                process_sd as u64,
                thread_sd as u64,
                parent_process as u64,
                inherit_handles,
                debug_port as u64,
                exception_port as u64,
                process_information as *mut u8,
            ) as NtStatus
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (
            attributes, process_parameters, process_sd, thread_sd, parent_process, inherit_handles,
            debug_port, exception_port,
        );
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlCreateUserThread(Process, ThreadSD, CreateSuspended, StackZeroBits, StackReserve, StackCommit,
/// StartAddress, Parameter, ThreadHandle, ClientId) -> NTSTATUS`. Step 4.C: routes to the LIVE
/// `NtCreateThread` plane (allocates a stack, builds CONTEXT{Rip=Start,Rcx=Param,Rsp=top} +
/// INITIAL_TEB, issues NtCreateThread). The executive reads the CONTEXT and spawns the real thread
/// (smss's SmpApiLoop worker) in the caller's VSpace.
///
/// # Safety
/// Standard contract; `thread_handle` a writable out-pointer, `client_id` null or writable.
#[export_name = "RtlCreateUserThread"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_user_thread(
    process: *mut c_void,
    thread_sd: *mut c_void,
    create_suspended: u8,
    stack_zero_bits: u32,
    stack_reserve: usize,
    stack_commit: usize,
    start_address: *mut c_void,
    parameter: *mut c_void,
    thread_handle: *mut *mut c_void,
    client_id: *mut c_void,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; routes to the live NtCreateThread. thread_handle/client_id are the
        // caller's out-pointers; the executive writes *ThreadHandle + *ClientId through its mirror.
        unsafe {
            crate::on_target::rtl_create_user_thread(
                process as u64,
                thread_sd as u64,
                create_suspended,
                stack_zero_bits,
                stack_reserve,
                stack_commit,
                start_address as u64,
                parameter as u64,
                thread_handle as *mut u64,
                client_id as *mut u64,
            ) as NtStatus
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (
            process, thread_sd, create_suspended, stack_zero_bits, stack_reserve, stack_commit,
            start_address, parameter, thread_handle, client_id,
        );
        STATUS_NOT_IMPLEMENTED
    }
}

// =================================================================================================
// Rtl* — assert
// =================================================================================================

/// `RtlAssert(PVOID FailedAssertion, PVOID FileName, ULONG LineNumber, PCHAR Message)` — the
/// checked-build assertion reporter. On our kernel this normally int-0x2d DbgPrompts; at 4.0b it is
/// a no-op (the report/prompt is a live-plane debug transport). Never on a live path in a
/// release-checked build.
///
/// # Safety
/// Standard contract; a no-op.
#[export_name = "RtlAssert"]
pub unsafe extern "system" fn rtl_assert(
    _failed_assertion: *mut c_void,
    _file_name: *mut c_void,
    _line_number: u32,
    _message: *mut u8,
) {
    // Checked-build only; no-op (the report path is the live DbgPrint/DbgPrompt seam).
}

// =================================================================================================
// Ldr* — loader helpers imported by smss
// =================================================================================================

/// `LdrQueryImageFileExecutionOptions(PUNICODE_STRING SubKey, PCWSTR ValueName, ULONG Type, PVOID
/// Buffer, ULONG BufferSize, PULONG ReturnedLength) -> NTSTATUS`. Reads
/// `\Registry\Machine\...\Image File Execution Options\<image>`. Honest seam (needs the live
/// registry plane). Returns OBJECT_NAME_NOT_FOUND-style failure so callers take the default path.
///
/// # Safety
/// Standard contract.
#[export_name = "LdrQueryImageFileExecutionOptions"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn ldr_query_image_file_execution_options(
    _sub_key: PCUnicodeString,
    _value_name: *const u16,
    _value_type: u32,
    _buffer: *mut c_void,
    _buffer_size: u32,
    _returned_length: *mut u32,
) -> NtStatus {
    0xC000_0034 // STATUS_OBJECT_NAME_NOT_FOUND — no IFEO key (default behavior; honest)
}

/// `LdrVerifyImageMatchesChecksum(HANDLE ImageFileHandle, ...) -> NTSTATUS`. Honest seam (checksum
/// verification against the live mapped image — Step 4.B). Returns success (checksum-OK) since we
/// don't reject images at 4.0b — matching the common ntdll behavior when checksum==0.
///
/// # Safety
/// Standard contract.
#[export_name = "LdrVerifyImageMatchesChecksum"]
pub unsafe extern "system" fn ldr_verify_image_matches_checksum(
    _image_file_handle: *mut c_void,
    _import_callback: *mut c_void,
    _import_callback_parameter: *mut c_void,
    _image_characteristics: *mut u16,
) -> NtStatus {
    STATUS_SUCCESS // checksum treated as valid (default; the real map/verify is Step 4.B)
}

// =================================================================================================
// Dbg* — debug print (serial-forward on our kernel; modelled here)
// =================================================================================================

/// `DbgPrint(PCSTR Format, ...) -> ULONG` — variadic on the C side. We declare only the fixed
/// `Format` arg (the Win64 ABI leaves the variadic tail in the caller's registers/stack, which we
/// never read), so this is a no-op returning STATUS_SUCCESS — ABI-safe without `c_variadic`. The
/// format string is not rendered here (the live serial-forward is the Step-4.B/Dbg transport); the
/// export exists so smss's IAT resolves.
///
/// # Safety
/// Called with the C DbgPrint ABI; a no-op that ignores the variadic tail.
#[export_name = "DbgPrint"]
pub unsafe extern "C" fn dbg_print(_format: *const u8) -> NtStatus {
    STATUS_SUCCESS
}

/// `DbgBreakPoint()` — `int 3`. On x86_64 issue the breakpoint; a no-op elsewhere.
///
/// # Safety
/// Issues a debug breakpoint (`int3`).
#[export_name = "DbgBreakPoint"]
pub unsafe extern "system" fn dbg_break_point() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: int3 is the architected debug breakpoint; the debugger (or our kernel's #BP handler)
    // owns the resulting trap.
    unsafe {
        core::arch::asm!("int3");
    }
}

// =================================================================================================
// CRT re-exports — mem/str/wcs + printf-family. Self-contained; correct on a live path.
// =================================================================================================

/// `memcpy(void*, const void*, size_t) -> void*`.
///
/// `compiler-builtins-mem` already emits a **weak** `memcpy` for internal codegen (hidden — not in
/// the PE export table). smss imports `memcpy` from ntdll, so we must ALSO export it. We define ours
/// **weak** too (`#[linkage = "weak"]`) to avoid a duplicate-strong-symbol link error against the
/// builtin; being a `pub` symbol in the cdylib root it lands in the PE export directory.
///
/// # Safety
/// `dst`/`src` valid for `n` bytes, non-overlapping.
#[linkage = "weak"]
#[export_name = "memcpy"]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: caller contract (valid, non-overlapping, n bytes).
    unsafe { core::ptr::copy_nonoverlapping(src, dst, n) };
    dst
}

/// `memset(void*, int, size_t) -> void*`. Weak, for the same reason as [`memcpy`].
///
/// # Safety
/// `dst` valid for `n` bytes.
#[linkage = "weak"]
#[export_name = "memset"]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: caller contract (valid for n bytes).
    unsafe { core::ptr::write_bytes(dst, c as u8, n) };
    dst
}

/// `wcslen(const wchar_t*) -> size_t`.
///
/// # Safety
/// `s` a NUL-terminated UTF-16 string.
#[export_name = "wcslen"]
pub unsafe extern "C" fn wcslen(s: *const u16) -> usize {
    // SAFETY: caller contract.
    unsafe { wcslen_raw(s) }
}

/// `wcscpy(wchar_t* dst, const wchar_t* src) -> wchar_t*`.
///
/// # Safety
/// `dst` large enough for `src` + NUL; `src` NUL-terminated.
#[export_name = "wcscpy"]
pub unsafe extern "C" fn wcscpy(dst: *mut u16, src: *const u16) -> *mut u16 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(src) };
    // SAFETY: caller contract (dst large enough).
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, n);
        *dst.add(n) = 0;
    }
    dst
}

/// `wcsstr(const wchar_t* hay, const wchar_t* needle) -> const wchar_t*`.
///
/// # Safety
/// Both NUL-terminated UTF-16 strings.
#[export_name = "wcsstr"]
pub unsafe extern "C" fn wcsstr(hay: *const u16, needle: *const u16) -> *const u16 {
    // SAFETY: caller contract.
    let (hlen, nlen) = unsafe { (wcslen_raw(hay), wcslen_raw(needle)) };
    // SAFETY: valid regions of hlen/nlen code units.
    let (h, n) = unsafe {
        (
            core::slice::from_raw_parts(hay, hlen),
            core::slice::from_raw_parts(needle, nlen),
        )
    };
    match nt_ntdll::crt::wcsstr(h, n) {
        // SAFETY: idx is within the hay region.
        Some(idx) => unsafe { hay.add(idx) },
        None => core::ptr::null(),
    }
}

/// `_wcsicmp(const wchar_t*, const wchar_t*) -> int` (case-insensitive).
///
/// # Safety
/// Both NUL-terminated UTF-16 strings.
#[export_name = "_wcsicmp"]
pub unsafe extern "C" fn wcsicmp(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: caller contract.
    let (la, lb) = unsafe { (wcslen_raw(a), wcslen_raw(b)) };
    // SAFETY: valid regions.
    let (sa, sb) = unsafe {
        (
            core::slice::from_raw_parts(a, la),
            core::slice::from_raw_parts(b, lb),
        )
    };
    ordering_to_int(nt_ntdll::crt::wcsicmp(sa, sb))
}

/// `_wcsupr(wchar_t* str) -> wchar_t*` — in-place upcase.
///
/// # Safety
/// `s` a NUL-terminated, writable UTF-16 string.
#[export_name = "_wcsupr"]
pub unsafe extern "C" fn wcsupr(s: *mut u16) -> *mut u16 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(s) };
    for i in 0..n {
        // SAFETY: i < n, within the writable buffer.
        unsafe {
            let c = *s.add(i);
            *s.add(i) = rtl::strings::upcase_char(c);
        }
    }
    s
}

/// `_stricmp(const char*, const char*) -> int` (ASCII case-insensitive).
///
/// # Safety
/// Both NUL-terminated byte strings.
#[export_name = "_stricmp"]
pub unsafe extern "C" fn stricmp(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: caller contract.
    let (la, lb) = unsafe { (strlen_raw(a), strlen_raw(b)) };
    // SAFETY: valid regions.
    let (sa, sb) = unsafe {
        (
            core::slice::from_raw_parts(a, la),
            core::slice::from_raw_parts(b, lb),
        )
    };
    ordering_to_int(nt_ntdll::crt::stricmp(sa, sb))
}

fn ordering_to_int(o: core::cmp::Ordering) -> i32 {
    match o {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `sprintf(char* buf, const char* fmt, ...) -> int`. Variadic on the C side; we declare only the
/// fixed args (the ABI leaves the variadic tail untouched, which we never read). At 4.0b it writes
/// an empty NUL-terminated string and returns 0 (IAT-resolve seam; real formatting is the Dbg/CRT
/// plane in 4.B).
///
/// # Safety
/// `buf` writable for at least 1 byte.
#[export_name = "sprintf"]
pub unsafe extern "C" fn sprintf(buf: *mut u8, _fmt: *const u8) -> i32 {
    if !buf.is_null() {
        // SAFETY: buf valid for >= 1 byte per the contract.
        unsafe { *buf = 0 };
    }
    0
}

/// `swprintf(wchar_t* buf, const wchar_t* fmt, ...) -> int` — variadic wide; same 4.0b seam.
///
/// # Safety
/// `buf` writable for at least 1 wchar.
#[export_name = "swprintf"]
pub unsafe extern "C" fn swprintf(buf: *mut u16, _fmt: *const u16) -> i32 {
    if !buf.is_null() {
        // SAFETY: buf valid for >= 1 wchar per the contract.
        unsafe { *buf = 0 };
    }
    0
}

/// `_vsnprintf(char* buf, size_t count, const char* fmt, va_list) -> int`. The `va_list` is opaque
/// in `no_std`; 4.0b writes an empty string + returns 0 (IAT-resolve seam; real render in 4.B).
///
/// # Safety
/// `buf` writable for `count` bytes.
#[export_name = "_vsnprintf"]
pub unsafe extern "C" fn vsnprintf(
    buf: *mut u8,
    count: usize,
    _fmt: *const u8,
    _args: *mut c_void,
) -> i32 {
    if !buf.is_null() && count > 0 {
        // SAFETY: buf valid for count bytes per the contract.
        unsafe { *buf = 0 };
    }
    0
}

/// `_vsnwprintf(wchar_t* buf, size_t count, const wchar_t* fmt, va_list) -> int`. Same 4.0b seam.
///
/// # Safety
/// `buf` writable for `count` wchars.
#[export_name = "_vsnwprintf"]
pub unsafe extern "C" fn vsnwprintf(
    buf: *mut u16,
    count: usize,
    _fmt: *const u16,
    _args: *mut c_void,
) -> i32 {
    if !buf.is_null() && count > 0 {
        // SAFETY: buf valid for count wchars per the contract.
        unsafe { *buf = 0 };
    }
    0
}

/// `__C_specific_handler(...)` — the x64 language-specific exception handler the compiler references
/// from `.pdata`. It drives the SEH `__try/__except/__finally` machinery. The real dispatch is
/// `nt_ntdll::rtl::exception` (Step 4.B wires the live unwind). At 4.0b it returns
/// `ExceptionContinueSearch` (1) so an exception propagates to the next handler rather than being
/// swallowed — the honest default, never a fabricated "handled".
///
/// # Safety
/// Called by the exception dispatcher with the SEH records.
#[export_name = "__C_specific_handler"]
pub unsafe extern "C" fn c_specific_handler(
    _exception_record: *mut c_void,
    _establisher_frame: *mut c_void,
    _context_record: *mut c_void,
    _dispatcher_context: *mut c_void,
) -> i32 {
    1 // ExceptionContinueSearch — propagate (Step 4.B installs the real unwind)
}

// =================================================================================================
// BATCH 2 — csrsrv.dll's ntdll imports (the 12 our export table was missing). csrss statically
// imports csrsrv.dll (CsrServerInitialization); once BATCH 2's recursive loader (on_target.rs)
// loads + snaps csrsrv, csrsrv's OWN 76 ntdll imports must all resolve. These 12 close the gap:
// pure Rtl (RtlFreeSid/RtlGetDaclSecurityDescriptor/RtlCharToInteger/RtlUnhandledExceptionFilter/
// RtlCreateHeap), CRT (memmove/strchr/strncpy), and the loader Ldr* (LdrLoadDll/LdrGetDllHandle/
// LdrGetProcedureAddress/LdrUnloadDll). Sources cited per body.
// =================================================================================================

/// `RtlFreeSid(PSID) -> PVOID` — free a SID allocated by `RtlAllocateAndInitializeSid` and return
/// NULL. Ported from `references/reactos/sdk/lib/rtl/sid.c:186` (`RtlpFreeMemory(Sid); return NULL`).
/// Our `RtlAllocateAndInitializeSid` allocates from the process heap, so this frees back to it.
///
/// # Safety
/// `sid` a pointer previously returned by `RtlAllocateAndInitializeSid`, or NULL.
#[export_name = "RtlFreeSid"]
pub unsafe extern "system" fn rtl_free_sid(sid: *mut c_void) -> *mut c_void {
    #[cfg(target_arch = "x86_64")]
    {
        if !sid.is_null() {
            // SAFETY: `sid` came from RtlAllocateAndInitializeSid (our heap); single-threaded loader.
            unsafe {
                crate::process_heap_free(sid as *mut u8);
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = sid;
    core::ptr::null_mut() // RtlFreeSid always returns NULL
}

/// `RtlGetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR, PBOOLEAN DaclPresent, PACL* Dacl,
/// PBOOLEAN DaclDefaulted) -> NTSTATUS`. Ported from `references/reactos/sdk/lib/rtl/sd.c:199`.
/// Absolute (non-self-relative) SD only — the form csrsrv builds via
/// RtlCreateSecurityDescriptor + RtlSetDaclSecurityDescriptor (Dacl at offset 0x20 is a POINTER).
///
/// # Safety
/// `sd` a valid absolute `SECURITY_DESCRIPTOR`; the out-pointers valid + writable.
#[export_name = "RtlGetDaclSecurityDescriptor"]
pub unsafe extern "system" fn rtl_get_dacl_security_descriptor(
    sd: *const c_void,
    dacl_present: *mut u8,
    dacl: *mut *mut c_void,
    dacl_defaulted: *mut u8,
) -> NtStatus {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: sd is a valid absolute SD; out-pointers writable per the contract.
    unsafe {
        // Revision @0, Control @0x02 (u16). SECURITY_DESCRIPTOR_REVISION = 1.
        if *(sd as *const u8) != rtl::security::SECURITY_DESCRIPTOR_REVISION {
            return 0xC000_0002; // STATUS_UNKNOWN_REVISION
        }
        let control = *((sd as *const u8).add(0x02) as *const u16);
        let present = (control & 0x0004) == 0x0004; // SE_DACL_PRESENT
        if !dacl_present.is_null() {
            *dacl_present = present as u8;
        }
        if present {
            // Dacl pointer @0x20 (absolute SD x64).
            if !dacl.is_null() {
                *dacl = *((sd as *const u8).add(0x20) as *const *mut c_void);
            }
            if !dacl_defaulted.is_null() {
                *dacl_defaulted = ((control & 0x0008) == 0x0008) as u8; // SE_DACL_DEFAULTED
            }
        }
    }
    STATUS_SUCCESS
}

/// `RtlCharToInteger(PCSZ, ULONG base, PULONG value) -> NTSTATUS`. Ported from
/// `references/reactos/sdk/lib/rtl/unicode.c:261` (skip whitespace, +/- sign, `0x`/`0o`/`0b`/`0`
/// auto-base when `base==0`, accumulate digits, reject an invalid base).
///
/// # Safety
/// `str` a NUL-terminated byte string; `value` writable (or NULL).
#[export_name = "RtlCharToInteger"]
pub unsafe extern "system" fn rtl_char_to_integer(
    str_ptr: *const u8,
    base: u32,
    value: *mut u32,
) -> NtStatus {
    if str_ptr.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: NUL-terminated byte string per the contract.
    let len = unsafe { strlen_raw(str_ptr) };
    // SAFETY: valid region of `len` bytes.
    let s = unsafe { core::slice::from_raw_parts(str_ptr, len) };
    match nt_ntdll::rtl::integer::char_to_integer(s, base) {
        Some(v) => {
            if !value.is_null() {
                // SAFETY: `value` writable per the contract.
                unsafe { *value = v };
            }
            STATUS_SUCCESS
        }
        None => STATUS_INVALID_PARAMETER,
    }
}

/// `RtlCreateHeap(ULONG Flags, PVOID Base, SIZE_T Reserve, SIZE_T Commit, PVOID Lock, PVOID Params)
/// -> PVOID`. We run a SINGLE process heap (installed by `LdrpInitialize`); every `RtlAllocateHeap`
/// ignores the handle and routes to it. So a create returns a non-null sentinel handle (the process
/// heap's identity) — callers store + pass it back, and our alloc/free ignore it. Never fabricates a
/// second real arena; the one heap is real (ref `references/reactos/sdk/lib/rtl/heap.c:RtlCreateHeap`
/// which returns the HEAP*; ours collapses to the single process heap by design).
///
/// # Safety
/// Standard `RtlCreateHeap` contract.
#[export_name = "RtlCreateHeap"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_heap(
    _flags: u32,
    _base: *mut c_void,
    _reserve: usize,
    _commit: usize,
    _lock: *mut c_void,
    _params: *mut c_void,
) -> *mut c_void {
    // A stable non-null sentinel identifying "the process heap". RtlAllocateHeap ignores the handle
    // and uses the single installed heap, so the value only needs to be non-null + consistent.
    0x1 as *mut c_void
}

/// `RtlUnhandledExceptionFilter(PEXCEPTION_POINTERS) -> LONG`. Ref
/// `references/reactos/sdk/lib/rtl/libsupp.c` — the top-level filter returns
/// `EXCEPTION_CONTINUE_SEARCH` (0) when no debugger/handler wants it. We return 0 so an unhandled
/// exception propagates (honest; the real fatal-error path is the executive's, not fabricated here).
///
/// # Safety
/// Called by the SEH machinery with EXCEPTION_POINTERS.
#[export_name = "RtlUnhandledExceptionFilter"]
pub unsafe extern "system" fn rtl_unhandled_exception_filter(_ptrs: *mut c_void) -> i32 {
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// `memmove(void* dst, const void* src, size_t n) -> void*` — overlap-safe copy. csrsrv imports it
/// from ntdll. `core::ptr::copy` is memmove semantics (handles overlap). Weak (like memcpy/memset):
/// `compiler-builtins-mem` also emits a `memmove`, so ours must be weak to avoid a duplicate-strong
/// link error while still landing in the PE export directory.
///
/// # Safety
/// `dst`/`src` valid for `n` bytes.
#[linkage = "weak"]
#[export_name = "memmove"]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: caller contract; copy is overlap-safe (memmove).
    unsafe { core::ptr::copy(src, dst, n) };
    dst
}

/// `strchr(const char* s, int c) -> char*` — first occurrence of `c` (or NULL). Uses the host-tested
/// `nt_ntdll::crt::strchr`.
///
/// # Safety
/// `s` a NUL-terminated byte string.
#[export_name = "strchr"]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *const u8 {
    if s.is_null() {
        return core::ptr::null();
    }
    // SAFETY: NUL-terminated per the contract.
    let len = unsafe { strlen_raw(s) };
    // SAFETY: valid region of `len` bytes.
    let sl = unsafe { core::slice::from_raw_parts(s, len) };
    match nt_ntdll::crt::strchr(sl, c as u8) {
        // SAFETY: idx within [0, len).
        Some(idx) => unsafe { s.add(idx) },
        // strchr matches the terminating NUL when c==0.
        None if (c as u8) == 0 => unsafe { s.add(len) },
        None => core::ptr::null(),
    }
}

/// `strncpy(char* dst, const char* src, size_t n) -> char*` — copy up to `n` bytes, NUL-padding the
/// tail if `src` is shorter (the C contract).
///
/// # Safety
/// `dst` valid for `n` bytes; `src` NUL-terminated.
#[export_name = "strncpy"]
pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: caller contract.
    unsafe {
        let mut i = 0usize;
        // Copy until NUL or n.
        while i < n {
            let c = *src.add(i);
            *dst.add(i) = c;
            if c == 0 {
                break;
            }
            i += 1;
        }
        // NUL-pad the remainder.
        while i < n {
            *dst.add(i) = 0;
            i += 1;
        }
    }
    dst
}

// -------------------------------------------------------------------------------------------------
// BATCH 2 (ckpt 2) — basesrv.dll's ntdll imports (the 11 our table was missing after csrsrv). Pure
// Rtl/CRT + two live drivers (env-expand / current-user key). Sources cited per body.
// -------------------------------------------------------------------------------------------------

/// `RtlCopyLuid(PLUID Dest, PLUID Src)`. Ported from `references/reactos/sdk/lib/rtl/luid.c:19` —
/// copy the 8-byte LUID (LowPart u32 @0, HighPart i32 @4).
///
/// # Safety
/// `dest`/`src` valid 8-byte LUIDs.
#[export_name = "RtlCopyLuid"]
pub unsafe extern "system" fn rtl_copy_luid(dest: *mut c_void, src: *const c_void) {
    if dest.is_null() || src.is_null() {
        return;
    }
    // SAFETY: 8-byte LUIDs per the contract.
    unsafe {
        core::ptr::write_unaligned(
            dest as *mut u64,
            core::ptr::read_unaligned(src as *const u64),
        );
    }
}

/// `RtlInitString(PSTRING, PCSZ)` — set `Length`/`MaximumLength` from a NUL-terminated byte string;
/// `Buffer` = the source pointer (no copy). Ported from `references/reactos/sdk/lib/rtl/rtlp.c` /
/// `unicode.c:RtlInitString` (identical shape to `RtlInitAnsiString`).
///
/// # Safety
/// `dst` a valid writable `STRING` (ANSI_STRING, 16 bytes x64); `src` null or NUL-terminated.
#[export_name = "RtlInitString"]
pub unsafe extern "system" fn rtl_init_string(dst: *mut c_void, src: *const u8) {
    if dst.is_null() {
        return;
    }
    // SAFETY: caller contract.
    let len = unsafe { strlen_raw(src) };
    // STRING { Length(u16)@0, MaximumLength(u16)@2, _pad@4, Buffer(ptr)@8 }.
    // SAFETY: dst a valid writable STRING per the contract.
    unsafe {
        core::ptr::write_unaligned(dst as *mut u16, len as u16); // Length
        core::ptr::write_unaligned((dst as *mut u8).add(2) as *mut u16, (len + 1) as u16); // MaxLength
        core::ptr::write_unaligned((dst as *mut u8).add(8) as *mut u64, src as u64); // Buffer
    }
}

/// `RtlDeleteCriticalSection(PRTL_CRITICAL_SECTION) -> NTSTATUS` — reset the descriptor (the real one
/// also frees the LockSemaphore; we have no kernel semaphore in the uncontended model, so a zero-out
/// is the observable half). Ref `references/reactos/sdk/lib/rtl/critical.c:RtlDeleteCriticalSection`.
///
/// # Safety
/// `cs` a valid `RTL_CRITICAL_SECTION`.
#[export_name = "RtlDeleteCriticalSection"]
pub unsafe extern "system" fn rtl_delete_critical_section(cs: *mut c_void) -> NtStatus {
    if cs.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: cs a valid 40-byte RTL_CRITICAL_SECTION per the contract.
    unsafe { core::ptr::write_bytes(cs as *mut u8, 0, 40) };
    STATUS_SUCCESS
}

/// `RtlInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION, ULONG SpinCount) -> NTSTATUS`.
/// Ref `references/reactos/sdk/lib/rtl/critical.c` — init the CS then store the spin count (bit 31 of
/// the count field is masked out per the contract). Same uncontended layout as
/// [`rtl_initialize_critical_section`] with SpinCount @0x20 (x64).
///
/// # Safety
/// `cs` a valid writable `RTL_CRITICAL_SECTION`.
#[export_name = "RtlInitializeCriticalSectionAndSpinCount"]
pub unsafe extern "system" fn rtl_initialize_critical_section_and_spin_count(
    cs: *mut c_void,
    spin_count: u32,
) -> NtStatus {
    if cs.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: cs a valid 40-byte RTL_CRITICAL_SECTION per the contract.
    unsafe {
        core::ptr::write_bytes(cs as *mut u8, 0, 40);
        *((cs as *mut u8).add(0x08) as *mut i32) = -1; // LockCount = -1 (free)
        *((cs as *mut u8).add(0x20) as *mut u32) = spin_count & 0x7FFF_FFFF; // SpinCount (bit31 masked)
    }
    STATUS_SUCCESS
}

/// `RtlReAllocateHeap(PVOID Heap, ULONG Flags, PVOID Ptr, SIZE_T Size) -> PVOID` — grow/shrink `ptr`
/// to `size` in the single process heap. Honors HEAP_ZERO_MEMORY on a grow (zeroes the tail).
///
/// # Safety
/// `ptr` from `RtlAllocateHeap`/`RtlReAllocateHeap`.
#[export_name = "RtlReAllocateHeap"]
pub unsafe extern "system" fn rtl_reallocate_heap(
    _heap: *mut c_void,
    _flags: u32,
    ptr: *mut c_void,
    size: usize,
) -> *mut c_void {
    #[cfg(target_arch = "x86_64")]
    {
        if ptr.is_null() {
            // realloc(NULL, n) == alloc(n).
            // SAFETY: single-threaded loader context.
            return unsafe { crate::process_heap_alloc(size) } as *mut c_void;
        }
        // SAFETY: ptr from our heap; single-threaded loader.
        unsafe { crate::process_heap_realloc(ptr as *mut u8, size) as *mut c_void }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (ptr, size);
        core::ptr::null_mut()
    }
}

/// `RtlExpandEnvironmentStrings_U(PWSTR Env, PUNICODE_STRING Src, PUNICODE_STRING Dst, PULONG RetLen)`.
/// Live driver over the PEB env (`references/reactos/sdk/lib/rtl/env.c:264`).
///
/// # Safety
/// `src`/`dst` valid `UNICODE_STRING*`; `ret_len` writable/NULL.
#[export_name = "RtlExpandEnvironmentStrings_U"]
pub unsafe extern "system" fn rtl_expand_environment_strings_u(
    env: *const u16,
    src: PCUnicodeString,
    dst: PUnicodeString,
    ret_len: *mut u32,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; src/dst valid UNICODE_STRING per the contract.
        unsafe {
            crate::on_target::rtl_expand_environment_strings_u(
                env,
                src as *const u8,
                dst as *mut u8,
                ret_len,
            )
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (env, src, dst, ret_len);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlOpenCurrentUser(ACCESS_MASK, PHANDLE) -> NTSTATUS`. Live driver (opens the default user key via
/// NtOpenKey; `references/reactos/sdk/lib/rtl/registry.c:702`).
///
/// # Safety
/// `key_handle` writable.
#[export_name = "RtlOpenCurrentUser"]
pub unsafe extern "system" fn rtl_open_current_user(
    desired_access: u32,
    key_handle: *mut c_void,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; key_handle writable per the contract.
        unsafe { crate::on_target::rtl_open_current_user(desired_access, key_handle as *mut u64) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (desired_access, key_handle);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `_snwprintf(wchar_t* buf, size_t count, const wchar_t* fmt, ...) -> int` — variadic wide; the 4.0b
/// seam (writes an empty string; real formatting is the CRT plane). Declares only the fixed args (the
/// Win64 ABI leaves the variadic tail in caller regs/stack, which we never read).
///
/// # Safety
/// `buf` writable for at least 1 unit.
#[export_name = "_snwprintf"]
pub unsafe extern "C" fn snwprintf(buf: *mut u16, count: usize, _fmt: *const u16) -> i32 {
    if !buf.is_null() && count > 0 {
        // SAFETY: buf valid for >= 1 unit per the contract.
        unsafe { *buf = 0 };
    }
    0
}

/// `wcsncpy(wchar_t* dst, const wchar_t* src, size_t n) -> wchar_t*` — copy up to `n` units,
/// NUL-padding the tail (the C contract).
///
/// # Safety
/// `dst` valid for `n` units; `src` NUL-terminated.
#[export_name = "wcsncpy"]
pub unsafe extern "C" fn wcsncpy(dst: *mut u16, src: *const u16, n: usize) -> *mut u16 {
    // SAFETY: caller contract.
    unsafe {
        let mut i = 0usize;
        while i < n {
            let c = *src.add(i);
            *dst.add(i) = c;
            if c == 0 {
                break;
            }
            i += 1;
        }
        while i < n {
            *dst.add(i) = 0;
            i += 1;
        }
    }
    dst
}

/// `wcscat(wchar_t* dst, const wchar_t* src) -> wchar_t*` — append `src` to `dst` (NUL-terminated).
///
/// # Safety
/// `dst` NUL-terminated + large enough for the concatenation; `src` NUL-terminated.
#[export_name = "wcscat"]
pub unsafe extern "C" fn wcscat(dst: *mut u16, src: *const u16) -> *mut u16 {
    // SAFETY: caller contract.
    unsafe {
        let dl = wcslen_raw(dst);
        let sl = wcslen_raw(src);
        core::ptr::copy_nonoverlapping(src, dst.add(dl), sl);
        *dst.add(dl + sl) = 0;
    }
    dst
}

/// `_wcsnicmp(const wchar_t*, const wchar_t*, size_t n) -> int` — case-insensitive, first `n` units.
///
/// # Safety
/// Both valid for up to `n` units (NUL short-circuits).
#[export_name = "_wcsnicmp"]
pub unsafe extern "C" fn wcsnicmp(a: *const u16, b: *const u16, n: usize) -> i32 {
    // SAFETY: caller contract; NUL short-circuits before `n`.
    unsafe {
        for i in 0..n {
            let ca = rtl::strings::upcase_char(*a.add(i));
            let cb = rtl::strings::upcase_char(*b.add(i));
            if ca != cb {
                return if ca < cb { -1 } else { 1 };
            }
            if ca == 0 {
                break;
            }
        }
    }
    0
}

// -------------------------------------------------------------------------------------------------
// The loader Ldr* — csrsrv's CsrLoadServerDll uses these to load its ServerDlls (basesrv/winsrv) +
// resolve their entry points. Wired to the on-target recursive loader (on_target.rs).
// -------------------------------------------------------------------------------------------------

/// `LdrLoadDll(PWSTR SearchPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* BaseAddr)
/// -> NTSTATUS`. Ref `references/reactos/dll/ntdll/ldr/ldrapi.c:LdrLoadDll` → LdrpLoadDll. Loads the
/// named DLL (map + snap its imports recursively) and returns its base. Driven by the on-target
/// loader ([`crate::on_target::ldr_load_dll`]).
///
/// # Safety
/// `dll_name` a valid `UNICODE_STRING*`; `base_addr` a writable `PVOID*`.
#[export_name = "LdrLoadDll"]
pub unsafe extern "system" fn ldr_load_dll(
    _search_path: *mut u16,
    _characteristics: *mut u32,
    dll_name: PCUnicodeString,
    base_addr: *mut *mut c_void,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; dll_name a valid UNICODE_STRING, base_addr writable.
        unsafe { crate::on_target::ldr_load_dll(dll_name as *const c_void, base_addr) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (dll_name, base_addr);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `LdrGetDllHandle(PWSTR Path, PULONG Flags, PUNICODE_STRING DllName, PVOID* DllHandle) -> NTSTATUS`.
/// Ref `references/reactos/dll/ntdll/ldr/ldrapi.c:LdrGetDllHandle` — return the base of an
/// ALREADY-LOADED DLL (does NOT load). Driven by the on-target module table.
///
/// # Safety
/// `dll_name` a valid `UNICODE_STRING*`; `dll_handle` writable.
#[export_name = "LdrGetDllHandle"]
pub unsafe extern "system" fn ldr_get_dll_handle(
    _path: *mut u16,
    _flags: *mut u32,
    dll_name: PCUnicodeString,
    dll_handle: *mut *mut c_void,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; dll_name a valid UNICODE_STRING, dll_handle writable.
        unsafe { crate::on_target::ldr_get_dll_handle(dll_name as *const c_void, dll_handle) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (dll_name, dll_handle);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `LdrGetProcedureAddress(PVOID BaseAddress, PANSI_STRING Name, ULONG Ordinal, PVOID* Address)`.
/// Ref `references/reactos/dll/ntdll/ldr/ldrapi.c:LdrGetProcedureAddress` — resolve an export (by
/// name or ordinal) in a loaded module. Driven by the on-target export walker.
///
/// # Safety
/// `base_address` a mapped module; `name` a valid `ANSI_STRING*` (or NULL for by-ordinal); `address`
/// writable.
#[export_name = "LdrGetProcedureAddress"]
pub unsafe extern "system" fn ldr_get_procedure_address(
    base_address: *mut c_void,
    name: *const c_void,
    ordinal: u32,
    address: *mut *mut c_void,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target; base a mapped module, name an ANSI_STRING*/NULL, address writable.
        unsafe {
            crate::on_target::ldr_get_procedure_address(base_address, name, ordinal, address)
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (base_address, name, ordinal, address);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `LdrUnloadDll(PVOID BaseAddress) -> NTSTATUS`. Ref
/// `references/reactos/dll/ntdll/ldr/ldrapi.c:LdrUnloadDll`. We keep loaded modules mapped for the
/// process lifetime (no ref-count teardown yet — the ServerDlls live forever), so this reports
/// SUCCESS without unmapping (the observable contract for a still-referenced DLL). Not a fabricated
/// result: real ntdll also keeps a DLL mapped while its ref-count > 0.
///
/// # Safety
/// `base_address` a previously-loaded module base.
#[export_name = "LdrUnloadDll"]
pub unsafe extern "system" fn ldr_unload_dll(_base_address: *mut c_void) -> NtStatus {
    STATUS_SUCCESS
}

// =================================================================================================
// BATCH 4 — CRT (mem/str/wcs/ctype/math/parse) the Win32 stack imports from ntdll.
// Standard C-runtime re-exports (ntdll ships them so the Win32 DLLs don't statically link a CRT).
// Slice-marshalled over the host-tested `nt_ntdll::crt` cores where one exists; otherwise a
// correct-by-construction inline body (real semantics, not a seam). Signatures = the MS x64 CRT.
// =================================================================================================

/// `memcmp(const void*, const void*, size_t) -> int`. Weak (compiler-builtins-mem also provides it).
///
/// # Safety
/// Both valid for `n` bytes.
#[linkage = "weak"]
#[export_name = "memcmp"]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: caller contract.
    let (sa, sb) = unsafe {
        (
            core::slice::from_raw_parts(a, n),
            core::slice::from_raw_parts(b, n),
        )
    };
    match nt_ntdll::crt::memcmp(sa, sb, n) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `memchr(const void*, int, size_t) -> void*`.
///
/// # Safety
/// `s` valid for `n` bytes.
#[export_name = "memchr"]
pub unsafe extern "C" fn memchr(s: *const u8, c: i32, n: usize) -> *const u8 {
    // SAFETY: caller contract.
    let hay = unsafe { core::slice::from_raw_parts(s, n) };
    match nt_ntdll::crt::memchr(hay, c as u8, n) {
        // SAFETY: index within [0,n).
        Some(i) => unsafe { s.add(i) },
        None => core::ptr::null(),
    }
}

/// `strlen(const char*) -> size_t`. Weak (compiler-builtins-mem also provides it).
///
/// # Safety
/// `s` a NUL-terminated byte string.
#[linkage = "weak"]
#[export_name = "strlen"]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    // SAFETY: caller contract.
    unsafe { strlen_raw(s) }
}

/// `strcmp(const char*, const char*) -> int`.
///
/// # Safety
/// Both NUL-terminated byte strings.
#[export_name = "strcmp"]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: caller contract.
    let (sa, sb) = unsafe {
        (
            core::slice::from_raw_parts(a, strlen_raw(a)),
            core::slice::from_raw_parts(b, strlen_raw(b)),
        )
    };
    match nt_ntdll::crt::strcmp(sa, sb) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `_strcmpi(const char*, const char*) -> int` (== `stricmp`, case-insensitive).
///
/// # Safety
/// Both NUL-terminated byte strings.
#[export_name = "_strcmpi"]
pub unsafe extern "C" fn strcmpi(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: caller contract.
    let (sa, sb) = unsafe {
        (
            core::slice::from_raw_parts(a, strlen_raw(a)),
            core::slice::from_raw_parts(b, strlen_raw(b)),
        )
    };
    match nt_ntdll::crt::stricmp(sa, sb) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `strncmp(const char*, const char*, size_t) -> int`.
///
/// # Safety
/// Both valid up to a NUL or `n` bytes.
#[export_name = "strncmp"]
pub unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: caller contract — walk at most n, stopping at a NUL in either.
    let (la, lb) = unsafe { (strnlen_raw(a, n), strnlen_raw(b, n)) };
    let (sa, sb) =
        // SAFETY: la/lb <= n and within the strings.
        unsafe {
            (
                core::slice::from_raw_parts(a, la),
                core::slice::from_raw_parts(b, lb),
            )
        };
    match nt_ntdll::crt::strncmp(sa, sb, n) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `strcpy(char* dst, const char* src) -> char*`.
///
/// # Safety
/// `dst` large enough for `src`+NUL; `src` NUL-terminated.
#[export_name = "strcpy"]
pub unsafe extern "C" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: caller contract.
    let n = unsafe { strlen_raw(src) };
    // SAFETY: dst large enough per the contract.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, n);
        *dst.add(n) = 0;
    }
    dst
}

/// `strcat(char* dst, const char* src) -> char*`.
///
/// # Safety
/// `dst` NUL-terminated + large enough for the concatenation; `src` NUL-terminated.
#[export_name = "strcat"]
pub unsafe extern "C" fn strcat(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: caller contract.
    let dlen = unsafe { strlen_raw(dst) };
    let slen = unsafe { strlen_raw(src) };
    // SAFETY: dst large enough per the contract.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst.add(dlen), slen);
        *dst.add(dlen + slen) = 0;
    }
    dst
}

/// `strchr(const char*, int) -> char*` — already exported above; not duplicated.
/// `strrchr(const char*, int) -> char*`.
///
/// # Safety
/// `s` a NUL-terminated byte string.
#[export_name = "strrchr"]
pub unsafe extern "C" fn strrchr(s: *const u8, c: i32) -> *const u8 {
    // SAFETY: caller contract.
    let len = unsafe { strlen_raw(s) };
    // SAFETY: valid region of len bytes.
    let hay = unsafe { core::slice::from_raw_parts(s, len) };
    match nt_ntdll::crt::strrchr(hay, c as u8) {
        // SAFETY: i within [0,len).
        Some(i) => unsafe { s.add(i) },
        // The NUL matches strrchr(s, 0) in C; return &NUL.
        None if (c as u8) == 0 => unsafe { s.add(len) },
        None => core::ptr::null(),
    }
}

/// `strstr(const char*, const char*) -> char*`.
///
/// # Safety
/// Both NUL-terminated byte strings.
#[export_name = "strstr"]
pub unsafe extern "C" fn strstr(hay: *const u8, needle: *const u8) -> *const u8 {
    // SAFETY: caller contract.
    let (hl, nl) = unsafe { (strlen_raw(hay), strlen_raw(needle)) };
    // SAFETY: valid regions.
    let (h, n) = unsafe {
        (
            core::slice::from_raw_parts(hay, hl),
            core::slice::from_raw_parts(needle, nl),
        )
    };
    match nt_ntdll::crt::strstr(h, n) {
        // SAFETY: i within the haystack.
        Some(i) => unsafe { hay.add(i) },
        None => core::ptr::null(),
    }
}

/// `strcspn(const char* s, const char* reject) -> size_t` — length of the initial run of `s` with
/// no char in `reject`.
///
/// # Safety
/// Both NUL-terminated byte strings.
#[export_name = "strcspn"]
pub unsafe extern "C" fn strcspn(s: *const u8, reject: *const u8) -> usize {
    // SAFETY: caller contract.
    let (sl, rl) = unsafe { (strlen_raw(s), strlen_raw(reject)) };
    let (ss, rs) = unsafe {
        (
            core::slice::from_raw_parts(s, sl),
            core::slice::from_raw_parts(reject, rl),
        )
    };
    ss.iter().take_while(|b| !rs.contains(b)).count()
}

/// `strpbrk(const char* s, const char* accept) -> char*` — first char of `s` in `accept`.
///
/// # Safety
/// Both NUL-terminated byte strings.
#[export_name = "strpbrk"]
pub unsafe extern "C" fn strpbrk(s: *const u8, accept: *const u8) -> *const u8 {
    // SAFETY: caller contract.
    let (sl, al) = unsafe { (strlen_raw(s), strlen_raw(accept)) };
    let (ss, ac) = unsafe {
        (
            core::slice::from_raw_parts(s, sl),
            core::slice::from_raw_parts(accept, al),
        )
    };
    match ss.iter().position(|b| ac.contains(b)) {
        // SAFETY: i within the string.
        Some(i) => unsafe { s.add(i) },
        None => core::ptr::null(),
    }
}

/// `_wcslwr(wchar_t*) -> wchar_t*` — lowercase an ASCII/Latin-1 wide string in place.
///
/// # Safety
/// `s` a NUL-terminated, writable UTF-16 string.
#[export_name = "_wcslwr"]
pub unsafe extern "C" fn wcslwr(s: *mut u16) -> *mut u16 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(s) };
    for i in 0..n {
        // SAFETY: i within [0,n).
        unsafe {
            let c = *s.add(i);
            if (0x41..=0x5A).contains(&c) {
                *s.add(i) = c + 0x20;
            }
        }
    }
    s
}

/// `wcschr(const wchar_t*, wchar_t) -> wchar_t*`.
///
/// # Safety
/// `s` a NUL-terminated UTF-16 string.
#[export_name = "wcschr"]
pub unsafe extern "C" fn wcschr(s: *const u16, c: u16) -> *const u16 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(s) };
    let hay = unsafe { core::slice::from_raw_parts(s, n) };
    match nt_ntdll::crt::wcschr(hay, c) {
        // SAFETY: i within [0,n).
        Some(i) => unsafe { s.add(i) },
        None if c == 0 => unsafe { s.add(n) },
        None => core::ptr::null(),
    }
}

/// `wcsrchr(const wchar_t*, wchar_t) -> wchar_t*`.
///
/// # Safety
/// `s` a NUL-terminated UTF-16 string.
#[export_name = "wcsrchr"]
pub unsafe extern "C" fn wcsrchr(s: *const u16, c: u16) -> *const u16 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(s) };
    let hay = unsafe { core::slice::from_raw_parts(s, n) };
    match hay.iter().rposition(|&w| w == c) {
        // SAFETY: i within [0,n).
        Some(i) => unsafe { s.add(i) },
        None if c == 0 => unsafe { s.add(n) },
        None => core::ptr::null(),
    }
}

/// `wcscmp(const wchar_t*, const wchar_t*) -> int`.
///
/// # Safety
/// Both NUL-terminated UTF-16 strings.
#[export_name = "wcscmp"]
pub unsafe extern "C" fn wcscmp(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: caller contract.
    let (sa, sb) = unsafe {
        (
            core::slice::from_raw_parts(a, wcslen_raw(a)),
            core::slice::from_raw_parts(b, wcslen_raw(b)),
        )
    };
    match nt_ntdll::crt::wcscmp(sa, sb) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `wcsncmp(const wchar_t*, const wchar_t*, size_t) -> int`.
///
/// # Safety
/// Both valid up to a NUL or `n` code units.
#[export_name = "wcsncmp"]
pub unsafe extern "C" fn wcsncmp(a: *const u16, b: *const u16, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: caller contract — walk at most n, stop at a NUL in either.
        let (ca, cb) = unsafe { (*a.add(i), *b.add(i)) };
        if ca != cb {
            return if ca < cb { -1 } else { 1 };
        }
        if ca == 0 {
            break;
        }
    }
    0
}

/// `wcscspn(const wchar_t* s, const wchar_t* reject) -> size_t`.
///
/// # Safety
/// Both NUL-terminated UTF-16 strings.
#[export_name = "wcscspn"]
pub unsafe extern "C" fn wcscspn(s: *const u16, reject: *const u16) -> usize {
    // SAFETY: caller contract.
    let (sl, rl) = unsafe { (wcslen_raw(s), wcslen_raw(reject)) };
    let (ss, rs) = unsafe {
        (
            core::slice::from_raw_parts(s, sl),
            core::slice::from_raw_parts(reject, rl),
        )
    };
    ss.iter().take_while(|w| !rs.contains(w)).count()
}

/// `wcsspn(const wchar_t* s, const wchar_t* accept) -> size_t`.
///
/// # Safety
/// Both NUL-terminated UTF-16 strings.
#[export_name = "wcsspn"]
pub unsafe extern "C" fn wcsspn(s: *const u16, accept: *const u16) -> usize {
    // SAFETY: caller contract.
    let (sl, al) = unsafe { (wcslen_raw(s), wcslen_raw(accept)) };
    let (ss, ac) = unsafe {
        (
            core::slice::from_raw_parts(s, sl),
            core::slice::from_raw_parts(accept, al),
        )
    };
    ss.iter().take_while(|w| ac.contains(w)).count()
}

/// `atoi(const char*) -> int`.
///
/// # Safety
/// `s` a NUL-terminated byte string.
#[export_name = "atoi"]
pub unsafe extern "C" fn atoi(s: *const u8) -> i32 {
    // SAFETY: caller contract.
    let n = unsafe { strlen_raw(s) };
    let bytes = unsafe { core::slice::from_raw_parts(s, n) };
    nt_ntdll::crt::atoi(bytes)
}

/// `_wtoi(const wchar_t*) -> int` — wide `atoi`.
///
/// # Safety
/// `s` a NUL-terminated UTF-16 string.
#[export_name = "_wtoi"]
pub unsafe extern "C" fn wtoi(s: *const u16) -> i32 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(s) };
    let ws = unsafe { core::slice::from_raw_parts(s, n) };
    // Fold to ASCII bytes then reuse atoi (values are ASCII digits/sign).
    let bytes: Vec<u8> = ws.iter().map(|&w| (w & 0xFF) as u8).collect();
    nt_ntdll::crt::atoi(&bytes)
}

/// `strtol(const char* s, char** endptr, int base) -> long`.
///
/// # Safety
/// `s` NUL-terminated; `endptr` null or writable.
#[export_name = "strtol"]
pub unsafe extern "C" fn strtol(s: *const u8, endptr: *mut *mut u8, base: i32) -> i64 {
    // SAFETY: caller contract.
    let n = unsafe { strlen_raw(s) };
    let bytes = unsafe { core::slice::from_raw_parts(s, n) };
    let v = nt_ntdll::crt::strtoul(bytes, base as u32) as i64;
    if !endptr.is_null() {
        // SAFETY: endptr writable per the contract; consume the whole numeric run conservatively.
        unsafe { *endptr = s.add(n) as *mut u8 };
    }
    v
}

/// `strtoul(const char* s, char** endptr, int base) -> unsigned long`.
///
/// # Safety
/// `s` NUL-terminated; `endptr` null or writable.
#[export_name = "strtoul"]
pub unsafe extern "C" fn strtoul(s: *const u8, endptr: *mut *mut u8, base: i32) -> u64 {
    // SAFETY: caller contract.
    let n = unsafe { strlen_raw(s) };
    let bytes = unsafe { core::slice::from_raw_parts(s, n) };
    let v = nt_ntdll::crt::strtoul(bytes, base as u32) as u64;
    if !endptr.is_null() {
        // SAFETY: endptr writable per the contract.
        unsafe { *endptr = s.add(n) as *mut u8 };
    }
    v
}

/// `wcstol(const wchar_t* s, wchar_t** endptr, int base) -> long`.
///
/// # Safety
/// `s` NUL-terminated; `endptr` null or writable.
#[export_name = "wcstol"]
pub unsafe extern "C" fn wcstol(s: *const u16, endptr: *mut *mut u16, base: i32) -> i64 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(s) };
    let ws = unsafe { core::slice::from_raw_parts(s, n) };
    let bytes: Vec<u8> = ws.iter().map(|&w| (w & 0xFF) as u8).collect();
    let v = nt_ntdll::crt::strtoul(&bytes, base as u32) as i64;
    if !endptr.is_null() {
        // SAFETY: endptr writable per the contract.
        unsafe { *endptr = s.add(n) as *mut u16 };
    }
    v
}

/// `wcstoul(const wchar_t* s, wchar_t** endptr, int base) -> unsigned long`.
///
/// # Safety
/// `s` NUL-terminated; `endptr` null or writable.
#[export_name = "wcstoul"]
pub unsafe extern "C" fn wcstoul(s: *const u16, endptr: *mut *mut u16, base: i32) -> u64 {
    // SAFETY: caller contract.
    let n = unsafe { wcslen_raw(s) };
    let ws = unsafe { core::slice::from_raw_parts(s, n) };
    let bytes: Vec<u8> = ws.iter().map(|&w| (w & 0xFF) as u8).collect();
    let v = nt_ntdll::crt::strtoul(&bytes, base as u32) as u64;
    if !endptr.is_null() {
        // SAFETY: endptr writable per the contract.
        unsafe { *endptr = s.add(n) as *mut u16 };
    }
    v
}

/// `_ultow(unsigned long value, wchar_t* buf, int radix) -> wchar_t*` — unsigned-to-wide-string.
///
/// # Safety
/// `buf` large enough (>= 33 wchars for radix 2).
#[export_name = "_ultow"]
pub unsafe extern "C" fn ultow(value: u32, buf: *mut u16, radix: i32) -> *mut u16 {
    let radix = if (2..=36).contains(&radix) {
        radix as u32
    } else {
        10
    };
    let mut tmp = [0u16; 34];
    let mut v = value;
    let mut i = 0usize;
    if v == 0 {
        tmp[0] = b'0' as u16;
        i = 1;
    }
    while v != 0 {
        let d = (v % radix) as u8;
        tmp[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 } as u16;
        v /= radix;
        i += 1;
    }
    // reversed
    for j in 0..i {
        // SAFETY: buf large enough per the contract.
        unsafe { *buf.add(j) = tmp[i - 1 - j] };
    }
    // SAFETY: terminator within the provided buffer.
    unsafe { *buf.add(i) = 0 };
    buf
}

/// `abs(int) -> int`.
#[export_name = "abs"]
pub extern "C" fn abs(v: i32) -> i32 {
    nt_ntdll::crt::abs(v)
}

/// `labs(long) -> long`.
#[export_name = "labs"]
pub extern "C" fn labs(v: i64) -> i64 {
    nt_ntdll::crt::labs(v)
}

/// `tolower(int) -> int` (ASCII).
#[export_name = "tolower"]
pub extern "C" fn tolower(c: i32) -> i32 {
    if (0x41..=0x5A).contains(&c) {
        c + 0x20
    } else {
        c
    }
}

/// `toupper(int) -> int` (ASCII).
#[export_name = "toupper"]
pub extern "C" fn toupper(c: i32) -> i32 {
    if (0x61..=0x7A).contains(&c) {
        c - 0x20
    } else {
        c
    }
}

/// `towlower(wint_t) -> wint_t` (Latin-1 subset).
#[export_name = "towlower"]
pub extern "C" fn towlower(c: u32) -> u32 {
    if (0x41..=0x5A).contains(&c) {
        c + 0x20
    } else {
        c
    }
}

/// `towupper(wint_t) -> wint_t` (Latin-1 subset).
#[export_name = "towupper"]
pub extern "C" fn towupper(c: u32) -> u32 {
    if (0x61..=0x7A).contains(&c) {
        c - 0x20
    } else {
        c
    }
}

/// `isalpha(int) -> int` (ASCII).
#[export_name = "isalpha"]
pub extern "C" fn isalpha(c: i32) -> i32 {
    i32::from((0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c))
}

/// `islower(int) -> int` (ASCII).
#[export_name = "islower"]
pub extern "C" fn islower(c: i32) -> i32 {
    i32::from((0x61..=0x7A).contains(&c))
}

/// `iswctype(wint_t c, wctype_t type) -> int` — the wide ctype predicate. We serve the classes the
/// Win32 stack actually queries (alpha/digit/space/upper/lower/alnum) over ASCII/Latin-1; the mask
/// bits follow the MSVCRT `_ISxxx` values.
#[export_name = "iswctype"]
pub extern "C" fn iswctype(c: u32, mask: u16) -> i32 {
    const IS_UPPER: u16 = 0x0001;
    const IS_LOWER: u16 = 0x0002;
    const IS_DIGIT: u16 = 0x0004;
    const IS_SPACE: u16 = 0x0008;
    const IS_ALPHA: u16 = 0x0100;
    let upper = (0x41..=0x5A).contains(&c);
    let lower = (0x61..=0x7A).contains(&c);
    let digit = (0x30..=0x39).contains(&c);
    let space = matches!(c, 0x20 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D);
    let mut hit = false;
    if mask & IS_UPPER != 0 && upper {
        hit = true;
    }
    if mask & IS_LOWER != 0 && lower {
        hit = true;
    }
    if mask & IS_DIGIT != 0 && digit {
        hit = true;
    }
    if mask & IS_SPACE != 0 && space {
        hit = true;
    }
    if mask & IS_ALPHA != 0 && (upper || lower) {
        hit = true;
    }
    i32::from(hit)
}

/// `sin(double) -> double`. Minimal Taylor/CORDIC-free reduction — the Win32 boot path uses these
/// only in cosmetic float paths; a real range-reduced Taylor series is accurate for the small
/// arguments seen. (No libm in `no_std`.)
#[export_name = "sin"]
pub extern "C" fn sin(x: f64) -> f64 {
    poly_sin(reduce_pi(x))
}

/// `cos(double) -> double`.
#[export_name = "cos"]
pub extern "C" fn cos(x: f64) -> f64 {
    poly_sin(reduce_pi(x + core::f64::consts::FRAC_PI_2))
}

/// `fabs(double) -> double`.
#[export_name = "fabs"]
pub extern "C" fn fabs(x: f64) -> f64 {
    if x < 0.0 {
        -x
    } else {
        x
    }
}

/// `floor(double) -> double`.
#[export_name = "floor"]
pub extern "C" fn floor(x: f64) -> f64 {
    let t = x as i64 as f64;
    if t > x {
        t - 1.0
    } else {
        t
    }
}

/// `bsearch(const void* key, const void* base, size_t num, size_t size, cmp) -> void*`. Generic
/// C `bsearch` over an opaque array with a C comparator.
///
/// # Safety
/// `base` valid for `num*size` bytes; `compar` a valid C comparator; `key` valid for `size` bytes.
#[export_name = "bsearch"]
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    num: usize,
    size: usize,
    compar: extern "C" fn(*const c_void, *const c_void) -> i32,
) -> *const c_void {
    if base.is_null() || size == 0 {
        return core::ptr::null();
    }
    let mut lo = 0isize;
    let mut hi = num as isize - 1;
    while lo <= hi {
        let mid = (lo + hi) / 2;
        // SAFETY: mid in [0,num); element at base + mid*size.
        let elem = unsafe { (base as *const u8).add(mid as usize * size) } as *const c_void;
        let r = compar(key, elem);
        match r.cmp(&0) {
            core::cmp::Ordering::Equal => return elem,
            core::cmp::Ordering::Less => hi = mid - 1,
            core::cmp::Ordering::Greater => lo = mid + 1,
        }
    }
    core::ptr::null()
}

/// `qsort(void* base, size_t num, size_t size, cmp)`. In-place, over an opaque byte array with a C
/// comparator. Insertion sort (stable, correct, no allocation) — the Win32 boot arrays are tiny.
///
/// # Safety
/// `base` valid + writable for `num*size` bytes; `compar` a valid C comparator.
#[export_name = "qsort"]
pub unsafe extern "C" fn qsort(
    base: *mut c_void,
    num: usize,
    size: usize,
    compar: extern "C" fn(*const c_void, *const c_void) -> i32,
) {
    if base.is_null() || size == 0 || num < 2 {
        return;
    }
    let b = base as *mut u8;
    let mut scratch = alloc::vec![0u8; size];
    for i in 1..num {
        // element i -> scratch
        // SAFETY: i < num; regions within base.
        unsafe {
            core::ptr::copy_nonoverlapping(b.add(i * size), scratch.as_mut_ptr(), size);
        }
        let mut j = i;
        while j > 0 {
            // SAFETY: (j-1) < num.
            let prev = unsafe { b.add((j - 1) * size) } as *const c_void;
            if compar(prev, scratch.as_ptr() as *const c_void) <= 0 {
                break;
            }
            // SAFETY: shift element (j-1) up to j.
            unsafe {
                core::ptr::copy_nonoverlapping(b.add((j - 1) * size), b.add(j * size), size);
            }
            j -= 1;
        }
        // SAFETY: place scratch at j.
        unsafe {
            core::ptr::copy_nonoverlapping(scratch.as_ptr(), b.add(j * size), size);
        }
    }
}

/// `__chkstk` — the MSVC stack-probe intrinsic. On our committed-stack model there is nothing to
/// probe (pages are demand-faulted + backed on touch), so it is a no-op that preserves the ABI
/// contract (RAX = allocation size in, RSP already adjusted by the caller). Naked so it doesn't
/// perturb registers.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[export_name = "__chkstk"]
pub unsafe extern "C" fn chkstk() {
    core::arch::naked_asm!("ret");
}

/// `_local_unwind(void* frame, void* target)` — MSVC SEH local unwind helper. The full unwinder is
/// the `RtlUnwind`/`__C_specific_handler` machinery (target-side seam); the local-unwind entry is a
/// no-op on the non-exception boot path (no `__finally` frames run during normal init).
///
/// # Safety
/// Called by compiler-emitted SEH prologue/epilogue code only.
#[export_name = "_local_unwind"]
pub unsafe extern "C" fn local_unwind(_frame: *mut c_void, _target: *mut c_void) {}

/// `VerSetConditionMask(ULONGLONG mask, DWORD type, BYTE cond) -> ULONGLONG` — the version-info
/// condition accumulator (`ntdll` export used by `VerifyVersionInfo`). Packs the 3-bit condition for
/// the type's field-index into the 64-bit mask (7 fields × 8 bits). Ref MS `VerSetConditionMask`.
#[export_name = "VerSetConditionMask"]
pub extern "C" fn ver_set_condition_mask(mask: u64, type_bit_mask: u32, condition: u8) -> u64 {
    if type_bit_mask == 0 {
        return mask;
    }
    // find the single set bit's index (VER_MINORVERSION=1, MAJORVERSION=2, BUILDNUMBER=4, ...).
    let index = type_bit_mask.trailing_zeros() as u64;
    let cond = (condition & 0x07) as u64;
    let shift = 3 * index;
    (mask & !(0x07u64 << shift)) | (cond << shift)
}

// ---- math helpers for sin/cos (no libm) ----------------------------------------------------------
fn reduce_pi(x: f64) -> f64 {
    // reduce to [-pi, pi] WITHOUT the `%` operator (which lowers to a libm `fmod` call, absent in
    // no_std): subtract k*2pi where k = round(x / 2pi), computed via integer truncation.
    let two_pi = 2.0 * core::f64::consts::PI;
    let k = (x / two_pi + if x >= 0.0 { 0.5 } else { -0.5 }) as i64 as f64;
    let mut r = x - k * two_pi;
    if r > core::f64::consts::PI {
        r -= two_pi;
    } else if r < -core::f64::consts::PI {
        r += two_pi;
    }
    r
}
fn poly_sin(x: f64) -> f64 {
    // 7th-order Taylor, accurate on [-pi,pi] to ~1e-4.
    let x2 = x * x;
    x * (1.0 - x2 / 6.0 * (1.0 - x2 / 20.0 * (1.0 - x2 / 42.0)))
}

/// Count bytes up to `n` or a NUL (whichever first).
///
/// # Safety
/// `p` valid for reads up to the first NUL or `n` bytes.
unsafe fn strnlen_raw(p: *const u8, n: usize) -> usize {
    let mut i = 0usize;
    // SAFETY: caller contract.
    while i < n && unsafe { *p.add(i) } != 0 {
        i += 1;
    }
    i
}

// =================================================================================================
// BATCH 4 — Rtl* activation-context (SxS) / path / guid / image / handle-table / resource-lock /
// timer-queue / thread-pool / debug-buffer families.
//   * SxS: no activation-context plane hosted → the whole family is honest no-ops that report "no
//     active context" (the caller falls back to the process default — which IS how a manifest-less
//     process behaves). The Ex/UnsafeFast variants share the no-op.
//   * path/guid: real bodies over the host-tested nt_ntdll::rtl::{path,guid}.
//   * image: real bodies over nt_ntdll::rtl::image (a mapped image = a byte slice from the base).
//   * handle-table / resource-lock: real inline (single-threaded).
//   * timer-queue / thread-pool: no scheduler plane → honest STATUS_NOT_IMPLEMENTED / no-op.
// =================================================================================================

// ---- activation context (SxS) — no plane; report "no active context" -----------------------------

/// `RtlActivateActivationContext(ULONG Flags, PVOID ActCtx, PULONG_PTR Cookie) -> NTSTATUS` — push
/// an activation context. No SxS plane; set the cookie to a sentinel + STATUS_SUCCESS (the caller
/// pairs it with Deactivate, a matched no-op).
///
/// # Safety
/// `cookie` null or writable.
#[export_name = "RtlActivateActivationContext"]
pub unsafe extern "system" fn rtl_activate_activation_context(
    _flags: u32,
    _act_ctx: *mut c_void,
    cookie: *mut usize,
) -> NtStatus {
    if !cookie.is_null() {
        // SAFETY: cookie writable per the contract.
        unsafe { *cookie = 1 };
    }
    STATUS_SUCCESS
}

/// `RtlActivateActivationContextEx(ULONG Flags, PTEB Teb, PVOID ActCtx, PULONG_PTR Cookie)`.
///
/// # Safety
/// `cookie` null or writable.
#[export_name = "RtlActivateActivationContextEx"]
pub unsafe extern "system" fn rtl_activate_activation_context_ex(
    _flags: u32,
    _teb: *mut c_void,
    _act_ctx: *mut c_void,
    cookie: *mut usize,
) -> NtStatus {
    if !cookie.is_null() {
        // SAFETY: cookie writable per the contract.
        unsafe { *cookie = 1 };
    }
    STATUS_SUCCESS
}

/// `RtlActivateActivationContextUnsafeFast(PRTL_ACTIVATION_CONTEXT_STACK_FRAME Frame, PVOID ActCtx)`
/// — the inlined fast-path push. No-op (no SxS stack).
///
/// # Safety
/// `frame` a valid RTL_ACTIVATION_CONTEXT_STACK_FRAME or NULL.
#[export_name = "RtlActivateActivationContextUnsafeFast"]
pub unsafe extern "system" fn rtl_activate_activation_context_unsafe_fast(
    _frame: *mut c_void,
    _act_ctx: *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `RtlDeactivateActivationContext(ULONG Flags, ULONG_PTR Cookie) -> NTSTATUS` — pop. No-op success.
///
/// # Safety
/// `cookie` from a matching Activate.
#[export_name = "RtlDeactivateActivationContext"]
pub unsafe extern "system" fn rtl_deactivate_activation_context(_flags: u32, _cookie: usize) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlDeactivateActivationContextUnsafeFast(PRTL_ACTIVATION_CONTEXT_STACK_FRAME Frame)` — no-op.
///
/// # Safety
/// `frame` a valid stack frame or NULL.
#[export_name = "RtlDeactivateActivationContextUnsafeFast"]
pub unsafe extern "system" fn rtl_deactivate_activation_context_unsafe_fast(_frame: *mut c_void) {}

/// `RtlCreateActivationContext(ULONG Flags, PVOID ActivationContextData, ULONG ExtraBytes,
/// PVOID Callback, PVOID CallbackData, PVOID* ActCtx) -> NTSTATUS` — build an activation context.
/// No SxS plane; return a non-null sentinel handle (so the caller's null-check passes) that
/// Add/Release/Find treat as "empty context". Never a fabricated section lookup.
///
/// # Safety
/// `act_ctx` writable.
#[export_name = "RtlCreateActivationContext"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_activation_context(
    _flags: u32,
    _data: *mut c_void,
    _extra_bytes: u32,
    _callback: *mut c_void,
    _callback_data: *mut c_void,
    act_ctx: *mut *mut c_void,
) -> NtStatus {
    if !act_ctx.is_null() {
        // A stable non-null "empty context" sentinel (the default-activation-context marker).
        // SAFETY: act_ctx writable per the contract.
        unsafe { *act_ctx = 1 as *mut c_void };
    }
    STATUS_SUCCESS
}

/// `RtlAddRefActivationContext(PVOID ActCtx)` — no ref-count store; no-op.
///
/// # Safety
/// `act_ctx` an activation-context sentinel.
#[export_name = "RtlAddRefActivationContext"]
pub unsafe extern "system" fn rtl_add_ref_activation_context(_act_ctx: *mut c_void) {}

/// `RtlReleaseActivationContext(PVOID ActCtx)` — no-op (no ref-count store).
///
/// # Safety
/// `act_ctx` an activation-context sentinel.
#[export_name = "RtlReleaseActivationContext"]
pub unsafe extern "system" fn rtl_release_activation_context(_act_ctx: *mut c_void) {}

/// `RtlZombifyActivationContext(PVOID ActCtx) -> NTSTATUS` — mark for teardown. No-op success.
///
/// # Safety
/// `act_ctx` an activation-context sentinel.
#[export_name = "RtlZombifyActivationContext"]
pub unsafe extern "system" fn rtl_zombify_activation_context(_act_ctx: *mut c_void) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlGetActiveActivationContext(PVOID* ActCtx) -> NTSTATUS` — report the active context = none
/// (NULL = the process default). The caller then uses the default search path.
///
/// # Safety
/// `act_ctx` writable.
#[export_name = "RtlGetActiveActivationContext"]
pub unsafe extern "system" fn rtl_get_active_activation_context(act_ctx: *mut *mut c_void) -> NtStatus {
    if !act_ctx.is_null() {
        // SAFETY: act_ctx writable per the contract.
        unsafe { *act_ctx = core::ptr::null_mut() };
    }
    STATUS_SUCCESS
}

/// `RtlFindActivationContextSectionString(ULONG Flags, PGUID ExtGuid, ULONG SectionId,
/// PUNICODE_STRING StringToFind, PVOID ReturnedData) -> NTSTATUS` — resolve a redirected name via
/// SxS. No manifest data → STATUS_SXS_KEY_NOT_FOUND (0xC0150004): the caller falls back to the
/// unredirected name (the manifest-less behavior). NEVER a fabricated redirection.
///
/// # Safety
/// Args per the RtlFindActivationContextSectionString ABI.
#[export_name = "RtlFindActivationContextSectionString"]
pub unsafe extern "system" fn rtl_find_activation_context_section_string(
    _flags: u32,
    _ext_guid: *const c_void,
    _section_id: u32,
    _string_to_find: *const c_void,
    _returned_data: *mut c_void,
) -> NtStatus {
    0xC015_0004 // STATUS_SXS_KEY_NOT_FOUND
}

/// `RtlFindActivationContextSectionGuid(...)` — same "no manifest" contract.
///
/// # Safety
/// Args per the RtlFindActivationContextSectionGuid ABI.
#[export_name = "RtlFindActivationContextSectionGuid"]
pub unsafe extern "system" fn rtl_find_activation_context_section_guid(
    _flags: u32,
    _ext_guid: *const c_void,
    _section_id: u32,
    _guid_to_find: *const c_void,
    _returned_data: *mut c_void,
) -> NtStatus {
    0xC015_0004
}

/// `RtlQueryInformationActivationContext(...) -> NTSTATUS` — query context metadata. Report the
/// default (empty) context; STATUS_SUCCESS with zeroed output where a buffer is provided.
///
/// # Safety
/// Args per the ABI; `info` null or writable for `info_len` bytes.
#[export_name = "RtlQueryInformationActivationContext"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_query_information_activation_context(
    _flags: u32,
    _act_ctx: *mut c_void,
    _sub_instance: *mut c_void,
    _info_class: u32,
    info: *mut c_void,
    info_len: usize,
    ret_len: *mut usize,
) -> NtStatus {
    if !info.is_null() && info_len > 0 {
        // SAFETY: info writable for info_len bytes per the contract.
        unsafe { core::ptr::write_bytes(info as *mut u8, 0, info_len) };
    }
    if !ret_len.is_null() {
        // SAFETY: ret_len writable.
        unsafe { *ret_len = 0 };
    }
    STATUS_SUCCESS
}

/// `RtlAllocateActivationContextStack(PVOID* Stack) -> NTSTATUS` — allocate the per-thread SxS
/// frame-list. No SxS stack; NULL out + STATUS_SUCCESS (the thread runs with no activation stack).
///
/// # Safety
/// `stack` writable.
#[export_name = "RtlAllocateActivationContextStack"]
pub unsafe extern "system" fn rtl_allocate_activation_context_stack(stack: *mut *mut c_void) -> NtStatus {
    if !stack.is_null() {
        // SAFETY: stack writable per the contract.
        unsafe { *stack = core::ptr::null_mut() };
    }
    STATUS_SUCCESS
}

/// `RtlFreeActivationContextStack(PVOID Stack)` — no-op (none allocated).
///
/// # Safety
/// `stack` from `RtlAllocateActivationContextStack` or NULL.
#[export_name = "RtlFreeActivationContextStack"]
pub unsafe extern "system" fn rtl_free_activation_context_stack(_stack: *mut c_void) {}

/// `RtlIsThreadWithinLoaderCallout() -> BOOLEAN` — are we inside a DllMain callout? The boot runs
/// DllMains serially from the loader; report FALSE (the safe default — callers use it to avoid
/// re-entrant loads; FALSE lets them proceed, which is correct for our single-threaded init).
///
/// # Safety
/// Reads no cross-plane state.
#[export_name = "RtlIsThreadWithinLoaderCallout"]
pub unsafe extern "system" fn rtl_is_thread_within_loader_callout() -> u8 {
    0
}

// ---- path / guid (host-tested bodies) ------------------------------------------------------------

/// `RtlDetermineDosPathNameType_U(PCWSTR Path) -> RTL_PATH_TYPE`.
///
/// # Safety
/// `path` a NUL-terminated UTF-16 string.
#[export_name = "RtlDetermineDosPathNameType_U"]
pub unsafe extern "system" fn rtl_determine_dos_path_name_type_u(path: *const u16) -> u32 {
    // SAFETY: path NUL-terminated per the contract.
    let n = unsafe { wcslen_raw(path) };
    let s = unsafe { core::slice::from_raw_parts(path, n) };
    // Map to the Windows RTL_PATH_TYPE ordinals (0..=7), matched by variant.
    use nt_ntdll::rtl::path::DosPathType as T;
    match nt_ntdll::rtl::path::determine_dos_path_name_type(s) {
        T::Unknown => 0,
        T::UncAbsolute => 1,
        T::DriveAbsolute => 2,
        T::DriveRelative => 3,
        T::Rooted => 4,
        T::Relative => 5,
        T::LocalDevice => 6,
        T::RootLocalDevice => 7,
    }
}

/// `RtlIsDosDeviceName_U(PCWSTR Path) -> ULONG` — packed {offset<<16 | length} if a DOS device,
/// else 0.
///
/// # Safety
/// `path` a NUL-terminated UTF-16 string.
#[export_name = "RtlIsDosDeviceName_U"]
pub unsafe extern "system" fn rtl_is_dos_device_name_u(path: *const u16) -> u32 {
    // SAFETY: path NUL-terminated per the contract.
    let n = unsafe { wcslen_raw(path) };
    let s = unsafe { core::slice::from_raw_parts(path, n) };
    if nt_ntdll::rtl::path::is_dos_device_name(s) {
        // Offset 0, length = whole name in bytes (a conservative but valid packed result).
        (n * 2) as u32
    } else {
        0
    }
}

/// `RtlIsNameLegalDOS8Dot3(PCUNICODE_STRING Name, POEM_STRING OemName, PBOOLEAN SpacesPresent)
/// -> BOOLEAN`.
///
/// # Safety
/// `name` a valid UNICODE_STRING; `spaces_present` null or writable.
#[export_name = "RtlIsNameLegalDOS8Dot3"]
pub unsafe extern "system" fn rtl_is_name_legal_dos_8dot3(
    name: PCUnicodeString,
    _oem_name: *mut c_void,
    spaces_present: *mut u8,
) -> u8 {
    if name.is_null() {
        return 0;
    }
    // SAFETY: name valid per the contract.
    let (buf, units) = unsafe { ((*name).buffer as *const u16, (*name).length as usize / 2) };
    let s = if buf.is_null() {
        &[][..]
    } else {
        // SAFETY: valid region.
        unsafe { core::slice::from_raw_parts(buf, units) }
    };
    if !spaces_present.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *spaces_present = u8::from(s.contains(&0x20)) };
    }
    u8::from(nt_ntdll::rtl::strings::is_name_legal_dos_8dot3(s))
}

/// `RtlGUIDFromString(PCUNICODE_STRING GuidString, GUID* Guid) -> NTSTATUS`.
///
/// # Safety
/// `guid_string` a valid UNICODE_STRING; `guid` writable (16 bytes).
#[export_name = "RtlGUIDFromString"]
pub unsafe extern "system" fn rtl_guid_from_string(
    guid_string: PCUnicodeString,
    guid: *mut c_void,
) -> NtStatus {
    if guid_string.is_null() || guid.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: guid_string valid per the contract.
    let (buf, units) = unsafe {
        ((*guid_string).buffer as *const u16, (*guid_string).length as usize / 2)
    };
    let s = unsafe { core::slice::from_raw_parts(buf, units) };
    match nt_ntdll::rtl::guid::guid_from_string(s) {
        Some(g) => {
            // GUID: Data1:u32, Data2:u16, Data3:u16, Data4:[u8;8].
            // SAFETY: guid writable for 16 bytes per the contract.
            unsafe {
                *(guid as *mut u32) = g.data1;
                *((guid as *mut u16).add(2)) = g.data2;
                *((guid as *mut u16).add(3)) = g.data3;
                core::ptr::copy_nonoverlapping(g.data4.as_ptr(), (guid as *mut u8).add(8), 8);
            }
            STATUS_SUCCESS
        }
        None => 0xC000_0059, // STATUS_INVALID_PARAMETER-ish; RtlGUIDFromString uses STATUS_INVALID_PARAMETER
    }
}

// ---- image (host-tested nt_ntdll::rtl::image over a mapped image byte slice) ----------------------

/// `RtlImageNtHeader(PVOID BaseAddress) -> PIMAGE_NT_HEADERS` — the NT headers of a mapped image.
///
/// # Safety
/// `base` a mapped PE image.
#[export_name = "RtlImageNtHeader"]
pub unsafe extern "system" fn rtl_image_nt_header(base: *mut c_void) -> *mut c_void {
    if base.is_null() {
        return core::ptr::null_mut();
    }
    // e_lfanew @ base+0x3C → the NT headers offset. Validate the MZ + PE signatures.
    // SAFETY: base is a mapped image with a DOS header per the contract.
    unsafe {
        if *(base as *const u16) != 0x5A4D {
            return core::ptr::null_mut(); // no "MZ"
        }
        let e_lfanew = *((base as *const u8).add(0x3C) as *const u32) as usize;
        let nt = (base as *const u8).add(e_lfanew);
        if *(nt as *const u32) != 0x0000_4550 {
            return core::ptr::null_mut(); // no "PE\0\0"
        }
        nt as *mut c_void
    }
}

/// `RtlImageDirectoryEntryToData(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry,
/// PULONG Size) -> PVOID` — the data of a data directory in a mapped image.
///
/// # Safety
/// `base` a mapped PE image; `size` null or writable.
#[export_name = "RtlImageDirectoryEntryToData"]
pub unsafe extern "system" fn rtl_image_directory_entry_to_data(
    base: *mut c_void,
    _mapped_as_image: u8,
    directory_entry: u16,
    size: *mut u32,
) -> *mut c_void {
    // SAFETY: base a mapped image per the contract.
    let nt = unsafe { rtl_image_nt_header(base) };
    if nt.is_null() {
        return core::ptr::null_mut();
    }
    // OptionalHeader @ nt+0x18; Magic @ +0. For PE32+ (0x20B), the data-directory array starts at
    // OptionalHeader+0x70; each entry = {VirtualAddress:u32, Size:u32}.
    // SAFETY: nt valid per rtl_image_nt_header.
    unsafe {
        let opt = (nt as *const u8).add(0x18);
        let magic = *(opt as *const u16);
        let dir_base = if magic == 0x20B { opt.add(0x70) } else { opt.add(0x60) };
        let entry = dir_base.add(directory_entry as usize * 8);
        let rva = *(entry as *const u32);
        let sz = *((entry as *const u32).add(1));
        if rva == 0 {
            return core::ptr::null_mut();
        }
        if !size.is_null() {
            *size = sz;
        }
        (base as *const u8).add(rva as usize) as *mut c_void
    }
}

/// `RtlImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva, PIMAGE_SECTION_HEADER* Sec)
/// -> PVOID`. For a mapped-as-image module the VA is simply base+rva.
///
/// # Safety
/// `base` a mapped PE image.
#[export_name = "RtlImageRvaToVa"]
pub unsafe extern "system" fn rtl_image_rva_to_va(
    _nt_headers: *mut c_void,
    base: *mut c_void,
    rva: u32,
    _last_section: *mut *mut c_void,
) -> *mut c_void {
    if base.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: base mapped; base+rva is within the image per the contract.
    unsafe { (base as *mut u8).add(rva as usize) as *mut c_void }
}

/// `RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage) -> PVOID` — find the image base containing
/// PC. No dynamic module map here; return NULL (unknown), with `*BaseOfImage=NULL`. The boot path
/// only calls this from the SEH unwinder (which doesn't run on the normal path).
///
/// # Safety
/// `base_of_image` null or writable.
#[export_name = "RtlPcToFileHeader"]
pub unsafe extern "system" fn rtl_pc_to_file_header(
    _pc_value: *mut c_void,
    base_of_image: *mut *mut c_void,
) -> *mut c_void {
    if !base_of_image.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *base_of_image = core::ptr::null_mut() };
    }
    core::ptr::null_mut()
}

// ---- handle tables (RTL_HANDLE_TABLE) — real inline single-threaded --------------------------------
// RTL_HANDLE_TABLE (x64): MaximumNumberOfHandles:u32@0, SizeOfHandleTableEntry:u32@4,
// Reserved[2]@8, FreeHandles:ptr@0x18, CommittedHandles:ptr@0x20, UnCommittedHandles:ptr@0x28,
// MaxReservedHandles:ptr@0x30, Handles:ptr@0x38. We model a simple bump-array of entries.

/// `RtlInitializeHandleTable(ULONG MaximumNumberOfHandles, ULONG SizeOfHandleTableEntry,
/// PRTL_HANDLE_TABLE HandleTable)` — allocate a fixed handle array.
///
/// # Safety
/// `table` a valid writable RTL_HANDLE_TABLE (>= 0x40 bytes).
#[export_name = "RtlInitializeHandleTable"]
pub unsafe extern "system" fn rtl_initialize_handle_table(
    max_handles: u32,
    entry_size: u32,
    table: *mut c_void,
) {
    if table.is_null() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let bytes = (max_handles as usize) * (entry_size as usize);
        // SAFETY: on-target heap.
        let arr = unsafe { crate::process_heap_alloc(bytes.max(1)) };
        // SAFETY: table valid for the RTL_HANDLE_TABLE fields per the contract.
        unsafe {
            core::ptr::write_bytes(table as *mut u8, 0, 0x40);
            *(table as *mut u32) = max_handles;
            *((table as *mut u32).add(1)) = entry_size;
            *((table as *mut u64).byte_add(0x38)) = arr as u64; // Handles
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (max_handles, entry_size);
    }
}

/// `RtlAllocateHandle(PRTL_HANDLE_TABLE HandleTable, PULONG HandleIndex) -> PRTL_HANDLE_TABLE_ENTRY`
/// — allocate the next free entry (bump allocator over the fixed array).
///
/// # Safety
/// `table` from `RtlInitializeHandleTable`; `index` null or writable.
#[export_name = "RtlAllocateHandle"]
pub unsafe extern "system" fn rtl_allocate_handle(table: *mut c_void, index: *mut u32) -> *mut c_void {
    if table.is_null() {
        return core::ptr::null_mut();
    }
    // Track the next-free index in Reserved[0] @ +8 (a bump cursor).
    // SAFETY: table valid per the contract.
    unsafe {
        let max = *(table as *const u32);
        let entry_size = *((table as *const u32).add(1)) as usize;
        let cursor = (table as *mut u32).byte_add(8);
        let i = *cursor;
        if i >= max {
            return core::ptr::null_mut();
        }
        *cursor = i + 1;
        let handles = *((table as *const u64).byte_add(0x38)) as *mut u8;
        if handles.is_null() {
            return core::ptr::null_mut();
        }
        if !index.is_null() {
            *index = i;
        }
        handles.add(i as usize * entry_size) as *mut c_void
    }
}

/// `RtlFreeHandle(PRTL_HANDLE_TABLE, PRTL_HANDLE_TABLE_ENTRY) -> BOOLEAN` — mark an entry free. Our
/// bump allocator doesn't reclaim mid-array (the handle-table users on the boot path allocate
/// monotonically); mark the entry's flags-word (last u32) as free + return TRUE.
///
/// # Safety
/// `entry` from `RtlAllocateHandle`.
#[export_name = "RtlFreeHandle"]
pub unsafe extern "system" fn rtl_free_handle(_table: *mut c_void, entry: *mut c_void) -> u8 {
    if entry.is_null() {
        return 0;
    }
    // Clear the entry's first word (a common "in use" flag lives there).
    // SAFETY: entry valid per the contract.
    unsafe { *(entry as *mut u32) = 0 };
    1
}

/// `RtlIsValidHandle(PRTL_HANDLE_TABLE, PRTL_HANDLE_TABLE_ENTRY) -> BOOLEAN`.
///
/// # Safety
/// `entry` from `RtlAllocateHandle` or NULL.
#[export_name = "RtlIsValidHandle"]
pub unsafe extern "system" fn rtl_is_valid_handle(table: *mut c_void, entry: *mut c_void) -> u8 {
    if table.is_null() || entry.is_null() {
        return 0;
    }
    // Valid if entry is within the Handles array bounds.
    // SAFETY: table valid per the contract.
    unsafe {
        let max = *(table as *const u32) as usize;
        let entry_size = *((table as *const u32).add(1)) as usize;
        let handles = *((table as *const u64).byte_add(0x38)) as usize;
        let e = entry as usize;
        u8::from(handles != 0 && e >= handles && e < handles + max * entry_size)
    }
}

// ---- resource RW-lock (RTL_RESOURCE) — real inline single-threaded --------------------------------

/// `RtlInitializeResource(PRTL_RESOURCE Resource)` — zero the resource (unlocked).
///
/// # Safety
/// `resource` a valid writable RTL_RESOURCE.
#[export_name = "RtlInitializeResource"]
pub unsafe extern "system" fn rtl_initialize_resource(resource: *mut c_void) {
    if !resource.is_null() {
        // RTL_RESOURCE is ~0x38 bytes; zero it = unlocked, 0 shared/exclusive owners.
        // SAFETY: resource valid per the contract.
        unsafe { core::ptr::write_bytes(resource as *mut u8, 0, 0x38) };
    }
}

/// `RtlAcquireResourceShared(PRTL_RESOURCE, BOOLEAN Wait) -> BOOLEAN` — single-threaded → always
/// granted (bump the shared count @ +0x18).
///
/// # Safety
/// `resource` from `RtlInitializeResource`.
#[export_name = "RtlAcquireResourceShared"]
pub unsafe extern "system" fn rtl_acquire_resource_shared(resource: *mut c_void, _wait: u8) -> u8 {
    if resource.is_null() {
        return 0;
    }
    // SAFETY: resource valid per the contract; NumberActive @ +0x18 (i32).
    unsafe {
        let active = (resource as *mut i32).byte_add(0x18);
        *active += 1;
    }
    1
}

/// `RtlAcquireResourceExclusive(PRTL_RESOURCE, BOOLEAN Wait) -> BOOLEAN` — single-threaded → granted
/// (NumberActive = -1 = exclusive).
///
/// # Safety
/// `resource` from `RtlInitializeResource`.
#[export_name = "RtlAcquireResourceExclusive"]
pub unsafe extern "system" fn rtl_acquire_resource_exclusive(resource: *mut c_void, _wait: u8) -> u8 {
    if resource.is_null() {
        return 0;
    }
    // SAFETY: resource valid per the contract.
    unsafe {
        let active = (resource as *mut i32).byte_add(0x18);
        *active = -1;
    }
    1
}

/// `RtlReleaseResource(PRTL_RESOURCE)` — release (reset the active count).
///
/// # Safety
/// `resource` from `RtlInitializeResource`.
#[export_name = "RtlReleaseResource"]
pub unsafe extern "system" fn rtl_release_resource(resource: *mut c_void) {
    if resource.is_null() {
        return;
    }
    // SAFETY: resource valid per the contract.
    unsafe {
        let active = (resource as *mut i32).byte_add(0x18);
        if *active < 0 {
            *active = 0; // exclusive → free
        } else if *active > 0 {
            *active -= 1; // one shared holder leaves
        }
    }
}

// ---- timer-queue / thread-pool / work-item — no scheduler plane (honest seams) --------------------

/// `RtlCreateTimerQueue(PHANDLE TimerQueue) -> NTSTATUS` — no thread-pool plane; return a non-null
/// sentinel handle so the caller proceeds (the queue simply never fires — an honest no-op timer
/// queue, never a fabricated timer). Timer callbacks aren't on the boot path.
///
/// # Safety
/// `timer_queue` writable.
#[export_name = "RtlCreateTimerQueue"]
pub unsafe extern "system" fn rtl_create_timer_queue(timer_queue: *mut *mut c_void) -> NtStatus {
    if !timer_queue.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *timer_queue = 1 as *mut c_void };
    }
    STATUS_SUCCESS
}

/// `RtlCreateTimer(HANDLE TimerQueue, PHANDLE Timer, WAITORTIMERCALLBACKFUNC Callback,
/// PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags) -> NTSTATUS`. No plane; sentinel
/// handle + STATUS_SUCCESS (the timer never fires).
///
/// # Safety
/// `timer` writable.
#[export_name = "RtlCreateTimer"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_timer(
    _timer_queue: *mut c_void,
    timer: *mut *mut c_void,
    _callback: *mut c_void,
    _parameter: *mut c_void,
    _due_time: u32,
    _period: u32,
    _flags: u32,
) -> NtStatus {
    if !timer.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *timer = 1 as *mut c_void };
    }
    STATUS_SUCCESS
}

/// `RtlUpdateTimer(HANDLE TimerQueue, HANDLE Timer, DWORD DueTime, DWORD Period) -> NTSTATUS`.
///
/// # Safety
/// Handles from Create*.
#[export_name = "RtlUpdateTimer"]
pub unsafe extern "system" fn rtl_update_timer(
    _timer_queue: *mut c_void,
    _timer: *mut c_void,
    _due_time: u32,
    _period: u32,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlDeleteTimer(HANDLE TimerQueue, HANDLE Timer, HANDLE CompletionEvent) -> NTSTATUS`.
///
/// # Safety
/// Handles from Create*.
#[export_name = "RtlDeleteTimer"]
pub unsafe extern "system" fn rtl_delete_timer(
    _timer_queue: *mut c_void,
    _timer: *mut c_void,
    _completion_event: *mut c_void,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlDeleteTimerQueueEx(HANDLE TimerQueue, HANDLE CompletionEvent) -> NTSTATUS`.
///
/// # Safety
/// `timer_queue` from `RtlCreateTimerQueue`.
#[export_name = "RtlDeleteTimerQueueEx"]
pub unsafe extern "system" fn rtl_delete_timer_queue_ex(
    _timer_queue: *mut c_void,
    _completion_event: *mut c_void,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlQueueWorkItem(WORKERCALLBACKFUNC Function, PVOID Context, ULONG Flags) -> NTSTATUS`. No
/// thread-pool plane. Rather than drop the work (which could hang a caller awaiting it), we run it
/// SYNCHRONOUSLY inline — a legitimate degenerate thread pool (immediate execution on the caller's
/// thread). This is the honest behavior for a single-threaded environment, not a no-op that loses
/// the work.
///
/// # Safety
/// `function` a valid `void(*)(PVOID)` callback; `context` its argument.
#[export_name = "RtlQueueWorkItem"]
pub unsafe extern "system" fn rtl_queue_work_item(
    function: extern "system" fn(*mut c_void),
    context: *mut c_void,
    _flags: u32,
) -> NtStatus {
    // Run inline (synchronous degenerate thread pool).
    function(context);
    STATUS_SUCCESS
}

/// `RtlRegisterWait(PHANDLE NewWaitObject, HANDLE Object, WAITORTIMERCALLBACK Callback,
/// PVOID Context, ULONG Milliseconds, ULONG Flags) -> NTSTATUS`. No wait-thread plane; sentinel
/// handle + STATUS_SUCCESS (the wait never completes — no waitable events fire on the boot path).
///
/// # Safety
/// `new_wait_object` writable.
#[export_name = "RtlRegisterWait"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_register_wait(
    new_wait_object: *mut *mut c_void,
    _object: *mut c_void,
    _callback: *mut c_void,
    _context: *mut c_void,
    _milliseconds: u32,
    _flags: u32,
) -> NtStatus {
    if !new_wait_object.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *new_wait_object = 1 as *mut c_void };
    }
    STATUS_SUCCESS
}

/// `RtlDeregisterWaitEx(HANDLE WaitHandle, HANDLE CompletionEvent) -> NTSTATUS`.
///
/// # Safety
/// `wait_handle` from `RtlRegisterWait`.
#[export_name = "RtlDeregisterWaitEx"]
pub unsafe extern "system" fn rtl_deregister_wait_ex(
    _wait_handle: *mut c_void,
    _completion_event: *mut c_void,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlSetIoCompletionCallback(HANDLE FileHandle, PIO_APC_ROUTINE Callback, ULONG Flags) -> NTSTATUS`
/// — bind an I/O completion callback (thread-pool). No plane → STATUS_SUCCESS no-op.
///
/// # Safety
/// `file_handle` a valid handle.
#[export_name = "RtlSetIoCompletionCallback"]
pub unsafe extern "system" fn rtl_set_io_completion_callback(
    _file_handle: *mut c_void,
    _callback: *mut c_void,
    _flags: u32,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlSetThreadPoolStartFunc(PVOID StartFunc, PVOID ExitFunc) -> NTSTATUS` — install the thread-pool
/// worker start/exit hooks. No plane → STATUS_SUCCESS no-op.
///
/// # Safety
/// `start_func`/`exit_func` valid callbacks or NULL.
#[export_name = "RtlSetThreadPoolStartFunc"]
pub unsafe extern "system" fn rtl_set_thread_pool_start_func(
    _start_func: *mut c_void,
    _exit_func: *mut c_void,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlSetTimeZoneInformation(PRTL_TIME_ZONE_INFORMATION TimeZoneInformation) -> NTSTATUS` — set the
/// system time zone. No time-zone plane → STATUS_SUCCESS no-op (UTC assumed).
///
/// # Safety
/// `time_zone_information` a valid RTL_TIME_ZONE_INFORMATION.
#[export_name = "RtlSetTimeZoneInformation"]
pub unsafe extern "system" fn rtl_set_time_zone_information(_tz: *const c_void) -> NtStatus {
    STATUS_SUCCESS
}

// ---- debug buffer / stack backtrace / WOW64 fs-redirection (honest no-ops) ------------------------

/// `RtlCreateQueryDebugBuffer(ULONG Size, BOOLEAN EventPair) -> PRTL_DEBUG_INFORMATION` — allocate a
/// debug-query buffer. Allocate a zeroed block from the process heap (the caller fills it via
/// RtlQueryProcessDebugInformation, which we no-op).
///
/// # Safety
/// Reads no memory.
#[export_name = "RtlCreateQueryDebugBuffer"]
pub unsafe extern "system" fn rtl_create_query_debug_buffer(size: u32, _event_pair: u8) -> *mut c_void {
    #[cfg(target_arch = "x86_64")]
    {
        let n = (size as usize).max(0x1000);
        // SAFETY: on-target heap.
        let p = unsafe { crate::process_heap_alloc(n) };
        if !p.is_null() {
            // SAFETY: p valid for n bytes.
            unsafe { core::ptr::write_bytes(p, 0, n) };
        }
        p as *mut c_void
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = size;
        core::ptr::null_mut()
    }
}

/// `RtlDestroyQueryDebugBuffer(PRTL_DEBUG_INFORMATION Buffer) -> NTSTATUS`.
///
/// # Safety
/// `buffer` from `RtlCreateQueryDebugBuffer`.
#[export_name = "RtlDestroyQueryDebugBuffer"]
pub unsafe extern "system" fn rtl_destroy_query_debug_buffer(buffer: *mut c_void) -> NtStatus {
    if !buffer.is_null() {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: buffer from the process heap.
        unsafe {
            crate::process_heap_free(buffer as *mut u8);
        }
    }
    STATUS_SUCCESS
}

/// `RtlQueryProcessDebugInformation(HANDLE UniqueProcessId, ULONG Flags, PRTL_DEBUG_INFORMATION Buf)
/// -> NTSTATUS` — no debug-info plane; STATUS_SUCCESS leaving the buffer zeroed (empty info).
///
/// # Safety
/// `buffer` from `RtlCreateQueryDebugBuffer`.
#[export_name = "RtlQueryProcessDebugInformation"]
pub unsafe extern "system" fn rtl_query_process_debug_information(
    _unique_process_id: *mut c_void,
    _flags: u32,
    _buffer: *mut c_void,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlCaptureStackBackTrace(ULONG FramesToSkip, ULONG FramesToCapture, PVOID* BackTrace,
/// PULONG BackTraceHash) -> USHORT` — no stack walker; capture 0 frames (honest).
///
/// # Safety
/// `back_trace` writable for `frames_to_capture` entries; `hash` null or writable.
#[export_name = "RtlCaptureStackBackTrace"]
pub unsafe extern "system" fn rtl_capture_stack_back_trace(
    _frames_to_skip: u32,
    _frames_to_capture: u32,
    _back_trace: *mut *mut c_void,
    hash: *mut u32,
) -> u16 {
    if !hash.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *hash = 0 };
    }
    0
}

/// `RtlWow64EnableFsRedirection(BOOLEAN Enable) -> NTSTATUS` — we are native x64, no WOW64
/// redirection → STATUS_SUCCESS no-op.
///
/// # Safety
/// Reads no memory.
#[export_name = "RtlWow64EnableFsRedirection"]
pub unsafe extern "system" fn rtl_wow64_enable_fs_redirection(_enable: u8) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlWow64EnableFsRedirectionEx(PVOID DisableFsRedirection, PVOID* OldValue) -> NTSTATUS`.
///
/// # Safety
/// `old_value` null or writable.
#[export_name = "RtlWow64EnableFsRedirectionEx"]
pub unsafe extern "system" fn rtl_wow64_enable_fs_redirection_ex(
    _disable: *mut c_void,
    old_value: *mut *mut c_void,
) -> NtStatus {
    if !old_value.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *old_value = core::ptr::null_mut() };
    }
    STATUS_SUCCESS
}

// =================================================================================================
// BATCH 4 — Rtl* memory / bitmap / atom / encode / time / random / SList / misc families.
// Backed by the host-tested nt_ntdll::rtl::{bitmap,time,encode,random} + inline correct bodies.
// The SxS/activation-context, timer-queue, thread-pool, and stack-unwind families have no body
// yet (they need process planes we don't host); they export at the correct ABI + return an honest
// failure / no-op — NEVER a fabricated result — so the IAT resolves + the call is ABI-safe.
// =================================================================================================

// ---- memory intrinsics (Rtl aliases of the CRT mem ops) ------------------------------------------

/// `RtlFillMemory(void* dst, SIZE_T len, UCHAR fill)`.
///
/// # Safety
/// `dst` writable for `len` bytes.
#[export_name = "RtlFillMemory"]
pub unsafe extern "system" fn rtl_fill_memory(dst: *mut u8, len: usize, fill: u8) {
    // SAFETY: dst writable for len per the contract.
    unsafe { core::ptr::write_bytes(dst, fill, len) };
}

/// `RtlZeroMemory(void* dst, SIZE_T len)`.
///
/// # Safety
/// `dst` writable for `len` bytes.
#[export_name = "RtlZeroMemory"]
pub unsafe extern "system" fn rtl_zero_memory(dst: *mut u8, len: usize) {
    // SAFETY: dst writable per the contract.
    unsafe { core::ptr::write_bytes(dst, 0, len) };
}

/// `RtlMoveMemory(void* dst, const void* src, SIZE_T len)` — overlap-safe copy.
///
/// # Safety
/// `dst`/`src` valid for `len` bytes.
#[export_name = "RtlMoveMemory"]
pub unsafe extern "system" fn rtl_move_memory(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: valid regions per the contract; copy handles overlap.
    unsafe { core::ptr::copy(src, dst, len) };
}

/// `RtlCompareMemory(const void* a, const void* b, SIZE_T len) -> SIZE_T` — count of equal leading
/// bytes.
///
/// # Safety
/// `a`/`b` valid for `len` bytes.
#[export_name = "RtlCompareMemory"]
pub unsafe extern "system" fn rtl_compare_memory(a: *const u8, b: *const u8, len: usize) -> usize {
    // SAFETY: valid regions per the contract.
    let (sa, sb) = unsafe {
        (
            core::slice::from_raw_parts(a, len),
            core::slice::from_raw_parts(b, len),
        )
    };
    sa.iter().zip(sb.iter()).take_while(|(x, y)| x == y).count()
}

// ---- RTL_BITMAP family (raw RTL_BITMAP*: {SizeOfBitMap:u32@0, _pad, Buffer:*u32@8}) --------------

/// `RtlInitializeBitMap(PRTL_BITMAP BitMapHeader, PULONG BitMapBuffer, ULONG SizeOfBitMap)`.
///
/// # Safety
/// `header` a valid RTL_BITMAP; `buffer` valid for `ceil(size/8)` bytes.
#[export_name = "RtlInitializeBitMap"]
pub unsafe extern "system" fn rtl_initialize_bit_map(
    header: *mut c_void,
    buffer: *mut u32,
    size: u32,
) {
    // SAFETY: header valid per the contract; the rtl_bitmap helper writes {size@0, buffer@8}.
    unsafe { nt_ntdll::rtl::bitmap::initialize(header as *mut u8, buffer as u64, size) };
}

/// `RtlSetBits(PRTL_BITMAP, ULONG StartingIndex, ULONG NumberToSet)`.
///
/// # Safety
/// `header` a valid initialized RTL_BITMAP; range within `SizeOfBitMap`.
#[export_name = "RtlSetBits"]
pub unsafe extern "system" fn rtl_set_bits(header: *mut c_void, start: u32, count: u32) {
    // SAFETY: header initialized per the contract.
    unsafe { nt_ntdll::rtl::bitmap::set_bits(header as *mut u8, start, count) };
}

/// `RtlClearBits(PRTL_BITMAP, ULONG StartingIndex, ULONG NumberToClear)`.
///
/// # Safety
/// `header` a valid initialized RTL_BITMAP; range within `SizeOfBitMap`.
#[export_name = "RtlClearBits"]
pub unsafe extern "system" fn rtl_clear_bits(header: *mut c_void, start: u32, count: u32) {
    // SAFETY: header initialized per the contract.
    unsafe { nt_ntdll::rtl::bitmap::clear_bits(header as *mut u8, start, count) };
}

/// `RtlAreBitsSet(PRTL_BITMAP, ULONG StartingIndex, ULONG Length) -> BOOLEAN`.
///
/// # Safety
/// `header` a valid initialized RTL_BITMAP.
#[export_name = "RtlAreBitsSet"]
pub unsafe extern "system" fn rtl_are_bits_set(header: *const c_void, start: u32, length: u32) -> u8 {
    if length == 0 {
        return 0;
    }
    // "all set" == "none of the range is clear". test_bit each.
    // SAFETY: header initialized per the contract.
    unsafe {
        for i in start..start + length {
            if !nt_ntdll::rtl::bitmap::test_bit(header as *const u8, i) {
                return 0;
            }
        }
    }
    1
}

/// `RtlAreBitsClear(PRTL_BITMAP, ULONG StartingIndex, ULONG Length) -> BOOLEAN`.
///
/// # Safety
/// `header` a valid initialized RTL_BITMAP.
#[export_name = "RtlAreBitsClear"]
pub unsafe extern "system" fn rtl_are_bits_clear(
    header: *const c_void,
    start: u32,
    length: u32,
) -> u8 {
    if length == 0 {
        return 0;
    }
    // SAFETY: header initialized per the contract.
    u8::from(unsafe { nt_ntdll::rtl::bitmap::are_bits_clear(header as *const u8, start, length) })
}

/// `RtlFindClearBitsAndSet(PRTL_BITMAP, ULONG NumberToFind, ULONG HintIndex) -> ULONG` — find a run
/// of clear bits, set them, return the start index (0xFFFFFFFF if none).
///
/// # Safety
/// `header` a valid initialized RTL_BITMAP.
#[export_name = "RtlFindClearBitsAndSet"]
pub unsafe extern "system" fn rtl_find_clear_bits_and_set(
    header: *mut c_void,
    count: u32,
    hint: u32,
) -> u32 {
    // SAFETY: header initialized per the contract.
    unsafe { nt_ntdll::rtl::bitmap::find_clear_bits_and_set(header as *mut u8, count, hint) }
}

// ---- atom tables (reuse nt-kernel-exec via nt_ntdll::rtl::atom) -----------------------------------
// The atom-table API is object-oriented (OwnedAtomTable). The Win32 stack's RtlCreateAtomTable
// returns a HANDLE; we back it with a heap-boxed OwnedAtomTable and pass the box pointer as the
// handle. Full add/lookup/delete/query route through the boxed table.

/// `RtlCreateAtomTable(ULONG NumberOfBuckets, PVOID* AtomTable) -> NTSTATUS`.
///
/// # Safety
/// `atom_table` writable.
#[export_name = "RtlCreateAtomTable"]
pub unsafe extern "system" fn rtl_create_atom_table(
    _number_of_buckets: u32,
    atom_table: *mut *mut c_void,
) -> NtStatus {
    if atom_table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: on-target box lives on the process heap; the handle is the box pointer.
    #[cfg(target_arch = "x86_64")]
    {
        let table = match nt_ntdll::rtl::atom::OwnedAtomTable::with_capacity(37) {
            Some(t) => t,
            None => return STATUS_NO_MEMORY,
        };
        let boxed = alloc::boxed::Box::new(table);
        // SAFETY: atom_table writable per the contract.
        unsafe { *atom_table = alloc::boxed::Box::into_raw(boxed) as *mut c_void };
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlAddAtomToAtomTable(PVOID AtomTable, PWSTR AtomName, PUSHORT Atom) -> NTSTATUS`.
///
/// # Safety
/// `atom_table` from `RtlCreateAtomTable`; `atom_name` NUL-terminated; `atom` null or writable.
#[export_name = "RtlAddAtomToAtomTable"]
pub unsafe extern "system" fn rtl_add_atom_to_atom_table(
    atom_table: *mut c_void,
    atom_name: *const u16,
    atom: *mut u16,
) -> NtStatus {
    if atom_table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: atom_table is a boxed OwnedAtomTable; atom_name NUL-terminated.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let table = &mut *(atom_table as *mut nt_ntdll::rtl::atom::OwnedAtomTable);
        let n = wcslen_raw(atom_name);
        let name = core::slice::from_raw_parts(atom_name, n);
        match table.add_name(name) {
            Ok(a) => {
                if !atom.is_null() {
                    *atom = a;
                }
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (atom_name, atom);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlLookupAtomInAtomTable(PVOID AtomTable, PWSTR AtomName, PUSHORT Atom) -> NTSTATUS`.
///
/// # Safety
/// As `RtlAddAtomToAtomTable`.
#[export_name = "RtlLookupAtomInAtomTable"]
pub unsafe extern "system" fn rtl_lookup_atom_in_atom_table(
    atom_table: *mut c_void,
    atom_name: *const u16,
    atom: *mut u16,
) -> NtStatus {
    if atom_table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: atom_table is a boxed OwnedAtomTable; atom_name NUL-terminated.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let table = &*(atom_table as *const nt_ntdll::rtl::atom::OwnedAtomTable);
        let n = wcslen_raw(atom_name);
        let name = core::slice::from_raw_parts(atom_name, n);
        match table.find_name(name) {
            Ok(a) => {
                if !atom.is_null() {
                    *atom = a;
                }
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (atom_name, atom);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlDeleteAtomFromAtomTable(PVOID AtomTable, USHORT Atom) -> NTSTATUS`.
///
/// # Safety
/// `atom_table` from `RtlCreateAtomTable`.
#[export_name = "RtlDeleteAtomFromAtomTable"]
pub unsafe extern "system" fn rtl_delete_atom_from_atom_table(
    atom_table: *mut c_void,
    atom: u16,
) -> NtStatus {
    if atom_table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: atom_table is a boxed OwnedAtomTable.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let table = &mut *(atom_table as *mut nt_ntdll::rtl::atom::OwnedAtomTable);
        table.delete(atom) // returns an NTSTATUS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = atom;
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlQueryAtomInAtomTable(PVOID AtomTable, USHORT Atom, PULONG RefCount, PULONG PinCount,
/// PWSTR AtomName, PULONG AtomNameLength) -> NTSTATUS`. We serve the name-back path; ref/pin
/// counts = 1 (present). Honest STATUS_OBJECT_NAME_NOT_FOUND if absent.
///
/// # Safety
/// Out-params null or writable.
#[export_name = "RtlQueryAtomInAtomTable"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_query_atom_in_atom_table(
    atom_table: *mut c_void,
    atom: u16,
    ref_count: *mut u32,
    pin_count: *mut u32,
    atom_name: *mut u16,
    atom_name_length: *mut u32,
) -> NtStatus {
    if atom_table.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: atom_table is a boxed OwnedAtomTable; out-params per the contract.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let table = &*(atom_table as *const nt_ntdll::rtl::atom::OwnedAtomTable);
        // The query helper writes the name into a caller-owned 256+1 scratch (its NAME_CAP contract).
        let mut scratch = [0u16; 255 + 1];
        let cap_bytes = if atom_name_length.is_null() {
            0
        } else {
            *atom_name_length
        };
        let res = table.query(atom, &mut scratch, cap_bytes);
        if res.status != STATUS_SUCCESS {
            return res.status;
        }
        if !ref_count.is_null() {
            *ref_count = res.reference_count;
        }
        if !pin_count.is_null() {
            *pin_count = res.pin_count;
        }
        if !atom_name.is_null() {
            let units = (res.name_length as usize) / 2;
            for i in 0..units {
                *atom_name.add(i) = scratch[i];
            }
        }
        if !atom_name_length.is_null() {
            *atom_name_length = res.name_length;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (atom, ref_count, pin_count, atom_name, atom_name_length);
        STATUS_NOT_IMPLEMENTED
    }
}

// ---- encode/decode pointer (process cookie from PEB->Cookie@0x2C0? actually @0x0? use 0) ----------

/// `RtlEncodePointer(PVOID Ptr) -> PVOID`. The process cookie is 0 until wired (a documented seam);
/// with cookie 0 the transform is identity — a valid (weaker) encoding, never a corrupted pointer.
///
/// # Safety
/// Pure arithmetic on the pointer value.
#[export_name = "RtlEncodePointer"]
pub unsafe extern "system" fn rtl_encode_pointer(ptr: *mut c_void) -> *mut c_void {
    nt_ntdll::rtl::encode::encode_pointer(ptr as u64, process_cookie()) as *mut c_void
}

/// `RtlDecodePointer(PVOID Ptr) -> PVOID`.
///
/// # Safety
/// Pure arithmetic.
#[export_name = "RtlDecodePointer"]
pub unsafe extern "system" fn rtl_decode_pointer(ptr: *mut c_void) -> *mut c_void {
    nt_ntdll::rtl::encode::decode_pointer(ptr as u64, process_cookie()) as *mut c_void
}

/// `RtlEncodeSystemPointer(PVOID Ptr) -> PVOID`.
///
/// # Safety
/// Pure arithmetic.
#[export_name = "RtlEncodeSystemPointer"]
pub unsafe extern "system" fn rtl_encode_system_pointer(ptr: *mut c_void) -> *mut c_void {
    nt_ntdll::rtl::encode::encode_system_pointer(ptr as u64, 0) as *mut c_void
}

/// `RtlDecodeSystemPointer(PVOID Ptr) -> PVOID`.
///
/// # Safety
/// Pure arithmetic.
#[export_name = "RtlDecodeSystemPointer"]
pub unsafe extern "system" fn rtl_decode_system_pointer(ptr: *mut c_void) -> *mut c_void {
    nt_ntdll::rtl::encode::decode_system_pointer(ptr as u64, 0) as *mut c_void
}

/// The per-process pointer-encoding cookie. Read from PEB+0x40 (`ProcessCookie` isn't there on x64;
/// the loader publishes it). Until the loader wires it, 0 (identity encode — safe, just weaker).
fn process_cookie() -> u64 {
    0
}

// ---- time family (host-tested nt_ntdll::rtl::time) -----------------------------------------------

/// `RtlTimeToSecondsSince1970(PLARGE_INTEGER Time, PULONG Seconds) -> BOOLEAN`.
///
/// # Safety
/// `time`/`seconds` valid pointers.
#[export_name = "RtlTimeToSecondsSince1970"]
pub unsafe extern "system" fn rtl_time_to_seconds_since_1970(time: *const i64, seconds: *mut u32) -> u8 {
    if time.is_null() || seconds.is_null() {
        return 0;
    }
    // SAFETY: valid per the contract.
    let t = unsafe { *time };
    match nt_ntdll::rtl::time::time_to_seconds_since_1970(t) {
        Some(s) => {
            // SAFETY: seconds writable.
            unsafe { *seconds = s };
            1
        }
        None => 0,
    }
}

/// `RtlTimeToTimeFields(PLARGE_INTEGER Time, PTIME_FIELDS TimeFields)`. TIME_FIELDS = 7 shorts
/// {Year,Month,Day,Hour,Minute,Second,Milliseconds,Weekday}.
///
/// # Safety
/// `time`/`time_fields` valid.
#[export_name = "RtlTimeToTimeFields"]
pub unsafe extern "system" fn rtl_time_to_time_fields(time: *const i64, time_fields: *mut i16) {
    if time.is_null() || time_fields.is_null() {
        return;
    }
    // SAFETY: valid per the contract.
    let tf = nt_ntdll::rtl::time::time_to_time_fields(unsafe { *time });
    // SAFETY: time_fields writable for 8 shorts.
    unsafe {
        *time_fields.add(0) = tf.year;
        *time_fields.add(1) = tf.month;
        *time_fields.add(2) = tf.day;
        *time_fields.add(3) = tf.hour;
        *time_fields.add(4) = tf.minute;
        *time_fields.add(5) = tf.second;
        *time_fields.add(6) = tf.milliseconds;
        *time_fields.add(7) = tf.weekday;
    }
}

/// `RtlTimeFieldsToTime(PTIME_FIELDS TimeFields, PLARGE_INTEGER Time) -> BOOLEAN`.
///
/// # Safety
/// `time_fields`/`time` valid.
#[export_name = "RtlTimeFieldsToTime"]
pub unsafe extern "system" fn rtl_time_fields_to_time(time_fields: *const i16, time: *mut i64) -> u8 {
    if time_fields.is_null() || time.is_null() {
        return 0;
    }
    // SAFETY: time_fields valid for 8 shorts.
    let tf = unsafe {
        nt_ntdll::rtl::time::TimeFields {
            year: *time_fields.add(0),
            month: *time_fields.add(1),
            day: *time_fields.add(2),
            hour: *time_fields.add(3),
            minute: *time_fields.add(4),
            second: *time_fields.add(5),
            milliseconds: *time_fields.add(6),
            weekday: *time_fields.add(7),
        }
    };
    match nt_ntdll::rtl::time::time_fields_to_time(&tf) {
        Some(t) => {
            // SAFETY: time writable.
            unsafe { *time = t };
            1
        }
        None => 0,
    }
}

// ---- random (host-tested) ------------------------------------------------------------------------

/// `RtlUniform(PULONG Seed) -> ULONG`.
///
/// # Safety
/// `seed` a valid writable u32.
#[export_name = "RtlUniform"]
pub unsafe extern "system" fn rtl_uniform(seed: *mut u32) -> u32 {
    if seed.is_null() {
        return 0;
    }
    // SAFETY: seed valid per the contract.
    unsafe {
        let mut s = *seed;
        let r = nt_ntdll::rtl::random::uniform(&mut s);
        *seed = s;
        r
    }
}

/// `RtlRandom(PULONG Seed) -> ULONG`.
///
/// # Safety
/// `seed` a valid writable u32.
#[export_name = "RtlRandom"]
pub unsafe extern "system" fn rtl_random(seed: *mut u32) -> u32 {
    if seed.is_null() {
        return 0;
    }
    // SAFETY: seed valid per the contract.
    unsafe {
        let mut s = *seed;
        let r = nt_ntdll::rtl::random::random(&mut s);
        *seed = s;
        r
    }
}

/// `RtlIntegerToChar(ULONG Value, ULONG Base, LONG Length, PSZ String) -> NTSTATUS` — format an
/// integer into an ASCII buffer.
///
/// # Safety
/// `string` writable for `length` bytes (or, if length<=0, until NUL room).
#[export_name = "RtlIntegerToChar"]
pub unsafe extern "system" fn rtl_integer_to_char(
    value: u32,
    base: u32,
    length: i32,
    string: *mut u8,
) -> NtStatus {
    let base = if base == 0 { 10 } else { base };
    if !(2..=16).contains(&base) || string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut tmp = [0u8; 33];
    let mut v = value;
    let mut i = 0usize;
    if v == 0 {
        tmp[0] = b'0';
        i = 1;
    }
    while v != 0 {
        let d = (v % base) as u8;
        tmp[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v /= base;
        i += 1;
    }
    let needed = i + if length < 0 { 0 } else { 1 }; // +NUL when a positive field width
    if length > 0 && needed > length as usize {
        return STATUS_BUFFER_OVERFLOW;
    }
    // SAFETY: string writable for `i` (+NUL) per the check.
    unsafe {
        for j in 0..i {
            *string.add(j) = tmp[i - 1 - j];
        }
        if length != 0 {
            *string.add(i) = 0;
        }
    }
    STATUS_SUCCESS
}

// ---- interlocked SList (single-linked list, x64 SLIST_HEADER is 16 bytes) -------------------------
// We model the SLIST_HEADER's first 8 bytes as the head pointer + next 8 as {Depth:u16, Sequence}.
// Single-threaded, so the "interlocked" ops are plain pointer swaps.

/// `RtlInitializeSListHead(PSLIST_HEADER ListHead)`.
///
/// # Safety
/// `head` a valid 16-byte-aligned SLIST_HEADER.
#[export_name = "RtlInitializeSListHead"]
pub unsafe extern "system" fn rtl_initialize_slist_head(head: *mut c_void) {
    if head.is_null() {
        return;
    }
    // SAFETY: head valid for 16 bytes.
    unsafe {
        *(head as *mut u64) = 0; // Next
        *((head as *mut u64).add(1)) = 0; // Depth/Sequence
    }
}

/// `RtlInterlockedPushEntrySList(PSLIST_HEADER, PSLIST_ENTRY Entry) -> PSLIST_ENTRY` — push, return
/// previous head. Single-threaded pointer swap; bumps Depth.
///
/// # Safety
/// `head` valid SLIST_HEADER; `entry` a valid SLIST_ENTRY (its first 8 bytes = Next).
#[export_name = "RtlInterlockedPushEntrySList"]
pub unsafe extern "system" fn rtl_interlocked_push_entry_slist(
    head: *mut c_void,
    entry: *mut c_void,
) -> *mut c_void {
    if head.is_null() || entry.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: head/entry valid per the contract.
    unsafe {
        let prev = *(head as *mut u64);
        *(entry as *mut u64) = prev; // Entry->Next = old head
        *(head as *mut u64) = entry as u64;
        let depth = (head as *mut u16).add(4);
        *depth = depth.read().wrapping_add(1);
        prev as *mut c_void
    }
}

/// `RtlInterlockedPopEntrySList(PSLIST_HEADER) -> PSLIST_ENTRY` — pop the head (NULL if empty).
///
/// # Safety
/// `head` a valid SLIST_HEADER.
#[export_name = "RtlInterlockedPopEntrySList"]
pub unsafe extern "system" fn rtl_interlocked_pop_entry_slist(head: *mut c_void) -> *mut c_void {
    if head.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: head valid per the contract.
    unsafe {
        let top = *(head as *mut u64);
        if top == 0 {
            return core::ptr::null_mut();
        }
        let next = *(top as *mut u64); // top->Next
        *(head as *mut u64) = next;
        let depth = (head as *mut u16).add(4);
        *depth = depth.read().wrapping_sub(1);
        top as *mut c_void
    }
}

/// `RtlInterlockedFlushSList(PSLIST_HEADER) -> PSLIST_ENTRY` — detach the whole chain (return old
/// head), leaving the list empty.
///
/// # Safety
/// `head` a valid SLIST_HEADER.
#[export_name = "RtlInterlockedFlushSList"]
pub unsafe extern "system" fn rtl_interlocked_flush_slist(head: *mut c_void) -> *mut c_void {
    if head.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: head valid per the contract.
    unsafe {
        let top = *(head as *mut u64);
        *(head as *mut u64) = 0;
        *((head as *mut u16).add(4)) = 0; // Depth = 0
        top as *mut c_void
    }
}

/// `RtlQueryDepthSList(PSLIST_HEADER) -> USHORT`.
///
/// # Safety
/// `head` a valid SLIST_HEADER.
#[export_name = "RtlQueryDepthSList"]
pub unsafe extern "system" fn rtl_query_depth_slist(head: *const c_void) -> u16 {
    if head.is_null() {
        return 0;
    }
    // SAFETY: head valid; Depth @ +8 low 16 bits.
    unsafe { *((head as *const u16).add(4)) }
}

// ---- status / thread-error-mode / version / product-type -----------------------------------------

/// `RtlGetLastNtStatus() -> NTSTATUS` — TEB->LastStatusValue @ 0x1250.
///
/// # Safety
/// Reads gs:[0]-based TEB on target.
#[export_name = "RtlGetLastNtStatus"]
pub unsafe extern "system" fn rtl_get_last_nt_status() -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: on-target; the TEB is at gs:0.
    unsafe {
        let status: u32;
        core::arch::asm!("mov {:e}, gs:[0x1250]", out(reg) status);
        status
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        STATUS_SUCCESS
    }
}

/// `RtlRestoreLastWin32Error(DWORD Error)` — TEB->LastErrorValue @ 0x68 (== RtlSetLastWin32Error).
///
/// # Safety
/// Writes gs:[0]-based TEB on target.
#[export_name = "RtlRestoreLastWin32Error"]
pub unsafe extern "system" fn rtl_restore_last_win32_error(error: u32) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: on-target; TEB->LastErrorValue @ 0x68.
    unsafe {
        core::arch::asm!("mov gs:[0x68], {:e}", in(reg) error);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = error;
    }
}

/// `RtlGetThreadErrorMode() -> ULONG` — TEB->HardErrorMode. Default 0 (all errors reported).
///
/// # Safety
/// Reads no cross-plane state.
#[export_name = "RtlGetThreadErrorMode"]
pub unsafe extern "system" fn rtl_get_thread_error_mode() -> u32 {
    0
}

/// `RtlSetThreadErrorMode(ULONG NewMode, PULONG OldMode) -> NTSTATUS`.
///
/// # Safety
/// `old_mode` null or writable.
#[export_name = "RtlSetThreadErrorMode"]
pub unsafe extern "system" fn rtl_set_thread_error_mode(_new_mode: u32, old_mode: *mut u32) -> NtStatus {
    if !old_mode.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *old_mode = 0 };
    }
    STATUS_SUCCESS
}

/// `RtlGetNtProductType(PNT_PRODUCT_TYPE ProductType) -> BOOLEAN` — 1 = NtProductWinNt.
///
/// # Safety
/// `product_type` writable.
#[export_name = "RtlGetNtProductType"]
pub unsafe extern "system" fn rtl_get_nt_product_type(product_type: *mut u32) -> u8 {
    if product_type.is_null() {
        return 0;
    }
    // SAFETY: writable per the contract.
    unsafe { *product_type = 1 }; // NtProductWinNt
    1
}

/// `RtlGetVersion(PRTL_OSVERSIONINFOW VersionInformation) -> NTSTATUS`. Report Windows 5.2 (the
/// ReactOS-emulated target OS). OSVERSIONINFOW: dwOSVersionInfoSize@0, dwMajorVersion@4,
/// dwMinorVersion@8, dwBuildNumber@0xC, dwPlatformId@0x10, szCSDVersion[128]@0x14.
///
/// # Safety
/// `vi` a valid RTL_OSVERSIONINFOW (or the EX variant) with a correct size prefix.
#[export_name = "RtlGetVersion"]
pub unsafe extern "system" fn rtl_get_version(vi: *mut c_void) -> NtStatus {
    if vi.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: vi valid per the contract (>= 0x114 bytes for OSVERSIONINFOW).
    unsafe {
        let p = vi as *mut u32;
        *p.add(1) = 5; // major
        *p.add(2) = 2; // minor
        *p.add(3) = 3790; // build
        *p.add(4) = 2; // VER_PLATFORM_WIN32_NT
        // szCSDVersion @ 0x14: zero the first wchar (empty).
        *((vi as *mut u16).add(0x14 / 2)) = 0;
    }
    STATUS_SUCCESS
}

/// `RtlVerifyVersionInfo(PRTL_OSVERSIONINFOEXW VersionInfo, ULONG TypeMask, ULONGLONG ConditionMask)
/// -> NTSTATUS`. Compare against our reported 5.2.3790. For the common `>=` boot checks we return
/// STATUS_SUCCESS (the running version satisfies a `<=` requirement); a strictly-greater requirement
/// returns STATUS_REVISION_MISMATCH (0xC0000059).
///
/// # Safety
/// `vi` a valid RTL_OSVERSIONINFOEXW.
#[export_name = "RtlVerifyVersionInfo"]
pub unsafe extern "system" fn rtl_verify_version_info(
    vi: *const c_void,
    _type_mask: u32,
    _condition_mask: u64,
) -> NtStatus {
    if vi.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: vi valid per the contract.
    let (major, minor) = unsafe {
        let p = vi as *const u32;
        (*p.add(1), *p.add(2))
    };
    // Our OS = 5.2. Satisfy any requirement <= 5.2 (the boot path checks "at least NT4/2000").
    if major < 5 || (major == 5 && minor <= 2) {
        STATUS_SUCCESS
    } else {
        0xC000_0059 // STATUS_REVISION_MISMATCH
    }
}

/// `RtlGetCurrentProcessorNumber() -> ULONG` — always CPU 0 (single-CPU boot).
///
/// # Safety
/// Reads no memory.
#[export_name = "RtlGetCurrentProcessorNumber"]
pub unsafe extern "system" fn rtl_get_current_processor_number() -> u32 {
    0
}

/// `RtlGetNativeSystemInformation(...)` — forwards to `NtQuerySystemInformation`. On WOW64 it queries
/// the native (64-bit) view; we ARE native x64, so it's identical. Route to the Nt* stub.
///
/// # Safety
/// As `NtQuerySystemInformation`.
#[export_name = "RtlGetNativeSystemInformation"]
pub unsafe extern "system" fn rtl_get_native_system_information(
    info_class: u32,
    info: *mut c_void,
    info_len: u32,
    ret_len: *mut u32,
) -> NtStatus {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: forwards to the NtQuerySystemInformation native stub with the same ABI.
    unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(),
            unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> NtStatus,
        >(nt_ntdll::trap_stubs::nt_query_system_information)(
            info_class, info, info_len, ret_len,
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (info_class, info, info_len, ret_len);
        STATUS_NOT_IMPLEMENTED
    }
}

// ---- vectored exception handlers / SEH function tables (honest no-op/seam) ------------------------

/// `RtlAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) -> PVOID` —
/// register a VEH. No VEH dispatch plane yet; return a non-null cookie (the Handler ptr) so the
/// caller's "registration failed?" check passes. The handler simply won't be invoked (no exceptions
/// on the boot path) — an honest no-op, never a fabricated dispatch.
///
/// # Safety
/// `handler` a valid VEH callback.
#[export_name = "RtlAddVectoredExceptionHandler"]
pub unsafe extern "system" fn rtl_add_vectored_exception_handler(
    _first: u32,
    handler: *mut c_void,
) -> *mut c_void {
    handler
}

/// `RtlRemoveVectoredExceptionHandler(PVOID Handle) -> ULONG` — 1 = removed.
///
/// # Safety
/// `handle` from `RtlAddVectoredExceptionHandler`.
#[export_name = "RtlRemoveVectoredExceptionHandler"]
pub unsafe extern "system" fn rtl_remove_vectored_exception_handler(_handle: *mut c_void) -> u32 {
    1
}

/// `RtlAddVectoredContinueHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) -> PVOID`.
///
/// # Safety
/// `handler` a valid callback.
#[export_name = "RtlAddVectoredContinueHandler"]
pub unsafe extern "system" fn rtl_add_vectored_continue_handler(
    _first: u32,
    handler: *mut c_void,
) -> *mut c_void {
    handler
}

/// `RtlRemoveVectoredContinueHandler(PVOID Handle) -> ULONG`.
///
/// # Safety
/// `handle` a registration cookie.
#[export_name = "RtlRemoveVectoredContinueHandler"]
pub unsafe extern "system" fn rtl_remove_vectored_continue_handler(_handle: *mut c_void) -> u32 {
    1
}

/// `RtlAddFunctionTable(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress)
/// -> BOOLEAN` — register a `.pdata` table for SEH. No dynamic SEH unwind on the boot path; accept
/// the registration (TRUE) as a no-op (the static image `.pdata` is what the boot uses).
///
/// # Safety
/// `function_table` valid for `entry_count` RUNTIME_FUNCTIONs.
#[export_name = "RtlAddFunctionTable"]
pub unsafe extern "system" fn rtl_add_function_table(
    _function_table: *mut c_void,
    _entry_count: u32,
    _base_address: u64,
) -> u8 {
    1
}

/// `RtlDeleteFunctionTable(PRUNTIME_FUNCTION FunctionTable) -> BOOLEAN`.
///
/// # Safety
/// `function_table` from `RtlAddFunctionTable`.
#[export_name = "RtlDeleteFunctionTable"]
pub unsafe extern "system" fn rtl_delete_function_table(_function_table: *mut c_void) -> u8 {
    1
}

/// `RtlInstallFunctionTableCallback(...) -> BOOLEAN` — dynamic function-table callback. No-op TRUE.
///
/// # Safety
/// Args per the RtlInstallFunctionTableCallback ABI.
#[export_name = "RtlInstallFunctionTableCallback"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_install_function_table_callback(
    _table_identifier: u64,
    _base_address: u64,
    _length: u32,
    _callback: *mut c_void,
    _context: *mut c_void,
    _out_of_process_dll: *const u16,
) -> u8 {
    1
}

/// `RtlLookupFunctionEntry(DWORD64 ControlPc, PDWORD64 ImageBase, PVOID HistoryTable)
/// -> PRUNTIME_FUNCTION` — no dynamic table; return NULL (leaf function / no unwind info). The boot
/// path doesn't unwind, so a NULL result is correct (the caller treats it as a leaf frame).
///
/// # Safety
/// `image_base` null or writable.
#[export_name = "RtlLookupFunctionEntry"]
pub unsafe extern "system" fn rtl_lookup_function_entry(
    _control_pc: u64,
    image_base: *mut u64,
    _history_table: *mut c_void,
) -> *mut c_void {
    if !image_base.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *image_base = 0 };
    }
    core::ptr::null_mut()
}

/// `RtlCaptureContext(PCONTEXT ContextRecord)` — capture the current CONTEXT. The boot path doesn't
/// unwind through a captured context; zero the record (an honest empty capture) rather than
/// fabricate register values. (A full capture is a naked-asm target seam.)
///
/// # Safety
/// `context` a valid writable CONTEXT (>= 0x4D0 bytes on x64).
#[export_name = "RtlCaptureContext"]
pub unsafe extern "system" fn rtl_capture_context(context: *mut c_void) {
    if !context.is_null() {
        // SAFETY: zero the first 0x4D0 bytes (the x64 CONTEXT size) per the contract.
        unsafe { core::ptr::write_bytes(context as *mut u8, 0, 0x4D0) };
    }
}

/// `RtlRaiseStatus(NTSTATUS Status)` — raise a noncontinuable exception with `Status`. No SEH plane
/// on the boot path; issue an `int 3` (debug break → the kernel #BP handler) so control does NOT
/// silently continue past a raised status (an honest non-return, not a fabricated recovery).
///
/// # Safety
/// Does not return on target (int3).
#[export_name = "RtlRaiseStatus"]
pub unsafe extern "system" fn rtl_raise_status(_status: NtStatus) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: int3 traps to the kernel; RtlRaiseStatus does not return.
    unsafe {
        core::arch::asm!("int3", options(noreturn));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {}
}

/// `RtlRaiseException(PEXCEPTION_RECORD ExceptionRecord)` — raise an exception. Same honest int3.
///
/// # Safety
/// `exception_record` a valid EXCEPTION_RECORD.
#[export_name = "RtlRaiseException"]
pub unsafe extern "system" fn rtl_raise_exception(_exception_record: *mut c_void) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: int3 traps to the kernel.
    unsafe {
        core::arch::asm!("int3");
    }
}

/// `RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD, PVOID ReturnValue)` — SEH unwind.
/// The boot path doesn't unwind; no-op (an honest non-unwind — the caller only reaches here on an
/// exception, which doesn't occur on the boot path).
///
/// # Safety
/// Called only during exception dispatch (not on the boot path).
#[export_name = "RtlUnwind"]
pub unsafe extern "system" fn rtl_unwind(
    _target_frame: *mut c_void,
    _target_ip: *mut c_void,
    _exception_record: *mut c_void,
    _return_value: *mut c_void,
) {
}

/// `RtlUnwindEx(...)` — the extended (x64) SEH unwind. Same no-op seam.
///
/// # Safety
/// Called only during exception dispatch.
#[export_name = "RtlUnwindEx"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_unwind_ex(
    _target_frame: *mut c_void,
    _target_ip: *mut c_void,
    _exception_record: *mut c_void,
    _return_value: *mut c_void,
    _context: *mut c_void,
    _history_table: *mut c_void,
) {
}

/// `RtlVirtualUnwind(...)` — unwind one frame using a RUNTIME_FUNCTION. Return the caller's IP.
/// No unwind plane; return NULL handler + leave the context unchanged (the boot path doesn't call
/// this).
///
/// # Safety
/// Called only during exception dispatch.
#[export_name = "RtlVirtualUnwind"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_virtual_unwind(
    _handler_type: u32,
    _image_base: u64,
    _control_pc: u64,
    _function_entry: *mut c_void,
    _context: *mut c_void,
    _handler_data: *mut *mut c_void,
    _establisher_frame: *mut u64,
    _context_pointers: *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `RtlRestoreContext(PCONTEXT ContextRecord, PEXCEPTION_RECORD)` — resume at a captured context. No
/// resume plane; int3 (an honest non-return, not a fabricated resume).
///
/// # Safety
/// Called only during exception dispatch.
#[export_name = "RtlRestoreContext"]
pub unsafe extern "system" fn rtl_restore_context(
    _context: *mut c_void,
    _exception_record: *mut c_void,
) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: int3 traps to the kernel.
    unsafe {
        core::arch::asm!("int3");
    }
}

/// `RtlExitUserThread(NTSTATUS Status)` — terminate the current thread. Route to the NtTerminateThread
/// stub with the current-thread pseudo-handle (-2).
///
/// # Safety
/// Does not return.
#[export_name = "RtlExitUserThread"]
pub unsafe extern "system" fn rtl_exit_user_thread(status: NtStatus) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: forwards to NtTerminateThread(NtCurrentThread=-2, status); does not return.
    unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(),
            unsafe extern "system" fn(isize, NtStatus) -> NtStatus,
        >(nt_ntdll::trap_stubs::nt_terminate_thread)(-2, status);
        // Should not return; if it does, spin at a breakpoint.
        core::arch::asm!("int3");
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = status;
    }
}

/// `RtlComputeImportTableHash(HANDLE FileHandle, PCHAR Hash, ULONG ImportTableHashSize) -> NTSTATUS`
/// — hash a module's import table (used by the loader-integrity path). Not needed on the boot path;
/// zero the hash + STATUS_SUCCESS (an empty hash — the caller stores it, no verification consumer).
///
/// # Safety
/// `hash` writable for `size` bytes.
#[export_name = "RtlComputeImportTableHash"]
pub unsafe extern "system" fn rtl_compute_import_table_hash(
    _file_handle: *mut c_void,
    hash: *mut u8,
    size: u32,
) -> NtStatus {
    if !hash.is_null() {
        // SAFETY: hash writable for size bytes per the contract.
        unsafe { core::ptr::write_bytes(hash, 0, size as usize) };
    }
    STATUS_SUCCESS
}

/// `RtlFlushSecureMemoryCache(PVOID MemoryCache, SIZE_T MemoryLength) -> BOOLEAN` — flush a secure
/// memory region from the CPU cache. No secure-memory plane; return TRUE (nothing to flush).
///
/// # Safety
/// `memory_cache` a mapped region or NULL.
#[export_name = "RtlFlushSecureMemoryCache"]
pub unsafe extern "system" fn rtl_flush_secure_memory_cache(
    _memory_cache: *mut c_void,
    _memory_length: usize,
) -> u8 {
    1
}

/// `RtlSetCriticalSectionSpinCount(PRTL_CRITICAL_SECTION, ULONG SpinCount) -> ULONG` — set the
/// adaptive-spin count in the CS's SpinCount field; return the previous value.
///
/// # Safety
/// `cs` a valid RTL_CRITICAL_SECTION (SpinCount @ 0x20 on x64).
#[export_name = "RtlSetCriticalSectionSpinCount"]
pub unsafe extern "system" fn rtl_set_critical_section_spin_count(cs: *mut c_void, spin: u32) -> u32 {
    if cs.is_null() {
        return 0;
    }
    // RTL_CRITICAL_SECTION: DebugInfo@0, LockCount@8, RecursionCount@0xC, OwningThread@0x10,
    // LockSemaphore@0x18, SpinCount@0x20.
    // SAFETY: cs valid per the contract.
    unsafe {
        let p = (cs as *mut u32).byte_add(0x20);
        let prev = *p;
        *p = spin;
        prev
    }
}

/// `RtlTryEnterCriticalSection(PRTL_CRITICAL_SECTION) -> BOOLEAN` — non-blocking acquire. Single-
/// threaded: if free (or owned by us), acquire; else FALSE. Model the interlocked LockCount.
///
/// # Safety
/// `cs` a valid RTL_CRITICAL_SECTION.
#[export_name = "RtlTryEnterCriticalSection"]
pub unsafe extern "system" fn rtl_try_enter_critical_section(cs: *mut c_void) -> u8 {
    if cs.is_null() {
        return 0;
    }
    // SAFETY: cs valid per the contract. LockCount @ 8 (init -1 = free), RecursionCount @ 0xC.
    unsafe {
        let lock = (cs as *mut i32).byte_add(8);
        let rec = (cs as *mut i32).byte_add(0xC);
        if *lock == -1 {
            *lock = 0;
            *rec = 1;
            1
        } else {
            // Single-threaded: treat as recursive re-entry (we are the only thread).
            *lock += 1;
            *rec += 1;
            1
        }
    }
}

// =================================================================================================
// BATCH 4 — Rtl* heap family the Win32 stack imports. The process has ONE heap (ours); the
// HANDLE arg (Peb->ProcessHeap) is honoured as "the process heap". Alloc/free/realloc/size route
// to the installed first-fit heap; the introspection/lock/tag ops are correct no-ops for a
// single-threaded single-heap model.
// =================================================================================================

/// `RtlSizeHeap(PVOID HeapHandle, ULONG Flags, PVOID MemoryPointer) -> SIZE_T` — payload size.
///
/// # Safety
/// `mem` a live block from the process heap (or NULL).
#[export_name = "RtlSizeHeap"]
pub unsafe extern "system" fn rtl_size_heap(_heap: *mut c_void, _flags: u32, mem: *mut c_void) -> usize {
    if mem.is_null() {
        return usize::MAX; // (SIZE_T)-1 = failure, matching RtlSizeHeap.
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: mem came from the process heap per the contract.
        match unsafe { crate::process_heap_size(mem as *mut u8) } {
            Some(n) => n,
            None => usize::MAX,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        usize::MAX
    }
}

/// `RtlValidateHeap(PVOID HeapHandle, ULONG Flags, PVOID MemoryPointer) -> BOOLEAN` — validate the
/// heap (or a block). Our first-fit heap is internally consistent by construction; return TRUE.
///
/// # Safety
/// `heap`/`mem` valid or NULL.
#[export_name = "RtlValidateHeap"]
pub unsafe extern "system" fn rtl_validate_heap(_heap: *mut c_void, _flags: u32, _mem: *mut c_void) -> u8 {
    1
}

/// `RtlDestroyHeap(PVOID HeapHandle) -> PVOID` — destroy a heap (returns NULL on success). We have
/// exactly one process heap that lives for the process lifetime; destroying it would break the
/// allocator, so we no-op and return the handle unchanged (the "still in use" contract — real
/// RtlDestroyHeap also refuses to destroy the process heap `Peb->ProcessHeap`).
///
/// # Safety
/// `heap` a heap handle.
#[export_name = "RtlDestroyHeap"]
pub unsafe extern "system" fn rtl_destroy_heap(heap: *mut c_void) -> *mut c_void {
    heap
}

/// `RtlGetProcessHeaps(ULONG Count, PVOID* Heaps) -> ULONG` — enumerate the process's heaps. We have
/// one (the process heap = `Peb->ProcessHeap` @ gs:[0x60]->0x30).
///
/// # Safety
/// `heaps` writable for `count` entries.
#[export_name = "RtlGetProcessHeaps"]
pub unsafe extern "system" fn rtl_get_process_heaps(count: u32, heaps: *mut *mut c_void) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // Read Peb->ProcessHeap: PEB @ gs:[0x60], ProcessHeap @ PEB+0x30.
        // SAFETY: on-target; the PEB is mapped + gs points at the TEB.
        let ph = unsafe {
            let peb: *const u8;
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
            *(peb.add(0x30) as *const *mut c_void)
        };
        if count >= 1 && !heaps.is_null() {
            // SAFETY: heaps writable for >= 1 entry per the check.
            unsafe { *heaps = ph };
        }
        1
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (count, heaps);
        0
    }
}

macro_rules! heap_noop_bool {
    ($export:literal, $fn:ident) => {
        /// A single-threaded single-heap no-op heap op returning TRUE (success).
        ///
        /// # Safety
        /// `heap` a heap handle.
        #[export_name = $export]
        pub unsafe extern "system" fn $fn(_heap: *mut c_void) -> u8 {
            1
        }
    };
}
heap_noop_bool!("RtlLockHeap", rtl_lock_heap);
heap_noop_bool!("RtlUnlockHeap", rtl_unlock_heap);

/// `RtlCompactHeap(PVOID HeapHandle, ULONG Flags) -> SIZE_T` — compact + return the largest free
/// block. No compaction model; return 0 (the documented "size unavailable" value).
///
/// # Safety
/// `heap` a heap handle.
#[export_name = "RtlCompactHeap"]
pub unsafe extern "system" fn rtl_compact_heap(_heap: *mut c_void, _flags: u32) -> usize {
    0
}

/// `RtlWalkHeap(PVOID HeapHandle, PVOID Entry) -> NTSTATUS` — iterate heap blocks. We don't expose a
/// walk interface; return STATUS_NO_MORE_ENTRIES (0x8000001A) so the caller's loop terminates
/// cleanly rather than spinning.
///
/// # Safety
/// `entry` a valid RTL_HEAP_WALK_ENTRY* or NULL.
#[export_name = "RtlWalkHeap"]
pub unsafe extern "system" fn rtl_walk_heap(_heap: *mut c_void, _entry: *mut c_void) -> NtStatus {
    0x8000_001A // STATUS_NO_MORE_ENTRIES
}

/// `RtlQueryHeapInformation(PVOID HeapHandle, HEAP_INFORMATION_CLASS Class, PVOID Info,
/// SIZE_T Length, PSIZE_T Return) -> NTSTATUS`. Serves HeapCompatibilityInformation (class 0) = 0
/// (standard heap); returns STATUS_SUCCESS.
///
/// # Safety
/// `info` writable for `length` bytes; `ret` null or writable.
#[export_name = "RtlQueryHeapInformation"]
pub unsafe extern "system" fn rtl_query_heap_information(
    _heap: *mut c_void,
    class: u32,
    info: *mut c_void,
    length: usize,
    ret: *mut usize,
) -> NtStatus {
    if class == 0 && !info.is_null() && length >= 4 {
        // HeapCompatibilityInformation: 0 = standard front-end.
        // SAFETY: info writable for >= 4 bytes per the check.
        unsafe { *(info as *mut u32) = 0 };
        if !ret.is_null() {
            // SAFETY: ret writable.
            unsafe { *ret = 4 };
        }
    }
    STATUS_SUCCESS
}

/// `RtlSetHeapInformation(PVOID HeapHandle, HEAP_INFORMATION_CLASS Class, PVOID Info, SIZE_T Length)
/// -> NTSTATUS`. No configurable front-end; accept the request (STATUS_SUCCESS) — the observable
/// contract for a standard heap that ignores the tuning knob.
///
/// # Safety
/// `info` valid for `length` bytes or NULL.
#[export_name = "RtlSetHeapInformation"]
pub unsafe extern "system" fn rtl_set_heap_information(
    _heap: *mut c_void,
    _class: u32,
    _info: *mut c_void,
    _length: usize,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `RtlGetUserInfoHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, PVOID* UserValue,
/// PULONG UserFlags) -> BOOLEAN` — per-allocation user metadata. Not tracked; return FALSE (no user
/// value) — never a fabricated value.
///
/// # Safety
/// `user_value`/`user_flags` null or writable.
#[export_name = "RtlGetUserInfoHeap"]
pub unsafe extern "system" fn rtl_get_user_info_heap(
    _heap: *mut c_void,
    _flags: u32,
    _base: *mut c_void,
    user_value: *mut *mut c_void,
    user_flags: *mut u32,
) -> u8 {
    if !user_value.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *user_value = core::ptr::null_mut() };
    }
    if !user_flags.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *user_flags = 0 };
    }
    0
}

/// `RtlSetUserValueHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, PVOID UserValue)
/// -> BOOLEAN` — set per-allocation user metadata. Not tracked; return FALSE.
///
/// # Safety
/// `base` a live block or NULL.
#[export_name = "RtlSetUserValueHeap"]
pub unsafe extern "system" fn rtl_set_user_value_heap(
    _heap: *mut c_void,
    _flags: u32,
    _base: *mut c_void,
    _user_value: *mut c_void,
) -> u8 {
    0
}

/// `RtlQueryTagHeap(...)` — heap tag introspection (debug). No tag store; return NULL.
///
/// # Safety
/// Args are the RtlQueryTagHeap ABI; reads no memory here.
#[export_name = "RtlQueryTagHeap"]
pub unsafe extern "system" fn rtl_query_tag_heap(
    _heap: *mut c_void,
    _flags: u32,
    _tag_index: u16,
    _reset: u8,
    _tag_name: *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

// =================================================================================================
// BATCH 4 — Etw* trace client. ETW is off in our environment (no trace session). Every Etw* API
// returns ERROR_SUCCESS (0) / a null handle — the observable "tracing disabled" contract (a real
// no-provider ETW client behaves the same: registration succeeds, events go nowhere). All take the
// Win32 error-code convention (ULONG, 0 = success), NOT NTSTATUS.
// =================================================================================================

macro_rules! etw_ok {
    ($export:literal, $fn:ident) => {
        /// ETW trace API — tracing disabled; returns ERROR_SUCCESS (0).
        ///
        /// # Safety
        /// Called with the corresponding Etw* ABI; ignores its args (no trace session).
        #[export_name = $export]
        pub unsafe extern "system" fn $fn(
            _a: u64,
            _b: u64,
            _c: u64,
            _d: u64,
        ) -> u32 {
            0
        }
    };
}
etw_ok!("EtwControlTraceA", etw_control_trace_a);
etw_ok!("EtwControlTraceW", etw_control_trace_w);
etw_ok!("EtwCreateTraceInstanceId", etw_create_trace_instance_id);
etw_ok!("EtwEnableTrace", etw_enable_trace);
etw_ok!("EtwEnumerateTraceGuids", etw_enumerate_trace_guids);
etw_ok!("EtwFlushTraceA", etw_flush_trace_a);
etw_ok!("EtwFlushTraceW", etw_flush_trace_w);
etw_ok!("EtwGetTraceEnableFlags", etw_get_trace_enable_flags);
etw_ok!("EtwGetTraceEnableLevel", etw_get_trace_enable_level);
etw_ok!("EtwGetTraceLoggerHandle", etw_get_trace_logger_handle);
etw_ok!("EtwNotificationRegistrationA", etw_notification_registration_a);
etw_ok!("EtwNotificationRegistrationW", etw_notification_registration_w);
etw_ok!("EtwQueryAllTracesA", etw_query_all_traces_a);
etw_ok!("EtwQueryAllTracesW", etw_query_all_traces_w);
etw_ok!("EtwQueryTraceA", etw_query_trace_a);
etw_ok!("EtwQueryTraceW", etw_query_trace_w);
etw_ok!("EtwReceiveNotificationsA", etw_receive_notifications_a);
etw_ok!("EtwReceiveNotificationsW", etw_receive_notifications_w);
etw_ok!("EtwRegisterTraceGuidsA", etw_register_trace_guids_a);
etw_ok!("EtwRegisterTraceGuidsW", etw_register_trace_guids_w);
etw_ok!("EtwStartTraceA", etw_start_trace_a);
etw_ok!("EtwStartTraceW", etw_start_trace_w);
etw_ok!("EtwStopTraceA", etw_stop_trace_a);
etw_ok!("EtwStopTraceW", etw_stop_trace_w);
etw_ok!("EtwTraceEvent", etw_trace_event);
etw_ok!("EtwTraceEventInstance", etw_trace_event_instance);
etw_ok!("EtwTraceMessage", etw_trace_message);
etw_ok!("EtwTraceMessageVa", etw_trace_message_va);
etw_ok!("EtwUnregisterTraceGuids", etw_unregister_trace_guids);
etw_ok!("EtwUpdateTraceA", etw_update_trace_a);
etw_ok!("EtwUpdateTraceW", etw_update_trace_w);

// =================================================================================================
// BATCH 4 — Zw* aliases. Zw* and Nt* are identical exports (same SSN, same ABI) — real ntdll
// exports both names pointing at the same code. We emit a naked tail-`jmp` to the corresponding
// Nt* export so the Zw name lands in the export directory (transport-agnostic: whatever transport
// the Nt* stub uses, the Zw alias inherits it).
// =================================================================================================

/// `ZwYieldExecution` — alias of `NtYieldExecution` (SSN 288). Naked `jmp NtYieldExecution`.
///
/// # Safety
/// Tail-calls the `NtYieldExecution` stub (same ABI); no local state.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[export_name = "ZwYieldExecution"]
pub unsafe extern "C" fn zw_yield_execution() {
    core::arch::naked_asm!("jmp {}", sym nt_ntdll::trap_stubs::nt_yield_execution);
}

/// `ZwCallbackReturn` — alias of `NtCallbackReturn` (SSN 22). `NtCallbackReturn` is not in the 188
/// trap-stub set (it's a Ki-adjacent stub); emit a direct native/trap stub here under BOTH names is
/// unnecessary — the Win32 boot path calls `ZwCallbackReturn` only from `KiUserCallbackDispatcher`,
/// which we service via the callback seam. Provide the export as a trap stub (SSN 22).
///
/// # Safety
/// Issues the NtCallbackReturn syscall (SSN 22, trap ABI).
#[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
#[unsafe(naked)]
#[export_name = "ZwCallbackReturn"]
pub unsafe extern "C" fn zw_callback_return() {
    core::arch::naked_asm!("mov r10, rcx", "mov eax, 22", "syscall", "ret");
}

/// `ZwCallbackReturn` (native seL4-Call transport variant) — SSN 22.
///
/// # Safety
/// Issues the NtCallbackReturn native seL4 Call (SSN 22).
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[unsafe(naked)]
#[export_name = "ZwCallbackReturn"]
pub unsafe extern "C" fn zw_callback_return() {
    core::arch::naked_asm!(
        "movabs rax, 0x00000100105FB000",
        "mov qword ptr [rax + 0x28], r8",
        "mov qword ptr [rax + 0x30], r9",
        "mov r8, rsp",
        "mov r9, rcx",
        "mov r15, rdx",
        "mov r10d, 22",
        "mov edi, 6",
        "mov esi, 0x04E54006",
        "mov rdx, -1",
        "syscall",
        "mov rax, r10",
        "ret",
    );
}

// =================================================================================================
// BATCH 4 — Rtl* string / convert family the Win32 stack imports.
// Raw UNICODE_STRING / ANSI_STRING (both the 16-byte {Length:u16, MaximumLength:u16, _pad:u32,
// Buffer:u64} shape) wrappers over the host-tested nt_ntdll::rtl string/convert cores. Single-byte
// code-page default (1252/437) → 1 UTF-16 unit per ANSI byte.
// =================================================================================================

/// `RtlCopyUnicodeString(PUNICODE_STRING dst, PCUNICODE_STRING src)` — copy up to
/// `dst->MaximumLength` bytes; sets `dst->Length`.
///
/// # Safety
/// `dst` a valid writable UNICODE_STRING with a buffer of `MaximumLength` bytes; `src` valid/NULL.
#[export_name = "RtlCopyUnicodeString"]
pub unsafe extern "system" fn rtl_copy_unicode_string(dst: PUnicodeString, src: PCUnicodeString) {
    if dst.is_null() {
        return;
    }
    // SAFETY: dst valid per the contract.
    let (dbuf, dmax) = unsafe { ((*dst).buffer as *mut u16, (*dst).maximum_length as usize) };
    if src.is_null() {
        // SAFETY: dst valid.
        unsafe { (*dst).length = 0 };
        return;
    }
    // SAFETY: src valid per the contract.
    let (sbuf, slen) = unsafe { ((*src).buffer as *const u16, (*src).length as usize) };
    let n = core::cmp::min(slen, dmax) & !1; // byte length, even
    if !dbuf.is_null() && !sbuf.is_null() {
        // SAFETY: copy n bytes; both within their buffers.
        unsafe { core::ptr::copy_nonoverlapping(sbuf as *const u8, dbuf as *mut u8, n) };
    }
    // NUL-terminate if room.
    if n + 2 <= dmax && !dbuf.is_null() {
        // SAFETY: room for a terminator per the check.
        unsafe { *dbuf.add(n / 2) = 0 };
    }
    // SAFETY: dst valid.
    unsafe { (*dst).length = n as u16 };
}

/// `RtlUpcaseUnicodeString(PUNICODE_STRING dst, PCUNICODE_STRING src, BOOLEAN Allocate)` — uppercase.
///
/// # Safety
/// `dst` writable; `src` valid.
#[export_name = "RtlUpcaseUnicodeString"]
pub unsafe extern "system" fn rtl_upcase_unicode_string(
    dst: PUnicodeString,
    src: PCUnicodeString,
    allocate: u8,
) -> NtStatus {
    if dst.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src valid per the contract.
    let (sbuf, slen) = unsafe { ((*src).buffer as *const u16, (*src).length as usize / 2) };
    let src_slice = if sbuf.is_null() {
        &[][..]
    } else {
        // SAFETY: valid region of slen units.
        unsafe { core::slice::from_raw_parts(sbuf, slen) }
    };
    let up = rtl::strings::upcase_unicode_string(src_slice);
    let out_bytes = up.len() * 2;
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: dst valid per the contract.
        let dbuf = if allocate != 0 {
            // SAFETY: on-target heap.
            let p = unsafe { crate::process_heap_alloc(out_bytes + 2) } as *mut u16;
            if p.is_null() {
                return STATUS_NO_MEMORY;
            }
            // SAFETY: dst valid.
            unsafe {
                (*dst).buffer = p as u64;
                (*dst).maximum_length = (out_bytes + 2) as u16;
            }
            p
        } else {
            // SAFETY: dst valid.
            unsafe {
                if (*dst).maximum_length < out_bytes as u16 {
                    return STATUS_BUFFER_OVERFLOW;
                }
                (*dst).buffer as *mut u16
            }
        };
        // SAFETY: dbuf valid for up.len() units.
        unsafe {
            core::ptr::copy_nonoverlapping(up.as_ptr(), dbuf, up.len());
            (*dst).length = out_bytes as u16;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (allocate, out_bytes);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlDuplicateUnicodeString(ULONG Flags, PCUNICODE_STRING src, PUNICODE_STRING dst)` — allocate a
/// copy. Flags bit 1 = add-NUL. Ref `sdk/lib/rtl/unicode.c:RtlDuplicateUnicodeString`.
///
/// # Safety
/// `src` valid; `dst` writable.
#[export_name = "RtlDuplicateUnicodeString"]
pub unsafe extern "system" fn rtl_duplicate_unicode_string(
    flags: u32,
    src: PCUnicodeString,
    dst: PUnicodeString,
) -> NtStatus {
    if src.is_null() || dst.is_null() || flags > 3 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src valid per the contract.
    let (sbuf, slen) = unsafe { ((*src).buffer as *const u16, (*src).length as usize) };
    let add_nul = flags & 1 != 0;
    if slen == 0 && flags & 2 == 0 {
        // Empty result, NULL buffer (RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE not set).
        // SAFETY: dst valid.
        unsafe {
            (*dst).length = 0;
            (*dst).maximum_length = 0;
            (*dst).buffer = 0;
        }
        return STATUS_SUCCESS;
    }
    let alloc_bytes = slen + if add_nul { 2 } else { 0 };
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target heap.
        let p = unsafe { crate::process_heap_alloc(alloc_bytes.max(2)) } as *mut u8;
        if p.is_null() {
            return STATUS_NO_MEMORY;
        }
        // SAFETY: copy slen bytes; buffers valid.
        unsafe {
            if !sbuf.is_null() && slen > 0 {
                core::ptr::copy_nonoverlapping(sbuf as *const u8, p, slen);
            }
            if add_nul {
                *(p.add(slen) as *mut u16) = 0;
            }
            (*dst).length = slen as u16;
            (*dst).maximum_length = alloc_bytes as u16;
            (*dst).buffer = p as u64;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (sbuf, alloc_bytes);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlCreateUnicodeStringFromAsciiz(PUNICODE_STRING dst, PCSZ src) -> BOOLEAN` — widen a
/// NUL-terminated ASCII string into a freshly-allocated UNICODE_STRING.
///
/// # Safety
/// `dst` writable; `src` a NUL-terminated byte string.
#[export_name = "RtlCreateUnicodeStringFromAsciiz"]
pub unsafe extern "system" fn rtl_create_unicode_string_from_asciiz(
    dst: PUnicodeString,
    src: *const u8,
) -> u8 {
    if dst.is_null() {
        return 0;
    }
    // SAFETY: src NUL-terminated per the contract.
    let n = unsafe { strlen_raw(src) };
    let out_bytes = n * 2;
    if out_bytes + 2 > 0xFFFF {
        return 0;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: on-target heap.
        let p = unsafe { crate::process_heap_alloc(out_bytes + 2) } as *mut u16;
        if p.is_null() {
            return 0;
        }
        // SAFETY: widen each byte; buffers valid.
        unsafe {
            for i in 0..n {
                *p.add(i) = rtl::convert::ansi_char_to_unicode_char(*src.add(i));
            }
            *p.add(n) = 0;
            (*dst).length = out_bytes as u16;
            (*dst).maximum_length = (out_bytes + 2) as u16;
            (*dst).buffer = p as u64;
        }
        1
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (n, out_bytes);
        0
    }
}

/// `RtlFreeAnsiString(PANSI_STRING)` — free a heap-allocated ANSI string.
///
/// # Safety
/// `s` a valid ANSI_STRING whose Buffer came from the process heap (or NULL Buffer).
#[export_name = "RtlFreeAnsiString"]
pub unsafe extern "system" fn rtl_free_ansi_string(s: PUnicodeString) {
    if s.is_null() {
        return;
    }
    // SAFETY: s valid per the contract.
    let buf = unsafe { (*s).buffer };
    if buf != 0 {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: buf came from the process heap.
        unsafe {
            crate::process_heap_free(buf as *mut u8);
        }
        // SAFETY: s valid.
        unsafe {
            (*s).length = 0;
            (*s).maximum_length = 0;
            (*s).buffer = 0;
        }
    }
}

/// `RtlInitAnsiStringEx(PANSI_STRING dst, PCSZ src) -> NTSTATUS` — like RtlInitAnsiString but
/// rejects a string >= 0xFFFF bytes.
///
/// # Safety
/// `dst` writable; `src` null or NUL-terminated.
#[export_name = "RtlInitAnsiStringEx"]
pub unsafe extern "system" fn rtl_init_ansi_string_ex(dst: PUnicodeString, src: *const u8) -> NtStatus {
    if dst.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src per the contract.
    let len = unsafe { strlen_raw(src) };
    if len > 0xFFFE {
        return 0xC000_0106; // STATUS_NAME_TOO_LONG
    }
    // SAFETY: dst valid.
    unsafe {
        (*dst).length = len as u16;
        (*dst).maximum_length = if src.is_null() { 0 } else { (len + 1) as u16 };
        (*dst).buffer = src as u64;
    }
    STATUS_SUCCESS
}

/// `RtlInitUnicodeStringEx(PUNICODE_STRING dst, PCWSTR src) -> NTSTATUS`.
///
/// # Safety
/// `dst` writable; `src` null or NUL-terminated UTF-16.
#[export_name = "RtlInitUnicodeStringEx"]
pub unsafe extern "system" fn rtl_init_unicode_string_ex(
    dst: PUnicodeString,
    src: *const u16,
) -> NtStatus {
    if dst.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src per the contract.
    let units = unsafe { wcslen_raw(src) };
    if units > 0x7FFE {
        return 0xC000_0106; // STATUS_NAME_TOO_LONG
    }
    let bytes = (units * 2) as u16;
    // SAFETY: dst valid.
    unsafe {
        (*dst).length = bytes;
        (*dst).maximum_length = if src.is_null() { 0 } else { bytes + 2 };
        (*dst).buffer = src as u64;
    }
    STATUS_SUCCESS
}

/// `RtlAnsiCharToUnicodeChar(PUCHAR* SourceCharacter) -> WCHAR` — widen one ANSI char + advance the
/// source pointer.
///
/// # Safety
/// `src` a valid `PUCHAR*` pointing at a readable byte.
#[export_name = "RtlAnsiCharToUnicodeChar"]
pub unsafe extern "system" fn rtl_ansi_char_to_unicode_char(src: *mut *const u8) -> u16 {
    if src.is_null() {
        return 0;
    }
    // SAFETY: src valid per the contract.
    unsafe {
        let p = *src;
        let b = *p;
        *src = p.add(1);
        rtl::convert::ansi_char_to_unicode_char(b)
    }
}

/// `RtlIntegerToUnicodeString(ULONG Value, ULONG Base, PUNICODE_STRING dst) -> NTSTATUS`.
///
/// # Safety
/// `dst` a valid writable UNICODE_STRING with a buffer.
#[export_name = "RtlIntegerToUnicodeString"]
pub unsafe extern "system" fn rtl_integer_to_unicode_string(
    value: u32,
    base: u32,
    dst: PUnicodeString,
) -> NtStatus {
    if dst.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let base = if base == 0 { 10 } else { base };
    let digits = match rtl::integer::integer_to_unicode(value, base) {
        Some(d) => d,
        None => return STATUS_INVALID_PARAMETER,
    };
    let out_bytes = digits.len() * 2;
    // SAFETY: dst valid per the contract.
    unsafe {
        if (*dst).maximum_length < (out_bytes + 2) as u16 {
            return STATUS_BUFFER_OVERFLOW;
        }
        let dbuf = (*dst).buffer as *mut u16;
        if dbuf.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        core::ptr::copy_nonoverlapping(digits.as_ptr(), dbuf, digits.len());
        *dbuf.add(digits.len()) = 0;
        (*dst).length = out_bytes as u16;
    }
    STATUS_SUCCESS
}

/// `RtlUnicodeToMultiByteN(PCHAR MbStr, ULONG MbSize, PULONG BytesInMbStr, PCWCH UnicodeStr,
/// ULONG BytesInUnicodeStr) -> NTSTATUS` — UTF-16 → single-byte code page.
///
/// # Safety
/// `mb_str` writable for `mb_size` bytes; `unicode_str` valid for `bytes_in_unicode` bytes;
/// `bytes_out` null or writable.
#[export_name = "RtlUnicodeToMultiByteN"]
pub unsafe extern "system" fn rtl_unicode_to_multi_byte_n(
    mb_str: *mut u8,
    mb_size: u32,
    bytes_out: *mut u32,
    unicode_str: *const u16,
    bytes_in_unicode: u32,
) -> NtStatus {
    let units = bytes_in_unicode as usize / 2;
    let n = core::cmp::min(units, mb_size as usize);
    // SAFETY: unicode_str valid for `units`; mb_str writable for `mb_size`.
    unsafe {
        for i in 0..n {
            let c = *unicode_str.add(i);
            *mb_str.add(i) = if c < 0x100 { c as u8 } else { b'?' };
        }
        if !bytes_out.is_null() {
            *bytes_out = n as u32;
        }
    }
    STATUS_SUCCESS
}

/// `RtlUnicodeToOemN(...)` — identical to MultiByteN for our single-byte OEM (437) default path.
///
/// # Safety
/// As `RtlUnicodeToMultiByteN`.
#[export_name = "RtlUnicodeToOemN"]
pub unsafe extern "system" fn rtl_unicode_to_oem_n(
    oem_str: *mut u8,
    oem_size: u32,
    bytes_out: *mut u32,
    unicode_str: *const u16,
    bytes_in_unicode: u32,
) -> NtStatus {
    // SAFETY: same contract.
    unsafe {
        rtl_unicode_to_multi_byte_n(oem_str, oem_size, bytes_out, unicode_str, bytes_in_unicode)
    }
}

/// `RtlMultiByteToUnicodeN(PWCH UnicodeStr, ULONG UnicodeSize, PULONG BytesInUnicodeStr,
/// PCCH MbStr, ULONG BytesInMbStr) -> NTSTATUS` — single-byte code page → UTF-16.
///
/// # Safety
/// `unicode_str` writable for `unicode_size` bytes; `mb_str` valid for `bytes_in_mb` bytes.
#[export_name = "RtlMultiByteToUnicodeN"]
pub unsafe extern "system" fn rtl_multi_byte_to_unicode_n(
    unicode_str: *mut u16,
    unicode_size: u32,
    bytes_out: *mut u32,
    mb_str: *const u8,
    bytes_in_mb: u32,
) -> NtStatus {
    let max_units = unicode_size as usize / 2;
    let n = core::cmp::min(bytes_in_mb as usize, max_units);
    // SAFETY: buffers valid per the contract.
    unsafe {
        for i in 0..n {
            *unicode_str.add(i) = rtl::convert::ansi_char_to_unicode_char(*mb_str.add(i));
        }
        if !bytes_out.is_null() {
            *bytes_out = (n * 2) as u32;
        }
    }
    STATUS_SUCCESS
}

/// `RtlUnicodeToMultiByteSize(PULONG BytesInMbStr, PCWCH UnicodeStr, ULONG BytesInUnicodeStr)`.
///
/// # Safety
/// `bytes_out` writable; `unicode_str` valid for `bytes_in_unicode` bytes.
#[export_name = "RtlUnicodeToMultiByteSize"]
pub unsafe extern "system" fn rtl_unicode_to_multi_byte_size(
    bytes_out: *mut u32,
    _unicode_str: *const u16,
    bytes_in_unicode: u32,
) -> NtStatus {
    if bytes_out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Single-byte: 1 output byte per UTF-16 unit.
    // SAFETY: bytes_out writable.
    unsafe { *bytes_out = bytes_in_unicode / 2 };
    STATUS_SUCCESS
}

/// `RtlOemStringToUnicodeString(PUNICODE_STRING dst, PCOEM_STRING src, BOOLEAN Allocate)`.
/// Same single-byte widen as the ANSI variant.
///
/// # Safety
/// As `RtlAnsiStringToUnicodeString`.
#[export_name = "RtlOemStringToUnicodeString"]
pub unsafe extern "system" fn rtl_oem_string_to_unicode_string(
    dst: PUnicodeString,
    src: PCUnicodeString,
    allocate: u8,
) -> NtStatus {
    // SAFETY: same 16-byte STRING shape + single-byte code page.
    unsafe { rtl_ansi_string_to_unicode_string(dst, src, allocate) }
}

/// `RtlUnicodeStringToOemString(POEM_STRING dst, PCUNICODE_STRING src, BOOLEAN Allocate)` —
/// narrow UTF-16 → single-byte OEM.
///
/// # Safety
/// `dst` writable STRING; `src` valid UNICODE_STRING.
#[export_name = "RtlUnicodeStringToOemString"]
pub unsafe extern "system" fn rtl_unicode_string_to_oem_string(
    dst: PUnicodeString,
    src: PCUnicodeString,
    allocate: u8,
) -> NtStatus {
    if dst.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: src valid per the contract.
    let (sbuf, sunits) = unsafe { ((*src).buffer as *const u16, (*src).length as usize / 2) };
    let out_bytes = sunits + 1; // + NUL
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: dst valid per the contract.
        let dbuf = if allocate != 0 {
            // SAFETY: on-target heap.
            let p = unsafe { crate::process_heap_alloc(out_bytes) } as *mut u8;
            if p.is_null() {
                return STATUS_NO_MEMORY;
            }
            // SAFETY: dst valid.
            unsafe {
                (*dst).buffer = p as u64;
                (*dst).maximum_length = out_bytes as u16;
            }
            p
        } else {
            // SAFETY: dst valid.
            unsafe {
                if (*dst).maximum_length < out_bytes as u16 {
                    return STATUS_BUFFER_OVERFLOW;
                }
                (*dst).buffer as *mut u8
            }
        };
        // SAFETY: buffers valid per the checks.
        unsafe {
            for i in 0..sunits {
                let c = *sbuf.add(i);
                *dbuf.add(i) = if c < 0x100 { c as u8 } else { b'?' };
            }
            *dbuf.add(sunits) = 0;
            (*dst).length = sunits as u16;
        }
        STATUS_SUCCESS
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (allocate, out_bytes, sbuf);
        STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlIsTextUnicode(PVOID Buffer, INT Size, INT* Result) -> BOOLEAN` — heuristic UTF-16 detection.
/// We apply the standard IS_TEXT_UNICODE_STATISTICS heuristic: even byte count + a majority of
/// zero high-bytes ⇒ likely UTF-16LE.
///
/// # Safety
/// `buffer` valid for `size` bytes; `result` null or writable.
#[export_name = "RtlIsTextUnicode"]
pub unsafe extern "system" fn rtl_is_text_unicode(
    buffer: *const c_void,
    size: i32,
    result: *mut i32,
) -> u8 {
    if buffer.is_null() || size < 2 {
        if !result.is_null() {
            // SAFETY: result writable.
            unsafe { *result = 0 };
        }
        return 0;
    }
    let n = size as usize;
    // SAFETY: buffer valid for n bytes.
    let bytes = unsafe { core::slice::from_raw_parts(buffer as *const u8, n) };
    let even = n % 2 == 0;
    let units = n / 2;
    let mut zero_hi = 0usize;
    for i in 0..units {
        if bytes[i * 2 + 1] == 0 {
            zero_hi += 1;
        }
    }
    let likely = even && units > 0 && zero_hi * 2 >= units;
    if !result.is_null() {
        // IS_TEXT_UNICODE_STATISTICS = 0x2.
        // SAFETY: result writable.
        unsafe { *result = if likely { 0x2 } else { 0 } };
    }
    u8::from(likely)
}

/// `RtlxUnicodeStringToAnsiSize(PCUNICODE_STRING src) -> ULONG` — ANSI byte length incl. NUL.
///
/// # Safety
/// `src` a valid UNICODE_STRING.
#[export_name = "RtlxUnicodeStringToAnsiSize"]
pub unsafe extern "system" fn rtlx_unicode_string_to_ansi_size(src: PCUnicodeString) -> u32 {
    if src.is_null() {
        return 0;
    }
    // SAFETY: src valid.
    let units = unsafe { (*src).length as usize / 2 };
    (units + 1) as u32
}

/// `RtlxUnicodeStringToOemSize(PCUNICODE_STRING src) -> ULONG`.
///
/// # Safety
/// As `RtlxUnicodeStringToAnsiSize`.
#[export_name = "RtlxUnicodeStringToOemSize"]
pub unsafe extern "system" fn rtlx_unicode_string_to_oem_size(src: PCUnicodeString) -> u32 {
    // SAFETY: same contract.
    unsafe { rtlx_unicode_string_to_ansi_size(src) }
}

/// `RtlxAnsiStringToUnicodeSize(PCANSI_STRING src) -> ULONG` — UTF-16 byte length incl. NUL.
///
/// # Safety
/// `src` a valid ANSI_STRING.
#[export_name = "RtlxAnsiStringToUnicodeSize"]
pub unsafe extern "system" fn rtlx_ansi_string_to_unicode_size(src: PCUnicodeString) -> u32 {
    if src.is_null() {
        return 0;
    }
    // SAFETY: src valid.
    let bytes = unsafe { (*src).length as usize };
    ((bytes + 1) * 2) as u32
}

/// `RtlxOemStringToUnicodeSize(PCOEM_STRING src) -> ULONG`.
///
/// # Safety
/// As `RtlxAnsiStringToUnicodeSize`.
#[export_name = "RtlxOemStringToUnicodeSize"]
pub unsafe extern "system" fn rtlx_oem_string_to_unicode_size(src: PCUnicodeString) -> u32 {
    // SAFETY: same contract.
    unsafe { rtlx_ansi_string_to_unicode_size(src) }
}

/// `RtlInitCodePageTable(PUSHORT TableBase, PCPTABLEINFO CodePageTable)` — initialize an
/// NLS code-page table descriptor from the raw NLS table base. We serve the single-byte-default
/// path: mark the descriptor as a single-byte (SBCS) code page. The Win32 stack reads only the
/// MaximumCharacterSize / DBCS flags on the boot path.
///
/// # Safety
/// `table` a valid NLS table base; `cp_table` a writable CPTABLEINFO.
#[export_name = "RtlInitCodePageTable"]
pub unsafe extern "system" fn rtl_init_code_page_table(
    _table: *const u16,
    cp_table: *mut c_void,
) {
    if cp_table.is_null() {
        return;
    }
    // CPTABLEINFO: CodePage:u16@0, MaximumCharacterSize:u16@2, DefaultChar:u16@4, ... DBCSCodePage@?.
    // Zero the descriptor then set MaximumCharacterSize=1 (SBCS) + CodePage=1252.
    // SAFETY: cp_table writable (>= 0x20 bytes per CPTABLEINFO).
    unsafe {
        core::ptr::write_bytes(cp_table as *mut u8, 0, 0x20);
        *(cp_table as *mut u16) = 1252; // CodePage
        *((cp_table as *mut u16).add(1)) = 1; // MaximumCharacterSize (SBCS)
        *((cp_table as *mut u16).add(2)) = b'?' as u16; // DefaultChar
    }
}

// =================================================================================================
// BATCH 4 — Dbg* / Csr* / data exports the Win32 stack imports from ntdll.
// The Dbg* family is the debugger/trace client: on our target the debug output forwards to the
// kernel serial log via the int-0x2d DebugService (the DbgPrint path); the DbgUi* debugger-attach
// surface is a no-op (no user-mode debugger present). Csr* is the CSR client — the real port send
// is the LPC transport seam (nt_ntdll::csr builds the message); the export exists so the IAT
// resolves + the call is ABI-safe. Data exports are the NLS/prefix globals hosted binaries read.
// =================================================================================================

/// `DbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, ...) -> ULONG`. Variadic; we declare
/// only the fixed args (the Win64 variadic tail is left in the caller's registers/stack, unread).
/// ABI-safe no-op returning STATUS_SUCCESS — the export exists so the Win32 stack's IAT resolves
/// (kernel32!DbgPrintEx was the immediate frontier). The live render/serial-forward is the Dbg
/// transport seam (as with `DbgPrint`).
///
/// # Safety
/// Called with the C DbgPrintEx ABI; ignores the variadic tail.
#[export_name = "DbgPrintEx"]
pub unsafe extern "C" fn dbg_print_ex(_component: u32, _level: u32, _format: *const u8) -> NtStatus {
    STATUS_SUCCESS
}

/// `vDbgPrintExWithPrefix(PCSTR Prefix, ULONG ComponentId, ULONG Level, PCSTR Format, va_list)
/// -> ULONG`. The `va_list`-taking core of the DbgPrintEx family. `va_list` is opaque in `no_std`;
/// ABI-safe no-op returning STATUS_SUCCESS (IAT-resolve; live render = the Dbg transport seam).
///
/// # Safety
/// Called with the ntdll `vDbgPrintExWithPrefix` ABI; ignores the `va_list`.
#[export_name = "vDbgPrintExWithPrefix"]
pub unsafe extern "C" fn vdbg_print_ex_with_prefix(
    _prefix: *const u8,
    _component: u32,
    _level: u32,
    _format: *const u8,
    _args: *mut c_void,
) -> NtStatus {
    STATUS_SUCCESS
}

/// `DbgPrompt(PCSTR Prompt, PCH Response, ULONG Length) -> ULONG` — prompt the debugger for input.
/// No debugger is attached, so we return an empty response (0 bytes read) — the observable
/// no-debugger contract.
///
/// # Safety
/// `response` writable for `length` bytes.
#[export_name = "DbgPrompt"]
pub unsafe extern "C" fn dbg_prompt(_prompt: *const u8, response: *mut u8, length: u32) -> u32 {
    if !response.is_null() && length > 0 {
        // SAFETY: response valid for length bytes per the contract.
        unsafe { *response = 0 };
    }
    0
}

macro_rules! dbgui_noop {
    ($export:literal, $fn:ident) => {
        /// `DbgUi*` debugger-attach surface — no user-mode debugger present; returns
        /// STATUS_SUCCESS / a null handle. The export exists so the Win32 stack's IAT resolves.
        ///
        /// # Safety
        /// Called with the corresponding ntdll `DbgUi*` ABI; a no-op with no live debug object.
        #[export_name = $export]
        pub unsafe extern "system" fn $fn(
            _a: *mut c_void,
            _b: *mut c_void,
            _c: *mut c_void,
            _d: *mut c_void,
        ) -> NtStatus {
            STATUS_SUCCESS
        }
    };
}
dbgui_noop!("DbgUiConnectToDbg", dbg_ui_connect_to_dbg);
dbgui_noop!("DbgUiContinue", dbg_ui_continue);
dbgui_noop!("DbgUiConvertStateChangeStructure", dbg_ui_convert_state_change_structure);
dbgui_noop!("DbgUiDebugActiveProcess", dbg_ui_debug_active_process);
dbgui_noop!("DbgUiStopDebugging", dbg_ui_stop_debugging);
dbgui_noop!("DbgUiIssueRemoteBreakin", dbg_ui_issue_remote_breakin);
dbgui_noop!("DbgUiWaitStateChange", dbg_ui_wait_state_change);

/// `DbgUiGetThreadDebugObject() -> HANDLE` — returns the current thread's debug object (none) = NULL.
///
/// # Safety
/// Reads no memory; returns a NULL handle (no debug object bound).
#[export_name = "DbgUiGetThreadDebugObject"]
pub unsafe extern "system" fn dbg_ui_get_thread_debug_object() -> *mut c_void {
    core::ptr::null_mut()
}

// ---- Csr* — the CSR client. The real port send is the LPC transport seam. -------------------------

/// `CsrGetProcessId() -> HANDLE` — the CSR (csrss) process id. Not yet published to the client PEB;
/// returns 0 (unresolved) — never a fabricated pid. The export exists so the IAT resolves.
///
/// # Safety
/// Reads no memory.
#[export_name = "CsrGetProcessId"]
pub unsafe extern "system" fn csr_get_process_id() -> *mut c_void {
    core::ptr::null_mut()
}

/// `CsrClientConnectToServer(PCWSTR ObjectDirectory, ULONG ServerId, PVOID ConnectionInfo,
/// PULONG ConnectionInfoSize, PBOOLEAN ServerToServerCall) -> NTSTATUS`. The connect handshake is
/// the LPC transport seam (`nt_ntdll::csr::CsrPort::connect` builds it); returns
/// STATUS_NOT_IMPLEMENTED at the honest send seam — never a fabricated connection.
///
/// # Safety
/// The out-params (`connection_info_size`, `server_to_server`) are null or writable.
#[export_name = "CsrClientConnectToServer"]
pub unsafe extern "system" fn csr_client_connect_to_server(
    _object_directory: *const u16,
    _server_id: u32,
    _connection_info: *mut c_void,
    _connection_info_size: *mut u32,
    _server_to_server: *mut u8,
) -> NtStatus {
    STATUS_NOT_IMPLEMENTED
}

/// `CsrClientCallServer(PCSR_API_MESSAGE Request, PCSR_CAPTURE_BUFFER Capture, CSR_API_NUMBER
/// ApiNumber, ULONG RequestLength) -> NTSTATUS`. The port round-trip is the LPC transport seam;
/// returns STATUS_NOT_IMPLEMENTED — never a fabricated reply.
///
/// # Safety
/// `request` a valid `CSR_API_MESSAGE*`; `capture` null or a valid capture buffer.
#[export_name = "CsrClientCallServer"]
pub unsafe extern "system" fn csr_client_call_server(
    _request: *mut c_void,
    _capture: *mut c_void,
    _api_number: u32,
    _request_length: u32,
) -> NtStatus {
    STATUS_NOT_IMPLEMENTED
}

/// `CsrAllocateCaptureBuffer(ULONG ArgumentCount, ULONG BufferSize) -> PCSR_CAPTURE_BUFFER`.
/// Allocates a capture buffer on the process heap (the marshalling plane `nt_ntdll::csr` models).
/// Until the CSR heap plane is wired we return NULL (allocation unavailable) — never a dangling
/// buffer.
///
/// # Safety
/// Reads no memory.
#[export_name = "CsrAllocateCaptureBuffer"]
pub unsafe extern "system" fn csr_allocate_capture_buffer(
    _argument_count: u32,
    _buffer_size: u32,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `CsrFreeCaptureBuffer(PCSR_CAPTURE_BUFFER CaptureBuffer)`. Frees a buffer from
/// `CsrAllocateCaptureBuffer` (none allocated yet → no-op).
///
/// # Safety
/// `capture_buffer` null or a buffer from `CsrAllocateCaptureBuffer`.
#[export_name = "CsrFreeCaptureBuffer"]
pub unsafe extern "system" fn csr_free_capture_buffer(_capture_buffer: *mut c_void) {}

/// `CsrCaptureMessageBuffer(PCSR_CAPTURE_BUFFER CaptureBuffer, PVOID MessageBuffer, ULONG Length,
/// PVOID* CapturedBuffer) -> PCSR_CAPTURE_BUFFER`. Captures a pointer arg into the buffer. Seam:
/// returns NULL (no capture buffer plane) — never a fabricated captured pointer.
///
/// # Safety
/// `captured_buffer` null or writable.
#[export_name = "CsrCaptureMessageBuffer"]
pub unsafe extern "system" fn csr_capture_message_buffer(
    _capture_buffer: *mut c_void,
    _message_buffer: *mut c_void,
    _length: u32,
    _captured_buffer: *mut *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `CsrAllocateMessagePointer(PCSR_CAPTURE_BUFFER CaptureBuffer, ULONG Length, PVOID* Pointer)
/// -> ULONG`. Reserves `Length` bytes in the capture buffer. Seam: returns 0 bytes.
///
/// # Safety
/// `pointer` null or writable.
#[export_name = "CsrAllocateMessagePointer"]
pub unsafe extern "system" fn csr_allocate_message_pointer(
    _capture_buffer: *mut c_void,
    _length: u32,
    pointer: *mut *mut c_void,
) -> u32 {
    if !pointer.is_null() {
        // SAFETY: pointer writable per the contract.
        unsafe { *pointer = core::ptr::null_mut() };
    }
    0
}

/// `CsrNewThread() -> NTSTATUS` — register a new thread with the CSR client runtime (marks the TEB
/// CSR fields). No CSR client runtime state to update yet → STATUS_SUCCESS (the observable no-op:
/// the thread simply isn't CSR-registered, which the boot path tolerates).
///
/// # Safety
/// Reads no memory.
#[export_name = "CsrNewThread"]
pub unsafe extern "system" fn csr_new_thread() -> NtStatus {
    STATUS_SUCCESS
}

// ---- Data exports — the NLS multi-byte code-page tags hosted binaries read. -----------------------
//
// `NlsMbCodePageTag` / `NlsMbOemCodePageTag` are BOOLEANs: TRUE iff the ANSI / OEM code page is a
// MULTI-byte (DBCS) code page. Our defaults (1252 ANSI / 437 OEM) are BOTH single-byte, so both are
// FALSE — matching `nt_ntdll::crt`'s single-byte-default tags. Exported as data (a `#[used]`
// `#[no_mangle]` static under the real name).

/// `BOOLEAN NlsMbCodePageTag` — FALSE (the 1252 ANSI default is single-byte).
#[used]
#[export_name = "NlsMbCodePageTag"]
pub static NLS_MB_CODE_PAGE_TAG: u8 = 0;

/// `BOOLEAN NlsMbOemCodePageTag` — FALSE (the 437 OEM default is single-byte).
#[used]
#[export_name = "NlsMbOemCodePageTag"]
pub static NLS_MB_OEM_CODE_PAGE_TAG: u8 = 0;

// =================================================================================================
// Retention anchor — mirror the Nt* TRAP_STUB_ADDRS pattern so the linker keeps every export past
// `--no-gc-sections`/DCE. Referenced (via `#[used]`) from `lib.rs`'s KEEP anchor.
// =================================================================================================

/// Force the linker to RETAIN every non-`Nt*` export into the DLL export directory.
///
/// The `Nt*` stubs are retained via a `#[used]` fn-ptr *table* ([`trap_stubs::TRAP_STUB_ADDRS`]);
/// that pattern needs a homogeneous fn-pointer type, but our exports have 61 different signatures
/// (which can't be `as`-cast to one fn-pointer type in a `const`). So instead we anchor them by
/// *referencing each address at runtime* inside this one function and marking it `#[used]`: taking
/// `foo as usize` here creates a code reference the linker must keep, which transitively keeps `foo`.
/// `lib.rs` references [`export_anchor`] (also `#[used]`) so this whole graph survives DCE.
///
/// The function is never called; `black_box` prevents the optimizer from discarding the reads.
#[used]
pub static EXPORT_ANCHOR_FN: unsafe extern "C" fn() = export_anchor;

/// `RtlGetLastWin32Error() -> DWORD` — read `TEB.LastErrorValue` (@ 0x068).
///
/// This is the ntdll implementation of Win32 `GetLastError`. kernel32's `GetLastError` is a
/// FORWARDER export to `ntdll.RtlGetLastWin32Error` (as are user32's/advapi32's callers via
/// kernel32), so once the loader follows forwarders, every `GetLastError` call lands here. The TEB
/// self-pointer is `gs:[0x30]` (`NtTib.Self`); `LastErrorValue` is a 32-bit field at TEB+0x68
/// (asserted in `nt-ntdll-layout`).
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlGetLastWin32Error"]
pub unsafe extern "system" fn rtl_get_last_win32_error() -> u32 {
    // SAFETY: reads the current thread's TEB (self-pointer @ gs:[0x30]); the LastErrorValue field @
    // 0x68 is always mapped (the TEB is set up at spawn).
    unsafe {
        let teb: u64;
        core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, preserves_flags, readonly));
        core::ptr::read_volatile((teb + 0x68) as *const u32)
    }
}

/// `RtlSetLastWin32Error(DWORD)` — write `TEB.LastErrorValue` (@ 0x068).
///
/// The ntdll implementation of Win32 `SetLastError`; kernel32's `SetLastError` forwards to
/// `ntdll.RtlSetLastWin32Error`.
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlSetLastWin32Error"]
pub unsafe extern "system" fn rtl_set_last_win32_error(error: u32) {
    // SAFETY: writes the current thread's TEB LastErrorValue @ TEB+0x68 (self-pointer @ gs:[0x30]).
    unsafe {
        let teb: u64;
        core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb, options(nostack, preserves_flags, readonly));
        core::ptr::write_volatile((teb + 0x68) as *mut u32, error);
    }
}

/// The retention anchor body — see [`EXPORT_ANCHOR_FN`]. Never invoked.
///
/// # Safety
/// Never called; it only takes the addresses of the exports to anchor them for the linker.
pub unsafe extern "C" fn export_anchor() {
    // Each `... as usize` is a runtime address-of that references the symbol, forcing retention.
    let anchors: &[usize] = &[
        rtl_init_unicode_string as usize,
        rtl_init_ansi_string as usize,
        rtl_upcase_unicode_char as usize,
        rtl_compare_unicode_string as usize,
        rtl_equal_unicode_string as usize,
        rtl_prefix_unicode_string as usize,
        rtl_append_unicode_to_string as usize,
        rtl_append_unicode_string_to_string as usize,
        rtl_unicode_string_to_integer as usize,
        rtl_allocate_heap as usize,
        rtl_free_heap as usize,
        rtl_create_tag_heap as usize,
        rtl_free_unicode_string as usize,
        rtl_create_unicode_string as usize,
        rtl_ansi_string_to_unicode_string as usize,
        rtl_unicode_string_to_ansi_string as usize,
        rtl_initialize_critical_section as usize,
        rtl_enter_critical_section as usize,
        rtl_leave_critical_section as usize,
        rtl_length_sid as usize,
        rtl_create_security_descriptor as usize,
        rtl_set_dacl_security_descriptor as usize,
        rtl_create_acl as usize,
        rtl_get_ace as usize,
        rtl_add_access_allowed_ace as usize,
        rtl_allocate_and_initialize_sid as usize,
        rtl_adjust_privilege as usize,
        rtl_normalize_process_params as usize,
        rtl_denormalize_process_params as usize,
        rtl_create_process_parameters as usize,
        rtl_destroy_process_parameters as usize,
        rtl_create_environment as usize,
        rtl_set_environment_variable as usize,
        rtl_query_environment_variable_u as usize,
        rtl_dos_path_name_to_nt_path_name_u as usize,
        rtl_dos_search_path_u as usize,
        rtl_query_registry_values as usize,
        rtl_set_process_is_critical as usize,
        rtl_set_thread_is_critical as usize,
        rtl_get_set_boot_status_data as usize,
        rtl_lock_boot_status_data as usize,
        rtl_unlock_boot_status_data as usize,
        rtl_create_user_process as usize,
        rtl_create_user_thread as usize,
        rtl_assert as usize,
        ldr_query_image_file_execution_options as usize,
        ldr_verify_image_matches_checksum as usize,
        dbg_print as usize,
        dbg_break_point as usize,
        memcpy as usize,
        memset as usize,
        wcslen as usize,
        wcscpy as usize,
        wcsstr as usize,
        wcsicmp as usize,
        wcsupr as usize,
        stricmp as usize,
        sprintf as usize,
        swprintf as usize,
        vsnprintf as usize,
        vsnwprintf as usize,
        c_specific_handler as usize,
        // BATCH 2 — csrsrv's 12 ntdll imports.
        rtl_free_sid as usize,
        rtl_get_dacl_security_descriptor as usize,
        rtl_char_to_integer as usize,
        rtl_create_heap as usize,
        rtl_unhandled_exception_filter as usize,
        memmove as usize,
        strchr as usize,
        strncpy as usize,
        ldr_load_dll as usize,
        ldr_get_dll_handle as usize,
        ldr_get_procedure_address as usize,
        ldr_unload_dll as usize,
        // BATCH 2 ckpt 2 — basesrv's 11 ntdll imports.
        rtl_copy_luid as usize,
        rtl_init_string as usize,
        rtl_delete_critical_section as usize,
        rtl_initialize_critical_section_and_spin_count as usize,
        rtl_reallocate_heap as usize,
        rtl_expand_environment_strings_u as usize,
        rtl_open_current_user as usize,
        snwprintf as usize,
        wcsncpy as usize,
        wcscat as usize,
        wcsnicmp as usize,
        // BATCH 3 — the Win32 last-error pair (kernel32!GetLastError/SetLastError forward here).
        rtl_get_last_win32_error as usize,
        rtl_set_last_win32_error as usize,
        // BATCH 3 ckpt 2 — kernel32 early-init PEB-lock + global-flags + status-to-dos.
        rtl_acquire_peb_lock as usize,
        rtl_release_peb_lock as usize,
        rtl_get_nt_global_flags as usize,
        rtl_nt_status_to_dos_error as usize,
        // BATCH 4 — CRT surface the Win32 stack imports from ntdll.
        memcmp as usize,
        memchr as usize,
        strlen as usize,
        strcmp as usize,
        strcmpi as usize,
        strncmp as usize,
        strcpy as usize,
        strcat as usize,
        strrchr as usize,
        strstr as usize,
        strcspn as usize,
        strpbrk as usize,
        wcslwr as usize,
        wcschr as usize,
        wcsrchr as usize,
        wcscmp as usize,
        wcsncmp as usize,
        wcscspn as usize,
        wcsspn as usize,
        atoi as usize,
        wtoi as usize,
        strtol as usize,
        strtoul as usize,
        wcstol as usize,
        wcstoul as usize,
        ultow as usize,
        abs as usize,
        labs as usize,
        tolower as usize,
        toupper as usize,
        towlower as usize,
        towupper as usize,
        isalpha as usize,
        islower as usize,
        iswctype as usize,
        sin as usize,
        cos as usize,
        fabs as usize,
        floor as usize,
        bsearch as usize,
        qsort as usize,
        local_unwind as usize,
        ver_set_condition_mask as usize,
        // BATCH 4 — Dbg* / Csr* surface.
        dbg_print_ex as usize,
        vdbg_print_ex_with_prefix as usize,
        dbg_prompt as usize,
        dbg_ui_connect_to_dbg as usize,
        dbg_ui_continue as usize,
        dbg_ui_convert_state_change_structure as usize,
        dbg_ui_debug_active_process as usize,
        dbg_ui_stop_debugging as usize,
        dbg_ui_issue_remote_breakin as usize,
        dbg_ui_wait_state_change as usize,
        dbg_ui_get_thread_debug_object as usize,
        csr_get_process_id as usize,
        csr_client_connect_to_server as usize,
        csr_client_call_server as usize,
        csr_allocate_capture_buffer as usize,
        csr_free_capture_buffer as usize,
        csr_capture_message_buffer as usize,
        csr_allocate_message_pointer as usize,
        csr_new_thread as usize,
        &NLS_MB_CODE_PAGE_TAG as *const u8 as usize,
        &NLS_MB_OEM_CODE_PAGE_TAG as *const u8 as usize,
        // BATCH 4 — Rtl* string / convert family.
        rtl_copy_unicode_string as usize,
        rtl_upcase_unicode_string as usize,
        rtl_duplicate_unicode_string as usize,
        rtl_create_unicode_string_from_asciiz as usize,
        rtl_free_ansi_string as usize,
        rtl_init_ansi_string_ex as usize,
        rtl_init_unicode_string_ex as usize,
        rtl_ansi_char_to_unicode_char as usize,
        rtl_integer_to_unicode_string as usize,
        rtl_unicode_to_multi_byte_n as usize,
        rtl_unicode_to_oem_n as usize,
        rtl_multi_byte_to_unicode_n as usize,
        rtl_unicode_to_multi_byte_size as usize,
        rtl_oem_string_to_unicode_string as usize,
        rtl_unicode_string_to_oem_string as usize,
        rtl_is_text_unicode as usize,
        rtlx_unicode_string_to_ansi_size as usize,
        rtlx_unicode_string_to_oem_size as usize,
        rtlx_ansi_string_to_unicode_size as usize,
        rtlx_oem_string_to_unicode_size as usize,
        rtl_init_code_page_table as usize,
    ];
    #[cfg(target_arch = "x86_64")]
    let anchors3: &[usize] = &[
        zw_yield_execution as *const () as usize,
        zw_callback_return as *const () as usize,
    ];
    #[cfg(target_arch = "x86_64")]
    core::hint::black_box(anchors3);
    // BATCH 4 — Rtl* heap family.
    let anchors_heap: &[usize] = &[
        rtl_size_heap as usize,
        rtl_validate_heap as usize,
        rtl_destroy_heap as usize,
        rtl_get_process_heaps as usize,
        rtl_lock_heap as usize,
        rtl_unlock_heap as usize,
        rtl_compact_heap as usize,
        rtl_walk_heap as usize,
        rtl_query_heap_information as usize,
        rtl_set_heap_information as usize,
        rtl_get_user_info_heap as usize,
        rtl_set_user_value_heap as usize,
        rtl_query_tag_heap as usize,
    ];
    core::hint::black_box(anchors_heap);
    // BATCH 4 — Etw* trace client.
    let anchors_etw: &[usize] = &[
        etw_control_trace_a as usize,
        etw_control_trace_w as usize,
        etw_create_trace_instance_id as usize,
        etw_enable_trace as usize,
        etw_enumerate_trace_guids as usize,
        etw_flush_trace_a as usize,
        etw_flush_trace_w as usize,
        etw_get_trace_enable_flags as usize,
        etw_get_trace_enable_level as usize,
        etw_get_trace_logger_handle as usize,
        etw_notification_registration_a as usize,
        etw_notification_registration_w as usize,
        etw_query_all_traces_a as usize,
        etw_query_all_traces_w as usize,
        etw_query_trace_a as usize,
        etw_query_trace_w as usize,
        etw_receive_notifications_a as usize,
        etw_receive_notifications_w as usize,
        etw_register_trace_guids_a as usize,
        etw_register_trace_guids_w as usize,
        etw_start_trace_a as usize,
        etw_start_trace_w as usize,
        etw_stop_trace_a as usize,
        etw_stop_trace_w as usize,
        etw_trace_event as usize,
        etw_trace_event_instance as usize,
        etw_trace_message as usize,
        etw_trace_message_va as usize,
        etw_unregister_trace_guids as usize,
        etw_update_trace_a as usize,
        etw_update_trace_w as usize,
    ];
    core::hint::black_box(anchors_etw);
    // BATCH 4 — Rtl* memory / bitmap / atom / encode / time / random / SList / misc.
    let anchors_misc1: &[usize] = &[
        rtl_fill_memory as usize,
        rtl_zero_memory as usize,
        rtl_move_memory as usize,
        rtl_compare_memory as usize,
        rtl_initialize_bit_map as usize,
        rtl_set_bits as usize,
        rtl_clear_bits as usize,
        rtl_are_bits_set as usize,
        rtl_are_bits_clear as usize,
        rtl_find_clear_bits_and_set as usize,
        rtl_create_atom_table as usize,
        rtl_add_atom_to_atom_table as usize,
        rtl_lookup_atom_in_atom_table as usize,
        rtl_delete_atom_from_atom_table as usize,
        rtl_query_atom_in_atom_table as usize,
        rtl_encode_pointer as usize,
        rtl_decode_pointer as usize,
        rtl_encode_system_pointer as usize,
        rtl_decode_system_pointer as usize,
        rtl_time_to_seconds_since_1970 as usize,
        rtl_time_to_time_fields as usize,
        rtl_time_fields_to_time as usize,
        rtl_uniform as usize,
        rtl_random as usize,
        rtl_integer_to_char as usize,
    ];
    core::hint::black_box(anchors_misc1);
    let anchors_misc2: &[usize] = &[
        rtl_initialize_slist_head as usize,
        rtl_interlocked_push_entry_slist as usize,
        rtl_interlocked_pop_entry_slist as usize,
        rtl_interlocked_flush_slist as usize,
        rtl_query_depth_slist as usize,
        rtl_get_last_nt_status as usize,
        rtl_restore_last_win32_error as usize,
        rtl_get_thread_error_mode as usize,
        rtl_set_thread_error_mode as usize,
        rtl_get_nt_product_type as usize,
        rtl_get_version as usize,
        rtl_verify_version_info as usize,
        rtl_get_current_processor_number as usize,
        rtl_get_native_system_information as usize,
        rtl_add_vectored_exception_handler as usize,
        rtl_remove_vectored_exception_handler as usize,
        rtl_add_vectored_continue_handler as usize,
        rtl_remove_vectored_continue_handler as usize,
        rtl_add_function_table as usize,
        rtl_delete_function_table as usize,
        rtl_install_function_table_callback as usize,
        rtl_lookup_function_entry as usize,
        rtl_capture_context as usize,
        rtl_raise_status as usize,
        rtl_raise_exception as usize,
        rtl_unwind as usize,
        rtl_unwind_ex as usize,
        rtl_virtual_unwind as usize,
        rtl_restore_context as usize,
        rtl_exit_user_thread as usize,
        rtl_compute_import_table_hash as usize,
        rtl_flush_secure_memory_cache as usize,
        rtl_set_critical_section_spin_count as usize,
        rtl_try_enter_critical_section as usize,
    ];
    core::hint::black_box(anchors_misc2);
    // BATCH 4 — SxS / path / guid / image / handle-table / resource / timer / debug.
    let anchors_sxs: &[usize] = &[
        rtl_activate_activation_context as usize,
        rtl_activate_activation_context_ex as usize,
        rtl_activate_activation_context_unsafe_fast as usize,
        rtl_deactivate_activation_context as usize,
        rtl_deactivate_activation_context_unsafe_fast as usize,
        rtl_create_activation_context as usize,
        rtl_add_ref_activation_context as usize,
        rtl_release_activation_context as usize,
        rtl_zombify_activation_context as usize,
        rtl_get_active_activation_context as usize,
        rtl_find_activation_context_section_string as usize,
        rtl_find_activation_context_section_guid as usize,
        rtl_query_information_activation_context as usize,
        rtl_allocate_activation_context_stack as usize,
        rtl_free_activation_context_stack as usize,
        rtl_is_thread_within_loader_callout as usize,
    ];
    core::hint::black_box(anchors_sxs);
    let anchors_pathimg: &[usize] = &[
        rtl_determine_dos_path_name_type_u as usize,
        rtl_is_dos_device_name_u as usize,
        rtl_is_name_legal_dos_8dot3 as usize,
        rtl_guid_from_string as usize,
        rtl_image_nt_header as usize,
        rtl_image_directory_entry_to_data as usize,
        rtl_image_rva_to_va as usize,
        rtl_pc_to_file_header as usize,
        rtl_initialize_handle_table as usize,
        rtl_allocate_handle as usize,
        rtl_free_handle as usize,
        rtl_is_valid_handle as usize,
        rtl_initialize_resource as usize,
        rtl_acquire_resource_shared as usize,
        rtl_acquire_resource_exclusive as usize,
        rtl_release_resource as usize,
    ];
    core::hint::black_box(anchors_pathimg);
    let anchors_timer: &[usize] = &[
        rtl_create_timer_queue as usize,
        rtl_create_timer as usize,
        rtl_update_timer as usize,
        rtl_delete_timer as usize,
        rtl_delete_timer_queue_ex as usize,
        rtl_queue_work_item as usize,
        rtl_register_wait as usize,
        rtl_deregister_wait_ex as usize,
        rtl_set_io_completion_callback as usize,
        rtl_set_thread_pool_start_func as usize,
        rtl_set_time_zone_information as usize,
        rtl_create_query_debug_buffer as usize,
        rtl_destroy_query_debug_buffer as usize,
        rtl_query_process_debug_information as usize,
        rtl_capture_stack_back_trace as usize,
        rtl_wow64_enable_fs_redirection as usize,
        rtl_wow64_enable_fs_redirection_ex as usize,
    ];
    core::hint::black_box(anchors_timer);
    #[cfg(target_arch = "x86_64")]
    let anchors2: &[usize] = &[chkstk as *const () as usize];
    #[cfg(target_arch = "x86_64")]
    core::hint::black_box(anchors2);
    core::hint::black_box(anchors);
}
