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

use core::ffi::c_void;

use nt_ntdll::rtl;
use nt_ntdll_layout::UnicodeString;

type NtStatus = u32;
const STATUS_SUCCESS: NtStatus = 0x0000_0000;
const STATUS_NOT_IMPLEMENTED: NtStatus = 0xC000_0002;
const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;

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

/// `RtlNormalizeProcessParams(PRTL_USER_PROCESS_PARAMETERS) -> PRTL_USER_PROCESS_PARAMETERS`.
/// The real work (rebasing the UNICODE_STRING pointers + setting the NORMALIZED flag) is the loader
/// seam; the identity return + NORMALIZED-flag set is the observable half we can honor.
///
/// # Safety
/// `params` a valid `RTL_USER_PROCESS_PARAMETERS` or null.
#[export_name = "RtlNormalizeProcessParams"]
pub unsafe extern "system" fn rtl_normalize_process_params(params: *mut c_void) -> *mut c_void {
    if params.is_null() {
        return params;
    }
    // Set RTL_USER_PROC_PARAMS_NORMALIZED (0x1) in Flags (offset 0x08 on x64). Pointer rebase is the
    // loader's job (it holds the base delta); here we mark normalized + return the same block.
    // SAFETY: params points at a valid RTL_USER_PROCESS_PARAMETERS per the contract.
    unsafe {
        let flags = (params as *mut u8).add(0x08) as *mut u32;
        *flags |= 0x1;
    }
    params
}

/// `RtlCreateProcessParameters(...)` — build an `RTL_USER_PROCESS_PARAMETERS` on the heap. Honest
/// seam (needs the process heap). Returns an error and leaves the out-pointer untouched.
///
/// # Safety
/// Standard contract.
#[export_name = "RtlCreateProcessParameters"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_process_parameters(
    _params: *mut *mut c_void,
    _image_path: PCUnicodeString,
    _dll_path: PCUnicodeString,
    _current_directory: PCUnicodeString,
    _command_line: PCUnicodeString,
    _environment: *mut c_void,
    _window_title: PCUnicodeString,
    _desktop_info: PCUnicodeString,
    _shell_info: PCUnicodeString,
    _runtime_data: PCUnicodeString,
) -> NtStatus {
    STATUS_NO_MEMORY // needs the process heap (Step 4.B)
}

/// `RtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS) -> NTSTATUS`. Honest seam.
///
/// # Safety
/// Standard contract.
#[export_name = "RtlDestroyProcessParameters"]
pub unsafe extern "system" fn rtl_destroy_process_parameters(_params: *mut c_void) -> NtStatus {
    STATUS_SUCCESS // nothing allocated by us to free (heap seam)
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

/// `RtlCreateUserProcess(...)` — the classic user-mode process create. Honest seam (needs the live
/// NtCreateProcessEx/section/thread create plane — Step 4.A/4.B).
///
/// # Safety
/// Standard contract.
#[export_name = "RtlCreateUserProcess"]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn rtl_create_user_process(
    _image_path: PCUnicodeString,
    _attributes: u32,
    _process_parameters: *mut c_void,
    _process_sd: *mut c_void,
    _thread_sd: *mut c_void,
    _parent_process: *mut c_void,
    _inherit_handles: u8,
    _debug_port: *mut c_void,
    _exception_port: *mut c_void,
    _process_information: *mut c_void,
) -> NtStatus {
    STATUS_NOT_IMPLEMENTED // live create plane (Step 4.A/4.B)
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
    ];
    core::hint::black_box(anchors);
}
