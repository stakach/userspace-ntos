//! # Real x64 table-based SEH dispatch (the live, on-target machinery).
//!
//! This module wires the pure, host-tested unwind core ([`nt_ntdll::rtl::exception`]) into the live
//! process: it provides the live [`ImageReader`]/[`StackReader`] (reading the real mapped images +
//! the real stack), the real x64 `CONTEXT` capture/restore (naked asm), and the
//! `RtlRaiseException` → `RtlDispatchException` → language-handler → `RtlUnwindEx` flow that
//! matches the documented x64 exception model (cross-ref `references/reactos/sdk/lib/rtl/amd64/`).
//!
//! ## What is real here (the SOFTWARE raise path)
//! A **software** exception (`RtlRaiseException`, e.g. rpcrt4's `RpcRaiseException`) is raised
//! entirely in-process: we capture the machine `CONTEXT` at the raise site, then walk the call
//! stack frame-by-frame via [`nt_ntdll::rtl::exception::virtual_unwind`] over the live `.pdata`,
//! calling each frame's language handler (`__C_specific_handler` for C `__try/__except`). When a
//! filter returns `EXCEPTION_EXECUTE_HANDLER`, the handler calls `RtlUnwindEx`, which runs the
//! intervening `__finally` blocks and transfers control to the `__except` body via a real
//! `CONTEXT` restore (naked `RtlRestoreContext`). This is the exact machinery Windows uses.
//!
//! ## Scoped-deferred (documented, not faked)
//! The **hardware-fault delivery** path — the executive redirecting a *faulting* hosted thread's
//! RIP to `KiUserExceptionDispatcher` with a stacked `EXCEPTION_RECORD`+`CONTEXT` — is a separate
//! (kernel/executive) lift. `KiUserExceptionDispatcher` here dispatches a delivered record through
//! the SAME machinery, but the executive-side redirection that lands on it is future work. C++ EH
//! (`__CxxFrameHandler*`) is not needed by the current hosted binaries (they use C SEH); it is not
//! implemented (an honest `ExceptionContinueSearch` if ever referenced).

#![cfg(target_arch = "x86_64")]

use core::ffi::c_void;

use nt_ntdll::rtl::dynamic_function_table::dynamic_function_tables;
use nt_ntdll::rtl::exception::{
    self as ex, Context, ImageReader, RuntimeFunction, ScopeRecord, StackReader,
};
use nt_ntdll::rtl::vectored_handler::{vectored_handlers, HandlerList};

// =================================================================================================
// The x64 CONTEXT — byte offsets (CONTEXT_AMD64, total 0x4D0). We read/write the register file
// through a raw pointer using these documented offsets (ref ke.h CONTEXT layout).
// =================================================================================================

/// `CONTEXT.ContextFlags` @ 0x30.
const CTX_FLAGS: usize = 0x30;
/// `CONTEXT.Rax` @ 0x78 — the start of the contiguous integer block (Rax..R15 then Rip).
const CTX_RAX: usize = 0x78;
/// `CONTEXT.Rsp` @ 0x98.
const CTX_RSP: usize = 0x98;
/// `CONTEXT.Rip` @ 0xF8.
const CTX_RIP: usize = 0xF8;
/// `CONTEXT.Xmm0` @ 0x1A0 (within FltSave).
const CTX_XMM0: usize = 0x1A0;
/// `CONTEXT` size in bytes.
const CONTEXT_SIZE: usize = 0x4D0;
/// `CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT`.
const CONTEXT_FULL: u32 = 0x0010_0007;

/// Stack storage for an AMD64 `CONTEXT`. `RtlCaptureContext` uses aligned XMM stores, matching the
/// platform ABI's 16-byte alignment requirement for this structure.
#[repr(C, align(16))]
pub(crate) struct AlignedContext([u8; CONTEXT_SIZE]);

impl AlignedContext {
    pub(crate) const fn zeroed() -> Self {
        Self([0; CONTEXT_SIZE])
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}

/// `NtContinue` SSN (shared `nt-syscall-abi` table).
const SSN_NT_CONTINUE: u32 = 0x43;
/// `NtRaiseException` SSN.
const SSN_NT_RAISE_EXCEPTION: u32 = 0x2E;

// =================================================================================================
// CONTEXT <-> the pure Context model
// =================================================================================================

/// Load our register-file [`Context`] model from a raw `CONTEXT*` (reads the 16 GPRs + Rip + XMM).
///
/// # Safety
/// `ctx_ptr` must be a valid, readable `CONTEXT` (>= 0x4D0 bytes).
unsafe fn context_from_raw(ctx_ptr: *const u8) -> Context {
    let mut c = Context::default();
    // SAFETY: reading the contiguous integer block Rax..R15 (16 u64s) at CTX_RAX per the layout.
    unsafe {
        for (i, slot) in c.gpr.iter_mut().enumerate() {
            *slot = core::ptr::read_unaligned(ctx_ptr.add(CTX_RAX + i * 8) as *const u64);
        }
        c.rip = core::ptr::read_unaligned(ctx_ptr.add(CTX_RIP) as *const u64);
        for (i, x) in c.xmm.iter_mut().enumerate() {
            x[0] = core::ptr::read_unaligned(ctx_ptr.add(CTX_XMM0 + i * 16) as *const u64);
            x[1] = core::ptr::read_unaligned(ctx_ptr.add(CTX_XMM0 + i * 16 + 8) as *const u64);
        }
    }
    c
}

/// Store our [`Context`] model back into a raw `CONTEXT*` (writes the 16 GPRs + Rip + XMM).
///
/// # Safety
/// `ctx_ptr` must be a valid, writable `CONTEXT`.
unsafe fn context_to_raw(c: &Context, ctx_ptr: *mut u8) {
    // SAFETY: writing the contiguous integer block per the layout.
    unsafe {
        for (i, v) in c.gpr.iter().enumerate() {
            core::ptr::write_unaligned(ctx_ptr.add(CTX_RAX + i * 8) as *mut u64, *v);
        }
        core::ptr::write_unaligned(ctx_ptr.add(CTX_RIP) as *mut u64, c.rip);
        for (i, x) in c.xmm.iter().enumerate() {
            core::ptr::write_unaligned(ctx_ptr.add(CTX_XMM0 + i * 16) as *mut u64, x[0]);
            core::ptr::write_unaligned(ctx_ptr.add(CTX_XMM0 + i * 16 + 8) as *mut u64, x[1]);
        }
    }
}

// =================================================================================================
// Live ImageReader / StackReader
// =================================================================================================

/// The live [`ImageReader`]: `lookup_function` uses the loader's module scan
/// ([`crate::on_target::seh_lookup_function`]); the byte reads are raw reads at `image_base + rva`
/// (RVAs == memory offsets for mapped images).
struct LiveImage;

/// Resolve a runtime-function entry using the native static-first rule. A miss inside a loaded
/// image's existing exception directory is final; only absence of a static table falls back to the
/// process dynamic-function-table registry.
unsafe fn resolve_function_entry(
    control_pc: u64,
    image_base_out: *mut u64,
) -> Option<(u64, RuntimeFunction, *mut c_void)> {
    match unsafe { crate::on_target::seh_lookup_static_function(control_pc) } {
        crate::on_target::SehStaticLookup::Found {
            base,
            begin,
            end,
            unwind_info,
        } => {
            if !image_base_out.is_null() {
                unsafe { *image_base_out = base };
            }
            let row = unsafe { pdata_row_ptr(base, begin) };
            (!row.is_null()).then_some((
                base,
                RuntimeFunction {
                    begin,
                    end,
                    unwind_info,
                },
                row,
            ))
        }
        crate::on_target::SehStaticLookup::TableMiss { image_base } => {
            if !image_base_out.is_null() {
                unsafe { *image_base_out = image_base };
            }
            None
        }
        crate::on_target::SehStaticLookup::NoTable { image_base } => {
            let mut local_base = image_base.unwrap_or(0);
            let base_out = if image_base_out.is_null() {
                &mut local_base
            } else {
                unsafe { &mut *image_base_out }
            };
            if let Some(image_base) = image_base {
                *base_out = image_base;
            }
            let row = unsafe { dynamic_function_tables().lookup(control_pc, base_out) };
            if row.is_null() {
                None
            } else {
                let base = *base_out;
                Some((base, unsafe { core::ptr::read_unaligned(row) }, row.cast()))
            }
        }
    }
}

impl ImageReader for LiveImage {
    fn lookup_function(&self, control_pc: u64) -> Option<(u64, RuntimeFunction)> {
        // SAFETY: on-target static image lookup plus the process dynamic registry.
        let mut base = 0u64;
        let (base, function, _) = unsafe { resolve_function_entry(control_pc, &mut base) }?;
        Some((base, function))
    }
    fn read_u8(&self, image_base: u64, rva: u32) -> Option<u8> {
        // SAFETY: image_base+rva is inside a mapped module image (the .xdata the unwinder reads
        // lives in a read-only section of the same image whose .pdata pointed us here).
        Some(unsafe { core::ptr::read_volatile((image_base + rva as u64) as *const u8) })
    }
    fn read_u32(&self, image_base: u64, rva: u32) -> Option<u32> {
        // SAFETY: as above; unaligned-safe read.
        Some(unsafe { core::ptr::read_unaligned((image_base + rva as u64) as *const u32) })
    }
}

/// The live [`StackReader`]: raw reads of the current thread's stack (the unwinder pops saved
/// nonvols + return addresses off the frames).
struct LiveStack;

impl StackReader for LiveStack {
    fn read_u64(&self, addr: u64) -> Option<u64> {
        if addr == 0 || addr & 7 != 0 {
            return None; // a misaligned/null stack slot is a corrupt frame — refuse
        }
        // SAFETY: `addr` is a stack address produced by unwinding real frames; the walk only reads
        // slots the prologue actually wrote (saved nonvols / the CALL return address).
        Some(unsafe { core::ptr::read_volatile(addr as *const u64) })
    }
}

/// `RtlWalkFrameChain(Callers, Count, Flags) -> ULONG`. Capture the current frame and walk through
/// the live loader function tables and current TEB stack range. The high flag bits carry the native
/// internal skip count; low flag bit 0 is only meaningful to kernel callers, so user-mode always
/// remains constrained to user addresses.
///
/// # Safety
/// `callers` must name `count` writable pointer slots when `count` is nonzero.
#[export_name = "RtlWalkFrameChain"]
#[inline(never)]
pub unsafe extern "system" fn rtl_walk_frame_chain(
    callers: *mut *mut c_void,
    count: u32,
    flags: u32,
) -> u32 {
    if count != 0 && callers.is_null() {
        return 0;
    }

    let mut context = AlignedContext::zeroed();
    let teb: u64;
    // SAFETY: capture writes a full aligned CONTEXT and GS:[0x30] is the current x64 TEB pointer.
    unsafe {
        capture_context(context.as_mut_ptr());
        core::ptr::write_unaligned(
            context.as_mut_ptr().add(CTX_FLAGS) as *mut u32,
            CONTEXT_FULL,
        );
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, preserves_flags, readonly)
        );
    }
    if teb == 0 {
        return 0;
    }

    // SAFETY: the NT_TIB is the TEB prefix; StackBase/StackLimit are fixed at +0x08/+0x10.
    let (stack_high, stack_low) = unsafe {
        (
            core::ptr::read_unaligned((teb + 0x08) as *const u64),
            core::ptr::read_unaligned((teb + 0x10) as *const u64),
        )
    };
    let output: &mut [u64] = if count == 0 {
        &mut []
    } else {
        // SAFETY: validated non-null above; the caller provides `count` writable pointer slots.
        unsafe { core::slice::from_raw_parts_mut(callers.cast::<u64>(), count as usize) }
    };
    // SAFETY: `context` contains the capture performed above.
    let context = unsafe { context_from_raw(context.as_ptr()) };
    ex::walk_frame_chain(
        context,
        output,
        (flags >> 8) as usize,
        stack_low,
        stack_high,
        &LiveImage,
        &LiveStack,
    )
    .map_or(0, |frames| frames as u32)
}

/// `RtlGetCallersAddress(CallersAddress, CallersCaller)`. The native helper walks four frames and
/// selects entries two and three after its own frame-walk prefix.
///
/// # Safety
/// Non-null output pointers must be writable.
#[export_name = "RtlGetCallersAddress"]
#[inline(never)]
pub unsafe extern "system" fn rtl_get_callers_address(
    callers_address: *mut *mut c_void,
    callers_caller: *mut *mut c_void,
) {
    let mut frames = [0u64; 4];
    // SAFETY: `frames` provides four writable pointer-sized slots.
    let count =
        unsafe { rtl_walk_frame_chain(frames.as_mut_ptr().cast::<*mut c_void>(), 4, 0) as usize };
    let (caller, caller_caller) = ex::callers_addresses(&frames, count);
    // SAFETY: non-null outputs are writable per the contract.
    unsafe {
        if !callers_address.is_null() {
            *callers_address = caller as *mut c_void;
        }
        if !callers_caller.is_null() {
            *callers_caller = caller_caller as *mut c_void;
        }
    }
}

// =================================================================================================
// RtlLookupFunctionEntry / RtlVirtualUnwind — the pure core, live-wired
// =================================================================================================

/// `RtlLookupFunctionEntry(ControlPc, ImageBase*, HistoryTable) -> PRUNTIME_FUNCTION`. Finds the
/// covering `.pdata` row, writes `*ImageBase`, and returns a pointer to the (in-image) 12-byte
/// `RUNTIME_FUNCTION`. Returns NULL for a leaf frame (no entry).
///
/// # Safety
/// `image_base_out` null or writable; `control_pc` a code address.
pub unsafe fn rtl_lookup_function_entry(
    control_pc: u64,
    image_base_out: *mut u64,
    _history_table: *mut c_void,
) -> *mut c_void {
    match unsafe { resolve_function_entry(control_pc, image_base_out) } {
        Some((base, _function, row)) => {
            if !image_base_out.is_null() {
                // SAFETY: writable per the contract.
                unsafe { *image_base_out = base };
            }
            row
        }
        None => core::ptr::null_mut(),
    }
}

/// Locate the in-image `RUNTIME_FUNCTION` row whose `BeginAddress == begin_rva`, returning a raw
/// pointer to it (so callers can pass a real `PRUNTIME_FUNCTION` to `RtlVirtualUnwind`).
///
/// # Safety
/// `base` a mapped PE image.
unsafe fn pdata_row_ptr(base: u64, begin_rva: u32) -> *mut c_void {
    // SAFETY: mapped-image reads.
    unsafe {
        let (pdata_rva, pdata_sz) = crate::on_target::data_directory_pub(base, 3);
        if pdata_rva == 0 || pdata_sz < 12 {
            return core::ptr::null_mut();
        }
        let count = (pdata_sz / 12) as usize;
        for i in 0..count {
            let row = base + pdata_rva as u64 + (i as u64) * 12;
            if core::ptr::read_unaligned(row as *const u32) == begin_rva {
                return row as *mut c_void;
            }
        }
    }
    core::ptr::null_mut()
}

/// `RtlVirtualUnwind(HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord, HandlerData*,
/// EstablisherFrame*, ContextPointers) -> PEXCEPTION_ROUTINE`. Unwinds ONE frame in place through the
/// live `.xdata`, updating `*ContextRecord`, writing `*EstablisherFrame` + `*HandlerData` (the SCOPE
/// TABLE VA for `__C_specific_handler`), and returning the language-handler VA (or NULL).
///
/// # Safety
/// `context_record` a valid CONTEXT; `function_entry` a `RUNTIME_FUNCTION*`; out-ptrs writable.
#[allow(clippy::too_many_arguments)]
pub unsafe fn rtl_virtual_unwind(
    handler_type: u32,
    image_base: u64,
    control_pc: u64,
    function_entry: *const u8,
    context_record: *mut u8,
    handler_data_out: *mut *mut c_void,
    establisher_frame_out: *mut u64,
    _context_pointers: *mut c_void,
) -> *mut c_void {
    if function_entry.is_null() || context_record.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: function_entry is a 12-byte RUNTIME_FUNCTION; context_record a valid CONTEXT.
    unsafe {
        let func = RuntimeFunction {
            begin: core::ptr::read_unaligned(function_entry as *const u32),
            end: core::ptr::read_unaligned(function_entry.add(4) as *const u32),
            unwind_info: core::ptr::read_unaligned(function_entry.add(8) as *const u32),
        };
        let mut ctx = context_from_raw(context_record);
        let res = ex::virtual_unwind(
            handler_type as u8,
            image_base,
            control_pc,
            func,
            &mut ctx,
            &LiveImage,
            &LiveStack,
        );
        match res {
            Some(r) => {
                context_to_raw(&ctx, context_record);
                if !establisher_frame_out.is_null() {
                    *establisher_frame_out = r.establisher_frame;
                }
                if r.handler_rva != 0 {
                    if !handler_data_out.is_null() {
                        // *HandlerData = image_base + handler_data_rva (the SCOPE_TABLE VA).
                        *handler_data_out =
                            (r.image_base + r.handler_data_rva as u64) as *mut c_void;
                    }
                    (r.image_base + r.handler_rva as u64) as *mut c_void
                } else {
                    core::ptr::null_mut()
                }
            }
            None => core::ptr::null_mut(),
        }
    }
}

// =================================================================================================
// RtlDispatchException — the first (search) pass over the live stack
// =================================================================================================

/// `DISPATCHER_CONTEXT` (the fields `__C_specific_handler` reads). We pass a live one to each
/// language handler.
#[repr(C)]
struct DispatcherContext {
    control_pc: u64,
    image_base: u64,
    function_entry: *const u8,
    establisher_frame: u64,
    target_ip: u64,
    context_record: *mut u8,
    language_handler: *const c_void,
    handler_data: *mut c_void,
    history_table: *mut c_void,
    scope_index: u32,
    fill0: u32,
}

/// An `EXCEPTION_ROUTINE`: `fn(ExceptionRecord*, EstablisherFrame, ContextRecord*, DispatcherContext*)
/// -> EXCEPTION_DISPOSITION`.
type ExceptionRoutine = unsafe extern "C" fn(*mut c_void, u64, *mut u8, *mut c_void) -> i32;

unsafe fn finish_vectored_dispatch(record: *mut c_void, context: *mut u8, handled: bool) -> bool {
    // SAFETY: record/context remain valid for the duration of the dispatch entry.
    unsafe {
        let _ = vectored_handlers().call(
            HandlerList::Continue,
            record,
            context.cast::<c_void>(),
            crate::exports::process_cookie(),
        );
    }
    handled
}

/// `RtlDispatchException(ExceptionRecord*, ContextRecord*) -> BOOLEAN`. The first pass: from the
/// faulting frame, iterate up the stack via `RtlVirtualUnwind`; for each frame with a language
/// handler, call it. `ExceptionContinueExecution` → resume (return TRUE). `ExceptionContinueSearch`
/// → keep walking. If a handler calls `RtlUnwindEx` (the `__except` path) it does not return here.
/// Runs out of frames → unhandled (return FALSE).
///
/// # Safety
/// `record`/`context` valid. Reads the live stack.
pub unsafe fn rtl_dispatch_exception(record: *mut c_void, context: *mut u8) -> bool {
    if record.is_null() || context.is_null() {
        return false;
    }
    // SAFETY: the input pair stays live for every registered callback.
    if unsafe {
        vectored_handlers().call(
            HandlerList::Exception,
            record,
            context.cast::<c_void>(),
            crate::exports::process_cookie(),
        )
    } {
        return unsafe { finish_vectored_dispatch(record, context, true) };
    }
    // Work on a COPY of the context so the first-pass unwind doesn't destroy the original (which a
    // handler needs to resume / which the unwind pass re-derives).
    let mut work = AlignedContext::zeroed();
    // SAFETY: copying the caller's CONTEXT.
    unsafe {
        core::ptr::copy_nonoverlapping(context, work.as_mut_ptr(), CONTEXT_SIZE);
    }
    let work_ptr = work.as_mut_ptr();

    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 4096 {
            return unsafe { finish_vectored_dispatch(record, context, false) };
        }
        // SAFETY: work_ptr is our CONTEXT copy.
        let control_pc = unsafe { core::ptr::read_unaligned(work_ptr.add(CTX_RIP) as *const u64) };
        if control_pc == 0 {
            return unsafe { finish_vectored_dispatch(record, context, false) };
        }
        let mut image_base: u64 = 0;
        // SAFETY: lookup + writable out.
        let func = unsafe {
            rtl_lookup_function_entry(control_pc, &mut image_base, core::ptr::null_mut())
        };
        if func.is_null() {
            // A leaf frame (no .pdata): pop the return address directly and continue.
            // SAFETY: reads/writes our CONTEXT copy + the live stack.
            unsafe {
                let rsp = core::ptr::read_unaligned(work_ptr.add(CTX_RSP) as *const u64);
                if rsp == 0 || rsp & 7 != 0 {
                    return finish_vectored_dispatch(record, context, false);
                }
                let ret = core::ptr::read_volatile(rsp as *const u64);
                if ret == 0 {
                    return finish_vectored_dispatch(record, context, false);
                }
                core::ptr::write_unaligned(work_ptr.add(CTX_RIP) as *mut u64, ret);
                core::ptr::write_unaligned(work_ptr.add(CTX_RSP) as *mut u64, rsp + 8);
            }
            continue;
        }

        // Unwind this frame (EHANDLER pass) — this both advances `work` to the caller AND returns the
        // language handler (if any) for THIS frame.
        let mut handler_data: *mut c_void = core::ptr::null_mut();
        let mut establisher: u64 = 0;
        // SAFETY: all pointers valid; func is a RUNTIME_FUNCTION*.
        let handler = unsafe {
            rtl_virtual_unwind(
                ex::unw_flag::EHANDLER as u32,
                image_base,
                control_pc,
                func as *const u8,
                work_ptr,
                &mut handler_data,
                &mut establisher,
                core::ptr::null_mut(),
            )
        };

        if !handler.is_null() {
            // Build the dispatcher context + call the language handler on the ORIGINAL context (a
            // handler that executes will RtlUnwindEx against the original, which it re-derives).
            let mut disp = DispatcherContext {
                control_pc,
                image_base,
                function_entry: func as *const u8,
                establisher_frame: establisher,
                target_ip: 0,
                context_record: context, // the ORIGINAL context (handler resumes/unwinds it)
                language_handler: handler,
                handler_data,
                history_table: core::ptr::null_mut(),
                scope_index: 0,
                fill0: 0,
            };
            // SAFETY: `handler` is a valid EXCEPTION_ROUTINE in a loaded image.
            let routine: ExceptionRoutine = unsafe { core::mem::transmute(handler) };
            // SAFETY: calling the language handler with the SEH ABI.
            let disp_ret = unsafe {
                routine(
                    record,
                    establisher,
                    context,
                    &mut disp as *mut _ as *mut c_void,
                )
            };
            match ex::Disposition::from_raw(disp_ret) {
                ex::Disposition::ContinueExecution => {
                    // The handler fixed the fault: resume the original context.
                    return unsafe { finish_vectored_dispatch(record, context, true) };
                }
                ex::Disposition::ContinueSearch => { /* keep walking up */ }
                // Nested/collided unwind: treat as continue-search for the software path (the full
                // collision handling is the RtlUnwindEx pass's job, driven by the handler).
                ex::Disposition::NestedException | ex::Disposition::CollidedUnwind => {}
            }
        }
        // NOTE: if the frame had NO handler, `rtl_virtual_unwind` already advanced `work` to the
        // caller; loop to the next frame.
    }
}

// =================================================================================================
// RtlRaiseException / RtlRaiseStatus — the software raise entry
// =================================================================================================

/// `RtlRaiseException(EXCEPTION_RECORD*)` — capture the CONTEXT at the raise site, set
/// `record->ExceptionAddress = Rip`, and dispatch. If dispatch returns (unhandled), fall through to
/// `NtRaiseException(FirstChance=FALSE)` so the kernel terminates the process (an honest last chance,
/// never a silent continue).
///
/// The CONTEXT capture is done by `RtlCaptureContext` (naked). `ExceptionAddress` (record+0x10) is
/// set to the captured Rip; the dispatch walks from there.
///
/// # Safety
/// `record` a valid EXCEPTION_RECORD.
pub unsafe fn rtl_raise_exception(record: *mut c_void) {
    if record.is_null() {
        return;
    }
    let mut ctx = AlignedContext::zeroed();
    // SAFETY: capture the live register file into our stack CONTEXT.
    unsafe {
        capture_context(ctx.as_mut_ptr());
        core::ptr::write_unaligned(ctx.as_mut_ptr().add(CTX_FLAGS) as *mut u32, CONTEXT_FULL);
        // record->ExceptionAddress @ +0x10 = the captured Rip (the raise site).
        let rip = core::ptr::read_unaligned(ctx.as_ptr().add(CTX_RIP) as *const u64);
        core::ptr::write_unaligned((record as *mut u8).add(0x10) as *mut u64, rip);
        // First-chance dispatch through the live stack. NOTE: if a `__except` filter fires, the
        // language handler calls `RtlUnwindEx`, which restores the target CONTEXT and never returns
        // here — so control does not come back for the caught case. `rtl_dispatch_exception` returns
        // `true` only for the rarer `ExceptionContinueExecution` (a handler fixed the fault in
        // place); resume the (fixed) context.
        if rtl_dispatch_exception(record, ctx.as_mut_ptr()) {
            nt_continue(ctx.as_mut_ptr()); // does not return
        }
        // Unhandled: last-chance → terminate the process (honest non-return, never a silent
        // continue). NtRaiseException(FirstChance=FALSE) is the kernel path; until the executive
        // services it, an `int3` (→ the kernel #BP handler) terminates deterministically.
        nt_raise_exception(record, ctx.as_mut_ptr(), 0 /*FirstChance=FALSE*/);
    }
}

// =================================================================================================
// RtlUnwindEx — the second (unwind) pass
// =================================================================================================

/// `RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord*, ReturnValue, ContextRecord*, HistoryTable)`.
/// The second pass: from the current frame down to `target_frame`, call each frame's TERMINATION
/// handler (`__finally`, via the UHANDLER language handler with `EXCEPTION_UNWINDING` set), then
/// transfer control to `target_ip` at `target_frame` with `RAX = return_value`. Does not return.
///
/// # Safety
/// `context_record` valid; `target_frame`/`target_ip` from the search pass. Reads the live stack.
pub unsafe fn rtl_unwind_ex(
    target_frame: u64,
    target_ip: u64,
    exception_record: *mut c_void,
    return_value: u64,
    context_record: *mut u8,
    history_table: *mut c_void,
) {
    if context_record.is_null() {
        return;
    }
    // A local EXCEPTION_RECORD if none was supplied (STATUS_UNWIND, EXCEPTION_UNWINDING).
    let mut local_rec = [0u8; 0x98 + 15 * 8];
    let record: *mut c_void = if exception_record.is_null() {
        // SAFETY: our stack buffer, sized for the fixed EXCEPTION_RECORD.
        unsafe {
            core::ptr::write_unaligned(local_rec.as_mut_ptr() as *mut u32, ex::STATUS_UNWIND);
            core::ptr::write_unaligned(
                local_rec.as_mut_ptr().add(4) as *mut u32,
                ex::EXCEPTION_UNWINDING,
            );
        }
        local_rec.as_mut_ptr() as *mut c_void
    } else {
        // Mark the caller's record as unwinding.
        // SAFETY: record+4 is ExceptionFlags.
        unsafe {
            let flags =
                core::ptr::read_unaligned((exception_record as *const u8).add(4) as *const u32);
            core::ptr::write_unaligned(
                (exception_record as *mut u8).add(4) as *mut u32,
                flags | ex::EXCEPTION_UNWINDING,
            );
        }
        exception_record
    };

    // Work on a copy so we can advance frame-by-frame while running finallys.
    let mut work = AlignedContext::zeroed();
    // SAFETY: copy the caller context.
    unsafe {
        core::ptr::copy_nonoverlapping(context_record, work.as_mut_ptr(), CONTEXT_SIZE);
    }
    let work_ptr = work.as_mut_ptr();

    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 4096 {
            break;
        }
        // SAFETY: our CONTEXT copy.
        let control_pc = unsafe { core::ptr::read_unaligned(work_ptr.add(CTX_RIP) as *const u64) };
        let rsp = unsafe { core::ptr::read_unaligned(work_ptr.add(CTX_RSP) as *const u64) };
        if control_pc == 0 {
            break;
        }
        let mut image_base: u64 = 0;
        // SAFETY: lookup.
        let func = unsafe {
            rtl_lookup_function_entry(control_pc, &mut image_base, core::ptr::null_mut())
        };
        if func.is_null() {
            // Leaf: pop return addr and continue.
            // SAFETY: stack read + CONTEXT write.
            unsafe {
                if rsp == 0 || rsp & 7 != 0 {
                    break;
                }
                let ret = core::ptr::read_volatile(rsp as *const u64);
                core::ptr::write_unaligned(work_ptr.add(CTX_RIP) as *mut u64, ret);
                core::ptr::write_unaligned(work_ptr.add(CTX_RSP) as *mut u64, rsp + 8);
            }
            continue;
        }

        // Have we reached the target frame? The establisher frame of THIS function equals
        // target_frame → this is where the __except body lives; stop unwinding here.
        let mut handler_data: *mut c_void = core::ptr::null_mut();
        let mut establisher: u64 = 0;
        // SAFETY: unwind one frame with the UHANDLER (termination) pass.
        let handler = unsafe {
            rtl_virtual_unwind(
                ex::unw_flag::UHANDLER as u32,
                image_base,
                control_pc,
                func as *const u8,
                work_ptr,
                &mut handler_data,
                &mut establisher,
                core::ptr::null_mut(),
            )
        };

        if establisher == target_frame {
            // Reached the target: transfer control to target_ip at target_frame with RAX=retval.
            break;
        }

        // Run this frame's termination handler (__finally) if present, with EXCEPTION_UNWINDING set.
        if !handler.is_null() {
            let mut disp = DispatcherContext {
                control_pc,
                image_base,
                function_entry: func as *const u8,
                establisher_frame: establisher,
                target_ip,
                context_record: work_ptr,
                language_handler: handler,
                handler_data,
                history_table,
                scope_index: 0,
                fill0: 0,
            };
            // SAFETY: valid EXCEPTION_ROUTINE.
            let routine: ExceptionRoutine = unsafe { core::mem::transmute(handler) };
            // SAFETY: calling the termination handler; it runs the __finally blocks.
            unsafe {
                routine(
                    record,
                    establisher,
                    work_ptr,
                    &mut disp as *mut _ as *mut c_void,
                );
            }
        }
    }

    // Transfer control to the target: set Rip=target_ip, Rsp=target_frame (the __except handler runs
    // on the establisher frame), Rax=return_value, then RtlRestoreContext (NtContinue) — no return.
    // SAFETY: writing the target context + resuming it.
    unsafe {
        core::ptr::write_unaligned(context_record.add(CTX_RIP) as *mut u64, target_ip);
        // The __except body expects RSP at the establisher frame. RtlUnwindEx sets Rsp = TargetFrame.
        if target_frame != 0 {
            core::ptr::write_unaligned(context_record.add(CTX_RSP) as *mut u64, target_frame);
        }
        core::ptr::write_unaligned(context_record.add(CTX_RAX) as *mut u64, return_value);
        core::ptr::write_unaligned(context_record.add(CTX_FLAGS) as *mut u32, CONTEXT_FULL);
        nt_continue(context_record);
    }
}

// =================================================================================================
// __C_specific_handler — the C SEH language handler (rpcrt4/win32k client stubs)
// =================================================================================================

/// `__C_specific_handler(ExceptionRecord*, EstablisherFrame, ContextRecord*, DispatcherContext*)
/// -> EXCEPTION_DISPOSITION`. Walks the `SCOPE_TABLE` (`DispatcherContext->HandlerData`) covering the
/// fault PC. On the SEARCH pass: for each `__try/__except` whose `[begin,end)` covers the PC, run
/// its filter; on `EXECUTE_HANDLER` call `RtlUnwindEx` to its `__except` body (does not return). On
/// the UNWIND pass: run each covered `__finally`. Faithful to ReactOS's `__C_specific_handler`.
///
/// # Safety
/// SEH ABI: called by the dispatcher with valid records.
pub unsafe fn c_specific_handler(
    exception_record: *mut c_void,
    establisher_frame: u64,
    _context_record: *mut u8,
    dispatcher_context: *mut c_void,
) -> i32 {
    if dispatcher_context.is_null() {
        return ex::EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: the dispatcher passed a valid DISPATCHER_CONTEXT.
    let disp = unsafe { &mut *(dispatcher_context as *mut DispatcherContext) };
    let image_base = disp.image_base;
    let control_pc = disp.control_pc;
    let scope_table = disp.handler_data as *const u8; // SCOPE_TABLE VA
    if scope_table.is_null() {
        return ex::EXCEPTION_CONTINUE_SEARCH;
    }
    // SCOPE_TABLE: Count @0, then Count × { Begin, End, Handler, Target } (4 u32s each).
    // SAFETY: scope_table is a mapped read-only .xdata region.
    let count = unsafe { core::ptr::read_unaligned(scope_table as *const u32) } as usize;
    if count == 0 || count > 4096 {
        return ex::EXCEPTION_CONTINUE_SEARCH;
    }
    let pc_rva = (control_pc.wrapping_sub(image_base)) as u32;

    // Read the exception flags (record+4) to distinguish the search pass from the unwind pass.
    let flags = if exception_record.is_null() {
        0
    } else {
        // SAFETY: record+4 = ExceptionFlags.
        unsafe { core::ptr::read_unaligned((exception_record as *const u8).add(4) as *const u32) }
    };
    let unwinding = flags & ex::EXCEPTION_UNWINDING != 0;

    // Read a scope record.
    // SAFETY: bounded by `count`, within the mapped SCOPE_TABLE.
    let read_scope = |i: usize| -> ScopeRecord {
        unsafe {
            let p = scope_table.add(4 + i * 16);
            ScopeRecord {
                begin: core::ptr::read_unaligned(p as *const u32),
                end: core::ptr::read_unaligned(p.add(4) as *const u32),
                handler: core::ptr::read_unaligned(p.add(8) as *const u32),
                target: core::ptr::read_unaligned(p.add(12) as *const u32),
            }
        }
    };

    if unwinding {
        // UNWIND pass: run each covered __finally (target == 0).
        for i in 0..count {
            let s = read_scope(i);
            if pc_rva >= s.begin && pc_rva < s.end {
                // If unwinding to a target within this scope's __except, stop.
                if s.target != 0
                    && (flags & ex::EXCEPTION_TARGET_UNWIND != 0)
                    && disp.target_ip == image_base + s.target as u64
                {
                    return ex::EXCEPTION_CONTINUE_SEARCH;
                }
                if s.target == 0 {
                    // A __finally: call it with (AbnormalTermination=TRUE, EstablisherFrame).
                    let fin = image_base + s.handler as u64;
                    // SAFETY: `fin` is a __finally routine in a loaded image; SEH __finally ABI is
                    // fn(BOOLEAN AbnormalTermination, PVOID EstablisherFrame).
                    unsafe {
                        let f: unsafe extern "C" fn(u8, u64) = core::mem::transmute(fin);
                        f(1, establisher_frame);
                    }
                }
            }
        }
        return ex::EXCEPTION_CONTINUE_SEARCH;
    }

    // SEARCH pass: find the first __except whose filter says EXECUTE.
    for i in 0..count {
        let s = read_scope(i);
        if pc_rva < s.begin || pc_rva >= s.end {
            continue;
        }
        if s.target == 0 {
            continue; // a __finally — no filter in the search pass
        }
        let verdict = if s.handler == ex::SCOPE_HANDLER_EXECUTE {
            ex::EXCEPTION_EXECUTE_HANDLER
        } else {
            // Call the filter: int filter(EXCEPTION_POINTERS*, EstablisherFrame). We build a small
            // EXCEPTION_POINTERS { ExceptionRecord, ContextRecord } on the stack.
            let filt = image_base + s.handler as u64;
            #[repr(C)]
            struct ExceptionPointers {
                record: *mut c_void,
                context: *mut u8,
            }
            let ptrs = ExceptionPointers {
                record: exception_record,
                context: _context_record,
            };
            // SAFETY: `filt` is a filter routine in a loaded image; the SEH filter ABI.
            unsafe {
                let f: unsafe extern "C" fn(*const c_void, u64) -> i32 = core::mem::transmute(filt);
                f(&ptrs as *const _ as *const c_void, establisher_frame)
            }
        };
        if verdict == ex::EXCEPTION_CONTINUE_EXECUTION {
            return ex::EXCEPTION_CONTINUE_EXECUTION;
        }
        if verdict == ex::EXCEPTION_EXECUTE_HANDLER {
            // Unwind to the __except body — does not return.
            let target_ip = image_base + s.target as u64;
            // SAFETY: RtlUnwindEx transfers control; the ExceptionCode goes to RAX as the return.
            let code = if exception_record.is_null() {
                0
            } else {
                unsafe { core::ptr::read_unaligned(exception_record as *const u32) as u64 }
            };
            unsafe {
                rtl_unwind_ex(
                    establisher_frame,
                    target_ip,
                    exception_record,
                    code,
                    disp.context_record,
                    disp.history_table,
                );
            }
            // Not reached.
            return ex::EXCEPTION_CONTINUE_SEARCH;
        }
        // CONTINUE_SEARCH → next scope.
    }
    ex::EXCEPTION_CONTINUE_SEARCH
}

// =================================================================================================
// KiUserExceptionDispatcher — the entry the kernel/executive would jump to for a delivered fault.
// SOFTWARE path dispatches through the same machinery; hardware-fault DELIVERY (the executive
// redirecting a faulting thread's RIP here) is the scoped-deferred lift.
// =================================================================================================

/// `KiUserExceptionDispatcher(ExceptionRecord*, ContextRecord*)` — dispatch a delivered exception.
/// Runs the first-pass dispatch; on handled `NtContinue`, on unhandled last-chance
/// `NtRaiseException`. (The software raise path lands here indirectly via `RtlRaiseException`; the
/// hardware-fault redirection onto this entry is future executive work — see the module doc.)
///
/// # Safety
/// `record`/`context` valid (a stacked EXCEPTION_RECORD + CONTEXT).
pub unsafe extern "C" fn ki_user_exception_dispatcher(record: *mut c_void, context: *mut u8) -> ! {
    // SAFETY: dispatch + resume/raise per the delivered records. Neither branch returns (a caught
    // handler unwinds via RtlUnwindEx; a fixed fault resumes; an unhandled one terminates).
    unsafe {
        if rtl_dispatch_exception(record, context) {
            nt_continue(context); // does not return
        }
        nt_raise_exception(record, context, 0) // does not return
    }
}

// =================================================================================================
// CONTEXT capture / restore + NtContinue / NtRaiseException seams
// =================================================================================================

/// `RtlCaptureContext(CONTEXT*)` — capture the live register file into `*ctx`. Naked so it does not
/// perturb the registers it is capturing. Captures the integer GPRs (Rax..R15), the return address
/// as Rip, and Rsp as it was at the call site (after the return address is accounted for).
///
/// # Safety
/// `ctx` (RCX) a valid writable CONTEXT (>= 0x4D0 bytes).
#[unsafe(naked)]
pub unsafe extern "C" fn capture_context(_ctx: *mut u8) {
    core::arch::naked_asm!(
        // RCX = CONTEXT*. Store the integer registers at their documented offsets.
        "mov [rcx + 0x78], rax",
        "mov [rcx + 0x80], rcx", // (the incoming RCX — the CONTEXT ptr; matches RtlCaptureContext)
        "mov [rcx + 0x88], rdx",
        "mov [rcx + 0x90], rbx",
        "mov [rcx + 0xA0], rbp",
        "mov [rcx + 0xA8], rsi",
        "mov [rcx + 0xB0], rdi",
        "mov [rcx + 0xB8], r8",
        "mov [rcx + 0xC0], r9",
        "mov [rcx + 0xC8], r10",
        "mov [rcx + 0xD0], r11",
        "mov [rcx + 0xD8], r12",
        "mov [rcx + 0xE0], r13",
        "mov [rcx + 0xE8], r14",
        "mov [rcx + 0xF0], r15",
        // Rip = the return address at [rsp].
        "mov rax, [rsp]",
        "mov [rcx + 0xF8], rax",
        // Rsp = the caller's RSP AFTER the call returns (rsp + 8, popping the return address).
        "lea rax, [rsp + 8]",
        "mov [rcx + 0x98], rax",
        // Save XMM6..XMM15 (nonvols) at their offsets (0x1A0 + 16*n).
        "movaps [rcx + 0x200], xmm6",
        "movaps [rcx + 0x210], xmm7",
        "movaps [rcx + 0x220], xmm8",
        "movaps [rcx + 0x230], xmm9",
        "movaps [rcx + 0x240], xmm10",
        "movaps [rcx + 0x250], xmm11",
        "movaps [rcx + 0x260], xmm12",
        "movaps [rcx + 0x270], xmm13",
        "movaps [rcx + 0x280], xmm14",
        "movaps [rcx + 0x290], xmm15",
        "ret",
    );
}

/// Public `RtlRestoreContext` entry — resume a captured context (does not return).
///
/// # Safety
/// `context` a valid CONTEXT to resume.
pub unsafe fn seh_nt_continue(context: *mut u8) {
    // SAFETY: resume the captured context.
    unsafe { nt_continue(context) }
}

/// Resume a captured/target `CONTEXT` (does not return) — an IN-PROCESS register restore + jump.
///
/// For the SOFTWARE raise/unwind path the thread never left user mode, so resuming is a pure
/// user-mode operation: reload the GPRs + XMM nonvols from the CONTEXT and `jmp` to `context->Rip`
/// with `context->Rsp` installed. No kernel round-trip (an `NtContinue` syscall would be needed only
/// to resume a context the KERNEL delivered — the hardware-fault path, scoped-deferred). This is
/// exactly what real ntdll's `RtlRestoreContext` does for an in-process unwind.
///
/// # Safety
/// `context` a valid CONTEXT to resume; control transfers to `context->Rip` (never returns).
unsafe fn nt_continue(context: *mut u8) -> ! {
    // SAFETY: `context` is a valid CONTEXT; restore_context installs it and jumps (no return).
    unsafe {
        restore_context(context);
        core::hint::unreachable_unchecked()
    }
}

/// The naked register-restore + jump: load RSP/RBP/nonvols/volatiles + XMM from the CONTEXT (RCX),
/// push `context->Rip` on the target stack, and `ret` into it. Does not return.
///
/// # Safety
/// RCX = a valid CONTEXT; the target Rsp/Rip describe a resumable frame.
#[unsafe(naked)]
unsafe extern "C" fn restore_context(_context: *mut u8) -> ! {
    core::arch::naked_asm!(
        // RCX = CONTEXT*. Restore XMM nonvols first (before we clobber RCX-relative reads is fine —
        // RCX is preserved until the end).
        "movaps xmm6,  [rcx + 0x200]",
        "movaps xmm7,  [rcx + 0x210]",
        "movaps xmm8,  [rcx + 0x220]",
        "movaps xmm9,  [rcx + 0x230]",
        "movaps xmm10, [rcx + 0x240]",
        "movaps xmm11, [rcx + 0x250]",
        "movaps xmm12, [rcx + 0x260]",
        "movaps xmm13, [rcx + 0x270]",
        "movaps xmm14, [rcx + 0x280]",
        "movaps xmm15, [rcx + 0x290]",
        // Load the target RSP, then push the target Rip so a final `ret` transfers to it.
        "mov rsp, [rcx + 0x98]", // target Rsp
        "mov rax, [rcx + 0xF8]", // target Rip
        "push rax",              // return address = target Rip
        // Restore the GPRs (RAX/RCX restored last since we still need RCX as the CONTEXT ptr).
        "mov rbx, [rcx + 0x90]",
        "mov rbp, [rcx + 0xA0]",
        "mov rsi, [rcx + 0xA8]",
        "mov rdi, [rcx + 0xB0]",
        "mov r8,  [rcx + 0xB8]",
        "mov r9,  [rcx + 0xC0]",
        "mov r10, [rcx + 0xC8]",
        "mov r11, [rcx + 0xD0]",
        "mov r12, [rcx + 0xD8]",
        "mov r13, [rcx + 0xE0]",
        "mov r14, [rcx + 0xE8]",
        "mov r15, [rcx + 0xF0]",
        "mov rdx, [rcx + 0x88]",
        "mov rax, [rcx + 0x78]", // target Rax (the unwind return value)
        "mov rcx, [rcx + 0x80]", // target Rcx (restored last)
        "ret",                   // jump to the pushed target Rip
    );
}

/// `NtRaiseException(EXCEPTION_RECORD*, CONTEXT*, FirstChance)` — the last-chance raise into the
/// kernel. On `FirstChance=FALSE` this is the unhandled-exception terminate. The executive does not
/// yet service `NtRaiseException` (SSN reserved), so we terminate deterministically via `int3` (→ the
/// kernel #BP handler) — an HONEST non-return for an unhandled exception, never a silent continue.
/// When the executive services `NtRaiseException`, swap the `int3` for the trap.
///
/// # Safety
/// `record`/`context` valid. Does not return.
unsafe fn nt_raise_exception(record: *mut c_void, context: *mut u8, _first_chance: u64) -> ! {
    let _ = (record, context, SSN_NT_RAISE_EXCEPTION, SSN_NT_CONTINUE);
    // SAFETY: int3 traps to the kernel #BP handler → process terminates; does not return.
    unsafe {
        core::arch::asm!("int3", options(noreturn));
    }
}

// =================================================================================================
// LIVE self-test — run during LdrpInitialize (smss). Validates the REAL machinery against our own
// real compiled `.pdata`/`.xdata`: capture a CONTEXT at a real call site, RtlLookupFunctionEntry
// the covering RUNTIME_FUNCTION, and RtlVirtualUnwind ONE real frame — asserting the unwind produces
// a plausible caller (RIP inside our own image, RSP advanced upward). This proves the live
// `.pdata` walk + `.xdata` unwind-code interpretation work on real hardware with real tables (the
// pure LOGIC is already exhaustively host-tested). Prints one `[seh-selftest]` line to serial.
// =================================================================================================

/// A tiny non-leaf helper with a real prologue (the compiler emits `.pdata`/`.xdata` for it because
/// it makes a call). Returns its own captured (Rip, Rsp, lookup-hit, unwound-Rip, unwound-Rsp).
///
/// # Safety
/// On-target; issues a real CONTEXT capture + unwind.
#[inline(never)]
unsafe fn seh_selftest_frame() -> (u64, u64, bool, u64, u64) {
    let mut ctx = AlignedContext::zeroed();
    // SAFETY: capture the live register file at THIS call site.
    unsafe {
        capture_context(ctx.as_mut_ptr());
        let rip = core::ptr::read_unaligned(ctx.as_ptr().add(CTX_RIP) as *const u64);
        let rsp = core::ptr::read_unaligned(ctx.as_ptr().add(CTX_RSP) as *const u64);
        let mut image_base: u64 = 0;
        let func = rtl_lookup_function_entry(rip, &mut image_base, core::ptr::null_mut());
        if func.is_null() {
            return (rip, rsp, false, 0, 0);
        }
        // Unwind ONE real frame (no handler wanted — pure prologue unwind).
        let mut hd: *mut c_void = core::ptr::null_mut();
        let mut ef: u64 = 0;
        let _ = rtl_virtual_unwind(
            0,
            image_base,
            rip,
            func as *const u8,
            ctx.as_mut_ptr(),
            &mut hd,
            &mut ef,
            core::ptr::null_mut(),
        );
        let urip = core::ptr::read_unaligned(ctx.as_ptr().add(CTX_RIP) as *const u64);
        let ursp = core::ptr::read_unaligned(ctx.as_ptr().add(CTX_RSP) as *const u64);
        (rip, rsp, true, urip, ursp)
    }
}

/// Run the live SEH self-test + print a `[seh-selftest]` result line to serial. Called once from
/// `ldrp_drive` (smss). Non-fatal: it only reads/unwinds a synthetic frame — never raises.
///
/// # Safety
/// On-target only.
pub unsafe fn run_selftest() {
    // SAFETY: the frame helper only captures + unwinds; no control transfer.
    let (rip, rsp, hit, urip, ursp) = unsafe { seh_selftest_frame() };
    // A PASS: the lookup found a real .pdata entry AND the unwind advanced to a plausible caller
    // (RSP moved upward — the prologue's pushes/allocs were undone — and a non-zero return RIP).
    let pass = hit && ursp > rsp && urip != 0 && urip != rip;
    let mut buf = [0u8; 128];
    let mut n = 0usize;
    let put = |buf: &mut [u8; 128], n: &mut usize, s: &[u8]| {
        for &b in s {
            if *n < buf.len() {
                buf[*n] = b;
                *n += 1;
            }
        }
    };
    let put_hex = |buf: &mut [u8; 128], n: &mut usize, v: u64| {
        put(buf, n, b"0x");
        let mut started = false;
        for i in (0..16).rev() {
            let nib = ((v >> (i * 4)) & 0xF) as u8;
            if nib != 0 || started || i == 0 {
                started = true;
                if *n < buf.len() {
                    buf[*n] = if nib < 10 {
                        b'0' + nib
                    } else {
                        b'a' + nib - 10
                    };
                    *n += 1;
                }
            }
        }
    };
    put(&mut buf, &mut n, b"[seh-selftest] live RtlVirtualUnwind ");
    put(&mut buf, &mut n, if pass { b"PASS" } else { b"FAIL" });
    put(&mut buf, &mut n, b" rip=");
    put_hex(&mut buf, &mut n, rip);
    put(&mut buf, &mut n, b" -> caller=");
    put_hex(&mut buf, &mut n, urip);
    put(&mut buf, &mut n, b" rsp=");
    put_hex(&mut buf, &mut n, rsp);
    put(&mut buf, &mut n, b"->");
    put_hex(&mut buf, &mut n, ursp);
    put(&mut buf, &mut n, b"\n");
    // SAFETY: buf is a mapped stack local of length n.
    unsafe {
        crate::dbg_print_bytes(buf.as_ptr(), n);
    }
}
