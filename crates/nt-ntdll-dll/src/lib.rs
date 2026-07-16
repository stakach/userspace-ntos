//! # `nt-ntdll-dll` — the PE32+ DLL wrapper (Step 4.0)
//!
//! This crate exists ONLY to EMIT our Rust ntdll as a loadable `ntdll.dll`. It is a thin `cdylib`
//! around the host-tested [`nt_ntdll`] rlib — all the real logic (the 188 `Nt*` trap stubs, the
//! `Rtl*`/`Csr*`/`Dbg*`/`Ki*` surface, the loader engine) lives there and stays under `cargo test`.
//!
//! Its job here is three things the rlib can't do on its own:
//! 1. **Force-retain the exports.** The 188 naked `Nt*` trap stubs (defined in
//!    [`nt_ntdll::trap_stubs`], exported under their real Windows names via `#[export_name]`) are
//!    unreferenced by anything else, so linker dead-code elimination would drop them. We anchor them
//!    with [`nt_ntdll::trap_stubs::TRAP_STUB_ADDRS`] (a `#[used]` fn-ptr array in the rlib) —
//!    referencing it here keeps the whole set in the DLL export directory.
//! 2. **Export `LdrpInitialize`** at a findable RVA — the entry the executive's spawn trampoline
//!    hands control to (Step 4.B). The body is the real orchestration seam; Step 4.B fleshes out the
//!    live `LoaderHost` on-target. For Step 4.0 it just has to EXIST in the export table.
//! 3. **Provide the no_std runtime bits** a `cdylib` needs with no CRT: a `#[panic_handler]` and
//!    `DllMain` (so there is no CRT `_DllMainCRTStartup` dependency).
//!
//! Built for `x86_64-pc-windows-gnullvm` (LLVM/lld, no mingw). Verified with `llvm-objdump`. NOT
//! wired into the boot — that is Step 4.A+.

#![no_std]
#![allow(internal_features)]
// `memcpy`/`memset` are exported weak (compiler-builtins-mem also emits them) — needs `linkage`.
#![feature(linkage)]

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

/// Step 4.0b — the `Rtl*` / `Ldr*` / `Dbg*` / CRT PE exports smss.exe imports (completes the export
/// table so smss's FULL ntdll import set resolves against our DLL). See [`exports`].
pub mod exports;

/// A placeholder global allocator. The [`nt_ntdll`] rlib links `alloc`, so a `cdylib` around it
/// needs a `#[global_allocator]` to satisfy the linker. At Step 4.0 the DLL runs no allocating code
/// (the exports are trap stubs + a placeholder `LdrpInitialize`), so this allocator is never called
/// on a live path — it is a link-time requirement. Step 4.B replaces it with the real
/// `RtlAllocateHeap`-backed allocator (the process heap from [`nt_ntdll::heap`]). It aborts if ever
/// actually invoked so a stray allocation can't silently corrupt memory.
struct AbortAllocator;

// SAFETY: every method aborts rather than returning a bogus pointer; there is no live allocation at
// Step 4.0, so no valid allocation contract needs to be upheld yet.
unsafe impl GlobalAlloc for AbortAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        // No heap at Step 4.0. Return null → the caller's alloc-error path (which also aborts).
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: AbortAllocator = AbortAllocator;

/// Anchor the 188 `Nt*` trap stubs so the linker retains them into the DLL export directory.
///
/// `TRAP_STUB_ADDRS` is `#[used]` in the rlib, but a `#[used]` static in a *dependency* rlib is only
/// kept if the dependency itself is pulled in. Taking its address here from the cdylib's root object
/// guarantees the linker walks it (and therefore every stub it points at). Marked `#[used]` again so
/// this reference itself is never optimized away.
#[used]
static KEEP_TRAP_STUBS: &[unsafe extern "C" fn()] = nt_ntdll::trap_stubs::TRAP_STUB_ADDRS;

/// Anchor the Step-4.0b `Rtl*`/`Ldr*`/`Dbg*`/CRT exports (defined in [`exports`]) so the linker
/// retains them into the DLL export directory. Analogous to [`KEEP_TRAP_STUBS`]: it references
/// [`exports::EXPORT_ANCHOR_FN`] (a `#[used]` anchor fn that in turn address-of's all 61 exports),
/// so the whole graph survives DCE. Without this the non-`Nt*` exports (which nothing else in the
/// cdylib references) would be dropped.
#[used]
static KEEP_EXPORTS: unsafe extern "C" fn() = exports::EXPORT_ANCHOR_FN;

/// The Step-4.A observable marker bytes, emitted via the `int 0x2d` DebugService (`PRINT`) the
/// kernel forwards to serial as `[dbg] ...` (see `project_smss_sec_image` +
/// `rust-micro/src/arch/x86_64/exceptions.rs`). Seeing this line in the boot log PROVES our Rust
/// ntdll executed IN smss's isolated VSpace and a trap reached the kernel.
///
/// ★ These are `u8` LITERALS built onto the STACK at runtime (NOT a `.rdata` static): the kernel's
/// int-0x2d PRINT handler READS the message buffer (`rcx`) DIRECTLY from kernel mode, so it must sit
/// on a page already mapped in smss's VSpace. Our LdrpInitialize's `.text` page is demand-faulted in
/// (that is how we got here), but a fresh `.rdata` page would NOT be mapped yet → the kernel read
/// would #PF in kernel mode. The stack IS fully mapped at spawn, so a stack buffer is safe.
const STEP4A_MARKER_LEN: usize = 60;

/// `LdrpInitialize` — the loader entry the executive's spawn trampoline transfers to.
///
/// Real-ntdll ABI (x64): `VOID LdrpInitialize(PCONTEXT Context, PVOID NtDllBase)`. The full live
/// orchestration ([`nt_ntdll::loader::ldrp_initialize`]) needs an on-target `LoaderHost` (the live
/// map/IAT/PEB-commit/transfer ops) which Step 4.B wires.
///
/// **Step 4.A — first live control + an observable syscall.** As its FIRST action this emits the
/// Step-4.A marker via the `int 0x2d` DebugService (`ServiceClass = PRINT`), which our kernel
/// forwards to the serial log. That single line is the Step-4.A proof: OUR Rust ran in smss's own
/// VSpace and issued a trap the kernel serviced. After the marker it returns to the trampoline (the
/// live `LoaderHost` map/IAT/PEB/transfer drive is Step 4.B) — it does NOT fabricate a completed
/// init; the process will not reach smss's entry until 4.B wires the real loader.
///
/// # Safety
/// Called by the kernel/trampoline with the loader `CONTEXT`. Emits an `int 0x2d` (target x86_64
/// only) then returns; no live-init side effects until Step 4.B.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn LdrpInitialize(_context: *mut c_void, _ntdll_base: *mut c_void) {
    // Step 4.A observable marker: prove OUR code runs in-process + a trap reaches the kernel.
    // The kernel's int-0x2d handler forwards RCX(msg)/RDX(len) with EAX=1 (PRINT) to serial and,
    // on resume, advances RIP past `int 0x2d; int3` (3 bytes) — so we pair them exactly.
    #[cfg(target_arch = "x86_64")]
    {
        // Build the marker on the STACK (mapped at spawn) — see STEP4A_MARKER_LEN doc for why not
        // a .rdata static. "nt-ntdll: our Rust LdrpInitialize running in smss (Step 4.A)\0" (60 B).
        let marker: [u8; STEP4A_MARKER_LEN] = *b"nt-ntdll: our Rust LdrpInitialize running in smss (Step 4.A)";
        let msg = marker.as_ptr();
        core::arch::asm!(
            "int 0x2d",
            "int3",
            in("eax") 1u32, // BREAKPOINT_PRINT
            in("rcx") msg,
            in("rdx") STEP4A_MARKER_LEN,
            options(nostack, preserves_flags),
        );
        // Keep the stack buffer live across the asm (it is read by the kernel handler above).
        core::hint::black_box(&marker);
    }
    // Step 4.B replaces the rest with the live-host drive of `nt_ntdll::loader::ldrp_initialize`.
    core::hint::black_box(_context);
    core::hint::black_box(_ntdll_base);
}

/// `DllMainCRTStartup` — the DLL entry point the PE loader calls. Normally the CRT supplies this
/// (it runs static initializers then calls `DllMain`); with no CRT we provide it ourselves. It just
/// forwards to [`DllMain`]. This is the PE's `AddressOfEntryPoint`.
///
/// # Safety
/// Called by the PE loader with the standard DLL-entry arguments.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMainCRTStartup(
    module: *mut c_void,
    reason: u32,
    reserved: *mut c_void,
) -> i32 {
    // SAFETY: forwarding the loader-supplied arguments to our own no-op DllMain.
    unsafe { DllMain(module, reason, reserved) }
}

/// `DllMain` — present so the linker does not pull in the CRT's `_DllMainCRTStartup`. Returns TRUE.
///
/// # Safety
/// The standard `DllMain` contract; a no-op that reports success.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _module: *mut c_void,
    _reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    1 // TRUE
}

// ---------------------------------------------------------------------------------------------
// C-runtime intrinsics normally supplied by mingw's msvcrt. We drop the mingw import libs (no CRT),
// so `compiler_builtins` provides `mem*` (via the `compiler-builtins-mem` build-std feature), and we
// supply the `fma`/`fmaf` fused-multiply-add symbols that `libm`'s float traits reference. They are
// NOT on any live ntdll path here (Step 4.0 exports are trap stubs + a placeholder LdrpInitialize);
// these are honest fallbacks so the DLL links, computing the un-fused result.
/// `fma` — fused multiply-add fallback (unfused). Linker-required; not on a live path at Step 4.0.
///
/// # Safety
/// A pure math fallback with no memory effects.
#[unsafe(no_mangle)]
pub extern "C" fn fma(x: f64, y: f64, z: f64) -> f64 {
    x * y + z
}

/// `fmaf` — 32-bit fused multiply-add fallback (unfused). Linker-required; not on a live path.
///
/// # Safety
/// A pure math fallback with no memory effects.
#[unsafe(no_mangle)]
pub extern "C" fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    x * y + z
}

/// no_std panic handler (abort). ntdll must never unwind through a `panic!`.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
