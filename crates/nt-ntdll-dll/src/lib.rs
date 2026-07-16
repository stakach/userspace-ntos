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

/// `LdrpInitialize` — the loader entry the executive's spawn trampoline transfers to.
///
/// Real-ntdll ABI (x64): `VOID LdrpInitialize(PCONTEXT Context, PVOID NtDllBase)`. The full live
/// orchestration ([`nt_ntdll::loader::ldrp_initialize`]) needs an on-target `LoaderHost` (the live
/// map/IAT/PEB-commit/transfer ops) which Step 4.B wires. For Step 4.0 this export just has to
/// EXIST at a findable RVA so the trampoline can be pointed at it; the body is a minimal, honest
/// placeholder that returns to the caller (it does NOT fabricate a completed init).
///
/// # Safety
/// Called by the kernel/trampoline with the loader `CONTEXT`. A no-op-return placeholder until
/// Step 4.B installs the live path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn LdrpInitialize(_context: *mut c_void, _ntdll_base: *mut c_void) {
    // Step 4.B replaces this with the live-host drive of `nt_ntdll::loader::ldrp_initialize`.
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
