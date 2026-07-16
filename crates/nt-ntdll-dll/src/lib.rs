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

use nt_ntdll::heap::Heap;

/// Step 4.0b — the `Rtl*` / `Ldr*` / `Dbg*` / CRT PE exports smss.exe imports (completes the export
/// table so smss's FULL ntdll import set resolves against our DLL). See [`exports`].
pub mod exports;

/// Step 4.B — the on-target IN-PROCESS loader drive (real heap + import snap). See [`on_target`].
#[cfg(target_arch = "x86_64")]
pub mod on_target;

/// The process heap backing type installed at Step 4.B (a real `NtAllocateVirtualMemory` region).
#[cfg(target_arch = "x86_64")]
type ProcessHeap = Heap<on_target::HeapBacking>;

/// The **real process heap** installed in-process by [`LdrpInitialize`] (Step 4.B). Single-threaded
/// during load (smss is one thread until it spawns), so a `static mut` accessed only from the loader
/// thread is sound. `None` until `LdrpInitialize` creates it; a global-alloc call before then falls
/// back to a null (allocation-failure) return — the honest behavior (never a bogus pointer).
///
/// NOTE: the heap type is target-gated (`HeapBacking` is target-only), so this cell only exists on
/// x86_64; on the host build the allocator is a no-op abort cell (there is no live allocation off
/// target anyway).
#[cfg(target_arch = "x86_64")]
static mut PROCESS_HEAP: Option<ProcessHeap> = None;

/// Install the process heap (called once by [`LdrpInitialize`] after `NtAllocateVirtualMemory`).
///
/// # Safety
/// Called once, single-threaded, during process load before any concurrent allocation.
#[cfg(target_arch = "x86_64")]
pub(crate) fn install_process_heap(heap: ProcessHeap) {
    // SAFETY: single-threaded loader context; installed exactly once before concurrent use.
    unsafe {
        core::ptr::addr_of_mut!(PROCESS_HEAP).write(Some(heap));
    }
}

/// `RtlAllocateHeap` core — allocate `size` payload bytes from the installed process heap. The
/// `HeapHandle` the caller passes (`Peb->ProcessHeap`) is ignored: during the smss bring-up the
/// process has exactly one heap (ours), so routing every `RtlAllocateHeap` to it is correct. Returns
/// null on OOM / before the heap is installed (an honest allocation failure — never a bogus pointer).
///
/// # Safety
/// Single-threaded loader context (smss is one thread until it spawns csrss).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn process_heap_alloc(size: usize) -> *mut u8 {
    // SAFETY: single-threaded loader access to the installed heap.
    unsafe {
        if let Some(h) = (*core::ptr::addr_of_mut!(PROCESS_HEAP)).as_mut() {
            return h.allocate(size).unwrap_or(core::ptr::null_mut());
        }
    }
    core::ptr::null_mut()
}

/// `RtlFreeHeap` core — free `ptr` (returned by [`process_heap_alloc`]) back to the process heap.
/// Returns `true` if the block was freed. A null `ptr` or a not-live pointer returns `false`.
///
/// # Safety
/// `ptr` must have come from [`process_heap_alloc`]/[`process_heap_realloc`] (the real `RtlFreeHeap`
/// trusts the caller's pointer identically). Single-threaded loader context.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn process_heap_free(ptr: *mut u8) -> bool {
    // SAFETY: single-threaded loader access; ptr came from this heap per the contract.
    unsafe {
        if let Some(h) = (*core::ptr::addr_of_mut!(PROCESS_HEAP)).as_mut() {
            return h.free(ptr);
        }
    }
    false
}


/// The process-heap global allocator. Once [`LdrpInitialize`] installs the real heap, `alloc`/
/// `dealloc` route through it; before that (or if it OOMs) `alloc` returns null (honest failure, the
/// caller's alloc-error path handles it) rather than a fabricated pointer.
struct ProcessHeapAllocator;

// SAFETY: on-target, `alloc` returns either a valid pointer from the installed first-fit heap or
// null; `dealloc` frees a pointer the same heap handed out. Off-target it is a pure null-returning
// stub (no live allocation exists there). No fabricated pointers.
unsafe impl GlobalAlloc for ProcessHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: single-threaded loader access to the installed heap.
            unsafe {
                if let Some(h) = (*core::ptr::addr_of_mut!(PROCESS_HEAP)).as_mut() {
                    // The heap guarantees 16-byte alignment; larger alignments over-allocate to fit.
                    let want = layout.size().max(1) + layout.align().saturating_sub(1);
                    return h.allocate(want).unwrap_or(core::ptr::null_mut());
                }
            }
            core::ptr::null_mut()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = layout;
            core::ptr::null_mut()
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: single-threaded loader access; ptr came from this heap.
            unsafe {
                if let Some(h) = (*core::ptr::addr_of_mut!(PROCESS_HEAP)).as_mut() {
                    let _ = h.free(ptr);
                }
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = ptr;
        }
    }
}

#[global_allocator]
static ALLOCATOR: ProcessHeapAllocator = ProcessHeapAllocator;

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
/// Emit a NUL-free byte marker to the serial log via the `int 0x2d` DebugService (`PRINT`) the
/// kernel forwards (see `project_smss_sec_image`). The buffer MUST live on the STACK (an
/// already-mapped page): the kernel's PRINT handler reads `rcx` DIRECTLY from kernel mode, so a
/// not-yet-faulted `.rdata` page would #PF in the kernel. Pairs `int 0x2d; int3` (the kernel advances
/// RIP by 3 on resume).
///
/// # Safety
/// `msg`/`len` must describe a mapped, readable buffer (a stack local at the call site).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn dbg_print_bytes(msg: *const u8, len: usize) {
    // SAFETY: msg/len describe a mapped stack buffer per the contract.
    unsafe {
        core::arch::asm!(
            "int 0x2d",
            "int3",
            in("eax") 1u32, // BREAKPOINT_PRINT
            in("rcx") msg,
            in("rdx") len,
            options(nostack, preserves_flags),
        );
    }
}

/// `LdrpInitialize` — the loader entry the executive's spawn trampoline transfers to.
///
/// Real-ntdll ABI (x64): `VOID LdrpInitialize(PCONTEXT Context, PVOID NtDllBase)`. Our Step-4.B
/// trampoline additionally passes **smss's image base in `R8`** (the C-ABI 3rd arg `smss_base`) —
/// the real ntdll ignores SystemArgument2, but our in-process loader needs it to snap smss's imports
/// against OUR export table (see [`on_target`]).
///
/// **Step 4.B — the live in-process loader drive.** Runs IN smss's VSpace (Step 4.A proved control
/// reaches here + a trap is serviced). It:
/// 1. emits a diagnostic marker (the 4.A proof line, kept),
/// 2. creates the **process heap** (`NtAllocateVirtualMemory` → serviced) + installs the global
///    allocator, then
/// 3. **snaps smss's ntdll imports in-process** against OUR export directory — writing our export
///    addresses directly into smss's IAT slots (fixing the 4.A IAT-RVA mismatch).
/// 4. emits a second marker reporting the snap result, then returns to the trampoline, which chains
///    to smss's real entry (`NtProcessStartup`) — now running under OUR ntdll.
///
/// It never fabricates a completed init; each step is real (heap committed, IAT written) or an
/// honest no-op (a missing base → skip, logged).
///
/// # Safety
/// Called by the kernel/trampoline with `(Context, NtDllBase, smss_base)`. Issues syscall traps +
/// in-process image reads/writes (target x86_64 only).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn LdrpInitialize(
    _context: *mut c_void,
    ntdll_base: *mut c_void,
    smss_base: *mut c_void,
) {
    #[cfg(target_arch = "x86_64")]
    {
        // (1) The Step-4.A proof line (kept as a diagnostic; stack buffer — see dbg_print_bytes).
        let marker: [u8; 53] = *b"nt-ntdll: Step 4.B in-process loader drive (LdrpInit)";
        // SAFETY: on-target, marker is a mapped stack buffer.
        unsafe { dbg_print_bytes(marker.as_ptr(), marker.len()) };

        let ntdll = ntdll_base as u64;
        let smss = smss_base as u64;
        if smss != 0 && ntdll != 0 {
            // (2)+(3) Real heap + in-process import snap against OUR export table.
            // SAFETY: on-target; both are mapped PE images in this VSpace.
            let res = unsafe { on_target::ldrp_drive(smss, ntdll) };

            // (4) Report the snap result: "snap N/M spot=0x..." (built on the STACK). N=resolved,
            // M=resolved+missing, spot = the first written IAT value (proves it points into our ntdll).
            let mut buf = [0u8; 64];
            let mut n = 0usize;
            let put = |buf: &mut [u8; 64], n: &mut usize, b: &[u8]| {
                for &c in b {
                    if *n < buf.len() {
                        buf[*n] = c;
                        *n += 1;
                    }
                }
            };
            put(&mut buf, &mut n, b"nt-ntdll: snap resolved=");
            n = write_u32_dec(&mut buf, n, res.resolved);
            put(&mut buf, &mut n, b" missing=");
            n = write_u32_dec(&mut buf, n, res.missing);
            put(&mut buf, &mut n, b" spot=0x");
            n = write_u64_hex(&mut buf, n, res.spot_iat_value);
            // SAFETY: on-target, buf is a mapped stack buffer.
            unsafe { dbg_print_bytes(buf.as_ptr(), n) };
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (ntdll_base, smss_base);
    }
    core::hint::black_box(_context);
}

/// Append `v` as decimal into `buf[n..]`; return the new length. Stack-only (no alloc).
#[cfg(target_arch = "x86_64")]
fn write_u32_dec(buf: &mut [u8; 64], mut n: usize, v: u32) -> usize {
    if v == 0 {
        if n < buf.len() {
            buf[n] = b'0';
            n += 1;
        }
        return n;
    }
    let mut digits = [0u8; 10];
    let mut d = 0;
    let mut x = v;
    while x > 0 {
        digits[d] = b'0' + (x % 10) as u8;
        d += 1;
        x /= 10;
    }
    while d > 0 {
        d -= 1;
        if n < buf.len() {
            buf[n] = digits[d];
            n += 1;
        }
    }
    n
}

/// Append `v` as 16-hex-digit into `buf[n..]`; return the new length. Stack-only (no alloc).
#[cfg(target_arch = "x86_64")]
fn write_u64_hex(buf: &mut [u8; 64], mut n: usize, v: u64) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in (0..16).rev() {
        let nib = ((v >> (i * 4)) & 0xf) as usize;
        if n < buf.len() {
            buf[n] = HEX[nib];
            n += 1;
        }
    }
    n
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
