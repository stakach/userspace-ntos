//! `win32k_host` — load the REAL ReactOS `win32k.sys` into an isolated seL4 component and
//! run its `DriverEntry` as far as it goes (Phase 2b of `plans/wiggly-doodling-badger.md`).
//!
//! Structural split (mirrors [`crate::kmdf_host`], scaled to a 2.1 MiB image staged off disk):
//!   * the EXECUTIVE (which owns the heap + the staged image at `WIN32KBUF`) parses the PE,
//!     copies its 8 sections into a run of untyped-backed frames at [`WIN32K_CODE_VA`]
//!     (VIRTUAL layout — not a `PeFile::map()` Vec, which the 128 KiB bump heap can't hold),
//!     applies the 1920 DIR64 relocations in place, and patches the IAT: init-path imports →
//!     real trampolines below, data-export globals → non-null placeholder cells, everything
//!     else → a benign zero stub. See [`load_into`].
//!   * the HOST (the spawned component) maps the image W^X (RX code / RW data), a pool arena,
//!     the data-export region, and calls `DriverEntry(DRIVER_OBJECT*, UNICODE_STRING*)` with
//!     its fault endpoint armed. On return it writes a verdict + the recorded SSDT to the
//!     shared page and trips a SENTINEL fault so the executive's fault-recv loop knows it
//!     finished (vs. faulted mid-init). See [`win32k_host_entry`].
//!
//! The trampolines are compiled into the executive's image (mapped RWX-shared into the host),
//! so the host calls them at the same VA — exactly the KMDF-host pattern.

use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};

use crate::*;

// --- component VA layout (identical in executive-load + host-run views) ----------------------

/// The relocated/loaded win32k image (VIRTUAL layout), mapped W^X in the host. size_of_image
/// is 0x220000 (544 frames); place it in its own 2-PT window well clear of everything else.
pub const WIN32K_CODE_VA: u64 = 0x0000_0100_0680_0000;
/// win32k image frame count (size_of_image 0x220000 / 0x1000).
pub const WIN32K_IMAGE_FRAMES: u64 = 0x220;
/// Pool arena the `ExAllocatePool*` trampolines bump-allocate from (counter at +0, data at +0x1000).
/// PRE-MAPPED pure bump (the committed-baseline mechanism), relocated to its own window + grown from
/// 1 MiB → 8 MiB: win32k's GUI init (DirectX + fonts + PDEV/surface/brush) needs more than 1 MiB, and
/// the old 1 MiB exhausted at the gray-brush allocation. Retype-zeroed frames give counter 0. Its own
/// 0x0A00_0000 window (4 × 2 MiB PTs). (Demand-mapping + a real free list were tried and reverted —
/// win32k's init froze with them.)
pub const WIN32K_POOL_VADDR: u64 = 0x0000_0100_0A00_0000;
pub const WIN32K_POOL_FRAMES: u64 = 2048; // 8 MiB, pre-mapped
/// The 2 MiB PT window (0x0700_0000..0x0720_0000) that holds the DATA/SHARED/SENTINEL/ARG frames
/// (the pool used to share it; now the pool has its own window above). Both the executive-load view
/// and the host-run view map a page table here for those frames.
pub const WIN32K_AUX_PT_VADDR: u64 = 0x0000_0100_0700_0000;
/// Data-export region: placeholder structs (page 0) + import cells (page 1) + KPCR (page 2) +
/// HEAP handle (page 3) + per-process slots/callout table (page 4) + EPROCESS (page 5) +
/// W32PROCESS (page 6) + W32THREAD (page 7). 8 frames.
pub const WIN32K_DATA_VADDR: u64 = 0x0000_0100_0710_0000;
pub const WIN32K_DATA_FRAMES: u64 = 8;
/// The component's GS base — a zeroed KPCR placeholder (win32k, a kernel driver, reads `gs:[..]`
/// expecting the Processor Control Region). Page 2 of the DATA region (mapped, RW, zeroed).
pub const WIN32K_KPCR_VA: u64 = WIN32K_DATA_VADDR + 0x2000;
/// A zeroed page used as the fake HEAP handle `RtlCreateHeap` returns (win32k stores it + passes
/// it back to RtlAllocateHeap; any field reads see 0). Page 3 of the DATA region.
pub const WIN32K_HEAP_HANDLE: u64 = WIN32K_DATA_VADDR + 0x3000;
/// Per-process win32 state (page 4): the current-process win32-slots + a copy of win32k's callout
/// table (recorded by PsEstablishWin32Callouts). Single hosted client (csrss) for now.
const SLOT_W32PROCESS: u64 = WIN32K_DATA_VADDR + 0x4000; // Ps{Set,Get}ProcessWin32Process slot
const SLOT_W32THREAD: u64 = WIN32K_DATA_VADDR + 0x4008; // Ps{Set,Get}ThreadWin32Thread slot
const WIN32_CALLOUTS: u64 = WIN32K_DATA_VADDR + 0x4100; // recorded WIN32_CALLOUTS_FG table (copy)
/// A fuller EPROCESS placeholder (page 5) — win32k's process-attach callout asserts fields like
/// `EPROCESS+0x2b8 != 0`; ObReferenceObjectByHandle(process handle) returns this.
const PH_EPROCESS_VA: u64 = WIN32K_DATA_VADDR + 0x5000;
/// The per-process W32PROCESS/PROCESSINFO placeholder (page 6) win32k's callout initializes.
const PH_W32PROCESS_VA: u64 = WIN32K_DATA_VADDR + 0x6000;
/// The per-thread W32THREAD placeholder (page 7).
const PH_W32THREAD_VA: u64 = WIN32K_DATA_VADDR + 0x7000;
/// A synthetic process handle NtUserProcessConnect's ObReferenceObjectByHandle resolves.
pub const FAKE_PROCESS_HANDLE: u64 = 0x0000_0000_5A5A_0100;
/// The win32k session-heap arena that RtlAllocateHeap + the Mm session/system view mappers
/// bump-allocate from (counter at +0, data at +0x1000). win32k creates its session heap + maps
/// several ~1 MiB session views; give it 16 MiB. Its own 8 PT window (0x0740_0000..0x0840_0000).
pub const WIN32K_HEAP_VADDR: u64 = 0x0000_0100_0740_0000;
pub const WIN32K_HEAP_FRAMES: u64 = 4096;
/// Shared handoff page (executive ↔ host). Within the pool's 2 MiB PT window (0x0700..0x0720).
pub const WIN32K_SHARED_VADDR: u64 = 0x0000_0100_0718_0000;
/// An unmapped VA the host reads once DriverEntry returns / a dispatch completes — the fault-recv
/// loop recognises the address as the "ready/done" signal (vs. a fault mid-init). Pool PT window.
pub const WIN32K_SENTINEL_VADDR: u64 = 0x0000_0100_0719_0000;
/// The cross-address-space ARG-MARSHAL frame: mapped RW in BOTH the executive and the win32k
/// component (within the pool PT window). The executive copies a dispatched syscall's user buffers
/// here (sized per the win32k SSN signature); win32k's handler reads/writes them in its own context;
/// the executive copies out-params back to the caller on reply. 4 pages = 16 KiB.
pub const WIN32K_ARG_VADDR: u64 = 0x0000_0100_071A_0000;
pub const WIN32K_ARG_FRAMES: u64 = 4;

/// The csrss-side VA where win32k's global USER heap arena ([`WIN32K_HEAP_VADDR`] — where gpsi, the
/// USER handle table `gHandleTable`, and the handle-entry array all live, being `UserHeapAlloc`ed)
/// is RO-mapped so the Win32 client stack (user32/gdi32) can read the SHAREDINFO the USERCONNECT's
/// `siClient` pointers name. A full 16 MiB window ([`WIN32K_HEAP_FRAMES`]), 2-MiB-aligned, sitting
/// in the free gap between csrss's DLL region (ends ~0x8a00_0000) and its NLS section (0xA000_0000).
/// The executive's connect marshaling rewrites the `siClient` pointers + `ulSharedDelta` to this
/// base (server→client delta = `WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`).
pub const CSRSS_W32_SHARED_VA: u64 = 0x0000_0000_9000_0000;

// USERCONNECT / SHAREDINFO x64 field offsets (references/reactos win32ss/include/ntuser.h): a
// USERCONNECT is { ULONG ulVersion; ULONG ulCurrentVersion; DWORD dwDispatchCount; SHAREDINFO
// siClient; } with siClient (8-byte aligned) at +0x10, and SHAREDINFO = { PSERVERINFO psi; PVOID
// aheList; PVOID pDispInfo; ULONG_PTR ulSharedDelta; ... }. NtUserProcessConnect fills these with
// SERVER pointers (shifted by W32Process->HeapMappings delta = 0 in this single-AS host); the
// executive rewrites them to CSRSS_W32_SHARED_VA-relative client pointers before copy-out.
pub const UC_SI_PSI: u64 = 0x10; // SHAREDINFO.psi
pub const UC_SI_AHELIST: u64 = 0x18; // SHAREDINFO.aheList
pub const UC_SI_PDISPINFO: u64 = 0x20; // SHAREDINFO.pDispInfo
pub const UC_SI_DELTA: u64 = 0x28; // SHAREDINFO.ulSharedDelta

const POOL_DATA_OFF: u64 = 0x1000;

// shared-page offsets
pub const SH_ENTRY_RVA: u64 = 0x00; // in:  DriverEntry RVA (u64)
pub const SH_VERDICT: u64 = 0x08; // out: verdict bitmask (u32)
pub const SH_DE_STATUS: u64 = 0x10; // out: DriverEntry NTSTATUS (i32)
pub const SH_SSDT_BASE: u64 = 0x18; // out: recorded win32k SSDT base (u64)
pub const SH_SSDT_COUNT: u64 = 0x20; // out: recorded win32k SSDT count (u32)
pub const SH_SSDT_INDEX: u64 = 0x24; // out: recorded SSDT index (u32)
pub const SH_POOL_USED: u64 = 0x30; // out: pool high-water (u64)
pub const SH_NTUSER_HANDLER: u64 = 0x40; // out: resolved SSDT[0xFA] handler VA (u64)
pub const SH_NTUSER_STATUS: u64 = 0x48; // out: NtUserInitialize NTSTATUS (i32)
// Phase 2c dispatch-loop request/reply (executive → win32k, via the shared page). After
// DriverEntry+attach the host enters a persistent loop: it trips the sentinel (ready/done), the
// executive fills these fields + resume-replies, the host resolves the SSN through the registered
// SSDT, invokes the handler in its own context (GS=KPCR/session heap), writes SH_REQ_STATUS, loops.
pub const SH_REQ_SSN: u64 = 0x50; // in:  the win32k SSN (>= 0x1000) to dispatch (u64)
pub const SH_REQ_A0: u64 = 0x58; // in:  handler arg0 (rcx)
pub const SH_REQ_A1: u64 = 0x60; // in:  handler arg1 (rdx)
pub const SH_REQ_A2: u64 = 0x68; // in:  handler arg2 (r8)
pub const SH_REQ_A3: u64 = 0x70; // in:  handler arg3 (r9)
pub const SH_REQ_STATUS: u64 = 0x78; // out: handler NTSTATUS (i32)
pub const SH_REQ_SEQ: u64 = 0x80; // out: completed-request counter (u64) — observability

// verdict bits
pub const V_ENTERED: u32 = 1; // host called into DriverEntry
pub const V_RETURNED: u32 = 2; // DriverEntry returned (did not fault)
pub const V_SUCCESS: u32 = 4; // DriverEntry returned STATUS_SUCCESS
pub const V_SSDT: u32 = 8; // KeAddSystemServiceTable recorded the win32k table
pub const V_NTUSER_ENTERED: u32 = 0x10; // dispatched SSDT[0xFA] NtUserInitialize into the handler
pub const V_NTUSER_RETURNED: u32 = 0x20; // NtUserInitialize returned (did not fault)
pub const V_NTUSER_SUCCESS: u32 = 0x40; // NtUserInitialize returned STATUS_SUCCESS
pub const V_CALLOUT_ENTERED: u32 = 0x80; // invoked win32k's process-create callout
pub const V_CALLOUT_RETURNED: u32 = 0x100; // process-create callout returned (did not fault)
pub const V_NTUSER_RESOLVED: u32 = 0x200; // SSDT resolve(0x10FA) yielded a real win32k handler

/// The win32k NtUser/NtGdi shadow-SSDT base service number; SSN 0x10FA = NtUserInitialize.
pub const WIN32K_SERVICE_BASE: u64 = 0x1000;
pub const SSN_NT_USER_INITIALIZE: u64 = 0x10FA;

/// Fix (B) self-test SSN — a SYNTHETIC dispatch (well outside win32k's real 740-entry SSDT) whose
/// handler deliberately READS an un-demand-paged data page in this component's VSpace. The read
/// FAULTS mid-dispatch; the executive's `win32k_dispatch` fault loop demand-maps the page THROUGH
/// the per-caller reply cap (REPLY_W32 / decode_reply) and resumes us. We then read the (zeroed)
/// page and return [`TEST_FAULT_STATUS`]. A clean round-trip proves the dispatch fault path no
/// longer relies on the single per-TCB `reply_to`, so a nested faulting SSN can't orphan an outer
/// caller's reply.
pub const SSN_TEST_FAULT: u64 = 0x1FFE;
/// Un-demand-paged, demand-pageable probe VA: past the win32k image tail (0x06A2_0000, so NOT
/// flagged `in_image`) yet inside the same PD as the image, so the executive maps it with no new
/// page table. Zeroed on first touch.
pub const TEST_FAULT_VA: u64 = 0x0000_0100_06B0_0000;
/// The sentinel NTSTATUS the synthetic handler returns after surviving the fault.
pub const TEST_FAULT_STATUS: i32 = 0x600D_600Du32 as i32;

/// Synthetic dispatch SSN: invoke win32k's `co_IntInitializeDesktopGraphics` (RVA 0xfca10) directly.
/// This is the lazy PDEV/desktop-graphics init that a GUI op (GetDC) would trigger — but our hosted
/// csrss can't reach that (blocked at the SM↔CSR LPC handshake). It runs PDEVOBJ_lChangeDisplaySettings
/// → loads framebuf.dll → DrvEnablePDEV/DrvEnableSurface (IOCTL_VIDEO_MAP_VIDEO_MEMORY → the BOOTBOOT
/// framebuffer) → IntCreatePrimarySurface → co_IntShowDesktop (paints the desktop) = PIXELS.
pub const SSN_INIT_DESKTOP_GFX: u64 = 0x1FFD;
/// co_IntInitializeDesktopGraphics RVA (identified via its L"DISPLAY" ref + the PDEVOBJ_lChangeDisplay
/// Settings(&gpmdev)/gbBaseVideo/EngpUpdateGraphicsDeviceList structure).
pub const CO_INIT_DESKTOP_GFX_RVA: u64 = 0xfca10;

/// The IPC message label the dispatch loop uses when it `seL4_Call`s the executive to signal
/// ready/done. win32k is NOT a hosted TCB (its trampolines issue real seL4 syscalls for serial), so
/// the dispatch loop uses a genuine `seL4_Call` on its fault-endpoint cap ([`crate::CT_FAULT`]) —
/// a normal, resumable IPC (send + block for the reply), not a fault. The executive receives faults
/// AND these Calls on the same endpoint and tells them apart by the message label: fault labels are
/// small (VMFault=6, UnknownSyscall=2, …), so this distinctive value never collides.
pub const W32_DISPATCH_LABEL: u64 = 0x770;

// --- pool allocator (host-side; the trampolines run in the component) ------------------------
//
// A real free-list allocator (NOT a leak-forever bump arena): win32k's GUI bring-up ALLOC/FREEs
// pool in tight churn loops (font/GDI object caches), and with no-op `ExFreePool` those leak
// unbounded — the pool exhausted at EXACTLY whatever cap was set (1 MiB, then 8 MiB). So each block
// carries a 16-byte header ([hdr+0]=capacity, [hdr+8]=next-free when on the list); `pool_free`
// pushes the block onto a single free list (head word at [POOL_VADDR+8]); `pool_alloc` first-fits
// that list before bumping. Same-size churn (the common case) reuses the freed block immediately →
// bounded. The bump counter lives at [POOL_VADDR+0]; data starts at POOL_DATA_OFF (0x1000).

// Pure bump arena (matches the known-good committed baseline, just larger + relocated). NOTE: a real
// free list was tried and reverted — win32k's GUI init froze with it (a churn path did not compose
// with reclaimed blocks). `ExFreePool` stays a no-op; the arena is sized generously instead.

unsafe fn pool_alloc(size: u64) -> u64 {
    let ctr = WIN32K_POOL_VADDR as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    let start = (WIN32K_POOL_VADDR + cur + 15) & !15;
    let cap = WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000;
    if size == 0 || start + size > cap {
        print_str(b"[win32k-host] POOL EXHAUSTED size=0x");
        print_hex(size as u32);
        print_str(b" used=0x");
        print_hex(cur as u32);
        print_str(b"\n");
        return 0;
    }
    write_volatile(ctr, (start + size) - WIN32K_POOL_VADDR);
    start
}

/// A SEPARATE bump arena for FreeType (ftfd) allocations. FreeType's font-subsystem init allocates
/// unboundedly (it allocates until the arena OOMs, then truncates + returns success — the same graceful
/// behaviour the shared 1 MiB pool gave in the committed baseline). Isolating its `'FTYP'`-tagged
/// allocations here means it can't starve the MAIN pool that the gray-brush / PDEV / primary-surface
/// creation in the rest of NtUserInitialize needs. (Root cause — a FreeType loop fed a bad count via a
/// win32k font-init path — is a deeper ftfd-hosting fix; this bounds the blast radius.) Counter at +0.
pub const WIN32K_FTYP_VADDR: u64 = 0x0000_0100_0B00_0000;
pub const WIN32K_FTYP_FRAMES: u64 = 512; // 2 MiB (own window, pre-mapped)
/// FreeType's `EngAllocMem` tag ('FTYP', little-endian) — see the ftfd ft_alloc disasm.
pub const FTYP_TAG: u64 = 0x5059_5446;

unsafe fn ftyp_alloc(size: u64) -> u64 {
    let ctr = WIN32K_FTYP_VADDR as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    let start = (WIN32K_FTYP_VADDR + cur + 15) & !15;
    let cap = WIN32K_FTYP_VADDR + WIN32K_FTYP_FRAMES * 0x1000;
    if size == 0 || start + size > cap {
        return 0; // OOM → FreeType truncates gracefully (matches the baseline)
    }
    write_volatile(ctr, (start + size) - WIN32K_FTYP_VADDR);
    start
}

/// User-mode VM arena for `ZwAllocateVirtualMemory(NtCurrentProcess(), ...)`. win32k's GDI attribute
/// pool ([`GdiPoolAllocateSection`], win32ss/gdi/ntgdi/gdipool.c) reserves a 64 KiB user-mode region
/// per pool section (`MEM_RESERVE`) then commits pages on demand (`MEM_COMMIT`) — the DC_ATTR /
/// RGN_ATTR storage. In this single-address-space host the whole arena is pre-mapped RW, so RESERVE
/// hands out a bump slice and COMMIT is a no-op. Own 2 MiB-aligned window + PTs (spawn_win32k_host).
/// Counter at +0 (like the pool/ftyp arenas).
pub const WIN32K_USERVM_VADDR: u64 = 0x0000_0100_0C00_0000;
pub const WIN32K_USERVM_FRAMES: u64 = 1024; // 4 MiB, pre-mapped (64 GDI-pool sections)

unsafe fn uservm_alloc(size: u64) -> u64 {
    let ctr = WIN32K_USERVM_VADDR as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    // 64 KiB granularity (GDI_POOL_ALLOCATION_GRANULARITY) so each reservation is page-run isolated.
    let start = (WIN32K_USERVM_VADDR + cur + 0xFFFF) & !0xFFFF;
    let cap = WIN32K_USERVM_VADDR + WIN32K_USERVM_FRAMES * 0x1000;
    if size == 0 || start + size > cap {
        return 0;
    }
    write_volatile(ctr, (start + size) - WIN32K_USERVM_VADDR);
    start
}

// --- ntoskrnl trampolines (extern "win64"; win64 args = rcx, rdx, r8, r9, stack) -------------

extern "win64" fn s_zero() -> u64 {
    0
}
extern "win64" fn s_true() -> u64 {
    1
}

const PH_ETHREAD: u64 = WIN32K_DATA_VADDR + 0x600;

/// `PEPROCESS IoGetCurrentProcess()` / `PsGetCurrentProcess()` — the current (only) hosted client's
/// EPROCESS. A fuller placeholder (page 5) so win32k's process-attach callout finds its asserted
/// fields set.
extern "win64" fn s_current_process() -> u64 {
    PH_EPROCESS_VA
}
extern "win64" fn s_current_thread() -> u64 {
    PH_ETHREAD
}
/// `PVOID PsGetProcessWin32Process(PEPROCESS)` / `PsGetCurrentProcessWin32Process()` — the real
/// per-process win32-slot (set by win32k via PsSetProcessWin32Process during process attach).
extern "win64" fn s_get_win32process() -> u64 {
    unsafe { read_volatile(SLOT_W32PROCESS as *const u64) }
}
extern "win64" fn s_get_win32thread() -> u64 {
    unsafe { read_volatile(SLOT_W32THREAD as *const u64) }
}
/// `VOID PsSetProcessWin32Process(PEPROCESS Process, PVOID W32Process, PVOID OldValue)` — store the
/// W32Process win32k allocated in the per-process slot. (Single client; Process arg ignored.)
extern "win64" fn s_set_win32process(_process: u64, w32process: u64, _old: u64) -> i32 {
    unsafe { write_volatile(SLOT_W32PROCESS as *mut u64, w32process) };
    0
}
extern "win64" fn s_set_win32thread(_thread: u64, w32thread: u64, _old: u64) -> i32 {
    unsafe { write_volatile(SLOT_W32THREAD as *mut u64, w32thread) };
    0
}

/// `PsEstablishWin32Callouts(PWIN32_CALLOUTS_FG CalloutData)` — record win32k's callout table
/// (ProcessCallout, ThreadCallout, …) into persistent storage so the host can invoke win32k's own
/// process-create callout when a client first attaches. The table is on win32k's stack; copy it.
extern "win64" fn s_establish_win32_callouts(callout_data: u64) -> i32 {
    if callout_data != 0 {
        unsafe {
            for i in 0..(0x100u64 / 8) {
                let v = read_volatile((callout_data + i * 8) as *const u64);
                write_volatile((WIN32_CALLOUTS + i * 8) as *mut u64, v);
            }
        }
    }
    0
}

/// `NTSTATUS ObReferenceObjectByHandle(HANDLE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE,
/// PVOID *Object, ...)` — resolve a handle to its object. For win32k's process-connect the handle
/// is the client process handle → return the current EPROCESS. Writes `*Object`, refs it.
extern "win64" fn s_ob_reference_object_by_handle(
    _handle: u64,
    _access: u64,
    _obj_type: u64,
    _mode: u64,
    object_out: *mut u64,
) -> i32 {
    if !object_out.is_null() {
        unsafe { write_unaligned(object_out, PH_EPROCESS_VA) };
    }
    0
}

/// Bump-allocate from the win32k session-heap arena (RtlAllocateHeap). Same shape as `pool_alloc`
/// but over its own 4 MiB region.
unsafe fn heap_alloc(size: u64) -> u64 {
    let ctr = WIN32K_HEAP_VADDR as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    let start = (WIN32K_HEAP_VADDR + cur + 15) & !15;
    let cap = WIN32K_HEAP_VADDR + WIN32K_HEAP_FRAMES * 0x1000;
    if size == 0 || start + size > cap {
        print_str(b"[win32k-host] HEAP EXHAUSTED size=0x");
        print_hex(size as u32);
        print_str(b" used=0x");
        print_hex(cur as u32);
        print_str(b"\n");
        return 0;
    }
    write_volatile(ctr, (start + size) - WIN32K_HEAP_VADDR);
    start
}

/// A GENERAL_LOOKASIDE's default Allocate `PVOID(POOL_TYPE, SIZE_T, ULONG Tag)` — bump the heap
/// arena (the lookaside is a per-type object cache; slow-path allocation on an empty free-list).
extern "win64" fn s_lookaside_alloc(_pool_type: u64, size: u64, _tag: u64) -> u64 {
    unsafe { heap_alloc(size) }
}
/// A GENERAL_LOOKASIDE's default Free `VOID(PVOID)` — no-op (bump arena never frees).
extern "win64" fn s_lookaside_free(_buf: u64) {}

/// Initialize a GENERAL_LOOKASIDE via the real [`nt_kernel_exec::init_general_lookaside`] primitive
/// (host-tested x64 layout), defaulting the Allocate/Free callbacks to this host's pool trampolines
/// when the caller passed null. `ExInitialize{,N}PagedLookasideList` — a no-op stub left
/// Allocate(+0x30) null, so win32k's slow-path `call [desc+0x30]` jumped to null (RVA 0xb3e88).
unsafe fn init_lookaside(la: u64, allocate: u64, free: u64, size: u64, tag: u64, depth: u64, pool_type: u32) {
    if la == 0 {
        return;
    }
    let alloc_fn = if allocate != 0 { allocate } else { s_lookaside_alloc as usize as u64 };
    let free_fn = if free != 0 { free } else { s_lookaside_free as usize as u64 };
    nt_kernel_exec::init_general_lookaside(
        la as *mut u8,
        la, // same-AS: the ListEntry self-link VA is the descriptor pointer
        alloc_fn,
        free_fn,
        size as u32,
        tag as u32,
        depth as u16,
        pool_type,
    );
}

/// `ExInitializePagedLookasideList(Lookaside, Allocate, Free, Flags, Size, Tag, Depth)`.
extern "win64" fn s_ex_init_paged_lookaside(
    la: u64,
    allocate: u64,
    free: u64,
    _flags: u64,
    size: u64,
    tag: u64,
    depth: u64,
) {
    unsafe { init_lookaside(la, allocate, free, size, tag, depth, nt_kernel_exec::POOL_TYPE_PAGED) }
}
/// `ExInitializeNPagedLookasideList(...)` — same layout, NonPagedPool type.
extern "win64" fn s_ex_init_npaged_lookaside(
    la: u64,
    allocate: u64,
    free: u64,
    _flags: u64,
    size: u64,
    tag: u64,
    depth: u64,
) {
    unsafe { init_lookaside(la, allocate, free, size, tag, depth, 0 /* NonPagedPool */) }
}

/// `PVOID RtlCreateHeap(Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters)` — win32k
/// creates its session heap. Return a non-null fake handle; RtlAllocateHeap bumps the arena.
extern "win64" fn s_rtl_create_heap() -> u64 {
    WIN32K_HEAP_HANDLE
}
/// `PVOID RtlAllocateHeap(HeapHandle, Flags, Size)` — bump the session-heap arena.
extern "win64" fn s_rtl_allocate_heap(_heap: u64, _flags: u64, size: u64) -> u64 {
    unsafe { heap_alloc(size) }
}
/// `BOOLEAN RtlFreeHeap(HeapHandle, Flags, Base)` — no-op (bump arena never frees).
extern "win64" fn s_rtl_free_heap() -> u64 {
    1
}

use nt_kernel_exec::session_section::{
    init_section, is_section, map_section, section_object, section_size,
};

const STATUS_NO_MEMORY: i32 = 0xC000_0017u32 as i32;

/// Resolve (allocating once, from the heap arena) the coherent backing base + size for a section
/// map. If `section` is one of our [`init_section`] descriptors, use its recorded size + idempotent
/// base (so the kernel session view and every per-process view share one backing); otherwise fall
/// back to `size_hint` (a foreign/system-space section we didn't create).
unsafe fn section_view(section: u64, size_hint: u64) -> (u64, u64) {
    if is_section(section as *const u8) {
        let sz = section_size(section as *const u8);
        (map_section(section as *mut u8, |s| heap_alloc(s)), sz)
    } else {
        let mut size = size_hint;
        if size == 0 || size > 0x0040_0000 {
            size = 0x0010_0000; // default/cap the view at 1 MiB
        }
        size = (size + 0xFFF) & !0xFFF;
        (heap_alloc(size), size)
    }
}

/// `NTSTATUS MmCreateSection(PVOID *SectionObject, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER
/// MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle,
/// PFILE_OBJECT FileObject)` — win32k's `UserCreateHeap` creates the global USER-heap section here.
/// Allocate a real [`session_section`](nt_memory_manager::session_section) descriptor from the pool
/// and write it to `*SectionObject` (a no-op stub left it null → `MapGlobalUserHeap` later asserted).
extern "win64" fn s_mm_create_section(
    section_out: *mut u64,
    _access: u64,
    _obj_attr: u64,
    max_size: *const i64,
) -> i32 {
    unsafe {
        let size = if max_size.is_null() { 0x0010_0000 } else { read_unaligned(max_size) as u64 };
        let desc = pool_alloc(section_object::SIZE_OF as u64);
        if desc == 0 {
            return STATUS_NO_MEMORY;
        }
        init_section(desc as *mut u8, size);
        if !section_out.is_null() {
            write_unaligned(section_out, desc);
        }
    }
    0
}

/// `MmMapViewInSessionSpace/MmMapViewInSystemSpace(Section, PVOID *MappedBase, PSIZE_T ViewSize)`
/// — win32k maps a section into session/system space and then USES the mapped view (memsets it,
/// builds shared structures). Back it with the section's coherent region, populating `*MappedBase`
/// + `*ViewSize` (a no-op stub left `*MappedBase` null → memset(null)).
extern "win64" fn s_mm_map_view(section: u64, base_out: *mut u64, size_io: *mut u64) -> i32 {
    unsafe {
        let hint = if size_io.is_null() { 0 } else { read_volatile(size_io) };
        let (base, size) = section_view(section, hint);
        if base == 0 {
            return STATUS_NO_MEMORY;
        }
        if !base_out.is_null() {
            write_volatile(base_out, base);
        }
        if !size_io.is_null() {
            write_volatile(size_io, size);
        }
    }
    0
}

/// `NTSTATUS MmMapViewOfSection(PVOID Section, PEPROCESS Process, PVOID *BaseAddress, ULONG_PTR
/// ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT,
/// ULONG AllocationType, ULONG Win32Protect)` — `MapGlobalUserHeap` projects the global USER-heap
/// section into each connecting process. Return the SAME backing the session-space map used (single
/// address space → kernel + user views coincide, delta 0), writing `*BaseAddress` + `*ViewSize`.
extern "win64" fn s_mm_map_view_of_section(
    section: u64,
    _process: u64,
    base_out: *mut u64,
    _zero_bits: u64,
    _commit: u64,
    _offset: u64,
    size_io: *mut u64,
) -> i32 {
    unsafe {
        let hint = if size_io.is_null() { 0 } else { read_volatile(size_io) };
        let (base, size) = section_view(section, hint);
        if base == 0 {
            return STATUS_NO_MEMORY;
        }
        if !base_out.is_null() {
            write_volatile(base_out, base);
        }
        if !size_io.is_null() {
            write_volatile(size_io, size);
        }
    }
    0
}

/// `PVOID ExAllocatePoolWithTag(POOL_TYPE, SIZE_T NumberOfBytes, ULONG Tag)`. FreeType's `'FTYP'`-
/// tagged allocations (unbounded) go to a separate arena so they can't starve the main pool.
extern "win64" fn s_ex_alloc_pool_with_tag(_pool: u64, size: u64, tag: u64) -> u64 {
    unsafe {
        if (tag as u32) as u64 == FTYP_TAG {
            ftyp_alloc(size)
        } else {
            pool_alloc(size)
        }
    }
}
/// `PVOID ExAllocatePool(POOL_TYPE, SIZE_T NumberOfBytes)`.
extern "win64" fn s_ex_alloc_pool(_pool: u64, size: u64) -> u64 {
    unsafe { pool_alloc(size) }
}
/// `PVOID ExAllocatePoolWithQuotaTag(POOL_TYPE, SIZE_T, ULONG Tag)`.
extern "win64" fn s_ex_alloc_pool_quota(_pool: u64, size: u64, _tag: u64) -> u64 {
    unsafe { pool_alloc(size) }
}

/// `VOID RtlInitUnicodeString(PUNICODE_STRING Dest, PCWSTR Source)`.
extern "win64" fn s_rtl_init_unicode_string(dest: *mut u8, source: *const u16) {
    if dest.is_null() {
        return;
    }
    let mut n = 0usize;
    if !source.is_null() {
        unsafe {
            while *source.add(n) != 0 && n < 32768 {
                n += 1;
            }
        }
    }
    let bytes = (n * 2) as u16;
    unsafe {
        core::ptr::write_unaligned(dest as *mut u16, bytes);
        core::ptr::write_unaligned((dest as *mut u16).add(1), bytes.wrapping_add(2));
        core::ptr::write_unaligned(dest.add(8) as *mut u64, source as u64);
    }
}

/// `VOID RtlInitAnsiString(PANSI_STRING Dest, PCSZ Source)`.
extern "win64" fn s_rtl_init_ansi_string(dest: *mut u8, source: *const u8) {
    if dest.is_null() {
        return;
    }
    let mut n = 0usize;
    if !source.is_null() {
        unsafe {
            while *source.add(n) != 0 && n < 32768 {
                n += 1;
            }
        }
    }
    let bytes = n as u16;
    unsafe {
        core::ptr::write_unaligned(dest as *mut u16, bytes);
        core::ptr::write_unaligned((dest as *mut u16).add(1), bytes.wrapping_add(1));
        core::ptr::write_unaligned(dest.add(8) as *mut u64, source as u64);
    }
}

/// `KeAddSystemServiceTable(Base, Count, Limit, Number, Index)` — win32k registers its
/// NtUser/NtGdi table at shadow index 1. Record it into the shared page for the executive.
extern "win64" fn s_ke_add_system_service_table(
    base: u64,
    _count_ptr: u64,
    limit: u64,
    _number_ptr: u64,
    index: u64,
) -> u64 {
    unsafe {
        write_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *mut u64, base);
        write_volatile((WIN32K_SHARED_VADDR + SH_SSDT_COUNT) as *mut u32, limit as u32);
        write_volatile((WIN32K_SHARED_VADDR + SH_SSDT_INDEX) as *mut u32, index as u32);
        let v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32);
        write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v | V_SSDT);
    }
    1
}

/// `DbgPrint(PCSTR Format, ...)` — forward the (format) string to serial for observability.
extern "win64" fn s_dbg_print(fmt: *const u8) -> u32 {
    if !fmt.is_null() {
        print_str(b"[win32k dbg] ");
        unsafe {
            let mut i = 0usize;
            while i < 240 {
                let c = *fmt.add(i);
                if c == 0 {
                    break;
                }
                debug_put_char(c);
                i += 1;
            }
        }
        print_str(b"\n");
    }
    0
}

// --- CRT + misc ntoskrnl trampolines dxg.sys imports -----------------------------------------

/// `void* memcpy(void* dst, const void* src, size_t n)`.
extern "win64" fn s_memcpy(dst: u64, src: u64, n: u64) -> u64 {
    unsafe {
        let mut i = 0u64;
        while i < n {
            write_volatile((dst + i) as *mut u8, read_volatile((src + i) as *const u8));
            i += 1;
        }
    }
    dst
}
/// `void* memmove(void* dst, const void* src, size_t n)` — overlap-safe.
extern "win64" fn s_memmove(dst: u64, src: u64, n: u64) -> u64 {
    unsafe {
        if dst < src || dst >= src + n {
            let mut i = 0u64;
            while i < n {
                write_volatile((dst + i) as *mut u8, read_volatile((src + i) as *const u8));
                i += 1;
            }
        } else {
            let mut i = n;
            while i > 0 {
                i -= 1;
                write_volatile((dst + i) as *mut u8, read_volatile((src + i) as *const u8));
            }
        }
    }
    dst
}
/// `void* memset(void* dst, int c, size_t n)`.
extern "win64" fn s_memset(dst: u64, c: u64, n: u64) -> u64 {
    unsafe {
        let b = c as u8;
        let mut i = 0u64;
        while i < n {
            write_volatile((dst + i) as *mut u8, b);
            i += 1;
        }
    }
    dst
}
/// `VOID ExFreePoolWithTag(PVOID, ULONG)` — no-op (pure bump arena).
extern "win64" fn s_ex_free_pool_with_tag(_p: u64, _tag: u64) {}

// --- ZwAllocateVirtualMemory + RTL_BITMAP (GDI DC_ATTR / RGN_ATTR pool) -----------------------

const MEM_COMMIT: u64 = 0x1000;
const MEM_RESERVE: u64 = 0x2000;

/// `NTSTATUS ZwAllocateVirtualMemory(HANDLE, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T
/// RegionSize, ULONG AllocationType, ULONG Protect)`. win32k's GDI attribute pool
/// (`GdiPoolAllocateSection` → RESERVE 64 KiB; `GdiPoolAllocate` → COMMIT pages) is the caller. The
/// USERVM arena is pre-mapped RW, so RESERVE hands out a bump slice + writes `*BaseAddress`, and
/// COMMIT of an already-reserved region just succeeds (memory is already backed). Previously this
/// fell to the s_zero stub (SUCCESS but never wrote `*BaseAddress`) → `pvBaseAddress` stayed NULL →
/// GdiPoolAllocate returned NULL → "Could not allocate DC attr".
extern "win64" fn s_zw_allocate_virtual_memory(
    _process: u64,
    base_io: *mut u64,
    _zero_bits: u64,
    size_io: *mut u64,
    alloc_type: u64,
    _protect: u64,
) -> i32 {
    if base_io.is_null() || size_io.is_null() {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    unsafe {
        let want = read_volatile(size_io);
        let size = (want + 0xFFF) & !0xFFF;
        if alloc_type & MEM_RESERVE != 0 {
            let base = uservm_alloc(size.max(0x1_0000));
            if base == 0 {
                return 0xC000_0017u32 as i32; // STATUS_NO_MEMORY
            }
            write_volatile(base_io, base);
            write_volatile(size_io, size.max(0x1_0000));
        } else {
            // MEM_COMMIT: the region was already reserved (pre-mapped). Keep *BaseAddress; if the
            // caller passed a bare COMMIT with no reservation, back it from the arena.
            if read_volatile(base_io) == 0 {
                let base = uservm_alloc(size.max(0x1000));
                if base == 0 {
                    return 0xC000_0017u32 as i32;
                }
                write_volatile(base_io, base);
            }
            write_volatile(size_io, size.max(0x1000));
        }
        0 // STATUS_SUCCESS
    }
}

/// `NTSTATUS ZwFreeVirtualMemory(HANDLE, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)` —
/// no-op success (the USERVM arena never reclaims; GdiPool only frees on section teardown).
extern "win64" fn s_zw_free_virtual_memory(_p: u64, _base: u64, _size: u64, _ty: u64) -> i32 {
    0
}

use nt_kernel_exec::rtl_bitmap;

/// `VOID RtlInitializeBitMap(PRTL_BITMAP, PULONG Buffer, ULONG SizeOfBitMap)`.
extern "win64" fn s_rtl_initialize_bitmap(bm: u64, buffer: u64, size: u32) {
    if bm != 0 {
        unsafe { rtl_bitmap::initialize(bm as *mut u8, buffer, size) };
    }
}
/// `VOID RtlClearAllBits(PRTL_BITMAP)`.
extern "win64" fn s_rtl_clear_all_bits(bm: u64) {
    if bm != 0 {
        unsafe { rtl_bitmap::clear_all(bm as *mut u8) };
    }
}
/// `VOID RtlSetAllBits(PRTL_BITMAP)`.
extern "win64" fn s_rtl_set_all_bits(bm: u64) {
    if bm != 0 {
        unsafe { rtl_bitmap::set_all(bm as *mut u8) };
    }
}
/// `ULONG RtlFindClearBitsAndSet(PRTL_BITMAP, ULONG NumberToFind, ULONG HintIndex)`.
extern "win64" fn s_rtl_find_clear_bits_and_set(bm: u64, count: u32, hint: u32) -> u32 {
    if bm == 0 {
        return rtl_bitmap::BITMAP_NONE;
    }
    unsafe { rtl_bitmap::find_clear_bits_and_set(bm as *mut u8, count, hint) }
}
/// `ULONG RtlNumberOfSetBits(PRTL_BITMAP)`.
extern "win64" fn s_rtl_number_of_set_bits(bm: u64) -> u32 {
    if bm == 0 {
        return 0;
    }
    unsafe { rtl_bitmap::number_of_set_bits(bm as *const u8) }
}
/// `BOOLEAN RtlTestBit(PRTL_BITMAP, ULONG)`.
extern "win64" fn s_rtl_test_bit(bm: u64, i: u32) -> u8 {
    if bm != 0 && unsafe { rtl_bitmap::test_bit(bm as *const u8, i) } {
        1
    } else {
        0
    }
}
/// `VOID RtlSetBit(PRTL_BITMAP, ULONG)`.
extern "win64" fn s_rtl_set_bit(bm: u64, i: u32) {
    if bm != 0 {
        unsafe { rtl_bitmap::set_bit(bm as *mut u8, i) };
    }
}
/// `VOID RtlClearBit(PRTL_BITMAP, ULONG)`.
extern "win64" fn s_rtl_clear_bit(bm: u64, i: u32) {
    if bm != 0 {
        unsafe { rtl_bitmap::clear_bit(bm as *mut u8, i) };
    }
}
/// `VOID RtlSetBits(PRTL_BITMAP, ULONG StartingIndex, ULONG NumberToSet)`.
extern "win64" fn s_rtl_set_bits(bm: u64, start: u32, count: u32) {
    if bm != 0 {
        unsafe { rtl_bitmap::set_bits(bm as *mut u8, start, count) };
    }
}
/// `VOID RtlClearBits(PRTL_BITMAP, ULONG StartingIndex, ULONG NumberToClear)`.
extern "win64" fn s_rtl_clear_bits(bm: u64, start: u32, count: u32) {
    if bm != 0 {
        unsafe { rtl_bitmap::clear_bits(bm as *mut u8, start, count) };
    }
}
/// `BOOLEAN RtlAreBitsClear(PRTL_BITMAP, ULONG StartingIndex, ULONG Length)`.
extern "win64" fn s_rtl_are_bits_clear(bm: u64, start: u32, count: u32) -> u8 {
    if bm != 0 && unsafe { rtl_bitmap::are_bits_clear(bm as *const u8, start, count) } {
        1
    } else {
        0
    }
}
/// `HANDLE PsGetCurrentProcessId()` / `PsGetCurrentThreadProcessId()` — a fixed nonzero PID.
extern "win64" fn s_current_process_id() -> u64 {
    (FAKE_PROCESS_HANDLE as u32) as u64
}

/// `NTSTATUS ZwOpenFile(...)` — win32k's font init (IntLoadSystemFonts) opens `\SystemRoot\Fonts\`
/// as a directory to enumerate *.ttf. That directory doesn't exist in this environment, so return
/// STATUS_OBJECT_NAME_NOT_FOUND: IntLoadSystemFonts then SKIPS the whole enumeration loop (rather
/// than being fed a garbage handle by an s_zero=SUCCESS stub and crashing on a bogus font read), and
/// InitFontSupport returns TRUE. A no-op SUCCESS here is actively harmful (it faked a valid handle).
extern "win64" fn s_zw_open_file_fail() -> i32 {
    0xC000_0034u32 as i32 // STATUS_OBJECT_NAME_NOT_FOUND
}

/// `VOID RtlInitEmptyUnicodeString(PUNICODE_STRING, PWSTR Buffer, USHORT MaximumLength)`.
extern "win64" fn s_rtl_init_empty_unicode_string(dest: *mut u8, buffer: u64, max_len: u64) {
    if dest.is_null() {
        return;
    }
    unsafe {
        write_unaligned(dest as *mut u16, 0); // Length
        write_unaligned((dest as *mut u16).add(1), max_len as u16); // MaximumLength
        write_unaligned(dest.add(8) as *mut u64, buffer); // Buffer
    }
}
/// `VOID RtlCopyUnicodeString(PUNICODE_STRING Dest, PCUNICODE_STRING Src)`.
extern "win64" fn s_rtl_copy_unicode_string(dest: *mut u8, src: *const u8) {
    if dest.is_null() || src.is_null() {
        return;
    }
    unsafe {
        let src_len = read_unaligned(src as *const u16);
        let src_buf = read_unaligned(src.add(8) as *const u64);
        let dst_max = read_unaligned((dest as *const u16).add(1));
        let n = src_len.min(dst_max);
        let dst_buf = read_unaligned(dest.add(8) as *const u64);
        if src_buf != 0 && dst_buf != 0 {
            let mut i = 0u64;
            while i < n as u64 {
                write_volatile((dst_buf + i) as *mut u8, read_volatile((src_buf + i) as *const u8));
                i += 1;
            }
        }
        write_unaligned(dest as *mut u16, n); // Length
    }
}

/// `size_t wcslen(PCWSTR)`.
extern "win64" fn s_wcslen(s: u64) -> u64 {
    if s == 0 {
        return 0;
    }
    let mut n = 0u64;
    unsafe {
        while read_unaligned((s + n * 2) as *const u16) != 0 && n < 32768 {
            n += 1;
        }
    }
    n
}
/// `NTSTATUS RtlAppendUnicodeToString(PUNICODE_STRING Dest, PCWSTR Src)` — append a wide string.
extern "win64" fn s_rtl_append_unicode_to_string(dest: *mut u8, src: u64) -> i32 {
    if dest.is_null() {
        return 0;
    }
    unsafe {
        let max = read_unaligned((dest as *const u16).add(1)) as u64; // MaximumLength (bytes)
        let buf = read_unaligned(dest.add(8) as *const u64);
        if buf == 0 || src == 0 {
            return 0;
        }
        let mut pos = read_unaligned(dest as *const u16) as u64; // current Length (bytes)
        let mut w = 0u64;
        loop {
            let c = read_unaligned((src + w * 2) as *const u16);
            if c == 0 || pos + 2 > max {
                break;
            }
            write_unaligned((buf + pos) as *mut u16, c);
            pos += 2;
            w += 1;
        }
        write_unaligned(dest as *mut u16, pos as u16); // new Length
    }
    0
}
/// `BOOLEAN RtlCreateUnicodeString(PUNICODE_STRING Dest, PCWSTR Src)` — allocate a NUL-terminated
/// copy of `Src` from the win32k pool and point `Dest` at it. Returns TRUE on success. win32k's font
/// init logs "RtlCreateUnicodeString failed" if this returns FALSE, so it must really allocate+copy.
extern "win64" fn s_rtl_create_unicode_string(dest: *mut u8, src: u64) -> u32 {
    if dest.is_null() {
        return 0;
    }
    unsafe {
        // wide length (chars) of Src.
        let mut n = 0u64;
        if src != 0 {
            while read_unaligned((src + n * 2) as *const u16) != 0 && n < 32768 {
                n += 1;
            }
        }
        let bytes = n * 2;
        let buf = pool_alloc(bytes + 2); // + NUL wchar
        if buf == 0 {
            return 0;
        }
        let mut i = 0u64;
        while i < bytes {
            write_volatile((buf + i) as *mut u8, read_volatile((src + i) as *const u8));
            i += 1;
        }
        write_unaligned((buf + bytes) as *mut u16, 0);
        write_unaligned(dest as *mut u16, bytes as u16); // Length
        write_unaligned((dest as *mut u16).add(1), (bytes + 2) as u16); // MaximumLength
        write_unaligned(dest.add(8) as *mut u64, buf); // Buffer
    }
    1
}

/// `NTSTATUS RtlMultiByteToUnicodeN(PWCH Unicode, ULONG MaxBytes, PULONG BytesOut, PCSTR Mb, ULONG
/// MbBytes)` — convert a multibyte string to UTF-16. Simplified to a zero-extending (ASCII/Latin-1)
/// conversion, which is exact for font/face names. Backs win32k's EngMultiByteToUnicodeN forwarder.
extern "win64" fn s_rtl_multibyte_to_unicode_n(
    unicode: *mut u16,
    max_bytes: u32,
    bytes_out: *mut u32,
    mb: *const u8,
    mb_bytes: u32,
) -> i32 {
    let max_chars = (max_bytes / 2) as usize;
    let n = (mb_bytes as usize).min(max_chars);
    unsafe {
        if !unicode.is_null() && !mb.is_null() {
            for i in 0..n {
                core::ptr::write_unaligned(unicode.add(i), *mb.add(i) as u16);
            }
        }
        if !bytes_out.is_null() {
            core::ptr::write_unaligned(bytes_out, (n * 2) as u32);
        }
    }
    0 // STATUS_SUCCESS
}
/// `int _wcsnicmp(PCWSTR, PCWSTR, size_t)` — case-insensitive wide compare (0 = equal).
extern "win64" fn s_wcsnicmp(a: u64, b: u64, n: u64) -> i32 {
    unsafe {
        let mut i = 0u64;
        while i < n {
            let ca = read_unaligned((a + i * 2) as *const u16);
            let cb = read_unaligned((b + i * 2) as *const u16);
            let la = if (b'A' as u16..=b'Z' as u16).contains(&ca) { ca + 32 } else { ca };
            let lb = if (b'A' as u16..=b'Z' as u16).contains(&cb) { cb + 32 } else { cb };
            if la != lb {
                return if la < lb { -1 } else { 1 };
            }
            if ca == 0 {
                return 0;
            }
            i += 1;
        }
    }
    0
}

/// `NTSTATUS ZwSetSystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG)`. win32k's
/// `LDEVOBJ_bLoadImage` loads a GDI driver by calling this with class
/// `SystemLoadGdiDriverInformation` (26) + a `SYSTEM_GDI_DRIVER_INFORMATION` whose DriverName it
/// filled; the "kernel" loads the driver + fills ImageAddress/EntryPoint/ExportSectionPointer/etc.
/// We pre-loaded dxg.sys into win32k's VSpace at bring-up; match the name + fill the struct from the
/// recorded info (offsets: DriverName@0, ImageAddress@0x10, SectionPointer@0x18, EntryPoint@0x20,
/// ExportSectionPointer@0x28, ImageLength@0x30). Other classes → benign success.
/// Case-insensitive: does the wide DriverName [name_buf, +name_len bytes) end with the ASCII tail?
unsafe fn wname_ends_with(name_buf: u64, name_len: usize, tail: &[u8]) -> bool {
    if name_buf == 0 || name_len < tail.len() * 2 {
        return false;
    }
    for (k, &wc) in tail.iter().enumerate() {
        let off = name_buf + (name_len as u64 - (tail.len() - k) as u64 * 2);
        let c = read_unaligned(off as *const u16);
        let lc = if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c };
        if lc != wc as u16 {
            return false;
        }
    }
    true
}

extern "win64" fn s_zw_set_system_information(class: u64, buf: u64, _len: u64) -> i32 {
    const SYSTEM_LOAD_GDI_DRIVER_INFORMATION: u64 = 26;
    if class != SYSTEM_LOAD_GDI_DRIVER_INFORMATION || buf == 0 {
        return 0; // STATUS_SUCCESS (unmodelled classes are no-ops)
    }
    unsafe {
        // Read DriverName (UNICODE_STRING @ buf+0: u16 Length, u16 Max, u32 pad, u64 Buffer).
        let name_len = read_unaligned(buf as *const u16) as usize;
        let name_buf = read_unaligned((buf + 8) as *const u64);
        // Match the tail against a hosted GDI driver (dxg.sys / framebuf.dll) + pick its recorded info.
        let (image, entry, expdir, len, tag): (u64, u64, u64, u32, &[u8]) =
            if wname_ends_with(name_buf, name_len, b"dxg.sys") {
                (
                    read_volatile(core::ptr::addr_of!(DXG_IMAGE)),
                    read_volatile(core::ptr::addr_of!(DXG_ENTRY)),
                    read_volatile(core::ptr::addr_of!(DXG_EXPORT_DIR)),
                    read_volatile(core::ptr::addr_of!(DXG_IMAGE_LEN)),
                    b"dxg.sys",
                )
            } else if wname_ends_with(name_buf, name_len, b"framebuf.dll") {
                (
                    read_volatile(core::ptr::addr_of!(FRAMEBUF_IMAGE)),
                    read_volatile(core::ptr::addr_of!(FRAMEBUF_ENTRY)),
                    read_volatile(core::ptr::addr_of!(FRAMEBUF_EXPORT_DIR)),
                    read_volatile(core::ptr::addr_of!(FRAMEBUF_IMAGE_LEN)),
                    b"framebuf.dll",
                )
            } else {
                print_str(b"[win32k gdidrv] ZwSetSystemInformation(GdiDriver) unknown driver\n");
                return 0xC000_0135u32 as i32; // STATUS_DLL_NOT_FOUND
            };
        if image == 0 {
            return 0xC000_0135u32 as i32;
        }
        write_unaligned((buf + 0x10) as *mut u64, image); // ImageAddress
        write_unaligned((buf + 0x18) as *mut u64, image); // SectionPointer (non-null placeholder)
        write_unaligned((buf + 0x20) as *mut u64, entry); // EntryPoint (= DrvEnableDriver for framebuf)
        write_unaligned((buf + 0x28) as *mut u64, expdir); // ExportSectionPointer
        write_unaligned((buf + 0x30) as *mut u32, len); // ImageLength
        print_str(b"[win32k gdidrv] hosted ");
        print_str(tag);
        print_str(b" -> image=0x");
        print_hex((image >> 32) as u32);
        print_hex(image as u32);
        print_str(b"\n");
    }
    0
}

// --- video-device registry synthesis + framebuf miniport IOCTL intercept ---------------------
//
// win32k's EngpUpdateGraphicsDeviceList / InitDisplayDriver (ReactOS win32ss/gdi/eng/device.c +
// win32ss/user/ntuser/display.c) read the video device map from the registry (RegOpenKey→ZwOpenKey,
// RegQueryValue/RegReadDWORD→ZwQueryValueKey). There is no real registry in win32k's context, so
// these trampolines synthesise the MINIMAL device map that makes win32k find + load a "framebuf"
// display device, and intercept framebuf's video-miniport IOCTLs to feed it the BOOTBOOT framebuffer.

// Synthetic HKEYs (opaque handles win32k passes back to ZwQueryValueKey / ZwClose).
const HKEY_VIDEO_MAP: u64 = 0x5A5A_0F10; // \Registry\Machine\HARDWARE\DEVICEMAP\VIDEO
const HKEY_FB_SETTINGS: u64 = 0x5A5A_0F11; // ..\Services\framebuf\Device0 (the display settings key)
// A fake DEVICE_OBJECT / FILE_OBJECT for \Device\Video0 (win32k passes DeviceObject as the miniport
// handle to framebuf + EngDeviceIoControl — which we intercept — so it only needs to be non-null +
// stable). Zeroed sub-regions of DATA page 0.
const FAKE_DEVICE_OBJECT: u64 = WIN32K_DATA_VADDR + 0x900;
const FAKE_FILE_OBJECT: u64 = WIN32K_DATA_VADDR + 0x980;

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;

/// Case-insensitive: does the wide string [buf, +len_bytes) contain the ASCII pattern?
unsafe fn wstr_contains_ascii(buf: u64, len_bytes: usize, pat: &[u8]) -> bool {
    if buf == 0 || pat.is_empty() {
        return false;
    }
    let n = len_bytes / 2;
    if n < pat.len() {
        return false;
    }
    let low = |c: u16| -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c }
    };
    for start in 0..=(n - pat.len()) {
        let mut ok = true;
        for (k, &pb) in pat.iter().enumerate() {
            let c = low(read_unaligned((buf + ((start + k) * 2) as u64) as *const u16));
            if c != low(pb as u16) {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
}
/// Case-insensitive exact compare of a wide value-name [buf, +len_bytes) against an ASCII pattern.
unsafe fn wstr_eq_ascii(buf: u64, len_bytes: usize, pat: &[u8]) -> bool {
    if buf == 0 || len_bytes / 2 != pat.len() {
        return false;
    }
    let low = |c: u16| -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c }
    };
    for k in 0..pat.len() {
        let c = low(read_unaligned((buf + (k * 2) as u64) as *const u16));
        if c != low(pat[k] as u16) {
            return false;
        }
    }
    true
}

/// `NTSTATUS ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK, POBJECT_ATTRIBUTES)`. OBJECT_ATTRIBUTES x64:
/// ObjectName (PUNICODE_STRING) at +0x10. Match the key path to a synthetic HKEY (else NOT_FOUND, so
/// win32k's optional keys — e.g. GraphicsDrivers\BaseVideo — fail cleanly and gbBaseVideo stays 0).
extern "win64" fn s_zw_open_key(handle_out: *mut u64, _access: u64, obj_attr: u64) -> i32 {
    if obj_attr == 0 {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    unsafe {
        let ustr = read_unaligned((obj_attr + 0x10) as *const u64); // PUNICODE_STRING
        if ustr == 0 {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        let len = read_unaligned(ustr as *const u16) as usize; // Length (bytes)
        let buf = read_unaligned((ustr + 8) as *const u64); // Buffer
        let hkey = if wstr_contains_ascii(buf, len, b"DEVICEMAP\\VIDEO") {
            HKEY_VIDEO_MAP
        } else if wstr_contains_ascii(buf, len, b"framebuf") {
            HKEY_FB_SETTINGS
        } else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if !handle_out.is_null() {
            write_unaligned(handle_out, hkey);
        }
    }
    0
}

/// Emit an ASCII string `s` as a wide (UTF-16) REG_SZ/REG_MULTI_SZ into a KEY_VALUE_PARTIAL_INFORMATION
/// {TitleIndex@0, Type@4, DataLength@8, Data@0xC}. `extra_nul` adds a second terminator (MULTI_SZ).
unsafe fn emit_kvpi_wsz(kvi: u64, length: u64, result_len: *mut u32, rtype: u32, s: &[u8], extra_nul: bool) -> i32 {
    let nchars = s.len() + 1 + if extra_nul { 1 } else { 0 };
    let dbytes = (nchars * 2) as u64;
    let need = 0xC + dbytes;
    if !result_len.is_null() {
        write_unaligned(result_len, need as u32);
    }
    if kvi == 0 || length < need {
        return STATUS_BUFFER_OVERFLOW;
    }
    write_unaligned(kvi as *mut u32, 0);
    write_unaligned((kvi + 4) as *mut u32, rtype);
    write_unaligned((kvi + 8) as *mut u32, dbytes as u32);
    let d = kvi + 0xC;
    for (i, &b) in s.iter().enumerate() {
        write_unaligned((d + (i * 2) as u64) as *mut u16, b as u16);
    }
    write_unaligned((d + (s.len() * 2) as u64) as *mut u16, 0);
    if extra_nul {
        write_unaligned((d + ((s.len() + 1) * 2) as u64) as *mut u16, 0);
    }
    0
}
unsafe fn emit_kvpi_dword(kvi: u64, length: u64, result_len: *mut u32, val: u32) -> i32 {
    let need = 0xC + 4;
    if !result_len.is_null() {
        write_unaligned(result_len, need as u32);
    }
    if kvi == 0 || length < need {
        return STATUS_BUFFER_OVERFLOW;
    }
    write_unaligned(kvi as *mut u32, 0);
    write_unaligned((kvi + 4) as *mut u32, REG_DWORD);
    write_unaligned((kvi + 8) as *mut u32, 4);
    write_unaligned((kvi + 0xC) as *mut u32, val);
    0
}

/// `NTSTATUS ZwQueryValueKey(HANDLE, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS, PVOID
/// KeyValueInformation, ULONG Length, PULONG ResultLength)` — serve the synthetic device-map values.
extern "win64" fn s_zw_query_value_key(
    hkey: u64,
    value_name: u64,
    info_class: u64,
    kvi: u64,
    length: u64,
    result_len: *mut u32,
) -> i32 {
    const KEY_VALUE_PARTIAL_INFORMATION: u64 = 2;
    if info_class != KEY_VALUE_PARTIAL_INFORMATION || value_name == 0 {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    unsafe {
        let vlen = read_unaligned(value_name as *const u16) as usize;
        let vbuf = read_unaligned((value_name + 8) as *const u64);
        match hkey {
            HKEY_VIDEO_MAP => {
                if wstr_eq_ascii(vbuf, vlen, b"MaxObjectNumber") {
                    return emit_kvpi_dword(kvi, length, result_len, 0);
                }
                if wstr_eq_ascii(vbuf, vlen, b"\\Device\\Video0") {
                    return emit_kvpi_wsz(
                        kvi, length, result_len, REG_SZ,
                        b"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\framebuf\\Device0",
                        false,
                    );
                }
            }
            HKEY_FB_SETTINGS => {
                if wstr_eq_ascii(vbuf, vlen, b"InstalledDisplayDrivers") {
                    return emit_kvpi_wsz(kvi, length, result_len, REG_MULTI_SZ, b"framebuf", true);
                }
                if wstr_eq_ascii(vbuf, vlen, b"Device Description") {
                    return emit_kvpi_wsz(kvi, length, result_len, REG_SZ, b"BOOTBOOT Framebuffer", false);
                }
                if wstr_eq_ascii(vbuf, vlen, b"VgaCompatible") {
                    return emit_kvpi_dword(kvi, length, result_len, 0);
                }
            }
            _ => {}
        }
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// `NTSTATUS IoGetDeviceObjectPointer(PUNICODE_STRING, ACCESS_MASK, PFILE_OBJECT*, PDEVICE_OBJECT*)`.
extern "win64" fn s_io_get_device_object_pointer(
    _name: u64,
    _access: u64,
    fileobj_out: *mut u64,
    devobj_out: *mut u64,
) -> i32 {
    unsafe {
        if !fileobj_out.is_null() {
            write_unaligned(fileobj_out, FAKE_FILE_OBJECT);
        }
        if !devobj_out.is_null() {
            write_unaligned(devobj_out, FAKE_DEVICE_OBJECT);
        }
    }
    0
}

// Video-miniport IOCTLs (ntddvdeo.h: FILE_DEVICE_VIDEO=0x23, METHOD_BUFFERED, FILE_ANY_ACCESS →
// value = 0x0023_0000 | (Function << 2)).
const IOCTL_VIDEO_QUERY_AVAIL_MODES: u64 = 0x0023_0400;
const IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES: u64 = 0x0023_0404;
const IOCTL_VIDEO_QUERY_CURRENT_MODE: u64 = 0x0023_0408;
const IOCTL_VIDEO_SET_CURRENT_MODE: u64 = 0x0023_040C;
const IOCTL_VIDEO_MAP_VIDEO_MEMORY: u64 = 0x0023_0458;

/// Fill an 80-byte VIDEO_MODE_INFORMATION for 1024x768x32 (scanline 4096) at `out`.
unsafe fn fill_video_mode(out: u64) {
    let w = |off: u64, v: u32| write_unaligned((out + off) as *mut u32, v);
    w(0, 80); // Length (== ModeInformationLength; nonzero = a valid mode)
    w(4, 1); // ModeIndex
    w(8, 1024); // VisScreenWidth
    w(12, 768); // VisScreenHeight
    w(16, 4096); // ScreenStride (bytes/scanline)
    w(20, 1); // NumberOfPlanes (must be 1)
    w(24, 32); // BitsPerPlane (8/16/24/32)
    w(28, 60); // Frequency
    w(32, 320); // XMillimeter
    w(36, 240); // YMillimeter
    w(40, 8); // NumberRedBits
    w(44, 8); // NumberGreenBits
    w(48, 8); // NumberBlueBits
    w(52, 0x00FF_0000); // RedMask
    w(56, 0x0000_FF00); // GreenMask
    w(60, 0x0000_00FF); // BlueMask
    w(64, 0x0000_0003); // AttributeFlags = VIDEO_MODE_COLOR | VIDEO_MODE_GRAPHICS
    w(68, 1024); // VideoMemoryBitmapWidth
    w(72, 768); // VideoMemoryBitmapHeight
    w(76, 0); // DriverSpecificAttributeFlags
}

/// win32k's `EngDeviceIoControl` — INTERCEPTED (win32k's export is patched to jmp here in `load_into`,
/// so BOTH framebuf's imported calls AND win32k's own internal calls route here without a real
/// miniport/DeviceObject). Services the video IOCTLs framebuf.dll issues, feeding it the BOOTBOOT
/// framebuffer. Returns 0 (ERROR_SUCCESS) on handled, nonzero on unhandled (benign for the optional
/// IOCTLs — the callers only check zero/non-zero). win64: rcx=hDev, rdx=ioctl, r8=inbuf, r9=inlen,
/// stack: outbuf, outlen, bytesret.
extern "win64" fn s_eng_device_io_control(
    _hdev: u64,
    ioctl: u64,
    _in_buf: u64,
    _in_len: u64,
    out_buf: u64,
    out_len: u64,
    bytes_ret: *mut u32,
) -> u32 {
    unsafe {
        let set_ret = |n: u32| {
            if !bytes_ret.is_null() {
                write_unaligned(bytes_ret, n);
            }
        };
        match ioctl {
            IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES => {
                if out_buf != 0 && out_len >= 8 {
                    write_unaligned(out_buf as *mut u32, 1); // NumModes
                    write_unaligned((out_buf + 4) as *mut u32, 80); // ModeInformationLength
                    set_ret(8);
                    return 0;
                }
            }
            IOCTL_VIDEO_QUERY_AVAIL_MODES | IOCTL_VIDEO_QUERY_CURRENT_MODE => {
                if out_buf != 0 && out_len >= 80 {
                    fill_video_mode(out_buf);
                    set_ret(80);
                    return 0;
                }
            }
            IOCTL_VIDEO_SET_CURRENT_MODE => {
                set_ret(0);
                return 0;
            }
            IOCTL_VIDEO_MAP_VIDEO_MEMORY => {
                if out_buf != 0 && out_len >= 32 {
                    write_unaligned(out_buf as *mut u64, WIN32K_FB_VA); // VideoRamBase
                    write_unaligned((out_buf + 8) as *mut u32, WIN32K_FB_SIZE as u32); // VideoRamLength
                    write_unaligned((out_buf + 16) as *mut u64, WIN32K_FB_VA); // FrameBufferBase
                    write_unaligned((out_buf + 24) as *mut u32, WIN32K_FB_SIZE as u32); // FrameBufferLength
                    set_ret(32);
                    print_str(b"[win32k fb] IOCTL_VIDEO_MAP_VIDEO_MEMORY -> FrameBufferBase=0x");
                    print_hex((WIN32K_FB_VA >> 32) as u32);
                    print_hex(WIN32K_FB_VA as u32);
                    print_str(b"\n");
                    return 0;
                }
            }
            _ => {}
        }
    }
    1 // unhandled → failure (benign)
}

/// Patch win32k's exported `EngDeviceIoControl` to `jmp s_eng_device_io_control`. Runs in `load_into`
/// while win32k's image is mapped RW in the executive (before spawn maps it RX). 12 bytes:
/// `mov rax, imm64 (48 B8 ..); jmp rax (FF E0)`. Both framebuf's IAT-resolved import AND win32k's own
/// internal EngDeviceIoControl callers then route to our video-IOCTL handler.
unsafe fn patch_eng_device_io_control() {
    let va = pe_export_lookup(WIN32K_CODE_VA, b"EngDeviceIoControl\0");
    if va == 0 {
        print_str(b"[win32k fb] WARN: EngDeviceIoControl export not found\n");
        return;
    }
    let tgt = s_eng_device_io_control as usize as u64;
    write_volatile(va as *mut u8, 0x48);
    write_volatile((va + 1) as *mut u8, 0xB8);
    write_unaligned((va + 2) as *mut u64, tgt);
    write_volatile((va + 10) as *mut u8, 0xFF);
    write_volatile((va + 11) as *mut u8, 0xE0);
}

/// Resolve an import name to a trampoline. Data exports are handled separately (cells); this
/// returns code addresses only. Unknown/unmodelled → a benign zero stub (like the KMDF host).
pub fn export_addr(name: &str) -> u64 {
    let f: u64 = match name {
        // pool
        "ExAllocatePoolWithTag" => s_ex_alloc_pool_with_tag as usize as u64,
        "ExAllocatePool" => s_ex_alloc_pool as usize as u64,
        "ExAllocatePoolWithQuotaTag" => s_ex_alloc_pool_quota as usize as u64,
        // heap (win32k session heap)
        "RtlCreateHeap" => s_rtl_create_heap as usize as u64,
        "RtlAllocateHeap" => s_rtl_allocate_heap as usize as u64,
        "RtlFreeHeap" => s_rtl_free_heap as usize as u64,
        // section objects: create a real descriptor, map it coherently into session/user space
        "MmCreateSection" => s_mm_create_section as usize as u64,
        "MmMapViewInSessionSpace" | "MmMapViewInSystemSpace" => s_mm_map_view as usize as u64,
        "MmMapViewOfSection" => s_mm_map_view_of_section as usize as u64,
        // lookaside-list init (populates the GENERAL_LOOKASIDE Allocate/Free callbacks at +0x30/+0x38)
        "ExInitializePagedLookasideList" => s_ex_init_paged_lookaside as usize as u64,
        "ExInitializeNPagedLookasideList" => s_ex_init_npaged_lookaside as usize as u64,
        // CRT + misc (dxg.sys imports)
        "memcpy" | "RtlCopyMemory" => s_memcpy as usize as u64,
        "memmove" | "RtlMoveMemory" => s_memmove as usize as u64,
        "memset" | "RtlFillMemory" => s_memset as usize as u64,
        "ExFreePoolWithTag" | "ExFreePool" => s_ex_free_pool_with_tag as usize as u64,
        "PsGetCurrentProcessId" | "PsGetCurrentThreadProcessId" => s_current_process_id as usize as u64,
        // GDI attribute pool user-mode VM (GdiPoolAllocateSection RESERVE + GdiPoolAllocate COMMIT)
        "ZwAllocateVirtualMemory" | "NtAllocateVirtualMemory" => {
            s_zw_allocate_virtual_memory as usize as u64
        }
        "ZwFreeVirtualMemory" | "NtFreeVirtualMemory" => s_zw_free_virtual_memory as usize as u64,
        // RTL_BITMAP (GDI pool slot allocator — DC_ATTR / RGN_ATTR distinct storage)
        "RtlInitializeBitMap" => s_rtl_initialize_bitmap as usize as u64,
        "RtlClearAllBits" => s_rtl_clear_all_bits as usize as u64,
        "RtlSetAllBits" => s_rtl_set_all_bits as usize as u64,
        "RtlFindClearBitsAndSet" => s_rtl_find_clear_bits_and_set as usize as u64,
        "RtlNumberOfSetBits" => s_rtl_number_of_set_bits as usize as u64,
        "RtlTestBit" => s_rtl_test_bit as usize as u64,
        "RtlSetBit" => s_rtl_set_bit as usize as u64,
        "RtlClearBit" => s_rtl_clear_bit as usize as u64,
        "RtlSetBits" => s_rtl_set_bits as usize as u64,
        "RtlClearBits" => s_rtl_clear_bits as usize as u64,
        "RtlAreBitsClear" => s_rtl_are_bits_clear as usize as u64,
        // GDI driver load (win32k's LDEVOBJ_bLoadImage → dxg.sys hosting)
        "ZwSetSystemInformation" | "NtSetSystemInformation" => s_zw_set_system_information as usize as u64,
        // font dir open (\SystemRoot\Fonts) → fail cleanly so IntLoadSystemFonts skips enumeration
        "ZwOpenFile" | "NtOpenFile" => s_zw_open_file_fail as usize as u64,
        // video-device registry synthesis (EngpUpdateGraphicsDeviceList / InitDisplayDriver)
        "ZwOpenKey" | "NtOpenKey" => s_zw_open_key as usize as u64,
        "ZwQueryValueKey" | "NtQueryValueKey" => s_zw_query_value_key as usize as u64,
        "IoGetDeviceObjectPointer" => s_io_get_device_object_pointer as usize as u64,
        // Rtl string init
        "RtlInitUnicodeString" => s_rtl_init_unicode_string as usize as u64,
        "RtlInitAnsiString" => s_rtl_init_ansi_string as usize as u64,
        "RtlInitEmptyUnicodeString" => s_rtl_init_empty_unicode_string as usize as u64,
        "RtlCopyUnicodeString" => s_rtl_copy_unicode_string as usize as u64,
        "RtlAppendUnicodeToString" => s_rtl_append_unicode_to_string as usize as u64,
        "RtlCreateUnicodeString" => s_rtl_create_unicode_string as usize as u64,
        "RtlMultiByteToUnicodeN" => s_rtl_multibyte_to_unicode_n as usize as u64,
        "wcslen" => s_wcslen as usize as u64,
        "_wcsnicmp" | "wcsnicmp" => s_wcsnicmp as usize as u64,
        // SSDT registration
        "KeAddSystemServiceTable" => s_ke_add_system_service_table as usize as u64,
        // debug print
        "DbgPrint" => s_dbg_print as usize as u64,
        "vDbgPrintExWithPrefix" => s_zero as usize as u64,
        // current process/thread + real per-process win32-slots (set by win32k's process callout)
        "IoGetCurrentProcess" | "PsGetCurrentProcess" => s_current_process as usize as u64,
        "PsGetCurrentThread" | "KeGetCurrentThread" => s_current_thread as usize as u64,
        "PsGetCurrentProcessWin32Process" | "PsGetProcessWin32Process" => {
            s_get_win32process as usize as u64
        }
        "PsGetCurrentThreadWin32Thread" | "PsGetThreadWin32Thread" => {
            s_get_win32thread as usize as u64
        }
        "PsSetProcessWin32Process" => s_set_win32process as usize as u64,
        "PsSetThreadWin32Thread" => s_set_win32thread as usize as u64,
        "PsEstablishWin32Callouts" => s_establish_win32_callouts as usize as u64,
        "ObReferenceObjectByHandle" => s_ob_reference_object_by_handle as usize as u64,
        // resource / lock acquire → BOOLEAN TRUE (single-threaded host: always "acquired")
        "ExAcquireResourceExclusiveLite"
        | "ExAcquireResourceSharedLite"
        | "ExIsResourceAcquiredExclusiveLite"
        | "ExIsResourceAcquiredSharedLite"
        | "ExEnterCriticalRegionAndAcquireResourceShared"
        | "ExEnterCriticalRegionAndAcquireResourceExclusive"
        | "ExEnterCriticalRegionAndAcquireFastMutexUnsafe"
        | "ExfAcquirePushLockExclusive"
        | "ExfTryToWakePushLock"
        | "KeSetKernelStackSwapEnable"
        | "ExGetPreviousMode" => s_true as usize as u64,
        // everything else: benign zero (STATUS_SUCCESS / null / void)
        _ => s_zero as usize as u64,
    };
    f
}

/// The 11 data-export globals win32k dereferences at init. Returns the fixed CELL address for
/// `name` (the IAT slot points here; the cell holds a non-null pointer or a constant value),
/// or `None` if `name` is not a data export.
fn data_cell_addr(name: &str) -> Option<u64> {
    let cell = WIN32K_DATA_VADDR + 0x1000;
    let idx = DATA_EXPORTS.iter().position(|(n, _)| *n == name)?;
    Some(cell + idx as u64 * 8)
}

/// (name, cell value). Object-type / SE_EXPORTS / NlsMbCodePageTag point at a zeroed placeholder
/// struct in the DATA page-0 region; the Mm boundary constants hold their x64 values directly.
const DATA_EXPORTS: &[(&str, u64)] = &[
    ("PsProcessType", WIN32K_DATA_VADDR + 0x040),
    ("PsThreadType", WIN32K_DATA_VADDR + 0x080),
    ("ExDesktopObjectType", WIN32K_DATA_VADDR + 0x0C0),
    ("ExWindowStationObjectType", WIN32K_DATA_VADDR + 0x100),
    ("ExEventObjectType", WIN32K_DATA_VADDR + 0x140),
    ("LpcPortObjectType", WIN32K_DATA_VADDR + 0x180),
    ("SeExports", WIN32K_DATA_VADDR + 0x1C0),
    ("NlsMbCodePageTag", WIN32K_DATA_VADDR + 0x200),
    ("MmSystemRangeStart", 0xFFFF_0800_0000_0000),
    ("MmUserProbeAddress", 0x0000_7FFF_FFFF_0000),
    ("MmHighestUserAddress", 0x0000_7FFF_FFFF_EFFF),
];

// --- executive-side loader (fully manual, HEAP-FREE) -----------------------------------------
//
// By the time the win32k-service section runs (after smss/csrss), the executive's 128 KiB bump
// heap is exhausted — so this loader must not allocate. It parses win32k.sys's headers directly
// out of WIN32KBUF, copies sections into the (retype-zeroed) CODE_VA frames, applies relocs, and
// walks the import table in place — no `PeFile`/`Vec` anywhere.

/// Per-frame W^X rights for the loaded image (2 = RX code / RW_NX = RW data). A `static` (not a
/// stack array or heap Vec): the rootserver stack is only 16 KiB and the heap is spent.
static mut CODE_RIGHTS: [u64; WIN32K_IMAGE_FRAMES as usize] = [RW_NX; WIN32K_IMAGE_FRAMES as usize];

/// The per-frame rights `load_into` computed (for `spawn_win32k_host`'s W^X mapping).
pub fn code_rights() -> &'static [u64] {
    // SAFETY: single-threaded; written once by load_into before this is read.
    unsafe { &*core::ptr::addr_of!(CODE_RIGHTS) }
}

unsafe fn copy_bytes(dst: u64, src: u64, n: u64) {
    let mut i = 0u64;
    while i + 8 <= n {
        write_unaligned((dst + i) as *mut u64, read_unaligned((src + i) as *const u64));
        i += 8;
    }
    while i < n {
        write_volatile((dst + i) as *mut u8, read_volatile((src + i) as *const u8));
        i += 1;
    }
}

/// Runs in the EXECUTIVE. `src_va`/`src_size` name the raw win32k.sys staged in WIN32KBUF; the
/// image frames are mapped RW at [`WIN32K_CODE_VA`] and the DATA region at [`WIN32K_DATA_VADDR`].
/// Copy the sections into their virtual offsets, apply DIR64 relocs, initialise the data-export
/// cells + placeholders, patch the IAT. Fills [`CODE_RIGHTS`]. Returns the DriverEntry RVA.
pub unsafe fn load_into(src_va: u64, _src_size: usize) -> Option<u32> {
    let e = read_unaligned((src_va + 0x3c) as *const u32) as u64; // e_lfanew
    let nt = src_va + e; // "PE\0\0"
    if read_unaligned(nt as *const u32) != 0x0000_4550 {
        return None;
    }
    let file_hdr = nt + 4;
    let num_sections = read_unaligned((file_hdr + 2) as *const u16) as u64;
    let size_opt_hdr = read_unaligned((file_hdr + 16) as *const u16) as u64;
    let opt = file_hdr + 20; // OptionalHeader64
    let entry_rva = read_unaligned((opt + 16) as *const u32);
    let image_base = read_unaligned((opt + 24) as *const u64);
    let size_of_headers = read_unaligned((opt + 60) as *const u32) as u64;
    let sec_table = opt + size_opt_hdr;
    let code_va = WIN32K_CODE_VA;

    // Copy the PE headers (CODE frames are retype-zeroed, so gaps/BSS stay 0).
    copy_bytes(code_va, src_va, size_of_headers);

    // Copy each section into its virtual address; compute per-frame rights.
    let rights = &mut *core::ptr::addr_of_mut!(CODE_RIGHTS);
    for s in 0..num_sections {
        let sh = sec_table + s * 40;
        let va = read_unaligned((sh + 12) as *const u32) as u64;
        let raw_size = read_unaligned((sh + 16) as *const u32) as u64;
        let raw_ptr = read_unaligned((sh + 20) as *const u32) as u64;
        let vsize = read_unaligned((sh + 8) as *const u32) as u64;
        let chars = read_unaligned((sh + 36) as *const u32);
        let n = raw_size.min(WIN32K_IMAGE_FRAMES * 0x1000 - va);
        copy_bytes(code_va + va, src_va + raw_ptr, n);
        // IMAGE_SCN_MEM_EXECUTE = 0x2000_0000 → RX (rights 2); else RW_NX.
        let r = if chars & 0x2000_0000 != 0 { 2u64 } else { RW_NX };
        let span = va + vsize.max(raw_size);
        let mut p = va & !0xFFF;
        while p < span {
            let idx = (p / 0x1000) as usize;
            if idx < rights.len() {
                rights[idx] = r;
            }
            p += 0x1000;
        }
    }

    // Relocate the virtual image for its load at CODE_VA (DIR64 only).
    let delta = code_va.wrapping_sub(image_base);
    if delta != 0 {
        let reloc_rva = read_unaligned((opt + 112 + 5 * 8) as *const u32) as u64;
        let reloc_size = read_unaligned((opt + 112 + 5 * 8 + 4) as *const u32) as u64;
        let mut off = 0u64;
        while reloc_rva != 0 && off + 8 <= reloc_size {
            let page_rva = read_unaligned((code_va + reloc_rva + off) as *const u32) as u64;
            let block = read_unaligned((code_va + reloc_rva + off + 4) as *const u32) as u64;
            if block < 8 {
                break;
            }
            let cnt = (block - 8) / 2;
            for i in 0..cnt {
                let ent = read_unaligned((code_va + reloc_rva + off + 8 + i * 2) as *const u16);
                if (ent >> 12) == 10 {
                    let t = page_rva + (ent & 0xFFF) as u64;
                    let v = read_unaligned((code_va + t) as *const u64);
                    write_unaligned((code_va + t) as *mut u64, v.wrapping_add(delta));
                }
            }
            off += block;
        }
    }

    // Initialise the data-export placeholders (page 0, already zero) + cells (page 1).
    for (idx, (_name, value)) in DATA_EXPORTS.iter().enumerate() {
        write_volatile((WIN32K_DATA_VADDR + 0x1000 + idx as u64 * 8) as *mut u64, *value);
    }

    // KPCR.Prcb.CurrentThread (gs:[0x188]) — win32k's INTERNAL KeGetCurrentThread reads this directly
    // (bypassing the import trampoline). Point it at the same fake ETHREAD `s_current_thread` returns
    // so checked-build lock asserts (e.g. font mutex `NT_ASSERT(Owner != CurrentThread)` at RVA
    // 0x12e3b3) see a NON-null current thread instead of 0==0.
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, PH_ETHREAD);

    // Patch the IAT in place: walk the import descriptors (data dir 1) in the mapped image.
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva != 0 {
        let mut desc = code_va + imp_rva;
        loop {
            let ilt = read_unaligned(desc as *const u32) as u64; // OriginalFirstThunk
            let iat = read_unaligned((desc + 16) as *const u32) as u64; // FirstThunk
            if ilt == 0 && iat == 0 {
                break;
            }
            let names = code_va + if ilt != 0 { ilt } else { iat };
            let slots = code_va + iat;
            let mut k = 0u64;
            loop {
                let thunk = read_unaligned((names + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }
                if thunk & 0x8000_0000_0000_0000 == 0 {
                    // import by name: RVA → IMAGE_IMPORT_BY_NAME { Hint u16, Name[] }.
                    let name_ptr = code_va + (thunk & 0x7FFF_FFFF) + 2;
                    let mut buf = [0u8; 96];
                    let mut n = 0usize;
                    while n < 95 {
                        let c = read_volatile((name_ptr + n as u64) as *const u8);
                        if c == 0 {
                            break;
                        }
                        buf[n] = c;
                        n += 1;
                    }
                    let name = core::str::from_utf8_unchecked(&buf[..n]);
                    let addr = data_cell_addr(name).unwrap_or_else(|| export_addr(name));
                    write_unaligned((slots + k * 8) as *mut u64, addr);
                }
                k += 1;
            }
            desc += 20;
        }
    }

    // Patch win32k's EngDeviceIoControl export to our video-IOCTL intercept (so framebuf's imported
    // calls AND win32k's own internal miniport IOCTLs route to us — no real DeviceObject needed).
    patch_eng_device_io_control();

    Some(entry_rva)
}

// --- host-side entry -------------------------------------------------------------------------

/// The win32k host component entry. Reads the DriverEntry RVA from the shared page, builds a
/// minimal DRIVER_OBJECT + RegistryPath from the pool, calls `DriverEntry`, writes the verdict,
/// then trips the SENTINEL fault so the executive knows init finished.
#[no_mangle]
#[link_section = ".text.win32k_host_entry"]
pub unsafe extern "C" fn win32k_host_entry() -> ! {
    let entry_rva = read_volatile((WIN32K_SHARED_VADDR + SH_ENTRY_RVA) as *const u64) as u32;
    print_str(b"[win32k-host] START DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");

    // DRIVER_OBJECT (Type@0=4, Size@2=336, DriverExtension@48) + RegistryPath UNICODE_STRING.
    let drv = pool_alloc(0x200);
    core::ptr::write_unaligned(drv as *mut i16, 4);
    core::ptr::write_unaligned((drv + 2) as *mut i16, 336);
    let ext = pool_alloc(0x40);
    core::ptr::write_unaligned((drv + 48) as *mut u64, ext);
    let reg_path = pool_alloc(0x20);
    // UNICODE_STRING { Length=0, MaximumLength=2, Buffer=<a NUL wchar> }.
    let reg_buf = pool_alloc(0x10);
    core::ptr::write_unaligned(reg_path as *mut u16, 0);
    core::ptr::write_unaligned((reg_path + 2) as *mut u16, 2);
    core::ptr::write_unaligned((reg_path + 8) as *mut u64, reg_buf);

    // Mark "entered" BEFORE the call so a fault mid-init is still attributable.
    write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, V_ENTERED);

    let entry = WIN32K_CODE_VA + entry_rva as u64;
    let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = de(drv, reg_path);

    let v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32);
    let mut v = v | V_RETURNED;
    if status == 0 {
        v |= V_SUCCESS;
    }
    write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
    write_volatile((WIN32K_SHARED_VADDR + SH_DE_STATUS) as *mut i32, status);
    let pool_used = read_volatile(WIN32K_POOL_VADDR as *const u64);
    write_volatile((WIN32K_SHARED_VADDR + SH_POOL_USED) as *mut u64, pool_used);
    print_str(b"[win32k-host] DriverEntry returned status=0x");
    print_hex(status as u32);
    print_str(b" verdict=0x");
    print_hex(v);
    print_str(b"\n");

    // Phase 2c: establish the calling client's per-process win32 context THE AUTHENTIC WAY — invoke
    // win32k's OWN process-create callout (recorded by PsEstablishWin32Callouts during DriverEntry)
    // so win32k allocates + owns the client's W32PROCESS and calls PsSetProcessWin32Process — then
    // dispatch NtUserProcessConnect (SSN 0x10FA) through the SSDT in this component's context. Any
    // fault is caught + backtraced by the executive's fault loop before the sentinel below.
    if status == 0 {
        establish_client_and_dispatch();
    }

    // Enter the persistent dispatch loop (Milestone B): the host does NOT park after attach — it
    // serves win32k SSN requests forever. The first sentinel below IS the "DriverEntry+attach done"
    // signal the executive's bring-up loop waits for; thereafter each sentinel means "ready / prior
    // request done", and the executive fills a request + resume-replies to drive the next handler.
    dispatch_loop()
}

/// Resolve a win32k SSN (>= [`WIN32K_SERVICE_BASE`]) through the registered NtUser/NtGdi SSDT and
/// invoke its handler with up to four win64 register args. Returns the handler NTSTATUS (or
/// `STATUS_INVALID_SYSTEM_SERVICE` if the SSN is out of range / unregistered).
unsafe fn dispatch_ssn(ssn: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i32 {
    const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000_001Cu32 as i32;
    let base = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *const u64);
    let count = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_COUNT) as *const u32) as u64;
    if base == 0 || ssn < WIN32K_SERVICE_BASE {
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    let idx = ssn - WIN32K_SERVICE_BASE;
    if count != 0 && idx >= count {
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    let handler = read_volatile((base + idx * 8) as *const u64);
    if handler == 0 {
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    let f: extern "win64" fn(u64, u64, u64, u64) -> i32 = core::mem::transmute(handler as *const ());
    f(a0, a1, a2, a3)
}

/// Signal ready/done to the executive: a PLAIN `seL4_Send` on this component's fault-endpoint cap
/// ([`crate::CT_FAULT`]) carrying [`W32_DISPATCH_LABEL`]. Fix (A) — the dispatch handshake is
/// Send/Recv, NOT `seL4_Call`: a Call parks win32k needing the executive's *reply*, which flows
/// through the kernel's single per-TCB `reply_to` slot. When the executive drives a dispatch while
/// mid-service of a csrss syscall (nested), `reply_to` names csrss, so the Call-reply targeted the
/// wrong thread and win32k never ran (the root-caused hang). A plain Send doesn't touch `reply_to`,
/// so csrss's in-flight reply survives. win32k runs on its own bound scheduling context.
#[inline(never)]
unsafe fn send_done() {
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_SEND as u64,
        in("rdi") crate::CT_FAULT,
        in("rsi") W32_DISPATCH_LABEL << 12, // msginfo: label, length 0 (request via shared page)
        in("r10") 0u64, in("r8") 0u64, in("r9") 0u64, in("r15") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// Block for the next dispatch request: a plain `seL4_Recv` on [`crate::CT_FAULT`]. The executive
/// wakes us with a plain Send (the request payload rides the shared page `SH_REQ_*`, so the message
/// itself is ignored). No reply cap involved.
#[inline(never)]
unsafe fn recv_req() {
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_RECV as u64,
        inout("rdi") crate::CT_FAULT => _,
        lateout("rsi") _, lateout("r10") _, lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// The persistent win32k dispatch service loop (fix A, Send/Recv handshake). Each iteration: Send a
/// ready/done signal (the FIRST one is the "DriverEntry+attach done" signal the bring-up loop waits
/// for), Recv the next request, then resolve the SSN through the registered SSDT and invoke the
/// handler in this component's context (GS=KPCR / session heap). Never returns.
/// Build the "current process/thread" context win32k's INLINED accessors read during a dispatch —
/// distinct from the bring-up attach phase (which is happy with a zeroed KPCR: its optional
/// environment getter early-returns STATUS_NOT_FOUND when `gs:[0x30]==0`). During a routed dispatch,
/// win32k reads the current process the inlined way: `proc = [[gs:0x30] + 0x60]` (KPCR.Used_Self →
/// current EPROCESS) and then walks it — `UserCreateWinstaDirectory` reads `proc->SessionId@0x2c0`
/// (want 0 → session-0 winsta path) while the process-env getter walks `proc[+0x20] → [+0x80]` (a
/// wide param string). Model the WHOLE chain against the same fake EPROCESS the import trampoline
/// (`s_current_process`) returns, so gs-inlined and trampoline resolution agree:
///   gs:[0x30] (KPCR.Used_Self) = KPCR self; [KPCR+0x60] = PH_EPROCESS; PH_EPROCESS.SessionId(0x2c0)=0;
///   PH_EPROCESS[+0x20] = Q (non-null, else the env getter faults — it has no NULL check there);
///   Q[+0x80] = an empty wide string (first WCHAR 0 → getter returns cleanly).
/// One coherent context covers every csrss dispatch (single client, session 0); a multi-session model
/// would swap PH_EPROCESS/PH_ETHREAD per caller here.
unsafe fn setup_dispatch_context() {
    let q = PH_EPROCESS_VA + 0x900; // a zeroed sub-region used as PH_EPROCESS[+0x20]
    let zstr = PH_EPROCESS_VA + 0xA00; // empty wide string (WCHAR 0, already zeroed)
    write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, WIN32K_KPCR_VA); // KPCR.Used_Self = self
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, PH_EPROCESS_VA); // [Used_Self+0x60] = EPROCESS
    write_volatile((PH_EPROCESS_VA + 0x2c0) as *mut u32, 0); // SessionId = 0
    write_volatile((PH_EPROCESS_VA + 0x20) as *mut u64, q); // [EPROCESS+0x20] = Q
    write_volatile((q + 0x80) as *mut u64, zstr); // [Q+0x80] = empty wide string ptr
    write_volatile(zstr as *mut u16, 0);
}

unsafe fn dispatch_loop() -> ! {
    // Enter the per-dispatch process/thread context (see `setup_dispatch_context`). The bring-up
    // attach already ran with a zeroed KPCR (its happy path); every dispatch below runs as the
    // current (csrss) process so win32k's inlined IoGetCurrentProcess/SessionId resolve.
    setup_dispatch_context();
    loop {
        send_done();
        recv_req();
        let ssn = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_SSN) as *const u64);
        let a0 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A0) as *const u64);
        let a1 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A1) as *const u64);
        let a2 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A2) as *const u64);
        let a3 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A3) as *const u64);
        let status = if ssn == SSN_TEST_FAULT {
            // Fix (B) self-test: touch an un-demand-paged page → FAULT mid-dispatch. The executive
            // resolves it via the REPLY_W32 reply cap and resumes us here; we read back the zeroed
            // page (observability into SH_REQ_A0) and report the sentinel status.
            let probe = read_volatile(TEST_FAULT_VA as *const u64);
            write_volatile((WIN32K_SHARED_VADDR + SH_REQ_A0) as *mut u64, probe);
            TEST_FAULT_STATUS
        } else if ssn == SSN_INIT_DESKTOP_GFX {
            // Invoke co_IntInitializeDesktopGraphics() directly (VOID → BOOL) to run the framebuf
            // display-driver enable + primary-surface + show-desktop chain (= PIXELS).
            print_str(b"[win32k-host] invoking co_IntInitializeDesktopGraphics (RVA 0xfca10)\n");
            let f: extern "win64" fn() -> i32 =
                core::mem::transmute((WIN32K_CODE_VA + CO_INIT_DESKTOP_GFX_RVA) as *const ());
            let r = f();
            print_str(b"[win32k-host] co_IntInitializeDesktopGraphics returned 0x");
            print_hex(r as u32);
            print_str(b"\n");
            r
        } else {
            dispatch_ssn(ssn, a0, a1, a2, a3)
        };
        write_volatile((WIN32K_SHARED_VADDR + SH_REQ_STATUS) as *mut i32, status);
        let seq = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_SEQ) as *const u64);
        write_volatile((WIN32K_SHARED_VADDR + SH_REQ_SEQ) as *mut u64, seq + 1);
    }
}

/// Give the EPROCESS placeholder the fields win32k's process callout asserts, invoke win32k's
/// process-create callout (WIN32_CALLOUTS[0]) to build the W32PROCESS authentically, then dispatch
/// NtUserProcessConnect(ProcessHandle, USERCONNECT buffer, 0x240) via the SSDT.
unsafe fn establish_client_and_dispatch() {
    // Resolve NtUserProcessConnect (SSN 0x10FA) through the registered SSDT FIRST (before the
    // fault-prone callout/connect below) so the routing-seam proof is recorded regardless.
    let ssdt_base = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *const u64);
    if ssdt_base == 0 {
        return;
    }
    let idx = SSN_NT_USER_INITIALIZE - WIN32K_SERVICE_BASE;
    let handler = read_volatile((ssdt_base + idx * 8) as *const u64);
    write_volatile((WIN32K_SHARED_VADDR + SH_NTUSER_HANDLER) as *mut u64, handler);
    print_str(b"[win32k-host] SSDT resolve(0x10FA) -> handler=0x");
    print_hex((handler >> 32) as u32);
    print_hex(handler as u32);
    print_str(b"\n");
    if handler == 0 {
        return;
    }
    let v0 = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_NTUSER_RESOLVED;
    write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v0);

    // EPROCESS+0x2b8 must be non-null (the callout ASSERTs it — an `int 0x2c` otherwise). Point it
    // at a small zeroed sub-region of the EPROCESS page.
    write_volatile((PH_EPROCESS_VA + 0x2b8) as *mut u64, PH_EPROCESS_VA + 0x800);

    // Invoke win32k's process-create callout: W32pProcessCallout(PEPROCESS, BOOLEAN Initialize=TRUE).
    let callout = read_volatile(WIN32_CALLOUTS as *const u64);
    print_str(b"[win32k-host] win32k process-create callout=0x");
    print_hex((callout >> 32) as u32);
    print_hex(callout as u32);
    print_str(b"\n");
    if callout != 0 {
        let mut v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_CALLOUT_ENTERED;
        write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
        let co: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(callout as *const ());
        let cstatus = co(PH_EPROCESS_VA, 1);
        v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_CALLOUT_RETURNED;
        write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
        print_str(b"[win32k-host] process-create callout returned status=0x");
        print_hex(cstatus as u32);
        print_str(b" W32PROCESS=0x");
        let w32 = read_volatile(SLOT_W32PROCESS as *const u64);
        print_hex((w32 >> 32) as u32);
        print_hex(w32 as u32);
        print_str(b"\n");
    }
    // If the callout did not populate the win32-slot, fall back to the placeholder so the connect
    // path still has a non-null W32PROCESS to walk (surfaces the next requirement rather than a null
    // deref).
    if read_volatile(SLOT_W32PROCESS as *const u64) == 0 {
        write_volatile(SLOT_W32PROCESS as *mut u64, PH_W32PROCESS_VA);
    }
    if read_volatile(SLOT_W32THREAD as *const u64) == 0 {
        write_volatile(SLOT_W32THREAD as *mut u64, PH_W32THREAD_VA);
    }

    // Dispatch NtUserProcessConnect (SSN 0x10FA) with real args: a process handle, a 0x240-byte
    // USERCONNECT buffer, and its size 0x240.
    let user_connect = pool_alloc(0x240);
    let mut v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_NTUSER_ENTERED;
    write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
    let f: extern "win64" fn(u64, u64, u64) -> i32 = core::mem::transmute(handler as *const ());
    let nstatus = f(FAKE_PROCESS_HANDLE, user_connect, 0x240);
    v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_NTUSER_RETURNED;
    if nstatus == 0 {
        v |= V_NTUSER_SUCCESS;
    }
    write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
    write_volatile((WIN32K_SHARED_VADDR + SH_NTUSER_STATUS) as *mut i32, nstatus);
    print_str(b"[win32k-host] NtUserProcessConnect(0x10FA) returned status=0x");
    print_hex(nstatus as u32);
    print_str(b"\n");
}

// --- DirectX driver hosting (dxg.sys + dxgthk.sys) -------------------------------------------
//
// win32k's InitializeGreCSRSS -> DxDdStartupDxGraphics loads dxg.sys via EngLoadImage ->
// LDEVOBJ_bLoadImage -> ZwSetSystemInformation(SystemLoadGdiDriverInformation). The executive
// (privileged) PRE-LOADS dxg.sys + its dxgthk.sys dependency into win32k's VSpace at bring-up
// (parse, map W^X, relocs, resolve imports), then the ZwSetSystemInformation trampoline reports
// the pre-loaded image to win32k. This is the reusable driver-loader for framebuf.dll later.

/// dxgthk.sys loaded-image base in win32k's VSpace (size_of_image 0x5000 -> 8 frames / one 2 MiB PT).
pub const DXGTHK_VA: u64 = 0x0000_0100_0850_0000;
pub const DXGTHK_LOAD_FRAMES: u64 = 8;
/// dxg.sys loaded-image base in win32k's VSpace (size_of_image 0xd000 -> 16 frames / one 2 MiB PT).
pub const DXG_VA: u64 = 0x0000_0100_0860_0000;
pub const DXG_LOAD_FRAMES: u64 = 16;
/// ftfd.dll (FreeType font driver) loaded-image base in win32k's VSpace. size_of_image=0xf8000 ->
/// 248 frames (one 2 MiB PT, 2 MiB-aligned at 0x0870). win32k statically imports 34 FT_* from it.
pub const FTFD_VA: u64 = 0x0000_0100_0870_0000;
pub const FTFD_LOAD_FRAMES: u64 = 248;
/// framebuf.dll (generic linear-framebuffer display driver) loaded-image base in win32k's VSpace.
/// size_of_image 0x8000 -> 8 frames (its own 2 MiB PT at 0x0890). win32k loads it dynamically via
/// ZwSetSystemInformation (like dxg); framebuf's PE entry (RVA 0x1260) IS its DrvEnableDriver.
pub const FRAMEBUF_VA: u64 = 0x0000_0100_0890_0000;
pub const FRAMEBUF_LOAD_FRAMES: u64 = 8;
/// The BOOTBOOT framebuffer (Phase-0a fb device frames) mapped into win32k's VSpace, RW. framebuf's
/// DrvEnableSurface issues IOCTL_VIDEO_MAP_VIDEO_MEMORY; our EngDeviceIoControl intercept returns
/// this VA as FrameBufferBase, so framebuf writes pixels straight to the real framebuffer.
/// 1024x768x32 scanline 4096 = 0x300000 = 768 pages (2 PTs at 0x0900/0x0920).
pub const WIN32K_FB_VA: u64 = 0x0000_0100_0900_0000;
pub const WIN32K_FB_FRAMES: u64 = 768;
pub const WIN32K_FB_SIZE: u64 = 0x30_0000;

// The pre-loaded dxg.sys image info the ZwSetSystemInformation trampoline reports to win32k. Written
// by the executive (load_dxg_drivers) at bring-up; read by s_zw_set_system_information.
static mut DXG_IMAGE: u64 = 0; // ImageAddress = DXG_VA
static mut DXG_ENTRY: u64 = 0; // EntryPoint = DXG_VA + entry_rva
static mut DXG_EXPORT_DIR: u64 = 0; // ExportSectionPointer = DXG_VA + export_dir_rva
static mut DXG_IMAGE_LEN: u32 = 0; // size_of_image
// Pre-loaded framebuf.dll image info (parallel to DXG_*), reported to win32k when it dynamically
// loads "framebuf.dll" via ZwSetSystemInformation(SystemLoadGdiDriverInformation).
static mut FRAMEBUF_IMAGE: u64 = 0;
static mut FRAMEBUF_ENTRY: u64 = 0;
static mut FRAMEBUF_EXPORT_DIR: u64 = 0;
static mut FRAMEBUF_IMAGE_LEN: u32 = 0;

/// Record the loaded framebuf.dll info (called by the executive after `load_driver_into(framebuf)`).
/// framebuf has NO export directory; win32k's `EngFindImageProcAddress("DrvEnableDriver")` special-
/// cases to `EntryPoint` (ldevobj.c), so ExportSectionPointer may be 0.
pub fn record_framebuf(entry_rva: u32, export_dir_rva: u32, image_len: u32) {
    unsafe {
        write_volatile(core::ptr::addr_of_mut!(FRAMEBUF_IMAGE), FRAMEBUF_VA);
        write_volatile(core::ptr::addr_of_mut!(FRAMEBUF_ENTRY), FRAMEBUF_VA + entry_rva as u64);
        let expd = if export_dir_rva != 0 { FRAMEBUF_VA + export_dir_rva as u64 } else { 0 };
        write_volatile(core::ptr::addr_of_mut!(FRAMEBUF_EXPORT_DIR), expd);
        write_volatile(core::ptr::addr_of_mut!(FRAMEBUF_IMAGE_LEN), image_len);
    }
}

/// Walk an already-mapped image's export table (data-dir 0) at `base`; return the VA of the export
/// named `name` (nul-terminated), or 0. Handles FORWARDER exports: dxgthk's Eng* exports forward to
/// "win32k.Eng*" (the func RVA points into the export section, and the data there is a "Dll.Func"
/// string) — resolve the func part against win32k's own export table ([`WIN32K_CODE_VA`]).
unsafe fn pe_export_lookup(base: u64, name: &[u8]) -> u64 {
    let e = read_unaligned((base + 0x3c) as *const u32) as u64;
    let opt = base + e + 4 + 20;
    let exp_rva = read_unaligned((opt + 112) as *const u32) as u64;
    let exp_sz = read_unaligned((opt + 116) as *const u32) as u64;
    if exp_rva == 0 {
        return 0;
    }
    let ed = base + exp_rva;
    let nnames = read_unaligned((ed + 24) as *const u32) as u64;
    let funcs = base + read_unaligned((ed + 28) as *const u32) as u64;
    let names = base + read_unaligned((ed + 32) as *const u32) as u64;
    let ords = base + read_unaligned((ed + 36) as *const u32) as u64;
    for i in 0..nnames {
        let nr = read_unaligned((names + i * 4) as *const u32) as u64;
        let np = base + nr;
        let mut eq = true;
        let mut k = 0usize;
        loop {
            let c = read_volatile((np + k as u64) as *const u8);
            let want = if k < name.len() { name[k] } else { 0 };
            if c != want {
                eq = false;
                break;
            }
            if c == 0 {
                break;
            }
            k += 1;
        }
        if eq {
            let ord = read_unaligned((ords + i * 2) as *const u16) as u64;
            let far = read_unaligned((funcs + ord * 4) as *const u32) as u64;
            if far >= exp_rva && far < exp_rva + exp_sz {
                // FORWARDER: the string at base+far is "Dll.Func". Route by target DLL:
                //   win32k.*   -> resolve Func against win32k's own exports (dxgthk/ftfd Eng* thunks)
                //   NTOSKRNL.* / HAL.* -> resolve Func via export_addr trampolines (win32k's own Eng*
                //                         exports that forward to ntoskrnl, e.g. EngMultiByteToUnicodeN
                //                         -> RtlMultiByteToUnicodeN, EngBugCheckEx -> KeBugCheckEx).
                let s = base + far;
                let mut dll = [0u8; 16];
                let mut dl = 0usize;
                let mut dot = 0u64;
                loop {
                    let c = read_volatile((s + dot) as *const u8);
                    if c == 0 || c == b'.' {
                        break;
                    }
                    if dl < 15 {
                        dll[dl] = c.to_ascii_lowercase();
                        dl += 1;
                    }
                    dot += 1;
                }
                let mut fb = [0u8; 64];
                let mut fl = 0usize;
                while fl < 63 {
                    let c = read_volatile((s + dot + 1 + fl as u64) as *const u8);
                    if c == 0 {
                        break;
                    }
                    fb[fl] = c;
                    fl += 1;
                }
                fb[fl] = 0;
                let is_win32k = dl >= 6 && &dll[..6] == b"win32k";
                if is_win32k {
                    return pe_export_lookup(WIN32K_CODE_VA, &fb[..fl + 1]);
                }
                // ntoskrnl / hal forwarder → trampoline.
                let name = core::str::from_utf8_unchecked(&fb[..fl]);
                return export_addr(name);
            }
            return base + far;
        }
    }
    0
}

/// Load a driver PE (raw bytes at `src_va`) into `dst_va` (frames pre-mapped RW in BOTH the executive
/// and win32k). Copies headers + sections, applies DIR64 relocs for `dst_va`, patches the IAT
/// (dxgthk imports -> `dxgthk_base` exports; ntoskrnl/hal -> [`export_addr`]), records per-frame
/// rights in `rights_out`. Returns `(entry_rva, export_dir_rva, size_of_image)` or None. HEAP-FREE.
pub unsafe fn load_driver_into(
    src_va: u64,
    dst_va: u64,
    max_frames: u64,
    rights_out: &mut [u64],
    dxgthk_base: u64,
) -> Option<(u32, u32, u32)> {
    let e = read_unaligned((src_va + 0x3c) as *const u32) as u64;
    let nt = src_va + e;
    if read_unaligned(nt as *const u32) != 0x0000_4550 {
        return None;
    }
    let file_hdr = nt + 4;
    let num_sections = read_unaligned((file_hdr + 2) as *const u16) as u64;
    let size_opt_hdr = read_unaligned((file_hdr + 16) as *const u16) as u64;
    let opt = file_hdr + 20;
    let entry_rva = read_unaligned((opt + 16) as *const u32);
    let image_base = read_unaligned((opt + 24) as *const u64);
    let size_of_headers = read_unaligned((opt + 60) as *const u32) as u64;
    let size_of_image = read_unaligned((opt + 56) as *const u32);
    let export_dir_rva = read_unaligned((opt + 112) as *const u32);
    let sec_table = opt + size_opt_hdr;
    let cap = max_frames * 0x1000;

    copy_bytes(dst_va, src_va, size_of_headers.min(cap));
    for s in 0..num_sections {
        let sh = sec_table + s * 40;
        let va = read_unaligned((sh + 12) as *const u32) as u64;
        let raw_size = read_unaligned((sh + 16) as *const u32) as u64;
        let raw_ptr = read_unaligned((sh + 20) as *const u32) as u64;
        let vsize = read_unaligned((sh + 8) as *const u32) as u64;
        let chars = read_unaligned((sh + 36) as *const u32);
        if va >= cap {
            continue;
        }
        let n = raw_size.min(cap - va);
        copy_bytes(dst_va + va, src_va + raw_ptr, n);
        let r = if chars & 0x2000_0000 != 0 { 2u64 } else { RW_NX };
        let span = va + vsize.max(raw_size);
        let mut p = va & !0xFFF;
        while p < span {
            let idx = (p / 0x1000) as usize;
            if idx < rights_out.len() {
                rights_out[idx] = r;
            }
            p += 0x1000;
        }
    }

    // DIR64 relocs for the load at dst_va.
    let delta = dst_va.wrapping_sub(image_base);
    if delta != 0 {
        let reloc_rva = read_unaligned((opt + 112 + 5 * 8) as *const u32) as u64;
        let reloc_size = read_unaligned((opt + 112 + 5 * 8 + 4) as *const u32) as u64;
        let mut off = 0u64;
        while reloc_rva != 0 && off + 8 <= reloc_size {
            let page_rva = read_unaligned((dst_va + reloc_rva + off) as *const u32) as u64;
            let block = read_unaligned((dst_va + reloc_rva + off + 4) as *const u32) as u64;
            if block < 8 {
                break;
            }
            let cnt = (block - 8) / 2;
            for i in 0..cnt {
                let ent = read_unaligned((dst_va + reloc_rva + off + 8 + i * 2) as *const u16);
                if (ent >> 12) == 10 {
                    let t = page_rva + (ent & 0xFFF) as u64;
                    if t < cap {
                        let v = read_unaligned((dst_va + t) as *const u64);
                        write_unaligned((dst_va + t) as *mut u64, v.wrapping_add(delta));
                    }
                }
            }
            off += block;
        }
    }

    // Patch the IAT: resolve per import descriptor by DLL name.
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva != 0 {
        let mut desc = dst_va + imp_rva;
        loop {
            let ilt = read_unaligned(desc as *const u32) as u64;
            let iat = read_unaligned((desc + 16) as *const u32) as u64;
            let dll_name_rva = read_unaligned((desc + 12) as *const u32) as u64;
            if ilt == 0 && iat == 0 {
                break;
            }
            // read DLL name → is it dxgthk?
            let mut dllbuf = [0u8; 32];
            let mut dn = 0usize;
            if dll_name_rva != 0 {
                while dn < 31 {
                    let c = read_volatile((dst_va + dll_name_rva + dn as u64) as *const u8);
                    if c == 0 {
                        break;
                    }
                    dllbuf[dn] = c.to_ascii_lowercase();
                    dn += 1;
                }
            }
            let is_dxgthk = dn >= 6 && &dllbuf[..6] == b"dxgthk";
            // ftfd.dll imports its 8 Eng*/Rtl thunks from win32k.sys — resolve against win32k's
            // own export table (real Eng* code + forwarders to ntoskrnl handled by pe_export_lookup).
            let is_win32k = dn >= 6 && &dllbuf[..6] == b"win32k";
            let names = dst_va + if ilt != 0 { ilt } else { iat };
            let slots = dst_va + iat;
            let mut k = 0u64;
            loop {
                let thunk = read_unaligned((names + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }
                if thunk & 0x8000_0000_0000_0000 == 0 {
                    let name_ptr = dst_va + (thunk & 0x7FFF_FFFF) + 2;
                    let mut buf = [0u8; 64];
                    let mut n = 0usize;
                    while n < 63 {
                        let c = read_volatile((name_ptr + n as u64) as *const u8);
                        if c == 0 {
                            break;
                        }
                        buf[n] = c;
                        n += 1;
                    }
                    let addr = if is_dxgthk && dxgthk_base != 0 {
                        let mut nb = [0u8; 65];
                        nb[..n].copy_from_slice(&buf[..n]);
                        pe_export_lookup(dxgthk_base, &nb[..n + 1])
                    } else if is_win32k {
                        let mut nb = [0u8; 65];
                        nb[..n].copy_from_slice(&buf[..n]);
                        pe_export_lookup(WIN32K_CODE_VA, &nb[..n + 1])
                    } else {
                        let name = core::str::from_utf8_unchecked(&buf[..n]);
                        export_addr(name)
                    };
                    write_unaligned((slots + k * 8) as *mut u64, addr);
                }
                k += 1;
            }
            desc += 20;
        }
    }

    Some((entry_rva, export_dir_rva, size_of_image))
}

/// Record the loaded dxg.sys info for the ZwSetSystemInformation trampoline. Called by the executive
/// after `load_driver_into(dxg)`.
pub fn record_dxg(entry_rva: u32, export_dir_rva: u32, image_len: u32) {
    unsafe {
        write_volatile(core::ptr::addr_of_mut!(DXG_IMAGE), DXG_VA);
        write_volatile(core::ptr::addr_of_mut!(DXG_ENTRY), DXG_VA + entry_rva as u64);
        write_volatile(core::ptr::addr_of_mut!(DXG_EXPORT_DIR), DXG_VA + export_dir_rva as u64);
        write_volatile(core::ptr::addr_of_mut!(DXG_IMAGE_LEN), image_len);
    }
}

/// Re-patch win32k's OWN IAT for the `ftfd.dll` import descriptor (34 FT_* entries) against the
/// now-loaded ftfd image's export table at `ftfd_base`. Runs in the EXECUTIVE (win32k's frames are
/// still mapped RW at [`WIN32K_CODE_VA`] from `load_into`). load_into initially resolved these to
/// benign zero stubs (ftfd wasn't loaded yet); this points them at the real FreeType functions so
/// win32k's InitFontSupport → FT_Init_FreeType actually initialises the font subsystem. Returns the
/// number of FT_* slots patched (0 if no ftfd descriptor / not found). HEAP-FREE.
pub unsafe fn patch_win32k_ftfd_imports(ftfd_base: u64) -> u32 {
    let code_va = WIN32K_CODE_VA;
    let e = read_unaligned((code_va + 0x3c) as *const u32) as u64;
    let opt = code_va + e + 4 + 20;
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva == 0 {
        return 0;
    }
    let mut patched = 0u32;
    let mut desc = code_va + imp_rva;
    loop {
        let ilt = read_unaligned(desc as *const u32) as u64;
        let iat = read_unaligned((desc + 16) as *const u32) as u64;
        let dll_name_rva = read_unaligned((desc + 12) as *const u32) as u64;
        if ilt == 0 && iat == 0 {
            break;
        }
        // Is this the ftfd.dll descriptor?
        let mut dllbuf = [0u8; 16];
        let mut dn = 0usize;
        if dll_name_rva != 0 {
            while dn < 15 {
                let c = read_volatile((code_va + dll_name_rva + dn as u64) as *const u8);
                if c == 0 {
                    break;
                }
                dllbuf[dn] = c.to_ascii_lowercase();
                dn += 1;
            }
        }
        if dn >= 4 && &dllbuf[..4] == b"ftfd" {
            let names = code_va + if ilt != 0 { ilt } else { iat };
            let slots = code_va + iat;
            let mut k = 0u64;
            loop {
                let thunk = read_unaligned((names + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }
                if thunk & 0x8000_0000_0000_0000 == 0 {
                    let name_ptr = code_va + (thunk & 0x7FFF_FFFF) + 2;
                    let mut buf = [0u8; 65];
                    let mut n = 0usize;
                    while n < 63 {
                        let c = read_volatile((name_ptr + n as u64) as *const u8);
                        if c == 0 {
                            break;
                        }
                        buf[n] = c;
                        n += 1;
                    }
                    let addr = pe_export_lookup(ftfd_base, &buf[..n + 1]);
                    if addr != 0 {
                        write_unaligned((slots + k * 8) as *mut u64, addr);
                        patched += 1;
                    }
                }
                k += 1;
            }
            break;
        }
        desc += 20;
    }
    patched
}
