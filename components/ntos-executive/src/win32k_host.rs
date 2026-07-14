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
use nt_compat_exports::DriverExportRegistry;

// Pure, driver-agnostic ntoskrnl byte/string primitives shared with the FSD class.
use crate::ntoskrnl_shared::{s_memcpy, s_memmove, s_memset, s_wcslen};

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
/// The win32k COMPONENT's own stack (32 frames = 128 KiB, own 2 MiB PT). Deliberately NOT at the
/// hosted-process `STACK_BASE` (0x100_105C_0000): win32k must be able to dereference a GUI client's
/// stack-built pointers (e.g. winlogon's NtUserCreateWindowStation OBJECT_ATTRIBUTES) at their
/// IDENTITY VA (STACK_BASE region) via the per-client attach — so that VA MUST be free in win32k's
/// own VSpace (else win32k's own stack shadows it and the client pointer reads win32k's stack garbage).
pub const WIN32K_STACK_VADDR: u64 = 0x0000_0100_0D00_0000;
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
/// The real `SE_EXPORTS` struct (well-known SID pointers + privilege LUIDs) that win32k's `SeExports`
/// data-export cell points at, built by [`nt_security::se_exports::build_se_exports`]. Lives in DATA
/// page 0 (the old zeroed placeholder region, clear of the SeExports/Nls placeholders at +0x1C0/
/// +0x200). win32k reads only `SeAliasAdminsSid` (+0x110), off the interactive boot/paint path
/// (`IntCreateServiceSecurity`, non-interactive service window-station).
const WIN32K_SE_EXPORTS_VA: u64 = WIN32K_DATA_VADDR + 0x800;
/// The SID blob pool the `SE_EXPORTS` pointer members reference (DATA page 0, after the struct).
const WIN32K_SE_SID_POOL_VA: u64 = WIN32K_DATA_VADDR + 0xA00;
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
pub const SH_FONT_SIZE: u64 = 0x88; // in:  staged system-font (.ttf) byte size at FONTBUF_VADDR (u32)

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

/// The win32k NtUser/NtGdi shadow-SSDT base service number (`SSN >= 0x1000` selects the shadow SSDT).
pub const WIN32K_SERVICE_BASE: u64 = 0x1000;
/// `SSN 0x10FA` — the win32k service csrss's user32 client init drives through the connect path
/// (`NtUserProcessConnect`, RVA 0xc2ba0; the marshaled-buffer dispatch). Named for its historical
/// role in the bring-up; NOT `NtUserInitialize` (that is [`SSN_NT_USER_INITIALIZE_REAL`]).
pub const SSN_NT_USER_INITIALIZE: u64 = 0x10FA;
/// `SSN 0x125a` — the real `NtUserInitialize(dwWinVersion, hPowerRequestEvent, hMediaRequestEvent)`
/// (RVA 0xc41a0) winsrv's `UserServerDllInitialization` issues. Its `IntInitWin32PowerManagement`
/// does `ObReferenceObjectByHandle(hPowerRequestEvent, *ExEventObjectType)`; the dispatch loop
/// materializes real typed `Event` objects for the two event-handle args (see `dispatch_loop`).
pub const SSN_NT_USER_INITIALIZE_REAL: u64 = 0x125A;

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

/// co_IntInitializeDesktopGraphics RVA (identified via its L"DISPLAY" ref + the PDEVOBJ_lChangeDisplay
/// Settings(&gpmdev)/gbBaseVideo/EngpUpdateGraphicsDeviceList structure). NOTE: this is NO LONGER
/// invoked directly by the host — the eager SSN_INIT_DESKTOP_GFX scaffold that called it was RETIRED.
/// InitVideo/surface + the paint now run fully lazily: winlogon's first GUI DC-op drives
/// `co_IntGraphicsCheck(TRUE)` → `co_AddGuiApp` (win32k RVA 0x7a080, which bumps the `NrGuiAppsRunning`
/// counter at RVA 0x20be88 on the 0→1 transition) → this function. Kept only as a structural landmark.
pub const CO_INIT_DESKTOP_GFX_RVA: u64 = 0xfca10;

/// win32k `.data` global `gptiDesktopThread` (desktop.c:54) RVA. `IntGetAndReferenceClass(WC_DESKTOP,
/// bDesktopThread=TRUE)` (class.c:1457) reads it as the desktop thread's THREADINFO — NULL in our host
/// → the fault at RVA 0x50f94 (`mov rax,[gptiDesktopThread]; mov rax,[rax+0x58]` = pti->ppi). Derived
/// from the disasm at RVA 0x50f76 `mov rax,[rip+0x1ba5bb]` (0x50f7d + 0x1ba5bb). We point it at a
/// desktop-thread THREADINFO placeholder whose `ppi` (+0x58) is the hosted client's PROCESSINFO.
pub const GPTI_DESKTOP_THREAD_RVA: u64 = 0x20b538;
/// THREADINFO->ppi offset (confirmed by the disasm above: `mov rax,[rax+0x58]`).
const THREADINFO_PPI_OFF: u64 = 0x58;

/// win32k `.data` global `gpdeskInputDesktop` (desktop.c:52) RVA. `IntGetActiveDesktop()` returns it
/// (desktop.c:1287); `co_IntShowDesktop` (winsta.c:340) derefs `Desktop->pDeskInfo->spwnd` and faults
/// when it is NULL (RVA 0x6dc5c `mov rax,[rcx+8]`). It is written ONLY by `NtUserSwitchDesktop`
/// (desktop.c:3044) — winlogon-driven, never reached in our flow. Derived from the disasm at
/// NtUserSwitchDesktop RVA 0x6c2f8 `mov rax,[rip+0x19f229]` (0x6c2ff + 0x19f229) = the
/// `pdesk == gpdeskInputDesktop` compare (desktop.c:2995); it sits directly below ScreenDeviceContext
/// (0x20b530) and gptiDesktopThread (0x20b538). We no longer poke this global directly — the real
/// `NtUserSwitchDesktop` (RVA 0x6c140, driven from `create_winsta_and_desktop`) sets it after its full
/// handle-validation / winsta-locking / InputWindowStation guards; we only READ it here to report the
/// switch's effect.
pub const GPDESK_INPUT_DESKTOP_RVA: u64 = 0x20b528;

/// NtUserCreateWindowStation — SSDT idx 0x22f (w32ksvc64.h), RVA read from the registered SSDT.
pub const NT_USER_CREATE_WINDOW_STATION_RVA: u64 = 0xfa710;
/// NtUserCreateDesktop — SSDT idx 0x22d, calls IntCreateDesktop (RVA 0x657f0).
pub const NT_USER_CREATE_DESKTOP_RVA: u64 = 0x6b530;
/// NtUserSwitchDesktop — SSDT idx 0x288 (w32ksvc64.h), the AUTHENTIC setter of `gpdeskInputDesktop`
/// (desktop.c:2971→:3044). We drive it directly (instead of poking `gpdeskInputDesktop`) once the
/// desktop's `rpwinstaParent` + the `InputWindowStation` global are stood up (see below).
pub const NT_USER_SWITCH_DESKTOP_RVA: u64 = 0x6c140;
/// win32k `.data` global `InputWindowStation` (winsta.c:21) RVA — the interactive window station.
/// `NtUserSwitchDesktop` requires `pdesk->rpwinstaParent == InputWindowStation` (desktop.c:3015) or it
/// returns FALSE. Derived from the disasm at NtUserSwitchDesktop RVA 0x6c44e `mov rcx,[rip+0x19fc13]`
/// (0x6c455 + 0x19fc13). We set it to our created WINDOWSTATION body before the switch.
pub const INPUT_WINDOW_STATION_RVA: u64 = 0x20c068;
/// DESKTOP.rpwinstaParent offset (confirmed by the NtUserSwitchDesktop disasm: RVA 0x6c3b1
/// `mov rax,[rax+0x20]` = pdesk->rpwinstaParent, then [+0x20]=WINSTATION.Flags for the WSS_LOCKED
/// check; and RVA 0x6c281 `mov rcx,[pdesk+0x20]; cmp sessionId,[rcx]` = winsta->dwSessionId@0).
pub const DESKTOP_RPWINSTA_PARENT_OFF: u64 = 0x20;

/// SSN of NtUserCreateDesktop (WIN32K_SERVICE_BASE 0x1000 + SSDT idx 0x22d). When a hosted client
/// (winlogon) drives its own CreateWindowStation→CreateDesktop→SwitchDesktop chain, its
/// naturally-created DESKTOP objects come through the routed `dispatch_ssn` path; our Ob layer does
/// not populate `pdesk->rpwinstaParent` (the winsta→desktop parent linkage IntCreateDesktop would
/// set from the parse context), so we poke it after the create — exactly as the gfx-trigger's
/// `create_winsta_and_desktop` does for the Default desktop — else NtUserSwitchDesktop NULL-derefs it
/// (RVA 0x6c281→0x6c285). See the `dispatch_ssn` fixup.
pub const SSN_NT_USER_CREATE_DESKTOP: u64 = 0x122d;

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

/// A system font (arial.ttf) staged off disk into a buffer mapped into win32k's VSpace (both the
/// executive + win32k map the same frames here). At bring-up the host feeds these bytes to
/// win32k's `IntGdiAddFontMemResource` so the desktop-graphics font realize finds a real font (the
/// registry Fonts key is empty + `\SystemRoot\Fonts` doesn't exist, so no font loads naturally).
/// Own 2 MiB PT window at 0x06E0 (free in both VSpaces: after FRAMEBUFBUF 0x06C0, before AUX_PT 0x0700).
pub const FONTBUF_VADDR: u64 = 0x0000_0100_06E0_0000;
pub const FONTBUF_FRAMES: u64 = 64; // 256 KiB (arial.ttf = 180,144 B)
/// `IntGdiAddFontMemResource(PVOID Buffer, DWORD dwSize, PDWORD pNumAdded)` — win32k RVA. Found via
/// NtGdiAddFontMemResourceEx (SSDT idx 0x116 / RVA 0x124020): the SECOND internal call is
/// IntGdiAddFontMemResource (the first, 0x1cbd80, is the inlined memcpy for RtlCopyMemory). Verified
/// by disasm: ExAllocatePoolWithTag(PagedPool, dwSize, 'ETNF') → memcpy → SharedMem_Create →
/// Characteristics=0x30 (FR_PRIVATE|FR_NOT_ENUM) → IntGdiLoadFontByIndexFromMemory. Adds the font
/// FR_PRIVATE to the current process's private list, which TextIntRealizeFont searches (alongside
/// g_FontListHead) to find the system font.
pub const INT_GDI_ADD_FONT_MEM_RESOURCE_RVA: u64 = 0x12c840;

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

/// `NTSTATUS SeQueryAuthenticationIdToken(PACCESS_TOKEN Token, PLUID AuthenticationId)`.
///
/// The ONE Se* function on the boot/connect path (backlog item 3, Se→nt-security): win32k's
/// `GetProcessLuid` (→ `IntResolveDesktop` → `InitThreadCallback`, the per-thread win32k connect
/// callout) calls it while a GUI thread attaches; a failing/zero-LUID result aborts desktop
/// resolution. Model the SYSTEM subject (the init path runs as Local System): write the well-known
/// SYSTEM logon-session LUID + return STATUS_SUCCESS. Behavior-preserving — the prior `s_zero` stub
/// already returned SUCCESS(0); this additionally fills a genuine LUID
/// (`nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID`) into the caller's out-param.
extern "win64" fn s_se_query_authentication_id_token(_token: u64, luid_out: *mut u32) -> i32 {
    if !luid_out.is_null() {
        // SAFETY: luid_out is win32k's stack-local &LUID (2 x u32); the component stack is mapped.
        unsafe {
            write_unaligned(luid_out, nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_LOW);
            write_unaligned(
                luid_out.add(1),
                nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_HIGH as u32,
            );
        }
    }
    0 // STATUS_SUCCESS
}

/// A synthetic non-null SYSTEM primary-token marker stored in captured subject contexts. The host's
/// `SePrivilegeCheck` models the SYSTEM subject via `nt_security` `SYSTEM_PRIVILEGE_LUIDS` and never
/// dereferences this pointer; it exists only so a captured context has a non-null `PrimaryToken`.
const PH_SYSTEM_TOKEN: u64 = 0x0000_0000_5E5E_0018; // "Se" + S-1-5-18 (LocalSystem) marker

/// `void SeCaptureSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)`. Snapshot the caller's
/// security identity into `SubjectContext`. The win32k init/shutdown caller runs as Local System, so
/// capture the SYSTEM subject (no impersonation, PrimaryToken = the SYSTEM marker). Off the boot/paint
/// path (only `HasPrivilege` → `UserInitiateShutdown` calls it).
extern "win64" fn s_se_capture_subject_context(ctx: *mut u8) {
    if !ctx.is_null() {
        // SAFETY: ctx is win32k's stack-local SECURITY_SUBJECT_CONTEXT (0x20 bytes); stack is mapped.
        unsafe { nt_security::se_exports::capture_system_subject_context(ctx, PH_SYSTEM_TOKEN) };
    }
}

/// `void SeLockSubjectContext` / `SeUnlockSubjectContext` / `SeReleaseSubjectContext`
/// `(PSECURITY_SUBJECT_CONTEXT)`. In real NT these take/release the token reference lock and deref the
/// captured tokens; in this single-threaded, no-token-object host there is nothing to lock or free, so
/// they are genuine no-ops (the captured SYSTEM identity is const data). Kept as a distinct named
/// trampoline (not `s_zero`) so the Se surface is fully bound + auditable.
extern "win64" fn s_se_lock_subject_context(_ctx: u64) {}

/// `BOOLEAN SePrivilegeCheck(PPRIVILEGE_SET RequiredPrivileges, PSECURITY_SUBJECT_CONTEXT
/// SubjectContext, KPROCESSOR_MODE AccessMode)`. The real privilege-check algorithm (via
/// `nt_security::se_exports::se_privilege_check_raw`) over the SYSTEM subject's privileges: KernelMode
/// callers bypass; a UserMode check succeeds because the SYSTEM subject holds the required privilege
/// (e.g. `SeShutdownPrivilege` for win32k's `HasPrivilege` on the shutdown path — legitimately PASS,
/// not a bypass; an unprivileged subject would be DENIED). Off the boot/paint path.
extern "win64" fn s_se_privilege_check(required: *const u8, _ctx: u64, access_mode: u64) -> i32 {
    // KPROCESSOR_MODE: KernelMode == 0 (privilege checks are bypassed for kernel-mode callers).
    if access_mode == 0 || required.is_null() {
        return 1;
    }
    // SAFETY: required is win32k's PRIVILEGE_SET (stack/static); max 8 entries caps any over-read.
    let ok = unsafe {
        nt_security::se_exports::se_privilege_check_raw(
            required,
            nt_security::se_exports::SYSTEM_PRIVILEGE_LUIDS,
            8,
        )
    };
    ok as i32
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

// --- win32k Ob object layer (DESKTOP + WINDOWSTATION) ----------------------------------------
//
// win32k creates/opens real DESKTOP and WINDOWSTATION_OBJECT bodies through the ntoskrnl Ob* API
// (ObOpenObjectByName / ObCreateObject / ObInsertObject / ObReferenceObjectByHandle). Previously
// these all fell to `s_zero` (returned STATUS_SUCCESS but wrote no handle/object) so
// IntCreateDesktop got Context==FALSE and returned early WITHOUT building the desktop window graph.
// Backed by REAL object bodies (allocated from the win32k pool) + the handle→(type, body) registry
// that lives in `nt_object_manager::win32k_ob` (a raw-pointer, alloc-free, host-tested primitive),
// IntCreateDesktop advances past the Ob early-return into the window-manager graph
// (IntGetAndReferenceClass(WC_DESKTOP) etc.).
//
// The four trampolines below are THIN win64-ABI marshaling shims: they classify the type-object
// pointer win32k passes into an `ObKind`, allocate bodies from the win32k pool, drive the shared
// `ObHandleTable`, and write *Handle / *Context / *Object into win32k's memory. ALL object-manager
// semantics (handle minting, the registry, the create→insert latch, the single-instance
// window-station cache) live in the crate.
use nt_object_manager::win32k_ob::{
    init_desktop_body, ObHandleTable, ObKind, DESKTOPINFO_SIZE, DESKTOP_BODY_SIZE,
};

/// The single win32k object registry (single-threaded host; handle→(type, body) lives in the crate).
static mut OBJ_TABLE: ObHandleTable = ObHandleTable::new();

/// Classify the `OBJECT_TYPE` pointer win32k passed into an [`ObKind`] (`None` = an unrecognized
/// type). The pointer is the value held in win32k's imported `ExDesktopObjectType` /
/// `ExWindowStationObjectType` data cell — now the address of a **real** `OBJECT_TYPE` static (see
/// [`object_type_cell_value`] / [`nt_object_manager::object_type`]). Discrimination is delegated to
/// the host-tested crate, which compares against those static addresses.
fn classify_type(obj_type: u64) -> Option<ObKind> {
    nt_object_manager::win32k_ob::classify(obj_type)
}

/// Model a real `Event` object for a win32k-visible event `handle` (winsrv's power/media request
/// events). Allocates a genuine `KEVENT` (`nt_kernel_exec::kevent`, Synchronization / non-signalled)
/// from the win32k pool and registers it in [`OBJ_TABLE`] under the external handle value, so
/// [`s_ob_reference_object_by_handle`] resolves it to a typed `Event` (`ExEventObjectType`). A NULL
/// or already-modelled handle is a no-op (the registry is idempotent). Runs in the win32k component
/// (its pool + `OBJ_TABLE` are live here).
unsafe fn register_event_object(handle: u64) {
    use nt_object_manager::win32k_ob::ObKind;
    let table = &mut *core::ptr::addr_of_mut!(OBJ_TABLE);
    if handle == 0 || matches!(table.lookup(handle), Some((ObKind::Event, _))) {
        return; // NULL, or already modelled (idempotent — don't leak a second KEVENT).
    }
    let body = pool_alloc(nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64);
    if body == 0 {
        return; // pool exhausted — leave unmodelled (ObRefByHandle will report no object).
    }
    nt_kernel_exec::kevent::init_kevent(
        body as *mut u8,
        nt_kernel_exec::kevent::EventKind::Synchronization,
        false,
    );
    table.register_event(handle, body);
}

/// Allocate + zero a DESKTOP body (with a DESKTOPINFO hung off `pDeskInfo`@+0x08) from the win32k
/// pool. Enough to satisfy IntCreateDesktop up to IntGetAndReferenceClass(WC_DESKTOP); the desktop
/// heap + full DESKTOPINFO population is the following increment's work. The body layout lives with
/// the object-type definition in the crate ([`init_desktop_body`]).
unsafe fn alloc_desktop_body() -> u64 {
    let desk = pool_alloc(DESKTOP_BODY_SIZE); // zeroed by the arena
    if desk == 0 {
        return 0;
    }
    let dinfo = pool_alloc(DESKTOPINFO_SIZE); // DESKTOPINFO + szDesktopName tail, zeroed
    if dinfo != 0 {
        init_desktop_body(desk as *mut u8, dinfo); // DESKTOP.pDeskInfo
    }
    desk
}

/// `NTSTATUS ObOpenObjectByName(POBJECT_ATTRIBUTES, POBJECT_TYPE, KPROCESSOR_MODE, PACCESS_STATE,
/// ACCESS_MASK DesiredAccess, PVOID ParseContext, PHANDLE Handle)`.
/// - DESKTOP (ParseContext != NULL = a create-open): allocate a real DESKTOP, write *Handle, set
///   *ParseContext = TRUE (Context — "the object was created"), return SUCCESS. This is what makes
///   IntCreateDesktop proceed past its `if (Context == FALSE) goto Quit` early-return.
/// - WINDOWSTATION (IntCreateWindowStation's "try open existing", ParseContext == NULL): if we have
///   already created the input winsta, OPEN it (write its handle, SUCCESS); otherwise report
///   STATUS_OBJECT_NAME_NOT_FOUND so IntCreateWindowStation falls through to ObCreateObject/Insert.
extern "win64" fn s_ob_open_object_by_name(
    _object_attributes: u64,
    obj_type: u64,
    _access_mode: u64,
    _access_state: u64,
    _desired_access: u64,
    parse_context: u64,
    handle: *mut u64,
) -> i32 {
    unsafe {
        let table = &mut *core::ptr::addr_of_mut!(OBJ_TABLE);
        match classify_type(obj_type) {
            Some(ObKind::Desktop) => {
                let body = alloc_desktop_body();
                if body == 0 {
                    return 0xC000_009Au32 as i32; // STATUS_INSUFFICIENT_RESOURCES
                }
                let h = table.register(ObKind::Desktop, body);
                if !handle.is_null() {
                    write_unaligned(handle, h);
                }
                if parse_context != 0 {
                    write_volatile(parse_context as *mut u8, 1); // Context = TRUE (object created)
                }
                0
            }
            Some(ObKind::WindowStation) => {
                let cached = table.cached_winsta_handle();
                if cached != 0 {
                    if !handle.is_null() {
                        write_unaligned(handle, cached);
                    }
                    if parse_context != 0 {
                        write_volatile(parse_context as *mut u8, 0); // opened existing, not created
                    }
                    return 0;
                }
                // No existing winsta → force IntCreateWindowStation's create path.
                STATUS_OBJECT_NAME_NOT_FOUND
            }
            // Unknown object type: preserve the old benign behaviour (success, no handle).
            _ => 0,
        }
    }
}

/// `NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode, POBJECT_TYPE ObjectType, POBJECT_ATTRIBUTES,
/// KPROCESSOR_MODE OwnerMode, PVOID ParseContext, ULONG ObjectBodySize, ULONG PagedCharge,
/// ULONG NonPagedCharge, PVOID *Object)` — allocate a zeroed object body of ObjectBodySize from the
/// win32k pool, write *Object, and latch (kind, body) for the following ObInsertObject.
extern "win64" fn s_ob_create_object(
    _probe_mode: u64,
    obj_type: u64,
    _object_attributes: u64,
    _owner_mode: u64,
    _parse_context: u64,
    body_size: u64,
    _paged: u64,
    _nonpaged: u64,
    object_out: *mut u64,
) -> i32 {
    unsafe {
        let size = (body_size as u32 as u64).max(0x40);
        let body = pool_alloc(size);
        if body == 0 {
            return 0xC000_009Au32 as i32;
        }
        let table = &mut *core::ptr::addr_of_mut!(OBJ_TABLE);
        let kind = classify_type(obj_type).unwrap_or(ObKind::Other);
        table.latch_pending(kind, body);
        if !object_out.is_null() {
            write_unaligned(object_out, body);
        }
        0
    }
}

/// `NTSTATUS ObInsertObject(PVOID Object, PACCESS_STATE, ACCESS_MASK, ULONG ObjectPointerBias,
/// PVOID *NewObject, PHANDLE Handle)` — register the (latched) object under a fresh handle, write
/// *Handle (+ *NewObject if requested).
extern "win64" fn s_ob_insert_object(
    object: u64,
    _access_state: u64,
    _desired_access: u64,
    _bias: u64,
    new_object: *mut u64,
    handle: *mut u64,
) -> i32 {
    unsafe {
        let table = &mut *core::ptr::addr_of_mut!(OBJ_TABLE);
        let h = table.insert_pending(object);
        if !handle.is_null() {
            write_unaligned(handle, h);
        }
        if !new_object.is_null() {
            write_unaligned(new_object, object);
        }
        0
    }
}

/// `STATUS_OBJECT_TYPE_MISMATCH` — `ObReferenceObjectByHandle` ExpectedType check failed.
const STATUS_OBJECT_TYPE_MISMATCH: i32 = 0xC000_0024u32 as i32;

/// `NTSTATUS ObReferenceObjectByHandle(HANDLE, ACCESS_MASK, POBJECT_TYPE ObjectType, KPROCESSOR_MODE,
/// PVOID *Object, ...)` — resolve a handle to its object, **enforcing `ObjectType`** (real NT
/// semantics, `references/nt5/base/ntos/ob/obref.c`): a non-NULL `ObjectType` that does not match the
/// referenced object's type fails with `STATUS_OBJECT_TYPE_MISMATCH` and hands back no object; a NULL
/// `ObjectType` is polymorphic (any type — e.g. `NtClose`/`NtQueryObject`).
///
/// A registered win32k object handle → its real body, checked against its [`ObKind`] via
/// [`nt_object_manager::win32k_ob::object_type_matches`]:
///  - `DESKTOP` / `WINDOWSTATION` (from the `Ob*` create path);
///  - `Event` (`ExEventObjectType`) — winsrv's power/media request events, modeled as real `KEVENT`
///    objects when `NtUserInitialize` receives their handles (see [`register_event_object`]).
///
/// The only unregistered handle we resolve is win32k's process-connect handle ([`FAKE_PROCESS_HANDLE`])
/// → the current EPROCESS (`PsProcessType`). Every other typed reference to an unregistered handle is
/// enforced honestly (`STATUS_OBJECT_TYPE_MISMATCH`) — no fake-EPROCESS rubber-stamp; a future win32k
/// path that needs such an object should MODEL it (as the Event path now does).
extern "win64" fn s_ob_reference_object_by_handle(
    handle: u64,
    _access: u64,
    obj_type: u64,
    _mode: u64,
    object_out: *mut u64,
) -> i32 {
    let table = unsafe { &*core::ptr::addr_of!(OBJ_TABLE) };
    let obj = match table.lookup(handle) {
        Some((kind, body)) => {
            if !nt_object_manager::win32k_ob::object_type_matches(kind, obj_type) {
                ob_type_mismatch_trace(handle, obj_type, b"win32k-obj");
                return STATUS_OBJECT_TYPE_MISMATCH;
            }
            body
        }
        None => {
            let process_ty = nt_object_manager::object_type::process_object_type_addr();
            if handle == FAKE_PROCESS_HANDLE {
                // win32k's process-connect handle → the current EPROCESS; enforce a specific
                // ExpectedType against PsProcessType (NULL is polymorphic).
                if obj_type != 0 && obj_type != process_ty {
                    ob_type_mismatch_trace(handle, obj_type, b"process-connect");
                    return STATUS_OBJECT_TYPE_MISMATCH;
                }
                PH_EPROCESS_VA
            } else if obj_type == 0 || obj_type == process_ty {
                // A polymorphic (NULL) or process-typed reference to some other unregistered handle →
                // the EPROCESS fallback (unchanged; no modeled object to verify against).
                PH_EPROCESS_VA
            } else {
                // A SPECIFIC non-process ExpectedType against an unregistered handle. Every modeled
                // typed object resolves above; reaching here is a real type requirement we don't model
                // — enforce honestly (this is where the Event fake used to rubber-stamp a fake
                // EPROCESS; that path is now a real modeled Event).
                ob_type_mismatch_trace(handle, obj_type, b"unmodeled");
                return STATUS_OBJECT_TYPE_MISMATCH;
            }
        }
    };
    if !object_out.is_null() {
        unsafe { write_unaligned(object_out, obj) };
    }
    0
}

/// Diagnostic for an `ObReferenceObjectByHandle` ExpectedType mismatch — prints the handle, the
/// (unexpected) `ObjectType` pointer, and which known type statics it is/ isn't, so a gate mismatch
/// can be classified (polymorphic call site that should pass NULL vs a genuine type confusion).
fn ob_type_mismatch_trace(handle: u64, obj_type: u64, which: &[u8]) {
    unsafe {
        use nt_object_manager::object_type as ot;
        print_str(b"[win32k-host] ObRefByHandle TYPE_MISMATCH on ");
        print_str(which);
        print_str(b" handle=0x");
        print_hex(handle as u32);
        print_str(b" expected_type=0x");
        print_hex((obj_type >> 32) as u32);
        print_hex(obj_type as u32);
        let tag: &[u8] = if obj_type == ot::desktop_object_type_addr() {
            b" (=Desktop)"
        } else if obj_type == ot::window_station_object_type_addr() {
            b" (=WindowStation)"
        } else if obj_type == ot::process_object_type_addr() {
            b" (=Process)"
        } else if obj_type == ot::thread_object_type_addr() {
            b" (=Thread)"
        } else if obj_type == ot::event_object_type_addr() {
            b" (=Event)"
        } else if obj_type == ot::port_object_type_addr() {
            b" (=Port)"
        } else {
            b" (=unknown)"
        };
        print_str(tag);
        print_str(b"\n");
    }
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

/// `ULONG vDbgPrintExWithPrefix(PCCH Prefix, ULONG ComponentId, ULONG Level, PCCH Format,
/// va_list arglist)` — the real DbgPrintEx backend. win64: rcx/rdx/r8/r9 + the 5th arg
/// (`va_list`, a pointer to the argument array) from the stack. Prints the prefix then the
/// `%`-substituted format via the host-tested `nt_kernel_exec::dbg` formatter, so win32k's
/// `DPRINT`/`DbgPrintEx` diagnostics finally render substituted (was an `s_zero` no-op).
extern "win64" fn s_vdbg_print_ex_with_prefix(
    prefix: u64,
    _component: u64,
    _level: u64,
    fmt: u64,
    va_list: u64,
) -> u32 {
    print_str(b"[win32k dbg] ");
    unsafe {
        if prefix != 0 {
            let mut i = 0u64;
            while i < 64 {
                let c = read_volatile((prefix + i) as *const u8);
                if c == 0 {
                    break;
                }
                debug_put_char(c);
                i += 1;
            }
        }
        if fmt != 0 {
            let mut fbuf = [0u8; 256];
            let mut flen = 0usize;
            while flen < 255 {
                let c = read_volatile((fmt + flen as u64) as *const u8);
                if c == 0 {
                    break;
                }
                fbuf[flen] = c;
                flen += 1;
            }
            let mut k = 0u64;
            let mut next_arg = || {
                let v = if va_list != 0 {
                    unsafe { read_volatile((va_list + k * 8) as *const u64) }
                } else {
                    0
                };
                k += 1;
                v
            };
            let mut read_cstr = |ptr: u64, buf: &mut [u8]| -> usize {
                let mut n = 0usize;
                while n < buf.len() {
                    let c = unsafe { read_volatile((ptr + n as u64) as *const u8) };
                    if c == 0 {
                        break;
                    }
                    buf[n] = c;
                    n += 1;
                }
                n
            };
            nt_kernel_exec::dbg::format_dbg(
                &fbuf[..flen],
                &mut next_arg,
                &mut read_cstr,
                &mut |b| debug_put_char(b),
            );
        }
    }
    print_str(b"\n");
    0
}

// --- CRT + misc ntoskrnl trampolines dxg.sys imports -----------------------------------------

/// `void* memcpy(void* dst, const void* src, size_t n)`.
// memcpy / memmove / memset are the pure, driver-agnostic byte-loop primitives —
// shared with the FSD class in [`crate::ntoskrnl_shared`] (registered by name below).

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

use nt_kernel_exec::rtl_atom;

/// The single arena backing every atom table this component hands out (`gAtomTable` +
/// per-window-station tables). Lazily pool-allocated on the first `RtlCreateAtomTable`; each table
/// is a distinct sub-region so class atoms (global table) and global atoms (winsta tables) don't
/// collide. Each arena is 64 KiB (≈370 entries — ample for the system classes + a few user atoms).
const ATOM_ARENA_BYTES: u64 = 0x10000;

/// `NTSTATUS RtlCreateAtomTable(ULONG TableSize, PRTL_ATOM_TABLE* AtomTable)`. Pool-allocate an
/// arena, lay a fresh table over it, write `*AtomTable`. Idempotent if `*AtomTable` already set
/// (matches ReactOS sdk/lib/rtl/atom.c). This is what populates win32k's `gAtomTable`
/// (session.c:20 `InitSessionImpl`), previously null under the `s_zero` stub.
extern "win64" fn s_rtl_create_atom_table(_size: u32, out_table: *mut u64) -> i32 {
    if out_table.is_null() {
        return rtl_atom::status::INVALID_PARAMETER as i32;
    }
    unsafe {
        if read_unaligned(out_table) != 0 {
            return rtl_atom::status::SUCCESS as i32; // already created
        }
        let arena = pool_alloc(ATOM_ARENA_BYTES);
        if arena == 0 {
            return rtl_atom::status::NO_MEMORY as i32;
        }
        let table = rtl_atom::create(arena as *mut u8, ATOM_ARENA_BYTES as usize);
        if table.is_null() {
            return rtl_atom::status::NO_MEMORY as i32;
        }
        write_unaligned(out_table, table as u64);
    }
    rtl_atom::status::SUCCESS as i32
}
/// `NTSTATUS RtlAddAtomToAtomTable(PRTL_ATOM_TABLE, PWSTR AtomName, PRTL_ATOM* Atom)`.
extern "win64" fn s_rtl_add_atom_to_atom_table(table: u64, name: u64, out: *mut u16) -> i32 {
    unsafe { rtl_atom::add(table as *mut u8, name as *const u16, out) as i32 }
}
/// `NTSTATUS RtlLookupAtomInAtomTable(PRTL_ATOM_TABLE, PWSTR AtomName, PRTL_ATOM* Atom)`.
extern "win64" fn s_rtl_lookup_atom_in_atom_table(table: u64, name: u64, out: *mut u16) -> i32 {
    unsafe { rtl_atom::lookup(table as *const u8, name as *const u16, out) as i32 }
}
/// `NTSTATUS RtlDeleteAtomFromAtomTable(PRTL_ATOM_TABLE, RTL_ATOM Atom)`.
extern "win64" fn s_rtl_delete_atom_from_atom_table(table: u64, atom: u32) -> i32 {
    unsafe { rtl_atom::delete(table as *mut u8, atom as u16) as i32 }
}
/// `NTSTATUS RtlPinAtomInAtomTable(PRTL_ATOM_TABLE, RTL_ATOM Atom)`.
extern "win64" fn s_rtl_pin_atom_in_atom_table(table: u64, atom: u32) -> i32 {
    unsafe { rtl_atom::pin(table as *mut u8, atom as u16) as i32 }
}
/// `NTSTATUS RtlQueryAtomInAtomTable(PRTL_ATOM_TABLE, RTL_ATOM, PULONG RefCount, PULONG PinCount,
/// PWSTR AtomName, PULONG NameLength)`.
extern "win64" fn s_rtl_query_atom_in_atom_table(
    table: u64,
    atom: u32,
    ref_count: *mut u32,
    pin_count: *mut u32,
    name: u64,
    name_len: *mut u32,
) -> i32 {
    unsafe {
        rtl_atom::query(
            table as *const u8,
            atom as u16,
            ref_count,
            pin_count,
            name as *mut u16,
            name_len,
        ) as i32
    }
}
/// `NTSTATUS RtlDestroyAtomTable(PRTL_ATOM_TABLE)` — no-op success (the pool arena is never freed).
extern "win64" fn s_rtl_destroy_atom_table(_table: u64) -> i32 {
    rtl_atom::status::SUCCESS as i32
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

// wcslen is a pure primitive — shared in [`crate::ntoskrnl_shared`] (bound by name below).

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

/// win32k's KeGetCurrentIrql helper RVA — `mov rax, cr8` (bytes 44 0F 20 C0) followed by `ret`. The
/// unique CR8 access in the image (verified by opcode scan).
const KE_GET_CURRENT_IRQL_RVA: u64 = 0x305c0;

/// Patch win32k's inlined KeGetCurrentIrql (`mov rax,cr8`) to `xor rax,rax; nop` so it returns
/// PASSIVE_LEVEL (0) instead of executing the CPL-0-only CR8 read (which #GPs in our user-mode
/// component). Runs in `load_into` while win32k is mapped RW in the executive. Verifies the exact
/// bytes first (44 0F 20 C0) so a future rebuild that moves the helper fails loudly rather than
/// corrupting an unrelated instruction.
unsafe fn patch_ke_get_current_irql() {
    let p = WIN32K_CODE_VA + KE_GET_CURRENT_IRQL_RVA;
    if read_volatile(p as *const u8) == 0x44
        && read_volatile((p + 1) as *const u8) == 0x0F
        && read_volatile((p + 2) as *const u8) == 0x20
        && read_volatile((p + 3) as *const u8) == 0xC0
    {
        write_volatile(p as *mut u8, 0x48); // xor rax, rax
        write_volatile((p + 1) as *mut u8, 0x31);
        write_volatile((p + 2) as *mut u8, 0xC0);
        write_volatile((p + 3) as *mut u8, 0x90); // nop (preserve the following ret)
    } else {
        print_str(b"[win32k] WARN: KeGetCurrentIrql cr8 bytes not found at RVA 0x305c0\n");
    }
}

// --- win32k -> client user-mode callback bridge (KeUserModeCallback) --------------------------
//
// `NTSTATUS KeUserModeCallback(ULONG ApiNumber, PVOID InputBuffer, ULONG InputLength,
//                              PVOID *OutputBuffer, PULONG OutputLength)`
//
// win32k's desktop-init tail (co_IntInitializeDesktopGraphics, winsta.c:329-335) calls back into the
// user32 CLIENT via this ntoskrnl export for cursor/icon/menu resource setup:
//   ApiNumber 3  USER32_CALLBACK_LOADDEFAULTCURSORS (co_IntLoadDefaultCursors) → *Out = &HCURSOR
//   ApiNumber 11 USER32_CALLBACK_SETWNDICONS        (co_IntSetWndIcons)        → *Out = SETWNDICONS_CALLBACK_ARGUMENTS
//   ApiNumber 15 USER32_CALLBACK_SETOBM             (co_IntSetupOBM/MenuInit)  → *Out = SETOBM_CALLBACK_ARGUMENTS
// In real Windows the callback runs user32's KiUserCallbackDispatcher on the CLIENT stack; our win32k
// is a separate component. Each of these init callbacks returns a structure of HANDLES that win32k
// tolerates all-NULL (IntLoadSystenIcons(NULL)/RtlCopyMemory of zeros are safe no-ops), so we
// SYNTHESIZE structurally-valid, zeroed output here (a real IAT CALL/return — no RIP redirect
// needed). This is the callback EFFECT faithfully: a client that found no custom resources.
//
// Contract: allocate a zeroed output buffer sized to max(caller's *OutputLength, InputLength, 8),
// point *OutputBuffer at it, set *OutputLength, return STATUS_SUCCESS. (The caller pre-seeds
// *OutputLength with the exact struct size it will RtlMoveMemory back, so honour it.)
const USER32_CB_LOADDEFAULTCURSORS: u32 = 3;
extern "win64" fn s_ke_user_mode_callback(
    api: u32,
    _input: u64,
    input_len: u32,
    out_buf: *mut u64,
    out_len: *mut u32,
) -> i32 {
    unsafe {
        let want = if out_len.is_null() { 0 } else { read_volatile(out_len) };
        let mut size = want as u64;
        if (input_len as u64) > size {
            size = input_len as u64;
        }
        if size < 8 {
            size = 8;
        }
        // Round up for safety headroom (some client dispatchers over-copy).
        size = (size + 15) & !15;
        let buf = pool_alloc(size);
        print_str(b"[win32k-host] KeUserModeCallback api=");
        print_hex(api);
        print_str(b" inlen=0x");
        print_hex(input_len);
        print_str(b" outlen=0x");
        print_hex(want);
        print_str(b" -> buf=0x");
        print_hex(buf as u32);
        print_str(b"\n");
        if buf == 0 {
            return 0xC000_009Au32 as i32; // STATUS_INSUFFICIENT_RESOURCES
        }
        // Zero the buffer (all-NULL handles: gDesktopCursor=NULL, icons=NULL, oembmi=0 — safe).
        let mut i = 0u64;
        while i < size {
            write_volatile((buf + i) as *mut u64, 0);
            i += 8;
        }
        // LOADDEFAULTCURSORS: *ResultPointer must be an HCURSOR* → first 8 bytes = the HCURSOR (NULL).
        // (Already zeroed; the buffer itself is the &HCURSOR win32k reads via `mov rax,[rax]`.)
        let _ = api == USER32_CB_LOADDEFAULTCURSORS;
        if !out_buf.is_null() {
            write_volatile(out_buf, buf);
        }
        if !out_len.is_null() {
            write_volatile(out_len, size as u32);
        }
        0 // STATUS_SUCCESS
    }
}

/// Registration-driven export resolution. The executive binds its machine-code trampoline VAs by
/// import name into the SHARED, driver-agnostic `nt-compat-exports` [`DriverExportRegistry`] — the
/// SAME registry mechanism every hosted `.sys` (FSD/KMDF/Subsystem) resolves its IAT through; the
/// loader resolves win32k's IAT via [`export_addr`]. The win32k-specific data (which imports, the
/// data-cell exports) stays in `nt-compat-exports::win32k_resolve`; only the resolution MECHANISM
/// is now unified onto the one registry (the parallel `Win32kExportRegistry` struct was retired).
static mut WIN32K_EXPORTS: DriverExportRegistry = DriverExportRegistry::new();
static mut WIN32K_EXPORTS_READY: bool = false;

/// Bind the first-batch trampolines into [`WIN32K_EXPORTS`]. Idempotent (`bind` updates in place),
/// so it is safe to call from any loader (win32k / dxg / driver) regardless of order; each bound VA
/// is IDENTICAL to what the `match` in [`export_addr`] would return, so resolution is unchanged.
fn register_trampolines() {
    // SAFETY: single-threaded executive; the registry is only ever touched here + in export_addr.
    let reg = unsafe { &mut *core::ptr::addr_of_mut!(WIN32K_EXPORTS) };
    // pool (Driver Host arena)
    reg.bind("ExAllocatePoolWithTag", s_ex_alloc_pool_with_tag as usize as u64);
    reg.bind("ExAllocatePool", s_ex_alloc_pool as usize as u64);
    reg.bind("ExAllocatePoolWithQuotaTag", s_ex_alloc_pool_quota as usize as u64);
    reg.bind("ExFreePoolWithTag", s_ex_free_pool_with_tag as usize as u64);
    reg.bind("ExFreePool", s_ex_free_pool_with_tag as usize as u64);
    // RTL atom table (nt_kernel_exec::rtl_atom)
    reg.bind("RtlCreateAtomTable", s_rtl_create_atom_table as usize as u64);
    reg.bind("RtlAddAtomToAtomTable", s_rtl_add_atom_to_atom_table as usize as u64);
    reg.bind("RtlLookupAtomInAtomTable", s_rtl_lookup_atom_in_atom_table as usize as u64);
    reg.bind("RtlDeleteAtomFromAtomTable", s_rtl_delete_atom_from_atom_table as usize as u64);
    reg.bind("RtlPinAtomInAtomTable", s_rtl_pin_atom_in_atom_table as usize as u64);
    reg.bind("RtlQueryAtomInAtomTable", s_rtl_query_atom_in_atom_table as usize as u64);
    reg.bind("RtlDestroyAtomTable", s_rtl_destroy_atom_table as usize as u64);
    // Ob object layer (nt-object-manager)
    reg.bind("ObReferenceObjectByHandle", s_ob_reference_object_by_handle as usize as u64);
    reg.bind("ObOpenObjectByName", s_ob_open_object_by_name as usize as u64);
    reg.bind("ObCreateObject", s_ob_create_object as usize as u64);
    reg.bind("ObInsertObject", s_ob_insert_object as usize as u64);
    // --- batch 2: RTL heap (win32k session heap) ---
    reg.bind("RtlCreateHeap", s_rtl_create_heap as usize as u64);
    reg.bind("RtlAllocateHeap", s_rtl_allocate_heap as usize as u64);
    reg.bind("RtlFreeHeap", s_rtl_free_heap as usize as u64);
    // --- batch 2: RTL_BITMAP (GDI pool slot allocator) ---
    reg.bind("RtlInitializeBitMap", s_rtl_initialize_bitmap as usize as u64);
    reg.bind("RtlClearAllBits", s_rtl_clear_all_bits as usize as u64);
    reg.bind("RtlSetAllBits", s_rtl_set_all_bits as usize as u64);
    reg.bind("RtlFindClearBitsAndSet", s_rtl_find_clear_bits_and_set as usize as u64);
    reg.bind("RtlNumberOfSetBits", s_rtl_number_of_set_bits as usize as u64);
    reg.bind("RtlTestBit", s_rtl_test_bit as usize as u64);
    reg.bind("RtlSetBit", s_rtl_set_bit as usize as u64);
    reg.bind("RtlClearBit", s_rtl_clear_bit as usize as u64);
    reg.bind("RtlSetBits", s_rtl_set_bits as usize as u64);
    reg.bind("RtlClearBits", s_rtl_clear_bits as usize as u64);
    reg.bind("RtlAreBitsClear", s_rtl_are_bits_clear as usize as u64);
    // --- batch 2: RTL string init ---
    reg.bind("RtlInitUnicodeString", s_rtl_init_unicode_string as usize as u64);
    reg.bind("RtlInitAnsiString", s_rtl_init_ansi_string as usize as u64);
    reg.bind("RtlInitEmptyUnicodeString", s_rtl_init_empty_unicode_string as usize as u64);
    reg.bind("RtlCopyUnicodeString", s_rtl_copy_unicode_string as usize as u64);
    reg.bind("RtlAppendUnicodeToString", s_rtl_append_unicode_to_string as usize as u64);
    reg.bind("RtlCreateUnicodeString", s_rtl_create_unicode_string as usize as u64);
    reg.bind("RtlMultiByteToUnicodeN", s_rtl_multibyte_to_unicode_n as usize as u64);
    reg.bind("wcslen", s_wcslen as usize as u64);
    reg.bind("_wcsnicmp", s_wcsnicmp as usize as u64);
    reg.bind("wcsnicmp", s_wcsnicmp as usize as u64);
    // --- batch 2: real va_list DbgPrintEx backend (nt_kernel_exec::dbg) ---
    reg.bind("vDbgPrintExWithPrefix", s_vdbg_print_ex_with_prefix as usize as u64);
    // --- batch 3: section objects (nt-kernel-exec session_section) ---
    reg.bind("MmCreateSection", s_mm_create_section as usize as u64);
    reg.bind("MmMapViewInSessionSpace", s_mm_map_view as usize as u64);
    reg.bind("MmMapViewInSystemSpace", s_mm_map_view as usize as u64);
    reg.bind("MmMapViewOfSection", s_mm_map_view_of_section as usize as u64);
    // --- batch 3: lookaside-list init (nt_kernel_exec::init_general_lookaside) ---
    reg.bind("ExInitializePagedLookasideList", s_ex_init_paged_lookaside as usize as u64);
    reg.bind("ExInitializeNPagedLookasideList", s_ex_init_npaged_lookaside as usize as u64);
    // --- batch 3: Zw virtual-memory / registry / file (canned; see backlog) ---
    reg.bind("ZwAllocateVirtualMemory", s_zw_allocate_virtual_memory as usize as u64);
    reg.bind("NtAllocateVirtualMemory", s_zw_allocate_virtual_memory as usize as u64);
    reg.bind("ZwFreeVirtualMemory", s_zw_free_virtual_memory as usize as u64);
    reg.bind("NtFreeVirtualMemory", s_zw_free_virtual_memory as usize as u64);
    reg.bind("ZwSetSystemInformation", s_zw_set_system_information as usize as u64);
    reg.bind("NtSetSystemInformation", s_zw_set_system_information as usize as u64);
    reg.bind("ZwOpenFile", s_zw_open_file_fail as usize as u64);
    reg.bind("NtOpenFile", s_zw_open_file_fail as usize as u64);
    reg.bind("ZwOpenKey", s_zw_open_key as usize as u64);
    reg.bind("NtOpenKey", s_zw_open_key as usize as u64);
    reg.bind("ZwQueryValueKey", s_zw_query_value_key as usize as u64);
    reg.bind("NtQueryValueKey", s_zw_query_value_key as usize as u64);
    // --- batch 3: CRT mem intrinsics (dxg.sys imports) ---
    reg.bind("memcpy", s_memcpy as usize as u64);
    reg.bind("RtlCopyMemory", s_memcpy as usize as u64);
    reg.bind("memmove", s_memmove as usize as u64);
    reg.bind("RtlMoveMemory", s_memmove as usize as u64);
    reg.bind("memset", s_memset as usize as u64);
    reg.bind("RtlFillMemory", s_memset as usize as u64);
    // --- batch 4: Ps identity + per-process win32-slots (set by win32k's process callout) ---
    reg.bind("PsGetCurrentProcessId", s_current_process_id as usize as u64);
    reg.bind("PsGetCurrentThreadProcessId", s_current_process_id as usize as u64);
    reg.bind("IoGetCurrentProcess", s_current_process as usize as u64);
    reg.bind("PsGetCurrentProcess", s_current_process as usize as u64);
    reg.bind("PsGetCurrentThread", s_current_thread as usize as u64);
    reg.bind("KeGetCurrentThread", s_current_thread as usize as u64);
    reg.bind("PsGetCurrentProcessWin32Process", s_get_win32process as usize as u64);
    reg.bind("PsGetProcessWin32Process", s_get_win32process as usize as u64);
    reg.bind("PsGetCurrentThreadWin32Thread", s_get_win32thread as usize as u64);
    reg.bind("PsGetThreadWin32Thread", s_get_win32thread as usize as u64);
    reg.bind("PsSetProcessWin32Process", s_set_win32process as usize as u64);
    reg.bind("PsSetThreadWin32Thread", s_set_win32thread as usize as u64);
    reg.bind("PsEstablishWin32Callouts", s_establish_win32_callouts as usize as u64);
    // --- batch 4: misc scalars ---
    reg.bind("IoGetDeviceObjectPointer", s_io_get_device_object_pointer as usize as u64);
    reg.bind("KeUserModeCallback", s_ke_user_mode_callback as usize as u64);
    reg.bind("KeAddSystemServiceTable", s_ke_add_system_service_table as usize as u64);
    reg.bind("DbgPrint", s_dbg_print as usize as u64);
    // --- batch 4: resource / lock acquire → BOOLEAN TRUE (single-threaded host: always acquired) ---
    reg.bind("ExAcquireResourceExclusiveLite", s_true as usize as u64);
    reg.bind("ExAcquireResourceSharedLite", s_true as usize as u64);
    reg.bind("ExIsResourceAcquiredExclusiveLite", s_true as usize as u64);
    reg.bind("ExIsResourceAcquiredSharedLite", s_true as usize as u64);
    reg.bind("ExEnterCriticalRegionAndAcquireResourceShared", s_true as usize as u64);
    reg.bind("ExEnterCriticalRegionAndAcquireResourceExclusive", s_true as usize as u64);
    reg.bind("ExEnterCriticalRegionAndAcquireFastMutexUnsafe", s_true as usize as u64);
    reg.bind("ExfAcquirePushLockExclusive", s_true as usize as u64);
    reg.bind("ExfTryToWakePushLock", s_true as usize as u64);
    reg.bind("KeSetKernelStackSwapEnable", s_true as usize as u64);
    reg.bind("ExGetPreviousMode", s_true as usize as u64);
    // --- batch 5: Se → nt-security (backlog item 3, COMPLETE — all 7 Se imports real) ---
    // SeQueryAuthenticationIdToken is the only Se* on the boot/connect path (win32k GetProcessLuid);
    // return the SYSTEM auth LUID + SUCCESS. The SeExports DATA cell resolves to a real SE_EXPORTS
    // (built in load_into). The subject-context/privilege group (SeCaptureSubjectContext / Se{Lock,
    // Unlock,Release}SubjectContext / SePrivilegeCheck) is win32k shutdown-path only (HasPrivilege →
    // UserInitiateShutdown, off the boot/paint path): capture models the SYSTEM subject, lock/unlock/
    // release are no-ops (single-threaded, no token objects), and SePrivilegeCheck runs the REAL
    // privilege-check algorithm over the SYSTEM privilege set → legitimately PASSES for SeShutdown.
    reg.bind(
        "SeQueryAuthenticationIdToken",
        s_se_query_authentication_id_token as usize as u64,
    );
    reg.bind(
        "SeCaptureSubjectContext",
        s_se_capture_subject_context as usize as u64,
    );
    reg.bind(
        "SeLockSubjectContext",
        s_se_lock_subject_context as usize as u64,
    );
    reg.bind(
        "SeUnlockSubjectContext",
        s_se_lock_subject_context as usize as u64,
    );
    reg.bind(
        "SeReleaseSubjectContext",
        s_se_lock_subject_context as usize as u64,
    );
    reg.bind("SePrivilegeCheck", s_se_privilege_check as usize as u64);
    // --- batch 4: DATA EXPORTS folded in as data-cell resolutions. The IAT slot points at the
    // cell (WIN32K_DATA_VADDR page 1); load_into writes each cell's VALUE from DATA_EXPORTS. The
    // 8 object-type/Se/Nls cells still hold placeholder pointers (backlog: real OBJECT_TYPEs);
    // the 3 Mm cells hold architectural x64 constants. Contract declared in
    // nt_compat_exports::win32k_resolve::WIN32K_DATA_EXPORTS.
    let mut di = 0usize;
    while di < DATA_EXPORTS.len() {
        reg.bind(DATA_EXPORTS[di].0, WIN32K_DATA_VADDR + 0x1000 + di as u64 * 8);
        di += 1;
    }
}

/// Resolve an import name to its IAT-slot value: a code trampoline VA, or (for the 11 data
/// exports) the data-cell address. Pure registry resolve now (Workstream B): the executive
/// registered every real trampoline + data cell by name into the `nt-compat-exports`
/// [`Win32kExportRegistry`]; unregistered names get the benign zero stub (STATUS_SUCCESS / null
/// / void), which is how the declared stub / `TrapIfCalled` / off-path imports resolve. The
/// hardcoded match is GONE.
pub fn export_addr(name: &str) -> u64 {
    // SAFETY: single-threaded; the registry is populated once (lazily) and read-only thereafter.
    unsafe {
        if !WIN32K_EXPORTS_READY {
            register_trampolines();
            WIN32K_EXPORTS_READY = true;
        }
        (*core::ptr::addr_of!(WIN32K_EXPORTS))
            .lookup(name)
            .unwrap_or(s_zero as usize as u64)
    }
}

/// (name, cell value). The six **object-type** cells (`Ps*Type`, `Ex*ObjectType`, `LpcPortObjectType`)
/// now resolve at runtime to the address of a **real** `nt_object_manager::object_type` `OBJECT_TYPE`
/// static (see [`object_type_cell_value`]) — their `0` here is a placeholder overridden in
/// `load_into`. `SeExports` now points at a **real** `nt_security::se_exports` `SE_EXPORTS` struct
/// ([`WIN32K_SE_EXPORTS_VA`], well-known SIDs + privilege LUIDs) built in `load_into` (backlog item 3,
/// Se→nt-security); `NlsMbCodePageTag` still points at a zeroed placeholder (backlog: Nls data); the
/// Mm boundary constants hold their x64 values directly.
const DATA_EXPORTS: &[(&str, u64)] = &[
    ("PsProcessType", 0),
    ("PsThreadType", 0),
    ("ExDesktopObjectType", 0),
    ("ExWindowStationObjectType", 0),
    ("ExEventObjectType", 0),
    ("LpcPortObjectType", 0),
    ("SeExports", WIN32K_SE_EXPORTS_VA),
    ("NlsMbCodePageTag", WIN32K_DATA_VADDR + 0x200),
    ("MmSystemRangeStart", 0xFFFF_0800_0000_0000),
    ("MmUserProbeAddress", 0x0000_7FFF_FFFF_0000),
    ("MmHighestUserAddress", 0x0000_7FFF_FFFF_EFFF),
];

/// Resolve an object-type data-export name to the address of its **real** `OBJECT_TYPE` static, or
/// [`None`] for a non-object-type export (Se/Nls placeholder, Mm constant). win32k reads this value
/// out of the import cell as its `POBJECT_TYPE` type identity and, for the desktop / window-station
/// types, writes its `->TypeInfo.{GenericMapping,ValidAccessMask,DefaultNonPagedPoolCharge}` fields
/// into the struct (offsets +0xB0/+0xC0/+0xD0) — the `OBJECT_TYPE` static is sized and writable to
/// absorb those writes. `classify_type` compares against the same addresses.
fn object_type_cell_value(name: &str) -> Option<u64> {
    use nt_object_manager::object_type as ot;
    Some(match name {
        "PsProcessType" => ot::process_object_type_addr(),
        "PsThreadType" => ot::thread_object_type_addr(),
        "ExDesktopObjectType" => ot::desktop_object_type_addr(),
        "ExWindowStationObjectType" => ot::window_station_object_type_addr(),
        "ExEventObjectType" => ot::event_object_type_addr(),
        "LpcPortObjectType" => ot::port_object_type_addr(),
        _ => return None,
    })
}

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

    // Initialise the data-export cells (page 1). The six object-type cells resolve to their real
    // `OBJECT_TYPE` statics (win32k writes/uses them as typed identities); the rest hold their
    // Se/Nls placeholder addresses or Mm constants. The page-0 placeholder region is now only used
    // by the Se/Nls cells.
    for (idx, (name, value)) in DATA_EXPORTS.iter().enumerate() {
        let cell_value = object_type_cell_value(name).unwrap_or(*value);
        write_volatile((WIN32K_DATA_VADDR + 0x1000 + idx as u64 * 8) as *mut u64, cell_value);
    }

    // SeExports (backlog item 3, Se→nt-security): build a REAL SE_EXPORTS in DATA page 0 so
    // win32k's `SeExports->SeAliasAdminsSid` deref (IntCreateServiceSecurity, the non-interactive
    // service-window-station SD path — off the interactive boot/paint path) reads a genuine SID
    // instead of NULL. The DATA frames are retype-zeroed, so the SID-pointer members win32k never
    // reads stay NULL (matching NT, which only populates what a driver asks for at this stage).
    nt_security::se_exports::build_se_exports(
        WIN32K_SE_EXPORTS_VA as *mut u8,
        WIN32K_SE_SID_POOL_VA as *mut u8,
        WIN32K_SE_SID_POOL_VA,
    );

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
                    // Pure registry resolve: code trampoline VAs AND the 11 data-cell addresses
                    // both come from export_addr now (data cells folded into the registry).
                    let addr = export_addr(name);
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

    // Patch win32k's inlined KeGetCurrentIrql helper (RVA 0x305c0 = `mov rax,cr8; ret`) to
    // `xor rax,rax; nop; ret` (= return PASSIVE_LEVEL). CR8 (the x64 IRQL register) is CPL-0 only, so
    // the read #GPs in our user-mode component; the window-position/lock path (co_WinPosSetWindowPos →
    // focus/activation) reaches it. There is exactly ONE CR8 access in the image (verified by opcode
    // scan), and our single-threaded, interrupt-free host is always at PASSIVE_LEVEL, so returning 0 is
    // authentic.
    patch_ke_get_current_irql();

    // NOTE: the FIRST-LIGHT binary patch (`patch_skip_cursor_tail`) that made
    // co_IntInitializeDesktopGraphics return early — skipping the cursor/icon/menu/show-desktop tail —
    // is REMOVED. The real `KeUserModeCallback` bridge (`s_ke_user_mode_callback`) now services the
    // cursor/icon/menu client callbacks, so the tail runs its FULL natural flow through
    // co_IntShowDesktop / IntPaintDesktop (the authentic desktop-background paint).

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
    let ret = f(a0, a1, a2, a3);

    // Stand up the winsta->desktop parent linkage our Ob layer does not populate. A hosted client's
    // (winlogon's) natural CreateDesktop returns a real DESKTOP body (IntCreateDesktop builds its
    // window graph), but `pdesk->rpwinstaParent` (DESKTOP+0x20) stays NULL — in real win32k
    // IntCreateDesktop sets it from the window station the desktop is parsed under. NtUserSwitchDesktop
    // then derefs it (session-id guard RVA 0x6c281→0x6c285; WSS_LOCKED guard :3007; the
    // `rpwinstaParent == InputWindowStation` guard :3015) and NULL-derefs without it. Poke it to the
    // interactive window station (the single-instance cached WINDOWSTATION == the InputWindowStation
    // global the bring-up gfx-trigger already set) — the same field the gfx-trigger's
    // `create_winsta_and_desktop` pokes on the Default desktop. The returned HDESK is a small handle
    // (0xc/0x10/0x14) so the i32 return carries it intact.
    if ssn == SSN_NT_USER_CREATE_DESKTOP && ret != 0 {
        let hdesk = (ret as u32) as u64;
        let desk_body = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk);
        let winsta_body = (*core::ptr::addr_of!(OBJ_TABLE)).cached_winsta_body();
        if desk_body != 0 && winsta_body != 0 {
            let rpwinsta = (desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *mut u64;
            if read_volatile(rpwinsta) == 0 {
                write_volatile(rpwinsta, winsta_body);
                // Keep the InputWindowStation global consistent (it is already set by the bring-up
                // gfx-trigger to this same cached body; setting it is idempotent/harmless).
                write_volatile((WIN32K_CODE_VA + INPUT_WINDOW_STATION_RVA) as *mut u64, winsta_body);
                print_str(b"[win32k-host] routed NtUserCreateDesktop hDesk=0x");
                print_hex(hdesk as u32);
                print_str(b" rpwinstaParent set -> body=0x");
                print_hex((desk_body >> 32) as u32);
                print_hex(desk_body as u32);
                print_str(b"\n");
            }
        }
    }
    ret
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

    // win32k's IntCbAllocateMemory (callback.c:44) does
    // `InsertTailList(&W32Thread->W32CallbackListHead, &Mem->ListEntry)` in the desktop-init callback
    // tail (co_IntSetWndIcons). In the CHECKED build InsertTailList calls RtlpCheckListEntry which
    // derefs the head's Flink; our W32THREAD is a zeroed placeholder so Flink==NULL → null-deref at
    // RVA 0x24c66. Real win32k initializes this in InitThreadCallback (main.c:497
    // `InitializeListHead(&ptiCurrent->W32CallbackListHead)`). Offset confirmed by disasm of
    // IntCbAllocateMemory (RVA 0x4aa86: `add rcx, 0x2e8; call InsertTailList`). Make it a real empty
    // list head (Flink=Blink=&head) — the authentic InitializeListHead.
    let w32thread = {
        let t = read_volatile(SLOT_W32THREAD as *const u64);
        if t == 0 { PH_W32THREAD_VA } else { t }
    };
    init_threadinfo_placeholder(w32thread);

    // Stand up gptiDesktopThread so IntCreateDesktop's IntGetAndReferenceClass(WC_DESKTOP, TRUE) has
    // the desktop thread's THREADINFO (class.c:1457) instead of the NULL global that faults at RVA
    // 0x50f94. Real win32k sets this from the RIT/desktop-thread bring-up (desktop.c:1566
    // `gptiDesktopThread = PsGetCurrentThreadWin32Thread()`) which our host never runs.
    //
    // POINT IT AT THE DISPATCH THREAD (== the current thread), NOT a separate placeholder. The desktop
    // WINDOW is created ON gptiDesktopThread (IntCreateWindow window.c:1821
    // `pti = pdeskCreated ? gptiDesktopThread : GetW32ThreadInfo()`). If that differs from the current
    // thread, then co_IntShowDesktop's `co_WinPosSetWindowPos`/`co_UserRedrawWindow` sends to the desktop
    // window become CROSS-THREAD → co_MsqSendMessage queues into the desktop thread's message queue
    // (uninitialized here → RtlpCheckListEntry null-deref at RVA 0x24c66, msgqueue.c) and would block on
    // a thread that never runs. Making gptiDesktopThread == the current dispatch thread makes every
    // desktop-window send INTRA-thread → win32k dispatches straight to DesktopWindowProc (WM_ERASEBKGND
    // → IntPaintDesktop, no queue) — which mirrors real Windows where co_IntInitializeDesktopGraphics
    // runs ON the desktop thread. The callback.c `ASSERT(current != gptiDesktopThread)` in the
    // KeUserModeCallback path then trips (current IS gptiDesktopThread) but is an `int 0x2c` we skip
    // (release-build semantics), harmless in our single-threaded host. `ppi` (+0x58) must be the
    // PROCESSINFO the system classes registered into (SLOT_W32PROCESS) so IntGetClassAtom finds
    // WC_DESKTOP.
    let ppi = read_volatile(SLOT_W32PROCESS as *const u64);
    let gpti_cell = (WIN32K_CODE_VA + GPTI_DESKTOP_THREAD_RVA) as *mut u64;
    if read_volatile(gpti_cell) == 0 && ppi != 0 {
        let desk_thread = w32thread; // the dispatch thread (same-thread desktop-window sends)
        if desk_thread != 0 {
            write_volatile((desk_thread + THREADINFO_PPI_OFF) as *mut u64, ppi);
            init_threadinfo_placeholder(desk_thread);
            write_volatile(gpti_cell, desk_thread);
            print_str(b"[win32k-host] gptiDesktopThread = dispatch thread (ppi=0x");
            print_hex((ppi >> 32) as u32);
            print_hex(ppi as u32);
            print_str(b")\n");
        }
    }
}

/// Initialize the thread-list heads + `pClientInfo` a win32k THREADINFO needs before it can host
/// window/callback linking. Both the dispatch thread and the desktop thread (`gptiDesktopThread`) run
/// through window-manager code that operates on these fields; our zeroed placeholders leave them NULL.
/// Offsets (checked build, confirmed by disasm):
///   +0x2d8 WindowListHead     — `InsertTailList(&pti->WindowListHead,…)` IntCreateWindow window.c:2142
///   +0x2e8 W32CallbackListHead — `InsertTailList(&pti->W32CallbackListHead,…)` IntCbAllocateMemory
///   +0x88  pClientInfo         — `pti->pClientInfo->dwTIFlags = …` IntCreateDesktop
/// Real win32k `InitializeListHead`s the lists in CreateThreadInfo (main.c) and points pClientInfo at
/// the thread's CLIENTINFO. `pool_alloc` returns zeroed memory, so an already-initialized field is
/// left as-is.
unsafe fn init_threadinfo_placeholder(w32thread: u64) {
    // THREADINFO LIST_ENTRY heads the window-manager / paint path touches (offsets from win32.h,
    // W32THREAD prefix = 0x50; anchored to the confirmed +0x88 pClientInfo / +0x90 TIF_flags):
    //   +0xB0  SentMessagesListHead   (message.c / co_MsqSendMessage)
    //   +0x2d8 WindowListHead         (IntCreateWindow window.c:2142)
    //   +0x2e8 W32CallbackListHead    (IntCbAllocateMemory callback.c)
    for off in [0xB0u64, 0x2d8, 0x2e8] {
        let head = w32thread + off;
        write_volatile(head as *mut u64, head); // Flink = &head
        write_volatile((head + 8) as *mut u64, head); // Blink = &head
    }
    if read_volatile((w32thread + 0x88) as *const u64) == 0 {
        let ci = pool_alloc(0x100);
        if ci != 0 {
            write_volatile((w32thread + 0x88) as *mut u64, ci);
        }
    }
    // MessageQueue (THREADINFO+0x60): the paint/window-position path references the window's thread
    // and reads `pti->MessageQueue->QF_flags` (USER_MESSAGE_QUEUE+0xAC) — a NULL queue null-derefs in
    // painting.c (RVA 0xb6a55). Provision a real zeroed USER_MESSAGE_QUEUE (References=1) with its
    // HardwareMessagesListHead (+0x38) initialized. Since the desktop-window sends are intra-thread
    // (gptiDesktopThread == the dispatch thread), win32k dispatches straight to DesktopWindowProc; the
    // queue is used only for paint accounting (cPaintsReady, QF_flags), so a zeroed queue with valid
    // list heads suffices. Real win32k creates this in CreateThreadInfo → MsqCreateMessageQueue.
    if read_volatile((w32thread + 0x60) as *const u64) == 0 {
        let mq = pool_alloc(0x200); // USER_MESSAGE_QUEUE (~0xC0 + CaretInfo), zeroed
        if mq != 0 {
            write_volatile(mq as *mut u32, 1); // References = 1
            let hw = mq + 0x38; // HardwareMessagesListHead
            write_volatile(hw as *mut u64, hw);
            write_volatile((hw + 8) as *mut u64, hw);
            write_volatile((w32thread + 0x60) as *mut u64, mq);
        }
    }
    // pcti (THREADINFO+0x70): the paint path sets the thread's wake bits via
    // `pti->pcti->fsWakeBits |= …` (CLIENTTHREADINFO+0x6) — a NULL pcti null-derefs in painting.c
    // (RVA 0xb6acc). Provision a zeroed CLIENTTHREADINFO (CTI_flags@0, fsChangeBits@4, fsWakeBits@6,
    // fsWakeMask@0xA, timeLastRead@0xC). Real win32k points pcti at the desktop-heap CLIENTTHREADINFO
    // (or the embedded pti->cti when there is no desktop).
    if read_volatile((w32thread + 0x70) as *const u64) == 0 {
        let pcti = pool_alloc(0x20);
        if pcti != 0 {
            write_volatile((w32thread + 0x70) as *mut u64, pcti);
        }
    }
}

/// Load the staged system font (arial.ttf at [`FONTBUF_VADDR`]) into win32k via
/// `IntGdiAddFontMemResource`, so the desktop-graphics font realize (TextIntRealizeFont) finds a
/// real font instead of null-derefing at RVA 0x4d7eb ("no fonts loaded at all"). Runs once, after
/// the dispatch context is established (win32k's font code reads gs:/current-process).
///
/// Reclaims the FreeType arena first: ftfd's FreeType probe during InitFontSupport alloc-then-freed
/// the whole `'FTYP'` arena in a churn loop (our ExFreePoolWithTag is a no-op, so the bump pointer
/// never rewound). Those blocks are logically free, so resetting the bump pointer gives
/// `FT_New_Memory_Face` room to parse this face without OOM.
unsafe fn load_system_font() {
    let size = read_volatile((WIN32K_SHARED_VADDR + SH_FONT_SIZE) as *const u32) as u64;
    if size == 0 {
        print_str(b"[win32k-host] no system font staged - font realize will fail\n");
        return;
    }
    let ftyp_hw = read_volatile(WIN32K_FTYP_VADDR as *const u64);
    print_str(b"[win32k-host] FTYP arena high-water=0x");
    print_hex(ftyp_hw as u32);
    print_str(b" (cap=0x");
    print_hex((WIN32K_FTYP_FRAMES * 0x1000) as u32);
    print_str(b")\n");
    print_str(b"[win32k-host] loading system font (");
    print_hex(size as u32);
    print_str(b" B) via IntGdiAddFontMemResource\n");
    let mut num_added: u32 = 0;
    let fptr = WIN32K_CODE_VA + INT_GDI_ADD_FONT_MEM_RESOURCE_RVA;
    // Call through an asm shim that FORCES 16-byte stack alignment (`and rsp,-16` + shadow space):
    // ftfd (FreeType) saves xmm6-15 with `movdqa`, which #GPs (exc 13) on a stack slot that isn't
    // 16-aligned. Guarantee the win64 ABI alignment invariant across the Rust→MSVC→ftfd boundary.
    let handle: u64;
    core::arch::asm!(
        "mov r14, rsp",
        "and rsp, -16",
        "sub rsp, 32",          // shadow space (keeps rsp % 16 == 0 before the call)
        "call r11",
        "mov rsp, r14",
        in("r11") fptr,
        in("rcx") FONTBUF_VADDR,
        in("edx") size as u32,
        in("r8") &mut num_added as *mut u32,
        out("rax") handle,
        out("r14") _,
        clobber_abi("win64"),
    );
    print_str(b"[win32k-host] IntGdiAddFontMemResource -> handle=0x");
    print_hex((handle >> 32) as u32);
    print_hex(handle as u32);
    print_str(b" numAdded=");
    print_hex(num_added);
    print_str(b"\n");
}

/// Build a minimal OBJECT_ATTRIBUTES (Length=0x30) naming `name` (a null-terminated wide string
/// already written in win32k memory) in the win32k pool, and return its address. A non-NULL
/// ObjectName makes NtUserCreateWindowStation skip BuildUserModeWindowStationName (which would touch
/// the client TEB). Layout (x64): OA{Length@0, RootDirectory@8, ObjectName@0x10, Attributes@0x18,
/// SD@0x20, SQoS@0x28}; UNICODE_STRING{Length@0, MaxLength@2, Buffer@8}.
unsafe fn build_object_attributes(name: &[u16]) -> u64 {
    let buf = pool_alloc(((name.len() + 1) * 2) as u64);
    for (i, &w) in name.iter().enumerate() {
        write_volatile((buf + (i * 2) as u64) as *mut u16, w);
    }
    write_volatile((buf + (name.len() * 2) as u64) as *mut u16, 0);
    let us = pool_alloc(0x10);
    write_volatile(us as *mut u16, (name.len() * 2) as u16); // Length (bytes)
    write_volatile((us + 2) as *mut u16, ((name.len() + 1) * 2) as u16); // MaximumLength
    write_volatile((us + 8) as *mut u64, buf); // Buffer
    let oa = pool_alloc(0x30);
    write_volatile(oa as *mut u32, 0x30); // Length == sizeof(OBJECT_ATTRIBUTES)
    write_volatile((oa + 0x10) as *mut u64, us); // ObjectName
    write_volatile((oa + 0x18) as *mut u32, 0x40); // Attributes = OBJ_CASE_INSENSITIVE
    oa
}

/// Drive `NtUserCreateWindowStation` → `NtUserCreateDesktop` (winlogon's normal path, which our
/// hosted csrss can't reach — it's blocked upstream at the Phase-4 SmConnectToSm LPC wall) so
/// IntCreateDesktop runs on REAL Ob DESKTOP + WINDOWSTATION objects (see the Ob object layer above)
/// instead of the previous all-`s_zero` stubs. This advances IntCreateDesktop past its Context==FALSE
/// early-return into the window-manager object graph (IntGetAndReferenceClass(WC_DESKTOP), the next
/// wall). Runs in the post-NtUserInitialize (SSN 0x125a) dispatch context (GS=KPCR/session heap/
/// pClientInfo set), so any internal faults/asserts are serviced by the executive's win32k_dispatch
/// fault loop. The trailing NtUserSwitchDesktop uses bRedraw=FALSE so it does NOT itself trigger the
/// lazy co_IntInitializeDesktopGraphics — that stays winlogon's to drive.
unsafe fn create_winsta_and_desktop() {
    const MAXIMUM_ALLOWED: u64 = 0x0200_0000;
    // "WinSta0"
    let winsta_name = [0x57u16, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x30];
    let oa_ws = build_object_attributes(&winsta_name);
    print_str(b"[win32k-host] NtUserCreateWindowStation(WinSta0)...\n");
    let cws: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64) -> i32 =
        core::mem::transmute((WIN32K_CODE_VA + NT_USER_CREATE_WINDOW_STATION_RVA) as *const ());
    let hws = cws(oa_ws, MAXIMUM_ALLOWED, 0, 0, 0, 0, 0);
    print_str(b"[win32k-host] NtUserCreateWindowStation -> hWinSta=0x");
    print_hex(hws as u32);
    print_str(b" (winsta body=0x");
    print_hex((*core::ptr::addr_of!(OBJ_TABLE)).cached_winsta_body() as u32);
    print_str(b")\n");

    // "Default"
    let desk_name = [0x44u16, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74];
    let oa_dsk = build_object_attributes(&desk_name);
    print_str(b"[win32k-host] NtUserCreateDesktop(Default)...\n");
    // NtUserCreateDesktop(ObjectAttributes, lpszDesktopDevice, lpdmw, dwFlags, dwDesiredAccess) -> HDESK
    let cd: extern "win64" fn(u64, u64, u64, u64, u64) -> u64 =
        core::mem::transmute((WIN32K_CODE_VA + NT_USER_CREATE_DESKTOP_RVA) as *const ());
    let hdesk = cd(oa_dsk, 0, 0, 0, MAXIMUM_ALLOWED);
    print_str(b"[win32k-host] NtUserCreateDesktop -> hDesk=0x");
    print_hex((hdesk >> 32) as u32);
    print_hex(hdesk as u32);
    print_str(b"\n");

    // Set `gpdeskInputDesktop` to the created DESKTOP body so `IntGetActiveDesktop()` returns it and
    // `co_IntShowDesktop` (winsta.c:340, invoked next by co_IntInitializeDesktopGraphics) derefs a real
    // `Desktop->pDeskInfo->spwnd` (the desktop window IntCreateWindow built) instead of NULL.
    //
    // Drive the AUTHENTIC `NtUserSwitchDesktop` (desktop.c:2971) rather than poke the global directly:
    // it is win32k's own `gpdeskInputDesktop = pdesk` writer (desktop.c:3044) and it validates the
    // desktop through the real Ob handle (IntValidateDesktopHandle → ObReferenceObjectByHandle against
    // ExDesktopObjectType). The switch guards (disasm of RVA 0x6c140) require, before it will set the
    // global:
    //   (1) pdesk->rpwinstaParent (DESKTOP+0x20) non-NULL and == the InputWindowStation global — else
    //       desktop.c:3015 returns FALSE (and the session-id check at 0x6c281 derefs it);
    //   (2) InputWindowStation (winsta.c:21 global, RVA 0x20c068) == that same window station;
    //   (3) winsta->dwSessionId (WINSTATION+0) == PsGetCurrentProcessSessionId() (both 0 here);
    //   (4) winsta->Flags (WINSTATION+0x20) WSS_LOCKED bit clear (zeroed body → clear).
    // We stand up (1)+(2) from our created WINDOWSTATION body; (3)+(4) hold for the zeroed body. This is
    // strictly MORE authentic than the old blind poke — the switch now runs win32k's real handle
    // validation + winsta-locking checks. On this first switch gpdeskInputDesktop is NULL so the
    // hide-previous-desktop branch (desktop.c:3031) is skipped; the switch's own trailing
    // co_IntShowDesktop runs with bRedraw=FALSE (no paint — SM_CX/CYSCREEN are still 0 pre-InitVideo),
    // then co_IntInitializeDesktopGraphics's :340 co_IntShowDesktop(bRedraw=TRUE) does the real paint.
    let desk_body = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk);
    let winsta_body = (*core::ptr::addr_of!(OBJ_TABLE)).cached_winsta_body();
    if desk_body != 0 && winsta_body != 0 {
        // (1) pdesk->rpwinstaParent = our WINDOWSTATION body.
        write_volatile((desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *mut u64, winsta_body);
        // (2) the interactive InputWindowStation global = the same window station.
        write_volatile((WIN32K_CODE_VA + INPUT_WINDOW_STATION_RVA) as *mut u64, winsta_body);

        print_str(b"[win32k-host] NtUserSwitchDesktop(hDesk) [rpwinstaParent+InputWindowStation set]\n");
        let switch: extern "win64" fn(u64) -> i32 =
            core::mem::transmute((WIN32K_CODE_VA + NT_USER_SWITCH_DESKTOP_RVA) as *const ());
        let sret = switch(hdesk);
        let gpdesk = read_volatile((WIN32K_CODE_VA + GPDESK_INPUT_DESKTOP_RVA) as *const u64);
        print_str(b"[win32k-host] NtUserSwitchDesktop -> ret=0x");
        print_hex(sret as u32);
        print_str(b", gpdeskInputDesktop=0x");
        print_hex((gpdesk >> 32) as u32);
        print_hex(gpdesk as u32);
        print_str(b" (spwnd=0x");
        // pDeskInfo @ body+0x08; DESKTOPINFO.spwnd @ +0x10 (pvDesktopBase@0, pvDesktopLimit@8, spwnd@0x10
        // — confirmed by co_IntShowDesktop disasm 0x6dc5c `mov rax,[rax+8]`; 0x6dc60 `mov rax,[rax+0x10]`).
        let pdeskinfo = if gpdesk != 0 { read_volatile((gpdesk + 0x08) as *const u64) } else { 0 };
        let spwnd = if pdeskinfo != 0 { read_volatile((pdeskinfo + 0x10) as *const u64) } else { 0 };
        print_hex((spwnd >> 32) as u32);
        print_hex(spwnd as u32);
        print_str(b")\n");
    } else {
        print_str(b"[win32k-host] WARN: no desktop/winsta body - gpdeskInputDesktop unset\n");
    }
}

/// Once-guard: the post-NtUserInitialize host-prerequisite seed (system font + WinSta0/Default Ob
/// objects) runs a single time. Single-threaded component → a plain `static mut` bool suffices.
static mut DESKTOP_GFX_SEEDED: bool = false;

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
        // Each client dispatch begins with the dispatch thread owning NO windows. The desktop windows
        // IntCreateDesktop builds live on gptiDesktopThread, which our single-threaded host merged with
        // the dispatch thread — so winlogon's NtUserSetThreadDesktop (desktop.c:3331 IsListEmpty check)
        // would wrongly see those desktop windows as ITS windows and fail "thread has windows",
        // short-circuiting its `SetThreadDesktop(Winlogon) && SwitchDesktop(Winlogon)` (wlx.c:1077) —
        // the natural co_IntShowDesktop / co_IntInitializeDesktopGraphics trigger. Re-empty the current
        // thread's WindowListHead (+0x2d8) each dispatch to restore the authentic invariant (in real
        // Windows the desktop windows belong to a SEPARATE desktop/RIT thread; the desktop window is
        // still reachable via pdesk->pDeskInfo->spwnd, not the thread list).
        {
            let t = read_volatile(SLOT_W32THREAD as *const u64);
            let t = if t == 0 { PH_W32THREAD_VA } else { t };
            let head = t + 0x2d8;
            write_volatile(head as *mut u64, head);
            write_volatile((head + 8) as *mut u64, head);
        }
        if ssn == SSN_NT_USER_INITIALIZE_REAL {
            // NtUserInitialize(dwWinVersion, hPowerRequestEvent=a1, hMediaRequestEvent=a2). These are
            // real Event handles winsrv created via NtCreateEvent; win32k's IntInitWin32PowerManagement
            // references the power event by handle+type. MODEL them as real typed Event objects — a
            // KEVENT body from the win32k pool + a win32k_ob registration keyed by the handle — so the
            // subsequent ObReferenceObjectByHandle(handle, *ExEventObjectType) resolves + type-checks a
            // genuine KEVENT (no fake-EPROCESS masking). Synchronization/non-signalled == winsrv's
            // NtCreateEvent(SynchronizationEvent, FALSE).
            register_event_object(a1);
            register_event_object(a2);
        }
        let status = if ssn == SSN_TEST_FAULT {
            // Fix (B) self-test: touch an un-demand-paged page → FAULT mid-dispatch. The executive
            // resolves it via the REPLY_W32 reply cap and resumes us here; we read back the zeroed
            // page (observability into SH_REQ_A0) and report the sentinel status.
            let probe = read_volatile(TEST_FAULT_VA as *const u64);
            write_volatile((WIN32K_SHARED_VADDR + SH_REQ_A0) as *mut u64, probe);
            TEST_FAULT_STATUS
        } else {
            dispatch_ssn(ssn, a0, a1, a2, a3)
        };
        // Post-NtUserInitialize (0x125a) HOST-PREREQUISITE SEED (once). The eager
        // co_IntInitializeDesktopGraphics scaffold is RETIRED — InitVideo/surface + the paint now run
        // fully lazily from winlogon's own first GUI DC-op (SwitchDesktop → co_IntShowDesktop → erase →
        // DceAllocDCE → co_IntGraphicsCheck → co_IntInitializeDesktopGraphics). But two host-side
        // prerequisites that the lazy init depends on cannot be produced by winlogon itself and must be
        // seeded here, at the earliest valid point (NtUserInitialize → InitializeGreCSRSS → InitFontSupport
        // has just run, so FreeType/g_FreeTypeLock exist):
        //   (1) the system font (arial.ttf memory-font) — else the lazy co_IntInitializeDesktopGraphics's
        //       font realize null-derefs ("no fonts loaded at all");
        //   (2) the WinSta0/Default Ob object graph winlogon reuses (its NtUserCreateWindowStation returns
        //       hWinSta=0x4, and gpdeskInputDesktop is set) — via a bRedraw=FALSE SwitchDesktop that does
        //       NOT itself trigger the lazy path, leaving NrGuiAppsRunning==0 for winlogon to drive.
        if ssn == SSN_NT_USER_INITIALIZE_REAL && status == 0 && !DESKTOP_GFX_SEEDED {
            DESKTOP_GFX_SEEDED = true;
            load_system_font();
            create_winsta_and_desktop();
        }
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
