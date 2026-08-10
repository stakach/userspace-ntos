//! `win32k_subsystem` — the **Subsystem-class** driver implementation: the REAL ReactOS
//! `win32k.sys` loaded by-path into an isolated seL4 component, plus the genuine subsystem POLICY
//! that has no generic home and stays here (the window-manager Ob object graph, the Ps win32
//! callouts, the NtUser/NtGdi SSDT dispatch, and the `KeUserModeCallback`/framebuffer paint loop).
//!
//! Class relationship: like `npfs.sys` is the first client of the FSD class (`driver_launch`'s
//! `fsd_component_entry` + shared `DriverExportRegistry`), `win32k.sys` is the first client of the
//! GUI syscall server class ([`DriverClass::GuiSyscallServer`](crate::driver_launch::DriverClass)). The RESOLUTION
//! MECHANISM is converged — win32k binds its `ntoskrnl.exe` imports into the SAME driver-agnostic
//! [`DriverExportRegistry`] every hosted `.sys` uses, and the pure byte/string primitives are the
//! SAME [`crate::ntoskrnl_shared`] impls the FSD class calls. What is NOT generic (and by design
//! stays here) is the subsystem-specific policy: win32k's protocol is a large inline demand-fault
//! init loop with paint side-effects, not the FSD IRP-dispatch loop, so its component entry is
//! win32k's own ([`win32k_subsystem_entry`]) rather than the FSD entry.
//!
//! Structural split (scaled to a 2.1 MiB image staged off disk):
//!   * the EXECUTIVE (which owns the heap + the staged image at `WIN32KBUF`) parses the PE,
//!     copies its 8 sections into a run of untyped-backed frames at [`WIN32K_CODE_VA`]
//!     (VIRTUAL layout — not a `PeFile::map()` Vec, which the 128 KiB bump heap can't hold),
//!     applies the 1920 DIR64 relocations in place, and patches the IAT: init-path imports →
//!     real trampolines below, data-export globals → non-null placeholder cells, everything
//!     else → a benign zero stub. See [`load_into`].
//!   * the COMPONENT (the spawned Subsystem-class component) maps the image W^X (RX code / RW
//!     data), a pool arena, the data-export region, and calls `DriverEntry(DRIVER_OBJECT*,
//!     UNICODE_STRING*)` with its fault endpoint armed. On return it writes a verdict + the
//!     recorded SSDT to the shared page and trips a SENTINEL fault so the executive's fault-recv
//!     loop knows it finished (vs. faulted mid-init). See [`win32k_subsystem_entry`].
//!
//! The trampolines are compiled into the executive's image (mapped RWX-shared into the component),
//! so the component calls them at the same VA.

use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};
use nt_compat_exports::{
    ssdt::{
        x64_argument_count_from_sspt_byte,
        WIN32K_SERVICE_TABLE_INDEX as NT_WIN32K_SERVICE_TABLE_INDEX,
    },
    DriverExportRegistry,
};

// Pure, driver-agnostic ntoskrnl byte/string primitives shared with the FSD class.
use crate::ntoskrnl_shared::{s_memcpy, s_memmove, s_memset, s_wcslen};

use crate::*;

// --- component VA layout (identical in executive-load + host-run views) ----------------------

/// The relocated/loaded win32k image (VIRTUAL layout), mapped W^X in the host. size_of_image
/// is 0x220000 (544 frames); place it in its own 2-PT window well clear of everything else.
pub const WIN32K_CODE_VA: u64 = 0x0000_0100_0680_0000;
/// win32k image frame count (size_of_image 0x220000 / 0x1000).
pub const WIN32K_IMAGE_FRAMES: u64 = 0x220;
const WIN32K_IMAGE_BYTES: u64 = WIN32K_IMAGE_FRAMES * 0x1000;
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
/// HEAP handle (page 3) + win32 compatibility slots/callout table (page 4) + reserved mapped data
/// pages (pages 5-8). Runtime EPROCESS/ETHREAD bodies and per-thread callout TEB mirrors are
/// allocated from win32k-owned arenas instead of fixed cells in this region.
/// 9 frames.
pub const WIN32K_DATA_VADDR: u64 = 0x0000_0100_0710_0000;
pub const WIN32K_DATA_FRAMES: u64 = 9;
/// Per-dispatch primary-token user SID bytes. The shared dispatch page carries a pointer to this
/// data-region buffer so the callback frame can remain at its fixed `0x200` offset.
pub const WIN32K_TOKEN_USER_SID_VADDR: u64 = WIN32K_DATA_VADDR + 0x5000;
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
/// Current-process win32 state (page 4): compatibility cells mirroring the selected runtime
/// context + a copy of win32k's callout table (recorded by PsEstablishWin32Callouts).
const SLOT_W32PROCESS: u64 = WIN32K_DATA_VADDR + 0x4000; // Ps{Set,Get}ProcessWin32Process slot
const SLOT_W32THREAD: u64 = WIN32K_DATA_VADDR + 0x4008; // Ps{Set,Get}ThreadWin32Thread slot
const WIN32_CALLOUTS: u64 = WIN32K_DATA_VADDR + 0x4100; // recorded WIN32_CALLOUTS_FG table (copy)
/// A synthetic process handle NtUserProcessConnect's ObReferenceObjectByHandle resolves.
pub const FAKE_PROCESS_HANDLE: u64 = 0x0000_0000_5A5A_0100;
const WIN32K_BOOTSTRAP_PI: usize = 1;
const WIN32K_BOOTSTRAP_TID: u64 = FAKE_PROCESS_HANDLE + 0x100;
const WIN32K_EPROCESS_BYTES: u64 = 0x1000;
const WIN32K_ETHREAD_BYTES: u64 = 0x400;
/// The win32k session-heap arena that RtlAllocateHeap + the Mm session/system view mappers allocate
/// from (counter at +0, free-list head at +8, data at +0x1000). The arena is reclaimed through the
/// hosted RtlFreeHeap path instead of being grown to mask leaks.
pub const WIN32K_HEAP_VADDR: u64 = 0x0000_0100_0740_0000;
pub const WIN32K_HEAP_FRAMES: u64 = 4096;
const _: () =
    assert!(WIN32K_HEAP_VADDR + WIN32K_HEAP_FRAMES * 0x1000 <= WIN32K_POOL_VADDR);
const _: () =
    assert!(WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000 <= WIN32K_STACK_VADDR);
/// Shared handoff page (executive ↔ host). Within the pool's 2 MiB PT window (0x0700..0x0720).
pub const WIN32K_SHARED_VADDR: u64 = 0x0000_0100_0718_0000;
/// The cross-address-space ARG-MARSHAL frame: mapped RW in BOTH the executive and the win32k
/// component (within the pool PT window). The executive copies a dispatched syscall's user buffers
/// here (sized per the win32k SSN signature); win32k's handler reads/writes them in its own context;
/// the executive copies out-params back to the caller on reply. 4 pages = 16 KiB.
pub const WIN32K_ARG_VADDR: u64 = 0x0000_0100_071A_0000;
pub const WIN32K_ARG_FRAMES: u64 = 4;
/// Bulk client-buffer staging for provider-dispatched win32k calls whose input is data, not just
/// scalar argument tails. `NtGdiStretchDIBitsInternal` can receive DIB payloads far larger than the
/// generic ARG window, so it gets a dedicated shared 2 MiB PT window between AUX and the session heap.
pub const WIN32K_BULK_ARG_VADDR: u64 = 0x0000_0100_0720_0000;
pub const WIN32K_BULK_ARG_FRAMES: u64 = 512;
/// Kernel-mode KUSER_SHARED_DATA mapping used by win32k's direct `SharedUserData` reads. User
/// processes also see the low 0x7FFE0000 alias; win32k, as a kernel driver, reads the canonical
/// high VA directly (for example TickCount at +0x320).
pub const WIN32K_KUSER_SHARED_DATA_VA: u64 = 0xFFFF_F780_0000_0000;
/// Executive-only scratch VA, inside the already mapped win32k aux PT, used to initialize the
/// KUSER frame before aliasing it into the win32k component at the canonical high VA.
pub const WIN32K_KUSER_SCRATCH_VA: u64 = WIN32K_AUX_PT_VADDR + 0x1B_0000;

/// The csrss-side VA where win32k's global USER heap arena ([`WIN32K_HEAP_VADDR`] — where gpsi, the
/// USER handle table `gHandleTable`, and the handle-entry array all live, being `UserHeapAlloc`ed)
/// is RO-mapped so the Win32 client stack (user32/gdi32) can read the SHAREDINFO the USERCONNECT's
/// `siClient` pointers name. A full 16 MiB window ([`WIN32K_HEAP_FRAMES`]), 2-MiB-aligned, sitting
/// immediately above the bounded compact DLL arena and below the NLS section (0xA000_0000).
/// **Was 0x9000_0000, where the former fixed-slot DLL layout collided with it and made lsass execute
/// win32k-heap NX pages.** 0x9800_0000 is now the explicit DLL-arena end and stays inside the shared
/// 0x8000_0000..0xC000_0000 1 GiB PD. Delta-relative: the
/// connect marshaling rewrites `siClient`/`ulSharedDelta` by `WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`,
/// so moving the base is behavior-preserving for the existing GUI clients (csrss pi 1 / winlogon pi 2).
pub const CSRSS_W32_SHARED_VA: u64 = 0x0000_0000_9800_0000;

/// The GUI-client-side VA where win32k's POOL arena ([`WIN32K_POOL_VADDR`] — where the DESKTOP body +
/// its DESKTOPINFO are `pool_alloc`ed) is RO-mapped, so user32's client-side `DesktopPtrToUser` can
/// read `pci->pDeskInfo->pvDesktopBase/pvDesktopLimit` (the DESKTOPINFO lives in the POOL, NOT the
/// USER heap). Sits immediately ABOVE the 16 MiB USER-heap window (0x9800_0000..0x9900_0000) and below
/// the NLS section (0xA000_0000), inside the shared 0x8000_0000..0xC000_0000 1 GiB PD. The client VA of
/// a pool object = its server VA - ([`WIN32K_POOL_VADDR`] - `CSRSS_W32_POOL_VA`).
pub const CSRSS_W32_POOL_VA: u64 = 0x0000_0000_9900_0000;
// The USER-heap window (16 MiB) must end at or below the POOL window base so the two client windows
// never overlap; the POOL window (8 MiB) must end below the NLS section (0xA000_0000).
const _: () = assert!(CSRSS_W32_SHARED_VA + WIN32K_HEAP_FRAMES * 0x1000 <= CSRSS_W32_POOL_VA);
const _: () = assert!(CSRSS_W32_POOL_VA + WIN32K_POOL_FRAMES * 0x1000 <= 0x0000_0000_A000_0000);

// ★ DIALOG BATCH 3 — CLIENT-GDI HANDLE TABLE window. gdi32's client-side validity check indexes
// `GdiSharedHandleTable[handle & 0xffff]` (0x18-byte GDI_TABLE_ENTRY each — KernelData@0, ProcessId@8,
// Type@0xc, UserData@0x10; ntgdihdl.h). The base pointer is `PEB->GdiSharedHandleTable` (PEB+0xf8);
// gdi32's `GdiProcessSetup` (RVA 0x1100) copies it into its cached global (gdi32 RVA 0x4e188). We
// RO-map a full GDI_HANDLE_COUNT (0x10000) entry array so ANY handle&0xffff index is in-bounds (no
// fault on the read), zero-initialized (a zero entry.Type mismatches the validity check → gdi32 takes
// its `invalid handle` branch rather than a NULL-deref). Sits ABOVE the POOL client window
// (0x9900_0000 + 8 MiB = 0x9980_0000) and below the NLS section (0xA000_0000).
pub const GDI_SHARED_TABLE_VA: u64 = 0x0000_0000_9C00_0000;
/// GDI handle count (ReactOS GDI_HANDLE_COUNT) — the index space of `handle & 0xffff`.
pub const GDI_HANDLE_COUNT: u64 = 0x1_0000;
/// sizeof(GDI_TABLE_ENTRY) on x64 (KernelData 8 + ProcessId/Type union 8 + UserData 8).
pub const GDI_TABLE_ENTRY_SIZE: u64 = 0x18;
/// Frames spanning the GDI table (0x10000 * 0x18 = 0x18_0000 = 1.5 MiB = 384 frames).
pub const GDI_SHARED_TABLE_FRAMES: u64 = (GDI_HANDLE_COUNT * GDI_TABLE_ENTRY_SIZE + 0xfff) / 0x1000;
const _: () =
    assert!(GDI_SHARED_TABLE_VA + GDI_SHARED_TABLE_FRAMES * 0x1000 <= 0x0000_0000_A000_0000);
const _: () = assert!(GDI_SHARED_TABLE_VA >= CSRSS_W32_POOL_VA + WIN32K_POOL_FRAMES * 0x1000);

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
pub const SH_SSDT_ARGUMENT_TABLE: u64 = 0x28; // out: recorded win32k SSPT/KiArgumentTable base (u64)
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
pub const SH_REQ_STATUS: u64 = 0x78; // out: handler return value (u64; low i32 remains NTSTATUS-compatible)
pub const SH_FONT_SIZE: u64 = 0x88; // in:  staged system-font (.ttf) byte size at FONTBUF_VADDR (u32)
                                    // STACK-ARG TAIL for executive-originated win32k SSNs. Real client syscalls pass their caller RSP in
                                    // SH_REQ_CALLER_SP and the component reads the required tail directly from the attached client stack,
                                    // after deriving the exact arity from win32k's registered SSPT/KiArgumentTable.
pub const SH_REQ_A4: u64 = 0x90; // in:  handler arg4 (1st stack arg)
pub const SH_REQ_NARGS: u64 = 0xF0; // in:  total arg count staged in SH_REQ_A4.., or 0 for caller-stack args
pub const WIN32K_MAX_SERVICE_ARGS: u64 = 16;
pub const WIN32K_STACK_TAIL_ARGS: usize = (WIN32K_MAX_SERVICE_ARGS - 4) as usize;
// Compile-time invariants for the stack-arg-tail region (host-verified at build):
//  - SH_REQ_A4 must sit ABOVE the last register field (SH_FONT_SIZE=0x88) so it never aliases.
//  - The widest SSN is 16 args (SH_REQ_A4 holds args 5..16 = 12 u64 slots = 0x90..0xF0), which must
//    END exactly at SH_REQ_NARGS with no overlap — i.e. NARGS = A4 + 12*8.
const _: () = assert!(SH_REQ_A4 > SH_FONT_SIZE);
const _: () = assert!(SH_REQ_NARGS == SH_REQ_A4 + WIN32K_STACK_TAIL_ARGS as u64 * 8);

// ★ DESKTOP-HEAP CLIENT-WINDOW MAPPING (SAS DispatchMessageW client-side resolution). win32k
// publishes, per dispatch, the two server-VA facts the executive needs to seed the GUI client's
// TEB.Win32ClientInfo so user32's `ValidateHwnd`/`DesktopPtrToUser`/`IntCallMessageProc` resolve a
// real window PWND out of win32k's (unified USER+desktop) heap into the client's RO-mapped view:
//   - SH_SAS_DESKINFO: the bound DESKTOP's DESKTOPINFO server VA (winlogon's CLIENTINFO.pDeskInfo =
//     this − delta; its pvDesktopBase/pvDesktopLimit are set to bracket the whole heap so
//     DesktopPtrToUser's range check accepts any heap-resident PWND/CLS).
//   - SH_SAS_PTI: the dispatch THREADINFO server VA (== the window's `head.pti`); the client's
//     TEB.Win32ThreadInfo must equal it so IntCallMessageProc's `Wnd->head.pti == GetW32ThreadInfo()`
//     same-thread check passes (else ERROR_MESSAGE_SYNC_ONLY → the proc never runs).
// Both are 0 until the desktop is bound (BOUND_DESK_* latched). Written above SH_REQ_NARGS.
pub const SH_SAS_DESKINFO: u64 = 0x100; // out: bound DESKTOPINFO server VA (u64)
pub const SH_SAS_PTI: u64 = 0x108; // out: dispatch THREADINFO server VA (== window head.pti) (u64)
                                   // The USER handle table (gSharedInfo.aheList) server VA — the executive captures it from the
                                   // USERCONNECT during NtUserProcessConnect and publishes it here so win32k's WM_CREATE callback bridge
                                   // can resolve a HWND → its PWND (handles[(hwnd&0xffff − 0x20)>>1].ptr) to persist WND.dwUserData.
pub const SH_SAS_AHELIST: u64 = 0x110; // in: gSharedInfo.aheList (USER_HANDLE_TABLE) server VA (u64)
                                       // The SAS window's Session pointer (CreateWindowEx lpCreateParams), published by win32k's WM_CREATE
                                       // callback bridge; the executive reads winlogon's `Session->LogonState` (Session+0x118) through it to
                                       // PROVE SASWindowProc → DispatchSAS ran client-side (STATE_INIT→STATE_LOGGED_OFF after the SAS).
pub const SH_SAS_SESSION: u64 = 0x118; // out: winlogon SAS-window Session VA (u64)
                                       // The SAS window's HWND (handle value), published by win32k's WM_CREATE callback bridge. The executive
                                       // uses it to INJECT the 2nd SAS: at STATE_LOGGED_OFF it posts WLX_WM_SAS(WLX_SAS_TYPE_CTRL_ALT_DEL) to
                                       // this HWND via the REAL NtUserPostMessage(0x100e) path (co_IntPostMessage → MsqPostMessage), simulating
                                       // the Ctrl-Alt-Del a headless host can't receive from a keyboard, so winlogon's GetMessage retrieves it →
                                       // client-side SASWindowProc → DispatchSAS → WlxLoggedOutSAS (the msgina logon dialog).
pub const SH_SAS_HWND: u64 = 0x120; // out: winlogon SAS-window HWND (u64)
pub const SH_GDI_TABLE_BASE: u64 = 0x128; // out: coherent hosted GDI handle-table backing (u64)
pub const SH_GDI_TABLE_SIZE: u64 = 0x130; // out: full hosted GDI handle-table byte size (u64)
pub const SH_REQ_PROCESS_ID: u64 = 0x138; // in: routed caller's real Process Manager pid (u64)
pub const SH_REQ_NESTED_CALLBACK: u64 = 0x140; // in: dispatch is nested inside a parked user callback
pub const SH_REQ_CLIENT_PI: u64 = 0x148; // in: executive hosted-process index for this dispatch
pub const SH_REQ_CLIENT_TEB: u64 = 0x150; // in: routed caller's current-thread TEB user VA
pub const SH_REQ_DEBUG_FLAGS: u64 = 0x158; // in: executive-only diagnostic flags for this dispatch
pub const SH_REQ_CALLER_SP: u64 = 0x160; // in: real syscall-entry RSP when tail args live on the client stack
pub const SH_REQ_THREAD_ID: u64 = 0x168; // in: routed caller's real Process Manager tid (u64)
pub const SH_REQ_EPROCESS: u64 = 0x170; // in: Process Manager's parked EPROCESS body, or 0
pub const SH_REQ_ETHREAD: u64 = 0x178; // in: Process Manager's parked ETHREAD body, or 0
pub const SH_CTX_PROCESS_ID: u64 = 0x180; // out: selected runtime PID
pub const SH_CTX_THREAD_ID: u64 = 0x188; // out: selected runtime TID
pub const SH_CTX_EPROCESS: u64 = 0x190; // out: selected EPROCESS body
pub const SH_CTX_ETHREAD: u64 = 0x198; // out: selected ETHREAD body
pub const SH_CTX_W32PROCESS: u64 = 0x1A0; // out: win32k W32PROCESS parked on EPROCESS, or 0
pub const SH_CTX_W32THREAD: u64 = 0x1A8; // out: win32k W32THREAD parked on ETHREAD, or 0
pub const SH_REQ_PROCESS_ROLE: u64 = 0x1B0; // in: registered hosted-process role code
pub const SH_REQ_TOKEN_AUTH: u64 = 0x1B8; // in: packed primary-token AuthenticationId LUID
pub const SH_REQ_TOKEN_USER_SID_LEN: u64 = 0x1C0; // in: native user SID byte length
pub const SH_REQ_TOKEN_USER_SID_PTR: u64 = 0x1C8; // in: component VA of native user SID bytes
pub const WIN32K_TOKEN_USER_SID_MAX: usize = 68; // SID header + 15 sub-authorities
pub const SH_GDI_LOAD_LEAF_LEN: u64 = 0x1D0; // in: ASCII driver leaf byte length
pub const SH_GDI_LOAD_STATUS: u64 = 0x1D8; // out: executive load NTSTATUS
pub const SH_GDI_LOAD_LEAF: u64 = 0x1E0; // in: lower-case ASCII driver leaf bytes
pub const SH_GDI_LOAD_LEAF_CAP: usize = 24;
pub const SH_REQ_DEBUG_ATL_REPLAY: u64 = 0x0000_0001;
const _: () = assert!(SH_SAS_DESKINFO > SH_REQ_NARGS);
/// Phase 2A callback rendezvous frame. The fixed, pointer-free ABI occupies the otherwise-unused
/// tail of the existing shared page; both the component stub and executive pump access it here.
pub const SH_USER_CALLBACK: u64 = 0x200;
const _: () = assert!(SH_REQ_TOKEN_USER_SID_PTR + 8 <= SH_USER_CALLBACK);
const _: () = assert!(SH_GDI_LOAD_LEAF + SH_GDI_LOAD_LEAF_CAP as u64 <= SH_USER_CALLBACK);
const _: () = assert!(SH_USER_CALLBACK as usize + nt_user_callback::CALLBACK_FRAME_SIZE <= 0x1000);

pub const HOSTED_PROCESS_ROLE_NONE: u64 = 0;
pub const HOSTED_PROCESS_ROLE_NATIVE_SESSION: u64 = 1;
pub const HOSTED_PROCESS_ROLE_WIN32_SUBSYSTEM: u64 = 2;
pub const HOSTED_PROCESS_ROLE_INTERACTIVE_LOGON: u64 = 3;
pub const HOSTED_PROCESS_ROLE_NONINTERACTIVE_SERVICE: u64 = 4;
pub const HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL_BOOTSTRAP: u64 = 5;
pub const HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL: u64 = 6;

/// The registered win32k service metadata published by `KeAddSystemServiceTable`.
///
/// The argument table is a provider VA. The executive may record and log it, but must not dereference
/// it unless that VA is explicitly mapped into the executive. The component-side dispatcher can read
/// it directly in win32k's own VSpace.
pub fn registered_win32k_service_metadata() -> Option<(u64, u32, u64)> {
    unsafe {
        let base = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *const u64);
        let count = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_COUNT) as *const u32);
        let index = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_INDEX) as *const u32);
        let argument_table =
            read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_ARGUMENT_TABLE) as *const u64);
        if base == 0 || count == 0 || argument_table == 0 || index != NT_WIN32K_SERVICE_TABLE_INDEX
        {
            None
        } else {
            Some((base, count, argument_table))
        }
    }
}

/// Component-side lookup of the provider's win32k x64 SSPT/KiArgumentTable arity.
///
/// # Safety
///
/// `argument_table` is the raw pointer win32k registered from its own address space. Call this only
/// while running in the win32k component VSpace, where that pointer is valid.
unsafe fn registered_win32k_provider_argc(ssn: u64) -> Option<u64> {
    let (_base, count, argument_table) = registered_win32k_service_metadata()?;
    let index = ssn.checked_sub(WIN32K_SERVICE_BASE)?;
    if index >= count as u64 {
        return None;
    }
    let argument_byte = read_volatile(argument_table.checked_add(index)? as *const u8);
    Some(u64::from(x64_argument_count_from_sspt_byte(argument_byte)))
}

// verdict bits
pub const V_ENTERED: u32 = 1; // host called into DriverEntry
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
const SSN_GDI_CREATE_COMPATIBLE_BITMAP: u64 = 0x104A;
const SSN_GDI_CREATE_COMPATIBLE_DC: u64 = 0x1054;
const SSN_GDI_CREATE_BITMAP: u64 = 0x106C;
const SSN_GDI_CREATE_DIB_SECTION: u64 = 0x109B;
const SSN_GDI_CREATE_DIBITMAP_INTERNAL: u64 = 0x10A0;
const SSN_GDI_OPEN_DCW: u64 = 0x10DE;
const GDI_HANDLE_TYPE_MASK: u32 = 0x007f_0000;
const GDI_HANDLE_BASETYPE_MASK: u32 = 0x001f_0000;
const GDI_ENTRY_PROCESS_ID_OFF: u64 = 0x08;
const GDI_ENTRY_TYPE_OFF: u64 = 0x0C;
const GDI_ENTRY_USER_DATA_OFF: u64 = 0x10;
const GDI_ENTRY_UPPER_SHIFT: u32 = 16;
const GDI_OBJECT_TYPE_DC: u32 = 0x0001_0000;
const GDI_OBJECT_TYPE_BITMAP: u32 = 0x0005_0000;

/// Fix (B) self-test SSN — a SYNTHETIC dispatch (well outside win32k's real 740-entry SSDT) whose
/// handler deliberately READS an un-demand-paged data page in this component's VSpace. The read
/// FAULTS mid-dispatch; the executive's `win32k_dispatch` fault loop demand-maps the page THROUGH
/// the per-caller reply cap (REPLY_W32 / decode_reply) and resumes us. We then read the (zeroed)
/// page and return [`TEST_FAULT_STATUS`]. A clean round-trip proves the dispatch fault path no
/// longer relies on the single per-TCB `reply_to`, so a nested faulting SSN can't orphan an outer
/// caller's reply.
pub const SSN_TEST_FAULT: u64 = 0x1FFE;
/// Private executive selector for ReactOS' registered `WIN32_CALLOUTS_FPNS.BatchFlushRoutine`.
/// Real NT calls this through `KeGdiFlushUserBatch` before every win32k syscall when
/// `TEB.GdiBatchCount != 0`; it is not an SSDT service.
pub const SSN_GDI_BATCH_FLUSH_CALLOUT: u64 = 0x1FFD;
/// Un-demand-paged, demand-pageable probe VA: past the win32k image tail (0x06A2_0000, so NOT
/// flagged `in_image`) yet inside the same PD as the image, so the executive maps it with no new
/// page table. Zeroed on first touch.
pub const TEST_FAULT_VA: u64 = 0x0000_0100_06B0_0000;
/// The sentinel NTSTATUS the synthetic handler returns after surviving the fault.
pub const TEST_FAULT_STATUS: i32 = 0x600D_600Du32 as i32;
const WIN32_CALLOUT_BATCH_FLUSH_OFF: u64 = 6 * 8;

/// win32k `.data` global `gptiDesktopThread` (desktop.c:54) RVA. `IntGetAndReferenceClass(WC_DESKTOP,
/// bDesktopThread=TRUE)` (class.c:1457) reads it as the desktop thread's THREADINFO — NULL in our host
/// → the fault at RVA 0x50f94 (`mov rax,[gptiDesktopThread]; mov rax,[rax+0x58]` = pti->ppi). Derived
/// from the disasm at RVA 0x50f76 `mov rax,[rip+0x1ba5bb]` (0x50f7d + 0x1ba5bb). We point it at a
/// desktop-thread THREADINFO placeholder whose `ppi` (+0x58) is the hosted client's PROCESSINFO.
pub const GPTI_DESKTOP_THREAD_RVA: u64 = 0x20b538;
/// THREADINFO->ppi offset (confirmed by the disasm above: `mov rax,[rax+0x58]`).
const THREADINFO_PPI_OFF: u64 = 0x58;
/// PROCESSINFO->ptiList offset (win32.h: the first PROCESSINFO field after the W32PROCESS prefix).
/// Disasm-confirmed at CreateCallProc RVA 0x4dc92 (`mov r8,[pi+0xd8]` feeding
/// `UserCreateObject(ht, Desktop, pi->ptiList, …)`). Our hosted PROCESSINFO leaves it NULL, so the
/// class call-proc path deref'd a NULL thread (`pti->ppi`, pti+0x58) at RVA 0xfd3fd.
const PROCESSINFO_PTILIST_OFF: u64 = 0xD8;
/// PROCESSINFO->ptiMainThread / ->rpdeskStartup / ->hdeskStartup. These follow `ptiList` in
/// ReactOS' PROCESSINFO layout (`win32ss/user/ntuser/win32.h`). Seeding the startup desktop lets the
/// real IntSetThreadDesktop path skip the debug-only "assign it now" branch that formats
/// `peProcess->ImageFileName` out of our synthetic EPROCESS body.
const PROCESSINFO_PTIMAINTHREAD_OFF: u64 = 0xE0;
const PROCESSINFO_RPDESK_STARTUP_OFF: u64 = 0xE8;
const PROCESSINFO_HDESK_STARTUP_OFF: u64 = 0x110;
const PROCESSINFO_PRPWINSTA_OFF: u64 = 0x220;
const PROCESSINFO_HWINSTA_OFF: u64 = 0x228;
const PROCESSINFO_AMWINSTA_OFF: u64 = 0x230;
const W32PROCESS_PEPROCESS_OFF: u64 = 0x00;
const W32PROCESS_FLAGS_OFF: u64 = 0x0C;
const W32PROCESS_W32PID_OFF: u64 = 0x40;
const W32PF_READSCREENACCESSGRANTED: u32 = 0x0000_0010;
const WINSTA_ALL_ACCESS: u32 = 0x000f_037f;
/// WND->head.pti offset (ntuser.h: THRDESKHEAD at +0).
const WND_HEAD_PTI_OFF: u64 = 0x10;
const SSN_NT_USER_SET_WINDOW_LONG: u64 = 0x105b;
const SSN_NT_USER_SET_WINDOW_LONG_PTR: u64 = 0x1298;
const GWLP_WNDPROC_INDEX_U32: u64 = 0xffff_fffc;
static WIN32K_EXPLORER_SETWNDPROC_CLIENT_CALLS: AtomicU64 = AtomicU64::new(0);
static WIN32K_EXPLORER_SETWNDPROC_REPLAY_CALLS: AtomicU64 = AtomicU64::new(0);
static WIN32K_GDI_HANDLE_MISMATCH_TRACES: AtomicU64 = AtomicU64::new(0);

/// THREADINFO->rpdesk offset (win32.h: W32THREAD prefix 0x50, then ptl@0x50, ppi@0x58,
/// MessageQueue@0x60, KeyboardLayout@0x68, pcti@0x70, **rpdesk@0x78**, pDeskInfo@0x80). The thread's
/// currently-assigned DESKTOP object — `IntSetThreadDesktop` sets it (desktop.c:3428).
const THREADINFO_RPDESK_OFF: u64 = 0x78;
/// THREADINFO->pDeskInfo offset (win32.h, immediately after rpdesk). The DESKTOPINFO of the thread's
/// assigned desktop — `IntSetThreadDesktop` copies it from `rpdesk->pDeskInfo` (desktop.c:3430).
///
/// CORRECTION (BATCH 43, disasm + subagent verified): the `NtUserGetClassInfo` (0x10bd) fault at
/// executive-RVA 0x4f5e3 is NOT `pti->pDeskInfo`. Resolving the ImageBase offset (objdump VMA =
/// executive-RVA + 0x10000; win32k.sys ImageBase == 0x10000), RVA 0x4f5e3 disassembles to
/// `mov rax,[rsp+0x40]; mov rcx,[rax+0x80]; call RtlAllocateHeap` = the inlined `DesktopHeapAlloc`,
/// where `rax` is a **DESKTOP** (NULL) and `[rax+0x80]` is `DESKTOP.pheapDesktop` (see
/// [`DESKTOP_PHEAP_OFF`]) — the two just happen to collide at +0x80. The real fix is a non-NULL
/// `pti->rpdesk` (a DESKTOP with a non-NULL pheapDesktop), which the class call-proc path
/// (`UserGetCPD`, callproc.c:139) falls back to when the class has `rpdeskParent==NULL`.
const THREADINFO_PDESKINFO_OFF: u64 = 0x80;
/// THREADINFO->pClientInfo offset (win32.h, after pDeskInfo). `IntSetThreadDesktop` also updates the
/// client-side `pci->pDeskInfo` (desktop.c:3434) from this.
const THREADINFO_PCLIENTINFO_OFF: u64 = 0x88;
/// THREADINFO->hdesk offset (`win32.h`: after `exitCode`, before `cPaintsReady`). Keep it consistent
/// with `rpdesk`/`pDeskInfo` when preparing a real first `NtUserSetThreadDesktop` call.
const THREADINFO_HDESK_OFF: u64 = 0xD8;
/// THREADINFO->hEventQueueClient / ->pEventQueueServer offsets. ReactOS' `CreateThreadInfo` creates
/// a synchronization event, stores the client handle at +0x138, then references it to a server KEVENT
/// pointer at +0x140. `IntMsqSetWakeMask` returns the handle to user32 and `MsqWakeQueue` signals the
/// server pointer.
const THREADINFO_HEVENT_QUEUE_CLIENT_OFF: u64 = 0x138;
const THREADINFO_PEVENT_QUEUE_SERVER_OFF: u64 = 0x140;
/// THREADINFO->PtiLink offset, membership in DESKTOP.PtiList.
const THREADINFO_PTI_LINK_OFF: u64 = 0x148;
/// USER_MESSAGE_QUEUE offsets used by ReactOS `MsqInitializeMessageQueue`.
const USER_MESSAGE_QUEUE_PTI_MOUSE_OFF: u64 = 0x28;
const USER_MESSAGE_QUEUE_PTI_KEYBOARD_OFF: u64 = 0x30;
const USER_MESSAGE_QUEUE_HARDWARE_MESSAGES_OFF: u64 = 0x38;
const USER_MESSAGE_QUEUE_CTHREADS_OFF: u64 = 0xB0;

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

/// win32k `.data` global `NrGuiAppsRunning` (guicheck.c:17) RVA — the lazy-graphics-init gate counter.
/// `co_AddGuiApp` triggers `co_IntInitializeDesktopGraphics` only on the 0→1 transition. We READ it to
/// diagnose whether winlogon's SwitchGDI DC-op fires the lazy InitVideo (paint) or is short-circuited.
pub const NR_GUI_APPS_RUNNING_RVA: u64 = 0x20be88;
/// `gpmdev`, the active MDEV pointer populated by `PDEVOBJ_lChangeDisplaySettings`.
pub const GPMDEV_RVA: u64 = 0x20b490;
/// `PDEVOBJ_lChangeDisplaySettings` — creates the real display PDEV and its initial driver surface.
pub const PDEVOBJ_L_CHANGE_DISPLAY_SETTINGS_RVA: u64 = 0x2e100;

/// SSN NtUserSwitchDesktop — SSDT idx 0x288 (== `WIN32K_SERVICE_BASE + 0x288`).
pub const SSN_NT_USER_SWITCH_DESKTOP: u64 = 0x1288;
/// SSN NtUserRedrawWindow — SSDT idx 0x012 (w32ksvc64.h: `SVC_(UserRedrawWindow, 4) // 0x1012`).
pub const SSN_NT_USER_REDRAW_WINDOW: u64 = 0x1012;
/// SSN NtUserSetProcessWindowStation — win32k's real PROCESSINFO/EPROCESS station association.
pub const SSN_NT_USER_SET_PROCESS_WINDOW_STATION: u64 = 0x10ac;
/// `co_IntGraphicsCheck(BOOL Create)` RVA (guicheck.c) — win32k's AUTHENTIC lazy-graphics entry.
/// Disasm-confirmed for THIS build (0.4.17): prologue at 0x7a100 does
/// `W32Data = PsGetCurrentProcessWin32Process(); if (Create && !(W32PF_CREATEDWINORDC|W32PF_MANUALGUICHECK))
///  co_AddGuiApp(W32Data);` where `co_AddGuiApp` (RVA 0x7a080) sets W32PF_CREATEDWINORDC, does
/// `InterlockedIncrement(&NrGuiAppsRunning@0x20be88)` and, on the 0→1 transition, calls
/// `co_IntInitializeDesktopGraphics` (RVA 0xfca10) — the REAL InitVideo (display surface + SM_CX/CYSCREEN)
/// whose tail runs `co_IntShowDesktop(IntGetActiveDesktop(), SM_CX, SM_CY, TRUE)` = the authentic
/// IntPaintDesktop that blits 0x003a6ea5 through the selected display DLL. This is the exact call win32k makes
/// from `DceCreateDisplayDC` (windc.c:44) on the first display-DC alloc.
pub const CO_INT_GRAPHICS_CHECK_RVA: u64 = 0x7a100;

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

/// DESKTOP.pheapDesktop offset (`desktop.h` `struct _DESKTOP`: dwSessionId@0, pDeskInfo@8,
/// ListEntry@0x10, rpwinstaParent@0x20, ..., hsectionDesktop@0x78, **pheapDesktop@0x80**). The
/// per-desktop USER heap handle `DesktopHeapAlloc → RtlAllocateHeap(pdesk->pheapDesktop, ...)` uses
/// (callproc.c CreateCallProc / object.c AllocDeskProcObject). A NULL here is the REAL cr2=0x80 fault
/// at win32k RVA 0x4f5e3 (`mov rax,[rsp+0x40]=pdesk; mov rcx,[rax+0x80]=pheapDesktop; call
/// RtlAllocateHeap`). Matches `nt_object_manager::win32k_ob::desktop` (pheapDesktop@0x80).
pub const DESKTOP_PHEAP_OFF: u64 = 0x80;

/// SSN of NtUserCreateDesktop (WIN32K_SERVICE_BASE 0x1000 + SSDT idx 0x22d). When a hosted client
/// (winlogon) drives its own CreateWindowStation→CreateDesktop→SwitchDesktop chain, its
/// naturally-created DESKTOP objects come through the routed `dispatch_ssn` path; our Ob layer does
/// not populate `pdesk->rpwinstaParent` (the winsta→desktop parent linkage IntCreateDesktop would
/// set from the parse context), so we poke it after the create — exactly as the gfx-trigger's
/// `create_winsta_and_desktop` does for the Default desktop — else NtUserSwitchDesktop NULL-derefs it
/// (RVA 0x6c281→0x6c285). See the `dispatch_ssn` fixup.
pub const SSN_NT_USER_CREATE_DESKTOP: u64 = 0x122d;

/// `NtUserSetThreadDesktop` (SSN 0x1092, w32ksvc64.h) → `IntSetThreadDesktop` (desktop.c:3295), the
/// REAL thread↔desktop connection: it sets `pti->rpdesk` + `pti->pDeskInfo`. winlogon's WlxActivate
/// user thread drives it (wlx.c:1077 `SetThreadDesktop(hdeskWinlogon)`). We latch the fields it sets
/// (post-dispatch) so the per-dispatch reassert can protect `pti->pDeskInfo` for the class path.
pub const SSN_NT_USER_SET_THREAD_DESKTOP: u64 = 0x1092;

/// The IPC message label the dispatch loop uses when it `seL4_Call`s the executive to signal
/// ready/done. win32k is NOT a hosted TCB (its trampolines issue real seL4 syscalls for serial), so
/// the dispatch loop uses a genuine `seL4_Call` on its fault-endpoint cap ([`crate::CT_FAULT`]) —
/// a normal, resumable IPC (send + block for the reply), not a fault. The executive receives faults
/// AND these Calls on the same endpoint and tells them apart by the message label: fault labels are
/// small (VMFault=6, UnknownSyscall=2, …), so this distinctive value never collides.
pub const W32_DISPATCH_LABEL: u64 = 0x770;
/// A component-side `KeUserModeCallback` request issued while the outer 0x770 dispatch is active.
pub const W32_USER_CALLBACK_LABEL: u64 = 0x772;
/// Plain Send/Recv continuation signal for a component callback trampoline. Unlike the former
/// synchronous callback Call reply, this leaves the sole win32k TCB runnable as a nested-dispatch
/// receiver while the user callback executes.
pub const W32_USER_CALLBACK_RESUME_LABEL: u64 = 0x773;
/// A component-side `ZwSetSystemInformation(SystemLoadGdiDriverInformation)` request. The trampoline
/// cannot do executive-owned filesystem/capability work in win32k's VSpace, so it sends the bounded
/// driver leaf through the shared page and waits while the executive performs the real load.
pub const W32_GDI_LOAD_LABEL: u64 = 0x774;

// --- pool allocator (host-side; the trampolines run in the component) ------------------------
//
// The main win32k pool remains the known-good pure bump arena; earlier attempts to reclaim general
// pool blocks froze GUI init when reclaimed object bodies were reused across incompatible paths.
// FreeType/session-heap churn is reclaimed by dedicated allocators below, where ownership is clear.

unsafe fn pool_alloc(size: u64) -> u64 {
    let ctr = WIN32K_POOL_VADDR as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    let start = (WIN32K_POOL_VADDR + cur + 15) & !15;
    let cap = WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000;
    if size == 0 || start + size > cap {
        crate::WIN32K_POOL_EXHAUSTIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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

/// A SEPARATE arena for FreeType (ftfd) allocations. FreeType's ReactOS glue allocates through
/// `EngAllocMem(TAG_FREETYPE)` and frees through `EngFreeMem`, so unlike the main win32k pool this
/// arena must reclaim blocks or each GUI client consumes the whole window while probing fonts.
/// Counter at +0, address-ordered free-list head at +8, payload starts at +0x1000.
pub const WIN32K_FTYP_VADDR: u64 = 0x0000_0100_0B00_0000;
pub const WIN32K_FTYP_FRAMES: u64 = 512; // 2 MiB (own window, pre-mapped)
/// FreeType's `EngAllocMem` tag ('FTYP', little-endian) — see the ftfd ft_alloc disasm.
pub const FTYP_TAG: u64 = 0x5059_5446;

const FTYP_HDR_SIZE: u64 = 16;
const FTYP_ALLOC_MARKER: u64 = 0xffff_ffff_ffff_fffe;

fn align16(size: u64) -> u64 {
    (size + 15) & !15
}

unsafe fn ftyp_alloc(size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    let want = align16(size);
    let head = (WIN32K_FTYP_VADDR + 8) as *mut u64;
    let mut prev = 0u64;
    let mut cur = read_volatile(head);
    let mut scanned = 0usize;
    while cur != 0 && scanned < 4096 {
        let cap = read_volatile(cur as *const u64);
        let next = read_volatile((cur + 8) as *const u64);
        if cap >= want {
            if prev == 0 {
                write_volatile(head, next);
            } else {
                write_volatile((prev + 8) as *mut u64, next);
            }
            if cap >= want + FTYP_HDR_SIZE + 16 {
                let split = cur + FTYP_HDR_SIZE + want;
                write_volatile(split as *mut u64, cap - want - FTYP_HDR_SIZE);
                write_volatile((split + 8) as *mut u64, next);
                if prev == 0 {
                    write_volatile(head, split);
                } else {
                    write_volatile((prev + 8) as *mut u64, split);
                }
                write_volatile(cur as *mut u64, want);
            }
            write_volatile((cur + 8) as *mut u64, FTYP_ALLOC_MARKER);
            return cur + FTYP_HDR_SIZE;
        }
        prev = cur;
        cur = next;
        scanned += 1;
    }

    let ctr = WIN32K_FTYP_VADDR as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    let hdr = align16(WIN32K_FTYP_VADDR + cur);
    let cap = WIN32K_FTYP_VADDR + WIN32K_FTYP_FRAMES * 0x1000;
    if hdr + FTYP_HDR_SIZE + want > cap {
        return 0; // OOM → FreeType truncates gracefully (matches the baseline)
    }
    write_volatile(ctr, (hdr + FTYP_HDR_SIZE + want) - WIN32K_FTYP_VADDR);
    write_volatile(hdr as *mut u64, want);
    write_volatile((hdr + 8) as *mut u64, FTYP_ALLOC_MARKER);
    hdr + FTYP_HDR_SIZE
}

unsafe fn ftyp_free(p: u64) {
    let arena_start = WIN32K_FTYP_VADDR + POOL_DATA_OFF;
    let arena_end = WIN32K_FTYP_VADDR + WIN32K_FTYP_FRAMES * 0x1000;
    if p < arena_start + FTYP_HDR_SIZE || p >= arena_end || (p & 15) != 0 {
        return;
    }
    let hdr = p - FTYP_HDR_SIZE;
    let cap = read_volatile(hdr as *const u64);
    let marker = read_volatile((hdr + 8) as *const u64);
    if marker != FTYP_ALLOC_MARKER || cap == 0 || (cap & 15) != 0 {
        return;
    }
    if hdr < arena_start || hdr + FTYP_HDR_SIZE + cap > arena_end {
        return;
    }

    let head = (WIN32K_FTYP_VADDR + 8) as *mut u64;
    let mut prev = 0u64;
    let mut cur = read_volatile(head);
    let mut scanned = 0usize;
    while cur != 0 && cur < hdr && scanned < 4096 {
        prev = cur;
        cur = read_volatile((cur + 8) as *const u64);
        scanned += 1;
    }
    if scanned >= 4096 {
        return;
    }

    write_volatile(hdr as *mut u64, cap);
    write_volatile((hdr + 8) as *mut u64, cur);
    if prev == 0 {
        write_volatile(head, hdr);
    } else {
        write_volatile((prev + 8) as *mut u64, hdr);
    }

    let mut block = hdr;
    let mut block_cap = cap;
    if cur != 0 && block + FTYP_HDR_SIZE + block_cap == cur {
        let cur_cap = read_volatile(cur as *const u64);
        let cur_next = read_volatile((cur + 8) as *const u64);
        block_cap += FTYP_HDR_SIZE + cur_cap;
        write_volatile(block as *mut u64, block_cap);
        write_volatile((block + 8) as *mut u64, cur_next);
    }
    if prev != 0 {
        let prev_cap = read_volatile(prev as *const u64);
        if prev + FTYP_HDR_SIZE + prev_cap == block {
            let next = read_volatile((block + 8) as *const u64);
            block = prev;
            block_cap += FTYP_HDR_SIZE + prev_cap;
            write_volatile(block as *mut u64, block_cap);
            write_volatile((block + 8) as *mut u64, next);
        }
    }

    let ctr = WIN32K_FTYP_VADDR as *mut u64;
    let high = WIN32K_FTYP_VADDR + read_volatile(ctr);
    if block + FTYP_HDR_SIZE + block_cap == high {
        let mut list_prev = 0u64;
        let mut list_cur = read_volatile(head);
        let mut scanned = 0usize;
        while list_cur != 0 && list_cur != block && scanned < 4096 {
            list_prev = list_cur;
            list_cur = read_volatile((list_cur + 8) as *const u64);
            scanned += 1;
        }
        if list_cur == block {
            let next = read_volatile((block + 8) as *const u64);
            if list_prev == 0 {
                write_volatile(head, next);
            } else {
                write_volatile((list_prev + 8) as *mut u64, next);
            }
            write_volatile(ctr, block - WIN32K_FTYP_VADDR);
        }
    }
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
/// Own 2 MiB PT window at 0x06E0 (free in both VSpaces: after the win32k image window, before AUX_PT 0x0700).
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
extern "win64" fn s_void() {}

const STATUS_INVALID_PARAMETER_I32: i32 = 0xC000_000Du32 as i32;
const STATUS_NO_TOKEN_I32: i32 = 0xC000_007Cu32 as i32;
const STATUS_ACCESS_VIOLATION_I32: i32 = 0xC000_0005u32 as i32;
const STATUS_INVALID_HANDLE_I32: i32 = 0xC000_0008u32 as i32;
const STATUS_BUFFER_TOO_SMALL_I32: i32 = 0xC000_0023u32 as i32;
const STATUS_INVALID_INFO_CLASS_I32: i32 = 0xC000_0003u32 as i32;
const STATUS_UNKNOWN_REVISION_I32: i32 = 0xC000_0058u32 as i32;
const STATUS_REVISION_MISMATCH_I32: i32 = 0xC000_0059u32 as i32;
const STATUS_INVALID_ACL_I32: i32 = 0xC000_0077u32 as i32;
const STATUS_INVALID_SID_I32: i32 = 0xC000_0078u32 as i32;
const STATUS_INVALID_SECURITY_DESCR_I32: i32 = 0xC000_0079u32 as i32;
const STATUS_ALLOTTED_SPACE_EXCEEDED_I32: i32 = 0xC000_0099u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES_I32: i32 = 0xC000_009Au32 as i32;
const STATUS_BAD_DESCRIPTOR_FORMAT_I32: i32 = 0xC000_00E7u32 as i32;
const WIN32K_PRIMARY_TOKEN_MAGIC: u64 = 0x544f_4b45_4e4c_5549; // "TOKENLUI"
const WIN32K_PRIMARY_TOKEN_BYTES: u64 = 0x70;
const TOKEN_AUTHENTICATION_ID_OFF: u64 = 0x08;
const TOKEN_EPROCESS_OFF: u64 = 0x10;
const TOKEN_PID_OFF: u64 = 0x18;
const TOKEN_USER_SID_LEN_OFF: u64 = 0x20;
const TOKEN_USER_SID_OFF: u64 = 0x28;
const TOKEN_INFORMATION_CLASS_USER: u64 = 1;
const TOKEN_QUERY_ACCESS: u64 = 0x0008;
const WIN32K_TOKEN_HANDLE_BASE: u64 = 0x0000_0000_5E70_0000;
const WIN32K_TOKEN_HANDLE_CAP: usize = 16;
const SECURITY_DESCRIPTOR_REVISION_U64: u64 = 1;
const SECURITY_DESCRIPTOR_ABSOLUTE_BYTES: usize = 0x28;
const SECURITY_DESCRIPTOR_RELATIVE_BYTES: usize = 0x14;
const SD_CONTROL_OFF: u64 = 0x02;
const SD_OWNER_OFF: u64 = 0x08;
const SD_GROUP_OFF: u64 = 0x10;
const SD_SACL_OFF: u64 = 0x18;
const SD_DACL_OFF: u64 = 0x20;
const SD_REL_OWNER_OFF: u64 = 0x04;
const SD_REL_GROUP_OFF: u64 = 0x08;
const SD_REL_SACL_OFF: u64 = 0x0C;
const SD_REL_DACL_OFF: u64 = 0x10;
const SE_OWNER_DEFAULTED: u16 = 0x0001;
const SE_GROUP_DEFAULTED: u16 = 0x0002;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_DEFAULTED: u16 = 0x0008;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;
const ACL_HEADER_BYTES: usize = 8;
const ACL_REVISION_MIN: u64 = 2;
const ACL_REVISION_MAX: u64 = 4;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const KNOWN_ACE_HEADER_BYTES: usize = 8; // ACE_HEADER + ACCESS_MASK; SidStart follows.
const SID_HEADER_BYTES: usize = 8;
const SID_MAX_SUB_AUTHORITIES: usize = 15;
const VALID_INHERIT_FLAGS: u64 = 0x1F;

fn local_system_sid_native() -> ([u8; WIN32K_TOKEN_USER_SID_MAX], usize) {
    let mut sid = [0u8; WIN32K_TOKEN_USER_SID_MAX];
    let len = nt_security::Sid::local_system()
        .write_native(&mut sid)
        .unwrap_or(0);
    (sid, len)
}

fn native_sid_len(sid: &[u8], supplied_len: usize) -> Option<usize> {
    if supplied_len < 8 || supplied_len > WIN32K_TOKEN_USER_SID_MAX || supplied_len > sid.len() {
        return None;
    }
    if sid[0] != 1 {
        return None;
    }
    let subauths = sid[1] as usize;
    if subauths > 15 {
        return None;
    }
    let expected = 8usize.checked_add(subauths.checked_mul(4)?)?;
    (expected == supplied_len).then_some(expected)
}

unsafe fn record_process_token_context(
    process_index: usize,
    token_authentication_id: u64,
    token_user_sid: &[u8],
    token_user_sid_len: usize,
) -> bool {
    let token_user_sid_len = native_sid_len(token_user_sid, token_user_sid_len).unwrap_or(0);
    if process_index >= WIN32K_GUI_PROCESS_CAP
        || token_authentication_id == 0
        || token_user_sid_len == 0
        || token_user_sid_len > WIN32K_TOKEN_USER_SID_MAX
        || token_user_sid_len > token_user_sid.len()
    {
        let n = WIN32K_CLIENT_TOKEN_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            let pid = if process_index < WIN32K_GUI_PROCESS_CAP {
                WIN32K_PROCESS_CTX_PIDS[process_index].load(Ordering::Relaxed)
            } else {
                0
            };
            print_str(b"[win32k-token] ERROR: missing primary-token AuthenticationId pid=");
            print_u64(pid);
            print_str(b" process-index=");
            print_u64(process_index as u64);
            print_str(b" sid-len=");
            print_u64(token_user_sid_len as u64);
            print_str(b"\n");
        }
        return false;
    }
    WIN32K_PROCESS_CTX_TOKEN_AUTH[process_index].store(token_authentication_id, Ordering::Relaxed);

    let token = ensure_primary_token_object(process_index);
    if token == 0 {
        return false;
    }
    write_volatile(
        (token + TOKEN_USER_SID_LEN_OFF) as *mut u64,
        token_user_sid_len as u64,
    );
    let sid_base = (token + TOKEN_USER_SID_OFF) as *mut u8;
    let mut i = 0usize;
    while i < WIN32K_TOKEN_USER_SID_MAX {
        let byte = if i < token_user_sid_len {
            token_user_sid[i]
        } else {
            0
        };
        write_volatile(sid_base.add(i), byte);
        i += 1;
    }
    true
}

unsafe fn ensure_primary_token_object(process_index: usize) -> u64 {
    if process_index >= WIN32K_GUI_PROCESS_CAP {
        return 0;
    }
    let token_authentication_id =
        WIN32K_PROCESS_CTX_TOKEN_AUTH[process_index].load(Ordering::Relaxed);
    if token_authentication_id == 0 {
        return 0;
    }
    let existing = WIN32K_PROCESS_CTX_PRIMARY_TOKEN[process_index].load(Ordering::Relaxed);
    let token = if existing != 0 {
        existing
    } else {
        let allocated = allocate_kernel_object_body(WIN32K_PRIMARY_TOKEN_BYTES);
        if allocated == 0 {
            return 0;
        }
        write_volatile(allocated as *mut u64, WIN32K_PRIMARY_TOKEN_MAGIC);
        WIN32K_PROCESS_CTX_PRIMARY_TOKEN[process_index].store(allocated, Ordering::Relaxed);
        allocated
    };
    write_volatile(
        (token + TOKEN_AUTHENTICATION_ID_OFF) as *mut u64,
        token_authentication_id,
    );
    write_volatile(
        (token + TOKEN_EPROCESS_OFF) as *mut u64,
        WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed),
    );
    write_volatile(
        (token + TOKEN_PID_OFF) as *mut u64,
        WIN32K_PROCESS_CTX_PIDS[process_index].load(Ordering::Relaxed),
    );
    token
}

unsafe fn token_context_index(token: u64) -> Option<usize> {
    if token == 0 {
        return None;
    }
    for index in 0..WIN32K_GUI_PROCESS_CAP {
        if WIN32K_PROCESS_CTX_PRIMARY_TOKEN[index].load(Ordering::Relaxed) == token {
            if read_volatile(token as *const u64) != WIN32K_PRIMARY_TOKEN_MAGIC {
                return None;
            }
            return Some(index);
        }
    }
    None
}

unsafe fn primary_token_authentication_id(token: u64) -> Option<u64> {
    token_context_index(token).and_then(|_| {
        let auth = read_volatile((token + TOKEN_AUTHENTICATION_ID_OFF) as *const u64);
        (auth != 0).then_some(auth)
    })
}

unsafe fn primary_token_user_sid(
    token: u64,
    out: &mut [u8; WIN32K_TOKEN_USER_SID_MAX],
) -> Option<usize> {
    token_context_index(token)?;
    let len = read_volatile((token + TOKEN_USER_SID_LEN_OFF) as *const u64) as usize;
    if len == 0 || len > WIN32K_TOKEN_USER_SID_MAX {
        return None;
    }
    let sid_base = (token + TOKEN_USER_SID_OFF) as *const u8;
    let mut i = 0usize;
    while i < WIN32K_TOKEN_USER_SID_MAX {
        out[i] = if i < len {
            read_volatile(sid_base.add(i))
        } else {
            0
        };
        i += 1;
    }
    Some(len)
}

unsafe fn token_handle_slot(handle: u64) -> Option<usize> {
    let index = handle.checked_sub(WIN32K_TOKEN_HANDLE_BASE)? / 4;
    (index < WIN32K_TOKEN_HANDLE_CAP as u64).then_some(index as usize)
}

unsafe fn register_token_handle(token: u64) -> u64 {
    if token_context_index(token).is_none() {
        return 0;
    }
    for index in 0..WIN32K_TOKEN_HANDLE_CAP {
        if WIN32K_TOKEN_HANDLE_TOKENS[index].load(Ordering::Relaxed) == 0 {
            let handle = WIN32K_TOKEN_HANDLE_BASE + (index as u64) * 4;
            WIN32K_TOKEN_HANDLE_TOKENS[index].store(token, Ordering::Relaxed);
            return handle;
        }
    }
    0
}

unsafe fn token_for_handle(handle: u64) -> Option<u64> {
    let slot = token_handle_slot(handle)?;
    let token = WIN32K_TOKEN_HANDLE_TOKENS[slot].load(Ordering::Relaxed);
    (token_context_index(token).is_some()).then_some(token)
}

unsafe fn close_token_handle(handle: u64) -> bool {
    let Some(slot) = token_handle_slot(handle) else {
        return false;
    };
    WIN32K_TOKEN_HANDLE_TOKENS[slot].swap(0, Ordering::Relaxed) != 0
}

fn round_up4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|v| v & !3)
}

unsafe fn zero_component_bytes(dst: u64, len: usize) {
    let mut i = 0usize;
    while i < len {
        write_volatile((dst + i as u64) as *mut u8, 0);
        i += 1;
    }
}

unsafe fn copy_component_bytes(dst: u64, src: u64, len: usize) {
    let mut i = 0usize;
    while i < len {
        let byte = read_volatile((src + i as u64) as *const u8);
        write_volatile((dst + i as u64) as *mut u8, byte);
        i += 1;
    }
}

unsafe fn sid_len_from_ptr(sid: u64) -> Option<usize> {
    if sid == 0 {
        return None;
    }
    let revision = read_volatile(sid as *const u8);
    let subauths = read_volatile((sid + 1) as *const u8) as usize;
    if revision != 1 || subauths > SID_MAX_SUB_AUTHORITIES {
        return None;
    }
    SID_HEADER_BYTES.checked_add(subauths.checked_mul(4)?)
}

unsafe fn acl_size_from_ptr(acl: u64) -> Option<usize> {
    if acl == 0 {
        return None;
    }
    let revision = read_volatile(acl as *const u8) as u64;
    let size = read_unaligned((acl + 2) as *const u16) as usize;
    if !(ACL_REVISION_MIN..=ACL_REVISION_MAX).contains(&revision) || size < ACL_HEADER_BYTES {
        return None;
    }
    Some(size)
}

unsafe fn acl_first_free_offset(acl: u64) -> Option<usize> {
    let acl_size = acl_size_from_ptr(acl)?;
    let ace_count = read_unaligned((acl + 4) as *const u16) as usize;
    let mut offset = ACL_HEADER_BYTES;
    let mut index = 0usize;
    while index < ace_count {
        if offset.checked_add(4)? > acl_size {
            return None;
        }
        let ace_size = read_unaligned((acl + offset as u64 + 2) as *const u16) as usize;
        if ace_size < 4 || offset.checked_add(ace_size)? > acl_size {
            return None;
        }
        offset += ace_size;
        index += 1;
    }
    Some(offset)
}

unsafe fn sd_component_len_sid(ptr: u64) -> Option<usize> {
    if ptr == 0 {
        return Some(0);
    }
    round_up4(sid_len_from_ptr(ptr)?)
}

unsafe fn sd_component_len_acl(ptr: u64) -> Option<usize> {
    if ptr == 0 {
        return Some(0);
    }
    round_up4(acl_size_from_ptr(ptr)?)
}

/// `NTSTATUS RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR, ULONG)`.
extern "win64" fn s_rtl_create_security_descriptor(sd: u64, revision: u64) -> i32 {
    if sd == 0 {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    if revision != SECURITY_DESCRIPTOR_REVISION_U64 {
        return STATUS_UNKNOWN_REVISION_I32;
    }
    unsafe {
        zero_component_bytes(sd, SECURITY_DESCRIPTOR_ABSOLUTE_BYTES);
        write_volatile(sd as *mut u8, SECURITY_DESCRIPTOR_REVISION_U64 as u8);
    }
    0
}

/// `ULONG RtlLengthSid(PSID)`.
extern "win64" fn s_rtl_length_sid(sid: u64) -> u64 {
    unsafe { sid_len_from_ptr(sid).unwrap_or(0) as u64 }
}

/// `NTSTATUS RtlCreateAcl(PACL, ULONG, ULONG)`.
extern "win64" fn s_rtl_create_acl(acl: u64, acl_size: u64, acl_revision: u64) -> i32 {
    if acl == 0 {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    if acl_size < ACL_HEADER_BYTES as u64 {
        return STATUS_BUFFER_TOO_SMALL_I32;
    }
    if !(ACL_REVISION_MIN..=ACL_REVISION_MAX).contains(&acl_revision) || acl_size > u16::MAX as u64
    {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Some(rounded_size) = round_up4(acl_size as usize) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    if rounded_size > u16::MAX as usize {
        return STATUS_INVALID_PARAMETER_I32;
    }
    unsafe {
        write_volatile(acl as *mut u8, acl_revision as u8);
        write_volatile((acl + 1) as *mut u8, 0);
        write_unaligned((acl + 2) as *mut u16, rounded_size as u16);
        write_unaligned((acl + 4) as *mut u16, 0);
        write_unaligned((acl + 6) as *mut u16, 0);
    }
    0
}

/// `NTSTATUS RtlAddAccessAllowedAceEx(PACL, ULONG, ULONG, ACCESS_MASK, PSID)`.
extern "win64" fn s_rtl_add_access_allowed_ace_ex(
    acl: u64,
    revision: u64,
    flags: u64,
    access_mask: u64,
    sid: u64,
) -> i32 {
    if acl == 0 {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    let Some(sid_len) = (unsafe { sid_len_from_ptr(sid) }) else {
        return STATUS_INVALID_SID_I32;
    };
    unsafe {
        let acl_revision = read_volatile(acl as *const u8) as u64;
        if acl_revision > ACL_REVISION_MAX || revision > ACL_REVISION_MAX {
            return STATUS_REVISION_MISMATCH_I32;
        }
        if acl_revision < ACL_REVISION_MIN {
            return STATUS_INVALID_ACL_I32;
        }
        if flags & !VALID_INHERIT_FLAGS != 0 {
            return STATUS_INVALID_PARAMETER_I32;
        }
        let Some(acl_size) = acl_size_from_ptr(acl) else {
            return STATUS_INVALID_ACL_I32;
        };
        let Some(first_free) = acl_first_free_offset(acl) else {
            return STATUS_INVALID_ACL_I32;
        };
        let Some(ace_size) = sid_len.checked_add(KNOWN_ACE_HEADER_BYTES) else {
            return STATUS_ALLOTTED_SPACE_EXCEEDED_I32;
        };
        if first_free.checked_add(ace_size).unwrap_or(usize::MAX) > acl_size {
            return STATUS_ALLOTTED_SPACE_EXCEEDED_I32;
        }
        let ace = acl + first_free as u64;
        write_volatile(ace as *mut u8, ACCESS_ALLOWED_ACE_TYPE);
        write_volatile((ace + 1) as *mut u8, flags as u8);
        write_unaligned((ace + 2) as *mut u16, ace_size as u16);
        write_unaligned((ace + 4) as *mut u32, access_mask as u32);
        copy_component_bytes(ace + KNOWN_ACE_HEADER_BYTES as u64, sid, sid_len);

        let ace_count = read_unaligned((acl + 4) as *const u16);
        write_unaligned((acl + 4) as *mut u16, ace_count.wrapping_add(1));
        if revision > acl_revision {
            write_volatile(acl as *mut u8, revision as u8);
        }
    }
    0
}

/// `NTSTATUS RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR, BOOLEAN, PACL, BOOLEAN)`.
extern "win64" fn s_rtl_set_dacl_security_descriptor(
    sd: u64,
    dacl_present: u64,
    dacl: u64,
    dacl_defaulted: u64,
) -> i32 {
    if sd == 0 {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    unsafe {
        if read_volatile(sd as *const u8) as u64 != SECURITY_DESCRIPTOR_REVISION_U64 {
            return STATUS_UNKNOWN_REVISION_I32;
        }
        let mut control = read_unaligned((sd + SD_CONTROL_OFF) as *const u16);
        if dacl_present != 0 {
            control |= SE_DACL_PRESENT;
            write_unaligned((sd + SD_DACL_OFF) as *mut u64, dacl);
        } else {
            control &= !SE_DACL_PRESENT;
            write_unaligned((sd + SD_DACL_OFF) as *mut u64, 0);
        }
        if dacl_defaulted != 0 {
            control |= SE_DACL_DEFAULTED;
        } else {
            control &= !SE_DACL_DEFAULTED;
        }
        write_unaligned((sd + SD_CONTROL_OFF) as *mut u16, control);
    }
    0
}

/// `NTSTATUS RtlSetOwnerSecurityDescriptor(PSECURITY_DESCRIPTOR, PSID, BOOLEAN)`.
extern "win64" fn s_rtl_set_owner_security_descriptor(
    sd: u64,
    owner: u64,
    owner_defaulted: u64,
) -> i32 {
    if sd == 0 {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    unsafe {
        if read_volatile(sd as *const u8) as u64 != SECURITY_DESCRIPTOR_REVISION_U64 {
            return STATUS_UNKNOWN_REVISION_I32;
        }
        let mut control = read_unaligned((sd + SD_CONTROL_OFF) as *const u16);
        if owner_defaulted != 0 {
            control |= SE_OWNER_DEFAULTED;
        } else {
            control &= !SE_OWNER_DEFAULTED;
        }
        write_unaligned((sd + SD_OWNER_OFF) as *mut u64, owner);
        write_unaligned((sd + SD_CONTROL_OFF) as *mut u16, control);
    }
    0
}

/// `NTSTATUS RtlSetGroupSecurityDescriptor(PSECURITY_DESCRIPTOR, PSID, BOOLEAN)`.
extern "win64" fn s_rtl_set_group_security_descriptor(
    sd: u64,
    group: u64,
    group_defaulted: u64,
) -> i32 {
    if sd == 0 {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    unsafe {
        if read_volatile(sd as *const u8) as u64 != SECURITY_DESCRIPTOR_REVISION_U64 {
            return STATUS_UNKNOWN_REVISION_I32;
        }
        let mut control = read_unaligned((sd + SD_CONTROL_OFF) as *const u16);
        if group_defaulted != 0 {
            control |= SE_GROUP_DEFAULTED;
        } else {
            control &= !SE_GROUP_DEFAULTED;
        }
        write_unaligned((sd + SD_GROUP_OFF) as *mut u64, group);
        write_unaligned((sd + SD_CONTROL_OFF) as *mut u16, control);
    }
    0
}

/// `NTSTATUS RtlAbsoluteToSelfRelativeSD(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG)`.
extern "win64" fn s_rtl_absolute_to_self_relative_sd(
    absolute_sd: u64,
    self_relative_sd: u64,
    buffer_length: *mut u32,
) -> i32 {
    if absolute_sd == 0 || buffer_length.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    unsafe {
        if read_volatile(absolute_sd as *const u8) as u64 != SECURITY_DESCRIPTOR_REVISION_U64 {
            return STATUS_UNKNOWN_REVISION_I32;
        }
        let control = read_unaligned((absolute_sd + SD_CONTROL_OFF) as *const u16);
        if control & SE_SELF_RELATIVE != 0 {
            return STATUS_BAD_DESCRIPTOR_FORMAT_I32;
        }

        let owner = read_unaligned((absolute_sd + SD_OWNER_OFF) as *const u64);
        let group = read_unaligned((absolute_sd + SD_GROUP_OFF) as *const u64);
        let sacl = read_unaligned((absolute_sd + SD_SACL_OFF) as *const u64);
        let dacl = read_unaligned((absolute_sd + SD_DACL_OFF) as *const u64);
        let Some(owner_len) = sd_component_len_sid(owner) else {
            return STATUS_INVALID_SID_I32;
        };
        let Some(group_len) = sd_component_len_sid(group) else {
            return STATUS_INVALID_SID_I32;
        };
        let Some(sacl_len) = sd_component_len_acl(sacl) else {
            return STATUS_INVALID_ACL_I32;
        };
        let Some(dacl_len) = sd_component_len_acl(dacl) else {
            return STATUS_INVALID_ACL_I32;
        };
        let Some(total_len) = SECURITY_DESCRIPTOR_RELATIVE_BYTES
            .checked_add(owner_len)
            .and_then(|v| v.checked_add(group_len))
            .and_then(|v| v.checked_add(sacl_len))
            .and_then(|v| v.checked_add(dacl_len))
        else {
            return STATUS_ALLOTTED_SPACE_EXCEEDED_I32;
        };

        let caller_len = read_unaligned(buffer_length);
        if caller_len < total_len as u32 {
            write_unaligned(buffer_length, total_len as u32);
            return STATUS_BUFFER_TOO_SMALL_I32;
        }
        if self_relative_sd == 0 {
            return STATUS_ACCESS_VIOLATION_I32;
        }

        zero_component_bytes(self_relative_sd, total_len);
        copy_component_bytes(self_relative_sd, absolute_sd, 4);
        let mut current = SECURITY_DESCRIPTOR_RELATIVE_BYTES;
        if sacl_len != 0 {
            copy_component_bytes(self_relative_sd + current as u64, sacl, sacl_len);
            write_unaligned(
                (self_relative_sd + SD_REL_SACL_OFF) as *mut u32,
                current as u32,
            );
            current += sacl_len;
        }
        if dacl_len != 0 {
            copy_component_bytes(self_relative_sd + current as u64, dacl, dacl_len);
            write_unaligned(
                (self_relative_sd + SD_REL_DACL_OFF) as *mut u32,
                current as u32,
            );
            current += dacl_len;
        }
        if owner_len != 0 {
            copy_component_bytes(self_relative_sd + current as u64, owner, owner_len);
            write_unaligned(
                (self_relative_sd + SD_REL_OWNER_OFF) as *mut u32,
                current as u32,
            );
            current += owner_len;
        }
        if group_len != 0 {
            copy_component_bytes(self_relative_sd + current as u64, group, group_len);
            write_unaligned(
                (self_relative_sd + SD_REL_GROUP_OFF) as *mut u32,
                current as u32,
            );
        }
        let rel_control = control | SE_SELF_RELATIVE;
        write_unaligned((self_relative_sd + SD_CONTROL_OFF) as *mut u16, rel_control);
        write_unaligned(buffer_length, total_len as u32);
    }
    0
}

/// `NTSTATUS SeQueryAuthenticationIdToken(PACCESS_TOKEN Token, PLUID AuthenticationId)`.
///
/// win32k's `GetProcessLuid` obtains `Process->Token` through `PsReferencePrimaryToken` and then
/// calls this routine. The executive serializes the selected process's real ProcessManager primary
/// token AuthenticationId into the win32k dispatch request; the component exposes that metadata as a
/// kernel token object and fails visibly for unknown token pointers.
extern "win64" fn s_se_query_authentication_id_token(token: u64, luid_out: *mut u32) -> i32 {
    if luid_out.is_null() {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Some(auth) = (unsafe { primary_token_authentication_id(token) }) else {
        return STATUS_NO_TOKEN_I32;
    };
    // SAFETY: luid_out is win32k's stack-local &LUID (2 x u32); the component stack is mapped.
    unsafe {
        write_unaligned(luid_out, auth as u32);
        write_unaligned(luid_out.add(1), (auth >> 32) as u32);
    }
    0 // STATUS_SUCCESS
}

/// `void SeCaptureSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext)`. Snapshot the caller's
/// security identity into `SubjectContext` from the currently selected process primary token.
extern "win64" fn s_se_capture_subject_context(ctx: *mut u8) {
    if !ctx.is_null() {
        // SAFETY: ctx is win32k's stack-local SECURITY_SUBJECT_CONTEXT (0x20 bytes); stack is mapped.
        unsafe {
            let primary = current_process_context_index()
                .map(|index| ensure_primary_token_object(index))
                .unwrap_or(0);
            nt_security::se_exports::capture_system_subject_context(ctx, primary);
        }
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

/// `KTHREAD::Win32Thread` — the per-thread win32k state pointer, which real NT stores **in the
/// thread object** (`PsSetThreadWin32Thread` = `InterlockedExchangePointer(&Thread->Tcb.Win32Thread,
/// …)`, `ntoskrnl/ps/thread.c:909`) and which `PsGetCurrentThreadWin32Thread()` reads back.
///
/// The MSVC win32k build **inlines that read**: `NtUserCallNoParam(NOPARAM_ROUTINE_DESTROY_CARET)`
/// compiles to `call PsGetCurrentThread; mov rcx,[rax+0x250]; call co_IntDestroyCaret`
/// (win32k RVA `0xd3a25`), and `co_IntDestroyCaret` immediately does `pti->MessageQueue` (+0x60).
/// With the slot written ONLY to the executive's side cell, that inline read returned NULL and the
/// hosted win32k took a `#PF` at `cr2 = 0x60` the moment the logon dialog tore down — the first
/// thing the real `EndDialog(WLX_SAS_ACTION_LOGON)` path does after a SUCCESSFUL logon. Three other
/// `[reg+0x250]` reads exist in the image and none of them stores, confirming the field is written
/// by the kernel side alone.
const KTHREAD_WIN32THREAD_OFF: u64 = 0x250;
/// `KTHREAD::Teb` (ReactOS Win2003 x64 profile). `InitThreadCallback` uses `NtCurrentTeb()`, but
/// other win32k paths also recover the TEB through the current thread object.
const KTHREAD_TEB_OFF: u64 = 0xB0;
/// `KTHREAD::Process` (embedded `KPROCESS`) points at the owning process body.
const KTHREAD_PROCESS_OFF: u64 = 0x200;
/// `ETHREAD::Cid` in the staged ReactOS x64 win32k image. The checked build reads
/// `Thread->Cid.UniqueThread` at +0x380 in `InitThreadCallback`'s failure trace path.
const ETHREAD_CID_OFF: u64 = 0x378;
const ETHREAD_CID_UNIQUE_PROCESS_OFF: u64 = ETHREAD_CID_OFF;
const ETHREAD_CID_UNIQUE_THREAD_OFF: u64 = ETHREAD_CID_OFF + 8;
/// `ETHREAD::ThreadsProcess`, the field ReactOS `InitThreadCallback` reads before attaching a GUI
/// thread to its process `PROCESSINFO`. Disassembly of this win32k build loads it from +0x3d8.
const ETHREAD_THREADS_PROCESS_OFF: u64 = 0x3D8;
const TEB_SELF_OFF: u64 = 0x30;
const TEB_CLIENT_ID_PROCESS_OFF: u64 = 0x40;
const TEB_CLIENT_ID_THREAD_OFF: u64 = 0x48;
const TEB_PROCESS_ENVIRONMENT_BLOCK_OFF: u64 = 0x60;
const PEB_PROCESS_PARAMETERS_OFF: u64 = 0x20;
const PS_W32_THREAD_CALLOUT_INITIALIZE: u64 = 0;
/// ReactOS Win2003 x64 `EPROCESS` offsets used by win32k's process/thread callouts.
const EPROCESS_UNIQUE_PROCESS_ID_OFF: u64 = 0xD0;
const EPROCESS_WIN32PROCESS_OFF: u64 = 0x1D8;
#[allow(dead_code)]
const EPROCESS_SECTION_BASE_ADDRESS_OFF: u64 = 0x1F0;
const EPROCESS_WIN32_WINDOW_STATION_OFF: u64 = 0x208;
#[allow(dead_code)]
const EPROCESS_SESSION_OFF: u64 = 0x258;
const EPROCESS_PEB_OFF: u64 = 0x2B8;

/// `PEPROCESS IoGetCurrentProcess()` / `PsGetCurrentProcess()` — the selected client's EPROCESS
/// body, resolved through the PID-keyed GUI runtime record.
extern "win64" fn s_current_process() -> u64 {
    unsafe { current_eprocess() }
}
extern "win64" fn s_current_thread() -> u64 {
    unsafe { current_ethread() }
}
/// `HANDLE PsGetProcessId(PEPROCESS Process)` — resolve a process body back to its selected PID.
extern "win64" fn s_ps_get_process_id(process: u64) -> u64 {
    unsafe {
        process_context_index_for_eprocess(process)
            .map(|index| WIN32K_PROCESS_CTX_PIDS[index].load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// `HANDLE PsGetCurrentThreadId()` — the routed client's current TID.
extern "win64" fn s_ps_get_current_thread_id() -> u64 {
    WIN32K_CURRENT_THREAD_ID.load(Ordering::Relaxed)
}

/// `HANDLE PsGetThreadId(PETHREAD Thread)` — resolve a thread body back to its selected TID.
extern "win64" fn s_ps_get_thread_id(thread: u64) -> u64 {
    unsafe {
        if let Some(index) = thread_context_index_for_ethread(thread) {
            return WIN32K_THREAD_CTX_TIDS[index].load(Ordering::Relaxed);
        }
        if thread != 0 {
            read_volatile((thread + ETHREAD_CID_UNIQUE_THREAD_OFF) as *const u64)
        } else {
            0
        }
    }
}

/// `HANDLE PsGetThreadProcessId(PETHREAD Thread)` — resolve a thread body to its owning PID.
extern "win64" fn s_ps_get_thread_process_id(thread: u64) -> u64 {
    unsafe {
        if let Some(index) = thread_context_index_for_ethread(thread) {
            return WIN32K_THREAD_CTX_PIDS[index].load(Ordering::Relaxed);
        }
        if thread != 0 {
            read_volatile((thread + ETHREAD_CID_UNIQUE_PROCESS_OFF) as *const u64)
        } else {
            0
        }
    }
}

/// `PEPROCESS PsGetThreadProcess(PETHREAD Thread)` — return the owning process object for a known
/// ETHREAD. Unknown thread objects return NULL rather than the current process.
extern "win64" fn s_ps_get_thread_process(thread: u64) -> u64 {
    unsafe {
        if let Some(index) = thread_context_index_for_ethread(thread) {
            let pid = WIN32K_THREAD_CTX_PIDS[index].load(Ordering::Relaxed);
            return eprocess_for_pid(pid);
        }
        if thread != 0 {
            let process = read_volatile((thread + ETHREAD_THREADS_PROCESS_OFF) as *const u64);
            if process_context_index_for_eprocess(process).is_some() {
                return process;
            }
        }
        0
    }
}

/// `PACCESS_TOKEN PsReferencePrimaryToken(PEPROCESS Process)` — reference the selected process's
/// primary-token object. The token metadata is owned by the executive ProcessManager and delivered
/// in the win32k dispatch request; missing metadata is a visible NULL result.
extern "win64" fn s_ps_reference_primary_token(process: u64) -> u64 {
    unsafe {
        let Some(index) = process_context_index_for_eprocess(process) else {
            let n = WIN32K_PRIMARY_TOKEN_REFERENCE_FAILURES.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                print_str(b"[win32k-token] ERROR: PsReferencePrimaryToken unknown EPROCESS=0x");
                print_hex((process >> 32) as u32);
                print_hex(process as u32);
                print_str(b"\n");
            }
            return 0;
        };
        let token = ensure_primary_token_object(index);
        if token == 0 {
            let n = WIN32K_PRIMARY_TOKEN_REFERENCE_FAILURES.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                print_str(b"[win32k-token] ERROR: PsReferencePrimaryToken missing token pid=");
                print_u64(WIN32K_PROCESS_CTX_PIDS[index].load(Ordering::Relaxed));
                print_str(b"\n");
            }
        }
        token
    }
}

/// `PACCESS_TOKEN PsReferenceImpersonationToken(...)` — no hosted win32k caller currently carries a
/// thread impersonation token in the component context, so report the native no-token shape.
extern "win64" fn s_ps_reference_impersonation_token(
    _thread: u64,
    copy_on_open: *mut u8,
    effective_only: *mut u8,
    impersonation_level: *mut u32,
) -> u64 {
    unsafe {
        if !copy_on_open.is_null() {
            write_unaligned(copy_on_open, 0);
        }
        if !effective_only.is_null() {
            write_unaligned(effective_only, 0);
        }
        if !impersonation_level.is_null() {
            write_unaligned(impersonation_level, 0);
        }
    }
    0
}

/// `NTSTATUS ZwOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
/// PHANDLE TokenHandle)`. No hosted win32k thread currently carries an impersonation token, so the
/// native result is `STATUS_NO_TOKEN` and the caller can fall back to `ZwOpenProcessToken`.
extern "win64" fn s_zw_open_thread_token(
    _thread_handle: u64,
    _desired_access: u64,
    _open_as_self: u64,
    token_handle: *mut u64,
) -> i32 {
    if token_handle.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    unsafe {
        write_unaligned(token_handle, 0);
    }
    STATUS_NO_TOKEN_I32
}

/// `NTSTATUS ZwOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
/// PHANDLE TokenHandle)`. Open a handle to the selected GUI process's primary token object.
extern "win64" fn s_zw_open_process_token(
    process_handle: u64,
    desired_access: u64,
    token_handle: *mut u64,
) -> i32 {
    if token_handle.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    unsafe {
        write_unaligned(token_handle, 0);
        if desired_access & TOKEN_QUERY_ACCESS == 0 {
            return STATUS_INVALID_PARAMETER_I32;
        }
        if process_handle != u64::MAX && process_handle != FAKE_PROCESS_HANDLE {
            return STATUS_INVALID_HANDLE_I32;
        }
        let Some(index) = current_process_context_index() else {
            return STATUS_INVALID_HANDLE_I32;
        };
        let token = ensure_primary_token_object(index);
        if token == 0 {
            return STATUS_NO_TOKEN_I32;
        }
        let handle = register_token_handle(token);
        if handle == 0 {
            return STATUS_NO_MEMORY;
        }
        write_unaligned(token_handle, handle);
        0
    }
}

/// `NTSTATUS ZwQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS Class,
/// PVOID Buffer, ULONG Length, PULONG ReturnLength)`. The service window-station security path only
/// needs `TokenUser`; return the native `TOKEN_USER` layout from the process primary token.
extern "win64" fn s_zw_query_information_token(
    token_handle: u64,
    token_information_class: u64,
    token_information: u64,
    token_information_length: u64,
    return_length: *mut u32,
) -> i32 {
    if return_length.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    if token_information_class != TOKEN_INFORMATION_CLASS_USER {
        return STATUS_INVALID_INFO_CLASS_I32;
    }
    let Some(token) = (unsafe { token_for_handle(token_handle) }) else {
        return STATUS_INVALID_HANDLE_I32;
    };
    let mut sid = [0u8; WIN32K_TOKEN_USER_SID_MAX];
    let Some(sid_len) = (unsafe { primary_token_user_sid(token, &mut sid) }) else {
        return STATUS_NO_TOKEN_I32;
    };
    let needed = 16usize + sid_len;
    unsafe {
        write_unaligned(return_length, needed as u32);
    }
    if token_information_length < needed as u64 {
        return STATUS_BUFFER_TOO_SMALL_I32;
    }
    if token_information == 0 {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    unsafe {
        write_unaligned(token_information as *mut u64, token_information + 16);
        write_unaligned((token_information + 8) as *mut u32, 0);
        write_unaligned((token_information + 12) as *mut u32, 0);
        let sid_out = (token_information + 16) as *mut u8;
        let mut i = 0usize;
        while i < sid_len {
            write_volatile(sid_out.add(i), sid[i]);
            i += 1;
        }
    }
    0
}

/// `NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process)` — resolve a PID to
/// its runtime-owned EPROCESS body. Unknown non-zero PIDs remain visible as failure so callers do not
/// silently attach to the wrong GUI process identity.
extern "win64" fn s_ps_lookup_process_by_id(process_id: u64, process_out: *mut u64) -> i32 {
    unsafe {
        if process_id == 0 {
            return 0xC000_000Bu32 as i32; // STATUS_INVALID_CID
        }
        let process = eprocess_for_pid(process_id);
        if process == 0 {
            return 0xC000_000Bu32 as i32; // STATUS_INVALID_CID
        }
        if !process_out.is_null() {
            write_volatile(process_out, process);
        }
    }
    0 // STATUS_SUCCESS
}
/// `PVOID PsGetCurrentProcessWin32Process()` — the selected client's process win32 slot.
extern "win64" fn s_get_current_win32process() -> u64 {
    unsafe {
        let process = current_eprocess();
        if process == 0 {
            0
        } else {
            read_volatile((process + EPROCESS_WIN32PROCESS_OFF) as *const u64)
        }
    }
}

/// `PVOID PsGetProcessWin32Process(PEPROCESS)` — the win32 slot attached to the supplied process.
extern "win64" fn s_get_process_win32process(process: u64) -> u64 {
    unsafe {
        if process == 0 {
            0
        } else {
            read_volatile((process + EPROCESS_WIN32PROCESS_OFF) as *const u64)
        }
    }
}

/// `PVOID PsGetCurrentThreadWin32Thread()` — the selected client's thread win32 slot.
extern "win64" fn s_get_current_win32thread() -> u64 {
    unsafe { current_w32thread() }
}

/// `PVOID PsGetThreadWin32Thread(PETHREAD)` — read the slot from a specific thread body.
extern "win64" fn s_get_thread_win32thread(thread: u64) -> u64 {
    unsafe {
        if let Some(index) = thread_context_index_for_ethread(thread) {
            let w32thread = WIN32K_THREAD_CTX_W32THREAD[index].load(Ordering::Relaxed);
            if w32thread != 0 {
                return w32thread;
            }
        }
        if thread != 0 {
            let field = read_volatile((thread + KTHREAD_WIN32THREAD_OFF) as *const u64);
            if field != 0 {
                return field;
            }
        }
        0
    }
}
/// `VOID PsSetProcessWin32Process(PEPROCESS Process, PVOID W32Process, PVOID OldValue)` — park the
/// W32PROCESS pointer on the process body win32k passed us.
extern "win64" fn s_set_win32process(process: u64, w32process: u64, old: u64) -> i32 {
    unsafe {
        if process == 0 {
            return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
        }
        let context_index = process_context_index_for_eprocess(process);
        let field = (process + EPROCESS_WIN32PROCESS_OFF) as *mut u64;
        let previous = read_volatile(field);
        if w32process != 0 {
            if previous != 0 {
                return 0xC000_010Au32 as i32; // STATUS_PROCESS_IS_TERMINATING
            }
            write_volatile(field, w32process);
        } else if previous == old {
            write_volatile(field, 0);
        } else {
            return 0xC000_0001u32 as i32; // STATUS_UNSUCCESSFUL
        }
        if let Some(index) = context_index {
            WIN32K_PROCESS_CTX_W32PROCESS[index].store(w32process, Ordering::Relaxed);
            if index == current_process_context_index().unwrap_or(usize::MAX) {
                write_volatile(SLOT_W32PROCESS as *mut u64, w32process);
            }
            if let Some(thread_index) = current_thread_context_index() {
                publish_selected_context(index, thread_index);
            }
        }
    };
    0
}
/// `PVOID PsSetThreadWin32Thread(PETHREAD Thread, PVOID Win32Thread, PVOID OldWin32Thread)` —
/// `ntoskrnl/ps/thread.c:909`. Stores the pointer in **the thread object** (`Thread->Tcb.Win32Thread`
/// at [`KTHREAD_WIN32THREAD_OFF`]) and returns the previous value; a NULL `Win32Thread` is the RESET
/// form, which only takes effect when the current value matches `OldWin32Thread`.
///
/// The compatibility cell ([`SLOT_W32THREAD`]) is kept in lockstep for current-thread imports, but the
/// *thread-object* store is the load-bearing half: win32k inlines
/// `PsGetCurrentThread()->Tcb.Win32Thread` and never goes through the export.
extern "win64" fn s_set_win32thread(thread: u64, w32thread: u64, old: u64) -> u64 {
    unsafe {
        let thread = if thread == 0 {
            current_ethread()
        } else {
            thread
        };
        let context_index = thread_context_index_for_ethread(thread);
        let field = (thread + KTHREAD_WIN32THREAD_OFF) as *mut u64;
        let previous = read_volatile(field);
        if w32thread != 0 || previous == old {
            write_volatile(field, w32thread);
            if let Some(index) = context_index {
                WIN32K_THREAD_CTX_W32THREAD[index].store(w32thread, Ordering::Relaxed);
                if let Some(process_index) = current_process_context_index() {
                    publish_selected_context(process_index, index);
                }
            }
            if thread == current_ethread() {
                write_volatile(SLOT_W32THREAD as *mut u64, w32thread);
            }
        }
        previous
    }
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
    init_desktop_body, link_thread_to_desktop, unlink_thread_from_desktop, ObHandleTable, ObKind,
    DESKTOPINFO_SIZE, DESKTOP_BODY_SIZE,
};

/// The single win32k object registry (single-threaded host; handle→(type, body) lives in the crate).
static mut OBJ_TABLE: ObHandleTable = ObHandleTable::new();

/// Duplicate a handle owned by win32k's USER object table. Native `NtDuplicateObject` calls this
/// after the caller's EPROCESS table reports `STATUS_INVALID_HANDLE`, because desktop/window-
/// station handles are minted by win32k's Ob layer rather than the executive's native table.
pub(crate) unsafe fn duplicate_user_object_handle(handle: u64) -> Option<u64> {
    (&mut *core::ptr::addr_of_mut!(OBJ_TABLE)).duplicate(handle)
}

/// Close one handle alias in win32k's USER object table. The session-pool object body remains live
/// while any other handle aliases it.
pub(crate) unsafe fn close_user_object_handle(handle: u64) -> bool {
    (&mut *core::ptr::addr_of_mut!(OBJ_TABLE)).close(handle)
}

/// Return the access mask granted to a modeled USER object handle.
pub(crate) unsafe fn user_object_granted_access(handle: u64) -> Option<u32> {
    (*core::ptr::addr_of!(OBJ_TABLE)).granted_access(handle)
}

/// Return the stored self-relative security descriptor for a modeled USER object handle.
pub(crate) unsafe fn user_object_security_descriptor(handle: u64) -> Option<&'static [u8]> {
    (*core::ptr::addr_of!(OBJ_TABLE)).security_descriptor(handle)
}

/// Replace the stored self-relative security descriptor for a modeled USER object handle.
pub(crate) unsafe fn set_user_object_security_descriptor(handle: u64, descriptor: &[u8]) -> bool {
    (&mut *core::ptr::addr_of_mut!(OBJ_TABLE)).set_security_descriptor(handle, descriptor)
}

pub(crate) unsafe fn switch_desktop_would_change_input_desktop(hdesk: u64) -> bool {
    let target_body = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk);
    if target_body == 0 {
        return false;
    }
    let gpdesk = read_volatile((WIN32K_CODE_VA + GPDESK_INPUT_DESKTOP_RVA) as *const u64);
    gpdesk != target_body
}

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

pub(crate) fn event_body_for_client_handle(handle: u64) -> Option<u64> {
    use nt_object_manager::win32k_ob::ObKind;
    let table = unsafe { &*core::ptr::addr_of!(OBJ_TABLE) };
    match table.lookup(handle) {
        Some((ObKind::Event, body)) => Some(body),
        _ => None,
    }
}

pub(crate) fn event_body_ready(body: u64) -> bool {
    body != 0 && unsafe { nt_kernel_exec::kevent::kevent_read_state(body as *const u8) }
}

pub(crate) fn event_body_consume(body: u64) -> bool {
    if body == 0 {
        return false;
    }
    unsafe {
        if !nt_kernel_exec::kevent::kevent_read_state(body as *const u8) {
            return false;
        }
        if matches!(
            nt_kernel_exec::kevent::kevent_kind(body as *const u8),
            nt_kernel_exec::kevent::EventKind::Synchronization
        ) {
            nt_kernel_exec::kevent::kevent_reset(body as *mut u8);
        }
    }
    true
}

unsafe fn register_win32k_local_event_body(body: u64) -> Option<u64> {
    if body == 0 {
        return None;
    }
    let handle = WIN32K_LOCAL_EVENT_HANDLE_NEXT.fetch_add(4, Ordering::Relaxed);
    if (&mut *core::ptr::addr_of_mut!(OBJ_TABLE)).register_event(handle, body) {
        Some(handle)
    } else {
        None
    }
}

unsafe fn create_win32k_local_queue_event() -> Option<(u64, u64)> {
    let body = pool_alloc(nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64);
    if body == 0 {
        return None;
    }
    nt_kernel_exec::kevent::init_kevent(
        body as *mut u8,
        nt_kernel_exec::kevent::EventKind::Synchronization,
        false,
    );
    register_win32k_local_event_body(body).map(|handle| (handle, body))
}

unsafe fn ensure_thread_queue_event(w32thread: u64) {
    if w32thread == 0 {
        return;
    }
    let handle_slot = (w32thread + THREADINFO_HEVENT_QUEUE_CLIENT_OFF) as *mut u64;
    let server_slot = (w32thread + THREADINFO_PEVENT_QUEUE_SERVER_OFF) as *mut u64;
    let handle = read_volatile(handle_slot);
    let server = read_volatile(server_slot);
    if handle != 0 && server != 0 {
        return;
    }

    if server == 0 && handle != 0 {
        if let Some(body) = event_body_for_client_handle(handle) {
            write_volatile(server_slot, body);
            return;
        }
    }

    if handle == 0 && server != 0 {
        if let Some(alias) = register_win32k_local_event_body(server) {
            write_volatile(handle_slot, alias);
            return;
        }
    }

    if let Some((new_handle, new_server)) = create_win32k_local_queue_event() {
        write_volatile(handle_slot, new_handle);
        write_volatile(server_slot, new_server);
        let n = WIN32K_THREAD_QUEUE_EVENT_SEEDS.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] seeded message queue event pti=0x");
            print_hex((w32thread >> 32) as u32);
            print_hex(w32thread as u32);
            print_str(b" handle=0x");
            print_hex((new_handle >> 32) as u32);
            print_hex(new_handle as u32);
            print_str(b" server=0x");
            print_hex((new_server >> 32) as u32);
            print_hex(new_server as u32);
            print_str(b"\n");
        }
    } else {
        let n = WIN32K_THREAD_QUEUE_EVENT_SEEDS.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: could not seed message queue event pti=0x");
            print_hex((w32thread >> 32) as u32);
            print_hex(w32thread as u32);
            print_str(b"\n");
        }
    }
}

extern "win64" fn s_ob_reference_object(object: u64) -> u64 {
    object
}

extern "win64" fn s_zw_create_event(
    handle_out: *mut u64,
    _desired_access: u64,
    _object_attributes: u64,
    event_type: u64,
    initial_state: u64,
) -> i32 {
    if handle_out.is_null() {
        return 0xC000_0005u32 as i32; // STATUS_ACCESS_VIOLATION
    }
    if event_type > 1 {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    unsafe {
        write_unaligned(handle_out, 0);
        let body = pool_alloc(nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64);
        if body == 0 {
            return STATUS_NO_MEMORY;
        }
        let kind = if event_type == 1 {
            nt_kernel_exec::kevent::EventKind::Synchronization
        } else {
            nt_kernel_exec::kevent::EventKind::Notification
        };
        nt_kernel_exec::kevent::init_kevent(body as *mut u8, kind, initial_state != 0);
        let handle = WIN32K_LOCAL_EVENT_HANDLE_NEXT.fetch_add(4, Ordering::Relaxed);
        if !(&mut *core::ptr::addr_of_mut!(OBJ_TABLE)).register_event(handle, body) {
            return STATUS_NO_MEMORY;
        }
        write_unaligned(handle_out, handle);
    }
    0
}

extern "win64" fn s_zw_close(handle: u64) -> i32 {
    if close_win32k_reg_handle(handle) {
        return 0;
    }
    s_ob_close_handle(handle, 0)
}

extern "win64" fn s_ke_initialize_event(event: u64, event_type: u64, initial_state: u64) {
    if event == 0 {
        return;
    }
    let kind = if event_type == 1 {
        nt_kernel_exec::kevent::EventKind::Synchronization
    } else {
        nt_kernel_exec::kevent::EventKind::Notification
    };
    unsafe {
        nt_kernel_exec::kevent::init_kevent(event as *mut u8, kind, initial_state != 0);
    }
}

extern "win64" fn s_ke_set_event(event: u64, _increment: u64, _wait: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    let previous = unsafe { nt_kernel_exec::kevent::kevent_set(event as *mut u8) };
    record_local_event_signal(event);
    previous as i32
}

extern "win64" fn s_ke_reset_event(event: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    unsafe { nt_kernel_exec::kevent::kevent_reset(event as *mut u8) as i32 }
}

extern "win64" fn s_ke_clear_event(event: u64) {
    if event != 0 {
        unsafe { nt_kernel_exec::kevent::kevent_clear(event as *mut u8) };
    }
}

extern "win64" fn s_ke_pulse_event(event: u64, _increment: u64, _wait: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    let previous = unsafe { nt_kernel_exec::kevent::kevent_pulse(event as *mut u8) };
    record_local_event_signal(event);
    previous as i32
}

extern "win64" fn s_ke_read_state_event(event: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    unsafe { nt_kernel_exec::kevent::kevent_read_state(event as *const u8) as i32 }
}

extern "win64" fn s_ke_wait_for_single_object(
    event: u64,
    _wait_reason: u64,
    _wait_mode: u64,
    _alertable: u64,
    _timeout: u64,
) -> i32 {
    if event != 0 {
        unsafe {
            if nt_kernel_exec::kevent::kevent_read_state(event as *const u8)
                && matches!(
                    nt_kernel_exec::kevent::kevent_kind(event as *const u8),
                    nt_kernel_exec::kevent::EventKind::Synchronization
                )
            {
                nt_kernel_exec::kevent::kevent_reset(event as *mut u8);
            }
        }
    }
    0 // STATUS_WAIT_0
}

extern "win64" fn s_eng_get_tick_count() -> u32 {
    WIN32K_TICK_COUNT.fetch_add(1, Ordering::Relaxed) as u32
}

extern "win64" fn s_rtl_get_exp_winver(_base: u64) -> u32 {
    0x0501 // MAKEWORD(1, 5): Windows XP/Server 2003-compatible subsystem version.
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

unsafe fn object_attributes_unicode_buffer(object_attributes: u64) -> Option<(u64, usize)> {
    if object_attributes == 0 {
        return None;
    }
    let ustr = read_unaligned((object_attributes + 0x10) as *const u64);
    if ustr == 0 {
        return None;
    }
    let length = read_unaligned(ustr as *const u16) as usize;
    let buffer = read_unaligned((ustr + 8) as *const u64);
    if length == 0 || length & 1 != 0 || buffer == 0 {
        return None;
    }
    let units = length / 2;
    (units <= 512).then_some((buffer, units))
}

fn ascii_u16_eq_ignore_case(unit: u16, ascii: u8) -> bool {
    let lower = if unit >= b'A' as u16 && unit <= b'Z' as u16 {
        unit + 0x20
    } else {
        unit
    };
    lower == ascii.to_ascii_lowercase() as u16
}

unsafe fn object_attributes_name_contains_ascii(object_attributes: u64, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let Some((buffer, units)) = object_attributes_unicode_buffer(object_attributes) else {
        return false;
    };
    if units < needle.len() {
        return false;
    }
    let mut index = 0usize;
    while index + needle.len() <= units {
        let mut matched = true;
        let mut offset = 0usize;
        while offset < needle.len() {
            let unit = read_unaligned((buffer + ((index + offset) * 2) as u64) as *const u16);
            if !ascii_u16_eq_ignore_case(unit, needle[offset]) {
                matched = false;
                break;
            }
            offset += 1;
        }
        if matched {
            return true;
        }
        index += 1;
    }
    false
}

unsafe fn object_attributes_name_leaf_eq_ascii(object_attributes: u64, leaf: &[u8]) -> bool {
    let Some((buffer, units)) = object_attributes_unicode_buffer(object_attributes) else {
        return false;
    };
    let mut start = 0usize;
    let mut index = 0usize;
    while index < units {
        let unit = read_unaligned((buffer + (index * 2) as u64) as *const u16);
        if unit == b'\\' as u16 || unit == b'/' as u16 {
            start = index + 1;
        }
        index += 1;
    }
    if units - start != leaf.len() {
        return false;
    }
    let mut offset = 0usize;
    while offset < leaf.len() {
        let unit = read_unaligned((buffer + ((start + offset) * 2) as u64) as *const u16);
        if !ascii_u16_eq_ignore_case(unit, leaf[offset]) {
            return false;
        }
        offset += 1;
    }
    true
}

unsafe fn object_attributes_root_directory(object_attributes: u64) -> u64 {
    if object_attributes == 0 {
        0
    } else {
        read_unaligned((object_attributes + 0x08) as *const u64)
    }
}

unsafe fn object_attributes_name_leaf_ascii(
    object_attributes: u64,
) -> Option<([u8; nt_object_manager::win32k_ob::OB_NAMED_DESKTOP_NAME_MAX], usize)> {
    let Some((buffer, units)) = object_attributes_unicode_buffer(object_attributes) else {
        return None;
    };
    if units == 0 {
        return None;
    }
    let mut start = 0usize;
    let mut index = 0usize;
    while index < units {
        let unit = read_unaligned((buffer + (index * 2) as u64) as *const u16);
        if unit == b'\\' as u16 || unit == b'/' as u16 {
            start = index + 1;
        }
        index += 1;
    }
    let len = units - start;
    if len == 0 || len > nt_object_manager::win32k_ob::OB_NAMED_DESKTOP_NAME_MAX {
        return None;
    }
    let mut leaf = [0u8; nt_object_manager::win32k_ob::OB_NAMED_DESKTOP_NAME_MAX];
    let mut offset = 0usize;
    while offset < len {
        let unit = read_unaligned((buffer + ((start + offset) * 2) as u64) as *const u16);
        if unit > 0x7f {
            return None;
        }
        leaf[offset] = (unit as u8).to_ascii_lowercase();
        offset += 1;
    }
    Some((leaf, len))
}

struct CapturedUserObjectSecurityDescriptor {
    len: usize,
    bytes: [u8; nt_object_manager::win32k_ob::OB_SECURITY_DESCRIPTOR_MAX],
}

impl CapturedUserObjectSecurityDescriptor {
    fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; nt_object_manager::win32k_ob::OB_SECURITY_DESCRIPTOR_MAX],
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

unsafe fn copy_component_bytes_to_slice(dst: &mut [u8], offset: usize, src: u64, len: usize) {
    let mut i = 0usize;
    while i < len {
        dst[offset + i] = read_volatile((src + i as u64) as *const u8);
        i += 1;
    }
}

fn write_slice_u16(dst: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    dst[offset] = bytes[0];
    dst[offset + 1] = bytes[1];
}

fn write_slice_u32(dst: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    dst[offset] = bytes[0];
    dst[offset + 1] = bytes[1];
    dst[offset + 2] = bytes[2];
    dst[offset + 3] = bytes[3];
}

fn checked_self_relative_component_end(offset: u32, len: usize) -> Option<usize> {
    if offset == 0 {
        return Some(SECURITY_DESCRIPTOR_RELATIVE_BYTES);
    }
    let offset = offset as usize;
    if offset < SECURITY_DESCRIPTOR_RELATIVE_BYTES {
        return None;
    }
    offset.checked_add(len)
}

unsafe fn self_relative_security_descriptor_len(sd: u64, control: u16) -> Result<usize, i32> {
    let mut total = SECURITY_DESCRIPTOR_RELATIVE_BYTES;
    for offset in [
        read_unaligned((sd + SD_REL_OWNER_OFF) as *const u32),
        read_unaligned((sd + SD_REL_GROUP_OFF) as *const u32),
    ] {
        if offset != 0 {
            let component = sd
                .checked_add(offset as u64)
                .ok_or(STATUS_INVALID_SECURITY_DESCR_I32)?;
            let Some(len) = sid_len_from_ptr(component) else {
                return Err(STATUS_INVALID_SID_I32);
            };
            let Some(end) = checked_self_relative_component_end(offset, len) else {
                return Err(STATUS_INVALID_SECURITY_DESCR_I32);
            };
            total = total.max(end);
        }
    }

    for (present, offset) in [
        (
            control & SE_SACL_PRESENT != 0,
            read_unaligned((sd + SD_REL_SACL_OFF) as *const u32),
        ),
        (
            control & SE_DACL_PRESENT != 0,
            read_unaligned((sd + SD_REL_DACL_OFF) as *const u32),
        ),
    ] {
        if !present {
            if offset != 0 {
                return Err(STATUS_INVALID_SECURITY_DESCR_I32);
            }
            continue;
        }
        if offset == 0 {
            continue;
        }
        let component = sd
            .checked_add(offset as u64)
            .ok_or(STATUS_INVALID_SECURITY_DESCR_I32)?;
        let Some(len) = acl_size_from_ptr(component) else {
            return Err(STATUS_INVALID_ACL_I32);
        };
        let Some(end) = checked_self_relative_component_end(offset, len) else {
            return Err(STATUS_INVALID_SECURITY_DESCR_I32);
        };
        total = total.max(end);
    }

    Ok(total)
}

unsafe fn capture_user_object_security_descriptor(
    sd: u64,
) -> Result<CapturedUserObjectSecurityDescriptor, i32> {
    if sd == 0 {
        return Err(STATUS_ACCESS_VIOLATION_I32);
    }
    if read_volatile(sd as *const u8) as u64 != SECURITY_DESCRIPTOR_REVISION_U64 {
        return Err(STATUS_UNKNOWN_REVISION_I32);
    }

    let control = read_unaligned((sd + SD_CONTROL_OFF) as *const u16);
    let mut captured = CapturedUserObjectSecurityDescriptor::empty();

    if control & SE_SELF_RELATIVE != 0 {
        let len = self_relative_security_descriptor_len(sd, control)?;
        if len > captured.bytes.len() {
            return Err(STATUS_INSUFFICIENT_RESOURCES_I32);
        }
        copy_component_bytes_to_slice(&mut captured.bytes, 0, sd, len);
        captured.len = len;
        return Ok(captured);
    }

    let owner = read_unaligned((sd + SD_OWNER_OFF) as *const u64);
    let group = read_unaligned((sd + SD_GROUP_OFF) as *const u64);
    let sacl = if control & SE_SACL_PRESENT != 0 {
        read_unaligned((sd + SD_SACL_OFF) as *const u64)
    } else {
        0
    };
    let dacl = if control & SE_DACL_PRESENT != 0 {
        read_unaligned((sd + SD_DACL_OFF) as *const u64)
    } else {
        0
    };
    let Some(owner_len) = sd_component_len_sid(owner) else {
        return Err(STATUS_INVALID_SID_I32);
    };
    let Some(group_len) = sd_component_len_sid(group) else {
        return Err(STATUS_INVALID_SID_I32);
    };
    let Some(sacl_len) = sd_component_len_acl(sacl) else {
        return Err(STATUS_INVALID_ACL_I32);
    };
    let Some(dacl_len) = sd_component_len_acl(dacl) else {
        return Err(STATUS_INVALID_ACL_I32);
    };
    let Some(total_len) = SECURITY_DESCRIPTOR_RELATIVE_BYTES
        .checked_add(owner_len)
        .and_then(|v| v.checked_add(group_len))
        .and_then(|v| v.checked_add(sacl_len))
        .and_then(|v| v.checked_add(dacl_len))
    else {
        return Err(STATUS_ALLOTTED_SPACE_EXCEEDED_I32);
    };
    if total_len > captured.bytes.len() {
        return Err(STATUS_INSUFFICIENT_RESOURCES_I32);
    }

    captured.bytes[0] = read_volatile(sd as *const u8);
    captured.bytes[1] = read_volatile((sd + 1) as *const u8);
    write_slice_u16(
        &mut captured.bytes,
        SD_CONTROL_OFF as usize,
        control | SE_SELF_RELATIVE,
    );
    let mut current = SECURITY_DESCRIPTOR_RELATIVE_BYTES;
    if sacl_len != 0 {
        copy_component_bytes_to_slice(&mut captured.bytes, current, sacl, sacl_len);
        write_slice_u32(&mut captured.bytes, SD_REL_SACL_OFF as usize, current as u32);
        current += sacl_len;
    }
    if dacl_len != 0 {
        copy_component_bytes_to_slice(&mut captured.bytes, current, dacl, dacl_len);
        write_slice_u32(&mut captured.bytes, SD_REL_DACL_OFF as usize, current as u32);
        current += dacl_len;
    }
    if owner_len != 0 {
        copy_component_bytes_to_slice(&mut captured.bytes, current, owner, owner_len);
        write_slice_u32(&mut captured.bytes, SD_REL_OWNER_OFF as usize, current as u32);
        current += owner_len;
    }
    if group_len != 0 {
        copy_component_bytes_to_slice(&mut captured.bytes, current, group, group_len);
        write_slice_u32(&mut captured.bytes, SD_REL_GROUP_OFF as usize, current as u32);
    }
    captured.len = total_len;
    Ok(captured)
}

unsafe fn object_attributes_security_descriptor(
    object_attributes: u64,
) -> Result<Option<CapturedUserObjectSecurityDescriptor>, i32> {
    if object_attributes == 0 {
        return Ok(None);
    }
    let sd = read_unaligned((object_attributes + 0x20) as *const u64);
    if sd == 0 {
        return Ok(None);
    }
    capture_user_object_security_descriptor(sd).map(Some)
}

unsafe fn current_token_authentication_id() -> u64 {
    current_process_context_index()
        .map(|index| WIN32K_PROCESS_CTX_TOKEN_AUTH[index].load(Ordering::Relaxed))
        .unwrap_or(0)
}

unsafe fn service_winsta_index_for_auth(token_authentication_id: u64) -> Option<usize> {
    if token_authentication_id == 0 {
        return None;
    }
    for index in 0..WIN32K_SERVICE_WINSTA_CAP {
        if WIN32K_SERVICE_WINSTA_AUTHS[index].load(Ordering::Relaxed) == token_authentication_id {
            return Some(index);
        }
    }
    None
}

unsafe fn record_service_window_station(handle: u64) {
    let token_authentication_id = current_token_authentication_id();
    if token_authentication_id == 0 || handle == 0 {
        return;
    }
    if let Some(index) = service_winsta_index_for_auth(token_authentication_id) {
        WIN32K_SERVICE_WINSTA_HANDLES[index].store(handle, Ordering::Relaxed);
        return;
    }
    for index in 0..WIN32K_SERVICE_WINSTA_CAP {
        if WIN32K_SERVICE_WINSTA_AUTHS[index].load(Ordering::Relaxed) == 0 {
            WIN32K_SERVICE_WINSTA_AUTHS[index].store(token_authentication_id, Ordering::Relaxed);
            WIN32K_SERVICE_WINSTA_HANDLES[index].store(handle, Ordering::Relaxed);
            return;
        }
    }
}

unsafe fn service_window_station_handle_for_current_token() -> u64 {
    let token_authentication_id = current_token_authentication_id();
    service_winsta_index_for_auth(token_authentication_id)
        .map(|index| WIN32K_SERVICE_WINSTA_HANDLES[index].load(Ordering::Relaxed))
        .unwrap_or(0)
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
    object_attributes: u64,
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
                let root = object_attributes_root_directory(object_attributes);
                let named_leaf = object_attributes_name_leaf_ascii(object_attributes);
                if let Some((leaf, len)) = named_leaf {
                    if let Some(existing) = table.desktop_handle_for_name(root, &leaf[..len]) {
                        if !handle.is_null() {
                            write_unaligned(handle, existing);
                        }
                        if parse_context != 0 {
                            write_volatile(parse_context as *mut u8, 0);
                        }
                        return 0;
                    }
                }
                if parse_context == 0 {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
                let security = match object_attributes_security_descriptor(object_attributes) {
                    Ok(security) => security,
                    Err(status) => return status,
                };
                let body = alloc_desktop_body();
                if body == 0 {
                    return STATUS_INSUFFICIENT_RESOURCES_I32;
                }
                if let Some((ObKind::WindowStation, winsta_body)) = table.lookup(root) {
                    write_volatile(
                        (body + DESKTOP_RPWINSTA_PARENT_OFF) as *mut u64,
                        winsta_body,
                    );
                }
                let h = table.register_with_security(
                    ObKind::Desktop,
                    body,
                    security.as_ref().map(CapturedUserObjectSecurityDescriptor::as_slice),
                );
                if h == 0 {
                    return STATUS_INSUFFICIENT_RESOURCES_I32;
                }
                if let Some((leaf, len)) = named_leaf {
                    let _ = table.remember_desktop_name(root, &leaf[..len], h);
                }
                if !handle.is_null() {
                    write_unaligned(handle, h);
                }
                if parse_context != 0 {
                    write_volatile(parse_context as *mut u8, 1); // Context = TRUE (object created)
                }
                0
            }
            Some(ObKind::WindowStation) => {
                let service = object_attributes_name_contains_ascii(object_attributes, b"service-");
                if service {
                    let handle_for_service = service_window_station_handle_for_current_token();
                    if handle_for_service != 0 {
                        if !handle.is_null() {
                            write_unaligned(handle, handle_for_service);
                        }
                        if parse_context != 0 {
                            write_volatile(parse_context as *mut u8, 0);
                        }
                        return 0;
                    }
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
                if object_attributes_name_leaf_eq_ascii(object_attributes, b"winsta0") {
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
                }
                if object_attributes == 0 {
                    let cached = table.cached_winsta_handle();
                    if cached != 0 {
                        if !handle.is_null() {
                            write_unaligned(handle, cached);
                        }
                        if parse_context != 0 {
                            write_volatile(parse_context as *mut u8, 0);
                        }
                        return 0;
                    }
                }
                // No matching winsta exists → force IntCreateWindowStation's create path.
                STATUS_OBJECT_NAME_NOT_FOUND
            }
            // Unknown object type: fail visibly; object-manager imports must be modeled by type.
            _ => STATUS_OBJECT_NAME_NOT_FOUND,
        }
    }
}

/// `NTSTATUS ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PACCESS_STATE,
/// ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle)`.
extern "win64" fn s_ob_open_object_by_pointer(
    object: u64,
    _handle_attributes: u64,
    _access_state: u64,
    _desired_access: u64,
    obj_type: u64,
    _access_mode: u64,
    handle: *mut u64,
) -> i32 {
    if handle.is_null() {
        return 0xC000_0005u32 as i32; // STATUS_ACCESS_VIOLATION
    }
    unsafe {
        write_unaligned(handle, 0);
        let process_ty = nt_object_manager::object_type::process_object_type_addr();
        if obj_type == process_ty && process_context_index_for_eprocess(object).is_some() {
            write_unaligned(handle, FAKE_PROCESS_HANDLE);
            return 0;
        }
        let Some(kind) = classify_type(obj_type) else {
            return STATUS_OBJECT_TYPE_MISMATCH;
        };
        let table = &mut *core::ptr::addr_of_mut!(OBJ_TABLE);
        match table.duplicate_by_body(kind, object) {
            Some(alias) => {
                write_unaligned(handle, alias);
                0
            }
            None if table.handle_for_body(kind, object).is_none() => 0xC000_0008u32 as i32,
            None => 0xC000_009Au32 as i32,
        }
    }
}

/// `BOOLEAN ObFindHandleForObject(PEPROCESS Process, PVOID Object, POBJECT_TYPE ObjectType,
/// POBJECT_HANDLE_INFORMATION HandleInformation, PHANDLE Handle)` — this host does not synthesize
/// inherited USER handles; it only resolves explicit object-body searches.
extern "win64" fn s_ob_find_handle_for_object(
    _process: u64,
    object: u64,
    obj_type: u64,
    handle_info: *mut u8,
    handle: *mut u64,
) -> u8 {
    unsafe {
        if !handle.is_null() {
            write_unaligned(handle, 0);
        }
        let Some(kind) = classify_type(obj_type) else {
            return 0;
        };
        if object == 0 {
            return 0;
        }
        let Some(found) = (&*core::ptr::addr_of!(OBJ_TABLE)).handle_for_body(kind, object) else {
            return 0;
        };
        if !handle.is_null() {
            write_unaligned(handle, found);
        }
        if !handle_info.is_null() {
            write_unaligned(handle_info as *mut u32, 0);
            write_unaligned(handle_info.add(4) as *mut u32, u32::MAX);
        }
        1
    }
}

/// `NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode, POBJECT_TYPE ObjectType, POBJECT_ATTRIBUTES,
/// KPROCESSOR_MODE OwnerMode, PVOID ParseContext, ULONG ObjectBodySize, ULONG PagedCharge,
/// ULONG NonPagedCharge, PVOID *Object)` — allocate a zeroed object body of ObjectBodySize from the
/// win32k pool, write *Object, and latch (kind, body) for the following ObInsertObject.
extern "win64" fn s_ob_create_object(
    _probe_mode: u64,
    obj_type: u64,
    object_attributes: u64,
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
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let table = &mut *core::ptr::addr_of_mut!(OBJ_TABLE);
        let kind = classify_type(obj_type).unwrap_or(ObKind::Other);
        let security = if matches!(kind, ObKind::Desktop | ObKind::WindowStation) {
            match object_attributes_security_descriptor(object_attributes) {
                Ok(security) => security,
                Err(status) => return status,
            }
        } else {
            None
        };
        if !table.latch_pending_with_security(
            kind,
            body,
            security.as_ref().map(CapturedUserObjectSecurityDescriptor::as_slice),
        ) {
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let uncached_winsta = kind == ObKind::WindowStation
            && object_attributes_name_contains_ascii(object_attributes, b"service-");
        WIN32K_PENDING_OB_UNCACHED_WINSTA.store(uncached_winsta as u64, Ordering::Relaxed);
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
        let uncached_winsta = WIN32K_PENDING_OB_UNCACHED_WINSTA.swap(0, Ordering::Relaxed) != 0;
        let h = if uncached_winsta {
            table.insert_pending_uncached(object)
        } else {
            table.insert_pending(object)
        };
        if uncached_winsta {
            record_service_window_station(h);
        }
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
/// The only unregistered process handles we resolve are win32k's narrow process-connect handle
/// ([`FAKE_PROCESS_HANDLE`]) and `NtCurrentProcess()`'s pseudo handle, both to the selected dispatch
/// EPROCESS. Every other typed reference to an unregistered handle is enforced honestly
/// (`STATUS_OBJECT_TYPE_MISMATCH`); the service side must rewrite real process handles only after
/// resolving them through ProcessManager.
extern "win64" fn s_ob_reference_object_by_handle(
    handle: u64,
    _access: u64,
    obj_type: u64,
    _mode: u64,
    object_out: *mut u64,
    handle_info: *mut u8,
) -> i32 {
    if !object_out.is_null() {
        unsafe { write_unaligned(object_out, 0) };
    }
    let table = unsafe { &*core::ptr::addr_of!(OBJ_TABLE) };
    let (obj, granted_access) = match table.lookup(handle) {
        Some((kind, body)) => {
            if !nt_object_manager::win32k_ob::object_type_matches(kind, obj_type) {
                ob_type_mismatch_trace(handle, obj_type, b"win32k-obj");
                return STATUS_OBJECT_TYPE_MISMATCH;
            }
            let access = match kind {
                // winuser.h: WINSTA_ALL_ACCESS / DESKTOP_ALL_ACCESS. The modeled objects are
                // created with MAXIMUM_ALLOWED, and duplicate aliases preserve the same grant.
                ObKind::WindowStation => 0x000f_037f,
                ObKind::Desktop => 0x000f_01ff,
                ObKind::Event => 0x001f_0003,
                ObKind::Other => u32::MAX,
            };
            (body, access)
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
                (unsafe { current_eprocess() }, u32::MAX)
            } else if handle == 0xFFFF_FFFF_FFFF_FFFF && (obj_type == 0 || obj_type == process_ty) {
                // NtCurrentProcess() pseudo handle → selected dispatch EPROCESS.
                (unsafe { current_eprocess() }, u32::MAX)
            } else {
                // Every modeled typed object resolves above; reaching here is a real object-manager
                // requirement we do not model, so fail visibly.
                ob_type_mismatch_trace(handle, obj_type, b"unmodeled");
                return STATUS_OBJECT_TYPE_MISMATCH;
            }
        }
    };
    if !object_out.is_null() {
        unsafe { write_unaligned(object_out, obj) };
    }
    if !handle_info.is_null() {
        unsafe {
            // OBJECT_HANDLE_INFORMATION { ULONG HandleAttributes; ACCESS_MASK GrantedAccess; }
            write_unaligned(handle_info as *mut u32, 0);
            write_unaligned(handle_info.add(4) as *mut u32, granted_access);
        }
    }
    0
}

extern "win64" fn s_ps_get_process_winsta(process: u64) -> u64 {
    if process == 0 {
        0
    } else {
        unsafe { read_volatile((process + EPROCESS_WIN32_WINDOW_STATION_OFF) as *const u64) }
    }
}

extern "win64" fn s_ps_set_process_winsta(process: u64, handle: u64) {
    if process != 0 {
        unsafe {
            write_volatile(
                (process + EPROCESS_WIN32_WINDOW_STATION_OFF) as *mut u64,
                handle,
            );
        }
    }
}

/// `ZwDuplicateObject`: duplicate a modeled USER handle into an independently closeable alias.
extern "win64" fn s_zw_duplicate_object(
    _source_process: u64,
    source_handle: u64,
    _target_process: u64,
    target_handle: *mut u64,
    _desired_access: u64,
    _handle_attributes: u64,
    _options: u64,
) -> i32 {
    if target_handle.is_null() {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    unsafe { write_unaligned(target_handle, 0) };
    let table = unsafe { &mut *core::ptr::addr_of_mut!(OBJ_TABLE) };
    match table.duplicate(source_handle) {
        Some(alias) => {
            unsafe { write_unaligned(target_handle, alias) };
            0
        }
        None if table.lookup(source_handle).is_none() => 0xC000_0008u32 as i32,
        None => 0xC000_009Au32 as i32,
    }
}

/// `ObCloseHandle`: duplicated aliases have handle lifetime; canonical pool-backed objects have
/// session lifetime in this host and remain registered after a successful close.
extern "win64" fn s_ob_close_handle(handle: u64, _mode: u64) -> i32 {
    if handle == FAKE_PROCESS_HANDLE {
        return 0;
    }
    if unsafe { close_token_handle(handle) } {
        return 0;
    }
    let table = unsafe { &mut *core::ptr::addr_of_mut!(OBJ_TABLE) };
    if table.close(handle) || table.lookup(handle).is_some() {
        0
    } else {
        0xC000_0008u32 as i32 // STATUS_INVALID_HANDLE
    }
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

const HEAP_HDR_SIZE: u64 = 16;
const HEAP_ALLOC_MARKER: u64 = 0xffff_ffff_ffff_fffd;
const HEAP_ZERO_MEMORY: u64 = 0x0000_0008;
const HEAP_REALLOC_IN_PLACE_ONLY: u64 = 0x0000_0010;

/// Allocate from the win32k session-heap arena. The block header stores the aligned payload
/// capacity; free blocks use the second header word as a next pointer, and live blocks carry a marker.
unsafe fn heap_alloc(size: u64, zero: bool) -> u64 {
    if size == 0 {
        return 0;
    }
    let want = align16(size);
    let head = (WIN32K_HEAP_VADDR + 8) as *mut u64;
    let mut prev = 0u64;
    let mut cur = read_volatile(head);
    let mut scanned = 0usize;
    while cur != 0 && scanned < 4096 {
        let cap = read_volatile(cur as *const u64);
        let next = read_volatile((cur + 8) as *const u64);
        if cap >= want {
            if prev == 0 {
                write_volatile(head, next);
            } else {
                write_volatile((prev + 8) as *mut u64, next);
            }
            if cap >= want + HEAP_HDR_SIZE + 16 {
                let split = cur + HEAP_HDR_SIZE + want;
                write_volatile(split as *mut u64, cap - want - HEAP_HDR_SIZE);
                write_volatile((split + 8) as *mut u64, next);
                if prev == 0 {
                    write_volatile(head, split);
                } else {
                    write_volatile((prev + 8) as *mut u64, split);
                }
                write_volatile(cur as *mut u64, want);
            }
            write_volatile((cur + 8) as *mut u64, HEAP_ALLOC_MARKER);
            let payload = cur + HEAP_HDR_SIZE;
            if zero {
                core::ptr::write_bytes(payload as *mut u8, 0, size as usize);
            }
            return payload;
        }
        prev = cur;
        cur = next;
        scanned += 1;
    }

    let ctr = WIN32K_HEAP_VADDR as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    let hdr = align16(WIN32K_HEAP_VADDR + cur);
    let cap = WIN32K_HEAP_VADDR + WIN32K_HEAP_FRAMES * 0x1000;
    if hdr + HEAP_HDR_SIZE + want > cap {
        print_str(b"[win32k-host] HEAP EXHAUSTED size=0x");
        print_hex(size as u32);
        print_str(b" used=0x");
        print_hex(cur as u32);
        print_str(b"\n");
        return 0;
    }
    write_volatile(ctr, (hdr + HEAP_HDR_SIZE + want) - WIN32K_HEAP_VADDR);
    write_volatile(hdr as *mut u64, want);
    write_volatile((hdr + 8) as *mut u64, HEAP_ALLOC_MARKER);
    let payload = hdr + HEAP_HDR_SIZE;
    if zero {
        core::ptr::write_bytes(payload as *mut u8, 0, size as usize);
    }
    payload
}

unsafe fn heap_block_capacity(p: u64) -> Option<u64> {
    let arena_start = WIN32K_HEAP_VADDR + POOL_DATA_OFF;
    let arena_end = WIN32K_HEAP_VADDR + WIN32K_HEAP_FRAMES * 0x1000;
    if p < arena_start + HEAP_HDR_SIZE || p >= arena_end || (p & 15) != 0 {
        return None;
    }
    let hdr = p - HEAP_HDR_SIZE;
    let cap = read_volatile(hdr as *const u64);
    let marker = read_volatile((hdr + 8) as *const u64);
    if marker != HEAP_ALLOC_MARKER || cap == 0 || (cap & 15) != 0 {
        return None;
    }
    if hdr < arena_start || hdr + HEAP_HDR_SIZE + cap > arena_end {
        return None;
    }
    Some(cap)
}

unsafe fn heap_free(p: u64) -> bool {
    let Some(cap) = heap_block_capacity(p) else {
        return false;
    };
    let hdr = p - HEAP_HDR_SIZE;

    let head = (WIN32K_HEAP_VADDR + 8) as *mut u64;
    let mut prev = 0u64;
    let mut cur = read_volatile(head);
    let mut scanned = 0usize;
    while cur != 0 && cur < hdr && scanned < 4096 {
        prev = cur;
        cur = read_volatile((cur + 8) as *const u64);
        scanned += 1;
    }
    if scanned >= 4096 {
        return false;
    }

    write_volatile(hdr as *mut u64, cap);
    write_volatile((hdr + 8) as *mut u64, cur);
    if prev == 0 {
        write_volatile(head, hdr);
    } else {
        write_volatile((prev + 8) as *mut u64, hdr);
    }

    let mut block = hdr;
    let mut block_cap = cap;
    if cur != 0 && block + HEAP_HDR_SIZE + block_cap == cur {
        let cur_cap = read_volatile(cur as *const u64);
        let cur_next = read_volatile((cur + 8) as *const u64);
        block_cap += HEAP_HDR_SIZE + cur_cap;
        write_volatile(block as *mut u64, block_cap);
        write_volatile((block + 8) as *mut u64, cur_next);
    }
    if prev != 0 {
        let prev_cap = read_volatile(prev as *const u64);
        if prev + HEAP_HDR_SIZE + prev_cap == block {
            let next = read_volatile((block + 8) as *const u64);
            block = prev;
            block_cap += HEAP_HDR_SIZE + prev_cap;
            write_volatile(block as *mut u64, block_cap);
            write_volatile((block + 8) as *mut u64, next);
        }
    }

    let ctr = WIN32K_HEAP_VADDR as *mut u64;
    let high = WIN32K_HEAP_VADDR + read_volatile(ctr);
    if block + HEAP_HDR_SIZE + block_cap == high {
        let mut list_prev = 0u64;
        let mut list_cur = read_volatile(head);
        let mut scanned = 0usize;
        while list_cur != 0 && list_cur != block && scanned < 4096 {
            list_prev = list_cur;
            list_cur = read_volatile((list_cur + 8) as *const u64);
            scanned += 1;
        }
        if list_cur == block {
            let next = read_volatile((block + 8) as *const u64);
            if list_prev == 0 {
                write_volatile(head, next);
            } else {
                write_volatile((list_prev + 8) as *mut u64, next);
            }
            write_volatile(ctr, block - WIN32K_HEAP_VADDR);
        }
    }
    true
}

unsafe fn heap_realloc(flags: u64, p: u64, size: u64) -> u64 {
    if p == 0 {
        return heap_alloc(size, flags & HEAP_ZERO_MEMORY != 0);
    }
    if size == 0 {
        heap_free(p);
        return 0;
    }
    let Some(old_cap) = heap_block_capacity(p) else {
        return 0;
    };
    let want = align16(size);
    if want <= old_cap {
        return p;
    }
    if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
        return 0;
    }
    let newp = heap_alloc(size, flags & HEAP_ZERO_MEMORY != 0);
    if newp == 0 {
        return 0;
    }
    core::ptr::copy_nonoverlapping(
        p as *const u8,
        newp as *mut u8,
        core::cmp::min(old_cap, size) as usize,
    );
    heap_free(p);
    newp
}

/// A GENERAL_LOOKASIDE's default Allocate `PVOID(POOL_TYPE, SIZE_T, ULONG Tag)` — bump the heap
/// arena (the lookaside is a per-type object cache; slow-path allocation on an empty free-list).
extern "win64" fn s_lookaside_alloc(_pool_type: u64, size: u64, _tag: u64) -> u64 {
    unsafe { heap_alloc(size, false) }
}
/// A GENERAL_LOOKASIDE's default Free `VOID(PVOID)`.
extern "win64" fn s_lookaside_free(buf: u64) {
    unsafe {
        heap_free(buf);
    }
}

/// Initialize a GENERAL_LOOKASIDE via the real [`nt_kernel_exec::init_general_lookaside`] primitive
/// (host-tested x64 layout), defaulting the Allocate/Free callbacks to this host's pool trampolines
/// when the caller passed null. `ExInitialize{,N}PagedLookasideList` — a no-op stub left
/// Allocate(+0x30) null, so win32k's slow-path `call [desc+0x30]` jumped to null (RVA 0xb3e88).
unsafe fn init_lookaside(
    la: u64,
    allocate: u64,
    free: u64,
    size: u64,
    tag: u64,
    depth: u64,
    pool_type: u32,
) {
    if la == 0 {
        return;
    }
    let alloc_fn = if allocate != 0 {
        allocate
    } else {
        s_lookaside_alloc as usize as u64
    };
    let free_fn = if free != 0 {
        free
    } else {
        s_lookaside_free as usize as u64
    };
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
    unsafe {
        init_lookaside(
            la,
            allocate,
            free,
            size,
            tag,
            depth,
            nt_kernel_exec::POOL_TYPE_PAGED,
        )
    }
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
    unsafe {
        init_lookaside(
            la, allocate, free, size, tag, depth, 0, /* NonPagedPool */
        )
    }
}

/// `PVOID RtlCreateHeap(Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters)` — win32k
/// creates its session heap. Return a non-null fake handle; RtlAllocateHeap uses the arena above.
extern "win64" fn s_rtl_create_heap() -> u64 {
    WIN32K_HEAP_HANDLE
}
/// `PVOID RtlAllocateHeap(HeapHandle, Flags, Size)`.
extern "win64" fn s_rtl_allocate_heap(_heap: u64, flags: u64, size: u64) -> u64 {
    unsafe { heap_alloc(size, flags & HEAP_ZERO_MEMORY != 0) }
}
/// `BOOLEAN RtlFreeHeap(HeapHandle, Flags, Base)`.
extern "win64" fn s_rtl_free_heap(_heap: u64, _flags: u64, base: u64) -> u64 {
    if base == 0 {
        return 1;
    }
    unsafe { heap_free(base) as u64 }
}
/// `SIZE_T RtlSizeHeap(HeapHandle, Flags, Base)`.
extern "win64" fn s_rtl_size_heap(_heap: u64, _flags: u64, base: u64) -> u64 {
    unsafe { heap_block_capacity(base).unwrap_or(u64::MAX) }
}
/// `PVOID RtlReAllocateHeap(HeapHandle, Flags, Base, Size)`.
extern "win64" fn s_rtl_reallocate_heap(_heap: u64, flags: u64, base: u64, size: u64) -> u64 {
    unsafe { heap_realloc(flags, base, size) }
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
        (map_section(section as *mut u8, |s| heap_alloc(s, true)), sz)
    } else {
        let mut size = size_hint;
        if size == 0 || size > 0x0040_0000 {
            size = 0x0010_0000; // default/cap the view at 1 MiB
        }
        size = (size + 0xFFF) & !0xFFF;
        (heap_alloc(size, true), size)
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
        let size = if max_size.is_null() {
            0x0010_0000
        } else {
            read_unaligned(max_size) as u64
        };
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
        let hint = if size_io.is_null() {
            0
        } else {
            read_volatile(size_io)
        };
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
        if size >= GDI_HANDLE_COUNT * GDI_TABLE_ENTRY_SIZE && size < 0x0020_0000 {
            write_volatile((WIN32K_SHARED_VADDR + SH_GDI_TABLE_BASE) as *mut u64, base);
            write_volatile((WIN32K_SHARED_VADDR + SH_GDI_TABLE_SIZE) as *mut u64, size);
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
        let hint = if size_io.is_null() {
            0
        } else {
            read_volatile(size_io)
        };
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
    argument_table: u64,
    index: u64,
) -> u64 {
    unsafe {
        write_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *mut u64, base);
        write_volatile(
            (WIN32K_SHARED_VADDR + SH_SSDT_COUNT) as *mut u32,
            limit as u32,
        );
        write_volatile(
            (WIN32K_SHARED_VADDR + SH_SSDT_INDEX) as *mut u32,
            index as u32,
        );
        write_volatile(
            (WIN32K_SHARED_VADDR + SH_SSDT_ARGUMENT_TABLE) as *mut u64,
            argument_table,
        );
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

/// `VOID ExFreePoolWithTag(PVOID, ULONG)`. The main pool remains a bump arena, but FreeType's
/// dedicated FTYP arena has real frees because ReactOS ftfd alloc/free churns heavily per client.
extern "win64" fn s_ex_free_pool_with_tag(p: u64, _tag: u64) {
    unsafe {
        ftyp_free(p);
    }
}

// --- ZwAllocateVirtualMemory + RTL_BITMAP (GDI DC_ATTR / RGN_ATTR pool) -----------------------

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
/// collide. Each arena is 64 KiB (≈125 full-length entries — ample for system classes + user atoms).
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

static WIN32K_CURRENT_PROCESS_ID: AtomicU64 = AtomicU64::new(FAKE_PROCESS_HANDLE);
static WIN32K_CURRENT_THREAD_ID: AtomicU64 = AtomicU64::new(WIN32K_BOOTSTRAP_TID);
static WIN32K_CURRENT_CLIENT_PI: AtomicU64 = AtomicU64::new(WIN32K_BOOTSTRAP_PI as u64);
const WIN32K_GUI_PROCESS_CAP: usize = MAX_PI;
const WIN32K_GUI_THREAD_CAP: usize = MAX_PI * 8;
static WIN32K_PROCESS_CTX_PIDS: [AtomicU64; WIN32K_GUI_PROCESS_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_PROCESS_CAP];
static WIN32K_PROCESS_CTX_PIS: [AtomicU64; WIN32K_GUI_PROCESS_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_PROCESS_CAP];
static WIN32K_PROCESS_CTX_EPROCESS: [AtomicU64; WIN32K_GUI_PROCESS_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_PROCESS_CAP];
static WIN32K_PROCESS_CTX_W32PROCESS: [AtomicU64; WIN32K_GUI_PROCESS_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_PROCESS_CAP];
static WIN32K_PROCESS_CTX_TOKEN_AUTH: [AtomicU64; WIN32K_GUI_PROCESS_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_PROCESS_CAP];
static WIN32K_PROCESS_CTX_PRIMARY_TOKEN: [AtomicU64; WIN32K_GUI_PROCESS_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_PROCESS_CAP];
static WIN32K_TOKEN_HANDLE_TOKENS: [AtomicU64; WIN32K_TOKEN_HANDLE_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_TOKEN_HANDLE_CAP];
static WIN32K_THREAD_CTX_TIDS: [AtomicU64; WIN32K_GUI_THREAD_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_THREAD_CAP];
static WIN32K_THREAD_CTX_PIDS: [AtomicU64; WIN32K_GUI_THREAD_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_THREAD_CAP];
static WIN32K_THREAD_CTX_PIS: [AtomicU64; WIN32K_GUI_THREAD_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_THREAD_CAP];
static WIN32K_THREAD_CTX_TEB: [AtomicU64; WIN32K_GUI_THREAD_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_THREAD_CAP];
static WIN32K_THREAD_CTX_CALLOUT_TEB: [AtomicU64; WIN32K_GUI_THREAD_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_THREAD_CAP];
static WIN32K_THREAD_CTX_ETHREAD: [AtomicU64; WIN32K_GUI_THREAD_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_THREAD_CAP];
static WIN32K_THREAD_CTX_W32THREAD: [AtomicU64; WIN32K_GUI_THREAD_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_GUI_THREAD_CAP];
static WIN32K_CLIENT_PROCESS_CALLOUTS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_THREAD_CALLOUTS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CONTEXT_TRACES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CALLBACK_RESUME_CONTEXT_RESTORES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_WALL_CONTEXT_TRACES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_TOKEN_CONTEXT_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_PRIMARY_TOKEN_REFERENCE_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_PENDING_OB_UNCACHED_WINSTA: AtomicU64 = AtomicU64::new(0);
const WIN32K_SERVICE_WINSTA_CAP: usize = 8;
static WIN32K_SERVICE_WINSTA_AUTHS: [AtomicU64; WIN32K_SERVICE_WINSTA_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_SERVICE_WINSTA_CAP];
static WIN32K_SERVICE_WINSTA_HANDLES: [AtomicU64; WIN32K_SERVICE_WINSTA_CAP] =
    [const { AtomicU64::new(0) }; WIN32K_SERVICE_WINSTA_CAP];
static WIN32K_STARTUP_DESKTOP_SEEDS: AtomicU64 = AtomicU64::new(0);
static WIN32K_INHERITED_WINSTA_SEEDS: AtomicU64 = AtomicU64::new(0);
static WIN32K_NONINTERACTIVE_WINSTA_RESOLVES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CSRSS_BOOTSTRAP_REKEYS: AtomicU64 = AtomicU64::new(0);
static WIN32K_DEFAULT_DESKTOP_HANDLE: AtomicU64 = AtomicU64::new(0);
static WIN32K_DEFAULT_DESKTOP_BODY: AtomicU64 = AtomicU64::new(0);
static WIN32K_DEFAULT_DESKTOP_PUBLISHES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_SYSTEM_FONT_SEEDS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_SYSTEM_FONT_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_SYSTEM_FONT_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_SET_THREAD_DESKTOP_PREPARES: AtomicU64 = AtomicU64::new(0);
static SET_THREAD_DESKTOP_WINDOW_LIST_RESET_DONE: AtomicU64 = AtomicU64::new(0);
static WIN32K_LOCAL_EVENT_HANDLE_NEXT: AtomicU64 = AtomicU64::new(0x0000_0000_6E00_0000);
static WIN32K_LOCAL_EVENT_SIGNAL_PENDING: AtomicU64 = AtomicU64::new(0);
const WIN32K_LOCAL_EVENT_SIGNAL_RING_N: usize = 128;
static WIN32K_LOCAL_EVENT_SIGNAL_WRITE: AtomicU64 = AtomicU64::new(0);
static WIN32K_LOCAL_EVENT_SIGNAL_READ: AtomicU64 = AtomicU64::new(0);
static WIN32K_LOCAL_EVENT_SIGNAL_BODIES: [AtomicU64; WIN32K_LOCAL_EVENT_SIGNAL_RING_N] =
    [const { AtomicU64::new(0) }; WIN32K_LOCAL_EVENT_SIGNAL_RING_N];
static WIN32K_THREAD_QUEUE_EVENT_SEEDS: AtomicU64 = AtomicU64::new(0);
static WIN32K_TICK_COUNT: AtomicU64 = AtomicU64::new(1);

fn record_local_event_signal(event: u64) {
    let write = WIN32K_LOCAL_EVENT_SIGNAL_WRITE.fetch_add(1, Ordering::Relaxed);
    WIN32K_LOCAL_EVENT_SIGNAL_BODIES[write as usize % WIN32K_LOCAL_EVENT_SIGNAL_RING_N]
        .store(event, Ordering::Relaxed);
    WIN32K_LOCAL_EVENT_SIGNAL_PENDING.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn take_local_event_signal_body() -> Option<u64> {
    loop {
        let pending = WIN32K_LOCAL_EVENT_SIGNAL_PENDING.load(Ordering::Relaxed);
        if pending == 0 {
            return None;
        }
        if WIN32K_LOCAL_EVENT_SIGNAL_PENDING
            .compare_exchange(
                pending,
                pending - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            let read = WIN32K_LOCAL_EVENT_SIGNAL_READ.fetch_add(1, Ordering::Relaxed);
            let body = WIN32K_LOCAL_EVENT_SIGNAL_BODIES
                [read as usize % WIN32K_LOCAL_EVENT_SIGNAL_RING_N]
                .load(Ordering::Relaxed);
            return (body != 0).then_some(body);
        }
    }
}

pub(crate) unsafe fn current_thread_queue_event_body() -> Option<u64> {
    let w32thread = current_w32thread();
    if w32thread == 0 {
        return None;
    }
    ensure_thread_queue_event(w32thread);
    let body = read_volatile(
        (w32thread + THREADINFO_PEVENT_QUEUE_SERVER_OFF) as *const u64,
    );
    (body != 0).then_some(body)
}

/// `HANDLE PsGetCurrentProcessId()` / `PsGetCurrentThreadProcessId()` for the routed client. The
/// bootstrap identity remains in place until the first client request reaches the component.
extern "win64" fn s_current_process_id() -> u64 {
    WIN32K_CURRENT_PROCESS_ID.load(Ordering::Relaxed)
}

unsafe fn zero_region(base: u64, size: u64) {
    let mut offset = 0u64;
    while offset < size {
        write_volatile((base + offset) as *mut u64, 0);
        offset += 8;
    }
}

unsafe fn current_client_index() -> usize {
    let pi = WIN32K_CURRENT_CLIENT_PI.load(Ordering::Relaxed) as usize;
    if pi < MAX_PI {
        pi
    } else {
        WIN32K_BOOTSTRAP_PI
    }
}

unsafe fn checked_client_index(pi: u64) -> Option<usize> {
    let pi = pi as usize;
    (pi < MAX_PI).then_some(pi)
}

unsafe fn allocate_kernel_object_body(size: u64) -> u64 {
    let body = pool_alloc(size);
    if body != 0 {
        zero_region(body, size);
    }
    body
}

unsafe fn process_context_index_for_pid(pid: u64) -> Option<usize> {
    if pid == 0 {
        return None;
    }
    for index in 0..WIN32K_GUI_PROCESS_CAP {
        if WIN32K_PROCESS_CTX_PIDS[index].load(Ordering::Relaxed) == pid {
            return Some(index);
        }
    }
    None
}

unsafe fn process_context_index_for_eprocess(process: u64) -> Option<usize> {
    if process == 0 {
        return None;
    }
    for index in 0..WIN32K_GUI_PROCESS_CAP {
        if WIN32K_PROCESS_CTX_EPROCESS[index].load(Ordering::Relaxed) == process {
            return Some(index);
        }
    }
    None
}

unsafe fn current_process_context_index() -> Option<usize> {
    process_context_index_for_pid(WIN32K_CURRENT_PROCESS_ID.load(Ordering::Relaxed))
}

unsafe fn thread_context_index_for_tid(tid: u64) -> Option<usize> {
    if tid == 0 {
        return None;
    }
    for index in 0..WIN32K_GUI_THREAD_CAP {
        if WIN32K_THREAD_CTX_TIDS[index].load(Ordering::Relaxed) == tid {
            return Some(index);
        }
    }
    None
}

unsafe fn thread_context_index_for_ethread(thread: u64) -> Option<usize> {
    if thread == 0 {
        return None;
    }
    for index in 0..WIN32K_GUI_THREAD_CAP {
        if WIN32K_THREAD_CTX_ETHREAD[index].load(Ordering::Relaxed) == thread {
            return Some(index);
        }
    }
    None
}

unsafe fn thread_context_index_for_w32thread(thread: u64) -> Option<usize> {
    if thread == 0 {
        return None;
    }
    for index in 0..WIN32K_GUI_THREAD_CAP {
        if WIN32K_THREAD_CTX_W32THREAD[index].load(Ordering::Relaxed) == thread {
            return Some(index);
        }
    }
    None
}

unsafe fn current_thread_context_index() -> Option<usize> {
    thread_context_index_for_tid(WIN32K_CURRENT_THREAD_ID.load(Ordering::Relaxed))
}

unsafe fn current_eprocess() -> u64 {
    current_process_context_index()
        .map(|index| WIN32K_PROCESS_CTX_EPROCESS[index].load(Ordering::Relaxed))
        .unwrap_or(0)
}

unsafe fn current_ethread() -> u64 {
    current_thread_context_index()
        .map(|index| WIN32K_THREAD_CTX_ETHREAD[index].load(Ordering::Relaxed))
        .unwrap_or(0)
}

unsafe fn current_w32process() -> u64 {
    let Some(index) = current_process_context_index() else {
        return 0;
    };
    let eprocess = WIN32K_PROCESS_CTX_EPROCESS[index].load(Ordering::Relaxed);
    if eprocess != 0 {
        let field = read_volatile((eprocess + EPROCESS_WIN32PROCESS_OFF) as *const u64);
        if field != 0 {
            if WIN32K_PROCESS_CTX_W32PROCESS[index].load(Ordering::Relaxed) == 0 {
                WIN32K_PROCESS_CTX_W32PROCESS[index].store(field, Ordering::Relaxed);
            }
            return field;
        }
    }
    WIN32K_PROCESS_CTX_W32PROCESS[index].load(Ordering::Relaxed)
}

unsafe fn current_w32thread() -> u64 {
    current_thread_context_index()
        .map(|index| WIN32K_THREAD_CTX_W32THREAD[index].load(Ordering::Relaxed))
        .unwrap_or(0)
}

fn print_win32k_hex64(value: u64) {
    print_hex((value >> 32) as u32);
    print_hex(value as u32);
}

unsafe fn read_u64_field_if_present(base: u64, offset: u64) -> u64 {
    if base == 0 {
        0
    } else {
        read_volatile((base + offset) as *const u64)
    }
}

/// Wall-only context diagnostic for ReactOS win32k failures that depend on the current-thread object.
/// `UserRefObjectCo` / `UserDerefObjectCo` use `PsGetCurrentThreadWin32Thread()->ReferencesList`;
/// when that list is unexpectedly empty, the important state is which ETHREAD/THREADINFO win32k saw
/// at the exact fault, not whichever client request the executive handles next.
pub(crate) unsafe fn trace_win32k_wall_context() {
    let n = WIN32K_WALL_CONTEXT_TRACES.fetch_add(1, Ordering::Relaxed);
    if n >= 8 {
        return;
    }
    let pi = WIN32K_CURRENT_CLIENT_PI.load(Ordering::Relaxed);
    let pid = WIN32K_CURRENT_PROCESS_ID.load(Ordering::Relaxed);
    let tid = WIN32K_CURRENT_THREAD_ID.load(Ordering::Relaxed);
    let eprocess = current_eprocess();
    let ethread = current_ethread();
    let w32process = current_w32process();
    let w32thread = current_w32thread();
    let slot_process = read_volatile(SLOT_W32PROCESS as *const u64);
    let slot_thread = read_volatile(SLOT_W32THREAD as *const u64);
    let kpcr_teb = read_volatile((WIN32K_KPCR_VA + 0x30) as *const u64);
    let kpcr_process = read_volatile((WIN32K_KPCR_VA + 0x60) as *const u64);
    let kpcr_thread = read_volatile((WIN32K_KPCR_VA + 0x188) as *const u64);
    let kthread_w32thread = read_u64_field_if_present(ethread, KTHREAD_WIN32THREAD_OFF);
    let refs = read_u64_field_if_present(w32thread, 0x2f8);
    let locks = if w32thread == 0 {
        0
    } else {
        read_volatile((w32thread + 0x344) as *const u32) as u64
    };
    print_str(b"[w32ctx-wall] #");
    print_u64(n);
    print_str(b" current pi=");
    print_u64(pi);
    print_str(b" pid=");
    print_u64(pid);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" eprocess=0x");
    print_win32k_hex64(eprocess);
    print_str(b" ethread=0x");
    print_win32k_hex64(ethread);
    print_str(b" ppi=0x");
    print_win32k_hex64(w32process);
    print_str(b" pti=0x");
    print_win32k_hex64(w32thread);
    print_str(b"\n");
    print_str(b"[w32ctx-wall] slots ppi=0x");
    print_win32k_hex64(slot_process);
    print_str(b" pti=0x");
    print_win32k_hex64(slot_thread);
    print_str(b" kpcr-teb=0x");
    print_win32k_hex64(kpcr_teb);
    print_str(b" kpcr-process=0x");
    print_win32k_hex64(kpcr_process);
    print_str(b" kpcr-thread=0x");
    print_win32k_hex64(kpcr_thread);
    print_str(b" kth-pti=0x");
    print_win32k_hex64(kthread_w32thread);
    print_str(b" refs=0x");
    print_win32k_hex64(refs);
    print_str(b" locks=");
    print_u64(locks);
    print_str(b"\n");

    let mut printed = 0usize;
    for index in 0..WIN32K_GUI_THREAD_CAP {
        let row_tid = WIN32K_THREAD_CTX_TIDS[index].load(Ordering::Relaxed);
        if row_tid == 0 || WIN32K_THREAD_CTX_PIS[index].load(Ordering::Relaxed) != pi {
            continue;
        }
        let row_pid = WIN32K_THREAD_CTX_PIDS[index].load(Ordering::Relaxed);
        let row_ethread = WIN32K_THREAD_CTX_ETHREAD[index].load(Ordering::Relaxed);
        let row_w32thread = WIN32K_THREAD_CTX_W32THREAD[index].load(Ordering::Relaxed);
        let row_refs = read_u64_field_if_present(row_w32thread, 0x2f8);
        let row_kthread_w32thread = read_u64_field_if_present(row_ethread, KTHREAD_WIN32THREAD_OFF);
        print_str(b"[w32ctx-wall] table idx=");
        print_u64(index as u64);
        print_str(b" pid=");
        print_u64(row_pid);
        print_str(b" tid=");
        print_u64(row_tid);
        print_str(b" ethread=0x");
        print_win32k_hex64(row_ethread);
        print_str(b" pti=0x");
        print_win32k_hex64(row_w32thread);
        print_str(b" kth-pti=0x");
        print_win32k_hex64(row_kthread_w32thread);
        print_str(b" refs=0x");
        print_win32k_hex64(row_refs);
        print_str(b"\n");
        printed += 1;
        if printed >= 12 {
            break;
        }
    }
}

unsafe fn eprocess_for_pid(process_id: u64) -> u64 {
    if process_id == 0 {
        return current_eprocess();
    }
    process_context_index_for_pid(process_id)
        .map(|index| WIN32K_PROCESS_CTX_EPROCESS[index].load(Ordering::Relaxed))
        .unwrap_or(0)
}

unsafe fn initialize_eprocess_body(eprocess: u64, process_id: u64) {
    let q = eprocess + 0x900;
    let zstr = eprocess + 0xA00;
    write_volatile((eprocess + 0x20) as *mut u64, q);
    write_volatile((q + 0x80) as *mut u64, zstr);
    write_volatile(zstr as *mut u16, 0);
    write_volatile(
        (eprocess + EPROCESS_UNIQUE_PROCESS_ID_OFF) as *mut u64,
        process_id,
    );
    if read_volatile((eprocess + EPROCESS_PEB_OFF) as *const u64) == 0 {
        write_volatile((eprocess + EPROCESS_PEB_OFF) as *mut u64, eprocess + 0x800);
    }
}

unsafe fn seed_win32k_callout_teb(thread_index: usize) -> Option<u64> {
    let existing = WIN32K_THREAD_CTX_CALLOUT_TEB[thread_index].load(Ordering::Relaxed);
    let teb = if existing != 0 {
        existing
    } else {
        let allocated = pool_alloc(0x1000);
        if allocated != 0 {
            s_memset(allocated, 0, 0x1000);
            WIN32K_THREAD_CTX_CALLOUT_TEB[thread_index].store(allocated, Ordering::Relaxed);
            allocated
        } else {
            return None;
        }
    };

    let peb = teb + 0xA00;
    let process_params = teb + 0xB00;
    let mut pid = WIN32K_THREAD_CTX_PIDS[thread_index].load(Ordering::Relaxed);
    let mut tid = WIN32K_THREAD_CTX_TIDS[thread_index].load(Ordering::Relaxed);
    if pid == 0 {
        pid = FAKE_PROCESS_HANDLE;
    }
    if tid == 0 {
        tid = pid.wrapping_add(0x100);
    }

    write_volatile((teb + TEB_SELF_OFF) as *mut u64, teb);
    write_volatile((teb + TEB_CLIENT_ID_PROCESS_OFF) as *mut u64, pid);
    write_volatile((teb + TEB_CLIENT_ID_THREAD_OFF) as *mut u64, tid);
    write_volatile((teb + TEB_PROCESS_ENVIRONMENT_BLOCK_OFF) as *mut u64, peb);
    write_volatile(
        (peb + PEB_PROCESS_PARAMETERS_OFF) as *mut u64,
        process_params,
    );
    Some(teb)
}

unsafe fn prepare_ethread_for_win32k_callout(thread_index: usize, teb: u64) {
    let pid = WIN32K_THREAD_CTX_PIDS[thread_index].load(Ordering::Relaxed);
    let eprocess = eprocess_for_pid(pid);
    let ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);
    if eprocess == 0 || ethread == 0 {
        return;
    }

    let mut process_id = pid;
    let mut tid = WIN32K_THREAD_CTX_TIDS[thread_index].load(Ordering::Relaxed);
    if process_id == 0 {
        process_id = FAKE_PROCESS_HANDLE;
    }
    if tid == 0 {
        tid = process_id.wrapping_add(0x100);
    }

    write_volatile((ethread + KTHREAD_TEB_OFF) as *mut u64, teb);
    write_volatile((ethread + KTHREAD_PROCESS_OFF) as *mut u64, eprocess);
    write_volatile(
        (ethread + ETHREAD_CID_UNIQUE_PROCESS_OFF) as *mut u64,
        process_id,
    );
    write_volatile((ethread + ETHREAD_CID_UNIQUE_THREAD_OFF) as *mut u64, tid);
    write_volatile(
        (ethread + ETHREAD_THREADS_PROCESS_OFF) as *mut u64,
        eprocess,
    );
}

unsafe fn context_object_matches_or_empty(slot: &AtomicU64, supplied: u64) -> bool {
    let existing = slot.load(Ordering::Relaxed);
    supplied == 0 || existing == 0 || existing == supplied
}

unsafe fn store_context_object_or_allocate(
    slot: &AtomicU64,
    supplied: u64,
    size: u64,
) -> Option<u64> {
    let existing = slot.load(Ordering::Relaxed);
    if existing != 0 {
        return Some(existing);
    }
    let object = if supplied != 0 {
        supplied
    } else {
        allocate_kernel_object_body(size)
    };
    if object == 0 {
        return None;
    }
    slot.store(object, Ordering::Relaxed);
    Some(object)
}

unsafe fn publish_selected_context(process_index: usize, thread_index: usize) {
    let pid = WIN32K_PROCESS_CTX_PIDS[process_index].load(Ordering::Relaxed);
    let tid = WIN32K_THREAD_CTX_TIDS[thread_index].load(Ordering::Relaxed);
    let eprocess = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
    let ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);
    let w32process = WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed);
    let w32thread = WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed);
    write_volatile((WIN32K_SHARED_VADDR + SH_CTX_PROCESS_ID) as *mut u64, pid);
    write_volatile((WIN32K_SHARED_VADDR + SH_CTX_THREAD_ID) as *mut u64, tid);
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_EPROCESS) as *mut u64,
        eprocess,
    );
    write_volatile((WIN32K_SHARED_VADDR + SH_CTX_ETHREAD) as *mut u64, ethread);
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_W32PROCESS) as *mut u64,
        w32process,
    );
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_CTX_W32THREAD) as *mut u64,
        w32thread,
    );
}

#[derive(Clone, Copy)]
struct Win32kCallbackRequestContext {
    pi: u32,
    pid: u64,
    tid: u64,
    client_teb: u64,
    supplied_eprocess: u64,
    supplied_ethread: u64,
    process_role: u64,
}

unsafe fn callback_request_context_for_request(
    request: &nt_user_callback::CallbackHeader,
) -> Option<Win32kCallbackRequestContext> {
    if request.client_pi == 0 || request.client_tid == 0 {
        return None;
    }
    let thread_index = thread_context_index_for_tid(request.client_tid)?;
    let pid = WIN32K_THREAD_CTX_PIDS[thread_index].load(Ordering::Relaxed);
    if pid == 0 {
        return None;
    }
    let process_index = process_context_index_for_pid(pid)?;
    if WIN32K_PROCESS_CTX_PIS[process_index].load(Ordering::Relaxed) != request.client_pi as u64
        || WIN32K_THREAD_CTX_PIS[thread_index].load(Ordering::Relaxed) != request.client_pi as u64
    {
        return None;
    }

    let sh = WIN32K_SHARED_VADDR;
    let sh_pi = read_volatile((sh + SH_REQ_CLIENT_PI) as *const u64);
    let sh_pid = read_volatile((sh + SH_REQ_PROCESS_ID) as *const u64);
    let sh_tid = read_volatile((sh + SH_REQ_THREAD_ID) as *const u64);
    let sh_matches_request =
        sh_pi == request.client_pi as u64 && sh_pid == pid && sh_tid == request.client_tid;
    let role_matches_process = sh_pi == request.client_pi as u64 && sh_pid == pid;
    let table_teb = WIN32K_THREAD_CTX_TEB[thread_index].load(Ordering::Relaxed);
    let supplied_eprocess = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
    let supplied_ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);

    Some(Win32kCallbackRequestContext {
        pi: request.client_pi,
        pid,
        tid: request.client_tid,
        client_teb: if sh_matches_request {
            let sh_teb = read_volatile((sh + SH_REQ_CLIENT_TEB) as *const u64);
            if sh_teb != 0 {
                sh_teb
            } else {
                table_teb
            }
        } else {
            table_teb
        },
        supplied_eprocess,
        supplied_ethread,
        process_role: if role_matches_process {
            read_volatile((sh + SH_REQ_PROCESS_ROLE) as *const u64)
        } else {
            HOSTED_PROCESS_ROLE_NONE
        },
    })
}

unsafe fn restore_user_callback_request_context(context: Win32kCallbackRequestContext) -> bool {
    restore_current_context_for_user_callback_resume_inner(
        context.pi,
        context.pid,
        context.tid,
        context.client_teb,
        context.supplied_eprocess,
        context.supplied_ethread,
        context.process_role,
        true,
        false,
    )
}

pub(crate) unsafe fn restore_current_context_for_user_callback_resume(
    pi: u32,
    pid: u64,
    tid: u64,
    client_teb: u64,
    supplied_eprocess: u64,
    supplied_ethread: u64,
    process_role: u64,
) -> bool {
    restore_current_context_for_user_callback_resume_inner(
        pi,
        pid,
        tid,
        client_teb,
        supplied_eprocess,
        supplied_ethread,
        process_role,
        true,
        true,
    )
}

unsafe fn restore_current_context_for_user_callback_resume_inner(
    pi: u32,
    pid: u64,
    tid: u64,
    client_teb: u64,
    supplied_eprocess: u64,
    supplied_ethread: u64,
    process_role: u64,
    publish_context: bool,
    trace_resume: bool,
) -> bool {
    if pid == 0 || tid == 0 {
        let n = WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: callback resume missing pid/tid pi=");
            print_u64(pi as u64);
            print_str(b" pid=");
            print_u64(pid);
            print_str(b" tid=");
            print_u64(tid);
            print_str(b"\n");
        }
        return false;
    }
    let Some(process_index) = process_context_index_for_pid(pid) else {
        let n = WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: callback resume unknown pid=");
            print_u64(pid);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b"\n");
        }
        return false;
    };
    let Some(thread_index) = thread_context_index_for_tid(tid) else {
        let n = WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: callback resume unknown tid=");
            print_u64(tid);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b"\n");
        }
        return false;
    };
    if WIN32K_PROCESS_CTX_PIS[process_index].load(Ordering::Relaxed) != pi as u64
        || WIN32K_THREAD_CTX_PIS[thread_index].load(Ordering::Relaxed) != pi as u64
    {
        let n = WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: callback resume pi mismatch pi=");
            print_u64(pi as u64);
            print_str(b" pid=");
            print_u64(pid);
            print_str(b" tid=");
            print_u64(tid);
            print_str(b"\n");
        }
        return false;
    }
    let eprocess = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
    let ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);
    let w32process = WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed);
    let w32thread = WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed);
    if client_teb != 0 {
        WIN32K_THREAD_CTX_TEB[thread_index].store(client_teb, Ordering::Relaxed);
    }
    let Some(teb) = seed_win32k_callout_teb(thread_index) else {
        let n = WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: callback resume could not select TEB pi=");
            print_u64(pi as u64);
            print_str(b" pid=");
            print_u64(pid);
            print_str(b" tid=");
            print_u64(tid);
            print_str(b"\n");
        }
        return false;
    };
    if eprocess == 0
        || ethread == 0
        || w32process == 0
        || w32thread == 0
        || (supplied_eprocess != 0 && supplied_eprocess != eprocess)
        || (supplied_ethread != 0 && supplied_ethread != ethread)
    {
        let n = WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: callback resume object mismatch pi=");
            print_u64(pi as u64);
            print_str(b" pid=");
            print_u64(pid);
            print_str(b" tid=");
            print_u64(tid);
            print_str(b" eprocess=0x");
            print_hex((eprocess >> 32) as u32);
            print_hex(eprocess as u32);
            print_str(b" ethread=0x");
            print_hex((ethread >> 32) as u32);
            print_hex(ethread as u32);
            print_str(b" pti=0x");
            print_hex((w32thread >> 32) as u32);
            print_hex(w32thread as u32);
            print_str(b"\n");
        }
        return false;
    }

    WIN32K_CURRENT_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(tid, Ordering::Relaxed);
    prepare_ethread_for_win32k_callout(thread_index, teb);
    write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, teb);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, ethread);
    write_volatile(SLOT_W32PROCESS as *mut u64, w32process);
    write_volatile(SLOT_W32THREAD as *mut u64, w32thread);
    write_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *mut u64, w32thread);
    write_volatile(w32thread as *mut u64, ethread);
    sync_threadinfo_process(w32thread);
    if publish_context {
        publish_selected_context(process_index, thread_index);
    }

    let ppi = current_w32process();
    if let Some((hdesk, desk_body, pdeskinfo)) =
        selected_thread_desktop(process_role, ppi, w32thread)
    {
        publish_thread_desktop_binding(w32thread, hdesk, desk_body, pdeskinfo);
    }

    if trace_resume {
        let n = WIN32K_CALLBACK_RESUME_CONTEXT_RESTORES.fetch_add(1, Ordering::Relaxed);
        if n < 24 {
            let refs = read_volatile((w32thread + 0x2f8) as *const u64);
            let locks = read_volatile((w32thread + 0x344) as *const u32);
            print_str(b"[win32k-context] callback resume selected pi=");
            print_u64(pi as u64);
            print_str(b" pid=");
            print_u64(pid);
            print_str(b" tid=");
            print_u64(tid);
            print_str(b" pti=0x");
            print_hex((w32thread >> 32) as u32);
            print_hex(w32thread as u32);
            print_str(b" teb=0x");
            print_hex((teb >> 32) as u32);
            print_hex(teb as u32);
            print_str(b" refs=0x");
            print_hex((refs >> 32) as u32);
            print_hex(refs as u32);
            print_str(b" locks=");
            print_u64(locks as u64);
            print_str(b"\n");
        }
    }
    true
}

unsafe fn ensure_process_context(pi: usize, pid: u64, supplied_eprocess: u64) -> Option<usize> {
    if pid == 0 {
        return None;
    }
    if let Some(index) = process_context_index_for_pid(pid) {
        WIN32K_PROCESS_CTX_PIS[index].store(pi as u64, Ordering::Relaxed);
        if !context_object_matches_or_empty(&WIN32K_PROCESS_CTX_EPROCESS[index], supplied_eprocess)
        {
            print_str(b"[win32k-context] ERROR: supplied EPROCESS mismatch for pid=");
            print_u64(pid);
            print_str(b"\n");
            return None;
        }
        let eprocess = store_context_object_or_allocate(
            &WIN32K_PROCESS_CTX_EPROCESS[index],
            supplied_eprocess,
            WIN32K_EPROCESS_BYTES,
        )?;
        initialize_eprocess_body(eprocess, pid);
        return Some(index);
    }
    for index in 0..WIN32K_GUI_PROCESS_CAP {
        if WIN32K_PROCESS_CTX_PIDS[index].load(Ordering::Relaxed) == 0 {
            let eprocess = store_context_object_or_allocate(
                &WIN32K_PROCESS_CTX_EPROCESS[index],
                supplied_eprocess,
                WIN32K_EPROCESS_BYTES,
            )?;
            WIN32K_PROCESS_CTX_PIDS[index].store(pid, Ordering::Relaxed);
            WIN32K_PROCESS_CTX_PIS[index].store(pi as u64, Ordering::Relaxed);
            initialize_eprocess_body(eprocess, pid);
            return Some(index);
        }
    }
    None
}

unsafe fn ensure_thread_context(
    pi: usize,
    pid: u64,
    tid: u64,
    teb: u64,
    supplied_ethread: u64,
) -> Option<usize> {
    if pid == 0 || tid == 0 {
        return None;
    }
    if let Some(index) = thread_context_index_for_tid(tid) {
        if WIN32K_THREAD_CTX_PIDS[index].load(Ordering::Relaxed) != pid {
            return None;
        }
        WIN32K_THREAD_CTX_PIS[index].store(pi as u64, Ordering::Relaxed);
        if teb != 0 {
            WIN32K_THREAD_CTX_TEB[index].store(teb, Ordering::Relaxed);
        }
        if !context_object_matches_or_empty(&WIN32K_THREAD_CTX_ETHREAD[index], supplied_ethread) {
            print_str(b"[win32k-context] ERROR: supplied ETHREAD mismatch for tid=");
            print_u64(tid);
            print_str(b"\n");
            return None;
        }
        let _ = store_context_object_or_allocate(
            &WIN32K_THREAD_CTX_ETHREAD[index],
            supplied_ethread,
            WIN32K_ETHREAD_BYTES,
        )?;
        return Some(index);
    }
    for index in 0..WIN32K_GUI_THREAD_CAP {
        if WIN32K_THREAD_CTX_TIDS[index].load(Ordering::Relaxed) == 0 {
            let _ethread = store_context_object_or_allocate(
                &WIN32K_THREAD_CTX_ETHREAD[index],
                supplied_ethread,
                WIN32K_ETHREAD_BYTES,
            )?;
            WIN32K_THREAD_CTX_TIDS[index].store(tid, Ordering::Relaxed);
            WIN32K_THREAD_CTX_PIDS[index].store(pid, Ordering::Relaxed);
            WIN32K_THREAD_CTX_PIS[index].store(pi as u64, Ordering::Relaxed);
            WIN32K_THREAD_CTX_TEB[index].store(teb, Ordering::Relaxed);
            return Some(index);
        }
    }
    None
}

unsafe fn derive_client_identity(
    pi: usize,
    process_id: u64,
    thread_id: u64,
    client_teb: u64,
) -> Option<(u64, u64)> {
    let mut pid = process_id;
    let mut tid = thread_id;
    if client_teb != 0 {
        let teb_pid = read_volatile((client_teb + TEB_CLIENT_ID_PROCESS_OFF) as *const u64);
        let teb_tid = read_volatile((client_teb + TEB_CLIENT_ID_THREAD_OFF) as *const u64);
        if pid == 0 && teb_pid != 0 {
            pid = teb_pid;
        }
        if tid == 0 && teb_tid != 0 {
            tid = teb_tid;
        }
    }
    if pid == 0 {
        pid = WIN32K_CURRENT_PROCESS_ID.load(Ordering::Relaxed);
    }
    if pid == 0 {
        pid = FAKE_PROCESS_HANDLE;
    }
    if tid == 0 {
        tid = WIN32K_CURRENT_THREAD_ID.load(Ordering::Relaxed);
    }
    if tid == 0 {
        tid = pid.wrapping_add(0x100 + pi as u64);
    }
    Some((pid, tid))
}

unsafe fn adopt_bootstrap_csrss_context(
    pi: usize,
    pid: u64,
    tid: u64,
    teb: u64,
    supplied_eprocess: u64,
    supplied_ethread: u64,
    token_authentication_id: u64,
    token_user_sid: &[u8],
    token_user_sid_len: usize,
) -> Option<(usize, usize)> {
    if pid == 0 || tid == 0 {
        return None;
    }

    let process_index = if let Some(existing) = process_context_index_for_pid(pid) {
        existing
    } else {
        process_context_index_for_pid(FAKE_PROCESS_HANDLE)?
    };
    let eprocess = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
    if eprocess == 0 || (supplied_eprocess != 0 && supplied_eprocess != eprocess) {
        return None;
    }

    let thread_index = if let Some(existing) = thread_context_index_for_tid(tid) {
        existing
    } else {
        thread_context_index_for_tid(WIN32K_BOOTSTRAP_TID)?
    };
    let ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);
    if ethread == 0 || (supplied_ethread != 0 && supplied_ethread != ethread) {
        return None;
    }

    WIN32K_PROCESS_CTX_PIDS[process_index].store(pid, Ordering::Relaxed);
    WIN32K_PROCESS_CTX_PIS[process_index].store(pi as u64, Ordering::Relaxed);
    initialize_eprocess_body(eprocess, pid);
    if !record_process_token_context(
        process_index,
        token_authentication_id,
        token_user_sid,
        token_user_sid_len,
    ) {
        return None;
    }

    let ppi = WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed);
    if ppi != 0 {
        write_volatile((ppi + W32PROCESS_PEPROCESS_OFF) as *mut u64, eprocess);
        write_volatile((ppi + W32PROCESS_W32PID_OFF) as *mut u32, pid as u32);
    }

    WIN32K_THREAD_CTX_TIDS[thread_index].store(tid, Ordering::Relaxed);
    WIN32K_THREAD_CTX_PIDS[thread_index].store(pid, Ordering::Relaxed);
    WIN32K_THREAD_CTX_PIS[thread_index].store(pi as u64, Ordering::Relaxed);
    let effective_teb = if teb != 0 {
        WIN32K_THREAD_CTX_TEB[thread_index].store(teb, Ordering::Relaxed);
        seed_win32k_callout_teb(thread_index)?
    } else {
        seed_win32k_callout_teb(thread_index)?
    };
    prepare_ethread_for_win32k_callout(thread_index, effective_teb);

    WIN32K_CURRENT_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(tid, Ordering::Relaxed);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, ethread);
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed),
    );
    write_volatile(
        SLOT_W32THREAD as *mut u64,
        WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed),
    );
    publish_selected_context(process_index, thread_index);

    if WIN32K_CSRSS_BOOTSTRAP_REKEYS.fetch_add(1, Ordering::Relaxed) < 4 {
        print_str(b"[win32k-context] adopted bootstrap CSRSS context pid=");
        print_u64(pid);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" pi=");
        print_u64(pi as u64);
        print_str(b" eprocess=0x");
        print_hex((eprocess >> 32) as u32);
        print_hex(eprocess as u32);
        print_str(b" ethread=0x");
        print_hex((ethread >> 32) as u32);
        print_hex(ethread as u32);
        print_str(b"\n");
    }

    Some((process_index, thread_index))
}

unsafe fn select_win32k_client_context(
    pi: u64,
    process_id: u64,
    thread_id: u64,
    client_teb: u64,
    supplied_eprocess: u64,
    supplied_ethread: u64,
    process_role: u64,
    token_authentication_id: u64,
    token_user_sid: &[u8],
    token_user_sid_len: usize,
) -> Option<(usize, usize)> {
    let pi = checked_client_index(pi)?;
    let (pid, tid) = derive_client_identity(pi, process_id, thread_id, client_teb)?;
    if process_role == HOSTED_PROCESS_ROLE_WIN32_SUBSYSTEM {
        if let Some(adopted) = adopt_bootstrap_csrss_context(
            pi,
            pid,
            tid,
            client_teb,
            supplied_eprocess,
            supplied_ethread,
            token_authentication_id,
            token_user_sid,
            token_user_sid_len,
        ) {
            return Some(adopted);
        }
    }
    let process_index = ensure_process_context(pi, pid, supplied_eprocess)?;
    if !record_process_token_context(
        process_index,
        token_authentication_id,
        token_user_sid,
        token_user_sid_len,
    ) {
        return None;
    }
    let thread_index = ensure_thread_context(pi, pid, tid, client_teb, supplied_ethread)?;
    let eprocess = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
    let ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);
    initialize_eprocess_body(eprocess, pid);
    WIN32K_CURRENT_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(tid, Ordering::Relaxed);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, ethread);
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed),
    );
    write_volatile(
        SLOT_W32THREAD as *mut u64,
        WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed),
    );
    publish_selected_context(process_index, thread_index);
    Some((process_index, thread_index))
}

unsafe fn ensure_bootstrap_win32k_context() -> Option<(usize, usize)> {
    let (system_sid, system_sid_len) = local_system_sid_native();
    select_win32k_client_context(
        WIN32K_BOOTSTRAP_PI as u64,
        FAKE_PROCESS_HANDLE,
        WIN32K_BOOTSTRAP_TID,
        0,
        0,
        0,
        HOSTED_PROCESS_ROLE_NONE,
        nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_LOW as u64
            | ((nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_HIGH as u32 as u64) << 32),
        &system_sid,
        system_sid_len,
    )
}

unsafe fn ensure_win32k_process_attached(process_index: usize, process_role: u64) -> bool {
    if process_index >= WIN32K_GUI_PROCESS_CAP {
        return false;
    }
    if WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed) == 0 {
        let callout = read_volatile(WIN32_CALLOUTS as *const u64);
        if callout != 0 {
            let process = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
            let co: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(callout as *const ());
            let status = co(process, 1);
            let slot_value = read_volatile(SLOT_W32PROCESS as *const u64);
            if slot_value != 0 {
                WIN32K_PROCESS_CTX_W32PROCESS[process_index].store(slot_value, Ordering::Relaxed);
            } else if process != 0 {
                let field = read_volatile((process + EPROCESS_WIN32PROCESS_OFF) as *const u64);
                if field != 0 {
                    WIN32K_PROCESS_CTX_W32PROCESS[process_index].store(field, Ordering::Relaxed);
                    write_volatile(SLOT_W32PROCESS as *mut u64, field);
                }
            }
            if let Some(thread_index) = current_thread_context_index() {
                publish_selected_context(process_index, thread_index);
            }
            let n = WIN32K_CLIENT_PROCESS_CALLOUTS.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                let pi = WIN32K_PROCESS_CTX_PIS[process_index].load(Ordering::Relaxed);
                let pid = WIN32K_PROCESS_CTX_PIDS[process_index].load(Ordering::Relaxed);
                print_str(b"[win32k-context] process callout pid=");
                print_u64(pid);
                print_str(b" pi=");
                print_u64(pi);
                print_str(b" status=0x");
                print_hex(status as u32);
                print_str(b" ppi=0x");
                let ppi = WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed);
                print_hex((ppi >> 32) as u32);
                print_hex(ppi as u32);
                print_str(b"\n");
            }
        }
    }
    if WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed) == 0 {
        let pid = WIN32K_PROCESS_CTX_PIDS[process_index].load(Ordering::Relaxed);
        print_str(b"[win32k-context] ERROR: process callout did not publish W32PROCESS for pid=");
        print_u64(pid);
        print_str(b"\n");
        return false;
    }
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed),
    );
    link_processinfo_to_eprocess(process_index);
    if process_role == HOSTED_PROCESS_ROLE_NONINTERACTIVE_SERVICE {
        let n = WIN32K_NONINTERACTIVE_WINSTA_RESOLVES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            let pi = WIN32K_PROCESS_CTX_PIS[process_index].load(Ordering::Relaxed);
            let pid = WIN32K_PROCESS_CTX_PIDS[process_index].load(Ordering::Relaxed);
            let ppi = WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed);
            print_str(b"[win32k-host] noninteractive service desktop left to InitThreadCallback pid=");
            print_u64(pid);
            print_str(b" pi=");
            print_u64(pi);
            print_str(b" ppi=0x");
            print_hex((ppi >> 32) as u32);
            print_hex(ppi as u32);
            print_str(b"\n");
        }
    } else {
        seed_inherited_process_window_station(process_index);
    }
    true
}

unsafe fn link_processinfo_to_eprocess(process_index: usize) {
    let process = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
    let ppi = WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed);
    if process == 0 || ppi == 0 {
        return;
    }
    let eprocess_win32 = (process + EPROCESS_WIN32PROCESS_OFF) as *mut u64;
    if read_volatile(eprocess_win32) == 0 {
        write_volatile(eprocess_win32, ppi);
    }
    if read_volatile((ppi + W32PROCESS_PEPROCESS_OFF) as *const u64) == 0 {
        write_volatile((ppi + W32PROCESS_PEPROCESS_OFF) as *mut u64, process);
    }
}

unsafe fn seed_inherited_process_window_station(process_index: usize) {
    let ppi = WIN32K_PROCESS_CTX_W32PROCESS[process_index].load(Ordering::Relaxed);
    if ppi == 0 {
        return;
    }
    let table = &*core::ptr::addr_of!(OBJ_TABLE);
    let winsta_handle = table.cached_winsta_handle();
    let winsta_body = table.cached_winsta_body();
    if winsta_handle == 0 || winsta_body == 0 {
        return;
    }

    link_processinfo_to_eprocess(process_index);
    let eprocess = WIN32K_PROCESS_CTX_EPROCESS[process_index].load(Ordering::Relaxed);
    if eprocess != 0 && s_ps_get_process_winsta(eprocess) == 0 {
        s_ps_set_process_winsta(eprocess, winsta_handle);
    }

    let mut seeded_winsta = false;
    if read_volatile((ppi + PROCESSINFO_PRPWINSTA_OFF) as *const u64) == 0 {
        write_volatile((ppi + PROCESSINFO_PRPWINSTA_OFF) as *mut u64, winsta_body);
        write_volatile((ppi + PROCESSINFO_HWINSTA_OFF) as *mut u64, winsta_handle);
        write_volatile(
            (ppi + PROCESSINFO_AMWINSTA_OFF) as *mut u32,
            WINSTA_ALL_ACCESS,
        );
        let flags = read_volatile((ppi + W32PROCESS_FLAGS_OFF) as *const u32);
        write_volatile(
            (ppi + W32PROCESS_FLAGS_OFF) as *mut u32,
            flags | W32PF_READSCREENACCESSGRANTED,
        );
        seeded_winsta = true;
    }
    seed_default_startup_desktop_for_process(ppi, 0);

    if seeded_winsta && WIN32K_INHERITED_WINSTA_SEEDS.fetch_add(1, Ordering::Relaxed) < 16 {
        let pi = WIN32K_PROCESS_CTX_PIS[process_index].load(Ordering::Relaxed);
        let pid = WIN32K_PROCESS_CTX_PIDS[process_index].load(Ordering::Relaxed);
        print_str(b"[win32k-host] inherited WinSta0 for pid=");
        print_u64(pid);
        print_str(b" pi=");
        print_u64(pi as u64);
        print_str(b" ppi=0x");
        print_hex((ppi >> 32) as u32);
        print_hex(ppi as u32);
        print_str(b" hWinSta=0x");
        print_hex(winsta_handle as u32);
        print_str(b" body=0x");
        print_hex((winsta_body >> 32) as u32);
        print_hex(winsta_body as u32);
        print_str(b"\n");
    }
}

unsafe fn publish_default_desktop(hdesk: u64, desk_body: u64, source: &[u8]) {
    if hdesk == 0 || desk_body == 0 {
        return;
    }
    let old_hdesk = WIN32K_DEFAULT_DESKTOP_HANDLE.load(Ordering::Relaxed);
    let old_body = WIN32K_DEFAULT_DESKTOP_BODY.load(Ordering::Relaxed);
    WIN32K_DEFAULT_DESKTOP_HANDLE.store(hdesk, Ordering::Relaxed);
    WIN32K_DEFAULT_DESKTOP_BODY.store(desk_body, Ordering::Relaxed);
    if (old_hdesk != hdesk || old_body != desk_body)
        && WIN32K_DEFAULT_DESKTOP_PUBLISHES.fetch_add(1, Ordering::Relaxed) < 16
    {
        print_str(b"[win32k-host] published default desktop from ");
        print_str(source);
        print_str(b" hDesk=0x");
        print_hex(hdesk as u32);
        print_str(b" body=0x");
        print_hex((desk_body >> 32) as u32);
        print_hex(desk_body as u32);
        print_str(b"\n");
    }
}

unsafe fn default_desktop() -> Option<(u64, u64)> {
    let hdesk = WIN32K_DEFAULT_DESKTOP_HANDLE.load(Ordering::Relaxed);
    let desk_body = WIN32K_DEFAULT_DESKTOP_BODY.load(Ordering::Relaxed);
    if hdesk == 0 || desk_body == 0 {
        return None;
    }
    if (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk) != desk_body {
        return None;
    }
    Some((hdesk, desk_body))
}

unsafe fn ensure_desktop_runtime_fields(desk_body: u64) -> Option<u64> {
    if desk_body == 0 {
        return None;
    }
    if read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64) == 0 {
        write_volatile(
            (desk_body + DESKTOP_PHEAP_OFF) as *mut u64,
            WIN32K_HEAP_HANDLE,
        );
    }
    let pdeskinfo = read_volatile((desk_body + 0x08) as *const u64);
    if pdeskinfo == 0 {
        return None;
    }
    if read_volatile(pdeskinfo as *const u64) == 0 {
        write_volatile(pdeskinfo as *mut u64, WIN32K_HEAP_VADDR);
        write_volatile(
            (pdeskinfo + 0x08) as *mut u64,
            WIN32K_HEAP_VADDR + WIN32K_HEAP_FRAMES * 0x1000,
        );
    }
    Some(pdeskinfo)
}

unsafe fn process_startup_desktop(ppi: u64) -> Option<(u64, u64, u64)> {
    if ppi == 0 {
        return None;
    }
    let hdesk = read_volatile((ppi + PROCESSINFO_HDESK_STARTUP_OFF) as *const u64);
    let desk_body = read_volatile((ppi + PROCESSINFO_RPDESK_STARTUP_OFF) as *const u64);
    if hdesk == 0 || desk_body == 0 {
        return None;
    }
    if (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk) != desk_body {
        return None;
    }
    ensure_desktop_runtime_fields(desk_body).map(|pdeskinfo| (hdesk, desk_body, pdeskinfo))
}

unsafe fn selected_thread_desktop(
    process_role: u64,
    ppi: u64,
    pti: u64,
) -> Option<(u64, u64, u64)> {
    if pti == 0 {
        return None;
    }

    let current_body = read_volatile((pti + THREADINFO_RPDESK_OFF) as *const u64);
    let current_info = read_volatile((pti + THREADINFO_PDESKINFO_OFF) as *const u64);
    if current_body != 0 && current_info != 0 {
        let current_hdesk = read_volatile((pti + THREADINFO_HDESK_OFF) as *const u64);
        return Some((current_hdesk, current_body, current_info));
    }

    let shell_client = process_role == HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL_BOOTSTRAP
        || process_role == HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL;
    if shell_client {
        if let Some(startup) = process_startup_desktop(ppi) {
            return Some(startup);
        }
    }

    if process_role != HOSTED_PROCESS_ROLE_NONINTERACTIVE_SERVICE
        && BOUND_DESK_BODY != 0
        && BOUND_DESK_PDESKINFO != 0
    {
        return Some((0, BOUND_DESK_BODY, BOUND_DESK_PDESKINFO));
    }

    process_startup_desktop(ppi)
}

unsafe fn publish_thread_desktop_binding(pti: u64, hdesk: u64, desk_body: u64, pdeskinfo: u64) {
    if pti == 0 || desk_body == 0 || pdeskinfo == 0 {
        return;
    }
    let Some(pdeskinfo) = ensure_desktop_runtime_fields(desk_body) else {
        return;
    };
    write_volatile((pti + THREADINFO_RPDESK_OFF) as *mut u64, desk_body);
    write_volatile((pti + THREADINFO_PDESKINFO_OFF) as *mut u64, pdeskinfo);
    if hdesk != 0 {
        write_volatile((pti + THREADINFO_HDESK_OFF) as *mut u64, hdesk);
    }
    let pci = read_volatile((pti + THREADINFO_PCLIENTINFO_OFF) as *const u64);
    if pci != 0 {
        write_volatile((pci + 0x20) as *mut u64, pdeskinfo);
    }
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_SAS_DESKINFO) as *mut u64,
        pdeskinfo,
    );
    write_volatile((WIN32K_SHARED_VADDR + SH_SAS_PTI) as *mut u64, pti);
}

unsafe fn seed_default_startup_desktop_for_process(ppi: u64, pti: u64) -> bool {
    let Some((hdesk, desk_body)) = default_desktop() else {
        return false;
    };
    seed_process_startup_desktop_for_process(ppi, hdesk, desk_body, pti)
}

unsafe fn ensure_win32k_threadinfo(thread_index: usize, client_teb: u64) -> bool {
    if thread_index >= WIN32K_GUI_THREAD_CAP {
        return false;
    }
    if WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed) == 0 {
        if client_teb != 0 {
            WIN32K_THREAD_CTX_TEB[thread_index].store(client_teb, Ordering::Relaxed);
        }
        let Some(teb) = seed_win32k_callout_teb(thread_index) else {
            let tid = WIN32K_THREAD_CTX_TIDS[thread_index].load(Ordering::Relaxed);
            print_str(b"[win32k-context] ERROR: could not allocate thread callout TEB for tid=");
            print_u64(tid);
            print_str(b"\n");
            return false;
        };
        prepare_ethread_for_win32k_callout(thread_index, teb);
        write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, teb);
        write_volatile(SLOT_W32THREAD as *mut u64, 0);

        let callout = read_volatile((WIN32_CALLOUTS + 8) as *const u64);
        if callout != 0 {
            let ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);
            let co: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(callout as *const ());
            let status = co(ethread, PS_W32_THREAD_CALLOUT_INITIALIZE);
            let slot_value = read_volatile(SLOT_W32THREAD as *const u64);
            if slot_value != 0 {
                WIN32K_THREAD_CTX_W32THREAD[thread_index].store(slot_value, Ordering::Relaxed);
            } else {
                let field = read_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *const u64);
                if field != 0 {
                    WIN32K_THREAD_CTX_W32THREAD[thread_index].store(field, Ordering::Relaxed);
                    write_volatile(SLOT_W32THREAD as *mut u64, field);
                }
            }
            if let Some(process_index) = current_process_context_index() {
                publish_selected_context(process_index, thread_index);
            }
            let n = WIN32K_CLIENT_THREAD_CALLOUTS.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                let pi = WIN32K_THREAD_CTX_PIS[thread_index].load(Ordering::Relaxed);
                let tid = WIN32K_THREAD_CTX_TIDS[thread_index].load(Ordering::Relaxed);
                print_str(b"[win32k-context] thread callout tid=");
                print_u64(tid);
                print_str(b" pi=");
                print_u64(pi);
                print_str(b" status=0x");
                print_hex(status as u32);
                print_str(b" pti=0x");
                let pti = WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed);
                print_hex((pti >> 32) as u32);
                print_hex(pti as u32);
                print_str(b" teb=0x");
                print_hex((teb >> 32) as u32);
                print_hex(teb as u32);
                print_str(b"\n");
            }
        }
    }
    if WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed) == 0 {
        let tid = WIN32K_THREAD_CTX_TIDS[thread_index].load(Ordering::Relaxed);
        print_str(b"[win32k-context] ERROR: thread callout did not publish W32THREAD for tid=");
        print_u64(tid);
        print_str(b"\n");
        return false;
    }
    let thread = WIN32K_THREAD_CTX_W32THREAD[thread_index].load(Ordering::Relaxed);
    write_volatile(SLOT_W32THREAD as *mut u64, thread);
    init_threadinfo_placeholder(thread);
    let ethread = WIN32K_THREAD_CTX_ETHREAD[thread_index].load(Ordering::Relaxed);
    if ethread != 0 {
        write_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *mut u64, thread);
        if read_volatile(thread as *const u64) == 0 {
            write_volatile(thread as *mut u64, ethread);
        }
    }
    true
}

pub(crate) unsafe fn win32k_window_owner_pi(hwnd: u64) -> Option<u32> {
    let pwnd = hwnd_to_pwnd(hwnd);
    if pwnd == 0 {
        return None;
    }
    let pti = read_volatile((pwnd + WND_HEAD_PTI_OFF) as *const u64);
    if pti == 0 {
        return None;
    }
    let thread_index = thread_context_index_for_w32thread(pti)?;
    let pid = WIN32K_THREAD_CTX_PIDS[thread_index].load(Ordering::Relaxed);
    let process_index = process_context_index_for_pid(pid)?;
    Some(WIN32K_PROCESS_CTX_PIS[process_index].load(Ordering::Relaxed) as u32)
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
                write_volatile(
                    (dst_buf + i) as *mut u8,
                    read_volatile((src_buf + i) as *const u8),
                );
                i += 1;
            }
        }
        write_unaligned(dest as *mut u16, n); // Length
    }
}

/// Borrow the used UTF-16 units from a native `UNICODE_STRING` descriptor.
///
/// The descriptor is laid out as `{ USHORT Length, USHORT MaximumLength, padding, PWSTR Buffer }`
/// on x64. `Length` is a byte count and the string need not be NUL terminated.
unsafe fn rtl_unicode_slice<'a>(string: *const u8) -> &'a [u16] {
    if string.is_null() {
        return &[];
    }
    let length = read_unaligned(string as *const u16) as usize;
    let buffer = read_unaligned(string.add(8) as *const u64) as *const u16;
    if buffer.is_null() || length < 2 {
        return &[];
    }
    core::slice::from_raw_parts(buffer, length / 2)
}

/// `LONG RtlCompareUnicodeString(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN)`.
extern "win64" fn s_rtl_compare_unicode_string(
    a: *const u8,
    b: *const u8,
    case_insensitive: u8,
) -> i32 {
    let (a, b) = unsafe { (rtl_unicode_slice(a), rtl_unicode_slice(b)) };
    match nt_compat_exports::rtl::compare_unicode(a, b, case_insensitive != 0) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `BOOLEAN RtlEqualUnicodeString(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN)`.
extern "win64" fn s_rtl_equal_unicode_string(
    a: *const u8,
    b: *const u8,
    case_insensitive: u8,
) -> u8 {
    let (a, b) = unsafe { (rtl_unicode_slice(a), rtl_unicode_slice(b)) };
    nt_compat_exports::rtl::equal_unicode(a, b, case_insensitive != 0) as u8
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
            let la = if (b'A' as u16..=b'Z' as u16).contains(&ca) {
                ca + 32
            } else {
                ca
            };
            let lb = if (b'A' as u16..=b'Z' as u16).contains(&cb) {
                cb + 32
            } else {
                cb
            };
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
/// The executive registers each hosted GDI driver image as it is loaded, and this import resolves
/// only against that registered state (offsets: DriverName@0, ImageAddress@0x10,
/// SectionPointer@0x18, EntryPoint@0x20, ExportSectionPointer@0x28, ImageLength@0x30). Other
/// classes → benign success.
/// Case-insensitive: does the wide DriverName [name_buf, +name_len bytes) end with the ASCII tail?
unsafe fn wname_ends_with(name_buf: u64, name_len: usize, tail: &[u8]) -> bool {
    if name_buf == 0 || name_len < tail.len() * 2 {
        return false;
    }
    for (k, &wc) in tail.iter().enumerate() {
        let off = name_buf + (name_len as u64 - (tail.len() - k) as u64 * 2);
        let c = read_unaligned(off as *const u16);
        let lc = if (b'A' as u16..=b'Z' as u16).contains(&c) {
            c + 32
        } else {
            c
        };
        if lc != wc as u16 {
            return false;
        }
    }
    true
}

const GDI_DRIVER_RECORD_CAP: usize = 8;
const GDI_DRIVER_LEAF_CAP: usize = 24;

#[derive(Clone, Copy)]
struct GdiDriverRecord {
    leaf: [u8; GDI_DRIVER_LEAF_CAP],
    leaf_len: u8,
    image: u64,
    entry: u64,
    expdir: u64,
    image_len: u32,
}

impl GdiDriverRecord {
    const EMPTY: Self = Self {
        leaf: [0; GDI_DRIVER_LEAF_CAP],
        leaf_len: 0,
        image: 0,
        entry: 0,
        expdir: 0,
        image_len: 0,
    };

    fn leaf_bytes(&self) -> &[u8] {
        &self.leaf[..self.leaf_len as usize]
    }
}

static mut GDI_DRIVER_RECORDS: [GdiDriverRecord; GDI_DRIVER_RECORD_CAP] =
    [GdiDriverRecord::EMPTY; GDI_DRIVER_RECORD_CAP];

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

fn register_gdi_driver_image(
    leaf: &[u8],
    image: u64,
    entry: u64,
    expdir: u64,
    image_len: u32,
) -> bool {
    if leaf.is_empty() || leaf.len() > GDI_DRIVER_LEAF_CAP || image == 0 || image_len == 0 {
        return false;
    }
    unsafe {
        let records = &mut *core::ptr::addr_of_mut!(GDI_DRIVER_RECORDS);
        let mut empty = None;
        for (idx, rec) in records.iter().enumerate() {
            if rec.leaf_len == 0 {
                empty.get_or_insert(idx);
                continue;
            }
            if ascii_eq_ignore_case(rec.leaf_bytes(), leaf) {
                records[idx] = registered_gdi_driver_record(leaf, image, entry, expdir, image_len);
                return true;
            }
        }
        let Some(idx) = empty else {
            return false;
        };
        records[idx] = registered_gdi_driver_record(leaf, image, entry, expdir, image_len);
        true
    }
}

fn registered_gdi_driver_record(
    leaf: &[u8],
    image: u64,
    entry: u64,
    expdir: u64,
    image_len: u32,
) -> GdiDriverRecord {
    let mut rec = GdiDriverRecord::EMPTY;
    rec.leaf_len = leaf.len() as u8;
    for (idx, &b) in leaf.iter().enumerate() {
        rec.leaf[idx] = b.to_ascii_lowercase();
    }
    rec.image = image;
    rec.entry = entry;
    rec.expdir = expdir;
    rec.image_len = image_len;
    rec
}

unsafe fn registered_gdi_driver_for_name(
    name_buf: u64,
    name_len: usize,
) -> Option<GdiDriverRecord> {
    let records = &*core::ptr::addr_of!(GDI_DRIVER_RECORDS);
    for rec in records.iter() {
        if rec.leaf_len == 0 {
            continue;
        }
        if wname_ends_with(name_buf, name_len, rec.leaf_bytes()) {
            return Some(*rec);
        }
    }
    None
}

fn registered_gdi_driver_for_leaf(leaf: &[u8]) -> Option<GdiDriverRecord> {
    let records = unsafe { &*core::ptr::addr_of!(GDI_DRIVER_RECORDS) };
    for rec in records.iter() {
        if rec.leaf_len != 0 && ascii_eq_ignore_case(rec.leaf_bytes(), leaf) {
            return Some(*rec);
        }
    }
    None
}

pub(crate) fn gdi_driver_registered(leaf: &[u8]) -> bool {
    registered_gdi_driver_for_leaf(leaf).is_some()
}

unsafe fn gdi_driver_leaf_from_wname(
    name_buf: u64,
    name_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    if name_len == 0 || name_len % 2 != 0 || name_buf == 0 {
        return None;
    }
    let chars = name_len / 2;
    let mut start = 0usize;
    for i in 0..chars {
        let unit = read_unaligned((name_buf + (i * 2) as u64) as *const u16);
        if unit == b'\\' as u16 || unit == b'/' as u16 {
            start = i + 1;
        }
    }
    let leaf_chars = chars.checked_sub(start)?;
    if leaf_chars == 0 || leaf_chars > out.len() {
        return None;
    }
    for i in 0..leaf_chars {
        let unit = read_unaligned((name_buf + ((start + i) * 2) as u64) as *const u16);
        if unit > 0x7f {
            return None;
        }
        out[i] = (unit as u8).to_ascii_lowercase();
    }
    Some(leaf_chars)
}

unsafe fn request_gdi_driver_load(leaf: &[u8]) -> i32 {
    if leaf.is_empty() || leaf.len() > SH_GDI_LOAD_LEAF_CAP {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_GDI_LOAD_LEAF_LEN) as *mut u64,
        leaf.len() as u64,
    );
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_GDI_LOAD_STATUS) as *mut i32,
        0x0000_0103, // STATUS_PENDING, overwritten by the executive before reply.
    );
    for i in 0..SH_GDI_LOAD_LEAF_CAP {
        let b = if i < leaf.len() {
            leaf[i].to_ascii_lowercase()
        } else {
            0
        };
        write_volatile(
            (WIN32K_SHARED_VADDR + SH_GDI_LOAD_LEAF + i as u64) as *mut u8,
            b,
        );
    }
    let (_label, _tag, _, _, _) = crate::driver_launch::call_on(W32_GDI_LOAD_LABEL << 12);
    read_volatile((WIN32K_SHARED_VADDR + SH_GDI_LOAD_STATUS) as *const i32)
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
        let mut requested_leaf = [0u8; GDI_DRIVER_LEAF_CAP];
        if let Some(leaf_len) = gdi_driver_leaf_from_wname(name_buf, name_len, &mut requested_leaf)
        {
            let leaf = &requested_leaf[..leaf_len];
            if !gdi_driver_registered(leaf) {
                let status = request_gdi_driver_load(leaf);
                if status != 0 {
                    return status;
                }
            }
        }
        let Some(driver) = registered_gdi_driver_for_name(name_buf, name_len) else {
            print_str(b"[win32k gdidrv] ZwSetSystemInformation(GdiDriver) unknown driver\n");
            return 0xC000_0135u32 as i32; // STATUS_DLL_NOT_FOUND
        };
        if driver.image == 0 {
            return 0xC000_0135u32 as i32;
        }
        write_unaligned((buf + 0x10) as *mut u64, driver.image); // ImageAddress
        write_unaligned((buf + 0x18) as *mut u64, driver.image); // SectionPointer (non-null placeholder)
        write_unaligned((buf + 0x20) as *mut u64, driver.entry); // EntryPoint (= DrvEnableDriver for display DLL)
        write_unaligned((buf + 0x28) as *mut u64, driver.expdir); // ExportSectionPointer
        write_unaligned((buf + 0x30) as *mut u32, driver.image_len); // ImageLength
        print_str(b"[win32k gdidrv] hosted ");
        print_str(driver.leaf_bytes());
        print_str(b" -> image=0x");
        print_hex((driver.image >> 32) as u32);
        print_hex(driver.image as u32);
        print_str(b"\n");
    }
    0
}

// --- video-device registry import + display miniport IOCTL intercept --------------------------
//
// win32k's EngpUpdateGraphicsDeviceList / InitDisplayDriver (ReactOS win32ss/gdi/eng/device.c +
// win32ss/user/ntuser/display.c) open registry keys through ntoskrnl imports. These trampolines now
// resolve those imports against real executive-owned state: the mounted SYSTEM hive for service and
// keyboard-layout keys, plus the runtime Video0 DeviceMap key published through Configuration
// Manager when the selected display route is registered. There is no key/value mirror: ZwOpenKey
// only mints an opaque handle to a live target, and ZwQueryValueKey reads the value from that target.
// Video0's projected IO object identities and framebuffer IOCTL state are owned by `video_device`;
// win32k only carries opaque registry handles to the registry authority.

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const WIN32K_REG_HANDLE_CAP: usize = 16;
const WIN32K_REG_PATH_CAP: usize = 192;
const WIN32K_REG_VALUE_NAME_CAP: usize = 48;
const WIN32K_REG_VALUE_DATA_CAP: usize = 512;
const WIN32K_REG_HANDLE_BASE: u64 = 0x5A5A_1000;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Win32kRegHandleTarget {
    Empty,
    VideoDeviceMap,
    SystemHive { key: u32 },
}

#[derive(Clone, Copy)]
struct Win32kRegHandle {
    handle: u64,
    target: Win32kRegHandleTarget,
}

impl Win32kRegHandle {
    const EMPTY: Self = Self {
        handle: 0,
        target: Win32kRegHandleTarget::Empty,
    };
}

static mut WIN32K_REG_HANDLES: [Win32kRegHandle; WIN32K_REG_HANDLE_CAP] =
    [Win32kRegHandle::EMPTY; WIN32K_REG_HANDLE_CAP];

pub(crate) struct DisplayRegistrySpec<'a> {
    pub(crate) service_name: &'a [u8],
    pub(crate) service_key_pattern: &'a [u8],
    pub(crate) service_registry_path: &'a [u8],
    pub(crate) installed_display_driver: &'a [u8],
    pub(crate) display_driver_leaf: &'a [u8],
    pub(crate) device_description: &'a [u8],
    pub(crate) vga_compatible: u32,
    pub(crate) framebuffer_size: u64,
    pub(crate) mode: DisplayModeSpec,
}

#[derive(Clone, Copy)]
pub(crate) struct DisplayModeSpec {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride: u32,
    pub(crate) bits_per_plane: u32,
}

fn reg_ascii_eq(a: &[u8], b: &[u8]) -> bool {
    ascii_eq_ignore_case(a, b)
}

fn register_win32k_reg_handle(target: Win32kRegHandleTarget) -> Option<u64> {
    if matches!(target, Win32kRegHandleTarget::Empty) {
        return None;
    }
    unsafe {
        let handles = &mut *core::ptr::addr_of_mut!(WIN32K_REG_HANDLES);
        for (idx, entry) in handles.iter().enumerate() {
            if matches!(entry.target, Win32kRegHandleTarget::Empty) {
                let handle = WIN32K_REG_HANDLE_BASE + idx as u64;
                handles[idx] = Win32kRegHandle { handle, target };
                return Some(handle);
            }
        }
        None
    }
}

fn lookup_win32k_reg_handle(handle: u64) -> Option<Win32kRegHandleTarget> {
    unsafe {
        (&*core::ptr::addr_of!(WIN32K_REG_HANDLES))
            .iter()
            .find(|entry| {
                entry.handle == handle && !matches!(entry.target, Win32kRegHandleTarget::Empty)
            })
            .map(|entry| entry.target)
    }
}

fn close_win32k_reg_handle(handle: u64) -> bool {
    unsafe {
        let handles = &mut *core::ptr::addr_of_mut!(WIN32K_REG_HANDLES);
        if let Some(entry) = handles.iter_mut().find(|entry| {
            entry.handle == handle && !matches!(entry.target, Win32kRegHandleTarget::Empty)
        }) {
            *entry = Win32kRegHandle::EMPTY;
            true
        } else {
            false
        }
    }
}

fn register_display_device_route(spec: &DisplayRegistrySpec<'_>) -> bool {
    let _ = spec.vga_compatible;
    if spec.service_name.is_empty()
        || spec.service_key_pattern.is_empty()
        || spec.service_registry_path.is_empty()
        || spec.installed_display_driver.is_empty()
        || spec.display_driver_leaf.is_empty()
        || spec.device_description.is_empty()
        || spec.framebuffer_size == 0
        || spec.mode.width == 0
        || spec.mode.height == 0
        || spec.mode.stride == 0
        || spec.mode.bits_per_plane == 0
    {
        return false;
    }
    unsafe {
        crate::video_device::publish_boot_framebuffer_video_device(
            &crate::video_device::VideoDeviceRegistration {
                driver_name: spec.service_name,
                service_registry_path: spec.service_registry_path,
                framebuffer_va: WIN32K_FB_VA,
                framebuffer_size: spec.framebuffer_size,
                mode: crate::video_device::VideoModeSpec {
                    width: spec.mode.width,
                    height: spec.mode.height,
                    stride: spec.mode.stride,
                    bits_per_plane: spec.mode.bits_per_plane,
                },
                allocate_projection: pool_alloc,
            },
        )
    }
}

pub(crate) fn publish_display_device_route(spec: &DisplayRegistrySpec<'_>) -> bool {
    register_display_device_route(spec)
}

fn strip_ascii_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() >= prefix.len() && reg_ascii_eq(&bytes[..prefix.len()], prefix) {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
}

fn registry_path_tail(mut path: &[u8]) -> &[u8] {
    while path.first() == Some(&b'\\') {
        path = &path[1..];
    }
    strip_ascii_prefix(path, b"registry\\machine\\").unwrap_or(path)
}

fn is_video_device_map_key(path: &[u8]) -> bool {
    reg_ascii_eq(registry_path_tail(path), b"hardware\\devicemap\\video")
}

fn system_hive_relative_path(path: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut tail = registry_path_tail(path);
    tail = strip_ascii_prefix(tail, b"system\\")?;
    if reg_ascii_eq(tail, b"currentcontrolset") {
        let alias = b"controlset001";
        if alias.len() > out.len() {
            return None;
        }
        out[..alias.len()].copy_from_slice(alias);
        Some(alias.len())
    } else if let Some(rest) = strip_ascii_prefix(tail, b"currentcontrolset\\") {
        let alias = b"controlset001";
        if alias.len() + 1 + rest.len() > out.len() {
            return None;
        }
        out[..alias.len()].copy_from_slice(alias);
        out[alias.len()] = b'\\';
        out[alias.len() + 1..alias.len() + 1 + rest.len()].copy_from_slice(rest);
        Some(alias.len() + 1 + rest.len())
    } else {
        if tail.len() > out.len() {
            return None;
        }
        out[..tail.len()].copy_from_slice(tail);
        Some(tail.len())
    }
}

fn system_hive_key_from_path(path: &[u8]) -> Option<u32> {
    let hive = system_hive_regf()?;
    let mut rel = [0u8; WIN32K_REG_PATH_CAP];
    let rel_len = system_hive_relative_path(path, &mut rel)?;
    let rel_str = unsafe { core::str::from_utf8_unchecked(&rel[..rel_len]) };
    hive.open_key(rel_str)
}

fn system_hive_key_from_root_path(root: u32, path: &[u8]) -> Option<u32> {
    let hive = system_hive_regf()?;
    if path.is_empty() {
        return Some(root);
    }
    let rel_str = unsafe { core::str::from_utf8_unchecked(path) };
    hive.open_key_from(root, rel_str)
}

fn win32k_reg_path_is_absolute(path: &[u8]) -> bool {
    path.first() == Some(&b'\\')
        || strip_ascii_prefix(path, b"registry\\machine\\").is_some()
        || strip_ascii_prefix(path, b"system\\").is_some()
        || strip_ascii_prefix(path, b"hardware\\").is_some()
}

unsafe fn read_unicode_string_ascii_lower(ustr: u64, out: &mut [u8]) -> Option<usize> {
    if ustr == 0 {
        return None;
    }
    let len = read_unaligned(ustr as *const u16) as usize;
    if len % 2 != 0 {
        return None;
    }
    let chars = len / 2;
    if chars > out.len() {
        return None;
    }
    let buf = read_unaligned((ustr + 8) as *const u64);
    if chars != 0 && buf == 0 {
        return None;
    }
    for i in 0..chars {
        let unit = read_unaligned((buf + (i * 2) as u64) as *const u16);
        if unit > 0x7f {
            return None;
        }
        out[i] = (unit as u8).to_ascii_lowercase();
    }
    Some(chars)
}

unsafe fn object_attributes_name_ascii_lower(obj_attr: u64, out: &mut [u8]) -> Option<usize> {
    if obj_attr == 0 {
        return None;
    }
    let ustr = read_unaligned((obj_attr + 0x10) as *const u64);
    read_unicode_string_ascii_lower(ustr, out)
}

/// `NTSTATUS ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK, POBJECT_ATTRIBUTES)`. OBJECT_ATTRIBUTES x64:
/// ObjectName (PUNICODE_STRING) at +0x10. Resolve win32k's registry imports to live registry/device
/// targets; optional keys not present in the mounted hives fail with NOT_FOUND.
extern "win64" fn s_zw_open_key(handle_out: *mut u64, _access: u64, obj_attr: u64) -> i32 {
    if handle_out.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    if obj_attr == 0 {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    unsafe {
        let mut path = [0u8; WIN32K_REG_PATH_CAP];
        let Some(path_len) = object_attributes_name_ascii_lower(obj_attr, &mut path) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let path = &path[..path_len];
        let root_dir = read_unaligned((obj_attr + 0x8) as *const u64);
        let root_target = if root_dir == 0 {
            None
        } else {
            lookup_win32k_reg_handle(root_dir)
        };
        let target = if !win32k_reg_path_is_absolute(path) {
            match root_target {
                Some(Win32kRegHandleTarget::SystemHive { key }) => {
                    if let Some(key) = system_hive_key_from_root_path(key, path) {
                        Win32kRegHandleTarget::SystemHive { key }
                    } else {
                        return STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                }
                _ => {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }
        } else if is_video_device_map_key(path) {
            if !crate::video_device::video_device_map_published() {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            Win32kRegHandleTarget::VideoDeviceMap
        } else if let Some(key) = system_hive_key_from_path(path) {
            Win32kRegHandleTarget::SystemHive { key }
        } else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let Some(hkey) = register_win32k_reg_handle(target) else {
            return STATUS_NO_MEMORY;
        };
        write_unaligned(handle_out, hkey);
    }
    0
}

unsafe fn emit_kvpi_bytes(
    kvi: u64,
    length: u64,
    result_len: *mut u32,
    value_type: u32,
    data: &[u8],
) -> i32 {
    let need = 0xC + data.len() as u64;
    if !result_len.is_null() {
        write_unaligned(result_len, need as u32);
    }
    if kvi == 0 || length < need {
        return STATUS_BUFFER_OVERFLOW;
    }
    write_unaligned(kvi as *mut u32, 0);
    write_unaligned((kvi + 4) as *mut u32, value_type);
    write_unaligned((kvi + 8) as *mut u32, data.len() as u32);
    let dst = kvi + 0xC;
    for (idx, &byte) in data.iter().enumerate() {
        write_unaligned((dst + idx as u64) as *mut u8, byte);
    }
    0
}

unsafe fn query_system_hive_value(
    key: u32,
    name: &[u8],
    kvi: u64,
    length: u64,
    result_len: *mut u32,
) -> i32 {
    let Some(hive) = system_hive_regf() else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    let name = core::str::from_utf8_unchecked(name);
    let Some((value_type, data)) = hive.value(key, name) else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    emit_kvpi_bytes(kvi, length, result_len, value_type, &data)
}

unsafe fn query_video_device_map_value(
    name: &[u8],
    kvi: u64,
    length: u64,
    result_len: *mut u32,
) -> i32 {
    let mut data = [0u8; WIN32K_REG_VALUE_DATA_CAP];
    match crate::video_device::query_video_device_map_value(name, &mut data) {
        Ok((value_type, data_len)) => {
            emit_kvpi_bytes(kvi, length, result_len, value_type, &data[..data_len])
        }
        Err(status) => status,
    }
}

/// `NTSTATUS ZwQueryValueKey(HANDLE, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS, PVOID
/// KeyValueInformation, ULONG Length, PULONG ResultLength)`.
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
        let Some(target) = lookup_win32k_reg_handle(hkey) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let mut name = [0u8; WIN32K_REG_VALUE_NAME_CAP];
        let Some(name_len) = read_unicode_string_ascii_lower(value_name, &mut name) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let name = &name[..name_len];
        match target {
            Win32kRegHandleTarget::Empty => STATUS_OBJECT_NAME_NOT_FOUND,
            Win32kRegHandleTarget::VideoDeviceMap => {
                query_video_device_map_value(name, kvi, length, result_len)
            }
            Win32kRegHandleTarget::SystemHive { key } => {
                query_system_hive_value(key, name, kvi, length, result_len)
            }
        }
    }
}

/// `NTSTATUS IoGetDeviceObjectPointer(PUNICODE_STRING, ACCESS_MASK, PFILE_OBJECT*, PDEVICE_OBJECT*)`.
extern "win64" fn s_io_get_device_object_pointer(
    name: u64,
    _access: u64,
    fileobj_out: *mut u64,
    devobj_out: *mut u64,
) -> i32 {
    unsafe { crate::video_device::video_get_device_object_pointer(name, fileobj_out, devobj_out) }
}

/// win32k's `EngDeviceIoControl` — INTERCEPTED (win32k's export is patched to jmp here in
/// `load_into`, so both the display DLL's imported calls and win32k's own internal calls route into
/// the executive-owned video-device boundary). Returns 0 (ERROR_SUCCESS) on handled, nonzero on
/// unhandled. win64: rcx=hDev, rdx=ioctl, r8=inbuf, r9=inlen, stack: outbuf, outlen, bytesret.
extern "win64" fn s_eng_device_io_control(
    hdev: u64,
    ioctl: u64,
    in_buf: u64,
    in_len: u64,
    out_buf: u64,
    out_len: u64,
    bytes_ret: *mut u32,
) -> u32 {
    unsafe {
        crate::video_device::video_device_io_control(
            hdev, ioctl, in_buf, in_len, out_buf, out_len, bytes_ret,
        )
    }
}

/// Patch win32k's exported `EngDeviceIoControl` to `jmp s_eng_device_io_control`. Runs in `load_into`
/// while win32k's image is mapped RW in the executive (before spawn maps it RX). 12 bytes:
/// `mov rax, imm64 (48 B8 ..); jmp rax (FF E0)`. Both the display DLL's IAT-resolved import AND win32k's own
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
// Phase 2A: because this is a directly-bound component import (not an executive syscall), the stub
// copies the bounded input into the pointer-free shared ABI and Sends W32_USER_CALLBACK_LABEL. It
// then receives either W32_USER_CALLBACK_RESUME_LABEL or a nested W32_DISPATCH_LABEL. This explicit
// receive loop is the Phase-3 re-entrancy seam: the sole component TCB remains able to run a nested
// USER/GDI dispatch while the outer window-proc callback executes. No direct component pointer
// crosses the ABI.
#[cfg(any())]
const USER32_CB_LOADDEFAULTCURSORS: u32 = 3;
// USER32_CALLBACK_WINDOWPROC (u32cb.h:9) — the CLIENT window-proc dispatch (WM_NCCREATE / WM_CREATE /
// WM_NCCALCSIZE etc.). co_IntCallWindowProc (callback.c:351,373) RtlMoveMemory's the OUTPUT buffer back
// over the input Arguments then reads the window-proc LRESULT from `Arguments->Result`. Zeroing the
// output (the init-callback path) yields Result=0 → WM_NCCREATE returns FALSE → co_UserCreateWindowEx
// "NCCREATE message failed" → NULL HWND. So for the WINDOWPROC api we PRESERVE the input Arguments
// (copy input→output, incl. the trailing lParam/CREATESTRUCT buffer) and write the correct DefWindowProc
// LRESULT at Result (offset 0x38). See WINDOWPROC_CALLBACK_ARGUMENTS (callback.h:21): x64 layout is
// Proc@0 IsAnsiProc@8 Wnd@0x10 Msg@0x18 wParam@0x20 lParam@0x28 lParamBufferSize@0x30 Result@0x38.
const USER32_CB_WINDOWPROC: u32 = 0;
#[cfg(any())]
const WPCA_MSG: u64 = 0x18; // UINT Msg
const WPCA_RESULT: u64 = 0x38; // LRESULT Result
                               // WINDOWPROC_CALLBACK_ARGUMENTS x64 layout invariant (callback.h:21): Proc@0 IsAnsiProc@8 Wnd@0x10
                               // Msg@0x18 wParam@0x20 lParam@0x28 lParamBufferSize@0x30 Result@0x38. Result is the 8th 8-byte slot.
const _: () = assert!(WPCA_RESULT == 7 * 8);
extern "win64" fn s_ke_user_mode_callback_rendezvous(
    api: u32,
    input: u64,
    input_len: u32,
    out_buf: *mut u64,
    out_len: *mut u32,
) -> i32 {
    unsafe {
        let Some(contract) = nt_user_callback::UserCallbackContract::for_api(api) else {
            return 0xC000_00BBu32 as i32;
        };
        let Some(minimum_result_capacity) = contract.minimum_result_capacity(input_len) else {
            return 0xC000_0004u32 as i32;
        };
        let mut output_capacity = input_len.max(minimum_result_capacity).max(8) as usize;
        output_capacity = match output_capacity.checked_add(15) {
            Some(value) => value & !15,
            None => return 0xC000_000Du32 as i32,
        };
        if input_len != 0 && input == 0 {
            return 0xC000_000Du32 as i32;
        }
        if input_len as usize > nt_user_callback::CALLBACK_PAYLOAD_MAX
            || output_capacity > nt_user_callback::CALLBACK_PAYLOAD_MAX
        {
            return 0xC000_0023u32 as i32;
        }

        let frame =
            (WIN32K_SHARED_VADDR + SH_USER_CALLBACK) as *mut nt_user_callback::CallbackFrame;
        let mut header = read_volatile(core::ptr::addr_of!((*frame).header));
        if header
            .begin_request(api, input_len as usize, output_capacity)
            .is_err()
        {
            return 0xC000_000Du32 as i32;
        }
        for offset in 0..input_len as usize {
            write_volatile(
                core::ptr::addr_of_mut!((*frame).payload[offset]),
                read_volatile((input + offset as u64) as *const u8),
            );
        }
        if api == USER32_CB_WINDOWPROC && input_len as usize >= 0x40 {
            let lparam_size = read_volatile((input + 0x30) as *const i32);
            if lparam_size >= 0
                && 0x40usize
                    .checked_add(lparam_size as usize)
                    .is_some_and(|end| end <= input_len as usize)
            {
                header.payload_reference_offset = 0x40;
                for offset in 0x28..0x30 {
                    write_volatile(core::ptr::addr_of_mut!((*frame).payload[offset]), 0);
                }
            }
        }
        for offset in input_len as usize..output_capacity {
            write_volatile(core::ptr::addr_of_mut!((*frame).payload[offset]), 0);
        }
        write_volatile(core::ptr::addr_of_mut!((*frame).header), header);
        let request = header;
        let Some(callback_request_context) = callback_request_context_for_request(&request) else {
            return 0xC000_000Du32 as i32;
        };

        // ★ THE NESTING SEAM, on the `Call` transport (`docs/transport-migration.md` §3.4).
        //
        // The FIRST Call raises the callback as an EVENT: it is not the completion of a request, and
        // the executive answers it in place (RESUME) or SUSPENDS this dispatch by simply not
        // replying — which leaves the executive's reply object bound to THIS Call for the whole
        // callback excursion. That kernel binding is the entirety of the "suspended outer dispatch"
        // state; there is no token, no stack, and no depth bookkeeping on either side.
        //
        // While this outer dispatch is parked here, the client's redirected `WndProc` can issue
        // further `NtUser*`/`NtGdi*` syscalls, each arriving as a NESTED dispatch — replied onto the
        // SAME reply object, because this component has one TCB and is blocked in exactly one Call.
        // Each nested completion and the next receive are the SAME syscall, so no level can publish
        // a completion the executive has not asked for: the phase slip is UNREPRESENTABLE, at any
        // depth. Nesting is bounded only by this component's own C stack.
        let mut out = W32_USER_CALLBACK_LABEL << 12;
        loop {
            // The reply's message label is always 0 (`spawn_hosts::REQUEST_TAG_LEN`); the request
            // TAG rides in MR0.
            let (_label, tag, _, _, _) = crate::driver_launch::call_on(out);
            match tag {
                W32_USER_CALLBACK_RESUME_LABEL => {
                    if !restore_current_context_for_user_callback_resume_inner(
                        callback_request_context.pi,
                        callback_request_context.pid,
                        callback_request_context.tid,
                        callback_request_context.client_teb,
                        callback_request_context.supplied_eprocess,
                        callback_request_context.supplied_ethread,
                        callback_request_context.process_role,
                        true,
                        true,
                    ) {
                        return 0xC000_000Du32 as i32;
                    }
                    break;
                }
                W32_DISPATCH_LABEL => {
                    let (status, info) = win32k_dispatch(&crate::spawn_hosts::DispatchReq {
                        sel: read_volatile((WIN32K_SHARED_VADDR + SH_REQ_SSN) as *const u64),
                        drv: 0,
                    });
                    if !restore_user_callback_request_context(callback_request_context) {
                        return 0xC000_000Du32 as i32;
                    }
                    write_volatile((WIN32K_SHARED_VADDR + SH_REQ_STATUS) as *mut u64, info);
                    write_volatile((WIN32K_SHARED_VADDR + SH_REQ_STATUS) as *mut i32, status);
                    // The nested completion IS the next receive.
                    out = W32_DISPATCH_LABEL << 12;
                }
                _ => return 0xC000_0001u32 as i32,
            }
        }
        let reply = read_volatile(core::ptr::addr_of!((*frame).header));
        if nt_user_callback::validate_reply(&request, &reply).is_err() {
            return 0xC000_0001u32 as i32;
        }
        if !restore_user_callback_request_context(callback_request_context) {
            return 0xC000_000Du32 as i32;
        }

        let buf = core::ptr::addr_of!((*frame).payload) as u64;
        if !out_buf.is_null() {
            write_volatile(out_buf, buf);
        }
        if !out_len.is_null() {
            write_volatile(out_len, reply.output_length);
        }
        reply.status
    }
}

// Historical pre-Phase-2A shortcut retained outside every build only as nearby bring-up context.
#[cfg(any())]
extern "win64" fn removed_s_ke_user_mode_callback_synthetic_baseline(
    api: u32,
    _input: u64,
    input_len: u32,
    out_buf: *mut u64,
    out_len: *mut u32,
) -> i32 {
    unsafe {
        let want = if out_len.is_null() {
            0
        } else {
            read_volatile(out_len)
        };
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
        if api == USER32_CB_WINDOWPROC && _input != 0 && input_len as u64 >= WPCA_RESULT + 8 {
            // WINDOWPROC dispatch: PRESERVE the input Arguments (Proc/Wnd/Msg/lParam + trailing
            // CREATESTRUCT so co_IntCallWindowProc's RtlMoveMemory write-back to lParam is valid) and
            // stamp the correct DefWindowProc LRESULT. Copy the whole input over the zeroed output.
            let n = (input_len as u64).min(size);
            let mut j = 0u64;
            while j + 8 <= n {
                write_volatile(
                    (buf + j) as *mut u64,
                    read_volatile((_input + j) as *const u64),
                );
                j += 8;
            }
            while j < n {
                write_volatile(
                    (buf + j) as *mut u8,
                    read_volatile((_input + j) as *const u8),
                );
                j += 1;
            }
            // DefWindowProc LRESULT: TRUE(1) for the window-create messages (WM_NCCREATE=0x81 /
            // WM_CREATE=0x01 return TRUE to CONTINUE creation); WM_NCCALCSIZE=0x83 returns 0. Default to
            // TRUE so an unmodelled create-message doesn't abort the window. This is the invisible 0x0
            // WS_POPUP SAS window's create path — DefWindowProc's real result.
            let msg = read_volatile((_input + WPCA_MSG) as *const u32);
            // ★ DESKTOP-HEAP CLIENT-WINDOW MAPPING — WM_CREATE persists the Session into WND.dwUserData.
            // In real Windows the window-creation WM_CREATE runs the CLIENT's real window proc (e.g.
            // winlogon's SASWindowProc), whose WM_CREATE does `SetWindowLongPtr(hwnd, GWLP_USERDATA,
            // ((CREATESTRUCT*)lParam)->lpCreateParams)` (sas.c:1572-1575) — the Session pointer. Our host
            // SYNTHESIZES this callback (it doesn't RIP-redirect into the client proc), so that store
            // never happens → later, when the SAS window's real SASWindowProc runs CLIENT-SIDE for
            // WLX_WM_SAS, `GetWindowLongPtr(GWLP_USERDATA)` (= client-side ValidateHwnd(hwnd)->dwUserData)
            // returns 0 → DispatchSAS(NULL) → null-deref. Reproduce the authentic WM_CREATE effect here:
            // WINDOWPROC_CALLBACK_ARGUMENTS { … Wnd@0x10, wParam@0x20, lParam@0x28 }; for WM_CREATE
            // lParam → CREATESTRUCT, whose lpCreateParams@0x00 = the Session. Store it into the kernel
            // PWND's dwUserData (WND+0x110, x64: after head(0x28)+state..fnid(0x20)+5*spwnd(0x28)+
            // rcWindow/rcClient(0x20)+lpfnWndProc/pcls/hrgnUpdate(0x18)+PropListHead/Items(0x18)+
            // pSBInfo/SystemMenu/IDMenu/hrgnClip/hrgnNewFrame(0x28)+strName(0x10)+cbwndExtra(0x8)+
            // spwndLastActive/hImc(0x10) = 0x110). win32k owns the heap RW, so the write takes; winlogon
            // sees it in its RO client mapping → GetWindowLongPtr returns the real Session.
            const WPCA_WND: u64 = 0x10; // HWND (a handle value, NOT a PWND)
            const WPCA_LPARAM: u64 = 0x28;
            const WND_DWUSERDATA_OFF: u64 = 0x110;
            if msg == 0x0001 {
                let hwnd = read_volatile((_input + WPCA_WND) as *const u64);
                let lparam = read_volatile((_input + WPCA_LPARAM) as *const u64);
                // Resolve HWND → PWND via the USER handle table (gSharedInfo.aheList, published by the
                // executive from the USERCONNECT). handles@0x00, nb_handles@0x10; USER_HANDLE_ENTRY:
                // ptr@0x00, sizeof 0x18 (ptr,pti,type,flags,generation). index = (hwnd&0xffff−0x20)>>1.
                let ahelist = read_volatile((WIN32K_SHARED_VADDR + SH_SAS_AHELIST) as *const u64);
                let mut pwnd = 0u64;
                if ahelist != 0 && (hwnd & 0xffff) >= 0x20 {
                    let handles = read_volatile(ahelist as *const u64);
                    let nb = read_volatile((ahelist + 0x10) as *const u32) as u64;
                    let index = ((hwnd & 0xffff) - 0x20) >> 1;
                    if handles != 0 && index < nb {
                        let entry = handles + index * 0x18;
                        // Only accept a live TYPE_WINDOW(1) entry (USER_HANDLE_ENTRY.type @ +0x10) —
                        // a freed/wrong-type slot (type==0/other) must NOT be dereferenced+written (ReactOS
                        // handle_to_entry returns NULL for type==0). Guards against type-confusion if this
                        // path is ever reused for an arbitrary HWND.
                        if read_volatile((entry + 0x10) as *const u8) == 1 {
                            pwnd = read_volatile(entry as *const u64);
                        }
                    }
                }
                if pwnd != 0 && lparam != 0 {
                    // CREATESTRUCT.lpCreateParams @ +0x00 = the Session pointer.
                    let create_params = read_volatile(lparam as *const u64);
                    if create_params != 0 {
                        write_volatile((pwnd + WND_DWUSERDATA_OFF) as *mut u64, create_params);
                        // Publish the Session VA so the executive can read LogonState (proof of the
                        // client-side SASWindowProc→DispatchSAS run).
                        write_volatile(
                            (WIN32K_SHARED_VADDR + SH_SAS_SESSION) as *mut u64,
                            create_params,
                        );
                        // Publish the SAS window HWND so the executive can INJECT the 2nd SAS to it via
                        // the real NtUserPostMessage path (the keyboard Ctrl-Alt-Del a headless host lacks).
                        write_volatile((WIN32K_SHARED_VADDR + SH_SAS_HWND) as *mut u64, hwnd);
                        print_str(b"[win32k-host] WM_CREATE stored Session 0x");
                        print_hex((create_params >> 32) as u32);
                        print_hex(create_params as u32);
                        print_str(b" into WND+0x110 (dwUserData) hwnd=0x");
                        print_hex(hwnd as u32);
                        print_str(b" pwnd=0x");
                        print_hex(pwnd as u32);
                        print_str(b"\n");
                    }
                }
            }
            let result: u64 = match msg {
                0x0083 => 0, // WM_NCCALCSIZE -> 0
                _ => 1,      // WM_NCCREATE / WM_CREATE / etc. -> TRUE (continue creation)
            };
            write_volatile((buf + WPCA_RESULT) as *mut u64, result);
            print_str(b"[win32k-host] WINDOWPROC cb msg=0x");
            print_hex(msg);
            print_str(b" -> Result=");
            print_u64(result);
            print_str(b"\n");
        }
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
    reg.bind(
        "ExAllocatePoolWithTag",
        s_ex_alloc_pool_with_tag as usize as u64,
    );
    reg.bind("ExAllocatePool", s_ex_alloc_pool as usize as u64);
    reg.bind(
        "ExAllocatePoolWithQuotaTag",
        s_ex_alloc_pool_quota as usize as u64,
    );
    reg.bind("ExFreePoolWithTag", s_ex_free_pool_with_tag as usize as u64);
    reg.bind("ExFreePool", s_ex_free_pool_with_tag as usize as u64);
    // RTL atom table (nt_kernel_exec::rtl_atom)
    reg.bind(
        "RtlCreateAtomTable",
        s_rtl_create_atom_table as usize as u64,
    );
    reg.bind(
        "RtlAddAtomToAtomTable",
        s_rtl_add_atom_to_atom_table as usize as u64,
    );
    reg.bind(
        "RtlLookupAtomInAtomTable",
        s_rtl_lookup_atom_in_atom_table as usize as u64,
    );
    reg.bind(
        "RtlDeleteAtomFromAtomTable",
        s_rtl_delete_atom_from_atom_table as usize as u64,
    );
    reg.bind(
        "RtlPinAtomInAtomTable",
        s_rtl_pin_atom_in_atom_table as usize as u64,
    );
    reg.bind(
        "RtlQueryAtomInAtomTable",
        s_rtl_query_atom_in_atom_table as usize as u64,
    );
    reg.bind(
        "RtlDestroyAtomTable",
        s_rtl_destroy_atom_table as usize as u64,
    );
    // Ob object layer (nt-object-manager)
    reg.bind(
        "ObReferenceObjectByHandle",
        s_ob_reference_object_by_handle as usize as u64,
    );
    reg.bind(
        "ObOpenObjectByName",
        s_ob_open_object_by_name as usize as u64,
    );
    reg.bind(
        "ObOpenObjectByPointer",
        s_ob_open_object_by_pointer as usize as u64,
    );
    reg.bind(
        "ObFindHandleForObject",
        s_ob_find_handle_for_object as usize as u64,
    );
    reg.bind("ObCreateObject", s_ob_create_object as usize as u64);
    reg.bind("ObInsertObject", s_ob_insert_object as usize as u64);
    reg.bind("ObCloseHandle", s_ob_close_handle as usize as u64);
    reg.bind("ObReferenceObject", s_ob_reference_object as usize as u64);
    reg.bind("ObDereferenceObject", s_void as usize as u64);
    reg.bind("ZwDuplicateObject", s_zw_duplicate_object as usize as u64);
    reg.bind("NtDuplicateObject", s_zw_duplicate_object as usize as u64);
    reg.bind("ZwClose", s_zw_close as usize as u64);
    reg.bind("NtClose", s_zw_close as usize as u64);
    reg.bind("ZwCreateEvent", s_zw_create_event as usize as u64);
    reg.bind("NtCreateEvent", s_zw_create_event as usize as u64);
    reg.bind("KeInitializeEvent", s_ke_initialize_event as usize as u64);
    reg.bind("KeSetEvent", s_ke_set_event as usize as u64);
    reg.bind("KeResetEvent", s_ke_reset_event as usize as u64);
    reg.bind("KeClearEvent", s_ke_clear_event as usize as u64);
    reg.bind("KePulseEvent", s_ke_pulse_event as usize as u64);
    reg.bind("KeReadStateEvent", s_ke_read_state_event as usize as u64);
    reg.bind(
        "KeWaitForSingleObject",
        s_ke_wait_for_single_object as usize as u64,
    );
    reg.bind("KeEnterCriticalRegion", s_void as usize as u64);
    reg.bind("KeLeaveCriticalRegion", s_void as usize as u64);
    reg.bind("KeEnterGuardedRegion", s_void as usize as u64);
    reg.bind("KeLeaveGuardedRegion", s_void as usize as u64);
    reg.bind("EngGetTickCount", s_eng_get_tick_count as usize as u64);
    reg.bind("EngGetTickCount32", s_eng_get_tick_count as usize as u64);
    reg.bind("RtlGetExpWinVer", s_rtl_get_exp_winver as usize as u64);
    // --- batch 2: RTL heap (win32k session heap) ---
    reg.bind("RtlCreateHeap", s_rtl_create_heap as usize as u64);
    reg.bind("RtlAllocateHeap", s_rtl_allocate_heap as usize as u64);
    reg.bind("RtlFreeHeap", s_rtl_free_heap as usize as u64);
    reg.bind("RtlSizeHeap", s_rtl_size_heap as usize as u64);
    reg.bind("RtlReAllocateHeap", s_rtl_reallocate_heap as usize as u64);
    // --- batch 2: RTL_BITMAP (GDI pool slot allocator) ---
    reg.bind(
        "RtlInitializeBitMap",
        s_rtl_initialize_bitmap as usize as u64,
    );
    reg.bind("RtlClearAllBits", s_rtl_clear_all_bits as usize as u64);
    reg.bind("RtlSetAllBits", s_rtl_set_all_bits as usize as u64);
    reg.bind(
        "RtlFindClearBitsAndSet",
        s_rtl_find_clear_bits_and_set as usize as u64,
    );
    reg.bind(
        "RtlNumberOfSetBits",
        s_rtl_number_of_set_bits as usize as u64,
    );
    reg.bind("RtlTestBit", s_rtl_test_bit as usize as u64);
    reg.bind("RtlSetBit", s_rtl_set_bit as usize as u64);
    reg.bind("RtlClearBit", s_rtl_clear_bit as usize as u64);
    reg.bind("RtlSetBits", s_rtl_set_bits as usize as u64);
    reg.bind("RtlClearBits", s_rtl_clear_bits as usize as u64);
    reg.bind("RtlAreBitsClear", s_rtl_are_bits_clear as usize as u64);
    // --- batch 2: RTL string init ---
    reg.bind(
        "RtlInitUnicodeString",
        s_rtl_init_unicode_string as usize as u64,
    );
    reg.bind("RtlInitAnsiString", s_rtl_init_ansi_string as usize as u64);
    reg.bind(
        "RtlInitEmptyUnicodeString",
        s_rtl_init_empty_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlCopyUnicodeString",
        s_rtl_copy_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlCompareUnicodeString",
        s_rtl_compare_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlEqualUnicodeString",
        s_rtl_equal_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlAppendUnicodeToString",
        s_rtl_append_unicode_to_string as usize as u64,
    );
    reg.bind(
        "RtlCreateUnicodeString",
        s_rtl_create_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlMultiByteToUnicodeN",
        s_rtl_multibyte_to_unicode_n as usize as u64,
    );
    reg.bind("wcslen", s_wcslen as usize as u64);
    reg.bind("_wcsnicmp", s_wcsnicmp as usize as u64);
    reg.bind("wcsnicmp", s_wcsnicmp as usize as u64);
    // --- batch 2: real va_list DbgPrintEx backend (nt_kernel_exec::dbg) ---
    reg.bind(
        "vDbgPrintExWithPrefix",
        s_vdbg_print_ex_with_prefix as usize as u64,
    );
    // --- batch 3: section objects (nt-kernel-exec session_section) ---
    reg.bind("MmCreateSection", s_mm_create_section as usize as u64);
    reg.bind("MmMapViewInSessionSpace", s_mm_map_view as usize as u64);
    reg.bind("MmMapViewInSystemSpace", s_mm_map_view as usize as u64);
    reg.bind(
        "MmMapViewOfSection",
        s_mm_map_view_of_section as usize as u64,
    );
    // --- batch 3: lookaside-list init (nt_kernel_exec::init_general_lookaside) ---
    reg.bind(
        "ExInitializePagedLookasideList",
        s_ex_init_paged_lookaside as usize as u64,
    );
    reg.bind(
        "ExInitializeNPagedLookasideList",
        s_ex_init_npaged_lookaside as usize as u64,
    );
    // --- batch 3: Zw virtual-memory / registry / file (canned; see backlog) ---
    reg.bind(
        "ZwAllocateVirtualMemory",
        s_zw_allocate_virtual_memory as usize as u64,
    );
    reg.bind(
        "NtAllocateVirtualMemory",
        s_zw_allocate_virtual_memory as usize as u64,
    );
    reg.bind(
        "ZwFreeVirtualMemory",
        s_zw_free_virtual_memory as usize as u64,
    );
    reg.bind(
        "NtFreeVirtualMemory",
        s_zw_free_virtual_memory as usize as u64,
    );
    reg.bind(
        "ZwSetSystemInformation",
        s_zw_set_system_information as usize as u64,
    );
    reg.bind(
        "NtSetSystemInformation",
        s_zw_set_system_information as usize as u64,
    );
    reg.bind("ZwOpenFile", s_zw_open_file_fail as usize as u64);
    reg.bind("NtOpenFile", s_zw_open_file_fail as usize as u64);
    reg.bind("ZwOpenKey", s_zw_open_key as usize as u64);
    reg.bind("NtOpenKey", s_zw_open_key as usize as u64);
    reg.bind("ZwQueryValueKey", s_zw_query_value_key as usize as u64);
    reg.bind("NtQueryValueKey", s_zw_query_value_key as usize as u64);
    reg.bind("ZwOpenThreadToken", s_zw_open_thread_token as usize as u64);
    reg.bind("NtOpenThreadToken", s_zw_open_thread_token as usize as u64);
    reg.bind(
        "ZwOpenProcessToken",
        s_zw_open_process_token as usize as u64,
    );
    reg.bind(
        "NtOpenProcessToken",
        s_zw_open_process_token as usize as u64,
    );
    reg.bind(
        "ZwQueryInformationToken",
        s_zw_query_information_token as usize as u64,
    );
    reg.bind(
        "NtQueryInformationToken",
        s_zw_query_information_token as usize as u64,
    );
    // --- batch 3: CRT mem intrinsics (dxg.sys imports) ---
    reg.bind("memcpy", s_memcpy as usize as u64);
    reg.bind("RtlCopyMemory", s_memcpy as usize as u64);
    reg.bind("memmove", s_memmove as usize as u64);
    reg.bind("RtlMoveMemory", s_memmove as usize as u64);
    reg.bind("memset", s_memset as usize as u64);
    reg.bind("RtlFillMemory", s_memset as usize as u64);
    // --- batch 4: Ps identity + per-process win32-slots (set by win32k's process callout) ---
    reg.bind(
        "PsGetCurrentProcessId",
        s_current_process_id as usize as u64,
    );
    reg.bind(
        "PsGetCurrentThreadProcessId",
        s_current_process_id as usize as u64,
    );
    reg.bind("PsGetProcessId", s_ps_get_process_id as usize as u64);
    reg.bind(
        "PsGetCurrentThreadId",
        s_ps_get_current_thread_id as usize as u64,
    );
    reg.bind("PsGetThreadId", s_ps_get_thread_id as usize as u64);
    reg.bind(
        "PsGetThreadProcessId",
        s_ps_get_thread_process_id as usize as u64,
    );
    reg.bind("IoGetCurrentProcess", s_current_process as usize as u64);
    reg.bind("PsGetCurrentProcess", s_current_process as usize as u64);
    reg.bind("PsGetCurrentThread", s_current_thread as usize as u64);
    reg.bind(
        "PsGetThreadProcess",
        s_ps_get_thread_process as usize as u64,
    );
    reg.bind(
        "PsLookupProcessByProcessId",
        s_ps_lookup_process_by_id as usize as u64,
    );
    reg.bind("KeGetCurrentThread", s_current_thread as usize as u64);
    reg.bind(
        "PsGetCurrentProcessWin32Process",
        s_get_current_win32process as usize as u64,
    );
    reg.bind(
        "PsGetProcessWin32Process",
        s_get_process_win32process as usize as u64,
    );
    reg.bind(
        "PsGetCurrentThreadWin32Thread",
        s_get_current_win32thread as usize as u64,
    );
    reg.bind(
        "PsGetThreadWin32Thread",
        s_get_thread_win32thread as usize as u64,
    );
    reg.bind(
        "PsSetProcessWin32Process",
        s_set_win32process as usize as u64,
    );
    reg.bind("PsSetThreadWin32Thread", s_set_win32thread as usize as u64);
    reg.bind(
        "PsGetProcessWin32WindowStation",
        s_ps_get_process_winsta as usize as u64,
    );
    reg.bind(
        "PsSetProcessWindowStation",
        s_ps_set_process_winsta as usize as u64,
    );
    reg.bind(
        "PsEstablishWin32Callouts",
        s_establish_win32_callouts as usize as u64,
    );
    reg.bind(
        "PsReferencePrimaryToken",
        s_ps_reference_primary_token as usize as u64,
    );
    reg.bind(
        "PsReferenceImpersonationToken",
        s_ps_reference_impersonation_token as usize as u64,
    );
    // --- batch 4: misc scalars ---
    reg.bind(
        "IoGetDeviceObjectPointer",
        s_io_get_device_object_pointer as usize as u64,
    );
    reg.bind(
        "KeUserModeCallback",
        s_ke_user_mode_callback_rendezvous as usize as u64,
    );
    reg.bind(
        "KeAddSystemServiceTable",
        s_ke_add_system_service_table as usize as u64,
    );
    reg.bind("DbgPrint", s_dbg_print as usize as u64);
    // --- batch 4: resource / lock acquire → BOOLEAN TRUE (single-threaded host: always acquired) ---
    reg.bind("ExAcquireResourceExclusiveLite", s_true as usize as u64);
    reg.bind("ExAcquireResourceSharedLite", s_true as usize as u64);
    reg.bind("ExIsResourceAcquiredExclusiveLite", s_true as usize as u64);
    reg.bind("ExIsResourceAcquiredSharedLite", s_true as usize as u64);
    reg.bind(
        "ExEnterCriticalRegionAndAcquireResourceShared",
        s_true as usize as u64,
    );
    reg.bind(
        "ExEnterCriticalRegionAndAcquireResourceExclusive",
        s_true as usize as u64,
    );
    reg.bind(
        "ExEnterCriticalRegionAndAcquireFastMutexUnsafe",
        s_true as usize as u64,
    );
    reg.bind("ExfAcquirePushLockExclusive", s_true as usize as u64);
    reg.bind("ExfTryToWakePushLock", s_true as usize as u64);
    reg.bind("KeSetKernelStackSwapEnable", s_true as usize as u64);
    reg.bind("ExGetPreviousMode", s_true as usize as u64);
    // --- batch 5: RTL security descriptors / ACLs / SIDs ---
    reg.bind(
        "RtlCreateSecurityDescriptor",
        s_rtl_create_security_descriptor as usize as u64,
    );
    reg.bind(
        "RtlSetDaclSecurityDescriptor",
        s_rtl_set_dacl_security_descriptor as usize as u64,
    );
    reg.bind("RtlLengthSid", s_rtl_length_sid as usize as u64);
    reg.bind("RtlCreateAcl", s_rtl_create_acl as usize as u64);
    reg.bind(
        "RtlAddAccessAllowedAceEx",
        s_rtl_add_access_allowed_ace_ex as usize as u64,
    );
    reg.bind(
        "RtlSetOwnerSecurityDescriptor",
        s_rtl_set_owner_security_descriptor as usize as u64,
    );
    reg.bind(
        "RtlSetGroupSecurityDescriptor",
        s_rtl_set_group_security_descriptor as usize as u64,
    );
    reg.bind(
        "RtlAbsoluteToSelfRelativeSD",
        s_rtl_absolute_to_self_relative_sd as usize as u64,
    );
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
        reg.bind(
            DATA_EXPORTS[di].0,
            WIN32K_DATA_VADDR + 0x1000 + di as u64 * 8,
        );
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
/// stack array or heap Vec): the rootserver stack is bounded and the heap is spent.
static mut CODE_RIGHTS: [u64; WIN32K_IMAGE_FRAMES as usize] = [RW_NX; WIN32K_IMAGE_FRAMES as usize];

/// The per-frame rights `load_into` computed (for `spawn_win32k_host`'s W^X mapping).
pub fn code_rights() -> &'static [u64] {
    // SAFETY: single-threaded; written once by load_into before this is read.
    unsafe { &*core::ptr::addr_of!(CODE_RIGHTS) }
}

unsafe fn copy_bytes(dst: u64, src: u64, n: u64) {
    let mut i = 0u64;
    while i + 8 <= n {
        write_unaligned(
            (dst + i) as *mut u64,
            read_unaligned((src + i) as *const u64),
        );
        i += 8;
    }
    while i < n {
        write_volatile((dst + i) as *mut u8, read_volatile((src + i) as *const u8));
        i += 1;
    }
}

fn image_rva_span_ok(rva: u64, len: u64, image_bytes: u64) -> bool {
    len != 0 && rva < image_bytes && len <= image_bytes - rva
}

unsafe fn image_c_string_len(base: u64, rva: u64, image_bytes: u64, limit: usize) -> Option<usize> {
    if rva >= image_bytes {
        return None;
    }
    let mut n = 0usize;
    while n < limit && (n as u64) < image_bytes - rva {
        if read_volatile((base + rva + n as u64) as *const u8) == 0 {
            return Some(n);
        }
        n += 1;
    }
    None
}

unsafe fn image_c_string_has_prefix_ignore_case(
    base: u64,
    rva: u64,
    image_bytes: u64,
    limit: usize,
    prefix: &[u8],
) -> bool {
    let Some(len) = image_c_string_len(base, rva, image_bytes, limit) else {
        return false;
    };
    if len < prefix.len() {
        return false;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        if read_volatile((base + rva + i as u64) as *const u8).to_ascii_lowercase() != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

unsafe fn image_c_string_eq_ignore_case(
    base: u64,
    rva: u64,
    image_bytes: u64,
    limit: usize,
    expected: &[u8],
) -> bool {
    let Some(len) = image_c_string_len(base, rva, image_bytes, limit) else {
        return false;
    };
    if len != expected.len() {
        return false;
    }
    let mut i = 0usize;
    while i < expected.len() {
        if read_volatile((base + rva + i as u64) as *const u8).to_ascii_lowercase() != expected[i] {
            return false;
        }
        i += 1;
    }
    true
}

unsafe fn image_c_string_is_safe(base: u64, rva: u64, len: usize) -> bool {
    if len == 0 || len > 31 {
        return false;
    }
    let mut i = 0usize;
    while i < len {
        let b = read_volatile((base + rva + i as u64) as *const u8).to_ascii_lowercase();
        let ok =
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.';
        if !ok {
            return false;
        }
        if i > 0 {
            let prev = read_volatile((base + rva + (i - 1) as u64) as *const u8);
            if prev == b'.' && b == b'.' {
                return false;
            }
        }
        i += 1;
    }
    true
}

fn import_dll_name_is_safe(dll: &[u8]) -> bool {
    !dll.is_empty()
        && dll.len() <= 31
        && dll.iter().copied().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
        })
        && !dll.windows(2).any(|w| w == b"..")
}

unsafe fn image_c_string_is_native_import(base: u64, rva: u64, len: usize) -> bool {
    if len >= 9 {
        let mut ntos = true;
        let mut i = 0usize;
        while i < 9 {
            if read_volatile((base + rva + i as u64) as *const u8).to_ascii_lowercase()
                != b"ntoskrnl."[i]
            {
                ntos = false;
                break;
            }
            i += 1;
        }
        if ntos {
            return true;
        }
    }
    if len >= 4 {
        let mut hal = true;
        let mut i = 0usize;
        while i < 4 {
            if read_volatile((base + rva + i as u64) as *const u8).to_ascii_lowercase()
                != b"hal."[i]
            {
                hal = false;
                break;
            }
            i += 1;
        }
        if hal {
            return true;
        }
    }
    false
}

unsafe fn pe_c_string_eq_slice(ptr: u64, expected: &[u8]) -> bool {
    let mut k = 0usize;
    loop {
        let c = read_volatile((ptr + k as u64) as *const u8);
        let want = if k < expected.len() { expected[k] } else { 0 };
        if c != want {
            return false;
        }
        if c == 0 {
            return true;
        }
        k += 1;
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
        let r = if chars & 0x2000_0000 != 0 {
            2u64
        } else {
            RW_NX
        };
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
        write_volatile(
            (WIN32K_DATA_VADDR + 0x1000 + idx as u64 * 8) as *mut u64,
            cell_value,
        );
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

    // Patch win32k's EngDeviceIoControl export to the executive-owned video-device boundary.
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
/// win32k's pool allocator exposed as a fn pointer for the shared [`crate::spawn_hosts::component_main`]
/// DriverEntry preamble (which must build the DRIVER_OBJECT / ext / RegistryPath from win32k's OWN
/// bump arena over `WIN32K_POOL_VADDR`, so the DriverEntry + `SH_POOL_USED` readback see win32k's pool).
pub(crate) unsafe fn pool_alloc_export(size: u64) -> u64 {
    pool_alloc(size)
}

#[no_mangle]
#[link_section = ".text.win32k_subsystem_entry"]
pub unsafe extern "C" fn win32k_subsystem_entry() -> ! {
    // NOW RUNS ON THE SHARED HARNESS (Phase B, Step 4b). The DriverEntry preamble (build DRIVER_OBJECT
    // + RegistryPath from win32k's OWN pool, mark V_ENTERED, call DriverEntry, record verdict/status),
    // the `post_driver_entry` hook, and the persistent send_done→recv_req→dispatch→writeback loop are
    // all delegated to [`crate::spawn_hosts::component_main`]. win32k's irreducible specifics stay
    // win32k-side: the SSN router + per-dispatch pre/post work is [`win32k_dispatch`] (the `dispatch`
    // closure); `establish_client_and_dispatch` + `setup_dispatch_context` are [`win32k_post_driver_entry`]
    // (both MUST run between DriverEntry and the FIRST send_done — preserved by the harness ordering).
    let entry_rva = read_volatile((WIN32K_SHARED_VADDR + SH_ENTRY_RVA) as *const u64) as u32;
    print_str(b"[win32k-host] START DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");
    // Seed a real bootstrap runtime EPROCESS/ETHREAD before DriverEntry. ReactOS win32k may call
    // PsGetCurrentProcess/Thread or inline KPCR.Prcb.CurrentThread while registering its callouts; those
    // reads now resolve through the same PID/TID-keyed context table used by routed client dispatches.
    if ensure_bootstrap_win32k_context().is_none() {
        print_str(
            b"[win32k-host] ERROR: bootstrap GUI context allocation failed before DriverEntry\n",
        );
    }
    write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, WIN32K_KPCR_VA);
    // Mark "entered" BEFORE component_main calls DriverEntry so a fault mid-init is still attributable.
    // (component_main also sets V_ENTERED, but win32k's DriverEntry may fault before that write; keep
    // the early mark to match the old entry's ordering exactly.)
    write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, V_ENTERED);
    crate::spawn_hosts::component_main(
        WIN32K_SHARED_VADDR,
        WIN32K_CODE_VA,
        // Allocate 0x200 but stamp Size=336 (0x150), exactly as the old bespoke entry; ext ptr @48
        // (0x30), ext block 0x40; win32k has NO MajorFunction table — mj @0x100 (a zeroed drv slot,
        // so no spurious V_MJ) and mj_table_off=MAX (do NOT record: 0x18 is win32k's SH_SSDT_BASE).
        crate::spawn_hosts::DriverObjectSpec {
            size: 0x200,
            size_field: 336,
            ext_size: 0x40,
            mj: 0x100,
            mj_table_off: u64::MAX,
            pool: pool_alloc_export,
            support_entry_rva_off: u64::MAX,
            support_status_off: u64::MAX,
            support_verdict_off: u64::MAX,
        },
        SH_REQ_STATUS,      // win32k status offset (0x78)
        W32_DISPATCH_LABEL, // 0x770
        win32k_dispatch,    // ssn → per-dispatch pre/post + dispatch_ssn
        win32k_post_driver_entry,
    )
}

/// win32k `post_driver_entry` (runs between DriverEntry and the FIRST `send_done`, exactly as the old
/// inline entry): emit the DriverEntry-returned diagnostic, record the pool high-water, then
/// establish the client's per-process win32 context (Phase 2c) and enter the per-dispatch process/
/// thread context ([`setup_dispatch_context`]) — the same establish→setup ordering the old
/// `win32k_subsystem_entry` → `dispatch_loop` did before its first sentinel.
unsafe fn win32k_post_driver_entry(status: i32, _drv: u64) {
    let v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32);
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
    // fault is caught + backtraced by the executive's fault loop before the first sentinel.
    if status == 0 {
        establish_client_and_dispatch();
    }
    // Enter the per-dispatch process/thread context (the old `dispatch_loop` ran this ONCE before the
    // loop; the harness's loop calls win32k_dispatch per request, so seed the context here — before the
    // FIRST send_done — to preserve the exact ordering).
    setup_dispatch_context();
}

/// The win32k `dispatch` closure plugged into [`crate::spawn_hosts::component_main`]. This is the EXACT
/// per-request body the retired inline `dispatch_loop` ran (minus the send_done/recv_req/status-writeback,
/// which the harness owns): the SetThreadDesktop WindowListHead compatibility reset + BATCH-43
/// thread↔desktop re-assert,
/// the SSN_TEST_FAULT self-test, NtUserInitialize event registration + the post-init font/winsta seed,
/// and the SSDT dispatch via `dispatch_ssn` (which retains the exact-arity wide-arg transmute). Returns
/// `(low32, full_result)` — win32k uses pointer-width syscall returns, with the low 32 bits kept as
/// status-compatible data for legacy harness readers.
unsafe fn win32k_dispatch(_req: &crate::spawn_hosts::DispatchReq) -> (i32, u64) {
    let ssn = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_SSN) as *const u64);
    let a0 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A0) as *const u64);
    let a1 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A1) as *const u64);
    let a2 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A2) as *const u64);
    let a3 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A3) as *const u64);
    let process_id = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_PROCESS_ID) as *const u64);
    let client_pi = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_CLIENT_PI) as *const u64);
    let client_teb = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_CLIENT_TEB) as *const u64);
    let thread_id = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_THREAD_ID) as *const u64);
    let supplied_eprocess = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_EPROCESS) as *const u64);
    let supplied_ethread = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_ETHREAD) as *const u64);
    let process_role = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_PROCESS_ROLE) as *const u64);
    let token_authentication_id =
        read_volatile((WIN32K_SHARED_VADDR + SH_REQ_TOKEN_AUTH) as *const u64);
    let token_user_sid_len =
        read_volatile((WIN32K_SHARED_VADDR + SH_REQ_TOKEN_USER_SID_LEN) as *const u64) as usize;
    let token_user_sid_ptr =
        read_volatile((WIN32K_SHARED_VADDR + SH_REQ_TOKEN_USER_SID_PTR) as *const u64);
    let mut token_user_sid = [0u8; WIN32K_TOKEN_USER_SID_MAX];
    if token_user_sid_ptr != 0 && token_user_sid_len <= WIN32K_TOKEN_USER_SID_MAX {
        let mut sid_i = 0usize;
        while sid_i < WIN32K_TOKEN_USER_SID_MAX {
            token_user_sid[sid_i] = read_volatile((token_user_sid_ptr + sid_i as u64) as *const u8);
            sid_i += 1;
        }
    }
    let top_level =
        read_volatile((WIN32K_SHARED_VADDR + SH_REQ_NESTED_CALLBACK) as *const u64) == 0;
    let Some((process_index, thread_index)) = select_win32k_client_context(
        client_pi,
        process_id,
        thread_id,
        client_teb,
        supplied_eprocess,
        supplied_ethread,
        process_role,
        token_authentication_id,
        &token_user_sid,
        token_user_sid_len,
    ) else {
        return (0xC000_009Au32 as i32, 0xC000_009Au32 as u64);
    };
    let process_attached = ensure_win32k_process_attached(process_index, process_role);
    let threadinfo_ready = process_attached && ensure_win32k_threadinfo(thread_index, client_teb);
    if !process_attached || !threadinfo_ready {
        return (0xC000_009Au32 as i32, 0xC000_009Au32 as u64);
    }
    if matches!(client_pi, 2 | 5 | 6) {
        load_system_font_for_client(client_pi as usize);
    }
    let trace = WIN32K_CLIENT_CONTEXT_TRACES.fetch_add(1, Ordering::Relaxed);
    if trace < 32 {
        let eprocess = current_eprocess();
        let ethread = current_ethread();
        let ppi = current_w32process();
        let pti = current_w32thread();
        print_str(b"[win32k-context] dispatch pi=");
        print_u64(client_pi);
        print_str(b" pid=0x");
        print_hex(process_id as u32);
        print_str(b" tid=0x");
        print_hex(thread_id as u32);
        print_str(b" eprocess=0x");
        print_hex((eprocess >> 32) as u32);
        print_hex(eprocess as u32);
        print_str(b" ethread=0x");
        print_hex((ethread >> 32) as u32);
        print_hex(ethread as u32);
        print_str(b" ppi=0x");
        print_hex((ppi >> 32) as u32);
        print_hex(ppi as u32);
        print_str(b" pti=0x");
        print_hex((pti >> 32) as u32);
        print_hex(pti as u32);
        print_str(b"\n");
    }
    // The established compatibility context remains load-bearing for win32k's early initialization.
    // Switch to the routed client's real TEB only where ReactOS may call kernel-mode NtCurrentTeb()
    // while capturing a user window-station/desktop name. The client attach path identity-maps the
    // registered TEB pages, so this remains the caller's live StaticUnicodeString/CLIENTINFO view.
    let teb_context = if ssn == SSN_GDI_BATCH_FLUSH_CALLOUT || ssn == 0x122f || ssn == 0x122d {
        client_teb
    } else {
        WIN32K_KPCR_VA
    };
    write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, teb_context);
    // The top-level SetThreadDesktop call begins with the client thread owning no windows. The desktop windows
    // IntCreateDesktop builds live on gptiDesktopThread, which our single-threaded host merged with
    // the dispatch thread — so winlogon's NtUserSetThreadDesktop (desktop.c:3331 IsListEmpty check)
    // would wrongly see those desktop windows as ITS windows and fail "thread has windows",
    // short-circuiting its `SetThreadDesktop(Winlogon) && SwitchDesktop(Winlogon)` (wlx.c:1077) —
    // the natural co_IntShowDesktop / co_IntInitializeDesktopGraphics trigger. Before the SAS window
    // exists, re-empty the current thread's WindowListHead (+0x2d8) once for that operation to
    // restore the authentic invariant. Never repeat this on unrelated dispatches: once IntCreateWindow has
    // inserted a WND.ThreadListEntry, rewriting only the head corrupts the checked RemoveEntryList
    // performed by co_UserFreeWindow.
    let t = current_w32thread();
    sync_threadinfo_process(t);
    // ★ Publish the dispatch THREADINFO into the CURRENT-THREAD OBJECT (`Thread->Tcb.Win32Thread`).
    // `PsGetCurrentThreadWin32Thread()` is an EXPORT we bind, but the MSVC win32k build also inlines
    // it as `PsGetCurrentThread(); mov rcx,[rax+0x250]` — and that inline read is the one
    // `NtUserCallNoParam(NOPARAM_ROUTINE_DESTROY_CARET)` uses. Every dispatch (top-level AND nested,
    // which is where the logon-dialog teardown reaches it) must therefore see the same `t` through
    // the thread object as through the slot. Idempotent, and the only writer of this field.
    let ethread = current_ethread();
    write_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *mut u64, t);
    // ★ THE OTHER HALF OF THE SAME BINDING: `THREADINFO.pEThread` (offset 0 — `W32THREAD`'s first
    // member, `win32ss/user/ntuser/win32.h:59`). Real win32k sets it in `InitThreadCallback`
    // (`pti->pEThread = PsGetCurrentThread()`), and handlers walk BACK through it to the thread
    // object: `IntSetTimer` does `pTmr->pti = Window->head.pti->pEThread->Tcb.Win32Thread`
    // (`win32ss/user/ntuser/timer.c:251`). With `pEThread` NULL that is a read of `[0 + 0x250]` —
    // measured on winlogon's post-logon `SetTimer` (SSN 0x1017): `#PF cr2 = 0x250`, which WALLED and
    // RETIRED the whole hosted win32k. Bind it to the same ETHREAD `PsGetCurrentThread` returns, so
    // the round trip pti → pEThread → Tcb.Win32Thread closes back onto `t`. Only ever fills a NULL:
    // a `pEThread` win32k set itself is left alone.
    if read_volatile(t as *const u64) == 0 {
        write_volatile(t as *mut u64, ethread);
    }
    if top_level
        && ssn == SSN_NT_USER_SET_THREAD_DESKTOP
        && SET_THREAD_DESKTOP_WINDOW_LIST_RESET_DONE.swap(1, Ordering::Relaxed) == 0
    {
        let head = t + 0x2d8;
        write_volatile(head as *mut u64, head);
        write_volatile((head + 8) as *mut u64, head);
    }
    // Reassert the selected client's own desktop binding before normal dispatch. Logon threads keep
    // the secure desktop they established through NtUserSetThreadDesktop; shell clients inherit the
    // process startup desktop that winlogon supplied through WinSta0\Default.
    if top_level && ssn != SSN_NT_USER_SET_THREAD_DESKTOP {
        let ppi = current_w32process();
        if let Some((hdesk, desk_body, pdeskinfo)) = selected_thread_desktop(process_role, ppi, t) {
            publish_thread_desktop_binding(t, hdesk, desk_body, pdeskinfo);
        }
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
    let result = if ssn == SSN_TEST_FAULT {
        // Fix (B) self-test: touch an un-demand-paged page → FAULT mid-dispatch. The executive
        // resolves it via the REPLY_W32 reply cap and resumes us here; we read back the zeroed
        // page (observability into SH_REQ_A0) and report the sentinel status.
        let probe = read_volatile(TEST_FAULT_VA as *const u64);
        write_volatile((WIN32K_SHARED_VADDR + SH_REQ_A0) as *mut u64, probe);
        TEST_FAULT_STATUS as u32 as u64
    } else if ssn == SSN_GDI_BATCH_FLUSH_CALLOUT {
        dispatch_gdi_batch_flush_callout(client_pi, client_teb)
    } else {
        dispatch_ssn(ssn, a0, a1, a2, a3)
    };
    // Post-NtUserInitialize (0x125a) HOST-PREREQUISITE SEED (once). InitializeGreCSRSS and
    // InitFontSupport have completed, so this is the earliest valid point to create the system font,
    // interactive object graph and PDEV. The PDEV must exist before user32's real
    // resource-backed system-cursor/class initialization starts issuing NtGdiOpenDCW; deferring it
    // until the later winlogon SwitchDesktop leaves every cursor display-DC open without a device.
    // Two prerequisites cannot be produced by winlogon itself and are seeded here:
    //   (1) the system font (arial.ttf memory-font) — else the lazy co_IntInitializeDesktopGraphics's
    //       font realize null-derefs ("no fonts loaded at all");
    //   (2) the WinSta0/Default Ob object graph winlogon reuses (its NtUserCreateWindowStation returns
    //       hWinSta=0x4, and gpdeskInputDesktop is set). A bRedraw=FALSE SwitchDesktop establishes the
    //       active desktop before co_IntGraphicsCheck creates the real device and surface.
    if ssn == SSN_NT_USER_INITIALIZE_REAL && result as u32 == 0 && !DESKTOP_GFX_SEEDED {
        DESKTOP_GFX_SEEDED = true;
        load_system_font_for_client(current_client_index());
        create_winsta_and_desktop();
        print_str(b"[win32k-gfx] creating display PDEV before user32 resources...\n");
        let change_display: extern "win64" fn(u64, u64, u64, *mut u64, u64) -> i32 =
            core::mem::transmute(
                (WIN32K_CODE_VA + PDEVOBJ_L_CHANGE_DISPLAY_SETTINGS_RVA) as *const (),
            );
        let gpmdev = (WIN32K_CODE_VA + GPMDEV_RVA) as *mut u64;
        let display_status = change_display(0, 0, 0, gpmdev, 1);
        print_str(b"[win32k-gfx] PDEVOBJ_lChangeDisplaySettings status=0x");
        print_hex(display_status as u32);
        print_str(b" gpmdev=0x");
        let mdev = read_volatile(gpmdev);
        print_hex((mdev >> 32) as u32);
        print_hex(mdev as u32);
        print_str(b"\n");
    }
    (result as u32 as i32, result)
}

/// Invoke win32k's real `WIN32_CALLOUTS_FPNS.BatchFlushRoutine` for the selected client thread.
/// The caller's TEB is exposed through KPCR.PrcbData.CurrentThread.Teb by `win32k_dispatch` above.
unsafe fn dispatch_gdi_batch_flush_callout(client_pi: u64, client_teb: u64) -> u64 {
    const STATUS_INVALID_PARAMETER: u64 = 0xC000_000Du32 as u64;
    const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002u32 as u64;

    if client_pi == 0 || client_teb == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let routine = read_volatile((WIN32_CALLOUTS + WIN32_CALLOUT_BATCH_FLUSH_OFF) as *const u64);
    if routine == 0 {
        return STATUS_NOT_IMPLEMENTED;
    }

    let flush: extern "win64" fn() -> i32 = core::mem::transmute(routine as *const ());
    flush() as u32 as u64
}

fn expected_gdi_return_type(ssn: u64) -> Option<u32> {
    match ssn {
        SSN_GDI_OPEN_DCW | SSN_GDI_CREATE_COMPATIBLE_DC => Some(GDI_OBJECT_TYPE_DC),
        SSN_GDI_CREATE_COMPATIBLE_BITMAP
        | SSN_GDI_CREATE_BITMAP
        | SSN_GDI_CREATE_DIB_SECTION
        | SSN_GDI_CREATE_DIBITMAP_INTERNAL => Some(GDI_OBJECT_TYPE_BITMAP),
        _ => None,
    }
}

unsafe fn observe_gdi_handle_return(ssn: u64, handle: u64) {
    let Some(expected_type) = expected_gdi_return_type(ssn) else {
        return;
    };
    if handle == 0 {
        return;
    }

    let table_base = read_volatile((WIN32K_SHARED_VADDR + SH_GDI_TABLE_BASE) as *const u64);
    let table_size = read_volatile((WIN32K_SHARED_VADDR + SH_GDI_TABLE_SIZE) as *const u64);
    let index = handle & (GDI_HANDLE_COUNT - 1);
    let offset = index * GDI_TABLE_ENTRY_SIZE;
    if table_base == 0 || offset + GDI_TABLE_ENTRY_SIZE > table_size {
        return;
    }

    let entry = table_base + offset;
    let entry_pid = read_volatile((entry + GDI_ENTRY_PROCESS_ID_OFF) as *const u32);
    let entry_type = read_volatile((entry + GDI_ENTRY_TYPE_OFF) as *const u32);
    let user_data = read_volatile((entry + GDI_ENTRY_USER_DATA_OFF) as *const u64);
    let handle_type = (handle as u32) & GDI_HANDLE_TYPE_MASK;
    let gdi32_entry_type = entry_type.wrapping_shl(GDI_ENTRY_UPPER_SHIFT) & GDI_HANDLE_TYPE_MASK;
    let current_pid = WIN32K_CURRENT_PROCESS_ID.load(Ordering::Relaxed) as u32;
    let owner_pid = entry_pid & !1;
    let type_ok = handle_type == expected_type
        && gdi32_entry_type == expected_type
        && (entry_type & GDI_HANDLE_BASETYPE_MASK) == (expected_type & GDI_HANDLE_BASETYPE_MASK);
    let owner_ok = owner_pid == current_pid;
    let user_data_ok = expected_type != GDI_OBJECT_TYPE_DC || user_data != 0;
    let mismatch = !type_ok || !owner_ok || !user_data_ok;
    if !mismatch {
        return;
    }

    let pi = current_client_index();
    let mismatch_trace = WIN32K_GDI_HANDLE_MISMATCH_TRACES.fetch_add(1, Ordering::Relaxed);
    if mismatch_trace >= 64 {
        return;
    }

    print_str(b"[gdi-entry] ssn=0x");
    print_hex(ssn as u32);
    print_str(b" pi=");
    print_u64(pi as u64);
    print_str(b" pid=0x");
    print_hex(current_pid);
    print_str(b" h=0x");
    print_hex(handle as u32);
    print_str(b" idx=0x");
    print_hex(index as u32);
    print_str(b" htype=0x");
    print_hex(handle_type);
    print_str(b" etype=0x");
    print_hex(entry_type);
    print_str(b" gdi32-type=0x");
    print_hex(gdi32_entry_type);
    print_str(b" owner=0x");
    print_hex(entry_pid);
    print_str(b" user=0x");
    print_hex((user_data >> 32) as u32);
    print_hex(user_data as u32);
    print_str(b" BAD\n");
}

/// Resolve a win32k SSN (>= [`WIN32K_SERVICE_BASE`]) through the registered NtUser/NtGdi SSDT and
/// invoke its handler with the correct win64 register/stack args. Returns the pointer-width handler
/// result (or `STATUS_INVALID_SYSTEM_SERVICE` in the low 32 bits if the SSN is invalid).
unsafe fn dispatch_ssn(ssn: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    const STATUS_INVALID_SYSTEM_SERVICE: u64 = 0xC000_001Cu32 as u64;
    const STATUS_INVALID_PARAMETER: u64 = 0xC000_000Du32 as u64;
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
    // Reconstruct a genuine N-arg win64 call using the arity win32k registered through
    // KeAddSystemServiceTable's SSPT/KiArgumentTable. Real client syscalls read stack args from the
    // attached caller stack; executive-originated calls must stage enough explicit args up front.
    let Some(nargs) = registered_win32k_provider_argc(ssn) else {
        return STATUS_INVALID_SYSTEM_SERVICE;
    };
    if nargs > WIN32K_MAX_SERVICE_ARGS {
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    let sh = WIN32K_SHARED_VADDR;
    let debug_flags = read_volatile((sh + SH_REQ_DEBUG_FLAGS) as *const u64);
    let caller_sp = read_volatile((sh + SH_REQ_CALLER_SP) as *const u64);
    let staged_nargs = read_volatile((sh + SH_REQ_NARGS) as *const u64);
    let request_client_pi = read_volatile((sh + SH_REQ_CLIENT_PI) as *const u64);
    if staged_nargs > WIN32K_MAX_SERVICE_ARGS {
        return STATUS_INVALID_PARAMETER;
    }
    if nargs > 4 {
        if caller_sp != 0 {
            let last_tail = nargs - 5;
            if caller_sp
                .checked_add(0x28)
                .and_then(|base| {
                    last_tail
                        .checked_mul(8)
                        .and_then(|offset| base.checked_add(offset))
                })
                .is_none()
            {
                return STATUS_INVALID_PARAMETER;
            }
        } else if staged_nargs < nargs {
            return STATUS_INVALID_PARAMETER;
        }
    }
    let s = |i: u64| {
        let tail = i - 4;
        if caller_sp != 0 {
            read_volatile((caller_sp + 0x28 + tail * 8) as *const u64)
        } else {
            read_volatile((sh + SH_REQ_A4 + tail * 8) as *const u64)
        }
    }; // stack arg i (i>=4)
       // ★ BATCH 46 diagnose — winlogon's SwitchDesktop paint short-circuit. Read the two gates BEFORE the
       // handler runs: (1) gpdeskInputDesktop (if it already == the target desktop, win32k's SwitchDesktop
       // returns TRUE with ZERO paint work — desktop.c:2996); (2) NrGuiAppsRunning (if != 0, co_AddGuiApp's
       // lazy co_IntInitializeDesktopGraphics won't run on the 0→1 transition → SM_CXSCREEN stays 0 → blit
       // no-ops). a0 (the HDESK) is the switch target.
    if ssn == SSN_NT_USER_SWITCH_DESKTOP {
        let gpdesk = read_volatile((WIN32K_CODE_VA + GPDESK_INPUT_DESKTOP_RVA) as *const u64);
        let target_body = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(a0);
        let ngui = read_volatile((WIN32K_CODE_VA + NR_GUI_APPS_RUNNING_RVA) as *const u32);
        print_str(b"[win32k-paint] PRE-SwitchDesktop hDesk=0x");
        print_hex(a0 as u32);
        print_str(b" target_body=0x");
        print_hex((target_body >> 32) as u32);
        print_hex(target_body as u32);
        print_str(b" gpdeskInputDesktop=0x");
        print_hex((gpdesk >> 32) as u32);
        print_hex(gpdesk as u32);
        print_str(b" NrGuiAppsRunning=0x");
        print_hex(ngui);
        print_str(if gpdesk != 0 && gpdesk == target_body {
            b" [ALREADY-CURRENT!]\n"
        } else {
            b"\n"
        });
    }
    let explorer_setwndproc = (ssn == SSN_NT_USER_SET_WINDOW_LONG
        || ssn == SSN_NT_USER_SET_WINDOW_LONG_PTR)
        && (a1 as u32) as u64 == GWLP_WNDPROC_INDEX_U32
        && request_client_pi == 6;
    if explorer_setwndproc {
        if debug_flags & SH_REQ_DEBUG_ATL_REPLAY != 0 {
            WIN32K_EXPLORER_SETWNDPROC_REPLAY_CALLS.fetch_add(1, Ordering::Relaxed);
        } else {
            WIN32K_EXPLORER_SETWNDPROC_CLIENT_CALLS.fetch_add(1, Ordering::Relaxed);
        }
    }
    if ssn == SSN_NT_USER_SET_THREAD_DESKTOP {
        prepare_set_thread_desktop(a0);
    }

    let ret = match nargs {
        0 => {
            let f: extern "win64" fn() -> u64 = core::mem::transmute(handler as *const ());
            f()
        }
        1 => {
            let f: extern "win64" fn(u64) -> u64 = core::mem::transmute(handler as *const ());
            f(a0)
        }
        2 => {
            let f: extern "win64" fn(u64, u64) -> u64 = core::mem::transmute(handler as *const ());
            f(a0, a1)
        }
        3 => {
            let f: extern "win64" fn(u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2)
        }
        4 => {
            let f: extern "win64" fn(u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3)
        }
        5 => {
            let f: extern "win64" fn(u64, u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3, s(4))
        }
        6 => {
            let f: extern "win64" fn(u64, u64, u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3, s(4), s(5))
        }
        7 => {
            let f: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3, s(4), s(5), s(6))
        }
        8 => {
            let f: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3, s(4), s(5), s(6), s(7))
        }
        9 => {
            let f: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3, s(4), s(5), s(6), s(7), s(8))
        }
        10 => {
            let f: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3, s(4), s(5), s(6), s(7), s(8), s(9))
        }
        11 => {
            let f: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 =
                core::mem::transmute(handler as *const ());
            f(a0, a1, a2, a3, s(4), s(5), s(6), s(7), s(8), s(9), s(10))
        }
        12 => {
            let f: extern "win64" fn(
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
            ) -> u64 = core::mem::transmute(handler as *const ());
            f(
                a0,
                a1,
                a2,
                a3,
                s(4),
                s(5),
                s(6),
                s(7),
                s(8),
                s(9),
                s(10),
                s(11),
            )
        }
        13 => {
            let f: extern "win64" fn(
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
            ) -> u64 = core::mem::transmute(handler as *const ());
            f(
                a0,
                a1,
                a2,
                a3,
                s(4),
                s(5),
                s(6),
                s(7),
                s(8),
                s(9),
                s(10),
                s(11),
                s(12),
            )
        }
        14 => {
            let f: extern "win64" fn(
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
            ) -> u64 = core::mem::transmute(handler as *const ());
            f(
                a0,
                a1,
                a2,
                a3,
                s(4),
                s(5),
                s(6),
                s(7),
                s(8),
                s(9),
                s(10),
                s(11),
                s(12),
                s(13),
            )
        }
        15 => {
            let f: extern "win64" fn(
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
            ) -> u64 = core::mem::transmute(handler as *const ());
            f(
                a0,
                a1,
                a2,
                a3,
                s(4),
                s(5),
                s(6),
                s(7),
                s(8),
                s(9),
                s(10),
                s(11),
                s(12),
                s(13),
                s(14),
            )
        }
        16 => {
            let f: extern "win64" fn(
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
                u64,
            ) -> u64 = core::mem::transmute(handler as *const ());
            f(
                a0,
                a1,
                a2,
                a3,
                s(4),
                s(5),
                s(6),
                s(7),
                s(8),
                s(9),
                s(10),
                s(11),
                s(12),
                s(13),
                s(14),
                s(15),
            )
        }
        _ => return STATUS_INVALID_SYSTEM_SERVICE,
    };
    observe_gdi_handle_return(ssn, ret);
    // ★ BATCH 46 — restore the desktop-paint TRIGGER on winlogon's real SwitchDesktop.
    //
    // ROOT CAUSE (instruction-confirmed, NtUserSwitchDesktop RVA 0x6c2f8/0x6c579): winlogon's switch is
    // the FIRST switch, so `gpdeskInputDesktop == NULL` on entry → win32k computes `bRedrawDesktop = FALSE`
    // (the `if (gpdeskInputDesktop != NULL)` VISIBLE-check branch is skipped) → `co_IntShowDesktop` runs
    // with SWP_NOREDRAW → NO `co_UserRedrawWindow` → NO WM_ERASEBKGND → NO GetDC → NO `co_IntGraphicsCheck`
    // → `NrGuiAppsRunning` stays 0 → `co_IntInitializeDesktopGraphics` (InitVideo) NEVER runs → SM_CX/CYSCREEN
    // stay 0 → IntPaintDesktop blits to a 0×0 surface (0/768 px). The counter proves it: NrGuiAppsRunning=0
    // both before AND after winlogon's switch.
    //
    // In real Windows the lazy InitVideo fires from winlogon's first GUI display-DC alloc
    // (`DceCreateDisplayDC → co_IntGraphicsCheck(TRUE)`, windc.c:44) once a message loop pumps the desktop
    // window's WM_PAINT/WM_ERASEBKGND. Our single-threaded host short-circuits the SAS window's WINDOWPROC
    // callbacks (BATCH 45) and never runs a message loop, so that natural DC-alloc never happens. The
    // FAITHFUL trigger — the SAME function win32k itself calls — is `co_IntGraphicsCheck(TRUE)`: it runs the
    // REAL `co_AddGuiApp → co_IntInitializeDesktopGraphics` (display surface init via PDEVOBJ_lChangeDisplay
    // Settings + IntGdiCreateDC(L"DISPLAY") + IntCreatePrimarySurface) whose tail does
    // `co_IntShowDesktop(IntGetActiveDesktop()=gpdeskInputDesktop, SM_CX, SM_CY, bRedraw=TRUE)` = the genuine
    // IntPaintDesktop that blits 0x003a6ea5 to the BOOTBOOT framebuffer through the selected display DLL.
    // NOTHING is faked — win32k's own GDI paints the pixels; we only supply the DC-alloc trigger our missing
    // message loop would otherwise supply, at the authentic point (right after the desktop is made current).
    if ssn == SSN_NT_USER_SWITCH_DESKTOP {
        let gpdesk = read_volatile((WIN32K_CODE_VA + GPDESK_INPUT_DESKTOP_RVA) as *const u64);
        let ngui = read_volatile((WIN32K_CODE_VA + NR_GUI_APPS_RUNNING_RVA) as *const u32);
        print_str(b"[win32k-paint] POST-SwitchDesktop ret=0x");
        print_hex(ret as u32);
        print_str(b" gpdeskInputDesktop=0x");
        print_hex((gpdesk >> 32) as u32);
        print_hex(gpdesk as u32);
        print_str(b" NrGuiAppsRunning=0x");
        print_hex(ngui);
        print_str(b"\n");
        // Fire the lazy graphics init exactly once, when a desktop is current (gpdeskInputDesktop set) and
        // InitVideo has not yet run (NrGuiAppsRunning == 0). co_IntGraphicsCheck's own W32PF_CREATEDWINORDC
        // guard makes a repeat call a no-op, but gating on ngui==0 keeps the log clean and matches the real
        // first-DC-alloc semantics.
        if gpdesk != 0 && ngui == 0 {
            print_str(b"[win32k-paint] driving co_IntGraphicsCheck(TRUE) -> InitVideo + IntPaintDesktop...\n");
            let gfx: extern "win64" fn(u64) -> i32 =
                core::mem::transmute((WIN32K_CODE_VA + CO_INT_GRAPHICS_CHECK_RVA) as *const ());
            let gret = gfx(1);
            let ngui2 = read_volatile((WIN32K_CODE_VA + NR_GUI_APPS_RUNNING_RVA) as *const u32);
            print_str(b"[win32k-paint] co_IntGraphicsCheck ret=0x");
            print_hex(gret as u32);
            print_str(b" NrGuiAppsRunning=0x");
            print_hex(ngui2);
            print_str(b"\n");
        }

        if gpdesk != 0 {
            // FULL-DESKTOP REPAINT. InitVideo's own `co_IntShowDesktop(pdesk, 1024, 768, TRUE)` GREW the
            // desktop window from the default 640×480 (winlogon's FIRST bRedraw=FALSE switch pre-showed it at
            // the boot-default SM_CX/CYSCREEN) to full 1024×768. co_WinPosSetWindowPos preserves the old
            // 640×480 area (SWP bitblt) and RDW_INVALIDATE only invalidates the newly-exposed L-region → the
            // top-left 640×480 keeps its NEVER-painted (magenta) content (observed: 468/768, an L-shape with a
            // 640×480 top-left hole). Force a WHOLE-desktop erase so IntPaintDesktop repaints the FULL screen:
            // invoke win32k's own `NtUserRedrawWindow(hwndDesktop, NULL, NULL,
            // RDW_INVALIDATE|RDW_ERASE|RDW_UPDATENOW|RDW_ALLCHILDREN)` — this is exactly the whole-desktop
            // repaint path win32k uses on WM_SYSCOLORCHANGE (desktop.c DesktopWindowProc) → DesktopWindowProc
            // WM_ERASEBKGND → IntPaintDesktop over the full clip box. The pixels are still painted by win32k's
            // real GDI, not by us. The desktop HWND is `gpdesk->pDeskInfo->spwnd->head.h` (WND HEAD.h @ spwnd+0).
            let pdeskinfo = read_volatile((gpdesk + 0x08) as *const u64); // DESKTOP.pDeskInfo
            let spwnd = if pdeskinfo != 0 {
                read_volatile((pdeskinfo + 0x10) as *const u64)
            } else {
                0
            };
            let hwnd_desktop = if spwnd != 0 {
                read_volatile(spwnd as *const u64)
            } else {
                0
            }; // WND HEAD.h
            if hwnd_desktop != 0 {
                // Per-client THREADINFO isolation means the desktop window can still carry the bootstrap
                // desktop-thread owner while this repaint runs in winlogon's isolated thread. In this
                // single-threaded host that turns DesktopWindowProc delivery into a queued cross-thread send
                // that no desktop thread will pump. Rebind the desktop WND to the current dispatch thread so
                // co_UserRedrawWindow dispatches WM_ERASEBKGND synchronously, as the original shared-thread
                // model did.
                let current_pti = current_w32thread();
                let owner_pti = read_volatile((spwnd + WND_HEAD_PTI_OFF) as *const u64);
                if current_pti != 0 && owner_pti != current_pti {
                    write_volatile((spwnd + WND_HEAD_PTI_OFF) as *mut u64, current_pti);
                    print_str(b"[win32k-paint] rebound desktop WND owner pti=0x");
                    print_hex((owner_pti >> 32) as u32);
                    print_hex(owner_pti as u32);
                    print_str(b" -> 0x");
                    print_hex((current_pti >> 32) as u32);
                    print_hex(current_pti as u32);
                    print_str(b"\n");
                }
                // RDW_INVALIDATE(0x1)|RDW_ERASE(0x4)|RDW_UPDATENOW(0x100)|RDW_ALLCHILDREN(0x80) = 0x185.
                const RDW_FULL: u64 = 0x1 | 0x4 | 0x100 | 0x80;
                let ssdt_base = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *const u64);
                let ridx = SSN_NT_USER_REDRAW_WINDOW - WIN32K_SERVICE_BASE;
                let rh = read_volatile((ssdt_base + ridx * 8) as *const u64);
                if rh != 0 {
                    let redraw: extern "win64" fn(u64, u64, u64, u64) -> i32 =
                        core::mem::transmute(rh as *const ());
                    let rret = redraw(hwnd_desktop, 0, 0, RDW_FULL);
                    print_str(b"[win32k-paint] NtUserRedrawWindow(hwndDesktop=0x");
                    print_hex(hwnd_desktop as u32);
                    print_str(b", RDW_FULL) ret=0x");
                    print_hex(rret as u32);
                    print_str(b"\n");
                } else {
                    print_str(b"[win32k-paint] WARN: NtUserRedrawWindow SSN unresolved\n");
                }
            } else {
                print_str(
                    b"[win32k-paint] WARN: no desktop HWND (spwnd null) - full repaint skipped\n",
                );
            }
        }
    }

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
                write_volatile(
                    (WIN32K_CODE_VA + INPUT_WINDOW_STATION_RVA) as *mut u64,
                    winsta_body,
                );
                print_str(b"[win32k-host] routed NtUserCreateDesktop hDesk=0x");
                print_hex(hdesk as u32);
                print_str(b" rpwinstaParent set -> body=0x");
                print_hex((desk_body >> 32) as u32);
                print_hex(desk_body as u32);
                print_str(b"\n");
            }
            if object_attributes_name_leaf_eq_ascii(a0, b"default") {
                publish_default_desktop(hdesk, desk_body, b"NtUserCreateDesktop(Default)");
            }
        }
    }
    // ★ BATCH 43 — LATCH the thread↔desktop connection winlogon's OWN NtUserSetThreadDesktop makes.
    //
    // `NtUserSetThreadDesktop` (SSN 0x1092 → IntSetThreadDesktop) is where winlogon connects its
    // interactive thread to the Default desktop: on its `if (pdesk != NULL)` branch it sets
    // `pti->rpdesk = pdesk; pti->pDeskInfo = pti->rpdesk->pDeskInfo;` (desktop.c:3428/3430). We DO NOT
    // pre-seed those fields (doing so flips its own `if (pti->rpdesk != NULL)` class-migration branch,
    // desktop.c:3404, into an unmapped-desktop-heap fault) — we let win32k's real handler do the bind,
    // then READ BACK the fields it set and LATCH them (BOUND_DESK_*). The dispatch_loop then re-asserts
    // them before every subsequent dispatch, so a LATER `NtUserProcessConnect` (0x10FA) whose inner
    // IntSetThreadDesktop ELSE branch (desktop.c:3451-3453) NULLs `pti->pDeskInfo` can't leave the
    // thread disconnected before the next `NtUserGetClassInfo` (0x10bd) reads `[pti+0x80]` — the wall.
    if ssn == SSN_NT_USER_SET_THREAD_DESKTOP && ret != 0 {
        let pti = current_w32thread();
        let rpdesk = read_volatile((pti + THREADINFO_RPDESK_OFF) as *const u64);
        let pdeskinfo = read_volatile((pti + THREADINFO_PDESKINFO_OFF) as *const u64);
        if rpdesk != 0 && pdeskinfo != 0 {
            BOUND_DESK_BODY = rpdesk;
            BOUND_DESK_PDESKINFO = pdeskinfo;
            // Ensure the bound DESKTOP has a NON-NULL `pheapDesktop` (DESKTOP+0x80, desktop.h). The class
            // call-proc path `UserGetCPD → CreateCallProc → DesktopHeapAlloc` (callproc.c:143,
            // object.c:103) does `RtlAllocateHeap(pdesk->pheapDesktop, ...)` — and our win32k
            // `RtlAllocateHeap` import is bound to `s_rtl_allocate_heap`, which IGNORES the handle and
            // bumps the shared session arena, so the handle only needs to be non-NULL to avoid the
            // `mov rcx,[pdesk+0x80]; call RtlAllocateHeap(NULL,...)` NULL-handle path. (This is the REAL
            // deref at RVA 0x4f5e3 — `Desktop->pheapDesktop`, NOT `pti->pDeskInfo`; see the corrected
            // comment at THREADINFO_PDESKINFO_OFF.)
            if read_volatile((rpdesk + DESKTOP_PHEAP_OFF) as *const u64) == 0 {
                write_volatile((rpdesk + DESKTOP_PHEAP_OFF) as *mut u64, WIN32K_HEAP_HANDLE);
            }
            print_str(b"[win32k-host] NtUserSetThreadDesktop latched: pti->rpdesk=0x");
            print_hex((rpdesk >> 32) as u32);
            print_hex(rpdesk as u32);
            print_str(b" pti->pDeskInfo=0x");
            print_hex((pdeskinfo >> 32) as u32);
            print_hex(pdeskinfo as u32);
            print_str(b" pheapDesktop=0x");
            print_hex(read_volatile((rpdesk + DESKTOP_PHEAP_OFF) as *const u64) as u32);
            print_str(b"\n");
        }
    }
    ret
}

/// The retired inline `send_done`/`recv_req`/`dispatch_loop` (win32k's bespoke Send/Recv handshake +
/// per-request loop) are now the SHARED harness's implementation (one `call_on` per dispatch in
/// `component_main`'s loop). win32k's per-dispatch body lives in [`win32k_dispatch`]
/// and its context seed in [`setup_dispatch_context`] (called from `win32k_post_driver_entry`).
///
/// Build the "current process/thread" context win32k's INLINED accessors read during a dispatch —
/// distinct from the bring-up attach phase (which is happy with a zeroed KPCR: its optional
/// environment getter early-returns STATUS_NOT_FOUND when `gs:[0x30]==0`). During a routed dispatch,
/// Most of the existing bootstrap path models process/session queries through `gs:[0x30]` pointing
/// at this KPCR placeholder. The per-request dispatch substitutes a real client TEB only for the
/// window-station/desktop capture handlers that call NtCurrentTeb. Model the bootstrap EPROCESS
/// chain against the same fake EPROCESS the import trampoline returns:
///   EPROCESS[+0x20] = Q (non-null, else the env getter faults — it has no NULL check there);
///   Q[+0x80] = an empty wide string (first WCHAR 0 → getter returns cleanly).
/// The bootstrap context is still used before the first routed dispatch. Once requests arrive,
/// [`select_win32k_client_context`] selects PID/TID-keyed EPROCESS/ETHREAD/W32PROCESS/W32THREAD
/// bodies.
unsafe fn setup_dispatch_context() {
    let _ = ensure_bootstrap_win32k_context();
    let eprocess = current_eprocess();
    let ethread = current_ethread();
    write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, WIN32K_KPCR_VA); // bootstrap compatibility context
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, ethread);
    initialize_eprocess_body(eprocess, FAKE_PROCESS_HANDLE);

    // win32k's IntCbAllocateMemory (callback.c:44) does
    // `InsertTailList(&W32Thread->W32CallbackListHead, &Mem->ListEntry)` in the desktop-init callback
    // tail (co_IntSetWndIcons). Real win32k initializes this in InitThreadCallback (main.c:497
    // `InitializeListHead(&ptiCurrent->W32CallbackListHead)`). Offset confirmed by disasm of
    // IntCbAllocateMemory (RVA 0x4aa86: `add rcx, 0x2e8; call InsertTailList`). Keep the real
    // callout-owned THREADINFO's list heads complete before the bootstrap connect path runs.
    let w32thread = current_w32thread();
    if w32thread == 0 {
        print_str(b"[win32k-host] ERROR: no callout-owned W32THREAD for dispatch setup\n");
        return;
    }
    init_threadinfo_placeholder(w32thread);

    let _ = bind_desktop_thread_to_current_context(false, b"bootstrap");
}

/// Stand up `gptiDesktopThread` from the currently selected dynamic GUI context.
///
/// Real ReactOS assigns this in `DesktopThreadMain`
/// (`gptiDesktopThread = PsGetCurrentThreadWin32Thread()`) before registering system classes. The
/// selected THREADINFO and selected PROCESSINFO must match: `UserRegisterSystemClasses()` registers
/// classes on `GetW32ProcessInfo()`, while `IntGetAndReferenceClass(..., bDesktopThread=TRUE)` later
/// searches `gptiDesktopThread->ppi`. Keeping those two identities aligned is what lets
/// `IntCreateDesktop` find `WC_DESKTOP` and `ICLS_HWNDMESSAGE` after process identity becomes dynamic.
unsafe fn bind_desktop_thread_to_current_context(replace_existing: bool, reason: &[u8]) -> bool {
    let ppi = read_volatile(SLOT_W32PROCESS as *const u64);
    let pti = current_w32thread();
    if ppi == 0 || pti == 0 {
        print_str(b"[win32k-host] ERROR: cannot bind desktop thread for ");
        print_str(reason);
        print_str(b"\n");
        return false;
    }

    let gpti_cell = (WIN32K_CODE_VA + GPTI_DESKTOP_THREAD_RVA) as *mut u64;
    let current = read_volatile(gpti_cell);
    if current != 0 && current != pti && !replace_existing {
        return true;
    }

    write_volatile((pti + THREADINFO_PPI_OFF) as *mut u64, ppi);
    init_threadinfo_placeholder(pti);

    // Link the dispatch thread into `ppi->ptiList` (PROCESSINFO+0xD8, disasm-confirmed:
    // CreateCallProc RVA 0x4dc92 `mov r8,[pi+0xd8]`). Real win32k links each thread here in
    // thread-init (IntLinkThreadInfo / CreateThreadInfo). Our hosted desktop work runs on the current
    // dispatch W32THREAD, so the process list must contain that THREADINFO before class/window objects
    // allocate owner records.
    if read_volatile((ppi + PROCESSINFO_PTILIST_OFF) as *const u64) == 0 {
        write_volatile((ppi + PROCESSINFO_PTILIST_OFF) as *mut u64, pti);
    }
    if read_volatile((ppi + PROCESSINFO_PTIMAINTHREAD_OFF) as *const u64) == 0 {
        write_volatile((ppi + PROCESSINFO_PTIMAINTHREAD_OFF) as *mut u64, pti);
    }

    if current != pti {
        write_volatile(gpti_cell, pti);
        print_str(b"[win32k-host] gptiDesktopThread = current thread (");
        print_str(reason);
        print_str(b" ppi=0x");
        print_hex((ppi >> 32) as u32);
        print_hex(ppi as u32);
        print_str(b" pti=0x");
        print_hex((pti >> 32) as u32);
        print_hex(pti as u32);
        print_str(b")\n");
    }
    true
}

/// Initialize the thread-list heads + `pClientInfo` a win32k THREADINFO needs before it can host
/// window/callback linking. Both the dispatch thread and the desktop thread (`gptiDesktopThread`) run
/// through window-manager code that operates on these fields; our zeroed placeholders leave them NULL.
/// Offsets (checked build, confirmed by disasm):
///   +0x2d8 WindowListHead     — `InsertTailList(&pti->WindowListHead,…)` IntCreateWindow window.c:2142
///   +0x2e8 W32CallbackListHead — `InsertTailList(&pti->W32CallbackListHead,…)` IntCbAllocateMemory
///   +0x148 PtiLink             — membership in the current DESKTOP.PtiList
///   +0x88  pClientInfo         — `pti->pClientInfo->dwTIFlags = …` IntCreateDesktop
/// Real win32k `InitializeListHead`s the lists in CreateThreadInfo (main.c) and points pClientInfo at
/// the thread's CLIENTINFO. `pool_alloc` returns zeroed memory, so an already-initialized field is
/// left as-is.
unsafe fn init_threadinfo_placeholder(w32thread: u64) {
    sync_threadinfo_process(w32thread);
    // THREADINFO LIST_ENTRY heads the window-manager / paint path touches (offsets from win32.h,
    // W32THREAD prefix = 0x50; anchored to the confirmed +0x88 pClientInfo / +0x90 TIF_flags):
    //   +0xB0  SentMessagesListHead   (message.c / co_MsqSendMessage)
    //   +0x2d8 WindowListHead         (IntCreateWindow window.c:2142)
    //   +0x2e8 W32CallbackListHead    (IntCbAllocateMemory callback.c)
    //   +0x148 PtiLink                (IntSetThreadDesktop desktop.c:3463/3471)
    //   +0x188 PostedMessagesListHead — `InsertTailList(&pti->PostedMessagesListHead,…)` MsqPostMessage
    //          (msgqueue.c:1369). NtUserPostMessage(SAS window, WLX_WM_SAS) posts here; a NULL (zeroed)
    //          list head → InsertTailList derefs head->Blink (offset +8) → null-deref at cr2=0x8.
    //          Offset computed from the SentMessagesListHead@0xB0 anchor per win32.h THREADINFO layout.
    for off in [0xB0u64, THREADINFO_PTI_LINK_OFF, 0x188, 0x2d8, 0x2e8] {
        let head = w32thread + off;
        ensure_list_head_initialized(head);
    }
    if read_volatile((w32thread + 0x88) as *const u64) == 0 {
        let ci = pool_alloc(0x100);
        if ci != 0 {
            write_volatile((w32thread + 0x88) as *mut u64, ci);
        }
    }
    // MessageQueue (THREADINFO+0x60): the paint/window-position path references the window's thread
    // and reads `pti->MessageQueue->QF_flags` (USER_MESSAGE_QUEUE+0xAC) — a NULL queue null-derefs in
    // painting.c (RVA 0xb6a55). Real win32k creates this in CreateThreadInfo -> MsqCreateMessageQueue
    // and then MsqInitializeMessageQueue seeds the hardware-message list, ptiMouse/ptiKeyboard, and
    // cThreads. Hosted THREADINFO placeholders need the same fields because later queue wake/paint
    // paths are shared with normal win32k execution.
    let mut mq = read_volatile((w32thread + 0x60) as *const u64);
    if mq == 0 {
        let mq = pool_alloc(0x200); // USER_MESSAGE_QUEUE (~0xC0 + CaretInfo), zeroed
        if mq != 0 {
            write_volatile(mq as *mut u32, 1); // References = 1
            write_volatile((w32thread + 0x60) as *mut u64, mq);
        }
    }
    mq = read_volatile((w32thread + 0x60) as *const u64);
    if mq != 0 {
        if read_volatile(mq as *const u32) == 0 {
            write_volatile(mq as *mut u32, 1);
        }
        let hw = mq + USER_MESSAGE_QUEUE_HARDWARE_MESSAGES_OFF;
        ensure_list_head_initialized(hw);
        if read_volatile((mq + USER_MESSAGE_QUEUE_PTI_MOUSE_OFF) as *const u64) == 0 {
            write_volatile((mq + USER_MESSAGE_QUEUE_PTI_MOUSE_OFF) as *mut u64, w32thread);
        }
        if read_volatile((mq + USER_MESSAGE_QUEUE_PTI_KEYBOARD_OFF) as *const u64) == 0 {
            write_volatile((mq + USER_MESSAGE_QUEUE_PTI_KEYBOARD_OFF) as *mut u64, w32thread);
        }
        if read_volatile((mq + USER_MESSAGE_QUEUE_CTHREADS_OFF) as *const u32) == 0 {
            write_volatile((mq + USER_MESSAGE_QUEUE_CTHREADS_OFF) as *mut u32, 1);
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
    // hEventQueueClient / pEventQueueServer: user32's MsgWaitForMultipleObjectsEx asks win32k for
    // this handle via NtUserxMsqSetWakeMask, and ReactOS signals the server KEVENT when queue bits
    // change. A hosted THREADINFO without these fields can still survive direct PeekMessage calls, but
    // it cannot participate in the real wait/wake path explorer uses while bringing up the desktop.
    ensure_thread_queue_event(w32thread);
}

unsafe fn initialize_list_head(head: u64) {
    write_volatile(head as *mut u64, head);
    write_volatile((head + 8) as *mut u64, head);
}

unsafe fn ensure_list_head_initialized(head: u64) {
    let flink = read_volatile(head as *const u64);
    let blink = read_volatile((head + 8) as *const u64);
    if flink == 0 || blink == 0 {
        initialize_list_head(head);
    }
}

unsafe fn sync_threadinfo_process(w32thread: u64) {
    if w32thread == 0 {
        return;
    }
    let ppi = read_volatile(SLOT_W32PROCESS as *const u64);
    if ppi == 0 {
        return;
    }
    let slot = (w32thread + THREADINFO_PPI_OFF) as *mut u64;
    if read_volatile(slot) != ppi {
        write_volatile(slot, ppi);
    }
    let pti_list = (ppi + PROCESSINFO_PTILIST_OFF) as *mut u64;
    if read_volatile(pti_list) == 0 {
        write_volatile(pti_list, w32thread);
    }
    let pti_main = (ppi + PROCESSINFO_PTIMAINTHREAD_OFF) as *mut u64;
    if read_volatile(pti_main) == 0 {
        write_volatile(pti_main, w32thread);
    }
}

unsafe fn prepare_set_thread_desktop(hdesk: u64) {
    seed_process_startup_desktop(hdesk);
    if hdesk == 0 {
        return;
    }
    let pti = current_w32thread();
    if pti == 0 {
        return;
    }

    let old_rpdesk = read_volatile((pti + THREADINFO_RPDESK_OFF) as *const u64);
    let old_pdeskinfo = read_volatile((pti + THREADINFO_PDESKINFO_OFF) as *const u64);
    let old_hdesk = read_volatile((pti + THREADINFO_HDESK_OFF) as *const u64);
    let requested_rpdesk = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk);
    if requested_rpdesk != 0 && requested_rpdesk == old_rpdesk {
        return;
    }
    if old_rpdesk == 0 && old_pdeskinfo == 0 && old_hdesk == 0 {
        ensure_list_head_initialized(pti + THREADINFO_PTI_LINK_OFF);
        return;
    }

    if !unlink_thread_from_desktop(pti as *mut u8) {
        let n = WIN32K_SET_THREAD_DESKTOP_PREPARES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            let flink = read_volatile((pti + THREADINFO_PTI_LINK_OFF) as *const u64);
            let blink = read_volatile((pti + THREADINFO_PTI_LINK_OFF + 8) as *const u64);
            print_str(b"[win32k-host] ERROR: cannot clear corrupt desktop membership pti=0x");
            print_hex((pti >> 32) as u32);
            print_hex(pti as u32);
            print_str(b" flink=0x");
            print_hex((flink >> 32) as u32);
            print_hex(flink as u32);
            print_str(b" blink=0x");
            print_hex((blink >> 32) as u32);
            print_hex(blink as u32);
            print_str(b"\n");
        }
        return;
    }

    write_volatile((pti + THREADINFO_RPDESK_OFF) as *mut u64, 0);
    write_volatile((pti + THREADINFO_PDESKINFO_OFF) as *mut u64, 0);
    write_volatile((pti + THREADINFO_HDESK_OFF) as *mut u64, 0);

    let n = WIN32K_SET_THREAD_DESKTOP_PREPARES.fetch_add(1, Ordering::Relaxed);
    if n < 16 {
        print_str(b"[win32k-host] pre-SetThreadDesktop cleared old binding pti=0x");
        print_hex((pti >> 32) as u32);
        print_hex(pti as u32);
        print_str(b" old-rpdesk=0x");
        print_hex((old_rpdesk >> 32) as u32);
        print_hex(old_rpdesk as u32);
        print_str(b" old-pdeskinfo=0x");
        print_hex((old_pdeskinfo >> 32) as u32);
        print_hex(old_pdeskinfo as u32);
        print_str(b" old-hdesk=0x");
        print_hex(old_hdesk as u32);
        print_str(b"\n");
    }
}

unsafe fn seed_process_startup_desktop(hdesk: u64) {
    if hdesk == 0 {
        return;
    }
    let ppi = current_w32process();
    if ppi == 0 {
        return;
    }
    let desk_body = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk);
    if desk_body == 0 {
        return;
    }
    let _ = seed_process_startup_desktop_for_process(ppi, hdesk, desk_body, current_w32thread());
}

unsafe fn seed_process_startup_desktop_for_process(
    ppi: u64,
    hdesk: u64,
    desk_body: u64,
    pti: u64,
) -> bool {
    if ppi == 0 || hdesk == 0 || desk_body == 0 {
        return false;
    }
    if read_volatile((ppi + PROCESSINFO_RPDESK_STARTUP_OFF) as *const u64) != 0
        || read_volatile((ppi + PROCESSINFO_HDESK_STARTUP_OFF) as *const u64) != 0
    {
        return false;
    }
    let winsta_body = (*core::ptr::addr_of!(OBJ_TABLE)).cached_winsta_body();
    if winsta_body != 0
        && read_volatile((desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *const u64) == 0
    {
        write_volatile(
            (desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *mut u64,
            winsta_body,
        );
    }
    if read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64) == 0 {
        write_volatile(
            (desk_body + DESKTOP_PHEAP_OFF) as *mut u64,
            WIN32K_HEAP_HANDLE,
        );
    }
    write_volatile((ppi + PROCESSINFO_HDESK_STARTUP_OFF) as *mut u64, hdesk);
    write_volatile(
        (ppi + PROCESSINFO_RPDESK_STARTUP_OFF) as *mut u64,
        desk_body,
    );
    if pti != 0 && read_volatile((ppi + PROCESSINFO_PTIMAINTHREAD_OFF) as *const u64) == 0 {
        write_volatile((ppi + PROCESSINFO_PTIMAINTHREAD_OFF) as *mut u64, pti);
    }
    let n = WIN32K_STARTUP_DESKTOP_SEEDS.fetch_add(1, Ordering::Relaxed);
    if n < 16 {
        print_str(b"[win32k-host] startup desktop seeded hDesk=0x");
        print_hex(hdesk as u32);
        print_str(b" ppi=0x");
        print_hex((ppi >> 32) as u32);
        print_hex(ppi as u32);
        print_str(b" rpdeskStartup=0x");
        print_hex((desk_body >> 32) as u32);
        print_hex(desk_body as u32);
        print_str(b"\n");
    }
    true
}

unsafe fn hwnd_to_pwnd(hwnd: u64) -> u64 {
    let ahelist = read_volatile((WIN32K_SHARED_VADDR + SH_SAS_AHELIST) as *const u64);
    if ahelist == 0 || (hwnd & 0xffff) < 0x20 {
        return 0;
    }
    let handles = read_volatile(ahelist as *const u64);
    let nb = read_volatile((ahelist + 0x10) as *const u32) as u64;
    let index = ((hwnd & 0xffff) - 0x20) >> 1;
    if handles == 0 || index >= nb {
        return 0;
    }
    let entry = handles + index * 0x18;
    if read_volatile((entry + 0x10) as *const u8) == 1
        && read_volatile((entry + 0x12) as *const u16) == (hwnd >> 16) as u16
    {
        read_volatile(entry as *const u64)
    } else {
        0
    }
}

/// Load the staged system font (arial.ttf at [`FONTBUF_VADDR`]) into win32k via
/// `IntGdiAddFontMemResource`, so the desktop-graphics font realize (TextIntRealizeFont) finds a
/// real font instead of null-derefing at RVA 0x4d7eb ("no fonts loaded at all"). Runs once, after
/// the dispatch context is established (win32k's font code reads gs:/current-process).
///
/// The FTYP arena has its own free list, so the per-client FreeType probe churn should leave room
/// for `FT_New_Memory_Face` to parse the staged system font instead of hitting arena OOM.
unsafe fn load_system_font_for_client(pi: usize) {
    if pi >= 64 {
        return;
    }
    let bit = 1u64 << pi;
    if WIN32K_CLIENT_SYSTEM_FONT_SEEDS.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return;
    }
    print_str(b"[win32k-host] seeding private system font for pi=");
    print_u64(pi as u64);
    print_str(b"\n");
    if load_system_font() {
        WIN32K_CLIENT_SYSTEM_FONT_SUCCESSES.fetch_or(bit, Ordering::Relaxed);
    } else {
        WIN32K_CLIENT_SYSTEM_FONT_FAILURES.fetch_or(bit, Ordering::Relaxed);
    }
}

unsafe fn load_system_font() -> bool {
    let size = read_volatile((WIN32K_SHARED_VADDR + SH_FONT_SIZE) as *const u32) as u64;
    if size == 0 {
        print_str(b"[win32k-host] no system font staged - font realize will fail\n");
        return false;
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
    handle != 0 && num_added != 0
}

pub(crate) fn client_system_font_proofs() -> (u64, u64, u64) {
    (
        WIN32K_CLIENT_SYSTEM_FONT_SEEDS.load(Ordering::Relaxed),
        WIN32K_CLIENT_SYSTEM_FONT_SUCCESSES.load(Ordering::Relaxed),
        WIN32K_CLIENT_SYSTEM_FONT_FAILURES.load(Ordering::Relaxed),
    )
}

pub(crate) fn explorer_setwndproc_proofs() -> (u64, u64) {
    (
        WIN32K_EXPLORER_SETWNDPROC_CLIENT_CALLS.load(Ordering::Relaxed),
        WIN32K_EXPLORER_SETWNDPROC_REPLAY_CALLS.load(Ordering::Relaxed),
    )
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
    if !bind_desktop_thread_to_current_context(true, b"default-desktop") {
        return;
    }

    // "WinSta0"
    let winsta_name = [0x57u16, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x30];
    let oa_ws = build_object_attributes(&winsta_name);
    print_str(b"[win32k-host] NtUserCreateWindowStation(WinSta0)...\n");
    let cws: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64) -> u64 =
        core::mem::transmute((WIN32K_CODE_VA + NT_USER_CREATE_WINDOW_STATION_RVA) as *const ());
    let hws = cws(oa_ws, MAXIMUM_ALLOWED, 0, 0, 0, 0, 0);
    print_str(b"[win32k-host] NtUserCreateWindowStation -> hWinSta=0x");
    print_hex((hws >> 32) as u32);
    print_hex(hws as u32);
    print_str(b" (winsta body=0x");
    print_hex((*core::ptr::addr_of!(OBJ_TABLE)).cached_winsta_body() as u32);
    print_str(b")\n");

    // Follow winlogon's real ordering: CreateWindowStation -> SetProcessWindowStation ->
    // CreateDesktop. The setter validates the real object handle, duplicates its EPROCESS cache
    // handle, and fills PROCESSINFO::{prpwinsta,hwinsta,amwinsta,W32PF_flags} inside win32k.
    let ssdt = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *const u64);
    if ssdt == 0 || hws == 0 {
        print_str(b"[win32k-host] ERROR: cannot associate WinSta0 with current process\n");
        return;
    }
    let set_winsta_handler = read_volatile(
        (ssdt + (SSN_NT_USER_SET_PROCESS_WINDOW_STATION - WIN32K_SERVICE_BASE) * 8) as *const u64,
    );
    if set_winsta_handler == 0 {
        print_str(b"[win32k-host] ERROR: cannot associate WinSta0 with current process\n");
        return;
    }
    let set_winsta: extern "win64" fn(u64) -> i32 =
        core::mem::transmute(set_winsta_handler as *const ());
    let set_winsta_ret = set_winsta(hws);
    print_str(b"[win32k-host] NtUserSetProcessWindowStation -> ret=0x");
    print_hex(set_winsta_ret as u32);
    print_str(b" cache=0x");
    let cached_winsta = s_ps_get_process_winsta(current_eprocess());
    print_hex(cached_winsta as u32);
    print_str(b"\n");
    if set_winsta_ret == 0 || cached_winsta == 0 {
        print_str(b"[win32k-host] ERROR: NtUserSetProcessWindowStation failed\n");
        return;
    }

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
        write_volatile(
            (desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *mut u64,
            winsta_body,
        );
        // (2) the interactive InputWindowStation global = the same window station.
        write_volatile(
            (WIN32K_CODE_VA + INPUT_WINDOW_STATION_RVA) as *mut u64,
            winsta_body,
        );

        print_str(
            b"[win32k-host] NtUserSwitchDesktop(hDesk) [rpwinstaParent+InputWindowStation set]\n",
        );
        let switch: extern "win64" fn(u64) -> i32 =
            core::mem::transmute((WIN32K_CODE_VA + NT_USER_SWITCH_DESKTOP_RVA) as *const ());
        let sret = switch(hdesk);
        let gpdesk = read_volatile((WIN32K_CODE_VA + GPDESK_INPUT_DESKTOP_RVA) as *const u64);
        if sret != 0 && gpdesk == desk_body {
            publish_default_desktop(hdesk, desk_body, b"bootstrap");
        }
        print_str(b"[win32k-host] NtUserSwitchDesktop -> ret=0x");
        print_hex(sret as u32);
        print_str(b", gpdeskInputDesktop=0x");
        print_hex((gpdesk >> 32) as u32);
        print_hex(gpdesk as u32);
        print_str(b" (spwnd=0x");
        // pDeskInfo @ body+0x08; DESKTOPINFO.spwnd @ +0x10 (pvDesktopBase@0, pvDesktopLimit@8, spwnd@0x10
        // — confirmed by co_IntShowDesktop disasm 0x6dc5c `mov rax,[rax+8]`; 0x6dc60 `mov rax,[rax+0x10]`).
        let pdeskinfo = if gpdesk != 0 {
            read_volatile((gpdesk + 0x08) as *const u64)
        } else {
            0
        };
        let spwnd = if pdeskinfo != 0 {
            read_volatile((pdeskinfo + 0x10) as *const u64)
        } else {
            0
        };
        print_hex((spwnd >> 32) as u32);
        print_hex(spwnd as u32);
        print_str(b")\n");

        // ★ BIND THE DISPATCH THREAD TO THE DESKTOP — the REAL `IntSetThreadDesktop` connection.
        //
        // The switch above sets the GLOBAL `gpdeskInputDesktop`, but does NOT connect the CURRENT
        // thread's win32k `THREADINFO` (`pti`) to the desktop. In real Windows that connection is done
        // by winlogon's `SetThreadDesktop(Default) → NtUserSetThreadDesktop → IntSetThreadDesktop`
        // (desktop.c:3428/3430), whose core is exactly:
        //     pti->rpdesk    = pdesk;                    // desktop.c:3428
        //     pti->pDeskInfo = pti->rpdesk->pDeskInfo;   // desktop.c:3430
        //     pci->pDeskInfo = pti->pDeskInfo - ulClientDelta;   // desktop.c:3434 (delta 0 in-host)
        // Our host merges winlogon's interactive thread onto the single shared dispatch W32THREAD
        // (`SLOT_W32THREAD`), and winlogon's own NtUserSetThreadDesktop can't drive the real
        // IntSetThreadDesktop body end-to-end (it needs the desktop-heap view / pcti alloc our host
        // doesn't map). So we perform the SAME two field assignments here, directly on the dispatch
        // W32THREAD, using the REAL created DESKTOP body + its real `pDeskInfo` (DESKTOP+0x08). This is
        // the thread↔desktop connection win32k's checked `NtUserGetClassInfo` helper asserts on:
        // `mov rcx,[pti+0x80]` (pti->pDeskInfo) — NULL before this, a real DESKTOPINFO after.
        let pti = current_w32thread();
        let desk_pdeskinfo = read_volatile((desk_body + 0x08) as *const u64); // DESKTOP.pDeskInfo
        let pti_link = pti + THREADINFO_PTI_LINK_OFF;
        let link_flink = read_volatile(pti_link as *const u64);
        let link_blink = read_volatile((pti_link + 8) as *const u64);
        if (link_flink != 0 || link_blink != 0) && !unlink_thread_from_desktop(pti as *mut u8) {
            print_str(b"[win32k-host] WARN: failed to unlink old desktop membership before Default bind\n");
        }
        if !link_thread_to_desktop(desk_body as *mut u8, pti as *mut u8) {
            print_str(b"[win32k-host] WARN: failed to link dispatch thread into Default desktop\n");
        }
        write_volatile((pti + THREADINFO_RPDESK_OFF) as *mut u64, desk_body); // pti->rpdesk = pdesk
        write_volatile((pti + THREADINFO_PDESKINFO_OFF) as *mut u64, desk_pdeskinfo); // = rpdesk->pDeskInfo
                                                                                      // Latch for per-dispatch re-assertion (see BOUND_DESK_* + dispatch_loop top).
        BOUND_DESK_BODY = desk_body;
        BOUND_DESK_PDESKINFO = desk_pdeskinfo;
        // Mirror the client side (pci->pDeskInfo), ulClientDelta == 0 in our single-AS host.
        let pci = read_volatile((pti + THREADINFO_PCLIENTINFO_OFF) as *const u64);
        if pci != 0 {
            // CLIENTINFO.pDeskInfo @ +0x20 (ntuser.h: CI_flags@0, cSpins@8, dwExpWinVer@0x10,
            // dwCompatFlags@0x14, dwCompatFlags2@0x18, dwTIFlags@0x1C, pDeskInfo@0x20).
            write_volatile((pci + 0x20) as *mut u64, desk_pdeskinfo);
        }
        print_str(b"[win32k-host] IntSetThreadDesktop(Default): pti->rpdesk=0x");
        print_hex((desk_body >> 32) as u32);
        print_hex(desk_body as u32);
        print_str(b" pti->pDeskInfo=0x");
        print_hex((desk_pdeskinfo >> 32) as u32);
        print_hex(desk_pdeskinfo as u32);
        print_str(b"\n");
    } else {
        print_str(b"[win32k-host] WARN: no desktop/winsta body - gpdeskInputDesktop unset\n");
    }
}

/// Once-guard: the post-NtUserInitialize host-prerequisite seed (system font + WinSta0/Default Ob
/// objects) runs a single time. Single-threaded component → a plain `static mut` bool suffices.
static mut DESKTOP_GFX_SEEDED: bool = false;

/// The DESKTOP body + its DESKTOPINFO (`rpdesk->pDeskInfo`) the dispatch thread is bound to, latched
/// by `create_winsta_and_desktop`'s IntSetThreadDesktop-equivalent. Re-asserted onto the shared
/// dispatch W32THREAD at the top of every dispatch so an intervening win32k `IntSetThreadDesktop`
/// ELSE branch (which clears `pti->pDeskInfo` when it can't map the desktop-heap view — the exact
/// pre-BATCH-43 wall) can't leave the thread disconnected before the NEXT syscall body reads
/// `pti->pDeskInfo`. Zero until the seed runs.
static mut BOUND_DESK_BODY: u64 = 0;
static mut BOUND_DESK_PDESKINFO: u64 = 0;

// The persistent win32k dispatch loop is now `component_main`'s (Phase B Step 4b); its per-request
// body + context seed moved to [`win32k_dispatch`] / [`setup_dispatch_context`] (above). BOUND_DESK_*
// (latched by `create_winsta_and_desktop` / `dispatch_ssn`, re-asserted per dispatch in `win32k_dispatch`).

/// Give the EPROCESS placeholder the fields win32k's process callout asserts, invoke win32k's
/// process-create callout (WIN32_CALLOUTS[0]) to build the W32PROCESS authentically, then dispatch
/// NtUserProcessConnect(ProcessHandle, USERCONNECT buffer, 0x240) via the SSDT.
unsafe fn establish_client_and_dispatch() {
    let Some((process_index, thread_index)) = ensure_bootstrap_win32k_context() else {
        print_str(b"[win32k-host] ERROR: bootstrap GUI context allocation failed\n");
        return;
    };
    let eprocess = current_eprocess();

    // Resolve NtUserProcessConnect (SSN 0x10FA) through the registered SSDT FIRST (before the
    // fault-prone callout/connect below) so the routing-seam proof is recorded regardless.
    let ssdt_base = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *const u64);
    if ssdt_base == 0 {
        return;
    }
    let idx = SSN_NT_USER_INITIALIZE - WIN32K_SERVICE_BASE;
    let handler = read_volatile((ssdt_base + idx * 8) as *const u64);
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_NTUSER_HANDLER) as *mut u64,
        handler,
    );
    print_str(b"[win32k-host] SSDT resolve(0x10FA) -> handler=0x");
    print_hex((handler >> 32) as u32);
    print_hex(handler as u32);
    print_str(b"\n");
    if handler == 0 {
        return;
    }
    let v0 = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_NTUSER_RESOLVED;
    write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v0);

    // EPROCESS.Peb must be non-null (the callout ASSERTs it — an `int 0x2c` otherwise). Point it at a
    // small zeroed sub-region of the EPROCESS page.
    initialize_eprocess_body(eprocess, FAKE_PROCESS_HANDLE);

    // Invoke win32k's process-create callout: W32pProcessCallout(PEPROCESS, BOOLEAN Initialize=TRUE).
    let callout = read_volatile(WIN32_CALLOUTS as *const u64);
    print_str(b"[win32k-host] win32k process-create callout=0x");
    print_hex((callout >> 32) as u32);
    print_hex(callout as u32);
    print_str(b"\n");
    if callout != 0 {
        let mut v =
            read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_CALLOUT_ENTERED;
        write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
        let co: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(callout as *const ());
        let cstatus = co(eprocess, 1);
        v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32) | V_CALLOUT_RETURNED;
        write_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
        print_str(b"[win32k-host] process-create callout returned status=0x");
        print_hex(cstatus as u32);
        print_str(b" W32PROCESS=0x");
        let w32 = read_volatile(SLOT_W32PROCESS as *const u64);
        if w32 != 0 {
            WIN32K_PROCESS_CTX_W32PROCESS[process_index].store(w32, Ordering::Relaxed);
        }
        print_hex((w32 >> 32) as u32);
        print_hex(w32 as u32);
        print_str(b"\n");
    }
    if read_volatile(SLOT_W32PROCESS as *const u64) == 0 {
        print_str(b"[win32k-host] ERROR: bootstrap process callout did not publish W32PROCESS\n");
        return;
    }
    if !ensure_win32k_threadinfo(thread_index, 0) {
        print_str(b"[win32k-host] ERROR: bootstrap thread callout did not publish W32THREAD\n");
        return;
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
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_NTUSER_STATUS) as *mut i32,
        nstatus,
    );
    print_str(b"[win32k-host] NtUserProcessConnect(0x10FA) returned status=0x");
    print_hex(nstatus as u32);
    print_str(b"\n");
}

// --- win32k-adjacent driver hosting -----------------------------------------------------------
//
// win32k's InitializeGreCSRSS -> DxDdStartupDxGraphics loads dxg.sys via EngLoadImage ->
// LDEVOBJ_bLoadImage -> ZwSetSystemInformation(SystemLoadGdiDriverInformation). The executive
// (privileged) reads requested GDI/display/keyboard images by path into pool memory, maps them into
// win32k's VSpace, then the ZwSetSystemInformation trampoline reports the registered image to
// win32k. The same loader also resolves static win32k import DLLs discovered from win32k's own PE
// import table.

/// dxgthk.sys loaded-image base in win32k's VSpace (size_of_image 0x5000 -> 8 frames / one 2 MiB PT).
pub const DXGTHK_VA: u64 = 0x0000_0100_0850_0000;
pub const DXGTHK_LOAD_FRAMES: u64 = 8;
/// dxg.sys loaded-image base in win32k's VSpace (size_of_image 0xd000 -> 16 frames / one 2 MiB PT).
pub const DXG_VA: u64 = 0x0000_0100_0860_0000;
pub const DXG_LOAD_FRAMES: u64 = 16;
/// Display driver loaded-image base in win32k's VSpace. ReactOS' current registry selects the
/// linear-framebuffer driver, whose size_of_image is 0x8000, so this reserves one 8-frame PT window.
/// win32k loads the selected display DLL dynamically via ZwSetSystemInformation.
pub const FRAMEBUF_VA: u64 = 0x0000_0100_0890_0000;
pub const FRAMEBUF_LOAD_FRAMES: u64 = 8;
/// Keyboard layout DLL loaded-image base in win32k's VSpace. size_of_image 0x4000 -> 4 frames;
/// reserve 8 frames in its own PT-aligned window. win32k loads the registry-selected layout DLL via
/// ZwSetSystemInformation, then resolves KbdLayerDescriptor from its export directory.
pub const KEYBOARD_LAYOUT_VA: u64 = 0x0000_0100_08A0_0000;
pub const KEYBOARD_LAYOUT_LOAD_FRAMES: u64 = 8;
/// The BOOTBOOT framebuffer (Phase-0a fb device frames) mapped into win32k's VSpace, RW. The
/// executive video-device boundary returns this VA for `IOCTL_VIDEO_MAP_VIDEO_MEMORY`, so the
/// display driver writes pixels straight to the real framebuffer.
/// The size and mode are discovered from BootInfo in Phase 0a and carried in `DisplayRegistrySpec`.
pub const WIN32K_FB_VA: u64 = 0x0000_0100_0900_0000;

/// Record the loaded display DLL info selected from the SYSTEM hive. Some ReactOS display DLLs have
/// no export directory; win32k's `EngFindImageProcAddress("DrvEnableDriver")` can special-case to
/// `EntryPoint` (ldevobj.c), so ExportSectionPointer may be 0.
pub fn record_display_driver(
    spec: &DisplayRegistrySpec<'_>,
    entry_rva: u32,
    export_dir_rva: u32,
    image_len: u32,
) -> bool {
    let expd = if export_dir_rva != 0 {
        FRAMEBUF_VA + export_dir_rva as u64
    } else {
        0
    };
    register_gdi_driver_image(
        spec.display_driver_leaf,
        FRAMEBUF_VA,
        FRAMEBUF_VA + entry_rva as u64,
        expd,
        image_len,
    ) && register_display_device_route(spec)
}

/// Record the loaded keyboard-layout DLL info. win32k uses the export directory to find
/// KbdLayerDescriptor; the PE entry may be zero.
pub fn record_keyboard_layout_driver(
    _layout_id: &[u8],
    layout_file: &[u8],
    entry_rva: u32,
    export_dir_rva: u32,
    image_len: u32,
) -> bool {
    let expd = if export_dir_rva != 0 {
        KEYBOARD_LAYOUT_VA + export_dir_rva as u64
    } else {
        0
    };
    register_gdi_driver_image(
        layout_file,
        KEYBOARD_LAYOUT_VA,
        KEYBOARD_LAYOUT_VA + entry_rva as u64,
        expd,
        image_len,
    )
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
        if pe_c_string_eq_slice(np, name) {
            let ord = read_unaligned((ords + i * 2) as *const u16) as u64;
            let far = read_unaligned((funcs + ord * 4) as *const u32) as u64;
            if far >= exp_rva && far < exp_rva + exp_sz {
                // FORWARDER: the string at base+far is "Dll.Func". Route by target DLL:
                //   win32k.*   -> resolve Func against win32k's own exports (dxgthk/ftfd Eng* thunks)
                //   NTOSKRNL.* / HAL.* -> resolve Func via export_addr trampolines (win32k's own Eng*
                //                         exports that forward to ntoskrnl, e.g. EngMultiByteToUnicodeN
                //                         -> RtlMultiByteToUnicodeN, EngBugCheckEx -> KeBugCheckEx).
                let s = base + far;
                let forwarder_cap = exp_sz - (far - exp_rva);
                let mut dot = 0usize;
                let mut has_dot = false;
                while dot < forwarder_cap as usize {
                    let c = read_volatile((s + dot as u64) as *const u8);
                    if c == 0 {
                        break;
                    }
                    if c == b'.' {
                        has_dot = true;
                        break;
                    }
                    dot += 1;
                }
                if !has_dot || dot + 1 >= forwarder_cap as usize {
                    return 0;
                }
                let func_ptr = s + dot as u64 + 1;
                let mut fl = 0usize;
                while dot + 1 + fl < forwarder_cap as usize {
                    let c = read_volatile((func_ptr + fl as u64) as *const u8);
                    if c == 0 {
                        break;
                    }
                    fl += 1;
                }
                if fl == 0 || dot + 1 + fl >= forwarder_cap as usize {
                    return 0;
                }
                let func = core::slice::from_raw_parts(func_ptr as *const u8, fl);
                let is_win32k = dot >= 6
                    && read_volatile(s as *const u8).to_ascii_lowercase() == b'w'
                    && read_volatile((s + 1) as *const u8).to_ascii_lowercase() == b'i'
                    && read_volatile((s + 2) as *const u8).to_ascii_lowercase() == b'n'
                    && read_volatile((s + 3) as *const u8).to_ascii_lowercase() == b'3'
                    && read_volatile((s + 4) as *const u8).to_ascii_lowercase() == b'2'
                    && read_volatile((s + 5) as *const u8).to_ascii_lowercase() == b'k';
                if is_win32k {
                    return pe_export_lookup(WIN32K_CODE_VA, func);
                }
                // ntoskrnl / hal forwarder → trampoline.
                let name = core::str::from_utf8_unchecked(func);
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
    if cap == 0 || size_of_image == 0 || size_of_image as u64 > cap || size_of_headers > cap {
        return None;
    }

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
        let r = if chars & 0x2000_0000 != 0 {
            2u64
        } else {
            RW_NX
        };
        let span = va.saturating_add(vsize.max(raw_size)).min(cap);
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
        if reloc_rva != 0 && !image_rva_span_ok(reloc_rva, reloc_size, cap) {
            return None;
        }
        let mut off = 0u64;
        while reloc_rva != 0 && off + 8 <= reloc_size {
            let block_rva = reloc_rva + off;
            let page_rva = read_unaligned((dst_va + block_rva) as *const u32) as u64;
            let block = read_unaligned((dst_va + block_rva + 4) as *const u32) as u64;
            if block < 8 || block > reloc_size - off {
                return None;
            }
            let cnt = (block - 8) / 2;
            for i in 0..cnt {
                let ent = read_unaligned((dst_va + block_rva + 8 + i * 2) as *const u16);
                if (ent >> 12) == 10 {
                    let t = page_rva + (ent & 0xFFF) as u64;
                    if image_rva_span_ok(t, 8, cap) {
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
        let imp_size = read_unaligned((opt + 112 + 8 + 4) as *const u32) as u64;
        if !image_rva_span_ok(imp_rva, imp_size, cap) {
            return None;
        }
        let imp_end = imp_rva + imp_size;
        let mut desc_rva = imp_rva;
        while desc_rva + 20 <= imp_end {
            let desc = dst_va + desc_rva;
            let ilt = read_unaligned(desc as *const u32) as u64;
            let iat = read_unaligned((desc + 16) as *const u32) as u64;
            let dll_name_rva = read_unaligned((desc + 12) as *const u32) as u64;
            if ilt == 0 && iat == 0 {
                break;
            }
            let is_dxgthk = dll_name_rva != 0
                && image_c_string_has_prefix_ignore_case(dst_va, dll_name_rva, cap, 31, b"dxgthk");
            // ftfd.dll imports its 8 Eng*/Rtl thunks from win32k.sys — resolve against win32k's
            // own export table (real Eng* code + forwarders to ntoskrnl handled by pe_export_lookup).
            let is_win32k = dll_name_rva != 0
                && image_c_string_has_prefix_ignore_case(dst_va, dll_name_rva, cap, 31, b"win32k");
            let thunk_rva = if ilt != 0 { ilt } else { iat };
            if !image_rva_span_ok(thunk_rva, 8, cap) || !image_rva_span_ok(iat, 8, cap) {
                return None;
            }
            let names = dst_va + thunk_rva;
            let slots = dst_va + iat;
            let mut k = 0u64;
            let thunk_cap = ((cap - thunk_rva) / 8).min((cap - iat) / 8);
            let mut terminated = false;
            while k < thunk_cap {
                let thunk = read_unaligned((names + k * 8) as *const u64);
                if thunk == 0 {
                    terminated = true;
                    break;
                }
                if thunk & 0x8000_0000_0000_0000 == 0 {
                    let name_rva = thunk & 0x7FFF_FFFF;
                    if !image_rva_span_ok(name_rva, 2, cap) {
                        return None;
                    }
                    let name_ptr = dst_va + name_rva + 2;
                    let cstr_len = image_c_string_len(dst_va, name_rva + 2, cap, 63)?;
                    let import_name = core::slice::from_raw_parts(name_ptr as *const u8, cstr_len);
                    let addr = if is_dxgthk && dxgthk_base != 0 {
                        pe_export_lookup(dxgthk_base, import_name)
                    } else if is_win32k {
                        pe_export_lookup(WIN32K_CODE_VA, import_name)
                    } else {
                        let name = core::str::from_utf8_unchecked(import_name);
                        export_addr(name)
                    };
                    write_unaligned((slots + k * 8) as *mut u64, addr);
                }
                k += 1;
            }
            if !terminated {
                return None;
            }
            desc_rva += 20;
        }
    }

    Some((entry_rva, export_dir_rva, size_of_image))
}

/// Record the loaded dxg.sys info for the ZwSetSystemInformation trampoline. Called by the executive
/// after `load_driver_into(dxg)`.
pub fn record_dxg(entry_rva: u32, export_dir_rva: u32, image_len: u32) {
    let expd = if export_dir_rva != 0 {
        DXG_VA + export_dir_rva as u64
    } else {
        0
    };
    let _ = register_gdi_driver_image(
        b"dxg.sys",
        DXG_VA,
        DXG_VA + entry_rva as u64,
        expd,
        image_len,
    );
}

/// Return the Nth non-native static dependency imported by win32k. Native imports (`ntoskrnl.*` and
/// `hal.*`) are bound by the normal trampoline registry during `load_into`; every other DLL must be
/// backed by a real System32 image before win32k can call it.
pub unsafe fn win32k_static_import_dependency(index: usize, out: &mut [u8]) -> Option<usize> {
    let code_va = WIN32K_CODE_VA;
    let e = read_unaligned((code_va + 0x3c) as *const u32) as u64;
    let opt = code_va + e + 4 + 20;
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva == 0 {
        return None;
    }
    let imp_size = read_unaligned((opt + 112 + 8 + 4) as *const u32) as u64;
    if !image_rva_span_ok(imp_rva, imp_size, WIN32K_IMAGE_BYTES) {
        return None;
    }
    let imp_end = imp_rva + imp_size;
    let mut seen = 0usize;
    let mut desc_rva = imp_rva;
    while desc_rva + 20 <= imp_end {
        let desc = code_va + desc_rva;
        let ilt = read_unaligned(desc as *const u32) as u64;
        let iat = read_unaligned((desc + 16) as *const u32) as u64;
        if ilt == 0 && iat == 0 {
            break;
        }
        let dll_name_rva = read_unaligned((desc + 12) as *const u32) as u64;
        if dll_name_rva != 0 {
            if let Some(dn) = image_c_string_len(code_va, dll_name_rva, WIN32K_IMAGE_BYTES, 31) {
                if image_c_string_is_safe(code_va, dll_name_rva, dn)
                    && !image_c_string_is_native_import(code_va, dll_name_rva, dn)
                {
                    if seen == index {
                        if dn > out.len() {
                            return None;
                        }
                        let mut n = 0usize;
                        while n < dn {
                            out[n] =
                                read_volatile((code_va + dll_name_rva + n as u64) as *const u8)
                                    .to_ascii_lowercase();
                            n += 1;
                        }
                        return Some(dn);
                    }
                    seen += 1;
                }
            }
        }
        desc_rva += 20;
    }
    None
}

/// Re-patch win32k's OWN IAT for a loaded static import DLL. Runs in the EXECUTIVE while win32k's
/// frames are still mapped writable at [`WIN32K_CODE_VA`]. `load_into` initially resolved non-native
/// imports to visible benign stubs because the dependency image was not loaded yet; this points the
/// import slots at real exports from the loaded dependency. Returns the number of slots patched.
pub unsafe fn patch_win32k_static_import(dll_name: &[u8], dll_base: u64) -> u32 {
    if !import_dll_name_is_safe(dll_name) || dll_base == 0 {
        return 0;
    }
    let code_va = WIN32K_CODE_VA;
    let e = read_unaligned((code_va + 0x3c) as *const u32) as u64;
    let opt = code_va + e + 4 + 20;
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva == 0 {
        return 0;
    }
    let imp_size = read_unaligned((opt + 112 + 8 + 4) as *const u32) as u64;
    if !image_rva_span_ok(imp_rva, imp_size, WIN32K_IMAGE_BYTES) {
        return 0;
    }
    let imp_end = imp_rva + imp_size;
    let mut patched = 0u32;
    let mut desc_rva = imp_rva;
    while desc_rva + 20 <= imp_end {
        let desc = code_va + desc_rva;
        let ilt = read_unaligned(desc as *const u32) as u64;
        let iat = read_unaligned((desc + 16) as *const u32) as u64;
        let dll_name_rva = read_unaligned((desc + 12) as *const u32) as u64;
        if ilt == 0 && iat == 0 {
            break;
        }
        if dll_name_rva != 0
            && image_c_string_eq_ignore_case(
                code_va,
                dll_name_rva,
                WIN32K_IMAGE_BYTES,
                31,
                dll_name,
            )
        {
            let thunk_rva = if ilt != 0 { ilt } else { iat };
            if !image_rva_span_ok(thunk_rva, 8, WIN32K_IMAGE_BYTES)
                || !image_rva_span_ok(iat, 8, WIN32K_IMAGE_BYTES)
            {
                return patched;
            }
            let names = code_va + thunk_rva;
            let slots = code_va + iat;
            let mut k = 0u64;
            let thunk_cap =
                ((WIN32K_IMAGE_BYTES - thunk_rva) / 8).min((WIN32K_IMAGE_BYTES - iat) / 8);
            while k < thunk_cap {
                let thunk = read_unaligned((names + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }
                if thunk & 0x8000_0000_0000_0000 == 0 {
                    let name_rva = thunk & 0x7FFF_FFFF;
                    if !image_rva_span_ok(name_rva, 2, WIN32K_IMAGE_BYTES) {
                        return patched;
                    }
                    let name_ptr = code_va + name_rva + 2;
                    let Some(cstr_len) =
                        image_c_string_len(code_va, name_rva + 2, WIN32K_IMAGE_BYTES, 63)
                    else {
                        return patched;
                    };
                    let import_name = core::slice::from_raw_parts(name_ptr as *const u8, cstr_len);
                    let addr = pe_export_lookup(dll_base, import_name);
                    if addr != 0 {
                        write_unaligned((slots + k * 8) as *mut u64, addr);
                        patched += 1;
                    }
                }
                k += 1;
            }
            break;
        }
        desc_rva += 20;
    }
    patched
}
