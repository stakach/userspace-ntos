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
//!     applies the 1920 DIR64 relocations in place, and patches the IAT: init-path imports ->
//!     real trampolines below, data-export globals -> non-null placeholder cells, everything
//!     else -> the legacy zero stub. See [`load_into`].
//!   * the COMPONENT (the spawned Subsystem-class component) maps the image W^X (RX code / RW
//!     data), a pool arena, the data-export region, and calls `DriverEntry(DRIVER_OBJECT*,
//!     UNICODE_STRING*)` with its fault endpoint armed. On return it writes a verdict + the
//!     recorded SSDT to the shared page and trips a SENTINEL fault so the executive's fault-recv
//!     loop knows it finished (vs. faulted mid-init). See [`win32k_subsystem_entry`].
//!
//! The trampolines are compiled into the executive's image (mapped RWX-shared into the component),
//! so the component calls them at the same VA.

use alloc::vec::Vec;
use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};
use nt_compat_exports::{
    ssdt::{
        x64_argument_count_from_sspt_byte,
        WIN32K_SERVICE_TABLE_INDEX as NT_WIN32K_SERVICE_TABLE_INDEX,
    },
    DriverExportRegistry, DriverExportRegistryStats, DRIVER_EXPORT_INITIAL_RESERVE,
};
use nt_kernel_exec::provider_pool as shared_pool;

// Pure, driver-agnostic ntoskrnl byte/string primitives shared with the FSD class.
use crate::ntoskrnl_shared::{
    s_ex_query_depth_slist, s_exp_interlocked_pop_entry_slist, s_exp_interlocked_push_entry_slist,
    s_ke_query_performance_counter, s_memcpy, s_memmove, s_memset, s_rtl_compare_memory,
    s_rtl_integer_to_unicode_string, s_rtl_time_to_time_fields, s_rtl_unicode_string_to_integer,
    s_wcslen,
};

use crate::*;

// --- component VA layout (identical in executive-load + host-run views) ----------------------

/// The relocated/loaded win32k image (VIRTUAL layout), mapped W^X in the host. size_of_image
/// is 0x220000 (544 frames); place it in its own 2-PT window well clear of everything else.
pub const WIN32K_CODE_VA: u64 = 0x0000_0100_0680_0000;
/// win32k image frame count (size_of_image 0x220000 / 0x1000).
pub const WIN32K_IMAGE_FRAMES: u64 = 0x220;
const WIN32K_IMAGE_BYTES: u64 = WIN32K_IMAGE_FRAMES * 0x1000;
/// Pool arena used by the `ExAllocatePool*` trampolines and component-owned GUI objects. It is
/// pre-mapped because provider pointers must remain directly dereferenceable, but allocation is a
/// headered first-fit free list with eager coalescing and tail trimming. Counter at +0, free-list
/// head at +8, data at +0x1000. Its own 0x0A00_0000 window spans four 2 MiB page tables.
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
/// reserved data (page 3) + win32 compatibility slots/callout table (page 4) + reserved mapped data
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
/// The real `SE_EXPORTS` struct (well-known SID pointers + privilege LUIDs) that win32k's `SeExports`
/// data-export cell points at, built by [`nt_security::se_exports::build_se_exports`]. Lives in DATA
/// page 0 (the old zeroed placeholder region, clear of the SeExports/Nls placeholders at +0x1C0/
/// +0x200). win32k reads only `SeAliasAdminsSid` (+0x110), off the interactive boot/paint path
/// (`IntCreateServiceSecurity`, non-interactive service window-station).
const WIN32K_SE_EXPORTS_VA: u64 = WIN32K_DATA_VADDR + 0x800;
/// The SID blob pool the `SE_EXPORTS` pointer members reference (DATA page 0, after the struct).
const WIN32K_SE_SID_POOL_VA: u64 = WIN32K_DATA_VADDR + 0xA00;
const WIN32K_NLS_MB_TAG_VA: u64 = WIN32K_DATA_VADDR + 0x200;
const WIN32K_NLS_STATE_VA: u64 = WIN32K_DATA_VADDR + 0x208;
const WIN32K_NLS_STATE_MAGIC: u32 = u32::from_le_bytes(*b"NLS1");

#[repr(C)]
#[derive(Clone, Copy)]
struct Win32kNlsState {
    magic: u32,
    ansi_size: u32,
    oem_size: u32,
    case_size: u32,
    ansi_code_page: u16,
    oem_code_page: u16,
    ansi_multi_byte_index: u32,
    ansi_wide_byte_offset: u32,
    oem_multi_byte_index: u32,
    upper_case_index: u32,
    upper_case_len: u32,
}
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
/// The win32k session-heap arena that lookaside fallbacks, section descriptors, and section backing
/// allocate from (counter at +0, free-list head at +8, data at +0x1000). Section-backed USER and
/// desktop heaps then allocate inside their own section views, using the same block allocator.
pub const WIN32K_HEAP_VADDR: u64 = 0x0000_0100_0740_0000;
pub const WIN32K_HEAP_FRAMES: u64 = 4096;
const PROVIDER_ARENA_ROOT_HEAP_ID: u64 = 1;
const PROVIDER_ARENA_SHARED_POOL_ID: u64 = 2;
const PROVIDER_ARENA_FTYP_POOL_ID: u64 = 3;
const PROVIDER_ARENA_FIRST_HOSTED_HEAP_ID: u64 = 4;
static PROVIDER_ARENA_NEXT_HOSTED_HEAP_ID: AtomicU64 =
    AtomicU64::new(PROVIDER_ARENA_FIRST_HOSTED_HEAP_ID);
static mut WIN32K_PROVIDER_ALLOCATIONS: Option<nt_provider_wait::ProviderAllocationCatalog> = None;
static mut WIN32K_HOSTED_HEAP_ARENAS: Option<Vec<HostedHeapArena>> = None;
static mut WIN32K_LOCAL_EVENTS: Option<nt_provider_wait::ProviderLocalEventCatalog> = None;
static mut WIN32K_STACK_EVENT_ACTIVATIONS: Option<Vec<ProviderStackEventActivation>> = None;
static mut WIN32K_DRIVER_STACK_EVENT_ACTIVATION: Option<ProviderStackEventActivation> = None;
static PROVIDER_STACK_ACTIVATION_GENERATION: AtomicU64 = AtomicU64::new(1);
static PROVIDER_LOCAL_EVENT_INITIALIZATIONS: AtomicU64 = AtomicU64::new(0);
const PROVIDER_DRIVER_ENTRY_DISPATCH_ID: u64 = u64::MAX;
const WIN32K_STACK_BYTES: u64 = 32 * 0x1000;

#[derive(Clone, Copy)]
struct HostedHeapArena {
    base: u64,
    bytes: u64,
    identity: nt_provider_wait::ProviderArenaIdentity,
    backing: nt_provider_wait::ProviderAllocationIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ProviderStackEventActivation {
    dispatch_id: u64,
    generation: u64,
}

impl ProviderStackEventActivation {
    const fn backing(self) -> nt_provider_wait::ProviderEventBacking {
        nt_provider_wait::ProviderEventBacking::Stack {
            dispatch_id: self.dispatch_id,
            activation_generation: self.generation,
        }
    }
}

struct ProviderStackEventActivationGuard {
    activation: ProviderStackEventActivation,
}

impl Drop for ProviderStackEventActivationGuard {
    fn drop(&mut self) {
        if !unsafe { finish_provider_stack_event_activation(self.activation) } {
            print_str(b"[win32k-event] stack activation retirement failed\n");
            park();
        }
    }
}
const _: () = assert!(WIN32K_HEAP_VADDR + WIN32K_HEAP_FRAMES * 0x1000 <= WIN32K_POOL_VADDR);
const _: () = assert!(WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000 <= WIN32K_STACK_VADDR);
/// Shared handoff page (executive ↔ host). Within the pool's 2 MiB PT window (0x0700..0x0720).
pub const WIN32K_SHARED_VADDR: u64 = 0x0000_0100_0718_0000;
/// Dedicated fixed-frame provider-wait ABI. A wait may remain live while nested dispatches overwrite
/// the general request and callback frames, so its canonical object identities cannot alias either.
pub const WIN32K_PROVIDER_WAIT_VADDR: u64 = WIN32K_SHARED_VADDR + 0x1000;
pub const WIN32K_PROVIDER_WAIT_FRAMES: u64 = 1;
const _: () = assert!(
    core::mem::size_of::<nt_provider_wait::ProviderWaitSharedPage>()
        <= WIN32K_PROVIDER_WAIT_FRAMES as usize * 0x1000
);
/// The cross-address-space ARG-MARSHAL frame: mapped RW in BOTH the executive and the win32k
/// component (within the pool PT window). The executive copies a dispatched syscall's user buffers
/// here (sized per the win32k SSN signature); win32k's handler reads/writes them in its own context;
/// the executive copies out-params back to the caller on reply. The first four pages remain the
/// general marshal arena; the final page contains dispatch-scoped `MSG` output slots which stay
/// leased while an outer dispatch is parked behind a user-mode callback.
pub const WIN32K_ARG_VADDR: u64 = 0x0000_0100_071A_0000;
pub const WIN32K_ARG_GENERAL_FRAMES: u64 = 4;
pub const WIN32K_ARG_FRAMES: u64 = WIN32K_ARG_GENERAL_FRAMES + 1;
pub const WIN32K_ARG_GENERAL_BYTES: u64 = WIN32K_ARG_GENERAL_FRAMES * 0x1000;
pub const WIN32K_MESSAGE_STAGE_BASE: u64 = WIN32K_ARG_VADDR + WIN32K_ARG_GENERAL_BYTES;
pub const WIN32K_MESSAGE_STAGE_SLOT_BYTES: u64 = 64;
pub const WIN32K_MESSAGE_STAGE_SLOTS: u64 = 0x1000 / WIN32K_MESSAGE_STAGE_SLOT_BYTES;
pub const WIN32K_MESSAGE_STAGE_OUTPUT_LENGTH_OFFSET: u64 = 56;
const _: () = assert!(
    WIN32K_PROVIDER_WAIT_VADDR + WIN32K_PROVIDER_WAIT_FRAMES * 0x1000 <= WIN32K_ARG_VADDR
);
const _: () = assert!(
    WIN32K_MESSAGE_STAGE_BASE + WIN32K_MESSAGE_STAGE_SLOTS * WIN32K_MESSAGE_STAGE_SLOT_BYTES
        == WIN32K_ARG_VADDR + WIN32K_ARG_FRAMES * 0x1000
);
const _: () = assert!(WIN32K_MESSAGE_STAGE_SLOTS <= u64::BITS as u64);
const _: () = assert!(
    WIN32K_MESSAGE_STAGE_OUTPUT_LENGTH_OFFSET
        >= nt_user_callback::DISPATCH_MESSAGE_OUTPUT_BYTES as u64
);
const _: () =
    assert!(WIN32K_MESSAGE_STAGE_OUTPUT_LENGTH_OFFSET + 8 <= WIN32K_MESSAGE_STAGE_SLOT_BYTES);
/// Dedicated cross-address-space video-control window. `EngDeviceIoControl` runs in the win32k
/// component, but hosted miniport IRPs are executive-owned; this window carries bounded METHOD_BUFFERED
/// input/output bytes without reusing the live syscall ARG frame or the user-callback shared page.
pub const WIN32K_VIDEO_IOCTL_VADDR: u64 = 0x0000_0100_071C_0000;
pub const WIN32K_VIDEO_IOCTL_FRAMES: u64 = 4;
pub const WIN32K_VIDEO_IOCTL_BYTES: usize = (WIN32K_VIDEO_IOCTL_FRAMES as usize) * 0x1000;
/// Dedicated cross-address-space LPC request window. Kernel LPC imports execute inside the win32k
/// component, while the isolated LPC broker channel belongs to the executive's CSpace. The
/// component therefore stages one bounded, pointer-free request here and calls the executive pump.
pub const WIN32K_LPC_VADDR: u64 = WIN32K_VIDEO_IOCTL_VADDR + WIN32K_VIDEO_IOCTL_FRAMES * 0x1000;
pub const WIN32K_LPC_FRAMES: u64 = 1;
pub const WIN32K_LPC_BYTES: usize = (WIN32K_LPC_FRAMES as usize) * 0x1000;
/// Dedicated pointer-free staging for native atom services redirected to a job-private win32k
/// namespace. It cannot share the general argument or LPC windows because either may remain live
/// while a nested hosted syscall is serviced.
pub const WIN32K_JOB_ATOM_VADDR: u64 = WIN32K_LPC_VADDR + WIN32K_LPC_FRAMES * 0x1000;
pub const WIN32K_JOB_ATOM_FRAMES: u64 = 1;
pub const WIN32K_JOB_ATOM_BYTES: usize = (WIN32K_JOB_ATOM_FRAMES as usize) * 0x1000;
pub const WIN32K_JOB_ATOM_PAYLOAD_OFF: u64 = 0x20;
/// Dedicated pointer-free registry staging. Registry imports execute in the win32k component, but
/// the isolated Configuration Manager transport and all CM key leases remain executive-owned.
pub const WIN32K_REGISTRY_VADDR: u64 = WIN32K_JOB_ATOM_VADDR + WIN32K_JOB_ATOM_FRAMES * 0x1000;
pub const WIN32K_REGISTRY_FRAMES: u64 = 16;
pub const WIN32K_REGISTRY_BYTES: usize = (WIN32K_REGISTRY_FRAMES as usize) * 0x1000;
/// Bulk client-buffer staging for provider-dispatched win32k calls whose input is data, not just
/// scalar argument tails. `NtGdiStretchDIBitsInternal` can receive DIB payloads far larger than the
/// generic ARG window, so it gets a dedicated shared 2 MiB PT window between AUX and the session heap.
pub const WIN32K_BULK_ARG_VADDR: u64 = 0x0000_0100_0720_0000;
pub const WIN32K_BULK_ARG_FRAMES: u64 = 512;
const _: () = assert!(WIN32K_ARG_VADDR + WIN32K_ARG_FRAMES * 0x1000 <= WIN32K_VIDEO_IOCTL_VADDR);
const _: () =
    assert!(WIN32K_VIDEO_IOCTL_VADDR + WIN32K_VIDEO_IOCTL_FRAMES * 0x1000 <= WIN32K_LPC_VADDR);
const _: () =
    assert!(WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_FRAMES * 0x1000 <= WIN32K_BULK_ARG_VADDR);
/// Kernel-mode KUSER_SHARED_DATA mapping used by win32k's direct `SharedUserData` reads. User
/// processes also see the low 0x7FFE0000 alias; win32k, as a kernel driver, reads the canonical
/// high VA directly (for example TickCount at +0x320).
pub const WIN32K_KUSER_SHARED_DATA_VA: u64 = 0xFFFF_F780_0000_0000;
/// Executive-only scratch VA, inside the already mapped win32k aux PT, used to initialize the
/// KUSER frame before aliasing it into the win32k component at the canonical high VA.
pub const WIN32K_KUSER_SCRATCH_VA: u64 = WIN32K_AUX_PT_VADDR + 0x1B_0000;

/// The GUI-client-side VA where win32k's global USER heap arena ([`WIN32K_HEAP_VADDR`] — where gpsi, the
/// USER handle table `gHandleTable`, and the handle-entry array all live, being `UserHeapAlloc`ed)
/// is RO-mapped so the Win32 client stack (user32/gdi32) can read the SHAREDINFO the USERCONNECT's
/// `siClient` pointers name. A full 16 MiB window ([`WIN32K_HEAP_FRAMES`]), 2-MiB-aligned, sitting
/// immediately above the bounded compact DLL arena and below the NLS section (0xA000_0000).
/// **Was 0x9000_0000, where the former fixed-slot DLL layout collided with it and made lsass execute
/// win32k-heap NX pages.** 0x9800_0000 is now the explicit DLL-arena end and stays inside the shared
/// 0x8000_0000..0xC000_0000 1 GiB PD. Delta-relative: the
/// connect marshaling rewrites `siClient`/`ulSharedDelta` by `WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`,
/// so moving the base is behavior-preserving for every GUI client.
pub const CSRSS_W32_SHARED_VA: u64 = 0x0000_0000_9800_0000;

/// The GUI-client-side VA where win32k's POOL arena ([`WIN32K_POOL_VADDR`] — where DESKTOP bodies and
/// other session-lifetime object bodies live) is RO-mapped. DESKTOPINFO lives in the per-desktop heap;
/// this pool window remains needed for object bodies referenced by USER/desktop structures. Sits
/// immediately ABOVE the 16 MiB USER-heap window (0x9800_0000..0x9900_0000) and below the NLS section
/// (0xA000_0000), inside the shared 0x8000_0000..0xC000_0000 1 GiB PD. The client VA of a pool object =
/// its server VA - ([`WIN32K_POOL_VADDR`] - `CSRSS_W32_POOL_VA`).
pub const CSRSS_W32_POOL_VA: u64 = 0x0000_0000_9900_0000;
// The USER-heap window (16 MiB) must end at or below the POOL window base so the two client windows
// never overlap; the POOL window (8 MiB) must end below the NLS section (0xA000_0000).
const _: () = assert!(CSRSS_W32_SHARED_VA + WIN32K_HEAP_FRAMES * 0x1000 <= CSRSS_W32_POOL_VA);
const _: () = assert!(CSRSS_W32_POOL_VA + WIN32K_POOL_FRAMES * 0x1000 <= 0x0000_0000_A000_0000);

// ★ DIALOG BATCH 3 — CLIENT-GDI HANDLE TABLE. gdi32's client-side validity check indexes
// `GdiSharedHandleTable[handle & 0xffff]` (0x18-byte GDI_TABLE_ENTRY each; ntgdihdl.h). The base
// pointer is `PEB->GdiSharedHandleTable` (PEB+0xf8), copied once by gdi32's `GdiProcessSetup`.
// ReactOS win32k allocates the table from session USER/GDI memory and returns a process-local user
// pointer. Our table is allocated inside the win32k USER heap and exposed through that heap's client
// alias; no separate fixed GDI-table VSpace window is reserved.
/// GDI handle count (ReactOS GDI_HANDLE_COUNT) — the index space of `handle & 0xffff`.
pub const GDI_HANDLE_COUNT: u64 = 0x1_0000;
/// sizeof(GDI_TABLE_ENTRY) on x64 (KernelData 8 + ProcessId/Type union 8 + UserData 8).
pub const GDI_TABLE_ENTRY_SIZE: u64 = 0x18;
/// Maximum accepted mapped section size for the shared GDI table allocation.
pub const GDI_SHARED_TABLE_MAX_BYTES: u64 = 0x0020_0000;
const _: () = assert!(GDI_HANDLE_COUNT * GDI_TABLE_ENTRY_SIZE <= GDI_SHARED_TABLE_MAX_BYTES);

// USERCONNECT / SHAREDINFO x64 field offsets (references/reactos win32ss/include/ntuser.h): a
// USERCONNECT is { ULONG ulVersion; ULONG ulCurrentVersion; DWORD dwDispatchCount; SHAREDINFO
// siClient; } with siClient (8-byte aligned) at +0x10, and SHAREDINFO = { PSERVERINFO psi; PVOID
// aheList; PVOID pDispInfo; ULONG_PTR ulSharedDelta; ... }. NtUserProcessConnect fills these with
// logical client pointers derived from W32Process->HeapMappings; the executive verifies and restates
// those CSRSS_W32_SHARED_VA-relative pointers before copy-out.
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
pub const SH_REQ_KIND: u64 = 0x80; // in: request class; SSDT dispatch or executive Ps control
pub const SH_FONT_SIZE: u64 = 0x88; // in:  staged system-font (.ttf) byte size at FONTBUF_VADDR (u32)
                                    // STACK-ARG TAIL for executive-originated win32k SSNs. Real client syscalls pass their caller RSP in
                                    // SH_REQ_CALLER_SP and the component reads the required tail directly from the attached client stack,
                                    // after deriving the exact arity from win32k's registered SSPT/KiArgumentTable.
pub const SH_REQ_A4: u64 = 0x90; // in:  handler arg4 (1st stack arg)
pub const SH_REQ_NARGS: u64 = 0xF0; // in:  total arg count staged in SH_REQ_A4.., or 0 for caller-stack args
pub const SH_EVENT_RECLAIM_PENDING: u64 = 0x100; // executive->provider reclaim work hint
pub const WIN32K_MAX_SERVICE_ARGS: u64 = 16;
pub const WIN32K_STACK_TAIL_ARGS: usize = (WIN32K_MAX_SERVICE_ARGS - 4) as usize;
// Compile-time invariants for the stack-arg-tail region (host-verified at build):
//  - SH_REQ_A4 must sit ABOVE the last register field (SH_FONT_SIZE=0x88) so it never aliases.
//  - The widest SSN is 16 args (SH_REQ_A4 holds args 5..16 = 12 u64 slots = 0x90..0xF0), which must
//    END exactly at SH_REQ_NARGS with no overlap — i.e. NARGS = A4 + 12*8.
const _: () = assert!(SH_REQ_A4 > SH_FONT_SIZE);
const _: () = assert!(SH_REQ_NARGS == SH_REQ_A4 + WIN32K_STACK_TAIL_ARGS as u64 * 8);
const _: () = assert!(SH_EVENT_RECLAIM_PENDING + 8 <= SH_SAS_AHELIST);

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
pub const SH_REQ_GENERATION: u64 = 0x1F8; // in: exact hosted-process identity generation
pub const WIN32K_REQUEST_SSDT: u64 = 0;
pub const WIN32K_REQUEST_PS_PROVIDER: u64 = 1;
pub const PS_WIN32_PROVIDER_THREAD_EXIT: u64 = 1;
pub const PS_WIN32_PROVIDER_PROCESS_EXIT: u64 = 2;
pub const PS_WIN32_PROVIDER_FINALIZE_PROCESS_OBJECTS: u64 = 3;
pub const PS_WIN32_PROVIDER_RETAIN_THREAD_CONTEXT: u64 = 1;
pub const SH_REQ_DEBUG_ATL_REPLAY: u64 = 0x0000_0001;
const _: () = assert!(SH_SAS_AHELIST > SH_REQ_NARGS);
/// Phase 2A callback rendezvous frame. The fixed, pointer-free ABI occupies the otherwise-unused
/// tail of the existing shared page; both the component stub and executive pump access it here.
pub const SH_USER_CALLBACK: u64 = 0x200;
const _: () = assert!(SH_REQ_TOKEN_USER_SID_PTR + 8 <= SH_USER_CALLBACK);
const _: () = assert!(SH_GDI_LOAD_LEAF + SH_GDI_LOAD_LEAF_CAP as u64 <= SH_USER_CALLBACK);
const _: () = assert!(SH_REQ_GENERATION + 8 <= SH_USER_CALLBACK);
const _: () = assert!(SH_USER_CALLBACK as usize + nt_user_callback::CALLBACK_FRAME_SIZE <= 0x1000);
/// Provider-owned `WIN32_CALLOUTS_FPNS` metadata copied out by `PsEstablishWin32Callouts`. These
/// pointers remain provider VAs and are invoked only by dispatching back into this component.
pub const SH_CALLOUT_TABLE: u64 = 0xFD0;
pub const SH_CALLOUT_PROCESS: u64 = 0xFD8;
pub const SH_CALLOUT_THREAD: u64 = 0xFE0;
pub const SH_CALLOUT_GLOBAL_ATOM: u64 = 0xFE8;
pub const SH_CALLOUT_JOB: u64 = 0xFF0;
pub const SH_CALLOUT_BATCH_FLUSH: u64 = 0xFF8;
const _: () = assert!(
    SH_USER_CALLBACK as usize + nt_user_callback::CALLBACK_FRAME_SIZE <= SH_CALLOUT_TABLE as usize
);
const _: () = assert!(SH_CALLOUT_BATCH_FLUSH + 8 == 0x1000);

pub const HOSTED_PROCESS_ROLE_NONE: u64 = 0;
pub const HOSTED_PROCESS_ROLE_NATIVE_SESSION: u64 = 1;
pub const HOSTED_PROCESS_ROLE_WIN32_SUBSYSTEM: u64 = 2;
pub const HOSTED_PROCESS_ROLE_INTERACTIVE_LOGON: u64 = 3;
pub const HOSTED_PROCESS_ROLE_NONINTERACTIVE_SERVICE: u64 = 4;
pub const HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL_BOOTSTRAP: u64 = 5;
pub const HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL: u64 = 6;
pub const HOSTED_PROCESS_ROLE_SERVICE_CONTROL_MANAGER: u64 = 7;
pub const HOSTED_PROCESS_ROLE_LOCAL_SECURITY_AUTHORITY: u64 = 8;

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

fn registered_provider_wait_domain() -> Option<nt_provider_wait::ProviderDomainIdentity> {
    unsafe {
        read_volatile(
            core::ptr::addr_of!(
                (*(WIN32K_PROVIDER_WAIT_VADDR
                    as *const nt_provider_wait::ProviderWaitSharedPage))
                .control
            ),
        )
        .identity()
    }
}

fn root_heap_arena_identity() -> Option<nt_provider_wait::ProviderArenaIdentity> {
    fixed_provider_arena_identity(PROVIDER_ARENA_ROOT_HEAP_ID)
}

fn fixed_provider_arena_identity(id: u64) -> Option<nt_provider_wait::ProviderArenaIdentity> {
    registered_provider_wait_domain().map(|provider| nt_provider_wait::ProviderArenaIdentity {
        id,
        generation: provider.generation,
    })
}

unsafe fn initialize_provider_allocation_tracking() -> bool {
    if registered_provider_wait_domain().is_none()
        || (&*core::ptr::addr_of!(WIN32K_PROVIDER_ALLOCATIONS)).is_some()
        || (&*core::ptr::addr_of!(WIN32K_HOSTED_HEAP_ARENAS)).is_some()
    {
        return false;
    }
    *core::ptr::addr_of_mut!(WIN32K_PROVIDER_ALLOCATIONS) =
        Some(nt_provider_wait::ProviderAllocationCatalog::new());
    *core::ptr::addr_of_mut!(WIN32K_HOSTED_HEAP_ARENAS) = Some(Vec::new());
    PROVIDER_ARENA_NEXT_HOSTED_HEAP_ID
        .store(PROVIDER_ARENA_FIRST_HOSTED_HEAP_ID, Ordering::Relaxed);
    true
}

unsafe fn initialize_provider_local_event_tracking() -> bool {
    let Some(provider) = registered_provider_wait_domain() else {
        return false;
    };
    if (&*core::ptr::addr_of!(WIN32K_LOCAL_EVENTS)).is_some()
        || (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS)).is_some()
    {
        return false;
    }
    let Ok(events) = nt_provider_wait::ProviderLocalEventCatalog::new(provider) else {
        return false;
    };
    *core::ptr::addr_of_mut!(WIN32K_LOCAL_EVENTS) = Some(events);
    *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS) = Some(Vec::new());
    *core::ptr::addr_of_mut!(WIN32K_DRIVER_STACK_EVENT_ACTIVATION) = None;
    PROVIDER_STACK_ACTIVATION_GENERATION.store(1, Ordering::Relaxed);
    PROVIDER_LOCAL_EVENT_INITIALIZATIONS.store(0, Ordering::Relaxed);
    true
}

unsafe fn provider_local_events_mut(
) -> Option<&'static mut nt_provider_wait::ProviderLocalEventCatalog> {
    (&mut *core::ptr::addr_of_mut!(WIN32K_LOCAL_EVENTS)).as_mut()
}

unsafe fn provider_local_events(
) -> Option<&'static nt_provider_wait::ProviderLocalEventCatalog> {
    (&*core::ptr::addr_of!(WIN32K_LOCAL_EVENTS)).as_ref()
}

unsafe fn active_provider_stack_event_activation() -> Option<ProviderStackEventActivation> {
    (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
        .as_ref()?
        .last()
        .copied()
}

unsafe fn begin_provider_stack_event_activation(
    dispatch_id: u64,
) -> Option<ProviderStackEventActivationGuard> {
    if dispatch_id == 0 {
        return None;
    }
    let generation = loop {
        let generation = PROVIDER_STACK_ACTIVATION_GENERATION.load(Ordering::Relaxed);
        let next = generation.checked_add(1)?;
        if generation == 0 {
            return None;
        }
        if PROVIDER_STACK_ACTIVATION_GENERATION
            .compare_exchange_weak(generation, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            break generation;
        }
    };
    let activation = ProviderStackEventActivation {
        dispatch_id,
        generation,
    };
    let stack = (&mut *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS)).as_mut()?;
    stack.try_reserve(1).ok()?;
    stack.push(activation);
    Some(ProviderStackEventActivationGuard { activation })
}

unsafe fn provider_allocations_mut(
) -> Option<&'static mut nt_provider_wait::ProviderAllocationCatalog> {
    (&mut *core::ptr::addr_of_mut!(WIN32K_PROVIDER_ALLOCATIONS)).as_mut()
}

unsafe fn register_provider_allocation(
    arena: nt_provider_wait::ProviderArenaIdentity,
    base: u64,
    capacity: u64,
) -> Option<nt_provider_wait::ProviderAllocationSnapshot> {
    provider_allocations_mut()?.register(arena, base, capacity).ok()
}

unsafe fn validate_provider_allocation_retirement(
    arena: nt_provider_wait::ProviderArenaIdentity,
    base: u64,
    required: u64,
) -> Option<nt_provider_wait::ProviderAllocationSnapshot> {
    let allocations = provider_allocations_mut()?;
    let allocation = allocations.exact(arena, base).ok()?;
    if allocation.capacity < required
        || allocations
            .validate_retirement(allocation.identity)
            .is_err()
    {
        return None;
    }
    Some(allocation)
}

unsafe fn retire_provider_allocation(
    allocation: nt_provider_wait::ProviderAllocationSnapshot,
) -> bool {
    provider_allocations_mut()
        .is_some_and(|allocations| allocations.retire(allocation.identity).is_ok())
}

unsafe fn provider_allocation_event_backing(
    allocation: nt_provider_wait::ProviderAllocationSnapshot,
) -> nt_provider_wait::ProviderEventBacking {
    nt_provider_wait::ProviderEventBacking::from_allocation(allocation)
}

unsafe fn validate_provider_allocation_event_retirement(
    allocation: nt_provider_wait::ProviderAllocationSnapshot,
) -> bool {
    provider_local_events().is_some_and(|events| {
        events
            .validate_backing_retirement(provider_allocation_event_backing(allocation))
            .is_ok()
    })
}

unsafe fn retire_provider_allocation_events(
    allocation: nt_provider_wait::ProviderAllocationSnapshot,
) -> bool {
    retire_provider_local_events_for_backing(provider_allocation_event_backing(allocation))
}

unsafe fn provider_heap_arena_identity(
    arena_base: u64,
) -> Option<nt_provider_wait::ProviderArenaIdentity> {
    if arena_base == WIN32K_HEAP_VADDR {
        return root_heap_arena_identity();
    }
    (&*core::ptr::addr_of!(WIN32K_HOSTED_HEAP_ARENAS))
        .as_ref()?
        .iter()
        .find(|arena| arena.base == arena_base)
        .map(|arena| arena.identity)
}

fn mint_hosted_heap_arena_identity() -> Option<nt_provider_wait::ProviderArenaIdentity> {
    let generation = registered_provider_wait_domain()?.generation;
    loop {
        let id = PROVIDER_ARENA_NEXT_HOSTED_HEAP_ID.load(Ordering::Relaxed);
        let next = id.checked_add(1)?;
        if PROVIDER_ARENA_NEXT_HOSTED_HEAP_ID
            .compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Some(nt_provider_wait::ProviderArenaIdentity { id, generation });
        }
    }
}

unsafe fn register_hosted_heap_arena(base: u64, bytes: u64) -> bool {
    let Some(root) = root_heap_arena_identity() else {
        return false;
    };
    let Some(allocations) = provider_allocations_mut() else {
        return false;
    };
    let Ok(backing) = allocations.exact(root, base) else {
        return false;
    };
    if backing.capacity < bytes {
        return false;
    }
    let Some(arenas) = (&mut *core::ptr::addr_of_mut!(WIN32K_HOSTED_HEAP_ARENAS)).as_mut() else {
        return false;
    };
    if let Some(existing) = arenas.iter().find(|arena| arena.base == base) {
        return existing.bytes == bytes && existing.backing == backing.identity;
    }
    if arenas.try_reserve(1).is_err() {
        return false;
    }
    let Some(identity) = mint_hosted_heap_arena_identity() else {
        return false;
    };
    arenas.push(HostedHeapArena {
        base,
        bytes,
        identity,
        backing: backing.identity,
    });
    true
}

unsafe fn hosted_heap_arena_backed_by(
    backing: nt_provider_wait::ProviderAllocationIdentity,
) -> Option<nt_provider_wait::ProviderArenaIdentity> {
    (&*core::ptr::addr_of!(WIN32K_HOSTED_HEAP_ARENAS))
        .as_ref()?
        .iter()
        .find(|arena| arena.backing == backing)
        .map(|arena| arena.identity)
}

unsafe fn retire_hosted_heap_arena(
    identity: nt_provider_wait::ProviderArenaIdentity,
    backing: nt_provider_wait::ProviderAllocationIdentity,
) -> bool {
    let Some(arenas) = (&mut *core::ptr::addr_of_mut!(WIN32K_HOSTED_HEAP_ARENAS)).as_mut() else {
        return false;
    };
    let Some(index) = arenas
        .iter()
        .position(|arena| arena.identity == identity && arena.backing == backing)
    else {
        return false;
    };
    arenas.swap_remove(index);
    true
}

pub fn registered_win32k_callouts() -> Option<nt_process::Win32Callouts> {
    unsafe {
        let callouts = nt_process::Win32Callouts {
            table: read_volatile((WIN32K_SHARED_VADDR + SH_CALLOUT_TABLE) as *const u64),
            process_callout: read_volatile(
                (WIN32K_SHARED_VADDR + SH_CALLOUT_PROCESS) as *const u64,
            ),
            thread_callout: read_volatile((WIN32K_SHARED_VADDR + SH_CALLOUT_THREAD) as *const u64),
            global_atom_callout: read_volatile(
                (WIN32K_SHARED_VADDR + SH_CALLOUT_GLOBAL_ATOM) as *const u64,
            ),
            job_callout: read_volatile((WIN32K_SHARED_VADDR + SH_CALLOUT_JOB) as *const u64),
            batch_flush_callout: read_volatile(
                (WIN32K_SHARED_VADDR + SH_CALLOUT_BATCH_FLUSH) as *const u64,
            ),
        };
        if callouts.table == 0
            || callouts.process_callout == 0
            || callouts.thread_callout == 0
            || callouts.job_callout == 0
            || callouts.batch_flush_callout == 0
        {
            None
        } else {
            Some(callouts)
        }
    }
}

fn hosted_process_role_is_noninteractive_service_class(process_role: u64) -> bool {
    matches!(
        process_role,
        HOSTED_PROCESS_ROLE_NONINTERACTIVE_SERVICE
            | HOSTED_PROCESS_ROLE_SERVICE_CONTROL_MANAGER
            | HOSTED_PROCESS_ROLE_LOCAL_SECURITY_AUTHORITY
    )
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
const SSN_GDI_CREATE_PATTERN_BRUSH_INTERNAL: u64 = 0x10B5;
const SSN_GDI_OPEN_DCW: u64 = 0x10DE;
const GDI_HANDLE_TYPE_MASK: u32 = 0x007f_0000;
const GDI_HANDLE_BASETYPE_MASK: u32 = 0x001f_0000;
const GDI_ENTRY_PROCESS_ID_OFF: u64 = 0x08;
const GDI_ENTRY_TYPE_OFF: u64 = 0x0C;
const GDI_ENTRY_USER_DATA_OFF: u64 = 0x10;
const GDI_ENTRY_UPPER_SHIFT: u32 = 16;
const GDI_OBJECT_TYPE_DC: u32 = 0x0001_0000;
const GDI_OBJECT_TYPE_BITMAP: u32 = 0x0005_0000;
const GDI_OBJECT_TYPE_BRUSH: u32 = 0x0010_0000;

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
/// Private executive selector for the provider registered in
/// `WIN32_CALLOUTS_FPNS.JobCallout`.
pub const SSN_WIN32_JOB_CALLOUT: u64 = 0x1FFC;
/// Private pointer-free selector for native atom operations against win32k's job-owned namespace.
pub const SSN_WIN32_JOB_ATOM: u64 = 0x1FFB;
/// Private client-context selector for an executive-authorized `UserHandleGrantAccess` request.
/// The public syscall carries an Object Manager job handle which win32k must never interpret.
pub const SSN_WIN32_JOB_USER_HANDLE: u64 = 0x1FFA;
pub const SSN_NT_USER_USER_HANDLE_GRANT_ACCESS: u64 = 0x1293;
pub const SSN_NT_USER_VALIDATE_HANDLE_SECURE: u64 = 0x1294;
pub const WIN32_JOB_ATOM_ADD_NAME: u64 = 0;
pub const WIN32_JOB_ATOM_FIND_NAME: u64 = 1;
pub const WIN32_JOB_ATOM_ADD_INTEGER: u64 = 2;
pub const WIN32_JOB_ATOM_FIND_INTEGER: u64 = 3;
pub const WIN32_JOB_ATOM_DELETE: u64 = 4;
pub const WIN32_JOB_ATOM_QUERY: u64 = 5;
pub const WIN32_JOB_ATOM_LIST: u64 = 6;
/// Un-demand-paged, demand-pageable probe VA: past the win32k image tail (0x06A2_0000, so NOT
/// flagged `in_image`) yet inside the same PD as the image, so the executive maps it with no new
/// page table. Zeroed on first touch.
pub const TEST_FAULT_VA: u64 = 0x0000_0100_06B0_0000;
/// The sentinel NTSTATUS the synthetic handler returns after surviving the fault.
pub const TEST_FAULT_STATUS: i32 = 0x600D_600Du32 as i32;
const WIN32_CALLOUT_BATCH_FLUSH_OFF: u64 = 6 * 8;
const WIN32_CALLOUT_JOB_OFF: u64 = 5 * 8;

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
/// `PROCESSINFO.pW32Job`, immediately after `dwLpkEntryPoints` in the NT5/ReactOS layout.
const PROCESSINFO_PW32JOB_OFF: u64 = 0x260;
/// ReactOS 0.4.17 `gAtomTable` pointer cell. `NtUserRegisterWindowMessage`'s call to `IntAddAtom`
/// loads this cell at image VA 0x21bfd8 (RVA 0x20bfd8); the job namespace wrapper substitutes only
/// for the two global-atom user services and restores it before returning.
const G_ATOM_TABLE_RVA: u64 = 0x20_BFD8;
static WIN32K_SESSION_ATOM_TABLE: AtomicU64 = AtomicU64::new(0);
/// PROCESSINFO->HeapMappings (`win32.h`). The first embedded entry is the global USER heap; its
/// `Next` chain holds per-desktop heap mappings for DesktopHeapGetUserDelta/DesktopHeapAddressToUser.
const PROCESSINFO_HEAP_MAPPINGS_OFF: u64 = 0x340;
const W32PROCESS_PEPROCESS_OFF: u64 = 0x00;
const W32PROCESS_FLAGS_OFF: u64 = 0x0C;
const W32PROCESS_W32PID_OFF: u64 = 0x40;
const W32HEAP_MAPPING_NEXT_OFF: u64 = 0x00;
const W32HEAP_MAPPING_KERNEL_OFF: u64 = 0x08;
const W32HEAP_MAPPING_USER_OFF: u64 = 0x10;
const W32HEAP_MAPPING_LIMIT_OFF: u64 = 0x18;
const W32HEAP_MAPPING_COUNT_OFF: u64 = 0x20;
const W32HEAP_MAPPING_SIZE: u64 = 0x28;
const W32PF_CREATEDWINORDC: u32 = 0x0400_0000;
const W32PF_READSCREENACCESSGRANTED: u32 = 0x0000_0010;
const WINSTA_ALL_ACCESS: u32 = 0x000f_037f;
const FIRST_USER_HANDLE: u64 = 0x20;
const LAST_USER_HANDLE: u64 = 0xFFEF;
const USER_HANDLE_ENTRY_SIZE: u64 = 0x18;
const USER_HANDLE_ENTRY_OWNER_OFF: u64 = 0x08;
const USER_HANDLE_ENTRY_TYPE_OFF: u64 = 0x10;
const USER_HANDLE_ENTRY_FLAGS_OFF: u64 = 0x11;
const USER_HANDLE_ENTRY_GENERATION_OFF: u64 = 0x12;
const USER_HANDLE_FLAG_GRANTED: u8 = 0x20;
/// WND->head.pti offset (ntuser.h: THRDESKHEAD at +0).
const WND_HEAD_PTI_OFF: u64 = 0x10;
const WND_EXSTYLE_OFF: u64 = 0x30;
const WND_STYLE_OFF: u64 = 0x34;
const WND_FNID_OFF: u64 = 0x40;
const WND_SPWND_NEXT_OFF: u64 = 0x48;
const WND_SPWND_PREV_OFF: u64 = 0x50;
const WND_SPWND_PARENT_OFF: u64 = 0x58;
const WND_SPWND_CHILD_OFF: u64 = 0x60;
const WND_PCLS_OFF: u64 = 0x98;
const CLS_PDCE_OFF: u64 = 0x18;
const CLS_STYLE_OFF: u64 = 0x54;
const SSN_NT_USER_CALL_ONE_PARAM: u64 = 0x1002;
const SSN_NT_USER_MESSAGE_CALL: u64 = 0x1007;
const SSN_NT_USER_POST_MESSAGE: u64 = 0x100E;
const SSN_NT_USER_UNHOOK_WINDOWS_HOOK_EX: u64 = 0x1070;
const SSN_NT_USER_SET_WINDOWS_HOOK_EX: u64 = 0x108D;
const SSN_NT_USER_SET_WIN_EVENT_HOOK: u64 = 0x1109;
const SSN_NT_USER_UNHOOK_WIN_EVENT: u64 = 0x110A;
const SSN_NT_USER_SET_WINDOW_LONG: u64 = 0x105b;
const SSN_NT_USER_SET_WINDOW_LONG_PTR: u64 = 0x1298;
const SSN_NT_USER_GET_DC: u64 = 0x100a;
const GWLP_WNDPROC_INDEX_U32: u64 = 0xffff_fffc;
const ONEPARAM_ROUTINE_GETKEYBOARDLAYOUT: u64 = 0x28;
const HWND_BROADCAST: u64 = 0xFFFF;
const HWND_TOPMOST: u64 = u64::MAX;
const FNID_MENU: u32 = 0x029C;
const FNID_DESKTOP: u32 = 0x029D;
const FNID_SWITCH: u32 = 0x02A0;
const FNID_SENDMESSAGE: u64 = 0x02B1;
const FNID_SENDMESSAGEFF: u64 = 0x02B2;
const FNID_SENDMESSAGEWTOOPTION: u64 = 0x02B3;
const FNID_BROADCASTSYSTEMMESSAGE: u64 = 0x02B5;
const FNID_SENDNOTIFYMESSAGE: u64 = 0x02B7;
const FNID_SENDMESSAGECALLBACK: u64 = 0x02B8;
const BSM_APPLICATIONS: u32 = 0x0000_0008;
const BSM_ALLDESKTOPS: u32 = 0x0000_0010;
const BSF_QUERY: u32 = 0x0000_0001;
const BSF_IGNORECURRENTTASK: u32 = 0x0000_0002;
const BSF_NOHANG: u32 = 0x0000_0008;
const BSF_POSTMESSAGE: u32 = 0x0000_0010;
const BSF_FORCEIFHUNG: u32 = 0x0000_0020;
const BSF_NOTIMEOUTIFNOTHUNG: u32 = 0x0000_0040;
const SMTO_ABORTIFHUNG: u32 = 0x0000_0002;
const SMTO_NOTIMEOUTIFNOTHUNG: u32 = 0x0000_0008;
const BROADCAST_QUERY_DENY: u64 = 1_112_363_332;
const WM_USER: u32 = 0x0400;
const REGISTERED_MESSAGE_FIRST: u32 = 0xC000;
static WIN32K_EXPLORER_SETWNDPROC_CLIENT_CALLS: AtomicU64 = AtomicU64::new(0);
static WIN32K_EXPLORER_SETWNDPROC_REPLAY_CALLS: AtomicU64 = AtomicU64::new(0);
static WIN32K_GDI_HANDLE_MISMATCH_TRACES: AtomicU64 = AtomicU64::new(0);

/// THREADINFO->rpdesk offset (win32.h: W32THREAD prefix 0x50, then ptl@0x50, ppi@0x58,
/// MessageQueue@0x60, KeyboardLayout@0x68, pcti@0x70, **rpdesk@0x78**, pDeskInfo@0x80). The thread's
/// currently-assigned DESKTOP object — `IntSetThreadDesktop` sets it (desktop.c:3428).
const THREADINFO_RPDESK_OFF: u64 = 0x78;
const THREADINFO_MESSAGE_QUEUE_OFF: u64 = 0x60;
const THREADINFO_KEYBOARD_LAYOUT_OFF: u64 = 0x68;
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
const THREADINFO_FLAGS_OFF: u64 = 0x90;
const THREADINFO_PCTI_OFF: u64 = 0x70;
/// THREADINFO.cti, the embedded CLIENTTHREADINFO used while a thread has no desktop. ReactOS
/// initializes `pcti = &cti` and only replaces it with desktop-heap storage in IntSetThreadDesktop.
const THREADINFO_EMBEDDED_CTI_OFF: u64 = 0x2A8;
const TIF_SYSTEMTHREAD: u32 = 0x0000_0004;
const TIF_CSRSSTHREAD: u32 = 0x0000_0008;
const CLIENTTHREADINFO_SIZE: u64 = 0x20;
const CLIENTINFO_PDESKINFO_OFF: u64 = 0x20;
const CLIENTINFO_ULCLIENTDELTA_OFF: u64 = 0x28;
const CLIENTINFO_PCLIENTTHREADINFO_OFF: u64 = 0x60;
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
/// KL layout and CLIENTINFO.{hKL,CodePage}. ReactOS' `tagKL` starts with `HEAD` (16 bytes on x64),
/// then the pklNext/pklPrev ring, flags, hkl, spkf, font sigs/base charset, and CodePage.
const KL_PKL_PREV_OFF: u64 = 0x18;
const KL_FLAGS_OFF: u64 = 0x20;
const KL_HKL_OFF: u64 = 0x28;
const KL_CODEPAGE_OFF: u64 = 0x40;
const KL_UNLOAD: u32 = 0x2000_0000;
const WIN32K_KL_WALK_LIMIT: usize = 64;
const CLIENTINFO_HKL_OFF: u64 = 0x90;
const CLIENTINFO_CODEPAGE_OFF: u64 = 0x98;
/// USER_MESSAGE_QUEUE offsets used by ReactOS `MsqInitializeMessageQueue`.
const USER_MESSAGE_QUEUE_PTI_MOUSE_OFF: u64 = 0x28;
const USER_MESSAGE_QUEUE_PTI_KEYBOARD_OFF: u64 = 0x30;
const USER_MESSAGE_QUEUE_HARDWARE_MESSAGES_OFF: u64 = 0x38;
const USER_MESSAGE_QUEUE_CTHREADS_OFF: u64 = 0xB0;
const SSN_NT_USER_LOAD_KEYBOARD_LAYOUT_EX: u64 = 0x125c;
static WIN32K_DEFAULT_KEYBOARD_LAYOUT: AtomicU64 = AtomicU64::new(0);
static WIN32K_KEYBOARD_LAYOUT_OBSERVES: AtomicU64 = AtomicU64::new(0);
static WIN32K_KEYBOARD_LAYOUT_BINDINGS: AtomicU64 = AtomicU64::new(0);

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

/// win32k `.data` global `gspklBaseLayout` (`kbdlayout.c:22`) RVA. Derived from this build's
/// disassembly:
///   * VMA 0x9ff20 is `W32kGetDefaultKeyLayout`: it reads 0x21bf40, tests `KL.dwKL_Flags` (+0x20)
///     for `KL_UNLOAD`, then follows `pklPrev` (+0x18) until it returns to the same global.
///   * win32k.sys ImageBase is 0x10000, so VMA 0x21bf40 maps to RVA 0x20bf40.
pub const GSPKL_BASE_LAYOUT_RVA: u64 = 0x20bf40;

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
/// SSN NtUserSetProcessWindowStation — win32k's real PROCESSINFO/EPROCESS station association.
pub const SSN_NT_USER_SET_PROCESS_WINDOW_STATION: u64 = 0x10ac;

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

pub const DESKTOP_HSECTION_OFF: u64 = 0x78;
/// DESKTOP.pheapDesktop offset (`desktop.h` `struct _DESKTOP`: dwSessionId@0, pDeskInfo@8,
/// ListEntry@0x10, rpwinstaParent@0x20, ..., hsectionDesktop@0x78, **pheapDesktop@0x80**). The
/// per-desktop USER heap handle `DesktopHeapAlloc → RtlAllocateHeap(pdesk->pheapDesktop, ...)` uses
/// (callproc.c CreateCallProc / object.c AllocDeskProcObject). A NULL here is the REAL cr2=0x80 fault
/// at win32k RVA 0x4f5e3 (`mov rax,[rsp+0x40]=pdesk; mov rcx,[rax+0x80]=pheapDesktop; call
/// RtlAllocateHeap`). Matches `nt_object_manager::win32k_ob::desktop` (pheapDesktop@0x80).
pub const DESKTOP_PHEAP_OFF: u64 = 0x80;
pub const DESKTOP_UL_HEAP_SIZE_OFF: u64 = 0x88;

const DESKTOPINFO_PV_DESKTOP_BASE_OFF: u64 = 0x00;
const DESKTOPINFO_PV_DESKTOP_LIMIT_OFF: u64 = 0x08;
const DESKTOPINFO_APHK_START_OFF: u64 = 0x20;
const DESKTOPINFO_HOOK_COUNT: u64 = 16; // WH_MINHOOK(-1)..WH_MAXHOOK(14)
const DESKTOPINFO_NAME_OFF: u64 = 0x154;
const DESKTOPINFO_MIN_ALLOC: u64 = 0x158;
const DESKTOP_HEAP_INTERACTIVE_BYTES: u64 = 3 * 1024 * 1024;
const DESKTOP_HEAP_NONINTERACTIVE_BYTES: u64 = 512 * 1024;
const DESKTOP_HEAP_WINLOGON_BYTES: u64 = 128 * 1024;

/// SSN of NtUserCreateDesktop (WIN32K_SERVICE_BASE 0x1000 + SSDT idx 0x22d). When a hosted client
/// (winlogon) drives its own CreateWindowStation→CreateDesktop→SwitchDesktop chain, its
/// naturally-created DESKTOP objects come through the routed `dispatch_ssn` path; Ob creation now
/// populates `pdesk->rpwinstaParent` and the section-backed desktop heap before the handle is returned.
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
/// A component-side `EngDeviceIoControl` request. The display driver and win32k run in the win32k
/// component, while hosted video miniport IRPs belong to the executive's generic IO manager.
pub const W32_VIDEO_IOCTL_LABEL: u64 = 0x775;
/// A component-side kernel LPC request. Broker capabilities stay executive-owned; the component
/// passes only an operation, an opaque broker handle, and a bounded native PORT_MESSAGE frame.
pub const W32_LPC_LABEL: u64 = 0x776;
/// A component-side registry request. The component stages bounded ASCII path/value bytes and the
/// executive performs the operation through Configuration Manager using an opaque leased handle.
pub const W32_REGISTRY_LABEL: u64 = 0x777;
/// Pointer-free Event object ownership requests. The component passes only scalar process handles,
/// generation-protected ids, and provider-body projections; the executive owns canonical identity.
pub const W32_EVENT_LABEL: u64 = 0x778;
/// Provider dispatcher wait request. Root may answer immediately or retain the component Call while
/// its native client continuation is parked.
pub const W32_PROVIDER_WAIT_LABEL: u64 = 0x779;
/// Request tag returned on the retained component Call after the exact wait is selected, times out,
/// or is cancelled. The correlated status lives in the dedicated provider-wait result frame.
pub const W32_PROVIDER_WAIT_RESUME_LABEL: u64 = 0x77A;
pub const W32_EVENT_OP_CREATE: u64 = 1;
pub const W32_EVENT_OP_REFERENCE: u64 = 2;
pub const W32_EVENT_OP_CLOSE: u64 = 3;
pub const W32_EVENT_OP_DEREFERENCE: u64 = 4;
pub const W32_EVENT_OP_DRAIN_RECLAIM: u64 = 5;
pub const W32_EVENT_OP_ACK_RECLAIM: u64 = 6;
pub const W32_EVENT_OP_RETAIN_POINTER: u64 = 7;
pub const W32_EVENT_OP_SET: u64 = 8;
pub const W32_EVENT_OP_RESET: u64 = 9;
pub const W32_EVENT_OP_CLEAR: u64 = 10;
pub const W32_EVENT_OP_PULSE: u64 = 11;
pub const W32_EVENT_OP_READ: u64 = 12;
pub const W32_EVENT_OP_PUBLISH_LOCAL: u64 = 13;
pub const W32_EVENT_OP_RETIRE_LOCAL: u64 = 14;
pub const W32_EVENT_OP_ACK_LOCAL_RETIREMENT: u64 = 15;
pub const W32_EVENT_OP_SET_LOCAL: u64 = 16;
pub const W32_EVENT_OP_RESET_LOCAL: u64 = 17;
pub const W32_EVENT_OP_CLEAR_LOCAL: u64 = 18;
pub const W32_EVENT_OP_PULSE_LOCAL: u64 = 19;
pub const W32_EVENT_OP_READ_LOCAL: u64 = 20;

static mut WIN32K_EVENT_PROJECTIONS: nt_kernel_exec::ProviderEventProjectionCatalog =
    nt_kernel_exec::ProviderEventProjectionCatalog::new();
static mut WIN32K_LPC_PORT_REFERENCES: nt_object_manager::win32k_ob::ExternalObjectReferenceTable =
    nt_object_manager::win32k_ob::ExternalObjectReferenceTable::new();

fn provider_event_projection_contains(body: u64) -> bool {
    unsafe { (&*core::ptr::addr_of!(WIN32K_EVENT_PROJECTIONS)).contains(body) }
}

unsafe fn provider_event_projection_reserve() -> bool {
    (&mut *core::ptr::addr_of_mut!(WIN32K_EVENT_PROJECTIONS))
        .reserve_one()
        .is_ok()
}

unsafe fn provider_event_projection_register_reserved(body: u64, raw_id: u64) -> bool {
    (&mut *core::ptr::addr_of_mut!(WIN32K_EVENT_PROJECTIONS))
        .register_reserved(
            body,
            nt_kernel_exec::EventObjectId(nt_types::ObjectId(raw_id)),
        )
        .is_ok()
}

unsafe fn provider_event_projection_remove(body: u64) -> bool {
    (&mut *core::ptr::addr_of_mut!(WIN32K_EVENT_PROJECTIONS))
        .remove(body)
        .is_ok()
}

const VIDEO_IOCTL_HDEV: u64 = 0x00;
const VIDEO_IOCTL_CODE: u64 = 0x08;
const VIDEO_IOCTL_IN_LEN: u64 = 0x10;
const VIDEO_IOCTL_OUT_LEN: u64 = 0x18;
const VIDEO_IOCTL_STATUS: u64 = 0x20;
const VIDEO_IOCTL_BYTES_RETURNED: u64 = 0x28;
const VIDEO_IOCTL_IN_BUF: u64 = 0x100;
const VIDEO_IOCTL_IN_CAP: usize = 0x1000;
const VIDEO_IOCTL_OUT_BUF: u64 = VIDEO_IOCTL_IN_BUF + VIDEO_IOCTL_IN_CAP as u64;
const VIDEO_IOCTL_OUT_CAP: usize = WIN32K_VIDEO_IOCTL_BYTES - VIDEO_IOCTL_OUT_BUF as usize;
const _: () =
    assert!(VIDEO_IOCTL_OUT_BUF as usize + VIDEO_IOCTL_OUT_CAP <= WIN32K_VIDEO_IOCTL_BYTES);
static WIN32K_VIDEO_IOCTL_TRACE: AtomicU64 = AtomicU64::new(0);
static WIN32K_VIDEO_IOCTL_REQUEST_TRACE: AtomicU64 = AtomicU64::new(0);
static GDI_DRIVER_IMPORT_TRACE: AtomicU64 = AtomicU64::new(0);

const LPC_SERVICE_PORT_HANDLE: u64 = 0x00;
const LPC_SERVICE_OPERATION: u64 = 0x08;
const LPC_SERVICE_STATUS: u64 = 0x0c;
const LPC_SERVICE_MESSAGE_LEN: u64 = 0x10;
const LPC_SERVICE_RESULT: u64 = 0x18;
const LPC_SERVICE_MESSAGE: u64 = 0x100;
const LPC_SERVICE_QUERY_HANDLE: u32 = 1;
const LPC_SERVICE_RETAIN_PORT: u32 = 2;
const LPC_SERVICE_RELEASE_PORT: u32 = 3;
const LPC_SERVICE_RETAINED_REQUEST_PORT: u32 = 4;
const LPC_SERVICE_MESSAGE_CAP: usize = nt_lpc_abi::PORT_MESSAGE_MAX_LEN;
const _: () = assert!(LPC_SERVICE_MESSAGE as usize + LPC_SERVICE_MESSAGE_CAP <= WIN32K_LPC_BYTES);

// --- pool allocator (host-side; the trampolines run in the component) ------------------------
//
// The main provider arena uses the same checked header/free-list machinery as the hosted RTL heaps
// below. Direct component allocations request explicit zeroing; ExAllocatePool* retains native
// nonzeroing semantics. This distinction prevents stale host object state without turning provider
// pool reuse into an implicit success fallback.

pub type ProviderPoolCensus = shared_pool::PoolCensus;

struct ProviderPoolMemory;

impl shared_pool::PoolMemory for ProviderPoolMemory {
    fn len(&self) -> u64 {
        WIN32K_POOL_FRAMES * 0x1000
    }

    fn read_u64(&self, offset: u64) -> Option<u64> {
        if offset.checked_add(8)? > self.len() || offset & 7 != 0 {
            return None;
        }
        Some(unsafe { read_volatile((WIN32K_POOL_VADDR + offset) as *const u64) })
    }

    fn write_u64(&mut self, offset: u64, value: u64) -> bool {
        if offset.checked_add(8).is_none_or(|end| end > self.len()) || offset & 7 != 0 {
            return false;
        }
        unsafe { write_volatile((WIN32K_POOL_VADDR + offset) as *mut u64, value) };
        true
    }

    fn zero(&mut self, offset: u64, len: u64) -> bool {
        if offset.checked_add(len).is_none_or(|end| end > self.len()) {
            return false;
        }
        unsafe { core::ptr::write_bytes((WIN32K_POOL_VADDR + offset) as *mut u8, 0, len as usize) };
        true
    }
}

struct ProviderPoolLockGuard;

impl Drop for ProviderPoolLockGuard {
    fn drop(&mut self) {
        unsafe {
            (&*((WIN32K_POOL_VADDR + shared_pool::LOCK_OFFSET) as *const AtomicU64))
                .store(0, Ordering::Release);
        }
    }
}

fn provider_pool_ready() -> bool {
    unsafe {
        (&*((WIN32K_POOL_VADDR + shared_pool::MAGIC_OFFSET) as *const AtomicU64))
            .load(Ordering::Acquire)
            == shared_pool::MAGIC
    }
}

unsafe fn provider_pool_lock() -> Option<ProviderPoolLockGuard> {
    if !provider_pool_ready() {
        return None;
    }
    let lock = &*((WIN32K_POOL_VADDR + shared_pool::LOCK_OFFSET) as *const AtomicU64);
    while lock
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        crate::yield_now();
    }
    Some(ProviderPoolLockGuard)
}

/// Initialize the already mapped provider arena exactly once, before the component is spawned.
pub unsafe fn initialize_provider_pool() -> bool {
    let magic = &*((WIN32K_POOL_VADDR + shared_pool::MAGIC_OFFSET) as *const AtomicU64);
    if magic.load(Ordering::Relaxed) != 0 {
        return false;
    }
    let mut memory = ProviderPoolMemory;
    if shared_pool::initialize(&mut memory).is_err() {
        return false;
    }
    magic.store(shared_pool::MAGIC, Ordering::Release);
    true
}

pub fn provider_pool_census() -> ProviderPoolCensus {
    unsafe {
        let Some(_guard) = provider_pool_lock() else {
            return ProviderPoolCensus::default();
        };
        shared_pool::census(&ProviderPoolMemory).unwrap_or_default()
    }
}

unsafe fn provider_pool_alloc(size: u64, zero: bool) -> u64 {
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_SHARED_POOL_ID) else {
        return 0;
    };
    let allocation = {
        let Some(_guard) = provider_pool_lock() else {
            print_str(b"[win32k-host] provider pool is not initialized\n");
            crate::WIN32K_POOL_EXHAUSTIONS.fetch_add(1, Ordering::Relaxed);
            return 0;
        };
        let mut memory = ProviderPoolMemory;
        match shared_pool::allocate(&mut memory, size, zero) {
            Ok(allocation) => allocation,
            Err(error) => {
                crate::WIN32K_POOL_EXHAUSTIONS.fetch_add(1, Ordering::Relaxed);
                print_str(b"[win32k-host] provider pool allocation failed reason=");
                print_u64(error as u64);
                print_str(b" size=0x");
                print_hex(size as u32);
                print_str(b"\n");
                return 0;
            }
        }
    };
    let payload = WIN32K_POOL_VADDR + allocation.payload_offset;
    if register_provider_allocation(arena, payload, allocation.capacity).is_some() {
        return payload;
    }
    if let Some(_guard) = provider_pool_lock() {
        let mut memory = ProviderPoolMemory;
        if shared_pool::allocation_identity(&memory, allocation.payload_offset)
            == Ok(allocation.identity)
        {
            let _ = shared_pool::free(&mut memory, allocation.payload_offset);
        }
    }
    crate::WIN32K_POOL_EXHAUSTIONS.fetch_add(1, Ordering::Relaxed);
    0
}

fn provider_pool_contains(p: u64) -> bool {
    p >= WIN32K_POOL_VADDR + shared_pool::DATA_OFFSET + shared_pool::HEADER_SIZE
        && p < WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000
}

unsafe fn provider_pool_allocation_capacity(p: u64) -> Option<u64> {
    if !provider_pool_contains(p) {
        return None;
    }
    let _guard = provider_pool_lock()?;
    shared_pool::allocation_capacity(&ProviderPoolMemory, p - WIN32K_POOL_VADDR).ok()
}

unsafe fn provider_pool_validate_owned(objects: &[(u64, u64)]) -> bool {
    let Some(_guard) = provider_pool_lock() else {
        return false;
    };
    let memory = ProviderPoolMemory;
    for (index, &(pointer, required)) in objects.iter().enumerate() {
        if pointer == 0 || !provider_pool_contains(pointer) {
            return false;
        }
        if objects[..index]
            .iter()
            .any(|&(previous, _)| previous == pointer)
        {
            return false;
        }
        if !matches!(
            shared_pool::allocation_capacity(&memory, pointer - WIN32K_POOL_VADDR),
            Ok(capacity) if capacity >= required
        ) {
            return false;
        }
    }
    true
}

unsafe fn provider_pool_release_owned(objects: &[(u64, u64)]) -> bool {
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_SHARED_POOL_ID) else {
        return false;
    };
    let mut shared_identities = Vec::new();
    let mut tracked_allocations = Vec::new();
    if shared_identities.try_reserve(objects.len()).is_err()
        || tracked_allocations.try_reserve(objects.len()).is_err()
    {
        return false;
    }
    {
        let Some(_guard) = provider_pool_lock() else {
            return false;
        };
        let memory = ProviderPoolMemory;
        for (index, &(pointer, required)) in objects.iter().enumerate() {
            if pointer == 0
                || !provider_pool_contains(pointer)
                || objects[..index]
                    .iter()
                    .any(|&(previous, _)| previous == pointer)
            {
                return false;
            }
            let offset = pointer - WIN32K_POOL_VADDR;
            let Ok(capacity) = shared_pool::allocation_capacity(&memory, offset) else {
                return false;
            };
            let Ok(identity) = shared_pool::allocation_identity(&memory, offset) else {
                return false;
            };
            if capacity < required {
                return false;
            }
            shared_identities.push(identity);
        }
    }
    for &(pointer, required) in objects {
        let Some(allocation) =
            validate_provider_allocation_retirement(arena, pointer, required)
        else {
            return false;
        };
        tracked_allocations.push(allocation);
    }
    if tracked_allocations
        .iter()
        .copied()
        .any(|allocation| !validate_provider_allocation_event_retirement(allocation))
    {
        return false;
    }
    for allocation in tracked_allocations.iter().copied() {
        if !retire_provider_allocation_events(allocation) {
            print_str(b"[win32k-host] fatal provider-pool Event retirement commit failure\n");
            park();
        }
    }
    {
        let Some(_guard) = provider_pool_lock() else {
            print_str(b"[win32k-host] fatal provider-pool lock loss during release commit\n");
            park();
        };
        let mut memory = ProviderPoolMemory;
        for (index, &(pointer, _)) in objects.iter().enumerate() {
            let offset = pointer - WIN32K_POOL_VADDR;
            if shared_pool::allocation_identity(&memory, offset) != Ok(shared_identities[index])
                || shared_pool::free(&mut memory, offset).is_err()
            {
                print_str(b"[win32k-host] fatal provider-pool allocator release commit failure\n");
                park();
            }
        }
    }
    for allocation in tracked_allocations {
        if !retire_provider_allocation(allocation) {
            print_str(b"[win32k-host] fatal provider-pool catalog release commit failure\n");
            park();
        }
    }
    true
}

unsafe fn provider_pool_free(p: u64) -> bool {
    provider_pool_release_owned(&[(p, 1)])
}

unsafe fn provider_pool_note_invalid_free() {
    if let Some(_guard) = provider_pool_lock() {
        let _ = shared_pool::note_invalid_free(&mut ProviderPoolMemory);
    }
}

unsafe fn pool_alloc(size: u64) -> u64 {
    provider_pool_alloc(size, true)
}

/// A separate reclaiming arena for allocations with explicit lifetime. FreeType first required it
/// for `EngAllocMem(TAG_FREETYPE)` churn; allocated RTL strings use the same allocator so
/// `RtlFreeUnicodeString` has matching ownership. Counter at +0, address-ordered free-list head at
/// +8, payload starts at +0x1000.
pub const WIN32K_FTYP_VADDR: u64 = 0x0000_0100_0B00_0000;
pub const WIN32K_FTYP_FRAMES: u64 = 512; // 2 MiB (own window, pre-mapped)
/// FreeType's `EngAllocMem` tag ('FTYP', little-endian) — see the ftfd ft_alloc disasm.
pub const FTYP_TAG: u64 = 0x5059_5446;

const FTYP_HDR_SIZE: u64 = 16;
const FTYP_ALLOC_MARKER: u64 = 0xffff_ffff_ffff_fffe;

fn align16(size: u64) -> u64 {
    (size + 15) & !15
}

unsafe fn reclaiming_pool_alloc_raw(size: u64) -> u64 {
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

unsafe fn reclaiming_pool_capacity(p: u64) -> Option<u64> {
    let arena_start = WIN32K_FTYP_VADDR + POOL_DATA_OFF;
    let arena_end = WIN32K_FTYP_VADDR + WIN32K_FTYP_FRAMES * 0x1000;
    if p < arena_start + FTYP_HDR_SIZE || p >= arena_end || (p & 15) != 0 {
        return None;
    }
    let hdr = p - FTYP_HDR_SIZE;
    let cap = read_volatile(hdr as *const u64);
    let marker = read_volatile((hdr + 8) as *const u64);
    if marker != FTYP_ALLOC_MARKER || cap == 0 || (cap & 15) != 0 {
        return None;
    }
    if hdr < arena_start || hdr + FTYP_HDR_SIZE + cap > arena_end {
        return None;
    }
    Some(cap)
}

unsafe fn reclaiming_pool_alloc(size: u64) -> u64 {
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_FTYP_POOL_ID) else {
        return 0;
    };
    let payload = reclaiming_pool_alloc_raw(size);
    if payload == 0 {
        return 0;
    }
    let Some(capacity) = reclaiming_pool_capacity(payload) else {
        return 0;
    };
    if register_provider_allocation(arena, payload, capacity).is_some() {
        payload
    } else {
        let _ = reclaiming_pool_free_raw(payload);
        0
    }
}

unsafe fn reclaiming_pool_free_raw(p: u64) -> bool {
    let Some(cap) = reclaiming_pool_capacity(p) else {
        return false;
    };
    let hdr = p - FTYP_HDR_SIZE;

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
    true
}

unsafe fn reclaiming_pool_free(p: u64) -> bool {
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_FTYP_POOL_ID) else {
        return false;
    };
    let Some(allocation) = validate_provider_allocation_retirement(arena, p, 1) else {
        return false;
    };
    if reclaiming_pool_capacity(p) != Some(allocation.capacity)
        || !validate_provider_allocation_event_retirement(allocation)
        || !retire_provider_allocation_events(allocation)
        || !reclaiming_pool_free_raw(p)
    {
        return false;
    }
    retire_provider_allocation(allocation)
}

/// User-mode VM arena for `ZwAllocateVirtualMemory(NtCurrentProcess(), ...)`. win32k's GDI attribute
/// pool ([`GdiPoolAllocateSection`], win32ss/gdi/ntgdi/gdipool.c) reserves a 64 KiB user-mode region
/// per pool section (`MEM_RESERVE`) then commits pages on demand (`MEM_COMMIT`) — the DC_ATTR /
/// RGN_ATTR storage. In this single-address-space host the whole arena is pre-mapped RW, so RESERVE
/// hands out a tracked 64 KiB slot run, COMMIT is a no-op, and MEM_RELEASE returns slots for later
/// GUI-capable service clients. Own 2 MiB-aligned window + PTs (spawn_win32k_host).
pub const WIN32K_USERVM_VADDR: u64 = 0x0000_0100_0C00_0000;
pub const WIN32K_USERVM_FRAMES: u64 = 1024; // 4 MiB, pre-mapped (64 GDI-pool sections)
const USERVM_GRANULARITY: u64 = 0x1_0000;
const USERVM_SLOT_COUNT: usize = ((WIN32K_USERVM_FRAMES * 0x1000) / USERVM_GRANULARITY) as usize;
const USERVM_FIRST_SLOT: usize = 1; // slot 0 stays reserved for arena metadata/sentinel space
static WIN32K_USERVM_NEXT_SLOT: AtomicU64 = AtomicU64::new(USERVM_FIRST_SLOT as u64);
static WIN32K_USERVM_FREE_MASK: AtomicU64 = AtomicU64::new(0);
static WIN32K_USERVM_ALLOC_MASK: AtomicU64 = AtomicU64::new(0);
static WIN32K_USERVM_RUN_SLOTS: [AtomicU64; USERVM_SLOT_COUNT] =
    [const { AtomicU64::new(0) }; USERVM_SLOT_COUNT];

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

fn uservm_mask(slot: usize, slots: usize) -> Option<u64> {
    if slots == 0 || slot < USERVM_FIRST_SLOT || slot + slots > USERVM_SLOT_COUNT {
        return None;
    }
    if slots >= 64 {
        return Some(u64::MAX << slot);
    }
    Some(((1u64 << slots) - 1) << slot)
}

fn uservm_slots_for(size: u64) -> Option<usize> {
    if size == 0 {
        return None;
    }
    let bytes = size.max(USERVM_GRANULARITY);
    let slots = ((bytes + USERVM_GRANULARITY - 1) / USERVM_GRANULARITY) as usize;
    if slots == 0 || slots > USERVM_SLOT_COUNT - USERVM_FIRST_SLOT {
        None
    } else {
        Some(slots)
    }
}

fn uservm_slot_base(slot: usize) -> u64 {
    WIN32K_USERVM_VADDR + slot as u64 * USERVM_GRANULARITY
}

unsafe fn uservm_publish_run(slot: usize, slots: usize, mask: u64) -> u64 {
    WIN32K_USERVM_ALLOC_MASK.fetch_or(mask, Ordering::Relaxed);
    for index in slot..slot + slots {
        WIN32K_USERVM_RUN_SLOTS[index].store(0, Ordering::Relaxed);
    }
    WIN32K_USERVM_RUN_SLOTS[slot].store(slots as u64, Ordering::Relaxed);
    let base = uservm_slot_base(slot);
    core::ptr::write_bytes(base as *mut u8, 0, slots * USERVM_GRANULARITY as usize);
    base
}

unsafe fn uservm_alloc(size: u64) -> u64 {
    let Some(slots) = uservm_slots_for(size) else {
        return 0;
    };

    let free_mask = WIN32K_USERVM_FREE_MASK.load(Ordering::Relaxed);
    for slot in USERVM_FIRST_SLOT..=USERVM_SLOT_COUNT - slots {
        let Some(mask) = uservm_mask(slot, slots) else {
            continue;
        };
        if free_mask & mask == mask {
            WIN32K_USERVM_FREE_MASK.fetch_and(!mask, Ordering::Relaxed);
            return uservm_publish_run(slot, slots, mask);
        }
    }

    let mut next_slot = WIN32K_USERVM_NEXT_SLOT.load(Ordering::Relaxed) as usize;
    if !(USERVM_FIRST_SLOT..=USERVM_SLOT_COUNT).contains(&next_slot) {
        next_slot = USERVM_FIRST_SLOT;
    }
    if next_slot + slots > USERVM_SLOT_COUNT {
        print_str(b"[win32k-host] USERVM EXHAUSTED size=0x");
        print_hex(size as u32);
        print_str(b" next_slot=0x");
        print_hex(next_slot as u32);
        print_str(b" free_mask=0x");
        print_u64(free_mask);
        print_str(b"\n");
        return 0;
    }
    let Some(mask) = uservm_mask(next_slot, slots) else {
        return 0;
    };
    WIN32K_USERVM_NEXT_SLOT.store((next_slot + slots) as u64, Ordering::Relaxed);
    uservm_publish_run(next_slot, slots, mask)
}

unsafe fn uservm_release(base: u64) -> bool {
    let arena_end = WIN32K_USERVM_VADDR + WIN32K_USERVM_FRAMES * 0x1000;
    if base < uservm_slot_base(USERVM_FIRST_SLOT)
        || base >= arena_end
        || (base - WIN32K_USERVM_VADDR) % USERVM_GRANULARITY != 0
    {
        return false;
    }
    let slot = ((base - WIN32K_USERVM_VADDR) / USERVM_GRANULARITY) as usize;
    if slot >= USERVM_SLOT_COUNT {
        return false;
    }
    let slots = WIN32K_USERVM_RUN_SLOTS[slot].load(Ordering::Relaxed) as usize;
    let Some(mask) = uservm_mask(slot, slots) else {
        return false;
    };
    if WIN32K_USERVM_ALLOC_MASK.load(Ordering::Relaxed) & mask != mask {
        return false;
    }
    WIN32K_USERVM_ALLOC_MASK.fetch_and(!mask, Ordering::Relaxed);
    WIN32K_USERVM_FREE_MASK.fetch_or(mask, Ordering::Relaxed);
    for index in slot..slot + slots {
        WIN32K_USERVM_RUN_SLOTS[index].store(0, Ordering::Relaxed);
    }
    true
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
const STATUS_NOT_IMPLEMENTED_I32: i32 = 0xC000_0002u32 as i32;
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
const WIN32K_TOKEN_HANDLE_INITIAL_CAP: u64 = 8;
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
    if !process_ctx_index_valid(process_index)
        || token_authentication_id == 0
        || token_user_sid_len == 0
        || token_user_sid_len > WIN32K_TOKEN_USER_SID_MAX
        || token_user_sid_len > token_user_sid.len()
    {
        let n = WIN32K_CLIENT_TOKEN_CONTEXT_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            let pid = if process_ctx_index_valid(process_index) {
                process_ctx_pid(process_index)
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
    set_process_ctx_token_authentication_id(process_index, token_authentication_id);

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
    if !process_ctx_index_valid(process_index) {
        return 0;
    }
    let token_authentication_id = process_ctx_token_authentication_id(process_index);
    if token_authentication_id == 0 {
        return 0;
    }
    let existing = process_ctx_primary_token(process_index);
    let token = if existing != 0 {
        existing
    } else {
        let allocated = allocate_kernel_object_body(WIN32K_PRIMARY_TOKEN_BYTES);
        if allocated == 0 {
            return 0;
        }
        write_volatile(allocated as *mut u64, WIN32K_PRIMARY_TOKEN_MAGIC);
        set_process_ctx_primary_token(process_index, allocated);
        WIN32K_CONTEXT_TOKEN_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        allocated
    };
    write_volatile(
        (token + TOKEN_AUTHENTICATION_ID_OFF) as *mut u64,
        token_authentication_id,
    );
    write_volatile(
        (token + TOKEN_EPROCESS_OFF) as *mut u64,
        process_ctx_eprocess(process_index),
    );
    write_volatile(
        (token + TOKEN_PID_OFF) as *mut u64,
        process_ctx_pid(process_index),
    );
    token
}

unsafe fn token_context_index(token: u64) -> Option<usize> {
    if token == 0 {
        return None;
    }
    for index in 0..process_ctx_len() {
        if process_ctx_primary_token(index) == token {
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

unsafe fn token_handle_slot_ptr(base: u64, index: u64) -> *mut u64 {
    (base + index * core::mem::size_of::<u64>() as u64) as *mut u64
}

unsafe fn ensure_token_handle_capacity(required: u64) -> bool {
    let cap = WIN32K_TOKEN_HANDLE_CAPACITY.load(Ordering::Relaxed);
    if cap >= required {
        return true;
    }
    let mut new_cap = if cap == 0 {
        WIN32K_TOKEN_HANDLE_INITIAL_CAP
    } else {
        cap.saturating_mul(2)
    };
    while new_cap < required {
        let next = new_cap.saturating_mul(2);
        if next <= new_cap {
            return false;
        }
        new_cap = next;
    }
    let Some(bytes) = (core::mem::size_of::<u64>() as u64).checked_mul(new_cap) else {
        return false;
    };
    let old_base = WIN32K_TOKEN_HANDLE_SLOTS_PTR.load(Ordering::Relaxed);
    let old_bytes = cap.checked_mul(core::mem::size_of::<u64>() as u64).unwrap_or(u64::MAX);
    if old_base != 0 && !provider_allocation_has_capacity(old_base, old_bytes) {
        return false;
    }
    let new_base = pool_alloc(bytes);
    if new_base == 0 {
        return false;
    }
    let len = WIN32K_TOKEN_HANDLE_LEN.load(Ordering::Relaxed);
    if old_base != 0 {
        for index in 0..len {
            let token = read_volatile(token_handle_slot_ptr(old_base, index));
            write_volatile(token_handle_slot_ptr(new_base, index), token);
        }
    }
    WIN32K_TOKEN_HANDLE_SLOTS_PTR.store(new_base, Ordering::Release);
    WIN32K_TOKEN_HANDLE_CAPACITY.store(new_cap, Ordering::Relaxed);
    release_replaced_context_backing(old_base);
    true
}

unsafe fn token_handle_slot(handle: u64) -> Option<u64> {
    let offset = handle.checked_sub(WIN32K_TOKEN_HANDLE_BASE)?;
    if offset % 4 != 0 {
        return None;
    }
    let index = offset / 4;
    (index < WIN32K_TOKEN_HANDLE_LEN.load(Ordering::Relaxed)).then_some(index)
}

unsafe fn register_token_handle(token: u64) -> u64 {
    if token_context_index(token).is_none() {
        return 0;
    }
    let len = WIN32K_TOKEN_HANDLE_LEN.load(Ordering::Relaxed);
    let base = WIN32K_TOKEN_HANDLE_SLOTS_PTR.load(Ordering::Acquire);
    if base != 0 {
        for index in 0..len {
            if read_volatile(token_handle_slot_ptr(base, index)) == 0 {
                let handle = WIN32K_TOKEN_HANDLE_BASE + index * 4;
                write_volatile(token_handle_slot_ptr(base, index), token);
                return handle;
            }
        }
    }
    let Some(required) = len.checked_add(1) else {
        return 0;
    };
    if !ensure_token_handle_capacity(required) {
        return 0;
    }
    let base = WIN32K_TOKEN_HANDLE_SLOTS_PTR.load(Ordering::Acquire);
    if base == 0 {
        return 0;
    }
    write_volatile(token_handle_slot_ptr(base, len), token);
    WIN32K_TOKEN_HANDLE_LEN.store(required, Ordering::Relaxed);
    WIN32K_TOKEN_HANDLE_BASE + len * 4
}

unsafe fn token_for_handle(handle: u64) -> Option<u64> {
    let slot = token_handle_slot(handle)?;
    let base = WIN32K_TOKEN_HANDLE_SLOTS_PTR.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    let token = read_volatile(token_handle_slot_ptr(base, slot));
    (token_context_index(token).is_some()).then_some(token)
}

unsafe fn close_token_handle(handle: u64) -> bool {
    let Some(slot) = token_handle_slot(handle) else {
        return false;
    };
    let base = WIN32K_TOKEN_HANDLE_SLOTS_PTR.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    let ptr = token_handle_slot_ptr(base, slot);
    let token = read_volatile(ptr);
    if token == 0 {
        return false;
    }
    write_volatile(ptr, 0);
    true
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
            .map(|index| process_ctx_pid(index))
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
            return thread_ctx_tid(index);
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
            return thread_ctx_pid(index);
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
            let pid = thread_ctx_pid(index);
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
                print_u64(process_ctx_pid(index));
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
            let w32thread = thread_ctx_w32thread(index);
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
        if w32process != 0
            && context_index.is_some_and(|index| process_ctx_terminating(index) != 0)
        {
            return 0xC000_010Au32 as i32; // STATUS_PROCESS_IS_TERMINATING
        }
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
            set_process_ctx_w32process(index, w32process);
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
                set_thread_ctx_w32thread(index, w32thread);
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

#[repr(C)]
struct Win32JobCalloutParameters {
    job: u64,
    callout_type: u32,
    _padding: u32,
    data: u64,
}

pub const PS_W32_JOB_CALLOUT_SET_INFORMATION: u32 = 0;
pub const PS_W32_JOB_CALLOUT_ADD_PROCESS: u32 = 1;
pub const PS_W32_JOB_CALLOUT_TERMINATE: u32 = 2;
/// Component-private inverse of `AddProcess`, used only if Ps publication rolls back or a real
/// W32PROCESS is deleted before its EJOB.
pub const PS_W32_JOB_CONTROL_REMOVE_PROCESS: u32 = 3;

static mut WIN32_JOB_UI_POLICY: core::mem::MaybeUninit<nt_win32k_job::JobUiPolicyStore> =
    core::mem::MaybeUninit::uninit();
static mut WIN32_JOB_UI_POLICY_INITIALIZED: bool = false;

unsafe fn win32_job_ui_policy() -> &'static mut nt_win32k_job::JobUiPolicyStore {
    if !WIN32_JOB_UI_POLICY_INITIALIZED {
        core::ptr::addr_of_mut!(WIN32_JOB_UI_POLICY).write(core::mem::MaybeUninit::new(
            nt_win32k_job::JobUiPolicyStore::new(),
        ));
        WIN32_JOB_UI_POLICY_INITIALIZED = true;
    }
    (&mut *core::ptr::addr_of_mut!(WIN32_JOB_UI_POLICY)).assume_init_mut()
}

unsafe fn set_win32_job_information(job: u64, restrictions: u32) -> u32 {
    let policy = win32_job_ui_policy();
    let token = match policy.job_token(job) {
        Some(token) => token,
        None => {
            let token = reclaiming_pool_alloc(16);
            if token == 0 {
                return nt_win32k_job::STATUS_INSUFFICIENT_RESOURCES;
            }
            write_volatile(token as *mut u64, job);
            write_volatile((token + 8) as *mut u32, restrictions);
            if let Err(status) = policy.register_job(job, token, restrictions) {
                reclaiming_pool_free(token);
                return status;
            }
            return nt_win32k_job::STATUS_SUCCESS;
        }
    };
    let members = match policy.members(job) {
        Ok(members) => members,
        Err(status) => return status,
    };
    for &process in members {
        let current = read_volatile((process + PROCESSINFO_PW32JOB_OFF) as *const u64);
        if current != 0 && current != token {
            return nt_win32k_job::STATUS_INVALID_PARAMETER;
        }
    }
    match policy.set_restrictions(job, restrictions) {
        Ok(()) => {
            write_volatile((token + 8) as *mut u32, restrictions);
            for &process in policy
                .members(job)
                .expect("registered win32k job remains live during its callout")
            {
                write_volatile(
                    (process + PROCESSINFO_PW32JOB_OFF) as *mut u64,
                    nt_win32k_job::process_job_token(restrictions, token),
                );
            }
            nt_win32k_job::STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

unsafe fn add_process_to_win32_job(job: u64, process: u64) -> u32 {
    let policy = win32_job_ui_policy();
    let Some(token) = policy.job_token(job) else {
        return nt_win32k_job::STATUS_INVALID_HANDLE;
    };
    let slot = (process + PROCESSINFO_PW32JOB_OFF) as *mut u64;
    let current = read_volatile(slot);
    if current != 0 && current != token {
        return nt_win32k_job::STATUS_ACCESS_DENIED;
    }
    match policy.add_process(job, process) {
        Ok(token) => {
            let restrictions = match policy.restrictions(job) {
                Ok(restrictions) => restrictions,
                Err(status) => return status,
            };
            write_volatile(slot, nt_win32k_job::process_job_token(restrictions, token));
            nt_win32k_job::STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

unsafe fn remove_process_from_win32_job(job: u64, process: u64) -> u32 {
    let policy = win32_job_ui_policy();
    let Some(token) = policy.job_token(job) else {
        return nt_win32k_job::STATUS_SUCCESS;
    };
    if !policy.process_in_job(job, process) {
        return nt_win32k_job::STATUS_SUCCESS;
    }
    let slot = (process + PROCESSINFO_PW32JOB_OFF) as *mut u64;
    let current = read_volatile(slot);
    if current != 0 && current != token {
        return nt_win32k_job::STATUS_INVALID_PARAMETER;
    }
    match policy.remove_process(job, process) {
        Ok(_) => {
            write_volatile(slot, 0);
            nt_win32k_job::STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

unsafe fn terminate_win32_job(job: u64) -> u32 {
    let policy = win32_job_ui_policy();
    if !policy.contains_job(job) {
        return nt_win32k_job::STATUS_SUCCESS;
    }
    let removed = match policy.take_job(job) {
        Ok(removed) => removed,
        Err(status) => return status,
    };
    for process in removed.members {
        let slot = (process + PROCESSINFO_PW32JOB_OFF) as *mut u64;
        if read_volatile(slot) == removed.token {
            write_volatile(slot, 0);
        }
    }
    reclaiming_pool_free(removed.token);
    nt_win32k_job::STATUS_SUCCESS
}

extern "win64" fn s_win32_job_callout(parameters: u64) -> i32 {
    if parameters == 0 {
        return nt_win32k_job::STATUS_INVALID_PARAMETER as i32;
    }
    unsafe {
        let parameters = &*(parameters as *const Win32JobCalloutParameters);
        let status = match parameters.callout_type {
            PS_W32_JOB_CALLOUT_SET_INFORMATION => {
                set_win32_job_information(parameters.job, parameters.data as u32)
            }
            PS_W32_JOB_CALLOUT_ADD_PROCESS => {
                add_process_to_win32_job(parameters.job, parameters.data)
            }
            PS_W32_JOB_CALLOUT_TERMINATE => terminate_win32_job(parameters.job),
            _ => nt_win32k_job::STATUS_INVALID_PARAMETER,
        };
        status as i32
    }
}

/// `PsEstablishWin32Callouts(PWIN32_CALLOUTS_FG CalloutData)` — compose and publish win32k's
/// callout table. ReactOS leaves `JobCallout` empty; this component supplies that missing provider
/// as part of its win32k personality rather than teaching the executive GUI policy.
extern "win64" fn s_establish_win32_callouts(callout_data: u64) -> i32 {
    if callout_data != 0 {
        unsafe {
            let _ = win32_job_ui_policy();
            // NT5/ReactOS WIN32_CALLOUTS_FPNS contains sixteen pointers on x64.
            for i in 0..(0x80u64 / 8) {
                let v = read_volatile((callout_data + i * 8) as *const u64);
                write_volatile((WIN32_CALLOUTS + i * 8) as *mut u64, v);
            }
            let job_callout = s_win32_job_callout as *const () as usize as u64;
            write_volatile(
                (WIN32_CALLOUTS + WIN32_CALLOUT_JOB_OFF) as *mut u64,
                job_callout,
            );
            let sh = WIN32K_SHARED_VADDR;
            write_volatile((sh + SH_CALLOUT_TABLE) as *mut u64, WIN32_CALLOUTS);
            write_volatile(
                (sh + SH_CALLOUT_PROCESS) as *mut u64,
                read_volatile(WIN32_CALLOUTS as *const u64),
            );
            write_volatile(
                (sh + SH_CALLOUT_THREAD) as *mut u64,
                read_volatile((WIN32_CALLOUTS + 8) as *const u64),
            );
            write_volatile(
                (sh + SH_CALLOUT_GLOBAL_ATOM) as *mut u64,
                read_volatile((WIN32_CALLOUTS + 2 * 8) as *const u64),
            );
            write_volatile((sh + SH_CALLOUT_JOB) as *mut u64, job_callout);
            write_volatile(
                (sh + SH_CALLOUT_BATCH_FLUSH) as *mut u64,
                read_volatile((WIN32_CALLOUTS + WIN32_CALLOUT_BATCH_FLUSH_OFF) as *const u64),
            );
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
    DESKTOP_BODY_SIZE,
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

/// Classify the `OBJECT_TYPE` pointer win32k passed into an [`ObKind`] (`None` = an unrecognized
/// type). The pointer is the value held in win32k's imported `ExDesktopObjectType` /
/// `ExWindowStationObjectType` data cell — now the address of a **real** `OBJECT_TYPE` static (see
/// [`object_type_cell_value`] / [`nt_object_manager::object_type`]). Discrimination is delegated to
/// the host-tested crate, which compares against those static addresses.
fn classify_type(obj_type: u64) -> Option<ObKind> {
    nt_object_manager::win32k_ob::classify(obj_type)
}

extern "win64" fn s_ob_reference_object(object: u64) -> u64 {
    if unsafe { (&*core::ptr::addr_of!(WIN32K_LPC_PORT_REFERENCES)).contains(object) } {
        return unsafe {
            (&mut *core::ptr::addr_of_mut!(WIN32K_LPC_PORT_REFERENCES))
                .reference(object)
                .expect("retained LPC object disappeared during reference") as u64
        };
    }
    if !provider_event_projection_contains(object) {
        return object;
    }
    let (status, count, _, _) =
        unsafe { win32k_event_broker_call(W32_EVENT_OP_RETAIN_POINTER, object, 0, 0) };
    assert_eq!(status, 0, "projected Event reference failed");
    count
}

extern "win64" fn s_ob_dereference_object(object: u64) -> u64 {
    if unsafe { (&*core::ptr::addr_of!(WIN32K_LPC_PORT_REFERENCES)).contains(object) } {
        let remaining = unsafe {
            (&mut *core::ptr::addr_of_mut!(WIN32K_LPC_PORT_REFERENCES))
                .dereference_nonfinal(object)
                .expect("retained LPC object disappeared during dereference")
        };
        if let Some(remaining) = remaining {
            return remaining as u64;
        }
        let (status, _) = unsafe { request_lpc_service(LPC_SERVICE_RELEASE_PORT, object, &[]) };
        assert_eq!(status, 0, "retained LPC object release failed");
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(WIN32K_LPC_PORT_REFERENCES))
                .complete_final_release(object)
        });
        return 0;
    }
    if !provider_event_projection_contains(object) {
        return 0;
    }
    let (status, count, _, _) =
        unsafe { win32k_event_broker_call(W32_EVENT_OP_DEREFERENCE, object, 0, 0) };
    assert_eq!(status, 0, "projected Event dereference failed");
    assert!(unsafe { drain_retired_event_provider_bodies() });
    count
}

extern "win64" fn s_zw_create_event(
    handle_out: *mut u64,
    desired_access: u64,
    object_attributes: u64,
    event_type: u64,
    initial_state: u64,
) -> i32 {
    if handle_out.is_null() {
        return 0xC000_0005u32 as i32; // STATUS_ACCESS_VIOLATION
    }
    if event_type > 1 {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    if object_attributes != 0 {
        return 0xC000_00BBu32 as i32; // STATUS_NOT_SUPPORTED until named provider creates are brokered.
    }
    unsafe {
        write_unaligned(handle_out, 0);
        let (status, handle, _, _) = win32k_event_broker_call(
            W32_EVENT_OP_CREATE,
            desired_access,
            event_type,
            initial_state,
        );
        if status != 0 {
            return status;
        }
        if handle == 0 {
            return STATUS_NO_MEMORY;
        }
        write_unaligned(handle_out, handle);
        if !drain_retired_event_provider_bodies() {
            let (close_status, _, _, _) =
                win32k_event_broker_call(W32_EVENT_OP_CLOSE, handle, 0, 0);
            assert_eq!(close_status, 0, "provider Event create rollback failed");
            write_unaligned(handle_out, 0);
            return 0xC000_0001u32 as i32;
        }
    }
    0
}

extern "win64" fn s_zw_close(handle: u64) -> i32 {
    if is_win32k_reg_handle(handle) {
        let (status, _, _) =
            unsafe { win32k_registry_broker_call(WIN32K_REGISTRY_OP_CLOSE, handle) };
        return status;
    }
    s_ob_close_handle(handle, 0)
}

unsafe fn retire_provider_local_event(
    retirement: nt_provider_wait::ProviderLocalEventRetirement,
) -> bool {
    let (status, object_id, object_generation, _) = win32k_event_broker_call(
        W32_EVENT_OP_RETIRE_LOCAL,
        retirement.id.raw(),
        0,
        0,
    );
    if status != 0
        || object_id != retirement.canonical.object_id
        || object_generation != retirement.canonical.object_generation
    {
        print_str(b"[win32k-event] local retirement rejected status=0x");
        print_hex(status as u32);
        print_str(b" local=0x");
        print_hex((retirement.id.raw() >> 32) as u32);
        print_hex(retirement.id.raw() as u32);
        print_str(b"\n");
        return false;
    }
    let (status, _, _, _) = win32k_event_broker_call(
        W32_EVENT_OP_ACK_LOCAL_RETIREMENT,
        retirement.id.raw(),
        object_id,
        object_generation,
    );
    if status != 0 {
        print_str(b"[win32k-event] local retirement acknowledgement rejected status=0x");
        print_hex(status as u32);
        print_str(b"\n");
        return false;
    }
    let local_ack = provider_local_events_mut()
        .is_some_and(|events| events.ack_retirement(retirement).is_ok());
    if !local_ack {
        print_str(b"[win32k-event] fatal local retirement commit mismatch\n");
        park();
    }
    true
}

unsafe fn rollback_provider_local_event_publication(
    id: nt_provider_wait::ProviderLocalEventId,
    executive_published: bool,
) -> bool {
    if executive_published {
        let (status, object_id, object_generation, _) =
            win32k_event_broker_call(W32_EVENT_OP_RETIRE_LOCAL, id.raw(), 0, 0);
        if status != 0 || object_id == 0 || object_generation == 0 {
            return false;
        }
        let (status, _, _, _) = win32k_event_broker_call(
            W32_EVENT_OP_ACK_LOCAL_RETIREMENT,
            id.raw(),
            object_id,
            object_generation,
        );
        if status != 0 {
            return false;
        }
    }
    let rolled_back = provider_local_events_mut()
        .is_some_and(|events| events.rollback_unpublished(id).is_ok());
    if !rolled_back {
        print_str(b"[win32k-event] fatal publication rollback commit mismatch\n");
        park();
    }
    true
}

unsafe fn retire_provider_local_events_for_backing(
    backing: nt_provider_wait::ProviderEventBacking,
) -> bool {
    let Some(events) = provider_local_events() else {
        return false;
    };
    if events.backing_event_count(backing) == 0 {
        return true;
    }
    let retirements = match provider_local_events_mut()
        .expect("local Event catalog disappeared")
        .begin_retire_backing(backing)
    {
        Ok(retirements) => retirements,
        Err(_) => return false,
    };
    for retirement in retirements {
        if !retire_provider_local_event(retirement) {
            return false;
        }
    }
    true
}

unsafe fn finish_provider_stack_event_activation(
    activation: ProviderStackEventActivation,
) -> bool {
    if active_provider_stack_event_activation() != Some(activation) {
        return false;
    }
    if !retire_provider_local_events_for_backing(activation.backing()) {
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS))
        .as_mut()
        .and_then(Vec::pop)
        == Some(activation)
}

unsafe fn retire_existing_provider_local_event(body: u64) -> bool {
    let existing = match provider_local_events()
        .expect("local Event catalog is not initialized")
        .snapshot_for_body(body)
    {
        Ok(existing) => existing,
        Err(nt_provider_wait::ProviderLocalEventError::NotFound) => return true,
        Err(_) => return false,
    };
    let trace = PROVIDER_LOCAL_EVENT_INITIALIZATIONS.load(Ordering::Relaxed) <= 16;
    if trace {
        print_str(b"[win32k-event] reinitialize body=0x");
        print_hex((body >> 32) as u32);
        print_hex(body as u32);
        print_str(b" local=0x");
        print_hex((existing.id.raw() >> 32) as u32);
        print_hex(existing.id.raw() as u32);
        print_str(b" canonical=");
        print_u64(u64::from(existing.canonical.is_some()));
        print_str(b" leases=");
        print_u64(u64::from(existing.wait_leases) + u64::from(existing.signal_leases));
        print_str(b"\n");
    }
    if existing.canonical.is_none() {
        let rolled_back = provider_local_events_mut()
            .is_some_and(|events| events.rollback_unpublished(existing.id).is_ok());
        if !rolled_back {
            print_str(b"[win32k-event] unpublished local reinitialization rollback failed\n");
        }
        return rolled_back;
    }
    let retirement = match provider_local_events_mut()
        .expect("local Event catalog disappeared")
        .begin_retire_event(existing.id)
    {
        Ok(retirement) => retirement,
        Err(error) => {
            print_str(b"[win32k-event] local reinitialization retirement rejected reason=");
            print_u64(error as u64);
            print_str(b"\n");
            return false;
        }
    };
    retire_provider_local_event(retirement)
}

unsafe fn initialize_provider_local_event(
    event: u64,
    kind: nt_provider_wait::ProviderEventKind,
    initial_state: bool,
) -> bool {
    let initialization = PROVIDER_LOCAL_EVENT_INITIALIZATIONS.fetch_add(1, Ordering::Relaxed) + 1;
    if initialization <= 16 {
        print_str(b"[win32k-event] initialize #");
        print_u64(initialization);
        print_str(b" body=0x");
        print_hex((event >> 32) as u32);
        print_hex(event as u32);
        print_str(b" kind=");
        print_u64(u64::from(matches!(
            kind,
            nt_provider_wait::ProviderEventKind::Synchronization
        )));
        print_str(b" allocation-catalog=");
        print_u64(u64::from(
            (&*core::ptr::addr_of!(WIN32K_PROVIDER_ALLOCATIONS)).is_some(),
        ));
        print_str(b" local-catalog=");
        print_u64(u64::from(
            (&*core::ptr::addr_of!(WIN32K_LOCAL_EVENTS)).is_some(),
        ));
        print_str(b"\n");
    }
    if !retire_existing_provider_local_event(event) {
        return false;
    }
    let event_bytes = nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64;
    let id = if let Some(allocations) =
        (&*core::ptr::addr_of!(WIN32K_PROVIDER_ALLOCATIONS)).as_ref()
    {
        match allocations.containing(event, event_bytes) {
            Ok(allocation) => match provider_local_events_mut().and_then(|events| {
                events
                    .initialize_in_allocation(
                        allocations,
                        allocation.identity,
                        event,
                        event_bytes,
                        kind,
                        initial_state,
                    )
                    .ok()
            }) {
                Some(id) => Some(id),
                None => {
                    print_str(b"[win32k-event] allocation-backed local identity rejected body=0x");
                    print_hex((event >> 32) as u32);
                    print_hex(event as u32);
                    print_str(b" allocation=0x");
                    print_hex(allocation.identity.allocation_id as u32);
                    print_str(b"\n");
                    None
                }
            },
            Err(error) => {
                if provider_pool_contains(event) {
                    print_str(b"[win32k-event] provider-pool allocation lookup rejected reason=");
                    print_u64(error as u64);
                    print_str(b" body=0x");
                    print_hex((event >> 32) as u32);
                    print_hex(event as u32);
                    print_str(b" native-cap=0x");
                    print_hex(provider_pool_allocation_capacity(event).unwrap_or(0) as u32);
                    print_str(b"\n");
                }
                None
            }
        }
    } else {
        print_str(b"[win32k-event] provider allocation catalog missing during initialization\n");
        None
    }
    .or_else(|| {
        let end = event.checked_add(event_bytes)?;
        if event >= WIN32K_STACK_VADDR && end <= WIN32K_STACK_VADDR + WIN32K_STACK_BYTES {
            let activation = active_provider_stack_event_activation()?;
            return provider_local_events_mut()?.initialize_stack(
                event,
                activation.dispatch_id,
                activation.generation,
                event - WIN32K_STACK_VADDR,
                kind,
                initial_state,
            ).ok();
        }
        None
    })
    .or_else(|| {
        let end = event.checked_add(event_bytes)?;
        if event >= WIN32K_CODE_VA && end <= WIN32K_CODE_VA + WIN32K_IMAGE_BYTES {
            return provider_local_events_mut()?.initialize_static(
                event,
                event - WIN32K_CODE_VA,
                kind,
                initial_state,
            ).ok();
        }
        None
    });
    let Some(id) = id else {
        print_str(b"[win32k-event] no owned storage classification body=0x");
        print_hex((event >> 32) as u32);
        print_hex(event as u32);
        print_str(b" provider-pool=");
        print_u64(u64::from(provider_pool_contains(event)));
        print_str(b" stack-activation=");
        print_u64(u64::from(active_provider_stack_event_activation().is_some()));
        print_str(b"\n");
        return false;
    };
    let event_type = u64::from(matches!(
        kind,
        nt_provider_wait::ProviderEventKind::Synchronization
    ));
    let (status, object_id, object_generation, metadata) = win32k_event_broker_call(
        W32_EVENT_OP_PUBLISH_LOCAL,
        id.raw(),
        event_type,
        u64::from(initial_state),
    );
    let expected_metadata = event_type | (u64::from(initial_state) << 1);
    if status != 0 || object_id == 0 || object_generation == 0 || metadata != expected_metadata {
        print_str(b"[win32k-event] local publication rejected status=0x");
        print_hex(status as u32);
        print_str(b" id=0x");
        print_hex(object_id as u32);
        print_str(b" generation=0x");
        print_hex(object_generation as u32);
        print_str(b" metadata=0x");
        print_hex(metadata as u32);
        print_str(b" expected=0x");
        print_hex(expected_metadata as u32);
        print_str(b"\n");
        if !rollback_provider_local_event_publication(id, status == 0) {
            print_str(b"[win32k-event] canonical publication rollback incomplete\n");
        }
        return false;
    }
    let canonical = nt_provider_wait::ProviderWaitObject::new(
        nt_provider_wait::ProviderWaitObjectType::Event,
        object_id,
        object_generation,
    );
    let bind_result = provider_local_events_mut()
        .expect("local Event catalog disappeared")
        .bind_canonical(id, canonical);
    if let Err(error) = bind_result {
        print_str(b"[win32k-event] canonical bind rejected reason=");
        print_u64(error as u64);
        print_str(b" local=0x");
        print_hex((id.raw() >> 32) as u32);
        print_hex(id.raw() as u32);
        print_str(b" canonical=");
        print_u64(object_id);
        print_str(b"/");
        print_u64(object_generation);
        print_str(b"\n");
        if !rollback_provider_local_event_publication(id, true) {
            print_str(b"[win32k-event] canonical bind rollback incomplete\n");
        }
        return false;
    }
    if initialization <= 16 {
        print_str(b"[win32k-event] published #");
        print_u64(initialization);
        print_str(b" local=0x");
        print_hex((id.raw() >> 32) as u32);
        print_hex(id.raw() as u32);
        print_str(b" canonical=");
        print_u64(object_id);
        print_str(b"/");
        print_u64(object_generation);
        print_str(b"\n");
    }
    let kernel_kind = match kind {
        nt_provider_wait::ProviderEventKind::Notification => {
            nt_kernel_exec::kevent::EventKind::Notification
        }
        nt_provider_wait::ProviderEventKind::Synchronization => {
            nt_kernel_exec::kevent::EventKind::Synchronization
        }
    };
    nt_kernel_exec::kevent::init_kevent(event as *mut u8, kernel_kind, initial_state);
    true
}

unsafe fn provider_local_event_snapshot_or_park(
    event: u64,
) -> nt_provider_wait::ProviderLocalEventSnapshot {
    match provider_local_events().and_then(|events| events.resolve_body(event).ok()) {
        Some(snapshot) => snapshot,
        None => {
            print_str(b"[win32k-event] unowned local Event body=0x");
            print_hex((event >> 32) as u32);
            print_hex(event as u32);
            print_str(b"\n");
            park();
        }
    }
}

unsafe fn provider_local_event_call(event: u64, op: u64) -> (u64, u64) {
    let snapshot = provider_local_event_snapshot_or_park(event);
    if provider_local_events_mut()
        .expect("local Event catalog disappeared")
        .acquire_lease(
            snapshot.id,
            nt_provider_wait::ProviderLocalEventLeaseKind::Signal,
        )
        .is_err()
    {
        park();
    }
    let (status, out1, out2, _) = win32k_event_broker_call(op, snapshot.id.raw(), 0, 0);
    let released = provider_local_events_mut()
        .expect("local Event catalog disappeared")
        .release_lease(
            snapshot.id,
            nt_provider_wait::ProviderLocalEventLeaseKind::Signal,
        )
        .is_ok();
    if status != 0 || !released {
        print_str(b"[win32k-event] canonical local Event operation failed\n");
        park();
    }
    (out1, out2)
}

extern "win64" fn s_ke_initialize_event(event: u64, event_type: u64, initial_state: u64) {
    if event == 0 {
        return;
    }
    let kind = if event_type == 1 {
        nt_provider_wait::ProviderEventKind::Synchronization
    } else {
        nt_provider_wait::ProviderEventKind::Notification
    };
    if !unsafe { initialize_provider_local_event(event, kind, initial_state != 0) } {
        print_str(b"[win32k-event] KeInitializeEvent storage classification failed body=0x");
        print_hex((event >> 32) as u32);
        print_hex(event as u32);
        print_str(b"\n");
        park();
    }
}

unsafe fn mirror_projected_event_state(event: u64, signaled: bool) {
    if signaled {
        nt_kernel_exec::kevent::kevent_set(event as *mut u8);
    } else {
        nt_kernel_exec::kevent::kevent_reset(event as *mut u8);
    }
}

extern "win64" fn s_ke_set_event(event: u64, _increment: u64, _wait: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    assert_eq!(_wait, 0, "KeSetEvent(Wait=TRUE) requires atomic signal-and-wait");
    if !provider_event_projection_contains(event) {
        let (previous, current) = unsafe { provider_local_event_call(event, W32_EVENT_OP_SET_LOCAL) };
        unsafe { mirror_projected_event_state(event, current != 0) };
        return previous as i32;
    }
    let (status, previous, current, _) =
        unsafe { win32k_event_broker_call(W32_EVENT_OP_SET, event, _increment, _wait) };
    assert_eq!(status, 0, "projected KeSetEvent broker failed");
    unsafe { mirror_projected_event_state(event, current != 0) };
    previous as i32
}

extern "win64" fn s_ke_reset_event(event: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    if !provider_event_projection_contains(event) {
        let (previous, _) = unsafe { provider_local_event_call(event, W32_EVENT_OP_RESET_LOCAL) };
        unsafe { mirror_projected_event_state(event, false) };
        return previous as i32;
    }
    let (status, previous, _, _) =
        unsafe { win32k_event_broker_call(W32_EVENT_OP_RESET, event, 0, 0) };
    assert_eq!(status, 0, "projected KeResetEvent broker failed");
    unsafe { mirror_projected_event_state(event, false) };
    previous as i32
}

extern "win64" fn s_ke_clear_event(event: u64) {
    if event == 0 {
        return;
    }
    if !provider_event_projection_contains(event) {
        unsafe {
            provider_local_event_call(event, W32_EVENT_OP_CLEAR_LOCAL);
            mirror_projected_event_state(event, false);
        }
        return;
    }
    let (status, _, _, _) = unsafe { win32k_event_broker_call(W32_EVENT_OP_CLEAR, event, 0, 0) };
    assert_eq!(status, 0, "projected KeClearEvent broker failed");
    unsafe { mirror_projected_event_state(event, false) };
}

extern "win64" fn s_ke_pulse_event(event: u64, _increment: u64, _wait: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    assert_eq!(
        _wait, 0,
        "KePulseEvent(Wait=TRUE) requires atomic signal-and-wait"
    );
    if !provider_event_projection_contains(event) {
        let (previous, _) = unsafe { provider_local_event_call(event, W32_EVENT_OP_PULSE_LOCAL) };
        unsafe { mirror_projected_event_state(event, false) };
        return previous as i32;
    }
    let (status, previous, _, _) =
        unsafe { win32k_event_broker_call(W32_EVENT_OP_PULSE, event, _increment, _wait) };
    assert_eq!(status, 0, "projected KePulseEvent broker failed");
    unsafe { mirror_projected_event_state(event, false) };
    previous as i32
}

extern "win64" fn s_ke_read_state_event(event: u64) -> i32 {
    if event == 0 {
        return 0;
    }
    if !provider_event_projection_contains(event) {
        let (signaled, _) = unsafe { provider_local_event_call(event, W32_EVENT_OP_READ_LOCAL) };
        unsafe { mirror_projected_event_state(event, signaled != 0) };
        return signaled as i32;
    }
    let (status, signaled, _, _) =
        unsafe { win32k_event_broker_call(W32_EVENT_OP_READ, event, 0, 0) };
    assert_eq!(status, 0, "projected KeReadStateEvent broker failed");
    unsafe { mirror_projected_event_state(event, signaled != 0) };
    signaled as i32
}

extern "win64" fn s_ke_wait_for_single_object(
    event: u64,
    _wait_reason: u32,
    wait_mode: i8,
    alertable: u8,
    timeout: u64,
) -> i32 {
    let Some(object) = (unsafe { provider_wait_object_for_event(event) }) else {
        return 0xC000_000Du32 as i32;
    };
    unsafe {
        provider_wait_rendezvous(
            core::slice::from_ref(&object),
            nt_provider_wait::ProviderWaitType::Any,
            wait_mode,
            alertable,
            timeout,
        )
    }
}

static PROVIDER_WAIT_NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn next_provider_wait_id() -> Option<u64> {
    PROVIDER_WAIT_NEXT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()
        .filter(|id| *id != 0)
}

unsafe fn provider_wait_object_for_event(event: u64) -> Option<nt_provider_wait::ProviderWaitObject> {
    let canonical = if let Some(id) = (&*core::ptr::addr_of!(WIN32K_EVENT_PROJECTIONS)).identity(event)
    {
        nt_provider_wait::ProviderWaitObject::new(
            nt_provider_wait::ProviderWaitObjectType::Event,
            id.0.slot().checked_add(1)?,
            u64::from(id.0.generation().0),
        )
    } else {
        provider_local_events()?.resolve_body(event).ok()?.canonical?
    };
    (canonical.typed() == Some(nt_provider_wait::ProviderWaitObjectType::Event))
        .then_some(canonical)
}

unsafe fn current_provider_wait_owner() -> Option<nt_provider_wait::ProviderWaitOwner> {
    let provider = registered_provider_wait_domain()?;
    let callback_frame =
        (WIN32K_SHARED_VADDR + SH_USER_CALLBACK) as *const nt_user_callback::CallbackFrame;
    let header = read_volatile(core::ptr::addr_of!((*callback_frame).header));
    let client_generation = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_GENERATION) as *const u64);
    let owner = nt_provider_wait::ProviderWaitOwner {
        provider_domain: provider.domain,
        provider_generation: provider.generation,
        client_pi: header.client_pi,
        client_generation,
        client_tid: header.client_tid,
        client_badge: header.client_badge,
        dispatch_id: header.dispatch_id,
    };
    owner.is_valid().then_some(owner)
}

unsafe fn provider_wait_timeout(
    timeout: u64,
) -> Option<(nt_provider_wait::ProviderWaitTimeoutKind, i64)> {
    if timeout == 0 {
        return Some((nt_provider_wait::ProviderWaitTimeoutKind::Infinite, 0));
    }
    let interval = read_unaligned(timeout as *const i64);
    let kind = if interval == 0 {
        nt_provider_wait::ProviderWaitTimeoutKind::Poll
    } else if interval < 0 {
        nt_provider_wait::ProviderWaitTimeoutKind::Relative
    } else {
        nt_provider_wait::ProviderWaitTimeoutKind::Absolute
    };
    Some((kind, interval))
}

unsafe fn provider_wait_rendezvous(
    objects: &[nt_provider_wait::ProviderWaitObject],
    wait_type: nt_provider_wait::ProviderWaitType,
    wait_mode: i8,
    alertable: u8,
    timeout: u64,
) -> i32 {
    let Some(owner) = current_provider_wait_owner() else {
        return 0xC000_000Du32 as i32;
    };
    let Some(wait_id) = next_provider_wait_id() else {
        return 0xC000_009Au32 as i32;
    };
    let Some((timeout_kind, timeout_100ns)) = provider_wait_timeout(timeout) else {
        return 0xC000_000Du32 as i32;
    };
    let wait_mode = match wait_mode {
        0 => nt_provider_wait::ProviderWaitMode::Kernel,
        1 => nt_provider_wait::ProviderWaitMode::User,
        _ => return 0xC000_000Du32 as i32,
    };
    let alertable = match alertable {
        0 => false,
        1 => true,
        _ => return 0xC000_000Du32 as i32,
    };
    let page = WIN32K_PROVIDER_WAIT_VADDR as *mut nt_provider_wait::ProviderWaitSharedPage;
    let mut request = nt_provider_wait::ProviderWaitRequest::empty();
    if request
        .begin(
            nt_provider_wait::ProviderWaitRequestMetadata {
                wait_id,
                owner,
                wait_type,
                wait_mode,
                alertable,
                timeout_kind,
                timeout_100ns,
            },
            objects,
    )
    .is_err()
    {
        return 0xC000_000Du32 as i32;
    }
    write_volatile(core::ptr::addr_of_mut!((*page).request), request);
    write_volatile(
        core::ptr::addr_of_mut!((*page).result),
        nt_provider_wait::ProviderWaitResult::EMPTY,
    );

    let callback_frame =
        (WIN32K_SHARED_VADDR + SH_USER_CALLBACK) as *const nt_user_callback::CallbackFrame;
    let owner_header = read_volatile(core::ptr::addr_of!((*callback_frame).header));
    let Some(wait_context) = callback_request_context_for_request(&owner_header) else {
        return 0xC000_000Du32 as i32;
    };
    let mut outgoing = W32_PROVIDER_WAIT_LABEL << 12;
    loop {
        let (_label, tag, _, _, _) = crate::driver_launch::call_on(outgoing);
        match tag {
            W32_PROVIDER_WAIT_RESUME_LABEL => {
                let result = read_volatile(core::ptr::addr_of!((*page).result));
                let Some(status) = result.validate(wait_id) else {
                    return 0xC000_0001u32 as i32;
                };
                if !restore_user_callback_request_context(wait_context) {
                    return 0xC000_000Du32 as i32;
                }
                return status;
            }
            W32_DISPATCH_LABEL => {
                let (status, info) = win32k_dispatch(&crate::spawn_hosts::DispatchReq {
                    sel: read_volatile((WIN32K_SHARED_VADDR + SH_REQ_SSN) as *const u64),
                    drv: 0,
                });
                if !restore_user_callback_request_context(wait_context) {
                    return 0xC000_000Du32 as i32;
                }
                write_volatile(
                    core::ptr::addr_of_mut!((*(callback_frame
                        as *mut nt_user_callback::CallbackFrame))
                        .header),
                    owner_header,
                );
                write_volatile((WIN32K_SHARED_VADDR + SH_REQ_STATUS) as *mut u64, info);
                write_volatile((WIN32K_SHARED_VADDR + SH_REQ_STATUS) as *mut i32, status);
                outgoing = W32_DISPATCH_LABEL << 12;
            }
            _ => return 0xC000_0001u32 as i32,
        }
    }
}

extern "win64" fn s_ke_wait_for_multiple_objects(
    count: u32,
    object_array: u64,
    wait_type: u32,
    _wait_reason: u32,
    wait_mode: i8,
    alertable: u8,
    timeout: u64,
    _wait_blocks: u64,
) -> i32 {
    if count == 0 || count as usize > nt_provider_wait::PROVIDER_WAIT_MAX_OBJECTS || object_array == 0
    {
        return 0xC000_000Du32 as i32;
    }
    let wait_type = match wait_type {
        0 => nt_provider_wait::ProviderWaitType::All,
        1 => nt_provider_wait::ProviderWaitType::Any,
        _ => return 0xC000_000Du32 as i32,
    };
    let mut objects = [
        nt_provider_wait::ProviderWaitObject::EMPTY;
        nt_provider_wait::PROVIDER_WAIT_MAX_OBJECTS
    ];
    for index in 0..count as usize {
        let event = unsafe { read_unaligned((object_array + index as u64 * 8) as *const u64) };
        let Some(object) = (unsafe { provider_wait_object_for_event(event) }) else {
            return 0xC000_000Du32 as i32;
        };
        objects[index] = object;
    }
    unsafe {
        provider_wait_rendezvous(
            &objects[..count as usize],
            wait_type,
            wait_mode,
            alertable,
            timeout,
        )
    }
}

extern "win64" fn s_eng_get_tick_count() -> u32 {
    WIN32K_TICK_COUNT.fetch_add(1, Ordering::Relaxed) as u32
}

extern "win64" fn s_rtl_get_exp_winver(_base: u64) -> u32 {
    0x0501 // MAKEWORD(1, 5): Windows XP/Server 2003-compatible subsystem version.
}

/// Allocate + initialize a DESKTOP body from the win32k pool. The DESKTOPINFO is created later from
/// the desktop's own section-backed heap, matching ReactOS `UserInitializeDesktop`.
unsafe fn alloc_desktop_body() -> u64 {
    let desk = pool_alloc(DESKTOP_BODY_SIZE);
    if desk == 0 {
        return 0;
    }
    init_desktop_body(desk as *mut u8, 0);
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
) -> Option<(
    [u8; nt_object_manager::win32k_ob::OB_NAMED_DESKTOP_NAME_MAX],
    usize,
)> {
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

unsafe fn object_attributes_name_leaf_unicode(object_attributes: u64) -> Option<(u64, usize)> {
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
    (len != 0).then_some((buffer + (start * 2) as u64, len))
}

unsafe fn desktop_root_from_handle(table: &ObHandleTable, handle: u64) -> Option<(u64, u64)> {
    match table.lookup(handle) {
        Some((ObKind::WindowStation, body)) if body != 0 => Some((handle, body)),
        _ => None,
    }
}

unsafe fn effective_desktop_root(table: &ObHandleTable, requested_root: u64) -> Option<(u64, u64)> {
    if requested_root != 0 {
        return desktop_root_from_handle(table, requested_root);
    }

    let ppi = current_w32process();
    if ppi != 0 {
        let h = read_volatile((ppi + PROCESSINFO_HWINSTA_OFF) as *const u64);
        let body = read_volatile((ppi + PROCESSINFO_PRPWINSTA_OFF) as *const u64);
        if h != 0 && body != 0 {
            if let Some((_, table_body)) = desktop_root_from_handle(table, h) {
                if table_body == body {
                    return Some((h, body));
                }
            }
        }
    }

    let h = s_ps_get_process_winsta(current_eprocess());
    if h != 0 {
        return desktop_root_from_handle(table, h);
    }
    None
}

unsafe fn desktop_heap_size_for(
    table: &ObHandleTable,
    winsta_body: u64,
    object_attributes: u64,
) -> u64 {
    let input_winsta = {
        let global = read_volatile((WIN32K_CODE_VA + INPUT_WINDOW_STATION_RVA) as *const u64);
        if global != 0 {
            global
        } else {
            table.cached_winsta_body()
        }
    };
    if winsta_body == input_winsta && winsta_body != 0 {
        if object_attributes_name_leaf_eq_ascii(object_attributes, b"winlogon") {
            DESKTOP_HEAP_WINLOGON_BYTES
        } else {
            DESKTOP_HEAP_INTERACTIVE_BYTES
        }
    } else {
        DESKTOP_HEAP_NONINTERACTIVE_BYTES
    }
}

unsafe fn desktop_info_alloc_size(object_attributes: u64) -> u64 {
    let name_bytes = object_attributes_name_leaf_unicode(object_attributes)
        .map(|(_, units)| ((units + 1) * 2) as u64)
        .unwrap_or(2);
    align16((DESKTOPINFO_NAME_OFF + name_bytes).max(DESKTOPINFO_MIN_ALLOC))
}

unsafe fn initialize_desktop_info(
    dinfo: u64,
    heap_base: u64,
    heap_size: u64,
    object_attributes: u64,
) {
    write_volatile(
        (dinfo + DESKTOPINFO_PV_DESKTOP_BASE_OFF) as *mut u64,
        heap_base,
    );
    write_volatile(
        (dinfo + DESKTOPINFO_PV_DESKTOP_LIMIT_OFF) as *mut u64,
        heap_base + heap_size,
    );

    let mut hook = 0u64;
    while hook < DESKTOPINFO_HOOK_COUNT {
        let head = dinfo + DESKTOPINFO_APHK_START_OFF + hook * 16;
        write_volatile(head as *mut u64, head);
        write_volatile((head + 8) as *mut u64, head);
        hook += 1;
    }

    let mut units = 0usize;
    if let Some((src, len)) = object_attributes_name_leaf_unicode(object_attributes) {
        while units < len {
            let ch = read_unaligned((src + (units * 2) as u64) as *const u16);
            write_volatile(
                (dinfo + DESKTOPINFO_NAME_OFF + (units * 2) as u64) as *mut u16,
                ch,
            );
            units += 1;
        }
    }
    write_volatile(
        (dinfo + DESKTOPINFO_NAME_OFF + (units * 2) as u64) as *mut u16,
        0,
    );
}

unsafe fn initialize_desktop_heap(
    table: &ObHandleTable,
    desk_body: u64,
    winsta_body: u64,
    object_attributes: u64,
) -> bool {
    if desk_body == 0 || winsta_body == 0 {
        return false;
    }
    let existing_section = read_volatile((desk_body + DESKTOP_HSECTION_OFF) as *const u64);
    let existing_heap = read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64);
    if existing_section != 0 || existing_heap != 0 {
        return existing_section != 0
            && is_section(existing_section as *const u8)
            && existing_heap != 0
            && hosted_heap_bounds(existing_heap).is_some();
    }

    let heap_size = desktop_heap_size_for(table, winsta_body, object_attributes);
    let section = pool_alloc(section_object::SIZE_OF as u64);
    if section == 0 {
        return false;
    }
    init_section(section as *mut u8, heap_size);
    register_section_descriptor(section);
    let (heap_base, mapped_size) = section_view(section, heap_size);
    if heap_base == 0 || mapped_size < heap_size {
        return false;
    }
    let pheap = hosted_heap_init(heap_base, heap_size);
    if pheap == 0 {
        return false;
    }
    let info_size = desktop_info_alloc_size(object_attributes);
    let dinfo = s_rtl_allocate_heap(pheap, HEAP_ZERO_MEMORY, info_size);
    if dinfo == 0 {
        return false;
    }

    init_desktop_body(desk_body as *mut u8, dinfo);
    initialize_desktop_info(dinfo, heap_base, heap_size, object_attributes);
    write_volatile((desk_body + DESKTOP_HSECTION_OFF) as *mut u64, section);
    write_volatile((desk_body + DESKTOP_PHEAP_OFF) as *mut u64, pheap);
    write_volatile(
        (desk_body + DESKTOP_UL_HEAP_SIZE_OFF) as *mut u64,
        heap_size,
    );
    true
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
        write_slice_u32(
            &mut captured.bytes,
            SD_REL_SACL_OFF as usize,
            current as u32,
        );
        current += sacl_len;
    }
    if dacl_len != 0 {
        copy_component_bytes_to_slice(&mut captured.bytes, current, dacl, dacl_len);
        write_slice_u32(
            &mut captured.bytes,
            SD_REL_DACL_OFF as usize,
            current as u32,
        );
        current += dacl_len;
    }
    if owner_len != 0 {
        copy_component_bytes_to_slice(&mut captured.bytes, current, owner, owner_len);
        write_slice_u32(
            &mut captured.bytes,
            SD_REL_OWNER_OFF as usize,
            current as u32,
        );
        current += owner_len;
    }
    if group_len != 0 {
        copy_component_bytes_to_slice(&mut captured.bytes, current, group, group_len);
        write_slice_u32(
            &mut captured.bytes,
            SD_REL_GROUP_OFF as usize,
            current as u32,
        );
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
        .map(|index| process_ctx_token_authentication_id(index))
        .unwrap_or(0)
}

#[derive(Clone, Copy)]
struct ServiceWinstaRecord {
    token_authentication_id: u64,
    handle: u64,
}

unsafe fn service_winsta_record_ptr(base: u64, index: u64) -> *mut ServiceWinstaRecord {
    (base + index * core::mem::size_of::<ServiceWinstaRecord>() as u64) as *mut ServiceWinstaRecord
}

unsafe fn ensure_service_winsta_record_capacity(required: u64) -> bool {
    let cap = WIN32K_SERVICE_WINSTA_RECORDS_CAP.load(Ordering::Relaxed);
    if cap >= required {
        return true;
    }
    let mut new_cap = if cap == 0 {
        WIN32K_SERVICE_WINSTA_INITIAL_CAP
    } else {
        cap.saturating_mul(2)
    };
    while new_cap < required {
        let next = new_cap.saturating_mul(2);
        if next <= new_cap {
            return false;
        }
        new_cap = next;
    }
    let Some(bytes) = (core::mem::size_of::<ServiceWinstaRecord>() as u64).checked_mul(new_cap)
    else {
        return false;
    };
    let new_base = pool_alloc(bytes);
    if new_base == 0 {
        return false;
    }
    let old_base = WIN32K_SERVICE_WINSTA_RECORDS_PTR.load(Ordering::Relaxed);
    let len = WIN32K_SERVICE_WINSTA_RECORDS_LEN.load(Ordering::Relaxed);
    if old_base != 0 {
        for index in 0..len {
            let rec = read_volatile(service_winsta_record_ptr(old_base, index));
            write_volatile(service_winsta_record_ptr(new_base, index), rec);
        }
    }
    WIN32K_SERVICE_WINSTA_RECORDS_PTR.store(new_base, Ordering::Relaxed);
    WIN32K_SERVICE_WINSTA_RECORDS_CAP.store(new_cap, Ordering::Relaxed);
    true
}

unsafe fn service_winsta_index_for_auth(token_authentication_id: u64) -> Option<usize> {
    if token_authentication_id == 0 {
        return None;
    }
    let base = WIN32K_SERVICE_WINSTA_RECORDS_PTR.load(Ordering::Relaxed);
    let len = WIN32K_SERVICE_WINSTA_RECORDS_LEN.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    for index in 0..len {
        let rec = read_volatile(service_winsta_record_ptr(base, index));
        if rec.token_authentication_id == token_authentication_id {
            return Some(index as usize);
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
        let base = WIN32K_SERVICE_WINSTA_RECORDS_PTR.load(Ordering::Relaxed);
        if base != 0 {
            write_volatile(
                service_winsta_record_ptr(base, index as u64),
                ServiceWinstaRecord {
                    token_authentication_id,
                    handle,
                },
            );
        }
        return;
    }
    let len = WIN32K_SERVICE_WINSTA_RECORDS_LEN.load(Ordering::Relaxed);
    let Some(required) = len.checked_add(1) else {
        return;
    };
    if !ensure_service_winsta_record_capacity(required) {
        return;
    }
    let base = WIN32K_SERVICE_WINSTA_RECORDS_PTR.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    write_volatile(
        service_winsta_record_ptr(base, len),
        ServiceWinstaRecord {
            token_authentication_id,
            handle,
        },
    );
    WIN32K_SERVICE_WINSTA_RECORDS_LEN.store(required, Ordering::Relaxed);
}

unsafe fn service_window_station_handle_for_current_token() -> u64 {
    let token_authentication_id = current_token_authentication_id();
    let Some(index) = service_winsta_index_for_auth(token_authentication_id) else {
        return 0;
    };
    let base = WIN32K_SERVICE_WINSTA_RECORDS_PTR.load(Ordering::Relaxed);
    if base == 0 {
        return 0;
    }
    read_volatile(service_winsta_record_ptr(base, index as u64)).handle
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
                let requested_root = object_attributes_root_directory(object_attributes);
                let Some((root, winsta_body)) = effective_desktop_root(table, requested_root)
                else {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                };
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
                write_volatile(
                    (body + DESKTOP_RPWINSTA_PARENT_OFF) as *mut u64,
                    winsta_body,
                );
                if !initialize_desktop_heap(table, body, winsta_body, object_attributes) {
                    return STATUS_INSUFFICIENT_RESOURCES_I32;
                }
                let h = table.register_with_security(
                    ObKind::Desktop,
                    body,
                    security
                        .as_ref()
                        .map(CapturedUserObjectSecurityDescriptor::as_slice),
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
            security
                .as_ref()
                .map(CapturedUserObjectSecurityDescriptor::as_slice),
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
/// The unregistered handles resolved here are win32k's narrow process-connect handle, NT's
/// current-process/current-thread pseudo handles, and broker-owned LPC port handles. Process/thread
/// identities resolve to the live dispatch context. An LPC reference is validated by the isolated
/// broker and retains that same opaque handle as the port object body; kernel LPC imports hand it
/// back to the broker instead of manufacturing a parallel object identity.
extern "win64" fn s_ob_reference_object_by_handle(
    handle: u64,
    access: u64,
    obj_type: u64,
    _mode: u64,
    object_out: *mut u64,
    handle_info: *mut u8,
) -> i32 {
    if !object_out.is_null() {
        unsafe { write_unaligned(object_out, 0) };
    }
    if obj_type == nt_object_manager::object_type::event_object_type_addr() {
        if object_out.is_null() {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        if !unsafe { provider_event_projection_reserve() } {
            return STATUS_NO_MEMORY;
        }
        let size = nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64;
        let proposed = unsafe { pool_alloc(size) };
        if proposed == 0 {
            return STATUS_NO_MEMORY;
        }
        let (status, body, raw_id, metadata_and_access) = unsafe {
            win32k_event_broker_call(W32_EVENT_OP_REFERENCE, handle, proposed, access)
        };
        if status != 0 || body == 0 || raw_id == 0 {
            if !unsafe { provider_pool_release_owned(&[(proposed, size)]) } {
                return 0xC000_0001u32 as i32;
            }
            return if status != 0 { status } else { STATUS_NO_MEMORY };
        }
        let metadata = metadata_and_access >> 32;
        let granted_access = metadata_and_access as u32;
        if body == proposed {
            let kind = if metadata & 1 != 0 {
                nt_kernel_exec::kevent::EventKind::Synchronization
            } else {
                nt_kernel_exec::kevent::EventKind::Notification
            };
            unsafe {
                nt_kernel_exec::kevent::init_kevent(body as *mut u8, kind, metadata & 2 != 0)
            };
        } else if !unsafe { provider_pool_release_owned(&[(proposed, size)]) } {
            let (release_status, _, _, _) = unsafe {
                win32k_event_broker_call(W32_EVENT_OP_DEREFERENCE, body, 0, 0)
            };
            assert_eq!(release_status, 0, "provider Event reference rollback failed");
            return 0xC000_0001u32 as i32;
        }
        assert!(unsafe { provider_event_projection_register_reserved(body, raw_id) });
        unsafe { write_unaligned(object_out, body) };
        if !handle_info.is_null() {
            unsafe {
                write_unaligned(handle_info as *mut u32, 0);
                write_unaligned(handle_info.add(4) as *mut u32, granted_access as u32);
            }
        }
        if !unsafe { drain_retired_event_provider_bodies() } {
            let (release_status, _, _, _) = unsafe {
                win32k_event_broker_call(W32_EVENT_OP_DEREFERENCE, body, 0, 0)
            };
            assert_eq!(release_status, 0, "provider Event publication rollback failed");
            unsafe { write_unaligned(object_out, 0) };
            return 0xC000_0001u32 as i32;
        }
        return 0;
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
                ObKind::Other => u32::MAX,
            };
            (body, access)
        }
        None => {
            let process_ty = nt_object_manager::object_type::process_object_type_addr();
            let thread_ty = nt_object_manager::object_type::thread_object_type_addr();
            let port_ty = nt_object_manager::object_type::port_object_type_addr();
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
            } else if handle == 0xFFFF_FFFF_FFFF_FFFE && (obj_type == 0 || obj_type == thread_ty) {
                // NtCurrentThread() pseudo handle → selected dispatch ETHREAD.
                (unsafe { current_ethread() }, u32::MAX)
            } else if obj_type == port_ty {
                if object_out.is_null() {
                    return STATUS_ACCESS_VIOLATION_I32;
                }
                if !unsafe {
                    (&mut *core::ptr::addr_of_mut!(WIN32K_LPC_PORT_REFERENCES)).reserve()
                } {
                    return STATUS_NO_MEMORY;
                }
                let (status, endpoint) =
                    unsafe { request_lpc_service(LPC_SERVICE_RETAIN_PORT, handle, &[]) };
                if status == 0 && endpoint != 0 {
                    if !unsafe {
                        (&mut *core::ptr::addr_of_mut!(WIN32K_LPC_PORT_REFERENCES))
                            .insert_reserved(endpoint)
                    } {
                        let (release_status, _) = unsafe {
                            request_lpc_service(LPC_SERVICE_RELEASE_PORT, endpoint, &[])
                        };
                        assert_eq!(release_status, 0, "LPC reference rollback failed");
                        return STATUS_NO_MEMORY;
                    }
                    (endpoint, u32::MAX)
                } else {
                    ob_type_mismatch_trace(handle, obj_type, b"invalid-lpc-handle");
                    return if status != 0 {
                        status
                    } else {
                        STATUS_INVALID_HANDLE_I32
                    };
                }
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

/// `NTSTATUS LpcRequestPort(PVOID PortObject, PPORT_MESSAGE Message)`.
///
/// The Object Manager hands win32k the broker handle itself as the opaque port body. Capture the
/// exact native frame, apply the kernel-owned type and ClientId fields, then enqueue it through the
/// isolated LPC service. Type zero is the documented datagram form; explicitly typed kernel
/// notifications retain their type after validation.
extern "win64" fn s_lpc_request_port(port_object: u64, message: *const u8) -> i32 {
    if port_object == 0
        || !unsafe { (&*core::ptr::addr_of!(WIN32K_LPC_PORT_REFERENCES)).contains(port_object) }
    {
        return STATUS_INVALID_HANDLE_I32;
    }
    if message.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }

    let mut frame = [0u8; nt_lpc_abi::PORT_MESSAGE_MAX_LEN];
    let header = unsafe { read_unaligned(message as *const u32) }.to_le_bytes();
    let Some(total) = nt_lpc_abi::port_message_total_length(header) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    unsafe { core::ptr::copy_nonoverlapping(message, frame.as_mut_ptr(), total) };
    if u16::from_le_bytes(frame[6..8].try_into().unwrap()) != 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let raw_type = u16::from_le_bytes(frame[4..6].try_into().unwrap());
    let message_type = if raw_type == 0 {
        nt_lpc_abi::msg_type::LPC_DATAGRAM
    } else if (nt_lpc_abi::msg_type::LPC_DATAGRAM..=nt_lpc_abi::msg_type::LPC_CLIENT_DIED)
        .contains(&raw_type)
    {
        raw_type
    } else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    frame[4..6].copy_from_slice(&message_type.to_le_bytes());
    frame[8..16].copy_from_slice(
        &WIN32K_CURRENT_PROCESS_ID
            .load(Ordering::Relaxed)
            .to_le_bytes(),
    );
    frame[16..24].copy_from_slice(
        &WIN32K_CURRENT_THREAD_ID
            .load(Ordering::Relaxed)
            .to_le_bytes(),
    );

    unsafe {
        request_lpc_service(
            LPC_SERVICE_RETAINED_REQUEST_PORT,
            port_object,
            &frame[..total],
        )
        .0
    }
}

/// Invoke an executive-owned LPC operation from the win32k component. The shared window contains
/// no pointers and the component cannot access the broker channel directly because its capabilities
/// are meaningful only in the executive's CSpace.
#[inline(never)]
unsafe fn request_lpc_service(operation: u32, port_handle: u64, message: &[u8]) -> (i32, u64) {
    if message.len() > LPC_SERVICE_MESSAGE_CAP {
        return (STATUS_INVALID_PARAMETER_I32, 0);
    }
    let sh = WIN32K_LPC_VADDR;
    write_volatile((sh + LPC_SERVICE_PORT_HANDLE) as *mut u64, port_handle);
    write_volatile((sh + LPC_SERVICE_OPERATION) as *mut u32, operation);
    write_volatile((sh + LPC_SERVICE_STATUS) as *mut i32, 0xC000_0001u32 as i32);
    write_volatile((sh + LPC_SERVICE_RESULT) as *mut u64, 0);
    write_volatile(
        (sh + LPC_SERVICE_MESSAGE_LEN) as *mut u32,
        message.len() as u32,
    );
    for (index, byte) in message.iter().enumerate() {
        write_volatile((sh + LPC_SERVICE_MESSAGE + index as u64) as *mut u8, *byte);
    }
    let _ = crate::driver_launch::call_on(W32_LPC_LABEL << 12);
    (
        read_volatile((sh + LPC_SERVICE_STATUS) as *const i32),
        read_volatile((sh + LPC_SERVICE_RESULT) as *const u64),
    )
}

/// Execute a bounded request against the isolated LPC broker from the executive component pump.
/// This is the sole half of the win32k LPC bridge that touches [`lpc_client`], so broker channel
/// capabilities never cross into the win32k CSpace.
#[inline(never)]
pub(crate) unsafe fn service_lpc_request() -> i32 {
    let sh = WIN32K_LPC_VADDR;
    let operation = read_volatile((sh + LPC_SERVICE_OPERATION) as *const u32);
    let port_handle = read_volatile((sh + LPC_SERVICE_PORT_HANDLE) as *const u64);
    let message_len = read_volatile((sh + LPC_SERVICE_MESSAGE_LEN) as *const u32) as usize;
    let mut result = 0;

    let status = match operation {
        LPC_SERVICE_QUERY_HANDLE if message_len == 0 => match lpc_client() {
            Some(lpc) => lpc
                .query_handle(port_handle)
                .map(|_| 0)
                .unwrap_or_else(|s| s.raw()),
            None => 0xC000_0001u32 as i32,
        },
        LPC_SERVICE_RETAIN_PORT if message_len == 0 => match lpc_client() {
            Some(lpc) => match lpc.retain_port_object(port_handle) {
                Ok(endpoint) => {
                    result = endpoint;
                    0
                }
                Err(status) => status.raw(),
            },
            None => 0xC000_0001u32 as i32,
        },
        LPC_SERVICE_RELEASE_PORT if message_len == 0 => match lpc_client() {
            Some(lpc) => lpc
                .release_port_object(port_handle)
                .map(|()| 0)
                .unwrap_or_else(|status| status.raw()),
            None => 0xC000_0001u32 as i32,
        },
        LPC_SERVICE_RETAINED_REQUEST_PORT if message_len <= LPC_SERVICE_MESSAGE_CAP => {
            let bytes =
                core::slice::from_raw_parts((sh + LPC_SERVICE_MESSAGE) as *const u8, message_len);
            let header = bytes.get(..4).and_then(|header| header.try_into().ok());
            let valid = header
                .and_then(nt_lpc_abi::port_message_total_length)
                .is_some_and(|total| total == message_len);
            if !valid {
                STATUS_INVALID_PARAMETER_I32
            } else {
                match lpc_client() {
                    Some(lpc) => match lpc.query_handle(port_handle) {
                        Ok(identity) => match lpc.retained_request_port(
                            port_handle,
                            bytes,
                            WIN32K_CURRENT_PROCESS_ID.load(Ordering::Relaxed),
                            WIN32K_CURRENT_THREAD_ID.load(Ordering::Relaxed),
                        ) {
                            Ok(()) => {
                                if lpc_name_is(&identity.name, b"\\windows\\apiport") {
                                    CSR_KERNEL_MESSAGES_PENDING.fetch_add(1, Ordering::Relaxed);
                                }
                                0
                            }
                            Err(status) => status.raw(),
                        },
                        Err(status) => status.raw(),
                    },
                    None => 0xC000_0001u32 as i32,
                }
            }
        }
        _ => STATUS_INVALID_PARAMETER_I32,
    };
    write_volatile((sh + LPC_SERVICE_STATUS) as *mut i32, status);
    write_volatile((sh + LPC_SERVICE_RESULT) as *mut u64, result);
    status
}

/// The synchronous kernel-client form requires suspending the current win32k continuation while a
/// user-mode port server runs. It is deliberately bound to an explicit failure until that shared
/// LPC continuation path owns the exchange; leaving the import unbound used to return synthetic
/// success through the loader's catch-all stub.
extern "win64" fn s_lpc_request_wait_reply_port(
    _port_object: u64,
    _request: *const u8,
    _reply: *mut u8,
) -> i32 {
    print_str(b"[win32k-lpc] LpcRequestWaitReplyPort requires a parked kernel continuation\n");
    STATUS_NOT_IMPLEMENTED_I32
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
    let (event_status, _, _, _) =
        unsafe { win32k_event_broker_call(W32_EVENT_OP_CLOSE, handle, 0, 0) };
    if event_status == 0 {
        return if unsafe { drain_retired_event_provider_bodies() } {
            0
        } else {
            0xC000_0001u32 as i32
        };
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

const HEAP_HDR_SIZE: u64 = 16;
const HEAP_ALLOC_MARKER: u64 = 0xffff_ffff_ffff_fffd;
const HEAP_HANDLE_MAGIC: u64 = 0x4845_4150_5355_4253; // "HEAPSUBS"
const HEAP_HANDLE_MAGIC_OFF: u64 = 0x10;
const HEAP_HANDLE_SIZE_OFF: u64 = 0x18;
const HEAP_ZERO_MEMORY: u64 = 0x0000_0008;
const HEAP_REALLOC_IN_PLACE_ONLY: u64 = 0x0000_0010;

/// Allocate from a hosted heap arena. The block header stores the aligned payload capacity; free
/// blocks use the second header word as a next pointer, and live blocks carry a marker.
unsafe fn heap_alloc_in_raw(
    arena_base: u64,
    arena_bytes: u64,
    size: u64,
    zero: bool,
    label: &[u8],
) -> u64 {
    if size == 0 {
        return 0;
    }
    let want = align16(size);
    let head = (arena_base + 8) as *mut u64;
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

    let ctr = arena_base as *mut u64;
    let mut cur = read_volatile(ctr);
    if cur < POOL_DATA_OFF {
        cur = POOL_DATA_OFF;
    }
    let hdr = align16(arena_base + cur);
    let cap = arena_base + arena_bytes;
    if hdr + HEAP_HDR_SIZE + want > cap {
        print_str(b"[win32k-host] ");
        print_str(label);
        print_str(b" EXHAUSTED size=0x");
        print_hex(size as u32);
        print_str(b" used=0x");
        print_hex(cur as u32);
        print_str(b"\n");
        return 0;
    }
    write_volatile(ctr, (hdr + HEAP_HDR_SIZE + want) - arena_base);
    write_volatile(hdr as *mut u64, want);
    write_volatile((hdr + 8) as *mut u64, HEAP_ALLOC_MARKER);
    let payload = hdr + HEAP_HDR_SIZE;
    if zero {
        core::ptr::write_bytes(payload as *mut u8, 0, size as usize);
    }
    payload
}

unsafe fn heap_alloc_in(
    arena_base: u64,
    arena_bytes: u64,
    size: u64,
    zero: bool,
    label: &[u8],
) -> u64 {
    let Some(arena) = provider_heap_arena_identity(arena_base) else {
        return 0;
    };
    let payload = heap_alloc_in_raw(arena_base, arena_bytes, size, zero, label);
    if payload == 0 {
        return 0;
    }
    let Some(capacity) = heap_block_capacity_in(arena_base, arena_bytes, payload) else {
        return 0;
    };
    let registered = provider_allocations_mut()
        .and_then(|allocations| allocations.register(arena, payload, capacity).ok())
        .is_some();
    if registered {
        payload
    } else {
        let _ = heap_free_in_raw(arena_base, arena_bytes, payload);
        0
    }
}

unsafe fn heap_block_capacity_in(arena_base: u64, arena_bytes: u64, p: u64) -> Option<u64> {
    let arena_start = arena_base + POOL_DATA_OFF;
    let arena_end = arena_base + arena_bytes;
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

unsafe fn heap_free_in_raw(arena_base: u64, arena_bytes: u64, p: u64) -> bool {
    let Some(cap) = heap_block_capacity_in(arena_base, arena_bytes, p) else {
        return false;
    };
    let hdr = p - HEAP_HDR_SIZE;

    let head = (arena_base + 8) as *mut u64;
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

    let ctr = arena_base as *mut u64;
    let high = arena_base + read_volatile(ctr);
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
            write_volatile(ctr, block - arena_base);
        }
    }
    true
}

unsafe fn heap_free_in(arena_base: u64, arena_bytes: u64, p: u64) -> bool {
    let Some(arena) = provider_heap_arena_identity(arena_base) else {
        return false;
    };
    let Some(allocation) = validate_provider_allocation_retirement(arena, p, 1) else {
        return false;
    };
    if heap_block_capacity_in(arena_base, arena_bytes, p) != Some(allocation.capacity)
        || !validate_provider_allocation_event_retirement(allocation)
        || !retire_provider_allocation_events(allocation)
    {
        return false;
    }
    let nested_arena = hosted_heap_arena_backed_by(allocation.identity);
    if !heap_free_in_raw(arena_base, arena_bytes, p) {
        return false;
    }
    if !retire_provider_allocation(allocation) {
        return false;
    }
    nested_arena.is_none_or(|identity| retire_hosted_heap_arena(identity, allocation.identity))
}

unsafe fn heap_realloc_in(
    arena_base: u64,
    arena_bytes: u64,
    flags: u64,
    p: u64,
    size: u64,
    label: &[u8],
) -> u64 {
    if p == 0 {
        return heap_alloc_in(
            arena_base,
            arena_bytes,
            size,
            flags & HEAP_ZERO_MEMORY != 0,
            label,
        );
    }
    if size == 0 {
        if !heap_free_in(arena_base, arena_bytes, p) {
            print_str(b"[win32k-host] fatal zero-size heap realloc release failure\n");
            park();
        }
        return 0;
    }
    let Some(old_cap) = heap_block_capacity_in(arena_base, arena_bytes, p) else {
        return 0;
    };
    let want = align16(size);
    if want <= old_cap {
        return p;
    }
    if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
        return 0;
    }
    let Some(arena) = provider_heap_arena_identity(arena_base) else {
        return 0;
    };
    let Some(allocation) = provider_allocations_mut()
        .and_then(|allocations| allocations.exact(arena, p).ok())
    else {
        return 0;
    };
    if provider_local_events().is_none_or(|events| {
        events.backing_event_count(provider_allocation_event_backing(allocation)) != 0
    }) {
        return 0;
    }
    let newp = heap_alloc_in(
        arena_base,
        arena_bytes,
        size,
        flags & HEAP_ZERO_MEMORY != 0,
        label,
    );
    if newp == 0 {
        return 0;
    }
    core::ptr::copy_nonoverlapping(
        p as *const u8,
        newp as *mut u8,
        core::cmp::min(old_cap, size) as usize,
    );
    if heap_free_in(arena_base, arena_bytes, p) {
        newp
    } else {
        let _ = heap_free_in(arena_base, arena_bytes, newp);
        0
    }
}

unsafe fn heap_alloc(size: u64, zero: bool) -> u64 {
    heap_alloc_in(
        WIN32K_HEAP_VADDR,
        WIN32K_HEAP_FRAMES * 0x1000,
        size,
        zero,
        b"HEAP",
    )
}

unsafe fn heap_free(p: u64) -> bool {
    heap_free_in(WIN32K_HEAP_VADDR, WIN32K_HEAP_FRAMES * 0x1000, p)
}

unsafe fn hosted_heap_init(base: u64, reserve_size: u64) -> u64 {
    let arena_start = WIN32K_HEAP_VADDR + POOL_DATA_OFF;
    let arena_bytes = WIN32K_HEAP_FRAMES * 0x1000;
    let arena_end = WIN32K_HEAP_VADDR + arena_bytes;
    let reserve_size = (reserve_size + 0xFFF) & !0xFFF;
    if base < arena_start
        || reserve_size < POOL_DATA_OFF + HEAP_HDR_SIZE
        || base.checked_add(reserve_size).is_none_or(|end| end > arena_end)
        || heap_block_capacity_in(WIN32K_HEAP_VADDR, arena_bytes, base)
            .is_none_or(|capacity| capacity < reserve_size)
        || !register_hosted_heap_arena(base, reserve_size)
    {
        return 0;
    }
    write_volatile(base as *mut u64, POOL_DATA_OFF);
    write_volatile((base + 8) as *mut u64, 0);
    write_volatile(
        (base + HEAP_HANDLE_MAGIC_OFF) as *mut u64,
        HEAP_HANDLE_MAGIC,
    );
    write_volatile((base + HEAP_HANDLE_SIZE_OFF) as *mut u64, reserve_size);
    base
}

unsafe fn shared_hosted_heap_bounds(heap: u64) -> Option<(u64, u64)> {
    let arena_start = WIN32K_HEAP_VADDR + POOL_DATA_OFF;
    let arena_bytes = WIN32K_HEAP_FRAMES * 0x1000;
    let arena_end = WIN32K_HEAP_VADDR + arena_bytes;
    if heap < arena_start
        || heap
            .checked_add(HEAP_HANDLE_SIZE_OFF + 8)
            .is_none_or(|end| end > arena_end)
    {
        return None;
    }
    if read_volatile((heap + HEAP_HANDLE_MAGIC_OFF) as *const u64) != HEAP_HANDLE_MAGIC {
        return None;
    }
    let size = read_volatile((heap + HEAP_HANDLE_SIZE_OFF) as *const u64);
    if size < POOL_DATA_OFF + HEAP_HDR_SIZE
        || heap.checked_add(size).is_none_or(|end| end > arena_end)
        || heap_block_capacity_in(WIN32K_HEAP_VADDR, arena_bytes, heap)
            .is_none_or(|capacity| capacity < size)
    {
        return None;
    }
    Some((heap, size))
}

/// Validate a provider heap in the provider address space. The arena and allocation catalogs use
/// provider-private `Vec` storage and must never be dereferenced by the executive copy of this
/// module; callers that only consume already-published scalar mapping facts use
/// [`shared_hosted_heap_bounds`] instead.
unsafe fn hosted_heap_bounds(heap: u64) -> Option<(u64, u64)> {
    let bounds = shared_hosted_heap_bounds(heap)?;
    let arenas = (&*core::ptr::addr_of!(WIN32K_HOSTED_HEAP_ARENAS)).as_ref()?;
    arenas
        .iter()
        .any(|arena| arena.base == heap && arena.bytes == bounds.1)
        .then_some(bounds)
}

pub(crate) fn win32k_user_heap_delta() -> u64 {
    WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA
}

pub(crate) unsafe fn win32k_user_heap_committed_frames() -> u64 {
    let used = read_volatile(WIN32K_HEAP_VADDR as *const u64).max(POOL_DATA_OFF);
    ((used + 0xfff) / 0x1000).clamp(1, WIN32K_HEAP_FRAMES)
}

pub(crate) fn win32k_uservm_committed_frames() -> u64 {
    let mut high_slot = WIN32K_USERVM_NEXT_SLOT
        .load(Ordering::Relaxed)
        .clamp(USERVM_FIRST_SLOT as u64, USERVM_SLOT_COUNT as u64) as usize;
    let allocated = WIN32K_USERVM_ALLOC_MASK.load(Ordering::Relaxed);
    let mut slot = USERVM_SLOT_COUNT;
    while slot > USERVM_FIRST_SLOT {
        slot -= 1;
        if allocated & (1u64 << slot) != 0 {
            high_slot = high_slot.max(slot + 1);
            break;
        }
    }
    let frames = (high_slot as u64 * USERVM_GRANULARITY + 0xfff) / 0x1000;
    frames.clamp(USERVM_GRANULARITY / 0x1000, WIN32K_USERVM_FRAMES)
}

pub(crate) fn win32k_heap_server_to_client(addr: u64) -> Option<u64> {
    let heap_lo = WIN32K_HEAP_VADDR;
    let heap_hi = heap_lo + WIN32K_HEAP_FRAMES * 0x1000;
    if addr >= heap_lo && addr < heap_hi {
        addr.checked_sub(win32k_user_heap_delta())
    } else {
        None
    }
}

fn win32k_heap_client_to_server(addr: u64) -> Option<u64> {
    let client_lo = CSRSS_W32_SHARED_VA;
    let client_hi = client_lo + WIN32K_HEAP_FRAMES * 0x1000;
    if addr >= client_lo && addr < client_hi {
        addr.checked_add(win32k_user_heap_delta())
    } else {
        None
    }
}

unsafe fn desktop_heap_client_mapping(desk_body: u64) -> Option<(u64, u64, u64)> {
    if desk_body == 0 {
        return None;
    }
    let pheap = read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64);
    let (kernel_base, limit) = hosted_heap_bounds(pheap)?;
    let user_base = win32k_heap_server_to_client(kernel_base)?;
    Some((kernel_base, user_base, limit))
}

fn desktop_heap_client_address(
    server_addr: u64,
    kernel_base: u64,
    user_base: u64,
    limit: u64,
) -> Option<u64> {
    if server_addr >= kernel_base && server_addr < kernel_base + limit {
        Some(server_addr - kernel_base + user_base)
    } else {
        None
    }
}

unsafe fn ensure_process_desktop_heap_mapping(ppi: u64, desk_body: u64) -> Option<(u64, u64, u64)> {
    if ppi == 0 {
        return None;
    }
    let (kernel_base, user_base, limit) = desktop_heap_client_mapping(desk_body)?;
    let head = ppi + PROCESSINFO_HEAP_MAPPINGS_OFF;
    let mut prev_next = head + W32HEAP_MAPPING_NEXT_OFF;
    let mut mapping = read_volatile(prev_next as *const u64);
    let mut scanned = 0usize;
    while mapping != 0 && scanned < 64 {
        let kernel = read_volatile((mapping + W32HEAP_MAPPING_KERNEL_OFF) as *const u64);
        if kernel == kernel_base {
            write_volatile((mapping + W32HEAP_MAPPING_USER_OFF) as *mut u64, user_base);
            write_volatile((mapping + W32HEAP_MAPPING_LIMIT_OFF) as *mut u64, limit);
            if read_volatile((mapping + W32HEAP_MAPPING_COUNT_OFF) as *const u32) == 0 {
                let section = read_volatile((desk_body + DESKTOP_HSECTION_OFF) as *const u64);
                let (mapped_base, mapped_size) = section_view(section, limit);
                if mapped_base != kernel_base || mapped_size < limit {
                    if mapped_base != 0 {
                        let _ = unmap_section(section as *mut u8, mapped_base, |base| {
                            heap_free(base)
                        });
                    }
                    return None;
                }
                write_volatile((mapping + W32HEAP_MAPPING_COUNT_OFF) as *mut u32, 1);
            }
            return Some((kernel_base, user_base, limit));
        }
        prev_next = mapping + W32HEAP_MAPPING_NEXT_OFF;
        mapping = read_volatile(prev_next as *const u64);
        scanned += 1;
    }
    if scanned >= 64 {
        return None;
    }

    // A W32HEAP mapping row is a real client-view lease. Acquire the matching section view before
    // publishing Count=1 so IntUnmapDesktopView cannot consume the permanent session mapping.
    let section = read_volatile((desk_body + DESKTOP_HSECTION_OFF) as *const u64);
    let (mapped_base, mapped_size) = section_view(section, limit);
    if mapped_base != kernel_base || mapped_size < limit {
        if mapped_base != 0 {
            let _ = unmap_section(section as *mut u8, mapped_base, |base| heap_free(base));
        }
        return None;
    }
    let user_heap = read_volatile((head + W32HEAP_MAPPING_KERNEL_OFF) as *const u64);
    let mapping = s_rtl_allocate_heap(user_heap, HEAP_ZERO_MEMORY, W32HEAP_MAPPING_SIZE);
    if mapping == 0 {
        let _ = unmap_section(section as *mut u8, mapped_base, |base| heap_free(base));
        return None;
    }
    write_volatile((mapping + W32HEAP_MAPPING_NEXT_OFF) as *mut u64, 0);
    write_volatile(
        (mapping + W32HEAP_MAPPING_KERNEL_OFF) as *mut u64,
        kernel_base,
    );
    write_volatile((mapping + W32HEAP_MAPPING_USER_OFF) as *mut u64, user_base);
    write_volatile((mapping + W32HEAP_MAPPING_LIMIT_OFF) as *mut u64, limit);
    write_volatile((mapping + W32HEAP_MAPPING_COUNT_OFF) as *mut u32, 1);
    write_volatile(prev_next as *mut u64, mapping);
    Some((kernel_base, user_base, limit))
}

unsafe fn ensure_thread_desktop_pcti(pti: u64, desk_body: u64) -> u64 {
    if pti == 0 || desk_body == 0 {
        return 0;
    }
    let pheap = read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64);
    let Some((kernel_base, limit)) = hosted_heap_bounds(pheap) else {
        return 0;
    };
    let pcti = read_volatile((pti + THREADINFO_PCTI_OFF) as *const u64);
    if heap_block_capacity_in(kernel_base, limit, pcti)
        .is_some_and(|capacity| capacity >= CLIENTTHREADINFO_SIZE)
    {
        return pcti;
    }
    let pcti = s_rtl_allocate_heap(pheap, HEAP_ZERO_MEMORY, CLIENTTHREADINFO_SIZE);
    if pcti != 0 {
        write_volatile((pti + THREADINFO_PCTI_OFF) as *mut u64, pcti);
    }
    pcti
}

unsafe fn write_thread_client_desktop_info(
    pti: u64,
    desk_body: u64,
    pdeskinfo: u64,
) -> Option<(u64, u64, u64)> {
    let mut ppi = read_u64_field_if_present(pti, THREADINFO_PPI_OFF);
    if ppi == 0 {
        ppi = current_w32process();
    }
    let (kernel_base, user_base, limit) = ensure_process_desktop_heap_mapping(ppi, desk_body)?;
    let delta = kernel_base - user_base;
    let client_deskinfo = desktop_heap_client_address(pdeskinfo, kernel_base, user_base, limit)?;
    let pcti = ensure_thread_desktop_pcti(pti, desk_body);
    let client_pcti = desktop_heap_client_address(pcti, kernel_base, user_base, limit).unwrap_or(0);
    let pci = read_volatile((pti + THREADINFO_PCLIENTINFO_OFF) as *const u64);
    if pci != 0 {
        write_volatile(
            (pci + CLIENTINFO_PDESKINFO_OFF) as *mut u64,
            client_deskinfo,
        );
        write_volatile((pci + CLIENTINFO_ULCLIENTDELTA_OFF) as *mut u64, delta);
        write_volatile(
            (pci + CLIENTINFO_PCLIENTTHREADINFO_OFF) as *mut u64,
            client_pcti,
        );
    }
    Some((client_deskinfo, delta, client_pcti))
}

unsafe fn prepare_thread_desktop_client_info(pti: u64) -> Option<()> {
    if pti == 0 {
        return None;
    }
    let desk_body = read_volatile((pti + THREADINFO_RPDESK_OFF) as *const u64);
    let server_deskinfo = ensure_desktop_runtime_fields(desk_body)?;
    if read_volatile((pti + THREADINFO_PDESKINFO_OFF) as *const u64) != server_deskinfo {
        write_volatile(
            (pti + THREADINFO_PDESKINFO_OFF) as *mut u64,
            server_deskinfo,
        );
    }
    write_thread_client_desktop_info(pti, desk_body, server_deskinfo)?;
    Some(())
}

unsafe fn prepared_process_desktop_mapping(
    ppi: u64,
    kernel_base: u64,
    user_base: u64,
    limit: u64,
) -> bool {
    if ppi == 0 {
        return false;
    }
    let mut mapping = read_volatile(
        (ppi + PROCESSINFO_HEAP_MAPPINGS_OFF + W32HEAP_MAPPING_NEXT_OFF) as *const u64,
    );
    let mut scanned = 0usize;
    while mapping != 0 && scanned < 64 {
        if read_volatile((mapping + W32HEAP_MAPPING_KERNEL_OFF) as *const u64) == kernel_base {
            return read_volatile((mapping + W32HEAP_MAPPING_USER_OFF) as *const u64) == user_base
                && read_volatile((mapping + W32HEAP_MAPPING_LIMIT_OFF) as *const u64) == limit
                && read_volatile((mapping + W32HEAP_MAPPING_COUNT_OFF) as *const u32) != 0;
        }
        mapping = read_volatile((mapping + W32HEAP_MAPPING_NEXT_OFF) as *const u64);
        scanned += 1;
    }
    false
}

pub(crate) unsafe fn desktop_client_info_for_w32thread(pti: u64) -> Option<(u64, u64, u64, u64)> {
    if pti == 0 {
        return None;
    }
    let desk_body = read_volatile((pti + THREADINFO_RPDESK_OFF) as *const u64);
    if desk_body == 0 {
        return None;
    }
    let hsection = read_volatile((desk_body + DESKTOP_HSECTION_OFF) as *const u64);
    if !is_section(hsection as *const u8) {
        return None;
    }
    let pheap = read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64);
    let (kernel_base, limit) = shared_hosted_heap_bounds(pheap)?;
    let server_deskinfo = read_volatile((pti + THREADINFO_PDESKINFO_OFF) as *const u64);
    if server_deskinfo == 0
        || server_deskinfo != read_volatile((desk_body + 0x08) as *const u64)
        || heap_block_capacity_in(kernel_base, limit, server_deskinfo)
            .is_none_or(|capacity| capacity < DESKTOPINFO_MIN_ALLOC)
        || read_volatile(server_deskinfo as *const u64) != kernel_base
        || read_volatile((server_deskinfo + 0x08) as *const u64) != kernel_base + limit
    {
        return None;
    }
    let user_base = win32k_heap_server_to_client(kernel_base)?;
    let ppi = read_u64_field_if_present(pti, THREADINFO_PPI_OFF);
    if !prepared_process_desktop_mapping(ppi, kernel_base, user_base, limit) {
        return None;
    }
    let delta = kernel_base - user_base;
    let client_deskinfo = desktop_heap_client_address(
        server_deskinfo,
        kernel_base,
        user_base,
        limit,
    )?;
    let pcti = read_volatile((pti + THREADINFO_PCTI_OFF) as *const u64);
    if heap_block_capacity_in(kernel_base, limit, pcti)
        .is_none_or(|capacity| capacity < CLIENTTHREADINFO_SIZE)
    {
        return None;
    }
    let client_pcti = desktop_heap_client_address(pcti, kernel_base, user_base, limit)?;
    let pci = read_volatile((pti + THREADINFO_PCLIENTINFO_OFF) as *const u64);
    if pci == 0
        || read_volatile((pci + CLIENTINFO_PDESKINFO_OFF) as *const u64) != client_deskinfo
        || read_volatile((pci + CLIENTINFO_ULCLIENTDELTA_OFF) as *const u64) != delta
        || read_volatile((pci + CLIENTINFO_PCLIENTTHREADINFO_OFF) as *const u64) != client_pcti
    {
        return None;
    }
    Some((client_deskinfo, pti, delta, client_pcti))
}

unsafe fn default_keyboard_layout_from_ring() -> u64 {
    let first = read_volatile((WIN32K_CODE_VA + GSPKL_BASE_LAYOUT_RVA) as *const u64);
    if first == 0 {
        return 0;
    }

    let mut kl = first;
    for _ in 0..WIN32K_KL_WALK_LIMIT {
        let flags = read_volatile((kl + KL_FLAGS_OFF) as *const u32);
        if flags & KL_UNLOAD == 0 {
            return kl;
        }

        let prev = read_volatile((kl + KL_PKL_PREV_OFF) as *const u64);
        if prev == 0 {
            return 0;
        }
        kl = prev;
        if kl == first {
            return 0;
        }
    }
    0
}

unsafe fn refresh_default_keyboard_layout() -> u64 {
    let kl = default_keyboard_layout_from_ring();
    let current = WIN32K_DEFAULT_KEYBOARD_LAYOUT.load(Ordering::Relaxed);
    if kl == 0 || kl == current {
        return kl;
    }

    WIN32K_DEFAULT_KEYBOARD_LAYOUT.store(kl, Ordering::Relaxed);
    let n = WIN32K_KEYBOARD_LAYOUT_OBSERVES.fetch_add(1, Ordering::Relaxed);
    if n < 8 {
        let hkl = read_volatile((kl + KL_HKL_OFF) as *const u64);
        let codepage = read_volatile((kl + KL_CODEPAGE_OFF) as *const u16);
        print_str(b"[win32k-kbd] default KL observed from gspklBaseLayout hkl=0x");
        print_hex((hkl >> 32) as u32);
        print_hex(hkl as u32);
        print_str(b" kl=0x");
        print_hex((kl >> 32) as u32);
        print_hex(kl as u32);
        print_str(b" codepage=");
        print_u64(codepage as u64);
        print_str(b"\n");
    }
    kl
}

unsafe fn keyboard_layout_client_values(kl: u64) -> Option<(u64, u16)> {
    if kl == 0 {
        return None;
    }
    let hkl = read_volatile((kl + KL_HKL_OFF) as *const u64);
    if hkl == 0 {
        return None;
    }
    let codepage = read_volatile((kl + KL_CODEPAGE_OFF) as *const u16);
    Some((hkl, codepage))
}

unsafe fn bind_default_keyboard_layout_to_thread(pti: u64) -> Option<(u64, u64, u16)> {
    if pti == 0 {
        return None;
    }

    let mut kl = read_volatile((pti + THREADINFO_KEYBOARD_LAYOUT_OFF) as *const u64);
    let bound_new = if kl == 0 {
        kl = refresh_default_keyboard_layout();
        if kl == 0 {
            return None;
        }
        write_volatile((pti + THREADINFO_KEYBOARD_LAYOUT_OFF) as *mut u64, kl);
        true
    } else {
        false
    };

    let (hkl, codepage) = keyboard_layout_client_values(kl)?;
    let pci = read_volatile((pti + THREADINFO_PCLIENTINFO_OFF) as *const u64);
    if pci != 0 {
        write_volatile((pci + CLIENTINFO_HKL_OFF) as *mut u64, hkl);
        write_volatile((pci + CLIENTINFO_CODEPAGE_OFF) as *mut u16, codepage);
    }

    if bound_new {
        let n = WIN32K_KEYBOARD_LAYOUT_BINDINGS.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-kbd] bound default KL to pti=0x");
            print_hex((pti >> 32) as u32);
            print_hex(pti as u32);
            print_str(b" hkl=0x");
            print_hex((hkl >> 32) as u32);
            print_hex(hkl as u32);
            print_str(b" kl=0x");
            print_hex((kl >> 32) as u32);
            print_hex(kl as u32);
            print_str(b"\n");
        }
    }
    Some((kl, hkl, codepage))
}

pub(crate) unsafe fn keyboard_layout_client_info_for_w32thread(
    pti: u64,
) -> Option<(u64, u64, u16)> {
    bind_default_keyboard_layout_to_thread(pti)
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

/// `PVOID RtlCreateHeap(Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters)`. win32k creates
/// the global USER heap and every desktop heap over a section view; return that view as the heap
/// handle and keep subsequent allocations inside the section-backed arena.
extern "win64" fn s_rtl_create_heap(
    _flags: u64,
    heap_base: u64,
    reserve_size: u64,
    _commit_size: u64,
    _lock: u64,
    _parameters: u64,
) -> u64 {
    unsafe {
        if heap_base != 0 {
            return hosted_heap_init(heap_base, reserve_size);
        }
    }
    0
}
/// `PVOID RtlAllocateHeap(HeapHandle, Flags, Size)`.
extern "win64" fn s_rtl_allocate_heap(heap: u64, flags: u64, size: u64) -> u64 {
    unsafe {
        let Some((base, bytes)) = hosted_heap_bounds(heap) else {
            return 0;
        };
        heap_alloc_in(
            base,
            bytes,
            size,
            flags & HEAP_ZERO_MEMORY != 0,
            b"RTL_HEAP",
        )
    }
}
/// `BOOLEAN RtlFreeHeap(HeapHandle, Flags, Base)`.
extern "win64" fn s_rtl_free_heap(heap: u64, _flags: u64, base: u64) -> u64 {
    if base == 0 {
        return 1;
    }
    unsafe {
        let Some((arena_base, arena_bytes)) = hosted_heap_bounds(heap) else {
            return 0;
        };
        heap_free_in(arena_base, arena_bytes, base) as u64
    }
}
/// `SIZE_T RtlSizeHeap(HeapHandle, Flags, Base)`.
extern "win64" fn s_rtl_size_heap(heap: u64, _flags: u64, base: u64) -> u64 {
    unsafe {
        let Some((arena_base, arena_bytes)) = hosted_heap_bounds(heap) else {
            return u64::MAX;
        };
        heap_block_capacity_in(arena_base, arena_bytes, base).unwrap_or(u64::MAX)
    }
}
/// `PVOID RtlReAllocateHeap(HeapHandle, Flags, Base, Size)`.
extern "win64" fn s_rtl_reallocate_heap(heap: u64, flags: u64, base: u64, size: u64) -> u64 {
    unsafe {
        let Some((arena_base, arena_bytes)) = hosted_heap_bounds(heap) else {
            return 0;
        };
        heap_realloc_in(arena_base, arena_bytes, flags, base, size, b"RTL_HEAP")
    }
}

use nt_kernel_exec::session_section::{
    init_section, is_section, map_section, section_contains_addr, section_next, section_object,
    section_size, set_section_next, unmap_section,
};

const STATUS_NO_MEMORY: i32 = 0xC000_0017u32 as i32;
static WIN32K_SECTION_LIST_HEAD: AtomicU64 = AtomicU64::new(0);

unsafe fn register_section_descriptor(desc: u64) {
    loop {
        let head = WIN32K_SECTION_LIST_HEAD.load(Ordering::Relaxed);
        set_section_next(desc as *mut u8, head);
        if WIN32K_SECTION_LIST_HEAD
            .compare_exchange(head, desc, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

unsafe fn find_section_for_view_addr(addr: u64) -> u64 {
    let mut cur = WIN32K_SECTION_LIST_HEAD.load(Ordering::Relaxed);
    let mut scanned = 0usize;
    while cur != 0 && scanned < 4096 {
        if is_section(cur as *const u8) {
            if section_contains_addr(cur as *const u8, addr) {
                return cur;
            }
            cur = section_next(cur as *const u8);
        } else {
            break;
        }
        scanned += 1;
    }
    0
}

unsafe fn unmap_section_view_addr(addr: u64) -> i32 {
    if addr == 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let backing_addr = win32k_heap_client_to_server(addr).unwrap_or(addr);
    let section = find_section_for_view_addr(backing_addr);
    if section == 0 {
        print_str(b"[win32k-host] MmUnmapView: unmapped/foreign base=0x");
        print_hex((addr >> 32) as u32);
        print_hex(addr as u32);
        print_str(b"\n");
        return STATUS_INVALID_PARAMETER_I32;
    }
    if unmap_section(section as *mut u8, backing_addr, |base| heap_free(base)) {
        0
    } else {
        STATUS_INVALID_PARAMETER_I32
    }
}

/// Resolve (allocating once, from the heap arena) the coherent backing base + size for a section
/// map. The section must be one of our [`init_section`] descriptors, so the kernel session view and
/// every per-process view share one backing. Unknown section pointers fail instead of receiving a
/// synthetic private mapping.
unsafe fn section_view(section: u64, _size_hint: u64) -> (u64, u64) {
    if section == 0 || !is_section(section as *const u8) {
        return (0, 0);
    }
    let sz = section_size(section as *const u8);
    (map_section(section as *mut u8, |s| heap_alloc(s, true)), sz)
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
        register_section_descriptor(desc);
        if !section_out.is_null() {
            write_unaligned(section_out, desc);
        }
    }
    0
}

/// `NTSTATUS MmUnmapViewOfSection(PEPROCESS Process, PVOID BaseAddress)`. The host maps session
/// sections at the same VA for kernel and client views, so unmap is logical: validate the base
/// belongs to a live section view, drop that view's reference, and release the backing when it was
/// the final view.
extern "win64" fn s_mm_unmap_view_of_section(_process: u64, base: u64) -> i32 {
    unsafe { unmap_section_view_addr(base) }
}

/// `NTSTATUS MmUnmapViewInSessionSpace(PVOID MappedBase)` / `MmUnmapViewInSystemSpace`.
extern "win64" fn s_mm_unmap_view_in_space(base: u64) -> i32 {
    unsafe { unmap_section_view_addr(base) }
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
/// ULONG AllocationType, ULONG Win32Protect)` — `MapGlobalUserHeap` and `IntMapDesktopView` project
/// USER/desktop heap sections into GUI client processes. The backing remains the coherent win32k heap
/// region, but the returned view base is the logical client alias inside `CSRSS_W32_SHARED_VA` so
/// ReactOS' W32PROCESS heap mappings publish the same server→client delta that user32 will use.
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
        let view_base = win32k_heap_server_to_client(base).unwrap_or(base);
        if !base_out.is_null() {
            write_volatile(base_out, view_base);
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
            reclaiming_pool_alloc(size)
        } else {
            provider_pool_alloc(size, false)
        }
    }
}
/// `PVOID ExAllocatePool(POOL_TYPE, SIZE_T NumberOfBytes)`.
extern "win64" fn s_ex_alloc_pool(_pool: u64, size: u64) -> u64 {
    unsafe { provider_pool_alloc(size, false) }
}
/// `PVOID ExAllocatePoolWithQuotaTag(POOL_TYPE, SIZE_T, ULONG Tag)`.
extern "win64" fn s_ex_alloc_pool_quota(_pool: u64, size: u64, _tag: u64) -> u64 {
    unsafe { provider_pool_alloc(size, false) }
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

/// `VOID ExFreePoolWithTag(PVOID, ULONG)`. Resolve the allocation by exact arena membership and
/// live-header validation. Foreign and duplicate frees remain visible instead of being accepted.
extern "win64" fn s_ex_free_pool_with_tag(p: u64, _tag: u64) {
    unsafe {
        let in_provider_pool = provider_pool_contains(p);
        let in_ftyp_pool = p >= WIN32K_FTYP_VADDR + POOL_DATA_OFF + FTYP_HDR_SIZE
            && p < WIN32K_FTYP_VADDR + WIN32K_FTYP_FRAMES * 0x1000;
        let freed = if in_provider_pool {
            provider_pool_free(p)
        } else if in_ftyp_pool {
            reclaiming_pool_free(p)
        } else {
            provider_pool_note_invalid_free();
            false
        };
        if freed {
            return;
        }
        if in_ftyp_pool {
            provider_pool_note_invalid_free();
        }
        let invalid = provider_pool_census().invalid_frees;
        if invalid <= 8 || invalid.is_power_of_two() {
            print_str(b"[win32k-host] invalid ExFreePool pointer=0x");
            print_hex((p >> 32) as u32);
            print_hex(p as u32);
            print_str(b" count=");
            print_u64(invalid);
            print_str(b"\n");
        }
        park();
    }
}

extern "win64" fn s_ex_free_pool(p: u64) {
    s_ex_free_pool_with_tag(p, 0);
}

// --- ZwAllocateVirtualMemory + RTL_BITMAP (GDI DC_ATTR / RGN_ATTR pool) -----------------------

const MEM_COMMIT: u64 = 0x1000;
const MEM_RESERVE: u64 = 0x2000;
const MEM_DECOMMIT: u64 = 0x4000;
const MEM_RELEASE: u64 = 0x8000;

/// `NTSTATUS ZwAllocateVirtualMemory(HANDLE, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T
/// RegionSize, ULONG AllocationType, ULONG Protect)`. win32k uses this both for the GDI attribute
/// pool (`GdiPoolAllocateSection` reserves 64 KiB, then commits pages on demand) and for small
/// user-mode buffers while resolving window stations/desktops. The USERVM arena is pre-mapped RW:
/// reserve and bare-commit allocate tracked 64 KiB slot runs, while commit into an already mapped
/// view is bookkeeping because the backing pages are already present.
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
        if alloc_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
            return STATUS_INVALID_PARAMETER_I32;
        }
        let want = read_volatile(size_io);
        if want == 0 {
            return STATUS_INVALID_PARAMETER_I32;
        }
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

/// `NTSTATUS ZwFreeVirtualMemory(HANDLE, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)`.
/// ReactOS callers release both GDI reservations and short-lived user buffers with MEM_RELEASE; some
/// pass zero `RegionSize`, others pass the captured size, so the tracked allocation base is the
/// authority for returning a slot run to the arena.
extern "win64" fn s_zw_free_virtual_memory(
    _process: u64,
    base_io: *mut u64,
    size_io: *mut u64,
    free_type: u64,
) -> i32 {
    if base_io.is_null() || size_io.is_null() {
        return STATUS_INVALID_PARAMETER_I32;
    }
    unsafe {
        let base = read_volatile(base_io);
        if free_type == MEM_RELEASE {
            if !uservm_release(base) {
                return STATUS_INVALID_PARAMETER_I32;
            }
            write_volatile(base_io, 0);
            write_volatile(size_io, 0);
            return 0;
        }
        if free_type == MEM_DECOMMIT {
            write_volatile(size_io, (read_volatile(size_io) + 0xFFF) & !0xFFF);
            return 0;
        }
    }
    STATUS_INVALID_PARAMETER_I32
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

/// Reusable arenas backing the atom tables this component hands out (`gAtomTable` +
/// per-window-station tables). Lazily pool-allocated on demand; each table is a distinct sub-region
/// so class atoms (global table) and global atoms (winsta tables) don't collide. Each arena is 64 KiB
/// (≈125 full-length entries — ample for system classes + user atoms).
const ATOM_ARENA_BYTES: u64 = 0x10000;

#[derive(Clone, Copy)]
struct AtomArenaRecord {
    table: u64,
    in_use: bool,
}

static mut ATOM_ARENAS: Option<Vec<AtomArenaRecord>> = None;

fn atom_arenas_mut() -> &'static mut Vec<AtomArenaRecord> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(ATOM_ARENAS);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        slot.as_mut().expect("initialized above")
    }
}

fn atom_arenas() -> Option<&'static Vec<AtomArenaRecord>> {
    unsafe { (&*core::ptr::addr_of!(ATOM_ARENAS)).as_ref() }
}

unsafe fn atom_arena_alloc() -> u64 {
    let arenas = atom_arenas_mut();
    for record in arenas.iter_mut() {
        if record.table != 0 && !record.in_use {
            record.in_use = true;
            return record.table;
        }
    }
    if arenas.try_reserve(1).is_err() {
        print_str(b"[win32k-atom] ERROR: arena record allocation failed\n");
        return 0;
    }
    let arena = pool_alloc(ATOM_ARENA_BYTES);
    if arena == 0 {
        return 0;
    }
    arenas.push(AtomArenaRecord {
        table: arena,
        in_use: true,
    });
    arena
}

fn atom_arena_release(table: u64) -> bool {
    unsafe {
        if let Some(arenas) = (&mut *core::ptr::addr_of_mut!(ATOM_ARENAS)).as_mut() {
            if let Some(record) = arenas.iter_mut().find(|record| record.table == table) {
                let was_in_use = record.in_use;
                record.in_use = false;
                return was_in_use;
            }
        }
    }
    false
}

fn atom_arena_is_in_use(table: u64) -> bool {
    if let Some(arenas) = atom_arenas() {
        for record in arenas {
            if record.table == table {
                return record.in_use;
            }
        }
    }
    false
}

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
        let arena = atom_arena_alloc();
        if arena == 0 {
            return rtl_atom::status::NO_MEMORY as i32;
        }
        let table = rtl_atom::create(arena as *mut u8, ATOM_ARENA_BYTES as usize);
        if table.is_null() {
            atom_arena_release(arena);
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
/// `NTSTATUS RtlDestroyAtomTable(PRTL_ATOM_TABLE)`. Clear the raw table and release its typed atom
/// arena for reuse. The general win32k pool remains bump-only; atom arenas have separate ownership
/// because all allocations are fixed-size and only reachable through this RTL atom table API.
extern "win64" fn s_rtl_destroy_atom_table(table: u64) -> i32 {
    if table == 0 {
        return rtl_atom::status::INVALID_PARAMETER as i32;
    }
    if !atom_arena_is_in_use(table) {
        return rtl_atom::status::INVALID_PARAMETER as i32;
    }
    let status = unsafe { rtl_atom::destroy(table as *mut u8, ATOM_ARENA_BYTES as usize) };
    if status != rtl_atom::status::SUCCESS {
        return status as i32;
    }
    atom_arena_release(table);
    rtl_atom::status::SUCCESS as i32
}

static WIN32K_CURRENT_PROCESS_ID: AtomicU64 = AtomicU64::new(FAKE_PROCESS_HANDLE);
static WIN32K_CURRENT_THREAD_ID: AtomicU64 = AtomicU64::new(WIN32K_BOOTSTRAP_TID);
static WIN32K_CURRENT_CLIENT_PI: AtomicU64 = AtomicU64::new(WIN32K_BOOTSTRAP_PI as u64);
const WIN32K_PROCESS_CTX_INITIAL_CAP: u64 = 8;
const WIN32K_THREAD_CTX_INITIAL_CAP: u64 = 64;
#[derive(Clone, Copy)]
struct Win32kProcessContextRecord {
    pid: u64,
    pi: u64,
    generation: u64,
    eprocess: u64,
    w32process: u64,
    terminating: u64,
    client_peb: u64,
    token_authentication_id: u64,
    primary_token: u64,
}

#[derive(Clone, Copy)]
struct Win32kThreadContextRecord {
    tid: u64,
    pid: u64,
    pi: u64,
    generation: u64,
    teb: u64,
    callout_teb: u64,
    ethread: u64,
    w32thread: u64,
}

static WIN32K_PROCESS_CTX_PTR: AtomicU64 = AtomicU64::new(0);
static WIN32K_PROCESS_CTX_LEN: AtomicU64 = AtomicU64::new(0);
static WIN32K_PROCESS_CTX_CAP: AtomicU64 = AtomicU64::new(0);
static WIN32K_PROCESS_CTX_GROWTHS: AtomicU64 = AtomicU64::new(0);
static WIN32K_PROCESS_CTX_ALLOC_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_THREAD_CTX_PTR: AtomicU64 = AtomicU64::new(0);
static WIN32K_THREAD_CTX_LEN: AtomicU64 = AtomicU64::new(0);
static WIN32K_THREAD_CTX_CAP: AtomicU64 = AtomicU64::new(0);
static WIN32K_THREAD_CTX_GROWTHS: AtomicU64 = AtomicU64::new(0);
static WIN32K_THREAD_CTX_ALLOC_FAILURES: AtomicU64 = AtomicU64::new(0);
// Context dispatch and callback resume are continuation-serialized through the single win32k
// component. Release publication therefore forms the quiescent boundary for replacing table
// backing. A future multi-worker provider must add an explicit read-side lifetime protocol.
static WIN32K_CONTEXT_EPROCESS_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_EPROCESS_FREES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_ETHREAD_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_ETHREAD_FREES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_TOKEN_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_TOKEN_FREES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_CALLOUT_TEB_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_CALLOUT_TEB_FREES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_BACKING_FREES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_TOKEN_HANDLE_RELEASES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CONTEXT_RETIREMENT_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_TOKEN_HANDLE_SLOTS_PTR: AtomicU64 = AtomicU64::new(0);
static WIN32K_TOKEN_HANDLE_LEN: AtomicU64 = AtomicU64::new(0);
static WIN32K_TOKEN_HANDLE_CAPACITY: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_PROCESS_CALLOUTS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_THREAD_CALLOUTS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CONTEXT_TRACES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CALLBACK_RESUME_CONTEXT_RESTORES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CALLBACK_RESUME_CONTEXT_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_PEB_INSTALLS: AtomicU64 = AtomicU64::new(0);
static WIN32K_WALL_CONTEXT_TRACES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_TOKEN_CONTEXT_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_PRIMARY_TOKEN_REFERENCE_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_PENDING_OB_UNCACHED_WINSTA: AtomicU64 = AtomicU64::new(0);
const WIN32K_SERVICE_WINSTA_INITIAL_CAP: u64 = 4;
static WIN32K_SERVICE_WINSTA_RECORDS_PTR: AtomicU64 = AtomicU64::new(0);
static WIN32K_SERVICE_WINSTA_RECORDS_LEN: AtomicU64 = AtomicU64::new(0);
static WIN32K_SERVICE_WINSTA_RECORDS_CAP: AtomicU64 = AtomicU64::new(0);
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
static WIN32K_TICK_COUNT: AtomicU64 = AtomicU64::new(1);

pub(crate) unsafe fn current_thread_queue_event_body() -> Option<u64> {
    let w32thread = current_w32thread();
    if w32thread == 0 {
        return None;
    }
    let body = read_volatile((w32thread + THREADINFO_PEVENT_QUEUE_SERVER_OFF) as *const u64);
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

unsafe fn process_ctx_record_ptr(base: u64, index: usize) -> *mut Win32kProcessContextRecord {
    (base + index as u64 * core::mem::size_of::<Win32kProcessContextRecord>() as u64)
        as *mut Win32kProcessContextRecord
}

unsafe fn thread_ctx_record_ptr(base: u64, index: usize) -> *mut Win32kThreadContextRecord {
    (base + index as u64 * core::mem::size_of::<Win32kThreadContextRecord>() as u64)
        as *mut Win32kThreadContextRecord
}

unsafe fn process_ctx_len() -> usize {
    WIN32K_PROCESS_CTX_LEN.load(Ordering::Acquire) as usize
}

unsafe fn thread_ctx_len() -> usize {
    WIN32K_THREAD_CTX_LEN.load(Ordering::Acquire) as usize
}

unsafe fn process_ctx_index_valid(index: usize) -> bool {
    index < process_ctx_len()
}

unsafe fn thread_ctx_index_valid(index: usize) -> bool {
    index < thread_ctx_len()
}

unsafe fn process_ctx_ptr(index: usize) -> Option<*mut Win32kProcessContextRecord> {
    if !process_ctx_index_valid(index) {
        return None;
    }
    let base = WIN32K_PROCESS_CTX_PTR.load(Ordering::Acquire);
    (base != 0).then_some(process_ctx_record_ptr(base, index))
}

unsafe fn thread_ctx_ptr(index: usize) -> Option<*mut Win32kThreadContextRecord> {
    if !thread_ctx_index_valid(index) {
        return None;
    }
    let base = WIN32K_THREAD_CTX_PTR.load(Ordering::Acquire);
    (base != 0).then_some(thread_ctx_record_ptr(base, index))
}

macro_rules! process_ctx_getter {
    ($name:ident, $field:ident) => {
        unsafe fn $name(index: usize) -> u64 {
            process_ctx_ptr(index)
                .map(|ptr| read_volatile(core::ptr::addr_of!((*ptr).$field)))
                .unwrap_or(0)
        }
    };
}

macro_rules! process_ctx_setter {
    ($name:ident, $field:ident) => {
        unsafe fn $name(index: usize, value: u64) {
            if let Some(ptr) = process_ctx_ptr(index) {
                write_volatile(core::ptr::addr_of_mut!((*ptr).$field), value);
            }
        }
    };
}

macro_rules! thread_ctx_getter {
    ($name:ident, $field:ident) => {
        unsafe fn $name(index: usize) -> u64 {
            thread_ctx_ptr(index)
                .map(|ptr| read_volatile(core::ptr::addr_of!((*ptr).$field)))
                .unwrap_or(0)
        }
    };
}

macro_rules! thread_ctx_setter {
    ($name:ident, $field:ident) => {
        unsafe fn $name(index: usize, value: u64) {
            if let Some(ptr) = thread_ctx_ptr(index) {
                write_volatile(core::ptr::addr_of_mut!((*ptr).$field), value);
            }
        }
    };
}

process_ctx_getter!(process_ctx_pid, pid);
process_ctx_getter!(process_ctx_pi, pi);
process_ctx_getter!(process_ctx_generation, generation);
process_ctx_getter!(process_ctx_eprocess, eprocess);
process_ctx_getter!(process_ctx_w32process, w32process);
process_ctx_getter!(process_ctx_terminating, terminating);
process_ctx_getter!(process_ctx_client_peb, client_peb);
process_ctx_getter!(process_ctx_token_authentication_id, token_authentication_id);
process_ctx_getter!(process_ctx_primary_token, primary_token);
process_ctx_setter!(set_process_ctx_pid, pid);
process_ctx_setter!(set_process_ctx_pi, pi);
process_ctx_setter!(set_process_ctx_generation, generation);
process_ctx_setter!(set_process_ctx_eprocess, eprocess);
process_ctx_setter!(set_process_ctx_w32process, w32process);
process_ctx_setter!(set_process_ctx_terminating, terminating);
process_ctx_setter!(set_process_ctx_client_peb, client_peb);
process_ctx_setter!(
    set_process_ctx_token_authentication_id,
    token_authentication_id
);
process_ctx_setter!(set_process_ctx_primary_token, primary_token);

thread_ctx_getter!(thread_ctx_tid, tid);
thread_ctx_getter!(thread_ctx_pid, pid);
thread_ctx_getter!(thread_ctx_pi, pi);
thread_ctx_getter!(thread_ctx_generation, generation);
thread_ctx_getter!(thread_ctx_teb, teb);
thread_ctx_getter!(thread_ctx_callout_teb, callout_teb);
thread_ctx_getter!(thread_ctx_ethread, ethread);
thread_ctx_getter!(thread_ctx_w32thread, w32thread);
thread_ctx_setter!(set_thread_ctx_pid, pid);
thread_ctx_setter!(set_thread_ctx_pi, pi);
thread_ctx_setter!(set_thread_ctx_generation, generation);
thread_ctx_setter!(set_thread_ctx_teb, teb);
thread_ctx_setter!(set_thread_ctx_callout_teb, callout_teb);
thread_ctx_setter!(set_thread_ctx_ethread, ethread);
thread_ctx_setter!(set_thread_ctx_w32thread, w32thread);

unsafe fn provider_allocation_has_capacity(pointer: u64, required: u64) -> bool {
    pointer != 0
        && provider_pool_allocation_capacity(pointer).is_some_and(|capacity| capacity >= required)
}

/// Return whether `pointer` is provider-owned storage. Pointers outside the provider arena are
/// borrowed native objects; pointers inside it must name an exact live allocation of sufficient
/// size, otherwise the ownership boundary is corrupt and finalization must fail closed.
unsafe fn provider_storage_owned(pointer: u64, required: u64) -> Result<bool, ()> {
    if !provider_pool_contains(pointer) {
        return Ok(false);
    }
    provider_pool_allocation_capacity(pointer)
        .filter(|&capacity| capacity >= required)
        .map(|_| true)
        .ok_or(())
}

unsafe fn release_replaced_context_backing(pointer: u64) {
    if pointer == 0 {
        return;
    }
    if provider_pool_free(pointer) {
        WIN32K_CONTEXT_BACKING_FREES.fetch_add(1, Ordering::Relaxed);
    } else {
        WIN32K_CONTEXT_RETIREMENT_FAILURES.fetch_add(1, Ordering::Relaxed);
        print_str(b"[win32k-context] ERROR: replacement backing release failed pointer=0x");
        print_win32k_hex64(pointer);
        print_str(b"\n");
    }
}

unsafe fn ensure_process_ctx_capacity(required: u64) -> bool {
    let cap = WIN32K_PROCESS_CTX_CAP.load(Ordering::Relaxed);
    if cap >= required {
        return true;
    }
    let mut new_cap = if cap == 0 {
        WIN32K_PROCESS_CTX_INITIAL_CAP
    } else {
        cap.saturating_mul(2)
    };
    while new_cap < required {
        let next = new_cap.saturating_mul(2);
        if next <= new_cap {
            return false;
        }
        new_cap = next;
    }
    let Some(bytes) =
        (core::mem::size_of::<Win32kProcessContextRecord>() as u64).checked_mul(new_cap)
    else {
        return false;
    };
    let old_base = WIN32K_PROCESS_CTX_PTR.load(Ordering::Relaxed);
    let old_bytes = (core::mem::size_of::<Win32kProcessContextRecord>() as u64)
        .checked_mul(cap)
        .unwrap_or(u64::MAX);
    if old_base != 0 && !provider_allocation_has_capacity(old_base, old_bytes) {
        return false;
    }
    let new_base = pool_alloc(bytes);
    if new_base == 0 {
        return false;
    }
    let len = WIN32K_PROCESS_CTX_LEN.load(Ordering::Relaxed) as usize;
    if old_base != 0 {
        for index in 0..len {
            let record = read_volatile(process_ctx_record_ptr(old_base, index));
            write_volatile(process_ctx_record_ptr(new_base, index), record);
        }
    }
    WIN32K_PROCESS_CTX_PTR.store(new_base, Ordering::Release);
    WIN32K_PROCESS_CTX_CAP.store(new_cap, Ordering::Relaxed);
    WIN32K_PROCESS_CTX_GROWTHS.fetch_add(1, Ordering::Relaxed);
    release_replaced_context_backing(old_base);
    true
}

unsafe fn ensure_thread_ctx_capacity(required: u64) -> bool {
    let cap = WIN32K_THREAD_CTX_CAP.load(Ordering::Relaxed);
    if cap >= required {
        return true;
    }
    let mut new_cap = if cap == 0 {
        WIN32K_THREAD_CTX_INITIAL_CAP
    } else {
        cap.saturating_mul(2)
    };
    while new_cap < required {
        let next = new_cap.saturating_mul(2);
        if next <= new_cap {
            return false;
        }
        new_cap = next;
    }
    let Some(bytes) =
        (core::mem::size_of::<Win32kThreadContextRecord>() as u64).checked_mul(new_cap)
    else {
        return false;
    };
    let old_base = WIN32K_THREAD_CTX_PTR.load(Ordering::Relaxed);
    let old_bytes = (core::mem::size_of::<Win32kThreadContextRecord>() as u64)
        .checked_mul(cap)
        .unwrap_or(u64::MAX);
    if old_base != 0 && !provider_allocation_has_capacity(old_base, old_bytes) {
        return false;
    }
    let new_base = pool_alloc(bytes);
    if new_base == 0 {
        return false;
    }
    let len = WIN32K_THREAD_CTX_LEN.load(Ordering::Relaxed) as usize;
    if old_base != 0 {
        for index in 0..len {
            let record = read_volatile(thread_ctx_record_ptr(old_base, index));
            write_volatile(thread_ctx_record_ptr(new_base, index), record);
        }
    }
    WIN32K_THREAD_CTX_PTR.store(new_base, Ordering::Release);
    WIN32K_THREAD_CTX_CAP.store(new_cap, Ordering::Relaxed);
    WIN32K_THREAD_CTX_GROWTHS.fetch_add(1, Ordering::Relaxed);
    release_replaced_context_backing(old_base);
    true
}

unsafe fn reserve_process_ctx_record() -> Option<usize> {
    for index in 0..process_ctx_len() {
        if process_ctx_pid(index) == 0 {
            return Some(index);
        }
    }
    let len = WIN32K_PROCESS_CTX_LEN.load(Ordering::Relaxed);
    let required = len.checked_add(1)?;
    if !ensure_process_ctx_capacity(required) {
        let n = WIN32K_PROCESS_CTX_ALLOC_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: process context table allocation failed required=");
            print_u64(required);
            print_str(b"\n");
        }
        return None;
    }
    let base = WIN32K_PROCESS_CTX_PTR.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    Some(len as usize)
}

unsafe fn commit_process_ctx_record(index: usize, record: Win32kProcessContextRecord) {
    let base = WIN32K_PROCESS_CTX_PTR.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    write_volatile(process_ctx_record_ptr(base, index), record);
    let len = WIN32K_PROCESS_CTX_LEN.load(Ordering::Relaxed);
    if index as u64 == len {
        WIN32K_PROCESS_CTX_LEN.store(len + 1, Ordering::Release);
    }
}

unsafe fn reserve_thread_ctx_record() -> Option<usize> {
    for index in 0..thread_ctx_len() {
        if thread_ctx_tid(index) == 0 {
            return Some(index);
        }
    }
    let len = WIN32K_THREAD_CTX_LEN.load(Ordering::Relaxed);
    let required = len.checked_add(1)?;
    if !ensure_thread_ctx_capacity(required) {
        let n = WIN32K_THREAD_CTX_ALLOC_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[win32k-context] ERROR: thread context table allocation failed required=");
            print_u64(required);
            print_str(b"\n");
        }
        return None;
    }
    let base = WIN32K_THREAD_CTX_PTR.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    Some(len as usize)
}

unsafe fn commit_thread_ctx_record(index: usize, record: Win32kThreadContextRecord) {
    let base = WIN32K_THREAD_CTX_PTR.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    write_volatile(thread_ctx_record_ptr(base, index), record);
    let len = WIN32K_THREAD_CTX_LEN.load(Ordering::Relaxed);
    if index as u64 == len {
        WIN32K_THREAD_CTX_LEN.store(len + 1, Ordering::Release);
    }
}

unsafe fn note_context_retirement_failure(kind: &[u8], identity: u64) -> bool {
    let count = WIN32K_CONTEXT_RETIREMENT_FAILURES.fetch_add(1, Ordering::Relaxed);
    if count < 16 {
        print_str(b"[win32k-context] ERROR: ");
        print_str(kind);
        print_str(b" retirement rejected identity=");
        print_u64(identity);
        print_str(b"\n");
    }
    false
}

unsafe fn finalize_thread_ctx_record(index: usize) -> bool {
    let Some(ptr) = thread_ctx_ptr(index) else {
        return note_context_retirement_failure(b"thread", index as u64);
    };
    let record = read_volatile(ptr);
    if record.tid == 0 {
        return true;
    }
    if record.ethread == 0
        || record.w32thread != 0
        || read_volatile((record.ethread + KTHREAD_WIN32THREAD_OFF) as *const u64) != 0
    {
        return note_context_retirement_failure(b"thread", record.tid);
    }

    let owns_ethread = match provider_storage_owned(record.ethread, WIN32K_ETHREAD_BYTES) {
        Ok(owned) => owned,
        Err(()) => {
            return note_context_retirement_failure(b"thread-ethread-storage", record.tid)
        }
    };
    let owns_callout_teb = if record.callout_teb == 0 {
        false
    } else {
        match provider_storage_owned(record.callout_teb, 0x1000) {
            Ok(true) => true,
            Ok(false) | Err(()) => {
                return note_context_retirement_failure(b"thread-teb-storage", record.tid)
            }
        }
    };

    let mut owned = [(0u64, 0u64); 2];
    let mut owned_len = 0usize;
    if owns_callout_teb {
        owned[owned_len] = (record.callout_teb, 0x1000);
        owned_len += 1;
    }
    if owns_ethread {
        owned[owned_len] = (record.ethread, WIN32K_ETHREAD_BYTES);
        owned_len += 1;
    }
    if owned_len != 0 && !provider_pool_validate_owned(&owned[..owned_len]) {
        return note_context_retirement_failure(b"thread-owned-storage", record.tid);
    }

    if read_volatile((WIN32K_KPCR_VA + 0x30) as *const u64) == record.callout_teb
        || read_volatile((WIN32K_KPCR_VA + 0x30) as *const u64) == record.teb
    {
        write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, WIN32K_KPCR_VA);
    }
    if read_volatile((WIN32K_KPCR_VA + 0x188) as *const u64) == record.ethread {
        write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, 0);
    }
    if WIN32K_CURRENT_CLIENT_PI.load(Ordering::Relaxed) == record.pi
        && WIN32K_CURRENT_THREAD_ID.load(Ordering::Relaxed) == record.tid
    {
        WIN32K_CURRENT_THREAD_ID.store(0, Ordering::Relaxed);
        write_volatile(SLOT_W32THREAD as *mut u64, 0);
    }
    let shared = WIN32K_SHARED_VADDR;
    if read_volatile((shared + SH_CTX_ETHREAD) as *const u64) == record.ethread {
        write_volatile((shared + SH_CTX_THREAD_ID) as *mut u64, 0);
        write_volatile((shared + SH_CTX_ETHREAD) as *mut u64, 0);
        write_volatile((shared + SH_CTX_W32THREAD) as *mut u64, 0);
    }

    if owned_len != 0 && !provider_pool_release_owned(&owned[..owned_len]) {
        return note_context_retirement_failure(b"thread-owned-storage-free", record.tid);
    }
    if owns_callout_teb {
        WIN32K_CONTEXT_CALLOUT_TEB_FREES.fetch_add(1, Ordering::Relaxed);
    }
    if owns_ethread {
        WIN32K_CONTEXT_ETHREAD_FREES.fetch_add(1, Ordering::Relaxed);
    }
    write_volatile(
        ptr,
        Win32kThreadContextRecord {
            tid: 0,
            pid: 0,
            pi: 0,
            generation: 0,
            teb: 0,
            callout_teb: 0,
            ethread: 0,
            w32thread: 0,
        },
    );
    true
}

unsafe fn clear_token_handle_publications(token: u64) -> u64 {
    if token == 0 {
        return 0;
    }
    let base = WIN32K_TOKEN_HANDLE_SLOTS_PTR.load(Ordering::Acquire);
    let len = WIN32K_TOKEN_HANDLE_LEN.load(Ordering::Relaxed);
    if base == 0 {
        return 0;
    }
    let mut cleared = 0u64;
    for slot in 0..len {
        let pointer = token_handle_slot_ptr(base, slot);
        if read_volatile(pointer) == token {
            write_volatile(pointer, 0);
            cleared += 1;
        }
    }
    let mut new_len = len;
    while new_len != 0 && read_volatile(token_handle_slot_ptr(base, new_len - 1)) == 0 {
        new_len -= 1;
    }
    WIN32K_TOKEN_HANDLE_LEN.store(new_len, Ordering::Release);
    WIN32K_CONTEXT_TOKEN_HANDLE_RELEASES.fetch_add(cleared, Ordering::Relaxed);
    cleared
}

unsafe fn finalize_process_ctx_record(index: usize) -> bool {
    let Some(ptr) = process_ctx_ptr(index) else {
        return note_context_retirement_failure(b"process", index as u64);
    };
    let record = read_volatile(ptr);
    if record.pid == 0 {
        return true;
    }
    if record.eprocess == 0
        || record.w32process != 0
        || read_volatile((record.eprocess + EPROCESS_WIN32PROCESS_OFF) as *const u64) != 0
        || (0..thread_ctx_len()).any(|thread| thread_ctx_pid(thread) == record.pid)
    {
        return note_context_retirement_failure(b"process", record.pid);
    }

    let owns_eprocess = match provider_storage_owned(record.eprocess, WIN32K_EPROCESS_BYTES) {
        Ok(owned) => owned,
        Err(()) => {
            return note_context_retirement_failure(b"process-eprocess-storage", record.pid)
        }
    };
    let owns_primary_token = if record.primary_token == 0 {
        false
    } else {
        match provider_storage_owned(record.primary_token, WIN32K_PRIMARY_TOKEN_BYTES) {
            Ok(true) => true,
            Ok(false) | Err(()) => {
                return note_context_retirement_failure(b"process-token-storage", record.pid)
            }
        }
    };

    let mut owned = [(0u64, 0u64); 2];
    let mut owned_len = 0usize;
    if owns_primary_token {
        owned[owned_len] = (record.primary_token, WIN32K_PRIMARY_TOKEN_BYTES);
        owned_len += 1;
    }
    if owns_eprocess {
        owned[owned_len] = (record.eprocess, WIN32K_EPROCESS_BYTES);
        owned_len += 1;
    }
    if owned_len != 0 && !provider_pool_validate_owned(&owned[..owned_len]) {
        return note_context_retirement_failure(b"process-owned-storage", record.pid);
    }

    clear_token_handle_publications(record.primary_token);
    if read_volatile((WIN32K_KPCR_VA + 0x60) as *const u64) == record.eprocess {
        write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, 0);
    }
    if WIN32K_CURRENT_CLIENT_PI.load(Ordering::Relaxed) == record.pi
        && WIN32K_CURRENT_PROCESS_ID.load(Ordering::Relaxed) == record.pid
    {
        WIN32K_CURRENT_CLIENT_PI.store(WIN32K_BOOTSTRAP_PI as u64, Ordering::Relaxed);
        WIN32K_CURRENT_PROCESS_ID.store(0, Ordering::Relaxed);
        WIN32K_CURRENT_THREAD_ID.store(0, Ordering::Relaxed);
        write_volatile(SLOT_W32PROCESS as *mut u64, 0);
        write_volatile(SLOT_W32THREAD as *mut u64, 0);
    }
    let shared = WIN32K_SHARED_VADDR;
    if read_volatile((shared + SH_CTX_EPROCESS) as *const u64) == record.eprocess {
        write_volatile((shared + SH_CTX_PROCESS_ID) as *mut u64, 0);
        write_volatile((shared + SH_CTX_THREAD_ID) as *mut u64, 0);
        write_volatile((shared + SH_CTX_EPROCESS) as *mut u64, 0);
        write_volatile((shared + SH_CTX_ETHREAD) as *mut u64, 0);
        write_volatile((shared + SH_CTX_W32PROCESS) as *mut u64, 0);
        write_volatile((shared + SH_CTX_W32THREAD) as *mut u64, 0);
    }

    if owned_len != 0 && !provider_pool_release_owned(&owned[..owned_len]) {
        return note_context_retirement_failure(b"process-owned-storage-free", record.pid);
    }
    if owns_primary_token {
        WIN32K_CONTEXT_TOKEN_FREES.fetch_add(1, Ordering::Relaxed);
    }
    if owns_eprocess {
        WIN32K_CONTEXT_EPROCESS_FREES.fetch_add(1, Ordering::Relaxed);
    }
    write_volatile(
        ptr,
        Win32kProcessContextRecord {
            pid: 0,
            pi: 0,
            generation: 0,
            eprocess: 0,
            w32process: 0,
            terminating: 0,
            client_peb: 0,
            token_authentication_id: 0,
            primary_token: 0,
        },
    );
    true
}

unsafe fn process_context_object_matches_or_empty(index: usize, supplied: u64) -> bool {
    let existing = process_ctx_eprocess(index);
    supplied == 0 || existing == 0 || existing == supplied
}

unsafe fn thread_context_object_matches_or_empty(index: usize, supplied: u64) -> bool {
    let existing = thread_ctx_ethread(index);
    supplied == 0 || existing == 0 || existing == supplied
}

unsafe fn process_context_object_or_allocate(
    index: usize,
    supplied: u64,
    size: u64,
) -> Option<u64> {
    let existing = process_ctx_eprocess(index);
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
    set_process_ctx_eprocess(index, object);
    if supplied == 0 {
        WIN32K_CONTEXT_EPROCESS_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    Some(object)
}

unsafe fn thread_context_object_or_allocate(index: usize, supplied: u64, size: u64) -> Option<u64> {
    let existing = thread_ctx_ethread(index);
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
    set_thread_ctx_ethread(index, object);
    if supplied == 0 {
        WIN32K_CONTEXT_ETHREAD_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    Some(object)
}

pub(crate) fn win32k_context_store_stats() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        WIN32K_PROCESS_CTX_LEN.load(Ordering::Relaxed),
        WIN32K_PROCESS_CTX_CAP.load(Ordering::Relaxed),
        WIN32K_PROCESS_CTX_GROWTHS.load(Ordering::Relaxed),
        WIN32K_PROCESS_CTX_ALLOC_FAILURES.load(Ordering::Relaxed),
        WIN32K_THREAD_CTX_LEN.load(Ordering::Relaxed),
        WIN32K_THREAD_CTX_CAP.load(Ordering::Relaxed),
        WIN32K_THREAD_CTX_GROWTHS.load(Ordering::Relaxed),
        WIN32K_THREAD_CTX_ALLOC_FAILURES.load(Ordering::Relaxed),
    )
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Win32kContextLifetimeCensus {
    pub process_rows_live: u64,
    pub thread_rows_live: u64,
    pub eprocess_allocations: u64,
    pub eprocess_frees: u64,
    pub ethread_allocations: u64,
    pub ethread_frees: u64,
    pub token_allocations: u64,
    pub token_frees: u64,
    pub callout_teb_allocations: u64,
    pub callout_teb_frees: u64,
    pub backing_frees: u64,
    pub token_handle_releases: u64,
    pub retirement_failures: u64,
}

pub(crate) fn win32k_context_lifetime_census() -> Win32kContextLifetimeCensus {
    unsafe {
        let process_rows_live = (0..process_ctx_len())
            .filter(|&index| process_ctx_pid(index) != 0)
            .count() as u64;
        let thread_rows_live = (0..thread_ctx_len())
            .filter(|&index| thread_ctx_tid(index) != 0)
            .count() as u64;
        Win32kContextLifetimeCensus {
            process_rows_live,
            thread_rows_live,
            eprocess_allocations: WIN32K_CONTEXT_EPROCESS_ALLOCATIONS.load(Ordering::Relaxed),
            eprocess_frees: WIN32K_CONTEXT_EPROCESS_FREES.load(Ordering::Relaxed),
            ethread_allocations: WIN32K_CONTEXT_ETHREAD_ALLOCATIONS.load(Ordering::Relaxed),
            ethread_frees: WIN32K_CONTEXT_ETHREAD_FREES.load(Ordering::Relaxed),
            token_allocations: WIN32K_CONTEXT_TOKEN_ALLOCATIONS.load(Ordering::Relaxed),
            token_frees: WIN32K_CONTEXT_TOKEN_FREES.load(Ordering::Relaxed),
            callout_teb_allocations: WIN32K_CONTEXT_CALLOUT_TEB_ALLOCATIONS.load(Ordering::Relaxed),
            callout_teb_frees: WIN32K_CONTEXT_CALLOUT_TEB_FREES.load(Ordering::Relaxed),
            backing_frees: WIN32K_CONTEXT_BACKING_FREES.load(Ordering::Relaxed),
            token_handle_releases: WIN32K_CONTEXT_TOKEN_HANDLE_RELEASES.load(Ordering::Relaxed),
            retirement_failures: WIN32K_CONTEXT_RETIREMENT_FAILURES.load(Ordering::Relaxed),
        }
    }
}

unsafe fn process_context_index_for_pid(pid: u64) -> Option<usize> {
    if pid == 0 {
        return None;
    }
    for index in 0..process_ctx_len() {
        if process_ctx_pid(index) == pid {
            return Some(index);
        }
    }
    None
}

unsafe fn process_context_index_for_eprocess(process: u64) -> Option<usize> {
    if process == 0 {
        return None;
    }
    for index in 0..process_ctx_len() {
        if process_ctx_eprocess(index) == process {
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
    for index in 0..thread_ctx_len() {
        if thread_ctx_tid(index) == tid {
            return Some(index);
        }
    }
    None
}

unsafe fn thread_context_index_for_ethread(thread: u64) -> Option<usize> {
    if thread == 0 {
        return None;
    }
    for index in 0..thread_ctx_len() {
        if thread_ctx_ethread(index) == thread {
            return Some(index);
        }
    }
    None
}

unsafe fn thread_context_index_for_w32thread(thread: u64) -> Option<usize> {
    if thread == 0 {
        return None;
    }
    for index in 0..thread_ctx_len() {
        if thread_ctx_w32thread(index) == thread {
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
        .map(|index| process_ctx_eprocess(index))
        .unwrap_or(0)
}

unsafe fn current_ethread() -> u64 {
    current_thread_context_index()
        .map(|index| thread_ctx_ethread(index))
        .unwrap_or(0)
}

unsafe fn current_w32process() -> u64 {
    let Some(index) = current_process_context_index() else {
        return 0;
    };
    let eprocess = process_ctx_eprocess(index);
    if eprocess != 0 {
        let field = read_volatile((eprocess + EPROCESS_WIN32PROCESS_OFF) as *const u64);
        if field != 0 {
            if process_ctx_w32process(index) == 0 {
                set_process_ctx_w32process(index, field);
            }
            return field;
        }
    }
    process_ctx_w32process(index)
}

unsafe fn current_w32thread() -> u64 {
    current_thread_context_index()
        .map(|index| thread_ctx_w32thread(index))
        .unwrap_or(0)
}

static mut WIN32K_EXECUTIVE_RESOURCES: Option<
    nt_kernel_exec::executive_sync::ExecutiveResourceStore,
> = None;

fn executive_resources_mut() -> &'static mut nt_kernel_exec::executive_sync::ExecutiveResourceStore
{
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(WIN32K_EXECUTIVE_RESOURCES);
        if slot.is_none() {
            *slot = Some(nt_kernel_exec::executive_sync::ExecutiveResourceStore::new());
        }
        slot.as_mut().expect("initialized above")
    }
}

#[cold]
fn reject_executive_sync(
    operation: &'static [u8],
    error: nt_kernel_exec::executive_sync::ExecutiveSyncError,
) -> ! {
    print_str(b"[win32k-sync] ERROR: ");
    print_str(operation);
    print_str(b" rejected, reason=0x");
    print_hex(error as u32);
    print_str(b"\n");
    panic!("win32k executive synchronization contract violated")
}

#[cold]
fn reject_resource_sync(
    operation: &'static [u8],
    error: nt_kernel_exec::executive_sync::ExecutiveSyncError,
    resource: u64,
    thread: u64,
) -> ! {
    print_str(b"[win32k-sync] resource=0x");
    print_win32k_hex64(resource);
    print_str(b" current-thread=0x");
    print_win32k_hex64(thread);
    if resource != 0 && resource & 7 == 0 {
        unsafe {
            let active_count = read_unaligned(
                (resource + nt_kernel_exec::executive_sync::eresource_layout::ACTIVE_COUNT as u64)
                    as *const i16,
            );
            let flags = read_unaligned(
                (resource + nt_kernel_exec::executive_sync::eresource_layout::FLAG as u64)
                    as *const u16,
            );
            let owner = read_unaligned(
                (resource + nt_kernel_exec::executive_sync::eresource_layout::OWNER_ENTRY as u64)
                    as *const u64,
            );
            let recursion = read_unaligned(
                (resource
                    + nt_kernel_exec::executive_sync::eresource_layout::OWNER_ENTRY as u64
                    + nt_kernel_exec::executive_sync::owner_entry_layout::OWNER_COUNT_OR_TABLE_SIZE
                        as u64) as *const u32,
            );
            let active_entries = read_unaligned(
                (resource + nt_kernel_exec::executive_sync::eresource_layout::ACTIVE_ENTRIES as u64)
                    as *const u32,
            );
            print_str(b" native-owner=0x");
            print_win32k_hex64(owner);
            print_str(b" recursion=");
            print_u64(recursion as u64);
            print_str(b" active=");
            print_u64(active_count as u16 as u64);
            print_str(b" entries=");
            print_u64(active_entries as u64);
            print_str(b" flags=0x");
            print_hex(flags as u32);
        }
    }
    print_str(b"\n");
    reject_executive_sync(operation, error)
}

#[cold]
fn reject_fast_mutex_sync(
    operation: &'static [u8],
    error: nt_kernel_exec::executive_sync::ExecutiveSyncError,
    mutex: u64,
    thread: u64,
) -> ! {
    print_str(b"[win32k-sync] fast-mutex=0x");
    print_win32k_hex64(mutex);
    print_str(b" current-thread=0x");
    print_win32k_hex64(thread);
    if mutex != 0 && mutex & 7 == 0 {
        unsafe {
            let count = read_unaligned(
                (mutex + nt_kernel_exec::executive_sync::fast_mutex_layout::COUNT as u64)
                    as *const i32,
            );
            let owner = read_unaligned(
                (mutex + nt_kernel_exec::executive_sync::fast_mutex_layout::OWNER as u64)
                    as *const u64,
            );
            let contention = read_unaligned(
                (mutex + nt_kernel_exec::executive_sync::fast_mutex_layout::CONTENTION as u64)
                    as *const u32,
            );
            print_str(b" native-owner=0x");
            print_win32k_hex64(owner);
            print_str(b" count=");
            print_u64(count as u32 as u64);
            print_str(b" contention=");
            print_u64(contention as u64);
        }
    }
    print_str(b"\n");
    reject_executive_sync(operation, error)
}

/// `NTSTATUS ExInitializeResourceLite(PERESOURCE Resource)`.
extern "win64" fn s_ex_initialize_resource_lite(resource: u64) -> i32 {
    match unsafe { executive_resources_mut().initialize(resource as *mut u8) } {
        Ok(()) => 0,
        Err(nt_kernel_exec::executive_sync::ExecutiveSyncError::AllocationFailed) => {
            STATUS_INSUFFICIENT_RESOURCES_I32
        }
        Err(_) => STATUS_INVALID_PARAMETER_I32,
    }
}

/// `NTSTATUS ExDeleteResourceLite(PERESOURCE Resource)`.
extern "win64" fn s_ex_delete_resource_lite(resource: u64) -> i32 {
    match unsafe { executive_resources_mut().delete(resource as *mut u8) } {
        Ok(()) => 0,
        Err(error) => reject_executive_sync(b"ExDeleteResourceLite", error),
    }
}

fn acquire_resource_lite(
    resource: u64,
    wait: bool,
    mode: nt_kernel_exec::executive_sync::ResourceMode,
    operation: &'static [u8],
) -> u8 {
    let thread = unsafe { current_ethread() };
    match unsafe { executive_resources_mut().acquire(resource as *mut u8, thread, mode) } {
        Ok(nt_kernel_exec::executive_sync::AcquireResult::Acquired) => 1,
        Ok(nt_kernel_exec::executive_sync::AcquireResult::WouldBlock) if !wait => 0,
        Ok(nt_kernel_exec::executive_sync::AcquireResult::WouldBlock) => reject_resource_sync(
            operation,
            nt_kernel_exec::executive_sync::ExecutiveSyncError::BlockingWaitRequired,
            resource,
            thread,
        ),
        Err(error) => reject_resource_sync(operation, error, resource, thread),
    }
}

/// `BOOLEAN ExAcquireResourceExclusiveLite(PERESOURCE Resource, BOOLEAN Wait)`.
extern "win64" fn s_ex_acquire_resource_exclusive_lite(resource: u64, wait: u8) -> u8 {
    acquire_resource_lite(
        resource,
        wait != 0,
        nt_kernel_exec::executive_sync::ResourceMode::Exclusive,
        b"ExAcquireResourceExclusiveLite",
    )
}

/// `BOOLEAN ExAcquireResourceSharedLite(PERESOURCE Resource, BOOLEAN Wait)`.
extern "win64" fn s_ex_acquire_resource_shared_lite(resource: u64, wait: u8) -> u8 {
    acquire_resource_lite(
        resource,
        wait != 0,
        nt_kernel_exec::executive_sync::ResourceMode::Shared,
        b"ExAcquireResourceSharedLite",
    )
}

/// `VOID ExReleaseResourceLite(PERESOURCE Resource)`.
extern "win64" fn s_ex_release_resource_lite(resource: u64) {
    let thread = unsafe { current_ethread() };
    if let Err(error) = unsafe { executive_resources_mut().release(resource as *mut u8, thread) } {
        reject_resource_sync(b"ExReleaseResourceLite", error, resource, thread);
    }
}

/// `BOOLEAN ExIsResourceAcquiredExclusiveLite(PERESOURCE Resource)`.
extern "win64" fn s_ex_is_resource_acquired_exclusive_lite(resource: u64) -> u8 {
    let thread = unsafe { current_ethread() };
    match executive_resources_mut().is_acquired_exclusive(resource, thread) {
        Ok(acquired) => acquired as u8,
        Err(error) => reject_resource_sync(
            b"ExIsResourceAcquiredExclusiveLite",
            error,
            resource,
            thread,
        ),
    }
}

/// `ULONG ExIsResourceAcquiredSharedLite(PERESOURCE Resource)`.
extern "win64" fn s_ex_is_resource_acquired_shared_lite(resource: u64) -> u32 {
    let thread = unsafe { current_ethread() };
    match executive_resources_mut().acquired_count(resource, thread) {
        Ok(count) => count,
        Err(error) => {
            reject_resource_sync(b"ExIsResourceAcquiredSharedLite", error, resource, thread)
        }
    }
}

/// `VOID KeEnterCriticalRegion(VOID)`.
extern "win64" fn s_ke_enter_critical_region() {
    let thread = unsafe { current_ethread() };
    if let Err(error) =
        unsafe { nt_kernel_exec::executive_sync::enter_critical_region(thread as *mut u8) }
    {
        reject_executive_sync(b"KeEnterCriticalRegion", error);
    }
}

/// `VOID KeLeaveCriticalRegion(VOID)`.
extern "win64" fn s_ke_leave_critical_region() {
    let thread = unsafe { current_ethread() };
    if let Err(error) =
        unsafe { nt_kernel_exec::executive_sync::leave_critical_region(thread as *mut u8) }
    {
        reject_executive_sync(b"KeLeaveCriticalRegion", error);
    }
}

/// `VOID KeEnterGuardedRegion(VOID)`.
extern "win64" fn s_ke_enter_guarded_region() {
    let thread = unsafe { current_ethread() };
    if let Err(error) =
        unsafe { nt_kernel_exec::executive_sync::enter_guarded_region(thread as *mut u8) }
    {
        reject_executive_sync(b"KeEnterGuardedRegion", error);
    }
}

/// `VOID KeLeaveGuardedRegion(VOID)`.
extern "win64" fn s_ke_leave_guarded_region() {
    let thread = unsafe { current_ethread() };
    if let Err(error) =
        unsafe { nt_kernel_exec::executive_sync::leave_guarded_region(thread as *mut u8) }
    {
        reject_executive_sync(b"KeLeaveGuardedRegion", error);
    }
}

/// `PVOID ExEnterCriticalRegionAndAcquireResourceShared(PERESOURCE Resource)`.
extern "win64" fn s_ex_enter_critical_region_and_acquire_resource_shared(resource: u64) -> u64 {
    s_ke_enter_critical_region();
    let _ = s_ex_acquire_resource_shared_lite(resource, 1);
    unsafe { current_w32thread() }
}

/// `PVOID ExEnterCriticalRegionAndAcquireResourceExclusive(PERESOURCE Resource)`.
extern "win64" fn s_ex_enter_critical_region_and_acquire_resource_exclusive(resource: u64) -> u64 {
    s_ke_enter_critical_region();
    let _ = s_ex_acquire_resource_exclusive_lite(resource, 1);
    unsafe { current_w32thread() }
}

/// `VOID ExReleaseResourceAndLeaveCriticalRegion(PERESOURCE Resource)`.
extern "win64" fn s_ex_release_resource_and_leave_critical_region(resource: u64) {
    s_ex_release_resource_lite(resource);
    s_ke_leave_critical_region();
}

/// `VOID ExAcquireFastMutexUnsafe(PFAST_MUTEX FastMutex)`.
extern "win64" fn s_ex_acquire_fast_mutex_unsafe(mutex: u64) {
    let thread = unsafe { current_ethread() };
    match unsafe {
        nt_kernel_exec::executive_sync::acquire_fast_mutex_unsafe(mutex as *mut u8, thread)
    } {
        Ok(nt_kernel_exec::executive_sync::AcquireResult::Acquired) => {}
        Ok(nt_kernel_exec::executive_sync::AcquireResult::WouldBlock) => reject_fast_mutex_sync(
            b"ExAcquireFastMutexUnsafe",
            nt_kernel_exec::executive_sync::ExecutiveSyncError::BlockingWaitRequired,
            mutex,
            thread,
        ),
        Err(error) => reject_fast_mutex_sync(b"ExAcquireFastMutexUnsafe", error, mutex, thread),
    }
}

/// `VOID ExReleaseFastMutexUnsafe(PFAST_MUTEX FastMutex)`.
extern "win64" fn s_ex_release_fast_mutex_unsafe(mutex: u64) {
    let thread = unsafe { current_ethread() };
    if let Err(error) = unsafe {
        nt_kernel_exec::executive_sync::release_fast_mutex_unsafe(mutex as *mut u8, thread)
    } {
        reject_fast_mutex_sync(b"ExReleaseFastMutexUnsafe", error, mutex, thread);
    }
}

/// `VOID ExEnterCriticalRegionAndAcquireFastMutexUnsafe(PFAST_MUTEX FastMutex)`.
extern "win64" fn s_ex_enter_critical_region_and_acquire_fast_mutex_unsafe(mutex: u64) {
    s_ke_enter_critical_region();
    s_ex_acquire_fast_mutex_unsafe(mutex);
}

/// `VOID ExReleaseFastMutexUnsafeAndLeaveCriticalRegion(PFAST_MUTEX FastMutex)`.
extern "win64" fn s_ex_release_fast_mutex_unsafe_and_leave_critical_region(mutex: u64) {
    s_ex_release_fast_mutex_unsafe(mutex);
    s_ke_leave_critical_region();
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

#[derive(Clone, Copy)]
struct UserHandleEntry {
    address: u64,
    object: u64,
    owner: u64,
    object_type: u8,
    canonical: u64,
}

/// Resolve one live entry exactly as ReactOS `handle_to_entry` does. The canonical value always
/// contains the current generation, including when USER accepts the legacy zero/FFFF generation.
unsafe fn resolve_user_handle_entry(handle: u64) -> Option<UserHandleEntry> {
    if handle > u32::MAX as u64 {
        return None;
    }
    let low = handle & 0xFFFF;
    if !(FIRST_USER_HANDLE..=LAST_USER_HANDLE).contains(&low) || (low - FIRST_USER_HANDLE) & 1 != 0
    {
        return None;
    }
    let table = read_volatile((WIN32K_SHARED_VADDR + SH_SAS_AHELIST) as *const u64);
    if table == 0 {
        return None;
    }
    let entries = read_volatile(table as *const u64);
    let count = read_volatile((table + 0x10) as *const u32) as u64;
    let index = (low - FIRST_USER_HANDLE) >> 1;
    if entries == 0 || index >= count {
        return None;
    }
    let entry = entries + index * USER_HANDLE_ENTRY_SIZE;
    let object_type = read_volatile((entry + USER_HANDLE_ENTRY_TYPE_OFF) as *const u8);
    if object_type == 0 {
        return None;
    }
    let actual_generation = read_volatile((entry + USER_HANDLE_ENTRY_GENERATION_OFF) as *const u16);
    let supplied_generation = ((handle >> 16) & 0xFFFF) as u16;
    if supplied_generation != 0
        && supplied_generation != u16::MAX
        && supplied_generation != actual_generation
    {
        return None;
    }
    Some(UserHandleEntry {
        address: entry,
        object: read_volatile(entry as *const u64),
        owner: read_volatile((entry + USER_HANDLE_ENTRY_OWNER_OFF) as *const u64),
        object_type,
        canonical: low | u64::from(actual_generation) << 16,
    })
}

unsafe fn user_handle_owner_process(entry: UserHandleEntry) -> Option<u64> {
    match entry.object_type {
        // Window, hook, WinEvent hook, and input-context entries are THREADINFO-owned.
        1 | 5 | 15 | 17 if entry.owner != 0 => {
            let process = read_volatile((entry.owner + THREADINFO_PPI_OFF) as *const u64);
            (process != 0).then_some(process)
        }
        // Menu, cursor, call-proc, and accelerator entries are PROCESSINFO-owned.
        2 | 3 | 7 | 8 if entry.owner != 0 => Some(entry.owner),
        _ => None,
    }
}

unsafe fn resolve_window_handle(hwnd: u64) -> u64 {
    resolve_user_handle_entry(hwnd)
        .filter(|entry| entry.object_type == 1)
        .map_or(0, |entry| entry.object)
}

unsafe fn trace_getdc_window_context(hwnd: u64) {
    let pwnd = resolve_window_handle(hwnd);
    print_str(b"[w32req-getdc] hwnd=0x");
    print_hex(hwnd as u32);
    print_str(b" pwnd=0x");
    print_win32k_hex64(pwnd);
    if pwnd == 0 {
        print_str(b"\n");
        return;
    }
    let pti = read_volatile((pwnd + WND_HEAD_PTI_OFF) as *const u64);
    let parent = read_volatile((pwnd + WND_SPWND_PARENT_OFF) as *const u64);
    let child = read_volatile((pwnd + WND_SPWND_CHILD_OFF) as *const u64);
    let next = read_volatile((pwnd + WND_SPWND_NEXT_OFF) as *const u64);
    let prev = read_volatile((pwnd + WND_SPWND_PREV_OFF) as *const u64);
    let style = read_volatile((pwnd + WND_STYLE_OFF) as *const u32);
    let exstyle = read_volatile((pwnd + WND_EXSTYLE_OFF) as *const u32);
    let pcls = read_volatile((pwnd + WND_PCLS_OFF) as *const u64);
    let class_style = if pcls == 0 {
        0
    } else {
        read_volatile((pcls + CLS_STYLE_OFF) as *const u32)
    };
    let class_dce = read_u64_field_if_present(pcls, CLS_PDCE_OFF);
    print_str(b" pti=0x");
    print_win32k_hex64(pti);
    print_str(b" parent=0x");
    print_win32k_hex64(parent);
    print_str(b" child=0x");
    print_win32k_hex64(child);
    print_str(b" next=0x");
    print_win32k_hex64(next);
    print_str(b" prev=0x");
    print_win32k_hex64(prev);
    print_str(b" style=0x");
    print_hex(style);
    print_str(b" ex=0x");
    print_hex(exstyle);
    print_str(b" pcls=0x");
    print_win32k_hex64(pcls);
    print_str(b" cls-style=0x");
    print_hex(class_style);
    print_str(b" cls-dce=0x");
    print_win32k_hex64(class_dce);
    print_str(b"\n");
}

unsafe fn trace_oneparam_thread_context(param: u64, routine: u64) {
    let pti = current_w32thread();
    print_str(b"[w32req-oneparam] routine=0x");
    print_hex(routine as u32);
    print_str(b" param=0x");
    print_win32k_hex64(param);
    print_str(b" pti=0x");
    print_win32k_hex64(pti);
    if pti == 0 {
        print_str(b"\n");
        return;
    }

    let ppi = read_u64_field_if_present(pti, THREADINFO_PPI_OFF);
    let mq = read_u64_field_if_present(pti, THREADINFO_MESSAGE_QUEUE_OFF);
    let kl = read_u64_field_if_present(pti, THREADINFO_KEYBOARD_LAYOUT_OFF);
    let pcti = read_u64_field_if_present(pti, 0x70);
    let rpdesk = read_u64_field_if_present(pti, THREADINFO_RPDESK_OFF);
    let pdeskinfo = read_u64_field_if_present(pti, THREADINFO_PDESKINFO_OFF);
    let pci = read_u64_field_if_present(pti, THREADINFO_PCLIENTINFO_OFF);
    let hkl = read_u64_field_if_present(kl, KL_HKL_OFF);
    let pci_hkl = read_u64_field_if_present(pci, CLIENTINFO_HKL_OFF);
    let pci_codepage = if pci == 0 {
        0
    } else {
        read_volatile((pci + CLIENTINFO_CODEPAGE_OFF) as *const u16) as u64
    };

    print_str(b" ppi=0x");
    print_win32k_hex64(ppi);
    print_str(b" mq=0x");
    print_win32k_hex64(mq);
    print_str(b" kl=0x");
    print_win32k_hex64(kl);
    print_str(b" hkl=0x");
    print_win32k_hex64(hkl);
    print_str(b" pcti=0x");
    print_win32k_hex64(pcti);
    print_str(b" rpdesk=0x");
    print_win32k_hex64(rpdesk);
    print_str(b" pdeskinfo=0x");
    print_win32k_hex64(pdeskinfo);
    print_str(b" pci=0x");
    print_win32k_hex64(pci);
    print_str(b" pci-hkl=0x");
    print_win32k_hex64(pci_hkl);
    print_str(b" cp=");
    print_u64(pci_codepage);
    if routine == ONEPARAM_ROUTINE_GETKEYBOARDLAYOUT && param == 0 {
        print_str(b" current-thread-hkl");
    }
    print_str(b"\n");
}

pub(crate) unsafe fn trace_win32k_request_context() {
    let sh = WIN32K_SHARED_VADDR;
    let ssn = read_volatile((sh + SH_REQ_SSN) as *const u64);
    let a0 = read_volatile((sh + SH_REQ_A0) as *const u64);
    let a1 = read_volatile((sh + SH_REQ_A1) as *const u64);
    let a2 = read_volatile((sh + SH_REQ_A2) as *const u64);
    let a3 = read_volatile((sh + SH_REQ_A3) as *const u64);
    let pi = read_volatile((sh + SH_REQ_CLIENT_PI) as *const u64);
    let tid = read_volatile((sh + SH_REQ_THREAD_ID) as *const u64);
    let nested = read_volatile((sh + SH_REQ_NESTED_CALLBACK) as *const u64);
    let caller_sp = read_volatile((sh + SH_REQ_CALLER_SP) as *const u64);
    let nargs = read_volatile((sh + SH_REQ_NARGS) as *const u64);
    let ppi = current_w32process();
    let ppi_flags = read_u64_field_if_present(ppi, W32PROCESS_FLAGS_OFF) as u32;
    let handler = if ssn >= WIN32K_SERVICE_BASE {
        let base = read_volatile((sh + SH_SSDT_BASE) as *const u64);
        let count = read_volatile((sh + SH_SSDT_COUNT) as *const u32) as u64;
        let idx = ssn - WIN32K_SERVICE_BASE;
        if base != 0 && (count == 0 || idx < count) {
            read_volatile((base + idx * 8) as *const u64)
        } else {
            0
        }
    } else {
        0
    };
    let provider_argc = registered_win32k_provider_argc(ssn).unwrap_or(u64::MAX);
    print_str(b"[w32req] ssn=0x");
    print_hex(ssn as u32);
    print_str(b" pi=");
    print_u64(pi);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" nested=");
    print_u64(nested);
    print_str(b" a0=0x");
    print_win32k_hex64(a0);
    print_str(b" a1=0x");
    print_win32k_hex64(a1);
    print_str(b" a2=0x");
    print_win32k_hex64(a2);
    print_str(b" a3=0x");
    print_win32k_hex64(a3);
    print_str(b" caller-sp=0x");
    print_win32k_hex64(caller_sp);
    print_str(b" nargs=");
    print_u64(nargs);
    print_str(b" provider-argc=");
    if provider_argc == u64::MAX {
        print_str(b"?");
    } else {
        print_u64(provider_argc);
    }
    print_str(b" handler-rva=0x");
    if handler >= WIN32K_CODE_VA {
        print_hex(handler.wrapping_sub(WIN32K_CODE_VA) as u32);
    } else {
        print_hex(0);
    }
    print_str(b" ppi-flags=0x");
    print_hex(ppi_flags);
    print_str(if ppi_flags & W32PF_CREATEDWINORDC != 0 {
        b" created-dc=1"
    } else {
        b" created-dc=0"
    });
    print_str(b"\n");
    if ssn == SSN_NT_USER_GET_DC {
        trace_getdc_window_context(a0);
    } else if ssn == SSN_NT_USER_CALL_ONE_PARAM {
        trace_oneparam_thread_context(a0, a1);
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
    for index in 0..thread_ctx_len() {
        let row_tid = thread_ctx_tid(index);
        if row_tid == 0 || thread_ctx_pi(index) != pi {
            continue;
        }
        let row_pid = thread_ctx_pid(index);
        let row_ethread = thread_ctx_ethread(index);
        let row_w32thread = thread_ctx_w32thread(index);
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
        .map(|index| process_ctx_eprocess(index))
        .unwrap_or(0)
}

unsafe fn client_peb_from_teb(client_teb: u64) -> u64 {
    if client_teb < 0x10000 {
        return 0;
    }
    let peb = read_volatile((client_teb + TEB_PROCESS_ENVIRONMENT_BLOCK_OFF) as *const u64);
    if peb < 0x10000 {
        0
    } else {
        peb
    }
}

unsafe fn record_process_client_peb(process_index: usize, client_peb: u64) {
    if client_peb != 0 {
        set_process_ctx_client_peb(process_index, client_peb);
    }
}

unsafe fn initialize_eprocess_body(eprocess: u64, process_id: u64, client_peb: u64) {
    let q = eprocess + 0x900;
    let zstr = eprocess + 0xA00;
    let synthetic_peb = eprocess + 0x800;
    let synthetic_params = eprocess + 0xB00;
    write_volatile((eprocess + 0x20) as *mut u64, q);
    write_volatile((q + 0x80) as *mut u64, zstr);
    write_volatile(zstr as *mut u16, 0);
    write_volatile(
        (eprocess + EPROCESS_UNIQUE_PROCESS_ID_OFF) as *mut u64,
        process_id,
    );
    if client_peb != 0 {
        let current = read_volatile((eprocess + EPROCESS_PEB_OFF) as *const u64);
        if current != client_peb {
            write_volatile((eprocess + EPROCESS_PEB_OFF) as *mut u64, client_peb);
            let n = WIN32K_CLIENT_PEB_INSTALLS.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                print_str(b"[win32k-context] EPROCESS.Peb <- client PEB pid=");
                print_u64(process_id);
                print_str(b" peb=0x");
                print_hex((client_peb >> 32) as u32);
                print_hex(client_peb as u32);
                print_str(b" params=<client>");
                print_str(b"\n");
            }
        }
    } else if read_volatile((eprocess + EPROCESS_PEB_OFF) as *const u64) == 0 {
        write_volatile((eprocess + EPROCESS_PEB_OFF) as *mut u64, synthetic_peb);
        write_volatile(
            (synthetic_peb + PEB_PROCESS_PARAMETERS_OFF) as *mut u64,
            synthetic_params,
        );
    }
}

unsafe fn seed_win32k_callout_teb(thread_index: usize) -> Option<u64> {
    let existing = thread_ctx_callout_teb(thread_index);
    let teb = if existing != 0 {
        existing
    } else {
        let allocated = pool_alloc(0x1000);
        if allocated != 0 {
            set_thread_ctx_callout_teb(thread_index, allocated);
            WIN32K_CONTEXT_CALLOUT_TEB_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            allocated
        } else {
            return None;
        }
    };

    let peb = teb + 0xA00;
    let process_params = teb + 0xB00;
    let mut pid = thread_ctx_pid(thread_index);
    let mut tid = thread_ctx_tid(thread_index);
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
    let pid = thread_ctx_pid(thread_index);
    let eprocess = eprocess_for_pid(pid);
    let ethread = thread_ctx_ethread(thread_index);
    if eprocess == 0 || ethread == 0 {
        return;
    }

    let mut process_id = pid;
    let mut tid = thread_ctx_tid(thread_index);
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

unsafe fn publish_selected_context(process_index: usize, thread_index: usize) {
    let pid = process_ctx_pid(process_index);
    let tid = thread_ctx_tid(thread_index);
    let eprocess = process_ctx_eprocess(process_index);
    let ethread = thread_ctx_ethread(thread_index);
    let w32process = process_ctx_w32process(process_index);
    let w32thread = thread_ctx_w32thread(thread_index);
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
    let pid = thread_ctx_pid(thread_index);
    if pid == 0 {
        return None;
    }
    let process_index = process_context_index_for_pid(pid)?;
    if process_ctx_pi(process_index) != request.client_pi as u64
        || thread_ctx_pi(thread_index) != request.client_pi as u64
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
    let table_teb = thread_ctx_teb(thread_index);
    let supplied_eprocess = process_ctx_eprocess(process_index);
    let supplied_ethread = thread_ctx_ethread(thread_index);

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
    if process_ctx_pi(process_index) != pi as u64 || thread_ctx_pi(thread_index) != pi as u64 {
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
    let eprocess = process_ctx_eprocess(process_index);
    let ethread = thread_ctx_ethread(thread_index);
    let w32process = process_ctx_w32process(process_index);
    let w32thread = thread_ctx_w32thread(thread_index);
    if client_teb != 0 {
        set_thread_ctx_teb(thread_index, client_teb);
    }
    let recorded_client_peb = process_ctx_client_peb(process_index);
    initialize_eprocess_body(eprocess, pid, recorded_client_peb);
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

unsafe fn ensure_process_context(
    pi: usize,
    pid: u64,
    generation: u64,
    supplied_eprocess: u64,
    client_peb: u64,
) -> Option<usize> {
    if pid == 0 {
        return None;
    }
    if let Some(index) = process_context_index_for_pid(pid) {
        let recorded_generation = process_ctx_generation(index);
        if generation != 0 && recorded_generation != 0 && generation != recorded_generation {
            return None;
        }
        set_process_ctx_pi(index, pi as u64);
        if recorded_generation == 0 {
            set_process_ctx_generation(index, generation);
        }
        if !process_context_object_matches_or_empty(index, supplied_eprocess) {
            print_str(b"[win32k-context] ERROR: supplied EPROCESS mismatch for pid=");
            print_u64(pid);
            print_str(b"\n");
            return None;
        }
        let eprocess =
            process_context_object_or_allocate(index, supplied_eprocess, WIN32K_EPROCESS_BYTES)?;
        record_process_client_peb(index, client_peb);
        initialize_eprocess_body(eprocess, pid, client_peb);
        return Some(index);
    }
    let index = reserve_process_ctx_record()?;
    let eprocess = if supplied_eprocess != 0 {
        supplied_eprocess
    } else {
        allocate_kernel_object_body(WIN32K_EPROCESS_BYTES)
    };
    if eprocess == 0 {
        return None;
    }
    if supplied_eprocess == 0 {
        WIN32K_CONTEXT_EPROCESS_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    commit_process_ctx_record(
        index,
        Win32kProcessContextRecord {
            pid,
            pi: pi as u64,
            generation,
            eprocess,
            w32process: 0,
            terminating: 0,
            client_peb,
            token_authentication_id: 0,
            primary_token: 0,
        },
    );
    initialize_eprocess_body(eprocess, pid, client_peb);
    Some(index)
}

unsafe fn ensure_thread_context(
    pi: usize,
    pid: u64,
    tid: u64,
    generation: u64,
    teb: u64,
    supplied_ethread: u64,
) -> Option<usize> {
    if pid == 0 || tid == 0 {
        return None;
    }
    if let Some(index) = thread_context_index_for_tid(tid) {
        if thread_ctx_pid(index) != pid {
            return None;
        }
        let recorded_generation = thread_ctx_generation(index);
        if generation != 0 && recorded_generation != 0 && generation != recorded_generation {
            return None;
        }
        set_thread_ctx_pi(index, pi as u64);
        if recorded_generation == 0 {
            set_thread_ctx_generation(index, generation);
        }
        if teb != 0 {
            set_thread_ctx_teb(index, teb);
        }
        if !thread_context_object_matches_or_empty(index, supplied_ethread) {
            print_str(b"[win32k-context] ERROR: supplied ETHREAD mismatch for tid=");
            print_u64(tid);
            print_str(b"\n");
            return None;
        }
        let _ = thread_context_object_or_allocate(index, supplied_ethread, WIN32K_ETHREAD_BYTES)?;
        return Some(index);
    }
    let index = reserve_thread_ctx_record()?;
    let ethread = if supplied_ethread != 0 {
        supplied_ethread
    } else {
        allocate_kernel_object_body(WIN32K_ETHREAD_BYTES)
    };
    if ethread == 0 {
        return None;
    }
    if supplied_ethread == 0 {
        WIN32K_CONTEXT_ETHREAD_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    commit_thread_ctx_record(
        index,
        Win32kThreadContextRecord {
            tid,
            pid,
            pi: pi as u64,
            generation,
            teb,
            callout_teb: 0,
            ethread,
            w32thread: 0,
        },
    );
    Some(index)
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

unsafe fn adopt_bootstrap_csrss_process(
    pi: usize,
    pid: u64,
    tid: u64,
    generation: u64,
    teb: u64,
    supplied_eprocess: u64,
    supplied_ethread: u64,
    token_authentication_id: u64,
    token_user_sid: &[u8],
    token_user_sid_len: usize,
) -> Option<(usize, usize)> {
    if pid == 0 || tid == 0 || generation == 0 {
        return None;
    }

    let process_index = if let Some(existing) = process_context_index_for_pid(pid) {
        existing
    } else {
        process_context_index_for_pid(FAKE_PROCESS_HANDLE)?
    };
    let eprocess = process_ctx_eprocess(process_index);
    let process_generation = process_ctx_generation(process_index);
    if eprocess == 0
        || (process_generation != 0 && process_generation != generation)
        || (supplied_eprocess != 0 && supplied_eprocess != eprocess)
    {
        return None;
    }

    set_process_ctx_pid(process_index, pid);
    set_process_ctx_pi(process_index, pi as u64);
    set_process_ctx_generation(process_index, generation);
    let client_peb = client_peb_from_teb(teb);
    record_process_client_peb(process_index, client_peb);
    initialize_eprocess_body(eprocess, pid, client_peb);
    if !record_process_token_context(
        process_index,
        token_authentication_id,
        token_user_sid,
        token_user_sid_len,
    ) {
        return None;
    }

    let ppi = process_ctx_w32process(process_index);
    if ppi != 0 {
        write_volatile((ppi + W32PROCESS_PEPROCESS_OFF) as *mut u64, eprocess);
        write_volatile((ppi + W32PROCESS_W32PID_OFF) as *mut u32, pid as u32);
    }

    // ReactOS runs DesktopThreadMain on a dedicated, non-terminating CSRSS GUI thread. The
    // bootstrap THREADINFO is that thread: retain its distinct TID and link it to the re-keyed CSRSS
    // process instead of aliasing it to CSRSS's main thread. Otherwise the real main-thread exit
    // callout sees the only PROCESSINFO thread, destroys the process system classes, and leaves
    // subsequent desktop creation unable to find WC_DESKTOP.
    let desktop_thread_index = thread_context_index_for_tid(WIN32K_BOOTSTRAP_TID)?;
    if thread_ctx_ethread(desktop_thread_index) == 0
        || (thread_ctx_pid(desktop_thread_index) != FAKE_PROCESS_HANDLE
            && thread_ctx_pid(desktop_thread_index) != pid)
    {
        return None;
    }
    set_thread_ctx_pid(desktop_thread_index, pid);
    set_thread_ctx_pi(desktop_thread_index, pi as u64);
    set_thread_ctx_generation(desktop_thread_index, generation);

    // InitThreadCallback creates the desktop thread's queue Event through ZwCreateEvent. Run it
    // only after the bootstrap row belongs to a live CSRSS generation, while the enclosing pump
    // carries this exact `(pi, generation)` to the executive object manager. The caller's real
    // main-thread context is selected immediately afterwards.
    let desktop_ethread = thread_ctx_ethread(desktop_thread_index);
    let desktop_teb = seed_win32k_callout_teb(desktop_thread_index)?;
    prepare_ethread_for_win32k_callout(desktop_thread_index, desktop_teb);
    WIN32K_CURRENT_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(WIN32K_BOOTSTRAP_TID, Ordering::Relaxed);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, desktop_ethread);
    write_volatile(SLOT_W32PROCESS as *mut u64, ppi);
    write_volatile(SLOT_W32THREAD as *mut u64, 0);
    publish_selected_context(process_index, desktop_thread_index);
    if !ensure_win32k_threadinfo(desktop_thread_index, desktop_teb)
        || !bind_desktop_thread_to_current_context(false, b"csrss-desktop")
    {
        return None;
    }

    let thread_index = ensure_thread_context(pi, pid, tid, generation, teb, supplied_ethread)?;
    let ethread = thread_ctx_ethread(thread_index);
    let effective_teb = seed_win32k_callout_teb(thread_index)?;
    prepare_ethread_for_win32k_callout(thread_index, effective_teb);

    WIN32K_CURRENT_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(tid, Ordering::Relaxed);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, ethread);
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        process_ctx_w32process(process_index),
    );
    write_volatile(
        SLOT_W32THREAD as *mut u64,
        thread_ctx_w32thread(thread_index),
    );
    publish_selected_context(process_index, thread_index);

    if WIN32K_CSRSS_BOOTSTRAP_REKEYS.fetch_add(1, Ordering::Relaxed) < 4 {
        print_str(b"[win32k-context] adopted bootstrap CSRSS process pid=");
        print_u64(pid);
        print_str(b" main-tid=");
        print_u64(tid);
        print_str(b" desktop-tid=");
        print_u64(WIN32K_BOOTSTRAP_TID);
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
    generation: u64,
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
        if let Some(adopted) = adopt_bootstrap_csrss_process(
            pi,
            pid,
            tid,
            generation,
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
    let client_peb = client_peb_from_teb(client_teb);
    let process_index = ensure_process_context(pi, pid, generation, supplied_eprocess, client_peb)?;
    if !record_process_token_context(
        process_index,
        token_authentication_id,
        token_user_sid,
        token_user_sid_len,
    ) {
        return None;
    }
    let thread_index =
        ensure_thread_context(pi, pid, tid, generation, client_teb, supplied_ethread)?;
    let eprocess = process_ctx_eprocess(process_index);
    let ethread = thread_ctx_ethread(thread_index);
    record_process_client_peb(process_index, client_peb);
    initialize_eprocess_body(eprocess, pid, client_peb);
    WIN32K_CURRENT_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(tid, Ordering::Relaxed);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, ethread);
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        process_ctx_w32process(process_index),
    );
    write_volatile(
        SLOT_W32THREAD as *mut u64,
        thread_ctx_w32thread(thread_index),
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
        0,
        HOSTED_PROCESS_ROLE_NONE,
        nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_LOW as u64
            | ((nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_HIGH as u32 as u64) << 32),
        &system_sid,
        system_sid_len,
    )
}

unsafe fn ensure_win32k_process_attached(process_index: usize, process_role: u64) -> bool {
    if !process_ctx_index_valid(process_index) {
        return false;
    }
    if process_ctx_terminating(process_index) != 0 {
        return false;
    }
    if process_ctx_w32process(process_index) == 0 {
        let callout = read_volatile(WIN32_CALLOUTS as *const u64);
        if callout != 0 {
            let process = process_ctx_eprocess(process_index);
            let co: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(callout as *const ());
            let status = co(process, 1);
            let slot_value = read_volatile(SLOT_W32PROCESS as *const u64);
            if slot_value != 0 {
                set_process_ctx_w32process(process_index, slot_value);
            } else if process != 0 {
                let field = read_volatile((process + EPROCESS_WIN32PROCESS_OFF) as *const u64);
                if field != 0 {
                    set_process_ctx_w32process(process_index, field);
                    write_volatile(SLOT_W32PROCESS as *mut u64, field);
                }
            }
            if let Some(thread_index) = current_thread_context_index() {
                publish_selected_context(process_index, thread_index);
            }
            let n = WIN32K_CLIENT_PROCESS_CALLOUTS.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                let pi = process_ctx_pi(process_index);
                let pid = process_ctx_pid(process_index);
                print_str(b"[win32k-context] process callout pid=");
                print_u64(pid);
                print_str(b" pi=");
                print_u64(pi);
                print_str(b" status=0x");
                print_hex(status as u32);
                print_str(b" ppi=0x");
                let ppi = process_ctx_w32process(process_index);
                print_hex((ppi >> 32) as u32);
                print_hex(ppi as u32);
                print_str(b"\n");
            }
        }
    }
    if process_ctx_w32process(process_index) == 0 {
        let pid = process_ctx_pid(process_index);
        print_str(b"[win32k-context] ERROR: process callout did not publish W32PROCESS for pid=");
        print_u64(pid);
        print_str(b"\n");
        return false;
    }
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        process_ctx_w32process(process_index),
    );
    link_processinfo_to_eprocess(process_index);
    if process_role == HOSTED_PROCESS_ROLE_WIN32_SUBSYSTEM
        || hosted_process_role_is_noninteractive_service_class(process_role)
    {
        let n = WIN32K_NONINTERACTIVE_WINSTA_RESOLVES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            let pi = process_ctx_pi(process_index);
            let pid = process_ctx_pid(process_index);
            let ppi = process_ctx_w32process(process_index);
            print_str(
                b"[win32k-host] noninteractive service desktop left to InitThreadCallback pid=",
            );
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
    let process = process_ctx_eprocess(process_index);
    let ppi = process_ctx_w32process(process_index);
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
    let ppi = process_ctx_w32process(process_index);
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
    let eprocess = process_ctx_eprocess(process_index);
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
        let pi = process_ctx_pi(process_index);
        let pid = process_ctx_pid(process_index);
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
    let hsection = read_volatile((desk_body + DESKTOP_HSECTION_OFF) as *const u64);
    if !is_section(hsection as *const u8) {
        return None;
    }
    let pheap = read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64);
    let (heap_base, heap_size) = hosted_heap_bounds(pheap)?;
    let pdeskinfo = read_volatile((desk_body + 0x08) as *const u64);
    if !heap_block_capacity_in(heap_base, heap_size, pdeskinfo)
        .is_some_and(|capacity| capacity >= DESKTOPINFO_MIN_ALLOC)
    {
        return None;
    }
    let desktop_base = read_volatile(pdeskinfo as *const u64);
    let desktop_limit = read_volatile((pdeskinfo + 0x08) as *const u64);
    if desktop_base != heap_base || desktop_limit != heap_base.checked_add(heap_size)? {
        return None;
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

    // ReactOS marks CSRSS GUI threads TIF_CSRSSTHREAD and explicitly excludes them from automatic
    // window-station/desktop assignment. DesktopThreadMain is the distinct permanent owner.
    let flags = read_volatile((pti + THREADINFO_FLAGS_OFF) as *const u32);
    if flags & (TIF_SYSTEMTHREAD | TIF_CSRSSTHREAD) != 0 {
        return None;
    }

    let shell_client = process_role == HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL_BOOTSTRAP
        || process_role == HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL;
    if shell_client {
        if let Some(startup) = process_startup_desktop(ppi) {
            return Some(startup);
        }
    }

    if !hosted_process_role_is_noninteractive_service_class(process_role)
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
    let _ = write_thread_client_desktop_info(pti, desk_body, pdeskinfo);
}

unsafe fn seed_default_startup_desktop_for_process(ppi: u64, pti: u64) -> bool {
    let Some((hdesk, desk_body)) = default_desktop() else {
        return false;
    };
    seed_process_startup_desktop_for_process(ppi, hdesk, desk_body, pti)
}

unsafe fn ensure_win32k_threadinfo(thread_index: usize, client_teb: u64) -> bool {
    if !thread_ctx_index_valid(thread_index) {
        return false;
    }
    if thread_ctx_w32thread(thread_index) == 0 {
        if client_teb != 0 {
            set_thread_ctx_teb(thread_index, client_teb);
        }
        let Some(teb) = seed_win32k_callout_teb(thread_index) else {
            let tid = thread_ctx_tid(thread_index);
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
            let ethread = thread_ctx_ethread(thread_index);
            let co: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(callout as *const ());
            let status = co(ethread, PS_W32_THREAD_CALLOUT_INITIALIZE);
            let slot_value = read_volatile(SLOT_W32THREAD as *const u64);
            if slot_value != 0 {
                set_thread_ctx_w32thread(thread_index, slot_value);
            } else {
                let field = read_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *const u64);
                if field != 0 {
                    set_thread_ctx_w32thread(thread_index, field);
                    write_volatile(SLOT_W32THREAD as *mut u64, field);
                }
            }
            if let Some(process_index) = current_process_context_index() {
                publish_selected_context(process_index, thread_index);
            }
            let n = WIN32K_CLIENT_THREAD_CALLOUTS.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                let pi = thread_ctx_pi(thread_index);
                let tid = thread_ctx_tid(thread_index);
                print_str(b"[win32k-context] thread callout tid=");
                print_u64(tid);
                print_str(b" pi=");
                print_u64(pi);
                print_str(b" status=0x");
                print_hex(status as u32);
                print_str(b" pti=0x");
                let pti = thread_ctx_w32thread(thread_index);
                print_hex((pti >> 32) as u32);
                print_hex(pti as u32);
                print_str(b" teb=0x");
                print_hex((teb >> 32) as u32);
                print_hex(teb as u32);
                print_str(b"\n");
            }
        }
    }
    if thread_ctx_w32thread(thread_index) == 0 {
        let tid = thread_ctx_tid(thread_index);
        print_str(b"[win32k-context] ERROR: thread callout did not publish W32THREAD for tid=");
        print_u64(tid);
        print_str(b"\n");
        return false;
    }
    let thread = thread_ctx_w32thread(thread_index);
    write_volatile(SLOT_W32THREAD as *mut u64, thread);
    init_threadinfo_placeholder(thread);
    let ethread = thread_ctx_ethread(thread_index);
    if ethread != 0 {
        write_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *mut u64, thread);
        if read_volatile(thread as *const u64) == 0 {
            write_volatile(thread as *mut u64, ethread);
        }
    }
    true
}

pub(crate) unsafe fn win32k_window_owner_pi(hwnd: u64) -> Option<u32> {
    let pwnd = resolve_window_handle(hwnd);
    if pwnd == 0 {
        return None;
    }
    let pti = read_volatile((pwnd + WND_HEAD_PTI_OFF) as *const u64);
    if pti == 0 {
        return None;
    }
    let thread_index = thread_context_index_for_w32thread(pti)?;
    let pid = thread_ctx_pid(thread_index);
    let process_index = process_context_index_for_pid(pid)?;
    Some(process_ctx_pi(process_index) as u32)
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
        return STATUS_INVALID_PARAMETER_I32;
    }
    if src == 0 {
        return 0;
    }
    unsafe {
        let max = read_unaligned((dest as *const u16).add(1)) as u64; // MaximumLength (bytes)
        let buf = read_unaligned(dest.add(8) as *const u64);
        let current = read_unaligned(dest as *const u16) as u64;
        let source_bytes = s_wcslen(src).saturating_mul(2);
        if source_bytes > max.saturating_sub(current) {
            return STATUS_BUFFER_TOO_SMALL_I32;
        }
        if source_bytes != 0 && buf == 0 {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let mut offset = 0u64;
        while offset < source_bytes {
            write_unaligned(
                (buf + current + offset) as *mut u16,
                read_unaligned((src + offset) as *const u16),
            );
            offset += 2;
        }
        let length = current + source_bytes;
        write_unaligned(dest as *mut u16, length as u16);
        if max > length {
            write_unaligned((buf + length) as *mut u16, 0);
        }
    }
    0
}

/// `NTSTATUS RtlAppendUnicodeStringToString(PUNICODE_STRING, PCUNICODE_STRING)`.
extern "win64" fn s_rtl_append_unicode_string_to_string(dest: *mut u8, src: *const u8) -> i32 {
    if dest.is_null() || src.is_null() {
        return STATUS_INVALID_PARAMETER_I32;
    }
    unsafe {
        let source_length = read_unaligned(src as *const u16) as u64;
        let source_buffer = read_unaligned(src.add(8) as *const u64);
        let length = read_unaligned(dest as *const u16) as u64;
        let maximum = read_unaligned((dest as *const u16).add(1)) as u64;
        let buffer = read_unaligned(dest.add(8) as *const u64);
        if source_length > maximum.saturating_sub(length) {
            return STATUS_BUFFER_TOO_SMALL_I32;
        }
        if source_length != 0 && (source_buffer == 0 || buffer == 0) {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let mut offset = 0u64;
        while offset < source_length {
            write_volatile(
                (buffer + length + offset) as *mut u8,
                read_volatile((source_buffer + offset) as *const u8),
            );
            offset += 1;
        }
        let new_length = length + source_length;
        write_unaligned(dest as *mut u16, new_length as u16);
        if maximum > new_length {
            write_unaligned((buffer + new_length) as *mut u16, 0);
        }
    }
    0
}

/// `NTSTATUS RtlFormatCurrentUserKeyPath(PUNICODE_STRING)`.
extern "win64" fn s_rtl_format_current_user_key_path(key_path: *mut u8) -> i32 {
    const PREFIX: &[u8] = b"\\Registry\\User\\";
    if key_path.is_null() {
        return STATUS_INVALID_PARAMETER_I32;
    }
    unsafe {
        write_unaligned(key_path as *mut u16, 0);
        write_unaligned((key_path as *mut u16).add(1), 0);
        write_unaligned(key_path.add(8) as *mut u64, 0);

        let Some(process_index) = current_process_context_index() else {
            return STATUS_NO_TOKEN_I32;
        };
        let token = ensure_primary_token_object(process_index);
        if token == 0 {
            return STATUS_NO_TOKEN_I32;
        }
        let mut native_sid = [0u8; WIN32K_TOKEN_USER_SID_MAX];
        let Some(native_sid_len) = primary_token_user_sid(token, &mut native_sid) else {
            return STATUS_NO_TOKEN_I32;
        };

        let mut path = [0u16; 208];
        for (unit, byte) in path.iter_mut().zip(PREFIX) {
            *unit = *byte as u16;
        }
        let sid_units = match nt_security::write_native_sid_sddl_utf16(
            &native_sid[..native_sid_len],
            &mut path[PREFIX.len()..],
        ) {
            Ok(units) => units,
            Err(status) => return status as i32,
        };
        let units = PREFIX.len() + sid_units;
        let bytes = units * 2;
        let allocation_bytes = bytes + 2;
        let buffer = reclaiming_pool_alloc(allocation_bytes as u64);
        if buffer == 0 {
            return STATUS_NO_MEMORY;
        }
        for (index, unit) in path[..units].iter().enumerate() {
            write_unaligned((buffer + index as u64 * 2) as *mut u16, *unit);
        }
        write_unaligned((buffer + bytes as u64) as *mut u16, 0);
        write_unaligned(key_path as *mut u16, bytes as u16);
        write_unaligned((key_path as *mut u16).add(1), allocation_bytes as u16);
        write_unaligned(key_path.add(8) as *mut u64, buffer);
    }
    0
}

/// `VOID RtlFreeUnicodeString(PUNICODE_STRING)`.
extern "win64" fn s_rtl_free_unicode_string(string: *mut u8) {
    if string.is_null() {
        return;
    }
    unsafe {
        let buffer = read_unaligned(string.add(8) as *const u64);
        if buffer != 0 {
            reclaiming_pool_free(buffer);
            write_unaligned(string as *mut u16, 0);
            write_unaligned((string as *mut u16).add(1), 0);
            write_unaligned(string.add(8) as *mut u64, 0);
        }
    }
}

/// `BOOLEAN RtlCreateUnicodeString(PUNICODE_STRING Dest, PCWSTR Src)` — allocate a NUL-terminated
/// copy of `Src` from the reclaiming win32k pool and point `Dest` at it. Returns TRUE on success.
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
        let buf = reclaiming_pool_alloc(bytes + 2); // + NUL wchar
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

#[cold]
fn nls_contract_trap() -> ! {
    unsafe {
        print_str(b"[win32k-nls] validated runtime state is unavailable\n");
        core::arch::asm!("ud2", options(noreturn));
    }
}

unsafe fn win32k_nls_state() -> Win32kNlsState {
    let state = read_unaligned(WIN32K_NLS_STATE_VA as *const Win32kNlsState);
    let ansi_mb_end = (state.ansi_multi_byte_index as usize)
        .checked_mul(2)
        .and_then(|offset| offset.checked_add(256 * 2));
    let ansi_wide_end = (state.ansi_wide_byte_offset as usize).checked_add(0x1_0000);
    let oem_mb_end = (state.oem_multi_byte_index as usize)
        .checked_mul(2)
        .and_then(|offset| offset.checked_add(256 * 2));
    let upper_end = (state.upper_case_index as usize)
        .checked_add(state.upper_case_len as usize)
        .and_then(|words| words.checked_mul(2));
    if state.magic != WIN32K_NLS_STATE_MAGIC
        || state.ansi_code_page != 1252
        || state.oem_code_page != 437
        || state.ansi_size as u64 > NLS_ANSI_FRAMES * 0x1000
        || state.oem_size as u64 > NLS_OEM_FRAMES * 0x1000
        || state.case_size as u64 > NLS_CASE_FRAMES * 0x1000
        || ansi_mb_end.map_or(true, |end| end > state.ansi_size as usize)
        || ansi_wide_end.map_or(true, |end| end > state.ansi_size as usize)
        || oem_mb_end.map_or(true, |end| end > state.oem_size as usize)
        || upper_end.map_or(true, |end| end > state.case_size as usize)
    {
        nls_contract_trap();
    }
    state
}

unsafe fn nls_byte_to_unicode_table(base: u64, index: u32) -> &'static [u16] {
    core::slice::from_raw_parts((base + index as u64 * 2) as *const u16, 256)
}

unsafe fn nls_unicode_to_byte_table(base: u64, byte_offset: u32) -> &'static [u8] {
    core::slice::from_raw_parts((base + byte_offset as u64) as *const u8, 0x1_0000)
}

unsafe fn nls_upper_case_table(state: Win32kNlsState) -> &'static [u16] {
    core::slice::from_raw_parts(
        (NLS_CASE_VADDR + state.upper_case_index as u64 * 2) as *const u16,
        state.upper_case_len as usize,
    )
}

const STATUS_INVALID_PARAMETER_2: i32 = 0xC000_00F0u32 as i32;

unsafe fn sbcs_to_unicode_n(
    table: &[u16],
    unicode: *mut u16,
    max_bytes: u32,
    bytes_out: *mut u32,
    source: *const u8,
    source_bytes: u32,
) -> i32 {
    let capacity = (max_bytes / 2) as usize;
    let input_len = source_bytes as usize;
    if (capacity != 0 && unicode.is_null()) || (input_len != 0 && source.is_null()) {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    let output: &mut [u16] = if capacity == 0 {
        &mut []
    } else {
        core::slice::from_raw_parts_mut(unicode, capacity)
    };
    let input: &[u8] = if input_len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(source, input_len)
    };
    let Some(written) = nt_nls::custom_cp_to_unicode_into(table, max_bytes as usize, input, output)
    else {
        nls_contract_trap();
    };
    if !bytes_out.is_null() {
        write_unaligned(bytes_out, (written * 2) as u32);
    }
    0
}

/// `VOID RtlGetDefaultCodePage(PUSHORT Ansi, PUSHORT Oem)`.
extern "win64" fn s_rtl_get_default_code_page(ansi: *mut u16, oem: *mut u16) {
    unsafe {
        let state = win32k_nls_state();
        if ansi.is_null() || oem.is_null() {
            nls_contract_trap();
        }
        write_unaligned(ansi, state.ansi_code_page);
        write_unaligned(oem, state.oem_code_page);
    }
}

/// `NTSTATUS RtlMultiByteToUnicodeN(...)`, backed by the validated CP1252 table.
extern "win64" fn s_rtl_multibyte_to_unicode_n(
    unicode: *mut u16,
    max_bytes: u32,
    bytes_out: *mut u32,
    mb: *const u8,
    mb_bytes: u32,
) -> i32 {
    unsafe {
        let state = win32k_nls_state();
        let table = nls_byte_to_unicode_table(NLS_ANSI_VADDR, state.ansi_multi_byte_index);
        sbcs_to_unicode_n(table, unicode, max_bytes, bytes_out, mb, mb_bytes)
    }
}

/// `NTSTATUS RtlOemToUnicodeN(...)`, backed by the validated CP437 table.
extern "win64" fn s_rtl_oem_to_unicode_n(
    unicode: *mut u16,
    max_bytes: u32,
    bytes_out: *mut u32,
    oem: *const u8,
    oem_bytes: u32,
) -> i32 {
    unsafe {
        let state = win32k_nls_state();
        let table = nls_byte_to_unicode_table(NLS_OEM_VADDR, state.oem_multi_byte_index);
        sbcs_to_unicode_n(table, unicode, max_bytes, bytes_out, oem, oem_bytes)
    }
}

/// `WCHAR RtlAnsiCharToUnicodeChar(PUCHAR *SourceCharacter)`.
extern "win64" fn s_rtl_ansi_char_to_unicode_char(source_character: *mut u64) -> u16 {
    unsafe {
        if source_character.is_null() {
            nls_contract_trap();
        }
        let source = read_unaligned(source_character);
        if source == 0 {
            nls_contract_trap();
        }
        let state = win32k_nls_state();
        let table = nls_byte_to_unicode_table(NLS_ANSI_VADDR, state.ansi_multi_byte_index);
        let result = table[read_volatile(source as *const u8) as usize];
        write_unaligned(source_character, source + 1);
        result
    }
}

/// `WCHAR RtlUpcaseUnicodeChar(WCHAR Source)`.
extern "win64" fn s_rtl_upcase_unicode_char(source: u16) -> u16 {
    unsafe {
        if source < b'a' as u16 {
            return source;
        }
        if source <= b'z' as u16 {
            return source - (b'a' - b'A') as u16;
        }
        let state = win32k_nls_state();
        let table = nls_upper_case_table(state);
        let Some(mapped) = nt_nls::nls_case_map(table, source) else {
            nls_contract_trap();
        };
        mapped
    }
}

/// `NTSTATUS RtlAnsiStringToUnicodeString(PUNICODE_STRING, PANSI_STRING, BOOLEAN)`.
extern "win64" fn s_rtl_ansi_string_to_unicode_string(
    destination: *mut u8,
    source: *const u8,
    allocate_destination: u8,
) -> i32 {
    unsafe {
        if destination.is_null() || source.is_null() {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let source_len = read_unaligned(source as *const u16) as usize;
        let source_buffer = read_unaligned(source.add(8) as *const u64);
        if source_len != 0 && source_buffer == 0 {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let Some(required) = source_len
            .checked_add(1)
            .and_then(|units| units.checked_mul(2))
        else {
            return STATUS_INVALID_PARAMETER_2;
        };
        if required > u16::MAX as usize {
            return STATUS_INVALID_PARAMETER_2;
        }
        let output_len = required - 2;
        write_unaligned(destination as *mut u16, output_len as u16);

        let output_buffer = if allocate_destination != 0 {
            write_unaligned((destination as *mut u16).add(1), required as u16);
            write_unaligned(destination.add(8) as *mut u64, 0);
            let buffer = reclaiming_pool_alloc(required as u64);
            if buffer == 0 {
                return STATUS_NO_MEMORY;
            }
            write_unaligned(destination.add(8) as *mut u64, buffer);
            buffer
        } else {
            let maximum = read_unaligned((destination as *const u16).add(1)) as usize;
            if output_len >= maximum {
                return STATUS_BUFFER_OVERFLOW;
            }
            read_unaligned(destination.add(8) as *const u64)
        };
        if output_buffer == 0 {
            return STATUS_ACCESS_VIOLATION_I32;
        }

        let mut written = 0u32;
        let status = s_rtl_multibyte_to_unicode_n(
            output_buffer as *mut u16,
            output_len as u32,
            &mut written,
            source_buffer as *const u8,
            source_len as u32,
        );
        if status != 0 {
            if allocate_destination != 0 {
                reclaiming_pool_free(output_buffer);
                write_unaligned(destination.add(8) as *mut u64, 0);
            }
            return status;
        }
        write_unaligned((output_buffer + written as u64) as *mut u16, 0);
        0
    }
}

/// `NTSTATUS RtlUnicodeToMultiByteSize(PULONG, PCWCH, ULONG)` for the validated SBCS ANSI page.
extern "win64" fn s_rtl_unicode_to_multibyte_size(
    multibyte_size: *mut u32,
    _unicode: *const u16,
    unicode_bytes: u32,
) -> i32 {
    unsafe {
        let _ = win32k_nls_state();
        if multibyte_size.is_null() {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        write_unaligned(multibyte_size, unicode_bytes / 2);
    }
    0
}

/// `ULONG RtlxUnicodeStringToAnsiSize(PCUNICODE_STRING)`, including the terminator.
extern "win64" fn s_rtlx_unicode_string_to_ansi_size(source: *const u8) -> u32 {
    unsafe {
        let _ = win32k_nls_state();
        if source.is_null() {
            nls_contract_trap();
        }
        read_unaligned(source as *const u16) as u32 / 2 + 1
    }
}

/// `NTSTATUS RtlUnicodeStringToAnsiString(PANSI_STRING, PCUNICODE_STRING, BOOLEAN)`.
extern "win64" fn s_rtl_unicode_string_to_ansi_string(
    destination: *mut u8,
    source: *const u8,
    allocate_destination: u8,
) -> i32 {
    unsafe {
        if destination.is_null() || source.is_null() {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let source_bytes = read_unaligned(source as *const u16) as usize;
        if source_bytes & 1 != 0 {
            return STATUS_INVALID_PARAMETER_2;
        }
        let source_units = source_bytes / 2;
        let source_buffer = read_unaligned(source.add(8) as *const u64);
        if source_units != 0 && source_buffer == 0 {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let required = source_units + 1;
        if required > u16::MAX as usize {
            return STATUS_INVALID_PARAMETER_2;
        }
        write_unaligned(destination as *mut u16, source_units as u16);
        let (output_buffer, output_len, status) = if allocate_destination != 0 {
            write_unaligned((destination as *mut u16).add(1), required as u16);
            write_unaligned(destination.add(8) as *mut u64, 0);
            let buffer = reclaiming_pool_alloc(required as u64);
            if buffer == 0 {
                return STATUS_NO_MEMORY;
            }
            write_unaligned(destination.add(8) as *mut u64, buffer);
            (buffer, source_units, 0)
        } else {
            let maximum = read_unaligned((destination as *const u16).add(1)) as usize;
            if maximum == 0 {
                return STATUS_BUFFER_OVERFLOW;
            }
            let output_len = source_units.min(maximum - 1);
            let status = if output_len != source_units {
                write_unaligned(destination as *mut u16, output_len as u16);
                STATUS_BUFFER_OVERFLOW
            } else {
                0
            };
            (
                read_unaligned(destination.add(8) as *const u64),
                output_len,
                status,
            )
        };
        if output_buffer == 0 {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let state = win32k_nls_state();
        let wide_table = nls_unicode_to_byte_table(NLS_ANSI_VADDR, state.ansi_wide_byte_offset);
        let input: &[u16] = if source_units == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(source_buffer as *const u16, source_units)
        };
        let output: &mut [u8] = if output_len == 0 {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(output_buffer as *mut u8, output_len)
        };
        if nt_nls::unicode_to_custom_cp_into(wide_table, output_len, input, false, output).is_none()
        {
            nls_contract_trap();
        }
        write_volatile((output_buffer + output_len as u64) as *mut u8, 0);
        status
    }
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

const GDI_DRIVER_RECORD_INITIAL_CAP: u64 = 4;
static GDI_DRIVER_RECORDS_PTR: AtomicU64 = AtomicU64::new(0);
static GDI_DRIVER_RECORDS_LEN: AtomicU64 = AtomicU64::new(0);
static GDI_DRIVER_RECORDS_CAP: AtomicU64 = AtomicU64::new(0);

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

unsafe fn gdi_driver_record_ptr(base: u64, index: u64) -> *mut GdiDriverRecord {
    (base + index * core::mem::size_of::<GdiDriverRecord>() as u64) as *mut GdiDriverRecord
}

unsafe fn ensure_gdi_driver_record_capacity(required: u64) -> bool {
    let cap = GDI_DRIVER_RECORDS_CAP.load(Ordering::Relaxed);
    if cap >= required {
        return true;
    }
    let mut new_cap = if cap == 0 {
        GDI_DRIVER_RECORD_INITIAL_CAP
    } else {
        cap.saturating_mul(2)
    };
    while new_cap < required {
        let next = new_cap.saturating_mul(2);
        if next <= new_cap {
            return false;
        }
        new_cap = next;
    }
    let Some(bytes) = (core::mem::size_of::<GdiDriverRecord>() as u64).checked_mul(new_cap) else {
        return false;
    };
    let new_base = pool_alloc(bytes);
    if new_base == 0 {
        return false;
    }
    let old_base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
    let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Relaxed);
    if old_base != 0 {
        for index in 0..len {
            let rec = read_volatile(gdi_driver_record_ptr(old_base, index));
            write_volatile(gdi_driver_record_ptr(new_base, index), rec);
        }
    }
    GDI_DRIVER_RECORDS_PTR.store(new_base, Ordering::Relaxed);
    GDI_DRIVER_RECORDS_CAP.store(new_cap, Ordering::Relaxed);
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
    let record = registered_gdi_driver_record(leaf, image, entry, expdir, image_len);
    unsafe {
        let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Relaxed);
        let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
        if base != 0 {
            for index in 0..len {
                let ptr = gdi_driver_record_ptr(base, index);
                let rec = read_volatile(ptr);
                if ascii_eq_ignore_case(rec.leaf_bytes(), leaf) {
                    write_volatile(ptr, record);
                    return true;
                }
            }
        }
        let Some(required) = len.checked_add(1) else {
            return false;
        };
        if !ensure_gdi_driver_record_capacity(required) {
            return false;
        }
        let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
        if base == 0 {
            return false;
        }
        write_volatile(gdi_driver_record_ptr(base, len), record);
        GDI_DRIVER_RECORDS_LEN.store(required, Ordering::Relaxed);
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
    let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
    let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    for index in 0..len {
        let rec = read_volatile(gdi_driver_record_ptr(base, index));
        if wname_ends_with(name_buf, name_len, rec.leaf_bytes()) {
            return Some(rec);
        }
    }
    None
}

fn registered_gdi_driver_for_leaf(leaf: &[u8]) -> Option<GdiDriverRecord> {
    unsafe {
        let base = GDI_DRIVER_RECORDS_PTR.load(Ordering::Relaxed);
        let len = GDI_DRIVER_RECORDS_LEN.load(Ordering::Relaxed);
        if base == 0 {
            return None;
        }
        for index in 0..len {
            let rec = read_volatile(gdi_driver_record_ptr(base, index));
            if ascii_eq_ignore_case(rec.leaf_bytes(), leaf) {
                return Some(rec);
            }
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
// resolve those imports against the isolated Configuration Manager's mounted SYSTEM hive for
// service and keyboard-layout keys, plus the runtime video DeviceMap key published when the selected
// display route is registered. Each SYSTEM handle owns one CM lease and its resolved physical path;
// ZwQueryValueKey reads through that lease and ZwClose releases it exactly once.
// The video route's projected IO object identities and framebuffer IOCTL state are owned by `video_device`;
// win32k only carries opaque registry handles to the registry authority.

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const RTL_REGISTRY_HANDLE: u32 = 0x4000_0000;
const RTL_QUERY_REGISTRY_SUBKEY: u32 = 0x0000_0001;
const RTL_QUERY_REGISTRY_REQUIRED: u32 = 0x0000_0004;
const RTL_QUERY_REGISTRY_NOVALUE: u32 = 0x0000_0008;
const RTL_QUERY_REGISTRY_DIRECT: u32 = 0x0000_0020;
const RTL_QUERY_REGISTRY_TABLE_SIZE: u64 = 56;
const REG_NONE: u32 = 0;
const REG_DWORD: u32 = 4;
const WIN32K_REG_HANDLE_BASE: u64 = 0xFFFF_FF00_5732_0000;
const WIN32K_REG_HANDLE_INDEX_MASK: u64 = 0x0000_FFFF;
const WIN32K_REGISTRY_PATH_MAX: usize = 384;
const WIN32K_REGISTRY_KEY_LEN: u64 = 0;
const WIN32K_REGISTRY_VALUE_LEN: u64 = 4;
const WIN32K_REGISTRY_VALUE_TYPE: u64 = 8;
const WIN32K_REGISTRY_DATA_LEN: u64 = 12;
const WIN32K_REGISTRY_KEY_OFF: u64 = 16;
const WIN32K_REGISTRY_VALUE_OFF: u64 = WIN32K_REGISTRY_KEY_OFF + WIN32K_REGISTRY_PATH_MAX as u64;
const WIN32K_REGISTRY_DATA_OFF: u64 = WIN32K_REGISTRY_VALUE_OFF + WIN32K_REGISTRY_PATH_MAX as u64;
const WIN32K_REGISTRY_VALUE_CAP: usize = WIN32K_REGISTRY_BYTES - WIN32K_REGISTRY_DATA_OFF as usize;
const WIN32K_REGISTRY_OP_OPEN: u64 = 1;
const WIN32K_REGISTRY_OP_CLOSE: u64 = 2;
const WIN32K_REGISTRY_OP_QUERY_VALUE: u64 = 3;
const _: () = assert!(
    WIN32K_REGISTRY_DATA_OFF + WIN32K_REGISTRY_VALUE_CAP as u64 <= WIN32K_REGISTRY_BYTES as u64
);
static WIN32K_VIDEO_REG_QUERY_TRACE: AtomicU64 = AtomicU64::new(0);

enum Win32kRegHandleTarget {
    Empty,
    VideoDeviceMap,
    SystemHive {
        lease: nt_config_client::SystemHiveKeyLease,
        physical_path: alloc::string::String,
    },
}

struct Win32kRegHandle {
    handle: u64,
    target: Win32kRegHandleTarget,
}

static mut WIN32K_REG_HANDLES: Option<Vec<Win32kRegHandle>> = None;

pub(crate) struct DisplayRegistrySpec<'a> {
    pub(crate) display_driver_leaf: &'a [u8],
    pub(crate) device_description: &'a [u8],
    pub(crate) framebuffer_size: u64,
    pub(crate) mode: DisplayModeSpec,
}

#[derive(Clone, Copy)]
pub(crate) struct DisplayModeSpec {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride: u32,
}

fn reg_ascii_eq(a: &[u8], b: &[u8]) -> bool {
    ascii_eq_ignore_case(a, b)
}

fn win32k_reg_handles_mut() -> &'static mut Vec<Win32kRegHandle> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(WIN32K_REG_HANDLES);
        if slot.is_none() {
            *slot = Some(Vec::new());
        }
        slot.as_mut().expect("initialized above")
    }
}

fn win32k_reg_handles() -> Option<&'static Vec<Win32kRegHandle>> {
    unsafe { (&*core::ptr::addr_of!(WIN32K_REG_HANDLES)).as_ref() }
}

fn register_win32k_reg_handle(target: Win32kRegHandleTarget) -> Result<u64, Win32kRegHandleTarget> {
    if matches!(&target, Win32kRegHandleTarget::Empty) {
        return Err(target);
    }
    let handles = win32k_reg_handles_mut();
    for (idx, entry) in handles.iter_mut().enumerate() {
        if matches!(&entry.target, Win32kRegHandleTarget::Empty) {
            if idx as u64 > WIN32K_REG_HANDLE_INDEX_MASK {
                return Err(target);
            }
            let handle = WIN32K_REG_HANDLE_BASE | idx as u64;
            *entry = Win32kRegHandle { handle, target };
            return Ok(handle);
        }
    }
    if handles.len() as u64 > WIN32K_REG_HANDLE_INDEX_MASK {
        return Err(target);
    }
    let handle = WIN32K_REG_HANDLE_BASE | handles.len() as u64;
    if handles.try_reserve(1).is_err() {
        return Err(target);
    }
    handles.push(Win32kRegHandle { handle, target });
    Ok(handle)
}

fn is_win32k_reg_handle(handle: u64) -> bool {
    handle & !WIN32K_REG_HANDLE_INDEX_MASK == WIN32K_REG_HANDLE_BASE
}

fn take_win32k_reg_handle(handle: u64) -> Option<Win32kRegHandleTarget> {
    let handles = win32k_reg_handles_mut();
    if let Some(entry) = handles.iter_mut().find(|entry| {
        entry.handle == handle && !matches!(&entry.target, Win32kRegHandleTarget::Empty)
    }) {
        entry.handle = 0;
        Some(core::mem::replace(
            &mut entry.target,
            Win32kRegHandleTarget::Empty,
        ))
    } else {
        None
    }
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

fn system_hive_absolute_path(path: &[u8]) -> Result<alloc::string::String, i32> {
    let mut tail = registry_path_tail(path);
    tail = if reg_ascii_eq(tail, b"system") {
        &[]
    } else {
        strip_ascii_prefix(tail, b"system\\").ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
    };
    let tail = core::str::from_utf8(tail).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let prefix = r"\Registry\Machine\System";
    let mut absolute = alloc::string::String::new();
    absolute
        .try_reserve_exact(
            prefix
                .len()
                .saturating_add(usize::from(!tail.is_empty()))
                .saturating_add(tail.len()),
        )
        .map_err(|_| STATUS_NO_MEMORY)?;
    absolute.push_str(prefix);
    if !tail.is_empty() {
        absolute.push('\\');
        absolute.push_str(tail);
    }
    Ok(absolute)
}

fn system_hive_relative_path_from_handle(
    root: u64,
    path: &[u8],
) -> Result<alloc::string::String, i32> {
    let handles = win32k_reg_handles().ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let entry = handles
        .iter()
        .find(|entry| entry.handle == root)
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let Win32kRegHandleTarget::SystemHive { physical_path, .. } = &entry.target else {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let relative = core::str::from_utf8(path).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let separator = usize::from(!relative.is_empty());
    let mut absolute = alloc::string::String::new();
    absolute
        .try_reserve_exact(
            physical_path
                .len()
                .saturating_add(separator)
                .saturating_add(relative.len()),
        )
        .map_err(|_| STATUS_NO_MEMORY)?;
    absolute.push_str(physical_path);
    if !relative.is_empty() {
        absolute.push('\\');
        absolute.push_str(relative);
    }
    Ok(absolute)
}

fn win32k_reg_path_is_absolute(path: &[u8]) -> bool {
    path.first() == Some(&b'\\')
        || strip_ascii_prefix(path, b"registry\\machine\\").is_some()
        || reg_ascii_eq(path, b"system")
        || strip_ascii_prefix(path, b"system\\").is_some()
        || reg_ascii_eq(path, b"hardware")
        || strip_ascii_prefix(path, b"hardware\\").is_some()
}

unsafe fn read_unicode_string_ascii_lower(ustr: u64) -> Option<Vec<u8>> {
    if ustr == 0 {
        return None;
    }
    let len = read_unaligned(ustr as *const u16) as usize;
    if len % 2 != 0 {
        return None;
    }
    let chars = len / 2;
    let buf = read_unaligned((ustr + 8) as *const u64);
    if chars != 0 && buf == 0 {
        return None;
    }
    let mut out = Vec::new();
    out.try_reserve_exact(chars).ok()?;
    for i in 0..chars {
        let unit = read_unaligned((buf + (i * 2) as u64) as *const u16);
        if unit > 0x7f {
            return None;
        }
        out.push((unit as u8).to_ascii_lowercase());
    }
    Some(out)
}

unsafe fn read_wide_cstr_ascii_lower(ptr: u64) -> Option<Vec<u8>> {
    if ptr == 0 {
        return None;
    }
    let mut out = Vec::new();
    out.try_reserve_exact(64).ok()?;
    for index in 0..256usize {
        let unit = read_unaligned((ptr + index as u64 * 2) as *const u16);
        if unit == 0 {
            return Some(out);
        }
        if unit > 0x7f {
            return None;
        }
        out.push((unit as u8).to_ascii_lowercase());
    }
    None
}

unsafe fn object_attributes_name_ascii_lower(obj_attr: u64) -> Option<Vec<u8>> {
    if obj_attr == 0 {
        return None;
    }
    let ustr = read_unaligned((obj_attr + 0x10) as *const u64);
    read_unicode_string_ascii_lower(ustr)
}

unsafe fn write_win32k_registry_ascii(len_off: u64, data_off: u64, value: &[u8]) -> bool {
    if value.len() > WIN32K_REGISTRY_PATH_MAX || value.iter().any(|byte| *byte == 0 || *byte > 0x7f)
    {
        return false;
    }
    write_volatile(
        (WIN32K_REGISTRY_VADDR + len_off) as *mut u32,
        value.len() as u32,
    );
    for (index, byte) in value.iter().copied().enumerate() {
        write_volatile(
            (WIN32K_REGISTRY_VADDR + data_off + index as u64) as *mut u8,
            byte,
        );
    }
    true
}

unsafe fn read_win32k_registry_ascii(len_off: u64, data_off: u64) -> Option<Vec<u8>> {
    let len = read_volatile((WIN32K_REGISTRY_VADDR + len_off) as *const u32) as usize;
    if len > WIN32K_REGISTRY_PATH_MAX {
        return None;
    }
    let mut value = Vec::new();
    value.try_reserve_exact(len).ok()?;
    for index in 0..len {
        let byte = read_volatile((WIN32K_REGISTRY_VADDR + data_off + index as u64) as *const u8);
        if byte == 0 || byte > 0x7f {
            return None;
        }
        value.push(byte);
    }
    Some(value)
}

unsafe fn win32k_registry_broker_call(op: u64, arg: u64) -> (i32, u64, u64) {
    let (_label, status, out1, out2, _) =
        crate::driver_launch::call_on4((W32_REGISTRY_LABEL << 12) | 2, op, arg, 0, 0);
    (status as u32 as i32, out1, out2)
}

unsafe fn win32k_event_broker_call(
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> (i32, u64, u64, u64) {
    let (_label, status, out1, out2, out3) =
        crate::driver_launch::call_on4((W32_EVENT_LABEL << 12) | 4, op, arg1, arg2, arg3);
    (status as u32 as i32, out1, out2, out3)
}

static WIN32K_EVENT_RECLAIM_ACK_ID: AtomicU64 = AtomicU64::new(0);
static WIN32K_EVENT_RECLAIM_ACK_BODY: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn mark_event_provider_reclaim_pending() {
    write_volatile(
        (WIN32K_SHARED_VADDR + SH_EVENT_RECLAIM_PENDING) as *mut u64,
        1,
    );
}

unsafe fn drain_retired_event_provider_bodies() -> bool {
    loop {
        let pending_id = WIN32K_EVENT_RECLAIM_ACK_ID.load(Ordering::Acquire);
        let pending_body = WIN32K_EVENT_RECLAIM_ACK_BODY.load(Ordering::Acquire);
        if pending_id != 0 || pending_body != 0 {
            if pending_id == 0 || pending_body == 0 {
                return false;
            }
            let (status, _, _, _) = win32k_event_broker_call(
                W32_EVENT_OP_ACK_RECLAIM,
                pending_id,
                pending_body,
                0,
            );
            if status != 0 {
                return false;
            }
            WIN32K_EVENT_RECLAIM_ACK_BODY.store(0, Ordering::Release);
            WIN32K_EVENT_RECLAIM_ACK_ID.store(0, Ordering::Release);
            continue;
        }
        let (status, id, body, _) =
            win32k_event_broker_call(W32_EVENT_OP_DRAIN_RECLAIM, 0, 0, 0);
        if status != 0 {
            return false;
        }
        if id == 0 && body == 0 {
            write_volatile(
                (WIN32K_SHARED_VADDR + SH_EVENT_RECLAIM_PENDING) as *mut u64,
                0,
            );
            return true;
        }
        if id == 0
            || body == 0
            || !provider_event_projection_contains(body)
            || !provider_pool_release_owned(&[(
                body,
                nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64,
            )])
        {
            return false;
        }
        if !provider_event_projection_remove(body) {
            return false;
        }
        WIN32K_EVENT_RECLAIM_ACK_ID.store(id, Ordering::Release);
        WIN32K_EVENT_RECLAIM_ACK_BODY.store(body, Ordering::Release);
    }
}

unsafe fn open_cm_system_hive_target(path: &str) -> Result<Win32kRegHandleTarget, i32> {
    let opened = crate::config_manager_open_system_hive_key(path)?;
    Ok(Win32kRegHandleTarget::SystemHive {
        lease: opened.lease,
        physical_path: opened.physical_path,
    })
}

fn close_win32k_reg_target(target: Win32kRegHandleTarget) -> i32 {
    match target {
        Win32kRegHandleTarget::Empty => STATUS_OBJECT_NAME_NOT_FOUND,
        Win32kRegHandleTarget::VideoDeviceMap => 0,
        Win32kRegHandleTarget::SystemHive { lease, .. } => unsafe {
            crate::config_manager_close_system_hive_key(lease)
                .map(|()| 0)
                .unwrap_or_else(|status| status)
        },
    }
}

#[derive(Clone, Copy)]
enum Win32kRegServiceQueryTarget {
    VideoDeviceMap,
    SystemHive(nt_config_client::SystemHiveKeyLease),
}

fn lookup_win32k_reg_service_query_target(handle: u64) -> Option<Win32kRegServiceQueryTarget> {
    win32k_reg_handles()?
        .iter()
        .find(|entry| {
            entry.handle == handle && !matches!(&entry.target, Win32kRegHandleTarget::Empty)
        })
        .and_then(|entry| match &entry.target {
            Win32kRegHandleTarget::Empty => None,
            Win32kRegHandleTarget::VideoDeviceMap => {
                Some(Win32kRegServiceQueryTarget::VideoDeviceMap)
            }
            Win32kRegHandleTarget::SystemHive { lease, .. } => {
                Some(Win32kRegServiceQueryTarget::SystemHive(*lease))
            }
        })
}

unsafe fn service_win32k_registry_open(root: u64, path: &[u8]) -> Result<u64, i32> {
    let target = if !win32k_reg_path_is_absolute(path) {
        let absolute = system_hive_relative_path_from_handle(root, path)?;
        open_cm_system_hive_target(&absolute)?
    } else if is_video_device_map_key(path) {
        let path = core::str::from_utf8(path).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !crate::config_manager_open_key(path) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        Win32kRegHandleTarget::VideoDeviceMap
    } else {
        let absolute = system_hive_absolute_path(path)?;
        open_cm_system_hive_target(&absolute)?
    };
    match register_win32k_reg_handle(target) {
        Ok(handle) => Ok(handle),
        Err(target) => {
            let _ = close_win32k_reg_target(target);
            Err(STATUS_NO_MEMORY)
        }
    }
}

unsafe fn service_win32k_registry_query(
    handle: u64,
    name: &[u8],
) -> Result<(u32, Vec<u8>, bool), i32> {
    match lookup_win32k_reg_service_query_target(handle).ok_or(STATUS_INVALID_HANDLE_I32)? {
        Win32kRegServiceQueryTarget::VideoDeviceMap => {
            crate::video_device::query_video_device_map_value_owned(name)
                .map(|(value_type, data)| (value_type, data, true))
        }
        Win32kRegServiceQueryTarget::SystemHive(lease) => {
            let name = core::str::from_utf8(name).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
            crate::config_manager_query_leased_system_hive_value(lease, name)
                .map(|value| (value.value_type, value.data, false))
        }
    }
}

/// Service one pointer-free registry request from the win32k component. This is called only by the
/// executive-side component pump, which owns the Configuration Manager transport and handle table.
pub(crate) unsafe fn service_registry_request(op: u64, arg: u64) -> (i32, u64, u64) {
    write_volatile(
        (WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_VALUE_TYPE) as *mut u32,
        0,
    );
    write_volatile(
        (WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_DATA_LEN) as *mut u32,
        0,
    );
    match op {
        WIN32K_REGISTRY_OP_OPEN => {
            let Some(path) =
                read_win32k_registry_ascii(WIN32K_REGISTRY_KEY_LEN, WIN32K_REGISTRY_KEY_OFF)
            else {
                return (STATUS_INVALID_PARAMETER_I32, 0, 0);
            };
            match service_win32k_registry_open(arg, &path) {
                Ok(handle) => (0, handle, 0),
                Err(status) => (status, 0, 0),
            }
        }
        WIN32K_REGISTRY_OP_CLOSE => match take_win32k_reg_handle(arg) {
            Some(target) => (close_win32k_reg_target(target), 0, 0),
            None => (STATUS_INVALID_HANDLE_I32, 0, 0),
        },
        WIN32K_REGISTRY_OP_QUERY_VALUE => {
            let Some(name) =
                read_win32k_registry_ascii(WIN32K_REGISTRY_VALUE_LEN, WIN32K_REGISTRY_VALUE_OFF)
            else {
                return (STATUS_INVALID_PARAMETER_I32, 0, 0);
            };
            match service_win32k_registry_query(arg, &name) {
                Ok((value_type, data, video)) => {
                    write_volatile(
                        (WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_VALUE_TYPE) as *mut u32,
                        value_type,
                    );
                    write_volatile(
                        (WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_DATA_LEN) as *mut u32,
                        data.len().min(u32::MAX as usize) as u32,
                    );
                    if data.len() > WIN32K_REGISTRY_VALUE_CAP {
                        return (
                            STATUS_BUFFER_TOO_SMALL_I32,
                            value_type as u64,
                            data.len() as u64,
                        );
                    }
                    for (index, byte) in data.iter().copied().enumerate() {
                        write_volatile(
                            (WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_DATA_OFF + index as u64)
                                as *mut u8,
                            byte,
                        );
                    }
                    if video {
                        let trace = WIN32K_VIDEO_REG_QUERY_TRACE.fetch_add(1, Ordering::Relaxed);
                        if trace < 16 {
                            print_str(b"[win32k-reg] CM-validated video devicemap query name=");
                            print_str(&name);
                            print_str(b" len=");
                            print_u64(data.len() as u64);
                            print_str(b" status=0x00000000\n");
                        }
                    }
                    (0, value_type as u64, data.len() as u64)
                }
                Err(status) => (status, 0, 0),
            }
        }
        _ => (STATUS_INVALID_PARAMETER_I32, 0, 0),
    }
}

/// `NTSTATUS ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK, POBJECT_ATTRIBUTES)`. OBJECT_ATTRIBUTES x64:
/// ObjectName (PUNICODE_STRING) at +0x10. Resolve win32k's registry imports to live registry/device
/// targets; optional keys not present in CM's mounted hive fail with CM's exact status.
extern "win64" fn s_zw_open_key(handle_out: *mut u64, _access: u64, obj_attr: u64) -> i32 {
    if handle_out.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    if obj_attr == 0 {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    unsafe {
        let Some(path) = object_attributes_name_ascii_lower(obj_attr) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let root_dir = read_unaligned((obj_attr + 0x8) as *const u64);
        if !write_win32k_registry_ascii(WIN32K_REGISTRY_KEY_LEN, WIN32K_REGISTRY_KEY_OFF, &path) {
            return STATUS_INVALID_PARAMETER_I32;
        }
        let (status, hkey, _) = win32k_registry_broker_call(WIN32K_REGISTRY_OP_OPEN, root_dir);
        if status != 0 {
            return status;
        }
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

unsafe fn query_win32k_registry_value(
    handle: u64,
    name: &[u8],
    kvi: u64,
    length: u64,
    result_len: *mut u32,
) -> i32 {
    if !write_win32k_registry_ascii(WIN32K_REGISTRY_VALUE_LEN, WIN32K_REGISTRY_VALUE_OFF, name) {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let (status, value_type, data_len) =
        win32k_registry_broker_call(WIN32K_REGISTRY_OP_QUERY_VALUE, handle);
    if status != 0 {
        if status == STATUS_BUFFER_TOO_SMALL_I32 && !result_len.is_null() {
            write_unaligned(result_len, 12u64.saturating_add(data_len) as u32);
        }
        return status;
    }
    let data = core::slice::from_raw_parts(
        (WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_DATA_OFF) as *const u8,
        data_len as usize,
    );
    emit_kvpi_bytes(kvi, length, result_len, value_type as u32, data)
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
        let Some(name) = read_unicode_string_ascii_lower(value_name) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        query_win32k_registry_value(hkey, &name, kvi, length, result_len)
    }
}

fn win32k_registry_value_owned(handle: u64, name: &[u8]) -> Result<Option<(u32, Vec<u8>)>, i32> {
    unsafe {
        if !write_win32k_registry_ascii(WIN32K_REGISTRY_VALUE_LEN, WIN32K_REGISTRY_VALUE_OFF, name)
        {
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let (status, value_type, data_len) =
            win32k_registry_broker_call(WIN32K_REGISTRY_OP_QUERY_VALUE, handle);
        if status == STATUS_OBJECT_NAME_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(status);
        }
        if data_len > WIN32K_REGISTRY_VALUE_CAP as u64 {
            return Err(STATUS_BUFFER_TOO_SMALL_I32);
        }
        let mut data = Vec::new();
        data.try_reserve_exact(data_len as usize)
            .map_err(|_| STATUS_NO_MEMORY)?;
        for index in 0..data_len as usize {
            data.push(read_volatile(
                (WIN32K_REGISTRY_VADDR + WIN32K_REGISTRY_DATA_OFF + index as u64) as *const u8,
            ));
        }
        Ok(Some((value_type as u32, data)))
    }
}

unsafe fn rtl_query_registry_dispatch(
    flags: u32,
    query_routine: u64,
    name_ptr: u64,
    entry_context: u64,
    value_type: u32,
    data: &[u8],
    context: u64,
) -> i32 {
    if flags & RTL_QUERY_REGISTRY_DIRECT != 0 {
        if entry_context == 0 {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        return match value_type {
            REG_DWORD if data.len() == 4 => {
                write_unaligned(
                    entry_context as *mut u32,
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
                );
                0
            }
            _ => STATUS_INVALID_PARAMETER_I32,
        };
    }
    if query_routine == 0 {
        return 0;
    }
    let routine: extern "win64" fn(u64, u32, u64, u32, u64, u64) -> i32 =
        core::mem::transmute(query_routine as *const ());
    routine(
        name_ptr,
        value_type,
        data.as_ptr() as u64,
        data.len() as u32,
        context,
        entry_context,
    )
}

/// `NTSTATUS RtlQueryRegistryValues(...)` over the same live registry targets as ZwOpenKey and
/// ZwQueryValueKey. win32k uses HANDLE + DIRECT tables for display configuration; callback entries
/// are also dispatched against the live value bytes. Unsupported traversal flags fail explicitly.
extern "win64" fn s_rtl_query_registry_values(
    relative_to: u32,
    path: u64,
    query_table: u64,
    context: u64,
    _environment: u64,
) -> i32 {
    if query_table == 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    if relative_to & RTL_REGISTRY_HANDLE == 0 {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if !is_win32k_reg_handle(path) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    unsafe {
        for index in 0..64u64 {
            let entry = query_table + index * RTL_QUERY_REGISTRY_TABLE_SIZE;
            let query_routine = read_unaligned(entry as *const u64);
            let flags = read_unaligned((entry + 8) as *const u32);
            let name_ptr = read_unaligned((entry + 16) as *const u64);
            let entry_context = read_unaligned((entry + 24) as *const u64);
            let default_type = read_unaligned((entry + 32) as *const u32);
            let default_data = read_unaligned((entry + 40) as *const u64);
            let default_length = read_unaligned((entry + 48) as *const u32);

            if query_routine == 0
                && flags & (RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_DIRECT) == 0
            {
                return 0;
            }
            if flags & RTL_QUERY_REGISTRY_SUBKEY != 0
                || (flags & RTL_QUERY_REGISTRY_DIRECT != 0 && (name_ptr == 0 || query_routine != 0))
            {
                return STATUS_INVALID_PARAMETER_I32;
            }
            if flags & RTL_QUERY_REGISTRY_NOVALUE != 0 {
                let status = rtl_query_registry_dispatch(
                    flags,
                    query_routine,
                    0,
                    entry_context,
                    REG_NONE,
                    &[],
                    context,
                );
                if status < 0 {
                    return status;
                }
                continue;
            }
            let Some(name) = read_wide_cstr_ascii_lower(name_ptr) else {
                return STATUS_INVALID_PARAMETER_I32;
            };
            let value = match win32k_registry_value_owned(path, &name) {
                Ok(value) => value,
                Err(status) => return status,
            };
            let status = if let Some((value_type, data)) = value {
                rtl_query_registry_dispatch(
                    flags,
                    query_routine,
                    name_ptr,
                    entry_context,
                    value_type,
                    &data,
                    context,
                )
            } else if default_type != REG_NONE && default_data != 0 && default_length != 0 {
                let data =
                    core::slice::from_raw_parts(default_data as *const u8, default_length as usize);
                rtl_query_registry_dispatch(
                    flags,
                    query_routine,
                    name_ptr,
                    entry_context,
                    default_type,
                    data,
                    context,
                )
            } else if flags & RTL_QUERY_REGISTRY_REQUIRED != 0 {
                STATUS_OBJECT_NAME_NOT_FOUND
            } else {
                0
            };
            if status < 0 {
                return status;
            }
        }
    }
    STATUS_INVALID_PARAMETER_I32
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

#[inline]
unsafe fn write_eng_device_io_control_bytes_returned(bytes_ret: *mut u32, value: u32) {
    if !bytes_ret.is_null() {
        write_unaligned(bytes_ret, value);
    }
}

#[inline(never)]
unsafe fn request_video_device_io_control(
    hdev: u64,
    ioctl: u32,
    in_buf: u64,
    in_len: u32,
    out_buf: u64,
    out_len: u32,
    bytes_ret: *mut u32,
) -> u32 {
    write_eng_device_io_control_bytes_returned(bytes_ret, 0);
    let in_len = in_len as u64;
    let out_len = out_len as u64;
    let invalid = in_len > VIDEO_IOCTL_IN_CAP as u64
        || out_len > VIDEO_IOCTL_OUT_CAP as u64
        || (in_len != 0 && in_buf == 0)
        || (out_len != 0 && out_buf == 0);
    let seq = WIN32K_VIDEO_IOCTL_REQUEST_TRACE.fetch_add(1, Ordering::Relaxed);
    if seq < 64 {
        print_str(b"[win32k-video-ioctl-request] hdev=0x");
        print_hex((hdev >> 32) as u32);
        print_hex(hdev as u32);
        print_str(b" ioctl=0x");
        print_hex(ioctl as u32);
        print_str(b" in/out=");
        print_u64(in_len);
        print_str(b"/");
        print_u64(out_len);
        print_str(b" inbuf=0x");
        print_hex((in_buf >> 32) as u32);
        print_hex(in_buf as u32);
        print_str(b" outbuf=0x");
        print_hex((out_buf >> 32) as u32);
        print_hex(out_buf as u32);
        print_str(b" bytes=0x");
        print_hex(((bytes_ret as u64) >> 32) as u32);
        print_hex((bytes_ret as u64) as u32);
        print_str(b" invalid=");
        print_u64(invalid as u64);
        print_str(b"\n");
    }
    if invalid {
        return 1;
    }

    let sh = WIN32K_VIDEO_IOCTL_VADDR;
    for index in 0..in_len as usize {
        let value = read_volatile((in_buf + index as u64) as *const u8);
        write_volatile((sh + VIDEO_IOCTL_IN_BUF + index as u64) as *mut u8, value);
    }
    for index in 0..out_len as usize {
        write_volatile((sh + VIDEO_IOCTL_OUT_BUF + index as u64) as *mut u8, 0);
    }
    write_volatile((sh + VIDEO_IOCTL_HDEV) as *mut u64, hdev);
    write_volatile((sh + VIDEO_IOCTL_CODE) as *mut u64, ioctl as u64);
    write_volatile((sh + VIDEO_IOCTL_IN_LEN) as *mut u64, in_len);
    write_volatile((sh + VIDEO_IOCTL_OUT_LEN) as *mut u64, out_len);
    write_volatile((sh + VIDEO_IOCTL_STATUS) as *mut u32, 1);
    write_volatile((sh + VIDEO_IOCTL_BYTES_RETURNED) as *mut u32, 0);

    let _ = crate::driver_launch::call_on(W32_VIDEO_IOCTL_LABEL << 12);
    let status = read_volatile((sh + VIDEO_IOCTL_STATUS) as *const u32);
    let bytes_returned = read_volatile((sh + VIDEO_IOCTL_BYTES_RETURNED) as *const u32);
    let copy_len = core::cmp::min(bytes_returned as u64, out_len) as usize;
    if status == 0 {
        for index in 0..copy_len {
            let value = read_volatile((sh + VIDEO_IOCTL_OUT_BUF + index as u64) as *const u8);
            write_volatile((out_buf + index as u64) as *mut u8, value);
        }
    }
    write_eng_device_io_control_bytes_returned(bytes_ret, bytes_returned);
    status
}

#[inline(never)]
pub(crate) unsafe fn service_video_device_io_control() -> u32 {
    let sh = WIN32K_VIDEO_IOCTL_VADDR;
    let hdev = read_volatile((sh + VIDEO_IOCTL_HDEV) as *const u64);
    let ioctl = read_volatile((sh + VIDEO_IOCTL_CODE) as *const u64);
    let in_len = read_volatile((sh + VIDEO_IOCTL_IN_LEN) as *const u64);
    let out_len = read_volatile((sh + VIDEO_IOCTL_OUT_LEN) as *const u64);
    let mut bytes_returned = 0u32;
    let status = if ioctl > u32::MAX as u64
        || in_len > VIDEO_IOCTL_IN_CAP as u64
        || out_len > VIDEO_IOCTL_OUT_CAP as u64
    {
        1
    } else {
        crate::video_device::video_device_io_control(
            hdev,
            ioctl,
            sh + VIDEO_IOCTL_IN_BUF,
            in_len,
            sh + VIDEO_IOCTL_OUT_BUF,
            out_len,
            &mut bytes_returned as *mut u32,
        )
    };
    if status != 0 {
        bytes_returned = 0;
    } else if ioctl == nt_video_miniport::IOCTL_VIDEO_QUERY_CURRENT_MODE as u64
        && bytes_returned as usize >= nt_video_miniport::VIDEO_MODE_INFORMATION_SIZE
    {
        let output = core::slice::from_raw_parts(
            (sh + VIDEO_IOCTL_OUT_BUF) as *const u8,
            bytes_returned as usize,
        );
        if let Ok(mode) = nt_video_miniport::parse_video_mode_information(output) {
            let _ = crate::publish_active_framebuffer_mode(mode);
        }
    } else if ioctl == nt_video_miniport::IOCTL_VIDEO_SET_CURRENT_MODE as u64 {
        let mut current_mode_bytes = 0u32;
        let query_status = crate::video_device::video_device_io_control(
            hdev,
            nt_video_miniport::IOCTL_VIDEO_QUERY_CURRENT_MODE as u64,
            0,
            0,
            sh + VIDEO_IOCTL_OUT_BUF,
            nt_video_miniport::VIDEO_MODE_INFORMATION_SIZE as u64,
            &mut current_mode_bytes,
        );
        if query_status == 0
            && current_mode_bytes as usize >= nt_video_miniport::VIDEO_MODE_INFORMATION_SIZE
        {
            let output = core::slice::from_raw_parts(
                (sh + VIDEO_IOCTL_OUT_BUF) as *const u8,
                current_mode_bytes as usize,
            );
            if let Ok(mode) = nt_video_miniport::parse_video_mode_information(output) {
                let _ = crate::publish_active_framebuffer_mode(mode);
            }
        }
    }
    write_volatile((sh + VIDEO_IOCTL_STATUS) as *mut u32, status);
    write_volatile(
        (sh + VIDEO_IOCTL_BYTES_RETURNED) as *mut u32,
        bytes_returned,
    );
    let seq = WIN32K_VIDEO_IOCTL_TRACE.fetch_add(1, Ordering::Relaxed);
    if seq < 64 {
        print_str(b"[win32k-video-ioctl] hdev=0x");
        print_hex((hdev >> 32) as u32);
        print_hex(hdev as u32);
        print_str(b" ioctl=0x");
        print_hex(ioctl as u32);
        print_str(b" in/out=");
        print_u64(in_len);
        print_str(b"/");
        print_u64(out_len);
        print_str(b" status=");
        print_u64(status as u64);
        print_str(b" bytes=");
        print_u64(bytes_returned as u64);
        print_str(b"\n");
    }
    status
}

/// win32k's `EngDeviceIoControl` — INTERCEPTED (win32k's export is patched to jmp here in
/// `load_into`, so both the display DLL's imported calls and win32k's own internal calls route into
/// the executive-owned video-device boundary). Returns 0 (ERROR_SUCCESS) on handled, nonzero on
/// unhandled. win64: rcx=hDev, edx=ioctl, r8=inbuf, r9d=inlen, stack: outbuf, outlen(ULONG),
/// bytesret.
extern "win64" fn s_eng_device_io_control(
    hdev: u64,
    ioctl: u32,
    in_buf: u64,
    in_len: u32,
    out_buf: u64,
    out_len: u32,
    bytes_ret: *mut u32,
) -> u32 {
    unsafe {
        request_video_device_io_control(hdev, ioctl, in_buf, in_len, out_buf, out_len, bytes_ret)
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
                let pwnd = resolve_window_handle(hwnd);
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
fn register_trampolines() -> bool {
    // SAFETY: single-threaded executive; the registry is only ever touched here + in export_addr.
    let reg = unsafe { &mut *core::ptr::addr_of_mut!(WIN32K_EXPORTS) };
    if !reg.reserve_initial(DRIVER_EXPORT_INITIAL_RESERVE) {
        return false;
    }
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
    reg.bind("ExFreePool", s_ex_free_pool as usize as u64);
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
    reg.bind("ObDereferenceObject", s_ob_dereference_object as usize as u64);
    reg.bind("ObfReferenceObject", s_ob_reference_object as usize as u64);
    reg.bind(
        "ObfDereferenceObject",
        s_ob_dereference_object as usize as u64,
    );
    reg.bind("ZwDuplicateObject", s_zw_duplicate_object as usize as u64);
    reg.bind("NtDuplicateObject", s_zw_duplicate_object as usize as u64);
    reg.bind("ZwClose", s_zw_close as usize as u64);
    reg.bind("NtClose", s_zw_close as usize as u64);
    reg.bind(
        "LpcRequestPort",
        s_lpc_request_port as *const () as usize as u64,
    );
    reg.bind(
        "LpcRequestWaitReplyPort",
        s_lpc_request_wait_reply_port as *const () as usize as u64,
    );
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
    reg.bind(
        "KeWaitForMultipleObjects",
        s_ke_wait_for_multiple_objects as usize as u64,
    );
    reg.bind(
        "KeEnterCriticalRegion",
        s_ke_enter_critical_region as usize as u64,
    );
    reg.bind(
        "KeLeaveCriticalRegion",
        s_ke_leave_critical_region as usize as u64,
    );
    reg.bind(
        "KeEnterGuardedRegion",
        s_ke_enter_guarded_region as usize as u64,
    );
    reg.bind(
        "KeLeaveGuardedRegion",
        s_ke_leave_guarded_region as usize as u64,
    );
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
        "RtlAppendUnicodeStringToString",
        s_rtl_append_unicode_string_to_string as usize as u64,
    );
    reg.bind(
        "RtlFormatCurrentUserKeyPath",
        s_rtl_format_current_user_key_path as usize as u64,
    );
    reg.bind(
        "RtlFreeUnicodeString",
        s_rtl_free_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlCreateUnicodeString",
        s_rtl_create_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlMultiByteToUnicodeN",
        s_rtl_multibyte_to_unicode_n as usize as u64,
    );
    reg.bind(
        "RtlGetDefaultCodePage",
        s_rtl_get_default_code_page as usize as u64,
    );
    reg.bind(
        "RtlAnsiStringToUnicodeString",
        s_rtl_ansi_string_to_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlUnicodeStringToAnsiString",
        s_rtl_unicode_string_to_ansi_string as usize as u64,
    );
    reg.bind(
        "RtlxUnicodeStringToAnsiSize",
        s_rtlx_unicode_string_to_ansi_size as usize as u64,
    );
    reg.bind(
        "RtlUnicodeToMultiByteSize",
        s_rtl_unicode_to_multibyte_size as usize as u64,
    );
    reg.bind("RtlOemToUnicodeN", s_rtl_oem_to_unicode_n as usize as u64);
    reg.bind(
        "RtlUpcaseUnicodeChar",
        s_rtl_upcase_unicode_char as usize as u64,
    );
    reg.bind(
        "RtlAnsiCharToUnicodeChar",
        s_rtl_ansi_char_to_unicode_char as usize as u64,
    );
    reg.bind("wcslen", s_wcslen as usize as u64);
    reg.bind("_wcsnicmp", s_wcsnicmp as usize as u64);
    reg.bind("wcsnicmp", s_wcsnicmp as usize as u64);
    reg.bind("RtlCompareMemory", s_rtl_compare_memory as usize as u64);
    reg.bind(
        "RtlIntegerToUnicodeString",
        s_rtl_integer_to_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlUnicodeStringToInteger",
        s_rtl_unicode_string_to_integer as usize as u64,
    );
    reg.bind(
        "RtlTimeToTimeFields",
        s_rtl_time_to_time_fields as usize as u64,
    );
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
    reg.bind(
        "MmUnmapViewInSessionSpace",
        s_mm_unmap_view_in_space as usize as u64,
    );
    reg.bind(
        "MmUnmapViewInSystemSpace",
        s_mm_unmap_view_in_space as usize as u64,
    );
    reg.bind(
        "MmUnmapViewOfSection",
        s_mm_unmap_view_of_section as usize as u64,
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
    reg.bind(
        "ExpInterlockedPushEntrySList",
        s_exp_interlocked_push_entry_slist as usize as u64,
    );
    reg.bind(
        "ExpInterlockedPopEntrySList",
        s_exp_interlocked_pop_entry_slist as usize as u64,
    );
    reg.bind("ExQueryDepthSList", s_ex_query_depth_slist as usize as u64);
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
    reg.bind(
        "RtlQueryRegistryValues",
        s_rtl_query_registry_values as usize as u64,
    );
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
    reg.bind(
        "KeQueryPerformanceCounter",
        s_ke_query_performance_counter as usize as u64,
    );
    reg.bind("DbgPrint", s_dbg_print as usize as u64);
    // --- batch 4: native executive resources / critical regions / fast mutexes ---
    reg.bind(
        "ExInitializeResourceLite",
        s_ex_initialize_resource_lite as usize as u64,
    );
    reg.bind(
        "ExDeleteResourceLite",
        s_ex_delete_resource_lite as usize as u64,
    );
    reg.bind(
        "ExAcquireResourceExclusiveLite",
        s_ex_acquire_resource_exclusive_lite as usize as u64,
    );
    reg.bind(
        "ExAcquireResourceSharedLite",
        s_ex_acquire_resource_shared_lite as usize as u64,
    );
    reg.bind(
        "ExReleaseResourceLite",
        s_ex_release_resource_lite as usize as u64,
    );
    reg.bind(
        "ExIsResourceAcquiredExclusiveLite",
        s_ex_is_resource_acquired_exclusive_lite as usize as u64,
    );
    reg.bind(
        "ExIsResourceAcquiredSharedLite",
        s_ex_is_resource_acquired_shared_lite as usize as u64,
    );
    reg.bind(
        "ExEnterCriticalRegionAndAcquireResourceShared",
        s_ex_enter_critical_region_and_acquire_resource_shared as usize as u64,
    );
    reg.bind(
        "ExEnterCriticalRegionAndAcquireResourceExclusive",
        s_ex_enter_critical_region_and_acquire_resource_exclusive as usize as u64,
    );
    reg.bind(
        "ExReleaseResourceAndLeaveCriticalRegion",
        s_ex_release_resource_and_leave_critical_region as usize as u64,
    );
    reg.bind(
        "ExAcquireFastMutexUnsafe",
        s_ex_acquire_fast_mutex_unsafe as usize as u64,
    );
    reg.bind(
        "ExReleaseFastMutexUnsafe",
        s_ex_release_fast_mutex_unsafe as usize as u64,
    );
    reg.bind(
        "ExEnterCriticalRegionAndAcquireFastMutexUnsafe",
        s_ex_enter_critical_region_and_acquire_fast_mutex_unsafe as usize as u64,
    );
    reg.bind(
        "ExReleaseFastMutexUnsafeAndLeaveCriticalRegion",
        s_ex_release_fast_mutex_unsafe_and_leave_critical_region as usize as u64,
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
    reg.stats().allocation_failures == 0
}

/// Resolve an import name to its IAT-slot value: a code trampoline VA, or (for the 11 data
/// exports) the data-cell address. Pure registry resolve now (Workstream B): the executive
/// registered every real trampoline + data cell by name into the `nt-compat-exports`
/// [`Win32kExportRegistry`]. The remaining unregistered declared imports retain the existing zero
/// trampoline until their real implementations are added and the loader can become fully
/// fail-closed.
pub(crate) fn initialize_export_registry() -> bool {
    unsafe {
        if !WIN32K_EXPORTS_READY {
            if !register_trampolines() {
                return false;
            }
            WIN32K_EXPORTS_READY = true;
        }
        true
    }
}

pub(crate) fn export_registry_stats() -> DriverExportRegistryStats {
    unsafe { (&*core::ptr::addr_of!(WIN32K_EXPORTS)).stats() }
}

pub fn export_addr(name: &str) -> u64 {
    if !initialize_export_registry() {
        return 0;
    }
    unsafe {
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
/// Se→nt-security); `NlsMbCodePageTag` points at the validated ANSI table's published DBCS flag;
/// the Mm boundary constants hold their x64 values directly.
const DATA_EXPORTS: &[(&str, u64)] = &[
    ("PsProcessType", 0),
    ("PsThreadType", 0),
    ("ExDesktopObjectType", 0),
    ("ExWindowStationObjectType", 0),
    ("ExEventObjectType", 0),
    ("LpcPortObjectType", 0),
    ("SeExports", WIN32K_SE_EXPORTS_VA),
    ("NlsMbCodePageTag", WIN32K_NLS_MB_TAG_VA),
    ("MmSystemRangeStart", 0xFFFF_0800_0000_0000),
    ("MmUserProbeAddress", 0x0000_7FFF_FFFF_0000),
    ("MmHighestUserAddress", 0x0000_7FFF_FFFF_EFFF),
];

/// Resolve an object-type data-export name to the address of its **real** `OBJECT_TYPE` static, or
/// [`None`] for a non-object-type export (Se/NLS state or Mm constant). win32k reads this value
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

fn import_name_eq(import_name: &[u8], expected: &[u8]) -> bool {
    import_name.len() == expected.len()
        && import_name
            .iter()
            .zip(expected.iter())
            .all(|(&actual, &expected)| actual == expected)
}

unsafe fn trace_gdi_driver_import(import_name: &[u8], slot: u64, addr: u64, direct: bool) {
    if !import_name_eq(import_name, b"EngDeviceIoControl") {
        return;
    }
    let seq = GDI_DRIVER_IMPORT_TRACE.fetch_add(1, Ordering::Relaxed);
    if seq >= 16 {
        return;
    }
    print_str(b"[win32k-gdidrv-import] ");
    print_str(import_name);
    print_str(b" slot=0x");
    print_hex((slot >> 32) as u32);
    print_hex(slot as u32);
    print_str(b" addr=0x");
    print_hex((addr >> 32) as u32);
    print_hex(addr as u32);
    print_str(b" direct=");
    print_u64(direct as u64);
    print_str(b"\n");
}

unsafe fn log_unresolved_gdi_driver_import(import_name: &[u8]) {
    print_str(b"[win32k-gdidrv-import] unresolved ");
    print_str(import_name);
    print_str(b"\n");
}

unsafe fn reject_win32k_nls(reason: &[u8]) -> bool {
    print_str(b"[win32k-nls] reject image: ");
    print_str(reason);
    print_str(b"\n");
    false
}

unsafe fn validate_and_publish_win32k_nls(nls_sizes: [usize; 3]) -> bool {
    let [ansi_size, oem_size, case_size] = nls_sizes;
    if ansi_size == 0 || ansi_size & 1 != 0 || ansi_size as u64 > NLS_ANSI_FRAMES * 0x1000 {
        return reject_win32k_nls(b"invalid c_1252.nls size");
    }
    if oem_size == 0 || oem_size & 1 != 0 || oem_size as u64 > NLS_OEM_FRAMES * 0x1000 {
        return reject_win32k_nls(b"invalid c_437.nls size");
    }
    if case_size == 0 || case_size & 1 != 0 || case_size as u64 > NLS_CASE_FRAMES * 0x1000 {
        return reject_win32k_nls(b"invalid l_intl.nls size");
    }

    let ansi = core::slice::from_raw_parts(NLS_ANSI_VADDR as *const u16, ansi_size / 2);
    let oem = core::slice::from_raw_parts(NLS_OEM_VADDR as *const u16, oem_size / 2);
    let case = core::slice::from_raw_parts(NLS_CASE_VADDR as *const u16, case_size / 2);
    let Some(ansi_layout) = nt_nls::validate_sbcs_code_page(ansi, 1252) else {
        return reject_win32k_nls(b"c_1252.nls is not a complete SBCS CP1252 table");
    };
    let Some(oem_layout) = nt_nls::validate_sbcs_code_page(oem, 437) else {
        return reject_win32k_nls(b"c_437.nls is not a complete SBCS CP437 table");
    };
    let Some(case_layout) = nt_nls::validate_case_table(case) else {
        return reject_win32k_nls(b"l_intl.nls contains an invalid case-map offset");
    };

    let ansi_bytes = core::slice::from_raw_parts(NLS_ANSI_VADDR as *const u8, ansi_size);
    let ansi_wide_offset = ansi_layout.wide_char_index * 2;
    if ansi[ansi_layout.multi_byte_index + 0x80] != 0x20ac
        || ansi_bytes[ansi_wide_offset + 0x20ac] != 0x80
    {
        return reject_win32k_nls(b"c_1252.nls conversion tables disagree");
    }
    if oem[oem_layout.multi_byte_index + 0x80] != 0x00c7 {
        return reject_win32k_nls(b"c_437.nls byte table has the wrong identity");
    }
    let upper = &case[case_layout.upper_index..case_layout.upper_index + case_layout.upper_len];
    if nt_nls::wide_upcase_with_table(0x00e9, upper) != 0x00c9 {
        return reject_win32k_nls(b"l_intl.nls uppercase table has the wrong identity");
    }

    let (Ok(ansi_size), Ok(oem_size), Ok(case_size)) = (
        u32::try_from(ansi_size),
        u32::try_from(oem_size),
        u32::try_from(case_size),
    ) else {
        return reject_win32k_nls(b"NLS file size cannot be published");
    };
    let state = Win32kNlsState {
        magic: WIN32K_NLS_STATE_MAGIC,
        ansi_size,
        oem_size,
        case_size,
        ansi_code_page: ansi_layout.code_page,
        oem_code_page: oem_layout.code_page,
        ansi_multi_byte_index: ansi_layout.multi_byte_index as u32,
        ansi_wide_byte_offset: ansi_wide_offset as u32,
        oem_multi_byte_index: oem_layout.multi_byte_index as u32,
        upper_case_index: case_layout.upper_index as u32,
        upper_case_len: case_layout.upper_len as u32,
    };
    write_volatile(
        WIN32K_NLS_MB_TAG_VA as *mut u8,
        ansi_layout.dbcs_code_page as u8,
    );
    write_unaligned(WIN32K_NLS_STATE_VA as *mut Win32kNlsState, state);
    print_str(b"[win32k-nls] validated CP1252/CP437/l_intl tables\n");
    true
}

/// Runs in the EXECUTIVE. `src_va`/`src_size` name the raw win32k.sys staged in WIN32KBUF; the
/// image frames are mapped RW at [`WIN32K_CODE_VA`] and the DATA region at [`WIN32K_DATA_VADDR`].
/// Copy the sections into their virtual offsets, apply DIR64 relocs, initialise the data-export
/// cells, validate and publish the mapped NLS tables, then patch the IAT. Fills [`CODE_RIGHTS`].
/// Returns the DriverEntry RVA.
pub unsafe fn load_into(src_va: u64, _src_size: usize, nls_sizes: [usize; 3]) -> Option<u32> {
    if !validate_and_publish_win32k_nls(nls_sizes) {
        return None;
    }
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
/// reclaiming arena over `WIN32K_POOL_VADDR`, so DriverEntry and executive bridge allocations share
/// one serialized ownership domain.
pub(crate) unsafe fn pool_alloc_export(size: u64) -> u64 {
    pool_alloc(size)
}

#[no_mangle]
#[link_section = ".text.win32k_subsystem_entry"]
pub unsafe extern "C" fn win32k_subsystem_entry(heap_frames: u64) -> ! {
    if !unsafe { allocator::initialize_mapped_heap(heap_frames) } {
        park();
    }
    if !provider_pool_ready() {
        print_str(b"[win32k-host] ERROR: provider pool metadata is not initialized\n");
        park();
    }
    if registered_provider_wait_domain().is_none() {
        print_str(b"[win32k-host] ERROR: provider wait domain is not published\n");
        park();
    }
    if !initialize_provider_allocation_tracking() {
        print_str(b"[win32k-host] ERROR: provider allocation tracking initialization failed\n");
        park();
    }
    if !initialize_provider_local_event_tracking() {
        print_str(b"[win32k-host] ERROR: provider local Event tracking initialization failed\n");
        park();
    }
    let Some(driver_activation) =
        begin_provider_stack_event_activation(PROVIDER_DRIVER_ENTRY_DISPATCH_ID)
    else {
        print_str(b"[win32k-host] ERROR: DriverEntry stack activation failed\n");
        park();
    };
    core::ptr::write(
        core::ptr::addr_of_mut!(WIN32K_DRIVER_STACK_EVENT_ACTIVATION),
        Some(driver_activation.activation),
    );
    core::mem::forget(driver_activation);
    // NOW RUNS ON THE SHARED HARNESS (Phase B, Step 4b). The DriverEntry preamble (build DRIVER_OBJECT
    // + RegistryPath from win32k's OWN pool, mark V_ENTERED, call DriverEntry, record verdict/status),
    // the `post_driver_entry` hook, and the persistent send_done→recv_req→dispatch→writeback loop are
    // all delegated to [`crate::spawn_hosts::component_main`]. win32k's irreducible specifics stay
    // win32k-side: the SSN router + per-dispatch pre/post work is [`win32k_dispatch`] (the `dispatch`
    // closure); bootstrap process establishment + `setup_dispatch_context` are
    // [`win32k_post_driver_entry`] (both MUST run between DriverEntry and the FIRST send_done —
    // preserved by the harness ordering). The user-thread callout is deferred until a real CSRSS
    // generation exists because its queue Event is a process-owned native handle.
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
            driver_object_off: u64::MAX,
            ext_size: 0x40,
            mj: 0x100,
            mj_table_off: u64::MAX,
            pool: pool_alloc_export,
            support_entry_rva_off: u64::MAX,
            support_count_off: u64::MAX,
            support_records_off: u64::MAX,
            support_record_capacity: 0,
            support_record_size: 0,
            support_status_off: u64::MAX,
            support_verdict_off: u64::MAX,
            default_major_function: 0,
        },
        SH_REQ_STATUS,      // win32k status offset (0x78)
        W32_DISPATCH_LABEL, // 0x770
        win32k_dispatch,    // ssn → per-dispatch pre/post + dispatch_ssn
        win32k_post_driver_entry,
    )
}

/// win32k `post_driver_entry` (runs between DriverEntry and the FIRST `send_done`, exactly as the old
/// inline entry): emit the DriverEntry-returned diagnostic, record the pool high-water, then
/// establish win32k's bootstrap process context and enter the per-dispatch process context
/// ([`setup_dispatch_context`]). The first real CSRSS dispatch rekeys the bootstrap process and
/// creates the permanent desktop thread with CSRSS's exact process generation active.
unsafe fn win32k_post_driver_entry(status: i32, _drv: u64) {
    let driver_activation =
        core::ptr::read(core::ptr::addr_of!(WIN32K_DRIVER_STACK_EVENT_ACTIVATION));
    core::ptr::write(
        core::ptr::addr_of_mut!(WIN32K_DRIVER_STACK_EVENT_ACTIVATION),
        None,
    );
    let Some(driver_activation) = driver_activation else {
        print_str(b"[win32k-event] DriverEntry stack activation identity missing\n");
        park();
    };
    if !finish_provider_stack_event_activation(driver_activation) {
        print_str(b"[win32k-event] DriverEntry stack Event retirement failed\n");
        park();
    }
    let v = read_volatile((WIN32K_SHARED_VADDR + SH_VERDICT) as *const u32);
    let pool_used = provider_pool_census().arena_high_water;
    write_volatile((WIN32K_SHARED_VADDR + SH_POOL_USED) as *mut u64, pool_used);
    print_str(b"[win32k-host] DriverEntry returned status=0x");
    print_hex(status as u32);
    print_str(b" verdict=0x");
    print_hex(v);
    print_str(b"\n");

    // Establish only the provider bootstrap PROCESSINFO here. InitThreadCallback calls
    // ZwCreateEvent, and no hosted process lifetime owns a handle table at DriverEntry time.
    if status == 0 {
        establish_bootstrap_process_context();
    }
    // Enter the per-dispatch process/thread context (the old `dispatch_loop` ran this ONCE before the
    // loop; the harness's loop calls win32k_dispatch per request, so seed the context here — before the
    // FIRST send_done — to preserve the exact ordering).
    setup_dispatch_context();
}

unsafe fn select_existing_ps_provider_context(
    require_thread: bool,
) -> Result<(usize, Option<usize>), u32> {
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INVALID_CID: u32 = 0xC000_000B;
    let sh = WIN32K_SHARED_VADDR;
    let pi = read_volatile((sh + SH_REQ_CLIENT_PI) as *const u64);
    let pid = read_volatile((sh + SH_REQ_PROCESS_ID) as *const u64);
    let tid = read_volatile((sh + SH_REQ_THREAD_ID) as *const u64);
    let generation = read_volatile((sh + SH_REQ_GENERATION) as *const u64);
    let supplied_eprocess = read_volatile((sh + SH_REQ_EPROCESS) as *const u64);
    let supplied_ethread = read_volatile((sh + SH_REQ_ETHREAD) as *const u64);
    if checked_client_index(pi).is_none()
        || pid == 0
        || generation == 0
        || supplied_eprocess == 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let process_index = process_context_index_for_pid(pid).ok_or(STATUS_INVALID_CID)?;
    if process_ctx_pi(process_index) != pi
        || process_ctx_generation(process_index) != generation
        || process_ctx_eprocess(process_index) != supplied_eprocess
    {
        return Err(STATUS_INVALID_CID);
    }

    let thread_index = if tid == 0 {
        None
    } else {
        let Some(index) = thread_context_index_for_tid(tid) else {
            if require_thread {
                return Err(STATUS_INVALID_CID);
            }
            return install_existing_ps_provider_process_context(process_index, pi, pid, supplied_eprocess);
        };
        if thread_ctx_pid(index) != pid
            || thread_ctx_pi(index) != pi
            || thread_ctx_generation(index) != generation
            || supplied_ethread == 0
            || thread_ctx_ethread(index) != supplied_ethread
        {
            return Err(STATUS_INVALID_CID);
        }
        Some(index)
    };

    WIN32K_CURRENT_CLIENT_PI.store(pi, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(tid, Ordering::Relaxed);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, supplied_eprocess);
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        process_ctx_w32process(process_index),
    );
    if let Some(thread_index) = thread_index {
        let recorded_teb = thread_ctx_teb(thread_index);
        let supplied_teb = read_volatile((sh + SH_REQ_CLIENT_TEB) as *const u64);
        if supplied_teb != 0 && recorded_teb != 0 && supplied_teb != recorded_teb {
            return Err(STATUS_INVALID_CID);
        }
        let teb = if supplied_teb != 0 {
            supplied_teb
        } else if recorded_teb != 0 {
            recorded_teb
        } else {
            thread_ctx_callout_teb(thread_index)
        };
        if teb == 0 {
            return Err(STATUS_INVALID_CID);
        }
        write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, teb);
        write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, supplied_ethread);
        write_volatile(
            SLOT_W32THREAD as *mut u64,
            thread_ctx_w32thread(thread_index),
        );
        publish_selected_context(process_index, thread_index);
    } else {
        write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, WIN32K_KPCR_VA);
        write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, 0);
        write_volatile(SLOT_W32THREAD as *mut u64, 0);
        write_volatile((sh + SH_CTX_PROCESS_ID) as *mut u64, pid);
        write_volatile((sh + SH_CTX_THREAD_ID) as *mut u64, 0);
        write_volatile((sh + SH_CTX_EPROCESS) as *mut u64, supplied_eprocess);
        write_volatile((sh + SH_CTX_ETHREAD) as *mut u64, 0);
        write_volatile(
            (sh + SH_CTX_W32PROCESS) as *mut u64,
            process_ctx_w32process(process_index),
        );
        write_volatile((sh + SH_CTX_W32THREAD) as *mut u64, 0);
    }
    Ok((process_index, thread_index))
}

unsafe fn install_existing_ps_provider_process_context(
    process_index: usize,
    pi: u64,
    pid: u64,
    eprocess: u64,
) -> Result<(usize, Option<usize>), u32> {
    let sh = WIN32K_SHARED_VADDR;
    WIN32K_CURRENT_CLIENT_PI.store(pi, Ordering::Relaxed);
    WIN32K_CURRENT_PROCESS_ID.store(pid, Ordering::Relaxed);
    WIN32K_CURRENT_THREAD_ID.store(0, Ordering::Relaxed);
    write_volatile((WIN32K_KPCR_VA + 0x30) as *mut u64, WIN32K_KPCR_VA);
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, eprocess);
    write_volatile((WIN32K_KPCR_VA + 0x188) as *mut u64, 0);
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        process_ctx_w32process(process_index),
    );
    write_volatile(SLOT_W32THREAD as *mut u64, 0);
    write_volatile((sh + SH_CTX_PROCESS_ID) as *mut u64, pid);
    write_volatile((sh + SH_CTX_THREAD_ID) as *mut u64, 0);
    write_volatile((sh + SH_CTX_EPROCESS) as *mut u64, eprocess);
    write_volatile((sh + SH_CTX_ETHREAD) as *mut u64, 0);
    write_volatile(
        (sh + SH_CTX_W32PROCESS) as *mut u64,
        process_ctx_w32process(process_index),
    );
    write_volatile((sh + SH_CTX_W32THREAD) as *mut u64, 0);
    Ok((process_index, None))
}

unsafe fn dispatch_ps_provider_command(command: u64, expected: u64, flags: u64) -> u64 {
    const STATUS_SUCCESS: u64 = 0;
    const STATUS_UNSUCCESSFUL: u64 = 0xC000_0001u32 as u64;
    const STATUS_INVALID_PARAMETER: u64 = 0xC000_000Du32 as u64;
    const STATUS_DEVICE_NOT_READY: u64 = 0xC000_00A3u32 as u64;
    if command == PS_WIN32_PROVIDER_FINALIZE_PROCESS_OBJECTS {
        if expected != 0 || flags != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let sh = WIN32K_SHARED_VADDR;
        let pi = read_volatile((sh + SH_REQ_CLIENT_PI) as *const u64);
        let pid = read_volatile((sh + SH_REQ_PROCESS_ID) as *const u64);
        let generation = read_volatile((sh + SH_REQ_GENERATION) as *const u64);
        if checked_client_index(pi).is_none() || pid == 0 || generation == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(process_index) = process_context_index_for_pid(pid) else {
            return if (0..thread_ctx_len()).any(|index| thread_ctx_pid(index) == pid) {
                STATUS_UNSUCCESSFUL
            } else {
                STATUS_SUCCESS
            };
        };
        if process_ctx_pi(process_index) != pi
            || process_ctx_generation(process_index) != generation
            || process_ctx_w32process(process_index) != 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        let eprocess = process_ctx_eprocess(process_index);
        if eprocess == 0
            || read_volatile((eprocess + EPROCESS_WIN32PROCESS_OFF) as *const u64) != 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        for index in 0..thread_ctx_len() {
            if thread_ctx_pid(index) != pid {
                continue;
            }
            let ethread = thread_ctx_ethread(index);
            if thread_ctx_pi(index) != pi
                || thread_ctx_generation(index) != generation
                || thread_ctx_w32thread(index) != 0
                || ethread == 0
                || read_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *const u64) != 0
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
        for index in 0..thread_ctx_len() {
            if thread_ctx_pid(index) == pid && !finalize_thread_ctx_record(index) {
                return STATUS_UNSUCCESSFUL;
            }
        }
        return if finalize_process_ctx_record(process_index) {
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        };
    }

    let require_thread = command == PS_WIN32_PROVIDER_THREAD_EXIT;
    let (process_index, thread_index) =
        match select_existing_ps_provider_context(require_thread) {
            Ok(selected) => selected,
            Err(status) => return status as u64,
        };
    let pid = process_ctx_pid(process_index);

    match command {
        PS_WIN32_PROVIDER_THREAD_EXIT => {
            let Some(thread_index) = thread_index else {
                return STATUS_INVALID_PARAMETER;
            };
            let ethread = thread_ctx_ethread(thread_index);
            if expected == 0
                || flags & !PS_WIN32_PROVIDER_RETAIN_THREAD_CONTEXT != 0
                || thread_ctx_w32thread(thread_index) != expected
                || read_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *const u64) != expected
            {
                return STATUS_INVALID_PARAMETER;
            }
            if flags & PS_WIN32_PROVIDER_RETAIN_THREAD_CONTEXT != 0 {
                set_process_ctx_terminating(process_index, 1);
            }
            let routine = read_volatile((WIN32_CALLOUTS + 8) as *const u64);
            if routine == 0 {
                return STATUS_DEVICE_NOT_READY;
            }
            let callout: extern "win64" fn(u64, u64) -> i32 =
                core::mem::transmute(routine as *const ());
            let status = callout(ethread, 1);
            if status < 0 {
                return status as u32 as u64;
            }
            if thread_ctx_w32thread(thread_index) != 0
                || read_volatile((ethread + KTHREAD_WIN32THREAD_OFF) as *const u64) != 0
                || read_volatile(SLOT_W32THREAD as *const u64) != 0
            {
                return STATUS_UNSUCCESSFUL;
            }
            publish_selected_context(process_index, thread_index);
            STATUS_SUCCESS
        }
        PS_WIN32_PROVIDER_PROCESS_EXIT => {
            let eprocess = process_ctx_eprocess(process_index);
            if expected == 0
                || flags != 0
                || process_ctx_w32process(process_index) != expected
                || read_volatile((eprocess + EPROCESS_WIN32PROCESS_OFF) as *const u64) != expected
            {
                return STATUS_INVALID_PARAMETER;
            }
            for index in 0..thread_ctx_len() {
                if thread_ctx_pid(index) == pid && thread_ctx_w32thread(index) != 0 {
                    return STATUS_INVALID_PARAMETER;
                }
            }
            set_process_ctx_terminating(process_index, 1);
            let routine = read_volatile(WIN32_CALLOUTS as *const u64);
            if routine == 0 {
                return STATUS_DEVICE_NOT_READY;
            }
            let callout: extern "win64" fn(u64, u64) -> i32 =
                core::mem::transmute(routine as *const ());
            let status = callout(eprocess, 0);
            if status < 0 {
                return status as u32 as u64;
            }
            if process_ctx_w32process(process_index) != 0
                || read_volatile((eprocess + EPROCESS_WIN32PROCESS_OFF) as *const u64) != 0
                || read_volatile(SLOT_W32PROCESS as *const u64) != 0
            {
                return STATUS_UNSUCCESSFUL;
            }
            if let Some(thread_index) = thread_index {
                publish_selected_context(process_index, thread_index);
            }
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER,
    }
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
    let callback_frame =
        (WIN32K_SHARED_VADDR + SH_USER_CALLBACK) as *const nt_user_callback::CallbackFrame;
    let dispatch_id = read_volatile(core::ptr::addr_of!((*callback_frame).header.dispatch_id));
    let Some(_stack_event_activation) = begin_provider_stack_event_activation(dispatch_id) else {
        let status = 0xC000_009Au32;
        return (status as i32, status as u64);
    };
    if read_volatile((WIN32K_SHARED_VADDR + SH_EVENT_RECLAIM_PENDING) as *const u64) != 0
        && !drain_retired_event_provider_bodies()
    {
        let status = 0xC000_0001u32;
        return (status as i32, status as u64);
    }
    let ssn = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_SSN) as *const u64);
    let a0 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A0) as *const u64);
    let a1 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A1) as *const u64);
    let a2 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A2) as *const u64);
    let a3 = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_A3) as *const u64);
    let request_kind = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_KIND) as *const u64);
    if request_kind == WIN32K_REQUEST_PS_PROVIDER {
        let result = dispatch_ps_provider_command(a0, a1, a2);
        return (result as u32 as i32, result);
    }
    if request_kind != WIN32K_REQUEST_SSDT {
        return (0xC000_000Du32 as i32, 0xC000_000Du32 as u64);
    }
    if ssn == SSN_TEST_FAULT {
        // Transport selftest: touch an un-demand-paged provider page without manufacturing a GUI
        // client. The executive resolves the fault through the dedicated win32k reply object.
        let probe = read_volatile(TEST_FAULT_VA as *const u64);
        write_volatile((WIN32K_SHARED_VADDR + SH_REQ_A0) as *mut u64, probe);
        return (TEST_FAULT_STATUS as u32 as i32, TEST_FAULT_STATUS as u32 as u64);
    }
    // Ps invokes the registered JobCallout as an executive-to-provider operation. It owns no
    // calling GUI thread and must not inherit or manufacture a client win32 context merely to
    // update win32k-owned job policy.
    if ssn == SSN_WIN32_JOB_CALLOUT {
        let result = dispatch_win32_job_callout(a0, a1 as u32, a2);
        return (result as u32 as i32, result);
    }
    if ssn == SSN_WIN32_JOB_ATOM {
        let result = dispatch_win32_job_atom(a0, a1, a2, a3);
        return (result as u32 as i32, result);
    }
    let output_stage_valid = a0 >= WIN32K_MESSAGE_STAGE_BASE
        && a0 < WIN32K_MESSAGE_STAGE_BASE + 0x1000
        && (a0 - WIN32K_MESSAGE_STAGE_BASE) % WIN32K_MESSAGE_STAGE_SLOT_BYTES == 0;
    if output_stage_valid {
        write_volatile(
            (a0 + WIN32K_MESSAGE_STAGE_OUTPUT_LENGTH_OFFSET) as *mut u64,
            u64::MAX,
        );
    }
    let process_id = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_PROCESS_ID) as *const u64);
    let client_pi = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_CLIENT_PI) as *const u64);
    let client_teb = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_CLIENT_TEB) as *const u64);
    let thread_id = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_THREAD_ID) as *const u64);
    let generation = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_GENERATION) as *const u64);
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
        generation,
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
    let result = if ssn == SSN_GDI_BATCH_FLUSH_CALLOUT {
        dispatch_gdi_batch_flush_callout(client_pi, client_teb)
    } else if ssn == SSN_WIN32_JOB_USER_HANDLE {
        dispatch_win32_job_user_handle(a0, a1, a2 != 0, a3 as u32)
    } else if ssn == SSN_NT_USER_VALIDATE_HANDLE_SECURE {
        dispatch_validate_user_handle_secure(a0)
    } else if let Some(result) = dispatch_job_scoped_broadcast(ssn, a0, a1, a2, a3) {
        result
    } else if let Some(result) = enforce_job_handle_target_policy(ssn, a0, a2) {
        result
    } else if let Some(denied_result) = enforce_win32_job_ui_policy(ssn, a0, a1) {
        denied_result
    } else if matches!(ssn, 0x1036 | 0x10AD) {
        dispatch_ssn_with_job_atom_namespace(process_index, ssn, a0, a1, a2, a3)
    } else {
        dispatch_ssn(ssn, a0, a1, a2, a3)
    };
    if ssn == SSN_NT_USER_LOAD_KEYBOARD_LAYOUT_EX && result != 0 {
        let _ = refresh_default_keyboard_layout();
        let _ = bind_default_keyboard_layout_to_thread(t);
    }
    // Post-NtUserInitialize (0x125a) display prerequisites (once). InitializeGreCSRSS and
    // InitFontSupport have completed, so this is the earliest valid point to load the system font
    // and create the PDEV before user32's resource-backed cursor/class initialization starts issuing
    // NtGdiOpenDCW. WinSta0 and its desktops are deliberately not created here: winlogon owns that
    // lifecycle, after CSRSS has created the API workers that service UserCreateSystemThread.
    if ssn == SSN_NT_USER_INITIALIZE_REAL && result as u32 == 0 && !DESKTOP_GFX_SEEDED {
        DESKTOP_GFX_SEEDED = true;
        load_system_font_for_client(current_client_index());
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
    // Desktop-heap mutation belongs to the win32k provider. Prepare the selected thread's client
    // mapping while the provider-private allocation and Event catalogs are addressable; the
    // executive consumes only the resulting scalar pointers after this dispatch completes.
    let _ = prepare_thread_desktop_client_info(t);
    if output_stage_valid {
        let staged_message = read_volatile((a0 + 8) as *const u32);
        let output_length =
            nt_user_callback::message_dispatch_output_length(ssn, result, staged_message);
        write_volatile(
            (a0 + WIN32K_MESSAGE_STAGE_OUTPUT_LENGTH_OFFSET) as *mut u64,
            u64::from(output_length),
        );
    }
    (result as u32 as i32, result)
}

/// Invoke win32k's real `WIN32_CALLOUTS_FPNS.BatchFlushRoutine` for the selected client thread.
/// The caller's TEB is exposed through KPCR.PrcbData.CurrentThread.Teb by `win32k_dispatch` above.
unsafe fn dispatch_gdi_batch_flush_callout(client_pi: u64, client_teb: u64) -> u64 {
    const STATUS_INVALID_PARAMETER: u64 = 0xC000_000Du32 as u64;
    const STATUS_DEVICE_NOT_READY: u64 = 0xC000_00A3u32 as u64;

    if client_pi == 0 || client_teb == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let routine = read_volatile((WIN32_CALLOUTS + WIN32_CALLOUT_BATCH_FLUSH_OFF) as *const u64);
    if routine == 0 {
        return STATUS_DEVICE_NOT_READY;
    }

    let flush: extern "win64" fn() -> i32 = core::mem::transmute(routine as *const ());
    flush() as u32 as u64
}

unsafe fn dispatch_win32_job_callout(job: u64, callout_type: u32, data: u64) -> u64 {
    if callout_type == PS_W32_JOB_CONTROL_REMOVE_PROCESS {
        return remove_process_from_win32_job(job, data) as u64;
    }
    let routine = read_volatile((WIN32_CALLOUTS + WIN32_CALLOUT_JOB_OFF) as *const u64);
    if routine == 0 {
        return 0xC000_00A3u32 as u64;
    }
    let parameters = Win32JobCalloutParameters {
        job,
        callout_type,
        _padding: 0,
        data,
    };
    let callout: extern "win64" fn(u64) -> i32 = core::mem::transmute(routine as *const ());
    callout(core::ptr::addr_of!(parameters) as u64) as u32 as u64
}

fn restricted_ui_operation(ssn: u64, a0: u64, a1: u64) -> Option<nt_win32k_job::UiOperation> {
    use nt_win32k_job::UiOperation;

    match ssn {
        // Clipboard data and observable clipboard state.
        0x102E | 0x1055 | 0x10CD | 0x10DC | 0x10ED | 0x10FD | 0x1115 | 0x1241 | 0x124F => {
            Some(UiOperation::ReadClipboard)
        }
        // Clipboard mutations. Open/CloseClipboard remain available so a process restricted in
        // only one direction can still use the permitted direction.
        0x10D5 | 0x10FC | 0x111F | 0x1121 => Some(UiOperation::WriteClipboard),
        // NtUserSystemParametersInfo: queries remain legal; only the NT5 SPI_SET surface is denied.
        0x1041 if nt_win32k_job::is_system_parameter_write(a0 as u32) => {
            Some(UiOperation::ChangeSystemParameters)
        }
        0x122A => Some(UiOperation::ChangeDisplaySettings),
        // The NT contract restricts desktop creation and switching, not ordinary open/query use.
        SSN_NT_USER_CREATE_DESKTOP | SSN_NT_USER_SWITCH_DESKTOP => {
            Some(UiOperation::CreateOrSwitchDesktop)
        }
        // NtUserSetInformationThread(Thread, UserThreadInitiateShutdown, ...).
        0x10E5 if a1 as u32 == 5 => Some(UiOperation::ExitWindows),
        _ => None,
    }
}

unsafe fn dispatch_win32_job_atom(job: u64, operation: u64, value: u64, capacity: u64) -> u64 {
    let stage = WIN32K_JOB_ATOM_VADDR;
    let payload = stage + WIN32K_JOB_ATOM_PAYLOAD_OFF;
    let policy = win32_job_ui_policy();
    match operation {
        WIN32_JOB_ATOM_ADD_NAME | WIN32_JOB_ATOM_FIND_NAME => {
            let byte_len = value as usize;
            if byte_len > nt_kernel_exec::rtl_atom::NAME_CAP * 2 || byte_len & 1 != 0 {
                return nt_win32k_job::STATUS_INVALID_PARAMETER as u64;
            }
            let name = core::slice::from_raw_parts(payload as *const u16, byte_len / 2);
            let result = if operation == WIN32_JOB_ATOM_ADD_NAME {
                policy.add_atom_name(job, name)
            } else {
                policy.find_atom_name(job, name)
            };
            match result {
                Ok(atom) => {
                    write_volatile(stage as *mut u16, atom);
                    nt_win32k_job::STATUS_SUCCESS as u64
                }
                Err(status) => status as u64,
            }
        }
        WIN32_JOB_ATOM_ADD_INTEGER | WIN32_JOB_ATOM_FIND_INTEGER => {
            let result = if operation == WIN32_JOB_ATOM_ADD_INTEGER {
                policy.add_integer_atom(job, value as u16)
            } else {
                policy.find_integer_atom(job, value as u16)
            };
            match result {
                Ok(atom) => {
                    write_volatile(stage as *mut u16, atom);
                    nt_win32k_job::STATUS_SUCCESS as u64
                }
                Err(status) => status as u64,
            }
        }
        WIN32_JOB_ATOM_DELETE => policy.delete_atom(job, value as u16) as u64,
        WIN32_JOB_ATOM_QUERY => {
            let name_capacity = (capacity as u32)
                .min(((WIN32K_JOB_ATOM_BYTES as u64 - WIN32K_JOB_ATOM_PAYLOAD_OFF) / 2 * 2) as u32);
            let mut name = [0u16; nt_kernel_exec::rtl_atom::NAME_CAP + 1];
            let result = policy.query_atom(job, value as u16, &mut name, name_capacity);
            write_volatile((stage + 4) as *mut u32, result.reference_count);
            write_volatile((stage + 8) as *mut u32, result.pin_count);
            write_volatile((stage + 12) as *mut u32, result.name_length);
            if result.status == nt_kernel_exec::rtl_atom::status::SUCCESS {
                let bytes = (result.name_length as usize).min(name.len() * 2);
                core::ptr::copy_nonoverlapping(
                    name.as_ptr() as *const u8,
                    payload as *mut u8,
                    bytes,
                );
            }
            result.status as u64
        }
        WIN32_JOB_ATOM_LIST => {
            let slots = (capacity as usize)
                .min((WIN32K_JOB_ATOM_BYTES - WIN32K_JOB_ATOM_PAYLOAD_OFF as usize) / 2);
            let atoms = core::slice::from_raw_parts_mut(payload as *mut u16, slots);
            let result = policy.list_atoms(job, atoms);
            write_volatile((stage + 16) as *mut u32, result.count as u32);
            result.status as u64
        }
        _ => nt_win32k_job::STATUS_INVALID_PARAMETER as u64,
    }
}

struct ResolvedUserHandle {
    entry_address: u64,
    canonical: u64,
    owner_process: Option<u64>,
}

/// Resolve a live ReactOS USER handle through the provider-owned handle table and recover its
/// W32PROCESS owner using the allocation class of the entry type. Legacy generation-less handles
/// are accepted by USER, but the grant store always receives the full current generation so a
/// recycled slot cannot inherit an old exception.
unsafe fn resolve_user_handle(handle: u64) -> Option<ResolvedUserHandle> {
    let entry = resolve_user_handle_entry(handle)?;
    Some(ResolvedUserHandle {
        entry_address: entry.address,
        canonical: entry.canonical,
        owner_process: user_handle_owner_process(entry),
    })
}

unsafe fn set_current_client_last_error(error: u32) {
    let teb = read_volatile((WIN32K_SHARED_VADDR + SH_REQ_CLIENT_TEB) as *const u64);
    if teb != 0 {
        write_volatile((teb + 0x68) as *mut u32, error);
    }
}

fn user_handle_status_to_error(status: u32) -> u32 {
    match status {
        nt_win32k_job::STATUS_ACCESS_DENIED => 5,
        nt_win32k_job::STATUS_INSUFFICIENT_RESOURCES => 8,
        nt_win32k_job::STATUS_INVALID_HANDLE => 6,
        _ => 87,
    }
}

/// Complete the provider half of `NtUserUserHandleGrantAccess`. `job` is an exact Ps JobId, never
/// the caller's Object Manager handle. A nonzero `executive_error` means Ps rejected the handle or
/// caller before win32k state was touched.
unsafe fn dispatch_win32_job_user_handle(
    user_handle: u64,
    job: u64,
    grant: bool,
    executive_error: u32,
) -> u64 {
    if executive_error != 0 {
        set_current_client_last_error(executive_error);
        return 0;
    }
    let caller_process = current_w32process();
    let Some(resolved) = resolve_user_handle(user_handle) else {
        set_current_client_last_error(87);
        return 0;
    };
    let result = win32_job_ui_policy().grant_user_handle(
        job,
        caller_process,
        resolved.canonical,
        resolved.owner_process,
        grant,
    );
    match result {
        Ok(()) => {
            let flags = (resolved.entry_address + USER_HANDLE_ENTRY_FLAGS_OFF) as *mut u8;
            write_volatile(flags, read_volatile(flags) | USER_HANDLE_FLAG_GRANTED);
            1
        }
        Err(status) => {
            set_current_client_last_error(user_handle_status_to_error(status));
            0
        }
    }
}

unsafe fn dispatch_validate_user_handle_secure(user_handle: u64) -> u64 {
    let Some(resolved) = resolve_user_handle(user_handle) else {
        set_current_client_last_error(6);
        return 0;
    };
    u64::from(win32_job_ui_policy().user_handle_allowed(
        current_w32process(),
        resolved.canonical,
        resolved.owner_process,
    ))
}

#[derive(Clone, Copy)]
struct BroadcastTarget {
    hwnd: u64,
    desktop: u64,
}

#[repr(C)]
struct DoSendMessage {
    flags: u32,
    timeout: u32,
    result: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct BroadcastParm {
    flags: u32,
    recipients: u32,
    desktop: u64,
    window: u64,
    luid: u64,
}

unsafe fn current_process_has_handle_restriction() -> bool {
    let process = current_w32process();
    process != 0
        && win32_job_ui_policy().restrictions_for_process(process)
            & nt_win32k_job::JOB_OBJECT_UILIMIT_HANDLES
            != 0
}

unsafe fn current_request_argument(index: u64) -> Option<u64> {
    if !(4..WIN32K_MAX_SERVICE_ARGS).contains(&index) {
        return None;
    }
    let sh = WIN32K_SHARED_VADDR;
    let caller_sp = read_volatile((sh + SH_REQ_CALLER_SP) as *const u64);
    if caller_sp != 0 {
        let address = caller_sp.checked_add(0x28 + (index - 4) * 8)?;
        Some(read_volatile(address as *const u64))
    } else {
        let nargs = read_volatile((sh + SH_REQ_NARGS) as *const u64);
        if nargs <= index {
            None
        } else {
            Some(read_volatile(
                (sh + SH_REQ_A4 + (index - 4) * 8) as *const u64,
            ))
        }
    }
}

/// Call the registered seven-argument `NtUserMessageCall` handler with an explicit tail. This is
/// used only after a restricted broadcast has been expanded into its permitted real HWND targets.
unsafe fn dispatch_message_call_direct(
    hwnd: u64,
    message: u64,
    wparam: u64,
    lparam: u64,
    result_info: u64,
    fnid: u64,
    ansi: u64,
) -> u64 {
    let base = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_BASE) as *const u64);
    let count = read_volatile((WIN32K_SHARED_VADDR + SH_SSDT_COUNT) as *const u32) as u64;
    let index = SSN_NT_USER_MESSAGE_CALL - WIN32K_SERVICE_BASE;
    if base == 0
        || (count != 0 && index >= count)
        || registered_win32k_provider_argc(SSN_NT_USER_MESSAGE_CALL) != Some(7)
    {
        return 0;
    }
    let handler = read_volatile((base + index * 8) as *const u64);
    if handler == 0 {
        return 0;
    }
    let call: extern "win64" fn(u64, u64, u64, u64, u64, u64, u64) -> u64 =
        core::mem::transmute(handler as *const ());
    call(hwnd, message, wparam, lparam, result_info, fnid, ansi)
}

/// Snapshot the real top-level windows visible to a handle-restricted job. Explicit handle grants
/// do not widen broadcasts: the documented broadcast and hook rules are same-job only.
unsafe fn collect_job_broadcast_targets(
    all_desktops: bool,
    ignore_current_thread: bool,
) -> Result<Vec<BroadcastTarget>, u32> {
    let caller_process = current_w32process();
    let caller_thread = current_w32thread();
    let current_desktop = if all_desktops || caller_thread == 0 {
        0
    } else {
        let info = read_volatile((caller_thread + THREADINFO_PDESKINFO_OFF) as *const u64);
        if info == 0 {
            0
        } else {
            read_volatile((info + 0x10) as *const u64)
        }
    };

    let table = read_volatile((WIN32K_SHARED_VADDR + SH_SAS_AHELIST) as *const u64);
    if table == 0 {
        return Err(nt_win32k_job::STATUS_INSUFFICIENT_RESOURCES);
    }
    let entries = read_volatile(table as *const u64);
    let maximum = (LAST_USER_HANDLE - FIRST_USER_HANDLE + 1) >> 1;
    let count = (read_volatile((table + 0x10) as *const u32) as u64).min(maximum);
    if entries == 0 {
        return Err(nt_win32k_job::STATUS_INSUFFICIENT_RESOURCES);
    }

    let mut targets = Vec::new();
    for index in 0..count {
        let address = entries + index * USER_HANDLE_ENTRY_SIZE;
        if read_volatile((address + USER_HANDLE_ENTRY_TYPE_OFF) as *const u8) != 1 {
            continue;
        }
        let window = read_volatile(address as *const u64);
        let owner = read_volatile((address + USER_HANDLE_ENTRY_OWNER_OFF) as *const u64);
        if window == 0 || owner == 0 || (ignore_current_thread && owner == caller_thread) {
            continue;
        }
        let parent = read_volatile((window + WND_SPWND_PARENT_OFF) as *const u64);
        if parent == 0
            || read_volatile((parent + WND_FNID_OFF) as *const u32) != FNID_DESKTOP
            || (!all_desktops && parent != current_desktop)
        {
            continue;
        }
        let fnid = read_volatile((window + WND_FNID_OFF) as *const u32);
        if matches!(fnid, FNID_MENU | FNID_SWITCH) {
            continue;
        }
        let owner_process = read_volatile((owner + THREADINFO_PPI_OFF) as *const u64);
        if !win32_job_ui_policy().same_job_target_allowed(
            caller_process,
            (owner_process != 0).then_some(owner_process),
        ) {
            continue;
        }
        targets
            .try_reserve(1)
            .map_err(|_| nt_win32k_job::STATUS_INSUFFICIENT_RESOURCES)?;
        let generation = read_volatile((address + USER_HANDLE_ENTRY_GENERATION_OFF) as *const u16);
        targets.push(BroadcastTarget {
            hwnd: FIRST_USER_HANDLE + index * 2 + (u64::from(generation) << 16),
            desktop: read_volatile(parent as *const u64),
        });
    }
    Ok(targets)
}

unsafe fn dispatch_broadcast_system_message(
    message: u64,
    wparam: u64,
    lparam: u64,
    result_info: u64,
    ansi: u64,
) -> u64 {
    if !user_pointer_range_valid(result_info, core::mem::size_of::<BroadcastParm>() as u64) {
        set_current_client_last_error(998);
        return 0;
    }
    let parameters = read_unaligned(result_info as *const BroadcastParm);
    let flags = parameters.flags;
    let recipients = parameters.recipients;
    let all_desktops = recipients == 0 || recipients & BSM_ALLDESKTOPS != 0;
    if !all_desktops && recipients & BSM_APPLICATIONS == 0 {
        return 0;
    }
    let targets =
        match collect_job_broadcast_targets(all_desktops, flags & BSF_IGNORECURRENTTASK != 0) {
            Ok(targets) => targets,
            Err(status) => {
                set_current_client_last_error(user_handle_status_to_error(status));
                return 0;
            }
        };

    if flags & BSF_QUERY != 0 {
        write_unaligned((result_info + 8) as *mut u64, 0);
        write_unaligned((result_info + 16) as *mut u64, 0);
        let timeout_flags = if flags & (BSF_FORCEIFHUNG | BSF_NOHANG) != 0 {
            SMTO_ABORTIFHUNG
        } else if flags & BSF_NOTIMEOUTIFNOTHUNG != 0 {
            SMTO_NOTIMEOUTIFNOTHUNG
        } else {
            0
        };
        let mut accepted = true;
        for target in targets {
            let mut send = DoSendMessage {
                flags: timeout_flags,
                timeout: 2_000,
                result: 0,
            };
            let sent = dispatch_message_call_direct(
                target.hwnd,
                message,
                wparam,
                lparam,
                core::ptr::addr_of_mut!(send) as u64,
                FNID_SENDMESSAGEWTOOPTION,
                ansi,
            );
            if sent == 0 && flags & BSF_FORCEIFHUNG == 0 {
                accepted = false;
            }
            if send.result == BROADCAST_QUERY_DENY {
                write_unaligned((result_info + 8) as *mut u64, target.desktop);
                write_unaligned((result_info + 16) as *mut u64, target.hwnd);
                return 0;
            }
        }
        return u64::from(accepted);
    }

    for target in &targets {
        if flags & BSF_POSTMESSAGE != 0 {
            let _ = dispatch_ssn(
                SSN_NT_USER_POST_MESSAGE,
                target.hwnd,
                message,
                wparam,
                lparam,
            );
        } else {
            let _ = dispatch_message_call_direct(
                target.hwnd,
                message,
                wparam,
                lparam,
                0,
                FNID_SENDNOTIFYMESSAGE,
                ansi,
            );
        }
    }
    if flags & BSF_POSTMESSAGE == 0
        && wparam == 0
        && unicode_string_equals_ignore_ascii_case(lparam, b"Environment")
    {
        for target in targets {
            let _ = dispatch_message_call_direct(
                target.hwnd,
                message,
                wparam,
                lparam,
                0,
                FNID_SENDMESSAGE,
                ansi,
            );
        }
    }
    1
}

unsafe fn unicode_string_equals_ignore_ascii_case(address: u64, expected: &[u8]) -> bool {
    let Some(bytes) = expected
        .len()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(2))
    else {
        return false;
    };
    if !user_pointer_range_valid(address, bytes as u64) {
        return false;
    }
    for (index, expected) in expected.iter().enumerate() {
        let unit = read_volatile((address + index as u64 * 2) as *const u16);
        if unit > u8::MAX as u16
            || (unit as u8).to_ascii_lowercase() != expected.to_ascii_lowercase()
        {
            return false;
        }
    }
    read_volatile((address + expected.len() as u64 * 2) as *const u16) == 0
}

const fn user_pointer_range_valid(address: u64, bytes: u64) -> bool {
    const USER_PROBE_ADDRESS: u64 = 0x0000_7FFF_FFFF_0000;
    address != 0 && address < USER_PROBE_ADDRESS && bytes <= USER_PROBE_ADDRESS - address
}

const fn message_is_broadcastable(message: u64) -> bool {
    let message = message as u32;
    message < WM_USER || message >= REGISTERED_MESSAGE_FIRST
}

unsafe fn dispatch_job_scoped_broadcast(
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
) -> Option<u64> {
    if !current_process_has_handle_restriction() {
        return None;
    }

    if ssn == SSN_NT_USER_POST_MESSAGE && matches!(a0, HWND_BROADCAST | HWND_TOPMOST) {
        if !message_is_broadcastable(a1) {
            return Some(1);
        }
        let targets = match collect_job_broadcast_targets(false, false) {
            Ok(targets) => targets,
            Err(status) => {
                set_current_client_last_error(user_handle_status_to_error(status));
                return Some(0);
            }
        };
        for target in targets {
            let _ = dispatch_ssn(SSN_NT_USER_POST_MESSAGE, target.hwnd, a1, a2, a3);
        }
        return Some(1);
    }
    if ssn != SSN_NT_USER_MESSAGE_CALL {
        return None;
    }

    let result_info = current_request_argument(4)?;
    let fnid = current_request_argument(5)?;
    let ansi = current_request_argument(6)?;
    if fnid == FNID_BROADCASTSYSTEMMESSAGE {
        return Some(dispatch_broadcast_system_message(
            a1,
            a2,
            a3,
            result_info,
            ansi,
        ));
    }
    let broadcast_handle = a0 == HWND_BROADCAST
        || (a0 == HWND_TOPMOST
            && matches!(
                fnid,
                FNID_SENDMESSAGE | FNID_SENDMESSAGEFF | FNID_SENDMESSAGEWTOOPTION
            ));
    if !broadcast_handle
        || !matches!(
            fnid,
            FNID_SENDMESSAGE
                | FNID_SENDMESSAGEFF
                | FNID_SENDMESSAGEWTOOPTION
                | FNID_SENDNOTIFYMESSAGE
                | FNID_SENDMESSAGECALLBACK
        )
    {
        return None;
    }
    if !message_is_broadcastable(a1) {
        return Some(1);
    }
    let targets = match collect_job_broadcast_targets(false, false) {
        Ok(targets) => targets,
        Err(status) => {
            set_current_client_last_error(user_handle_status_to_error(status));
            return Some(0);
        }
    };
    let mut delivered = true;
    for target in targets {
        delivered &=
            dispatch_message_call_direct(target.hwnd, a1, a2, a3, result_info, fnid, ansi) != 0;
    }
    Some(u64::from(delivered))
}

unsafe fn enforce_job_user_handle_access(handle: u64) -> bool {
    let Some(resolved) = resolve_user_handle(handle) else {
        set_current_client_last_error(6);
        return false;
    };
    let allowed = win32_job_ui_policy().user_handle_allowed(
        current_w32process(),
        resolved.canonical,
        resolved.owner_process,
    );
    if !allowed {
        set_current_client_last_error(5);
    }
    allowed
}

unsafe fn enforce_job_handle_target_policy(ssn: u64, a0: u64, a2: u64) -> Option<u64> {
    if !current_process_has_handle_restriction() {
        return None;
    }
    if ssn == SSN_NT_USER_SET_WINDOWS_HOOK_EX {
        let target_process = if a2 == 0 {
            None
        } else {
            thread_context_index_for_tid(a2).and_then(|index| {
                let process_index = usize::try_from(thread_ctx_pi(index)).ok()?;
                let process = process_ctx_w32process(process_index);
                (process != 0).then_some(process)
            })
        };
        if !win32_job_ui_policy().same_job_target_allowed(current_w32process(), target_process) {
            set_current_client_last_error(5);
            return Some(0);
        }
        return None;
    }
    if ssn == SSN_NT_USER_SET_WIN_EVENT_HOOK {
        let target_pid = current_request_argument(5).unwrap_or(0);
        let target_tid = current_request_argument(6).unwrap_or(0);
        let target_from_pid = (target_pid != 0).then(|| {
            process_context_index_for_pid(target_pid)
                .map(|index| process_ctx_w32process(index))
                .filter(|process| *process != 0)
        });
        let target_from_tid = (target_tid != 0).then(|| {
            thread_context_index_for_tid(target_tid).and_then(|index| {
                let process_index = usize::try_from(thread_ctx_pi(index)).ok()?;
                let process = process_ctx_w32process(process_index);
                (process != 0).then_some(process)
            })
        });
        let policy = win32_job_ui_policy();
        let caller = current_w32process();
        let allowed = target_from_pid
            .into_iter()
            .chain(target_from_tid)
            .all(|target| policy.same_job_target_allowed(caller, target))
            && (target_pid != 0 || target_tid != 0);
        if !allowed {
            set_current_client_last_error(5);
            return Some(0);
        }
        return None;
    }

    let user_handle = match ssn {
        SSN_NT_USER_MESSAGE_CALL | SSN_NT_USER_POST_MESSAGE
            if a0 != 0 && !matches!(a0, HWND_BROADCAST | HWND_TOPMOST) =>
        {
            Some(a0)
        }
        SSN_NT_USER_UNHOOK_WINDOWS_HOOK_EX | SSN_NT_USER_UNHOOK_WIN_EVENT => Some(a0),
        _ => None,
    }?;
    (!enforce_job_user_handle_access(user_handle)).then_some(0)
}

unsafe fn dispatch_ssn_with_job_atom_namespace(
    process_index: usize,
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
) -> u64 {
    let process = process_ctx_w32process(process_index);
    let cell = (WIN32K_CODE_VA + G_ATOM_TABLE_RVA) as *mut u64;
    let previous = read_volatile(cell);
    let mut session = WIN32K_SESSION_ATOM_TABLE.load(Ordering::Acquire);
    if session == 0 && previous != 0 {
        let _ = WIN32K_SESSION_ATOM_TABLE.compare_exchange(
            0,
            previous,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        session = WIN32K_SESSION_ATOM_TABLE.load(Ordering::Acquire);
    }
    if session == 0 {
        return nt_win32k_job::STATUS_INSUFFICIENT_RESOURCES as u64;
    }

    let policy = win32_job_ui_policy();
    let restrictions = policy.restrictions_for_process(process);
    let selected = if restrictions & nt_win32k_job::JOB_OBJECT_UILIMIT_GLOBALATOMS != 0 {
        let Some(table) = policy.private_atom_table_for_process(process) else {
            return nt_win32k_job::STATUS_INSUFFICIENT_RESOURCES as u64;
        };
        table
    } else {
        session
    };
    write_volatile(cell, selected);
    let result = dispatch_ssn(ssn, a0, a1, a2, a3);
    write_volatile(cell, previous);
    result
}

/// Return the API-appropriate failure value when the current W32PROCESS is denied by its job.
unsafe fn enforce_win32_job_ui_policy(ssn: u64, a0: u64, a1: u64) -> Option<u64> {
    let operation = restricted_ui_operation(ssn, a0, a1)?;
    let process = current_w32process();
    if process == 0 || win32_job_ui_policy().operation_allowed(process, operation) {
        return None;
    }
    Some(match operation {
        nt_win32k_job::UiOperation::ChangeDisplaySettings => u32::MAX as u64,
        nt_win32k_job::UiOperation::ExitWindows => nt_win32k_job::STATUS_ACCESS_DENIED as u64,
        _ => 0,
    })
}

fn expected_gdi_return_type(ssn: u64) -> Option<u32> {
    match ssn {
        SSN_GDI_OPEN_DCW | SSN_GDI_CREATE_COMPATIBLE_DC => Some(GDI_OBJECT_TYPE_DC),
        SSN_GDI_CREATE_COMPATIBLE_BITMAP
        | SSN_GDI_CREATE_BITMAP
        | SSN_GDI_CREATE_DIB_SECTION
        | SSN_GDI_CREATE_DIBITMAP_INTERNAL => Some(GDI_OBJECT_TYPE_BITMAP),
        SSN_GDI_CREATE_PATTERN_BRUSH_INTERNAL => Some(GDI_OBJECT_TYPE_BRUSH),
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
    let user_data_required =
        expected_type == GDI_OBJECT_TYPE_DC || expected_type == GDI_OBJECT_TYPE_BRUSH;
    let user_data_ok = !user_data_required || user_data != 0;
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

    // Publish only the interactive Default desktop after Ob creation has already installed its real
    // parent window station and desktop heap. Service desktops remain scoped to their own window
    // station and must not inherit WinSta0 here.
    if ssn == SSN_NT_USER_CREATE_DESKTOP && ret != 0 {
        let hdesk = (ret as u32) as u64;
        let desk_body = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk);
        if desk_body != 0 && object_attributes_name_leaf_eq_ascii(a0, b"default") {
            let rpwinsta = read_volatile((desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *const u64);
            let input_winsta =
                read_volatile((WIN32K_CODE_VA + INPUT_WINDOW_STATION_RVA) as *const u64);
            if rpwinsta != 0 && rpwinsta == input_winsta {
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
            // Keep the real per-desktop heap handle that IntCreateDesktop installed. The class
            // call-proc path `UserGetCPD -> CreateCallProc -> DesktopHeapAlloc` allocates through
            // `RtlAllocateHeap(pdesk->pheapDesktop, ...)`; a missing or foreign handle means desktop
            // initialization did not complete and must not be patched over here.
            let pheap = read_volatile((rpdesk + DESKTOP_PHEAP_OFF) as *const u64);
            if pheap == 0 || hosted_heap_bounds(pheap).is_none() {
                return ret;
            }
            BOUND_DESK_BODY = rpdesk;
            BOUND_DESK_PDESKINFO = pdeskinfo;
            print_str(b"[win32k-host] NtUserSetThreadDesktop latched: pti->rpdesk=0x");
            print_hex((rpdesk >> 32) as u32);
            print_hex(rpdesk as u32);
            print_str(b" pti->pDeskInfo=0x");
            print_hex((pdeskinfo >> 32) as u32);
            print_hex(pdeskinfo as u32);
            print_str(b" pheapDesktop=0x");
            print_hex(pheap as u32);
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
    initialize_eprocess_body(eprocess, FAKE_PROCESS_HANDLE, 0);

    // No W32THREAD is valid yet. InitThreadCallback creates a process-owned Event handle, so the
    // permanent desktop thread is initialized only when the first real CSRSS generation attaches.
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
    let _ = bind_default_keyboard_layout_to_thread(w32thread);
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
            write_volatile(
                (mq + USER_MESSAGE_QUEUE_PTI_MOUSE_OFF) as *mut u64,
                w32thread,
            );
        }
        if read_volatile((mq + USER_MESSAGE_QUEUE_PTI_KEYBOARD_OFF) as *const u64) == 0 {
            write_volatile(
                (mq + USER_MESSAGE_QUEUE_PTI_KEYBOARD_OFF) as *mut u64,
                w32thread,
            );
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
        write_volatile(
            (w32thread + THREADINFO_PCTI_OFF) as *mut u64,
            w32thread + THREADINFO_EMBEDDED_CTI_OFF,
        );
    }
    // hEventQueueClient / pEventQueueServer: user32's MsgWaitForMultipleObjectsEx asks win32k for
    // this handle via NtUserxMsqSetWakeMask, and ReactOS signals the server KEVENT when queue bits
    // change. A hosted THREADINFO without these fields can still survive direct PeekMessage calls, but
    // it cannot participate in the real wait/wake path explorer uses while bringing up the desktop.
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
    if read_volatile((desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *const u64) == 0 {
        return false;
    }
    let pheap = read_volatile((desk_body + DESKTOP_PHEAP_OFF) as *const u64);
    if pheap == 0 || hosted_heap_bounds(pheap).is_none() {
        return false;
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
    // DesktopThreadMain is already represented by the permanent bootstrap THREADINFO. CSRSS's
    // current main thread shares its PROCESSINFO, so system-class registration is process-correct
    // without replacing gptiDesktopThread and making those classes mortal with the main thread.
    if !bind_desktop_thread_to_current_context(false, b"default-desktop") {
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
    //   (4) winsta->Flags (WINSTATION+0x20) WSS_LOCKED bit clear (zeroed body -> clear).
    // Ob desktop creation now owns (1); this bootstrap only publishes (2) before running the real
    // switch. On this first switch gpdeskInputDesktop is NULL so the hide-previous-desktop branch
    // (desktop.c:3031) is skipped; the switch's own trailing co_IntShowDesktop runs with bRedraw=FALSE
    // (no paint -- SM_CX/CYSCREEN are still 0 pre-InitVideo), then co_IntInitializeDesktopGraphics's
    // :340 co_IntShowDesktop(bRedraw=TRUE) does the real paint.
    let desk_body = (*core::ptr::addr_of!(OBJ_TABLE)).lookup_body(hdesk);
    let winsta_body = (*core::ptr::addr_of!(OBJ_TABLE)).cached_winsta_body();
    if desk_body != 0 && winsta_body != 0 {
        let parent = read_volatile((desk_body + DESKTOP_RPWINSTA_PARENT_OFF) as *const u64);
        if parent != winsta_body {
            print_str(b"[win32k-host] ERROR: Default desktop parent mismatch, switch skipped\n");
            return;
        }
        // The interactive InputWindowStation global = the same window station.
        write_volatile(
            (WIN32K_CODE_VA + INPUT_WINDOW_STATION_RVA) as *mut u64,
            winsta_body,
        );

        print_str(b"[win32k-host] NtUserSwitchDesktop(hDesk) [InputWindowStation set]\n");
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

        // Bind the permanent DesktopThreadMain context to the desktop.
        //
        // The switch above sets the GLOBAL `gpdeskInputDesktop`, but does NOT connect the CURRENT
        // thread's win32k `THREADINFO` (`pti`) to the desktop. In real Windows that connection is done
        // by winlogon's `SetThreadDesktop(Default) → NtUserSetThreadDesktop → IntSetThreadDesktop`
        // (desktop.c:3428/3430), whose core is exactly:
        //     pti->rpdesk    = pdesk;                    // desktop.c:3428
        //     pti->pDeskInfo = pti->rpdesk->pDeskInfo;   // desktop.c:3430
        //     pci->pDeskInfo = pti->pDeskInfo - ulClientDelta;   // desktop.c:3434
        // This bootstrap path runs before winlogon's own SetThreadDesktop. Keep the permanent
        // THREADINFO, PROCESSINFO.HeapMappings, and CLIENTINFO coherent with ReactOS' desktop-heap
        // mapping model while CSRSS's main/system thread remains unbound.
        let pti = read_volatile((WIN32K_CODE_VA + GPTI_DESKTOP_THREAD_RVA) as *const u64);
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
        let client_info = write_thread_client_desktop_info(pti, desk_body, desk_pdeskinfo);
        print_str(b"[win32k-host] IntSetThreadDesktop(Default): pti->rpdesk=0x");
        print_hex((desk_body >> 32) as u32);
        print_hex(desk_body as u32);
        print_str(b" pti->pDeskInfo=0x");
        print_hex((desk_pdeskinfo >> 32) as u32);
        print_hex(desk_pdeskinfo as u32);
        if let Some((client_deskinfo, delta, client_pcti)) = client_info {
            print_str(b" client-pDeskInfo=0x");
            print_hex((client_deskinfo >> 32) as u32);
            print_hex(client_deskinfo as u32);
            print_str(b" ulClientDelta=0x");
            print_hex((delta >> 32) as u32);
            print_hex(delta as u32);
            print_str(b" client-pcti=0x");
            print_hex((client_pcti >> 32) as u32);
            print_hex(client_pcti as u32);
        }
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

/// Give the EPROCESS placeholder the fields win32k's process callout asserts and invoke win32k's
/// process-create callout (WIN32_CALLOUTS[0]) to build the W32PROCESS authentically. A user thread
/// and its handle table do not exist until the genuine CSRSS attach.
unsafe fn establish_bootstrap_process_context() {
    let Some((process_index, _thread_index)) = ensure_bootstrap_win32k_context() else {
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
    initialize_eprocess_body(eprocess, FAKE_PROCESS_HANDLE, 0);

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
            set_process_ctx_w32process(process_index, w32);
        }
        print_hex((w32 >> 32) as u32);
        print_hex(w32 as u32);
        print_str(b"\n");
    }
    if read_volatile(SLOT_W32PROCESS as *const u64) == 0 {
        print_str(b"[win32k-host] ERROR: bootstrap process callout did not publish W32PROCESS\n");
        return;
    }
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
/// The complete display PCI BAR mapped into win32k's VSpace, RW. The executive video-device
/// boundary returns an offset in this aperture for `IOCTL_VIDEO_MAP_VIDEO_MEMORY`; the bootloader
/// framebuffer fields describe the initial scanout geometry only.
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
    ) && crate::video_device::hosted_video_device_route_ready()
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
                    let (addr, direct) = if import_name_eq(import_name, b"EngDeviceIoControl") {
                        (s_eng_device_io_control as usize as u64, true)
                    } else if is_dxgthk {
                        if dxgthk_base == 0 {
                            log_unresolved_gdi_driver_import(import_name);
                            return None;
                        }
                        let addr = pe_export_lookup(dxgthk_base, import_name);
                        if addr == 0 {
                            log_unresolved_gdi_driver_import(import_name);
                            return None;
                        }
                        (addr, false)
                    } else if is_win32k {
                        let addr = pe_export_lookup(WIN32K_CODE_VA, import_name);
                        if addr == 0 {
                            log_unresolved_gdi_driver_import(import_name);
                            return None;
                        }
                        (addr, false)
                    } else {
                        let name = core::str::from_utf8_unchecked(import_name);
                        (export_addr(name), false)
                    };
                    trace_gdi_driver_import(import_name, slots + k * 8, addr, direct);
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
