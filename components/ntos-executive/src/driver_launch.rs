//! `driver_launch` — the GENERAL DYNAMIC driver-launch path (the NT `IoLoadDriver`/`NtLoadDriver`
//! / SCM driver-start model). Take a driver name/path → load the `.sys` by-path from the FS →
//! determine its POLICY CLASS → build a [`ComponentDescriptor`] → `spawn_component` it ISOLATED →
//! run its real `DriverEntry` in the component (capturing its MajorFunction table + device object).
//!
//! This GENERALIZES the bespoke boot-time spawners (`spawn_driver_host` NIC, `spawn_storage_host`,
//! `spawn_kmdf_host`, `spawn_win32k_host`) into ONE runtime service — like Win32 `CreateProcess` /
//! the general `NtCreateThread`. Any registry-declared `.sys` in a supported policy class becomes
//! launchable dynamically.
//!
//! POLICY CLASSES (see `project_driver_model.md`):
//!   * [`DriverClass::Fsd`]    — file-system drivers (npfs, fastfat, ntfs): image + heap/pool + stack
//!     + IPC-buf + fault EP + a shared handoff page; NO device caps.
//!   * [`DriverClass::Device`] — hardware drivers (NIC/AHCI/GPU): PnP selects devnodes/resources,
//!     then the executive grants the hosted driver exactly those MMIO/interrupt/DMA authorities.
//!   * [`DriverClass::Filter`]  — FS/bus filter drivers: the SAME IRP substrate + caps as `Fsd`.
//!   * [`DriverClass::GuiSyscallServer`] — win32k: a unique privileged class (kept bespoke — its
//!     Syscall substrate + paint-loop protocol are NOT routed through the IRP builder here).
//!
//! The existing bespoke spawners are follow-on migrations onto this path (their descriptor-builders
//! already exist post effort-1); the named-pipe provider remains the deepest FSD data-plane proof.

use core::mem::MaybeUninit;
use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use nt_compat_exports::DriverExportRegistry;
use nt_dma_manager::{DmaError, DmaManager as HostedDmaManager, DmaOwner};
use nt_kernel_exec::{kevent, EventKind};
use nt_io_abi::major;
use nt_io_manager::{
    write_wdm_file_object, write_wdm_io_stack_location, write_wdm_irp, CreateOptions,
    DeviceCharacteristics, DeviceControlParameters, DeviceFlags, DeviceType, DispatchContext,
    DispatchOutcome, DispatchTarget, DriverBackendId, DriverDispatchBackend, DriverId,
    DriverPeerId, FileId, InformationParameters, IoManager, IoParameters, IrpId, IrpProjection,
    MajorFunctionTable, ObjectManagerPort, ReadWriteParameters, ShareAccess, WdmFileObjectInit,
    WdmIoStackLocationInit, WdmIoStackParameters, WdmIrpInit, WDM_X64_DRIVER_EXTENSION_OFFSET,
    WDM_X64_DRIVER_EXTENSION_SIZE, WDM_X64_DRIVER_MAJOR_FUNCTION_OFFSET,
    WDM_X64_DRIVER_OBJECT_SIZE, WDM_X64_DRIVER_UNLOAD_OFFSET, WDM_X64_FILE_OBJECT_SIZE,
    WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IO_TYPE_FILE, WDM_X64_IRP_SIZE,
};
use nt_mdl::MdlRegistry;
use nt_resource_manager::{HalError, ResourceManager, ResourceOwner};
use nt_types::{AccessMask, ClientId, HandleValue};
use nt_types::{NtPath, ObjectId};

// Pure, driver-agnostic ntoskrnl byte primitives shared with the Subsystem (win32k) class.
use crate::ntoskrnl_shared::{s_memcpy, s_memset, s_rtl_compare_memory};

use crate::*;

// =============================================================================================
// The generic FSD-class component surface (formerly `npfs_host.rs`).
//
// A hosted file-system driver (npfs today; fastfat/ntfs next) runs as an ISOLATED component in
// its OWN VSpace/CNode/TCB (an FSD-class descriptor, NO device caps). The trampolines + entry +
// IRP dispatch loop below are GENERIC to any FSD — they are NOT npfs-specific machinery:
//   * the ntoskrnl-import TRAMPOLINES are the SHARED ntoskrnl surface an FSD links against. The
//     executive registers each trampoline VA by import name into a [`DriverExportRegistry`]
//     (`nt-compat-exports`, the same mechanism win32k uses); the loader resolves the driver's IAT
//     through it ([`fsd_export_addr`]). The pure prefix-match logic is `nt_kernel_exec::np_prefix`.
//   * the COMPONENT ENTRY ([`fsd_component_entry`]) runs the driver's real DriverEntry, captures the
//     DriverObject->MajorFunction[] table + control device, then serves file IRPs in a dispatch loop.
//
// These impls become reusable for the next FSD (fastfat) unchanged — the point of the convergence.
// The VA-layout / shared-page-offset / verdict consts below are generic FSD-hosting facts (were
// `npfs_host::*`; retained here as the one home for the FSD hosting contract).
// =============================================================================================

// --- component VA layout (identical in the executive-load view + the host-run view) ----------

/// The relocated/loaded FSD image (VIRTUAL layout). npfs.sys is ~62 KiB → SizeOfImage ~0x14000
/// (20 frames); reserve a generous 64-frame (256 KiB) window in its own 2 MiB PT, well clear of
/// win32k's windows (which start at 0x0680_0000).
pub const FSD_CODE_VA: u64 = 0x0000_0100_0E00_0000;
/// FSD image frame budget (SizeOfImage / 0x1000, capped). 64 frames = 256 KiB.
pub const FSD_IMAGE_FRAMES: u64 = 64;

/// The FSD pool arena the `ExAllocatePool*` trampolines bump-allocate from (counter @+0, data @
/// +0x1000). An FSD's DriverEntry + pipe/file-object allocation is modest; 4 MiB in its own 2-PT window.
pub const FSD_POOL_VADDR: u64 = 0x0000_0100_0E80_0000;
pub const FSD_POOL_FRAMES: u64 = 1024; // 4 MiB, pre-mapped

/// The component's own stack (32 frames = 128 KiB, own PT). An FSD's dispatch call chains
/// (NpFsdCreate → Np*) are moderately deep.
pub const FSD_STACK_VADDR: u64 = 0x0000_0100_0F00_0000;
pub const FSD_STACK_FRAMES: u64 = 32;

/// Aux PT window holding the DATA + SHARED + ARG frames (one 2 MiB PT).
pub const FSD_AUX_PT_VADDR: u64 = 0x0000_0100_0F20_0000;
/// DATA export/placeholder region: page 0 = misc placeholders, page 1 = KPCR placeholder (GS). 4 frames.
pub const FSD_DATA_VADDR: u64 = 0x0000_0100_0F30_0000;
pub const FSD_DATA_FRAMES: u64 = 4;
/// The component's GS base — a zeroed KPCR placeholder (an FSD, a kernel driver, may read `gs:[..]`).
pub const FSD_KPCR_VA: u64 = FSD_DATA_VADDR + 0x1000;

/// Shared handoff page (executive ↔ host): entry rva in, verdict + MajorFunction table + device
/// object out, then the IRP request/reply fields.
pub const FSD_SHARED_VADDR: u64 = 0x0000_0100_0F38_0000;

/// The cross-AS ARG-MARSHAL frame(s): mapped RW in BOTH the executive and the FSD component. The
/// executive copies an IRP's system-buffer here; the FSD's MajorFunction handler reads/writes it in
/// its own context; the executive copies out-params back to the caller on reply. 4 pages = 16 KiB.
pub const FSD_ARG_VADDR: u64 = 0x0000_0100_0F3A_0000;
pub const FSD_ARG_FRAMES: u64 = 4;

// --- PER-INSTANCE executive-side load/comm VAs (multi-driver de-singleton) --------------------
//
// The COMPONENT-side VAs above (`FSD_CODE_VA`, `FSD_POOL_VADDR`, … `FSD_ARG_VADDR`) are FIXED: every
// launched FSD component runs in its OWN isolated VSpace and reuses the same VAs there (the component
// entry / pool / dispatch loop all reference these fixed values). What MUST differ per instance is the
// EXECUTIVE-side mapping window — the executive maps every live instance's aliased CODE/DATA/SHARED/
// ARG frames into its OWN VSpace to (a) load+relocate the PE and (b) marshal IRPs — so two instances
// cannot both map at `FSD_CODE_VA`. Instance 0 keeps the fixed FSD VAs EXACTLY (byte-identical);
// instance N≥1 gets a distinct executive window at `FSD_EXEC_BASE + (N-1)*FSD_EXEC_STRIDE`, well clear
// of every other executive mapping (past the 48 MiB file pool at 0x100_1500_0000..0x100_1800_0000).
//
// The PE is RELOCATED for its EXECUTION VA (`FSD_CODE_VA`, same across instances) via `load_pe_into`'s
// `run_va` — decoupled from the executive load VA — so instance N runs correctly at `FSD_CODE_VA` in
// its own VSpace while the executive loaded its bytes at a distinct window.
pub const FSD_EXEC_BASE: u64 = 0x0000_0100_1A00_0000;
pub const FSD_EXEC_STRIDE: u64 = 0x0000_0000_0100_0000; // 16 MiB per instance window

/// The executive-side VA window for launching an instance's frames. Instance 0 == the fixed
/// historical FSD VAs (behavior-preserving); instance N≥1 == a distinct high window.
#[derive(Clone, Copy)]
pub(crate) struct ExecVaWindow {
    pub code_va: u64,
    pub data_va: u64,
    pub shared_va: u64,
    pub arg_va: u64,
    pub aux_pt_va: u64,
}

impl ExecVaWindow {
    pub fn for_instance(instance: usize) -> ExecVaWindow {
        if instance == 0 {
            ExecVaWindow {
                code_va: FSD_CODE_VA,
                data_va: FSD_DATA_VADDR,
                shared_va: FSD_SHARED_VADDR,
                arg_va: FSD_ARG_VADDR,
                aux_pt_va: FSD_AUX_PT_VADDR,
            }
        } else {
            let base = FSD_EXEC_BASE + (instance as u64 - 1) * FSD_EXEC_STRIDE;
            // Same RELATIVE offsets as the fixed layout: aux PT (2 MiB) holds DATA/SHARED/ARG.
            ExecVaWindow {
                code_va: base,                 // 256 KiB image window (fits in the first 2 MiB PT)
                data_va: base + 0x0030_0000,   // DATA (4 frames)
                shared_va: base + 0x0038_0000, // SHARED (1 frame)
                arg_va: base + 0x003A_0000,    // ARG (4 frames)
                aux_pt_va: base + 0x0020_0000, // aux PT covering the 2 MiB region holding DATA/SHARED/ARG
            }
        }
    }
}

// --- shared-page offsets ---------------------------------------------------------------------

pub const SH_ENTRY_RVA: u64 = 0x00; // in:  DriverEntry RVA (u64)
pub const SH_VERDICT: u64 = 0x08; // out: verdict bitmask (u32)
pub const SH_DE_STATUS: u64 = 0x10; // out: DriverEntry NTSTATUS (i32)
pub const SH_MJ_TABLE: u64 = 0x18; // out: recorded DriverObject->MajorFunction[] base VA (u64)
pub const SH_DEVOBJ: u64 = 0x20; // out: the control DEVICE_OBJECT VA (u64)
pub const SH_POOL_USED: u64 = 0x28; // out: pool high-water (u64)
pub const SH_DRVOBJ: u64 = 0x30; // out: the component-local DRIVER_OBJECT VA (u64)
pub const SH_DRIVER_UNLOAD: u64 = 0x38; // out: DriverObject->DriverUnload after DriverEntry (u64)
pub const SH_DEVICE_NAME_LEN: u64 = 0x80; // out: IoCreateDevice DeviceName bytes (u16)
pub const SH_SYMLINK_LINK_LEN: u64 = 0x82; // out: IoCreateSymbolicLink LinkName bytes (u16)
pub const SH_SYMLINK_TARGET_LEN: u64 = 0x84; // out: IoCreateSymbolicLink DeviceName bytes (u16)
pub const SH_ADD_DEVICE: u64 = 0x88; // out: DriverExtension->AddDevice after DriverEntry (u64)
pub const SH_DEVICE_NAME_BUF: u64 = 0x90; // out: UTF-16LE path capture
pub const SH_SYMLINK_LINK_BUF: u64 = 0x190; // out: UTF-16LE path capture
pub const SH_SYMLINK_TARGET_BUF: u64 = 0x290; // out: UTF-16LE path capture
pub const SH_CAPTURED_PATH_BYTES: usize = 0x100;
pub const SH_RESOURCE_MMIO_PHYS: u64 = 0x3A0; // in: granted physical BAR base for MmMapIoSpace
pub const SH_RESOURCE_MMIO_LEN: u64 = 0x3A8; // in: granted mapped BAR length
pub const SH_RESOURCE_MMIO_VA: u64 = 0x3B0; // in: component VA for the mapped BAR
pub const SH_RESOURCE_INTERRUPT_VECTOR: u64 = 0x3B8; // in: granted interrupt vector/level (u32)
pub const SH_RESOURCE_INTERRUPT_AFFINITY: u64 = 0x3C0; // in: granted interrupt affinity
pub const SH_RESOURCE_MMIO_MAPPED_PHYS: u64 = 0x3C8; // out: last MmMapIoSpace phys
pub const SH_RESOURCE_MMIO_MAPPED_LEN: u64 = 0x3D0; // out: last MmMapIoSpace length
pub const SH_RESOURCE_INTERRUPT_OBJECT: u64 = 0x3D8; // out: PKINTERRUPT projection
pub const SH_RESOURCE_INTERRUPT_ROUTINE: u64 = 0x3E0; // out: connected ISR routine
pub const SH_RESOURCE_INTERRUPT_CONTEXT: u64 = 0x3E8; // out: connected ISR context
pub const SH_ROOT_PDO_FORWARDED_MINOR: u64 = 0x3F0; // out: lower PDO PnP minor forwarded
pub const SH_ROOT_PDO_FORWARDED_STATUS: u64 = 0x3F8; // out: lower PDO completion status
pub const SH_DMA_COMMON_VA: u64 = 0x400; // in: component VA for the granted common buffer
pub const SH_DMA_COMMON_LEN: u64 = 0x408; // in: granted common-buffer length
pub const SH_DMA_COMMON_LOGICAL: u64 = 0x410; // in: granted device logical address / IOVA
pub const SH_DMA_ADAPTER_ID: u64 = 0x418; // in: canonical nt-dma-manager adapter id
pub const SH_DMA_ADAPTER_BLOB: u64 = 0x420; // out: driver-visible DMA_ADAPTER projection
pub const SH_DMA_OPS_BLOB: u64 = 0x428; // out: driver-visible DMA_OPERATIONS projection
pub const SH_DMA_REQUESTED_LEN: u64 = 0x430; // out: AllocateCommonBuffer requested length
pub const SH_DMA_ALLOCATED_VA: u64 = 0x438; // out: AllocateCommonBuffer CPU VA
pub const SH_DMA_ALLOCATED_LOGICAL: u64 = 0x440; // out: AllocateCommonBuffer logical address
pub const SH_DMA_FREED_LOGICAL: u64 = 0x448; // out: last FreeCommonBuffer logical address
pub const SH_RESOURCE_INTERRUPT_ID: u64 = 0x450; // out: canonical nt-resource-manager interrupt id
pub const SH_RESOURCE_INTERRUPT_DELIVERED_VECTOR: u64 = 0x458; // out: last delivered vector
pub const SH_RESOURCE_INTERRUPT_ISR_CLAIMED: u64 = 0x460; // out: last ISR BOOLEAN result
pub const SH_RESOURCE_INTERRUPT_DELIVERIES: u64 = 0x468; // out: ISR delivery count
pub const SH_DPC_QUEUE_HEAD: u64 = 0x470; // out: bounded KDPC queue consumer index
pub const SH_DPC_QUEUE_TAIL: u64 = 0x478; // out: bounded KDPC queue producer index
pub const SH_DPC_QUEUE_DROPS: u64 = 0x480; // out: failed inserts due to full queue
pub const SH_DPC_DELIVERIES: u64 = 0x488; // out: deferred routines called
pub const SH_DPC_QUEUE_BASE: u64 = 0x490; // out: queued KDPC pointers
pub const SH_DPC_QUEUE_SLOTS: u64 = 4;

// IRP dispatch request/reply (executive → FSD, via the shared page).
pub const SH_REQ_MAJOR: u64 = 0x40; // in:  IRP_MJ_* major function (u64)
pub const SH_REQ_MINOR: u64 = 0x48; // in:  minor function (u64)
pub const SH_REQ_FSCTL: u64 = 0x50; // in:  control code or FILE_INFORMATION_CLASS (u64)
pub const SH_REQ_INLEN: u64 = 0x58; // in:  input buffer length (u64)
pub const SH_REQ_OUTLEN: u64 = 0x60; // in:  output buffer length (u64)
pub const SH_REQ_FILEID: u64 = 0x68; // in/out: opaque FILE_OBJECT id (u64)
pub const SH_REQ_STATUS: u64 = 0x70; // out: IoStatus.Status (i32)
pub const SH_REQ_INFO: u64 = 0x78; // out: IoStatus.Information (u64)

const WDM_X64_DRIVER_EXTENSION_ADD_DEVICE_OFFSET: u64 = 0x08;

// --- verdict bits ----------------------------------------------------------------------------

pub const V_ENTERED: u32 = 1; // host called into DriverEntry
pub const V_RETURNED: u32 = 2; // DriverEntry returned (did not fault)
pub const V_SUCCESS: u32 = 4; // DriverEntry returned STATUS_SUCCESS
pub const V_DEVICE: u32 = 8; // IoCreateDevice(control device) succeeded
pub const V_MJ: u32 = 0x10; // DriverObject->MajorFunction[IRP_MJ_CREATE] is non-null (table filled)
pub const V_REGFS: u32 = 0x20; // IoRegisterFileSystem was called
pub const V_NAMED_DEVICE: u32 = 0x40; // IoCreateDevice declared a valid NT DeviceName
pub const V_SYMLINK: u32 = 0x80; // IoCreateSymbolicLink declared a valid link/target

/// The IPC message label the dispatch loop uses to Send its ready/done signal on the fault EP.
/// Distinct from the small fault labels (VMFault=6, …), so the executive tells them apart.
pub const FSD_DISPATCH_LABEL: u64 = 0x771;
pub const FSD_DISPATCH_UNLOAD: u64 = u64::MAX - 0x771;
pub const FSD_DISPATCH_ADD_DEVICE: u64 = u64::MAX - 0x772;
pub const FSD_DISPATCH_INTERRUPT: u64 = u64::MAX - 0x773;

const POOL_DATA_OFF: u64 = 0x1000;
const STATUS_PENDING: u32 = 0x0000_0103;

const IRP_MJ_READ: u64 = major::IRP_MJ_READ as u64;
const IRP_MJ_WRITE: u64 = major::IRP_MJ_WRITE as u64;
const IRP_MJ_SET_INFORMATION: u64 = major::IRP_MJ_SET_INFORMATION as u64;
const IRP_MJ_PNP: u64 = major::IRP_MJ_PNP as u64;
const IRP_MN_START_DEVICE: u64 = 0x00;
/// `IRP_MJ_CLOSE` / `IRP_MJ_CLEANUP` — the requests that END an open (and therefore the ONLY
/// requests that may destroy its FILE_OBJECT). See [`FILE_OBJECTS`].
const IRP_MJ_CLOSE: u64 = 0x02;
const IRP_MJ_CLEANUP: u64 = 0x12;

#[derive(Clone, Copy)]
struct PendingIrp {
    irp: u64,
    iosl: u64,
    file_object: u64,
    data: u64,
    major: u8,
    /// The npfs `FsContext` (opaque file id) this IRP was issued on, captured at ISSUE time.
    /// ★ Must NOT be re-read from `FILE_OBJECT->FsContext` at completion time: npfs NULLs that
    /// field through `NpSetFileObject(fo, NULL, NULL, …)` when a pipe end disconnects
    /// (`statesup.c:163/289/…`), so a completion racing a disconnect would key the delivered
    /// bytes under fid 0 and the parked reader would never be woken.
    fid: u64,
    /// Whether THIS IRP owns the FILE_OBJECT block (a transient one, not the per-open object in
    /// [`FILE_OBJECTS`]). Only a transient FILE_OBJECT may be freed on completion — see
    /// [`fo_for_open`].
    owns_fo: bool,
}

const PENDING_IRP_CAP: usize = 32;
const EMPTY_PENDING_IRP: PendingIrp = PendingIrp {
    irp: 0,
    iosl: 0,
    file_object: 0,
    data: 0,
    major: 0,
    fid: 0,
    owns_fo: false,
};
static mut PENDING_IRPS: [PendingIrp; PENDING_IRP_CAP] = [EMPTY_PENDING_IRP; PENDING_IRP_CAP];
static mut DATA_TRACE_COUNT: u32 = 0;
/// Bounded ENTER/EXIT trace of IRP dispatches (see [`dispatch_irp`]).
static mut FSD_DISPATCH_TRACE: u32 = 0;
/// Diagnostic heartbeat counters for the two unbounded-loop-capable driver callbacks.
static mut IO_COMPLETE_CALLS: u64 = 0;
static mut POOL_CALLS: u64 = 0;
static mut POOL_LONG_WALKS: u32 = 0;
static mut PEER_COMPLETION_TRACE_COUNT: u32 = 0;

// BATCH 37 — completed-pending-READ stash. When a pipe READ goes STATUS_PENDING, npfs retains the
// read IRP in its inbound queue (QueueState=ReadEntries) and the EXECUTIVE parks the caller. The
// peer's later WRITE is serviced by npfs's OWN NpWriteDataQueue fast path, which copies the write
// payload DIRECTLY into that pending read IRP's buffer and completes it via IoCompleteRequest —
// synchronously, during the write call. So by the time control returns to the executive the read data
// is IN the freed read IRP and the inbound queue is drained; a FRESH re-drive read would find nothing
// (or stale bytes). Capture the completed read's bytes here, keyed by the reader's fid, so the
// executive's pipe re-drive delivers THESE bytes to the parked reader instead of re-reading. The read
// result buffer npfs fills for a pending read is the IRP's user buffer (== our `data`, METHOD_NEITHER).
const COMPLETED_READ_CAP: usize = PENDING_IRP_CAP;
const COMPLETED_READ_BYTE_CAP: usize = (FSD_ARG_FRAMES as usize) * 0x1000;
#[derive(Clone, Copy)]
struct CompletedRead {
    fid: u64,
    status: u32,
    info: u64,
    length: usize,
    bytes: [u8; COMPLETED_READ_BYTE_CAP],
}
static mut COMPLETED_READS: [CompletedRead; COMPLETED_READ_CAP] = [CompletedRead {
    fid: 0,
    status: 0,
    info: 0,
    length: 0,
    bytes: [0; COMPLETED_READ_BYTE_CAP],
}; COMPLETED_READ_CAP];

#[derive(Clone, Copy)]
struct CompletedWrite {
    fid: u64,
    status: u32,
    info: u64,
}

static mut COMPLETED_WRITES: [CompletedWrite; COMPLETED_READ_CAP] = [CompletedWrite {
    fid: 0,
    status: 0,
    info: 0,
}; COMPLETED_READ_CAP];

/// Take (consume) a stashed completed-pending-read for `fid`, if any. Returns `(status, info, bytes)`.
pub(crate) unsafe fn take_completed_read(fid: u64) -> Option<(u32, u64, alloc::vec::Vec<u8>)> {
    let table = &mut *core::ptr::addr_of_mut!(COMPLETED_READS);
    let slot = table.iter_mut().find(|e| e.fid == fid && e.fid != 0)?;
    let bytes = alloc::vec::Vec::from(&slot.bytes[..slot.length]);
    let out = (slot.status, slot.info, bytes);
    slot.fid = 0;
    slot.length = 0;
    Some(out)
}

pub(crate) unsafe fn take_completed_write(fid: u64) -> Option<(u32, u64)> {
    let table = &mut *core::ptr::addr_of_mut!(COMPLETED_WRITES);
    let slot = table
        .iter_mut()
        .find(|entry| entry.fid == fid && entry.fid != 0)?;
    let result = (slot.status, slot.info);
    slot.fid = 0;
    Some(result)
}

// --- host-side pool allocator (the trampolines run in the component) --------------------------

/// Hard bound on a free-list traversal. The pool is 4 MiB with a 16-byte header, so a well-formed
/// list can never be longer than this; anything past it means the list is CORRUPT (a cycle), and a
/// cycle must degrade to the bump path rather than spin the whole executive.
const POOL_FREE_LIST_MAX: u64 = (FSD_POOL_FRAMES * 0x1000) / 16;
/// Double `pool_free` calls the guard below rejected, and free-list cycles `pool_alloc` broke out of.
/// Both are counter-backed so a regression is a gate failure rather than a silent 555-second hang.
pub(crate) static FSD_POOL_DOUBLE_FREES: AtomicU64 = AtomicU64::new(0);
pub(crate) static FSD_POOL_LIST_CYCLES: AtomicU64 = AtomicU64::new(0);

/// A simple free-list allocator: an FSD alloc/frees file objects; a leak-forever bump would exhaust
/// under FSCTL churn. Header = 16 B ([+0]=capacity, [+8]=next-free). `pool_free` pushes onto the
/// single free list (head @ [POOL+8]); `pool_alloc` first-fits it before bumping. Counter @ [POOL+0].
///
/// ★ The first-fit walk is CYCLE-BOUNDED. A block pushed onto the free list twice has
/// `next == itself`, so the unbounded walk below used to loop forever *inside the executive* — no
/// fault, no log line, every hosted thread frozen, the boot simply stopping. That is exactly what
/// happened once lsass' `\pipe\lsarpc` self-RPC put TWO concurrent IRPs on the SAME npfs
/// FILE_OBJECT (the per-connection worker's pending read plus the thread-pool worker's response
/// write): `s_io_complete_request` frees `slot.file_object` per completion, so the second completion
/// double-freed it. `pool_free` now refuses the double free (the real fix); this bound is the
/// belt-and-braces so a corrupt list can never again hang the system.
pub(crate) unsafe fn pool_alloc(size: u64) -> u64 {
    POOL_CALLS += 1;
    if POOL_CALLS % 16384 == 0 {
        print_str(b"[fsd-pool-heartbeat] calls=");
        print_u64(POOL_CALLS);
        print_str(b" size=");
        print_u64(size);
        print_str(b"\n");
    }
    // first-fit the free list
    let head_slot = (FSD_POOL_VADDR + 8) as *mut u64;
    let mut prev = head_slot;
    let mut cur = read_volatile(head_slot);
    let mut steps = 0u64;
    while cur != 0 {
        if steps >= POOL_FREE_LIST_MAX {
            if FSD_POOL_LIST_CYCLES.fetch_add(1, Ordering::Relaxed) == 0 {
                print_str(b"[fsd-host] POOL FREE-LIST CYCLE -> bump path\n");
            }
            break;
        }
        steps += 1;
        let cap = read_volatile((cur - 16) as *const u64);
        if cap >= size {
            let next = read_volatile((cur - 8) as *const u64);
            write_volatile(prev, next);
            return cur;
        }
        prev = (cur - 8) as *mut u64;
        cur = read_volatile((cur - 8) as *const u64);
    }
    // bump
    let ctr = FSD_POOL_VADDR as *mut u64;
    let mut off = read_volatile(ctr);
    if off < POOL_DATA_OFF {
        off = POOL_DATA_OFF;
    }
    // 16-byte header + 16-align the returned block
    let hdr = (FSD_POOL_VADDR + off + 15) & !15;
    let block = hdr + 16;
    let cap = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
    if size == 0 || block + size > cap {
        print_str(b"[fsd-host] POOL EXHAUSTED size=0x");
        print_hex(size as u32);
        print_str(b"\n");
        return 0;
    }
    write_volatile(ctr, (block + size) - FSD_POOL_VADDR);
    write_volatile((block - 16) as *mut u64, size); // capacity header
    write_volatile((block - 8) as *mut u64, 0);
    block
}

/// Push `p` back onto the single free list — **idempotently**.
///
/// ★ DOUBLE-FREE GUARD (the real fix for the LSA-self-RPC hang). Pushing a block that is ALREADY on
/// the list sets its `next` pointer to itself, and the allocator's first-fit walk then never
/// terminates. `s_io_complete_request` frees `slot.file_object` on EVERY IRP completion, so as soon
/// as two IRPs are outstanding on the same FILE_OBJECT — which is the normal rpcrt4 server shape:
/// `RPCRT4_io_thread` keeps a read pending on the connection while `RPCRT4_worker_thread` writes the
/// response on it — the second completion double-freed it. A real allocator must reject that rather
/// than corrupt its own list, so scan (bounded) and drop the redundant push.
unsafe fn pool_free(p: u64) {
    POOL_CALLS += 1;
    if POOL_CALLS % 16384 == 0 {
        print_str(b"[fsd-pool-heartbeat] calls=");
        print_u64(POOL_CALLS);
        print_str(b" free p=");
        print_hex(p as u32);
        print_str(b"\n");
    }
    if p < FSD_POOL_VADDR + POOL_DATA_OFF || p >= FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000 {
        return;
    }
    let head_slot = (FSD_POOL_VADDR + 8) as *mut u64;
    let mut cur = read_volatile(head_slot);
    let mut steps = 0u64;
    while cur != 0 && steps < POOL_FREE_LIST_MAX {
        if steps == 4096 && POOL_LONG_WALKS < 8 {
            POOL_LONG_WALKS += 1;
            print_str(b"[fsd-pool] LONG free-list walk p=");
            print_hex(p as u32);
            print_str(b" cur=");
            print_hex(cur as u32);
            print_str(b"\n");
        }
        if cur == p {
            if FSD_POOL_DOUBLE_FREES.fetch_add(1, Ordering::Relaxed) == 0 {
                print_str(b"[fsd-host] rejected DOUBLE pool_free p=0x");
                print_hex(p as u32);
                print_str(b" (would cycle the free list)\n");
            }
            return;
        }
        cur = read_volatile((cur - 8) as *const u64);
        steps += 1;
    }
    if cur != 0 {
        // Already corrupt (a cycle from before this guard existed) — do not extend it.
        if FSD_POOL_LIST_CYCLES.fetch_add(1, Ordering::Relaxed) == 0 {
            print_str(b"[fsd-host] POOL FREE-LIST CYCLE on free -> drop\n");
        }
        return;
    }
    let head = read_volatile(head_slot);
    write_volatile((p - 8) as *mut u64, head);
    write_volatile(head_slot, p);
}

// --- FILE_OBJECT LIFETIME: one FILE_OBJECT per OPEN, not per IRP -------------------------------
//
// ★ THE BUG THIS FIXES (the root cause of the LSA-self-RPC npfs hang). `run_irp` used to build a
// FRESH `FILE_OBJECT` for every dispatched IRP and free it the moment that IRP completed. But an
// FSD keeps the FILE_OBJECT pointer well past the IRP that introduced it:
//
//   * `NpSetFileObject(FileObject, Ccb, NonPagedCcb, End)` (`fileobsup.c:64`) stores our pointer,
//     and `NpCreateClientEnd`/`NpCreateExistingNamedPipe`/`NpSetConnectedPipeState` record it in
//     **`Ccb->FileObject[NamedPipeEnd]`** (`create.c:645/772`, `strucsup.c:334`, `statesup.c:51`).
//   * on disconnect/close npfs WRITES THROUGH that stored pointer —
//     `NpSetFileObject(Ccb->FileObject[end], NULL, NULL, …)` (`statesup.c:163/289/292/310/…`) zeroes
//     `FsContext`(+0x18) / `FsContext2`(+0x20) and sets `PrivateCacheMap`(+0x30) = 1.
//
// With the per-IRP lifetime those stores landed on a block the pool had already RECYCLED. The FSD
// pool hands 0x100-byte blocks straight back out, and the very next consumer of that size class is
// npfs' own `NP_DATA_QUEUE_ENTRY`/`NP_CCB`, so npfs silently corrupted its OWN data-queue
// bookkeeping: +0x10 of an `NP_DATA_QUEUE_ENTRY` is `DataEntryType`, +0x18 is `Irp`, +0x30 is
// `DataSize`; +0x10 of an `NP_DATA_QUEUE` is `QueueState`. A `DataEntryType` outside
// {Buffered, Unbuffered} with `QueueState == Empty` is precisely the state in which
// `NpGetNextRealDataQueueEntry` (`datasup.c:183`) loops forever: it re-reads `Queue.Flink`, calls
// `NpRemoveDataQueueEntry`, and that function returns WITHOUT removing anything when
// `QueueState == Empty` — a call-free infinite spin inside npfs (zero faults, zero imports), which
// is exactly what was observed.
//
// The fix is the NT lifetime: ONE FILE_OBJECT per OPEN, reused by every IRP on that open (which is
// also what makes two concurrent IRPs on one handle — a pending read plus a write, the ordinary
// rpcrt4 server shape — structurally correct rather than merely lucky), freed on CLEANUP/CLOSE.

#[derive(Clone, Copy)]
struct FileObjectSlot {
    /// npfs' `FsContext` for this open (the opaque file id the executive routes by).
    fid: u64,
    /// The FILE_OBJECT block in the FSD pool.
    fo: u64,
}

const FILE_OBJECT_CAP: usize = 64;
static mut FILE_OBJECTS: [FileObjectSlot; FILE_OBJECT_CAP] =
    [FileObjectSlot { fid: 0, fo: 0 }; FILE_OBJECT_CAP];

/// FILE_OBJECTs created for an open (one per open, not per IRP).
pub(crate) static FSD_FO_OPENS: AtomicU64 = AtomicU64::new(0);
/// IRPs that REUSED the open's existing FILE_OBJECT (the concurrent-IRP proof).
pub(crate) static FSD_FO_REUSED: AtomicU64 = AtomicU64::new(0);
/// Times a `Ccb->FileObject[end]` pointer npfs still holds was checked for liveness.
pub(crate) static FSD_FO_LIVE_CHECKS: AtomicU64 = AtomicU64::new(0);
/// …and was NOT one of our live per-open FILE_OBJECTs (a dangling FSD-held pointer).
pub(crate) static FSD_FO_DANGLING: AtomicU64 = AtomicU64::new(0);
/// …and no longer even CONTAINS a FILE_OBJECT (`Type != IO_TYPE_FILE` / wrong `Size`) — the hard,
/// non-circular evidence of a use-after-free: the pool recycled the block under npfs' feet.
pub(crate) static FSD_FO_CORRUPTED: AtomicU64 = AtomicU64::new(0);
/// Opens whose FILE_OBJECT had to be transient because [`FILE_OBJECTS`] was full (bounded fallback).
pub(crate) static FSD_FO_TABLE_FULL: AtomicU64 = AtomicU64::new(0);

/// The per-open FILE_OBJECT for `fid`, or 0.
unsafe fn fo_lookup(fid: u64) -> u64 {
    if fid == 0 {
        return 0;
    }
    let table = &*core::ptr::addr_of!(FILE_OBJECTS);
    for slot in table.iter() {
        if slot.fid == fid {
            return slot.fo;
        }
    }
    0
}

/// Is `fo` one of the live per-open FILE_OBJECTs?
unsafe fn fo_is_registered(fo: u64) -> bool {
    let table = &*core::ptr::addr_of!(FILE_OBJECTS);
    table.iter().any(|slot| slot.fid != 0 && slot.fo == fo)
}

/// Register `fo` as the per-open FILE_OBJECT for `fid`. A stale row for the same `fid` (the pool
/// re-issued a CCB address after a close) is replaced and its old block released.
unsafe fn fo_register(fid: u64, fo: u64) -> bool {
    if fid == 0 || fo == 0 {
        return false;
    }
    let table = &mut *core::ptr::addr_of_mut!(FILE_OBJECTS);
    for slot in table.iter_mut() {
        if slot.fid == fid {
            if slot.fo != fo {
                pool_free(slot.fo);
                slot.fo = fo;
            }
            return true;
        }
    }
    for slot in table.iter_mut() {
        if slot.fid == 0 {
            *slot = FileObjectSlot { fid, fo };
            FSD_FO_OPENS.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    FSD_FO_TABLE_FULL.fetch_add(1, Ordering::Relaxed);
    false
}

/// Release the per-open FILE_OBJECT for `fid` (CLEANUP/CLOSE — the ONLY place a FILE_OBJECT dies).
unsafe fn fo_release(fid: u64) {
    if fid == 0 {
        return;
    }
    let table = &mut *core::ptr::addr_of_mut!(FILE_OBJECTS);
    for slot in table.iter_mut() {
        if slot.fid == fid {
            pool_free(slot.fo);
            *slot = FileObjectSlot { fid: 0, fo: 0 };
            return;
        }
    }
}

// --- npfs DATA-QUEUE CONSISTENCY AUDIT (the hang guard + the lifetime proof) -------------------
//
// npfs' own `ASSERT`s over these invariants are compiled out of the release `npfs.sys` we host, so
// an inconsistency is not caught — it becomes the call-free `NpGetNextRealDataQueueEntry` spin
// described above, which freezes the WHOLE boot (the executive blocks in `component_pump`'s recv,
// RUNEXIT=124). Auditing the queues from the host BEFORE we dispatch into npfs turns that class of
// failure into a bounded, counter-backed report — and, because the audit also validates the
// FILE_OBJECT pointers npfs is holding, it is the direct proof that the lifetime fix above works.
//
// x64 offsets (`npfs.h`): NP_CCB { NodeType@0, NamedPipeState@2, ClientQos@8, CcbEntry@0x18,
// Fcb@0x28, FileObject[2]@0x30, Process@0x40, ClientSession@0x48, NonPagedCcb@0x50,
// DataQueue[2]@0x58 (0x28 each), ClientContext@0xA8, IrpList@0xB0 }.
// NP_DATA_QUEUE { Queue(LIST_ENTRY)@0, QueueState@0x10, BytesInQueue@0x14, EntriesInQueue@0x18,
// QuotaUsed@0x1c, ByteOffset@0x20, Quota@0x24 }.
// NP_DATA_QUEUE_ENTRY { QueueEntry(LIST_ENTRY)@0, DataEntryType@0x10, Irp@0x18, QuotaInEntry@0x20,
// ClientSecurityContext@0x28, DataSize@0x30 }.
const NPFS_NTC_CCB: u16 = 6;
const NP_CCB_FILE_OBJECT: u64 = 0x30;
const NP_CCB_DATA_QUEUE: u64 = 0x58;
const NP_DATA_QUEUE_SIZE: u64 = 0x28;
/// `NP_DATA_QUEUE_STATE::Empty`.
const NP_QUEUE_EMPTY: u32 = 2;
/// Largest legal `NP_DATA_QUEUE_ENTRY::DataEntryType` (Buffered=0, Unbuffered=1, plus npfs'
/// internal 2 = flush-buffers marker and 3).
const NP_ENTRY_TYPE_MAX: u32 = 3;
/// Hard bound on a data-queue walk (npfs' quotas keep real queues tiny).
const NP_QUEUE_WALK_MAX: u32 = 64;

/// Data queues audited before dispatch.
pub(crate) static FSD_QUEUE_AUDITS: AtomicU64 = AtomicU64::new(0);
/// Data queues found INCONSISTENT and re-initialised to a consistent empty state (the hang guard).
/// MUST be 0 on a healthy boot — a non-zero value is a gate failure, not a silent 555-second hang.
pub(crate) static FSD_QUEUE_REPAIRS: AtomicU64 = AtomicU64::new(0);
static mut QUEUE_DUMP_COUNT: u32 = 0;

/// Print one data-queue dump line (bounded).
unsafe fn queue_dump(tag: &[u8], dq: u64, state: u32, entries: u32, walked: u32, types: u32) {
    print_str(tag);
    print_str(b" dq=0x");
    print_hex(dq as u32);
    print_str(b" state=");
    print_u64(state as u64);
    print_str(b" entries=");
    print_u64(entries as u64);
    print_str(b" walked=");
    print_u64(walked as u64);
    print_str(b" types=0x");
    print_hex(types);
    unsafe {
        print_str(b" bytes=");
        print_u64(read_volatile((dq + 0x14) as *const u32) as u64);
        print_str(b" quotaused=");
        print_u64(read_volatile((dq + 0x1c) as *const u32) as u64);
        print_str(b" byteoff=");
        print_u64(read_volatile((dq + 0x20) as *const u32) as u64);
        print_str(b" quota=");
        print_u64(read_volatile((dq + 0x24) as *const u32) as u64);
    }
    print_str(b"\n");
}

/// Audit ONE `NP_DATA_QUEUE`; repair (re-init to a consistent Empty) if any npfs invariant is
/// broken. Returns true if a repair was made.
unsafe fn audit_data_queue(dq: u64) -> bool {
    let pool_end = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
    let flink = read_volatile(dq as *const u64);
    let state = read_volatile((dq + 0x10) as *const u32);
    let entries = read_volatile((dq + 0x18) as *const u32);
    let list_empty = flink == dq;
    let mut walked = 0u32;
    let mut types = 0u32; // a bitmask of the DataEntryTypes seen (diagnostic)
    let mut bad_link = false;
    let mut bad_type = false;
    let mut cur = flink;
    while cur != dq {
        if cur < FSD_POOL_VADDR + POOL_DATA_OFF || cur + 0x38 > pool_end || cur & 7 != 0 {
            bad_link = true;
            break;
        }
        let ty = read_volatile((cur + 0x10) as *const u32);
        if ty > NP_ENTRY_TYPE_MAX {
            bad_type = true;
        } else {
            types |= 1 << ty;
        }
        cur = read_volatile(cur as *const u64);
        walked += 1;
        if walked > NP_QUEUE_WALK_MAX {
            bad_link = true;
            break;
        }
    }
    let inconsistent = bad_link
        || bad_type
        || state > NP_QUEUE_EMPTY
        || (state == NP_QUEUE_EMPTY) != list_empty
        || walked != entries;
    FSD_QUEUE_AUDITS.fetch_add(1, Ordering::Relaxed);
    if !inconsistent {
        if QUEUE_DUMP_COUNT < 24 && !list_empty {
            QUEUE_DUMP_COUNT += 1;
            queue_dump(b"[fsd-queue]", dq, state, entries, walked, types);
            let mut e = read_volatile(dq as *const u64);
            let mut n = 0u32;
            while e != dq && n <= NP_QUEUE_WALK_MAX {
                if e < FSD_POOL_VADDR + POOL_DATA_OFF || e + 0x38 > pool_end {
                    break;
                }
                let ty = read_volatile((e + 0x10) as *const u32);
                let eirp = read_volatile((e + 0x18) as *const u64);
                let dsz = read_volatile((e + 0x30) as *const u32);
                let quota = read_volatile((e + 0x20) as *const u32);
                print_str(b"[fsd-queue]   entry=");
                print_hex(e as u32);
                print_str(b" type=");
                print_u64(ty as u64);
                print_str(b" size=");
                print_u64(dsz as u64);
                print_str(b" quota=");
                print_u64(quota as u64);
                print_str(b" irp=");
                print_hex(eirp as u32);
                if eirp != 0
                    && eirp >= FSD_POOL_VADDR + POOL_DATA_OFF
                    && eirp + WDM_X64_IRP_SIZE as u64 <= pool_end
                {
                    let stack = read_volatile((eirp + 0xb8) as *const u64);
                    let mj = if stack >= FSD_POOL_VADDR + POOL_DATA_OFF
                        && stack + WDM_X64_IO_STACK_LOCATION_SIZE as u64 <= pool_end
                    {
                        read_volatile(stack as *const u8) as u64
                    } else {
                        0xFF
                    };
                    print_str(b" irp-major=");
                    print_u64(mj);
                    print_str(b" pending=");
                    let table = &*core::ptr::addr_of!(PENDING_IRPS);
                    print_u64(table.iter().any(|s| s.irp == eirp) as u64);
                }
                print_str(b"\n");
                e = read_volatile(e as *const u64);
                n += 1;
            }
        }
        return false;
    }
    FSD_QUEUE_REPAIRS.fetch_add(1, Ordering::Relaxed);
    queue_dump(
        b"[fsd-queue] INCONSISTENT -> repaired",
        dq,
        state,
        entries,
        walked,
        types,
    );
    // Re-initialise exactly as `NpInitializeDataQueue` (`datasup.c:32`) does, keeping Quota: an
    // empty circular list in state Empty. npfs can no longer spin on it.
    write_volatile(dq as *mut u64, dq); // Flink = &Queue
    write_volatile((dq + 8) as *mut u64, dq); // Blink = &Queue
    write_volatile((dq + 0x10) as *mut u32, NP_QUEUE_EMPTY);
    write_volatile((dq + 0x14) as *mut u32, 0); // BytesInQueue
    write_volatile((dq + 0x18) as *mut u32, 0); // EntriesInQueue
    write_volatile((dq + 0x1c) as *mut u32, 0); // QuotaUsed
    write_volatile((dq + 0x20) as *mut u32, 0); // ByteOffset
    true
}

/// Audit the CCB behind `fid` before an IRP is dispatched on it: the FILE_OBJECT pointers npfs is
/// holding, then both data queues. No-op unless `fid` really is a `NPFS_NTC_CCB` inside the FSD pool.
unsafe fn audit_ccb(fid: u64) {
    if fid == 0 || fid == 1 {
        return;
    }
    let ccb = fid & !1;
    let pool_end = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
    if ccb < FSD_POOL_VADDR + POOL_DATA_OFF || ccb + 0xC0 > pool_end || ccb & 7 != 0 {
        return;
    }
    if read_volatile(ccb as *const u16) != NPFS_NTC_CCB {
        return;
    }
    if QUEUE_DUMP_COUNT < 24 {
        let fcb = read_volatile((ccb + 0x28) as *const u64);
        print_str(b"[fsd-ccb] ccb=");
        print_hex(ccb as u32);
        print_str(b" state=");
        print_u64(read_volatile((ccb + 2) as *const u8) as u64);
        print_str(b" readmode=");
        print_u64(read_volatile((ccb + 3) as *const u8) as u64);
        print_u64(read_volatile((ccb + 4) as *const u8) as u64);
        print_str(b" complmode=");
        print_u64(read_volatile((ccb + 5) as *const u8) as u64);
        print_u64(read_volatile((ccb + 6) as *const u8) as u64);
        print_str(b" fcb=");
        print_hex(fcb as u32);
        if fcb >= FSD_POOL_VADDR + POOL_DATA_OFF && fcb + 0x80 <= pool_end {
            print_str(b" cfg=");
            print_u64(read_volatile((fcb + 0x34) as *const u16) as u64);
            print_str(b" pipetype=");
            print_u64(read_volatile((fcb + 0x36) as *const u16) as u64);
            print_str(b" instances=");
            print_u64(read_volatile((fcb + 0x20) as *const u32) as u64);
        }
        print_str(b"\n");
    }
    // (a) the FILE_OBJECTs npfs still holds must still BE FILE_OBJECTs (the lifetime proof).
    for end in 0..2u64 {
        let held = read_volatile((ccb + NP_CCB_FILE_OBJECT + end * 8) as *const u64);
        if held == 0 {
            continue;
        }
        FSD_FO_LIVE_CHECKS.fetch_add(1, Ordering::Relaxed);
        let in_pool = held >= FSD_POOL_VADDR + POOL_DATA_OFF
            && held + WDM_X64_FILE_OBJECT_SIZE as u64 <= pool_end;
        let looks_like_fo = in_pool
            && read_volatile(held as *const u16) == WDM_X64_IO_TYPE_FILE as u16
            && read_volatile((held + 2) as *const u16) == WDM_X64_FILE_OBJECT_SIZE as u16;
        if !looks_like_fo && FSD_FO_CORRUPTED.fetch_add(1, Ordering::Relaxed) < 4 {
            print_str(b"[fsd-fo] CORRUPT FSD-held FILE_OBJECT ccb=0x");
            print_hex(ccb as u32);
            print_str(b" end=");
            print_u64(end);
            print_str(b" fo=0x");
            print_hex(held as u32);
            print_str(b"\n");
        }
        if !fo_is_registered(held) && FSD_FO_DANGLING.fetch_add(1, Ordering::Relaxed) < 4 {
            print_str(b"[fsd-fo] DANGLING FSD-held FILE_OBJECT ccb=0x");
            print_hex(ccb as u32);
            print_str(b" end=");
            print_u64(end);
            print_str(b" fo=0x");
            print_hex(held as u32);
            print_str(b"\n");
        }
    }
    // (b) both data queues.
    for q in 0..2u64 {
        audit_data_queue(ccb + NP_CCB_DATA_QUEUE + q * NP_DATA_QUEUE_SIZE);
    }
}

// --- KeBugCheckEx: a hosted driver's consistency bugcheck is CAUGHT, REPORTED and UNWOUND -------
//
// Every hosted driver imports `KeBugCheckEx` and npfs wraps it in `NpBugCheck(p1,p2,p3)` =
// `KeBugCheckEx(NPFS_FILE_SYSTEM, (FILE_ID << 16) | __LINE__, p1, p2, p3)` (`npfs.h:106`) — the
// driver's own statement that its state is inconsistent, complete with the source file id and line.
// It was an UNBOUND import, so it resolved to the fail-soft `s_true` no-op: the driver's assertion
// was SKIPPED and it carried on with a broken invariant. Now it is bound: the code + all four
// parameters + the raising component are reported, and the offending dispatch is failed CLEANLY by
// unwinding back to `run_irp` (the park/fail-closed discipline — never a hang, never a dead boot).

/// Bugchecks raised by a hosted driver (caught, not skipped).
pub(crate) static FSD_BUGCHECKS: AtomicU64 = AtomicU64::new(0);
/// …of which were unwound back to the dispatch loop (vs reported-and-returned outside an IRP).
pub(crate) static FSD_BUGCHECK_UNWINDS: AtomicU64 = AtomicU64::new(0);
/// The LAST bugcheck's code + 4 parameters (for the gate spec + the report).
pub(crate) static FSD_BUGCHECK_CODE: AtomicU64 = AtomicU64::new(0);
pub(crate) static FSD_BUGCHECK_P1: AtomicU64 = AtomicU64::new(0);
pub(crate) static FSD_BUGCHECK_P2: AtomicU64 = AtomicU64::new(0);
pub(crate) static FSD_BUGCHECK_P3: AtomicU64 = AtomicU64::new(0);
pub(crate) static FSD_BUGCHECK_P4: AtomicU64 = AtomicU64::new(0);
/// The driver INSTANCE that raised the last bugcheck (recorded by the executive-side dispatcher,
/// which is the only side that knows which component it just drove).
pub(crate) static FSD_BUGCHECK_INSTANCE: AtomicU64 = AtomicU64::new(0);

/// The dispatch escape buffer: `[0]` = the callee-saved pop-base inside [`fsd_guarded_call`],
/// `[1]` = the resume address (non-zero == ARMED), `[2]` = set by the longjmp path so the caller can
/// tell a bugchecked dispatch from a normal return.
static mut BUGCHECK_JB: [u64; 3] = [0; 3];

// The setjmp/longjmp pair. Written in assembly on purpose: the escape abandons npfs' frames, so no
// Rust value may be live across it. `fsd_guarded_call` saves every Win64 callee-saved GPR, records
// (pop-base, resume-address) in the jump buffer, then calls `handler(devobj, irp)` with a forced
// Win64 call frame (`rsp` 16-byte aligned before `call`, plus 32 bytes of shadow space). Both the
// normal return and the longjmp land on the SAME epilogue, so the register file is restored either
// way.
core::arch::global_asm!(
    ".text",
    ".globl fsd_guarded_call",
    "fsd_guarded_call:", // rcx = handler, rdx = devobj, r8 = irp, r9 = jump buffer
    "push rbp",
    "push rbx",
    "push rsi",
    "push rdi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov r15, r9",
    "lea rax, [rip + 9f]",
    "mov [r15], rsp",
    "mov [r15 + 8], rax",
    "mov r10, rcx",
    "mov rcx, rdx",
    "mov rdx, r8",
    "and rsp, -16",
    "sub rsp, 0x20",
    "call r10",
    "9:", // the longjmp lands here and uses the same pop-base restore as a normal return.
    "mov rsp, [r15]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rdi",
    "pop rsi",
    "pop rbx",
    "pop rbp",
    "ret",
    ".globl fsd_guarded_longjmp",
    "fsd_guarded_longjmp:", // rcx = jump buffer
    "mov r15, rcx",
    "mov rsp, [rcx]",
    "jmp qword ptr [rcx + 8]",
);

extern "win64" {
    fn fsd_guarded_call(handler: u64, devobj: u64, irp: u64, jb: *mut u64) -> i32;
    fn fsd_guarded_longjmp(jb: *mut u64) -> !;
}

/// `DECLSPEC_NORETURN void KeBugCheckEx(ULONG Code, ULONG_PTR P1, P2, P3, P4)`. Report the driver's
/// bugcheck (code, all four parameters, and — for `NPFS_FILE_SYSTEM` — the source file id + line
/// `NpBugCheck` encodes in P1) and unwind the current dispatch. A bugcheck raised OUTSIDE an IRP
/// dispatch (i.e. during `DriverEntry`, before the escape is armed) is reported and returns, which
/// is the historical fail-soft behaviour — but now visible instead of silent.
extern "win64" fn s_ke_bug_check_ex(code: u64, p1: u64, p2: u64, p3: u64, p4: u64) {
    unsafe {
        FSD_BUGCHECKS.fetch_add(1, Ordering::Relaxed);
        FSD_BUGCHECK_CODE.store(code, Ordering::Relaxed);
        FSD_BUGCHECK_P1.store(p1, Ordering::Relaxed);
        FSD_BUGCHECK_P2.store(p2, Ordering::Relaxed);
        FSD_BUGCHECK_P3.store(p3, Ordering::Relaxed);
        FSD_BUGCHECK_P4.store(p4, Ordering::Relaxed);
        print_str(b"[fsd-bugcheck] code=0x");
        print_hex(code as u32);
        print_str(b" p1=0x");
        print_hex(p1 as u32);
        print_str(b" p2=0x");
        print_hex(p2 as u32);
        print_str(b" p3=0x");
        print_hex(p3 as u32);
        print_str(b" p4=0x");
        print_hex(p4 as u32);
        if code == 0x25 {
            // NPFS_FILE_SYSTEM — `NpBugCheck` packs (FILE_ID << 16) | __LINE__ into P1.
            print_str(b" (npfs file=");
            print_u64(p1 >> 16);
            print_str(b" line=");
            print_u64(p1 & 0xFFFF);
            print_str(b")");
        }
        let jb = &mut *core::ptr::addr_of_mut!(BUGCHECK_JB);
        if jb[1] != 0 {
            print_str(b" -> dispatch UNWOUND\n");
            jb[2] = 1;
            FSD_BUGCHECK_UNWINDS.fetch_add(1, Ordering::Relaxed);
            fsd_guarded_longjmp(jb.as_mut_ptr());
        }
        print_str(b" -> outside a dispatch (reported, not unwound)\n");
    }
}

// --- ntoskrnl trampolines (extern "win64"; args = rcx, rdx, r8, r9, then stack) --------------

/// Bounded count of FSD imports logged as UNBOUND (the auditable fail-soft surface).
static mut FSD_UNBOUND_LOGGED: u32 = 0;

extern "win64" fn s_zero() -> u64 {
    0
}
extern "win64" fn s_true() -> u64 {
    1
}

/// `PVOID ExAllocatePoolWithTag(POOL_TYPE, SIZE_T NumberOfBytes, ULONG Tag)`.
extern "win64" fn s_ex_alloc_pool_tag(_pool: u64, size: u64, _tag: u64) -> u64 {
    unsafe { pool_alloc(size) }
}
/// `PVOID ExAllocatePoolWithQuotaTag(POOL_TYPE, SIZE_T, ULONG)`.
extern "win64" fn s_ex_alloc_pool_quota_tag(_pool: u64, size: u64, _tag: u64) -> u64 {
    unsafe { pool_alloc(size) }
}
/// `PVOID ExAllocatePool(POOL_TYPE, SIZE_T)`.
extern "win64" fn s_ex_alloc_pool(_pool: u64, size: u64) -> u64 {
    unsafe { pool_alloc(size) }
}
/// `void ExFreePoolWithTag(PVOID, ULONG)` / `void ExFreePool(PVOID)`.
extern "win64" fn s_ex_free_pool_tag(p: u64, _tag: u64) {
    unsafe { pool_free(p) }
}
extern "win64" fn s_ex_free_pool(p: u64) {
    unsafe { pool_free(p) }
}

/// `void RtlInitUnicodeString(PUNICODE_STRING Dest, PCWSTR Source)`.
extern "win64" fn s_rtl_init_unicode_string(dst: u64, src: u64) {
    if dst == 0 {
        return;
    }
    unsafe {
        let mut len = 0u16;
        if src != 0 {
            let mut n = 0u64;
            while read_unaligned((src + n * 2) as *const u16) != 0 {
                n += 1;
            }
            len = (n * 2) as u16;
        }
        write_unaligned(dst as *mut u16, len); // Length
        write_unaligned((dst + 2) as *mut u16, if src != 0 { len + 2 } else { 0 }); // MaximumLength
        write_unaligned((dst + 8) as *mut u64, src); // Buffer
    }
}

/// `void RtlInitEmptyUnicodeString(PUNICODE_STRING, PWSTR Buffer, USHORT MaxLen)`.
extern "win64" fn s_rtl_init_empty_unicode_string(dst: u64, buf: u64, maxlen: u64) {
    if dst == 0 {
        return;
    }
    unsafe {
        write_unaligned(dst as *mut u16, 0);
        write_unaligned((dst + 2) as *mut u16, maxlen as u16);
        write_unaligned((dst + 8) as *mut u64, buf);
    }
}

unsafe fn unicode_string_parts(us: u64) -> Option<(u64, u16)> {
    if us == 0 {
        return None;
    }
    let len = read_unaligned(us as *const u16);
    let buf = read_unaligned((us + 8) as *const u64);
    if len == 0 || len as usize > SH_CAPTURED_PATH_BYTES || (len & 1) != 0 || buf == 0 {
        return None;
    }
    Some((buf, len))
}

unsafe fn clear_shared_path_len(len_off: u64) {
    write_volatile((FSD_SHARED_VADDR + len_off) as *mut u16, 0);
}

unsafe fn copy_wstr_to_shared(src: u64, len: u16, len_off: u64, buf_off: u64) {
    let mut off = 0u64;
    while off < len as u64 {
        let b = read_volatile((src + off) as *const u8);
        write_volatile((FSD_SHARED_VADDR + buf_off + off) as *mut u8, b);
        off += 1;
    }
    write_volatile((FSD_SHARED_VADDR + len_off) as *mut u16, len);
}

/// `NTSTATUS IoCreateDevice(PDRIVER_OBJECT, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName,
/// DEVICE_TYPE, ULONG Characteristics, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject)`.
/// Allocate a DEVICE_OBJECT (with the requested extension) from the pool, minimally initialize it,
/// link it onto DriverObject->DeviceObject, and return it via the out-param. Records the device in
/// the shared page (the executive resolves the FSD's control device to it).
extern "win64" fn s_io_create_device(
    drv: u64,
    ext_size: u64,
    name: u64,
    dev_type: u64,
    _chars: u64,
    _excl: u64,
    dev_out: u64,
) -> i32 {
    unsafe {
        clear_shared_path_len(SH_DEVICE_NAME_LEN);
        let named_device = if name != 0 {
            match unicode_string_parts(name) {
                Some(parts) => Some(parts),
                None => return 0xC000_000Du32 as i32, // STATUS_INVALID_PARAMETER
            }
        } else {
            None
        };
        let projection = match crate::hosted_driver_projection::create_hosted_device_projection(
            drv,
            ext_size,
            dev_type as u32,
            pool_alloc,
            pool_free,
        ) {
            Ok(projection) => projection,
            Err(status) => return status,
        };
        let dev = projection.device_object();
        if dev_out != 0 {
            write_unaligned(dev_out as *mut u64, dev);
        }
        // record it for the executive
        write_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *mut u64, dev);
        let mut v = read_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *const u32) | V_DEVICE;
        if let Some((name_buf, name_len)) = named_device {
            copy_wstr_to_shared(name_buf, name_len, SH_DEVICE_NAME_LEN, SH_DEVICE_NAME_BUF);
            v |= V_NAMED_DEVICE;
        }
        write_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
    }
    0 // STATUS_SUCCESS
}

/// `void IoDeleteDevice(PDEVICE_OBJECT)`.
extern "win64" fn s_io_delete_device(dev: u64) {
    if dev == 0 {
        return;
    }
    unsafe {
        if let Some(binding) = hosted_device_binding_by_device_object(dev) {
            if binding.device_id != 0 {
                let device_id = nt_io_manager::DeviceId(binding.device_id);
                match io_manager_mut().destroy_device(device_id) {
                    Ok(_) => {
                        clear_hosted_device_binding_by_device_id(binding.device_id);
                        let table = &mut *core::ptr::addr_of_mut!(DRIVER_INSTANCES);
                        if binding.instance < table.len()
                            && table[binding.instance].device_object == dev
                        {
                            table[binding.instance].device_id = 0;
                            table[binding.instance].device_object = 0;
                            table[binding.instance].ready = false;
                        }
                    }
                    Err(nt_status::NtStatus::DELETE_PENDING) => return,
                    Err(_) => return,
                }
            }
        }

        crate::hosted_driver_projection::delete_hosted_device_projection(dev, pool_free);
        if read_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *const u64) == dev {
            write_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *mut u64, 0);
            clear_shared_path_len(SH_DEVICE_NAME_LEN);
            let verdict = read_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *const u32)
                & !(V_DEVICE | V_NAMED_DEVICE);
            write_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *mut u32, verdict);
        }
    }
}

fn nt_path_ascii_string(path: &NtPath) -> Option<String> {
    let mut out = String::new();
    for unit in path.to_units() {
        if !(0x20..=0x7e).contains(&unit) {
            return None;
        }
        out.push(char::from_u32(unit as u32)?);
    }
    Some(out)
}

/// `PDEVICE_OBJECT IoAttachDeviceToDeviceStack(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice)`.
extern "win64" fn s_io_attach_device_to_device_stack(source: u64, target: u64) -> u64 {
    unsafe {
        let lower = match crate::hosted_driver_projection::attach_hosted_device_projection(
            source, target,
        ) {
            Some(lower) => lower,
            None => return 0,
        };

        let source_instance = instance_by_device_object(source);
        let target_instance = instance_by_device_object(target);
        match (source_instance, target_instance) {
            (Some((_, source_inst)), Some((_, target_inst)))
                if source_inst.device_id != 0 && target_inst.device_id != 0 =>
            {
                match io_manager_mut().attach_device_to_stack(
                    nt_io_manager::DeviceId(source_inst.device_id),
                    nt_io_manager::DeviceId(target_inst.device_id),
                ) {
                    Ok(lower_id) => instance_by_device_id(lower_id.raw())
                        .map(|(_, inst)| inst.device_object)
                        .unwrap_or(lower),
                    Err(_) => {
                        crate::hosted_driver_projection::detach_hosted_device_projection(lower);
                        0
                    }
                }
            }
            (None, None) => lower,
            _ => lower,
        }
    }
}

/// `void IoDetachDevice(PDEVICE_OBJECT TargetDevice)`.
extern "win64" fn s_io_detach_device(lower: u64) {
    if lower == 0 {
        return;
    }
    unsafe {
        let upper = crate::hosted_driver_projection::hosted_attached_device(lower);
        if let Some((_, upper_inst)) = instance_by_device_object(upper) {
            if upper_inst.device_id != 0 {
                let _ = io_manager_mut()
                    .detach_device_from_stack(nt_io_manager::DeviceId(upper_inst.device_id));
            }
        }
        crate::hosted_driver_projection::detach_hosted_device_projection(lower);
    }
}

unsafe fn irp_current_stack_location(irp: u64) -> u64 {
    if irp == 0 {
        0
    } else {
        read_unaligned((irp + 0xb8) as *const u64)
    }
}

unsafe fn irp_next_stack_location(irp: u64) -> u64 {
    irp_current_stack_location(irp).saturating_sub(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
}

const WDM_X64_IRP_CURRENT_LOCATION_OFFSET: u64 = 0x43;
const WDM_X64_IRP_STACK_COUNT_OFFSET: u64 = 0x42;
const WDM_X64_IRP_IO_STATUS_STATUS_OFFSET: u64 = 0x30;
const WDM_X64_IO_STACK_MINOR_OFFSET: u64 = 0x01;
const WDM_X64_IO_STACK_CONTROL_OFFSET: u64 = 0x03;
const WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET: u64 = 0x20;
const WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET: u64 = 0x38;
const WDM_X64_IO_STACK_CONTEXT_OFFSET: u64 = 0x40;
const WDM_X64_SL_INVOKE_ON_SUCCESS: u8 = 0x40;
const WDM_X64_SL_INVOKE_ON_ERROR: u8 = 0x80;

/// `PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP)`.
extern "win64" fn s_io_get_current_irp_stack_location(irp: u64) -> u64 {
    unsafe { irp_current_stack_location(irp) }
}

/// `PIO_STACK_LOCATION IoGetNextIrpStackLocation(PIRP)`.
extern "win64" fn s_io_get_next_irp_stack_location(irp: u64) -> u64 {
    unsafe { irp_next_stack_location(irp) }
}

/// `void IoCopyCurrentIrpStackLocationToNext(PIRP)`.
extern "win64" fn s_io_copy_current_irp_stack_location_to_next(irp: u64) {
    unsafe {
        let current = irp_current_stack_location(irp);
        let next = irp_next_stack_location(irp);
        if current == 0 || next == 0 {
            return;
        }
        let mut off = 0u64;
        while off < WDM_X64_IO_STACK_LOCATION_SIZE as u64 {
            let byte = read_unaligned((current + off) as *const u8);
            write_unaligned((next + off) as *mut u8, byte);
            off += 1;
        }
    }
}

/// `void IoSkipCurrentIrpStackLocation(PIRP)`.
extern "win64" fn s_io_skip_current_irp_stack_location(irp: u64) {
    unsafe {
        if irp == 0 {
            return;
        }
        let current_location =
            read_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *const u8);
        write_unaligned(
            (irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *mut u8,
            current_location.wrapping_add(1),
        );
        let current_stack = irp_current_stack_location(irp);
        if current_stack != 0 {
            write_unaligned(
                (irp + 0xb8) as *mut u64,
                current_stack + WDM_X64_IO_STACK_LOCATION_SIZE as u64,
            );
        }
    }
}

/// `NTSTATUS IofCallDriver(PDEVICE_OBJECT, PIRP)`.
extern "win64" fn s_iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let mut next = 0;
        let mut forwarded_minor = read_volatile((FSD_SHARED_VADDR + SH_REQ_MINOR) as *const u64);
        if irp != 0 {
            let current_location =
                read_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *const u8);
            if current_location == 0 {
                return 0xC000_0010u32 as i32; // STATUS_INVALID_DEVICE_REQUEST
            }
            write_unaligned(
                (irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *mut u8,
                current_location - 1,
            );
            next = irp_next_stack_location(irp);
            if next != 0 {
                write_unaligned((irp + 0xb8) as *mut u64, next);
                write_unaligned(
                    (next + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET) as *mut u64,
                    device,
                );
                forwarded_minor =
                    read_unaligned((next + WDM_X64_IO_STACK_MINOR_OFFSET) as *const u8) as u64;
            }
        }
        let expected_pdo = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
        let status = if expected_pdo == 0 {
            0
        } else if device == expected_pdo {
            write_volatile(
                (FSD_SHARED_VADDR + SH_ROOT_PDO_FORWARDED_MINOR) as *mut u64,
                forwarded_minor,
            );
            0
        } else {
            0xC000_0010u32 as i32 // STATUS_INVALID_DEVICE_REQUEST
        };
        write_volatile(
            (FSD_SHARED_VADDR + SH_ROOT_PDO_FORWARDED_STATUS) as *mut i32,
            status,
        );
        if irp != 0 {
            write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32, status);
            if next != 0 {
                complete_forwarded_stack_location(irp, next, status);
            }
        }
        status
    }
}

unsafe fn complete_forwarded_stack_location(irp: u64, stack: u64, status: i32) {
    let completion = read_unaligned(
        (stack + WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET) as *const u64,
    );
    if completion == 0 {
        return;
    }
    let control =
        read_unaligned((stack + WDM_X64_IO_STACK_CONTROL_OFFSET) as *const u8);
    let invoke = if status >= 0 {
        (control & WDM_X64_SL_INVOKE_ON_SUCCESS) != 0
    } else {
        (control & WDM_X64_SL_INVOKE_ON_ERROR) != 0
    };
    if !invoke {
        return;
    }

    let current_location =
        read_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *const u8);
    let stack_count = read_unaligned((irp + WDM_X64_IRP_STACK_COUNT_OFFSET) as *const u8);
    let next_location = current_location.saturating_add(1);
    let next_stack = stack + WDM_X64_IO_STACK_LOCATION_SIZE as u64;
    write_unaligned(
        (irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *mut u8,
        next_location,
    );
    write_unaligned((irp + 0xb8) as *mut u64, next_stack);

    let device_object = if next_location <= stack_count {
        read_unaligned((next_stack + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET) as *const u64)
    } else {
        0
    };
    let context = read_unaligned((stack + WDM_X64_IO_STACK_CONTEXT_OFFSET) as *const u64);
    let routine: extern "win64" fn(u64, u64, u64) -> i32 =
        core::mem::transmute(completion as *const ());
    let _ = routine(device_object, irp, context);
}

/// `NTSTATUS PoCallDriver(PDEVICE_OBJECT, PIRP)`.
extern "win64" fn s_po_call_driver(device: u64, irp: u64) -> i32 {
    s_iof_call_driver(device, irp)
}

/// `void PoStartNextPowerIrp(PIRP)`.
extern "win64" fn s_po_start_next_power_irp(_irp: u64) {}

/// `POWER_STATE PoSetPowerState(PDEVICE_OBJECT, POWER_STATE_TYPE, POWER_STATE)` — record the
/// device power state the hosted driver reports and return the previous state.
extern "win64" fn s_po_set_power_state(_device: u64, power_type: u32, state: u32) -> u32 {
    const POWER_STATE_TYPE_DEVICE: u32 = 1;
    unsafe {
        let previous = read_volatile(core::ptr::addr_of!(HOSTED_DRIVER_DEVICE_POWER_STATE));
        if power_type == POWER_STATE_TYPE_DEVICE {
            write_volatile(
                core::ptr::addr_of_mut!(HOSTED_DRIVER_DEVICE_POWER_STATE),
                state,
            );
        }
        previous
    }
}

/// `PMDL IoAllocateMdl(PVOID, ULONG, BOOLEAN, BOOLEAN, PIRP)` — project a single-buffer MDL
/// while recording the canonical MDL id in the driver-visible `Next` field.
extern "win64" fn s_io_allocate_mdl(
    virtual_address: u64,
    length: u32,
    _secondary_buffer: u8,
    _charge_quota: u8,
    _irp: u64,
) -> u64 {
    unsafe {
        if virtual_address == 0 || length == 0 {
            return 0;
        }
        let mdl = pool_alloc(nt_mdl::MDL_SIZE as u64);
        if mdl == 0 {
            return 0;
        }
        let id = hosted_mdl_registry_mut().allocate(virtual_address, length);
        write_unaligned((mdl + nt_mdl::MDL_OFF_NEXT) as *mut u64, id);
        write_unaligned(
            (mdl + nt_mdl::MDL_OFF_SIZE) as *mut i16,
            nt_mdl::MDL_SIZE as i16,
        );
        write_unaligned(
            (mdl + nt_mdl::MDL_OFF_START_VA) as *mut u64,
            virtual_address & !0xFFF,
        );
        write_unaligned(
            (mdl + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32,
            length,
        );
        write_unaligned(
            (mdl + nt_mdl::MDL_OFF_BYTE_OFFSET) as *mut u32,
            (virtual_address & 0xFFF) as u32,
        );
        mdl
    }
}

/// `VOID IoFreeMdl(PMDL)`.
extern "win64" fn s_io_free_mdl(mdl: u64) {
    unsafe {
        if mdl == 0 {
            return;
        }
        let id = read_unaligned((mdl + nt_mdl::MDL_OFF_NEXT) as *const u64);
        let _ = hosted_mdl_registry_mut().free(id);
        pool_free(mdl);
    }
}

/// `VOID MmBuildMdlForNonPagedPool(PMDL)` — mark the MDL nonpaged and set `MappedSystemVa`.
extern "win64" fn s_mm_build_mdl_for_nonpaged_pool(mdl: u64) {
    unsafe {
        if mdl == 0 {
            return;
        }
        let id = read_unaligned((mdl + nt_mdl::MDL_OFF_NEXT) as *const u64);
        let _ = hosted_mdl_registry_mut().build_for_nonpaged(id);
        let flags = read_unaligned((mdl + nt_mdl::MDL_OFF_FLAGS) as *const i16);
        write_unaligned(
            (mdl + nt_mdl::MDL_OFF_FLAGS) as *mut i16,
            flags | nt_mdl::MDL_SOURCE_IS_NONPAGED_POOL | nt_mdl::MDL_MAPPED_TO_SYSTEM_VA,
        );
        let start = read_unaligned((mdl + nt_mdl::MDL_OFF_START_VA) as *const u64);
        let offset = read_unaligned((mdl + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32);
        write_unaligned(
            (mdl + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64,
            start + offset as u64,
        );
    }
}

/// `PVOID MmMapLockedPagesSpecifyCache(...)` — return the MDL's existing nonpaged mapping.
extern "win64" fn s_mm_map_locked_pages_specify_cache(
    mdl: u64,
    _access_mode: u8,
    _cache_type: u32,
    _requested_address: u64,
    _bug_check_on_failure: u32,
    _priority: u32,
) -> u64 {
    unsafe {
        if mdl == 0 {
            return 0;
        }
        let mapped = read_unaligned((mdl + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *const u64);
        if mapped != 0 {
            return mapped;
        }
        let start = read_unaligned((mdl + nt_mdl::MDL_OFF_START_VA) as *const u64);
        let offset = read_unaligned((mdl + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32);
        start + offset as u64
    }
}

/// `PVOID MmMapIoSpace(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE)` — return the component VA
/// for a BAR range the executive already granted to this hosted driver. Requests outside the active
/// grant fail with NULL; there is no success fallback.
extern "win64" fn s_mm_map_io_space(phys: u64, length: u64, _cache: u32) -> u64 {
    unsafe {
        let grant_phys = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_PHYS) as *const u64);
        let grant_len = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_LEN) as *const u64);
        let grant_va = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_VA) as *const u64);
        if grant_phys == 0 || grant_len == 0 || grant_va == 0 || length == 0 || phys < grant_phys {
            return 0;
        }
        let offset = phys - grant_phys;
        if offset > grant_len || length > grant_len - offset {
            return 0;
        }
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_MMIO_MAPPED_PHYS) as *mut u64,
            phys,
        );
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_MMIO_MAPPED_LEN) as *mut u64,
            length,
        );
        grant_va + offset
    }
}

/// `void MmUnmapIoSpace(PVOID, SIZE_T)` — revoke the recorded projection. The VSpace mapping is
/// owned by the executive grant and is torn down with the component.
extern "win64" fn s_mm_unmap_io_space(base: u64, _length: u64) {
    unsafe {
        let grant_va = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_VA) as *const u64);
        let grant_len = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_LEN) as *const u64);
        if grant_va != 0 && base >= grant_va && base < grant_va + grant_len {
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_MMIO_MAPPED_PHYS) as *mut u64,
                0,
            );
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_MMIO_MAPPED_LEN) as *mut u64,
                0,
            );
        }
    }
}

/// `NTSTATUS IoConnectInterrupt(...)` — validate the requested vector against the active PnP grant
/// and hand back a component-local interrupt projection.
#[allow(clippy::too_many_arguments)]
extern "win64" fn s_io_connect_interrupt(
    interrupt_obj_out: *mut u64,
    service_routine: u64,
    service_context: u64,
    _spin_lock: u64,
    vector: u32,
    _irql: u8,
    _sync_irql: u8,
    _mode: u32,
    _share: u8,
    affinity: u64,
    _floating: u8,
) -> i32 {
    unsafe {
        let granted_vector =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32);
        let granted_affinity =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_AFFINITY) as *const u64);
        if granted_vector == 0
            || vector != granted_vector
            || (affinity != 0 && granted_affinity != 0 && affinity != granted_affinity)
        {
            return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
        }
        let projection = pool_alloc(0x20);
        if projection == 0 {
            return 0xC000_009Au32 as i32; // STATUS_INSUFFICIENT_RESOURCES
        }
        write_unaligned(projection as *mut u32, vector);
        write_unaligned((projection + 8) as *mut u64, service_routine);
        write_unaligned((projection + 16) as *mut u64, service_context);
        if !interrupt_obj_out.is_null() {
            write_unaligned(interrupt_obj_out, projection);
        }
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_OBJECT) as *mut u64,
            projection,
        );
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ROUTINE) as *mut u64,
            service_routine,
        );
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_CONTEXT) as *mut u64,
            service_context,
        );
        0
    }
}

/// `void IoDisconnectInterrupt(PKINTERRUPT)` — clear the connected projection if it is the active
/// one for this hosted driver.
extern "win64" fn s_io_disconnect_interrupt(pkinterrupt: u64) {
    unsafe {
        let active = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_OBJECT) as *const u64);
        if pkinterrupt != 0 && pkinterrupt == active {
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_OBJECT) as *mut u64,
                0,
            );
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ROUTINE) as *mut u64,
                0,
            );
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_CONTEXT) as *mut u64,
                0,
            );
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ID) as *mut u64,
                0,
            );
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_DELIVERED_VECTOR) as *mut u64,
                0,
            );
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ISR_CLAIMED) as *mut u64,
                0,
            );
            write_volatile(
                (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_DELIVERIES) as *mut u64,
                0,
            );
            clear_dpc_queue_projection(FSD_SHARED_VADDR);
        }
    }
}

/// `PDMA_ADAPTER IoGetDmaAdapter(PDEVICE_OBJECT, PDEVICE_DESCRIPTION, PULONG)` — build a
/// driver-local DMA adapter projection only when PnP granted this devnode a DMA common buffer.
extern "win64" fn s_io_get_dma_adapter(
    _pdo: u64,
    _device_description: u64,
    number_of_map_registers: *mut u32,
) -> u64 {
    unsafe {
        let adapter_id = read_volatile((FSD_SHARED_VADDR + SH_DMA_ADAPTER_ID) as *const u64);
        let grant_va = read_volatile((FSD_SHARED_VADDR + SH_DMA_COMMON_VA) as *const u64);
        let grant_len = read_volatile((FSD_SHARED_VADDR + SH_DMA_COMMON_LEN) as *const u64);
        let grant_logical = read_volatile((FSD_SHARED_VADDR + SH_DMA_COMMON_LOGICAL) as *const u64);
        if adapter_id == 0 || grant_va == 0 || grant_len == 0 || grant_logical == 0 {
            return 0;
        }
        let active_adapter = read_volatile((FSD_SHARED_VADDR + SH_DMA_ADAPTER_BLOB) as *const u64);
        if active_adapter != 0 {
            if !number_of_map_registers.is_null() {
                write_unaligned(number_of_map_registers, 64);
            }
            return active_adapter;
        }

        let ops = pool_alloc(0x100);
        if ops == 0 {
            return 0;
        }
        let adapter = pool_alloc(0x40);
        if adapter == 0 {
            pool_free(ops);
            return 0;
        }

        // DMA_OPERATIONS: Size@0, PutDmaAdapter@8, AllocateCommonBuffer@16,
        // FreeCommonBuffer@24. Other operations stay NULL until the generic MDL map path exists.
        write_unaligned(ops as *mut u32, 0x100);
        write_unaligned(
            (ops + 8) as *mut u64,
            s_dma_put_adapter as *const () as usize as u64,
        );
        write_unaligned(
            (ops + 16) as *mut u64,
            s_dma_allocate_common_buffer as *const () as usize as u64,
        );
        write_unaligned(
            (ops + 24) as *mut u64,
            s_dma_free_common_buffer as *const () as usize as u64,
        );

        // DMA_ADAPTER: Version@0, Size@2, DmaOperations@8.
        write_unaligned(adapter as *mut u16, 1);
        write_unaligned((adapter + 2) as *mut u16, 0x40);
        write_unaligned((adapter + 8) as *mut u64, ops);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DMA_ADAPTER_BLOB) as *mut u64,
            adapter,
        );
        write_volatile((FSD_SHARED_VADDR + SH_DMA_OPS_BLOB) as *mut u64, ops);
        if !number_of_map_registers.is_null() {
            write_unaligned(number_of_map_registers, 64);
        }
        adapter
    }
}

/// `PutDmaAdapter` — release the component-local adapter projection.
extern "win64" fn s_dma_put_adapter(adapter: u64) {
    unsafe {
        let active = read_volatile((FSD_SHARED_VADDR + SH_DMA_ADAPTER_BLOB) as *const u64);
        if adapter != 0 && adapter == active {
            let ops = read_volatile((FSD_SHARED_VADDR + SH_DMA_OPS_BLOB) as *const u64);
            pool_free(adapter);
            if ops != 0 {
                pool_free(ops);
            }
            write_volatile((FSD_SHARED_VADDR + SH_DMA_ADAPTER_BLOB) as *mut u64, 0);
            write_volatile((FSD_SHARED_VADDR + SH_DMA_OPS_BLOB) as *mut u64, 0);
        }
    }
}

/// `AllocateCommonBuffer` — return the one common buffer PnP granted to this devnode.
extern "win64" fn s_dma_allocate_common_buffer(
    adapter: u64,
    length: u32,
    logical_out: *mut i64,
    _cache_enabled: u8,
) -> u64 {
    unsafe {
        let active = read_volatile((FSD_SHARED_VADDR + SH_DMA_ADAPTER_BLOB) as *const u64);
        let grant_va = read_volatile((FSD_SHARED_VADDR + SH_DMA_COMMON_VA) as *const u64);
        let grant_len = read_volatile((FSD_SHARED_VADDR + SH_DMA_COMMON_LEN) as *const u64);
        let grant_logical = read_volatile((FSD_SHARED_VADDR + SH_DMA_COMMON_LOGICAL) as *const u64);
        let allocated = read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_LOGICAL) as *const u64);
        let requested = length as u64;
        if adapter == 0
            || adapter != active
            || grant_va == 0
            || grant_len == 0
            || grant_logical == 0
            || requested == 0
            || requested > grant_len
            || allocated != 0
        {
            return 0;
        }

        core::ptr::write_bytes(grant_va as *mut u8, 0, requested as usize);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DMA_REQUESTED_LEN) as *mut u64,
            requested,
        );
        write_volatile(
            (FSD_SHARED_VADDR + SH_DMA_ALLOCATED_VA) as *mut u64,
            grant_va,
        );
        write_volatile(
            (FSD_SHARED_VADDR + SH_DMA_ALLOCATED_LOGICAL) as *mut u64,
            grant_logical,
        );
        if !logical_out.is_null() {
            write_unaligned(logical_out, grant_logical as i64);
        }
        grant_va
    }
}

/// `FreeCommonBuffer` — release the common-buffer projection if it matches the active grant.
extern "win64" fn s_dma_free_common_buffer(
    _adapter: u64,
    length: u32,
    logical: i64,
    virtual_address: u64,
    _cache_enabled: u8,
) {
    unsafe {
        let active_logical =
            read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_LOGICAL) as *const u64);
        let active_va = read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_VA) as *const u64);
        let active_len = read_volatile((FSD_SHARED_VADDR + SH_DMA_REQUESTED_LEN) as *const u64);
        if active_logical != 0
            && logical as u64 == active_logical
            && virtual_address == active_va
            && length as u64 == active_len
        {
            write_volatile(
                (FSD_SHARED_VADDR + SH_DMA_FREED_LOGICAL) as *mut u64,
                active_logical,
            );
            write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_LOGICAL) as *mut u64, 0);
            write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_VA) as *mut u64, 0);
            write_volatile((FSD_SHARED_VADDR + SH_DMA_REQUESTED_LEN) as *mut u64, 0);
        }
    }
}

/// `NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING, PUNICODE_STRING)` — capture the driver-declared
/// link so the executive can publish it through the kernel object namespace after DriverEntry.
extern "win64" fn s_io_create_symbolic_link(link: u64, target: u64) -> i32 {
    unsafe {
        clear_shared_path_len(SH_SYMLINK_LINK_LEN);
        clear_shared_path_len(SH_SYMLINK_TARGET_LEN);
        let Some((link_buf, link_len)) = unicode_string_parts(link) else {
            return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
        };
        let Some((target_buf, target_len)) = unicode_string_parts(target) else {
            return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
        };
        copy_wstr_to_shared(link_buf, link_len, SH_SYMLINK_LINK_LEN, SH_SYMLINK_LINK_BUF);
        copy_wstr_to_shared(
            target_buf,
            target_len,
            SH_SYMLINK_TARGET_LEN,
            SH_SYMLINK_TARGET_BUF,
        );
        let v = read_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *const u32);
        write_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *mut u32, v | V_SYMLINK);
    }
    0
}

/// `NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING)` — delete the driver-declared link through the
/// canonical I/O Manager/Object Manager path instead of resolving the import to a no-op.
extern "win64" fn s_io_delete_symbolic_link(link: u64) -> i32 {
    unsafe {
        let Some(path) = unicode_string_nt_path(link) else {
            return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
        };
        match io_manager_mut().delete_symbolic_link(&path) {
            Ok(()) => 0,
            Err(status) => status.raw(),
        }
    }
}

/// `void IoRegisterFileSystem(PDEVICE_OBJECT)`. Record that the FSD registered; no queue to maintain
/// (the executive routes named-pipe/file paths to the recorded device directly).
extern "win64" fn s_io_register_file_system(_dev: u64) {
    unsafe {
        let v = read_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *const u32);
        write_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *mut u32, v | V_REGFS);
    }
}

/// `void IoCompleteRequest(PIRP, CCHAR)`. Synchronous requests are reclaimed by `run_irp` after the
/// dispatch routine returns. A later peer operation can complete an older pending pipe IRP from
/// npfs's deferred list; reclaim that retained request graph here instead of leaking it forever.
extern "win64" fn s_io_complete_request(irp: u64, _boost: u64) {
    unsafe {
        // DIAGNOSTIC heartbeat: `NpCompleteDeferredIrps` walks a driver-built LIST_ENTRY chain, so a
        // corrupted (cyclic) deferred list becomes an unbounded completion loop with no other output.
        {
            IO_COMPLETE_CALLS += 1;
            if IO_COMPLETE_CALLS % 4096 == 0 {
                print_str(b"[fsd-complete-heartbeat] calls=");
                print_u64(IO_COMPLETE_CALLS);
                print_str(b" irp=");
                print_hex(irp as u32);
                print_str(b"\n");
            }
        }
        let table = &mut *core::ptr::addr_of_mut!(PENDING_IRPS);
        let Some(slot) = table.iter_mut().find(|entry| entry.irp == irp) else {
            if PEER_COMPLETION_TRACE_COUNT < 8 {
                PEER_COMPLETION_TRACE_COUNT += 1;
                print_str(b"[fsd-peer-complete] IRP=0x");
                print_hex((irp >> 32) as u32);
                print_hex(irp as u32);
                print_str(b" NOT in pending table\n");
            }
            return;
        };
        let status = read_unaligned((irp + 0x30) as *const u32);
        let information = read_unaligned((irp + 0x38) as *const u64);
        // BATCH 37/38: a completing pending READ carries the peer's just-written payload in its IRP
        // buffer. Stash those bytes keyed by the reader's fid so the executive's pipe re-drive delivers
        // them to the parked reader (a fresh re-drive read would miss — npfs already drained the queue
        // into THIS IRP). ★ BATCH 38 FIX: npfs's `NpWriteDataQueue` completing a *Buffered* read entry
        // does NOT copy into our original `slot.data` — it ALLOCATES a FRESH pool buffer, copies the
        // write payload into it, then REASSIGNS `WriteIrp->AssociatedIrp.SystemBuffer = Buffer` and sets
        // IRP_DEALLOCATE_BUFFER|IRP_BUFFERED_IO|IRP_INPUT_OPERATION (writesup.c:131-135). So the real
        // bytes live at the IRP's CURRENT AssociatedIrp.SystemBuffer (irp+0x18) — which npfs just
        // overwrote — NOT the stale `slot.data`. Reading `slot.data` returned 16 zero bytes (the
        // untouched original buffer), which is why rpcrt4 rejected the bind. Read irp+0x18 live.
        if slot.major as u64 == IRP_MJ_READ {
            let fid = slot.fid;
            // The buffer npfs actually filled = the IRP's CURRENT SystemBuffer (it may have reassigned
            // it). Fall back to our original buffer only if npfs left it in place.
            let sysbuf = read_unaligned((irp + 0x18) as *const u64);
            let irp_flags = read_unaligned((irp + 0x10) as *const u32);
            let ctable = &mut *core::ptr::addr_of_mut!(COMPLETED_READS);
            if let Some(cslot) = ctable.iter_mut().find(|e| e.fid == 0) {
                let length = (information as usize).min(COMPLETED_READ_BYTE_CAP);
                let source = if sysbuf != 0 { sysbuf } else { slot.data };
                let pool_end = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
                let source_valid = source >= FSD_POOL_VADDR + POOL_DATA_OFF
                    && source
                        .checked_add(length as u64)
                        .is_some_and(|end| end <= pool_end);
                cslot.fid = fid;
                cslot.status = if source_valid { status } else { 0xC000_0005 };
                cslot.info = if source_valid { information } else { 0 };
                cslot.length = if source_valid { length } else { 0 };
                if source_valid {
                    for index in 0..length {
                        cslot.bytes[index] = read_volatile((source + index as u64) as *const u8);
                    }
                }
            }
            // IoCompleteRequest normally owns a replacement SystemBuffer carrying
            // IRP_DEALLOCATE_BUFFER. Reclaim it while the component pool is mapped.
            if sysbuf != slot.data && irp_flags & 0x20 != 0 {
                pool_free(sysbuf);
            }
        } else if slot.major as u64 == IRP_MJ_WRITE {
            let fid = slot.fid;
            let completed = &mut *core::ptr::addr_of_mut!(COMPLETED_WRITES);
            if let Some(completed) = completed.iter_mut().find(|entry| entry.fid == 0) {
                completed.fid = fid;
                completed.status = status;
                completed.info = information;
            }
        }
        if PEER_COMPLETION_TRACE_COUNT < 8 {
            PEER_COMPLETION_TRACE_COUNT += 1;
            print_str(b"[fsd-peer-complete] major=");
            print_u64(slot.major as u64);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b" info=");
            print_u64(information);
            print_str(b"\n");
        }
        // The FSD pool exists only in the component VSpace. No graph pointer may escape this
        // callback for root-side reclamation.
        pool_free(slot.data);
        pool_free(slot.iosl);
        pool_free(slot.irp);
        // ★ The FILE_OBJECT is NOT freed here. It OUTLIVES the IRP: it belongs to the OPEN and npfs
        // keeps pointing at it (`Ccb->FileObject[end]`, written through on disconnect/close). Only a
        // transient FILE_OBJECT — one this IRP itself owns because the per-open table was full — dies
        // with the request. See [`FILE_OBJECTS`].
        if slot.owns_fo {
            pool_free(slot.file_object);
        }
        *slot = EMPTY_PENDING_IRP;
    }
}

// --- REAL VCB internals: the Unicode prefix table (name -> FCB), generic table, ERESOURCE ---------
//
// An FSD's DriverEntry runs its OWN `NpInitializeVcb`/`NpCreateRootDcb`, and every create/open runs
// its OWN `NpFsdCreate*` → `NpCreateFcb`/`NpCreateCcb`. Those exercise the prefix table + resource for
// REAL (the create path bug-checks on a NULL `RtlFindUnicodePrefix`, and create-then-connect must find
// the FCB by name). So these trampolines carry real host-side logic, backed by a fixed-capacity static
// table (no `alloc` in the isolated component). The prefix-MATCH contract is the host-tested
// [`nt_kernel_exec::np_prefix`] logic (component-prefix, case-insensitive, longest wins).
//
// `RtlInsertUnicodePrefix(Table, &Fcb->FullName, &Fcb->PrefixTableEntry)` records the entry pointer
// the FSD passed (so `RtlFindUnicodePrefix` can return the SAME pointer → `CONTAINING_RECORD` recovers
// the FCB). `RtlFindUnicodePrefix(Table, FullName, _)` returns the recorded entry of the longest name
// that is a component-prefix of `FullName`.

/// A recorded prefix-table entry: (the caller's `PUNICODE_PREFIX_TABLE_ENTRY`, the name VA, len-bytes).
/// The name is a `UNICODE_STRING.Buffer` (UTF-16); we read it live from the FSD's own pool at Find time.
#[derive(Clone, Copy)]
struct PrefixSlot {
    entry: u64, // the PUNICODE_PREFIX_TABLE_ENTRY the FSD passed to Insert (returned by Find)
    name_va: u64, // UNICODE_STRING.Buffer VA
    name_len: u16, // UNICODE_STRING.Length (bytes)
    used: bool,
}

const PREFIX_CAP: usize = 64;

/// The single VCB prefix table (npfs is a singleton driver). Lives in the executive image `.bss`
/// (shared into the component). Populated by `s_rtl_insert_unicode_prefix`, queried by
/// `s_rtl_find_unicode_prefix`. Reset by `s_rtl_init_unicode_prefix`.
static mut PREFIX_TABLE: [PrefixSlot; PREFIX_CAP] = [PrefixSlot {
    entry: 0,
    name_va: 0,
    name_len: 0,
    used: false,
}; PREFIX_CAP];

/// Copy a UNICODE_STRING.Buffer (UTF-16) into a fixed scratch for comparison. Returns the length in
/// u16 units (capped at the scratch size). Pipe names are short (`\ntsvcs` = 7).
unsafe fn read_ustr16(buf_va: u64, len_bytes: u16, out: &mut [u16]) -> usize {
    let n = ((len_bytes as usize) / 2).min(out.len());
    for i in 0..n {
        out[i] = read_unaligned((buf_va + (i as u64) * 2) as *const u16);
    }
    n
}

/// `void RtlInitializeUnicodePrefix(PUNICODE_PREFIX_TABLE)` — zero the control struct AND clear the
/// host-side table (the FSD calls this once at NpInitializeVcb before inserting the root DCB).
extern "win64" fn s_rtl_init_unicode_prefix(tbl: u64) {
    unsafe {
        if tbl != 0 {
            // UNICODE_PREFIX_TABLE (0x14 bytes): zero it (NodeTypeCode/NameLength/NextPrefixTree/…).
            write_unaligned(tbl as *mut u64, 0);
            write_unaligned((tbl + 8) as *mut u64, 0);
            write_unaligned((tbl + 16) as *mut u32, 0);
        }
        let table = &mut *core::ptr::addr_of_mut!(PREFIX_TABLE);
        for s in table.iter_mut() {
            *s = PrefixSlot {
                entry: 0,
                name_va: 0,
                name_len: 0,
                used: false,
            };
        }
    }
}

/// `BOOLEAN RtlInsertUnicodePrefix(PUNICODE_PREFIX_TABLE, PUNICODE_STRING Prefix,
/// PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry)`. Record (entry, name) so Find returns this entry for
/// names of which `Prefix` is a component-prefix. Returns TRUE unless a duplicate exact name exists.
extern "win64" fn s_rtl_insert_unicode_prefix(_tbl: u64, prefix: u64, entry: u64) -> u64 {
    if prefix == 0 || entry == 0 {
        return 0;
    }
    unsafe {
        let name_len = read_unaligned(prefix as *const u16); // UNICODE_STRING.Length
        let name_va = read_unaligned((prefix + 8) as *const u64); // UNICODE_STRING.Buffer
        let table = &mut *core::ptr::addr_of_mut!(PREFIX_TABLE);
        // dedup: an identical (case-insensitive) name already present → FALSE (the FSD bug-checks on
        // this, meaning it never re-creates the same pipe; our create arm rejects duplicates first).
        let mut new: [u16; 128] = [0; 128];
        let nn = read_ustr16(name_va, name_len, &mut new);
        for s in table.iter() {
            if !s.used {
                continue;
            }
            let mut ex: [u16; 128] = [0; 128];
            let en = read_ustr16(s.name_va, s.name_len, &mut ex);
            if en == nn
                && nt_kernel_exec::np_prefix::is_component_prefix(&ex[..en], &new[..nn])
                && nn == en
            {
                return 0; // duplicate
            }
        }
        for s in table.iter_mut() {
            if !s.used {
                *s = PrefixSlot {
                    entry,
                    name_va,
                    name_len,
                    used: true,
                };
                return 1;
            }
        }
    }
    0 // table full
}

/// `PUNICODE_PREFIX_TABLE_ENTRY RtlFindUnicodePrefix(PUNICODE_PREFIX_TABLE, PUNICODE_STRING FullName,
/// ULONG CaseInsensitiveIndex)`. Return the recorded entry of the longest inserted name that is a
/// component-prefix of `FullName` (NULL if none — the FSD bug-checks, but the root `\` always matches).
extern "win64" fn s_rtl_find_unicode_prefix(_tbl: u64, full: u64, _ci: u64) -> u64 {
    if full == 0 {
        return 0;
    }
    unsafe {
        let full_len = read_unaligned(full as *const u16);
        let full_va = read_unaligned((full + 8) as *const u64);
        let mut fbuf: [u16; 256] = [0; 256];
        let fn_ = read_ustr16(full_va, full_len, &mut fbuf);
        let table = &*core::ptr::addr_of!(PREFIX_TABLE);
        let mut best_entry = 0u64;
        let mut best_len = 0usize; // matched name length in u16 units
                                   // Compare against each used slot; keep the longest component-prefix.
        let mut cbuf: [u16; 128] = [0; 128];
        for s in table.iter() {
            if !s.used {
                continue;
            }
            let cn = read_ustr16(s.name_va, s.name_len, &mut cbuf);
            if nt_kernel_exec::np_prefix::is_component_prefix(&cbuf[..cn], &fbuf[..fn_])
                && cn >= best_len
            {
                best_len = cn;
                best_entry = s.entry;
            }
        }
        let _ = full_len;
        best_entry
    }
}

/// `void RtlInitializeGenericTable(PRTL_GENERIC_TABLE, ...)` — zero the 0x48-byte control struct +
/// stash the callbacks (the FSD's EventTable is only exercised on pipe-state-change notify — no live
/// consumer in bring-up, so a zeroing init suffices for it to be enumerable-empty).
extern "win64" fn s_rtl_init_generic_table(tbl: u64, cmp: u64, alloc: u64, free: u64, ctx: u64) {
    if tbl != 0 {
        unsafe {
            let mut i = 0u64;
            while i < 0x48 {
                write_unaligned((tbl + i) as *mut u64, 0);
                i += 8;
            }
            // RTL_GENERIC_TABLE: CompareRoutine@0x28, AllocateRoutine@0x30, FreeRoutine@0x38, Context@0x40.
            write_unaligned((tbl + 0x28) as *mut u64, cmp);
            write_unaligned((tbl + 0x30) as *mut u64, alloc);
            write_unaligned((tbl + 0x38) as *mut u64, free);
            write_unaligned((tbl + 0x40) as *mut u64, ctx);
        }
    }
}

/// `NTSTATUS ExInitializeResourceLite(PERESOURCE)` / `void KeInitializeSpinLock(PKSPIN_LOCK)` /
/// `KeInitializeEvent` / timers / DPCs — zero a small struct + return success. Single-threaded host.
extern "win64" fn s_init_small_struct(p: u64) -> i32 {
    if p != 0 {
        unsafe {
            let mut i = 0u64;
            while i < 0x38 {
                write_unaligned((p + i) as *mut u64, 0);
                i += 8;
            }
        }
    }
    0
}

/// `void KeInitializeSpinLock(PKSPIN_LOCK)` — a KSPIN_LOCK is pointer-sized storage.
extern "win64" fn s_ke_initialize_spin_lock(lock: u64) {
    unsafe {
        if lock != 0 {
            write_unaligned(lock as *mut u64, 0);
        }
    }
}

/// `KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK)` — single-threaded hosted drivers never spin, but
/// the lock's driver-visible storage records ownership until release.
extern "win64" fn s_ke_acquire_spin_lock_raise_to_dpc(lock: u64) -> u8 {
    unsafe {
        if lock != 0 {
            write_unaligned(lock as *mut u64, 1);
        }
    }
    0 // previous IRQL: PASSIVE_LEVEL
}

/// `void KeReleaseSpinLock(PKSPIN_LOCK, KIRQL)`.
extern "win64" fn s_ke_release_spin_lock(lock: u64, _old_irql: u8) {
    unsafe {
        if lock != 0 {
            write_unaligned(lock as *mut u64, 0);
        }
    }
}

/// `void KeInitializeEvent(PRKEVENT, EVENT_TYPE, BOOLEAN)`.
extern "win64" fn s_ke_initialize_event(event: u64, event_type: u32, state: u8) {
    if event == 0 {
        return;
    }
    let kind = if event_type == 1 {
        EventKind::Synchronization
    } else {
        EventKind::Notification
    };
    unsafe {
        kevent::init_kevent(event as *mut u8, kind, state != 0);
    }
}

/// `LONG KeSetEvent(PRKEVENT, KPRIORITY, BOOLEAN)`.
extern "win64" fn s_ke_set_event(event: u64, _increment: i32, _wait: u8) -> i32 {
    if event == 0 {
        return 0;
    }
    unsafe { kevent::kevent_set(event as *mut u8) as i32 }
}

/// `void KeClearEvent(PRKEVENT)`.
extern "win64" fn s_ke_clear_event(event: u64) {
    if event != 0 {
        unsafe {
            kevent::kevent_clear(event as *mut u8);
        }
    }
}

/// `NTSTATUS KeWaitForSingleObject(...)` for hosted-driver local dispatcher objects. The current
/// component transport cannot sleep inside an import trampoline, so unsatisfied waits report timeout
/// instead of fabricating success.
extern "win64" fn s_ke_wait_for_single_object(
    object: u64,
    _wait_reason: u32,
    _wait_mode: u32,
    _alertable: u8,
    _timeout: u64,
) -> i32 {
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_TIMEOUT: i32 = 0x0000_0102;
    if object == 0 {
        return 0xC000_000Du32 as i32; // STATUS_INVALID_PARAMETER
    }
    unsafe {
        if !kevent::kevent_read_state(object as *const u8) {
            return STATUS_TIMEOUT;
        }
        if kevent::kevent_kind(object as *const u8) == EventKind::Synchronization {
            kevent::kevent_clear(object as *mut u8);
        }
    }
    STATUS_SUCCESS
}

const KDPC_DEFERRED_ROUTINE_OFFSET: u64 = 0x18;
const KDPC_DEFERRED_CONTEXT_OFFSET: u64 = 0x20;
const KDPC_SYSTEM_ARGUMENT1_OFFSET: u64 = 0x28;
const KDPC_SYSTEM_ARGUMENT2_OFFSET: u64 = 0x30;
const KDPC_QUEUED_OFFSET: u64 = 0x38;
const KDPC_SIZE: u64 = 0x40;

unsafe fn clear_dpc_queue_projection(sh: u64) {
    write_volatile((sh + SH_DPC_QUEUE_HEAD) as *mut u64, 0);
    write_volatile((sh + SH_DPC_QUEUE_TAIL) as *mut u64, 0);
    write_volatile((sh + SH_DPC_QUEUE_DROPS) as *mut u64, 0);
    write_volatile((sh + SH_DPC_DELIVERIES) as *mut u64, 0);
    let mut slot = 0u64;
    while slot < SH_DPC_QUEUE_SLOTS {
        write_volatile(
            (sh + SH_DPC_QUEUE_BASE + slot * 8) as *mut u64,
            0,
        );
        slot += 1;
    }
}

/// `void KeInitializeDpc(PRKDPC, PKDEFERRED_ROUTINE, PVOID)`.
extern "win64" fn s_ke_initialize_dpc(dpc: u64, routine: u64, deferred_context: u64) {
    unsafe {
        if dpc == 0 {
            return;
        }
        core::ptr::write_bytes(dpc as *mut u8, 0, KDPC_SIZE as usize);
        write_unaligned((dpc + KDPC_DEFERRED_ROUTINE_OFFSET) as *mut u64, routine);
        write_unaligned(
            (dpc + KDPC_DEFERRED_CONTEXT_OFFSET) as *mut u64,
            deferred_context,
        );
    }
}

/// `BOOLEAN KeInsertQueueDpc(PRKDPC, PVOID, PVOID)` — queue state is represented in the driver-owned
/// KDPC projection so duplicate inserts are rejected deterministically.
extern "win64" fn s_ke_insert_queue_dpc(dpc: u64, arg1: u64, arg2: u64) -> u8 {
    unsafe {
        if dpc == 0
            || read_unaligned((dpc + KDPC_DEFERRED_ROUTINE_OFFSET) as *const u64) == 0
            || read_unaligned((dpc + KDPC_QUEUED_OFFSET) as *const u8) != 0
        {
            return 0;
        }
        let head = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_HEAD) as *const u64);
        let tail = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_TAIL) as *const u64);
        if tail.saturating_sub(head) >= SH_DPC_QUEUE_SLOTS {
            let drops = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_DROPS) as *const u64);
            write_volatile(
                (FSD_SHARED_VADDR + SH_DPC_QUEUE_DROPS) as *mut u64,
                drops.saturating_add(1),
            );
            return 0;
        }
        write_unaligned((dpc + KDPC_SYSTEM_ARGUMENT1_OFFSET) as *mut u64, arg1);
        write_unaligned((dpc + KDPC_SYSTEM_ARGUMENT2_OFFSET) as *mut u64, arg2);
        write_unaligned((dpc + KDPC_QUEUED_OFFSET) as *mut u8, 1);
        let slot = FSD_SHARED_VADDR + SH_DPC_QUEUE_BASE + (tail % SH_DPC_QUEUE_SLOTS) * 8;
        write_volatile(slot as *mut u64, dpc);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DPC_QUEUE_TAIL) as *mut u64,
            tail.saturating_add(1),
        );
    }
    1
}

unsafe fn fsd_drain_queued_dpcs() -> u64 {
    let mut inspected = 0u64;
    let mut delivered = 0u64;
    while inspected < SH_DPC_QUEUE_SLOTS {
        let head = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_HEAD) as *const u64);
        let tail = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_TAIL) as *const u64);
        if head == tail {
            break;
        }
        let slot = FSD_SHARED_VADDR + SH_DPC_QUEUE_BASE + (head % SH_DPC_QUEUE_SLOTS) * 8;
        let dpc = read_volatile(slot as *const u64);
        write_volatile(slot as *mut u64, 0);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DPC_QUEUE_HEAD) as *mut u64,
            head.saturating_add(1),
        );
        inspected += 1;
        if dpc == 0 {
            continue;
        }
        let routine = read_unaligned((dpc + KDPC_DEFERRED_ROUTINE_OFFSET) as *const u64);
        write_unaligned((dpc + KDPC_QUEUED_OFFSET) as *mut u8, 0);
        if routine == 0 {
            continue;
        }
        let context = read_unaligned((dpc + KDPC_DEFERRED_CONTEXT_OFFSET) as *const u64);
        let arg1 = read_unaligned((dpc + KDPC_SYSTEM_ARGUMENT1_OFFSET) as *const u64);
        let arg2 = read_unaligned((dpc + KDPC_SYSTEM_ARGUMENT2_OFFSET) as *const u64);
        let f: extern "win64" fn(u64, u64, u64, u64) =
            core::mem::transmute(routine as *const ());
        f(dpc, context, arg1, arg2);
        delivered += 1;
    }
    if delivered != 0 {
        let total = read_volatile((FSD_SHARED_VADDR + SH_DPC_DELIVERIES) as *const u64);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DPC_DELIVERIES) as *mut u64,
            total.saturating_add(delivered),
        );
    }
    delivered
}

/// `BOOLEAN ExAcquireResourceExclusiveLite(PERESOURCE, BOOLEAN Wait)` /
/// `ExAcquireResourceSharedLite` — uncontended single-threaded host: always granted.
extern "win64" fn s_acquire_resource(_res: u64, _wait: u64) -> u64 {
    1 // TRUE — acquired
}
/// `void ExReleaseResourceLite(PERESOURCE)` / `ExReleaseResourceForThreadLite` — no-op.
extern "win64" fn s_release_resource(_res: u64) {}

/// `void *memcpy(void *dst, const void *src, size_t n)` — REAL (RtlCopyMemory/RtlMoveMemory
/// macros compile to this; an unbound no-op silently corrupts every FCB name + file data buffer).
// memcpy / memset / RtlCompareMemory are pure, driver-agnostic byte primitives —
// shared with the Subsystem (win32k) class in [`crate::ntoskrnl_shared`] (bound by name below).

/// `WCHAR RtlUpcaseUnicodeChar(WCHAR)` — ASCII upcase (the pipe namespace is ASCII).
extern "win64" fn s_rtl_upcase_char(c: u64) -> u64 {
    let w = c as u16;
    if (b'a' as u16..=b'z' as u16).contains(&w) {
        (w - 32) as u64
    } else {
        w as u64
    }
}

/// `PGENERIC_MAPPING IoGetFileObjectGenericMapping()` — a static all-zero GENERIC_MAPPING is fine for
/// SeAssignSecurity in a host with no live access checks. Points at the KPCR placeholder page (zeroed).
extern "win64" fn s_generic_mapping() -> u64 {
    FSD_KPCR_VA
}

/// `NTSTATUS SeAssignSecurity(...)` — write a fake non-null SD pointer to *NewDescriptor (arg3) and
/// return SUCCESS. No live access checks in the host; the SD is only cached + stored on the FCB.
extern "win64" fn s_se_assign_security(
    _parent: u64,
    _explicit: u64,
    new_desc: u64,
    _is_dir: u64,
    _subj: u64,
    _map: u64,
    _pool: u64,
) -> i32 {
    unsafe {
        if new_desc != 0 {
            write_unaligned(new_desc as *mut u64, pool_alloc(0x40)); // a zeroed SD blob
        }
    }
    0
}

/// `NTSTATUS ObLogSecurityDescriptor(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *Cached, ULONG)` —
/// echo the input as the cached SD, return SUCCESS.
extern "win64" fn s_ob_log_sd(input: u64, cached_out: u64, _refbias: u64) -> i32 {
    unsafe {
        if cached_out != 0 {
            write_unaligned(cached_out as *mut u64, input);
        }
    }
    0
}

/// `PEPROCESS PsGetCurrentProcess()` / `PsGetCurrentThread()` — a fake non-null object pointer.
extern "win64" fn s_current_process() -> u64 {
    FSD_DATA_VADDR // a mapped, zeroed placeholder page
}

/// `PVOID IoGetCurrentProcess()` — same as above.
extern "win64" fn s_io_get_current_process() -> u64 {
    FSD_DATA_VADDR
}

/// Serial debug print forwarder (`vDbgPrintExWithPrefix` etc.) — swallow.
extern "win64" fn s_dbg_print() -> i32 {
    0
}

// --- the SHARED ntoskrnl export surface (registration-driven, the win32k model) ---------------

/// The FSD's ntoskrnl-import registry: a heap-free `name -> trampoline-VA` map (the SHARED
/// `nt-compat-exports` mechanism). The executive binds each `s_*` trampoline by name; the PE loader
/// resolves the FSD's IAT through [`fsd_export_addr`]. Reusable for the next FSD (fastfat) unchanged.
static mut FSD_EXPORTS: DriverExportRegistry = DriverExportRegistry::new();
static mut FSD_EXPORTS_READY: bool = false;

/// Bind the FSD ntoskrnl trampolines into [`FSD_EXPORTS`]. Idempotent (`bind` updates in place).
fn register_fsd_trampolines() {
    // SAFETY: single-threaded executive; the registry is only touched here + in fsd_export_addr.
    let reg = unsafe { &mut *core::ptr::addr_of_mut!(FSD_EXPORTS) };
    // pool (ExAllocatePool* → the FSD arena)
    reg.bind("ExAllocatePoolWithTag", s_ex_alloc_pool_tag as usize as u64);
    reg.bind(
        "ExAllocatePoolWithQuotaTag",
        s_ex_alloc_pool_quota_tag as usize as u64,
    );
    reg.bind("ExAllocatePool", s_ex_alloc_pool as usize as u64);
    reg.bind("ExFreePoolWithTag", s_ex_free_pool_tag as usize as u64);
    reg.bind("ExFreePool", s_ex_free_pool as usize as u64);
    // Rtl string init
    reg.bind(
        "RtlInitUnicodeString",
        s_rtl_init_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlInitEmptyUnicodeString",
        s_rtl_init_empty_unicode_string as usize as u64,
    );
    // Io device/registration (control DEVICE_OBJECT + FS registration)
    reg.bind("IoCreateDevice", s_io_create_device as usize as u64);
    reg.bind(
        "IoDeleteDevice",
        s_io_delete_device as *const () as usize as u64,
    );
    reg.bind(
        "IoAttachDeviceToDeviceStack",
        s_io_attach_device_to_device_stack as *const () as usize as u64,
    );
    reg.bind(
        "IoDetachDevice",
        s_io_detach_device as *const () as usize as u64,
    );
    reg.bind(
        "IoGetCurrentIrpStackLocation",
        s_io_get_current_irp_stack_location as *const () as usize as u64,
    );
    reg.bind(
        "IoGetNextIrpStackLocation",
        s_io_get_next_irp_stack_location as *const () as usize as u64,
    );
    reg.bind(
        "IoCopyCurrentIrpStackLocationToNext",
        s_io_copy_current_irp_stack_location_to_next as *const () as usize as u64,
    );
    reg.bind(
        "IoSkipCurrentIrpStackLocation",
        s_io_skip_current_irp_stack_location as *const () as usize as u64,
    );
    reg.bind(
        "IofCallDriver",
        s_iof_call_driver as *const () as usize as u64,
    );
    reg.bind(
        "IoCallDriver",
        s_iof_call_driver as *const () as usize as u64,
    );
    reg.bind(
        "PoCallDriver",
        s_po_call_driver as *const () as usize as u64,
    );
    reg.bind(
        "PoStartNextPowerIrp",
        s_po_start_next_power_irp as *const () as usize as u64,
    );
    reg.bind(
        "PoSetPowerState",
        s_po_set_power_state as *const () as usize as u64,
    );
    reg.bind(
        "IoGetDmaAdapter",
        s_io_get_dma_adapter as *const () as usize as u64,
    );
    reg.bind(
        "IoAllocateMdl",
        s_io_allocate_mdl as *const () as usize as u64,
    );
    reg.bind("IoFreeMdl", s_io_free_mdl as *const () as usize as u64);
    reg.bind(
        "MmBuildMdlForNonPagedPool",
        s_mm_build_mdl_for_nonpaged_pool as *const () as usize as u64,
    );
    reg.bind(
        "MmMapLockedPagesSpecifyCache",
        s_mm_map_locked_pages_specify_cache as *const () as usize as u64,
    );
    reg.bind(
        "MmMapIoSpace",
        s_mm_map_io_space as *const () as usize as u64,
    );
    reg.bind(
        "MmUnmapIoSpace",
        s_mm_unmap_io_space as *const () as usize as u64,
    );
    reg.bind(
        "IoConnectInterrupt",
        s_io_connect_interrupt as *const () as usize as u64,
    );
    reg.bind(
        "IoDisconnectInterrupt",
        s_io_disconnect_interrupt as *const () as usize as u64,
    );
    reg.bind(
        "IoCreateSymbolicLink",
        s_io_create_symbolic_link as usize as u64,
    );
    reg.bind(
        "IoDeleteSymbolicLink",
        s_io_delete_symbolic_link as *const () as usize as u64,
    );
    reg.bind(
        "IoRegisterFileSystem",
        s_io_register_file_system as usize as u64,
    );
    reg.bind("IoCompleteRequest", s_io_complete_request as usize as u64);
    // npfs.sys's PE actually imports the fastcall alias `IofCompleteRequest` (the `IoCompleteRequest`
    // macro compiles to it). On x64 there is ONE calling convention, so `Irp`/`PriorityBoost` still
    // arrive in RCX/RDX — the same `extern "win64"` trampoline serves both. Without THIS binding the
    // import fell to the `s_true` fail-soft no-op: when a peer WRITE satisfied a pending pipe READ,
    // npfs's `NpCompleteDeferredIrps` "completed" the read IRP into a no-op, so the executive never
    // learned the read finished (never stashed the delivered bytes), and the re-drive fresh read hit
    // the drained queue and returned uninitialized pool (`d0 16 d0 16 …`). BATCH 38 root cause.
    reg.bind("IofCompleteRequest", s_io_complete_request as usize as u64);
    // Rtl Unicode prefix table (nt_kernel_exec::np_prefix) — the VCB name→FCB map
    reg.bind(
        "RtlInitializeUnicodePrefix",
        s_rtl_init_unicode_prefix as usize as u64,
    );
    reg.bind(
        "RtlInsertUnicodePrefix",
        s_rtl_insert_unicode_prefix as usize as u64,
    );
    reg.bind(
        "RtlFindUnicodePrefix",
        s_rtl_find_unicode_prefix as usize as u64,
    );
    reg.bind(
        "RtlInitializeGenericTable",
        s_rtl_init_generic_table as usize as u64,
    );
    // ERESOURCE acquire/release (uncontended single-threaded host)
    reg.bind(
        "ExAcquireResourceExclusiveLite",
        s_acquire_resource as usize as u64,
    );
    reg.bind(
        "ExAcquireResourceSharedLite",
        s_acquire_resource as usize as u64,
    );
    reg.bind(
        "ExAcquireSharedStarveExclusive",
        s_acquire_resource as usize as u64,
    );
    reg.bind(
        "ExAcquireSharedWaitForExclusive",
        s_acquire_resource as usize as u64,
    );
    reg.bind("ExReleaseResourceLite", s_release_resource as usize as u64);
    reg.bind(
        "ExReleaseResourceForThreadLite",
        s_release_resource as usize as u64,
    );
    // The driver's OWN consistency bugchecks (npfs' `NpBugCheck`) — caught + reported + unwound,
    // never skipped. Previously an UNBOUND import resolving to the fail-soft `s_true` no-op.
    if crate::KEBUGCHECK_BOUND {
        reg.bind("KeBugCheckEx", s_ke_bug_check_ex as usize as u64);
    }
    // CRT / Rtl mem intrinsics (REAL — silent corruption otherwise)
    reg.bind("memcpy", s_memcpy as usize as u64);
    reg.bind("memmove", s_memcpy as usize as u64);
    reg.bind("RtlCopyMemory", s_memcpy as usize as u64);
    reg.bind("RtlMoveMemory", s_memcpy as usize as u64);
    reg.bind("memset", s_memset as usize as u64);
    reg.bind("RtlFillMemory", s_memset as usize as u64);
    reg.bind("RtlCompareMemory", s_rtl_compare_memory as usize as u64);
    reg.bind(
        "RtlCompareMemoryUlong",
        s_rtl_compare_memory as usize as u64,
    );
    reg.bind("RtlUpcaseUnicodeChar", s_rtl_upcase_char as usize as u64);
    // small-struct init (spinlock/event/timer/dpc/mutex/semaphore/ERESOURCE init)
    reg.bind(
        "ExInitializeResourceLite",
        s_init_small_struct as usize as u64,
    );
    reg.bind(
        "KeInitializeSpinLock",
        s_ke_initialize_spin_lock as *const () as usize as u64,
    );
    reg.bind(
        "KeAcquireSpinLockRaiseToDpc",
        s_ke_acquire_spin_lock_raise_to_dpc as *const () as usize as u64,
    );
    reg.bind(
        "KeReleaseSpinLock",
        s_ke_release_spin_lock as *const () as usize as u64,
    );
    reg.bind(
        "KeReleaseSpinLockFromDpcLevel",
        s_ke_release_spin_lock as *const () as usize as u64,
    );
    reg.bind(
        "KeInitializeEvent",
        s_ke_initialize_event as *const () as usize as u64,
    );
    reg.bind(
        "KeSetEvent",
        s_ke_set_event as *const () as usize as u64,
    );
    reg.bind(
        "KeClearEvent",
        s_ke_clear_event as *const () as usize as u64,
    );
    reg.bind(
        "KeWaitForSingleObject",
        s_ke_wait_for_single_object as *const () as usize as u64,
    );
    reg.bind("KeInitializeTimer", s_init_small_struct as usize as u64);
    reg.bind(
        "KeInitializeDpc",
        s_ke_initialize_dpc as *const () as usize as u64,
    );
    reg.bind(
        "KeInsertQueueDpc",
        s_ke_insert_queue_dpc as *const () as usize as u64,
    );
    reg.bind("ExInitializeFastMutex", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeMutex", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeSemaphore", s_init_small_struct as usize as u64);
    // Se / Ob security helpers
    reg.bind(
        "IoGetFileObjectGenericMapping",
        s_generic_mapping as usize as u64,
    );
    reg.bind("SeAssignSecurity", s_se_assign_security as usize as u64);
    reg.bind("ObLogSecurityDescriptor", s_ob_log_sd as usize as u64);
    // Ps/Io current-object identity
    reg.bind("PsGetCurrentProcess", s_current_process as usize as u64);
    reg.bind("PsGetCurrentThread", s_current_process as usize as u64);
    reg.bind("KeGetCurrentThread", s_current_process as usize as u64);
    reg.bind(
        "IoGetCurrentProcess",
        s_io_get_current_process as usize as u64,
    );
    // Debug print forwarders
    reg.bind("vDbgPrintExWithPrefix", s_dbg_print as usize as u64);
    reg.bind("vDbgPrintEx", s_dbg_print as usize as u64);
    reg.bind("DbgPrint", s_dbg_print as usize as u64);
    reg.bind("DbgPrintEx", s_dbg_print as usize as u64);
}

/// Resolve an FSD ntoskrnl/hal/fsrtl import NAME to its IAT-slot trampoline VA through the SHARED
/// [`DriverExportRegistry`]. Registered names resolve to their real trampoline; genuine no-ops
/// (release/delete/deref/exit-fs) resolve to `s_zero`; everything else falls back to `s_true` (a
/// benign non-crashing 1-returner) — DriverEntry's init path is broad but shallow, so unknown calls
/// that just return success let it proceed to fill the MJ table. FLAG (serial-logged in the loader)
/// each unbound name so the surface is auditable.
pub fn fsd_export_addr(name: &str) -> u64 {
    // SAFETY: single-threaded; the registry is populated once (lazily) and read-only thereafter.
    unsafe {
        if !FSD_EXPORTS_READY {
            register_fsd_trampolines();
            FSD_EXPORTS_READY = true;
        }
        if let Some(va) = (*core::ptr::addr_of!(FSD_EXPORTS)).lookup(name) {
            return va;
        }
    }
    // DIAGNOSTIC: log each import that falls to a fail-soft stub, so the FSD's unbound surface is
    // auditable (the doc above always claimed this; it was never actually printed).
    unsafe {
        if FSD_UNBOUND_LOGGED < 48 {
            FSD_UNBOUND_LOGGED += 1;
            print_str(b"[fsd-import] UNBOUND ");
            for &b in name.as_bytes() {
                debug_put_char(b);
            }
            print_str(b"\n");
        }
    }
    // Genuine no-ops (release resource / lock / free / deref / exit-fs / etc.): return 0.
    if name.starts_with("Ex") && (name.contains("Release") || name.contains("Delete"))
        || name.starts_with("Ke") && name.contains("Release")
        || name.starts_with("Fs")
        || name.starts_with("Ob") && (name.contains("Dereference") || name.contains("Reference"))
        || name.starts_with("Se") && name.contains("Unlock")
    {
        return s_zero as usize as u64;
    }
    s_true as usize as u64 // fail-soft default (auditable — the loader logs unbound names)
}

// --- the FSD component entry -----------------------------------------------------------------

/// The generic FSD host-component entry. NOW RUNS ON THE SHARED HARNESS: it delegates the whole
/// DriverEntry-preamble → dispatch-loop shape to [`crate::spawn_hosts::component_main`], plugging the
/// FSD's IRP router ([`fsd_dispatch`]) as the per-request callback, a no-op-plus-diagnostics
/// [`fsd_post_driver_entry`], and the FSD [`DriverObjectSpec`] (size 0x150, DriverExtension pointer
/// @0x30, DriverUnload @0x68, MajorFunction @0x70). The bespoke inline
/// `dispatch_loop`/`send_done`/`recv_req` are retired
/// in favour of the harness's shared implementation (one [`call_on`] per dispatch). This is the
/// component-side leg of the FSD's migration onto the unified harness (Phase B, Step 2). The
/// named-pipe provider and each service-selected FSD instance share this entry, so all of them run
/// on the harness.
/// Runs in the isolated component's VSpace (executive image mapped RWX-shared).
#[no_mangle]
#[link_section = ".text.fsd_component_entry"]
pub unsafe extern "C" fn fsd_component_entry() -> ! {
    let entry_rva = read_volatile((FSD_SHARED_VADDR + SH_ENTRY_RVA) as *const u64) as u32;
    print_str(b"[fsd-host] START DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");

    // The x64 DRIVER_OBJECT is 0x150 bytes: Type@0=4, Size@2, DriverExtension ptr @0x30 (ext block
    // 0x50), DriverUnload@0x68, MajorFunction[]@0x70 (28 entries * 8 = 0xE0 → ends at 0x150).
    // Hand the whole preamble + persistent recv→dispatch→reply loop to the SHARED harness.
    crate::spawn_hosts::component_main(
        FSD_SHARED_VADDR,
        FSD_CODE_VA,
        crate::spawn_hosts::DriverObjectSpec {
            size: WDM_X64_DRIVER_OBJECT_SIZE as u64,
            size_field: WDM_X64_DRIVER_OBJECT_SIZE as u16,
            ext_size: WDM_X64_DRIVER_EXTENSION_SIZE as u64,
            mj: WDM_X64_DRIVER_MAJOR_FUNCTION_OFFSET as u64,
            mj_table_off: SH_MJ_TABLE, // 0x18 — the FSD records its MajorFunction[] base here
            pool: pool_alloc,
        },
        SH_REQ_STATUS,      // FSD status offset (0x70)
        FSD_DISPATCH_LABEL, // 0x771
        fsd_dispatch,       // major → MajorFunction[major] → run_irp
        fsd_post_driver_entry,
    )
}

/// FSD `post_driver_entry` (runs between DriverEntry and the FIRST `send_done`, exactly as the old
/// inline path): record the pool high-water for diagnostics + emit the DriverEntry-returned line. The
/// verdict/status/MJ-table were already recorded by `component_main`; this only adds the FSD's
/// diagnostic prints so the boot serial keeps its `[fsd-host] DriverEntry returned ...` line.
unsafe fn fsd_post_driver_entry(status: i32, drv: u64) {
    let mj_create = read_unaligned((drv + 0x70) as *const u64);
    let driver_unload = read_unaligned((drv + WDM_X64_DRIVER_UNLOAD_OFFSET as u64) as *const u64);
    let driver_extension =
        read_unaligned((drv + WDM_X64_DRIVER_EXTENSION_OFFSET as u64) as *const u64);
    let add_device = if driver_extension == 0 {
        0
    } else {
        read_unaligned(
            (driver_extension + WDM_X64_DRIVER_EXTENSION_ADD_DEVICE_OFFSET) as *const u64,
        )
    };
    let v = read_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *const u32);
    write_volatile((FSD_SHARED_VADDR + SH_DRVOBJ) as *mut u64, drv);
    write_volatile(
        (FSD_SHARED_VADDR + SH_DRIVER_UNLOAD) as *mut u64,
        driver_unload,
    );
    write_volatile((FSD_SHARED_VADDR + SH_ADD_DEVICE) as *mut u64, add_device);
    // Pool high-water (diagnostic; not read by the executive — parity with the old inline entry).
    let pool_used = read_volatile(FSD_POOL_VADDR as *const u64);
    write_volatile((FSD_SHARED_VADDR + SH_POOL_USED) as *mut u64, pool_used);
    print_str(b"[fsd-host] DriverEntry returned status=0x");
    print_hex(status as u32);
    print_str(b" verdict=0x");
    print_hex(v);
    print_str(b" mj_create=0x");
    print_hex((mj_create >> 32) as u32);
    print_hex(mj_create as u32);
    if add_device != 0 {
        print_str(b" add_device=0x");
        print_hex((add_device >> 32) as u32);
        print_hex(add_device as u32);
    }
    print_str(b"\n");
}

/// The FSD IRP router — the `dispatch` callback plugged into [`crate::spawn_hosts::component_main`].
/// Reads the request's IRP major from `req.sel`, looks up `DriverObject->MajorFunction[major]`, and
/// runs the driver's handler via [`run_irp`] in this component's context. Returns `(status, info)`.
/// This is the EXACT body the retired inline `dispatch_loop` ran per request.
unsafe fn fsd_dispatch(req: &crate::spawn_hosts::DispatchReq) -> (i32, u64) {
    let major = req.sel;
    if major == FSD_DISPATCH_UNLOAD {
        let unload = read_volatile((req.drv + WDM_X64_DRIVER_UNLOAD_OFFSET as u64) as *const u64);
        if unload == 0 {
            return (0xC000_0010u32 as i32, 0); // STATUS_INVALID_DEVICE_REQUEST
        }
        let f: extern "win64" fn(u64) = core::mem::transmute(unload as *const ());
        f(req.drv);
        return (0, 0);
    }
    if major == FSD_DISPATCH_INTERRUPT {
        let interrupt_id = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
        let vector = read_volatile((FSD_SHARED_VADDR + SH_REQ_MINOR) as *const u64);
        let expected_id = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ID) as *const u64);
        let expected_vector =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32);
        let interrupt_object =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_OBJECT) as *const u64);
        let service_routine =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ROUTINE) as *const u64);
        let service_context =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_CONTEXT) as *const u64);
        if interrupt_id == 0
            || interrupt_id != expected_id
            || expected_vector == 0
            || vector != expected_vector as u64
            || interrupt_object == 0
            || service_routine == 0
        {
            return (0xC000_0010u32 as i32, 0); // STATUS_INVALID_DEVICE_REQUEST
        }
        let isr: extern "win64" fn(u64, u64) -> u8 =
            core::mem::transmute(service_routine as *const ());
        let claimed = isr(interrupt_object, service_context);
        let _ = fsd_drain_queued_dpcs();
        let deliveries =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_DELIVERIES) as *const u64);
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_DELIVERED_VECTOR) as *mut u64,
            vector,
        );
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ISR_CLAIMED) as *mut u64,
            (claimed != 0) as u64,
        );
        write_volatile(
            (FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_DELIVERIES) as *mut u64,
            deliveries.saturating_add(1),
        );
        return (0, (claimed != 0) as u64);
    }
    if major == FSD_DISPATCH_ADD_DEVICE {
        let add_device = read_volatile((FSD_SHARED_VADDR + SH_ADD_DEVICE) as *const u64);
        if add_device == 0 {
            return (0xC000_0010u32 as i32, 0); // STATUS_INVALID_DEVICE_REQUEST
        }
        let projection = match crate::hosted_driver_projection::create_hosted_device_projection(
            0,
            0,
            DeviceType::UNKNOWN.0,
            pool_alloc,
            pool_free,
        ) {
            Ok(projection) => projection,
            Err(status) => return (status, 0),
        };
        let pdo = projection.device_object();
        write_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *mut u64, pdo);
        write_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *mut u64, 0);
        let add: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
        let status = add(req.drv, pdo);
        let fdo = read_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *const u64);
        return (status, fdo);
    }
    let mj_base = req.drv + 0x70;
    let handler = read_volatile((mj_base + major * 8) as *const u64);
    if handler != 0 {
        run_irp(major, handler)
    } else {
        (0xC000_0002u32 as i32, 0) // STATUS_NOT_IMPLEMENTED
    }
}

/// ★ The COMPONENT half of the `Call`/reply-object dispatch transport
/// (`docs/transport-migration.md` §3.1): ONE `seL4_Call(CT_FAULT, msginfo)` that **publishes this
/// dispatch's completion AND returns the next request as its reply value**.
///
/// It REPLACED the hand-rolled `send_done_on` + `recv_req_on` Send/Recv pair (both deleted), and
/// with them the whole class of defects that pair had:
/// * there is no gap between "completion published" and "ready to receive" in which the executive's
///   wake could block — after a `Call` the component is `BlockedOnReply` from the instant the kernel
///   pairs it, with no user-visible window;
/// * the answer cannot be someone else's: the kernel binds the executive's reply object to THIS
///   caller (`endpoint.rs::finish_call` → `replies[i].bound_tcb = Some(sender)`), and the component
///   physically cannot publish a second completion before being replied to.
///
/// Returns `(label, mr0..mr3)` of the executive's reply — the label distinguishes a dispatch request
/// from win32k's callback-resume signal. Outgoing message length is whatever `msginfo` encodes (we
/// only ever send a bare label, length 0).
#[inline(never)]
pub(crate) unsafe fn call_on(msginfo: u64) -> (u64, u64, u64, u64, u64) {
    let reply_info: u64;
    let m0: u64;
    let m1: u64;
    let m2: u64;
    let m3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_CALL as u64,
        inout("rdi") crate::CT_FAULT => _,
        inout("rsi") msginfo => reply_info,
        inout("r10") 0u64 => m0,
        inout("r8") 0u64 => m1,
        inout("r9") 0u64 => m2,
        inout("r15") 0u64 => m3,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (reply_info >> 12, m0, m1, m2, m3)
}

/// Build a real IRP + IO_STACK_LOCATION + FILE_OBJECT (buffered I/O) and invoke the FSD's
/// `MajorFunction[major]` handler. The pipe/file name (UTF-16) rides in the ARG frame ([SH_REQ_INLEN]
/// bytes); the FILE_OBJECT's FileName points at it. Returns (status, information).
///
/// x64 layouts (references/nt5 io.h): FILE_OBJECT { DeviceObject@8, FsContext@0x18, FsContext2@0x20,
/// RelatedFileObject@0x40, FileName(UNICODE_STRING)@0x58 }. IRP { IoStatus@0x30, CurrentLocation
/// (CCHAR)@0x42, StackCount@0x43, AssociatedIrp.SystemBuffer@0x18, UserBuffer@0x70,
/// Tail.Overlay.CurrentStackLocation@0xb8 }. IO_STACK_LOCATION { Major@0, Minor@1, Parameters(union)
/// @0x08, DeviceObject@0x20, FileObject@0x30 }.
unsafe fn run_irp(major: u64, handler: u64) -> (i32, u64) {
    let devobj = read_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *const u64);
    let minor = read_volatile((FSD_SHARED_VADDR + SH_REQ_MINOR) as *const u64);
    let inlen = read_volatile((FSD_SHARED_VADDR + SH_REQ_INLEN) as *const u64);
    let outlen = read_volatile((FSD_SHARED_VADDR + SH_REQ_OUTLEN) as *const u64);
    let fsctl = read_volatile((FSD_SHARED_VADDR + SH_REQ_FSCTL) as *const u64);

    let file_id = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
    let uses_file_object = major != IRP_MJ_PNP;

    // ★ Audit the CCB's data queues (and the FILE_OBJECTs npfs holds) BEFORE handing it an IRP.
    // npfs' own ASSERTs over these invariants are compiled out of the release binary, and a broken
    // one is a call-free infinite spin inside `NpGetNextRealDataQueueEntry` that freezes the whole
    // boot. See [`audit_ccb`].
    if uses_file_object {
        audit_ccb(file_id);
    }

    // FILE_OBJECT — ONE per OPEN, reused by every IRP on that open, freed at CLEANUP/CLOSE.
    // A FILE_OBJECT outlives the IRP that introduced it (npfs stores it in `Ccb->FileObject[end]`
    // and writes through that pointer on disconnect), so it must NOT be rebuilt/freed per request.
    let existing = if uses_file_object && crate::FSD_FILE_OBJECT_PER_OPEN {
        fo_lookup(file_id)
    } else {
        0
    };
    let owns_fo = uses_file_object && existing == 0;
    let fo = if !uses_file_object {
        0
    } else if owns_fo {
        pool_alloc(WDM_X64_FILE_OBJECT_SIZE as u64)
    } else {
        existing
    };
    if uses_file_object && fo == 0 {
        return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
    }
    if owns_fo {
        let fo_bytes = core::slice::from_raw_parts_mut(fo as *mut u8, WDM_X64_FILE_OBJECT_SIZE);
        if write_wdm_file_object(
            fo_bytes,
            WdmFileObjectInit {
                device_object: devobj,
                fs_context: file_id,
                file_name_len: inlen as u16,
                file_name_max_len: (inlen + 2) as u16,
                file_name_buffer: FSD_ARG_VADDR,
            },
        )
        .is_err()
        {
            pool_free(fo);
            return (0xC000_000Du32 as i32, 0); // STATUS_INVALID_PARAMETER
        }
    } else if uses_file_object {
        // The open's FILE_OBJECT: npfs owns its contents (FsContext/FsContext2/Flags/PrivateCacheMap
        // were set by `NpSetFileObject` at create time and must persist). Leave them alone.
        FSD_FO_REUSED.fetch_add(1, Ordering::Relaxed);
    }

    // Give every request its own buffered-I/O storage. The ARG frame is transport scratch and is
    // overwritten by the next dispatch, so it cannot back an IRP retained in an npfs data queue.
    let data_len = inlen.max(outlen).max(1);
    let data_capacity = (data_len + 7) & !7;
    let data = pool_alloc(data_capacity);
    if data == 0 {
        if owns_fo {
            pool_free(fo);
        }
        return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
    }
    zero(data, data_capacity);
    let mut data_index = 0u64;
    while data_index < inlen {
        let byte = read_volatile((FSD_ARG_VADDR + data_index) as *const u8);
        write_volatile((data + data_index) as *mut u8, byte);
        data_index += 1;
    }

    // IO_STACK_LOCATION. Parameters union @ +0x08:
    // Create/CreatePipe: SecurityContext@+0x08, Options@+0x10, ShareAccess@+0x1a, Parameters@+0x20.
    // Read/Write: Length@+0x08. SetFile: Length@+0x08, FileInformationClass@+0x10.
    // FS/DeviceControl: OutputBufferLength@+0x08, InputBufferLength@+0x10, IoControlCode@+0x18.
    let iosl_len = if major == IRP_MJ_PNP {
        WDM_X64_IO_STACK_LOCATION_SIZE as u64 * 2
    } else {
        WDM_X64_IO_STACK_LOCATION_SIZE as u64
    };
    let iosl = pool_alloc(iosl_len);
    if iosl == 0 {
        pool_free(data);
        if owns_fo {
            pool_free(fo);
        }
        return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
    }
    let current_iosl = if major == IRP_MJ_PNP {
        iosl + WDM_X64_IO_STACK_LOCATION_SIZE as u64
    } else {
        iosl
    };
    let mut pnp_resource_list = 0u64;
    let stack_parameters = match major {
        0 | 1 => {
            // IRP_MJ_CREATE (client open) / IRP_MJ_CREATE_NAMED_PIPE (server create). The FSD derefs
            // SecurityContext->{AccessState,DesiredAccess}, Options (disposition<<24), ShareAccess, and
            // (create-named-pipe only) the NAMED_PIPE_CREATE_PARAMETERS. Build valid blocks from the pool.
            let sec_ctx = pool_alloc(0x20); // IO_SECURITY_CONTEXT {SecurityQos,AccessState,DesiredAccess,FullCreateOptions}
            let access_state = pool_alloc(0x80); // ACCESS_STATE — FSD reads AccessState->{SecurityDescriptor,SubjectSecurityContext}
            zero(sec_ctx, 0x20);
            zero(access_state, 0x80);
            write_unaligned((sec_ctx + 0x08) as *mut u64, access_state); // AccessState
            write_unaligned((sec_ctx + 0x10) as *mut u32, 0x001F_01FF); // DesiredAccess = all
            write_unaligned((iosl + 0x08) as *mut u64, sec_ctx); // SecurityContext
                                                                 // Options: Disposition in the high byte, CreateOptions in the low 24.
                                                                 // BATCH 37: CREATE_NAMED_PIPE must use FILE_OPEN_IF (3), NOT FILE_CREATE (2) — this is
                                                                 // exactly what Win32 CreateNamedPipe / NtCreateNamedPipeFile pass (kernel32 npipe.c:393).
                                                                 // npfs's NpCreateExistingNamedPipe (create.c:594) returns STATUS_ACCESS_DENIED for a 2nd+
                                                                 // instance opened with FILE_CREATE, while FILE_OPEN_IF opens-or-creates for both the new
                                                                 // FCB (NpCreateNewNamedPipe accepts anything but FILE_OPEN) AND every subsequent instance.
                                                                 // With FILE_CREATE the SCM listener's post-accept `rpcrt4_conn_create_pipe` re-create
                                                                 // (2nd \ntsvcs instance) failed → its re-listen failed → the rpcrt4 server thread entered
                                                                 // shutdown and called rpcrt4_conn_close_read on the just-handed-off connection, setting
                                                                 // conn->read_closed=1, so the per-connection worker's rpcrt4_conn_np_read skipped NtReadFile
                                                                 // and the bind was never read. Client opens (major 0) still use FILE_OPEN (1).
            let disposition: u32 = if major == 1 { 3 } else { 1 }; // create-named-pipe=FILE_OPEN_IF, open=FILE_OPEN
            let named_pipe_parameters = if major == 1 {
                // NAMED_PIPE_CREATE_PARAMETERS (0x28 bytes): NamedPipeType@0, ReadMode@4, CompletionMode@8,
                // MaximumInstances@0xc, InboundQuota@0x10, OutboundQuota@0x14, DefaultTimeout@0x18 (LI, must
                // be < 0 = relative), TimeoutSpecified@0x20 (BOOLEAN, must be TRUE + MaximumInstances != 0).
                let params = pool_alloc(0x28);
                zero(params, 0x28);
                write_unaligned((params + 0x00) as *mut u32, 1); // NamedPipeType = FILE_PIPE_MESSAGE_TYPE
                write_unaligned((params + 0x04) as *mut u32, 1); // ReadMode = message
                write_unaligned((params + 0x08) as *mut u32, 0); // CompletionMode = queue
                write_unaligned((params + 0x0c) as *mut u32, 0xFF); // MaximumInstances = unlimited-ish
                write_unaligned((params + 0x10) as *mut u32, 0x1000); // InboundQuota
                write_unaligned((params + 0x14) as *mut u32, 0x1000); // OutboundQuota
                write_unaligned((params + 0x18) as *mut i64, -50_000_000i64); // DefaultTimeout = -5s (relative)
                write_unaligned((params + 0x20) as *mut u8, 1); // TimeoutSpecified = TRUE
                Some(params)
            } else {
                None
            };
            WdmIoStackParameters::Create {
                security_context: sec_ctx,
                options: disposition << 24,
                share_access: 3,
                named_pipe_parameters,
            }
        }
        IRP_MJ_READ => WdmIoStackParameters::Read {
            length: outlen as u32,
        },
        IRP_MJ_WRITE => WdmIoStackParameters::Write {
            length: inlen as u32,
        },
        IRP_MJ_SET_INFORMATION => WdmIoStackParameters::SetInformation {
            length: inlen as u32,
            information_class: fsctl as u32,
        },
        0xd | 0xe => WdmIoStackParameters::DeviceControl {
            output_buffer_length: outlen as u32,
            input_buffer_length: inlen as u32,
            io_control_code: fsctl as u32,
        },
        IRP_MJ_PNP if minor == IRP_MN_START_DEVICE => {
            if inlen != 0 {
                let pnp_resource_capacity = (inlen + 7) & !7;
                pnp_resource_list = pool_alloc(pnp_resource_capacity);
                if pnp_resource_list == 0 {
                    pool_free(iosl);
                    pool_free(data);
                    if owns_fo {
                        pool_free(fo);
                    }
                    return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
                }
                zero(pnp_resource_list, pnp_resource_capacity);
                let mut index = 0u64;
                while index < inlen {
                    let byte = read_volatile((FSD_ARG_VADDR + index) as *const u8);
                    write_volatile((pnp_resource_list + index) as *mut u8, byte);
                    index += 1;
                }
            }
            WdmIoStackParameters::PnpStartDevice {
                allocated_resources: pnp_resource_list,
                allocated_resources_translated: pnp_resource_list,
            }
        }
        _ => WdmIoStackParameters::None,
    };
    let iosl_bytes =
        core::slice::from_raw_parts_mut(current_iosl as *mut u8, WDM_X64_IO_STACK_LOCATION_SIZE);
    if write_wdm_io_stack_location(
        iosl_bytes,
        WdmIoStackLocationInit {
            major: major as u8,
            minor: minor as u8,
            device_object: devobj,
            file_object: fo,
            parameters: stack_parameters,
        },
    )
    .is_err()
    {
        if pnp_resource_list != 0 {
            pool_free(pnp_resource_list);
        }
        pool_free(iosl);
        pool_free(data);
        if owns_fo {
            pool_free(fo);
        }
        return (0xC000_000Du32 as i32, 0); // STATUS_INVALID_PARAMETER
    }

    // IRP. Both buffered-I/O views refer to request-owned storage. Writes/sets arrive through
    // `inlen`; reads reserve `outlen` and are copied back to the ARG transport after completion.
    let irp = pool_alloc(WDM_X64_IRP_SIZE as u64);
    if irp == 0 {
        if pnp_resource_list != 0 {
            pool_free(pnp_resource_list);
        }
        pool_free(iosl);
        pool_free(data);
        if owns_fo {
            pool_free(fo);
        }
        return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
    }
    let irp_bytes = core::slice::from_raw_parts_mut(irp as *mut u8, WDM_X64_IRP_SIZE);
    if write_wdm_irp(
        irp_bytes,
        WdmIrpInit {
            system_buffer: data,
            user_buffer: data,
            stack_count: if major == IRP_MJ_PNP { 2 } else { 1 },
            current_location: if major == IRP_MJ_PNP { 2 } else { 1 },
            current_stack_location: current_iosl,
        },
    )
    .is_err()
    {
        pool_free(irp);
        if pnp_resource_list != 0 {
            pool_free(pnp_resource_list);
        }
        pool_free(iosl);
        pool_free(data);
        if owns_fo {
            pool_free(fo);
        }
        return (0xC000_000Du32 as i32, 0); // STATUS_INVALID_PARAMETER
    }

    // Call the driver's MajorFunction handler THROUGH the bugcheck escape: if the driver raises its
    // own consistency bugcheck (`NpBugCheck` → `KeBugCheckEx`) we unwind back here and fail THIS
    // dispatch cleanly instead of letting it continue on a broken invariant (or hang the boot).
    let jb = &mut *core::ptr::addr_of_mut!(BUGCHECK_JB);
    jb[0] = 0;
    jb[1] = 0;
    jb[2] = 0;
    let ret = fsd_guarded_call(handler, devobj, irp, jb.as_mut_ptr());
    let bugchecked = jb[2] != 0;
    jb[1] = 0; // disarm
    jb[2] = 0;
    if bugchecked {
        // The driver's state is undefined past its own bugcheck. Leak this request graph (the driver
        // may still hold pointers into it) rather than recycle memory it might write to, report the
        // failure to the caller, and let the dispatch loop keep serving — fail-closed, never a hang.
        write_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *mut u64, file_id);
        return (0xC000_0001u32 as i32, 0); // STATUS_UNSUCCESSFUL
    }

    let irp_status = read_unaligned((irp + 0x30) as *const i32);
    let info = read_unaligned((irp + 0x38) as *const u64);
    let st = if irp_status != 0 || info != 0 {
        irp_status
    } else {
        ret
    };
    // FsContext lands in the FILE_OBJECT; report it as the opaque file id for future file I/O.
    // PnP lifecycle IRPs carry no FILE_OBJECT, so keep SH_REQ_FILEID as the lower PDO token.
    let fsctx = if uses_file_object {
        read_unaligned((fo + 0x18) as *const u64)
    } else {
        file_id
    };
    write_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *mut u64, fsctx);
    // A freshly-created open: bind THIS FILE_OBJECT to the context npfs just handed back, so every
    // later IRP on that open reuses it (and npfs' stored `Ccb->FileObject[end]` stays valid).
    let mut fo_registered = false;
    if uses_file_object && crate::FSD_FILE_OBJECT_PER_OPEN && owns_fo && fsctx != 0 && fsctx != 1 {
        fo_registered = fo_register(fsctx, fo);
    }
    // CLEANUP / CLOSE end the open — this is where a FILE_OBJECT legitimately dies.
    if uses_file_object && (major == IRP_MJ_CLEANUP || major == IRP_MJ_CLOSE) {
        fo_release(file_id);
        fo_registered = false;
    }
    let irp_owns_fo = owns_fo && !fo_registered;
    if (major == IRP_MJ_READ || major == IRP_MJ_WRITE) && DATA_TRACE_COUNT < 12 {
        DATA_TRACE_COUNT += 1;
        print_str(b"[fsd-data-result] major=");
        print_u64(major);
        print_str(b" length=");
        print_u64(if major == IRP_MJ_READ { outlen } else { inlen });
        print_str(b" status=0x");
        print_hex(st as u32);
        print_str(b" info=");
        print_u64(info);
        print_str(b"\n");
    }
    if st as u32 == STATUS_PENDING {
        let table = &mut *core::ptr::addr_of_mut!(PENDING_IRPS);
        if let Some(slot) = table.iter_mut().find(|entry| entry.irp == 0) {
            *slot = PendingIrp {
                irp,
                iosl,
                file_object: fo,
                data,
                major: major as u8,
                // Capture the file id NOW: npfs NULLs `FILE_OBJECT->FsContext` on disconnect, so it
                // cannot be recovered from the object at completion time.
                fid: if fsctx != 0 { fsctx } else { file_id },
                owns_fo: irp_owns_fo,
            };
        } else {
            print_str(b"[fsd-host] pending IRP table exhausted\n");
        }
    } else {
        if major == IRP_MJ_READ {
            let copy_len = info.min(outlen);
            let mut index = 0u64;
            while index < copy_len {
                let byte = read_volatile((data + index) as *const u8);
                write_volatile((FSD_ARG_VADDR + index) as *mut u8, byte);
                index += 1;
            }
        }
        pool_free(data);
        if pnp_resource_list != 0 {
            pool_free(pnp_resource_list);
        }
        pool_free(iosl);
        pool_free(irp);
        if irp_owns_fo {
            pool_free(fo);
        }
    }
    (st, info)
}

#[inline]
unsafe fn zero(p: u64, n: u64) {
    let mut i = 0u64;
    while i < n {
        write_unaligned((p + i) as *mut u64, 0);
        i += 8;
    }
}

/// The policy class of a dynamically-launched driver — determines the [`ComponentDescriptor`]'s
/// [`HostCaps`], granted caps, and regions (the DECLARATIVE surface: a class → caps/layout map, not
/// a per-driver branch). See [`caps_and_layout_for`] + `docs/component-harness.md` §5.4.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverClass {
    /// File-system driver (npfs, fastfat, ntfs) — the DEFAULT persistent-IRP-server path, no device
    /// caps. `HostCaps { dispatch_server, kind: Irp }`.
    Fsd,
    /// A generic IRP filter/class driver (FS/bus filter). Same IRP substrate + caps as [`Fsd`]; the
    /// distinction is policy documentation (IRP forwarding is driver logic, not a harness concern).
    // Future-wiring: a registry-selected filter-driver class seam (design §5.4); no current service
    // selects it yet, but `caps_and_layout_for` already routes it. Intentional — matches `Device`.
    #[allow(dead_code)]
    Filter,
    /// Hardware device driver — same IRP substrate as [`Fsd`], plus a device-cap section (MMIO BAR
    /// frames / DMA / IRQ) that `nt-pnp` populates. The device caps/regions are a SEAM (not minted
    /// here yet); routed through the same `load_driver` Family-A path.
    #[allow(dead_code)]
    Device,
    /// The GUI syscall server (**win32k ONLY** — a unique privileged class). Its caps
    /// (`client_attach`/`usermode_callback`/`wide_arg_marshal`/`assert_skip`/`sparse_vspace`) are
    /// NEVER set for a normal user driver. win32k keeps its own Syscall substrate + paint-loop
    /// protocol (migrated onto the shared harness LAST — not routed through `load_driver`'s IRP
    /// builder). See [`crate::win32k_subsystem`] (`win32k_subsystem_entry`).
    #[allow(dead_code)]
    GuiSyscallServer,
}

/// The declarative class→policy map (design §5.4): a class selects [`HostCaps`] + whether device
/// caps are granted. NO per-driver branch — a new FSD/filter/device driver picks an existing class
/// and gets the descriptor for free. `(caps, wants_device_caps)`.
pub(crate) fn caps_and_layout_for(class: DriverClass) -> (HostCaps, bool) {
    match class {
        // The default user-driver path: a persistent IRP dispatch server, no device caps.
        DriverClass::Fsd | DriverClass::Filter => (
            HostCaps {
                dispatch_server: true,
                kind: ReqKind::Irp,
                ..HostCaps::default()
            },
            false,
        ),
        // Same IRP substrate; ONLY the granted-cap/region device section differs (nt-pnp populates it).
        DriverClass::Device => (
            HostCaps {
                dispatch_server: true,
                kind: ReqKind::Irp,
                ..HostCaps::default()
            },
            true,
        ),
        // win32k's unique privileged class — NOT routed through load_driver's IRP builder.
        DriverClass::GuiSyscallServer => (HostCaps::default(), false),
    }
}

/// A launched, isolated driver component — the caps + VAs the executive keeps to route IRPs to it.
pub(crate) struct DriverComponent {
    /// The component's VSpace (PML4 cap) — for demand-mapping pages / cross-AS reads.
    pub pml4: u64,
    /// The component's fault endpoint (also the IRP dispatch channel: plain Send/Recv).
    pub fault_ep: u64,
    /// The component-local DRIVER_OBJECT projection built for this driver.
    pub drvobj: u64,
    /// The DriverExtension->AddDevice pointer captured after DriverEntry, if any.
    pub add_device: u64,
    /// The recorded control DEVICE_OBJECT VA (\Device\NamedPipe for npfs).
    pub devobj: u64,
    /// The DriverObject->DriverUnload pointer captured after DriverEntry.
    pub driver_unload: u64,
    /// UTF-16LE path captured from `IoCreateDevice(DeviceName)`, if the driver created a named
    /// device object.
    pub device_name_len: u16,
    pub device_name_utf16: [u8; SH_CAPTURED_PATH_BYTES],
    /// UTF-16LE paths captured from `IoCreateSymbolicLink`, if the driver declared a link.
    pub symlink_link_len: u16,
    pub symlink_link_utf16: [u8; SH_CAPTURED_PATH_BYTES],
    pub symlink_target_len: u16,
    pub symlink_target_utf16: [u8; SH_CAPTURED_PATH_BYTES],
    /// The DriverEntry verdict bitmask ([`V_ENTERED`] etc.).
    pub verdict: u32,
    /// Whether DriverEntry ran to its dispatch loop (parked) vs faulted mid-init.
    pub finished: bool,
    /// The EXECUTIVE-side SHARED-frame VA for THIS instance (where the executive marshals IRP
    /// request/reply fields). Instance 0 == [`FSD_SHARED_VADDR`]; N≥1 == a per-instance window.
    pub exec_shared_va: u64,
    /// The EXECUTIVE-side ARG-frame VA for THIS instance (buffered-I/O in/out data).
    pub exec_arg_va: u64,
    /// This driver's instance index in [`DRIVER_INSTANCES`].
    pub instance: usize,
    /// Canonical executive/I/O route id for this driver binding.
    pub driver_id: u64,
    /// Canonical executive/I/O route id for this driver's named control device, if any.
    pub device_id: u64,
    /// The component host's TCB — used to `TCB_Suspend` it if its pump WALLS (transport risk R2).
    pub tcb: u64,
    /// The DEDICATED MCS reply object backing this component's `Call` dispatch transport.
    pub reply_cap: u64,
}

unsafe fn read_shared_path_capture(
    shared_va: u64,
    len_off: u64,
    buf_off: u64,
) -> (u16, [u8; SH_CAPTURED_PATH_BYTES]) {
    let len = read_volatile((shared_va + len_off) as *const u16);
    let mut out = [0u8; SH_CAPTURED_PATH_BYTES];
    if len as usize > SH_CAPTURED_PATH_BYTES || (len & 1) != 0 {
        return (0, out);
    }
    let mut off = 0usize;
    while off < len as usize {
        out[off] = read_volatile((shared_va + buf_off + off as u64) as *const u8);
        off += 1;
    }
    (len, out)
}

/// Copy `n` bytes from `src` to `dst` (both mapped in the executive). HEAP-FREE, byte-wise-safe
/// (unaligned windows in a PE).
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
        write_unaligned((dst + i) as *mut u8, read_unaligned((src + i) as *const u8));
        i += 1;
    }
}

/// Parse a driver PE at `src_va` (raw file bytes), copy its sections into `dst_va` (frames pre-mapped
/// RW in BOTH the executive and the component), apply DIR64 relocations for the load at `dst_va`, and
/// patch the IAT resolving each import name through `resolve`. Records per-frame W^X rights into
/// `rights_out`. Returns `(DriverEntryRva, SizeOfImage)`, or None. Fully HEAP-FREE.
///
/// This is the generic PE-load mechanism (the win32k `load_driver_into` shape, but with an injected
/// name resolver so it's driver-agnostic — the general dynamic path).
unsafe fn load_pe_into(
    src_va: u64,
    dst_va: u64,
    run_va: u64,
    max_frames: u64,
    rights_out: &mut [u64],
    resolve: fn(&str) -> u64,
) -> Option<(u32, u32)> {
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
    let size_of_image = read_unaligned((opt + 56) as *const u32);
    let size_of_headers = read_unaligned((opt + 60) as *const u32) as u64;
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
        // W^X: executable section → RX (2), else RW_NX.
        let r = if chars & 0x2000_0000 != 0 {
            2u64
        } else {
            RW_NX
        };
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

    // DIR64 relocs for the EXECUTION load at run_va (the component's VSpace VA). The bytes are
    // WRITTEN into dst_va (the executive's per-instance load window, aliased to the same frames), but
    // the relocated absolute values must target where the code RUNS (run_va), which is fixed across
    // instances (each in its own VSpace). For instance 0, run_va == dst_va == FSD_CODE_VA.
    let delta = run_va.wrapping_sub(image_base);
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

    // PASSIVE-level transform (documented; the win32k `KeGetCurrentIrql`-cr8 precedent): a kernel
    // driver reads the current IRQL as `mov %cr8, %reg` — a PRIVILEGED instruction that #GPs in the
    // component's usermode context (a UserException the fault-reply path can't set RAX through). npfs
    // runs entirely at PASSIVE_LEVEL (0) in this host, so neutralize each `REX.W 0f 20 c0` (mov %cr8,
    // %rax) into `xor %eax,%eax; nop` (`31 c0 90 90`, 4 bytes, result 0 = PASSIVE_LEVEL) and each
    // `mov %reg,%cr8` (`0f 22`, KeLowerIrql, 3 bytes) into `nop`s. Scan the whole loaded image.
    {
        let scan = (size_of_image as u64).min(cap);
        let mut p = 0u64;
        while p + 4 <= scan {
            let b0 = read_unaligned((dst_va + p) as *const u8);
            let b1 = read_unaligned((dst_va + p + 1) as *const u8);
            let b2 = read_unaligned((dst_va + p + 2) as *const u8);
            // REX prefix (0x40..0x4f), then 0F 20 (mov %cr,%reg): if the ModRM names cr8 (reg field
            // == 0, with REX.R providing the high bit → cr8), rewrite to xor eax,eax; nop; nop.
            if (b0 & 0xF0) == 0x40 && b1 == 0x0F && b2 == 0x20 {
                let modrm = read_unaligned((dst_va + p + 3) as *const u8);
                // ModRM = 11 000 rrr (reg field 000 = crN, rm = dest GPR). REX.R (b0 & 4) selects cr8.
                if (modrm & 0xC0) == 0xC0 && (modrm & 0x38) == 0x00 {
                    write_unaligned((dst_va + p) as *mut u8, 0x31); // xor
                    write_unaligned((dst_va + p + 1) as *mut u8, 0xC0); // eax,eax
                    write_unaligned((dst_va + p + 2) as *mut u8, 0x90); // nop
                    write_unaligned((dst_va + p + 3) as *mut u8, 0x90); // nop
                    p += 4;
                    continue;
                }
            }
            // 0F 22 (mov %reg,%cr): a KeRaise/LowerIrql write to cr8 → neutralize to nops (3 bytes;
            // an optional REX makes it 4). Rewrite the 0F 22 ModRM triple to nops.
            if b0 == 0x0F && b1 == 0x22 {
                write_unaligned((dst_va + p) as *mut u8, 0x90);
                write_unaligned((dst_va + p + 1) as *mut u8, 0x90);
                write_unaligned((dst_va + p + 2) as *mut u8, 0x90);
                p += 3;
                continue;
            }
            p += 1;
        }
    }

    // Seed a valid /GS cookie when the image declares one through the PE load-config directory.
    // MSVC's GsDriverEntry wrapper fastfails with int 0x29 if this is left at the CRT default.
    let load_config_rva = read_unaligned((opt + 112 + 10 * 8) as *const u32) as u64;
    let load_config_size = read_unaligned((opt + 112 + 10 * 8 + 4) as *const u32) as u64;
    if load_config_rva != 0 && load_config_size >= 96 && load_config_rva + 96 <= cap {
        let cookie_va = read_unaligned((dst_va + load_config_rva + 88) as *const u64);
        let cookie_rva = if cookie_va >= run_va && cookie_va - run_va <= cap {
            // The relocation pass above rebases the load-config SecurityCookie VA.
            Some(cookie_va - run_va)
        } else if cookie_va >= image_base && cookie_va - image_base <= cap {
            Some(cookie_va - image_base)
        } else {
            None
        };
        if let Some(cookie_rva) = cookie_rva {
            if cookie_rva + 8 <= cap {
                write_unaligned(
                    (dst_va + cookie_rva) as *mut u64,
                    nt_pe_loader::SECURITY_COOKIE_SEED,
                );
            }
        }
    }

    // Patch the IAT: resolve each import name through `resolve`.
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva != 0 {
        let mut desc = dst_va + imp_rva;
        loop {
            let ilt = read_unaligned(desc as *const u32) as u64;
            let iat = read_unaligned((desc + 16) as *const u32) as u64;
            if ilt == 0 && iat == 0 {
                break;
            }
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
                    let name = core::str::from_utf8_unchecked(&buf[..n]);
                    let addr = resolve(name);
                    write_unaligned((slots + k * 8) as *mut u64, addr);
                }
                k += 1;
            }
            desc += 20;
        }
    }

    Some((entry_rva, size_of_image))
}

/// The FSD image loaded/mapped rights (W^X), filled by [`load_pe_into`]. ONE array per instance
/// (a live driver's `Region` holds a `'static` slice, so two coexisting drivers need distinct arrays).
pub(crate) const MAX_DRIVER_INSTANCES: usize = 4;
static mut FSD_RIGHTS: [[u64; FSD_IMAGE_FRAMES as usize]; MAX_DRIVER_INSTANCES] =
    [[RW_NX; FSD_IMAGE_FRAMES as usize]; MAX_DRIVER_INSTANCES];

/// Next free instance slot. Slots are retired on unload, but the bump id is not reused yet because
/// the seL4 cap/window reclamation work is intentionally separate from the NT lifetime contract.
static DRIVER_NEXT_INSTANCE: AtomicU64 = AtomicU64::new(0);

/// GENERAL dynamic driver launch: load the `.sys` at `path` by-path from the FS, IAT-patch it, spawn
/// it as an ISOLATED component (per its `class`), run its real DriverEntry, and return the live
/// [`DriverComponent`]. The FSD/Filter/Device classes are all routed through this ONE Family-A IRP
/// path (`caps_and_layout_for(class)` selects the [`HostCaps`] + whether device caps are granted);
/// the GUI syscall server ([`DriverClass::GuiSyscallServer`], win32k) keeps its own Syscall substrate
/// and is NOT routed here — see [`crate::win32k_subsystem`].
///
/// MULTI-INSTANCE: each call takes a fresh instance slot; instance 0 uses the fixed FSD executive
/// VAs (byte-identical), instance N≥1 a distinct executive window ([`ExecVaWindow::for_instance`]).
/// The live driver state is recorded in [`DRIVER_INSTANCES`] so [`dispatch_irp`] can route to any of
/// N drivers by instance index. Adding a boot/system IRP driver means declaring a `Services\<Name>`
/// record with an image path, type, and start policy, then handing that metadata to this loader.
///
/// Fault-contained: the component's DriverEntry faults land on ITS fault EP (this loop demand-maps
/// benign pages + reports a wall) — a driver crash never brings down the executive root.
pub(crate) unsafe fn load_driver(
    fs: &Fat32,
    path: &[u8],
    class: DriverClass,
    driver_object_path: &str,
) -> Option<DriverComponent> {
    let (caps, _wants_device_caps) = caps_and_layout_for(class);
    if !caps.dispatch_server {
        // The GUI syscall server (win32k) is NOT routed through the general IRP path.
        return None;
    }
    if parse_nt_path(driver_object_path).is_none() {
        print_str(b"[driver-launch] invalid driver object path ");
        print_str(driver_object_path.as_bytes());
        print_str(b"\n");
        return None;
    }

    // Take a fresh instance slot + its executive-side VA window.
    let instance = DRIVER_NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed) as usize;
    if instance >= MAX_DRIVER_INSTANCES {
        print_str(b"[driver-launch] instance table full\n");
        return None;
    }
    let win = ExecVaWindow::for_instance(instance);

    // 1. Load the .sys bytes by-path into the executive's pool.
    let (src_va, src_size) = load_file_to_pool(fs, path)?;
    print_str(b"[driver-launch] loaded ");
    print_str(path);
    print_str(b" size=");
    print_u64(src_size as u64);
    print_str(b" instance=");
    print_u64(instance as u64);
    print_str(b"\n");

    // The image RUNS at the fixed component VA (FSD_CODE_VA) in its own VSpace; the executive loads
    // its bytes at the per-instance window (win.code_va) so two instances don't collide executive-side.
    let code_va = win.code_va;
    let run_va = FSD_CODE_VA;
    let img_frames = FSD_IMAGE_FRAMES;

    // 2. Executive-side frames: CODE (mapped RW to load into) in its own 2 MiB PT, DATA + SHARED +
    //    ARG in an aux PT. POOL is host-only.
    let cpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cpt);
    let _ = paging_struct_map(cpt, LBL_X86_PAGE_TABLE_MAP, code_va, CAP_INIT_THREAD_VSPACE);
    let code_base = alloc_frame();
    for _ in 1..img_frames {
        let _ = alloc_frame();
    }
    for i in 0..img_frames {
        let _ = page_map(
            copy_cap(code_base + i),
            code_va + i * 0x1000,
            RW_NX,
            CAP_INIT_THREAD_VSPACE,
        );
    }
    // POOL frames (host-only; allocate the caps, mapped by spawn_component).
    let pool_base = alloc_frame();
    for _ in 1..FSD_POOL_FRAMES {
        let _ = alloc_frame();
    }
    // DATA + SHARED + ARG: caps + an aux PT in the executive VSpace.
    let data_base = alloc_frame();
    for _ in 1..FSD_DATA_FRAMES {
        let _ = alloc_frame();
    }
    let shared = alloc_frame();
    let arg_base = alloc_frame();
    for _ in 1..FSD_ARG_FRAMES {
        let _ = alloc_frame();
    }
    let apt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, apt);
    let _ = paging_struct_map(
        apt,
        LBL_X86_PAGE_TABLE_MAP,
        win.aux_pt_va,
        CAP_INIT_THREAD_VSPACE,
    );
    for i in 0..FSD_DATA_FRAMES {
        let _ = page_map(
            copy_cap(data_base + i),
            win.data_va + i * 0x1000,
            RW_NX,
            CAP_INIT_THREAD_VSPACE,
        );
    }
    let _ = page_map(
        copy_cap(shared),
        win.shared_va,
        RW_NX,
        CAP_INIT_THREAD_VSPACE,
    );
    for i in 0..FSD_ARG_FRAMES {
        let _ = page_map(
            copy_cap(arg_base + i),
            win.arg_va + i * 0x1000,
            RW_NX,
            CAP_INIT_THREAD_VSPACE,
        );
    }

    // 3. Parse + copy + relocate + IAT-patch (HEAP-FREE, records W^X rights). Load bytes into the
    //    per-instance executive window (code_va) but relocate for the component execution VA (run_va).
    let rights = &mut (*core::ptr::addr_of_mut!(FSD_RIGHTS))[instance];
    let (entry_rva, image_len) =
        load_pe_into(src_va, code_va, run_va, img_frames, rights, fsd_export_addr)?;
    let _ = register_system_module(path, code_va, image_len);
    print_str(b"[driver-launch] DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");
    write_volatile((win.shared_va + SH_ENTRY_RVA) as *mut u64, entry_rva as u64);
    write_volatile((win.shared_va + SH_VERDICT) as *mut u32, 0);
    write_volatile((win.shared_va + SH_ADD_DEVICE) as *mut u64, 0);

    // 4. Build the FSD-class descriptor + spawn the isolated component.
    let fault_ep = make_object(OBJ_ENDPOINT);
    let (pml4, tcb) = spawn_fsd_component(
        code_base,
        pool_base,
        data_base,
        shared,
        arg_base,
        fault_ep,
        &rights[..img_frames as usize],
    );
    // ★ This instance's DEDICATED MCS reply object — the server-side binding of the `Call`
    // transport. One per component is enough at any depth (one TCB ⇒ at most one outstanding Call).
    let reply_cap = crate::fsd_reply_slot(instance);

    // 5. Drive the DriverEntry init fault-recv loop THROUGH THE SHARED HARNESS PUMP: demand-map
    //    benign pages, wall on a low/in-image fault or the 512 demand cap, wait for the dispatch-ready
    //    signal (FSD_DISPATCH_LABEL). Faults report addresses in the COMPONENT's VSpace (image runs at
    //    run_va), so the in-image wall bounds are `[run_va, run_va + img_frames*0x1000)`.
    // `InitialAction::RecvFirst`: the component is mid-DriverEntry (blocked in a fault `Call`, or about
    // to issue its ready `Call`), so the pump must start by RECEIVING. Trace on for observability.
    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep,
        pml4,
        code_va: run_va,
        image_frames: img_frames,
        shared_va: win.shared_va,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 512,
        trace_faults: true,
        // ★ The component is mid-DriverEntry: it is either blocked in a fault Call or about to issue
        // its post-DriverEntry ready Call. Either way we must RECEIVE first — and when the ready Call
        // arrives the component is left BLOCKED IN IT (the steady state the per-IRP pump replies to),
        // instead of racing on to a bare receive the executive could miss.
        initial: crate::spawn_hosts::InitialAction::RecvFirst,
        tcb,
        reply_cap,
        client_pi: 0,
        callback_client: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    let faults = pr.faults;
    let demand = pr.demand;
    let finished = pr.completed;
    let (wall_ip, wall_addr, wall_label) = (pr.wall_ip, pr.wall_addr, pr.wall_label);

    let verdict = read_volatile((win.shared_va + SH_VERDICT) as *const u32);
    let de_status = read_volatile((win.shared_va + SH_DE_STATUS) as *const i32);
    let drvobj = read_volatile((win.shared_va + SH_DRVOBJ) as *const u64);
    let devobj = read_volatile((win.shared_va + SH_DEVOBJ) as *const u64);
    let driver_unload = read_volatile((win.shared_va + SH_DRIVER_UNLOAD) as *const u64);
    let add_device = read_volatile((win.shared_va + SH_ADD_DEVICE) as *const u64);
    let (device_name_len, device_name_utf16) =
        read_shared_path_capture(win.shared_va, SH_DEVICE_NAME_LEN, SH_DEVICE_NAME_BUF);
    let (symlink_link_len, symlink_link_utf16) =
        read_shared_path_capture(win.shared_va, SH_SYMLINK_LINK_LEN, SH_SYMLINK_LINK_BUF);
    let (symlink_target_len, symlink_target_utf16) =
        read_shared_path_capture(win.shared_va, SH_SYMLINK_TARGET_LEN, SH_SYMLINK_TARGET_BUF);
    print_str(b"[npfs-svc] DriverEntry ");
    if finished {
        print_str(b"RETURNED status=0x");
        print_hex(de_status as u32);
    } else {
        print_str(b"STOPPED label=");
        print_u64(wall_label);
        print_str(b" ip=0x");
        print_hex(wall_ip as u32);
        print_str(b" RVA=0x");
        print_hex(wall_ip.wrapping_sub(run_va) as u32);
        print_str(b" addr=0x");
        print_hex((wall_addr >> 32) as u32);
        print_hex(wall_addr as u32);
    }
    print_str(b" verdict=0x");
    print_hex(verdict);
    print_str(b" faults=");
    print_u64(faults);
    print_str(b" demand=");
    print_u64(demand);
    print_str(b" devobj=0x");
    print_hex((devobj >> 32) as u32);
    print_hex(devobj as u32);
    print_str(b" unload=0x");
    print_hex((driver_unload >> 32) as u32);
    print_hex(driver_unload as u32);
    print_str(b"\n");

    if !finished || de_status != 0 {
        print_str(b"[driver-launch] DriverEntry failed; refusing to register ");
        print_str(driver_object_path.as_bytes());
        print_str(b"\n");
        return None;
    }

    let driver_id = register_io_driver(driver_object_path, instance)?;
    let dc = DriverComponent {
        pml4,
        fault_ep,
        drvobj,
        add_device,
        devobj,
        driver_unload,
        device_name_len,
        device_name_utf16,
        symlink_link_len,
        symlink_link_utf16,
        symlink_target_len,
        symlink_target_utf16,
        verdict,
        finished,
        exec_shared_va: win.shared_va,
        exec_arg_va: win.arg_va,
        instance,
        driver_id,
        device_id: 0,
        tcb,
        reply_cap,
    };
    let device_id = match register_io_device(driver_id, &dc) {
        Ok(device_id) => device_id,
        Err(status) => {
            print_str(b"[driver-launch] IoManager device publish failed status=0x");
            print_hex(status.raw() as u32);
            print_str(b" for ");
            print_str(driver_object_path.as_bytes());
            print_str(b"\n");
            destroy_registered_driver(driver_id);
            return None;
        }
    };
    let dc = DriverComponent { device_id, ..dc };
    if let Err(status) = register_io_symbolic_link(&dc) {
        print_str(b"[driver-launch] IoManager symlink publish failed status=0x");
        print_hex(status.raw() as u32);
        print_str(b" for ");
        print_str(driver_object_path.as_bytes());
        print_str(b"\n");
        destroy_registered_driver(driver_id);
        return None;
    }
    // Record the live instance and publish canonical driver/device route ids for callers.
    register_instance(&dc);
    Some(dc)
}

/// Spawn the isolated FSD component: image W^X, pool, stack, IPC-buf, DATA/SHARED/ARG windows, fault
/// EP — NO device caps. Delegates to the generic [`spawn_component`] engine.
unsafe fn spawn_fsd_component(
    code_base: u64,
    pool_base: u64,
    data_base: u64,
    shared: u64,
    arg_base: u64,
    fault_ep: u64,
    rights: &[u64],
) -> (u64, u64) {
    // SAFETY: rights lives in FSD_RIGHTS (a 'static); re-borrow as 'static for Rights::PerFrame.
    let rights_static: &'static [u64] = core::mem::transmute::<&[u64], &'static [u64]>(rights);
    let regions = [
        // The npfs PE image, W^X, its own 2 MiB PT.
        Region {
            source: FrameSource::Alias(code_base),
            base_va: FSD_CODE_VA,
            count: FSD_IMAGE_FRAMES,
            rights: Rights::PerFrame(rights_static),
            pts: 1,
        },
        // Pool arena (own window + PTs, aliased executive frames).
        Region {
            source: FrameSource::Alias(pool_base),
            base_va: FSD_POOL_VADDR,
            count: FSD_POOL_FRAMES,
            rights: Rights::Uniform(RW_NX),
            pts: 1,
        },
        // Aux PT window for DATA/SHARED/ARG.
        Region {
            source: FrameSource::Alias(0),
            base_va: FSD_AUX_PT_VADDR,
            count: 0,
            rights: Rights::Uniform(RW_NX),
            pts: 1,
        },
        // DATA export/placeholder region (aux window).
        Region {
            source: FrameSource::Alias(data_base),
            base_va: FSD_DATA_VADDR,
            count: FSD_DATA_FRAMES,
            rights: Rights::Uniform(RW_NX),
            pts: 0,
        },
        // Shared handoff page (aux window).
        Region {
            source: FrameSource::Alias(shared),
            base_va: FSD_SHARED_VADDR,
            count: 1,
            rights: Rights::Uniform(RW_NX),
            pts: 0,
        },
        // Arg-marshal frames (aux window).
        Region {
            source: FrameSource::Alias(arg_base),
            base_va: FSD_ARG_VADDR,
            count: FSD_ARG_FRAMES,
            rights: Rights::Uniform(RW_NX),
            pts: 0,
        },
    ];
    let d = ComponentDescriptor {
        entry: fsd_component_entry,
        image_rights: Rights::Uniform(3), // RWX (trampolines live in the shared executive image)
        map_heap_pt: false,
        stack_base: FSD_STACK_VADDR,
        stack_frames: FSD_STACK_FRAMES,
        stack_dedicated_pt: true,
        regions: &regions,
        granted: GrantedCaps {
            irq_ntfn: None,
            result_ntfn: None,
            fault_ep: Some(fault_ep),
        },
        prio: 100,
        gs_base: Some(FSD_KPCR_VA),
        caps: HostCaps::default(),
    };
    let sc = spawn_component(&d);
    (sc.pml4, sc.tcb)
}

/// Ensure the page table covering `page` exists in `pml4` (SYS_SEND page_map can't report a
/// missing-PT error). Idempotent-ish: builds one PT per 2 MiB region touched (tracked in a small
/// static bitmap keyed by the 2 MiB index within the pool/demand window). Mirrors the win32k
/// `ensure_w32_client_paging` mechanism.
pub(crate) unsafe fn ensure_paging(page: u64, pml4: u64) {
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, page & !0x1F_FFFF, pml4);
}

// ---------------------------------------------------------------------------------------------
// The live launched IRP-driver transport table + the generic IRP dispatch transport.
//
// De-singletoned (multi-driver): canonical driver/device identity, names, and Object Manager ids
// live in [`IoManager`]. This module keeps only the private seL4 transport state needed to wake an
// isolated component instance.
// ---------------------------------------------------------------------------------------------

pub(crate) const IO_MANAGER_COMPONENT_ID: u64 = 0x494F_0000;

#[derive(Clone, Copy, Default)]
struct ExecutiveObjectManagerPort;

impl ExecutiveObjectManagerPort {
    fn ascii_path(path: &NtPath) -> Result<String, nt_status::NtStatus> {
        nt_path_ascii_string(path).ok_or(nt_status::NtStatus::INVALID_PARAMETER)
    }
}

impl ObjectManagerPort for ExecutiveObjectManagerPort {
    fn register_client(&mut self) -> ClientId {
        ClientId(IO_MANAGER_COMPONENT_ID)
    }

    fn close_client(&mut self, _client: ClientId) -> Result<(), nt_status::NtStatus> {
        Ok(())
    }

    fn create_driver_object(
        &mut self,
        name: &NtPath,
        owner_local_id: u64,
    ) -> Result<ObjectId, nt_status::NtStatus> {
        let path = Self::ascii_path(name)?;
        unsafe {
            crate::object_manager_create_driver_path(&path, IO_MANAGER_COMPONENT_ID, owner_local_id)
                .map(ObjectId)
        }
    }

    fn delete_driver_object(
        &mut self,
        _object: ObjectId,
        name: &NtPath,
    ) -> Result<(), nt_status::NtStatus> {
        let path = Self::ascii_path(name)?;
        unsafe { crate::object_manager_delete_path(&path) }
    }

    fn create_device_object(
        &mut self,
        name: Option<&NtPath>,
        owner_local_id: u64,
    ) -> Result<ObjectId, nt_status::NtStatus> {
        match name {
            Some(name) => {
                let path = Self::ascii_path(name)?;
                unsafe {
                    crate::object_manager_create_device_path(
                        &path,
                        IO_MANAGER_COMPONENT_ID,
                        owner_local_id,
                    )
                    .map(ObjectId)
                }
            }
            None => Ok(ObjectId::NULL),
        }
    }

    fn delete_device_object(
        &mut self,
        _object: ObjectId,
        name: Option<&NtPath>,
    ) -> Result<(), nt_status::NtStatus> {
        let path = Self::ascii_path(name.ok_or(nt_status::NtStatus::INVALID_PARAMETER)?)?;
        unsafe { crate::object_manager_delete_path(&path) }
    }

    fn open_device_object(&mut self, path: &NtPath) -> Result<ObjectId, nt_status::NtStatus> {
        let path = Self::ascii_path(path)?;
        unsafe { crate::object_manager_lookup_path(&path).map(ObjectId) }
    }

    fn create_symbolic_link(
        &mut self,
        link: &NtPath,
        target: &NtPath,
    ) -> Result<(), nt_status::NtStatus> {
        let link = Self::ascii_path(link)?;
        let target = Self::ascii_path(target)?;
        unsafe { crate::object_manager_create_symbolic_link_path(&link, &target) }
    }

    fn delete_symbolic_link(&mut self, link: &NtPath) -> Result<(), nt_status::NtStatus> {
        let link = Self::ascii_path(link)?;
        unsafe { crate::object_manager_delete_symbolic_link_path(&link) }
    }

    fn create_file_object_and_handle(
        &mut self,
        _client: ClientId,
        device_object: ObjectId,
        owner_local_id: u64,
        desired_access: AccessMask,
    ) -> Result<(ObjectId, HandleValue), nt_status::NtStatus> {
        unsafe {
            crate::object_manager_create_file_handle(
                IO_MANAGER_COMPONENT_ID,
                owner_local_id,
                device_object.0,
                desired_access,
            )
            .map(|(file, handle)| (ObjectId(file), HandleValue(handle)))
        }
    }

    fn reference_file_by_handle(
        &mut self,
        _client: ClientId,
        handle: HandleValue,
        desired_access: AccessMask,
    ) -> Result<ObjectId, nt_status::NtStatus> {
        unsafe { crate::object_manager_reference_file_handle(handle, desired_access).map(ObjectId) }
    }

    fn reference_device(&mut self, device_object: ObjectId) -> Result<(), nt_status::NtStatus> {
        if device_object == ObjectId::NULL {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    fn close_handle(
        &mut self,
        _client: ClientId,
        handle: HandleValue,
    ) -> Result<(), nt_status::NtStatus> {
        unsafe { crate::object_manager_close_handle(handle) }
    }
}

type ExecutiveIoManager = IoManager<ExecutiveObjectManagerPort>;
static mut DRIVER_IO_MANAGER: MaybeUninit<ExecutiveIoManager> = MaybeUninit::uninit();
static mut DRIVER_IO_MANAGER_INIT: bool = false;

fn io_manager_mut() -> &'static mut ExecutiveIoManager {
    unsafe {
        let init = core::ptr::addr_of_mut!(DRIVER_IO_MANAGER_INIT);
        let slot = core::ptr::addr_of_mut!(DRIVER_IO_MANAGER);
        if !read_volatile(init) {
            (*slot).write(IoManager::new(ExecutiveObjectManagerPort));
            write_volatile(init, true);
        }
        (*slot).assume_init_mut()
    }
}

fn parse_nt_path(path: &str) -> Option<NtPath> {
    NtPath::parse_str(path).ok()
}

fn captured_nt_path(bytes: &[u8; SH_CAPTURED_PATH_BYTES], len: u16) -> Option<NtPath> {
    let len = len as usize;
    if len == 0 || len > bytes.len() || (len & 1) != 0 {
        return None;
    }
    let mut units = [0u16; SH_CAPTURED_PATH_BYTES / 2];
    let mut i = 0usize;
    while i < len / 2 {
        let off = i * 2;
        units[i] = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
        i += 1;
    }
    NtPath::parse(&units[..len / 2]).ok()
}

unsafe fn unicode_string_nt_path(us: u64) -> Option<NtPath> {
    let (buf, len) = unicode_string_parts(us)?;
    let mut units = [0u16; SH_CAPTURED_PATH_BYTES / 2];
    let count = len as usize / 2;
    let mut i = 0usize;
    while i < count {
        units[i] = read_unaligned((buf + (i * 2) as u64) as *const u16);
        i += 1;
    }
    NtPath::parse(&units[..count]).ok()
}

struct HostedDriverBackend {
    instance: usize,
}

fn projection_fsctl(irp: &IrpProjection) -> u64 {
    match &irp.parameters {
        IoParameters::DeviceControl(p) | IoParameters::InternalDeviceControl(p) => {
            p.ioctl_code as u64
        }
        IoParameters::QueryInformation(p) | IoParameters::SetInformation(p) => p.info_class as u64,
        _ => 0,
    }
}

fn projection_buffer_extents(irp: &IrpProjection, cap: usize) -> (usize, usize) {
    if let Some(buffer) = irp.buffer {
        (
            (buffer.input_len as usize).min(cap),
            (buffer.output_len as usize).min(cap),
        )
    } else {
        let (input_len, output_len) = irp.parameters.buffered_lengths(cap);
        (
            (input_len as usize).min(cap),
            (output_len as usize).min(cap),
        )
    }
}

impl DriverDispatchBackend for HostedDriverBackend {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, nt_status::NtStatus> {
        let (input_len, output_len) = projection_buffer_extents(irp, ctx.system_buffer.len());
        let input = Vec::from(&ctx.system_buffer[..input_len]);
        let fsctl = projection_fsctl(irp);
        let result = unsafe {
            dispatch_irp_for_instance(
                self.instance,
                irp.major as u64,
                irp.minor as u64,
                hosted_device_binding_by_device_id(irp.device_id.raw())
                    .map(|binding| binding.device_object)
                    .or_else(|| instance(self.instance).map(|inst| inst.device_object))
                    .unwrap_or(0),
                fsctl,
                irp.user_data,
                &input,
                &mut ctx.system_buffer[..output_len],
            )
        };
        match result {
            Some((status, information)) => Ok(DispatchOutcome::Completed {
                status: nt_status::NtStatus(status),
                information,
            }),
            None => Ok(DispatchOutcome::Failed {
                status: nt_status::NtStatus::DEVICE_NOT_CONNECTED,
            }),
        }
    }

    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), nt_status::NtStatus> {
        Err(nt_status::NtStatus::NOT_SUPPORTED)
    }
}

struct HostedRootBusBackend;

impl DriverDispatchBackend for HostedRootBusBackend {
    fn dispatch_irp(
        &mut self,
        _ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, nt_status::NtStatus> {
        if irp.major == major::IRP_MJ_PNP {
            Ok(DispatchOutcome::Completed {
                status: nt_status::NtStatus::SUCCESS,
                information: 0,
            })
        } else {
            Ok(DispatchOutcome::Failed {
                status: nt_status::NtStatus::INVALID_DEVICE_REQUEST,
            })
        }
    }

    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), nt_status::NtStatus> {
        Err(nt_status::NtStatus::NOT_SUPPORTED)
    }
}

const HOSTED_ROOT_BUS_DRIVER_PATH: &str = "\\Driver\\RootBus";

fn hosted_root_bus_driver_id() -> Result<DriverId, nt_status::NtStatus> {
    if let Some(id) = driver_id_by_name(HOSTED_ROOT_BUS_DRIVER_PATH) {
        return Ok(DriverId(id));
    }
    let name =
        parse_nt_path(HOSTED_ROOT_BUS_DRIVER_PATH).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let mut dispatch = MajorFunctionTable::new();
    dispatch.set(
        major::IRP_MJ_PNP,
        DispatchTarget::Kernel(DriverBackendId(0)),
    );
    io_manager_mut().create_kernel_driver_with_major_table(
        &name,
        Box::new(HostedRootBusBackend),
        dispatch,
    )
}

fn external_major(major: u64) -> Option<u8> {
    if major <= u8::MAX as u64 {
        Some(major as u8)
    } else {
        None
    }
}

fn external_len(len: usize) -> u32 {
    len.min(u32::MAX as usize) as u32
}

fn external_code(fsctl: u64) -> Option<u32> {
    if fsctl <= u32::MAX as u64 {
        Some(fsctl as u32)
    } else {
        None
    }
}

fn external_irp_parameters(
    major: u8,
    fsctl: u64,
    input_len: u32,
    output_len: u32,
) -> Option<IoParameters> {
    match major {
        major::IRP_MJ_CREATE | major::IRP_MJ_CREATE_NAMED_PIPE => {
            Some(IoParameters::Create(Default::default()))
        }
        major::IRP_MJ_CLEANUP => Some(IoParameters::Cleanup),
        major::IRP_MJ_CLOSE => Some(IoParameters::Close),
        major::IRP_MJ_READ => Some(IoParameters::Read(ReadWriteParameters {
            length: output_len,
            key: 0,
            offset: 0,
        })),
        major::IRP_MJ_WRITE => Some(IoParameters::Write(ReadWriteParameters {
            length: input_len,
            key: 0,
            offset: 0,
        })),
        major::IRP_MJ_QUERY_INFORMATION => {
            Some(IoParameters::QueryInformation(InformationParameters {
                info_class: external_code(fsctl)?,
                length: output_len,
            }))
        }
        major::IRP_MJ_SET_INFORMATION => {
            Some(IoParameters::SetInformation(InformationParameters {
                info_class: external_code(fsctl)?,
                length: input_len,
            }))
        }
        major::IRP_MJ_FLUSH_BUFFERS => Some(IoParameters::FlushBuffers),
        major::IRP_MJ_FILE_SYSTEM_CONTROL | major::IRP_MJ_DEVICE_CONTROL => {
            Some(IoParameters::DeviceControl(DeviceControlParameters {
                ioctl_code: external_code(fsctl)?,
                input_len,
                output_len,
            }))
        }
        major::IRP_MJ_INTERNAL_DEVICE_CONTROL => Some(IoParameters::InternalDeviceControl(
            DeviceControlParameters {
                ioctl_code: external_code(fsctl)?,
                input_len,
                output_len,
            },
        )),
        major::IRP_MJ_POWER => Some(IoParameters::Power),
        major::IRP_MJ_PNP => Some(IoParameters::Pnp),
        _ => Some(IoParameters::Unsupported),
    }
}

fn dispatch_external_irp_to_driver_record(
    driver_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    let major = external_major(major)?;
    let input_len = external_len(in_data.len());
    let output_len = external_len(out.len());
    let params = external_irp_parameters(major, fsctl, input_len, output_len)?;
    let mut system_buffer = Vec::new();
    system_buffer.resize(in_data.len().max(out.len()), 0);
    system_buffer[..in_data.len()].copy_from_slice(in_data);
    let (status, information) = io_manager_mut()
        .build_and_dispatch_external_to_driver(
            ClientId(IO_MANAGER_COMPONENT_ID),
            DriverId(driver_id),
            None::<FileId>,
            file_id,
            major,
            params,
            input_len,
            output_len,
            &mut system_buffer,
        )
        .ok()?;
    let copy_len = (information as usize)
        .min(out.len())
        .min(system_buffer.len());
    out[..copy_len].copy_from_slice(&system_buffer[..copy_len]);
    Some((status.raw(), information))
}

fn dispatch_external_irp_to_device_record(
    device_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    let major = external_major(major)?;
    let input_len = external_len(in_data.len());
    let output_len = external_len(out.len());
    let params = external_irp_parameters(major, fsctl, input_len, output_len)?;
    let mut system_buffer = Vec::new();
    system_buffer.resize(in_data.len().max(out.len()), 0);
    system_buffer[..in_data.len()].copy_from_slice(in_data);
    let (status, information) = io_manager_mut()
        .build_and_dispatch_external_to_device(
            ClientId(IO_MANAGER_COMPONENT_ID),
            nt_io_manager::DeviceId(device_id),
            None::<FileId>,
            file_id,
            major,
            params,
            input_len,
            output_len,
            &mut system_buffer,
        )
        .ok()?;
    let copy_len = (information as usize)
        .min(out.len())
        .min(system_buffer.len());
    out[..copy_len].copy_from_slice(&system_buffer[..copy_len]);
    Some((status.raw(), information))
}

fn register_io_driver(driver_object_path: &str, instance: usize) -> Option<u64> {
    let name = parse_nt_path(driver_object_path)?;
    let io = io_manager_mut();
    let mut dispatch = MajorFunctionTable::new();
    dispatch.set_all(DispatchTarget::DriverPeer(DriverPeerId(0)));
    io.create_driver_peer_with_major_table(
        &name,
        Box::new(HostedDriverBackend { instance }),
        dispatch,
    )
    .ok()
    .map(|driver_id| driver_id.raw())
}

pub(crate) fn register_kernel_io_driver_with_major_table(
    driver_object_path: &str,
    backend: Box<dyn DriverDispatchBackend>,
    dispatch: MajorFunctionTable,
) -> Result<u64, nt_status::NtStatus> {
    let name = parse_nt_path(driver_object_path).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    io_manager_mut()
        .create_kernel_driver_with_major_table(&name, backend, dispatch)
        .map(|driver_id| driver_id.raw())
}

pub(crate) fn driver_id_by_name(path: &str) -> Option<u64> {
    let path = parse_nt_path(path)?;
    io_manager_mut()
        .driver_id_by_name(&path)
        .map(|driver_id| driver_id.raw())
}

pub(crate) fn register_kernel_io_device(
    driver_id: u64,
    device_path: &str,
    device_type: DeviceType,
    characteristics: DeviceCharacteristics,
    flags: DeviceFlags,
    extension_size: u32,
) -> Result<(u64, u64), nt_status::NtStatus> {
    let name = parse_nt_path(device_path).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let device_id = io_manager_mut().create_device(
        DriverId(driver_id),
        Some(&name),
        device_type,
        characteristics,
        flags,
        extension_size,
    )?;
    let object_id = device_object_id(device_id.raw());
    Ok((device_id.raw(), object_id))
}

pub(crate) fn open_io_device(
    device_path: &str,
    desired_access: AccessMask,
) -> Result<(u64, u64, u64, u64), nt_status::NtStatus> {
    let path = parse_nt_path(device_path).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let client = ClientId(IO_MANAGER_COMPONENT_ID);
    let handle = io_manager_mut().open(
        client,
        &path,
        desired_access,
        ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
        CreateOptions::NON_DIRECTORY_FILE,
        1,
    )?;
    let (file_id, device_id, file_object_id) =
        io_manager_mut().reference_open_file_details(client, handle, AccessMask::empty())?;
    Ok((handle.0, file_id.raw(), device_id.raw(), file_object_id.0))
}

pub(crate) fn device_control_on_io_handle(
    handle: u64,
    ioctl: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<u64, nt_status::NtStatus> {
    io_manager_mut().device_control(
        ClientId(IO_MANAGER_COMPONENT_ID),
        HandleValue(handle),
        ioctl,
        input,
        output,
    )
}

pub(crate) fn close_io_handle(handle: u64) -> Result<(), nt_status::NtStatus> {
    io_manager_mut().close(ClientId(IO_MANAGER_COMPONENT_ID), HandleValue(handle))
}

fn register_io_device(driver_id: u64, dc: &DriverComponent) -> Result<u64, nt_status::NtStatus> {
    if dc.devobj == 0 || dc.device_name_len == 0 {
        return Ok(0);
    }
    let Some(name) = captured_nt_path(&dc.device_name_utf16, dc.device_name_len) else {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    };
    let device_id = io_manager_mut().create_device(
        DriverId(driver_id),
        Some(&name),
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )?;
    register_hosted_device_binding(driver_id, device_id.raw(), dc.instance, dc.devobj, 0);
    Ok(device_id.raw())
}

fn register_io_symbolic_link(dc: &DriverComponent) -> Result<(), nt_status::NtStatus> {
    if dc.symlink_link_len == 0 && dc.symlink_target_len == 0 {
        return Ok(());
    }
    let link = captured_nt_path(&dc.symlink_link_utf16, dc.symlink_link_len)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let target = captured_nt_path(&dc.symlink_target_utf16, dc.symlink_target_len)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    io_manager_mut().create_symbolic_link(&link, &target)
}

fn destroy_registered_driver(driver_id: u64) {
    let _ = io_manager_mut().destroy_driver(DriverId(driver_id));
}

#[derive(Clone, Copy)]
struct HostedDeviceBinding {
    driver_id: u64,
    device_id: u64,
    instance: usize,
    device_object: u64,
    pdo_object: u64,
    used: bool,
}

const EMPTY_HOSTED_DEVICE_BINDING: HostedDeviceBinding = HostedDeviceBinding {
    driver_id: 0,
    device_id: 0,
    instance: 0,
    device_object: 0,
    pdo_object: 0,
    used: false,
};

#[derive(Clone, Copy)]
struct HostedRootPdoBinding {
    pdo_object: u64,
    device_id: u64,
    used: bool,
}

const EMPTY_HOSTED_ROOT_PDO_BINDING: HostedRootPdoBinding = HostedRootPdoBinding {
    pdo_object: 0,
    device_id: 0,
    used: false,
};

#[derive(Clone, Copy, Default)]
pub(crate) struct HostedHardwareEvidence {
    pub resource_mmio_phys: u64,
    pub resource_mmio_len: u64,
    pub mmio_mapped_phys: u64,
    pub mmio_mapped_len: u64,
    pub interrupt_vector: u32,
    pub interrupt_id: u64,
    pub interrupt_object: u64,
    pub interrupt_routine: u64,
    pub interrupt_context: u64,
    pub interrupt_delivered_vector: u64,
    pub interrupt_isr_claimed: u64,
    pub interrupt_deliveries: u64,
    pub dpc_deliveries: u64,
    pub dpc_drops: u64,
    pub dma_adapter_id: u64,
    pub dma_adapter_blob: u64,
    pub dma_common_va: u64,
    pub dma_common_len: u64,
    pub dma_common_logical: u64,
    pub dma_requested_len: u64,
    pub dma_allocated_va: u64,
    pub dma_allocated_logical: u64,
    pub root_pdo_started: bool,
}

impl HostedHardwareEvidence {
    pub(crate) fn resource_granted(self) -> bool {
        self.resource_mmio_phys != 0
            || self.interrupt_vector != 0
            || self.dma_common_va != 0
            || self.dma_common_logical != 0
    }

    pub(crate) fn mmio_mapped(self) -> bool {
        self.mmio_mapped_phys != 0 && self.mmio_mapped_len != 0
    }

    pub(crate) fn interrupt_connected(self) -> bool {
        self.interrupt_id != 0 && self.interrupt_object != 0 && self.interrupt_routine != 0
    }

    pub(crate) fn interrupt_delivered(self) -> bool {
        self.interrupt_connected()
            && self.interrupt_deliveries != 0
            && self.interrupt_isr_claimed != 0
            && self.interrupt_delivered_vector == self.interrupt_vector as u64
    }

    pub(crate) fn dpc_delivered(self) -> bool {
        self.dpc_deliveries != 0 && self.dpc_drops == 0
    }

    pub(crate) fn dma_adapter_created(self) -> bool {
        self.dma_adapter_id != 0 && self.dma_adapter_blob != 0
    }

    pub(crate) fn dma_common_allocated(self) -> bool {
        self.dma_allocated_va != 0 && self.dma_allocated_logical != 0 && self.dma_requested_len != 0
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct HostedInterruptDelivery {
    pub interrupt_id: u64,
    pub vector: u32,
    pub claimed: bool,
}

const MAX_HOSTED_DEVICE_BINDINGS: usize = 16;
static mut HOSTED_DEVICE_BINDINGS: [HostedDeviceBinding; MAX_HOSTED_DEVICE_BINDINGS] =
    [EMPTY_HOSTED_DEVICE_BINDING; MAX_HOSTED_DEVICE_BINDINGS];
static mut HOSTED_ROOT_PDO_BINDINGS: [HostedRootPdoBinding; MAX_HOSTED_DEVICE_BINDINGS] =
    [EMPTY_HOSTED_ROOT_PDO_BINDING; MAX_HOSTED_DEVICE_BINDINGS];
static mut HOSTED_ROOT_BUS: Option<nt_root_bus::RootBus> = None;
static mut HOSTED_RESOURCE_MANAGER: Option<ResourceManager> = None;
static mut HOSTED_DMA_MANAGER: Option<HostedDmaManager> = None;
static mut HOSTED_MDL_REGISTRY: Option<MdlRegistry> = None;
static mut HOSTED_DRIVER_DEVICE_POWER_STATE: u32 = 1; // PowerDeviceD0

const HOSTED_MMIO_RESOURCE_KIND: u64 = 1;
const HOSTED_INTERRUPT_RESOURCE_KIND: u64 = 2;

fn hosted_resource_id(device_id: u64, kind: u64) -> Option<u64> {
    device_id.checked_mul(0x100)?.checked_add(kind)
}

fn hosted_mmio_resource_id(device_id: u64) -> Option<u64> {
    hosted_resource_id(device_id, HOSTED_MMIO_RESOURCE_KIND)
}

fn hosted_interrupt_resource_id(device_id: u64) -> Option<u64> {
    hosted_resource_id(device_id, HOSTED_INTERRUPT_RESOURCE_KIND)
}

fn hosted_resource_owner(binding: HostedDeviceBinding) -> ResourceOwner {
    ResourceOwner::new(binding.driver_id, binding.device_id)
}

fn hosted_dma_owner(binding: HostedDeviceBinding) -> DmaOwner {
    DmaOwner::new(binding.driver_id, binding.device_id)
}

unsafe fn hosted_root_bus_mut() -> &'static mut nt_root_bus::RootBus {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_ROOT_BUS);
    if slot.is_none() {
        *slot = Some(nt_root_bus::RootBus::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn hosted_resource_manager_mut() -> &'static mut ResourceManager {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_RESOURCE_MANAGER);
    if slot.is_none() {
        *slot = Some(ResourceManager::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn hosted_dma_manager_mut() -> &'static mut HostedDmaManager {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_DMA_MANAGER);
    if slot.is_none() {
        *slot = Some(HostedDmaManager::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn hosted_mdl_registry_mut() -> &'static mut MdlRegistry {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_MDL_REGISTRY);
    if slot.is_none() {
        *slot = Some(MdlRegistry::new());
    }
    slot.as_mut().unwrap()
}

fn hosted_hal_status(error: HalError) -> nt_status::NtStatus {
    match error {
        HalError::WrongOwner | HalError::AccessDenied => nt_status::NtStatus::ACCESS_DENIED,
        HalError::NotAssigned
        | HalError::OutOfRange
        | HalError::Revoked
        | HalError::StaleId
        | HalError::AlreadyConnected => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
    }
}

fn hosted_dma_status(error: DmaError) -> nt_status::NtStatus {
    match error {
        DmaError::WrongOwner | DmaError::LogicalViolation => nt_status::NtStatus::ACCESS_DENIED,
        DmaError::StaleId | DmaError::Inactive | DmaError::OutOfRange => {
            nt_status::NtStatus::INVALID_DEVICE_REQUEST
        }
    }
}

unsafe fn revoke_hosted_device_resources(binding: HostedDeviceBinding) {
    let _ = hosted_resource_manager_mut().revoke_owner(hosted_resource_owner(binding));
    let _ = hosted_dma_manager_mut().revoke_owner(hosted_dma_owner(binding));
}

unsafe fn clear_hosted_resource_projection(binding: HostedDeviceBinding, sh: u64) {
    revoke_hosted_device_resources(binding);
    write_volatile((sh + SH_RESOURCE_MMIO_PHYS) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_MMIO_LEN) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_MMIO_VA) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_VECTOR) as *mut u32, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_AFFINITY) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_MMIO_MAPPED_PHYS) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_MMIO_MAPPED_LEN) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_OBJECT) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_ROUTINE) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_CONTEXT) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_ID) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_DELIVERED_VECTOR) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_ISR_CLAIMED) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_DELIVERIES) as *mut u64, 0);
    clear_dpc_queue_projection(sh);
    write_volatile((sh + SH_DMA_COMMON_VA) as *mut u64, 0);
    write_volatile((sh + SH_DMA_COMMON_LEN) as *mut u64, 0);
    write_volatile((sh + SH_DMA_COMMON_LOGICAL) as *mut u64, 0);
    write_volatile((sh + SH_DMA_ADAPTER_ID) as *mut u64, 0);
    write_volatile((sh + SH_DMA_ADAPTER_BLOB) as *mut u64, 0);
    write_volatile((sh + SH_DMA_OPS_BLOB) as *mut u64, 0);
    write_volatile((sh + SH_DMA_REQUESTED_LEN) as *mut u64, 0);
    write_volatile((sh + SH_DMA_ALLOCATED_VA) as *mut u64, 0);
    write_volatile((sh + SH_DMA_ALLOCATED_LOGICAL) as *mut u64, 0);
    write_volatile((sh + SH_DMA_FREED_LOGICAL) as *mut u64, 0);
}

fn hosted_root_pdo_device_id(pdo_object: u64) -> Option<u64> {
    let bindings = unsafe { &*core::ptr::addr_of!(HOSTED_ROOT_PDO_BINDINGS) };
    bindings
        .iter()
        .copied()
        .find(|slot| slot.used && slot.pdo_object == pdo_object)
        .map(|slot| slot.device_id)
}

fn register_hosted_root_pdo_binding(
    pdo_object: u64,
    device_id: u64,
) -> Result<(), nt_status::NtStatus> {
    let bindings = unsafe { &mut *core::ptr::addr_of_mut!(HOSTED_ROOT_PDO_BINDINGS) };
    if let Some(slot) = bindings
        .iter_mut()
        .find(|slot| slot.used && slot.pdo_object == pdo_object)
    {
        slot.device_id = device_id;
        return Ok(());
    }
    if let Some(slot) = bindings.iter_mut().find(|slot| !slot.used) {
        *slot = HostedRootPdoBinding {
            pdo_object,
            device_id,
            used: true,
        };
        return Ok(());
    }
    Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES)
}

unsafe fn register_hosted_root_pdo(
    pdo_object: u64,
    instance_path: &str,
    hardware_ids: &[&str],
    compatible_ids: &[&str],
) -> Result<u64, nt_status::NtStatus> {
    if pdo_object == 0 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    if let Some(device_id) = hosted_root_pdo_device_id(pdo_object) {
        return Ok(device_id);
    }
    let root_driver_id = hosted_root_bus_driver_id()?;
    let pdo_device_id = io_manager_mut().create_device(
        root_driver_id,
        None,
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )?;
    if let Err(status) = register_hosted_root_pdo_binding(pdo_object, pdo_device_id.raw()) {
        let _ = io_manager_mut().destroy_device(pdo_device_id);
        return Err(status);
    }
    let (device_id, instance_id) = nt_root_bus::split_enum_instance_path(instance_path);
    let fallback_hardware = [device_id];
    let hardware_refs = if hardware_ids.is_empty() {
        &fallback_hardware[..]
    } else {
        hardware_ids
    };
    let bus = hosted_root_bus_mut();
    bus.create_pdo(
        pdo_object,
        device_id,
        hardware_refs,
        compatible_ids,
        instance_id,
    );
    Ok(pdo_device_id.raw())
}

fn register_hosted_device_binding(
    driver_id: u64,
    device_id: u64,
    instance: usize,
    device_object: u64,
    pdo_object: u64,
) {
    if device_id == 0 || device_object == 0 {
        return;
    }
    let bindings = unsafe { &mut *core::ptr::addr_of_mut!(HOSTED_DEVICE_BINDINGS) };
    if let Some(slot) = bindings
        .iter_mut()
        .find(|slot| slot.used && slot.device_id == device_id)
    {
        *slot = HostedDeviceBinding {
            driver_id,
            device_id,
            instance,
            device_object,
            pdo_object,
            used: true,
        };
        return;
    }
    if let Some(slot) = bindings.iter_mut().find(|slot| !slot.used) {
        *slot = HostedDeviceBinding {
            driver_id,
            device_id,
            instance,
            device_object,
            pdo_object,
            used: true,
        };
    }
}

fn hosted_device_binding_by_device_id(device_id: u64) -> Option<HostedDeviceBinding> {
    let bindings = unsafe { &*core::ptr::addr_of!(HOSTED_DEVICE_BINDINGS) };
    bindings
        .iter()
        .copied()
        .find(|slot| slot.used && slot.device_id == device_id)
}

fn hosted_device_binding_by_device_object(device_object: u64) -> Option<HostedDeviceBinding> {
    let bindings = unsafe { &*core::ptr::addr_of!(HOSTED_DEVICE_BINDINGS) };
    bindings
        .iter()
        .copied()
        .find(|slot| slot.used && slot.device_object == device_object)
}

pub(crate) fn hosted_hardware_evidence(device_id: u64) -> Option<HostedHardwareEvidence> {
    let binding = hosted_device_binding_by_device_id(device_id)?;
    let (_, inst) = instance_by_driver_id(binding.driver_id)?;
    let sh = inst.exec_shared_va;
    let root_pdo_started = unsafe {
        (*core::ptr::addr_of!(HOSTED_ROOT_BUS))
            .as_ref()
            .map(|bus| bus.pdo_started(binding.pdo_object))
            .unwrap_or(false)
    };
    Some(unsafe {
        HostedHardwareEvidence {
            resource_mmio_phys: read_volatile((sh + SH_RESOURCE_MMIO_PHYS) as *const u64),
            resource_mmio_len: read_volatile((sh + SH_RESOURCE_MMIO_LEN) as *const u64),
            mmio_mapped_phys: read_volatile((sh + SH_RESOURCE_MMIO_MAPPED_PHYS) as *const u64),
            mmio_mapped_len: read_volatile((sh + SH_RESOURCE_MMIO_MAPPED_LEN) as *const u64),
            interrupt_vector: read_volatile((sh + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32),
            interrupt_id: read_volatile((sh + SH_RESOURCE_INTERRUPT_ID) as *const u64),
            interrupt_object: read_volatile((sh + SH_RESOURCE_INTERRUPT_OBJECT) as *const u64),
            interrupt_routine: read_volatile((sh + SH_RESOURCE_INTERRUPT_ROUTINE) as *const u64),
            interrupt_context: read_volatile((sh + SH_RESOURCE_INTERRUPT_CONTEXT) as *const u64),
            interrupt_delivered_vector: read_volatile(
                (sh + SH_RESOURCE_INTERRUPT_DELIVERED_VECTOR) as *const u64,
            ),
            interrupt_isr_claimed: read_volatile(
                (sh + SH_RESOURCE_INTERRUPT_ISR_CLAIMED) as *const u64,
            ),
            interrupt_deliveries: read_volatile(
                (sh + SH_RESOURCE_INTERRUPT_DELIVERIES) as *const u64,
            ),
            dpc_deliveries: read_volatile((sh + SH_DPC_DELIVERIES) as *const u64),
            dpc_drops: read_volatile((sh + SH_DPC_QUEUE_DROPS) as *const u64),
            dma_adapter_id: read_volatile((sh + SH_DMA_ADAPTER_ID) as *const u64),
            dma_adapter_blob: read_volatile((sh + SH_DMA_ADAPTER_BLOB) as *const u64),
            dma_common_va: read_volatile((sh + SH_DMA_COMMON_VA) as *const u64),
            dma_common_len: read_volatile((sh + SH_DMA_COMMON_LEN) as *const u64),
            dma_common_logical: read_volatile((sh + SH_DMA_COMMON_LOGICAL) as *const u64),
            dma_requested_len: read_volatile((sh + SH_DMA_REQUESTED_LEN) as *const u64),
            dma_allocated_va: read_volatile((sh + SH_DMA_ALLOCATED_VA) as *const u64),
            dma_allocated_logical: read_volatile((sh + SH_DMA_ALLOCATED_LOGICAL) as *const u64),
            root_pdo_started,
        }
    })
}

fn clear_hosted_device_binding_by_device_id(device_id: u64) {
    let bindings = unsafe { &mut *core::ptr::addr_of_mut!(HOSTED_DEVICE_BINDINGS) };
    if let Some(slot) = bindings
        .iter_mut()
        .find(|slot| slot.used && slot.device_id == device_id)
    {
        unsafe {
            revoke_hosted_device_resources(*slot);
        }
        *slot = EMPTY_HOSTED_DEVICE_BINDING;
    }
}

fn clear_hosted_device_bindings_for_instance(instance: usize) {
    let bindings = unsafe { &mut *core::ptr::addr_of_mut!(HOSTED_DEVICE_BINDINGS) };
    for slot in bindings.iter_mut() {
        if slot.used && slot.instance == instance {
            unsafe {
                revoke_hosted_device_resources(*slot);
            }
            *slot = EMPTY_HOSTED_DEVICE_BINDING;
        }
    }
}

pub(crate) fn destroy_io_driver(driver_id: u64) {
    destroy_registered_driver(driver_id);
}

pub(crate) fn device_object_id(device_id: u64) -> u64 {
    io_manager_mut()
        .device(nt_io_manager::DeviceId(device_id))
        .map(|device| device.object_id.0)
        .unwrap_or(0)
}

/// A live launched IRP driver (a snapshot of the routing facts from its [`DriverComponent`]).
#[derive(Clone, Copy)]
pub(crate) struct DriverInstance {
    pub fault_ep: u64,
    pub pml4: u64,
    pub exec_shared_va: u64,
    pub exec_arg_va: u64,
    pub tcb: u64,
    pub reply_cap: u64,
    pub driver_id: u64,
    pub device_id: u64,
    pub driver_object: u64,
    pub device_object: u64,
    pub driver_unload: u64,
    pub add_device: u64,
    pub ready: bool,
    pub used: bool,
}

const EMPTY_INSTANCE: DriverInstance = DriverInstance {
    fault_ep: 0,
    pml4: 0,
    exec_shared_va: 0,
    exec_arg_va: 0,
    tcb: 0,
    reply_cap: 0,
    driver_id: 0,
    device_id: 0,
    driver_object: 0,
    device_object: 0,
    driver_unload: 0,
    add_device: 0,
    ready: false,
    used: false,
};

/// The live-driver instance table (indexed by [`DriverComponent::instance`]).
static mut DRIVER_INSTANCES: [DriverInstance; MAX_DRIVER_INSTANCES] =
    [EMPTY_INSTANCE; MAX_DRIVER_INSTANCES];

/// Record a launched driver in [`DRIVER_INSTANCES`] (called by [`load_driver`]). "Ready" iff it
/// parked at its dispatch loop with a control DEVICE_OBJECT (an FSD; a filter/device without an
/// IoCreateDevice may still be ready — see [`register_instance_ready`]).
fn register_instance(dc: &DriverComponent) {
    // SAFETY: single-threaded executive; the table is written here + read in dispatch_irp.
    let t = unsafe { &mut *core::ptr::addr_of_mut!(DRIVER_INSTANCES) };
    if dc.instance < t.len() {
        t[dc.instance] = DriverInstance {
            fault_ep: dc.fault_ep,
            pml4: dc.pml4,
            exec_shared_va: dc.exec_shared_va,
            exec_arg_va: dc.exec_arg_va,
            tcb: dc.tcb,
            reply_cap: dc.reply_cap,
            driver_id: dc.driver_id,
            device_id: dc.device_id,
            driver_object: dc.drvobj,
            device_object: dc.devobj,
            driver_unload: dc.driver_unload,
            add_device: dc.add_device,
            // Default readiness = npfs's historic rule (parked + a control device object). A
            // driver that fills its MJ table but creates no control device (a minimal filter/FSD)
            // is marked ready explicitly by the caller via `register_instance_ready`.
            ready: dc.finished && dc.devobj != 0,
            used: true,
        };
    }
}

pub(crate) fn driver_object_id(driver_id: u64) -> u64 {
    io_manager_mut()
        .driver(DriverId(driver_id))
        .map(|driver| driver.object_id.0)
        .unwrap_or(0)
}

fn clear_instance(i: usize) {
    clear_hosted_device_bindings_for_instance(i);
    let t = unsafe { &mut *core::ptr::addr_of_mut!(DRIVER_INSTANCES) };
    if i < t.len() {
        t[i] = EMPTY_INSTANCE;
    }
}

/// Mark instance `i` ready for IRP dispatch (used when readiness ≠ npfs's "has a devobj" rule, e.g.
/// a minimal driver that fills MajorFunction[] but creates no control DEVICE_OBJECT).
fn register_instance_ready(i: usize, ready: bool) {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(DRIVER_INSTANCES) };
    if i < t.len() && t[i].used {
        t[i].ready = ready;
    }
}

/// Mark a launched driver ready/unready for dispatch by canonical driver route id.
pub(crate) fn register_driver_ready(driver_id: u64, ready: bool) {
    if let Some((i, _)) = instance_by_driver_id(driver_id) {
        register_instance_ready(i, ready);
    }
}

/// The PML4 (VSpace) cap of a launched driver route (0 = not launched).
pub(crate) fn driver_pml4(driver_id: u64) -> u64 {
    instance_by_driver_id(driver_id)
        .map(|(_, d)| d.pml4)
        .unwrap_or(0)
}

#[allow(dead_code)]
pub(crate) fn driver_add_device(driver_id: u64) -> u64 {
    instance_by_driver_id(driver_id)
        .map(|(_, d)| d.add_device)
        .unwrap_or(0)
}

/// Snapshot of a live instance, or None if `i` isn't launched.
fn instance(i: usize) -> Option<DriverInstance> {
    let t = unsafe { &*core::ptr::addr_of!(DRIVER_INSTANCES) };
    if i < t.len() && t[i].used {
        Some(t[i])
    } else {
        None
    }
}

fn instance_by_driver_id(driver_id: u64) -> Option<(usize, DriverInstance)> {
    let t = unsafe { &*core::ptr::addr_of!(DRIVER_INSTANCES) };
    t.iter()
        .copied()
        .enumerate()
        .find(|(_, entry)| entry.used && entry.driver_id == driver_id)
}

fn instance_by_device_id(device_id: u64) -> Option<(usize, DriverInstance)> {
    let t = unsafe { &*core::ptr::addr_of!(DRIVER_INSTANCES) };
    t.iter()
        .copied()
        .enumerate()
        .find(|(_, entry)| entry.used && entry.device_id == device_id)
}

fn instance_by_device_object(device_object: u64) -> Option<(usize, DriverInstance)> {
    let t = unsafe { &*core::ptr::addr_of!(DRIVER_INSTANCES) };
    t.iter()
        .copied()
        .enumerate()
        .find(|(_, entry)| entry.used && entry.device_object == device_object)
}

fn destroy_registered_driver_after_unload(driver_id: u64) -> Result<(), nt_status::NtStatus> {
    io_manager_mut()
        .destroy_driver(DriverId(driver_id))
        .map(|_| ())
}

unsafe fn dispatch_driver_unload_for_instance(
    index: usize,
    inst: DriverInstance,
) -> Result<(), nt_status::NtStatus> {
    if inst.driver_object == 0 || inst.driver_unload == 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }

    let sh = inst.exec_shared_va;
    write_volatile((sh + SH_REQ_MAJOR) as *mut u64, FSD_DISPATCH_UNLOAD);
    write_volatile((sh + SH_REQ_MINOR) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FSCTL) as *mut u64, 0);
    write_volatile((sh + SH_REQ_INLEN) as *mut u64, 0);
    write_volatile((sh + SH_REQ_OUTLEN) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FILEID) as *mut u64, 0);
    write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);

    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: inst.fault_ep,
        pml4: inst.pml4,
        code_va: 0,
        image_frames: 0,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        client_pi: 0,
        callback_client: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    if !pr.completed {
        register_instance_ready(index, false);
        return Err(nt_status::NtStatus::UNSUCCESSFUL);
    }
    nt_status::NtStatus(pr.status).to_result()
}

struct AddDeviceDispatchResult {
    pdo_object: u64,
    fdo_object: u64,
}

unsafe fn dispatch_add_device_for_instance(
    index: usize,
    inst: DriverInstance,
) -> Result<AddDeviceDispatchResult, nt_status::NtStatus> {
    if inst.driver_object == 0 || inst.add_device == 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }

    let sh = inst.exec_shared_va;
    write_volatile((sh + SH_REQ_MAJOR) as *mut u64, FSD_DISPATCH_ADD_DEVICE);
    write_volatile((sh + SH_REQ_MINOR) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FSCTL) as *mut u64, 0);
    write_volatile((sh + SH_REQ_INLEN) as *mut u64, 0);
    write_volatile((sh + SH_REQ_OUTLEN) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FILEID) as *mut u64, 0);
    write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);

    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: inst.fault_ep,
        pml4: inst.pml4,
        code_va: 0,
        image_frames: 0,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        client_pi: 0,
        callback_client: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    if !pr.completed {
        register_instance_ready(index, false);
        return Err(nt_status::NtStatus::UNSUCCESSFUL);
    }
    nt_status::NtStatus(pr.status).to_result()?;
    let fdo_object = read_volatile((sh + SH_REQ_INFO) as *const u64);
    let pdo_object = read_volatile((sh + SH_REQ_FILEID) as *const u64);
    if fdo_object == 0 || pdo_object == 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(AddDeviceDispatchResult {
        pdo_object,
        fdo_object,
    })
}

/// Invoke a loaded WDM driver's real `DriverExtension->AddDevice` for one registry-selected devnode
/// and publish the FDO it creates as an unnamed I/O Manager device owned by that driver.
pub(crate) unsafe fn call_add_device_for_driver(
    driver_id: u64,
    instance_path: &str,
    hardware_ids: &[&str],
    compatible_ids: &[&str],
) -> Result<u64, nt_status::NtStatus> {
    let (index, inst) =
        instance_by_driver_id(driver_id).ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    let add_device = dispatch_add_device_for_instance(index, inst)?;
    let pdo_device_id = register_hosted_root_pdo(
        add_device.pdo_object,
        instance_path,
        hardware_ids,
        compatible_ids,
    )?;
    let device_id = io_manager_mut().create_device(
        DriverId(driver_id),
        None,
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )?;
    register_hosted_device_binding(
        driver_id,
        device_id.raw(),
        index,
        add_device.fdo_object,
        add_device.pdo_object,
    );
    io_manager_mut().attach_device_to_stack(device_id, nt_io_manager::DeviceId(pdo_device_id))?;

    let table = &mut *core::ptr::addr_of_mut!(DRIVER_INSTANCES);
    if index < table.len() && table[index].used {
        table[index].device_id = device_id.raw();
        table[index].device_object = add_device.fdo_object;
        table[index].ready = true;
    }
    Ok(device_id.raw())
}

/// Grant a hosted device driver access to the MMIO/interrupt resources selected for its devnode.
///
/// This is the executive mechanism behind the `CM_RESOURCE_LIST` passed at START: BAR frames are
/// mapped into the isolated component VSpace, and the shared page records the only physical range
/// and interrupt vector that `MmMapIoSpace`/`IoConnectInterrupt` may accept.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn grant_hosted_device_resources(
    device_id: u64,
    mmio_phys: u64,
    mmio_len: u64,
    mmio_va: u64,
    mmio_frame_base: u64,
    mmio_pages: u64,
    interrupt_vector: u32,
    interrupt_latched: bool,
    interrupt_affinity: u64,
    dma_va: u64,
    dma_frame_base: u64,
    dma_pages: u64,
    dma_logical: u64,
    dma_len: u64,
) -> Result<(), nt_status::NtStatus> {
    if mmio_phys == 0
        || mmio_len == 0
        || mmio_va == 0
        || mmio_frame_base == 0
        || mmio_pages == 0
        || interrupt_vector == 0
        || interrupt_affinity > u32::MAX as u64
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let has_dma =
        dma_va != 0 || dma_frame_base != 0 || dma_pages != 0 || dma_logical != 0 || dma_len != 0;
    if has_dma
        && (dma_va == 0
            || dma_frame_base == 0
            || dma_pages == 0
            || dma_logical == 0
            || dma_len == 0)
    {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let binding = hosted_device_binding_by_device_id(device_id)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let (_, inst) = instance_by_driver_id(binding.driver_id)
        .ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    let owner = hosted_resource_owner(binding);
    let mmio_resource_id =
        hosted_mmio_resource_id(device_id).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let interrupt_resource_id =
        hosted_interrupt_resource_id(device_id).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    clear_hosted_resource_projection(binding, inst.exec_shared_va);
    let mapped_len = mmio_len.min(mmio_pages.saturating_mul(0x1000));
    ensure_paging(mmio_va, inst.pml4);
    let mut page = 0u64;
    while page < mmio_pages {
        let err = page_map_r(
            copy_cap(mmio_frame_base + page),
            mmio_va + page * 0x1000,
            RW_NX,
            inst.pml4,
        );
        if err != 0 {
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        page += 1;
    }

    let mut mapped_dma_len = 0u64;
    let mut dma_adapter_id = 0u64;
    if has_dma {
        mapped_dma_len = dma_len.min(dma_pages.saturating_mul(0x1000));
        if mapped_dma_len == 0 || dma_len > mapped_dma_len {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        ensure_paging(dma_va, inst.pml4);
        let mut dma_page = 0u64;
        while dma_page < dma_pages {
            let err = page_map_r(
                copy_cap(dma_frame_base + dma_page),
                dma_va + dma_page * 0x1000,
                RW_NX,
                inst.pml4,
            );
            if err != 0 {
                return Err(nt_status::NtStatus::UNSUCCESSFUL);
            }
            dma_page += 1;
        }
        dma_adapter_id = hosted_dma_manager_mut().register_adapter(
            hosted_dma_owner(binding),
            true,
            dma_len,
            true,
        );
    }

    let rm = hosted_resource_manager_mut();
    rm.assign_memory(
        owner,
        mmio_resource_id,
        mmio_phys,
        mmio_va,
        mapped_len,
        nt_hal_abi::MM_NON_CACHED,
        nt_hal_abi::RIGHT_READ | nt_hal_abi::RIGHT_WRITE,
    );
    rm.assign_interrupt(
        owner,
        interrupt_resource_id,
        interrupt_vector,
        interrupt_vector as u8,
        interrupt_affinity as u32,
        if interrupt_latched {
            nt_hal_abi::INT_MODE_LATCHED
        } else {
            nt_hal_abi::INT_MODE_LEVEL_SENSITIVE
        },
    );

    let sh = inst.exec_shared_va;
    write_volatile((sh + SH_RESOURCE_MMIO_PHYS) as *mut u64, mmio_phys);
    write_volatile((sh + SH_RESOURCE_MMIO_LEN) as *mut u64, mapped_len);
    write_volatile((sh + SH_RESOURCE_MMIO_VA) as *mut u64, mmio_va);
    write_volatile(
        (sh + SH_RESOURCE_INTERRUPT_VECTOR) as *mut u32,
        interrupt_vector,
    );
    write_volatile(
        (sh + SH_RESOURCE_INTERRUPT_AFFINITY) as *mut u64,
        interrupt_affinity,
    );
    write_volatile((sh + SH_RESOURCE_MMIO_MAPPED_PHYS) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_MMIO_MAPPED_LEN) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_OBJECT) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_ROUTINE) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_CONTEXT) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_ID) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_DELIVERED_VECTOR) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_ISR_CLAIMED) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_INTERRUPT_DELIVERIES) as *mut u64, 0);
    clear_dpc_queue_projection(sh);
    write_volatile((sh + SH_DMA_COMMON_VA) as *mut u64, dma_va);
    write_volatile((sh + SH_DMA_COMMON_LEN) as *mut u64, mapped_dma_len);
    write_volatile((sh + SH_DMA_COMMON_LOGICAL) as *mut u64, dma_logical);
    write_volatile((sh + SH_DMA_ADAPTER_ID) as *mut u64, dma_adapter_id);
    write_volatile((sh + SH_DMA_ADAPTER_BLOB) as *mut u64, 0);
    write_volatile((sh + SH_DMA_OPS_BLOB) as *mut u64, 0);
    write_volatile((sh + SH_DMA_REQUESTED_LEN) as *mut u64, 0);
    write_volatile((sh + SH_DMA_ALLOCATED_VA) as *mut u64, 0);
    write_volatile((sh + SH_DMA_ALLOCATED_LOGICAL) as *mut u64, 0);
    write_volatile((sh + SH_DMA_FREED_LOGICAL) as *mut u64, 0);
    Ok(())
}

unsafe fn record_hosted_resource_usage(
    binding: HostedDeviceBinding,
    sh: u64,
) -> Result<(), nt_status::NtStatus> {
    let owner = hosted_resource_owner(binding);
    let grant_phys = read_volatile((sh + SH_RESOURCE_MMIO_PHYS) as *const u64);
    let grant_len = read_volatile((sh + SH_RESOURCE_MMIO_LEN) as *const u64);
    let grant_va = read_volatile((sh + SH_RESOURCE_MMIO_VA) as *const u64);
    let mapped_phys = read_volatile((sh + SH_RESOURCE_MMIO_MAPPED_PHYS) as *const u64);
    let mapped_len = read_volatile((sh + SH_RESOURCE_MMIO_MAPPED_LEN) as *const u64);
    if mapped_phys != 0 || mapped_len != 0 {
        if grant_phys == 0 || grant_len == 0 || grant_va == 0 || mapped_len == 0 {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let mapped_offset = mapped_phys
            .checked_sub(grant_phys)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        if mapped_offset > grant_len || mapped_len > grant_len - mapped_offset {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let mapped = hosted_resource_manager_mut()
            .map_io_space(owner, mapped_phys, mapped_len, nt_hal_abi::MM_NON_CACHED)
            .map_err(hosted_hal_status)?;
        if mapped.resource_id
            != hosted_mmio_resource_id(binding.device_id)
                .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?
            || mapped.translated_start != grant_va + mapped_offset
            || mapped.length != mapped_len
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
    }

    let interrupt_object = read_volatile((sh + SH_RESOURCE_INTERRUPT_OBJECT) as *const u64);
    let service_routine = read_volatile((sh + SH_RESOURCE_INTERRUPT_ROUTINE) as *const u64);
    let service_context = read_volatile((sh + SH_RESOURCE_INTERRUPT_CONTEXT) as *const u64);
    if interrupt_object != 0 || service_routine != 0 || service_context != 0 {
        if interrupt_object == 0 || service_routine == 0 {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let interrupt_id = hosted_interrupt_resource_id(binding.device_id)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        let connected = hosted_resource_manager_mut()
            .connect_interrupt(owner, interrupt_id, service_routine, service_context)
            .map_err(hosted_hal_status)?;
        if connected == 0 {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        write_volatile((sh + SH_RESOURCE_INTERRUPT_ID) as *mut u64, connected);
    }

    let dma_adapter_id = read_volatile((sh + SH_DMA_ADAPTER_ID) as *const u64);
    let dma_adapter_blob = read_volatile((sh + SH_DMA_ADAPTER_BLOB) as *const u64);
    let dma_grant_va = read_volatile((sh + SH_DMA_COMMON_VA) as *const u64);
    let dma_grant_len = read_volatile((sh + SH_DMA_COMMON_LEN) as *const u64);
    let dma_grant_logical = read_volatile((sh + SH_DMA_COMMON_LOGICAL) as *const u64);
    if dma_adapter_blob != 0 && dma_adapter_id == 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }

    let dma_requested_len = read_volatile((sh + SH_DMA_REQUESTED_LEN) as *const u64);
    let dma_allocated_va = read_volatile((sh + SH_DMA_ALLOCATED_VA) as *const u64);
    let dma_allocated_logical = read_volatile((sh + SH_DMA_ALLOCATED_LOGICAL) as *const u64);
    if dma_requested_len != 0 || dma_allocated_va != 0 || dma_allocated_logical != 0 {
        if dma_adapter_id == 0
            || dma_adapter_blob == 0
            || dma_grant_va == 0
            || dma_grant_len == 0
            || dma_grant_logical == 0
            || dma_requested_len == 0
            || dma_requested_len > dma_grant_len
            || dma_allocated_va != dma_grant_va
            || dma_allocated_logical != dma_grant_logical
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        hosted_dma_manager_mut()
            .register_common_buffer_at(
                hosted_dma_owner(binding),
                dma_adapter_id,
                dma_allocated_logical,
                dma_requested_len,
                dma_allocated_va,
            )
            .map_err(hosted_dma_status)?;
    }

    Ok(())
}

/// Send `IRP_MN_START_DEVICE` to a hosted FDO. `resource_list` is the caller-selected
/// `CM_RESOURCE_LIST` byte image; an empty slice represents a no-resource devnode.
pub(crate) unsafe fn start_hosted_device(
    device_id: u64,
    resource_list: &[u8],
) -> Result<(), nt_status::NtStatus> {
    let binding = hosted_device_binding_by_device_id(device_id)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let (_, inst) = instance_by_driver_id(binding.driver_id)
        .ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    if !inst.ready {
        return Err(nt_status::NtStatus(0xC000_00A3u32 as i32)); // STATUS_DEVICE_NOT_READY
    }
    let sh = inst.exec_shared_va;
    if resource_list.is_empty() {
        clear_hosted_resource_projection(binding, sh);
    }
    write_volatile((sh + SH_ROOT_PDO_FORWARDED_MINOR) as *mut u64, u64::MAX);
    write_volatile(
        (sh + SH_ROOT_PDO_FORWARDED_STATUS) as *mut i32,
        0xC000_0010u32 as i32,
    );
    let mut out = [];
    let (status, _) = dispatch_irp_for_instance(
        binding.instance,
        IRP_MJ_PNP,
        IRP_MN_START_DEVICE,
        binding.device_object,
        0,
        binding.pdo_object,
        resource_list,
        &mut out,
    )
    .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    record_hosted_resource_usage(binding, sh)?;
    nt_status::NtStatus(status).to_result()?;

    let forwarded_minor = read_volatile((sh + SH_ROOT_PDO_FORWARDED_MINOR) as *const u64);
    let forwarded_status = read_volatile((sh + SH_ROOT_PDO_FORWARDED_STATUS) as *const i32);
    if forwarded_minor <= u8::MAX as u64 && forwarded_status == 0 {
        let root_status =
            hosted_root_bus_mut().dispatch_pnp(binding.pdo_object, forwarded_minor as u8);
        nt_status::NtStatus(root_status).to_result()?;
    }
    Ok(())
}

/// Deliver one interrupt to a hosted device through its connected generic resource grant.
///
/// The executive resolves the canonical `nt-resource-manager` interrupt id for the devnode, then
/// drives the hosted component's dispatcher so the driver's ISR runs in the same VSpace that
/// registered it with `IoConnectInterrupt`.
pub(crate) unsafe fn inject_hosted_device_interrupt(
    device_id: u64,
) -> Result<HostedInterruptDelivery, nt_status::NtStatus> {
    let binding = hosted_device_binding_by_device_id(device_id)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let (_, inst) = instance_by_driver_id(binding.driver_id)
        .ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    if !inst.ready {
        return Err(nt_status::NtStatus(0xC000_00A3u32 as i32)); // STATUS_DEVICE_NOT_READY
    }

    let sh = inst.exec_shared_va;
    let interrupt_id = read_volatile((sh + SH_RESOURCE_INTERRUPT_ID) as *const u64);
    let interrupt_vector = read_volatile((sh + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32);
    let service_routine = read_volatile((sh + SH_RESOURCE_INTERRUPT_ROUTINE) as *const u64);
    let service_context = read_volatile((sh + SH_RESOURCE_INTERRUPT_CONTEXT) as *const u64);
    if interrupt_id == 0 || interrupt_vector == 0 || service_routine == 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }

    let tokens = hosted_resource_manager_mut()
        .inject_interrupt(interrupt_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if tokens.vector != interrupt_vector
        || tokens.service_routine_token != service_routine
        || tokens.service_context_token != service_context
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }

    let mut out = [];
    let (status, info) = dispatch_irp_for_instance(
        binding.instance,
        FSD_DISPATCH_INTERRUPT,
        tokens.vector as u64,
        binding.device_object,
        0,
        tokens.interrupt_id,
        &[],
        &mut out,
    )
    .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    nt_status::NtStatus(status).to_result()?;

    Ok(HostedInterruptDelivery {
        interrupt_id: tokens.interrupt_id,
        vector: tokens.vector,
        claimed: info != 0,
    })
}

/// Route SCM/native driver stop through the live hosted driver's real `DriverUnload`, then remove
/// canonical I/O Manager records and Object Manager namespace entries.
pub(crate) unsafe fn unload_driver_by_name(
    driver_object_path: &str,
) -> Result<(), nt_status::NtStatus> {
    let driver_id =
        driver_id_by_name(driver_object_path).ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    let (index, inst) =
        instance_by_driver_id(driver_id).ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    if inst.driver_unload == 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }

    {
        let io = io_manager_mut();
        io.request_driver_unload_records(DriverId(driver_id))?;
        if let Err(status) = io.can_destroy_driver(DriverId(driver_id)) {
            if status == nt_status::NtStatus::DELETE_PENDING {
                return Ok(());
            }
            return Err(status);
        }
    }

    dispatch_driver_unload_for_instance(index, inst)?;
    if inst.tcb != 0 {
        let _ = crate::tcb_suspend_r(inst.tcb);
    }
    destroy_registered_driver_after_unload(driver_id)?;
    clear_instance(index);
    Ok(())
}

pub(crate) fn device_id_by_name(path: &str) -> Option<u64> {
    let path = parse_nt_path(path)?;
    io_manager_mut()
        .device_id_by_name(&path)
        .map(|device_id| device_id.raw())
}

fn device_id_by_object_id(object_id: u64) -> Option<u64> {
    if object_id == 0 {
        return None;
    }
    io_manager_mut()
        .device_id_by_object_id(ObjectId(object_id))
        .map(|device_id| device_id.raw())
}

/// Whether the driver-declared `\Device\NamedPipe` route is ready to serve IRPs.
pub(crate) fn npfs_ready() -> bool {
    device_id_by_name("\\Device\\NamedPipe")
        .and_then(instance_by_device_id)
        .map(|(_, d)| d.ready)
        .unwrap_or(false)
}

/// The PML4 (VSpace) cap behind `\Device\NamedPipe` (0 = not launched).
pub(crate) fn npfs_pml4() -> u64 {
    device_id_by_name("\\Device\\NamedPipe")
        .and_then(instance_by_device_id)
        .map(|(_, d)| d.pml4)
        .unwrap_or(0)
}

/// The opaque FILE_OBJECT id (npfs's `FsContext`) from the last dispatched IRP to
/// `\Device\NamedPipe`.
pub(crate) unsafe fn npfs_last_file_id() -> u64 {
    let sh = device_id_by_name("\\Device\\NamedPipe")
        .and_then(instance_by_device_id)
        .map(|(_, d)| d.exec_shared_va)
        .unwrap_or(FSD_SHARED_VADDR);
    read_volatile((sh + SH_REQ_FILEID) as *const u64)
}

/// Route one IRP to launched driver `inst`: fill the shared request fields, drive its dispatch loop
/// (a plain Send wakes it; it runs `MajorFunction[major]` in its own context; a fault mid-IRP lands
/// on its fault EP → demand-map + resume), then read back the completion. Returns `(status,
/// information)`. `major` is an `IRP_MJ_*`; `in_data` is copied into the instance's ARG frame
/// (buffered I/O); `out` receives the driver's output. Returns `None` if `inst` isn't ready.
///
/// This is the private component transport engine. Public callers route through driver/device ids
/// and Object Manager object ids.
unsafe fn dispatch_irp_for_instance(
    inst: usize,
    major: u64,
    minor: u64,
    device_object: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    let d = instance(inst)?;
    if !d.ready {
        return None;
    }
    let ep = d.fault_ep;
    let pml4 = d.pml4;
    let sh = d.exec_shared_va;
    // buffered I/O: copy input into the instance's ARG frame (mapped RW in both AS).
    let arg = d.exec_arg_va;
    let inlen = in_data.len().min((FSD_ARG_FRAMES * 0x1000) as usize);
    for i in 0..inlen {
        write_volatile((arg + i as u64) as *mut u8, in_data[i]);
    }
    write_volatile((sh + SH_DEVOBJ) as *mut u64, device_object);
    write_volatile((sh + SH_REQ_MAJOR) as *mut u64, major);
    write_volatile((sh + SH_REQ_MINOR) as *mut u64, minor);
    write_volatile((sh + SH_REQ_FSCTL) as *mut u64, fsctl);
    write_volatile((sh + SH_REQ_INLEN) as *mut u64, inlen as u64);
    write_volatile((sh + SH_REQ_OUTLEN) as *mut u64, out.len() as u64);
    write_volatile((sh + SH_REQ_FILEID) as *mut u64, file_id);
    write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);

    // Wake the component (plain Send) + drive its fault loop until it re-parks, THROUGH THE SHARED
    // HARNESS PUMP. The per-IRP loop only walls on the low-address guard (image_frames=0 → no
    // in-image wall), demand-caps at 256, all win32k caps false — degenerate to today's inline loop
    // EXACTLY. `component_pump` bumps `HARNESS_IRP_DISPATCHES` per serviced dispatch (the
    // `exec_fsd_on_shared_harness` proof). Status is read at SH_REQ_STATUS(0x70) by kind=Irp.
    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: ep,
        pml4,
        code_va: 0,
        image_frames: 0, // per-IRP loop: no in-image wall (matches the old `addr < 0x10000` guard)
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        // ★ The component is blocked in its dispatch `Call`, bound to this instance's reply object;
        // we hand it the request by ANSWERING that Call. `reply_on` is `decode_reply` — it cannot
        // block, so the executive can never wedge on a component that is not receiving.
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: d.tcb,
        reply_cap: d.reply_cap,
        client_pi: 0,
        callback_client: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let bugchecks_before = FSD_BUGCHECKS.load(Ordering::Relaxed);
    // DIAGNOSTIC (bounded): an IRP dispatch is the ONE place the executive blocks on a hosted
    // component, so an `ENTER` with no matching `EXIT` is the signature of a driver that never
    // returned (the failure mode that used to end the boot in a 555-second silence).
    if FSD_DISPATCH_TRACE < 40 {
        FSD_DISPATCH_TRACE += 1;
        print_str(b"[fsd-svc] ENTER inst=");
        print_u64(inst as u64);
        print_str(b" major=");
        print_u64(major);
        print_str(b" fid=");
        print_hex(file_id as u32);
        print_str(b"\n");
    }
    let pr = crate::spawn_hosts::component_pump(&ch);
    if FSD_DISPATCH_TRACE <= 40 {
        print_str(b"[fsd-svc] EXIT inst=");
        print_u64(inst as u64);
        print_str(b" major=");
        print_u64(major);
        print_str(b" status=");
        print_hex(pr.status as u32);
        print_str(b"\n");
    }
    // Attribute any bugcheck the component raised to THIS instance — the executive is the only side
    // that knows which hosted component it just drove.
    if FSD_BUGCHECKS.load(Ordering::Relaxed) != bugchecks_before {
        FSD_BUGCHECK_INSTANCE.store(inst as u64 + 1, Ordering::Relaxed);
        print_str(b"[fsd-bugcheck] raised by hosted driver instance=");
        print_u64(inst as u64);
        print_str(b" during IRP_MJ_");
        print_u64(major);
        print_str(b" -> dispatch failed CLEANLY (component still serving)\n");
    }
    if !pr.completed {
        print_str(b"[fsd-svc] IRP fault wall inst=");
        print_u64(inst as u64);
        print_str(b" addr=0x");
        print_hex(pr.wall_addr as u32);
        print_str(b" -> instance RETIRED (component suspended by the pump)\n");
        // ★ Transport risk R2: the pump has SUSPENDED this component's TCB, and its reply object is
        // left bound to a thread that will never run again. Retire the instance so no later dispatch
        // can `reply_on` that stale binding (which the kernel would deliver as a FAULT reply).
        register_instance_ready(inst, false);
        return Some((0xC000_0001u32 as i32, 0)); // STATUS_UNSUCCESSFUL
    }
    let st = pr.status;
    // IoStatus.Information is at SH_REQ_INFO(0x78); the pump doesn't touch it.
    let info = read_volatile((sh + SH_REQ_INFO) as *const u64);
    // copy the driver's output back out (buffered I/O).
    let outlen = (info as usize).min(out.len());
    for i in 0..outlen {
        out[i] = read_volatile((arg + i as u64) as *const u8);
    }
    Some((st, info))
}

/// Route one IRP to a launched driver by its canonical driver route id.
pub(crate) unsafe fn dispatch_irp_to_driver(
    driver_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    let (_, inst) = instance_by_driver_id(driver_id)?;
    if !inst.ready || inst.driver_object == 0 {
        return None;
    }
    if io_manager_mut().driver(DriverId(driver_id)).is_none() {
        return None;
    }
    dispatch_external_irp_to_driver_record(driver_id, major, fsctl, file_id, in_data, out)
}

/// Route one IRP to a launched device by its canonical device route id.
pub(crate) unsafe fn dispatch_irp_to_device(
    device_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    let binding = hosted_device_binding_by_device_id(device_id)?;
    let (_, inst) = instance_by_driver_id(binding.driver_id)?;
    if !inst.ready || inst.driver_id == 0 || binding.device_object == 0 {
        return None;
    }
    if io_manager_mut()
        .device(nt_io_manager::DeviceId(device_id))
        .is_none()
    {
        return None;
    }
    dispatch_external_irp_to_device_record(device_id, major, fsctl, file_id, in_data, out)
}

/// Route one IRP to a launched device by the Object Manager Device object id.
pub(crate) unsafe fn dispatch_irp_to_device_object(
    object_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    let device_id = device_id_by_object_id(object_id)?;
    dispatch_irp_to_device(device_id, major, fsctl, file_id, in_data, out)
}

unsafe fn dispatch_irp_to_named_device(
    path: &str,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    let device_id = device_id_by_name(path)?;
    let object_id = io_manager_mut()
        .device(nt_io_manager::DeviceId(device_id))
        .map(|device| device.object_id.0)
        .unwrap_or(0);
    if object_id != 0 {
        dispatch_irp_to_device_object(object_id, major, fsctl, file_id, in_data, out)
    } else {
        dispatch_irp_to_device(device_id, major, fsctl, file_id, in_data, out)
    }
}

/// Route one IRP to the driver-declared `\Device\NamedPipe` route. Kept as a semantic npfs wrapper
/// for existing named-pipe call sites; it no longer assumes instance 0.
pub(crate) unsafe fn npfs_dispatch_irp(
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    dispatch_irp_to_named_device("\\Device\\NamedPipe", major, fsctl, file_id, in_data, out)
}
