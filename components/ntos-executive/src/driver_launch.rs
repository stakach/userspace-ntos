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
//!     + IPC-buf + fault EP + a shared handoff arena; NO device caps.
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
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use nt_compat_exports::DriverExportRegistry;
use nt_dma_manager::{DmaError, DmaManager as HostedDmaManager, DmaOwner};
use nt_io_abi::major;
use nt_io_manager::{
    write_wdm_file_object, write_wdm_io_stack_location, write_wdm_irp, CreateOptions,
    DeviceCharacteristics, DeviceControlParameters, DeviceFlags, DeviceType, DispatchContext,
    DispatchOutcome, DispatchTarget, DriverDispatchBackend, DriverId, DriverPeerId, FileId,
    InformationParameters, IoManager, IoParameters, IrpId, IrpProjection, MajorFunctionTable,
    ObjectManagerPort, ReadWriteParameters, ShareAccess, WdmFileObjectInit, WdmIoStackLocationInit,
    WdmIoStackParameters, WdmIrpInit, WDM_X64_DRIVER_EXTENSION_OFFSET,
    WDM_X64_DRIVER_EXTENSION_SIZE, WDM_X64_DRIVER_MAJOR_FUNCTION_OFFSET,
    WDM_X64_DRIVER_OBJECT_SIZE, WDM_X64_DRIVER_UNLOAD_OFFSET, WDM_X64_FILE_OBJECT_SIZE,
    WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IO_TYPE_FILE, WDM_X64_IRP_SIZE,
};
use nt_kernel_exec::{kevent, EventKind};
use nt_mdl::MdlRegistry;
use nt_resource_manager::{HalError, ResourceManager, ResourceOwner};
use nt_types::{AccessMask, ClientId, HandleValue};
use nt_types::{NtPath, ObjectId};

// Pure, driver-agnostic ntoskrnl byte/string primitives shared with the Subsystem (win32k) class.
use crate::ntoskrnl_shared::{s_memcpy, s_memmove, s_memset, s_rtl_compare_memory, s_wcslen};

use crate::*;

// =============================================================================================
// The generic FSD-class component surface (formerly `npfs_host.rs`).
//
// A hosted file-system driver (npfs today; fastfat/ntfs next) runs as an ISOLATED component in
// its OWN VSpace/CNode/TCB (an FSD-class descriptor, NO device caps). The trampolines + entry +
// IRP dispatch loop below are GENERIC to any FSD — they are NOT npfs-specific machinery:
//   * the ntoskrnl-import TRAMPOLINES are the SHARED ntoskrnl surface an FSD links against. The
//     executive registers each trampoline VA by import provider DLL + name into a
//     [`DriverExportRegistry`] (`nt-compat-exports`, the same mechanism win32k uses); the loader
//     resolves the driver's IAT through it ([`fsd_export_addr`]). The pure prefix-match logic is
//     `nt_kernel_exec::np_prefix`.
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
/// +0x1000). Hosted FSD/NDIS boot drivers currently fit comfortably inside one mapped 2 MiB window;
/// keep the allocation honest so unused per-instance frames do not consume root untyped headroom.
pub const FSD_POOL_VADDR: u64 = 0x0000_0100_0E80_0000;
pub const FSD_POOL_FRAMES: u64 = 512; // 2 MiB, pre-mapped

/// The component's own stack (32 frames = 128 KiB, own PT). An FSD's dispatch call chains
/// (NpFsdCreate → Np*) are moderately deep.
pub const FSD_STACK_VADDR: u64 = 0x0000_0100_0F00_0000;
pub const FSD_STACK_FRAMES: u64 = 32;

/// Aux PT window holding the DATA + SHARED + ARG frames (one 2 MiB PT).
pub const FSD_AUX_PT_VADDR: u64 = 0x0000_0100_0F20_0000;
/// DATA export/placeholder region: page 0 = misc placeholders, page 1 = KPCR placeholder (GS).
/// The remaining pages hold per-instance FSD runtime tables. These tables cannot live in Rust
/// `Vec`s: hosted driver callbacks run in the component VSpace, whose bump heap is private even
/// though image statics are shared. Per-instance DATA frames give both sides a real shared address
/// for the same driver instance.
pub const FSD_DATA_VADDR: u64 = 0x0000_0100_0F30_0000;
pub const FSD_DATA_FRAMES: u64 = 128;
/// The component's GS base — a zeroed KPCR placeholder (an FSD, a kernel driver, may read `gs:[..]`).
pub const FSD_KPCR_VA: u64 = FSD_DATA_VADDR + 0x1000;
const _: () = assert!(FSD_DATA_VADDR + FSD_DATA_FRAMES * 0x1000 <= FSD_SHARED_VADDR);

/// Shared handoff arena (executive ↔ host): entry rva in, verdict + MajorFunction table + device
/// object out, then the IRP request/reply fields. The arena extends up to the ARG window so hosted
/// import shims can publish variable-length state without baking a tiny fixed table into page 0.
pub const FSD_SHARED_VADDR: u64 = 0x0000_0100_0F38_0000;
pub const FSD_SHARED_FRAMES: u64 = (FSD_ARG_VADDR - FSD_SHARED_VADDR) / 0x1000;
const _: () = assert!(FSD_SHARED_FRAMES > 0);
const _: () = assert!(FSD_SHARED_VADDR + FSD_SHARED_FRAMES * 0x1000 <= FSD_ARG_VADDR);

/// The cross-AS ARG-MARSHAL frame(s): mapped RW in BOTH the executive and the FSD component. The
/// executive copies an IRP's system-buffer here; the FSD's MajorFunction handler reads/writes it in
/// its own context; the executive copies out-params back to the caller on reply. 4 pages = 16 KiB.
pub const FSD_ARG_VADDR: u64 = 0x0000_0100_0F3A_0000;
pub const FSD_ARG_FRAMES: u64 = 4;
const STATUS_INVALID_BUFFER_SIZE: u32 = 0xC000_0206;

// --- PER-INSTANCE executive-side load/comm VAs (multi-driver de-singleton) --------------------
//
// The COMPONENT-side VAs above (`FSD_CODE_VA`, `FSD_POOL_VADDR`, … `FSD_ARG_VADDR`) are FIXED: every
// launched FSD component runs in its OWN isolated VSpace and reuses the same VAs there (the component
// entry / pool / dispatch loop all reference these fixed values). What MUST differ per instance is the
// EXECUTIVE-side mapping window — the executive maps every live instance's aliased CODE/DATA/SHARED/
// ARG frames into its OWN VSpace to (a) load+relocate the PE and (b) marshal IRPs — so two instances
// cannot both map at `FSD_CODE_VA`. Instance 0 keeps the fixed FSD VAs EXACTLY (byte-identical);
// instance N≥1 gets a distinct executive window from the checked high arena
// `FSD_EXEC_BASE..FSD_EXEC_LIMIT`, well clear of the private user/process mirror range. The loader
// installs executive page-directory coverage for that arena on demand.
//
// The PE is RELOCATED for its EXECUTION VA (`FSD_CODE_VA`, same across instances) via `load_pe_into`'s
// `run_va` — decoupled from the executive load VA — so instance N runs correctly at `FSD_CODE_VA` in
// its own VSpace while the executive loaded its bytes at a distinct window.
pub const FSD_EXEC_BASE: u64 = 0x0000_0100_5000_0000;
pub const FSD_EXEC_LIMIT: u64 = 0x0000_0101_5000_0000;
pub const FSD_EXEC_STRIDE: u64 = 0x0000_0000_0100_0000; // 16 MiB per instance window
const _: () = assert!(FSD_EXEC_BASE >= crate::PRIVATE_VM_LIMIT);
const _: () = assert!(FSD_EXEC_BASE & 0x1f_ffff == 0);
const _: () = assert!(FSD_EXEC_STRIDE & 0x1f_ffff == 0);
const _: () = assert!(FSD_EXEC_BASE + FSD_EXEC_STRIDE <= FSD_EXEC_LIMIT);

/// The executive-side VA window for launching an instance's frames. Instance 0 == the fixed
/// historical FSD VAs (behavior-preserving); instance N≥1 == a checked high window.
#[derive(Clone, Copy)]
pub(crate) struct ExecVaWindow {
    pub code_va: u64,
    pub pool_va: u64,
    pub data_va: u64,
    pub shared_va: u64,
    pub arg_va: u64,
    pub aux_pt_va: u64,
}

impl ExecVaWindow {
    pub fn try_for_instance(instance: usize) -> Option<ExecVaWindow> {
        if instance == 0 {
            Some(ExecVaWindow {
                code_va: FSD_CODE_VA,
                pool_va: FSD_POOL_VADDR,
                data_va: FSD_DATA_VADDR,
                shared_va: FSD_SHARED_VADDR,
                arg_va: FSD_ARG_VADDR,
                aux_pt_va: FSD_AUX_PT_VADDR,
            })
        } else {
            let base = FSD_EXEC_BASE.checked_add(
                (instance as u64)
                    .checked_sub(1)?
                    .checked_mul(FSD_EXEC_STRIDE)?,
            )?;
            if base.checked_add(FSD_EXEC_STRIDE)? > FSD_EXEC_LIMIT {
                return None;
            }
            // Same RELATIVE offsets as the fixed layout: aux PT (2 MiB) holds DATA/SHARED/ARG.
            Some(ExecVaWindow {
                code_va: base,                 // 256 KiB image window (fits in the first 2 MiB PT)
                pool_va: base + 0x0080_0000,   // POOL (2 MiB, own PT)
                data_va: base + 0x0030_0000,   // DATA (4 frames)
                shared_va: base + 0x0038_0000, // SHARED (1 frame)
                arg_va: base + 0x003A_0000,    // ARG (4 frames)
                aux_pt_va: base + 0x0020_0000, // aux PT covering the 2 MiB region holding DATA/SHARED/ARG
            })
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
pub const SH_DPC_QUEUE_CAPACITY: u64 = 0x490; // out: active KDPC queue entries in the shared arena
pub const SH_SUPPORT_ENTRY_RVA: u64 = 0x4B0; // in: optional support DriverEntry RVA relative to image base
pub const SH_SUPPORT_DE_STATUS: u64 = 0x4B8; // out: support DriverEntry NTSTATUS
pub const SH_SUPPORT_VERDICT: u64 = 0x4C0; // out: support DriverEntry verdict bits
pub const SH_RESOURCE_INTERFACE_TYPE: u64 = 0x4C8; // in: granted INTERFACE_TYPE for bus APIs
pub const SH_RESOURCE_BUS_NUMBER: u64 = 0x4D0; // in: granted bus number
pub const SH_RESOURCE_ADDRESS: u64 = 0x4D8; // in: DevicePropertyAddress value
pub const SH_RESOURCE_PCI_VENDOR_DEVICE: u64 = 0x4E0; // in: PCI config dword 0x00
pub const SH_RESOURCE_PCI_CLASS_REV: u64 = 0x4E8; // in: PCI config dword 0x08
pub const SH_RESOURCE_PCI_IRQ: u64 = 0x4F0; // in: PCI interrupt line/pin bytes
pub const SH_REGISTRY_IDENTITY_FLAGS: u64 = 0x500; // in: hosted registry identity flags
pub const SH_REGISTRY_INSTANCE_LEN: u64 = 0x504; // in: ASCII bytes in instance path
pub const SH_REGISTRY_DRIVER_KEY_LEN: u64 = 0x506; // in: ASCII bytes in class driver key
pub const SH_REGISTRY_EXPORT_LEN: u64 = 0x508; // in: ASCII bytes in Linkage\Export
pub const SH_REGISTRY_INSTANCE_BUF: u64 = 0x510; // in: ASCII Enum instance path
pub const SH_REGISTRY_DRIVER_KEY_BUF: u64 = 0x590; // in: ASCII DevicePropertyDriverKeyName
pub const SH_REGISTRY_EXPORT_BUF: u64 = 0x610; // in: ASCII Linkage\Export
pub const SH_RESOURCE_IO_PORT_BASE: u64 = 0x690; // in: granted PCI I/O port base
pub const SH_RESOURCE_IO_PORT_LEN: u64 = 0x698; // in: granted PCI I/O port length
pub const SH_DMA_ALLOC_CURSOR: u64 = 0x6A0; // out: next offset in the granted common-buffer window
pub const SH_DMA_ALLOC_RECORD_COUNT: u64 = 0x6A8; // out: high-water mark in allocation records
pub const SH_DMA_ALLOC_RECORD_CAPACITY: u64 = 0x6B0; // out: records available in the shared arena
pub const SH_DMA_ALLOC_RECORD_SIZE: u64 = 0x18;
pub const SH_ACTIVE_IRP: u64 = 0x6C0; // out: component VA of the IRP currently inside MajorFunction
pub const SH_ACTIVE_IOSL: u64 = 0x6C8; // out: component VA of Tail.Overlay.CurrentStackLocation
pub const SH_ACTIVE_DATA: u64 = 0x6D0; // out: component VA of request SystemBuffer/UserBuffer
pub const SH_ACTIVE_DATA_CAP: u64 = 0x6D8; // out: bytes allocated for SH_ACTIVE_DATA
pub const SH_ACTIVE_FILE_OBJECT: u64 = 0x6E0; // out: component VA of the IRP FILE_OBJECT, if any
pub const SH_RESOURCE_IO_PORT_CAP: u64 = 0x770; // in: executive root-CNode IOPort cap for the grant
pub const SH_RESOURCE_IO_PORT_OUT32_FAULTS: u64 = 0x778; // out: serviced inline out dx,eax faults
pub const SH_DEVICE_INTERFACE_LINK_LEN: u64 = 0x780; // out: IoSetDeviceInterfaceState link bytes
pub const SH_DEVICE_INTERFACE_TARGET_LEN: u64 = 0x782; // out: target DeviceName bytes
pub const SH_DEVICE_INTERFACE_STATE: u64 = 0x784; // out: 1=enable, 0=disable
pub const SH_DEVICE_INTERFACE_LINK_BUF: u64 = 0x790; // out: UTF-16LE path capture
pub const SH_DEVICE_INTERFACE_TARGET_BUF: u64 = 0x890; // out: UTF-16LE path capture
pub const SH_HOSTED_CURRENT_IRQL: u64 = 0x990; // in/out: hosted KIRQL byte for patched CR8 helpers
pub const SH_HANDOFF_ARENA_BASE: u64 = 0xA00;
pub const SH_HANDOFF_ARENA_LIMIT: u64 = FSD_SHARED_FRAMES * 0x1000;
pub const SH_DPC_QUEUE_BASE: u64 = SH_HANDOFF_ARENA_BASE; // out: queued KDPC pointers
pub const SH_DPC_QUEUE_ENTRY_SIZE: u64 = 8;
pub const SH_DPC_QUEUE_ARENA_BYTES: u64 =
    ((SH_HANDOFF_ARENA_LIMIT - SH_HANDOFF_ARENA_BASE) / 8) & !0x7;
pub const SH_DPC_QUEUE_DERIVED_CAPACITY: u64 = SH_DPC_QUEUE_ARENA_BYTES / SH_DPC_QUEUE_ENTRY_SIZE;
pub const SH_DMA_ALLOC_RECORDS: u64 = SH_DPC_QUEUE_BASE + SH_DPC_QUEUE_ARENA_BYTES; // out: [logical,len,va] allocation records
pub const SH_DMA_ALLOC_RECORD_LIMIT: u64 = SH_HANDOFF_ARENA_LIMIT;
const _: () = assert!(SH_DMA_ALLOC_RECORDS > SH_HOSTED_CURRENT_IRQL);
const _: () = assert!(SH_DMA_ALLOC_RECORD_LIMIT > SH_DMA_ALLOC_RECORDS);
const _: () = assert!(SH_DPC_QUEUE_DERIVED_CAPACITY > 0);
const _: () = assert!(SH_DMA_ALLOC_RECORDS > SH_DPC_QUEUE_BASE);
const _: () = assert!(SH_ACTIVE_FILE_OBJECT + 8 <= SH_RESOURCE_IO_PORT_CAP);
const SH_REGISTRY_IDENTITY_PRESENT: u32 = 0x1;
const SH_REGISTRY_IDENTITY_HAS_DRIVER_KEY: u32 = 0x2;
const SH_REGISTRY_IDENTITY_HAS_EXPORT: u32 = 0x4;

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
pub const V_MJ: u32 = 0x10; // DriverEntry replaced MajorFunction[IRP_MJ_CREATE] with a real dispatch
pub const V_REGFS: u32 = 0x20; // IoRegisterFileSystem was called
pub const V_NAMED_DEVICE: u32 = 0x40; // IoCreateDevice declared a valid NT DeviceName
pub const V_SYMLINK: u32 = 0x80; // IoCreateSymbolicLink declared a valid link/target

const PASSIVE_LEVEL: u8 = 0;
const DISPATCH_LEVEL: u8 = 2;

/// The IPC message label the dispatch loop uses to Send its ready/done signal on the fault EP.
/// Distinct from the small fault labels (VMFault=6, …), so the executive tells them apart.
pub const FSD_DISPATCH_LABEL: u64 = 0x771;
pub const FSD_DISPATCH_UNLOAD: u64 = u64::MAX - 0x771;
pub const FSD_DISPATCH_ADD_DEVICE: u64 = u64::MAX - 0x772;
pub const FSD_DISPATCH_INTERRUPT: u64 = u64::MAX - 0x773;
pub const FSD_DISPATCH_CANCEL_PENDING_FILE: u64 = u64::MAX - 0x774;

const POOL_DATA_OFF: u64 = 0x1000;
const STATUS_PENDING: u32 = 0x0000_0103;

const IRP_MJ_READ: u64 = major::IRP_MJ_READ as u64;
const IRP_MJ_WRITE: u64 = major::IRP_MJ_WRITE as u64;
const IRP_MJ_QUERY_INFORMATION: u64 = major::IRP_MJ_QUERY_INFORMATION as u64;
const IRP_MJ_SET_INFORMATION: u64 = major::IRP_MJ_SET_INFORMATION as u64;
const IRP_MJ_FILE_SYSTEM_CONTROL: u64 = major::IRP_MJ_FILE_SYSTEM_CONTROL as u64;
const IRP_MJ_PNP: u64 = major::IRP_MJ_PNP as u64;
const IRP_MN_START_DEVICE: u64 = 0x00;
const FSCTL_PIPE_TRANSCEIVE: u64 = 0x0011_C017;
/// `IRP_MJ_CLOSE` releases the FILE_OBJECT. Cleanup may disconnect the open first, but the same
/// FILE_OBJECT must remain available for close. See [`FILE_OBJECTS`].
const IRP_MJ_CLOSE: u64 = 0x02;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingIrp {
    irp: u64,
    iosl: u64,
    file_object: u64,
    data: u64,
    /// The npfs `FsContext` (opaque file id) this IRP was issued on, captured at ISSUE time.
    /// ★ Must NOT be re-read from `FILE_OBJECT->FsContext` at completion time: npfs NULLs that
    /// field through `NpSetFileObject(fo, NULL, NULL, …)` when a pipe end disconnects
    /// (`statesup.c:163/289/…`), so a completion racing a disconnect would key the delivered
    /// bytes under fid 0 and the parked reader would never be woken.
    fid: u64,
    major: u8,
    /// This pending IRP completes with bytes for the caller's read/output buffer. `READ` and
    /// `FSCTL_PIPE_TRANSCEIVE` both enter npfs's read queue and are completed by a peer write.
    read_completion: bool,
    /// Whether THIS IRP owns the FILE_OBJECT block (a transient one, not the per-open object in
    /// [`FILE_OBJECTS`]). Only a transient FILE_OBJECT may be freed on completion — see
    /// [`fo_for_open`].
    owns_fo: bool,
    _pad: [u8; 5],
}

static mut DATA_TRACE_COUNT: u32 = 0;
/// Hosted-driver IRP dispatch sequence. This always increments; the print policy below is bounded.
static FSD_DISPATCH_SEQ: AtomicU64 = AtomicU64::new(0);
const FSD_DISPATCH_TRACE_CAP: u64 = 256;
pub(crate) static FSD_ACTIVE_DISPATCH_SEQ: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_DISPATCH_INST: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_DISPATCH_MAJOR: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_DISPATCH_FSCTL: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_DISPATCH_FID: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_DISPATCH_IN: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_DISPATCH_OUT: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_DISPATCH_STARTED_100NS: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_WRITE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
static FSD_ACTIVE_COMPLETE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
/// Narrow NPFS read/write queue-state trace for message-mode RPC over named pipes.
static mut PIPE_RW_TRACE_COUNT: u32 = 0;
/// Narrow NPFS transceive queue-state trace for RPC request/reply pipe transactions.
static mut PIPE_TRANSCEIVE_TRACE_COUNT: u32 = 0;
const PIPE_RW_TRACE_CAP: u32 = 768;
const PIPE_TRANSCEIVE_TRACE_CAP: u32 = 384;
const DCERPC_READ_REASSEMBLY_CAP: usize = 16;
const DCERPC_READ_REASSEMBLY_BYTES: usize = 512;
const DCERPC_READ_REASSEMBLY_TRACE_CAP: u32 = 160;
const DCERPC_READ_REASSEMBLY_CONTEXT_TRACE_CAP: u32 = 192;
const DCERPC_CONTEXT_FLOW_CAP: usize = 256;
const DCERPC_CONTEXT_FLOW_CREATE_TRACE_CAP: u32 = 64;
const DCERPC_CONTEXT_FLOW_USE_TRACE_CAP: u32 = 96;
const DCERPC_CONTEXT_FLOW_MISS_TRACE_CAP: u32 = 96;
/// Diagnostic heartbeat counters for the two unbounded-loop-capable driver callbacks.
static mut IO_COMPLETE_CALLS: u64 = 0;
static mut POOL_CALLS: u64 = 0;
static mut POOL_LONG_WALKS: u32 = 0;
static mut PEER_COMPLETION_TRACE_COUNT: u32 = 0;
static FSD_CANCEL_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
fn pending_irp_returns_read_bytes(major: u64, fsctl: u64) -> bool {
    major == IRP_MJ_READ
        || major == IRP_MJ_QUERY_INFORMATION
        || major == IRP_MJ_FILE_SYSTEM_CONTROL && fsctl == FSCTL_PIPE_TRANSCEIVE
}

// BATCH 37 — completed-pending-READ stash. When a pipe READ goes STATUS_PENDING, npfs retains the
// read IRP in its inbound queue (QueueState=ReadEntries) and the EXECUTIVE parks the caller. The
// peer's later WRITE is serviced by npfs's OWN NpWriteDataQueue fast path, which copies the write
// payload DIRECTLY into that pending read IRP's buffer and completes it via IoCompleteRequest —
// synchronously, during the write call. So by the time control returns to the executive the read data
// is IN the freed read IRP and the inbound queue is drained; a FRESH re-drive read would find nothing
// (or stale bytes). Capture the completed read's bytes here, keyed by the reader's fid, so the
// executive's pipe re-drive delivers THESE bytes to the parked reader instead of re-reading. The read
// result buffer npfs fills for a pending read is the IRP's user buffer (== our `data`, METHOD_NEITHER).
const COMPLETED_READ_BYTE_CAP: usize = (FSD_ARG_FRAMES as usize) * 0x1000;
#[repr(C)]
#[derive(Clone, Copy)]
struct CompletedRead {
    seq: u64,
    fid: u64,
    status: u32,
    length: u32,
    info: u64,
    bytes: [u8; COMPLETED_READ_BYTE_CAP],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CompletedWrite {
    seq: u64,
    fid: u64,
    status: u32,
    _pad: u32,
    info: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingIrpNode {
    next: u64,
    entry: PendingIrp,
}
const EMPTY_COMPLETED_READ: CompletedRead = CompletedRead {
    seq: 0,
    fid: 0,
    status: 0,
    length: 0,
    info: 0,
    bytes: [0; COMPLETED_READ_BYTE_CAP],
};
const EMPTY_COMPLETED_WRITE: CompletedWrite = CompletedWrite {
    seq: 0,
    fid: 0,
    status: 0,
    _pad: 0,
    info: 0,
};
const EMPTY_PENDING_IRP: PendingIrp = PendingIrp {
    irp: 0,
    iosl: 0,
    file_object: 0,
    data: 0,
    fid: 0,
    major: 0,
    read_completion: false,
    owns_fo: false,
    _pad: [0; 5],
};
const EMPTY_PENDING_IRP_NODE: PendingIrpNode = PendingIrpNode {
    next: 0,
    entry: EMPTY_PENDING_IRP,
};

const FSD_RUNTIME_TABLES_OFF: u64 = 0x2000;
const FSD_COMPLETION_SEQ_OFF: u64 = FSD_RUNTIME_TABLES_OFF;
const FSD_COMPLETED_WRITE_CAP: usize = 128;
const FSD_COMPLETED_READ_CAP: usize = 30;
const FSD_PENDING_IRP_CAP: usize = 256;
const FSD_PENDING_IRP_HEAD_OFF: u64 = FSD_RUNTIME_TABLES_OFF + 0x08;
const FSD_COMPLETED_WRITES_OFF: u64 = align_up_u64(FSD_RUNTIME_TABLES_OFF + 0x10, 8);
const FSD_COMPLETED_READS_OFF: u64 = align_up_u64(
    FSD_COMPLETED_WRITES_OFF
        + core::mem::size_of::<CompletedWrite>() as u64 * FSD_COMPLETED_WRITE_CAP as u64,
    8,
);
const FSD_PENDING_IRPS_OFF: u64 = align_up_u64(
    FSD_COMPLETED_READS_OFF
        + core::mem::size_of::<CompletedRead>() as u64 * FSD_COMPLETED_READ_CAP as u64,
    8,
);
const _: () = assert!(
    FSD_PENDING_IRPS_OFF
        + core::mem::size_of::<PendingIrpNode>() as u64 * FSD_PENDING_IRP_CAP as u64
        <= FSD_DATA_FRAMES * 0x1000
);

const fn align_up_u64(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

unsafe fn next_completion_seq(data_base: u64) -> u64 {
    let ptr = (data_base + FSD_COMPLETION_SEQ_OFF) as *mut u64;
    let mut next = read_volatile(ptr).wrapping_add(1);
    if next == 0 {
        next = 1;
    }
    write_volatile(ptr, next);
    next
}

#[inline]
unsafe fn pending_irp_head(data_base: u64) -> *mut u64 {
    (data_base + FSD_PENDING_IRP_HEAD_OFF) as *mut u64
}

#[inline]
unsafe fn completed_write_slot(data_base: u64, index: usize) -> *mut CompletedWrite {
    (data_base
        + FSD_COMPLETED_WRITES_OFF
        + (index as u64) * core::mem::size_of::<CompletedWrite>() as u64) as *mut CompletedWrite
}

#[inline]
unsafe fn completed_read_slot(data_base: u64, index: usize) -> *mut CompletedRead {
    (data_base
        + FSD_COMPLETED_READS_OFF
        + (index as u64) * core::mem::size_of::<CompletedRead>() as u64) as *mut CompletedRead
}

#[inline]
unsafe fn pending_irp_slot(data_base: u64, index: usize) -> *mut PendingIrpNode {
    (data_base
        + FSD_PENDING_IRPS_OFF
        + (index as u64) * core::mem::size_of::<PendingIrpNode>() as u64) as *mut PendingIrpNode
}

#[inline]
unsafe fn pending_irp_node_valid(node: u64) -> bool {
    let pool_start = FSD_POOL_VADDR + POOL_DATA_OFF;
    let pool_end = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
    let in_pool = node >= pool_start
        && node & 7 == 0
        && node
            .checked_add(core::mem::size_of::<PendingIrpNode>() as u64)
            .is_some_and(|end| end <= pool_end);
    let table_start = FSD_DATA_VADDR + FSD_PENDING_IRPS_OFF;
    let table_end =
        table_start + core::mem::size_of::<PendingIrpNode>() as u64 * FSD_PENDING_IRP_CAP as u64;
    let in_table = node >= table_start
        && node & 7 == 0
        && node
            .checked_add(core::mem::size_of::<PendingIrpNode>() as u64)
            .is_some_and(|end| end <= table_end)
        && (node - table_start) % core::mem::size_of::<PendingIrpNode>() as u64 == 0;
    in_pool || in_table
}

unsafe fn pending_irp_exists(irp: u64) -> bool {
    let mut node = read_volatile(pending_irp_head(FSD_DATA_VADDR));
    let mut steps = 0u64;
    while node != 0 && steps < POOL_FREE_LIST_MAX {
        if !pending_irp_node_valid(node) {
            return false;
        }
        let entry = read_volatile((node + 8) as *const PendingIrp);
        if entry.irp == irp {
            return true;
        }
        node = read_volatile(node as *const u64);
        steps += 1;
    }
    false
}

unsafe fn take_pending_irp(irp: u64) -> Option<PendingIrp> {
    let head = pending_irp_head(FSD_DATA_VADDR);
    let mut prev = head;
    let mut node = read_volatile(head);
    let mut steps = 0u64;
    while node != 0 && steps < POOL_FREE_LIST_MAX {
        if !pending_irp_node_valid(node) {
            return None;
        }
        let next = read_volatile(node as *const u64);
        let entry = read_volatile((node + 8) as *const PendingIrp);
        if entry.irp == irp {
            write_volatile(prev, next);
            let table_start = FSD_DATA_VADDR + FSD_PENDING_IRPS_OFF;
            let table_end = table_start
                + core::mem::size_of::<PendingIrpNode>() as u64 * FSD_PENDING_IRP_CAP as u64;
            if node >= table_start && node < table_end {
                write_volatile(node as *mut PendingIrpNode, EMPTY_PENDING_IRP_NODE);
            } else {
                pool_free(node);
            }
            return Some(entry);
        }
        prev = node as *mut u64;
        node = next;
        steps += 1;
    }
    None
}

unsafe fn insert_pending_irp(entry: PendingIrp) -> bool {
    let mut node = 0u64;
    for index in 0..FSD_PENDING_IRP_CAP {
        let slot = pending_irp_slot(FSD_DATA_VADDR, index);
        if read_volatile(slot).entry.irp == 0 {
            node = slot as u64;
            break;
        }
    }
    if node == 0 {
        node = pool_alloc(core::mem::size_of::<PendingIrpNode>() as u64);
        if node == 0 {
            return false;
        }
    }
    let head = pending_irp_head(FSD_DATA_VADDR);
    let old = read_volatile(head);
    write_volatile(
        node as *mut PendingIrpNode,
        PendingIrpNode { next: old, entry },
    );
    write_volatile(head, node);
    true
}

#[derive(Clone, Copy)]
struct PendingIrpCancelTarget {
    irp: u64,
    cancel_routine: u64,
}

unsafe fn find_pending_irp_cancel_target(fid: u64) -> Option<PendingIrpCancelTarget> {
    if fid == 0 {
        return None;
    }
    let mut node = read_volatile(pending_irp_head(FSD_DATA_VADDR));
    let mut steps = 0u64;
    while node != 0 && steps < POOL_FREE_LIST_MAX {
        if !pending_irp_node_valid(node) {
            return None;
        }
        let entry = read_volatile((node + 8) as *const PendingIrp);
        if entry.fid == fid && entry.irp != 0 {
            let cancel_routine = read_unaligned(
                (entry.irp + WDM_X64_IRP_CANCEL_ROUTINE_OFFSET) as *const u64,
            );
            if cancel_routine != 0 {
                return Some(PendingIrpCancelTarget {
                    irp: entry.irp,
                    cancel_routine,
                });
            }
        }
        node = read_volatile(node as *const u64);
        steps += 1;
    }
    None
}

unsafe fn discard_completed_file_records(fid: u64) -> u64 {
    if fid == 0 {
        return 0;
    }
    let mut discarded = 0u64;
    for index in 0..FSD_COMPLETED_READ_CAP {
        let ptr = completed_read_slot(FSD_DATA_VADDR, index);
        if read_volatile(ptr).fid == fid {
            write_volatile(ptr, EMPTY_COMPLETED_READ);
            discarded += 1;
        }
    }
    for index in 0..FSD_COMPLETED_WRITE_CAP {
        let ptr = completed_write_slot(FSD_DATA_VADDR, index);
        if read_volatile(ptr).fid == fid {
            write_volatile(ptr, EMPTY_COMPLETED_WRITE);
            discarded += 1;
        }
    }
    discarded
}

unsafe fn cancel_pending_irps_for_file(fid: u64, device_object: u64) -> u64 {
    let mut cancelled = 0u64;
    loop {
        let Some(target) = find_pending_irp_cancel_target(fid) else {
            break;
        };
        write_unaligned((target.irp + WDM_X64_IRP_CANCEL_OFFSET) as *mut u8, 1);
        write_unaligned((target.irp + WDM_X64_IRP_CANCEL_IRQL_OFFSET) as *mut u8, 0);
        write_unaligned(
            (target.irp + WDM_X64_IRP_CANCEL_ROUTINE_OFFSET) as *mut u64,
            0,
        );
        let cancel: extern "win64" fn(u64, u64) =
            core::mem::transmute(target.cancel_routine as *const ());
        cancel(device_object, target.irp);
        let discarded = discard_completed_file_records(fid);
        let trace = FSD_CANCEL_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
        if trace < 32 {
            print_str(b"[fsd-cancel] fid=0x");
            print_hex(fid as u32);
            print_str(b" irp=0x");
            print_hex((target.irp >> 32) as u32);
            print_hex(target.irp as u32);
            print_str(b" routine=0x");
            print_hex((target.cancel_routine >> 32) as u32);
            print_hex(target.cancel_routine as u32);
            print_str(b" discarded=");
            print_u64(discarded);
            print_str(b"\n");
        }
        cancelled += 1;
        if cancelled >= FSD_PENDING_IRP_CAP as u64 {
            break;
        }
    }
    let _ = discard_completed_file_records(fid);
    cancelled
}

unsafe fn insert_completed_write(fid: u64, status: u32, info: u64) -> bool {
    if fid == 0 {
        return false;
    }
    let seq = next_completion_seq(FSD_DATA_VADDR);
    for index in 0..FSD_COMPLETED_WRITE_CAP {
        let ptr = completed_write_slot(FSD_DATA_VADDR, index);
        if read_volatile(ptr).fid == 0 {
            write_volatile(
                ptr,
                CompletedWrite {
                    seq,
                    fid,
                    status,
                    _pad: 0,
                    info,
                },
            );
            return true;
        }
    }
    false
}

unsafe fn insert_completed_read(
    fid: u64,
    status: u32,
    info: u64,
    source: u64,
    length: usize,
) -> bool {
    if fid == 0 {
        return false;
    }
    let seq = next_completion_seq(FSD_DATA_VADDR);
    for index in 0..FSD_COMPLETED_READ_CAP {
        let ptr = completed_read_slot(FSD_DATA_VADDR, index);
        if read_volatile(ptr).fid == 0 {
            let mut record = EMPTY_COMPLETED_READ;
            record.seq = seq;
            record.fid = fid;
            record.status = status;
            record.info = info;
            record.length = length as u32;
            let mut byte = 0usize;
            while byte < length {
                record.bytes[byte] = read_volatile((source + byte as u64) as *const u8);
                byte += 1;
            }
            write_volatile(ptr, record);
            return true;
        }
    }
    false
}

unsafe fn take_completed_read_from_instance(
    instance: usize,
    fid: u64,
) -> Option<(u32, u64, alloc::vec::Vec<u8>)> {
    if fid == 0 {
        return None;
    }
    let win = ExecVaWindow::try_for_instance(instance)?;
    let mut best_slot = usize::MAX;
    let mut best_seq = u64::MAX;
    for slot_index in 0..FSD_COMPLETED_READ_CAP {
        let slot = read_volatile(completed_read_slot(win.data_va, slot_index));
        if slot.fid == fid && slot.seq < best_seq {
            best_slot = slot_index;
            best_seq = slot.seq;
        }
    }
    if best_slot == usize::MAX {
        return None;
    }
    let ptr = completed_read_slot(win.data_va, best_slot);
    let slot = read_volatile(ptr);
    write_volatile(ptr, EMPTY_COMPLETED_READ);
    let length = (slot.length as usize).min(COMPLETED_READ_BYTE_CAP);
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&slot.bytes[..length]);
    Some((slot.status, slot.info, bytes))
}

/// Take (consume) a stashed completed-pending-read for `fid` from `device_id`'s hosted component.
/// Returns `(status, info, bytes)`.
pub(crate) unsafe fn take_completed_read_for_device(
    device_id: u64,
    fid: u64,
) -> Option<(u32, u64, alloc::vec::Vec<u8>)> {
    let (instance, _) = instance_by_device_id(device_id)?;
    take_completed_read_from_instance(instance, fid)
}

unsafe fn take_completed_write_from_instance(instance: usize, fid: u64) -> Option<(u32, u64)> {
    if fid == 0 {
        return None;
    }
    let win = ExecVaWindow::try_for_instance(instance)?;
    let mut best_slot = usize::MAX;
    let mut best_seq = u64::MAX;
    for slot_index in 0..FSD_COMPLETED_WRITE_CAP {
        let slot = read_volatile(completed_write_slot(win.data_va, slot_index));
        if slot.fid == fid && slot.seq < best_seq {
            best_slot = slot_index;
            best_seq = slot.seq;
        }
    }
    if best_slot == usize::MAX {
        return None;
    }
    let ptr = completed_write_slot(win.data_va, best_slot);
    let slot = read_volatile(ptr);
    write_volatile(ptr, EMPTY_COMPLETED_WRITE);
    Some((slot.status, slot.info))
}

pub(crate) unsafe fn take_completed_write_for_device(
    device_id: u64,
    fid: u64,
) -> Option<(u32, u64)> {
    let (instance, _) = instance_by_device_id(device_id)?;
    take_completed_write_from_instance(instance, fid)
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
/// Opens rejected because the per-open FILE_OBJECT table was full.
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

unsafe fn fo_has_free_slot() -> bool {
    let table = &*core::ptr::addr_of!(FILE_OBJECTS);
    table.iter().any(|slot| slot.fid == 0)
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

#[derive(Clone, Copy)]
struct PipeQueueView {
    state: u32,
    bytes: u32,
    entries: u32,
    quota_used: u32,
    byte_offset: u32,
}

#[derive(Clone, Copy)]
struct PipeCcbView {
    q: [PipeQueueView; 2],
}

#[derive(Clone, Copy)]
pub(crate) struct DceRpcContextHandleView {
    offset: u16,
    attributes: u32,
    uuid: [u8; 16],
}

const DCERPC_CONTEXT_HANDLE_TRACE_CAP: usize = 4;

#[derive(Clone, Copy)]
pub(crate) struct DceRpcPduView {
    ptype: u8,
    flags: u8,
    frag_len: u16,
    call_id: u32,
    assoc_gid: Option<u32>,
    alloc_hint: Option<u32>,
    opnum: Option<u16>,
    fault_status: Option<u32>,
    context_handles: [Option<DceRpcContextHandleView>; DCERPC_CONTEXT_HANDLE_TRACE_CAP],
}

#[derive(Clone, Copy)]
struct DceRpcReadAssembly {
    fid: u64,
    frag_len: u16,
    len: u16,
    buf: [u8; DCERPC_READ_REASSEMBLY_BYTES],
}

#[derive(Clone, Copy)]
struct DceRpcContextFlow {
    uuid: [u8; 16],
    first_response_fid: u64,
    last_response_fid: u64,
    first_request_fid: u64,
    last_request_fid: u64,
    first_response_call: u32,
    first_request_call: u32,
    first_request_op: u16,
    response_count: u16,
    request_count: u16,
}

const EMPTY_DCERPC_READ_ASSEMBLY: DceRpcReadAssembly = DceRpcReadAssembly {
    fid: 0,
    frag_len: 0,
    len: 0,
    buf: [0; DCERPC_READ_REASSEMBLY_BYTES],
};

const EMPTY_DCERPC_CONTEXT_FLOW: DceRpcContextFlow = DceRpcContextFlow {
    uuid: [0; 16],
    first_response_fid: 0,
    last_response_fid: 0,
    first_request_fid: 0,
    last_request_fid: 0,
    first_response_call: 0,
    first_request_call: 0,
    first_request_op: 0,
    response_count: 0,
    request_count: 0,
};

static mut DCERPC_READ_REASSEMBLY: [DceRpcReadAssembly; DCERPC_READ_REASSEMBLY_CAP] =
    [EMPTY_DCERPC_READ_ASSEMBLY; DCERPC_READ_REASSEMBLY_CAP];
static mut DCERPC_READ_REASSEMBLY_CURSOR: usize = 0;
static mut DCERPC_READ_REASSEMBLY_TRACE_COUNT: u32 = 0;
static mut DCERPC_READ_REASSEMBLY_CONTEXT_TRACE_COUNT: u32 = 0;
static mut DCERPC_CONTEXT_FLOW: [DceRpcContextFlow; DCERPC_CONTEXT_FLOW_CAP] =
    [EMPTY_DCERPC_CONTEXT_FLOW; DCERPC_CONTEXT_FLOW_CAP];
static mut DCERPC_CONTEXT_FLOW_DROPS: u32 = 0;
static mut DCERPC_CONTEXT_FLOW_CREATE_TRACE_COUNT: u32 = 0;
static mut DCERPC_CONTEXT_FLOW_USE_TRACE_COUNT: u32 = 0;
static mut DCERPC_CONTEXT_FLOW_MISS_TRACE_COUNT: u32 = 0;

impl PipeCcbView {
    fn has_queued_state(&self) -> bool {
        self.q.iter().any(|q| {
            q.state != NP_QUEUE_EMPTY
                || q.bytes != 0
                || q.entries != 0
                || q.quota_used != 0
                || q.byte_offset != 0
        })
    }
}

unsafe fn dcerpc_pdu_view(payload: u64, len: u64) -> Option<DceRpcPduView> {
    if payload == 0 || len < 16 {
        return None;
    }
    let version = read_volatile(payload as *const u8);
    if version != 5 {
        return None;
    }
    let ptype = read_volatile((payload + 2) as *const u8);
    if ptype > 19 {
        return None;
    }
    let flags = read_volatile((payload + 3) as *const u8);
    let frag_len = u16::from_le_bytes([
        read_volatile((payload + 8) as *const u8),
        read_volatile((payload + 9) as *const u8),
    ]);
    let call_id = u32::from_le_bytes([
        read_volatile((payload + 12) as *const u8),
        read_volatile((payload + 13) as *const u8),
        read_volatile((payload + 14) as *const u8),
        read_volatile((payload + 15) as *const u8),
    ]);
    let alloc_hint = if (ptype == 0 || ptype == 2 || ptype == 3) && len >= 20 {
        Some(u32::from_le_bytes([
            read_volatile((payload + 16) as *const u8),
            read_volatile((payload + 17) as *const u8),
            read_volatile((payload + 18) as *const u8),
            read_volatile((payload + 19) as *const u8),
        ]))
    } else {
        None
    };
    let assoc_gid = if (ptype == 11 || ptype == 12) && len >= 24 {
        Some(u32::from_le_bytes([
            read_volatile((payload + 20) as *const u8),
            read_volatile((payload + 21) as *const u8),
            read_volatile((payload + 22) as *const u8),
            read_volatile((payload + 23) as *const u8),
        ]))
    } else {
        None
    };
    let opnum = if ptype == 0 && len >= 24 {
        Some(u16::from_le_bytes([
            read_volatile((payload + 22) as *const u8),
            read_volatile((payload + 23) as *const u8),
        ]))
    } else {
        None
    };
    let fault_status = if ptype == 3 && len >= 28 {
        Some(u32::from_le_bytes([
            read_volatile((payload + 24) as *const u8),
            read_volatile((payload + 25) as *const u8),
            read_volatile((payload + 26) as *const u8),
            read_volatile((payload + 27) as *const u8),
        ]))
    } else {
        None
    };
    let context_handles = dcerpc_context_handles(payload, len, ptype, frag_len);
    Some(DceRpcPduView {
        ptype,
        flags,
        frag_len,
        call_id,
        assoc_gid,
        alloc_hint,
        opnum,
        fault_status,
        context_handles,
    })
}

pub(crate) unsafe fn dcerpc_pdu_view_from_slice(payload: &[u8]) -> Option<DceRpcPduView> {
    dcerpc_pdu_view(payload.as_ptr() as u64, payload.len() as u64)
}

pub(crate) unsafe fn trace_dcerpc_read_reassembly_from_slice(
    file_id: u64,
    status: u32,
    info: u64,
    payload: &[u8],
) {
    trace_dcerpc_read_reassembly(
        file_id,
        status,
        info,
        payload.as_ptr() as u64,
        payload.len() as u64,
    );
}

unsafe fn trace_dcerpc_read_reassembly(
    file_id: u64,
    status: u32,
    info: u64,
    payload: u64,
    len: u64,
) {
    if file_id == 0 || payload == 0 || info == 0 || len == 0 {
        return;
    }
    if status != 0 && status != STATUS_BUFFER_OVERFLOW {
        return;
    }

    let chunk_len = core::cmp::min(info, len);
    if chunk_len == 0 {
        return;
    }

    if let Some(index) = dcerpc_read_reassembly_active_slot(file_id) {
        let complete = dcerpc_read_reassembly_append(index, payload, chunk_len);
        if complete {
            dcerpc_read_reassembly_emit(index, status, info);
            dcerpc_read_reassembly_clear(index);
        }
        return;
    }

    if chunk_len < 16 || read_volatile(payload as *const u8) != 5 {
        return;
    }

    let frag_len = u16::from_le_bytes([
        read_volatile((payload + 8) as *const u8),
        read_volatile((payload + 9) as *const u8),
    ]);
    if frag_len < 16 {
        return;
    }

    let index = dcerpc_read_reassembly_new_slot(file_id);
    dcerpc_read_reassembly_start(index, file_id, frag_len);
    let complete = dcerpc_read_reassembly_append(index, payload, chunk_len);
    if complete {
        dcerpc_read_reassembly_emit(index, status, info);
        dcerpc_read_reassembly_clear(index);
    }
}

unsafe fn dcerpc_read_reassembly_active_slot(fid: u64) -> Option<usize> {
    let table = &mut *core::ptr::addr_of_mut!(DCERPC_READ_REASSEMBLY);
    for (index, entry) in table.iter().enumerate() {
        if entry.fid == fid && entry.frag_len >= 16 && entry.len < entry.frag_len {
            return Some(index);
        }
    }
    None
}

unsafe fn dcerpc_read_reassembly_new_slot(fid: u64) -> usize {
    let table = &mut *core::ptr::addr_of_mut!(DCERPC_READ_REASSEMBLY);
    for (index, entry) in table.iter().enumerate() {
        if entry.fid == 0 || entry.fid == fid {
            return index;
        }
    }
    let index = DCERPC_READ_REASSEMBLY_CURSOR % DCERPC_READ_REASSEMBLY_CAP;
    DCERPC_READ_REASSEMBLY_CURSOR =
        (DCERPC_READ_REASSEMBLY_CURSOR + 1) % DCERPC_READ_REASSEMBLY_CAP;
    index
}

unsafe fn dcerpc_read_reassembly_start(index: usize, fid: u64, frag_len: u16) {
    let table = &mut *core::ptr::addr_of_mut!(DCERPC_READ_REASSEMBLY);
    table[index] = DceRpcReadAssembly {
        fid,
        frag_len,
        len: 0,
        buf: [0; DCERPC_READ_REASSEMBLY_BYTES],
    };
}

unsafe fn dcerpc_read_reassembly_append(index: usize, payload: u64, chunk_len: u64) -> bool {
    let table = &mut *core::ptr::addr_of_mut!(DCERPC_READ_REASSEMBLY);
    let entry = &mut table[index];
    let target_len = core::cmp::min(entry.frag_len as usize, DCERPC_READ_REASSEMBLY_BYTES);
    let have = entry.len as usize;
    if have >= target_len {
        return true;
    }
    let copy_len = core::cmp::min(target_len - have, chunk_len as usize);
    for offset in 0..copy_len {
        entry.buf[have + offset] = read_volatile((payload + offset as u64) as *const u8);
    }
    entry.len = (have + copy_len) as u16;
    entry.len as usize >= target_len
}

unsafe fn dcerpc_read_reassembly_emit(index: usize, status: u32, info: u64) {
    let table = &mut *core::ptr::addr_of_mut!(DCERPC_READ_REASSEMBLY);
    let entry = table[index];
    let view = dcerpc_pdu_view(entry.buf.as_ptr() as u64, entry.len as u64);
    let Some(view) = view else {
        return;
    };
    dcerpc_trace_context_flow(entry.fid, view);
    let force_late = dcerpc_pdu_has_context(view) || view.ptype == 3;
    if DCERPC_READ_REASSEMBLY_TRACE_COUNT >= DCERPC_READ_REASSEMBLY_TRACE_CAP {
        if !force_late
            || DCERPC_READ_REASSEMBLY_CONTEXT_TRACE_COUNT
                >= DCERPC_READ_REASSEMBLY_CONTEXT_TRACE_CAP
        {
            return;
        }
        DCERPC_READ_REASSEMBLY_CONTEXT_TRACE_COUNT += 1;
    } else {
        DCERPC_READ_REASSEMBLY_TRACE_COUNT += 1;
    }
    print_str(b"[fsd-pipe-rpc-read] fid=0x");
    print_hex(entry.fid as u32);
    print_str(b" captured=");
    print_u64(entry.len as u64);
    print_str(b" frag=");
    print_u64(entry.frag_len as u64);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" info=");
    print_u64(info);
    print_dcerpc_pdu_view(Some(view));
    print_str(b"\n");
}

fn dcerpc_pdu_has_context(pdu: DceRpcPduView) -> bool {
    pdu.context_handles.iter().any(Option::is_some)
}

unsafe fn dcerpc_trace_context_flow(fid: u64, pdu: DceRpcPduView) {
    if !matches!(pdu.ptype, 0 | 2 | 3) {
        return;
    }
    for context in pdu.context_handles.iter().flatten() {
        let existing_index = dcerpc_context_flow_find(context.uuid);
        let seen_response = existing_index
            .map(|index| {
                let table = &*core::ptr::addr_of!(DCERPC_CONTEXT_FLOW);
                table[index].response_count != 0
            })
            .unwrap_or(false);
        let Some(index) = existing_index.or_else(|| dcerpc_context_flow_alloc(context.uuid)) else {
            if pdu.ptype == 0
                && DCERPC_CONTEXT_FLOW_MISS_TRACE_COUNT < DCERPC_CONTEXT_FLOW_MISS_TRACE_CAP
            {
                DCERPC_CONTEXT_FLOW_MISS_TRACE_COUNT += 1;
                dcerpc_print_context_flow(b"drop", fid, pdu, *context, None, false);
            }
            continue;
        };

        let table = &mut *core::ptr::addr_of_mut!(DCERPC_CONTEXT_FLOW);
        let entry = &mut table[index];
        match pdu.ptype {
            0 => {
                if entry.first_request_fid == 0 {
                    entry.first_request_fid = fid;
                    entry.first_request_call = pdu.call_id;
                    entry.first_request_op = pdu.opnum.unwrap_or(0);
                }
                entry.last_request_fid = fid;
                entry.request_count = entry.request_count.saturating_add(1);
                if seen_response {
                    let first_use = entry.request_count == 1;
                    if first_use
                        && DCERPC_CONTEXT_FLOW_USE_TRACE_COUNT < DCERPC_CONTEXT_FLOW_USE_TRACE_CAP
                    {
                        DCERPC_CONTEXT_FLOW_USE_TRACE_COUNT += 1;
                        dcerpc_print_context_flow(b"use", fid, pdu, *context, Some(*entry), true);
                    }
                } else if DCERPC_CONTEXT_FLOW_MISS_TRACE_COUNT < DCERPC_CONTEXT_FLOW_MISS_TRACE_CAP
                {
                    DCERPC_CONTEXT_FLOW_MISS_TRACE_COUNT += 1;
                    dcerpc_print_context_flow(b"miss", fid, pdu, *context, Some(*entry), false);
                }
            }
            2 => {
                let first_response = entry.response_count == 0;
                if first_response {
                    entry.first_response_fid = fid;
                    entry.first_response_call = pdu.call_id;
                }
                entry.last_response_fid = fid;
                entry.response_count = entry.response_count.saturating_add(1);
                if first_response
                    && DCERPC_CONTEXT_FLOW_CREATE_TRACE_COUNT < DCERPC_CONTEXT_FLOW_CREATE_TRACE_CAP
                {
                    DCERPC_CONTEXT_FLOW_CREATE_TRACE_COUNT += 1;
                    dcerpc_print_context_flow(b"create", fid, pdu, *context, Some(*entry), true);
                }
            }
            3 => {
                if !seen_response
                    && DCERPC_CONTEXT_FLOW_MISS_TRACE_COUNT < DCERPC_CONTEXT_FLOW_MISS_TRACE_CAP
                {
                    DCERPC_CONTEXT_FLOW_MISS_TRACE_COUNT += 1;
                    dcerpc_print_context_flow(
                        b"fault-miss",
                        fid,
                        pdu,
                        *context,
                        Some(*entry),
                        false,
                    );
                }
            }
            _ => {}
        }
    }
}

unsafe fn dcerpc_context_flow_find(uuid: [u8; 16]) -> Option<usize> {
    let table = &*core::ptr::addr_of!(DCERPC_CONTEXT_FLOW);
    for (index, entry) in table.iter().enumerate() {
        if (entry.response_count != 0 || entry.request_count != 0) && entry.uuid == uuid {
            return Some(index);
        }
    }
    None
}

unsafe fn dcerpc_context_flow_alloc(uuid: [u8; 16]) -> Option<usize> {
    let table = &mut *core::ptr::addr_of_mut!(DCERPC_CONTEXT_FLOW);
    for (index, entry) in table.iter_mut().enumerate() {
        if entry.response_count == 0 && entry.request_count == 0 {
            *entry = DceRpcContextFlow {
                uuid,
                ..EMPTY_DCERPC_CONTEXT_FLOW
            };
            return Some(index);
        }
    }
    DCERPC_CONTEXT_FLOW_DROPS = DCERPC_CONTEXT_FLOW_DROPS.saturating_add(1);
    None
}

unsafe fn dcerpc_print_context_flow(
    kind: &[u8],
    fid: u64,
    pdu: DceRpcPduView,
    context: DceRpcContextHandleView,
    entry: Option<DceRpcContextFlow>,
    seen_response: bool,
) {
    print_str(b"[fsd-pipe-rpc-ctx] ");
    print_str(kind);
    print_str(b" fid=0x");
    print_hex(fid as u32);
    print_str(b" rpc=");
    print_str(dcerpc_ptype_name(pdu.ptype));
    print_str(b" call=");
    print_u64(pdu.call_id as u64);
    if let Some(opnum) = pdu.opnum {
        print_str(b" op=");
        print_u64(opnum as u64);
    }
    if let Some(status) = pdu.fault_status {
        print_str(b" fault=0x");
        print_hex(status);
    }
    print_str(b" ctx@");
    print_u64(context.offset as u64);
    print_str(b" attr=");
    print_u64(context.attributes as u64);
    print_str(b" uuid=");
    print_uuid(context.uuid);
    print_str(b" seen_rsp=");
    print_u64(seen_response as u64);
    if let Some(entry) = entry {
        print_str(b" rsp_fid=0x");
        print_hex(entry.first_response_fid as u32);
        print_str(b" last_rsp=0x");
        print_hex(entry.last_response_fid as u32);
        print_str(b" req_fid=0x");
        print_hex(entry.first_request_fid as u32);
        print_str(b" last_req=0x");
        print_hex(entry.last_request_fid as u32);
        print_str(b" rsp_n=");
        print_u64(entry.response_count as u64);
        print_str(b" req_n=");
        print_u64(entry.request_count as u64);
        if entry.first_request_call != 0 {
            print_str(b" first_req_call=");
            print_u64(entry.first_request_call as u64);
            print_str(b" first_req_op=");
            print_u64(entry.first_request_op as u64);
        }
    }
    if DCERPC_CONTEXT_FLOW_DROPS != 0 {
        print_str(b" drops=");
        print_u64(DCERPC_CONTEXT_FLOW_DROPS as u64);
    }
    print_str(b"\n");
}

unsafe fn dcerpc_read_reassembly_clear(index: usize) {
    let table = &mut *core::ptr::addr_of_mut!(DCERPC_READ_REASSEMBLY);
    table[index] = EMPTY_DCERPC_READ_ASSEMBLY;
}

unsafe fn dcerpc_context_handles(
    payload: u64,
    len: u64,
    ptype: u8,
    frag_len: u16,
) -> [Option<DceRpcContextHandleView>; DCERPC_CONTEXT_HANDLE_TRACE_CAP] {
    let mut handles = [None; DCERPC_CONTEXT_HANDLE_TRACE_CAP];
    if !matches!(ptype, 0 | 2 | 3) {
        return handles;
    }
    let wire_len = core::cmp::min(len, frag_len as u64);
    if wire_len < 44 {
        return handles;
    }

    // Request/response/fault bodies begin after the 24-byte PDU-specific header. Many stubs place a
    // context handle there, but later arguments can carry the same NDR wire shape too.
    if let Some(context) = dcerpc_context_handle_at(payload, wire_len, 24) {
        dcerpc_push_context_handle(&mut handles, context);
    }

    let mut offset = 28u64;
    while offset + 20 <= wire_len && offset <= u16::MAX as u64 {
        if let Some(context) = dcerpc_context_handle_at(payload, wire_len, offset as u16) {
            dcerpc_push_context_handle(&mut handles, context);
        }
        if handles.last().copied().flatten().is_some() {
            break;
        }
        offset += 4;
    }
    handles
}

fn dcerpc_push_context_handle(
    handles: &mut [Option<DceRpcContextHandleView>; DCERPC_CONTEXT_HANDLE_TRACE_CAP],
    context: DceRpcContextHandleView,
) {
    if handles.iter().flatten().any(|existing| {
        existing.offset == context.offset
            || (existing.attributes == context.attributes && existing.uuid == context.uuid)
    }) {
        return;
    }
    if let Some(slot) = handles.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(context);
    }
}

unsafe fn dcerpc_context_handle_at(
    payload: u64,
    len: u64,
    offset: u16,
) -> Option<DceRpcContextHandleView> {
    let offset_u64 = offset as u64;
    if len < offset_u64 + 20 {
        return None;
    }
    let attributes = u32::from_le_bytes([
        read_volatile((payload + offset_u64) as *const u8),
        read_volatile((payload + offset_u64 + 1) as *const u8),
        read_volatile((payload + offset_u64 + 2) as *const u8),
        read_volatile((payload + offset_u64 + 3) as *const u8),
    ]);
    if attributes > 2 {
        return None;
    }
    let mut uuid = [0u8; 16];
    let mut any = false;
    for (i, byte) in uuid.iter_mut().enumerate() {
        *byte = read_volatile((payload + offset_u64 + 4 + i as u64) as *const u8);
        any |= *byte != 0;
    }
    if !any || !dcerpc_uuid_looks_generated(&uuid) {
        return None;
    }
    Some(DceRpcContextHandleView {
        offset,
        attributes,
        uuid,
    })
}

fn dcerpc_uuid_looks_generated(uuid: &[u8; 16]) -> bool {
    // RPC context handles are assigned with UuidCreate before being marshalled. Filtering to normal
    // UUID version/variant bits keeps counted strings and small pointer fields out of the trace.
    let version = uuid[7] >> 4;
    let variant = uuid[8] & 0xc0;
    (1..=5).contains(&version) && variant == 0x80
}

fn dcerpc_ptype_name(ptype: u8) -> &'static [u8] {
    match ptype {
        0 => b"request",
        2 => b"response",
        3 => b"fault",
        11 => b"bind",
        12 => b"bind_ack",
        13 => b"bind_nak",
        14 => b"alter",
        15 => b"alter_ack",
        _ => b"pdu",
    }
}

pub(crate) fn print_dcerpc_pdu_view(view: Option<DceRpcPduView>) {
    let Some(pdu) = view else {
        return;
    };
    print_str(b" rpc=");
    print_str(dcerpc_ptype_name(pdu.ptype));
    print_str(b" call=");
    print_u64(pdu.call_id as u64);
    print_str(b" frag=");
    print_u64(pdu.frag_len as u64);
    print_str(b" flags=0x");
    print_hex(pdu.flags as u32);
    if let Some(assoc_gid) = pdu.assoc_gid {
        print_str(b" assoc=");
        print_u64(assoc_gid as u64);
    }
    if let Some(alloc_hint) = pdu.alloc_hint {
        print_str(b" hint=");
        print_u64(alloc_hint as u64);
    }
    if let Some(opnum) = pdu.opnum {
        print_str(b" op=");
        print_u64(opnum as u64);
    }
    if let Some(status) = pdu.fault_status {
        print_str(b" fault=0x");
        print_hex(status);
    }
    for context in pdu.context_handles.iter().flatten() {
        print_str(b" ctx@");
        print_u64(context.offset as u64);
        print_str(b" attr=");
        print_u64(context.attributes as u64);
        print_str(b" uuid=");
        print_uuid(context.uuid);
    }
}

fn print_hex_byte(byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    debug_put_char(HEX[(byte >> 4) as usize]);
    debug_put_char(HEX[(byte & 0xf) as usize]);
}

fn print_uuid(uuid: [u8; 16]) {
    debug_put_char(b'{');
    print_hex_byte(uuid[3]);
    print_hex_byte(uuid[2]);
    print_hex_byte(uuid[1]);
    print_hex_byte(uuid[0]);
    debug_put_char(b'-');
    print_hex_byte(uuid[5]);
    print_hex_byte(uuid[4]);
    debug_put_char(b'-');
    print_hex_byte(uuid[7]);
    print_hex_byte(uuid[6]);
    debug_put_char(b'-');
    print_hex_byte(uuid[8]);
    print_hex_byte(uuid[9]);
    debug_put_char(b'-');
    for byte in &uuid[10..16] {
        print_hex_byte(*byte);
    }
    debug_put_char(b'}');
}

unsafe fn pipe_queue_view(dq: u64) -> PipeQueueView {
    PipeQueueView {
        state: read_volatile((dq + 0x10) as *const u32),
        bytes: read_volatile((dq + 0x14) as *const u32),
        entries: read_volatile((dq + 0x18) as *const u32),
        quota_used: read_volatile((dq + 0x1c) as *const u32),
        byte_offset: read_volatile((dq + 0x20) as *const u32),
    }
}

unsafe fn pipe_ccb_view_in_pool(fid: u64, exec_pool_va: u64) -> Option<PipeCcbView> {
    if fid == 0 || fid == 1 {
        return None;
    }
    let component_ccb = fid & !1;
    let component_pool_end = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
    if component_ccb < FSD_POOL_VADDR + POOL_DATA_OFF
        || component_ccb + 0xC0 > component_pool_end
        || component_ccb & 7 != 0
    {
        return None;
    }
    let ccb = exec_pool_va + (component_ccb - FSD_POOL_VADDR);
    if read_volatile(ccb as *const u16) != NPFS_NTC_CCB {
        return None;
    }
    Some(PipeCcbView {
        q: [
            pipe_queue_view(ccb + NP_CCB_DATA_QUEUE),
            pipe_queue_view(ccb + NP_CCB_DATA_QUEUE + NP_DATA_QUEUE_SIZE),
        ],
    })
}

unsafe fn pipe_ccb_view(fid: u64) -> Option<PipeCcbView> {
    pipe_ccb_view_in_pool(fid, FSD_POOL_VADDR)
}

fn component_pool_end() -> u64 {
    FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000
}

fn component_pool_to_exec_va(exec_pool_va: u64, component_va: u64, bytes: u64) -> Option<u64> {
    if component_va < FSD_POOL_VADDR + POOL_DATA_OFF
        || component_va >= component_pool_end()
        || bytes > component_pool_end().saturating_sub(component_va)
    {
        return None;
    }
    exec_pool_va.checked_add(component_va - FSD_POOL_VADDR)
}

fn exec_pool_to_component_va(exec_pool_va: u64, exec_va: u64) -> Option<u64> {
    if exec_va < exec_pool_va {
        return None;
    }
    let off = exec_va - exec_pool_va;
    if off >= FSD_POOL_FRAMES * 0x1000 {
        return None;
    }
    Some(FSD_POOL_VADDR + off)
}

unsafe fn print_active_irp_graph_for_deadman(inst: &DriverInstance) {
    let sh = inst.exec_shared_va;
    let irp_c = read_volatile((sh + SH_ACTIVE_IRP) as *const u64);
    let iosl_c = read_volatile((sh + SH_ACTIVE_IOSL) as *const u64);
    let data_c = read_volatile((sh + SH_ACTIVE_DATA) as *const u64);
    let data_cap = read_volatile((sh + SH_ACTIVE_DATA_CAP) as *const u64);
    let fo_c = read_volatile((sh + SH_ACTIVE_FILE_OBJECT) as *const u64);
    if irp_c == 0 && iosl_c == 0 {
        return;
    }
    print_str(b"[deadman] active-driver-irp irp=");
    print_hex64(irp_c);
    print_str(b" iosl=");
    print_hex64(iosl_c);
    print_str(b" data=");
    print_hex64(data_c);
    print_str(b" data-cap=");
    print_u64(data_cap);
    print_str(b" fo=");
    print_hex64(fo_c);
    if let Some(irp) = component_pool_to_exec_va(inst.exec_pool_va, irp_c, WDM_X64_IRP_SIZE as u64)
    {
        let system_buffer = read_unaligned((irp + 0x18) as *const u64);
        let status = read_unaligned((irp + 0x30) as *const u32);
        let info = read_unaligned((irp + 0x38) as *const u64);
        let current_location = read_unaligned((irp + 0x42) as *const u8);
        let stack_count = read_unaligned((irp + 0x43) as *const u8);
        let user_buffer = read_unaligned((irp + 0x70) as *const u64);
        let current_stack = read_unaligned((irp + 0xb8) as *const u64);
        print_str(b" irp.sys=");
        print_hex64(system_buffer);
        print_str(b" irp.user=");
        print_hex64(user_buffer);
        print_str(b" irp.curstack=");
        print_hex64(current_stack);
        print_str(b" irp.loc=");
        print_u64(current_location as u64);
        print_str(b"/");
        print_u64(stack_count as u64);
        print_str(b" ios=");
        print_hex(status);
        print_str(b"/");
        print_u64(info);
    }
    if let Some(iosl) = component_pool_to_exec_va(
        inst.exec_pool_va,
        iosl_c,
        WDM_X64_IO_STACK_LOCATION_SIZE as u64,
    ) {
        let mj = read_unaligned(iosl as *const u8);
        let mn = read_unaligned((iosl + WDM_X64_IO_STACK_MINOR_OFFSET) as *const u8);
        let length = read_unaligned((iosl + 0x08) as *const u32);
        let io_control = read_unaligned((iosl + 0x18) as *const u32);
        let type3 = read_unaligned((iosl + 0x20) as *const u64);
        let device = read_unaligned((iosl + 0x28) as *const u64);
        let file_object = read_unaligned((iosl + 0x30) as *const u64);
        print_str(b" stack.mj=");
        print_u64(mj as u64);
        print_str(b".");
        print_u64(mn as u64);
        print_str(b" len=");
        print_u64(length as u64);
        print_str(b" ctl=0x");
        print_hex(io_control);
        print_str(b" type3=");
        print_hex64(type3);
        print_str(b" dev=");
        print_hex64(device);
        print_str(b" stack.fo=");
        print_hex64(file_object);
        if let Some(fo) = component_pool_to_exec_va(
            inst.exec_pool_va,
            file_object,
            WDM_X64_FILE_OBJECT_SIZE as u64,
        ) {
            let fsctx = read_unaligned((fo + 0x18) as *const u64);
            let fsctx2 = read_unaligned((fo + 0x20) as *const u64);
            print_str(b" fsctx=");
            print_hex64(fsctx);
            print_str(b" fsctx2=");
            print_hex64(fsctx2);
        }
    }
    print_str(b"\n");
}

unsafe fn print_pipe_queue_heads_for_deadman(fid: u64, inst: &DriverInstance, active_out: u64) {
    if fid == 0 || fid == 1 {
        return;
    }
    let component_ccb = fid & !1;
    if component_ccb < FSD_POOL_VADDR + POOL_DATA_OFF
        || component_ccb + 0xC0 > component_pool_end()
        || component_ccb & 7 != 0
    {
        return;
    }
    let Some(ccb) = component_pool_to_exec_va(inst.exec_pool_va, component_ccb, 0xC0) else {
        return;
    };
    if read_volatile(ccb as *const u16) != NPFS_NTC_CCB {
        return;
    }
    for end in 0..2u64 {
        let dq = ccb + NP_CCB_DATA_QUEUE + end * NP_DATA_QUEUE_SIZE;
        let Some(component_dq) = exec_pool_to_component_va(inst.exec_pool_va, dq) else {
            continue;
        };
        let head_c = read_volatile(dq as *const u64);
        let state = read_volatile((dq + 0x10) as *const u32);
        let bytes = read_volatile((dq + 0x14) as *const u32);
        let entries = read_volatile((dq + 0x18) as *const u32);
        let quota = read_volatile((dq + 0x1c) as *const u32);
        let byte_offset = read_volatile((dq + 0x20) as *const u32);
        print_str(b"[deadman] active-driver-q");
        print_u64(end);
        print_str(b" dq=");
        print_hex64(component_dq);
        print_str(b" state=");
        print_u64(state as u64);
        print_str(b" bytes=");
        print_u64(bytes as u64);
        print_str(b" entries=");
        print_u64(entries as u64);
        print_str(b" quota=");
        print_u64(quota as u64);
        print_str(b" offset=");
        print_u64(byte_offset as u64);
        print_str(b" head=");
        print_hex64(head_c);
        if head_c != component_dq && head_c & 7 == 0 {
            if let Some(head) = component_pool_to_exec_va(inst.exec_pool_va, head_c, 0x38) {
                let ty = read_volatile((head + 0x10) as *const u32);
                let irp = read_volatile((head + 0x18) as *const u64);
                let quota_in_entry = read_volatile((head + 0x20) as *const u32);
                let client_ctx = read_volatile((head + 0x28) as *const u64);
                let data_size = read_volatile((head + 0x30) as *const u32);
                let remaining = data_size.saturating_sub(byte_offset);
                let expected_copy = (remaining as u64).min(active_out);
                let src_c = head_c + 0x38 + byte_offset as u64;
                print_str(b" entry.type=");
                print_u64(ty as u64);
                print_str(b" entry.irp=");
                print_hex64(irp);
                print_str(b" entry.quota=");
                print_u64(quota_in_entry as u64);
                print_str(b" entry.ctx=");
                print_hex64(client_ctx);
                print_str(b" entry.size=");
                print_u64(data_size as u64);
                print_str(b" expected=");
                print_u64(remaining as u64);
                print_str(b"/");
                print_u64(expected_copy);
                print_str(b" src=");
                print_hex64(src_c);
                if let Some(src) = component_pool_to_exec_va(inst.exec_pool_va, src_c, 1) {
                    print_str(b" bytes=");
                    let preview = expected_copy.min(8);
                    for i in 0..preview {
                        print_hex_byte(read_volatile((src + i) as *const u8));
                    }
                }
            }
        }
        print_str(b"\n");
    }
}

fn print_pipe_ccb_view(tag: &[u8], view: PipeCcbView) {
    print_str(tag);
    for end in 0..2usize {
        let q = view.q[end];
        print_str(b" q");
        print_u64(end as u64);
        print_str(b"=");
        print_u64(q.state as u64);
        print_str(b"/");
        print_u64(q.bytes as u64);
        print_str(b"/");
        print_u64(q.entries as u64);
        print_str(b"/");
        print_u64(q.byte_offset as u64);
        print_str(b"/");
        print_u64(q.quota_used as u64);
    }
}

fn trace_active_write_call_site(phase: &[u8], seq: u64, file_id: u64, handler: u64, irp: u64) {
    print_str(b"[fsd-active-write] ");
    print_str(phase);
    print_str(b" seq=");
    print_u64(seq);
    print_str(b" fid=");
    print_hex64(file_id);
    print_str(b" handler=");
    print_hex64(handler);
    print_str(b" irp=");
    print_hex64(irp);
    unsafe {
        if let Some(view) = pipe_ccb_view(file_id) {
            print_pipe_ccb_view(b"", view);
        }
    }
    print_str(b"\n");
}

fn print_hex64(value: u64) {
    print_str(b"0x");
    for i in (0..16).rev() {
        let nib = ((value >> (i * 4)) & 0xf) as u8;
        debug_put_char(if nib < 10 {
            b'0' + nib
        } else {
            b'a' + (nib - 10)
        });
    }
}

fn print_tcb_debug_opt(value: u64) {
    if value == crate::win32k_glue::TCB_DEBUG_NONE {
        print_str(b"none");
    } else {
        print_u64(value);
    }
}

unsafe fn trace_pipe_rw_result(
    major: u64,
    file_id: u64,
    fsctx: u64,
    length: u64,
    status: u32,
    info: u64,
    before: Option<PipeCcbView>,
    payload: u64,
    payload_len: u64,
) {
    if major != IRP_MJ_READ && major != IRP_MJ_WRITE {
        return;
    }
    let after = pipe_ccb_view(if fsctx != 0 { fsctx } else { file_id });
    if major == IRP_MJ_READ {
        trace_dcerpc_read_reassembly(file_id, status, info, payload, payload_len);
    }
    let pdu = dcerpc_pdu_view(payload, payload_len);
    if let Some(view) = pdu {
        dcerpc_trace_context_flow(file_id, view);
    }
    let interesting = status == STATUS_PENDING
        || status == STATUS_BUFFER_OVERFLOW
        || info != 0
        || pdu.is_some()
        || before.is_some_and(|view| view.has_queued_state())
        || after.is_some_and(|view| view.has_queued_state());
    if !interesting || PIPE_RW_TRACE_COUNT >= PIPE_RW_TRACE_CAP {
        return;
    }
    PIPE_RW_TRACE_COUNT += 1;
    print_str(b"[fsd-pipe-rw] major=");
    print_u64(major);
    print_str(b" fid=0x");
    print_hex(file_id as u32);
    print_str(b" end=");
    print_u64(file_id & 1);
    print_str(b" fsctx=0x");
    print_hex(fsctx as u32);
    print_str(b" len=");
    print_u64(length);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" info=");
    print_u64(info);
    print_dcerpc_pdu_view(pdu);
    if let Some(view) = before {
        print_pipe_ccb_view(b" before", view);
    }
    if let Some(view) = after {
        print_pipe_ccb_view(b" after", view);
    }
    print_str(b"\n");
}

unsafe fn trace_pipe_transceive_result(
    file_id: u64,
    fsctx: u64,
    input_len: u64,
    output_len: u64,
    status: u32,
    info: u64,
    before: Option<PipeCcbView>,
    payload: u64,
    payload_len: u64,
) {
    let after = pipe_ccb_view(if fsctx != 0 { fsctx } else { file_id });
    let pdu = dcerpc_pdu_view(payload, payload_len);
    if let Some(view) = pdu {
        dcerpc_trace_context_flow(file_id, view);
    }
    let interesting = status == STATUS_PENDING
        || status == STATUS_BUFFER_OVERFLOW
        || status == 0xC000_00AE
        || status & 0xC000_0000 == 0xC000_0000
        || info != 0
        || pdu.is_some()
        || before.is_some_and(|view| view.has_queued_state())
        || after.is_some_and(|view| view.has_queued_state());
    if !interesting || PIPE_TRANSCEIVE_TRACE_COUNT >= PIPE_TRANSCEIVE_TRACE_CAP {
        return;
    }
    PIPE_TRANSCEIVE_TRACE_COUNT += 1;
    print_str(b"[fsd-pipe-transceive] fid=0x");
    print_hex(file_id as u32);
    print_str(b" end=");
    print_u64(file_id & 1);
    print_str(b" fsctx=0x");
    print_hex(fsctx as u32);
    print_str(b" in=");
    print_u64(input_len);
    print_str(b" out=");
    print_u64(output_len);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" info=");
    print_u64(info);
    print_dcerpc_pdu_view(pdu);
    if let Some(view) = before {
        print_pipe_ccb_view(b" before", view);
    }
    if let Some(view) = after {
        print_pipe_ccb_view(b" after", view);
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
                    print_u64(pending_irp_exists(eirp) as u64);
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
// It was once an unresolved import that resolved to a generic success no-op: the driver's assertion
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
/// dispatch (i.e. during `DriverEntry`, before the escape is armed) is reported explicitly; IRP
/// dispatch bugchecks are fail-closed through the guarded unwind path.
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

/// Bounded count of unresolved hosted-driver imports logged before the PE load is rejected.
static mut DRIVER_UNRESOLVED_IMPORTS_LOGGED: u32 = 0;

extern "win64" fn s_zero() -> u64 {
    0
}

extern "win64" fn s_void() {}

extern "win64" fn s_ke_release_mutex(_mutex: u64, _wait: u8) -> i32 {
    1
}

extern "win64" fn s_ke_cancel_timer(_timer: u64) -> u8 {
    0
}

extern "win64" fn s_ke_set_timer(_timer: u64, _due_time: u64, _dpc: u64) -> u8 {
    0
}

extern "win64" fn s_ke_set_timer_ex(_timer: u64, _due_time: u64, _period: i32, _dpc: u64) -> u8 {
    0
}

extern "win64" fn s_ke_stall_execution_processor(microseconds: u32) {
    let mut spins = 0u32;
    let limit = microseconds.min(1000).saturating_mul(64);
    while spins < limit {
        core::hint::spin_loop();
        spins += 1;
    }
}

extern "win64" fn s_probe_for_read(_address: u64, _length: u64, _alignment: u64) {}

extern "win64" fn s_probe_for_write(_address: u64, _length: u64, _alignment: u64) {}

extern "win64" fn s_c_specific_handler(
    _exception_record: u64,
    _establisher_frame: u64,
    _context_record: u64,
    _dispatcher_context: u64,
) -> i32 {
    0
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;
const STATUS_INVALID_HANDLE: i32 = 0xC000_0008u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001Au32 as i32;

const UNICODE_STRING_LENGTH_OFFSET: u64 = 0;
const UNICODE_STRING_MAXIMUM_LENGTH_OFFSET: u64 = 2;
const UNICODE_STRING_BUFFER_OFFSET: u64 = 8;
const ANSI_STRING_LENGTH_OFFSET: u64 = 0;
const ANSI_STRING_MAXIMUM_LENGTH_OFFSET: u64 = 2;
const ANSI_STRING_BUFFER_OFFSET: u64 = 8;

static mut KE_NUMBER_PROCESSORS_VALUE: u8 = 1;

const DRIVER_REGISTRY_HANDLE_BASE: u64 = 0xFFFF_FF00_4452_0000;
const DRIVER_REGISTRY_HANDLE_INDEX_MASK: u64 = 0x0000_FFFF;
const HOSTED_INSTANCE_PATH_MAX: usize = 128;
const HOSTED_DRIVER_KEY_NAME_MAX: usize = 128;
const HOSTED_REGISTRY_PATH_MAX: usize = 192;
const HOSTED_EXPORT_NAME_MAX: usize = 96;
const HOSTED_INTERFACE_LINK_MAX: usize = 192;
type HostedRegistryIdentityId = usize;
const INVALID_HOSTED_REGISTRY_IDENTITY_ID: HostedRegistryIdentityId = usize::MAX;

#[derive(Clone, Copy)]
struct DriverObjectExtensionSlot {
    driver_object: u64,
    client_id: u64,
    extension: u64,
    used: bool,
}

static mut DRIVER_OBJECT_EXTENSIONS: Option<Vec<DriverObjectExtensionSlot>> = None;

#[derive(Clone, Copy)]
struct HostedAscii<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> HostedAscii<N> {
    const fn empty() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn push_byte(&mut self, b: u8) -> bool {
        if self.len >= N || b > 0x7f || b == 0 {
            return false;
        }
        self.bytes[self.len] = b;
        self.len += 1;
        true
    }

    fn push_str(&mut self, src: &str) -> bool {
        let bytes = src.as_bytes();
        if self.len + bytes.len() > N {
            return false;
        }
        let mut i = 0usize;
        while i < bytes.len() {
            let b = bytes[i];
            if b > 0x7f || b == 0 {
                return false;
            }
            self.bytes[self.len + i] = b;
            i += 1;
        }
        self.len += bytes.len();
        true
    }

    fn set_str(&mut self, src: &str) -> bool {
        self.clear();
        self.push_str(src)
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

#[derive(Clone, Copy)]
struct HostedDriverRegistryIdentity {
    instance_path: HostedAscii<HOSTED_INSTANCE_PATH_MAX>,
    driver_key_name: HostedAscii<HOSTED_DRIVER_KEY_NAME_MAX>,
    export_name: HostedAscii<HOSTED_EXPORT_NAME_MAX>,
    used: bool,
}

const EMPTY_HOSTED_DRIVER_REGISTRY_IDENTITY: HostedDriverRegistryIdentity =
    HostedDriverRegistryIdentity {
        instance_path: HostedAscii::empty(),
        driver_key_name: HostedAscii::empty(),
        export_name: HostedAscii::empty(),
        used: false,
    };

impl HostedDriverRegistryIdentity {
    fn has_driver_key(self) -> bool {
        self.used && !self.driver_key_name.is_empty()
    }

    fn has_linkage_export(self) -> bool {
        self.has_driver_key() && !self.export_name.is_empty()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DriverRegistryHandleKind {
    DriverKey,
    LinkageKey,
}

#[derive(Clone, Copy)]
struct HostedDeviceInterfaceRegistration {
    symbolic_link: HostedAscii<HOSTED_INTERFACE_LINK_MAX>,
    target: HostedAscii<HOSTED_EXPORT_NAME_MAX>,
    enabled: bool,
    used: bool,
}

const EMPTY_HOSTED_DEVICE_INTERFACE_REGISTRATION: HostedDeviceInterfaceRegistration =
    HostedDeviceInterfaceRegistration {
        symbolic_link: HostedAscii::empty(),
        target: HostedAscii::empty(),
        enabled: false,
        used: false,
    };

#[derive(Clone, Copy)]
struct HostedRegistryIdentitySlot {
    identity: HostedDriverRegistryIdentity,
    ref_count: u8,
    used: bool,
}

const EMPTY_HOSTED_REGISTRY_IDENTITY_SLOT: HostedRegistryIdentitySlot =
    HostedRegistryIdentitySlot {
        identity: EMPTY_HOSTED_DRIVER_REGISTRY_IDENTITY,
        ref_count: 0,
        used: false,
    };

#[derive(Clone, Copy)]
struct DriverRegistryHandleSlot {
    handle: u64,
    kind: DriverRegistryHandleKind,
    identity: HostedDriverRegistryIdentity,
    used: bool,
}

const EMPTY_DRIVER_REGISTRY_HANDLE_SLOT: DriverRegistryHandleSlot = DriverRegistryHandleSlot {
    handle: 0,
    kind: DriverRegistryHandleKind::DriverKey,
    identity: EMPTY_HOSTED_DRIVER_REGISTRY_IDENTITY,
    used: false,
};

static mut DRIVER_REGISTRY_HANDLES: Option<Vec<DriverRegistryHandleSlot>> = None;
static mut HOSTED_REGISTRY_IDENTITIES: Option<Vec<HostedRegistryIdentitySlot>> = None;
static mut HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID: HostedRegistryIdentityId =
    INVALID_HOSTED_REGISTRY_IDENTITY_ID;
static mut HOSTED_DEVICE_INTERFACE_REGISTRATIONS: Option<Vec<HostedDeviceInterfaceRegistration>> =
    None;

#[inline]
fn ascii_upcase_u16(c: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&c) {
        c - 32
    } else {
        c
    }
}

#[inline]
fn ascii_upcase_u8(c: u8) -> u8 {
    if c.is_ascii_lowercase() {
        c - 32
    } else {
        c
    }
}

fn ascii_eq_ignore_case(a: &str, b: &str) -> bool {
    let aa = a.as_bytes();
    let bb = b.as_bytes();
    if aa.len() != bb.len() {
        return false;
    }
    let mut i = 0usize;
    while i < aa.len() {
        if ascii_upcase_u8(aa[i]) != ascii_upcase_u8(bb[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn ascii_prefix_eq_ignore_case(text: &str, prefix: &str) -> bool {
    let text = text.as_bytes();
    let prefix = prefix.as_bytes();
    if text.len() < prefix.len() {
        return false;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        if ascii_upcase_u8(text[i]) != ascii_upcase_u8(prefix[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn hosted_ascii_eq_ignore_case<const A: usize, const B: usize>(
    a: &HostedAscii<A>,
    b: &HostedAscii<B>,
) -> bool {
    if a.len != b.len {
        return false;
    }
    let mut i = 0usize;
    while i < a.len {
        if ascii_upcase_u8(a.bytes[i]) != ascii_upcase_u8(b.bytes[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn hosted_ascii_eq_ignore_case_str<const N: usize>(a: &HostedAscii<N>, b: &str) -> bool {
    let bb = b.as_bytes();
    if a.len != bb.len() {
        return false;
    }
    let mut i = 0usize;
    while i < a.len {
        if ascii_upcase_u8(a.bytes[i]) != ascii_upcase_u8(bb[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn driver_key_matches_class_guid(driver_key: &str, class_guid: &str) -> bool {
    if class_guid.is_empty() {
        return true;
    }
    let key = if ascii_prefix_eq_ignore_case(driver_key, "Class\\") {
        &driver_key[6..]
    } else {
        driver_key
    };
    if key.len() < class_guid.len() {
        return false;
    }
    if !ascii_prefix_eq_ignore_case(key, class_guid) {
        return false;
    }
    key.len() == class_guid.len() || key.as_bytes()[class_guid.len()] == b'\\'
}

fn build_hosted_registry_identity(
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
) -> Result<HostedDriverRegistryIdentity, nt_status::NtStatus> {
    let mut identity = EMPTY_HOSTED_DRIVER_REGISTRY_IDENTITY;
    if !identity.instance_path.set_str(instance_path) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }

    if let Some(driver_key) = driver_key.filter(|key| !key.is_empty()) {
        if let Some(class_guid) = class_guid.filter(|guid| !guid.is_empty()) {
            if !driver_key_matches_class_guid(driver_key, class_guid) {
                return Err(nt_status::NtStatus::INVALID_PARAMETER);
            }
        }
        if !identity.driver_key_name.set_str(driver_key) {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        if let Some(linkage_export) = linkage_export {
            if linkage_export.is_empty() || !identity.export_name.set_str(linkage_export) {
                return Err(nt_status::NtStatus::INVALID_PARAMETER);
            }
        }
    } else if linkage_export.is_some() {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }

    identity.used = true;
    Ok(identity)
}

unsafe fn write_shared_registry_ascii<const N: usize>(
    sh: u64,
    len_off: u64,
    buf_off: u64,
    value: &HostedAscii<N>,
) -> Result<(), nt_status::NtStatus> {
    let len = u16::try_from(value.len).map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    write_volatile((sh + len_off) as *mut u16, len);
    let mut i = 0usize;
    while i < value.len {
        write_volatile((sh + buf_off + i as u64) as *mut u8, value.bytes[i]);
        i += 1;
    }
    Ok(())
}

unsafe fn read_shared_registry_ascii<const N: usize>(
    len_off: u64,
    buf_off: u64,
) -> Option<HostedAscii<N>> {
    let len = read_volatile((FSD_SHARED_VADDR + len_off) as *const u16) as usize;
    if len > N {
        return None;
    }
    let mut out = HostedAscii::<N>::empty();
    let mut i = 0usize;
    while i < len {
        let b = read_volatile((FSD_SHARED_VADDR + buf_off + i as u64) as *const u8);
        if b == 0 || b > 0x7f || !out.push_byte(b) {
            return None;
        }
        i += 1;
    }
    Some(out)
}

unsafe fn clear_shared_registry_identity_at(sh: u64) {
    write_volatile((sh + SH_REGISTRY_IDENTITY_FLAGS) as *mut u32, 0);
    write_volatile((sh + SH_REGISTRY_INSTANCE_LEN) as *mut u16, 0);
    write_volatile((sh + SH_REGISTRY_DRIVER_KEY_LEN) as *mut u16, 0);
    write_volatile((sh + SH_REGISTRY_EXPORT_LEN) as *mut u16, 0);
}

unsafe fn publish_shared_registry_identity_at(
    sh: u64,
    identity: &HostedDriverRegistryIdentity,
) -> Result<(), nt_status::NtStatus> {
    clear_shared_registry_identity_at(sh);
    if !identity.used || identity.instance_path.is_empty() {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    write_shared_registry_ascii(
        sh,
        SH_REGISTRY_INSTANCE_LEN,
        SH_REGISTRY_INSTANCE_BUF,
        &identity.instance_path,
    )?;
    let mut flags = SH_REGISTRY_IDENTITY_PRESENT;
    if identity.has_driver_key() {
        write_shared_registry_ascii(
            sh,
            SH_REGISTRY_DRIVER_KEY_LEN,
            SH_REGISTRY_DRIVER_KEY_BUF,
            &identity.driver_key_name,
        )?;
        flags |= SH_REGISTRY_IDENTITY_HAS_DRIVER_KEY;
    }
    if identity.has_linkage_export() {
        write_shared_registry_ascii(
            sh,
            SH_REGISTRY_EXPORT_LEN,
            SH_REGISTRY_EXPORT_BUF,
            &identity.export_name,
        )?;
        flags |= SH_REGISTRY_IDENTITY_HAS_EXPORT;
    }
    write_volatile((sh + SH_REGISTRY_IDENTITY_FLAGS) as *mut u32, flags);
    Ok(())
}

unsafe fn shared_registry_identity() -> Option<HostedDriverRegistryIdentity> {
    let flags = read_volatile((FSD_SHARED_VADDR + SH_REGISTRY_IDENTITY_FLAGS) as *const u32);
    if (flags & SH_REGISTRY_IDENTITY_PRESENT) == 0 {
        return None;
    }
    if (flags & SH_REGISTRY_IDENTITY_HAS_EXPORT) != 0
        && (flags & SH_REGISTRY_IDENTITY_HAS_DRIVER_KEY) == 0
    {
        return None;
    }
    let instance_path = read_shared_registry_ascii::<HOSTED_INSTANCE_PATH_MAX>(
        SH_REGISTRY_INSTANCE_LEN,
        SH_REGISTRY_INSTANCE_BUF,
    )?;
    if instance_path.is_empty() {
        return None;
    }
    let driver_key_name = if (flags & SH_REGISTRY_IDENTITY_HAS_DRIVER_KEY) != 0 {
        let key = read_shared_registry_ascii::<HOSTED_DRIVER_KEY_NAME_MAX>(
            SH_REGISTRY_DRIVER_KEY_LEN,
            SH_REGISTRY_DRIVER_KEY_BUF,
        )?;
        if key.is_empty() {
            return None;
        }
        key
    } else {
        HostedAscii::empty()
    };
    let export_name = if (flags & SH_REGISTRY_IDENTITY_HAS_EXPORT) != 0 {
        let export = read_shared_registry_ascii::<HOSTED_EXPORT_NAME_MAX>(
            SH_REGISTRY_EXPORT_LEN,
            SH_REGISTRY_EXPORT_BUF,
        )?;
        if export.is_empty() {
            return None;
        }
        export
    } else {
        HostedAscii::empty()
    };
    Some(HostedDriverRegistryIdentity {
        instance_path,
        driver_key_name,
        export_name,
        used: true,
    })
}

fn hosted_linkage_path_matches<const N: usize>(
    path: &HostedAscii<N>,
    driver_key: &HostedAscii<HOSTED_DRIVER_KEY_NAME_MAX>,
) -> bool {
    const PREFIX: &[u8] = b"Class\\";
    const SUFFIX: &[u8] = b"\\Linkage";
    let expected_len = PREFIX.len() + driver_key.len + SUFFIX.len();
    if driver_key.is_empty() || path.len != expected_len {
        return false;
    }
    let mut i = 0usize;
    while i < PREFIX.len() {
        if ascii_upcase_u8(path.bytes[i]) != ascii_upcase_u8(PREFIX[i]) {
            return false;
        }
        i += 1;
    }
    let mut key_idx = 0usize;
    while key_idx < driver_key.len {
        if ascii_upcase_u8(path.bytes[PREFIX.len() + key_idx])
            != ascii_upcase_u8(driver_key.bytes[key_idx])
        {
            return false;
        }
        key_idx += 1;
    }
    let suffix_start = PREFIX.len() + driver_key.len;
    let mut suffix_idx = 0usize;
    while suffix_idx < SUFFIX.len() {
        if ascii_upcase_u8(path.bytes[suffix_start + suffix_idx])
            != ascii_upcase_u8(SUFFIX[suffix_idx])
        {
            return false;
        }
        suffix_idx += 1;
    }
    true
}

unsafe fn unicode_string_triplet(us: u64) -> Option<(u16, u16, u64)> {
    if us == 0 {
        return None;
    }
    Some((
        read_unaligned((us + UNICODE_STRING_LENGTH_OFFSET) as *const u16),
        read_unaligned((us + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16),
        read_unaligned((us + UNICODE_STRING_BUFFER_OFFSET) as *const u64),
    ))
}

unsafe fn unicode_string_to_hosted_ascii<const N: usize>(
    us: u64,
    allow_empty: bool,
) -> Option<HostedAscii<N>> {
    let (len, _max, buf) = unicode_string_triplet(us)?;
    if (len & 1) != 0 || (len != 0 && buf == 0) {
        return None;
    }
    if len == 0 {
        return if allow_empty {
            Some(HostedAscii::empty())
        } else {
            None
        };
    }
    let chars = (len / 2) as usize;
    if chars > N {
        return None;
    }
    let mut out = HostedAscii::<N>::empty();
    let mut i = 0usize;
    while i < chars {
        let c = read_unaligned((buf + (i as u64) * 2) as *const u16);
        if c == 0 || c > 0x7f {
            return None;
        }
        if !out.push_byte(c as u8) {
            return None;
        }
        i += 1;
    }
    Some(out)
}

unsafe fn wide_cstr_to_hosted_ascii<const N: usize>(ptr: u64) -> Option<HostedAscii<N>> {
    if ptr == 0 {
        return None;
    }
    let mut out = HostedAscii::<N>::empty();
    let mut i = 0usize;
    loop {
        if i >= N {
            return None;
        }
        let c = read_unaligned((ptr + (i as u64) * 2) as *const u16);
        if c == 0 {
            return Some(out);
        }
        if c > 0x7f || !out.push_byte(c as u8) {
            return None;
        }
        i += 1;
    }
}

unsafe fn write_allocated_unicode_string_from_ascii<const N: usize>(
    us: u64,
    value: &HostedAscii<N>,
) -> i32 {
    if us == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let data_len = value.len.saturating_mul(2);
    if data_len > u16::MAX as usize - 2 {
        return STATUS_INVALID_PARAMETER;
    }
    let alloc_len = data_len + 2;
    let buf = pool_alloc(alloc_len as u64);
    if buf == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let mut i = 0usize;
    while i < value.len {
        write_unaligned((buf + (i as u64) * 2) as *mut u16, value.bytes[i] as u16);
        i += 1;
    }
    write_unaligned((buf + data_len as u64) as *mut u16, 0);
    write_unaligned(
        (us + UNICODE_STRING_LENGTH_OFFSET) as *mut u16,
        data_len as u16,
    );
    write_unaligned(
        (us + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16,
        alloc_len as u16,
    );
    write_unaligned((us + UNICODE_STRING_BUFFER_OFFSET) as *mut u64, buf);
    STATUS_SUCCESS
}

unsafe fn write_ascii_sz_property_utf16<const N: usize>(
    buffer_len: u32,
    buffer: u64,
    result_len: u64,
    value: &HostedAscii<N>,
) -> i32 {
    let need = (value.len.saturating_add(1)).saturating_mul(2);
    if result_len != 0 {
        write_unaligned(result_len as *mut u32, need as u32);
    }
    if need > u32::MAX as usize || buffer == 0 || buffer_len < need as u32 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut i = 0usize;
    while i < value.len {
        write_unaligned((buffer + (i as u64) * 2) as *mut u16, value.bytes[i] as u16);
        i += 1;
    }
    write_unaligned((buffer + (value.len as u64) * 2) as *mut u16, 0);
    STATUS_SUCCESS
}

unsafe fn object_attributes_root_and_name<const N: usize>(
    object_attributes: u64,
) -> Option<(u64, HostedAscii<N>)> {
    if object_attributes == 0 {
        return None;
    }
    let root = read_unaligned((object_attributes + 8) as *const u64);
    let name = read_unaligned((object_attributes + 0x10) as *const u64);
    let name = if name == 0 {
        HostedAscii::empty()
    } else {
        unicode_string_to_hosted_ascii(name, true)?
    };
    Some((root, name))
}

fn hex_digit(value: u8) -> u8 {
    match value & 0xf {
        0..=9 => b'0' + (value & 0xf),
        _ => b'A' + ((value & 0xf) - 10),
    }
}

fn push_hex_u32<const N: usize>(out: &mut HostedAscii<N>, value: u32, nibbles: u8) -> bool {
    let mut shift = (nibbles as i32 - 1) * 4;
    while shift >= 0 {
        if !out.push_byte(hex_digit(((value >> shift) & 0xf) as u8)) {
            return false;
        }
        shift -= 4;
    }
    true
}

fn push_hex_u16<const N: usize>(out: &mut HostedAscii<N>, value: u16, nibbles: u8) -> bool {
    push_hex_u32(out, value as u32, nibbles)
}

fn push_hex_u8<const N: usize>(out: &mut HostedAscii<N>, value: u8) -> bool {
    push_hex_u32(out, value as u32, 2)
}

unsafe fn guid_to_hosted_ascii(guid: u64) -> Option<HostedAscii<HOSTED_DRIVER_KEY_NAME_MAX>> {
    if guid == 0 {
        return None;
    }
    let d1 = read_unaligned(guid as *const u32);
    let d2 = read_unaligned((guid + 4) as *const u16);
    let d3 = read_unaligned((guid + 6) as *const u16);
    let mut d4 = [0u8; 8];
    let mut i = 0usize;
    while i < d4.len() {
        d4[i] = read_unaligned((guid + 8 + i as u64) as *const u8);
        i += 1;
    }

    let mut out = HostedAscii::<HOSTED_DRIVER_KEY_NAME_MAX>::empty();
    if !out.push_byte(b'{')
        || !push_hex_u32(&mut out, d1, 8)
        || !out.push_byte(b'-')
        || !push_hex_u16(&mut out, d2, 4)
        || !out.push_byte(b'-')
        || !push_hex_u16(&mut out, d3, 4)
        || !out.push_byte(b'-')
        || !push_hex_u8(&mut out, d4[0])
        || !push_hex_u8(&mut out, d4[1])
        || !out.push_byte(b'-')
    {
        return None;
    }
    i = 2;
    while i < d4.len() {
        if !push_hex_u8(&mut out, d4[i]) {
            return None;
        }
        i += 1;
    }
    if !out.push_byte(b'}') {
        return None;
    }
    Some(out)
}

unsafe fn copy_bytes_unchecked(dst: u64, src: u64, len: u64) {
    let mut off = 0u64;
    while off < len {
        write_unaligned(
            (dst + off) as *mut u8,
            read_unaligned((src + off) as *const u8),
        );
        off += 1;
    }
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

/// `VOID RtlFreeUnicodeString(PUNICODE_STRING)`.
extern "win64" fn s_rtl_free_unicode_string(us: u64) {
    unsafe {
        if let Some((_len, _max, buf)) = unicode_string_triplet(us) {
            if buf != 0 {
                pool_free(buf);
            }
            write_unaligned((us + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, 0);
            write_unaligned((us + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16, 0);
            write_unaligned((us + UNICODE_STRING_BUFFER_OFFSET) as *mut u64, 0);
        }
    }
}

/// `VOID RtlCopyUnicodeString(PUNICODE_STRING Destination, PCUNICODE_STRING Source)`.
extern "win64" fn s_rtl_copy_unicode_string(dst: u64, src: u64) {
    if dst == 0 {
        return;
    }
    unsafe {
        let dst_max =
            read_unaligned((dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16) & !1;
        let dst_buf = read_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *const u64);
        if src == 0 || dst_buf == 0 || dst_max == 0 {
            write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, 0);
            return;
        }
        let (src_len, _src_max, src_buf) = unicode_string_triplet(src).unwrap_or((0, 0, 0));
        let copy_len = (src_len & !1).min(dst_max);
        if src_buf != 0 && copy_len != 0 {
            copy_bytes_unchecked(dst_buf, src_buf, copy_len as u64);
        }
        write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, copy_len);
    }
}

/// `LONG RtlCompareUnicodeString(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN CaseInsensitive)`.
extern "win64" fn s_rtl_compare_unicode_string(left: u64, right: u64, case_insensitive: u8) -> i32 {
    unsafe {
        let (left_len, _left_max, left_buf) = unicode_string_triplet(left).unwrap_or((0, 0, 0));
        let (right_len, _right_max, right_buf) = unicode_string_triplet(right).unwrap_or((0, 0, 0));
        let left_chars = (left_len / 2) as u64;
        let right_chars = (right_len / 2) as u64;
        let common = left_chars.min(right_chars);
        let mut i = 0u64;
        while i < common {
            let mut a = if left_buf == 0 {
                0
            } else {
                read_unaligned((left_buf + i * 2) as *const u16)
            };
            let mut b = if right_buf == 0 {
                0
            } else {
                read_unaligned((right_buf + i * 2) as *const u16)
            };
            if case_insensitive != 0 {
                a = ascii_upcase_u16(a);
                b = ascii_upcase_u16(b);
            }
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        left_chars as i32 - right_chars as i32
    }
}

/// `NTSTATUS RtlUpcaseUnicodeString(PUNICODE_STRING Dest, PCUNICODE_STRING Src, BOOLEAN Allocate)`.
extern "win64" fn s_rtl_upcase_unicode_string(dst: u64, src: u64, allocate: u8) -> i32 {
    if dst == 0 || src == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let (src_len, _src_max, src_buf) = unicode_string_triplet(src).unwrap_or((0, 0, 0));
        if src_len != 0 && src_buf == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let dst_buf = if allocate != 0 {
            let alloc_len = (src_len as u64).max(2);
            let p = pool_alloc(alloc_len);
            if p == 0 {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            write_unaligned(
                (dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16,
                alloc_len as u16,
            );
            write_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *mut u64, p);
            p
        } else {
            let max_len =
                read_unaligned((dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16) & !1;
            let p = read_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *const u64);
            if src_len > max_len || (src_len != 0 && p == 0) {
                write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, 0);
                return STATUS_BUFFER_TOO_SMALL;
            }
            p
        };
        let mut off = 0u64;
        while off < src_len as u64 {
            let c = read_unaligned((src_buf + off) as *const u16);
            write_unaligned((dst_buf + off) as *mut u16, ascii_upcase_u16(c));
            off += 2;
        }
        write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, src_len);
    }
    STATUS_SUCCESS
}

/// `NTSTATUS RtlAppendUnicodeStringToString(PUNICODE_STRING Dest, PCUNICODE_STRING Src)`.
extern "win64" fn s_rtl_append_unicode_string_to_string(dst: u64, src: u64) -> i32 {
    if dst == 0 || src == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let dst_len = read_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *const u16) & !1;
        let dst_max =
            read_unaligned((dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16) & !1;
        let dst_buf = read_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *const u64);
        let (src_len, _src_max, src_buf) = unicode_string_triplet(src).unwrap_or((0, 0, 0));
        if dst_buf == 0 || (src_len != 0 && src_buf == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if src_len > dst_max.saturating_sub(dst_len) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        copy_bytes_unchecked(dst_buf + dst_len as u64, src_buf, src_len as u64);
        let new_len = dst_len + src_len;
        write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, new_len);
        if new_len <= dst_max.saturating_sub(2) {
            write_unaligned((dst_buf + new_len as u64) as *mut u16, 0);
        }
    }
    STATUS_SUCCESS
}

/// `NTSTATUS RtlAppendUnicodeToString(PUNICODE_STRING Dest, PCWSTR Src)`.
extern "win64" fn s_rtl_append_unicode_to_string(dst: u64, src: u64) -> i32 {
    if dst == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if src == 0 {
        return STATUS_SUCCESS;
    }
    unsafe {
        let dst_len = read_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *const u16) & !1;
        let dst_max =
            read_unaligned((dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16) & !1;
        let dst_buf = read_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *const u64);
        if dst_buf == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let src_chars = s_wcslen(src) as u16;
        let src_len = src_chars.saturating_mul(2);
        if src_len > dst_max.saturating_sub(dst_len) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        copy_bytes_unchecked(dst_buf + dst_len as u64, src, src_len as u64);
        let new_len = dst_len + src_len;
        write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, new_len);
        if new_len <= dst_max.saturating_sub(2) {
            write_unaligned((dst_buf + new_len as u64) as *mut u16, 0);
        }
    }
    STATUS_SUCCESS
}

/// `BOOLEAN RtlEqualUnicodeString(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN)`.
extern "win64" fn s_rtl_equal_unicode_string(left: u64, right: u64, case_insensitive: u8) -> u8 {
    (s_rtl_compare_unicode_string(left, right, case_insensitive) == 0) as u8
}

unsafe fn ansi_string_triplet(s: u64) -> Option<(u16, u16, u64)> {
    if s == 0 {
        return None;
    }
    Some((
        read_unaligned((s + ANSI_STRING_LENGTH_OFFSET) as *const u16),
        read_unaligned((s + ANSI_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16),
        read_unaligned((s + ANSI_STRING_BUFFER_OFFSET) as *const u64),
    ))
}

unsafe fn strlen8(src: u64) -> u16 {
    if src == 0 {
        return 0;
    }
    let mut n = 0u64;
    while n < u16::MAX as u64 && read_unaligned((src + n) as *const u8) != 0 {
        n += 1;
    }
    n as u16
}

/// `VOID RtlInitAnsiString(PANSI_STRING Dest, PCSZ Source)` / `RtlInitString`.
extern "win64" fn s_rtl_init_ansi_string(dst: u64, src: u64) {
    if dst == 0 {
        return;
    }
    unsafe {
        let len = strlen8(src);
        write_unaligned((dst + ANSI_STRING_LENGTH_OFFSET) as *mut u16, len);
        write_unaligned(
            (dst + ANSI_STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16,
            if src == 0 { 0 } else { len.saturating_add(1) },
        );
        write_unaligned((dst + ANSI_STRING_BUFFER_OFFSET) as *mut u64, src);
    }
}

/// `NTSTATUS RtlAnsiStringToUnicodeString(PUNICODE_STRING, PCANSI_STRING, BOOLEAN Allocate)`.
extern "win64" fn s_rtl_ansi_string_to_unicode_string(dst: u64, src: u64, allocate: u8) -> i32 {
    if dst == 0 || src == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let (src_len, _src_max, src_buf) = ansi_string_triplet(src).unwrap_or((0, 0, 0));
        if src_len != 0 && src_buf == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let out_len = src_len.saturating_mul(2);
        let dst_buf = if allocate != 0 {
            let alloc_len = (out_len as u64).saturating_add(2);
            let p = pool_alloc(alloc_len);
            if p == 0 {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            write_unaligned(
                (dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16,
                alloc_len as u16,
            );
            write_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *mut u64, p);
            p
        } else {
            let max_len =
                read_unaligned((dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16);
            let p = read_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *const u64);
            if out_len > max_len || (out_len != 0 && p == 0) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            p
        };
        let mut i = 0u64;
        while i < src_len as u64 {
            let b = read_unaligned((src_buf + i) as *const u8);
            write_unaligned((dst_buf + i * 2) as *mut u16, b as u16);
            i += 1;
        }
        write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, out_len);
        if out_len
            <= read_unaligned((dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16)
                .saturating_sub(2)
        {
            write_unaligned((dst_buf + out_len as u64) as *mut u16, 0);
        }
    }
    STATUS_SUCCESS
}

/// `NTSTATUS RtlUnicodeStringToAnsiString(PANSI_STRING, PCUNICODE_STRING, BOOLEAN Allocate)`.
extern "win64" fn s_rtl_unicode_string_to_ansi_string(dst: u64, src: u64, allocate: u8) -> i32 {
    if dst == 0 || src == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let (src_len, _src_max, src_buf) = unicode_string_triplet(src).unwrap_or((0, 0, 0));
        if src_len != 0 && src_buf == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let out_len = src_len / 2;
        let dst_buf = if allocate != 0 {
            let alloc_len = (out_len as u64).saturating_add(1);
            let p = pool_alloc(alloc_len);
            if p == 0 {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            write_unaligned(
                (dst + ANSI_STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16,
                alloc_len as u16,
            );
            write_unaligned((dst + ANSI_STRING_BUFFER_OFFSET) as *mut u64, p);
            p
        } else {
            let max_len = read_unaligned((dst + ANSI_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16);
            let p = read_unaligned((dst + ANSI_STRING_BUFFER_OFFSET) as *const u64);
            if out_len > max_len || (out_len != 0 && p == 0) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            p
        };
        let mut i = 0u64;
        while i < out_len as u64 {
            let w = read_unaligned((src_buf + i * 2) as *const u16);
            write_unaligned(
                (dst_buf + i) as *mut u8,
                if w <= 0x7f { w as u8 } else { b'?' },
            );
            i += 1;
        }
        write_unaligned((dst + ANSI_STRING_LENGTH_OFFSET) as *mut u16, out_len);
        if out_len
            <= read_unaligned((dst + ANSI_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16)
                .saturating_sub(1)
        {
            write_unaligned((dst_buf + out_len as u64) as *mut u8, 0);
        }
    }
    STATUS_SUCCESS
}

/// `LONG RtlCompareString(PCANSI_STRING, PCANSI_STRING, BOOLEAN)`.
extern "win64" fn s_rtl_compare_string(left: u64, right: u64, case_insensitive: u8) -> i32 {
    unsafe {
        let (left_len, _left_max, left_buf) = ansi_string_triplet(left).unwrap_or((0, 0, 0));
        let (right_len, _right_max, right_buf) = ansi_string_triplet(right).unwrap_or((0, 0, 0));
        let common = (left_len as u64).min(right_len as u64);
        let mut i = 0u64;
        while i < common {
            let mut a = if left_buf == 0 {
                0
            } else {
                read_unaligned((left_buf + i) as *const u8)
            };
            let mut b = if right_buf == 0 {
                0
            } else {
                read_unaligned((right_buf + i) as *const u8)
            };
            if case_insensitive != 0 {
                a = ascii_upcase_u8(a);
                b = ascii_upcase_u8(b);
            }
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        left_len as i32 - right_len as i32
    }
}

/// `NTSTATUS RtlIntegerToUnicodeString(ULONG Value, ULONG Base, PUNICODE_STRING String)`.
extern "win64" fn s_rtl_integer_to_unicode_string(value: u32, base: u32, dst: u64) -> i32 {
    if dst == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let radix = if base == 0 { 10 } else { base };
    if !(2..=16).contains(&radix) {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let max_len =
            read_unaligned((dst + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *const u16) & !1;
        let buf = read_unaligned((dst + UNICODE_STRING_BUFFER_OFFSET) as *const u64);
        if buf == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let mut tmp = [0u16; 32];
        let mut n = 0usize;
        let mut v = value;
        loop {
            let d = (v % radix) as u8;
            tmp[n] = if d < 10 {
                (b'0' + d) as u16
            } else {
                (b'A' + d - 10) as u16
            };
            n += 1;
            v /= radix;
            if v == 0 {
                break;
            }
        }
        let need = (n * 2) as u16;
        if need > max_len {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let mut i = 0usize;
        while i < n {
            write_unaligned((buf + (i as u64) * 2) as *mut u16, tmp[n - 1 - i]);
            i += 1;
        }
        write_unaligned((dst + UNICODE_STRING_LENGTH_OFFSET) as *mut u16, need);
        if need <= max_len.saturating_sub(2) {
            write_unaligned((buf + need as u64) as *mut u16, 0);
        }
    }
    STATUS_SUCCESS
}

/// `NTSTATUS RtlUnicodeStringToInteger(PCUNICODE_STRING String, ULONG Base, PULONG Value)`.
extern "win64" fn s_rtl_unicode_string_to_integer(src: u64, base: u32, value_out: u64) -> i32 {
    if src == 0 || value_out == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut radix = if base == 0 { 10 } else { base };
    if !(2..=16).contains(&radix) {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let (len, _max, buf) = unicode_string_triplet(src).unwrap_or((0, 0, 0));
        if len != 0 && buf == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let chars = (len / 2) as u64;
        let mut i = 0u64;
        while i < chars && read_unaligned((buf + i * 2) as *const u16) == b' ' as u16 {
            i += 1;
        }
        if base == 0
            && i + 1 < chars
            && read_unaligned((buf + i * 2) as *const u16) == b'0' as u16
            && ascii_upcase_u16(read_unaligned((buf + (i + 1) * 2) as *const u16)) == b'X' as u16
        {
            radix = 16;
            i += 2;
        }
        let mut value = 0u32;
        let mut saw_digit = false;
        while i < chars {
            let c = ascii_upcase_u16(read_unaligned((buf + i * 2) as *const u16));
            let digit = if (b'0' as u16..=b'9' as u16).contains(&c) {
                c - b'0' as u16
            } else if (b'A' as u16..=b'F' as u16).contains(&c) {
                c - b'A' as u16 + 10
            } else {
                break;
            };
            if digit as u32 >= radix {
                break;
            }
            value = value.saturating_mul(radix).saturating_add(digit as u32);
            saw_digit = true;
            i += 1;
        }
        if !saw_digit {
            return STATUS_INVALID_PARAMETER;
        }
        write_unaligned(value_out as *mut u32, value);
    }
    STATUS_SUCCESS
}

/// `wcsncmp`.
extern "win64" fn s_wcsncmp(left: u64, right: u64, count: u64) -> i32 {
    unsafe {
        let mut i = 0u64;
        while i < count {
            let a = if left == 0 {
                0
            } else {
                read_unaligned((left + i * 2) as *const u16)
            };
            let b = if right == 0 {
                0
            } else {
                read_unaligned((right + i * 2) as *const u16)
            };
            if a != b || a == 0 || b == 0 {
                return a as i32 - b as i32;
            }
            i += 1;
        }
    }
    0
}

extern "win64" fn s_wcscpy(dst: u64, src: u64) -> u64 {
    unsafe {
        let mut i = 0u64;
        loop {
            let c = if src == 0 {
                0
            } else {
                read_unaligned((src + i * 2) as *const u16)
            };
            write_unaligned((dst + i * 2) as *mut u16, c);
            i += 1;
            if c == 0 {
                break;
            }
        }
    }
    dst
}

extern "win64" fn s_wcsncpy(dst: u64, src: u64, count: u64) -> u64 {
    unsafe {
        let mut i = 0u64;
        let mut padding = false;
        while i < count {
            let c = if padding || src == 0 {
                0
            } else {
                read_unaligned((src + i * 2) as *const u16)
            };
            write_unaligned((dst + i * 2) as *mut u16, c);
            if c == 0 {
                padding = true;
            }
            i += 1;
        }
    }
    dst
}

unsafe fn wcs_end(mut s: u64) -> u64 {
    while read_unaligned(s as *const u16) != 0 {
        s += 2;
    }
    s
}

extern "win64" fn s_wcscat(dst: u64, src: u64) -> u64 {
    unsafe {
        let end = wcs_end(dst);
        let _ = s_wcscpy(end, src);
    }
    dst
}

extern "win64" fn s_wcsncat(dst: u64, src: u64, count: u64) -> u64 {
    unsafe {
        let mut out = wcs_end(dst);
        let mut i = 0u64;
        while i < count {
            let c = if src == 0 {
                0
            } else {
                read_unaligned((src + i * 2) as *const u16)
            };
            if c == 0 {
                break;
            }
            write_unaligned(out as *mut u16, c);
            out += 2;
            i += 1;
        }
        write_unaligned(out as *mut u16, 0);
    }
    dst
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

unsafe fn clear_shared_device_interface_state_at(sh: u64) {
    write_volatile((sh + SH_DEVICE_INTERFACE_LINK_LEN) as *mut u16, 0);
    write_volatile((sh + SH_DEVICE_INTERFACE_TARGET_LEN) as *mut u16, 0);
    write_volatile((sh + SH_DEVICE_INTERFACE_STATE) as *mut u32, 0);
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

unsafe fn copy_ascii_to_shared_utf16<const N: usize>(
    value: &HostedAscii<N>,
    len_off: u64,
    buf_off: u64,
) -> i32 {
    let len = value.len.saturating_mul(2);
    if len > SH_CAPTURED_PATH_BYTES {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut i = 0usize;
    while i < value.len {
        let out = FSD_SHARED_VADDR + buf_off + (i as u64) * 2;
        write_volatile(out as *mut u16, value.bytes[i] as u16);
        i += 1;
    }
    write_volatile((FSD_SHARED_VADDR + len_off) as *mut u16, len as u16);
    STATUS_SUCCESS
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
                        let table = driver_instances_mut();
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

/// `NTSTATUS IoAllocateDriverObjectExtension(PDRIVER_OBJECT, PVOID ClientId, ULONG Size, PVOID *Out)`.
extern "win64" fn s_io_allocate_driver_object_extension(
    driver_object: u64,
    client_id: u64,
    size: u32,
    extension_out: u64,
) -> i32 {
    if driver_object == 0 || extension_out == 0 || size == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let table = driver_object_extensions_mut();
        if table.iter().any(|slot| {
            slot.used && slot.driver_object == driver_object && slot.client_id == client_id
        }) {
            write_unaligned(extension_out as *mut u64, 0);
            return STATUS_OBJECT_NAME_COLLISION;
        }
        let reusable = table.iter().position(|slot| !slot.used);
        let extension = pool_alloc(size as u64);
        if extension == 0 {
            write_unaligned(extension_out as *mut u64, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        core::ptr::write_bytes(extension as *mut u8, 0, size as usize);
        let slot = DriverObjectExtensionSlot {
            driver_object,
            client_id,
            extension,
            used: true,
        };
        if let Some(idx) = reusable {
            table[idx] = slot;
        } else {
            table.push(slot);
        }
        write_unaligned(extension_out as *mut u64, extension);
    }
    STATUS_SUCCESS
}

/// `PVOID IoGetDriverObjectExtension(PDRIVER_OBJECT, PVOID ClientId)`.
extern "win64" fn s_io_get_driver_object_extension(driver_object: u64, client_id: u64) -> u64 {
    unsafe {
        let Some(table) = driver_object_extensions() else {
            return 0;
        };
        table
            .iter()
            .find(|slot| {
                slot.used && slot.driver_object == driver_object && slot.client_id == client_id
            })
            .map(|slot| slot.extension)
            .unwrap_or(0)
    }
}

unsafe fn driver_object_extensions_mut() -> &'static mut Vec<DriverObjectExtensionSlot> {
    let slot = &mut *core::ptr::addr_of_mut!(DRIVER_OBJECT_EXTENSIONS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn driver_object_extensions() -> Option<&'static Vec<DriverObjectExtensionSlot>> {
    (*core::ptr::addr_of!(DRIVER_OBJECT_EXTENSIONS)).as_ref()
}

unsafe fn clear_driver_object_extensions_for_driver_object(driver_object: u64) {
    if driver_object == 0 {
        return;
    }
    let Some(table) = (*core::ptr::addr_of_mut!(DRIVER_OBJECT_EXTENSIONS)).as_mut() else {
        return;
    };
    for slot in table.iter_mut() {
        if slot.used && slot.driver_object == driver_object {
            slot.driver_object = 0;
            slot.client_id = 0;
            slot.extension = 0;
            slot.used = false;
        }
    }
}

unsafe fn driver_registry_handles_mut() -> &'static mut Vec<DriverRegistryHandleSlot> {
    let slot = &mut *core::ptr::addr_of_mut!(DRIVER_REGISTRY_HANDLES);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn hosted_registry_identities_mut() -> &'static mut Vec<HostedRegistryIdentitySlot> {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_REGISTRY_IDENTITIES);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn hosted_registry_identities() -> Option<&'static Vec<HostedRegistryIdentitySlot>> {
    (*core::ptr::addr_of!(HOSTED_REGISTRY_IDENTITIES)).as_ref()
}

unsafe fn allocate_hosted_registry_identity(
    identity: HostedDriverRegistryIdentity,
) -> Result<HostedRegistryIdentityId, nt_status::NtStatus> {
    let table = hosted_registry_identities_mut();
    for (idx, slot) in table.iter_mut().enumerate() {
        if !slot.used {
            *slot = HostedRegistryIdentitySlot {
                identity,
                ref_count: 1,
                used: true,
            };
            return Ok(idx);
        }
    }
    let idx = table.len();
    table.push(HostedRegistryIdentitySlot {
        identity,
        ref_count: 1,
        used: true,
    });
    Ok(idx)
}

unsafe fn hosted_registry_identity(
    identity_id: HostedRegistryIdentityId,
) -> Option<HostedDriverRegistryIdentity> {
    if identity_id == INVALID_HOSTED_REGISTRY_IDENTITY_ID {
        return None;
    }
    let table = hosted_registry_identities()?;
    if identity_id < table.len() && table[identity_id].used {
        Some(table[identity_id].identity)
    } else {
        None
    }
}

unsafe fn release_hosted_registry_identity(identity_id: HostedRegistryIdentityId) {
    if identity_id == INVALID_HOSTED_REGISTRY_IDENTITY_ID {
        return;
    }
    let Some(table) = (*core::ptr::addr_of_mut!(HOSTED_REGISTRY_IDENTITIES)).as_mut() else {
        return;
    };
    if identity_id >= table.len() || !table[identity_id].used || table[identity_id].ref_count == 0 {
        return;
    }
    table[identity_id].ref_count -= 1;
    if table[identity_id].ref_count == 0 {
        table[identity_id] = EMPTY_HOSTED_REGISTRY_IDENTITY_SLOT;
    }
}

unsafe fn allocate_driver_registry_handle(
    kind: DriverRegistryHandleKind,
    identity: HostedDriverRegistryIdentity,
) -> Option<u64> {
    if !identity.used {
        return None;
    }
    let table = driver_registry_handles_mut();
    for (idx, slot) in table.iter_mut().enumerate() {
        if !slot.used {
            if idx as u64 > DRIVER_REGISTRY_HANDLE_INDEX_MASK {
                return None;
            }
            let handle = DRIVER_REGISTRY_HANDLE_BASE | idx as u64;
            *slot = DriverRegistryHandleSlot {
                handle,
                kind,
                identity,
                used: true,
            };
            return Some(handle);
        }
    }
    if table.len() as u64 > DRIVER_REGISTRY_HANDLE_INDEX_MASK {
        return None;
    }
    let idx = table.len();
    let handle = DRIVER_REGISTRY_HANDLE_BASE | idx as u64;
    table.push(DriverRegistryHandleSlot {
        handle,
        kind,
        identity,
        used: true,
    });
    Some(handle)
}

unsafe fn close_driver_registry_handle(handle: u64) -> bool {
    if (handle & !DRIVER_REGISTRY_HANDLE_INDEX_MASK) != DRIVER_REGISTRY_HANDLE_BASE {
        return false;
    }
    let idx = (handle & DRIVER_REGISTRY_HANDLE_INDEX_MASK) as usize;
    let Some(table) = (*core::ptr::addr_of_mut!(DRIVER_REGISTRY_HANDLES)).as_mut() else {
        return false;
    };
    if idx >= table.len() || !table[idx].used || table[idx].handle != handle {
        return false;
    }
    table[idx] = EMPTY_DRIVER_REGISTRY_HANDLE_SLOT;
    true
}

unsafe fn driver_registry_handle_slot(handle: u64) -> Option<DriverRegistryHandleSlot> {
    if (handle & !DRIVER_REGISTRY_HANDLE_INDEX_MASK) != DRIVER_REGISTRY_HANDLE_BASE {
        return None;
    }
    let idx = (handle & DRIVER_REGISTRY_HANDLE_INDEX_MASK) as usize;
    let table = (*core::ptr::addr_of!(DRIVER_REGISTRY_HANDLES)).as_ref()?;
    if idx < table.len() && table[idx].used && table[idx].handle == handle {
        Some(table[idx])
    } else {
        None
    }
}

unsafe fn driver_registry_handle_live(handle: u64) -> bool {
    driver_registry_handle_slot(handle).is_some()
}

/// `NTSTATUS IoOpenDeviceRegistryKey(PDEVICE_OBJECT, ULONG, ACCESS_MASK, PHANDLE)`.
extern "win64" fn s_io_open_device_registry_key(
    pdo: u64,
    _dev_inst_key_type: u32,
    _desired_access: u32,
    handle_out: u64,
) -> i32 {
    if handle_out == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if unsafe { !hosted_pdo_known(pdo) } {
        unsafe {
            write_unaligned(handle_out as *mut u64, 0);
        }
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let Some(identity) = hosted_registry_identity_by_pdo_object(pdo) else {
            write_unaligned(handle_out as *mut u64, 0);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if !identity.has_driver_key() {
            write_unaligned(handle_out as *mut u64, 0);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        let Some(handle) =
            allocate_driver_registry_handle(DriverRegistryHandleKind::DriverKey, identity)
        else {
            write_unaligned(handle_out as *mut u64, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        write_unaligned(handle_out as *mut u64, handle);
    }
    STATUS_SUCCESS
}

const DEVICE_PROPERTY_DRIVER_KEY_NAME: u32 = 0x7;
const DEVICE_PROPERTY_LEGACY_BUS_TYPE: u32 = 0xD;
const DEVICE_PROPERTY_BUS_NUMBER: u32 = 0xE;
const DEVICE_PROPERTY_ADDRESS: u32 = 0x10;
pub(crate) const HOSTED_INTERFACE_TYPE_INTERNAL: u32 = 0;
pub(crate) const HOSTED_INTERFACE_TYPE_PCIBUS: u32 = 5;
const BUS_DATA_TYPE_PCI_CONFIGURATION: u32 = 4;

#[derive(Clone, Copy)]
pub(crate) struct HostedBusIdentity {
    pub interface_type: u32,
    pub bus_number: u32,
    pub address: u32,
    pub pci_vendor_id: u16,
    pub pci_device_id: u16,
    pub pci_class: u32,
    pub pci_irq_line: u8,
    pub pci_irq_pin: u8,
}

impl HostedBusIdentity {
    pub(crate) const fn root_bus() -> Self {
        Self {
            interface_type: HOSTED_INTERFACE_TYPE_INTERNAL,
            bus_number: 0,
            address: 0,
            pci_vendor_id: 0,
            pci_device_id: 0,
            pci_class: 0,
            pci_irq_line: 0,
            pci_irq_pin: 0,
        }
    }

    pub(crate) const fn pci(
        bus: u8,
        dev: u8,
        func: u8,
        vendor: u16,
        device: u16,
        class: u32,
        irq_line: u8,
        irq_pin: u8,
    ) -> Self {
        Self {
            interface_type: HOSTED_INTERFACE_TYPE_PCIBUS,
            bus_number: bus as u32,
            address: ((dev as u32) << 16) | func as u32,
            pci_vendor_id: vendor,
            pci_device_id: device,
            pci_class: class,
            pci_irq_line: irq_line,
            pci_irq_pin: irq_pin,
        }
    }
}

unsafe fn write_u32_property(buffer_len: u32, buffer: u64, result_len: u64, value: u32) -> i32 {
    if result_len != 0 {
        write_unaligned(result_len as *mut u32, 4);
    }
    if buffer_len < 4 || buffer == 0 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    write_unaligned(buffer as *mut u32, value);
    STATUS_SUCCESS
}

unsafe fn hosted_resource_identity_active() -> bool {
    read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_LEN) as *const u64) != 0
        || read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32) != 0
        || read_volatile((FSD_SHARED_VADDR + SH_DMA_COMMON_LEN) as *const u64) != 0
        || read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_IO_PORT_LEN) as *const u64) != 0
}

unsafe fn hosted_pdo_known(pdo: u64) -> bool {
    pdo != 0
        && (hosted_device_binding_by_pdo_object(pdo).is_some()
            || read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64) == pdo)
}

unsafe fn hosted_registry_identity_by_pdo_object(pdo: u64) -> Option<HostedDriverRegistryIdentity> {
    if let Some(identity_id) = hosted_registry_identity_id_by_pdo_object(pdo) {
        if let Some(identity) = hosted_registry_identity(identity_id) {
            return Some(identity);
        }
    }
    let inflight_pdo = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
    if inflight_pdo == pdo {
        shared_registry_identity()
    } else {
        None
    }
}

unsafe fn hosted_registry_identity_id_by_pdo_object(pdo: u64) -> Option<HostedRegistryIdentityId> {
    if pdo == 0 {
        return None;
    }
    if let Some(binding) = hosted_device_binding_by_pdo_object(pdo) {
        if hosted_registry_identity(binding.registry_identity_id).is_some() {
            return Some(binding.registry_identity_id);
        }
    }
    let inflight_pdo = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
    let identity_id = read_volatile(core::ptr::addr_of!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID));
    if inflight_pdo == pdo && hosted_registry_identity(identity_id).is_some() {
        Some(identity_id)
    } else {
        None
    }
}

unsafe fn hosted_registry_identity_by_linkage_path<const N: usize>(
    path: &HostedAscii<N>,
) -> Option<HostedDriverRegistryIdentity> {
    if let Some(inflight) = shared_registry_identity() {
        if inflight.has_linkage_export()
            && hosted_linkage_path_matches(path, &inflight.driver_key_name)
        {
            return Some(inflight);
        }
    }
    let inflight_id = read_volatile(core::ptr::addr_of!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID));
    if let Some(inflight) = hosted_registry_identity(inflight_id) {
        if inflight.has_linkage_export()
            && hosted_linkage_path_matches(path, &inflight.driver_key_name)
        {
            return Some(inflight);
        }
    }
    if let Some(bindings) = hosted_device_bindings() {
        for binding in bindings.iter().copied() {
            if !binding.used {
                continue;
            }
            if let Some(identity) = hosted_registry_identity(binding.registry_identity_id) {
                if identity.has_linkage_export()
                    && hosted_linkage_path_matches(path, &identity.driver_key_name)
                {
                    return Some(identity);
                }
            }
        }
    }
    None
}

unsafe fn hosted_device_object_known(device_object: u64) -> bool {
    device_object != 0
        && (hosted_device_binding_by_device_object(device_object).is_some()
            || read_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *const u64) == device_object)
}

/// `NTSTATUS IoGetDeviceProperty(PDEVICE_OBJECT, DEVICE_REGISTRY_PROPERTY, ULONG, PVOID, PULONG)`.
extern "win64" fn s_io_get_device_property(
    pdo: u64,
    property: u32,
    buffer_len: u32,
    buffer: u64,
    result_len: u64,
) -> i32 {
    unsafe {
        if !hosted_pdo_known(pdo) {
            if result_len != 0 {
                write_unaligned(result_len as *mut u32, 0);
            }
            return STATUS_INVALID_PARAMETER;
        }
        if property == DEVICE_PROPERTY_DRIVER_KEY_NAME {
            let Some(identity) = hosted_registry_identity_by_pdo_object(pdo) else {
                if result_len != 0 {
                    write_unaligned(result_len as *mut u32, 0);
                }
                return STATUS_OBJECT_NAME_NOT_FOUND;
            };
            if !identity.has_driver_key() {
                if result_len != 0 {
                    write_unaligned(result_len as *mut u32, 0);
                }
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            return write_ascii_sz_property_utf16(
                buffer_len,
                buffer,
                result_len,
                &identity.driver_key_name,
            );
        }
        if !hosted_resource_identity_active() {
            if result_len != 0 {
                write_unaligned(result_len as *mut u32, 0);
            }
            return STATUS_NOT_SUPPORTED;
        }
        match property {
            DEVICE_PROPERTY_LEGACY_BUS_TYPE => {
                let value =
                    read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERFACE_TYPE) as *const u32);
                write_u32_property(buffer_len, buffer, result_len, value)
            }
            DEVICE_PROPERTY_BUS_NUMBER | DEVICE_PROPERTY_ADDRESS => {
                let value = if property == DEVICE_PROPERTY_BUS_NUMBER {
                    read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_BUS_NUMBER) as *const u32)
                } else {
                    read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_ADDRESS) as *const u32)
                };
                write_u32_property(buffer_len, buffer, result_len, value)
            }
            _ => STATUS_NOT_SUPPORTED,
        }
    }
}

fn build_hosted_interface_link(
    guid: &HostedAscii<HOSTED_DRIVER_KEY_NAME_MAX>,
    instance_path: &HostedAscii<HOSTED_INSTANCE_PATH_MAX>,
    reference: &HostedAscii<HOSTED_DRIVER_KEY_NAME_MAX>,
) -> Option<HostedAscii<HOSTED_INTERFACE_LINK_MAX>> {
    if guid.is_empty() || instance_path.is_empty() {
        return None;
    }
    let mut out = HostedAscii::<HOSTED_INTERFACE_LINK_MAX>::empty();
    if !out.push_str("\\??\\") || !out.push_str(guid.as_str()) || !out.push_byte(b'#') {
        return None;
    }
    let mut i = 0usize;
    while i < instance_path.len {
        let b = if instance_path.bytes[i] == b'\\' {
            b'#'
        } else {
            instance_path.bytes[i]
        };
        if !out.push_byte(b) {
            return None;
        }
        i += 1;
    }
    if !reference.is_empty() {
        if !out.push_byte(b'#') || !out.push_str(reference.as_str()) {
            return None;
        }
    }
    Some(out)
}

unsafe fn shared_device_name_ascii() -> Option<HostedAscii<HOSTED_EXPORT_NAME_MAX>> {
    let len = read_volatile((FSD_SHARED_VADDR + SH_DEVICE_NAME_LEN) as *const u16) as usize;
    if len == 0 || len > HOSTED_EXPORT_NAME_MAX * 2 || (len & 1) != 0 {
        return None;
    }
    let mut out = HostedAscii::<HOSTED_EXPORT_NAME_MAX>::empty();
    let chars = len / 2;
    let mut i = 0usize;
    while i < chars {
        let lo =
            read_volatile((FSD_SHARED_VADDR + SH_DEVICE_NAME_BUF + (i * 2) as u64) as *const u8);
        let hi = read_volatile(
            (FSD_SHARED_VADDR + SH_DEVICE_NAME_BUF + (i * 2 + 1) as u64) as *const u8,
        );
        if hi != 0 || lo == 0 || lo > 0x7f || !out.push_byte(lo) {
            return None;
        }
        i += 1;
    }
    Some(out)
}

unsafe fn hosted_device_interface_registrations_mut(
) -> &'static mut Vec<HostedDeviceInterfaceRegistration> {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_DEVICE_INTERFACE_REGISTRATIONS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn upsert_hosted_device_interface(
    symbolic_link: HostedAscii<HOSTED_INTERFACE_LINK_MAX>,
    target: HostedAscii<HOSTED_EXPORT_NAME_MAX>,
) -> Result<(), nt_status::NtStatus> {
    let table = hosted_device_interface_registrations_mut();
    for slot in table.iter_mut() {
        if slot.used && hosted_ascii_eq_ignore_case(&slot.symbolic_link, &symbolic_link) {
            slot.target = target;
            return Ok(());
        }
    }
    for slot in table.iter_mut() {
        if !slot.used {
            *slot = HostedDeviceInterfaceRegistration {
                symbolic_link,
                target,
                enabled: false,
                used: true,
            };
            return Ok(());
        }
    }
    table.push(HostedDeviceInterfaceRegistration {
        symbolic_link,
        target,
        enabled: false,
        used: true,
    });
    Ok(())
}

unsafe fn clear_hosted_device_interface<const N: usize>(symbolic_link: &HostedAscii<N>) {
    let Some(table) = (*core::ptr::addr_of_mut!(HOSTED_DEVICE_INTERFACE_REGISTRATIONS)).as_mut()
    else {
        return;
    };
    for slot in table.iter_mut() {
        if slot.used && hosted_ascii_eq_ignore_case(&slot.symbolic_link, symbolic_link) {
            *slot = EMPTY_HOSTED_DEVICE_INTERFACE_REGISTRATION;
            return;
        }
    }
}

/// `NTSTATUS IoRegisterDeviceInterface(...)`.
extern "win64" fn s_io_register_device_interface(
    pdo: u64,
    class_guid: u64,
    reference_string: u64,
    symbolic_link_name: u64,
) -> i32 {
    if symbolic_link_name == 0 || class_guid == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        write_unaligned(
            (symbolic_link_name + UNICODE_STRING_LENGTH_OFFSET) as *mut u16,
            0,
        );
        write_unaligned(
            (symbolic_link_name + UNICODE_STRING_MAXIMUM_LENGTH_OFFSET) as *mut u16,
            0,
        );
        write_unaligned(
            (symbolic_link_name + UNICODE_STRING_BUFFER_OFFSET) as *mut u64,
            0,
        );

        if !hosted_pdo_known(pdo) {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(identity) = hosted_registry_identity_by_pdo_object(pdo) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let Some(guid) = guid_to_hosted_ascii(class_guid) else {
            return STATUS_INVALID_PARAMETER;
        };
        let reference = if reference_string == 0 {
            HostedAscii::<HOSTED_DRIVER_KEY_NAME_MAX>::empty()
        } else {
            let Some(reference) = unicode_string_to_hosted_ascii::<HOSTED_DRIVER_KEY_NAME_MAX>(
                reference_string,
                true,
            ) else {
                return STATUS_INVALID_PARAMETER;
            };
            reference
        };
        let Some(symbolic_link) =
            build_hosted_interface_link(&guid, &identity.instance_path, &reference)
        else {
            return STATUS_INVALID_PARAMETER;
        };
        let target = shared_device_name_ascii().unwrap_or(identity.export_name);
        if target.is_empty() {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if let Err(status) = upsert_hosted_device_interface(symbolic_link, target) {
            return status.raw();
        }
        let status = write_allocated_unicode_string_from_ascii(symbolic_link_name, &symbolic_link);
        if status < 0 {
            clear_hosted_device_interface(&symbolic_link);
        }
        status
    }
}

extern "win64" fn s_io_set_device_interface_state(symbolic_link_name: u64, enable: u8) -> i32 {
    unsafe {
        clear_shared_device_interface_state_at(FSD_SHARED_VADDR);
        let Some((link_buf, link_len)) = unicode_string_parts(symbolic_link_name) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(symbolic_link) =
            unicode_string_to_hosted_ascii::<HOSTED_INTERFACE_LINK_MAX>(symbolic_link_name, false)
        else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(table) =
            (*core::ptr::addr_of_mut!(HOSTED_DEVICE_INTERFACE_REGISTRATIONS)).as_mut()
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let Some(slot) = table.iter_mut().find(|slot| {
            slot.used && hosted_ascii_eq_ignore_case(&slot.symbolic_link, &symbolic_link)
        }) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if (enable != 0) == slot.enabled {
            return STATUS_SUCCESS;
        }
        copy_wstr_to_shared(
            link_buf,
            link_len,
            SH_DEVICE_INTERFACE_LINK_LEN,
            SH_DEVICE_INTERFACE_LINK_BUF,
        );
        if enable != 0 {
            let status = copy_ascii_to_shared_utf16(
                &slot.target,
                SH_DEVICE_INTERFACE_TARGET_LEN,
                SH_DEVICE_INTERFACE_TARGET_BUF,
            );
            if status < 0 {
                clear_shared_device_interface_state_at(FSD_SHARED_VADDR);
                return status;
            }
            write_volatile(
                (FSD_SHARED_VADDR + SH_DEVICE_INTERFACE_STATE) as *mut u32,
                1,
            );
            slot.enabled = true;
        } else {
            write_volatile(
                (FSD_SHARED_VADDR + SH_DEVICE_INTERFACE_STATE) as *mut u32,
                0,
            );
            slot.enabled = false;
        }
        STATUS_SUCCESS
    }
}

extern "win64" fn s_io_register_shutdown_notification(device: u64) -> i32 {
    unsafe {
        if hosted_device_object_known(device) {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_PARAMETER
        }
    }
}

extern "win64" fn s_io_unregister_shutdown_notification(_device: u64) {}

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
const WDM_X64_IRP_PENDING_RETURNED_OFFSET: u64 = 0x41;
const WDM_X64_IRP_CANCEL_OFFSET: u64 = 0x44;
const WDM_X64_IRP_CANCEL_IRQL_OFFSET: u64 = 0x45;
const WDM_X64_IRP_CANCEL_ROUTINE_OFFSET: u64 = 0x68;
const WDM_X64_IRP_DRIVER_CONTEXT3_OFFSET: u64 = 0x90;
const WDM_X64_IO_STACK_MINOR_OFFSET: u64 = 0x01;
const WDM_X64_IO_STACK_CONTROL_OFFSET: u64 = 0x03;
const WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET: u64 = 0x28;
const WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET: u64 = 0x38;
const WDM_X64_IO_STACK_CONTEXT_OFFSET: u64 = 0x40;
const WDM_X64_SL_INVOKE_ON_SUCCESS: u8 = 0x40;
const WDM_X64_SL_INVOKE_ON_ERROR: u8 = 0x80;

const WDM_X64_IO_TYPE_IRP: u16 = 6;
const IO_TYPE_CSQ_IRP_CONTEXT: u32 = 1;
const IO_TYPE_CSQ: u32 = 2;
const IO_CSQ_SIZE: u64 = 64;
const IO_CSQ_INSERT_IRP_OFFSET: u64 = 0x08;
const IO_CSQ_REMOVE_IRP_OFFSET: u64 = 0x10;
const IO_CSQ_PEEK_NEXT_IRP_OFFSET: u64 = 0x18;
const IO_CSQ_ACQUIRE_LOCK_OFFSET: u64 = 0x20;
const IO_CSQ_RELEASE_LOCK_OFFSET: u64 = 0x28;
const IO_CSQ_COMPLETE_CANCELED_IRP_OFFSET: u64 = 0x30;
const IO_CSQ_RESERVE_POINTER_OFFSET: u64 = 0x38;
const IO_CSQ_IRP_CONTEXT_TYPE_OFFSET: u64 = 0x00;
const IO_CSQ_IRP_CONTEXT_IRP_OFFSET: u64 = 0x08;
const IO_CSQ_IRP_CONTEXT_CSQ_OFFSET: u64 = 0x10;

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

/// `PDRIVER_CANCEL IoSetCancelRoutine(PIRP, PDRIVER_CANCEL)`.
extern "win64" fn s_io_set_cancel_routine(irp: u64, cancel_routine: u64) -> u64 {
    if irp == 0 {
        return 0;
    }
    unsafe {
        let slot = (irp + WDM_X64_IRP_CANCEL_ROUTINE_OFFSET) as *mut u64;
        let old = read_unaligned(slot as *const u64);
        write_unaligned(slot, cancel_routine);
        old
    }
}

/// `PIRP IoAllocateIrp(CCHAR StackSize, BOOLEAN ChargeQuota)`.
extern "win64" fn s_io_allocate_irp(stack_size: u8, _charge_quota: u8) -> u64 {
    let stack_count = stack_size as u64;
    if stack_count == 0 || stack_count > 32 {
        return 0;
    }
    let total = WDM_X64_IRP_SIZE as u64 + stack_count * WDM_X64_IO_STACK_LOCATION_SIZE as u64;
    unsafe {
        let irp = pool_alloc(total);
        if irp == 0 {
            return 0;
        }
        core::ptr::write_bytes(irp as *mut u8, 0, total as usize);
        let stack_base = irp + WDM_X64_IRP_SIZE as u64;
        write_unaligned(irp as *mut u16, WDM_X64_IO_TYPE_IRP);
        write_unaligned((irp + 2) as *mut u16, WDM_X64_IRP_SIZE as u16);
        write_unaligned(
            (irp + WDM_X64_IRP_STACK_COUNT_OFFSET) as *mut u8,
            stack_size,
        );
        write_unaligned(
            (irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *mut u8,
            stack_size.saturating_add(1),
        );
        write_unaligned(
            (irp + 0xb8) as *mut u64,
            stack_base + stack_count * WDM_X64_IO_STACK_LOCATION_SIZE as u64,
        );
        irp
    }
}

/// `VOID IoFreeIrp(PIRP)`.
extern "win64" fn s_io_free_irp(irp: u64) {
    unsafe {
        pool_free(irp);
    }
}

/// `PIO_WORKITEM IoAllocateWorkItem(PDEVICE_OBJECT)`.
extern "win64" fn s_io_allocate_work_item(device_object: u64) -> u64 {
    unsafe {
        let work_item = pool_alloc(0x40);
        if work_item == 0 {
            return 0;
        }
        core::ptr::write_bytes(work_item as *mut u8, 0, 0x40);
        write_unaligned((work_item + 0x20) as *mut u64, device_object);
        work_item
    }
}

/// `VOID IoQueueWorkItem(PIO_WORKITEM, PIO_WORKITEM_ROUTINE, WORK_QUEUE_TYPE, PVOID)`.
extern "win64" fn s_io_queue_work_item(
    work_item: u64,
    worker_routine: u64,
    _queue_type: u32,
    context: u64,
) {
    if work_item == 0 || worker_routine == 0 {
        return;
    }
    unsafe {
        let device_object = read_unaligned((work_item + 0x20) as *const u64);
        write_unaligned((work_item + 0x28) as *mut u64, worker_routine);
        write_unaligned((work_item + 0x30) as *mut u64, context);
        let f: extern "win64" fn(u64, u64) = core::mem::transmute(worker_routine as *const ());
        f(device_object, context);
    }
}

/// `VOID IoFreeWorkItem(PIO_WORKITEM)`.
extern "win64" fn s_io_free_work_item(work_item: u64) {
    unsafe {
        pool_free(work_item);
    }
}

/// `VOID IoReleaseCancelSpinLock(KIRQL)`.
extern "win64" fn s_io_release_cancel_spin_lock(_old_irql: u8) {}

unsafe fn csq_acquire(csq: u64) -> u8 {
    let acquire = read_unaligned((csq + IO_CSQ_ACQUIRE_LOCK_OFFSET) as *const u64);
    let mut irql = 0u8;
    if acquire != 0 {
        let f: extern "win64" fn(u64, u64) = core::mem::transmute(acquire as *const ());
        f(csq, (&mut irql as *mut u8) as u64);
    }
    irql
}

unsafe fn csq_release(csq: u64, irql: u8) {
    let release = read_unaligned((csq + IO_CSQ_RELEASE_LOCK_OFFSET) as *const u64);
    if release != 0 {
        let f: extern "win64" fn(u64, u8) = core::mem::transmute(release as *const ());
        f(csq, irql);
    }
}

unsafe fn csq_clear_irp_context(irp: u64) {
    if irp == 0 {
        return;
    }
    let context = read_unaligned((irp + WDM_X64_IRP_DRIVER_CONTEXT3_OFFSET) as *const u64);
    if context != 0
        && read_unaligned((context + IO_CSQ_IRP_CONTEXT_TYPE_OFFSET) as *const u32)
            == IO_TYPE_CSQ_IRP_CONTEXT
    {
        write_unaligned((context + IO_CSQ_IRP_CONTEXT_IRP_OFFSET) as *mut u64, 0);
    }
    write_unaligned((irp + WDM_X64_IRP_DRIVER_CONTEXT3_OFFSET) as *mut u64, 0);
}

/// `NTSTATUS IoCsqInitialize(PIO_CSQ, callbacks...)`.
extern "win64" fn s_io_csq_initialize(
    csq: u64,
    insert: u64,
    remove: u64,
    peek: u64,
    acquire: u64,
    release: u64,
    complete_canceled: u64,
) -> i32 {
    if csq == 0 || insert == 0 || remove == 0 || peek == 0 || acquire == 0 || release == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        core::ptr::write_bytes(csq as *mut u8, 0, IO_CSQ_SIZE as usize);
        write_unaligned(csq as *mut u32, IO_TYPE_CSQ);
        write_unaligned((csq + IO_CSQ_INSERT_IRP_OFFSET) as *mut u64, insert);
        write_unaligned((csq + IO_CSQ_REMOVE_IRP_OFFSET) as *mut u64, remove);
        write_unaligned((csq + IO_CSQ_PEEK_NEXT_IRP_OFFSET) as *mut u64, peek);
        write_unaligned((csq + IO_CSQ_ACQUIRE_LOCK_OFFSET) as *mut u64, acquire);
        write_unaligned((csq + IO_CSQ_RELEASE_LOCK_OFFSET) as *mut u64, release);
        write_unaligned(
            (csq + IO_CSQ_COMPLETE_CANCELED_IRP_OFFSET) as *mut u64,
            complete_canceled,
        );
        write_unaligned((csq + IO_CSQ_RESERVE_POINTER_OFFSET) as *mut u64, 0);
    }
    STATUS_SUCCESS
}

/// `VOID IoCsqInsertIrp(PIO_CSQ, PIRP, PIO_CSQ_IRP_CONTEXT)`.
extern "win64" fn s_io_csq_insert_irp(csq: u64, irp: u64, context: u64) {
    if csq == 0 || irp == 0 {
        return;
    }
    unsafe {
        if context != 0 {
            write_unaligned(
                (context + IO_CSQ_IRP_CONTEXT_TYPE_OFFSET) as *mut u32,
                IO_TYPE_CSQ_IRP_CONTEXT,
            );
            write_unaligned((context + IO_CSQ_IRP_CONTEXT_IRP_OFFSET) as *mut u64, irp);
            write_unaligned((context + IO_CSQ_IRP_CONTEXT_CSQ_OFFSET) as *mut u64, csq);
            write_unaligned(
                (irp + WDM_X64_IRP_DRIVER_CONTEXT3_OFFSET) as *mut u64,
                context,
            );
        } else {
            write_unaligned((irp + WDM_X64_IRP_DRIVER_CONTEXT3_OFFSET) as *mut u64, csq);
        }
        write_unaligned((irp + WDM_X64_IRP_PENDING_RETURNED_OFFSET) as *mut u8, 1);
        let insert = read_unaligned((csq + IO_CSQ_INSERT_IRP_OFFSET) as *const u64);
        if insert == 0 {
            return;
        }
        let irql = csq_acquire(csq);
        let f: extern "win64" fn(u64, u64) = core::mem::transmute(insert as *const ());
        f(csq, irp);
        csq_release(csq, irql);
    }
}

/// `PIRP IoCsqRemoveIrp(PIO_CSQ, PIO_CSQ_IRP_CONTEXT)`.
extern "win64" fn s_io_csq_remove_irp(csq: u64, context: u64) -> u64 {
    if csq == 0 || context == 0 {
        return 0;
    }
    unsafe {
        let irp = read_unaligned((context + IO_CSQ_IRP_CONTEXT_IRP_OFFSET) as *const u64);
        if irp == 0 {
            return 0;
        }
        let remove = read_unaligned((csq + IO_CSQ_REMOVE_IRP_OFFSET) as *const u64);
        if remove == 0 {
            return 0;
        }
        let irql = csq_acquire(csq);
        let f: extern "win64" fn(u64, u64) = core::mem::transmute(remove as *const ());
        f(csq, irp);
        csq_clear_irp_context(irp);
        csq_release(csq, irql);
        irp
    }
}

/// `PIRP IoCsqRemoveNextIrp(PIO_CSQ, PVOID PeekContext)`.
extern "win64" fn s_io_csq_remove_next_irp(csq: u64, peek_context: u64) -> u64 {
    if csq == 0 {
        return 0;
    }
    unsafe {
        let peek = read_unaligned((csq + IO_CSQ_PEEK_NEXT_IRP_OFFSET) as *const u64);
        let remove = read_unaligned((csq + IO_CSQ_REMOVE_IRP_OFFSET) as *const u64);
        if peek == 0 || remove == 0 {
            return 0;
        }
        let irql = csq_acquire(csq);
        let peek_fn: extern "win64" fn(u64, u64, u64) -> u64 =
            core::mem::transmute(peek as *const ());
        let irp = peek_fn(csq, 0, peek_context);
        if irp != 0 {
            let remove_fn: extern "win64" fn(u64, u64) = core::mem::transmute(remove as *const ());
            remove_fn(csq, irp);
            csq_clear_irp_context(irp);
        }
        csq_release(csq, irql);
        irp
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
            write_unaligned(
                (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32,
                status,
            );
            if next != 0 {
                complete_forwarded_stack_location(irp, next, status);
            }
        }
        status
    }
}

unsafe fn complete_forwarded_stack_location(irp: u64, stack: u64, status: i32) {
    let completion =
        read_unaligned((stack + WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET) as *const u64);
    if completion == 0 {
        return;
    }
    let control = read_unaligned((stack + WDM_X64_IO_STACK_CONTROL_OFFSET) as *const u8);
    let invoke = if status >= 0 {
        (control & WDM_X64_SL_INVOKE_ON_SUCCESS) != 0
    } else {
        (control & WDM_X64_SL_INVOKE_ON_ERROR) != 0
    };
    if !invoke {
        return;
    }

    let current_location = read_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *const u8);
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
        write_unaligned((mdl + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, length);
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

/// `VOID IoBuildPartialMdl(PMDL SourceMdl, PMDL TargetMdl, PVOID VirtualAddress, ULONG Length)`.
extern "win64" fn s_io_build_partial_mdl(
    source_mdl: u64,
    target_mdl: u64,
    virtual_address: u64,
    length: u32,
) {
    if source_mdl == 0 || target_mdl == 0 {
        return;
    }
    unsafe {
        let source_start = read_unaligned((source_mdl + nt_mdl::MDL_OFF_START_VA) as *const u64);
        let source_offset =
            read_unaligned((source_mdl + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32);
        let source_len = read_unaligned((source_mdl + nt_mdl::MDL_OFF_BYTE_COUNT) as *const u32);
        let va = if virtual_address != 0 {
            virtual_address
        } else {
            source_start + source_offset as u64
        };
        let len = if length != 0 { length } else { source_len };
        write_unaligned((target_mdl + nt_mdl::MDL_OFF_NEXT) as *mut u64, 0);
        write_unaligned(
            (target_mdl + nt_mdl::MDL_OFF_SIZE) as *mut i16,
            nt_mdl::MDL_SIZE as i16,
        );
        write_unaligned(
            (target_mdl + nt_mdl::MDL_OFF_FLAGS) as *mut i16,
            nt_mdl::MDL_MAPPED_TO_SYSTEM_VA,
        );
        write_unaligned(
            (target_mdl + nt_mdl::MDL_OFF_START_VA) as *mut u64,
            va & !0xFFF,
        );
        write_unaligned((target_mdl + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, len);
        write_unaligned(
            (target_mdl + nt_mdl::MDL_OFF_BYTE_OFFSET) as *mut u32,
            (va & 0xFFF) as u32,
        );
        write_unaligned(
            (target_mdl + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64,
            va,
        );
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

/// `PVOID MmMapLockedPages(PMDL, KPROCESSOR_MODE)`.
extern "win64" fn s_mm_map_locked_pages(mdl: u64, access_mode: u8) -> u64 {
    s_mm_map_locked_pages_specify_cache(mdl, access_mode, 0, 0, 0, 0)
}

/// `PVOID MmAllocateContiguousMemorySpecifyCache(...)`.
extern "win64" fn s_mm_allocate_contiguous_memory_specify_cache(
    number_of_bytes: u64,
    _lowest: u64,
    _highest: u64,
    _boundary: u64,
    _cache_type: u32,
) -> u64 {
    unsafe { pool_alloc(number_of_bytes) }
}

extern "win64" fn s_mm_free_contiguous_memory_specify_cache(
    base: u64,
    _number_of_bytes: u64,
    _cache_type: u32,
) {
    unsafe {
        pool_free(base);
    }
}

extern "win64" fn s_mm_allocate_non_cached_memory(number_of_bytes: u64) -> u64 {
    unsafe { pool_alloc(number_of_bytes) }
}

extern "win64" fn s_mm_free_non_cached_memory(base: u64, _number_of_bytes: u64) {
    unsafe {
        pool_free(base);
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
            write_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ID) as *mut u64, 0);
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

const HOSTED_DMA_COMMON_ALIGNMENT: u64 = 0x1000;

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    value
        .checked_add(alignment - 1)
        .map(|aligned| aligned & !(alignment - 1))
}

unsafe fn dma_allocation_record(sh: u64, index: u64) -> Option<u64> {
    if index >= dma_allocation_record_capacity(sh) {
        return None;
    }
    let offset = SH_DMA_ALLOC_RECORDS.checked_add(index.checked_mul(SH_DMA_ALLOC_RECORD_SIZE)?)?;
    if offset.checked_add(SH_DMA_ALLOC_RECORD_SIZE)? > SH_DMA_ALLOC_RECORD_LIMIT {
        return None;
    }
    Some(sh + offset)
}

const fn dma_allocation_record_arena_capacity() -> u64 {
    (SH_DMA_ALLOC_RECORD_LIMIT - SH_DMA_ALLOC_RECORDS) / SH_DMA_ALLOC_RECORD_SIZE
}

unsafe fn dma_allocation_record_capacity(sh: u64) -> u64 {
    let capacity = read_volatile((sh + SH_DMA_ALLOC_RECORD_CAPACITY) as *const u64);
    if capacity == dma_allocation_record_arena_capacity() {
        capacity
    } else {
        0
    }
}

unsafe fn clear_dma_allocation_records(sh: u64) {
    write_volatile((sh + SH_DMA_ALLOC_CURSOR) as *mut u64, 0);
    write_volatile((sh + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64, 0);
    write_volatile(
        (sh + SH_DMA_ALLOC_RECORD_CAPACITY) as *mut u64,
        dma_allocation_record_arena_capacity(),
    );
    let mut i = 0u64;
    while i < dma_allocation_record_arena_capacity() {
        if let Some(record) = dma_allocation_record(sh, i) {
            write_volatile(record as *mut u64, 0);
            write_volatile((record + 8) as *mut u64, 0);
            write_volatile((record + 16) as *mut u64, 0);
        }
        i += 1;
    }
}

unsafe fn dma_allocation_range_overlaps(
    sh: u64,
    grant_logical: u64,
    offset: u64,
    length: u64,
) -> Option<u64> {
    let end = offset.checked_add(length)?;
    let mut i = 0u64;
    let capacity = dma_allocation_record_capacity(sh);
    while i < capacity {
        let record = dma_allocation_record(sh, i)?;
        let logical = read_volatile(record as *const u64);
        let record_len = read_volatile((record + 8) as *const u64);
        if logical != 0 && record_len != 0 {
            let record_offset = logical.checked_sub(grant_logical)?;
            let record_end = record_offset.checked_add(record_len)?;
            if offset < record_end && record_offset < end {
                return Some(record_end);
            }
        }
        i += 1;
    }
    None
}

unsafe fn first_free_dma_allocation_record(sh: u64) -> Option<u64> {
    let mut i = 0u64;
    let capacity = dma_allocation_record_capacity(sh);
    while i < capacity {
        let record = dma_allocation_record(sh, i)?;
        if read_volatile((record + 8) as *const u64) == 0 {
            return Some(record);
        }
        i += 1;
    }
    None
}

/// `AllocateCommonBuffer` — allocate a bounded slice from the PnP-granted DMA common-buffer window.
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
        let requested = length as u64;
        if adapter == 0
            || adapter != active
            || grant_va == 0
            || grant_len == 0
            || grant_logical == 0
            || requested == 0
            || requested > grant_len
        {
            return 0;
        }

        let Some(record) = first_free_dma_allocation_record(FSD_SHARED_VADDR) else {
            return 0;
        };
        let mut offset = 0u64;
        loop {
            let Some(aligned) = align_up(offset, HOSTED_DMA_COMMON_ALIGNMENT) else {
                return 0;
            };
            let Some(end) = aligned.checked_add(requested) else {
                return 0;
            };
            if end > grant_len {
                return 0;
            }
            if let Some(next_offset) =
                dma_allocation_range_overlaps(FSD_SHARED_VADDR, grant_logical, aligned, requested)
            {
                offset = next_offset;
                continue;
            }
            offset = aligned;
            break;
        }

        let va = grant_va + offset;
        let logical = grant_logical + offset;
        core::ptr::write_bytes(va as *mut u8, 0, requested as usize);
        write_volatile(record as *mut u64, logical);
        write_volatile((record + 8) as *mut u64, requested);
        write_volatile((record + 16) as *mut u64, va);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DMA_REQUESTED_LEN) as *mut u64,
            requested,
        );
        write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_VA) as *mut u64, va);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DMA_ALLOCATED_LOGICAL) as *mut u64,
            logical,
        );
        let count = read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *const u64);
        let used = ((record - FSD_SHARED_VADDR - SH_DMA_ALLOC_RECORDS) / SH_DMA_ALLOC_RECORD_SIZE)
            .saturating_add(1);
        if used > count {
            write_volatile(
                (FSD_SHARED_VADDR + SH_DMA_ALLOC_RECORD_COUNT) as *mut u64,
                used,
            );
        }
        let cursor = read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_CURSOR) as *const u64);
        let end = offset + requested;
        if end > cursor {
            write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOC_CURSOR) as *mut u64, end);
        }
        if !logical_out.is_null() {
            write_unaligned(logical_out, logical as i64);
        }
        va
    }
}

/// `FreeCommonBuffer` — release the matching common-buffer allocation record.
extern "win64" fn s_dma_free_common_buffer(
    _adapter: u64,
    length: u32,
    logical: i64,
    virtual_address: u64,
    _cache_enabled: u8,
) {
    unsafe {
        let logical = logical as u64;
        let mut i = 0u64;
        let capacity = dma_allocation_record_capacity(FSD_SHARED_VADDR);
        while i < capacity {
            if let Some(record) = dma_allocation_record(FSD_SHARED_VADDR, i) {
                let active_logical = read_volatile(record as *const u64);
                let active_len = read_volatile((record + 8) as *const u64);
                let active_va = read_volatile((record + 16) as *const u64);
                if active_logical != 0
                    && logical == active_logical
                    && virtual_address == active_va
                    && length as u64 == active_len
                {
                    write_volatile(
                        (FSD_SHARED_VADDR + SH_DMA_FREED_LOGICAL) as *mut u64,
                        active_logical,
                    );
                    write_volatile(record as *mut u64, 0);
                    write_volatile((record + 8) as *mut u64, 0);
                    write_volatile((record + 16) as *mut u64, 0);
                    if read_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_LOGICAL) as *const u64)
                        == active_logical
                    {
                        write_volatile(
                            (FSD_SHARED_VADDR + SH_DMA_ALLOCATED_LOGICAL) as *mut u64,
                            0,
                        );
                        write_volatile((FSD_SHARED_VADDR + SH_DMA_ALLOCATED_VA) as *mut u64, 0);
                        write_volatile((FSD_SHARED_VADDR + SH_DMA_REQUESTED_LEN) as *mut u64, 0);
                    }
                    return;
                }
            }
            i += 1;
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
        let active_seq = FSD_ACTIVE_DISPATCH_SEQ.load(Ordering::Relaxed);
        if active_seq >= 128 && FSD_ACTIVE_COMPLETE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 16
        {
            print_str(b"[fsd-complete-active] seq=");
            print_u64(active_seq);
            print_str(b" irp=");
            print_hex64(irp);
            if irp >= FSD_POOL_VADDR + POOL_DATA_OFF
                && irp + WDM_X64_IRP_SIZE as u64 <= FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000
            {
                print_str(b" status=");
                print_hex(read_unaligned(
                    (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *const u32,
                ));
                print_str(b" info=");
                print_u64(read_unaligned((irp + 0x38) as *const u64));
            }
            print_str(b"\n");
        }
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
        let Some(slot) = take_pending_irp(irp) else {
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
        if slot.read_completion {
            let fid = slot.fid;
            // The buffer npfs actually filled = the IRP's CURRENT SystemBuffer (it may have reassigned
            // it). Fall back to our original buffer only if npfs left it in place.
            let sysbuf = read_unaligned((irp + 0x18) as *const u64);
            let irp_flags = read_unaligned((irp + 0x10) as *const u32);
            let length = (information as usize).min(COMPLETED_READ_BYTE_CAP);
            let source = if sysbuf != 0 { sysbuf } else { slot.data };
            let pool_end = FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
            let source_valid = source >= FSD_POOL_VADDR + POOL_DATA_OFF
                && source
                    .checked_add(length as u64)
                    .is_some_and(|end| end <= pool_end);
            let _ = insert_completed_read(
                fid,
                if source_valid { status } else { 0xC000_0005 },
                if source_valid { information } else { 0 },
                source,
                if source_valid { length } else { 0 },
            );
            // IoCompleteRequest normally owns a replacement SystemBuffer carrying
            // IRP_DEALLOCATE_BUFFER. Reclaim it while the component pool is mapped.
            if sysbuf != slot.data && irp_flags & 0x20 != 0 {
                pool_free(sysbuf);
            }
        } else if slot.major as u64 == IRP_MJ_WRITE {
            let _ = insert_completed_write(slot.fid, status, information);
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

/// `BOOLEAN RtlDeleteElementGenericTable(PRTL_GENERIC_TABLE, PVOID)`.
extern "win64" fn s_rtl_delete_element_generic_table(_tbl: u64, _buffer: u64) -> u8 {
    0
}

/// `VOID RtlRemoveUnicodePrefix(PUNICODE_PREFIX_TABLE, PUNICODE_PREFIX_TABLE_ENTRY)`.
extern "win64" fn s_rtl_remove_unicode_prefix(_tbl: u64, entry: u64) {
    if entry == 0 {
        return;
    }
    unsafe {
        let table = &mut *core::ptr::addr_of_mut!(PREFIX_TABLE);
        for slot in table.iter_mut() {
            if slot.used && slot.entry == entry {
                *slot = PrefixSlot {
                    entry: 0,
                    name_va: 0,
                    name_len: 0,
                    used: false,
                };
                return;
            }
        }
    }
}

const RTL_QUERY_REGISTRY_TABLE_SIZE: u64 = 56;
const RTL_QUERY_REGISTRY_SUBKEY: u32 = 0x0000_0001;
const RTL_QUERY_REGISTRY_REQUIRED: u32 = 0x0000_0004;
const RTL_QUERY_REGISTRY_NOVALUE: u32 = 0x0000_0008;
const RTL_QUERY_REGISTRY_DIRECT: u32 = 0x0000_0020;
const REG_NONE: u32 = 0;
const REG_SZ: u32 = 1;
const KEY_VALUE_PARTIAL_INFORMATION_CLASS: u32 = 2;

/// `NTSTATUS RtlQueryRegistryValues(...)` for hosted FSD service parameters.
///
/// The FSD host does not keep a private registry mirror. Current ReactOS FSD callers use this during
/// initialization for optional service parameters and defaults, so the explicit hosted behavior is:
/// apply caller-provided defaults, report missing required values, and enumerate empty optional keys.
extern "win64" fn s_rtl_query_registry_values(
    _relative_to: u32,
    path: u64,
    query_table: u64,
    context: u64,
    _environment: u64,
) -> i32 {
    if query_table == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let registry_path = wide_cstr_to_hosted_ascii::<HOSTED_REGISTRY_PATH_MAX>(path);
        let mut idx = 0u64;
        while idx < 64 {
            let entry = query_table + idx * RTL_QUERY_REGISTRY_TABLE_SIZE;
            let routine = read_unaligned(entry as *const u64);
            let flags = read_unaligned((entry + 8) as *const u32);
            let name = read_unaligned((entry + 16) as *const u64);
            let entry_context = read_unaligned((entry + 24) as *const u64);
            let default_type = read_unaligned((entry + 32) as *const u32);
            let default_data = read_unaligned((entry + 40) as *const u64);
            let default_length = read_unaligned((entry + 48) as *const u32);

            if routine == 0
                && (flags & (RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_DIRECT)) == 0
            {
                break;
            }

            if (flags & RTL_QUERY_REGISTRY_DIRECT) != 0 {
                if name == 0 || routine != 0 || (flags & RTL_QUERY_REGISTRY_SUBKEY) != 0 {
                    return STATUS_INVALID_PARAMETER;
                }
                let linkage_export = registry_path
                    .as_ref()
                    .and_then(|registry_path| {
                        hosted_registry_identity_by_linkage_path(registry_path)
                    })
                    .filter(|identity| {
                        wide_cstr_to_hosted_ascii::<HOSTED_DRIVER_KEY_NAME_MAX>(name)
                            .as_ref()
                            .is_some_and(|value_name| {
                                hosted_ascii_eq_ignore_case_str(value_name, "Export")
                            })
                            && identity.has_linkage_export()
                    });
                if let Some(identity) = linkage_export {
                    if entry_context == 0 {
                        return STATUS_INVALID_PARAMETER;
                    }
                    let status = write_allocated_unicode_string_from_ascii(
                        entry_context,
                        &identity.export_name,
                    );
                    if status < 0 {
                        return status;
                    }
                } else if entry_context != 0 && default_data != 0 && default_length != 0 {
                    let copy_len = (default_length as u64).min(4096);
                    copy_bytes_unchecked(entry_context, default_data, copy_len);
                } else if (flags & RTL_QUERY_REGISTRY_REQUIRED) != 0 {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
                idx += 1;
                continue;
            }

            if (flags & RTL_QUERY_REGISTRY_SUBKEY) != 0 {
                if name == 0 {
                    return STATUS_INVALID_PARAMETER;
                }
                if routine == 0 {
                    idx += 1;
                    continue;
                }
            }

            if (flags & RTL_QUERY_REGISTRY_NOVALUE) != 0 && routine != 0 {
                let f: extern "win64" fn(u64, u32, u64, u32, u64, u64) -> i32 =
                    core::mem::transmute(routine as *const ());
                let status = f(0, REG_NONE, 0, 0, context, entry_context);
                if status < 0 {
                    return status;
                }
                idx += 1;
                continue;
            }

            if routine != 0 && name != 0 {
                let f: extern "win64" fn(u64, u32, u64, u32, u64, u64) -> i32 =
                    core::mem::transmute(routine as *const ());
                let status = if default_data != 0 || default_length != 0 {
                    f(
                        name,
                        default_type,
                        default_data,
                        default_length,
                        context,
                        entry_context,
                    )
                } else {
                    f(name, REG_NONE, 0, 0, context, entry_context)
                };
                if status < 0 {
                    return status;
                }
            } else if routine != 0 && (flags & RTL_QUERY_REGISTRY_REQUIRED) != 0 {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            idx += 1;
        }
    }
    STATUS_SUCCESS
}

unsafe fn list_insert_between(entry: u64, prev: u64, next: u64) {
    write_unaligned(entry as *mut u64, next);
    write_unaligned((entry + 8) as *mut u64, prev);
    write_unaligned((prev) as *mut u64, entry);
    write_unaligned((next + 8) as *mut u64, entry);
}

/// `PLIST_ENTRY ExInterlockedInsertTailList(PLIST_ENTRY Head, PLIST_ENTRY Entry, PKSPIN_LOCK)`.
extern "win64" fn s_ex_interlocked_insert_tail_list(head: u64, entry: u64, _lock: u64) -> u64 {
    if head == 0 || entry == 0 {
        return 0;
    }
    unsafe {
        let old_tail = read_unaligned((head + 8) as *const u64);
        let tail = if old_tail == 0 { head } else { old_tail };
        list_insert_between(entry, tail, head);
        old_tail
    }
}

/// `PLIST_ENTRY ExInterlockedInsertHeadList(PLIST_ENTRY Head, PLIST_ENTRY Entry, PKSPIN_LOCK)`.
extern "win64" fn s_ex_interlocked_insert_head_list(head: u64, entry: u64, _lock: u64) -> u64 {
    if head == 0 || entry == 0 {
        return 0;
    }
    unsafe {
        let old_head = read_unaligned(head as *const u64);
        let first = if old_head == 0 { head } else { old_head };
        list_insert_between(entry, head, first);
        old_head
    }
}

/// `PLIST_ENTRY ExInterlockedRemoveHeadList(PLIST_ENTRY Head, PKSPIN_LOCK)`.
extern "win64" fn s_ex_interlocked_remove_head_list(head: u64, _lock: u64) -> u64 {
    if head == 0 {
        return 0;
    }
    unsafe {
        let first = read_unaligned(head as *const u64);
        if first == 0 || first == head {
            return 0;
        }
        let next = read_unaligned(first as *const u64);
        write_unaligned(head as *mut u64, next);
        write_unaligned((next + 8) as *mut u64, head);
        write_unaligned(first as *mut u64, first);
        write_unaligned((first + 8) as *mut u64, first);
        first
    }
}

/// `LARGE_INTEGER ExInterlockedAddLargeInteger(PLARGE_INTEGER, LARGE_INTEGER, PKSPIN_LOCK)`.
extern "win64" fn s_ex_interlocked_add_large_integer(
    addend: u64,
    increment: i64,
    _lock: u64,
) -> i64 {
    unsafe {
        if addend == 0 {
            return 0;
        }
        let old = read_unaligned(addend as *const i64);
        write_unaligned(addend as *mut i64, old.wrapping_add(increment));
        old
    }
}

/// `ULONG ExInterlockedAddUlong(PULONG, ULONG, PKSPIN_LOCK)`.
extern "win64" fn s_ex_interlocked_add_ulong(addend: u64, increment: u32, _lock: u64) -> u32 {
    unsafe {
        if addend == 0 {
            return 0;
        }
        let old = read_unaligned(addend as *const u32);
        write_unaligned(addend as *mut u32, old.wrapping_add(increment));
        old
    }
}

/// `PSLIST_ENTRY ExpInterlockedPushEntrySList(PSLIST_HEADER, PSLIST_ENTRY)`.
extern "win64" fn s_exp_interlocked_push_entry_slist(head: u64, entry: u64) -> u64 {
    if head == 0 || entry == 0 {
        return 0;
    }
    unsafe {
        let old = read_unaligned(head as *const u64);
        write_unaligned(entry as *mut u64, old);
        write_unaligned(head as *mut u64, entry);
        old
    }
}

/// `PSLIST_ENTRY ExpInterlockedPopEntrySList(PSLIST_HEADER)`.
extern "win64" fn s_exp_interlocked_pop_entry_slist(head: u64) -> u64 {
    if head == 0 {
        return 0;
    }
    unsafe {
        let old = read_unaligned(head as *const u64);
        if old != 0 {
            let next = read_unaligned(old as *const u64);
            write_unaligned(head as *mut u64, next);
            write_unaligned(old as *mut u64, 0);
        }
        old
    }
}

/// `VOID ExQueueWorkItem(PWORK_QUEUE_ITEM, WORK_QUEUE_TYPE)`.
extern "win64" fn s_ex_queue_work_item(work_item: u64, _queue_type: u32) {
    if work_item == 0 {
        return;
    }
    unsafe {
        let routine = read_unaligned((work_item + 0x10) as *const u64);
        let parameter = read_unaligned((work_item + 0x18) as *const u64);
        if routine != 0 {
            let f: extern "win64" fn(u64) = core::mem::transmute(routine as *const ());
            f(parameter);
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

#[inline]
unsafe fn hosted_current_irql() -> u8 {
    read_volatile((FSD_SHARED_VADDR + SH_HOSTED_CURRENT_IRQL) as *const u8)
}

#[inline]
unsafe fn hosted_set_current_irql(irql: u8) {
    write_volatile((FSD_SHARED_VADDR + SH_HOSTED_CURRENT_IRQL) as *mut u8, irql);
}

#[inline]
unsafe fn hosted_raise_irql(irql: u8) -> u8 {
    let old = hosted_current_irql();
    if irql > old {
        hosted_set_current_irql(irql);
    }
    old
}

#[inline]
unsafe fn hosted_lower_irql(irql: u8) {
    hosted_set_current_irql(irql);
}

/// `KIRQL KeGetCurrentIrql()`.
extern "win64" fn s_ke_get_current_irql() -> u8 {
    unsafe { hosted_current_irql() }
}

/// `KIRQL KeAcquireSpinLockRaiseToDpc(PKSPIN_LOCK)` — single-threaded hosted drivers never spin, but
/// the lock's driver-visible storage records ownership until release.
extern "win64" fn s_ke_acquire_spin_lock_raise_to_dpc(lock: u64) -> u8 {
    unsafe {
        let old_irql = hosted_raise_irql(DISPATCH_LEVEL);
        if lock != 0 {
            write_unaligned(lock as *mut u64, 1);
        }
        old_irql
    }
}

/// `void KeReleaseSpinLock(PKSPIN_LOCK, KIRQL)`.
extern "win64" fn s_ke_release_spin_lock(lock: u64, old_irql: u8) {
    unsafe {
        if lock != 0 {
            write_unaligned(lock as *mut u64, 0);
        }
        hosted_lower_irql(old_irql);
    }
}

/// `VOID KeAcquireSpinLockAtDpcLevel(PKSPIN_LOCK)`.
extern "win64" fn s_ke_acquire_spin_lock_at_dpc_level(lock: u64) {
    unsafe {
        if lock != 0 {
            write_unaligned(lock as *mut u64, 1);
        }
    }
}

/// `VOID KeReleaseSpinLockFromDpcLevel(PKSPIN_LOCK)`.
extern "win64" fn s_ke_release_spin_lock_from_dpc_level(lock: u64) {
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

unsafe fn dpc_queue_capacity(sh: u64) -> u64 {
    let capacity = read_volatile((sh + SH_DPC_QUEUE_CAPACITY) as *const u64);
    if capacity == 0 || capacity > SH_DPC_QUEUE_DERIVED_CAPACITY {
        0
    } else {
        capacity
    }
}

#[inline]
fn dpc_queue_slot(sh: u64, index: u64, capacity: u64) -> u64 {
    sh + SH_DPC_QUEUE_BASE + (index % capacity) * SH_DPC_QUEUE_ENTRY_SIZE
}

unsafe fn clear_dpc_queue_projection(sh: u64) {
    write_volatile((sh + SH_DPC_QUEUE_HEAD) as *mut u64, 0);
    write_volatile((sh + SH_DPC_QUEUE_TAIL) as *mut u64, 0);
    write_volatile((sh + SH_DPC_QUEUE_DROPS) as *mut u64, 0);
    write_volatile((sh + SH_DPC_DELIVERIES) as *mut u64, 0);
    write_volatile(
        (sh + SH_DPC_QUEUE_CAPACITY) as *mut u64,
        SH_DPC_QUEUE_DERIVED_CAPACITY,
    );
    let mut slot = 0u64;
    while slot < SH_DPC_QUEUE_DERIVED_CAPACITY {
        write_volatile(
            (sh + SH_DPC_QUEUE_BASE + slot * SH_DPC_QUEUE_ENTRY_SIZE) as *mut u64,
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
        let capacity = dpc_queue_capacity(FSD_SHARED_VADDR);
        if capacity == 0 {
            let drops = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_DROPS) as *const u64);
            write_volatile(
                (FSD_SHARED_VADDR + SH_DPC_QUEUE_DROPS) as *mut u64,
                drops.saturating_add(1),
            );
            return 0;
        }
        let head = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_HEAD) as *const u64);
        let tail = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_TAIL) as *const u64);
        if tail.saturating_sub(head) >= capacity {
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
        let slot = dpc_queue_slot(FSD_SHARED_VADDR, tail, capacity);
        write_volatile(slot as *mut u64, dpc);
        write_volatile(
            (FSD_SHARED_VADDR + SH_DPC_QUEUE_TAIL) as *mut u64,
            tail.saturating_add(1),
        );
    }
    1
}

/// `ULONG KeQueryTimeIncrement()`.
extern "win64" fn s_ke_query_time_increment() -> u32 {
    156_250
}

/// `ULONG KeGetRecommendedSharedDataAlignment()`.
extern "win64" fn s_ke_get_recommended_shared_data_alignment() -> u32 {
    64
}

/// `BOOLEAN KeRegisterBugCheckCallback(...)`.
extern "win64" fn s_ke_register_bug_check_callback(
    record: u64,
    callback: u64,
    buffer: u64,
    length: u32,
    component: u64,
) -> u8 {
    if record == 0 || callback == 0 {
        return 0;
    }
    unsafe {
        write_unaligned(record as *mut u64, callback);
        write_unaligned((record + 8) as *mut u64, buffer);
        write_unaligned((record + 16) as *mut u32, length);
        write_unaligned((record + 24) as *mut u64, component);
    }
    1
}

/// `BOOLEAN KeDeregisterBugCheckCallback(PKBUGCHECK_CALLBACK_RECORD)`.
extern "win64" fn s_ke_deregister_bug_check_callback(record: u64) -> u8 {
    if record != 0 {
        unsafe {
            write_unaligned(record as *mut u64, 0);
        }
    }
    1
}

/// `BOOLEAN KeSynchronizeExecution(PKINTERRUPT, PKSYNCHRONIZE_ROUTINE, PVOID)`.
extern "win64" fn s_ke_synchronize_execution(_interrupt: u64, routine: u64, context: u64) -> u8 {
    if routine == 0 {
        return 0;
    }
    unsafe {
        let f: extern "win64" fn(u64) -> u8 = core::mem::transmute(routine as *const ());
        f(context)
    }
}

unsafe fn fsd_drain_queued_dpcs() -> u64 {
    let capacity = dpc_queue_capacity(FSD_SHARED_VADDR);
    if capacity == 0 {
        return 0;
    }
    let mut inspected = 0u64;
    let mut delivered = 0u64;
    while inspected < capacity {
        let head = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_HEAD) as *const u64);
        let tail = read_volatile((FSD_SHARED_VADDR + SH_DPC_QUEUE_TAIL) as *const u64);
        if head == tail {
            break;
        }
        let slot = dpc_queue_slot(FSD_SHARED_VADDR, head, capacity);
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
        let f: extern "win64" fn(u64, u64, u64, u64) = core::mem::transmute(routine as *const ());
        let old_irql = hosted_raise_irql(DISPATCH_LEVEL);
        f(dpc, context, arg1, arg2);
        hosted_lower_irql(old_irql);
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

/// `BOOLEAN SeAccessCheck(...)` — the hosted FSD security boundary is the executive/object-manager
/// handle path; inside the isolated FSD, grant the already-authorized desired access explicitly.
extern "win64" fn s_se_access_check(
    _security_descriptor: u64,
    _subject_context: u64,
    _subject_context_locked: u8,
    desired_access: u32,
    previously_granted_access: u32,
    privileges: u64,
    _generic_mapping: u64,
    _access_mode: u8,
    granted_access: u64,
    access_status: u64,
) -> u8 {
    unsafe {
        if privileges != 0 {
            write_unaligned(privileges as *mut u64, 0);
        }
        if granted_access != 0 {
            write_unaligned(
                granted_access as *mut u32,
                desired_access | previously_granted_access,
            );
        }
        if access_status != 0 {
            write_unaligned(access_status as *mut i32, STATUS_SUCCESS);
        }
    }
    1
}

extern "win64" fn s_se_lock_subject_context(_subject_context: u64) {}

extern "win64" fn s_se_unlock_subject_context(_subject_context: u64) {}

extern "win64" fn s_se_open_object_audit_alarm(
    _object_type_name: u64,
    _object: u64,
    _absolute_object_name: u64,
    _security_descriptor: u64,
    _access_state: u64,
    _object_created: u8,
    _access_granted: u8,
    _access_mode: u8,
    generate_on_close: u64,
) {
    unsafe {
        if generate_on_close != 0 {
            write_unaligned(generate_on_close as *mut u8, 0);
        }
    }
}

extern "win64" fn s_se_append_privileges(_access_state: u64, _privileges: u64) -> i32 {
    STATUS_SUCCESS
}

extern "win64" fn s_se_free_privileges(_privileges: u64) {}

/// `TOKEN_TYPE SeTokenType(PACCESS_TOKEN)`; TokenPrimary is 1 in NT5.
extern "win64" fn s_se_token_type(_token: u64) -> u32 {
    1
}

extern "win64" fn s_se_create_client_security(
    _client_thread: u64,
    _client_security_qos: u64,
    _remote_session: u8,
    client_context: u64,
) -> i32 {
    unsafe {
        if client_context != 0 {
            core::ptr::write_bytes(client_context as *mut u8, 0, 0x40);
        }
    }
    STATUS_SUCCESS
}

extern "win64" fn s_se_impersonate_client_ex(_client_context: u64, _server_thread: u64) -> i32 {
    STATUS_SUCCESS
}

extern "win64" fn s_se_query_security_descriptor_info(
    _security_information: u64,
    _security_descriptor: u64,
    length: u64,
    _objects_security_descriptor: u64,
) -> i32 {
    unsafe {
        if length != 0 {
            write_unaligned(length as *mut u32, 0);
        }
    }
    STATUS_SUCCESS
}

extern "win64" fn s_se_set_security_descriptor_info(
    _object: u64,
    _security_information: u64,
    security_descriptor: u64,
    objects_security_descriptor: u64,
    _pool_type: u32,
    _generic_mapping: u64,
) -> i32 {
    unsafe {
        if objects_security_descriptor != 0 {
            write_unaligned(objects_security_descriptor as *mut u64, security_descriptor);
        }
    }
    STATUS_SUCCESS
}

extern "win64" fn s_ob_dereference_security_descriptor(_security_descriptor: u64) {}

extern "win64" fn s_obf_reference_object(object: u64) -> u64 {
    object
}

extern "win64" fn s_obf_dereference_object(_object: u64) -> u64 {
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

/// `NTSTATUS ZwClose(HANDLE)`.
extern "win64" fn s_zw_close(handle: u64) -> i32 {
    unsafe {
        if close_driver_registry_handle(handle) {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_HANDLE
        }
    }
}

unsafe fn write_key_value_partial_sz<const N: usize>(
    value: &HostedAscii<N>,
    key_value_information: u64,
    length: u32,
    result_length: u64,
) -> i32 {
    let data_len = (value.len.saturating_add(1)).saturating_mul(2);
    let need = 12usize.saturating_add(data_len);
    if result_length != 0 {
        write_unaligned(result_length as *mut u32, need as u32);
    }
    if need > u32::MAX as usize || key_value_information == 0 || length < need as u32 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    write_unaligned(key_value_information as *mut u32, 0);
    write_unaligned((key_value_information + 4) as *mut u32, REG_SZ);
    write_unaligned((key_value_information + 8) as *mut u32, data_len as u32);
    let data = key_value_information + 12;
    let mut i = 0usize;
    while i < value.len {
        write_unaligned((data + (i as u64) * 2) as *mut u16, value.bytes[i] as u16);
        i += 1;
    }
    write_unaligned((data + (value.len as u64) * 2) as *mut u16, 0);
    STATUS_SUCCESS
}

/// `NTSTATUS ZwOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)`.
extern "win64" fn s_zw_open_key(
    handle_out: u64,
    _desired_access: u32,
    object_attributes: u64,
) -> i32 {
    if handle_out != 0 {
        unsafe {
            write_unaligned(handle_out as *mut u64, 0);
        }
    }
    if handle_out == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let Some((root, name)) =
            object_attributes_root_and_name::<HOSTED_REGISTRY_PATH_MAX>(object_attributes)
        else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(root_slot) = driver_registry_handle_slot(root) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let kind = if name.is_empty() {
            root_slot.kind
        } else if root_slot.kind == DriverRegistryHandleKind::DriverKey
            && hosted_ascii_eq_ignore_case_str(&name, "Linkage")
        {
            DriverRegistryHandleKind::LinkageKey
        } else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let Some(handle) = allocate_driver_registry_handle(kind, root_slot.identity) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        write_unaligned(handle_out as *mut u64, handle);
    }
    STATUS_SUCCESS
}

/// `NTSTATUS ZwEnumerateKey(...)`.
extern "win64" fn s_zw_enumerate_key(
    handle: u64,
    _index: u32,
    _key_information_class: u32,
    _key_information: u64,
    _length: u32,
    result_length: u64,
) -> i32 {
    unsafe {
        if !driver_registry_handle_live(handle) {
            return STATUS_INVALID_HANDLE;
        }
        if result_length != 0 {
            write_unaligned(result_length as *mut u32, 0);
        }
    }
    STATUS_NO_MORE_ENTRIES
}

/// `NTSTATUS ZwQueryValueKey(...)` against a hosted driver registry handle.
extern "win64" fn s_zw_query_value_key(
    handle: u64,
    value_name: u64,
    key_value_information_class: u32,
    key_value_information: u64,
    length: u32,
    result_length: u64,
) -> i32 {
    unsafe {
        let Some(slot) = driver_registry_handle_slot(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let value_name =
            match unicode_string_to_hosted_ascii::<HOSTED_DRIVER_KEY_NAME_MAX>(value_name, false) {
                Some(value_name) => value_name,
                None => return STATUS_INVALID_PARAMETER,
            };
        if slot.kind == DriverRegistryHandleKind::LinkageKey
            && key_value_information_class == KEY_VALUE_PARTIAL_INFORMATION_CLASS
            && hosted_ascii_eq_ignore_case_str(&value_name, "Export")
        {
            if slot.identity.has_linkage_export() {
                return write_key_value_partial_sz(
                    &slot.identity.export_name,
                    key_value_information,
                    length,
                    result_length,
                );
            }
        }
        if result_length != 0 {
            write_unaligned(result_length as *mut u32, 0);
        }
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// `NTSTATUS ZwSetValueKey(...)`.
extern "win64" fn s_zw_set_value_key(
    handle: u64,
    _value_name: u64,
    _title_index: u32,
    _typ: u32,
    _data: u64,
    _data_size: u32,
) -> i32 {
    unsafe {
        if !driver_registry_handle_live(handle) {
            return STATUS_INVALID_HANDLE;
        }
    }
    STATUS_NOT_SUPPORTED
}

extern "win64" fn s_zw_create_file(
    file_handle_out: u64,
    _desired_access: u32,
    _object_attributes: u64,
    _io_status_block: u64,
    _allocation_size: u64,
    _file_attributes: u32,
    _share_access: u32,
    _create_disposition: u32,
    _create_options: u32,
    _ea_buffer: u64,
    _ea_length: u32,
) -> i32 {
    if file_handle_out != 0 {
        unsafe {
            write_unaligned(file_handle_out as *mut u64, 0);
        }
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

extern "win64" fn s_zw_query_information_file(
    _file_handle: u64,
    io_status_block: u64,
    _file_information: u64,
    _length: u32,
    _file_information_class: u32,
) -> i32 {
    if io_status_block != 0 {
        unsafe {
            write_unaligned(io_status_block as *mut i32, STATUS_OBJECT_NAME_NOT_FOUND);
            write_unaligned((io_status_block + 8) as *mut u64, 0);
        }
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

extern "win64" fn s_zw_read_file(
    _file_handle: u64,
    _event: u64,
    _apc_routine: u64,
    _apc_context: u64,
    io_status_block: u64,
    _buffer: u64,
    _length: u32,
    _byte_offset: u64,
    _key: u64,
) -> i32 {
    if io_status_block != 0 {
        unsafe {
            write_unaligned(io_status_block as *mut i32, STATUS_OBJECT_NAME_NOT_FOUND);
            write_unaligned((io_status_block + 8) as *mut u64, 0);
        }
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

extern "win64" fn s_ex_get_current_processor_counts(idle: u64, kernel: u64, user: u64) {
    unsafe {
        if idle != 0 {
            write_unaligned(idle as *mut u32, 0);
        }
        if kernel != 0 {
            write_unaligned(kernel as *mut u32, 0);
        }
        if user != 0 {
            write_unaligned(user as *mut u32, 0);
        }
    }
}

extern "win64" fn s_ex_get_current_processor_cpu_usage(_processor: u32) -> u32 {
    0
}

extern "win64" fn s_hal_translate_bus_address(
    interface_type: u32,
    bus_number: u32,
    bus_address: u64,
    address_space: u64,
    translated_address: u64,
) -> u8 {
    unsafe {
        if !hosted_resource_identity_active()
            || interface_type
                != read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERFACE_TYPE) as *const u32)
            || bus_number
                != read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_BUS_NUMBER) as *const u32)
        {
            return 0;
        }
        let grant_phys = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_PHYS) as *const u64);
        let grant_len = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_LEN) as *const u64);
        let requested_space = if address_space != 0 {
            read_unaligned(address_space as *const u32)
        } else {
            0
        };
        if requested_space != 0 {
            let port_base =
                read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_IO_PORT_BASE) as *const u64);
            let port_len =
                read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_IO_PORT_LEN) as *const u64);
            if port_base == 0
                || port_len == 0
                || bus_address < port_base
                || bus_address >= port_base.saturating_add(port_len)
            {
                return 0;
            }
            if address_space != 0 {
                write_unaligned(address_space as *mut u32, 1);
            }
            if translated_address != 0 {
                write_unaligned(translated_address as *mut u64, bus_address);
            }
            return 1;
        }
        if grant_phys == 0
            || grant_len == 0
            || bus_address < grant_phys
            || bus_address >= grant_phys.saturating_add(grant_len)
        {
            return 0;
        }
        if address_space != 0 {
            write_unaligned(address_space as *mut u32, 0);
        }
        if translated_address != 0 {
            write_unaligned(translated_address as *mut u64, bus_address);
        }
    }
    1
}

extern "win64" fn s_hal_get_interrupt_vector(
    interface_type: u32,
    bus_number: u32,
    _bus_interrupt_level: u32,
    bus_interrupt_vector: u32,
    irql_out: u64,
    affinity_out: u64,
) -> u32 {
    unsafe {
        if !hosted_resource_identity_active()
            || interface_type
                != read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERFACE_TYPE) as *const u32)
            || bus_number
                != read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_BUS_NUMBER) as *const u32)
        {
            return 0;
        }
        let granted_vector =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32);
        if granted_vector == 0
            || (bus_interrupt_vector != 0 && bus_interrupt_vector != granted_vector)
        {
            return 0;
        }
        if irql_out != 0 {
            write_unaligned(irql_out as *mut u8, granted_vector.min(0xF) as u8);
        }
        if affinity_out != 0 {
            let affinity =
                read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_AFFINITY) as *const u64);
            write_unaligned(
                affinity_out as *mut u64,
                if affinity == 0 { 1 } else { affinity },
            );
        }
        granted_vector
    }
}

unsafe fn hosted_pci_device_function() -> (u32, u32, u32) {
    let address = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_ADDRESS) as *const u32);
    let dev = (address >> 16) & 0x1F;
    let func = address & 0x7;
    (address, dev, func)
}

unsafe fn hosted_pci_slot_number_matches(slot_number: u32) -> bool {
    let (address, dev, func) = hosted_pci_device_function();
    let nt_slot_number = dev | (func << 5);
    let legacy_devfn_slot_number = (dev << 3) | func;
    slot_number == nt_slot_number
        || slot_number == legacy_devfn_slot_number
        || slot_number == address
        || (func == 0 && slot_number == dev)
}

unsafe fn hosted_pci_config_byte(offset: u32) -> u8 {
    let vendor_device =
        read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_PCI_VENDOR_DEVICE) as *const u32);
    let class_rev = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_PCI_CLASS_REV) as *const u32);
    let grant_phys = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_MMIO_PHYS) as *const u64) as u32;
    let port_base =
        read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_IO_PORT_BASE) as *const u64) as u32;
    let port_len = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_IO_PORT_LEN) as *const u64);
    let pci_irq = read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_PCI_IRQ) as *const u32);
    let value = match offset {
        0x00..=0x03 => vendor_device,
        0x04..=0x07 => {
            if port_len != 0 {
                0x0000_0007 // COMMAND: I/O space + memory space + bus master enabled.
            } else {
                0x0000_0006 // COMMAND: memory space + bus master enabled, STATUS clear.
            }
        }
        0x08..=0x0B => class_rev,
        0x10..=0x13 => grant_phys & 0xFFFF_FFF0,
        0x14..=0x17 if port_len != 0 => (port_base & 0xFFFF_FFFC) | 1,
        0x2C..=0x2F => 0,
        0x3C..=0x3F => pci_irq,
        _ => 0,
    };
    ((value >> ((offset & 3) * 8)) & 0xFF) as u8
}

extern "win64" fn s_hal_get_bus_data_by_offset(
    bus_data_type: u32,
    bus_number: u32,
    slot_number: u32,
    buffer: u64,
    offset: u32,
    length: u32,
) -> u32 {
    if buffer == 0 || length == 0 {
        return 0;
    }
    unsafe {
        if bus_data_type != BUS_DATA_TYPE_PCI_CONFIGURATION
            || !hosted_resource_identity_active()
            || read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERFACE_TYPE) as *const u32)
                != HOSTED_INTERFACE_TYPE_PCIBUS
            || bus_number
                != read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_BUS_NUMBER) as *const u32)
            || !hosted_pci_slot_number_matches(slot_number)
        {
            return 0;
        }
        let mut copied = 0u32;
        while copied < length && offset.saturating_add(copied) < 0x100 {
            let b = hosted_pci_config_byte(offset + copied);
            write_unaligned((buffer + copied as u64) as *mut u8, b);
            copied += 1;
        }
        copied
    }
}

extern "win64" fn s_hal_get_bus_data(
    bus_data_type: u32,
    bus_number: u32,
    slot_number: u32,
    buffer: u64,
    length: u32,
) -> u32 {
    s_hal_get_bus_data_by_offset(bus_data_type, bus_number, slot_number, buffer, 0, length)
}

extern "win64" fn s_hal_set_bus_data_by_offset(
    _bus_data_type: u32,
    _bus_number: u32,
    _slot_number: u32,
    _buffer: u64,
    _offset: u32,
    _length: u32,
) -> u32 {
    0
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

const HOSTED_DEP_PROVIDER_MAX: usize = 64;
const HOSTED_DEP_PATH_MAX: usize = 96;
const HOSTED_DRIVER_DEP_PATH_PREFIX: &[u8] = b"reactos\\system32\\drivers\\";
const MAX_RAW_IMPORT_DESCRIPTORS: u32 = 256;
const MAX_LOADED_EXPORT_NAMES: u32 = 1024;

#[derive(Clone, Copy)]
struct LoadedDependencyImage {
    present: bool,
    exec_va: u64,
    run_va: u64,
    image_len: u32,
}

impl LoadedDependencyImage {
    const fn empty() -> LoadedDependencyImage {
        LoadedDependencyImage {
            present: false,
            exec_va: 0,
            run_va: 0,
            image_len: 0,
        }
    }
}

static mut NDIS_DEP_IMAGE: LoadedDependencyImage = LoadedDependencyImage::empty();

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
    reg.bind(
        "RtlFreeUnicodeString",
        s_rtl_free_unicode_string as usize as u64,
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
        "RtlUpcaseUnicodeString",
        s_rtl_upcase_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlAppendUnicodeStringToString",
        s_rtl_append_unicode_string_to_string as usize as u64,
    );
    reg.bind(
        "RtlAppendUnicodeToString",
        s_rtl_append_unicode_to_string as usize as u64,
    );
    reg.bind(
        "RtlIntegerToUnicodeString",
        s_rtl_integer_to_unicode_string as usize as u64,
    );
    reg.bind(
        "RtlUnicodeStringToInteger",
        s_rtl_unicode_string_to_integer as usize as u64,
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
        "RtlEqualUnicodeString",
        s_rtl_equal_unicode_string as usize as u64,
    );
    reg.bind("RtlInitAnsiString", s_rtl_init_ansi_string as usize as u64);
    reg.bind("RtlInitString", s_rtl_init_ansi_string as usize as u64);
    reg.bind(
        "RtlQueryRegistryValues",
        s_rtl_query_registry_values as usize as u64,
    );
    // Io device/registration (control DEVICE_OBJECT + FS registration)
    reg.bind("IoCreateDevice", s_io_create_device as usize as u64);
    reg.bind(
        "IoDeleteDevice",
        s_io_delete_device as *const () as usize as u64,
    );
    reg.bind(
        "IoAllocateDriverObjectExtension",
        s_io_allocate_driver_object_extension as *const () as usize as u64,
    );
    reg.bind(
        "IoGetDriverObjectExtension",
        s_io_get_driver_object_extension as *const () as usize as u64,
    );
    reg.bind(
        "IoOpenDeviceRegistryKey",
        s_io_open_device_registry_key as *const () as usize as u64,
    );
    reg.bind(
        "IoGetDeviceProperty",
        s_io_get_device_property as *const () as usize as u64,
    );
    reg.bind(
        "IoRegisterDeviceInterface",
        s_io_register_device_interface as *const () as usize as u64,
    );
    reg.bind(
        "IoSetDeviceInterfaceState",
        s_io_set_device_interface_state as *const () as usize as u64,
    );
    reg.bind(
        "IoRegisterShutdownNotification",
        s_io_register_shutdown_notification as *const () as usize as u64,
    );
    reg.bind(
        "IoUnregisterShutdownNotification",
        s_io_unregister_shutdown_notification as *const () as usize as u64,
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
        "IoSetCancelRoutine",
        s_io_set_cancel_routine as *const () as usize as u64,
    );
    reg.bind(
        "IoAllocateIrp",
        s_io_allocate_irp as *const () as usize as u64,
    );
    reg.bind("IoFreeIrp", s_io_free_irp as *const () as usize as u64);
    reg.bind(
        "IoReleaseCancelSpinLock",
        s_io_release_cancel_spin_lock as *const () as usize as u64,
    );
    reg.bind(
        "IoCsqInitialize",
        s_io_csq_initialize as *const () as usize as u64,
    );
    reg.bind(
        "IoCsqInsertIrp",
        s_io_csq_insert_irp as *const () as usize as u64,
    );
    reg.bind(
        "IoCsqRemoveIrp",
        s_io_csq_remove_irp as *const () as usize as u64,
    );
    reg.bind(
        "IoCsqRemoveNextIrp",
        s_io_csq_remove_next_irp as *const () as usize as u64,
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
        "IoAllocateWorkItem",
        s_io_allocate_work_item as *const () as usize as u64,
    );
    reg.bind(
        "IoQueueWorkItem",
        s_io_queue_work_item as *const () as usize as u64,
    );
    reg.bind(
        "IoFreeWorkItem",
        s_io_free_work_item as *const () as usize as u64,
    );
    reg.bind(
        "IoAllocateMdl",
        s_io_allocate_mdl as *const () as usize as u64,
    );
    reg.bind(
        "IoBuildPartialMdl",
        s_io_build_partial_mdl as *const () as usize as u64,
    );
    reg.bind("IoFreeMdl", s_io_free_mdl as *const () as usize as u64);
    reg.bind(
        "MmBuildMdlForNonPagedPool",
        s_mm_build_mdl_for_nonpaged_pool as *const () as usize as u64,
    );
    reg.bind(
        "MmMapLockedPages",
        s_mm_map_locked_pages as *const () as usize as u64,
    );
    reg.bind(
        "MmMapLockedPagesSpecifyCache",
        s_mm_map_locked_pages_specify_cache as *const () as usize as u64,
    );
    reg.bind(
        "MmAllocateContiguousMemorySpecifyCache",
        s_mm_allocate_contiguous_memory_specify_cache as *const () as usize as u64,
    );
    reg.bind(
        "MmFreeContiguousMemorySpecifyCache",
        s_mm_free_contiguous_memory_specify_cache as *const () as usize as u64,
    );
    reg.bind(
        "MmAllocateNonCachedMemory",
        s_mm_allocate_non_cached_memory as *const () as usize as u64,
    );
    reg.bind(
        "MmFreeNonCachedMemory",
        s_mm_free_non_cached_memory as *const () as usize as u64,
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
    // import used to resolve to a generic success no-op: when a peer WRITE satisfied a pending pipe READ,
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
        "RtlRemoveUnicodePrefix",
        s_rtl_remove_unicode_prefix as usize as u64,
    );
    reg.bind(
        "RtlInitializeGenericTable",
        s_rtl_init_generic_table as usize as u64,
    );
    reg.bind(
        "RtlDeleteElementGenericTable",
        s_rtl_delete_element_generic_table as usize as u64,
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
    reg.bind("ExDeleteResourceLite", s_zero as usize as u64);
    // The driver's OWN consistency bugchecks (npfs' `NpBugCheck`) — caught + reported + unwound,
    // never skipped. Previously an unresolved import resolved to a generic success no-op.
    if crate::KEBUGCHECK_BOUND {
        reg.bind("KeBugCheckEx", s_ke_bug_check_ex as usize as u64);
    }
    reg.bind("__C_specific_handler", s_c_specific_handler as usize as u64);
    // CRT / Rtl mem intrinsics (REAL — silent corruption otherwise)
    reg.bind("memcpy", s_memcpy as usize as u64);
    reg.bind("memmove", s_memmove as usize as u64);
    reg.bind("RtlCopyMemory", s_memcpy as usize as u64);
    reg.bind("RtlMoveMemory", s_memmove as usize as u64);
    reg.bind("memset", s_memset as usize as u64);
    reg.bind("RtlFillMemory", s_memset as usize as u64);
    reg.bind("RtlCompareMemory", s_rtl_compare_memory as usize as u64);
    reg.bind("wcslen", s_wcslen as usize as u64);
    reg.bind("wcsncmp", s_wcsncmp as usize as u64);
    reg.bind("wcsncpy", s_wcsncpy as usize as u64);
    reg.bind("wcscat", s_wcscat as usize as u64);
    reg.bind("wcscpy", s_wcscpy as usize as u64);
    reg.bind("wcsncat", s_wcsncat as usize as u64);
    reg.bind(
        "RtlCompareMemoryUlong",
        s_rtl_compare_memory as usize as u64,
    );
    reg.bind("RtlCompareString", s_rtl_compare_string as usize as u64);
    reg.bind("RtlUpcaseUnicodeChar", s_rtl_upcase_char as usize as u64);
    reg.bind("ZwClose", s_zw_close as usize as u64);
    reg.bind("ZwOpenKey", s_zw_open_key as usize as u64);
    reg.bind("ZwEnumerateKey", s_zw_enumerate_key as usize as u64);
    reg.bind("ZwQueryValueKey", s_zw_query_value_key as usize as u64);
    reg.bind("ZwSetValueKey", s_zw_set_value_key as usize as u64);
    reg.bind("ZwCreateFile", s_zw_create_file as usize as u64);
    reg.bind(
        "ZwQueryInformationFile",
        s_zw_query_information_file as usize as u64,
    );
    reg.bind("ZwReadFile", s_zw_read_file as usize as u64);
    reg.bind(
        "ExInterlockedInsertTailList",
        s_ex_interlocked_insert_tail_list as usize as u64,
    );
    reg.bind(
        "ExInterlockedInsertHeadList",
        s_ex_interlocked_insert_head_list as usize as u64,
    );
    reg.bind(
        "ExInterlockedRemoveHeadList",
        s_ex_interlocked_remove_head_list as usize as u64,
    );
    reg.bind(
        "ExInterlockedAddLargeInteger",
        s_ex_interlocked_add_large_integer as usize as u64,
    );
    reg.bind(
        "ExInterlockedAddUlong",
        s_ex_interlocked_add_ulong as usize as u64,
    );
    reg.bind(
        "ExpInterlockedPushEntrySList",
        s_exp_interlocked_push_entry_slist as usize as u64,
    );
    reg.bind(
        "ExpInterlockedPopEntrySList",
        s_exp_interlocked_pop_entry_slist as usize as u64,
    );
    reg.bind("ExQueueWorkItem", s_ex_queue_work_item as usize as u64);
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
        "KeAcquireSpinLockAtDpcLevel",
        s_ke_acquire_spin_lock_at_dpc_level as *const () as usize as u64,
    );
    reg.bind(
        "KeReleaseSpinLock",
        s_ke_release_spin_lock as *const () as usize as u64,
    );
    reg.bind(
        "KeReleaseSpinLockFromDpcLevel",
        s_ke_release_spin_lock_from_dpc_level as *const () as usize as u64,
    );
    reg.bind(
        "KeGetCurrentIrql",
        s_ke_get_current_irql as *const () as usize as u64,
    );
    reg.bind("KeEnterCriticalRegion", s_void as usize as u64);
    reg.bind("KeLeaveCriticalRegion", s_void as usize as u64);
    reg.bind(
        "KeInitializeEvent",
        s_ke_initialize_event as *const () as usize as u64,
    );
    reg.bind("KeSetEvent", s_ke_set_event as *const () as usize as u64);
    reg.bind(
        "KeClearEvent",
        s_ke_clear_event as *const () as usize as u64,
    );
    reg.bind(
        "KeWaitForSingleObject",
        s_ke_wait_for_single_object as *const () as usize as u64,
    );
    reg.bind("KeInitializeTimer", s_init_small_struct as usize as u64);
    reg.bind("KeCancelTimer", s_ke_cancel_timer as usize as u64);
    reg.bind("KeSetTimer", s_ke_set_timer as usize as u64);
    reg.bind("KeSetTimerEx", s_ke_set_timer_ex as usize as u64);
    reg.bind(
        "KeStallExecutionProcessor",
        s_ke_stall_execution_processor as *const () as usize as u64,
    );
    reg.bind(
        "KeInitializeDpc",
        s_ke_initialize_dpc as *const () as usize as u64,
    );
    reg.bind(
        "KeInsertQueueDpc",
        s_ke_insert_queue_dpc as *const () as usize as u64,
    );
    reg.bind(
        "KeQueryTimeIncrement",
        s_ke_query_time_increment as usize as u64,
    );
    reg.bind(
        "KeGetRecommendedSharedDataAlignment",
        s_ke_get_recommended_shared_data_alignment as usize as u64,
    );
    reg.bind(
        "KeRegisterBugCheckCallback",
        s_ke_register_bug_check_callback as usize as u64,
    );
    reg.bind(
        "KeDeregisterBugCheckCallback",
        s_ke_deregister_bug_check_callback as usize as u64,
    );
    reg.bind(
        "KeSynchronizeExecution",
        s_ke_synchronize_execution as usize as u64,
    );
    reg.bind(
        "KeNumberProcessors",
        core::ptr::addr_of!(KE_NUMBER_PROCESSORS_VALUE) as usize as u64,
    );
    reg.bind("ExInitializeFastMutex", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeMutex", s_init_small_struct as usize as u64);
    reg.bind("KeReleaseMutex", s_ke_release_mutex as usize as u64);
    reg.bind("KeInitializeSemaphore", s_init_small_struct as usize as u64);
    reg.bind("ProbeForRead", s_probe_for_read as usize as u64);
    reg.bind("ProbeForWrite", s_probe_for_write as usize as u64);
    // Se / Ob security helpers
    reg.bind(
        "IoGetFileObjectGenericMapping",
        s_generic_mapping as usize as u64,
    );
    reg.bind("SeAssignSecurity", s_se_assign_security as usize as u64);
    reg.bind("SeAccessCheck", s_se_access_check as usize as u64);
    reg.bind(
        "SeLockSubjectContext",
        s_se_lock_subject_context as usize as u64,
    );
    reg.bind(
        "SeUnlockSubjectContext",
        s_se_unlock_subject_context as usize as u64,
    );
    reg.bind(
        "SeOpenObjectAuditAlarm",
        s_se_open_object_audit_alarm as usize as u64,
    );
    reg.bind("SeAppendPrivileges", s_se_append_privileges as usize as u64);
    reg.bind("SeFreePrivileges", s_se_free_privileges as usize as u64);
    reg.bind("SeTokenType", s_se_token_type as usize as u64);
    reg.bind(
        "SeCreateClientSecurity",
        s_se_create_client_security as usize as u64,
    );
    reg.bind(
        "SeImpersonateClientEx",
        s_se_impersonate_client_ex as usize as u64,
    );
    reg.bind(
        "SeQuerySecurityDescriptorInfo",
        s_se_query_security_descriptor_info as usize as u64,
    );
    reg.bind(
        "SeSetSecurityDescriptorInfo",
        s_se_set_security_descriptor_info as usize as u64,
    );
    reg.bind("ObLogSecurityDescriptor", s_ob_log_sd as usize as u64);
    reg.bind(
        "ObDereferenceSecurityDescriptor",
        s_ob_dereference_security_descriptor as usize as u64,
    );
    reg.bind("ObfReferenceObject", s_obf_reference_object as usize as u64);
    reg.bind(
        "ObfDereferenceObject",
        s_obf_dereference_object as usize as u64,
    );
    // Ps/Io current-object identity
    reg.bind("PsGetCurrentProcess", s_current_process as usize as u64);
    reg.bind("PsGetCurrentThread", s_current_process as usize as u64);
    reg.bind("KeGetCurrentThread", s_current_process as usize as u64);
    reg.bind("IoGetRequestorProcess", s_current_process as usize as u64);
    reg.bind("IoThreadToProcess", s_current_process as usize as u64);
    reg.bind(
        "IoGetCurrentProcess",
        s_io_get_current_process as usize as u64,
    );
    // Debug print forwarders
    reg.bind("vDbgPrintExWithPrefix", s_dbg_print as usize as u64);
    reg.bind("vDbgPrintEx", s_dbg_print as usize as u64);
    reg.bind("DbgPrint", s_dbg_print as usize as u64);
    reg.bind("DbgPrintEx", s_dbg_print as usize as u64);
    reg.bind(
        "ExGetCurrentProcessorCounts",
        s_ex_get_current_processor_counts as usize as u64,
    );
    reg.bind(
        "ExGetCurrentProcessorCpuUsage",
        s_ex_get_current_processor_cpu_usage as usize as u64,
    );
    reg.bind(
        "HalTranslateBusAddress",
        s_hal_translate_bus_address as usize as u64,
    );
    reg.bind(
        "HalGetInterruptVector",
        s_hal_get_interrupt_vector as usize as u64,
    );
    reg.bind("HalGetBusData", s_hal_get_bus_data as usize as u64);
    reg.bind(
        "HalGetBusDataByOffset",
        s_hal_get_bus_data_by_offset as usize as u64,
    );
    reg.bind(
        "HalSetBusDataByOffset",
        s_hal_set_bus_data_by_offset as usize as u64,
    );

    if reg.is_exhausted() {
        panic!("FSD export registry capacity exhausted");
    }
}

fn hosted_kernel_provider_dll(dll: &str) -> bool {
    ascii_eq_ignore_case(dll, "ntoskrnl.exe")
        || ascii_eq_ignore_case(dll, "ntoskrnl")
        || ascii_eq_ignore_case(dll, "hal.dll")
        || ascii_eq_ignore_case(dll, "hal")
}

fn hosted_ndis_provider_dll(dll: &str) -> bool {
    ascii_eq_ignore_case(dll, "ndis.sys") || ascii_eq_ignore_case(dll, "ndis")
}

fn hosted_dependency_provider_dll(dll: &str) -> bool {
    hosted_ndis_provider_dll(dll)
}

unsafe fn log_unresolved_driver_import(dll: &str, name: &str) {
    if DRIVER_UNRESOLVED_IMPORTS_LOGGED < 48 {
        DRIVER_UNRESOLVED_IMPORTS_LOGGED += 1;
        print_str(b"[driver-import] unresolved ");
        for &b in dll.as_bytes() {
            debug_put_char(b);
        }
        debug_put_char(b'!');
        for &b in name.as_bytes() {
            debug_put_char(b);
        }
        print_str(b"\n");
    }
}

/// Resolve a hosted-driver import `DLL!NAME` to its IAT-slot trampoline VA through the SHARED
/// [`DriverExportRegistry`]. Only kernel-provider DLLs backed by the executive (`ntoskrnl` and `hal`)
/// are accepted here; dependency images such as `ndis.sys` must be mapped and resolved as real images.
/// Unknown provider DLLs or names return `None`, causing the PE load to fail before `DriverEntry`.
pub fn fsd_export_addr(dll: &str, name: &str) -> Option<u64> {
    if hosted_ndis_provider_dll(dll) {
        unsafe {
            if let Some(addr) = lookup_ndis_dependency_export(name) {
                return Some(addr);
            }
            log_unresolved_driver_import(dll, name);
        }
        return None;
    }
    if !hosted_kernel_provider_dll(dll) {
        unsafe {
            log_unresolved_driver_import(dll, name);
        }
        return None;
    }
    // SAFETY: single-threaded; the registry is populated once (lazily) and read-only thereafter.
    unsafe {
        if !FSD_EXPORTS_READY {
            register_fsd_trampolines();
            FSD_EXPORTS_READY = true;
        }
        if let Some(va) = (*core::ptr::addr_of!(FSD_EXPORTS)).lookup(name) {
            return Some(va);
        }
    }
    unsafe {
        log_unresolved_driver_import(dll, name);
    }
    None
}

// --- the FSD component entry -----------------------------------------------------------------

unsafe extern "win64" fn fsd_invalid_device_request(_devobj: u64, irp: u64) -> i32 {
    const STATUS_INVALID_DEVICE_REQUEST_I32: i32 = 0xC000_0010u32 as i32;
    if irp != 0 {
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32,
            STATUS_INVALID_DEVICE_REQUEST_I32,
        );
        write_unaligned((irp + 0x38) as *mut u64, 0);
    }
    STATUS_INVALID_DEVICE_REQUEST_I32
}

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
            support_entry_rva_off: SH_SUPPORT_ENTRY_RVA,
            support_status_off: SH_SUPPORT_DE_STATUS,
            support_verdict_off: SH_SUPPORT_VERDICT,
            default_major_function: fsd_invalid_device_request as *const () as u64,
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
        let expected_id =
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_ID) as *const u64);
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
    if major == FSD_DISPATCH_CANCEL_PENDING_FILE {
        let file_id = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
        let devobj = read_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *const u64);
        let cancelled = cancel_pending_irps_for_file(file_id, devobj);
        return (0, cancelled);
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
        (0xC000_0010u32 as i32, 0) // STATUS_INVALID_DEVICE_REQUEST
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
/// @0x08, DeviceObject@0x28, FileObject@0x30 }.
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
    let pipe_rw_before = if major == IRP_MJ_READ
        || major == IRP_MJ_WRITE
        || (major == IRP_MJ_FILE_SYSTEM_CONTROL && fsctl == FSCTL_PIPE_TRANSCEIVE)
    {
        pipe_ccb_view(file_id)
    } else {
        None
    };

    // FILE_OBJECT — ONE per OPEN, reused by every IRP on that open, freed at CLEANUP/CLOSE.
    // A FILE_OBJECT outlives the IRP that introduced it (npfs stores it in `Ccb->FileObject[end]`
    // and writes through that pointer on disconnect), so it must NOT be rebuilt/freed per request.
    let existing = if uses_file_object && crate::FSD_FILE_OBJECT_PER_OPEN {
        fo_lookup(file_id)
    } else {
        0
    };
    let owns_fo = uses_file_object && existing == 0;
    if owns_fo && crate::FSD_FILE_OBJECT_PER_OPEN && !fo_has_free_slot() {
        FSD_FO_TABLE_FULL.fetch_add(1, Ordering::Relaxed);
        return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
    }
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
    // Read/Write: Length@+0x08. QueryFile/SetFile: Length@+0x08, FileInformationClass@+0x10.
    // FS/DeviceControl: OutputBufferLength@+0x08, InputBufferLength@+0x10, IoControlCode@+0x18,
    // Type3InputBuffer@+0x20. `Irp->UserBuffer` carries the output buffer.
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
        IRP_MJ_QUERY_INFORMATION => WdmIoStackParameters::QueryInformation {
            length: outlen as u32,
            information_class: fsctl as u32,
        },
        IRP_MJ_SET_INFORMATION => WdmIoStackParameters::SetInformation {
            length: inlen as u32,
            information_class: fsctl as u32,
        },
        0xd | 0xe => WdmIoStackParameters::DeviceControl {
            output_buffer_length: outlen as u32,
            input_buffer_length: inlen as u32,
            io_control_code: fsctl as u32,
            type3_input_buffer: data,
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
            thread: s_current_process(),
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
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_IRP) as *mut u64, irp);
    write_volatile(
        (FSD_SHARED_VADDR + SH_ACTIVE_IOSL) as *mut u64,
        current_iosl,
    );
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_DATA) as *mut u64, data);
    write_volatile(
        (FSD_SHARED_VADDR + SH_ACTIVE_DATA_CAP) as *mut u64,
        data_capacity,
    );
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_FILE_OBJECT) as *mut u64, fo);

    // Call the driver's MajorFunction handler THROUGH the bugcheck escape: if the driver raises its
    // own consistency bugcheck (`NpBugCheck` → `KeBugCheckEx`) we unwind back here and fail THIS
    // dispatch cleanly instead of letting it continue on a broken invariant (or hang the boot).
    let active_seq = FSD_ACTIVE_DISPATCH_SEQ.load(Ordering::Relaxed);
    let trace_active_write = major == IRP_MJ_WRITE
        && active_seq >= 128
        && FSD_ACTIVE_WRITE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 16;
    if trace_active_write {
        trace_active_write_call_site(b"before-call", active_seq, file_id, handler, irp);
    }
    let jb = &mut *core::ptr::addr_of_mut!(BUGCHECK_JB);
    jb[0] = 0;
    jb[1] = 0;
    jb[2] = 0;
    let ret = fsd_guarded_call(handler, devobj, irp, jb.as_mut_ptr());
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_IRP) as *mut u64, 0);
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_IOSL) as *mut u64, 0);
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_DATA) as *mut u64, 0);
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_DATA_CAP) as *mut u64, 0);
    write_volatile((FSD_SHARED_VADDR + SH_ACTIVE_FILE_OBJECT) as *mut u64, 0);
    if trace_active_write {
        print_str(b"[fsd-active-write] after-call seq=");
        print_u64(active_seq);
        print_str(b" ret=");
        print_hex(ret as u32);
        print_str(b" irp-status=");
        print_hex(read_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *const u32,
        ));
        print_str(b" info=");
        print_u64(read_unaligned((irp + 0x38) as *const u64));
        unsafe {
            if let Some(view) = pipe_ccb_view(file_id) {
                print_pipe_ccb_view(b"", view);
            }
        }
        print_str(b"\n");
    }
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
    // CLOSE is where the FILE_OBJECT memory legitimately dies. CLEANUP may clear its FsContext, but
    // the same FILE_OBJECT must remain available for the following CLOSE IRP.
    if uses_file_object && major == IRP_MJ_CLOSE {
        fo_release(file_id);
        fo_registered = false;
    }
    let irp_owns_fo = owns_fo && !fo_registered;
    let read_completion = pending_irp_returns_read_bytes(major, fsctl);
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
    trace_pipe_rw_result(
        major,
        file_id,
        fsctx,
        if major == IRP_MJ_READ { outlen } else { inlen },
        st as u32,
        info,
        pipe_rw_before,
        data,
        if major == IRP_MJ_READ {
            info.min(outlen)
        } else {
            inlen
        },
    );
    if major == IRP_MJ_FILE_SYSTEM_CONTROL && fsctl == FSCTL_PIPE_TRANSCEIVE {
        trace_pipe_transceive_result(
            file_id,
            fsctx,
            inlen,
            outlen,
            st as u32,
            info,
            pipe_rw_before,
            data,
            inlen,
        );
    }
    if st as u32 == STATUS_PENDING {
        let inserted = insert_pending_irp(PendingIrp {
            irp,
            iosl,
            file_object: fo,
            data,
            // Capture the caller's open identity NOW: npfs may normalize or later NULL
            // `FILE_OBJECT->FsContext`, but executive waiters are parked on the exact endpoint fid
            // carried in this request.
            fid: if file_id != 0 { file_id } else { fsctx },
            major: major as u8,
            read_completion,
            owns_fo: irp_owns_fo,
            _pad: [0; 5],
        });
        if !inserted {
            pool_free(data);
            if pnp_resource_list != 0 {
                pool_free(pnp_resource_list);
            }
            pool_free(iosl);
            pool_free(irp);
            if irp_owns_fo {
                pool_free(fo);
            }
            return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
        }
    } else {
        if read_completion {
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
    /// The support image's DriverEntry status when this driver depends on a hosted provider image.
    pub support_status: i32,
    /// The support image's DriverEntry verdict bitmask.
    pub support_verdict: u32,
    /// Whether DriverEntry ran to its dispatch loop (parked) vs faulted mid-init.
    pub finished: bool,
    /// The EXECUTIVE-side SHARED-frame VA for THIS instance (where the executive marshals IRP
    /// request/reply fields). Instance 0 == [`FSD_SHARED_VADDR`]; N≥1 == a per-instance window.
    pub exec_shared_va: u64,
    /// The EXECUTIVE-side mirror of this component's FSD pool frames. Component pointers remain in
    /// the fixed [`FSD_POOL_VADDR`] range and are translated through this base before executive-side
    /// diagnostics or teardown read them.
    pub exec_pool_va: u64,
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

unsafe fn read_pe_ascii<'a>(
    image_va: u64,
    image_cap: u64,
    rva: u64,
    skip: u64,
    buf: &'a mut [u8],
) -> Option<&'a str> {
    let start = rva.checked_add(skip)?;
    if start >= image_cap || buf.is_empty() {
        return None;
    }
    let mut n = 0usize;
    while n < buf.len() {
        let off = start.checked_add(n as u64)?;
        if off >= image_cap {
            return None;
        }
        let c = read_volatile((image_va + off) as *const u8);
        if c == 0 {
            if n == 0 {
                return None;
            }
            return Some(core::str::from_utf8_unchecked(&buf[..n]));
        }
        if !(0x20..=0x7e).contains(&c) {
            return None;
        }
        buf[n] = c;
        n += 1;
    }
    None
}

#[derive(Clone, Copy)]
struct RawPeLayout {
    src_va: u64,
    src_size: u64,
    opt: u64,
    sec_table: u64,
    num_sections: u64,
    size_of_headers: u64,
}

unsafe fn raw_u16(src_va: u64, src_size: u64, off: u64) -> Option<u16> {
    if off > src_size.saturating_sub(2) {
        return None;
    }
    Some(read_unaligned((src_va + off) as *const u16))
}

unsafe fn raw_u32(src_va: u64, src_size: u64, off: u64) -> Option<u32> {
    if off > src_size.saturating_sub(4) {
        return None;
    }
    Some(read_unaligned((src_va + off) as *const u32))
}

unsafe fn raw_pe_layout(src_va: u64, src_size: u32) -> Option<RawPeLayout> {
    let src_size = src_size as u64;
    let e = raw_u32(src_va, src_size, 0x3c)? as u64;
    if raw_u32(src_va, src_size, e)? != 0x0000_4550 {
        return None;
    }
    let file_hdr = e.checked_add(4)?;
    let num_sections = raw_u16(src_va, src_size, file_hdr.checked_add(2)?)? as u64;
    let size_opt_hdr = raw_u16(src_va, src_size, file_hdr.checked_add(16)?)? as u64;
    let opt = file_hdr.checked_add(20)?;
    let magic = raw_u16(src_va, src_size, opt)?;
    if magic != 0x20b {
        return None;
    }
    let sec_table = opt.checked_add(size_opt_hdr)?;
    if sec_table.checked_add(num_sections.checked_mul(40)?)? > src_size {
        return None;
    }
    Some(RawPeLayout {
        src_va,
        src_size,
        opt,
        sec_table,
        num_sections,
        size_of_headers: raw_u32(src_va, src_size, opt.checked_add(60)?)? as u64,
    })
}

unsafe fn raw_pe_rva_to_file(layout: &RawPeLayout, rva: u64, len: u64) -> Option<u64> {
    if len == 0 {
        return None;
    }
    if rva < layout.size_of_headers && len <= layout.size_of_headers.saturating_sub(rva) {
        if len <= layout.src_size.saturating_sub(rva) {
            return Some(rva);
        }
        return None;
    }
    let mut i = 0u64;
    while i < layout.num_sections {
        let sh = layout.sec_table.checked_add(i.checked_mul(40)?)?;
        let vsize = raw_u32(layout.src_va, layout.src_size, sh.checked_add(8)?)? as u64;
        let va = raw_u32(layout.src_va, layout.src_size, sh.checked_add(12)?)? as u64;
        let raw_size = raw_u32(layout.src_va, layout.src_size, sh.checked_add(16)?)? as u64;
        let raw_ptr = raw_u32(layout.src_va, layout.src_size, sh.checked_add(20)?)? as u64;
        let span = vsize.max(raw_size);
        if rva >= va && rva - va < span {
            let delta = rva - va;
            if delta > raw_size.saturating_sub(len) {
                return None;
            }
            let off = raw_ptr.checked_add(delta)?;
            if len <= layout.src_size.saturating_sub(off) {
                return Some(off);
            }
            return None;
        }
        i += 1;
    }
    None
}

unsafe fn read_raw_ascii<'a>(
    src_va: u64,
    src_size: u64,
    off: u64,
    buf: &'a mut [u8],
) -> Option<&'a str> {
    if off >= src_size || buf.is_empty() {
        return None;
    }
    let mut n = 0usize;
    while n < buf.len() {
        let cur = off.checked_add(n as u64)?;
        if cur >= src_size {
            return None;
        }
        let c = read_volatile((src_va + cur) as *const u8);
        if c == 0 {
            if n == 0 {
                return None;
            }
            return Some(core::str::from_utf8_unchecked(&buf[..n]));
        }
        if !(0x20..=0x7e).contains(&c) {
            return None;
        }
        buf[n] = c;
        n += 1;
    }
    None
}

unsafe fn raw_pe_size_of_image(src_va: u64, src_size: u32) -> Option<u32> {
    let layout = raw_pe_layout(src_va, src_size)?;
    raw_u32(layout.src_va, layout.src_size, layout.opt.checked_add(56)?)
}

unsafe fn raw_pe_find_hosted_dependency<'a>(
    src_va: u64,
    src_size: u32,
    out: &'a mut [u8],
) -> Option<&'a str> {
    let layout = raw_pe_layout(src_va, src_size)?;
    let imp_rva = raw_u32(
        layout.src_va,
        layout.src_size,
        layout.opt.checked_add(112 + 8)?,
    )? as u64;
    if imp_rva == 0 {
        return None;
    }
    let mut desc_rva = imp_rva;
    let mut count = 0u32;
    while count < MAX_RAW_IMPORT_DESCRIPTORS {
        let desc = raw_pe_rva_to_file(&layout, desc_rva, 20)?;
        let original_first_thunk = raw_u32(layout.src_va, layout.src_size, desc)?;
        let name_rva = raw_u32(layout.src_va, layout.src_size, desc.checked_add(12)?)? as u64;
        let first_thunk = raw_u32(layout.src_va, layout.src_size, desc.checked_add(16)?)?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            return None;
        }
        let name_off = raw_pe_rva_to_file(&layout, name_rva, 1)?;
        let mut dll_buf = [0u8; HOSTED_DEP_PROVIDER_MAX];
        let dll = read_raw_ascii(layout.src_va, layout.src_size, name_off, &mut dll_buf)?;
        if !hosted_kernel_provider_dll(dll) && hosted_dependency_provider_dll(dll) {
            if dll.len() > out.len() {
                return None;
            }
            let mut i = 0usize;
            while i < dll.len() {
                out[i] = dll.as_bytes()[i];
                i += 1;
            }
            return Some(core::str::from_utf8_unchecked(&out[..dll.len()]));
        }
        desc_rva = desc_rva.checked_add(20)?;
        count += 1;
    }
    None
}

fn align_up_4k(v: u64) -> Option<u64> {
    v.checked_add(0xfff).map(|x| x & !0xfff)
}

fn hosted_dependency_path(provider: &str, out: &mut [u8]) -> Option<usize> {
    let provider_bytes = provider.as_bytes();
    if provider_bytes.len() <= 4 {
        return None;
    }
    let ext = &provider_bytes[provider_bytes.len() - 4..];
    if ext[0] != b'.'
        || ascii_upcase_u8(ext[1]) != b'S'
        || ascii_upcase_u8(ext[2]) != b'Y'
        || ascii_upcase_u8(ext[3]) != b'S'
    {
        return None;
    }
    let total = HOSTED_DRIVER_DEP_PATH_PREFIX
        .len()
        .checked_add(provider_bytes.len())?;
    if total > out.len() {
        return None;
    }
    let mut n = 0usize;
    while n < HOSTED_DRIVER_DEP_PATH_PREFIX.len() {
        out[n] = HOSTED_DRIVER_DEP_PATH_PREFIX[n];
        n += 1;
    }
    for &b in provider_bytes {
        if b > 0x7f || b == b'\\' || b == b'/' || b == b':' {
            return None;
        }
        out[n] = if b.is_ascii_uppercase() { b + 32 } else { b };
        n += 1;
    }
    Some(n)
}

unsafe fn loaded_pe_u16(image_va: u64, cap: u64, rva: u64) -> Option<u16> {
    if rva > cap.saturating_sub(2) {
        return None;
    }
    Some(read_unaligned((image_va + rva) as *const u16))
}

unsafe fn loaded_pe_u32(image_va: u64, cap: u64, rva: u64) -> Option<u32> {
    if rva > cap.saturating_sub(4) {
        return None;
    }
    Some(read_unaligned((image_va + rva) as *const u32))
}

unsafe fn lookup_loaded_pe_export(
    image_va: u64,
    run_va: u64,
    image_len: u32,
    export_name: &str,
) -> Option<u64> {
    let cap = image_len as u64;
    let e = loaded_pe_u32(image_va, cap, 0x3c)? as u64;
    if loaded_pe_u32(image_va, cap, e)? != 0x0000_4550 {
        return None;
    }
    let opt = e.checked_add(24)?;
    let export_rva = loaded_pe_u32(image_va, cap, opt.checked_add(112)?)? as u64;
    let export_size = loaded_pe_u32(image_va, cap, opt.checked_add(112 + 4)?)? as u64;
    if export_rva == 0 || export_size == 0 || export_rva > cap.saturating_sub(40) {
        return None;
    }
    let number_of_functions = loaded_pe_u32(image_va, cap, export_rva.checked_add(20)?)? as u64;
    let number_of_names = loaded_pe_u32(image_va, cap, export_rva.checked_add(24)?)?;
    if number_of_names > MAX_LOADED_EXPORT_NAMES {
        return None;
    }
    let address_of_functions = loaded_pe_u32(image_va, cap, export_rva.checked_add(28)?)? as u64;
    let address_of_names = loaded_pe_u32(image_va, cap, export_rva.checked_add(32)?)? as u64;
    let address_of_ordinals = loaded_pe_u32(image_va, cap, export_rva.checked_add(36)?)? as u64;
    let mut i = 0u32;
    while i < number_of_names {
        let name_rva = loaded_pe_u32(
            image_va,
            cap,
            address_of_names.checked_add((i as u64).checked_mul(4)?)?,
        )? as u64;
        let mut name_buf = [0u8; 128];
        let name = read_pe_ascii(image_va, cap, name_rva, 0, &mut name_buf)?;
        if name == export_name {
            let ordinal_index = loaded_pe_u16(
                image_va,
                cap,
                address_of_ordinals.checked_add((i as u64).checked_mul(2)?)?,
            )? as u64;
            if ordinal_index >= number_of_functions {
                return None;
            }
            let func_rva = loaded_pe_u32(
                image_va,
                cap,
                address_of_functions.checked_add(ordinal_index.checked_mul(4)?)?,
            )? as u64;
            if func_rva >= export_rva && func_rva < export_rva.saturating_add(export_size) {
                print_str(b"[driver-import] forwarder export unsupported ");
                print_str(export_name.as_bytes());
                print_str(b"\n");
                return None;
            }
            if func_rva >= cap {
                return None;
            }
            return Some(run_va + func_rva);
        }
        i += 1;
    }
    None
}

unsafe fn lookup_ndis_dependency_export(name: &str) -> Option<u64> {
    let dep = NDIS_DEP_IMAGE;
    if !dep.present {
        return None;
    }
    lookup_loaded_pe_export(dep.exec_va, dep.run_va, dep.image_len, name)
}

/// Parse a driver PE at `src_va` (raw file bytes), copy its sections into `dst_va` (frames pre-mapped
/// RW in BOTH the executive and the component), apply DIR64 relocations for the load at `dst_va`, and
/// patch the IAT resolving each provider DLL + import name through `resolve`. Records per-frame W^X rights into
/// `rights_out`. Returns `(DriverEntryRva, SizeOfImage)`, or None. Fully HEAP-FREE.
///
/// This is the generic PE-load mechanism (the win32k `load_driver_into` shape, but with an injected
/// provider-aware resolver so it's driver-agnostic — the general dynamic path).
unsafe fn load_pe_into(
    src_va: u64,
    dst_va: u64,
    run_va: u64,
    max_frames: u64,
    rights_out: &mut [u64],
    resolve: fn(&str, &str) -> Option<u64>,
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

    // CR8 transform (documented; the win32k `KeGetCurrentIrql`-cr8 precedent): a kernel driver reads
    // the current IRQL as `mov %cr8, %reg` — a privileged instruction that #GPs in the component's
    // usermode context. ReactOS x64 helpers use `44 0f 20 c0; c3` (`mov %cr8,%rax; ret`); expand that
    // helper in place to `movzx eax, byte ptr [rip+SH_HOSTED_CURRENT_IRQL]; ret`, so DPC delivery can
    // report DISPATCH_LEVEL while ordinary dispatch remains PASSIVE_LEVEL. Short inline reads that do
    // not have a helper-sized padding budget are still neutralized to PASSIVE_LEVEL. CR8 writes are
    // nopped; hosted IRQL transitions are owned by the ntoskrnl import trampolines and DPC pump.
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
                    if (b0 & 0x04) != 0
                        && modrm == 0xC0
                        && p + 8 <= scan
                        && read_unaligned((dst_va + p + 4) as *const u8) == 0xC3
                    {
                        let target = FSD_SHARED_VADDR + SH_HOSTED_CURRENT_IRQL;
                        let next_rip = run_va + p + 7;
                        let disp = target as i64 - next_rip as i64;
                        if disp >= i32::MIN as i64 && disp <= i32::MAX as i64 {
                            let d = disp as u32;
                            write_unaligned((dst_va + p) as *mut u8, 0x0F); // movzx eax, byte ptr [rip+disp32]
                            write_unaligned((dst_va + p + 1) as *mut u8, 0xB6);
                            write_unaligned((dst_va + p + 2) as *mut u8, 0x05);
                            write_unaligned((dst_va + p + 3) as *mut u8, d as u8);
                            write_unaligned((dst_va + p + 4) as *mut u8, (d >> 8) as u8);
                            write_unaligned((dst_va + p + 5) as *mut u8, (d >> 16) as u8);
                            write_unaligned((dst_va + p + 6) as *mut u8, (d >> 24) as u8);
                            write_unaligned((dst_va + p + 7) as *mut u8, 0xC3); // ret
                            p += 8;
                            continue;
                        }
                    }
                    write_unaligned((dst_va + p) as *mut u8, 0x31); // xor
                    write_unaligned((dst_va + p + 1) as *mut u8, 0xC0); // eax,eax
                    write_unaligned((dst_va + p + 2) as *mut u8, 0xB0); // mov al,
                    write_unaligned((dst_va + p + 3) as *mut u8, PASSIVE_LEVEL);
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

    // Patch the IAT: resolve each provider DLL + import name through `resolve`.
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva != 0 {
        let mut desc_rva = imp_rva;
        loop {
            if desc_rva > cap.saturating_sub(20) {
                return None;
            }
            let desc = dst_va + desc_rva;
            let ilt = read_unaligned(desc as *const u32) as u64;
            let dll_rva = read_unaligned((desc + 12) as *const u32) as u64;
            let iat = read_unaligned((desc + 16) as *const u32) as u64;
            if ilt == 0 && iat == 0 {
                break;
            }
            if iat == 0 {
                return None;
            }
            let mut dll_buf = [0u8; 64];
            let dll = read_pe_ascii(dst_va, cap, dll_rva, 0, &mut dll_buf)?;
            let names_rva = if ilt != 0 { ilt } else { iat };
            let mut k = 0u64;
            loop {
                let entry_rva = names_rva.checked_add(k.checked_mul(8)?)?;
                if entry_rva > cap.saturating_sub(8) {
                    return None;
                }
                let thunk = read_unaligned((dst_va + entry_rva) as *const u64);
                if thunk == 0 {
                    break;
                }
                let slot_rva = iat.checked_add(k.checked_mul(8)?)?;
                if slot_rva > cap.saturating_sub(8) {
                    return None;
                }
                if thunk & 0x8000_0000_0000_0000 != 0 {
                    print_str(b"[driver-import] ordinal imports unsupported in ");
                    for &b in dll.as_bytes() {
                        debug_put_char(b);
                    }
                    print_str(b"\n");
                    return None;
                }
                let mut name_buf = [0u8; 128];
                let name =
                    read_pe_ascii(dst_va, cap, thunk & 0x7FFF_FFFF_FFFF_FFFF, 2, &mut name_buf)?;
                let addr = resolve(dll, name)?;
                write_unaligned((dst_va + slot_rva) as *mut u64, addr);
                k = k.checked_add(1)?;
            }
            desc_rva = desc_rva.checked_add(20)?;
        }
    }

    Some((entry_rva, size_of_image))
}

/// Executive-side frame aliases mapped while launching hosted drivers.
///
/// Each driver gets a growable cap list keyed by its live instance index. The previous fixed
/// matrix made instance count a compile-time policy decision; now the real limits are root CSpace,
/// untyped memory, and the executive VA window calculation.
static mut DRIVER_EXEC_MAPPED_CAPS: Option<Vec<Vec<u64>>> = None;
static mut DRIVER_EXEC_PD_WINDOWS: Option<Vec<u64>> = None;
const EXEC_PD_SPAN: u64 = 0x4000_0000; // 1 GiB
const SEL4_DELETE_FIRST: u64 = 8;

unsafe fn load_hosted_dependency_images(
    fs: &Fat32,
    primary_src_va: u64,
    primary_src_size: u32,
    code_va: u64,
    run_va: u64,
    img_frames: u64,
    rights: &mut [u64],
) -> Option<u64> {
    NDIS_DEP_IMAGE = LoadedDependencyImage::empty();

    let mut provider_buf = [0u8; HOSTED_DEP_PROVIDER_MAX];
    let Some(provider) =
        raw_pe_find_hosted_dependency(primary_src_va, primary_src_size, &mut provider_buf)
    else {
        return Some(0);
    };
    let primary_image_len = raw_pe_size_of_image(primary_src_va, primary_src_size)? as u64;
    let dep_offset = align_up_4k(primary_image_len)?;
    let dep_frame_offset = dep_offset / 0x1000;
    if dep_frame_offset >= img_frames {
        print_str(b"[driver-launch] dependency image window exhausted before ");
        print_str(provider.as_bytes());
        print_str(b"\n");
        return None;
    }
    let dep_frames = img_frames - dep_frame_offset;
    let dep_rights = &mut rights[dep_frame_offset as usize..];
    let mut dep_path = [0u8; HOSTED_DEP_PATH_MAX];
    let dep_path_len = hosted_dependency_path(provider, &mut dep_path)?;
    print_str(b"[driver-launch] dependency ");
    print_str(provider.as_bytes());
    print_str(b" -> ");
    print_str(&dep_path[..dep_path_len]);
    print_str(b" offset=0x");
    print_hex(dep_offset as u32);
    print_str(b"\n");

    let (dep_src_va, dep_src_size) = load_file_to_pool(fs, &dep_path[..dep_path_len])?;
    let dep_exec_va = code_va + dep_offset;
    let dep_run_va = run_va + dep_offset;
    let (dep_entry_rva, dep_image_len) = load_pe_into(
        dep_src_va,
        dep_exec_va,
        dep_run_va,
        dep_frames,
        dep_rights,
        fsd_export_addr,
    )?;
    if dep_image_len as u64 > dep_frames * 0x1000 {
        return None;
    }
    if hosted_ndis_provider_dll(provider) {
        NDIS_DEP_IMAGE = LoadedDependencyImage {
            present: true,
            exec_va: dep_exec_va,
            run_va: dep_run_va,
            image_len: dep_image_len,
        };
    }
    let _ = register_system_module(&dep_path[..dep_path_len], dep_exec_va, dep_image_len);
    print_str(b"[driver-launch] dependency loaded ");
    print_str(provider.as_bytes());
    print_str(b" size=");
    print_u64(dep_src_size as u64);
    print_str(b" image=0x");
    print_hex(dep_image_len);
    print_str(b" entry=0x");
    print_hex(dep_entry_rva);
    print_str(b"\n");
    Some(dep_offset + dep_entry_rva as u64)
}

/// GENERAL dynamic driver launch: load the `.sys` at `path` by-path from the FS, IAT-patch it, spawn
/// it as an ISOLATED component (per its `class`), run its real DriverEntry, and return the live
/// [`DriverComponent`]. The FSD/Filter/Device classes are all routed through this ONE Family-A IRP
/// path (`caps_and_layout_for(class)` selects the [`HostCaps`] + whether device caps are granted);
/// the GUI syscall server ([`DriverClass::GuiSyscallServer`], win32k) keeps its own Syscall substrate
/// and is NOT routed here — see [`crate::win32k_subsystem`].
///
/// MULTI-INSTANCE: each call reserves the first free instance slot; instance 0 uses the fixed FSD
/// executive VAs (byte-identical), instance N≥1 a distinct executive window from the checked
/// [`ExecVaWindow`] arena. The live driver state is recorded in [`DRIVER_INSTANCES`] so
/// [`dispatch_irp`] can route to any loaded driver by instance index. Adding a boot/system IRP driver
/// means declaring a `Services\<Name>` record with an image path, type, and start policy, then handing
/// that metadata to this loader.
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

    let Some(instance) = reserve_instance_slot() else {
        print_str(b"[driver-launch] instance reservation failed\n");
        return None;
    };

    let loaded = load_driver_reserved(fs, path, driver_object_path, instance);
    if loaded.is_none() {
        clear_instance(instance);
    }
    loaded
}

unsafe fn load_driver_reserved(
    fs: &Fat32,
    path: &[u8],
    driver_object_path: &str,
    instance: usize,
) -> Option<DriverComponent> {
    let Some(win) = ExecVaWindow::try_for_instance(instance) else {
        print_str(b"[driver-launch] instance VA window exhausted inst=");
        print_u64(instance as u64);
        print_str(b"\n");
        return None;
    };

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

    // 2. Executive-side frames: CODE (mapped RW to load into) in its own 2 MiB PT, POOL in its own
    //    mirrored 2 MiB PT, and DATA + SHARED + ARG in an aux PT.
    let cpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cpt);
    map_instance_exec_pt(instance, cpt, code_va)?;
    let code_base = alloc_frame();
    for _ in 1..img_frames {
        let _ = alloc_frame();
    }
    for i in 0..img_frames {
        let cap = copy_cap(code_base + i);
        map_instance_exec_frame(instance, cap, code_va + i * 0x1000, RW_NX)?;
    }
    // POOL frames (host-only; allocate the caps, mapped by spawn_component).
    let pool_base = alloc_frame();
    for _ in 1..FSD_POOL_FRAMES {
        let _ = alloc_frame();
    }
    let ppt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ppt);
    map_instance_exec_pt(instance, ppt, win.pool_va)?;
    for i in 0..FSD_POOL_FRAMES {
        let cap = copy_cap(pool_base + i);
        map_instance_exec_frame(instance, cap, win.pool_va + i * 0x1000, RW_NX)?;
    }
    // DATA + SHARED + ARG: caps + an aux PT in the executive VSpace.
    let data_base = alloc_frame();
    for _ in 1..FSD_DATA_FRAMES {
        let _ = alloc_frame();
    }
    let shared_base = alloc_frame();
    for _ in 1..FSD_SHARED_FRAMES {
        let _ = alloc_frame();
    }
    let arg_base = alloc_frame();
    for _ in 1..FSD_ARG_FRAMES {
        let _ = alloc_frame();
    }
    let apt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, apt);
    map_instance_exec_pt(instance, apt, win.aux_pt_va)?;
    for i in 0..FSD_DATA_FRAMES {
        let cap = copy_cap(data_base + i);
        map_instance_exec_frame(instance, cap, win.data_va + i * 0x1000, RW_NX)?;
    }
    for i in 0..FSD_SHARED_FRAMES {
        let cap = copy_cap(shared_base + i);
        map_instance_exec_frame(instance, cap, win.shared_va + i * 0x1000, RW_NX)?;
    }
    for i in 0..FSD_ARG_FRAMES {
        let cap = copy_cap(arg_base + i);
        map_instance_exec_frame(instance, cap, win.arg_va + i * 0x1000, RW_NX)?;
    }

    // 3. Parse + copy + relocate + IAT-patch (HEAP-FREE, records W^X rights). Load bytes into the
    //    per-instance executive window (code_va) but relocate for the component execution VA (run_va).
    let rights = Box::leak(Box::new([RW_NX; FSD_IMAGE_FRAMES as usize]));
    let support_entry_rva =
        load_hosted_dependency_images(fs, src_va, src_size, code_va, run_va, img_frames, rights)?;
    let (entry_rva, image_len) =
        load_pe_into(src_va, code_va, run_va, img_frames, rights, fsd_export_addr)?;
    let _ = register_system_module(path, code_va, image_len);
    print_str(b"[driver-launch] DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");
    write_volatile((win.shared_va + SH_ENTRY_RVA) as *mut u64, entry_rva as u64);
    write_volatile((win.shared_va + SH_VERDICT) as *mut u32, 0);
    write_volatile((win.shared_va + SH_ADD_DEVICE) as *mut u64, 0);
    write_volatile(
        (win.shared_va + SH_SUPPORT_ENTRY_RVA) as *mut u64,
        support_entry_rva,
    );
    write_volatile((win.shared_va + SH_SUPPORT_DE_STATUS) as *mut i32, 0);
    write_volatile((win.shared_va + SH_SUPPORT_VERDICT) as *mut u32, 0);
    write_volatile(
        (win.shared_va + SH_HOSTED_CURRENT_IRQL) as *mut u8,
        PASSIVE_LEVEL,
    );
    clear_dma_allocation_records(win.shared_va);
    clear_shared_device_interface_state_at(win.shared_va);
    clear_shared_registry_identity_at(win.shared_va);

    // 4. Build the FSD-class descriptor + spawn the isolated component.
    let fault_ep = make_object(OBJ_ENDPOINT);
    let (pml4, tcb) = spawn_fsd_component(
        code_base,
        pool_base,
        data_base,
        shared_base,
        arg_base,
        fault_ep,
        &rights[..img_frames as usize],
    );
    // ★ This instance's DEDICATED MCS reply object — the server-side binding of the `Call`
    // transport. One per component is enough at any depth (one TCB ⇒ at most one outstanding Call).
    let reply_cap = crate::ensure_fsd_reply_slot(instance);
    if reply_cap == 0 {
        print_str(b"[driver-launch] reply cap allocation failed inst=");
        print_u64(instance as u64);
        print_str(b"\n");
        return None;
    }

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
        exec_code_va: code_va,
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
    let support_status = read_volatile((win.shared_va + SH_SUPPORT_DE_STATUS) as *const i32);
    let support_verdict = read_volatile((win.shared_va + SH_SUPPORT_VERDICT) as *const u32);
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
    if support_entry_rva != 0 {
        print_str(b" support_status=0x");
        print_hex(support_status as u32);
        print_str(b" support_verdict=0x");
        print_hex(support_verdict);
    }
    print_str(b" unload=0x");
    print_hex((driver_unload >> 32) as u32);
    print_hex(driver_unload as u32);
    print_str(b"\n");

    if !finished || de_status != 0 {
        print_str(b"[driver-launch] DriverEntry failed; refusing to register ");
        print_str(driver_object_path.as_bytes());
        print_str(b"\n");
        clear_driver_object_extensions_for_driver_object(drvobj);
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
        support_status,
        support_verdict,
        finished,
        exec_shared_va: win.shared_va,
        exec_pool_va: win.pool_va,
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
            clear_driver_object_extensions_for_driver_object(drvobj);
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
        clear_driver_object_extensions_for_driver_object(drvobj);
        destroy_registered_driver(driver_id);
        return None;
    }
    // Record the live instance and publish canonical driver/device route ids for callers.
    register_instance(&dc);
    Some(dc)
}

/// Spawn the isolated FSD component: image W^X, pool, stack, IPC-buf, DATA/SHARED arena/ARG windows,
/// fault EP — NO device caps. Delegates to the generic [`spawn_component`] engine.
unsafe fn spawn_fsd_component(
    code_base: u64,
    pool_base: u64,
    data_base: u64,
    shared: u64,
    arg_base: u64,
    fault_ep: u64,
    rights: &[u64],
) -> (u64, u64) {
    // SAFETY: rights is heap-leaked by the loader for the component lifetime.
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
            pts: pts_for(FSD_POOL_FRAMES),
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
        // Shared handoff arena (aux window).
        Region {
            source: FrameSource::Alias(shared),
            base_va: FSD_SHARED_VADDR,
            count: FSD_SHARED_FRAMES,
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

#[inline(never)]
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
const HOSTED_ROOT_BUS_SUPPORTED_MAJORS: [u8; 1] = [major::IRP_MJ_PNP];

fn hosted_root_bus_driver_id() -> Result<DriverId, nt_status::NtStatus> {
    if let Some(id) = driver_id_by_name(HOSTED_ROOT_BUS_DRIVER_PATH) {
        return Ok(DriverId(id));
    }
    register_kernel_io_driver_with_majors(
        HOSTED_ROOT_BUS_DRIVER_PATH,
        Box::new(HostedRootBusBackend),
        &HOSTED_ROOT_BUS_SUPPORTED_MAJORS,
    )
    .map(DriverId)
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

fn external_dispatch_buffer_lengths(
    input_len: usize,
    output_len: usize,
) -> Result<(u32, u32, usize), u32> {
    let transport_capacity = (FSD_ARG_FRAMES * 0x1000) as usize;
    if input_len > transport_capacity {
        return Err(STATUS_INVALID_BUFFER_SIZE);
    }
    let output_len = output_len.min(transport_capacity);
    Ok((
        external_len(input_len),
        external_len(output_len),
        input_len.max(output_len),
    ))
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

fn dispatch_external_irp_to_driver_record_result(
    driver_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Result<(i32, u64), u32> {
    let major = external_major(major).ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let (input_len, output_len, system_buffer_len) =
        external_dispatch_buffer_lengths(in_data.len(), out.len())?;
    let params = external_irp_parameters(major, fsctl, input_len, output_len)
        .ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let mut system_buffer = Vec::new();
    system_buffer.resize(system_buffer_len, 0);
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
        .map_err(|status| status.raw() as u32)?;
    let copy_len = (information as usize)
        .min(out.len())
        .min(system_buffer.len());
    out[..copy_len].copy_from_slice(&system_buffer[..copy_len]);
    Ok((status.raw(), information))
}

fn dispatch_external_irp_to_device_record_result(
    device_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Result<(i32, u64), u32> {
    let major = external_major(major).ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let (input_len, output_len, system_buffer_len) =
        external_dispatch_buffer_lengths(in_data.len(), out.len())?;
    let params = external_irp_parameters(major, fsctl, input_len, output_len)
        .ok_or(STATUS_INVALID_PARAMETER as u32)?;
    let mut system_buffer = Vec::new();
    system_buffer.resize(system_buffer_len, 0);
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
        .map_err(|status| status.raw() as u32)?;
    let copy_len = (information as usize)
        .min(out.len())
        .min(system_buffer.len());
    out[..copy_len].copy_from_slice(&system_buffer[..copy_len]);
    Ok((status.raw(), information))
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

#[inline(never)]
pub(crate) fn register_kernel_io_driver_with_majors(
    driver_object_path: &str,
    backend: Box<dyn DriverDispatchBackend>,
    majors: &[u8],
) -> Result<u64, nt_status::NtStatus> {
    let name = parse_nt_path(driver_object_path).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    io_manager_mut()
        .create_kernel_driver_with_majors(&name, backend, majors)
        .map(|driver_id| driver_id.raw())
}

pub(crate) fn driver_id_by_name(path: &str) -> Option<u64> {
    let path = parse_nt_path(path)?;
    io_manager_mut()
        .driver_id_by_name(&path)
        .map(|driver_id| driver_id.raw())
}

#[inline(never)]
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

#[inline(never)]
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

#[inline(never)]
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
    register_hosted_device_binding(
        driver_id,
        device_id.raw(),
        dc.instance,
        dc.devobj,
        0,
        INVALID_HOSTED_REGISTRY_IDENTITY_ID,
    )?;
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

unsafe fn apply_hosted_device_interface_state(sh: u64) -> Result<(), nt_status::NtStatus> {
    let (link_len, link_utf16) = read_shared_path_capture(
        sh,
        SH_DEVICE_INTERFACE_LINK_LEN,
        SH_DEVICE_INTERFACE_LINK_BUF,
    );
    if link_len == 0 {
        return Ok(());
    }
    let link =
        captured_nt_path(&link_utf16, link_len).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let state = read_volatile((sh + SH_DEVICE_INTERFACE_STATE) as *const u32);
    if state == 0 {
        match io_manager_mut().delete_symbolic_link(&link) {
            Ok(()) | Err(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND) => Ok(()),
            Err(status) => Err(status),
        }
    } else {
        let (target_len, target_utf16) = read_shared_path_capture(
            sh,
            SH_DEVICE_INTERFACE_TARGET_LEN,
            SH_DEVICE_INTERFACE_TARGET_BUF,
        );
        let target = captured_nt_path(&target_utf16, target_len)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        io_manager_mut().create_symbolic_link(&link, &target)
    }
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
    registry_identity_id: HostedRegistryIdentityId,
    used: bool,
}

const EMPTY_HOSTED_DEVICE_BINDING: HostedDeviceBinding = HostedDeviceBinding {
    driver_id: 0,
    device_id: 0,
    instance: 0,
    device_object: 0,
    pdo_object: 0,
    registry_identity_id: INVALID_HOSTED_REGISTRY_IDENTITY_ID,
    used: false,
};

#[derive(Clone, Copy)]
struct HostedRootPdoBinding {
    pdo_object: u64,
    device_id: u64,
    used: bool,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct HostedHardwareEvidence {
    pub resource_mmio_phys: u64,
    pub resource_mmio_len: u64,
    pub resource_io_port_len: u64,
    pub resource_io_port_cap: u64,
    pub io_port_out32_faults: u64,
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
            || self.resource_io_port_len != 0
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

    pub(crate) fn io_port_out32_serviced(self) -> bool {
        self.resource_io_port_len != 0
            && self.resource_io_port_cap != 0
            && self.io_port_out32_faults != 0
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct HostedInterruptDelivery {
    pub interrupt_id: u64,
    pub vector: u32,
    pub claimed: bool,
}

static mut HOSTED_DEVICE_BINDINGS: Option<Vec<HostedDeviceBinding>> = None;
static mut HOSTED_ROOT_PDO_BINDINGS: Option<Vec<HostedRootPdoBinding>> = None;
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

unsafe fn hosted_device_bindings_mut() -> &'static mut Vec<HostedDeviceBinding> {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_DEVICE_BINDINGS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn hosted_device_bindings() -> Option<&'static Vec<HostedDeviceBinding>> {
    (*core::ptr::addr_of!(HOSTED_DEVICE_BINDINGS)).as_ref()
}

unsafe fn hosted_root_pdo_bindings_mut() -> &'static mut Vec<HostedRootPdoBinding> {
    let slot = &mut *core::ptr::addr_of_mut!(HOSTED_ROOT_PDO_BINDINGS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn hosted_root_pdo_bindings() -> Option<&'static Vec<HostedRootPdoBinding>> {
    (*core::ptr::addr_of!(HOSTED_ROOT_PDO_BINDINGS)).as_ref()
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
    let old_ioport_cap = read_volatile((sh + SH_RESOURCE_IO_PORT_CAP) as *const u64);
    if old_ioport_cap != 0 {
        let _ = crate::cnode_delete_recycle_r(old_ioport_cap);
    }
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
    write_volatile(
        (sh + SH_RESOURCE_INTERFACE_TYPE) as *mut u32,
        HOSTED_INTERFACE_TYPE_INTERNAL,
    );
    write_volatile((sh + SH_RESOURCE_BUS_NUMBER) as *mut u32, 0);
    write_volatile((sh + SH_RESOURCE_ADDRESS) as *mut u32, 0);
    write_volatile((sh + SH_RESOURCE_PCI_VENDOR_DEVICE) as *mut u32, 0);
    write_volatile((sh + SH_RESOURCE_PCI_CLASS_REV) as *mut u32, 0);
    write_volatile((sh + SH_RESOURCE_PCI_IRQ) as *mut u32, 0);
    write_volatile((sh + SH_RESOURCE_IO_PORT_BASE) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_IO_PORT_LEN) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_IO_PORT_CAP) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_IO_PORT_OUT32_FAULTS) as *mut u64, 0);
    clear_shared_device_interface_state_at(sh);
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
    clear_dma_allocation_records(sh);
}

fn hosted_root_pdo_device_id(pdo_object: u64) -> Option<u64> {
    let bindings = unsafe { hosted_root_pdo_bindings()? };
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
    let bindings = unsafe { hosted_root_pdo_bindings_mut() };
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
    bindings.push(HostedRootPdoBinding {
        pdo_object,
        device_id,
        used: true,
    });
    Ok(())
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
    registry_identity_id: HostedRegistryIdentityId,
) -> Result<(), nt_status::NtStatus> {
    if device_id == 0 || device_object == 0 {
        return Ok(());
    }
    let bindings = unsafe { hosted_device_bindings_mut() };
    if let Some(slot) = bindings
        .iter_mut()
        .find(|slot| slot.used && slot.device_id == device_id)
    {
        let old_identity_id = slot.registry_identity_id;
        *slot = HostedDeviceBinding {
            driver_id,
            device_id,
            instance,
            device_object,
            pdo_object,
            registry_identity_id,
            used: true,
        };
        if old_identity_id != registry_identity_id {
            unsafe {
                release_hosted_registry_identity(old_identity_id);
            }
        }
        return Ok(());
    }
    if let Some(slot) = bindings.iter_mut().find(|slot| !slot.used) {
        *slot = HostedDeviceBinding {
            driver_id,
            device_id,
            instance,
            device_object,
            pdo_object,
            registry_identity_id,
            used: true,
        };
        return Ok(());
    }
    bindings.push(HostedDeviceBinding {
        driver_id,
        device_id,
        instance,
        device_object,
        pdo_object,
        registry_identity_id,
        used: true,
    });
    Ok(())
}

fn hosted_device_binding_by_device_id(device_id: u64) -> Option<HostedDeviceBinding> {
    let bindings = unsafe { hosted_device_bindings()? };
    bindings
        .iter()
        .copied()
        .find(|slot| slot.used && slot.device_id != 0 && slot.device_id == device_id)
}

fn hosted_device_binding_by_device_object(device_object: u64) -> Option<HostedDeviceBinding> {
    let bindings = unsafe { hosted_device_bindings()? };
    bindings
        .iter()
        .copied()
        .find(|slot| slot.used && slot.device_object != 0 && slot.device_object == device_object)
}

fn hosted_device_binding_by_pdo_object(pdo_object: u64) -> Option<HostedDeviceBinding> {
    let bindings = unsafe { hosted_device_bindings()? };
    bindings
        .iter()
        .copied()
        .find(|slot| slot.used && slot.pdo_object != 0 && slot.pdo_object == pdo_object)
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
            resource_io_port_len: read_volatile((sh + SH_RESOURCE_IO_PORT_LEN) as *const u64),
            resource_io_port_cap: read_volatile((sh + SH_RESOURCE_IO_PORT_CAP) as *const u64),
            io_port_out32_faults: read_volatile(
                (sh + SH_RESOURCE_IO_PORT_OUT32_FAULTS) as *const u64,
            ),
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
    let Some(bindings) = (unsafe { (*core::ptr::addr_of_mut!(HOSTED_DEVICE_BINDINGS)).as_mut() })
    else {
        return;
    };
    if let Some(slot) = bindings
        .iter_mut()
        .find(|slot| slot.used && slot.device_id == device_id)
    {
        let identity_id = slot.registry_identity_id;
        unsafe {
            revoke_hosted_device_resources(*slot);
            release_hosted_registry_identity(identity_id);
        }
        *slot = EMPTY_HOSTED_DEVICE_BINDING;
    }
}

fn clear_hosted_device_bindings_for_instance(instance: usize) {
    let Some(bindings) = (unsafe { (*core::ptr::addr_of_mut!(HOSTED_DEVICE_BINDINGS)).as_mut() })
    else {
        return;
    };
    for slot in bindings.iter_mut() {
        if slot.used && slot.instance == instance {
            let identity_id = slot.registry_identity_id;
            unsafe {
                revoke_hosted_device_resources(*slot);
                release_hosted_registry_identity(identity_id);
            }
            *slot = EMPTY_HOSTED_DEVICE_BINDING;
        }
    }
}

#[inline(never)]
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
    pub exec_pool_va: u64,
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
    exec_pool_va: 0,
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
static mut DRIVER_INSTANCES: Option<Vec<DriverInstance>> = None;

unsafe fn driver_instances_mut() -> &'static mut Vec<DriverInstance> {
    let slot = &mut *core::ptr::addr_of_mut!(DRIVER_INSTANCES);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn driver_instances() -> Option<&'static Vec<DriverInstance>> {
    (*core::ptr::addr_of!(DRIVER_INSTANCES)).as_ref()
}

unsafe fn driver_exec_mapped_caps_mut() -> &'static mut Vec<Vec<u64>> {
    let slot = &mut *core::ptr::addr_of_mut!(DRIVER_EXEC_MAPPED_CAPS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn driver_exec_pd_windows_mut() -> &'static mut Vec<u64> {
    let slot = &mut *core::ptr::addr_of_mut!(DRIVER_EXEC_PD_WINDOWS);
    if slot.is_none() {
        let mut windows = Vec::new();
        windows.push(crate::IMAGE_BASE & !(EXEC_PD_SPAN - 1));
        *slot = Some(windows);
    }
    slot.as_mut().unwrap()
}

unsafe fn ensure_exec_mapping_slot(instance: usize) -> &'static mut Vec<u64> {
    let mappings = driver_exec_mapped_caps_mut();
    while mappings.len() <= instance {
        mappings.push(Vec::new());
    }
    &mut mappings[instance]
}

fn reserve_instance_slot() -> Option<usize> {
    let reusable = unsafe {
        driver_instances().and_then(|table| {
            table
                .iter()
                .enumerate()
                .find(|(index, slot)| {
                    !slot.used && ExecVaWindow::try_for_instance(*index).is_some()
                })
                .map(|(index, _)| index)
        })
    };
    if let Some(index) = reusable {
        clear_instance_exec_mappings(index);
        let table = unsafe { driver_instances_mut() };
        table[index] = DriverInstance {
            used: true,
            ..EMPTY_INSTANCE
        };
        unsafe {
            ensure_exec_mapping_slot(index);
        }
        return Some(index);
    }

    let table = unsafe { driver_instances_mut() };
    let index = table.len();
    ExecVaWindow::try_for_instance(index)?;
    table.push(DriverInstance {
        used: true,
        ..EMPTY_INSTANCE
    });
    unsafe {
        ensure_exec_mapping_slot(index);
    }
    Some(index)
}

fn record_instance_exec_mapping(instance: usize, cap: u64) {
    if cap == 0 {
        return;
    }
    unsafe {
        ensure_exec_mapping_slot(instance).push(cap);
    }
}

fn clear_instance_exec_mappings(instance: usize) {
    let Some(mappings) = (unsafe { (*core::ptr::addr_of_mut!(DRIVER_EXEC_MAPPED_CAPS)).as_mut() })
    else {
        return;
    };
    if let Some(caps) = mappings.get_mut(instance) {
        for cap in caps.drain(..) {
            if cap != 0 {
                let _ = unsafe { page_unmap_r(cap) };
            }
        }
    }
}

unsafe fn ensure_instance_exec_pd(instance: usize, vaddr: u64) -> Option<()> {
    let pd_base = vaddr & !(EXEC_PD_SPAN - 1);
    if driver_exec_pd_windows_mut()
        .iter()
        .any(|base| *base == pd_base)
    {
        return Some(());
    }

    let pd = alloc_slot();
    let retype = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    if retype != 0 {
        print_str(b"[driver-launch] exec PD retype failed inst=");
        print_u64(instance as u64);
        print_str(b" pd-base=0x");
        print_hex((pd_base >> 32) as u32);
        print_hex(pd_base as u32);
        print_str(b" label=");
        print_u64(retype);
        print_str(b"\n");
        return None;
    }

    let map = paging_struct_map_r(
        pd,
        LBL_X86_PAGE_DIRECTORY_MAP,
        pd_base,
        CAP_INIT_THREAD_VSPACE,
    );
    if map != 0 && map != SEL4_DELETE_FIRST {
        print_str(b"[driver-launch] exec PD map failed inst=");
        print_u64(instance as u64);
        print_str(b" pd-base=0x");
        print_hex((pd_base >> 32) as u32);
        print_hex(pd_base as u32);
        print_str(b" label=");
        print_u64(map);
        print_str(b"\n");
        return None;
    }

    driver_exec_pd_windows_mut().push(pd_base);
    Some(())
}

unsafe fn map_instance_exec_pt(instance: usize, cap: u64, vaddr: u64) -> Option<()> {
    ensure_instance_exec_pd(instance, vaddr)?;
    let label = paging_struct_map_r(cap, LBL_X86_PAGE_TABLE_MAP, vaddr, CAP_INIT_THREAD_VSPACE);
    if label != 0 && label != SEL4_DELETE_FIRST {
        print_str(b"[driver-launch] exec PT map failed inst=");
        print_u64(instance as u64);
        print_str(b" va=0x");
        print_hex((vaddr >> 32) as u32);
        print_hex(vaddr as u32);
        print_str(b" label=");
        print_u64(label);
        print_str(b"\n");
        return None;
    }
    Some(())
}

unsafe fn map_instance_exec_frame(
    instance: usize,
    cap: u64,
    vaddr: u64,
    rights: u64,
) -> Option<()> {
    let label = page_map_r(cap, vaddr, rights, CAP_INIT_THREAD_VSPACE);
    if label != 0 {
        print_str(b"[driver-launch] exec frame map failed inst=");
        print_u64(instance as u64);
        print_str(b" va=0x");
        print_hex((vaddr >> 32) as u32);
        print_hex(vaddr as u32);
        print_str(b" label=");
        print_u64(label);
        print_str(b"\n");
        return None;
    }
    record_instance_exec_mapping(instance, cap);
    Some(())
}

/// Record a launched driver in [`DRIVER_INSTANCES`] (called by [`load_driver`]). "Ready" iff it
/// parked at its dispatch loop with a control DEVICE_OBJECT (an FSD; a filter/device without an
/// IoCreateDevice may still be ready — see [`register_instance_ready`]).
fn register_instance(dc: &DriverComponent) {
    // SAFETY: single-threaded executive; the table is written here + read in dispatch_irp.
    let t = unsafe { driver_instances_mut() };
    while t.len() <= dc.instance {
        t.push(EMPTY_INSTANCE);
    }
    t[dc.instance] = DriverInstance {
        fault_ep: dc.fault_ep,
        pml4: dc.pml4,
        exec_shared_va: dc.exec_shared_va,
        exec_pool_va: dc.exec_pool_va,
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

pub(crate) fn driver_object_id(driver_id: u64) -> u64 {
    io_manager_mut()
        .driver(DriverId(driver_id))
        .map(|driver| driver.object_id.0)
        .unwrap_or(0)
}

fn clear_instance(i: usize) {
    clear_hosted_device_bindings_for_instance(i);
    if let Some(inst) = instance(i) {
        unsafe {
            clear_driver_object_extensions_for_driver_object(inst.driver_object);
        }
    }
    let t = unsafe { driver_instances_mut() };
    if i < t.len() {
        let sh = t[i].exec_shared_va;
        if sh != 0 {
            unsafe {
                clear_shared_registry_identity_at(sh);
            }
        }
        clear_instance_exec_mappings(i);
        t[i] = EMPTY_INSTANCE;
    } else {
        clear_instance_exec_mappings(i);
    }
}

/// Mark instance `i` ready for IRP dispatch (used when readiness ≠ npfs's "has a devobj" rule, e.g.
/// a minimal driver that fills MajorFunction[] but creates no control DEVICE_OBJECT).
fn register_instance_ready(i: usize, ready: bool) {
    let t = unsafe { driver_instances_mut() };
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
    let t = unsafe { driver_instances()? };
    if i < t.len() && t[i].used {
        Some(t[i])
    } else {
        None
    }
}

fn instance_by_driver_id(driver_id: u64) -> Option<(usize, DriverInstance)> {
    let t = unsafe { driver_instances()? };
    t.iter()
        .copied()
        .enumerate()
        .find(|(_, entry)| entry.used && entry.driver_id != 0 && entry.driver_id == driver_id)
}

fn instance_by_device_id(device_id: u64) -> Option<(usize, DriverInstance)> {
    let t = unsafe { driver_instances()? };
    t.iter()
        .copied()
        .enumerate()
        .find(|(_, entry)| entry.used && entry.device_id != 0 && entry.device_id == device_id)
}

fn instance_by_device_object(device_object: u64) -> Option<(usize, DriverInstance)> {
    let t = unsafe { driver_instances()? };
    t.iter().copied().enumerate().find(|(_, entry)| {
        entry.used && entry.device_object != 0 && entry.device_object == device_object
    })
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
        exec_code_va: ExecVaWindow::try_for_instance(index)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?
            .code_va,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        client_pi: 0,
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
    fdo_name: Option<HostedAscii<HOSTED_EXPORT_NAME_MAX>>,
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
    write_volatile((sh + SH_DEVOBJ) as *mut u64, 0);
    clear_shared_path_len(SH_DEVICE_NAME_LEN);

    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: inst.fault_ep,
        pml4: inst.pml4,
        code_va: 0,
        image_frames: 0,
        exec_code_va: ExecVaWindow::try_for_instance(index)
            .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?
            .code_va,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        client_pi: 0,
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
        fdo_name: shared_device_name_ascii(),
    })
}

/// Invoke a loaded WDM driver's real `DriverExtension->AddDevice` for one registry-selected devnode
/// and publish the FDO it creates as an unnamed I/O Manager device owned by that driver.
pub(crate) unsafe fn call_add_device_for_driver(
    driver_id: u64,
    class_guid: Option<&str>,
    driver_key: Option<&str>,
    linkage_export: Option<&str>,
    instance_path: &str,
    hardware_ids: &[&str],
    compatible_ids: &[&str],
) -> Result<u64, nt_status::NtStatus> {
    let (index, inst) =
        instance_by_driver_id(driver_id).ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    let registry_identity =
        build_hosted_registry_identity(class_guid, driver_key, linkage_export, instance_path)?;
    let registry_identity_id = allocate_hosted_registry_identity(registry_identity)?;
    publish_shared_registry_identity_at(inst.exec_shared_va, &registry_identity)?;
    write_volatile(
        core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
        registry_identity_id,
    );
    let add_device_result = dispatch_add_device_for_instance(index, inst);
    write_volatile(
        core::ptr::addr_of_mut!(HOSTED_ADD_DEVICE_REGISTRY_IDENTITY_ID),
        INVALID_HOSTED_REGISTRY_IDENTITY_ID,
    );
    let add_device = match add_device_result {
        Ok(add_device) => add_device,
        Err(status) => {
            clear_shared_registry_identity_at(inst.exec_shared_va);
            release_hosted_registry_identity(registry_identity_id);
            return Err(status);
        }
    };
    if let Some(fdo_name) = add_device.fdo_name {
        if registry_identity.has_linkage_export()
            && !hosted_ascii_eq_ignore_case(&fdo_name, &registry_identity.export_name)
        {
            clear_shared_registry_identity_at(inst.exec_shared_va);
            release_hosted_registry_identity(registry_identity_id);
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
    }
    let fdo_name = match add_device.fdo_name.as_ref() {
        Some(name) => match parse_nt_path(name.as_str()) {
            Some(path) => Some(path),
            None => {
                clear_shared_registry_identity_at(inst.exec_shared_va);
                release_hosted_registry_identity(registry_identity_id);
                return Err(nt_status::NtStatus::INVALID_PARAMETER);
            }
        },
        None => None,
    };
    let pdo_device_id = match register_hosted_root_pdo(
        add_device.pdo_object,
        instance_path,
        hardware_ids,
        compatible_ids,
    ) {
        Ok(device_id) => device_id,
        Err(status) => {
            clear_shared_registry_identity_at(inst.exec_shared_va);
            release_hosted_registry_identity(registry_identity_id);
            return Err(status);
        }
    };
    let device_id = match io_manager_mut().create_device(
        DriverId(driver_id),
        fdo_name.as_ref(),
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    ) {
        Ok(device_id) => device_id,
        Err(status) => {
            clear_shared_registry_identity_at(inst.exec_shared_va);
            release_hosted_registry_identity(registry_identity_id);
            return Err(status);
        }
    };
    if let Err(status) = register_hosted_device_binding(
        driver_id,
        device_id.raw(),
        index,
        add_device.fdo_object,
        add_device.pdo_object,
        registry_identity_id,
    ) {
        let _ = io_manager_mut().destroy_device(device_id);
        clear_shared_registry_identity_at(inst.exec_shared_va);
        release_hosted_registry_identity(registry_identity_id);
        return Err(status);
    }
    if let Err(status) =
        io_manager_mut().attach_device_to_stack(device_id, nt_io_manager::DeviceId(pdo_device_id))
    {
        clear_hosted_device_binding_by_device_id(device_id.raw());
        let _ = io_manager_mut().destroy_device(device_id);
        clear_shared_registry_identity_at(inst.exec_shared_va);
        return Err(status);
    }

    let table = driver_instances_mut();
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
    bus_identity: HostedBusIdentity,
    mmio_phys: u64,
    mmio_len: u64,
    io_port_base: u64,
    io_port_len: u32,
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
    if (io_port_base == 0) != (io_port_len == 0) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let io_port_last = if io_port_len != 0 {
        let last = io_port_base
            .checked_add(io_port_len as u64 - 1)
            .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
        if io_port_base > u16::MAX as u64 || last > u16::MAX as u64 {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        last
    } else {
        0
    };
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
    for window in 0..mmio_pages.div_ceil(512).max(1) {
        ensure_paging(mmio_va + window * 0x20_0000, inst.pml4);
    }
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
        for window in 0..dma_pages.div_ceil(512).max(1) {
            ensure_paging(dma_va + window * 0x20_0000, inst.pml4);
        }
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

    let mut io_port_cap = 0u64;
    if io_port_len != 0 {
        let Some(cap) = try_alloc_slot() else {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        };
        let issue = crate::issue_ioport_cap(cap, io_port_base as u16, io_port_last as u16);
        if issue != 0 {
            recycle_deleted_root_slot(cap);
            print_str(b"[driver-launch] IOPortControl_Issue failed label=");
            print_u64(issue);
            print_str(b" range=0x");
            print_hex(io_port_base as u32);
            print_str(b"..0x");
            print_hex(io_port_last as u32);
            print_str(b"\n");
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        io_port_cap = cap;
    }

    let sh = inst.exec_shared_va;
    write_volatile((sh + SH_RESOURCE_MMIO_PHYS) as *mut u64, mmio_phys);
    write_volatile((sh + SH_RESOURCE_MMIO_LEN) as *mut u64, mapped_len);
    write_volatile((sh + SH_RESOURCE_IO_PORT_BASE) as *mut u64, io_port_base);
    write_volatile(
        (sh + SH_RESOURCE_IO_PORT_LEN) as *mut u64,
        io_port_len as u64,
    );
    write_volatile((sh + SH_RESOURCE_IO_PORT_CAP) as *mut u64, io_port_cap);
    write_volatile((sh + SH_RESOURCE_IO_PORT_OUT32_FAULTS) as *mut u64, 0);
    write_volatile((sh + SH_RESOURCE_MMIO_VA) as *mut u64, mmio_va);
    write_volatile(
        (sh + SH_RESOURCE_INTERRUPT_VECTOR) as *mut u32,
        interrupt_vector,
    );
    write_volatile(
        (sh + SH_RESOURCE_INTERRUPT_AFFINITY) as *mut u64,
        interrupt_affinity,
    );
    write_volatile(
        (sh + SH_RESOURCE_INTERFACE_TYPE) as *mut u32,
        bus_identity.interface_type,
    );
    write_volatile(
        (sh + SH_RESOURCE_BUS_NUMBER) as *mut u32,
        bus_identity.bus_number,
    );
    write_volatile((sh + SH_RESOURCE_ADDRESS) as *mut u32, bus_identity.address);
    write_volatile(
        (sh + SH_RESOURCE_PCI_VENDOR_DEVICE) as *mut u32,
        (bus_identity.pci_device_id as u32) << 16 | bus_identity.pci_vendor_id as u32,
    );
    write_volatile(
        (sh + SH_RESOURCE_PCI_CLASS_REV) as *mut u32,
        (bus_identity.pci_class & 0x00FF_FFFF) << 8,
    );
    write_volatile(
        (sh + SH_RESOURCE_PCI_IRQ) as *mut u32,
        bus_identity.pci_irq_line as u32 | ((bus_identity.pci_irq_pin as u32) << 8),
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
    clear_dma_allocation_records(sh);
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

    let record_capacity = dma_allocation_record_capacity(sh);
    let record_count = read_volatile((sh + SH_DMA_ALLOC_RECORD_COUNT) as *const u64);
    if record_capacity != dma_allocation_record_arena_capacity() || record_count > record_capacity {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let mut record_index = 0u64;
    while record_index < record_count {
        let Some(record) = dma_allocation_record(sh, record_index) else {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        };
        let logical = read_volatile(record as *const u64);
        let len = read_volatile((record + 8) as *const u64);
        let va = read_volatile((record + 16) as *const u64);
        if logical != 0 || len != 0 || va != 0 {
            if dma_adapter_id == 0
                || dma_adapter_blob == 0
                || dma_grant_va == 0
                || dma_grant_len == 0
                || dma_grant_logical == 0
                || logical < dma_grant_logical
                || va < dma_grant_va
                || len == 0
            {
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            let logical_offset = logical
                .checked_sub(dma_grant_logical)
                .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
            let va_offset = va
                .checked_sub(dma_grant_va)
                .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
            if logical_offset != va_offset
                || logical_offset > dma_grant_len
                || len > dma_grant_len - logical_offset
            {
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            hosted_dma_manager_mut()
                .register_common_buffer_at(
                    hosted_dma_owner(binding),
                    dma_adapter_id,
                    logical,
                    len,
                    va,
                )
                .map_err(hosted_dma_status)?;
        }
        record_index += 1;
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
    clear_shared_device_interface_state_at(sh);
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
    apply_hosted_device_interface_state(sh)?;

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

/// Whether the driver-declared `\Device\NamedPipe` route is ready to serve IRPs.
pub(crate) fn npfs_ready() -> bool {
    device_id_by_name("\\Device\\NamedPipe")
        .map(hosted_device_ready_for_dispatch)
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

pub(crate) fn print_active_driver_dispatch_for_deadman() {
    let seq = FSD_ACTIVE_DISPATCH_SEQ.load(Ordering::Relaxed);
    if seq == 0 {
        return;
    }
    let inst_index = FSD_ACTIVE_DISPATCH_INST.load(Ordering::Relaxed);
    let major = FSD_ACTIVE_DISPATCH_MAJOR.load(Ordering::Relaxed);
    let fsctl = FSD_ACTIVE_DISPATCH_FSCTL.load(Ordering::Relaxed);
    let file_id = FSD_ACTIVE_DISPATCH_FID.load(Ordering::Relaxed);
    let started = FSD_ACTIVE_DISPATCH_STARTED_100NS.load(Ordering::Relaxed);
    let elapsed = monotonic_time_100ns().saturating_sub(started) / 10_000;
    print_str(b"[deadman] active-driver-dispatch #");
    print_u64(seq);
    print_str(b" inst=");
    print_u64(inst_index);
    print_str(b" major=");
    print_u64(major);
    print_str(b" fsctl=");
    print_hex64(fsctl);
    print_str(b" fid=");
    print_hex64(file_id);
    print_str(b" in=");
    print_u64(FSD_ACTIVE_DISPATCH_IN.load(Ordering::Relaxed));
    print_str(b" out=");
    print_u64(FSD_ACTIVE_DISPATCH_OUT.load(Ordering::Relaxed));
    print_str(b" elapsed-ms=");
    print_u64(elapsed);
    print_str(b"\n");

    if let Some(inst) = instance(inst_index as usize) {
        if inst.tcb != 0 {
            let mut regs = [0u64; 20];
            unsafe {
                crate::win32k_glue::tcb_read_regs20(inst.tcb, &mut regs);
            }
            let rip = regs[nt_user_callback::USER_CONTEXT_RIP];
            print_str(b"[deadman] active-driver-regs rip=");
            print_hex64(rip);
            if (FSD_CODE_VA..FSD_CODE_VA + FSD_IMAGE_FRAMES * 0x1000).contains(&rip) {
                print_str(b" rva=");
                print_hex64(rip - FSD_CODE_VA);
            }
            print_str(b" rsp=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_RSP]);
            print_str(b" rax=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_RAX]);
            print_str(b" rcx=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_RCX]);
            print_str(b" rdx=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_RDX]);
            print_str(b" rsi=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_RSI]);
            print_str(b" rdi=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_RDI]);
            print_str(b" r8=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_R8]);
            print_str(b" r9=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_R9]);
            print_str(b" r10=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_R10]);
            print_str(b" r15=");
            print_hex64(regs[nt_user_callback::USER_CONTEXT_R15]);
            print_str(b"\n");

            let mut state = [0u64; crate::win32k_glue::TCB_DEBUG_STATE_WORDS];
            unsafe {
                crate::win32k_glue::tcb_read_debug_state(inst.tcb, inst.reply_cap, &mut state);
            }
            print_str(b"[deadman] active-driver-tcb state=");
            print_u64(state[crate::win32k_glue::TCB_DBG_STATE]);
            print_str(b" sched=");
            print_u64(state[crate::win32k_glue::TCB_DBG_SCHEDULABLE]);
            print_str(b" enq=");
            print_u64(state[crate::win32k_glue::TCB_DBG_ENQUEUED]);
            print_str(b" prio=");
            print_u64(state[crate::win32k_glue::TCB_DBG_PRIORITY]);
            print_str(b" sc=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_SC]);
            print_str(b" active_sc=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_ACTIVE_SC]);
            print_str(b" pend_reply=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_PENDING_REPLY]);
            print_str(b" reply_to=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_REPLY_TO]);
            print_str(b" ntfn=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_BOUND_NOTIFICATION]);
            print_str(b" call=");
            print_u64(state[crate::win32k_glue::TCB_DBG_BLOCKED_IS_CALL]);
            print_str(b" grant=");
            print_u64(state[crate::win32k_glue::TCB_DBG_BLOCKED_CAN_GRANT]);
            print_str(b" donated=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_DONATED_SC]);
            print_str(b" fault=");
            print_u64(state[crate::win32k_glue::TCB_DBG_PENDING_FAULT]);
            print_str(b" hosted=");
            print_u64(state[crate::win32k_glue::TCB_DBG_HOSTED_SYSCALLS]);
            print_str(b" reply_bound=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_REPLY_BOUND_TCB]);
            print_str(b" current=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_CURRENT_TCB]);
            print_str(b" target=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_TARGET_TCB]);
            print_str(b" comp-handoff=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_COMPOSITE_REPLY_HANDOFF]);
            print_str(b" aff=");
            print_u64(state[crate::win32k_glue::TCB_DBG_AFFINITY]);
            print_str(b" dom=");
            print_u64(state[crate::win32k_glue::TCB_DBG_DOMAIN]);
            print_str(b" cur-dom=");
            print_u64(state[crate::win32k_glue::TCB_DBG_CURRENT_DOMAIN]);
            print_str(b" qtop=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_QUEUE_TOP_PRIORITY]);
            print_str(b" direct=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_DIRECT_HANDOFF]);
            print_str(b" cspace=");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_CSPACE_INDEX]);
            print_str(b" fault-cap-kind=");
            print_u64(state[crate::win32k_glue::TCB_DBG_FAULT_CAP_KIND]);
            print_str(b" fault-cap-detail=");
            print_hex64(state[crate::win32k_glue::TCB_DBG_FAULT_CAP_DETAIL]);
            print_str(b" fault-ep=");
            print_u64(state[crate::win32k_glue::TCB_DBG_FAULT_EP_STATE]);
            print_str(b"/");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_FAULT_EP_HEAD]);
            print_str(b"/");
            print_tcb_debug_opt(state[crate::win32k_glue::TCB_DBG_FAULT_EP_TAIL]);
            print_str(b"\n");

            let mut exec_state = [0u64; crate::win32k_glue::TCB_DEBUG_STATE_WORDS];
            unsafe {
                crate::win32k_glue::tcb_read_debug_state(1, 0, &mut exec_state);
            }
            print_str(b"[deadman] executive-tcb state=");
            print_u64(exec_state[crate::win32k_glue::TCB_DBG_STATE]);
            print_str(b" sched=");
            print_u64(exec_state[crate::win32k_glue::TCB_DBG_SCHEDULABLE]);
            print_str(b" enq=");
            print_u64(exec_state[crate::win32k_glue::TCB_DBG_ENQUEUED]);
            print_str(b" prio=");
            print_u64(exec_state[crate::win32k_glue::TCB_DBG_PRIORITY]);
            print_str(b" sc=");
            print_tcb_debug_opt(exec_state[crate::win32k_glue::TCB_DBG_SC]);
            print_str(b" current=");
            print_tcb_debug_opt(exec_state[crate::win32k_glue::TCB_DBG_CURRENT_TCB]);
            print_str(b" target=");
            print_tcb_debug_opt(exec_state[crate::win32k_glue::TCB_DBG_TARGET_TCB]);
            print_str(b" comp-handoff=");
            print_tcb_debug_opt(exec_state[crate::win32k_glue::TCB_DBG_COMPOSITE_REPLY_HANDOFF]);
            print_str(b" aff=");
            print_u64(exec_state[crate::win32k_glue::TCB_DBG_AFFINITY]);
            print_str(b" dom=");
            print_u64(exec_state[crate::win32k_glue::TCB_DBG_DOMAIN]);
            print_str(b" cur-dom=");
            print_u64(exec_state[crate::win32k_glue::TCB_DBG_CURRENT_DOMAIN]);
            print_str(b" qtop=");
            print_tcb_debug_opt(exec_state[crate::win32k_glue::TCB_DBG_QUEUE_TOP_PRIORITY]);
            print_str(b" direct=");
            print_tcb_debug_opt(exec_state[crate::win32k_glue::TCB_DBG_DIRECT_HANDOFF]);
            print_str(b"\n");
        }
        unsafe {
            print_active_irp_graph_for_deadman(&inst);
            print_pipe_queue_heads_for_deadman(
                file_id,
                &inst,
                FSD_ACTIVE_DISPATCH_OUT.load(Ordering::Relaxed),
            );
            if let Some(view) = pipe_ccb_view_in_pool(file_id, inst.exec_pool_va) {
                print_pipe_ccb_view(b"[deadman] active-driver-ccb", view);
                print_str(b"\n");
            }
        }
    }
}

/// Route one IRP to launched driver `inst`: fill the shared request fields, drive its dispatch loop
/// (a plain Send wakes it; it runs `MajorFunction[major]` in its own context; a fault mid-IRP lands
/// on its fault EP → demand-map + resume), then read back the completion. Returns `(status,
/// information)`. `major` is an `IRP_MJ_*`; `in_data` is copied into the instance's ARG frame
/// (buffered I/O); `out` receives the driver's output. Returns `None` if `inst` isn't ready.
///
/// This is the private component transport engine. Public callers route through driver/device ids.
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
    write_volatile((sh + SH_ACTIVE_IRP) as *mut u64, 0);
    write_volatile((sh + SH_ACTIVE_IOSL) as *mut u64, 0);
    write_volatile((sh + SH_ACTIVE_DATA) as *mut u64, 0);
    write_volatile((sh + SH_ACTIVE_DATA_CAP) as *mut u64, 0);
    write_volatile((sh + SH_ACTIVE_FILE_OBJECT) as *mut u64, 0);

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
        exec_code_va: ExecVaWindow::try_for_instance(inst)?.code_va,
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
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            io_port_faults: read_volatile((sh + SH_RESOURCE_IO_PORT_CAP) as *const u64) != 0,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let bugchecks_before = FSD_BUGCHECKS.load(Ordering::Relaxed);
    // DIAGNOSTIC (bounded): an IRP dispatch is the one place the executive blocks on a hosted
    // component, so an `ENTER` with no matching `EXIT` is the signature of a driver that never
    // returned.
    let dispatch_seq = FSD_DISPATCH_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    FSD_ACTIVE_DISPATCH_SEQ.store(dispatch_seq, Ordering::Relaxed);
    FSD_ACTIVE_DISPATCH_INST.store(inst as u64, Ordering::Relaxed);
    FSD_ACTIVE_DISPATCH_MAJOR.store(major, Ordering::Relaxed);
    FSD_ACTIVE_DISPATCH_FSCTL.store(fsctl, Ordering::Relaxed);
    FSD_ACTIVE_DISPATCH_FID.store(file_id, Ordering::Relaxed);
    FSD_ACTIVE_DISPATCH_IN.store(in_data.len() as u64, Ordering::Relaxed);
    FSD_ACTIVE_DISPATCH_OUT.store(out.len() as u64, Ordering::Relaxed);
    FSD_ACTIVE_DISPATCH_STARTED_100NS.store(monotonic_time_100ns(), Ordering::Relaxed);
    let trace_dispatch = dispatch_seq <= FSD_DISPATCH_TRACE_CAP;
    if trace_dispatch {
        print_str(b"[fsd-svc] ENTER inst=");
        print_u64(inst as u64);
        print_str(b" #");
        print_u64(dispatch_seq);
        print_str(b" major=");
        print_u64(major);
        if fsctl != 0 {
            print_str(b" fsctl=0x");
            print_hex(fsctl as u32);
        }
        print_str(b" fid=");
        print_hex(file_id as u32);
        print_str(b" in=");
        print_u64(in_data.len() as u64);
        print_str(b" out=");
        print_u64(out.len() as u64);
        print_str(b"\n");
    }
    let pr = crate::spawn_hosts::component_pump(&ch);
    FSD_ACTIVE_DISPATCH_SEQ.store(0, Ordering::Relaxed);
    if trace_dispatch {
        print_str(b"[fsd-svc] EXIT inst=");
        print_u64(inst as u64);
        print_str(b" #");
        print_u64(dispatch_seq);
        print_str(b" major=");
        print_u64(major);
        print_str(b" status=");
        print_hex(pr.status as u32);
        print_str(b" completed=");
        print_u64(pr.completed as u64);
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
    dispatch_irp_to_driver_result(driver_id, major, fsctl, file_id, in_data, out).ok()
}

pub(crate) unsafe fn dispatch_irp_to_driver_result(
    driver_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Result<(i32, u64), u32> {
    let Some((_, inst)) = instance_by_driver_id(driver_id) else {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    };
    if !inst.ready || inst.driver_object == 0 {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    }
    if io_manager_mut().driver(DriverId(driver_id)).is_none() {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    }
    dispatch_external_irp_to_driver_record_result(driver_id, major, fsctl, file_id, in_data, out)
}

pub(crate) unsafe fn dispatch_irp_to_device_result(
    device_id: u64,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Result<(i32, u64), u32> {
    require_hosted_device_ready_for_dispatch(device_id)?;
    dispatch_external_irp_to_device_record_result(device_id, major, fsctl, file_id, in_data, out)
}

pub(crate) unsafe fn cancel_pending_file_irps(
    device_id: u64,
    file_id: u64,
) -> Result<u64, u32> {
    let binding = hosted_device_binding_by_device_id(device_id)
        .ok_or(STATUS_DEVICE_NOT_READY as u32)?;
    let Some((_, inst)) = instance_by_driver_id(binding.driver_id) else {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    };
    if !inst.ready || inst.driver_id == 0 || binding.device_object == 0 {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    }
    if io_manager_mut()
        .device(nt_io_manager::DeviceId(device_id))
        .is_none()
    {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    }
    let mut out = [];
    let (status, cancelled) = dispatch_irp_for_instance(
        binding.instance,
        FSD_DISPATCH_CANCEL_PENDING_FILE,
        0,
        binding.device_object,
        0,
        file_id,
        &[],
        &mut out,
    )
    .ok_or(STATUS_DEVICE_NOT_READY as u32)?;
    if status == 0 {
        Ok(cancelled)
    } else {
        Err(status as u32)
    }
}

fn hosted_device_ready_for_dispatch(device_id: u64) -> bool {
    require_hosted_device_ready_for_dispatch(device_id).is_ok()
}

fn require_hosted_device_ready_for_dispatch(device_id: u64) -> Result<(), u32> {
    let Some(binding) = hosted_device_binding_by_device_id(device_id) else {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    };
    let Some((_, inst)) = instance_by_driver_id(binding.driver_id) else {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    };
    if !inst.ready || inst.driver_id == 0 || binding.device_object == 0 {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    }
    if io_manager_mut()
        .device(nt_io_manager::DeviceId(device_id))
        .is_none()
    {
        return Err(STATUS_DEVICE_NOT_READY as u32);
    }
    Ok(())
}

unsafe fn dispatch_irp_to_named_device(
    path: &str,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    dispatch_irp_to_named_device_result(path, major, fsctl, file_id, in_data, out).ok()
}

unsafe fn dispatch_irp_to_named_device_result(
    path: &str,
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Result<(i32, u64), u32> {
    let device_id = device_id_by_name(path).ok_or(STATUS_DEVICE_NOT_READY as u32)?;
    dispatch_irp_to_device_result(device_id, major, fsctl, file_id, in_data, out)
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

pub(crate) unsafe fn npfs_dispatch_irp_result(
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Result<(i32, u64), u32> {
    dispatch_irp_to_named_device_result("\\Device\\NamedPipe", major, fsctl, file_id, in_data, out)
}
