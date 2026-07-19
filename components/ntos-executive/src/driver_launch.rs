//! `driver_launch` — the GENERAL DYNAMIC driver-launch path (the NT `IoLoadDriver`/`NtLoadDriver`
//! / SCM driver-start model). Take a driver name/path → load the `.sys` by-path from the FS →
//! determine its POLICY CLASS → build a [`ComponentDescriptor`] → `spawn_component` it ISOLATED →
//! run its real `DriverEntry` in the component (capturing its MajorFunction table + device object).
//!
//! This GENERALIZES the bespoke boot-time spawners (`spawn_driver_host` NIC, `spawn_storage_host`,
//! `spawn_kmdf_host`, `spawn_win32k_host`) into ONE runtime service — like Win32 `CreateProcess` /
//! the general `NtCreateThread`. Any `.sys` becomes launchable dynamically. The first client is
//! **npfs.sys** (an FSD-class descriptor, NO device caps).
//!
//! POLICY CLASSES (see `project_driver_model.md`):
//!   * [`DriverClass::Fsd`]    — file-system drivers (npfs, fastfat, ntfs): image + heap/pool + stack
//!     + IPC-buf + fault EP + a shared handoff page; NO device caps.
//!   * [`DriverClass::Device`] — hardware drivers (NIC/AHCI/GPU): the device-cap section is populated
//!     by `nt-pnp` (MMIO BARs / IRQ / DMA). SEAM ONLY here (out of scope for this increment).
//!   * [`DriverClass::Filter`]  — FS/bus filter drivers: the SAME IRP substrate + caps as `Fsd`.
//!   * [`DriverClass::GuiSyscallServer`] — win32k: a unique privileged class (kept bespoke — its
//!     Syscall substrate + paint-loop protocol are NOT routed through the IRP builder here).
//!
//! The existing bespoke spawners are follow-on migrations onto this path (their descriptor-builders
//! already exist post effort-1); this increment builds the general path + proves it with npfs.

use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};

use nt_compat_exports::DriverExportRegistry;
use nt_io_abi::major;

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
// cannot both map at `FSD_CODE_VA`. Instance 0 (npfs) keeps the fixed VAs EXACTLY (byte-identical);
// instance N≥1 gets a distinct executive window at `FSD_EXEC_BASE + (N-1)*FSD_EXEC_STRIDE`, well clear
// of every other executive mapping (past the 48 MiB file pool at 0x100_1500_0000..0x100_1800_0000).
//
// The PE is RELOCATED for its EXECUTION VA (`FSD_CODE_VA`, same across instances) via `load_pe_into`'s
// `run_va` — decoupled from the executive load VA — so instance N runs correctly at `FSD_CODE_VA` in
// its own VSpace while the executive loaded its bytes at a distinct window.
pub const FSD_EXEC_BASE: u64 = 0x0000_0100_1A00_0000;
pub const FSD_EXEC_STRIDE: u64 = 0x0000_0000_0100_0000; // 16 MiB per instance window

/// The executive-side VA window for launching an instance's frames. Instance 0 == the fixed
/// (npfs) VAs (behavior-preserving); instance N≥1 == a distinct high window.
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
                code_va: base,                  // 256 KiB image window (fits in the first 2 MiB PT)
                data_va: base + 0x0030_0000,    // DATA (4 frames)
                shared_va: base + 0x0038_0000,  // SHARED (1 frame)
                arg_va: base + 0x003A_0000,     // ARG (4 frames)
                aux_pt_va: base + 0x0020_0000,  // aux PT covering the 2 MiB region holding DATA/SHARED/ARG
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
// IRP dispatch request/reply (executive → FSD, via the shared page).
pub const SH_REQ_MAJOR: u64 = 0x40; // in:  IRP_MJ_* major function (u64)
pub const SH_REQ_MINOR: u64 = 0x48; // in:  minor function (u64)
pub const SH_REQ_FSCTL: u64 = 0x50; // in:  control code or FILE_INFORMATION_CLASS (u64)
pub const SH_REQ_INLEN: u64 = 0x58; // in:  input buffer length (u64)
pub const SH_REQ_OUTLEN: u64 = 0x60; // in:  output buffer length (u64)
pub const SH_REQ_FILEID: u64 = 0x68; // in/out: opaque FILE_OBJECT id (u64)
pub const SH_REQ_STATUS: u64 = 0x70; // out: IoStatus.Status (i32)
pub const SH_REQ_INFO: u64 = 0x78; // out: IoStatus.Information (u64)

// --- verdict bits ----------------------------------------------------------------------------

pub const V_ENTERED: u32 = 1; // host called into DriverEntry
pub const V_RETURNED: u32 = 2; // DriverEntry returned (did not fault)
pub const V_SUCCESS: u32 = 4; // DriverEntry returned STATUS_SUCCESS
pub const V_DEVICE: u32 = 8; // IoCreateDevice(control device) succeeded
pub const V_MJ: u32 = 0x10; // DriverObject->MajorFunction[IRP_MJ_CREATE] is non-null (table filled)
pub const V_REGFS: u32 = 0x20; // IoRegisterFileSystem was called

/// The IPC message label the dispatch loop uses to Send its ready/done signal on the fault EP.
/// Distinct from the small fault labels (VMFault=6, …), so the executive tells them apart.
pub const FSD_DISPATCH_LABEL: u64 = 0x771;

const POOL_DATA_OFF: u64 = 0x1000;
const STATUS_PENDING: u32 = 0x0000_0103;

const IRP_MJ_READ: u64 = major::IRP_MJ_READ as u64;
const IRP_MJ_WRITE: u64 = major::IRP_MJ_WRITE as u64;
const IRP_MJ_SET_INFORMATION: u64 = major::IRP_MJ_SET_INFORMATION as u64;

#[derive(Clone, Copy)]
struct PendingIrp {
    irp: u64,
    iosl: u64,
    file_object: u64,
    data: u64,
    major: u8,
}

const PENDING_IRP_CAP: usize = 32;
static mut PENDING_IRPS: [PendingIrp; PENDING_IRP_CAP] = [PendingIrp {
    irp: 0,
    iosl: 0,
    file_object: 0,
    data: 0,
    major: 0,
}; PENDING_IRP_CAP];
static mut DATA_TRACE_COUNT: u32 = 0;
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
const COMPLETED_READ_CAP: usize = 8;
const COMPLETED_READ_BYTES: usize = 4096;
#[derive(Clone, Copy)]
struct CompletedRead {
    fid: u64,
    status: u32,
    info: u64,
    len: usize,
    bytes: [u8; COMPLETED_READ_BYTES],
}
static mut COMPLETED_READS: [CompletedRead; COMPLETED_READ_CAP] = [CompletedRead {
    fid: 0,
    status: 0,
    info: 0,
    len: 0,
    bytes: [0u8; COMPLETED_READ_BYTES],
}; COMPLETED_READ_CAP];

/// Take (consume) a stashed completed-pending-read for `fid`, if any. Returns `(status, info, bytes)`.
pub(crate) unsafe fn take_completed_read(fid: u64) -> Option<(u32, u64, alloc::vec::Vec<u8>)> {
    let table = &mut *core::ptr::addr_of_mut!(COMPLETED_READS);
    let slot = table.iter_mut().find(|e| e.fid == fid && e.fid != 0)?;
    let bytes = slot.bytes[..slot.len].to_vec();
    let out = (slot.status, slot.info, bytes);
    slot.fid = 0;
    Some(out)
}

// --- host-side pool allocator (the trampolines run in the component) --------------------------

/// A simple free-list allocator: an FSD alloc/frees file objects; a leak-forever bump would exhaust
/// under FSCTL churn. Header = 16 B ([+0]=capacity, [+8]=next-free). `pool_free` pushes onto the
/// single free list (head @ [POOL+8]); `pool_alloc` first-fits it before bumping. Counter @ [POOL+0].
pub(crate) unsafe fn pool_alloc(size: u64) -> u64 {
    // first-fit the free list
    let head_slot = (FSD_POOL_VADDR + 8) as *mut u64;
    let mut prev = head_slot;
    let mut cur = read_volatile(head_slot);
    while cur != 0 {
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

unsafe fn pool_free(p: u64) {
    if p == 0 || p < FSD_POOL_VADDR + POOL_DATA_OFF {
        return;
    }
    let head_slot = (FSD_POOL_VADDR + 8) as *mut u64;
    let head = read_volatile(head_slot);
    write_volatile((p - 8) as *mut u64, head);
    write_volatile(head_slot, p);
}

// --- ntoskrnl trampolines (extern "win64"; args = rcx, rdx, r8, r9, then stack) --------------

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

/// `NTSTATUS IoCreateDevice(PDRIVER_OBJECT, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName,
/// DEVICE_TYPE, ULONG Characteristics, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject)`.
/// Allocate a DEVICE_OBJECT (with the requested extension) from the pool, minimally initialize it,
/// link it onto DriverObject->DeviceObject, and return it via the out-param. Records the device in
/// the shared page (the executive resolves the FSD's control device to it).
extern "win64" fn s_io_create_device(
    drv: u64,
    ext_size: u64,
    _name: u64,
    dev_type: u64,
    _chars: u64,
    _excl: u64,
    dev_out: u64,
) -> i32 {
    unsafe {
        // DEVICE_OBJECT is ~0x150 bytes (x64); allocate that + the driver extension contiguously.
        let dev = pool_alloc(0x150 + ext_size);
        if dev == 0 {
            return 0xC000_009Au32 as i32; // STATUS_INSUFFICIENT_RESOURCES
        }
        // zero the body
        let mut i = 0u64;
        while i < 0x150 + ext_size {
            write_unaligned((dev + i) as *mut u64, 0);
            i += 8;
        }
        // x64 DEVICE_OBJECT layout (references/nt5 io.h): Type@0, Size@2, DriverObject@8,
        // NextDevice@0x10, CurrentIrp@0x20, Flags@0x30, DeviceExtension@0x40, DeviceType@0x48.
        write_unaligned(dev as *mut i16, 3); // IO_TYPE_DEVICE
        write_unaligned((dev + 2) as *mut u16, 0x150);
        write_unaligned((dev + 8) as *mut u64, drv); // DriverObject
        if ext_size != 0 {
            write_unaligned((dev + 0x40) as *mut u64, dev + 0x150); // DeviceExtension (past the body)
        }
        write_unaligned((dev + 0x48) as *mut u32, dev_type as u32); // DeviceType
        // link onto DriverObject->DeviceObject@8 (NextDevice@0x10).
        if drv != 0 {
            let head = read_unaligned((drv + 8) as *const u64);
            write_unaligned((dev + 0x10) as *mut u64, head);
            write_unaligned((drv + 8) as *mut u64, dev);
        }
        if dev_out != 0 {
            write_unaligned(dev_out as *mut u64, dev);
        }
        // record it for the executive
        write_volatile((FSD_SHARED_VADDR + SH_DEVOBJ) as *mut u64, dev);
        let v = read_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *const u32);
        write_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *mut u32, v | V_DEVICE);
    }
    0 // STATUS_SUCCESS
}

/// `NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING, PUNICODE_STRING)` — no-op success (the executive
/// object namespace owns \?? symlinks; the driver just declares one).
extern "win64" fn s_io_create_symbolic_link(_a: u64, _b: u64) -> i32 {
    0
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
            let fid = read_unaligned((slot.file_object + 0x18) as *const u64);
            // The buffer npfs actually filled = the IRP's CURRENT SystemBuffer (it may have reassigned
            // it). Fall back to our original buffer only if npfs left it in place.
            let sysbuf = read_unaligned((irp + 0x18) as *const u64);
            let src = if sysbuf != 0 { sysbuf } else { slot.data };
            let n = (information as usize).min(COMPLETED_READ_BYTES);
            let ctable = &mut *core::ptr::addr_of_mut!(COMPLETED_READS);
            if let Some(cslot) = ctable.iter_mut().find(|e| e.fid == 0) {
                cslot.fid = fid;
                cslot.status = status;
                cslot.info = information;
                cslot.len = n;
                let mut i = 0usize;
                while i < n {
                    cslot.bytes[i] = read_volatile((src + i as u64) as *const u8);
                    i += 1;
                }
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
        pool_free(slot.data);
        pool_free(slot.iosl);
        pool_free(slot.irp);
        pool_free(slot.file_object);
        *slot = PendingIrp { irp: 0, iosl: 0, file_object: 0, data: 0, major: 0 };
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
    entry: u64,   // the PUNICODE_PREFIX_TABLE_ENTRY the FSD passed to Insert (returned by Find)
    name_va: u64, // UNICODE_STRING.Buffer VA
    name_len: u16, // UNICODE_STRING.Length (bytes)
    used: bool,
}

const PREFIX_CAP: usize = 64;

/// The single VCB prefix table (npfs is a singleton driver). Lives in the executive image `.bss`
/// (shared into the component). Populated by `s_rtl_insert_unicode_prefix`, queried by
/// `s_rtl_find_unicode_prefix`. Reset by `s_rtl_init_unicode_prefix`.
static mut PREFIX_TABLE: [PrefixSlot; PREFIX_CAP] =
    [PrefixSlot { entry: 0, name_va: 0, name_len: 0, used: false }; PREFIX_CAP];

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
            *s = PrefixSlot { entry: 0, name_va: 0, name_len: 0, used: false };
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
            if en == nn && nt_kernel_exec::np_prefix::is_component_prefix(&ex[..en], &new[..nn]) && nn == en {
                return 0; // duplicate
            }
        }
        for s in table.iter_mut() {
            if !s.used {
                *s = PrefixSlot { entry, name_va, name_len, used: true };
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
            if nt_kernel_exec::np_prefix::is_component_prefix(&cbuf[..cn], &fbuf[..fn_]) && cn >= best_len {
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
    reg.bind("ExAllocatePoolWithQuotaTag", s_ex_alloc_pool_quota_tag as usize as u64);
    reg.bind("ExAllocatePool", s_ex_alloc_pool as usize as u64);
    reg.bind("ExFreePoolWithTag", s_ex_free_pool_tag as usize as u64);
    reg.bind("ExFreePool", s_ex_free_pool as usize as u64);
    // Rtl string init
    reg.bind("RtlInitUnicodeString", s_rtl_init_unicode_string as usize as u64);
    reg.bind("RtlInitEmptyUnicodeString", s_rtl_init_empty_unicode_string as usize as u64);
    // Io device/registration (control DEVICE_OBJECT + FS registration)
    reg.bind("IoCreateDevice", s_io_create_device as usize as u64);
    reg.bind("IoCreateSymbolicLink", s_io_create_symbolic_link as usize as u64);
    reg.bind("IoRegisterFileSystem", s_io_register_file_system as usize as u64);
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
    reg.bind("RtlInitializeUnicodePrefix", s_rtl_init_unicode_prefix as usize as u64);
    reg.bind("RtlInsertUnicodePrefix", s_rtl_insert_unicode_prefix as usize as u64);
    reg.bind("RtlFindUnicodePrefix", s_rtl_find_unicode_prefix as usize as u64);
    reg.bind("RtlInitializeGenericTable", s_rtl_init_generic_table as usize as u64);
    // ERESOURCE acquire/release (uncontended single-threaded host)
    reg.bind("ExAcquireResourceExclusiveLite", s_acquire_resource as usize as u64);
    reg.bind("ExAcquireResourceSharedLite", s_acquire_resource as usize as u64);
    reg.bind("ExAcquireSharedStarveExclusive", s_acquire_resource as usize as u64);
    reg.bind("ExAcquireSharedWaitForExclusive", s_acquire_resource as usize as u64);
    reg.bind("ExReleaseResourceLite", s_release_resource as usize as u64);
    reg.bind("ExReleaseResourceForThreadLite", s_release_resource as usize as u64);
    // CRT / Rtl mem intrinsics (REAL — silent corruption otherwise)
    reg.bind("memcpy", s_memcpy as usize as u64);
    reg.bind("memmove", s_memcpy as usize as u64);
    reg.bind("RtlCopyMemory", s_memcpy as usize as u64);
    reg.bind("RtlMoveMemory", s_memcpy as usize as u64);
    reg.bind("memset", s_memset as usize as u64);
    reg.bind("RtlFillMemory", s_memset as usize as u64);
    reg.bind("RtlCompareMemory", s_rtl_compare_memory as usize as u64);
    reg.bind("RtlCompareMemoryUlong", s_rtl_compare_memory as usize as u64);
    reg.bind("RtlUpcaseUnicodeChar", s_rtl_upcase_char as usize as u64);
    // small-struct init (spinlock/event/timer/dpc/mutex/semaphore/ERESOURCE init)
    reg.bind("ExInitializeResourceLite", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeSpinLock", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeEvent", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeTimer", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeDpc", s_init_small_struct as usize as u64);
    reg.bind("ExInitializeFastMutex", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeMutex", s_init_small_struct as usize as u64);
    reg.bind("KeInitializeSemaphore", s_init_small_struct as usize as u64);
    // Se / Ob security helpers
    reg.bind("IoGetFileObjectGenericMapping", s_generic_mapping as usize as u64);
    reg.bind("SeAssignSecurity", s_se_assign_security as usize as u64);
    reg.bind("ObLogSecurityDescriptor", s_ob_log_sd as usize as u64);
    // Ps/Io current-object identity
    reg.bind("PsGetCurrentProcess", s_current_process as usize as u64);
    reg.bind("PsGetCurrentThread", s_current_process as usize as u64);
    reg.bind("KeGetCurrentThread", s_current_process as usize as u64);
    reg.bind("IoGetCurrentProcess", s_io_get_current_process as usize as u64);
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
/// [`fsd_post_driver_entry`], and the FSD [`DriverObjectSpec`] (size 0x150, ext ptr @0x68, ext size
/// 0x50, MajorFunction @0x70). The bespoke inline `dispatch_loop`/`send_done`/`recv_req` are retired
/// in favour of the harness's shared implementation (`send_done_on`/`recv_req_on`). This is the
/// component-side leg of the FSD's migration onto the unified harness (Phase B, Step 2). Both the
/// npfs instance and the 2nd `IrpFsdTest.sys` instance share this entry, so BOTH now run on the harness.
/// Runs in the isolated component's VSpace (executive image mapped RWX-shared).
#[no_mangle]
#[link_section = ".text.fsd_component_entry"]
pub unsafe extern "C" fn fsd_component_entry() -> ! {
    let entry_rva = read_volatile((FSD_SHARED_VADDR + SH_ENTRY_RVA) as *const u64) as u32;
    print_str(b"[fsd-host] START DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");

    // The x64 DRIVER_OBJECT is 0x150 bytes: Type@0=4, Size@2, DriverExtension ptr @0x68 (ext block
    // 0x50), MajorFunction[]@0x70 (28 entries * 8 = 0xE0 → ends at 0x150). Hand the whole preamble +
    // persistent recv→dispatch→reply loop to the SHARED harness.
    crate::spawn_hosts::component_main(
        FSD_SHARED_VADDR,
        FSD_CODE_VA,
        crate::spawn_hosts::DriverObjectSpec {
            size: 0x150,
            size_field: 0x150,
            ext: 0x68,
            ext_size: 0x50,
            mj: 0x70,
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
    let v = read_volatile((FSD_SHARED_VADDR + SH_VERDICT) as *const u32);
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
    print_str(b"\n");
}

/// The FSD IRP router — the `dispatch` callback plugged into [`crate::spawn_hosts::component_main`].
/// Reads the request's IRP major from `req.sel`, looks up `DriverObject->MajorFunction[major]`, and
/// runs the driver's handler via [`run_irp`] in this component's context. Returns `(status, info)`.
/// This is the EXACT body the retired inline `dispatch_loop` ran per request.
unsafe fn fsd_dispatch(req: &crate::spawn_hosts::DispatchReq) -> (i32, u64) {
    let major = req.sel;
    let mj_base = req.drv + 0x70;
    let handler = read_volatile((mj_base + major * 8) as *const u64);
    if handler != 0 {
        run_irp(major, handler)
    } else {
        (0xC000_0002u32 as i32, 0) // STATUS_NOT_IMPLEMENTED
    }
}

/// Generic (label-parameterised) ready/done signal for the shared [`crate::spawn_hosts::component_main`]
/// harness: a plain `seL4_Send(CT_FAULT, label)` (Send/Recv, NOT Call — the win32k fix-A rationale).
/// The FSD dispatch loop (now the harness's) Sends [`FSD_DISPATCH_LABEL`] through this.
#[inline(never)]
pub(crate) unsafe fn send_done_on(label: u64) {
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_SEND as u64,
        in("rdi") crate::CT_FAULT,
        in("rsi") label << 12,
        in("r10") 0u64, in("r8") 0u64, in("r9") 0u64, in("r15") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// Block for the next dispatch request for the shared [`crate::spawn_hosts::component_main`]
/// harness: a plain `seL4_Recv(CT_FAULT)`.
#[inline(never)]
pub(crate) unsafe fn recv_req_on() {
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_RECV as u64,
        inout("rdi") crate::CT_FAULT => _,
        lateout("rsi") _, lateout("r10") _, lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
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
    let inlen = read_volatile((FSD_SHARED_VADDR + SH_REQ_INLEN) as *const u64);
    let outlen = read_volatile((FSD_SHARED_VADDR + SH_REQ_OUTLEN) as *const u64);
    let fsctl = read_volatile((FSD_SHARED_VADDR + SH_REQ_FSCTL) as *const u64);

    // FILE_OBJECT (0x100 bytes) — DeviceObject + FileName (points at the ARG frame name buffer).
    let fo = pool_alloc(0x100);
    zero(fo, 0x100);
    write_unaligned(fo as *mut i16, 5); // Type = IO_TYPE_FILE
    write_unaligned((fo + 2) as *mut u16, 0x100);
    write_unaligned((fo + 8) as *mut u64, devobj); // DeviceObject
    // Follow-up IRPs rebuild a transient FILE_OBJECT around the context returned by CREATE/OPEN.
    let file_id = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
    write_unaligned((fo + 0x18) as *mut u64, file_id); // FsContext
    // FileName UNICODE_STRING @0x58 = { Length=inlen, MaximumLength=inlen+2, Buffer=ARG frame }.
    write_unaligned((fo + 0x58) as *mut u16, inlen as u16); // Length (bytes)
    write_unaligned((fo + 0x5a) as *mut u16, (inlen + 2) as u16); // MaximumLength
    write_unaligned((fo + 0x60) as *mut u64, FSD_ARG_VADDR); // Buffer = the pipe name (UTF-16)

    // Give every request its own buffered-I/O storage. The ARG frame is transport scratch and is
    // overwritten by the next dispatch, so it cannot back an IRP retained in an npfs data queue.
    let data_len = inlen.max(outlen).max(1);
    let data_capacity = (data_len + 7) & !7;
    let data = pool_alloc(data_capacity);
    if data == 0 {
        pool_free(fo);
        return (0xC000_009Au32 as i32, 0); // STATUS_INSUFFICIENT_RESOURCES
    }
    zero(data, data_capacity);
    let mut data_index = 0u64;
    while data_index < inlen {
        let byte = read_volatile((FSD_ARG_VADDR + data_index) as *const u8);
        write_volatile((data + data_index) as *mut u8, byte);
        data_index += 1;
    }

    // IRP (0x120 bytes).
    let irp = pool_alloc(0x120);
    zero(irp, 0x120);
    // Both buffered-I/O views refer to request-owned storage. Writes/sets arrive through `inlen`;
    // reads reserve `outlen` and are copied back to the ARG transport only after completion.
    write_unaligned((irp + 0x18) as *mut u64, data);
    write_unaligned((irp + 0x70) as *mut u64, data); // UserBuffer
    // CurrentLocation@0x42 = 1, StackCount@0x43 = 1 (IoGetCurrentIrpStackLocation asserts this).
    write_unaligned((irp + 0x42) as *mut u8, 1);
    write_unaligned((irp + 0x43) as *mut u8, 1);

    // IO_STACK_LOCATION (0x48 bytes).
    let iosl = pool_alloc(0x48);
    zero(iosl, 0x48);
    write_unaligned(iosl as *mut u8, major as u8); // MajorFunction
    write_unaligned((iosl + 1) as *mut u8, 0); // MinorFunction
    write_unaligned((iosl + 0x20) as *mut u64, devobj); // DeviceObject
    write_unaligned((iosl + 0x30) as *mut u64, fo); // FileObject
    // Parameters union @ iosl+0x08. Layouts (references/reactos ndk/iotypes.h; POINTER_ALIGNMENT =
    // DECLSPEC_ALIGN(8) on x64 → Reserved/FileAttributes 8-align, ShareAccess follows, next ptr 8-aligns):
    //  Create/CreatePipe: SecurityContext@iosl+0x08, Options@iosl+0x10, ShareAccess(USHORT)@iosl+0x1a,
    //    Parameters@iosl+0x20.
    //  Read/Write: Length(ULONG)@0x08, Key@0x10, ByteOffset(LARGE_INTEGER)@0x18.
    //  SetFile: Length(ULONG)@0x08, FileInformationClass (8-aligned) @0x10.
    //  FS/DeviceControl: OutputBufferLength@0x08, InputBufferLength@0x10, IoControlCode@0x18,
    //    Type3InputBuffer@0x20.
    match major {
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
            write_unaligned((iosl + 0x10) as *mut u32, disposition << 24);
            write_unaligned((iosl + 0x1a) as *mut u16, 3); // ShareAccess = FILE_SHARE_READ|WRITE (full duplex)
            if major == 1 {
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
                write_unaligned((iosl + 0x20) as *mut u64, params); // Parameters
            }
        }
        IRP_MJ_READ => {
            write_unaligned((iosl + 0x08) as *mut u32, outlen as u32);
        }
        IRP_MJ_WRITE => {
            write_unaligned((iosl + 0x08) as *mut u32, inlen as u32);
        }
        IRP_MJ_SET_INFORMATION => {
            write_unaligned((iosl + 0x08) as *mut u32, inlen as u32);
            write_unaligned((iosl + 0x10) as *mut u32, fsctl as u32);
        }
        0xd | 0xe => {
            write_unaligned((iosl + 0x08) as *mut u32, outlen as u32);
            write_unaligned((iosl + 0x10) as *mut u32, inlen as u32);
            write_unaligned((iosl + 0x18) as *mut u32, fsctl as u32);
        }
        _ => {}
    }
    write_unaligned((irp + 0xb8) as *mut u64, iosl); // CurrentStackLocation

    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(handler as *const ());
    let ret = f(devobj, irp);

    let irp_status = read_unaligned((irp + 0x30) as *const i32);
    let info = read_unaligned((irp + 0x38) as *const u64);
    let st = if irp_status != 0 || info != 0 { irp_status } else { ret };
    // FsContext lands in the FILE_OBJECT; report it as the opaque file id (for future read/write).
    let fsctx = read_unaligned((fo + 0x18) as *const u64);
    write_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *mut u64, fsctx);
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
        pool_free(iosl);
        pool_free(irp);
        pool_free(fo);
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
    // Future-wiring: a user-specified filter-driver class seam (design §5.4); no `DriverSpec`
    // constructs it yet, but `caps_and_layout_for` already routes it. Intentional — matches `Device`.
    #[allow(dead_code)]
    Filter,
    /// Hardware device driver — same IRP substrate as [`Fsd`], plus a device-cap section (MMIO BAR
    /// frames / DMA / IRQ) that `nt-pnp` populates. The device caps/regions are a SEAM (not minted
    /// here yet); routed through the same `load_driver` Family-A path.
    #[allow(dead_code)]
    Device,
    /// The GUI syscall server (**win32k ONLY** — a unique privileged class). Its caps
    /// (`client_attach`/`usermode_callback`/`wide_arg_marshal`/`assert_skip`/`nested_reply_cap`) are
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
        DriverClass::Fsd | DriverClass::Filter => {
            (HostCaps { dispatch_server: true, kind: ReqKind::Irp, ..HostCaps::default() }, false)
        }
        // Same IRP substrate; ONLY the granted-cap/region device section differs (nt-pnp populates it).
        DriverClass::Device => {
            (HostCaps { dispatch_server: true, kind: ReqKind::Irp, ..HostCaps::default() }, true)
        }
        // win32k's unique privileged class — NOT routed through load_driver's IRP builder.
        DriverClass::GuiSyscallServer => (HostCaps::default(), false),
    }
}

/// A user-specifiable driver to launch by-path: the `.sys` path + its policy [`DriverClass`]. The
/// boot iterates a static [`DRIVERS`] list, calling [`load_driver`] for each — the "user specifies
/// drivers to run" surface (registry `\Services` / boot-arg population is a later increment; a static
/// list proves the reuse). Adding a driver = stage the `.sys` by-path + add ONE `DriverSpec`.
#[derive(Clone, Copy)]
pub(crate) struct DriverSpec {
    pub path: &'static [u8],
    pub class: DriverClass,
}

/// A launched, isolated driver component — the caps + VAs the executive keeps to route IRPs to it.
pub(crate) struct DriverComponent {
    /// The component's VSpace (PML4 cap) — for demand-mapping pages / cross-AS reads.
    pub pml4: u64,
    /// The component's fault endpoint (also the IRP dispatch channel: plain Send/Recv).
    pub fault_ep: u64,
    /// The recorded control DEVICE_OBJECT VA (\Device\NamedPipe for npfs).
    pub devobj: u64,
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
}

/// Copy `n` bytes from `src` to `dst` (both mapped in the executive). HEAP-FREE, byte-wise-safe
/// (unaligned windows in a PE).
unsafe fn copy_bytes(dst: u64, src: u64, n: u64) {
    let mut i = 0u64;
    while i + 8 <= n {
        write_unaligned((dst + i) as *mut u64, read_unaligned((src + i) as *const u64));
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
/// `rights_out`. Returns the DriverEntry RVA, or None. Fully HEAP-FREE.
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
) -> Option<u32> {
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
        let size_of_image = read_unaligned((opt + 56) as *const u32) as u64;
        let scan = size_of_image.min(cap);
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

    Some(entry_rva)
}

/// The FSD image loaded/mapped rights (W^X), filled by [`load_pe_into`]. ONE array per instance
/// (a live driver's `Region` holds a `'static` slice, so two coexisting drivers need distinct arrays).
pub(crate) const MAX_DRIVER_INSTANCES: usize = 4;
static mut FSD_RIGHTS: [[u64; FSD_IMAGE_FRAMES as usize]; MAX_DRIVER_INSTANCES] =
    [[RW_NX; FSD_IMAGE_FRAMES as usize]; MAX_DRIVER_INSTANCES];

/// Next free instance slot (bump — a driver launched via [`load_driver`] never unloads in this host).
static DRIVER_NEXT_INSTANCE: AtomicU64 = AtomicU64::new(0);

/// GENERAL dynamic driver launch: load the `.sys` at `path` by-path from the FS, IAT-patch it, spawn
/// it as an ISOLATED component (per its `class`), run its real DriverEntry, and return the live
/// [`DriverComponent`]. The FSD/Filter/Device classes are all routed through this ONE Family-A IRP
/// path (`caps_and_layout_for(class)` selects the [`HostCaps`] + whether device caps are granted);
/// the GUI syscall server ([`DriverClass::GuiSyscallServer`], win32k) keeps its own Syscall substrate
/// and is NOT routed here — see [`crate::win32k_subsystem`].
///
/// MULTI-INSTANCE: each call takes a fresh instance slot; instance 0 uses the fixed npfs executive
/// VAs (byte-identical), instance N≥1 a distinct executive window ([`ExecVaWindow::for_instance`]).
/// The live driver state is recorded in [`DRIVER_INSTANCES`] so [`dispatch_irp`] can route to any of
/// N drivers by instance index. Adding a new IRP driver needs ZERO bespoke code — a `DriverSpec`.
///
/// Fault-contained: the component's DriverEntry faults land on ITS fault EP (this loop demand-maps
/// benign pages + reports a wall) — a driver crash never brings down the executive root.
pub(crate) unsafe fn load_driver(
    fs: &Fat32,
    path: &[u8],
    class: DriverClass,
) -> Option<DriverComponent> {
    let (caps, _wants_device_caps) = caps_and_layout_for(class);
    if !caps.dispatch_server {
        // The GUI syscall server (win32k) is NOT routed through the general IRP path.
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
        let _ = page_map(copy_cap(code_base + i), code_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
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
    let _ = paging_struct_map(apt, LBL_X86_PAGE_TABLE_MAP, win.aux_pt_va, CAP_INIT_THREAD_VSPACE);
    for i in 0..FSD_DATA_FRAMES {
        let _ = page_map(copy_cap(data_base + i), win.data_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    let _ = page_map(copy_cap(shared), win.shared_va, RW_NX, CAP_INIT_THREAD_VSPACE);
    for i in 0..FSD_ARG_FRAMES {
        let _ = page_map(copy_cap(arg_base + i), win.arg_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }

    // 3. Parse + copy + relocate + IAT-patch (HEAP-FREE, records W^X rights). Load bytes into the
    //    per-instance executive window (code_va) but relocate for the component execution VA (run_va).
    let rights = &mut (*core::ptr::addr_of_mut!(FSD_RIGHTS))[instance];
    let entry_rva = load_pe_into(src_va, code_va, run_va, img_frames, rights, fsd_export_addr)?;
    print_str(b"[driver-launch] DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");
    write_volatile((win.shared_va + SH_ENTRY_RVA) as *mut u64, entry_rva as u64);
    write_volatile((win.shared_va + SH_VERDICT) as *mut u32, 0);

    // 4. Build the FSD-class descriptor + spawn the isolated component.
    let fault_ep = make_object(OBJ_ENDPOINT);
    let pml4 = spawn_fsd_component(code_base, pool_base, data_base, shared, arg_base, fault_ep, &rights[..img_frames as usize]);

    // 5. Drive the DriverEntry init fault-recv loop THROUGH THE SHARED HARNESS PUMP: demand-map
    //    benign pages, wall on a low/in-image fault or the 512 demand cap, wait for the dispatch-ready
    //    signal (FSD_DISPATCH_LABEL). Faults report addresses in the COMPONENT's VSpace (image runs at
    //    run_va), so the in-image wall bounds are `[run_va, run_va + img_frames*0x1000)`.
    // `wake_first=false`: the component is mid-DriverEntry (a blocked SENDER on its fault EP, or about
    // to Send its ready signal), NOT parked at a recv — so the pump must start by RECEIVING, exactly
    // as the old inline `ep_recv_full(fault_ep)` did. Trace on for init-time observability.
    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep,
        pml4,
        code_va: run_va,
        image_frames: img_frames,
        shared_va: win.shared_va,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 512,
        trace_faults: true,
        wake_first: false,
        reply_cap: 0,
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
    let devobj = read_volatile((win.shared_va + SH_DEVOBJ) as *const u64);
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
    print_str(b"\n");

    let dc = DriverComponent {
        pml4,
        fault_ep,
        devobj,
        verdict,
        finished,
        exec_shared_va: win.shared_va,
        exec_arg_va: win.arg_va,
        instance,
    };
    // Record the live instance so `dispatch_irp(instance, ...)` can route to it from anywhere.
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
) -> u64 {
    // SAFETY: rights lives in FSD_RIGHTS (a 'static); re-borrow as 'static for Rights::PerFrame.
    let rights_static: &'static [u64] = core::mem::transmute::<&[u64], &'static [u64]>(rights);
    let regions = [
        // The npfs PE image, W^X, its own 2 MiB PT.
        Region { source: FrameSource::Alias(code_base), base_va: FSD_CODE_VA, count: FSD_IMAGE_FRAMES, rights: Rights::PerFrame(rights_static), pts: 1 },
        // Pool arena (own window + PTs, aliased executive frames).
        Region { source: FrameSource::Alias(pool_base), base_va: FSD_POOL_VADDR, count: FSD_POOL_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 },
        // Aux PT window for DATA/SHARED/ARG.
        Region { source: FrameSource::Alias(0), base_va: FSD_AUX_PT_VADDR, count: 0, rights: Rights::Uniform(RW_NX), pts: 1 },
        // DATA export/placeholder region (aux window).
        Region { source: FrameSource::Alias(data_base), base_va: FSD_DATA_VADDR, count: FSD_DATA_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
        // Shared handoff page (aux window).
        Region { source: FrameSource::Alias(shared), base_va: FSD_SHARED_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
        // Arg-marshal frames (aux window).
        Region { source: FrameSource::Alias(arg_base), base_va: FSD_ARG_VADDR, count: FSD_ARG_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
    ];
    let d = ComponentDescriptor {
        entry: fsd_component_entry,
        image_rights: Rights::Uniform(3), // RWX (trampolines live in the shared executive image)
        map_heap_pt: false,
        stack_base: FSD_STACK_VADDR,
        stack_frames: FSD_STACK_FRAMES,
        stack_dedicated_pt: true,
        regions: &regions,
        granted: GrantedCaps { irq_ntfn: None, result_ntfn: None, fault_ep: Some(fault_ep) },
        prio: 100,
        gs_base: Some(FSD_KPCR_VA),
        caps: HostCaps::default(),
    };
    spawn_component(&d).pml4
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
// The live launched IRP-driver instance table + the generic IRP dispatch call.
//
// De-singletoned (multi-driver): the executive keeps a small table of live [`DriverComponent`]s
// keyed by instance index. [`dispatch_irp(instance, …)`] routes an IRP to ANY launched driver;
// `npfs_dispatch_irp` is the instance-0 (npfs) convenience wrapper so the many existing npfs call
// sites are unchanged. Each instance carries its OWN executive-side SHARED/ARG VAs, fault EP, and
// PML4 — two drivers coexist with fully isolated windows.
// ---------------------------------------------------------------------------------------------

/// A live launched IRP driver (a snapshot of the routing facts from its [`DriverComponent`]).
#[derive(Clone, Copy)]
pub(crate) struct DriverInstance {
    pub fault_ep: u64,
    pub pml4: u64,
    pub exec_shared_va: u64,
    pub exec_arg_va: u64,
    pub ready: bool,
    pub used: bool,
}

const EMPTY_INSTANCE: DriverInstance = DriverInstance {
    fault_ep: 0,
    pml4: 0,
    exec_shared_va: 0,
    exec_arg_va: 0,
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
            // Default readiness = npfs's historic rule (parked + a control device object). A
            // driver that fills its MJ table but creates no control device (a minimal filter/FSD)
            // is marked ready explicitly by the caller via `register_instance_ready`.
            ready: dc.finished && dc.devobj != 0,
            used: true,
        };
    }
}

/// Mark instance `i` ready for IRP dispatch (used when readiness ≠ npfs's "has a devobj" rule, e.g.
/// a minimal driver that fills MajorFunction[] but creates no control DEVICE_OBJECT).
pub(crate) fn register_instance_ready(i: usize, ready: bool) {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(DRIVER_INSTANCES) };
    if i < t.len() && t[i].used {
        t[i].ready = ready;
    }
}

/// The PML4 (VSpace) cap of launched instance `i` (0 = not launched) — for the isolation proof.
pub(crate) fn instance_pml4(i: usize) -> u64 {
    instance(i).map(|d| d.pml4).unwrap_or(0)
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

/// Record a launched npfs component (instance 0). Kept for source compatibility — `load_driver`
/// already registered it in [`DRIVER_INSTANCES`]; this only re-asserts the npfs (instance-0) row.
pub(crate) fn register_npfs(dc: &DriverComponent) {
    register_instance(dc);
}

/// Whether npfs (instance 0) is launched + parked at its dispatch loop (ready to serve IRPs).
pub(crate) fn npfs_ready() -> bool {
    instance(0).map(|d| d.ready).unwrap_or(false)
}

/// The opaque FILE_OBJECT id (npfs's `FsContext`) from the LAST dispatched IRP to instance 0.
pub(crate) unsafe fn npfs_last_file_id() -> u64 {
    let sh = instance(0).map(|d| d.exec_shared_va).unwrap_or(FSD_SHARED_VADDR);
    read_volatile((sh + SH_REQ_FILEID) as *const u64)
}

/// Route one IRP to launched driver `inst`: fill the shared request fields, drive its dispatch loop
/// (a plain Send wakes it; it runs `MajorFunction[major]` in its own context; a fault mid-IRP lands
/// on its fault EP → demand-map + resume), then read back the completion. Returns `(status,
/// information)`. `major` is an `IRP_MJ_*`; `in_data` is copied into the instance's ARG frame
/// (buffered I/O); `out` receives the driver's output. Returns `None` if `inst` isn't ready.
///
/// This is the SHARED multi-driver dispatch engine — no per-driver code. `npfs_dispatch_irp` is the
/// instance-0 wrapper.
pub(crate) unsafe fn dispatch_irp(
    inst: usize,
    major: u64,
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
    write_volatile((sh + SH_REQ_MAJOR) as *mut u64, major);
    write_volatile((sh + SH_REQ_MINOR) as *mut u64, 0);
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
        wake_first: true, // per-IRP: the component is parked in recv_req_on → Send wakes it
        reply_cap: 0,
        client_pi: 0,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    if !pr.completed {
        print_str(b"[fsd-svc] IRP fault wall inst=");
        print_u64(inst as u64);
        print_str(b" addr=0x");
        print_hex(pr.wall_addr as u32);
        print_str(b"\n");
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

/// Route one IRP to the isolated npfs component (instance 0). Thin wrapper over [`dispatch_irp`]
/// so the many existing npfs call sites are unchanged. Returns `None` if npfs isn't ready.
pub(crate) unsafe fn npfs_dispatch_irp(
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    dispatch_irp(0, major, fsctl, file_id, in_data, out)
}
