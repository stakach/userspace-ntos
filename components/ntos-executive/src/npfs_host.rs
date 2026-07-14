//! `npfs_host` — the component-side of hosting the REAL ReactOS `npfs.sys` as an ISOLATED
//! file-system driver (an FSD-class component, NO device caps). Mirrors [`crate::win32k_host`]
//! but far smaller: npfs is not a GUI subsystem, it registers a `\Device\NamedPipe` control
//! device + a `MajorFunction[]` table and serves named-pipe file IRPs.
//!
//! Split (identical to the win32k pattern):
//!   * the EXECUTIVE (in [`crate::driver_launch`]) loads/relocates/IAT-patches npfs.sys into a
//!     run of frames at [`NPFS_CODE_VA`] and spawns this component with its fault EP armed.
//!   * the HOST (this component) runs npfs's real `DriverEntry(DRIVER_OBJECT*, RegistryPath*)`
//!     — which fills `DriverObject->MajorFunction[IRP_MJ_*]` + calls `IoCreateDevice`/
//!     `IoRegisterFileSystem` through the trampolines below — records the resulting MajorFunction
//!     table + device object into the shared page, then enters a persistent IRP dispatch loop.
//!
//! The trampolines are compiled into the executive's image (mapped RWX-shared into the host at the
//! same VA) — the KMDF/win32k host pattern. npfs's IAT is resolved through [`npfs_export_addr`].

use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};

use crate::*;

// --- component VA layout (identical in the executive-load view + the host-run view) ----------

/// The relocated/loaded npfs image (VIRTUAL layout). npfs.sys is ~62 KiB → SizeOfImage ~0x14000
/// (20 frames); reserve a generous 64-frame (256 KiB) window in its own 2 MiB PT, well clear of
/// win32k's windows (which start at 0x0680_0000).
pub const NPFS_CODE_VA: u64 = 0x0000_0100_0E00_0000;
/// npfs image frame budget (SizeOfImage / 0x1000, capped). 64 frames = 256 KiB.
pub const NPFS_IMAGE_FRAMES: u64 = 64;

/// The npfs pool arena the `ExAllocatePool*` trampolines bump-allocate from (counter @+0, data @
/// +0x1000). npfs's DriverEntry + pipe-object allocation is modest; 4 MiB in its own 2-PT window.
pub const NPFS_POOL_VADDR: u64 = 0x0000_0100_0E80_0000;
pub const NPFS_POOL_FRAMES: u64 = 1024; // 4 MiB, pre-mapped

/// The component's own stack (32 frames = 128 KiB, own PT). npfs's dispatch call chains
/// (NpFsdCreate → Np*) are moderately deep.
pub const NPFS_STACK_VADDR: u64 = 0x0000_0100_0F00_0000;
pub const NPFS_STACK_FRAMES: u64 = 32;

/// Aux PT window holding the DATA + SHARED + ARG frames (one 2 MiB PT).
pub const NPFS_AUX_PT_VADDR: u64 = 0x0000_0100_0F20_0000;
/// DATA export/placeholder region: page 0 = misc placeholders, page 1 = KPCR placeholder (GS),
/// page 2 = the DRIVER_OBJECT the shim builds is in the pool, not here. 4 frames.
pub const NPFS_DATA_VADDR: u64 = 0x0000_0100_0F30_0000;
pub const NPFS_DATA_FRAMES: u64 = 4;
/// The component's GS base — a zeroed KPCR placeholder (npfs, a kernel driver, may read `gs:[..]`).
pub const NPFS_KPCR_VA: u64 = NPFS_DATA_VADDR + 0x1000;

/// Shared handoff page (executive ↔ host): entry rva in, verdict + MajorFunction table + device
/// object out, then the IRP request/reply fields.
pub const NPFS_SHARED_VADDR: u64 = 0x0000_0100_0F38_0000;

/// The cross-AS ARG-MARSHAL frame(s): mapped RW in BOTH the executive and the npfs component. The
/// executive copies an IRP's system-buffer here; npfs's MajorFunction handler reads/writes it in its
/// own context; the executive copies out-params back to the caller on reply. 4 pages = 16 KiB.
pub const NPFS_ARG_VADDR: u64 = 0x0000_0100_0F3A_0000;
pub const NPFS_ARG_FRAMES: u64 = 4;

// --- shared-page offsets ---------------------------------------------------------------------

pub const SH_ENTRY_RVA: u64 = 0x00; // in:  DriverEntry RVA (u64)
pub const SH_VERDICT: u64 = 0x08; // out: verdict bitmask (u32)
pub const SH_DE_STATUS: u64 = 0x10; // out: DriverEntry NTSTATUS (i32)
pub const SH_MJ_TABLE: u64 = 0x18; // out: recorded DriverObject->MajorFunction[] base VA (u64)
pub const SH_DEVOBJ: u64 = 0x20; // out: the \Device\NamedPipe DEVICE_OBJECT VA (u64)
pub const SH_POOL_USED: u64 = 0x28; // out: pool high-water (u64)
// IRP dispatch request/reply (executive → npfs, via the shared page).
pub const SH_REQ_MAJOR: u64 = 0x40; // in:  IRP_MJ_* major function (u64)
pub const SH_REQ_MINOR: u64 = 0x48; // in:  minor function (u64)
pub const SH_REQ_FSCTL: u64 = 0x50; // in:  FsControlCode / IoControlCode (u64)
pub const SH_REQ_INLEN: u64 = 0x58; // in:  input buffer length (u64)
pub const SH_REQ_OUTLEN: u64 = 0x60; // in:  output buffer length (u64)
pub const SH_REQ_FILEID: u64 = 0x68; // in/out: opaque FILE_OBJECT id (u64)
pub const SH_REQ_STATUS: u64 = 0x70; // out: IoStatus.Status (i32)
pub const SH_REQ_INFO: u64 = 0x78; // out: IoStatus.Information (u64)
pub const SH_REQ_SEQ: u64 = 0x80; // out: completed-request counter (u64) — observability

// --- verdict bits ----------------------------------------------------------------------------

pub const V_ENTERED: u32 = 1; // host called into DriverEntry
pub const V_RETURNED: u32 = 2; // DriverEntry returned (did not fault)
pub const V_SUCCESS: u32 = 4; // DriverEntry returned STATUS_SUCCESS
pub const V_DEVICE: u32 = 8; // IoCreateDevice(\Device\NamedPipe) succeeded
pub const V_MJ: u32 = 0x10; // DriverObject->MajorFunction[IRP_MJ_CREATE] is non-null (table filled)
pub const V_REGFS: u32 = 0x20; // IoRegisterFileSystem was called

/// The IPC message label the dispatch loop uses to Send its ready/done signal on the fault EP.
/// Distinct from the small fault labels (VMFault=6, …), so the executive tells them apart.
pub const NPFS_DISPATCH_LABEL: u64 = 0x771;

const POOL_DATA_OFF: u64 = 0x1000;

// --- host-side pool allocator (the trampolines run in the component) --------------------------

/// A simple free-list allocator: npfs alloc/frees pipe objects; a leak-forever bump would exhaust
/// under FSCTL churn. Header = 16 B ([+0]=capacity, [+8]=next-free). `pool_free` pushes onto the
/// single free list (head @ [POOL+8]); `pool_alloc` first-fits it before bumping. Counter @ [POOL+0].
unsafe fn pool_alloc(size: u64) -> u64 {
    // first-fit the free list
    let head_slot = (NPFS_POOL_VADDR + 8) as *mut u64;
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
    let ctr = NPFS_POOL_VADDR as *mut u64;
    let mut off = read_volatile(ctr);
    if off < POOL_DATA_OFF {
        off = POOL_DATA_OFF;
    }
    // 16-byte header + 16-align the returned block
    let hdr = (NPFS_POOL_VADDR + off + 15) & !15;
    let block = hdr + 16;
    let cap = NPFS_POOL_VADDR + NPFS_POOL_FRAMES * 0x1000;
    if size == 0 || block + size > cap {
        print_str(b"[npfs-host] POOL EXHAUSTED size=0x");
        print_hex(size as u32);
        print_str(b"\n");
        return 0;
    }
    write_volatile(ctr, (block + size) - NPFS_POOL_VADDR);
    write_volatile((block - 16) as *mut u64, size); // capacity header
    write_volatile((block - 8) as *mut u64, 0);
    block
}

unsafe fn pool_free(p: u64) {
    if p == 0 || p < NPFS_POOL_VADDR + POOL_DATA_OFF {
        return;
    }
    let head_slot = (NPFS_POOL_VADDR + 8) as *mut u64;
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
/// the shared page (the executive resolves \Device\NamedPipe to it).
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
        write_volatile((NPFS_SHARED_VADDR + SH_DEVOBJ) as *mut u64, dev);
        let v = read_volatile((NPFS_SHARED_VADDR + SH_VERDICT) as *const u32);
        write_volatile((NPFS_SHARED_VADDR + SH_VERDICT) as *mut u32, v | V_DEVICE);
    }
    0 // STATUS_SUCCESS
}

/// `NTSTATUS IoCreateSymbolicLink(PUNICODE_STRING, PUNICODE_STRING)` — no-op success (the executive
/// object namespace owns \?? symlinks; the driver just declares one).
extern "win64" fn s_io_create_symbolic_link(_a: u64, _b: u64) -> i32 {
    0
}

/// `void IoRegisterFileSystem(PDEVICE_OBJECT)`. Record that npfs registered as an FSD; no queue to
/// maintain (the executive routes named-pipe paths to the recorded device directly).
extern "win64" fn s_io_register_file_system(_dev: u64) {
    unsafe {
        let v = read_volatile((NPFS_SHARED_VADDR + SH_VERDICT) as *const u32);
        write_volatile((NPFS_SHARED_VADDR + SH_VERDICT) as *mut u32, v | V_REGFS);
    }
}

/// `void IoCompleteRequest(PIRP, CCHAR)`. The dispatch shim reads the IRP's IoStatus directly after
/// the handler returns, so completion is a no-op marker here.
extern "win64" fn s_io_complete_request(_irp: u64, _boost: u64) {}

// The DriverEntry/init path also touches: prefix trees, generic tables, resources, spinlocks,
// timers, DPCs. In this single-threaded host the synchronization primitives are genuine no-ops.
// The prefix tree / generic table INIT functions just zero their control structs; npfs allocates the
// structs from paged pool + passes them in, so a zeroing init suffices for DriverEntry to complete
// (the real lookup/insert semantics are exercised only during IRP dispatch — modeled there).

/// `void RtlInitializeUnicodePrefix(PUNICODE_PREFIX_TABLE)` — zero the small control struct.
extern "win64" fn s_rtl_init_unicode_prefix(tbl: u64) {
    if tbl != 0 {
        unsafe {
            // UNICODE_PREFIX_TABLE = { SHORT NodeTypeCode; SHORT NameLength; PUNICODE_PREFIX_TABLE_ENTRY
            // NextPrefixTree; PRTL_SPLAY_LINKS TableRoot; } — 0x18 bytes.
            write_unaligned(tbl as *mut u64, 0);
            write_unaligned((tbl + 8) as *mut u64, 0);
            write_unaligned((tbl + 16) as *mut u64, 0);
        }
    }
}

/// `void RtlInitializeGenericTable(PRTL_GENERIC_TABLE, ...)` — zero the control struct.
extern "win64" fn s_rtl_init_generic_table(tbl: u64, _cmp: u64, _alloc: u64, _free: u64, _ctx: u64) {
    if tbl != 0 {
        unsafe {
            let mut i = 0u64;
            while i < 0x40 {
                write_unaligned((tbl + i) as *mut u64, 0);
                i += 8;
            }
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

/// `PEPROCESS PsGetCurrentProcess()` / `PsGetCurrentThread()` — a fake non-null object pointer.
extern "win64" fn s_current_process() -> u64 {
    NPFS_DATA_VADDR // a mapped, zeroed placeholder page
}

/// `PVOID IoGetCurrentProcess()` — same as above.
extern "win64" fn s_io_get_current_process() -> u64 {
    NPFS_DATA_VADDR
}

/// Serial debug print forwarder (`vDbgPrintExWithPrefix` etc.) — swallow.
extern "win64" fn s_dbg_print() -> i32 {
    0
}

/// Resolve an npfs ntoskrnl/hal/fsrtl import NAME to its IAT-slot trampoline VA. Everything not
/// explicitly bound falls back to `s_true` (a benign non-crashing 1-returner) — DriverEntry's init
/// path is broad but shallow; unknown calls that just return success let it proceed to fill the MJ
/// table. FLAG (serial-logged in the loader) each unbound name so the surface is auditable.
pub fn npfs_export_addr(name: &str) -> u64 {
    let t = match name {
        "ExAllocatePoolWithTag" => s_ex_alloc_pool_tag as usize,
        "ExAllocatePoolWithQuotaTag" => s_ex_alloc_pool_quota_tag as usize,
        "ExAllocatePool" => s_ex_alloc_pool as usize,
        "ExFreePoolWithTag" => s_ex_free_pool_tag as usize,
        "ExFreePool" => s_ex_free_pool as usize,
        "RtlInitUnicodeString" => s_rtl_init_unicode_string as usize,
        "RtlInitEmptyUnicodeString" => s_rtl_init_empty_unicode_string as usize,
        "IoCreateDevice" => s_io_create_device as usize,
        "IoCreateSymbolicLink" => s_io_create_symbolic_link as usize,
        "IoRegisterFileSystem" => s_io_register_file_system as usize,
        "IoCompleteRequest" => s_io_complete_request as usize,
        "RtlInitializeUnicodePrefix" => s_rtl_init_unicode_prefix as usize,
        "RtlInitializeGenericTable" => s_rtl_init_generic_table as usize,
        "ExInitializeResourceLite" | "KeInitializeSpinLock" | "KeInitializeEvent"
        | "KeInitializeTimer" | "KeInitializeDpc" | "ExInitializeFastMutex"
        | "KeInitializeMutex" | "KeInitializeSemaphore" => s_init_small_struct as usize,
        "PsGetCurrentProcess" | "PsGetCurrentThread" | "KeGetCurrentThread" => {
            s_current_process as usize
        }
        "IoGetCurrentProcess" => s_io_get_current_process as usize,
        "vDbgPrintExWithPrefix" | "vDbgPrintEx" | "DbgPrint" | "DbgPrintEx" => s_dbg_print as usize,
        // Genuine no-ops (release resource / lock / free / deref / exit-fs / etc.): return 0.
        _ if name.starts_with("Ex") && (name.contains("Release") || name.contains("Delete"))
            || name.starts_with("Ke") && name.contains("Release")
            || name.starts_with("Fs")
            || name.starts_with("Ob") && (name.contains("Dereference") || name.contains("Reference"))
            || name.starts_with("Se") && name.contains("Unlock") =>
        {
            s_zero as usize
        }
        _ => s_true as usize, // fail-soft default (auditable — the loader logs unbound names)
    };
    t as u64
}

/// Whether a name was EXPLICITLY bound (vs the fail-soft default) — the loader uses this to log the
/// unresolved surface for auditing.
pub fn npfs_is_bound(name: &str) -> bool {
    npfs_export_addr(name) != s_true as usize as u64
}

// --- the component entry ---------------------------------------------------------------------

/// The npfs host component entry. Reads the DriverEntry RVA from the shared page, builds a minimal
/// DRIVER_OBJECT + RegistryPath from the pool, calls `DriverEntry`, records the MajorFunction table
/// + verdict, then enters the IRP dispatch loop. Sends its ready/done signal on the fault EP.
#[no_mangle]
#[link_section = ".text.npfs_host_entry"]
pub unsafe extern "C" fn npfs_host_entry() -> ! {
    let entry_rva = read_volatile((NPFS_SHARED_VADDR + SH_ENTRY_RVA) as *const u64) as u32;
    print_str(b"[npfs-host] START DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");

    // DRIVER_OBJECT (Type@0=4, Size@2=0x150, MajorFunction[]@0x70..). The x64 DRIVER_OBJECT is
    // 0x150 bytes with MajorFunction at offset 0x70 (28 entries * 8 = 0xE0 → ends at 0x150).
    let drv = pool_alloc(0x150);
    let mut i = 0u64;
    while i < 0x150 {
        write_unaligned((drv + i) as *mut u64, 0);
        i += 8;
    }
    write_unaligned(drv as *mut i16, 4); // Type = IO_TYPE_DRIVER
    write_unaligned((drv + 2) as *mut u16, 0x150); // Size
    // DriverExtension@0x70? No — MajorFunction is at 0x70; DriverExtension is at 0x68 (a pointer).
    let ext = pool_alloc(0x50);
    let mut j = 0u64;
    while j < 0x50 {
        write_unaligned((ext + j) as *mut u64, 0);
        j += 8;
    }
    write_unaligned((drv + 0x68) as *mut u64, ext);

    // RegistryPath UNICODE_STRING { Length=0, MaximumLength=2, Buffer=&NUL }.
    let reg_path = pool_alloc(0x18);
    let reg_buf = pool_alloc(0x10);
    write_unaligned(reg_buf as *mut u16, 0);
    write_unaligned(reg_path as *mut u16, 0);
    write_unaligned((reg_path + 2) as *mut u16, 2);
    write_unaligned((reg_path + 8) as *mut u64, reg_buf);

    write_volatile((NPFS_SHARED_VADDR + SH_VERDICT) as *mut u32, V_ENTERED);

    let entry = NPFS_CODE_VA + entry_rva as u64;
    let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = de(drv, reg_path);

    // MajorFunction table base = drv + 0x70.
    let mj_base = drv + 0x70;
    let mj_create = read_unaligned(mj_base as *const u64);
    let mut v = read_volatile((NPFS_SHARED_VADDR + SH_VERDICT) as *const u32);
    v |= V_RETURNED;
    if status == 0 {
        v |= V_SUCCESS;
    }
    if mj_create != 0 {
        v |= V_MJ;
    }
    write_volatile((NPFS_SHARED_VADDR + SH_VERDICT) as *mut u32, v);
    write_volatile((NPFS_SHARED_VADDR + SH_DE_STATUS) as *mut i32, status);
    write_volatile((NPFS_SHARED_VADDR + SH_MJ_TABLE) as *mut u64, mj_base);
    let pool_used = read_volatile(NPFS_POOL_VADDR as *const u64);
    write_volatile((NPFS_SHARED_VADDR + SH_POOL_USED) as *mut u64, pool_used);
    print_str(b"[npfs-host] DriverEntry returned status=0x");
    print_hex(status as u32);
    print_str(b" verdict=0x");
    print_hex(v);
    print_str(b" mj_create=0x");
    print_hex((mj_create >> 32) as u32);
    print_hex(mj_create as u32);
    print_str(b"\n");

    dispatch_loop(drv)
}

/// Signal ready/done to the executive: a plain `seL4_Send` on the fault-endpoint cap ([`crate::CT_FAULT`])
/// carrying [`NPFS_DISPATCH_LABEL`] (Send/Recv, NOT Call — the win32k fix-A rationale).
#[inline(never)]
unsafe fn send_done() {
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_SEND as u64,
        in("rdi") crate::CT_FAULT,
        in("rsi") NPFS_DISPATCH_LABEL << 12,
        in("r10") 0u64, in("r8") 0u64, in("r9") 0u64, in("r15") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// Block for the next dispatch request: a plain `seL4_Recv` on [`crate::CT_FAULT`].
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

/// The persistent npfs IRP dispatch loop (Send/Recv handshake). Each iteration: Send ready/done, Recv
/// the next request, build a minimal IRP + IO_STACK_LOCATION for `SH_REQ_MAJOR`, invoke
/// `DriverObject->MajorFunction[major]` in this component's context, and write the IoStatus back.
unsafe fn dispatch_loop(drv: u64) -> ! {
    let mj_base = drv + 0x70;
    let mut seq = 0u64;
    loop {
        send_done();
        recv_req();
        let major = read_volatile((NPFS_SHARED_VADDR + SH_REQ_MAJOR) as *const u64);
        let handler = read_volatile((mj_base + major * 8) as *const u64);
        let (mut st, mut info): (i32, u64) = (0xC000_0002u32 as i32, 0); // STATUS_NOT_IMPLEMENTED
        if handler != 0 {
            // Build a minimal IRP: IoStatus@+0x30 { Status; Information }, StackLocation via
            // CurrentStackLocation@+0xb8. Allocate the IRP + one stack location from the pool.
            let irp = pool_alloc(0x100);
            let mut i = 0u64;
            while i < 0x100 {
                write_unaligned((irp + i) as *mut u64, 0);
                i += 8;
            }
            let iosl = pool_alloc(0x48);
            let mut k = 0u64;
            while k < 0x48 {
                write_unaligned((iosl + k) as *mut u64, 0);
                k += 8;
            }
            // IO_STACK_LOCATION: MajorFunction@0, MinorFunction@1.
            write_unaligned(iosl as *mut u8, major as u8);
            write_unaligned((iosl + 1) as *mut u8, 0);
            // IRP.Tail.Overlay.CurrentStackLocation@0xb8.
            write_unaligned((irp + 0xb8) as *mut u64, iosl);
            // Point IoStatus to a known slot; the handler / IoCompleteRequest write it.
            // We read it back from irp+0x30 after.
            let devobj = read_volatile((NPFS_SHARED_VADDR + SH_DEVOBJ) as *const u64);
            let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(handler as *const ());
            let ret = f(devobj, irp);
            // Prefer the IRP's IoStatus if the handler filled it, else the return value.
            let irp_status = read_unaligned((irp + 0x30) as *const i32);
            info = read_unaligned((irp + 0x38) as *const u64);
            st = if irp_status != 0 || info != 0 { irp_status } else { ret };
            pool_free(iosl);
            pool_free(irp);
        }
        write_volatile((NPFS_SHARED_VADDR + SH_REQ_STATUS) as *mut i32, st);
        write_volatile((NPFS_SHARED_VADDR + SH_REQ_INFO) as *mut u64, info);
        seq += 1;
        write_volatile((NPFS_SHARED_VADDR + SH_REQ_SEQ) as *mut u64, seq);
    }
}
