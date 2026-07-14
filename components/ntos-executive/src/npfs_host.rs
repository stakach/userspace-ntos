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

// --- REAL VCB internals: the Unicode prefix table (name -> FCB), generic table, ERESOURCE ---------
//
// npfs's DriverEntry runs its OWN `NpInitializeVcb`/`NpCreateRootDcb`, and every create/open runs its
// OWN `NpFsdCreate*` → `NpCreateFcb`/`NpCreateCcb`. Those exercise the prefix table + resource for
// REAL (the create path bug-checks on a NULL `RtlFindUnicodePrefix`, and create-then-connect must find
// the FCB by name). So these trampolines carry real host-side logic, backed by a fixed-capacity static
// table (no `alloc` in the isolated component). The prefix-MATCH contract is the host-tested
// [`nt_kernel_exec::np_prefix`] logic (component-prefix, case-insensitive, longest wins).
//
// `RtlInsertUnicodePrefix(Table, &Fcb->FullName, &Fcb->PrefixTableEntry)` records the entry pointer
// npfs passed (so `RtlFindUnicodePrefix` can return the SAME pointer → `CONTAINING_RECORD` recovers
// the FCB). `RtlFindUnicodePrefix(Table, FullName, _)` returns the recorded entry of the longest name
// that is a component-prefix of `FullName`.

/// A recorded prefix-table entry: (the caller's `PUNICODE_PREFIX_TABLE_ENTRY`, the name VA, len-bytes).
/// The name is a `UNICODE_STRING.Buffer` (UTF-16); we read it live from npfs's own pool at Find time.
#[derive(Clone, Copy)]
struct PrefixSlot {
    entry: u64,   // the PUNICODE_PREFIX_TABLE_ENTRY npfs passed to Insert (returned by Find)
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
/// u16 units (capped at the scratch size). npfs pipe names are short (`\ntsvcs` = 7).
unsafe fn read_ustr16(buf_va: u64, len_bytes: u16, out: &mut [u16]) -> usize {
    let n = ((len_bytes as usize) / 2).min(out.len());
    for i in 0..n {
        out[i] = read_unaligned((buf_va + (i as u64) * 2) as *const u16);
    }
    n
}

/// `void RtlInitializeUnicodePrefix(PUNICODE_PREFIX_TABLE)` — zero the control struct AND clear the
/// host-side table (npfs calls this once at NpInitializeVcb before inserting the root DCB).
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
        // dedup: an identical (case-insensitive) name already present → FALSE (npfs bug-checks on this,
        // meaning it never re-creates the same pipe; our create arm rejects duplicates before calling).
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
/// component-prefix of `FullName` (NULL if none — npfs bug-checks, but the root `\` always matches).
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
/// stash the callbacks (npfs's EventTable is only exercised on pipe-state-change notify — no live
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

/// `void *memcpy(void *dst, const void *src, size_t n)` — REAL (npfs's RtlCopyMemory/RtlMoveMemory
/// macros compile to this; an unbound no-op silently corrupts every FCB name + pipe data buffer).
extern "win64" fn s_memcpy(dst: u64, src: u64, n: u64) -> u64 {
    unsafe {
        let mut i = 0u64;
        while i < n {
            write_unaligned((dst + i) as *mut u8, read_unaligned((src + i) as *const u8));
            i += 1;
        }
    }
    dst
}
/// `void *memset(void *dst, int c, size_t n)` — REAL (RtlZeroMemory / RtlFillMemory).
extern "win64" fn s_memset(dst: u64, c: u64, n: u64) -> u64 {
    unsafe {
        let b = c as u8;
        let mut i = 0u64;
        while i < n {
            write_unaligned((dst + i) as *mut u8, b);
            i += 1;
        }
    }
    dst
}
/// `SIZE_T RtlCompareMemory(const void *s1, const void *s2, SIZE_T n)` — count of leading equal bytes.
extern "win64" fn s_rtl_compare_memory(a: u64, b: u64, n: u64) -> u64 {
    unsafe {
        let mut i = 0u64;
        while i < n {
            if read_unaligned((a + i) as *const u8) != read_unaligned((b + i) as *const u8) {
                break;
            }
            i += 1;
        }
        i
    }
}
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
    NPFS_KPCR_VA
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
        "RtlInsertUnicodePrefix" => s_rtl_insert_unicode_prefix as usize,
        "RtlFindUnicodePrefix" => s_rtl_find_unicode_prefix as usize,
        "RtlInitializeGenericTable" => s_rtl_init_generic_table as usize,
        "ExAcquireResourceExclusiveLite" | "ExAcquireResourceSharedLite"
        | "ExAcquireSharedStarveExclusive" | "ExAcquireSharedWaitForExclusive" => {
            s_acquire_resource as usize
        }
        "ExReleaseResourceLite" | "ExReleaseResourceForThreadLite" => s_release_resource as usize,
        "memcpy" | "memmove" | "RtlCopyMemory" | "RtlMoveMemory" => s_memcpy as usize,
        "memset" | "RtlFillMemory" => s_memset as usize,
        "RtlCompareMemory" | "RtlCompareMemoryUlong" => s_rtl_compare_memory as usize,
        "RtlUpcaseUnicodeChar" => s_rtl_upcase_char as usize,
        "IoGetFileObjectGenericMapping" => s_generic_mapping as usize,
        "SeAssignSecurity" => s_se_assign_security as usize,
        "ObLogSecurityDescriptor" => s_ob_log_sd as usize,
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
            let (rst, rinfo) = run_irp(major, handler);
            st = rst;
            info = rinfo;
        }
        write_volatile((NPFS_SHARED_VADDR + SH_REQ_STATUS) as *mut i32, st);
        write_volatile((NPFS_SHARED_VADDR + SH_REQ_INFO) as *mut u64, info);
        seq += 1;
        write_volatile((NPFS_SHARED_VADDR + SH_REQ_SEQ) as *mut u64, seq);
    }
}

/// Build a real IRP + IO_STACK_LOCATION + FILE_OBJECT (buffered I/O) and invoke npfs's
/// `MajorFunction[major]` handler. The pipe name (UTF-16) rides in the ARG frame ([SH_REQ_INLEN]
/// bytes); the FILE_OBJECT's FileName points at it. Returns (status, information).
///
/// x64 layouts (references/nt5 io.h): FILE_OBJECT { DeviceObject@8, FsContext@0x18, FsContext2@0x20,
/// RelatedFileObject@0x40, FileName(UNICODE_STRING)@0x58 }. IRP { IoStatus@0x30, CurrentLocation
/// (CCHAR)@0x42, StackCount@0x43, AssociatedIrp.SystemBuffer@0x18, UserBuffer@0x70,
/// Tail.Overlay.CurrentStackLocation@0xb8 }. IO_STACK_LOCATION { Major@0, Minor@1, Parameters(union)
/// @0x08, DeviceObject@0x20, FileObject@0x30 }.
unsafe fn run_irp(major: u64, handler: u64) -> (i32, u64) {
    let devobj = read_volatile((NPFS_SHARED_VADDR + SH_DEVOBJ) as *const u64);
    let inlen = read_volatile((NPFS_SHARED_VADDR + SH_REQ_INLEN) as *const u64);
    let outlen = read_volatile((NPFS_SHARED_VADDR + SH_REQ_OUTLEN) as *const u64);
    let fsctl = read_volatile((NPFS_SHARED_VADDR + SH_REQ_FSCTL) as *const u64);

    // FILE_OBJECT (0x100 bytes) — DeviceObject + FileName (points at the ARG frame name buffer).
    let fo = pool_alloc(0x100);
    zero(fo, 0x100);
    write_unaligned(fo as *mut i16, 5); // Type = IO_TYPE_FILE
    write_unaligned((fo + 2) as *mut u16, 0x100);
    write_unaligned((fo + 8) as *mut u64, devobj); // DeviceObject
    // FileName UNICODE_STRING @0x58 = { Length=inlen, MaximumLength=inlen+2, Buffer=ARG frame }.
    write_unaligned((fo + 0x58) as *mut u16, inlen as u16); // Length (bytes)
    write_unaligned((fo + 0x5a) as *mut u16, (inlen + 2) as u16); // MaximumLength
    write_unaligned((fo + 0x60) as *mut u64, NPFS_ARG_VADDR); // Buffer = the pipe name (UTF-16)

    // IRP (0x120 bytes).
    let irp = pool_alloc(0x120);
    zero(irp, 0x120);
    // AssociatedIrp.SystemBuffer@0x18 = the ARG frame (buffered I/O in/out).
    write_unaligned((irp + 0x18) as *mut u64, NPFS_ARG_VADDR);
    write_unaligned((irp + 0x70) as *mut u64, NPFS_ARG_VADDR); // UserBuffer
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
    //  FS/DeviceControl: OutputBufferLength@0x08, InputBufferLength@0x10, IoControlCode@0x18,
    //    Type3InputBuffer@0x20.
    match major {
        0 | 1 => {
            // IRP_MJ_CREATE (client open) / IRP_MJ_CREATE_NAMED_PIPE (server create). npfs derefs
            // SecurityContext->{AccessState,DesiredAccess}, Options (disposition<<24), ShareAccess, and
            // (create-named-pipe only) the NAMED_PIPE_CREATE_PARAMETERS. Build valid blocks from the pool.
            let sec_ctx = pool_alloc(0x20); // IO_SECURITY_CONTEXT {SecurityQos,AccessState,DesiredAccess,FullCreateOptions}
            let access_state = pool_alloc(0x80); // ACCESS_STATE — npfs reads AccessState->{SecurityDescriptor,SubjectSecurityContext}
            zero(sec_ctx, 0x20);
            zero(access_state, 0x80);
            write_unaligned((sec_ctx + 0x08) as *mut u64, access_state); // AccessState
            write_unaligned((sec_ctx + 0x10) as *mut u32, 0x001F_01FF); // DesiredAccess = all
            write_unaligned((iosl + 0x08) as *mut u64, sec_ctx); // SecurityContext
            // Options: Disposition (FILE_CREATE=2) in the high byte, CreateOptions in the low 24.
            let disposition: u32 = if major == 1 { 2 } else { 1 }; // create-named-pipe=FILE_CREATE, open=FILE_OPEN
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
        3 | 4 => {
            write_unaligned((iosl + 0x08) as *mut u32, if major == 4 { inlen } else { outlen } as u32);
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
    write_volatile((NPFS_SHARED_VADDR + SH_REQ_FILEID) as *mut u64, fsctx);
    pool_free(iosl);
    pool_free(irp);
    pool_free(fo);
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
