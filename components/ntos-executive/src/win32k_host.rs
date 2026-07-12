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
/// Pool arena the `ExAllocatePool*` trampolines bump-allocate from (counter at +0, data at
/// +0x1000). Retype-zeroed frames give counter 0 → no init step. 256 frames = 1 MiB.
pub const WIN32K_POOL_VADDR: u64 = 0x0000_0100_0700_0000;
pub const WIN32K_POOL_FRAMES: u64 = 256;
/// Data-export region: placeholder structs (page 0) + import cells (page 1) + a KPCR placeholder
/// (page 2) the component's GS base points at. 4 frames.
pub const WIN32K_DATA_VADDR: u64 = 0x0000_0100_0710_0000;
pub const WIN32K_DATA_FRAMES: u64 = 4;
/// The component's GS base — a zeroed KPCR placeholder (win32k, a kernel driver, reads `gs:[..]`
/// expecting the Processor Control Region). Page 2 of the DATA region (mapped, RW, zeroed).
pub const WIN32K_KPCR_VA: u64 = WIN32K_DATA_VADDR + 0x2000;
/// A zeroed page used as the fake HEAP handle `RtlCreateHeap` returns (win32k stores it + passes
/// it back to RtlAllocateHeap; any field reads see 0). Page 3 of the DATA region.
pub const WIN32K_HEAP_HANDLE: u64 = WIN32K_DATA_VADDR + 0x3000;
/// The win32k session-heap arena that RtlAllocateHeap + the Mm session/system view mappers
/// bump-allocate from (counter at +0, data at +0x1000). win32k creates its session heap + maps
/// several ~1 MiB session views; give it 16 MiB. Its own 8 PT window (0x0740_0000..0x0840_0000).
pub const WIN32K_HEAP_VADDR: u64 = 0x0000_0100_0740_0000;
pub const WIN32K_HEAP_FRAMES: u64 = 4096;
/// Shared handoff page (executive ↔ host). Within the pool's 2 MiB PT window (0x0700..0x0720).
pub const WIN32K_SHARED_VADDR: u64 = 0x0000_0100_0718_0000;
/// An unmapped VA the host reads once DriverEntry returns — the fault-recv loop recognises the
/// address as "DriverEntry finished" (vs. a fault mid-init). Also in the pool PT window.
pub const WIN32K_SENTINEL_VADDR: u64 = 0x0000_0100_0719_0000;

const POOL_DATA_OFF: u64 = 0x1000;

// shared-page offsets
pub const SH_ENTRY_RVA: u64 = 0x00; // in:  DriverEntry RVA (u64)
pub const SH_VERDICT: u64 = 0x08; // out: verdict bitmask (u32)
pub const SH_DE_STATUS: u64 = 0x10; // out: DriverEntry NTSTATUS (i32)
pub const SH_SSDT_BASE: u64 = 0x18; // out: recorded win32k SSDT base (u64)
pub const SH_SSDT_COUNT: u64 = 0x20; // out: recorded win32k SSDT count (u32)
pub const SH_SSDT_INDEX: u64 = 0x24; // out: recorded SSDT index (u32)
pub const SH_POOL_USED: u64 = 0x30; // out: pool high-water (u64)

// verdict bits
pub const V_ENTERED: u32 = 1; // host called into DriverEntry
pub const V_RETURNED: u32 = 2; // DriverEntry returned (did not fault)
pub const V_SUCCESS: u32 = 4; // DriverEntry returned STATUS_SUCCESS
pub const V_SSDT: u32 = 8; // KeAddSystemServiceTable recorded the win32k table

// --- pool allocator (host-side; the trampolines run in the component) ------------------------

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

// --- ntoskrnl trampolines (extern "win64"; win64 args = rcx, rdx, r8, r9, stack) -------------

extern "win64" fn s_zero() -> u64 {
    0
}
extern "win64" fn s_true() -> u64 {
    1
}

// Non-null EPROCESS / ETHREAD / Win32Process / Win32Thread placeholders (zeroed regions in the
// DATA page-0 area). win32k's post-SSDT init reads current-process/thread pointers and then
// dereferences their fields — returning a real non-null zeroed struct lets it read past them.
const PH_EPROCESS: u64 = WIN32K_DATA_VADDR + 0x400;
const PH_ETHREAD: u64 = WIN32K_DATA_VADDR + 0x600;
const PH_WIN32PROCESS: u64 = WIN32K_DATA_VADDR + 0x800;
const PH_WIN32THREAD: u64 = WIN32K_DATA_VADDR + 0xA00;

extern "win64" fn s_current_process() -> u64 {
    PH_EPROCESS
}
extern "win64" fn s_current_thread() -> u64 {
    PH_ETHREAD
}
extern "win64" fn s_get_win32process() -> u64 {
    PH_WIN32PROCESS
}
extern "win64" fn s_get_win32thread() -> u64 {
    PH_WIN32THREAD
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

/// `MmMapViewInSessionSpace/MmMapViewInSystemSpace(Section, PVOID *MappedBase, PSIZE_T ViewSize)`
/// — win32k maps a section into session/system space and then USES the mapped view (memsets it,
/// builds shared structures). Back it with a real region from the heap/view arena, populating the
/// `*MappedBase` + `*ViewSize` out-params (a no-op stub left `*MappedBase` null → memset(null)).
extern "win64" fn s_mm_map_view(_section: u64, base_out: *mut u64, size_io: *mut u64) -> i32 {
    unsafe {
        let mut size = if size_io.is_null() { 0 } else { read_volatile(size_io) };
        if size == 0 || size > 0x0040_0000 {
            size = 0x0010_0000; // default/cap the view at 1 MiB
        }
        size = (size + 0xFFF) & !0xFFF;
        let region = heap_alloc(size);
        if region == 0 {
            return 0xC000_0017u32 as i32; // STATUS_NO_MEMORY
        }
        if !base_out.is_null() {
            write_volatile(base_out, region);
        }
        if !size_io.is_null() {
            write_volatile(size_io, size);
        }
    }
    0
}

/// `PVOID ExAllocatePoolWithTag(POOL_TYPE, SIZE_T NumberOfBytes, ULONG Tag)`.
extern "win64" fn s_ex_alloc_pool_with_tag(_pool: u64, size: u64, _tag: u64) -> u64 {
    unsafe { pool_alloc(size) }
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
        // section view mapping into session/system space (populates *MappedBase + *ViewSize)
        "MmMapViewInSessionSpace" | "MmMapViewInSystemSpace" => s_mm_map_view as usize as u64,
        // Rtl string init
        "RtlInitUnicodeString" => s_rtl_init_unicode_string as usize as u64,
        "RtlInitAnsiString" => s_rtl_init_ansi_string as usize as u64,
        // SSDT registration
        "KeAddSystemServiceTable" => s_ke_add_system_service_table as usize as u64,
        // debug print
        "DbgPrint" => s_dbg_print as usize as u64,
        "vDbgPrintExWithPrefix" => s_zero as usize as u64,
        // current process/thread → non-null zeroed placeholders (win32k derefs their fields)
        "IoGetCurrentProcess" | "PsGetCurrentProcess" => s_current_process as usize as u64,
        "PsGetCurrentThread" | "KeGetCurrentThread" => s_current_thread as usize as u64,
        "PsGetCurrentProcessWin32Process" | "PsGetProcessWin32Process" => {
            s_get_win32process as usize as u64
        }
        "PsGetCurrentThreadWin32Thread" | "PsGetThreadWin32Thread" => {
            s_get_win32thread as usize as u64
        }
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

    // Trip the sentinel: a read from an unmapped VA the executive's fault loop recognises.
    let _ = read_volatile(WIN32K_SENTINEL_VADDR as *const u64);
    park()
}
