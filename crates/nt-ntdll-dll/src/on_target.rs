//! # Step 4.B — the on-target, IN-PROCESS loader drive.
//!
//! Our `LdrpInitialize` runs IN smss's own VSpace (Step 4.A proved it: a trap issued from here
//! reached the kernel). So — exactly like the real ntdll — this module does the loader's live work
//! **in-process**:
//!
//! 1. **A real process heap** ([`HeapBacking`] over a region obtained via our own
//!    `NtAllocateVirtualMemory` `Nt*` stub → traps → serviced by the executive), so the loader
//!    engine's `alloc` (module Vecs etc.) works, as real ntdll creates the process heap early.
//! 2. **Import snap in-process**: read OUR own export directory (we are mapped at `ntdll_base`) and
//!    smss's import directory (smss's image is mapped at its `ImageBaseAddress`), resolve each of
//!    smss's ntdll imports name→our-export-address, and **write the address directly into smss's IAT
//!    slot** (`*(slot) = addr`) — a raw in-process pointer write, no syscall. This fixes the 4.A
//!    IAT-RVA mismatch (smss's IAT was pre-snapped by the executive against REAL-ntdll RVAs).
//!
//! The reads/writes go through mapped-image **RVA** walks (`base + rva`), NOT `nt-pe-loader::PeFile`
//! (which parses a FLAT FILE, where section file-offsets differ from RVAs). In-process the image is
//! already mapped, so RVA == memory offset from the base — a small dedicated walker is the honest
//! tool here.
//!
//! Everything is `unsafe` raw-pointer work over a live address space; the discipline is: only touch
//! pages the executive has mapped (image headers/sections + the heap region we just allocated), and
//! never fabricate a result.

extern crate alloc;

use core::{ffi::c_void, marker::PhantomData};

use nt_ntdll::heap::{Backing, Heap};
use nt_ntdll_layout::Teb;

// ---------------------------------------------------------------------------------------------
// In-process Nt* syscall callers (the trap backend — `mov r10,rcx; mov eax,ssn; syscall`).
// We call our OWN exported trap stub semantics inline. The executive services these via the fault
// EP exactly as it does smss's own ntdll calls.
// ---------------------------------------------------------------------------------------------

/// `NtAllocateVirtualMemory` SSN (shared `nt-syscall-abi` table).
const SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 18;
/// `NtFreeVirtualMemory` SSN.
const SSN_NT_FREE_VIRTUAL_MEMORY: u32 = 87;
/// `NtProtectVirtualMemory` SSN.
const SSN_NT_PROTECT_VIRTUAL_MEMORY: u32 = 143;

/// `NtRequestWaitReplyPort` SSN (CSR API message data plane).
#[cfg(target_arch = "x86_64")]
const SSN_NT_REQUEST_WAIT_REPLY_PORT: u32 = 208;

/// `STATUS_NO_MEMORY`.
const STATUS_NO_MEMORY: u64 = 0xC000_0017;

/// `MEM_COMMIT`.
const MEM_COMMIT: u32 = 0x0000_1000;
/// `MEM_RESERVE`.
const MEM_RESERVE: u32 = 0x0000_2000;
/// `MEM_COMMIT | MEM_RESERVE`.
const MEM_COMMIT_RESERVE: u32 = 0x0000_3000;
/// `MEM_RELEASE`.
const MEM_RELEASE: u32 = 0x0000_8000;
/// `PAGE_READWRITE`.
const PAGE_READWRITE: u32 = 0x04;
/// `PAGE_GUARD`.
const PAGE_GUARD: u32 = 0x100;
/// `NtCurrentProcess()` pseudo-handle.
const NT_CURRENT_PROCESS: u64 = u64::MAX; // (HANDLE)-1

/// Connected CSR client state, populated by `CsrClientConnectToServer` and consumed by
/// `CsrClientCallServer`. ReactOS keeps these as ntdll globals (`CsrApiPort`,
/// `CsrPortMemoryDelta`, `CsrProcessId`).
#[cfg(target_arch = "x86_64")]
static mut CSR_API_PORT: u64 = 0;
#[cfg(target_arch = "x86_64")]
static mut CSR_PORT_MEMORY_DELTA: isize = 0;
#[cfg(target_arch = "x86_64")]
static mut CSR_PROCESS_ID: u64 = 0;

/// Return the connected CSR process id (`CsrGetProcessId`).
#[cfg(target_arch = "x86_64")]
pub unsafe fn csr_process_id() -> u64 {
    // SAFETY: single-writer during CSR connect; later reads are plain scalar loads.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CSR_PROCESS_ID)) }
}

/// Return the connected CSR API port handle.
#[cfg(target_arch = "x86_64")]
pub unsafe fn csr_api_port() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CSR_API_PORT)) }
}

/// Return the client/server CSR port-memory delta.
#[cfg(target_arch = "x86_64")]
pub unsafe fn csr_port_memory_delta() -> isize {
    // SAFETY: single-writer during CSR connect; later reads are plain scalar loads.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CSR_PORT_MEMORY_DELTA)) }
}

/// Issue `NtRequestWaitReplyPort(CsrApiPort, message, message)` for a CSR API message.
///
/// # Safety
/// `message` must point to a writable CSR_API_MESSAGE whose PORT_MESSAGE header starts at byte 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn csr_request_wait_reply(message: u64) -> u32 {
    // SAFETY: single-writer during CSR connect; later reads are plain scalar loads.
    let port = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CSR_API_PORT)) };
    if port == 0 || message == 0 {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    // SAFETY: message is both request and reply buffer, matching ReactOS CsrClientCallServer.
    unsafe { seh_syscall3(SSN_NT_REQUEST_WAIT_REPLY_PORT, port, message, message) as u32 }
}

/// Issue `NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT|RESERVE, RW)`.
///
/// ★ The executive reads/writes `*BaseAddress` (RDX) and `*RegionSize` (R9) through its STACK
/// mirror, so `base`/`size` MUST be stack locals (they are — this fn's frame). On success it writes
/// the chosen base + rounded size back into them and returns STATUS_SUCCESS.
///
/// Returns the committed base VA, or 0 on failure.
///
/// This delegates to the generic 6-arg helper, so it flips between the TRAP and native seL4-Call
/// transports with the rest of the surface (ntdll_plan Step 6.A).
///
/// # Safety
/// Issues a real syscall serviced by the executive; only valid on-target in a hosted process.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn nt_allocate_virtual_memory(size_in: usize) -> u64 {
    // SAFETY: on-target hosted-process syscall.
    match unsafe {
        nt_allocate_virtual_memory_raw(0, size_in, 0, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    } {
        Ok((base, _)) => base,
        Err(_) => 0,
    }
}

/// Issue `NtAllocateVirtualMemory` with explicit base/size/type.
///
/// # Safety
/// On-target hosted-process syscall; the requested address range must be valid for the process.
#[cfg(target_arch = "x86_64")]
unsafe fn nt_allocate_virtual_memory_raw(
    base_in: u64,
    size_in: usize,
    zero_bits: u32,
    allocation_type: u32,
    protect: u32,
) -> Result<(u64, usize), u32> {
    let mut base: u64 = base_in;
    let mut region: u64 = size_in as u64;
    // arg1=ProcessHandle, arg2=&BaseAddress, arg3=ZeroBits, arg4=&RegionSize, arg5=AllocationType,
    // arg6=Protect. The executive reads/writes *BaseAddress + *RegionSize through its stack mirror.
    // SAFETY: base/region are valid stack locals for the out-writes.
    let status = unsafe {
        syscall6(
            SSN_NT_ALLOCATE_VIRTUAL_MEMORY,
            NT_CURRENT_PROCESS,
            core::ptr::addr_of_mut!(base) as u64,
            zero_bits as u64,
            core::ptr::addr_of_mut!(region) as u64,
            allocation_type as u64,
            protect as u64,
        )
    } as u32;
    if (status as i32) < 0 {
        Err(status)
    } else {
        Ok((base, region as usize))
    }
}

/// Issue `NtProtectVirtualMemory` for a current-process range.
///
/// # Safety
/// On-target hosted-process syscall; the requested address range must be valid.
#[cfg(target_arch = "x86_64")]
unsafe fn nt_protect_virtual_memory(base_in: u64, size_in: usize, protect: u32) -> u32 {
    let mut base = base_in;
    let mut size = size_in as u64;
    let mut old_protect = 0u32;
    // SAFETY: base/size/old_protect are stack locals for syscall out-params.
    unsafe {
        syscall6(
            SSN_NT_PROTECT_VIRTUAL_MEMORY,
            NT_CURRENT_PROCESS,
            core::ptr::addr_of_mut!(base) as u64,
            core::ptr::addr_of_mut!(size) as u64,
            protect as u64,
            core::ptr::addr_of_mut!(old_protect) as u64,
            0,
        ) as u32
    }
}

/// Issue `NtFreeVirtualMemory(MEM_RELEASE)` for a current-process stack reservation.
///
/// # Safety
/// On-target hosted-process syscall; `base_in` should be a stack allocation base.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn nt_release_virtual_memory(base_in: u64) -> u32 {
    let mut base = base_in;
    let mut size = 0u64;
    // SAFETY: base/size are stack locals for syscall out-params.
    unsafe {
        syscall6(
            SSN_NT_FREE_VIRTUAL_MEMORY,
            NT_CURRENT_PROCESS,
            core::ptr::addr_of_mut!(base) as u64,
            core::ptr::addr_of_mut!(size) as u64,
            MEM_RELEASE as u64,
            0,
            0,
        ) as u32
    }
}

// ---------------------------------------------------------------------------------------------
// The process heap: a real first-fit allocator (nt_ntdll::heap) over an NtAllocateVirtualMemory
// region, installed as the #[global_allocator] so the loader engine's `alloc` works in-process.
// ---------------------------------------------------------------------------------------------

/// The process-heap reservation size (1 MiB) — ample for the loader's transient Vecs. Committed up
/// front via one `NtAllocateVirtualMemory` (real ntdll grows on demand; a fixed reserve is enough
/// for the smss-only bring-up + keeps the seam simple).
const PROCESS_HEAP_SIZE: usize = 0x10_0000;

/// A [`Backing`] over a raw `NtAllocateVirtualMemory` region (base + len).
pub struct HeapBacking {
    pub(crate) base: *mut u8,
    pub(crate) len: usize,
    /// RTL owns VM it reserved itself, but must leave caller-supplied section/view memory mapped.
    pub(crate) owned: bool,
}

// SAFETY: `base..base+len` is a committed RW region from NtAllocateVirtualMemory, valid for the
// lifetime of the process, 16-byte-aligned (page-aligned in fact).
unsafe impl Backing for HeapBacking {
    fn base(&self) -> *mut u8 {
        self.base
    }
    fn len(&self) -> usize {
        self.len
    }
}

/// Initialize the process heap in-process. Returns `Some(heap)` once the region is committed.
///
/// # Safety
/// On-target only; issues the allocation syscall.
#[cfg(target_arch = "x86_64")]
unsafe fn create_process_heap() -> Option<(Heap<HeapBacking>, u64)> {
    // SAFETY: on-target hosted-process syscall.
    let base = unsafe { nt_allocate_virtual_memory(PROCESS_HEAP_SIZE) };
    if base == 0 {
        return None;
    }
    Heap::create(HeapBacking {
        base: base as *mut u8,
        len: PROCESS_HEAP_SIZE,
        owned: true,
    })
    .map(|h| (h, base))
}

// ---------------------------------------------------------------------------------------------
// A minimal MAPPED-IMAGE PE walker (by RVA). In-process every image is already mapped, so RVA is
// the offset from the module base — unlike nt-pe-loader::PeFile (flat-file, uses section
// file-offsets). We only need: the export directory (name→rva) and the import directory (which
// names + their IAT slot RVAs).
// ---------------------------------------------------------------------------------------------

/// Read a `u16` at `base + off`.
///
/// # Safety
/// `base + off` must be a mapped, readable address.
unsafe fn rd16(base: u64, off: u64) -> u16 {
    // SAFETY: caller guarantees the address is mapped.
    unsafe { core::ptr::read_unaligned((base + off) as *const u16) }
}
/// Read a `u32` at `base + off`.
///
/// # Safety
/// `base + off` must be a mapped, readable address.
unsafe fn rd32(base: u64, off: u64) -> u32 {
    // SAFETY: caller guarantees the address is mapped.
    unsafe { core::ptr::read_unaligned((base + off) as *const u32) }
}

/// Force-fault every 4 KiB page in `[start, start+len)` into the current process's VSpace by reading
/// one byte per page (volatile so the compiler can't elide it). Used before walking a dependency's
/// export tables: the executive demand-fills hosted DLL pages PER PROCESS, and an untouched export
/// array/name page reads back as zeros → a silent export-walk miss. Touching first fills them.
///
/// # Safety
/// `[start, start+len)` must be a reserved/mappable range in this VSpace (a mapped PE image extent).
unsafe fn touch_range(start: u64, len: u64) {
    // SAFETY: reads are within the dependency image's mapped extent (the export data directory lies
    // inside the image); each read faults-and-fills the page if absent.
    unsafe {
        let mut p = start & !0xFFFu64;
        let end = start + len;
        while p < end {
            let _ = core::ptr::read_volatile(p as *const u8);
            p += 0x1000;
        }
    }
}

/// The `(virtual_address, size)` of data directory `idx` in a mapped PE at `base`.
///
/// # Safety
/// `base` must be a mapped PE image (DOS + NT headers readable).
unsafe fn data_directory(base: u64, idx: u64) -> (u32, u32) {
    // SAFETY: reading the mapped PE headers per the contract.
    unsafe {
        let e_lfanew = rd32(base, 0x3c) as u64;
        // NT headers: Signature(4) + FileHeader(20) = 24; OptionalHeader starts at e_lfanew+24.
        // OptionalHeader is PE32+ (Magic 0x20b): DataDirectory begins at OptionalHeader+112.
        let opt = base + e_lfanew + 24;
        let dd = opt + 112 + idx * 8;
        let va = core::ptr::read_unaligned(dd as *const u32);
        let sz = core::ptr::read_unaligned((dd + 4) as *const u32);
        (va, sz)
    }
}

/// The `AddressOfEntryPoint` RVA of a mapped PE image (0 if none). OptionalHeader+16 on both PE32/32+.
///
/// # Safety
/// `base` must be a mapped PE image (DOS + NT headers readable).
#[cfg(target_arch = "x86_64")]
unsafe fn entry_point_rva(base: u64) -> u32 {
    // SAFETY: reading the mapped PE headers per the contract.
    unsafe {
        let e_lfanew = rd32(base, 0x3c) as u64;
        let opt = base + e_lfanew + 24; // OptionalHeader
        rd32_at(opt + 16) // AddressOfEntryPoint
    }
}

/// Read a `u32` at an absolute address.
///
/// # Safety
/// `addr` must be a mapped, readable address.
#[cfg(target_arch = "x86_64")]
unsafe fn rd32_at(addr: u64) -> u32 {
    // SAFETY: caller guarantees the address is mapped.
    unsafe { core::ptr::read_unaligned(addr as *const u32) }
}

/// Invoke a module's `DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)` with the
/// Windows x64 ABI (rcx=base, rdx=reason, r8=reserved). Returns the `BOOL` in EAX. A tiny naked-free
/// asm shim; the caller selects the native reserved value for attach, rollback, or shutdown.
///
/// # Safety
/// `entry_va` must be the mapped, executable entry point of a real DLL in this VSpace.
#[cfg(target_arch = "x86_64")]
unsafe fn call_dll_main(base: u64, reason: u32, reserved: u64) -> u64 {
    let entry = unsafe { base + entry_point_rva(base) as u64 };
    unsafe { call_init_routine(entry, base, reason, reserved) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn call_init_routine(entry: u64, base: u64, reason: u32, reserved: u64) -> u64 {
    type InitRoutine = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
    let routine: InitRoutine = unsafe { core::mem::transmute(entry as usize) };
    unsafe { routine(base as *mut c_void, reason, reserved as *mut c_void) as i64 as u64 }
}

/// Invoke every PE TLS callback for `reason`. IMAGE_TLS_DIRECTORY64.AddressOfCallBacks is an
/// absolute VA at offset 0x18 and points to a NULL-terminated callback array.
#[cfg(target_arch = "x86_64")]
unsafe fn call_tls_initializers(base: u64, reason: u32) {
    let (tls_rva, tls_size) = unsafe { data_directory(base, 9) };
    if tls_rva == 0 || tls_size < 0x28 {
        return;
    }
    let callbacks = unsafe {
        core::ptr::read_unaligned((base + tls_rva as u64 + 0x18) as *const u64)
    };
    if callbacks == 0 {
        return;
    }
    let mut index = 0u64;
    loop {
        let callback = unsafe {
            core::ptr::read_unaligned((callbacks + index * 8) as *const u64)
        };
        if callback == 0 {
            break;
        }
        let _ = unsafe { call_init_routine(callback, base, reason, 0) };
        index += 1;
        if index >= 256 {
            break;
        }
    }
}

/// Run `DLL_PROCESS_ATTACH` for every loaded DEPENDENT DLL (not the EXE, not our own ntdll), in
/// reverse discovery order (leaf dependencies first — the DFS `snap_module` inserts a parent before
/// its children, so the LAST-inserted entries are the deepest leaves). This is the live
/// `LdrpRunInitializeRoutines` seam: kernel32's `DllMain` runs `InitCommandLines()` (→
/// `GetCommandLineA`), msvcrt's runs its CRT `_acmdln` setup, etc. Without it winlogon's CRT startup
/// dereferences a NULL command line (`strdup(GetCommandLineA())` → `strlen(NULL)`).
///
/// # Safety
/// On-target; every table entry is a mapped DLL image whose imports have been snapped. `table` is a
/// valid `*mut ModuleTable` uniquely owned by the single-threaded loader (used mutably to RE-SNAP a
/// module's imports immediately before its DllMain — see [`attach_dfs`]).
#[cfg(target_arch = "x86_64")]
unsafe fn run_process_attach(table: *mut ModuleTable, startup_reserved: u64) -> u32 {
    let _callout = unsafe { crate::exports::enter_loader_callout() };
    // Post-order DFS: a module's DEPENDENCIES init before it (kernel32 before advapi32 before mpr,
    // etc.). A per-base visited set dedupes diamonds + breaks cycles. The order matters: mpr's
    // DllMain calls kernel32 functions, so kernel32 must have run InitCommandLines first. Reverse
    // insertion order was WRONG (mpr-first → kernel32 uninitialized → crash).
    // SAFETY: single-threaded loader uniquely owns `table`; each base is a mapped, snapped image.
    unsafe {
        let count = (*table).count.min(MODULE_TABLE_CAP);
        let mut visited = [0u64; MODULE_TABLE_CAP];
        let mut vn = 0usize;
        let mut newly_attached = [0u64; MODULE_TABLE_CAP];
        let mut attached_count = 0usize;
        let mut i = 0usize;
        while i < count {
            let b = (*table).mods[i].base;
            if b >= 0x1_0000 {
                let status = attach_dfs(
                    table,
                    b,
                    &mut visited,
                    &mut vn,
                    &mut newly_attached,
                    &mut attached_count,
                    startup_reserved,
                    0,
                );
                if status != 0 {
                    rollback_process_attach(table, &newly_attached[..attached_count]);
                    return status;
                }
            }
            i += 1;
        }
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn run_process_attach_root(table: *mut ModuleTable, base: u64) -> u32 {
    let _callout = unsafe { crate::exports::enter_loader_callout() };
    let mut visited = [0u64; MODULE_TABLE_CAP];
    let mut visited_count = 0usize;
    let mut newly_attached = [0u64; MODULE_TABLE_CAP];
    let mut attached_count = 0usize;
    let status = unsafe {
        attach_dfs(
            table,
            base,
            &mut visited,
            &mut visited_count,
            &mut newly_attached,
            &mut attached_count,
            0,
            0,
        )
    };
    if status != 0 {
        unsafe { rollback_process_attach(table, &newly_attached[..attached_count]) };
    }
    status
}

/// Recursively `DLL_PROCESS_ATTACH` `base`'s dependencies (post-order) then `base` itself. `visited`
/// records already-attached bases (dedupe + cycle break). Skips our own ntdll (no C DllMain).
///
/// # Safety
/// On-target; `base` is a mapped, snapped PE image in this VSpace; `table` (a `*mut ModuleTable`
/// uniquely owned by the single-threaded loader) holds mapped images.
#[cfg(target_arch = "x86_64")]
unsafe fn attach_dfs(
    table: *mut ModuleTable,
    base: u64,
    visited: &mut [u64; MODULE_TABLE_CAP],
    vn: &mut usize,
    newly_attached: &mut [u64; MODULE_TABLE_CAP],
    attached_count: &mut usize,
    attach_reserved: u64,
    depth: u32,
) -> u32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;
    if base < 0x1_0000 || depth > 16 {
        return 0xC000_0001; // STATUS_UNSUCCESSFUL
    }
    let Some(module_index) = (unsafe { (*table).index_by_base(base) }) else {
        return 0xC000_0135; // STATUS_DLL_NOT_FOUND
    };
    if unsafe { !(*table).mods[module_index].imports_ready } {
        return 0xC000_0135; // never run module callouts over a partial or failed IAT
    }
    if unsafe { (*table).mods[module_index].attached || (*table).mods[module_index].attaching } {
        return 0;
    }
    // Already attached?
    for &v in visited.iter().take(*vn) {
        if v == base {
            return 0;
        }
    }
    // Mark visited BEFORE recursing (cycle break).
    if *vn < MODULE_TABLE_CAP {
        visited[*vn] = base;
        *vn += 1;
    }
    // SAFETY: base is a mapped PE image; the import walk reads mapped headers; `table` uniquely owned.
    unsafe {
        (*table).mods[module_index].attaching = true;
        // Walk this module's imports; for each imported DLL found in the table, recurse first.
        let (idir_rva, _sz) = data_directory(base, 1);
        if idir_rva != 0 {
            let mut desc = base + idir_rva as u64;
            loop {
                let name_rva = rd32(desc, 12);
                let ft = rd32(desc, 16);
                if name_rva == 0 && ft == 0 {
                    break;
                }
                let mut nb = [0u8; 32];
                let bn = import_desc_basename(base, name_rva, &mut nb);
                let dep = (*table).find(&nb[..bn]);
                if dep >= 0x1_0000 && dep != base {
                    let status = attach_dfs(
                        table,
                        dep,
                        visited,
                        vn,
                        newly_attached,
                        attached_count,
                        attach_reserved,
                        depth + 1,
                    );
                    if status != 0 {
                        (*table).mods[module_index].attaching = false;
                        return status;
                    }
                }
                desc += 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
            }
        }
        // Skip our own ntdll (no C DllMain).
        if is_ntdll_base(&*table, base) {
            (*table).mods[module_index].attaching = false;
            if !record_attached(table, base, newly_attached, attached_count) {
                return 0xC000_0017; // STATUS_NO_MEMORY
            }
            (*table).mods[module_index].attached = true;
            set_ldr_process_attached(base, true);
            return 0;
        }
        let epr = entry_point_rva(base);
        if epr == 0 {
            (*table).mods[module_index].attaching = false;
            if !record_attached(table, base, newly_attached, attached_count) {
                return 0xC000_0017; // STATUS_NO_MEMORY
            }
            (*table).mods[module_index].attached = true;
            set_ldr_process_attached(base, true);
            return 0; // resource-only DLL — nothing to run
        }
        let mut activation_frame = [0u64; 7];
        let _activation_context =
            match ModuleActivationContextGuard::enter(base, &mut activation_frame) {
                Ok(guard) => guard,
                Err(status) => {
                    (*table).mods[module_index].attaching = false;
                    return status;
                }
            };
        // ★ RE-SNAP this module's imports RIGHT BEFORE its DllMain runs. The executive demand-fills a
        // hosted DLL's per-process pages (headers/.rdata/.idata/IAT) lazily and from the ON-DISK PE
        // (raw, un-snapped thunks); a page we snapped earlier (during the static import walk) can be
        // re-faulted later in the loader and RE-FILLED from the PE, silently reverting our IAT writes
        // (observed: comdlg32's kernel32 IAT slot held our resolved 0x803c14f0 immediately after the
        // snap, then read back the raw 0x3ad64 by DllMain time). Re-snapping here — on the same thread,
        // immediately before the `jmp *IAT[..]`, so the pages are freshly resident — makes the IAT the
        // DllMain sees authoritative. `snap_module` is idempotent (re-resolves + re-writes each thunk),
        // de-dupes loads via the table, and is cheap for an already-mapped graph.
        let ntdll_base = (*table).find(b"ntdll");
        if ntdll_base != 0 {
            let mut sink = SnapResult::default();
            snap_module(base, ntdll_base, table, &mut sink, 0);
            if sink.status != 0 {
                (*table).mods[module_index].attaching = false;
                return sink.status;
            }
        }
        {
            let mut mb = [0u8; 64];
            let mut mn = 0usize;
            for &c in b"DllMain base=0x" {
                if mn < 64 {
                    mb[mn] = c;
                    mn += 1;
                }
            }
            mn = crate::write_u64_hex(&mut mb, mn, base);
            crate::dbg_print_bytes(mb.as_ptr(), mn);
        }
        call_tls_initializers(base, DLL_PROCESS_ATTACH);
        if call_dll_main(base, DLL_PROCESS_ATTACH, attach_reserved) == 0 {
            (*table).mods[module_index].attaching = false;
            return 0xC000_0142; // STATUS_DLL_INIT_FAILED
        }
        if !record_attached(table, base, newly_attached, attached_count) {
            call_tls_initializers(base, DLL_PROCESS_DETACH);
            let _ = call_dll_main(base, DLL_PROCESS_DETACH, 0);
            (*table).mods[module_index].attaching = false;
            return 0xC000_0017; // STATUS_NO_MEMORY
        }
        (*table).mods[module_index].attaching = false;
        (*table).mods[module_index].attached = true;
        set_ldr_process_attached(base, true);
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn record_attached(
    table: *mut ModuleTable,
    base: u64,
    newly_attached: &mut [u64; MODULE_TABLE_CAP],
    attached_count: &mut usize,
) -> bool {
    if !unsafe { (*table).attach_order.record(base) } {
        return false;
    }
    if *attached_count < MODULE_TABLE_CAP {
        newly_attached[*attached_count] = base;
        *attached_count += 1;
        true
    } else {
        unsafe { (*table).attach_order.remove(base) };
        false
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn rollback_process_attach(table: *mut ModuleTable, attached: &[u64]) {
    const DLL_PROCESS_DETACH: u32 = 0;
    for &base in attached.iter().rev() {
        let Some(index) = (unsafe { (*table).index_by_base(base) }) else {
            continue;
        };
        if unsafe { !(*table).mods[index].attached } {
            continue;
        }
        if unsafe { !is_ntdll_base(&*table, base) && entry_point_rva(base) != 0 } {
            unsafe {
                let mut activation_frame = [0u64; 7];
                if let Ok(_activation_context) =
                    ModuleActivationContextGuard::enter(base, &mut activation_frame)
                {
                    call_tls_initializers(base, DLL_PROCESS_DETACH);
                    let _ = call_dll_main(base, DLL_PROCESS_DETACH, 0);
                };
            }
        }
        unsafe {
            (*table).mods[index].attached = false;
            (*table).mods[index].attaching = false;
            (*table).attach_order.remove(base);
            set_ldr_process_attached(base, false);
        }
    }
}

/// Run successful module process-detach callbacks in reverse process-attach order.
///
/// # Safety
/// The process loader lock is held and all ledger bases remain mapped.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldr_shutdown_process() -> u32 {
    const DLL_PROCESS_DETACH: u32 = 0;
    let table = core::ptr::addr_of_mut!(MODULE_TABLE);
    let mut index = unsafe { (*table).attach_order.as_slice().len() };
    while index != 0 {
        index -= 1;
        let base = unsafe { (*table).attach_order.as_slice()[index] };
        let Some(module_index) = (unsafe { (*table).index_by_base(base) }) else {
            continue;
        };
        if unsafe { !(*table).mods[module_index].attached || is_ntdll_base(&*table, base) } {
            continue;
        }
        if unsafe { entry_point_rva(base) } == 0 {
            continue;
        }
        unsafe {
            let mut activation_frame = [0u64; 7];
            let Ok(_activation_context) =
                ModuleActivationContextGuard::enter(base, &mut activation_frame)
            else {
                return STATUS_NO_MEMORY as u32;
            };
            call_tls_initializers(base, DLL_PROCESS_DETACH);
            let _ = call_dll_main(base, DLL_PROCESS_DETACH, 1);
        }
    }
    0
}

/// Run balanced thread-detach callbacks for a thread whose loader initialization committed.
///
/// # Safety
/// The process loader lock is held and `teb` identifies the current live TEB.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldr_shutdown_thread(teb: u64, process_shutdown: bool) -> u32 {
    const DLL_THREAD_DETACH: u32 = 3;
    let committed = unsafe {
        (*core::ptr::addr_of_mut!(THREAD_INIT_LEDGER)).take_committed_for_shutdown(teb)
    };
    let table = unsafe { &*core::ptr::addr_of!(MODULE_TABLE) };
    let mut modules = [nt_ntdll::loader::thread::ThreadModuleState::default(); MODULE_TABLE_CAP];
    let mut count = 0usize;
    if committed {
        for &base in table.attach_order.as_slice() {
            if count == modules.len() {
                return STATUS_NO_MEMORY as u32;
            }
            let entry = unsafe { ldr_entry_for_base(base) };
            let flags = if entry != 0 {
                unsafe { core::ptr::read_unaligned((entry + 0x68) as *const u32) }
            } else {
                0
            };
            let (tls_rva, tls_size) = unsafe { data_directory(base, 9) };
            modules[count] = nt_ntdll::loader::thread::ThreadModuleState {
                base,
                entry_point_rva: unsafe { entry_point_rva(base) },
                flags,
                has_tls: tls_rva != 0 && tls_size >= 0x28,
                is_ntdll: is_ntdll_base(table, base),
            };
            count += 1;
        }
    }
    let executable_tls_base = if committed {
        let base = unsafe { EXE_BASE };
        let (tls_rva, tls_size) = if base != 0 {
            unsafe { data_directory(base, 9) }
        } else {
            (0, 0)
        };
        if tls_rva != 0 && tls_size >= 0x28 {
            base
        } else {
            0
        }
    } else {
        0
    };
    let Ok(plan) = nt_ntdll::loader::thread::plan_thread_detach::<MODULE_TABLE_CAP>(
        committed,
        process_shutdown,
        &modules[..count],
        executable_tls_base,
    ) else {
        return STATUS_NO_MEMORY as u32;
    };

    let _callout = unsafe { crate::exports::enter_loader_callout() };
    for action in plan.actions() {
        let mut activation_frame = [0u64; 7];
        let Ok(_activation_context) =
            (unsafe { ModuleActivationContextGuard::enter(action.base, &mut activation_frame) })
        else {
            continue;
        };
        if action.call_tls {
            unsafe { call_tls_initializers(action.base, DLL_THREAD_DETACH) };
        }
        let _ = unsafe { call_dll_main(action.base, DLL_THREAD_DETACH, 0) };
    }
    if plan.executable_tls_base() != 0 {
        let mut activation_frame = [0u64; 7];
        if let Ok(_activation_context) = unsafe {
            ModuleActivationContextGuard::enter(
                plan.executable_tls_base(),
                &mut activation_frame,
            )
        } {
            unsafe { call_tls_initializers(plan.executable_tls_base(), DLL_THREAD_DETACH) };
        };
    }
    0
}

/// True if `base` is our own ntdll (matched by the table's `b"ntdll"` entry) — it has no C DllMain.
#[cfg(target_arch = "x86_64")]
fn is_ntdll_base(table: &ModuleTable, base: u64) -> bool {
    table.find(b"ntdll") == base
}

/// Compare a NUL-terminated ASCII export name at `base + name_rva` against `want` (ASCII bytes).
///
/// # Safety
/// `base + name_rva` must point at a mapped, NUL-terminated ASCII string.
unsafe fn name_eq(base: u64, name_rva: u32, want: &[u8]) -> bool {
    // SAFETY: caller guarantees a mapped NUL-terminated string.
    unsafe {
        let p = (base + name_rva as u64) as *const u8;
        let mut i = 0usize;
        loop {
            let c = core::ptr::read(p.add(i));
            if i >= want.len() {
                return c == 0; // exact length match: next char must be the NUL
            }
            if c != want[i] {
                return false;
            }
            i += 1;
        }
    }
}

/// Resolve an export **by name** in the mapped PE at `base` → its target RVA (0 if not found).
/// Forwarders (RVA inside the export dir) are NOT expected for smss's ntdll imports (our ntdll's
/// exports are all concrete), so a forwarder RVA is returned as-is (still resolves to our own image,
/// which for the smss set never happens) — the honest path.
///
/// # Safety
/// `base` must be a mapped PE image.
unsafe fn export_rva_by_name(base: u64, want: &[u8]) -> u32 {
    // SAFETY: reading the mapped export directory per the contract.
    unsafe {
        let (edir_rva, edir_sz) = data_directory(base, 0); // IMAGE_DIRECTORY_ENTRY_EXPORT = 0
        if edir_rva == 0 {
            return 0;
        }
        // ★ Force-fault the WHOLE export directory region into THIS process's VSpace before the walk.
        // The executive demand-faults each hosted DLL page-by-page PER PROCESS; a dependency's export
        // tables (Export Directory + AddressOfNames/Functions/NameOrdinals + the name strings — all
        // inside the export data-directory range in PE images we host) may not yet be present in the
        // CURRENT process's VSpace when we snap against it. An unfaulted array/name page reads back as
        // a zero page (no synchronous fault-and-fill on read here) → `name_eq` mismatches → the walk
        // silently returns 0 → the IAT slot is left at its raw ILT value → a later `jmp *IAT[..]` faults
        // to a bare RVA. (Observed: comdlg32's kernel32 `GetSystemTimeAsFileTime` [name idx 458, deep in
        // kernel32's 982-name table] resolved fine in csrss's VSpace but returned 0 in winlogon's — a
        // pure per-VSpace demand-paging gap, NOT an export-table math bug: the direct AoNO[458]/AoF[ord]
        // read gave the correct 0x214f0 once the page was touched.) Touching every page here forces the
        // executive's fault router to fill them from the dependency's parsed PE, so the walk sees the
        // real tables. This is the general fix — it makes EVERY export resolution robust against the
        // lazy per-process fill, not just this one symbol.
        touch_range(base + edir_rva as u64, edir_sz as u64);
        let ed = base + edir_rva as u64;
        let number_of_names = rd32(ed, 0x18);
        let addr_of_functions = rd32(ed, 0x1c) as u64; // AddressOfFunctions RVA
        let addr_of_names = rd32(ed, 0x20) as u64; // AddressOfNames RVA
        let addr_of_ordinals = rd32(ed, 0x24) as u64; // AddressOfNameOrdinals RVA
        for i in 0..number_of_names as u64 {
            let name_rva = rd32(base, addr_of_names + i * 4);
            if name_eq(base, name_rva, want) {
                let ordinal = rd16(base, addr_of_ordinals + i * 2) as u64;
                let func_rva = rd32(base, addr_of_functions + ordinal * 4);
                return func_rva;
            }
        }
        0
    }
}

/// The result of the in-process import snap.
#[derive(Copy, Clone, Debug, Default)]
pub struct SnapResult {
    /// Number of smss ntdll imports resolved + written.
    pub resolved: u32,
    /// Number of imports that could NOT be resolved (missing export) — should be 0.
    pub missing: u32,
    /// A spot-check IAT slot's written value (for the boot-log proof it points into our ntdll).
    pub spot_iat_value: u64,
    /// The IAT slot RVA the spot value came from.
    pub spot_iat_rva: u32,
    /// First loader-entry preparation failure observed while recursively snapping.
    pub status: u32,
}

/// **Snap smss's ntdll imports in-process** against OUR export table.
///
/// Walks smss's import directory (mapped at `smss_base`); for each descriptor naming `ntdll` (any
/// case, with/without the `.dll` suffix — smss imports ONLY ntdll), resolves each imported name in
/// OUR export directory (mapped at `ntdll_base`) and writes `ntdll_base + export_rva` into the
/// corresponding IAT slot in smss's image (a direct in-process pointer write — the slot page is RW
/// + demand-faulted). Returns a [`SnapResult`] for the boot-log proof.
///
/// # Safety
/// `smss_base` + `ntdll_base` must be mapped PE images in this VSpace; the IAT pages must be
/// writable (they are — `.rdata`, RW_NX). On-target only.
pub unsafe fn snap_smss_imports(smss_base: u64, ntdll_base: u64) -> SnapResult {
    let mut out = SnapResult::default();
    // SAFETY: reading smss's mapped import directory + writing its mapped RW IAT per the contract.
    unsafe {
        let (idir_rva, _sz) = data_directory(smss_base, 1); // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
        if idir_rva == 0 {
            return out;
        }
        // Walk the IMAGE_IMPORT_DESCRIPTOR array (20 bytes each), terminated by an all-zero entry.
        let mut desc = smss_base + idir_rva as u64;
        loop {
            let original_first_thunk = rd32(desc, 0); // OriginalFirstThunk (ILT) RVA
            let name_rva = rd32(desc, 12); // Name RVA
            let first_thunk = rd32(desc, 16); // FirstThunk (IAT) RVA
            if name_rva == 0 && first_thunk == 0 {
                break; // terminator
            }
            // Only snap the ntdll descriptor (smss imports ONLY ntdll, but be defensive).
            if import_desc_is_ntdll(smss_base, name_rva) {
                // Use the ILT (OriginalFirstThunk) for the names if present, else the IAT itself.
                let ilt_rva = if original_first_thunk != 0 {
                    original_first_thunk
                } else {
                    first_thunk
                };
                let mut ilt = smss_base + ilt_rva as u64;
                let mut iat = smss_base + first_thunk as u64;
                loop {
                    let thunk = core::ptr::read_unaligned(ilt as *const u64);
                    if thunk == 0 {
                        break; // end of this descriptor's imports
                    }
                    // Bit 63 set = import by ordinal; smss imports ALL by name (measured), but guard.
                    if thunk & (1u64 << 63) == 0 {
                        // IMAGE_IMPORT_BY_NAME at RVA (thunk & 0x7fffffff): Hint(2) + NUL-term name.
                        let ibn_rva = (thunk & 0x7fff_ffff) as u32;
                        let name_ptr_rva = ibn_rva + 2; // skip the 2-byte Hint
                        let mut namebuf = [0u8; 96];
                        let nlen = read_cstr(smss_base, name_ptr_rva, &mut namebuf);
                        let export_rva = export_rva_by_name(ntdll_base, &namebuf[..nlen]);
                        let iat_slot_rva = (iat - smss_base) as u32;
                        if export_rva != 0 {
                            let addr = ntdll_base + export_rva as u64;
                            core::ptr::write_unaligned(iat as *mut u64, addr);
                            out.resolved += 1;
                            if out.spot_iat_value == 0 {
                                out.spot_iat_value = addr;
                                out.spot_iat_rva = iat_slot_rva;
                            }
                        } else {
                            out.missing += 1;
                        }
                    }
                    ilt += 8;
                    iat += 8;
                }
            }
            desc += 20;
        }
    }
    out
}

/// Is the import descriptor's DLL name `ntdll` (case-insensitive, `.dll` optional)?
///
/// # Safety
/// `smss_base + name_rva` must point at a mapped, NUL-terminated ASCII string.
unsafe fn import_desc_is_ntdll(smss_base: u64, name_rva: u32) -> bool {
    let mut buf = [0u8; 64];
    // SAFETY: caller contract.
    let n = unsafe { read_cstr(smss_base, name_rva, &mut buf) };
    let name = &buf[..n];
    // Lowercase-compare against "ntdll" or "ntdll.dll".
    let mut lower = [0u8; 64];
    for (i, &b) in name.iter().enumerate() {
        lower[i] = b.to_ascii_lowercase();
    }
    let l = &lower[..n];
    l == b"ntdll.dll" || l == b"ntdll"
}

/// Read a NUL-terminated ASCII string at `base + rva` into `buf`; returns the byte length (excl NUL).
///
/// # Safety
/// `base + rva` must point at a mapped, NUL-terminated ASCII string.
unsafe fn read_cstr(base: u64, rva: u32, buf: &mut [u8]) -> usize {
    // SAFETY: caller contract.
    unsafe {
        let p = (base + rva as u64) as *const u8;
        let mut i = 0usize;
        while i < buf.len() {
            let c = core::ptr::read(p.add(i));
            if c == 0 {
                break;
            }
            buf[i] = c;
            i += 1;
        }
        i
    }
}

// ---------------------------------------------------------------------------------------------
// BATCH 2 — the recursive dependent-DLL loader (Ldr live-op).
//
// smss imports ONLY ntdll, so its `LdrpInitialize` never needed to load a dependent DLL. csrss
// (the current frontier) statically imports **csrsrv.dll** (`CsrServerInitialization`) in addition
// to ntdll. Its IAT slot for the csrsrv import stays at the raw ILT value (a low RVA, e.g. 0x2440)
// until the loader resolves it — and csrss's first act is to CALL `CsrServerInitialization`, so an
// unresolved slot faults as an instruction-fetch at that low address (the observed 0x2440 wall).
//
// Real ntdll's `LdrpInitialize` → `LdrpWalkImportDescriptor` walks EVERY import descriptor: for each
// dependency not already loaded, it maps the DLL (the executive services NtOpenFile →
// NtCreateSection(SEC_IMAGE) → NtMapViewOfSection, assigning csrsrv its pinned base 0x8000_0000),
// snaps THAT DLL's own imports (recursively), then snaps the current module's thunks against the
// dependency's exports. We do the same IN-PROCESS over our mapped-image RVA walker + our own Nt*
// stubs. The `MODULE_TABLE` de-dupes loads (name → base) so a diamond / repeat dependency maps once
// and recursion terminates.
// ---------------------------------------------------------------------------------------------

/// `NtMapViewOfSection` SSN (shared `nt-syscall-abi` table).
#[cfg(target_arch = "x86_64")]
const SSN_NT_MAP_VIEW_OF_SECTION: u32 = 113;

/// The largest dependency graph we resolve in one process. ★ winlogon's runtime graph is LARGE — it
/// LoadLibrary's the crypto/UI stack (comdlg32, shell32, comctl32, wintrust, crypt32, dbghelp, …) so
/// **55+ distinct DLLs** load in one process. The table MUST hold every loaded module: it is the
/// dedup key (`find` → skip re-map) AND the DFS `run_process_attach` module set. At cap 32 the table
/// OVERFLOWED — `insert` silently dropped the 33rd+ module, so `find` later returned 0 for it → the
/// executive RE-MAPPED that DLL fresh over its VA (a new SEC_IMAGE view with a RAW, unsnapped IAT),
/// and its `DllMain` then `jmp`ed through an unsnapped import thunk to a bare RVA (comdlg32's
/// `GetSystemTimeAsFileTime` = 0x3ad64). Sized well above the observed 55 for headroom (csrss's tiny
/// graph is unaffected; the cost is a larger static table + a deeper DFS `visited`/`entry_vas`).
#[cfg(target_arch = "x86_64")]
const MODULE_TABLE_CAP: usize = 256;

/// A loaded dependent module: its lowercased base name (`.dll` optional, ≤ 31 bytes) + mapped base.
/// The image we started snapping from (the EXE, `image_base`) is seeded as entry 0; ntdll as entry 1.
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
struct LoadedMod {
    /// Lowercased base name bytes (no path, no NUL) — e.g. `b"csrsrv"` / `b"ntdll"`.
    name: [u8; 32],
    /// Byte length of `name`.
    nlen: u8,
    /// The module's mapped base VA (0 = empty slot).
    base: u64,
    /// Process-attach lifecycle persisted across static initialization and runtime LdrLoadDll calls.
    attached: bool,
    attaching: bool,
    /// The mapped image's ordinary and delay import tables have been snapped at least once.
    imports_ready: bool,
    /// A snap transaction currently owns this mapping; dependency back-edges may resolve it but
    /// no TLS callback or DllMain may run until the transaction commits.
    imports_in_progress: bool,
    /// The last import transaction failed; the mapped image and Ldr entry remain retryable.
    imports_failed: bool,
    /// A runtime load reached DllMain but failed before publishing a handle/notification.
    attach_failed: bool,
}

/// The per-drive module table (single-threaded loader; a process's LdrpInitialize runs once, on one
/// thread, before any other thread exists). Not shared across processes — each spawn re-runs the
/// drive fresh in its own VSpace.
#[cfg(target_arch = "x86_64")]
struct ModuleTable {
    mods: [LoadedMod; MODULE_TABLE_CAP],
    count: usize,
    attach_order: nt_ntdll::loader::lifecycle::AttachLedger<MODULE_TABLE_CAP>,
}

/// The PROCESS-WIDE loaded-module table. Single-threaded loader context (the process's LdrpInitialize
/// + all subsequent `LdrLoadDll`/`LdrGetDllHandle` calls run before any competing thread touches it —
/// csrsrv's CsrLoadServerDll runs on the main thread during CsrServerInitialization). Seeded by
/// [`snap_all_imports`] (ntdll + the EXE's static deps), then extended by runtime `LdrLoadDll`.
#[cfg(target_arch = "x86_64")]
static mut MODULE_TABLE: ModuleTable = ModuleTable {
    mods: [LoadedMod {
        name: [0u8; 32],
        nlen: 0,
        base: 0,
        attached: false,
        attaching: false,
        imports_ready: false,
        imports_in_progress: false,
        imports_failed: false,
        attach_failed: false,
    }; MODULE_TABLE_CAP],
    count: 0,
    attach_order: nt_ntdll::loader::lifecycle::AttachLedger::new(),
};

/// Balances future per-thread attach and detach callouts. No current thread is committed until the
/// secondary-thread initialization path begins issuing DLL_THREAD_ATTACH.
#[cfg(target_arch = "x86_64")]
static mut THREAD_INIT_LEDGER: nt_ntdll::loader::lifecycle::ThreadInitLedger<MODULE_TABLE_CAP> =
    nt_ntdll::loader::lifecycle::ThreadInitLedger::new();

#[cfg(target_arch = "x86_64")]
static mut STATIC_TLS_CATALOG: nt_ntdll::loader::tls::StaticTlsCatalog<MODULE_TABLE_CAP> =
    nt_ntdll::loader::tls::StaticTlsCatalog::new();

#[cfg(target_arch = "x86_64")]
unsafe fn current_teb() -> *mut Teb {
    let teb: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, preserves_flags, readonly)
        )
    };
    teb as *mut Teb
}

#[cfg(target_arch = "x86_64")]
unsafe fn image_tls_directory(base: u64) -> Option<nt_ntdll::loader::tls::ImageTlsDirectory> {
    let (rva, size) = unsafe { data_directory(base, 9) };
    if rva == 0 || size < 0x28 {
        return None;
    }
    let directory = base + rva as u64;
    Some(nt_ntdll::loader::tls::ImageTlsDirectory {
        start_address_of_raw_data: unsafe {
            core::ptr::read_unaligned(directory as *const u64)
        },
        end_address_of_raw_data: unsafe {
            core::ptr::read_unaligned((directory + 0x08) as *const u64)
        },
        address_of_index: unsafe {
            core::ptr::read_unaligned((directory + 0x10) as *const u64)
        },
        address_of_callbacks: unsafe {
            core::ptr::read_unaligned((directory + 0x18) as *const u64)
        },
        size_of_zero_fill: unsafe {
            core::ptr::read_unaligned((directory + 0x20) as *const u32)
        },
    })
}

#[cfg(target_arch = "x86_64")]
unsafe fn add_image_static_tls(
    catalog: &mut nt_ntdll::loader::tls::StaticTlsCatalog<MODULE_TABLE_CAP>,
    base: u64,
) -> Result<(), u32> {
    let Some(directory) = (unsafe { image_tls_directory(base) }) else {
        return Ok(());
    };
    catalog
        .add(base, directory)
        .map(|_| ())
        .map_err(|_| 0xC000_007B) // STATUS_INVALID_IMAGE_FORMAT
}

#[cfg(target_arch = "x86_64")]
unsafe fn allocate_current_thread_static_tls() -> u32 {
    let catalog = unsafe { &*core::ptr::addr_of!(STATIC_TLS_CATALOG) };
    let teb = unsafe { current_teb() };
    if teb.is_null() {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    unsafe { (*teb).thread_local_storage_pointer = 0 };
    if catalog.is_empty() {
        return 0;
    }

    let vector_size = match catalog.len().checked_mul(core::mem::size_of::<u64>()) {
        Some(size) => size,
        None => return STATUS_NO_MEMORY as u32,
    };
    let vector = unsafe { crate::process_heap_alloc(vector_size) } as *mut u64;
    if vector.is_null() {
        return STATUS_NO_MEMORY as u32;
    }
    unsafe { core::ptr::write_bytes(vector.cast::<u8>(), 0, vector_size) };

    for entry in catalog.entries() {
        let Some(size) = entry.allocation_size() else {
            unsafe { free_static_tls_vector(vector) };
            return STATUS_NO_MEMORY as u32;
        };
        let block = unsafe { crate::process_heap_alloc(size.max(1)) };
        if block.is_null() {
            unsafe { free_static_tls_vector(vector) };
            return STATUS_NO_MEMORY as u32;
        }
        if entry.raw_data_size != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    entry.raw_data_address as *const u8,
                    block,
                    entry.raw_data_size,
                )
            };
        }
        if entry.zero_fill_size != 0 {
            unsafe {
                core::ptr::write_bytes(
                    block.add(entry.raw_data_size),
                    0,
                    entry.zero_fill_size,
                )
            };
        }
        unsafe { core::ptr::write(vector.add(entry.index as usize), block as u64) };
    }
    unsafe { (*teb).thread_local_storage_pointer = vector as u64 };
    0
}

#[cfg(target_arch = "x86_64")]
unsafe fn free_static_tls_vector(vector: *mut u64) {
    if vector.is_null() {
        return;
    }
    let catalog = unsafe { &*core::ptr::addr_of!(STATIC_TLS_CATALOG) };
    for entry in catalog.entries() {
        let block = unsafe { core::ptr::read(vector.add(entry.index as usize)) } as *mut u8;
        if !block.is_null() {
            let _ = unsafe { crate::process_heap_free(block) };
        }
    }
    let _ = unsafe { crate::process_heap_free(vector.cast()) };
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn free_current_thread_static_tls() {
    let teb = unsafe { current_teb() };
    if teb.is_null() {
        return;
    }
    let vector = unsafe { (*teb).thread_local_storage_pointer as *mut u64 };
    unsafe { (*teb).thread_local_storage_pointer = 0 };
    unsafe { free_static_tls_vector(vector) };
}

#[cfg(target_arch = "x86_64")]
unsafe fn initialize_process_static_tls(exe_base: u64, table: *const ModuleTable) -> u32 {
    let mut catalog = nt_ntdll::loader::tls::StaticTlsCatalog::<MODULE_TABLE_CAP>::new();
    if let Err(status) = unsafe { add_image_static_tls(&mut catalog, exe_base) } {
        return status;
    }
    let table = unsafe { &*table };
    for module in &table.mods[..table.count.min(MODULE_TABLE_CAP)] {
        if module.base != 0 && module.base != exe_base {
            if let Err(status) = unsafe { add_image_static_tls(&mut catalog, module.base) } {
                return status;
            }
        }
    }

    for entry in catalog.entries() {
        unsafe { core::ptr::write_unaligned(entry.address_of_index as *mut u32, entry.index) };
        let ldr_entry = unsafe { ldr_entry_for_base(entry.module_base) };
        if ldr_entry != 0 {
            unsafe { core::ptr::write_unaligned((ldr_entry + 0x6e) as *mut u16, u16::MAX) };
        }
    }
    unsafe { STATIC_TLS_CATALOG = catalog };
    unsafe { allocate_current_thread_static_tls() }
}

#[cfg(target_arch = "x86_64")]
impl ModuleTable {
    /// Insert `(name, base)` (name already lowercased, no `.dll` suffix). Ignores overflow + dups.
    fn insert(&mut self, name: &[u8], base: u64) {
        if self.find_any(name) != 0 {
            return; // already present
        }
        if self.count >= MODULE_TABLE_CAP {
            return;
        }
        let mut m = LoadedMod {
            name: [0u8; 32],
            nlen: 0,
            base,
            attached: false,
            attaching: false,
            imports_ready: false,
            imports_in_progress: false,
            imports_failed: false,
            attach_failed: false,
        };
        let n = name.len().min(32);
        m.name[..n].copy_from_slice(&name[..n]);
        m.nlen = n as u8;
        self.mods[self.count] = m;
        self.count += 1;
    }

    /// Find a loaded module by lowercased base name; returns its base (0 if absent).
    fn find(&self, name: &[u8]) -> u64 {
        for m in &self.mods[..self.count] {
            if (!m.imports_failed || m.imports_in_progress)
                && m.nlen as usize == name.len()
                && &m.name[..name.len()] == name
            {
                return m.base;
            }
        }
        0
    }

    fn find_any(&self, name: &[u8]) -> u64 {
        for m in &self.mods[..self.count] {
            if m.nlen as usize == name.len() && &m.name[..name.len()] == name {
                return m.base;
            }
        }
        0
    }

    fn index_by_base(&self, base: u64) -> Option<usize> {
        self.mods[..self.count]
            .iter()
            .position(|module| module.base == base)
    }

    fn imports_ready(&self, base: u64) -> bool {
        self.index_by_base(base)
            .is_some_and(|index| self.mods[index].imports_ready)
    }

    fn begin_imports(&mut self, base: u64) {
        if let Some(index) = self.index_by_base(base) {
            self.mods[index].imports_ready = false;
            self.mods[index].imports_in_progress = true;
            self.mods[index].imports_failed = false;
        }
    }

    fn set_imports_ready(&mut self, base: u64) {
        if let Some(index) = self.index_by_base(base) {
            self.mods[index].imports_ready = true;
            self.mods[index].imports_in_progress = false;
            self.mods[index].imports_failed = false;
        }
    }

    fn set_imports_failed(&mut self, base: u64) {
        if let Some(index) = self.index_by_base(base) {
            self.mods[index].imports_ready = false;
            self.mods[index].imports_in_progress = false;
            self.mods[index].imports_failed = true;
        }
    }

    fn attach_failed(&self, base: u64) -> bool {
        self.index_by_base(base)
            .is_some_and(|index| self.mods[index].attach_failed)
    }

    fn set_attach_failed(&mut self, base: u64, failed: bool) {
        if let Some(index) = self.index_by_base(base) {
            self.mods[index].attach_failed = failed;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SEH support: RtlLookupFunctionEntry over the loaded module set.
//
// The x64 SEH unwinder (`nt_ntdll::rtl::exception`) needs, for an absolute control PC: the
// containing image base + the covering `RUNTIME_FUNCTION` from that image's `.pdata`
// (IMAGE_DIRECTORY_ENTRY_EXCEPTION). We scan every loaded module (the EXE + MODULE_TABLE) whose
// mapped `[base, base+SizeOfImage)` contains the PC, then binary-search its `.pdata`.
// ---------------------------------------------------------------------------------------------

/// The EXE (root) image base — set by [`ldrp_drive`]. Not in `MODULE_TABLE` (which holds only
/// dependencies), so tracked separately for the SEH module scan.
#[cfg(target_arch = "x86_64")]
static mut EXE_BASE: u64 = 0;

/// Run-once guard for the BATCH 42 live SEH self-test (first hosted process only).
#[cfg(target_arch = "x86_64")]
static mut SEH_SELFTEST_DONE: bool = false;

/// `IMAGE_DIRECTORY_ENTRY_EXCEPTION`.
#[cfg(target_arch = "x86_64")]
const DIRECTORY_ENTRY_EXCEPTION: u64 = 3;

/// Find the image base whose mapped extent contains `pc` (scans the EXE + every `MODULE_TABLE`
/// module). Returns 0 if `pc` is in no known module.
///
/// # Safety
/// Reads mapped PE headers of each loaded module.
#[cfg(target_arch = "x86_64")]
pub unsafe fn seh_containing_image(pc: u64) -> u64 {
    // SAFETY: single-threaded loader context; module images stay mapped for the process lifetime.
    unsafe {
        let exe = EXE_BASE;
        if exe != 0 && pc >= exe {
            let sz = size_of_image(exe) as u64;
            if sz != 0 && pc < exe + sz {
                return exe;
            }
        }
        let table = &*core::ptr::addr_of!(MODULE_TABLE);
        for m in &table.mods[..table.count.min(MODULE_TABLE_CAP)] {
            if m.base == 0 || pc < m.base {
                continue;
            }
            let sz = size_of_image(m.base) as u64;
            if sz != 0 && pc < m.base + sz {
                return m.base;
            }
        }
    }
    0
}

/// Static image lookup state used to preserve the native dynamic-table fallback rule.
#[cfg(target_arch = "x86_64")]
pub enum SehStaticLookup {
    /// No loaded image with an exception directory owns the PC; dynamic tables may be consulted.
    NoTable { image_base: Option<u64> },
    /// A loaded image exception table owns the PC range but has no covering row.
    TableMiss { image_base: u64 },
    /// The static table contains the covering runtime-function row.
    Found {
        base: u64,
        begin: u32,
        end: u32,
        unwind_info: u32,
    },
}

/// `RtlLookupFunctionEntry`'s static core: find a containing loaded image and binary-search its
/// `.pdata`, distinguishing a table miss from absence of any static table.
///
/// # Safety
/// Reads mapped PE headers + `.pdata` of the containing module.
#[cfg(target_arch = "x86_64")]
pub unsafe fn seh_lookup_static_function(pc: u64) -> SehStaticLookup {
    // SAFETY: mapped-image reads per the contract.
    unsafe {
        let base = seh_containing_image(pc);
        if base == 0 {
            return SehStaticLookup::NoTable { image_base: None };
        }
        let (pdata_rva, pdata_sz) = data_directory(base, DIRECTORY_ENTRY_EXCEPTION);
        if pdata_rva == 0 {
            return SehStaticLookup::NoTable {
                image_base: Some(base),
            };
        }
        if pdata_sz < 12 {
            return SehStaticLookup::TableMiss { image_base: base };
        }
        // Fault the .pdata pages in (they may not have been demand-filled yet).
        touch_range(base + pdata_rva as u64, pdata_sz as u64);
        let count = (pdata_sz / 12) as usize;
        let rva = (pc - base) as u32;
        // Binary search over the sorted RUNTIME_FUNCTION rows (12 bytes each: begin,end,unwind).
        let read_row = |i: usize| -> (u32, u32, u32) {
            let row = base + pdata_rva as u64 + (i as u64) * 12;
            (rd32_at(row), rd32_at(row + 4), rd32_at(row + 8))
        };
        let (mut lo, mut hi) = (0usize, count);
        let mut found: Option<(u32, u32, u32)> = None;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (b, e, u) = read_row(mid);
            if rva < b {
                hi = mid;
            } else if rva >= e {
                lo = mid + 1;
            } else {
                found = Some((b, e, u));
                break;
            }
        }
        match found {
            Some((begin, end, unwind_info)) => SehStaticLookup::Found {
                base,
                begin,
                end,
                unwind_info,
            },
            None => SehStaticLookup::TableMiss { image_base: base },
        }
    }
}

/// Compatibility projection for existing static-only callers.
#[cfg(target_arch = "x86_64")]
pub unsafe fn seh_lookup_function(pc: u64) -> Option<(u64, u32, u32, u32)> {
    match unsafe { seh_lookup_static_function(pc) } {
        SehStaticLookup::Found {
            base,
            begin,
            end,
            unwind_info,
        } => Some((base, begin, end, unwind_info)),
        SehStaticLookup::NoTable { .. } | SehStaticLookup::TableMiss { .. } => None,
    }
}

/// Lowercase an import descriptor's DLL name into `out` and STRIP a trailing `.dll`; returns the
/// base-name length written. (e.g. `"CSRSRV.dll"` → `b"csrsrv"`, len 6.)
///
/// # Safety
/// `base + name_rva` must be a mapped NUL-terminated ASCII string.
#[cfg(target_arch = "x86_64")]
unsafe fn import_desc_basename(base: u64, name_rva: u32, out: &mut [u8; 32]) -> usize {
    let mut raw = [0u8; 64];
    // SAFETY: caller contract.
    let n = unsafe { read_cstr(base, name_rva, &mut raw) };
    let mut n = n.min(32 + 4); // room to strip ".dll"
                               // Strip a trailing ".dll" (case-insensitive).
    if n >= 4 {
        let tail = &raw[n - 4..n];
        if tail[0] == b'.'
            && tail[1].to_ascii_lowercase() == b'd'
            && tail[2].to_ascii_lowercase() == b'l'
            && tail[3].to_ascii_lowercase() == b'l'
        {
            n -= 4;
        }
    }
    let n = n.min(32);
    for i in 0..n {
        out[i] = raw[i].to_ascii_lowercase();
    }
    n
}

/// Snap ONE import descriptor's thunks against `dep_base`'s export directory (direct in-process IAT
/// writes). Returns `(resolved, missing)`. `image_base` is the module whose IAT we patch;
/// `ilt_rva`/`iat_rva` are its descriptor's OriginalFirstThunk/FirstThunk.
///
/// # Safety
/// All three bases must be mapped PE images; `image_base`'s IAT pages must be writable.
#[cfg(target_arch = "x86_64")]
unsafe fn snap_descriptor_against(
    image_base: u64,
    ilt_rva: u32,
    iat_rva: u32,
    dep_base: u64,
    table: *mut ModuleTable,
    out: &mut SnapResult,
) {
    // SAFETY: caller contract — mapped images, writable IAT.
    unsafe {
        let mut ilt = image_base + ilt_rva as u64;
        let mut iat = image_base + iat_rva as u64;
        loop {
            let thunk = core::ptr::read_unaligned(ilt as *const u64);
            if thunk == 0 {
                break;
            }
            // Resolve each thunk to its FINAL absolute address, following forwarders (e.g.
            // kernel32!GetLastError → "ntdll.RtlGetLastWin32Error"). A forwarder RVA left un-followed
            // would write the forwarder-STRING address into the IAT → an instruction-fetch fault into
            // the target's .rdata on the first call (the kernel32+0xa9954 map=8 wall).
            let addr = if thunk & (1u64 << 63) == 0 {
                // by name: IMAGE_IMPORT_BY_NAME RVA = thunk & 0x7fffffff; +2 skips the Hint.
                let ibn_rva = (thunk & 0x7fff_ffff) as u32;
                let mut namebuf = [0u8; 96];
                let nlen = read_cstr(image_base, ibn_rva + 2, &mut namebuf);
                resolve_export_addr(
                    dep_base,
                    false,
                    &namebuf[..nlen],
                    0,
                    table,
                    &mut out.status,
                    0,
                )
            } else {
                // by ordinal.
                let ord = (thunk & 0xffff) as u32;
                resolve_export_addr(dep_base, true, &[], ord, table, &mut out.status, 0)
            };
            if out.status != 0 {
                return;
            }
            if addr != 0 {
                core::ptr::write_unaligned(iat as *mut u64, addr);
                out.resolved += 1;
                if out.spot_iat_value == 0 {
                    out.spot_iat_value = addr;
                    out.spot_iat_rva = (iat - image_base) as u32;
                }
            } else {
                out.missing += 1;
            }
            ilt += 8;
            iat += 8;
        }
    }
}

/// Resolve an export **by ordinal** in the mapped PE at `base` → its target RVA (0 if absent).
///
/// # Safety
/// `base` must be a mapped PE image.
#[cfg(target_arch = "x86_64")]
unsafe fn export_rva_by_ordinal(base: u64, ordinal: u32) -> u32 {
    // SAFETY: reading the mapped export directory.
    unsafe {
        let (edir_rva, edir_sz) = data_directory(base, 0);
        if edir_rva == 0 {
            return 0;
        }
        // Force-fault the export dir region first (same per-VSpace lazy-fill fix as export_rva_by_name).
        touch_range(base + edir_rva as u64, edir_sz as u64);
        let ed = base + edir_rva as u64;
        let ordinal_base = rd32(ed, 0x10);
        let number_of_functions = rd32(ed, 0x14);
        let addr_of_functions = rd32(ed, 0x1c) as u64;
        if ordinal < ordinal_base {
            return 0;
        }
        let idx = ordinal - ordinal_base;
        if idx >= number_of_functions {
            return 0;
        }
        rd32(base, addr_of_functions + idx as u64 * 4)
    }
}

/// The export directory `(rva, size)` for the mapped PE at `base` — used to classify a resolved
/// export RVA as a FORWARDER (an RVA that falls INSIDE the export directory is not code/data in the
/// image; it is a `"TARGETDLL.func"` / `"TARGETDLL.#ordinal"` ASCII string to redirect to).
///
/// # Safety
/// `base` must be a mapped PE image.
#[cfg(target_arch = "x86_64")]
unsafe fn export_dir_range(base: u64) -> (u32, u32) {
    // SAFETY: reading the mapped PE headers per the contract.
    unsafe { data_directory(base, 0) } // IMAGE_DIRECTORY_ENTRY_EXPORT = 0
}

/// Is `rva` a FORWARDER for the module at `base`? (RVA inside the export directory range.)
///
/// # Safety
/// `base` must be a mapped PE image.
#[cfg(target_arch = "x86_64")]
unsafe fn is_forwarder(base: u64, rva: u32) -> bool {
    // SAFETY: reading the mapped PE headers per the contract.
    let (edir_rva, edir_sz) = unsafe { export_dir_range(base) };
    edir_sz != 0 && rva >= edir_rva && rva < edir_rva + edir_sz
}

/// Resolve an imported symbol (by name or by ordinal) in the module at `dep_base` to its FINAL
/// ABSOLUTE virtual address, **following forwarders** (`kernel32!GetLastError` → the forwarder string
/// `"ntdll.RtlGetLastWin32Error"` → the concrete `ntdll` export). This is the on-target equivalent of
/// `nt-ntdll::loader::resolve`'s forwarder chain, but over live mapped images + the `MODULE_TABLE`
/// (loading a forwarder-target DLL if not already present, exactly as `LdrpSnapThunk` does).
///
/// Returns the absolute address, or 0 if unresolvable (missing export / target DLL). `depth` guards a
/// pathological forwarder cycle (real chains are 1-2 hops).
///
/// # Safety
/// `dep_base` must be a mapped PE image; on-target (may load a forwarder-target DLL via syscalls).
#[cfg(target_arch = "x86_64")]
unsafe fn resolve_export_addr(
    dep_base: u64,
    by_ordinal: bool,
    name: &[u8],
    ordinal: u32,
    table: *mut ModuleTable,
    load_status: &mut u32,
    depth: u32,
) -> u64 {
    if depth > 8 {
        if *load_status == 0 {
            *load_status = 0xC000_0001; // STATUS_UNSUCCESSFUL
        }
        return 0; // forwarder-cycle / over-deep guard
    }
    // SAFETY: mapped-image export walk per the contract.
    unsafe {
        let rva = if by_ordinal {
            export_rva_by_ordinal(dep_base, ordinal)
        } else {
            export_rva_by_name(dep_base, name)
        };
        if rva == 0 {
            return 0;
        }
        if !is_forwarder(dep_base, rva) {
            // Concrete export — the common case.
            return dep_base + rva as u64;
        }
        // FORWARDER: the RVA points at an ASCII `"TARGETDLL.func"` / `"TARGETDLL.#ordinal"` string.
        // Split on the LAST '.' (api-set names can contain dots; ReactOS ones don't, but be exact).
        let mut fbuf = [0u8; 128];
        let flen = read_cstr(dep_base, rva, &mut fbuf);
        let fwd = &fbuf[..flen];
        let dot = match fwd.iter().rposition(|&c| c == b'.') {
            Some(d) => d,
            None => return 0, // malformed forwarder
        };
        let (mod_part, sym_part) = (&fwd[..dot], &fwd[dot + 1..]);

        // Lowercase the target module base name (strip a trailing ".dll" if present — forwarders
        // usually omit it, e.g. "ntdll", but be defensive).
        let mut tmod = [0u8; 32];
        let mut tlen = 0usize;
        for &b in mod_part.iter().take(32) {
            tmod[tlen] = b.to_ascii_lowercase();
            tlen += 1;
        }
        if tlen >= 4 {
            let tail = &tmod[tlen - 4..tlen];
            if tail == b".dll" {
                tlen -= 4;
            }
        }
        let tmod_lc = &tmod[..tlen];

        // Find the forwarder-target module (load it if not already mapped — as LdrpSnapThunk does).
        let mut tbase = (&*table).find(tmod_lc);
        if tbase == 0 {
            let mut sink = SnapResult::default();
            tbase = load_and_snap_dependency(
                tmod_lc,
                (&*table).find(b"ntdll"),
                table,
                &mut sink,
                depth + 1,
            );
            if sink.status != 0 {
                if *load_status == 0 {
                    *load_status = sink.status;
                }
                return 0;
            }
        }
        if tbase == 0 {
            return 0;
        }

        // Resolve the target symbol IN the target module — by ordinal (`#123`) or by name — RECURSING
        // (the target may itself be a forwarder).
        if !sym_part.is_empty() && sym_part[0] == b'#' {
            let mut ord = 0u32;
            for &c in &sym_part[1..] {
                if c.is_ascii_digit() {
                    ord = ord * 10 + (c - b'0') as u32;
                }
            }
            resolve_export_addr(tbase, true, &[], ord, table, load_status, depth + 1)
        } else {
            resolve_export_addr(tbase, false, sym_part, 0, table, load_status, depth + 1)
        }
    }
}

/// Load a dependent DLL BY NAME (the executive resolves it against the real `\reactos\system32` FS +
/// its DLL registry, assigning the module its fixed base — csrsrv → 0x8000_0000). Issues
/// `NtOpenFile → NtCreateSection(SEC_IMAGE) → NtMapViewOfSection`; returns the mapped base (0 on
/// failure). `name_lc` is the lowercased base name (no `.dll`); we build a `<name>.dll` path leaf.
///
/// # Safety
/// On-target hosted process; issues real syscalls the executive services.
#[cfg(target_arch = "x86_64")]
unsafe fn load_dependent_dll(name_lc: &[u8]) -> u64 {
    // Build a NUL-terminated UTF-16 leaf `<name>.dll` for the OBJECT_ATTRIBUTES.ObjectName. The
    // executive's NtOpenFile matches the DLL by a substring of the object name (reg.resolve_name /
    // demand_load_dll), so a bare leaf suffices.
    let mut wname = [0u16; 40];
    let mut wn = 0usize;
    for &b in name_lc.iter().take(32) {
        wname[wn] = b as u16;
        wn += 1;
    }
    for &b in b".dll" {
        wname[wn] = b as u16;
        wn += 1;
    }
    // UNICODE_STRING { Length, MaximumLength, Buffer } (x64: u16,u16,pad,ptr).
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        _pad: u32,
        buffer: u64,
    }
    let us = UnicodeString {
        length: (wn * 2) as u16,
        maximum_length: (wn * 2) as u16,
        _pad: 0,
        buffer: wname.as_ptr() as u64,
    };

    // NtOpenFile(image) → NtCreateSection(SEC_IMAGE): reuse rtlp_map_file (opens by name, closes the
    // file, leaves the SEC_IMAGE handle in `section`).
    let mut section: u64 = 0;
    // SAFETY: on-target; us is a valid UNICODE_STRING*, section a writable stack local.
    let st = unsafe {
        rtlp_map_file(
            core::ptr::addr_of!(us) as *const u8,
            0x40, // OBJ_CASE_INSENSITIVE
            core::ptr::addr_of_mut!(section),
        )
    };
    if (st as i32) < 0 || section == 0 {
        return 0;
    }

    // NtMapViewOfSection(Section, NtCurrentProcess(), &BaseAddress, ZeroBits=0, CommitSize=0,
    //                    &SectionOffset=NULL, &ViewSize, InheritDisposition=1, AllocationType=0,
    //                    Protect=PAGE_EXECUTE_READ). The executive writes the DLL's fixed registry
    // base into *BaseAddress and its extent into *ViewSize. *BaseAddress MUST be a stack local (the
    // executive writes it through its stack mirror).
    let mut base_address: u64 = 0;
    let mut view_size: u64 = 0;
    // SAFETY: on-target syscall; stack-local out-params.
    let st = unsafe {
        syscall_map_view(
            section,
            NT_CURRENT_PROCESS,
            core::ptr::addr_of_mut!(base_address) as u64,
            0,
            0,
            0,
            core::ptr::addr_of_mut!(view_size) as u64,
            1,    // ViewShare
            0,    // AllocationType
            0x20, // PAGE_EXECUTE_READ
        )
    };
    if (st as i32) < 0 {
        return 0;
    }
    base_address
}

/// Return an existing dependency or complete one retained failed import transaction in place.
/// A failed mapping remains registered because the executive cannot safely unmap it yet; retrying
/// that exact base avoids duplicate mappings and preserves the loader entry's owned state.
#[cfg(target_arch = "x86_64")]
unsafe fn load_and_snap_dependency(
    name_lc: &[u8],
    ntdll_base: u64,
    table: *mut ModuleTable,
    out: &mut SnapResult,
    depth: u32,
) -> u64 {
    let existing = unsafe { (&*table).find(name_lc) };
    if existing != 0 {
        return existing;
    }
    let retained = unsafe { (&*table).find_any(name_lc) };
    let base = if retained != 0 {
        retained
    } else {
        let loaded = unsafe { load_dependent_dll(name_lc) };
        if loaded == 0 {
            return 0;
        }
        unsafe { (&mut *table).insert(name_lc, loaded) };
        loaded
    };
    let status = unsafe { add_runtime_ldr_module(base, name_lc) };
    if status != 0 {
        if out.status == 0 {
            out.status = status;
        }
        return 0;
    }
    unsafe { snap_module(base, ntdll_base, table, out, depth) };
    if out.status == 0 { base } else { 0 }
}

/// `NtMapViewOfSection` — a dedicated 10-arg caller (its arity exceeds syscall8's 8). Uses the same
/// register/stack ABI: a1..a4 → R10/RDX/R8/R9, a5..a10 → `[rsp+0x28..0x50]`.
///
/// # Safety
/// On-target hosted-process syscall; out-param pointers must be valid.
#[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn syscall_map_view(
    section: u64,
    process: u64,
    base_address: u64,
    zero_bits: u64,
    commit_size: u64,
    section_offset: u64,
    view_size: u64,
    inherit: u64,
    alloc_type: u64,
    protect: u64,
) -> u64 {
    let status: u64;
    // SAFETY: a hosted-process syscall trap serviced by the executive.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x58",
            "mov qword ptr [rsp+0x28], {a5}",
            "mov qword ptr [rsp+0x30], {a6}",
            "mov qword ptr [rsp+0x38], {a7}",
            "mov qword ptr [rsp+0x40], {a8}",
            "mov qword ptr [rsp+0x48], {a9}",
            "mov qword ptr [rsp+0x50], {a10}",
            "mov r10, {a1}",
            "mov rdx, {a2}",
            "mov r8,  {a3}",
            "mov r9,  {a4}",
            "mov eax, {ssn:e}",
            "syscall",
            "add rsp, 0x58",
            ssn = in(reg) SSN_NT_MAP_VIEW_OF_SECTION,
            a1 = in(reg) section, a2 = in(reg) process, a3 = in(reg) base_address, a4 = in(reg) zero_bits,
            a5 = in(reg) commit_size, a6 = in(reg) section_offset, a7 = in(reg) view_size,
            a8 = in(reg) inherit, a9 = in(reg) alloc_type, a10 = in(reg) protect,
            out("rax") status,
            out("rcx") _, out("r11") _, out("r10") _, out("r8") _, out("r9") _,
            clobber_abi("system"),
        );
    }
    status
}

/// `NtMapViewOfSection` over the NATIVE seL4-Call transport (10 args). MR0=SSN, MR1=rsp, MR2=a1,
/// MR3=a2, MR4=a3, MR5=a4 (IPC buffer), a5..a10 on the stack `[rsp+0x28..0x50]` (read by the
/// executive via its mirror) — identical stack layout to the trap path, so the executive's handler
/// (which reads a5+ from the stack) is unchanged.
///
/// # Safety
/// On-target hosted-process syscall.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn syscall_map_view(
    section: u64,
    process: u64,
    base_address: u64,
    zero_bits: u64,
    commit_size: u64,
    section_offset: u64,
    view_size: u64,
    inherit: u64,
    alloc_type: u64,
    protect: u64,
) -> u64 {
    // native_syscall8 handles a1..a4 in the message + a5..a8 on the stack; a9/a10 need two more
    // stack slots. We place ALL six tail args on the stack ourselves and issue the native Call with
    // a1..a4 in the message. Build the request array as native_syscall8 does but with the extra tail.
    // SAFETY: on-target native transport.
    unsafe {
        native_map_view(
            section,
            process,
            base_address,
            zero_bits,
            [
                commit_size,
                section_offset,
                view_size,
                inherit,
                alloc_type,
                protect,
            ],
        )
    }
}

/// The full Step-4.B in-process loader drive. Returns the snap result (for the boot-log proof).
///
/// 1. Create the process heap (installs it via [`crate::install_process_heap`]).
/// 2. Snap smss's ntdll imports against OUR export table (direct IAT writes).
///
/// After this returns, the trampoline chains to smss's real entry (`NtProcessStartup`) — now with a
/// correctly-snapped IAT, so smss runs under OUR ntdll.
///
/// # Safety
/// On-target only; `smss_base`/`ntdll_base` mapped PE images.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldrp_drive(smss_base: u64, ntdll_base: u64, startup_reserved: u64) -> SnapResult {
    // Record the EXE base for RtlLookupFunctionEntry (the EXE is NOT in MODULE_TABLE, which holds
    // only dependencies). The SEH unwinder must cover a fault PC in the EXE's own code too.
    // SAFETY: single-threaded loader; written once before any thread that reads it.
    unsafe {
        EXE_BASE = smss_base;
    }
    // (1) Process heap — install it so `alloc` works for any engine code that needs it, AND publish
    // its base into `Peb->ProcessHeap` (x64 PEB+0x30). Real ntdll's LdrpInitializeProcess sets
    // `Peb->ProcessHeap = RtlCreateHeap(...)`; kernel32's `GetProcessHeap()` returns exactly that
    // field. msvcrt's DllMain `_heap_init` calls `GetProcessHeap()` and, if NULL, returns FALSE →
    // its whole CRT process-attach bails BEFORE setting `_acmdln = strdup(GetCommandLineA())`, so
    // winlogon's later `__getmainargs → _setargv → strlen(_acmdln=NULL)` NULL-derefs. Publishing the
    // heap base here makes GetProcessHeap non-NULL → msvcrt's attach completes → `_acmdln` set.
    // SAFETY: on-target syscall + gs:[0x60] = PEB (byte-exact x64 layout).
    if let Some((heap, heap_base)) = unsafe { create_process_heap() } {
        crate::install_process_heap(heap);
        unsafe {
            let peb: u64;
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
            if peb != 0 {
                core::ptr::write_volatile((peb + 0x30) as *mut u64, heap_base); // Peb->ProcessHeap
            }
        }
    }
    unsafe {
        let peb: u64;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        crate::exports::ldr_publish_loader_lock(peb);
    }
    let _loader_lock = match unsafe { crate::exports::acquire_loader_lock() } {
        Ok(guard) => guard,
        Err(status) => unsafe {
            crate::exports::rtl_raise_status(status);
            core::hint::unreachable_unchecked()
        },
    };
    // (2) Snap the EXE's imports against our export table + any dependent DLLs (csrsrv for csrss).
    // smss imports only ntdll (dep-free); csrss also imports csrsrv.dll — which this loads + snaps.
    // SAFETY: on-target mapped-image walk + IAT write + dependent-DLL load syscalls.
    let out = unsafe { snap_all_imports(smss_base, ntdll_base) };
    if out.status != 0 {
        drop(_loader_lock);
        unsafe {
            crate::exports::rtl_raise_status(out.status);
            core::hint::unreachable_unchecked()
        }
    }
    // (2.5) BUILD `PEB->Ldr` (PEB+0x18) — the three circularly-linked LDR_DATA_TABLE_ENTRY lists,
    // one entry per loaded module (the EXE + ntdll + every cascaded/delay DLL now in MODULE_TABLE).
    // Real ntdll's LdrpInitializeProcess builds this BEFORE running init routines, and hosted code
    // (kernel32's GetModuleFileNameW / LdrGetDllHandle, WinDbg) walks it. Without it, `Peb->Ldr` is
    // NULL → GetModuleFileNameW(NULL)'s `[Peb->Ldr]+0x10` InLoadOrder walk derefs NULL+0x10 (the
    // kernel32+0xff13 wall). `image_base` (the EXE) is recorded as list entry 0.
    // SAFETY: single-threaded loader; MODULE_TABLE holds mapped images; the process heap is installed.
    let ldr_status =
        unsafe { build_peb_ldr(core::ptr::addr_of!(MODULE_TABLE), smss_base) };
    if ldr_status != 0 {
        drop(_loader_lock);
        unsafe {
            crate::exports::rtl_raise_status(ldr_status);
            core::hint::unreachable_unchecked()
        }
    }
    let tls_status = unsafe {
        initialize_process_static_tls(smss_base, core::ptr::addr_of!(MODULE_TABLE))
    };
    if tls_status != 0 {
        drop(_loader_lock);
        unsafe {
            crate::exports::rtl_raise_status(tls_status);
            core::hint::unreachable_unchecked()
        }
    }
    // (2.6) BATCH 42 — LIVE SEH self-test: validate the REAL RtlLookupFunctionEntry +
    // RtlVirtualUnwind against our own compiled `.pdata`/`.xdata` (proves the live table walk +
    // unwind-code interpretation on real hardware). Run ONCE (first hosted process). Prints one
    // `[seh-selftest]` line to serial; non-fatal (only reads + unwinds a synthetic frame).
    // SAFETY: MODULE_TABLE holds our mapped ntdll; the self-test only captures + unwinds.
    unsafe {
        if !SEH_SELFTEST_DONE {
            SEH_SELFTEST_DONE = true;
            crate::seh::run_selftest();
        }
    }
    // (3) Run DLL_PROCESS_ATTACH for every dependent DLL (the live LdrpRunInitializeRoutines seam).
    // kernel32's DllMain runs InitCommandLines() so GetCommandLineA is non-NULL — winlogon's msvcrt
    // CRT startup does strdup(GetCommandLineA()), which strlen(NULL)-faults without this.
    // SAFETY: single-threaded loader; MODULE_TABLE holds mapped, snapped DLL images.
    unsafe {
        let status = run_process_attach(
            core::ptr::addr_of_mut!(MODULE_TABLE),
            startup_reserved,
        );
        if status != 0 {
            drop(_loader_lock);
            crate::exports::rtl_raise_status(status);
            core::hint::unreachable_unchecked();
        }
    }
    out
}

/// Snap `image_base`'s FULL import table (all descriptors) against OUR ntdll + any dependent DLLs,
/// recursively — the real `LdrpWalkImportDescriptor`. For each descriptor:
///   * `ntdll` → resolve against `ntdll_base` (OUR export table, already mapped).
///   * any OTHER DLL → LOAD it (NtOpenFile → NtCreateSection(SEC_IMAGE) → NtMapViewOfSection; the
///     executive assigns its fixed base), recursively snap ITS imports, then snap this descriptor
///     against the loaded DLL's exports.
/// A `ModuleTable` de-dupes loads (name → base) so a diamond / repeat dependency maps once + recursion
/// terminates. Returns the aggregate [`SnapResult`] (for the boot-log proof).
///
/// # Safety
/// On-target; `image_base`/`ntdll_base` are mapped PE images in this VSpace.
#[cfg(target_arch = "x86_64")]
pub unsafe fn snap_all_imports(image_base: u64, ntdll_base: u64) -> SnapResult {
    let mut out = SnapResult::default();
    // SAFETY: single-threaded loader context — MODULE_TABLE is touched only on the main thread while
    // LdrpInitialize runs (no other thread exists yet). The recursive helper honours the contract.
    unsafe {
        let table = core::ptr::addr_of_mut!(MODULE_TABLE);
        (&mut *table).insert(b"ntdll", ntdll_base);
        (&mut *table).set_imports_ready(ntdll_base);
        snap_module(image_base, ntdll_base, table, &mut out, 0);
    }
    out
}

/// The recursive per-module snap (see [`snap_all_imports`]). `depth` guards against a pathological
/// import cycle (real import graphs are acyclic module-wise; the guard is belt-and-braces).
///
/// # Safety
/// On-target; `image_base`/`ntdll_base` mapped PE images.
#[cfg(target_arch = "x86_64")]
unsafe fn snap_module(
    image_base: u64,
    ntdll_base: u64,
    table: *mut ModuleTable,
    out: &mut SnapResult,
    depth: u32,
) {
    if out.status != 0 {
        unsafe { (&mut *table).set_imports_failed(image_base) };
        return;
    }
    if depth > 8 {
        if out.status == 0 {
            out.status = 0xC000_0001; // STATUS_UNSUCCESSFUL
        }
        unsafe { (&mut *table).set_imports_failed(image_base) };
        return; // cycle / over-deep guard — csrss's graph is 2 deep at most
    }
    unsafe { (&mut *table).begin_imports(image_base) };
    let mut imports_ready = ModuleImportsReadyGuard {
        table,
        base: image_base,
        committed: false,
    };
    let mut activation_frame = [0u64; 7];
    let _activation_context =
        match unsafe { ModuleActivationContextGuard::enter(image_base, &mut activation_frame) } {
            Ok(guard) => guard,
            Err(status) => {
                if out.status == 0 {
                    out.status = status;
                }
                return;
            }
        };
    // SAFETY: reading the mapped import directory + writing the mapped RW IAT per the contract.
    unsafe {
        let (idir_rva, _sz) = data_directory(image_base, 1); // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
        if idir_rva != 0 {
            let mut desc = image_base + idir_rva as u64;
            loop {
                let oft = rd32(desc, 0); // OriginalFirstThunk (ILT) RVA
                let name_rva = rd32(desc, 12); // Name RVA
                let ft = rd32(desc, 16); // FirstThunk (IAT) RVA
                if name_rva == 0 && ft == 0 {
                    break; // terminator
                }
                let ilt_rva = if oft != 0 { oft } else { ft };

                // Resolve this dependency's base: ntdll / an already-loaded module / load it now.
                let mut base = [0u8; 32];
                let bn = import_desc_basename(image_base, name_rva, &mut base);
                let dep_name = &base[..bn];
                let mut dep_base = (&*table).find(dep_name);
                if dep_base == 0 {
                    dep_base = load_and_snap_dependency(
                        dep_name,
                        ntdll_base,
                        table,
                        out,
                        depth + 1,
                    );
                    if out.status != 0 {
                        return;
                    }
                }
                if dep_base != 0 {
                    snap_descriptor_against(image_base, ilt_rva, ft, dep_base, table, out);
                    if out.status != 0 {
                        return;
                    }
                } else {
                    // Could not resolve the dependency — count its thunks as missing (honest, not faked).
                    let mut ilt = image_base + ilt_rva as u64;
                    while core::ptr::read_unaligned(ilt as *const u64) != 0 {
                        out.missing += 1;
                        ilt += 8;
                    }
                }
                desc += 20;
            }
        }
        if out.status != 0 {
            return;
        }
        // BATCH 14 — also EAGERLY bind DELAY imports (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13). A VC++
        // delay-load leaves the delay-IAT pointing at `__delayLoadHelper2`, which at first call does
        // `LoadLibrary(szDll)` in real kernel32; in our environment that path fails BEFORE reaching our
        // ntdll `LdrLoadDll`, so the helper raises `0xC06D007E` (ERROR_MOD_NOT_FOUND). Pre-binding the
        // delay IAT here (map the DLL + snap the delay INT→IAT like a normal import) means the helper is
        // never invoked — the delay-imported functions are already resolved. This is the root fix for
        // winlogon parking at `RtlRaiseException` on kernel32_vista's delay-load of ntdll_vista.dll.
        // `ImgDelayDescr` (x64, grAttrs&1 => RVA-based): grAttrs@0x00, rvaDLLName@0x04, rvaHmod@0x08,
        // rvaIAT@0x0C, rvaINT@0x10, rvaBoundIAT@0x14, rvaUnloadIAT@0x18, dwTimeStamp@0x1C (32 bytes).
        let (ddir_rva, _dsz) = data_directory(image_base, 13);
        if ddir_rva != 0 {
            let mut ddesc = image_base + ddir_rva as u64;
            loop {
                let name_rva = rd32(ddesc, 4); // rvaDLLName
                let iat_rva = rd32(ddesc, 12); // rvaIAT
                let int_rva = rd32(ddesc, 16); // rvaINT
                if name_rva == 0 && iat_rva == 0 {
                    break; // terminator
                }
                if depth <= 8 && int_rva != 0 && iat_rva != 0 {
                    let mut base = [0u8; 32];
                    let bn = import_desc_basename(image_base, name_rva, &mut base);
                    let dep_name = &base[..bn];
                    let mut dep_base = (&*table).find(dep_name);
                    if dep_base == 0 {
                        dep_base = load_and_snap_dependency(
                            dep_name,
                            ntdll_base,
                            table,
                            out,
                            depth + 1,
                        );
                        if out.status != 0 {
                            return;
                        }
                    }
                    if dep_base != 0 {
                        // Snap the delay INT (int_rva) → the delay IAT (iat_rva), exactly like a normal
                        // import descriptor. The delay-load helper is now bypassed for this DLL.
                        snap_descriptor_against(image_base, int_rva, iat_rva, dep_base, table, out);
                        if out.status != 0 {
                            return;
                        }
                    }
                }
                ddesc += 32; // sizeof(ImgDelayDescr)
            }
        }
        if out.status == 0 {
            imports_ready.commit();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// BATCH 15 — build + maintain `PEB->Ldr` (the three LDR_DATA_TABLE_ENTRY module lists).
//
// Real ntdll's LdrpInitializeProcess allocates a PEB_LDR_DATA + one LDR_DATA_TABLE_ENTRY per loaded
// module and threads them into three circular doubly-linked lists (InLoadOrder / InMemoryOrder /
// InInitializationOrder), then sets `Peb->Ldr` (PEB+0x18). Hosted code walks these: kernel32's
// GetModuleFileNameW(NULL) follows `Peb->Ldr->InLoadOrderModuleList` to find the entry whose DllBase
// matches; WinDbg's `!peb` reads them; LdrGetDllHandle walks them. Without them `Peb->Ldr` is NULL
// and the walk derefs NULL+0x10 (the kernel32+0xff13 wall).
//
// We build them IN-PROCESS from MODULE_TABLE (+ the EXE base), over a process-lifetime page region
// (bump-allocated so the entry VAs are persistent — a runtime LdrLoadDll appends another entry and
// re-threads). The circular link math is `nt_ntdll::loader::peb::circular_links` (the SAME
// host-tested primitive the model `build_ldr` uses) — link math authored + tested once.
//
// x64 LDR_DATA_TABLE_ENTRY field offsets (nt-ntdll-layout static-asserts):
//   InLoadOrderLinks@0x00, InMemoryOrderLinks@0x10, InInitializationOrderLinks@0x20,
//   DllBase@0x30, EntryPoint@0x38, SizeOfImage@0x40, FullDllName@0x48 (UNICODE_STRING),
//   BaseDllName@0x58, Flags@0x68, LoadCount@0x6C, TlsIndex@0x6E.
// PEB_LDR_DATA: Length@0x00, Initialized@0x04, SsHandle@0x08, InLoadOrderModuleList@0x10,
//   InMemoryOrderModuleList@0x20, InInitializationOrderModuleList@0x30.
// UNICODE_STRING: Length@0x00(u16), MaximumLength@0x02(u16), Buffer@0x08(ptr).
// ---------------------------------------------------------------------------------------------

/// Size of one `LDR_DATA_TABLE_ENTRY`, rounded up to 16 bytes. The native tail includes
/// `EntryPointActivationContext@0x88` and `PatchInformation@0x90`.
#[cfg(target_arch = "x86_64")]
const LDR_ENTRY_SIZE: u64 =
    (core::mem::size_of::<nt_ntdll_layout::LdrDataTableEntry>() as u64 + 15) & !15;

#[cfg(target_arch = "x86_64")]
struct ModuleActivationContextGuard<'a> {
    frame: *mut c_void,
    _storage: PhantomData<&'a mut [u64; 7]>,
}

#[cfg(target_arch = "x86_64")]
impl<'a> ModuleActivationContextGuard<'a> {
    unsafe fn enter(base: u64, storage: &'a mut [u64; 7]) -> Result<Self, u32> {
        let context = unsafe { crate::exports::ldr_entry_activation_context_for_base(base) };
        if context.is_null() {
            return Ok(Self {
                frame: core::ptr::null_mut(),
                _storage: PhantomData,
            });
        }
        storage.fill(0);
        storage[0] = core::mem::size_of_val(storage) as u64;
        storage[1] = nt_ntdll::rtl::activation::CALLER_FRAME_FORMAT_WHISTLER as u64;
        let frame = unsafe {
            crate::exports::rtl_activate_activation_context_unsafe_fast(
                storage.as_mut_ptr().cast(),
                context,
            )
        };
        if frame.is_null() {
            Err(STATUS_NO_MEMORY as u32)
        } else {
            Ok(Self {
                frame: storage.as_mut_ptr().cast(),
                _storage: PhantomData,
            })
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for ModuleActivationContextGuard<'_> {
    fn drop(&mut self) {
        if !self.frame.is_null() {
            let _ = unsafe {
                crate::exports::rtl_deactivate_activation_context_unsafe_fast(self.frame)
            };
        }
    }
}

#[cfg(target_arch = "x86_64")]
struct ModuleImportsReadyGuard {
    table: *mut ModuleTable,
    base: u64,
    committed: bool,
}

#[cfg(target_arch = "x86_64")]
impl ModuleImportsReadyGuard {
    fn commit(&mut self) {
        self.committed = true;
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for ModuleImportsReadyGuard {
    fn drop(&mut self) {
        unsafe {
            if self.committed {
                (&mut *self.table).set_imports_ready(self.base);
            } else {
                (&mut *self.table).set_imports_failed(self.base);
            }
        };
    }
}

/// Size of the `PEB_LDR_DATA` head (round to 0x60).
#[cfg(target_arch = "x86_64")]
const PEB_LDR_DATA_SIZE: u64 = 0x60;
/// The process-lifetime region reserved for the Ldr head + entries + name buffers. Ample for the
/// full winlogon module set (~300 loader entries observed) at ~0x80 struct + name bytes each.
#[cfg(target_arch = "x86_64")]
const LDR_REGION_SIZE: usize = 0x8_0000; // 512 KiB

/// The maximum modules we thread into PEB->Ldr in one process.
#[cfg(target_arch = "x86_64")]
const LDR_MAX_ENTRIES: usize = 512;

/// Process-lifetime state for the built PEB->Ldr: the bump region, the head VA, and the persistent
/// per-module entry VAs (so a runtime LdrLoadDll can append + re-thread). Single-threaded loader
/// context (LdrpInitialize + subsequent LdrLoadDll all run before/serialized on the main thread).
#[cfg(target_arch = "x86_64")]
struct LdrState {
    /// The bump-allocation cursor VA within the reserved region (0 = not yet initialized).
    cursor: u64,
    /// One-past-the-end of the reserved region.
    region_end: u64,
    /// The `PEB_LDR_DATA` head VA (0 = not yet built).
    ldr_va: u64,
    /// Per-module `LDR_DATA_TABLE_ENTRY` VAs, in load order.
    entry_vas: [u64; LDR_MAX_ENTRIES],
    /// Number of entries threaded.
    count: usize,
}

#[cfg(target_arch = "x86_64")]
static mut LDR_STATE: LdrState = LdrState {
    cursor: 0,
    region_end: 0,
    ldr_va: 0,
    entry_vas: [0u64; LDR_MAX_ENTRIES],
    count: 0,
};

/// Bump `n` bytes (16-aligned) from the Ldr region; returns the VA (0 on exhaustion).
///
/// # Safety
/// On-target; `LDR_STATE` region must be reserved (cursor != 0). Single-threaded loader.
#[cfg(target_arch = "x86_64")]
unsafe fn ldr_bump(n: u64) -> u64 {
    // SAFETY: single-threaded loader touches LDR_STATE only here + build_peb_ldr.
    unsafe {
        let st = &mut *core::ptr::addr_of_mut!(LDR_STATE);
        let aligned = (st.cursor + 15) & !15u64;
        if aligned + n > st.region_end {
            return 0; // exhausted — honest failure, never overrun the region
        }
        st.cursor = aligned + n;
        aligned
    }
}

/// The `SizeOfImage` (OptionalHeader+56) of a mapped PE at `base` (0 if unreadable).
///
/// # Safety
/// `base` must be a mapped PE image (DOS + NT headers readable).
#[cfg(target_arch = "x86_64")]
unsafe fn size_of_image(base: u64) -> u32 {
    // SAFETY: reading the mapped PE headers per the contract.
    unsafe {
        let e_lfanew = rd32(base, 0x3c) as u64;
        let opt = base + e_lfanew + 24; // OptionalHeader
        rd32_at(opt + 56) // SizeOfImage
    }
}

/// Materialize ONE `LDR_DATA_TABLE_ENTRY` at a freshly-bumped VA for the module `base` with base name
/// `name_lc` (lowercased, no `.dll`). Fills DllBase / EntryPoint / SizeOfImage / LoadCount / a
/// `FullDllName` resolved from the process image path or current System32 loader root, plus a
/// `BaseDllName` pointing at a persistent UTF-16 `<name>.dll`.
/// The `LIST_ENTRY` links are left zero here (threaded by [`thread_ldr_lists`]). Returns the entry VA
/// (0 on region exhaustion).
///
/// # Safety
/// On-target; `base` a mapped PE image; the Ldr region is reserved.
#[cfg(target_arch = "x86_64")]
unsafe fn build_ldr_entry(base: u64, name_lc: &[u8]) -> u64 {
    // SAFETY: bump-alloc + raw writes into the reserved process-lifetime region.
    unsafe {
        let entry = ldr_bump(LDR_ENTRY_SIZE);
        if entry == 0 {
            return 0;
        }
        // Zero the entry struct.
        for i in 0..(LDR_ENTRY_SIZE / 8) {
            core::ptr::write_unaligned((entry + i * 8) as *mut u64, 0);
        }
        // Build a UTF-16 "<name>.dll" base-name buffer in the region (persistent).
        let nchars = name_lc.len() + 4; // + ".dll"
        let name_bytes = (nchars * 2) as u64;
        let namebuf = ldr_bump(name_bytes + 2); // + NUL
        if namebuf == 0 {
            return 0;
        }
        let mut w = 0u64;
        for &c in name_lc {
            core::ptr::write_unaligned((namebuf + w) as *mut u16, c as u16);
            w += 2;
        }
        for &c in b".dll" {
            core::ptr::write_unaligned((namebuf + w) as *mut u16, c as u16);
            w += 2;
        }
        core::ptr::write_unaligned((namebuf + w) as *mut u16, 0); // NUL

        // The root image already has its exact path in ProcessParameters.ImagePathName. Every DLL
        // this loader currently maps is resolved by the executive from System32, so materialize that
        // resolved loader path rather than publishing the base-name leaf as FullDllName.
        let mut image_path_buffer = 0u64;
        let mut image_path_units = 0usize;
        if base == EXE_BASE {
            let peb: u64;
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
            if peb != 0 {
                let parameters = core::ptr::read_unaligned((peb + 0x20) as *const u64);
                if parameters != 0 {
                    let length = core::ptr::read_unaligned((parameters + 0x60) as *const u16);
                    let maximum =
                        core::ptr::read_unaligned((parameters + 0x62) as *const u16);
                    let buffer = core::ptr::read_unaligned((parameters + 0x68) as *const u64);
                    if length & 1 == 0
                        && length != 0
                        && length <= maximum
                        && length <= u16::MAX - 2
                        && buffer != 0
                    {
                        image_path_buffer = buffer;
                        image_path_units = length as usize / 2;
                    }
                }
            }
            if image_path_units == 0 {
                return 0;
            }
        }
        const SYSTEM32_PREFIX: &[u8] = b"\\SystemRoot\\System32\\";
        let full_units = if image_path_units != 0 {
            image_path_units
        } else {
            SYSTEM32_PREFIX.len() + nchars
        };
        let full_bytes = (full_units * 2) as u64;
        let fullbuf = ldr_bump(full_bytes + 2);
        if fullbuf == 0 {
            return 0;
        }
        if image_path_units != 0 {
            core::ptr::copy_nonoverlapping(
                image_path_buffer as *const u16,
                fullbuf as *mut u16,
                image_path_units,
            );
        } else {
            let mut offset = 0usize;
            for &unit in SYSTEM32_PREFIX.iter().chain(name_lc).chain(b".dll") {
                core::ptr::write_unaligned((fullbuf as *mut u16).add(offset), unit as u16);
                offset += 1;
            }
        }
        core::ptr::write_unaligned((fullbuf as *mut u16).add(full_units), 0);

        core::ptr::write_unaligned((entry + 0x30) as *mut u64, base); // DllBase
        let epr = entry_point_rva(base);
        let ep = if epr != 0 { base + epr as u64 } else { 0 };
        core::ptr::write_unaligned((entry + 0x38) as *mut u64, ep); // EntryPoint
        core::ptr::write_unaligned((entry + 0x40) as *mut u32, size_of_image(base)); // SizeOfImage

        // FullDllName @0x48, BaseDllName @0x58 — both UNICODE_STRING{Length,MaxLength,_,Buffer}.
        core::ptr::write_unaligned((entry + 0x48) as *mut u16, full_bytes as u16);
        core::ptr::write_unaligned((entry + 0x4A) as *mut u16, (full_bytes + 2) as u16);
        core::ptr::write_unaligned((entry + 0x50) as *mut u64, fullbuf);
        core::ptr::write_unaligned((entry + 0x58) as *mut u16, name_bytes as u16);
        core::ptr::write_unaligned((entry + 0x5A) as *mut u16, (name_bytes + 2) as u16);
        core::ptr::write_unaligned((entry + 0x60) as *mut u64, namebuf);
        let load_count = if base == EXE_BASE || name_lc.eq_ignore_ascii_case(b"ntdll") {
            nt_ntdll::loader::lifecycle::LOAD_COUNT_PINNED
        } else {
            1
        };
        core::ptr::write_unaligned((entry + 0x6C) as *mut u16, load_count);
        entry
    }
}

/// (Re)thread the three PEB->Ldr circular lists over the current `LDR_STATE.entry_vas[..count]`,
/// using the shared [`nt_ntdll::loader::peb::circular_links`] primitive, and (re)publish the head's
/// three list-head `LIST_ENTRY`s. Load / memory / init order all use insertion order here (a faithful
/// model — the real memory order is by base VA but the threading is identical + walkers key by
/// DllBase, not position).
///
/// # Safety
/// On-target; `LDR_STATE.ldr_va` + all `entry_vas[..count]` are in the reserved region.
#[cfg(target_arch = "x86_64")]
unsafe fn thread_ldr_lists() {
    use nt_ntdll::loader::peb::circular_links;
    // SAFETY: single-threaded loader; the region VAs are mapped + reserved.
    unsafe {
        let st = &*core::ptr::addr_of!(LDR_STATE);
        let ldr_va = st.ldr_va;
        let count = st.count.min(LDR_MAX_ENTRIES);
        // Each list threads through a DIFFERENT LIST_ENTRY offset within the entry + head.
        // (entry node offset, head list-head offset).
        let lists: [(u64, u64); 3] = [
            (0x00, 0x10), // InLoadOrder:  entry@0x00, head@0x10
            (0x10, 0x20), // InMemoryOrder:entry@0x10, head@0x20
            (0x20, 0x30), // InInitOrder:  entry@0x20, head@0x30
        ];
        for &(node_off, head_off) in &lists {
            let head_node_va = ldr_va + head_off;
            // Build the ordered list of this list's node VAs.
            let mut node_vas = [0u64; LDR_MAX_ENTRIES];
            for i in 0..count {
                node_vas[i] = st.entry_vas[i] + node_off;
            }
            let (head, members) = circular_links(head_node_va, &node_vas[..count]);
            // Head's list-head LIST_ENTRY.
            core::ptr::write_unaligned((head_node_va) as *mut u64, head.flink);
            core::ptr::write_unaligned((head_node_va + 8) as *mut u64, head.blink);
            // Each member's LIST_ENTRY.
            for (i, nl) in members.iter().enumerate() {
                let node = st.entry_vas[i] + node_off;
                core::ptr::write_unaligned(node as *mut u64, nl.flink);
                core::ptr::write_unaligned((node + 8) as *mut u64, nl.blink);
            }
        }
    }
}

/// Build `PEB->Ldr` from the current module set (`table` = MODULE_TABLE) plus the EXE at
/// `exe_base` (which is NOT in MODULE_TABLE — MODULE_TABLE holds only dependencies). Reserves a
/// process-lifetime region, materializes the head + one entry per module (EXE first, so a
/// GetModuleFileNameW(NULL) InLoadOrder walk returns the EXE), threads the three lists, and sets
/// `Peb->Ldr` (PEB+0x18).
///
/// Order: the EXE is list entry 0 (real ntdll puts the image first in load order). Then ntdll, then
/// the remaining dependencies in MODULE_TABLE insertion order (a faithful model of load order).
///
/// # Safety
/// On-target; `exe_base` + every `table` base are mapped PE images; the process heap is installed;
/// `gs:[0x60]` = PEB (byte-exact x64 layout).
#[cfg(target_arch = "x86_64")]
pub unsafe fn build_peb_ldr(table: *const ModuleTable, exe_base: u64) -> u32 {
    // SAFETY: on-target; reserve the region + raw writes into it + the gs-relative PEB write.
    unsafe {
        // Reserve the process-lifetime region for the head + entries + name buffers.
        let region = nt_allocate_virtual_memory(LDR_REGION_SIZE);
        if region == 0 {
            return STATUS_NO_MEMORY as u32;
        }
        {
            let st = &mut *core::ptr::addr_of_mut!(LDR_STATE);
            st.cursor = region;
            st.region_end = region + LDR_REGION_SIZE as u64;
            st.count = 0;
        }
        // Head first.
        let ldr_va = ldr_bump(PEB_LDR_DATA_SIZE);
        if ldr_va == 0 {
            return STATUS_NO_MEMORY as u32;
        }
        // Zero + fill the fixed head fields.
        for i in 0..(PEB_LDR_DATA_SIZE / 8) {
            core::ptr::write_unaligned((ldr_va + i * 8) as *mut u64, 0);
        }
        core::ptr::write_unaligned((ldr_va) as *mut u32, PEB_LDR_DATA_SIZE as u32); // Length
        core::ptr::write_unaligned((ldr_va + 4) as *mut u32, 1u32); // Initialized = TRUE
        {
            let st = &mut *core::ptr::addr_of_mut!(LDR_STATE);
            st.ldr_va = ldr_va;
        }

        // Entry 0 = the EXE (its base name from its own PE export dir isn't reliable; derive a leaf
        // from a fixed "image" tag — GetModuleFileNameW(NULL) matches by DllBase, not by name).
        if add_ldr_module(exe_base, b"image") == 0 {
            return STATUS_NO_MEMORY as u32;
        }

        // Then every module in MODULE_TABLE (ntdll + all deps), skipping any whose base == exe_base.
        let table_count = (&*table).count.min(MODULE_TABLE_CAP);
        for m in &(&*table).mods[..table_count] {
            if m.base >= 0x1_0000 && m.base != exe_base {
                if add_ldr_module(m.base, &m.name[..m.nlen as usize]) == 0 {
                    return STATUS_NO_MEMORY as u32;
                }
            }
        }

        // Thread the three lists over all recorded entries.
        thread_ldr_lists();

        // Publish `Peb->Ldr` (PEB+0x18).
        let peb: u64;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb != 0 {
            core::ptr::write_volatile((peb + 0x18) as *mut u64, ldr_va);
        }

        // Static imports were snapped before the Ldr region existed. Materialize their inherited
        // activation-context ownership now, before any TLS callback or DllMain can run.
        {
            let mut entries = [0u64; LDR_MAX_ENTRIES];
            let count = {
                let state = &*core::ptr::addr_of!(LDR_STATE);
                let count = state.count.min(LDR_MAX_ENTRIES);
                entries[..count].copy_from_slice(&state.entry_vas[..count]);
                count
            };
            for &entry in &entries[..count] {
                let status = crate::exports::ldr_prepare_entry_activation_context(entry);
                if status != 0 {
                    return status;
                }
            }
            if count != 0 {
                let status =
                    crate::exports::ldr_initialize_process_activation_context(entries[0]);
                if status != 0 {
                    return status;
                }
            }
        }

        {
            // Boot-log proof: "PebLdr va=0x.. n=N".
            let st = &*core::ptr::addr_of!(LDR_STATE);
            let mut mb = [0u8; 64];
            let mut mn = 0usize;
            for &c in b"PebLdr va=0x" {
                if mn < 64 {
                    mb[mn] = c;
                    mn += 1;
                }
            }
            mn = crate::write_u64_hex(&mut mb, mn, ldr_va);
            for &c in b" n=" {
                if mn < 64 {
                    mb[mn] = c;
                    mn += 1;
                }
            }
            mn = crate::write_u32_dec(&mut mb, mn, st.count as u32);
            crate::dbg_print_bytes(mb.as_ptr(), mn);
        }
        0
    }
}

/// Record one module in `LDR_STATE` (materialize its entry; do NOT thread yet). De-dupes by base.
///
/// # Safety
/// On-target; `base` a mapped PE image; the Ldr region is reserved.
#[cfg(target_arch = "x86_64")]
unsafe fn ldr_entry_for_base(base: u64) -> u64 {
    let state = unsafe { &*core::ptr::addr_of!(LDR_STATE) };
    for &entry in &state.entry_vas[..state.count.min(LDR_MAX_ENTRIES)] {
        if unsafe { core::ptr::read_unaligned((entry + 0x30) as *const u64) } == base {
            return entry;
        }
    }
    0
}

#[cfg(target_arch = "x86_64")]
unsafe fn add_ldr_module(base: u64, name_lc: &[u8]) -> u64 {
    // SAFETY: single-threaded loader; region reserved.
    unsafe {
        let existing = ldr_entry_for_base(base);
        if existing != 0 {
            return existing;
        }
        let count = (&*core::ptr::addr_of!(LDR_STATE)).count;
        if count >= LDR_MAX_ENTRIES {
            return 0;
        }
        let entry = build_ldr_entry(base, name_lc);
        if entry == 0 {
            return 0;
        }
        let state = &mut *core::ptr::addr_of_mut!(LDR_STATE);
        state.entry_vas[count] = entry;
        state.count = count + 1;
        entry
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn add_runtime_ldr_module(base: u64, name_lc: &[u8]) -> u32 {
    if unsafe { (&*core::ptr::addr_of!(LDR_STATE)).ldr_va } == 0 {
        return 0;
    }
    unsafe { (&mut *core::ptr::addr_of_mut!(MODULE_TABLE)).begin_imports(base) };
    let existing = unsafe { ldr_entry_for_base(base) };
    let entry = if existing != 0 {
        existing
    } else {
        unsafe { add_ldr_module(base, name_lc) }
    };
    if entry == 0 {
        unsafe { (&mut *core::ptr::addr_of_mut!(MODULE_TABLE)).set_imports_failed(base) };
        return STATUS_NO_MEMORY as u32;
    }
    let status = unsafe {
        if existing == 0 {
            thread_ldr_lists();
        }
        crate::exports::ldr_prepare_entry_activation_context(entry)
    };
    if status != 0 {
        unsafe { (&mut *core::ptr::addr_of_mut!(MODULE_TABLE)).set_imports_failed(base) };
    }
    status
}

#[cfg(target_arch = "x86_64")]
unsafe fn set_ldr_process_attached(base: u64, attached: bool) {
    const LDRP_IMAGE_DLL: u32 = 0x0000_0004;
    const LDRP_ENTRY_PROCESSED: u32 = 0x0000_4000;
    const LDRP_PROCESS_ATTACH_CALLED: u32 = 0x0008_0000;
    unsafe {
        let state = &*core::ptr::addr_of!(LDR_STATE);
        for &entry in &state.entry_vas[..state.count.min(LDR_MAX_ENTRIES)] {
            if core::ptr::read_unaligned((entry + 0x30) as *const u64) != base {
                continue;
            }
            let flags = (entry + 0x68) as *mut u32;
            let mut value = core::ptr::read_unaligned(flags);
            value |= LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED;
            if attached {
                value |= LDRP_PROCESS_ATTACH_CALLED;
            } else {
                value &= !LDRP_PROCESS_ATTACH_CALLED;
            }
            core::ptr::write_unaligned(flags, value);
            break;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// BATCH 2 — the runtime loader Ldr* drivers (LdrLoadDll / LdrGetDllHandle / LdrGetProcedureAddress).
//
// csrsrv's `CsrLoadServerDll` calls `LdrLoadDll` to bring up its ServerDlls (basesrv/winsrv), then
// `LdrGetProcedureAddress` to find each ServerDll's entry (`ServerDllInitialization`). These reuse
// the same in-process machinery as the static-import snap: load-by-name + snap-imports + the export
// walker, over the process-wide MODULE_TABLE.
// ---------------------------------------------------------------------------------------------

/// Read a `UNICODE_STRING`'s wide `Buffer` into a lowercased ASCII base name (`.dll` stripped) — the
/// key MODULE_TABLE uses. Returns the byte length written (0 on a null/empty string).
///
/// # Safety
/// `us` a valid `UNICODE_STRING*` (Length @0 u16, Buffer @8 ptr).
#[cfg(target_arch = "x86_64")]
unsafe fn unicode_basename_lc(us: *const c_void, out: &mut [u8; 32]) -> usize {
    if us.is_null() {
        return 0;
    }
    // SAFETY: us is a valid UNICODE_STRING per the contract.
    unsafe {
        let length = core::ptr::read_unaligned(us as *const u16) as usize; // Length (bytes)
        let buffer = core::ptr::read_unaligned((us as *const u8).add(8) as *const u64); // Buffer
        if buffer == 0 || length == 0 {
            return 0;
        }
        let nchars = length / 2;
        // Find the last path separator so we key by the leaf name.
        let mut start = 0usize;
        for i in 0..nchars {
            let c = core::ptr::read_unaligned((buffer as *const u16).add(i));
            if c == b'\\' as u16 || c == b'/' as u16 {
                start = i + 1;
            }
        }
        let mut n = 0usize;
        for i in start..nchars {
            let c = core::ptr::read_unaligned((buffer as *const u16).add(i)) as u32;
            if c > 0x7f {
                break;
            }
            if n < 32 {
                out[n] = (c as u8).to_ascii_lowercase();
                n += 1;
            }
        }
        // Strip a trailing ".dll".
        if n >= 4
            && out[n - 4] == b'.'
            && out[n - 3] == b'd'
            && out[n - 2] == b'l'
            && out[n - 1] == b'l'
        {
            n -= 4;
        }
        n
    }
}

/// `LdrLoadDll` in-process driver — load `dll_name` (map + recursively snap its imports), record it in
/// MODULE_TABLE, write its base to `*base_addr`. Returns STATUS_SUCCESS / STATUS_DLL_NOT_FOUND.
///
/// # Safety
/// On-target; `dll_name` a valid `UNICODE_STRING*`; `base_addr` writable.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldr_load_dll(dll_name: *const c_void, base_addr: *mut *mut c_void) -> u32 {
    let mut name = [0u8; 32];
    // SAFETY: dll_name a valid UNICODE_STRING per the contract.
    let n = unsafe { unicode_basename_lc(dll_name, &mut name) };
    if n == 0 {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    let dep = &name[..n];
    // SAFETY: single-threaded loader; MODULE_TABLE touched only here + snap.
    unsafe {
        let table_ptr = core::ptr::addr_of_mut!(MODULE_TABLE);
        // Already loaded? Return its base.
        let existing = (&*table_ptr).find(dep);
        let retained = (&*table_ptr).find_any(dep);
        let mut newly_loaded = existing == 0;
        let mut reference_added = false;
        let base = if existing != 0 {
            if !(&*table_ptr).imports_ready(existing) {
                return 0xC000_0135; // STATUS_DLL_NOT_FOUND while this mapping is still in progress
            }
            if (&*table_ptr).attach_failed(existing) {
                // The first caller never received a handle, so its initial count still owns this
                // retry and must not be incremented again before DllMain succeeds.
                newly_loaded = true;
            } else {
                let status = ldr_add_ref_dll(existing, false);
                if status != 0 {
                    return status;
                }
                reference_added = true;
            }
            existing
        } else {
            let loaded = if retained != 0 {
                retained
            } else {
                let loaded = load_dependent_dll(dep);
                if loaded == 0 {
                    return 0xC000_0135; // STATUS_DLL_NOT_FOUND
                }
                (&mut *table_ptr).insert(dep, loaded);
                loaded
            };
            {
                let status = add_runtime_ldr_module(loaded, dep);
                if status != 0 {
                    return status;
                }
                // Snap the freshly-loaded DLL's own imports (ntdll + any deps) so it can run.
                let ntdll_base = (&*table_ptr).find(b"ntdll");
                let mut out = SnapResult::default();
                snap_module(loaded, ntdll_base, table_ptr, &mut out, 0);
                if out.status != 0 {
                    return out.status;
                }
            }
            // BATCH 15 — link the runtime-loaded module (+ any deps it pulled in) into PEB->Ldr so a
            // later GetModuleFileNameW / LdrGetDllHandle walk finds it + still terminates circularly.
            // Re-thread from the FULL MODULE_TABLE (add_ldr_module de-dupes) to catch transitive deps
            // snap_module just mapped, not only `loaded` itself.
            {
                let table = &*table_ptr;
                let mut i = 0usize;
                while i < table.count.min(MODULE_TABLE_CAP) {
                    let m = table.mods[i];
                    if m.base >= 0x1_0000 {
                        add_ldr_module(m.base, &m.name[..m.nlen as usize]);
                    }
                    i += 1;
                }
                thread_ldr_lists();
            }
            loaded
        };
        let attach_status = run_process_attach_root(table_ptr, base);
        if attach_status != 0 {
            if reference_added {
                let rollback_status = ldr_release_dll_reference(base);
                if rollback_status != 0 {
                    return rollback_status;
                }
            }
            if newly_loaded {
                (&mut *table_ptr).set_attach_failed(base, true);
            }
            return attach_status;
        }
        (&mut *table_ptr).set_attach_failed(base, false);
        if newly_loaded {
            crate::exports::ldr_send_dll_notifications_for_base(base, 1);
        }
        if !base_addr.is_null() {
            core::ptr::write_unaligned(base_addr, base as *mut c_void);
        }
    }
    0 // STATUS_SUCCESS
}

/// Apply an ordinary or pin reference to `base` and propagate it across loaded import edges.
///
/// # Safety
/// `base` is a mapped module recorded in `PEB->Ldr`; the loader lock is held by the caller.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldr_add_ref_dll(base: u64, pin: bool) -> u32 {
    let mut visited = [0u64; MODULE_TABLE_CAP];
    let mut visited_count = 0usize;
    let status = unsafe {
        collect_reference_modules_dfs(
            core::ptr::addr_of!(MODULE_TABLE),
            base,
            &mut visited,
            &mut visited_count,
        )
    };
    if status != 0 {
        return status;
    }

    // Plan the full graph before publishing any count. A missing late loader entry therefore
    // leaves every earlier module unchanged, and an already-pinned root still propagates a pin to
    // non-pinned dependencies.
    let mut count_ptrs = [0u64; MODULE_TABLE_CAP];
    let mut next_counts = [0u16; MODULE_TABLE_CAP];
    for (index, &module) in visited[..visited_count].iter().enumerate() {
        match unsafe { crate::exports::ldr_plan_module_reference(module, pin) } {
            Ok((count_ptr, next)) => {
                count_ptrs[index] = count_ptr as u64;
                next_counts[index] = next;
            }
            Err(status) => return status,
        }
    }
    for index in 0..visited_count {
        unsafe {
            core::ptr::write_unaligned(count_ptrs[index] as *mut u16, next_counts[index]);
        }
    }
    0
}

/// Release one loader reference from `base` and each loaded import edge it owns. The transaction is
/// committed only when every count remains nonzero; actual detach/unmap remains a separate path.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldr_release_dll_reference(base: u64) -> u32 {
    use nt_ntdll::loader::lifecycle::{ReferenceReleaseLedger, ReferenceReleasePlan};

    match unsafe { crate::exports::ldr_plan_module_release(base, 1) } {
        Ok((_, _, ReferenceReleasePlan::Pinned)) => return 0,
        Ok((_, _, ReferenceReleasePlan::TeardownRequired)) => return 0xC000_0002,
        Ok((_, _, ReferenceReleasePlan::Invalid)) => return 0xC000_000D,
        Ok((_, _, ReferenceReleasePlan::DecrementTo(_))) => {}
        Err(status) => return status,
    }
    let table = core::ptr::addr_of!(MODULE_TABLE);
    if unsafe { (&*table).index_by_base(base) }.is_none() {
        return 0xC000_0135; // STATUS_DLL_NOT_FOUND
    }

    let mut ledger = ReferenceReleaseLedger::<MODULE_TABLE_CAP>::new();
    if !ledger.record(base) {
        return 0xC000_0017; // STATUS_NO_MEMORY
    }
    let mut visited = [0u64; MODULE_TABLE_CAP];
    let mut visited_count = 0usize;
    let collect_status = unsafe {
        collect_reference_releases(
            table,
            base,
            &mut ledger,
            &mut visited,
            &mut visited_count,
        )
    };
    if collect_status != 0 {
        return collect_status;
    }

    let mut count_ptrs = [0u64; MODULE_TABLE_CAP];
    let mut next = [0u16; MODULE_TABLE_CAP];
    for (index, release) in ledger.as_slice().iter().enumerate() {
        let (count_ptr, current, plan) = match unsafe {
            crate::exports::ldr_plan_module_release(release.base, release.releases)
        } {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        count_ptrs[index] = count_ptr as u64;
        match plan {
            ReferenceReleasePlan::Pinned => next[index] = current,
            ReferenceReleasePlan::DecrementTo(value) => next[index] = value,
            ReferenceReleasePlan::TeardownRequired => return 0xC000_0002,
            ReferenceReleasePlan::Invalid => return 0xC000_000D,
        }
    }

    for (index, _) in ledger.as_slice().iter().enumerate() {
        let count_ptr = count_ptrs[index] as *mut u16;
        let current = unsafe { core::ptr::read_unaligned(count_ptr) };
        if next[index] == current {
            continue;
        }
        unsafe { core::ptr::write_unaligned(count_ptr, next[index]) };
    }
    0
}

#[cfg(target_arch = "x86_64")]
unsafe fn collect_reference_releases(
    table: *const ModuleTable,
    base: u64,
    ledger: &mut nt_ntdll::loader::lifecycle::ReferenceReleaseLedger<MODULE_TABLE_CAP>,
    visited: &mut [u64; MODULE_TABLE_CAP],
    visited_count: &mut usize,
) -> u32 {
    if visited[..*visited_count].contains(&base) {
        return 0;
    }
    if *visited_count >= MODULE_TABLE_CAP {
        return 0xC000_0017;
    }
    visited[*visited_count] = base;
    *visited_count += 1;

    let (imports_rva, _) = unsafe { data_directory(base, 1) };
    if imports_rva == 0 {
        return 0;
    }
    let mut descriptor = base + imports_rva as u64;
    let mut descriptor_count = 0usize;
    loop {
        let name_rva = unsafe { rd32(descriptor, 12) };
        let first_thunk = unsafe { rd32(descriptor, 16) };
        if name_rva == 0 || first_thunk == 0 {
            break;
        }
        let mut name = [0u8; 32];
        let length = unsafe { import_desc_basename(base, name_rva, &mut name) };
        let dependency = unsafe { (&*table).find(&name[..length]) };
        if dependency >= 0x1_0000 {
            if !ledger.record(dependency) {
                return 0xC000_0017;
            }
            let status = unsafe {
                collect_reference_releases(table, dependency, ledger, visited, visited_count)
            };
            if status != 0 {
                return status;
            }
        }
        descriptor += 20;
        descriptor_count += 1;
        if descriptor_count >= MODULE_TABLE_CAP {
            return 0xC000_007B;
        }
    }
    0
}

#[cfg(target_arch = "x86_64")]
unsafe fn collect_reference_modules_dfs(
    table: *const ModuleTable,
    base: u64,
    visited: &mut [u64; MODULE_TABLE_CAP],
    visited_count: &mut usize,
) -> u32 {
    if visited[..*visited_count].contains(&base) {
        return 0;
    }
    if *visited_count >= MODULE_TABLE_CAP {
        return 0xC000_0017; // STATUS_NO_MEMORY: bounded graph capacity exhausted.
    }
    visited[*visited_count] = base;
    *visited_count += 1;

    let (imports_rva, _) = unsafe { data_directory(base, 1) };
    if imports_rva == 0 {
        return 0;
    }
    let mut descriptor = base + imports_rva as u64;
    let mut descriptor_count = 0usize;
    loop {
        let name_rva = unsafe { rd32(descriptor, 12) };
        let first_thunk = unsafe { rd32(descriptor, 16) };
        if name_rva == 0 || first_thunk == 0 {
            break;
        }
        let mut name = [0u8; 32];
        let length = unsafe { import_desc_basename(base, name_rva, &mut name) };
        let dependency = unsafe { (&*table).find(&name[..length]) };
        if dependency >= 0x1_0000 {
            let status = unsafe {
                collect_reference_modules_dfs(table, dependency, visited, visited_count)
            };
            if status != 0 {
                return status;
            }
        }
        descriptor += 20;
        descriptor_count += 1;
        if descriptor_count >= MODULE_TABLE_CAP {
            return 0xC000_007B; // STATUS_INVALID_IMAGE_FORMAT
        }
    }
    0
}

/// `LdrGetDllHandle` in-process driver — return the base of an already-loaded module (does NOT load).
///
/// # Safety
/// On-target; `dll_name` a valid `UNICODE_STRING*`; `dll_handle` writable.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldr_get_dll_handle(dll_name: *const c_void, dll_handle: *mut *mut c_void) -> u32 {
    let mut name = [0u8; 32];
    // SAFETY: dll_name a valid UNICODE_STRING per the contract.
    let n = unsafe { unicode_basename_lc(dll_name, &mut name) };
    if n == 0 {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    // SAFETY: single-threaded loader table read.
    let base = unsafe {
        let table = &*core::ptr::addr_of!(MODULE_TABLE);
        table.find(&name[..n])
    };
    if base == 0 {
        return 0xC000_0135; // STATUS_DLL_NOT_FOUND
    }
    if !dll_handle.is_null() {
        // SAFETY: dll_handle writable per the contract.
        unsafe { core::ptr::write_unaligned(dll_handle, base as *mut c_void) };
    }
    0
}

/// `LdrGetProcedureAddress` in-process driver — resolve an export (by name via the `ANSI_STRING`, or
/// by ordinal if `name` is NULL) in the mapped module at `base_address`.
///
/// # Safety
/// On-target; `base_address` a mapped module; `name` a valid `ANSI_STRING*` or NULL; `address`
/// writable.
#[cfg(target_arch = "x86_64")]
pub unsafe fn ldr_get_procedure_address(
    base_address: *mut c_void,
    name: *const c_void,
    ordinal: u32,
    address: *mut *mut c_void,
) -> u32 {
    let base = base_address as u64;
    if base == 0 {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    // SAFETY: reading the module's export directory + the optional ANSI_STRING name, and (for a
    // forwarded export) resolving the forwarder target over the process-wide MODULE_TABLE — the same
    // forwarder handling the static import snap does (else a forwarded proc address would be the
    // forwarder STRING, faulting on the first call).
    let addr = unsafe {
        let table = core::ptr::addr_of_mut!(MODULE_TABLE);
        if name.is_null() {
            let mut load_status = 0;
            let address = resolve_export_addr(
                base,
                true,
                &[],
                ordinal,
                table,
                &mut load_status,
                0,
            );
            if load_status != 0 {
                return load_status;
            }
            address
        } else {
            // ANSI_STRING { Length(u16)@0, MaximumLength(u16)@2, Buffer(ptr)@8 }.
            let length = core::ptr::read_unaligned(name as *const u16) as usize;
            let buffer = core::ptr::read_unaligned((name as *const u8).add(8) as *const u64);
            if buffer == 0 || length == 0 {
                0
            } else {
                let mut nb = [0u8; 96];
                let l = length.min(96);
                for i in 0..l {
                    nb[i] = core::ptr::read_unaligned((buffer as *const u8).add(i));
                }
                let mut load_status = 0;
                let address = resolve_export_addr(
                    base,
                    false,
                    &nb[..l],
                    0,
                    table,
                    &mut load_status,
                    0,
                );
                if load_status != 0 {
                    return load_status;
                }
                address
            }
        }
    };
    if addr == 0 {
        return 0xC000_0139; // STATUS_ENTRYPOINT_NOT_FOUND
    }
    if !address.is_null() {
        // SAFETY: address writable per the contract.
        unsafe { core::ptr::write_unaligned(address, addr as *mut c_void) };
    }
    0
}

// ---------------------------------------------------------------------------------------------
// Step 4.C — RtlAdjustPrivilege over the live token plane.
//
// The real ntdll `RtlAdjustPrivilege` opens the selected process/thread token, adjusts one
// privilege, and returns its prior enabled state. The executive owns the persistent token state.
// ---------------------------------------------------------------------------------------------

const SSN_NT_OPEN_PROCESS_TOKEN: u32 = 129;
const SSN_NT_OPEN_THREAD_TOKEN: u32 = 135;
const SSN_NT_ADJUST_PRIVILEGES_TOKEN: u32 = 12;
const SSN_NT_CLOSE: u32 = 27;

/// `TOKEN_ADJUST_PRIVILEGES (0x20) | TOKEN_QUERY (0x08)`.
const TOKEN_ADJUST_PRIVILEGES_QUERY: u32 = 0x28;
/// `SE_PRIVILEGE_ENABLED`.
const SE_PRIVILEGE_ENABLED: u32 = 0x2;

/// A general 4-register-arg syscall (`arg1..arg4`). TRAP transport (fallback): `mov r10,rcx; syscall`.
///
/// # Safety
/// On-target hosted-process syscall; the args must satisfy the target syscall's contract.
#[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
#[inline]
unsafe fn syscall4(ssn: u32, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let status: u64;
    // SAFETY: a hosted-process syscall trap serviced by the executive.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x28",
            "mov r10, {a1}",
            "mov rdx, {a2}",
            "mov r8,  {a3}",
            "mov r9,  {a4}",
            "mov eax, {ssn:e}",
            "syscall",
            "add rsp, 0x28",
            ssn = in(reg) ssn,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            a3 = in(reg) a3,
            a4 = in(reg) a4,
            out("rax") status,
            out("rcx") _, out("r11") _, out("r10") _, out("r8") _, out("r9") _,
            clobber_abi("system"),
        );
    }
    status
}

/// A general 4-register-arg syscall (`arg1..arg4`). NATIVE seL4-Call transport (ntdll_plan Step 6.A):
/// a real native `Call(CT_FAULT)` carrying the NT_NATIVE_SYSCALL request; NTSTATUS from reply MR0.
/// Delegates to the 6-arg helper with zero stack args (a3/a4 ride in MR4/MR5).
///
/// # Safety
/// On-target hosted-process syscall; the args must satisfy the target syscall's contract.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
unsafe fn syscall4(ssn: u32, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    // SAFETY: forwarding to the native 6-arg helper (a5/a6 = 0, unused by a 4-arg service).
    unsafe { native_syscall(ssn, a1, a2, a3, a4, 0, 0) }
}

/// SEH seam: a 2-arg syscall (`NtContinue(CONTEXT*, alertable)`). Transport-agnostic — delegates to
/// [`syscall4`] which flips between the trap + native transports with the rest of the surface.
///
/// # Safety
/// On-target hosted-process syscall; `a1` must satisfy the target syscall's contract.
#[cfg(target_arch = "x86_64")]
pub unsafe fn seh_syscall2(ssn: u32, a1: u64, a2: u64) -> u64 {
    // SAFETY: forwarding to the general 4-arg helper (a3/a4 unused).
    unsafe { syscall4(ssn, a1, a2, 0, 0) }
}

/// SEH seam: a 3-arg syscall (`NtRaiseException(record, context, first_chance)`).
///
/// # Safety
/// On-target hosted-process syscall; the args must satisfy the target syscall's contract.
#[cfg(target_arch = "x86_64")]
pub unsafe fn seh_syscall3(ssn: u32, a1: u64, a2: u64, a3: u64) -> u64 {
    // SAFETY: forwarding to the general 4-arg helper (a4 unused).
    unsafe { syscall4(ssn, a1, a2, a3, 0) }
}

/// SEH seam: the `(virtual_address, size)` of data directory `idx` in a mapped PE at `base`
/// (public wrapper over [`data_directory`] for the SEH module).
///
/// # Safety
/// `base` must be a mapped PE image (DOS + NT headers readable).
#[cfg(target_arch = "x86_64")]
pub unsafe fn data_directory_pub(base: u64, idx: u64) -> (u32, u32) {
    // SAFETY: mapped-image header read.
    unsafe { data_directory(base, idx) }
}

/// The NATIVE seL4-Call transport primitive (ntdll_plan Step 6.A). Builds the NT_NATIVE_SYSCALL
/// REQUEST message and issues a real native seL4 `Call(CT_FAULT)`:
///   MR0=SSN, MR1=caller-rsp, MR2=a1, MR3=a2, MR4=a3, MR5=a4  (a5/a6 → stack at [rsp+0x28/0x30]).
/// The executive Recv's it (label 0x4E54), decodes SSN+args (reading a5+ AND writing stack out-params
/// through its stack mirror — hence MR1=rsp), services via ExecNtHandler, and replies MR0=NTSTATUS.
///
/// The stack args a5/a6 are placed at `[rsp+0x28]/[rsp+0x30]` exactly as the Windows x64 ABI + the
/// trap path do, and `rsp` is captured into MR1 AFTER reserving that frame — so the executive's
/// `smss_stack_read(rsp+0x28+…)` finds them. All register out-params (`&base`/`&handle`/…) are
/// pointers into the caller's mapped stack, written by the executive through the same mirror — no
/// out-param-in-reply needed for this transport cut (that layers on later).
///
/// # Safety
/// On-target hosted-process; args satisfy the service contract; register out-param pointers are
/// valid stack locals in the caller's frame.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn native_syscall(ssn: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    // SAFETY: forwarding to the general native primitive (a7/a8 = 0, unused by a ≤6-arg service).
    unsafe { native_syscall8(ssn, a1, a2, a3, a4, a5, a6, 0, 0) }
}

/// The IPC buffer fixed per-process VA. MR `i` lives at byte `8 + i*8`; MR4 @ +0x28, MR5 @ +0x30.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
const IPCBUF_VADDR: u64 = 0x0000_0100_105F_B000;

/// The general NATIVE seL4-Call transport primitive (ntdll_plan Step 6.A) — up to 8 args.
///
/// Register-pressure discipline: only the essential values are held live across the asm. MR4/MR5
/// (a3/a4) are written to the IPC buffer with plain Rust BEFORE the asm; the 4 register message
/// words + the stack args (a5..a8) are passed through a small on-stack `req` array which the asm
/// reads (a single `in(reg)` pointer), and the asm copies a5..a8 to `[rsp+0x28..0x40]` (the Windows
/// x64 ABI stack-arg slots the executive's mirror reads) then Calls.
///
/// # Safety
/// On-target hosted-process; the register out-param pointers (in a1..a4) are valid stack locals.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn native_syscall8(
    ssn: u32,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
) -> u64 {
    // MR4/MR5 = a3/a4 into the IPC buffer (plain Rust — no live registers needed across the Call).
    // SAFETY: IPCBUF_VADDR is this process's mapped IPC buffer frame; MR4/MR5 at +0x28/+0x30.
    unsafe {
        core::ptr::write_volatile((IPCBUF_VADDR + 0x28) as *mut u64, a3);
        core::ptr::write_volatile((IPCBUF_VADDR + 0x30) as *mut u64, a4);
    }
    // The register message words + the stack args, laid out for the asm to consume via ONE pointer:
    //   [0]=SSN(MR0)  [1]=a1(MR2)  [2]=a2(MR3)  [3]=a5  [4]=a6  [5]=a7  [6]=a8
    let req: [u64; 7] = [ssn as u64, a1, a2, a5, a6, a7, a8];
    let status: u64;
    // SAFETY: a native seL4 Call serviced by the executive. `req` is a valid readable stack array;
    // the asm reserves the ABI stack frame, copies a5..a8 to [rsp+0x28..0x40] (the mirror-read
    // slots), sets the register message (MR0=r10, MR1=rsp, MR2=r9, MR3=r15), and Calls. rsp (MR1) is
    // captured AFTER the frame reservation so the executive's `sp+0x28` reads land on a5..a8.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x48",
            "mov rax, [{req} + 0x18]",          // a5
            "mov [rsp+0x28], rax",
            "mov rax, [{req} + 0x20]",          // a6
            "mov [rsp+0x30], rax",
            "mov rax, [{req} + 0x28]",          // a7
            "mov [rsp+0x38], rax",
            "mov rax, [{req} + 0x30]",          // a8
            "mov [rsp+0x40], rax",
            "mov r10, [{req} + 0x00]",          // MR0 = SSN
            "mov r9,  [{req} + 0x08]",          // MR2 = a1
            "mov r15, [{req} + 0x10]",          // MR3 = a2
            "mov r8, rsp",                      // MR1 = caller rsp (points at the reserved frame)
            "mov edi, 6",                       // rdi = CT_FAULT cap slot
            "mov esi, 0x04E54006",              // rsi = (0x4E54<<12)|6 = label 0x4E54, length 6
            "mov rdx, -1",                      // rdx = SysCall
            "syscall",
            "add rsp, 0x48",
            "mov {status}, r10",                // reply MR0 = NTSTATUS (IPC return ABI: r10)
            req = in(reg) req.as_ptr(),
            status = out(reg) status,
            out("rax") _, out("rcx") _, out("r11") _, out("r8") _, out("r9") _,
            out("r10") _, out("rsi") _, out("rdi") _, out("rdx") _, out("r15") _,
            options(nostack),
        );
    }
    status
}

/// `NtMapViewOfSection` (10 args) over the NATIVE seL4-Call transport. Same message shape as
/// [`native_syscall8`] (MR0=SSN, MR1=rsp, MR2=a1, MR3=a2, MR4=a3, MR5=a4) but the SIX tail args
/// (a5..a10 = commit_size/section_offset/view_size/inherit/alloc_type/protect) go on the stack at
/// `[rsp+0x28..0x50]` — the exact slots the executive's map handler reads (a5=`sp+0x28`,
/// a6/SectionOffset=`sp+0x30`, a7/ViewSize=`sp+0x38`, …). a3 (*BaseAddress) lands in MR4 →
/// `set_recv_mr(7)` → the `get_recv_mr(7)` the handler reads.
///
/// # Safety
/// On-target hosted-process; the out-param pointers (base_address/view_size) are valid stack locals.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn native_map_view(a1: u64, a2: u64, a3: u64, a4: u64, tail: [u64; 6]) -> u64 {
    // MR4/MR5 = a3/a4 into the IPC buffer (plain Rust — no live registers across the Call).
    // SAFETY: IPCBUF_VADDR is this process's mapped IPC buffer; MR4/MR5 at +0x28/+0x30.
    unsafe {
        core::ptr::write_volatile((IPCBUF_VADDR + 0x28) as *mut u64, a3);
        core::ptr::write_volatile((IPCBUF_VADDR + 0x30) as *mut u64, a4);
    }
    // req: [0]=SSN(MR0) [1]=a1(MR2) [2]=a2(MR3) [3..9]=the six stack tail args.
    let req: [u64; 9] = [
        SSN_NT_MAP_VIEW_OF_SECTION as u64,
        a1,
        a2,
        tail[0],
        tail[1],
        tail[2],
        tail[3],
        tail[4],
        tail[5],
    ];
    let status: u64;
    // SAFETY: a native seL4 Call serviced by the executive. `req` is a valid readable stack array;
    // the asm reserves the ABI frame, copies the 6 tail args to [rsp+0x28..0x50] (the mirror-read
    // slots), sets the register message (MR0=r10, MR1=rsp, MR2=r9, MR3=r15), and Calls.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x58",
            "mov rax, [{req} + 0x18]", // tail[0] (a5)
            "mov [rsp+0x28], rax",
            "mov rax, [{req} + 0x20]", // tail[1] (a6)
            "mov [rsp+0x30], rax",
            "mov rax, [{req} + 0x28]", // tail[2] (a7)
            "mov [rsp+0x38], rax",
            "mov rax, [{req} + 0x30]", // tail[3] (a8)
            "mov [rsp+0x40], rax",
            "mov rax, [{req} + 0x38]", // tail[4] (a9)
            "mov [rsp+0x48], rax",
            "mov rax, [{req} + 0x40]", // tail[5] (a10)
            "mov [rsp+0x50], rax",
            "mov r10, [{req} + 0x00]", // MR0 = SSN
            "mov r9,  [{req} + 0x08]", // MR2 = a1
            "mov r15, [{req} + 0x10]", // MR3 = a2
            "mov r8, rsp",             // MR1 = caller rsp
            "mov edi, 6",              // rdi = CT_FAULT cap slot
            "mov esi, 0x04E54006",     // rsi = (0x4E54<<12)|6
            "mov rdx, -1",             // rdx = SysCall
            "syscall",
            "add rsp, 0x58",
            "mov {status}, r10",
            req = in(reg) req.as_ptr(),
            status = out(reg) status,
            out("rax") _, out("rcx") _, out("r11") _, out("r8") _, out("r9") _,
            out("r10") _, out("rsi") _, out("rdi") _, out("rdx") _, out("r15") _,
            options(nostack),
        );
    }
    status
}

/// `NtSecureConnectPort` (9 args) over the NATIVE seL4-Call transport. Same message shape as
/// [`native_syscall8`] / [`native_map_view`] (MR0=SSN, MR1=rsp, MR2=a1, MR3=a2, MR4=a3, MR5=a4) but
/// the FIVE tail args (a5..a9 = ServerSid/ServerView/MaxMessageLength/ConnectionInformation/
/// ConnectionInformationLength) go on the stack at `[rsp+0x28..0x50]` — the exact slots the
/// executive's `csr_client_connect` reads (a8/ConnectionInformation = `sp+0x40`).
///
/// # Safety
/// On-target hosted-process; the pointer args (PortHandle/PortName/Qos/ClientView/ConnInfo) are valid
/// stack locals whose out-fields the executive fills through its stack mirror.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn native_secure_connect_port(a1: u64, a2: u64, a3: u64, a4: u64, tail: [u64; 5]) -> u64 {
    // MR4/MR5 = a3/a4 into the IPC buffer (plain Rust — no live registers across the Call).
    // SAFETY: IPCBUF_VADDR is this process's mapped IPC buffer; MR4/MR5 at +0x28/+0x30.
    unsafe {
        core::ptr::write_volatile((IPCBUF_VADDR + 0x28) as *mut u64, a3);
        core::ptr::write_volatile((IPCBUF_VADDR + 0x30) as *mut u64, a4);
    }
    // req: [0]=SSN(MR0) [1]=a1(MR2) [2]=a2(MR3) [3..8]=the five stack tail args (a5..a9).
    let req: [u64; 8] = [
        SSN_NT_SECURE_CONNECT_PORT as u64,
        a1,
        a2,
        tail[0],
        tail[1],
        tail[2],
        tail[3],
        tail[4],
    ];
    let status: u64;
    // SAFETY: a native seL4 Call serviced by the executive. `req` is a valid readable stack array;
    // the asm reserves the ABI frame, copies the 5 tail args to [rsp+0x28..0x50] (the mirror-read
    // slots), sets the register message (MR0=r10, MR1=rsp, MR2=r9, MR3=r15), and Calls.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x58",
            "mov rax, [{req} + 0x18]", // tail[0] (a5)
            "mov [rsp+0x28], rax",
            "mov rax, [{req} + 0x20]", // tail[1] (a6)
            "mov [rsp+0x30], rax",
            "mov rax, [{req} + 0x28]", // tail[2] (a7)
            "mov [rsp+0x38], rax",
            "mov rax, [{req} + 0x30]", // tail[3] (a8 = ConnectionInformation)
            "mov [rsp+0x40], rax",
            "mov rax, [{req} + 0x38]", // tail[4] (a9 = ConnectionInformationLength)
            "mov [rsp+0x48], rax",
            "mov r10, [{req} + 0x00]", // MR0 = SSN
            "mov r9,  [{req} + 0x08]", // MR2 = a1
            "mov r15, [{req} + 0x10]", // MR3 = a2
            "mov r8, rsp",             // MR1 = caller rsp
            "mov edi, 6",              // rdi = CT_FAULT cap slot
            "mov esi, 0x04E54006",     // rsi = (0x4E54<<12)|6
            "mov rdx, -1",             // rdx = SysCall
            "syscall",
            "add rsp, 0x58",
            "mov {status}, r10",
            req = in(reg) req.as_ptr(),
            status = out(reg) status,
            out("rax") _, out("rcx") _, out("r11") _, out("r8") _, out("r9") _,
            out("r10") _, out("rsi") _, out("rdi") _, out("rdx") _, out("r15") _,
            options(nostack),
        );
    }
    status
}

/// `NtSecureConnectPort` over the TRAP transport. This is the same Windows x64 ABI shape as
/// [`syscall8`], extended with the fifth stack argument at `[rsp+0x48]`.
///
/// # Safety
/// On-target hosted-process syscall; pointer arguments must satisfy the target syscall contract.
#[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn secure_connect_port(a1: u64, a2: u64, a3: u64, a4: u64, tail: [u64; 5]) -> u64 {
    let status: u64;
    // SAFETY: a hosted-process syscall trap serviced by the executive. The stack slots match the
    // Windows x64 ABI positions the executive mirror reads for NtSecureConnectPort args 5..9.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x58",
            "mov qword ptr [rsp+0x28], {a5}",
            "mov qword ptr [rsp+0x30], {a6}",
            "mov qword ptr [rsp+0x38], {a7}",
            "mov qword ptr [rsp+0x40], {a8}",
            "mov qword ptr [rsp+0x48], {a9}",
            "mov r10, {a1}",
            "mov rdx, {a2}",
            "mov r8,  {a3}",
            "mov r9,  {a4}",
            "mov eax, {ssn:e}",
            "syscall",
            "add rsp, 0x58",
            ssn = in(reg) SSN_NT_SECURE_CONNECT_PORT,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            a3 = in(reg) a3,
            a4 = in(reg) a4,
            a5 = in(reg) tail[0],
            a6 = in(reg) tail[1],
            a7 = in(reg) tail[2],
            a8 = in(reg) tail[3],
            a9 = in(reg) tail[4],
            out("rax") status,
            out("rcx") _, out("r11") _, out("r10") _, out("r8") _, out("r9") _,
            clobber_abi("system"),
        );
    }
    status
}

/// `NtSecureConnectPort` over the native seL4-call transport.
///
/// # Safety
/// On-target hosted-process syscall; pointer arguments must satisfy the target syscall contract.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn secure_connect_port(a1: u64, a2: u64, a3: u64, a4: u64, tail: [u64; 5]) -> u64 {
    // SAFETY: forwarding the already-validated NtSecureConnectPort ABI frame.
    unsafe { native_secure_connect_port(a1, a2, a3, a4, tail) }
}

/// `NtSecureConnectPort` SSN (shared `nt-syscall-abi` table; sysfuncs.lst line 219 = index 218).
#[cfg(target_arch = "x86_64")]
const SSN_NT_SECURE_CONNECT_PORT: u32 = 218;

/// The CSR client connect — port of ReactOS `CsrpConnectToServer` (`subsystems/csr/csrlib/connect.c`).
///
/// Called from `CsrClientConnectToServer` (kernel32's `BaseDllInitialize` → the very first thing in
/// its `DLL_PROCESS_ATTACH`). Builds the `\Windows\ApiPort` PortName + the PORT_VIEW / QoS /
/// CSR_API_CONNECTINFO stack locals, issues the 9-arg `NtSecureConnectPort` (which the executive's
/// `csr_client_connect` services — it maps the CSR heap-view + fills LpcWrite + the connectinfo),
/// then copies `ConnectionInfo.{SharedSectionBase,SharedSectionHeap,SharedStaticServerData}` into the
/// PEB (`ReadOnlySharedMemoryBase@0x88 / …Heap@0x90 / ReadOnlyStaticServerData@0x98`) — exactly what
/// kernel32's `DllMain` reads next (`ASSERT(Peb->ReadOnlyStaticServerData)` +
/// `BaseStaticServerData = Peb->ReadOnlyStaticServerData[BASESRV=1]`).
///
/// ★ All the out-param structs are STACK locals so the executive's stack-mirror writes land (same
/// discipline as [`nt_allocate_virtual_memory`]). We skip the real `NtCreateSection` for the CSR
/// section (the executive owns + maps the CSR heap view at a fixed VA regardless) and pass a NULL
/// SectionHandle + NULL SystemSid — cosmetic on the modeled accept path; faithful to the connect
/// shape otherwise.
///
/// # Safety
/// On-target hosted process; issues a real syscall. `object_directory` is a NUL-terminated UTF-16
/// string (or NULL → default `\Windows`). The out-params (`connection_info_size`,
/// `server_to_server`) are NULL or writable.
#[cfg(target_arch = "x86_64")]
pub unsafe fn csr_client_connect_to_server(
    object_directory: *const u16,
    _server_id: u32,
    _connection_info: *mut core::ffi::c_void,
    connection_info_size: *mut u32,
    server_to_server: *mut u8,
) -> u64 {
    // A CSR client (not a server-to-server call).
    if !server_to_server.is_null() {
        // SAFETY: caller passed a writable byte or NULL (checked).
        unsafe { core::ptr::write(server_to_server, 0) };
    }

    // ★ Faithful to CsrpConnectToServer's `if (!CsrApiPort)` guard: connect to \Windows\ApiPort
    // exactly ONCE per process. kernel32's BaseDllInitialize + winlogon's own init both call
    // CsrClientConnectToServer; the second+ calls must be no-op successes (the PEB CSR fields are
    // already published) — otherwise we redundantly re-drive the executive's CSR rendezvous.
    // SAFETY: single-threaded during loader init; a benign racy re-store is harmless (idempotent).
    #[cfg(target_arch = "x86_64")]
    {
        use core::sync::atomic::{AtomicBool, Ordering};
        static CSR_CONNECTED: AtomicBool = AtomicBool::new(false);
        if CSR_CONNECTED.swap(true, Ordering::Relaxed) {
            if !connection_info_size.is_null() {
                // SAFETY: writable ULONG or NULL (checked). 0x38 = sizeof(CSR_API_CONNECTINFO) x64.
                unsafe { core::ptr::write(connection_info_size, 0x38) };
            }
            return 0; // STATUS_SUCCESS — already connected.
        }
    }

    // Build the PortName = "<ObjectDirectory>\ApiPort". ObjectDirectory is L"\Windows" for the base
    // session (CSR_PORT_NAME = L"ApiPort"). Assemble it into a stack UTF-16 buffer.
    let mut name_buf = [0u16; 64];
    let mut nlen = 0usize;
    // Copy the object directory (default L"\Windows" if NULL).
    if object_directory.is_null() {
        for &c in &[
            0x5Cu16,
            b'W' as u16,
            b'i' as u16,
            b'n' as u16,
            b'd' as u16,
            b'o' as u16,
            b'w' as u16,
            b's' as u16,
        ] {
            name_buf[nlen] = c;
            nlen += 1;
        }
    } else {
        // SAFETY: NUL-terminated UTF-16 (the loader passed a valid PCWSTR).
        unsafe {
            let mut i = 0usize;
            loop {
                let c = *object_directory.add(i);
                if c == 0 || nlen >= 55 {
                    break;
                }
                name_buf[nlen] = c;
                nlen += 1;
                i += 1;
            }
        }
    }
    // Append "\ApiPort".
    for &c in &[
        0x5Cu16,
        b'A' as u16,
        b'p' as u16,
        b'i' as u16,
        b'P' as u16,
        b'o' as u16,
        b'r' as u16,
        b't' as u16,
    ] {
        if nlen >= 63 {
            break;
        }
        name_buf[nlen] = c;
        nlen += 1;
    }
    let name_bytes = (nlen * 2) as u16;

    // UNICODE_STRING PortName { Length, MaximumLength, Buffer } (stack local, points at name_buf).
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        _pad: u32,
        buffer: u64,
    }
    let port_name = UnicodeString {
        length: name_bytes,
        maximum_length: name_bytes,
        _pad: 0,
        buffer: name_buf.as_ptr() as u64,
    };

    // SECURITY_QUALITY_OF_SERVICE { Length, ImpersonationLevel, ContextTrackingMode, EffectiveOnly }.
    #[repr(C)]
    struct SecurityQos {
        length: u32,
        impersonation_level: u32,  // SecurityImpersonation = 2
        context_tracking_mode: u8, // SECURITY_DYNAMIC_TRACKING = 1
        effective_only: u8,        // TRUE
        _pad: [u8; 2],
    }
    let qos = SecurityQos {
        length: 12,
        impersonation_level: 2,
        context_tracking_mode: 1,
        effective_only: 1,
        _pad: [0; 2],
    };

    // PORT_VIEW LpcWrite { Length, SectionHandle, SectionOffset, ViewSize, ViewBase, ViewRemoteBase }.
    // The executive fills ViewSize@0x18 / ViewBase@0x20 / ViewRemoteBase@0x28. NULL SectionHandle (the
    // executive maps the CSR heap view itself — we skip the real NtCreateSection).
    #[repr(C)]
    struct PortView {
        length: u32,
        _pad0: u32,
        section_handle: u64,
        section_offset: u32,
        _pad1: u32,
        view_size: u64,
        view_base: u64,
        view_remote_base: u64,
    }
    let mut lpc_write = PortView {
        length: 0x30,
        _pad0: 0,
        section_handle: 0,
        section_offset: 0,
        _pad1: 0,
        view_size: 0x1_0000,
        view_base: 0,
        view_remote_base: 0,
    };

    // REMOTE_PORT_VIEW LpcRead { Length, ViewSize, ViewBase }.
    #[repr(C)]
    struct RemotePortView {
        length: u32,
        _pad0: u32,
        view_size: u64,
        view_base: u64,
    }
    let mut lpc_read = RemotePortView {
        length: 0x18,
        _pad0: 0,
        view_size: 0,
        view_base: 0,
    };

    // CSR_API_CONNECTINFO ConnectionInfo (x64 0x38): ObjectDirectory@0, SharedSectionBase@0x08,
    // SharedStaticServerData@0x10, SharedSectionHeap@0x18, DebugFlags@0x20, …, ServerProcessId@0x30.
    #[repr(C)]
    struct CsrApiConnectInfo {
        object_directory: u64,
        shared_section_base: u64,
        shared_static_server_data: u64,
        shared_section_heap: u64,
        debug_flags: u32,
        size_of_peb_data: u32,
        size_of_teb_data: u32,
        number_of_server_dll_names: u32,
        server_process_id: u64,
    }
    let mut conn_info = CsrApiConnectInfo {
        object_directory: 0,
        shared_section_base: 0,
        shared_static_server_data: 0,
        shared_section_heap: 0,
        debug_flags: 0,
        size_of_peb_data: 0,
        size_of_teb_data: 0,
        number_of_server_dll_names: 0,
        server_process_id: 0,
    };
    let mut conn_info_len: u32 = core::mem::size_of::<CsrApiConnectInfo>() as u32;

    // *CsrApiPort — the returned client comm-port handle (stack local, executive writes it).
    let mut csr_api_port: u64 = 0;

    // NtSecureConnectPort(&CsrApiPort, &PortName, &Qos, &LpcWrite, SystemSid=NULL, &LpcRead,
    //                     MaxMessageLength=NULL, &ConnectionInfo, &ConnectionInfoLength).
    // SAFETY: all pointer args are valid stack locals; the executive services SSN 218.
    let status = unsafe {
        secure_connect_port(
            &mut csr_api_port as *mut u64 as u64,      // a1 = *PortHandle
            &port_name as *const UnicodeString as u64, // a2 = PortName
            &qos as *const SecurityQos as u64,         // a3 = SecurityQos
            &mut lpc_write as *mut PortView as u64,    // a4 = ClientView (LpcWrite)
            [
                0,                                               // a5 = ServerSid (NULL)
                &mut lpc_read as *mut RemotePortView as u64,     // a6 = ServerView (LpcRead)
                0,                                               // a7 = MaxMessageLength (NULL)
                &mut conn_info as *mut CsrApiConnectInfo as u64, // a8 = ConnectionInformation
                &mut conn_info_len as *mut u32 as u64,           // a9 = ConnectionInformationLength
            ],
        )
    };
    if status != 0 {
        return status;
    }

    // Publish ReactOS's CSR ntdll globals for later CsrClientCallServer/CsrGetProcessId calls.
    // The executive currently maps the client and server CSR views at the same VA, so the delta is
    // zero; keep the real formula so a non-zero remote view starts working without changing the
    // capture-buffer conversion code.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CSR_API_PORT), csr_api_port);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(CSR_PORT_MEMORY_DELTA),
            (lpc_write.view_remote_base as isize).wrapping_sub(lpc_write.view_base as isize),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(CSR_PROCESS_ID),
            conn_info.server_process_id,
        );
    }

    // Copy the CSR section data into the PEB (CsrpConnectToServer, connect.c:167-169).
    // SAFETY: gs:[0x60] = PEB; offsets are the byte-exact x64 layout (nt-ntdll-layout).
    unsafe {
        let peb: u64;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb != 0 {
            core::ptr::write_volatile((peb + 0x88) as *mut u64, conn_info.shared_section_base); // ReadOnlySharedMemoryBase
            core::ptr::write_volatile((peb + 0x90) as *mut u64, conn_info.shared_section_heap); // ReadOnlySharedMemoryHeap
            core::ptr::write_volatile(
                (peb + 0x98) as *mut u64,
                conn_info.shared_static_server_data,
            ); // ReadOnlyStaticServerData
        }
    }

    // Report the (unchanged) connection-info size back to the caller.
    if !connection_info_size.is_null() {
        // SAFETY: caller passed a writable ULONG or NULL (checked).
        unsafe { core::ptr::write(connection_info_size, conn_info_len) };
    }
    0 // STATUS_SUCCESS
}

/// A general 6-arg syscall. TRAP transport (fallback): arg1..4 registers, arg5/arg6 on the stack.
///
/// # Safety
/// On-target hosted-process syscall; args must satisfy the target syscall's contract.
#[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
#[inline]
unsafe fn syscall6(ssn: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    let status: u64;
    // SAFETY: a hosted-process syscall trap serviced by the executive.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x38",
            "mov qword ptr [rsp+0x28], {a5}",
            "mov qword ptr [rsp+0x30], {a6}",
            "mov r10, {a1}",
            "mov rdx, {a2}",
            "mov r8,  {a3}",
            "mov r9,  {a4}",
            "mov eax, {ssn:e}",
            "syscall",
            "add rsp, 0x38",
            ssn = in(reg) ssn,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            a3 = in(reg) a3,
            a4 = in(reg) a4,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            out("rax") status,
            out("rcx") _, out("r11") _, out("r10") _, out("r8") _, out("r9") _,
            clobber_abi("system"),
        );
    }
    status
}

/// A general 6-arg syscall. NATIVE seL4-Call transport (ntdll_plan Step 6.A) — delegates to
/// [`native_syscall`] (a5/a6 at `[rsp+0x28/0x30]`, MR1=rsp).
///
/// # Safety
/// On-target hosted-process syscall; args must satisfy the target syscall's contract.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
unsafe fn syscall6(ssn: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    // SAFETY: forwarding to the native primitive.
    unsafe { native_syscall(ssn, a1, a2, a3, a4, a5, a6) }
}

/// `RtlAdjustPrivilege(Privilege, Enable, CurrentThread, WasEnabled)` — the live-token implementation.
///
/// Opens the selected token, builds a one-entry `TOKEN_PRIVILEGES { count=1, luid={priv,0},
/// attrs=Enable?ENABLED:0 }`, calls `NtAdjustPrivilegesToken`, closes the token, and reports the prior
/// enabled state in `*was_enabled`. Returns the `NtAdjustPrivilegesToken` status.
///
/// # Safety
/// On-target hosted-process; `was_enabled` is null or a valid writable byte.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_adjust_privilege(
    privilege: u32,
    enable: u8,
    current_thread: u8,
    was_enabled: *mut u8,
) -> u64 {
    let mut token: u64 = 0;
    let st_open = if current_thread != 0 {
        // SAFETY: on-target NtOpenThreadToken call with a writable stack out-parameter.
        unsafe {
            syscall4(
                SSN_NT_OPEN_THREAD_TOKEN,
                NT_CURRENT_THREAD,
                TOKEN_ADJUST_PRIVILEGES_QUERY as u64,
                0,
                &mut token as *mut u64 as u64,
            )
        }
    } else {
        // SAFETY: on-target NtOpenProcessToken call with a writable stack out-parameter.
        unsafe {
            syscall4(
                SSN_NT_OPEN_PROCESS_TOKEN,
                NT_CURRENT_PROCESS,
                TOKEN_ADJUST_PRIVILEGES_QUERY as u64,
                &mut token as *mut u64 as u64,
                0,
            )
        }
    };
    if st_open != 0 {
        return st_open;
    }
    // TOKEN_PRIVILEGES on the stack: PrivilegeCount(u32) + LUID_AND_ATTRIBUTES{ LUID(low u32,high
    // i32), Attributes(u32) }. Laid out as [count, luid_low, luid_high, attrs] u32s (16 bytes).
    let new_state: [u32; 4] = [
        1,                                                  // PrivilegeCount
        privilege,                                          // Luid.LowPart (SE_*_PRIVILEGE index)
        0,                                                  // Luid.HighPart
        if enable != 0 { SE_PRIVILEGE_ENABLED } else { 0 }, // Attributes
    ];
    let mut old_state: [u32; 4] = [1, 0, 0, 0];
    let mut ret_len: u32 = 0;
    // NtAdjustPrivilegesToken(Token, DisableAll=FALSE, &NewState, sizeof(OldState), &OldState,
    //                         &ReturnLength).
    // SAFETY: on-target token syscall; the buffers are valid stack locals.
    let st_adj = unsafe {
        syscall6(
            SSN_NT_ADJUST_PRIVILEGES_TOKEN,
            token,
            0, // DisableAllPrivileges = FALSE
            new_state.as_ptr() as u64,
            core::mem::size_of::<[u32; 4]>() as u64,
            old_state.as_mut_ptr() as u64,
            &mut ret_len as *mut u32 as u64,
        )
    };
    // NtClose(Token).
    // SAFETY: on-target; closing the token handle we opened.
    let _ = unsafe { syscall4(SSN_NT_CLOSE, token, 0, 0, 0) };
    if st_adj == 0x0000_0106 {
        return 0xC000_0061; // STATUS_PRIVILEGE_NOT_HELD
    }
    if (st_adj as u32 as i32) < 0 {
        return st_adj;
    }
    if !was_enabled.is_null() {
        let prev = if old_state[0] == 0 {
            enable != 0
        } else {
            (old_state[3] & SE_PRIVILEGE_ENABLED) != 0
        };
        // SAFETY: was_enabled is a valid writable byte per the contract.
        unsafe { core::ptr::write(was_enabled, prev as u8) };
    }
    st_adj
}

// ---------------------------------------------------------------------------------------------
// Step 4.C — RtlSetProcessIsCritical / RtlSetThreadIsCritical over the live info-class plane.
//
// Real ntdll optionally gates on PEB.NtGlobalFlag, queries the prior flag, then sets the persistent
// EPROCESS/ETHREAD BreakOnTermination field through the native information classes.
// ---------------------------------------------------------------------------------------------

const SSN_NT_SET_INFORMATION_PROCESS: u32 = 237;
const SSN_NT_SET_INFORMATION_THREAD: u32 = 238;
const SSN_NT_QUERY_INFORMATION_PROCESS_CRITICAL: u32 = 161;
const SSN_NT_QUERY_INFORMATION_THREAD_CRITICAL: u32 = 162;
/// `ProcessBreakOnTermination` info class.
const PROCESS_BREAK_ON_TERMINATION: u64 = 0x1D;
/// `ThreadBreakOnTermination` info class.
const THREAD_BREAK_ON_TERMINATION: u64 = 0x12;
/// `NtCurrentThread()` pseudo-handle `(HANDLE)-2`.
const NT_CURRENT_THREAD: u64 = u64::MAX - 1;
const FLG_ENABLE_SYSTEM_CRIT_BREAKS: u32 = 0x0010_0000;

unsafe fn critical_breaks_enabled() -> bool {
    let peb: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags, readonly)
        )
    };
    peb != 0
        && unsafe { core::ptr::read_unaligned((peb + 0xBC) as *const u32) }
            & FLG_ENABLE_SYSTEM_CRIT_BREAKS
            != 0
}

/// `RtlSetProcessIsCritical(New, Old, CheckFlag)` — set/clear ProcessBreakOnTermination via a live
/// `NtSetInformationProcess`. `*old` reports the queried prior state when requested.
///
/// # Safety
/// On-target hosted-process; `old` null or a valid writable byte.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_set_process_is_critical(new: u8, old: *mut u8, check_flag: u8) -> u64 {
    if !old.is_null() {
        // SAFETY: caller-provided writable byte.
        unsafe { core::ptr::write(old, 0) };
    }
    if check_flag != 0 && !unsafe { critical_breaks_enabled() } {
        return 0xC000_0001; // STATUS_UNSUCCESSFUL
    }
    if !old.is_null() {
        let mut previous = 0u32;
        let _ = unsafe {
            syscall6(
                SSN_NT_QUERY_INFORMATION_PROCESS_CRITICAL,
                NT_CURRENT_PROCESS,
                PROCESS_BREAK_ON_TERMINATION,
                &mut previous as *mut u32 as u64,
                core::mem::size_of::<u32>() as u64,
                0,
                0,
            )
        };
        unsafe { core::ptr::write(old, previous as u8) };
    }
    let value: u32 = (new != 0) as u32;
    // NtSetInformationProcess(NtCurrentProcess(), ProcessBreakOnTermination, &value, sizeof(ULONG)).
    // SAFETY: on-target syscall; &value is a valid stack in-param.
    unsafe {
        syscall4(
            SSN_NT_SET_INFORMATION_PROCESS,
            NT_CURRENT_PROCESS,
            PROCESS_BREAK_ON_TERMINATION,
            &value as *const u32 as u64,
            core::mem::size_of::<u32>() as u64,
        )
    }
}

/// `RtlSetThreadIsCritical(New, Old, CheckFlag)` — set/clear ThreadBreakOnTermination via a live
/// `NtSetInformationThread`.
///
/// # Safety
/// On-target hosted-process; `old` null or a valid writable byte.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_set_thread_is_critical(new: u8, old: *mut u8, check_flag: u8) -> u64 {
    if !old.is_null() {
        // SAFETY: caller-provided writable byte.
        unsafe { core::ptr::write(old, 0) };
    }
    if check_flag != 0 && !unsafe { critical_breaks_enabled() } {
        return 0xC000_0001;
    }
    if !old.is_null() {
        let mut previous = 0u32;
        let _ = unsafe {
            syscall6(
                SSN_NT_QUERY_INFORMATION_THREAD_CRITICAL,
                NT_CURRENT_THREAD,
                THREAD_BREAK_ON_TERMINATION,
                &mut previous as *mut u32 as u64,
                core::mem::size_of::<u32>() as u64,
                0,
                0,
            )
        };
        unsafe { core::ptr::write(old, previous as u8) };
    }
    let value: u32 = (new != 0) as u32;
    // NtSetInformationThread(NtCurrentThread(), ThreadBreakOnTermination, &value, sizeof(ULONG)).
    // SAFETY: on-target syscall; &value is a valid stack in-param.
    unsafe {
        syscall4(
            SSN_NT_SET_INFORMATION_THREAD,
            NT_CURRENT_THREAD,
            THREAD_BREAK_ON_TERMINATION,
            &value as *const u32 as u64,
            core::mem::size_of::<u32>() as u64,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Step 4.C — RtlCreateUserThread over the live NtCreateThread plane.
//
// Real ntdll `RtlCreateUserThread` allocates a stack, builds an INITIAL_TEB + a CONTEXT (Rip =
// StartAddress, Rcx = Parameter, Rsp = stack top), and calls `NtCreateThread`. Our executive's smss
// (pi 0) NtCreateThread handler reads Context* at [rsp+0x30] (arg6), then Context.Rip@0xF8 =
// StartAddress and Context.Rcx@0x80 = Parameter, and spawns the REAL SmpApiLoop thread in smss's
// VSpace (`spawn_sm_loop_thread`). So building that exact CONTEXT + issuing NtCreateThread here is the
// honest live implementation — smss's SM API worker thread actually gets created.
// ---------------------------------------------------------------------------------------------

const SSN_NT_CREATE_THREAD: u32 = 55;
/// `THREAD_ALL_ACCESS`.
const THREAD_ALL_ACCESS: u64 = 0x001F_FFFF;
/// The thread stack reserve (default when the caller passes 0).
const DEFAULT_THREAD_STACK: usize = 0x10_0000; // 1 MiB
/// CONTEXT.Rcx / .Rsp / .Rip byte offsets (amd64), and INITIAL_TEB stack fields — mirror
/// `nt_thread_start`'s constants (the executive reads the same offsets).
const CTX_RCX: usize = 0x80;
const CTX_RSP: usize = 0x98;
const CTX_RIP: usize = 0xF8;
/// The amd64 CONTEXT record size (enough to hold through RIP@0xF8 + the extended area the kernel may
/// touch); 0x4D0 is the real `sizeof(CONTEXT)` on x64.
const CONTEXT_SIZE: usize = 0x4D0;

/// Best-effort current-image stack defaults from `PEB->ImageBaseAddress` optional header.
///
/// # Safety
/// On-target; reads the current PEB and mapped image headers.
#[cfg(target_arch = "x86_64")]
unsafe fn current_image_stack_defaults() -> (usize, usize) {
    let mut commit = nt_ntdll::rtl::user_stack::DEFAULT_STACK_COMMIT;
    let mut reserve = nt_ntdll::rtl::user_stack::DEFAULT_STACK_RESERVE;
    // SAFETY: current hosted thread has a PEB at GS:[0x60].
    unsafe {
        let peb: *const u8;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags, readonly));
        if peb.is_null() {
            return (commit, reserve);
        }
        let image = core::ptr::read_unaligned(peb.add(0x10) as *const u64);
        if image < 0x1_0000 || core::ptr::read_unaligned(image as *const u16) != 0x5A4D {
            return (commit, reserve);
        }
        let e_lfanew = core::ptr::read_unaligned((image + 0x3C) as *const u32) as u64;
        let nt = image + e_lfanew;
        if core::ptr::read_unaligned(nt as *const u32) != 0x0000_4550 {
            return (commit, reserve);
        }
        let opt = nt + 24;
        let magic = core::ptr::read_unaligned(opt as *const u16);
        if magic == 0x20B {
            reserve = core::ptr::read_unaligned((opt + 0x48) as *const u64) as usize;
            commit = core::ptr::read_unaligned((opt + 0x50) as *const u64) as usize;
        } else if magic == 0x10B {
            reserve = core::ptr::read_unaligned((opt + 0x48) as *const u32) as usize;
            commit = core::ptr::read_unaligned((opt + 0x4C) as *const u32) as usize;
        }
    }
    (commit, reserve)
}

/// `RtlCreateUserStack(CommittedStackSize, MaximumStackSize, ZeroBits, PageSize,
/// ReserveAlignment, InitialTeb) -> NTSTATUS`.
///
/// # Safety
/// On-target hosted process; `initial_teb` must be writable for an `INITIAL_TEB`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_create_user_stack(
    committed_stack_size: usize,
    maximum_stack_size: usize,
    zero_bits: u32,
    commit_alignment: usize,
    reserve_alignment: usize,
    initial_teb: *mut u64,
) -> u32 {
    if initial_teb.is_null() {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    let (default_commit, default_reserve) = unsafe { current_image_stack_defaults() };
    let layout = match nt_ntdll::rtl::user_stack::create_user_stack_layout(
        committed_stack_size,
        maximum_stack_size,
        zero_bits,
        commit_alignment,
        reserve_alignment,
        default_commit,
        default_reserve,
    ) {
        Ok(layout) => layout,
        Err(status) => return status,
    };

    let (allocation_base, actual_reserve) = match unsafe {
        nt_allocate_virtual_memory_raw(0, layout.reserve, zero_bits, MEM_RESERVE, PAGE_READWRITE)
    } {
        Ok(pair) => pair,
        Err(status) => return status,
    };
    let layout = nt_ntdll::rtl::user_stack::UserStackLayout {
        reserve: actual_reserve,
        ..layout
    };
    let stack_limit = allocation_base + layout.reserve as u64 - layout.commit as u64;
    let commit_base = if layout.guard != 0 {
        stack_limit - layout.guard as u64
    } else {
        stack_limit
    };
    let commit_size = layout.commit + layout.guard;
    if let Err(status) = unsafe {
        nt_allocate_virtual_memory_raw(commit_base, commit_size, 0, MEM_COMMIT, PAGE_READWRITE)
    } {
        let _ = unsafe { nt_release_virtual_memory(allocation_base) };
        return status;
    }
    if layout.guard != 0 {
        let status = unsafe {
            nt_protect_virtual_memory(commit_base, layout.guard, PAGE_READWRITE | PAGE_GUARD)
        };
        if (status as i32) < 0 {
            let _ = unsafe { nt_release_virtual_memory(allocation_base) };
            return status;
        }
    }

    let fields = nt_ntdll::rtl::user_stack::initial_teb_fields(allocation_base, layout);
    // SAFETY: initial_teb points at five pointer-width fields.
    unsafe {
        core::ptr::write_unaligned(initial_teb.add(0), fields.previous_stack_base);
        core::ptr::write_unaligned(initial_teb.add(1), fields.previous_stack_limit);
        core::ptr::write_unaligned(initial_teb.add(2), fields.stack_base);
        core::ptr::write_unaligned(initial_teb.add(3), fields.stack_limit);
        core::ptr::write_unaligned(initial_teb.add(4), fields.allocated_stack_base);
    }
    0
}

/// `RtlFreeUserStack(DeallocationStack)`.
///
/// # Safety
/// On-target hosted process; `deallocation_stack` should come from `RtlCreateUserStack`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_free_user_stack(deallocation_stack: u64) {
    if deallocation_stack != 0 {
        let _ = unsafe { nt_release_virtual_memory(deallocation_stack) };
    }
}

/// An 8-arg syscall. TRAP transport (fallback): arg1..4 registers; arg5..8 on the stack.
///
/// # Safety
/// On-target hosted-process syscall; args must satisfy the target syscall's contract.
#[cfg(all(target_arch = "x86_64", not(feature = "native_transport")))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn syscall8(
    ssn: u32,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
) -> u64 {
    let status: u64;
    // SAFETY: a hosted-process syscall trap serviced by the executive.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x48",
            "mov qword ptr [rsp+0x28], {a5}",
            "mov qword ptr [rsp+0x30], {a6}",
            "mov qword ptr [rsp+0x38], {a7}",
            "mov qword ptr [rsp+0x40], {a8}",
            "mov r10, {a1}",
            "mov rdx, {a2}",
            "mov r8,  {a3}",
            "mov r9,  {a4}",
            "mov eax, {ssn:e}",
            "syscall",
            "add rsp, 0x48",
            ssn = in(reg) ssn,
            a1 = in(reg) a1, a2 = in(reg) a2, a3 = in(reg) a3, a4 = in(reg) a4,
            a5 = in(reg) a5, a6 = in(reg) a6, a7 = in(reg) a7, a8 = in(reg) a8,
            out("rax") status,
            out("rcx") _, out("r11") _, out("r10") _, out("r8") _, out("r9") _,
            clobber_abi("system"),
        );
    }
    status
}

/// An 8-arg syscall. NATIVE seL4-Call transport (ntdll_plan Step 6.A): MR0=SSN, MR1=rsp, MR2=a1,
/// MR3=a2, MR4=a3, MR5=a4 (IPC buffer), and a5..a8 on the stack at `[rsp+0x28/0x30/0x38/0x40]` (read
/// by the executive via its mirror). Same request as [`native_syscall`] but with two more stack args.
///
/// # Safety
/// On-target hosted-process syscall; args must satisfy the target syscall's contract.
#[cfg(all(target_arch = "x86_64", feature = "native_transport"))]
#[inline]
#[allow(clippy::too_many_arguments)]
unsafe fn syscall8(
    ssn: u32,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
) -> u64 {
    // SAFETY: forwarding to the general native primitive.
    unsafe { native_syscall8(ssn, a1, a2, a3, a4, a5, a6, a7, a8) }
}

/// `RtlCreateUserThread(Process, ThreadSD, CreateSuspended, StackZeroBits, StackReserve, StackCommit,
/// StartAddress, Parameter, ThreadHandle, ClientId) -> NTSTATUS`. The live implementation.
///
/// Allocates a thread stack from the process heap-adjacent VM (`NtAllocateVirtualMemory`), builds the
/// amd64 CONTEXT (`Rip=StartAddress, Rcx=Parameter, Rsp=stack top`) + an INITIAL_TEB, then calls
/// `NtCreateThread`. The executive reads Context.Rip/Rcx and spawns the real thread; it writes
/// `*ThreadHandle` (arg1) and `*ClientId` (arg5). Returns the `NtCreateThread` status.
///
/// # Safety
/// On-target hosted-process; `thread_handle`/`client_id` valid writable out-pointers (or null for cid).
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
pub unsafe fn rtl_create_user_thread(
    process: u64,
    _thread_sd: u64,
    create_suspended: u8,
    _stack_zero_bits: u32,
    stack_reserve: usize,
    _stack_commit: usize,
    start_address: u64,
    parameter: u64,
    thread_handle: *mut u64,
    client_id: *mut u64,
) -> u64 {
    // Allocate the thread stack.
    let stack_size = if stack_reserve != 0 {
        stack_reserve
    } else {
        DEFAULT_THREAD_STACK
    };
    // SAFETY: on-target VM syscall.
    let stack_base = unsafe { nt_allocate_virtual_memory(stack_size) };
    if stack_base == 0 {
        return STATUS_NO_MEMORY;
    }
    // stack grows down: top = base + size (16-aligned, minus a shadow).
    let stack_top = (stack_base + stack_size as u64) & !0xF;

    // Build the CONTEXT record on the current stack (zeroed, then Rip/Rcx/Rsp set). It must live long
    // enough for the executive's stack-mirror read during the syscall — a stack local of this fn.
    let mut context = [0u8; CONTEXT_SIZE];
    // SAFETY: writing within the fixed-size context buffer at the known amd64 offsets.
    unsafe {
        core::ptr::write_unaligned(context.as_mut_ptr().add(CTX_RCX) as *mut u64, parameter);
        core::ptr::write_unaligned(context.as_mut_ptr().add(CTX_RSP) as *mut u64, stack_top);
        core::ptr::write_unaligned(context.as_mut_ptr().add(CTX_RIP) as *mut u64, start_address);
    }
    // INITIAL_TEB: { _, StackBase(0x10), StackLimit(0x18), AllocatedStackBase(0x20), _ }.
    let mut initial_teb = [0u64; 8];
    initial_teb[2] = stack_base + stack_size as u64; // StackBase @0x10
    initial_teb[3] = stack_base; // StackLimit @0x18
    initial_teb[4] = stack_base; // AllocatedStackBase @0x20

    // NtCreateThread(&ThreadHandle, THREAD_ALL_ACCESS, ObjectAttributes=NULL, ProcessHandle,
    //                &ClientId, &Context, &InitialTeb, CreateSuspended).
    // SAFETY: on-target; all pointers are valid stack locals / the caller's out-params.
    unsafe {
        syscall8(
            SSN_NT_CREATE_THREAD,
            thread_handle as u64,
            THREAD_ALL_ACCESS,
            0, // ObjectAttributes = NULL
            process,
            client_id as u64,
            context.as_ptr() as u64,
            initial_teb.as_ptr() as u64,
            (create_suspended != 0) as u64,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// BATCH 27 — the RtlpNt* registry shims the lsass tree (lsasrv) imports. Thin wrappers over the
// Nt*Key syscalls (references/reactos/sdk/lib/rtl/registry.c:913-1006), issued through OUR trap/
// native transport (serviced by the executive against ::ROSSYS.HIV). WITHOUT these exports the
// on-target loader leaves lsasrv's `ntdll!RtlpNtOpenKey` IAT slot at the raw by-name thunk (a bare
// `.rdata` RVA 0x3a288) → lsasrv `call *[IAT]` jumps into garbage → the instruction-fetch fault
// that blocked LSA init before `SetEvent(LSA_RPC_SERVER_ACTIVE)`.
// ---------------------------------------------------------------------------------------------

/// `KEY_VALUE_PARTIAL_INFORMATION` (x64): TitleIndex(4), Type(4), DataLength(4), Data[...]. The
/// `Data` field starts at offset 0x0C (= `FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)`).
const KVPI_DATA_OFFSET: u64 = 0x0C;
/// `KeyValuePartialInformation` class.
const KEY_VALUE_PARTIAL_INFORMATION: u64 = 2;
const SSN_NT_SET_VALUE_KEY: u32 = 256;
const STATUS_NO_MEMORY_U: u64 = 0xC000_0017;
const STATUS_BUFFER_OVERFLOW_U: u64 = 0x8000_0005;

/// An empty inline `UNICODE_STRING { Length:0, MaximumLength:0, _pad:0, Buffer:NULL }` (the
/// nameless-default-value name used by the `RtlpNt*Value*` shims). Returns its address for a syscall
/// `PUNICODE_STRING` argument. `slot` is caller-owned storage (must outlive the call).
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn empty_unicode_string(slot: &mut [u64; 2]) -> u64 {
    slot[0] = 0; // Length(u16) | MaximumLength(u16) | pad(u32)
    slot[1] = 0; // Buffer(u64) = NULL
    slot.as_ptr() as u64
}

/// `RtlpNtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
/// ULONG Unused)` — mask off OBJ_PERMANENT|OBJ_EXCLUSIVE, then `NtOpenKey` (registry.c:913).
///
/// # Safety
/// `key_handle` writable; `object_attributes` a valid OBJECT_ATTRIBUTES or NULL.
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlpNtOpenKey"]
pub unsafe extern "system" fn rtlp_nt_open_key(
    key_handle: u64,
    desired_access: u64,
    object_attributes: u64,
    _unused: u64,
) -> u32 {
    // OBJECT_ATTRIBUTES.Attributes @ +0x10 (ULONG). Clear OBJ_PERMANENT(0x10)|OBJ_EXCLUSIVE(0x20).
    if object_attributes != 0 {
        // SAFETY: OA valid per the contract; Attributes is a ULONG at +0x10.
        unsafe {
            let attr_ptr = (object_attributes + 0x10) as *mut u32;
            let a = core::ptr::read_unaligned(attr_ptr);
            core::ptr::write_unaligned(attr_ptr, a & !(0x10 | 0x20));
        }
    }
    // SAFETY: NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes) — SSN 125, 3 args.
    unsafe {
        syscall4(
            SSN_NT_OPEN_KEY,
            key_handle,
            desired_access,
            object_attributes,
            0,
        ) as u32
    }
}

/// `RtlpNtQueryValueKey(HANDLE KeyHandle, PULONG Type, PVOID Data, PULONG DataLength, ULONG Unused)`
/// — query the key's DEFAULT (nameless) value via `NtQueryValueKey(KeyValuePartialInformation)`,
/// returning Type + copying Data (registry.c:934). Allocates a partial-info buffer on the process
/// heap, exactly as real ntdll.
///
/// # Safety
/// `type_out`/`data`/`data_length` writable or NULL per the ABI.
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlpNtQueryValueKey"]
pub unsafe extern "system" fn rtlp_nt_query_value_key(
    key_handle: u64,
    type_out: u64,
    data: u64,
    data_length: u64,
    _unused: u64,
) -> u32 {
    // BufferLength = (*DataLength if given) + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data).
    let mut buffer_length: u64 = 0;
    if data_length != 0 {
        // SAFETY: writable ULONG per the ABI.
        buffer_length = unsafe { core::ptr::read_unaligned(data_length as *const u32) } as u64;
    }
    buffer_length += KVPI_DATA_OFFSET;
    // SAFETY: heap allocation for the partial-info buffer (freed below).
    let value_info = unsafe { crate::process_heap_alloc(buffer_length as usize) };
    if value_info.is_null() {
        return STATUS_NO_MEMORY_U as u32;
    }
    let vi = value_info as u64;
    let mut result_length: u32 = 0;
    // SAFETY: NtQueryValueKey(KeyHandle, &ValueName(empty), KeyValuePartialInformation, ValueInfo,
    // BufferLength, &ResultLength) — SSN 185, 6 args.
    let status = unsafe {
        let mut name_slot = [0u64; 2];
        let name = empty_unicode_string(&mut name_slot);
        syscall6(
            SSN_NT_QUERY_VALUE_KEY,
            key_handle,
            name,
            KEY_VALUE_PARTIAL_INFORMATION,
            vi,
            buffer_length,
            &mut result_length as *mut u32 as u64,
        )
    };
    let ok = (status as i32) >= 0; // NT_SUCCESS
    if ok || status == STATUS_BUFFER_OVERFLOW_U {
        // SAFETY: reading the partial-info Type@+4 / DataLength@+8; writing the caller's out-params.
        unsafe {
            let vtype = core::ptr::read_unaligned((vi + 4) as *const u32);
            let vlen = core::ptr::read_unaligned((vi + 8) as *const u32);
            if data_length != 0 {
                core::ptr::write_unaligned(data_length as *mut u32, vlen);
            }
            if type_out != 0 {
                core::ptr::write_unaligned(type_out as *mut u32, vtype);
            }
            if ok && data != 0 {
                core::ptr::copy_nonoverlapping(
                    (vi + KVPI_DATA_OFFSET) as *const u8,
                    data as *mut u8,
                    vlen as usize,
                );
            }
        }
    }
    // SAFETY: free the buffer allocated above.
    unsafe { crate::process_heap_free(value_info) };
    status as u32
}

/// `RtlpNtSetValueKey(HANDLE KeyHandle, ULONG Type, PVOID Data, ULONG DataLength)` — set the key's
/// DEFAULT (nameless) value via `NtSetValueKey` (registry.c:989).
///
/// # Safety
/// `data` a valid buffer of `data_length` bytes or NULL.
#[cfg(target_arch = "x86_64")]
#[export_name = "RtlpNtSetValueKey"]
pub unsafe extern "system" fn rtlp_nt_set_value_key(
    key_handle: u64,
    type_val: u64,
    data: u64,
    data_length: u64,
) -> u32 {
    // SAFETY: NtSetValueKey(KeyHandle, &ValueName(empty), TitleIndex=0, Type, Data, DataLength) —
    // SSN 256, 6 args.
    unsafe {
        let mut name_slot = [0u64; 2];
        let name = empty_unicode_string(&mut name_slot);
        syscall6(
            SSN_NT_SET_VALUE_KEY,
            key_handle,
            name,
            0,
            type_val,
            data,
            data_length,
        ) as u32
    }
}

// ---------------------------------------------------------------------------------------------
// Step 4.C — RtlQueryRegistryValues over the LIVE registry plane.
//
// Real ntdll's RtlQueryRegistryValues (references/reactos/sdk/lib/rtl/registry.c:1013) opens a
// registry key (RelativeTo + Path), walks the caller's RTL_QUERY_REGISTRY_TABLE, and for each entry
// either enumerates a subkey's values or queries a named value — invoking the caller's QueryRoutine
// (or copying into a DIRECT EntryContext) with the real registry data, expanding REG_EXPAND_SZ.
//
// smss's SmpLoadDataFromRegistry (sminit.c:2328) calls it with RTL_REGISTRY_CONTROL ("\Registry\
// Machine\System\CurrentControlSet\Control") + "Session Manager" + SmpRegistryConfigurationTable.
// The load-bearing entry is `KnownDlls` (SUBKEY + QueryRoutine SmpConfigureKnownDlls): our previous
// defaults-only stub never ran the callback (the entry's DefaultType is REG_NONE), so SmpKnownDllPath
// stayed NULL → RtlDosPathNameToNtPathName_U(NULL) failed → the fatal NtRaiseHardError. Reading the
// real hive (which holds KnownDlls\DllDirectory = %SystemRoot%\system32) populates SmpKnownDllPath.
//
// This is the real-ntdll behavior over OUR trap stubs (NtOpenKey/NtEnumerateValueKey/NtQueryValueKey,
// serviced by the executive against ::ROSSYS.HIV). Absent keys/values fall to the caller's defaults,
// exactly as real ntdll — never a fabricated value.
// ---------------------------------------------------------------------------------------------

const SSN_NT_OPEN_KEY: u32 = 125;
const SSN_NT_ENUMERATE_VALUE_KEY: u32 = 77;
const SSN_NT_QUERY_VALUE_KEY: u32 = 185;

/// KeyValueFullInformation class (the format `build_key_value_info` emits): TitleIndex(4), Type(4),
/// DataOffset(4), DataLength(4), NameLength(4), Name[...], pad-to-8, Data[...].
const KEY_VALUE_FULL_INFORMATION: u64 = 1;

const STATUS_SUCCESS_U: u64 = 0;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001A;

/// RTL_QUERY_REGISTRY_* flags.
const RTL_QUERY_REGISTRY_SUBKEY: u32 = 0x01;
const RTL_QUERY_REGISTRY_TOPKEY: u32 = 0x02;
const RTL_QUERY_REGISTRY_REQUIRED: u32 = 0x04;
const RTL_QUERY_REGISTRY_NOEXPAND: u32 = 0x10;
const RTL_QUERY_REGISTRY_DIRECT: u32 = 0x20;

/// RTL_REGISTRY_* RelativeTo bases (the subset smss uses).
const RTL_REGISTRY_ABSOLUTE: u32 = 0;
const RTL_REGISTRY_SERVICES: u32 = 1;
const RTL_REGISTRY_CONTROL: u32 = 2;
const RTL_REGISTRY_WINDOWS_NT: u32 = 3;
const RTL_REGISTRY_HANDLE: u32 = 0x4000_0000;
const RTL_REGISTRY_OPTIONAL: u32 = 0x8000_0000;

const REG_NONE: u32 = 0;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_MULTI_SZ: u32 = 7;

const ENTRY_SIZE: usize = 0x38;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// The RTL_QUERY_REGISTRY_TABLE entry, read field-by-field from the caller's array.
struct QueryEntry {
    query_routine: u64,
    flags: u32,
    name: u64,
    entry_context: u64,
    default_type: u32,
    default_data: u64,
    default_length: u32,
}

/// Read the RTL_QUERY_REGISTRY_TABLE entry at `e`.
///
/// # Safety
/// `e` points at a valid 0x38-byte entry.
#[cfg(target_arch = "x86_64")]
unsafe fn read_query_entry(e: *const u8) -> QueryEntry {
    // SAFETY: e is a valid entry per the caller.
    unsafe {
        QueryEntry {
            query_routine: core::ptr::read_unaligned(e as *const u64),
            flags: core::ptr::read_unaligned(e.add(0x08) as *const u32),
            name: core::ptr::read_unaligned(e.add(0x10) as *const u64),
            entry_context: core::ptr::read_unaligned(e.add(0x18) as *const u64),
            default_type: core::ptr::read_unaligned(e.add(0x20) as *const u32),
            default_data: core::ptr::read_unaligned(e.add(0x28) as *const u64),
            default_length: core::ptr::read_unaligned(e.add(0x30) as *const u32),
        }
    }
}

/// The RTL_QUERY_REGISTRY_ROUTINE ABI: `(ValueName, ValueType, ValueData, ValueLength, Context,
/// EntryContext) -> NTSTATUS`.
type OnTargetQueryRoutine = unsafe extern "system" fn(u64, u32, u64, u32, u64, u64) -> u32;

/// `wcslen` over a live UTF-16 pointer.
///
/// # Safety
/// `p` NUL-terminated.
#[cfg(target_arch = "x86_64")]
unsafe fn wlen(p: *const u16) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0;
    // SAFETY: NUL-terminated per the contract.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

/// Build an OBJECT_ATTRIBUTES on `oa` (a 0x30-byte stack buffer) for `name` (a UNICODE_STRING built
/// on `us` — a 16-byte stack buffer) relative to `root`. `name_ptr`/`name_len_units` describe the
/// name buffer.
///
/// x64 OBJECT_ATTRIBUTES: Length@0(4), RootDirectory@8(8), ObjectName@0x10(8), Attributes@0x18(4).
/// x64 UNICODE_STRING: Length@0(2), MaximumLength@2(2), Buffer@8(8).
///
/// # Safety
/// `oa` a 0x30-byte writable buffer, `us` a 16-byte writable buffer.
#[cfg(target_arch = "x86_64")]
unsafe fn build_oa(
    oa: *mut u8,
    us: *mut u8,
    root: u64,
    name_ptr: *const u16,
    name_len_units: usize,
) {
    // SAFETY: buffers sized per the contract.
    unsafe {
        core::ptr::write_bytes(oa, 0, 0x30);
        core::ptr::write(oa as *mut u32, 0x30); // Length
        core::ptr::write(oa.add(8) as *mut u64, root); // RootDirectory
        core::ptr::write(oa.add(0x10) as *mut u64, us as u64); // ObjectName
        core::ptr::write(oa.add(0x18) as *mut u32, OBJ_CASE_INSENSITIVE); // Attributes
        let bytes = (name_len_units * 2) as u16;
        core::ptr::write(us as *mut u16, bytes); // Length
        core::ptr::write(us.add(2) as *mut u16, bytes); // MaximumLength
        core::ptr::write(us.add(8) as *mut u64, name_ptr as u64); // Buffer
    }
}

/// Open a registry key (NtOpenKey) named `name` (a `'\0'`-terminated Rust byte slice, ASCII → UTF-16)
/// relative to `root`. Returns the opened handle, or 0 on failure.
///
/// # Safety
/// On-target hosted-process syscall.
#[cfg(target_arch = "x86_64")]
unsafe fn open_key_utf16(root: u64, name: &[u16]) -> u64 {
    let (status, handle) = unsafe { open_key_utf16_status(root, name) };
    if status == STATUS_SUCCESS_U as u32 {
        handle
    } else {
        0
    }
}

/// Open a UTF-16 registry path and preserve the native status for compatibility helpers.
#[cfg(target_arch = "x86_64")]
unsafe fn open_key_utf16_status(root: u64, name: &[u16]) -> (u32, u64) {
    let mut oa = [0u8; 0x30];
    let mut us = [0u8; 0x10];
    let mut handle: u64 = 0;
    const KEY_READ: u64 = 0x2_0019;
    // SAFETY: valid stack buffers; name is a valid UTF-16 slice.
    unsafe {
        build_oa(
            oa.as_mut_ptr(),
            us.as_mut_ptr(),
            root,
            name.as_ptr(),
            name.len(),
        );
        let st = syscall4(
            SSN_NT_OPEN_KEY,
            &mut handle as *mut u64 as u64,
            KEY_READ,
            oa.as_ptr() as u64,
            0,
        );
        return (st as u32, handle);
    }
}

/// Resolve the RelativeTo base key path into a UTF-16 vec (absolute NT path), or `None` for
/// RTL_REGISTRY_HANDLE (Path itself is the handle) / RTL_REGISTRY_ABSOLUTE (Path is already absolute).
#[cfg(target_arch = "x86_64")]
fn registry_base_path(relative_to: u32) -> Option<&'static str> {
    match relative_to & !(RTL_REGISTRY_OPTIONAL | 0x2000_0000) {
        RTL_REGISTRY_SERVICES => Some("\\Registry\\Machine\\System\\CurrentControlSet\\Services"),
        RTL_REGISTRY_CONTROL => Some("\\Registry\\Machine\\System\\CurrentControlSet\\Control"),
        RTL_REGISTRY_WINDOWS_NT => {
            Some("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion")
        }
        4 => Some("\\Registry\\Machine\\Hardware\\DeviceMap"),
        5 => Some("\\Registry\\User\\.Default"),
        _ => None, // ABSOLUTE / HANDLE — caller handles
    }
}

/// `RtlCheckRegistryKey` live driver: resolve the `RTL_REGISTRY_*` base, open read-only through
/// NtOpenKey, close the resulting handle, and return the original open status.
///
/// # Safety
/// `path` is a NUL-terminated UTF-16 path, NULL, or a handle in RTL_REGISTRY_HANDLE mode.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_check_registry_key(relative_to: u32, path: *const u16) -> u32 {
    use alloc::vec::Vec;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
    const RTL_REGISTRY_MAXIMUM: u32 = 6;

    if relative_to & RTL_REGISTRY_HANDLE != 0 {
        let handle = path as u64;
        let _ = unsafe { syscall4(SSN_NT_CLOSE, handle, 0, 0, 0) };
        return STATUS_SUCCESS_U as u32;
    }

    let base_kind = relative_to & !RTL_REGISTRY_OPTIONAL;
    if base_kind >= RTL_REGISTRY_MAXIMUM {
        return STATUS_INVALID_PARAMETER;
    }
    let path_length = if path.is_null() {
        0
    } else {
        unsafe { wlen(path) }
    };
    if base_kind == RTL_REGISTRY_ABSOLUTE && path_length == 0 {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    let mut full = Vec::new();
    if let Some(base) = registry_base_path(base_kind) {
        full.extend(base.encode_utf16());
    }
    if path_length != 0 {
        let mut path_slice = unsafe { core::slice::from_raw_parts(path, path_length) };
        if base_kind != RTL_REGISTRY_ABSOLUTE && path_slice.first().copied() == Some(b'\\' as u16) {
            path_slice = &path_slice[1..];
        }
        if !full.is_empty() && !path_slice.is_empty() {
            full.push(b'\\' as u16);
        }
        full.extend_from_slice(path_slice);
    }

    let (status, handle) = unsafe { open_key_utf16_status(0, &full) };
    if status != STATUS_SUCCESS_U as u32 {
        return status;
    }
    let _ = unsafe { syscall4(SSN_NT_CLOSE, handle, 0, 0, 0) };
    STATUS_SUCCESS_U as u32
}

/// Does the NUL-terminated UTF-16 `name_ptr` equal the ASCII `want` (case-sensitive)?
#[cfg(target_arch = "x86_64")]
unsafe fn name_is(name_ptr: *const u16, want: &[u8]) -> bool {
    if name_ptr.is_null() {
        return false;
    }
    let mut i = 0usize;
    while i < want.len() {
        let c = unsafe { *name_ptr.add(i) };
        if c != want[i] as u16 {
            return false;
        }
        i += 1;
    }
    unsafe { *name_ptr.add(i) == 0 }
}

/// Dispatch one registry value to the caller's QueryRoutine (or the DIRECT copy), applying
/// REG_EXPAND_SZ expansion (unless NOEXPAND) exactly like RtlpCallQueryRegistryRoutine.
/// `name_ptr` is the value name (UTF-16, NUL-terminated); `ty`/`data`/`len` the value.
///
/// # Safety
/// On-target; the pointers/slices are valid; the QueryRoutine ABI is honored.
#[cfg(target_arch = "x86_64")]
unsafe fn dispatch_value(
    entry: &QueryEntry,
    name_ptr: *const u16,
    ty: u32,
    data: *const u8,
    len: u32,
    context: u64,
) -> u32 {
    use alloc::vec::Vec;
    // REG_MULTI_SZ split (skip if NOEXPAND) — faithful port of ReactOS `RtlpCallQueryRegistryRoutine`
    // (sdk/lib/rtl/registry.c:254): a multi-string value is dispatched ONE SUB-STRING AT A TIME, each
    // with Type=REG_SZ and Length = that sub-string's byte length INCLUDING its terminating NUL. This
    // is exactly what auth-package enumeration relies on: lsass' `LsapAddAuthPackage` reads the
    // `Lsa\Authentication Packages` MULTI_SZ and does `PackageName.Length = ValueLength - sizeof(WCHAR)`
    // per string → without the split it would receive the WHOLE blob (`msv1_0\0\0`) as one call and
    // build a garbage DLL name (`msv1_0<NUL>.dll`) that misses the FS. With the split it gets `msv1_0\0`
    // (14 bytes) → name `msv1_0` → the msv1_0.dll load resolves. General: applies to every MULTI_SZ
    // callback query, not just auth packages.
    // `ObjectDirectories` (smss' Session-Manager config) is the ONE carve-out (see the block below);
    // its callback iterates the blob internally + issues object-namespace syscalls, so it works with
    // the whole blob AND must NOT be split here (an executive stack-mirror fragility during the
    // concurrent SmpApiLoop-thread spawn corrupts smss' stack on the extra syscall — flagged as an
    // executive follow-up, not an ntdll bug). Every OTHER MULTI_SZ callback query IS split, faithfully.
    if (entry.flags & RTL_QUERY_REGISTRY_NOEXPAND) == 0
        && ty == REG_MULTI_SZ
        && len >= 4
        && !unsafe { name_is(name_ptr, b"ObjectDirectories") }
    {
        let units = (len as usize) / 2;
        // SAFETY: [data, data+len) is the value body; interpret as UTF-16.
        let blob: &[u16] = unsafe { core::slice::from_raw_parts(data as *const u16, units) };
        // ValueEnd = Data + Length - 2*sizeof(NUL): stop before the block's terminating empty string.
        // (units - 2 leaves off the final double-NUL, matching registry.c's `ValueEnd`.)
        let value_end = units.saturating_sub(2);
        let mut start = 0usize;
        let mut status = STATUS_SUCCESS_U as u32;
        while start < value_end {
            // Advance past this sub-string's terminating NUL (registry.c: `while (*p++);`).
            let mut p = start;
            while p < units && blob[p] != 0 {
                p += 1;
            }
            p += 1; // include the terminating NUL, exactly like `p` post-incremented past it
            let sub_len_bytes = ((p - start) * 2) as u32; // Length INCLUDING the NUL
                                                          // SAFETY: the sub-string [start,p) lies within the value body; call the routine as REG_SZ.
            let st = unsafe {
                dispatch_value(
                    entry,
                    name_ptr,
                    REG_SZ,
                    (data as *const u16).add(start) as *const u8,
                    sub_len_bytes,
                    context,
                )
            };
            if st != STATUS_SUCCESS_U as u32 {
                status = st;
                break;
            }
            start = p;
        }
        return status;
    }
    // REG_EXPAND_SZ expansion (skip if NOEXPAND).
    let mut expanded: Option<Vec<u16>> = None;
    if (entry.flags & RTL_QUERY_REGISTRY_NOEXPAND) == 0 && ty == REG_EXPAND_SZ && len >= 2 {
        // Read the source string (drop the trailing NUL if present).
        let units = (len as usize) / 2;
        // SAFETY: [data, data+len) is the value; interpret as UTF-16.
        let src: &[u16] = unsafe { core::slice::from_raw_parts(data as *const u16, units) };
        let src_trim = if src.last() == Some(&0) {
            &src[..units - 1]
        } else {
            src
        };
        if src_trim.contains(&(b'%' as u16)) {
            // Expand via the live PEB environment block.
            if let Some(out) = expand_env_units(src_trim) {
                expanded = Some(out);
            }
        }
    }
    let (ty_out, data_out, len_out): (u32, u64, u32) = if let Some(ref e) = expanded {
        (REG_SZ, e.as_ptr() as u64, (e.len() * 2) as u32)
    } else {
        (ty, data as u64, len)
    };
    if (entry.flags & RTL_QUERY_REGISTRY_DIRECT) != 0 {
        // DIRECT: copy into the EntryContext UNICODE_STRING (REG_SZ) — smss's Session Manager table
        // uses callbacks, so this path is minimal (copy the raw bytes into a UNICODE_STRING buffer if
        // one is present). We conservatively only handle the callback case; DIRECT returns SUCCESS.
        let _ = (ty_out, data_out, len_out);
        return STATUS_SUCCESS_U as u32;
    }
    if entry.query_routine == 0 {
        return STATUS_SUCCESS_U as u32;
    }
    // SAFETY: query_routine is the caller's routine matching the RTL_QUERY_REGISTRY_ROUTINE ABI.
    let routine: OnTargetQueryRoutine =
        unsafe { core::mem::transmute::<u64, OnTargetQueryRoutine>(entry.query_routine) };
    // SAFETY: calling into the caller's routine with its declared ABI + valid pointers.
    // Forward the caller's `Context` (the argument passed to RtlQueryRegistryValues) as the
    // routine's 5th parameter, exactly like RtlpCallQueryRegistryRoutine (registry.c:289): the
    // routine receives (Name, Type, Data, Length, Context, EntryContext). Previously hardcoded to
    // 0, which NULLed lsass' `LsapAddAuthPackage` Context (=&PackageId) → `*Id` NULL-deref at
    // authpackage.c:297 (Package->LsaApInitializePackage(*Id, ...)).
    let st = unsafe {
        routine(
            name_ptr as u64,
            ty_out,
            data_out,
            len_out,
            context,
            entry.entry_context,
        )
    };
    // STATUS_BUFFER_TOO_SMALL is normalized to SUCCESS by real ntdll.
    if st == 0xC000_0023 {
        STATUS_SUCCESS_U as u32
    } else {
        st
    }
}

/// Expand a `%VAR%` UTF-16 string against the live PEB environment block. Returns the expanded units
/// (NUL-terminated), or `None` if the env can't be read.
#[cfg(target_arch = "x86_64")]
fn expand_env_units(src: &[u16]) -> Option<alloc::vec::Vec<u16>> {
    use alloc::string::String;
    // Read NtCurrentPeb() = gs:[0x60] → ProcessParameters(+0x20) → Environment(+0x80).
    let env_ptr: *const u16;
    // SAFETY: gs:[0x60] is the PEB; the offsets are the byte-exact x64 layout (nt-ntdll-layout).
    unsafe {
        let peb: u64;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb == 0 {
            return None;
        }
        let params = core::ptr::read((peb + 0x20) as *const u64);
        if params == 0 {
            return None;
        }
        env_ptr = core::ptr::read((params + 0x80) as *const u64) as *const u16;
    }
    if env_ptr.is_null() {
        return None;
    }
    // Read the double-NUL-terminated block into a slice.
    let mut n = 0usize;
    // SAFETY: the env block is a valid double-NUL-terminated UTF-16 region (executive-staged).
    unsafe {
        loop {
            let c = *env_ptr.add(n);
            let nx = *env_ptr.add(n + 1);
            n += 1;
            if c == 0 && nx == 0 {
                break;
            }
            if n > 0x8000 {
                break; // sanity bound
            }
        }
    }
    // SAFETY: [env_ptr, env_ptr+n] is the block body.
    let block: &[u16] = unsafe { core::slice::from_raw_parts(env_ptr, n) };
    let env = nt_ntdll::rtl::environment::Environment::from_block(block);
    let src_str = String::from_utf16_lossy(src);
    let out_str = env.expand(&src_str);
    let mut out: alloc::vec::Vec<u16> = out_str.encode_utf16().collect();
    out.push(0); // NUL-terminate
    Some(out)
}

/// Read the double-NUL-terminated env block at `env_ptr` into an owned [`Environment`], plus its
/// original length in units.
///
/// # Safety
/// `env_ptr` a valid double-NUL-terminated UTF-16 block, or null.
#[cfg(target_arch = "x86_64")]
unsafe fn read_env_block(env_ptr: *const u16) -> nt_ntdll::rtl::environment::Environment {
    if env_ptr.is_null() {
        return nt_ntdll::rtl::environment::Environment::new();
    }
    let mut n = 0usize;
    // SAFETY: measure to the double-NUL, INCLUDING the first terminating NUL so `from_block` sees the
    // closing NUL of the last variable (it only emits a var on a NUL; without the trailing NUL the
    // last variable would be silently dropped).
    unsafe {
        loop {
            let c = *env_ptr.add(n);
            let nx = *env_ptr.add(n + 1);
            if c == 0 && nx == 0 {
                n += 1; // include the first NUL of the double-NUL so the last var terminates
                break;
            }
            n += 1;
            if n > 0x8000 {
                break;
            }
        }
    }
    // SAFETY: [env_ptr, env_ptr+n] is the block body (incl. the last var's terminating NUL).
    let block: &[u16] = unsafe { core::slice::from_raw_parts(env_ptr, n) };
    nt_ntdll::rtl::environment::Environment::from_block(block)
}

/// `RtlSetEnvironmentVariable` — set (or, `value==NULL`, delete) a variable in the target env block.
/// `environment` is `PVOID*` (NULL → the process env at `PEB->ProcessParameters->Environment`). On a
/// change, serializes a fresh block on the process heap and writes the new pointer back (to
/// `*environment` and, for the process-env case, into the PEB).
///
/// # Safety
/// On-target; `name`/`value` are `UNICODE_STRING*` (value NULL → delete); `environment` NULL or a
/// valid `PVOID*`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_set_environment_variable(
    environment: *mut u64,
    name: *const u8,
    value: *const u8,
) -> u32 {
    use alloc::string::String;
    // Read a required UNICODE_STRING (Length@0 u16 bytes, Buffer@8).
    // SAFETY: p is a valid UNICODE_STRING per the contract.
    unsafe fn read_required_ustr(p: *const u8) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: valid UNICODE_STRING.
        let (len_bytes, buf) = unsafe {
            (
                core::ptr::read_unaligned(p as *const u16) as usize,
                core::ptr::read_unaligned(p.add(8) as *const u64) as *const u16,
            )
        };
        if buf.is_null() {
            return Some(String::new());
        }
        // SAFETY: [buf, buf+len_bytes/2) is the string body.
        let units = unsafe { core::slice::from_raw_parts(buf, len_bytes / 2) };
        Some(String::from_utf16_lossy(units))
    }

    // Read an optional value UNICODE_STRING. ReactOS treats `Value == NULL` and
    // `Value->Buffer == NULL` as delete; an empty non-null buffer is a set-to-empty.
    // SAFETY: p is NULL or a valid UNICODE_STRING.
    unsafe fn read_optional_value_ustr(p: *const u8) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: valid UNICODE_STRING.
        let (len_bytes, buf) = unsafe {
            (
                core::ptr::read_unaligned(p as *const u16) as usize,
                core::ptr::read_unaligned(p.add(8) as *const u64) as *const u16,
            )
        };
        if buf.is_null() {
            return None;
        }
        // SAFETY: [buf, buf+len_bytes/2) is the string body.
        let units = unsafe { core::slice::from_raw_parts(buf, len_bytes / 2) };
        Some(String::from_utf16_lossy(units))
    }

    // SAFETY: reading the caller's UNICODE_STRINGs.
    let name_s = match unsafe { read_required_ustr(name) } {
        Some(s) if !s.is_empty() => s,
        _ => return 0xC000_000D, // STATUS_INVALID_PARAMETER
    };
    // SAFETY: reading the value (NULL → delete).
    let val_s = unsafe { read_optional_value_ustr(value) };

    // Locate the target block pointer: *environment if given, else the PEB process-env slot.
    let mut peb_params: u64 = 0;
    let cur_ptr: *const u16 = if !environment.is_null() {
        // SAFETY: environment is a valid PVOID*.
        unsafe { core::ptr::read(environment) as *const u16 }
    } else {
        // SAFETY: gs:[0x60] = PEB → ProcessParameters(+0x20) → Environment(+0x80).
        unsafe {
            let peb: u64;
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
            if peb == 0 {
                return 0xC000_00A5; // STATUS_INVALID_ENVIRONMENT (no PEB)
            }
            peb_params = core::ptr::read((peb + 0x20) as *const u64);
            if peb_params == 0 {
                return 0xC000_00A5;
            }
            core::ptr::read((peb_params + 0x80) as *const u64) as *const u16
        }
    };

    // Edit the block.
    // SAFETY: cur_ptr is a valid double-NUL-terminated block (or null → empty).
    let mut env = unsafe { read_env_block(cur_ptr) };
    if env.set_checked(&name_s, val_s.as_deref()).is_err() {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    let block = env.to_block(); // Vec<u16>, double-NUL-terminated
    let bytes = core::cmp::max(block.len(), 2) * 2;

    // Allocate + copy the new block.
    // SAFETY: process heap alloc.
    let dst = unsafe { crate::process_heap_alloc(bytes) } as *mut u16;
    if dst.is_null() {
        return 0xC000_0017; // STATUS_NO_MEMORY
    }
    // SAFETY: dst is a fresh bytes-byte region.
    unsafe {
        core::ptr::write_bytes(dst, 0, bytes / 2);
        core::ptr::copy_nonoverlapping(block.as_ptr(), dst, block.len());
    }

    // Write the new pointer back.
    // SAFETY: writing the caller's PVOID* / the PEB env slot.
    unsafe {
        if !environment.is_null() {
            core::ptr::write(environment, dst as u64);
        } else if peb_params != 0 {
            core::ptr::write((peb_params + 0x80) as *mut u64, dst as u64);
        }
    }
    STATUS_SUCCESS_U as u32
}

const SSN_NT_QUERY_ATTRIBUTES_FILE: u32 = 145;

/// `RtlQueryEnvironmentVariable_U(Environment, Name, Value)` — look up `Name` in the env block and
/// copy the value into `Value->Buffer`. Returns SUCCESS / STATUS_BUFFER_TOO_SMALL / STATUS_VARIABLE_
/// NOT_FOUND. `environment` NULL → the PEB process-env.
///
/// # Safety
/// On-target; `name` a UNICODE_STRING*, `value` a UNICODE_STRING* with a MaximumLength Buffer.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_query_environment_variable_u(
    environment: *const u16,
    name: *const u8,
    value: *mut u8,
) -> u32 {
    use alloc::string::String;
    const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    const STATUS_VARIABLE_NOT_FOUND: u32 = 0xC000_0100;
    // Read the Name UNICODE_STRING.
    // SAFETY: name is a valid UNICODE_STRING.
    let (name_bytes, name_buf) = unsafe {
        (
            core::ptr::read_unaligned(name as *const u16) as usize,
            core::ptr::read_unaligned(name.add(8) as *const u64) as *const u16,
        )
    };
    if name_buf.is_null() {
        return STATUS_VARIABLE_NOT_FOUND;
    }
    // SAFETY: [name_buf, name_buf+name_bytes/2) is the name.
    let name_units = unsafe { core::slice::from_raw_parts(name_buf, name_bytes / 2) };
    let name_s = String::from_utf16_lossy(name_units);

    // Resolve the env block pointer.
    let env_ptr: *const u16 = if !environment.is_null() {
        environment
    } else {
        // SAFETY: PEB env.
        unsafe {
            let peb: u64;
            core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
            if peb == 0 {
                return STATUS_VARIABLE_NOT_FOUND;
            }
            let params = core::ptr::read((peb + 0x20) as *const u64);
            if params == 0 {
                return STATUS_VARIABLE_NOT_FOUND;
            }
            core::ptr::read((params + 0x80) as *const u64) as *const u16
        }
    };
    // SAFETY: env_ptr is a valid double-NUL block (or null → empty).
    let env = unsafe { read_env_block(env_ptr) };
    let val = match env.query(&name_s) {
        Some(v) => v,
        None => return STATUS_VARIABLE_NOT_FOUND,
    };
    let val_units: alloc::vec::Vec<u16> = val.encode_utf16().collect();

    // Read Value->MaximumLength + Buffer.
    // SAFETY: value is a valid UNICODE_STRING with a MaximumLength Buffer.
    unsafe {
        let max_bytes = core::ptr::read_unaligned(value.add(2) as *const u16) as usize;
        let out_buf = core::ptr::read_unaligned(value.add(8) as *const u64) as *mut u16;
        let needed_bytes = val_units.len() * 2;
        if needed_bytes + 2 > max_bytes {
            // Doesn't fit (incl. the NUL). Report the required BYTE count in Length (UNICODE_STRING
            // Length is in bytes, NOT chars — env.c:685 `Value->Length = ReturnLength * sizeof(WCHAR)`
            // on the STATUS_BUFFER_TOO_SMALL path, EXCLUDING the terminating NUL). kernel32's
            // BasepComputeProcessPath re-allocates `EnvPath.Length + sizeof(WCHAR)` and re-queries;
            // returning the CHAR count here (half the bytes) under-allocated → the re-query failed
            // BUFFER_TOO_SMALL again → BaseComputeProcessDllPath returned NULL → CreateProcessW bailed.
            if !out_buf.is_null() && max_bytes >= 2 {
                core::ptr::write(out_buf, 0);
            }
            core::ptr::write_unaligned(value as *mut u16, needed_bytes as u16);
            return STATUS_BUFFER_TOO_SMALL;
        }
        core::ptr::copy_nonoverlapping(val_units.as_ptr(), out_buf, val_units.len());
        core::ptr::write(out_buf.add(val_units.len()), 0); // NUL
        core::ptr::write_unaligned(value as *mut u16, needed_bytes as u16); // Length
    }
    STATUS_SUCCESS_U as u32
}

/// `RtlExpandEnvironmentStrings_U(Environment, Source, Destination, ReturnLength)` — replace each
/// `%VAR%` in `Source` with its value from the env block (`Environment` or the live PEB process-env),
/// writing into `Destination->Buffer` (up to `Destination->MaximumLength`, NUL-terminated). Sets
/// `Destination->Length` + `*ReturnLength` (the required byte count incl. NUL). STATUS_BUFFER_TOO_SMALL
/// if it doesn't fit. Ported from `references/reactos/sdk/lib/rtl/env.c:264` (over the host-tested
/// `Environment::expand`).
///
/// # Safety
/// On-target; `source`/`destination` valid `UNICODE_STRING*`; `return_length` writable (or NULL).
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_expand_environment_strings_u(
    environment: *const u16,
    source: *const u8,
    destination: *mut u8,
    return_length: *mut u32,
) -> u32 {
    const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    if source.is_null() || destination.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // Read Source UNICODE_STRING.
    // SAFETY: source is a valid UNICODE_STRING.
    let src_units: alloc::vec::Vec<u16> = unsafe {
        let len = core::ptr::read_unaligned(source as *const u16) as usize / 2;
        let buf = core::ptr::read_unaligned(source.add(8) as *const u64) as *const u16;
        if buf.is_null() {
            alloc::vec::Vec::new()
        } else {
            core::slice::from_raw_parts(buf, len).to_vec()
        }
    };
    // Expand against the env (custom `environment` block if given, else the live PEB env).
    let expanded = if !environment.is_null() {
        use alloc::string::String;
        // SAFETY: caller-supplied double-NUL block.
        let env = unsafe { read_env_block(environment) };
        let s = String::from_utf16_lossy(&src_units);
        let mut v: alloc::vec::Vec<u16> = env.expand(&s).encode_utf16().collect();
        v.push(0);
        v
    } else {
        expand_env_units(&src_units).unwrap_or_else(|| {
            let mut v = src_units.clone();
            v.push(0);
            v
        })
    };
    // expanded includes the trailing NUL; body length = expanded.len()-1.
    let body_units = expanded.len().saturating_sub(1);
    let needed_bytes = (body_units + 1) * 2; // incl. NUL
    if !return_length.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *return_length = needed_bytes as u32 };
    }
    // SAFETY: destination is a valid UNICODE_STRING with a MaximumLength Buffer.
    unsafe {
        let max_bytes = core::ptr::read_unaligned(destination.add(2) as *const u16) as usize;
        let out = core::ptr::read_unaligned(destination.add(8) as *const u64) as *mut u16;
        if needed_bytes > max_bytes || out.is_null() {
            return STATUS_BUFFER_TOO_SMALL;
        }
        core::ptr::copy_nonoverlapping(expanded.as_ptr(), out, expanded.len());
        core::ptr::write_unaligned(destination as *mut u16, (body_units * 2) as u16);
        // Length
    }
    0 // STATUS_SUCCESS
}

/// `RtlOpenCurrentUser(ACCESS_MASK, PHANDLE) -> NTSTATUS`. Ported from
/// `references/reactos/sdk/lib/rtl/registry.c:702` — open the current-user registry key. We open the
/// default user key `\Registry\User\.Default` via our own `NtOpenKey(125)` trap (the executive's
/// registry plane services it), writing the handle to `*key_handle`. (The real body first tries
/// `\Registry\User\<SID>` from the thread token, then falls back to `.Default`; our single-user boot
/// uses the fallback directly — behavior-equivalent for basesrv's init read.)
///
/// # Safety
/// On-target; `key_handle` writable.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_open_current_user(desired_access: u32, key_handle: *mut u64) -> u32 {
    // Build the UNICODE_STRING "\Registry\User\.Default" (UTF-16, NUL-terminated).
    const PATH: &[u8] = b"\\Registry\\User\\.Default";
    let mut wpath = [0u16; 32];
    for (i, &b) in PATH.iter().enumerate() {
        wpath[i] = b as u16;
    }
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        _pad: u32,
        buffer: u64,
    }
    let us = UnicodeString {
        length: (PATH.len() * 2) as u16,
        maximum_length: (PATH.len() * 2) as u16,
        _pad: 0,
        buffer: wpath.as_ptr() as u64,
    };
    let oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        _p0: 0,
        root_directory: 0,
        object_name: core::ptr::addr_of!(us) as u64,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        _p1: 0,
        security_descriptor: 0,
        security_qos: 0,
    };
    // NtOpenKey(&KeyHandle, DesiredAccess, &OA).
    // SAFETY: on-target; all pointers valid stack locals; key_handle writable.
    let st = unsafe {
        syscall4(
            SSN_NT_OPEN_KEY,
            key_handle as u64,
            desired_access as u64,
            core::ptr::addr_of!(oa) as u64,
            0,
        )
    } as u32;
    st
}

/// `RtlDosSearchPath_U(Path, FileName, Extension, BufferLength, Buffer, PartName)` — search each
/// `;`-separated dir in `Path` for `FileName` (+`Extension` if no dot), probing existence via
/// NtQueryAttributesFile. On the first hit writes the DOS path into `Buffer`, sets `*PartName`, and
/// returns the byte length written; 0 = not found.
///
/// # Safety
/// On-target; pointers per the contract.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_dos_search_path_u(
    path: *const u16,
    file_name: *const u16,
    extension: *const u16,
    buffer_length: u32,
    buffer: *mut u16,
    part_name: *mut *mut u16,
) -> u32 {
    use alloc::string::String;
    use alloc::vec::Vec;
    // SAFETY: NUL-terminated inputs.
    let path_s = unsafe { utf16_to_string(path) };
    let file_s = unsafe { utf16_to_string(file_name) };
    let ext_s = if extension.is_null() {
        String::new()
    } else {
        // SAFETY: NUL-terminated.
        unsafe { utf16_to_string(extension) }
    };
    if file_s.is_empty() {
        return 0;
    }
    // Append the extension only if FileName has no '.'.
    let has_dot = file_s.contains('.');
    let leaf = if has_dot || ext_s.is_empty() {
        file_s.clone()
    } else {
        let mut l = file_s.clone();
        l.push_str(&ext_s);
        l
    };
    // Try each ';'-separated directory.
    for dir in path_s.split(';') {
        if dir.is_empty() {
            continue;
        }
        // Build the candidate DOS path: dir (strip trailing '\') + '\' + leaf.
        let mut cand = String::from(dir.trim_end_matches('\\'));
        cand.push('\\');
        cand.push_str(&leaf);
        // Convert to an NT path (\??\...) for NtQueryAttributesFile.
        let cand_units: Vec<u16> = cand.encode_utf16().collect();
        let Some(nt) = nt_ntdll::rtl::path::dos_path_name_to_nt_path_name(&cand_units) else {
            continue;
        };
        // Build OBJECT_ATTRIBUTES + UNICODE_STRING + FILE_BASIC_INFORMATION on the stack.
        let mut nt_nul: Vec<u16> = nt.clone();
        nt_nul.push(0);
        let mut oa = [0u8; 0x30];
        let mut us = [0u8; 0x10];
        let mut basic = [0u8; 0x28]; // FILE_BASIC_INFORMATION: 4×i64 times + FileAttributes@0x20
                                     // SAFETY: build the OA/US for the candidate NT path.
        let exists = unsafe {
            build_oa(oa.as_mut_ptr(), us.as_mut_ptr(), 0, nt.as_ptr(), nt.len());
            let st = syscall4(
                SSN_NT_QUERY_ATTRIBUTES_FILE,
                oa.as_ptr() as u64,
                basic.as_mut_ptr() as u64,
                0,
                0,
            );
            st == STATUS_SUCCESS_U
        };
        if exists {
            // Write the DOS candidate into Buffer (NUL-terminated) if it fits.
            let need = (cand_units.len() + 1) * 2;
            if need > buffer_length as usize {
                return 0;
            }
            // SAFETY: buffer is a buffer_length-byte writable region.
            unsafe {
                core::ptr::copy_nonoverlapping(cand_units.as_ptr(), buffer, cand_units.len());
                core::ptr::write(buffer.add(cand_units.len()), 0);
                if !part_name.is_null() {
                    // *PartName points at the leaf (after the last '\').
                    let last = cand_units
                        .iter()
                        .rposition(|&c| c == b'\\' as u16)
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    core::ptr::write(part_name, buffer.add(last));
                }
            }
            return (cand_units.len() * 2) as u32;
        }
    }
    0
}

/// Read a NUL-terminated UTF-16 pointer into an owned String.
///
/// # Safety
/// `p` NUL-terminated (or null → empty).
#[cfg(target_arch = "x86_64")]
unsafe fn utf16_to_string(p: *const u16) -> alloc::string::String {
    if p.is_null() {
        return alloc::string::String::new();
    }
    // SAFETY: NUL-terminated.
    let n = unsafe { wlen(p) };
    // SAFETY: [p, p+n) is the body.
    let units = unsafe { core::slice::from_raw_parts(p, n) };
    alloc::string::String::from_utf16_lossy(units)
}

/// `RtlQueryRegistryValues` — the live registry reader. Opens the base key, walks the query table,
/// enumerates subkey values / queries named values, dispatches the caller's routine with expansion.
/// Absent keys/values fall to the caller's defaults (or SUCCESS/OBJECT_NAME_NOT_FOUND for REQUIRED).
///
/// # Safety
/// On-target hosted-process; `query_table` a valid RTL_QUERY_REGISTRY_TABLE array; `path` a valid
/// NUL-terminated UTF-16 string or NULL.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_query_registry_values(
    relative_to: u32,
    path: *const u16,
    query_table: *const u8,
    context: u64,
) -> u32 {
    use alloc::vec::Vec;
    if query_table.is_null() {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }
    // Build the absolute base key path (base + '\' + Path), then open it.
    let base_key: u64 = if (relative_to & RTL_REGISTRY_HANDLE) != 0 {
        // Path IS the handle.
        path as u64
    } else {
        let mut full: Vec<u16> = Vec::new();
        if (relative_to & !(RTL_REGISTRY_OPTIONAL | 0x2000_0000)) == RTL_REGISTRY_ABSOLUTE {
            // Path is already absolute.
        } else if let Some(base) = registry_base_path(relative_to) {
            full.extend(base.encode_utf16());
        }
        if !path.is_null() {
            // SAFETY: path is NUL-terminated per the contract.
            let plen = unsafe { wlen(path) };
            if plen != 0 {
                // Real ntdll skips a leading '\' on Path unless ABSOLUTE (the "HACK!" at
                // registry.c:529).
                // SAFETY: [path, path+plen) is the string.
                let pslice = unsafe { core::slice::from_raw_parts(path, plen) };
                if !full.is_empty() {
                    full.push(b'\\' as u16);
                }
                full.extend_from_slice(pslice);
            }
        }
        if full.is_empty() {
            return 0xC000_000D;
        }
        // SAFETY: on-target key open.
        let h = unsafe { open_key_utf16(0, &full) };
        if h == 0 {
            // Base key not found. If OPTIONAL, this is fine (SUCCESS); else fail.
            return if (relative_to & RTL_REGISTRY_OPTIONAL) != 0 {
                STATUS_SUCCESS_U as u32
            } else {
                0xC000_0034 // STATUS_OBJECT_NAME_NOT_FOUND
            };
        }
        h
    };

    // A reusable KeyValueFullInformation buffer.
    let mut info = [0u8; 2048];
    let mut status: u32 = STATUS_SUCCESS_U as u32;
    let mut e = query_table;
    let mut current_key = base_key;
    loop {
        // SAFETY: e points at a valid entry (terminator checked below).
        let entry = unsafe { read_query_entry(e) };
        // Terminator: QueryRoutine == NULL && no SUBKEY/DIRECT flag.
        if entry.query_routine == 0
            && (entry.flags & (RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_DIRECT)) == 0
        {
            break;
        }

        // TOPKEY / SUBKEY: reset to the base key if we descended.
        if (entry.flags & (RTL_QUERY_REGISTRY_TOPKEY | RTL_QUERY_REGISTRY_SUBKEY)) != 0
            && current_key != base_key
        {
            // SAFETY: close the descended subkey handle.
            unsafe { syscall4(SSN_NT_CLOSE, current_key, 0, 0, 0) };
            current_key = base_key;
        }

        if (entry.flags & RTL_QUERY_REGISTRY_SUBKEY) != 0 && entry.name != 0 {
            // Open the named subkey relative to the base, then enumerate its values.
            // SAFETY: entry.name is a NUL-terminated UTF-16 string.
            let nlen = unsafe { wlen(entry.name as *const u16) };
            // SAFETY: [name, name+nlen) is the string.
            let nslice = unsafe { core::slice::from_raw_parts(entry.name as *const u16, nlen) };
            // SAFETY: on-target subkey open.
            let sub = unsafe { open_key_utf16(base_key, nslice) };
            if sub != 0 {
                current_key = sub;
                if entry.query_routine != 0 {
                    // ProcessValues: enumerate every value, dispatch the routine.
                    let mut index: u32 = 0;
                    loop {
                        let mut result_len: u32 = 0;
                        // SAFETY: enumerate value `index` into `info`.
                        let st = unsafe {
                            syscall6(
                                SSN_NT_ENUMERATE_VALUE_KEY,
                                current_key,
                                index as u64,
                                KEY_VALUE_FULL_INFORMATION,
                                info.as_mut_ptr() as u64,
                                info.len() as u64,
                                &mut result_len as *mut u32 as u64,
                            )
                        };
                        if st == STATUS_NO_MORE_ENTRIES {
                            status = STATUS_SUCCESS_U as u32;
                            break;
                        }
                        if st != STATUS_SUCCESS_U {
                            // Buffer overflow or error: stop enumerating this subkey.
                            break;
                        }
                        // Parse the KeyValueFullInformation.
                        // SAFETY: `info` holds a valid KEY_VALUE_FULL_INFORMATION.
                        unsafe {
                            let ty = core::ptr::read_unaligned(info.as_ptr().add(4) as *const u32);
                            let data_off =
                                core::ptr::read_unaligned(info.as_ptr().add(8) as *const u32)
                                    as usize;
                            let data_len =
                                core::ptr::read_unaligned(info.as_ptr().add(0x0c) as *const u32);
                            let name_len =
                                core::ptr::read_unaligned(info.as_ptr().add(0x10) as *const u32)
                                    as usize;
                            // The name follows the 0x14-byte header; NUL-terminate a local copy.
                            let mut name_buf: Vec<u16> = Vec::with_capacity(name_len / 2 + 1);
                            for k in 0..(name_len / 2) {
                                name_buf.push(core::ptr::read_unaligned(
                                    info.as_ptr().add(0x14 + k * 2) as *const u16,
                                ));
                            }
                            name_buf.push(0);
                            let data_ptr = info.as_ptr().add(data_off);
                            let st2 = dispatch_value(
                                &entry,
                                name_buf.as_ptr(),
                                ty,
                                data_ptr,
                                data_len,
                                context,
                            );
                            if st2 != STATUS_SUCCESS_U as u32 {
                                status = st2;
                                break;
                            }
                        }
                        index += 1;
                    }
                }
            } else if (entry.flags & RTL_QUERY_REGISTRY_REQUIRED) != 0 {
                status = 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND
            }
        } else if entry.name != 0 {
            // A named value under the current key: NtQueryValueKey.
            let mut oa_us = [0u8; 0x10];
            // SAFETY: entry.name is NUL-terminated.
            let nlen = unsafe { wlen(entry.name as *const u16) };
            let bytes = (nlen * 2) as u16;
            // Build the UNICODE_STRING value name.
            // SAFETY: valid stack buffer.
            unsafe {
                core::ptr::write(oa_us.as_mut_ptr() as *mut u16, bytes);
                core::ptr::write(oa_us.as_mut_ptr().add(2) as *mut u16, bytes);
                core::ptr::write(oa_us.as_mut_ptr().add(8) as *mut u64, entry.name);
            }
            let mut result_len: u32 = 0;
            // SAFETY: query the named value into `info`.
            let st = unsafe {
                syscall6(
                    SSN_NT_QUERY_VALUE_KEY,
                    current_key,
                    oa_us.as_ptr() as u64,
                    KEY_VALUE_FULL_INFORMATION,
                    info.as_mut_ptr() as u64,
                    info.len() as u64,
                    &mut result_len as *mut u32 as u64,
                )
            };
            if st == STATUS_SUCCESS_U {
                // SAFETY: `info` holds a valid KEY_VALUE_FULL_INFORMATION.
                unsafe {
                    let ty = core::ptr::read_unaligned(info.as_ptr().add(4) as *const u32);
                    let data_off =
                        core::ptr::read_unaligned(info.as_ptr().add(8) as *const u32) as usize;
                    let data_len = core::ptr::read_unaligned(info.as_ptr().add(0x0c) as *const u32);
                    let st2 = dispatch_value(
                        &entry,
                        entry.name as *const u16,
                        ty,
                        info.as_ptr().add(data_off),
                        data_len,
                        context,
                    );
                    if st2 != STATUS_SUCCESS_U as u32 {
                        status = st2;
                    }
                }
            } else {
                // Value absent → fall to the caller's default (if any).
                let st2 = unsafe { dispatch_default(&entry, context) };
                if st2 != STATUS_SUCCESS_U as u32 {
                    status = st2;
                }
            }
        }

        if status != STATUS_SUCCESS_U as u32 {
            break;
        }
        e = e.wrapping_add(ENTRY_SIZE);
    }

    // Close a descended subkey + the base key.
    if current_key != base_key {
        // SAFETY: close the subkey handle.
        unsafe { syscall4(SSN_NT_CLOSE, current_key, 0, 0, 0) };
    }
    if (relative_to & RTL_REGISTRY_HANDLE) == 0 {
        // SAFETY: close the base key we opened.
        unsafe { syscall4(SSN_NT_CLOSE, base_key, 0, 0, 0) };
    }
    status
}

/// Dispatch the caller's DEFAULT for an absent named value (RtlpCallQueryRegistryRoutine's
/// KeyValueInfo->Type == REG_NONE branch): if DefaultType == REG_NONE → SUCCESS (or NOT_FOUND if
/// REQUIRED); else call the routine / DIRECT-copy with the default data.
///
/// # Safety
/// On-target; `entry` valid.
#[cfg(target_arch = "x86_64")]
unsafe fn dispatch_default(entry: &QueryEntry, context: u64) -> u32 {
    if entry.default_type == REG_NONE {
        return if (entry.flags & RTL_QUERY_REGISTRY_REQUIRED) != 0 {
            0xC000_0034 // STATUS_OBJECT_NAME_NOT_FOUND
        } else {
            STATUS_SUCCESS_U as u32
        };
    }
    // Compute the default length if not given (for string types, count units).
    let mut len = entry.default_length;
    if len == 0 && entry.default_data != 0 {
        match entry.default_type {
            REG_SZ | REG_EXPAND_SZ => {
                // SAFETY: default_data is a NUL-terminated UTF-16 string.
                let u = unsafe { wlen(entry.default_data as *const u16) };
                len = ((u + 1) * 2) as u32;
            }
            REG_MULTI_SZ => {
                // Count to the double NUL.
                // SAFETY: default_data is a double-NUL-terminated block.
                let p = entry.default_data as *const u16;
                let mut n = 0usize;
                unsafe {
                    loop {
                        if *p.add(n) == 0 && *p.add(n + 1) == 0 {
                            break;
                        }
                        n += 1;
                        if n > 0x4000 {
                            break;
                        }
                    }
                }
                len = ((n + 2) * 2) as u32;
            }
            _ => {}
        }
    }
    // SAFETY: dispatch the default value.
    unsafe {
        dispatch_value(
            entry,
            entry.name as *const u16,
            entry.default_type,
            entry.default_data as *const u8,
            len,
            context,
        )
    }
}

// =================================================================================================
// RtlCreateProcessParameters — build the RTL_USER_PROCESS_PARAMETERS block on the process heap.
// Ported from references/reactos/sdk/lib/rtl/ppb.c (pure builder in nt_ntdll::rtl::process_params).
// =================================================================================================

/// Read a caller `UNICODE_STRING*` into an owned UTF-16 body (None if `p` is NULL). Reads
/// `Length`@0 (bytes) + `Buffer`@8.
///
/// # Safety
/// `p` is NULL or a valid `UNICODE_STRING`.
#[cfg(target_arch = "x86_64")]
unsafe fn read_ustr_units(p: *const u8) -> Option<alloc::vec::Vec<u16>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: valid UNICODE_STRING per the contract.
    let (len_bytes, buf) = unsafe {
        (
            core::ptr::read_unaligned(p as *const u16) as usize,
            core::ptr::read_unaligned(p.add(8) as *const u64) as *const u16,
        )
    };
    if buf.is_null() || len_bytes == 0 {
        return Some(alloc::vec::Vec::new());
    }
    // SAFETY: [buf, buf+len_bytes/2) is the string body.
    let units = unsafe { core::slice::from_raw_parts(buf, len_bytes / 2) };
    Some(units.to_vec())
}

/// `RtlCreateProcessParameters` — build the `RTL_USER_PROCESS_PARAMETERS` block for a child process on
/// the process heap (de-normalized, per ppb.c), writing the block base to `*process_parameters`.
///
/// Ports `references/reactos/sdk/lib/rtl/ppb.c:RtlCreateProcessParameters`: the NULL substitutions
/// (UserMode: DllPath / CurrentDirectory / Environment default to the live
/// `PEB->ProcessParameters->{DllPath, CurrentDirectory.DosPath, Environment}`; CommandLine defaults to
/// ImagePathName; WindowTitle/DesktopInfo/ShellInfo default to the EmptyString; RuntimeData to the
/// NullString) then the pure block layout ([`nt_ntdll::rtl::process_params::create_process_parameters`]).
///
/// # Safety
/// On-target; `image_path` a valid `UNICODE_STRING*`; the other string args NULL or valid
/// `UNICODE_STRING*`; `environment` NULL or a UTF-16 double-NUL block; `process_parameters` a writable
/// `PVOID*`.
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
pub unsafe fn rtl_create_process_parameters(
    process_parameters: *mut u64,
    image_path: *const u8,
    dll_path: *const u8,
    current_directory: *const u8,
    command_line: *const u8,
    environment: *const u16,
    window_title: *const u8,
    desktop_info: *const u8,
    shell_info: *const u8,
    runtime_data: *const u8,
) -> u32 {
    use nt_ntdll::rtl::process_params::{
        create_process_parameters, denormalize, ParamString, ParamsInput,
    };
    if process_parameters.is_null() || image_path.is_null() {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }

    // Read the live PEB → ProcessParameters (for the UserMode NULL substitutions).
    // SAFETY: gs:[0x60] is the PEB; ProcessParameters @ +0x20.
    let peb_params: u64 = unsafe {
        let peb: u64;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb == 0 {
            0
        } else {
            core::ptr::read((peb + 0x20) as *const u64)
        }
    };

    // --- ImagePathName (required). ---
    // SAFETY: image_path is a valid UNICODE_STRING.
    let image = unsafe { read_ustr_units(image_path) }.unwrap_or_default();

    // --- CommandLine: NULL → ImagePathName (ppb.c). ---
    // SAFETY: command_line NULL or valid.
    let cmd = unsafe { read_ustr_units(command_line) }.unwrap_or_else(|| image.clone());

    // --- DllPath: NULL → PEB->ProcessParameters->DllPath (+0x50). ---
    // SAFETY: dll_path NULL or valid; the PEB DllPath is a valid UNICODE_STRING when peb_params != 0.
    let dll = unsafe { read_ustr_units(dll_path) }.unwrap_or_else(|| {
        if peb_params != 0 {
            // SAFETY: PEB->ProcessParameters + 0x50 = DllPath UNICODE_STRING.
            unsafe { read_ustr_units((peb_params + 0x50) as *const u8) }.unwrap_or_default()
        } else {
            alloc::vec::Vec::new()
        }
    });

    // --- CurrentDirectory: NULL → PEB->ProcessParameters->CurrentDirectory.DosPath (+0x38). ---
    // SAFETY: current_directory NULL or valid; PEB CurrentDirectory is valid when peb_params != 0.
    let cwd = unsafe { read_ustr_units(current_directory) }.unwrap_or_else(|| {
        if peb_params != 0 {
            // SAFETY: PEB->ProcessParameters + 0x38 = CurrentDirectory.DosPath UNICODE_STRING.
            unsafe { read_ustr_units((peb_params + 0x38) as *const u8) }.unwrap_or_default()
        } else {
            alloc::vec::Vec::new()
        }
    });

    // --- Environment: NULL → PEB->ProcessParameters->Environment (+0x80). ---
    let env_ptr: *const u16 = if !environment.is_null() {
        environment
    } else if peb_params != 0 {
        // SAFETY: PEB->ProcessParameters + 0x80 = Environment PVOID.
        unsafe { core::ptr::read((peb_params + 0x80) as *const u64) as *const u16 }
    } else {
        core::ptr::null()
    };
    // SAFETY: env_ptr NULL or a valid double-NUL UTF-16 block.
    let env_units = unsafe { read_env_units(env_ptr) };

    // --- The optional strings: NULL → EmptyString (or NullString for RuntimeData). ---
    // SAFETY: each NULL or a valid UNICODE_STRING.
    let title = unsafe { read_ustr_units(window_title) };
    let desktop = unsafe { read_ustr_units(desktop_info) };
    let shell = unsafe { read_ustr_units(shell_info) };
    let runtime = unsafe { read_ustr_units(runtime_data) };

    let to_param = |o: Option<alloc::vec::Vec<u16>>| match o {
        Some(v) => ParamString::new(&v),
        None => ParamString::empty(),
    };

    let input = ParamsInput {
        image_path_name: ParamString::new(&image),
        dll_path: if dll.is_empty() {
            ParamString::empty()
        } else {
            ParamString::new(&dll)
        },
        current_directory: if cwd.is_empty() {
            ParamString::empty()
        } else {
            ParamString::new(&cwd)
        },
        command_line: ParamString::new(&cmd),
        window_title: to_param(title),
        desktop_info: to_param(desktop),
        shell_info: to_param(shell),
        // RuntimeData NULL → NullString ({0,0,NULL}), never EmptyString.
        runtime_data: match runtime {
            Some(v) if !v.is_empty() => ParamString::new(&v),
            _ => ParamString::null_string(),
        },
        environment: env_units,
    };

    let mut built = create_process_parameters(&input);
    // The pure builder produces a de-normalized block already (string Buffers = offsets); ensure it
    // (idempotent). NOTE: the builder stores `Environment` as an OFFSET (it is VA-agnostic); the VA
    // fix-up happens below once we know the heap `dst`.
    denormalize(&mut built.block, 0);
    let env_off = built.environment_offset;

    // Copy onto the process heap.
    let total = built.block.len();
    // SAFETY: process heap installed by LdrpInitialize.
    let dst = unsafe { crate::process_heap_alloc(total) };
    if dst.is_null() {
        return 0xC000_0017; // STATUS_INSUFFICIENT_RESOURCES
    }
    // SAFETY: dst is a fresh `total`-byte region.
    unsafe {
        core::ptr::copy_nonoverlapping(built.block.as_ptr(), dst, total);
        // ★ ReactOS ppb.c: `Param->Environment = Dest` — Environment is a LIVE VA, never an offset,
        // and normalize/denormalize NEVER touch it. The pure builder only knows the offset, so the
        // export (which knows the heap VA) performs the VA fix-up here. `RtlpInitEnvironment` /
        // `RtlCreateUserProcess` dereference this field directly; leaving it an offset (e.g. 0x668)
        // faulted (#PF cr2=0x668). A zero offset means "no environment" → leave the field NULL.
        if env_off != 0 {
            core::ptr::write((dst as u64 + 0x80) as *mut u64, dst as u64 + env_off);
        }
        core::ptr::write(process_parameters, dst as u64);
    }
    0 // STATUS_SUCCESS
}

/// Measure a double-NUL UTF-16 environment block and return an owned copy INCLUDING the terminating
/// double-NUL (so the pure builder copies it verbatim). Empty (NULL) → empty vec.
///
/// # Safety
/// `env_ptr` NULL or a valid double-NUL UTF-16 block.
#[cfg(target_arch = "x86_64")]
unsafe fn read_env_units(env_ptr: *const u16) -> alloc::vec::Vec<u16> {
    if env_ptr.is_null() {
        return alloc::vec::Vec::new();
    }
    let mut n = 0usize;
    // SAFETY: measure to the double-NUL, including BOTH terminating NULs.
    unsafe {
        loop {
            let a = *env_ptr.add(n);
            let b = *env_ptr.add(n + 1);
            if a == 0 && b == 0 {
                n += 2; // include the terminating double-NUL
                break;
            }
            n += 1;
            if n > 0x8000 {
                n += 2;
                break;
            }
        }
        core::slice::from_raw_parts(env_ptr, n).to_vec()
    }
}

// =================================================================================================
// RtlCreateUserProcess — the classic user-mode process create (ported from process.c:194).
// Drives NtOpenFile→NtCreateSection(SEC_IMAGE)→NtCreateProcessEx→NtQuerySection→
// NtQueryInformationProcess→RtlpInitEnvironment(NtAllocate/WriteVirtualMemory)→RtlCreateUserThread.
// This is smss's SmpExecuteImage (smss.c:92) csrss-spawn path. Transport-heavy (all syscalls); the
// per-call out-params ride the executive's stack mirror exactly as our other on_target drivers.
// =================================================================================================

/// `NtCreateSection` SSN.
#[cfg(target_arch = "x86_64")]
const SSN_NT_CREATE_SECTION: u32 = 52;
/// `NtOpenFile` SSN.
#[cfg(target_arch = "x86_64")]
const SSN_NT_OPEN_FILE: u32 = 122;
/// `NtCreateProcessEx` SSN (the imported create; 49's args are a prefix — see ntdll_plan Step 2c).
#[cfg(target_arch = "x86_64")]
const SSN_NT_CREATE_PROCESS_EX: u32 = 50;
/// `NtQuerySection` SSN.
#[cfg(target_arch = "x86_64")]
const SSN_NT_QUERY_SECTION: u32 = 175;
/// `NtQueryInformationProcess` SSN.
#[cfg(target_arch = "x86_64")]
const SSN_NT_QUERY_INFORMATION_PROCESS: u32 = 161;
/// `SECTION_ALL_ACCESS`.
#[cfg(target_arch = "x86_64")]
const SECTION_ALL_ACCESS: u64 = 0x000F_0000 | 0x1F;
/// `PAGE_EXECUTE`.
#[cfg(target_arch = "x86_64")]
const PAGE_EXECUTE: u64 = 0x10;
/// `SEC_IMAGE`.
#[cfg(target_arch = "x86_64")]
const SEC_IMAGE: u64 = 0x0100_0000;
/// `PROCESS_ALL_ACCESS`.
#[cfg(target_arch = "x86_64")]
const PROCESS_ALL_ACCESS: u64 = 0x001F_0FFF;
/// `SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA`.
#[cfg(target_arch = "x86_64")]
const FILE_EXECUTE_READ: u64 = 0x0010_0000 | 0x0020 | 0x0001;
/// `FILE_SHARE_READ | FILE_SHARE_DELETE`.
#[cfg(target_arch = "x86_64")]
const FILE_SHARE_READ_DELETE: u64 = 0x0001 | 0x0004;
/// `FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE`.
#[cfg(target_arch = "x86_64")]
const FILE_OPEN_FLAGS: u64 = 0x0020 | 0x0040;
/// `SectionImageInformation` class (NtQuerySection).
#[cfg(target_arch = "x86_64")]
const SECTION_IMAGE_INFORMATION: u64 = 1;
/// `ProcessBasicInformation` class.
#[cfg(target_arch = "x86_64")]
const PROCESS_BASIC_INFORMATION: u64 = 0;

/// A minimal `OBJECT_ATTRIBUTES` (x64, 0x30 bytes): Length@0, RootDirectory@8, ObjectName@0x10,
/// Attributes@0x18, SecurityDescriptor@0x20, SecurityQoS@0x28.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    _p0: u32,
    root_directory: u64,
    object_name: u64,
    attributes: u32,
    _p1: u32,
    security_descriptor: u64,
    security_qos: u64,
}

/// `RtlpMapFile` (process.c:20): NtOpenFile(image) → NtCreateSection(SEC_IMAGE) → NtClose(file). On
/// success `*section` holds the SEC_IMAGE handle.
///
/// # Safety
/// On-target; `image_file_name` a valid `UNICODE_STRING*`; `section` a writable `HANDLE*`.
#[cfg(target_arch = "x86_64")]
unsafe fn rtlp_map_file(image_file_name: *const u8, attributes: u32, section: *mut u64) -> u32 {
    let mut h_file: u64 = 0;
    let mut iosb: [u64; 2] = [0; 2];
    let oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        _p0: 0,
        root_directory: 0,
        object_name: image_file_name as u64,
        // OBJ_CASE_INSENSITIVE (0x40) | OBJ_INHERIT (0x02) masked from attributes.
        attributes: attributes & (0x40 | 0x02),
        _p1: 0,
        security_descriptor: 0,
        security_qos: 0,
    };
    // NtOpenFile(&hFile, DesiredAccess, &OA, &IoStatusBlock, ShareAccess, OpenOptions).
    // SAFETY: on-target syscall; all pointers are valid stack locals / the caller's UNICODE_STRING.
    let st = unsafe {
        syscall6(
            SSN_NT_OPEN_FILE,
            core::ptr::addr_of_mut!(h_file) as u64,
            FILE_EXECUTE_READ,
            core::ptr::addr_of!(oa) as u64,
            core::ptr::addr_of_mut!(iosb) as u64,
            FILE_SHARE_READ_DELETE,
            FILE_OPEN_FLAGS,
        )
    } as u32;
    if (st as i32) < 0 {
        return st;
    }
    // NtCreateSection(&Section, SECTION_ALL_ACCESS, OA=NULL, MaxSize=NULL, PAGE_EXECUTE, SEC_IMAGE,
    //                 hFile).
    // SAFETY: on-target syscall.
    let st = unsafe {
        syscall8(
            SSN_NT_CREATE_SECTION,
            section as u64,
            SECTION_ALL_ACCESS,
            0,
            0,
            PAGE_EXECUTE,
            SEC_IMAGE,
            h_file,
            0,
        )
    } as u32;
    // ZwClose(hFile).
    // SAFETY: on-target; 27 = NtClose.
    unsafe {
        syscall4(27, h_file, 0, 0, 0);
    }
    st
}

/// `RtlCreateUserProcess` (process.c:194) — create a process + its (suspended) initial thread from an
/// image path + a (normalized) `RTL_USER_PROCESS_PARAMETERS`. Fills the caller's
/// `RTL_USER_PROCESS_INFORMATION` (Length/ProcessHandle/ThreadHandle/ClientId/ImageInformation).
///
/// # Safety
/// On-target; `image_file_name` a valid `UNICODE_STRING*`; `process_parameters` a normalized params
/// block; `process_information` a writable `RTL_USER_PROCESS_INFORMATION` (≥ 0x60 bytes on x64).
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
pub unsafe fn rtl_create_user_process(
    image_file_name: *const u8,
    attributes: u32,
    process_parameters: *mut u8,
    _process_sd: u64,
    thread_sd: u64,
    parent_process: u64,
    inherit_handles: u8,
    debug_port: u64,
    exception_port: u64,
    process_information: *mut u8,
) -> u32 {
    if image_file_name.is_null() || process_information.is_null() {
        return 0xC000_000D; // STATUS_INVALID_PARAMETER
    }

    // --- RtlpMapFile: open the image + create its SEC_IMAGE section. ---
    let mut h_section: u64 = 0;
    // SAFETY: on-target.
    let st = unsafe { rtlp_map_file(image_file_name, attributes, &mut h_section) };
    if (st as i32) < 0 {
        return st;
    }

    // RTL_USER_PROCESS_INFORMATION x64 layout:
    //   Size@0x00 (already set by caller), ProcessHandle@0x08, ThreadHandle@0x10,
    //   ClientId@0x18 (16 bytes), ImageInformation@0x28 (SECTION_IMAGE_INFORMATION, 0x40 bytes).
    let pinfo = process_information;
    // SAFETY: pinfo is a valid RTL_USER_PROCESS_INFORMATION.
    let (ph_ptr, th_ptr, cid_ptr, imginfo_ptr) = unsafe {
        (
            pinfo.add(0x08) as *mut u64,
            pinfo.add(0x10) as *mut u64,
            pinfo.add(0x18) as *mut u64,
            pinfo.add(0x28),
        )
    };

    let parent = if parent_process != 0 {
        parent_process
    } else {
        NT_CURRENT_PROCESS
    };

    // --- NtCreateProcessEx(&ProcessHandle, PROCESS_ALL_ACCESS, OA=NULL, ParentProcess, Flags=0,
    //     SectionHandle, DebugPort, ExceptionPort, JobMemberLevel=0). ---
    // (ZwCreateProcess in process.c maps to NtCreateProcessEx=50, the imported stub — the executive's
    // SSN-50 arm reads these; 49's args are a prefix.)
    // SAFETY: on-target syscall; ph_ptr is the caller's out-handle slot (written via the mirror).
    let st = unsafe {
        native_syscall_ge5(
            SSN_NT_CREATE_PROCESS_EX,
            &[
                ph_ptr as u64,
                PROCESS_ALL_ACCESS,
                0, // ObjectAttributes
                parent,
                (inherit_handles != 0) as u64, // Flags: InheritHandles → PS_INHERIT_HANDLES bit path
                h_section,
                debug_port,
                exception_port,
                0, // JobMemberLevel
            ],
        )
    } as u32;
    if (st as i32) < 0 {
        // SAFETY: close the section on failure.
        unsafe { syscall4(27, h_section, 0, 0, 0) };
        return st;
    }

    // --- NtQuerySection(hSection, SectionImageInformation, &ImageInformation, size, NULL). ---
    // SAFETY: on-target; imginfo_ptr is a 0x40-byte slot in the caller's struct.
    let st = unsafe {
        syscall6(
            SSN_NT_QUERY_SECTION,
            h_section,
            SECTION_IMAGE_INFORMATION,
            imginfo_ptr as u64,
            0x40,
            0,
            0,
        )
    } as u32;
    if (st as i32) < 0 {
        // SAFETY: close both handles.
        unsafe {
            syscall4(27, core::ptr::read(ph_ptr), 0, 0, 0);
            syscall4(27, h_section, 0, 0, 0);
        }
        return st;
    }

    // --- NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &PBI, size, NULL). ---
    // PROCESS_BASIC_INFORMATION x64: ExitStatus@0, PebBaseAddress@0x08, ... (0x30 bytes).
    let mut pbi = [0u64; 6];
    // SAFETY: on-target; read the process handle the create wrote.
    let process_handle = unsafe { core::ptr::read(ph_ptr) };
    // SAFETY: on-target syscall.
    let st = unsafe {
        syscall6(
            SSN_NT_QUERY_INFORMATION_PROCESS,
            process_handle,
            PROCESS_BASIC_INFORMATION,
            pbi.as_mut_ptr() as u64,
            (pbi.len() * 8) as u64,
            0,
            0,
        )
    } as u32;
    if (st as i32) < 0 {
        // SAFETY: close both handles.
        unsafe {
            syscall4(27, process_handle, 0, 0, 0);
            syscall4(27, h_section, 0, 0, 0);
        }
        return st;
    }
    let peb_base = pbi[1]; // PebBaseAddress @ +0x08

    // --- RtlpInitEnvironment: write the environment + parameter block into the child + point
    //     Peb->ProcessParameters at it (process.c:68). ---
    // SAFETY: on-target; drives NtAllocate/NtWriteVirtualMemory in the child.
    let st = unsafe { rtlp_init_environment(process_handle, peb_base, process_parameters) };
    if (st as i32) < 0 {
        // SAFETY: close both handles.
        unsafe {
            syscall4(27, process_handle, 0, 0, 0);
            syscall4(27, h_section, 0, 0, 0);
        }
        return st;
    }

    // --- RtlCreateUserThread(ProcessHandle, ThreadSD, CreateSuspended=TRUE, ..., TransferAddress,
    //     PebBaseAddress, &ThreadHandle, &ClientId). ---
    // SECTION_IMAGE_INFORMATION: TransferAddress@0x00, ..., MaximumStackSize@0x18, CommittedStackSize@
    // 0x20 (x64). Read them from the queried block.
    // SAFETY: imginfo_ptr is the 0x40-byte SECTION_IMAGE_INFORMATION we queried above.
    let (transfer, max_stack, _commit_stack) = unsafe {
        (
            core::ptr::read_unaligned(imginfo_ptr as *const u64),
            core::ptr::read_unaligned(imginfo_ptr.add(0x18) as *const u64),
            core::ptr::read_unaligned(imginfo_ptr.add(0x20) as *const u64),
        )
    };
    // SAFETY: on-target; th_ptr/cid_ptr are the caller's out-slots.
    let st = unsafe {
        rtl_create_user_thread(
            process_handle,
            thread_sd,
            1, // CreateSuspended = TRUE (process.c: the first thread is created suspended)
            0,
            max_stack as usize,
            0,
            transfer,
            peb_base,
            th_ptr,
            cid_ptr,
        )
    } as u32;
    // ZwClose(hSection) (process.c:386) — regardless of thread-create success/failure it closes it.
    // SAFETY: on-target.
    unsafe { syscall4(27, h_section, 0, 0, 0) };
    if (st as i32) < 0 {
        // SAFETY: close the process handle on thread-create failure.
        unsafe { syscall4(27, process_handle, 0, 0, 0) };
        return st;
    }
    0 // STATUS_SUCCESS
}

/// `RtlpInitEnvironment` (process.c:68): allocate + write the environment block and the parameter
/// block into the child process, then point `Peb->ProcessParameters` at the written block.
///
/// # Safety
/// On-target; `process_handle` a valid child; `peb_base` the child PEB VA; `params` the caller's
/// (normalized) parameter block.
#[cfg(target_arch = "x86_64")]
unsafe fn rtlp_init_environment(process_handle: u64, peb_base: u64, params: *mut u8) -> u32 {
    if params.is_null() {
        return 0xC000_000D;
    }
    // Read Length @ +0x04, MaximumLength @ +0x00, Environment @ +0x80 from the params block.
    // SAFETY: params is a valid RTL_USER_PROCESS_PARAMETERS.
    let (max_len, length, env_ptr) = unsafe {
        (
            core::ptr::read_unaligned(params as *const u32) as usize,
            core::ptr::read_unaligned(params.add(0x04) as *const u32) as usize,
            core::ptr::read_unaligned(params.add(0x80) as *const u64) as *const u16,
        )
    };

    // Environment: measure + allocate in the child + write + rebase the params' Environment pointer.
    if !env_ptr.is_null() {
        // SAFETY: env_ptr is a double-NUL block.
        let env_units = unsafe { read_env_units(env_ptr) };
        let env_bytes = env_units.len() * 2;
        if env_bytes != 0 {
            // SAFETY: allocate in the child.
            let base = unsafe { nt_allocate_in_process(process_handle, env_bytes) };
            if base == 0 {
                return 0xC000_0017;
            }
            // SAFETY: write the env block into the child.
            let st = unsafe {
                nt_write_virtual_memory(process_handle, base, env_units.as_ptr() as u64, env_bytes)
            };
            if (st as i32) < 0 {
                return st;
            }
            // ProcessParameters->Environment = base (in OUR copy, which we write below).
            // SAFETY: params + 0x80 is the Environment pointer.
            unsafe { core::ptr::write_unaligned(params.add(0x80) as *mut u64, base) };
        }
    }

    // Allocate the parameter block in the child + write `Length` bytes.
    // SAFETY: allocate MaximumLength bytes in the child.
    let param_base = unsafe { nt_allocate_in_process(process_handle, max_len) };
    if param_base == 0 {
        return 0xC000_0017;
    }
    // SAFETY: write the parameter block.
    let st = unsafe { nt_write_virtual_memory(process_handle, param_base, params as u64, length) };
    if (st as i32) < 0 {
        return st;
    }
    // Peb->ProcessParameters = param_base (PEB + 0x20 on x64).
    let mut base_local = param_base;
    // SAFETY: write the child PEB's ProcessParameters slot.
    let st = unsafe {
        nt_write_virtual_memory(
            process_handle,
            peb_base + 0x20,
            core::ptr::addr_of_mut!(base_local) as u64,
            8,
        )
    };
    if (st as i32) < 0 {
        return st;
    }
    0
}

/// `NtAllocateVirtualMemory` in another process (`process_handle`), MEM_COMMIT|MEM_RESERVE / RW. Returns
/// the base VA (0 on failure). Like [`nt_allocate_virtual_memory`] but with an explicit process handle.
///
/// # Safety
/// On-target syscall.
#[cfg(target_arch = "x86_64")]
unsafe fn nt_allocate_in_process(process_handle: u64, size_in: usize) -> u64 {
    let mut base: u64 = 0;
    let mut size: u64 = size_in as u64;
    // NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &RegionSize, MEM_COMMIT|MEM_RESERVE,
    //                         PAGE_READWRITE).
    // SAFETY: on-target; base/size are stack locals the executive reads/writes via its mirror.
    let st = unsafe {
        syscall6(
            SSN_NT_ALLOCATE_VIRTUAL_MEMORY,
            process_handle,
            core::ptr::addr_of_mut!(base) as u64,
            0,
            core::ptr::addr_of_mut!(size) as u64,
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            0x04,            // PAGE_READWRITE
        )
    } as u32;
    if (st as i32) < 0 {
        return 0;
    }
    base
}

/// `NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytes, NULL)`.
///
/// # Safety
/// On-target syscall; `buffer` points at `bytes` valid source bytes.
#[cfg(target_arch = "x86_64")]
unsafe fn nt_write_virtual_memory(
    process_handle: u64,
    base: u64,
    buffer: u64,
    bytes: usize,
) -> u32 {
    // SAFETY: on-target syscall (277 = NtWriteVirtualMemory in the shared table).
    unsafe {
        syscall6(
            SSN_NT_WRITE_VIRTUAL_MEMORY_REAL,
            process_handle,
            base,
            buffer,
            bytes as u64,
            0,
            0,
        ) as u32
    }
}

/// `NtWriteVirtualMemory` SSN (shared table).
#[cfg(target_arch = "x86_64")]
const SSN_NT_WRITE_VIRTUAL_MEMORY_REAL: u32 = 287;

/// `NtCreateProcessEx` has 9 args (the 9th = JobMemberLevel). We drive it via [`syscall8`] with the
/// first 8 args; the executive's SSN-50 arm reads args 1..8 (JobMemberLevel=0 is the common case and
/// the 8-arg window carries SectionHandle/DebugPort/ExceptionPort). If a non-zero JobMemberLevel is
/// ever needed a 9-arg native stub can be added; smss always passes 0.
///
/// # Safety
/// On-target syscall; `args` satisfies the target's contract (≥ 8 entries expected).
#[cfg(target_arch = "x86_64")]
unsafe fn native_syscall_ge5(ssn: u32, args: &[u64]) -> u64 {
    let a = |i: usize| *args.get(i).unwrap_or(&0);
    // SAFETY: on-target; a1..a4 → registers, a5..a8 → stack tail (the mirror-read slots). arg 9
    // (JobMemberLevel) is 0 for every smss create — not carried.
    unsafe { syscall8(ssn, a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7)) }
}

/// Suppress "unused" for the c_void alias on non-target hosts (the module is target-gated in use).
#[allow(dead_code)]
type _Unused = *mut c_void;
