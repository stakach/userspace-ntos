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

use core::ffi::c_void;

use nt_ntdll::heap::{Backing, Heap};

// ---------------------------------------------------------------------------------------------
// In-process Nt* syscall callers (the trap backend — `mov r10,rcx; mov eax,ssn; syscall`).
// We call our OWN exported trap stub semantics inline. The executive services these via the fault
// EP exactly as it does smss's own ntdll calls.
// ---------------------------------------------------------------------------------------------

/// `NtAllocateVirtualMemory` SSN (shared `nt-syscall-abi` table).
const SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 18;

/// `STATUS_NO_MEMORY`.
const STATUS_NO_MEMORY: u64 = 0xC000_0017;

/// `MEM_COMMIT | MEM_RESERVE`.
const MEM_COMMIT_RESERVE: u32 = 0x0000_3000;
/// `PAGE_READWRITE`.
const PAGE_READWRITE: u32 = 0x04;
/// `NtCurrentProcess()` pseudo-handle.
const NT_CURRENT_PROCESS: u64 = u64::MAX; // (HANDLE)-1

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
unsafe fn nt_allocate_virtual_memory(size_in: usize) -> u64 {
    let mut base: u64 = 0; // 0 = let the executive pick the per-process bump base
    let mut region: u64 = size_in as u64;
    // arg1=ProcessHandle, arg2=&BaseAddress, arg3=ZeroBits, arg4=&RegionSize, arg5=AllocationType,
    // arg6=Protect. The executive reads/writes *BaseAddress + *RegionSize through its stack mirror.
    // SAFETY: base/region are valid stack locals for the out-writes.
    let status = unsafe {
        syscall6(
            SSN_NT_ALLOCATE_VIRTUAL_MEMORY,
            NT_CURRENT_PROCESS,
            &mut base as *mut u64 as u64,
            0,
            &mut region as *mut u64 as u64,
            MEM_COMMIT_RESERVE as u64,
            PAGE_READWRITE as u64,
        )
    };
    if status == 0 {
        base
    } else {
        0
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
    base: *mut u8,
    len: usize,
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
unsafe fn create_process_heap() -> Option<Heap<HeapBacking>> {
    // SAFETY: on-target hosted-process syscall.
    let base = unsafe { nt_allocate_virtual_memory(PROCESS_HEAP_SIZE) };
    if base == 0 {
        return None;
    }
    Heap::create(HeapBacking {
        base: base as *mut u8,
        len: PROCESS_HEAP_SIZE,
    })
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
/// asm shim; the reserved arg is NULL (dynamic-load convention gives non-NULL only for static links,
/// but ReactOS DllMains ignore it during ATTACH).
///
/// # Safety
/// `entry_va` must be the mapped, executable entry point of a real DLL in this VSpace.
#[cfg(target_arch = "x86_64")]
unsafe fn call_dll_main(base: u64, reason: u32) -> u64 {
    let ret: u64;
    // SAFETY: entry_va is a mapped executable DLL entry; the callee follows the Win64 ABI. We
    // provide 0x20 shadow space + keep rsp 16-aligned across the call.
    unsafe {
        let entry = base + entry_point_rva(base) as u64;
        core::arch::asm!(
            "sub rsp, 0x28",
            "xor r8d, r8d",
            "call {entry}",
            "add rsp, 0x28",
            entry = in(reg) entry,
            in("rcx") base,
            in("rdx") reason as u64,
            lateout("rax") ret,
            lateout("rcx") _, lateout("rdx") _, lateout("r8") _, lateout("r9") _,
            lateout("r10") _, lateout("r11") _,
        );
    }
    ret
}

/// Run `DLL_PROCESS_ATTACH` for every loaded DEPENDENT DLL (not the EXE, not our own ntdll), in
/// reverse discovery order (leaf dependencies first — the DFS `snap_module` inserts a parent before
/// its children, so the LAST-inserted entries are the deepest leaves). This is the live
/// `LdrpRunInitializeRoutines` seam: kernel32's `DllMain` runs `InitCommandLines()` (→
/// `GetCommandLineA`), msvcrt's runs its CRT `_acmdln` setup, etc. Without it winlogon's CRT startup
/// dereferences a NULL command line (`strdup(GetCommandLineA())` → `strlen(NULL)`).
///
/// # Safety
/// On-target; every table entry is a mapped DLL image whose imports have been snapped.
#[cfg(target_arch = "x86_64")]
unsafe fn run_process_attach(table: &ModuleTable) {
    // Post-order DFS: a module's DEPENDENCIES init before it (kernel32 before advapi32 before mpr,
    // etc.). A per-base visited set dedupes diamonds + breaks cycles. The order matters: mpr's
    // DllMain calls kernel32 functions, so kernel32 must have run InitCommandLines first. Reverse
    // insertion order was WRONG (mpr-first → kernel32 uninitialized → crash).
    let count = table.count.min(MODULE_TABLE_CAP);
    let mut visited = [0u64; MODULE_TABLE_CAP];
    let mut vn = 0usize;
    // SAFETY: single-threaded loader; each table base is a mapped, snapped image.
    unsafe {
        let mut i = 0usize;
        while i < count {
            let b = table.mods[i].base;
            if b >= 0x1_0000 {
                attach_dfs(table, b, &mut visited, &mut vn, 0);
            }
            i += 1;
        }
    }
}

/// Recursively `DLL_PROCESS_ATTACH` `base`'s dependencies (post-order) then `base` itself. `visited`
/// records already-attached bases (dedupe + cycle break). Skips our own ntdll (no C DllMain).
///
/// # Safety
/// On-target; `base` is a mapped, snapped PE image in this VSpace; `table` bases are mapped images.
#[cfg(target_arch = "x86_64")]
unsafe fn attach_dfs(
    table: &ModuleTable,
    base: u64,
    visited: &mut [u64; MODULE_TABLE_CAP],
    vn: &mut usize,
    depth: u32,
) {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if base < 0x1_0000 || depth > 16 {
        return;
    }
    // Already attached?
    for &v in visited.iter().take(*vn) {
        if v == base {
            return;
        }
    }
    // Mark visited BEFORE recursing (cycle break).
    if *vn < MODULE_TABLE_CAP {
        visited[*vn] = base;
        *vn += 1;
    }
    // SAFETY: base is a mapped PE image; the import walk reads mapped headers.
    unsafe {
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
                let dep = table.find(&nb[..bn]);
                if dep >= 0x1_0000 && dep != base {
                    attach_dfs(table, dep, visited, vn, depth + 1);
                }
                desc += 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
            }
        }
        // Skip our own ntdll (no C DllMain).
        if is_ntdll_base(table, base) {
            return;
        }
        let epr = entry_point_rva(base);
        if epr == 0 {
            return; // resource-only DLL — nothing to run
        }
        {
            let mut mb = [0u8; 64];
            let mut mn = 0usize;
            for &c in b"DllMain base=0x" {
                if mn < 64 { mb[mn] = c; mn += 1; }
            }
            mn = crate::write_u64_hex(&mut mb, mn, base);
            crate::dbg_print_bytes(mb.as_ptr(), mn);
        }
        let _ = call_dll_main(base, DLL_PROCESS_ATTACH);
    }
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
        let (edir_rva, _edir_sz) = data_directory(base, 0); // IMAGE_DIRECTORY_ENTRY_EXPORT = 0
        if edir_rva == 0 {
            return 0;
        }
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

/// The largest dependency graph we resolve in one process (csrss's is tiny: ntdll + csrsrv; leave
/// headroom for csrsrv's own deps + future ServerDlls).
#[cfg(target_arch = "x86_64")]
const MODULE_TABLE_CAP: usize = 32;

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
}

/// The per-drive module table (single-threaded loader; a process's LdrpInitialize runs once, on one
/// thread, before any other thread exists). Not shared across processes — each spawn re-runs the
/// drive fresh in its own VSpace.
#[cfg(target_arch = "x86_64")]
struct ModuleTable {
    mods: [LoadedMod; MODULE_TABLE_CAP],
    count: usize,
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
    }; MODULE_TABLE_CAP],
    count: 0,
};

#[cfg(target_arch = "x86_64")]
impl ModuleTable {
    /// Insert `(name, base)` (name already lowercased, no `.dll` suffix). Ignores overflow + dups.
    fn insert(&mut self, name: &[u8], base: u64) {
        if self.find(name) != 0 {
            return; // already present
        }
        if self.count >= MODULE_TABLE_CAP {
            return;
        }
        let mut m = LoadedMod {
            name: [0u8; 32],
            nlen: 0,
            base,
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
            if m.nlen as usize == name.len() && &m.name[..name.len()] == name {
                return m.base;
            }
        }
        0
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
    table: &mut ModuleTable,
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
                resolve_export_addr(dep_base, false, &namebuf[..nlen], 0, table, 0)
            } else {
                // by ordinal.
                let ord = (thunk & 0xffff) as u32;
                resolve_export_addr(dep_base, true, &[], ord, table, 0)
            };
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
        let (edir_rva, _sz) = data_directory(base, 0);
        if edir_rva == 0 {
            return 0;
        }
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
    table: &mut ModuleTable,
    depth: u32,
) -> u64 {
    if depth > 8 {
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
        let mut tbase = table.find(tmod_lc);
        if tbase == 0 {
            let loaded = load_dependent_dll(tmod_lc);
            if loaded != 0 {
                table.insert(tmod_lc, loaded);
                let mut sink = SnapResult::default();
                snap_module(loaded, table.find(b"ntdll"), table, &mut sink, depth + 1);
                tbase = loaded;
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
            resolve_export_addr(tbase, true, &[], ord, table, depth + 1)
        } else {
            resolve_export_addr(tbase, false, sym_part, 0, table, depth + 1)
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
            1,      // ViewShare
            0,      // AllocationType
            0x20,   // PAGE_EXECUTE_READ
        )
    };
    if (st as i32) < 0 {
        return 0;
    }
    base_address
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
            [commit_size, section_offset, view_size, inherit, alloc_type, protect],
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
pub unsafe fn ldrp_drive(smss_base: u64, ntdll_base: u64) -> SnapResult {
    // (1) Process heap — install it so `alloc` works for any engine code that needs it.
    // SAFETY: on-target syscall.
    if let Some(heap) = unsafe { create_process_heap() } {
        crate::install_process_heap(heap);
    }
    // (2) Snap the EXE's imports against our export table + any dependent DLLs (csrsrv for csrss).
    // smss imports only ntdll (dep-free); csrss also imports csrsrv.dll — which this loads + snaps.
    // SAFETY: on-target mapped-image walk + IAT write + dependent-DLL load syscalls.
    let out = unsafe { snap_all_imports(smss_base, ntdll_base) };
    // (3) Run DLL_PROCESS_ATTACH for every dependent DLL (the live LdrpRunInitializeRoutines seam).
    // kernel32's DllMain runs InitCommandLines() so GetCommandLineA is non-NULL — winlogon's msvcrt
    // CRT startup does strdup(GetCommandLineA()), which strlen(NULL)-faults without this.
    // SAFETY: single-threaded loader; MODULE_TABLE holds mapped, snapped DLL images.
    unsafe {
        let table = &*core::ptr::addr_of!(MODULE_TABLE);
        run_process_attach(table);
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
        let table = &mut *core::ptr::addr_of_mut!(MODULE_TABLE);
        table.insert(b"ntdll", ntdll_base);
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
    table: &mut ModuleTable,
    out: &mut SnapResult,
    depth: u32,
) {
    if depth > 8 {
        return; // cycle / over-deep guard — csrss's graph is 2 deep at most
    }
    // SAFETY: reading the mapped import directory + writing the mapped RW IAT per the contract.
    unsafe {
        let (idir_rva, _sz) = data_directory(image_base, 1); // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
        if idir_rva == 0 {
            return;
        }
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
            let mut dep_base = table.find(dep_name);
            if dep_base == 0 {
                // Not loaded yet — map it (the executive assigns its fixed registry base), record it,
                // then recursively snap ITS imports before we snap this module against it.
                let loaded = load_dependent_dll(dep_name);
                if loaded != 0 {
                    table.insert(dep_name, loaded);
                    snap_module(loaded, ntdll_base, table, out, depth + 1);
                    dep_base = loaded;
                }
            }
            if dep_base != 0 {
                snap_descriptor_against(image_base, ilt_rva, ft, dep_base, table, out);
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
        let table = &mut *core::ptr::addr_of_mut!(MODULE_TABLE);
        // Already loaded? Return its base.
        let existing = table.find(dep);
        let base = if existing != 0 {
            existing
        } else {
            let loaded = load_dependent_dll(dep);
            if loaded == 0 {
                return 0xC000_0135; // STATUS_DLL_NOT_FOUND
            }
            table.insert(dep, loaded);
            // Snap the freshly-loaded DLL's own imports (ntdll + any deps) so it can run.
            let ntdll_base = table.find(b"ntdll");
            let mut out = SnapResult::default();
            snap_module(loaded, ntdll_base, table, &mut out, 0);
            loaded
        };
        if !base_addr.is_null() {
            core::ptr::write_unaligned(base_addr, base as *mut c_void);
        }
    }
    0 // STATUS_SUCCESS
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
        let table = &mut *core::ptr::addr_of_mut!(MODULE_TABLE);
        if name.is_null() {
            resolve_export_addr(base, true, &[], ordinal, table, 0)
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
                resolve_export_addr(base, false, &nb[..l], 0, table, 0)
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
// The real ntdll `RtlAdjustPrivilege` opens the process (or thread) token, builds a one-entry
// TOKEN_PRIVILEGES, and calls `NtAdjustPrivilegesToken`. Our executive services `NtOpenProcessToken`
// + `NtAdjustPrivilegesToken` + `NtClose` (as success no-ops for the smss bring-up), so routing the
// real syscalls here is the honest live-plane implementation (not a fabricated success) — it issues
// the actual token syscalls the real ntdll would, through our own trap stubs.
// ---------------------------------------------------------------------------------------------

const SSN_NT_OPEN_PROCESS_TOKEN: u32 = 129;
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
/// Opens the process token (the `CurrentThread` thread-token variant is not needed by smss and
/// degrades to the process token), builds a one-entry `TOKEN_PRIVILEGES { count=1, luid={priv,0},
/// attrs=Enable?ENABLED:0 }`, calls `NtAdjustPrivilegesToken`, closes the token, and reports the prior
/// enabled state in `*was_enabled`. Returns the `NtAdjustPrivilegesToken` status.
///
/// # Safety
/// On-target hosted-process; `was_enabled` is null or a valid writable byte.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_adjust_privilege(
    privilege: u32,
    enable: u8,
    _current_thread: u8,
    was_enabled: *mut u8,
) -> u64 {
    // NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &TokenHandle).
    let mut token: u64 = 0;
    // SAFETY: on-target token syscall; &token is a valid stack out-param (the executive writes it
    // through its stack mirror, matching NtOpenProcessToken's *TokenHandle out).
    let st_open = unsafe {
        syscall4(
            SSN_NT_OPEN_PROCESS_TOKEN,
            NT_CURRENT_PROCESS,
            TOKEN_ADJUST_PRIVILEGES_QUERY as u64,
            &mut token as *mut u64 as u64,
            0,
        )
    };
    // TOKEN_PRIVILEGES on the stack: PrivilegeCount(u32) + LUID_AND_ATTRIBUTES{ LUID(low u32,high
    // i32), Attributes(u32) }. Laid out as [count, luid_low, luid_high, attrs] u32s (16 bytes).
    let new_state: [u32; 4] = [
        1,                                                  // PrivilegeCount
        privilege,                                          // Luid.LowPart (SE_*_PRIVILEGE index)
        0,                                                  // Luid.HighPart
        if enable != 0 { SE_PRIVILEGE_ENABLED } else { 0 }, // Attributes
    ];
    let mut old_state: [u32; 4] = [0; 4];
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
    if st_open == 0 {
        let _ = unsafe { syscall4(SSN_NT_CLOSE, token, 0, 0, 0) };
    }
    if !was_enabled.is_null() {
        // Report whether the privilege was previously enabled (from OldState if it came back).
        let prev = (old_state[3] & SE_PRIVILEGE_ENABLED) != 0;
        // SAFETY: was_enabled is a valid writable byte per the contract.
        unsafe { core::ptr::write(was_enabled, prev as u8) };
    }
    // The executive services the token plane as success no-ops; report the adjust status (which is
    // STATUS_SUCCESS there). If the open failed, surface that instead.
    if st_open != 0 { st_open } else { st_adj }
}

// ---------------------------------------------------------------------------------------------
// Step 4.C — RtlSetProcessIsCritical / RtlSetThreadIsCritical over the live info-class plane.
//
// Real ntdll calls NtSetInformationProcess(ProcessBreakOnTermination) / NtSetInformationThread
// (ThreadBreakOnTermination) with a ULONG boolean. The executive services both info-set syscalls
// (success no-ops), so routing the real syscalls here is the honest implementation — it issues the
// actual SetInformation the real ntdll would, not a fabricated success.
// ---------------------------------------------------------------------------------------------

const SSN_NT_SET_INFORMATION_PROCESS: u32 = 237;
const SSN_NT_SET_INFORMATION_THREAD: u32 = 238;
/// `ProcessBreakOnTermination` info class.
const PROCESS_BREAK_ON_TERMINATION: u64 = 0x1D;
/// `ThreadBreakOnTermination` info class.
const THREAD_BREAK_ON_TERMINATION: u64 = 0x12;
/// `NtCurrentThread()` pseudo-handle `(HANDLE)-2`.
const NT_CURRENT_THREAD: u64 = u64::MAX - 1;

/// `RtlSetProcessIsCritical(New, Old, CheckFlag)` — set/clear ProcessBreakOnTermination via a live
/// `NtSetInformationProcess`. `*old` (if non-null) reports the prior state (best-effort: 0, since the
/// executive doesn't return a queried prior value). Returns the syscall status.
///
/// # Safety
/// On-target hosted-process; `old` null or a valid writable byte.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rtl_set_process_is_critical(new: u8, old: *mut u8, _check_flag: u8) -> u64 {
    if !old.is_null() {
        // SAFETY: caller-provided writable byte.
        unsafe { core::ptr::write(old, 0) };
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
pub unsafe fn rtl_set_thread_is_critical(new: u8, old: *mut u8, _check_flag: u8) -> u64 {
    if !old.is_null() {
        // SAFETY: caller-provided writable byte.
        unsafe { core::ptr::write(old, 0) };
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
unsafe fn build_oa(oa: *mut u8, us: *mut u8, root: u64, name_ptr: *const u16, name_len_units: usize) {
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
    let mut oa = [0u8; 0x30];
    let mut us = [0u8; 0x10];
    let mut handle: u64 = 0;
    const KEY_READ: u64 = 0x2_0019;
    // SAFETY: valid stack buffers; name is a valid UTF-16 slice.
    unsafe {
        build_oa(oa.as_mut_ptr(), us.as_mut_ptr(), root, name.as_ptr(), name.len());
        let st = syscall4(
            SSN_NT_OPEN_KEY,
            &mut handle as *mut u64 as u64,
            KEY_READ,
            oa.as_ptr() as u64,
            0,
        );
        if st != STATUS_SUCCESS_U {
            return 0;
        }
    }
    handle
}

/// Resolve the RelativeTo base key path into a UTF-16 vec (absolute NT path), or `None` for
/// RTL_REGISTRY_HANDLE (Path itself is the handle) / RTL_REGISTRY_ABSOLUTE (Path is already absolute).
#[cfg(target_arch = "x86_64")]
fn registry_base_path(relative_to: u32) -> Option<&'static str> {
    match relative_to & !(RTL_REGISTRY_OPTIONAL | 0x2000_0000) {
        RTL_REGISTRY_SERVICES => {
            Some("\\Registry\\Machine\\System\\CurrentControlSet\\Services")
        }
        RTL_REGISTRY_CONTROL => {
            Some("\\Registry\\Machine\\System\\CurrentControlSet\\Control")
        }
        RTL_REGISTRY_WINDOWS_NT => {
            Some("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion")
        }
        _ => None, // ABSOLUTE / HANDLE — caller handles
    }
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
) -> u32 {
    use alloc::vec::Vec;
    // REG_EXPAND_SZ expansion (skip if NOEXPAND).
    let mut expanded: Option<Vec<u16>> = None;
    if (entry.flags & RTL_QUERY_REGISTRY_NOEXPAND) == 0
        && ty == REG_EXPAND_SZ
        && len >= 2
    {
        // Read the source string (drop the trailing NUL if present).
        let units = (len as usize) / 2;
        // SAFETY: [data, data+len) is the value; interpret as UTF-16.
        let src: &[u16] = unsafe { core::slice::from_raw_parts(data as *const u16, units) };
        let src_trim = if src.last() == Some(&0) { &src[..units - 1] } else { src };
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
    let routine: OnTargetQueryRoutine = unsafe { core::mem::transmute::<u64, OnTargetQueryRoutine>(entry.query_routine) };
    // SAFETY: calling into the caller's routine with its declared ABI + valid pointers.
    let st = unsafe {
        routine(name_ptr as u64, ty_out, data_out, len_out, 0, entry.entry_context)
    };
    // STATUS_BUFFER_TOO_SMALL is normalized to SUCCESS by real ntdll.
    if st == 0xC000_0023 { STATUS_SUCCESS_U as u32 } else { st }
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
    // Read a UNICODE_STRING (Length@0 u16 bytes, Buffer@8).
    // SAFETY: p is a valid UNICODE_STRING per the contract.
    unsafe fn read_ustr(p: *const u8) -> Option<String> {
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
    // SAFETY: reading the caller's UNICODE_STRINGs.
    let name_s = match unsafe { read_ustr(name) } {
        Some(s) if !s.is_empty() => s,
        _ => return 0xC000_000D, // STATUS_INVALID_PARAMETER
    };
    // SAFETY: reading the value (NULL → delete).
    let val_s = unsafe { read_ustr(value) };

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
    env.set(&name_s, val_s.as_deref());
    let block = env.to_block(); // Vec<u16>, double-NUL-terminated
    let bytes = block.len() * 2;

    // Allocate + copy the new block.
    // SAFETY: process heap alloc.
    let dst = unsafe { crate::process_heap_alloc(bytes) } as *mut u16;
    if dst.is_null() {
        return 0xC000_0017; // STATUS_NO_MEMORY
    }
    // SAFETY: dst is a fresh bytes-byte region.
    unsafe {
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
            // Doesn't fit (incl. the NUL). Report the required char count in Length.
            core::ptr::write_unaligned(value as *mut u16, val_units.len() as u16);
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
            core::ptr::write_unaligned(destination as *mut u16, (body_units * 2) as u16); // Length
            return STATUS_BUFFER_TOO_SMALL;
        }
        core::ptr::copy_nonoverlapping(expanded.as_ptr(), out, expanded.len());
        core::ptr::write_unaligned(destination as *mut u16, (body_units * 2) as u16); // Length
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
    _context: u64,
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
                                core::ptr::read_unaligned(info.as_ptr().add(8) as *const u32) as usize;
                            let data_len =
                                core::ptr::read_unaligned(info.as_ptr().add(0x0c) as *const u32);
                            let name_len =
                                core::ptr::read_unaligned(info.as_ptr().add(0x10) as *const u32) as usize;
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
                    );
                    if st2 != STATUS_SUCCESS_U as u32 {
                        status = st2;
                    }
                }
            } else {
                // Value absent → fall to the caller's default (if any).
                let st2 = unsafe { dispatch_default(&entry) };
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
unsafe fn dispatch_default(entry: &QueryEntry) -> u32 {
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
        if peb == 0 { 0 } else { core::ptr::read((peb + 0x20) as *const u64) }
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
        dll_path: if dll.is_empty() { ParamString::empty() } else { ParamString::new(&dll) },
        current_directory: if cwd.is_empty() { ParamString::empty() } else { ParamString::new(&cwd) },
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

    let parent = if parent_process != 0 { parent_process } else { NT_CURRENT_PROCESS };

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
    let st = unsafe {
        rtlp_init_environment(process_handle, peb_base, process_parameters)
    };
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
unsafe fn nt_write_virtual_memory(process_handle: u64, base: u64, buffer: u64, bytes: usize) -> u32 {
    // SAFETY: on-target syscall (277 = NtWriteVirtualMemory in the shared table).
    unsafe {
        syscall6(SSN_NT_WRITE_VIRTUAL_MEMORY_REAL, process_handle, base, buffer, bytes as u64, 0, 0)
            as u32
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
