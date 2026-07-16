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
    // (2) Snap smss's imports against our export table (the 4.A IAT-mismatch fix).
    // SAFETY: on-target mapped-image walk + IAT write.
    unsafe { snap_smss_imports(smss_base, ntdll_base) }
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
    // IPC buffer MR4/MR5 = a3/a4 (only 4 MRs ride in registers; MR4+ go via the IPC buffer).
    // IPCBUF_VADDR is a fixed per-process VA; MR i lives at byte (8 + i*8): MR4 @ +0x28, MR5 @ +0x30.
    const IPCBUF_VADDR: u64 = 0x0000_0100_105F_B000;
    let status: u64;
    // SAFETY: a native seL4 Call; the executive services it via Recv/Reply on the fault EP. The
    // stack-frame reservation holds a5/a6 for the executive's mirror read; rsp (MR1) is captured
    // after the reservation so the offsets match the executive's `sp+0x28` reads.
    unsafe {
        core::arch::asm!(
            // Reserve the ABI stack frame + place a5/a6 where the executive reads them.
            "sub rsp, 0x38",
            "mov qword ptr [rsp+0x28], {a5}",   // stack arg5
            "mov qword ptr [rsp+0x30], {a6}",   // stack arg6
            // MR4/MR5 (a3/a4) into the IPC buffer.
            "movabs r11, {ipcbuf}",
            "mov qword ptr [r11 + 0x28], {a3}", // MR4 = arg3
            "mov qword ptr [r11 + 0x30], {a4}", // MR5 = arg4
            // Register message: MR0=SSN(r10), MR1=rsp(r8), MR2=a1(r9), MR3=a2(r15).
            "mov r8, rsp",                      // MR1 = caller rsp (points at the reserved frame)
            "mov r10d, {ssn:e}",                // MR0 = SSN
            "mov r9,  {a1}",                    // MR2 = arg1
            "mov r15, {a2}",                    // MR3 = arg2
            "mov edi, 6",                       // rdi = CT_FAULT cap slot
            "mov esi, 0x4E546006",              // rsi = (0x4E54<<12)|6
            "mov rdx, -1",                      // rdx = SysCall (native seL4 Call)
            "syscall",
            "add rsp, 0x38",
            ssn = in(reg) ssn,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            a3 = in(reg) a3,
            a4 = in(reg) a4,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            ipcbuf = const IPCBUF_VADDR,
            // Reply MR0 (NTSTATUS) comes back in r10 (the IPC return ABI). Capture it.
            out("r10") status,
            out("rax") _, out("rcx") _, out("r11") _, out("r8") _, out("r9") _,
            out("rsi") _, out("rdi") _, out("rdx") _, out("r15") _,
            clobber_abi("system"),
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
    const IPCBUF_VADDR: u64 = 0x0000_0100_105F_B000;
    let status: u64;
    // SAFETY: native seL4 Call; the executive reads a5..a8 + writes stack out-params via its mirror.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x48",
            "mov qword ptr [rsp+0x28], {a5}",
            "mov qword ptr [rsp+0x30], {a6}",
            "mov qword ptr [rsp+0x38], {a7}",
            "mov qword ptr [rsp+0x40], {a8}",
            "movabs r11, {ipcbuf}",
            "mov qword ptr [r11 + 0x28], {a3}", // MR4 = arg3
            "mov qword ptr [r11 + 0x30], {a4}", // MR5 = arg4
            "mov r8, rsp",                      // MR1 = caller rsp
            "mov r10d, {ssn:e}",                // MR0 = SSN
            "mov r9,  {a1}",                    // MR2 = arg1
            "mov r15, {a2}",                    // MR3 = arg2
            "mov edi, 6",                       // rdi = CT_FAULT
            "mov esi, 0x4E546006",              // rsi = (0x4E54<<12)|6
            "mov rdx, -1",                      // rdx = SysCall
            "syscall",
            "add rsp, 0x48",
            ssn = in(reg) ssn,
            a1 = in(reg) a1, a2 = in(reg) a2, a3 = in(reg) a3, a4 = in(reg) a4,
            a5 = in(reg) a5, a6 = in(reg) a6, a7 = in(reg) a7, a8 = in(reg) a8,
            ipcbuf = const IPCBUF_VADDR,
            out("r10") status,
            out("rax") _, out("rcx") _, out("r11") _, out("r8") _, out("r9") _,
            out("rsi") _, out("rdi") _, out("rdx") _, out("r15") _,
            clobber_abi("system"),
        );
    }
    status
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

/// Suppress "unused" for the c_void alias on non-target hosts (the module is target-gated in use).
#[allow(dead_code)]
type _Unused = *mut c_void;
