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

use core::ffi::c_void;

use nt_ntdll::heap::{Backing, Heap};

// ---------------------------------------------------------------------------------------------
// In-process Nt* syscall callers (the trap backend — `mov r10,rcx; mov eax,ssn; syscall`).
// We call our OWN exported trap stub semantics inline. The executive services these via the fault
// EP exactly as it does smss's own ntdll calls.
// ---------------------------------------------------------------------------------------------

/// `NtAllocateVirtualMemory` SSN (shared `nt-syscall-abi` table).
const SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 18;

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
/// # Safety
/// Issues a real syscall trap serviced by the executive; only valid on-target in a hosted process.
#[cfg(target_arch = "x86_64")]
unsafe fn nt_allocate_virtual_memory(size_in: usize) -> u64 {
    let mut base: u64 = 0; // 0 = let the executive pick the per-process bump base
    let mut region: u64 = size_in as u64;
    let status: u64;
    // x64 native syscall ABI: arg1=RCX(→R10)=ProcessHandle, arg2=RDX=&BaseAddress, arg3=R8=ZeroBits,
    // arg4=R9=&RegionSize, arg5/arg6 on the stack = AllocationType, Protect. The naked `Nt*` stub
    // form is `mov r10,rcx; mov eax,ssn; syscall`; we inline the equivalent, placing the two stack
    // args at [rsp+0x28]/[rsp+0x30] (past the 0x20 shadow + return slot) per the Windows x64 ABI.
    // SAFETY: a hosted-process syscall trap; base/region are valid stack locals for the out-writes.
    unsafe {
        core::arch::asm!(
            "sub rsp, 0x38",
            "mov qword ptr [rsp+0x28], {atype}",
            "mov qword ptr [rsp+0x30], {prot}",
            "mov r10, {proc}",         // arg1: ProcessHandle
            "mov rdx, {pbase}",        // arg2: &BaseAddress
            "xor r8d, r8d",            // arg3: ZeroBits = 0
            "mov r9, {psize}",         // arg4: &RegionSize
            "mov eax, {ssn}",
            "syscall",
            "add rsp, 0x38",
            ssn = const SSN_NT_ALLOCATE_VIRTUAL_MEMORY,
            proc = in(reg) NT_CURRENT_PROCESS,
            pbase = in(reg) &mut base as *mut u64,
            psize = in(reg) &mut region as *mut u64,
            atype = in(reg) MEM_COMMIT_RESERVE as u64,
            prot = in(reg) PAGE_READWRITE as u64,
            out("rax") status,
            out("rcx") _,
            out("r11") _,
            out("r10") _,
            out("r8") _,
            out("r9") _,
            clobber_abi("system"),
        );
    }
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

/// A general 4-register-arg syscall trap (`arg1..arg4` in RCX/RDX/R8/R9; `mov r10,rcx; syscall`).
///
/// # Safety
/// On-target hosted-process syscall; the args must satisfy the target syscall's contract.
#[cfg(target_arch = "x86_64")]
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

/// A general 6-arg syscall trap (arg1..4 in registers, arg5/arg6 on the stack at `[rsp+0x28/0x30]`).
///
/// # Safety
/// On-target hosted-process syscall; args must satisfy the target syscall's contract.
#[cfg(target_arch = "x86_64")]
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

/// Suppress "unused" for the c_void alias on non-target hosts (the module is target-gated in use).
#[allow(dead_code)]
type _Unused = *mut c_void;
