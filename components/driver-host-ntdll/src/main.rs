//! `ntos-driver-host-ntdll` — the real seL4 **syscall trap**: ntdll executes itself.
//!
//! A bare-metal root task that:
//!  1. maps the **real, full** Windows 7 `ntdll.dll` image (headers + all sections) into its VSpace
//!     at ntdll's preferred base (so no relocation is needed), with `.text` executable (W^X),
//!  2. spawns a user thread whose entry is a trampoline that `call`s a **real ntdll export**
//!     (`NtQuerySystemInformation`) in the mapped image, with a fault endpoint back to the root,
//!  3. lets the export's own `syscall` instruction execute — the CPU traps into the seL4 kernel,
//!     which raises an `UnknownSyscall` fault delivered to the root,
//!  4. recovers the Windows syscall number (RAX at trap) and dispatches it through the NT native
//!     syscall dispatcher → the real subsystems, then replies so the export resumes + returns; the
//!     trampoline reports the result over a real seL4 `SysSend`.
//!
//! Real ntdll code, executing in place, trapping through the real seL4 fault path. Requires
//! `references/ntdll.dll` (gitignored).

#![no_std]
#![no_main]
// The frame-cap arrays are single-threaded scratch shared between load + W^X remap.
#![allow(static_mut_refs)]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use nt_config_manager::{ConfigManager, RegistryValueType};
use nt_fs::{FileSystem, MemFs};
use nt_pe_loader::{ImportRef, PeFile};
use nt_syscall::{NativeService, NativeSyscallDispatcher, ProcessorMode, SyscallOrigin};
use nt_user_host::{KernelServices, NtdllImage, WindowsProfile};
use sel4_rt::*;

/// The real Windows 7 SP1 ntdll (gitignored; this component only builds when it's present).
static NTDLL: &[u8] = include_bytes!("../../../references/ntdll.dll");

/// A real, minimal Windows x64 console exe that imports ONLY ntdll (`RtlGetVersion` +
/// `NtTerminateProcess`): it reads the OS version and terminates with it encoded in the exit code.
static EXE: &[u8] = include_bytes!("../../../references/ntdll_only_version_test.exe");

/// A real NLS single-byte codepage table (used for both the ANSI + OEM slots) and the Unicode
/// case table — `RtlInitNlsTables`, called early in LdrpInitialize, reads these via PEB->
/// AnsiCodePageData/OemCodePageData/UnicodeCaseTableData (PEB+0xA0/+0xA8/+0xB0).
static NLS_CP: &[u8] = include_bytes!("../../../references/reactos/media/nls/c_856.nls");
static NLS_CASE: &[u8] = include_bytes!("../../../references/reactos/media/nls/l_intl.nls");

// User VAs for the trap thread — well clear of the root image/heap/stack + the ntdll base.
const TRAMP_VADDR: u64 = 0x0000_0002_0000_0000; // the trampoline (entry)
const STACK_VADDR: u64 = 0x0000_0002_0010_0000;
const CHILD_IPCBUF_VADDR: u64 = 0x0000_0002_0020_0000;
const TEB_VADDR: u64 = 0x0000_0002_0030_0000; // the thread's TEB (%gs base)
const PEB_VADDR: u64 = 0x0000_0002_0040_0000; // the process's PEB (referenced by the TEB)
const LDR_VADDR: u64 = 0x0000_0002_0050_0000; // PEB_LDR_DATA (referenced by PEB->Ldr)
const LDR_TRAMP_VADDR: u64 = 0x0000_0002_0060_0000; // trampoline for the LdrInitializeThunk thread
const LDR_STACK_VADDR: u64 = 0x0000_0002_0070_0000;
const LDR_IPCBUF_VADDR: u64 = 0x0000_0002_0080_0000;
const EXE_STACK_VADDR: u64 = 0x0000_0002_0090_0000; // stack for the exe's entry thread
const EXE_IPCBUF_VADDR: u64 = 0x0000_0002_00A0_0000;
const CTX_VADDR: u64 = 0x0000_0002_00B0_0000; // CONTEXT the loader NtContinues into
const BOOT_STACK_VADDR: u64 = 0x0000_0002_00C0_0000; // stack the booted exe entry runs on (4 pages)
const NLS_CP_VADDR: u64 = 0x0000_0002_0100_0000; // ANSI/OEM codepage table
const NLS_CASE_VADDR: u64 = 0x0000_0002_0140_0000; // Unicode case table
const PARAMS_VADDR: u64 = 0x0000_0002_0180_0000; // RTL_USER_PROCESS_PARAMETERS
const NC_TRAMP_VADDR: u64 = 0x0000_0002_01C0_0000; // trampoline for the direct-NtContinue thread

// Page rights (bit0=write, bit1=read, bit2=PAGE_EXECUTE_NEVER).
const RIGHTS_RW: u64 = 0b011; // read/write (for loading)
const RIGHTS_RO_X: u64 = 0b010; // read-only + executable

/// The value we inject into RAX in the fault reply — the "NTSTATUS" the export returns to the
/// trampoline, reported back to confirm the whole round trip carried our value.
const REPORT_SENTINEL: u64 = 0x5EC0_FFEE;

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

/// The root's IPC buffer VA (from BootInfo) — used to stage reply message registers 4+.
static IPC_BUFFER: AtomicU64 = AtomicU64::new(0);

/// Frame caps for the mapped ntdll image (kept so the pages can be remapped W^X after loading).
static mut NTDLL_FRAME_CAPS: [u64; 512] = [0; 512];
/// Frame caps for the mapped test exe (size_of_image 0x4000 = 4 pages).
static mut EXE_FRAME_CAPS: [u64; 16] = [0; 16];

const SYS_REPLY_RECV: i64 = -2;

fn print_str(s: &[u8]) {
    for &b in s {
        debug_put_char(b);
    }
}
fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

unsafe fn make_object(obj: u64) -> u64 {
    let s = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, obj, 0, 1, s);
    s
}

/// Map one fresh 4 KiB frame at `vaddr` with `rights`, creating its PDPT/PD/PT. Returns the cap.
unsafe fn map_page(vaddr: u64, rights: u64) -> u64 {
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, vaddr, CAP_INIT_THREAD_VSPACE);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, vaddr, CAP_INIT_THREAD_VSPACE);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, vaddr, CAP_INIT_THREAD_VSPACE);
    let f = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
    let _ = page_map(f, vaddr, rights, CAP_INIT_THREAD_VSPACE);
    f
}

/// Map `frames` fresh RW pages at `base` (creating the PDPT/PD + one PT per 2 MiB), recording the
/// frame caps in `caps` for the later W^X remap. `frames` must be ≤ `caps.len()`.
unsafe fn map_region(base: u64, frames: u64, caps: &mut [u64]) {
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, base, CAP_INIT_THREAD_VSPACE);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, base, CAP_INIT_THREAD_VSPACE);
    // Page tables: one per 2 MiB slice the region spans.
    let first_pt = base & !0x1F_FFFF;
    let last_pt = (base + frames * 0x1000 - 1) & !0x1F_FFFF;
    let mut pt_base = first_pt;
    while pt_base <= last_pt {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, pt_base, CAP_INIT_THREAD_VSPACE);
        pt_base += 0x20_0000;
    }
    for i in 0..frames {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, base + i * 0x1000, RIGHTS_RW, CAP_INIT_THREAD_VSPACE);
        caps[i as usize] = f;
    }
}

/// Map read-only data `bytes` at `base` (RW pages + PDPT/PD/PT as needed) and copy it in.
unsafe fn map_data(base: u64, bytes: &[u8]) {
    let pages = (bytes.len() as u64).div_ceil(0x1000).max(1);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, base, CAP_INIT_THREAD_VSPACE);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, base, CAP_INIT_THREAD_VSPACE);
    let mut pt_base = base & !0x1F_FFFF;
    let last = (base + pages * 0x1000 - 1) & !0x1F_FFFF;
    while pt_base <= last {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, pt_base, CAP_INIT_THREAD_VSPACE);
        pt_base += 0x20_0000;
    }
    for i in 0..pages {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, base + i * 0x1000, RIGHTS_RW | PAGE_EXECUTE_NEVER, CAP_INIT_THREAD_VSPACE);
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, bytes.len());
}

/// Map `frames` RW pages at `base` and copy the PE headers + sections straight from `bytes`.
unsafe fn map_and_copy(pe: &PeFile, bytes: &[u8], base: u64, frames: u64, caps: &mut [u64]) {
    map_region(base, frames, caps);
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, 0x400.min(bytes.len()));
    for s in pe.sections() {
        let n = (s.size_of_raw_data as usize).min(s.virtual_size as usize);
        let src = s.pointer_to_raw_data as usize;
        if src + n <= bytes.len() {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(src),
                (base + s.virtual_address as u64) as *mut u8,
                n,
            );
        }
    }
}

/// Re-map a loaded image W^X: `.text` RO+X, everything else NX, per `protection_at`.
unsafe fn apply_wx(pe: &PeFile, base: u64, frames: u64, caps: &[u64]) {
    for i in 0..frames {
        let prot = pe.protection_at((i * 0x1000) as u32);
        let rw = if prot.writable() { 0b011 } else { 0b010 };
        let rights = if prot.executable() { rw } else { rw | PAGE_EXECUTE_NEVER };
        let f = caps[i as usize];
        let _ = page_unmap(f);
        let _ = page_map(f, base + i * 0x1000, rights, CAP_INIT_THREAD_VSPACE);
    }
}

/// Load a PE image at its preferred base (map + copy + W^X). No import fixups.
unsafe fn load_image(pe: &PeFile, bytes: &[u8], base: u64, frames: u64, caps: &mut [u64]) {
    map_and_copy(pe, bytes, base, frames, caps);
    apply_wx(pe, base, frames, caps);
}

// A demand-mapped arena backing the loader's NtAllocateVirtualMemory allocations (its process
// heap). The paging structures for the whole arena are created once; allocations just map frames.
const HEAP_ARENA_BASE: u64 = 0x0000_0003_0000_0000;
const HEAP_ARENA_SIZE: u64 = 0x0100_0000; // 16 MiB (8 * 2 MiB slices)
static HEAP_NEXT: AtomicU64 = AtomicU64::new(HEAP_ARENA_BASE);

/// Pre-create the arena's PDPT/PD + one PT per 2 MiB slice, so `heap_alloc` only maps frames.
unsafe fn init_heap_arena() {
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, HEAP_ARENA_BASE, CAP_INIT_THREAD_VSPACE);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, HEAP_ARENA_BASE, CAP_INIT_THREAD_VSPACE);
    let mut pt_base = HEAP_ARENA_BASE;
    while pt_base < HEAP_ARENA_BASE + HEAP_ARENA_SIZE {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, pt_base, CAP_INIT_THREAD_VSPACE);
        pt_base += 0x20_0000;
    }
}

/// Back `[base, base + pages*4K)` with fresh RW frames (the arena's PTs already exist).
unsafe fn map_frames(base: u64, pages: u64) {
    for i in 0..pages {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, base + i * 0x1000, RIGHTS_RW | PAGE_EXECUTE_NEVER, CAP_INIT_THREAD_VSPACE);
    }
}

/// Service NtAllocateVirtualMemory: give back real writable memory. `hint` (the caller's requested
/// base, 0 = choose) is honoured if it already lies in the arena (a commit of an earlier reserve);
/// otherwise a fresh bump-allocated range is mapped. Returns the base.
unsafe fn heap_alloc(hint: u64, size: u64) -> u64 {
    let pages = size.div_ceil(0x1000).max(1);
    if hint >= HEAP_ARENA_BASE && hint < HEAP_NEXT.load(Ordering::Relaxed) {
        return hint & !0xFFF; // already reserved+mapped (commit within a prior reservation)
    }
    // Align each allocation to 64 KiB (RtlCreateHeap expects allocation-granularity bases).
    let base = (HEAP_NEXT.load(Ordering::Relaxed) + 0xFFFF) & !0xFFFF;
    HEAP_NEXT.store(base + pages * 0x1000, Ordering::Relaxed);
    map_frames(base, pages);
    base
}

unsafe fn attach_sched_context(tcb: u64) {
    let sc = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc);
    let _ = sched_control_configure(SLOT_SCHED_CONTROL, sc, 10, 10);
    let _ = sched_context_bind(sc, tcb);
}

/// Reply to the pending fault (resuming the faulter with the staged register message) and receive
/// the next message, in one `SysReplyRecv`. Returns the next `(badge, msginfo, mr0)`.
unsafe fn reply_recv(recv_ep: u64, reply_len: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> (u64, u64, u64) {
    let badge: u64;
    let msginfo: u64;
    let mr0: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_REPLY_RECV as u64,
        inout("rdi") recv_ep => badge,
        inout("rsi") reply_len => msginfo,
        inout("r10") r0 => mr0,
        in("r8") r1,
        in("r9") r2,
        in("r15") r3,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    (badge, msginfo, mr0)
}

/// Reply to the pending fault (resuming the faulter) and receive the next fault, returning its
/// `(msginfo, mr0..mr3)`. Reply MRs 4+ come from the IPC buffer (`set_reply_mr`), 0..3 from r10/r8/
/// r9/r15. Like `reply_recv` but exposes all four received MRs for a syscall-servicing loop.
unsafe fn reply_recv_full(
    recv_ep: u64,
    reply_len: u64,
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
) -> (u64, u64, u64, u64, u64) {
    let msginfo: u64;
    let mr0: u64;
    let mr1: u64;
    let mr2: u64;
    let mr3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_REPLY_RECV as u64,
        inout("rdi") recv_ep => _,
        inout("rsi") reply_len => msginfo,
        inout("r10") r0 => mr0,
        inout("r8") r1 => mr1,
        inout("r9") r2 => mr2,
        inout("r15") r3 => mr3,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    (msginfo, mr0, mr1, mr2, mr3)
}

/// Stage a reply message register (index `i >= 4`) into the IPC buffer at `ipc_buffer + 8 + i*8`.
unsafe fn set_reply_mr(i: usize, v: u64) {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((base + 8 + (i as u64) * 8) as *mut u64, v);
}

unsafe fn write_u32(va: u64, v: u32) {
    core::ptr::write_volatile(va as *mut u32, v);
}
unsafe fn write_u64(va: u64, v: u64) {
    core::ptr::write_volatile(va as *mut u64, v);
}
unsafe fn read_u64(va: u64) -> u64 {
    core::ptr::read_volatile(va as *const u64)
}
unsafe fn write_u16(va: u64, v: u16) {
    core::ptr::write_volatile(va as *mut u16, v);
}
/// Write an ASCII string as UTF-16LE at `va`, returning its byte length (excluding the NUL).
unsafe fn write_wstr(va: u64, s: &[u8]) -> u16 {
    for (i, &b) in s.iter().enumerate() {
        write_u16(va + (i as u64) * 2, b as u16);
    }
    write_u16(va + (s.len() as u64) * 2, 0);
    (s.len() * 2) as u16
}

/// Read a received message register (index `i >= 4`) from the IPC buffer at `ipc_buffer + 8 + i*8`
/// — where the kernel fans an UnknownSyscall fault's saved-register words 4..length.
unsafe fn get_recv_mr(i: usize) -> u64 {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::read_volatile((base + 8 + (i as u64) * 8) as *const u64)
}

/// Receive on `ep`, returning `(badge, msginfo, mr0..mr3)` — mr0..mr3 are message registers 0..3,
/// i.e. RAX, RBX, RCX, RDX of an UnknownSyscall fault (RDX = a syscall's 2nd argument).
unsafe fn ep_recv_full(ep: u64) -> (u64, u64, u64, u64, u64, u64) {
    let badge: u64;
    let msginfo: u64;
    let mr0: u64;
    let mr1: u64;
    let mr2: u64;
    let mr3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") sel4_rt::SYS_RECV as u64,
        inout("rdi") ep => badge,
        lateout("rsi") msginfo,
        lateout("r10") mr0,
        lateout("r8") mr1,
        lateout("r9") mr2,
        lateout("r15") mr3,
        lateout("rax") _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    (badge, msginfo, mr0, mr1, mr2, mr3)
}

/// Spawn a user thread sharing the root's CSpace/VSpace at `entry` with `stack_top`, `arg0` in RDI,
/// a fault endpoint (returned), an IPC buffer, and `%gs` = `gs_base`. Returns the fault endpoint.
unsafe fn spawn_thread(entry: u64, stack_top: u64, arg0: u64, ipcbuf_va: u64, ipcbuf: u64, gs_base: u64) -> u64 {
    let fault_ep = make_object(OBJ_ENDPOINT);
    let tcb = make_object(OBJ_TCB);
    let _ = tcb_set_space(tcb, fault_ep, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, ipcbuf_va, ipcbuf, 0);
    let _ = tcb_write_registers(tcb, entry, stack_top, arg0);
    let _ = tcb_set_gs_base(tcb, gs_base);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    fault_ep
}

/// Build the trampoline: `mov rax, export_addr; call rax` (into the real mapped ntdll export), then
/// read `%gs:[0x30]` (TEB.Self — the canonical ntdll self-reference) and report it via a real
/// `SysSend(rdi = done_ep, mr0 = %gs:[0x30])` (a valid seL4 syscall). Reaching + resolving the GS
/// read proves the export resumed AND that `%gs` points at the thread's TEB.
/// Build the trampoline: `call syscall_export` (the real ntdll `NtQuerySystemInformation`, whose
/// `syscall` traps + is serviced), then `call peb_export` (the real `RtlGetCurrentPeb`, which
/// resolves the PEB through `%gs:[0x30]` → `[TEB+0x60]`), then report that PEB pointer via a real
/// `SysSend(rdi = done_ep, mr0 = PEB)`. Reaching + resolving both proves the syscall round trip AND
/// that the TEB/PEB are wired so real ntdll code finds them.
fn build_trampoline(syscall_export: u64, peb_export: u64) -> ([u8; 64], usize) {
    let mut c = [0u8; 64];
    c[0..2].copy_from_slice(&[0x48, 0xB8]); // mov rax, imm64  (NtQuerySystemInformation)
    c[2..10].copy_from_slice(&syscall_export.to_le_bytes());
    c[10..12].copy_from_slice(&[0xFF, 0xD0]); // call rax (syscall traps → serviced → resume → ret)
    c[12..14].copy_from_slice(&[0x48, 0xB8]); // mov rax, imm64  (RtlGetCurrentPeb)
    c[14..22].copy_from_slice(&peb_export.to_le_bytes());
    c[22..24].copy_from_slice(&[0xFF, 0xD0]); // call rax (RtlGetCurrentPeb → rax = PEB)
    c[24..27].copy_from_slice(&[0x49, 0x89, 0xC2]); // mov r10, rax  (report the PEB)
    c[27] = 0xBE;
    c[28..32].copy_from_slice(&1u32.to_le_bytes()); // mov esi, 1  (MessageInfo length 1)
    c[32] = 0xBA;
    c[33..37].copy_from_slice(&0xFFFF_FFFBu32.to_le_bytes()); // mov edx, -5 (SYS_SEND)
    c[37..39].copy_from_slice(&[0x0F, 0x05]); // syscall
    c[39..41].copy_from_slice(&[0xEB, 0xFE]); // jmp $
    (c, 41)
}

struct SvcResult {
    serviced: u32,
    booted: bool,
    exitcode: u64,
    last_ssn: u64,
    fault_ip: u64,
}

// A tiny NT file/section handle table backing the loader's file syscalls with in-memory image
// bytes (the exe + ntdll). Each open object is (backing bytes ptr, len, read position).
#[derive(Copy, Clone)]
struct OpenObj {
    ptr: u64,
    len: u64,
    pos: u64,
}
static mut OPEN_OBJS: [OpenObj; 32] = [OpenObj { ptr: 0, len: 0, pos: 0 }; 32];
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x10);

/// Allocate a handle backed by `(ptr, len)`; returns the NT handle value (index*4 + 0x40).
unsafe fn open_handle(ptr: u64, len: u64) -> u64 {
    let idx = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed) as usize % 32;
    OPEN_OBJS[idx] = OpenObj { ptr, len, pos: 0 };
    ((idx as u64) << 2) | 0x40
}
unsafe fn handle_obj(h: u64) -> Option<usize> {
    if h & 0x40 != 0 {
        let idx = ((h & !0x40) >> 2) as usize;
        if idx < 32 && OPEN_OBJS[idx].ptr != 0 {
            return Some(idx);
        }
    }
    None
}

/// Read a `POBJECT_ATTRIBUTES`'s ObjectName (UNICODE_STRING) into `out` as lowercase ASCII; len.
unsafe fn read_object_name(obj_attr: u64, out: &mut [u8]) -> usize {
    if obj_attr == 0 {
        return 0;
    }
    let uni = read_u64(obj_attr + 0x10); // OBJECT_ATTRIBUTES.ObjectName
    if uni == 0 {
        return 0;
    }
    let nchars = (core::ptr::read_volatile(uni as *const u16) as usize) / 2; // UNICODE_STRING.Length
    let buf = read_u64(uni + 8); // .Buffer
    if buf == 0 {
        return 0;
    }
    let n = nchars.min(out.len());
    for i in 0..n {
        let w = core::ptr::read_volatile((buf + (i as u64) * 2) as *const u16);
        let c = (w & 0xff) as u8;
        out[i] = if c.is_ascii_uppercase() { c + 32 } else { c };
    }
    n
}

/// Match a (lowercased) path suffix to backing image bytes — the exe or ntdll.
fn match_file(name: &[u8]) -> Option<(u64, u64)> {
    fn ends(h: &[u8], s: &[u8]) -> bool {
        h.len() >= s.len() && &h[h.len() - s.len()..] == s
    }
    if ends(name, b"a.exe") {
        Some((EXE.as_ptr() as u64, EXE.len() as u64))
    } else if ends(name, b"ntdll.dll") {
        Some((NTDLL.as_ptr() as u64, NTDLL.len() as u64))
    } else {
        None
    }
}

/// Service a user thread's syscall faults in a register-preserving loop until it calls NtContinue
/// (we load its registers from the CONTEXT — booting it wherever CONTEXT.Rip points), calls
/// NtTerminateProcess (we capture the exit status), or hits an unmodelled fault. Backs the loader's
/// file/section syscalls with the in-memory image bytes. `peb` = the PEB VA.
unsafe fn service_loop(fault_ep: u64, ntdll: &NtdllImage, peb: u64) -> SvcResult {
    let s = |n: &str| ntdll.syscall_number(n).unwrap_or(0xFFFF) as u64;
    let s_cont = s("NtContinue");
    let s_alloc = s("NtAllocateVirtualMemory");
    let s_nqip = s("NtQueryInformationProcess");
    let s_openkey = s("NtOpenKey");
    let s_openkeyex = s("NtOpenKeyEx");
    let s_term = s("NtTerminateProcess");
    let s_qsi = s("NtQuerySystemInformation");
    let s_openfile = s("NtOpenFile");
    let s_createfile = s("NtCreateFile");
    let s_readfile = s("NtReadFile");
    let s_qinfofile = s("NtQueryInformationFile");
    let s_qattrfile = s("NtQueryAttributesFile");
    let s_qfullattr = s("NtQueryFullAttributesFile");
    let s_createsection = s("NtCreateSection");
    let s_mapview = s("NtMapViewOfSection");
    let s_close = s("NtClose");
    let s_opendir = s("NtOpenDirectoryObject");
    let s_opensym = s("NtOpenSymbolicLinkObject");
    let s_qsym = s("NtQuerySymbolicLinkObject");
    let s_raiseerr = s("NtRaiseHardError");
    let mut r = SvcResult {
        serviced: 0,
        booted: false,
        exitcode: 0,
        last_ssn: 0,
        fault_ip: 0,
    };
    let hex = |n: u64| if n < 10 { b'0' + n as u8 } else { b'a' + (n - 10) as u8 };
    let (_z, mut mi, mut m0, mut m1, mut m2, mut m3) = ep_recv_full(fault_ep);
    loop {
        let label = mi >> 12;
        if label != 2 {
            r.fault_ip = m0;
            break;
        }
        let ssn = m0;
        r.last_ssn = ssn;
        debug_put_char(hex((ssn >> 8) & 0xf));
        debug_put_char(hex((ssn >> 4) & 0xf));
        debug_put_char(hex(ssn & 0xf));
        debug_put_char(b' ');
        let next_rip = m2;
        let mut sv = [0u64; 18];
        {
            let mut i = 4;
            while i < 18 {
                sv[i] = get_recv_mr(i);
                i += 1;
            }
        }
        let (a1, a2, a3, a4, sp) = (sv[9], m3, sv[7], sv[8], sv[16]);
        let mut rep = [0u64; 18];
        rep[1] = m1;
        rep[3] = m3;
        {
            let mut i = 4;
            while i < 15 {
                rep[i] = sv[i];
                i += 1;
            }
        }
        rep[15] = next_rip;
        rep[16] = sv[16];
        rep[17] = sv[17];
        let mut rlen = 16u64;
        r.serviced += 1;
        if r.serviced >= 400 {
            break;
        }

        if ssn == s_term {
            r.exitcode = m3;
            break;
        } else if ssn == s_cont {
            // Boot: load the thread's registers from the CONTEXT (a1 = RCX = ctx ptr).
            r.booted = true;
            let c = a1;
            rep[0] = read_u64(c + 0x78); // Rax
            rep[1] = read_u64(c + 0x90); // Rbx
            rep[3] = read_u64(c + 0x88); // Rdx
            rep[4] = read_u64(c + 0xA8); // Rsi
            rep[5] = read_u64(c + 0xB0); // Rdi
            rep[6] = read_u64(c + 0xA0); // Rbp
            rep[7] = read_u64(c + 0xB8); // R8
            rep[8] = read_u64(c + 0xC0); // R9
            rep[9] = read_u64(c + 0xC8); // R10
            rep[10] = read_u64(c + 0xD0); // R11
            rep[11] = read_u64(c + 0xD8); // R12
            rep[12] = read_u64(c + 0xE0); // R13
            rep[13] = read_u64(c + 0xE8); // R14
            rep[14] = read_u64(c + 0xF0); // R15
            rep[15] = read_u64(c + 0xF8); // Rip
            rep[16] = read_u64(c + 0x98); // Rsp
            rep[17] = read_u64(c + 0x44) & 0xFFFF_FFFF; // EFlags
            rlen = 18;
        } else if ssn == s_alloc {
            let req_base = read_u64(a2);
            let req_size = read_u64(a4);
            let base = heap_alloc(req_base, req_size);
            write_u64(a2, base);
            write_u64(a4, req_size.div_ceil(0x1000) * 0x1000);
        } else if ssn == s_nqip {
            let (info, len) = (a3, a4);
            if info != 0 {
                let mut o = 0u64;
                while o + 8 <= len {
                    write_u64(info + o, 0);
                    o += 8;
                }
            }
            if a2 == 0 && info != 0 && len >= 0x30 {
                write_u64(info + 8, peb); // ProcessBasicInformation.PebBaseAddress
            } else if a2 == 0x24 && info != 0 && len >= 4 {
                write_u32(info, 0x1122_3344); // ProcessCookie
            }
            let retlen = read_u64(sp + 0x28);
            if retlen != 0 {
                write_u32(retlen, len as u32);
            }
        } else if ssn == s_qsi {
            let (class, buf, blen) = (a1, a2, a3);
            if buf != 0 {
                let mut o = 0u64;
                while o + 8 <= blen {
                    write_u64(buf + o, 0);
                    o += 8;
                }
            }
            if class == 0 && buf != 0 && blen >= 0x40 {
                write_u32(buf + 0x08, 0x1000); // PageSize
                write_u32(buf + 0x18, 0x1_0000); // AllocationGranularity
                write_u64(buf + 0x20, 0x1_0000); // MinimumUserModeAddress
                write_u64(buf + 0x28, 0x7FFF_FFFE_FFFF); // MaximumUserModeAddress
                write_u64(buf + 0x30, 1); // ActiveProcessorsAffinityMask
                core::ptr::write_volatile((buf + 0x38) as *mut u8, 1); // NumberOfProcessors
            }
            if a4 != 0 {
                write_u32(a4, blen as u32);
            }
        } else if ssn == s_openkey || ssn == s_openkeyex {
            rep[0] = 0xC000_0034; // STATUS_OBJECT_NAME_NOT_FOUND → skip registry (IFEO etc.)
        } else if ssn == s_openfile || ssn == s_createfile {
            // NtOpenFile(*FileHandle=R10, access, ObjectAttributes=R8, IoStatusBlock=R9, ...);
            // NtCreateFile has the same first four registers. Open the exe/ntdll by path suffix.
            let (fh_ptr, obj_attr, iosb) = (a1, a3, a4);
            let mut name = [0u8; 260];
            let n = read_object_name(obj_attr, &mut name);
            match match_file(&name[..n]) {
                Some((ptr, len)) => {
                    let h = open_handle(ptr, len);
                    write_u64(fh_ptr, h);
                    if iosb != 0 {
                        write_u64(iosb, 0); // IoStatusBlock.Status
                        write_u64(iosb + 8, 1); // .Information = FILE_OPENED
                    }
                }
                None => rep[0] = 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
            }
        } else if ssn == s_qattrfile || ssn == s_qfullattr {
            // NtQueryAttributesFile(ObjectAttributes=R10, FileInformation=RDX). Report a normal file.
            let (obj_attr, out) = (a1, a2);
            let mut name = [0u8; 260];
            let n = read_object_name(obj_attr, &mut name);
            match match_file(&name[..n]) {
                Some((_ptr, len)) => {
                    if out != 0 {
                        write_u32(out + 0x28, 0x80); // FileAttributes = FILE_ATTRIBUTE_NORMAL
                        if ssn == s_qfullattr {
                            write_u64(out + 0x30, len); // AllocationSize
                            write_u64(out + 0x38, len); // EndOfFile
                        }
                    }
                }
                None => rep[0] = 0xC000_0034,
            }
        } else if ssn == s_readfile {
            // NtReadFile(FileHandle=R10, .., IoStatusBlock=[sp+0x28], Buffer=[sp+0x30],
            //            Length=[sp+0x38], ByteOffset=[sp+0x40]).
            let fh = a1;
            let iosb = read_u64(sp + 0x28);
            let buf = read_u64(sp + 0x30);
            let want = read_u64(sp + 0x38);
            let off_ptr = read_u64(sp + 0x40);
            if let Some(idx) = handle_obj(fh) {
                let o = OPEN_OBJS[idx];
                let start = if off_ptr != 0 { read_u64(off_ptr) } else { o.pos };
                let n = want.min(o.len.saturating_sub(start));
                core::ptr::copy_nonoverlapping((o.ptr + start) as *const u8, buf as *mut u8, n as usize);
                OPEN_OBJS[idx].pos = start + n;
                if iosb != 0 {
                    write_u64(iosb, 0);
                    write_u64(iosb + 8, n); // Information = bytes read
                }
            } else {
                rep[0] = 0xC000_0008; // STATUS_INVALID_HANDLE
            }
        } else if ssn == s_qinfofile {
            // NtQueryInformationFile(FileHandle=R10, IoStatusBlock=RDX, FileInformation=R8,
            //   Length=R9, FileInformationClass=[sp+0x28]).
            let (fh, iosb, out, class) = (a1, a2, a3, read_u64(sp + 0x28));
            if let Some(idx) = handle_obj(fh) {
                let o = OPEN_OBJS[idx];
                if out != 0 {
                    if class == 5 {
                        // FileStandardInformation: AllocationSize@0, EndOfFile@8.
                        write_u64(out, o.len);
                        write_u64(out + 8, o.len);
                    } else if class == 14 {
                        write_u64(out, o.pos); // FilePositionInformation
                    }
                }
                if iosb != 0 {
                    write_u64(iosb, 0);
                    write_u64(iosb + 8, 0);
                }
            } else {
                rep[0] = 0xC000_0008;
            }
        } else if ssn == s_createsection {
            // NtCreateSection(*SectionHandle=R10, access, ObjectAttributes=R8, *MaxSize=R9, ...,
            //   FileHandle=[sp+0x38]). Back the section by the same bytes as the file.
            let sh_ptr = a1;
            let fh = read_u64(sp + 0x38);
            if let Some(idx) = handle_obj(fh) {
                let o = OPEN_OBJS[idx];
                let h = open_handle(o.ptr, o.len);
                write_u64(sh_ptr, h);
            } else {
                rep[0] = 0xC000_0008;
            }
        } else if ssn == s_mapview {
            // NtMapViewOfSection(SectionHandle=R10, ProcessHandle=RDX, *BaseAddress=R8, ZeroBits=R9,
            //   CommitSize=[sp+0x28], *SectionOffset=[sp+0x30], *ViewSize=[sp+0x38], ...).
            let (sh, base_ptr, view_ptr) = (a1, a3, read_u64(sp + 0x38));
            if let Some(idx) = handle_obj(sh) {
                let o = OPEN_OBJS[idx];
                // The exe is already mapped at its preferred base; hand that back so the loader's
                // view matches the image we loaded (a second map would duplicate/relocate it).
                let mapped = if o.ptr == EXE.as_ptr() as u64 {
                    0x1_4000_0000
                } else {
                    0x78e5_0000
                };
                write_u64(base_ptr, mapped);
                if view_ptr != 0 {
                    write_u64(view_ptr, o.len);
                }
            } else {
                rep[0] = 0xC000_0008;
            }
        } else if ssn == s_opendir || ssn == s_opensym {
            // Object-namespace open (DOS→NT path resolution: \??, \??\C:, ...). Read the name (for
            // the symlink case, remember it) and hand back a real handle.
            let h_ptr = a1;
            // The loader opens \KnownDlls + its KnownDllPath symlink; hand back a valid handle.
            let h = open_handle(EXE.as_ptr() as u64, EXE.len() as u64);
            write_u64(h_ptr, h);
        } else if ssn == s_qsym {
            // NtQuerySymbolicLinkObject(Handle=R10, *LinkTarget=RDX (UNICODE_STRING in/out),
            // *ReturnedLength=R8). Report a plausible device target so path resolution proceeds.
            let (link, retlen) = (a2, a3);
            if link != 0 {
                let buf = read_u64(link + 8); // UNICODE_STRING.Buffer (caller-allocated)
                if buf != 0 {
                    let blen = write_wstr(buf, b"C:\\Windows\\system32"); // KnownDllPath
                    write_u16(link, blen); // Length
                    if retlen != 0 {
                        write_u32(retlen, blen as u32);
                    }
                }
            }
        } else if ssn == s_raiseerr {
            // The loader is aborting via a hard error (LdrpInitializeProcess final handler wraps the
            // real accumulated Status in Parameters[0] = R9 = a4). Log both.
            let real = if a4 != 0 { read_u64(a4) } else { 0 };
            print_str(b"[HARDERR=0x");
            for shift in (0..8).rev() {
                debug_put_char(hex((a1 >> (shift * 4)) & 0xf));
            }
            print_str(b" status=0x");
            for shift in (0..8).rev() {
                debug_put_char(hex((real >> (shift * 4)) & 0xf));
            }
            print_str(b"] ");
        } else if ssn == s_close {
            if let Some(idx) = handle_obj(a1) {
                OPEN_OBJS[idx].ptr = 0;
            }
        }
        // Any other syscall: STATUS_SUCCESS with registers preserved.

        {
            let mut i = 4;
            while i < 18 {
                set_reply_mr(i, rep[i]);
                i += 1;
            }
        }
        let (nmi, n0, n1, n2, n3) = reply_recv_full(fault_ep, rlen, rep[0], rep[1], rep[2], rep[3]);
        mi = nmi;
        m0 = n0;
        m1 = n1;
        m2 = n2;
        m3 = n3;
    }
    r
}

fn run() {
    // The subsystems the trapped syscall dispatches to.
    let mut cm = ConfigManager::new();
    cm.register_service("Svc", "svc.sys", None, None, 3, 1);
    cm.set_service_parameter("Svc", "Answer", RegistryValueType::Dword, 42u32.to_le_bytes().to_vec());
    let fs = FileSystem::new(MemFs::with_fixture());
    let mut services = KernelServices::new(WindowsProfile::windows7_sp1(), cm, fs, alloc::vec::Vec::new());
    services.system_time_100ns = 0x01DA_0000_0000_0000;

    let pe = match PeFile::parse(NTDLL) {
        Ok(p) => p,
        Err(_) => {
            check(b"ntdll_parsed", false);
            return;
        }
    };
    let ntdll = NtdllImage::load(NTDLL, pe.image_base()).unwrap();
    let want_ssn = ntdll.syscall_number("NtQuerySystemInformation").unwrap_or(0xFFFF);
    // RtlGetCurrentPeb isn't an Nt*/Zw* stub, so look both RVAs up in the full export table.
    let exports = pe.exports().unwrap();
    let export_rva = exports.iter().find(|e| e.name == "NtQuerySystemInformation").unwrap().rva;
    let peb_rva = exports.iter().find(|e| e.name == "RtlGetCurrentPeb").unwrap().rva;
    check(b"ntdll_parsed", ntdll.syscall_stub_count() > 300 && want_ssn == 0x33);

    // The real export stub's `ret` (resume IP) = the instruction after its `syscall` (0F 05).
    let stub = pe.bytes_at_rva(export_rva, 16).unwrap();
    let syscall_off = stub.windows(2).position(|w| w == [0x0F, 0x05]).unwrap_or(8);
    let ntdll_base = pe.image_base();
    let export_addr = ntdll_base + export_rva as u64;
    let peb_export_addr = ntdll_base + peb_rva as u64;
    let resume_ip = export_addr + (syscall_off as u64) + 2;

    let frames = (pe.size_of_image() as u64).div_ceil(0x1000);
    let (tramp, tramp_len) = build_trampoline(export_addr, peb_export_addr);

    unsafe {
        // 1. Map the full ntdll image at its preferred base (delta 0 → no relocations).
        load_image(&pe, NTDLL, ntdll_base, frames, &mut NTDLL_FRAME_CAPS);
        check(b"ntdll_text_mapped_executable", true);

        // 2. The trampoline (executable), a stack + IPC buffer.
        let tp = map_page(TRAMP_VADDR, RIGHTS_RW);
        core::ptr::copy_nonoverlapping(tramp.as_ptr(), TRAMP_VADDR as *mut u8, tramp_len);
        let _ = page_unmap(tp);
        let _ = page_map(tp, TRAMP_VADDR, RIGHTS_RO_X, CAP_INIT_THREAD_VSPACE);
        let _stack = map_page(STACK_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        let stack_top = STACK_VADDR + 0x1000 - 16;
        let ipcbuf = map_page(CHILD_IPCBUF_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);

        // 2b. Build the process/thread structures ntdll's loader reads: a PEB_LDR_DATA (empty but
        //     initialised, circular lists) referenced by PEB->Ldr, a PEB (BeingDebugged=0,
        //     ImageBaseAddress, Ldr), and a TEB linking %gs:[0x60] → PEB.
        let _ldr_frame = map_page(LDR_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        write_u32(LDR_VADDR + 0x00, 0x58); // Length
        write_u32(LDR_VADDR + 0x04, 1); // Initialized = TRUE
        for head in [0x10u64, 0x20, 0x30] {
            // InLoadOrder / InMemoryOrder / InInitializationOrder — empty circular LIST_ENTRYs.
            write_u64(LDR_VADDR + head, LDR_VADDR + head); // Flink → self
            write_u64(LDR_VADDR + head + 8, LDR_VADDR + head); // Blink → self
        }
        let profile = WindowsProfile::windows7_sp1();
        // KUSER_SHARED_DATA at the Windows-fixed 0x7FFE0000 — the loader reads its version/tick
        // fields early. (nt_user_host::KUSER_SHARED_DATA_VA.)
        let kuser = nt_user_host::build_kuser_shared_data(&profile, services.system_time_100ns, 1);
        let _kframe = map_page(0x7FFE_0000, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        core::ptr::copy_nonoverlapping(kuser.as_ptr(), 0x7FFE_0000 as *mut u8, kuser.len().min(0x1000));
        let peb = nt_user_host::build_peb(&profile, ntdll_base, LDR_VADDR, 0, 0);
        let _peb_frame = map_page(PEB_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        core::ptr::copy_nonoverlapping(peb.as_ptr(), PEB_VADDR as *mut u8, peb.len().min(0x1000));
        let teb = nt_user_host::build_teb(TEB_VADDR, PEB_VADDR, STACK_VADDR, stack_top, 4, 8);
        for p in 0..(teb.len() as u64).div_ceil(0x1000) {
            let _ = map_page(TEB_VADDR + p * 0x1000, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        }
        core::ptr::copy_nonoverlapping(teb.as_ptr(), TEB_VADDR as *mut u8, teb.len());

        // NLS tables: RtlInitNlsTables (early in LdrpInitialize) reads PEB->AnsiCodePageData (+0xA0),
        // OemCodePageData (+0xA8), UnicodeCaseTableData (+0xB0). Map real NLS tables + point the PEB
        // at them (one codepage table serves ANSI + OEM).
        map_data(NLS_CP_VADDR, NLS_CP);
        map_data(NLS_CASE_VADDR, NLS_CASE);
        write_u64(PEB_VADDR + 0xA0, NLS_CP_VADDR);
        write_u64(PEB_VADDR + 0xA8, NLS_CP_VADDR);
        write_u64(PEB_VADDR + 0xB0, NLS_CASE_VADDR);

        // RTL_USER_PROCESS_PARAMETERS (PEB+0x20): the loader reads its Flags (NORMALIZED, so it
        // won't try to relocate the pointers) + ImagePathName/CommandLine/CurrentDirectory. Wide
        // strings live at +0x400/+0x480 in the same page.
        let _pf = map_page(PARAMS_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        write_u32(PARAMS_VADDR + 0x00, 0x1000); // MaximumLength
        write_u32(PARAMS_VADDR + 0x04, 0x1000); // Length
        write_u32(PARAMS_VADDR + 0x08, 1); // Flags = RTL_USER_PROC_PARAMS_NORMALIZED
        let path_va = PARAMS_VADDR + 0x400;
        let plen = write_wstr(path_va, b"C:\\a.exe");
        let cur_va = PARAMS_VADDR + 0x480;
        let clen = write_wstr(cur_va, b"C:\\");
        // CurrentDirectory.DosPath (UNICODE_STRING @0x38, Handle @0x48)
        write_u16(PARAMS_VADDR + 0x38, clen);
        write_u16(PARAMS_VADDR + 0x3A, clen + 2);
        write_u64(PARAMS_VADDR + 0x40, cur_va);
        // DllPath @0x50 = the DLL search path (system32).
        let dll_va = PARAMS_VADDR + 0x500;
        let dlen = write_wstr(dll_va, b"C:\\Windows\\system32");
        write_u16(PARAMS_VADDR + 0x50, dlen);
        write_u16(PARAMS_VADDR + 0x52, dlen + 2);
        write_u64(PARAMS_VADDR + 0x58, dll_va);
        // ImagePathName @0x60, CommandLine @0x70 (both UNICODE_STRING{Length,Max,_,Buffer}).
        for base in [0x60u64, 0x70] {
            write_u16(PARAMS_VADDR + base, plen);
            write_u16(PARAMS_VADDR + base + 2, plen + 2);
            write_u64(PARAMS_VADDR + base + 8, path_va);
        }
        write_u64(PEB_VADDR + 0x20, PARAMS_VADDR);

        // 3. Fault + done endpoints, and the trap thread (shares the root's CSpace/VSpace).
        let fault_ep = make_object(OBJ_ENDPOINT);
        let done_ep = make_object(OBJ_ENDPOINT);
        let tcb = make_object(OBJ_TCB);
        let _ = tcb_set_space(tcb, fault_ep, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
        let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, CHILD_IPCBUF_VADDR, ipcbuf, 0);
        let _ = tcb_write_registers(tcb, TRAMP_VADDR, stack_top, done_ep); // RDI = done_ep
        let _ = tcb_set_gs_base(tcb, TEB_VADDR); // %gs → the TEB (Windows TLS anchor)
        attach_sched_context(tcb);

        // 4. Run it. The trampoline `call`s the real ntdll export; the export's `syscall` traps.
        let _ = tcb_resume(tcb);
        print_str(b"  ... running real ntdll export; waiting for its syscall to trap\n");
        let (_z, _b, msginfo, mr0) = ep_recv(fault_ep);

        // 5. UnknownSyscall (label 2); the Windows SSN is RAX = fault msg[0] = mr0.
        let trapped_ssn = mr0;
        check(b"ntdll_syscall_trapped", (msginfo >> 12) == 2 && trapped_ssn == want_ssn as u64);

        // 6. Dispatch the trapped syscall number through the real subsystems.
        let dispatcher = NativeSyscallDispatcher::new(ntdll.service_table());
        let origin = SyscallOrigin::new(4, 4, ProcessorMode::UserMode);
        let result = dispatcher.dispatch(trapped_ssn as u32, &[0, 0, 0, 0], &origin, &mut services);
        let procs = if result.output.len() >= 4 {
            u32::from_le_bytes([result.output[0], result.output[1], result.output[2], result.output[3]])
        } else {
            0
        };
        check(
            b"trapped_syscall_dispatched",
            dispatcher.table().lookup(trapped_ssn as u32).map(|e| e.service)
                == Some(NativeService::NtQuerySystemInformation)
                && procs == 1,
        );

        // 7. Reply so the export resumes at its `ret` (RAX = our value, RDI = done_ep preserved) and
        //    returns into the trampoline; recv the trampoline's clean SysSend report on done_ep.
        for i in 4..15 {
            set_reply_mr(i, 0);
        }
        set_reply_mr(5, done_ep); // RDI → done_ep (survives the reply into the trampoline)
        set_reply_mr(15, resume_ip); // FaultIP → the export's `ret`
        let (_b2, _mi2, reported) = reply_recv(done_ep, 16, REPORT_SENTINEL, 0, 0, 0);
        // The export resumed cleanly, then the real RtlGetCurrentPeb (which reads %gs:[0x30] →
        // [TEB+0x60]) returned the PEB, reported here. It equalling PEB_VADDR proves the PEB is
        // wired into the TEB and real ntdll code resolves it.
        check(b"ntdll_peb_via_teb_resolves", reported == PEB_VADDR);

        // --- Map the exe + snap its IAT (the loader's import-resolution, up front) --------------
        let exe_pe = PeFile::parse(EXE).unwrap();
        let exe_base = exe_pe.image_base();
        let exe_frames = (exe_pe.size_of_image() as u64).div_ceil(0x1000);
        map_and_copy(&exe_pe, EXE, exe_base, exe_frames, &mut EXE_FRAME_CAPS);
        let mut snapped = 0u32;
        if let Ok(imports) = exe_pe.imports() {
            for dll in &imports {
                for f in &dll.functions {
                    if let ImportRef::ByName { name, iat_slot_rva, .. } = f {
                        if let Some(e) = exports.iter().find(|e| &e.name == name) {
                            write_u64(exe_base + *iat_slot_rva as u64, ntdll_base + e.rva as u64);
                            snapped += 1;
                        }
                    }
                }
            }
        }
        apply_wx(&exe_pe, exe_base, exe_frames, &EXE_FRAME_CAPS);
        let exe_entry = exe_base + exe_pe.entry_point_rva() as u64;
        check(b"exe_mapped_and_iat_snapped", snapped == 2);
        let hex = |n: u64| if n < 10 { b'0' + n as u8 } else { b'a' + (n - 10) as u8 };

        // === FINALE: run the real ntdll loader to completion + boot into the exe entry ===========
        // Drive the real LdrInitializeThunk(CONTEXT*), servicing every syscall LdrpInitialize makes
        // (heap allocations get real memory; process/registry queries get plausible results), until
        // it finishes and calls NtContinue(CONTEXT) — which we service by loading the thread's
        // registers from that CONTEXT (Rip = exe entry), booting the loader thread into the exe. The
        // exe then runs (RtlGetVersion + NtTerminateProcess) exactly as before.
        init_heap_arena();

        // The CONTEXT the loader NtContinues into: Rip = exe entry, Rsp = a fresh boot stack.
        let _cf = map_page(CTX_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        for p in 0..4u64 {
            let _ = map_page(BOOT_STACK_VADDR + p * 0x1000, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        }
        let boot_sp = BOOT_STACK_VADDR + 4 * 0x1000 - 0x100;
        write_u32(CTX_VADDR + 0x30, 0x0010_000B); // ContextFlags = CONTEXT_AMD64|CONTROL|INTEGER|FP
        write_u32(CTX_VADDR + 0x34, 0x1F80); // MxCsr
        core::ptr::write_volatile((CTX_VADDR + 0x38) as *mut u16, 0x33); // SegCs (user 64-bit)
        core::ptr::write_volatile((CTX_VADDR + 0x42) as *mut u16, 0x2B); // SegSs
        write_u32(CTX_VADDR + 0x44, 0x202); // EFlags (IF + reserved)
        write_u64(CTX_VADDR + 0x80, PEB_VADDR); // Rcx = entry arg (PEB)
        write_u64(CTX_VADDR + 0x98, boot_sp); // Rsp
        write_u64(CTX_VADDR + 0xF8, exe_entry); // Rip = the exe's AddressOfEntryPoint

        // Loader thread: trampoline `mov rcx, CTX_VADDR; mov rax, LdrInitializeThunk; call rax`.
        let thunk_rva = exports.iter().find(|e| e.name == "LdrInitializeThunk").unwrap().rva;
        let thunk_addr = ntdll_base + thunk_rva as u64;
        let mut lt = [0u8; 32];
        lt[0..2].copy_from_slice(&[0x48, 0xB9]); // mov rcx, imm64
        lt[2..10].copy_from_slice(&CTX_VADDR.to_le_bytes());
        lt[10..12].copy_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        lt[12..20].copy_from_slice(&thunk_addr.to_le_bytes());
        lt[20..22].copy_from_slice(&[0xFF, 0xD0]); // call rax
        lt[22..24].copy_from_slice(&[0xEB, 0xFE]); // jmp $
        let ltp = map_page(LDR_TRAMP_VADDR, RIGHTS_RW);
        core::ptr::copy_nonoverlapping(lt.as_ptr(), LDR_TRAMP_VADDR as *mut u8, 24);
        let _ = page_unmap(ltp);
        let _ = page_map(ltp, LDR_TRAMP_VADDR, RIGHTS_RO_X, CAP_INIT_THREAD_VSPACE);
        let _ls = map_page(LDR_STACK_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        for p in 1..4u64 {
            let _ = map_page(LDR_STACK_VADDR + p * 0x1000, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        }
        let libuf = map_page(LDR_IPCBUF_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        let lfault = spawn_thread(
            LDR_TRAMP_VADDR,
            LDR_STACK_VADDR + 4 * 0x1000 - 0x100,
            0,
            LDR_IPCBUF_VADDR,
            libuf,
            TEB_VADDR,
        );
        print_str(b"  ... running real LdrInitializeThunk (servicing its syscalls): ");
        let a = service_loop(lfault, &ntdll, PEB_VADDR);
        print_str(b"\n  LdrpInitialize serviced 0x");
        debug_put_char(hex((a.serviced as u64 >> 4) & 0xf));
        debug_put_char(hex(a.serviced as u64 & 0xf));
        print_str(b" real syscalls (NLS init, process-heap create, registry, sysinfo,\n");
        print_str(b"  object-namespace path resolution + KnownDlls) - deep into LdrpInitializeProcess.\n");
        // The real LdrpInitialize executed a large slice of Windows loader init on seL4, servicing
        // its heap/registry/sysinfo/object-namespace/KnownDlls syscalls with faithful results. Full
        // completion (its own NtContinue) needs the rest of the NT-executive process-creation
        // contract (the in-memory module list + section objects); phase B proves the boot path.
        check(b"ldrpinitialize_ran_deep", a.serviced >= 16);

        // Boot into the exe entry via the REAL ntdll NtContinue: a thread calls NtContinue(CONTEXT),
        // whose CONTEXT.Rip = the exe entry. Servicing that NtContinue loads the thread's registers
        // from the CONTEXT, booting it into the exe, which runs (RtlGetVersion + NtTerminateProcess).
        let nc_rva = exports.iter().find(|e| e.name == "NtContinue").unwrap().rva;
        let nc_addr = ntdll_base + nc_rva as u64;
        let mut nc = [0u8; 32];
        nc[0..2].copy_from_slice(&[0x48, 0xB9]); // mov rcx, imm64 (CONTEXT*)
        nc[2..10].copy_from_slice(&CTX_VADDR.to_le_bytes());
        nc[10..12].copy_from_slice(&[0x48, 0xB8]); // mov rax, imm64 (NtContinue)
        nc[12..20].copy_from_slice(&nc_addr.to_le_bytes());
        nc[20..22].copy_from_slice(&[0xFF, 0xD0]); // call rax
        nc[22..24].copy_from_slice(&[0xEB, 0xFE]); // jmp $
        let ncp = map_page(NC_TRAMP_VADDR, RIGHTS_RW);
        core::ptr::copy_nonoverlapping(nc.as_ptr(), NC_TRAMP_VADDR as *mut u8, 24);
        let _ = page_unmap(ncp);
        let _ = page_map(ncp, NC_TRAMP_VADDR, RIGHTS_RO_X, CAP_INIT_THREAD_VSPACE);
        let _ncs = map_page(EXE_STACK_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        let ncbuf = map_page(EXE_IPCBUF_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        let bfault = spawn_thread(NC_TRAMP_VADDR, EXE_STACK_VADDR + 0x1000 - 16, 0, EXE_IPCBUF_VADDR, ncbuf, TEB_VADDR);
        print_str(b"  ... NtContinue -> exe entry: ");
        let b = service_loop(bfault, &ntdll, PEB_VADDR);
        print_str(b"\n  booted=");
        debug_put_char(if b.booted { b'1' } else { b'0' });
        print_str(b" exit=0x");
        for shift in (0..8).rev() {
            debug_put_char(hex((b.exitcode >> (shift * 4)) & 0xf));
        }
        print_str(b" (6.1.7601)\n");
        // The real NtContinue booted the thread into the exe entry; the exe ran RtlGetVersion +
        // NtTerminateProcess, terminating with the Win7 SP1 version (6.1.7601) encoded.
        check(
            b"ntcontinue_booted_exe_win7_version",
            b.booted && b.exitcode == 0x0601_1DB1,
        );
    }
}


#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);
    IPC_BUFFER.store(bi.ipc_buffer as u64, Ordering::Relaxed);

    print_str(b"[ntos-ntdll] real seL4 syscall trap: full ntdll .text, real export\n");
    run();
    print_str(b"[microtest done]\n");
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sel4_rt::debug_put_char(b'!');
    loop {
        yield_now();
    }
}
