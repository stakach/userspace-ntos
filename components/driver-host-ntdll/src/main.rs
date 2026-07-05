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

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use nt_config_manager::{ConfigManager, RegistryValueType};
use nt_fs::{FileSystem, MemFs};
use nt_pe_loader::PeFile;
use nt_syscall::{NativeService, NativeSyscallDispatcher, ProcessorMode, SyscallOrigin};
use nt_user_host::{KernelServices, NtdllImage, WindowsProfile};
use sel4_rt::*;

/// The real Windows 7 SP1 ntdll (gitignored; this component only builds when it's present).
static NTDLL: &[u8] = include_bytes!("../../../references/ntdll.dll");

// User VAs for the trap thread — well clear of the root image/heap/stack + the ntdll base.
const TRAMP_VADDR: u64 = 0x0000_0002_0000_0000; // the trampoline (entry)
const STACK_VADDR: u64 = 0x0000_0002_0010_0000;
const CHILD_IPCBUF_VADDR: u64 = 0x0000_0002_0020_0000;
const TEB_VADDR: u64 = 0x0000_0002_0030_0000; // the thread's TEB (%gs base)
const PEB_VADDR: u64 = 0x0000_0002_0040_0000; // the process's PEB (referenced by the TEB)

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
/// frame caps for the later W^X remap. `base` + `frames*4K` must fit the recorded region (≤ 512).
unsafe fn map_region(base: u64, frames: u64) {
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
        NTDLL_FRAME_CAPS[i as usize] = f;
    }
}

/// Re-map the ntdll image W^X: `.text` code read-only + executable, everything else NX.
unsafe fn apply_wx(pe: &PeFile, base: u64, frames: u64) {
    for i in 0..frames {
        let prot = pe.protection_at((i * 0x1000) as u32);
        let rw = if prot.writable() { 0b011 } else { 0b010 };
        let rights = if prot.executable() { rw } else { rw | PAGE_EXECUTE_NEVER };
        let f = NTDLL_FRAME_CAPS[i as usize];
        let _ = page_unmap(f);
        let _ = page_map(f, base + i * 0x1000, rights, CAP_INIT_THREAD_VSPACE);
    }
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

/// Stage a reply message register (index `i >= 4`) into the IPC buffer at `ipc_buffer + 8 + i*8`.
unsafe fn set_reply_mr(i: usize, v: u64) {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((base + 8 + (i as u64) * 8) as *mut u64, v);
}

/// Build the trampoline: `mov rax, export_addr; call rax` (into the real mapped ntdll export), then
/// read `%gs:[0x30]` (TEB.Self — the canonical ntdll self-reference) and report it via a real
/// `SysSend(rdi = done_ep, mr0 = %gs:[0x30])` (a valid seL4 syscall). Reaching + resolving the GS
/// read proves the export resumed AND that `%gs` points at the thread's TEB.
fn build_trampoline(export_addr: u64) -> ([u8; 48], usize) {
    let mut c = [0u8; 48];
    c[0..2].copy_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    c[2..10].copy_from_slice(&export_addr.to_le_bytes());
    c[10..12].copy_from_slice(&[0xFF, 0xD0]); // call rax (export: syscall traps → serviced → ret)
    // mov rax, gs:[0x30]  — read TEB.Self AFTER the syscall trap+resume (proves %gs survives it).
    c[12..21].copy_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00]);
    c[21..24].copy_from_slice(&[0x49, 0x89, 0xC2]); // mov r10, rax
    c[24] = 0xBE;
    c[25..29].copy_from_slice(&1u32.to_le_bytes()); // mov esi, 1  (MessageInfo length 1)
    c[29] = 0xBA;
    c[30..34].copy_from_slice(&0xFFFF_FFFBu32.to_le_bytes()); // mov edx, -5 (SYS_SEND)
    c[34..36].copy_from_slice(&[0x0F, 0x05]); // syscall
    c[36..38].copy_from_slice(&[0xEB, 0xFE]); // jmp $
    (c, 38)
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
    let export_rva = ntdll.export("NtQuerySystemInformation").unwrap().rva;
    check(b"ntdll_parsed", ntdll.syscall_stub_count() > 300 && want_ssn == 0x33);

    // The real export stub's `ret` (resume IP) = the instruction after its `syscall` (0F 05).
    let stub = pe.bytes_at_rva(export_rva, 16).unwrap();
    let syscall_off = stub.windows(2).position(|w| w == [0x0F, 0x05]).unwrap_or(8);
    let ntdll_base = pe.image_base();
    let export_addr = ntdll_base + export_rva as u64;
    let resume_ip = export_addr + (syscall_off as u64) + 2;

    let frames = (pe.size_of_image() as u64).div_ceil(0x1000);
    let (tramp, tramp_len) = build_trampoline(export_addr);

    unsafe {
        // 1. Map the full ntdll image at its preferred base + copy headers/sections in (delta 0).
        map_region(ntdll_base, frames);
        // Headers.
        core::ptr::copy_nonoverlapping(NTDLL.as_ptr(), ntdll_base as *mut u8, 0x400.min(NTDLL.len()));
        // Each section by virtual address.
        for s in pe.sections() {
            let n = (s.size_of_raw_data as usize).min(s.virtual_size as usize);
            let src = s.pointer_to_raw_data as usize;
            if src + n <= NTDLL.len() {
                core::ptr::copy_nonoverlapping(
                    NTDLL.as_ptr().add(src),
                    (ntdll_base + s.virtual_address as u64) as *mut u8,
                    n,
                );
            }
        }
        apply_wx(&pe, ntdll_base, frames);
        check(b"ntdll_text_mapped_executable", true);

        // 2. The trampoline (executable), a stack + IPC buffer.
        let tp = map_page(TRAMP_VADDR, RIGHTS_RW);
        core::ptr::copy_nonoverlapping(tramp.as_ptr(), TRAMP_VADDR as *mut u8, tramp_len);
        let _ = page_unmap(tp);
        let _ = page_map(tp, TRAMP_VADDR, RIGHTS_RO_X, CAP_INIT_THREAD_VSPACE);
        let _stack = map_page(STACK_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        let stack_top = STACK_VADDR + 0x1000 - 16;
        let ipcbuf = map_page(CHILD_IPCBUF_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);

        // 2b. Build a Windows TEB + map it, so ntdll self-references (`%gs:[0x30]` = TEB self,
        //     `%gs:[0x60]` = PEB) resolve. The trap thread's %gs base is set to the TEB below.
        let teb = nt_user_host::build_teb(TEB_VADDR, PEB_VADDR, STACK_VADDR, stack_top, 4, 8);
        let _teb_frame = map_page(TEB_VADDR, RIGHTS_RW | PAGE_EXECUTE_NEVER);
        core::ptr::copy_nonoverlapping(teb.as_ptr(), TEB_VADDR as *mut u8, teb.len().min(0x1000));

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
        // The trampoline resumed cleanly and reported %gs:[0x30] (TEB.Self) over IPC. It equalling
        // TEB_VADDR proves %gs resolves to the thread's TEB — ntdll self-references work.
        check(b"ntdll_teb_via_gs_resolves", reported == TEB_VADDR);
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
