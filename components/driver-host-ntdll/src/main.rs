//! `ntos-driver-host-ntdll` — the real seL4 **syscall trap**: ntdll executes itself.
//!
//! A bare-metal root task that:
//!  1. maps a real Windows 7 `ntdll` syscall stub (`mov r10,rcx; mov eax,<ssn>; syscall`) into an
//!     **executable** page of its VSpace,
//!  2. spawns a user thread whose entry is that stub, with a **fault endpoint** back to the root,
//!  3. lets the stub's own `syscall` instruction execute — the CPU traps into the seL4 kernel,
//!     which sees a non-seL4 syscall and raises an `UnknownSyscall` fault delivered to the root,
//!  4. recovers the Windows syscall number from the fault (RAX at trap time) and dispatches it
//!     through the NT native syscall dispatcher → the real subsystems.
//!
//! This is the real syscall path: ntdll's own instruction stream traps, and the NT personality
//! services it — no interpretation. Requires `references/ntdll.dll` (gitignored).

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

// User VAs for the trap thread — well clear of the root image/heap/stack.
const STUB_VADDR: u64 = 0x0000_0002_0000_0000; // the executable ntdll stub
const STACK_VADDR: u64 = 0x0000_0002_0010_0000;
const CHILD_IPCBUF_VADDR: u64 = 0x0000_0002_0020_0000;

// Page rights (bit0=write, bit1=read, bit2=PAGE_EXECUTE_NEVER).
const RIGHTS_RW: u64 = 0b011; // read/write, executable (for loading)
const RIGHTS_RO_X: u64 = 0b010; // read-only, executable (the stub)
const RIGHTS_RW_NX: u64 = 0b011 | PAGE_EXECUTE_NEVER;

/// Offset of the real ntdll stub within the executable page (after the trampoline).
const STUB_OFF: usize = 22;
/// The value we inject into RAX in the fault reply — the "NTSTATUS" the stub returns to the
/// trampoline, which reports it back so we can confirm the whole round trip carried our value.
const REPORT_SENTINEL: u64 = 0x5EC0_FFEE;

/// Build the trap thread's code page: a trampoline that `call`s the real ntdll `stub` (so the
/// stub's `ret` returns cleanly), then reports RAX via a real seL4 `SysSend(rdi=done_ep, mr0=rax)`
/// — a *valid* seL4 syscall, so it does not trap. `stub` is placed at [`STUB_OFF`].
fn build_trap_code(stub: &[u8]) -> ([u8; 64], usize) {
    let mut code = [0u8; 64];
    // call stub (E8 rel32); the stub sits at STUB_OFF, the next instruction is at offset 5.
    code[0] = 0xE8;
    code[1..5].copy_from_slice(&((STUB_OFF as i32) - 5).to_le_bytes());
    // mov r10, rax  — mr0 = the NTSTATUS the stub returned.
    code[5..8].copy_from_slice(&[0x49, 0x89, 0xC2]);
    // mov esi, 1    — MessageInfo: length 1, label 0.
    code[8] = 0xBE;
    code[9..13].copy_from_slice(&1u32.to_le_bytes());
    // mov edx, -5   — SYS_SEND (the kernel reads the seL4 syscall number from RDX as i32).
    code[13] = 0xBA;
    code[14..18].copy_from_slice(&0xFFFF_FFFBu32.to_le_bytes());
    // syscall       — real seL4 Send to done_ep (rdi), reporting RAX.
    code[18..20].copy_from_slice(&[0x0F, 0x05]);
    // jmp $         — spin after reporting.
    code[20..22].copy_from_slice(&[0xEB, 0xFE]);
    // The real ntdll syscall stub (mov r10,rcx; mov eax,<ssn>; syscall; ret).
    code[STUB_OFF..STUB_OFF + stub.len()].copy_from_slice(stub);
    (code, STUB_OFF + stub.len())
}

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

/// The root's IPC buffer VA (from BootInfo) — used to stage reply message registers 4+.
static IPC_BUFFER: AtomicU64 = AtomicU64::new(0);

const SYS_REPLY_RECV: i64 = -2;

/// Reply to the pending fault (resuming the faulter with the staged register message) and receive
/// the next fault, in one `SysReplyRecv`. `reply_len` message registers are sent: `r0..r3` here,
/// `4..reply_len` from the IPC buffer (which the caller must have written). Returns the next
/// fault's `(badge, msginfo, mr0)`.
unsafe fn reply_recv(recv_ep: u64, reply_len: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> (u64, u64, u64) {
    let badge: u64;
    let msginfo: u64;
    let mr0: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_REPLY_RECV as u64,
        inout("rdi") recv_ep => badge,
        inout("rsi") reply_len => msginfo, // MessageInfo: length in low bits, label 0 (restart)
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

/// Stage a reply message register (index `i >= 4`) into the IPC buffer, at `ipc_buffer + 8 + i*8`.
unsafe fn set_reply_mr(i: usize, v: u64) {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    let p = (base + 8 + (i as u64) * 8) as *mut u64;
    core::ptr::write_volatile(p, v);
}

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

/// Retype an object from the init untyped into a fresh slot.
unsafe fn make_object(obj: u64) -> u64 {
    let s = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, obj, 0, 1, s);
    s
}

/// Map one fresh 4 KiB frame at `vaddr` in the root's VSpace with `rights`, creating the
/// PDPT/PD/PT for its region. Returns the frame cap.
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

unsafe fn attach_sched_context(tcb: u64) {
    let sc = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc);
    let _ = sched_control_configure(SLOT_SCHED_CONTROL, sc, 10, 10);
    let _ = sched_context_bind(sc, tcb);
}

fn run() {
    // The subsystems the trapped syscall dispatches to.
    let mut cm = ConfigManager::new();
    cm.register_service("Svc", "svc.sys", None, None, 3, 1);
    cm.set_service_parameter("Svc", "Answer", RegistryValueType::Dword, 42u32.to_le_bytes().to_vec());
    let fs = FileSystem::new(MemFs::with_fixture());
    let mut services = KernelServices::new(WindowsProfile::windows7_sp1(), cm, fs, alloc::vec::Vec::new());
    services.system_time_100ns = 0x01DA_0000_0000_0000;

    // The real ntdll: build the Win7 service table (real numbers) + locate NtQuerySystemInformation.
    let ntdll = match NtdllImage::load(NTDLL, 0x1_8000_0000) {
        Ok(i) => i,
        Err(_) => {
            check(b"ntdll_parsed", false);
            return;
        }
    };
    let want_ssn = ntdll.syscall_number("NtQuerySystemInformation").unwrap_or(0xFFFF);
    check(b"ntdll_parsed", ntdll.syscall_stub_count() > 300 && want_ssn == 0x33);

    // The real stub bytes straight out of ntdll's .text (its own instruction stream).
    let export_rva = ntdll.export("NtQuerySystemInformation").unwrap().rva;
    let pe = PeFile::parse(NTDLL).unwrap();
    let stub = pe.bytes_at_rva(export_rva, 16).unwrap();

    let (code, code_len) = build_trap_code(stub);

    unsafe {
        // 1. Map an executable page + copy the trampoline + real ntdll stub into it.
        let page = map_page(STUB_VADDR, RIGHTS_RW);
        core::ptr::copy_nonoverlapping(code.as_ptr(), STUB_VADDR as *mut u8, code_len);
        // Re-map read-only + executable (W^X) so the CPU can fetch + run it.
        let _ = page_unmap(page);
        let _ = page_map(page, STUB_VADDR, RIGHTS_RO_X, CAP_INIT_THREAD_VSPACE);

        // 2. Stack + IPC buffer for the trap thread.
        let _stack = map_page(STACK_VADDR, RIGHTS_RW_NX);
        let stack_top = STACK_VADDR + 0x1000 - 16;
        let ipcbuf = map_page(CHILD_IPCBUF_VADDR, RIGHTS_RW_NX);

        // 3. A fault endpoint (for the syscall trap) + a done endpoint (for the trampoline's
        //    result report) + the trap thread (shares the root's CSpace/VSpace).
        let fault_ep = make_object(OBJ_ENDPOINT);
        let done_ep = make_object(OBJ_ENDPOINT);
        let tcb = make_object(OBJ_TCB);
        let _ = tcb_set_space(tcb, fault_ep, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
        let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, CHILD_IPCBUF_VADDR, ipcbuf, 0);
        // Entry = the trampoline (offset 0); RDI (arg0) = done_ep for its `SysSend`.
        let _ = tcb_write_registers(tcb, STUB_VADDR, stack_top, done_ep);
        attach_sched_context(tcb);

        // 4. Run it. The trampoline `call`s the stub; the stub's `mov eax,0x33; syscall` traps into
        //    seL4, which raises an UnknownSyscall fault delivered to our fault endpoint.
        let _ = tcb_resume(tcb);
        print_str(b"  ... resumed trap thread; waiting for ntdll's syscall to trap\n");
        let (_z, _badge, msginfo, mr0) = ep_recv(fault_ep);

        // 5. The fault arrived. UnknownSyscall label = 2; RAX (the Windows SSN) is msg[0] = mr0.
        let label = msginfo >> 12;
        let trapped_ssn = mr0;
        check(b"ntdll_syscall_trapped", label == 2 && trapped_ssn == want_ssn as u64);

        // 6. Dispatch the trapped syscall number through the real subsystems.
        let dispatcher = NativeSyscallDispatcher::new(ntdll.service_table());
        let origin = SyscallOrigin::new(4, 4, ProcessorMode::UserMode);
        let result = dispatcher.dispatch(trapped_ssn as u32, &[0, 0, 0, 0], &origin, &mut services);
        let procs = if result.output.len() >= 4 {
            u32::from_le_bytes([result.output[0], result.output[1], result.output[2], result.output[3]])
        } else {
            0
        };
        let _ = result;
        check(
            b"trapped_syscall_dispatched",
            dispatcher.table().lookup(trapped_ssn as u32).map(|e| e.service)
                == Some(NativeService::NtQuerySystemInformation)
                && procs == 1,
        );

        // 7. Reply so the stub RESUMES with our value in RAX and runs its `ret` back into the
        //    trampoline. The `syscall` is at STUB_OFF+8, so the resume IP is the `ret` at STUB_OFF+10
        //    (reply slot 15 = FaultIP). Slot 5 = RDI = done_ep (preserved for the trampoline's Send);
        //    slots 4/6..15 = 0; SP/RFLAGS are preserved (reply length 16). Then recv the trampoline's
        //    clean result report on `done_ep` — no page fault.
        for i in 4..15 {
            set_reply_mr(i, 0);
        }
        set_reply_mr(5, done_ep); // RDI → done_ep (survives the reply into the trampoline)
        set_reply_mr(15, STUB_VADDR + STUB_OFF as u64 + 10); // FaultIP → the `ret`
        let (_b2, _mi2, reported) = reply_recv(done_ep, 16, REPORT_SENTINEL, 0, 0, 0);
        // The trampoline reported RAX back over IPC: a clean resume (no fault) carrying our value.
        check(b"stub_resumed_clean_and_reported", reported == REPORT_SENTINEL);
    }
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);
    IPC_BUFFER.store(bi.ipc_buffer as u64, Ordering::Relaxed);

    print_str(b"[ntos-ntdll] real seL4 syscall trap: ntdll executes itself\n");
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
