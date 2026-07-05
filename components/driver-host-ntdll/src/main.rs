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

    unsafe {
        // 1. Map an executable page + copy ntdll's real stub bytes into it.
        let code = map_page(STUB_VADDR, RIGHTS_RW);
        core::ptr::copy_nonoverlapping(stub.as_ptr(), STUB_VADDR as *mut u8, stub.len());
        // Re-map read-only + executable (W^X) so the CPU can fetch + run it.
        let _ = page_unmap(code);
        let _ = page_map(code, STUB_VADDR, RIGHTS_RO_X, CAP_INIT_THREAD_VSPACE);

        // 2. Stack + IPC buffer for the trap thread.
        let _stack = map_page(STACK_VADDR, RIGHTS_RW_NX);
        let stack_top = STACK_VADDR + 0x1000 - 16;
        let ipcbuf = map_page(CHILD_IPCBUF_VADDR, RIGHTS_RW_NX);

        // 3. A fault endpoint + the trap thread (shares the root's CSpace/VSpace).
        let fault_ep = make_object(OBJ_ENDPOINT);
        let tcb = make_object(OBJ_TCB);
        let _ = tcb_set_space(tcb, fault_ep, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE);
        let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, CHILD_IPCBUF_VADDR, ipcbuf, 0);
        let _ = tcb_write_registers(tcb, STUB_VADDR, stack_top, 0);
        attach_sched_context(tcb);

        // 4. Run it. The stub executes `mov r10,rcx; mov eax,0x33; syscall` — the syscall traps
        //    into seL4, which raises an UnknownSyscall fault delivered to our fault endpoint.
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
        check(
            b"trapped_syscall_dispatched",
            dispatcher.table().lookup(trapped_ssn as u32).map(|e| e.service)
                == Some(NativeService::NtQuerySystemInformation)
                && procs == 1,
        );

        // 7. Complete the round trip: reply so the stub RESUMES with the NTSTATUS in RAX and
        //    executes its `ret`. The `syscall` is at STUB_VADDR+8, so the resume IP is the `ret` at
        //    STUB_VADDR+10 (reply register slot 15 = FaultIP). Slots 4..15 are staged to 0; the
        //    saved SP/RFLAGS are preserved (we send length 16, so slots 16/17 are untouched).
        for i in 4..15 {
            set_reply_mr(i, 0);
        }
        set_reply_mr(15, STUB_VADDR + 10); // FaultIP → the `ret` after the syscall
        let ntstatus = result.status as u64; // RAX the stub returns to its caller
        // ReplyRecv: resume the faulter + wait for its next fault (the `ret` jumps to [SP]=0 → #PF).
        let (_b2, msginfo2, _mr0b) = reply_recv(fault_ep, 16, ntstatus, 0, 0, 0);
        let label2 = msginfo2 >> 12;
        // A *different* fault (VMFault, label != 2) proves the stub resumed past the syscall and ran
        // `ret`; another UnknownSyscall (label 2) would mean it re-executed the syscall (no resume).
        check(b"stub_resumed_after_syscall", label2 != 2);
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
