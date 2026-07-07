//! `ntos-executive` — the trusted NT executive core (P0 seed).
//!
//! The root task the rust-micro kernel boots. It owns the root untyped and the
//! hardware capabilities, spawns the NT executive **services** as isolated seL4
//! components (own CSpace/VSpace), wires the SURT rings between them + itself, and
//! (later) hosts the native syscall trap front-end.
//!
//! This first increment stands up the **Object Manager as an isolated service
//! component** and drives it *from the executive itself* — the executive is the
//! front-end/client, not a spawned test client. It proves the executive shape:
//! broker + front-end composing a real isolated service over SURT + cap transfer.
//! (Reuses `object-service`'s proven server + spawn machinery.)

#![no_std]
#![no_main]

extern crate alloc;

// Re-export the kernel ABI at crate root so `server` can `use crate::*`.
pub use sel4_rt::*;

mod allocator;
mod server;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use nt_object_abi::ObReply;
use nt_object_client::{Backend, ObjectClient};
use nt_types::{AccessMask, ObjectId};
use surt_sel4::surt_core::surt_abi::{feature, role, SurtCqe, SurtSqe};
use surt_sel4::surt_core::{init_ring, Consumer, Producer, RingConfig};
use surt_sel4::{drain_blocking, CPtr, Sel4Env, Sel4Notify};

// SURT's wakeup contract: signal a notification / wait on it.
pub struct KernelEnv;
impl Sel4Env for KernelEnv {
    fn signal(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Send length 0 = seL4_Signal.
        unsafe {
            syscall5(SYS_SEND, ntfn, 0, 0, 0, 0);
        }
    }
    fn wait(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Recv = seL4_Wait.
        unsafe {
            let _ = ep_recv(ntfn);
        }
    }
}
pub static ENV: KernelEnv = KernelEnv;

// Component vaddr layout — all inside the one 2 MiB PT of each component. These
// vaddrs are used in BOTH the executive's own VSpace (front-end side) and each
// spawned service's VSpace (they map their own copies of the same frames).
pub const IMAGE_BASE: u64 = 0x0000_0100_0040_0000;
pub const SUB_RING_VADDR: u64 = 0x0000_0100_0050_0000;
pub const COMP_RING_VADDR: u64 = 0x0000_0100_0051_0000;
pub const REQ_DATA_VADDR: u64 = 0x0000_0100_0052_0000;
pub const REP_DATA_VADDR: u64 = 0x0000_0100_0053_0000;
pub const STACK_BASE: u64 = 0x0000_0100_005C_0000;
pub const IPCBUF_VADDR: u64 = 0x0000_0100_005F_B000;

pub const STACK_FRAMES: u64 = 4; // 16 KiB
pub const RING_LEN: usize = 4096;
pub const REP_DATA_LEN: usize = 4096;
const QLEN: u32 = 8;
/// Read/write, non-executable — data regions (heap, stack, rings, buffers).
const RW_NX: u64 = 3 | PAGE_EXECUTE_NEVER;

// A spawned component's own CNode cptrs.
pub const CT_PML4: u64 = 2;
pub const CT_N_SUB: u64 = 3;
pub const CT_N_COMP: u64 = 4;
pub const CT_FAULT: u64 = 6; // a user thread's own cap to its fault endpoint
const CN_RADIX: u32 = 5;
const CN_GUARD_BADGE: u64 = 59;

// `SysReplyRecv` — reply to a pending fault + receive the next, in one syscall.
const SYS_REPLY_RECV: i64 = -2;
/// The executive's own IPC buffer VA (from BootInfo) — stages reply message registers 4+.
static IPC_BUFFER: AtomicU64 = AtomicU64::new(0);

// The native "syscall" numbers the isolated user thread issues (we own both sides;
// these stand in for the ntdll SSNs a real user process would trap with).
const SSN_OB_CREATE_DIR: u64 = 0x0100; // arg1 = directory index → \Device\Syscall<n>
const SSN_OB_LOOKUP_DIR: u64 = 0x0101; // arg1 = directory index
const SSN_DONE: u64 = 0x01FF; // arg1 = verdict (1 = all passed)

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_START: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_COUNT: AtomicU64 = AtomicU64::new(0);

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}
unsafe fn alloc_frame() -> u64 {
    let s = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, s);
    s
}
unsafe fn copy_cap(src: u64) -> u64 {
    let d = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, d, src, 0);
    d
}
unsafe fn make_object(obj: u64) -> u64 {
    let s = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, obj, 0, 1, s);
    s
}
unsafe fn attach_sched_context(tcb: u64) {
    let sc = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_SCHED_CONTEXT, SCHED_CONTEXT_BITS, 1, sc);
    let _ = sched_control_configure(SLOT_SCHED_CONTROL, sc, 10, 10);
    let _ = sched_context_bind(sc, tcb);
}

/// Map the executive's OWN heap (so its front-end can allocate). The root image's
/// `.bss` is fixed at boot; the allocator's arena lives at `HEAP_BASE` past it.
unsafe fn map_own_heap() {
    for i in 0..allocator::HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(
            f,
            allocator::HEAP_BASE as u64 + i * 0x1000,
            RW_NX,
            CAP_INIT_THREAD_VSPACE,
        );
    }
}

/// Build a spawned service's VSpace: image RO+X, private heap, private stack, and
/// the four shared SURT frames at the shared vaddrs.
unsafe fn build_service_vspace(sub: u64, comp: u64, req: u64, rep: u64) -> u64 {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..allocator::HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, RW_NX, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let _ = page_map(sub, SUB_RING_VADDR, RW_NX, pml4);
    let _ = page_map(comp, COMP_RING_VADDR, RW_NX, pml4);
    let _ = page_map(req, REQ_DATA_VADDR, RW_NX, pml4);
    let _ = page_map(rep, REP_DATA_VADDR, RW_NX, pml4);
    pml4
}

/// Spawn one isolated service component at `entry`, seeded with `seeds`.
unsafe fn spawn_service(
    entry: unsafe extern "C" fn() -> !,
    seeds: &[(u64, u64)],
    sub: u64,
    comp: u64,
    req: u64,
    rep: u64,
) {
    let pml4 = build_service_vspace(sub, comp, req, rep);
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    for &(slot, src) in seeds {
        let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, slot, src, 0);
    }
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, 0, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

// --- The executive's front-end: an ObjectClient over the SURT ring to the
// isolated Object Manager service. -------------------------------------------

struct SurtBackend<'a> {
    sq: Producer<SurtSqe>,
    cq: Consumer<SurtCqe>,
    signal_request: Sel4Notify<'a, KernelEnv>,
    wait_completion: Sel4Notify<'a, KernelEnv>,
    next_id: u64,
}
impl Backend for SurtBackend<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> ObReply {
        // SAFETY: single request in flight; the ring push/pop orders these writes.
        unsafe {
            let dst = REQ_DATA_VADDR as *mut u8;
            for (i, b) in in_buf.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        let sqe = SurtSqe {
            opcode,
            len: in_buf.len() as u32,
            request_id: id,
            offset: 0,
            ..Default::default()
        };
        while self.sq.try_push(sqe).is_err() {
            yield_now();
        }
        let _ = self.sq.notify_consumer(&self.signal_request);
        let mut reply = ObReply::default();
        let _ = drain_blocking(&mut self.cq, &self.wait_completion, |cqe: &SurtCqe| {
            if cqe.request_id == id {
                reply = ObReply {
                    status: cqe.status,
                    information: cqe.information as u32,
                    detail0: cqe.detail0,
                    detail1: cqe.detail1,
                };
                false
            } else {
                true
            }
        });
        let n = (reply.information as usize).min(out_buf.len());
        // SAFETY: reply frame holds `n` result bytes.
        unsafe {
            let src = REP_DATA_VADDR as *const u8;
            for (i, slot) in out_buf.iter_mut().enumerate().take(n) {
                *slot = core::ptr::read_volatile(src.add(i));
            }
        }
        reply
    }
}

// --- Native syscall trap front-end -----------------------------------------
// The executive catches a user thread's `syscall` (delivered as a seL4
// UnknownSyscall fault), routes it to the owning isolated service over SURT, and
// replies register-accurately so the user resumes past the syscall. (Trap/reply
// mechanics ported from driver-host-ntdll, which services real ntdll.)

/// Receive an UnknownSyscall fault: `(badge, msginfo, mr0..mr3)` = RAX(SSN), RBX,
/// RCX(=return IP), RDX. Saved regs 4+ land in this thread's IPC buffer.
unsafe fn ep_recv_full(ep: u64) -> (u64, u64, u64, u64, u64, u64) {
    let badge: u64;
    let msginfo: u64;
    let mr0: u64;
    let mr1: u64;
    let mr2: u64;
    let mr3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_RECV as u64,
        inout("rdi") ep => badge,
        lateout("rsi") msginfo,
        lateout("r10") mr0,
        lateout("r8") mr1,
        lateout("r9") mr2,
        lateout("r15") mr3,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (badge, msginfo, mr0, mr1, mr2, mr3)
}

/// Reply to the pending fault (resume the faulter with the staged registers) + recv
/// the next fault. `r0..r3` → reply MRs 0..3 (RAX,RBX,RCX,RDX); MRs 4+ from `set_reply_mr`.
unsafe fn reply_recv_full(recv_ep: u64, reply_len: u64, r0: u64, r1: u64, r2: u64, r3: u64) -> (u64, u64, u64, u64, u64) {
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
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    (msginfo, mr0, mr1, mr2, mr3)
}

unsafe fn set_reply_mr(i: usize, v: u64) {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((base + 8 + (i as u64) * 8) as *mut u64, v);
}
unsafe fn get_recv_mr(i: usize) -> u64 {
    let base = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::read_volatile((base + 8 + (i as u64) * 8) as *const u64)
}

/// The fixed object path for a syscall's directory index.
fn path_for(i: u64) -> &'static str {
    match i {
        0 => "\\Device\\Syscall0",
        1 => "\\Device\\Syscall1",
        _ => "\\Device\\SyscallX",
    }
}

/// A raw native syscall from the isolated user thread: SSN in RAX, arg1 in R10
/// (the Windows x64 convention — RCX is clobbered by `syscall`), result in RAX.
unsafe fn ob_syscall(ssn: u64, arg1: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inout("rax") ssn => ret,
        in("r10") arg1,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

/// The isolated user thread: a separate VSpace/CSpace with no access to the Object
/// Manager — it reaches objects only by trapping `syscall`s the executive services.
#[no_mangle]
#[link_section = ".text.user_entry"]
pub unsafe extern "C" fn user_entry() -> ! {
    let r0 = ob_syscall(SSN_OB_CREATE_DIR, 0);
    let r0b = ob_syscall(SSN_OB_LOOKUP_DIR, 0);
    let r1 = ob_syscall(SSN_OB_CREATE_DIR, 1);
    let ok = r0 == 1 && r0b == 1 && r1 == 1;
    let _ = ob_syscall(SSN_DONE, ok as u64);
    park()
}

/// Spawn the isolated user thread: its own VSpace (image RO + stack + IPC buffer),
/// its own CNode holding a cap to `fault_ep_c`, and its faults routed there (the
/// kernel's legacy TCBSetSpace resolves the fault cptr in the FAULTER's cspace).
unsafe fn spawn_user_thread(entry: unsafe extern "C" fn() -> !, fault_ep_c: u64) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, IMAGE_BASE, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, IMAGE_BASE, pml4);
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep_c, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, 100);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

/// Run the native-syscall service loop for the isolated user thread, routing each
/// Ob syscall to the isolated Object Manager service via `client`. Returns
/// `(serviced, verdict)`.
unsafe fn service_user_syscalls<B: Backend>(
    user_fault_ep: u64,
    client: &mut ObjectClient<B>,
) -> (u64, u64) {
    let mut created: [Option<ObjectId>; 2] = [None, None];
    let mut serviced = 0u64;
    let mut verdict = 0u64;
    let (_z, mut mi, mut m0, mut m1, mut m2, mut m3) = ep_recv_full(user_fault_ep);
    loop {
        if (mi >> 12) != 2 {
            break; // not an UnknownSyscall — stop
        }
        let ssn = m0;
        let arg1 = get_recv_mr(9); // R10
        if ssn == SSN_DONE {
            verdict = arg1;
            break; // leave the faulter blocked; test is done
        }
        let resume_ip = m2; // RCX = return address saved by `syscall`
        let sp = get_recv_mr(16);
        let flags = get_recv_mr(17);
        let result = match ssn {
            SSN_OB_CREATE_DIR => {
                let i = arg1 as usize;
                match client.create_directory(path_for(arg1), true) {
                    Ok(id) => {
                        if i < 2 {
                            created[i] = Some(id);
                        }
                        1
                    }
                    Err(_) => 0,
                }
            }
            SSN_OB_LOOKUP_DIR => {
                let i = arg1 as usize;
                match client.lookup(path_for(arg1), true) {
                    Ok(id) if i < 2 && created[i] == Some(id) => 1,
                    _ => 0,
                }
            }
            _ => 0,
        };
        serviced += 1;
        // Reply: RAX = result, resume at the return IP, preserve SP/FLAGS.
        set_reply_mr(15, resume_ip);
        set_reply_mr(16, sp);
        set_reply_mr(17, flags);
        let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(user_fault_ep, 18, result, m1, 0, m3);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    (serviced, verdict)
}

fn check(name: &[u8], ok: bool, passed: &mut u64) {
    if ok {
        print_str(b"  PASS ");
        *passed += 1;
    } else {
        print_str(b"  FAIL ");
    }
    print_str(name);
    print_str(b"\n");
}

fn park() -> ! {
    loop {
        yield_now();
    }
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);
    IPC_BUFFER.store(bi.ipc_buffer as u64, Ordering::Relaxed);
    let img = bi.user_image_frames;
    IMAGE_FRAMES_START.store(img.start, Ordering::Relaxed);
    IMAGE_FRAMES_COUNT.store(img.end - img.start, Ordering::Relaxed);

    print_str(b"[ntos-exec] NT executive core: spawning the Object Manager as an isolated service\n");

    // The executive front-end allocates (ObjectClient), so give it its own heap.
    map_own_heap();

    // Shared reflector objects (the executive owns the untyped).
    let n_sub = make_object(OBJ_NOTIFICATION);
    let n_comp = make_object(OBJ_NOTIFICATION);
    let f_sub = alloc_frame();
    let f_comp = alloc_frame();
    let f_req = alloc_frame();
    let f_rep = alloc_frame();

    // Map the four frames into the EXECUTIVE's own VSpace (front-end side) + lay
    // out both ring headers, so the spawned service just attaches.
    let _ = page_map(f_sub, SUB_RING_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_comp, COMP_RING_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_req, REQ_DATA_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_rep, REP_DATA_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    let cfg_sub = RingConfig {
        queue_len: QLEN,
        ring_id: 1,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let _ = init_ring::<SurtSqe>(SUB_RING_VADDR as *mut u8, RING_LEN, &cfg_sub);
    let cfg_comp = RingConfig {
        queue_len: QLEN,
        ring_id: 2,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let _ = init_ring::<SurtCqe>(COMP_RING_VADDR as *mut u8, RING_LEN, &cfg_comp);

    // Second caps for the service's own CSpace/VSpace.
    let n_sub_c = copy_cap(n_sub);
    let n_comp_c = copy_cap(n_comp);
    let f_sub_c = copy_cap(f_sub);
    let f_comp_c = copy_cap(f_comp);
    let f_req_c = copy_cap(f_req);
    let f_rep_c = copy_cap(f_rep);

    // Spawn the Object Manager service (isolated): it waits on N_SUB, signals N_COMP.
    spawn_service(
        server::server_entry,
        &[(CT_N_SUB, n_sub_c), (CT_N_COMP, n_comp_c)],
        f_sub_c,
        f_comp_c,
        f_req_c,
        f_rep_c,
    );

    // The executive front-end drives the isolated service over SURT (it signals
    // N_SUB, waits N_COMP) — a real Object Manager stack across an isolation boundary.
    let sq = match Producer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let cq = match Consumer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let mut c = ObjectClient::new(SurtBackend {
        sq,
        cq,
        signal_request: Sel4Notify::new(&ENV, n_sub),
        wait_completion: Sel4Notify::new(&ENV, n_comp),
        next_id: 1,
    });

    let mut passed = 0u64;
    check(b"exec_ob_ping", c.ping().is_success(), &mut passed);
    let created = c.create_directory("\\Device\\Test0", true);
    check(b"exec_ob_create_directory", created.is_ok(), &mut passed);
    let id = created.unwrap_or(ObjectId::NULL);
    check(b"exec_ob_lookup", c.lookup("\\Device\\Test0", true) == Ok(id), &mut passed);
    let handle = c.open("\\Device\\Test0", AccessMask::GENERIC_READ, None, true);
    check(b"exec_ob_open", handle.is_ok(), &mut passed);
    check(
        b"exec_ob_create_symbolic_link",
        c.create_symbolic_link("\\??\\Link", "\\Device\\Test0", true).is_ok(),
        &mut passed,
    );
    check(
        b"exec_ob_lookup_via_symlink",
        c.lookup("\\??\\Link", true) == Ok(id),
        &mut passed,
    );
    let expected: Vec<u16> = "\\Device\\Test0".encode_utf16().collect();
    let target = c.query_symbolic_link("\\??\\Link", true);
    check(
        b"exec_ob_query_symbolic_link",
        matches!(&target, Ok(t) if t.as_slice() == expected.as_slice()),
        &mut passed,
    );
    match handle {
        Ok(h) => check(b"exec_ob_close_handle", c.close_handle(h).is_ok(), &mut passed),
        Err(_) => check(b"exec_ob_close_handle", false, &mut passed),
    }

    // --- Native syscall front-end: an isolated USER thread traps `syscall`s; the
    // executive routes each to the isolated Ob service over SURT and replies so the
    // user resumes. User -> executive front-end -> isolated service -> reply.
    print_str(b"[ntos-exec] spawning an isolated user thread; routing its native syscalls to Ob\n");
    let user_fault_ep = make_object(OBJ_ENDPOINT);
    let user_fault_ep_c = copy_cap(user_fault_ep);
    spawn_user_thread(user_entry, user_fault_ep_c);
    let (serviced, verdict) = service_user_syscalls(user_fault_ep, &mut c);
    check(b"exec_syscall_frontend_serviced", serviced >= 3, &mut passed);
    check(b"exec_syscall_user_verdict_passed", verdict == 1, &mut passed);
    // The directory the user created via a syscall is visible in the isolated Ob service.
    check(
        b"exec_syscall_created_dir_visible",
        c.lookup(path_for(0), true).is_ok(),
        &mut passed,
    );

    print_str(b"[ntos-exec summary: ");
    print_u64(passed);
    print_str(b"/11 executive->isolated-service checks passed]\n");
    print_str(b"[microtest done]\n");
    park()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_put_char(b'!');
    park()
}
