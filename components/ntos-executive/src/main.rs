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
mod cm_server;
mod io_server;
mod isr;
mod server;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use nt_config_abi::CmReply;
use nt_config_client::ConfigClient;
use nt_io_abi::wire::IoReply;
use nt_io_client::IoClient;
use nt_object_abi::ObReply;
use nt_object_client::ObjectClient;
use nt_syscall::{NativeService, NativeServiceTable, UserlandAbiProfile};
use nt_types::{AccessMask, HandleValue, ObjAttrFlags, ObjectAttributes, ObjectId, UnicodeString};
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
// A SECOND ring set — the executive's side of the Configuration Manager service.
// (Each spawned service maps ITS frames at the shared SUB/COMP/REQ/REP vaddrs above
// in its own VSpace; the executive maps each service's frames at distinct vaddrs.)
pub const CM_SUB_VADDR: u64 = 0x0000_0100_0054_0000;
pub const CM_COMP_VADDR: u64 = 0x0000_0100_0055_0000;
pub const CM_REQ_VADDR: u64 = 0x0000_0100_0056_0000;
pub const CM_REP_VADDR: u64 = 0x0000_0100_0057_0000;
// A THIRD ring set — the executive's side of the I/O Manager service.
pub const IO_SUB_VADDR: u64 = 0x0000_0100_0058_0000;
pub const IO_COMP_VADDR: u64 = 0x0000_0100_0059_0000;
pub const IO_REQ_VADDR: u64 = 0x0000_0100_005A_0000;
pub const IO_REP_VADDR: u64 = 0x0000_0100_005B_0000;
pub const STACK_BASE: u64 = 0x0000_0100_005C_0000;
/// A per-user-thread syscall argument frame, mapped at the SAME vaddr in both the
/// executive and the user thread — so a `UNICODE_STRING` whose `Buffer` points into
/// it is valid in both address spaces (the copyin path for pointer-based `Nt*` args).
pub const SYSARG_VADDR: u64 = 0x0000_0100_005D_0000;
/// Where the executive maps real device MMIO it claims (P1). HPET is exposed by the
/// kernel as a device untyped and isn't used by the kernel, so it's a safe first target.
pub const HPET_PADDR: u64 = 0xFED0_0000;
pub const HPET_VADDR: u64 = 0x0000_0100_005E_0000;
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
pub const CT_IRQ_NTFN: u64 = 3; // the ISR host's cap to the IRQ notification
pub const CT_RESULT_NTFN: u64 = 4; // the ISR host's cap to the result notification
const CN_RADIX: u32 = 5;
const CN_GUARD_BADGE: u64 = 59;
/// Badge the isolated ISR host signals after it handles the interrupt.
const ISR_DONE_BADGE: u64 = 0x80;

// `SysReplyRecv` — reply to a pending fault + receive the next, in one syscall.
const SYS_REPLY_RECV: i64 = -2;
/// `X86IRQIssueIRQHandlerIOAPIC` invocation label — issues an IRQ-handler cap AND
/// programs the IOAPIC redirection-table entry for `pin` → vector+PIC1_VECTOR_BASE.
const LBL_X86_IRQ_ISSUE_IOAPIC: u64 = 64;
/// Badge for the IRQ notification, so a delivered interrupt is distinguishable from
/// "not signalled" (badge 0) when we poll.
const IRQ_BADGE: u64 = 0x40;
/// The user-visible IRQ/vector (a legacy-range stub the kernel routes through
/// irq{V}_entry → handle_interrupt(V)); the HPET's IOAPIC pin is chosen separately.
const IRQ_VECTOR: u64 = 11;

// x86 I/O-port invocation labels + the IOPortControl cap slot (canonical slot 7).
const SLOT_IO_PORT_CONTROL: u64 = 7;
const LBL_IOPORT_CONTROL_ISSUE: u64 = 57;
const LBL_IOPORT_IN32: u64 = 60;
const LBL_IOPORT_OUT32: u64 = 63;
// PCI configuration-space access ports (0xCF8 address, 0xCFC data).
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// HPET register offsets (from the mapped MMIO base).
const HPET_GEN_CONF: u64 = 0x10;
const HPET_MAIN_COUNTER: u64 = 0xF0;
const HPET_T0_CONFIG: u64 = 0x100;
const HPET_T0_COMPARATOR: u64 = 0x108;
/// The executive's own IPC buffer VA (from BootInfo) — stages reply message registers 4+.
static IPC_BUFFER: AtomicU64 = AtomicU64::new(0);

// Registry syscalls use the REAL ntdll SSN numbers (Windows 7 SP1 x64) + the real
// `NativeService` classification via `NativeServiceTable`; a real isolated ntdll
// process registers its own numbers the same way (from_numbers(ntdll.syscall_number)).
const NT_CREATE_KEY: u64 = 0x1D; // NtCreateKey(*OBJECT_ATTRIBUTES)
const NT_QUERY_VALUE_KEY: u64 = 0x18; // NtQueryValueKey(*OBJECT_ATTRIBUTES) → value in RAX
const NT_SET_VALUE_KEY: u64 = 0x5D; // NtSetValueKey(*OBJECT_ATTRIBUTES, value in RDX)

// The Object Manager namespace ops aren't in the `NativeService` enum (a niche
// syscall surface), so they keep synthetic numbers — but now carry a real
// OBJECT_ATTRIBUTES for the by-name variants.
const SSN_OB_CREATE_DIR: u64 = 0x0100; // arg1 = directory index → \Device\Syscall<n>
const SSN_OB_LOOKUP_DIR: u64 = 0x0101; // arg1 = directory index
const SSN_OB_CREATE_BYNAME: u64 = 0x0102; // arg1 = *OBJECT_ATTRIBUTES (a user-supplied path)
const SSN_OB_LOOKUP_BYNAME: u64 = 0x0103; // arg1 = *OBJECT_ATTRIBUTES
const SSN_DONE: u64 = 0x01FF; // arg1 = verdict (1 = all passed)

/// The fixed registry key the syscall front-end reads/writes for the Cm route.
const REG_KEY: &str = r"\Registry\Machine\System\CurrentControlSet\Services\FromSyscall";

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

/// One request/reply SURT channel to an isolated service, parameterized by its data
/// frame vaddrs — so the executive can hold several (one per service).
struct RingChannel<'a> {
    sq: Producer<SurtSqe>,
    cq: Consumer<SurtCqe>,
    signal: Sel4Notify<'a, KernelEnv>,
    wait: Sel4Notify<'a, KernelEnv>,
    req_vaddr: u64,
    rep_vaddr: u64,
    next_id: u64,
}
impl RingChannel<'_> {
    /// One synchronous request/reply: stage `in_buf` in the request frame, push the
    /// SQE, wait for the matching completion, copy the reply payload out. Returns
    /// `(status, flags, information, detail0, detail1)`.
    fn raw(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> (i32, u32, u64, u64, u64) {
        // SAFETY: single request in flight; the ring push/pop orders these writes.
        unsafe {
            let dst = self.req_vaddr as *mut u8;
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
        let _ = self.sq.notify_consumer(&self.signal);
        let mut out = (0i32, 0u32, 0u64, 0u64, 0u64);
        let _ = drain_blocking(&mut self.cq, &self.wait, |cqe: &SurtCqe| {
            if cqe.request_id == id {
                out = (cqe.status, cqe.flags, cqe.information, cqe.detail0, cqe.detail1);
                false
            } else {
                true
            }
        });
        let n = (out.2 as usize).min(out_buf.len());
        // SAFETY: reply frame holds `n` result bytes.
        unsafe {
            let src = self.rep_vaddr as *const u8;
            for (i, slot) in out_buf.iter_mut().enumerate().take(n) {
                *slot = core::ptr::read_volatile(src.add(i));
            }
        }
        out
    }
}

/// The Object Manager transport wrapper.
struct ObChan<'a>(RingChannel<'a>);
impl nt_object_client::Backend for ObChan<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> ObReply {
        let (status, _flags, information, detail0, detail1) = self.0.raw(opcode, in_buf, out_buf);
        ObReply {
            status,
            information: information as u32,
            detail0,
            detail1,
        }
    }
}

/// The Configuration Manager transport wrapper.
struct CmChan<'a>(RingChannel<'a>);
impl nt_config_client::Backend for CmChan<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> CmReply {
        let (status, _flags, information, detail0, detail1) = self.0.raw(opcode, in_buf, out_buf);
        CmReply {
            status,
            information: information as u32,
            detail0,
            detail1,
        }
    }
}

/// The I/O Manager transport wrapper (carries the extra `flags` + a u64 `information`).
struct IoChan<'a>(RingChannel<'a>);
impl nt_io_client::Backend for IoChan<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> IoReply {
        let (status, flags, information, detail0, detail1) = self.0.raw(opcode, in_buf, out_buf);
        IoReply {
            status,
            flags,
            information,
            detail0,
            detail1,
        }
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

/// Issue an IRQ-handler cap for a real IOAPIC `pin`, delivering `IRQ_VECTOR`, into
/// `dest_slot` of the executive's root CNode. This is `X86IRQIssueIRQHandlerIOAPIC`:
/// a 7-word message (msg_regs[0..6]) + one extra cap (the dest CNode root). mr0..2 go
/// in registers, mr3 (pin) in r15, mr4..6 in the IPC buffer, the extra cap at IPC
/// word 122. The kernel also programs IOAPIC RTE[pin] → pin fires vector+0x20.
unsafe fn ioapic_issue_irq_handler(dest_slot: u64, pin: u64) {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 5 * 8) as *mut u64, 0); // mr4 = level    (edge)
    core::ptr::write_volatile((ipc + 6 * 8) as *mut u64, 0); // mr5 = polarity (active-high)
    core::ptr::write_volatile((ipc + 7 * 8) as *mut u64, IRQ_VECTOR); // mr6 = vector
    // caps_or_badges[0] = the dest CNode root (resolved in the caller's cspace).
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, CAP_INIT_THREAD_CNODE);
    // msginfo: label=64, capsUnwrapped=1, extraCaps=1, length=7.
    let msginfo = (LBL_X86_IRQ_ISSUE_IOAPIC << 12) | (1 << 9) | (1 << 7) | 7;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") SLOT_IRQ_CONTROL,
        in("rsi") msginfo,
        in("r10") dest_slot, // mr0 = index (dest slot)
        in("r8") 64u64,      // mr1 = depth (init CNode: guard=0, so depth 64 resolves the slot)
        in("r9") 0u64,       // mr2 = ioapic id (ignored)
        in("r15") pin,       // mr3 = pin
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// The fixed object path for a syscall's directory index.
fn path_for(i: u64) -> &'static str {
    match i {
        0 => "\\Device\\Syscall0",
        1 => "\\Device\\Syscall1",
        _ => "\\Device\\SyscallX",
    }
}

/// The x64 `UNICODE_STRING` a user thread passes to a name-based syscall: a 16-byte
/// header (4 bytes of tail padding before the 8-byte `Buffer`) + UTF-16LE chars the
/// `Buffer` points at. Both live in the shared arg frame (same vaddr in both VSpaces).
#[repr(C)]
#[derive(Copy, Clone)]
struct NtUnicodeString {
    length: u16,         // bytes of the name (excluding NUL)
    maximum_length: u16, // capacity in bytes
    _pad: u32,
    buffer: u64, // vaddr of the UTF-16 chars (into the shared arg frame)
}

/// Copyin a user-supplied path from a `UNICODE_STRING` at `ptr`. Probes like a real
/// kernel: both the header and the `Buffer` range must lie inside the one shared arg
/// frame `[SYSARG_VADDR, SYSARG_VADDR + 4096)` — a hostile user can't steer the read
/// at executive memory. Returns the decoded path.
unsafe fn copyin_user_path(ptr: u64) -> Option<alloc::string::String> {
    let frame_lo = SYSARG_VADDR;
    let frame_hi = SYSARG_VADDR + 0x1000;
    let hdr = core::mem::size_of::<NtUnicodeString>() as u64;
    if ptr < frame_lo || ptr.checked_add(hdr)? > frame_hi {
        return None;
    }
    let us = core::ptr::read_unaligned(ptr as *const NtUnicodeString);
    let len = us.length as u64;
    if len % 2 != 0 || len > 1024 || us.buffer < frame_lo || us.buffer.checked_add(len)? > frame_hi {
        return None;
    }
    let mut units = Vec::with_capacity((len / 2) as usize);
    for i in 0..(len / 2) {
        units.push(core::ptr::read_unaligned((us.buffer + i * 2) as *const u16));
    }
    Some(alloc::string::String::from_utf16_lossy(&units))
}

/// The x64 `OBJECT_ATTRIBUTES` a create/open syscall carries (48 bytes): `Length`,
/// `RootDirectory`, `ObjectName` (→ `UNICODE_STRING`), `Attributes`, and two security
/// pointers we don't use yet. Built by the user in the shared arg frame.
#[repr(C)]
#[derive(Copy, Clone)]
struct RawObjectAttributes {
    length: u32,
    _pad0: u32,
    root_directory: u64,
    object_name: u64, // *UNICODE_STRING
    attributes: u32,
    _pad1: u32,
    security_descriptor: u64,
    security_qos: u64,
}

/// Copyin + decode a user `OBJECT_ATTRIBUTES` at `ptr` into the kernel-side
/// [`ObjectAttributes`]. Probes the header + follows `ObjectName` through the same
/// bounds-checked path copyin — exactly what a real `Nt*` create/open does with the
/// pointer a real ntdll passes.
unsafe fn copyin_object_attributes(ptr: u64) -> Option<ObjectAttributes> {
    let hdr = core::mem::size_of::<RawObjectAttributes>() as u64;
    if ptr < SYSARG_VADDR || ptr.checked_add(hdr)? > SYSARG_VADDR + 0x1000 {
        return None;
    }
    let raw = core::ptr::read_unaligned(ptr as *const RawObjectAttributes);
    let object_name = if raw.object_name == 0 {
        None
    } else {
        Some(UnicodeString::from_str(&copyin_user_path(raw.object_name)?))
    };
    Some(ObjectAttributes {
        root_directory: None,
        object_name,
        attributes: ObjAttrFlags::from_bits_truncate(raw.attributes),
    })
}

/// The absolute NT path an `OBJECT_ATTRIBUTES` names (this cut ignores RootDirectory).
fn oa_path(oa: &ObjectAttributes) -> Option<alloc::string::String> {
    oa.object_name
        .as_ref()
        .map(|n| alloc::string::String::from_utf16_lossy(n.as_units()))
}

/// A raw native syscall from the isolated user thread: SSN in RAX, arg1 in R10
/// (the Windows x64 convention — RCX is clobbered by `syscall`), result in RAX.
unsafe fn native_syscall(ssn: u64, arg1: u64) -> u64 {
    native_syscall2(ssn, arg1, 0)
}

/// Like [`native_syscall`] but with a 2nd arg in RDX (Windows x64 convention).
unsafe fn native_syscall2(ssn: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inout("rax") ssn => ret,
        in("r10") arg1,
        in("rdx") arg2,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

/// The isolated user thread: a separate VSpace/CSpace with no access to the Object
/// Manager — it reaches objects only by trapping `syscall`s the executive services.
#[no_mangle]
#[link_section = ".text.user_entry"]
/// Build a real x64 `OBJECT_ATTRIBUTES` naming `name` in the shared arg frame:
/// header @ 0 → `UNICODE_STRING` @ 48 → UTF-16 chars @ 64. Returns the OA pointer.
unsafe fn write_object_attributes(name: &[u8]) -> u64 {
    let oa_v = SYSARG_VADDR;
    let us_v = SYSARG_VADDR + 48;
    let buf_v = SYSARG_VADDR + 64;
    for (i, &ch) in name.iter().enumerate() {
        core::ptr::write_volatile((buf_v + (i as u64) * 2) as *mut u16, ch as u16);
    }
    core::ptr::write_unaligned(
        us_v as *mut NtUnicodeString,
        NtUnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            _pad: 0,
            buffer: buf_v,
        },
    );
    core::ptr::write_unaligned(
        oa_v as *mut RawObjectAttributes,
        RawObjectAttributes {
            length: 48,
            _pad0: 0,
            root_directory: 0,
            object_name: us_v,
            attributes: 0,
            _pad1: 0,
            security_descriptor: 0,
            security_qos: 0,
        },
    );
    oa_v
}

pub unsafe extern "C" fn user_entry() -> ! {
    // Object Manager route (scalar args — fixed paths by index).
    let r0 = native_syscall(SSN_OB_CREATE_DIR, 0);
    let r0b = native_syscall(SSN_OB_LOOKUP_DIR, 0);
    let r1 = native_syscall(SSN_OB_CREATE_DIR, 1);

    // Object Manager route (pointer arg — a real OBJECT_ATTRIBUTES in the shared frame).
    let oa = write_object_attributes(b"\\Device\\FromUserString");
    let created = native_syscall(SSN_OB_CREATE_BYNAME, oa);
    let found = native_syscall(SSN_OB_LOOKUP_BYNAME, oa);

    // Registry route — REAL ntdll SSNs + a real OBJECT_ATTRIBUTES naming the key.
    let key_oa = write_object_attributes(REG_KEY.as_bytes());
    let ck = native_syscall(NT_CREATE_KEY, key_oa);
    let sk = native_syscall2(NT_SET_VALUE_KEY, key_oa, 42);
    let val = native_syscall(NT_QUERY_VALUE_KEY, key_oa);

    let ok = r0 == 1
        && r0b == 1
        && r1 == 1
        && created == 1
        && found == 1
        && ck == 1
        && sk == 1
        && val == 42;
    let _ = native_syscall(SSN_DONE, ok as u64);
    park()
}

/// Spawn the isolated user thread: its own VSpace (image RO + stack + IPC buffer),
/// its own CNode holding a cap to `fault_ep_c`, and its faults routed there (the
/// kernel's legacy TCBSetSpace resolves the fault cptr in the FAULTER's cspace).
unsafe fn spawn_user_thread(entry: unsafe extern "C" fn() -> !, fault_ep_c: u64, sysarg_c: u64) {
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
    // The shared syscall-arg frame, at the SAME vaddr as in the executive.
    let _ = page_map(sysarg_c, SYSARG_VADDR, RW_NX, pml4);
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

/// Spawn the isolated ISR "driver host" (P1): its own VSpace (image RO + stack + IPC
/// buffer) and a CNode holding ONLY a cap to the IRQ notification + the result
/// notification — least privilege. Its thread (`isr_entry`) blocks on the IRQ
/// notification and, when the real interrupt fires, signals the result notification.
unsafe fn spawn_isr(entry: unsafe extern "C" fn() -> !, irq_cap: u64, result_cap: u64) {
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
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_IRQ_NTFN, irq_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, result_cap, 0);
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

/// Run the native-syscall service loop for the isolated user thread, routing each
/// Ob syscall to the isolated Object Manager service via `client`. Returns
/// `(serviced, verdict)`.
unsafe fn service_user_syscalls<B, CB>(
    user_fault_ep: u64,
    client: &mut ObjectClient<B>,
    cm: &mut ConfigClient<CB>,
) -> (u64, u64)
where
    B: nt_object_client::Backend,
    CB: nt_config_client::Backend,
{
    // The real NT service table: maps the trapped SSN → a `NativeService`. A real
    // ntdll process would register its own numbers here (from its syscall stubs).
    let table = NativeServiceTable::from_numbers(
        UserlandAbiProfile::Windows7,
        &[
            (NativeService::NtCreateKey, NT_CREATE_KEY as u32),
            (NativeService::NtSetValueKey, NT_SET_VALUE_KEY as u32),
            (NativeService::NtQueryValueKey, NT_QUERY_VALUE_KEY as u32),
        ],
    );

    let mut created: [Option<ObjectId>; 2] = [None, None];
    let mut serviced = 0u64;
    let mut verdict = 0u64;
    let (_z, mut mi, mut m0, mut m1, mut m2, mut m3) = ep_recv_full(user_fault_ep);
    loop {
        if (mi >> 12) != 2 {
            break; // not an UnknownSyscall — stop
        }
        let ssn = m0;
        let arg1 = get_recv_mr(9); // R10 = arg1
        let arg2 = m3; // RDX = arg2
        if ssn == SSN_DONE {
            verdict = arg1;
            break; // leave the faulter blocked; test is done
        }
        let resume_ip = m2; // RCX = return address saved by `syscall`
        let sp = get_recv_mr(16);
        let flags = get_recv_mr(17);
        // Registry syscalls go through the real service table + a real OBJECT_ATTRIBUTES.
        let result = if let Some(entry) = table.lookup(ssn as u32) {
            let key = copyin_object_attributes(arg1).as_ref().and_then(oa_path);
            match (entry.service, key) {
                (NativeService::NtCreateKey, Some(k)) => cm.create_key(&k).map(|_| 1).unwrap_or(0),
                (NativeService::NtSetValueKey, Some(k)) => {
                    cm.set_dword(&k, "Answer", arg2 as u32).map(|_| 1).unwrap_or(0)
                }
                (NativeService::NtQueryValueKey, Some(k)) => {
                    cm.query_dword(&k, "Answer").map(|v| v as u64).unwrap_or(0)
                }
                _ => 0,
            }
        } else {
            match ssn {
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
                // Object create/open by a real OBJECT_ATTRIBUTES pointer.
                SSN_OB_CREATE_BYNAME => match copyin_object_attributes(arg1).as_ref().and_then(oa_path) {
                    Some(path) => client.create_directory(&path, true).map(|_| 1).unwrap_or(0),
                    None => 0,
                },
                SSN_OB_LOOKUP_BYNAME => match copyin_object_attributes(arg1).as_ref().and_then(oa_path) {
                    Some(path) if client.lookup(&path, true).is_ok() => 1,
                    _ => 0,
                },
                _ => 0,
            }
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

/// Print `0x` + 8 hex digits (for PCI IDs / BARs).
fn print_hex(v: u32) {
    print_str(b"0x");
    for i in (0..8).rev() {
        let nib = ((v >> (i * 4)) & 0xf) as u8;
        debug_put_char(if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) });
    }
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

/// Stand up one isolated service (the component-launch primitive): create its ring
/// set (2 notifications + 4 frames), map the frames in the executive's own VSpace at
/// `[sub_v, comp_v, req_v, rep_v]` + lay out both ring headers, spawn the service at
/// `entry` seeded with cap copies, and return the executive-side [`RingChannel`] to
/// drive it. Adding a service is now one call + wrapping the channel in its client.
unsafe fn stand_up_service(
    entry: unsafe extern "C" fn() -> !,
    sub_v: u64,
    comp_v: u64,
    req_v: u64,
    rep_v: u64,
) -> RingChannel<'static> {
    let n_sub = make_object(OBJ_NOTIFICATION);
    let n_comp = make_object(OBJ_NOTIFICATION);
    let f_sub = alloc_frame();
    let f_comp = alloc_frame();
    let f_req = alloc_frame();
    let f_rep = alloc_frame();
    // Map the four frames into the executive's own VSpace + lay out both ring headers
    // (broker-init, so the spawned service just attaches — no producer/consumer race).
    let _ = page_map(f_sub, sub_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_comp, comp_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_req, req_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let _ = page_map(f_rep, rep_v, RW_NX, CAP_INIT_THREAD_VSPACE);
    let cfg_sub = RingConfig {
        queue_len: QLEN,
        ring_id: 1,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let cfg_comp = RingConfig {
        queue_len: QLEN,
        ring_id: 2,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let _ = init_ring::<SurtSqe>(sub_v as *mut u8, RING_LEN, &cfg_sub);
    let _ = init_ring::<SurtCqe>(comp_v as *mut u8, RING_LEN, &cfg_comp);
    // The service maps its own cap copies at the shared vaddrs in its own VSpace.
    spawn_service(
        entry,
        &[(CT_N_SUB, copy_cap(n_sub)), (CT_N_COMP, copy_cap(n_comp))],
        copy_cap(f_sub),
        copy_cap(f_comp),
        copy_cap(f_req),
        copy_cap(f_rep),
    );
    let sq = match Producer::<SurtSqe>::attach(sub_v as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let cq = match Consumer::<SurtCqe>::attach(comp_v as *mut u8, RING_LEN) {
        Ok(q) => q,
        Err(_) => park(),
    };
    RingChannel {
        sq,
        cq,
        signal: Sel4Notify::new(&ENV, n_sub),
        wait: Sel4Notify::new(&ENV, n_comp),
        req_vaddr: req_v,
        rep_vaddr: rep_v,
        next_id: 1,
    }
}

/// Claim a real device MMIO page (P1): find the device untyped in BootInfo whose
/// paddr matches `paddr`, retype a device frame from it, and map it at `vaddr` in the
/// executive's VSpace (the kernel makes device frames uncacheable). Returns whether
/// the device untyped was found + mapped. This is how the executive, which owns the
/// hardware caps, hands real MMIO to itself (and later to isolated driver hosts).
unsafe fn claim_device_page(bi: &BootInfo, paddr: u64, vaddr: u64) -> bool {
    let count = bi.untyped.end - bi.untyped.start;
    for i in 0..count {
        let d = bi.untyped_list[i as usize];
        if d.is_device == 1 && d.paddr == paddr {
            let frame = alloc_slot();
            let _ = untyped_retype(bi.untyped.start + i, OBJ_X86_4K_PAGE, PAGING_BITS, 1, frame);
            let _ = page_map(frame, vaddr, RW_NX, CAP_INIT_THREAD_VSPACE);
            return true;
        }
    }
    false
}

/// Issue an x86 I/O-port cap for the inclusive window `[first, last]` into
/// `dest_slot` of the executive's root CNode (from the singleton IOPortControl cap).
/// ABI: mr0=first, mr1=last, mr2=dest_index, mr3=dest_depth, extra cap = dest CNode.
unsafe fn issue_ioport_cap(dest_slot: u64, first: u16, last: u16) {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, CAP_INIT_THREAD_CNODE);
    let msginfo = (LBL_IOPORT_CONTROL_ISSUE << 12) | (1 << 9) | (1 << 7) | 4;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") SLOT_IO_PORT_CONTROL,
        in("rsi") msginfo,
        in("r10") first as u64,     // mr0 = first_port
        in("r8") last as u64,       // mr1 = last_port
        in("r9") dest_slot,         // mr2 = dest_index
        in("r15") 64u64,            // mr3 = dest_depth (init CNode guard=0 → depth 64)
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// `out dx, eax` via an I/O-port cap (no reply).
unsafe fn io_out32(ioport: u64, port: u16, value: u32) {
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") ioport,
        in("rsi") (LBL_IOPORT_OUT32 << 12) | 2,
        in("r10") port as u64,      // mr0 = port
        in("r8") value as u64,      // mr1 = value
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// `in eax, dx` via an I/O-port cap — invoked with SysCall; the read value comes
/// back as the reply's mr0 (r10).
unsafe fn io_in32(ioport: u64, port: u16) -> u32 {
    let value: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_CALL as u64,
        inout("rdi") ioport => _,
        inout("rsi") ((LBL_IOPORT_IN32 << 12) | 1) => _,
        inout("r10") port as u64 => value, // mr0 in = port; reply mr0 = value
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    value as u32
}

/// Read a 32-bit PCI configuration register (mechanism #1: 0xCF8 address / 0xCFC data).
unsafe fn pci_read32(ioport: u64, bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg as u32) & 0xFC);
    io_out32(ioport, PCI_CONFIG_ADDR, addr);
    io_in32(ioport, PCI_CONFIG_DATA)
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

    // The executive front-end allocates (ObjectClient etc.), so give it its own heap.
    map_own_heap();

    // Object Manager: stand it up as an isolated service + drive it as the front-end.
    let mut c = ObjectClient::new(ObChan(stand_up_service(
        server::server_entry,
        SUB_RING_VADDR,
        COMP_RING_VADDR,
        REQ_DATA_VADDR,
        REP_DATA_VADDR,
    )));

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

    // --- Second isolated service: the Configuration Manager (registry) over SURT.
    print_str(b"[ntos-exec] spawning the Configuration Manager as a second isolated service\n");
    let mut cm = ConfigClient::new(CmChan(stand_up_service(
        cm_server::cm_server_entry,
        CM_SUB_VADDR,
        CM_COMP_VADDR,
        CM_REQ_VADDR,
        CM_REP_VADDR,
    )));
    let svc_key = r"\Registry\Machine\System\CurrentControlSet\Services\Demo";
    check(b"exec_cm_ping", cm.ping(), &mut passed);
    check(b"exec_cm_create_key", cm.create_key(svc_key).is_ok(), &mut passed);
    check(b"exec_cm_open_key", cm.open_key(svc_key), &mut passed);
    check(b"exec_cm_set_dword", cm.set_dword(svc_key, "Start", 3).is_ok(), &mut passed);
    check(
        b"exec_cm_query_dword",
        cm.query_dword(svc_key, "Start") == Ok(3),
        &mut passed,
    );

    // --- Third isolated service: the I/O Manager over SURT (open/read/write/close a
    // device backed by a mock driver + an embedded Object Manager, in its own VSpace).
    print_str(b"[ntos-exec] spawning the I/O Manager as a third isolated service\n");
    let mut io = IoClient::new(IoChan(stand_up_service(
        io_server::io_server_entry,
        IO_SUB_VADDR,
        IO_COMP_VADDR,
        IO_REQ_VADDR,
        IO_REP_VADDR,
    )));
    check(b"exec_io_ping", io.ping().is_success(), &mut passed);
    let io_handle = io.open(
        "\\??\\Test0",
        AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
        0,
        0,
        0,
    );
    check(b"exec_io_open", io_handle.is_ok(), &mut passed);
    let ih = io_handle.unwrap_or(HandleValue::NULL);
    check(b"exec_io_write", io.write(ih, 0, b"hello") == Ok(5), &mut passed);
    let mut io_out = [0u8; 8];
    check(
        b"exec_io_read",
        matches!(io.read(ih, 0, &mut io_out), Ok(5)) && &io_out[..5] == b"hello",
        &mut passed,
    );
    check(b"exec_io_close", io.close(ih).is_ok(), &mut passed);

    // --- Native syscall front-end: an isolated USER thread traps `syscall`s; the
    // executive routes each to the isolated Ob service over SURT and replies so the
    // user resumes. User -> executive front-end -> isolated service -> reply.
    print_str(b"[ntos-exec] spawning an isolated user thread; routing its native syscalls to Ob\n");
    let user_fault_ep = make_object(OBJ_ENDPOINT);
    let user_fault_ep_c = copy_cap(user_fault_ep);
    // The shared syscall-arg frame: mapped at SYSARG_VADDR in the executive AND (via
    // the cap copy) at the same vaddr in the user thread — so a user UNICODE_STRING's
    // Buffer pointer resolves in both address spaces.
    let sysarg = alloc_frame();
    let _ = page_map(sysarg, SYSARG_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    spawn_user_thread(user_entry, user_fault_ep_c, copy_cap(sysarg));
    let (serviced, verdict) = service_user_syscalls(user_fault_ep, &mut c, &mut cm);
    check(b"exec_syscall_frontend_serviced", serviced >= 7, &mut passed);
    check(b"exec_syscall_user_verdict_passed", verdict == 1, &mut passed);
    // The directory the user created via a syscall is visible in the isolated Ob service.
    check(
        b"exec_syscall_created_dir_visible",
        c.lookup(path_for(0), true).is_ok(),
        &mut passed,
    );
    // The user-supplied UNICODE_STRING path (copyin'd from the shared frame) created a
    // real object visible in the isolated Ob service.
    check(
        b"exec_syscall_byname_path_visible",
        c.lookup("\\Device\\FromUserString", true).is_ok(),
        &mut passed,
    );
    // The DWORD the user set via a registry syscall is visible in the isolated Cm service.
    check(
        b"exec_syscall_registry_value_visible",
        cm.query_dword(REG_KEY, "Answer") == Ok(42),
        &mut passed,
    );

    // --- P1: real MMIO. Claim the HPET's device memory (a real device untyped from
    // BootInfo) as a frame cap, map it, and read a real hardware register — proving
    // the mapping hits real device memory, not RAM.
    print_str(b"[ntos-exec] P1: claiming real HPET MMIO (0xFED00000) as a device frame\n");
    let mmio_mapped = claim_device_page(bi, HPET_PADDR, HPET_VADDR);
    check(b"exec_hpet_device_untyped_mapped", mmio_mapped, &mut passed);
    if mmio_mapped {
        // HPET General Capabilities + ID (offset 0): bits [31:16] = VENDOR_ID.
        let gcap = core::ptr::read_volatile(HPET_VADDR as *const u32);
        print_str(b"[ntos-exec] HPET GCAP_ID low dword = ");
        print_u64(gcap as u64);
        print_str(b" (vendor ");
        print_u64((gcap >> 16) as u64);
        print_str(b")\n");
        // QEMU's HPET reports the Intel vendor id 0x8086 (= 32902).
        check(b"exec_hpet_mmio_vendor_intel", (gcap >> 16) == 0x8086, &mut passed);
    }

    // --- P1: a real hardware interrupt. Program HPET timer 0 for a one-shot, route
    // it to an IOAPIC pin, get an IRQ-handler cap for that pin (which programs the
    // IOAPIC RTE), bind a badged notification, arm the timer, and confirm the real
    // interrupt is delivered. Poll non-blocking so a misfire fails, never hangs.
    if mmio_mapped {
        print_str(b"[ntos-exec] P1: arming HPET timer 0 -> IOAPIC IRQ-handler cap -> notification\n");
        // Timer 0's INT_ROUTE_CAP (config bits [63:32]) = the IOAPIC pins it may drive.
        let t0cfg = core::ptr::read_volatile((HPET_VADDR + HPET_T0_CONFIG) as *const u64);
        let route_cap = (t0cfg >> 32) as u32;
        check(b"exec_hpet_irq_route_cap_nonzero", route_cap != 0, &mut passed);
        if route_cap != 0 {
            let pin = (31 - route_cap.leading_zeros()) as u64; // highest allowed pin
            print_str(b"[ntos-exec] HPET timer0 IOAPIC pin = ");
            print_u64(pin);
            print_str(b", vector = ");
            print_u64(IRQ_VECTOR);
            print_str(b"\n");

            // The IRQ notification (bound to the handler; the ISR host waits on it) +
            // the result notification (the ISR host signals it). Badged so signals are
            // unambiguous when polled.
            let irq_ntfn = make_object(OBJ_NOTIFICATION);
            let irq_ntfn_badged = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                irq_ntfn_badged,
                irq_ntfn,
                IRQ_BADGE,
            );
            let irq_ntfn_isr = copy_cap(irq_ntfn); // the isolated ISR host waits on this
            let result_ntfn = make_object(OBJ_NOTIFICATION);
            let result_ntfn_badged = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                result_ntfn_badged,
                result_ntfn,
                ISR_DONE_BADGE,
            );
            // Issue the IOAPIC IRQ-handler cap (also programs IOAPIC RTE[pin]) + bind it.
            let handler = alloc_slot();
            ioapic_issue_irq_handler(handler, pin);
            let _ = irq_handler_set_notification(handler, irq_ntfn_badged);
            // Hand the isolated ISR "driver host" ONLY the IRQ + result notifications;
            // its ISR thread blocks on the IRQ and reports via the result notification.
            spawn_isr(isr::isr_entry, irq_ntfn_isr, result_ntfn_badged);

            // Program timer 0: interrupt enable + route to `pin`, edge, one-shot.
            let newcfg = (1u64 << 2) | (pin << 9);
            core::ptr::write_volatile((HPET_VADDR + HPET_T0_CONFIG) as *mut u64, newcfg);
            // Comparator = now + a small delta so it fires within our poll window.
            let now = core::ptr::read_volatile((HPET_VADDR + HPET_MAIN_COUNTER) as *const u64);
            core::ptr::write_volatile(
                (HPET_VADDR + HPET_T0_COMPARATOR) as *mut u64,
                now.wrapping_add(0x20000),
            );
            // Enable the HPET main counter (GEN_CONF bit 0).
            let gc = core::ptr::read_volatile((HPET_VADDR + HPET_GEN_CONF) as *const u64);
            core::ptr::write_volatile((HPET_VADDR + HPET_GEN_CONF) as *mut u64, gc | 1);

            // Block on the RESULT notification. The executive is priority 255, so it
            // must BLOCK (not spin) to yield the CPU to the priority-100 ISR host —
            // which then waits on the IRQ and, when the real interrupt fires, signals
            // us back. (Same pattern as the SURT service waits; the timer delivery is
            // proven, so this returns rather than hangs.)
            let (_z, got, _s, _m) = ep_recv(result_ntfn);
            print_str(b"[ntos-exec] isolated ISR host reported badge = ");
            print_u64(got);
            print_str(b"\n");
            check(
                b"exec_hpet_irq_reached_isolated_isr",
                got == ISR_DONE_BADGE,
                &mut passed,
            );
        }
    }

    // --- P1: PCI enumeration via real x86 port I/O. Get an I/O-port cap for the PCI
    // config ports, walk bus 0, and read each device's vendor/device/class/BAR0/IRQ —
    // the discovery step that finds a real device (its BAR + IRQ) to hand to a host.
    print_str(b"[ntos-exec] P1: enumerating PCI bus 0 via port I/O (0xCF8/0xCFC)\n");
    let pci_io = alloc_slot();
    issue_ioport_cap(pci_io, PCI_CONFIG_ADDR, PCI_CONFIG_DATA + 3); // 0xCF8..=0xCFF
    // Host bridge 00:00.0 — reading its vendor id proves port I/O + config access work.
    let hb = pci_read32(pci_io, 0, 0, 0, 0x00);
    let hb_vendor = (hb & 0xFFFF) as u16;
    check(b"exec_pci_portio_reads_config", hb_vendor != 0xFFFF, &mut passed);
    check(b"exec_pci_host_bridge_intel", hb_vendor == 0x8086, &mut passed);

    let mut count = 0u64;
    let mut found_storage = false;
    let (mut storage_bar5, mut storage_irq) = (0u32, 0u32);
    for dev in 0..32u8 {
        for func in 0..8u8 {
            let vd = pci_read32(pci_io, 0, dev, func, 0x00);
            let vendor = (vd & 0xFFFF) as u16;
            if vendor == 0xFFFF {
                if func == 0 {
                    break; // no function 0 → device absent
                }
                continue;
            }
            count += 1;
            let device = (vd >> 16) as u16;
            let class = pci_read32(pci_io, 0, dev, func, 0x08); // [class][sub][progif][rev]
            let bar0 = pci_read32(pci_io, 0, dev, func, 0x10);
            let irq = pci_read32(pci_io, 0, dev, func, 0x3C) & 0xFF;
            print_str(b"  pci 0:");
            print_u64(dev as u64);
            print_str(b".");
            print_u64(func as u64);
            print_str(b" id=");
            print_hex(((device as u32) << 16) | vendor as u32);
            print_str(b" class=");
            print_hex(class >> 8);
            print_str(b" bar0=");
            print_hex(bar0);
            print_str(b" irq=");
            print_u64(irq as u64);
            print_str(b"\n");
            // A mass-storage controller (class 0x01) — a real device with a BAR + IRQ
            // we can hand to an isolated driver host next (AHCI ABAR = BAR5).
            if (class >> 24) == 0x01 {
                found_storage = true;
                storage_bar5 = pci_read32(pci_io, 0, dev, func, 0x24);
                storage_irq = irq;
            }
        }
    }
    print_str(b"[ntos-exec] PCI devices on bus 0 = ");
    print_u64(count);
    print_str(b"\n");
    check(b"exec_pci_found_multiple_devices", count >= 2, &mut passed);
    check(b"exec_pci_found_storage_controller", found_storage, &mut passed);
    if found_storage {
        print_str(b"[ntos-exec] storage controller ABAR(BAR5)=");
        print_hex(storage_bar5);
        print_str(b" irq=");
        print_u64(storage_irq as u64);
        print_str(b" (a real device to hand an isolated driver host)\n");
    }

    print_str(b"[ntos-exec summary: ");
    print_u64(passed);
    print_str(b"/31 executive->isolated-service checks passed]\n");
    print_str(b"[microtest done]\n");
    park()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_put_char(b'!');
    park()
}
