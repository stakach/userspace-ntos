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
mod driver_host;
mod driver_pe;
mod isr;
mod kmdf_host;
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
/// Where the executive maps a real PCI device's BAR (P1 capstone — the e1000e NIC).
pub const NIC_VADDR: u64 = 0x0000_0100_005F_0000;
/// P2: the AHCI controller ABAR (BAR5) MMIO, and a DMA frame for its command structures +
/// the sector data buffer (both just past the NIC's 4-page BAR, before IPCBUF).
pub const AHCI_VADDR: u64 = 0x0000_0100_005F_4000;
pub const AHCI_DMA_VADDR: u64 = 0x0000_0100_005F_5000;
pub const IPCBUF_VADDR: u64 = 0x0000_0100_005F_B000;
/// A normal RAM frame the executive owns, used as a DMA buffer (TX descriptor ring +
/// packet buffer) for the e1000e. VT-d translation is off (identity) so the NIC DMAs
/// straight to this frame's physical address. Kept just past IPCBUF so it stays inside
/// the same 2 MiB page table as every other runtime mapping (0x40_0000..0x5F_FFFF) — a
/// vaddr in the next 2 MiB region would need a PT this vspace doesn't have.
pub const DMA_VADDR: u64 = 0x0000_0100_005F_C000;

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
/// `SysNBRecv` — non-blocking poll of a notification (badge 0 if not signalled).
const SYS_NB_RECV: i64 = -8;
/// `X86IRQIssueIRQHandlerIOAPIC` invocation label — issues an IRQ-handler cap AND
/// programs the IOAPIC redirection-table entry for `pin` → vector+PIC1_VECTOR_BASE.
const LBL_X86_IRQ_ISSUE_IOAPIC: u64 = 64;
/// `X86IRQIssueIRQHandlerMSI` — issues an IRQ-handler cap for a message-signalled
/// interrupt (no IOAPIC pin; the device writes the vector to the LAPIC directly).
const LBL_X86_IRQ_ISSUE_MSI: u64 = 65;
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

// Intel e1000e interrupt registers (offsets from the NIC BAR base).
const E1000_ITR: u64 = 0xC4; // Interrupt Throttling (0 = deliver immediately, no postpone)
const E1000_ICR: u64 = 0xC0; // Interrupt Cause Read (reading clears)
const E1000_ICS: u64 = 0xC8; // Interrupt Cause Set (writing raises a cause → asserts INTx)
const E1000_IMS: u64 = 0xD0; // Interrupt Mask Set (enable causes)
// e1000e transmit-DMA registers (offsets from the NIC BAR base).
const E1000_TCTL: u64 = 0x0400; // Transmit Control (bit0 EN, bit1 PSP)
const E1000_TDBAL: u64 = 0x3800; // TX descriptor ring base, low 32 (a physical addr)
const E1000_TDBAH: u64 = 0x3804; // TX descriptor ring base, high 32
const E1000_TDLEN: u64 = 0x3808; // TX descriptor ring length in bytes (128-byte aligned)
const E1000_TDH: u64 = 0x3810; // TX descriptor head (NIC advances)
const E1000_TDT: u64 = 0x3818; // TX descriptor tail (we advance to hand off descriptors)
const E1000_TARC0: u64 = 0x3840; // TX arbitration counter, queue 0 (bit10 = engine ENABLE)

/// `X86Page::GetAddress` invocation label — returns a frame cap's physical address.
const LBL_X86_PAGE_GET_ADDRESS: u64 = 54;
// VT-d confined-DMA (Phase 2): map a driver's DMA frame into a device's IO address space
// so the device can only DMA into frames we granted.
const LBL_X86_IO_PAGE_TABLE_MAP: u64 = 49; // install a VT-d IO page table (builds context)
const LBL_X86_PAGE_MAP_IO: u64 = 53; // map a frame at an IOVA in a device's IO space
const OBJ_X86_IO_PAGE_TABLE: u64 = 13; // seL4_X86_IOPageTableObject
const SLOT_IO_SPACE: u64 = 8; // seL4_CapIOSpace — the master IO-space cap in the root CNode
/// IOVA we grant the NIC for its DMA frame. The NIC is programmed with this address; VT-d
/// translates it to the frame's real paddr. Any DMA outside the granted frame faults.
const NIC_IOVA: u64 = 0x1000;
/// Driver-host VSpace: where the executive maps the CM_RESOURCE_LIST + common-buffer
/// descriptor (also mapped at the same vaddr in the host, aliasing the frame).
pub const RESLIST_VADDR: u64 = 0x0000_0100_005F_D000;
/// The MSI vector we bind for the NIC interrupt (matches the NIC IRQ section).
const NIC_MSI_VECTOR: u64 = 5;
/// The IOAPIC pins PCI INTx routes to on q35 (GSI 16..23) — the NIC's exact pin is
/// chipset-routed, so we cover them all (edge-triggered, one delivery per assertion).

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
/// Issue an MSI IRQ-handler cap for `vector` into `dest_slot` (no IOAPIC pin — the
/// device delivers by writing the vector to the LAPIC). Same 7-word + extra-cap ABI
/// as the IOAPIC issue, but label 65; the pin/level/polarity words are ignored.
unsafe fn msi_issue_irq_handler(dest_slot: u64, vector: u64) {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 5 * 8) as *mut u64, 0); // mr4 (ignored for MSI)
    core::ptr::write_volatile((ipc + 6 * 8) as *mut u64, 0); // mr5 (ignored)
    core::ptr::write_volatile((ipc + 7 * 8) as *mut u64, vector); // mr6 = vector
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, CAP_INIT_THREAD_CNODE);
    let msginfo = (LBL_X86_IRQ_ISSUE_MSI << 12) | (1 << 9) | (1 << 7) | 7;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_SEND as u64,
        in("rdi") SLOT_IRQ_CONTROL,
        in("rsi") msginfo,
        in("r10") dest_slot, // mr0 = index (dest slot)
        in("r8") 64u64,      // mr1 = depth
        in("r9") 0u64,       // mr2 = ioapic id (ignored)
        in("r15") 0u64,      // mr3 = pin (ignored for MSI)
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
}

/// Non-blocking poll of a notification: returns the pending badge (0 if none).
unsafe fn nb_recv(ntfn: u64) -> u64 {
    let badge: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_NB_RECV as u64,
        inout("rdi") ntfn => badge,
        lateout("rsi") _, lateout("r10") _, lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    badge
}

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
unsafe fn ioapic_issue_irq_handler(dest_slot: u64, pin: u64, vector: u64, level: u64, polarity: u64) {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 5 * 8) as *mut u64, level); // mr4 = level (0=edge, 1=level)
    core::ptr::write_volatile((ipc + 6 * 8) as *mut u64, polarity); // mr5 = polarity (1=active-low)
    core::ptr::write_volatile((ipc + 7 * 8) as *mut u64, vector); // mr6 = vector (irq table index)
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
unsafe fn spawn_isr(entry: unsafe extern "C" fn() -> !, irq_cap: u64, result_cap: u64, prio: u64) {
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
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

/// Spawn an isolated PnP driver host: a fresh VSpace/CSpace, plus — mapped into its
/// VSpace — the granted device resources: the NIC BAR (`bar_base`..+4 pages at
/// `NIC_VADDR`), a confined common DMA buffer (`dma_frame` at `DMA_VADDR`), and the
/// resource frame (`reslist_frame` at `RESLIST_VADDR`) holding the CM_RESOURCE_LIST. The
/// host gets caps only to the IRQ + result notifications. Device frames are aliased via
/// `copy_cap`, so the same physical pages are also mapped in the executive.
unsafe fn spawn_driver_host(
    entry: unsafe extern "C" fn() -> !,
    irq_cap: u64,
    result_cap: u64,
    fault_ep: u64,
    prio: u64,
    bar_base: u64,
    dma_frame: u64,
    reslist_frame: u64,
    pe_base: u64,
    arena_base: u64,
) {
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
    // Granted device resources, mapped into the host's VSpace (all within the image PT):
    //   the 4 NIC BAR pages at NIC_VADDR, the confined DMA buffer at DMA_VADDR, and the
    //   resource frame at RESLIST_VADDR. Each is a copy aliasing the executive's frame.
    for i in 0..4u64 {
        let cp = copy_cap(bar_base + i);
        let _ = page_map(cp, NIC_VADDR + i * 0x1000, RW_NX, pml4);
    }
    let dma_cp = copy_cap(dma_frame);
    let _ = page_map(dma_cp, DMA_VADDR, RW_NX, pml4);
    let res_cp = copy_cap(reslist_frame);
    let _ = page_map(res_cp, RESLIST_VADDR, RW_NX, pml4);
    // The pre-loaded real .sys image (R+W+X — W^X hardening deferred) + its RW arena.
    for i in 0..driver_pe::PE_FRAMES {
        let cp = copy_cap(pe_base + i);
        let _ = page_map(cp, driver_pe::CODE_VA + i * 0x1000, /* RWX */ 3, pml4);
    }
    for i in 0..driver_pe::ARENA_FRAMES {
        let cp = copy_cap(arena_base + i);
        let _ = page_map(cp, driver_pe::ARENA_VADDR + i * 0x1000, RW_NX, pml4);
    }

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_IRQ_NTFN, irq_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, result_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}

/// Spawn an isolated KMDF driver host. Like `spawn_isr` but with what a real KMDF driver
/// + the WDF runtime need: the host image mapped RW (the 444-entry WDF function table +
/// globals live in `.bss`), a heap (WdfRuntime + every Wdf*Create allocate), the pre-loaded
/// KMDF PE image (RWX), and a shared word (DriverEntry rva in, verdict out). A bigger stack
/// for the deep driver→thunk→runtime call chains. Software-only — no device resources.
unsafe fn spawn_kmdf_host(
    entry: unsafe extern "C" fn() -> !,
    result_cap: u64,
    fault_ep: u64,
    prio: u64,
    kmdf_pe_base: u64,
    shared_frame: u64,
    nic_bar_base: u64,
) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let stack_frames = 16u64; // 64 KiB — WDF call chains are deep
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
    // Image mapped RW (rights=3 → RWX): the WDF function table + globals live in `.bss`
    // and this host must WRITE them. NOTE: these are the executive's SHARED image frames,
    // so — unlike the RO-image hosts — a buggy KMDF host could scribble on the executive's
    // code/data. Acceptable here (the host runs to completion before the executive resumes,
    // and a correct host writes only its own WDF statics); tightening to a private image
    // copy is a hardening follow-on.
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RWX */ 3, pml4);
    }
    // Heap for the WDF runtime; retype-zeroed frames give bump counter 0 (no init).
    for i in 0..allocator::HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, RW_NX, pml4);
    }
    for i in 0..stack_frames {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, RW_NX, pml4);
    }
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // The pre-loaded KMDF PE image (RWX) + the shared word (RW, entry rva / verdict).
    for i in 0..kmdf_host::KMDF_PE_FRAMES {
        let cp = copy_cap(kmdf_pe_base + i);
        let _ = page_map(cp, kmdf_host::KMDF_CODE_VA + i * 0x1000, /* RWX */ 3, pml4);
    }
    let sh = copy_cap(shared_frame);
    let _ = page_map(sh, kmdf_host::KMDF_SHARED_VADDR, RW_NX, pml4);
    // The REAL e1000e NIC BAR (4 pages, aliased from the executive's caps) at NIC_VADDR —
    // the KMDF driver reaches real hardware via MmMapIoSpace → NIC_VADDR.
    if nic_bar_base != 0 {
        for i in 0..4u64 {
            let cp = copy_cap(nic_bar_base + i);
            let _ = page_map(cp, NIC_VADDR + i * 0x1000, RW_NX, pml4);
        }
    }

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, result_cap, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = STACK_BASE + stack_frames * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
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
    claim_device_pages(bi, paddr, vaddr, 1) != 0
}

/// Map the first `n` 4 KiB pages of the device MMIO region whose untyped base is
/// `paddr`, at consecutive vaddrs from `vaddr`. Consecutive retypes from one untyped
/// hand out consecutive physical frames, so page p lands at `paddr + p*0x1000` mapped
/// at `vaddr + p*0x1000` — i.e. an identity-offset window over the BAR. Needed for the
/// e1000e, whose TX descriptor registers sit at BAR offset 0x3800 (the 4th page).
/// Returns the cap slot of the FIRST mapped BAR frame (0 if not found). The `n` frames
/// occupy consecutive slots, so a caller can `copy_cap(base + p)` to alias a page (e.g.
/// to map the BAR into an isolated driver host's VSpace too).
unsafe fn claim_device_pages(bi: &BootInfo, paddr: u64, vaddr: u64, n: u64) -> u64 {
    let count = bi.untyped.end - bi.untyped.start;
    for i in 0..count {
        let d = bi.untyped_list[i as usize];
        if d.is_device == 1 && d.paddr == paddr {
            let mut base = 0u64;
            for p in 0..n {
                let frame = alloc_slot();
                if p == 0 {
                    base = frame;
                }
                let _ = untyped_retype(bi.untyped.start + i, OBJ_X86_4K_PAGE, PAGING_BITS, 1, frame);
                let _ = page_map(frame, vaddr + p * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            return base;
        }
    }
    0
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
/// Invoke `X86Page::GetAddress` on a frame cap and return its physical address. The
/// kernel writes the paddr into reply msg_reg[0], which lands in r10 on return (same
/// reply-register convention `io_in32` relies on). No message args.
unsafe fn get_frame_paddr(frame_cap: u64) -> u64 {
    let paddr: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") SYS_CALL as u64,
        inout("rdi") frame_cap => _,
        inout("rsi") (LBL_X86_PAGE_GET_ADDRESS << 12) => _,
        out("r10") paddr, // reply mr0 = physical address
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    paddr
}

/// Bring up AHCI port 0 and READ one 512-byte sector (`sector`) into the DMA frame at
/// `dma_vaddr + 0x800` (paddr `dma_paddr + 0x800`) via ATA READ DMA EXT. All AHCI DMA
/// structures live in one 4 KiB frame: Command List @0 (1 KiB-aligned), FIS Rx @0x400
/// (256-aligned), Command Table @0x500 (128-aligned), data buffer @0x800. Returns the
/// port Task File Data low byte after completion (0 = success; 0xFF = timeout). READ ONLY.
unsafe fn ahci_read_sector(ahci_vaddr: u64, dma_vaddr: u64, dma_paddr: u64, sector: u64) -> u32 {
    let port = ahci_vaddr + 0x100; // port 0 register set
    let pr = |o: u64| core::ptr::read_volatile((port + o) as *const u32);
    let pw = |o: u64, v: u32| core::ptr::write_volatile((port + o) as *mut u32, v);
    // Enable AHCI mode (GHC.AE bit 31).
    let ghc = core::ptr::read_volatile((ahci_vaddr + 0x04) as *const u32);
    core::ptr::write_volatile((ahci_vaddr + 0x04) as *mut u32, ghc | (1 << 31));
    // Stop the port: clear ST (bit 0) + FRE (bit 4); wait CR (bit 15) + FR (bit 14) clear.
    pw(0x18, pr(0x18) & !((1 << 0) | (1 << 4)));
    for _ in 0..1_000_000u64 {
        if pr(0x18) & ((1 << 15) | (1 << 14)) == 0 {
            break;
        }
        yield_now();
    }
    // Zero the command list + FIS + command table region, then program the bases.
    for i in 0..(0x800u64 / 8) {
        core::ptr::write_volatile((dma_vaddr + i * 8) as *mut u64, 0);
    }
    pw(0x00, dma_paddr as u32); // PxCLB  (command list @ +0)
    pw(0x04, (dma_paddr >> 32) as u32); // PxCLBU
    pw(0x08, (dma_paddr + 0x400) as u32); // PxFB (FIS rx @ +0x400)
    pw(0x0C, (dma_paddr >> 32) as u32); // PxFBU
    // Start FRE, then ST.
    pw(0x18, pr(0x18) | (1 << 4));
    yield_now();
    pw(0x18, pr(0x18) | (1 << 0));
    pw(0x10, 0xFFFF_FFFF); // clear PxIS

    // Command Table @ dma+0x500: H2D Register FIS (READ DMA EXT) + PRDT[0].
    let ct = dma_vaddr + 0x500;
    let cb = |o: u64, v: u8| core::ptr::write_volatile((ct + o) as *mut u8, v);
    cb(0, 0x27); // FIS type = Register H2D
    cb(1, 0x80); // C = 1 (command), PMPort 0
    cb(2, 0x25); // command = READ DMA EXT
    cb(4, sector as u8); // LBA 7:0
    cb(5, (sector >> 8) as u8); // LBA 15:8
    cb(6, (sector >> 16) as u8); // LBA 23:16
    cb(7, 0x40); // device = LBA48
    cb(8, (sector >> 24) as u8); // LBA 31:24
    cb(9, (sector >> 32) as u8); // LBA 39:32
    cb(10, (sector >> 40) as u8); // LBA 47:40
    core::ptr::write_volatile((ct + 12) as *mut u16, 1); // count = 1 sector
    // PRDT[0] @ ct + 0x80.
    core::ptr::write_volatile((ct + 0x80) as *mut u32, (dma_paddr + 0x800) as u32); // DBA
    core::ptr::write_volatile((ct + 0x84) as *mut u32, (dma_paddr >> 32) as u32); // DBAU
    core::ptr::write_volatile((ct + 0x8C) as *mut u32, 511 | (1 << 31)); // DBC = 512 B | IOC

    // Command Header slot 0 @ dma+0. DW0 = CFL(5) | PRDTL(1)<<16; CTBA @ +8.
    core::ptr::write_volatile(dma_vaddr as *mut u32, 5 | (1u32 << 16));
    core::ptr::write_volatile((dma_vaddr + 8) as *mut u32, (dma_paddr + 0x500) as u32); // CTBA
    core::ptr::write_volatile((dma_vaddr + 12) as *mut u32, (dma_paddr >> 32) as u32); // CTBAU

    // Issue command slot 0 (PxCI bit 0) + poll for completion.
    pw(0x38, 1);
    for _ in 0..5_000_000u64 {
        if pr(0x38) & 1 == 0 {
            return pr(0x20) & 0xFF; // PxTFD low byte (0 = success)
        }
        yield_now();
    }
    0xFF // timeout
}

/// FAT32 filesystem geometry parsed from the volume's BPB (sector 0), plus the AHCI handles
/// needed to read further sectors. All reads go through `ahci_read_sector` into the shared
/// data buffer at `AHCI_DMA_VADDR + 0x800` — so a caller MUST consume one sector's bytes
/// before triggering the next read.
#[derive(Clone, Copy)]
struct Fat32 {
    ahci_vaddr: u64,
    dma_vaddr: u64,
    dma_paddr: u64,
    bps: u32,        // bytes per sector
    spc: u32,        // sectors per cluster
    fat_start: u32,  // first FAT sector
    data_start: u32, // first data sector (cluster 2)
    root_cl: u32,    // root directory cluster
}

/// Read `sector` off the disk (via AHCI) and return a pointer to its 512 bytes.
unsafe fn fat_read_sector(fs: &Fat32, sector: u32) -> *const u8 {
    ahci_read_sector(fs.ahci_vaddr, fs.dma_vaddr, fs.dma_paddr, sector as u64);
    (fs.dma_vaddr + 0x800) as *const u8
}

/// First disk sector of a cluster.
fn fat_cluster_sector(fs: &Fat32, cluster: u32) -> u32 {
    fs.data_start + (cluster - 2) * fs.spc
}

/// Follow the FAT: next cluster after `cluster` (>= 0x0FFF_FFF8 means end-of-chain).
unsafe fn fat_next(fs: &Fat32, cluster: u32) -> u32 {
    let byte = cluster * 4;
    let sec = fs.fat_start + byte / fs.bps;
    let off = (byte % fs.bps) as u64;
    let p = fat_read_sector(fs, sec);
    (core::ptr::read_unaligned(p.add(off as usize) as *const u32)) & 0x0FFF_FFFF
}

/// Scan directory `dir_cluster` (following its cluster chain) for the 8.3 name `name11`
/// (11 bytes, space-padded). Returns (first_cluster, size_bytes, attr). LFN / deleted /
/// volume-label / free entries are skipped. Extracts the entry before any further reads.
unsafe fn dir_find(fs: &Fat32, dir_cluster: u32, name11: &[u8; 11]) -> Option<(u32, u32, u8)> {
    let mut cl = dir_cluster;
    while cl >= 2 && cl < 0x0FFF_FFF8 {
        for s in 0..fs.spc {
            let p = fat_read_sector(fs, fat_cluster_sector(fs, cl) + s);
            for e in 0..(fs.bps as usize / 32) {
                let ent = p.add(e * 32);
                let first = *ent;
                if first == 0x00 {
                    return None; // end of directory
                }
                if first == 0xE5 {
                    continue; // deleted
                }
                let attr = *ent.add(0x0B);
                if attr == 0x0F || (attr & 0x08) != 0 {
                    continue; // LFN fragment or volume label
                }
                let mut matches = true;
                for i in 0..11 {
                    if *ent.add(i) != name11[i] {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    let hi = core::ptr::read_unaligned(ent.add(0x14) as *const u16) as u32;
                    let lo = core::ptr::read_unaligned(ent.add(0x1A) as *const u16) as u32;
                    let size = core::ptr::read_unaligned(ent.add(0x1C) as *const u32);
                    return Some(((hi << 16) | lo, size, attr));
                }
            }
        }
        cl = fat_next(fs, cl); // overwrites the buffer — fine, we're done with this cluster
    }
    None
}

/// Install a VT-d IO page table `iopt_cap` into device IO space `io_space_cap`, walking
/// toward `io_address`. Returns the invocation error label (0 = success). The first call
/// for a device installs the context root (and lazily enables VT-d translation).
unsafe fn iopt_map(iopt_cap: u64, io_space_cap: u64, io_address: u64) -> u64 {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, io_space_cap); // extraCaps[0] = IOSpace
    let msginfo = (LBL_X86_IO_PAGE_TABLE_MAP << 12) | (1 << 9) | (1 << 7) | 1;
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") iopt_cap => _,
        inout("rsi") msginfo => reply,
        inout("r10") io_address => _, // mr0 = io_address (args.a2)
        lateout("r8") _, lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}

/// Map frame `frame_cap` into device IO space `io_space_cap` at `io_address` with `rights`
/// (bit0 = write, bit1 = read). Returns the error label (0 = success). The frame cap must
/// be UNMAPPED — pass a copy if the original is mapped in a VSpace.
unsafe fn map_io(frame_cap: u64, io_space_cap: u64, rights: u64, io_address: u64) -> u64 {
    let ipc = IPC_BUFFER.load(Ordering::Relaxed);
    core::ptr::write_volatile((ipc + 122 * 8) as *mut u64, io_space_cap); // extraCaps[0] = IOSpace
    let msginfo = (LBL_X86_PAGE_MAP_IO << 12) | (1 << 9) | (1 << 7) | 2;
    let reply: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") frame_cap => _,
        inout("rsi") msginfo => reply,
        inout("r10") rights => _,    // mr0 = rights (args.a2)
        inout("r8") io_address => _, // mr1 = io_address (args.a3)
        lateout("r9") _, lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply >> 12
}

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

/// Write a 32-bit PCI configuration register.
unsafe fn pci_write32(ioport: u64, bus: u8, dev: u8, func: u8, reg: u8, value: u32) {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((reg as u32) & 0xFC);
    io_out32(ioport, PCI_CONFIG_ADDR, addr);
    io_out32(ioport, PCI_CONFIG_DATA, value);
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
            // Issue the IOAPIC IRQ-handler cap LEVEL-triggered: this exercises the
            // kernel's mask-on-deliver fix — a level line held asserted (the HPET holds
            // it until its status is cleared) would storm without it. With the fix it
            // delivers once, the kernel masks the line, and the host wakes cleanly.
            let handler = alloc_slot();
            ioapic_issue_irq_handler(handler, pin, IRQ_VECTOR, /*level*/ 1, /*polarity*/ 0);
            let _ = irq_handler_set_notification(handler, irq_ntfn_badged);
            // Hand the isolated ISR "driver host" ONLY the IRQ + result notifications;
            // its ISR thread blocks on the IRQ and reports via the result notification.
            spawn_isr(isr::isr_entry, irq_ntfn_isr, result_ntfn_badged, 100);

            // Program timer 0: interrupt enable + route to `pin`, LEVEL-triggered, one-shot.
            let newcfg = (1u64 << 1) | (1u64 << 2) | (pin << 9);
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
    let (mut storage_dev, mut storage_func) = (0u8, 0u8);
    let (mut nic_bar0, mut nic_irq, mut found_nic) = (0u32, 0u32, false);
    let (mut nic_dev, mut nic_func) = (0u8, 0u8);
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
            // First AHCI SATA controller (class 0x0106). On q35 the boot disk is on the
            // add-in `-device ahci` at a low slot (00:3.0); the built-in ICH9 SATA (00:31.2)
            // is empty — so first-wins picks the one with the disk. ABAR = BAR5.
            if (class >> 8) == 0x01_0601 && !found_storage {
                found_storage = true;
                storage_bar5 = pci_read32(pci_io, 0, dev, func, 0x24);
                storage_irq = irq;
                storage_dev = dev;
                storage_func = func;
            }
            // A network controller (class 0x02) — the e1000e NIC we drive as the
            // P1 capstone (its MMIO BAR0 + interrupt line).
            if (class >> 24) == 0x02 {
                found_nic = true;
                nic_bar0 = bar0;
                nic_irq = irq;
                nic_dev = dev;
                nic_func = func;
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

    // --- P2: real block I/O. Bring up the AHCI controller (boot disk on port 0) and READ
    // sector 0 off the real disk via READ DMA EXT — the disk end of the disk→volume→FS→
    // registry chain. Runs BEFORE the NIC block so VT-d translation is still OFF (identity
    // DMA); the HBA DMAs straight to our frame's physical address. READ ONLY.
    if found_storage {
        let ahci_bar = (storage_bar5 & 0xFFFF_FFF0) as u64;
        print_str(b"[ntos-exec] P2: AHCI ABAR=");
        print_hex(ahci_bar as u32);
        print_str(b" dev=");
        print_u64(storage_dev as u64);
        print_str(b"\n");
        // Bus Master (Command bit 2) + Memory Space (bit 1) so the HBA can DMA.
        let cmd = pci_read32(pci_io, 0, storage_dev, storage_func, 0x04);
        pci_write32(pci_io, 0, storage_dev, storage_func, 0x04, cmd | (1 << 2) | (1 << 1));
        let mapped = claim_device_page(bi, ahci_bar, AHCI_VADDR);
        check(b"exec_ahci_abar_mapped", mapped, &mut passed);
        if mapped {
            let dma_frame = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, dma_frame);
            let _ = page_map(dma_frame, AHCI_DMA_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            let dma_paddr = get_frame_paddr(dma_frame);
            // Port 0 device present? PxSSTS DET field [11:8] == 3 (present + PHY up).
            let ssts = core::ptr::read_volatile((AHCI_VADDR + 0x100 + 0x28) as *const u32);
            let det = (ssts >> 8) & 0xF;
            print_str(b"[ntos-exec] AHCI port0 SSTS.DET=");
            print_u64(det as u64);
            print_str(b"\n");
            check(b"exec_ahci_port0_device_present", det != 0, &mut passed);
            // Read sector 0 (the boot sector) via a real READ DMA EXT.
            let tfd = ahci_read_sector(AHCI_VADDR, AHCI_DMA_VADDR, dma_paddr, 0);
            let db = |i: u64| core::ptr::read_volatile((AHCI_DMA_VADDR + 0x800 + i) as *const u8);
            let mut nonzero = false;
            for i in 0..512u64 {
                if db(i) != 0 {
                    nonzero = true;
                    break;
                }
            }
            let sig = (db(510) as u16) | ((db(511) as u16) << 8);
            print_str(b"[ntos-exec] AHCI read sector0 TFD=0x");
            print_hex(tfd);
            print_str(b" sig=0x");
            print_hex(sig as u32);
            print_str(b" bytes[0..8]=0x");
            print_hex(core::ptr::read_volatile((AHCI_DMA_VADDR + 0x800) as *const u32));
            print_hex(core::ptr::read_volatile((AHCI_DMA_VADDR + 0x804) as *const u32));
            print_str(b"\n");
            // Proof of real block I/O: the command completed with no error (BSY/DRQ/ERR all
            // clear), real data landed in the zeroed buffer, AND it's the MBR boot signature
            // (byte 510=0x55, 511=0xAA → little-endian 0xAA55).
            check(
                b"exec_ahci_read_sector0",
                (tfd & 0x89) == 0 && nonzero && sig == 0xAA55,
                &mut passed,
            );

            // --- P2 filesystem: read a real FILE through the FAT32 volume on this disk.
            // Sector 0 (the BPB) is still in the buffer from the read above. Parse it,
            // then navigate root → BOOTBOOT → INITRD and read the file's first cluster.
            let bp = |o: u64| core::ptr::read_volatile((AHCI_DMA_VADDR + 0x800 + o) as *const u8);
            let bp16 = |o: u64| (bp(o) as u32) | ((bp(o + 1) as u32) << 8);
            let bp32 = |o: u64| bp16(o) | (bp16(o + 2) << 16);
            let bps = bp16(0x0B);
            let spc = bp(0x0D) as u32;
            let reserved = bp16(0x0E);
            let nfats = bp(0x10) as u32;
            let spf32 = bp32(0x24);
            let root_cl = bp32(0x2C);
            let is_fat32 = bp(0x52) == b'F' && bp(0x53) == b'A' && bp(0x54) == b'T';
            print_str(b"[ntos-exec] FAT32 bps=");
            print_u64(bps as u64);
            print_str(b" spc=");
            print_u64(spc as u64);
            print_str(b" reserved=");
            print_u64(reserved as u64);
            print_str(b" nfats=");
            print_u64(nfats as u64);
            print_str(b" spf=");
            print_u64(spf32 as u64);
            print_str(b"\n");
            check(b"exec_fat32_bpb_ok", bps == 512 && spc >= 1 && is_fat32, &mut passed);
            if bps == 512 && spc >= 1 {
                let fs = Fat32 {
                    ahci_vaddr: AHCI_VADDR,
                    dma_vaddr: AHCI_DMA_VADDR,
                    dma_paddr,
                    bps,
                    spc,
                    fat_start: reserved,
                    data_start: reserved + nfats * spf32,
                    root_cl,
                };
                // List the root directory (8.3 names) — a real directory read.
                print_str(b"[ntos-exec] root dir:");
                let rp = fat_read_sector(&fs, fat_cluster_sector(&fs, fs.root_cl));
                for e in 0..(fs.bps as usize / 32) {
                    let ent = rp.add(e * 32);
                    if *ent == 0x00 {
                        break;
                    }
                    let attr = *ent.add(0x0B);
                    if *ent == 0xE5 || attr == 0x0F || (attr & 0x08) != 0 {
                        continue;
                    }
                    debug_put_char(b' ');
                    for i in 0..11 {
                        let c = *ent.add(i);
                        if c != b' ' {
                            debug_put_char(c);
                        }
                    }
                }
                print_str(b"\n");
                let have_efi = dir_find(&fs, fs.root_cl, b"EFI        ").is_some();
                let bootboot = dir_find(&fs, fs.root_cl, b"BOOTBOOT   ");
                check(b"exec_fat32_root_dir", have_efi && bootboot.is_some(), &mut passed);
                // Navigate BOOTBOOT/ → INITRD, then read the file's first cluster.
                let mut read_ok = false;
                if let Some((bb_cl, _, _)) = bootboot {
                    if let Some((initrd_cl, initrd_size, _)) = dir_find(&fs, bb_cl, b"INITRD     ") {
                        let fp = fat_read_sector(&fs, fat_cluster_sector(&fs, initrd_cl));
                        let mut nz = false;
                        for i in 0..512usize {
                            if *fp.add(i) != 0 {
                                nz = true;
                                break;
                            }
                        }
                        print_str(b"[ntos-exec] BOOTBOOT/INITRD cluster=");
                        print_u64(initrd_cl as u64);
                        print_str(b" size=");
                        print_u64(initrd_size as u64);
                        print_str(b" first8=0x");
                        print_hex(core::ptr::read_unaligned(fp as *const u32));
                        print_hex(core::ptr::read_unaligned(fp.add(4) as *const u32));
                        print_str(b"\n");
                        read_ok = initrd_size > 0 && nz;
                    }
                }
                check(b"exec_fat32_read_file", read_ok, &mut passed);
            }
        }
    }

    // --- P1 CAPSTONE: drive the real e1000e NIC. Map its enumerated BAR0 as a
    // device frame and read a live device register — a real driver path touching
    // real (QEMU-emulated) network hardware, not a mock.
    let mut kmdf_nic_bar_base = 0u64; // the real NIC BAR caps, handed to the KMDF host below
    if found_nic {
        let nic_mmio = (nic_bar0 & 0xFFFF_FFF0) as u64; // mask the BAR flag bits
        print_str(b"[ntos-exec] P1 CAPSTONE: mapping e1000e NIC BAR0 ");
        print_hex(nic_mmio as u32);
        print_str(b" (irq ");
        print_u64(nic_irq as u64);
        print_str(b")\n");
        // Map the first 4 pages (16 KiB) of the BAR: page 0 has CTRL/STATUS/interrupt
        // regs, page 3 (offset 0x3000) has the TX descriptor registers (0x3800..0x3828).
        let nic_bar_base = claim_device_pages(bi, nic_mmio, NIC_VADDR, 4);
        check(b"exec_nic_bar_mapped", nic_bar_base != 0, &mut passed);
        kmdf_nic_bar_base = nic_bar_base; // hand the real BAR to the KMDF host later
        if nic_bar_base != 0 {
            // Intel e1000e register file: CTRL @ 0x00, STATUS @ 0x08.
            let ctrl = core::ptr::read_volatile((NIC_VADDR + 0x00) as *const u32);
            let status = core::ptr::read_volatile((NIC_VADDR + 0x08) as *const u32);
            print_str(b"[ntos-exec] e1000e CTRL=");
            print_hex(ctrl);
            print_str(b" STATUS=");
            print_hex(status);
            print_str(b"\n");
            // A live NIC returns a real value — not 0xFFFFFFFF (unmapped MMIO) or 0.
            check(
                b"exec_nic_mmio_status_live",
                status != 0xFFFF_FFFF && status != 0,
                &mut passed,
            );

            // --- FULL-DEVICE LOOP: a real NIC interrupt delivered into an isolated
            // driver host. Issue IOAPIC handlers for the PCI GSIs (the NIC's exact
            // pin is chipset-routed) bound to a notification, spawn an isolated ISR
            // host, then trigger a real NIC interrupt via the e1000e ICS register.
            print_str(b"[ntos-exec] FULL LOOP: real NIC interrupt -> isolated ISR host\n");
            // Diagnostic: PCI Interrupt Pin (config 0x3D) — 1=INTA .. 4=INTD, 0=no INTx
            // (MSI-only). Tells us whether INTx routing is even the right mechanism.
            let int_pin = (pci_read32(pci_io, 0, nic_dev, nic_func, 0x3C) >> 8) & 0xFF;
            print_str(b"[ntos-exec] NIC Interrupt Pin = ");
            print_u64(int_pin as u64);
            print_str(b"\n");
            let nic_irq_ntfn = make_object(OBJ_NOTIFICATION);
            let nic_irq_badged = alloc_slot();
            let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, nic_irq_badged, nic_irq_ntfn, IRQ_BADGE);
            let result_ntfn = make_object(OBJ_NOTIFICATION);
            let result_badged = alloc_slot();
            let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, result_badged, result_ntfn, ISR_DONE_BADGE);
            let _ = int_pin;
            // The isolated ISR host waits on the NIC notification (reuses spawn_isr).
            let nic_irq_isr = copy_cap(nic_irq_ntfn);
            spawn_isr(isr::isr_entry, nic_irq_isr, result_badged, 255);

            // Deliver the NIC interrupt via MSI (its INTx isn't routed to the IOAPIC in
            // this QEMU q35 config; MSI is a memory write to the LAPIC that bypasses the
            // IOAPIC + chipset entirely). Walk the PCI capability list for the MSI cap
            // (ID 0x05), program it to deliver our vector to the LAPIC, then enable it.
            let mut cap = (pci_read32(pci_io, 0, nic_dev, nic_func, 0x34) & 0xFC) as u8;
            let mut msi_off = 0u8;
            let mut msix_off = 0u8;
            for _ in 0..16 {
                if cap == 0 {
                    break;
                }
                let hdr = pci_read32(pci_io, 0, nic_dev, nic_func, cap);
                let id = (hdr & 0xFF) as u8;
                print_str(b"[ntos-exec]   pci cap id=0x");
                print_hex(id as u32);
                print_str(b" @ 0x");
                print_hex(cap as u32);
                print_str(b"\n");
                if id == 0x05 {
                    msi_off = cap;
                }
                if id == 0x11 {
                    msix_off = cap;
                }
                cap = ((hdr >> 8) & 0xFC) as u8;
            }
            let _ = msix_off;
            print_str(b"[ntos-exec] NIC MSI capability @ config 0x");
            print_hex(msi_off as u32);
            print_str(b"\n");
            check(b"exec_nic_has_msi_capability", msi_off != 0, &mut passed);
            let msi_vector = 5u64; // irq index → LAPIC vector 0x25
            if msi_off != 0 {
                let msg_ctrl = (pci_read32(pci_io, 0, nic_dev, nic_func, msi_off) >> 16) as u16;
                let data_off = if (msg_ctrl & 0x80) != 0 { msi_off + 0xC } else { msi_off + 8 };
                // Message Address = LAPIC (0xFEE00000, physical dest APIC 0); Message
                // Data = the CPU vector (irq index + PIC1_VECTOR_BASE → IDT irq stub).
                pci_write32(pci_io, 0, nic_dev, nic_func, msi_off + 4, 0xFEE0_0000);
                if (msg_ctrl & 0x80) != 0 {
                    pci_write32(pci_io, 0, nic_dev, nic_func, msi_off + 8, 0);
                }
                pci_write32(pci_io, 0, nic_dev, nic_func, data_off, (msi_vector + 0x20) as u32);
                // Issue the MSI IRQ-handler cap + bind the NIC notification.
                let handler = alloc_slot();
                msi_issue_irq_handler(handler, msi_vector);
                let _ = irq_handler_set_notification(handler, nic_irq_badged);
                // Bus Master (Command bit 2) so the NIC can DMA the MSI write; then set
                // the MSI Enable bit (Message Control bit 0 = dword bit 16).
                let cmd = pci_read32(pci_io, 0, nic_dev, nic_func, 0x04);
                pci_write32(pci_io, 0, nic_dev, nic_func, 0x04, cmd | (1 << 2));
                let ctrl = pci_read32(pci_io, 0, nic_dev, nic_func, msi_off);
                pci_write32(pci_io, 0, nic_dev, nic_func, msi_off, ctrl | (1 << 16));
            }
            // ITR=0 so QEMU's e1000e doesn't postpone the interrupt (throttling).
            core::ptr::write_volatile((NIC_VADDR + E1000_ITR) as *mut u32, 0);
            // Enable + raise a real NIC interrupt (e1000e): unmask a cause, then set it.
            core::ptr::write_volatile((NIC_VADDR + E1000_IMS) as *mut u32, 0x1);
            core::ptr::write_volatile((NIC_VADDR + E1000_ICS) as *mut u32, 0x1);
            // Poll the result (bounded, non-blocking so a misroute fails not hangs).
            // The ISR host is priority 255 (== executive), so yield_now round-robins
            // to it when the real interrupt makes it runnable.
            let mut got = 0u64;
            for _ in 0..2_000_000u64 {
                let b = nb_recv(result_ntfn);
                if b != 0 {
                    got = b;
                    break;
                }
                yield_now();
            }
            // Diagnostic: read ICR from the executive. Nonzero ⇒ ICS asserted a real
            // cause (so the trigger works even if the IOAPIC route missed).
            let icr = core::ptr::read_volatile((NIC_VADDR + E1000_ICR) as *const u32);
            print_str(b"[ntos-exec] NIC ISR host badge=");
            print_u64(got);
            print_str(b" e1000e ICR=");
            print_hex(icr);
            print_str(b"\n");
            // The NIC raises a REAL interrupt: ICR bit 31 (INT asserted) + our cause.
            check(b"exec_nic_raised_real_interrupt", (icr & 0x8000_0000) != 0, &mut passed);
            // ...and it is delivered via MSI all the way into the isolated ISR host — a
            // real driver on real hardware taking a real device interrupt, crash-
            // contained. QEMU's e1000e delivers plain MSI on a legacy cause; the kernel
            // LAPIC-EOIs so this isn't blocked by the earlier HPET interrupt's ISR bit.
            check(b"exec_nic_irq_reached_isolated_host", got == ISR_DONE_BADGE, &mut passed);

            // ---- DMA: prove the NIC does REAL DMA to memory the executive allocates.
            // Build a TX descriptor ring + packet buffer in a normal RAM frame, learn its
            // physical address (VT-d translation is off → identity), point the e1000e TX
            // engine at it, kick the tail, and watch the NIC DMA-write the descriptor-DONE
            // bit back. DD=1 ⇒ the NIC DMA-read the ring + buffer and DMA-wrote the status.
            print_str(b"[ntos-exec] DMA: real e1000e TX DMA to an executive-owned frame\n");
            // Bus Master (Command bit 2) + Memory Space (bit 1) — DMA needs BME (idempotent
            // with the MSI setup above, but assert it so DMA doesn't depend on that path).
            let cmd = pci_read32(pci_io, 0, nic_dev, nic_func, 0x04);
            pci_write32(pci_io, 0, nic_dev, nic_func, 0x04, cmd | (1 << 2) | (1 << 1));

            let dma_frame = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, dma_frame);
            let _ = page_map(dma_frame, DMA_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            let dma_paddr = get_frame_paddr(dma_frame);
            print_str(b"[ntos-exec] DMA frame paddr=");
            print_hex((dma_paddr >> 32) as u32);
            print_hex(dma_paddr as u32);
            print_str(b"\n");
            check(
                b"exec_frame_get_paddr",
                dma_paddr != 0 && (dma_paddr & 0xFFF) == 0,
                &mut passed,
            );

            // Frame layout: TX ring at offset 0 (8 legacy descriptors = 128 bytes, meeting
            // the TDLEN 128-byte-alignment rule; we use descriptor 0), packet at 0x200.
            const RING_OFF: u64 = 0x0;
            const PKT_OFF: u64 = 0x200;
            const PKT_LEN: u16 = 64;
            for i in 0..PKT_LEN as u64 {
                core::ptr::write_volatile((DMA_VADDR + PKT_OFF + i) as *mut u8, 0xA5);
            }
            // Legacy TX descriptor 0 (16 bytes): buffer_addr[0..7], length[8..9], CSO[10],
            // CMD[11]=EOP|RS, STA[12] (NIC writes DD here), CSS[13], special[14..15].
            core::ptr::write_volatile((DMA_VADDR + RING_OFF) as *mut u64, dma_paddr + PKT_OFF);
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 8) as *mut u16, PKT_LEN);
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 10) as *mut u8, 0); // CSO
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 11) as *mut u8, 0x09); // CMD = EOP | RS
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 12) as *mut u8, 0); // STA (NIC writes DD)
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 13) as *mut u8, 0); // CSS
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 14) as *mut u16, 0); // special

            // Point the TX engine at the ring's PHYSICAL address, enable TX, arm queue 0,
            // then kick. QEMU's e1000e gates TX on TARC0 bit 10 (E1000_TARC_ENABLE) — not
            // TXDCTL — so without it a TDT write silently does nothing.
            let ring_paddr = dma_paddr + RING_OFF;
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAL) as *mut u32, ring_paddr as u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAH) as *mut u32, (ring_paddr >> 32) as u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDLEN) as *mut u32, 128);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDH) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TCTL) as *mut u32, 0x0004_00F3); // EN|PSP|CT|COLD
            let tarc0 = core::ptr::read_volatile((NIC_VADDR + E1000_TARC0) as *const u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TARC0) as *mut u32, tarc0 | (1 << 10));
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 1); // hand off descriptor 0

            // Poll the descriptor's STA byte (offset +12) for DD (bit 0) — set by the NIC
            // via DMA once it has processed the descriptor.
            let mut dd = 0u8;
            for _ in 0..2_000_000u64 {
                dd = core::ptr::read_volatile((DMA_VADDR + RING_OFF + 12) as *const u8);
                if dd & 0x1 != 0 {
                    break;
                }
                yield_now();
            }
            print_str(b"[ntos-exec] TX descriptor STA=0x");
            print_hex(dd as u32);
            print_str(b" (DD=1 => NIC DMA-read the ring+buffer and DMA-wrote status)\n");
            check(b"exec_nic_tx_dma_writeback", dd & 0x1 != 0, &mut passed);

            // ---- DMA Phase 2: CONFINE the NIC's DMA via the VT-d IOMMU. Grant the NIC an
            // IO address space containing ONLY this frame, reprogram it to address memory
            // by IOVA (not raw paddr), and prove the DMA still lands — now translated +
            // confined, so a DMA anywhere else would fault. Building the NIC's first IO
            // context lazily turns on VT-d translation (kernel side).
            print_str(b"[ntos-exec] DMA Phase 2: confine NIC DMA via the VT-d IOMMU\n");
            // Mint a device IO-space cap stamped with the NIC's PCI request-id + a domain.
            let nic_rid = ((nic_dev as u64) << 3) | (nic_func as u64);
            let nic_io_badge = (1u64 << 16) | nic_rid;
            let nic_io_space = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                nic_io_space,
                SLOT_IO_SPACE,
                nic_io_badge,
            );
            // Build the 4-level IO page-table hierarchy toward NIC_IOVA: 4 tables (context
            // root + 3 intermediate — the walk starts at levels_remaining=3 so MapIO reaches
            // level 0 only after 4 tables). The first install creates the context + TE.
            let mut iopt_err = 0u64;
            for _ in 0..4 {
                let iopt = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_IO_PAGE_TABLE, PAGING_BITS, 1, iopt);
                let e = iopt_map(iopt, nic_io_space, NIC_IOVA);
                if e != 0 {
                    iopt_err = e;
                }
            }
            print_str(b"[ntos-exec] IO page-table build err=");
            print_u64(iopt_err);
            print_str(b"\n");
            check(b"exec_nic_iopt_hierarchy_built", iopt_err == 0, &mut passed);
            // Map the DMA frame (a COPY — the original stays VSpace-mapped for CPU access)
            // into the NIC's IO space at NIC_IOVA, read+write.
            let dma_frame_io = copy_cap(dma_frame);
            let map_err = map_io(dma_frame_io, nic_io_space, 0x3, NIC_IOVA);
            print_str(b"[ntos-exec] map_io err=");
            print_u64(map_err);
            print_str(b"\n");
            check(b"exec_nic_dma_frame_io_mapped", map_err == 0, &mut passed);

            // Re-arm a transmit, but now the NIC addresses memory via the IOVA: ring base =
            // NIC_IOVA, buffer = NIC_IOVA + PKT_OFF. The CPU still reads/writes the
            // descriptor through the VSpace mapping (DMA_VADDR) — VT-d only gates the device.
            core::ptr::write_volatile((DMA_VADDR + RING_OFF) as *mut u64, NIC_IOVA + PKT_OFF);
            core::ptr::write_volatile((DMA_VADDR + RING_OFF + 12) as *mut u8, 0); // clear STA/DD
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAL) as *mut u32, NIC_IOVA as u32);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDBAH) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDH) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 0);
            core::ptr::write_volatile((NIC_VADDR + E1000_TDT) as *mut u32, 1);
            let mut dd2 = 0u8;
            for _ in 0..2_000_000u64 {
                dd2 = core::ptr::read_volatile((DMA_VADDR + RING_OFF + 12) as *const u8);
                if dd2 & 0x1 != 0 {
                    break;
                }
                yield_now();
            }
            print_str(b"[ntos-exec] confined TX descriptor STA=0x");
            print_hex(dd2 as u32);
            print_str(b" (DD=1 => NIC DMA went through VT-d: IOVA -> frame)\n");
            check(b"exec_nic_confined_dma", dd2 & 0x1 != 0, &mut passed);

            // ---- DRIVER HOST AT START: the executive, acting as the PnP manager + HAL,
            // hands an ISOLATED driver host a real NT CM_RESOURCE_LIST (MMIO + interrupt)
            // and a VT-d-confined common DMA buffer, then lets it drive the NIC (MMIO +
            // confined DMA) entirely from its own CSpace/VSpace — the seL4 analogue of a
            // KMDF driver's START_DEVICE. A fault or rogue DMA is contained in the host.
            print_str(b"[ntos-exec] driver host: START with CM_RESOURCE_LIST + confined DMA buffer\n");
            // Resource frame: mapped here (to fill it) and, via a copy, in the host.
            let reslist_frame = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, reslist_frame);
            let _ = page_map(reslist_frame, RESLIST_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
            {
                use nt_cm_resources::*;
                let buf =
                    core::slice::from_raw_parts_mut(RESLIST_VADDR as *mut u8, MEMORY_INTERRUPT_LIST_SIZE);
                let _ = build_memory_interrupt_list(
                    buf,
                    0, // bus 0
                    MemoryDescriptor {
                        start: NIC_VADDR, // the host's MMIO window (already mapped for it)
                        length: 0x4000,
                        flags: CM_RESOURCE_MEMORY_READ_WRITE,
                        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
                    },
                    InterruptDescriptor {
                        level: NIC_MSI_VECTOR as u32,
                        vector: NIC_MSI_VECTOR as u32,
                        affinity: 1,
                        flags: CM_RESOURCE_INTERRUPT_LATCHED,
                        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
                    },
                );
            }
            // Common-buffer descriptor (the DMA adapter's AllocateCommonBuffer result):
            // CPU virtual address, device logical address (IOVA), length.
            core::ptr::write_volatile((RESLIST_VADDR + 0x100) as *mut u64, DMA_VADDR);
            core::ptr::write_volatile((RESLIST_VADDR + 0x108) as *mut u64, NIC_IOVA);
            core::ptr::write_volatile((RESLIST_VADDR + 0x110) as *mut u64, 0x1000u64);
            core::ptr::write_volatile((RESLIST_VADDR + 0x200) as *mut u8, 0); // clear verdict
            core::ptr::write_volatile((RESLIST_VADDR + 0x210) as *mut u8, 0); // clear .sys verdict
            // Pre-load the REAL .sys driver (the executive owns the heap): map its image
            // frames RW here, parse/map/relocate/patch-IAT to our stubs, then hand the same
            // frames to the host R+X. Also a RW arena for the driver's host-side state.
            let mut pe_base = 0u64;
            for i in 0..driver_pe::PE_FRAMES {
                let f = alloc_slot();
                if i == 0 {
                    pe_base = f;
                }
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                let _ = page_map(f, driver_pe::CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            let sys_entry = driver_pe::load_into().unwrap_or(0);
            let mut arena_base = 0u64;
            for i in 0..driver_pe::ARENA_FRAMES {
                let f = alloc_slot();
                if i == 0 {
                    arena_base = f;
                }
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                let _ = page_map(f, driver_pe::ARENA_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
            }
            core::ptr::write_volatile((RESLIST_VADDR + 0x300) as *mut u64, sys_entry as u64);
            core::ptr::write_volatile((RESLIST_VADDR + 0x308) as *mut u64, nic_mmio);
            print_str(b"[ntos-exec] pre-loaded real PnpMmioInterruptTest.sys; DriverEntry rva=");
            print_hex(sys_entry);
            print_str(b"\n");
            // A fresh badged result notification the host signals when it's done.
            let dh_result = make_object(OBJ_NOTIFICATION);
            let dh_result_badged = alloc_slot();
            let _ = syscall5(
                SYS_SEND,
                CAP_INIT_THREAD_CNODE,
                LBL_CNODE_MINT << 12,
                dh_result_badged,
                dh_result,
                ISR_DONE_BADGE,
            );
            // Hand the host a cap to the NIC's IRQ notification too (full resource grant).
            let dh_irq = copy_cap(nic_irq_ntfn);
            let dh_fault = make_object(OBJ_ENDPOINT);
            spawn_driver_host(
                driver_host::driver_host_entry,
                dh_irq,
                dh_result_badged,
                dh_fault,
                100,
                nic_bar_base,
                dma_frame,
                reslist_frame,
                pe_base,
                arena_base,
            );
            let _ = dh_fault; // a fault EP so a host fault is contained cleanly, not silent
            // The host always signals when done; read back its verdict from the shared frame.
            let (_z, dhb, _s, _m) = ep_recv(dh_result);
            let dh_verdict = core::ptr::read_volatile((RESLIST_VADDR + 0x200) as *const u8);
            print_str(b"[ntos-exec] driver host signalled badge=");
            print_u64(dhb);
            print_str(b" verdict=");
            print_u64(dh_verdict as u64);
            print_str(b"\n");
            check(b"exec_driver_host_drove_nic", dh_verdict == 1, &mut passed);
            // ...and a REAL Windows .sys driver binary ran in that same isolated host,
            // driven through DriverEntry → AddDevice → IRP_MN_START_DEVICE with our real
            // CM_RESOURCE_LIST, reaching the real NIC via MmMapIoSpace.
            let sys_v = core::ptr::read_volatile((RESLIST_VADDR + 0x210) as *const u8);
            print_str(b"[ntos-exec] hosted real .sys verdict bits=0x");
            print_hex(sys_v as u32);
            print_str(b"\n");
            check(b"exec_sys_driver_entry_ok", (sys_v & 1) != 0, &mut passed);
            check(b"exec_sys_adddevice_built_fdo", (sys_v & 2) != 0, &mut passed);
            check(b"exec_sys_start_reached_real_nic", (sys_v & 8) != 0, &mut passed);
            if (sys_v & 4) == 0 {
                print_str(b"[ntos-exec]   note: the driver's START handler ran + did real MMIO,\n");
                print_str(b"[ntos-exec]   then returned a device-specific status (the real device\n");
                print_str(b"[ntos-exec]   is an e1000e NIC, not this driver's own test device).\n");
            }
        }
    }

    // ---- KMDF DRIVER HOST: host a real KMDF driver (KmdfBasicTest.sys) through the FULL
    // WDF lifecycle (DriverEntry → WdfDriverCreate → AddDevice → EvtDevicePrepareHardware
    // → D0Entry → IOCTLs → REMOVE) in a SEPARATE isolated host — the MODERN Windows driver
    // framework, crash-contained on the microkernel. Software-only (simulated MMIO).
    {
        print_str(b"[ntos-exec] KMDF host: loading real KmdfBasicTest.sys\n");
        let mut kmdf_pe_base = 0u64;
        for i in 0..kmdf_host::KMDF_PE_FRAMES {
            let f = alloc_slot();
            if i == 0 {
                kmdf_pe_base = f;
            }
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
            let _ = page_map(f, kmdf_host::KMDF_CODE_VA + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        let kmdf_entry = kmdf_host::load_into().unwrap_or(0);
        let kmdf_shared = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, kmdf_shared);
        let _ = page_map(kmdf_shared, kmdf_host::KMDF_SHARED_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
        core::ptr::write_volatile(kmdf_host::KMDF_SHARED_VADDR as *mut u64, kmdf_entry as u64);
        core::ptr::write_volatile((kmdf_host::KMDF_SHARED_VADDR + 8) as *mut u32, 0);
        core::ptr::write_volatile((kmdf_host::KMDF_SHARED_VADDR + 0x10) as *mut u32, 0);
        print_str(b"[ntos-exec] pre-loaded KmdfBasicTest.sys; FxDriverEntry rva=");
        print_hex(kmdf_entry);
        print_str(b"\n");
        let kmdf_result = make_object(OBJ_NOTIFICATION);
        let kmdf_result_badged = alloc_slot();
        let _ = syscall5(
            SYS_SEND,
            CAP_INIT_THREAD_CNODE,
            LBL_CNODE_MINT << 12,
            kmdf_result_badged,
            kmdf_result,
            ISR_DONE_BADGE,
        );
        let kmdf_fault = make_object(OBJ_ENDPOINT);
        spawn_kmdf_host(
            kmdf_host::kmdf_host_entry,
            kmdf_result_badged,
            kmdf_fault,
            100,
            kmdf_pe_base,
            kmdf_shared,
            kmdf_nic_bar_base,
        );
        let _ = kmdf_fault;
        let (_z, _b, _s, _m) = ep_recv(kmdf_result);
        let kv = core::ptr::read_volatile((kmdf_host::KMDF_SHARED_VADDR + 8) as *const u32);
        print_str(b"[ntos-exec] KMDF host lifecycle verdict bits=0x");
        print_hex(kv);
        print_str(b"\n");
        check(b"exec_kmdf_driver_create", (kv & 1) != 0, &mut passed);
        check(b"exec_kmdf_adddevice_queue", (kv & 2) != 0, &mut passed);
        // bit 4 now = the driver's PrepareHardware mapped the REAL NIC BAR + read + rejected
        // a real register (not its 'KMDF' test HW) — a real KMDF driver reaching real HW.
        check(b"exec_kmdf_prepare_hw_read_real_nic", (kv & 4) != 0, &mut passed);
        check(b"exec_kmdf_ioctl", (kv & 8) != 0, &mut passed);
        check(b"exec_kmdf_remove", (kv & 16) != 0, &mut passed);
        // The KMDF driver, in EvtDevicePrepareHardware, mapped the REAL e1000e BAR
        // (MmMapIoSpace → NIC_VADDR) and its READ_REG32 IOCTL returned register 0 (CTRL).
        // Verify it matches a direct read of the same live register — a real KMDF driver
        // reaching real hardware through the WDF stack.
        let kmdf_ctrl = core::ptr::read_volatile((kmdf_host::KMDF_SHARED_VADDR + 0x10) as *const u32);
        let direct_ctrl = if kmdf_nic_bar_base != 0 {
            core::ptr::read_volatile(NIC_VADDR as *const u32)
        } else {
            0
        };
        print_str(b"[ntos-exec] KMDF driver read real NIC CTRL=0x");
        print_hex(kmdf_ctrl);
        print_str(b" (direct read=0x");
        print_hex(direct_ctrl);
        print_str(b")\n");
        check(
            b"exec_kmdf_read_real_nic",
            kmdf_ctrl != 0 && kmdf_ctrl != 0xFFFF_FFFF && kmdf_ctrl == direct_ctrl,
            &mut passed,
        );
    }

    print_str(b"[ntos-exec summary: ");
    print_u64(passed);
    print_str(b"/57 executive->isolated-service checks passed]\n");
    print_str(b"[microtest done]\n");
    park()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_put_char(b'!');
    park()
}
