//! `ntos-driver-host-svc` — the Driver Host as an ISOLATED seL4 component driven
//! over SURT.
//!
//! A broker root task spawns two fully-isolated children — an `io_side` requester
//! and a `driver_host` that maps the real `SurtTest.sys` into an **executable**
//! region and runs it. The io_side sends `DH_OP_DISPATCH_IRP` requests over a SURT
//! ring pair; the Driver Host runs the real driver's dispatch routine and replies
//! with the completion. A real Windows driver, executing in an isolated,
//! fault-contained component, driven across an address-space boundary.

#![no_std]
#![no_main]

extern crate alloc;

pub use sel4_rt::*;

mod allocator;
mod driver_host;
mod io_side;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use surt_sel4::surt_core::surt_abi::{feature, role, SurtCqe, SurtSqe};
use surt_sel4::surt_core::{init_ring, RingConfig};
use surt_sel4::{CPtr, Sel4Env};

// --- SURT wakeup: two seL4 syscalls ----------------------------------------
pub struct KernelEnv;

impl Sel4Env for KernelEnv {
    fn signal(&self, ntfn: CPtr) {
        unsafe {
            syscall5(SYS_SEND, ntfn, 0, 0, 0, 0);
        }
    }
    fn wait(&self, ntfn: CPtr) {
        unsafe {
            let _ = ep_recv(ntfn);
        }
    }
}

pub static ENV: KernelEnv = KernelEnv;

// --- child VSpace layout ----------------------------------------------------
pub const IMAGE_BASE: u64 = 0x0000_0100_0040_0000;
pub const SUB_RING_VADDR: u64 = 0x0000_0100_0050_0000;
pub const COMP_RING_VADDR: u64 = 0x0000_0100_0051_0000;
pub const REQ_DATA_VADDR: u64 = 0x0000_0100_0052_0000;
pub const REP_DATA_VADDR: u64 = 0x0000_0100_0053_0000;
pub const STATE_VADDR: u64 = 0x0000_0100_0054_0000; // driver_host only
pub const STACK_BASE: u64 = 0x0000_0100_005C_0000;
pub const IPCBUF_VADDR: u64 = 0x0000_0100_005F_B000;
pub const SCRATCH_VADDR: u64 = 0x0000_0100_005F_C000; // broker only

/// The driver image region — a fresh PML4 entry, RWX in the Driver Host child.
pub const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
pub const CODE_FRAMES: u64 = 8;

pub const STACK_FRAMES: u64 = 8;
pub const RING_LEN: usize = 4096;
const QLEN: u32 = 8;

// Child CSpace slots.
pub const CT_PML4: u64 = 2;
pub const CT_N_SUB: u64 = 3;
pub const CT_N_COMP: u64 = 4;
pub const CT_RESULT: u64 = 5;
/// Base slot for the driver image frame caps, seeded so the child can remap W^X.
pub const CT_CODE_BASE: u64 = 8;

static mut CODE_FRAME_CAPS: [u64; CODE_FRAMES as usize] = [0; CODE_FRAMES as usize];

const CN_RADIX: u32 = 5;
const CN_GUARD_BADGE: u64 = 59;

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

unsafe fn init_sqe_ring(frame: u64) {
    let _ = page_map(frame, SCRATCH_VADDR, 3, CAP_INIT_THREAD_VSPACE);
    let cfg = RingConfig {
        queue_len: QLEN,
        ring_id: 1,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let _ = init_ring::<SurtSqe>(SCRATCH_VADDR as *mut u8, RING_LEN, &cfg);
    let _ = page_unmap(frame);
}

unsafe fn init_cqe_ring(frame: u64) {
    let _ = page_map(frame, SCRATCH_VADDR, 3, CAP_INIT_THREAD_VSPACE);
    let cfg = RingConfig {
        queue_len: QLEN,
        ring_id: 2,
        feature_flags: feature::REQUIRED_V0_1,
        role: role::PRODUCER,
    };
    let _ = init_ring::<SurtCqe>(SCRATCH_VADDR as *mut u8, RING_LEN, &cfg);
    let _ = page_unmap(frame);
}

unsafe fn map_fresh_region(pml4: u64, base: u64, frames: u64, rights: u64) {
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, base, pml4);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, base, pml4);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, base, pml4);
    for i in 0..frames {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, base + i * 0x1000, rights, pml4);
        if i < CODE_FRAMES {
            CODE_FRAME_CAPS[i as usize] = f;
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn build_component_vspace(
    sub: u64,
    comp: u64,
    req: u64,
    rep: u64,
    with_driver: bool,
) -> u64 {
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
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, /* RW */ 3, pml4);
    }
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, /* RW */ 3, pml4);
    }
    // Shared SURT rings + data frames — RW, same vaddrs in both children.
    let _ = page_map(sub, SUB_RING_VADDR, 3, pml4);
    let _ = page_map(comp, COMP_RING_VADDR, 3, pml4);
    let _ = page_map(req, REQ_DATA_VADDR, 3, pml4);
    let _ = page_map(rep, REP_DATA_VADDR, 3, pml4);

    if with_driver {
        // Driver-runtime state page — RW.
        let state = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, state);
        let _ = page_map(state, STATE_VADDR, /* RW */ 3, pml4);
        // Driver image region — RW(X) at a fresh PML4 entry.
        map_fresh_region(pml4, CODE_VADDR, CODE_FRAMES, /* RW + exec */ 3);
    }
    pml4
}

unsafe fn build_component_cnode() -> u64 {
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let guarded = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, guarded, raw, CN_GUARD_BADGE);
    guarded
}

unsafe fn seed_cnode(cnode: u64, dest_slot: u64, src: u64) {
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, dest_slot, src, 0);
}

#[allow(clippy::too_many_arguments)]
unsafe fn spawn_component(
    entry: unsafe extern "C" fn() -> !,
    seeds: &[(u64, u64)],
    sub: u64,
    comp: u64,
    req: u64,
    rep: u64,
    with_driver: bool,
) {
    let pml4 = build_component_vspace(sub, comp, req, rep, with_driver);
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, 3, pml4);
    let cnode = build_component_cnode();
    seed_cnode(cnode, CT_PML4, pml4);
    for &(slot, src) in seeds {
        seed_cnode(cnode, slot, src);
    }
    if with_driver {
        // Give the child its image frame caps so it can remap the region W^X.
        for i in 0..CODE_FRAMES {
            seed_cnode(cnode, CT_CODE_BASE + i, CODE_FRAME_CAPS[i as usize]);
        }
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

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);
    let img = bi.user_image_frames;
    IMAGE_FRAMES_START.store(img.start, Ordering::Relaxed);
    IMAGE_FRAMES_COUNT.store(img.end - img.start, Ordering::Relaxed);

    print_str(b"[ntos-dhs] real WDM driver in an isolated component, driven over SURT\n");

    let n_sub = make_object(OBJ_NOTIFICATION);
    let n_comp = make_object(OBJ_NOTIFICATION);
    let result_ep = make_object(OBJ_ENDPOINT);
    let f_sub = alloc_frame();
    let f_comp = alloc_frame();
    let f_req = alloc_frame();
    let f_rep = alloc_frame();

    init_sqe_ring(f_sub);
    init_cqe_ring(f_comp);

    let n_sub_c = copy_cap(n_sub);
    let n_comp_c = copy_cap(n_comp);
    let result_c = copy_cap(result_ep);
    let f_sub_c = copy_cap(f_sub);
    let f_comp_c = copy_cap(f_comp);
    let f_req_c = copy_cap(f_req);
    let f_rep_c = copy_cap(f_rep);

    // Driver Host: waits N_SUB (requests), signals N_COMP (completions); runs the
    // real driver in its executable region.
    spawn_component(
        driver_host::driver_host_entry,
        &[(CT_N_SUB, n_sub), (CT_N_COMP, n_comp)],
        f_sub,
        f_comp,
        f_req,
        f_rep,
        true,
    );
    // io_side: signals N_SUB, waits N_COMP, reports the verdict on RESULT.
    spawn_component(
        io_side::io_side_entry,
        &[(CT_N_SUB, n_sub_c), (CT_N_COMP, n_comp_c), (CT_RESULT, result_c)],
        f_sub_c,
        f_comp_c,
        f_req_c,
        f_rep_c,
        false,
    );

    let (_r, _b, _i, verdict) = ep_recv(result_ep);
    print_str(b"[ntos-dhs summary: ");
    print_u64(verdict);
    print_str(b" passed, ");
    print_u64(io_side::CHECKS.saturating_sub(verdict));
    print_str(b" failed]\n");
    print_str(b"[microtest done]\n");
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_put_char(b'!');
    loop {
        yield_now();
    }
}
