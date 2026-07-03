//! `ntos-driver-host-svc` — the Driver Host as an ISOLATED seL4 component.
//!
//! A broker root task the rust-micro kernel boots. It spawns a fully-isolated
//! child (its own CSpace + VSpace) whose VSpace includes an **executable** region;
//! the child maps the real `SurtTest.sys` WDM driver into it and runs its
//! `DriverEntry` + IRP dispatch under the Microsoft x64 ABI — a real Windows
//! driver executing in an isolated, fault-contained seL4 component.
//!
//! Phase 3a (this): the child runs the driver + reports its pass count to the
//! broker over an endpoint. Phase 3b drives IRPs over the SURT `DH_OP_*` transport.

#![no_std]
#![no_main]

extern crate alloc;

pub use sel4_rt::*;

mod allocator;
mod driver_host;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

// --- child VSpace layout (all but the driver image share one 2 MiB PT) ------
pub const IMAGE_BASE: u64 = 0x0000_0100_0040_0000;
pub const STACK_BASE: u64 = 0x0000_0100_005C_0000;
pub const STACK_FRAMES: u64 = 8; // 32 KiB (the driver runs on this stack)
pub const IPCBUF_VADDR: u64 = 0x0000_0100_005F_B000;

/// The driver image region — a fresh PML4 entry, mapped RWX in the child.
pub const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
pub const CODE_FRAMES: u64 = 8; // 32 KiB (SurtTest.sys is 0x7000)

/// A dedicated RW page for the child's driver-runtime state (the image `.bss` is
/// mapped read-only, so mutable statics can't live there).
pub const STATE_VADDR: u64 = 0x0000_0100_0050_0000;

// Child CSpace slots.
pub const CT_PML4: u64 = 2;
pub const CT_RESULT: u64 = 5;

const CN_RADIX: u32 = 5;
const CN_GUARD_BADGE: u64 = 59;

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_START: AtomicU64 = AtomicU64::new(0);
static IMAGE_FRAMES_COUNT: AtomicU64 = AtomicU64::new(0);

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
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
    }
}

unsafe fn build_component_vspace() -> u64 {
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

    // Child image frames (shared, RO).
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RO */ 2, pml4);
    }
    // Private heap — RW.
    for i in 0..allocator::HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, /* RW */ 3, pml4);
    }
    // Private stack — RW.
    for i in 0..STACK_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, STACK_BASE + i * 0x1000, /* RW */ 3, pml4);
    }
    // Driver-runtime state page — RW (shares the image's 2 MiB PT).
    let state = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, state);
    let _ = page_map(state, STATE_VADDR, /* RW */ 3, pml4);
    // Driver image region — RW(X) at a fresh PML4 entry.
    map_fresh_region(pml4, CODE_VADDR, CODE_FRAMES, /* RW + exec */ 3);
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

unsafe fn spawn_component(entry: unsafe extern "C" fn() -> !, seeds: &[(u64, u64)]) {
    let pml4 = build_component_vspace();
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, 3, pml4);
    let cnode = build_component_cnode();
    seed_cnode(cnode, CT_PML4, pml4);
    for &(slot, src) in seeds {
        seed_cnode(cnode, slot, src);
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

    print_str(b"[ntos-dhs] real WDM driver in an ISOLATED seL4 component\n");

    let result_ep = make_object(OBJ_ENDPOINT);
    let result_c = copy_cap(result_ep);
    spawn_component(driver_host::driver_host_entry, &[(CT_RESULT, result_c)]);

    // Block until the isolated Driver Host reports how many checks passed.
    let (_r, _b, _i, verdict) = ep_recv(result_ep);
    print_str(b"[ntos-dhs summary: ");
    print_u64(verdict);
    print_str(b" passed, ");
    print_u64(driver_host::CHECKS.saturating_sub(verdict));
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
