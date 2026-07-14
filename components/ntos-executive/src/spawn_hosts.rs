//! `spawn_hosts` — spawners for the isolated hosts (ISR / WDM driver-host / KMDF
//! host / win32k host / storage host), each a least-privilege seL4 component.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

/// Spawn the isolated ISR "driver host" (P1): its own VSpace (image RO + stack + IPC
/// buffer) and a CNode holding ONLY a cap to the IRQ notification + the result
/// notification — least privilege. Its thread (`isr_entry`) blocks on the IRQ
/// notification and, when the real interrupt fires, signals the result notification.
pub(crate) unsafe fn spawn_isr(entry: unsafe extern "C" fn() -> !, irq_cap: u64, result_cap: u64, prio: u64) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    map_image_skeleton(pml4, img_count);
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
pub(crate) unsafe fn spawn_driver_host(
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
    map_image_skeleton(pml4, img_count);
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
    // Granted device resources, mapped into the host's VSpace (all within the cluster PT):
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
pub(crate) unsafe fn spawn_kmdf_host(
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
    map_image_skeleton(pml4, img_count);
    map_heap_pt(pml4);
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
    for i in 0..allocator::SERVICE_HEAP_FRAMES {
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

/// Spawn the isolated **win32k-service** component: like `spawn_kmdf_host` but scaled to the
/// 2.1 MiB win32k image. Maps the executive image RWX (the trampolines live there), a heap +
/// deep stack, the pre-loaded win32k PE at `WIN32K_CODE_VA` **W^X** (per-frame `code_rights`:
/// RX code / RW data), the pool arena, the data-export region, and the shared handoff page.
/// The executive receives on `fault_ep` (crash-contained): win32k's DriverEntry runs here and
/// every fault (or the completion SENTINEL) is delivered to the executive. Returns the host
/// `pml4` cap so the fault loop can demand-map pages into it.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn spawn_win32k_host(
    entry: unsafe extern "C" fn() -> !,
    fault_ep: u64,
    prio: u64,
    code_base: u64,
    code_rights: &[u64],
    pool_base: u64,
    data_base: u64,
    shared_frame: u64,
    heap_base: u64,
    arg_base: u64,
) -> u64 {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let stack_frames = 32u64; // 128 KiB — win32k init call chains are deep
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    map_image_skeleton(pml4, img_count);
    map_heap_pt(pml4);
    // Executive image RWX (the trampolines + statics the host calls into live in it).
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, /* RWX */ 3, pml4);
    }
    for i in 0..allocator::SERVICE_HEAP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, allocator::HEAP_BASE as u64 + i * 0x1000, RW_NX, pml4);
    }
    // win32k's OWN stack at WIN32K_STACK_VADDR (NOT the hosted-process STACK_BASE — that VA must stay
    // free in win32k's VSpace so the per-client attach can identity-map a client's stack-built pointer
    // there). Its own 2 MiB PT (128 KiB stack fits one PT).
    let wspt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wspt);
    let _ = paging_struct_map(wspt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_STACK_VADDR, pml4);
    let mut stack_slot_base = 0u64;
    for i in 0..stack_frames {
        let f = alloc_slot();
        if i == 0 {
            stack_slot_base = f;
        }
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, win32k_host::WIN32K_STACK_VADDR + i * 0x1000, RW_NX, pml4);
    }
    WIN32K_STACK_SLOT.store(stack_slot_base, Ordering::Relaxed);
    WIN32K_STACK_FRAMES.store(stack_frames, Ordering::Relaxed);
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // The pre-loaded win32k PE image, W^X (per-frame rights). Two 2 MiB PTs.
    for p in 0..2u64 {
        let cpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cpt);
        let _ = paging_struct_map(cpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_CODE_VA + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_IMAGE_FRAMES {
        let cp = copy_cap(code_base + i);
        let rights = code_rights.get(i as usize).copied().unwrap_or(RW_NX);
        let _ = page_map(cp, win32k_host::WIN32K_CODE_VA + i * 0x1000, rights, pml4);
    }
    // DATA/SHARED/SENTINEL/ARG share the aux PT window (0x0700_0000..0x0720_0000); the pool has its
    // own dedicated window (0x0A00_0000, 8 MiB / 4 PTs), pre-mapped.
    let apt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, apt);
    let _ = paging_struct_map(apt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_AUX_PT_VADDR, pml4);
    for p in 0..(win32k_host::WIN32K_POOL_FRAMES + 511) / 512 {
        let ppt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ppt);
        let _ = paging_struct_map(ppt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_POOL_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_POOL_FRAMES {
        let cp = copy_cap(pool_base + i);
        let _ = page_map(cp, win32k_host::WIN32K_POOL_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // FreeType's separate arena (win32k-only; own window + PTs, pre-mapped) — bounds ftfd's unbounded
    // font-init allocations so they can't starve the main pool.
    for p in 0..(win32k_host::WIN32K_FTYP_FRAMES + 511) / 512 {
        let fpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, fpt);
        let _ = paging_struct_map(fpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_FTYP_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_FTYP_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, win32k_host::WIN32K_FTYP_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // GDI-attribute user-mode VM arena (ZwAllocateVirtualMemory: GDI DC_ATTR / RGN_ATTR pools) —
    // own window + PTs, pre-mapped RW so RESERVE hands out backed memory and COMMIT is a no-op.
    for p in 0..(win32k_host::WIN32K_USERVM_FRAMES + 511) / 512 {
        let upt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, upt);
        let _ = paging_struct_map(upt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_USERVM_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_USERVM_FRAMES {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, win32k_host::WIN32K_USERVM_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The staged system font (arial.ttf) frames — the SAME frames the storage host filled (via
    // FONTBUF_START) mapped into win32k at FONTBUF_VADDR, so load_system_font can feed the raw ttf
    // bytes to IntGdiAddFontMemResource (own PT window at 0x06E0).
    let font_base = FONTBUF_START.load(Ordering::Relaxed);
    if font_base != 0 {
        let fbpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, fbpt);
        let _ = paging_struct_map(fbpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::FONTBUF_VADDR, pml4);
        for i in 0..win32k_host::FONTBUF_FRAMES {
            let _ = page_map(copy_cap(font_base + i), win32k_host::FONTBUF_VADDR + i * 0x1000, RW_NX, pml4);
        }
    }
    for i in 0..win32k_host::WIN32K_DATA_FRAMES {
        let cp = copy_cap(data_base + i);
        let _ = page_map(cp, win32k_host::WIN32K_DATA_VADDR + i * 0x1000, RW_NX, pml4);
    }
    let sh = copy_cap(shared_frame);
    let _ = page_map(sh, win32k_host::WIN32K_SHARED_VADDR, RW_NX, pml4);
    // The cross-AS arg-marshal frame(s) (same pool PT window as pool/data/shared).
    for i in 0..win32k_host::WIN32K_ARG_FRAMES {
        let _ = page_map(copy_cap(arg_base + i), win32k_host::WIN32K_ARG_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The win32k session-heap + Mm-view arena (RtlAllocateHeap + MmMapView*) — 4096 frames =
    // 16 MiB, 8 PTs (0x0740_0000..0x0840_0000).
    for p in 0..(win32k_host::WIN32K_HEAP_FRAMES / 512) {
        let hpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, hpt);
        let _ = paging_struct_map(hpt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_HEAP_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..win32k_host::WIN32K_HEAP_FRAMES {
        let cp = copy_cap(heap_base + i);
        let _ = page_map(cp, win32k_host::WIN32K_HEAP_VADDR + i * 0x1000, RW_NX, pml4);
    }

    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, fault_ep, 0);
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    WIN32K_TCB.store(tcb, Ordering::Relaxed);
    let _ = tcb_set_space(tcb, CT_FAULT, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = win32k_host::WIN32K_STACK_VADDR + stack_frames * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    // win32k is a kernel driver: it reads the KPCR via `gs:[..]`. Point GS at a zeroed KPCR
    // placeholder so those reads resolve (0) instead of faulting on linear address `[0x30]` etc.
    let _ = tcb_set_gs_base(tcb, win32k_host::WIN32K_KPCR_VA);
    // NOTE: win32k is NOT marked HOSTED (unlike smss/csrss): its init/trampoline code issues REAL
    // seL4 syscalls (SysDebugPutChar for serial), which must dispatch natively. The dispatch loop's
    // ready/done signal instead faults by putting an INVALID nr in RDX (see `dispatch_signal`), so
    // only that one syscall becomes an UnknownSyscall the executive catches.
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    pml4
}

/// Spawn an isolated **storage** host: an RO-image component granted ONLY the AHCI BAR + a
/// DMA frame + a shared word, so it drives the disk entirely from its own VSpace. The
/// executive (Tier-1 broker) has already enabled Bus Master; the host gets no PCI-config
/// access. `shared` carries `dma_paddr` in (@0) and the verdict + INITRD info out.
pub(crate) unsafe fn spawn_storage_host(
    entry: unsafe extern "C" fn() -> !,
    result_cap: u64,
    fault_ep: u64,
    prio: u64,
    ahci_bar_frame: u64,
    dma_frame: u64,
    shared_frame: u64,
    filebuf_start: u64,
    ntdllbuf_start: u64,
    srvbuf_start: u64,
    win32buf_start: u64,
    nls_ansi_start: u64,
    nls_oem_start: u64,
    nls_case_start: u64,
    nls20127_start: u64,
    hivebuf_start: u64,
    win32kbuf_start: u64,
    winlogonbuf_start: u64,
) {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    map_image_skeleton(pml4, img_count);
    // Image mapped READ-ONLY (rights=2) — the storage path writes no statics, so the host
    // cannot scribble on the executive's shared code/data.
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
    // Granted device resources (each a copy aliasing the executive's frame): the AHCI BAR
    // (1 page) at AHCI_VADDR, the DMA frame at AHCI_DMA_VADDR, the shared word.
    let bar_cp = copy_cap(ahci_bar_frame);
    let _ = page_map(bar_cp, AHCI_VADDR, RW_NX, pml4);
    let dma_cp = copy_cap(dma_frame);
    let _ = page_map(dma_cp, AHCI_DMA_VADDR, RW_NX, pml4);
    let sh_cp = copy_cap(shared_frame);
    let _ = page_map(sh_cp, STORAGE_SHARED_VADDR, RW_NX, pml4);
    // The shared file buffer (a run of FILEBUF_FRAMES consecutive frame caps), mapped
    // contiguously so the host can read a whole PE off disk into it for the executive to parse.
    // FILEBUF_VADDR is a fresh 2 MiB region in the host's VSpace too — give it its own PT.
    let fb_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, fb_pt);
    let _ = paging_struct_map(fb_pt, LBL_X86_PAGE_TABLE_MAP, FILEBUF_VADDR, pml4);
    for i in 0..FILEBUF_FRAMES {
        let fb_cp = copy_cap(filebuf_start + i);
        let _ = page_map(fb_cp, FILEBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The ntdll buffer (its own PT), same pattern.
    let nb_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, nb_pt);
    let _ = paging_struct_map(nb_pt, LBL_X86_PAGE_TABLE_MAP, NTDLLBUF_VADDR, pml4);
    for i in 0..NTDLLBUF_FRAMES {
        let nb_cp = copy_cap(ntdllbuf_start + i);
        let _ = page_map(nb_cp, NTDLLBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The server-DLL buffer (basesrv.dll + winsrv.dll, its own PT), same pattern.
    let sb_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, sb_pt);
    let _ = paging_struct_map(sb_pt, LBL_X86_PAGE_TABLE_MAP, SRVBUF_VADDR, pml4);
    for i in 0..SRVBUF_FRAMES {
        let sb_cp = copy_cap(srvbuf_start + i);
        let _ = page_map(sb_cp, SRVBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The Win32 client-stack buffer (kernel32+user32+gdi32 + Win32 deps, 4 PTs), mapped into the host too.
    for p in 0..4u64 {
        let wpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
        let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, WIN32BUF_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..WIN32BUF_FRAMES {
        let wb_cp = copy_cap(win32buf_start + i);
        let _ = page_map(wb_cp, WIN32BUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The raw win32k.sys staging buffer (544 frames = two 2 MiB PTs), mapped into the host too.
    for p in 0..2u64 {
        let kpt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, kpt);
        let _ = paging_struct_map(kpt, LBL_X86_PAGE_TABLE_MAP, WIN32KBUF_VADDR + p * 0x20_0000, pml4);
    }
    for i in 0..WIN32KBUF_FRAMES {
        let kb_cp = copy_cap(win32kbuf_start + i);
        let _ = page_map(kb_cp, WIN32KBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The raw winlogon.exe staging buffer (its own PT), mapped into the host too so it reads the PE
    // off disk into it; the executive parses the same frames + spawns winlogon.
    let wl_pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wl_pt);
    let _ = paging_struct_map(wl_pt, LBL_X86_PAGE_TABLE_MAP, WINLOGONBUF_VADDR, pml4);
    for i in 0..WINLOGONBUF_FRAMES {
        let wl_cp = copy_cap(winlogonbuf_start + i);
        let _ = page_map(wl_cp, WINLOGONBUF_VADDR + i * 0x1000, RW_NX, pml4);
    }
    // The raw dxg.sys / dxgthk.sys staging buffers (one PT each), mapped into the host too.
    for (start, vaddr, frames) in [
        (DXGBUF_START.load(Ordering::Relaxed), DXGBUF_VADDR, DXGBUF_FRAMES),
        (DXGTHKBUF_START.load(Ordering::Relaxed), DXGTHKBUF_VADDR, DXGTHKBUF_FRAMES),
        (FTFDBUF_START.load(Ordering::Relaxed), FTFDBUF_VADDR, FTFDBUF_FRAMES),
        (FRAMEBUFBUF_START.load(Ordering::Relaxed), FRAMEBUFBUF_VADDR, FRAMEBUFBUF_FRAMES),
        (FONTBUF_START.load(Ordering::Relaxed), win32k_host::FONTBUF_VADDR, win32k_host::FONTBUF_FRAMES),
    ] {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, vaddr, pml4);
        for i in 0..frames {
            let _ = page_map(copy_cap(start + i), vaddr + i * 0x1000, RW_NX, pml4);
        }
    }
    // The NLS + SYSTEM-hive buffers share the NTDLLBUF page table (0xA0-0xC0 region) — no extra PT.
    for (start, vaddr, frames) in [
        (nls_ansi_start, NLS_ANSI_VADDR, NLS_ANSI_FRAMES),
        (nls_oem_start, NLS_OEM_VADDR, NLS_OEM_FRAMES),
        (nls_case_start, NLS_CASE_VADDR, NLS_CASE_FRAMES),
        (nls20127_start, NLS_20127_VADDR, NLS_20127_FRAMES),
        (hivebuf_start, HIVEBUF_VADDR, HIVEBUF_FRAMES),
    ] {
        for i in 0..frames {
            let _ = page_map(copy_cap(start + i), vaddr + i * 0x1000, RW_NX, pml4);
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
    let stack_top = STACK_BASE + STACK_FRAMES * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, prio);
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
}
