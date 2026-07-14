//! `spawn_hosts` — spawners for the isolated hosts (ISR / WDM driver-host / KMDF
//! host / win32k host / storage host), each a least-privilege seL4 component.
//!
//! All five now share ONE generic MECHANISM engine — [`spawn_component`] — which
//! consumes a declarative [`ComponentDescriptor`] (data-only POLICY: which frames /
//! VAs / rights / caps the isolated component is granted). Each `spawn_*` below is a
//! thin descriptor-builder. This is effort-1 of the driver model (see
//! `project_driver_model.md`): the descriptor shape is the CONTRACT a future `nt-pnp`
//! will populate for device drivers (its device-cap section = PnP-minted MMIO/IRQ/DMA
//! caps). Behaviour is byte-identical to the old bespoke spawners.
#![allow(clippy::all)]
use crate::*;

/// Where a region's frame caps come from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameSource {
    /// Fresh retype-zeroed 4K pages (private to this component; e.g. stack, heap, IPC buf).
    FreshZeroed,
    /// `copy_cap`-aliased frames starting at this cap slot — the SAME physical frames are
    /// (or stay) mapped in the executive too (device BARs, DMA, staging buffers, shared pages).
    Alias(u64),
}

/// Per-frame rights for a region.
#[derive(Clone, Copy)]
pub(crate) enum Rights {
    /// One uniform rights value for every frame (2=RO, 3=RWX, `RW_NX`, …).
    Uniform(u64),
    /// A per-frame rights slice (the W^X case: RX code / RW data). Frames past the slice
    /// fall back to `RW_NX`.
    PerFrame(&'static [u64]),
}

/// A contiguous VA region to map into the component's VSpace: `count` frames from `source`
/// at `base_va`, with `rights`. `pts` = how many dedicated page-tables to retype+map first,
/// one per 2 MiB starting at `base_va` (0 = none; the VAs are already covered by the image
/// skeleton or a prior region's PT window). A region may declare `pts` with `count: 0` to build
/// a PT window that LATER regions map frames into (the win32k aux window).
#[derive(Clone, Copy)]
pub(crate) struct Region {
    pub source: FrameSource,
    pub base_va: u64,
    pub count: u64,
    pub rights: Rights,
    pub pts: u64,
}

/// Helper: `pts` value that gives one PT per 2 MiB spanning `count` frames.
#[inline]
const fn pts_for(count: u64) -> u64 {
    (count + 511) / 512
}

/// Which shared caps to copy into the component's CNode (PML4 is always copied). Each is an
/// `Option<cap>`; `None` = not granted. This is the declarative least-privilege cap POLICY.
#[derive(Clone, Copy, Default)]
pub(crate) struct GrantedCaps {
    pub irq_ntfn: Option<u64>,
    pub result_ntfn: Option<u64>,
    pub fault_ep: Option<u64>,
}

/// Fully declarative description of an isolated component to spawn. DATA only — the POLICY
/// (which frames/VAs/rights/caps). [`spawn_component`] turns it into the seL4 MECHANISM.
pub(crate) struct ComponentDescriptor<'a> {
    /// The component's entry point (a raw executive fn — the hosted-PE trampolines live in the image).
    pub entry: unsafe extern "C" fn() -> !,
    /// The executive image mapping (base = `IMAGE_BASE`, count = `IMAGE_FRAMES_COUNT`); its rights
    /// differ per host (RO / RWX / W^X). The image skeleton (pdpt/pd/image PTs/cluster PT) is
    /// always built.
    pub image_rights: Rights,
    /// Map the heap PT (`HEAP_BASE`) as part of the skeleton (kmdf/win32k need it before regions).
    pub map_heap_pt: bool,
    /// Stack: base VA, frame count, and whether it needs its OWN dedicated PT (win32k's stack is
    /// at a private VA outside the image skeleton).
    pub stack_base: u64,
    pub stack_frames: u64,
    pub stack_dedicated_pt: bool,
    /// Additional regions (heap, MMIO BARs, DMA, staging buffers, arenas, shared pages, …), in
    /// map order. Mapped after the image + stack + IPC buffer.
    pub regions: &'a [Region],
    /// Caps copied into the component's CNode (PML4 always; these are optional).
    pub granted: GrantedCaps,
    /// Priority.
    pub prio: u64,
    /// Optional GS base (win32k's KPCR placeholder). `None` = leave GS unset.
    pub gs_base: Option<u64>,
}

/// What a spawned component hands back (the caps the caller may still need).
pub(crate) struct SpawnedComponent {
    pub pml4: u64,
    pub tcb: u64,
    pub cnode: u64,
    /// The cap slot of the first stack frame (win32k stashes this for later remaps). Only
    /// meaningful when the stack uses `FreshZeroed`.
    pub stack_frame_base: u64,
}

/// THE generic mechanism: build a fresh VSpace + CSpace + TCB for an isolated component from a
/// declarative [`ComponentDescriptor`], granting exactly the frames/VAs/rights/caps it names, and
/// resume it. This is the seL4 dance written ONCE; every `spawn_*` below is a descriptor-builder.
pub(crate) unsafe fn spawn_component(d: &ComponentDescriptor) -> SpawnedComponent {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let pml4 = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PML4, PAGING_BITS, 1, pml4);
    map_image_skeleton(pml4, img_count);
    if d.map_heap_pt {
        map_heap_pt(pml4);
    }
    // Executive image frames.
    for i in 0..img_count {
        let cp = alloc_slot();
        let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_COPY << 12, cp, img_start + i, 0);
        let _ = page_map(cp, IMAGE_BASE + i * 0x1000, rights_at(d.image_rights, i), pml4);
    }
    // Stack.
    if d.stack_dedicated_pt {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, d.stack_base, pml4);
    }
    let mut stack_frame_base = 0u64;
    for i in 0..d.stack_frames {
        let f = alloc_slot();
        if i == 0 {
            stack_frame_base = f;
        }
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, d.stack_base + i * 0x1000, RW_NX, pml4);
    }
    // IPC buffer (always a fresh page at IPCBUF_VADDR).
    let ipcbuf = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, ipcbuf);
    let _ = page_map(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    // Additional regions.
    for r in d.regions {
        map_region(pml4, r);
    }
    // CSpace: a guarded CNode holding PML4 + the granted caps.
    let raw = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_CNODE, CN_RADIX, 1, raw);
    let cnode = alloc_slot();
    let _ = syscall5(SYS_SEND, CAP_INIT_THREAD_CNODE, LBL_CNODE_MINT << 12, cnode, raw, CN_GUARD_BADGE);
    let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_PML4, pml4, 0);
    if let Some(c) = d.granted.irq_ntfn {
        let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_IRQ_NTFN, c, 0);
    }
    if let Some(c) = d.granted.result_ntfn {
        let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_RESULT_NTFN, c, 0);
    }
    if let Some(c) = d.granted.fault_ep {
        let _ = syscall5(SYS_SEND, cnode, LBL_CNODE_COPY << 12, CT_FAULT, c, 0);
    }
    // TCB.
    let tcb = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_TCB, 0, 1, tcb);
    // The fault-handler cap slot in the new CSpace is CT_FAULT when a fault EP was granted, else 0.
    let fault_slot = if d.granted.fault_ep.is_some() { CT_FAULT } else { 0 };
    let _ = tcb_set_space(tcb, fault_slot, cnode, pml4);
    let _ = syscall5(SYS_SEND, tcb, LBL_TCB_SET_IPC_BUFFER << 12, IPCBUF_VADDR, ipcbuf, 0);
    let stack_top = d.stack_base + d.stack_frames * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, d.entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, d.prio);
    if let Some(gs) = d.gs_base {
        let _ = tcb_set_gs_base(tcb, gs);
    }
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    SpawnedComponent { pml4, tcb, cnode, stack_frame_base }
}

/// Resolve the rights for frame `i` of a region/image.
#[inline]
fn rights_at(r: Rights, i: u64) -> u64 {
    match r {
        Rights::Uniform(v) => v,
        Rights::PerFrame(s) => s.get(i as usize).copied().unwrap_or(RW_NX),
    }
}

/// Map one [`Region`] into `pml4`: optionally build dedicated PTs (one per 2 MiB), then map each
/// frame from its source with its rights.
unsafe fn map_region(pml4: u64, r: &Region) {
    for p in 0..r.pts {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, r.base_va + p * 0x20_0000, pml4);
    }
    for i in 0..r.count {
        let cap = match r.source {
            FrameSource::FreshZeroed => {
                let f = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                f
            }
            FrameSource::Alias(base) => copy_cap(base + i),
        };
        let _ = page_map(cap, r.base_va + i * 0x1000, rights_at(r.rights, i), pml4);
    }
}

/// Spawn the isolated ISR "driver host" (P1): its own VSpace (image RO + stack + IPC
/// buffer) and a CNode holding ONLY a cap to the IRQ notification + the result
/// notification — least privilege. Its thread (`isr_entry`) blocks on the IRQ
/// notification and, when the real interrupt fires, signals the result notification.
pub(crate) unsafe fn spawn_isr(entry: unsafe extern "C" fn() -> !, irq_cap: u64, result_cap: u64, prio: u64) {
    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(2), // RO
        map_heap_pt: false,
        stack_base: STACK_BASE,
        stack_frames: STACK_FRAMES,
        stack_dedicated_pt: false,
        regions: &[],
        granted: GrantedCaps { irq_ntfn: Some(irq_cap), result_ntfn: Some(result_cap), fault_ep: None },
        prio,
        gs_base: None,
    };
    let _ = spawn_component(&d);
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
    // Granted device resources (all within the cluster PT window, no dedicated PTs): the 4 NIC BAR
    // pages, the confined DMA buffer, the CM_RESOURCE_LIST frame; then the real .sys image (RWX) +
    // its RW arena. Each device frame is a copy aliasing the executive's frame.
    let regions = [
        Region { source: FrameSource::Alias(bar_base), base_va: NIC_VADDR, count: 4, rights: Rights::Uniform(RW_NX), pts: 0 },
        Region { source: FrameSource::Alias(dma_frame), base_va: DMA_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
        Region { source: FrameSource::Alias(reslist_frame), base_va: RESLIST_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
        Region { source: FrameSource::Alias(pe_base), base_va: driver_pe::CODE_VA, count: driver_pe::PE_FRAMES, rights: Rights::Uniform(3 /* RWX */), pts: 0 },
        Region { source: FrameSource::Alias(arena_base), base_va: driver_pe::ARENA_VADDR, count: driver_pe::ARENA_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
    ];
    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(2), // RO
        map_heap_pt: false,
        stack_base: STACK_BASE,
        stack_frames: STACK_FRAMES,
        stack_dedicated_pt: false,
        regions: &regions,
        granted: GrantedCaps { irq_ntfn: Some(irq_cap), result_ntfn: Some(result_cap), fault_ep: Some(fault_ep) },
        prio,
        gs_base: None,
    };
    let _ = spawn_component(&d);
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
    // Image mapped RWX (the WDF function table + globals live in `.bss` — this host must WRITE
    // them). These are the executive's SHARED image frames, so a buggy host could scribble on the
    // executive; acceptable (host runs to completion first) — a private image copy is a follow-on.
    // Heap for the WDF runtime; the pre-loaded KMDF PE (RWX); the shared word; and (optionally) the
    // real e1000e NIC BAR (4 pages aliased) at NIC_VADDR for MmMapIoSpace.
    let mut regions: [Region; 4] = [
        Region { source: FrameSource::FreshZeroed, base_va: allocator::HEAP_BASE as u64, count: allocator::SERVICE_HEAP_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
        Region { source: FrameSource::Alias(kmdf_pe_base), base_va: kmdf_host::KMDF_CODE_VA, count: kmdf_host::KMDF_PE_FRAMES, rights: Rights::Uniform(3 /* RWX */), pts: 0 },
        Region { source: FrameSource::Alias(shared_frame), base_va: kmdf_host::KMDF_SHARED_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
        // Placeholder slot for the optional NIC BAR; count=0 when absent (no-op).
        Region { source: FrameSource::Alias(0), base_va: NIC_VADDR, count: 0, rights: Rights::Uniform(RW_NX), pts: 0 },
    ];
    if nic_bar_base != 0 {
        regions[3] = Region { source: FrameSource::Alias(nic_bar_base), base_va: NIC_VADDR, count: 4, rights: Rights::Uniform(RW_NX), pts: 0 };
    }
    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(3), // RWX
        map_heap_pt: true,
        stack_base: STACK_BASE,
        stack_frames: 16, // 64 KiB — WDF call chains are deep
        stack_dedicated_pt: false,
        regions: &regions,
        granted: GrantedCaps { irq_ntfn: None, result_ntfn: Some(result_cap), fault_ep: Some(fault_ep) },
        prio,
        gs_base: None,
    };
    let _ = spawn_component(&d);
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
    let stack_frames = 32u64; // 128 KiB — win32k init call chains are deep
    // code_rights is a &[u64]; the descriptor's PerFrame wants &'static. win32k_host::code_rights()
    // returns a &'static slice, so re-borrow it as such (it lives in the win32k module's statics).
    let code_rights_static: &'static [u64] = core::mem::transmute::<&[u64], &'static [u64]>(code_rights);
    let font_base = FONTBUF_START.load(Ordering::Relaxed);

    // Regions, in the EXACT order the old bespoke spawner mapped them (order is behaviourally
    // irrelevant but kept identical for a byte-identical boot). The image is RWX (image_rights);
    // the win32k PE is W^X (PerFrame code_rights). DATA/SHARED/ARG share the aux PT window (a single
    // aux-PT region with count=0 builds that PT ahead of them). We model each window's `pts` explicitly.
    //
    // NOTE: several windows below carried their own PT builds in the original; we reproduce each.
    let mut regions: [Region; 32] = [Region { source: FrameSource::Alias(0), base_va: 0, count: 0, rights: Rights::Uniform(RW_NX), pts: 0 }; 32];
    let mut n = 0usize;
    // Heap (uses the pre-built heap PT — map_heap_pt=true).
    regions[n] = Region { source: FrameSource::FreshZeroed, base_va: allocator::HEAP_BASE as u64, count: allocator::SERVICE_HEAP_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
    // win32k PE image, W^X, its own two 2 MiB PTs.
    regions[n] = Region { source: FrameSource::Alias(code_base), base_va: win32k_host::WIN32K_CODE_VA, count: win32k_host::WIN32K_IMAGE_FRAMES, rights: Rights::PerFrame(code_rights_static), pts: 2 }; n += 1;
    // The aux PT window (DATA/SHARED/ARG live here) — a single PT built ahead of those frames.
    regions[n] = Region { source: FrameSource::Alias(0), base_va: win32k_host::WIN32K_AUX_PT_VADDR, count: 0, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
    // Pool arena (own window + PTs).
    regions[n] = Region { source: FrameSource::Alias(pool_base), base_va: win32k_host::WIN32K_POOL_VADDR, count: win32k_host::WIN32K_POOL_FRAMES, rights: Rights::Uniform(RW_NX), pts: pts_for(win32k_host::WIN32K_POOL_FRAMES) }; n += 1;
    // FreeType arena (own window + PTs, fresh frames).
    regions[n] = Region { source: FrameSource::FreshZeroed, base_va: win32k_host::WIN32K_FTYP_VADDR, count: win32k_host::WIN32K_FTYP_FRAMES, rights: Rights::Uniform(RW_NX), pts: pts_for(win32k_host::WIN32K_FTYP_FRAMES) }; n += 1;
    // GDI-attribute user-mode VM arena (own window + PTs, fresh frames).
    regions[n] = Region { source: FrameSource::FreshZeroed, base_va: win32k_host::WIN32K_USERVM_VADDR, count: win32k_host::WIN32K_USERVM_FRAMES, rights: Rights::Uniform(RW_NX), pts: pts_for(win32k_host::WIN32K_USERVM_FRAMES) }; n += 1;
    // Staged system font (arial.ttf) — its own PT window, aliased frames (only if present).
    if font_base != 0 {
        regions[n] = Region { source: FrameSource::Alias(font_base), base_va: win32k_host::FONTBUF_VADDR, count: win32k_host::FONTBUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
    }
    // DATA export region (aux PT window — no dedicated PT).
    regions[n] = Region { source: FrameSource::Alias(data_base), base_va: win32k_host::WIN32K_DATA_VADDR, count: win32k_host::WIN32K_DATA_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
    // Shared handoff page (aux PT window).
    regions[n] = Region { source: FrameSource::Alias(shared_frame), base_va: win32k_host::WIN32K_SHARED_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
    // Arg-marshal frame(s) (aux PT window).
    regions[n] = Region { source: FrameSource::Alias(arg_base), base_va: win32k_host::WIN32K_ARG_VADDR, count: win32k_host::WIN32K_ARG_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
    // Session-heap + Mm-view arena (own window + PTs, aliased frames). Original used HEAP_FRAMES/512.
    regions[n] = Region { source: FrameSource::Alias(heap_base), base_va: win32k_host::WIN32K_HEAP_VADDR, count: win32k_host::WIN32K_HEAP_FRAMES, rights: Rights::Uniform(RW_NX), pts: win32k_host::WIN32K_HEAP_FRAMES / 512 }; n += 1;

    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(3), // RWX (trampolines + statics)
        map_heap_pt: true,
        // win32k's OWN stack at WIN32K_STACK_VADDR (NOT STACK_BASE — that VA must stay free for the
        // per-client attach). Its own dedicated PT (128 KiB fits one PT).
        stack_base: win32k_host::WIN32K_STACK_VADDR,
        stack_frames,
        stack_dedicated_pt: true,
        regions: &regions[..n],
        granted: GrantedCaps { irq_ntfn: None, result_ntfn: None, fault_ep: Some(fault_ep) },
        prio,
        // win32k is a kernel driver: it reads the KPCR via gs:[..]. Point GS at a zeroed KPCR
        // placeholder so those reads resolve (0) instead of faulting.
        gs_base: Some(win32k_host::WIN32K_KPCR_VA),
    };
    let sc = spawn_component(&d);
    // Stash the globals the old bespoke spawner set (the demand-map fault loop + per-client attach
    // need them). The stack frame base is the first FreshZeroed frame of the dedicated stack.
    WIN32K_STACK_SLOT.store(sc.stack_frame_base, Ordering::Relaxed);
    WIN32K_STACK_FRAMES.store(stack_frames, Ordering::Relaxed);
    WIN32K_TCB.store(sc.tcb, Ordering::Relaxed);
    // NOTE: win32k is NOT marked HOSTED (unlike smss/csrss): its init/trampoline code issues REAL
    // seL4 syscalls (SysDebugPutChar for serial), which must dispatch natively. The dispatch loop's
    // ready/done signal instead faults by putting an INVALID nr in RDX (see `dispatch_signal`).
    sc.pml4
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
    // Granted device resources + staging buffers, in the EXACT map order of the old spawner.
    // Device resources (cluster PT window, no dedicated PT): AHCI BAR, DMA frame, shared word.
    // Then the staging buffers, each with its own dedicated PT(s) — EXCEPT the NLS + SYSTEM-hive
    // buffers, which share the NTDLLBUF page table (0xA0-0xC0 region) so map with pts=0.
    let mut regions: [Region; 32] = [Region { source: FrameSource::Alias(0), base_va: 0, count: 0, rights: Rights::Uniform(RW_NX), pts: 0 }; 32];
    let mut n = 0usize;
    regions[n] = Region { source: FrameSource::Alias(ahci_bar_frame), base_va: AHCI_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
    regions[n] = Region { source: FrameSource::Alias(dma_frame), base_va: AHCI_DMA_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
    regions[n] = Region { source: FrameSource::Alias(shared_frame), base_va: STORAGE_SHARED_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 }; n += 1;
    // FILEBUF (own PT), NTDLLBUF (own PT), SRVBUF (own PT).
    regions[n] = Region { source: FrameSource::Alias(filebuf_start), base_va: FILEBUF_VADDR, count: FILEBUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
    regions[n] = Region { source: FrameSource::Alias(ntdllbuf_start), base_va: NTDLLBUF_VADDR, count: NTDLLBUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
    regions[n] = Region { source: FrameSource::Alias(srvbuf_start), base_va: SRVBUF_VADDR, count: SRVBUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
    // WIN32BUF (4 PTs), WIN32KBUF (2 PTs).
    regions[n] = Region { source: FrameSource::Alias(win32buf_start), base_va: WIN32BUF_VADDR, count: WIN32BUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 4 }; n += 1;
    regions[n] = Region { source: FrameSource::Alias(win32kbuf_start), base_va: WIN32KBUF_VADDR, count: WIN32KBUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 2 }; n += 1;
    // WINLOGONBUF (own PT).
    regions[n] = Region { source: FrameSource::Alias(winlogonbuf_start), base_va: WINLOGONBUF_VADDR, count: WINLOGONBUF_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 }; n += 1;
    // dxg/dxgthk/ftfd/framebuf/font staging buffers (one PT each).
    for (start, vaddr, frames) in [
        (DXGBUF_START.load(Ordering::Relaxed), DXGBUF_VADDR, DXGBUF_FRAMES),
        (DXGTHKBUF_START.load(Ordering::Relaxed), DXGTHKBUF_VADDR, DXGTHKBUF_FRAMES),
        (FTFDBUF_START.load(Ordering::Relaxed), FTFDBUF_VADDR, FTFDBUF_FRAMES),
        (FRAMEBUFBUF_START.load(Ordering::Relaxed), FRAMEBUFBUF_VADDR, FRAMEBUFBUF_FRAMES),
        (FONTBUF_START.load(Ordering::Relaxed), win32k_host::FONTBUF_VADDR, win32k_host::FONTBUF_FRAMES),
    ] {
        regions[n] = Region { source: FrameSource::Alias(start), base_va: vaddr, count: frames, rights: Rights::Uniform(RW_NX), pts: 1 };
        n += 1;
    }
    // NLS + SYSTEM-hive buffers share the NTDLLBUF page table — NO dedicated PT.
    for (start, vaddr, frames) in [
        (nls_ansi_start, NLS_ANSI_VADDR, NLS_ANSI_FRAMES),
        (nls_oem_start, NLS_OEM_VADDR, NLS_OEM_FRAMES),
        (nls_case_start, NLS_CASE_VADDR, NLS_CASE_FRAMES),
        (nls20127_start, NLS_20127_VADDR, NLS_20127_FRAMES),
        (hivebuf_start, HIVEBUF_VADDR, HIVEBUF_FRAMES),
    ] {
        regions[n] = Region { source: FrameSource::Alias(start), base_va: vaddr, count: frames, rights: Rights::Uniform(RW_NX), pts: 0 };
        n += 1;
    }
    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(2), // RO — the storage path writes no statics
        map_heap_pt: false,
        stack_base: STACK_BASE,
        stack_frames: STACK_FRAMES,
        stack_dedicated_pt: false,
        regions: &regions[..n],
        granted: GrantedCaps { irq_ntfn: None, result_ntfn: Some(result_cap), fault_ep: Some(fault_ep) },
        prio,
        gs_base: None,
    };
    let _ = spawn_component(&d);
}
