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
pub(crate) const fn pts_for(count: u64) -> u64 {
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

// =============================================================================================
// Component-runtime harness ABI scaffolding (Phase B, Step 0).
//
// The two Family-A persistent dispatch servers (the npfs FSD + win32k) run near-identical
// recv→dispatch→reply loops on the component side and near-identical ep_send+demand-map fault
// pumps on the executive side. This block introduces the SHARED abstractions the two families
// converge onto: a KIND-tagged request header, a [`HostCaps`] capability set on
// [`ComponentDescriptor`] gating win32k's irreducible specifics, and the shared
// [`component_pump`] (executive-side) + [`component_main`] (component-side) run loops.
//
// STEP 0 is PURELY ADDITIVE: these types + fns are defined but WIRED TO NOTHING. Every existing
// descriptor keeps `caps: HostCaps::default()` (all-false) so the boot is byte-identical. The FSD
// migrates onto `component_pump`/`component_main` in Steps 1/2; win32k migrates LAST (Step 4).
// See `docs/component-harness.md` §2.
// =============================================================================================

/// The KIND a Family-A dispatch server speaks over its shared frame. `Irp` = the FSD IRP protocol
/// (reads `SH_REQ_MAJOR/MINOR/FSCTL/INLEN/OUTLEN/FILEID`, writes status@0x70 + info@0x78);
/// `Syscall` = win32k's SSN protocol (reads `SH_REQ_SSN/A0..`, writes status@0x78). Constant per
/// component (no component serves both today), so it is set once by the descriptor builder.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub(crate) enum ReqKind {
    Irp = 0,
    Syscall = 1,
}

impl Default for ReqKind {
    #[inline]
    fn default() -> Self {
        ReqKind::Irp
    }
}

/// Shared-frame request-header KIND tag offset. VERIFIED FREE in BOTH Family-A frames:
///   * FSD frame: between `SH_POOL_USED=0x28` and `SH_REQ_MAJOR=0x40` (`driver_launch.rs`).
///   * win32k frame: between `SH_POOL_USED=0x30` and `SH_NTUSER_HANDLER=0x40` (`win32k_subsystem.rs`).
/// A component builder MAY stamp its constant `ReqKind` here at spawn time; the pump can also key
/// KIND off the descriptor (`caps.kind`) since it is constant per component — the design's fallback.
pub(crate) const SH_REQ_KIND: u64 = 0x38;

/// Out: NTSTATUS offset — DIFFERS by KIND (FSD writes 0x70, win32k 0x78). The pump reads the offset
/// appropriate to `caps.kind`; these do NOT unify (design §2.2 status-offset note).
pub(crate) const SH_REQ_STATUS_IRP: u64 = 0x70;
pub(crate) const SH_REQ_STATUS_SYSCALL: u64 = 0x78;
/// Out: monotonic completed-request counter — SHARED (both frames already agree at 0x80).
pub(crate) const SH_REQ_SEQ: u64 = 0x80;

/// Capability flags on a component descriptor. ALL DEFAULT FALSE → a component with
/// `HostCaps::default()` is byte-identical to today (Family B + the FSD). The flags are consumed on
/// the EXECUTIVE side ([`component_pump`]) to gate win32k's irreducible specifics; the win32k
/// component-side specifics (usermode-callback registration, exact-arity transmute) stay keyed off
/// the SSN, not a runtime flag. See `docs/component-harness.md` §2.3.
#[derive(Clone, Copy, Default)]
pub(crate) struct HostCaps {
    /// Component runs a persistent recv→dispatch→reply server loop (Family A).
    /// false => one-shot run_once (Family B).
    pub dispatch_server: bool,
    /// Dispatch KIND the server speaks (only meaningful when `dispatch_server`).
    pub kind: ReqKind,
    /// win32k: attach the calling client's user memory (`w32_client_attach`) before each dispatch,
    /// and share foreign client frames on demand-fault instead of zero-filling.
    pub client_attach: bool,
    /// win32k: honour `KeUserModeCallback` / WINDOWPROC bridge (documents the capability; the
    /// callback is bound component-side in DriverEntry).
    pub usermode_callback: bool,
    /// win32k: stage wide (>4) stack args from the caller frame into `SH_REQ_A4..` / `SH_REQ_NARGS`.
    pub wide_arg_marshal: bool,
    /// win32k: skip checked-build int-0x2c NT_ASSERTs (resume IP+2) on a label-3 UserException.
    pub assert_skip: bool,
    /// win32k: answer nested demand-page faults through a per-caller reply cap (REPLY_W32) rather
    /// than the fault EP's reply_recv, so an outer caller's reply binding survives.
    pub nested_reply_cap: bool,
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
    /// Component-runtime capability flags (Phase B harness). `HostCaps::default()` (all-false) is
    /// byte-identical to a pre-harness component — consumed only by [`component_pump`].
    pub caps: HostCaps,
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
        caps: HostCaps::default(),
    };
    let _ = spawn_component(&d);
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
        (FONTBUF_START.load(Ordering::Relaxed), win32k_subsystem::FONTBUF_VADDR, win32k_subsystem::FONTBUF_FRAMES),
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
        caps: HostCaps::default(),
    };
    let _ = spawn_component(&d);
}

// =============================================================================================
// The unified component-runtime harness (Phase B): `component_pump` (executive-side) +
// `component_main` (component-side). STEP 0 defines them; they are wired to nothing yet. The FSD
// migrates onto them in Steps 1/2; win32k (which adds the flag-gated branches marked below) LAST.
// See `docs/component-harness.md` §2.4-2.5.
// =============================================================================================

/// The executive-side channel to one Family-A dispatch server. Carries the fault/dispatch EP, the
/// component VSpace (for demand-map), the in-image wall bounds, the shared frame base, the DONE
/// label, and the per-server demand budget. `reply_cap`/`client_pi`/`caps` gate win32k's specifics
/// (Step 4); for the FSD they are 0/0/all-false and the pump degenerates to today's
/// `npfs_dispatch_irp`/`load_driver` inner loop EXACTLY.
#[derive(Clone, Copy)]
pub(crate) struct PumpChannel {
    /// Dispatch + fault channel (the `CT_FAULT` peer cap for this component).
    pub fault_ep: u64,
    /// Component VSpace root, for demand-mapping its page faults.
    pub pml4: u64,
    /// In-image wall bounds: a fault whose address lands inside `[code_va, code_va+image_frames*0x1000)`
    /// is a real code-page fault (a wall), not a benign demand page. `image_frames == 0` disables the
    /// in-image wall (the per-IRP loop shape, which only walls on the low-address guard).
    pub code_va: u64,
    pub image_frames: u64,
    /// The `SH_*` shared-frame base for this component.
    pub shared_va: u64,
    /// The DONE / ready label the server Sends when it re-parks (0x771 FSD / 0x770 win32k).
    pub dispatch_label: u64,
    /// Max benign demand-pages to satisfy before walling (FSD init-loop = 512, per-IRP loop = 256).
    pub demand_cap: u64,
    /// Emit `[svc] fault #N ...` trace lines for the first 40 faults (init-loop observability).
    pub trace_faults: bool,
    /// Whether to WAKE the server with a leading `ep_send(dispatch_label)` before receiving.
    /// `true` = the PER-REQUEST shape: the server is parked in `recv_req_on` (a blocked receiver),
    /// so the executive Sends to hand it the request (the win32k / per-IRP loops). `false` = the
    /// DRIVER-ENTRY-INIT shape: the component is NOT yet at a recv — it is mid-DriverEntry and will
    /// fault (a blocked SENDER on the fault EP) or Send its ready signal, so the executive must start
    /// by RECEIVING (a leading Send would deadlock against the faulting sender). See `load_driver`.
    pub wake_first: bool,
    /// win32k Step-4 fields (0 for the FSD): the per-caller reply cap (REPLY_W32) and the client
    /// process-index for `client_attach`/foreign-frame sharing.
    pub reply_cap: u64,
    pub client_pi: u64,
    /// The win32k capability gates (all-false for the FSD).
    pub caps: HostCaps,
}

/// PROOF-OF-WIRING counters: `component_pump` increments these per SERVICED dispatch, tagged by
/// `ReqKind`. They are the durable evidence that a component's live traffic actually flows through
/// the SHARED harness pump (not the retired bespoke inline loop). The `exec_fsd_on_shared_harness`
/// gate spec asserts `HARNESS_IRP_DISPATCHES >= N` for the real npfs data-plane + 2nd-driver IRPs —
/// if the FSD were NOT routed through `component_pump`, this counter would stay 0 and the spec FAILS.
pub(crate) static HARNESS_IRP_DISPATCHES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub(crate) static HARNESS_SYSCALL_DISPATCHES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Total dispatches serviced by [`component_pump`] for the given `kind`.
pub(crate) fn harness_dispatches(kind: ReqKind) -> u64 {
    match kind {
        ReqKind::Irp => HARNESS_IRP_DISPATCHES.load(Ordering::Relaxed),
        ReqKind::Syscall => HARNESS_SYSCALL_DISPATCHES.load(Ordering::Relaxed),
    }
}

/// The outcome of one pump: `(status, completed)`. `completed=true` iff the server re-parked at its
/// dispatch loop (sent `dispatch_label`); `false` = it hit a wall (fault we won't demand-map).
#[derive(Clone, Copy)]
pub(crate) struct PumpResult {
    pub status: i32,
    pub completed: bool,
    /// Wall diagnostics (only meaningful when `!completed`).
    pub wall_ip: u64,
    pub wall_addr: u64,
    pub wall_label: u64,
    pub faults: u64,
    pub demand: u64,
}

/// Drive ONE request to a Family-A dispatch server: wake the parked server with `dispatch_label`,
/// demand-map its page faults against `pml4`, and return when it re-parks (completed) or walls.
///
/// The caller MUST have already filled the shared-frame request fields (the IRP struct build for
/// the FSD / the SSN+args for win32k) — the pump owns only the IPC + fault engine, not the KIND-
/// specific marshal. On completion the pump reads `SH_REQ_STATUS` at the offset appropriate to
/// `caps.kind` (0x70 Irp / 0x78 Syscall). This is the ONE loop `npfs_dispatch_irp` (Step 1) and
/// `load_driver`'s init loop (Step 1) and `win32k_dispatch_wide` (Step 4) converge onto.
///
/// On a COMPLETED dispatch (server re-parked) the pump bumps [`HARNESS_IRP_DISPATCHES`] /
/// [`HARNESS_SYSCALL_DISPATCHES`] per `caps.kind` — the durable proof the traffic is on the harness.
pub(crate) unsafe fn component_pump(ch: &PumpChannel) -> PumpResult {
    // (Step 4, win32k) if ch.caps.client_attach { w32_client_attach(ch.client_pi); }
    // (Step 4, win32k) if ch.caps.wide_arg_marshal { stage SH_REQ_A4../NARGS from the caller SP. }

    // Wake the server (per-request shape), then pump its faults until it re-parks or walls. The
    // DriverEntry-init shape (`wake_first=false`) starts by RECEIVING — the component is a blocked
    // sender (mid-init fault / ready-Send), so a leading Send would deadlock against it.
    if ch.wake_first {
        crate::ep_send(ch.fault_ep, ch.dispatch_label);
    }
    let (mut _b, mut mi, mut m0, mut m1, mut _m2, mut _m3) = crate::ep_recv_full(ch.fault_ep);
    let mut faults = 0u64;
    let mut demand = 0u64;
    let (mut wall_ip, mut wall_addr, mut wall_label) = (0u64, 0u64, 0u64);
    let mut completed = false;
    loop {
        let label = mi >> 12;
        if label == ch.dispatch_label {
            completed = true;
            break;
        } else if label == 6 {
            let ip = m0;
            let addr = m1;
            faults += 1;
            if ch.trace_faults && faults <= 40 {
                crate::print_str(b"[svc] fault #");
                crate::print_u64(faults);
                crate::print_str(b" ip=0x");
                crate::print_hex(ip as u32);
                crate::print_str(b" RVA=0x");
                crate::print_hex(ip.wrapping_sub(ch.code_va) as u32);
                crate::print_str(b" addr=0x");
                crate::print_hex((addr >> 32) as u32);
                crate::print_hex(addr as u32);
                crate::print_str(b"\n");
            }
            let in_image =
                ch.image_frames != 0 && addr >= ch.code_va && addr < ch.code_va + ch.image_frames * 0x1000;
            if addr < 0x10000 || in_image || demand >= ch.demand_cap {
                wall_ip = ip;
                wall_addr = addr;
                wall_label = label;
                break;
            }
            // (Step 4, win32k) if ch.caps.client_attach { foreign-frame-share / internal-low zero-fill. }
            let page = addr & !0xFFF;
            crate::driver_launch::ensure_paging(page, ch.pml4);
            let f = crate::alloc_frame();
            let _ = crate::page_map(f, page, crate::RW_NX, ch.pml4);
            demand += 1;
            // (Step 4, win32k) nested_reply_cap => send_on_reply(reply_cap,..)+recv_full_r12.
            let (nmi, nm0, nm1, nm2, nm3) = crate::reply_recv_full(ch.fault_ep, 0, 0, 0, 0, 0);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            _m2 = nm2;
            _m3 = nm3;
            continue;
        } else {
            // (Step 4, win32k) label==3 UserException + assert_skip => verify CD 2C, resume IP+2.
            wall_ip = m0;
            wall_addr = m1;
            wall_label = label;
            break;
        }
    }
    let status = if completed {
        // Proof-of-wiring: count each serviced dispatch by kind.
        match ch.caps.kind {
            ReqKind::Irp => HARNESS_IRP_DISPATCHES.fetch_add(1, Ordering::Relaxed),
            ReqKind::Syscall => HARNESS_SYSCALL_DISPATCHES.fetch_add(1, Ordering::Relaxed),
        };
        let so = match ch.caps.kind {
            ReqKind::Irp => SH_REQ_STATUS_IRP,
            ReqKind::Syscall => SH_REQ_STATUS_SYSCALL,
        };
        core::ptr::read_volatile((ch.shared_va + so) as *const i32)
    } else {
        0xC000_0001u32 as i32 // STATUS_UNSUCCESSFUL
    };
    PumpResult { status, completed, wall_ip, wall_addr, wall_label, faults, demand }
}

/// The DRIVER_OBJECT byte layout a component's `DriverEntry` expects. FSD = { size:0x150, ext:0x68 };
/// win32k = { size:0x200, ext:0x30 }. `component_main` builds a zeroed DRIVER_OBJECT of `size` with
/// Type=4 @0, Size @2, a zeroed DriverExtension pointer @`ext`, and MajorFunction @`mj`.
#[derive(Clone, Copy)]
pub(crate) struct DriverObjectSpec {
    pub size: u64,
    pub ext: u64,
    pub ext_size: u64,
    pub mj: u64,
}

/// One dispatched request handed to the component-side `dispatch` callback. For the FSD, `sel` is
/// the IRP major function; the router does `major → MajorFunction[major] → run_irp`.
#[derive(Clone, Copy)]
pub(crate) struct DispatchReq {
    /// The dispatch selector: IRP major (Irp) or SSN (Syscall).
    pub sel: u64,
    pub drv: u64,
}

/// The component-side shared entry (Family A): read the DriverEntry RVA from the shared frame, build
/// a `DriverObjectSpec`-shaped DRIVER_OBJECT + a zero-length RegistryPath from the pool, mark
/// `V_ENTERED`, call `DriverEntry`, record the verdict/status, run `post_driver_entry` (win32k:
/// establish-client; FSD: no-op — MUST run between DriverEntry and the FIRST send_done), then loop
/// `send_done → recv_req → dispatch(req) → write SH_REQ_STATUS + bump SH_REQ_SEQ`.
///
/// `code_va` is the loaded image base (DriverEntry = code_va + entry_rva). `dispatch` is the KIND
/// router (FSD: major→run_irp; win32k: ssn→dispatch_ssn). This is the shape both
/// `fsd_component_entry` (Step 2) and `win32k_subsystem_entry` (Step 4) collapse onto.
pub(crate) unsafe fn component_main(
    shared_va: u64,
    code_va: u64,
    spec: DriverObjectSpec,
    status_off: u64,
    dispatch_label: u64,
    dispatch: unsafe fn(&DispatchReq) -> (i32, u64),
    post_driver_entry: unsafe fn(status: i32, drv: u64),
) -> ! {
    let entry_rva = core::ptr::read_volatile((shared_va + SH_ENTRY_RVA_H) as *const u64) as u32;

    // DRIVER_OBJECT (Type@0=4, Size@2, DriverExtension@spec.ext, MajorFunction@spec.mj).
    let drv = crate::driver_launch::pool_alloc(spec.size);
    let mut i = 0u64;
    while i < spec.size {
        core::ptr::write_unaligned((drv + i) as *mut u64, 0);
        i += 8;
    }
    core::ptr::write_unaligned(drv as *mut i16, 4); // Type = IO_TYPE_DRIVER
    core::ptr::write_unaligned((drv + 2) as *mut u16, spec.size as u16); // Size
    let ext = crate::driver_launch::pool_alloc(spec.ext_size);
    let mut j = 0u64;
    while j < spec.ext_size {
        core::ptr::write_unaligned((ext + j) as *mut u64, 0);
        j += 8;
    }
    core::ptr::write_unaligned((drv + spec.ext) as *mut u64, ext);

    // RegistryPath UNICODE_STRING { Length=0, MaximumLength=2, Buffer=&NUL }.
    let reg_path = crate::driver_launch::pool_alloc(0x18);
    let reg_buf = crate::driver_launch::pool_alloc(0x10);
    core::ptr::write_unaligned(reg_buf as *mut u16, 0);
    core::ptr::write_unaligned(reg_path as *mut u16, 0);
    core::ptr::write_unaligned((reg_path + 2) as *mut u16, 2);
    core::ptr::write_unaligned((reg_path + 8) as *mut u64, reg_buf);

    core::ptr::write_volatile((shared_va + SH_VERDICT_H) as *mut u32, crate::driver_launch::V_ENTERED);

    let entry = code_va + entry_rva as u64;
    let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = de(drv, reg_path);

    let mj_base = drv + spec.mj;
    let mj_create = core::ptr::read_unaligned(mj_base as *const u64);
    let mut v = core::ptr::read_volatile((shared_va + SH_VERDICT_H) as *const u32);
    v |= crate::driver_launch::V_RETURNED;
    if status == 0 {
        v |= crate::driver_launch::V_SUCCESS;
    }
    if mj_create != 0 {
        v |= crate::driver_launch::V_MJ;
    }
    core::ptr::write_volatile((shared_va + SH_VERDICT_H) as *mut u32, v);
    core::ptr::write_volatile((shared_va + SH_DE_STATUS_H) as *mut i32, status);
    core::ptr::write_volatile((shared_va + SH_MJ_TABLE_H) as *mut u64, mj_base);

    post_driver_entry(status, drv);

    // The persistent dispatch loop.
    let mut seq = 0u64;
    loop {
        crate::driver_launch::send_done_on(dispatch_label);
        crate::driver_launch::recv_req_on();
        let sel = core::ptr::read_volatile((shared_va + SH_REQ_SEL_H) as *const u64);
        let (st, info) = dispatch(&DispatchReq { sel, drv });
        core::ptr::write_volatile((shared_va + status_off) as *mut i32, st);
        core::ptr::write_volatile((shared_va + SH_REQ_INFO_H) as *mut u64, info);
        seq += 1;
        core::ptr::write_volatile((shared_va + SH_REQ_SEQ) as *mut u64, seq);
    }
}

// Header-prefix offsets shared by both Family-A frames (design §1.2 "the header prefix (0x00-0x30)
// is the same shape"). These name the SAME bytes the FSD/win32k modules already use under their own
// const names; `component_main` uses these generic names.
const SH_ENTRY_RVA_H: u64 = 0x00;
const SH_VERDICT_H: u64 = 0x08;
const SH_DE_STATUS_H: u64 = 0x10;
const SH_MJ_TABLE_H: u64 = 0x18;
/// The dispatch selector (IRP major @0x40 for the FSD; the caller writes it before the pump). NOTE:
/// win32k's SSN lives at 0x50, so Step 4 passes a KIND-appropriate selector offset — for the FSD
/// (Step 2) the selector is `SH_REQ_MAJOR=0x40`.
const SH_REQ_SEL_H: u64 = 0x40;
/// IoStatus.Information out (FSD @0x78). win32k does not use this field.
const SH_REQ_INFO_H: u64 = 0x78;

/// Family-B one-shot epilogue: run `body` to a verdict, store it at `verdict_va`, signal
/// `CT_RESULT_NTFN` once, and park. STEP 0 skeleton (Family B folds onto this in the OPTIONAL
/// Step 3); wired to nothing yet.
#[allow(dead_code)]
pub(crate) unsafe fn run_once(body: unsafe fn() -> u32, verdict_va: u64) -> ! {
    let verdict = body();
    core::ptr::write_volatile(verdict_va as *mut u32, verdict);
    // Signal the executive once (the Family-B result notification), exactly as driver_host/kmdf do.
    let _ = crate::syscall5(crate::SYS_SEND, crate::CT_RESULT_NTFN, 0, 0, 0, 0);
    loop {
        crate::yield_now();
    }
}
