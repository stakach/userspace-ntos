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

/// Out: NTSTATUS offset — DIFFERS by KIND (FSD writes 0x70, win32k 0x78). The pump reads the offset
/// appropriate to `caps.kind`; these do NOT unify (design §2.2 status-offset note).
pub(crate) const SH_REQ_STATUS_IRP: u64 = 0x70;
pub(crate) const SH_REQ_STATUS_SYSCALL: u64 = 0x78;

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
    /// win32k: service the nested callback rendezvous label while an outer dispatch is active.
    pub usermode_callback: bool,
    /// win32k: carry wide (>4) stack args through caller RSP or explicit `SH_REQ_A4..` staging.
    // Capability-surface documentation (§2.3) — see `usermode_callback`; not read by the pump.
    #[allow(dead_code)]
    pub wide_arg_marshal: bool,
    /// win32k: skip checked-build int-0x2c NT_ASSERTs (resume IP+2) on a label-3 UserException.
    pub assert_skip: bool,
    /// The component's VSpace is SPARSE: a demand fault may need the whole PDPT→PD→PT walk built,
    /// not just a leaf page table. win32k's windows (image / pool / FreeType / user-VM / session
    /// heap / staged font) straddle several 512 GiB + 1 GiB regions that were never pre-created, so
    /// its faults resolve through `ensure_w32_client_paging`; the FSD's windows are pre-built and
    /// only ever need the 2 MiB PT (`driver_launch::ensure_paging`). This is orthogonal to
    /// [`Self::client_attach`] (which is about SHARING A CLIENT'S FRAMES, not about page tables) —
    /// win32k's DriverEntry-init pump needs the paging discipline WITHOUT the client sharing.
    pub sparse_vspace: bool,
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
    // Future-wiring seam (Step-0 additive ABI): the pump reads `PumpChannel.caps`, built independently
    // by the win32k/FSD callers, so `spawn_component` never reads this descriptor field yet. Kept as
    // the documented descriptor→spawn_component caps path for when that wiring lands.
    #[allow(dead_code)]
    pub caps: HostCaps,
}

/// What a spawned component hands back (the caps the caller may still need).
pub(crate) struct SpawnedComponent {
    pub pml4: u64,
    pub tcb: u64,
    // Documentation-of-record: the component's CNode cap. Callers use `pml4`/`tcb`/`stack_frame_base`;
    // the CNode is returned for a future teardown/revoke path (cap reclaim on component exit).
    #[allow(dead_code)]
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
        let _ = syscall5(
            SYS_SEND,
            CAP_INIT_THREAD_CNODE,
            LBL_CNODE_COPY << 12,
            cp,
            img_start + i,
            0,
        );
        let _ = page_map(
            cp,
            IMAGE_BASE + i * 0x1000,
            rights_at(d.image_rights, i),
            pml4,
        );
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
    let _ = syscall5(
        SYS_SEND,
        CAP_INIT_THREAD_CNODE,
        LBL_CNODE_MINT << 12,
        cnode,
        raw,
        CN_GUARD_BADGE,
    );
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
    let fault_slot = if d.granted.fault_ep.is_some() {
        CT_FAULT
    } else {
        0
    };
    let _ = tcb_set_space(tcb, fault_slot, cnode, pml4);
    let _ = syscall5(
        SYS_SEND,
        tcb,
        LBL_TCB_SET_IPC_BUFFER << 12,
        IPCBUF_VADDR,
        ipcbuf,
        0,
    );
    let stack_top = d.stack_base + d.stack_frames * 0x1000 - 16;
    let _ = tcb_write_registers(tcb, d.entry as u64, stack_top, 0);
    let _ = tcb_set_priority(tcb, d.prio);
    if let Some(gs) = d.gs_base {
        let _ = tcb_set_gs_base(tcb, gs);
    }
    attach_sched_context(tcb);
    let _ = tcb_resume(tcb);
    SpawnedComponent {
        pml4,
        tcb,
        cnode,
        stack_frame_base,
    }
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
    let mut first = 0;
    for i in 0..r.count {
        let cap = match r.source {
            FrameSource::FreshZeroed => {
                let f = alloc_slot();
                let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
                f
            }
            FrameSource::Alias(base) => copy_cap(base + i),
        };
        if i == 0 {
            first = match r.source {
                FrameSource::FreshZeroed => cap,
                FrameSource::Alias(base) => base,
            };
        }
        let _ = page_map(cap, r.base_va + i * 0x1000, rights_at(r.rights, i), pml4);
    }
    if r.base_va == crate::win32k_subsystem::WIN32K_USERVM_VADDR && first != 0 {
        crate::WIN32K_USERVM_FRAME_BASE.store(first, Ordering::Relaxed);
    }
}

/// Spawn the isolated ISR "driver host" (P1): its own VSpace (image RO + stack + IPC
/// buffer) and a CNode holding ONLY a cap to the IRQ notification + the result
/// notification — least privilege. Its thread (`isr_entry`) blocks on the IRQ
/// notification and, when the real interrupt fires, signals the result notification.
pub(crate) unsafe fn spawn_isr(
    entry: unsafe extern "C" fn() -> !,
    irq_cap: u64,
    result_cap: u64,
    prio: u64,
) {
    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(2), // RO
        map_heap_pt: false,
        stack_base: STACK_BASE,
        stack_frames: STACK_FRAMES,
        stack_dedicated_pt: false,
        regions: &[],
        granted: GrantedCaps {
            irq_ntfn: Some(irq_cap),
            result_ntfn: Some(result_cap),
            fault_ep: None,
        },
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
    // Then the staging buffers, each with its own dedicated PT(s). NLS + SYSTEM-hive share one
    // input page table with each other, distinct from the relocated NTDLLBUF.
    let mut regions: [Region; 32] = [Region {
        source: FrameSource::Alias(0),
        base_va: 0,
        count: 0,
        rights: Rights::Uniform(RW_NX),
        pts: 0,
    }; 32];
    let mut n = 0usize;
    regions[n] = Region {
        source: FrameSource::Alias(ahci_bar_frame),
        base_va: AHCI_VADDR,
        count: 1,
        rights: Rights::Uniform(RW_NX),
        pts: 0,
    };
    n += 1;
    regions[n] = Region {
        source: FrameSource::Alias(dma_frame),
        base_va: AHCI_DMA_VADDR,
        count: 1,
        rights: Rights::Uniform(RW_NX),
        pts: 0,
    };
    n += 1;
    regions[n] = Region {
        source: FrameSource::Alias(shared_frame),
        base_va: STORAGE_SHARED_VADDR,
        count: 1,
        rights: Rights::Uniform(RW_NX),
        pts: 0,
    };
    n += 1;
    // FILEBUF (own PT), NTDLLBUF (own PT), SRVBUF (own PT).
    regions[n] = Region {
        source: FrameSource::Alias(filebuf_start),
        base_va: FILEBUF_VADDR,
        count: FILEBUF_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 1,
    };
    n += 1;
    regions[n] = Region {
        source: FrameSource::Alias(ntdllbuf_start),
        base_va: NTDLLBUF_VADDR,
        count: NTDLLBUF_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 1,
    };
    n += 1;
    regions[n] = Region {
        source: FrameSource::Alias(srvbuf_start),
        base_va: SRVBUF_VADDR,
        count: SRVBUF_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 1,
    };
    n += 1;
    // WIN32BUF (4 PTs), WIN32KBUF (2 PTs).
    regions[n] = Region {
        source: FrameSource::Alias(win32buf_start),
        base_va: WIN32BUF_VADDR,
        count: WIN32BUF_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 4,
    };
    n += 1;
    regions[n] = Region {
        source: FrameSource::Alias(win32kbuf_start),
        base_va: WIN32KBUF_VADDR,
        count: WIN32KBUF_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 2,
    };
    n += 1;
    // WINLOGONBUF (own PT).
    regions[n] = Region {
        source: FrameSource::Alias(winlogonbuf_start),
        base_va: WINLOGONBUF_VADDR,
        count: WINLOGONBUF_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 1,
    };
    n += 1;
    // Font staging buffer (one PT).
    for (start, vaddr, frames) in [(
        FONTBUF_START.load(Ordering::Relaxed),
        win32k_subsystem::FONTBUF_VADDR,
        win32k_subsystem::FONTBUF_FRAMES,
    )] {
        regions[n] = Region {
            source: FrameSource::Alias(start),
            base_va: vaddr,
            count: frames,
            rights: Rights::Uniform(RW_NX),
            pts: 1,
        };
        n += 1;
    }
    // NLS + SYSTEM-hive buffers share one page table; the first descriptor creates it.
    for (index, (start, vaddr, frames)) in [
        (nls_ansi_start, NLS_ANSI_VADDR, NLS_ANSI_FRAMES),
        (nls_oem_start, NLS_OEM_VADDR, NLS_OEM_FRAMES),
        (nls_case_start, NLS_CASE_VADDR, NLS_CASE_FRAMES),
        (nls20127_start, NLS_20127_VADDR, NLS_20127_FRAMES),
        (hivebuf_start, HIVEBUF_VADDR, HIVEBUF_FRAMES),
        (
            SECHIVEBUF_START.load(Ordering::Relaxed),
            SECHIVEBUF_VADDR,
            SECHIVEBUF_FRAMES,
        ),
        (
            SAMHIVEBUF_START.load(Ordering::Relaxed),
            SAMHIVEBUF_VADDR,
            SAMHIVEBUF_FRAMES,
        ),
        (
            DEFHIVEBUF_START.load(Ordering::Relaxed),
            DEFHIVEBUF_VADDR,
            DEFHIVEBUF_FRAMES,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        regions[n] = Region {
            source: FrameSource::Alias(start),
            base_va: vaddr,
            count: frames,
            rights: Rights::Uniform(RW_NX),
            pts: u64::from(index == 0),
        };
        n += 1;
    }
    // The SOFTWARE hive buffer (471040 B) — its own 2 MiB window + dedicated PT, mirroring the
    // executive-side mapping (it does not fit in the shared 0xA0-0xC0 input page table).
    regions[n] = Region {
        source: FrameSource::Alias(SWHIVEBUF_START.load(Ordering::Relaxed)),
        base_va: SWHIVEBUF_VADDR,
        count: SWHIVEBUF_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 1,
    };
    n += 1;
    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(2), // RO — the storage path writes no statics
        map_heap_pt: false,
        stack_base: STACK_BASE,
        stack_frames: STACK_FRAMES,
        stack_dedicated_pt: false,
        regions: &regions[..n],
        granted: GrantedCaps {
            irq_ntfn: None,
            result_ntfn: Some(result_cap),
            fault_ep: Some(fault_ep),
        },
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

/// ★ What a pump does FIRST — the `Call`-transport successor of the deleted `wake_first` flag
/// (`docs/transport-migration.md` §3.3).
///
/// `wake_first` had to encode "is the component parked at a recv, or is it a blocked sender?" — a
/// question that only exists because the hand-rolled transport is an unpaired Send/Recv. Under the
/// `Call` transport the question becomes a statement about the reply object:
///
/// * [`InitialAction::ReplyRequest`] — the component is blocked in a `Call` bound to this channel's
///   reply object, so the pump ANSWERS that Call with the request (`reply_on`, which cannot block).
/// * [`InitialAction::RecvFirst`] — the component is not yet blocked in a dispatch `Call` (it is
///   mid-DriverEntry: either blocked in a fault Call or about to issue its ready Call), so the pump
///   starts by RECEIVING.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitialAction {
    ReplyRequest,
    RecvFirst,
}

/// The executive-side channel to one Family-A dispatch server. Carries the fault/dispatch EP, the
/// component VSpace (for demand-map), the in-image wall bounds, the shared frame base, the DONE
/// label, the component's MCS reply object and the per-server demand budget. `client_pi`/`caps`
/// gate win32k's specifics; for the FSD they are 0/all-false and the pump degenerates to today's
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
    /// What the pump does FIRST (see [`InitialAction`]): ANSWER the component's outstanding dispatch
    /// `Call` with the request, or (mid-DriverEntry) start by RECEIVING.
    pub initial: InitialAction,
    /// The component host's TCB. Needed ONLY to `TCB_Suspend` it on a WALL (risk R2 — see the wall
    /// tail of [`component_pump_inner`]). 0 = cannot suspend.
    pub tcb: u64,
    /// ★ This component's DEDICATED MCS reply object — the server side of the `Call` transport, and
    /// now MANDATORY (a zero here means the channel has no transport at all). `R_win32k`
    /// (`REPLY_W32`) and `R_fsd[inst]` (`REPLY_FSD`) are DISTINCT objects that are never pooled,
    /// never stolen and never rotated (risk R5/R7).
    pub reply_cap: u64,
    /// win32k only (0 for the FSD): the client process-index for `client_attach`/foreign-frame sharing.
    pub client_pi: u64,
    /// Explicit identity of the user thread whose win32k syscall is currently forwarded. This is
    /// carried with the pump invocation so callback diagnostics never consult stale global identity.
    pub callback_client: Option<UserCallbackClient>,
    /// The win32k capability gates (all-false for the FSD).
    pub caps: HostCaps,
}

#[derive(Clone, Copy)]
pub(crate) struct UserCallbackClient {
    pub pi: u32,
    pub pid: u64,
    pub badge: u64,
    pub tid: u64,
    pub tcb: u64,
    pub teb: u64,
    pub eprocess: u64,
    pub ethread: u64,
    pub role: Option<HostedThreadRole>,
    pub process_role: Option<nt_exe_image::HostedProcessRole>,
    pub top_badge: u64,
    /// Executive alias of this process's PEB page, or zero when the dispatch has no user client.
    pub peb_mirror: u64,
    /// Executive scratch mapping used to access this process's demand-paged user buffers.
    pub scratch_base: u64,
    /// Packed primary-token AuthenticationId LUID (`HighPart << 32 | LowPart`) for this caller.
    pub token_authentication_id: u64,
    /// Native TOKEN_USER SID bytes for the caller's primary token.
    pub token_user_sid: [u8; win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX],
    /// Valid byte length in `token_user_sid`.
    pub token_user_sid_len: u32,
}

/// win32k demand-fault verbosity budget: print the first 60 demand faults per dispatch (matches the
/// bespoke `win32k_dispatch_wide` `if demand < 60` gate exactly).
const W32_FAULT_LOG_LIMIT: u64 = 60;
/// win32k int-0x2c assert-skip per-dispatch bound (a looping assert still walls after this many).
const W32_ASSERT_SKIP_BOUND: u64 = 4000;

/// win32k WALL diagnostic (relocated VERBATIM from `win32k_dispatch_wide`'s tail): label + fault
/// IP/addr, RVA relative to the win32k image + dxg, and the UserException number/flags.
#[inline(never)]
unsafe fn win32k_wall_diag(ch: &PumpChannel, label: u64, m0: u64, m1: u64, m2: u64, m3: u64) {
    crate::print_str(b"[w32disp] WALL label=");
    crate::print_u64(label);
    crate::print_str(b" m0=0x");
    crate::print_hex((m0 >> 32) as u32);
    crate::print_hex(m0 as u32);
    crate::print_str(b" RVA=0x");
    crate::print_hex(m0.wrapping_sub(ch.code_va) as u32);
    crate::print_str(b" dxgRVA=0x");
    crate::print_hex(m0.wrapping_sub(crate::win32k_subsystem::DXG_VA) as u32);
    crate::print_str(b" m1=0x");
    crate::print_hex((m1 >> 32) as u32);
    crate::print_hex(m1 as u32);
    crate::print_str(b" exc#=");
    crate::print_u64(m3);
    crate::print_str(b" flags=0x");
    crate::print_hex(m2 as u32);
    crate::print_str(b"\n");
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

// =============================================================================================
// ★ THE `Call` ⇄ MCS REPLY-OBJECT TRANSPORT (the IRP substrate; `docs/transport-migration.md`).
//
// The component is always the CALLER, the executive always the SERVER. The component's ONE
// `call_on` publishes its completion AND returns the next request; the executive answers with
// `reply_on` — a `Send` on a `Cap::Reply`, which NEVER blocks.
//
// This is not a correlation *mechanism* we maintain; it is a correlation *fact the kernel keeps*:
//
//   * a recv registering reply object `R` (`recv_full_r12`) makes the kernel bind `R` to whichever
//     thread's Call pairs with it — `endpoint.rs::finish_call` → `replies[i].bound_tcb = sender`;
//   * `reply_on(R, …)` (`invocation.rs::decode_reply`) resumes exactly `bound_tcb` and CLEARS the
//     binding, or fails with `seL4_InvalidCapability` if there is none;
//   * a thread blocked in `Call` is `BlockedOnReply` and cannot race ahead to publish a second
//     completion.
//
// Therefore a stale or misdirected completion is UNREPRESENTABLE: the component cannot speak again
// until we reply, and our reply cannot reach anyone but the thread the kernel bound. The
// `SH_REQ_SEQ` sequence handshake and the per-dispatch token stack that used to reconstruct this
// property in userspace are deleted — `PUMP_REPLY_ERRORS == 0` over a whole boot is the kernel
// attesting the invariant held on every single request.
// =============================================================================================

/// Requests answered on a component's reply object (`reply_on(R, tag)`), BY KIND. Every one of them
/// returned label 0, i.e. the kernel confirmed `R` was BOUND — which is only true if the component
/// had issued exactly one `Call` since our last reply.
static PUMP_CALL_REQUESTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// Dispatches whose completion arrived as the return value of the COMPONENT'S OWN `Call` on the
/// bound reply object, BY KIND. Must equal [`HARNESS_IRP_DISPATCHES`] /
/// [`HARNESS_SYSCALL_DISPATCHES`] — every substrate is on the `Call` transport.
static PUMP_CALL_DISPATCHES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Requests handed over as a reply on a bound reply object, for `kind`.
pub(crate) fn pump_call_requests(kind: ReqKind) -> u64 {
    PUMP_CALL_REQUESTS[kind as usize].load(Ordering::Relaxed)
}
/// Dispatches completed as the return value of the component's own `Call`, for `kind`.
pub(crate) fn pump_call_dispatches(kind: ReqKind) -> u64 {
    PUMP_CALL_DISPATCHES[kind as usize].load(Ordering::Relaxed)
}
/// ★ Non-zero `reply_on` invocation labels. MUST be **0** for the whole boot: a non-zero label means
/// we replied to an UNBOUND reply object, i.e. our belief "the component is blocked in a Call" was
/// wrong — an invariant break. Risk R3: reply-object rebinding is silent in the kernel, so this
/// error-returning reply is the only diagnostic there is. Asserted 0 by
/// `exec_irp_transport_call_bound`.
pub(crate) static PUMP_REPLY_ERRORS: AtomicU64 = AtomicU64::new(0);
/// Components suspended (`TCB_Suspend`) because their pump WALLED — see risk R2 at the wall tail.
pub(crate) static PUMP_WALL_SUSPENDS: AtomicU64 = AtomicU64::new(0);

// ── ★ NESTING OBSERVABILITY (Phase 2). These counters are NOT correlation state — nothing reads
// them to decide where a message goes. That is the whole point: the 32-deep `DISPATCH_TOKEN_STACK`
// they replace WAS load-bearing, and now the kernel's `bound_tcb` is the only binding there is.
// They exist so `exec_win32k_transport_call_nested` can SAY at what depth the property was proven.
/// Outstanding win32k dispatch levels (a level is outstanding from the moment its request is replied
/// until its completion Call arrives; a level suspended inside a usermode callback stays counted).
static PUMP_DISPATCH_DEPTH: AtomicU64 = AtomicU64::new(0);
/// High-water of [`PUMP_DISPATCH_DEPTH`] over the boot. >= 2 means a nested dispatch really ran with
/// an outer dispatch still outstanding on the SAME single reply object.
pub(crate) static PUMP_MAX_DISPATCH_DEPTH: AtomicU64 = AtomicU64::new(0);
/// ★ RISK R6 — dispatches currently SUSPENDED inside a usermode callback, i.e. pumps that returned
/// while deliberately NOT replying, leaving `R` bound to the component's callback `Call`. Every one
/// of them MUST eventually be resumed by one of the three resume sites (`NtCallbackReturn`,
/// dead-client unwind, cancel); a non-zero value at quiesce is a component wedged holding `R`.
pub(crate) static SUSPENDED_COMPONENT_OUTSTANDING: AtomicU64 = AtomicU64::new(0);

/// Current outstanding win32k dispatch nesting depth (0 = win32k holds no outstanding dispatch).
pub(crate) fn dispatch_depth() -> u64 {
    PUMP_DISPATCH_DEPTH.load(Ordering::Relaxed)
}

fn dispatch_depth_enter() {
    let depth = PUMP_DISPATCH_DEPTH.fetch_add(1, Ordering::Relaxed) + 1;
    if depth > PUMP_MAX_DISPATCH_DEPTH.load(Ordering::Relaxed) {
        PUMP_MAX_DISPATCH_DEPTH.store(depth, Ordering::Relaxed);
    }
}

fn dispatch_depth_leave() {
    let _ = PUMP_DISPATCH_DEPTH.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| {
        Some(d.saturating_sub(1))
    });
}

/// ★ PLAN CORRECTION (`docs/transport-migration.md` §2.3 got this half-right and half-wrong),
/// and its consequence, now RESOLVED by Phase 3.
///
/// The plan said "a Call consumes the executive's single `reply_to` slot" is WRONG because
/// `endpoint.rs::finish_call` writes the **receiver's** slot, not the sender's. That is true — and
/// it is exactly why making the COMPONENT the caller reintroduced the hazard from the other side:
/// the executive is the RECEIVER, so every component `Call` it takes writes
/// `executive.reply_to = component`, and a DISPATCH COMPLETION leaves the component deliberately
/// blocked there — so `reply_to` keeps naming it long after the pump returns.
///
/// Phase 1 dodged that with a `COMPONENT_CALL_CLOBBERED_REPLY_TO` flag: the main service loop asked
/// "did a component speak while I serviced this syscall?" and, if so, replied through the caller's
/// BOUND reply object instead of the legacy slot. **Phase 3 deleted both the flag and the question.**
/// The main loop never replies through `reply_to` any more (`main.rs::reply_recv_badge` is now
/// `client_reply_on` + `recv_full_r12`), so a clobbered `reply_to` cannot mis-address anything: the
/// executive simply has no consumer for it left. Nothing here needs to announce the clobber.

/// ★ PLAN CORRECTION (`docs/transport-migration.md` §3.5 was WRONG about this).
///
/// A reply issued on a `Cap::Reply` **cannot carry an arbitrary message LABEL**. `reply_on` is a
/// `SYS_CALL` on a non-endpoint cap, so the kernel routes it through
/// `invocation.rs::decode_invocation`, which parses the msginfo label as an `InvocationLabel`
/// *before* dispatching on the cap type — `InvocationLabel::from_u64(0x771)` is `None`, so the
/// reply fails `seL4_InvalidArgument` (1) and never reaches `decode_reply`. Only label **0**
/// (`InvalidInvocation`) survives that gate. (The COMPONENT→executive direction is unaffected: the
/// component's `Call` targets an Endpoint cap, so its `dispatch_label` rides in the label as before,
/// which is what the pump's DONE arm matches on.)
///
/// So the executive's request rides as a length-1 message with the tag in **MR0**. Phase 2 needs
/// exactly this to tell a nested DISPATCH from a callback RESUME.
const REQUEST_TAG_LEN: u64 = 1;

/// Answer the component's outstanding `Call` on this channel's reply object, recording the
/// invocation label. Non-blocking by construction (`decode_reply` wakes the bound caller or fails).
unsafe fn pump_reply_on(ch: &PumpChannel, msginfo: u64, r0: u64) -> u64 {
    let e = crate::reply_on(ch.reply_cap, msginfo, r0, 0, 0, 0);
    if e != 0 && PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed) < 8 {
        crate::print_str(b"[pump] reply_on error label=");
        crate::print_u64(e);
        crate::print_str(b" cap=0x");
        crate::print_hex(ch.reply_cap as u32);
        crate::print_str(
            b" -> the reply object was NOT bound (component was not blocked in a Call)\n",
        );
    }
    e
}

/// Receive the component's next message. The recv REGISTERS the channel's reply object in r12, so
/// the kernel binds it to whichever Call — dispatch completion, demand-page fault or callback —
/// pairs with us. This is the ONLY correlation state the transport has, and it is the kernel's.
///
/// ★ THE BADGE IS LOAD-BEARING (Phase 4). The executive's root TCB has the HPET one-shot
/// notification BOUND to it, so this `Recv` has a SECOND thing that can satisfy it besides a
/// component `Call`: a timer tick. The kernel's bound-notification pre-check
/// (`syscall_handler.rs::handle_recv`) returns `rdi = DELAY_TIMER_BADGE`, `rsi = 0` and **leaves the
/// message registers untouched**, so a tick absorbed here reads as `label = 0` with MR0 still
/// holding whatever `pump_reply_on` left there — the request tag. That is a WALL, and it is exactly
/// what killed the LSA route's npfs READ (`[pump] WALL label=0 ip=0x771`): the route is the first
/// thing in the boot that arms an HPET one-shot (`NtDelayExecution` from the RPC worker) WHILE a
/// component dispatch is in flight. The main service loop has always screened this badge; the pump
/// did not, because before the route nothing ticked during a dispatch.
///
/// So: recognise the tick, count it for the main service loop (`DELAY_TIMER_TICKS_PENDING`) and go
/// back to receiving. The watchdog re-arm path Acks nested deliveries; the service loop then services
/// the coalesced timer state once while accounting for every pump-absorbed tick.
#[inline]
unsafe fn pump_recv(ch: &PumpChannel) -> (u64, u64, u64, u64, u64) {
    loop {
        // (This recv pairs a component `Call`, so the kernel writes `executive.reply_to = component`.
        // Harmless since Phase 3: no executive reply reads `reply_to` any more.)
        let (badge, mi, m0, m1, m2, m3) = crate::recv_full_r12(ch.fault_ep, ch.reply_cap);
        if badge == crate::DELAY_TIMER_BADGE {
            crate::DELAY_TIMER_TICKS_PENDING.fetch_add(1, Ordering::Relaxed);
            // The main service loop owns the ordinary re-arm + IRQ Ack, and it cannot run while this
            // pump is blocked — so a deadlock INSIDE a dispatch would get exactly one tick and could
            // never trip the deadman. Re-arm it here (see `watchdog_nested_rearm`).
            crate::watchdog_nested_rearm();
            let n = crate::PUMP_TIMER_TICKS_ABSORBED.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                crate::print_str(
                    b"[pump] HPET tick landed on a component recv -> deferred to the service loop (NOT a wall)\n",
                );
            }
            continue;
        }
        return (mi, m0, m1, m2, m3);
    }
}

/// Resume the component (a fault reply, or the int-0x2c assert-skip reply) and receive its next
/// message. `len`/`r0` are the reply message-info and MR0 — the component pump only ever emits
/// len 0 (VMFault: `apply_fault_reply` restarts unconditionally) and len 1 (int-0x2c
/// UserException: MR0 = the resume FaultIP). It NEVER emits the len-18 UnknownSyscall shape; those
/// are client-syscall replies on REPLY_MAIN, a different plane entirely (risk R4).
#[inline]
unsafe fn pump_resume_recv(ch: &PumpChannel, len: u64, r0: u64) -> (u64, u64, u64, u64, u64) {
    pump_reply_on(ch, len, r0);
    pump_recv(ch)
}

/// The outcome of one pump: `(status, completed)`. `completed=true` iff the server re-parked at its
/// dispatch loop (sent `dispatch_label`); `false` = it hit a wall (fault we won't demand-map).
#[derive(Clone, Copy)]
pub(crate) struct PumpResult {
    pub status: i32,
    /// Pointer-width dispatch return. For IRP components this mirrors `status`; for win32k it is
    /// the full handler RAX, needed by NtUser/NtGdi APIs that return handles or LONG_PTR values.
    pub result: u64,
    pub completed: bool,
    pub callback_suspended: bool,
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
    component_pump_inner(ch, false)
}

pub(crate) unsafe fn component_pump_resume_user_callback(ch: &PumpChannel) -> PumpResult {
    component_pump_inner(ch, true)
}

unsafe fn component_pump_inner(ch: &PumpChannel, resume_user_callback: bool) -> PumpResult {
    // (Step 4, win32k) The request fill — `w32_client_attach(client_pi)`, the SSN/args write, and the
    // wide-arg source selection — caller RSP for real syscalls or explicit SH_REQ_A4.. staging for
    // executive-originated calls — is done by the win32k caller wrapper `win32k_dispatch_wide`
    // BEFORE this pump runs (exactly as the FSD `dispatch_irp` fills the IRP fields before the pump).
    // `caps.client_attach` here gates only the DEMAND-FAULT foreign-frame sharing (pump step 4); the
    // initial attach is the caller's, matching the design's caller-owns-fill split.

    // ★ THE `Call` TRANSPORT — now the ONLY one. The component is blocked in a `Call` bound to
    // `reply_cap`; we ANSWER it with the request (`InitialAction::ReplyRequest`) or, mid-DriverEntry,
    // start by RECEIVING its ready/fault Call (`RecvFirst`). Every recv re-registers `reply_cap`, so
    // the kernel — not us — is what binds a completion to the request that provoked it. ONE reply
    // object per component suffices at ANY nesting depth: the component host has ONE TCB, so it is
    // blocked in at most one Call, and the "stack" of suspended levels is its own C stack.
    //
    // The request TAG rides in MR0, NOT in the message label — `reply_on` is a `SYS_CALL` on a
    // non-endpoint cap, so a non-zero label is parsed as an `InvocationLabel` and rejected before it
    // ever reaches `decode_reply` (see [`REQUEST_TAG_LEN`]). A fresh dispatch hands over
    // `dispatch_label`; the callback-RESUME pump hands over `W32_USER_CALLBACK_RESUME_LABEL` on the
    // SAME outstanding Call — which is the whole of what used to be a bespoke resume preamble.
    let request_tag = if resume_user_callback {
        crate::win32k_subsystem::W32_USER_CALLBACK_RESUME_LABEL
    } else {
        ch.dispatch_label
    };

    // Nesting OBSERVABILITY only (no correlation depends on it): a pump that hands over a request
    // owns one outstanding dispatch level; a RESUME pump inherits the level its suspension left
    // outstanding. The `RecvFirst` DriverEntry-init shape owns none (the component's ready Call is a
    // completion that answers no request).
    let owns_depth = ch.caps.usermode_callback
        && (resume_user_callback || ch.initial == InitialAction::ReplyRequest);
    if resume_user_callback {
        SUSPENDED_COMPONENT_OUTSTANDING.fetch_sub(1, Ordering::Relaxed);
    } else if owns_depth {
        dispatch_depth_enter();
    }

    // ★ ONE non-blocking reply hands over the request. There is no wake `Send` any more, so there is
    // no window in which the executive can block against a component that is running rather than
    // receiving (defect 3). `RecvFirst` means the component has not yet issued the Call we would be
    // answering (mid-DriverEntry), so we just receive.
    if ch.initial == InitialAction::ReplyRequest
        && pump_reply_on(ch, REQUEST_TAG_LEN, request_tag) == 0
    {
        PUMP_CALL_REQUESTS[ch.caps.kind as usize].fetch_add(1, Ordering::Relaxed);
    }
    let (mut mi, mut m0, mut m1, mut _m2, mut m3) = pump_recv(ch);
    let mut faults = 0u64;
    let mut demand = 0u64;
    let mut skips = 0u64; // win32k int-0x2c asserts skipped this dispatch (bounded → a looping assert walls)
    let (mut wall_ip, mut wall_addr, mut wall_label) = (0u64, 0u64, 0u64);
    let mut completed = false;
    let mut callback_suspended = false;
    loop {
        let label = mi >> 12;
        if label == ch.dispatch_label {
            // ★ There is nothing to check. This message is the return half of the component's OWN
            // `Call`, the kernel bound our reply object to that exact caller when it paired, and the
            // component could not have spoken at all without first being replied to. A stale or
            // misdirected completion is UNREPRESENTABLE — which is why the sequence handshake and
            // the per-dispatch token stack are gone.
            PUMP_CALL_DISPATCHES[ch.caps.kind as usize].fetch_add(1, Ordering::Relaxed);
            completed = true;
            break;
        } else if label == crate::win32k_subsystem::W32_USER_CALLBACK_LABEL
            && ch.caps.usermode_callback
        {
            let disposition = ch
                .callback_client
                .and_then(|client| crate::win32k_glue::service_user_callback(client));
            let Some(disposition) = disposition else {
                wall_ip = m0;
                wall_addr = m1;
                wall_label = label;
                break;
            };
            if disposition == crate::win32k_glue::UserCallbackDisposition::SuspendComponent {
                // ★ THE SUSPENSION IS A NON-REPLY. We simply RETURN without answering, so `R` stays
                // BOUND to the component's callback `Call` for the whole callback excursion (client
                // redirect → arbitrarily deep nested dispatches → `NtCallbackReturn`). That kernel
                // binding IS the "suspended outer dispatch" state; we keep none of our own.
                callback_suspended = true;
                break;
            }
            // Answer the callback in place: the RESUME tag on the component's outstanding Call.
            let (nmi, nm0, nm1, nm2, nm3) = pump_resume_recv(
                ch,
                REQUEST_TAG_LEN,
                crate::win32k_subsystem::W32_USER_CALLBACK_RESUME_LABEL,
            );
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            _m2 = nm2;
            m3 = nm3;
            continue;
        } else if label == crate::win32k_subsystem::W32_GDI_LOAD_LABEL
            && ch.caps.kind == ReqKind::Syscall
        {
            let status = crate::win32k_glue::service_gdi_driver_load();
            let (nmi, nm0, nm1, nm2, nm3) =
                pump_resume_recv(ch, REQUEST_TAG_LEN, status as u32 as u64);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            _m2 = nm2;
            m3 = nm3;
            continue;
        } else if label == 6 {
            let ip = m0;
            let addr = m1;
            faults += 1;
            let in_image = ch.image_frames != 0
                && addr >= ch.code_va
                && addr < ch.code_va + ch.image_frames * 0x1000;
            if ch.caps.client_attach {
                // ── win32k demand-fault CLIENT-FRAME-SHARING (relocated VERBATIM from
                // `win32k_dispatch_wide`; foreign-pointer detection + internal-low zero-fill discrimination).
                let page = addr & !0xFFF;
                let foreign = addr < 0x0000_0100_0000_0000
                    || (addr >= 0x10000
                        && !in_image
                        && crate::csrss_frame_get(ch.client_pi, page) != 0);
                if crate::DEBUG_TRACE && demand < W32_FAULT_LOG_LIMIT {
                    crate::print_str(b"[w32disp] fault #");
                    crate::print_u64(demand);
                    crate::print_str(b" ip=0x");
                    crate::print_hex((ip >> 32) as u32);
                    crate::print_hex(ip as u32);
                    crate::print_str(b" RVA=0x");
                    crate::print_hex(ip.wrapping_sub(ch.code_va) as u32);
                    crate::print_str(b" addr=0x");
                    crate::print_hex((addr >> 32) as u32);
                    crate::print_hex(addr as u32);
                    if foreign {
                        crate::print_str(b" (client ptr - sharing csrss frame)");
                    }
                    crate::print_str(b"\n");
                }
                // Hard walls: a genuine null/low deref, a W^X write into the RX image, or the demand cap.
                if addr < 0x10000 || in_image || demand >= ch.demand_cap {
                    crate::win32k_glue::win32k_dispatch_backtrace();
                    wall_ip = ip;
                    wall_addr = addr;
                    wall_label = label;
                    break;
                }
                // ★ THE CLIENT TEB TAIL IS READ-ONLY TO win32k. A WRITE fault (x86 `#PF` error-code
                // bit 1, delivered as the VMFault `FSR`) on a page that is ALREADY attached can only
                // be the read-only tail mapping refusing a store — every other attached page is RW.
                // Answer it with a private copy-on-write shadow instead of the caller's real TEB.
                if crate::W32_CLIENT_TEB_TAIL_PROTECTED
                    && (m3 & 0x2) != 0
                    && crate::win32k_glue::w32_attach_mapped(page)
                    && crate::is_teb_tail_page(page)
                {
                    if crate::win32k_glue::w32_teb_tail_cow(page, ch.client_pi, ch.pml4, ip) {
                        demand += 1;
                        let (nmi, nm0, nm1, nm2, nm3) = pump_resume_recv(ch, 0, 0);
                        mi = nmi;
                        m0 = nm0;
                        m1 = nm1;
                        _m2 = nm2;
                        m3 = nm3;
                        continue;
                    }
                    crate::win32k_glue::win32k_dispatch_backtrace();
                    wall_ip = ip;
                    wall_addr = addr;
                    wall_label = label;
                    break;
                }
                if foreign {
                    if !crate::win32k_glue::map_csrss_page_into_win32k(page, ch.client_pi, ch.pml4)
                    {
                        let win32k_internal_low = page < 0x0000_0100_0000_0000 && page >= 0x10000;
                        if win32k_internal_low {
                            if crate::DEBUG_TRACE && demand < W32_FAULT_LOG_LIMIT {
                                crate::print_str(b"[w32disp] win32k-internal unbacked low VA 0x");
                                crate::print_hex((page >> 32) as u32);
                                crate::print_hex(page as u32);
                                crate::print_str(b" -> zero-fill (blit source buffer)\n");
                            }
                            crate::win32k_glue::ensure_w32_client_paging(page, ch.pml4);
                            let f = crate::alloc_frame();
                            let _ = crate::page_map(f, page, crate::RW_NX, ch.pml4);
                        } else {
                            crate::print_str(b"[w32disp] map_csrss_page_into_win32k FALSE page=0x");
                            crate::print_hex((page >> 32) as u32);
                            crate::print_hex(page as u32);
                            crate::print_str(b" client_pi=");
                            crate::print_u64(ch.client_pi);
                            crate::print_str(b"\n");
                            crate::win32k_glue::win32k_dispatch_backtrace();
                            wall_ip = ip;
                            wall_addr = addr;
                            wall_label = label;
                            break;
                        }
                    }
                } else {
                    crate::win32k_glue::ensure_w32_client_paging(page, ch.pml4);
                    let f = crate::alloc_frame();
                    let _ = crate::page_map(f, page, crate::RW_NX, ch.pml4);
                }
                demand += 1;
            } else {
                // ── FSD / generic demand-map (byte-identical to the old inline loop).
                if crate::DEBUG_TRACE && ch.trace_faults && faults <= 40 {
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
                if addr < 0x10000 || in_image || demand >= ch.demand_cap {
                    wall_ip = ip;
                    wall_addr = addr;
                    wall_label = label;
                    break;
                }
                let page = addr & !0xFFF;
                if ch.caps.sparse_vspace {
                    crate::win32k_glue::ensure_w32_client_paging(page, ch.pml4);
                } else {
                    crate::driver_launch::ensure_paging(page, ch.pml4);
                }
                let f = crate::alloc_frame();
                let _ = crate::page_map(f, page, crate::RW_NX, ch.pml4);
                demand += 1;
            }
            // Resume the server + recv the next fault/DONE: `reply_on(R, len 0)` — a VMFault reply,
            // which `apply_fault_reply` restarts unconditionally (`fault.rs`) — followed by a recv
            // that re-registers `R`. A nested demand fault therefore rides the SAME reply object as
            // the dispatch it happened inside, which is exactly Fix B's guarantee (the outer client's
            // REPLY_MAIN binding is untouched) with no second transport to keep gated.
            let (nmi, nm0, nm1, nm2, nm3) = pump_resume_recv(ch, 0, 0);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            _m2 = nm2;
            m3 = nm3;
            continue;
        } else if label == 3 && ch.caps.assert_skip {
            // ── win32k checked-build int-0x2c ASSERT-SKIP (relocated VERBATIM). Verify CD 2C via the
            // executive's RW view of win32k's image at the same VA, then resume at IP+2 (release-build
            // semantics). Bounded by W32_ASSERT_SKIP_BOUND (a looping assert still walls).
            let ip = m0;
            let in_win32k = ip >= ch.code_va && ip < ch.code_va + ch.image_frames * 0x1000;
            let is_int2c = in_win32k
                && core::ptr::read_volatile(ip as *const u8) == 0xCD
                && core::ptr::read_volatile((ip + 1) as *const u8) == 0x2C;
            // Gated on `caps.assert_skip` (win32k only) — NOT on `reply_cap != 0`, which is now
            // mandatory on every channel and would silently widen this arm to the FSD (risk R10).
            if is_int2c && skips < W32_ASSERT_SKIP_BOUND {
                // Verbose grind-era trace: the per-skip int-0x2c diagnostic (bounded to 40). Gated
                // behind `debug-trace` — pure noise once the boot is stable, not load-bearing.
                if crate::DEBUG_TRACE && crate::W32_ASSERT_LOG.fetch_add(1, Ordering::Relaxed) < 40
                {
                    crate::print_str(b"[w32disp] skip int 0x2c assert @ RVA 0x");
                    crate::print_hex(ip.wrapping_sub(ch.code_va) as u32);
                    crate::print_str(b"\n");
                }
                skips += 1;
                // UserException(3) reply: len 1, MR0 = the resume FaultIP (past `CD 2C`). This is
                // the ONLY non-zero-length reply the component pump ever emits (risk R4).
                let (nmi, nm0, nm1, nm2, nm3) = pump_resume_recv(ch, 1, ip + 2);
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                _m2 = nm2;
                m3 = nm3;
                continue;
            }
            // Not a skippable int-0x2c — fall through to the wall.
            if ch.caps.client_attach {
                win32k_wall_diag(ch, label, m0, m1, _m2, m3);
                crate::win32k_glue::win32k_dispatch_backtrace();
            }
            wall_ip = m0;
            wall_addr = m1;
            wall_label = label;
            break;
        } else {
            // Any other fault — a real wall inside the handler.
            if ch.caps.client_attach {
                win32k_wall_diag(ch, label, m0, m1, _m2, m3);
                crate::win32k_glue::win32k_dispatch_backtrace();
            }
            wall_ip = m0;
            wall_addr = m1;
            wall_label = label;
            break;
        }
    }
    // Retire this level from the depth GAUGE unless it is now suspended inside a usermode callback
    // (in which case it stays outstanding until a resume pump completes it). Observability only.
    if owns_depth {
        if callback_suspended {
            SUSPENDED_COMPONENT_OUTSTANDING.fetch_add(1, Ordering::Relaxed);
        } else {
            dispatch_depth_leave();
        }
    }
    // ★ RISK R2 — WALL HANDLING UNDER THE `Call` TRANSPORT.
    //
    // A wall means we received a fault we refuse to service. The component is therefore blocked in
    // that fault Call with our reply object STILL BOUND to it. If we later did
    // `reply_on(R, request)`, `decode_reply` would see `pending_fault != 0` and route it through
    // `fault::apply_fault_reply`, which returns `restart = true` UNCONDITIONALLY for VMFault(6) and
    // CapFault(1) (`fault.rs`) — the component would resume at the faulting instruction carrying a
    // request it never asked for, and immediately re-fault. There is no "park it via the reply"
    // option and no kernel invocation to unbind a reply object.
    //
    // So we take the honest one: SUSPEND the component's TCB. It stops running, its reply object is
    // left bound to a thread that will never run again, and the caller retires it so nothing ever
    // pumps it a second time (`dispatch_irp` → `register_instance_ready(inst,false)`;
    // `win32k_dispatch_wide` → `WIN32K_RETIRED`). A walled component is dead, and it now says so.
    // Zero walls occur on a green boot for EITHER substrate, so this path is defensive.
    if !completed && !callback_suspended {
        PUMP_WALL_SUSPENDS.fetch_add(1, Ordering::Relaxed);
        let e = if ch.tcb != 0 {
            crate::tcb_suspend_r(ch.tcb)
        } else {
            0xFFFF
        };
        crate::print_str(b"[pump] WALL label=");
        crate::print_u64(wall_label);
        crate::print_str(b" ip=0x");
        crate::print_hex(wall_ip as u32);
        crate::print_str(b" addr=0x");
        crate::print_hex((wall_addr >> 32) as u32);
        crate::print_hex(wall_addr as u32);
        crate::print_str(b" -> TCB_Suspend(component) e=");
        crate::print_u64(e);
        crate::print_str(
            b" (its reply object stays bound to a thread that will never run again)\n",
        );
    }
    let (status, result) = if completed {
        // Proof-of-wiring: count each serviced dispatch by kind.
        match ch.caps.kind {
            ReqKind::Irp => HARNESS_IRP_DISPATCHES.fetch_add(1, Ordering::Relaxed),
            ReqKind::Syscall => HARNESS_SYSCALL_DISPATCHES.fetch_add(1, Ordering::Relaxed),
        };
        match ch.caps.kind {
            ReqKind::Irp => {
                let status =
                    core::ptr::read_volatile((ch.shared_va + SH_REQ_STATUS_IRP) as *const i32);
                (status, status as u32 as u64)
            }
            ReqKind::Syscall => {
                let result =
                    core::ptr::read_volatile((ch.shared_va + SH_REQ_STATUS_SYSCALL) as *const u64);
                (result as u32 as i32, result)
            }
        }
    } else if callback_suspended {
        let status = nt_user_callback::STATUS_PENDING;
        (status, status as u32 as u64)
    } else {
        let status = 0xC000_0001u32 as i32; // STATUS_UNSUCCESSFUL
        (status, status as u32 as u64)
    };
    PumpResult {
        status,
        result,
        completed,
        callback_suspended,
        wall_ip,
        wall_addr,
        wall_label,
        faults,
        demand,
    }
}

/// The DRIVER_OBJECT byte layout a component's `DriverEntry` expects. FSD = { size:0x150, ext:0x68 };
/// win32k = { size:0x200, ext:0x30 }. `component_main` builds a zeroed DRIVER_OBJECT of `size` with
/// Type=4 @0, Size @2, a zeroed DriverExtension pointer @`ext`, and MajorFunction @`mj`.
#[derive(Clone, Copy)]
pub(crate) struct DriverObjectSpec {
    /// The DRIVER_OBJECT allocation size (bytes reserved from `pool`).
    pub size: u64,
    /// The value written into the DRIVER_OBJECT `Size` field @2. USUALLY == `size` (FSD), but win32k
    /// allocates 0x200 yet stamps Size=336 (0x150) — so this is a distinct field to preserve that.
    pub size_field: u16,
    pub ext: u64,
    pub ext_size: u64,
    pub mj: u64,
    /// Shared-frame offset to record `drv + mj` (the MajorFunction[] base) into, for the executive to
    /// read back. FSD = 0x18 (`SH_MJ_TABLE`). `u64::MAX` = DO NOT record — win32k does not use an
    /// MJ-table field and 0x18 in ITS frame is `SH_SSDT_BASE` (which DriverEntry populates); writing
    /// there would clobber the SSDT base → dispatch fails. So win32k passes `u64::MAX`.
    pub mj_table_off: u64,
    /// The component's pool allocator (FSD's free-list `driver_launch::pool_alloc`, or win32k's own
    /// bump allocator over `WIN32K_POOL_VADDR`). `component_main` builds the DRIVER_OBJECT / ext /
    /// RegistryPath from THIS pool — win32k's DriverEntry + `SH_POOL_USED` readback need its own pool.
    pub pool: unsafe fn(u64) -> u64,
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
/// establish-client; FSD: no-op — MUST run between DriverEntry and the FIRST completion `Call`),
/// then loop `call_on(completion) → dispatch(request) → write SH_REQ_STATUS`.
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
    let drv = (spec.pool)(spec.size);
    let mut i = 0u64;
    while i < spec.size {
        core::ptr::write_unaligned((drv + i) as *mut u64, 0);
        i += 8;
    }
    core::ptr::write_unaligned(drv as *mut i16, 4); // Type = IO_TYPE_DRIVER
    core::ptr::write_unaligned((drv + 2) as *mut u16, spec.size_field); // Size (may differ from alloc)
    let ext = (spec.pool)(spec.ext_size);
    let mut j = 0u64;
    while j < spec.ext_size {
        core::ptr::write_unaligned((ext + j) as *mut u64, 0);
        j += 8;
    }
    core::ptr::write_unaligned((drv + spec.ext) as *mut u64, ext);

    // RegistryPath UNICODE_STRING { Length=0, MaximumLength=2, Buffer=&NUL }.
    let reg_path = (spec.pool)(0x18);
    let reg_buf = (spec.pool)(0x10);
    core::ptr::write_unaligned(reg_buf as *mut u16, 0);
    core::ptr::write_unaligned(reg_path as *mut u16, 0);
    core::ptr::write_unaligned((reg_path + 2) as *mut u16, 2);
    core::ptr::write_unaligned((reg_path + 8) as *mut u64, reg_buf);

    core::ptr::write_volatile(
        (shared_va + SH_VERDICT_H) as *mut u32,
        crate::driver_launch::V_ENTERED,
    );

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
    // Record the MajorFunction[] base ONLY when the spec names a field for it (FSD 0x18). win32k
    // passes u64::MAX (its 0x18 is SH_SSDT_BASE, populated by DriverEntry — must not be clobbered).
    if spec.mj_table_off != u64::MAX {
        core::ptr::write_volatile((shared_va + spec.mj_table_off) as *mut u64, mj_base);
    }

    post_driver_entry(status, drv);

    // ★ THE PERSISTENT DISPATCH LOOP — ONE syscall.
    //
    // `call_on` publishes this dispatch's completion (the status/info are already in the shared
    // frame) AND returns the next request as its reply value. The very first Call is the
    // post-DriverEntry READY signal — no request has been received yet, which is exactly why the
    // executive's init pump starts with `RecvFirst`.
    //
    // Everything the hand-rolled loop needed to reconstruct the request↔completion binding in
    // userspace — the correlation token, the `SH_REQ_SEQ` counter, the slip injectors — is GONE: the
    // component is `BlockedOnReply` between the Call and the executive's reply, so it cannot publish
    // a second completion, and the executive's reply cannot reach any thread but this one.
    //
    // The reply's message LABEL is always 0 (`REQUEST_TAG_LEN`); the request tag is in MR0. This
    // OUTER loop only ever receives `dispatch_label` — the callback-RESUME tag is answered to the
    // rendezvous loop's own Call, deeper in this same component's C stack.
    loop {
        let (_label, _tag, _, _, _) = crate::driver_launch::call_on(dispatch_label << 12);
        let sel = core::ptr::read_volatile((shared_va + SH_REQ_SEL_H) as *const u64);
        let (st, info) = dispatch(&DispatchReq { sel, drv });
        // Write info/result FIRST, then status LAST. The FSD has distinct offsets
        // (status@0x70, info@0x78). win32k's status@0x78 ALIASES info@0x78, so the first write
        // preserves the high 32 bits of a pointer-width return and the second write commits the
        // low 32 bits last, matching the existing NTSTATUS ordering.
        core::ptr::write_volatile((shared_va + SH_REQ_INFO_H) as *mut u64, info);
        core::ptr::write_volatile((shared_va + status_off) as *mut i32, st);
        let _ = CM_TRACE;
    }
}

static mut CM_TRACE: u32 = 0;
// Header-prefix offsets shared by both Family-A frames (design §1.2 "the header prefix (0x00-0x30)
// is the same shape"). These name the SAME bytes the FSD/win32k modules already use under their own
// const names; `component_main` uses these generic names.
const SH_ENTRY_RVA_H: u64 = 0x00;
const SH_VERDICT_H: u64 = 0x08;
const SH_DE_STATUS_H: u64 = 0x10;
// (SH_MJ_TABLE is now parameterised per-spec via `DriverObjectSpec::mj_table_off` — FSD 0x18, win32k
//  MAX/none — since 0x18 is SH_SSDT_BASE in win32k's frame and must not be clobbered.)
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
