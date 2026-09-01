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
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use nt_io_manager::{write_wdm_driver_object, WdmDriverObjectInit};

const SEL4_RETYPE_FAN_OUT_LIMIT: u64 = 256;

/// Where a region's frame caps come from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameSource {
    /// Fresh retype-zeroed 4K pages (private to this component; e.g. stack, heap, IPC buf).
    FreshZeroed,
    /// `copy_cap`-aliased frames starting at this cap slot — the SAME physical frames are
    /// (or stay) mapped in the executive too (device BARs, DMA, staging buffers, shared pages).
    Alias(u64),
    /// `copy_cap`-aliased frames from an explicit cap list.
    ///
    /// Hosted driver images normally use a contiguous fresh cap range, but shared provider images
    /// such as a future singleton `ndis.sys` need to mix provider-owned frames with dependent-owned
    /// primary-driver frames in one component VA image window.
    AliasList(&'static [u64]),
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
    /// Hosted hardware drivers: service x86 #GP faults caused by inline I/O-port writes when the
    /// driver has a PnP-granted I/O-port cap in its shared resource projection.
    pub io_port_faults: bool,
}

/// Fully declarative description of an isolated component to spawn. DATA only — the POLICY
/// (which frames/VAs/rights/caps). [`spawn_component`] turns it into the seL4 MECHANISM.
pub(crate) struct ComponentDescriptor<'a> {
    /// The component's entry point (a raw executive fn — the hosted-PE trampolines live in the image).
    pub entry: unsafe extern "C" fn(u64) -> !,
    /// The executive image mapping (base = `IMAGE_BASE`, count = `IMAGE_FRAMES_COUNT`); its rights
    /// differ per host (RO / RWX / W^X). The image skeleton (pdpt/pd/image PTs/cluster PT) is
    /// always built.
    pub image_rights: Rights,
    /// Defer mapping the shared executive/runtime image until the component faults it in.
    ///
    /// This is only valid for components whose fault endpoint is actively driven by
    /// [`component_pump`] from startup onward. Notification-only components such as storage and
    /// faultless ISR helpers keep the eager path.
    pub lazy_image: bool,
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
    pub raw_cnode: u64,
    pub sched_context: u64,
    /// Shared owner-tagged bank that owns this component's mapped frame and paging caps.
    pub map_cap_bank: ComponentMapCapBank,
    /// The cap slot of the first stack frame (win32k stashes this for later remaps). Only
    /// meaningful when the stack uses `FreshZeroed`.
    pub stack_frame_base: u64,
    pub stack_frame_count: u64,
    /// Fresh IPC-buffer frame retained by the root CSpace for address-translation publication.
    pub ipc_buffer_frame: u64,
}

static COMPONENT_HANDOFF_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
const COMPONENT_HANDOFF_TRACE_CAP: u64 = 48;
static COMPONENT_SPAWN_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
const COMPONENT_SPAWN_TRACE_CAP: u64 = 256;
static COMPONENT_ROOT_IMAGE_DEMAND_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);
const COMPONENT_ROOT_IMAGE_DEMAND_TRACE_CAP: u64 = 64;

#[inline(never)]
unsafe fn trace_component_spawn_stage(stage: &[u8], a: u64, b: u64) {
    let trace = COMPONENT_SPAWN_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
    if trace >= COMPONENT_SPAWN_TRACE_CAP {
        return;
    }
    crate::print_str(b"[component-spawn] stage=");
    crate::print_str(stage);
    crate::print_str(b" a=0x");
    crate::print_hex(a as u32);
    crate::print_str(b" b=0x");
    crate::print_hex(b as u32);
    crate::print_str(b"\n");
}

#[inline(never)]
unsafe fn trace_component_handoff(stage: &[u8], tcb: u64, reply_cap: u64, detail: u64) {
    let trace = COMPONENT_HANDOFF_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
    if trace >= COMPONENT_HANDOFF_TRACE_CAP {
        return;
    }
    crate::print_str(b"[component-handoff] stage=");
    crate::print_str(stage);
    crate::print_str(b" tcb=0x");
    crate::print_hex(tcb as u32);
    crate::print_str(b" reply=0x");
    crate::print_hex(reply_cap as u32);
    crate::print_str(b" detail=");
    crate::print_u64(detail);
    crate::print_str(b"\n");
    crate::win32k_glue::trace_hosted_tcb_debug_state(stage, tcb, reply_cap);
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ComponentMapCapBank {
    pub owner: u16,
    pub count: u64,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ComponentMapCapBankRelease {
    pub caps: u64,
    pub failures: u64,
}

const COMPONENT_MAP_CAP_BANK_RESERVED_SLOTS: u64 = 64;
static COMPONENT_MAP_CAP_BANK_OWNER_NEXT: AtomicU64 = AtomicU64::new(1);
static COMPONENT_MAP_CAP_ROOT_OWNER: [AtomicU16; ROOT_SLOT_TRACK_CAP] =
    [const { AtomicU16::new(0) }; ROOT_SLOT_TRACK_CAP];

#[inline]
fn component_heap_pt_count(frames: u64) -> u64 {
    frames.div_ceil(512).max(1)
}

fn component_allocator_heap_frames(d: &ComponentDescriptor) -> u64 {
    let mut frames = 0u64;
    for region in d.regions {
        if region.base_va != allocator::HEAP_BASE as u64 || region.count == 0 {
            continue;
        }
        assert_eq!(
            frames, 0,
            "component declares multiple allocator heap regions"
        );
        frames = region.count;
    }
    assert!(frames <= allocator::HEAP_FRAMES);
    assert_eq!(d.map_heap_pt, frames != 0);
    frames
}

#[inline]
fn component_descriptor_map_cap_count(d: &ComponentDescriptor, img_count: u64) -> u64 {
    let image_skeleton_caps = 2 + component_heap_pt_count(img_count) + 1;
    let heap_frames = component_allocator_heap_frames(d);
    let heap_caps = if heap_frames != 0 {
        component_heap_pt_count(heap_frames)
    } else {
        0
    };
    let stack_pt_caps = u64::from(d.stack_dedicated_pt);
    let region_caps = d.regions.iter().fold(0u64, |acc, r| {
        acc.saturating_add(r.pts).saturating_add(r.count)
    });
    image_skeleton_caps
        .saturating_add(img_count)
        .saturating_add(heap_caps)
        .saturating_add(stack_pt_caps)
        .saturating_add(1)
        .saturating_add(region_caps)
        .saturating_add(COMPONENT_MAP_CAP_BANK_RESERVED_SLOTS)
}

#[inline(never)]
unsafe fn component_spawn_fail(stage: &[u8], subject: u64, error: u64) -> ! {
    print_str(b"[component-spawn] ");
    print_str(stage);
    print_str(b" failed subject=0x");
    print_hex((subject >> 32) as u32);
    print_hex(subject as u32);
    print_str(b" error=");
    print_u64(error);
    print_str(b"\n");
    park()
}

#[inline(always)]
unsafe fn component_expect(stage: &[u8], subject: u64, error: u64) {
    if error != 0 {
        component_spawn_fail(stage, subject, error);
    }
}

#[inline(always)]
unsafe fn component_alloc_slot(stage: &[u8]) -> u64 {
    match try_alloc_slot() {
        Some(slot) => slot,
        None => component_spawn_fail(stage, 0, 4),
    }
}

#[inline(always)]
unsafe fn component_retype(stage: &[u8], obj: u64, bits: u32, dest: u64) {
    let error = untyped_retype_r(CAP_INIT_UNTYPED, obj, bits, 1, dest);
    component_expect(stage, dest, error);
}

#[inline(always)]
unsafe fn component_copy(stage: &[u8], source: u64) -> u64 {
    let (cap, error) = copy_cap_r(source);
    if error != 0 {
        component_spawn_fail(stage, source, error);
    }
    cap
}

unsafe fn component_alloc_frame_run(stage: &[u8], count: u64) -> u64 {
    let Some(base) = try_alloc_slot_run(count) else {
        component_spawn_fail(stage, count, 4);
    };
    let mut done = 0u64;
    while done < count {
        let remaining = count - done;
        let batch = remaining.min(SEL4_RETYPE_FAN_OUT_LIMIT);
        let slot = base + done;
        let error = untyped_retype_r(
            CAP_INIT_UNTYPED,
            OBJ_X86_4K_PAGE,
            PAGING_BITS,
            batch as u32,
            slot,
        );
        if error != 0 {
            let mut j = 0u64;
            while j < done {
                let _ = cnode_delete_recycle_r(base + j);
                j += 1;
            }
            while j < count {
                recycle_deleted_root_slot(base + j);
                j += 1;
            }
            component_spawn_fail(stage, slot, error);
        }
        done += batch;
    }
    base
}

unsafe fn component_map_cap_bank_create(count: u64) -> ComponentMapCapBank {
    if count > ROOT_SLOT_TRACK_CAP as u64 {
        component_spawn_fail(b"component-bank-capacity", count, 4);
    }
    let owner = COMPONENT_MAP_CAP_BANK_OWNER_NEXT.fetch_add(1, Ordering::Relaxed);
    if owner == 0 || owner > u16::MAX as u64 {
        component_spawn_fail(b"component-bank-owner", count, owner);
    }
    ComponentMapCapBank {
        owner: owner as u16,
        count: 0,
    }
}

unsafe fn component_map_cap_bank_store(bank: &mut ComponentMapCapBank, root_cap: u64) {
    if bank.owner == 0 {
        component_spawn_fail(b"component-bank-owner", root_cap, 0);
    }
    let Some(owner_slot) = root_slot_index(root_cap) else {
        component_spawn_fail(b"component-bank-root-slot", root_cap, bank.count);
    };
    if COMPONENT_MAP_CAP_ROOT_OWNER[owner_slot].swap(bank.owner, Ordering::Relaxed) != 0 {
        component_spawn_fail(b"component-bank-owner-slot", root_cap, owner_slot as u64);
    }
    bank.count += 1;
}

unsafe fn component_map_cap_bank_tag(owner: u16, root_cap: u64) -> bool {
    if owner == 0 {
        return false;
    }
    let Some(owner_slot) = root_slot_index(root_cap) else {
        return false;
    };
    COMPONENT_MAP_CAP_ROOT_OWNER[owner_slot].swap(owner, Ordering::Relaxed) == 0
}

pub(crate) unsafe fn release_component_map_cap_bank(
    bank: ComponentMapCapBank,
) -> ComponentMapCapBankRelease {
    if bank.owner == 0 || bank.count == 0 {
        return ComponentMapCapBankRelease::default();
    }
    let mut released = 0u64;
    let mut failures = 0u64;
    let start = ROOT_CSPACE_START.load(Ordering::Relaxed);
    let scan_limit = NEXT_SLOT
        .load(Ordering::Relaxed)
        .saturating_sub(start)
        .min(ROOT_SLOT_TRACK_CAP as u64);
    let mut owner_slot = 0usize;
    while owner_slot < scan_limit as usize {
        if COMPONENT_MAP_CAP_ROOT_OWNER[owner_slot].load(Ordering::Relaxed) == bank.owner {
            let root_cap = start + owner_slot as u64;
            if cnode_delete_recycle_r(root_cap) == 0 {
                COMPONENT_MAP_CAP_ROOT_OWNER[owner_slot].store(0, Ordering::Relaxed);
                released += 1;
            } else {
                failures += 1;
            }
        }
        owner_slot += 1;
    }
    if released != bank.count {
        failures = failures.saturating_add(bank.count.saturating_sub(released));
    }
    ComponentMapCapBankRelease {
        caps: released,
        failures,
    }
}

unsafe fn component_map_paging_cap(
    bank: &mut ComponentMapCapBank,
    stage: &[u8],
    object_type: u64,
    map_label: u64,
    va: u64,
    pml4: u64,
) {
    let cap = component_alloc_slot(stage);
    component_retype(stage, object_type, PAGING_BITS, cap);
    let error = paging_struct_map_r(cap, map_label, va, pml4);
    component_expect(stage, va, error);
    component_map_cap_bank_store(bank, cap);
}

unsafe fn component_map_cluster_pt(pml4: u64, bank: &mut ComponentMapCapBank) {
    component_map_paging_cap(
        bank,
        b"cluster-pt-map",
        OBJ_X86_PAGE_TABLE,
        LBL_X86_PAGE_TABLE_MAP,
        WORK_CLUSTER_BASE,
        pml4,
    );
}

unsafe fn component_map_heap_pts(pml4: u64, frames: u64, bank: &mut ComponentMapCapBank) {
    let windows = component_heap_pt_count(frames);
    let mut window = 0u64;
    while window < windows {
        component_map_paging_cap(
            bank,
            b"heap-pt-map",
            OBJ_X86_PAGE_TABLE,
            LBL_X86_PAGE_TABLE_MAP,
            allocator::HEAP_BASE as u64 + window * 0x20_0000,
            pml4,
        );
        window += 1;
    }
}

unsafe fn component_map_image_skeleton(pml4: u64, img_count: u64, bank: &mut ComponentMapCapBank) {
    component_map_paging_cap(
        bank,
        b"image-pdpt-map",
        OBJ_X86_PDPT,
        LBL_X86_PDPT_MAP,
        IMAGE_BASE,
        pml4,
    );
    component_map_paging_cap(
        bank,
        b"image-pd-map",
        OBJ_X86_PAGE_DIRECTORY,
        LBL_X86_PAGE_DIRECTORY_MAP,
        IMAGE_BASE,
        pml4,
    );
    let npt = component_heap_pt_count(img_count);
    let mut k = 0u64;
    while k < npt {
        component_map_paging_cap(
            bank,
            b"image-pt-map",
            OBJ_X86_PAGE_TABLE,
            LBL_X86_PAGE_TABLE_MAP,
            IMAGE_BASE + k * 0x20_0000,
            pml4,
        );
        k += 1;
    }
    component_map_cluster_pt(pml4, bank);
}

/// THE generic mechanism: build a fresh VSpace + CSpace + TCB for an isolated component from a
/// declarative [`ComponentDescriptor`], granting exactly the frames/VAs/rights/caps it names, and
/// resume it. This is the seL4 dance written ONCE; every `spawn_*` below is a descriptor-builder.
pub(crate) unsafe fn spawn_component(d: &ComponentDescriptor) -> SpawnedComponent {
    spawn_component_inner(d, true)
}

/// Build a component completely but leave its TCB suspended so the owner can publish derived
/// mapping metadata before any component instruction executes.
pub(crate) unsafe fn spawn_component_suspended(d: &ComponentDescriptor) -> SpawnedComponent {
    spawn_component_inner(d, false)
}

pub(crate) unsafe fn resume_spawned_component(component: &SpawnedComponent) -> u64 {
    trace_component_spawn_stage(b"resume-begin", component.tcb, component.sched_context);
    let error = tcb_resume_r(component.tcb);
    trace_component_spawn_stage(b"resume-end", component.tcb, error);
    trace_component_handoff(b"component-resume", component.tcb, 0, error);
    error
}

unsafe fn spawn_component_inner(d: &ComponentDescriptor, resume: bool) -> SpawnedComponent {
    let img_start = IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let img_count = IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    let heap_frames = component_allocator_heap_frames(d);
    trace_component_spawn_stage(b"enter", d.entry as u64, img_count);
    let mut map_cap_bank =
        component_map_cap_bank_create(component_descriptor_map_cap_count(d, img_count));
    let pml4 = component_alloc_slot(b"pml4-slot");
    component_retype(b"pml4-retype", OBJ_X86_PML4, PAGING_BITS, pml4);
    require_vspace_asid(pml4, b"isolated-component");
    component_map_image_skeleton(pml4, img_count, &mut map_cap_bank);
    if heap_frames != 0 {
        component_map_heap_pts(pml4, heap_frames, &mut map_cap_bank);
    }
    trace_component_spawn_stage(b"vspace-ready", pml4, map_cap_bank.count);
    if d.lazy_image {
        trace_component_spawn_stage(b"image-lazy", img_count, map_cap_bank.count);
    } else {
        // Executive image frames.
        for i in 0..img_count {
            if i < 16 || (i & 0x3f) == 0 {
                trace_component_spawn_stage(b"image-loop", i, map_cap_bank.count);
            }
            let va = IMAGE_BASE + i * 0x1000;
            let cp = component_copy(b"image-copy", img_start + i);
            let error = page_map_r(cp, va, rights_at(d.image_rights, i), pml4);
            component_expect(b"image-map", va, error);
            component_map_cap_bank_store(&mut map_cap_bank, cp);
            if i < 16 || (i & 0x3f) == 0 {
                trace_component_spawn_stage(b"image-step", i, map_cap_bank.count);
            }
        }
        trace_component_spawn_stage(b"image-mapped", img_count, map_cap_bank.count);
    }
    // Stack.
    if d.stack_dedicated_pt {
        component_map_paging_cap(
            &mut map_cap_bank,
            b"stack-pt-map",
            OBJ_X86_PAGE_TABLE,
            LBL_X86_PAGE_TABLE_MAP,
            d.stack_base,
            pml4,
        );
    }
    let stack_frame_base = if d.stack_frames == 0 {
        0
    } else {
        component_alloc_frame_run(b"stack-frame-run", d.stack_frames)
    };
    for i in 0..d.stack_frames {
        let f = stack_frame_base + i;
        let va = d.stack_base + i * 0x1000;
        let error = page_map_r(f, va, RW_NX, pml4);
        component_expect(b"stack-frame-map", va, error);
    }
    trace_component_spawn_stage(b"stack-mapped", stack_frame_base, d.stack_frames);
    // IPC buffer (always a fresh page at IPCBUF_VADDR).
    let ipcbuf = component_alloc_slot(b"ipcbuf-slot");
    component_retype(b"ipcbuf-retype", OBJ_X86_4K_PAGE, PAGING_BITS, ipcbuf);
    let error = page_map_r(ipcbuf, IPCBUF_VADDR, RW_NX, pml4);
    component_expect(b"ipcbuf-map", IPCBUF_VADDR, error);
    trace_component_spawn_stage(b"ipcbuf-mapped", ipcbuf, IPCBUF_VADDR);
    // Additional regions.
    trace_component_spawn_stage(b"regions-begin", d.regions.len() as u64, map_cap_bank.count);
    for r in d.regions {
        map_region(pml4, r, &mut map_cap_bank);
    }
    trace_component_spawn_stage(b"regions-end", d.regions.len() as u64, map_cap_bank.count);
    // CSpace: a guarded CNode holding PML4 + the granted caps.
    let raw = component_alloc_slot(b"cnode-raw-slot");
    component_retype(b"cnode-raw-retype", OBJ_CNODE, CN_RADIX, raw);
    let cnode = component_alloc_slot(b"cnode-slot");
    let error = cnode_mint_r(CAP_INIT_THREAD_CNODE, cnode, raw, CN_GUARD_BADGE);
    component_expect(b"cnode-mint", raw, error);
    let error = cnode_copy_at_r(cnode, CT_PML4, pml4);
    component_expect(b"cnode-pml4-copy", pml4, error);
    if let Some(c) = d.granted.irq_ntfn {
        let error = cnode_copy_at_r(cnode, CT_IRQ_NTFN, c);
        component_expect(b"cnode-irq-copy", c, error);
    }
    if let Some(c) = d.granted.result_ntfn {
        let error = cnode_copy_at_r(cnode, CT_RESULT_NTFN, c);
        component_expect(b"cnode-result-copy", c, error);
    }
    if let Some(c) = d.granted.fault_ep {
        let error = cnode_copy_at_r(cnode, CT_FAULT, c);
        component_expect(b"cnode-fault-copy", c, error);
    }
    trace_component_spawn_stage(b"cspace-ready", cnode, raw);
    // TCB.
    let tcb = component_alloc_slot(b"tcb-slot");
    component_retype(b"tcb-retype", OBJ_TCB, 0, tcb);
    // The fault-handler cap slot in the new CSpace is CT_FAULT when a fault EP was granted, else 0.
    let fault_slot = if d.granted.fault_ep.is_some() {
        CT_FAULT
    } else {
        0
    };
    let error = tcb_set_space_r(tcb, fault_slot, cnode, pml4);
    component_expect(b"tcb-set-space", tcb, error);
    let error = tcb_set_ipc_buffer_r(tcb, IPCBUF_VADDR, ipcbuf);
    component_expect(b"tcb-set-ipcbuf", tcb, error);
    component_map_cap_bank_store(&mut map_cap_bank, ipcbuf);
    let stack_top = d.stack_base + d.stack_frames * 0x1000 - 16;
    let error = tcb_write_registers_r(tcb, d.entry as u64, stack_top, heap_frames);
    component_expect(b"tcb-write-registers", tcb, error);
    let _ = tcb_set_priority(tcb, d.prio);
    if let Some(gs) = d.gs_base {
        let _ = tcb_set_gs_base(tcb, gs);
    }
    trace_component_spawn_stage(b"tcb-ready", tcb, d.prio);
    let sched_context = match attach_sched_context(tcb) {
        Ok(sc) => sc,
        Err(e_sc) => {
            print_str(b"[thread-life] component SC attach failed tcb=0x");
            print_hex(tcb as u32);
            print_str(b" error=");
            print_u64(e_sc);
            print_str(b"\n");
            park();
        }
    };
    trace_component_spawn_stage(b"sc-attached", tcb, sched_context);
    let component = SpawnedComponent {
        pml4,
        tcb,
        cnode,
        raw_cnode: raw,
        sched_context,
        map_cap_bank,
        stack_frame_base,
        stack_frame_count: d.stack_frames,
        ipc_buffer_frame: ipcbuf,
    };
    if resume {
        let error = resume_spawned_component(&component);
        component_expect(b"tcb-resume", tcb, error);
    }
    component
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
unsafe fn map_region(pml4: u64, r: &Region, bank: &mut ComponentMapCapBank) {
    for p in 0..r.pts {
        let va = r.base_va + p * 0x20_0000;
        component_map_paging_cap(
            bank,
            b"region-pt-map",
            OBJ_X86_PAGE_TABLE,
            LBL_X86_PAGE_TABLE_MAP,
            va,
            pml4,
        );
    }
    let fresh_base = if r.source == FrameSource::FreshZeroed && r.count != 0 {
        component_alloc_frame_run(b"region-frame-run", r.count)
    } else {
        0
    };
    let mut first = 0;
    for i in 0..r.count {
        let cap = match r.source {
            FrameSource::FreshZeroed => fresh_base + i,
            FrameSource::Alias(base) => component_copy(b"region-alias-copy", base + i),
            FrameSource::AliasList(frames) => match frames.get(i as usize).copied() {
                Some(frame) => component_copy(b"region-list-copy", frame),
                None => {
                    print_str(b"[component-spawn] image cap list too short have=");
                    print_u64(frames.len() as u64);
                    print_str(b" need=");
                    print_u64(r.count);
                    print_str(b"\n");
                    park();
                }
            },
        };
        if i == 0 {
            first = match r.source {
                FrameSource::FreshZeroed => cap,
                FrameSource::Alias(base) => base,
                FrameSource::AliasList(frames) => frames.first().copied().unwrap_or(0),
            };
        }
        let va = r.base_va + i * 0x1000;
        let error = page_map_r(cap, va, rights_at(r.rights, i), pml4);
        component_expect(b"region-map", va, error);
        component_map_cap_bank_store(bank, cap);
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
    entry: unsafe extern "C" fn(u64) -> !,
    irq_cap: u64,
    result_cap: u64,
    prio: u64,
) {
    let d = ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(2), // RO
        lazy_image: false,
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
/// DMA frame + a small shared metadata/data run, so it drives the disk entirely from its own VSpace. The
/// executive (Tier-1 broker) has already enabled Bus Master; the host gets no PCI-config
/// access. `shared` carries `dma_paddr` in (@0), the verdict + INITRD info out, and the generated
/// hive on page 1.
pub(crate) unsafe fn spawn_storage_host(
    entry: unsafe extern "C" fn(u64) -> !,
    result_cap: u64,
    fault_ep: u64,
    prio: u64,
    ahci_bar_frame: u64,
    dma_frame: u64,
    shared_start: u64,
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
    // Component heap, then device resources (cluster PT window, no dedicated PT): AHCI BAR, DMA
    // frame, shared run. Then the staging buffers, each with its own dedicated PT(s). NLS +
    // SYSTEM-hive share one input page table with each other, distinct from the relocated NTDLLBUF.
    let mut regions: [Region; 32] = [Region {
        source: FrameSource::Alias(0),
        base_va: 0,
        count: 0,
        rights: Rights::Uniform(RW_NX),
        pts: 0,
    }; 32];
    let mut n = 0usize;
    regions[n] = Region {
        source: FrameSource::FreshZeroed,
        base_va: allocator::HEAP_BASE as u64,
        count: allocator::DEFAULT_SERVICE_HEAP_FRAMES,
        rights: Rights::Uniform(RW_NX),
        pts: 0,
    };
    n += 1;
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
        source: FrameSource::Alias(shared_start),
        base_va: STORAGE_SHARED_VADDR,
        count: STORAGE_SHARED_FRAMES,
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
        lazy_image: false,
        map_heap_pt: true,
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
///   reply object, so the pump answers that Call and receives the next component message in one
///   composite kernel entry.
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
    /// Executive-side alias for the component image bytes. This differs from [`Self::code_va`] for
    /// multi-instance hosted drivers, because every component runs at `FSD_CODE_VA` in its own VSpace
    /// while the executive maps each loaded image at a unique alias.
    pub exec_code_va: u64,
    /// Rights used when demand-mapping the shared executive/runtime image at [`crate::IMAGE_BASE`].
    pub root_image_rights: u64,
    /// Component map-cap bank owner used to tag root-image demand-map caps for teardown.
    pub root_image_map_owner: u16,
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
    /// ★ This component's active MCS reply object — the server side of the `Call` transport, and now
    /// MANDATORY (a zero here means the channel has no transport at all). `R_win32k` (`REPLY_W32`)
    /// and `R_fsd[inst]` (`REPLY_FSD`) are distinct from the hosted-user wait reply pool. FSD worker
    /// parking needs driver-owned rotation around this active object.
    pub reply_cap: u64,
    /// win32k only (0 for the FSD): the exact client identity captured when this dispatch was routed.
    /// Event-object broker calls consume both fields from this scoped channel rather than consulting
    /// ambient last-writer state, so a nested GUI dispatch cannot change the outer caller's owner.
    pub client_pi: u64,
    pub client_generation: u64,
    /// The win32k capability gates (all-false for the FSD).
    pub caps: HostCaps,
}

#[derive(Clone, Copy)]
pub(crate) struct UserCallbackClient {
    pub pi: u32,
    /// Process-manager generation paired with `pi`; callback nesting must retain the exact lifetime.
    pub generation: u64,
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

#[inline(always)]
fn pump_print_hex64(value: u64) {
    crate::print_hex((value >> 32) as u32);
    crate::print_hex(value as u32);
}

#[inline(never)]
unsafe fn pump_wall_state_diag(ch: &PumpChannel, outcome: PumpLoopOutcome) {
    if ch.tcb == 0
        || PUMP_WALL_STATE_TRACES.fetch_add(1, Ordering::Relaxed) >= PUMP_WALL_STATE_TRACE_CAP
    {
        return;
    }

    let mut regs = [0u64; 20];
    crate::win32k_glue::tcb_read_regs20(ch.tcb, &mut regs);
    crate::print_str(b"[pump-wall-regs] label=");
    crate::print_u64(outcome.wall_label);
    crate::print_str(b" rip=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RIP]);
    crate::print_str(b" rsp=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RSP]);
    crate::print_str(b" rflags=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RFLAGS]);
    crate::print_str(b" rax=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RAX]);
    crate::print_str(b" rbx=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RBX]);
    crate::print_str(b" rcx=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RCX]);
    crate::print_str(b" rdx=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RDX]);
    crate::print_str(b" rsi=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RSI]);
    crate::print_str(b" rdi=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RDI]);
    crate::print_str(b" rbp=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_RBP]);
    crate::print_str(b" r8=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R8]);
    crate::print_str(b" r9=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R9]);
    crate::print_str(b" r10=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R10]);
    crate::print_str(b" r11=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R11]);
    crate::print_str(b" r12=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R12]);
    crate::print_str(b" r13=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R13]);
    crate::print_str(b" r14=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R14]);
    crate::print_str(b" r15=0x");
    pump_print_hex64(regs[nt_user_callback::USER_CONTEXT_R15]);
    crate::print_str(b"\n");

    let rsp = regs[nt_user_callback::USER_CONTEXT_RSP];
    crate::print_str(b"[pump-wall-stack] shared=0x");
    pump_print_hex64(ch.shared_va);
    crate::print_str(b" rsp=0x");
    pump_print_hex64(rsp);
    crate::print_str(b" top:");
    let mut i = 0u64;
    while i < 8 {
        crate::print_str(b" +");
        crate::print_u64(i * 8);
        crate::print_str(b"=0x");
        if let Some(value) =
            crate::driver_launch::hosted_component_stack_qword(ch.shared_va, rsp, i)
        {
            pump_print_hex64(value);
        } else {
            crate::print_str(b"?");
        }
        i += 1;
    }
    crate::print_str(b"\n");
}

/// PROOF-OF-WIRING counters: `component_pump` increments these per SERVICED dispatch, tagged by
/// `ReqKind`. They are the durable evidence that a component's live traffic actually flows through
/// the SHARED harness pump (not the retired bespoke inline loop). The `exec_fsd_on_shared_harness`
/// gate spec asserts `HARNESS_IRP_DISPATCHES >= N` for real device-bound named-pipe traffic. If FSD
/// dispatch were not routed through `component_pump`, this counter would stay 0 and the spec FAILS.
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
// `call_on` publishes its completion AND returns the next request; the executive answers with the
// reply half of `SysNBSendRecv`, then receives the component's next Call in the same kernel entry.
//
// This is not a correlation *mechanism* we maintain; it is a correlation *fact the kernel keeps*:
//
//   * a recv registering reply object `R` (`recv_full_r12`) makes the kernel bind `R` to whichever
//     thread's Call pairs with it — `endpoint.rs::finish_call` → `replies[i].bound_tcb = sender`;
//   * sending on `R` (`invocation.rs::decode_reply`) resumes exactly `bound_tcb` and CLEARS the
//     binding, or fails with `seL4_InvalidCapability` if there is none;
//   * a thread blocked in `Call` is `BlockedOnReply` and cannot race ahead to publish a second
//     completion.
//
// Therefore a stale or misdirected completion is UNREPRESENTABLE: the component cannot speak again
// until we reply, and our reply cannot reach anyone but the thread the kernel bound. The
// `SH_REQ_SEQ` sequence handshake and the per-dispatch token stack that used to reconstruct this
// property in userspace are deleted.
// =============================================================================================

/// Requests answered on a component's reply object, BY KIND. Every one of them uses the composite
/// reply+receive syscall, so the executive cannot keep running between reply delivery and the next
/// receive boundary.
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
/// Legacy counter retained for transport gates that assert no component reply-object error was
/// observed. The component pump now uses composite reply+receive rather than the older standalone
/// `reply_on` helper, so this remains zero unless a future explicit error-returning component reply
/// path is added.
pub(crate) static PUMP_REPLY_ERRORS: AtomicU64 = AtomicU64::new(0);
/// Components suspended (`TCB_Suspend`) because their pump WALLED — see risk R2 at the wall tail.
pub(crate) static PUMP_WALL_SUSPENDS: AtomicU64 = AtomicU64::new(0);
static PUMP_WALL_STATE_TRACES: AtomicU64 = AtomicU64::new(0);
const PUMP_WALL_STATE_TRACE_CAP: u64 = 16;
/// Hosted hardware-driver inline `out dx,eax` faults serviced through a PnP-granted IOPort cap.
pub(crate) static HOSTED_IO_PORT_OUT32_FAULTS: AtomicU64 = AtomicU64::new(0);
static HOSTED_IO_PORT_UNHANDLED_GPS: AtomicU64 = AtomicU64::new(0);

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
static PUMP_TIMER_FAIR_POLLS: AtomicU64 = AtomicU64::new(0);
static PUMP_TIMER_FAIR_HITS: AtomicU64 = AtomicU64::new(0);
static PUMP_DEADMAN_UNWINDS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn pump_label_can_arrive_after_timer(ch: &PumpChannel, label: u64) -> bool {
    label == ch.dispatch_label
        || (crate::driver_launch::is_fsd_component_service_label(label)
            && ch.caps.kind == ReqKind::Irp)
        || (label == crate::win32k_subsystem::W32_USER_CALLBACK_LABEL && ch.caps.usermode_callback)
        || (label == crate::win32k_subsystem::W32_GDI_LOAD_LABEL
            && ch.caps.kind == ReqKind::Syscall)
        || (label == crate::win32k_subsystem::W32_VIDEO_IOCTL_LABEL
            && ch.caps.kind == ReqKind::Syscall)
        || (label == crate::win32k_subsystem::W32_LPC_LABEL && ch.caps.kind == ReqKind::Syscall)
        || (label == crate::win32k_subsystem::W32_REGISTRY_LABEL
            && ch.caps.kind == ReqKind::Syscall)
        || (label == crate::win32k_subsystem::W32_EVENT_LABEL
            && ch.caps.kind == ReqKind::Syscall)
        || label == 6
        || (label == 3 && (ch.caps.io_port_faults || ch.caps.assert_skip))
}

unsafe fn pump_handle_executive_event_badge(badge: u64) -> (bool, bool) {
    let timer = crate::badge_has_delay_timer(badge);
    let irq_lines = crate::driver_launch::latch_hosted_irq_badge(badge);
    let event = timer || irq_lines != 0;
    if crate::EXEC_DEADMAN_WATCHDOG {
        if timer {
            crate::watchdog_on_tick();
        } else if !event {
            crate::WATCHDOG_MSGS.fetch_add(1, Ordering::Relaxed);
        }
    }
    if timer {
        crate::DELAY_TIMER_TICKS_PENDING.fetch_add(1, Ordering::Relaxed);
        if !crate::drain_nested_pump_timer_delivery() {
            crate::delay_timer_nested_ack();
        }
    }
    (event, timer)
}

/// After a bound HPET notification interrupts a component endpoint receive, probe that endpoint
/// once without blocking. This prevents a ready component Call from sitting behind a stream of timer
/// badges on the root TCB's bound notification while preserving normal blocking behavior when the
/// endpoint is still idle.
#[inline(never)]
unsafe fn pump_try_recv_after_timer(ch: &PumpChannel, reply_cap: u64) -> Option<PumpMessage> {
    PUMP_TIMER_FAIR_POLLS.fetch_add(1, Ordering::Relaxed);
    let badge: u64;
    let mi: u64;
    let m0: u64;
    let m1: u64;
    let m2: u64;
    let m3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_NB_RECV as u64,
        inout("rdi") ch.fault_ep => badge,
        lateout("rsi") mi,
        lateout("r10") m0,
        lateout("r8") m1,
        lateout("r9") m2,
        lateout("r15") m3,
        in("r12") reply_cap,
        in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    let (executive_event, _timer) = pump_handle_executive_event_badge(badge);
    if executive_event {
        if pump_deadman_tripped() {
            return Some(PumpMessage::deadman_wall());
        }
        return None;
    }
    let label = mi >> 12;
    // A timer drain can leave non-endpoint msginfo in the volatile receive registers (for example
    // the executive's IRQ-ack label). This fairness probe is advisory, so only protocol labels that
    // the component pump already knows how to service are allowed to short-circuit the next Recv.
    if !pump_label_can_arrive_after_timer(ch, label) {
        return None;
    }
    let hit = PUMP_TIMER_FAIR_HITS.fetch_add(1, Ordering::Relaxed);
    if hit < 8 {
        crate::print_str(b"[pump] timer-fair NBRecv accepted component message label=");
        crate::print_u64(label);
        crate::print_str(b"\n");
    }
    let m4 = if (mi & 0x7F) > 4 {
        crate::get_recv_mr(4)
    } else {
        0
    };
    Some(PumpMessage {
        badge,
        mi,
        m0,
        m1,
        m2,
        m3,
        m4,
        scheduler_yield: false,
    })
}

#[derive(Clone, Copy)]
struct PumpMessage {
    badge: u64,
    mi: u64,
    m0: u64,
    m1: u64,
    m2: u64,
    m3: u64,
    m4: u64,
    scheduler_yield: bool,
}

impl PumpMessage {
    #[inline]
    fn label(self) -> u64 {
        self.mi >> 12
    }

    #[inline]
    const fn deadman_wall() -> Self {
        Self {
            badge: 0,
            mi: 0,
            m0: 0,
            m1: 0,
            m2: 0,
            m3: 0,
            m4: 0,
            scheduler_yield: false,
        }
    }

    #[inline]
    const fn scheduler_yield() -> Self {
        Self {
            badge: 0,
            mi: 0,
            m0: 0,
            m1: 0,
            m2: 0,
            m3: 0,
            m4: 0,
            scheduler_yield: true,
        }
    }
}

#[inline]
fn pump_deadman_tripped() -> bool {
    if crate::WATCHDOG_TRIPPED.load(Ordering::Relaxed) == 0 {
        return false;
    }
    if unsafe { crate::watchdog_defer_if_hosted_work_can_run(b"component-pump") } {
        return false;
    }
    unsafe {
        crate::watchdog_confirm_trip();
    }
    let n = PUMP_DEADMAN_UNWINDS.fetch_add(1, Ordering::Relaxed);
    if n < 8 {
        crate::print_str(b"[pump] deadman confirmed during nested receive -> unwind to gate\n");
    }
    true
}

macro_rules! pump_reply_recv_into {
    ($ch:expr, $reply_cap:expr, $msg:ident, $len:expr, $r0:expr) => {{
        $msg = pump_reply_recv($ch, $reply_cap, $len as u64, $r0 as u64);
    }};
}

macro_rules! pump_reply_recv4_into {
    ($ch:expr, $reply_cap:expr, $msg:ident, $len:expr, $r0:expr, $r1:expr, $r2:expr, $r3:expr) => {{
        $msg = pump_reply_recv4(
            $ch,
            $reply_cap,
            $len as u64,
            $r0 as u64,
            $r1 as u64,
            $r2 as u64,
            $r3 as u64,
        );
    }};
}

#[derive(Clone, Copy)]
struct PumpLoopOutcome {
    completed: bool,
    callback_suspended: bool,
    scheduler_yielded: bool,
    wall_ip: u64,
    wall_addr: u64,
    wall_label: u64,
    wall_flags: u64,
    wall_exception: u64,
    wall_code: u64,
    faults: u64,
    demand: u64,
}

impl PumpLoopOutcome {
    #[inline]
    const fn new() -> Self {
        Self {
            completed: false,
            callback_suspended: false,
            scheduler_yielded: false,
            wall_ip: 0,
            wall_addr: 0,
            wall_label: 0,
            wall_flags: 0,
            wall_exception: 0,
            wall_code: 0,
            faults: 0,
            demand: 0,
        }
    }

    #[inline]
    fn wall(&mut self, msg: PumpMessage) {
        self.wall_ip = msg.m0;
        self.wall_addr = msg.m1;
        self.wall_label = msg.label();
        self.wall_flags = msg.m2;
        self.wall_exception = msg.m3;
        self.wall_code = msg.m4;
    }
}

/// Receive the component's next message. The recv REGISTERS the channel's reply object in r12, so
/// the kernel binds it to whichever Call — dispatch completion, demand-page fault or callback —
/// pairs with us. This is the ONLY correlation state the transport has, and it is the kernel's.
///
/// ★ THE BADGE IS LOAD-BEARING (Phase 4). The executive's root TCB has the HPET one-shot
/// notification BOUND to it, so this `Recv` has a SECOND thing that can satisfy it besides a
/// component `Call`: a timer tick. The kernel's bound-notification pre-check
/// (`syscall_handler.rs::handle_recv`) returns `rdi = DELAY_TIMER_BADGE`, `rsi = 0` and **leaves the
/// message registers untouched** without staging `ch.reply_cap` for IPC, so a tick absorbed here
/// reads as `label = 0` with MR0 still holding the reply-half request tag.
/// That is a WALL, and it is exactly what killed the LSA route's npfs READ
/// (`[pump] WALL label=0 ip=0x771`): the route is the first thing in the boot that arms an HPET
/// one-shot (`NtDelayExecution` from the RPC worker) WHILE a component dispatch is in flight. The
/// main service loop has always screened this badge; the pump did not, because before the route
/// nothing ticked during a dispatch.
///
/// So: recognise the tick, count it, and ask the service-loop-owned timer hook to drain the real
/// queues immediately when that context is live. If no service context is registered (early init or
/// post-loop tests), fall back to acknowledging the IRQ line and let the ordinary loop drain the
/// coalesced tick later.
#[inline(never)]
unsafe fn pump_recv(ch: &PumpChannel, reply_cap: u64) -> PumpMessage {
    loop {
        // (This recv pairs a component `Call`, so the kernel writes `executive.reply_to = component`.
        // Harmless since Phase 3: no executive reply reads `reply_to` any more.)
        let badge: u64;
        let mi: u64;
        let m0: u64;
        let m1: u64;
        let m2: u64;
        let m3: u64;
        core::arch::asm!(
            "syscall",
            in("rdx") crate::SYS_RECV as u64,
            inout("rdi") ch.fault_ep => badge,
            lateout("rsi") mi,
            lateout("r10") m0,
            lateout("r8") m1,
            lateout("r9") m2,
            lateout("r15") m3,
            in("r12") reply_cap,
            in("r13") 0u64,
            lateout("rax") _, lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        let (executive_event, timer) = pump_handle_executive_event_badge(badge);
        if executive_event {
            if pump_deadman_tripped() {
                return PumpMessage::deadman_wall();
            }
            if ch.caps.kind == ReqKind::Irp {
                return PumpMessage::scheduler_yield();
            }
            if timer {
                if let Some(polled) = pump_try_recv_after_timer(ch, reply_cap) {
                    crate::PUMP_TIMER_TICKS_ABSORBED.fetch_add(1, Ordering::Relaxed);
                    return polled;
                }
                let n = crate::PUMP_TIMER_TICKS_ABSORBED.fetch_add(1, Ordering::Relaxed);
                if n < 8 {
                    crate::print_str(
                        b"[pump] HPET tick landed on a component recv -> deferred to the service loop (NOT a wall)\n",
                    );
                }
            }
            continue;
        }
        let m4 = if (mi & 0x7F) > 4 {
            crate::get_recv_mr(4)
        } else {
            0
        };
        return PumpMessage {
            badge,
            mi,
            m0,
            m1,
            m2,
            m3,
            m4,
            scheduler_yield: false,
        };
    }
}

/// Reply to the component's outstanding `Call` and receive the next component message in one kernel
/// entry. The send half targets the reply cap in r13; the receive half offers the same reply cap in
/// r12 so the next component `Call` binds to the same kernel reply object.
#[inline(never)]
unsafe fn pump_reply_recv(
    ch: &PumpChannel,
    reply_cap: u64,
    reply_msginfo: u64,
    reply_r0: u64,
) -> PumpMessage {
    pump_reply_recv4(ch, reply_cap, reply_msginfo, reply_r0, 0, 0, 0)
}

unsafe fn pump_reply_recv4(
    ch: &PumpChannel,
    reply_cap: u64,
    reply_msginfo: u64,
    reply_r0: u64,
    reply_r1: u64,
    reply_r2: u64,
    reply_r3: u64,
) -> PumpMessage {
    let badge: u64;
    let mi: u64;
    let m0: u64;
    let m1: u64;
    let m2: u64;
    let m3: u64;
    core::arch::asm!(
        "syscall",
        in("rdx") crate::SYS_NB_SEND_RECV as u64,
        inout("rdi") ch.fault_ep => badge,
        inout("rsi") reply_msginfo => mi,
        inout("r10") reply_r0 => m0,
        inout("r8") reply_r1 => m1,
        inout("r9") reply_r2 => m2,
        inout("r15") reply_r3 => m3,
        in("r12") reply_cap,
        in("r13") reply_cap,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    let (executive_event, timer) = pump_handle_executive_event_badge(badge);
    if executive_event {
        if pump_deadman_tripped() {
            return PumpMessage::deadman_wall();
        }
        if ch.caps.kind == ReqKind::Irp {
            return PumpMessage::scheduler_yield();
        }
        if timer {
            if let Some(polled) = pump_try_recv_after_timer(ch, reply_cap) {
                crate::PUMP_TIMER_TICKS_ABSORBED.fetch_add(1, Ordering::Relaxed);
                return polled;
            }
            let n = crate::PUMP_TIMER_TICKS_ABSORBED.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                crate::print_str(
                    b"[pump] HPET tick landed on a component replyrecv -> deferred to the service loop (NOT a wall)\n",
                );
            }
        }
        return pump_recv(ch, reply_cap);
    }
    let m4 = if (mi & 0x7F) > 4 {
        crate::get_recv_mr(4)
    } else {
        0
    };
    PumpMessage {
        badge,
        mi,
        m0,
        m1,
        m2,
        m3,
        m4,
        scheduler_yield: false,
    }
}

/// Reply to a component `Call` that was deliberately parked outside the immediate pump
/// reply+receive step. Hosted-driver waits use this when an event/semaphore producer wakes a worker
/// that the wait service previously left blocked on its bound reply object.
pub(crate) unsafe fn pump_reply_on(
    reply_cap: u64,
    msginfo: u64,
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
) -> bool {
    let label: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") crate::SYS_CALL as u64 => _,
        inout("rdi") reply_cap => _,
        inout("rsi") msginfo => label,
        inout("r10") r0 => _,
        inout("r8") r1 => _,
        inout("r9") r2 => _,
        inout("r15") r3 => _,
        in("r12") 0u64,
        in("r13") crate::SYS_REPLY_HANDOFF_MAGIC,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    let error = label >> 12;
    if error == 0 {
        return true;
    }
    if PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed) < 8 {
        crate::print_str(b"[pump-reply] UNBOUND parked component reply cptr=");
        crate::print_u64(reply_cap);
        crate::print_str(b" label=");
        crate::print_u64(error);
        crate::print_str(b" mi=");
        crate::print_u64(msginfo);
        crate::print_str(b"\n");
    }
    false
}

/// The outcome of one pump: `(status, completed)`. `completed=true` iff the server re-parked at its
/// dispatch loop (sent `dispatch_label`); `false` = it hit a wall (fault we won't demand-map).
#[derive(Clone, Copy)]
pub(crate) struct PumpResult {
    pub status: i32,
    /// Pointer-width dispatch return. For IRP components this mirrors `status`; for win32k it is
    /// the full handler RAX, needed by NtUser/NtGdi APIs that return handles or LONG_PTR values.
    pub result: u64,
    /// The reply object the pump was using when it returned. Hosted driver worker waits can park
    /// one reply object and continue receiving on a fresh one; callers that persist the dispatch
    /// transport must retain this final active cap.
    pub reply_cap: u64,
    pub completed: bool,
    pub callback_suspended: bool,
    /// The component request is still live, but hosted scheduler work must run before its pump
    /// continues. The caller resumes with `RecvFirst` on this same reply object.
    pub scheduler_yielded: bool,
    /// Wall diagnostics (only meaningful when `!completed`).
    pub wall_ip: u64,
    pub wall_addr: u64,
    pub wall_label: u64,
    pub wall_flags: u64,
    pub wall_exception: u64,
    pub wall_code: u64,
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

#[inline(never)]
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
    // The request TAG rides in MR0, NOT in the message label. A fresh dispatch hands over
    // `dispatch_label`; the callback-RESUME pump hands over `W32_USER_CALLBACK_RESUME_LABEL` on the
    // SAME outstanding Call — which is the whole of what used to be a bespoke resume preamble.
    let request_tag = pump_request_tag(ch, resume_user_callback);
    let owns_depth = pump_enter_depth(ch, resume_user_callback);
    let mut reply_cap = ch.reply_cap;
    if ch.initial == InitialAction::RecvFirst {
        trace_component_handoff(b"pump-recvfirst-enter", ch.tcb, reply_cap, request_tag);
    }
    let first = if let Some(msg) = pump_deliver_initial_request(ch, reply_cap, request_tag) {
        msg
    } else {
        pump_recv(ch, reply_cap)
    };
    let outcome = component_pump_loop(ch, first, &mut reply_cap);
    if ch.initial == InitialAction::RecvFirst {
        let detail = if outcome.completed {
            ch.dispatch_label
        } else {
            outcome.wall_label
        };
        trace_component_handoff(b"pump-recvfirst-exit", ch.tcb, reply_cap, detail);
    }
    pump_leave_depth(owns_depth, outcome.callback_suspended);
    pump_suspend_walled_component(ch, outcome);
    pump_result_from_outcome(ch, outcome, reply_cap)
}

#[inline(never)]
fn pump_request_tag(ch: &PumpChannel, resume_user_callback: bool) -> u64 {
    if resume_user_callback {
        crate::win32k_subsystem::W32_USER_CALLBACK_RESUME_LABEL
    } else {
        ch.dispatch_label
    }
}

#[inline(never)]
fn pump_enter_depth(ch: &PumpChannel, resume_user_callback: bool) -> bool {
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
    owns_depth
}

#[inline(never)]
unsafe fn pump_deliver_initial_request(
    ch: &PumpChannel,
    reply_cap: u64,
    request_tag: u64,
) -> Option<PumpMessage> {
    // ★ ONE composite reply+receive hands over the request. `RecvFirst` means the component has not
    // yet issued the Call we would be answering (mid-DriverEntry), so the caller performs a plain
    // receive instead.
    if ch.initial != InitialAction::ReplyRequest {
        return None;
    }
    PUMP_CALL_REQUESTS[ch.caps.kind as usize].fetch_add(1, Ordering::Relaxed);
    Some(pump_reply_recv(ch, reply_cap, REQUEST_TAG_LEN, request_tag))
}

#[inline(never)]
unsafe fn component_pump_loop(
    ch: &PumpChannel,
    first: PumpMessage,
    reply_cap: &mut u64,
) -> PumpLoopOutcome {
    let mut msg = first;
    let mut outcome = PumpLoopOutcome::new();
    let mut skips = 0u64; // win32k int-0x2c asserts skipped this dispatch (bounded -> wall).
    loop {
        if msg.scheduler_yield {
            outcome.scheduler_yielded = true;
            break;
        }
        let label = msg.label();
        if label == ch.dispatch_label {
            // ★ There is nothing to check. This message is the return half of the component's OWN
            // `Call`, the kernel bound our reply object to that exact caller when it paired, and the
            // component could not have spoken at all without first being replied to. A stale or
            // misdirected completion is UNREPRESENTABLE — which is why the sequence handshake and
            // the per-dispatch token stack are gone.
            PUMP_CALL_DISPATCHES[ch.caps.kind as usize].fetch_add(1, Ordering::Relaxed);
            outcome.completed = true;
            break;
        } else if label == crate::win32k_subsystem::W32_USER_CALLBACK_LABEL
            && ch.caps.usermode_callback
        {
            let disposition = pump_service_user_callback(ch);
            let Some(disposition) = disposition else {
                outcome.wall(msg);
                break;
            };
            if disposition == crate::win32k_glue::UserCallbackDisposition::SuspendComponent {
                // ★ THE SUSPENSION IS A NON-REPLY. We simply RETURN without answering, so `R` stays
                // BOUND to the component's callback `Call` for the whole callback excursion (client
                // redirect → arbitrarily deep nested dispatches → `NtCallbackReturn`). That kernel
                // binding IS the "suspended outer dispatch" state; we keep none of our own.
                outcome.callback_suspended = true;
                break;
            }
            // Answer the callback in place: the RESUME tag on the component's outstanding Call.
            pump_reply_recv_into!(
                ch,
                *reply_cap,
                msg,
                REQUEST_TAG_LEN,
                crate::win32k_subsystem::W32_USER_CALLBACK_RESUME_LABEL
            );
            continue;
        } else if label == crate::win32k_subsystem::W32_GDI_LOAD_LABEL
            && ch.caps.kind == ReqKind::Syscall
        {
            let status = pump_service_gdi_driver_load();
            pump_reply_recv_into!(ch, *reply_cap, msg, REQUEST_TAG_LEN, status as u32 as u64);
            continue;
        } else if label == crate::win32k_subsystem::W32_VIDEO_IOCTL_LABEL
            && ch.caps.kind == ReqKind::Syscall
        {
            let status = pump_service_video_device_io_control();
            pump_reply_recv_into!(ch, *reply_cap, msg, REQUEST_TAG_LEN, status as u64);
            continue;
        } else if label == crate::win32k_subsystem::W32_LPC_LABEL
            && ch.caps.kind == ReqKind::Syscall
        {
            let status = pump_service_lpc_request();
            pump_reply_recv_into!(ch, *reply_cap, msg, REQUEST_TAG_LEN, status as u32 as u64);
            continue;
        } else if label == crate::win32k_subsystem::W32_REGISTRY_LABEL
            && ch.caps.kind == ReqKind::Syscall
        {
            let (status, out1, out2) =
                crate::win32k_subsystem::service_registry_request(msg.m0, msg.m1);
            pump_reply_recv4_into!(ch, *reply_cap, msg, 3, status as u32 as u64, out1, out2, 0);
            continue;
        } else if label == crate::win32k_subsystem::W32_EVENT_LABEL
            && ch.caps.kind == ReqKind::Syscall
        {
            let (status, out1, out2, out3) = unsafe {
                crate::service_sec_image::service_win32k_event_request(
                    ch.client_pi,
                    ch.client_generation,
                    msg.m0,
                    msg.m1,
                    msg.m2,
                    msg.m3,
                )
            };
            pump_reply_recv4_into!(
                ch,
                *reply_cap,
                msg,
                4,
                status as u32 as u64,
                out1,
                out2,
                out3
            );
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PS_CREATE_SYSTEM_THREAD_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let (status, handle) =
                crate::driver_launch::service_hosted_driver_ps_create_system_thread(
                    ch, msg.m0, msg.m1, msg.m2, msg.m3, msg.m4, msg.badge, *reply_cap,
                );
            pump_reply_recv4_into!(ch, *reply_cap, msg, 2, status as u32 as u64, handle, 0, 0);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PS_GET_CURRENT_THREAD_ID_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let (status, thread_id) =
                crate::driver_launch::service_hosted_driver_ps_get_current_thread_id(
                    ch, msg.badge, *reply_cap,
                );
            pump_reply_recv4_into!(
                ch,
                *reply_cap,
                msg,
                2,
                status as u32 as u64,
                thread_id,
                0,
                0
            );
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PCI_CONFIG_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let (status, transferred) = crate::driver_launch::service_hosted_driver_pci_config(
                ch, msg.m0, msg.m1, msg.m2, msg.m3, msg.badge, *reply_cap,
            );
            pump_reply_recv4_into!(
                ch,
                *reply_cap,
                msg,
                2,
                status as u32 as u64,
                transferred,
                0,
                0
            );
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_INTERRUPT_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let (status, interrupt_id) = crate::driver_launch::service_hosted_driver_interrupt(
                ch, msg.m0, msg.m1, *reply_cap,
            );
            pump_reply_recv4_into!(
                ch,
                *reply_cap,
                msg,
                2,
                status as u32 as u64,
                interrupt_id,
                0,
                0
            );
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PS_TERMINATE_SYSTEM_THREAD_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            match crate::driver_launch::service_hosted_driver_ps_terminate_system_thread(
                ch,
                msg.m0 as u32 as i32,
                msg.badge,
                *reply_cap,
            ) {
                crate::driver_launch::HostedDriverThreadTerminateServiceResult::Reply(status) => {
                    pump_reply_recv_into!(ch, *reply_cap, msg, 1, status as u32 as u64);
                }
                crate::driver_launch::HostedDriverThreadTerminateServiceResult::Terminated {
                    fresh_reply_cap,
                } => {
                    *reply_cap = fresh_reply_cap;
                    msg = pump_recv(ch, *reply_cap);
                }
            }
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_KE_SET_EVENT_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let previous = crate::driver_launch::service_hosted_driver_ke_set_event(
                ch, msg.m0, *reply_cap, msg.badge,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, previous as u32 as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_KE_SET_TIMER_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let previous = crate::driver_launch::service_hosted_driver_ke_set_timer(
                ch,
                msg.m0,
                msg.m1 as i64,
                msg.m2 as u32,
                msg.m3,
                *reply_cap,
                msg.badge,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, previous as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_KE_CANCEL_TIMER_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let previous = crate::driver_launch::service_hosted_driver_ke_cancel_timer(
                ch, msg.m0, *reply_cap, msg.badge,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, previous as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PULL_IRP_INPUT_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let status = crate::driver_launch::service_hosted_irp_input_pull(
                ch, msg.m0, msg.m1, msg.m2, *reply_cap,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, status as u32 as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PULL_IRP_OUTPUT_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let status = crate::driver_launch::service_hosted_irp_output_pull(
                ch, msg.m0, msg.m1, msg.m2, *reply_cap,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, status as u32 as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PUSH_IRP_OUTPUT_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let status = crate::driver_launch::service_hosted_irp_output_push(
                ch, msg.m0, msg.m1, msg.m2, *reply_cap,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, status as u32 as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_ROOT_PDO_PNP_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let (status, handled) = crate::driver_launch::service_hosted_root_pdo_pnp(
                ch,
                msg.m0,
                msg.m1 as u8,
                *reply_cap,
            );
            pump_reply_recv4_into!(
                ch,
                *reply_cap,
                msg,
                2,
                status as u32 as u64,
                handled as u64,
                0,
                0
            );
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_DEVICE_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let (status, required_len, transfer_token, chunk_len) =
                crate::driver_launch::service_hosted_device(
                    ch, msg.m0, msg.m1, msg.m2, msg.m3, *reply_cap,
                );
            pump_reply_recv4_into!(
                ch,
                *reply_cap,
                msg,
                4,
                status as u32 as u64,
                required_len,
                transfer_token,
                chunk_len
            );
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_KE_PULSE_EVENT_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let previous = crate::driver_launch::service_hosted_driver_ke_pulse_event(
                ch, msg.m0, *reply_cap, msg.badge,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, previous as u32 as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_KE_RELEASE_SEMAPHORE_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let previous = crate::driver_launch::service_hosted_driver_ke_release_semaphore(
                ch,
                msg.m0,
                msg.m1 as u32 as i32,
                *reply_cap,
                msg.badge,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, previous as u32 as u64);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_KE_WAIT_SINGLE_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            match crate::driver_launch::service_hosted_driver_ke_wait_single(
                ch, msg.m0, msg.m1, msg.m2, msg.m3, msg.badge, *reply_cap,
            ) {
                crate::driver_launch::HostedDriverWaitServiceResult::Reply(status) => {
                    pump_reply_recv_into!(ch, *reply_cap, msg, 1, status as u32 as u64);
                }
                crate::driver_launch::HostedDriverWaitServiceResult::Parked { fresh_reply_cap } => {
                    *reply_cap = fresh_reply_cap;
                    msg = pump_recv(ch, *reply_cap);
                }
            }
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_KE_WAIT_MULTIPLE_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            match crate::driver_launch::service_hosted_driver_ke_wait_multiple(
                ch,
                msg.m0,
                msg.m1 as u32,
                msg.m2,
                msg.m3,
                msg.badge,
                *reply_cap,
            ) {
                crate::driver_launch::HostedDriverWaitServiceResult::Reply(status) => {
                    pump_reply_recv_into!(ch, *reply_cap, msg, 1, status as u32 as u64);
                }
                crate::driver_launch::HostedDriverWaitServiceResult::Parked { fresh_reply_cap } => {
                    *reply_cap = fresh_reply_cap;
                    msg = pump_recv(ch, *reply_cap);
                }
            }
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_REGISTRY_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let (status, out1, out2) = crate::driver_launch::service_hosted_driver_registry(
                ch, msg.m0, msg.m1, msg.m2, msg.m3, msg.badge, *reply_cap,
            );
            pump_reply_recv4_into!(ch, *reply_cap, msg, 3, status as u32 as u64, out1, out2, 0);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PROVIDER_EXPORT_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let result = crate::driver_launch::service_hosted_provider_export(
                ch, msg.m0, msg.m1, msg.m2, msg.m3,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, result);
            continue;
        } else if label == crate::driver_launch::FSD_SERVICE_PROVIDER_CALLBACK_LABEL
            && ch.caps.kind == ReqKind::Irp
        {
            let result = crate::driver_launch::service_hosted_provider_callback(
                ch, msg.m0, msg.m1, msg.m2, msg.m3,
            );
            pump_reply_recv_into!(ch, *reply_cap, msg, 1, result);
            continue;
        } else if label == 6 {
            outcome.faults += 1;
            if !pump_service_vm_fault(
                ch,
                label,
                msg.m0,
                msg.m1,
                msg.m3,
                outcome.faults,
                outcome.demand,
            ) {
                outcome.wall(msg);
                break;
            }
            outcome.demand += 1;
            // Resume the server + recv the next fault/DONE with one composite reply+receive. A
            // VMFault reply is restarted unconditionally (`fault.rs`), and the receive half
            // re-registers `R`. A nested demand fault therefore rides the SAME reply object as the
            // dispatch it happened inside, which is exactly Fix B's guarantee (the outer client's
            // REPLY_MAIN binding is untouched) with no second transport to keep gated.
            pump_reply_recv_into!(ch, *reply_cap, msg, 0, 0);
            continue;
        } else if label == 3 && ch.caps.io_port_faults {
            if let Some(next_ip) = pump_service_io_port_fault(ch, msg.m0, msg.m3) {
                pump_reply_recv_into!(ch, *reply_cap, msg, 1, next_ip);
                continue;
            }
            outcome.wall(msg);
            break;
        } else if label == 3 && ch.caps.assert_skip {
            // ── win32k checked-build int-0x2c ASSERT-SKIP (relocated VERBATIM). Verify CD 2C via the
            // executive's RW view of win32k's image at the same VA, then resume at IP+2 (release-build
            // semantics). Bounded by W32_ASSERT_SKIP_BOUND (a looping assert still walls).
            // Gated on `caps.assert_skip` (win32k only) — NOT on `reply_cap != 0`, which is now
            // mandatory on every channel and would silently widen this arm to the FSD (risk R10).
            let code_va = core::ptr::read_volatile(core::ptr::addr_of!(ch.code_va));
            let image_frames = core::ptr::read_volatile(core::ptr::addr_of!(ch.image_frames));
            let in_win32k = msg.m0 >= code_va && msg.m0 < code_va + image_frames * 0x1000;
            let is_int2c = in_win32k
                && core::ptr::read_volatile(msg.m0 as *const u8) == 0xCD
                && core::ptr::read_volatile((msg.m0 + 1) as *const u8) == 0x2C;
            if is_int2c && skips < W32_ASSERT_SKIP_BOUND {
                if crate::DEBUG_TRACE && crate::W32_ASSERT_LOG.fetch_add(1, Ordering::Relaxed) < 40
                {
                    crate::print_str(b"[w32disp] skip int 0x2c assert @ RVA 0x");
                    crate::print_hex(msg.m0.wrapping_sub(code_va) as u32);
                    crate::print_str(b"\n");
                }
                skips += 1;
                // UserException(3) reply: len 1, MR0 = the resume FaultIP (past `CD 2C`). This is
                // the ONLY non-zero-length reply the component pump ever emits (risk R4).
                pump_reply_recv_into!(ch, *reply_cap, msg, 1, msg.m0 + 2);
                continue;
            }
            // Not a skippable int-0x2c — fall through to the wall.
            if ch.caps.client_attach {
                win32k_wall_diag(ch, label, msg.m0, msg.m1, msg.m2, msg.m3);
                crate::win32k_glue::win32k_dispatch_backtrace();
            }
            outcome.wall(msg);
            break;
        } else {
            // Any other fault — a real wall inside the handler.
            if ch.caps.client_attach {
                win32k_wall_diag(ch, label, msg.m0, msg.m1, msg.m2, msg.m3);
                crate::win32k_glue::win32k_dispatch_backtrace();
            }
            outcome.wall(msg);
            break;
        }
    }
    outcome
}

#[inline(never)]
unsafe fn pump_service_user_callback(
    ch: &PumpChannel,
) -> Option<crate::win32k_glue::UserCallbackDisposition> {
    let _ = ch;
    crate::win32k_glue::service_user_callback()
}

#[inline(never)]
unsafe fn pump_service_gdi_driver_load() -> i32 {
    crate::win32k_glue::service_gdi_driver_load()
}

#[inline(never)]
unsafe fn pump_service_video_device_io_control() -> u32 {
    crate::win32k_subsystem::service_video_device_io_control()
}

#[inline(never)]
unsafe fn pump_service_lpc_request() -> i32 {
    crate::win32k_subsystem::service_lpc_request()
}

#[inline(never)]
unsafe fn pump_service_vm_fault(
    ch: &PumpChannel,
    label: u64,
    ip: u64,
    addr: u64,
    fsr: u64,
    faults: u64,
    demand: u64,
) -> bool {
    if pump_addr_in_root_image(addr) {
        return pump_map_root_image_page(ch, ip, addr, fsr, demand);
    }
    let in_image =
        ch.image_frames != 0 && addr >= ch.code_va && addr < ch.code_va + ch.image_frames * 0x1000;
    if ch.caps.client_attach {
        pump_service_win32k_fault(ch, ip, addr, fsr, in_image, demand)
    } else {
        pump_service_generic_fault(ch, label, ip, addr, in_image, faults, demand)
    }
}

#[inline]
fn pump_addr_in_root_image(addr: u64) -> bool {
    let image_frames = crate::IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    image_frames != 0
        && addr >= crate::IMAGE_BASE
        && addr < crate::IMAGE_BASE + image_frames * 0x1000
}

#[inline(never)]
unsafe fn pump_map_root_image_page(
    ch: &PumpChannel,
    ip: u64,
    addr: u64,
    fsr: u64,
    demand: u64,
) -> bool {
    let page = addr & !0xFFF;
    let image_start = crate::IMAGE_FRAMES_START.load(Ordering::Relaxed);
    let image_frames = crate::IMAGE_FRAMES_COUNT.load(Ordering::Relaxed);
    if image_start == 0 || image_frames == 0 || page < crate::IMAGE_BASE {
        return false;
    }
    let index = (page - crate::IMAGE_BASE) / 0x1000;
    if index >= image_frames || ch.root_image_map_owner == 0 {
        return false;
    }
    let rights = if ch.root_image_rights == 0 {
        crate::RO_NX
    } else {
        ch.root_image_rights
    };
    let (cap, copy_error) = crate::copy_cap_r(image_start + index);
    if copy_error != 0 {
        crate::print_str(b"[component-image-fault] copy failed index=");
        crate::print_u64(index);
        crate::print_str(b" source=0x");
        crate::print_hex((image_start + index) as u32);
        crate::print_str(b" error=");
        crate::print_u64(copy_error);
        crate::print_str(b"\n");
        return false;
    }
    let map = crate::page_map_r(cap, page, rights, ch.pml4);
    if map == 0 {
        if !component_map_cap_bank_tag(ch.root_image_map_owner, cap) {
            crate::print_str(b"[component-image-fault] owner tag failed cap=0x");
            crate::print_hex(cap as u32);
            crate::print_str(b" owner=");
            crate::print_u64(ch.root_image_map_owner as u64);
            crate::print_str(b"\n");
            let _ = crate::cnode_delete_recycle_r(cap);
            return false;
        }
        let trace = COMPONENT_ROOT_IMAGE_DEMAND_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
        if trace < COMPONENT_ROOT_IMAGE_DEMAND_TRACE_CAP {
            crate::print_str(b"[component-image-fault] mapped index=");
            crate::print_u64(index);
            crate::print_str(b" page=0x");
            crate::print_hex((page >> 32) as u32);
            crate::print_hex(page as u32);
            crate::print_str(b" ip=0x");
            crate::print_hex((ip >> 32) as u32);
            crate::print_hex(ip as u32);
            crate::print_str(b" fsr=0x");
            crate::print_hex(fsr as u32);
            crate::print_str(b" demand=");
            crate::print_u64(demand);
            crate::print_str(b"\n");
        }
        return true;
    }
    crate::print_str(b"[component-image-fault] map failed index=");
    crate::print_u64(index);
    crate::print_str(b" page=0x");
    crate::print_hex((page >> 32) as u32);
    crate::print_hex(page as u32);
    crate::print_str(b" error=");
    crate::print_u64(map);
    crate::print_str(b"\n");
    let _ = crate::cnode_delete_recycle_r(cap);
    false
}

#[inline(never)]
unsafe fn pump_service_win32k_fault(
    ch: &PumpChannel,
    ip: u64,
    addr: u64,
    fsr: u64,
    in_image: bool,
    demand: u64,
) -> bool {
    // win32k demand-fault CLIENT-FRAME-SHARING (relocated from `win32k_dispatch_wide`).
    let page = addr & !0xFFF;
    let foreign = addr < 0x0000_0100_0000_0000
        || (addr >= 0x10000 && !in_image && crate::csrss_frame_get(ch.client_pi, page) != 0);
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
        return false;
    }
    // The client TEB tail is read-only to win32k; service writes with a private COW shadow.
    if crate::W32_CLIENT_TEB_TAIL_PROTECTED
        && (fsr & 0x2) != 0
        && crate::win32k_glue::w32_attach_mapped(page)
        && crate::is_teb_tail_page(page)
    {
        if crate::win32k_glue::w32_teb_tail_cow(page, ch.client_pi, ch.pml4, ip) {
            return true;
        }
        crate::win32k_glue::win32k_dispatch_backtrace();
        return false;
    }
    if foreign {
        pump_service_win32k_foreign_fault(ch, page, demand)
    } else {
        pump_map_win32k_private_page(ch, page)
    }
}

#[inline(never)]
unsafe fn pump_service_win32k_foreign_fault(ch: &PumpChannel, page: u64, demand: u64) -> bool {
    if crate::win32k_glue::map_csrss_page_into_win32k(page, ch.client_pi, ch.pml4) {
        return true;
    }
    let win32k_internal_low = page < 0x0000_0100_0000_0000 && page >= 0x10000;
    if win32k_internal_low {
        if crate::DEBUG_TRACE && demand < W32_FAULT_LOG_LIMIT {
            crate::print_str(b"[w32disp] win32k-internal unbacked low VA 0x");
            crate::print_hex((page >> 32) as u32);
            crate::print_hex(page as u32);
            crate::print_str(b" -> zero-fill (blit source buffer)\n");
        }
        return pump_map_win32k_private_page(ch, page);
    }
    crate::print_str(b"[w32disp] map_csrss_page_into_win32k FALSE page=0x");
    crate::print_hex((page >> 32) as u32);
    crate::print_hex(page as u32);
    crate::print_str(b" client_pi=");
    crate::print_u64(ch.client_pi);
    crate::print_str(b"\n");
    crate::win32k_glue::win32k_dispatch_backtrace();
    false
}

#[inline(never)]
unsafe fn pump_map_win32k_private_page(ch: &PumpChannel, page: u64) -> bool {
    if !crate::win32k_glue::ensure_w32_client_paging(page, ch.pml4) {
        crate::win32k_glue::win32k_dispatch_backtrace();
        return false;
    }
    let f = crate::alloc_frame();
    let map = crate::page_map_r(f, page, crate::RW_NX, ch.pml4);
    if map == 0 {
        return true;
    }
    crate::print_str(b"[w32disp] private map failed page=0x");
    crate::print_hex((page >> 32) as u32);
    crate::print_hex(page as u32);
    crate::print_str(b" error=");
    crate::print_u64(map);
    crate::print_str(b"\n");
    let _ = crate::cnode_delete_recycle_r(f);
    crate::win32k_glue::win32k_dispatch_backtrace();
    false
}

#[inline(never)]
unsafe fn pump_service_generic_fault(
    ch: &PumpChannel,
    _label: u64,
    ip: u64,
    addr: u64,
    in_image: bool,
    faults: u64,
    demand: u64,
) -> bool {
    // FSD / generic demand-map (byte-identical to the old inline loop).
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
        return false;
    }
    if crate::driver_launch::hosted_published_dma_aperture_contains(ch.pml4, addr) {
        crate::print_str(b"[svc] refusing private page in published DMA aperture addr=0x");
        crate::print_hex((addr >> 32) as u32);
        crate::print_hex(addr as u32);
        crate::print_str(b" pml4=0x");
        crate::print_hex(ch.pml4 as u32);
        crate::print_str(b"\n");
        return false;
    }
    let page = addr & !0xFFF;
    if ch.caps.sparse_vspace {
        if !crate::win32k_glue::ensure_w32_client_paging(page, ch.pml4) {
            return false;
        }
    } else {
        let Some(domain) = crate::driver_launch::hosted_domain_identity_for_pml4(ch.pml4) else {
            return false;
        };
        if !crate::driver_launch::ensure_paging(page, ch.pml4, domain) {
            return false;
        }
    }
    let f = crate::alloc_frame();
    let map = crate::page_map_r(f, page, crate::RW_NX, ch.pml4);
    if map == 0 {
        return true;
    }
    crate::print_str(b"[svc] private map failed page=0x");
    crate::print_hex((page >> 32) as u32);
    crate::print_hex(page as u32);
    crate::print_str(b" error=");
    crate::print_u64(map);
    crate::print_str(b"\n");
    let _ = crate::cnode_delete_recycle_r(f);
    false
}

#[inline(never)]
unsafe fn pump_service_io_port_fault(
    ch: &PumpChannel,
    fault_ip: u64,
    exception_number: u64,
) -> Option<u64> {
    const X86_GP_EXCEPTION: u64 = 13;

    if exception_number != X86_GP_EXCEPTION || ch.tcb == 0 {
        return None;
    }

    let sh = ch.shared_va;
    let (component_code_va, image_frames) = if ch.code_va != 0 && ch.image_frames != 0 {
        (ch.code_va, ch.image_frames)
    } else if ch.caps.kind == ReqKind::Irp {
        (
            crate::driver_launch::FSD_CODE_VA,
            crate::driver_launch::FSD_IMAGE_FRAMES,
        )
    } else {
        return None;
    };
    let image_len = image_frames.checked_mul(0x1000)?;
    let (exec_ip, exec_limit) =
        if fault_ip >= component_code_va && fault_ip < component_code_va.checked_add(image_len)? {
            if ch.exec_code_va == 0 {
                return None;
            }
            let offset = fault_ip - component_code_va;
            (
                ch.exec_code_va.checked_add(offset)?,
                ch.exec_code_va.checked_add(image_len)?,
            )
        } else {
            let executive_len = crate::IMAGE_FRAMES_COUNT
                .load(Ordering::Relaxed)
                .checked_mul(0x1000)?;
            if fault_ip < crate::IMAGE_BASE
                || fault_ip >= crate::IMAGE_BASE.checked_add(executive_len)?
            {
                return None;
            }
            (fault_ip, crate::IMAGE_BASE.checked_add(executive_len)?)
        };
    let available = usize::try_from(exec_limit.checked_sub(exec_ip)?)
        .ok()?
        .min(4);
    let mut instruction_bytes = [0u8; 4];
    for (index, byte) in instruction_bytes[..available].iter_mut().enumerate() {
        *byte = core::ptr::read_volatile((exec_ip + index as u64) as *const u8);
    }
    let Some(instruction) =
        nt_kernel_exec::x86_io::decode_port_io_instruction(&instruction_bytes[..available])
    else {
        let count = HOSTED_IO_PORT_UNHANDLED_GPS.fetch_add(1, Ordering::Relaxed);
        if count < 8 {
            crate::print_str(b"[pump] unhandled IOPort GP ip=0x");
            crate::print_hex((fault_ip >> 32) as u32);
            crate::print_hex(fault_ip as u32);
            crate::print_str(b" exec=0x");
            crate::print_hex((exec_ip >> 32) as u32);
            crate::print_hex(exec_ip as u32);
            crate::print_str(b" bytes=0x");
            crate::print_hex(
                ((instruction_bytes[0] as u32) << 24)
                    | ((instruction_bytes[1] as u32) << 16)
                    | ((instruction_bytes[2] as u32) << 8)
                    | instruction_bytes[3] as u32,
            );
            crate::print_str(b"\n");
        }
        return None;
    };
    let is_in = instruction.direction == nt_kernel_exec::x86_io::PortIoDirection::Read;
    let bits = instruction.width_bits;
    let insn_len = instruction.len as u64;

    let mut regs = [0u64; 20];
    crate::win32k_glue::tcb_read_regs20(ch.tcb, &mut regs);
    let port = match instruction.port {
        nt_kernel_exec::x86_io::PortIoPort::Dx => (regs[6] & 0xFFFF) as u16,
        nt_kernel_exec::x86_io::PortIoPort::Immediate(port) => port as u16,
    };
    let grant = crate::driver_launch::hosted_io_port_fault_grant(sh, port)?;
    let port_cap = grant.cap;
    let port_base = grant.base;
    let port_len = grant.len;
    let port_u64 = port as u64;
    let width = u64::from(bits) / 8;
    let grant_end = port_base.checked_add(port_len)?;
    let Some(access_end) = port_u64.checked_add(width) else {
        return None;
    };
    if width == 0 || port_u64 < port_base || access_end > grant_end {
        if bits == 16 {
            let offset = if is_in {
                crate::driver_launch::SH_RESOURCE_IO_PORT_IN16_DENIED
            } else {
                crate::driver_launch::SH_RESOURCE_IO_PORT_OUT16_DENIED
            };
            let local = core::ptr::read_volatile((sh + offset) as *const u64);
            core::ptr::write_volatile((sh + offset) as *mut u64, local.saturating_add(1));
        }
        return None;
    }

    if bits == 8 {
        if is_in {
            let (value, io) = crate::io_in8_r(port_cap, port);
            if io != 0 {
                crate::print_str(b"[pump] IOPortIn8 failed label=");
                crate::print_u64(io);
                crate::print_str(b" port=0x");
                crate::print_hex(port as u32);
                crate::print_str(b"\n");
                return None;
            }
            regs[3] = (regs[3] & !0xFF) | value as u64;
            if crate::win32k_glue::tcb_write_regs20(ch.tcb, &regs, false) != 0 {
                return None;
            }
        } else {
            let value = regs[3] as u8;
            let io = crate::io_out8(port_cap, port, value);
            if io != 0 {
                crate::print_str(b"[pump] IOPortOut8 failed label=");
                crate::print_u64(io);
                crate::print_str(b" port=0x");
                crate::print_hex(port as u32);
                crate::print_str(b" value=0x");
                crate::print_hex(value as u32);
                crate::print_str(b"\n");
                return None;
            }
        }
    } else if bits == 16 {
        let call_offset = if is_in {
            crate::driver_launch::SH_RESOURCE_IO_PORT_IN16_CALLS
        } else {
            crate::driver_launch::SH_RESOURCE_IO_PORT_OUT16_CALLS
        };
        let calls = core::ptr::read_volatile((sh + call_offset) as *const u64);
        core::ptr::write_volatile((sh + call_offset) as *mut u64, calls.saturating_add(1));
        if is_in {
            core::ptr::write_volatile(
                (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_LAST_IN16_PORT) as *mut u64,
                port as u64,
            );
            let (value, io) = crate::io_in16_r(port_cap, port);
            core::ptr::write_volatile(
                (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_LAST_IN16_STATUS) as *mut u64,
                io,
            );
            core::ptr::write_volatile(
                (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_LAST_IN16_VALUE) as *mut u64,
                value as u64,
            );
            if io != 0 {
                let failures = core::ptr::read_volatile(
                    (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_IN16_FAILURES) as *const u64,
                )
                .saturating_add(1);
                core::ptr::write_volatile(
                    (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_IN16_FAILURES) as *mut u64,
                    failures,
                );
                crate::print_str(b"[pump] IOPortIn16 failed label=");
                crate::print_u64(io);
                crate::print_str(b" port=0x");
                crate::print_hex(port as u32);
                crate::print_str(b"\n");
                return None;
            }
            regs[3] = (regs[3] & !0xFFFF) | value as u64;
            if crate::win32k_glue::tcb_write_regs20(ch.tcb, &regs, false) != 0 {
                return None;
            }
        } else {
            let value = regs[3] as u16;
            core::ptr::write_volatile(
                (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_LAST_OUT16_PORT) as *mut u64,
                port as u64,
            );
            core::ptr::write_volatile(
                (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_LAST_OUT16_VALUE) as *mut u64,
                value as u64,
            );
            let io = crate::io_out16(port_cap, port, value);
            core::ptr::write_volatile(
                (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_LAST_OUT16_STATUS) as *mut u64,
                io,
            );
            if io != 0 {
                let failures = core::ptr::read_volatile(
                    (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_OUT16_FAILURES) as *const u64,
                )
                .saturating_add(1);
                core::ptr::write_volatile(
                    (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_OUT16_FAILURES) as *mut u64,
                    failures,
                );
                crate::print_str(b"[pump] IOPortOut16 failed label=");
                crate::print_u64(io);
                crate::print_str(b" port=0x");
                crate::print_hex(port as u32);
                crate::print_str(b" value=0x");
                crate::print_hex(value as u32);
                crate::print_str(b"\n");
                return None;
            }
        }
    } else if is_in {
        let (raw_value, io) = crate::io_in32_r(port_cap, port);
        if io != 0 {
            crate::print_str(b"[pump] IOPortIn32 failed label=");
            crate::print_u64(io);
            crate::print_str(b" port=0x");
            crate::print_hex(port as u32);
            crate::print_str(b"\n");
            return None;
        }
        regs[3] = (regs[3] & !0xFFFF_FFFFu64) | raw_value as u64;
        if crate::win32k_glue::tcb_write_regs20(ch.tcb, &regs, false) != 0 {
            return None;
        }
    } else {
        let value = regs[3] as u32;
        let io = crate::io_out32(port_cap, port, value);
        if io != 0 {
            crate::print_str(b"[pump] IOPortOut32 failed label=");
            crate::print_u64(io);
            crate::print_str(b" port=0x");
            crate::print_hex(port as u32);
            crate::print_str(b"\n");
            return None;
        }
        let local = core::ptr::read_volatile(
            (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_OUT32_FAULTS) as *const u64,
        );
        core::ptr::write_volatile(
            (sh + crate::driver_launch::SH_RESOURCE_IO_PORT_OUT32_FAULTS) as *mut u64,
            local.saturating_add(1),
        );
        let global = HOSTED_IO_PORT_OUT32_FAULTS.fetch_add(1, Ordering::Relaxed);
        if crate::DEBUG_TRACE && global < 16 {
            crate::print_str(b"[pump] serviced IOPortOut32 port=0x");
            crate::print_hex(port as u32);
            crate::print_str(b" value=0x");
            crate::print_hex(value);
            crate::print_str(b" ip=0x");
            crate::print_hex(fault_ip as u32);
            crate::print_str(b"\n");
        }
    }
    crate::driver_launch::refresh_hosted_resource_state_for_shared(sh);
    Some(fault_ip + insn_len)
}

#[inline(never)]
fn pump_leave_depth(owns_depth: bool, callback_suspended: bool) {
    // Retire this level from the depth GAUGE unless it is now suspended inside a usermode callback
    // (in which case it stays outstanding until a resume pump completes it). Observability only.
    if owns_depth {
        if callback_suspended {
            SUSPENDED_COMPONENT_OUTSTANDING.fetch_add(1, Ordering::Relaxed);
        } else {
            dispatch_depth_leave();
        }
    }
}

#[inline(never)]
unsafe fn pump_suspend_walled_component(ch: &PumpChannel, outcome: PumpLoopOutcome) {
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
    if !outcome.completed && !outcome.callback_suspended && !outcome.scheduler_yielded {
        PUMP_WALL_SUSPENDS.fetch_add(1, Ordering::Relaxed);
        pump_wall_state_diag(ch, outcome);
        let e = if ch.tcb != 0 {
            crate::tcb_suspend_r(ch.tcb)
        } else {
            0xFFFF
        };
        crate::print_str(b"[pump] WALL label=");
        crate::print_u64(outcome.wall_label);
        crate::print_str(b" ip=0x");
        crate::print_hex((outcome.wall_ip >> 32) as u32);
        crate::print_hex(outcome.wall_ip as u32);
        crate::print_str(b" addr=0x");
        crate::print_hex((outcome.wall_addr >> 32) as u32);
        crate::print_hex(outcome.wall_addr as u32);
        if outcome.wall_label == 3 {
            crate::print_str(b" exc#=");
            crate::print_u64(outcome.wall_exception);
            crate::print_str(b" code=0x");
            crate::print_hex((outcome.wall_code >> 32) as u32);
            crate::print_hex(outcome.wall_code as u32);
            crate::print_str(b" flags=0x");
            crate::print_hex(outcome.wall_flags as u32);
        }
        crate::print_str(b" -> TCB_Suspend(component) e=");
        crate::print_u64(e);
        crate::print_str(
            b" (its reply object stays bound to a thread that will never run again)\n",
        );
    }
}

#[inline(never)]
unsafe fn pump_result_from_outcome(
    ch: &PumpChannel,
    outcome: PumpLoopOutcome,
    reply_cap: u64,
) -> PumpResult {
    let (status, result) = if outcome.completed {
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
    } else if outcome.callback_suspended || outcome.scheduler_yielded {
        let status = nt_user_callback::STATUS_PENDING;
        (status, status as u32 as u64)
    } else {
        let status = 0xC000_0001u32 as i32; // STATUS_UNSUCCESSFUL
        (status, status as u32 as u64)
    };
    PumpResult {
        status,
        result,
        reply_cap,
        completed: outcome.completed,
        callback_suspended: outcome.callback_suspended,
        scheduler_yielded: outcome.scheduler_yielded,
        wall_ip: outcome.wall_ip,
        wall_addr: outcome.wall_addr,
        wall_label: outcome.wall_label,
        wall_flags: outcome.wall_flags,
        wall_exception: outcome.wall_exception,
        wall_code: outcome.wall_code,
        faults: outcome.faults,
        demand: outcome.demand,
    }
}

/// The DRIVER_OBJECT byte layout a component's `DriverEntry` expects. `component_main` builds a
/// zeroed DRIVER_OBJECT of `size` with Type=4 @0, Size @2, a DriverExtension pointer at the NT x64
/// offset, a zero DriverUnload slot, and MajorFunction @`mj`. WDM hosts may also seed every major
/// function slot with the I/O manager's default invalid-device-request dispatch before DriverEntry.
#[derive(Clone, Copy)]
pub(crate) struct DriverObjectSpec {
    /// The DRIVER_OBJECT allocation size (bytes reserved from `pool`).
    pub size: u64,
    /// The value written into the DRIVER_OBJECT `Size` field @2. USUALLY == `size` (FSD), but win32k
    /// allocates 0x200 yet stamps Size=336 (0x150) — so this is a distinct field to preserve that.
    pub size_field: u16,
    /// Shared-frame field that publishes the component-local DRIVER_OBJECT before DriverEntry.
    /// Use `u64::MAX` when the hosted personality does not expose that identity in its frame.
    pub driver_object_off: u64,
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
    /// Optional shared-frame offset containing a support image `DriverEntry` RVA relative to
    /// `code_va`. `u64::MAX` disables support-driver initialization for hosted kinds that do not use
    /// dependency images.
    pub support_entry_rva_off: u64,
    /// Optional shared-frame offset containing the number of support records to initialize.
    pub support_count_off: u64,
    /// Optional shared-frame offset containing support records. Each record is
    /// `[entry_rva: u64, status: i32, verdict: u32]`.
    pub support_records_off: u64,
    /// Maximum support records available at `support_records_off`.
    pub support_record_capacity: u64,
    /// Bytes between support records.
    pub support_record_size: u64,
    /// Optional shared-frame offset receiving the support image `DriverEntry` status.
    pub support_status_off: u64,
    /// Optional shared-frame offset receiving support image verdict bits.
    pub support_verdict_off: u64,
    /// Component-local WDM default dispatch pointer for unclaimed MajorFunction slots. `0` leaves the
    /// table zeroed for hosts that do not expose WDM majors, such as win32k's syscall server.
    pub default_major_function: u64,
}

/// One dispatched request handed to the component-side `dispatch` callback. For the FSD, `sel` is
/// the IRP major function; the router does `major → MajorFunction[major] → run_irp`.
#[derive(Clone, Copy)]
pub(crate) struct DispatchReq {
    /// The dispatch selector: IRP major (Irp) or SSN (Syscall).
    pub sel: u64,
    pub drv: u64,
}

const STATUS_INVALID_PARAMETER_I32: i32 = 0xC000_000D_u32 as i32;

unsafe fn component_support_count(
    shared_va: u64,
    spec: DriverObjectSpec,
    legacy_entry_rva: u64,
) -> u64 {
    if spec.support_count_off == u64::MAX {
        if legacy_entry_rva == 0 {
            0
        } else {
            1
        }
    } else {
        core::ptr::read_volatile((shared_va + spec.support_count_off) as *const u32) as u64
    }
}

unsafe fn component_support_record_offsets(
    spec: DriverObjectSpec,
    index: u64,
) -> Option<(u64, u64, u64)> {
    if spec.support_records_off != u64::MAX
        && spec.support_record_size >= 0x10
        && index < spec.support_record_capacity
    {
        let record = spec.support_records_off + index * spec.support_record_size;
        return Some((record, record + 0x08, record + 0x0C));
    }
    if index == 0
        && spec.support_entry_rva_off != u64::MAX
        && spec.support_status_off != u64::MAX
        && spec.support_verdict_off != u64::MAX
    {
        return Some((
            spec.support_entry_rva_off,
            spec.support_status_off,
            spec.support_verdict_off,
        ));
    }
    None
}

unsafe fn component_write_support_aggregate(
    shared_va: u64,
    spec: DriverObjectSpec,
    status: i32,
    verdict: u32,
) {
    if spec.support_status_off != u64::MAX {
        core::ptr::write_volatile((shared_va + spec.support_status_off) as *mut i32, status);
    }
    if spec.support_verdict_off != u64::MAX {
        core::ptr::write_volatile((shared_va + spec.support_verdict_off) as *mut u32, verdict);
    }
}

unsafe fn component_run_support_entries(
    shared_va: u64,
    code_va: u64,
    spec: DriverObjectSpec,
    legacy_entry_rva: u64,
) -> i32 {
    let support_count = component_support_count(shared_va, spec, legacy_entry_rva);
    if support_count == 0 {
        component_write_support_aggregate(shared_va, spec, 0, 0);
        return 0;
    }
    if spec.support_record_capacity != 0 && support_count > spec.support_record_capacity {
        component_write_support_aggregate(
            shared_va,
            spec,
            STATUS_INVALID_PARAMETER_I32,
            crate::driver_launch::V_ENTERED,
        );
        return STATUS_INVALID_PARAMETER_I32;
    }

    let mut aggregate_verdict = 0u32;
    let mut aggregate_status = 0i32;
    let mut index = 0u64;
    while index < support_count {
        let Some((entry_rva_off, status_off, verdict_off)) =
            component_support_record_offsets(spec, index)
        else {
            aggregate_status = STATUS_INVALID_PARAMETER_I32;
            break;
        };
        let entry_rva = if spec.support_records_off == u64::MAX {
            legacy_entry_rva
        } else {
            core::ptr::read_volatile((shared_va + entry_rva_off) as *const u64)
        };
        if entry_rva == 0 {
            aggregate_status = STATUS_INVALID_PARAMETER_I32;
            break;
        }

        let verdict_va = shared_va + verdict_off;
        let status_va = shared_va + status_off;
        let mut verdict = crate::driver_launch::V_ENTERED;
        aggregate_verdict |= crate::driver_launch::V_ENTERED;
        core::ptr::write_volatile(verdict_va as *mut u32, verdict);

        let (support_drv, support_reg_path) = component_driver_entry_context(spec);
        let support_entry = code_va + entry_rva;
        let support_de: extern "win64" fn(u64, u64) -> i32 =
            core::mem::transmute(support_entry as *const ());
        aggregate_status = support_de(support_drv, support_reg_path);
        core::ptr::write_volatile(status_va as *mut i32, aggregate_status);
        verdict |= crate::driver_launch::V_RETURNED;
        aggregate_verdict |= crate::driver_launch::V_RETURNED;
        if aggregate_status == 0 {
            verdict |= crate::driver_launch::V_SUCCESS;
        }
        core::ptr::write_volatile(verdict_va as *mut u32, verdict);
        if aggregate_status != 0 {
            break;
        }
        index += 1;
    }
    if aggregate_status == 0 && index == support_count {
        aggregate_verdict |= crate::driver_launch::V_SUCCESS;
    }
    component_write_support_aggregate(shared_va, spec, aggregate_status, aggregate_verdict);
    aggregate_status
}

/// The component-side shared entry (Family A): read the DriverEntry RVA from the shared frame, build
/// a `DriverObjectSpec`-shaped DRIVER_OBJECT + a zero-length RegistryPath from the pool, optionally
/// initialize a support image first, call the primary `DriverEntry`, record the verdict/status, run
/// `post_driver_entry` (win32k: establish-client; FSD: no-op — MUST run between DriverEntry and the
/// FIRST completion `Call`), then loop `call_on(completion) → dispatch(request) → write
/// SH_REQ_STATUS`.
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

    let (drv, reg_path) = component_driver_entry_context(spec);
    if spec.driver_object_off != u64::MAX {
        core::ptr::write_volatile((shared_va + spec.driver_object_off) as *mut u64, drv);
    }

    let support_entry_rva = if spec.support_entry_rva_off == u64::MAX {
        0
    } else {
        core::ptr::read_volatile((shared_va + spec.support_entry_rva_off) as *const u64)
    };
    let mut status = component_run_support_entries(shared_va, code_va, spec, support_entry_rva);

    let mut primary_ran = false;
    if status == 0 {
        core::ptr::write_volatile(
            (shared_va + SH_VERDICT_H) as *mut u32,
            crate::driver_launch::V_ENTERED,
        );
        let entry = code_va + entry_rva as u64;
        let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
        primary_ran = true;
        status = de(drv, reg_path);
    }

    let mj_base = drv + spec.mj;
    let mj_create = core::ptr::read_unaligned(mj_base as *const u64);
    let mut v = core::ptr::read_volatile((shared_va + SH_VERDICT_H) as *const u32);
    if primary_ran {
        v |= crate::driver_launch::V_RETURNED;
        if status == 0 {
            v |= crate::driver_launch::V_SUCCESS;
        }
        if mj_create != 0
            && (spec.default_major_function == 0 || mj_create != spec.default_major_function)
        {
            v |= crate::driver_launch::V_MJ;
        }
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

unsafe fn component_driver_entry_context(spec: DriverObjectSpec) -> (u64, u64) {
    // DRIVER_OBJECT (Type@0=4, Size@2, DriverExtension at the NT x64 offset, DriverUnload=0,
    // MajorFunction@spec.mj).
    let drv = (spec.pool)(spec.size);
    let ext = (spec.pool)(spec.ext_size);
    let mut j = 0u64;
    while j < spec.ext_size {
        core::ptr::write_unaligned((ext + j) as *mut u64, 0);
        j += 8;
    }
    let driver_bytes = core::slice::from_raw_parts_mut(drv as *mut u8, spec.size as usize);
    if write_wdm_driver_object(
        driver_bytes,
        WdmDriverObjectInit {
            size_field: spec.size_field,
            device_object: 0,
            driver_extension: ext,
            driver_unload: 0,
        },
    )
    .is_err()
    {
        panic!("invalid DriverObjectSpec");
    }
    if spec.default_major_function != 0 {
        let mut off = spec.mj;
        while off + 8 <= spec.size {
            core::ptr::write_unaligned((drv + off) as *mut u64, spec.default_major_function);
            off += 8;
        }
    }

    // RegistryPath UNICODE_STRING { Length=0, MaximumLength=2, Buffer=&NUL }.
    let reg_path = (spec.pool)(0x18);
    let reg_buf = (spec.pool)(0x10);
    core::ptr::write_unaligned(reg_buf as *mut u16, 0);
    core::ptr::write_unaligned(reg_path as *mut u16, 0);
    core::ptr::write_unaligned((reg_path + 2) as *mut u16, 2);
    core::ptr::write_unaligned((reg_path + 8) as *mut u64, reg_buf);
    (drv, reg_path)
}

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
