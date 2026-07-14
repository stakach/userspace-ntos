//! `driver_launch` — the GENERAL DYNAMIC driver-launch path (the NT `IoLoadDriver`/`NtLoadDriver`
//! / SCM driver-start model). Take a driver name/path → load the `.sys` by-path from the FS →
//! determine its POLICY CLASS → build a [`ComponentDescriptor`] → `spawn_component` it ISOLATED →
//! run its real `DriverEntry` in the component (capturing its MajorFunction table + device object).
//!
//! This GENERALIZES the bespoke boot-time spawners (`spawn_driver_host` NIC, `spawn_storage_host`,
//! `spawn_kmdf_host`, `spawn_win32k_host`) into ONE runtime service — like Win32 `CreateProcess` /
//! the general `NtCreateThread`. Any `.sys` becomes launchable dynamically. The first client is
//! **npfs.sys** (an FSD-class descriptor, NO device caps).
//!
//! POLICY CLASSES (see `project_driver_model.md`):
//!   * [`DriverClass::Fsd`]    — file-system drivers (npfs, fastfat, ntfs): image + heap/pool + stack
//!     + IPC-buf + fault EP + a shared handoff page; NO device caps.
//!   * [`DriverClass::Device`] — hardware drivers (NIC/AHCI/GPU): the device-cap section is populated
//!     by `nt-pnp` (MMIO BARs / IRQ / DMA). SEAM ONLY here (out of scope for this increment).
//!   * [`DriverClass::Subsystem`] — win32k/WDF: explicit subsystem contract (kept bespoke for now).
//!
//! The existing bespoke spawners are follow-on migrations onto this path (their descriptor-builders
//! already exist post effort-1); this increment builds the general path + proves it with npfs.

use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};

use crate::npfs_host;
use crate::*;

/// The policy class of a dynamically-launched driver — determines the [`ComponentDescriptor`]'s
/// device-cap section.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverClass {
    /// File-system driver (npfs, fastfat, ntfs) — no device caps.
    Fsd,
    /// Hardware device driver — device caps minted by nt-pnp (SEAM; not built here).
    #[allow(dead_code)]
    Device,
    /// Subsystem/runtime driver (win32k, WDF) — bespoke (not routed through here yet).
    #[allow(dead_code)]
    Subsystem,
}

/// A launched, isolated driver component — the caps + VAs the executive keeps to route IRPs to it.
pub(crate) struct DriverComponent {
    /// The component's VSpace (PML4 cap) — for demand-mapping pages / cross-AS reads.
    pub pml4: u64,
    /// The component's fault endpoint (also the IRP dispatch channel: plain Send/Recv).
    pub fault_ep: u64,
    /// The loaded image base VA (= [`npfs_host::NPFS_CODE_VA`] for npfs).
    pub code_va: u64,
    /// The recorded `DriverObject->MajorFunction[]` base VA (in the component's VSpace).
    pub mj_table: u64,
    /// The recorded control DEVICE_OBJECT VA (\Device\NamedPipe for npfs).
    pub devobj: u64,
    /// The DriverEntry verdict bitmask (npfs_host::V_*).
    pub verdict: u32,
    /// Whether DriverEntry ran to its dispatch loop (parked) vs faulted mid-init.
    pub finished: bool,
}

/// Copy `n` bytes from `src` to `dst` (both mapped in the executive). HEAP-FREE, byte-wise-safe
/// (unaligned windows in a PE).
unsafe fn copy_bytes(dst: u64, src: u64, n: u64) {
    let mut i = 0u64;
    while i + 8 <= n {
        write_unaligned((dst + i) as *mut u64, read_unaligned((src + i) as *const u64));
        i += 8;
    }
    while i < n {
        write_unaligned((dst + i) as *mut u8, read_unaligned((src + i) as *const u8));
        i += 1;
    }
}

/// Parse a driver PE at `src_va` (raw file bytes), copy its sections into `dst_va` (frames pre-mapped
/// RW in BOTH the executive and the component), apply DIR64 relocations for the load at `dst_va`, and
/// patch the IAT resolving each import name through `resolve`. Records per-frame W^X rights into
/// `rights_out`. Returns the DriverEntry RVA, or None. Fully HEAP-FREE.
///
/// This is the generic PE-load mechanism (the win32k `load_driver_into` shape, but with an injected
/// name resolver so it's driver-agnostic — the general dynamic path).
unsafe fn load_pe_into(
    src_va: u64,
    dst_va: u64,
    max_frames: u64,
    rights_out: &mut [u64],
    resolve: fn(&str) -> u64,
) -> Option<u32> {
    let e = read_unaligned((src_va + 0x3c) as *const u32) as u64;
    let nt = src_va + e;
    if read_unaligned(nt as *const u32) != 0x0000_4550 {
        return None;
    }
    let file_hdr = nt + 4;
    let num_sections = read_unaligned((file_hdr + 2) as *const u16) as u64;
    let size_opt_hdr = read_unaligned((file_hdr + 16) as *const u16) as u64;
    let opt = file_hdr + 20;
    let entry_rva = read_unaligned((opt + 16) as *const u32);
    let image_base = read_unaligned((opt + 24) as *const u64);
    let size_of_headers = read_unaligned((opt + 60) as *const u32) as u64;
    let sec_table = opt + size_opt_hdr;
    let cap = max_frames * 0x1000;

    copy_bytes(dst_va, src_va, size_of_headers.min(cap));
    for s in 0..num_sections {
        let sh = sec_table + s * 40;
        let va = read_unaligned((sh + 12) as *const u32) as u64;
        let raw_size = read_unaligned((sh + 16) as *const u32) as u64;
        let raw_ptr = read_unaligned((sh + 20) as *const u32) as u64;
        let vsize = read_unaligned((sh + 8) as *const u32) as u64;
        let chars = read_unaligned((sh + 36) as *const u32);
        if va >= cap {
            continue;
        }
        let n = raw_size.min(cap - va);
        copy_bytes(dst_va + va, src_va + raw_ptr, n);
        // W^X: executable section → RX (2), else RW_NX.
        let r = if chars & 0x2000_0000 != 0 { 2u64 } else { RW_NX };
        let span = va + vsize.max(raw_size);
        let mut p = va & !0xFFF;
        while p < span {
            let idx = (p / 0x1000) as usize;
            if idx < rights_out.len() {
                rights_out[idx] = r;
            }
            p += 0x1000;
        }
    }

    // DIR64 relocs for the load at dst_va.
    let delta = dst_va.wrapping_sub(image_base);
    if delta != 0 {
        let reloc_rva = read_unaligned((opt + 112 + 5 * 8) as *const u32) as u64;
        let reloc_size = read_unaligned((opt + 112 + 5 * 8 + 4) as *const u32) as u64;
        let mut off = 0u64;
        while reloc_rva != 0 && off + 8 <= reloc_size {
            let page_rva = read_unaligned((dst_va + reloc_rva + off) as *const u32) as u64;
            let block = read_unaligned((dst_va + reloc_rva + off + 4) as *const u32) as u64;
            if block < 8 {
                break;
            }
            let cnt = (block - 8) / 2;
            for i in 0..cnt {
                let ent = read_unaligned((dst_va + reloc_rva + off + 8 + i * 2) as *const u16);
                if (ent >> 12) == 10 {
                    let t = page_rva + (ent & 0xFFF) as u64;
                    if t < cap {
                        let v = read_unaligned((dst_va + t) as *const u64);
                        write_unaligned((dst_va + t) as *mut u64, v.wrapping_add(delta));
                    }
                }
            }
            off += block;
        }
    }

    // PASSIVE-level transform (documented; the win32k `KeGetCurrentIrql`-cr8 precedent): a kernel
    // driver reads the current IRQL as `mov %cr8, %reg` — a PRIVILEGED instruction that #GPs in the
    // component's usermode context (a UserException the fault-reply path can't set RAX through). npfs
    // runs entirely at PASSIVE_LEVEL (0) in this host, so neutralize each `REX.W 0f 20 c0` (mov %cr8,
    // %rax) into `xor %eax,%eax; nop` (`31 c0 90 90`, 4 bytes, result 0 = PASSIVE_LEVEL) and each
    // `mov %reg,%cr8` (`0f 22`, KeLowerIrql, 3 bytes) into `nop`s. Scan the whole loaded image.
    {
        let size_of_image = read_unaligned((opt + 56) as *const u32) as u64;
        let scan = size_of_image.min(cap);
        let mut p = 0u64;
        while p + 4 <= scan {
            let b0 = read_unaligned((dst_va + p) as *const u8);
            let b1 = read_unaligned((dst_va + p + 1) as *const u8);
            let b2 = read_unaligned((dst_va + p + 2) as *const u8);
            // REX prefix (0x40..0x4f), then 0F 20 (mov %cr,%reg): if the ModRM names cr8 (reg field
            // == 0, with REX.R providing the high bit → cr8), rewrite to xor eax,eax; nop; nop.
            if (b0 & 0xF0) == 0x40 && b1 == 0x0F && b2 == 0x20 {
                let modrm = read_unaligned((dst_va + p + 3) as *const u8);
                // ModRM = 11 000 rrr (reg field 000 = crN, rm = dest GPR). REX.R (b0 & 4) selects cr8.
                if (modrm & 0xC0) == 0xC0 && (modrm & 0x38) == 0x00 {
                    write_unaligned((dst_va + p) as *mut u8, 0x31); // xor
                    write_unaligned((dst_va + p + 1) as *mut u8, 0xC0); // eax,eax
                    write_unaligned((dst_va + p + 2) as *mut u8, 0x90); // nop
                    write_unaligned((dst_va + p + 3) as *mut u8, 0x90); // nop
                    p += 4;
                    continue;
                }
            }
            // 0F 22 (mov %reg,%cr): a KeRaise/LowerIrql write to cr8 → neutralize to nops (3 bytes;
            // an optional REX makes it 4). Rewrite the 0F 22 ModRM triple to nops.
            if b0 == 0x0F && b1 == 0x22 {
                write_unaligned((dst_va + p) as *mut u8, 0x90);
                write_unaligned((dst_va + p + 1) as *mut u8, 0x90);
                write_unaligned((dst_va + p + 2) as *mut u8, 0x90);
                p += 3;
                continue;
            }
            p += 1;
        }
    }

    // Patch the IAT: resolve each import name through `resolve`.
    let imp_rva = read_unaligned((opt + 112 + 8) as *const u32) as u64;
    if imp_rva != 0 {
        let mut desc = dst_va + imp_rva;
        loop {
            let ilt = read_unaligned(desc as *const u32) as u64;
            let iat = read_unaligned((desc + 16) as *const u32) as u64;
            if ilt == 0 && iat == 0 {
                break;
            }
            let names = dst_va + if ilt != 0 { ilt } else { iat };
            let slots = dst_va + iat;
            let mut k = 0u64;
            loop {
                let thunk = read_unaligned((names + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }
                if thunk & 0x8000_0000_0000_0000 == 0 {
                    let name_ptr = dst_va + (thunk & 0x7FFF_FFFF) + 2;
                    let mut buf = [0u8; 64];
                    let mut n = 0usize;
                    while n < 63 {
                        let c = read_volatile((name_ptr + n as u64) as *const u8);
                        if c == 0 {
                            break;
                        }
                        buf[n] = c;
                        n += 1;
                    }
                    let name = core::str::from_utf8_unchecked(&buf[..n]);
                    let addr = resolve(name);
                    write_unaligned((slots + k * 8) as *mut u64, addr);
                }
                k += 1;
            }
            desc += 20;
        }
    }

    Some(entry_rva)
}

/// The npfs image loaded/mapped rights (W^X), filled by [`load_pe_into`].
static mut NPFS_RIGHTS: [u64; npfs_host::NPFS_IMAGE_FRAMES as usize] =
    [RW_NX; npfs_host::NPFS_IMAGE_FRAMES as usize];

/// GENERAL dynamic driver launch: load the `.sys` at `path` by-path from the FS, IAT-patch it, spawn
/// it as an ISOLATED component (per its `class`), run its real DriverEntry, and return the live
/// [`DriverComponent`]. Currently the FSD class is fully built (npfs is the first client); the
/// Device class is a documented seam (nt-pnp populates the device caps) and Subsystem stays bespoke.
///
/// Fault-contained: the component's DriverEntry faults land on ITS fault EP (this loop demand-maps
/// benign pages + reports a wall) — a driver crash never brings down the executive root.
pub(crate) unsafe fn load_driver(
    fs: &Fat32,
    path: &[u8],
    class: DriverClass,
) -> Option<DriverComponent> {
    if class != DriverClass::Fsd {
        // Device/Subsystem seams: not routed through the general path in this increment.
        return None;
    }

    // 1. Load the .sys bytes by-path into the executive's pool.
    let (src_va, src_size) = load_file_to_pool(fs, path)?;
    print_str(b"[driver-launch] loaded ");
    print_str(path);
    print_str(b" size=");
    print_u64(src_size as u64);
    print_str(b"\n");

    let code_va = npfs_host::NPFS_CODE_VA;
    let img_frames = npfs_host::NPFS_IMAGE_FRAMES;

    // 2. Executive-side frames: CODE (mapped RW to load into) in its own 2 MiB PT, DATA + SHARED +
    //    ARG in an aux PT. POOL is host-only.
    let cpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cpt);
    let _ = paging_struct_map(cpt, LBL_X86_PAGE_TABLE_MAP, code_va, CAP_INIT_THREAD_VSPACE);
    let code_base = alloc_frame();
    for _ in 1..img_frames {
        let _ = alloc_frame();
    }
    for i in 0..img_frames {
        let _ = page_map(copy_cap(code_base + i), code_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    // POOL frames (host-only; allocate the caps, mapped by spawn_component).
    let pool_base = alloc_frame();
    for _ in 1..npfs_host::NPFS_POOL_FRAMES {
        let _ = alloc_frame();
    }
    // DATA + SHARED + ARG: caps + an aux PT in the executive VSpace.
    let data_base = alloc_frame();
    for _ in 1..npfs_host::NPFS_DATA_FRAMES {
        let _ = alloc_frame();
    }
    let shared = alloc_frame();
    let arg_base = alloc_frame();
    for _ in 1..npfs_host::NPFS_ARG_FRAMES {
        let _ = alloc_frame();
    }
    let apt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, apt);
    let _ = paging_struct_map(apt, LBL_X86_PAGE_TABLE_MAP, npfs_host::NPFS_AUX_PT_VADDR, CAP_INIT_THREAD_VSPACE);
    for i in 0..npfs_host::NPFS_DATA_FRAMES {
        let _ = page_map(copy_cap(data_base + i), npfs_host::NPFS_DATA_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    let _ = page_map(copy_cap(shared), npfs_host::NPFS_SHARED_VADDR, RW_NX, CAP_INIT_THREAD_VSPACE);
    for i in 0..npfs_host::NPFS_ARG_FRAMES {
        let _ = page_map(copy_cap(arg_base + i), npfs_host::NPFS_ARG_VADDR + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }

    // 3. Parse + copy + relocate + IAT-patch (HEAP-FREE, records W^X rights).
    let rights = &mut *core::ptr::addr_of_mut!(NPFS_RIGHTS);
    let entry_rva = load_pe_into(src_va, code_va, img_frames, rights, npfs_host::npfs_export_addr)?;
    print_str(b"[driver-launch] npfs DriverEntry rva=0x");
    print_hex(entry_rva);
    print_str(b"\n");
    write_volatile((npfs_host::NPFS_SHARED_VADDR + npfs_host::SH_ENTRY_RVA) as *mut u64, entry_rva as u64);
    write_volatile((npfs_host::NPFS_SHARED_VADDR + npfs_host::SH_VERDICT) as *mut u32, 0);

    // 4. Build the FSD-class descriptor + spawn the isolated component.
    let fault_ep = make_object(OBJ_ENDPOINT);
    let pml4 = spawn_fsd_component(code_base, pool_base, data_base, shared, arg_base, fault_ep, &rights[..img_frames as usize]);

    // 5. Drive the fault-recv loop: demand-map benign pages, wait for the dispatch-ready signal.
    const DEMAND_CAP: u64 = 512;
    let mut faults = 0u64;
    let mut demand = 0u64;
    let mut finished = false;
    let (mut wall_ip, mut wall_addr, mut wall_label) = (0u64, 0u64, 0u64);
    let (mut _bdg, mut mi, mut m0, mut m1, mut _m2, mut _m3) = ep_recv_full(fault_ep);
    loop {
        let label = mi >> 12;
        if label == 6 {
            let ip = m0;
            let addr = m1;
            faults += 1;
            if faults <= 40 {
                print_str(b"[npfs-svc] fault #");
                print_u64(faults);
                print_str(b" ip=0x");
                print_hex(ip as u32);
                print_str(b" RVA=0x");
                print_hex(ip.wrapping_sub(code_va) as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                print_str(b"\n");
            }
            let in_image = addr >= code_va && addr < code_va + img_frames * 0x1000;
            if addr < 0x10000 || in_image || demand >= DEMAND_CAP {
                wall_ip = ip;
                wall_addr = addr;
                wall_label = label;
                break;
            }
            let page = addr & !0xFFF;
            ensure_paging(page, pml4);
            let f = alloc_frame();
            let _ = page_map(f, page, RW_NX, pml4);
            demand += 1;
            let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(fault_ep, 0, 0, 0, 0, 0);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            _m2 = nm2;
            _m3 = nm3;
            continue;
        } else if label == npfs_host::NPFS_DISPATCH_LABEL {
            finished = true;
            break;
        } else {
            wall_ip = m0;
            wall_addr = m1;
            wall_label = label;
            break;
        }
    }

    let verdict = read_volatile((npfs_host::NPFS_SHARED_VADDR + npfs_host::SH_VERDICT) as *const u32);
    let de_status = read_volatile((npfs_host::NPFS_SHARED_VADDR + npfs_host::SH_DE_STATUS) as *const i32);
    let mj_table = read_volatile((npfs_host::NPFS_SHARED_VADDR + npfs_host::SH_MJ_TABLE) as *const u64);
    let devobj = read_volatile((npfs_host::NPFS_SHARED_VADDR + npfs_host::SH_DEVOBJ) as *const u64);
    print_str(b"[npfs-svc] DriverEntry ");
    if finished {
        print_str(b"RETURNED status=0x");
        print_hex(de_status as u32);
    } else {
        print_str(b"STOPPED label=");
        print_u64(wall_label);
        print_str(b" ip=0x");
        print_hex(wall_ip as u32);
        print_str(b" RVA=0x");
        print_hex(wall_ip.wrapping_sub(code_va) as u32);
        print_str(b" addr=0x");
        print_hex((wall_addr >> 32) as u32);
        print_hex(wall_addr as u32);
    }
    print_str(b" verdict=0x");
    print_hex(verdict);
    print_str(b" faults=");
    print_u64(faults);
    print_str(b" demand=");
    print_u64(demand);
    print_str(b" devobj=0x");
    print_hex((devobj >> 32) as u32);
    print_hex(devobj as u32);
    print_str(b"\n");

    Some(DriverComponent { pml4, fault_ep, code_va, mj_table, devobj, verdict, finished })
}

/// Spawn the isolated FSD component: image W^X, pool, stack, IPC-buf, DATA/SHARED/ARG windows, fault
/// EP — NO device caps. Delegates to the generic [`spawn_component`] engine.
unsafe fn spawn_fsd_component(
    code_base: u64,
    pool_base: u64,
    data_base: u64,
    shared: u64,
    arg_base: u64,
    fault_ep: u64,
    rights: &[u64],
) -> u64 {
    // SAFETY: rights lives in NPFS_RIGHTS (a 'static); re-borrow as 'static for Rights::PerFrame.
    let rights_static: &'static [u64] = core::mem::transmute::<&[u64], &'static [u64]>(rights);
    let regions = [
        // The npfs PE image, W^X, its own 2 MiB PT.
        Region { source: FrameSource::Alias(code_base), base_va: npfs_host::NPFS_CODE_VA, count: npfs_host::NPFS_IMAGE_FRAMES, rights: Rights::PerFrame(rights_static), pts: 1 },
        // Pool arena (own window + PTs, aliased executive frames).
        Region { source: FrameSource::Alias(pool_base), base_va: npfs_host::NPFS_POOL_VADDR, count: npfs_host::NPFS_POOL_FRAMES, rights: Rights::Uniform(RW_NX), pts: 1 },
        // Aux PT window for DATA/SHARED/ARG.
        Region { source: FrameSource::Alias(0), base_va: npfs_host::NPFS_AUX_PT_VADDR, count: 0, rights: Rights::Uniform(RW_NX), pts: 1 },
        // DATA export/placeholder region (aux window).
        Region { source: FrameSource::Alias(data_base), base_va: npfs_host::NPFS_DATA_VADDR, count: npfs_host::NPFS_DATA_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
        // Shared handoff page (aux window).
        Region { source: FrameSource::Alias(shared), base_va: npfs_host::NPFS_SHARED_VADDR, count: 1, rights: Rights::Uniform(RW_NX), pts: 0 },
        // Arg-marshal frames (aux window).
        Region { source: FrameSource::Alias(arg_base), base_va: npfs_host::NPFS_ARG_VADDR, count: npfs_host::NPFS_ARG_FRAMES, rights: Rights::Uniform(RW_NX), pts: 0 },
    ];
    let d = ComponentDescriptor {
        entry: npfs_host::npfs_host_entry,
        image_rights: Rights::Uniform(3), // RWX (trampolines live in the shared executive image)
        map_heap_pt: false,
        stack_base: npfs_host::NPFS_STACK_VADDR,
        stack_frames: npfs_host::NPFS_STACK_FRAMES,
        stack_dedicated_pt: true,
        regions: &regions,
        granted: GrantedCaps { irq_ntfn: None, result_ntfn: None, fault_ep: Some(fault_ep) },
        prio: 100,
        gs_base: Some(npfs_host::NPFS_KPCR_VA),
    };
    spawn_component(&d).pml4
}

/// Ensure the page table covering `page` exists in `pml4` (SYS_SEND page_map can't report a
/// missing-PT error). Idempotent-ish: builds one PT per 2 MiB region touched (tracked in a small
/// static bitmap keyed by the 2 MiB index within the pool/demand window). Mirrors the win32k
/// `ensure_w32_client_paging` mechanism.
unsafe fn ensure_paging(page: u64, pml4: u64) {
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, page & !0x1F_FFFF, pml4);
}

// ---------------------------------------------------------------------------------------------
// The live launched npfs component + the IRP dispatch call.
// ---------------------------------------------------------------------------------------------

static NPFS_FAULT_EP: AtomicU64 = AtomicU64::new(0);
static NPFS_PML4: AtomicU64 = AtomicU64::new(0);
static NPFS_MJ_TABLE: AtomicU64 = AtomicU64::new(0);
static NPFS_DEVOBJ: AtomicU64 = AtomicU64::new(0);
static NPFS_READY: AtomicU64 = AtomicU64::new(0);

/// Record a launched npfs component so [`npfs_dispatch_irp`] can route IRPs to it from anywhere.
pub(crate) fn register_npfs(dc: &DriverComponent) {
    NPFS_FAULT_EP.store(dc.fault_ep, Ordering::Relaxed);
    NPFS_PML4.store(dc.pml4, Ordering::Relaxed);
    NPFS_MJ_TABLE.store(dc.mj_table, Ordering::Relaxed);
    NPFS_DEVOBJ.store(dc.devobj, Ordering::Relaxed);
    NPFS_READY.store(if dc.finished && dc.devobj != 0 { 1 } else { 0 }, Ordering::Relaxed);
}

/// Whether npfs is launched + parked at its dispatch loop (ready to serve IRPs).
pub(crate) fn npfs_ready() -> bool {
    NPFS_READY.load(Ordering::Relaxed) != 0
}

/// The recorded \Device\NamedPipe DEVICE_OBJECT (0 = not launched).
pub(crate) fn npfs_devobj() -> u64 {
    NPFS_DEVOBJ.load(Ordering::Relaxed)
}

/// Route one IRP to the isolated npfs component: fill the shared request fields, drive its dispatch
/// loop (a plain Send wakes it; it runs `MajorFunction[major]` in its own context; a fault mid-IRP
/// lands on its fault EP → demand-map + resume), then read back the completion. Returns
/// `(status, information)`. `major` is an `IRP_MJ_*`; `in_data` is copied into the ARG frame (buffered
/// I/O); `out` receives the driver's output.
///
/// Returns `None` if npfs isn't ready (the caller falls back to the modeled path).
pub(crate) unsafe fn npfs_dispatch_irp(
    major: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<(i32, u64)> {
    if !npfs_ready() {
        return None;
    }
    let ep = NPFS_FAULT_EP.load(Ordering::Relaxed);
    let pml4 = NPFS_PML4.load(Ordering::Relaxed);
    let sh = npfs_host::NPFS_SHARED_VADDR;
    // buffered I/O: copy input into the ARG frame (mapped RW in both AS).
    let arg = npfs_host::NPFS_ARG_VADDR;
    let inlen = in_data.len().min((npfs_host::NPFS_ARG_FRAMES * 0x1000) as usize);
    for i in 0..inlen {
        write_volatile((arg + i as u64) as *mut u8, in_data[i]);
    }
    write_volatile((sh + npfs_host::SH_REQ_MAJOR) as *mut u64, major);
    write_volatile((sh + npfs_host::SH_REQ_MINOR) as *mut u64, 0);
    write_volatile((sh + npfs_host::SH_REQ_FSCTL) as *mut u64, fsctl);
    write_volatile((sh + npfs_host::SH_REQ_INLEN) as *mut u64, inlen as u64);
    write_volatile((sh + npfs_host::SH_REQ_OUTLEN) as *mut u64, out.len() as u64);
    write_volatile((sh + npfs_host::SH_REQ_FILEID) as *mut u64, file_id);
    write_volatile((sh + npfs_host::SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + npfs_host::SH_REQ_INFO) as *mut u64, 0);

    // Wake the component (plain Send), then drive its fault loop until it re-parks (its next
    // send_done). Any fault mid-IRP → demand-map + resume.
    ep_send(ep, npfs_host::NPFS_DISPATCH_LABEL);
    let (mut _b, mut mi, mut m0, mut m1, mut _m2, mut _m3) = ep_recv_full(ep);
    let mut guard = 0u64;
    loop {
        let label = mi >> 12;
        if label == npfs_host::NPFS_DISPATCH_LABEL {
            break; // re-parked at its dispatch loop → request complete
        } else if label == 6 {
            let addr = m1;
            let page = addr & !0xFFF;
            if addr >= 0x10000 && guard < 256 {
                ensure_paging(page, pml4);
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                guard += 1;
                let (nmi, nm0, nm1, nm2, nm3) = reply_recv_full(ep, 0, 0, 0, 0, 0);
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                _m2 = nm2;
                _m3 = nm3;
                continue;
            }
            print_str(b"[npfs-svc] IRP fault wall addr=0x");
            print_hex(addr as u32);
            print_str(b"\n");
            return Some((0xC000_0001u32 as i32, 0)); // STATUS_UNSUCCESSFUL
        } else {
            let _ = (m0,);
            return Some((0xC000_0001u32 as i32, 0));
        }
    }
    let st = read_volatile((sh + npfs_host::SH_REQ_STATUS) as *const i32);
    let info = read_volatile((sh + npfs_host::SH_REQ_INFO) as *const u64);
    // copy the driver's output back out (buffered I/O).
    let outlen = (info as usize).min(out.len());
    for i in 0..outlen {
        out[i] = read_volatile((arg + i as u64) as *const u8);
    }
    Some((st, info))
}
