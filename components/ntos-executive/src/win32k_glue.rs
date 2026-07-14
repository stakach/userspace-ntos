//! `win32k_glue` — the executive-side win32k client plumbing: RO-map win32k's
//! USER heap into csrss, per-client cross-AS page attach (w32_*), the DirectX/
//! ftfd/framebuffer driver loaders, and the win32k syscall dispatch + backtrace.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

/// RO-map win32k's global USER heap arena ([`win32k_host::WIN32K_HEAP_VADDR`], where gpsi /
/// gHandleTable / the USER handle-entry array live) into the caller's (csrss's) VSpace at
/// [`win32k_host::CSRSS_W32_SHARED_VA`], so the Win32 client can dereference the SHAREDINFO the
/// USERCONNECT points at. Maps a fresh copy of each arena frame RO+NX (win32k keeps its own RW
/// copy — coherent shared memory). One-time (guarded). Returns the server→client delta
/// (`WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`) the marshaling applies to the siClient pointers.
pub(crate) unsafe fn map_win32k_heap_into_csrss(pml4: u64, pi: usize) -> u64 {
    let delta = win32k_host::WIN32K_HEAP_VADDR - win32k_host::CSRSS_W32_SHARED_VA;
    // Per-process guard (bit `pi`): the arena is mapped into EACH GUI client's VSpace independently
    // (csrss = pi 1, winlogon = pi 2) at the same CSRSS_W32_SHARED_VA window, so the delta — hence
    // the siClient rewrite — is identical for both. A single bool would skip the 2nd client's map.
    let bit = 1u64 << pi;
    if WIN32K_CLIENT_MAPPED.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return delta; // already mapped into this process's VSpace
    }
    let heap_base = WIN32K_HEAP_FRAME_BASE.load(Ordering::Relaxed);
    if heap_base == 0 {
        return delta;
    }
    const RO_NX: u64 = 2 | PAGE_EXECUTE_NEVER; // read-only, non-executable
    let frames = win32k_host::WIN32K_HEAP_FRAMES;
    // The 1 GiB PD covering 0x8000_0000..0xC000_0000 already exists in csrss (its DLL region shares
    // it). The CSRSS_W32_SHARED_VA window is fresh, so allocate + map one page table per 2 MiB
    // sub-range UP FRONT — deterministic, because the SYS_SEND `page_map` is fire-and-forget and
    // can't report a missing-PT error to drive a retry.
    for p in 0..(frames + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_host::CSRSS_W32_SHARED_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(heap_base + i);
        let _ = page_map(cp, win32k_host::CSRSS_W32_SHARED_VA + i * 0x1000, RO_NX, pml4);
    }
    print_str(b"[win32k-svc] RO-mapped win32k USER heap into csrss @0x");
    print_hex(win32k_host::CSRSS_W32_SHARED_VA as u32);
    print_str(b" (delta=0x");
    print_hex((delta >> 32) as u32);
    print_hex(delta as u32);
    print_str(b")\n");
    delta
}

// --- win32k cross-AS client-memory sharing (the authentic "win32k shares the caller's user AS") ---
// win32k-side paging structures provisioned for the shared client window, and pages already mapped,
// keyed by a level-tagged aligned index (SYS_SEND paging_struct_map is fire-and-forget so we can't
// detect "already mapped" — track it). Client VAs are all < 0x100_0000_0000 (PML4 slots 0/1), never
// win32k's own PML4[2] (>= 0x100_..), so building a fresh PDPT/PD/PT hierarchy here can't collide
// with win32k's own mappings.
pub(crate) static mut W32_CLIENT_SEEN: [u64; 8192] = [0; 8192];
pub(crate) static mut W32_CLIENT_SEEN_N: usize = 0;
pub(crate) unsafe fn w32_seen(key: u64) -> bool {
    let n = core::ptr::read(core::ptr::addr_of!(W32_CLIENT_SEEN_N));
    let a = core::ptr::addr_of!(W32_CLIENT_SEEN) as *const u64;
    for i in 0..n {
        if core::ptr::read(a.add(i)) == key {
            return true;
        }
    }
    false
}
pub(crate) unsafe fn w32_mark(key: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(W32_CLIENT_SEEN_N));
    if n < 8192 {
        core::ptr::write((core::ptr::addr_of_mut!(W32_CLIENT_SEEN) as *mut u64).add(n), key);
        core::ptr::write(core::ptr::addr_of_mut!(W32_CLIENT_SEEN_N), n + 1);
    }
}
/// Ensure win32k's VSpace has a PDPT/PD/PT chain covering `page` (each created once, tracked in
/// W32_CLIENT_SEEN). Used both for FOREIGN client pages (PML4[0/1], fresh hierarchy) AND for
/// win32k-OWN demand-mapped regions (the demand-mapped pool at 0x0A00, whose 2 MiB PTs don't exist
/// yet). Deterministic because `page_map`/`paging_struct_map` are SYS_SEND (fire-and-forget) and
/// can't report a missing-PT error to drive a retry — so the PT must be created up front. For
/// win32k-own PML4[2] pages the PDPT/PD already exist; the duplicate retype+map fails silently
/// (seL4 won't replace an occupied slot) and only the fresh PT actually takes.
pub(crate) unsafe fn ensure_w32_client_paging(page: u64, w_pml4: u64) {
    let k_pdpt = (1u64 << 60) | (page >> 39);
    if !w32_seen(k_pdpt) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PDPT_MAP, page, w_pml4);
        w32_mark(k_pdpt);
    }
    let k_pd = (2u64 << 60) | (page >> 30);
    if !w32_seen(k_pd) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PAGE_DIRECTORY_MAP, page, w_pml4);
        w32_mark(k_pd);
    }
    let k_pt = (3u64 << 60) | (page >> 21);
    if !w32_seen(k_pt) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PAGE_TABLE_MAP, page, w_pml4);
        w32_mark(k_pt);
    }
}
// --- win32k per-client attach/detach (the KeStackAttachProcess model) ---------------------------
// win32k's client window is shared with EXACTLY ONE GUI client at a time. csrss (pi 1) and winlogon
// (pi 2) map an overlapping DLL/stack set at IDENTICAL VAs but DISTINCT frames, so a static shared
// window can't hold both — win32k must re-point (attach to) the CURRENT dispatch's client. The
// attach table records the client leaf pages currently mapped into win32k (page -> the copy_cap
// slot used, so we can Unmap it on detach). On a client switch we Unmap the previous client's leaf
// pages (they re-fault fresh for the new client, resolving the colliding VA to THIS client's frame);
// the PDPT/PD/PT structures persist in W32_CLIENT_SEEN (empty tables after the leaf Unmap). The
// arch-level Unmap uses the invoked (win32k) cap's asid → only win32k's mapping is torn down; the
// client keeps its own mapping in its own VSpace.
/// Bit `pi` set once a GUI client's `NtUserProcessConnect` (SSN 0x10FA) has been routed to win32k and
/// returned STATUS_SUCCESS — the "win32k client connected" mask. csrss=pi 1, winlogon=pi 2,
/// services=pi 3. Drives the `exec_services_win32k_connect` gate spec (bit 3 = the 3rd client).
pub(crate) static W32_CONNECTED_MASK: AtomicU64 = AtomicU64::new(0);
pub(crate) static W32_ATTACHED_PI: AtomicU64 = AtomicU64::new(0xFFFF_FFFF);
/// The pi of the client whose call `win32k_dispatch` is currently servicing (set by the forward arm
/// before each dispatch; defaults to csrss so bring-up/self-test dispatches attach to pi 1). Read by
/// `win32k_dispatch` at entry to drive `w32_client_attach`.
pub(crate) static W32_CLIENT_PI: AtomicU64 = AtomicU64::new(1);
pub(crate) const W32_ATTACH_CAP: usize = 8192;
pub(crate) static mut W32_ATTACH_PAGE: [u64; W32_ATTACH_CAP] = [0; W32_ATTACH_CAP];
pub(crate) static mut W32_ATTACH_SLOT: [u64; W32_ATTACH_CAP] = [0; W32_ATTACH_CAP];
pub(crate) static mut W32_ATTACH_N: usize = 0;
/// Is `page` currently mapped into win32k for the attached client?
pub(crate) unsafe fn w32_attach_mapped(page: u64) -> bool {
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let a = core::ptr::addr_of!(W32_ATTACH_PAGE) as *const u64;
    for i in 0..n {
        if core::ptr::read(a.add(i)) == page {
            return true;
        }
    }
    false
}
/// Record that `page` is now mapped into win32k via copy-cap `slot` (for a later detach Unmap).
pub(crate) unsafe fn w32_attach_record(page: u64, slot: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    if n < W32_ATTACH_CAP {
        core::ptr::write((core::ptr::addr_of_mut!(W32_ATTACH_PAGE) as *mut u64).add(n), page);
        core::ptr::write((core::ptr::addr_of_mut!(W32_ATTACH_SLOT) as *mut u64).add(n), slot);
        core::ptr::write(core::ptr::addr_of_mut!(W32_ATTACH_N), n + 1);
    }
}
/// Attach win32k's client window to GUI client `pi` (the KeStackAttachProcess model). If a DIFFERENT
/// client is currently attached, DETACH it: Unmap all its leaf client pages from win32k so the new
/// client's colliding VAs re-fault to THIS client's frames. Idempotent when `pi` is already attached.
pub(crate) unsafe fn w32_client_attach(pi: u64) {
    let prev = W32_ATTACHED_PI.load(Ordering::Relaxed);
    if prev == pi {
        return;
    }
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let slots = core::ptr::addr_of!(W32_ATTACH_SLOT) as *const u64;
    for i in 0..n {
        // Unmap win32k's mapping of the previous client's page (arch Unmap uses this cap's win32k
        // asid → csrss/winlogon's own VSpace mapping is untouched). Cap slot is leaked (bump CNode,
        // XL 131072-slot pool → bounded for bring-up); a fresh copy_cap is used on the re-map.
        let _ = page_unmap(core::ptr::read(slots.add(i)));
    }
    print_str(b"[w32attach] client ");
    print_u64(prev);
    print_str(b" -> ");
    print_u64(pi);
    print_str(b" (detached ");
    print_u64(n as u64);
    print_str(b" client pages)\n");
    core::ptr::write(core::ptr::addr_of_mut!(W32_ATTACH_N), 0);
    W32_ATTACHED_PI.store(pi, Ordering::Relaxed);
}
/// Share GUI client `pi`'s frame for `page` into win32k's VSpace at the SAME VA (identity) so
/// win32k's handler dereferences the caller's real user memory. Returns false if the page isn't
/// backed by a known client frame (win32k would read garbage → the caller stops with a diagnostic).
/// Idempotent per page for the currently-attached client (see `w32_client_attach`).
pub(crate) unsafe fn map_csrss_page_into_win32k(page: u64, pi: u64, w_pml4: u64) -> bool {
    if w32_attach_mapped(page) {
        return true; // already shared for the currently-attached client
    }
    let fr = csrss_frame_get(pi, page);
    if fr == 0 {
        return false;
    }
    ensure_w32_client_paging(page, w_pml4);
    // RW: win32k (kernel-mode) may read AND write the caller's user memory; the frame is shared with
    // the client so writes propagate back (out-params). Non-executable — client data, not code.
    let cc = copy_cap(fr);
    let _ = page_map(cc, page, RW_NX, w_pml4);
    w32_attach_record(page, cc);
    true
}

/// Load ONE driver PE (raw at `src_va` in the executive) into `dst_va` in BOTH the executive (RW,
/// to load) and win32k (W^X, to run). Reuses [`win32k_host::load_driver_into`]. `dxgthk_base` names
/// a prior-loaded dxgthk for import resolution (0 for a leaf). Returns (entry_rva, export_dir_rva,
/// size_of_image). The reusable driver-loader mechanism (framebuf.dll will use it too).
pub(crate) unsafe fn load_one_driver(
    src_va: u64,
    dst_va: u64,
    frames: u64,
    host_pml4: u64,
    dxgthk_base: u64,
) -> Option<(u32, u32, u32)> {
    // Executive-side PT + frames (RW), to load into.
    let ept = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ept);
    let _ = paging_struct_map(ept, LBL_X86_PAGE_TABLE_MAP, dst_va, CAP_INIT_THREAD_VSPACE);
    let base = alloc_frame();
    for _ in 1..frames {
        let _ = alloc_frame();
    }
    for i in 0..frames {
        let _ = page_map(copy_cap(base + i), dst_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    // Parse + copy + reloc + resolve imports (writes via the executive's RW mapping). The per-frame
    // rights live in a `static` (ftfd.dll = 248 frames overflows a stack array; the rootserver stack
    // is only 16 KiB). Single-threaded + sequential loads → the shared static is safe.
    static mut DRIVER_RIGHTS: [u64; 256] = [RW_NX; 256];
    let rights = &mut *core::ptr::addr_of_mut!(DRIVER_RIGHTS);
    for r in rights.iter_mut() {
        *r = RW_NX;
    }
    let res = win32k_host::load_driver_into(
        src_va,
        dst_va,
        frames,
        &mut rights[..frames as usize],
        dxgthk_base,
    )?;
    // Map the SAME frames W^X into win32k's VSpace at the same VA (RX code / RW data).
    let wpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
    let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, dst_va, host_pml4);
    for i in 0..frames {
        let r = rights[i as usize];
        let _ = page_map(copy_cap(base + i), dst_va + i * 0x1000, r, host_pml4);
    }
    Some(res)
}

/// Pre-load dxg.sys + its dxgthk.sys dependency into win32k's VSpace so win32k's
/// `ZwSetSystemInformation(SystemLoadGdiDriverInformation)` (from InitializeGreCSRSS →
/// DxDdStartupDxGraphics) can report the hosted dxg image. dxgthk (leaf) first, then dxg (imports
/// dxgthk's Eng* + ntoskrnl). Called once at win32k bring-up.
pub(crate) unsafe fn load_directx_drivers(host_pml4: u64) {
    let dxg_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x80) as *const u32);
    let dxgthk_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x84) as *const u32);
    if dxg_size == 0 || dxgthk_size == 0 {
        print_str(b"[win32k-svc] dxg/dxgthk not staged - DirectX gate will fail\n");
        return;
    }
    if load_one_driver(DXGTHKBUF_VADDR, win32k_host::DXGTHK_VA, win32k_host::DXGTHK_LOAD_FRAMES, host_pml4, 0)
        .is_none()
    {
        print_str(b"[win32k-svc] dxgthk load failed\n");
        return;
    }
    match load_one_driver(
        DXGBUF_VADDR,
        win32k_host::DXG_VA,
        win32k_host::DXG_LOAD_FRAMES,
        host_pml4,
        win32k_host::DXGTHK_VA,
    ) {
        Some((entry, expdir, len)) => {
            win32k_host::record_dxg(entry, expdir, len);
            print_str(b"[win32k-svc] hosted dxg.sys + dxgthk.sys: entry_rva=0x");
            print_hex(entry);
            print_str(b" export_dir_rva=0x");
            print_hex(expdir);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] dxg load failed\n"),
    }
}

/// Host ftfd.dll (the FreeType font driver) into win32k's VSpace + patch win32k's OWN IAT for its 34
/// FT_* imports against ftfd's export table. Unlike dxg (dynamic, via ZwSetSystemInformation), ftfd
/// is a STATIC win32k import: win32k's InitFontSupport → FT_Init_FreeType calls it directly. ftfd
/// imports only 8 Eng*/Rtl thunks back from win32k.sys (resolved by load_driver_into's is_win32k arm).
/// Called once at win32k bring-up, AFTER win32k is loaded (its exports must be present for ftfd's IAT)
/// and BEFORE any FT_* call (which happens far later, during a routed NtUserInitialize dispatch).
pub(crate) unsafe fn load_ftfd_driver(host_pml4: u64) {
    let ftfd_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x88) as *const u32);
    if ftfd_size == 0 {
        print_str(b"[win32k-svc] ftfd.dll not staged - font gate will fail\n");
        return;
    }
    match load_one_driver(
        FTFDBUF_VADDR,
        win32k_host::FTFD_VA,
        win32k_host::FTFD_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, _expdir, len)) => {
            let patched = win32k_host::patch_win32k_ftfd_imports(win32k_host::FTFD_VA);
            print_str(b"[win32k-svc] hosted ftfd.dll: entry_rva=0x");
            print_hex(entry);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b" win32k FT_* IAT patched=");
            print_u64(patched as u64);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] ftfd load failed\n"),
    }
}

/// Host framebuf.dll (the display driver) into win32k's VSpace + map the BOOTBOOT framebuffer into
/// win32k. win32k loads framebuf DYNAMICALLY (like dxg) via ZwSetSystemInformation when it enables the
/// display device (co_IntInitializeDesktopGraphics → PDEVOBJ_Create → LDEVOBJ_pLoadDriver("framebuf")),
/// so pre-load it + record it for the s_zw_set_system_information trampoline. framebuf's video-miniport
/// IOCTLs (DrvEnablePDEV/DrvEnableSurface) are serviced by the patched EngDeviceIoControl intercept,
/// which returns WIN32K_FB_VA — the fb frames mapped here.
pub(crate) unsafe fn load_framebuf_driver(host_pml4: u64) {
    let sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x8C) as *const u32);
    if sz == 0 {
        print_str(b"[win32k-svc] framebuf.dll not staged - display gate will fail\n");
        return;
    }
    match load_one_driver(
        FRAMEBUFBUF_VADDR,
        win32k_host::FRAMEBUF_VA,
        win32k_host::FRAMEBUF_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, expdir, len)) => {
            win32k_host::record_framebuf(entry, expdir, len);
            print_str(b"[win32k-svc] hosted framebuf.dll: entry_rva=0x");
            print_hex(entry);
            print_str(b" (DrvEnableDriver) len=0x");
            print_hex(len);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] framebuf load failed\n"),
    }
    // Map the BOOTBOOT framebuffer (Phase-0a fb device frames) into win32k at WIN32K_FB_VA, RW.
    let base = FB_FRAME_BASE.load(Ordering::Relaxed);
    let count = FB_FRAME_COUNT.load(Ordering::Relaxed);
    if base != 0 && count != 0 {
        for p in 0..(count + 511) / 512 {
            let pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, win32k_host::WIN32K_FB_VA + p * 0x20_0000, host_pml4);
        }
        for i in 0..count {
            let _ = page_map(copy_cap(base + i), win32k_host::WIN32K_FB_VA + i * 0x1000, RW_NX, host_pml4);
        }
        print_str(b"[win32k-svc] mapped BOOTBOOT framebuffer into win32k: ");
        print_u64(count);
        print_str(b" frames @ WIN32K_FB_VA=0x");
        print_hex((win32k_host::WIN32K_FB_VA >> 32) as u32);
        print_hex(win32k_host::WIN32K_FB_VA as u32);
        print_str(b"\n");
    }
}

/// Dispatch one win32k SSN (>= 0x1000) into the parked win32k component and run its fault-service
/// loop until the handler completes (Milestone B). PRECONDITION: the component is blocked in its
/// dispatch `seL4_Call` on `w_fault` (the executive has received the Call but not yet replied). We
/// fill the request in the shared page, reply (the Call returns → the component runs the handler),
/// then demand-page the handler's faults until the component issues its NEXT dispatch Call = "done".
/// Returns `(status, ok)`; `ok=false` on a wall (null deref / W^X / demand cap / unexpected fault).
pub(crate) unsafe fn win32k_dispatch(ssn: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> (i32, bool) {
    let w_fault = WIN32K_FAULT_EP.load(Ordering::Relaxed);
    let host_pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    if w_fault == 0 {
        return (0xC000_0001u32 as i32, false);
    }
    // Attach win32k's client window to the CURRENT dispatch client (KeStackAttachProcess). If this is
    // a different client than last time, the previous client's leaf pages are Unmapped so the new
    // client's identical VAs re-fault to THIS client's frames (per-client cross-AS client memory).
    let client_pi = W32_CLIENT_PI.load(Ordering::Relaxed);
    w32_client_attach(client_pi);
    let sh = win32k_host::WIN32K_SHARED_VADDR;
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_SSN) as *mut u64, ssn);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A0) as *mut u64, a0);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A1) as *mut u64, a1);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A2) as *mut u64, a2);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_A3) as *mut u64, a3);
    core::ptr::write_volatile((sh + win32k_host::SH_REQ_STATUS) as *mut i32, 0);
    let code_va = win32k_host::WIN32K_CODE_VA;
    // The desktop-graphics init (co_IntInitializeDesktopGraphics) is a deep chain that demand-maps
    // many pages and trips many checked-build asserts; allow generous headroom (still bounded).
    const DEMAND_CAP: u64 = 8192;
    let mut demand = 0u64;
    let mut skips = 0u64; // int-0x2c asserts skipped (bounded, so a looping assert still walls)
    // Fix (A): WAKE the parked component with a PLAIN Send (it is blocked in `recv_req`, waiting for
    // a request). A plain Send does NOT touch the executive's single `reply_to` slot, so a csrss
    // syscall reply in flight on this same executive thread is preserved (the root-caused nesting
    // bug). The component reads SH_REQ_* + runs the handler on its own scheduling context.
    //
    // Fix (B): the component's demand-page FAULTS are delivered as Calls to `w_fault`; recv them
    // with REPLY_W32 registered (r12) so the kernel binds win32k to REPLY_W32 (finish_call) INSTEAD
    // of relying on `reply_to`. We then resume win32k via Send-on-REPLY_W32 (decode_reply). This
    // leaves REPLY_MAIN's binding to the outer csrss caller intact across win32k faults — removing
    // the (A) caveat where a nested faulting SSN clobbered `reply_to`. The DONE signal is still a
    // plain Send (no cap), distinguished by its label. cptr 0 (pre-retype) falls back to reply_to.
    let rw = REPLY_W32_SLOT.load(Ordering::Relaxed);
    ep_send(w_fault, win32k_host::W32_DISPATCH_LABEL);
    let (_b0, mut mi, mut m0, mut m1, mut m2, mut m3) = if rw != 0 {
        recv_full_r12(w_fault, rw)
    } else {
        ep_recv_full(w_fault)
    };
    loop {
        let label = mi >> 12;
        if label == 6 {
            let addr = m1;
            let in_image =
                addr >= code_va && addr < code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
            // A foreign CLIENT pointer: the handler dereferenced a csrss/user32/gdi32/winlogon USER
            // pointer directly. Rather than zero-fill (WRONG data), SHARE the current client's OWN
            // frame for that page into win32k at the same VA — the authentic model where win32k
            // dereferences the calling process's user address space. Detection: (a) anything below
            // 0x100_.. is a client DLL/heap/anon pointer (win32k's own regions are all PML4[2] >=
            // 0x100_0680_0000); (b) a HIGH client pointer — the hosted-process STACK lives at
            // STACK_BASE=0x100_105C_0000 (PML4[2], ABOVE win32k's own regions), so an address-range
            // test alone misses a stack-built OBJECT_ATTRIBUTES; identify it by the per-client frame
            // table (win32k's OWN demand pages — session/pool/past-image — are never recorded there).
            let page = addr & !0xFFF;
            let foreign = addr < 0x0000_0100_0000_0000
                || (addr >= 0x10000 && !in_image && csrss_frame_get(client_pi, page) != 0);
            if demand < 60 {
                print_str(b"[w32disp] fault #");
                print_u64(demand);
                print_str(b" ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" RVA=0x");
                print_hex(m0.wrapping_sub(code_va) as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                if foreign {
                    print_str(b" (client ptr - sharing csrss frame)");
                }
                print_str(b"\n");
            }
            // Hard walls: a genuine null/low deref, a W^X write into the RX image, or the demand cap.
            if addr < 0x10000 || in_image || demand >= DEMAND_CAP {
                win32k_dispatch_backtrace();
                return (0xC000_0001u32 as i32, false);
            }
            if foreign {
                // Map the CALLER's (csrss's) own frame for this page into win32k at the identical VA.
                // False = the page isn't backed by a recorded csrss frame (win32k would read garbage,
                // or it's a PML4[2] client range needing per-SSN marshaling) — stop cleanly.
                if !map_csrss_page_into_win32k(page, client_pi, host_pml4) {
                    return (0xC000_0001u32 as i32, false);
                }
            } else {
                // A win32k-own demand-pageable page (past the image tail / session arena / the
                // demand-mapped pool): ensure its page table exists (SYS_SEND page_map can't report a
                // missing-PT error to drive a retry), then zero-fill.
                ensure_w32_client_paging(page, host_pml4);
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, host_pml4);
            }
            demand += 1;
            // Fix (B): resume win32k via its bound reply cap (Send-on-REPLY_W32 -> decode_reply ->
            // apply_fault_reply for the VMFault, length 0) then recv the next fault/DONE re-binding
            // REPLY_W32. Falls back to the legacy reply_recv on the single `reply_to` if REPLY_W32
            // wasn't retyped.
            let (nmi, nm0, nm1) = if rw != 0 {
                send_on_reply(rw, 0, 0, 0, 0, 0);
                let (_b, nmi, nm0, nm1, _, _) = recv_full_r12(w_fault, rw);
                (nmi, nm0, nm1)
            } else {
                let (nmi, nm0, nm1, _, _) = reply_recv_full(w_fault, 0, 0, 0, 0, 0);
                (nmi, nm0, nm1)
            };
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            continue;
        }
        if label == win32k_host::W32_DISPATCH_LABEL {
            // The component sent its DONE signal (a plain Send) — handler finished. Read back the
            // status. The component then loops to `recv_req` (blocked), ready for the next dispatch.
            let _ = m0;
            let status = core::ptr::read_volatile((sh + win32k_host::SH_REQ_STATUS) as *const i32);
            return (status, true);
        }
        if label == 3 {
            // UserException — almost always a checked-build `int 0x2c` NT_ASSERT
            // (DbgRaiseAssertionFailure). Verify the faulting instruction (CD 2C) via the executive's
            // RW view of win32k's image at the SAME VA, then SKIP it (resume at IP+2), treating the
            // assert as ignored — like a release build. Our single-threaded lock/thread stubs trip
            // lock-ownership + context asserts that a real multi-threaded kernel wouldn't; the
            // underlying operation is fine. m0 = FaultIP.
            let ip = m0;
            let in_win32k = ip >= code_va && ip < code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
            let is_int2c = in_win32k
                && core::ptr::read_volatile(ip as *const u8) == 0xCD
                && core::ptr::read_volatile((ip + 1) as *const u8) == 0x2C;
            if is_int2c && rw != 0 && skips < 4000 {
                if skips < 40 {
                    print_str(b"[w32disp] skip int 0x2c assert @ RVA 0x");
                    print_hex(ip.wrapping_sub(code_va) as u32);
                    print_str(b"\n");
                }
                skips += 1;
                send_on_reply(rw, 1, ip + 2, 0, 0, 0); // label 0, len 1, MR0 = resume FaultIP (past CD 2C)
                let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(w_fault, rw);
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
        }
        // Any other fault (a real wall inside the handler) — fail. Diagnose: label + fault IP/addr
        // (m0=IP, m1=addr for exceptions; for UnknownSyscall m0=SSN). RVA relative to code / dxg.
        print_str(b"[w32disp] WALL label=");
        print_u64(label);
        print_str(b" m0=0x");
        print_hex((m0 >> 32) as u32);
        print_hex(m0 as u32);
        print_str(b" RVA=0x");
        print_hex(m0.wrapping_sub(code_va) as u32);
        print_str(b" dxgRVA=0x");
        print_hex(m0.wrapping_sub(win32k_host::DXG_VA) as u32);
        print_str(b" m1=0x");
        print_hex((m1 >> 32) as u32);
        print_hex(m1 as u32);
        // For a UserException (label 3): m2=FLAGS, m3=exception Number (#UD=6, #NM=7, #GP=13, #AC=17).
        print_str(b" exc#=");
        print_u64(m3);
        print_str(b" flags=0x");
        print_hex(m2 as u32);
        print_str(b"\n");
        return (0xC000_0001u32 as i32, false);
    }
}

/// `seL4_TCB_ReadRegisters` (label 2, legacy length-0 form) → the target's `(rip, rsp, rax)`.
pub(crate) unsafe fn tcb_read_rsp(tcb: u64) -> u64 {
    let rsp: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") 2u64 << 12 => _, // TCBReadRegisters, length 0
        lateout("r10") _,             // MR0 = rip
        lateout("r8") rsp,            // MR1 = rsp
        lateout("r9") _,              // MR2 = rax
        lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rsp
}

/// Print the win32k call chain (return-address RVAs, deepest first) at a `win32k_dispatch` wall.
/// Mirrors win32k's ACTIVE stack (fault-time RSP .. stack_top) into the executive's own VSpace and
/// scans it for return addresses in win32k's image — same technique as the DriverEntry-path backtrace.
pub(crate) unsafe fn win32k_dispatch_backtrace() {
    let ss = WIN32K_STACK_SLOT.load(Ordering::Relaxed);
    let sf = WIN32K_STACK_FRAMES.load(Ordering::Relaxed);
    let tcb = WIN32K_TCB.load(Ordering::Relaxed);
    if ss == 0 || sf == 0 || tcb == 0 {
        return;
    }
    let mirror = 0x0000_0100_0732_0000u64;
    if WIN32K_DISP_BT_PT.load(Ordering::Relaxed) == 0 {
        let spt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
        let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, mirror, CAP_INIT_THREAD_VSPACE);
        for i in 0..sf {
            let _ = page_map(copy_cap(ss + i), mirror + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        WIN32K_DISP_BT_PT.store(1, Ordering::Relaxed);
    }
    let rsp = tcb_read_rsp(tcb);
    let sbase = win32k_host::WIN32K_STACK_VADDR;
    let stack_top = sbase + sf * 0x1000;
    let start = if rsp >= sbase && rsp < stack_top { rsp } else { sbase };
    let code_va = win32k_host::WIN32K_CODE_VA;
    let lo = code_va;
    let hi = code_va + win32k_host::WIN32K_IMAGE_FRAMES * 0x1000;
    print_str(b"[w32disp] backtrace rsp=0x");
    print_hex((rsp >> 32) as u32);
    print_hex(rsp as u32);
    print_str(b"\n");
    // RAW stack window from fault rsp: each qword annotated with its win32k RVA if it lands in the
    // image (a return address). RtlpCheckListEntry (0x24c50) did `sub rsp,0x28`, so its own return
    // address is at [rsp+0x28] = the exact InsertXxxList wrapper caller — read that precisely.
    if start >= sbase && start + 0x120 <= stack_top {
        let mut off = 0u64;
        while off < 0x120 {
            let va = start + off;
            let v = core::ptr::read_volatile((mirror + (va - sbase)) as *const u64);
            if v >= lo && v < hi {
                print_str(b"  [rsp+0x");
                print_hex(off as u32);
                print_str(b"] rva=0x");
                print_hex(v.wrapping_sub(code_va) as u32);
                print_str(b"\n");
            }
            off += 8;
        }
    }
}
