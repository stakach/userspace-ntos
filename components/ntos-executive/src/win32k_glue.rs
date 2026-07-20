//! `win32k_glue` — the executive-side win32k client plumbing: RO-map win32k's
//! USER heap into csrss, per-client cross-AS page attach (w32_*), the DirectX/
//! ftfd/framebuffer driver loaders, and the win32k syscall dispatch + backtrace.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

/// RO-map win32k's global USER heap arena ([`win32k_subsystem::WIN32K_HEAP_VADDR`], where gpsi /
/// gHandleTable / the USER handle-entry array live) into the caller's (csrss's) VSpace at
/// [`win32k_subsystem::CSRSS_W32_SHARED_VA`], so the Win32 client can dereference the SHAREDINFO the
/// USERCONNECT points at. Maps a fresh copy of each arena frame RO+NX (win32k keeps its own RW
/// copy — coherent shared memory). One-time (guarded). Returns the server→client delta
/// (`WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`) the marshaling applies to the siClient pointers.
pub(crate) unsafe fn map_win32k_heap_into_csrss(pml4: u64, pi: usize) -> u64 {
    let delta = win32k_subsystem::WIN32K_HEAP_VADDR - win32k_subsystem::CSRSS_W32_SHARED_VA;
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
    let frames = win32k_subsystem::WIN32K_HEAP_FRAMES;
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
            win32k_subsystem::CSRSS_W32_SHARED_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(heap_base + i);
        let _ = page_map(cp, win32k_subsystem::CSRSS_W32_SHARED_VA + i * 0x1000, RO_NX, pml4);
    }
    print_str(b"[win32k-svc] RO-mapped win32k USER heap into csrss @0x");
    print_hex(win32k_subsystem::CSRSS_W32_SHARED_VA as u32);
    print_str(b" (delta=0x");
    print_hex((delta >> 32) as u32);
    print_hex(delta as u32);
    print_str(b")\n");
    delta
}

/// RO-map win32k's POOL arena ([`win32k_subsystem::WIN32K_POOL_VADDR`] — where the DESKTOP body + its
/// DESKTOPINFO are `pool_alloc`ed) into the GUI client `pi`'s VSpace at
/// [`win32k_subsystem::CSRSS_W32_POOL_VA`], so user32's client-side `DesktopPtrToUser` can read the
/// bound DESKTOPINFO (`pci->pDeskInfo->pvDesktopBase/pvDesktopLimit`) — the desktop-heap client-window
/// mapping (the DESKTOPINFO lives in the POOL, NOT the RO-mapped USER heap). Per-pi guarded, mirroring
/// [`map_win32k_heap_into_csrss`]. Returns the pool server→client delta.
pub(crate) unsafe fn map_win32k_pool_into_csrss(pml4: u64, pi: usize) -> u64 {
    let delta = win32k_subsystem::WIN32K_POOL_VADDR - win32k_subsystem::CSRSS_W32_POOL_VA;
    // Validate the frame base BEFORE consuming the per-pi guard bit: a base-not-yet-stored call must
    // NOT latch the bit (it would leave the POOL unmapped on a later real call → an unmapped
    // pci->pDeskInfo deref). On the live path pool_base is stored at bring-up before any dispatch.
    let pool_base = WIN32K_POOL_FRAME_BASE.load(Ordering::Relaxed);
    if pool_base == 0 {
        return delta;
    }
    let bit = 1u64 << pi;
    if WIN32K_POOL_CLIENT_MAPPED.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return delta; // already mapped into this process's VSpace
    }
    const RO_NX: u64 = 2 | PAGE_EXECUTE_NEVER;
    let frames = win32k_subsystem::WIN32K_POOL_FRAMES;
    for p in 0..(frames + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_subsystem::CSRSS_W32_POOL_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(pool_base + i);
        let _ = page_map(cp, win32k_subsystem::CSRSS_W32_POOL_VA + i * 0x1000, RO_NX, pml4);
    }
    print_str(b"[win32k-svc] RO-mapped win32k POOL into csrss @0x");
    print_hex(win32k_subsystem::CSRSS_W32_POOL_VA as u32);
    print_str(b" (pool-delta=0x");
    print_hex((delta >> 32) as u32);
    print_hex(delta as u32);
    print_str(b")\n");
    delta
}

/// ★ DIALOG BATCH 3 — RO-map the GDI shared handle table into GUI client `pi`'s VSpace at
/// [`win32k_subsystem::GDI_SHARED_TABLE_VA`]. Client-side gdi32 validates every GDI handle through
/// `GdiSharedHandleTable[handle & 0xffff]` (base = `PEB->GdiSharedHandleTable`, PEB+0xf8). In real
/// Windows win32k allocates this table from a GdiPool section + RO-maps it into every GUI process; our
/// host allocates the frames ONCE (globally, zero-initialized — a zero `entry.Type@0xc` mismatches
/// gdi32's type-bits check → gdi32 takes its `invalid handle` path instead of NULL-derefing at RVA
/// 0x535a), then RO-maps that same table into each client. Per-pi guarded (mirrors
/// [`map_win32k_pool_into_csrss`]). Returns the client-side base VA (== GDI_SHARED_TABLE_VA).
pub(crate) unsafe fn map_gdi_shared_handle_table_into_client(pml4: u64, pi: usize) -> u64 {
    const RW_NX_L: u64 = 3 | PAGE_EXECUTE_NEVER; // read-write, non-executable (executive scratch)
    let frames = win32k_subsystem::GDI_SHARED_TABLE_FRAMES;
    // Allocate + zero-init the table frames once (shared into any GUI client thereafter).
    let mut base = GDI_SHARED_TABLE_FRAME_BASE.load(Ordering::Relaxed);
    if base == 0 {
        // Allocate `frames` contiguous frame caps, then zero them by mapping the whole run into a
        // dedicated executive-side 2 MiB scratch window (its own fresh PT — frames < 512 fit one PT)
        // and memset-ing once. GDI_SHARED_TABLE_VA is a CLIENT VA; the frames are copy_cap'ed RO into
        // the client afterward, and win32k never writes them, so the zero fill is durable.
        const GDI_ZERO_SCR: u64 = 0x0000_0100_1400_0000; // dedicated 2 MiB scratch window, own PT
        debug_assert!(frames <= 512);
        let scr_pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, scr_pt);
        let _ = paging_struct_map(scr_pt, LBL_X86_PAGE_TABLE_MAP, GDI_ZERO_SCR, CAP_INIT_THREAD_VSPACE);
        let first = alloc_frame();
        base = first;
        let _ = page_map(first, GDI_ZERO_SCR, RW_NX_L, CAP_INIT_THREAD_VSPACE);
        for i in 1..frames {
            // Frame caps are handed out sequentially (alloc_frame bumps a slot), so the run is
            // contiguous; map each at its own scratch page (no VA reuse → no occupied-slot failure).
            let f = alloc_frame();
            let _ = page_map(f, GDI_ZERO_SCR + i * 0x1000, RW_NX_L, CAP_INIT_THREAD_VSPACE);
        }
        core::ptr::write_bytes(GDI_ZERO_SCR as *mut u8, 0, (frames * 0x1000) as usize);
        GDI_SHARED_TABLE_FRAME_BASE.store(base, Ordering::Relaxed);
        print_str(b"[win32k-svc] allocated GDI shared handle table (0x");
        print_hex(frames as u32);
        print_str(b" frames, zero-init)\n");
    }
    let bit = 1u64 << pi;
    if GDI_SHARED_TABLE_MAPPED.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return win32k_subsystem::GDI_SHARED_TABLE_VA; // already mapped into this process's VSpace
    }
    const RO_NX: u64 = 2 | PAGE_EXECUTE_NEVER; // read-only, non-executable
    // The 1 GiB PD covering 0x8000_0000..0xC000_0000 already exists in the client; the table window is
    // fresh, so allocate + map one PT per 2 MiB sub-range up front (page_map is fire-and-forget).
    for p in 0..(frames + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_subsystem::GDI_SHARED_TABLE_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(base + i);
        let _ = page_map(cp, win32k_subsystem::GDI_SHARED_TABLE_VA + i * 0x1000, RO_NX, pml4);
    }
    print_str(b"[win32k-svc] RO-mapped GDI shared handle table into pi 0x");
    print_hex(pi as u32);
    print_str(b" @0x");
    print_hex(win32k_subsystem::GDI_SHARED_TABLE_VA as u32);
    print_str(b"\n");
    win32k_subsystem::GDI_SHARED_TABLE_VA
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
/// to load) and win32k (W^X, to run). Reuses [`win32k_subsystem::load_driver_into`]. `dxgthk_base` names
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
    let res = win32k_subsystem::load_driver_into(
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
    if load_one_driver(DXGTHKBUF_VADDR, win32k_subsystem::DXGTHK_VA, win32k_subsystem::DXGTHK_LOAD_FRAMES, host_pml4, 0)
        .is_none()
    {
        print_str(b"[win32k-svc] dxgthk load failed\n");
        return;
    }
    match load_one_driver(
        DXGBUF_VADDR,
        win32k_subsystem::DXG_VA,
        win32k_subsystem::DXG_LOAD_FRAMES,
        host_pml4,
        win32k_subsystem::DXGTHK_VA,
    ) {
        Some((entry, expdir, len)) => {
            win32k_subsystem::record_dxg(entry, expdir, len);
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
        win32k_subsystem::FTFD_VA,
        win32k_subsystem::FTFD_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, _expdir, len)) => {
            let patched = win32k_subsystem::patch_win32k_ftfd_imports(win32k_subsystem::FTFD_VA);
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
        win32k_subsystem::FRAMEBUF_VA,
        win32k_subsystem::FRAMEBUF_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, expdir, len)) => {
            win32k_subsystem::record_framebuf(entry, expdir, len);
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
            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, win32k_subsystem::WIN32K_FB_VA + p * 0x20_0000, host_pml4);
        }
        for i in 0..count {
            let _ = page_map(copy_cap(base + i), win32k_subsystem::WIN32K_FB_VA + i * 0x1000, RW_NX, host_pml4);
        }
        print_str(b"[win32k-svc] mapped BOOTBOOT framebuffer into win32k: ");
        print_u64(count);
        print_str(b" frames @ WIN32K_FB_VA=0x");
        print_hex((win32k_subsystem::WIN32K_FB_VA >> 32) as u32);
        print_hex(win32k_subsystem::WIN32K_FB_VA as u32);
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
    win32k_dispatch_wide(ssn, a0, a1, a2, a3, 0, 0)
}

/// Like [`win32k_dispatch`] but marshals the win64 STACK-ARG TAIL for WIDE SSNs (args 5+). The x64
/// win64 ABI passes args 1-4 in rcx/rdx/r8/r9 and args 5..N on the CALLER's stack at
/// `[rsp+0x28], [rsp+0x30], …` (rsp = the syscall-entry stack pointer). `caller_sp` is the client's
/// stack pointer at the syscall (get_recv_mr(16)); `nargs` is the handler's TOTAL arg count. For
/// `nargs<=4` this is byte-identical to the old register-only dispatch. For a wide SSN (e.g.
/// NtUserCreateWindowEx = 15 args) we read stack args 5..N from the client's stack via
/// `smss_stack_read` and stage them into SH_REQ_A4.. so win32k's `dispatch_ssn` can rebuild a real
/// N-arg win64 call — the FIX for the garbage-hMenu wall (BATCH 44).
pub(crate) unsafe fn win32k_dispatch_wide(
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    nargs: u64,
) -> (i32, bool) {
    let w_fault = WIN32K_FAULT_EP.load(Ordering::Relaxed);
    let host_pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    if w_fault == 0 {
        return (0xC000_0001u32 as i32, false);
    }
    // ── REQUEST FILL (caller-owned, exactly as the FSD `dispatch_irp` fills the IRP before the pump).
    // Attach win32k's client window to the CURRENT dispatch client (KeStackAttachProcess). If this is
    // a different client than last time, the previous client's leaf pages are Unmapped so the new
    // client's identical VAs re-fault to THIS client's frames (per-client cross-AS client memory).
    let client_pi = W32_CLIENT_PI.load(Ordering::Relaxed);
    w32_client_attach(client_pi);
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_SSN) as *mut u64, ssn);
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A0) as *mut u64, a0);
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A1) as *mut u64, a1);
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A2) as *mut u64, a2);
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A3) as *mut u64, a3);
    // Stage the win64 STACK-ARG TAIL (args 5..N) from the client's stack. `nargs<=4` (or a 0-sp
    // self-test dispatch) leaves SH_REQ_NARGS=0 → win32k's dispatch_ssn takes the register-only path.
    let staged = if nargs > 4 && caller_sp != 0 { nargs.min(16) } else { 0 };
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_NARGS) as *mut u64, staged);
    let mut i = 4u64;
    while i < staged {
        // arg (i+1) is the (i-3)-th stack slot at [rsp + 0x28 + (i-4)*8].
        let v = crate::img_spawn::smss_stack_read(caller_sp + 0x28 + (i - 4) * 8);
        core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A4 + (i - 4) * 8) as *mut u64, v);
        i += 1;
    }
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_STATUS) as *mut i32, 0);

    // ── FAULT LOOP (shared): drive win32k's dispatch through the unified `component_pump`, all win32k
    // capability gates TRUE. Fix (A) [DONE via a plain Send, distinguished by label] + Fix (B) [nested
    // faults answered through the per-caller REPLY_W32 cap so REPLY_MAIN's binding to the outer csrss
    // caller survives] + (f) demand-fault client-frame sharing + (g) int-0x2c assert-skip + the
    // 8192-page demand cap all live in the pump behind these flags — no logic deleted, only relocated.
    let rw = REPLY_W32_SLOT.load(Ordering::Relaxed);
    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: w_fault,
        pml4: host_pml4,
        code_va: win32k_subsystem::WIN32K_CODE_VA,
        image_frames: win32k_subsystem::WIN32K_IMAGE_FRAMES,
        shared_va: sh,
        dispatch_label: win32k_subsystem::W32_DISPATCH_LABEL,
        // The desktop-graphics init (co_IntInitializeDesktopGraphics) is a deep chain that demand-maps
        // many pages and trips many checked-build asserts; allow generous headroom (still bounded).
        demand_cap: 8192,
        trace_faults: false,
        wake_first: true, // win32k is parked in `recv_req` → wake it with a leading plain Send
        reply_cap: rw,
        client_pi,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Syscall,
            client_attach: true,
            usermode_callback: true,
            wide_arg_marshal: true,
            assert_skip: true,
            nested_reply_cap: true,
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    (pr.status, pr.completed)
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

/// `seL4_TCB_ReadRegisters` (label 2, legacy length-0 form) → the target's saved RIP (MR0).
/// Used to sample a PARKED thread's instruction pointer for spin-diagnosis (BATCH 10).
pub(crate) unsafe fn tcb_read_rip(tcb: u64) -> u64 {
    let rip: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") 2u64 << 12 => _, // TCBReadRegisters, length 0
        lateout("r10") rip,           // MR0 = rip
        lateout("r8") _,              // MR1 = rsp
        lateout("r9") _,              // MR2 = rax
        lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rip
}

/// `seL4_TCB_ReadRegisters` (length=20) → the target's full GPR set in `seL4_UserContext` order:
/// `[rip, rsp, rflags, rax, rbx, rcx, rdx, rsi, rdi, rbp, r8..r15, fs_base, gs_base]`. The first 4
/// words come back in r10/r8/r9/r15; words 4..20 spill into the invoker's IPC buffer (readable via
/// `get_recv_mr`). Valid rcx/r11 only for #exception-captured threads (`use_iretq_resume`), which an
/// int3-stopped hosted thread is. Used to recover the EXCEPTION_RECORD ptr (RCX) at RtlRaiseException.
pub(crate) unsafe fn tcb_read_regs20(tcb: u64, out: &mut [u64; 20]) {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") (2u64 << 12) | 20 => _, // TCBReadRegisters, msginfo.length=20 (label<<12 | len)
        inout("r10") 0u64 => r0,   // MR0 in / word 0 (rip) out
        inout("r8") 20u64 => r1,   // MR1 = count(20) in / word 1 (rsp) out
        lateout("r9") r2,          // word 2 (rflags)
        lateout("r15") r3,         // word 3 (rax)
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    out[0] = r0;
    out[1] = r1;
    out[2] = r2;
    out[3] = r3;
    // Words 4..20 were spilled into the executive's IPC buffer at MR slot i.
    for (i, slot) in out.iter_mut().enumerate().take(20).skip(4) {
        *slot = crate::get_recv_mr(i);
    }
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
    let sbase = win32k_subsystem::WIN32K_STACK_VADDR;
    let stack_top = sbase + sf * 0x1000;
    let start = if rsp >= sbase && rsp < stack_top { rsp } else { sbase };
    let code_va = win32k_subsystem::WIN32K_CODE_VA;
    let lo = code_va;
    let hi = code_va + win32k_subsystem::WIN32K_IMAGE_FRAMES * 0x1000;
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
