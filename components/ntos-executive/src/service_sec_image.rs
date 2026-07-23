//! `service_sec_image` — the per-process SEC_IMAGE demand-fault service loop.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;
use nt_io_abi::major;

const SEC_IMAGE_FAULT_CAP: u64 = 15000;

/// Populate one winlogon thread's client-side win32 state from the desktop facts published by the
/// live win32k dispatch thread. `Win32ThreadInfo` is an opaque server THREADINFO identity; the
/// inline CLIENTINFO stores the client mapping of DESKTOPINFO and the USER-heap pointer delta.
unsafe fn seed_winlogon_thread_client_info(teb_alias: u64, pml4: u64) -> Option<(u64, u64, u64)> {
    let server_deskinfo = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_DESKINFO) as *const u64,
    );
    let pti = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_PTI) as *const u64,
    );
    if server_deskinfo == 0 || pti == 0 {
        return None;
    }

    let pool_delta = win32k_glue::map_win32k_pool_into_csrss(pml4, 2);
    let user_delta = win32k_subsystem::WIN32K_HEAP_VADDR
        - win32k_subsystem::CSRSS_W32_SHARED_VA;
    let client_deskinfo = server_deskinfo.checked_sub(pool_delta)?;
    core::ptr::write_volatile((teb_alias + 0x78) as *mut u64, pti);
    core::ptr::write_volatile((teb_alias + 0x820) as *mut u64, client_deskinfo);
    core::ptr::write_volatile((teb_alias + 0x828) as *mut u64, user_delta);
    Some((client_deskinfo, pti, user_delta))
}

unsafe fn observe_winlogon_completed_dispatch(
    dispatch: win32k_glue::CompletedWin32kDispatch,
    filled_pages: &mut [u64; 512],
    faults: usize,
    scratch_base: u64,
) {
    if dispatch.ssn != 0x1077 || dispatch.status == 0 {
        return;
    }
    let hwnd = dispatch.status as u32 as u64;
    let class = dispatch.args[1];
    let name = dispatch.args[3];
    let sas_hwnd = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND) as *const u64,
    );
    if sas_hwnd != 0 && hwnd == sas_hwnd {
        if WINLOGON_SAS_MILESTONE.swap(1, Ordering::Relaxed) == 0 {
            print_str(b"[wl-main] winlogon created SAS window (completed NtUserCreateWindowEx -> HWND 0x");
            print_hex(hwnd as u32);
            print_str(b")\n");
        }
        return;
    }
    if WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) == 0 {
        return;
    }

    if class != nt_user_callback::WC_DIALOG_ATOM {
        return;
    }
    WINLOGON_DIALOG_WINDOWS.fetch_add(1, Ordering::Relaxed);
    if WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) == 0
        || WINLOGON_KEY_OPENED.load(Ordering::Relaxed)
            <= WINLOGON_KEY_OPENED_AT_INJECT.load(Ordering::Relaxed)
        || name == 0
    {
        return;
    }

    let mut raw = [0u8; 16];
    let descriptor_read = img_spawn::client_copyin_mapped(
        2,
        name,
        &mut raw,
        filled_pages,
        faults,
        scratch_base,
    );
    let descriptor = descriptor_read
        .then(|| nt_user_callback::LargeUnicodeStringDescriptor::parse(&raw))
        .and_then(Result::ok);
    let raw_length = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let raw_maximum_and_ansi = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let raw_buffer = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    let source = if descriptor.is_some()
        && img_spawn::smss_mirror(raw_buffer, raw_length as u64).is_some()
    {
        1
    } else if descriptor.is_some()
        && img_spawn::scratch_for(raw_buffer, filled_pages, faults, scratch_base).is_some()
    {
        2
    } else if descriptor.is_some() && csrss_frame_get(2, raw_buffer & !0xfff) != 0 {
        3
    } else if descriptor.is_some() && client_copyin_frame_get(2, raw_buffer & !0xfff) != 0 {
        4
    } else {
        0
    };
    let mut bytes = [0u8; nt_user_callback::MAX_DIALOG_CAPTION_CODE_UNITS * 2];
    let mut units = [0u16; nt_user_callback::MAX_DIALOG_CAPTION_CODE_UNITS];
    let mut count = 0usize;
    let mut caption_read = false;
    if let Some(descriptor) = descriptor {
        let length = descriptor.length_bytes as usize;
        caption_read = img_spawn::client_copyin_mapped(
            2,
            descriptor.buffer,
            &mut bytes[..length],
            filled_pages,
            faults,
            scratch_base,
        );
        if caption_read {
            count = nt_user_callback::decode_utf16le_bounded(&bytes[..length], &mut units)
                .unwrap_or(0);
        }
    }
    let style = smss_stack_read(dispatch.caller_sp + 0x28) as u32;
    let top_level = style & 0x8000_0000 != 0 && style & 0x4000_0000 == 0;
    let caption_match = caption_read && units[..count] == nt_user_callback::IDD_LOGON_CAPTION;
    let session = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION) as *const u64,
    );
    let correlated = if caption_read {
        winlogon_dialog_capture_idd_logon(
            session,
            hwnd,
            class,
            &units[..count],
            top_level,
            true,
        )
    } else {
        false
    };
    print_str(b"[dialog-caption] hwnd=0x");
    print_hex(hwnd as u32);
    print_str(b" descriptor-read=");
    print_u64(descriptor_read as u64);
    print_str(b" parse=");
    print_u64(descriptor.is_some() as u64);
    print_str(b" len=");
    print_u64(raw_length as u64);
    print_str(b" maxansi=0x");
    print_hex(raw_maximum_and_ansi);
    print_str(b" buf=0x");
    print_hex((raw_buffer >> 32) as u32);
    print_hex(raw_buffer as u32);
    print_str(b" source=");
    print_u64(source);
    print_str(b" caption-read=");
    print_u64(caption_read as u64);
    print_str(b" units=");
    print_u64(count as u64);
    print_str(b" Logon=");
    print_u64(caption_match as u64);
    print_str(b" top-level=");
    print_u64(top_level as u64);
    print_str(b" correlated=");
    print_u64(correlated as u64);
    print_str(b"\n");
}

unsafe fn observe_completed_dialog_modal_dispatch(
    dispatch: win32k_glue::CompletedWin32kDispatch,
    badge: u64,
    tid: u64,
) {
    if winlogon_dialog_modal_expected_ssn() != dispatch.ssn
        || !winlogon_dialog_modal_thread_matches(badge, tid, dispatch.args[0])
    {
        return;
    }
    let hwnd = smss_stack_read(dispatch.args[0]);
    let message = smss_stack_read(dispatch.args[0] + 8) as u32;
    let _ = winlogon_dialog_modal_observe(dispatch.ssn, dispatch.status, hwnd, message);
}

/// Service a SEC_IMAGE process: on each VMFault, fault the faulting image page in BY RVA from
/// the PE file (scratch frames rotate from `scratch_base`); on SSN_DONE, capture the verdict.
/// Faults are routed to the main image (at PE_LOAD_BASE) or, if present, a second image `ntdll`
/// at `(base, pe)` — so smss's resolved ntdll calls fault ntdll's pages in and EXECUTE. SAFE
/// STOP: halt (don't loop) on a fault outside BOTH images (a null deref / bad address), a
/// non-VMFault (#GP), or a fault cap. Returns (verdict, faults, first, stop, ntdll_faults).
pub(crate) unsafe fn service_sec_image(
    fault_ep: u64,
    pml4: u64,
    pe: &nt_pe_loader::PeFile,
    scratch_base: u64,
    ntdll: Option<(u64, &nt_pe_loader::PeFile)>,
) -> (u64, u64, u64, u64, u64, u64) {
    loader_trace_clear();
    let img_end = PE_LOAD_BASE + image_extent(pe);
    let (nt_base, nt_end) = match ntdll {
        Some((b, npe)) => (b, b + image_extent(npe)),
        None => (0, 0),
    };
    let mut verdict = 0u64;
    let mut faults = 0u64;
    // Per-process demand-fault backstop (see the use sites). BATCH-22: raised from 2000 now that the
    // persistent scratch VA is decoupled from this count (bounded ≤256 slots) — it's a frame-budget /
    // runaway guard only, sized to let lsass's full LSA-init DLL tree page in within the frame pool.
    // Per-process fresh-fill ceiling. Each fresh fill consumes a UNIQUE monotonic scratch slot
    // (`scratch_base + faults*0x1000`), so this must stay under the per-process scratch window
    // (now 64 MiB = 16384 slots, see map_demand_scratch_pts). (A) EAGER IMAGE-MAP front-loads a
    // process's whole DLL tree, so raised 6000→15000 (headroom under 16384) to let lsass's full
    // LSA-init tree page in eagerly without hitting the cap. Runaway/frame-pool guard only.
    let mut first = 0u64;
    let mut stop = 0u64;
    let mut ntfaults = 0u64;
    let mut stop_ssn = 0u64;
    let mut iters = 0u64;
    let mut dbgsvc = 0u64;
    // page VA filled at each fault index → its persistent executive scratch is
    // scratch_base + index*0x1000. Lets a syscall handler copy OUT to any already-mapped image
    // page (e.g. an ntdll .data global), not just the stack (which has its own mirror).
    // Working buffer for the current pi's demand-filled page VAs — a STATIC (not a 4 KiB stack local)
    // so the 5th hosted process doesn't pressure the rootserver stack on the deep FS-walk call
    // chain (see FILLED_WORK). Loaded from / saved to `pfilled[pi]` around each dispatch below.
    let filled_pages: &mut [u64; 512] = &mut *core::ptr::addr_of_mut!(FILLED_WORK);
    // DIAG ring buffer of the last serviced SSNs, to locate the silent 0x80000005.
    let mut ssn_ring = [0u16; 32];
    let mut ssn_ring_badge = [0u8; 32];
    // winlogon-main-only ring (badge==WINLOGON_BADGE) — isolate winlogon's sequence from the
    // services (badge 6) noise that dominates the shared ring, to diagnose the StartLsass wall.
    let mut wl_ring = [0u16; 48];
    let mut wl_ri = 0usize;
    let mut ssn_ri = 0usize;
    // Distinct fake handles for objects we don't model yet (ports/threads/events/sections) now live
    // on `nt_handler.next_handle` (Workstream A group A) — a single monotonic source shared by the
    // migrated create-handle handlers and the remaining ladder cases (NtCreateSection/Process/File).
    // Track the handles smss uses to launch csrss.exe: the file handle it opens (NtOpenFile), and
    // the SEC_IMAGE section it creates from it (NtCreateSection). NtCreateProcess (next step) will
    // spawn the real process from the section. Parse the staged csrss PE up front to prove it's
    // available (FILEBUF tail; size at STORAGE_SHARED+0x3c).
    let mut csrss_file_handle = 0u64;
    let mut csrss_section_handle = 0u64;
    let mut csrss_process_handle = 0u64;
    // winlogon.exe (the 3rd hosted process, smss's SmpExecuteInitialCommand initial command): the
    // file/section handles smss opens+creates for it, and its process handle once spawned. Same roles
    // as the csrss_* trio; the parsed PE is `winlogon_pe` below.
    let mut winlogon_file_handle = 0u64;
    let mut winlogon_section_handle = 0u64;
    let mut winlogon_process_handle = 0u64;
    // services.exe (the 4th hosted process, winlogon's Win32 CreateProcessW target): the file/section
    // handles winlogon opens+creates for it. Same roles as the csrss_/winlogon_ trios; `services_pe`
    // is parsed above. `services_process_handle` is set by the NtCreateProcessEx spawn (badge 4).
    let mut services_file_handle = 0u64;
    let mut services_section_handle = 0u64;
    let mut services_process_handle = 0u64;
    // lsass.exe (the 5th hosted process, winlogon's StartLsass CreateProcessW target).
    let mut lsass_file_handle = 0u64;
    let mut lsass_section_handle = 0u64;
    let mut lsass_process_handle = 0u64;
    // csrss's loadable DLLs (csrsrv + the ServerDlls basesrv/winsrv) are tracked by the generic
    // nt-dll-registry, built below once their PEs are parsed. The shared page-directory covering the
    // 0x8000_0000 1 GiB range (the compact DLL arena lives in it) is created on the first map.
    // Per-process (indexed by pi: 0=smss, 1=csrss, 2=winlogon): the DLL page-directory once-flag +
    // a bitset of which arena PT windows are reserved in that process's VSpace. Compact DLLs may
    // share a PT and large DLLs may span several.
    let mut dll_pd_created = [false; MAX_PI];
    let mut dll_pt_bits = [[0u64; DLL_ARENA_PT_WORDS]; MAX_PI];
    // csrss's ANONYMOUS section (no file backing) — its CSR SharedSection shared memory. Tracked by
    // handle + requested size; NtMapViewOfSection reserves a VA range and the fault router
    // demand-pages ZERO frames into it (commit-on-touch).
    let mut csrss_anon_section_handle = 0u64;
    let mut csrss_anon_base = 0u64;
    let mut csrss_anon_size = 0u64;
    // The named NLS section \Nls\NlsSectionCP20127 (US-ASCII code-page table) csrss's Win32 client
    // stack maps during a DllMain. NtOpenSection records the handle; NtMapViewOfSection maps the
    // staged c_20127.nls frames into csrss.
    let mut nls_section_handle = 0u64;
    // Only the LIVE smss run (ntdll present) launches csrss/winlogon; the earlier demo SEC_IMAGE call
    // has no FS/pool, so skip the read there. The two hosted-process EXEs csrss.exe + winlogon.exe
    // (like services.exe/lsass.exe below) are sourced BY PATH from the real \reactos FS into the
    // demand-load pool — NO fixed buffer. Each is relocated to its load base (PE_LOAD_BASE) + its
    // OptionalHeader.ImageBase patched to match — so ntdll doesn't try to RELOCATE THE EXE
    // (ldrinit.c:2409, the EXE-reloc path, is UNIMPLEMENTED in ReactOS → STATUS_INVALID_IMAGE_FORMAT).
    // The relocation runs on the pool `*_va`; the demand-fault router reads the relocated bytes via the
    // PeFile slice.
    let (csrss_pe, csrss_va) = if ntdll.is_some() {
        load_dll_from_fs(b"reactos\\system32\\csrss.exe", b"csrss.exe")
    } else {
        (None, 0)
    };
    if let Some(ref cpe) = csrss_pe {
        apply_relocations_to_buf(cpe, csrss_va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((csrss_va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((csrss_va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
    }
    // winlogon.exe — smss's SmpExecuteInitialCommand initial command (the 3rd hosted process).
    let (winlogon_pe, winlogon_va) = if ntdll.is_some() {
        load_dll_from_fs(b"reactos\\system32\\winlogon.exe", b"winlogon.exe")
    } else {
        (None, 0)
    };
    if let Some(ref wpe) = winlogon_pe {
        apply_relocations_to_buf(wpe, winlogon_va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((winlogon_va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((winlogon_va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
    }
    // services.exe — the 4th hosted process, spawned by winlogon's Win32 CreateProcessW
    // (StartServicesManager). Sourced BY PATH from the FS pool (P7-A — no fixed buffer needed); on
    // the demo run (ntdll=None) it stays None (services only spawns on the live run). Same EXE-reloc
    // + ImageBase patch as csrss/winlogon so ntdll doesn't hit the unimplemented EXE-reloc path.
    let (services_pe, services_va) = if ntdll.is_some() {
        load_dll_from_fs(b"reactos\\system32\\services.exe", b"services.exe")
    } else {
        (None, 0)
    };
    if let Some(ref spe) = services_pe {
        apply_relocations_to_buf(spe, services_va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((services_va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((services_va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
    }
    // lsass.exe — the 5th hosted process, spawned by winlogon's StartLsass Win32 CreateProcessW.
    // Sourced BY PATH from the FS pool. Same EXE-reloc + ImageBase patch as services.
    let (lsass_pe, lsass_va) = if ntdll.is_some() {
        load_dll_from_fs(b"reactos\\system32\\lsass.exe", b"lsass.exe")
    } else {
        (None, 0)
    };
    if let Some(ref lpe) = lsass_pe {
        apply_relocations_to_buf(lpe, lsass_va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((lsass_va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((lsass_va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
    }
    // Generic DLL registry: the loadable DLLs each hosted process's ntdll loader resolves +
    // demand-pages — csrss's static import csrsrv.dll + its CsrLoadServerDll ServerDlls
    // basesrv/winsrv, the shared Win32 client stack (kernel32/user32/gdi32/rpcrt4/…), winlogon's
    // userenv/mpr, and lsass's lsasrv/samsrv/msv1_0. ALL are sourced BY PATH from the real \reactos
    // FS into the demand-load pool — NO hardcoded per-DLL block, NO fixed staging buffer, NO
    // STORAGE_SHARED offset: a single DATA-DRIVEN table (seed stem, System32 leaf) drives the load.
    // Adding a served DLL = one row here. ORDER IS LOAD-BEARING: it is the registration order, which
    // is the base-assignment order — csrsrv MUST stay first so it keeps registry base 0x8000_0000 =
    // its preferred ImageBase (relocation delta 0, text byte-identical + shared read-only across
    // processes); the rest are loader-relocated to their fixed slots. All slots share the 1 GiB
    // 0x8000_0000 PDPT range. Load-flow DECISIONS (name/handle/VA lookups + SECTION_IMAGE_INFORMATION)
    // run through host-tested nt-dll-registry; the executive keeps the parsed PEs parallel (same
    // index) for the effectful demand-fill. (winsrv is ~100 pages — the root CNode is an XL page under
    // extern-rootserver, so the caps fit.) These load at BOOT (below the service_sec_image heap mark)
    // rather than on the fly during a syscall because the per-syscall bump-heap reset would rewind any
    // registry Vec growth / pool alloc made ABOVE the mark; loading them here keeps every DLL's parsed
    // PE + registry slot persistent (see project_full_fs Part 2 for the demand-load-during-syscall
    // rework this still awaits).
    // Part 3 — TRUE syscall-time demand-load. The eager per-DLL `DLL_TABLE` is GONE: DLLs load PURELY
    // ON-DEMAND from the real \reactos FS when a hosted process's loader first requests one (a
    // `reg.resolve_name` MISS in NtOpenFile → `fs_loader::demand_load_dll`). At boot we only:
    //   (1) PIN csrsrv at slot 0 (base 0x8000_0000 = its preferred ImageBase, relocation delta 0 →
    //       byte-identical shared text, loader never relocates it). Demand-load assigns slots in
    //       loader-request order, which can't guarantee csrsrv lands at slot 0, so this ONE entry is a
    //       documented pin (DLL_PIN_COUNT). No other DLL cares about its base (all get relocated).
    //   (2) RESERVE the remaining metadata slots empty (per-pi handle stores pre-allocated below
    //       the heap_mark → the on-demand `activate` at syscall time needs NO heap growth, surviving
    //       the per-syscall bump-heap reset). `dll_pe_store` is pre-sized below the mark, so an
    //       on-demand `dll_pe_store[slot] = Some(pe)` is likewise reset-safe. The pool bytes live
    //       in the cap-mapped POOL arena (atomic POOL_NEXT), reset-safe too.
    // Adding a new DLL (userinit/explorer/shell32/…) now needs NO edit here — it demand-loads into a
    // free reserved slot. NO maintained DLL list remains (only the 1-entry csrsrv base pin).
    // csrsrv (base pin) + the three `_vista` forwarder DLLs (loaded via LdrpSnapThunk's forwarder
    // path, which the NtOpenFile-based demand-load hook can't catch — see DLL_PIN_COUNT). ws2help is
    // demand-loadable (ws2_32 loads it as a normal import, not a forwarder), so it's NOT pinned.
    const DLL_PINS: [(&[u8], &[u8]); DLL_PIN_COUNT] = [
        (b"csrsrv", b"reactos\\system32\\csrsrv.dll"),
        (b"kernel32_vista", b"reactos\\system32\\kernel32_vista.dll"),
        (b"advapi32_vista", b"reactos\\system32\\advapi32_vista.dll"),
        (b"ntdll_vista", b"reactos\\system32\\ntdll_vista.dll"),
    ];
    // Heap-backed parsed-PE storage (lives for the whole loop without consuming the 16 KiB stack).
    // `dll_pes[i]` holds `&dll_pe_store[i]`
    // — a stable ref into this array — so the erased `*const [&Option<PeFile>; N]` handed to the
    // handler stays valid when a demand-load later writes `dll_pe_store[slot] = Some(pe)` (the ref
    // points AT the slot, so it observes the new value). Only the LIVE run (ntdll present) mounts the
    // pool/FS + demand-loads; the demo SEC_IMAGE call leaves every slot None.
    let mut dll_pe_store: Vec<Option<nt_pe_loader::PeFile<'static>>> =
        Vec::with_capacity(DLL_REG_COUNT);
    dll_pe_store.resize_with(DLL_REG_COUNT, || None);
    let mut reg = nt_dll_registry::Registry::new(DLL_ARENA_START, DLL_ARENA_END);
    if ntdll.is_some() {
        // (1) Load + register + relocate the pinned csrsrv at slot 0 (base 0x8000_0000, delta 0).
        for (i, &(stem, path)) in DLL_PINS.iter().enumerate() {
            let (pe, va) = load_dll_from_fs(path, stem);
            let (sz, ent) = pe
                .as_ref()
                .map(|p| (image_extent(p), p.entry_point_rva()))
                .unwrap_or((0, 0));
            reg.register(stem, sz, ent);
            if let Some(ref p) = pe {
                let base = reg.base(i);
                apply_relocations_to_buf(p, va, base);
                let e_lfanew = core::ptr::read_volatile((va + 0x3c) as *const u32) as u64;
                core::ptr::write_volatile((va + e_lfanew + 0x30) as *mut u64, base);
            }
            dll_pe_store[i] = pe;
        }
    }
    // (2) Reserve remaining metadata slots. VA is consumed only when a real image activates one.
    for _ in DLL_PIN_COUNT..DLL_REG_COUNT {
        reg.reserve();
    }
    // Raw mut ptr to the PE store for the on-demand fill (the handler activates a reserved slot then
    // writes its parsed PE here via this ptr; `dll_pes[slot]` — a ref AT the slot — observes it).
    // Taken BEFORE `dll_pes` borrows the array immutably (a raw ptr holds no borrow). The demand-load
    // writes through this ptr are single-threaded + never alias a live `dll_pes[i]` read (the router
    // reads a slot only after it's mapped, which is after it's written).
    let dll_pe_store_ptr = dll_pe_store.as_mut_ptr();
    let dll_pes: Vec<&Option<nt_pe_loader::PeFile>> =
        (0..DLL_REG_COUNT).map(|i| &dll_pe_store[i]).collect();
    // The real NT syscall path (seam): dispatch SSNs the handler implements; the rest fall back
    // to the broker match below.
    let nt_dispatcher = NativeSyscallDispatcher::new(build_nt_table());
    let mut nt_handler = ExecNtHandler::new();
    let mut delay_queue = nt_delay_execution::Queue::<DELAY_WAITER_N>::new();
    // Heap high-water mark taken AFTER all persistent state (the service table + the
    // pre-reserved process handle tables) is allocated. Each smss syscall we service allocates
    // transient Vec/String (copyin buffers, registry value info) on the no-free bump heap; without
    // reclamation a few hundred registry syscalls exhaust the 128 KiB heap and the executive
    // panics. Rewinding to this mark each iteration reclaims all per-syscall transients while
    // leaving the persistent state (below the mark) intact.
    // `mut` because the CM write overlay's runtime `String`/`Vec` growth (NtCreateKey/NtSetValueKey)
    // must survive the per-syscall reset: after a mutating syscall the loop advances this mark past
    // the overlay's new allocations (see the `overlay_dirty` consume below the dispatch).
    let mut heap_mark = allocator::mark();
    // Per-hosted-process state, indexed by fault badge (0 = smss, 1 = csrss). The SINGLE service
    // loop multiplexes both: each thread faults through a fault-EP cap minted with its badge, so the
    // recv badge selects whose VSpace / image / scratch / fault-bookkeeping to use. Slot 1 (csrss)
    // is filled in when NtCreateProcess spawns it; until then only slot 0 (smss) is live. The `mut`
    // working locals (pml4/scratch_base/img_end/pe via shadowing, faults/first/ntfaults/filled_pages)
    // are LOADED from these at the top of each iteration and SAVED back before each recv, so the
    // ~30 body references stay unchanged.
    // smss's PE (the function param `pe` is shadowed per-iteration to the active process's image; the
    // SM-loop rendezvous always demand-fills SMSS's image, so capture it here before the shadow).
    let smss_pe: &nt_pe_loader::PeFile = pe;
    // Bind smss's pre-created main ETHREAD to its real image entry (smss is already running from the
    // initial recv, not a loop spawn — so bind here). Only on the LIVE run (ntdll present).
    if ntdll.is_some() {
        nt_handler.bind_main_thread_entry(0, PE_LOAD_BASE + smss_pe.entry_point_rva() as u64);
    }
    // Slots: 0 = smss, 1 = csrss, 2 = winlogon (filled when NtCreateProcess spawns each). Path 3:
    // the six ex-parallel identity arrays are now ONE array of `ProcExec`, each slot EPROCESS-linked
    // via its `pid` (== PM_PIDS[pi]; the EPROCESS exists at boot, so link all three now). smss (slot
    // 0) is live from the initial recv; csrss/winlogon's pml4/scratch/img_end fill in at their spawn.
    let mut procs = [ProcExec::empty(); MAX_PI];
    for (i, p) in procs.iter_mut().enumerate() {
        p.pid = nt_handler.pm_pid_for_pi(i).map(|pid| pid as u64).unwrap_or(0);
    }
    procs[0].pml4 = pml4;
    procs[0].scratch_base = scratch_base;
    procs[0].img_end = img_end;
    // Per-process demand-fill bookkeeping is kept in static storage rather than on the bounded
    // rootserver stack (a local copy plus the loop's other arrays would risk the guard
    // page — the recurring stack-array-overflow hazard). service_sec_image runs once for the live
    // run; zero it at entry so the demo call (ntdll=None) starts clean too.
    let pfilled: &mut [[u64; 512]; MAX_PI] = &mut *core::ptr::addr_of_mut!(PFILLED);
    for p in pfilled.iter_mut() {
        for e in p.iter_mut() {
            *e = 0;
        }
    }
    let vm_maps = core::ptr::addr_of_mut!(PROCESS_VM_REGIONS)
        as *mut nt_address_space::VmRegionMap<VM_REGION_CAPACITY>;
    for index in 0..MAX_PI {
        core::ptr::write(
            vm_maps.add(index),
            nt_address_space::VmRegionMap::new(SMSS_ALLOC_VA, PRIVATE_VM_LIMIT),
        );
    }
    VM_FREE_FRAME_N = 0;
    // Fix (B): the INITIAL recv also binds REPLY_MAIN (r12) so the first caller's Call is captured
    // as a reply cap, matching every reply_recv_badge recv in the loop body.
    let (mut badge, mut mi, mut m0, mut m1, mut m2, mut m3) =
        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
    // ★★ PARK + QUIESCE CONTRACT — see docs/n-threads-multiplex.md §1a for the authoritative catalog
    // of every park site + the quiesce predicate. Load-bearing: moving a park's location/condition or
    // changing the quiesce logic can hang the boot (never quiesce) or quiesce EARLY (miss specs / skip
    // the desktop paint). The two helpers below (`park_and_log!` crash parks, `mark_wait_parked!`
    // wakeable waits) + the `crash_parked`/`wait_parked` bitmasks ARE the unified park mechanism; the
    // remaining direct-`break` sites are per-process steady-state predicates (notably the
    // LSA_RPC_SERVER_ACTIVE_SIGNALLED paint-ordering guard) intentionally kept distinct.
    // ★ FAULT ISOLATION (generalized park-and-log). An UNHANDLED / UNRECOVERABLE fault in ONE hosted
    // process must PARK THAT PROCESS (with a clear one-line log) and let the shared loop CONTINUE
    // servicing the others — a process crash does not halt the kernel (fundamental OS fault isolation).
    // This replaces the recurring whack-a-mole of adding a bespoke park arm per new terminal wall
    // (smss-190, the listener-parks, the lsass-post-signal park, …). `crash_parked` is a bitmask of
    // top-level process badges (0/2/4/6/8, all < 64) that have hit an unrecoverable crash; a parked
    // process's further faults are re-parked WITHOUT re-logging (the `already` guard). QUIESCE
    // (break → gate) only when no live top-level process can make forward progress — every live one
    // is crash-parked (so `recv` would block forever). Cooperative parks (wait/delay/listener) are a
    // DIFFERENT, wakeable state and are left as-is; only a real crash sets a `crash_parked` bit.
    let mut crash_parked: u64 = 0;
    // Cooperative-wait bitmask: top-level process badges currently parked in a WAKEABLE wait
    // (NtWaitForSingleObject/MultipleObjects on an unsignalled event, or a lsass-post-signal
    // containment park). A wait-parked process CAN still be woken by a RUNNING process's NtSetEvent,
    // so it stays in the live set — UNLESS every live process is now parked (crash OR wait), in which
    // case no signaler remains → deadlock → quiesce. Cleared at loop-top when the process produces an
    // event (it's running again). This closes the quiesce gap: winlogon WaitForLsass-parked + lsass
    // server-thread-parked + services crash-parked would otherwise block `recv` forever (boot timeout,
    // gate never runs). See the `maybe_quiesce_all_parked!` uses at the wait-park sites.
    let mut wait_parked: u64 = 0;
    // park_and_log!(label, ip, cr2): the generalized UNRECOVERABLE-fault handler. Logs once per
    // top-level process (`[parked] pi=.. badge=.. fault=.. ip=.. cr2=..`), marks its crash bit,
    // flushes this pi's fault bookkeeping, then QUIESCE-checks (if every live top-level process is
    // now crash-parked, break → the gate runs + qemu_exit) else recv-next WITHOUT replying (the
    // faulting thread stays blocked in-kernel, exactly like the cooperative listener-park) and
    // continue the loop for another badge. Uses the surrounding loop locals directly (single call
    // site style), so it must be invoked where they are all in scope.
    macro_rules! park_and_log {
        ($pi:expr, $label:expr, $ip:expr, $cr2:expr) => {{
            let __pi: usize = $pi;
            let __owner = owner_top_badge(badge);
            let __bit = 1u64 << __owner;
            let __already = (crash_parked & __bit) != 0;
            crash_parked |= __bit;
            if !__already {
                print_str(b"[parked] pi=");
                print_u64(__pi as u64);
                print_str(b" badge=");
                print_u64(badge);
                print_str(b" fault=");
                print_str($label);
                print_str(b" ip=0x");
                print_hex((($ip as u64) >> 32) as u32);
                print_hex($ip as u32);
                print_str(b" cr2=0x");
                print_hex((($cr2 as u64) >> 32) as u32);
                print_hex($cr2 as u32);
                print_str(b" -> PARK process (unrecoverable); loop continues\n");
            }
            procs[__pi].faults = faults;
            procs[__pi].first = first;
            procs[__pi].ntfaults = ntfaults;
            pfilled[__pi] = *filled_pages;
            // QUIESCE: no live top-level process can still fault → nothing left to serve.
            if (live_top_badges() & !crash_parked) == 0 {
                print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
                stop = $ip as u64;
                break;
            }
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
            badge = nb;
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            // Diverges: park_and_log! always exits the current loop iteration (never yields a value).
            continue
        }};
    }
    // mark_wait_parked!(pi): record that this top-level process is now cooperatively wait-parked, and
    // if EVERY live top-level process is now parked (crash OR wait) — i.e. no runnable thread remains
    // to signal any waiter — QUIESCE (break → the gate runs). Called right before a wait-park's
    // recv-without-reply. Non-diverging in the common case (just sets the bit); breaks only at true
    // all-parked deadlock. `$ip` is used as the reported stop value.
    macro_rules! mark_wait_parked {
        ($pi:expr, $ip:expr) => {{
            let __owner = owner_top_badge(badge);
            wait_parked |= 1u64 << __owner;
            if (live_top_badges() & !(crash_parked | wait_parked)) == 0 {
                print_str(b"[quiesce] every live process parked/waiting (no signaler left) -> run gate\n");
                stop = $ip as u64;
                let _ = $pi;
                break;
            }
        }};
    }
    // (B) GLOBAL PROGRESS-STALL WATCHDOG state — WALL-CLOCK based (iteration counts are useless here:
    // each win32k dispatch is a whole-component TCG round-trip taking SECONDS, so the loop does only
    // ~1-2 iterations/sec and an iter-count stall never trips within the boot budget). `last_progress_t`
    // is the monotonic time (100ns units) at the last epoch bump (a NEW demand-load / fresh page fill /
    // event / paint = real forward progress). If NO progress happens for STALL_BUDGET_100NS of
    // WALL-CLOCK time, forward progress is impossible (every live process cooperatively parked with no
    // signaler, or a slow win32k live-lock that WALLs without loading/filling anything new) → QUIESCE
    // (break → run the gate + qemu_exit). Generous enough that a genuinely-advancing (even if slow)
    // boot phase — which keeps filling pages / loading DLLs — never trips; only a true stall does.
    const STALL_BUDGET_100NS: u64 = 45 * 10_000_000; // 45 s of NO forward progress
    let mut last_progress_epoch = PROGRESS_EPOCH.load(Ordering::Relaxed);
    let mut last_progress_t = monotonic_time_100ns();
    loop {
        // Progress-stall accounting: reset the wall-clock window on any epoch bump (real forward
        // progress); quiesce if no progress for STALL_BUDGET_100NS.
        {
            let ep = PROGRESS_EPOCH.load(Ordering::Relaxed);
            let now = monotonic_time_100ns();
            if ep != last_progress_epoch {
                last_progress_epoch = ep;
                last_progress_t = now;
            } else if now.wrapping_sub(last_progress_t) >= STALL_BUDGET_100NS {
                print_str(b"[quiesce] no forward progress for ~45s wall-clock (no new load/fill/event/paint) -> run gate\n");
                stop = m1;
                break;
            }
        }
        if badge == DELAY_TIMER_BADGE {
            if delay_queue.len() != 0 && delay_queue.has_badge_other_than(badge) {
                let progress = DELAY_OTHER_BADGE_PROGRESS.fetch_add(1, Ordering::Relaxed);
                if progress < 8 {
                    print_str(b"[delay] timer badge progressed while client waiter parked: queued=");
                    print_u64(delay_queue.len() as u64);
                    print_str(b"\n");
                }
            }
            let timer_trace = DELAY_TIMER_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
            if timer_trace < 8 {
                print_str(b"[delay] TIMER-NOTIFICATION msginfo_label=");
                print_u64(mi >> 12);
                print_str(b" raw_m0=0x");
                print_hex_u64(m0);
                print_str(b"\n");
            }
            delay_timer_interrupt(&mut delay_queue, &mut nt_handler);
            let received = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
            badge = received.0;
            mi = received.1;
            m0 = received.2;
            m1 = received.3;
            m2 = received.4;
            m3 = received.5;
            continue;
        }
        if delay_queue.len() != 0 && delay_queue.has_badge_other_than(badge) {
            let progress = DELAY_OTHER_BADGE_PROGRESS.fetch_add(1, Ordering::Relaxed);
            if progress < 8 {
                print_str(b"[delay] unrelated badge progressed while waiter parked: badge=");
                print_u64(badge);
                print_str(b" queued=");
                print_u64(delay_queue.len() as u64);
                print_str(b"\n");
            }
        }
        // SAFETY: every allocation made past `heap_mark` belongs to the previous iteration's
        // syscall service and is dead now (its Vec/String were dropped at the loop-body's end).
        unsafe { allocator::reset_to(heap_mark) };
        iters += 1;
        // With the per-syscall heap reset above, smss now runs all the way through the ntdll
        // loader + Session Manager SmpInit — enumerating its real registry (NtOpenKey/
        // NtEnumerateValueKey/NtClose) — to a NATURAL stop: SmpInit fails at the missing \??
        // DosDevices object namespace and smss winds down into an unserviced syscall (stop_ssn),
        // ~290 iters, a few seconds. This ceiling is only a safety backstop against a future
        // genuine infinite loop; the run stops well before it. NOTE: with FOUR hosted processes
        // (smss/csrss/winlogon/services) multiplexing through this ONE service loop, the shared
        // budget now covers services' full DllMain/CRT bring-up too — raised 3000→5000 so services
        // reaches its real SCM entry (ScmMain) rather than starving at the old ceiling. Verified
        // each process still PROGRESSES (new SSNs / advancing demand-faults), not spinning.
        // BATCH 20: services.exe now SPAWNS (winlogon's CreateProcessInternalW no longer bails — the
        // relative-path fix) and runs its FULL ntdll loader — but it pulls in an ENORMOUS dependency
        // tree (57 modules: crypt32/dbghelp/libtiff/wintrust/…), each snapping+relocating hundreds of
        // pages via demand faults. Under TCG (~4 faults/s) fully loading services would take >2000s.
        // The gate-relevant work (winlogon → SwitchDesktop → paint + services SPAWNING + its loader
        // STARTING) is complete well before that. Cap at 5000 iters so the boot TERMINATES in-budget
        // and the specs (incl. exec_services_spawned) run; services' full SCM bring-up is the next
        // batch's frontier. Backstop only — each process still PROGRESSES (advancing faults), not
        // spinning (verified: cr2 sweeps the whole DLL space at the loader's snap RIP, never repeats).
        // BATCH 22: the demand-fault BATCH bulk-fill (fill a run of consecutive same-image pages per
        // fault-EP round-trip) + the scratch-VA decoupling cut the per-page round-trip cost ~3× (boot
        // 106s→~35s @5000 iters). With the per-process fault cost now bounded (FAULT_CAP + batching),
        // the iters backstop is lifted so lsass's full LSA-init DLL tree (lsasrv/samsrv/msv1_0 + deps)
        // can grind to LSA_RPC_SERVER_ACTIVE inside the 500s TCG budget → winlogon WaitForLsass wake →
        // InitializeSAS → SwitchDesktop → the 0x003a6ea5 paint. Still a runaway backstop, not the
        // functional terminus.
        if iters > 60000 {
            stop = m1;
            break;
        }
        // Select the hosted process this fault/syscall came from (0 = smss, CSRSS_BADGE = csrss) and
        // LOAD its state into the working locals. pml4/scratch_base/img_end/pe are immutable per
        // process (shadow the params); faults/first/ntfaults/filled_pages are mutable (SAVED back
        // before every recv below).
        // The N-threads-per-process multiplex: SVC_LISTENER_BADGE is services' (pi 3) RPC listener
        // thread — same VSpace/image/pml4 as services' main thread, but a DIFFERENT stack + TEB. It's
        // resolved to pi 3 here; the per-thread stack mirror is switched below (is_svc_listener).
        let is_svc_listener = badge == SVC_LISTENER_BADGE;
        // BATCH 35: services' SCM per-connection RPC worker (pi 3, its OWN stack mirror/TEB) — the
        // N-threads multiplex generalized to a DYNAMICALLY-spawned worker (not a pre-created pool
        // listener). It reads winlogon's bind PDU + writes bind_ack; resolved to pi 3 like the listener.
        let is_scm_worker = badge == SCM_WORKER_BADGE;
        let is_lsass_listener = badge == LSASS_LISTENER_BADGE;
        let is_lsass_listener2 = badge == LSASS_LISTENER2_BADGE;
        let is_lsass_listener3 = badge == LSASS_LISTENER3_BADGE;
        // Generic ntdll workers have one badge per process and role (slot 0: 16..20, slot 1: 21..25).
        // role orthogonal to the listener recognizers: it shares process state and mirrors, but not
        // RPC-listener-specific parking or quiesce policy.
        let tp_worker_identity = tp_worker_identity_from_badge(badge);
        let tp_worker_pi = tp_worker_identity.map(|(pi, _)| pi);
        let tp_worker_slot = tp_worker_identity.map(|(_, slot)| slot);
        let is_tp_worker = tp_worker_identity.is_some();
        // winlogon's rpcrt4 server WORKER thread (pi 2, its own stack mirror/TEB) — same N-threads
        // multiplex. It runs the wait array (NtWaitForMultipleObjects → parks) that the main thread's
        // signal_state_changed wakes, completing the rpcrt4 server-thread handshake.
        let is_wl_worker = matches!(
            badge,
            WINLOGON_WORKER_BADGE | WINLOGON_WORKER2_BADGE | WINLOGON_WORKER3_BADGE
        );
        if is_wl_worker {
            let n = WL_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                print_str(b"[wl-worker] multiplex event #");
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 2 rpcrt4 worker)\n");
            }
        }
        if is_svc_listener {
            let n = SVC_LISTENER_FAULTS.fetch_add(1, Ordering::Relaxed);
            if n < 4 {
                print_str(b"[svc-listener] multiplex event #");
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 3 listener)\n");
            }
        }
        if is_scm_worker {
            let n = SCM_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                print_str(b"[scm-worker] multiplex event #");
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 3 per-connection worker)\n");
            }
        }
        if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 {
            let ctr = if is_lsass_listener3 {
                &LSASS_LISTENER3_FAULTS
            } else if is_lsass_listener2 {
                &LSASS_LISTENER2_FAULTS
            } else {
                &LSASS_LISTENER_FAULTS
            };
            let n = ctr.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                print_str(if is_lsass_listener3 {
                    b"[lsass-listener3] multiplex event #"
                } else if is_lsass_listener2 {
                    b"[lsass-listener2] multiplex event #"
                } else {
                    b"[lsass-listener] multiplex event #"
                });
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 4 listener)\n");
            }
        }
        let pi = if let Some(tp_pi) = tp_worker_pi {
            tp_pi
        } else if badge == CSRSS_BADGE {
            1
        } else if badge == WINLOGON_BADGE || is_wl_worker {
            2
        } else if badge == SERVICES_BADGE || is_svc_listener || is_scm_worker {
            3
        } else if badge == LSASS_BADGE
            || is_lsass_listener
            || is_lsass_listener2
            || is_lsass_listener3
        {
            4
        } else {
            0
        };
        // This process is producing an event → it's running, not wait-parked. Clear its cooperative
        // wait bit so the all-parked quiesce test reflects reality (a woken waiter re-enters here).
        wait_parked &= !(1u64 << owner_top_badge(badge));
        if badge == WINLOGON_BADGE {
            WINLOGON_MAIN_EVENT_WAIT_PARKED.store(0, Ordering::Relaxed);
        }
        if PM_TERMINATE_THREAD_NO_REPLY.load(Ordering::Relaxed) != 0 && badge < 64 {
            PM_POST_TERM_CONTINUED_BADGES.fetch_or(1u64 << badge, Ordering::Relaxed);
        }
        // LOUD overflow guard: `pi` indexes the fixed-size per-process arrays (procs / pfilled /
        // dll_pd_created / dll_pt_bits, all sized to MAX_PI). A future 6th/7th hosted process
        // adds a badge→pi arm above; if one ever exceeds MAX_PI this panics with a clear message
        // (the panic handler prints file:line) instead of silently corrupting an adjacent array /
        // spinning. Bump MAX_PI (a scalar .bss cost) to admit more processes.
        assert!(pi < MAX_PI, "hosted process pi exceeds MAX_PI — bump MAX_PI");
        // Convergence (first increment): resolve this fault badge → its real EPROCESS via the Process
        // Manager (badge → pi → PM_PIDS[pi] → pm.process(pid)). Read-only (no alloc under the reset),
        // it proves the live badge-multiplex is backed by real nt-process objects. The ad-hoc per-pi
        // arrays below still carry the load-bearing mechanism state; the bulk migrates that onto the
        // EPROCESS next (see the convergence report).
        if let Some(pid) = nt_handler.pm_pid_for_pi(pi) {
            if nt_handler.pm.process(pid).is_some() {
                PM_BADGE_LOOKUPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Route the shared stack helpers (smss_stack_read/write) to THIS process's stack mirror, so
        // its syscall out-params (e.g. NtAllocateVirtualMemory's base for RtlCreateHeap) land on its
        // own stack, not the other process's.
        let (active_stack_base, active_stack_frames) = if let Some(slot) = tp_worker_slot {
            (tp_worker_stack_base(slot), TP_WORKER_STACK_FRAMES)
        } else if is_svc_listener {
            (SVC_LISTENER_STACK_BASE, SVC_LISTENER_STACK_FRAMES)
        } else if is_scm_worker {
            (SCM_WORKER_STACK_BASE, SCM_WORKER_STACK_FRAMES)
        } else if is_lsass_listener {
            (LSASS_LISTENER_STACK_BASE, LSASS_LISTENER_STACK_FRAMES)
        } else if is_lsass_listener2 {
            (LSASS_LISTENER2_STACK_BASE, LSASS_LISTENER2_STACK_FRAMES)
        } else if is_lsass_listener3 {
            (LSASS_LISTENER3_STACK_BASE, LSASS_LISTENER3_STACK_FRAMES)
        } else if is_wl_worker {
            match badge {
                WINLOGON_WORKER2_BADGE => (WL_WORKER2_STACK_BASE, WL_WORKER2_STACK_FRAMES),
                WINLOGON_WORKER3_BADGE => (WL_WORKER3_STACK_BASE, WL_WORKER3_STACK_FRAMES),
                _ => (WL_LISTENER_STACK_BASE, WL_LISTENER_STACK_FRAMES),
            }
        } else {
            (STACK_BASE, STACK_FRAMES)
        };
        ACTIVE_STACK_BASE.store(active_stack_base, Ordering::Relaxed);
        ACTIVE_STACK_SIZE.store(active_stack_frames * 0x1000, Ordering::Relaxed);
        ACTIVE_STACK_MIRROR.store(
            if let Some((tp_pi, tp_slot)) = tp_worker_identity {
                tp_worker_stack_mirror_va(tp_pi, tp_slot)
            } else if is_svc_listener {
                // Per-thread sub-selection: the listener's OWN stack mirror (its syscall out-params /
                // stack-arg reads land on its own stack, not services' main-thread stack).
                SVC_LISTENER_STACK_MIRROR_VA
            } else if is_scm_worker {
                // BATCH 35: the SCM worker's OWN stack mirror (its bind-PDU read buffer / out-params).
                SCM_WORKER_STACK_MIRROR_VA
            } else if is_lsass_listener {
                // Per-thread sub-selection: lsass' LSA server thread's OWN stack mirror (distinct from
                // lsass' main-thread stack).
                LSASS_LISTENER_STACK_MIRROR_VA
            } else if is_lsass_listener2 {
                LSASS_LISTENER2_STACK_MIRROR_VA
            } else if is_lsass_listener3 {
                LSASS_LISTENER3_STACK_MIRROR_VA
            } else if is_wl_worker {
                match badge {
                    WINLOGON_WORKER2_BADGE => WINLOGON_WORKER2_STACK_MIRROR_VA,
                    WINLOGON_WORKER3_BADGE => WINLOGON_WORKER3_STACK_MIRROR_VA,
                    _ => WINLOGON_WORKER_STACK_MIRROR_VA,
                }
            } else {
                match pi {
                    1 => CSRSS_STACK_MIRROR_VA,
                    2 => WINLOGON_STACK_MIRROR_VA,
                    3 => SERVICES_STACK_MIRROR_VA,
                    4 => LSASS_STACK_MIRROR_VA,
                    _ => SMSS_STACK_MIRROR_VA,
                }
            },
            Ordering::Relaxed,
        );
        ACTIVE_IMAGE_MIRROR.store(
            match pi {
                1 => CSRSS_IMAGE_MIRROR_VA,
                2 => WINLOGON_IMAGE_MIRROR_VA,
                3 => SERVICES_IMAGE_MIRROR_VA,
                4 => LSASS_IMAGE_MIRROR_VA,
                _ => IMAGE_MIRROR_VA,
            },
            Ordering::Relaxed,
        );
        ACTIVE_HEAP_MIRROR.store(
            match pi {
                1 => CSRSS_HEAP_MIRROR_VA,
                2 => WINLOGON_HEAP_MIRROR_VA,
                3 => SERVICES_HEAP_MIRROR_VA,
                4 => LSASS_HEAP_MIRROR_VA,
                _ => SMSS_HEAP_MIRROR_VA,
            },
            Ordering::Relaxed,
        );
        let pml4 = procs[pi].pml4;
        let scratch_base = procs[pi].scratch_base;
        let img_end = procs[pi].img_end;
        let pe: &nt_pe_loader::PeFile = match pi {
            1 => csrss_pe.as_ref().unwrap(),
            2 => winlogon_pe.as_ref().unwrap(),
            3 => services_pe.as_ref().unwrap(),
            4 => lsass_pe.as_ref().unwrap(),
            _ => pe,
        };
        faults = procs[pi].faults;
        first = procs[pi].first;
        ntfaults = procs[pi].ntfaults;
        *filled_pages = pfilled[pi];
        if pi == 2 {
            let watch = KERNEL32_TABLE_WATCH_SCRATCH.load(Ordering::Relaxed);
            if watch != 0 {
                // BaseHeapHandleTable+8 is zero after the kernel32 BSS page is materialized. The
                // value below is the first eight bytes of the msgina dialog-resource signature
                // observed in the corrupt page. Catch the first client event after it changes.
                let value = core::ptr::read_volatile((watch + 0x648) as *const u64);
                if value == 0x0039_003c_5081_0080
                    && KERNEL32_TABLE_WATCH_CORRUPT.swap(1, Ordering::Relaxed) == 0
                {
                    print_str(b"[alias-corrupt] badge=");
                    print_u64(badge);
                    print_str(b" label=0x");
                    print_hex((mi >> 12) as u32);
                    print_str(b" m0=0x");
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" m1=0x");
                    print_hex((m1 >> 32) as u32);
                    print_hex(m1 as u32);
                    print_str(b" faults=");
                    print_u64(faults);
                    print_str(b" scratch=0x");
                    print_hex((watch >> 32) as u32);
                    print_hex(watch as u32);
                    print_str(b"\n");
                }
            }
        }
        // A CPU exception (label 3). The DEBUG ntdll emits `int 0x2d` (DebugService/DPRINT),
        // which #GPs with no kernel debugger; emulate it as a no-op by skipping past the
        // `int 0x2d; int3` pair (echo the registers, advance the fault IP by 3, restart).
        if (mi >> 12) == 3 {
            // UserException delivery: m0=FaultIP, m1=SP, m2=FLAGS, m3=Number, mr4=Code. The
            // reply sets IP/SP/FLAGS (length 3); the general registers are preserved.
            let fip = m0;
            let mut skipped = false;
            if let Some((nb, npe)) = ntdll {
                if fip >= nb && fip < nb + image_extent(npe) {
                    if pe_byte_at_rva(npe, (fip - nb) as u32) == Some(0xCD) {
                        // Skip `int 0x2d; int3` (3 bytes) — the no-op DebugService.
                        procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                        let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 3, fip + 3, m1, m2, 0);
                        badge = nb;
                        mi = nmi;
                        m0 = nm0;
                        m1 = nm1;
                        m2 = nm2;
                        m3 = nm3;
                        skipped = true;
                        dbgsvc += 1;
                    }
                }
            }
            if skipped {
                continue;
            }
            // Unhandled CPU exception (label 3) at a non-skippable site — a real crash. Park+log.
            park_and_log!(pi, b"cpu-exception(3)", fip, fip);
        }
        // DebugException (label 4 = int3 / #BP). OUR ntdll's `RtlRaiseException` / `RtlRaiseStatus`
        // seams issue int3. Decode WHAT exception the caller is raising: recover winlogon's full GPRs
        // (RCX = PEXCEPTION_RECORD arg, RSP), read the EXCEPTION_RECORD from its demand-faulted memory,
        // and walk the stack for the raise site. m1 = fault_ip for a DebugException fault.
        if (mi >> 12) == 4 {
            let bp_ip = m1;
            let tcb = crate::PM_MAIN_TCBS[pi as usize].load(Ordering::Relaxed);
            if tcb != 0 && ntdll.is_some() {
                let mut regs = [0u64; 20];
                crate::win32k_glue::tcb_read_regs20(tcb, &mut regs);
                let rip = regs[0];
                let rcx = regs[5];
                let rsp = regs[1];
                let raise_rva = if let Some((nb, _)) = ntdll { rip.wrapping_sub(nb) } else { rip };
                print_str(b"[bp-diag] int3 rva=0x");
                print_hex(raise_rva as u32);
                print_str(b" rcx(record*)=0x");
                print_hex((rcx >> 32) as u32);
                print_hex(rcx as u32);
                print_str(b" rsp=0x");
                print_hex((rsp >> 32) as u32);
                print_hex(rsp as u32);
                print_str(b"\n");
                // Read the EXCEPTION_RECORD (first 0x30 bytes) from winlogon's memory. The record lives
                // on the raiser's stack → read via the stack mirror (`smss_stack_read`), falling back to
                // the demand-faulted-page scratch alias for a non-stack record ptr.
                let stk_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
                let stk_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
                let stk_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
                let read_wl = |va: u64| -> Option<u64> {
                    unsafe {
                        if va >= stk_base && va + 8 <= stk_base + stk_size {
                            return Some(core::ptr::read_volatile(
                                (stk_mirror + (va - stk_base)) as *const u64,
                            ));
                        }
                        scratch_for(va, filled_pages, faults as usize, scratch_base)
                            .map(|m| core::ptr::read_volatile(m as *const u64))
                    }
                };
                let mut rec = [0u8; 0x30];
                let mut got = true;
                for off in (0..0x30u64).step_by(8) {
                    if let Some(v) = read_wl(rcx + off) {
                        rec[off as usize..off as usize + 8].copy_from_slice(&v.to_le_bytes());
                    } else {
                        got = false;
                        break;
                    }
                }
                if got {
                    let code = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                    let flags = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                    let addr = u64::from_le_bytes([
                        rec[16], rec[17], rec[18], rec[19], rec[20], rec[21], rec[22], rec[23],
                    ]);
                    // NumberParameters @ +0x18 (byte 24); ExceptionInformation[] @ +0x20 (byte 32).
                    let nparm = u32::from_le_bytes([rec[24], rec[25], rec[26], rec[27]]);
                    let info0 = u64::from_le_bytes([
                        rec[32], rec[33], rec[34], rec[35], rec[36], rec[37], rec[38], rec[39],
                    ]);
                    let info1 = u64::from_le_bytes([
                        rec[40], rec[41], rec[42], rec[43], rec[44], rec[45], rec[46], rec[47],
                    ]);
                    print_str(b"[bp-diag] EXCEPTION_RECORD code=0x");
                    print_hex(code);
                    print_str(b" flags=0x");
                    print_hex(flags);
                    print_str(b" addr=0x");
                    print_hex((addr >> 32) as u32);
                    print_hex(addr as u32);
                    print_str(b" nparams=");
                    print_u64(nparm as u64);
                    print_str(b" info0=0x");
                    print_hex((info0 >> 32) as u32);
                    print_hex(info0 as u32);
                    print_str(b" info1=0x");
                    print_hex((info1 >> 32) as u32);
                    print_hex(info1 as u32);
                    print_str(b"\n");
                    // 0xC06D007E = VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND) — a VC++
                    // delay-load failure. ExceptionInformation[0] points at a DelayLoadInfo whose
                    // +0x08 (szDll, LPCSTR) names the missing DLL. Dump it.
                    if code == 0xC06D_007E && info0 != 0 {
                        // DelayLoadInfo: cb@0, pidd@0x08, ppfn@0x10, szDll(LPCSTR)@0x18.
                        if let Some(szdll) = read_wl(info0 + 0x18) {
                            print_str(b"[bp-diag] delayload szDll ptr=0x");
                            print_hex((szdll >> 32) as u32);
                            print_hex(szdll as u32);
                            print_str(b" name=\"");
                            // Read up to 40 ASCII bytes of the DLL name into a buffer.
                            let mut name = [0u8; 41];
                            let mut n = 0usize;
                            for j in 0..40u64 {
                                if let Some(w) = read_wl((szdll + j) & !7) {
                                    let b = ((w >> (8 * ((szdll + j) & 7))) & 0xff) as u8;
                                    if b == 0 {
                                        break;
                                    }
                                    name[n] = if b.is_ascii_graphic() || b == b' ' { b } else { b'?' };
                                    n += 1;
                                } else {
                                    break;
                                }
                            }
                            print_str(&name[..n]);
                            print_str(b"\"\n");
                        }
                    }
                } else {
                    print_str(b"[bp-diag] EXCEPTION_RECORD not in a faulted page (rcx unmapped)\n");
                }
                // Walk the caller's stack for return addresses in ntdll / DLLs to identify the raise
                // site (who called RtlRaiseException / RtlRaiseStatus).
                print_str(b"[bp-diag] callers:");
                let mut shown = 0;
                for i in 0..96u64 {
                    if let Some(v) = read_wl(rsp + i * 8) {
                        if let Some((nb, npe)) = ntdll {
                            if v >= nb && v < nb + image_extent(npe) {
                                print_str(b" n+0x");
                                print_hex((v - nb) as u32);
                                shown += 1;
                            }
                        }
                        if v >= 0x8000_0000 && v < 0x8080_0000 {
                            print_str(b" d+0x");
                            print_hex(v as u32);
                            shown += 1;
                        }
                        if shown >= 24 {
                            break;
                        }
                    }
                }
                print_str(b"\n");
            }
            // Unhandled int3/#BP (a RtlRaiseException the loader/process can't recover) — a crash. Park+log.
            park_and_log!(pi, b"debug-exception(4)", bp_ip, bp_ip);
        }
        if (mi >> 12) == 6 {
            let addr = m1;
            if faults == 0 {
                first = addr;
            }
            let page = addr & !0xFFFu64;
            if pi == 2
                && (m3 & 0x7) == 0x7
                && WINLOGON_HANDLE_FAULT_DIAG_N.fetch_add(1, Ordering::Relaxed) == 0
            {
                const KERNEL32_BASE_HEAP_HANDLE_TABLE: u64 = 0x8045_1640;
                let mut table = [0u8; 0x30];
                let table_ok = img_spawn::client_copyin_mapped(
                    pi as u64,
                    KERNEL32_BASE_HEAP_HANDLE_TABLE,
                    &mut table,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b"[handle-fault] table-ok=");
                print_u64(table_ok as u64);
                if table_ok {
                    for off in (0..table.len()).step_by(8) {
                        let value = u64::from_le_bytes(
                            table[off..off + 8].try_into().unwrap(),
                        );
                        print_str(b" +");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                const KERNEL32_RTL_ALLOCATE_HANDLE_IAT: u64 = 0x8041_74a8;
                let mut iat = [0u8; 8];
                let iat_ok = img_spawn::client_copyin_mapped(
                    pi as u64,
                    KERNEL32_RTL_ALLOCATE_HANDLE_IAT,
                    &mut iat,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b" iat-ok=");
                print_u64(iat_ok as u64);
                if iat_ok {
                    let target = u64::from_le_bytes(iat);
                    print_str(b" iat=0x");
                    print_hex((target >> 32) as u32);
                    print_hex(target as u32);
                }
                for (name, (frame, index)) in [
                    (b" table".as_slice(), csrss_frame_get_exact(2, 0x8045_1000)),
                    (b" msgina".as_slice(), csrss_frame_get_exact(2, 0x8230_e000)),
                    (b" entry".as_slice(), csrss_frame_get_exact(2, 0x0000_0100_0057_9000)),
                ] {
                    print_str(name);
                    print_str(b"-cap=0x");
                    print_hex(frame as u32);
                    print_str(b"-pa=0x");
                    let paddr = if frame != 0 { get_frame_paddr(frame) } else { 0 };
                    print_hex((paddr >> 32) as u32);
                    print_hex(paddr as u32);
                    print_str(b"-idx=");
                    print_u64(if index == usize::MAX { u64::MAX } else { index as u64 });
                }
                print_str(b" frame-n=");
                print_u64(core::ptr::read(core::ptr::addr_of!(CSRSS_FRAME_N)) as u64);
                let (heap_frame, heap_index) =
                    csrss_frame_get_exact(2, NTDLL_BASE + 0x99_000);
                print_str(b" heap-cap=0x");
                print_hex(heap_frame as u32);
                print_str(b"-pa=0x");
                let heap_pa = if heap_frame != 0 { get_frame_paddr(heap_frame) } else { 0 };
                print_hex((heap_pa >> 32) as u32);
                print_hex(heap_pa as u32);
                print_str(b"-idx=");
                print_u64(if heap_index == usize::MAX { u64::MAX } else { heap_index as u64 });
                let mut heap_state = [0u8; 0x30];
                let heap_ok = img_spawn::client_copyin_mapped(
                    2,
                    NTDLL_BASE + 0x99_000,
                    &mut heap_state,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b" heap-ok=");
                print_u64(heap_ok as u64);
                if heap_ok {
                    for off in (0..heap_state.len()).step_by(8) {
                        let value = u64::from_le_bytes(
                            heap_state[off..off + 8].try_into().unwrap(),
                        );
                        print_str(b" +");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                let callback_frame = (win32k_subsystem::WIN32K_SHARED_VADDR
                    + win32k_subsystem::SH_USER_CALLBACK) as *const nt_user_callback::CallbackFrame;
                let callback_proc = core::ptr::read_volatile(
                    core::ptr::addr_of!((*callback_frame).payload[0]) as *const u64,
                );
                print_str(b" callback-proc=0x");
                print_hex((callback_proc >> 32) as u32);
                print_hex(callback_proc as u32);
                let entry_va = addr.saturating_sub(8);
                let mut entry = [0u8; 0x20];
                let entry_ok = img_spawn::client_copyin_mapped(
                    pi as u64,
                    entry_va,
                    &mut entry,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b" entry=0x");
                print_hex((entry_va >> 32) as u32);
                print_hex(entry_va as u32);
                print_str(b" entry-ok=");
                print_u64(entry_ok as u64);
                if entry_ok {
                    for off in (0..entry.len()).step_by(8) {
                        let value = u64::from_le_bytes(
                            entry[off..off + 8].try_into().unwrap(),
                        );
                        print_str(b" +");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                let tcb = tp_worker_identity
                    .map(|(tp_pi, tp_slot)| TP_WORKER_TCB[tp_pi][tp_slot].load(Ordering::Relaxed))
                    .unwrap_or_else(|| PM_MAIN_TCBS[pi].load(Ordering::Relaxed));
                if tcb != 0 {
                    let mut regs = [0u64; 20];
                    win32k_glue::tcb_read_regs20(tcb, &mut regs);
                    print_str(b" rip=0x");
                    print_hex((regs[0] >> 32) as u32);
                    print_hex(regs[0] as u32);
                    print_str(b" rsp=0x");
                    print_hex((regs[1] >> 32) as u32);
                    print_hex(regs[1] as u32);
                    print_str(b" rcx=0x");
                    print_hex((regs[5] >> 32) as u32);
                    print_hex(regs[5] as u32);
                    for off in (0..=0x80u64).step_by(8) {
                        let value = smss_stack_read(regs[1] + off);
                        print_str(b" sp+");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                print_str(b"\n");
            }
            // ROBUSTNESS (gate-safety): a genuine NULL/low deref (addr < 64 KiB) is never a
            // demand-fillable region (image/DLL/scratch/stack/anon all live far above) — it's an
            // unrecoverable client fault (e.g. user32's UserClientDllInitialize deref of a still-null
            // gSharedInfo). Map it and we hand the faulter a zero page → it silently spins on the bad
            // value and the loop never makes progress (deterministic hang). So STOP the loop cleanly
            // with a diagnostic instead — exactly like the win32k `[vmf-out]` stop path.
            if addr < 0x10000 {
                let tcb = tp_worker_identity
                    .map(|(tp_pi, tp_slot)| TP_WORKER_TCB[tp_pi][tp_slot].load(Ordering::Relaxed))
                    .unwrap_or_else(|| PM_MAIN_TCBS[pi].load(Ordering::Relaxed));
                if tcb != 0 {
                    let mut regs = [0u64; 20];
                    win32k_glue::tcb_read_regs20(tcb, &mut regs);
                    print_str(b"[vmf-low] rcx=0x");
                    print_hex((regs[5] >> 32) as u32);
                    print_hex(regs[5] as u32);
                    print_str(b" rsi=0x");
                    print_hex((regs[7] >> 32) as u32);
                    print_hex(regs[7] as u32);
                    print_str(b" rdi=0x");
                    print_hex((regs[8] >> 32) as u32);
                    print_hex(regs[8] as u32);
                    print_str(b" rsp=0x");
                    print_hex((regs[1] >> 32) as u32);
                    print_hex(regs[1] as u32);
                    print_str(b" ret=0x");
                    let ret = smss_stack_read(regs[1] + 0x10);
                    print_hex((ret >> 32) as u32);
                    print_hex(ret as u32);
                    print_str(b"\n");
                }
                // user32 GetThreadDesktopWnd (RVA 0x50009) dereferences
                // `GetThreadDesktopInfo()->spwnd`. IntSetThreadDesktop can clear the client fields
                // while the hosted per-thread desktop-heap view is being established. Repair the
                // exact fault in the TEB that owns it (main or one of winlogon's worker TEBs), then
                // retry the instruction. This must precede the generic worker-wall park below.
                if pi == 2 && m0 == 0x801a_0009 && addr == 0x10 {
                    let teb_alias = if let Some((2, tp_slot)) = tp_worker_identity {
                        tp_worker_stack_mirror_va(2, tp_slot) + TP_WORKER_STACK_FRAMES * 0x1000
                    } else if is_wl_worker {
                        match badge {
                            WINLOGON_WORKER2_BADGE => WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000,
                            WINLOGON_WORKER3_BADGE => WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000,
                            _ => WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000,
                        }
                    } else {
                        0x0000_0100_107C_0000
                    };
                    let tcb = match badge {
                        _ if tp_worker_identity.is_some() => {
                            let (_, tp_slot) = tp_worker_identity.unwrap();
                            TP_WORKER_TCB[2][tp_slot].load(Ordering::Relaxed)
                        }
                        WINLOGON_WORKER_BADGE => WL_LISTENER_TCB.load(Ordering::Relaxed),
                        WINLOGON_WORKER2_BADGE => WL_WORKER2_TCB.load(Ordering::Relaxed),
                        WINLOGON_WORKER3_BADGE => WL_WORKER3_TCB.load(Ordering::Relaxed),
                        _ => PM_MAIN_TCBS[2].load(Ordering::Relaxed),
                    };
                    if let Some((client_deskinfo, pti, _)) =
                        seed_winlogon_thread_client_info(teb_alias, pml4)
                    {
                        // The faulting instruction already has RAX=NULL. Re-run the helper call at
                        // 0x801a0004 so it reloads the repaired TEB fields before dereferencing.
                        if tcb != 0 && win32k_glue::rewind_fault_ip(tcb, 0x801a_0004) {
                            print_str(b"[wl-deskinfo-fixup] badge=");
                            print_u64(badge);
                            print_str(b" real pti=0x");
                            print_hex((pti >> 32) as u32);
                            print_hex(pti as u32);
                            print_str(b" pDeskInfo=0x");
                            print_hex((client_deskinfo >> 32) as u32);
                            print_hex(client_deskinfo as u32);
                            print_str(b" -> rewind helper call; RESUME\n");
                            procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                            badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                            continue;
                        }
                    }
                    print_str(b"[wl-deskinfo-fixup] real client state unavailable; PARK worker\n");
                }
                if is_tp_worker {
                    print_str(b"[tp-worker] wall badge=");
                    print_u64(badge);
                    print_str(b" ip=0x");
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" addr=0x");
                    print_hex(addr as u32);
                    print_str(b" -> PARK generic worker; owner continues\n");
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(
                        fault_ep,
                        REPLY_MAIN_SLOT.load(Ordering::Relaxed),
                    );
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // N-threads multiplex: the services RPC listener (badge 7) walls on its OWN
                // unrecoverable fault (rpcrt4 io_thread derefs a connection field that needs a real
                // client connect — the listener's next frontier). PARK it (don't reply → it stays
                // blocked, its ETHREAD/TEB stay mapped) and CONTINUE the loop so services' main thread
                // + winlogon keep advancing (winlogon → StartLsass). Contained per-thread, not a boot
                // stop — the whole point of the per-thread multiplex.
                if is_svc_listener || is_scm_worker || is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 || is_wl_worker {
                    print_str(if is_wl_worker { b"[wl-worker] wall ip=0x" } else if is_scm_worker { b"[scm-worker] wall ip=0x" } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 { b"[lsass-listener] wall ip=0x" } else { b"[svc-listener] wall ip=0x" });
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" addr=0x");
                    print_hex(addr as u32);
                    print_str(b" -> PARK thread (its own unrecoverable fault); boot continues\n");
                    if is_wl_worker
                        && WINLOGON_MAIN_EVENT_WAIT_PARKED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[wl-worker] terminal wall while winlogon main waits for this worker -> run gate\n");
                        stop = m0;
                        break;
                    }
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    // Recv the next event WITHOUT replying to the listener (it stays blocked).
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
                print_str(if pi == 1 { b"[csrss vmf] NULL/low deref ip=0x" } else if pi == 2 { b"[winlogon vmf] NULL/low deref ip=0x" } else { b"[smss vmf] NULL/low deref ip=0x" });
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                print_str(b" (dll_rva = ip - dll_base; user32@0x84000000, gdi32@0x85000000)\n");
                // DIAG (BATCH 7): dump the fault frame RSP + the caller return addresses so we can
                // identify who passed NULL (e.g. strlen(NULL) during msvcrt CRT init). At strlen+0x16
                // the frame is `sub rsp,0x18` deep so the return addr is at [rsp+0x18]; also dump a
                // small window of the stack to see the call chain.
                {
                    let sp = get_recv_mr(16);
                    print_str(b"[winlogon vmf] rsp=0x");
                    print_hex((sp >> 32) as u32);
                    print_hex(sp as u32);
                    print_str(b" retaddrs[");
                    // Scan up the stack for the first plausible RETURN ADDRESSES (msvcrt 0x806xxxxx,
                    // our ntdll 0x100_00xxxxxx, or another mapped DLL 0x80xxxxxx) so we see the caller
                    // chain that reached strlen(NULL).
                    let mut k: u64 = 0;
                    let mut printed: u64 = 0;
                    while k < 96 && printed < 10 {
                        let v = smss_stack_read(sp + k * 8);
                        let is_ntdll = v >= 0x0000_0100_0000_0000 && v < 0x0000_0100_0100_0000;
                        let is_dll = v >= 0x8000_0000 && v < 0x8100_0000;
                        if is_ntdll || is_dll {
                            print_str(b" +0x");
                            print_hex((k * 8) as u32);
                            print_str(b":0x");
                            print_hex((v >> 32) as u32);
                            print_hex(v as u32);
                            printed += 1;
                        }
                        k += 1;
                    }
                    print_str(b" ]\n");
                }
                // BATCH 39 — winlogon (pi 2) is the process the whole boot drives toward; once it has
                // crossed OpenSCManager (the SCM RPC round-trip) and reached its GUI/login init, the
                // remaining "live" top-level processes (services / lsass) are just the SCM + LSA RPC
                // SERVERS with no live client left. So when winlogon hits an unrecoverable crash AT its
                // GUI/login frontier (its next wall past OpenSCManager — currently msgina.dll's login
                // flow, RVA 0x95f8), with LSA already signalled (steady state), QUIESCE to the gate
                // instead of blocking the loop's recv forever (the servers can't advance without
                // winlogon). This makes the route-ON boot reach the gate cleanly (BATCH 38 flagged this
                // as the "break-on-winlogon-crash quiesce"). Mark winlogon crash-parked first so the
                // gate's crash state is honest.
                if pi == 2 && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0 {
                    crash_parked |= 1u64 << owner_top_badge(badge);
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    print_str(b"[wl-main] winlogon crashed at its post-OpenSCManager GUI/login frontier (LSA signalled, SCM servers idle) -> QUIESCE; run gate\n");
                    stop = m0;
                    break;
                }
                // Unrecoverable NULL/low deref on a top-level process thread — a crash. Park+log
                // (the per-process detail above already printed; park_and_log adds the [parked] line).
                park_and_log!(pi, b"null-deref", m0, addr);
            }
            // Slot 0 returns from its fixed loader bootstrap stack into the reservation created by
            // kernel32!BaseCreateStack. Grow only the next contiguous page in that reservation and
            // advance the live TEB limit before retrying the fault.
            if badge == WINLOGON_WORKER_BADGE {
                let allocation_base = WL_LISTENER_STACK_ALLOCATION_BASE.load(Ordering::Acquire);
                let stack_base = WL_LISTENER_STACK_BASE_REAL.load(Ordering::Acquire);
                let mapped_low = WL_LISTENER_STACK_MAPPED_LOW.load(Ordering::Acquire);
                if m3 & 1 == 0
                    && page < stack_base
                    && csrss_frame_get_exact(2, page).0 == 0
                    && nt_thread_start::next_stack_growth_page(allocation_base, mapped_low, addr)
                        == Some(page)
                {
                    let (frame, retype_error) = alloc_frame_r();
                    let map_error = if retype_error == 0 {
                        page_map_r(frame, page, RW_NX, pml4)
                    } else {
                        retype_error
                    };
                    if retype_error == 0 && map_error == 0 {
                        csrss_frame_put(2, page, frame);
                        if csrss_frame_get_exact(2, page).0 == frame {
                            let teb_alias = WINLOGON_WORKER_STACK_MIRROR_VA
                                + WL_LISTENER_STACK_FRAMES * 0x1000;
                            core::ptr::write_volatile(
                                (teb_alias + 0x10) as *mut u64,
                                page + nt_thread_start::USER_PAGE_SIZE,
                            );
                            WL_LISTENER_STACK_MAPPED_LOW.store(page, Ordering::Release);
                            print_str(b"[wl-worker] grew real stack page=0x");
                            print_hex((page >> 32) as u32);
                            print_hex(page as u32);
                            print_str(b" allocation=0x");
                            print_hex((allocation_base >> 32) as u32);
                            print_hex(allocation_base as u32);
                            print_str(b"\n");
                            procs[pi].faults = faults;
                            procs[pi].first = first;
                            procs[pi].ntfaults = ntfaults;
                            pfilled[pi] = *filled_pages;
                            let (nb, nmi, nm0, nm1, nm2, nm3) =
                                reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                            badge = nb;
                            mi = nmi;
                            m0 = nm0;
                            m1 = nm1;
                            m2 = nm2;
                            m3 = nm3;
                            continue;
                        }
                    }
                    if frame != 0 {
                        let _ = cnode_delete_r(frame);
                    }
                    print_str(b"[wl-worker] real stack growth failed page=0x");
                    print_hex((page >> 32) as u32);
                    print_hex(page as u32);
                    print_str(b" retype=");
                    print_u64(retype_error);
                    print_str(b" map=");
                    print_u64(map_error);
                    print_str(b"\n");
                    park_and_log!(pi, b"wl-stack-growth", m0, addr);
                }
            }
            // Dynamic stack growth (Windows guard-page style): a fault just below the committed
            // stack commits a fresh zeroed page and restarts, so smss's stack grows on demand
            // instead of crashing at the 16 KiB initial commit. Bounded by STACK_GROWTH_FLOOR so it
            // never runs into the env mappings below.
            if page >= STACK_GROWTH_FLOOR && page < STACK_BASE {
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                if pi == 1 || pi == 2 {
                    // A GUI client (csrss pi 1 / winlogon pi 2) stack pointer — shareable into win32k
                    // at the same VA when this client dispatches an NtUser/NtGdi call (per-client).
                    csrss_frame_put(pi as u64, page, f);
                }
                faults += 1;
                procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            // csrss's anonymous section (CSR shared memory): commit a ZERO frame on touch.
            if pi == 1
                && csrss_anon_base != 0
                && page >= csrss_anon_base
                && page < csrss_anon_base + ((csrss_anon_size + 0xFFF) & !0xFFFu64)
            {
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                csrss_frame_put(pi as u64, page, f); // CSR shared section (pi 1) — shareable into win32k
                faults += 1;
                procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            // Route to whichever image contains the faulting page.
            let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
                (PE_LOAD_BASE, pe)
            } else if nt_base != 0 && page >= nt_base && page < nt_end {
                ntfaults += 1;
                (nt_base, ntdll.unwrap().1)
            } else if let Some((i, _)) = if pi >= 1 { reg.dll_for_page(page) } else { None } {
                // A mapped registry DLL (csrsrv/basesrv/winsrv/Win32 stack) in a DLL-loading
                // process's VSpace (csrss pi==1 OR winlogon pi==2) — demand-page it from that DLL's
                // parsed PE. csrsrv sits at its preferred ImageBase (no relocation); the others are
                // loader-relocated to their fixed bases. The registry resolves which one owns the page.
                (reg.base(i), dll_pes[i].as_ref().unwrap())
            } else {
                // DIAG: dump the fault so we can tell a stack-growth fault (addr just below the
                // stack) from a real null deref. m0=IP, m1=addr(cr2), m2=prefetch, m3=fsr.
                print_str(b"[vmf-out] ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                print_str(b" pf=");
                print_u64(m2);
                print_str(b" fsr=");
                print_u64(m3);
                print_str(b" img_end=0x");
                print_hex((img_end >> 32) as u32);
                print_hex(img_end as u32);
                print_str(b" stack=[0x");
                print_hex(STACK_BASE as u32);
                print_str(b"..0x");
                print_hex((STACK_BASE + STACK_FRAMES * 0x1000) as u32);
                print_str(b")\n");
                // On an INSTRUCTION-FETCH fault (ip==addr, both a bare low RVA) execution CALLed/JMPed
                // through a bad/truncated code pointer. Read the faulting thread's real GPRs + walk its
                // stack (TCB rsp) for return addresses in any mapped module — this identifies the CALLER
                // (module + RVA) whose indirect transfer landed on the bare RVA. General class-of-wall
                // diagnostic (BATCH 24/25: lsass rpcrt4 `0x3a288`); applies to any process at quiescence.
                if m0 == addr && addr < 0x8000_0000 {
                    let tcb = crate::PM_MAIN_TCBS[pi as usize].load(Ordering::Relaxed);
                    if tcb != 0 {
                        let mut regs = [0u64; 20];
                        crate::win32k_glue::tcb_read_regs20(tcb, &mut regs);
                        // seL4 x86_64 UserContext order: [0]rip [1]rsp [2]rflags [3]rax [4]rbx [5]rcx
                        // [6]rdx [7]rsi [8]rdi [9]rbp [10]r8..[17]r15.
                        print_str(b"[vmf-out] regs: rip=0x");
                        print_hex(regs[0] as u32);
                        print_str(b" rsp=0x");
                        print_hex((regs[1] >> 32) as u32);
                        print_hex(regs[1] as u32);
                        print_str(b" rax=0x");
                        print_hex((regs[3] >> 32) as u32);
                        print_hex(regs[3] as u32);
                        print_str(b" rcx=0x");
                        print_hex((regs[5] >> 32) as u32);
                        print_hex(regs[5] as u32);
                        print_str(b"\n");
                        // Walk the REAL stack (TCB rsp) for return addresses (ntdll 0x100_00xxxxxx / a
                        // mapped DLL 0x80xxxxxx). The nearest one identifies the faulting caller.
                        let rsp = regs[1];
                        // ★ TRUNC PROBE: [rsp] is the return address the CALLER pushed with its
                        // `call [mem]` that jumped to the bare RVA. Print [rsp+0..0x20] unconditionally
                        // so the immediate caller (module+RVA) is visible.
                        print_str(b"[trunc] top-of-stack:");
                        {
                            let mut j: u64 = 0;
                            while j < 4 {
                                let v = smss_stack_read(rsp + j * 8);
                                print_str(b" [rsp+0x");
                                print_hex((j * 8) as u32);
                                print_str(b"]=0x");
                                print_hex((v >> 32) as u32);
                                print_hex(v as u32);
                                j += 1;
                            }
                            print_str(b"\n");
                        }
                        print_str(b"[vmf-out] instr-fetch [rsp..]:");
                        let mut k: u64 = 0;
                        let mut printed: u64 = 0;
                        while k < 64 && printed < 12 {
                            let v = smss_stack_read(rsp + k * 8);
                            let is_ntdll = v >= 0x0000_0100_0000_0000 && v < 0x0000_0100_0100_0000;
                            // Widen to ALL mapped DLLs (0x8000_0000..0x8300_0000 covers rpcrt4/lsasrv/…)
                            // + lsass.exe/heap (0x100_0056_0000..0x100_00d0_0000) so the immediate
                            // rpcrt4/lsasrv caller + the heap dispatch object are captured.
                            let is_dll = v >= 0x8000_0000 && v < 0x8300_0000;
                            let is_lsass = v >= 0x0000_0100_0055_0000 && v < 0x0000_0100_00d0_0000;
                            if is_ntdll || is_dll || is_lsass {
                                print_str(b" +0x");
                                print_hex((k * 8) as u32);
                                print_str(b":0x");
                                print_hex((v >> 32) as u32);
                                print_hex(v as u32);
                                printed += 1;
                            }
                            k += 1;
                        }
                        print_str(b"\n");
                    }
                }
                // ★ Checkpoint B containment: once lsass has signaled LSA_RPC_SERVER_ACTIVE (its
                // essential init is done), an unrecoverable fault on lsass' MAIN thread (badge 8) —
                // e.g. rpcrt4 NdrSimpleTypeUnmarshall dereferencing a bogus RPC request buffer
                // (cr2 ~0xe000002d6) while its RPC server services a self-directed call — is CONTAINED:
                // PARK that thread (recv the next event without replying, leaving it blocked) so the
                // boot advances to winlogon's WaitForLsass/login instead of stopping. Same philosophy
                // as the N-threads listener-park; scoped so it can't mask a pre-signal lsass fault or
                // any other process's fault.
                if badge == LSASS_BADGE
                    && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                {
                    print_str(b"[wait] lsass main unrecoverable fault POST-LSA-signal -> PARK (boot continues)\n");
                    // Terminal for lsass main — count toward quiesce (lsass has done its signalling job).
                    crash_parked |= 1u64 << owner_top_badge(badge);
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    if (live_top_badges() & !(crash_parked | wait_parked)) == 0 {
                        print_str(b"[quiesce] every live process parked/waiting (no signaler left) -> run gate\n");
                        stop = addr;
                        break;
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
                // Unrecoverable fault outside every mapped image/DLL/scratch/stack (a truncated code
                // pointer / bad address the diagnostics above symbolized) — a real crash. Park+log.
                // park_and_log! diverges (type `!`) so this arm yields no value — match type is satisfied.
                park_and_log!(pi, b"vmf-out", m0, addr)
            };
            // Per-process demand-fault backstop. With the BATCH-22 scratch-VA decoupling (persistent
            // scratch bounded to ≤256 slots regardless of this count) this is now purely a
            // frame-budget / runaway guard, not a scratch limit — raised so lsass's full LSA-init DLL
            // tree (lsasrv/samsrv/msv1_0 + deps, thousands of pages) fits.
            if faults >= SEC_IMAGE_FAULT_CAP {
                // This process exhausted its per-process demand-fault budget (runaway / frame-pool
                // guard) — treat as unrecoverable for THIS process: park+log, let the others proceed.
                park_and_log!(pi, b"fault-cap", m0, addr);
            }
            // ★ BATCH BULK-FILL (BATCH 22 perf fix): under QEMU TCG each demand fault is a full
            // fault-EP round-trip (~4/s), so a big DLL image page-by-page dominates the boot budget
            // (lsass' LSA-init DLL tree ran past the 500s timeout). Instead of filling ONLY the
            // faulting page, fill+map a forward RUN of consecutive same-image pages in this one
            // round-trip. Every extra page is filled EXACTLY as its own demand fault would (same
            // fill_image_page/rights/cache/mirror/filled_pages bookkeeping) — pure correctness
            // preservation — so when the process resumes it finds the next pages already present and
            // does NOT re-fault them. This cuts the per-process round-trip count by ~BATCH×.
            //
            // The `end` bound is the containing image's extent (main image → img_end; a registered
            // DLL → base + image_size; ntdll → nt_end). Extra pages are only PRE-filled when they are
            // genuinely unmapped in THIS process — a per-process page not yet in `filled_pages`, and a
            // shared-text page not yet in the global `dll_cache` — so we never double-map. The
            // FAULTING page (batch index 0) keeps the full original logic incl. the shared-cache HIT
            // path; extra pages take the fresh-fill path (a shared page already cached is left to a
            // normal later fault — correct, just unbatched).
            let img_hi = if base == PE_LOAD_BASE {
                img_end
            } else if base == nt_base {
                nt_end
            } else if let Some((di, _)) = reg.dll_for_page(page) {
                reg.base(di) + reg.get(di).map(|d| d.image_size).unwrap_or(0)
            } else {
                base
            };
            // ★ (A) EAGER IMAGE-MAP. The FIRST time this process faults into an image (`base`), fill+map
            // the WHOLE image extent `[base, img_hi)` in this ONE round-trip instead of a small forward
            // RUN — same total frames, just UPFRONT, so the process never demand-faults that image's code
            // pages again (the dominant TCG cost: each per-page fault is a full fault-EP round-trip). On a
            // LATER fault into an already-eager image (a runtime re-touch / a fixup re-fault), fall back to
            // the small forward BATCH from the faulting page (the fixup-remap path preserves its frame).
            // The per-page body below is IDENTICAL for both — it just walks a wider window. `eager_mark`
            // makes this run exactly ONCE per (pi, image), so the whole-image pass is O(pages), not
            // O(pages^2): we start from `base`, and each page's mapped-state is checked via the scalable
            // (pi,page) frame map / shared cache — not the bounded `filled_pages` linear scan.
            let do_eager = img_hi > base && !eager_done(pi as u64, base);
            let (batch_start, batch_pages) = if do_eager {
                eager_mark(pi as u64, base);
                (base, (img_hi - base) / 0x1000)
            } else {
                const FORWARD_RUN: u64 = 4;
                (page, FORWARD_RUN)
            };
            let mut bi: u64 = 0;
            while bi < batch_pages {
                let bpage = batch_start + bi * 0x1000;
                if bpage >= img_hi || bpage < base {
                    break;
                }
                // The single page that actually FAULTED (present in every window). Only this page is
                // guaranteed unmapped; every other page must be checked before (re)mapping.
                let is_fault_page = bpage == page;
                if faults >= SEC_IMAGE_FAULT_CAP {
                    break;
                }
                let rva = (bpage - base) as u32;
                // SHAREABLE = a registered DLL's executable text (not the per-process main image at
                // PE_LOAD_BASE, and an RX page). Byte-identical across processes (each DLL loaded at a
                // fixed base + pre-relocated) → filled ONCE into a frame, mapped READ-ONLY (RX) into
                // every process that faults it — real image sharing.
                let shareable = base != PE_LOAD_BASE && page_rights(tpe, rva) == 2;
                let cached = if shareable { dll_cache_get(bpage) } else { 0 };
                // A forward run may overlap pages filled by an earlier run. The faulting page must
                // still be handled, but speculative neighbours that are already resident must not
                // be filled into a new frame and mapped over the live page (seL4 DeleteFirst).
                if !is_fault_page && !shareable && filled_pages.contains(&bpage) {
                    bi += 1;
                    continue;
                }
                // ★ BATCH 25 — FIXUP-SURVIVAL (the general correctness fix). A per-process image page
                // (a DLL's headers/.rdata/.idata/IAT or the main image) is filled ONCE from the raw
                // on-disk PE, then the ON-TARGET ntdll loader applies base RELOCATIONS + snaps the IAT
                // by WRITING into that mapped frame (in-process). Those fixups live ONLY in the frame,
                // NOT in the on-disk PE. If such a page is later RE-FAULTED at runtime (its mapping was
                // dropped / never landed / the demand loader re-touches it) and we naively re-FILL it
                // from the raw PE, we DISCARD the loader's fixups — a snapped IAT slot reverts to its
                // raw ILT thunk (a bare IMAGE_IMPORT_BY_NAME RVA), a relocated pointer loses its base.
                // OBSERVED (lsass, BATCH 24): kernel32's ntdll-IAT page (RVA 0x77000, in .rdata → RW)
                // reverted → CloseHandle's `call *[IAT]` jumped to the bare RVA 0x3a288 (should be
                // NTDLL_BASE+0x3a288) → instr-fetch fault, before SetEvent(LSA_RPC_SERVER_ACTIVE).
                // FIX: for a per-process page THIS process already has a frame recorded for
                // (`csrss_frame_get(pi,page)` — populated at the FIRST fill for every pi>=1 process),
                // RE-MAP that SAME frame (which holds the loader's in-memory fixups) instead of filling a
                // fresh raw frame. `csrss_frame_get` falls back to the shared DLL cache, so restrict to
                // `!shareable` (a genuine per-process frame the caller recorded). Applies to ANY page in
                // the window (not just the faulting one) so an eager whole-image pass re-maps, never
                // re-fills, a page whose fixups already landed.
                if !shareable && pi >= 1 {
                    let existing = csrss_frame_get(pi as u64, bpage);
                    if existing != 0 && existing != dll_cache_get(bpage) {
                        if is_fault_page {
                            // A previously-filled per-process frame for THE FAULTING page → re-map it
                            // (preserving fixups). rights: per-process image pages are RW_NX here.
                            let (cc, ce) = copy_cap_r(existing);
                            let me = page_map_r(cc, bpage, RW_NX, pml4);
                            let n = FIXUP_REMAP_N.fetch_add(1, Ordering::Relaxed);
                            if n < 16 {
                                print_str(b"[fixup-remap] pi=");
                                print_u64(pi as u64);
                                print_str(b" page=0x");
                                print_hex(bpage as u32);
                                print_str(b" frame preserved (copy=");
                                print_u64(ce);
                                print_str(b" map=");
                                print_u64(me);
                                print_str(b")\n");
                            }
                        }
                        // Already backed by a recorded per-process frame → it is (or was) mapped; do NOT
                        // re-fill/double-map a non-faulting page. Advance. (No `faults` bump — no fill.)
                        bi += 1;
                        continue;
                    }
                }
                // A non-faulting page must only be (pre)filled if it is genuinely UNMAPPED in this
                // process. The faulting page always proceeds (it faulted → it is NOT mapped). For a
                // shared page, `cached != 0` means a frame exists.
                //  - In the small FORWARD-RUN (non-eager) path, THIS process may already have the
                //    cached shared page mapped (it's a re-entry) → skip pre-mapping to avoid a
                //    double-map; let it fault normally if unmapped.
                //  - In the EAGER whole-image path (`do_eager` = the FIRST time this pi maps this
                //    image), the page is NOT yet mapped in this pi, so MAP the cached shared frame into
                //    THIS process here (cheap: a copy_cap + page_map, no fill, no fresh frame). This is
                //    the key eager win for a SECOND+ process mapping a DLL a prior process already
                //    filled: it gets every RX text page mapped in ONE round-trip, never demand-faulting
                //    that DLL's code. (The map falls through to the `cached != 0` arm below.)
                if !is_fault_page && shareable && cached != 0 && !do_eager {
                    bi += 1;
                    continue;
                }
                let (frame, rights) = if cached != 0 {
                    DLL_SHARED_HITS.fetch_add(1, Ordering::Relaxed);
                    (cached, 2u64) // shared text → RX, no fill, no fresh frame
                } else {
                    // MISS (shared, first process) or a per-process page: fill a fresh frame `f`,
                    // mapped at a UNIQUE monotonic scratch slot (seL4 records the mapping on the frame
                    // object, so a slot must not be reused without an unmap — unique slots are the
                    // proven model; a COPY of `f` is what gets mapped into the process). The BATCH does
                    // not change the TOTAL distinct pages a process fills (only WHEN, in fewer
                    // round-trips), so scratch consumption matches the pre-batch baseline; the widened
                    // + re-spaced per-process scratch windows (see *_SCRATCH_BASE) give room for the
                    // higher counts lsass's LSA-init tree reaches.
                    let scratch = scratch_base + faults * 0x1000;
                    let (f, fe) = alloc_frame_r();
                    let se = page_map_r(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                    if pi == 2 && bpage == 0x8230_e000 {
                        let (old, old_index) = csrss_frame_get_exact(2, 0x8045_1000);
                        print_str(b"[alias-diag] msgina-before faults=");
                        print_u64(faults);
                        print_str(b" scratch=0x");
                        print_hex((scratch >> 32) as u32);
                        print_hex(scratch as u32);
                        print_str(b" new-cap=0x");
                        print_hex(f as u32);
                        print_str(b" new-pa=0x");
                        let new_pa = if fe == 0 { get_frame_paddr(f) } else { 0 };
                        print_hex((new_pa >> 32) as u32);
                        print_hex(new_pa as u32);
                        print_str(b" old-cap=0x");
                        print_hex(old as u32);
                        print_str(b" old-pa=0x");
                        let old_pa = if old != 0 { get_frame_paddr(old) } else { 0 };
                        print_hex((old_pa >> 32) as u32);
                        print_hex(old_pa as u32);
                        print_str(b" old-idx=");
                        print_u64(if old_index == usize::MAX { u64::MAX } else { old_index as u64 });
                        print_str(b" retype=");
                        print_u64(fe);
                        print_str(b" smap=");
                        print_u64(se);
                        print_str(b"\n");
                    }
                    // ★ ROBUSTNESS (must precede the fill): fill_image_page WRITES the PE bytes THROUGH
                    // the scratch alias. If alloc_frame_r / page_map_r failed (untyped pool or CNode
                    // slots exhausted — the frame pressure eager-map front-loads), the scratch VA is
                    // NOT mapped, and an unconditional write here faults the EXECUTIVE ITSELF (tcb=3,
                    // no fault handler → the whole boot dies). Guard the fill on a successful map, and
                    // break out of this image's batch so the faulting thread is handled below (it will
                    // re-fault or park) instead of taking the executive down.
                    if fe != 0 || se != 0 {
                        print_str(b"[map-fail] rva=0x");
                        print_hex(rva);
                        print_str(b" retype=");
                        print_u64(fe);
                        print_str(b" smap=");
                        print_u64(se);
                        print_str(b" faults=");
                        print_u64(faults);
                        print_str(b" (alloc/map FAILED - skip fill, likely frame-pool pressure)\n");
                        break;
                    }
                    let r = fill_image_page(tpe, rva, scratch);
                    if pi == 2 && bpage == 0x8045_1000 {
                        KERNEL32_TABLE_WATCH_SCRATCH.store(scratch, Ordering::Relaxed);
                        print_str(b"[alias-watch] kernel32 table faults=");
                        print_u64(faults);
                        print_str(b" scratch=0x");
                        print_hex((scratch >> 32) as u32);
                        print_hex(scratch as u32);
                        print_str(b" cap=0x");
                        print_hex(f as u32);
                        print_str(b" pa=0x");
                        let pa = get_frame_paddr(f);
                        print_hex((pa >> 32) as u32);
                        print_hex(pa as u32);
                        print_str(b"\n");
                    }
                    if shareable {
                        dll_cache_put(bpage, f); // this frame becomes the shared copy for all processes
                    } else {
                        // Per-process page (main image, or DLL headers/rdata/data/IAT): record it for
                        // copy-out via its scratch alias, and mirror the main image so smss_copyin can
                        // read static-string args from .rdata.
                        if (faults as usize) < filled_pages.len() {
                            filled_pages[faults as usize] = bpage;
                        }
                        if pi == 1 || pi == 2 {
                            // Record this GUI client's (csrss pi 1 / winlogon pi 2) frame so win32k can
                            // identity-map + read/write it per-client (a client pointer into user32/gdi32
                            // .data — e.g. the PFNCLIENT arrays — the client's stack-built OBJECT_ATTRIBUTES,
                            // or its own image). The frame is shared with the executive's scratch, so it
                            // holds the client's LIVE runtime data, not the (zeroed) PE static content.
                            csrss_frame_put_at(pi as u64, bpage, f, scratch);
                        }
                        if base == PE_LOAD_BASE {
                            let off = bpage - PE_LOAD_BASE;
                            if off < IMAGE_MIRROR_WINDOW {
                                let mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
                                let _ = page_map(copy_cap(f), mirror + off, RW_NX, CAP_INIT_THREAD_VSPACE);
                            }
                        }
                    }
                    faults += 1; // a fill consumed a scratch slot; shared HITs do not
                    bump_progress(); // (B) a fresh page filled = real memory progress (resets stall)
                    (f, if shareable { 2 } else { r })
                };
                // Map the frame into the faulting process (RX for shared text, its fill rights otherwise).
                let (cc, ce) = copy_cap_r(frame);
                let me = page_map_r(cc, bpage, rights, pml4);
                if ce != 0 || me != 0 {
                    print_str(b"[map-fail] va=0x");
                    print_hex(bpage as u32);
                    print_str(b" copy=");
                    print_u64(ce);
                    print_str(b" map=");
                    print_u64(me);
                    print_str(b" shared=");
                    print_u64(shareable as u64);
                    print_str(b"\n");
                }
                bi += 1;
            }
            procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
            badge = nb;
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        // ntdll_plan Step 6.A — NATIVE seL4-Call transport. OUR ntdll (native-transport smss) does a
        // real seL4 `Call(CT_FAULT)` instead of a Windows-`syscall` UnknownSyscall trap. The request
        // carries: MR0=SSN(m0), MR1=caller-rsp(m1), MR2=arg1(m2), MR3=arg2(m3), MR4=arg3(recv_mr[4]),
        // MR5=arg4(recv_mr[5]); args5+ stay on the caller's stack (read via the mirror using rsp). We
        // NORMALIZE it into the fault-frame register slots the `(mi>>12)==2` arm reads, then re-label
        // the message as UnknownSyscall (2) so it flows through that arm's FULL servicing body
        // unchanged (dispatch + out-writes + spawn/park/delay post-actions). The reply is a NORMAL IPC
        // reply (the native caller has NO pending fault): `reply_recv_badge(..,result,..)` fans
        // result→MR0→the caller's r10, which our native stub reads as NTSTATUS.
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0; // MR0
            let rsp = m1; // MR1 = caller rsp (for stack args + stack out-param mirror writes)
            let arg1 = m2; // MR2
            let arg2 = m3; // MR3
            let arg3 = get_recv_mr(4); // MR4 (IPC buffer)
            let arg4 = get_recv_mr(5); // MR5 (IPC buffer)
            // Stage the fault-frame register slots the `==2` arm reads: R10@9=arg1, R8@7=arg3,
            // R9@8=arg4, SP@16=rsp, FLAGS@17=0. (arg2 is read directly from `m3`.)
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            // m0 stays = SSN; m2 becomes resume_ip (unused for a native reply — no fault restart).
            m0 = ssn;
            m2 = 0;
            // Re-label as UnknownSyscall so the shared servicing arm below runs.
            mi = (2u64 << 12) | (mi & 0x7F);
            // BATCH 34 DIAG: trace every SERVER listener SSN so the boot log reveals the exact
            // rpcrt4 ncacn_np server-side wait model (NtCreateNamedPipeFile / FSCTL_PIPE_LISTEN /
            // overlapped NtReadFile / NtWaitForMultipleObjects). Bounded so it never floods.
            if is_svc_listener {
                let dn = SVC_LISTENER_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if dn < 24 {
                    print_str(b"[svc-listener-ssn] #");
                    print_u64(dn);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b" arg1=0x");
                    print_hex(arg1 as u32);
                    print_str(b" arg2=0x");
                    print_hex(arg2 as u32);
                    print_str(b"\n");
                }
            }
            // BATCH 37 DIAG: trace the SCM per-connection worker's native SSNs to reveal exactly why it
            // exits before reading the bind (the self-inspection syscalls + which handle it reads/exits on).
            if is_scm_worker {
                let dn = SCM_WORKER_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if dn < 32 {
                    print_str(b"[scm-worker-ssn] #");
                    print_u64(dn);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b" arg1=0x");
                    print_hex(arg1 as u32);
                    print_str(b" arg2=0x");
                    print_hex(arg2 as u32);
                    print_str(b"\n");
                }
            }
        }
        if (mi >> 12) == 2 {
            // A native `syscall` from the process (via ntdll's Nt* stub). SSN_DONE is our test
            // sentinel; otherwise it's a REAL Nt* system call to service.
            if m0 == SSN_DONE {
                verdict = get_recv_mr(9); // R10 = arg1
                break;
            }
            ssn_ring[ssn_ri % 32] = m0 as u16;
            ssn_ring_badge[ssn_ri % 32] = badge as u8;
            ssn_ri += 1;
            if badge == WINLOGON_BADGE {
                wl_ring[wl_ri % 48] = m0 as u16;
                wl_ri += 1;
            }
            let resume_ip = m2; // RCX = syscall return address
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let current_tid = if let Some((tp_pi, tp_slot)) = tp_worker_identity {
                TP_WORKER_TID[tp_pi][tp_slot].load(Ordering::Relaxed)
            } else if is_svc_listener {
                SVC_LISTENER_TID.load(Ordering::Relaxed)
            } else if is_scm_worker {
                SCM_WORKER_TID.load(Ordering::Relaxed)
            } else if is_lsass_listener {
                LSASS_LISTENER_TID.load(Ordering::Relaxed)
            } else if is_lsass_listener2 {
                LSASS_LISTENER2_TID.load(Ordering::Relaxed)
            } else if is_lsass_listener3 {
                LSASS_LISTENER3_TID.load(Ordering::Relaxed)
            } else if is_wl_worker {
                match badge {
                    WINLOGON_WORKER2_BADGE => WL_WORKER2_TID.load(Ordering::Relaxed),
                    WINLOGON_WORKER3_BADGE => WL_WORKER3_TID.load(Ordering::Relaxed),
                    _ => PM_LISTENER_TID.load(Ordering::Relaxed),
                }
            } else {
                PM_TIDS[pi].load(Ordering::Relaxed)
            };
            if m0 == 22 {
                if let Some(completion) = win32k_glue::complete_controlled_user_callback(
                    pi as u32,
                    badge,
                    current_tid,
                    get_recv_mr(9),
                    m3,
                    get_recv_mr(7),
                ) {
                    if pi == 2 {
                        if let Some(dispatch) = completion.outer_dispatch {
                            observe_winlogon_completed_dispatch(
                                dispatch,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            );
                            observe_completed_dialog_modal_dispatch(
                                dispatch,
                                badge,
                                current_tid,
                            );
                        }
                    }
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    send_on_reply(reply_main, 0, 0, 0, 0, 0);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, reply_main);
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
            }
            let mut result = 0u64; // STATUS_SUCCESS unless a handler overrides
            let mut handled = true;
            // BATCH 43: set when winlogon reaches its win32k SAS-window creation milestone (0x1077 OK) →
            // park it (recv-next-without-reply) so the boot quiesces + the gate runs (see the !handled block).
            let mut wl_milestone_park = false;
            // Fix (B): set when this syscall was routed to the win32k component. win32k faults
            // during the nested dispatch clobber the executive's `reply_to` (finish_call), so this
            // caller's reply must go back through its bound reply cap (REPLY_MAIN) rather than the
            // legacy reply_to path — see the tail below.
            let mut routed_win32k = false;
            // Set when csrss's NtConnectPort was completed via the nested SM rendezvous (like
            // routed_win32k, the SM-loop thread's faults clobbered `reply_to`, so reply via REPLY_MAIN).
            let mut routed_lpc = false;
            // Set when winlogon's NtSecureConnectPort was completed via the nested CSR rendezvous
            // (like routed_lpc, the CSR thread's faults clobbered reply_to → reply via REPLY_MAIN).
            let mut routed_csr = false;
            let mut redirected_user_callback = false;
            // Broker-only terminal waits (currently smss waiting forever for csrss/winlogon) park
            // by withholding a reply. Self-termination does not use this flag: its explicit post
            // action deletes the bound Reply cap and caller TCB before receiving again.
            let mut park_caller = false;
            // Checkpoint B: -1 = no wait-park; >=0 = NtWaitForSingleObject asked to park this caller on
            // the given obj_ns event index (set from nt_handler.wait_park_event after dispatch).
            let mut park_wait_event: i64 = -1;
            // Array-wait park (NtWaitForMultipleObjects): the resolved obj_ns event set + WaitAll flag.
            // count 0 = no array-park. Consumed next to park_wait_event in the reply block.
            let park_wait_set = &mut *core::ptr::addr_of_mut!(PARK_WAIT_SET_WORK);
            let park_wait_indices = &mut *core::ptr::addr_of_mut!(PARK_WAIT_INDEX_WORK);
            let mut park_wait_set_n: usize = 0;
            let mut park_wait_set_all = false;
            let mut park_wait_deadline: Option<u64> = None;
            let mut park_keyed_wait_key: u64 = u64::MAX;
            let mut park_keyed_wait_deadline: Option<u64> = None;
            let mut park_delay_deadline: Option<u64> = None;
            let mut park_io_completion_port: i64 = -1;
            let mut park_io_completion_key_out: u64 = 0;
            let mut park_io_completion_apc_out: u64 = 0;
            let mut park_io_completion_iosb_out: u64 = 0;
            let mut park_io_completion_deadline: Option<u64> = None;
            // BATCH 33 — pipe-pending park request latched from the handler (0 = none). Consumed at the
            // reply site (the reply-cap steal needs resume_ip/sp/flags, known there).
            let mut park_pipe_fid: u64 = 0;
            let mut park_pipe_buffer_va: u64 = 0;
            let mut park_pipe_buffer_len: u32 = 0;
            let mut park_pipe_iosb_va: u64 = 0;
            let mut park_pipe_transceive = false;
            // Every syscall path, including the still hand-wired ladder below, resolves process-local
            // handles through ExecNtHandler. Refresh caller identity before choosing table vs ladder;
            // doing this only inside table dispatch left a runtime worker using whichever process ran
            // the previous registered syscall.
            nt_handler.pi = pi;
            nt_handler.current_badge = badge;
            nt_handler.current_tid = current_tid;
            // SEAM: if this SSN is in the real service table, dispatch it through the NT syscall
            // dispatcher -> real handler; otherwise fall through to the broker match. The x64 native
            // ABI passes args in r10(=rcx),rdx,r8,r9 then the stack; here we forward the register
            // args (sized to the service's max) — pointer/stack args come with the copyin layer.
            if let Some(entry) = nt_dispatcher.table().lookup(m0 as u32) {
                let origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
                // x64 native syscall args: arg1=R10 (the stub's `mov r10,rcx`; RCX itself is the
                // syscall return address), arg2=RDX, arg3=R8, arg4=R9, then arg5+ on the caller's
                // stack at [rsp+0x28], [rsp+0x30], … RDX rides in m3; R8/R9/R10 + the stack come
                // from the IPC buffer / stack mirror.
                let mut argv = [0u64; 16];
                argv[0] = get_recv_mr(9); // R10
                argv[1] = m3; // RDX
                argv[2] = get_recv_mr(7); // R8
                argv[3] = get_recv_mr(8); // R9
                let n = (entry.max_args as usize).min(16);
                let mut stack_args_valid = true;
                for i in 4..n {
                    let Some(argument_va) =
                        sp.checked_add(0x28 + (i as u64 - 4) * 8)
                    else {
                        stack_args_valid = false;
                        break;
                    };
                    let mut bytes = [0u8; 8];
                    if client_copyin_mapped(
                        pi as u64,
                        argument_va,
                        &mut bytes,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    ) {
                        argv[i] = u64::from_le_bytes(bytes);
                    } else {
                        stack_args_valid = false;
                        break;
                    }
                }
                // Refresh the handler's per-call executive context, then clear the stop side-signal
                // + out-write queue so a migrated handler can raise them (group A/B signals).
                nt_handler.post_action = ExecPostAction::None;
                nt_handler.stop = false;
                nt_handler.overlay_dirty = false;
                nt_handler.dll_loaded_dirty = false;
                nt_handler.token_dirty = false;
                nt_handler.out_writes_n = 0;
                nt_handler.spawn_request = false;
                nt_handler.winlogon_spawn_request = false;
                nt_handler.services_spawn_request = false;
                nt_handler.lsass_spawn_request = false;
                nt_handler.process_spawn_desired_access = 0;
                nt_handler.sm_spawn_request = false;
                nt_handler.wl_spawn_request = 0;
                nt_handler.svc_listener_spawn = false;
                nt_handler.lsass_listener_spawn = false;
                nt_handler.lsass_listener2_spawn = false;
                nt_handler.lsass_listener3_spawn = false;
                nt_handler.tp_worker_spawn_request = 0;
                nt_handler.wait_park_event = -1;
                nt_handler.wait_deadline_100ns = u64::MAX;
                nt_handler.keyed_wait_key = u64::MAX;
                nt_handler.keyed_wait_deadline_100ns = u64::MAX;
                nt_handler.delay_requested = false;
                nt_handler.delay_interval_100ns = 0;
                nt_handler.delay_alertable = false;
                nt_handler.io_completion_park_port = -1;
                nt_handler.io_completion_key_out = 0;
                nt_handler.io_completion_apc_out = 0;
                nt_handler.io_completion_iosb_out = 0;
                nt_handler.io_completion_deadline_100ns = u64::MAX;
                nt_handler.io_completion_wake = None;
                nt_handler.io_signal_event = -1;
                nt_handler.pipe_park_fid = 0;
                nt_handler.pipe_park_buffer_va = 0;
                nt_handler.pipe_park_buffer_len = 0;
                nt_handler.pipe_park_iosb_va = 0;
                nt_handler.pipe_park_transceive = false;
                nt_handler.pipe_write_redrive = false;
                nt_handler.pipe_listen_fid = 0;
                nt_handler.pipe_listen_event_handle = 0;
                nt_handler.pipe_listen_iosb_va = 0;
                nt_handler.pipe_connect_redrive = 0;
                nt_handler.lpc_rendezvous_conn = 0;
                nt_handler.sm_request_port = 0;
                nt_handler.sm_request_message = 0;
                nt_handler.sm_reply_message = 0;
                nt_handler.csr_spawn_request = 0;
                nt_handler.csr_start_request = 0;
                nt_handler.csr_rendezvous_conn = 0;
                // Group-C handlers reach the loop's section/registry/demand-fill state through this
                // ctx of raw refs (rebuilt each iteration at the current loop locals).
                nt_handler.loop_ctx = Some(ExecLoopCtx {
                    pml4,
                    procs: &mut procs,
                    pfilled,
                    nls_section_handle: &mut nls_section_handle as *mut u64,
                    reg: &mut reg as *mut nt_dll_registry::Registry,
                    csrss_file_handle: &mut csrss_file_handle as *mut u64,
                    csrss_section_handle: &mut csrss_section_handle as *mut u64,
                    csrss_pe: &csrss_pe as *const Option<nt_pe_loader::PeFile<'static>>,
                    winlogon_file_handle: &mut winlogon_file_handle as *mut u64,
                    winlogon_section_handle: &mut winlogon_section_handle as *mut u64,
                    winlogon_pe: &winlogon_pe as *const Option<nt_pe_loader::PeFile<'static>>,
                    services_file_handle: &mut services_file_handle as *mut u64,
                    services_section_handle: &mut services_section_handle as *mut u64,
                    services_pe: &services_pe as *const Option<nt_pe_loader::PeFile<'static>>,
                    lsass_file_handle: &mut lsass_file_handle as *mut u64,
                    lsass_section_handle: &mut lsass_section_handle as *mut u64,
                    lsass_pe: &lsass_pe as *const Option<nt_pe_loader::PeFile<'static>>,
                    filled_pages: filled_pages as *mut [u64; 512],
                    faults: &mut faults as *mut u64,
                    scratch_base,
                    // Erase the non-'static lifetime through a thin `*const ()` (the image bytes are
                    // executive-lifetime; the loop outlives every `dispatch`).
                    pe: pe as *const nt_pe_loader::PeFile as *const ()
                        as *const nt_pe_loader::PeFile<'static>,
                    ntdll_pe: match ntdll {
                        Some((_, npe)) => {
                            npe as *const nt_pe_loader::PeFile as *const ()
                                as *const nt_pe_loader::PeFile<'static>
                        }
                        None => core::ptr::null(),
                    },
                    img_end,
                    nt_base,
                    nt_end,
                    dll_pes: dll_pes.as_ptr() as *const &'static Option<nt_pe_loader::PeFile<'static>>,
                    dll_pes_len: dll_pes.len(),
                    dll_pe_store: dll_pe_store_ptr as *mut ()
                        as *mut Option<nt_pe_loader::PeFile<'static>>,
                    csrss_anon_section_handle: &mut csrss_anon_section_handle as *mut u64,
                    csrss_anon_size: &mut csrss_anon_size as *mut u64,
                    csrss_anon_base: &mut csrss_anon_base as *mut u64,
                    dll_pd_created: &mut dll_pd_created as *mut [bool; MAX_PI],
                    dll_pt_bits: &mut dll_pt_bits
                        as *mut [[u64; DLL_ARENA_PT_WORDS]; MAX_PI],
                });
                // ALPC last-mile item (a): NtAlpc* SSNs are registered in the dispatcher via this
                // recognizer. DORMANT — `ALPC_HOST_PRESENT` is never set at boot (no ALPC binary
                // yet), and the Win7 ALPC SSNs collide with the live ReactOS SSN space, so it can
                // never fire for the 3 live ReactOS processes → byte-identical boot. When active it
                // routes a real ALPC process's NtAlpc* syscall to the unified port-service ALPC
                // adapter (skipping the native ReactOS dispatch).
                if !stack_args_valid {
                    result = 0xC000_0005;
                } else if let Some(st) = try_route_alpc_ssn(m0, &[], &mut [0u8; 8]) {
                    result = st;
                    handled = true;
                } else {
                    let res = nt_dispatcher.dispatch(m0 as u32, &argv[..n], &origin, &mut nt_handler);
                    result = res.status as u64;
                    if nt_handler.stop {
                        handled = false; // handler couldn't service → stop with the SSN recorded
                    }
                }
                // NtResumeThread for a CSRSS server worker is a serialized run-to-receive action.
                // Execute it immediately after dispatch, while the main CSRSS Call is still bound to
                // REPLY_MAIN and therefore cannot race this worker on the shared native IPC frame.
                if nt_handler.csr_start_request != 0 {
                    // The nested CSR endpoint receive replaces the kernel's implicit reply_to.
                    // Preserve the main caller by forcing the tail through its bound REPLY_MAIN cap.
                    routed_csr = true;
                    print_str(b"[csr-thread] outer start role=");
                    print_u64(nt_handler.csr_start_request as u64);
                    print_str(b"\n");
                    if nt_handler.csr_start_request == 1 {
                        let tcb = CSR_LOOP_TCB.load(Ordering::Relaxed);
                        if tcb > 1 {
                            let _ = tcb_resume(tcb);
                            let _ = csr_rendezvous(
                                0,
                                procs[1].pml4,
                                csrss_pe.as_ref().unwrap(),
                                procs[1].img_end,
                                nt_base,
                                nt_end,
                                ntdll.map(|(_, p)| p),
                                &reg,
                                &dll_pes,
                                &mut nt_handler,
                            );
                            if CSR_API_RECEIVE_PARKED.load(Ordering::Relaxed) == 0 {
                                result = 0xC000_0001;
                            } else {
                                let tid = CSR_API_TID.load(Ordering::Relaxed);
                                let _ = nt_handler.pm.set_thread_state(
                                    tid as nt_process::ThreadId,
                                    nt_process::ThreadState::Running,
                                );
                            }
                        } else {
                            result = 0xC000_0001;
                        }
                    } else if nt_handler.csr_start_request == 2 {
                        let tcb = CSR_SB_LOOP_TCB.load(Ordering::Relaxed);
                        if tcb > 1 {
                            let _ = tcb_resume(tcb);
                            if !csr_sb_startup(
                                procs[1].pml4,
                                csrss_pe.as_ref().unwrap(),
                                procs[1].img_end,
                                nt_base,
                                nt_end,
                                ntdll.map(|(_, p)| p),
                                &reg,
                                &dll_pes,
                            ) {
                                result = 0xC000_0001;
                            } else {
                                let tid = CSR_SB_TID.load(Ordering::Relaxed);
                                let _ = nt_handler.pm.set_thread_state(
                                    tid as nt_process::ThreadId,
                                    nt_process::ThreadState::Running,
                                );
                            }
                        } else {
                            result = 0xC000_0001;
                        }
                    }
                }
                // A successful self-termination is a control-flow action, not a status-returning
                // syscall. First delete/replace the Reply object bound to this fault (so no send can
                // resume it), then suspend/delete the exact badge-selected TCB, and receive the next
                // caller immediately. Remote termination tears down its target but still replies to
                // the caller through the normal tail below.
                match nt_handler.post_action {
                    ExecPostAction::TerminateCurrentThread { tid } => {
                        // BATCH 34: if the SCM RPC listener (svc-listener, badge 7) terminates, mark the
                        // SCM server no-longer-live so winlogon's SCM read-park becomes terminal (quiesce)
                        // instead of hanging the loop's recv (no signaler left until the per-connection
                        // worker is routed — the flagged N-threads follow-up).
                        if is_svc_listener {
                            SVC_LISTENER_TERMINATED.store(1, Ordering::Relaxed);
                        }
                        let reply_dropped = drop_current_syscall_reply();
                        let mechanism_deleted = terminate_hosted_thread_mechanism(
                            tid,
                            &mut delay_queue,
                            &mut nt_handler,
                        );
                        if reply_dropped && mechanism_deleted {
                            PM_TERMINATE_THREAD_NO_REPLY.fetch_add(1, Ordering::Relaxed);
                        }
                        print_str(b"[thread-term] self-post tid=");
                        print_u64(tid);
                        print_str(b" reply-dropped=");
                        print_u64(reply_dropped as u64);
                        print_str(b" mechanism-deleted=");
                        print_u64(mechanism_deleted as u64);
                        print_str(b" -> recv without reply\n");
                        procs[pi].faults = faults;
                        procs[pi].first = first;
                        procs[pi].ntfaults = ntfaults;
                        pfilled[pi] = *filled_pages;
                        // BATCH 34: the SCM listener just exited AND winlogon is already SCM-read-parked
                        // (waiting for bind_ack). No live signaler remains (BATCH 35 routes the
                        // per-connection worker but it PARKS on a trampoline-entry fault — see the frontier
                        // note; it does not yet write bind_ack), so QUIESCE now → run the gate + clean
                        // qemu_exit instead of blocking to timeout.
                        if is_svc_listener
                            && WINLOGON_SCM_PARKED.load(Ordering::Relaxed) != 0
                        {
                            print_str(b"[wl-main] SCM listener exited while winlogon SCM-read-parked (no worker routed yet) -> QUIESCE; run gate\n");
                            stop = m1;
                            break;
                        }
                        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                        let (nb, nmi, nm0, nm1, nm2, nm3) =
                            recv_full_r12(fault_ep, new_reply);
                        badge = nb;
                        mi = nmi;
                        m0 = nm0;
                        m1 = nm1;
                        m2 = nm2;
                        m3 = nm3;
                        continue;
                    }
                    ExecPostAction::TerminateRemoteThread { tid } => {
                        let _ = terminate_hosted_thread_mechanism(
                            tid,
                            &mut delay_queue,
                            &mut nt_handler,
                        );
                    }
                    ExecPostAction::CleanupProcessWaiters { process_index } => {
                        io_completion_cancel_process(&mut nt_handler, process_index);
                        delay_timer_rearm(&delay_queue);
                    }
                    ExecPostAction::CriticalTermination { code, object } => {
                        let reply_dropped = drop_current_syscall_reply();
                        print_str(b"[critical-termination] bugcheck=0x");
                        print_hex(code);
                        print_str(b" object=0x");
                        print_hex((object >> 32) as u32);
                        print_hex(object as u32);
                        print_str(b" reply-dropped=");
                        print_u64(reply_dropped as u64);
                        print_str(b" -> fatal stop\n");
                        stop = code as u64;
                        break;
                    }
                    ExecPostAction::None => {}
                }
                // CM write plane: a handler that mutated the registry overlay (NtCreateKey/
                // NtSetValueKey) allocated `String`/`Vec` on the bump heap ABOVE `heap_mark`. Pin the
                // mark PAST them now so the next iteration's `reset_to(heap_mark)` keeps them (real
                // NT: created keys/values persist). The mark also swallows this iteration's transient
                // allocations — a bounded leak (only a handful of overlay mutations per boot), well
                // within the 2 MiB heap; non-mutating iterations still reset fully.
                if nt_handler.overlay_dirty {
                    nt_handler.overlay_dirty = false;
                    heap_mark = allocator::mark();
                }
                // Demand-load plane: a handler that demand-loaded a DLL (NtOpenFile resolve-miss →
                // fs_loader::demand_load_dll → registry `activate`d a reserved slot + wrote its parsed
                // PE into dll_pe_store) pins the heap mark PAST the load's allocations so the activated
                // registry slot survives the next `reset_to(heap_mark)`. Mirrors `overlay_dirty` — the
                // pool bytes + dll_pe_store write are already reset-safe; this covers the registry fill.
                if nt_handler.dll_loaded_dirty {
                    nt_handler.dll_loaded_dirty = false;
                    heap_mark = allocator::mark();
                }
                if nt_handler.token_dirty {
                    nt_handler.token_dirty = false;
                    heap_mark = allocator::mark();
                }
                // Drain queued out-param writes (group B2): csrss out-ptrs may be arbitrary VAs that
                // need a persistent image-page alias; other hosted processes can also return values
                // to DLL globals. Use the handler's common cross-address-space writer for both.
                for k in 0..nt_handler.out_writes_n {
                    let (ptr, val) = nt_handler.out_writes[k];
                    if !nt_handler.xas_write_u64(ptr, val) {
                        print_str(b"[copyout] failed pi=");
                        print_u64(pi as u64);
                        print_str(b" ptr=0x");
                        print_hex((ptr >> 32) as u32);
                        print_hex(ptr as u32);
                        print_str(b"\n");
                    }
                }
                // Checkpoint B: NtWaitForSingleObject on an unsignaled real event asked to PARK this
                // caller. Latch it for the reply site (the actual reply-cap steal happens there where
                // resume_ip/sp/flags are known).
                if nt_handler.wait_park_event >= 0 {
                    park_wait_event = nt_handler.wait_park_event;
                    if nt_handler.wait_deadline_100ns != u64::MAX {
                        park_wait_deadline = Some(nt_handler.wait_deadline_100ns);
                    }
                }
                if nt_handler.keyed_wait_key != u64::MAX {
                    park_keyed_wait_key = nt_handler.keyed_wait_key;
                    if nt_handler.keyed_wait_deadline_100ns != u64::MAX {
                        park_keyed_wait_deadline = Some(nt_handler.keyed_wait_deadline_100ns);
                    }
                }
                if nt_handler.delay_requested {
                    let monotonic_now = monotonic_time_100ns();
                    let system_now = nt_system_time_100ns();
                    match nt_delay_execution::due_time(
                        nt_handler.delay_interval_100ns,
                        monotonic_now,
                        system_now,
                    ) {
                        nt_delay_execution::Due::Immediate => {
                            if DELAY_TRACE_COUNT.load(Ordering::Relaxed) <= 16 {
                                print_str(b"[delay] COMPLETE-IMMEDIATE badge=");
                                print_u64(badge);
                                print_str(b" tid=");
                                print_u64(nt_handler.current_tid);
                                print_str(b" callsite=0x");
                                print_hex_u64(resume_ip);
                                print_str(b" interval_100ns=");
                                if nt_handler.delay_interval_100ns < 0 {
                                    print_str(b"-");
                                    print_u64(nt_handler.delay_interval_100ns.unsigned_abs());
                                } else {
                                    print_u64(nt_handler.delay_interval_100ns as u64);
                                }
                                print_str(b"\n");
                            }
                        }
                        nt_delay_execution::Due::Monotonic100ns(deadline) => {
                            park_delay_deadline = Some(deadline);
                            if DELAY_TRACE_COUNT.load(Ordering::Relaxed) <= 16 {
                                print_str(b"[delay] PARK-REQUEST badge=");
                                print_u64(badge);
                                print_str(b" tid=");
                                print_u64(nt_handler.current_tid);
                                print_str(b" callsite=0x");
                                print_hex_u64(resume_ip);
                                print_str(b" deadline_100ns=");
                                print_u64(deadline);
                                print_str(b" now_100ns=");
                                print_u64(monotonic_now);
                                print_str(if nt_handler.delay_alertable {
                                    b" alertable=1 queued_apc=0\n"
                                } else {
                                    b" alertable=0 queued_apc=0\n"
                                });
                            }
                        }
                    }
                }
                if nt_handler.io_completion_park_port >= 0 {
                    park_io_completion_port = nt_handler.io_completion_park_port;
                    park_io_completion_key_out = nt_handler.io_completion_key_out;
                    park_io_completion_apc_out = nt_handler.io_completion_apc_out;
                    park_io_completion_iosb_out = nt_handler.io_completion_iosb_out;
                    if nt_handler.io_completion_deadline_100ns != u64::MAX {
                        park_io_completion_deadline = Some(nt_handler.io_completion_deadline_100ns);
                    }
                }
                if nt_handler.io_completion_wake.is_some() {
                    let _ = unsafe { io_completion_deliver(&mut nt_handler) };
                }
                if nt_handler.io_signal_event >= 0 {
                    let _ = wait_wake_dispatcher_set(&mut nt_handler);
                }
                // BATCH 33: latch a pipe-pending park request (the reply-cap steal happens at the reply
                // site where resume_ip/sp/flags are known). Re-drive any parked pipe reads on a peer
                // write (done HERE, before the writer's own reply — npfs already queued the bytes).
                if nt_handler.pipe_park_fid != 0 {
                    park_pipe_fid = nt_handler.pipe_park_fid;
                    park_pipe_buffer_va = nt_handler.pipe_park_buffer_va;
                    park_pipe_buffer_len = nt_handler.pipe_park_buffer_len;
                    park_pipe_iosb_va = nt_handler.pipe_park_iosb_va;
                    park_pipe_transceive = nt_handler.pipe_park_transceive;
                }
                // ★ BATCH 34: a client CONNECT to a pipe with a pending async server FSCTL_PIPE_LISTEN
                // for the SAME pipe name completes that listen — signal its completion event so the
                // server's NtWaitForMultipleObjects wakes and reads the client's first PDU (the bind).
                // Name-scoped (pipe_connect_redrive carries the connected pipe's leaf name-hash) so a
                // connect to \ntsvcs never spuriously wakes the \lsarpc/\samr servers. Only a CONNECT
                // (not a write) completes a listen — a write re-drives parked reads (below), which is
                // the correct edge once the connection is established.
                if nt_handler.pipe_connect_redrive != 0 {
                    let connect_name_hash = nt_handler.pipe_connect_redrive;
                    let listens = pipe_listen_complete_named(&mut nt_handler, connect_name_hash);
                    if listens != 0 {
                        print_str(b"[pipe-listen] completed ");
                        print_u64(listens);
                        print_str(b" pending server listen(s) on client connect\n");
                    }
                }
                if nt_handler.pipe_write_redrive {
                    let woken = pipe_redrive_all(&mut nt_handler);
                    if woken != 0 && PIPE_REDRIVE_TRACE_COUNT.load(Ordering::Relaxed) <= 20 {
                        print_str(b"[pipe-redrive] peer write woke ");
                        print_u64(woken);
                        print_str(b" parked reader(s)\n");
                    }
                }
                // Control-flow post-action (group C): NtCreateProcess validated the csrss section and
                // asked the loop to spawn the subsystem process (needs fault_ep + the per-badge
                // arrays that stay loop-resident). Mirrors the stop/out-write signal-back.
                if nt_handler.spawn_request {
                    // Fault-EP cap minted at CSRSS_BADGE: csrss's faults/syscalls arrive on the shared
                    // service EP tagged with that badge, so this loop multiplexes it against smss.
                    let cf_c = mint_badged(fault_ep, CSRSS_BADGE);
                    let cpe = csrss_pe.as_ref().unwrap();
                    // Priority 101 (above smss's 100) so csrss actually gets scheduled: at equal
                    // priority smss + the executive ping-pong and csrss never runs. csrss preempts
                    // when runnable but blocks on every demand-fault (serviced by THIS loop, badge 2),
                    // which hands smss its turns — so both make progress and smss's own checks still
                    // pass. csrss uses a DISTINCT env-build scratch (0x78_0000, vs smss's 0x74_0000)
                    // so its trampoline/PEB/params frames aren't clobbered by smss's still-mapped ones.
                    // csrss's OWN process parameters (not smss's): its System32 image path drives
                    // the loader's DLL search + ".local" SxS probe, and its Server command line
                    // (ObjectDirectory/ServerDll=…) is what csrss.exe's entry parses once loaded.
                    const CSRSS_IMAGE_PATH: &[u8] = b"\\SystemRoot\\System32\\csrss.exe";
                    // TEMP (Phase 0b): drop the two `ServerDll=winsrv:...` entries. winsrv is the
                    // Win32 GUI server; its UserServerDllInitialization issues win32k NtUser/NtGdi
                    // syscalls (SSN >= 0x1000) that we have no graphics subsystem to service — a
                    // benign-success stub makes it null-deref the fake HWND/HDESK return. Skipping
                    // winsrv makes CsrParseServerCommandLine load only basesrv + csrsrv (neither
                    // touches win32k) so csrss reaches csrsrv's CsrApiPortInitialize / \SmApiPort +
                    // the SM<->CSR handshake, which csrsrv owns independently of winsrv. Real winsrv
                    // init returns once win32k is hosted (Phase 2).
                    // (`ServerDll=csrsrv` is NOT listed: csrsrv is ServerDll index 0, loaded
                    // implicitly by CsrServerInitialization itself. Listing it fails CsrLoadServerDll
                    // with STATUS_INVALID_PARAMETER — it has no ServerId. The real ReactOS command
                    // line omits it too; it was only masked before by winsrv crashing first.)
                    // Milestone C — winsrv DEFERRED pending the gSharedInfo grind (routing + marshaling
                    // infra is IN PLACE; re-enabling is the one-line ServerDll add below). With winsrv
                    // ON, csrsrv loads the full 14-DLL Win32 client stack and user32's DllMain `Init`
                    // (dllmain.c:410) calls **NtUserProcessConnect(NtCurrentProcess(), USERCONNECT*, 0x240)**
                    // = win32k SSN 0x10FA. The executive's SSN>=0x1000 forward arm ROUTES it (translating
                    // NtCurrentProcess()==-1 → the hosted client handle + marshaling the 0x240 USERCONNECT
                    // buffer through the shared ARG frame). BUT win32k's real NtUserProcessConnect handler
                    // then CPU-SPINS (zero faults, never signals done) — with the real ulVersion=USER_VERSION
                    // input it takes the FULL connect path that fills UserCon->siClient (gSharedInfo: psi +
                    // aheList handle table) from win32k's shared section, which isn't set up as a
                    // client-mappable section yet. Completing that (win32k produces a real USERCONNECT +
                    // executive maps win32k's gSharedInfo shared section RO into csrss + user32 derefs
                    // gHandleTable->handles) is the NEXT grind. Until then winsrv stays OUT so the gate is
                    // green. (`ServerDll=csrsrv` also stays OUT — csrsrv is ServerDll index 0, implicit.)
                    const CSRSS_CMD_LINE: &[u8] = b"csrss.exe ObjectDirectory=\\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16";
                    let cpml4 = spawn_sec_image(
                        1, cpe, cf_c, NTDLL_BASE, true, 101, 0x0000_0100_1078_0000,
                        CSRSS_STACK_MIRROR_VA, CSRSS_HEAP_MIRROR_VA, 0, CSRSS_IMAGE_PATH, CSRSS_CMD_LINE,
                        0, // 0 → effective_ldrp_rva resolves to OUR ntdll's derived LdrpInitialize RVA
                    );
                    // Register csrss's per-process state (slot 1) so badge-2 faults resolve against
                    // ITS VSpace/image and a private scratch window.
                    procs[1].pml4 = cpml4;
                    CSRSS_SPAWNED.store(1, Ordering::Relaxed);
                    procs[1].img_end = PE_LOAD_BASE + image_extent(cpe);
                    procs[1].scratch_base = CSRSS_SCRATCH_BASE;
                    map_demand_scratch_pts(CSRSS_SCRATCH_BASE); // own 64 MiB scratch window PTs
                    // Bind csrss's pre-created main ETHREAD to its real image entry — pm at spawn.
                    nt_handler
                        .bind_main_thread_entry(1, PE_LOAD_BASE + cpe.entry_point_rva() as u64);
                    // Record csrss's process handle in smss's (the creator's) EPROCESS table as a
                    // real typed Process object; the returned dense value IS the handle smss gets
                    // (path 1b — process-local value). Fallback to a global value if pids are
                    // unknown (shouldn't happen for the 3 hosted).
                    csrss_process_handle = match (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(1)) {
                        (Some(smss_pid), Some(csrss_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                smss_pid,
                                nt_process::HandleObject::Process(csrss_pid),
                                nt_process::map_process_access(
                                    nt_handler.process_spawn_desired_access,
                                ),
                            );
                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                            h.map(|v| v as u64).unwrap_or_else(|_| {
                                let g = nt_handler.next_handle;
                                nt_handler.next_handle += 1;
                                g
                            })
                        }
                        _ => {
                            let g = nt_handler.next_handle;
                            nt_handler.next_handle += 1;
                            g
                        }
                    };
                    smss_stack_write(get_recv_mr(9), csrss_process_handle); // *ProcessHandle (R10)
                    print_str(b"[ntos-exec] NtCreateProcess: spawned csrss (badge 2) -> handle 0x");
                    print_hex((csrss_process_handle >> 32) as u32);
                    print_hex(csrss_process_handle as u32);
                    print_str(b"; its faults now multiplexed into this loop\n");
                }
                // The 3rd hosted process: smss's SmpExecuteInitialCommand → RtlCreateUserProcess
                // created winlogon's SEC_IMAGE section; NtCreateProcess validated it. Spawn winlogon
                // (badge WINLOGON_BADGE) exactly like csrss — its own VSpace + image + ntdll + fault
                // EP, per-process env-scratch/mirrors/alloc-bump (all distinct from smss/csrss). Its
                // ntdll loader then runs, multiplexed into this loop by badge. Prio 102 (> csrss 101 >
                // smss 100) so it is actually scheduled; it blocks on every demand-fault (serviced
                // here), handing the others their turns.
                if nt_handler.winlogon_spawn_request {
                    let wf_c = mint_badged(fault_ep, WINLOGON_BADGE);
                    let wpe = winlogon_pe.as_ref().unwrap();
                    const WINLOGON_IMAGE_PATH: &[u8] = b"\\SystemRoot\\System32\\winlogon.exe";
                    const WINLOGON_CMD_LINE: &[u8] = b"winlogon.exe";
                    let wpml4 = spawn_sec_image(
                        2, wpe, wf_c, NTDLL_BASE, true, 102, 0x0000_0100_107C_0000,
                        WINLOGON_STACK_MIRROR_VA, WINLOGON_HEAP_MIRROR_VA, WINLOGON_IMAGE_MIRROR_VA,
                        WINLOGON_IMAGE_PATH, WINLOGON_CMD_LINE,
                        0, // pi>=1: real ntdll LdrpInitialize
                    );
                    procs[2].pml4 = wpml4;
                    procs[2].img_end = PE_LOAD_BASE + image_extent(wpe);
                    procs[2].scratch_base = WINLOGON_SCRATCH_BASE;
                    map_demand_scratch_pts(WINLOGON_SCRATCH_BASE); // own 64 MiB scratch window PTs
                    // Bind winlogon's pre-created main ETHREAD to its real image entry — pm at spawn.
                    nt_handler
                        .bind_main_thread_entry(2, PE_LOAD_BASE + wpe.entry_point_rva() as u64);
                    // Record winlogon's process handle in smss's EPROCESS table as a typed Process
                    // object; the returned dense value IS smss's handle (path 1b).
                    winlogon_process_handle = match (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(2)) {
                        (Some(smss_pid), Some(winlogon_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                smss_pid,
                                nt_process::HandleObject::Process(winlogon_pid),
                                nt_process::map_process_access(
                                    nt_handler.process_spawn_desired_access,
                                ),
                            );
                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                            h.map(|v| v as u64).unwrap_or_else(|_| {
                                let g = nt_handler.next_handle;
                                nt_handler.next_handle += 1;
                                g
                            })
                        }
                        _ => {
                            let g = nt_handler.next_handle;
                            nt_handler.next_handle += 1;
                            g
                        }
                    };
                    smss_stack_write(get_recv_mr(9), winlogon_process_handle); // *ProcessHandle (R10)
                    print_str(b"[ntos-exec] NtCreateProcess: spawned winlogon (badge 4) -> handle 0x");
                    print_hex((winlogon_process_handle >> 32) as u32);
                    print_hex(winlogon_process_handle as u32);
                    print_str(b"; its ntdll loader now multiplexed into this loop\n");
                    WINLOGON_SPAWNED.store(1, Ordering::Relaxed);
                }
                // winlogon's Win32 NtCreateProcessEx(50) StartServicesManager — spawn services.exe (the
                // 4th hosted process). SSN 50 is table-routed to exec_handler's NtCreateProcess handler,
                // which validated the services.exe SEC_IMAGE section + set services_spawn_request; the
                // actual spawn lives here (it needs fault_ep + procs[]/mirrors — loop-resident). Mirrors
                // the winlogon_spawn_request block above.
                if nt_handler.services_spawn_request
                    && SERVICES_SPAWNED.swap(1, Ordering::Relaxed) == 0
                    && services_pe.is_some()
                {
                    let sf_c = mint_badged(fault_ep, SERVICES_BADGE);
                    let spe = services_pe.as_ref().unwrap();
                    const SERVICES_IMAGE_PATH: &[u8] = b"\\SystemRoot\\System32\\services.exe";
                    const SERVICES_CMD_LINE: &[u8] = b"services.exe";
                    let spml4 = spawn_sec_image(
                        3, spe, sf_c, NTDLL_BASE, true, 103, SERVICES_ENV_SCRATCH_VA,
                        SERVICES_STACK_MIRROR_VA, SERVICES_HEAP_MIRROR_VA, SERVICES_IMAGE_MIRROR_VA,
                        SERVICES_IMAGE_PATH, SERVICES_CMD_LINE,
                        0, // pi>=1: real ntdll LdrpInitialize
                    );
                    procs[3].pml4 = spml4;
                    procs[3].img_end = PE_LOAD_BASE + image_extent(spe);
                    procs[3].scratch_base = SERVICES_SCRATCH_BASE;
                    map_demand_scratch_pts(SERVICES_SCRATCH_BASE); // own 64 MiB scratch window PTs
                    nt_handler.bind_main_thread_entry(3, PE_LOAD_BASE + spe.entry_point_rva() as u64);
                    services_process_handle = match (nt_handler.pm_pid_for_pi(2), nt_handler.pm_pid_for_pi(3)) {
                        (Some(wl_pid), Some(sv_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                wl_pid,
                                nt_process::HandleObject::Process(sv_pid),
                                nt_process::map_process_access(
                                    nt_handler.process_spawn_desired_access,
                                ),
                            );
                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                            h.map(|v| v as u64).unwrap_or_else(|_| {
                                let g = nt_handler.next_handle;
                                nt_handler.next_handle += 1;
                                g
                            })
                        }
                        _ => {
                            let g = nt_handler.next_handle;
                            nt_handler.next_handle += 1;
                            g
                        }
                    };
                    smss_stack_write(get_recv_mr(9), services_process_handle); // *ProcessHandle (R10)
                    print_str(b"[ntos-exec] NtCreateProcessEx: spawned services.exe (badge 6) -> handle 0x");
                    print_hex((services_process_handle >> 32) as u32);
                    print_hex(services_process_handle as u32);
                    print_str(b"; its ntdll loader now multiplexed into this loop\n");
                } else if nt_handler.services_spawn_request && services_process_handle != 0 {
                    // Idempotent re-create: return the same handle.
                    smss_stack_write(get_recv_mr(9), services_process_handle);
                }
                // winlogon's StartLsass NtCreateProcessEx(50) — spawn lsass.exe (the 5th hosted process).
                if nt_handler.lsass_spawn_request
                    && LSASS_SPAWNED.swap(1, Ordering::Relaxed) == 0
                    && lsass_pe.is_some()
                {
                    let lf_c = mint_badged(fault_ep, LSASS_BADGE);
                    let lpe = lsass_pe.as_ref().unwrap();
                    const LSASS_IMAGE_PATH: &[u8] = b"\\SystemRoot\\System32\\lsass.exe";
                    const LSASS_CMD_LINE: &[u8] = b"lsass.exe";
                    let lpml4 = spawn_sec_image(
                        4, lpe, lf_c, NTDLL_BASE, true, 104, LSASS_ENV_SCRATCH_VA,
                        LSASS_STACK_MIRROR_VA, LSASS_HEAP_MIRROR_VA, LSASS_IMAGE_MIRROR_VA,
                        LSASS_IMAGE_PATH, LSASS_CMD_LINE,
                        0, // pi>=1: real ntdll LdrpInitialize
                    );
                    procs[4].pml4 = lpml4;
                    procs[4].img_end = PE_LOAD_BASE + image_extent(lpe);
                    procs[4].scratch_base = LSASS_SCRATCH_BASE;
                    map_demand_scratch_pts(LSASS_SCRATCH_BASE); // own 64 MiB scratch window PTs
                    nt_handler.bind_main_thread_entry(4, PE_LOAD_BASE + lpe.entry_point_rva() as u64);
                    lsass_process_handle = match (nt_handler.pm_pid_for_pi(2), nt_handler.pm_pid_for_pi(4)) {
                        (Some(wl_pid), Some(ls_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                wl_pid,
                                nt_process::HandleObject::Process(ls_pid),
                                nt_process::map_process_access(
                                    nt_handler.process_spawn_desired_access,
                                ),
                            );
                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                            h.map(|v| v as u64).unwrap_or_else(|_| {
                                let g = nt_handler.next_handle; nt_handler.next_handle += 1; g
                            })
                        }
                        _ => { let g = nt_handler.next_handle; nt_handler.next_handle += 1; g }
                    };
                    smss_stack_write(get_recv_mr(9), lsass_process_handle); // *ProcessHandle (R10)
                    print_str(b"[ntos-exec] NtCreateProcessEx: spawned lsass.exe (badge 8) -> handle 0x");
                    print_hex((lsass_process_handle >> 32) as u32);
                    print_hex(lsass_process_handle as u32);
                    print_str(b"; its ntdll loader now multiplexed into this loop\n");
                } else if nt_handler.lsass_spawn_request && lsass_process_handle != 0 {
                    smss_stack_write(get_recv_mr(9), lsass_process_handle);
                }
                // Path B: smss's first NtCreateThread (an SmpApiLoop worker) — spawn the REAL SM-loop
                // thread in smss's VSpace. Read the CONTEXT off smss's stack: the NtCreateThread ABI
                // has Context* at [sp+0x30] (arg6), and RtlInitializeContext(amd64) set CONTEXT.Rip@0xF8
                // = StartAddress (SmpApiLoop) and CONTEXT.Rcx@0x80 = Parameter (the \SmApiPort handle).
                // (pi == 0 here so ACTIVE_STACK_MIRROR = smss's mirror; pml4 = smss's PML4.)
                if nt_handler.sm_spawn_request && SM_LOOP_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let entry_rip = smss_stack_read(ctx_va + 0xF8);
                    let port_handle = smss_stack_read(ctx_va + 0x80);
                    print_str(b"[sm-loop] spawning REAL SmpApiLoop thread: ctx=0x");
                    print_hex((ctx_va >> 32) as u32);
                    print_hex(ctx_va as u32);
                    print_str(b" entry=0x");
                    print_hex((entry_rip >> 32) as u32);
                    print_hex(entry_rip as u32);
                    print_str(b" port=0x");
                    print_hex((port_handle >> 32) as u32);
                    print_hex(port_handle as u32);
                    print_str(b"\n");
                    let tcb = spawn_sm_loop_thread(pml4, entry_rip, port_handle);
                    SM_LOOP_TCB.store(tcb, Ordering::Relaxed);
                    print_str(b"[sm-loop] spawned tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (parks on its first fault to sm_fault_ep)\n");
                }
                // Authentic CSR accept: csrss's first NtCreateThread (its CsrApiRequestThread) — spawn
                // the REAL CSR API thread in csrss's VSpace (pi == 1 here → pml4 = csrss's PML4,
                // ACTIVE_STACK_MIRROR = csrss's mirror). Same CONTEXT ABI as SM: Context* at [sp+0x30],
                // CONTEXT.Rip@0xF8 = CsrApiRequestThread, CONTEXT.Rcx@0x80 = Parameter (hRequestEvent).
                if nt_handler.csr_spawn_request == 1 && CSR_LOOP_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let entry_rip = smss_stack_read(ctx_va + 0xF8);
                    let param = smss_stack_read(ctx_va + 0x80);
                    print_str(b"[csr-loop] spawning REAL CsrApiRequestThread: entry=0x");
                    print_hex((entry_rip >> 32) as u32);
                    print_hex(entry_rip as u32);
                    print_str(b" param=0x");
                    print_hex(param as u32);
                    print_str(b"\n");
                    let pid = nt_handler.pm_pid_for_pi(1).unwrap_or(0) as u64;
                    let tid = CSR_API_TID.load(Ordering::Relaxed);
                    let tcb = spawn_csr_loop_thread(pml4, entry_rip, param, pid, tid);
                    CSR_LOOP_TCB.store(tcb, Ordering::Relaxed);
                    print_str(b"[csr-loop] spawned tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (parks on its first fault to csr_fault_ep)\n");
                }
                if nt_handler.csr_spawn_request == 2
                    && CSR_SB_LOOP_TCB.swap(1, Ordering::Relaxed) == 0
                {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let entry_rip = smss_stack_read(ctx_va + 0xF8);
                    let param = smss_stack_read(ctx_va + 0x80);
                    let pid = nt_handler.pm_pid_for_pi(1).unwrap_or(0) as u64;
                    let tid = CSR_SB_TID.load(Ordering::Relaxed);
                    print_str(b"[csr-sb] spawning REAL CsrSbApiRequestThread: entry=0x");
                    print_hex((entry_rip >> 32) as u32);
                    print_hex(entry_rip as u32);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b"\n");
                    let tcb = spawn_csr_sb_loop_thread(pml4, entry_rip, param, pid, tid);
                    CSR_SB_LOOP_TCB.store(tcb, Ordering::Relaxed);
                }
                // ★ GENERAL NtCreateThread: winlogon's first NtCreateThread (its RPC listener) — spawn
                // the REAL thread in winlogon's VSpace (pi == 2 here → pml4 = winlogon's PML4,
                // ACTIVE_STACK_MIRROR = winlogon's mirror). Same CONTEXT ABI as SM/CSR: Context* at
                // [sp+0x30], CONTEXT.Rip@0xF8 = StartRoutine, CONTEXT.Rcx@0x80 = Parameter. Its real
                // ETHREAD (PM_LISTENER_TID) was already popped + bound in the handler; here we build the
                // seL4 TCB + real TEB and record the TEB base on the ETHREAD (alloc-free). The TCB is
                // spawned SUSPENDED (a parked listener) — its TEB is mapped + queryable by the main
                // thread's NtQueryInformationThread(162), which is what unblocks StartRpcServer.
                if nt_handler.wl_spawn_request != 0 {
                    let slot = nt_handler.wl_spawn_request as usize - 1;
                    let tcb_cell = match slot {
                        0 => &WL_LISTENER_TCB,
                        1 => &WL_WORKER2_TCB,
                        2 => &WL_WORKER3_TCB,
                        _ => unreachable!(),
                    };
                    tcb_cell.store(1, Ordering::Relaxed);
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let start = nt_thread_start::Amd64ThreadContext::read(
                        |address| smss_stack_read(address),
                        ctx_va,
                    );
                    let initial_teb_va = smss_stack_read(sp + 0x38);
                    let initial_teb = nt_thread_start::InitialTeb64::read(
                        |address| smss_stack_read(address),
                        initial_teb_va,
                    );
                    let tid = match slot {
                        0 => PM_LISTENER_TID.load(Ordering::Relaxed),
                        1 => WL_WORKER2_TID.load(Ordering::Relaxed),
                        2 => WL_WORKER3_TID.load(Ordering::Relaxed),
                        _ => 0,
                    };
                    let teb = match slot {
                        0 => WL_LISTENER_TEB_VA,
                        1 => WL_WORKER2_TEB_VA,
                        2 => WL_WORKER3_TEB_VA,
                        _ => 0,
                    };
                    let cid_proc = nt_handler.pm_pid_for_pi(2).unwrap_or(0) as u64;
                    print_str(b"[wl-thread] spawning REAL worker slot=");
                    print_u64(slot as u64);
                    print_str(b" (multiplexed): entry=0x");
                    print_hex((start.rip >> 32) as u32);
                    print_hex(start.rip as u32);
                    print_str(b" arg0=0x");
                    print_hex((start.rcx >> 32) as u32);
                    print_hex(start.rcx as u32);
                    print_str(b" arg1=0x");
                    print_hex((start.rdx >> 32) as u32);
                    print_hex(start.rdx as u32);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b"\n");
                    let suspended = PM_POOL_SUSPENDED[2].load(Ordering::Relaxed) & (1 << slot) != 0;
                    let tcb = spawn_wl_listener_thread(
                        slot,
                        procs[2].pml4,
                        start,
                        initial_teb,
                        cid_proc,
                        tid,
                        fault_ep,
                        false,
                    );
                    let teb_alias = match slot {
                        0 => WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000,
                        1 => WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000,
                        2 => WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000,
                        _ => 0,
                    };
                    if seed_winlogon_thread_client_info(teb_alias, procs[2].pml4).is_none() {
                        print_str(b"[wl-thread] win32 client state not published before worker spawn\n");
                    }
                    if slot == 0 {
                        let mapped_low = initial_teb
                            .stack_limit
                            .checked_sub(nt_thread_start::USER_PAGE_SIZE)
                            .filter(|&low| {
                                initial_teb.allocated_stack_base & 0xfff == 0
                                    && initial_teb.stack_base & 0xfff == 0
                                    && initial_teb.allocated_stack_base <= low
                                    && low < initial_teb.stack_base
                                    && csrss_frame_get_exact(2, low).0 != 0
                            })
                            .unwrap_or(0);
                        if mapped_low != 0 {
                            WL_LISTENER_STACK_ALLOCATION_BASE.store(
                                initial_teb.allocated_stack_base,
                                Ordering::Release,
                            );
                            WL_LISTENER_STACK_BASE_REAL
                                .store(initial_teb.stack_base, Ordering::Release);
                            WL_LISTENER_STACK_MAPPED_LOW.store(mapped_low, Ordering::Release);
                        } else {
                            WL_LISTENER_STACK_ALLOCATION_BASE.store(0, Ordering::Release);
                            WL_LISTENER_STACK_BASE_REAL.store(0, Ordering::Release);
                            WL_LISTENER_STACK_MAPPED_LOW.store(0, Ordering::Release);
                            print_str(b"[wl-thread] real stack reservation could not be armed\n");
                        }
                    }
                    tcb_cell.store(tcb, Ordering::Relaxed);
                    // Record the real TEB base on the ETHREAD (alloc-free) so 162 reports it.
                    nt_handler.pm.set_thread_teb(tid as nt_process::ThreadId, teb);
                    if !suspended {
                        let _ = tcb_resume(tcb);
                    }
                    print_str(b"[wl-thread] spawned tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" TEB=0x");
                    print_hex((teb >> 32) as u32);
                    print_hex(teb as u32);
                    print_str(if suspended {
                        b" (SUSPENDED; NtResumeThread owns first run; real ETHREAD + TEB)\n"
                    } else {
                        b" (RESUMED into multiplex; real ETHREAD + TEB)\n"
                    });
                    nt_handler.wl_spawn_request = 0;
                }
                // ★ N-threads multiplex: services' RPC listener thread — spawned RESUMED into the main
                // service loop (badge SVC_LISTENER_BADGE). Its faults/syscalls interleave with services'
                // main thread; the loop sub-selects it by badge → the listener's own stack mirror/TEB.
                if nt_handler.svc_listener_spawn && SVC_LISTENER_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let start = nt_thread_start::Amd64ThreadContext::read(
                        |address| smss_stack_read(address),
                        ctx_va,
                    );
                    let tid = SVC_LISTENER_TID.load(Ordering::Relaxed);
                    let cid_proc = nt_handler.pm_pid_for_pi(3).unwrap_or(0) as u64;
                    print_str(b"[svc-thread] spawning + RESUMING REAL RPC listener thread: entry=0x");
                    print_hex((start.rip >> 32) as u32);
                    print_hex(start.rip as u32);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b"\n");
                    let suspended = runtime_thread_slot(tid)
                        .is_some_and(|(pi, slot)| PM_POOL_SUSPENDED[pi].load(Ordering::Relaxed) & (1 << slot) != 0);
                    let tcb = spawn_svc_listener_thread(
                        procs[3].pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep,
                        !suspended,
                    );
                    SVC_LISTENER_TCB.store(tcb, Ordering::Relaxed);
                    nt_handler.pm.set_thread_teb(tid as nt_process::ThreadId, SVC_LISTENER_TEB_VA);
                    print_str(b"[svc-thread] spawned + resumed tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (runs into the main multiplex, badge 7)\n");
                }
                // ★ BATCH 35: services' SCM per-connection RPC WORKER thread — spawned RESUMED into the
                // main service loop (badge SCM_WORKER_BADGE). Its faults sub-select to (pi 3, scm-worker)
                // by badge → its OWN stack mirror/TEB. This is the thread that reads winlogon's bind PDU
                // and writes bind_ack; its pipe reads park (pipe_wait_park) + re-drive on winlogon's write.
                if nt_handler.scm_worker_spawn && SCM_WORKER_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let start = nt_thread_start::Amd64ThreadContext::read(
                        |address| smss_stack_read(address),
                        ctx_va,
                    );
                    let tid = SCM_WORKER_TID.load(Ordering::Relaxed);
                    let cid_proc = nt_handler.pm_pid_for_pi(3).unwrap_or(0) as u64;
                    // Spawn RESUMED into the multiplex, like the SVC/LSASS listeners. This block only
                    // runs when the recognizer sets `scm_worker_spawn` (gated by SCM_WORKER_ROUTE_ENABLED
                    // in exec_handler.rs — currently OFF pending the trampoline-entry fault; see the
                    // BATCH 35 frontier note). When enabled, the worker runs into the loop at badge 15
                    // (own stack mirror/TEB), reads winlogon's bind PDU, and writes bind_ack.
                    print_str(b"[scm-worker] spawning + RESUMING REAL per-connection RPC worker: entry=0x");
                    print_hex((start.rip >> 32) as u32);
                    print_hex(start.rip as u32);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b"\n");
                    let tcb = spawn_scm_worker_thread(
                        procs[3].pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep,
                        true,
                    );
                    SCM_WORKER_TCB.store(tcb, Ordering::Relaxed);
                    nt_handler.pm.set_thread_teb(tid as nt_process::ThreadId, SCM_WORKER_TEB_VA);
                    print_str(b"[scm-worker] spawned + resumed tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (runs into the main multiplex, badge 15)\n");
                }
                // ★ N-threads multiplex: lsass' (pi 4) LSA server thread — spawned RESUMED into the main
                // service loop (badge LSASS_LISTENER_BADGE). Same shape as the svc listener; its faults
                // sub-select to (pi 4, listener) by badge → the listener's own stack mirror/TEB.
                if nt_handler.lsass_listener_spawn && LSASS_LISTENER_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let start = nt_thread_start::Amd64ThreadContext::read(
                        |address| smss_stack_read(address),
                        ctx_va,
                    );
                    let tid = LSASS_LISTENER_TID.load(Ordering::Relaxed);
                    let cid_proc = nt_handler.pm_pid_for_pi(4).unwrap_or(0) as u64;
                    print_str(b"[lsass-thread] spawning + RESUMING REAL LSA server thread: entry=0x");
                    print_hex((start.rip >> 32) as u32);
                    print_hex(start.rip as u32);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b"\n");
                    let suspended = runtime_thread_slot(tid)
                        .is_some_and(|(pi, slot)| PM_POOL_SUSPENDED[pi].load(Ordering::Relaxed) & (1 << slot) != 0);
                    let tcb = spawn_lsass_listener_thread(
                        procs[4].pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep,
                        !suspended,
                    );
                    LSASS_LISTENER_TCB.store(tcb, Ordering::Relaxed);
                    nt_handler.pm.set_thread_teb(tid as nt_process::ThreadId, LSASS_LISTENER_TEB_VA);
                    print_str(b"[lsass-thread] spawned + resumed tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (runs into the main multiplex, badge 9)\n");
                }
                // ★ lsass' SECOND server thread (LsapRmServerThread) — same multiplex, badge 10.
                if nt_handler.lsass_listener2_spawn && LSASS_LISTENER2_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let start = nt_thread_start::Amd64ThreadContext::read(
                        |address| smss_stack_read(address),
                        ctx_va,
                    );
                    let tid = LSASS_LISTENER2_TID.load(Ordering::Relaxed);
                    let cid_proc = nt_handler.pm_pid_for_pi(4).unwrap_or(0) as u64;
                    print_str(b"[lsass-thread2] spawning + RESUMING 2nd LSA server thread: entry=0x");
                    print_hex((start.rip >> 32) as u32);
                    print_hex(start.rip as u32);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b"\n");
                    let suspended = runtime_thread_slot(tid)
                        .is_some_and(|(pi, slot)| PM_POOL_SUSPENDED[pi].load(Ordering::Relaxed) & (1 << slot) != 0);
                    let tcb = spawn_lsass_listener2_thread(
                        procs[4].pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep,
                        !suspended,
                    );
                    LSASS_LISTENER2_TCB.store(tcb, Ordering::Relaxed);
                    nt_handler.pm.set_thread_teb(tid as nt_process::ThreadId, LSASS_LISTENER2_TEB_VA);
                    print_str(b"[lsass-thread2] spawned + resumed tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (runs into the main multiplex, badge 10)\n");
                }
                if nt_handler.lsass_listener3_spawn
                    && LSASS_LISTENER3_TCB.swap(1, Ordering::Relaxed) == 0
                {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let start = nt_thread_start::Amd64ThreadContext::read(
                        |address| smss_stack_read(address),
                        ctx_va,
                    );
                    let tid = LSASS_LISTENER3_TID.load(Ordering::Relaxed);
                    let cid_proc = nt_handler.pm_pid_for_pi(4).unwrap_or(0) as u64;
                    print_str(b"[lsass-thread3] spawning + RESUMING 3rd LSA worker: entry=0x");
                    print_hex((start.rip >> 32) as u32);
                    print_hex(start.rip as u32);
                    print_str(b" tid=");
                    print_u64(tid);
                    print_str(b"\n");
                    let tcb = spawn_lsass_listener3_thread(
                        procs[4].pml4,
                        start.rip,
                        start.rcx,
                        start.rdx,
                        cid_proc,
                        tid,
                        fault_ep,
                        !runtime_thread_slot(tid).is_some_and(|(pi, slot)| {
                            PM_POOL_SUSPENDED[pi].load(Ordering::Relaxed) & (1 << slot) != 0
                        }),
                    );
                    LSASS_LISTENER3_TCB.store(tcb, Ordering::Relaxed);
                    nt_handler
                        .pm
                        .set_thread_teb(tid as nt_process::ThreadId, LSASS_LISTENER3_TEB_VA);
                    print_str(b"[lsass-thread3] spawned + resumed tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (runs into the main multiplex, badge 14)\n");
                }
                let tp_request = core::mem::replace(&mut nt_handler.tp_worker_spawn_request, 0);
                if tp_request != 0 {
                    let identity = tp_request as usize - 1;
                    let tp_pi = identity % TP_WORKER_PI_COUNT;
                    let tp_slot = identity / TP_WORKER_PI_COUNT;
                    if tp_slot < TP_WORKER_SLOT_COUNT {
                        spawn_requested_tp_worker(
                            &mut nt_handler,
                            tp_pi,
                            tp_slot,
                            procs[tp_pi].pml4,
                            sp,
                            fault_ep,
                        );
                    }
                }
                // Path B (authentic accept): csrss's NtConnectPort left the broker connection Pending
                // (Manual). Drive the REAL SmpApiLoop thread through the connection rendezvous (it runs
                // in smss's VSpace = procs[0].pml4, demand-filling from smss's image + ntdll), then write the
                // completed client comm-port handle to csrss's *PortHandle + reply csrss via REPLY_MAIN.
                if nt_handler.lpc_rendezvous_conn != 0 {
                    let conn_id = nt_handler.lpc_rendezvous_conn;
                    let out_ptr = nt_handler.lpc_rendezvous_out;
                    print_str(b"[sm-rdv] caller pi=");
                    print_u64(pi as u64);
                    print_str(b" NtConnectPort pending (conn=");
                    print_u64(conn_id);
                    print_str(b") -> driving the real SmpApiLoop accept\n");
                    let client_handle = sm_rendezvous(
                        conn_id,
                        pi,
                        procs[0].pml4,
                        smss_pe,
                        procs[0].img_end,
                        nt_base,
                        nt_end,
                        ntdll.map(|(_, p)| p),
                        procs[1].pml4,
                        csrss_pe.as_ref().unwrap(),
                        procs[1].img_end,
                        &reg,
                        &dll_pes,
                        &mut nt_handler,
                    );
                    if client_handle != 0 {
                        if nt_handler.xas_write_u64(out_ptr, client_handle) {
                            let name16 = nt_handler.read_lpc_name(m3); // RDX = PortName
                            nt_handler.cache_lpc_connection(conn_id, client_handle, &name16);
                            result = 0; // STATUS_SUCCESS
                            routed_lpc = true;
                            print_str(b"[sm-rdv] AUTHENTIC accept complete: client handle=0x");
                            print_hex((client_handle >> 32) as u32);
                            print_hex(client_handle as u32);
                            print_str(b" -> caller NtConnectPort SUCCESS\n");
                        } else {
                            print_str(b"[sm-rdv] WALL: failed client handle copyout\n");
                            handled = false;
                            result = 0xC0000005;
                        }
                    } else {
                        // The rendezvous walled — stop cleanly with a diagnostic (don't hand csrss junk).
                        print_str(b"[sm-rdv] WALL: rendezvous produced no client handle\n");
                        handled = false;
                        result = 0xC0000001;
                    }
                }
                if nt_handler.sm_request_port != 0 {
                    let completed = sm_api_request_rendezvous(
                        nt_handler.sm_request_port,
                        nt_handler.sm_request_message,
                        nt_handler.sm_reply_message,
                        procs[0].pml4,
                        smss_pe,
                        procs[0].img_end,
                        nt_base,
                        nt_end,
                        ntdll.map(|(_, p)| p),
                        procs[1].pml4,
                        csrss_pe.as_ref().unwrap(),
                        procs[1].img_end,
                        &reg,
                        &dll_pes,
                        &mut nt_handler,
                    );
                    if completed {
                        result = 0;
                        routed_lpc = true;
                    } else {
                        print_str(b"[sm-api] WALL: synchronous SM request did not complete\n");
                        result = 0xC0000001;
                        handled = false;
                    }
                }
                // Authentic CSR accept: winlogon's NtSecureConnectPort left the broker connection
                // Pending (Manual). Drive the REAL CsrApiRequestThread through the connection accept (it
                // runs in csrss's VSpace = procs[1].pml4, demand-filling from csrss's image + the mapped
                // DLLs + ntdll), then write the completed client comm-port handle to winlogon's
                // *PortHandle + reply winlogon via REPLY_MAIN. (pi == 2 here = winlogon, so pml4 =
                // winlogon's; csr_rendezvous takes csrss's PML4 explicitly.)
                if nt_handler.csr_rendezvous_conn != 0 {
                    let conn_id = nt_handler.csr_rendezvous_conn;
                    let out_ptr = nt_handler.csr_rendezvous_out;
                    // Only drive the real accept if csrss actually spawned its CsrApiRequestThread
                    // (CSR_LOOP_TCB is a real cap > 1). Otherwise recv_full_r12(CSR_FAULT_EP) would block
                    // forever with no faulter — fall back to a modeled accept so winlogon still connects.
                    let have_thread = CSR_LOOP_TCB.load(Ordering::Relaxed) > 1
                        && csrss_pe.is_some();
                    let client_handle = if have_thread {
                        print_str(b"[csr-rdv] winlogon NtSecureConnectPort pending (conn=");
                        print_u64(conn_id);
                        print_str(b") -> driving the real CsrApiRequestThread accept\n");
                        csr_rendezvous(
                            conn_id,
                            procs[1].pml4,
                            csrss_pe.as_ref().unwrap(),
                            procs[1].img_end,
                            nt_base,
                            nt_end,
                            ntdll.map(|(_, p)| p),
                            &reg,
                            &dll_pes,
                            &mut nt_handler,
                        )
                    } else {
                        print_str(b"[csr-rdv] no real CSR thread -> modeled accept\n");
                        0
                    };
                    let ch = if client_handle != 0 {
                        // AUTHENTIC: the real CSR thread accepted + completed the connection.
                        nt_handler.cache_lpc_connection(conn_id, client_handle, b"\\Windows\\ApiPort".iter().map(|&b| b as u16).collect::<alloc::vec::Vec<u16>>().as_slice());
                        print_str(b"[csr-rdv] AUTHENTIC accept complete: client handle=0x");
                        print_hex((client_handle >> 32) as u32);
                        print_hex(client_handle as u32);
                        print_str(b" -> winlogon NtSecureConnectPort SUCCESS\n");
                        client_handle
                    } else {
                        // The rendezvous walled — fall back to a modeled accept so winlogon still
                        // connects (behavior-preserving; the boot never hangs on the CSR path).
                        print_str(b"[csr-rdv] WALL: rendezvous produced no handle -> modeled fallback\n");
                        let h = lpc_client()
                            .and_then(|c| {
                                let _ = c.accept_connect(conn_id, true, 0);
                                c.complete_connect(conn_id).ok().map(|(ch, _)| ch)
                            })
                            .unwrap_or_else(|| nt_handler.mint_handle());
                        nt_handler.cache_lpc_connection(conn_id, h, b"\\Windows\\ApiPort".iter().map(|&b| b as u16).collect::<alloc::vec::Vec<u16>>().as_slice());
                        h
                    };
                    if out_ptr != 0 {
                        // winlogon's *PortHandle (&CsrApiPort, an ntdll .data global) — demand-fill window.
                        csrss_out_write(out_ptr, ch, &mut *filled_pages, &mut faults,
                            scratch_base, &reg, &dll_pes, pml4);
                    }
                    result = 0; // STATUS_SUCCESS (winlogon's connect always succeeds)
                    routed_csr = true;
                }
            } else if m0 == 223 {
                // NtSetDefaultHardErrorPort(PortHandle=R10). csrsrv's CsrServerInitialization registers
                // its API port as the hard-error port right after SmConnectToSm succeeds
                // (init.c:1119). No kernel state to model in the host — accept it so CsrServerInit
                // returns and csrss.exe's main continues. (One-time; NtRaiseHardError already routes to
                // our diagnostic path.)
                result = 0; // STATUS_SUCCESS
            } else if m0 == 45 {
                // NtCreateMutant(MutantHandle=R10, DesiredAccess=RDX, ObjectAttributes=R8,
                // InitialOwner=R9). rpcrt4's ncacn_np server init (StartRpcServer) creates sync
                // mutants. Mint a fake handle so the caller can later wait/release it; no real mutant
                // is modeled (the wait/release paths below are no-ops). Additive.
                let out = get_recv_mr(9); // R10 = *MutantHandle
                if out != 0 {
                    let value = FAKE_SYNC_HANDLE.fetch_add(4, Ordering::Relaxed);
                    let _ = client_write_u64_mapped(
                        pi as u64,
                        out,
                        value,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                }
                result = 0;
            } else if m0 == 196 {
                // NtReleaseMutant(196) — legacy modeled object.
                result = 0;
            } else if m0 == 280 && badge != 0 {
                // ★ NtWaitForMultipleObjects(ObjectCount=R10, HandleArray=RDX, WaitType=R8,
                // Alertable=R9, *TimeOut=[sp+0x28]) — REAL array-wait with reply-cap parking (Part 1 of
                // the winlogon rpcrt4 handshake). WaitType 1 = WaitAny, 0 = WaitAll. This is the
                // worker-thread half of the rpcrt4 two-thread handshake: the server WORKER thread
                // (multiplexed via WINLOGON_WORKER_BADGE / SVC/LSASS listeners) runs
                // rpcrt4_protseq_np_wait_for_new_connection = WaitForMultipleObjects([mgr_event,
                // listen_events…]). We resolve the handle array to dispatcher objects:
                //   • WaitAny + any already signalled → immediate WAIT_0+index.
                //   • WaitAll + all signalled → immediate WAIT_0.
                //   • otherwise, if the set contains at least one real waitable object —
                //     the main thread's signal_state_changed SetEvents mgr_event) → PARK on the set
                //     (steal the reply cap, recv next, wake on NtSetEvent). ★ NO-DEADLOCK: only park
                //     when a real event is present; a set of only fake handles → immediate WAIT_0.
                let count = get_recv_mr(9) as usize; // R10 = ObjectCount
                let harr = m3; // RDX = HandleArray
                let wait_type = get_recv_mr(7); // R8 = WaitType (1=Any, 0=All)
                let wait_all = wait_type == 0;
                let mut nev = 0usize;
                let mut any_signalled_idx: i64 = -1; // handle-array index (k) of the first signalled
                let mut any_signalled_obj: usize = 0; // obj_ns idx of that event (for auto-reset)
                let mut any_signalled_real = false;
                let mut all_signalled = true;
                let mut has_real_event = false;
                let mut wait_identities = [u64::MAX; WAITER_MAX_EVENTS];
                let mut wait_error: Option<u32> = if harr == 0
                    || count == 0
                    || count > WAITER_MAX_EVENTS
                    || wait_type > 1
                {
                    Some(0xC000_000D) // STATUS_INVALID_PARAMETER
                } else {
                    None
                };
                let trace = EVENT_TRACE_N.fetch_add(1, Ordering::Relaxed);
                if wait_error.is_none() {
                    for k in 0..count {
                        let h = client_read_u64_mapped(
                            pi as u64,
                            harr + (k as u64) * 8,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                        .unwrap_or(0);
                        match nt_handler.waitable_index_for_handle(h, SYNCHRONIZE_ACCESS) {
                            Ok(idx) => {
                                    if trace < 32 {
                                        print_str(b"[event] wait-item k="); print_u64(k as u64);
                                        print_str(b" h=0x"); print_hex_u64(h);
                                        print_str(b" -> obj="); print_u64(idx as u64); print_str(b"\n");
                                    }
                                    has_real_event = true;
                                    park_wait_set[nev] = idx;
                                    park_wait_indices[nev] = k as u8;
                                    wait_identities[k] = idx as u64;
                                    nev += 1;
                                    if nt_handler.dispatcher_ready(idx) {
                                        if any_signalled_idx < 0 {
                                            any_signalled_idx = k as i64;
                                            any_signalled_obj = idx;
                                            any_signalled_real = true;
                                        }
                                    } else {
                                        all_signalled = false;
                                    }
                                    continue;
                            }
                            Err(_) if nt_handler.is_legacy_opaque_handle(h) => {
                                if trace < 32 {
                                    print_str(b"[event] wait-item k="); print_u64(k as u64);
                                    print_str(b" h=0x"); print_hex_u64(h);
                                    print_str(b" -> legacy\n");
                                }
                                // Compatibility sync handles are modeled as permanently signaled.
                                // Preserve their original array position for WaitAny.
                                if any_signalled_idx < 0 {
                                    any_signalled_idx = k as i64;
                                }
                                wait_identities[k] = 0x8000_0000_0000_0000 | h;
                            }
                            Err(status) => {
                                if trace < 32 {
                                    print_str(b"[event] wait-item k="); print_u64(k as u64);
                                    print_str(b" h=0x"); print_hex_u64(h);
                                    print_str(b" -> status=0x"); print_hex(status); print_str(b"\n");
                                }
                                wait_error = Some(status);
                                break;
                            }
                        }
                    }
                    if wait_all && wait_error.is_none() {
                        'duplicates: for left in 0..count {
                            for right in left + 1..count {
                                if wait_identities[left] == wait_identities[right] {
                                    wait_error = Some(0xC000_0030); // STATUS_INVALID_PARAMETER_MIX
                                    break 'duplicates;
                                }
                            }
                        }
                    }
                }
                // Consume dispatcher state only after the complete immediate condition is satisfied.
                let timeout_ptr = client_read_u64_mapped(
                    pi as u64,
                    sp + 0x28,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                )
                .unwrap_or(0);
                let wait_due = if timeout_ptr == 0 {
                    None
                } else {
                    Some(nt_delay_execution::due_time(
                        client_read_u64_mapped(
                            pi as u64,
                            timeout_ptr,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                        .unwrap_or(0) as i64,
                        monotonic_time_100ns(),
                        nt_system_time_100ns(),
                    ))
                };
                let zero_timeout = matches!(wait_due, Some(nt_delay_execution::Due::Immediate));
                let finite_deadline = match wait_due {
                    Some(nt_delay_execution::Due::Monotonic100ns(deadline)) => Some(deadline),
                    _ => None,
                };
                if trace < 32 {
                    print_str(b"[event] wait-multi pi=");
                    print_u64(pi as u64);
                    print_str(b" badge=");
                    print_u64(badge);
                    print_str(b" count=");
                    print_u64(count as u64);
                    print_str(if wait_all { b" all" } else { b" any" });
                    print_str(b" real=");
                    print_u64(nev as u64);
                    print_str(if zero_timeout { b" timeout=zero\n" } else if timeout_ptr == 0 { b" timeout=infinite\n" } else { b" timeout=finite\n" });
                }
                if let Some(status) = wait_error {
                    result = status as u64;
                } else if wait_all {
                    if has_real_event && all_signalled {
                        for k in 0..nev { nt_handler.dispatcher_consume(park_wait_set[k]); }
                        result = 0; // WAIT_0 (all satisfied)
                    } else if zero_timeout {
                        result = 0x102;
                    } else if has_real_event {
                        park_wait_set_n = nev;
                        park_wait_set_all = true;
                        park_wait_deadline = finite_deadline;
                        result = 0;
                    } else {
                        result = 0; // no real event → immediate WAIT_0 (no live signaler; documented)
                    }
                } else {
                    // WaitAny
                    if any_signalled_idx >= 0 {
                        if any_signalled_real {
                            nt_handler.dispatcher_consume(any_signalled_obj);
                        }
                        result = any_signalled_idx as u64; // WAIT_OBJECT_0 + index
                    } else if zero_timeout {
                        result = 0x102;
                    } else if has_real_event {
                        park_wait_set_n = nev;
                        park_wait_set_all = false;
                        park_wait_deadline = finite_deadline;
                        result = 0;
                    } else {
                        result = 0; // no real event to park on → immediate WAIT_0 (documented)
                    }
                }
            } else if m0 == 98 && badge == WINLOGON_BADGE {
                // NtIsProcessInJob(ProcessHandle=R10, JobHandle=RDX). kernel32's CreateProcessInternalW
                // prologue (spawning services.exe) queries whether winlogon is in a job (JobHandle=NULL
                // → "in ANY job"). Not modeled — winlogon is in no job. Return STATUS_SUCCESS (0):
                // kernel32 treats a non-zero return as "in a job" (→ CREATE_SEPARATE_WOW_VDM, harmless
                // for a native x64 app but avoided); 0 keeps it on the normal create path.
                result = 0;
            } else if m0 == 19 {
                // NtApphelpCacheControl(Command=R10, Data=RDX). kernel32's CreateProcessInternalW →
                // BasepCheckBadapp → BaseCheckAppcompatCache → BasepShimCacheSearch does
                // NtApphelpCacheControl(ApphelpCacheServiceLookup). Returning SUCCESS means "the image
                // is in the shim cache, known-good" → BaseCheckAppcompatCache returns TRUE → the app is
                // allowed WITHOUT loading apphelp.dll or running the shim engine. No app-compat state is
                // modeled; SUCCESS is the "no shim needed" answer. (BasepShimCacheCheckBypass is a
                // hardcoded FALSE in ReactOS, so this single SUCCESS short-circuits the whole path.)
                result = 0;
            } else if m0 == 195 {
                // NtRegisterThreadTerminatePort(PortHandle=R10). kernel32's CsrNewThread() — the LAST
                // step of BaseDllInitialize after the CSR connect — registers the thread's LPC
                // terminate port (so CSR is told when the thread dies). No terminate-port model in the
                // host → accept it (STATUS_SUCCESS) so winlogon's kernel32 DllMain completes + the
                // loader runs the remaining DllMains toward winlogon's entry.
                result = 0;
            } else if m0 == 280 && badge == 0 {
                // NtWaitForMultipleObjects — smss's main thread waits (WaitAny) on {csrss, winlogon}
                // to die (smss.c:518). In our boot NEITHER dies, so smss's correct terminal state is to
                // block here FOREVER. PARK it (never reply, recv the next event) so the higher-priority
                // winlogon keeps running forward. Returning STATUS_WAIT_0 instead would make smss think
                // csrss/winlogon terminated -> its hard-error teardown path (wrong). This is the
                // designed end of smss's lifetime; the loop now terminates on winlogon's next wall.
                park_caller = true;
                result = 0;
            } else if m0 >= win32k_subsystem::WIN32K_SERVICE_BASE
                && (badge == CSRSS_BADGE
                    || badge == WINLOGON_BADGE
                    || is_wl_worker
                    || badge == SERVICES_BADGE
                    || badge == LSASS_BADGE
                    || (is_tp_worker && pi != 0))
            {
                routed_win32k = true;
                let dialog_modal_expected_ssn = if pi == 2 {
                    winlogon_dialog_modal_expected_ssn()
                } else {
                    0
                };
                let modal_message_buffer = get_recv_mr(9);
                let dialog_modal_dispatch = dialog_modal_expected_ssn != 0
                    && dialog_modal_expected_ssn == m0
                    && winlogon_dialog_modal_thread_matches(
                        badge,
                        current_tid,
                        modal_message_buffer,
                    );
                if dialog_modal_dispatch {
                    print_str(b"[dialog-pump] routing real modal SSN=");
                    print_hex(m0 as u32);
                    print_str(b"\n");
                    if WINLOGON_KEY_OPENED.load(Ordering::Relaxed)
                        > WINLOGON_KEY_OPENED_AT_INJECT.load(Ordering::Relaxed)
                    {
                        WINLOGON_LOGGED_OUT_SAS_RAN.store(1, Ordering::Relaxed);
                    }
                }
                let sas_hwnd = if pi == 2 {
                    core::ptr::read_volatile(
                        (win32k_subsystem::WIN32K_SHARED_VADDR
                            + win32k_subsystem::SH_SAS_HWND) as *const u64,
                    )
                } else {
                    0
                };
                if pi == 2
                    && m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                    && WINLOGON_DIALOG_MODAL_READY.load(Ordering::Relaxed) != 0
                    && !winlogon_dialog_modal_target_alive()
                    && winlogon_dialog_modal_thread_matches(
                        badge,
                        current_tid,
                        modal_message_buffer,
                    )
                {
                    WINLOGON_DIALOG_MODAL_ERRORS.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[dialog-pump] correlated IDD_LOGON was destroyed; parking modal GetMessage\n");
                    handled = false;
                    wl_milestone_park = true;
                } else if pi == 2
                    && m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                    && WINLOGON_DIALOG_MODAL_DRAINED.load(Ordering::Relaxed) != 0
                    && winlogon_dialog_modal_thread_matches(
                        badge,
                        current_tid,
                        modal_message_buffer,
                    )
                {
                    print_str(b"[dialog-pump] real IDD_LOGON queue drained; parking its blocking GetMessage\n");
                    handled = false;
                    wl_milestone_park = true;
                } else if pi == 2
                    && m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                    && sas_hwnd != 0
                    && m3 == sas_hwnd
                    && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) != 0
                {
                    let n = WINLOGON_MSGLOOP_MILESTONE.fetch_add(1, Ordering::Relaxed);
                    if n == 0 {
                        print_str(b"[wl-main] winlogon entered its SAS message loop; routing real GetMessage for posted WLX_WM_SAS\n");
                    } else {
                        print_str(b"[wl-main] SAS queue empty at main-loop GetMessage -> parking\n");
                        handled = false;
                        wl_milestone_park = true;
                    }
                }
                // Tell win32k_dispatch WHICH client this call belongs to (csrss pi 1 / winlogon pi 2 /
                // services pi 3 / lsass pi 4) so it attaches win32k's client window to this client's frames
                // (per-client cross-AS client memory — services' OBJECT_ATTRIBUTES / USERCONNECT
                // resolve to SERVICES' frames, not the stale csrss/winlogon frame at the same VA).
                // The w32_client_attach / csrss_frame_get / map_win32k_heap_into_csrss machinery is
                // fully pi-keyed (bit `1<<pi`), so a 3rd GUI client needs no new state — same recipe
                // that made winlogon the 2nd client. The reply routing (routed_win32k ->
                // send_on_reply(REPLY_MAIN)) is caller-agnostic: REPLY_MAIN is bound to THIS caller at
                // its recv, so the routed reply resumes exactly services (no reply-spin).
                W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
                // ★ (B) SPIN WATCHDOG. A GUI client can live-lock a run of win32k calls that never
                // terminates — either all WALLing (csrss's user32 RegisterSystemClasses hammering
                // NtUserFindExistingCursorIcon 0x103d / NtUserRegisterClassExWOW 0x10b4 when win32k
                // asserts) OR each returning STATUS_SUCCESS yet never satisfying the loop condition (the
                // assert-skips leave win32k's class table inconsistent so the same cursor/class is
                // re-registered forever). It keeps issuing syscalls so it is neither crash- nor
                // wait-parked → without this it spins the shared loop to the TCG timeout and the boot
                // never reaches the gate. A TOTAL per-client win32k-dispatch budget catches BOTH cases:
                // a client's real win32k init is bounded (a few hundred calls), so past a generous
                // ceiling it is a live-lock → PARK the client (like a crash) so the loop quiesces + the
                // gate runs. General: applies to any client (winlogon's paint fires well under the cap).
                {
                    // Real cursor/icon/OBM callbacks run bounded resource-load bursts before SAS;
                    // dispatching the first real SAS then starts welcome-dialog construction, whose child
                    // creation and layout legitimately cross the historical 500-call ceiling before
                    // IDD_LOGON can be correlated. Grant only a bounded bridge after both the dequeued
                    // SAS and a real post-SAS dialog creation; reserve the larger burst for the exact
                    // correlated credential dialog.
                    const W32_TOTAL_LIMIT: u64 = 500;
                    const W32_RESOURCE_CALLBACK_LIMIT: u64 = 1536;
                    const W32_POST_SAS_DIALOG_LIMIT: u64 = 2048;
                    const W32_IDD_LOGON_LIMIT: u64 = 4096;
                    let limit = if pi == 2
                        && WINLOGON_DIALOG_MODAL_READY.load(Ordering::Relaxed) != 0
                    {
                        W32_IDD_LOGON_LIMIT
                    } else if pi == 2
                        && WINLOGON_SAS1_RETRIEVED.load(Ordering::Relaxed) != 0
                        && WINLOGON_DIALOG_WINDOWS.load(Ordering::Relaxed) != 0
                    {
                        W32_POST_SAS_DIALOG_LIMIT
                    } else if pi == 2 && win32k_glue::real_resource_callback_started() {
                        W32_RESOURCE_CALLBACK_LIMIT
                    } else {
                        W32_TOTAL_LIMIT
                    };
                    let total = W32_TOTAL_DISPATCH[pi].fetch_add(1, Ordering::Relaxed) + 1;
                    if total >= limit {
                        print_str(b"[w32-spin] pi=");
                        print_u64(pi as u64);
                        print_str(b" badge=");
                        print_u64(badge);
                        print_str(b" last SSN=0x");
                        print_hex(m0 as u32);
                        print_str(b" exceeded ");
                        print_u64(total);
                        print_str(b" total win32k dispatches (live-lock) -> PARK\n");
                        park_and_log!(pi, b"win32k-spin", m0, m0);
                    }
                }
                // Phase 2c Milestone C: a win32k NtUser/NtGdi system call (SSN >= 0x1000) issued by
                // csrss (winsrv's UserServerDllInitialization) OR by winlogon (its user32 DllMain's
                // NtUserProcessConnect + WinMain's window-station/desktop calls) — the SECOND hosted
                // GUI client. Forward it to the parked win32k component through the persistent dispatch
                // loop; the handler runs in win32k's OWN context (GS=KPCR / session heap). Both clients
                // are serviced ONE AT A TIME by the main loop (FIFO recv), each bound to REPLY_MAIN at
                // its recv, so the routed reply (send_on_reply(REPLY_MAIN)) resumes exactly this caller
                // — csrss and winlogon never orphan each other. Scalar + handle args ride the registers
                // exactly as the native x64 syscall passed them (arg1=R10, arg2=RDX, arg3=R8, arg4=R9);
                // pointer/buffer args are marshaled per SSN as needed. Per-process stack/heap/image
                // mirrors are already selected by `pi` above (smss_stack_read reaches winlogon's stack).
                let a0 = get_recv_mr(9); // R10 = arg1
                let a1 = m3; // RDX = arg2
                let a2 = get_recv_mr(7); // R8 = arg3
                let a3 = get_recv_mr(8); // R9 = arg4
                // NtUserInitialize(dwWinVersion=a0, hPowerRequestEvent=a1, hMediaRequestEvent=a2):
                // winsrv created these events via NtCreateEvent into its own image globals. Forward
                // exactly what the caller supplied; no executive-side substitution is permitted.
                if m0 == win32k_subsystem::SSN_NT_USER_INITIALIZE_REAL {
                    print_str(b"[ntuser-init] raw power=0x");
                    print_hex((a1 >> 32) as u32);
                    print_hex(a1 as u32);
                    print_str(b" media=0x");
                    print_hex((a2 >> 32) as u32);
                    print_hex(a2 as u32);
                    print_str(b"\n");
                }
                // NtCurrentProcess() == (HANDLE)-1: win32k's ObReferenceObjectByHandle resolves the
                // hosted client's process via the synthetic handle the DriverEntry attach used.
                let mut d_a0 = if a0 == 0xFFFF_FFFF_FFFF_FFFF { win32k_subsystem::FAKE_PROCESS_HANDLE } else { a0 };
                // CROSS-AS ARG MARSHALING. NtUserProcessConnect(handle, USERCONNECT* buf, size): the
                // buffer is a csrss user pointer (its stack) NOT mapped in win32k's VSpace — passing it
                // raw makes win32k's handler fault/spin on an address win32k_dispatch can't resolve.
                // Copy csrss's input buffer into the shared ARG frame (mapped in BOTH), dispatch with
                // the ARG-frame pointer, then copy win32k's out-params (the USERCONNECT) back to csrss.
                let has_buf = m0 == win32k_subsystem::SSN_NT_USER_INITIALIZE; // 0x10FA = NtUserProcessConnect
                let (d_a1, blen) = if has_buf {
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    let n = a2.min(win32k_subsystem::WIN32K_ARG_FRAMES * 0x1000);
                    core::ptr::write_bytes(arg as *mut u8, 0, (win32k_subsystem::WIN32K_ARG_FRAMES * 0x1000) as usize);
                    let mut off = 0u64;
                    while off + 8 <= n {
                        core::ptr::write_volatile((arg + off) as *mut u64, smss_stack_read(a1 + off));
                        off += 8;
                    }
                    (arg, n)
                } else {
                    (a1, 0)
                };
                // BATCH 43: throttle the per-dispatch header for the HIGH-FREQUENCY class-registration
                // loop SSNs (0x103d NtUserFindExistingCursorIcon / 0x10b4 NtUserRegisterClassExWOW), which
                // each fire dozens of times during user32 RegisterSystemClasses. Serial writes dominate the
                // TCG per-round-trip cost and the boot budget is tight now that winlogon crosses its win32k
                // wall (BATCH 43). Print the first 6 of each, then suppress; all OTHER SSNs always print.
                let w32_hot = m0 == 0x103d || m0 == 0x10b4;
                let w32_log = !w32_hot || W32_HOT_LOG.fetch_add(1, Ordering::Relaxed) < 12;
                if w32_log {
                    print_str(b"[win32k-svc] csrss -> SSN 0x");
                    print_hex(m0 as u32);
                    print_str(b" (dispatch)\n");
                }
                // DIAG: NtUserCreateWindowStation(0x122f) OA-pointer probe — read the client's REAL
                // OBJECT_ATTRIBUTES.Length via its stack mirror (pi-selected) so we can tell a stale
                // (wrong-client) frame in win32k from a genuinely-bad OA the client built.
                if m0 == 0x122f {
                    let mut oa = [0u8; 0x30];
                    let oa_ok = img_spawn::client_copyin_mapped(
                        pi as u64,
                        a0,
                        &mut oa,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    let object_name = if oa_ok {
                        u64::from_le_bytes(oa[0x10..0x18].try_into().unwrap())
                    } else {
                        0
                    };
                    let mut name = [0u8; 0x10];
                    let name_ok = object_name != 0
                        && img_spawn::client_copyin_mapped(
                            pi as u64,
                            object_name,
                            &mut name,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                    let name_lengths = if name_ok {
                        u32::from_le_bytes(name[0..4].try_into().unwrap())
                    } else {
                        0
                    };
                    let name_buffer = if name_ok {
                        u64::from_le_bytes(name[8..16].try_into().unwrap())
                    } else {
                        0
                    };
                    let mut prefix = [0u8; 8];
                    let prefix_ok = name_buffer != 0
                        && img_spawn::client_copyin_mapped(
                            pi as u64,
                            name_buffer,
                            &mut prefix,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                    print_str(b"[w32diag] 0x122f OA=0x");
                    print_hex((a0 >> 32) as u32);
                    print_hex(a0 as u32);
                    print_str(b" real-Length=0x");
                    print_hex(smss_stack_read(a0) as u32);
                    print_str(b" pi=");
                    print_u64(pi as u64);
                    print_str(b" graph=");
                    print_u64(oa_ok as u64);
                    print_str(b"/");
                    print_u64(name_ok as u64);
                    print_str(b"/");
                    print_u64(prefix_ok as u64);
                    print_str(b" ObjectName=0x");
                    print_hex((object_name >> 32) as u32);
                    print_hex(object_name as u32);
                    print_str(b" LenMax=0x");
                    print_hex(name_lengths);
                    print_str(b" Buffer=0x");
                    print_hex((name_buffer >> 32) as u32);
                    print_hex(name_buffer as u32);
                    print_str(b" text4=0x");
                    print_hex(u64::from_le_bytes(prefix) as u32);
                    print_str(b"\n");

                    // win32k is an isolated component, so capture the nested user pointer graph at
                    // the executive boundary just as NtUserCreateWindowStation's ProbeForRead block
                    // does in a monolithic kernel. Preserve scalar handles/flags and the caller's
                    // security descriptor pointer; only the OA, counted-string descriptor, and its
                    // bounded UTF-16 buffer need rebasing into the shared argument window.
                    let name_len = (name_lengths & 0xffff) as usize;
                    let name_max = (name_lengths >> 16) as usize;
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    let arg_bytes = (win32k_subsystem::WIN32K_ARG_FRAMES * 0x1000) as usize;
                    let graph_valid = oa_ok
                        && name_ok
                        && prefix_ok
                        && name_len != 0
                        && name_len & 1 == 0
                        && name_len <= name_max
                        && name_max <= arg_bytes - 0x40;
                    if graph_valid {
                        core::ptr::write_bytes(arg as *mut u8, 0, arg_bytes);
                        core::ptr::copy_nonoverlapping(oa.as_ptr(), arg as *mut u8, oa.len());
                        core::ptr::copy_nonoverlapping(
                            name.as_ptr(),
                            (arg + 0x30) as *mut u8,
                            name.len(),
                        );
                        let name_out = core::slice::from_raw_parts_mut(
                            (arg + 0x40) as *mut u8,
                            name_max,
                        );
                        if img_spawn::client_copyin_mapped(
                            pi as u64,
                            name_buffer,
                            name_out,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        ) {
                            core::ptr::write_unaligned((arg + 0x10) as *mut u64, arg + 0x30);
                            core::ptr::write_unaligned((arg + 0x38) as *mut u64, arg + 0x40);
                            d_a0 = arg;
                            print_str(b"[w32marshal] captured named window-station OA graph bytes=");
                            print_u64(0x40 + name_max as u64);
                            print_str(b"\n");
                        }
                    }
                }
                // ★ THE COUNTED DESKTOP PAINT — winlogon's OWN natural NtUserSwitchDesktop paints the
                // framebuffer, and THIS is the source of the `exec_win32k_desktop_painted` gate spec
                // (scaffold RETIRED — see the m0==0x125a arm, which now runs ONLY the InitVideo/surface
                // bringup, not the paint). Right BEFORE winlogon's SSN 0x1288 we clear the WHOLE fb to
                // magenta — now LOAD-BEARING: it wipes any earlier pixels so the counted spec genuinely
                // proves winlogon's co_IntShowDesktop -> co_UserRedrawWindow -> DesktopWindowProc
                // WM_ERASEBKGND -> IntPaintDesktop re-painted 0x003a6ea5 by the AUTHENTIC boot flow
                // (BOOTBOOT -> kernel -> smss -> csrss -> winlogon -> win32k), not a stale scaffold paint.
                // ★ BATCH 46 — only the FIRST winlogon switch is the real (painting) transition; the second
                // is win32k's `pdesk == gpdeskInputDesktop` already-current no-op (zero paint work). Gate the
                // magenta-clear + readback on WINLOGON_PAINT_DONE so the already-current second switch does
                // NOT wipe the painted fb back to magenta and re-read 0/768.
                let winlogon_switch =
                    m0 == 0x1288 && badge == WINLOGON_BADGE && WINLOGON_PAINT_DONE.load(Ordering::Relaxed) == 0;
                if winlogon_switch {
                    let fb = FB_VADDR as *mut u32;
                    for i in 0..(1024u64 * 768) {
                        core::ptr::write_volatile(fb.add(i as usize), 0x00FF_00FF);
                    }
                    print_str(b"[win32k-svc] fb cleared to magenta before winlogon NtUserSwitchDesktop\n");
                }
                // P5 — FAKE NtUserLoadKeyboardLayoutEx (SSN 0x125c) for winlogon. Routing it to win32k
                // faults dereferencing the client `pustrKLID` at a low VA AND drags in the interactive-
                // winsta / desktop-thread keyboard-layout window-manager fork (which regressed the
                // paint). winlogon's IntLoadKeyboardLayout only needs a NON-NULL HKL back (it checks
                // `if (LoadKeyboardLayoutW(...))`), so return the US layout HKL MAKELONG(0x0409,0x0409)
                // WITHOUT dispatching — win32k's post-paint window state stays clean (the counted paint
                // already fired at SSN 0x1288 above).
                // ★ NON-INTERACTIVE SERVICE user32-init cursor/class fake (services=6 / lsass=8).
                // A service's user32 DllMain runs RegisterSystemClasses, but win32k's shared system
                // cursors (gasyscur) are ONLY loaded by winlogon's INTERACTIVE SwitchDesktop ->
                // co_IntLoadDefaultCursors -> NtUserSetSystemCursor. A service on a non-interactive
                // (WSS_NOIO) winstation never triggers that, so NtUserFindExistingCursorIcon (0x103d)
                // returns NULL forever and NtUserRegisterClassExWOW (0x10b4) can't satisfy its cursor
                // precondition -> the per-class registration loop never advances -> the service never
                // finishes process-attach -> lsass never reaches LsaInitializeRpcServer ->
                // never SetEvent(lsa_rpc_server_active) -> winlogon's WaitForLsass deadlocks. Since a
                // service is non-interactive and never creates a real window, SATISFY the loop's
                // preconditions here (do NOT route to win32k, which drags in the interactive-winsta
                // cursor fork winlogon owns): 0x103d -> a non-NULL synthetic HCURSOR so user32's
                // LoadCursor short-circuits; 0x10b4 -> a fresh RTL_ATOM (0xC1xx) so the class registers.
                // Gated to services/lsass ONLY — winlogon's real GUI path is untouched.
                // ★ BATCH 32: extend the gate to SERVICES (badge 6) as well as LSASS (badge 8). Both
                // are NON-INTERACTIVE services on a WSS_NOIO window station — neither creates a real
                // window nor does GDI drawing, so both must take the light non-interactive user32-init
                // path instead of tripping win32k's interactive cursor/class/stock-object EngCopyBits
                // runaway blit (RVA 0x1cbdd8). The prior LSASS-only gate was because, in an EARLIER
                // batch, lsass had not yet spawned and faking services' calls perturbed the multiplex
                // timing that let winlogon's StartLsass run. That concern is now STALE: lsass fully
                // spawns AND signals LSA_RPC_SERVER_ACTIVE BEFORE services even reaches its user32
                // init (verified in the boot log — winlogon's WaitForLsass wakes, then loads
                // sfc/msgina, then opens \pipe\ntsvcs), so faking services' GDI-blit family no longer
                // races lsass spawn. services.exe is now ON the critical path: it is the SCM and must
                // run its main thread to ScmStartRpcServer → NtCreateNamedPipeFile(\pipe\ntsvcs), which
                // it can only reach if its user32 process-attach class-registration loop COMPLETES
                // (parking on 0x103d left \pipe\ntsvcs unserved → winlogon's OpenSCManager 0xC0000034).
                let svc_noninteractive = pi == 3 || pi == 4;
                let (mut st, mut ok) = if wl_milestone_park {
                    // winlogon reached its SAS message-loop milestone (0x1006/0x1001) — do NOT dispatch to
                    // win32k (its GetMessage would block the executive); the !handled block parks winlogon.
                    (0i32, false)
                } else if m0 == 0x125c && badge == WINLOGON_BADGE {
                    KBD_LAYOUT_LOADED.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[win32k-svc] winlogon NtUserLoadKeyboardLayoutEx(0x125c) FAKED -> HKL=0x04090409\n");
                    (0x0409_0409i32, true)
                } else if m0 == 0x103d && svc_noninteractive {
                    // NtUserFindExistingCursorIcon -> a non-NULL cached HCURSOR (user handle-ish value).
                    SVC_USER32_FAKE_CALLS.fetch_add(1, Ordering::Relaxed);
                    (0x0001_0005i32, true)
                } else if m0 == 0x10b4 && svc_noninteractive {
                    // NtUserRegisterClassExWOW -> a fresh class atom so RegisterSystemClasses advances.
                    SVC_USER32_FAKE_CALLS.fetch_add(1, Ordering::Relaxed);
                    let atom = SVC_FAKE_CLASS_ATOM.fetch_add(1, Ordering::Relaxed);
                    ((atom & 0xFFFF) as i32, true)
                } else if m0 == 0x125b && svc_noninteractive {
                    // ★ NON-INTERACTIVE SERVICE NtUserInitializeClientPfnArrays (lsass, badge 8).
                    // THE win32k 0x125b TERMINUS FIX (diagnose-first, fork (b): non-interactive path).
                    // The REAL wall (root-caused by reading win32k's OWN faulting RIP at the hang): win32k
                    // spins forever in the GDI scanline-copy loop `EngCopyBits` at RVA 0x1cbdd8 (the
                    // `pvScan0 + y*lDelta + x*4` blit inner loop, confirmed by disasm) — NOT in
                    // NtUserInitializeClientPfnArrays' trivial `RtlCopyMemory(&gpsi->apfnClient*, ...)`
                    // body, but in the cursor/icon/stock-object bitmap-init blit the SERVICE user32
                    // process-attach drags in (NtUserFindExistingCursorIcon 0x103d /
                    // NtUserRegisterClassExWOW 0x10b4 / NtGdiCreateBitmap 0x106c → an EngCopyBits over a
                    // SURFOBJ whose dimensions are garbage for our faked service cursor/class state → an
                    // UNBOUNDED copy). With all its source pages zero-filled it stops faulting and just
                    // spins → the executive blocks in win32k_dispatch's recv forever (all vCPUs
                    // kernel-idle = the addendum's observation). lsass is a NON-INTERACTIVE service on a
                    // WSS_NOIO window station (winsta.c) — it never creates a real window/desktop, so it
                    // must NOT drive win32k's INTERACTIVE cursor/icon/GDI path (faithful to the real
                    // non-interactive-service user32 init). NtUserInitializeClientPfnArrays is trivial
                    // server-side (copy 3 client PFN arrays into the already-initialized gpsi under the
                    // USER lock — `if (ClientPfnInit) return STATUS_SUCCESS`, and ClientPfnInit is ALREADY
                    // TRUE from winlogon's interactive 0x125b); the CLIENT only checks the returned
                    // NTSTATUS. So SATISFY it here with STATUS_SUCCESS WITHOUT dispatching into win32k —
                    // exactly the same reasoning already applied+documented for 0x103d/0x10b4 above.
                    // Scoped to lsass ONLY (badge 8) so winlogon's REAL interactive 0x125b + paint path
                    // is untouched (a blanket 0x125b fake was tried+reverted in BATCH 28: it moved the
                    // hang to 0x11e0 by breaking winlogon's interactive init).
                    SVC_USER32_FAKE_CALLS.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[win32k-svc] svc NtUserInitializeClientPfnArrays(0x125b) FAKED (non-interactive service, no GDI blit) -> STATUS_SUCCESS\n");
                    (0, true)
                } else if m0 == 0x11e0 && svc_noninteractive {
                    // ★ NON-INTERACTIVE SERVICE NtGdiInit (0x11e0, GdiInit — w32ksvc64.h) for lsass.
                    // The 0x125b fix advanced lsass to its NEXT interactive win32k SSN = NtGdiInit, which
                    // hit the SAME EngCopyBits (RVA 0x1cbdd8) runaway blit spin (win32k's GDI stock-object /
                    // DDB bitmap-init blit — the source SURFOBJ dimensions are garbage for our faked
                    // service cursor/class/GDI state). This is the EXACT "moved the hang to 0x11e0" BATCH 28
                    // saw — now understood: a non-interactive service issues a SEQUENCE of interactive
                    // user32/gdi32-init SSNs, each tripping the blit; each must take the non-interactive
                    // light path. NtGdiInit is a per-process "init GDI" that returns BOOL; the REAL
                    // interactive winlogon's NtGdiInit returned TRUE(1) in the SAME boot (proper stock
                    // state → no runaway blit). A non-interactive service does NO GDI drawing, so returning
                    // TRUE(1) WITHOUT dispatching is byte-behavior-identical for the client (gdi32
                    // GdiProcessSetup checks the BOOL) and skips the interactive stock-object blit. Scoped
                    // to lsass (badge 8) — winlogon's real NtGdiInit path is untouched.
                    SVC_USER32_FAKE_CALLS.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[win32k-svc] svc NtGdiInit(0x11e0) FAKED (non-interactive service, no GDI stock blit) -> TRUE\n");
                    (1, true)
                } else if (m0 == 0x106c || m0 == 0x10b5) && svc_noninteractive {
                    // ★ NON-INTERACTIVE SERVICE GDI object-creation (0x106c NtGdiCreateBitmap /
                    // 0x10b5 NtGdiGetStockObject — w32ksvc64.h) for lsass. After 0x125b/0x11e0, lsass'
                    // GUI-DLL DllMains (comctl32/uxtheme) create cached GDI objects; routing these into
                    // win32k trips the SAME EngCopyBits (RVA 0x1cbdd8) runaway blit (a fault-FREE spin the
                    // executive cannot interrupt — it's blocked in win32k_dispatch's recv). A non-interactive
                    // service creates these objects but NEVER draws with them, so return a synthetic non-NULL
                    // GDI handle (mimicking the interactive path's 0x00050048/0x0010004a GDI-handle shape) so
                    // the client's DllMain stores a plausible handle and proceeds — the same
                    // non-interactive-service short-circuit as 0x103d/0x10b4/0x125b/0x11e0. Scoped to lsass
                    // (badge 8); the interactive clients' real routed 0x106c/0x10b5 (BATCH 16, bounded via
                    // zero-fill) are untouched. If a service later performs a REAL blit with the handle that
                    // is the next diagnosed wall (a service normally does not).
                    SVC_USER32_FAKE_CALLS.fetch_add(1, Ordering::Relaxed);
                    let h = SVC_FAKE_GDI_HANDLE.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[win32k-svc] svc NtGdi obj-create(0x");
                    print_hex(m0 as u32);
                    print_str(b") FAKED (non-interactive service, no GDI blit) -> handle 0x");
                    print_hex(h as u32);
                    print_str(b"\n");
                    (h as i32, true)
                } else if m0 == 0x10bd && svc_noninteractive {
                    // ★ NON-INTERACTIVE SERVICE NtUserGetClassInfo (0x10bd — w32ksvc64.h) for lsass.
                    // ROOT of the whole GDI-blit family: win32k's class-lookup path
                    // (IntGetAndReferenceClass, class.c:1461) does
                    //   `if (!(pti->ppi->W32PF_flags & W32PF_CLASSESREGISTERED)) UserRegisterSystemClasses();`
                    // and lsass' PROCESSINFO never has W32PF_CLASSESREGISTERED set (we faked the class
                    // registration, never ran the REAL UserRegisterSystemClasses), so EVERY class call
                    // (GetClassInfo, and any window-create) RE-triggers UserRegisterSystemClasses → the
                    // interactive stock-object/cursor EngCopyBits (RVA 0x1cbdd8) runaway blit. Since our
                    // single-threaded host shares ONE PROCESSINFO across clients (setup_dispatch_context),
                    // we cannot set W32PF_CLASSESREGISTERED globally without breaking winlogon's REAL
                    // interactive class registration (needed for the paint). So short-circuit lsass'
                    // NtUserGetClassInfo → FALSE (0, class-not-found) WITHOUT dispatching: user32's
                    // GetClassInfoExW treats it as an unregistered class (benign for a non-interactive
                    // service that never creates windows) and does NOT reach the class-lookup that runs
                    // UserRegisterSystemClasses. Scoped to lsass (badge 8); winlogon's real 0x10bd untouched.
                    SVC_USER32_FAKE_CALLS.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[win32k-svc] svc NtUserGetClassInfo(0x10bd) FAKED (non-interactive service, skip UserRegisterSystemClasses blit) -> FALSE\n");
                    (0, true)
                } else {
                    // ★ BATCH 44 — marshal the win64 STACK-ARG TAIL for WIDE win32k SSNs. `sp` is the
                    // client's syscall-entry stack pointer (MR16). The kernel captures the faulting
                    // thread's RSP into MR16 (see the NtQueryInformationThread return_length read at
                    // sp+0x28 above), so args 5..N live at [sp+0x28], [sp+0x30], … per win64. For a wide
                    // SSN (nargs>4) win32k_dispatch_wide reads args 5..N from the client stack; for the
                    // common nargs<=4 case it is byte-identical to the old register-only dispatch.
                    let sp = get_recv_mr(16);
                    let nargs = win32k_subsystem::win32k_ssn_argc(m0);
                    let stack_arg_count = nargs.min(16).saturating_sub(4) as usize;
                    let mut stack_args = [0u64; 12];
                    for (index, value) in stack_args[..stack_arg_count].iter_mut().enumerate() {
                        *value = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x28 + index as u64 * 8,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                        .unwrap_or(0);
                    }
                    let peb_mirror = match pi {
                        0 => 0x0000_0100_1074_1000,
                        1 => 0x0000_0100_1078_1000,
                        2 => 0x0000_0100_107C_1000,
                        3 => SERVICES_ENV_SCRATCH_VA + 0x1000,
                        4 => LSASS_ENV_SCRATCH_VA + 0x1000,
                        _ => 0,
                    };
                    let client_teb = nt_handler
                        .pm
                        .thread_teb(nt_handler.current_tid as nt_process::ThreadId)
                        .filter(|teb| *teb != 0)
                        .unwrap_or(SMSS_TEB_VA);
                    if pi >= 1 && m0 == 0x1077 && a3 != 0 {
                        prefill_client_large_string_pages(
                            pi as u64,
                            a3,
                            scratch_base,
                            &mut faults,
                            filled_pages,
                            &reg,
                            &dll_pes,
                        );
                    }
                    let r = win32k_glue::win32k_dispatch_wide(
                        m0,
                        d_a0,
                        d_a1,
                        a2,
                        a3,
                        sp,
                        nargs,
                        &stack_args[..stack_arg_count],
                        win32k_glue::Win32kClientContext {
                            pi: pi as u32,
                            pid: nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
                            badge,
                            tid: nt_handler.current_tid,
                            teb: client_teb,
                            peb_mirror,
                            scratch_base,
                        },
                    );
                    // DIAG: dump the retrieved MSG for winlogon's SAS GetMessage (a0=R10=&Msg). MSG =
                    // {hwnd@0, message@8, wParam@0x10, lParam@0x18}. Confirms whether the injected
                    // WLX_WM_SAS (0x659) reaches winlogon so DispatchMessageW runs SASWindowProc.
                    if pi == 2 && (m0 == 0x1006 || m0 == 0x1001) && a0 != 0 {
                        let hwnd = smss_stack_read(a0);
                        let message = smss_stack_read(a0 + 8);
                        let wparam = smss_stack_read(a0 + 0x10);
                        print_str(b"[wl-diag] GetMessage retrieved MSG hwnd=0x");
                        print_hex(hwnd as u32);
                        print_str(b" message=0x");
                        print_hex(message as u32);
                        print_str(b" wParam=0x");
                        print_hex(wparam as u32);
                        print_str(b" (ret=0x");
                        print_hex(r.0 as u32);
                        print_str(b")\n");
                        if r.0 == 1
                            && message as u32 == nt_user_callback::WLX_WM_SAS
                            && wparam == nt_user_callback::WLX_SAS_TYPE_CTRL_ALT_DEL
                        {
                            if WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) == 0
                                && WINLOGON_SAS1_RETRIEVED.swap(1, Ordering::Relaxed) == 0
                            {
                                WINLOGON_PAINT_RETURNS_AT_SAS1.store(
                                    win32k_glue::real_wm_paint_callback_returns(),
                                    Ordering::Relaxed,
                                );
                            } else if WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) != 0 {
                                WINLOGON_MSGLOOP_MILESTONE.fetch_add(1, Ordering::Relaxed);
                            }
                            let session = core::ptr::read_volatile(
                                (win32k_subsystem::WIN32K_SHARED_VADDR
                                    + win32k_subsystem::SH_SAS_SESSION)
                                    as *const u64,
                            );
                            let _ = winlogon_dialog_observe_sas_message(
                                session,
                                hwnd,
                                message as u32,
                                wparam,
                            );
                        }
                    }
                    if pi == 2
                        && m0 == nt_user_callback::NTUSER_PEEK_MESSAGE_SSN
                        && r.0 == 0
                        && badge == WINLOGON_BADGE
                        && current_tid == PM_TIDS[pi].load(Ordering::Relaxed)
                        && WINLOGON_SAS1_RETRIEVED.load(Ordering::Relaxed) != 0
                        && WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) == 0
                        && win32k_glue::real_wm_paint_callback_returns()
                            > WINLOGON_PAINT_RETURNS_AT_SAS1.load(Ordering::Relaxed)
                        && winlogon_pwnd_for_hwnd(win32k_glue::last_real_wm_paint_hwnd()) != 0
                    {
                        let session = core::ptr::read_volatile(
                            (win32k_subsystem::WIN32K_SHARED_VADDR
                                + win32k_subsystem::SH_SAS_SESSION) as *const u64,
                        );
                        let mut logon_state = 0u32;
                        if session != 0 {
                            const WLSESSION_LOGONSTATE_OFF: u64 = 0x118;
                            let mut bytes = [0u8; 4];
                            if img_spawn::smss_copyin(
                                session + WLSESSION_LOGONSTATE_OFF,
                                &mut bytes,
                            ) {
                                logon_state = u32::from_le_bytes(bytes);
                            }
                        }
                        print_str(b"[wl-main] welcome queue drained after real paint; Session->LogonState=0x");
                        print_hex(logon_state);
                        print_str(b"\n");
                        if logon_state == nt_user_callback::WINLOGON_STATE_LOGGED_OFF {
                            WINLOGON_SAS_LOGONSTATE.store(logon_state as u64, Ordering::Relaxed);
                            let _ = winlogon_dialog_observe_logged_off(session, logon_state);
                            let hwnd = core::ptr::read_volatile(
                                (win32k_subsystem::WIN32K_SHARED_VADDR
                                    + win32k_subsystem::SH_SAS_HWND) as *const u64,
                            );
                            if hwnd != 0 {
                                WINLOGON_KEY_OPENED_AT_INJECT.store(
                                    WINLOGON_KEY_OPENED.load(Ordering::Relaxed),
                                    Ordering::Relaxed,
                                );
                                print_str(b"[wl-main] posting simulated Ctrl-Alt-Del through real NtUserPostMessage hwnd=0x");
                                print_hex(hwnd as u32);
                                print_str(b"\n");
                                let post = win32k_glue::win32k_dispatch_wide(
                                    0x100e,
                                    hwnd,
                                    nt_user_callback::WLX_WM_SAS as u64,
                                    nt_user_callback::WLX_SAS_TYPE_CTRL_ALT_DEL,
                                    0,
                                    0,
                                    4,
                                    &[],
                                    win32k_glue::Win32kClientContext {
                                        pi: pi as u32,
                                        pid: nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
                                        badge,
                                        tid: nt_handler.current_tid,
                                        teb: client_teb,
                                        peb_mirror,
                                        scratch_base,
                                    },
                                );
                                print_str(b"[wl-main] NtUserPostMessage(WLX_WM_SAS) -> ret=0x");
                                print_hex(post.0 as u32);
                                print_str(b"\n");
                                if post.1 && post.0 != 0 {
                                    WINLOGON_SAS2_INJECTED.store(1, Ordering::Relaxed);
                                } else {
                                    handled = false;
                                    wl_milestone_park = true;
                                }
                            }
                        }
                    }
                    r
                };
                let callback_suspended = win32k_glue::take_user_callback_pump_suspended();
                if dialog_modal_dispatch && !callback_suspended {
                    let hwnd = if a0 != 0 { smss_stack_read(a0) } else { 0 };
                    let message = if a0 != 0 {
                        smss_stack_read(a0 + 8) as u32
                    } else {
                        0
                    };
                    if !winlogon_dialog_modal_observe(m0, st, hwnd, message) {
                        handled = false;
                        wl_milestone_park = true;
                    }
                }
                if callback_suspended {
                    let peb_mirror = match pi {
                        0 => 0x0000_0100_1074_1000,
                        1 => 0x0000_0100_1078_1000,
                        2 => 0x0000_0100_107C_1000,
                        3 => SERVICES_ENV_SCRATCH_VA + 0x1000,
                        4 => LSASS_ENV_SCRATCH_VA + 0x1000,
                        _ => 0,
                    };
                    let client_teb = nt_handler
                        .pm
                        .thread_teb(nt_handler.current_tid as nt_process::ThreadId)
                        .filter(|teb| *teb != 0)
                        .unwrap_or(SMSS_TEB_VA);
                    redirected_user_callback = win32k_glue::begin_controlled_user_callback_redirect(
                        win32k_glue::Win32kClientContext {
                            pi: pi as u32,
                            pid: nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
                            badge,
                            tid: nt_handler.current_tid,
                            teb: client_teb,
                            peb_mirror,
                            scratch_base,
                        },
                        resume_ip,
                        sp,
                        flags,
                    );
                    if !redirected_user_callback {
                        let resumed = win32k_glue::cancel_suspended_user_callback();
                        st = resumed.0;
                        ok = resumed.1;
                    }
                }
                if winlogon_switch && !redirected_user_callback {
                    // Read back the 768-px sampled grid; count how many winlogon's OWN SwitchDesktop flow
                    // painted to the WC_DESKTOP background. This drives the counted paint gate.
                    let fb = FB_VADDR as *const u32;
                    let mut matched = 0u32;
                    let mut changed = 0u32;
                    let mut non_bg_count = 0u32;
                    let mut non_bg_index = 0u64;
                    let mut non_bg_value = 0u32;
                    let mut sample0 = 0u32;
                    for r in 0..24u64 {
                        for c in 0..32u64 {
                            let idx = r * 32 * 1024 + c * 32;
                            let px = core::ptr::read_volatile(fb.add(idx as usize));
                            if r == 0 && c == 0 {
                                sample0 = px;
                            }
                            if px != 0x00FF_00FF {
                                changed += 1;
                            }
                            if px == FB_DESKTOP_BG {
                                matched += 1;
                            } else {
                                non_bg_count += 1;
                                non_bg_index = idx;
                                non_bg_value = px;
                            }
                        }
                    }
                    WINLOGON_NATURAL_PAINT.store(matched as u64, Ordering::Relaxed);
                    // Feed the counted `exec_win32k_desktop_painted` gate from winlogon's NATURAL paint
                    // (the scaffold no longer paints — the m0==0x125a arm keeps only InitVideo/surface).
                    FB_PIXELS_DREW.store(if changed > 0 { 2 } else { 1 }, Ordering::Relaxed);
                    FB_PIXELS_MATCH.store(matched as u64, Ordering::Relaxed);
                    FB_PIXELS_CHANGED.store(changed as u64, Ordering::Relaxed);
                    FB_NON_BG_COUNT.store(non_bg_count as u64, Ordering::Relaxed);
                    FB_NON_BG_INDEX.store(non_bg_index, Ordering::Relaxed);
                    FB_NON_BG_VALUE.store(non_bg_value as u64, Ordering::Relaxed);
                    FB_PIXELS_SAMPLE0.store(sample0 as u64, Ordering::Relaxed);
                    print_str(b"[win32k-svc] winlogon NtUserSwitchDesktop ret=0x");
                    print_hex(st as u32);
                    print_str(b" -> NATURAL fb readback: changed ");
                    print_u64(changed as u64);
                    print_str(b"/768, desktop-bg ");
                    print_u64(matched as u64);
                    print_str(b"/768 (px0=0x");
                    print_hex(sample0);
                    print_str(b", non-bg ");
                    print_u64(non_bg_count as u64);
                    print_str(b" at 0x");
                    print_hex(non_bg_index as u32);
                    print_str(b" value=0x");
                    print_hex(non_bg_value);
                    print_str(b")\n");
                    // Latch: this painting switch is done. The next winlogon 0x1288 (already-current no-op)
                    // must NOT clear/re-read the fb (it would wipe the paint we just sampled).
                    WINLOGON_PAINT_DONE.store(1, Ordering::Relaxed);
                }
                if has_buf && ok && st == 0 && !redirected_user_callback {
                    // NtUserProcessConnect (0x10FA) returned STATUS_SUCCESS for this GUI client —
                    // record the per-pi "win32k client connected" bit (csrss=1, winlogon=2, services=3).
                    W32_CONNECTED_MASK.fetch_or(1u64 << pi, Ordering::Relaxed);
                }
                if has_buf && ok && !redirected_user_callback {
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    // gSharedInfo CLIENT-MAPPING. win32k's NtUserProcessConnect handler filled the
                    // USERCONNECT's siClient with pointers into its OWN session-space USER heap
                    // (gpsi / gHandleTable / the handle-entry array — all `UserHeapAlloc`ed), which
                    // is NOT mapped in csrss → user32's DllMain `Init` faults dereferencing
                    // gSharedInfo.aheList->handles. RO-map that heap arena into csrss and rewrite the
                    // siClient pointers (+ ulSharedDelta) to the csrss-relative client addresses so
                    // the client reads valid memory. delta = server(win32k) − client(csrss).
                    let delta = map_win32k_heap_into_csrss(pml4, pi);
                    let heap_lo = win32k_subsystem::WIN32K_HEAP_VADDR;
                    let heap_hi = heap_lo + win32k_subsystem::WIN32K_HEAP_FRAMES * 0x1000;
                    // The handler's own shift (0 in this single-AS host; be robust anyway): recover
                    // the raw server VA before applying our delta.
                    let hd = core::ptr::read_volatile((arg + win32k_subsystem::UC_SI_DELTA) as *const u64);
                    // Publish the RAW server-VA aheList (USER handle table) so win32k's WM_CREATE callback
                    // bridge can resolve a HWND → its PWND to persist WND.dwUserData (the Session), for the
                    // client-side SASWindowProc. Capture it before the delta rewrite below.
                    {
                        let ahe_client = core::ptr::read_volatile(
                            (arg + win32k_subsystem::UC_SI_AHELIST) as *const u64,
                        );
                        if ahe_client != 0 {
                            let ahe_server = ahe_client.wrapping_add(hd);
                            if ahe_server >= heap_lo && ahe_server < heap_hi {
                                core::ptr::write_volatile(
                                    (win32k_subsystem::WIN32K_SHARED_VADDR
                                        + win32k_subsystem::SH_SAS_AHELIST)
                                        as *mut u64,
                                    ahe_server,
                                );
                            }
                        }
                    }
                    for off in [win32k_subsystem::UC_SI_PSI, win32k_subsystem::UC_SI_AHELIST] {
                        let client = core::ptr::read_volatile((arg + off) as *const u64);
                        if client != 0 {
                            let server = client.wrapping_add(hd);
                            if server >= heap_lo && server < heap_hi {
                                core::ptr::write_volatile(
                                    (arg + off) as *mut u64,
                                    server.wrapping_sub(delta),
                                );
                            }
                        }
                    }
                    core::ptr::write_volatile((arg + win32k_subsystem::UC_SI_DELTA) as *mut u64, delta);
                    core::ptr::write_volatile((arg + win32k_subsystem::UC_SI_PDISPINFO) as *mut u64, 0);
                    // Copy the fixed-up USERCONNECT back to csrss's stack.
                    let mut off = 0u64;
                    while off + 8 <= blen {
                        smss_stack_write(a1 + off, core::ptr::read_volatile((arg + off) as *const u64));
                        off += 8;
                    }
                }
                // BATCH 43: throttle the status line for the same hot class-loop SSNs (WALL statuses ALWAYS
                // print — a wall is never suppressed).
                if !redirected_user_callback && (!ok || w32_log) {
                    print_str(b"[win32k-svc] csrss SSN 0x");
                    print_hex(m0 as u32);
                    print_str(if ok { b" -> status=0x" } else { b" -> WALL status=0x" });
                    print_hex(st as u32);
                    print_str(b"\n");
                }
                // BATCH 39 — REASSERT winlogon's client CLIENTINFO.pDeskInfo after any win32k call.
                // spawn_sec_image seeds TEB.Win32ClientInfo.pDeskInfo (TEB+0x820) with a valid client
                // DESKTOPINFO so an interactive client's user32 GetThreadDesktopWnd() (RVA 0x50009,
                // `mov rax,[pDeskInfo+0x10]`) doesn't NULL-deref. BUT win32k's real IntSetThreadDesktop
                // (desktop.c:3456), run KeStackAttachProcess'd to winlogon during NtUserProcessConnect,
                // takes its ELSE branch (winlogon's pti->rpdesk is NULL in our host — the per-thread
                // desktop-heap view isn't wired) and CLEARS `pci->pDeskInfo = NULL`, re-introducing the
                // crash. The executive still holds each winlogon TEB frame mapped at its env-scratch
                // base, so re-write the faulting thread's client fields after every pi-2 win32k
                // dispatch. (Only pi 2 is interactive + hits GetThreadDesktopWnd;
                // the non-interactive services/lsass short-circuit before their user32 desktop path.)
                if pi == 2 {
                    let winlogon_teb_alias = if let Some((2, tp_slot)) = tp_worker_identity {
                        tp_worker_stack_mirror_va(2, tp_slot) + TP_WORKER_STACK_FRAMES * 0x1000
                    } else if is_wl_worker {
                        match badge {
                            WINLOGON_WORKER2_BADGE => WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000,
                            WINLOGON_WORKER3_BADGE => WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000,
                            _ => WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000,
                        }
                    } else {
                        0x0000_0100_107C_0000
                    };
                    // ★ DESKTOP-HEAP CLIENT-WINDOW MAPPING. Once win32k has bound the Default desktop it
                    // publishes (per dispatch, via the coherent shared page) the DESKTOPINFO server VA
                    // (SH_SAS_DESKINFO) + the dispatch THREADINFO server VA (SH_SAS_PTI == every window's
                    // head.pti). Seed winlogon's TEB.Win32ClientInfo so user32's client-side
                    // ValidateHwnd/DesktopPtrToUser/IntCallMessageProc resolve a real heap-resident PWND
                    // (the SAS window) into winlogon's RO-mapped heap view and run its real SASWindowProc
                    // WITHOUT a syscall (DispatchMessageW message.c:1990 — the SAS-dispatch mechanism):
                    //   - Win32ThreadInfo (TEB+0x78) = pti (server VA) — must EQUAL Wnd->head.pti so
                    //     IntCallMessageProc's same-thread check passes (else ERROR_MESSAGE_SYNC_ONLY).
                    //   - CLIENTINFO.pDeskInfo (TEB+0x820) = DESKTOPINFO − delta (its client VA in the
                    //     RO-mapped heap window at CSRSS_W32_SHARED_VA).
                    //   - CLIENTINFO.ulClientDelta (TEB+0x828) = delta, so DesktopPtrToUser maps every
                    //     heap-resident server pointer (PWND/pcls/spwnd) → its client VA (server−delta).
                    // The DESKTOPINFO's pvDesktopBase/pvDesktopLimit (win32k-side, RO-shared) bracket
                    // the whole heap so the range check accepts any heap pointer. Do not manufacture a
                    // placeholder THREADINFO: without published server state this thread is not ready
                    // for client-side USER dispatch.
                    if let Some((client_deskinfo, pti, delta)) =
                        seed_winlogon_thread_client_info(winlogon_teb_alias, pml4)
                    {
                        if WINLOGON_DESKHEAP_MAPPED.swap(1, Ordering::Relaxed) == 0 {
                            print_str(b"[wl-main] winlogon CLIENTINFO seeded for client-side ValidateHwnd: pDeskInfo=0x");
                            print_hex((client_deskinfo >> 32) as u32);
                            print_hex(client_deskinfo as u32);
                            print_str(b" pti=0x");
                            print_hex((pti >> 32) as u32);
                            print_hex(pti as u32);
                            print_str(b" ulClientDelta=0x");
                            print_hex((delta >> 32) as u32);
                            print_hex(delta as u32);
                            print_str(b"\n");
                        }
                    }
                    // ★ DIALOG BATCH 3 — CLIENT-GDI HANDLE-TABLE MAPPING. The msgina logon dialog's
                    // CreateWindowEx(#32770) → DC/font setup makes client-side gdi32 validate GDI handles
                    // through `GdiSharedHandleTable[handle & 0xffff]` (base = PEB->GdiSharedHandleTable,
                    // seeded at spawn in img_spawn.rs). Project win32k's coherent live handle-table
                    // section and client-writable GDI attribute pool into winlogon. PEB+0xf8 was already
                    // seeded pre-loader so gdi32's GdiProcessSetup cached this same VA.
                    let gdi_va = win32k_glue::map_gdi_shared_handle_table_into_client(pml4, pi);
                    let gdi_attributes = win32k_glue::map_gdi_user_attributes_into_client(pml4, pi);
                    if gdi_va != 0
                        && gdi_attributes
                        && WINLOGON_GDI_MAPPED.swap(1, Ordering::Relaxed) == 0
                    {
                        print_str(b"[wl-main] winlogon client GDI handle table mapped @0x");
                        print_hex((gdi_va >> 32) as u32);
                        print_hex(gdi_va as u32);
                        print_str(b" with live user attributes (PEB->GdiSharedHandleTable seeded pre-loader)\n");
                    }
                }
                // ★ EAGER DESKTOP-GFX HOOK FULLY RETIRED. There is no longer any m0==0x125a
                // SSN_INIT_DESKTOP_GFX scaffold here: win32k's own NtUserInitialize (0x125a) dispatch
                // seeds the host prerequisites the display init depends on (the system font +
                // WinSta0/Default Ob objects — see win32k_subsystem::dispatch_loop's post-0x125a step). The
                // actual InitVideo/framebuf-surface bringup AND the paint now happen FULLY LAZILY from
                // winlogon's OWN first GUI DC-op: NtUserSwitchDesktop → co_IntShowDesktop →
                // co_UserRedrawWindow → WM_ERASEBKGND → UserGetDCEx(DCX_CACHE) → DceAllocDCE →
                // DceCreateDisplayDC → co_IntGraphicsCheck(TRUE) → co_AddGuiApp →
                // co_IntInitializeDesktopGraphics (InitVideo/surface :278/:286 + the atomic paint :340).
                // The counted exec_win32k_desktop_painted spec is fed by the m0==0x1288 arm above.
                if redirected_user_callback {
                    result = nt_user_callback::STATUS_PENDING as u32 as u64;
                } else if ok {
                    result = st as u32 as u64; // NTSTATUS (EAX) back to csrss
                    if pi == 2 && m0 == 0x1077 && st != 0 {
                        observe_winlogon_completed_dispatch(
                            win32k_glue::CompletedWin32kDispatch {
                                ssn: m0,
                                args: [a0, a1, a2, a3],
                                caller_sp: sp,
                                status: st,
                            },
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                    }
                    // ★ BATCH 45 — QUIESCE at the InitializeSAS-complete milestone. `UserSetLogonNotifyWindow`
                    // (0x127c) is winlogon's DEFINING final interactive step: it registers its logon-notify
                    // window, which happens exactly once after the SAS window exists. Past this, winlogon
                    // enters its SAS message loop (an infinite NtUserGetMessage wait we don't service) and
                    // never returns to the executive → the boot would never quiesce and the gate never runs
                    // (the BATCH-44 620s timeout). This is the win32k analogue of the listener milestone
                    // parks below: winlogon's TCB stays blocked at this proven-advanced steady state, the boot
                    // quiesces, and the gate runs cleanly. Gated on the SAS HWND milestone so we only park
                    // once winlogon actually created its window (never on the old NULL-HWND failure path).
                    if pi == 2 && m0 == 0x127c && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) != 0 {
                        // UserSetLogonNotifyWindow success = the SAS window + logon-notify registration is
                        // done. winlogon now runs the InitializeSAS tail (SetDefaultLanguage) + WinMain's
                        // post-SAS setup (RemoveStatusMessage, GetSetupType, PostMessage(WLX_WM_SAS),
                        // NtInitializeRegistry) then enters its GetMessage loop. Do NOT park here — let it
                        // advance; the message-loop milestone park (0x1006/0x1001 above) is its real steady
                        // state. (Reaching 0x127c-success now requires the PsLookup/gpidLogon fix, else the
                        // logon-process access check would fail SetLogonNotifyWindow → InitializeSAS FALSE.)
                        print_str(b"[wl-main] winlogon registered logon-notify window (0x127c) = SAS window ready -> advancing to post-SAS setup\n");
                    }
                } else {
                    handled = false; // dispatch wall — stop with the SSN recorded
                    result = 0xC0000001;
                }
            } else {
                handled = false;
                result = 0xC0000002; // STATUS_NOT_IMPLEMENTED
            }
            if !handled {
                // ★ BATCH 43 — winlogon SAS-window MILESTONE park (recv-next-without-reply). winlogon has
                // CROSSED its win32k class-call-proc wall and created its SAS window; its further
                // window-show→paint flow exceeds the 620s TCG budget. Park it here (its TCB stays blocked
                // at the proven-advanced state) and QUIESCE to the gate — provided the boot is otherwise at
                // steady state (winlogon crossed msgina + LSA signalled). This is the win32k analogue of the
                // listener milestone parks below.
                if wl_milestone_park {
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    crash_parked |= 1u64 << owner_top_badge(badge);
                    if WINLOGON_KEY_OPENED.load(Ordering::Relaxed) != 0
                        && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[quiesce] winlogon reached its win32k SAS-window milestone + steady state -> run gate\n");
                        stop = m0;
                        break;
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
                if is_tp_worker {
                    print_str(b"[tp-worker] blocking/unserviced syscall badge=");
                    print_u64(badge);
                    print_str(b" SSN=");
                    print_u64(m0);
                    print_str(b" -> PARK generic worker; owner continues\n");
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(
                        fault_ep,
                        REPLY_MAIN_SLOT.load(Ordering::Relaxed),
                    );
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // N-threads multiplex: a SERVER thread (svc/lsass listener) that walls on an unserviced
                // BLOCKING server-loop syscall (e.g. NtListenPort / NtReplyWaitReceivePort — it reached
                // its LPC/RPC receive loop and would block forever waiting for a client) PARKS instead of
                // stopping the whole boot. Recv the next event WITHOUT replying → the listener's seL4
                // thread stays blocked (its ETHREAD/TEB/stack stay mapped), and lsass' main thread + the
                // rest of the boot keep advancing. Contained per-thread — the point of the multiplex.
                if is_svc_listener || is_scm_worker || is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 || is_wl_worker {
                    print_str(if is_wl_worker { b"[wl-worker] blocking/unserviced server syscall SSN=" } else if is_scm_worker { b"[scm-worker] blocking/unserviced server syscall SSN=" } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 { b"[lsass-listener] blocking server syscall SSN=" } else { b"[svc-listener] blocking server syscall SSN=" });
                    print_u64(m0);
                    print_str(b" -> PARK thread (reached its RPC receive loop / unserviced); boot continues\n");
                    if is_wl_worker
                        && WINLOGON_MAIN_EVENT_WAIT_PARKED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[wl-worker] parked before signalling the waiting winlogon main thread -> run gate\n");
                        stop = m0;
                        break;
                    }
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    // BATCH 40: a PURE-SERVER listener (services pi3 / lsass pi4) reaching its RPC
                    // receive loop is a terminal cooperative park (it blocks forever waiting for a
                    // client, and by now its process' main thread is done its bring-up). Count its
                    // OWNER process toward the all-parked quiesce so the boot reaches the gate once
                    // every live process is parked — otherwise (now that winlogon crosses msgina and no
                    // longer CRASHES to trigger a quiesce) the main loop blocks in recv forever after
                    // the last listener parks. EXCLUDE is_wl_worker: it shares winlogon's badge whose
                    // MAIN thread has its own SCM-RPC-read quiesce path — marking winlogon here while its
                    // main is still active would quiesce prematurely. mark_wait_parked! only breaks at
                    // true all-parked deadlock; otherwise it just records the bit and recv proceeds.
                    if is_svc_listener {
                        // The SCM listener parking → no live signaler for winlogon's SCM read.
                        SVC_LISTENER_PARKED.store(1, Ordering::Relaxed);
                    }
                    if !is_wl_worker {
                        mark_wait_parked!(pi, m0);
                    }
                    // BATCH 40 terminal backstop: once winlogon has CROSSED its msgina GINA init
                    // (WINLOGON_KEY_OPENED > 0 — WlxInitialize got a non-NULL context, no
                    // WlxShutdown(NULL) crash) AND lsass has signalled LSA_RPC_SERVER_ACTIVE, the boot
                    // has reached steady state: the only remaining live top-level processes are the
                    // persistent SCM/LSA/CSR RPC SERVERS with no live terminating client. A server
                    // listener parking here (SSN=24 = its blocking receive) means it will block forever
                    // waiting for a client the (crashed/parked) clients will never send — so the main
                    // loop's next recv would hang forever (winlogon no longer CRASHES to trigger the
                    // old msgina-wall quiesce). QUIESCE to the gate. Gated on the msgina-crossed +
                    // LSA-signalled steady state so it never fires during live bring-up.
                    // Gate the terminal quiesce on winlogon having reached its SAS MESSAGE-LOOP milestone
                    // (WINLOGON_MSGLOOP_MILESTONE) in addition to the msgina + LSA steady state. Without
                    // this, a server listener parking races winlogon's post-InitializeSAS flow: it fires
                    // right after SetDefaultLanguage (SSN 224) and stops the loop before winlogon issues
                    // PostMessage(WLX_WM_SAS) / enters GetMessage. Requiring the message-loop milestone makes
                    // the quiesce deterministic — winlogon is parked at its genuine steady state first.
                    if WINLOGON_KEY_OPENED.load(Ordering::Relaxed) != 0
                        && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                        && WINLOGON_MSGLOOP_MILESTONE.load(Ordering::Relaxed) >= 2
                    {
                        print_str(b"[quiesce] server listener parked + winlogon parked at empty SAS message loop + LSA signalled -> steady state -> run gate\n");
                        stop = m0;
                        break;
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
                // ★ N-processes multiplex (BATCH 17): smss' (badge 0) main thread terminating must NOT
                // stop the whole boot while a HIGHER hosted process (winlogon) still has pending work.
                // smss reaches NtRaiseHardError (SSN 190) via SmpTerminate (smss.c:SmpTerminate ->
                // NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED) -> NtTerminateProcess) — its death
                // cry after it has finished spawning csrss + winlogon. In real NT smss then WAITS on the
                // subsystem handles; here its main thread is done its bring-up job. PARK it (recv next
                // WITHOUT replying, exactly like a server listener) so winlogon's user32 window-class /
                // cursor init keeps being serviced instead of freezing at its 0x103d fetch. Behavior-
                // preserving for smss (it was terminating regardless); unblocks the higher process. This
                // is the same class of fix as BATCH 10 (a terminal syscall from one process killed the
                // shared loop), generalized to smss' hard-error path.
                if badge == 0 && m0 == 190 {
                    print_str(b"[smss] NtRaiseHardError(190) = SmpTerminate -> PARK smss main; winlogon continues\n");
                    // Terminal for smss (its bring-up job is done) — count it toward quiesce so the
                    // loop can cleanly exit once every other live process is parked too.
                    crash_parked |= 1u64 << owner_top_badge(badge);
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
                if badge == WINLOGON_BADGE && m0 == 190 {
                    // DIAG (BATCH 21): winlogon's hard-error site — dump raw args while its mirror
                    // is active (ErrorStatus=R10, param0=[stack], caller=[rsp]).
                    print_str(b"[wl-190] R10=0x");
                    print_hex((get_recv_mr(9) >> 32) as u32);
                    print_hex(get_recv_mr(9) as u32);
                    print_str(b" RDX=0x");
                    print_hex(m3 as u32);
                    print_str(b" R8=0x");
                    print_hex(get_recv_mr(7) as u32);
                    print_str(b" sp=0x");
                    print_hex(get_recv_mr(16) as u32);
                    print_str(b" [sp]=0x");
                    print_hex(smss_stack_read(get_recv_mr(16)) as u32);
                    print_str(b"\n");
                }
                // An Nt* syscall we don't service yet AND can't safely fake a result for — the process
                // can't make progress. Record the SSN for the report line, then park+log this process
                // (unrecoverable for it) and let the shared loop keep servicing the others.
                stop_ssn = m0;
                park_and_log!(pi, b"unhandled-syscall", m0, m0);
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
            let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            if park_io_completion_port >= 0 && reply_main != 0 {
                if park_io_completion_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if io_completion_park(
                    &mut nt_handler,
                    park_io_completion_port as u32,
                    park_io_completion_key_out,
                    park_io_completion_apc_out,
                    park_io_completion_iosb_out,
                    park_io_completion_deadline.unwrap_or(u64::MAX),
                    resume_ip,
                    sp,
                    flags,
                ) {
                    delay_timer_rearm(&delay_queue);
                    print_str(b"[io-completion] pi=");
                    print_u64(pi as u64);
                    print_str(b" port=");
                    print_u64(park_io_completion_port as u64);
                    print_str(b" -> PARK remover\n");
                    let received = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = received.0;
                    mi = received.1;
                    m0 = received.2;
                    m1 = received.3;
                    m2 = received.4;
                    m3 = received.5;
                    continue;
                } else {
                    print_str(
                        b"[io-completion] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n",
                    );
                    result = 0xC000_009A;
                }
            }
            if let Some(deadline) = park_delay_deadline {
                if delay_park(
                    &mut delay_queue,
                    deadline,
                    reply_main,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    badge,
                ) {
                    if DELAY_PARKED_COUNT.load(Ordering::Relaxed) <= 16 {
                        print_str(b"[delay] PARKED badge=");
                        print_u64(badge);
                        print_str(b" tid=");
                        print_u64(nt_handler.current_tid);
                        print_str(b" queued=");
                        print_u64(delay_queue.len() as u64);
                        print_str(b" -> receive continues\n");
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let received = recv_full_r12(fault_ep, new_reply);
                    badge = received.0;
                    mi = received.1;
                    m0 = received.2;
                    m1 = received.3;
                    m2 = received.4;
                    m3 = received.5;
                    continue;
                }
                print_str(b"[delay] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                result = 0xC000_009A;
            }
            // Keyed-event wait park (`NtWaitForKeyedEvent`): used by ReactOS condition variables and
            // run-once state. The matching `NtReleaseKeyedEvent` wakes via keyed_wait_wake_one.
            if park_keyed_wait_key != u64::MAX && reply_main != 0 {
                if park_keyed_wait_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if keyed_wait_park(
                    park_keyed_wait_key,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    park_keyed_wait_deadline,
                ) {
                    delay_timer_rearm(&delay_queue);
                    print_str(b"[keyed] NtWaitForKeyedEvent key=0x");
                    print_hex_u64(park_keyed_wait_key);
                    print_str(b" -> PARK caller\n");
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let received = recv_full_r12(fault_ep, new_reply);
                    badge = received.0;
                    mi = received.1;
                    m0 = received.2;
                    m1 = received.3;
                    m2 = received.4;
                    m3 = received.5;
                    continue;
                } else {
                    print_str(b"[keyed] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            // Checkpoint B: PARK this caller on an unsignaled event (steal its reply cap into the waiter
            // queue keyed by the event, rotate REPLY_MAIN to a fresh pool object, recv the next event
            // WITHOUT replying). The matching NtSetEvent wakes it. If the pool/queue is exhausted,
            // wait_park returns false → fall through to a normal (immediate WAIT_0) reply, never a hang.
            // A winlogon worker that has started but has not yet created the SAS/status window is a
            // live signaler for the main thread's anonymous server-ready event. The historical
            // `WL_WORKER_FAULTS > 0` shortcut treated any serviced worker syscall as a terminal park
            // and stopped immediately after RegisterClassExWOW, before the runnable worker's next
            // timeslice. Park the main thread normally and keep servicing the worker instead.
            let winlogon_worker_can_signal = park_wait_event >= 0
                && pi == 2
                && badge == WINLOGON_BADGE
                && WL_WORKER2_TCB.load(Ordering::Relaxed) != 0
                && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) == 0;
            if park_wait_event >= 0 && reply_main != 0 {
                if park_wait_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if wait_park(
                    park_wait_event as usize,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    park_wait_deadline,
                ) {
                    delay_timer_rearm(&delay_queue);
                    // An INDEFINITE (no-deadline) wait by a top-level process is quiesce-relevant: if
                    // every live process is now parked, no signaler remains → run the gate. A
                    // deadline-bounded wait is timer-woken, so it never deadlocks — don't count it.
                    if winlogon_worker_can_signal {
                        WINLOGON_MAIN_EVENT_WAIT_PARKED.store(1, Ordering::Relaxed);
                        print_str(b"[wl-main] parked on worker-ready event; runnable worker remains a signaler\n");
                    } else if park_wait_deadline.is_none() && pi_is_top_level(badge) {
                        mark_wait_parked!(pi, resume_ip);
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                } else {
                    print_str(b"[wait] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            // Array-wait park (NtWaitForMultipleObjects): PARK on the resolved event SET (WaitAny/All).
            // The matching NtSetEvent (signal_state_changed → SetEvent(mgr_event)) wakes it via
            // dispatcher wake path, returning WAIT_0+index. Pool/queue exhaustion → immediate fallback.
            if park_wait_set_n > 0 && reply_main != 0 {
                if park_wait_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if wait_park_multi(
                    &park_wait_set[..park_wait_set_n],
                    &park_wait_indices[..park_wait_set_n],
                    park_wait_set_all,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    park_wait_deadline,
                ) {
                    delay_timer_rearm(&delay_queue);
                    print_str(b"[wait] pi=");
                    print_u64(pi as u64);
                    print_str(b" NtWaitForMultipleObjects(");
                    print_u64(park_wait_set_n as u64);
                    print_str(if park_wait_set_all { b" events, WaitAll) UNSIGNALLED -> PARK caller\n" } else { b" events, WaitAny) UNSIGNALLED -> PARK caller\n" });
                    if park_wait_deadline.is_none() && pi_is_top_level(badge) {
                        mark_wait_parked!(pi, resume_ip);
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                } else {
                    print_str(b"[wait] array park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            // BATCH 33 — PIPE-PENDING PARK: a real npfs pipe read / TRANSCEIVE returned STATUS_PENDING
            // (no data yet). Steal this caller's reply cap into the PipeWaiterTable keyed by the reading
            // end fid (rotate REPLY_MAIN to a fresh pool object), recv the next event WITHOUT replying —
            // the caller stays blocked in-kernel. A later peer write re-drives it (pipe_redrive_all).
            // Pool/table exhaustion returns STATUS_INSUFFICIENT_RESOURCES; returning PENDING without
            // retaining an owned IRP would leave both completion and ThreadIsIoPending inconsistent.
            if park_pipe_fid != 0 && reply_main != 0 {
                if pipe_wait_park(
                    park_pipe_fid,
                    pi as u32,
                    nt_handler.current_tid,
                    badge,
                    park_pipe_buffer_va,
                    park_pipe_buffer_len,
                    park_pipe_iosb_va,
                    park_pipe_transceive,
                    resume_ip,
                    sp,
                    flags,
                ) {
                    print_str(b"[pipe-park] badge=");
                    print_u64(badge);
                    print_str(b" fid=0x");
                    print_hex(park_pipe_fid as u32);
                    print_str(b" -> PARK reader (re-driven on peer write)\n");
                    // Quiesce accounting: a top-level process (winlogon) parked on a pipe read whose
                    // peer may never write is quiesce-relevant — if every live process is now parked
                    // (crash OR wait OR pipe) with no runnable signaler, break to the gate rather than
                    // block the loop's recv forever. A listener/worker sub-thread parking is NOT
                    // quiesce-relevant (its parent process may still run + write).
                    if pi_is_top_level(badge) {
                        // ★ BATCH 34 — the SCM server round-trip is now LIVE. winlogon's SCM-RPC read
                        // parking (recoverable, re-drivable) is NO LONGER terminal once its ncacn_np
                        // SERVER peer (services' SCM listener) has been connected: a client connect
                        // completed the server's async FSCTL_PIPE_LISTEN + signalled its event, so the
                        // svc-listener is a RUNNABLE (non-top-level, badge 7) signaler that will read the
                        // bind PDU and write bind_ack — which re-drives THIS parked read (batch-33 edge).
                        // The all-top-level-parked quiesce test does NOT see the runnable svc-listener, so
                        // marking winlogon parked here would falsely quiesce. So while the server is live
                        // (a listen was signalled), DON'T mark_wait_parked! (skip the immediate quiesce)
                        // — just continue the loop's recv: the runnable server produces events, and the
                        // 45s wall-clock progress watchdog still stops the loop cleanly if it truly stalls.
                        // The SCM server is LIVE only while its listener is signalled AND still running
                        // (not terminated). BATCH 35 routes the per-connection RPC worker into the
                        // multiplex, but until the worker's trampoline-entry fault is resolved (it PARKS
                        // unrecoverably — see the BATCH 35 frontier note) it is NOT a live signaler, so we
                        // do NOT treat a spawned-but-faulted worker as keeping the server live (that would
                        // hang the loop's recv with no signaler → boot timeout). Once the listener exits
                        // there is no signaler for winlogon's SCM read, so parking is terminal → quiesce.
                        let scm_server_live = pi == 2
                            && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                            && PIPE_LISTEN_SIGNALLED_COUNT.load(Ordering::Relaxed) != 0
                            && SVC_LISTENER_TERMINATED.load(Ordering::Relaxed) == 0
                            // BATCH 40: a PARKED listener (persistent-server world) is no longer a live
                            // signaler either — treat it like TERMINATED so winlogon's read-park becomes
                            // terminal and the boot quiesces (else the loop's recv hangs forever).
                            && SVC_LISTENER_PARKED.load(Ordering::Relaxed) == 0;
                        if !scm_server_live {
                            mark_wait_parked!(pi, resume_ip);
                            // Terminal backstop: winlogon's SCM read parking with NO live server signaler
                            // (no listen ever signalled, or the listener has exited) after LSA is signalled
                            // is its steady state — run the gate rather than block recv forever.
                            if pi == 2 && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0 {
                                print_str(b"[wl-main] winlogon SCM-RPC read parked (no live server signaler) + LSA signalled -> QUIESCE; run gate\n");
                                stop = resume_ip;
                                break;
                            }
                        } else {
                            // BATCH 43: only log on the FIRST 0→1 transition (this fires on every SCM read
                            // retry; serial writes dominate the TCG per-round-trip cost, and the boot budget
                            // is now tight with winlogon's heavier post-win32k-wall flow).
                            let first = WINLOGON_SCM_PARKED.swap(1, Ordering::Relaxed) == 0;
                            // BATCH 39 — defense-in-depth REASSERT of winlogon's client CLIENTINFO on the
                            // SCM-RPC read-park path (winlogon's LAST activity before its post-OpenSCManager
                            // GUI init calls user32 GetThreadDesktopWnd). win32k's IntSetThreadDesktop ELSE
                            // branch clears TEB.Win32ThreadInfo(+0x78)/pDeskInfo(+0x820); re-seed via the
                            // executive's persistent alias of winlogon's TEB frame. (The primary guarantee
                            // is the spawn seed + the fault-time repair; this keeps the window minimal.)
                            let _ = seed_winlogon_thread_client_info(
                                WINLOGON_MAIN_TEB_MIRROR_VA,
                                procs[2].pml4,
                            );
                            if first {
                                print_str(b"[wl-main] winlogon SCM-RPC read parked; SCM server LIVE (listener signalled + running) -> continue recv (server may write bind_ack)\n");
                            }
                        }
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                } else {
                    print_str(b"[pipe-park] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            let (nb, nmi, nm0, nm1, nm2, nm3) = if park_caller && reply_main != 0 {
                recv_full_r12(fault_ep, reply_main)
            } else if redirected_user_callback && reply_main != 0 {
                send_on_reply(reply_main, 0, 0, 0, 0, 0);
                recv_full_r12(fault_ep, reply_main)
            } else if (routed_win32k || routed_lpc || routed_csr) && reply_main != 0 {
                // Fix (B): this caller's syscall was serviced by the win32k component, whose faults
                // clobbered the executive's single `reply_to`. Resume csrss via its BOUND reply cap
                // (REPLY_MAIN, decode_reply -> apply_fault_reply) instead of the now-stale reply_to,
                // then recv the next event (re-binding REPLY_MAIN). Split reply+recv is equivalent to
                // the atomic reply_recv_badge — the executive is the sole replier.
                send_on_reply(reply_main, 18, result, m1, 0, m3);
                recv_full_r12(fault_ep, reply_main)
            } else {
                // Non-routed path: `reply_to` names this caller (never clobbered) — legacy reply.
                reply_recv_badge(fault_ep, 18, result, m1, 0, m3)
            };
            badge = nb;
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        // A non-VMFault, non-syscall fault (e.g. #GP) the loop can't service — unrecoverable. Park+log.
        park_and_log!(pi, b"other-fault", m1, m1);
    }
    // === Path 2 lifecycle self-test (POST-LOOP: no more per-syscall heap reset follows, so these
    // durable pm allocations are safe). Proves NtOpenProcess + NtTerminateProcess route through pm.
    // The 3 HOSTED EPROCESSes are left untouched — terminate runs on a THROWAWAY process. ===
    if ntdll.is_some() {
        // NtOpenProcess: smss (pi 0) opens csrss by pid → a real Process(csrss_pid) handle in smss's
        // EPROCESS table.
        nt_handler.pi = 0;
        let mut open_ok = 0u64;
        if let (Some(smss_pid), Some(csrss_pid)) =
            (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(1))
        {
            let object_attributes = nt_ntdll_layout::ObjectAttributes::default();
            let client_id = nt_ntdll_layout::ClientId {
                unique_process: csrss_pid as u64,
                unique_thread: 0,
            };
            if let Ok((owner, _)) = nt_handler.open_process_captured(
                object_attributes,
                Some(client_id),
                0x0400, // PROCESS_QUERY_INFORMATION
            ) {
                nt_handler.account_published_pm_handle(owner);
                open_ok |= 1;
            }
            if nt_handler
                .pm
                .close_handle_by_object(smss_pid, nt_process::HandleObject::Process(csrss_pid))
            {
                open_ok |= 2; // the opened handle really is in smss's table
            }
        }
        PM_NTOPENPROCESS_OK.store(open_ok, Ordering::Relaxed);

        // NtTerminateProcess: build a throwaway EPROCESS + thread + handle, then run the same policy
        // teardown the handler drives, and verify the process/thread are signalled + wait-able + the
        // handle table closes. Also verify the handler's ProcessHandle resolve (NtCurrentProcess→self).
        let mut life_ok = 0u64;
        let parent = nt_handler.pm_pid_for_pi(0);
        let tpid = nt_handler.pm.create_process("lifecycle-test.exe", parent, None);
        if let Ok(ttid) = nt_handler.pm.create_thread(tpid, 0x1000, 0, false) {
            let th = nt_handler
                .pm
                .insert_handle(tpid, nt_process::HandleObject::Opaque(0xDEAD), 0)
                .ok();
            nt_handler.pi = 0;
            if nt_handler.resolve_process_handle(0xFFFF_FFFF_FFFF_FFFF) == nt_handler.pm_pid_for_pi(0)
            {
                life_ok |= 1; // NtCurrentProcess() resolves to the caller
            }
            if nt_handler.pm.terminate_process(tpid, 0x1234).is_ok() {
                life_ok |= 2;
            }
            if nt_handler.pm.is_process_signaled(tpid) {
                life_ok |= 4;
            }
            if nt_handler.pm.is_thread_signaled(ttid) {
                life_ok |= 8; // teardown signalled the process's threads
            }
            if nt_handler.pm.wait_process(tpid) == Some(0x1234) {
                life_ok |= 16; // exit status readable via wait
            }
            if th.is_some_and(|h| nt_handler.pm.close_handle(tpid, h).is_ok()) {
                life_ok |= 32; // handle-table teardown
            }
        }
        PM_LIFECYCLE_OK.store(life_ok, Ordering::Relaxed);

        // BATCH 39 — direct NtTerminateThread MECHANISM self-test (throwaway EPROCESS + threads).
        // Drives the exact terminate path the handler uses (`resolve_terminate_thread_handle` +
        // `terminate_thread`/`exit_thread` + `can_reclaim_thread`) WITHOUT depending on any live
        // hosted-thread self-exit. This replaces the batch-38 live-lifecycle terminate specs: with
        // the SCM RPC succeeding (route ON), the SCM worker/listener PERSIST as servers instead of
        // self-exiting, so a live self-exit COUNT is no longer a stable invariant. Runs post-loop on
        // throwaway processes/threads only → the 5 hosted processes are untouched (byte-identical).
        {
            use nt_process::{HandleObject, ProcessState, ThreadState};
            const THREAD_TERMINATE: u32 = 0x0001;
            let mut term_ok = 0u64;
            let parent = nt_handler.pm_pid_for_pi(0);
            // Process A: two threads. `victim` is terminated via a typed Thread handle; `bystander`
            // must keep running (proves per-thread, not per-process, termination).
            let pa = nt_handler.pm.create_process("term-selftest-a.exe", parent, None);
            if let (Ok(victim), Ok(bystander)) = (
                nt_handler.pm.create_thread(pa, 0x2000, 0, false),
                nt_handler.pm.create_thread(pa, 0x3000, 0, false),
            ) {
                // A typed Thread handle with THREAD_TERMINATE resolves to the target tid.
                let hv = nt_handler
                    .pm
                    .insert_handle(pa, HandleObject::Thread(victim), THREAD_TERMINATE)
                    .ok();
                if let Some(hv) = hv {
                    if nt_handler.pm.resolve_terminate_thread_handle(
                        pa,
                        bystander,
                        hv as u64,
                        THREAD_TERMINATE,
                    ) == Ok(victim)
                    {
                        term_ok |= 0x01;
                    }
                }
                // A Thread handle WITHOUT THREAD_TERMINATE is rejected (access check enforced).
                if let Ok(hna) = nt_handler
                    .pm
                    .insert_handle(pa, HandleObject::Thread(victim), 0)
                {
                    if nt_handler
                        .pm
                        .resolve_terminate_thread_handle(pa, bystander, hna as u64, THREAD_TERMINATE)
                        .is_err()
                    {
                        term_ok |= 0x02;
                    }
                    let _ = nt_handler.pm.close_handle(pa, hna);
                }
                // The NULL/current pseudo-handle form (kernel32!ExitThread) resolves to the caller.
                if nt_handler
                    .pm
                    .resolve_terminate_thread_handle(pa, victim, 0, THREAD_TERMINATE)
                    == Ok(victim)
                {
                    term_ok |= 0x04;
                }
                // Terminate the victim: it becomes Terminated (signalled) with the exit status; the
                // bystander stays Ready and the EPROCESS is NOT cascaded (a live thread remains).
                if nt_handler.pm.terminate_thread(victim, 0xDEAD).is_ok()
                    && nt_handler
                        .pm
                        .thread(victim)
                        .is_some_and(|t| t.state == ThreadState::Terminated && t.exit_status == Some(0xDEAD))
                    && nt_handler.pm.is_thread_signaled(victim)
                    && nt_handler
                        .pm
                        .thread(bystander)
                        .is_some_and(|t| t.state != ThreadState::Terminated)
                    && nt_handler
                        .pm
                        .process(pa)
                        .is_some_and(|p| p.state == ProcessState::Running)
                {
                    term_ok |= 0x08;
                    term_ok |= 0x40; // the unrelated bystander thread continued
                }
                // TCB-reclaim gating: while a process handle still refers to the terminated victim it
                // must NOT be reclaimable (TID/slot aliasing hazard); after every such handle closes
                // it becomes reclaimable. Mirrors the handler's live TCB-reclaim guard.
                if let Some(hv) = hv {
                    let blocked = !nt_handler.pm.can_reclaim_thread(victim);
                    let _ = nt_handler.pm.close_handle(pa, hv);
                    if blocked && nt_handler.pm.can_reclaim_thread(victim) {
                        term_ok |= 0x10;
                    }
                }
            }
            // Process B: exercise the NO-CASCADE exit_thread path the handler uses for a process
            // whose OTHER threads keep it alive (the csrss "CSRSRV keeps us going" shape). The init
            // thread exits but a worker thread remains → the EPROCESS stays Running.
            let pb = nt_handler.pm.create_process("term-selftest-b.exe", parent, None);
            if let (Ok(init), Ok(_worker)) = (
                nt_handler.pm.create_thread(pb, 0x4000, 0, false),
                nt_handler.pm.create_thread(pb, 0x5000, 0, false),
            ) {
                if nt_handler.pm.exit_thread(init, 0x1).is_ok()
                    && nt_handler
                        .pm
                        .thread(init)
                        .is_some_and(|t| t.state == ThreadState::Terminated)
                    && nt_handler
                        .pm
                        .process(pb)
                        .is_some_and(|p| p.state == ProcessState::Running)
                {
                    term_ok |= 0x20;
                }
            }
            PM_TERMINATE_THREAD_SELFTEST.store(term_ok, Ordering::Relaxed);
        }

        // The hosted receive loop is finished and has no delay waiter outstanding. Disable timer 0
        // and unbind its notification so a stale HPET signal cannot intercept later self-test recvs.
        delay_timer_shutdown(&delay_queue);

        // Path 1b COUNTED SPEC — process-local dense handle VALUES. Two DISTINCT live EPROCESSes each
        // allocate their first handle and BOTH get the SAME dense value (0x4), yet it refers to a
        // DIFFERENT object in each: proof of per-process handle namespaces (a global value scheme
        // could not hand out 0x4 twice). Runs post-loop on throwaway EPROCESSes (durable allocs are
        // safe — no reset follows), leaving the 3 hosted processes untouched.
        let pa = nt_handler.pm.create_process("hlocal-a.exe", None, None);
        let pb = nt_handler.pm.create_process("hlocal-b.exe", None, None);
        let ha = nt_handler
            .pm
            .insert_handle(pa, nt_process::HandleObject::Opaque(0xA11CE), 0);
        let hb = nt_handler
            .pm
            .insert_handle(pb, nt_process::HandleObject::Opaque(0xB0B), 0);
        let mut hl_ok = 0u64;
        if ha == Ok(4) && hb == Ok(4) {
            hl_ok |= 1; // both processes' FIRST handle is the same dense value 0x4
        }
        if nt_handler.pm.lookup_handle(pa, 4) == Some(nt_process::HandleObject::Opaque(0xA11CE))
            && nt_handler.pm.lookup_handle(pb, 4) == Some(nt_process::HandleObject::Opaque(0xB0B))
        {
            hl_ok |= 2; // the SAME value 0x4 resolves to a DIFFERENT object in each namespace
        }
        if nt_handler.pm.lookup_handle(pa, 4) != nt_handler.pm.lookup_handle(pb, 4) {
            hl_ok |= 4; // no cross-process aliasing
        }
        PM_HANDLE_LOCAL_OK.store(hl_ok, Ordering::Relaxed);

        // ITEM 2b — prove the seL4 MECHANISM-teardown (reclamation) on a THROWAWAY untyped/caps.
        // Runs here (post-loop, live boot only) alongside the other lifecycle self-tests; it touches
        // ONLY freshly-retyped throwaway caps + an unused scratch page, deletes everything it makes,
        // and never touches the 3 hosted processes' resources → byte-identical boot.
        PM_RECLAIM_OK.store(reclaim_mechanism_selftest(), Ordering::Relaxed);
        // ALPC last-mile item (b) — prove a REAL cross-address-space ALPC section view: two SEPARATE
        // throwaway endpoint VSpaces map the same port-section backing frames (copy_cap + page_map,
        // the CSRSS_ANON_BASE machinery), a hosted thread in one writes big data, a hosted thread in
        // the other reads it back through ITS OWN view mapping. Throwaway-only + reclaimed after →
        // the 3 live hosted processes are untouched (byte-identical boot).
        ALPC_XVIEW_OK.store(alpc_cross_vspace_selftest(), Ordering::Relaxed);
    }
    if csrss_process_handle != 0 {
        print_str(b"[sec-stop] csrss (badge 2) spawned, handle 0x");
        print_hex(csrss_process_handle as u32);
        print_str(b"; demand-paged ");
        print_u64(procs[1].faults);
        print_str(b" page(s) (");
        print_u64(procs[1].ntfaults);
        print_str(b" in ntdll), first fault=0x");
        print_hex((procs[1].first >> 32) as u32);
        print_hex(procs[1].first as u32);
        print_str(b"\n");
    }
    print_str(b"[sec-stop] NEXT_SLOT=");
    print_u64(NEXT_SLOT.load(Ordering::Relaxed));
    print_str(b" shared_frames=");
    print_u64(core::ptr::read(core::ptr::addr_of!(DLL_CACHE_N)) as u64);
    print_str(b" shared_hits=");
    print_u64(DLL_SHARED_HITS.load(Ordering::Relaxed));
    print_str(b"\n[sec-stop] badge=");
    print_u64(badge);
    print_str(b" (");
    print_str(if badge == CSRSS_BADGE {
        b"csrss" as &[u8]
    } else if badge == WINLOGON_BADGE {
        b"winlogon"
    } else if badge == SERVICES_BADGE {
        b"services"
    } else {
        b"smss"
    });
    print_str(b") label=");
    print_u64(mi >> 12);
    print_str(b" m0=0x");
    print_hex((m0 >> 32) as u32);
    print_hex(m0 as u32);
    print_str(b" m1=0x");
    print_hex((m1 >> 32) as u32);
    print_hex(m1 as u32);
    print_str(b" exc#=");
    print_u64(m3);
    print_str(b" code=0x");
    print_hex(get_recv_mr(4) as u32);
    print_str(b" iters=");
    print_u64(iters);
    print_str(b" dbgsvc=");
    print_u64(dbgsvc);
    print_str(b" stop_ssn=");
    print_u64(stop_ssn);
    // Dump the last serviced SSNs in chronological order (oldest first).
    print_str(b" ssns:");
    let ring_n = if ssn_ri < 32 { 0 } else { ssn_ri - 32 };
    for k in ring_n..ssn_ri {
        print_str(b" ");
        print_u64(ssn_ring_badge[k % 32] as u64);
        print_str(b":");
        print_u64(ssn_ring[k % 32] as u64);
    }
    // winlogon-main-only SSN sequence (badge 4), oldest first — isolates the StartLsass wall.
    print_str(b"\n[wl-ring]");
    let wl_n = if wl_ri < 48 { 0 } else { wl_ri - 48 };
    for k in wl_n..wl_ri {
        print_str(b" ");
        print_u64(wl_ring[k % 48] as u64);
    }
    // NtWriteVirtualMemory(287) diagnostic: dump the args + scan the caller's stack for smss/ntdll
    // return addresses to identify which routine issued it (RtlCreateUserProcess param-inject?).
    if stop_ssn == 287 {
        let sp = get_recv_mr(16);
        print_str(b"\n[287] proc=0x");
        print_hex(get_recv_mr(9) as u32); // R10 ProcessHandle
        print_str(b" base=0x");
        print_hex((m3 >> 32) as u32);
        print_hex(m3 as u32); // RDX BaseAddress
        print_str(b" buf=0x");
        print_hex((get_recv_mr(7) >> 32) as u32);
        print_hex(get_recv_mr(7) as u32); // R8 Buffer
        print_str(b" size=0x");
        print_hex(get_recv_mr(8) as u32); // R9 Size
        print_str(b" written*=0x");
        print_hex(smss_stack_read(sp + 0x28) as u32);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..160u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" n+0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
            } else if v >= PE_LOAD_BASE && v < PE_LOAD_BASE + 0x40000 {
                // smss image
                print_str(b" s+0x");
                print_hex((v - PE_LOAD_BASE) as u32);
                shown += 1;
            }
            if shown >= 16 {
                break;
            }
        }
    }
    // NtRaiseHardError(190): decode the status (R10), Parameters[0], and the caller ([rsp]).
    // Guarded to this case — get_recv_mr(16)/(8) only hold a valid smss stack ptr here.
    if stop_ssn == 190 {
        print_str(b" r10=0x");
        print_hex((get_recv_mr(9) >> 32) as u32);
        print_hex(get_recv_mr(9) as u32);
        print_str(b" param0=0x");
        print_hex(smss_stack_read(get_recv_mr(8)) as u32);
        print_str(b" caller=0x");
        print_hex(smss_stack_read(get_recv_mr(16)) as u32);
        // Scan the stack for ntdll AND kernel32 return addresses to reconstruct the call chain that
        // produced the failure status (winlogon's CreateProcessW hard-error path is kernel32 code).
        let sp = get_recv_mr(16);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..160u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" n+0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
            } else if v >= 0x803a0000 && v < 0x803a0000 + 0x2b0000 {
                print_str(b" k32+0x");
                print_hex((v - 0x803a0000) as u32);
                shown += 1;
            }
            if shown >= 20 {
                break;
            }
        }
    }
    print_str(b"\n");
    if ntdll.is_some() {
        loader_trace_dump(&reg);
    }
    // Record winlogon's (slot 2) demand-fault count for the spec check + report line.
    WINLOGON_FAULTS.store(procs[2].faults, Ordering::Relaxed);
    print_str(b"[ntos-exec] winlogon (slot 2) demand-faulted ");
    print_u64(procs[2].faults);
    print_str(b" page(s), first=0x");
    print_hex((procs[2].first >> 32) as u32);
    print_hex(procs[2].first as u32);
    print_str(b"\n");
    // Record services.exe's (slot 3) demand-fault count for the milestone spec + report line.
    SERVICES_FAULTS.store(procs[3].faults, Ordering::Relaxed);
    print_str(b"[ntos-exec] services (slot 3) demand-faulted ");
    print_u64(procs[3].faults);
    print_str(b" page(s), first=0x");
    print_hex((procs[3].first >> 32) as u32);
    print_hex(procs[3].first as u32);
    print_str(b"\n");
    LSASS_FAULTS.store(procs[4].faults, Ordering::Relaxed);
    print_str(b"[ntos-exec] lsass (slot 4) demand-faulted ");
    print_u64(procs[4].faults);
    print_str(b" page(s), first=0x");
    print_hex((procs[4].first >> 32) as u32);
    print_hex(procs[4].first as u32);
    print_str(b"\n");
    // Path 3: record that each folded per-process ProcExec is EPROCESS-linked (live pml4 + its pid
    // matches the ProcessManager's pid for that pi). Read by `exec_eprocess_linked_mechanism`.
    let mut link_ok = 0u64;
    for (i, p) in procs.iter().enumerate() {
        if p.pml4 != 0 && p.pid != 0 && nt_handler.pm_pid_for_pi(i).map(|pid| pid as u64) == Some(p.pid)
        {
            link_ok |= 1 << i;
        }
    }
    PM_EXEC_LINK_OK.store(link_ok, Ordering::Relaxed);
    // Report smss's (slot 0) own fault stats regardless of which process stopped the loop — csrss
    // (slot 1) commonly halts it now that it runs, and the caller's "smss faulted N" line + the
    // exec_reactos_smss_* checks are about smss specifically. csrss's counts are in the sec-stop line.
    (verdict, procs[0].faults, procs[0].first, stop, procs[0].ntfaults, stop_ssn)
}

#[inline(never)]
unsafe fn spawn_requested_tp_worker(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    worker_slot: usize,
    pml4: u64,
    caller_sp: u64,
    fault_ep: u64,
) {
    if TP_WORKER_TCB[pi][worker_slot]
        .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let context_va = smss_stack_read(caller_sp + 0x30);
    let start = nt_thread_start::Amd64ThreadContext::read(
        |address| unsafe { smss_stack_read(address) },
        context_va,
    );
    let tid = TP_WORKER_TID[pi][worker_slot].load(Ordering::Relaxed);
    let cid_proc = nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64;
    let suspended = runtime_thread_slot(tid).is_some_and(|(pool_pi, slot)| {
        pool_pi == pi && PM_POOL_SUSPENDED[pool_pi].load(Ordering::Relaxed) & (1 << slot) != 0
    });
    let tcb = spawn_tp_worker_thread(
        pi,
        worker_slot,
        pml4,
        start,
        cid_proc,
        tid,
        fault_ep,
        !suspended,
    );
    TP_WORKER_TCB[pi][worker_slot].store(tcb, Ordering::Relaxed);
    nt_handler.pm.set_thread_teb(tid as nt_process::ThreadId, tp_worker_teb_va(worker_slot));

    print_str(b"[tp-worker] spawned pi=");
    print_u64(pi as u64);
    print_str(b" badge=");
    print_u64(tp_worker_badge(pi, worker_slot));
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    if worker_slot != 0 {
        print_str(b" slot=");
        print_u64(worker_slot as u64);
    }
    print_str(if suspended {
        b" suspended; NtResumeThread owns first run\n"
    } else {
        b" resumed into generic multiplex\n"
    });
}

/// BATCH 33 — the (stack_base, stack_size, stack_mirror_va, heap_mirror_va, image_mirror_va) for the
/// thread identified by `badge` (its per-thread stack + its process's heap/image mirror windows). This
/// is the SAME selection the main service loop makes at each iteration (`service_sec_image` ~585-650);
/// the pipe re-drive reuses it to point the copyout helpers (`smss_copyout` via `xas_write_buf`) at a
/// PARKED reader's own VSpace mirrors while the WRITER is the active process. `pi` = the reader's
/// process index (0 smss, 1 csrss, 2 winlogon, 3 services, 4 lsass).
#[inline]
fn mirror_ctx_for(badge: u64, pi: usize) -> (u64, u64, u64, u64, u64) {
    let (stack_base, stack_frames, stack_mirror) = if let Some((tp_pi, tp_slot)) =
        tp_worker_identity_from_badge(badge)
    {
        debug_assert_eq!(tp_pi, pi);
        (
            tp_worker_stack_base(tp_slot),
            TP_WORKER_STACK_FRAMES,
            tp_worker_stack_mirror_va(tp_pi, tp_slot),
        )
    } else {
        match badge {
            SVC_LISTENER_BADGE => (
                SVC_LISTENER_STACK_BASE,
                SVC_LISTENER_STACK_FRAMES,
                SVC_LISTENER_STACK_MIRROR_VA,
            ),
            SCM_WORKER_BADGE => (
                SCM_WORKER_STACK_BASE,
                SCM_WORKER_STACK_FRAMES,
                SCM_WORKER_STACK_MIRROR_VA,
            ),
            LSASS_LISTENER_BADGE => (
                LSASS_LISTENER_STACK_BASE,
                LSASS_LISTENER_STACK_FRAMES,
                LSASS_LISTENER_STACK_MIRROR_VA,
            ),
            LSASS_LISTENER2_BADGE => (
                LSASS_LISTENER2_STACK_BASE,
                LSASS_LISTENER2_STACK_FRAMES,
                LSASS_LISTENER2_STACK_MIRROR_VA,
            ),
            LSASS_LISTENER3_BADGE => (
                LSASS_LISTENER3_STACK_BASE,
                LSASS_LISTENER3_STACK_FRAMES,
                LSASS_LISTENER3_STACK_MIRROR_VA,
            ),
            WINLOGON_WORKER2_BADGE => (
                WL_WORKER2_STACK_BASE,
                WL_WORKER2_STACK_FRAMES,
                WINLOGON_WORKER2_STACK_MIRROR_VA,
            ),
            WINLOGON_WORKER3_BADGE => (
                WL_WORKER3_STACK_BASE,
                WL_WORKER3_STACK_FRAMES,
                WINLOGON_WORKER3_STACK_MIRROR_VA,
            ),
            WINLOGON_WORKER_BADGE => (
                WL_LISTENER_STACK_BASE,
                WL_LISTENER_STACK_FRAMES,
                WINLOGON_WORKER_STACK_MIRROR_VA,
            ),
            _ => {
                // A top-level process MAIN thread — keyed by pi like the loop's default arm.
                let smv = match pi {
                    1 => CSRSS_STACK_MIRROR_VA,
                    2 => WINLOGON_STACK_MIRROR_VA,
                    3 => SERVICES_STACK_MIRROR_VA,
                    4 => LSASS_STACK_MIRROR_VA,
                    _ => SMSS_STACK_MIRROR_VA,
                };
                (STACK_BASE, STACK_FRAMES, smv)
            }
        }
    };
    let heap_mirror = match pi {
        1 => CSRSS_HEAP_MIRROR_VA,
        2 => WINLOGON_HEAP_MIRROR_VA,
        3 => SERVICES_HEAP_MIRROR_VA,
        4 => LSASS_HEAP_MIRROR_VA,
        _ => SMSS_HEAP_MIRROR_VA,
    };
    let image_mirror = match pi {
        1 => CSRSS_IMAGE_MIRROR_VA,
        2 => WINLOGON_IMAGE_MIRROR_VA,
        3 => SERVICES_IMAGE_MIRROR_VA,
        4 => LSASS_IMAGE_MIRROR_VA,
        _ => IMAGE_MIRROR_VA,
    };
    (stack_base, stack_frames * 0x1000, stack_mirror, heap_mirror, image_mirror)
}

unsafe fn io_completion_park(
    nt_handler: &mut ExecNtHandler,
    port_id: u32,
    key_context_out: u64,
    apc_context_out: u64,
    io_status_block_out: u64,
    deadline_100ns: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> bool {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return false;
    }
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    let Some((fresh_index, fresh)) = (0..WAIT_REPLY_POOL_N).find_map(|index| {
        let cap = WAIT_REPLY_POOL[index].load(Ordering::Relaxed);
        (used & (1u64 << index) == 0 && cap != 0).then_some((index, cap))
    }) else {
        return false;
    };
    if nt_handler.io_completion_ports.retain(port_id).is_err() {
        return false;
    }
    let mut waiter = nt_io_completion::CompletionWaiter::default();
    waiter.port_id = port_id;
    waiter.process_index = nt_handler.pi as u8;
    waiter.reply_cap = stolen;
    waiter.resume_ip = resume_ip;
    waiter.resume_sp = sp;
    waiter.resume_flags = flags;
    waiter.thread_id = nt_handler.current_tid;
    waiter.badge = nt_handler.current_badge;
    waiter.key_context_out = key_context_out;
    waiter.apc_context_out = apc_context_out;
    waiter.io_status_block_out = io_status_block_out;
    waiter.deadline_100ns = deadline_100ns;
    if unsafe { (&mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS)).insert(waiter) }.is_err() {
        let _ = nt_handler.io_completion_ports.release(port_id);
        return false;
    }
    WAIT_REPLY_POOL_USED.fetch_or(1u64 << fresh_index, Ordering::Relaxed);
    REPLY_MAIN_SLOT.store(fresh, Ordering::Relaxed);
    IO_COMPLETION_PARKED_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

unsafe fn io_completion_deliver(nt_handler: &mut ExecNtHandler) -> bool {
    let Some((waiter, packet)) = nt_handler.io_completion_wake.take() else {
        return false;
    };
    let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
    let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
    let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx.take();

    let (stack_base, stack_size, stack_mirror, heap_mirror, image_mirror) =
        mirror_ctx_for(waiter.badge, waiter.process_index as usize);
    ACTIVE_STACK_BASE.store(stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(image_mirror, Ordering::Relaxed);
    nt_handler.pi = waiter.process_index as usize;

    let copied = nt_handler
        .xas_try_write_buf(waiter.apc_context_out, &packet.apc_context.to_le_bytes())
        && nt_handler.xas_try_write_buf(waiter.key_context_out, &packet.key_context.to_le_bytes())
        && nt_handler.xas_try_write_buf(waiter.io_status_block_out, &packet.status.to_le_bytes())
        && nt_handler.xas_try_write_buf(
            waiter.io_status_block_out + 8,
            &packet.information.to_le_bytes(),
        );

    ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;

    set_reply_mr(15, waiter.resume_ip);
    set_reply_mr(16, waiter.resume_sp);
    set_reply_mr(17, waiter.resume_flags);
    send_on_reply(
        waiter.reply_cap,
        18,
        if copied { 0 } else { 0xC000_0005 },
        0,
        0,
        0,
    );
    release_reply_pool_cap(waiter.reply_cap);
    let _ = nt_handler.io_completion_ports.release(waiter.port_id);
    IO_COMPLETION_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// BATCH 33 — PARK a caller whose npfs pipe read returned STATUS_PENDING. Mirrors the event
/// `wait_park_multi` reply-cap steal EXACTLY (steal the active REPLY_MAIN, rotate a fresh pool object
/// into REPLY_MAIN so the next recv binds a new object), but records the wait in the PipeWaiterTable
/// keyed by the reading end's npfs file-id instead of an obj_ns event index. Returns true on success;
/// false if the pool or the waiter table is exhausted (caller then returns PENDING directly — degraded
/// but never a hang). The stolen cap resumes the blocked thread when the peer writes (`pipe_redrive_all`).
unsafe fn pipe_wait_park(
    file_id: u64,
    pi: u32,
    tid: u64,
    badge: u64,
    buffer_va: u64,
    buffer_len: u32,
    iosb_va: u64,
    is_transceive: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> bool {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return false;
    }
    // Find a FREE pool object to become the new active REPLY_MAIN (same rotation as wait_park_multi).
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    let mut fresh = 0u64;
    let mut fresh_bit = 0usize;
    for i in 0..WAIT_REPLY_POOL_N {
        if used & (1u64 << i) == 0 {
            let cp = WAIT_REPLY_POOL[i].load(Ordering::Relaxed);
            if cp != 0 {
                fresh = cp;
                fresh_bit = i;
                break;
            }
        }
    }
    if fresh == 0 {
        return false; // pool exhausted → caller returns PENDING directly
    }
    let table = &mut *core::ptr::addr_of_mut!(PIPE_WAITERS);
    let parked = table.park(nt_io_manager::PipeWaiter {
        file_id,
        pi,
        tid,
        badge,
        buffer_va,
        buffer_len,
        iosb_va,
        reply_cap: stolen,
        resume_ip,
        resume_sp: sp,
        resume_flags: flags,
        is_transceive,
    });
    if parked.is_none() {
        return false; // table exhausted → caller returns PENDING directly
    }
    // Commit the reply-cap rotation only after the waiter is recorded.
    WAIT_REPLY_POOL_USED.fetch_or(1u64 << fresh_bit, Ordering::Relaxed);
    REPLY_MAIN_SLOT.store(fresh, Ordering::Relaxed);
    PIPE_WAIT_PARKED_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// BATCH 33 — RE-DRIVE every parked pipe read after a peer write. The executive has no peer→reader
/// map (npfs pairs the two ends internally by name), so on ANY completed pipe write we re-issue EVERY
/// parked read against npfs: npfs's own FCB pairing makes the reader whose peer just wrote return data
/// (non-PENDING) while the others stay PENDING. For each reader that now has bytes we copy them into
/// its buffer + fill its IOSB (through ITS OWN VSpace mirrors — switched in for the copyout, since the
/// active process is the WRITER, then restored) and reply to its stolen reply cap (restoring its
/// native-syscall resume context, exactly like the event wake), then free the slot. Idempotent: a read
/// still PENDING leaves the waiter parked (re-armable for the next PDU / write). Returns woken count.
unsafe fn pipe_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    let transport_capacity = (driver_launch::FSD_ARG_FRAMES * 0x1000) as usize;
    // Snapshot the active-mirror context + handler identity so we can restore after each re-drive.
    let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
    let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
    let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx.take(); // copyout via mirrors only during the re-drive
    let mut woken = 0u64;
    let table = &*core::ptr::addr_of!(PIPE_WAITERS);
    let snapshot: alloc::vec::Vec<(usize, nt_io_manager::PipeWaiter)> = table.drain_all().collect();
    for (slot, w) in snapshot {
        // Re-issue this reader's read against npfs; if still PENDING, leave it parked.
        let want = (w.buffer_len as usize).min(transport_capacity).max(1);
        let mut output = alloc::vec![0u8; want];
        // BATCH 37: FIRST check for a completed-pending-read stash for this fid. When this reader's
        // original read went PENDING, npfs retained the read IRP; the peer WRITE already completed it
        // (copying the payload into THAT IRP) — so a fresh re-drive read would find the queue drained
        // and return garbage/PENDING. `take_completed_read` hands back the exact bytes npfs delivered
        // to the pending read IRP (this is how the rpcrt4 worker gets winlogon's bind PDU).
        let (status, completed) = if let Some((st, info, bytes)) =
            driver_launch::take_completed_read(w.file_id)
        {
            let n = (bytes.len()).min(output.len());
            output[..n].copy_from_slice(&bytes[..n]);
            (st, info)
        } else {
            match nt_handler.npfs_route_raw(
                major::IRP_MJ_READ as u64,
                0,
                w.file_id,
                &[],
                &mut output,
            ) {
                Some((st, info, _)) => (st as u32, info),
                None => continue,
            }
        };
        if status == 0x0000_0103 {
            continue; // still PENDING → stays parked (re-armable)
        }
        // Data (or a terminal status) available. Point the copyout at the READER's VSpace mirrors.
        let (sb, ss, smv, hmv, imv) = mirror_ctx_for(w.badge, w.pi as usize);
        ACTIVE_STACK_BASE.store(sb, Ordering::Relaxed);
        ACTIVE_STACK_SIZE.store(ss, Ordering::Relaxed);
        ACTIVE_STACK_MIRROR.store(smv, Ordering::Relaxed);
        ACTIVE_HEAP_MIRROR.store(hmv, Ordering::Relaxed);
        ACTIVE_IMAGE_MIRROR.store(imv, Ordering::Relaxed);
        nt_handler.pi = w.pi as usize;
        let copy_len = (completed as usize).min(output.len());
        // BATCH 37: copy the delivered bytes for SUCCESS *and* STATUS_BUFFER_OVERFLOW (0x80000005) —
        // a message-mode read of a message larger than the buffer returns the partial bytes WITH
        // overflow (rpcrt4 reads the 16-byte common header of a 72-byte bind PDU this way, then reads
        // the remainder). Gating the copyout on `status == 0` left the reader's buffer zeroed on
        // overflow, so rpcrt4's RPCRT4_ValidateCommonHeader saw an all-zero header and failed. Only a
        // hard error / PENDING leaves the buffer untouched.
        if (status == 0 || status == 0x8000_0005) && copy_len != 0 && w.buffer_va != 0 {
            nt_handler.xas_write_buf(w.buffer_va, &output[..copy_len]);
        }
        if w.iosb_va != 0 {
            nt_handler.xas_write_buf(w.iosb_va, &status.to_le_bytes());
            nt_handler.xas_write_buf(w.iosb_va + 8, &(completed as u64).to_le_bytes());
        }
        // Wake the blocked thread on its stolen reply cap — restore RCX/RSP/RFLAGS (MR15/16/17) and
        // return `status` in MR0 (→ RAX/r10), exactly like the event wake.
        let cap = w.reply_cap;
        if cap != 0 {
            set_reply_mr(15, w.resume_ip);
            set_reply_mr(16, w.resume_sp);
            set_reply_mr(17, w.resume_flags);
            send_on_reply(cap, 18, status as u64, 0, 0, 0);
            release_reply_pool_cap(cap);
        }
        // Free the slot (re-armable for the next PDU).
        let table_mut = &mut *core::ptr::addr_of_mut!(PIPE_WAITERS);
        table_mut.complete(slot);
        woken += 1;
        PIPE_WAIT_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
        if PIPE_REDRIVE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 16 {
            print_str(b"[pipe-redrive] WOKE reader fid=0x");
            print_hex(w.file_id as u32);
            print_str(b" pi=");
            print_u64(w.pi as u64);
            print_str(b" badge=");
            print_u64(w.badge);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b" bytes=");
            print_u64(completed);
            print_str(b"\n");
        }
    }
    // Restore the writer's active-mirror context + handler identity.
    ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;
    woken
}

/// BATCH 34 — complete the pending async server `FSCTL_PIPE_LISTEN` matching `name_hash` after a
/// client CONNECT to that same pipe name. The ncacn_np rpcrt4 SERVER posted an OVERLAPPED
/// FSCTL_PIPE_LISTEN (STATUS_PENDING, no client) with a completion EVENT, then parked on
/// `NtWaitForMultipleObjects([mgr_event, listen_event])`. The client just connected (npfs paired the
/// ends by name), so ONE matching pending listen is now satisfied: fill its listen IOSB
/// `{Status=SUCCESS, Information=0}` in the SERVER's VSpace (switch in the listener's mirror context
/// for the copyout, then restore) and signal its completion event via the shared dispatcher wake path
/// NtSetEvent wake path — waking the server's wait-array so it reads the client's first PDU (the bind).
/// Name-scoped so a `\ntsvcs` connect never wakes `\lsarpc`/`\samr` (which would spin their rpcrt4
/// accept loop). Returns 1 if a listen was completed, else 0. Re-armable: rpcrt4 re-posts a fresh
/// FSCTL_PIPE_LISTEN for the next client (a NEW record). Completes ONE listen per connect (one client).
unsafe fn pipe_listen_complete_named(nt_handler: &mut ExecNtHandler, name_hash: u64) -> u64 {
    // Find the matching pending listen (name-scoped); take it (consumed once per client connect).
    let l = {
        let table_mut = &mut *core::ptr::addr_of_mut!(PIPE_ASYNC_LISTENS);
        match table_mut.complete_by_name(name_hash) {
            Some(l) => l,
            None => return 0,
        }
    };
    let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
    let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
    let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx.take();
    let mut completed = 0u64;
    {
        // Point the IOSB copyout at the SERVER listener's VSpace mirrors.
        let badge = l.badge;
        let (sb, ss, smv, hmv, imv) = mirror_ctx_for(badge, l.pi as usize);
        ACTIVE_STACK_BASE.store(sb, Ordering::Relaxed);
        ACTIVE_STACK_SIZE.store(ss, Ordering::Relaxed);
        ACTIVE_STACK_MIRROR.store(smv, Ordering::Relaxed);
        ACTIVE_HEAP_MIRROR.store(hmv, Ordering::Relaxed);
        ACTIVE_IMAGE_MIRROR.store(imv, Ordering::Relaxed);
        nt_handler.pi = l.pi as usize;
        // Fill the listen IO_STATUS_BLOCK: {Status=STATUS_SUCCESS, Information=0}.
        if l.iosb_va != 0 {
            nt_handler.xas_write_buf(l.iosb_va, &0u32.to_le_bytes());
            nt_handler.xas_write_buf(l.iosb_va + 8, &0u64.to_le_bytes());
        }
        // SIGNAL the overlapped completion event → wakes the server's NtWaitForMultipleObjects. Reuse
        // the exact NtSetEvent wake path: set the event's `signalled` flag then reevaluate waiters.
        if l.event_obj_idx != u64::MAX {
            let idx = l.event_obj_idx as usize;
            let _ = nt_handler.events.set_existing(idx as u64);
            let woken = wait_wake_dispatcher_set(nt_handler);
            if PIPE_LISTEN_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 16 {
                print_str(b"[pipe-listen] COMPLETE server fid=0x");
                print_hex(l.server_file_id as u32);
                print_str(b" signalled event_obj=0x");
                print_hex(idx as u32);
                print_str(b" -> woke ");
                print_u64(woken);
                print_str(b" server wait(s)\n");
            }
        }
        completed += 1;
        PIPE_LISTEN_SIGNALLED_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;
    completed
}

unsafe fn ensure_client_copyin_dll_page(
    pi: u64,
    page: u64,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
) -> bool {
    if csrss_frame_get(pi, page) != 0 || client_copyin_frame_get(pi, page) != 0 {
        return true;
    }
    let Some((i, rva)) = reg.dll_for_page(page) else {
        return false;
    };
    let Some(slot) = dll_pes.get(i) else {
        return false;
    };
    let Some(tpe) = (*slot).as_ref() else {
        return false;
    };
    let prefetch_index = core::ptr::read(core::ptr::addr_of!(CLIENT_COPYIN_FRAME_N))
        .min(CLIENT_COPYIN_FRAME_CAP);
    if prefetch_index == CLIENT_COPYIN_FRAME_CAP {
        return false;
    }
    // Reserve the high end of each process scratch window for bounded copy-in prefetches. Demand
    // fills are capped below this range, so every prefetched page keeps a distinct live alias.
    let alias = scratch_base + DEMAND_SCRATCH_WINDOW - (prefetch_index as u64 + 3) * 0x1000;
    let (frame, fe) = alloc_frame_r();
    let se = page_map_r(frame, alias, RW_NX, CAP_INIT_THREAD_VSPACE);
    if fe != 0 || se != 0 {
        return false;
    }
    let _ = fill_image_page(tpe, rva, alias);
    client_copyin_frame_put(pi, page, frame, alias);
    true
}

unsafe fn prefill_client_large_string_pages(
    pi: u64,
    descriptor_va: u64,
    scratch_base: u64,
    faults: &mut u64,
    filled_pages: &mut [u64; 512],
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
) {
    let mut raw = [0u8; 16];
    if !img_spawn::client_copyin_mapped(
        pi,
        descriptor_va,
        &mut raw,
        filled_pages,
        *faults as usize,
        scratch_base,
    ) {
        return;
    }
    let Ok(descriptor) = nt_user_callback::LargeUnicodeStringDescriptor::parse(&raw) else {
        return;
    };
    let mut offset = 0usize;
    let length = descriptor.length_bytes as usize;
    let mut last_page = u64::MAX;
    while offset < length {
        let current = descriptor.buffer + offset as u64;
        let page = current & !0xfffu64;
        if page != last_page {
            let _ = ensure_client_copyin_dll_page(
                pi,
                page,
                scratch_base,
                reg,
                dll_pes,
            );
            last_page = page;
        }
        let page_remaining = 0x1000usize - (current as usize & 0xfff);
        offset += page_remaining.min(length - offset);
    }
}

/// Map any fault badge to the TOP-LEVEL process badge that owns it (a listener/worker thread's
/// crash belongs to its parent process for quiesce accounting). Top-level: smss=0, csrss=2,
/// winlogon=4, services=6, lsass=8.
#[inline]
fn owner_top_badge(badge: u64) -> u64 {
    if let Some((pi, _)) = tp_worker_identity_from_badge(badge) {
        return match pi {
            1 => CSRSS_BADGE,
            2 => WINLOGON_BADGE,
            3 => SERVICES_BADGE,
            4 => LSASS_BADGE,
            _ => 0,
        };
    }
    match badge {
        CSRSS_BADGE => CSRSS_BADGE,
        WINLOGON_BADGE | WINLOGON_WORKER_BADGE | WINLOGON_WORKER2_BADGE | WINLOGON_WORKER3_BADGE => {
            WINLOGON_BADGE
        }
        SERVICES_BADGE | SVC_LISTENER_BADGE | SCM_WORKER_BADGE => SERVICES_BADGE,
        LSASS_BADGE | LSASS_LISTENER_BADGE | LSASS_LISTENER2_BADGE | LSASS_LISTENER3_BADGE => {
            LSASS_BADGE
        }
        _ => 0, // smss (badge 0) + anything else
    }
}

/// A top-level process badge (its MAIN thread), not a listener/worker sub-thread. Only a top-level
/// process's indefinite wait is quiesce-relevant (a sub-thread listener parks cooperatively but its
/// parent process may still run).
#[inline]
fn pi_is_top_level(badge: u64) -> bool {
    matches!(
        badge,
        0 | CSRSS_BADGE | WINLOGON_BADGE | SERVICES_BADGE | LSASS_BADGE
    )
}

/// The bitmask of LIVE top-level process badges (smss is always live; the rest once SPAWNED).
/// Used by the quiesce test: the boot has no forward progress possible once every live top-level
/// process is crash-parked (so the loop's next `recv` would block on the fault-EP forever).
#[inline]
unsafe fn live_top_badges() -> u64 {
    let mut m = 1u64 << 0; // smss always live
    if CSRSS_SPAWNED.load(Ordering::Relaxed) == 1 {
        m |= 1u64 << CSRSS_BADGE;
    }
    if WINLOGON_SPAWNED.load(Ordering::Relaxed) == 1 {
        m |= 1u64 << WINLOGON_BADGE;
    }
    if SERVICES_SPAWNED.load(Ordering::Relaxed) == 1 {
        m |= 1u64 << SERVICES_BADGE;
    }
    if LSASS_SPAWNED.load(Ordering::Relaxed) == 1 {
        m |= 1u64 << LSASS_BADGE;
    }
    m
}
