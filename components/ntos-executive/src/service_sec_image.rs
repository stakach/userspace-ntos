//! `service_sec_image` — the per-process SEC_IMAGE demand-fault service loop.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

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
    let mut first = 0u64;
    let mut stop = 0u64;
    let mut ntfaults = 0u64;
    let mut stop_ssn = 0u64;
    let mut iters = 0u64;
    let mut dbgsvc = 0u64;
    // page VA filled at each fault index → its persistent executive scratch is
    // scratch_base + index*0x1000. Lets a syscall handler copy OUT to any already-mapped image
    // page (e.g. an ntdll .data global), not just the stack (which has its own mirror).
    // Working buffer for the current pi's demand-filled page VAs — a STATIC (not a 2 KiB stack local)
    // so the 5th hosted process doesn't overflow the 16 KiB rootserver stack on the deep FS-walk call
    // chain (see FILLED_WORK). Loaded from / saved to `pfilled[pi]` around each dispatch below.
    let filled_pages: &mut [u64; 256] = &mut *core::ptr::addr_of_mut!(FILLED_WORK);
    // DIAG ring buffer of the last serviced SSNs, to locate the silent 0x80000005.
    let mut ssn_ring = [0u16; 32];
    let mut ssn_ring_badge = [0u8; 32];
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
    // pre-reserved key_handles buffer) is allocated. Each smss syscall we service allocates
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
    // Per-process demand-fill bookkeeping — kept in a `static mut` (3×2 KiB) rather than on the
    // 16 KiB rootserver stack (a [[u64;256];3] local + the loop's other arrays would risk the guard
    // page — the recurring stack-array-overflow hazard). service_sec_image runs once for the live
    // run; zero it at entry so the demo call (ntdll=None) starts clean too.
    let pfilled: &mut [[u64; 256]; MAX_PI] = &mut *core::ptr::addr_of_mut!(PFILLED);
    for p in pfilled.iter_mut() {
        for e in p.iter_mut() {
            *e = 0;
        }
    }
    // Fix (B): the INITIAL recv also binds REPLY_MAIN (r12) so the first caller's Call is captured
    // as a reply cap, matching every reply_recv_badge recv in the loop body.
    let (mut badge, mut mi, mut m0, mut m1, mut m2, mut m3) =
        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
    loop {
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
            delay_timer_interrupt(&mut delay_queue);
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
        if iters > 8000 {
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
        let is_lsass_listener = badge == LSASS_LISTENER_BADGE;
        let is_lsass_listener2 = badge == LSASS_LISTENER2_BADGE;
        let is_lsass_listener3 = badge == LSASS_LISTENER3_BADGE;
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
        let pi = if badge == CSRSS_BADGE {
            1
        } else if badge == WINLOGON_BADGE || is_wl_worker {
            2
        } else if badge == SERVICES_BADGE || is_svc_listener {
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
        let (active_stack_base, active_stack_frames) = if is_svc_listener {
            (SVC_LISTENER_STACK_BASE, SVC_LISTENER_STACK_FRAMES)
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
            if is_svc_listener {
                // Per-thread sub-selection: the listener's OWN stack mirror (its syscall out-params /
                // stack-arg reads land on its own stack, not services' main-thread stack).
                SVC_LISTENER_STACK_MIRROR_VA
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
            stop = fip;
            break;
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
            stop = bp_ip;
            break;
        }
        if (mi >> 12) == 6 {
            let addr = m1;
            if faults == 0 {
                first = addr;
            }
            let page = addr & !0xFFFu64;
            // ROBUSTNESS (gate-safety): a genuine NULL/low deref (addr < 64 KiB) is never a
            // demand-fillable region (image/DLL/scratch/stack/anon all live far above) — it's an
            // unrecoverable client fault (e.g. user32's UserClientDllInitialize deref of a still-null
            // gSharedInfo). Map it and we hand the faulter a zero page → it silently spins on the bad
            // value and the loop never makes progress (deterministic hang). So STOP the loop cleanly
            // with a diagnostic instead — exactly like the win32k `[vmf-out]` stop path.
            if addr < 0x10000 {
                // N-threads multiplex: the services RPC listener (badge 7) walls on its OWN
                // unrecoverable fault (rpcrt4 io_thread derefs a connection field that needs a real
                // client connect — the listener's next frontier). PARK it (don't reply → it stays
                // blocked, its ETHREAD/TEB stay mapped) and CONTINUE the loop so services' main thread
                // + winlogon keep advancing (winlogon → StartLsass). Contained per-thread, not a boot
                // stop — the whole point of the per-thread multiplex.
                if is_svc_listener || is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 || is_wl_worker {
                    print_str(if is_wl_worker { b"[wl-worker] wall ip=0x" } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 { b"[lsass-listener] wall ip=0x" } else { b"[svc-listener] wall ip=0x" });
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" addr=0x");
                    print_hex(addr as u32);
                    print_str(b" -> PARK thread (its own unrecoverable fault); boot continues\n");
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
                stop = addr;
                break;
            }
            // Dynamic stack growth (Windows guard-page style): a fault just below the committed
            // stack commits a fresh zeroed page and restarts, so smss's stack grows on demand
            // instead of crashing at the 16 KiB initial commit. Bounded by STACK_GROWTH_FLOOR so it
            // never runs into the env mappings below.
            if page >= STACK_GROWTH_FLOOR && page < STACK_BASE {
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                if pi >= 1 {
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
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
                stop = addr; // outside both images (unresolved / null deref) — stop safely
                break;
            };
            if faults >= 2000 {
                stop = addr;
                break;
            }
            let rva = (page - base) as u32;
            // SHAREABLE = a registered DLL's executable text (not the per-process main image at
            // PE_LOAD_BASE, and an RX page). Such a page is byte-identical across processes (each DLL
            // is loaded at a fixed base + pre-relocated), so it's filled ONCE into a frame and that
            // frame is mapped READ-ONLY (RX) into every process that faults it — real image sharing.
            let shareable = base != PE_LOAD_BASE && page_rights(tpe, rva) == 2;
            let cached = if shareable { dll_cache_get(page) } else { 0 };
            let (frame, rights) = if cached != 0 {
                DLL_SHARED_HITS.fetch_add(1, Ordering::Relaxed);
                (cached, 2u64) // shared text → RX, no fill, no fresh frame
            } else {
                // MISS (shared, first process) or a per-process page: fill a fresh frame.
                let scratch = scratch_base + faults * 0x1000;
                let (f, fe) = alloc_frame_r();
                let se = page_map_r(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                let r = fill_image_page(tpe, rva, scratch);
                if fe != 0 || se != 0 {
                    print_str(b"[map-fail] rva=0x");
                    print_hex(rva);
                    print_str(b" retype=");
                    print_u64(fe);
                    print_str(b" smap=");
                    print_u64(se);
                    print_str(b" faults=");
                    print_u64(faults);
                    print_str(b"\n");
                }
                if shareable {
                    dll_cache_put(page, f); // this frame becomes the shared copy for all processes
                } else {
                    // Per-process page (main image, or DLL headers/rdata/data/IAT): record it for
                    // copy-out via its scratch alias, and mirror the main image so smss_copyin can
                    // read static-string args from .rdata.
                    if (faults as usize) < filled_pages.len() {
                        filled_pages[faults as usize] = page;
                    }
                    if pi >= 1 {
                        // Record this GUI client's (csrss pi 1 / winlogon pi 2) frame so win32k can
                        // identity-map + read/write it per-client (a client pointer into user32/gdi32
                        // .data — e.g. the PFNCLIENT arrays — the client's stack-built OBJECT_ATTRIBUTES,
                        // or its own image). The frame is shared with the executive's scratch, so it
                        // holds the client's LIVE runtime data, not the (zeroed) PE static content.
                        csrss_frame_put(pi as u64, page, f);
                    }
                    if base == PE_LOAD_BASE {
                        let off = page - PE_LOAD_BASE;
                        if off < IMAGE_MIRROR_WINDOW {
                            let mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
                            let _ = page_map(copy_cap(f), mirror + off, RW_NX, CAP_INIT_THREAD_VSPACE);
                        }
                    }
                }
                faults += 1; // a fill consumed a scratch slot; shared HITs do not
                (f, if shareable { 2 } else { r })
            };
            // Map the frame into the faulting process (RX for shared text, its fill rights otherwise).
            let (cc, ce) = copy_cap_r(frame);
            let me = page_map_r(cc, page, rights, pml4);
            if ce != 0 || me != 0 {
                print_str(b"[map-fail] va=0x");
                print_hex(page as u32);
                print_str(b" copy=");
                print_u64(ce);
                print_str(b" map=");
                print_u64(me);
                print_str(b" shared=");
                print_u64(shareable as u64);
                print_str(b"\n");
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
            let resume_ip = m2; // RCX = syscall return address
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let mut result = 0u64; // STATUS_SUCCESS unless a handler overrides
            let mut handled = true;
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
            // Broker-only terminal waits (currently smss waiting forever for csrss/winlogon) park
            // by withholding a reply. Self-termination does not use this flag: its explicit post
            // action deletes the bound Reply cap and caller TCB before receiving again.
            let mut park_caller = false;
            // Checkpoint B: -1 = no wait-park; >=0 = NtWaitForSingleObject asked to park this caller on
            // the given obj_ns event index (set from nt_handler.wait_park_event after dispatch).
            let mut park_wait_event: i64 = -1;
            // Array-wait park (NtWaitForMultipleObjects): the resolved obj_ns event set + WaitAll flag.
            // count 0 = no array-park. Consumed next to park_wait_event in the reply block.
            let mut park_wait_set = [0usize; 8];
            let mut park_wait_set_n: usize = 0;
            let mut park_wait_set_all = false;
            let mut park_wait_deadline: Option<u64> = None;
            let mut park_delay_deadline: Option<u64> = None;
            // Every syscall path, including the still hand-wired ladder below, resolves process-local
            // handles through ExecNtHandler. Refresh caller identity before choosing table vs ladder;
            // doing this only inside table dispatch left a runtime worker using whichever process ran
            // the previous registered syscall.
            nt_handler.pi = pi;
            nt_handler.current_badge = badge;
            nt_handler.current_tid = if is_svc_listener {
                SVC_LISTENER_TID.load(Ordering::Relaxed)
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
                for i in 4..n {
                    argv[i] = smss_stack_read(sp + 0x28 + (i as u64 - 4) * 8);
                }
                // Refresh the handler's per-call executive context, then clear the stop side-signal
                // + out-write queue so a migrated handler can raise them (group A/B signals).
                nt_handler.post_action = ExecPostAction::None;
                nt_handler.stop = false;
                nt_handler.overlay_dirty = false;
                nt_handler.dll_loaded_dirty = false;
                nt_handler.out_writes_n = 0;
                nt_handler.spawn_request = false;
                nt_handler.winlogon_spawn_request = false;
                nt_handler.sm_spawn_request = false;
                nt_handler.wl_spawn_request = 0;
                nt_handler.svc_listener_spawn = false;
                nt_handler.lsass_listener_spawn = false;
                nt_handler.lsass_listener2_spawn = false;
                nt_handler.lsass_listener3_spawn = false;
                nt_handler.wait_park_event = -1;
                nt_handler.wait_deadline_100ns = u64::MAX;
                nt_handler.delay_requested = false;
                nt_handler.delay_interval_100ns = 0;
                nt_handler.delay_alertable = false;
                nt_handler.io_signal_event = -1;
                nt_handler.lpc_rendezvous_conn = 0;
                nt_handler.csr_spawn_request = false;
                nt_handler.csr_rendezvous_conn = 0;
                // Group-C handlers reach the loop's section/registry/demand-fill state through this
                // ctx of raw refs (rebuilt each iteration at the current loop locals).
                nt_handler.loop_ctx = Some(ExecLoopCtx {
                    pml4,
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
                    filled_pages: filled_pages as *mut [u64; 256],
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
                if let Some(st) = try_route_alpc_ssn(m0, &[], &mut [0u8; 8]) {
                    result = st;
                    handled = true;
                } else {
                    let res = nt_dispatcher.dispatch(m0 as u32, &argv[..n], &origin, &mut nt_handler);
                    result = res.status as u64;
                    if nt_handler.stop {
                        handled = false; // handler couldn't service → stop with the SSN recorded
                    }
                }
                // A successful self-termination is a control-flow action, not a status-returning
                // syscall. First delete/replace the Reply object bound to this fault (so no send can
                // resume it), then suspend/delete the exact badge-selected TCB, and receive the next
                // caller immediately. Remote termination tears down its target but still replies to
                // the caller through the normal tail below.
                match nt_handler.post_action {
                    ExecPostAction::TerminateCurrentThread { tid } => {
                        let reply_dropped = drop_current_syscall_reply();
                        let mechanism_deleted =
                            terminate_hosted_thread_mechanism(tid, &mut delay_queue);
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
                        let _ = terminate_hosted_thread_mechanism(tid, &mut delay_queue);
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
                // Drain queued out-param writes (group B2): csrss out-ptrs may be arbitrary VAs that
                // need demand-fill (csrss_out_write); smss out-ptrs are stack locals (smss_stack_write).
                for k in 0..nt_handler.out_writes_n {
                    let (ptr, val) = nt_handler.out_writes[k];
                    if badge == CSRSS_BADGE {
                        csrss_out_write(ptr, val, &mut *filled_pages, &mut faults, scratch_base,
                            &reg, &dll_pes, pml4);
                    } else {
                        smss_stack_write(ptr, val);
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
                if nt_handler.io_signal_event >= 0 {
                    let event = nt_handler.io_signal_event as usize;
                    let _ = wait_wake_event_set(event, &mut nt_handler.events);
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
                    procs[1].img_end = PE_LOAD_BASE + image_extent(cpe);
                    procs[1].scratch_base = CSRSS_SCRATCH_BASE;
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
                                0,
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
                                0,
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
                if nt_handler.csr_spawn_request && CSR_LOOP_TCB.swap(1, Ordering::Relaxed) == 0 {
                    let ctx_va = smss_stack_read(sp + 0x30);
                    let entry_rip = smss_stack_read(ctx_va + 0xF8);
                    let param = smss_stack_read(ctx_va + 0x80);
                    print_str(b"[csr-loop] spawning REAL CsrApiRequestThread: entry=0x");
                    print_hex((entry_rip >> 32) as u32);
                    print_hex(entry_rip as u32);
                    print_str(b" param=0x");
                    print_hex(param as u32);
                    print_str(b"\n");
                    let tcb = spawn_csr_loop_thread(pml4, entry_rip, param);
                    CSR_LOOP_TCB.store(tcb, Ordering::Relaxed);
                    print_str(b"[csr-loop] spawned tcb=0x");
                    print_hex(tcb as u32);
                    print_str(b" (parks on its first fault to csr_fault_ep)\n");
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
                        start.rip,
                        start.rcx,
                        start.rdx,
                        cid_proc,
                        tid,
                        fault_ep,
                        !suspended,
                    );
                    tcb_cell.store(tcb, Ordering::Relaxed);
                    // Record the real TEB base on the ETHREAD (alloc-free) so 162 reports it.
                    nt_handler.pm.set_thread_teb(tid as nt_process::ThreadId, teb);
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
                // Path B (authentic accept): csrss's NtConnectPort left the broker connection Pending
                // (Manual). Drive the REAL SmpApiLoop thread through the connection rendezvous (it runs
                // in smss's VSpace = procs[0].pml4, demand-filling from smss's image + ntdll), then write the
                // completed client comm-port handle to csrss's *PortHandle + reply csrss via REPLY_MAIN.
                if nt_handler.lpc_rendezvous_conn != 0 {
                    let conn_id = nt_handler.lpc_rendezvous_conn;
                    let out_ptr = nt_handler.lpc_rendezvous_out;
                    print_str(b"[sm-rdv] csrss NtConnectPort pending (conn=");
                    print_u64(conn_id);
                    print_str(b") -> driving the real SmpApiLoop accept\n");
                    let client_handle = sm_rendezvous(
                        conn_id,
                        procs[0].pml4,
                        smss_pe,
                        procs[0].img_end,
                        nt_base,
                        nt_end,
                        ntdll.map(|(_, p)| p),
                    );
                    if client_handle != 0 {
                        // csrss's *PortHandle is a csrsrv/csrss VA (demand-fill window) — csrss_out_write.
                        csrss_out_write(out_ptr, client_handle, &mut *filled_pages, &mut faults,
                            scratch_base, &reg, &dll_pes, pml4);
                        let name16 = nt_handler.read_lpc_name(m3); // RDX = PortName (for the cache record)
                        nt_handler.cache_lpc_connection(conn_id, client_handle, &name16);
                        result = 0; // STATUS_SUCCESS
                        routed_lpc = true;
                        print_str(b"[sm-rdv] AUTHENTIC accept complete: client handle=0x");
                        print_hex((client_handle >> 32) as u32);
                        print_hex(client_handle as u32);
                        print_str(b" -> csrss NtConnectPort SUCCESS\n");
                    } else {
                        // The rendezvous walled — stop cleanly with a diagnostic (don't hand csrss junk).
                        print_str(b"[sm-rdv] WALL: rendezvous produced no client handle\n");
                        handled = false;
                        result = 0xC0000001;
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
            } else if m0 == 287 {
                // NtWriteVirtualMemory(ProcessHandle=R10, BaseAddress=RDX, Buffer=R8, Size=R9,
                // *NumberOfBytesWritten=[sp+0x28]). smss's RtlCreateUserProcess(csrss) reaches here to
                // inject the child's RTL_USER_PROCESS_PARAMETERS. In our hosted model spawn_sec_image
                // already built csrss's REAL PEB/params AND csrss has long since run its loader + SM
                // connect, so this late write is moot (its BaseAddress is garbage — the child-side
                // NtAllocateVirtualMemory that would have reserved the target is faked). Model it as a
                // successful write: set *NumberOfBytesWritten = Size and return SUCCESS so
                // RtlCreateUserProcess completes. TODO(migrate): a real cross-AS NtWriteVirtualMemory
                // belongs in nt-memory-manager once a genuinely-new child needs live param injection.
                let size = get_recv_mr(8); // R9 = NumberOfBytesToWrite
                let sp = get_recv_mr(16);
                let written_ptr = smss_stack_read(sp + 0x28); // arg5 = *NumberOfBytesWritten (optional)
                if written_ptr != 0 {
                    if badge == CSRSS_BADGE {
                        csrss_out_write(written_ptr, size, &mut *filled_pages, &mut faults,
                            scratch_base, &reg, &dll_pes, pml4);
                    } else {
                        smss_stack_write(written_ptr, size);
                    }
                }
                result = 0; // STATUS_SUCCESS
            } else if m0 == 223 {
                // NtSetDefaultHardErrorPort(PortHandle=R10). csrsrv's CsrServerInitialization registers
                // its API port as the hard-error port right after SmConnectToSm succeeds
                // (init.c:1119). No kernel state to model in the host — accept it so CsrServerInit
                // returns and csrss.exe's main continues. (One-time; NtRaiseHardError already routes to
                // our diagnostic path.)
                result = 0; // STATUS_SUCCESS
            } else if m0 == 228 {
                // NtSetEvent(EventHandle=R10, *PreviousState=RDX).
                // If the handle names a real executive event, including a typed anonymous event,
                // SET its `signalled` flag and WAKE every waiter parked on it (reply-cap park). This is
                // the signaler half — e.g. lsass' LsarStartRpcServer SetEvent(LSA_RPC_SERVER_ACTIVE)
                // wakes winlogon's WaitForLsass. Handles that aren't real events (smss subsystem/session
                // events, rpcrt4 fakes) are accepted as a SUCCESS no-op (nothing parks on them).
                let ev_handle = get_recv_mr(9); // R10 = EventHandle
                match nt_handler.event_index_for_handle(ev_handle, EVENT_MODIFY_STATE) {
                    Ok(idx) => {
                        let previous = nt_handler.events.set_existing(idx as u64).unwrap_or(false);
                        if m3 != 0 {
                            smss_stack_write32(m3, previous as u32);
                        }
                        let trace = EVENT_TRACE_N.fetch_add(1, Ordering::Relaxed);
                        if trace < 32 {
                            print_str(b"[event] set pi=");
                            print_u64(pi as u64);
                            print_str(b" badge=");
                            print_u64(badge);
                            print_str(b" h=0x");
                            print_hex_u64(ev_handle);
                            print_str(b" obj=");
                            print_u64(idx as u64);
                            print_str(if previous { b" previous=1\n" } else { b" previous=0\n" });
                        }
                        if nt_handler.obj_ns[idx].name() == b"lsa_rpc_server_active" {
                            LSA_RPC_SERVER_ACTIVE_SIGNALLED.store(1, Ordering::Relaxed);
                            print_str(b"[wait] lsass SIGNALLED LSA_RPC_SERVER_ACTIVE (event #");
                            print_u64(idx as u64);
                            print_str(b")\n");
                        }
                        // Wake any parked waiter whose condition is now satisfied (WaitAny/WaitAll over
                        // its event set). Auto-reset events consumed by a wake are cleared inside.
                        let woken = wait_wake_event_set(idx, &mut nt_handler.events);
                        if woken > 0 {
                            print_str(b"[wait] NtSetEvent(event #");
                            print_u64(idx as u64);
                            print_str(b") -> WOKE ");
                            print_u64(woken);
                            print_str(b" parked waiter(s)\n");
                        }
                        result = 0;
                    }
                    Err(status) => result = status as u64,
                }
            } else if m0 == 45 {
                // NtCreateMutant(MutantHandle=R10, DesiredAccess=RDX, ObjectAttributes=R8,
                // InitialOwner=R9). rpcrt4's ncacn_np server init (StartRpcServer) creates sync
                // mutants. Mint a fake handle so the caller can later wait/release it; no real mutant
                // is modeled (the wait/release paths below are no-ops). Additive.
                let out = get_recv_mr(9); // R10 = *MutantHandle
                if out != 0 {
                    smss_stack_write(out, FAKE_SYNC_HANDLE.fetch_add(4, Ordering::Relaxed));
                }
                result = 0;
            } else if m0 == 210 {
                // NtResetEvent(EventHandle=R10, *PreviousState=RDX).
                let ev_handle = get_recv_mr(9);
                match nt_handler.event_index_for_handle(ev_handle, EVENT_MODIFY_STATE) {
                    Ok(idx) => {
                        let previous = nt_handler.events.reset_existing(idx as u64).unwrap_or(false);
                        if m3 != 0 {
                            smss_stack_write32(m3, previous as u32);
                        }
                        result = 0;
                    }
                    Err(status) => result = status as u64,
                }
            } else if m0 == 196 || m0 == 197 {
                // NtReleaseMutant(196) / NtReleaseSemaphore(197) — legacy modeled objects.
                result = 0;
            } else if m0 == 280 && badge != 0 {
                // ★ NtWaitForMultipleObjects(ObjectCount=R10, HandleArray=RDX, WaitType=R8,
                // Alertable=R9, *TimeOut=[sp+0x28]) — REAL array-wait with reply-cap parking (Part 1 of
                // the winlogon rpcrt4 handshake). WaitType 1 = WaitAny, 0 = WaitAll. This is the
                // worker-thread half of the rpcrt4 two-thread handshake: the server WORKER thread
                // (multiplexed via WINLOGON_WORKER_BADGE / SVC/LSASS listeners) runs
                // rpcrt4_protseq_np_wait_for_new_connection = WaitForMultipleObjects([mgr_event,
                // listen_events…]). We resolve the handle array to obj_ns events:
                //   • WaitAny + any already signalled → immediate WAIT_0+index.
                //   • WaitAll + all signalled → immediate WAIT_0.
                //   • otherwise, if the set contains at least one REAL event (a live signaler exists —
                //     the main thread's signal_state_changed SetEvents mgr_event) → PARK on the set
                //     (steal the reply cap, recv next, wake on NtSetEvent). ★ NO-DEADLOCK: only park
                //     when a real event is present; a set of only fake handles → immediate WAIT_0.
                let count = get_recv_mr(9) as usize; // R10 = ObjectCount
                let harr = m3; // RDX = HandleArray
                let wait_type = get_recv_mr(7); // R8 = WaitType (1=Any, 0=All)
                let wait_all = wait_type == 0;
                let mut events = [0usize; 8];
                let mut nev = 0usize;
                let mut any_signalled_idx: i64 = -1; // handle-array index (k) of the first signalled
                let mut any_signalled_obj: usize = 0; // obj_ns idx of that event (for auto-reset)
                let mut all_signalled = true;
                let mut has_real_event = false;
                let mut wait_error: Option<u32> = None;
                let trace = EVENT_TRACE_N.fetch_add(1, Ordering::Relaxed);
                if harr != 0 && count > 0 && count <= 64 {
                    for k in 0..count {
                        let h = smss_stack_read(harr + (k as u64) * 8);
                        match nt_handler.event_index_for_handle(h, SYNCHRONIZE_ACCESS) {
                            Ok(idx) => {
                                    if trace < 32 {
                                        print_str(b"[event] wait-item k="); print_u64(k as u64);
                                        print_str(b" h=0x"); print_hex_u64(h);
                                        print_str(b" -> obj="); print_u64(idx as u64); print_str(b"\n");
                                    }
                                    has_real_event = true;
                                    if nev < 8 {
                                        events[nev] = idx;
                                        nev += 1;
                                    }
                                    if nt_handler.events.read_state(idx as u64) {
                                        if any_signalled_idx < 0 {
                                            any_signalled_idx = k as i64;
                                            any_signalled_obj = idx;
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
                }
                // Consume (auto-reset) an event satisfied on the IMMEDIATE path (NT clears an auto-reset
                // event that satisfies a wait). WaitAll: clear all consumed auto-reset events.
                let timeout_ptr = smss_stack_read(sp + 0x28);
                let wait_due = if timeout_ptr == 0 {
                    None
                } else {
                    Some(nt_delay_execution::due_time(
                        smss_stack_read(timeout_ptr) as i64,
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
                        for k in 0..nev { nt_handler.events.consume_existing(events[k] as u64); }
                        result = 0; // WAIT_0 (all satisfied)
                    } else if zero_timeout {
                        result = 0x102;
                    } else if has_real_event && nev <= 8 {
                        park_wait_set[..nev].copy_from_slice(&events[..nev]);
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
                        nt_handler.events.consume_existing(any_signalled_obj as u64);
                        result = any_signalled_idx as u64; // WAIT_OBJECT_0 + index
                    } else if zero_timeout {
                        result = 0x102;
                    } else if has_real_event && nev <= 8 {
                        park_wait_set[..nev].copy_from_slice(&events[..nev]);
                        park_wait_set_n = nev;
                        park_wait_set_all = false;
                        park_wait_deadline = finite_deadline;
                        result = 0;
                    } else {
                        result = 0; // no real event to park on → immediate WAIT_0 (documented)
                    }
                }
            } else if m0 == 162 {
                // ★ NtQueryInformationThread(ThreadHandle=R10, ThreadInformationClass=RDX,
                // ThreadInformation=R8, Length=R9, *ReturnLength=[sp+0x28]). GENERAL (all hosted
                // clients): winlogon's RpcServerListen queries the RPC LISTENER thread's
                // ThreadBasicInformation (kernel32 RVA 0x25f62 then derefs [Teb+0x2c8]); services'
                // msvcrt/ntdll CRT init queries its OWN thread (NtCurrentThread==-2) during startup.
                // Resolve the ThreadHandle VALUE → the ETHREAD and fill a real THREAD_BASIC_INFORMATION.
                // Class 0 = ThreadBasicInformation. Per-pi handle table (nt_handler.pi = pi below).
                nt_handler.pi = pi; // resolve the ThreadHandle in the CALLER's own handle table
                let cls = m3; // RDX = ThreadInformationClass
                let handle = get_recv_mr(9); // R10 = ThreadHandle
                let buf = get_recv_mr(7); // R8 = ThreadInformation
                let len = get_recv_mr(8); // R9 = ThreadInformationLength
                let sp = get_recv_mr(16);
                let return_length = smss_stack_read(sp + 0x28);
                let trace = THREAD_QUERY_TRACE_N.fetch_add(1, Ordering::Relaxed);
                if trace < 8 {
                    print_str(b"[thread-life] query caller_pi=");
                    print_u64(pi as u64);
                    print_str(b" badge=");
                    print_u64(badge);
                    print_str(b" handle=0x");
                    print_hex(handle as u32);
                    print_str(b" class=");
                    print_u64(cls);
                    print_str(b" length=");
                    print_u64(len);
                    print_str(b" output=0x");
                    print_hex(buf as u32);
                    print_str(b" return_length=0x");
                    print_hex(return_length as u32);
                    print_str(b"\n");
                }
                result = if cls != 0 {
                    nt_process::STATUS_INVALID_INFO_CLASS as u64
                } else if len != 0x30 {
                    if return_length != 0 {
                        csrss_out_write(return_length, 0x30, &mut *filled_pages, &mut faults,
                            scratch_base, &reg, &dll_pes, pml4);
                    }
                    nt_process::STATUS_INFO_LENGTH_MISMATCH as u64
                } else if buf == 0 {
                    0xC000_0005
                } else if let Some(caller_pid) = nt_handler.pm_pid_for_pi(pi) {
                    match nt_handler.pm.query_thread_basic(caller_pid, handle) {
                        Ok(basic) => {
                            let resolved_tid = basic.client_id.unique_thread as u64;
                            // Main-thread TEBs predate the ETHREAD convergence and are bound by the
                            // process spawn. Runtime threads always carry their distinct mapped TEB.
                            let teb = if basic.teb_base_address != 0 {
                                basic.teb_base_address
                            } else if pi == 0 {
                                SMSS_TEB_VA
                            } else {
                                TEB_VA
                            };
                            // THREAD_BASIC_INFORMATION (x64, 0x30 bytes): ExitStatus@0,
                            // TebBaseAddress@8, ClientId@0x10, AffinityMask@0x20, priorities@0x28.
                            let tbi: [(u64, u64); 6] = [
                                (0x00, basic.exit_status as u64),
                                (0x08, teb),
                                (0x10, basic.client_id.unique_process as u64),
                                (0x18, resolved_tid),
                                (0x20, basic.affinity_mask),
                                (0x28, 0),
                            ];
                            for (off, v) in tbi {
                                csrss_out_write(buf + off, v, &mut *filled_pages, &mut faults,
                                    scratch_base, &reg, &dll_pes, pml4);
                            }
                            if return_length != 0 {
                                csrss_out_write(return_length, 0x30, &mut *filled_pages, &mut faults,
                                    scratch_base, &reg, &dll_pes, pml4);
                            }
                            WL_LISTENER_TEB_QUERIED.fetch_add(1, Ordering::Relaxed);
                            print_str(b"[thread-life] query resolved ETHREAD tid=");
                            print_u64(resolved_tid);
                            print_str(b" written_teb=0x");
                            print_hex((teb >> 32) as u32);
                            print_hex(teb as u32);
                            let readback_teb = smss_stack_read(buf + 8);
                            print_str(b" readback_teb=0x");
                            print_hex((readback_teb >> 32) as u32);
                            print_hex(readback_teb as u32);
                            print_str(b"\n");
                            0
                        }
                        Err(status) => {
                            print_str(b"[thread-life] query unresolved handle status=0x");
                            print_hex(status);
                            print_str(b"\n");
                            status as u64
                        }
                    }
                } else {
                    nt_process::STATUS_INVALID_HANDLE as u64
                };
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
            } else if m0 == 50 && badge == WINLOGON_BADGE {
                // NtCreateProcessEx(*ProcessHandle[R10], DesiredAccess[RDX], OA[R8], ParentProcess[R9],
                // Flags[sp+0x28], SectionHandle[sp+0x30], DebugPort[sp+0x38], ExceptionPort[sp+0x40]).
                // winlogon's kernel32 CreateProcessInternalW creates services.exe — the 4th hosted
                // process (StartServicesManager). The Win32 path (unlike smss's native
                // RtlCreateUserProcess) builds the child AS via cross-process syscalls
                // (NtAllocateVirtualMemory/NtWriteVirtualMemory/NtCreateThread against the child
                // handle); in our hosted model spawn_sec_image already builds services.exe's REAL
                // env/stack/thread, so those cross-process calls are benign no-ops. Here we validate the
                // SectionHandle names the tracked services.exe SEC_IMAGE, then spawn services (badge
                // SERVICES_BADGE, pi 3) with its own VSpace/mirrors/scratch at prio 103.
                let sect = smss_stack_read(sp + 0x30); // SectionHandle
                if services_section_handle != 0
                    && sect == services_section_handle
                    && services_pe.is_some()
                    && SERVICES_SPAWNED.swap(1, Ordering::Relaxed) == 0
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
                    // Bind services' pre-created main ETHREAD to its real image entry — pm at spawn.
                    nt_handler.bind_main_thread_entry(3, PE_LOAD_BASE + spe.entry_point_rva() as u64);
                    // Record services' process handle in winlogon's (pi 2) EPROCESS table as a typed
                    // Process object; the returned dense value IS winlogon's handle (path 1b).
                    services_process_handle = match (nt_handler.pm_pid_for_pi(2), nt_handler.pm_pid_for_pi(3)) {
                        (Some(wl_pid), Some(sv_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                wl_pid,
                                nt_process::HandleObject::Process(sv_pid),
                                0,
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
                } else if lsass_section_handle != 0
                    && sect == lsass_section_handle
                    && lsass_pe.is_some()
                    && LSASS_SPAWNED.swap(1, Ordering::Relaxed) == 0
                {
                    // winlogon's StartLsass CreateProcessW(L"lsass.exe") — the 5th hosted process (badge
                    // LSASS_BADGE, pi 4), prio 104 (> services 103) so it runs when others park.
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
                    nt_handler.bind_main_thread_entry(4, PE_LOAD_BASE + lpe.entry_point_rva() as u64);
                    lsass_process_handle = match (nt_handler.pm_pid_for_pi(2), nt_handler.pm_pid_for_pi(4)) {
                        (Some(wl_pid), Some(ls_pid)) => {
                            let h = nt_handler.pm.insert_handle(
                                wl_pid, nt_process::HandleObject::Process(ls_pid), 0,
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
                } else if services_process_handle != 0 && sect == services_section_handle {
                    // Idempotent (a second create should not re-spawn): return the same handle.
                    smss_stack_write(get_recv_mr(9), services_process_handle);
                } else if lsass_process_handle != 0 && sect == lsass_section_handle {
                    smss_stack_write(get_recv_mr(9), lsass_process_handle);
                }
                result = 0;
            } else if m0 == 195 {
                // NtRegisterThreadTerminatePort(PortHandle=R10). kernel32's CsrNewThread() — the LAST
                // step of BaseDllInitialize after the CSR connect — registers the thread's LPC
                // terminate port (so CSR is told when the thread dies). No terminate-port model in the
                // host → accept it (STATUS_SUCCESS) so winlogon's kernel32 DllMain completes + the
                // loader runs the remaining DllMains toward winlogon's entry.
                result = 0;
            } else if m0 == 71 && badge == 0 {
                // NtDuplicateObject — smss's SmpExecuteInitialCommand duplicates winlogon's process
                // handle (SourceHandle=RDX) into InitialCommandProcess (*TargetHandle=R9) so it can
                // later wait on it (smss.c:344). If this FAILS smss KILLS winlogon (smss.c:355), so it
                // MUST succeed. Model the dup: write the source handle value to *TargetHandle and
                // return STATUS_SUCCESS (no real cross-process handle table needed — smss only uses the
                // dup'd handle in the NtWaitForMultipleObjects below, which we park). This is the smss
                // step that, when serviced, lets the loop keep multiplexing so winlogon (prio 102) runs
                // FORWARD past the desktop paint toward StartServicesManager -> services.exe.
                // ABI: SourceProcess=R10, SourceHandle=RDX(m3), TargetProcess=R8, TargetHandle=R9(PHANDLE).
                let src_handle = m3;
                let target = get_recv_mr(8); // R9 = *TargetHandle
                if target != 0 {
                    smss_stack_write(target, src_handle);
                }
                result = 0; // STATUS_SUCCESS
            } else if m0 == 280 && badge == 0 {
                // NtWaitForMultipleObjects — smss's main thread waits (WaitAny) on {csrss, winlogon}
                // to die (smss.c:518). In our boot NEITHER dies, so smss's correct terminal state is to
                // block here FOREVER. PARK it (never reply, recv the next event) so the higher-priority
                // winlogon keeps running forward. Returning STATUS_WAIT_0 instead would make smss think
                // csrss/winlogon terminated -> its hard-error teardown path (wrong). This is the
                // designed end of smss's lifetime; the loop now terminates on winlogon's next wall.
                park_caller = true;
                result = 0;
            } else if m0 == 136 {
                // NtOpenThreadTokenEx — winlogon's InitKeyboardLayouts calls RegOpenKeyExW(
                // HKEY_CURRENT_USER, "Keyboard Layout\\Preload") -> RtlOpenCurrentUser ->
                // NtOpenThreadToken(Ex). winlogon runs as SYSTEM with no impersonation token, so the
                // authentic result is STATUS_NO_TOKEN (0xC000007C) -> RtlOpenCurrentUser falls back to
                // the process-token user key (\Registry\User\S-1-5-18), which misses our SYSTEM-only
                // hive -> InitKeyboardLayouts loads the default US layout instead. (Mirrors the
                // NtOpenThreadToken=135 handler; 136 is the Ex variant the real ntdll uses.)
                result = 0xC000007C;
            } else if m0 == 130 {
                // NtOpenProcessTokenEx(ProcessHandle=R10, DesiredAccess=RDX, HandleAttributes=R8,
                // *TokenHandle=R9). RtlOpenCurrentUser falls here after NtOpenThreadTokenEx=NO_TOKEN to
                // fetch the process (primary) token so it can read the user SID (NtQueryInformationToken
                // TokenUser -> S-1-5-18) and open \Registry\User\<SID>. Mint a fake token handle to
                // *TokenHandle (mirrors the NtOpenProcessToken=129 handler; 130 is the Ex variant).
                let out = get_recv_mr(8); // R9 = *TokenHandle
                let h = nt_handler.next_handle;
                nt_handler.next_handle += 1;
                if out != 0 {
                    smss_stack_write(out, h);
                }
                result = 0; // STATUS_SUCCESS
            } else if m0 >= win32k_subsystem::WIN32K_SERVICE_BASE
                && (badge == CSRSS_BADGE
                    || badge == WINLOGON_BADGE
                    || badge == SERVICES_BADGE
                    || badge == LSASS_BADGE)
            {
                routed_win32k = true;
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
                let mut a1 = m3; // RDX = arg2
                let mut a2 = get_recv_mr(7); // R8 = arg3
                let a3 = get_recv_mr(8); // R9 = arg4
                // NtUserInitialize(dwWinVersion=a0, hPowerRequestEvent=a1, hMediaRequestEvent=a2):
                // winsrv created these events via NtCreateEvent but our csrss demand-fill window
                // couldn't write the handle back to winsrv's late .bss global, so they arrive NULL
                // (pre-fix a fake EPROCESS masked that). Substitute the REAL minted handles the
                // executive recorded (creation order = power, media), so win32k models + references
                // genuine typed Event objects. Only fills NULLs (a working marshal is respected).
                if m0 == win32k_subsystem::SSN_NT_USER_INITIALIZE_REAL {
                    if a1 == 0 {
                        a1 = nt_handler.csrss_event_handles[0];
                    }
                    if a2 == 0 {
                        a2 = nt_handler.csrss_event_handles[1];
                    }
                }
                // NtCurrentProcess() == (HANDLE)-1: win32k's ObReferenceObjectByHandle resolves the
                // hosted client's process via the synthetic handle the DriverEntry attach used.
                let d_a0 = if a0 == 0xFFFF_FFFF_FFFF_FFFF { win32k_subsystem::FAKE_PROCESS_HANDLE } else { a0 };
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
                print_str(b"[win32k-svc] csrss -> SSN 0x");
                print_hex(m0 as u32);
                print_str(b" (dispatch)\n");
                // DIAG: NtUserCreateWindowStation(0x122f) OA-pointer probe — read the client's REAL
                // OBJECT_ATTRIBUTES.Length via its stack mirror (pi-selected) so we can tell a stale
                // (wrong-client) frame in win32k from a genuinely-bad OA the client built.
                if m0 == 0x122f {
                    print_str(b"[w32diag] 0x122f OA=0x");
                    print_hex((a0 >> 32) as u32);
                    print_hex(a0 as u32);
                    print_str(b" real-Length=0x");
                    print_hex(smss_stack_read(a0) as u32);
                    print_str(b" pi=");
                    print_u64(pi as u64);
                    print_str(b"\n");
                }
                // ★ THE COUNTED DESKTOP PAINT — winlogon's OWN natural NtUserSwitchDesktop paints the
                // framebuffer, and THIS is the source of the `exec_win32k_desktop_painted` gate spec
                // (scaffold RETIRED — see the m0==0x125a arm, which now runs ONLY the InitVideo/surface
                // bringup, not the paint). Right BEFORE winlogon's SSN 0x1288 we clear the WHOLE fb to
                // magenta — now LOAD-BEARING: it wipes any earlier pixels so the counted spec genuinely
                // proves winlogon's co_IntShowDesktop -> co_UserRedrawWindow -> DesktopWindowProc
                // WM_ERASEBKGND -> IntPaintDesktop re-painted 0x003a6ea5 by the AUTHENTIC boot flow
                // (BOOTBOOT -> kernel -> smss -> csrss -> winlogon -> win32k), not a stale scaffold paint.
                let winlogon_switch = m0 == 0x1288 && badge == WINLOGON_BADGE;
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
                let (st, ok) = if m0 == 0x125c && badge == WINLOGON_BADGE {
                    KBD_LAYOUT_LOADED.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[win32k-svc] winlogon NtUserLoadKeyboardLayoutEx(0x125c) FAKED -> HKL=0x04090409\n");
                    (0x0409_0409i32, true)
                } else {
                    win32k_dispatch(m0, d_a0, d_a1, a2, a3)
                };
                if winlogon_switch {
                    // Read back the 768-px sampled grid; count how many winlogon's OWN SwitchDesktop flow
                    // painted to the WC_DESKTOP background. This drives the counted paint gate.
                    let fb = FB_VADDR as *const u32;
                    let mut matched = 0u32;
                    let mut changed = 0u32;
                    let mut sample0 = 0u32;
                    for r in 0..24u64 {
                        for c in 0..32u64 {
                            let idx = (r * 32 * 1024 + c * 32) as usize;
                            let px = core::ptr::read_volatile(fb.add(idx));
                            if r == 0 && c == 0 {
                                sample0 = px;
                            }
                            if px != 0x00FF_00FF {
                                changed += 1;
                            }
                            if px == FB_DESKTOP_BG {
                                matched += 1;
                            }
                        }
                    }
                    WINLOGON_NATURAL_PAINT.store(matched as u64, Ordering::Relaxed);
                    // Feed the counted `exec_win32k_desktop_painted` gate from winlogon's NATURAL paint
                    // (the scaffold no longer paints — the m0==0x125a arm keeps only InitVideo/surface).
                    FB_PIXELS_DREW.store(if changed > 0 { 2 } else { 1 }, Ordering::Relaxed);
                    FB_PIXELS_MATCH.store(matched as u64, Ordering::Relaxed);
                    FB_PIXELS_SAMPLE0.store(sample0 as u64, Ordering::Relaxed);
                    print_str(b"[win32k-svc] winlogon NtUserSwitchDesktop ret=0x");
                    print_hex(st as u32);
                    print_str(b" -> NATURAL fb readback: changed ");
                    print_u64(changed as u64);
                    print_str(b"/768, desktop-bg ");
                    print_u64(matched as u64);
                    print_str(b"/768 (px0=0x");
                    print_hex(sample0);
                    print_str(b")\n");
                }
                if has_buf && ok && st == 0 {
                    // NtUserProcessConnect (0x10FA) returned STATUS_SUCCESS for this GUI client —
                    // record the per-pi "win32k client connected" bit (csrss=1, winlogon=2, services=3).
                    W32_CONNECTED_MASK.fetch_or(1u64 << pi, Ordering::Relaxed);
                }
                if has_buf && ok {
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
                print_str(b"[win32k-svc] csrss SSN 0x");
                print_hex(m0 as u32);
                print_str(if ok { b" -> status=0x" } else { b" -> WALL status=0x" });
                print_hex(st as u32);
                print_str(b"\n");
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
                if ok {
                    result = st as u32 as u64; // NTSTATUS (EAX) back to csrss
                } else {
                    handled = false; // dispatch wall — stop with the SSN recorded
                    result = 0xC0000001;
                }
            } else {
                handled = false;
                result = 0xC0000002; // STATUS_NOT_IMPLEMENTED
            }
            if !handled {
                // N-threads multiplex: a SERVER thread (svc/lsass listener) that walls on an unserviced
                // BLOCKING server-loop syscall (e.g. NtListenPort / NtReplyWaitReceivePort — it reached
                // its LPC/RPC receive loop and would block forever waiting for a client) PARKS instead of
                // stopping the whole boot. Recv the next event WITHOUT replying → the listener's seL4
                // thread stays blocked (its ETHREAD/TEB/stack stay mapped), and lsass' main thread + the
                // rest of the boot keep advancing. Contained per-thread — the point of the multiplex.
                if is_svc_listener || is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 || is_wl_worker {
                    print_str(if is_wl_worker { b"[wl-worker] blocking/unserviced server syscall SSN=" } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 { b"[lsass-listener] blocking server syscall SSN=" } else { b"[svc-listener] blocking server syscall SSN=" });
                    print_u64(m0);
                    print_str(b" -> PARK thread (reached its RPC receive loop / unserviced); boot continues\n");
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
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
                    procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                }
                stop_ssn = m0; // an Nt* syscall we don't service yet — stop
                break;
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            procs[pi].faults = faults; procs[pi].first = first; procs[pi].ntfaults = ntfaults; pfilled[pi] = *filled_pages;
            let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
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
            // Checkpoint B: PARK this caller on an unsignaled event (steal its reply cap into the waiter
            // queue keyed by the event, rotate REPLY_MAIN to a fresh pool object, recv the next event
            // WITHOUT replying). The matching NtSetEvent wakes it. If the pool/queue is exhausted,
            // wait_park returns false → fall through to a normal (immediate WAIT_0) reply, never a hang.
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
            // wait_wake_event_set, returning WAIT_0+index. Pool/queue exhaustion → immediate fallback.
            if park_wait_set_n > 0 && reply_main != 0 {
                if park_wait_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if wait_park_multi(
                    &park_wait_set[..park_wait_set_n],
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
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb; mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
                    continue;
                } else {
                    print_str(b"[wait] array park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            let (nb, nmi, nm0, nm1, nm2, nm3) = if park_caller && reply_main != 0 {
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
        stop = m1; // a non-VMFault, non-syscall (e.g. #GP) — stop
        break;
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
            if nt_handler.nt_open_process(csrss_pid).is_some() {
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
        // Scan the stack for ntdll return addresses to reconstruct the call chain that produced
        // the failure status.
        let sp = get_recv_mr(16);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..96u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" 0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
                if shown >= 12 {
                    break;
                }
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
