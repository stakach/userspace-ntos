//! The VM fault arm of the service loop (issue #382, loop hoist).
//!
//! A page fault of a hosted thread (label 6): demand paging of images, sections, stacks and
//! private memory, or the park of a process that faulted unrecoverably.
//!
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::loop_flow::*;
use super::loop_receive::{receive, reply_receive};
use super::*;
use crate::executor::local;

#[inline(never)]
pub(super) unsafe fn vm_fault(
    lp: &mut LoopState<'_>,
    ev: &Event,
) -> ControlFlow<Turn, core::convert::Infallible> {
    let mut nt_handler = &mut *lp.handler;
    let nt_dispatcher = lp.dispatcher;
    let fault_ep = lp.ingress.fault_ep;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let generic_sections = lp.images.generic_sections;
    let dll_pe_store = &mut *lp.images.dll_pe_store;
    let reg = &mut *lp.images.reg;
    let ntdll = lp.images.ntdll;
    let nt_base = lp.images.nt_base;
    let Event {
        event_runtime, is_svc_listener, is_lsass_listener, is_lsass_listener2, is_lsass_listener3,
        is_tp_worker, is_scm_worker, is_lsa_worker, is_wl_worker, pi, scratch_base, pml4, img_end,
        img_base, ..
    } = *ev;
    let pe: &nt_pe_loader::PeFile = &*ev.pe;
    let addr = lp.msg.m1;
    let page = addr & !0xFFFu64;
    installer_child_span_census::note_fault(&nt_handler, pi,
        nt_handler.current_tid, lp.msg.badge, local().reply_main_slot.load(Ordering::Relaxed),
        lp.msg.m0, addr, lp.msg.m3);
    if hosted_thread_memory_access(pi as u64, page, nt_address_space::PAGE_SIZE).is_err() {
        // This is a valid caller making an invalid memory access, not stale ingress.
        // Debugger delivery retains the fault Reply; containment must cancel it otherwise.
        if dbgk_forward_exception(nt_handler, pi, nt_process::dbgk::ExceptionRecord::access_violation( lp.msg.m0, if lp.msg.m3 & 0x10 != 0 { 8 } else if lp.msg.m3 & 0x2 != 0 { 1 } else { 0 }, addr, )) && dbgk_block_and_park(
            &mut lp.exit, &mut lp.parks, &mut lp.ingress, nt_handler, procs, pfilled,
            filled_pages, pi, nt_process::dbgk::DBGK_BLOCK_VM_FAULT, lp.msg.m0, 0, 0, &mut lp.msg,
        )?
        {
            return ControlFlow::Break(Turn::Next);
        }
        return ControlFlow::Break(lp.park_and_log(pi, b"pending-memory", lp.msg.m0, addr));
    }
    if lp.exit.faults == 0 {
        lp.exit.first = addr;
    }
    if pi == 2
        && (lp.msg.m3 & 0x7) == 0x7
        && WINLOGON_HANDLE_FAULT_DIAG_N.fetch_add(1, Ordering::Relaxed) == 0
    {
        const KERNEL32_BASE_HEAP_HANDLE_TABLE: u64 = 0x8045_1640;
        let mut table = [0u8; 0x30];
        let table_ok = img_spawn::client_copyin_mapped(
            pi as u64,
            KERNEL32_BASE_HEAP_HANDLE_TABLE,
            &mut table,
            scratch_base,
        );
        print_str(b"[handle-fault] table-ok=");
        print_u64(table_ok as u64);
        if table_ok {
            for off in (0..table.len()).step_by(8) {
                let value = u64::from_le_bytes(table[off..off + 8].try_into().unwrap());
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
            (
                b" entry".as_slice(),
                csrss_frame_get_exact(2, 0x0000_0100_0057_9000),
            ),
        ] {
            print_str(name);
            print_str(b"-cap=0x");
            print_hex(frame as u32);
            print_str(b"-pa=0x");
            let paddr = if frame != 0 {
                get_frame_paddr(frame)
            } else {
                0
            };
            print_hex((paddr >> 32) as u32);
            print_hex(paddr as u32);
            print_str(b"-idx=");
            print_u64(if index == usize::MAX {
                u64::MAX
            } else {
                index as u64
            });
        }
        print_str(b" frame-n=");
        print_u64(client_frame_registry_stats().records as u64);
        let (heap_frame, heap_index) = csrss_frame_get_exact(2, NTDLL_BASE + 0x99_000);
        print_str(b" heap-cap=0x");
        print_hex(heap_frame as u32);
        print_str(b"-pa=0x");
        let heap_pa = if heap_frame != 0 {
            get_frame_paddr(heap_frame)
        } else {
            0
        };
        print_hex((heap_pa >> 32) as u32);
        print_hex(heap_pa as u32);
        print_str(b"-idx=");
        print_u64(if heap_index == usize::MAX {
            u64::MAX
        } else {
            heap_index as u64
        });
        let mut heap_state = [0u8; 0x30];
        let heap_ok = img_spawn::client_copyin_mapped(
            2,
            NTDLL_BASE + 0x99_000,
            &mut heap_state,
            scratch_base,
        );
        print_str(b" heap-ok=");
        print_u64(heap_ok as u64);
        if heap_ok {
            for off in (0..heap_state.len()).step_by(8) {
                let value =
                    u64::from_le_bytes(heap_state[off..off + 8].try_into().unwrap());
                print_str(b" +");
                print_hex(off as u32);
                print_str(b"=0x");
                print_hex((value >> 32) as u32);
                print_hex(value as u32);
            }
        }
        let callback_frame = (win32k_subsystem::WIN32K_SHARED_VADDR
            + win32k_subsystem::SH_USER_CALLBACK)
            as *const nt_user_callback::CallbackFrame;
        let callback_proc = core::ptr::read_volatile(core::ptr::addr_of!(
            (*callback_frame).payload[0]
        ) as *const u64);
        print_str(b" callback-proc=0x");
        print_hex((callback_proc >> 32) as u32);
        print_hex(callback_proc as u32);
        let entry_va = addr.saturating_sub(8);
        let mut entry = [0u8; 0x20];
        let entry_ok = img_spawn::client_copyin_mapped(
            pi as u64,
            entry_va,
            &mut entry,
            scratch_base,
        );
        print_str(b" entry=0x");
        print_hex((entry_va >> 32) as u32);
        print_hex(entry_va as u32);
        print_str(b" entry-ok=");
        print_u64(entry_ok as u64);
        if entry_ok {
            for off in (0..entry.len()).step_by(8) {
                let value = u64::from_le_bytes(entry[off..off + 8].try_into().unwrap());
                print_str(b" +");
                print_hex(off as u32);
                print_str(b"=0x");
                print_hex((value >> 32) as u32);
                print_hex(value as u32);
            }
        }
        let tcb = event_runtime.tcb;
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
        fault_stack_diagnostics::trace_user_fault_context(
            &nt_handler, event_runtime, scratch_base,
        );
        if is_tp_worker {
            assert!(drop_current_hosted_reply(), "terminal worker fault must retire its Call");
            print_str(b"[tp-worker] wall badge=");
            print_u64(lp.msg.badge);
            print_str(b" ip=0x");
            print_hex((lp.msg.m0 >> 32) as u32);
            print_hex(lp.msg.m0 as u32);
            print_str(b" addr=0x");
            print_hex(addr as u32);
            print_str(b" -> terminal worker containment; other threads continue\n");
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, lp.msg.m0,
            )?;
            let _ = finalize_service_loop_state(&mut nt_handler);
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        // N-threads multiplex: the services RPC listener (badge 7) walls on its OWN
        // unrecoverable fault (rpcrt4 io_thread derefs a connection field that needs a real
        // client connect — the listener's next frontier). PARK it (don't reply → it stays
        // blocked, its ETHREAD/TEB stay mapped) and CONTINUE the loop so services' main thread
        // + winlogon keep advancing (winlogon → StartLsass). Contained per-thread, not a boot
        // stop — the whole point of the per-thread multiplex.
        if is_svc_listener
            || is_scm_worker
            || is_lsass_listener
            || is_lsass_listener2
            || is_lsass_listener3
            || is_lsa_worker
            || is_wl_worker
        {
            assert!(drop_current_hosted_reply(), "terminal listener fault must retire its Call");
            print_str(if is_wl_worker {
                b"[wl-worker] wall ip=0x"
            } else if is_scm_worker {
                b"[scm-worker] wall ip=0x"
            } else if is_lsa_worker {
                b"[lsa-worker] wall ip=0x"
            } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 {
                b"[lsass-listener] wall ip=0x"
            } else {
                b"[svc-listener] wall ip=0x"
            });
            print_hex((lp.msg.m0 >> 32) as u32);
            print_hex(lp.msg.m0 as u32);
            print_str(b" addr=0x");
            print_hex(addr as u32);
            print_str(b" -> terminal thread containment (unrecoverable fault)\n");
            if is_wl_worker
                && WINLOGON_MAIN_EVENT_WAIT_PARKED.load(Ordering::Relaxed) != 0
                && !pre_user_shell_frontier_pending(
                    &nt_handler,
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                    b"winlogon-worker-terminal",
                )
            {
                print_str(b"[wl-worker] terminal wall while winlogon main waits for this worker -> run gate\n");
                lp.exit.stop = lp.msg.m0;
                lp.exit.record(b"winlogon-worker-terminal");
                return ControlFlow::Break(Turn::Exit);
            }
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            // Recv the next event WITHOUT replying to the listener (it stays blocked).
            let _ = finalize_service_loop_state(&mut nt_handler);
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
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
        // DbgkForwardException: an unrecoverable page fault is `STATUS_ACCESS_VIOLATION`
        // with `MmAccessFault`'s two arguments — the access type (from the x86 page-fault
        // error code in m3: bit 1 = write, bit 4 = instruction fetch) and the faulting
        // address. Forwarded BEFORE either terminal branch below so a debugger sees the
        // crash whichever one this process takes. No-op when nothing debugs it.
        if dbgk_forward_exception(nt_handler, pi, nt_process::dbgk::ExceptionRecord::access_violation( lp.msg.m0, if lp.msg.m3 & 0x10 != 0 { 8 } else if lp.msg.m3 & 0x2 != 0 { 1 } else { 0 }, addr, )) && dbgk_block_and_park(
            &mut lp.exit, &mut lp.parks, &mut lp.ingress, nt_handler, procs, pfilled,
            filled_pages, pi, nt_process::dbgk::DBGK_BLOCK_VM_FAULT, lp.msg.m0, 0, 0, &mut lp.msg,
        )?
        {
            // BLOCKED on the debugger's continue; the next event is already received. A
            // `DBG_CONTINUE` replies length-0 → the faulting instruction is RETRIED.
            return ControlFlow::Break(Turn::Next);
        }
        if pi == 2
            && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
            && !pre_user_shell_frontier_pending(
                &nt_handler,
                lp.parks.crash_parked,
                lp.parks.wait_parked,
                b"winlogon-frontier-crash",
            )
            && !defer_quiesce_for_active_user_callbacks(b"winlogon-frontier-crash")
        {
            lp.parks.crash_parked |= owner_bit_for_badge(&nt_handler, lp.msg.badge);
            service_watchdog_record_crash_parked(lp.parks.crash_parked);
            let _ = win32k_glue::unwind_dead_client_user_callbacks(pi as u32);
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            print_str(b"[wl-main] winlogon crashed at its post-OpenSCManager GUI/login frontier (LSA signalled, SCM servers idle) -> QUIESCE; run gate\n");
            lp.exit.stop = lp.msg.m0;
            lp.exit.record(b"winlogon-main-crash");
            return ControlFlow::Break(Turn::Exit);
        }
        // Unrecoverable NULL/low deref on a top-level process thread — a crash. Park+log
        // (the per-process detail above already printed; park_and_log adds the [parked] line).
        return ControlFlow::Break(lp.park_and_log(pi, b"null-deref", lp.msg.m0, addr));
    }
    // Slot 0 returns from its fixed loader bootstrap stack into the reservation created by
    // kernel32!BaseCreateStack. Grow only the next contiguous page in that reservation and
    // advance the live TEB limit before retrying the fault.
    if lp.msg.badge == WINLOGON_WORKER_BADGE {
        let allocation_base = WL_LISTENER_STACK_ALLOCATION_BASE.load(Ordering::Acquire);
        let stack_base = WL_LISTENER_STACK_BASE_REAL.load(Ordering::Acquire);
        let mapped_low = WL_LISTENER_STACK_MAPPED_LOW.load(Ordering::Acquire);
        if lp.msg.m3 & 1 == 0
            && page < stack_base
            && csrss_frame_get_exact(2, page).0 == 0
            && nt_thread_start::next_stack_growth_page(allocation_base, mapped_low, addr)
                == Some(page)
        {
            let (frame, retype_error) = alloc_frame_r();
            let map_cap = if retype_error == 0 {
                copy_cap(frame)
            } else {
                0
            };
            let map_error = if retype_error == 0 {
                page_map_r(map_cap, page, RW_NX, pml4)
            } else {
                retype_error
            };
            if retype_error == 0 && map_error == 0 {
                let registered = nt_handler.capture_process_identity(2)
                    .is_some_and(|process| csrss_frame_put_with_source(
                        2, nt_memory_manager::MemoryLifetime::Process(process), page, map_cap, frame,
                    ));
                if registered && csrss_frame_get_exact(2, page).0 == map_cap {
                    let teb_alias =
                        WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000;
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
                    procs[pi].faults = lp.exit.faults;
                    procs[pi].first = lp.exit.first;
                    procs[pi].ntfaults = lp.exit.ntfaults;
                    pfilled[pi] = *filled_pages;
                    let _ = finalize_service_loop_state(&mut nt_handler);
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        reply_receive(
                            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
                        )?;
                    trace_stack_growth_reply(pi, lp.msg.badge, nb, nmi, nm0, nm1, nm2, nm3);
                    lp.msg.badge = nb;
                    lp.msg.mi = nmi;
                    lp.msg.m0 = nm0;
                    lp.msg.m1 = nm1;
                    lp.msg.m2 = nm2;
                    lp.msg.m3 = nm3;
                    return ControlFlow::Break(Turn::Next);
                }
            }
            if frame != 0 {
                let _ = cnode_delete_recycle_r(frame);
            }
            if map_cap != 0 {
                let _ = cnode_delete_recycle_r(map_cap);
            }
            print_str(b"[wl-worker] real stack growth failed page=0x");
            print_hex((page >> 32) as u32);
            print_hex(page as u32);
            print_str(b" retype=");
            print_u64(retype_error);
            print_str(b" map=");
            print_u64(map_error);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"wl-stack-growth", lp.msg.m0, addr));
        }
    }
    match crate::hosted_stack_growth::service_hosted_stack_growth(
        &mut nt_handler, pi, lp.msg.badge, addr, pml4, scratch_base,
        vm_fault_access_from_x86_error(lp.msg.m3),
    ) {
        Ok(Some(nt_thread_start::stack_vad::StackVadOutcome::Grown)) => {
            note_boot_progress(BootProgress::PageMappingPublished);
            lp.exit.faults += 1;
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                reply_receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        Ok(Some(_)) => {
            print_str(b"[stack-guard] overflow; retaining fault Reply\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"stack-overflow", lp.msg.m0, addr));
        }
        Ok(None) => {}
        Err(status) => {
            print_str(b"[stack-guard] failed status=");
            print_hex(status);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"stack-guard", lp.msg.m0, addr));
        }
    }
    // Fixed bootstrap transport stacks do not own caller VAD reservations. Their
    // contiguous backing path must never replace caller-owned NT stack policy.
    if lp.msg.m3 & 1 == 0 && process_vm_region_map(pi).is_some_and(|map| map.extent_at(page).is_none()) {
        if let Some((allocation_base, stack_base, role)) =
            nt_handler.hosted_thread_user_stack_for_badge(lp.msg.badge, pi)
        {
            let next_page = page.checked_add(nt_thread_start::USER_PAGE_SIZE);
            let next_page_is_stack = next_page.is_some_and(|next_page| {
                next_page < stack_base && csrss_frame_get_exact(pi as u64, next_page).0 != 0
            });
            if page < stack_base
                && csrss_frame_get_exact(pi as u64, page).0 == 0
                && next_page_is_stack
                && next_page.is_some_and(|next_page| {
                    nt_thread_start::next_stack_growth_page(
                        allocation_base,
                        next_page,
                        addr,
                    ) == Some(page)
                })
            {
                let f = alloc_frame();
                let mut registered = false;
                let mut map_cap = 0;
                if pi == 0 {
                    let map_error = page_map_r(f, page, RW_NX, pml4);
                    if map_error == 0 {
                        if let Some(process) = nt_handler.capture_process_identity(pi) {
                            csrss_frame_put(pi as u64, nt_memory_manager::MemoryLifetime::Process(process), page, f);
                        }
                        registered = csrss_frame_get_exact(pi as u64, page).0 == f;
                    }
                } else {
                    map_cap = copy_cap(f);
                    let map_error = page_map_r(map_cap, page, RW_NX, pml4);
                    if map_error == 0 {
                        // Preserve the mapped frame cap so stack-based syscall arguments
                        // remain reachable after the stack grows below its fixed executive
                        // mirror. GUI clients also keep an unmapped source cap for
                        // win32k/client temporary aliases.
                        registered = nt_handler.capture_process_identity(pi)
                            .is_some_and(|process| csrss_frame_put_with_source(
                                pi as u64, nt_memory_manager::MemoryLifetime::Process(process), page, map_cap, f,
                            ));
                    }
                }
                if registered {
                    if matches!(role, HostedThreadRole::Main) {
                        let _ = smss_copyout(SMSS_TEB_VA + 0x10, &page.to_le_bytes());
                    }
                    print_str(b"[stack-growth] pi=");
                    print_u64(pi as u64);
                    print_str(b" badge=");
                    print_u64(lp.msg.badge);
                    print_str(b" page=0x");
                    print_hex((page >> 32) as u32);
                    print_hex(page as u32);
                    print_str(b" allocation=0x");
                    print_hex((allocation_base >> 32) as u32);
                    print_hex(allocation_base as u32);
                    print_str(b"\n");
                    lp.exit.faults += 1;
                    procs[pi].faults = lp.exit.faults;
                    procs[pi].first = lp.exit.first;
                    procs[pi].ntfaults = lp.exit.ntfaults;
                    pfilled[pi] = *filled_pages;
                    let _ = finalize_service_loop_state(&mut nt_handler);
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        reply_receive(
                            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
                        )?;
                    lp.msg.badge = nb;
                    lp.msg.mi = nmi;
                    lp.msg.m0 = nm0;
                    lp.msg.m1 = nm1;
                    lp.msg.m2 = nm2;
                    lp.msg.m3 = nm3;
                    return ControlFlow::Break(Turn::Next);
                }
                if map_cap != 0 {
                    let _ = cnode_delete_recycle_r(map_cap);
                }
                if f != 0 {
                    let _ = cnode_delete_recycle_r(f);
                }
                print_str(b"[stack-growth] failed pi=");
                print_u64(pi as u64);
                print_str(b" badge=");
                print_u64(lp.msg.badge);
                print_str(b" page=0x");
                print_hex((page >> 32) as u32);
                print_hex(page as u32);
                print_str(b"\n");
                return ControlFlow::Break(lp.park_and_log(pi, b"stack-growth", lp.msg.m0, addr));
            }
        }
    }
    match service_private_guard_page_fault(
        &mut nt_handler,
        pi,
        lp.msg.badge,
        page,
        pml4,
        scratch_base,
        vm_fault_access_from_x86_error(lp.msg.m3),
    ) {
        Ok(true) => {
            note_boot_progress(BootProgress::PageMappingPublished);
            lp.exit.faults += 1;
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        Ok(false) => {}
        Err(status) => {
            print_str(b"[guard-page] failed pi=");
            print_u64(pi as u64);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" page=0x");
            print_hex((page >> 32) as u32);
            print_hex(page as u32);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"guard-page", lp.msg.m0, addr));
        }
    }
    match nt_handler.service_committed_private_page_residency(
        pi, page, vm_fault_access_from_x86_error(lp.msg.m3),
        nt_address_space::ImageFaultObservation::from_x86_error(lp.msg.m3),
    ) {
        Ok(Some(())) => {
            note_boot_progress(BootProgress::PageMappingPublished);
            lp.exit.faults += 1;
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        Ok(None) => {}
        Err(status) => {
            print_str(b"[private-page] fault failed status=0x");
            print_hex(status);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"private-page", lp.msg.m0, addr));
        }
    }
    match crate::native_image_pagein_work::submit(
        &mut nt_handler, pi, page, vm_fault_access_from_x86_error(lp.msg.m3),
        nt_address_space::ImageFaultObservation::from_x86_error(lp.msg.m3),
    ) {
        Ok(true) => {
            crate::native_image_pagein_work::redrive(&mut nt_handler, &nt_dispatcher);
            let _ = finalize_service_loop_state(&mut nt_handler);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        }
        Ok(false) => {}
        Err(status) => {
            print_str(b"[native-image] deferred fault admission failed status=0x");
            print_hex(status);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"native-image-pagein-admission", lp.msg.m0, addr));
        }
    }
    match nt_handler.service_native_image_page_residency(
        pi, page, vm_fault_access_from_x86_error(lp.msg.m3), nt_address_space::ImageFaultObservation::from_x86_error(lp.msg.m3),
    ) {
        Ok(Some(())) => {
            note_boot_progress(BootProgress::PageMappingPublished);
            lp.exit.faults += 1;
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        Ok(None) => {}
        Err(status) => {
            print_str(b"[native-image] fault failed status=0x");
            print_hex(status);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"native-image", lp.msg.m0, addr));
        }
    }
    match service_generic_section_fault(
        &mut nt_handler,
        generic_sections,
        pi,
        page,
        pml4,
        scratch_base,
        vm_fault_access_from_x86_error(lp.msg.m3),
        true,
        false,
    ) {
        Ok(GenericSectionFaultResult::Mapped) => {
            note_boot_progress(BootProgress::PageMappingPublished);
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        Ok(GenericSectionFaultResult::RoutedPageIn) => {
            match crate::section_pagein_work::submit(
                &mut nt_handler, pi, page, vm_fault_access_from_x86_error(lp.msg.m3),
            ) {
                Ok(()) => {
                    crate::section_pagein_work::redrive(&mut nt_handler);
                    let _ = finalize_service_loop_state(&mut nt_handler);
                    let received = receive(
                        &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
                    )?;
                    lp.msg.badge = received.0;
                    lp.msg.mi = received.1;
                    lp.msg.m0 = received.2;
                    lp.msg.m1 = received.3;
                    lp.msg.m2 = received.4;
                    lp.msg.m3 = received.5;
                    return ControlFlow::Break(Turn::Next);
                }
                Err(status) => {
                    print_str(b"[section] deferred fault admission failed status=0x");
                    print_hex(status);
                    print_str(b"\n");
                    return ControlFlow::Break(lp.park_and_log(pi, b"section-pagein-admission", lp.msg.m0, addr));
                }
            }
        }
        Ok(GenericSectionFaultResult::Unmapped) => {}
        Err(status) => {
            print_str(b"[section] fault failed pi=");
            print_u64(pi as u64);
            print_str(b" page=0x");
            print_hex((page >> 32) as u32);
            print_hex(page as u32);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"section-fault", lp.msg.m0, addr));
        }
    }
    // Route image faults through the committed view table. The table proves that this
    // process owns an image allocation at the faulting page; PE globals/registry state only
    // identify the bytes used to fill that committed view.
    let (base, img_hi, tpe) = if let Some(image_owner) =
        process_committed_image_allocation(pi as u64, page)
    {
        let base = image_owner.allocation_base;
        let tpe = if base == img_base {
            pe
        } else if nt_base != 0 && base == nt_base {
            lp.exit.ntfaults += 1;
            ntdll.1
        } else if let Some((i, _)) = if pi >= 1 {
            reg.dll_for_page(pi, base)
        } else {
            None
        } {
            // A mapped registry DLL (csrsrv/basesrv/winsrv/Win32 stack) in a DLL-loading
            // process's VSpace (csrss pi==1 OR winlogon pi==2) — demand-page it from
            // that DLL's parsed PE. The committed view table resolves ownership; the
            // registry maps the allocation base to the parsed PE bytes.
            dll_pe_store.as_slice()[i].as_ref().unwrap()
        } else {
            print_str(b"[vmf-image-owner] no PE for committed image allocation pi=");
            print_u64(pi as u64);
            print_str(b" base=0x");
            print_hex((base >> 32) as u32);
            print_hex(base as u32);
            print_str(b" page=0x");
            print_hex((page >> 32) as u32);
            print_hex(page as u32);
            print_str(b"\n");
            return ControlFlow::Break(lp.park_and_log(pi, b"image-owner", lp.msg.m0, addr))
        };
        (base, image_owner.allocation_end, tpe)
    } else {
        let fault_tcb = event_runtime.tcb;
        // DIAG: dump the fault so we can tell a stack-growth fault (addr just below the
        // stack) from a real null deref. m0=IP, m1=addr(cr2), m2=prefetch, m3=fsr.
        print_str(b"[vmf-out] ip=0x");
        print_hex((lp.msg.m0 >> 32) as u32);
        print_hex(lp.msg.m0 as u32);
        print_str(b" addr=0x");
        print_hex((addr >> 32) as u32);
        print_hex(addr as u32);
        print_str(b" pf=");
        print_u64(lp.msg.m2);
        print_str(b" fsr=");
        print_u64(lp.msg.m3);
        print_str(b" img_end=0x");
        print_hex((img_end >> 32) as u32);
        print_hex(img_end as u32);
        print_str(b" stack=[0x");
        print_hex(STACK_BASE as u32);
        print_str(b"..0x");
        print_hex((STACK_BASE + STACK_FRAMES * 0x1000) as u32);
        print_str(b")\n");
        // On an INSTRUCTION-FETCH fault (ip==addr), execution CALLed/JMPed
        // through a bad/truncated code pointer. Read the faulting thread's real GPRs + walk its
        // stack (TCB rsp) for return addresses in any mapped module — this identifies the CALLER
        // (module + RVA) whose indirect transfer landed on the bad pointer. General class-of-wall
        // diagnostic; applies to any process at quiescence.
        if lp.msg.m0 == addr {
            if fault_tcb != 0 {
                let mut regs = [0u64; 20];
                crate::win32k_glue::tcb_read_regs20(fault_tcb, &mut regs);
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
                let diagnostic_process = nt_handler.capture_process_identity(pi);
                // ★ TRUNC PROBE: [rsp] is the return address the CALLER pushed with its
                // `call [mem]` that jumped to the bare RVA. Print [rsp+0..0x20] unconditionally
                // so the immediate caller (module+RVA) is visible.
                print_str(b"[trunc] top-of-stack:");
                {
                    let mut j: u64 = 0;
                    while j < 4 {
                        let Some(v) = read_fault_stack_word(
                            &nt_handler, pi, diagnostic_process, rsp, j, scratch_base,
                        ) else {
                            print_str(b" [unavailable]");
                            break;
                        };
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
                    let Some(v) = read_fault_stack_word(
                        &nt_handler, pi, diagnostic_process, rsp, k, scratch_base,
                    ) else {
                        print_str(b" [unavailable]");
                        break;
                    };
                    let is_ntdll = v >= 0x0000_0100_0000_0000 && v < 0x0000_0100_0100_0000;
                    // Widen to ALL mapped DLLs (0x8000_0000..0x8300_0000 covers rpcrt4/lsasrv/…)
                    // + hosted image/env pointers so the immediate rpcrt4/lsasrv caller +
                    // the heap/env dispatch object are captured.
                    let is_dll = v >= 0x8000_0000 && v < 0x8300_0000;
                    let is_hosted_image = v >= img_base && v < img_end;
                    let is_hosted_env = v >= HOSTED_CLIENT_ENV_BASE
                        && v < HOSTED_CLIENT_ENV_BASE + 0x20_0000;
                    if is_ntdll || is_dll || is_hosted_image || is_hosted_env {
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
        // A client that faults while a win32k user-mode callback is in flight: dump the exact
        // client-side state user32 used to derive the PWND it dereferenced (see
        // `dump_client_callback_crash_state`). Callback-scoped, so it costs nothing on any
        // other wall.
        win32k_glue::dump_client_callback_crash_state(pi, fault_tcb);
        // ★ Checkpoint B containment: once lsass has signaled LSA_RPC_SERVER_ACTIVE (its
        // essential init is done), an unrecoverable fault on lsass' MAIN thread (badge 8) —
        // e.g. rpcrt4 NdrSimpleTypeUnmarshall dereferencing a bogus RPC request buffer
        // (cr2 ~0xe000002d6) while its RPC server services a self-directed call — is CONTAINED:
        // PARK that thread (recv the next event without replying, leaving it blocked) so the
        // boot advances to winlogon's WaitForLsass/login instead of stopping. Same philosophy
        // as the N-threads listener-park; scoped so it can't mask a pre-signal lsass fault or
        // any other process's fault.
        // DbgkForwardException (same shape as the null-deref site above): report the
        // unmapped-address access violation to a debugger BEFORE either terminal branch.
        if dbgk_forward_exception(nt_handler, pi, nt_process::dbgk::ExceptionRecord::access_violation( lp.msg.m0, if lp.msg.m3 & 0x10 != 0 { 8 } else if lp.msg.m3 & 0x2 != 0 { 1 } else { 0 }, addr, )) && dbgk_block_and_park(
            &mut lp.exit, &mut lp.parks, &mut lp.ingress, nt_handler, procs, pfilled,
            filled_pages, pi, nt_process::dbgk::DBGK_BLOCK_VM_FAULT, lp.msg.m0, 0, 0, &mut lp.msg,
        )?
        {
            // BLOCKED on the debugger's continue; the next event is already received. A
            // `DBG_CONTINUE` replies length-0 → the faulting instruction is RETRIED.
            return ControlFlow::Break(Turn::Next);
        }
        if hosted_owner_has_role(
            &nt_handler,
            lp.msg.badge,
            nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
        ) && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
        {
            assert!(drop_current_hosted_reply(), "terminal service fault must retire its Call");
            print_str(b"[fault] lsass main unrecoverable fault POST-LSA-signal -> terminal thread containment\n");
            // Terminal for lsass main — count toward quiesce (lsass has done its signalling job).
            lp.parks.crash_parked |= owner_bit_for_badge(&nt_handler, lp.msg.badge);
            service_watchdog_record_crash_parked(lp.parks.crash_parked);
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            if !cfg!(feature = "mup-provider-kernel-only")
                && (live_top_badges(&nt_handler) & !(lp.parks.crash_parked | lp.parks.wait_parked)) == 0
                && !pre_user_shell_frontier_pending(
                    &nt_handler,
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                    b"lsass-post-signal-fault",
                )
                && !defer_quiesce_for_active_user_callbacks(b"lsass-post-signal-fault")
                && !driver_launch::native_disk_proof_hardware_irp_pending()
                && !driver_launch::active_relation_wal_retained()
                && !crate::mounted_volume::mounted_create_outstanding()
                && !crate::mounted_volume::mounted_read_outstanding()
                && !crate::mounted_volume::mounted_directory_outstanding()
                && !driver_launch::mounted_native_physical_irp_pending()
                && !crate::native_directory_open_work::occupied()
                && !crate::native_file_target_open_work::occupied()
                && !crate::native_directory_effect_work::has_outstanding(&nt_handler)
                && !crate::provider_directory_broker::has_outstanding()
            {
                driver_launch::print_mounted_native_block_quiesce_snapshot();
                print_str(b"[quiesce] every live process parked/waiting (no signaler left) -> run gate\n");
                lp.exit.stop = addr;
                lp.exit.record(b"fault-all-live-waiting");
                return ControlFlow::Break(Turn::Exit);
            }
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        // ★ WINLOGON POST-LOGON MILESTONE PARK. winlogon's main thread has, by this point,
        // COMPLETED the interactive logon for real: `LsaLogonUser` returned SUCCESS, lsass
        // duplicated the `NtCreateToken` token into winlogon's handle table and winlogon
        // queried it (`WINLOGON_LOGON_TOKEN_QUERIES`). Its post-logon path (profile load →
        // `userinit.exe`) is the NEXT frontier and it faults there — measured: our own
        // ntdll's `RtlQueryInformationActivationContext` reads
        // `TEB.ActivationContextStackPointer->ActiveFrame` and finds a NON-POINTER value.
        //
        // Park at the achieved milestone instead of crash-parking. The difference is not
        // cosmetic: `park_and_log!` calls `unwind_dead_client_user_callbacks(pi)`, which
        // latches the WHOLE process as a dead win32k callback client — wrong here, because
        // this is ONE thread and winlogon's worker threads are alive, hold no callback
        // frames (asserted, not assumed) and are still valid callback clients. The faulting
        // thread is left blocked at its fault exactly as any other park leaves its thread.
        //
        // ★ ANY winlogon THREAD, not just badge 4. The post-logon profile/`userinit` work is
        // driven from whichever winlogon thread `WlxActivateUserShell` runs on, and once the
        // profile copy really advanced (batch 59) the fault landed on a WORKER badge — which
        // fell through to `park_and_log!` and latched the whole process as a dead win32k
        // callback client, disarming both post-quiesce callback injections. The guard that
        // makes this safe is the callback-frame assertion below, which is per-PROCESS, so it
        // holds for any of its threads.
        if hosted_pi_has_role(
            &nt_handler,
            pi,
            nt_exe_image::HostedProcessRole::InteractiveLogon,
        ) && hosted_owner_has_role(
            &nt_handler,
            lp.msg.badge,
            nt_exe_image::HostedProcessRole::InteractiveLogon,
        ) && WINLOGON_LOGON_TOKEN_QUERIES.load(Ordering::Relaxed) != 0
            && !win32k_glue::client_has_active_callback_frames(pi as u32)
        {
            assert!(drop_current_hosted_reply(), "terminal post-logon fault must retire its Call");
            print_str(b"[wl-main] winlogon COMPLETED THE INTERACTIVE LOGON (LsaLogonUser SUCCESS + logon token received/queried); its POST-LOGON path faults at ip=0x");
            print_hex((lp.msg.m0 >> 32) as u32);
            print_hex(lp.msg.m0 as u32);
            print_str(b" cr2=0x");
            print_hex((addr >> 32) as u32);
            print_hex(addr as u32);
            print_str(
                b" -> terminal thread containment (no callback frame; other threads continue)\n",
            );
            lp.parks.crash_parked |= owner_bit_for_badge(&nt_handler, lp.msg.badge);
            service_watchdog_record_crash_parked(lp.parks.crash_parked);
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            WINLOGON_POST_LOGON_MILESTONE_PARK.store(lp.msg.m0, Ordering::Relaxed);
            WINLOGON_POST_LOGON_MILESTONE_CR2.store(addr, Ordering::Relaxed);
            // Same terminal rule `park_and_log!` applies to a parked winlogon: once the LSA
            // server has signalled, services/lsass are idle RPC servers with no live client
            // left, so a parked winlogon leaves NO runnable signaler and the next `recv`
            // would block forever (measured: RUNEXIT=124 without this clause).
            if ((live_top_badges(&nt_handler) & !(lp.parks.crash_parked | lp.parks.wait_parked)) == 0
                || LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0)
                && !pre_user_shell_frontier_pending(
                    &nt_handler,
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                    b"winlogon-post-logon-syscall",
                )
                && !defer_quiesce_for_active_user_callbacks(b"winlogon-post-logon-syscall")
            {
                print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
                lp.exit.stop = lp.msg.m0;
                lp.exit.record(b"winlogon-post-logon-syscall");
                return ControlFlow::Break(Turn::Exit);
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        // Unrecoverable fault outside every mapped image/DLL/scratch/stack (a truncated code
        // pointer / bad address the diagnostics above symbolized) — a real crash. Park+log.
        // park_and_log! diverges (type `!`) so this arm yields no value — match type is satisfied.
        return ControlFlow::Break(lp.park_and_log(pi, b"vmf-out", lp.msg.m0, addr))
    };
    // Per-process demand-fault backstop. With the BATCH-22 scratch-VA decoupling (persistent
    // scratch bounded to ≤256 slots regardless of this count) this is now purely a
    // frame-budget / runaway guard, not a scratch limit — raised so lsass's full LSA-init DLL
    // tree (lsasrv/samsrv/msv1_0 + deps, thousands of pages) fits.
    if lp.exit.faults >= SEC_IMAGE_FAULT_CAP {
        // This process exhausted its per-process demand-fault budget (runaway / frame-pool
        // guard) — treat as unrecoverable for THIS process: park+log, let the others proceed.
        return ControlFlow::Break(lp.park_and_log(pi, b"fault-cap", lp.msg.m0, addr));
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
    // The mandatory faulting page is handled first by the reusable Mm residency operation.
    // The `img_hi` bound then limits optional PRE-fill pages to this committed allocation.
    // Prefetch pages are only installed when genuinely unmapped in this process.
    // Prefetch a bounded forward window from the page the process actually touched. Whole-image
    // eager mapping made every untouched section resident and retained one root-CNode cap for
    // each scratch mapping plus one for each process mapping. A broad LSASS dependency scan
    // therefore exhausted the finite root CSpace before those pages were ever referenced.
    // A small forward run amortizes the QEMU fault round-trip while preserving genuine
    // demand paging; once root-slot, frame-registry, or root-Untyped pressure approaches the
    // gate, shrink the speculative run so late service DLL loads stop pre-residenting mostly
    // untouched pages.
    let forward_policy = sec_image_forward_policy();
    let (batch_start, batch_pages) = (page, forward_policy.pages);
    let mut allocation_failed = false;
    let mut image_protect_failed = false;
    let mut fault_page_serviced = true;
    let image_fault_access = vm_fault_access_from_x86_error(lp.msg.m3);
    if let Err(status) = service_image_page_residency(
        &mut nt_handler,
        pi,
        page,
        base,
        tpe,
        pml4,
        scratch_base,
        image_fault_access,
        true,
        filled_pages,
        &mut lp.exit.faults,
    ) {
        print_str(b"[vmf-image] residency failed pi=");
        print_u64(pi as u64);
        print_str(b" page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
        image_protect_failed = status == nt_address_space::STATUS_ACCESS_VIOLATION;
        allocation_failed = true;
        fault_page_serviced = false;
    }
    for bi in 1..batch_pages {
        if allocation_failed || lp.exit.faults >= SEC_IMAGE_FAULT_CAP {
            break;
        }
        let bpage = batch_start + bi * 0x1000;
        if bpage >= img_hi || bpage < base {
            break;
        }
        let Some(info) = process_committed_mapping_basic_information(pi as u64, bpage)
            .filter(|info| info.type_ == nt_address_space::MEM_IMAGE)
        else {
            break;
        };
        if nt_address_space::image_view_fault_access_status(
            info.protect,
            nt_address_space::FaultAccess::Lock,
        )
        .is_err()
        {
            break;
        }
        let plan = nt_address_space::image_view_fault_plan(info.protect, false);
        let shareable = sec_image_page_shareable(
            tpe, (bpage - base) as u32, base, img_base, info.protect, plan,
        );
        if !shareable && !forward_policy.private_neighbours {
            SEC_IMAGE_PRIVATE_PREFETCH_SKIPS.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let Some(process) = nt_handler.capture_process_identity(pi) else {
            break;
        };
        let shared_present = match shared_image_mapping_contains_for(pi as u64, process, bpage) {
            Ok(present) => present,
            Err(_) => break,
        };
        if csrss_frame_get_exact_record(pi as u64, bpage).is_some()
            || shared_present
            || (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).contains(pi as u64, bpage)
            || (shareable && dll_cache_get(bpage) != 0)
        {
            continue;
        }
        // Speculation uses the same admission/publication as a demand fault. A failure
        // stops optional work; it does not undo or park the successfully serviced fault.
        if service_image_page_residency(
            &mut nt_handler,
            pi,
            bpage,
            base,
            tpe,
            pml4,
            scratch_base,
            nt_address_space::FaultAccess::Lock,
            false,
            filled_pages,
            &mut lp.exit.faults,
        )
        .is_err()
        {
            break;
        }
    }
    // Image faults bypass the native-syscall reply tail below, but can grow several durable
    // mapping/cache authorities. Apply the same ownership barrier as every other receive.
    let _ = finalize_service_loop_state(&mut nt_handler);
    if allocation_failed {
        if image_protect_failed {
            return ControlFlow::Break(lp.park_and_log(pi, b"image-protect", lp.msg.m0, addr));
        } else {
            return ControlFlow::Break(lp.park_and_log(pi, b"image-map-resource", lp.msg.m0, addr));
        }
    }
    if fault_page_serviced {
        note_boot_progress(BootProgress::PageMappingPublished);
    }
    procs[pi].faults = lp.exit.faults;
    procs[pi].first = lp.exit.first;
    procs[pi].ntfaults = lp.exit.ntfaults;
    pfilled[pi] = *filled_pages;
    let (nb, nmi, nm0, nm1, nm2, nm3) = reply_receive(
        &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (local().reply_main_slot.load(Ordering::Relaxed), 0, 0, 0, 0, 0),
    )?;
    lp.msg.badge = nb;
    lp.msg.mi = nmi;
    lp.msg.m0 = nm0;
    lp.msg.m1 = nm1;
    lp.msg.m2 = nm2;
    lp.msg.m3 = nm3;
    return ControlFlow::Break(Turn::Next);
}
