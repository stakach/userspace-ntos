//! What the executive does after the service loop ends (issue #382, loop hoist).
//!
//! The terminal receipt of the loop, the quiesce checkpoint, the boot self-tests and
//! acceptance reports, and the verdict returned to `_start`. The text is the tail of
//! `service_sec_image()`, moved verbatim; it rebinds the loop's state from `LoopState` under
//! the names it had as locals.
//!
//! This is the first file of the `diag/` directory of the target layout. Like the hoisted
//! loop it is declared from `service_sec_image.rs`, whose private helpers it still reaches.

use super::*;

pub(super) unsafe fn report(
    lp: &mut LoopState<'_>,
    csrss_pi: usize,
) -> (
    u64,
    u64,
    u64,
    u64,
    u64,
    BootDriverStartReports,
    NativeDriverLoadReport,
    LiveDeviceActionReport,
    StartDeviceCallReport,
    DesktopAcceptanceReport,
) {
    if cfg!(feature = "mup-provider-kernel-only") {
        // This profile has no desktop verdict. Retain all live owners if its pump terminates.
        print_str(b"[mup-provider-gate] terminal service-loop failure\n");
        park();
    }
    // The loop's state under its old names. `lp` stays where the setup frame holds it: the
    // handler's loop context still records addresses inside it.
    let LoopExit {
        stop, stop_ssn, service_loop_exit_site, service_loop_exit_reason, iters, dbgsvc, ..
    } = lp.exit;
    let Parks { crash_parked, wait_parked, .. } = lp.parks;
    let ssn_ring = &*lp.diag.ssn_ring;
    let ssn_ring_badge = &*lp.diag.ssn_ring_badge;
    let wl_ring = &*lp.diag.wl_ring;
    let wl_ri = lp.diag.wl_ri;
    let ssn_ri = lp.diag.ssn_ri;
    let Message { badge, mi, m0, m1, m3, .. } = lp.msg;
    let root_add_device_turn = &lp.ingress.root_add_device_turn;
    let delay_queue = lp.ingress.delay_queue;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let csrss_process_handle = lp.procs.csrss_process_handle;
    let primary_pi = lp.procs.primary_pi;
    let hosted_loaded_images = &mut *lp.images.hosted_loaded_images;
    let reg = &mut *lp.images.reg;
    let ntdll = lp.images.ntdll;
    let mut nt_handler = &mut *lp.handler;
    let nt_dispatcher = lp.dispatcher;
    // One terminal receipt, before checkpointing can obscure the branch that ended the
    // serialized loop. Every field below is an observation; no owner or dirty bit is consumed.
    let ingress_hold = unsafe {
        crate::spawn_hosts::shared_ingress::owner::runtime::hold_snapshot()
    };
    let (callback_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
    print_str(b"[service-loop-exit] reason=");
    print_str(service_loop_exit_reason);
    print_str(b" site=");
    print_u64(service_loop_exit_site as u64);
    print_str(b" stop=");
    print_hex_u64(stop);
    print_str(b" stop-ssn=");
    print_u64(stop_ssn);
    print_str(b" badge/label/m0/reply=");
    print_u64(badge);
    print_str(b"/");
    print_u64(mi >> 12);
    print_str(b"/");
    print_hex_u64(m0);
    print_str(b"/");
    print_u64(REPLY_MAIN_SLOT.load(Ordering::Relaxed));
    print_str(b" child-pending=");
    print_u64(u64::from(crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()));
    print_str(b" add-device-owner=");
    match root_add_device_turn.as_ref().map(|turn| turn.owner()) {
        Some(RootAddDeviceOwner::DriverStart(owner)) => {
            print_str(b"driver-start/");
            print_u64(owner.slot() as u64);
        }
        Some(RootAddDeviceOwner::PnpRebalance(owner)) => {
            print_str(b"pnp-rebalance/");
            print_u64(owner.slot() as u64);
        }
        None => print_str(b"none"),
    }
    print_str(b" callbacks/continuations/dispatch/suspended=");
    print_u64(callback_depth as u64);
    print_str(b"/");
    print_u64(continuation_depth as u64);
    print_str(b"/");
    print_u64(spawn_hosts::dispatch_depth());
    print_str(b"/");
    print_u64(spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed));
    print_str(b" snapshot-dirty=");
    print_u64(u64::from(crate::writable_fs::snapshot_dirty_for_diagnostics()));
    print_str(b" live/crash/wait=");
    print_hex_u64(live_top_badges(&nt_handler));
    print_str(b"/");
    print_hex_u64(crash_parked);
    print_str(b"/");
    print_hex_u64(wait_parked);
    print_str(b"\n");
    if let Some(running) = ingress_hold.running {
        print_str(b"[service-loop-exit-owner] running lane/gen/epoch/route/executor/reply/tcb=");
        print_u64(running.lane.index as u64);
        print_str(b"/");
        print_u64(running.lane.generation);
        print_str(b"/");
        print_u64(running.dispatch.map_or(0, |dispatch| dispatch.epoch()));
        print_str(b"/");
        print_u64(running.route.map_or(0, |route| route.badge()));
        print_str(b"/");
        print_u64(running.binding.map_or(0, |binding| binding.executor_id));
        print_str(b"/");
        print_u64(running.binding.map_or(0, |binding| binding.reply_object));
        print_str(b"/");
        print_u64(running.physical.map_or(0, |source| source.tcb));
        print_str(b" quarantined=");
        print_u64(u64::from(running.quarantined.unwrap_or(false)));
        print_str(b"\n");
    }
    if let Some(oldest) = ingress_hold.oldest {
        print_str(b"[service-loop-exit-owner] oldest pi/pid/generation/tid/badge/reply/executor/admission=");
        print_u64(oldest.binding.pi as u64);
        print_str(b"/");
        print_u64(oldest.binding.process.pid as u64);
        print_str(b"/");
        match oldest.binding.process.generation {
            nt_types::ProcessGeneration::Hosted(generation) => {
                print_str(b"hosted:");
                print_u64(generation);
            }
            nt_types::ProcessGeneration::Temporary(generation) => {
                print_str(b"temporary:");
                print_u64(generation);
            }
        }
        print_str(b"/");
        print_u64(oldest.binding.tid);
        print_str(b"/");
        print_u64(oldest.binding.badge);
        print_str(b"/");
        print_u64(oldest.reply);
        print_str(b"/");
        print_u64(oldest.executor);
        print_str(b"/");
        print_u64(oldest.admission_sequence);
        print_str(b"\n");
    }
    nt_handler.loop_ctx = nt_handler.loop_ctx.map(|ctx| ctx.checkpoint_live());
    // Attribute a busy snapshot reserve before the terminal durability proof attempts to
    // acquire it. These owners are inspected once, after the serialized service loop exits.
    unsafe {
        crate::writable_fs::snapshot_storage::print_quiesce_header_owner();
        crate::writable_fs::print_quiesce_snapshot_owners();
        crate::registry_mutation_work::print_quiesce_owners();
        print_str(b"[quiesce-hive-journal] boot=");
        print_u64(u64::from(crate::writable_fs::hive_wal::has_retained_boot_hive_journal()));
        print_str(b" native=");
        print_u64(u64::from(crate::writable_fs::hive_wal::has_retained_native_hive_journal()));
        print_str(b"\n");
    }
    let quiesce_cm_status = checkpoint_boot_hives_at_quiesce(&mut nt_handler);
    if quiesce_cm_status != nt_fs::STATUS_SUCCESS {
        print_str(b"[cm-flush] shutdown hive durability refused status=0x");
        print_hex(quiesce_cm_status);
        print_str(b"\n");
        park();
    }
    dump_all_hosted_thread_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_interactive_logon_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_lsa_readiness_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_services_start_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_interactive_shell_frontier_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    dump_hot_hosted_thread_quiesce(
        &nt_handler,
        &*hosted_loaded_images,
        &reg,
        ntdll,
        procs,
        pfilled,
    );
    // ★ THE ESCAPE HATCH (unconditional, bounded). The service loop is done: release every reporter
    // still blocked on a debug event, so a debugger that attached, took an event and never continued
    // (or died holding one) can NEVER leave a target parked with its reply capability stranded. With
    // no debug object alive — every boot today — this returns on its first line and costs nothing.
    {
        let released = nt_handler.dbgk_release_all_blocked_reporters();
        if released != 0 {
            print_str(b"[dbgk] post-loop drain released ");
            print_u64(released as u64);
            print_str(b" blocked reporter(s)\n");
        }
    }
    // === PRIVATE-VM COMMIT/DECOMMIT/RE-COMMIT SELF-TEST (POST-QUIESCE). Runs on the real
    // `vm_map_private_page` path in a real hosted VSpace, at a VA above every placement the boot
    // makes, so it perturbs nothing. See `private_vm_unmap_selftest`. ===
    if let Some(logon_pi) = hosted_pi_for_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) {
        crate::private_vm_unmap_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
        crate::working_set_transition_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
        crate::mapped_section_writeback_selftest(procs[logon_pi].scratch_base);
        crate::mapped_section_writecopy_cow_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
        crate::image_writecopy_cow_selftest(
            &mut nt_handler,
            logon_pi,
            procs[logon_pi].pml4,
            procs[logon_pi].scratch_base,
        );
    } else {
        print_str(b"[private-vm] no runtime-registered interactive logon process -> skipped\n");
    }
    // === Path 2 lifecycle self-test (POST-LOOP: no more per-syscall heap reset follows, so these
    // durable pm allocations are safe). Proves NtOpenProcess + NtTerminateProcess route through pm.
    // The 3 HOSTED EPROCESSes are left untouched — terminate runs on a THROWAWAY process. ===
    {
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
                let _ = owner;
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
        let tpid = nt_handler
            .pm
            .create_process("lifecycle-test.exe", parent, None);
        if let Ok(ttid) = nt_handler.pm.create_thread(tpid, 0x1000, 0, false) {
            let th = nt_handler
                .pm
                .insert_handle(tpid, nt_process::HandleObject::Opaque(0xDEAD), 0)
                .ok();
            nt_handler.pi = 0;
            if nt_handler.resolve_process_handle(0xFFFF_FFFF_FFFF_FFFF)
                == nt_handler.pm_pid_for_pi(0)
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
        // throwaway processes/threads only -> the 6 hosted processes are untouched.
        {
            use nt_process::{HandleObject, ProcessState, ThreadState};
            const THREAD_TERMINATE: u32 = 0x0001;
            let mut term_ok = 0u64;
            let parent = nt_handler.pm_pid_for_pi(0);
            // Process A: two threads. `victim` is terminated via a typed Thread handle; `bystander`
            // must keep running (proves per-thread, not per-process, termination).
            let pa = nt_handler
                .pm
                .create_process("term-selftest-a.exe", parent, None);
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
                        .resolve_terminate_thread_handle(
                            pa,
                            bystander,
                            hna as u64,
                            THREAD_TERMINATE,
                        )
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
                    && nt_handler.pm.thread(victim).is_some_and(|t| {
                        t.state == ThreadState::Terminated && t.exit_status == Some(0xDEAD)
                    })
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
            let pb = nt_handler
                .pm
                .create_process("term-selftest-b.exe", parent, None);
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

        // === Dbgk END-TO-END SELF-TEST (POST-LOOP) =================================================
        // Drives the REAL user-mode debugging plane the five native handlers dispatch into:
        // create a DEBUG_OBJECT, mint a TYPED handle for it in smss's REAL EPROCESS handle table and
        // resolve it through the handler's own `debug_object_for_handle` (access checks included),
        // attach it to a THROWAWAY debuggee, retrieve the fake create-process message with
        // NtWaitForDebugEvent's core (handles opened in the debugger's table + a rendered
        // DBGUI_WAIT_STATE_CHANGE), resolve it with NtDebugContinue, observe the thread-create /
        // thread-exit / process-exit EVENT SOURCES, then detach and prove the plane goes inert.
        // The 3 hosted EPROCESSes are otherwise untouched (only smss gains + loses handles).
        {
            use nt_process::dbgk;
            nt_handler.pi = 0;
            let mut dbg_ok = 0u64;
            let debugger_pid = nt_handler.pm_pid_for_pi(0);
            if let Some(debugger_pid) = debugger_pid {
                let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
                let bad_flags_rejected = nt_handler.pm.create_debug_object(0x8000)
                    == Err(nt_process::STATUS_INVALID_PARAMETER);
                if let Ok(object) = nt_handler
                    .pm
                    .create_debug_object(dbgk::DBGK_KILL_PROCESS_ON_EXIT)
                {
                    if bad_flags_rejected
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.kill_process_on_exit())
                    {
                        dbg_ok |= 0x0001;
                    }
                    // 0x1000 — the handler's typed-handle resolution + access enforcement, driven
                    // against smss's REAL per-process handle table.
                    let full = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            dbgk::DEBUG_OBJECT_ALL_ACCESS,
                        )
                        .ok();
                    let no_access = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            0,
                        )
                        .ok();
                    let wrong_type = nt_handler
                        .pm
                        .insert_handle(debugger_pid, nt_process::HandleObject::Opaque(0xDB6), 0)
                        .ok();
                    if full.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(
                            h as u64,
                            dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                        ) == Ok(object)
                    }) && no_access.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(
                            h as u64,
                            dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                        ) == Err(0xC000_0022)
                    }) && wrong_type.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(h as u64, 0) == Err(0xC000_0024)
                    }) {
                        dbg_ok |= 0x1000;
                    }
                    for handle in [full, no_access, wrong_type].into_iter().flatten() {
                        let _ = nt_handler.pm.close_handle(debugger_pid, handle);
                    }

                    // A throwaway debuggee with a real image base + main thread.
                    let target = nt_handler
                        .pm
                        .create_process("dbgk-selftest.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_4000_0000);
                    if let Ok(main) = nt_handler.pm.create_thread(target, 0x2000, 0, false) {
                        let debugger = nt_process::ClientId {
                            unique_process: debugger_pid,
                            unique_thread: debugger_tid,
                        };
                        // 0x0002 — attach installs the port + PEB.BeingDebugged and posts + activates
                        // the fake DbgKmCreateProcessApi message.
                        if nt_handler.pm.debug_active_process(target, object, debugger) == Ok(1)
                            && nt_handler.pm.process_debug_port(target) == Some(object)
                            && nt_handler.pm.is_process_being_debugged(target)
                            && nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.len() == 1 && o.events_present())
                        {
                            dbg_ok |= 0x0002;
                        }
                        // 0x0004 — a self-attach is denied and a second attach is PORT_ALREADY_SET.
                        if let Ok(second) = nt_handler.pm.create_debug_object(0) {
                            if nt_handler
                                .pm
                                .debug_active_process(debugger_pid, second, debugger)
                                == Err(nt_process::STATUS_ACCESS_DENIED)
                                && nt_handler.pm.debug_active_process(target, second, debugger)
                                    == Err(dbgk::STATUS_PORT_ALREADY_SET)
                            {
                                dbg_ok |= 0x0004;
                            }
                            nt_handler.pm.destroy_debug_object(second);
                        }
                        // 0x0008 / 0x0010 — the wait retrieves it, with REAL handles opened in the
                        // debugger's table and the state change rendered around them.
                        if let Ok(Some(result)) =
                            nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                        {
                            let sc = &result.state_change;
                            let u64_at = |o: usize| {
                                u64::from_le_bytes(sc[o..o + 8].try_into().unwrap_or([0; 8]))
                            };
                            if result.state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                                && result.client_id.unique_process == target
                                && result.client_id.unique_thread == main
                                && u64_at(0x08) == target as u64
                                && u64_at(0x38) == 0x0000_0001_4000_0000
                                && u64_at(0x50) == 0x2000
                            {
                                dbg_ok |= 0x0008;
                            }
                            if result.handle_to_process != 0
                                && result.handle_to_thread != 0
                                && nt_handler
                                    .pm
                                    .lookup_handle(debugger_pid, result.handle_to_process)
                                    == Some(nt_process::HandleObject::Process(target))
                                && nt_handler
                                    .pm
                                    .lookup_handle(debugger_pid, result.handle_to_thread)
                                    == Some(nt_process::HandleObject::Thread(main))
                                && u64_at(0x18) == result.handle_to_process as u64
                                && u64_at(0x20) == result.handle_to_thread as u64
                            {
                                dbg_ok |= 0x0010;
                            }
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, result.handle_to_process);
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, result.handle_to_thread);
                            // 0x0020 — one outstanding event per debuggee process.
                            if matches!(
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid),
                                Ok(None)
                            ) {
                                dbg_ok |= 0x0020;
                            }
                            // 0x0040 — continue validates its status and resolves the read event.
                            if nt_handler
                                .pm
                                .debug_continue(object, result.client_id, 0x1234)
                                == Err(nt_process::STATUS_INVALID_PARAMETER)
                                && nt_handler
                                    .pm
                                    .debug_continue(object, result.client_id, dbgk::DBG_CONTINUE)
                                    .is_ok()
                                && nt_handler
                                    .pm
                                    .debug_object(object)
                                    .is_some_and(|o| o.is_empty())
                            {
                                dbg_ok |= 0x0040;
                            }
                        }
                        // 0x0080 — EVENT SOURCE: thread create.
                        if let Ok(worker) = nt_handler.pm.create_thread(target, 0x3000, 0, false) {
                            if let Ok(Some(created)) =
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                            {
                                if created.state == dbgk::DBG_CREATE_THREAD_STATE_CHANGE
                                    && created.client_id.unique_thread == worker
                                    && u64::from_le_bytes(
                                        created.state_change[0x28..0x30]
                                            .try_into()
                                            .unwrap_or([0; 8]),
                                    ) == 0x3000
                                {
                                    dbg_ok |= 0x0080;
                                }
                                let _ = nt_handler
                                    .pm
                                    .close_handle(debugger_pid, created.handle_to_thread);
                                let _ = nt_handler.pm.debug_continue(
                                    object,
                                    created.client_id,
                                    dbgk::DBG_CONTINUE,
                                );
                            }
                            // 0x0100 — EVENT SOURCE: thread exit (no cascade: main still lives).
                            let _ = nt_handler.pm.exit_thread(worker, 0x1234);
                            if let Ok(Some(exited)) =
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                            {
                                if exited.state == dbgk::DBG_EXIT_THREAD_STATE_CHANGE
                                    && exited.client_id.unique_thread == worker
                                    && u32::from_le_bytes(
                                        exited.state_change[0x18..0x1c]
                                            .try_into()
                                            .unwrap_or([0; 4]),
                                    ) == 0x1234
                                {
                                    dbg_ok |= 0x0100;
                                }
                                let _ = nt_handler.pm.debug_continue(
                                    object,
                                    exited.client_id,
                                    dbgk::DBG_CONTINUE,
                                );
                            }
                        }
                        // 0x0200 — EVENT SOURCE: process exit.
                        let _ = nt_handler.pm.terminate_process(target, 0x99);
                        if let Ok(Some(dead)) =
                            nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                        {
                            if dead.state == dbgk::DBG_EXIT_PROCESS_STATE_CHANGE
                                && u32::from_le_bytes(
                                    dead.state_change[0x18..0x1c].try_into().unwrap_or([0; 4]),
                                ) == 0x99
                            {
                                dbg_ok |= 0x0200;
                            }
                        }
                        // 0x0400 — detach clears the port + flushes; a second detach is PORT_NOT_SET.
                        let flushed = nt_handler.pm.remove_process_debug(target, object);
                        if flushed.is_ok()
                            && nt_handler.pm.process_debug_port(target).is_none()
                            && !nt_handler.pm.is_process_being_debugged(target)
                            && nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.is_empty())
                            && nt_handler.pm.remove_process_debug(target, object)
                                == Err(dbgk::STATUS_PORT_NOT_SET)
                        {
                            dbg_ok |= 0x0400;
                        }
                        // 0x0800 — a LIVE process that was attached then detached reports nothing
                        // further: attach a second throwaway debuggee, detach it, then create a
                        // thread in it and prove the plane stays inert.
                        let target2 =
                            nt_handler
                                .pm
                                .create_process("dbgk-selftest-b.exe", None, None);
                        if nt_handler
                            .pm
                            .create_thread(target2, 0x6000, 0, false)
                            .is_ok()
                        {
                            let attached = nt_handler
                                .pm
                                .debug_active_process(target2, object, debugger)
                                == Ok(1);
                            let detached =
                                nt_handler.pm.remove_process_debug(target2, object) == Ok(1);
                            let drained = nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.is_empty());
                            let _ = nt_handler.pm.create_thread(target2, 0x7000, 0, false);
                            if attached
                                && detached
                                && drained
                                && nt_handler
                                    .pm
                                    .debug_object(object)
                                    .is_some_and(|o| o.is_empty())
                                && matches!(
                                    nt_handler.pm.wait_for_debug_event(object, debugger_pid),
                                    Ok(None)
                                )
                            {
                                dbg_ok |= 0x0800;
                            }
                        }
                    }
                    nt_handler.pm.destroy_debug_object(object);
                }
            }
            DBGK_SELFTEST.store(dbg_ok, Ordering::Relaxed);
        }

        // === Dbgk SYSCALL-DISPATCH SELF-TEST (POST-LOOP) ===========================================
        // The block above drives the PLANE (ProcessManager + the pure `nt_process::dbgk` state
        // machine) directly; it proves nothing about the five NATIVE HANDLER ARMS. This block drives
        // those arms through the REAL dispatch route a hosted process uses —
        // `nt_dispatcher.dispatch(SSN, argv, origin, &mut nt_handler)`, the exact call the service
        // loop makes for every syscall — with REAL MARSHALLED ARGUMENTS living in CLIENT memory
        // (smss's mirrored stack). So the handler's own SSN→service resolution, typed-handle lookup,
        // `DbgkDebugObjectMapping` access checks, ProbeForWrite/copyin/copyout of the `*DebugHandle`,
        // `*Timeout`, `*CLIENT_ID` and `DBGUI_WAIT_STATE_CHANGE`, its counters and its wait-park
        // request all execute for real. Verified by the DBGK_* counters, which read 0 without it.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const ST_TIMEOUT: u32 = 0x0000_0102;
            const ST_ACCESS_VIOLATION: u32 = 0xC000_0005;
            const ST_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
            const ST_INVALID_HANDLE: u32 = 0xC000_0008;
            const ST_INVALID_PARAMETER: u32 = 0xC000_000D;
            const ST_ACCESS_DENIED: u32 = 0xC000_0022;
            const ST_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
            // The client-side argument block: the DEEPEST (unused) end of smss's 16 KiB stack, which
            // is inside its mirrored range so the handler's copyin/copyout reach it exactly as they
            // reach a live caller's stack. smss is parked in its final syscall and the boot exits
            // right after the specs, so nothing ever reads these bytes back.
            const A_HANDLE: u64 = STACK_BASE + 0x80; // *DebugHandle out (8)
            const A_CLIENT_ID: u64 = STACK_BASE + 0x88; // CLIENT_ID in (16)
            const A_TIMEOUT: u64 = STACK_BASE + 0x98; // LARGE_INTEGER *Timeout in (8)
                                                      // DBGUI_WAIT_STATE_CHANGE out (0xB8).
            const A_STATE: u64 = STACK_BASE + 0xA0;
            // Handler-owned temporary slots let the specs exercise pid -> pi routing without
            // publishing throwaway processes as hosted launch topology.

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            // Retain the process memory owner so syscall outputs use normal write admission.
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            nt_handler.pi = 0;

            let mut sc_ok = 0u64;
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            // Every service below goes through THIS — the dispatcher, by SSN. An unregistered number
            // returns STATUS_INVALID_SYSTEM_SERVICE and never reaches a handler; a wrong argument
            // count returns STATUS_INVALID_PARAMETER before the handler.
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }

            // 0x0001 — the five services really are registered at the sysfuncs.lst-derived SSNs, with
            // their documented argument counts.
            if [
                (NativeService::NtCreateDebugObject, 35u32, 4u8),
                (NativeService::NtDebugActiveProcess, 59, 2),
                (NativeService::NtDebugContinue, 60, 3),
                (NativeService::NtRemoveProcessDebug, 199, 2),
                (NativeService::NtWaitForDebugEvent, 279, 4),
            ]
            .iter()
            .all(|&(service, ssn, argc)| {
                nt_dispatcher.table().number_of(service) == Some(ssn)
                    && nt_dispatcher.table().lookup(ssn).is_some_and(|entry| {
                        entry.service == service && entry.min_args == argc && entry.max_args == argc
                    })
            }) {
                sc_ok |= 0x0001;
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            // Zero the client argument block through the mirror; if that fails the mirrors are not
            // usable and the whole test would be meaningless, so it stays 0 (=> FAIL) rather than
            // silently "passing".
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100]);
            if debugger_pid != 0 && client_args_ready {
                // --- NtCreateDebugObject (SSN 35): [*DebugHandle, DesiredAccess, *OA, Flags] ------
                let create = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                // Read the handle back out of CLIENT memory the way the caller would — proof the
                // out-parameter was really marshalled, not just returned.
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                let host_event = object
                    .and_then(|object| nt_handler.pm.debug_object(object))
                    .map(|o| o.host_event)
                    .unwrap_or(0);
                let create_negatives = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[0, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0]
                ) == ST_ACCESS_VIOLATION
                    && sysc!(
                        SSN_NT_CREATE_DEBUG_OBJECT,
                        &[A_HANDLE + 1, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0]
                    ) == ST_DATATYPE_MISALIGNMENT
                    && sysc!(
                        SSN_NT_CREATE_DEBUG_OBJECT,
                        &[A_HANDLE, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0x8000]
                    ) == ST_INVALID_PARAMETER;
                // 0x0002 — the handler created a real object, bound its EventsPresent dispatcher
                // event, minted a TYPED per-process handle and copied it out; its counter moved.
                if create == 0
                    && dbg_handle != 0
                    && object.is_some()
                    && host_event != 0
                    && DBGK_OBJECTS_CREATED.load(Ordering::Relaxed) >= 1
                    && create_negatives
                {
                    sc_ok |= 0x0002;
                }

                if let Some(object) = object {
                    // A throwaway debuggee with a real image base + main thread.
                    let target = nt_handler.pm.create_process("dbgk-syscall.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_5000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x2100, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let target_registered = target_claim.is_some();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_target_noaccess = nt_handler
                        .pm
                        .insert_handle(debugger_pid, nt_process::HandleObject::Process(target), 0)
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_dbg_noaccess = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            0,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_wrong_type = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Opaque(0xDB65),
                            dbgk::DEBUG_OBJECT_ALL_ACCESS,
                        )
                        .map(u64::from)
                        .unwrap_or(0);

                    // 0x0080 — the DEBUG-handle checks, all through the dispatch route: a handle
                    // without the required DbgkDebugObjectMapping access is ACCESS_DENIED on every
                    // service, a non-debug handle is OBJECT_TYPE_MISMATCH, and a NULL out/in pointer
                    // is ACCESS_VIOLATION.
                    if sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, h_dbg_noaccess])
                        == ST_ACCESS_DENIED
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[h_dbg_noaccess, 0, A_TIMEOUT, A_STATE]
                        ) == ST_ACCESS_DENIED
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[h_dbg_noaccess, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, h_dbg_noaccess])
                            == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, h_wrong_type])
                            == ST_OBJECT_TYPE_MISMATCH
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[h_wrong_type, 0, A_TIMEOUT, A_STATE]
                        ) == ST_OBJECT_TYPE_MISMATCH
                        && sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, A_TIMEOUT, 0])
                            == ST_ACCESS_VIOLATION
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, 0, dbgk::DBG_CONTINUE as u64]
                        ) == ST_ACCESS_VIOLATION
                    {
                        sc_ok |= 0x0080;
                    }
                    // 0x0200 — the PROCESS-handle side: a process handle lacking
                    // PROCESS_SUSPEND_RESUME is ACCESS_DENIED, an unknown one is INVALID_HANDLE, and
                    // detaching a process that was never attached is STATUS_PORT_NOT_SET.
                    if sysc!(
                        SSN_NT_DEBUG_ACTIVE_PROCESS,
                        &[h_target_noaccess, dbg_handle]
                    ) == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[0xDEAD_BEEF, dbg_handle])
                            == ST_INVALID_HANDLE
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_NOT_SET
                    {
                        sc_ok |= 0x0200;
                    }

                    // --- NtDebugActiveProcess (SSN 59): [ProcessHandle, DebugHandle] -------------
                    let attaches_before = DBGK_ATTACHES.load(Ordering::Relaxed);
                    let fake_before = DBGK_FAKE_MESSAGES.load(Ordering::Relaxed);
                    let attach = if target_registered {
                        sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle])
                    } else {
                        ST_INVALID_PARAMETER
                    };
                    // 0x0004 — the attach ran IN THE HANDLER (its counter moved), installed the port
                    // + PEB.BeingDebugged and posted the fake create message; a second one is
                    // STATUS_PORT_ALREADY_SET.
                    if attach == 0
                        && DBGK_ATTACHES.load(Ordering::Relaxed) == attaches_before + 1
                        && DBGK_FAKE_MESSAGES.load(Ordering::Relaxed) >= fake_before + 1
                        && nt_handler.pm.process_debug_port(target) == Some(object)
                        && nt_handler.pm.is_process_being_debugged(target)
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_ALREADY_SET
                    {
                        sc_ok |= 0x0004;
                    }

                    // --- NtWaitForDebugEvent (SSN 279): [DebugHandle, Alertable, *Timeout,
                    //     *StateChange] — a REAL immediate timeout in client memory + a REAL
                    //     DBGUI_WAIT_STATE_CHANGE copied back out to client memory.
                    let timeout_written = img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    let sc_u32 =
                        |o: usize| u32::from_le_bytes(sc[o..o + 4].try_into().unwrap_or([0; 4]));
                    let sc_u64 =
                        |o: usize| u64::from_le_bytes(sc[o..o + 8].try_into().unwrap_or([0; 8]));
                    let handle_to_process = sc_u64(0x18);
                    let handle_to_thread = sc_u64(0x20);
                    // 0x0008 — the handler served the wait and the OUT-PARAM LANDED IN CLIENT MEMORY:
                    // DbgCreateProcessStateChange for the right CLIENT_ID, carrying REAL process /
                    // thread handles opened in the debugger's own table, the image base and the
                    // initial thread's start address.
                    if wait == 0
                        && timeout_written
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32(0x00) == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && sc_u64(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64(0x10) == main as u64)
                        && sc_u64(0x38) == 0x0000_0001_5000_0000
                        && sc_u64(0x50) == 0x2100
                        && handle_to_process != 0
                        && handle_to_thread != 0
                        && nt_handler
                            .pm
                            .lookup_handle(debugger_pid, handle_to_process as nt_process::Handle)
                            == Some(nt_process::HandleObject::Process(target))
                        && main.is_some_and(|main| {
                            nt_handler
                                .pm
                                .lookup_handle(debugger_pid, handle_to_thread as nt_process::Handle)
                                == Some(nt_process::HandleObject::Thread(main))
                        })
                    {
                        sc_ok |= 0x0008;
                    }
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, handle_to_process as nt_process::Handle);
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, handle_to_thread as nt_process::Handle);
                    // 0x0010 — nothing further is reportable for this debuggee (one outstanding event
                    // per process) and the *Timeout the handler READ from client memory is immediate
                    // ⇒ STATUS_TIMEOUT, with no park requested.
                    if sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == ST_TIMEOUT
                        && nt_handler.wait_park_event < 0
                    {
                        sc_ok |= 0x0010;
                    }

                    // --- NtDebugContinue (SSN 60): [DebugHandle, *AppClientId, ContinueStatus] ---
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    let continues_before = DBGK_CONTINUES.load(Ordering::Relaxed);
                    // 0x0020 — the handler read the CLIENT_ID out of client memory, rejected an
                    // illegal continue status and resolved the read event; its counter moved.
                    if client_id_written
                        && sysc!(SSN_NT_DEBUG_CONTINUE, &[dbg_handle, A_CLIENT_ID, 0x1234])
                            == ST_INVALID_PARAMETER
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && DBGK_CONTINUES.load(Ordering::Relaxed) == continues_before + 1
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        sc_ok |= 0x0020;
                    }

                    // 0x0100 — WAIT-PARK / WAKE-SIGNAL. With the queue drained and a NULL (=
                    // infinite) *Timeout the handler must PARK: it binds `wait_park_event` to the
                    // debug object's EventsPresent dispatcher event — the same field the service loop
                    // consumes to steal the caller's reply cap — and that event is NOT ready. A later
                    // queue-side post through the same dispatch route (attaching a second debuggee)
                    // SETS that very dispatcher event, which is exactly what the loop's wake path
                    // consumes, and the re-issued wait then returns the new event.
                    // HONEST SCOPE: the reply-cap steal + thread resume itself is NOT exercised —
                    // post-loop there is no live client blocked inside the syscall.
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();
                    let park_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park_index = nt_handler.wait_park_event;
                    let parked = park_status == ST_TIMEOUT
                        && park_index >= 0
                        && park_index as u64 + 1 == host_event
                        && !nt_handler.dispatcher_ready(park_index as usize)
                        && nt_handler.wait_timeout.is_none();
                    nt_handler.wait_park_event = -1;
                    let target2 = nt_handler
                        .pm
                        .create_process("dbgk-syscall-b.exe", None, None);
                    nt_handler.pm.set_image_base(target2, 0x0000_0001_6000_0000);
                    let _ = nt_handler.pm.create_thread(target2, 0x2200, 0, false);
                    let target2_claim = nt_handler.claim_temporary_process_slot(target2, 0).ok();
                    let target2_registered = target2_claim.is_some();
                    let h_target2 = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target2),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let woke = target2_registered
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target2, dbg_handle]) == 0
                        && park_index >= 0
                        && nt_handler.dispatcher_ready(park_index as usize);
                    let redriven = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == 0;
                    let mut sc2 = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
                    let redriven_payload = img_spawn::smss_copyin(A_STATE, &mut sc2)
                        && u32::from_le_bytes(sc2[0..4].try_into().unwrap_or([0; 4]))
                            == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && u64::from_le_bytes(sc2[8..16].try_into().unwrap_or([0; 8]))
                            == target2 as u64;
                    if parked && woke && redriven && redriven_payload {
                        sc_ok |= 0x0100;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();

                    // --- NtRemoveProcessDebug (SSN 199): [ProcessHandle, DebugHandle] ------------
                    let detaches_before = DBGK_DETACHES.load(Ordering::Relaxed);
                    // 0x0040 — the detach ran IN THE HANDLER (its counter moved), cleared the port +
                    // BeingDebugged, and a second detach is STATUS_PORT_NOT_SET.
                    if sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle]) == 0
                        && DBGK_DETACHES.load(Ordering::Relaxed) == detaches_before + 1
                        && nt_handler.pm.process_debug_port(target).is_none()
                        && !nt_handler.pm.is_process_being_debugged(target)
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_NOT_SET
                    {
                        sc_ok |= 0x0040;
                    }
                    // 0x0400 — NtClose (SSN 27) on the last debug-object handle, through the same
                    // dispatch route, runs DbgkpCloseObject: the object is destroyed and the
                    // STILL-ATTACHED second debuggee is detached.
                    let aux_closed = h_dbg_noaccess == 0
                        || (sysc!(SSN_NT_CLOSE, &[h_dbg_noaccess]) == 0
                            && nt_handler.pm.debug_object(object).is_some());
                    if nt_handler.pm.process_debug_port(target2) == Some(object)
                        && aux_closed
                        && sysc!(SSN_NT_CLOSE, &[dbg_handle]) == 0
                        && nt_handler.pm.debug_object(object).is_none()
                        && nt_handler.pm.process_debug_port(target2).is_none()
                    {
                        sc_ok |= 0x0400;
                    }

                    if let Some(claim) = target_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    if let Some(claim) = target2_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    for handle in [
                        h_target,
                        h_target2,
                        h_target_noaccess,
                        h_dbg_noaccess,
                        h_wrong_type,
                    ] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                }
            }

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_SYSCALL_SELFTEST.store(sc_ok, Ordering::Relaxed);
        }

        // ═══ Dbgk EXCEPTION-FORWARDING self-test (post-loop) ═══════════════════════════════════
        // `DbgkForwardException` — the debug-event source the previous batch left DEFERRED and the
        // load-bearing one (without it a debugger cannot see a crash or an `int3`).
        //
        // WHAT IS DRIVEN FOR REAL: the debugger side goes through the REAL dispatch route
        // (`nt_dispatcher.dispatch(SSN, …)`, arguments marshalled in CLIENT memory) exactly as a
        // hosted process's syscalls do, and the DEBUGGEE side goes through
        // `ExecNtHandler::dbgk_forward_exception` — *the very entry the live fault path calls* at
        // its `#PF` / `#GP` / int3 classification sites (`dbgk_forward_exception!`). Nothing here
        // reimplements the forward: the throwaway debuggee is registered in a handler-owned
        // temporary slot, so the pi -> pid -> `EPROCESS.DebugPort` resolution the fault path
        // performs is the same resolution performed here.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const THREAD_TERMINATE: u32 = 0x0001;
            const ST_TIMEOUT: u32 = 0x0000_0102;
            const ST_INVALID_PARAMETER: u32 = 0xC000_000D;
            const A_HANDLE: u64 = STACK_BASE + 0x180;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x188;
            const A_TIMEOUT: u64 = STACK_BASE + 0x198;
            const A_STATE: u64 = STACK_BASE + 0x1A0;
            // Temporary slots for the throwaway debuggees are claimed from identities with no live
            // process/thread mechanism, VSpace, worker reservation, or registered client frames.

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut ex_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            // Read a field back out of the DBGUI_WAIT_STATE_CHANGE the handler copied to CLIENT
            // memory — the bytes ntdll's `DbgUiWaitStateChange` would receive.
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            if debugger_pid != 0 && client_args_ready {
                // --- setup: a real debug object + an attached throwaway debuggee, all by SSN ----
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                let host_event = object
                    .and_then(|object| nt_handler.pm.debug_object(object))
                    .map(|o| o.host_event)
                    .unwrap_or(0);
                if let (0, Some(object)) = (created, object) {
                    let target = nt_handler
                        .pm
                        .create_process("dbgk-exception.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_7000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x3100, 0, false).ok();
                    // A second thread so terminating one (the lifecycle poster below) does not
                    // signal the process and tear its handles down.
                    let worker = nt_handler.pm.create_thread(target, 0x3200, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let exc_test_pi = target_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let target_registered = target_claim.is_some();
                    // A NEVER-attached process in the OTHER free slot: the live-boot shape, the
                    // control for the no-debugger gate.
                    let plain = nt_handler.pm.create_process("dbgk-plain.exe", None, None);
                    let _ = nt_handler.pm.create_thread(plain, 0x3300, 0, false);
                    let plain_claim = nt_handler.claim_temporary_process_slot(plain, 0).ok();
                    let exc_test_pi2 = plain_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let plain_registered = plain_claim.is_some();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_worker = worker
                        .and_then(|worker| {
                            nt_handler
                                .pm
                                .insert_handle(
                                    debugger_pid,
                                    nt_process::HandleObject::Thread(worker),
                                    THREAD_TERMINATE,
                                )
                                .ok()
                        })
                        .map(u64::from)
                        .unwrap_or(0);
                    // Attach, then DRAIN every attach-time fake create message (one
                    // DbgKmCreateProcessApi for the first thread + a DbgKmCreateThreadApi for each
                    // other one) so the queue is empty and the exception below is unambiguously the
                    // outstanding event. Each drain step reads the reported CLIENT_ID straight back
                    // out of the state change in CLIENT memory and continues that exact thread.
                    let attached = target_registered
                        && h_target != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    let mut drained = 0u64;
                    while drained < 8
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                    {
                        let mut reported = [0u8; 16];
                        if !img_spawn::smss_copyin(A_STATE, &mut sc) {
                            break;
                        }
                        reported[0..8].copy_from_slice(&sc[0x08..0x10]);
                        reported[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &reported)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    // From here on the CLIENT_ID in client memory is the debuggee's MAIN thread —
                    // the thread every forwarded exception below reports for.
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    // 0x0001 — attached through the REAL dispatch route, with both fake create
                    // messages (two live threads) retrieved and continued by SSN, leaving the queue
                    // empty.
                    if attached
                        && client_id_written
                        && drained == 2
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        ex_ok |= 0x0001;
                    }

                    // --- THE FORWARD: the exact entry the live fault path calls ----------------
                    // A REAL page fault's record: STATUS_ACCESS_VIOLATION at RIP 0x0000_0001_7000_4321
                    // writing 0x0000_0000_0000_0018 — the shape `dbgk_forward_exception!` builds at
                    // the loop's null-deref / vmf-out sites from (m0, m3, addr).
                    const EXC_IP: u64 = 0x0000_0001_7000_4321;
                    const EXC_ADDR: u64 = 0x18;
                    let forwarded_before = DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed);
                    let forwarded = nt_handler.dbgk_forward_exception(
                        exc_test_pi,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::access_violation(EXC_IP, 1, EXC_ADDR),
                        true,
                    );
                    // 0x0002 — the forward ran: it resolved pi → pid → DebugPort, queued exactly one
                    // DbgKmExceptionApi event and moved the counter.
                    if forwarded
                        && DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed) == forwarded_before + 1
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 1
                                && o.events()[0].message.api_number() == dbgk::DBGKM_EXCEPTION_API
                        })
                    {
                        ex_ok |= 0x0002;
                    }

                    // 0x0004 — the debugger retrieves it through the REAL NtWaitForDebugEvent arm
                    // and the WHOLE record lands in CLIENT memory: DbgExceptionStateChange for the
                    // faulting CLIENT_ID, exception code / address / both MmAccessFault parameters
                    // / FirstChance.
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    // Macros, not closures: the state-change buffer is re-filled by each later
                    // `smss_copyin`, so nothing may hold a borrow of it across the checks.
                    macro_rules! sc_u32 {
                        ($o:expr) => {
                            u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap_or([0; 4]))
                        };
                    }
                    macro_rules! sc_u64 {
                        ($o:expr) => {
                            u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap_or([0; 8]))
                        };
                    }
                    if wait == 0
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                        && sc_u64!(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64!(0x10) == main as u64)
                        && sc_u32!(0x18) == dbgk::STATUS_ACCESS_VIOLATION
                        && sc_u64!(0x28) == EXC_IP
                        && sc_u32!(0x30) == 2
                        && sc_u64!(0x38) == 1
                        && sc_u64!(0x40) == EXC_ADDR
                        && sc_u32!(0xb0) == 1
                    {
                        ex_ok |= 0x0004;
                    }

                    // 0x0008 — NtDebugContinue resolves the EXCEPTION event: an illegal continue
                    // status is rejected, DBG_CONTINUE (read from the CLIENT_ID in client memory)
                    // succeeds, the handler counter moves and the queue drains.
                    let continues_before = DBGK_CONTINUES.load(Ordering::Relaxed);
                    if sysc!(SSN_NT_DEBUG_CONTINUE, &[dbg_handle, A_CLIENT_ID, 0x4321])
                        == ST_INVALID_PARAMETER
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && DBGK_CONTINUES.load(Ordering::Relaxed) == continues_before + 1
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        ex_ok |= 0x0008;
                    }

                    // 0x0010 — BREAKPOINT/trap refinement. An `int3` forwarded exactly as the
                    // label-4 fault site forwards it reports as DbgBreakpointStateChange (not a
                    // plain exception), and the trap-vector → NTSTATUS map the label-3 site uses is
                    // the one `KiDispatchException` reports.
                    const BP_IP: u64 = 0x0000_0001_7000_1005;
                    if nt_handler.dbgk_forward_exception(
                        exc_test_pi,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, BP_IP),
                        true,
                    ) && sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE
                        && sc_u32!(0x18) == dbgk::STATUS_BREAKPOINT
                        && sc_u64!(0x28) == BP_IP
                        && dbgk::exception_code_for_trap(3) == dbgk::STATUS_BREAKPOINT
                        && dbgk::exception_code_for_trap(6) == dbgk::STATUS_ILLEGAL_INSTRUCTION
                        && dbgk::exception_code_for_trap(14) == dbgk::STATUS_ACCESS_VIOLATION
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0010;
                    }

                    // 0x0020 — ★ THE NO-DEBUGGER GATE, the safety property the whole fault-path
                    // integration rests on: forwarding for a process with NO EPROCESS.DebugPort
                    // returns false, moves no counter and queues nothing. This is what EVERY fault
                    // on the live boot takes, which is why the fault path is byte-identical.
                    let quiet_before = DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed);
                    let queued_before = nt_handler
                        .pm
                        .debug_object(object)
                        .map(|o| o.len())
                        .unwrap_or(0);
                    if plain_registered
                        && !nt_handler.dbgk_forward_exception(
                            exc_test_pi2,
                            0,
                            dbgk::ExceptionRecord::access_violation(0x1000, 0, 0x40),
                            true,
                        )
                        && !nt_handler.pm.is_process_being_debugged(plain)
                        && DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed) == quiet_before
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .map(|o| o.len())
                            .unwrap_or(0)
                            == queued_before
                    {
                        ex_ok |= 0x0020;
                    }

                    // 0x0040 — ★ THE SIGNAL FIX, fault-path poster. Park the debugger on the
                    // object's EventsPresent dispatcher event (empty queue + NULL = infinite
                    // *Timeout), then forward an exception through the FAULT-PATH entry — which is
                    // not a syscall at all. Before this batch only the five dbgk syscall arms
                    // mirrored the modelled signal, so this post would have left the dispatcher
                    // event CLEAR and never woken the parked debugger.
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();
                    let park_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park_index = nt_handler.wait_park_event;
                    let parked = park_status == ST_TIMEOUT
                        && park_index >= 0
                        && park_index as u64 + 1 == host_event
                        && !nt_handler.dispatcher_ready(park_index as usize);
                    nt_handler.wait_park_event = -1;
                    const FAULT_IP: u64 = 0x0000_0001_7000_9999;
                    let woke = nt_handler.dbgk_forward_exception(
                        exc_test_pi,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::access_violation(FAULT_IP, 0, 0x88),
                        false,
                    ) && park_index >= 0
                        && nt_handler.dispatcher_ready(park_index as usize);
                    if parked
                        && woke
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                        && sc_u64!(0x28) == FAULT_IP
                        // SecondChance ⇒ FirstChance == 0, carried through faithfully.
                        && sc_u32!(0xb0) == 0
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_EXCEPTION_NOT_HANDLED as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0040;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();

                    // 0x0080 — ★ THE SIGNAL FIX, NON-DBGK SYSCALL poster. The same park, then
                    // NtTerminateThread (SSN 267) on one of the debuggee's threads: a LIFECYCLE
                    // event source whose handler arm never mirrored the debug signal before this
                    // batch (it is now covered because the mirror runs at the ONE chokepoint every
                    // service passes through). The dispatcher event must be SET and the re-issued
                    // wait must return that thread's DbgExitThreadStateChange.
                    let park2_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park2_index = nt_handler.wait_park_event;
                    let parked2 = park2_status == ST_TIMEOUT
                        && park2_index >= 0
                        && !nt_handler.dispatcher_ready(park2_index as usize);
                    nt_handler.wait_park_event = -1;
                    let mut worker_client = [0u8; 16];
                    worker_client[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    worker_client[8..16]
                        .copy_from_slice(&(worker.unwrap_or(0) as u64).to_le_bytes());
                    if parked2
                        && h_worker != 0
                        && img_spawn::smss_copyout(A_CLIENT_ID, &worker_client)
                        && sysc!(SSN_NT_TERMINATE_THREAD, &[h_worker, 0x1234]) == 0
                        && park2_index >= 0
                        && nt_handler.dispatcher_ready(park2_index as usize)
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_EXIT_THREAD_STATE_CHANGE
                        && worker.is_some_and(|worker| sc_u64!(0x10) == worker as u64)
                        && sc_u32!(0x18) == 0x1234
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0080;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_timeout = PendingWaitTimeout::none();

                    if let Some(claim) = target_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    if let Some(claim) = plain_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    for handle in [h_target, h_worker] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                    // DbgkpCloseObject through the real NtClose arm — leaves no debug object alive,
                    // so the gate's post-spec state matches a plain boot.
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle]);
                }
            }

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_EXCEPTION_SELFTEST.store(ex_ok, Ordering::Relaxed);
        }

        // ═══ Dbgk MODULE LOAD/UNLOAD self-test (post-loop) ═════════════════════════════════════
        // `DbgkMapViewOfSection` / `DbgkUnMapViewOfSection` + `DbgkpPostFakeModuleMessages` — the
        // last of the deferred debug-event sources.
        //
        // WHAT IS DRIVEN FOR REAL: the DEBUGGER side goes through the REAL dispatch route
        // (`nt_dispatcher.dispatch(SSN, …)` with the arguments marshalled in CLIENT memory), and the
        // DEBUGGEE side goes through `ExecNtHandler::dbgk_module_load` / `dbgk_module_unload` —
        // *the very entries the live `NtMapViewOfSection` SEC_IMAGE branch and the
        // `NtUnmapViewOfSection` arm call*. Nothing is reimplemented for the test: each throwaway
        // process sits in a handler-owned temporary slot, so the pi -> pid ->
        // `EPROCESS.DebugPort` resolution is the same one the mapping path performs.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const FILE_GENERIC_READ: u32 = 0x0012_0089;
            // Client argument block — past the exception self-test's 0x180..0x280 window.
            const A_HANDLE: u64 = STACK_BASE + 0x280;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x288;
            const A_TIMEOUT: u64 = STACK_BASE + 0x298;
            const A_STATE: u64 = STACK_BASE + 0x2A0;
            // Temporary identities are claimed dynamically so admitted hosted images cannot collide
            // with this integration-only debug plane.
            // The debuggee's own image base + the IMAGE views this test maps into it.
            const TARGET_IMAGE_BASE: u64 = 0x0000_0001_8000_0000;
            const DLL_BASE: u64 = 0x0000_0000_7100_0000;
            const NOT_AN_IMAGE_BASE: u64 = 0x0000_0000_7200_0000;
            const PLAIN_IMAGE_BASE: u64 = 0x0000_0001_9000_0000;
            const PLAIN_PROBE_BASE: u64 = 0x0000_0000_7300_0000;
            const PLAIN_DLL_A: u64 = 0x0000_0000_7400_0000;
            const PLAIN_DLL_B: u64 = 0x0000_0000_7500_0000;
            const NAME_POINTER: u64 = SMSS_TEB_VA + 0x28; // NtTib.ArbitraryUserPointer
            const DBG_INFO: (u32, u32) = (0x0000_1234, 0x0000_0056);

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut md_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap_or([0; 4]))
                };
            }
            macro_rules! sc_u64 {
                ($o:expr) => {
                    u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap_or([0; 8]))
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            if debugger_pid != 0 && client_args_ready {
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    // The DEBUGGED throwaway debuggee.
                    let target = nt_handler.pm.create_process("dbgk-module.exe", None, None);
                    nt_handler.pm.set_image_base(target, TARGET_IMAGE_BASE);
                    let main = nt_handler.pm.create_thread(target, 0x4100, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let mod_test_pi = target_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let target_registered = target_claim.is_some();
                    // The NEVER-attached control — the live-boot shape, and later the subject of the
                    // attach-time fake-module proof.
                    let plain = nt_handler
                        .pm
                        .create_process("dbgk-modplain.exe", None, None);
                    nt_handler.pm.set_image_base(plain, PLAIN_IMAGE_BASE);
                    let plain_main = nt_handler.pm.create_thread(plain, 0x4200, 0, false).ok();
                    let plain_claim = nt_handler.claim_temporary_process_slot(plain, 0).ok();
                    let mod_test_pi2 = plain_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let plain_registered = plain_claim.is_some();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_plain = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(plain),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    // The DEBUGGEE's own handle to the image file — the thing `DbgkpOpenHandles`
                    // duplicates. A real per-process handle in the debuggee's own table.
                    let debuggee_file = nt_handler
                        .pm
                        .insert_handle(
                            target,
                            nt_process::HandleObject::File(0xF11E_0001),
                            FILE_GENERIC_READ,
                        )
                        .map(u64::from)
                        .unwrap_or(0);

                    // --- 0x0001 setup: attach + drain the fake create message, all by SSN --------
                    let attached = target_registered
                        && h_target != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    if attached
                        && client_id_written
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0001;
                    }

                    // --- THE LOAD: the exact entry the live SEC_IMAGE map branch calls -----------
                    // On the live path the mapping thread is the caller, so report as the debuggee's
                    // thread (what `self.current_tid` holds inside a serviced syscall).
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let loads_before = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    let loaded = nt_handler.dbgk_module_load(
                        mod_test_pi,
                        DLL_BASE,
                        debuggee_file,
                        DBG_INFO,
                        NAME_POINTER,
                    );
                    nt_handler.current_tid = debugger_tid as u64;
                    // 0x0002 — the map-path entry queued exactly one DbgKmLoadDllApi, moved the
                    // counter, and tracked the view as a module of the debuggee.
                    if loaded
                        && DBGK_MODULE_LOADS.load(Ordering::Relaxed) == loads_before + 1
                        && nt_handler.pm.module_count(target) == 1
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 1
                                && o.events()[0].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                        })
                    {
                        md_ok |= 0x0002;
                    }

                    // 0x0004 — the debugger retrieves it through the REAL NtWaitForDebugEvent arm
                    // and the WHOLE payload lands in CLIENT memory, with the image FILE handle
                    // DUPLICATED into the debugger's own table (`DbgkpOpenHandles`).
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    let reported_file = sc_u64!(0x18);
                    if wait == 0
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32!(0x00) == dbgk::DBG_LOAD_DLL_STATE_CHANGE
                        && sc_u64!(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64!(0x10) == main as u64)
                        && sc_u64!(0x20) == DLL_BASE
                        && sc_u32!(0x28) == DBG_INFO.0
                        && sc_u32!(0x2c) == DBG_INFO.1
                        && sc_u64!(0x30) == NAME_POINTER
                        // The duplicate is a DIFFERENT handle value in the DEBUGGER's table naming
                        // the SAME file object, with DUPLICATE_SAME_ACCESS.
                        && debuggee_file != 0
                        && reported_file != 0
                        && reported_file != debuggee_file
                        && nt_handler
                            .pm
                            .lookup_handle(debugger_pid, reported_file as nt_process::Handle)
                            == Some(nt_process::HandleObject::File(0xF11E_0001))
                        && nt_handler
                            .pm
                            .handle_access(debugger_pid, reported_file as nt_process::Handle)
                            == Some(FILE_GENERIC_READ)
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        md_ok |= 0x0004;
                    }
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, reported_file as nt_process::Handle);

                    // --- THE UNLOAD: the exact entry the live NtUnmapViewOfSection arm calls -----
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let unloads_before = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    let unloaded = nt_handler.dbgk_module_unload(mod_test_pi, DLL_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    // 0x0008 — DbgKmUnloadDllApi posted, retrieved as DbgUnloadDllStateChange with
                    // the right base, and the view is no longer tracked.
                    if unloaded
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == unloads_before + 1
                        && nt_handler.pm.module_count(target) == 0
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_UNLOAD_DLL_STATE_CHANGE
                        && sc_u64!(0x18) == DLL_BASE
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        md_ok |= 0x0008;
                    }

                    // 0x0010 — IMAGE-ONLY. Unmapping a base that was never an IMAGE view (a data or
                    // anonymous mapping — the CSR shared section and the NLS section on the live
                    // boot) posts nothing: `MmUnmapViewOfSection` only calls
                    // `DbgkUnMapViewOfSection` when the VAD it tore down was an image VAD. Same for
                    // re-unmapping the view already unmapped above.
                    let quiet_unloads = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let image_only = !nt_handler.dbgk_module_unload(mod_test_pi, NOT_AN_IMAGE_BASE)
                        && !nt_handler.dbgk_module_unload(mod_test_pi, DLL_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    if image_only
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == quiet_unloads
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0010;
                    }

                    // 0x0020 — ★ THE NO-DEBUGGER GATE, the safety property the whole mapping-path
                    // integration rests on: a map AND an unmap in a process with NO
                    // `EPROCESS.DebugPort` both return false, move no counter and queue nothing.
                    // This is the path EVERY DLL map on the live boot takes (and with no debug
                    // object alive at all, `dbgk_module_load` returns on its FIRST line, before any
                    // lookup — which is the state of every boot today).
                    let quiet_loads = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    let quiet_unloads = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    let queued_before = nt_handler
                        .pm
                        .debug_object(object)
                        .map(|o| o.len())
                        .unwrap_or(0);
                    nt_handler.current_tid = plain_main.unwrap_or(0) as u64;
                    let gated = plain_registered
                        && !nt_handler.dbgk_module_load(
                            mod_test_pi2,
                            PLAIN_PROBE_BASE,
                            0,
                            DBG_INFO,
                            NAME_POINTER,
                        )
                        && !nt_handler.dbgk_module_unload(mod_test_pi2, PLAIN_PROBE_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    if gated
                        && !nt_handler.pm.is_process_being_debugged(plain)
                        && DBGK_MODULE_LOADS.load(Ordering::Relaxed) == quiet_loads
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == quiet_unloads
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .map(|o| o.len())
                            .unwrap_or(0)
                            == queued_before
                    {
                        md_ok |= 0x0020;
                    }

                    // --- 0x0040 — ATTACH-TIME FAKE MODULE MESSAGES -------------------------------
                    // Two DLLs + the process's OWN image map into the still-UNDEBUGGED control
                    // process (nothing posts — proven by the counter staying put), and only THEN is
                    // a debugger attached. `DbgkpPostFakeModuleMessages` must report the two DLLs as
                    // fake `DbgKmLoadDllApi` messages AFTER the create-process message, attributed
                    // to the first thread, with the EXE's own view NOT re-reported.
                    nt_handler.current_tid = plain_main.unwrap_or(0) as u64;
                    let premapped_loads = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    for base in [PLAIN_DLL_A, PLAIN_DLL_B, PLAIN_IMAGE_BASE] {
                        nt_handler.dbgk_module_load(mod_test_pi2, base, 0, DBG_INFO, NAME_POINTER);
                    }
                    nt_handler.current_tid = debugger_tid as u64;
                    let premapped = DBGK_MODULE_LOADS.load(Ordering::Relaxed) == premapped_loads
                        && nt_handler.pm.module_count(plain) == 3;
                    let fake_before = DBGK_FAKE_MESSAGES.load(Ordering::Relaxed);
                    let attach_plain = plain_registered
                        && h_plain != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_plain, dbg_handle]) == 0;
                    if premapped
                        && attach_plain
                        // 1 create-process + 2 load-dll fake messages (the EXE view is skipped).
                        && DBGK_FAKE_MESSAGES.load(Ordering::Relaxed) == fake_before + 3
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 3
                                && o.events()[0].message.api_number()
                                    == dbgk::DBGKM_CREATE_PROCESS_API
                                && o.events()[1].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                                && o.events()[2].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                                // The module messages ride the FIRST reported thread's CLIENT_ID …
                                && plain_main.is_some_and(|first| {
                                    o.events()[1].client_id.unique_thread == first
                                        && o.events()[2].client_id.unique_thread == first
                                })
                                // … are NOWAIT backout events, and only the create-process one was
                                // activated by DbgkpSetProcessDebugObject.
                                && o.events()[1].flags & dbgk::DEBUG_EVENT_NOWAIT != 0
                                && !o.events()[0].is_inactive()
                                && o.events()[1].is_inactive()
                                && o.events()[2].is_inactive()
                        })
                    {
                        md_ok |= 0x0040;
                    }

                    // 0x0080 — each of the three is retrieved through the REAL NtWaitForDebugEvent
                    // arm, in order, and continued by SSN: create-process, then the two
                    // DbgLoadDllStateChanges carrying the bases that were mapped before the attach.
                    let mut plain_client = [0u8; 16];
                    plain_client[0..8].copy_from_slice(&(plain as u64).to_le_bytes());
                    plain_client[8..16]
                        .copy_from_slice(&(plain_main.unwrap_or(0) as u64).to_le_bytes());
                    let mut drained_ok = img_spawn::smss_copyout(A_CLIENT_ID, &plain_client);
                    for (state, base) in [
                        (dbgk::DBG_CREATE_PROCESS_STATE_CHANGE, PLAIN_IMAGE_BASE),
                        (dbgk::DBG_LOAD_DLL_STATE_CHANGE, PLAIN_DLL_A),
                        (dbgk::DBG_LOAD_DLL_STATE_CHANGE, PLAIN_DLL_B),
                    ] {
                        let reported_base_offset = if state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        {
                            0x38 // CreateProcessInfo.NewProcess.BaseOfImage
                        } else {
                            0x20 // LoadDll.BaseOfDll
                        };
                        drained_ok = drained_ok
                            && sysc!(
                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                            ) == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == state
                            && sc_u64!(0x08) == plain as u64
                            && sc_u64!(reported_base_offset) == base
                            && sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) == 0;
                    }
                    if drained_ok
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0080;
                    }

                    if let Some(claim) = target_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    if let Some(claim) = plain_claim {
                        let _ = nt_handler.release_temporary_process_slot(claim);
                    }
                    for handle in [h_target, h_plain] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                    // DbgkpCloseObject through the real NtClose arm — no debug object survives the
                    // spec, so the gate's post-spec state matches a plain boot.
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle]);
                }
            }

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_MODULE_SELFTEST.store(md_ok, Ordering::Relaxed);
        }

        // The hosted receive loop is finished and has no delay waiter outstanding. Disable timer 0
        // and unbind its notification so a stale HPET signal cannot intercept later self-test recvs.
        delay_timer_shutdown(&mut *delay_queue, &nt_handler);
        clear_service_delay_drain_context();

        // === Dbgk TARGET-SIDE BLOCKING SELF-TEST (POST-LOOP) — the keystone deferred item ==========
        //
        // NT blocks the REPORTING thread inside `DbgkpQueueMessage` until `NtDebugContinue` runs
        // `DbgkpWakeTarget`, then applies the continue status to it. Proving that needs something no
        // model call can give: a LIVE thread genuinely blocked in-kernel on the Call that delivered
        // its fault, whose reply capability the executive holds. So this test stands up a REAL
        // throwaway CLIENT THREAD (`selftests::dbgk_client_spawn` — a fresh VSpace + code page +
        // hosted-syscalls TCB + SC, the same machinery as the ALPC cross-VSpace proof) that takes ONE
        // FAULT OF EACH FLAVOUR in order, writing a progress MARKER between them. The executive reads
        // that marker through its own window on the client's shared frame, so "the reporter blocked"
        // and "the continue resumed it" are OBSERVED, not inferred.
        //
        // The DEBUGGER side runs through the REAL dispatch route (`nt_dispatcher.dispatch(SSN, …)`
        // with the arguments marshalled in smss's CLIENT memory, the established idiom); the TARGET
        // side runs through `dbgk_forward_exception` / `dbgk_module_load` / `dbgk_block_reporter` -
        // the very entries the live fault loop and the live `NtMapViewOfSection` arm call.
        // Throwaway-only: a temporary handler slot, fresh caps, all reclaimed afterwards.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const A_HANDLE: u64 = STACK_BASE + 0x180;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x188;
            const A_TIMEOUT: u64 = STACK_BASE + 0x198;
            const A_STATE: u64 = STACK_BASE + 0x1A0;
            const A_CONTEXT: u64 = STACK_BASE + 0x280;
            const AMD64_CONTEXT_FLAGS_OFFSET: u64 = 0x30;
            const AMD64_CONTEXT_EFLAGS_OFFSET: u64 = 0x44;
            const CONTEXT_AMD64_CONTROL: u32 = 0x0010_0000 | 0x0000_0001;
            const CONTEXT_AMD64_DEBUG_REGISTERS: u32 = 0x0010_0000 | 0x0000_0010;
            const EFLAGS_TF: u32 = 0x0000_0100;
            const BLK_TEST_RUNTIME_BADGE: u64 = 0xDB6B_0001;
            const BLK_DEBUGGER_RUNTIME_BADGE: u64 = 0xDB6B_0002;
            const _: () = assert!(nt_component_suspension::badge::valid_endpoint_badge(
                BLK_DEBUGGER_RUNTIME_BADGE
            ));
            // Executive scratch VAs inside the SAME proven-resident 2 MiB page table the ALPC
            // cross-VSpace self-test uses (see its comment): base + 3000*0x1000, PT index 5.
            let write_scratch_t = SMSS_SCRATCH_BASE + 3010 * 0x1000;
            let write_scratch_d = SMSS_SCRATCH_BASE + 3011 * 0x1000;
            let marker_win_t = SMSS_SCRATCH_BASE + 3012 * 0x1000;
            let marker_win_d = SMSS_SCRATCH_BASE + 3013 * 0x1000;

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut bk_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap())
                };
            }
            macro_rules! sc_u64 {
                ($o:expr) => {
                    u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap())
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_CONTEXT, &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());

            // Throwaway caps: the client's shared marker frame, the `#PF` fixup frame, the reply
            // objects each fault is received on, and a spare reply object for the escape-hatch probe.
            let mut slots = [0u64; 96];
            let mut nslots = 0usize;
            let mut make = |kind: u64, bits: u32| -> u64 {
                let s = alloc_slot();
                slots[nslots] = s;
                nslots += 1;
                let made = untyped_retype_r(CAP_INIT_UNTYPED, kind, bits, 1, s);
                if made != 0 {
                    print_str(b"[dbgk-blk] retype FAILED kind=");
                    print_u64(kind);
                    print_str(b" status=");
                    print_u64(made);
                    print_str(b"\n");
                }
                s
            };
            let shared_t = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let shared_d = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let fixup_frame = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let reply_a = make(OBJ_REPLY, 0);
            let reply_hw = make(OBJ_REPLY, 0);
            let reply_b = make(OBJ_REPLY, 0);
            let reply_step = make(OBJ_REPLY, 0);
            let reply_c = make(OBJ_REPLY, 0);
            let reply_d = make(OBJ_REPLY, 0);
            let reply_spare = make(OBJ_REPLY, 0);
            let reply_debugger_done = make(OBJ_REPLY, 0);
            // NOTE the ORDER below: each marker frame is mapped into its CLIENT'S VSpace FIRST (by
            // `dbgk_client_spawn`) and only then windowed into the executive through a `copy_cap`.
            // A frame capability carries its own mapping, and mapping a COPY first leaves the
            // ORIGINAL's map attempt failing with `seL4_DeleteFirst` — which is exactly how the
            // ALPC cross-VSpace self-test orders its shared frames too.
            if debugger_pid != 0 && client_args_ready {
                // --- a real DEBUG_OBJECT, by SSN ---------------------------------------------
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    // The debuggee EPROCESS standing for the throwaway CLIENT THREAD, in a free
                    // temporary slot so pi -> pid -> DebugPort resolution is the real one. A second
                    // thread keeps the process alive when the first is terminated by DBG_TERMINATE.
                    let target = nt_handler.pm.create_process("dbgk-block.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_9000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x5100, 0, false).ok();
                    let keepalive = nt_handler.pm.create_thread(target, 0x5200, 0, false).ok();
                    let target_claim = nt_handler.claim_temporary_process_slot(target, 0).ok();
                    let blk_test_pi = target_claim
                        .map(TemporaryProcessSlotClaim::pi)
                        .unwrap_or(MAX_PI);
                    let target_registered = target_claim.is_some();
                    let main_tid = main.unwrap_or(0);
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main_tid as u64).to_le_bytes());
                    let cid_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);

                    // --- THE LIVE CLIENT THREAD ---------------------------------------------
                    let code = selftests::dbgk_target_client_code();
                    let (client_pml4, client_tcb, client_ep) = selftests::dbgk_client_spawn(
                        &code,
                        shared_t,
                        write_scratch_t,
                        0,
                        &mut slots,
                        &mut nslots,
                    );
                    let client_runtime_registered = main_tid != 0
                        && nt_handler.register_hosted_thread_tcb(
                            blk_test_pi,
                            main_tid as u64,
                            client_tcb,
                            BLK_TEST_RUNTIME_BADGE,
                            HostedThreadRole::DbgkSelftestTarget,
                        );
                    // 0x0001 — setup: attach BY SSN + drain the fake create message BY SSN. The
                    // FIRST recv also proves the client thread really ran (marker 1) and really
                    // faulted (its `#PF` on the deliberately-unmapped page).
                    let attach_ok = target_registered
                        && h_target != 0
                        && cid_written
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    // `DbgkpPostFakeProcessCreateMessages` posts one message per live thread — a
                    // `DbgKmCreateProcessApi` for the first and a `DbgKmCreateThreadApi` for the
                    // keep-alive one — so drain BOTH (each continued with ITS OWN CLIENT_ID) and
                    // leave the queue genuinely empty before the client's first fault is reported.
                    let mut drained = 0u64;
                    let mut first_state = 0u32;
                    let mut debuggee_thread_handle = 0u64;
                    while attach_ok && drained < 8 {
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                            || !img_spawn::smss_copyin(A_STATE, &mut sc)
                        {
                            break;
                        }
                        if drained == 0 {
                            first_state = sc_u32!(0x00);
                            debuggee_thread_handle = sc_u64!(0x20);
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    // Restore the reporting thread's CLIENT_ID for the blocking continues below.
                    let cid_restored = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    let attached = attach_ok
                        && cid_restored
                        && drained == 2
                        && first_state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty());
                    // ═══ FAULT 1 — VMFault (`#PF`), the flavour every page fault takes ═══════
                    // The executive's own window on the client's marker page (a copy_cap of the
                    // SAME physical frame the client writes — mapped only now that the client's own
                    // mapping is in place).
                    let win_t = {
                        let s = copy_cap(shared_t);
                        slots[nslots] = s;
                        nslots += 1;
                        s
                    };
                    let win_t_ok =
                        page_map_r(win_t, marker_win_t, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
                    let marker_t = || {
                        if win_t_ok {
                            core::ptr::read_volatile(marker_win_t as *const u64)
                        } else {
                            u64::MAX
                        }
                    };
                    // ★ Every stage below is GUARDED. A blocking `recv` on the client's endpoint is
                    // only ever issued once the previous continue is KNOWN to have resumed it, and
                    // any failure breaks out with the bits collected so far — a self-test that could
                    // block forever would be a boot wedge, which is exactly what this batch must not
                    // introduce. `loop { … break }` gives the early exits.
                    loop {
                        // ═══ FAULT 1 — VMFault (`#PF`), the flavour every page fault takes ═══
                        // The throwaway TCB can deliver an initial scheduler/startup fault before
                        // the target code reaches its marker write. That event is not the debuggee
                        // report this proof is about and, as a plain startup notification, does not
                        // leave `reply_a` bound to a blocked caller. Select the VMFault on FIXUP
                        // before parking the reporter so the later continue never replies to an
                        // unbound synthetic event.
                        let mut f1 = None;
                        let mut f1_guard = 0;
                        while f1_guard < 4 {
                            f1_guard += 1;
                            let (_fb, mi_r, m0_r, m1_r, _f1m2, _f1m3) =
                                recv_full_r12(client_ep, reply_a);
                            if (mi_r >> 12) == 6
                                && m1_r == selftests::DBGK_CLIENT_FIXUP
                                && marker_t() == 1
                            {
                                f1 = Some((mi_r, m0_r, m1_r));
                                dbgk_blk_trace(b"f1", mi_r, m0_r, m1_r, marker_t());
                                break;
                            }
                            dbgk_blk_trace(b"f1-foreign", mi_r, m0_r, m1_r, marker_t());
                        }
                        let Some((_f1_mi, f1_m0, f1_m1)) = f1 else {
                            break;
                        };
                        if attached && client_pml4 != 0 {
                            bk_ok |= 0x0001;
                        }
                        // 0x0002 — ★ THE BLOCK. Forward the fault through the entry the live loop
                        // uses, then PARK the reporting thread on the event it just queued.
                        // Observable: the block rides on the DEBUG_EVENT, the counter moves, and the
                        // client has NOT progressed (marker still 1) while the debugger holds it.
                        let blocked_before = DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed);
                        let forwarded = nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            main_tid as u64,
                            dbgk::ExceptionRecord::access_violation(f1_m0, 1, f1_m1),
                            true,
                        );
                        let parked = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_VM_FAULT,
                            reply_a,
                            f1_m0,
                            0,
                            0,
                            0,
                        );
                        dbgk_blk_trace(
                            b"blk1",
                            0,
                            forwarded as u64,
                            parked as u64,
                            nt_handler.pm.blocked_reporter_count(object) as u64,
                        );
                        let no_progress1 = forwarded
                            && parked
                            && DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed) == blocked_before + 1
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 1;
                        if no_progress1 {
                            bk_ok |= 0x0002;
                        }
                        if !parked {
                            break; // nothing holds the client's reply cap — never recv again
                        }
                        // 0x0200 — real hardware breakpoint context path. Arm DR0 against the
                        // target's next `int3` address while the thread is parked on the page fault.
                        // Continuing the page fault should run marker 2 and then trap with a seL4
                        // instruction-breakpoint DebugException before the software int3 executes.
                        let hw_breakpoint_ip =
                            selftests::DBGK_CLIENT_CODE + selftests::DBGK_TARGET_INT3_OFFSET;
                        let hw_dr7 = nt_thread_start::AMD64_DR7_RESERVED_ONE | 1;
                        let hw_context_written = no_progress1
                            && client_runtime_registered
                            && debuggee_thread_handle != 0
                            && img_spawn::smss_copyout(
                                A_CONTEXT,
                                &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR0_OFFSET,
                                &hw_breakpoint_ip.to_le_bytes(),
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR7_OFFSET,
                                &hw_dr7.to_le_bytes(),
                            );
                        let setctx_hw = if hw_context_written {
                            sysc!(
                                SSN_NT_SET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let getctx_hw_ready = setctx_hw == 0
                            && img_spawn::smss_copyout(
                                A_CONTEXT,
                                &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                            )
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                            );
                        let getctx_hw = if getctx_hw_ready {
                            sysc!(
                                SSN_NT_GET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let mut hw_dr0_buf = [0u8; 8];
                        let mut hw_dr7_buf = [0u8; 8];
                        let hw_breakpoint_armed = getctx_hw == 0
                            && img_spawn::smss_copyin(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR0_OFFSET,
                                &mut hw_dr0_buf,
                            )
                            && img_spawn::smss_copyin(
                                A_CONTEXT + nt_thread_start::CONTEXT_DR7_OFFSET,
                                &mut hw_dr7_buf,
                            )
                            && u64::from_le_bytes(hw_dr0_buf) == hw_breakpoint_ip
                            && u64::from_le_bytes(hw_dr7_buf) == hw_dr7;
                        // 0x0004 — ★ THE CONTINUE RESUMES IT. The debugger retrieves the exception,
                        // maps the page the client faulted on (a real debugger's fixup), and
                        // continues: `DbgkpWakeTarget` replies with the VMFault shape (length 0, no
                        // register transfer) so the faulting instruction is RETRIED — and now
                        // succeeds. Proof it resumed AND continued: its NEXT fault arrives with
                        // marker 2, i.e. the instruction after the `#PF` really executed.
                        let mapped = page_map_r(
                            fixup_frame,
                            selftests::DBGK_CLIENT_FIXUP,
                            RW_NX,
                            client_pml4,
                        ) == 0;
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait1 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read1 = wait1 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE;
                        let cont1 = if read1 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke1 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(b"c1", 0, wait1 as u64, cont1 as u64, woke1 as u64);
                        if !woke1 {
                            // The reporter was never resumed — release it so nothing is stranded,
                            // and do NOT recv (the client can no longer produce an event).
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        if hw_breakpoint_armed {
                            let (_fb, f2hw_mi, f2hw_m0, f2hw_m1, f2hw_m2, f2hw_m3) =
                                recv_full_r12(client_ep, reply_hw);
                            dbgk_blk_trace(b"f2hw", f2hw_mi, f2hw_m0, f2hw_m1, marker_t());
                            let hw_fault = mapped
                                && read1
                                && cont1 == 0
                                && (f2hw_mi >> 12) == 4
                                && f2hw_m0 == hw_breakpoint_ip
                                && f2hw_m1 == dbgk::SEL4_DEBUG_REASON_INSTRUCTION_BREAKPOINT
                                && f2hw_m2 == hw_breakpoint_ip
                                && f2hw_m3 == 0
                                && marker_t() == 2;
                            let forwarded_hw = hw_fault
                                && nt_handler.dbgk_forward_exception(
                                    blk_test_pi,
                                    main_tid as u64,
                                    dbgk::ExceptionRecord::new(dbgk::STATUS_SINGLE_STEP, f2hw_m0),
                                    true,
                                );
                            let blocked_hw = forwarded_hw
                                && nt_handler.dbgk_block_reporter(
                                    blk_test_pi,
                                    main_tid as u64,
                                    0,
                                    dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                                    reply_hw,
                                    f2hw_m0,
                                    f2hw_m2,
                                    f2hw_m3,
                                    0,
                                );
                            let no_progress_hw = blocked_hw
                                && nt_handler.pm.blocked_reporter_count(object) == 1
                                && marker_t() == 2;
                            let resumed_before_hw = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                            let wait_hw = if blocked_hw {
                                sysc!(
                                    SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                    &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                                )
                            } else {
                                u32::MAX
                            };
                            let read_hw = wait_hw == 0
                                && img_spawn::smss_copyin(A_STATE, &mut sc)
                                && sc_u32!(0x00) == dbgk::DBG_SINGLE_STEP_STATE_CHANGE;
                            let clear_hw_context_written = read_hw
                                && img_spawn::smss_copyout(
                                    A_CONTEXT,
                                    &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                                )
                                && img_spawn::smss_copyout(
                                    A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                    &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                                );
                            let setctx_hw_clear = if clear_hw_context_written {
                                sysc!(
                                    SSN_NT_SET_CONTEXT_THREAD,
                                    &[debuggee_thread_handle, A_CONTEXT]
                                )
                            } else {
                                u32::MAX
                            };
                            let getctx_hw_clear_ready = setctx_hw_clear == 0
                                && img_spawn::smss_copyout(
                                    A_CONTEXT,
                                    &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE],
                                )
                                && img_spawn::smss_copyout(
                                    A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                    &CONTEXT_AMD64_DEBUG_REGISTERS.to_le_bytes(),
                                );
                            let getctx_hw_clear = if getctx_hw_clear_ready {
                                sysc!(
                                    SSN_NT_GET_CONTEXT_THREAD,
                                    &[debuggee_thread_handle, A_CONTEXT]
                                )
                            } else {
                                u32::MAX
                            };
                            let mut hw_clear_dr7_buf = [0u8; 8];
                            let hw_breakpoint_cleared = getctx_hw_clear == 0
                                && img_spawn::smss_copyin(
                                    A_CONTEXT + nt_thread_start::CONTEXT_DR7_OFFSET,
                                    &mut hw_clear_dr7_buf,
                                )
                                && u64::from_le_bytes(hw_clear_dr7_buf)
                                    == nt_thread_start::AMD64_DR7_RESERVED_ONE;
                            let cont_hw =
                                if read_hw && setctx_hw_clear == 0 && hw_breakpoint_cleared {
                                    sysc!(
                                        SSN_NT_DEBUG_CONTINUE,
                                        &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                                    )
                                } else {
                                    u32::MAX
                                };
                            let woke_hw = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed)
                                == resumed_before_hw + 1;
                            dbgk_blk_trace(
                                b"c2hw",
                                no_progress_hw as u64,
                                wait_hw as u64,
                                cont_hw as u64,
                                woke_hw as u64,
                            );
                            if hw_fault
                                && no_progress_hw
                                && read_hw
                                && hw_breakpoint_cleared
                                && cont_hw == 0
                                && woke_hw
                            {
                                bk_ok |= 0x0200;
                            }
                            if !woke_hw {
                                let _ = crate::win32k_glue::tcb_unset_breakpoint(client_tcb, 0);
                                if !blocked_hw {
                                    client_reply_on(reply_hw, 0, 0, 0, 0, 0);
                                }
                                let _ = nt_handler.dbgk_release_all_blocked_reporters();
                                break;
                            }
                        }
                        // ═══ FAULT 2 — DebugException (int3) ══════════════════════════════
                        let (_fb, f2_mi, f2_m0, f2_m1, _f2m2, _f2m3) =
                            recv_full_r12(client_ep, reply_b);
                        dbgk_blk_trace(b"f2", f2_mi, f2_m0, f2_m1, marker_t());
                        if mapped
                            && read1
                            && cont1 == 0
                            && nt_handler.pm.blocked_reporter_count(object) == 0
                            && (f2_mi >> 12) == 4
                            && f2_m1 == dbgk::SEL4_DEBUG_REASON_SOFTWARE_BREAK_REQUEST
                            && marker_t() == 2
                        {
                            bk_ok |= 0x0004;
                        }
                        // 0x0008 — the DebugException flavour: forward the int3, BLOCK its reporter,
                        // prove no progress, then let the debugger edit the real target context
                        // before continuing it.
                        let forwarded2 = nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            main_tid as u64,
                            dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, f2_m0),
                            true,
                        );
                        let blocked2 = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                            reply_b,
                            f2_m0,
                            0,
                            0,
                            0,
                        );
                        let no_progress2 = forwarded2
                            && blocked2
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 2;
                        if !blocked2 {
                            break;
                        }
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait2 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read2 = wait2 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE;
                        let tf_flags_written = read2
                            && no_progress2
                            && client_runtime_registered
                            && debuggee_thread_handle != 0
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_CONTROL.to_le_bytes(),
                            );
                        let getctx_tf = if tf_flags_written {
                            sysc!(
                                SSN_NT_GET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let mut eflags_buf = [0u8; 4];
                        let eflags_read = getctx_tf == 0
                            && img_spawn::smss_copyin(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &mut eflags_buf,
                            );
                        let original_eflags = if eflags_read {
                            u32::from_le_bytes(eflags_buf)
                        } else {
                            0
                        };
                        let tf_eflags = original_eflags | EFLAGS_TF;
                        let tf_eflags_written = eflags_read
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &tf_eflags.to_le_bytes(),
                            );
                        let setctx_tf = if tf_eflags_written {
                            sysc!(
                                SSN_NT_SET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let cont2 = if read2 && setctx_tf == 0 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke2 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(
                            b"c2",
                            no_progress2 as u64,
                            wait2 as u64,
                            cont2 as u64,
                            woke2 as u64,
                        );
                        if !woke2 {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // 0x0010 — context edit proof. The debugger-set TF must produce a real
                        // single-step `#DB` after the one-byte nop, before marker 3 is written.
                        let (_fb, f2s_mi, f2s_m0, f2s_m1, _f2s_m2, _f2s_m3) =
                            recv_full_r12(client_ep, reply_step);
                        dbgk_blk_trace(b"f2s", f2s_mi, f2s_m0, f2s_m1, marker_t());
                        let step_fault = no_progress2
                            && cont2 == 0
                            && setctx_tf == 0
                            && (f2s_mi >> 12) == 4
                            && f2s_m1 == dbgk::SEL4_DEBUG_REASON_SINGLE_STEP
                            && marker_t() == 2;
                        let forwarded_step = step_fault
                            && nt_handler.dbgk_forward_exception(
                                blk_test_pi,
                                main_tid as u64,
                                dbgk::ExceptionRecord::new(dbgk::STATUS_SINGLE_STEP, f2s_m0),
                                true,
                            );
                        let blocked_step = forwarded_step
                            && nt_handler.dbgk_block_reporter(
                                blk_test_pi,
                                main_tid as u64,
                                0,
                                dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                                reply_step,
                                f2s_m0,
                                0,
                                0,
                                0,
                            );
                        let no_progress_step = blocked_step
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 2;
                        let resumed_before_step = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait_step = if blocked_step {
                            sysc!(
                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                            )
                        } else {
                            u32::MAX
                        };
                        let read_step = wait_step == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_SINGLE_STEP_STATE_CHANGE;
                        let clear_flags_written = read_step
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_FLAGS_OFFSET,
                                &CONTEXT_AMD64_CONTROL.to_le_bytes(),
                            );
                        let getctx_clear = if clear_flags_written {
                            sysc!(
                                SSN_NT_GET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let mut clear_buf = [0u8; 4];
                        let clear_read = getctx_clear == 0
                            && img_spawn::smss_copyin(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &mut clear_buf,
                            );
                        let clear_eflags = if clear_read {
                            u32::from_le_bytes(clear_buf) & !EFLAGS_TF
                        } else {
                            0
                        };
                        let clear_written = clear_read
                            && img_spawn::smss_copyout(
                                A_CONTEXT + AMD64_CONTEXT_EFLAGS_OFFSET,
                                &clear_eflags.to_le_bytes(),
                            );
                        let setctx_clear = if clear_written {
                            sysc!(
                                SSN_NT_SET_CONTEXT_THREAD,
                                &[debuggee_thread_handle, A_CONTEXT]
                            )
                        } else {
                            u32::MAX
                        };
                        let cont_step = if read_step && setctx_clear == 0 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke_step = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed)
                            == resumed_before_step + 1;
                        dbgk_blk_trace(
                            b"c2s",
                            no_progress_step as u64,
                            wait_step as u64,
                            cont_step as u64,
                            woke_step as u64,
                        );
                        if step_fault
                            && no_progress_step
                            && read_step
                            && setctx_clear == 0
                            && cont_step == 0
                            && woke_step
                        {
                            bk_ok |= 0x0010;
                        }
                        if !woke_step {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // ═══ FAULT 3 — UnknownSyscall: the SYSCALL flavour ═══════════════
                        let (_fb, f3_mi, f3_m0, _f3_m1, f3_m2, _f3_m3) =
                            recv_full_r12(client_ep, reply_c);
                        // The service loop's own derivation: for an UnknownSyscall the resume IP is
                        // RCX (MR2) — the address `syscall` pushed — NOT the message's FaultIP slot.
                        let f3_ip = f3_m2;
                        let f3_sp = get_recv_mr(16);
                        let f3_flags = get_recv_mr(17);
                        dbgk_blk_trace(b"f3", f3_mi, f3_m0, 0, marker_t());
                        if no_progress2
                            && cont2 == 0
                            && woke_step
                            && (f3_mi >> 12) == 2
                            && f3_m0 == 0xDB
                            && marker_t() == 3
                        {
                            bk_ok |= 0x0008;
                        }
                        // 0x0020 — the SYSCALL flavour. A real `DbgkMapViewOfSection` load-dll event
                        // posted from a SYSCALL blocks its reporter (NT queues it with flags 0), and
                        // DBG_CONTINUE supplies only status in MR0, preserving the canonical
                        // continuation so the syscall returns and the client runs on.
                        nt_handler.current_tid = main_tid as u64;
                        let module_posted = nt_handler.dbgk_module_load(
                            blk_test_pi,
                            0x0000_0001_9100_0000,
                            0,
                            (0, 0),
                            0,
                        );
                        nt_handler.current_tid = debugger_tid as u64;
                        nt_handler.dbgk_block_request = false;
                        let blocked3 = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_SYSCALL,
                            reply_c,
                            f3_ip,
                            f3_sp,
                            f3_flags,
                            0,
                        );
                        let no_progress3 = module_posted && blocked3 && marker_t() == 3;
                        if !blocked3 {
                            break;
                        }
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait3 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read3 = wait3 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_LOAD_DLL_STATE_CHANGE;
                        let cont3 = if read3 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke3 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(
                            b"c3",
                            no_progress3 as u64,
                            wait3 as u64,
                            cont3 as u64,
                            woke3 as u64,
                        );
                        if !woke3 {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // ═══ FAULT 4 — UserException (`ud2`) ════════════════════════════
                        let (_fb, f4_mi, f4_m0, f4_m1, f4_m2, _f4m3) =
                            recv_full_r12(client_ep, reply_d);
                        dbgk_blk_trace(b"f4", f4_mi, f4_m0, 0, marker_t());
                        if no_progress3 && cont3 == 0 && (f4_mi >> 12) == 3 && marker_t() == 4 {
                            bk_ok |= 0x0020;
                        }
                        // 0x0040 — ★ DBG_TERMINATE_THREAD **ENFORCED**. Block the `ud2` reporter,
                        // then continue with DBG_TERMINATE_THREAD: the reporting ETHREAD is really
                        // terminated and it is NEVER resumed — the marker stays 4, i.e. the
                        // instruction after the `ud2` never executed. (Before this batch the status
                        // was recorded, not enforced.)
                        let forwarded4 = nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            main_tid as u64,
                            dbgk::ExceptionRecord::new(0xC000_001D, f4_m0),
                            true,
                        );
                        let blocked4 = nt_handler.dbgk_block_reporter(
                            blk_test_pi,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_USER_EXCEPTION,
                            reply_d,
                            f4_m0,
                            f4_m1,
                            f4_m2,
                            0,
                        );
                        let terms_before = DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed);
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait4 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let terminated = forwarded4
                            && blocked4
                            && wait4 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                            && sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_TERMINATE_THREAD as u64]
                            ) == 0;
                        dbgk_blk_trace(
                            b"term",
                            terminated as u64,
                            DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed),
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed),
                            marker_t(),
                        );
                        if terminated
                            && DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed) == terms_before + 1
                            && DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before
                            && nt_handler
                                .pm
                                .thread(main_tid)
                                .is_some_and(|t| t.state == nt_process::ThreadState::Terminated)
                            && marker_t() == 4
                        {
                            bk_ok |= 0x0040;
                        }
                        break;
                    }

                    // ═══ 0x0100 — ★ THE DEBUGGER-SIDE BLOCKING WAIT, with a LIVE CLIENT ═══════
                    // A second real client thread issues a syscall the test services as
                    // `NtWaitForDebugEvent` with an EMPTY queue. Its private fault endpoint is
                    // received with REPLY_MAIN, so the PRODUCTION
                    // `wait_park` steals its reply capability exactly as the service loop does. The
                    // client cannot progress until a queue-side post runs `wait_wake_dispatcher_set`.
                    let dphase_ready = target_registered && attached && keepalive.is_some();
                    let debugger_wait_tid = dphase_ready
                        .then(|| nt_handler.pm.create_thread(debugger_pid, selftests::DBGK_CLIENT_CODE, 0, false).ok())
                        .flatten();
                    let debugger_ep = alloc_slot();
                    slots[nslots] = debugger_ep;
                    nslots += 1;
                    let debugger_fault = alloc_slot();
                    slots[nslots] = debugger_fault;
                    nslots += 1;
                    let debugger_endpoint_ready = debugger_wait_tid.is_some()
                        && untyped_retype_r(CAP_INIT_UNTYPED, OBJ_ENDPOINT, 0, 1, debugger_ep) == 0
                        && cnode_mint_r(
                            CAP_INIT_THREAD_CNODE,
                            debugger_fault,
                            debugger_ep,
                            BLK_DEBUGGER_RUNTIME_BADGE,
                        ) == 0;
                    let (dbg_pml4, dbg_tcb, _dbg_ep) = if debugger_endpoint_ready {
                        let dcode = selftests::dbgk_debugger_client_code();
                        selftests::dbgk_client_spawn(
                            &dcode,
                            shared_d,
                            write_scratch_d,
                            debugger_fault,
                            &mut slots,
                            &mut nslots,
                        )
                    } else {
                        (0, 0, 0)
                    };
                    let debugger_runtime_registered = debugger_wait_tid.is_some_and(|tid| {
                        dbg_tcb != 0
                            && nt_handler.register_hosted_thread_tcb(
                                0,
                                u64::from(tid),
                                dbg_tcb,
                                BLK_DEBUGGER_RUNTIME_BADGE,
                                HostedThreadRole::DbgkSelftestTarget,
                            )
                    });
                    let win_d = if dphase_ready {
                        let s = copy_cap(shared_d);
                        slots[nslots] = s;
                        nslots += 1;
                        s
                    } else {
                        0
                    };
                    let win_d_ok = dphase_ready
                        && page_map_r(win_d, marker_win_d, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
                    let marker_d = || {
                        if win_d_ok {
                            core::ptr::read_volatile(marker_win_d as *const u64)
                        } else {
                            u64::MAX
                        }
                    };
                    // Drain anything still queued so the wait genuinely finds nothing to report.
                    let mut drain_guard = 0;
                    while dphase_ready && drain_guard < 16 {
                        drain_guard += 1;
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                        {
                            break;
                        }
                        if !img_spawn::smss_copyin(A_STATE, &mut sc) {
                            break;
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                    }
                    // The root Reply slot is empty after the shared-ingress Call parks. This
                    // private endpoint needs its own pool-owned Reply for the live wait proof.
                    let private_reply = if debugger_runtime_registered
                        && REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0
                    {
                        wait_reply_pool_find_free().and_then(|(index, cap)| {
                            if !wait_reply_pool_mark_used(index) { return None; }
                            REPLY_MAIN_SLOT.store(cap, Ordering::Relaxed);
                            Some(cap)
                        })
                    } else {
                        None
                    };
                    // The private endpoint has exactly one registered sender. A mismatched fault
                    // fails this proof; no shared-endpoint caller is discarded or rebound.
                    let (w_badge, w_mi, w_m0, _, w_ip, _) = if let Some(reply) = private_reply {
                        recv_full_r12(debugger_ep, reply)
                    } else {
                        (0, 0, 0, 0, 0, 0)
                    };
                    let w_sp = get_recv_mr(16);
                    let w_flags = get_recv_mr(17);
                    let saved_wait_caller = (
                        nt_handler.current_tid,
                        nt_handler.current_badge,
                        nt_handler.current_resume_ip,
                        nt_handler.current_sp,
                        nt_handler.current_flags,
                        nt_handler.current_native_call_transport,
                    );
                    let debugger_wait_received = debugger_runtime_registered
                        && w_badge == BLK_DEBUGGER_RUNTIME_BADGE
                        && (w_mi >> 12) == 2
                        && w_m0 == 0xD1;
                    if debugger_wait_received {
                        nt_handler.current_tid = u64::from(debugger_wait_tid.unwrap());
                        nt_handler.current_badge = w_badge;
                        nt_handler.current_resume_ip = w_ip;
                        nt_handler.current_sp = w_sp;
                        nt_handler.current_flags = w_flags;
                        nt_handler.current_native_call_transport = false;
                    }
                    dbgk_blk_trace(b"dw1", w_mi, w_m0, 0, marker_d());
                    // The handler's own park REQUEST (NULL *Timeout, empty queue) — the exact arm a
                    // hosted debugger would take.
                    nt_handler.wait_park_event = -1;
                    let wait_status = if debugger_wait_received {
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE])
                    } else {
                        nt_process::STATUS_INSUFFICIENT_RESOURCES
                    };
                    let park_index = nt_handler.wait_park_event;
                    let live_parked = target_registered
                        && attached
                        && dbg_pml4 != 0
                        && debugger_wait_received
                        && wait_status == 0x102
                        && park_index >= 0
                        && wait_park(
                            &mut nt_handler,
                            WaitObject::dispatcher(park_index as usize),
                            false,
                            u64::from(debugger_wait_tid.unwrap()),
                            nt_delay_execution::Deadline::Infinite,
                        )
                        && marker_d() == 0;
                    // A queue-side post through the very entry the fault path uses SETS the
                    // object's EventsPresent dispatcher event and wakes the parked client.
                    let wake_posted = live_parked
                        && nt_handler.dbgk_forward_exception(
                            blk_test_pi,
                            keepalive.unwrap_or(0) as u64,
                            dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, 0x9999),
                            true,
                        );
                    // Only an acknowledged terminal delivery permits another blocking receive.
                    // A queued event alone cannot prove a failed Reply actually resumed the TCB.
                    if live_parked
                        && wake_posted
                        && !object_waiter_contains_tid(u64::from(debugger_wait_tid.unwrap()))
                    {
                        let (wb2, w2_mi, w2_m0, _x1, _x2, _x3) =
                            recv_full_r12(debugger_ep, reply_debugger_done);
                        dbgk_blk_trace(b"dw2", w2_mi, w2_m0, 0, marker_d());
                        if wb2 == BLK_DEBUGGER_RUNTIME_BADGE
                            && (w2_mi >> 12) == 2
                            && w2_m0 == 0xD2
                            && marker_d() == 1
                        {
                            bk_ok |= 0x0100;
                        }
                    } else if live_parked {
                        wait_cancel_thread(&mut nt_handler, u64::from(debugger_wait_tid.unwrap()));
                    } else if debugger_runtime_registered && w_mi >> 12 != 0 {
                        assert!(drop_current_hosted_reply(), "debugger proof failed to retire its received fault");
                    }
                    if private_reply.is_some() {
                        let replacement = REPLY_MAIN_SLOT.swap(0, Ordering::Relaxed);
                        let index = wait_reply_pool_find_cap(replacement)
                            .expect("debugger proof lost its private Reply replacement");
                        let identity = wait_reply_pool_ref().at(index)
                            .expect("debugger proof lost its private Reply identity");
                        assert_eq!(wait_reply_pool_ref().state(identity),
                            Ok(nt_component_suspension::RootReplySlotState::Used));
                        assert!(wait_reply_pool_mark_free(index));
                    }
                    (
                        nt_handler.current_tid,
                        nt_handler.current_badge,
                        nt_handler.current_resume_ip,
                        nt_handler.current_sp,
                        nt_handler.current_flags,
                        nt_handler.current_native_call_transport,
                    ) = saved_wait_caller;

                    // 0x0080 — ★ THE ESCAPE HATCH. Leave the live keepalive reporter blocked on
                    // the breakpoint event posted above, then destroy the debug object (`NtClose`
                    // → `DbgkpCloseObject`, i.e. the debugger died holding the event): every
                    // blocked target is RELEASED, so nothing can stay parked forever. The main
                    // reporter was deliberately terminated by the preceding phase and therefore
                    // cannot own another event.
                    let released_before = DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed);
                    let escape_tid = keepalive.unwrap_or(0) as u64;
                    let stranded = nt_handler.dbgk_block_reporter(
                        blk_test_pi,
                        escape_tid,
                        0,
                        dbgk::DBGK_BLOCK_VM_FAULT,
                        reply_spare,
                        0x1000,
                        0,
                        0,
                        0,
                    );
                    if stranded
                        && nt_handler.pm.blocked_reporter_count(object) == 1
                        && sysc!(SSN_NT_CLOSE, &[dbg_handle]) == 0
                        && DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed) == released_before + 1
                        && nt_handler.pm.debug_object(object).is_none()
                        && !nt_handler.pm.is_process_being_debugged(target)
                    {
                        bk_ok |= 0x0080;
                    }

                    // Reclaim private capabilities only after retained wait effects settle.
                    // An uncertain Send still owns the debugger TCB and all its runtime resources.
                    let _ = tcb_suspend_r(client_tcb);
                    if client_runtime_registered {
                        let _ = nt_handler.release_hosted_thread_runtime(main_tid as u64);
                    }
                    let mut debugger_resources_settled = true;
                    let mut debugger_tcb_owned = dbg_tcb != 0;
                    if let Some(tid) = debugger_wait_tid {
                        wait_cancel_thread(&mut nt_handler, u64::from(tid));
                        let _ = nt_handler.pm.terminate_thread(tid, 0);
                        crate::object_wait_reply::redrive(&mut nt_handler);
                        crate::object_wait_reply::redrive_terminated_runtimes(
                            &mut nt_handler,
                            &mut *delay_queue,
                        );
                        debugger_resources_settled = !object_waiter_contains_tid(u64::from(tid));
                        if debugger_runtime_registered
                            && nt_handler.thread_runtime.get_by_tid(u64::from(tid)).is_none()
                        {
                            // Retained termination reconciliation already deleted this TCB.
                            debugger_tcb_owned = false;
                        }
                        if debugger_resources_settled && debugger_runtime_registered {
                            let _ = nt_handler.release_hosted_thread_runtime(u64::from(tid));
                        }
                    }
                    if debugger_resources_settled {
                        if debugger_tcb_owned {
                            let _ = tcb_suspend_r(dbg_tcb);
                        }
                        for index in (0..nslots).rev() {
                            let s = slots[index];
                            if s == 0
                                || s == client_tcb
                                || s == dbg_tcb
                                || s == client_pml4
                                || s == dbg_pml4
                            {
                                continue;
                            }
                            let _ = cnode_delete_recycle_r(s);
                        }
                        let _ = cnode_delete_recycle_r(client_tcb);
                        if debugger_tcb_owned {
                            let _ = cnode_delete_recycle_r(dbg_tcb);
                        }
                        let _ = cnode_delete_recycle_r(client_pml4);
                        if dbg_pml4 != 0 {
                            let _ = cnode_delete_recycle_r(dbg_pml4);
                        }
                        if let Some(claim) = target_claim {
                            let _ = nt_handler.release_temporary_process_slot(claim);
                        }
                    } else {
                        bk_ok &= !0x0100;
                        print_str(b"[dbgk-blk] debugger teardown unsettled; private capabilities retained\n");
                    }
                }
            }

            print_str(b"[ntos-exec] dbgk target-block selftest bits=0x");
            print_hex(bk_ok as u32);
            print_str(b" blocked=");
            print_u64(DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed));
            print_str(b" resumed=");
            print_u64(DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed));
            print_str(b" terminated=");
            print_u64(DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed));
            print_str(b" released=");
            print_u64(DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed));
            print_str(b"\n");

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_BLOCK_SELFTEST.store(bk_ok, Ordering::Relaxed);
        }

        // === Dbgk REMOTE BREAK-IN SELF-TEST (POST-LOOP) — `DbgUiIssueRemoteBreakin`, end to end ===
        //
        // Three things had to become real together, because each is inert without the others:
        //   (1) CROSS-VSPACE THREAD CREATION — `NtCreateThread` with a FOREIGN `ProcessHandle` that
        //       really builds a thread (own stack + TEB + IPC buffer, caller-supplied entry AND
        //       parameter) inside the TARGET's address space (`create_remote_thread` →
        //       `rendezvous::spawn_slot_thread`).
        //   (2) `PEB->BeingDebugged` WRITE-THROUGH into the target's LIVE PEB page
        //       (`DbgkpMarkProcessPeb`) — without it `DbgUiRemoteBreakin` reads a zero byte, skips
        //       `DbgBreakPoint()` and exits silently, so the whole feature would be a no-op.
        //   (3) the `int3` → `DbgkForwardException` → `NtWaitForDebugEvent` → `NtDebugContinue`
        //       chain that batches 52 and 54 already built.
        //
        // The DEBUGGER side goes through the REAL dispatch route (`nt_dispatcher.dispatch(SSN, …)`
        // with the arguments marshalled in smss's CLIENT memory — the established idiom); the
        // TARGET side goes through `dbgk_forward_exception` / `dbgk_block_reporter`, the very
        // entries the live fault loop calls. The MECHANISM spawn calls `rendezvous::spawn_slot_thread`
        // — exactly what the loop's `spawn_requested_remote_thread` calls with the request the
        // handler produced — differing only in the two transport switches a target with no ntdll
        // mapped requires (direct entry instead of `LdrInitializeThunk`, hosted-syscalls instead of
        // the native Call) and a private endpoint, so the post-loop test can service it itself.
        if nt_handler.pm.has_process_exit_notify_registrations() {
            // This synthetic target has no ordinary provider create lifecycle. Do not inject its
            // exit into live providers from a post-loop diagnostic.
            print_str(b"[ntos-exec] dbgk remote-breakin selftest skipped: provider exit callbacks live\n");
            DBGK_BREAKIN_SELFTEST.store(0, Ordering::Relaxed);
        } else {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const PROCESS_CREATE_THREAD: u32 = 0x0002;
            const THREAD_ALL_ACCESS: u64 = 0x001F_03FF;
            const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
            // Argument scratch in smss's CLIENT memory (its stack mirror), clear of the block
            // self-test's window and of the live stack (which grows DOWN from the top).
            const A_HANDLE: u64 = STACK_BASE + 0x300;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x308;
            const A_TIMEOUT: u64 = STACK_BASE + 0x318;
            const A_STATE: u64 = STACK_BASE + 0x320;
            // A_STATE holds a whole DBGUI_WAIT_STATE_CHANGE (0xB8) → 0x320..0x3D8; keep the
            // NtCreateThread argument block clear of it.
            const A_THREAD_HANDLE: u64 = STACK_BASE + 0x400;
            const A_CID_OUT: u64 = STACK_BASE + 0x408;
            const A_CALLER_SP: u64 = STACK_BASE + 0x420; // the "client stack" NtCreateThread reads
            const A_CONTEXT: u64 = STACK_BASE + 0x500; // the caller's CONTEXT record
            const A_INITIAL_TEB: u64 = STACK_BASE + 0xa00;
            const A_STACK_BASE: u64 = STACK_BASE + 0xa30;
            const A_STACK_SIZE: u64 = STACK_BASE + 0xa38;
            // Outside the fixed worker windows and the executive's automatic heap mirror.
            const CALLER_STACK_BASE: u64 = SMSS_ALLOC_VA + 0x0200_0000;
            const CALLER_STACK_SIZE: u64 = 0x1_0000;
                                                       // Executive scratch inside the SAME proven-resident 2 MiB page table the other post-loop
                                                       // self-tests use (SMSS_SCRATCH_BASE + 3000*0x1000, PT index 5).
            let write_scratch = SMSS_SCRATCH_BASE + 3020 * 0x1000;
            let mark_win = SMSS_SCRATCH_BASE + 3021 * 0x1000;
            let peb_win = SMSS_SCRATCH_BASE + 3022 * 0x1000;

            let saved_client_pi = crate::executor::local().client_pi.load(Ordering::Relaxed);
            let saved_scratch_base = crate::executor::local().scratch_base.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx;
            crate::executor::local().client_pi.store(0, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut br_ok = 0u64;
            nt_handler.loop_ctx = saved_ctx.and_then(|ctx| ctx.for_process(0));
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            // Every dispatch through the real route, with the out-param write queue drained exactly
            // as the service loop drains it (`xas_write_u64` per queued write).
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {{
                    nt_handler.out_writes_n = 0;
                    let mut status = nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status;
                    for k in 0..nt_handler.out_writes_n {
                        let (ptr, val) = nt_handler.out_writes[k];
                        if !nt_handler.xas_write_u64(ptr, val) {
                            status = 0xC000_0005;
                        }
                    }
                    nt_handler.out_writes_n = 0;
                    status
                }};
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap())
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;

            let mut slots = [0u64; 64];
            let mut nslots = 0usize;
            // Macros (not closures) so the slot list stays freely usable alongside them.
            macro_rules! push_slot {
                ($cap:expr) => {{
                    let s = $cap;
                    slots[nslots] = s;
                    nslots += 1;
                    s
                }};
            }
            macro_rules! make {
                ($kind:expr, $bits:expr) => {{
                    let s = push_slot!(alloc_slot());
                    let made = untyped_retype_r(CAP_INIT_UNTYPED, $kind, $bits, 1, s);
                    if made != 0 {
                        print_str(b"[dbgk-brk] retype FAILED kind=");
                        print_u64($kind);
                        print_str(b" status=");
                        print_u64(made);
                        print_str(b"\n");
                    }
                    s
                }};
            }

            // ── The throwaway TARGET's address space ────────────────────────────────────────
            // A real hosted-process paging skeleton: the image PT, the hosted-client env PT
            // (PEB and test marker live in the dedicated env band), plus the WORK_CLUSTER PT that holds the
            // bounded thread-slot windows the remote thread's stack/TEB/IPC/trampoline land in.
            let target_pml4 = make!(OBJ_X86_PML4, PAGING_BITS);
            require_vspace_asid(target_pml4, b"dbgk-breakin-target");
            map_image_skeleton(target_pml4, 1);
            map_hosted_client_env_pt(target_pml4);
            map_tp_worker_target_lane_pts(target_pml4);
            let target = nt_handler.pm.create_process("dbgk-breakin.exe", None, None);
            nt_handler.pm.set_image_base(target, 0x0000_0001_A000_0000);
            let brk_test_claim = nt_handler
                .claim_temporary_process_slot(target, target_pml4)
                .ok();
            let test_pi = brk_test_claim
                .map(TemporaryProcessSlotClaim::pi)
                .unwrap_or(MAX_PI);
            // The real VM allocator consumes the target's ProcExec, not merely its Ps VSpace
            // lookup. Keep the previous empty slot until all caller VM ownership is retired.
            let saved_target_proc = if brk_test_claim.is_some() {
                nt_handler.loop_ctx.and_then(|ctx| {
                    let previous = (&*ctx.procs).get(test_pi).copied()?;
                    if previous.pid != 0 || previous.pml4 != 0
                        || !process_vm_region_map(test_pi).is_some_and(|map| map.extent_count() == 0)
                        || process_user_page_table_commit_bytes(test_pi) != 0
                    {
                        return None;
                    }
                    (&mut *ctx.procs)[test_pi] = ProcExec {
                        pid: u64::from(target),
                        pml4: target_pml4,
                        scratch_base: SMSS_SCRATCH_BASE + 3023 * 0x1000,
                        ..ProcExec::empty()
                    };
                    Some(previous)
                })
            } else {
                None
            };
            // The target's PEB page: mapped in ITS VSpace first, then windowed into the executive
            // (a frame capability carries its own mapping — map the original before any copy), and
            // registered with that window as its permanent alias, exactly as `spawn_sec_image`
            // registers a hosted process's PEB. That registration is what lets the general
            // client-memory writer reach it — `dbgk_mark_process_peb` invents no new mechanism.
            let peb_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let peb_mapped = page_map_r(peb_frame, SMSS_PEB_VA, RW_NX, target_pml4) == 0;
            let peb_alias = push_slot!(copy_cap(peb_frame));
            let peb_win_ok =
                peb_mapped && page_map_r(peb_alias, peb_win, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            let peb_registered = peb_win_ok
                && brk_test_claim.is_some()
                && csrss_frame_put_at_cap(
                    test_pi as u64,
                    nt_memory_manager::MemoryLifetime::Process(brk_test_claim.unwrap().identity()),
                    SMSS_PEB_VA,
                    peb_frame,
                    peb_win,
                    peb_alias,
                );
            // The marker page (target-only) + the executive's window on the same frame.
            let mark_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let mark_mapped = page_map_r(
                mark_frame,
                selftests::DBGK_BREAKIN_MARK_VA,
                RW_NX,
                target_pml4,
            ) == 0;
            let mark_alias = push_slot!(copy_cap(mark_frame));
            let mark_win_ok =
                mark_mapped && page_map_r(mark_alias, mark_win, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            let marker = |offset: u64| -> u64 {
                if mark_win_ok {
                    core::ptr::read_volatile((mark_win + offset) as *const u64)
                } else {
                    u64::MAX
                }
            };
            let peb_being_debugged = || -> u64 {
                if peb_win_ok {
                    core::ptr::read_volatile(
                        (peb_win + nt_ntdll_layout::PEB_BEING_DEBUGGED_OFFSET as u64) as *const u8,
                    ) as u64
                } else {
                    u64::MAX
                }
            };
            // `DbgUiRemoteBreakin`'s code page: written through an executive alias, mapped RX (W^X).
            let code = selftests::dbgk_breakin_thread_code();
            let code_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let code_written =
                page_map_r(code_frame, write_scratch, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            if code_written {
                for (i, b) in code.iter().enumerate() {
                    core::ptr::write_volatile((write_scratch + i as u64) as *mut u8, *b);
                }
            }
            let code_copy = push_slot!(copy_cap(code_frame));
            let code_mapped = code_written
                && page_map_r(
                    code_copy,
                    selftests::DBGK_BREAKIN_CODE_VA,
                    /* RX */ 2,
                    target_pml4,
                ) == 0;

            let brk_ep = make!(OBJ_ENDPOINT, 0);
            let reply_a = make!(OBJ_REPLY, 0);
            let reply_b = make!(OBJ_REPLY, 0);

            // ── The throwaway TARGET process object ────────────────────────────────────────
            let target_main = nt_handler
                .pm
                .create_thread(target, selftests::DBGK_BREAKIN_CODE_VA, 0, false)
                .unwrap_or(0);
            let target_backing = if peb_registered && target_main != 0
                && nt_handler.pm.set_peb_base(target, SMSS_PEB_VA)
            {
                let scratch = crate::executor::local().scratch_base.load(Ordering::Relaxed);
                let lifetime = nt_handler.pm.thread_lifetime(target_main)
                    .expect("debugger target main thread has an exact lifetime");
                match ps_object_backing::prepare_process(&nt_handler.pm, target, scratch) {
                    Ok(process_body) => {
                        match ps_object_backing::prepare_thread(&nt_handler.pm, lifetime, scratch) {
                            Ok(_) => {
                                if ps_object_backing::publish_prepared_pair(
                                    &mut nt_handler.pm, lifetime,
                                ).is_ok() {
                                    true
                                } else {
                                    ps_object_backing::abort_prepared_thread(
                                        &nt_handler.pm, lifetime, scratch,
                                    ).expect("failed debugger target retains unpublished thread body");
                                    ps_object_backing::abort_unpublished(
                                        &nt_handler.pm, process_body, scratch,
                                    ).expect("failed debugger target retains unpublished process body");
                                    false
                                }
                            }
                            Err(_) => {
                                ps_object_backing::abort_prepared_thread(
                                    &nt_handler.pm, lifetime, scratch,
                                ).expect("failed debugger target retains unpublished thread body");
                                ps_object_backing::abort_unpublished(
                                    &nt_handler.pm, process_body, scratch,
                                ).expect("failed debugger target retains unpublished process body");
                                false
                            }
                        }
                    }
                    Err(_) => false,
                }
            } else {
                false
            };
            let target_registered = brk_test_claim.is_some();
            // This process HAS its initial thread, so a foreign-handle create is a genuine
            // ADDITIONAL thread — the real cross-VSpace path (exactly the live rule).
            if target_registered {
                let plan = nt_handler.pm.prepare_initial_thread_creation(target)
                    .expect("debugger fixture reserves its exact initial thread")
                    .expect("debugger fixture has a fresh initial thread");
                nt_handler.pm.commit_initial_thread_creation(&plan)
                    .expect("debugger fixture retains its published initial thread");
            }

            let h_target = nt_handler
                .pm
                .insert_handle(
                    debugger_pid,
                    nt_process::HandleObject::Process(target),
                    PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | 0x0008, // PROCESS_VM_OPERATION
                )
                .map(u64::from)
                .unwrap_or(0);
            // The SAME process, through a handle that lacks PROCESS_CREATE_THREAD.
            let h_target_no_create = nt_handler
                .pm
                .insert_handle(
                    debugger_pid,
                    nt_process::HandleObject::Process(target),
                    PROCESS_SUSPEND_RESUME,
                )
                .map(u64::from)
                .unwrap_or(0);

            let args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_CONTEXT, &[0u8; nt_thread_start::AMD64_CONTEXT_SIZE])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            let caller_stack_allocated = saved_target_proc.is_some()
                && args_ready
                && h_target != 0
                && img_spawn::smss_copyout(A_STACK_BASE, &CALLER_STACK_BASE.to_le_bytes())
                && img_spawn::smss_copyout(A_STACK_SIZE, &CALLER_STACK_SIZE.to_le_bytes())
                && sysc!(SSN_NT_ALLOCATE_VM, &[
                    h_target, A_STACK_BASE, 0, A_STACK_SIZE,
                    u64::from(nt_address_space::MEM_RESERVE | nt_address_space::MEM_COMMIT),
                    u64::from(nt_address_space::PAGE_READWRITE),
                ]) == 0;
            let setup_ok = peb_registered
                && mark_win_ok
                && code_mapped
                && target_main != 0
                && target_backing
                && target_registered
                && h_target != 0
                && h_target_no_create != 0
                && args_ready
                && caller_stack_allocated
                && smss_stack_read(A_STACK_BASE) == CALLER_STACK_BASE
                && smss_stack_read(A_STACK_SIZE) == CALLER_STACK_SIZE
                && debugger_pid != 0;

            let mut spawned_breakin_tid = 0u64;
            let mut breakin_runtime_tid = 0u64;
            if setup_ok {
                // ── 0x0001 — a real DEBUG_OBJECT + attach BY SSN, fake create messages drained ──
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    let peb_before = peb_being_debugged();
                    let marks_before = DBGK_PEB_MARKS.load(Ordering::Relaxed);
                    let attached = sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    // Drain every fake thread/module message. Dormant pool identities are not live
                    // threads and therefore do not contribute to this cardinality.
                    let mut drained = 0u64;
                    while attached && drained < 8 {
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                            || !img_spawn::smss_copyin(A_STATE, &mut sc)
                        {
                            break;
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    if attached
                        && drained != 0
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        br_ok |= 0x0001;
                    }
                    // ── 0x0002 — ★ `PEB->BeingDebugged` WRITTEN THROUGH, read back out of the
                    // TARGET's own PEB page (the very frame its VSpace maps at SMSS_PEB_VA).
                    if peb_before == 0
                        && peb_being_debugged() == 1
                        && DBGK_PEB_MARKS.load(Ordering::Relaxed) == marks_before + 1
                        && nt_handler.pm.is_process_being_debugged(target)
                    {
                        br_ok |= 0x0002;
                    }

                    // ── 0x0008 — ★ THE CROSS-VSPACE CREATE, BY SSN. Marshal NtCreateThread's
                    // stack-resident arguments (ClientId / ThreadContext / InitialTeb /
                    // CreateSuspended) in CLIENT memory and stage the caller stack pointer the
                    // handler reads them through, then issue SSN 55 with the TARGET's handle.
                    let mut context = [0u8; nt_thread_start::AMD64_CONTEXT_SIZE];
                    nt_thread_start::initialize_amd64_user_context(
                        &mut context,
                        selftests::DBGK_BREAKIN_CODE_VA,
                        selftests::DBGK_BREAKIN_PARAM,
                        CALLER_STACK_BASE + CALLER_STACK_SIZE,
                    );
                    let mut initial_teb = [0u8; nt_thread_start::INITIAL_TEB64_SIZE];
                    initial_teb[0x10..0x18].copy_from_slice(&(CALLER_STACK_BASE + CALLER_STACK_SIZE).to_le_bytes());
                    initial_teb[0x18..0x20].copy_from_slice(&CALLER_STACK_BASE.to_le_bytes());
                    initial_teb[0x20..0x28].copy_from_slice(&CALLER_STACK_BASE.to_le_bytes());
                    let ctx_ok = img_spawn::smss_copyout(A_CONTEXT, &context)
                        && img_spawn::smss_copyout(A_INITIAL_TEB, &initial_teb)
                        && img_spawn::smss_copyout(A_CALLER_SP + 0x28, &A_CID_OUT.to_le_bytes())
                            && img_spawn::smss_copyout(
                                A_CALLER_SP + 0x30,
                                &A_CONTEXT.to_le_bytes(),
                            )
                            && img_spawn::smss_copyout(A_CALLER_SP + 0x38, &A_INITIAL_TEB.to_le_bytes())
                            && img_spawn::smss_copyout(A_CALLER_SP + 0x40, &0u64.to_le_bytes())
                            && img_spawn::smss_copyout(A_THREAD_HANDLE, &0u64.to_le_bytes())
                            && img_spawn::smss_copyout(A_CID_OUT, &[0u8; 16]);
                    set_recv_mr(16, A_CALLER_SP);
                    // ★ The security negative FIRST (it must change nothing): the same target
                    // through a handle without PROCESS_CREATE_THREAD.
                    // NtCreateThread's full 8-argument shape (the dispatcher enforces argc):
                    // ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
                    // ThreadContext, InitialTeb, CreateSuspended — the last four also readable
                    // through the caller's stack, which is where the handler takes them from.
                    let denied = sysc!(
                        SSN_NT_CREATE_THREAD,
                        &[
                            A_THREAD_HANDLE,
                            THREAD_ALL_ACCESS,
                            0,
                            h_target_no_create,
                            A_CID_OUT,
                            A_CONTEXT,
                            A_INITIAL_TEB,
                            0,
                        ]
                    );
                    let created_before = PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed);
                    set_recv_mr(16, A_CALLER_SP);
                    let create_status = sysc!(
                        SSN_NT_CREATE_THREAD,
                        &[
                            A_THREAD_HANDLE,
                            THREAD_ALL_ACCESS,
                            0,
                            h_target,
                            A_CID_OUT,
                            A_CONTEXT,
                            A_INITIAL_TEB,
                            0,
                        ]
                    );
                    let request = nt_handler.remote_thread_request.take();
                    let publication_invisible = request.as_ref().is_some_and(|request| {
                        smss_stack_read(A_THREAD_HANDLE) == 0
                            && smss_stack_read(A_CID_OUT) == 0
                            && smss_stack_read(A_CID_OUT + 8) == 0
                            && nt_handler
                                .pm
                                .lookup_handle(
                                    debugger_pid,
                                    request.publication.handle() as nt_process::Handle,
                                )
                                .is_none()
                    });
                    let request_observation = request.as_ref().map(|request| (
                        request.target_pi, request.pml4, request.start.rip,
                        request.start.rcx, request.cid_thread,
                    ));

                    // ── 0x0010 — ★ THE REMOTE THREAD REALLY RUNS IN THE TARGET'S VSPACE.
                    // Build the mechanism through the same entry the loop uses; the thread's own
                    // stack/TEB/IPC buffer are mapped in the TARGET's pml4, and the marker it writes
                    // lands in a page that exists ONLY there.
                    let mut spawned_tcb = 0u64;
                    let mut breakin_runtime_slot = 0usize;
                    if let Some(request) = request {
                        breakin_runtime_slot = request.slot;
                        let runtime_publication = nt_handler.prepare_hosted_thread_runtime_publication(
                            test_pi, request.cid_thread, tp_worker_badge(test_pi, request.slot),
                            HostedThreadRole::TpWorker { slot: request.slot },
                        ).expect("debugger fixture owns its reserved runtime before construction");
                        let spawned = rendezvous::spawn_slot_thread(
                            &mut nt_handler,
                            &rendezvous::RemoteThreadSpawn {
                                target_pi: request.target_pi,
                                slot: request.slot,
                                pml4: request.pml4,
                                start: request.start,
                                initial_context: &request.initial_context,
                                stack_origin: request.stack_origin,
                                cid_proc: request.cid_proc,
                                cid_thread: request.cid_thread,
                                fault_ep: ThreadFaultEndpoint::Borrowed(brk_ep),
                                // The throwaway target has no ntdll mapped, so enter the start routine
                                // directly and keep the hosted-syscalls trap (its exit `syscall` is
                                // delivered here as an UnknownSyscall fault).
                                use_loader: false,
                                native: false,
                            },
                        );
                        match spawned {
                            Ok(spawned) => {
                                spawned_tcb = spawned.tcb();
                                nt_handler.finish_hosted_thread_publication(
                                    runtime_publication, spawned, request.publication, request.resume,
                                ).expect("debugger fixture activates before first resume and handle publication");
                                for k in 0..nt_handler.out_writes_n {
                                    let (ptr, val) = nt_handler.out_writes[k];
                                    assert!(nt_handler.xas_write_u64(ptr, val));
                                }
                                nt_handler.out_writes_n = 0;
                                spawned_breakin_tid = request.cid_thread;
                                PM_REMOTE_THREADS_SPAWNED.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(failure) => {
                                nt_handler.fail_hosted_thread_runtime_publication(runtime_publication, failure);
                                nt_handler.abort_unbuilt_hosted_thread_publication(
                                    request.publication, test_pi, tp_worker_badge(test_pi, request.slot),
                                    HostedThreadRole::TpWorker { slot: request.slot },
                                );
                            }
                        }
                    }
                    let thread_handle = smss_stack_read(A_THREAD_HANDLE);
                    let cid_proc = smss_stack_read(A_CID_OUT);
                    let breakin_tid = smss_stack_read(A_CID_OUT + 8);
                    breakin_runtime_tid = breakin_tid;
                    let handle_ok = matches!(
                        nt_handler
                            .pm
                            .lookup_handle(debugger_pid, thread_handle as nt_process::Handle),
                        Some(nt_process::HandleObject::Thread(t)) if t as u64 == breakin_tid
                    );
                    if publication_invisible
                        && ctx_ok
                        && denied == STATUS_ACCESS_DENIED
                        && create_status == 0
                        && PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed) == created_before + 1
                        && thread_handle != 0
                        && handle_ok
                        && cid_proc == target as u64
                        && breakin_tid != 0
                        && breakin_tid != target_main as u64
                        && request_observation.is_some_and(|(pi, pml4, rip, rcx, tid)| {
                            pi == test_pi
                                && pml4 == target_pml4
                                && rip == selftests::DBGK_BREAKIN_CODE_VA
                                && rcx == selftests::DBGK_BREAKIN_PARAM
                                && tid == breakin_tid
                        })
                    {
                        br_ok |= 0x0008;
                    }
                    print_str(b"[dbgk-brk] denied=0x");
                    print_hex(denied);
                    print_str(b" create=0x");
                    print_hex(create_status);
                    print_str(b" ctx_ok=");
                    print_u64(ctx_ok as u64);
                    print_str(b" invisible=");
                    print_u64(publication_invisible as u64);
                    print_str(b" h=0x");
                    print_hex(thread_handle as u32);
                    print_str(b" tid=");
                    print_u64(breakin_tid);
                    print_str(b" req=");
                    print_u64(request_observation.is_some() as u64);
                    print_str(b"\n");
                    if spawned_tcb != 0 {
                        // Its first fault: the `int3` if it read BeingDebugged = 1, else its exit
                        // syscall. Either way it must have RUN — the marker proves the thread
                        // executed in the target's address space with a correct TEB/PEB.
                        //
                        // Hosted TCB admission may emit a startup/scheduler notification before the
                        // thread reaches its entry trampoline. That notification is not the
                        // break-in thread's debuggee event, and treating it as such leaves the
                        // marker at zero. Select the first message after the marker page proves
                        // the break-in code has run; the private endpoint means any later selected
                        // message still belongs to this throwaway thread.
                        let mut f1 = None;
                        let mut saw_breakin_marker = false;
                        let mut f1_guard = 0;
                        while f1_guard < 8 {
                            f1_guard += 1;
                            let (_fb, mi_r, m0_r, m1_r, _m2_r, _m3_r) =
                                recv_full_r12(brk_ep, reply_a);
                            let ran = marker(0x00);
                            if ran == 0x11 || ran == 0x12 {
                                saw_breakin_marker = true;
                                let label = mi_r >> 12;
                                if label == 4 || label == 2 {
                                    dbgk_brk_trace(b"f1", mi_r, m0_r, m1_r, ran);
                                    f1 = Some((mi_r, m0_r));
                                    break;
                                }
                                dbgk_brk_trace(b"f1-wait", mi_r, m0_r, m1_r, ran);
                                continue;
                            }
                            dbgk_brk_trace(b"f1-foreign", mi_r, m0_r, m1_r, ran);
                        }
                        if saw_breakin_marker
                            && marker(0x00) == 0x11
                            && marker(0x08) == SMSS_PEB_VA
                            && marker(0x18) == selftests::DBGK_BREAKIN_PARAM
                        {
                            br_ok |= 0x0010;
                        }
                        if let Some((f1_mi, f1_m0)) = f1 {
                            // ── 0x0020 — ★ IT HIT THE BREAKPOINT, and the debugger sees it.
                            // The byte it read is the write-through; the `int3` (DebugException,
                            // label 4) is forwarded through the live fault-loop entry and its reporter
                            // parked. A real debugger may first receive the remote thread's
                            // DbgCreateThreadStateChange, because `NtCreateThread` queued it before
                            // the thread ran to `int3`; continue that lifecycle event, then retrieve
                            // the breakpoint BY SSN carrying the BREAK-IN THREAD's CLIENT_ID.
                            let is_breakpoint = (f1_mi >> 12) == 4 && marker(0x10) == 1;
                            let forwarded = is_breakpoint
                                && nt_handler.dbgk_forward_exception(
                                    test_pi,
                                    breakin_tid,
                                    dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, f1_m0),
                                    true,
                                );
                            let parked = forwarded
                                && nt_handler.dbgk_block_reporter(
                                    test_pi,
                                    breakin_tid,
                                    0,
                                    dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                                    reply_a,
                                    f1_m0,
                                    0,
                                    0,
                                    0,
                                );
                            let mut waited = false;
                            if parked {
                                let first_wait = sysc!(
                                    SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                    &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                                );
                                if first_wait == 0 && img_spawn::smss_copyin(A_STATE, &mut sc) {
                                    let selected_state = sc_u32!(0x00);
                                    let selected_tid =
                                        u64::from_le_bytes(sc[0x10..0x18].try_into().unwrap());
                                    if selected_state == dbgk::DBG_CREATE_THREAD_STATE_CHANGE
                                        && u64::from_le_bytes(sc[0x08..0x10].try_into().unwrap())
                                            == target as u64
                                        && selected_tid == breakin_tid
                                    {
                                        let mut lifecycle_cid = [0u8; 16];
                                        lifecycle_cid.copy_from_slice(&sc[0x08..0x18]);
                                        if img_spawn::smss_copyout(A_CLIENT_ID, &lifecycle_cid)
                                            && sysc!(
                                                SSN_NT_DEBUG_CONTINUE,
                                                &[
                                                    dbg_handle,
                                                    A_CLIENT_ID,
                                                    dbgk::DBG_CONTINUE as u64
                                                ]
                                            ) == 0
                                        {
                                            let second_wait = sysc!(
                                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                                            );
                                            waited = second_wait == 0
                                                && img_spawn::smss_copyin(A_STATE, &mut sc);
                                        }
                                    } else {
                                        waited = true;
                                    }
                                }
                            }
                            let reported = waited
                                && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE
                                && u64::from_le_bytes(sc[0x08..0x10].try_into().unwrap())
                                    == target as u64
                                && u64::from_le_bytes(sc[0x10..0x18].try_into().unwrap())
                                    == breakin_tid
                                && sc_u32!(0x18) == dbgk::STATUS_BREAKPOINT;
                            if reported {
                                br_ok |= 0x0020;
                            }
                            // ── 0x0040 — ★ CONTINUE RESUMES IT PAST THE int3 AND IT EXITS CLEANLY.
                            let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                            let mut cid = [0u8; 16];
                            cid[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                            cid[8..16].copy_from_slice(&breakin_tid.to_le_bytes());
                            let continued = reported
                                && img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                                && sysc!(
                                    SSN_NT_DEBUG_CONTINUE,
                                    &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                                ) == 0
                                && DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed)
                                    == resumed_before + 1;
                            if continued {
                                // Its exit path: marker 0x12 (it really resumed past the breakpoint)
                                // then the `RtlExitUserThread` stand-in syscall arrives here.
                                let (_eb, e_mi, e_m0, _em1, _em2, _em3) =
                                    recv_full_r12(brk_ep, reply_b);
                                if (e_mi >> 12) == 2
                                    && e_m0 == selftests::DBGK_BREAKIN_EXIT_SSN
                                    && marker(0x00) == 0x12
                                {
                                    br_ok |= 0x0040;
                                }
                            } else if parked {
                                let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            }
                        }
                    }

                    // ── 0x0004 — ★ DETACH CLEARS `PEB->BeingDebugged` in the LIVE PEB page.
                    let marks_before_detach = DBGK_PEB_MARKS.load(Ordering::Relaxed);
                    let detached = sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle]) == 0;
                    if detached
                        && peb_being_debugged() == 0
                        && DBGK_PEB_MARKS.load(Ordering::Relaxed) == marks_before_detach + 1
                        && !nt_handler.pm.is_process_being_debugged(target)
                    {
                        br_ok |= 0x0004;
                    }
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle, 0, 0, 0]);
                    // Reclaim: suspend the remote thread, then drop every throwaway cap. Keep
                    // `target_pml4` out of the recycle path for now because its skeleton mappings are
                    // not tracked in this local slot list; all other slots here are local aliases,
                    // replies, endpoints, or throwaway frames.
                    let brk_tcb = nt_handler
                        .hosted_thread_tcb_for_role(
                            test_pi,
                            HostedThreadRole::TpWorker {
                                slot: breakin_runtime_slot,
                            },
                        )
                        .unwrap_or(0);
                    if brk_tcb > 1 {
                        assert_eq!(tcb_suspend_r(brk_tcb), 0,
                            "diagnostic caller stack remains owned until its TCB is suspended");
                    }
                }
            }
            print_str(b"[ntos-exec] dbgk remote-breakin selftest bits=0x");
            print_hex(br_ok as u32);
            print_str(b" peb-marks=");
            print_u64(DBGK_PEB_MARKS.load(Ordering::Relaxed));
            print_str(b" remote-created=");
            print_u64(PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed));
            print_str(b" remote-spawned=");
            print_u64(PM_REMOTE_THREADS_SPAWNED.load(Ordering::Relaxed));
            print_str(b" marker=0x");
            print_hex(if mark_win_ok {
                core::ptr::read_volatile(mark_win as *const u64) as u32
            } else {
                0xFFFF_FFFF
            });
            print_str(b"\n");
            for i in (0..nslots).rev() {
                let s = slots[i];
                if s != 0 && s != target_pml4 {
                    let _ = cnode_delete_recycle_r(s);
                }
            }
            if spawned_breakin_tid != 0 {
                breakin_runtime_tid = spawned_breakin_tid;
            }
            if breakin_runtime_tid != 0 {
                if let Some(runtime) = nt_handler.release_hosted_thread_runtime(breakin_runtime_tid)
                {
                    release_hosted_thread_resources(runtime.resources);
                    nt_handler.release_hosted_thread_commitment(runtime.resources);
                    release_hosted_thread_mechanism_cnodes(runtime);
                }
            }
            if caller_stack_allocated {
                assert!(img_spawn::smss_copyout(A_STACK_BASE, &CALLER_STACK_BASE.to_le_bytes())
                    && img_spawn::smss_copyout(A_STACK_SIZE, &0u64.to_le_bytes()));
                assert_eq!(sysc!(SSN_NT_FREE_VM, &[
                    h_target, A_STACK_BASE, A_STACK_SIZE, u64::from(nt_address_space::MEM_RELEASE),
                ]), 0, "diagnostic retains target context until real caller VAD release succeeds");
            }
            for handle in [h_target, h_target_no_create] {
                if handle != 0 && nt_handler.pm.lookup_handle(
                    debugger_pid, handle as nt_process::Handle,
                ).is_some() {
                    nt_handler.pm.close_handle(debugger_pid, handle as nt_process::Handle)
                        .expect("debugger fixture closes its target process handle");
                }
            }
            let breakin_pm_tid = u32::try_from(breakin_runtime_tid)
                .expect("debugger fixture runtime thread ID fits the process manager");
            for tid in [target_main, breakin_pm_tid] {
                while tid != 0 && nt_handler.pm.close_handle_by_object(
                    debugger_pid, nt_process::HandleObject::Thread(tid),
                ) {}
            }
            while nt_handler.pm.close_handle_by_object(
                debugger_pid, nt_process::HandleObject::Process(target),
            ) {}
            if saved_target_proc.is_some() {
                assert!(process_vm_region_map(test_pi).is_some_and(|map| map.extent_count() == 0));
                let (_, failed) = process_user_page_tables_release(test_pi, &mut nt_handler);
                assert_eq!(failed, 0, "diagnostic retains charged target page tables on failure");
            }
            if let Some(claim) = brk_test_claim {
                let _ = csrss_frame_take(test_pi as u64, SMSS_PEB_VA);
                assert!(nt_handler.release_temporary_process_slot(claim),
                    "debugger fixture releases its temporary process slot");
            }
            if let Some(previous) = saved_target_proc {
                if let Some(accounting) = nt_handler.process_commit.accounting(target) {
                    assert_eq!(accounting.current_bytes, 0);
                    assert_eq!(nt_handler.process_commit.unregister(target), Some(accounting));
                }
                let ctx = nt_handler.loop_ctx.expect("diagnostic target retains its paging context");
                assert_eq!((&*ctx.procs)[test_pi].pml4, target_pml4);
                (&mut *ctx.procs)[test_pi] = previous;
            }
            assert!(nt_handler.pm.process_debug_port(target).is_none(),
                "debugger fixture detaches before retiring target Ps bodies");
            nt_handler.pm.terminate_process(target, nt_process::STATUS_SUCCESS)
                .expect("debugger fixture terminates its throwaway target");
            crate::process_terminal_receipt::drain_hosted_process_exit_notifications(&mut nt_handler);
            let retirement = nt_handler.pm.withdraw_process_object_if_unreferenced(target)
                .expect("debugger fixture releases every target object reference");
            let backing = ps_object_backing::retire_withdrawn(
                &nt_handler.pm,
                &retirement,
                crate::executor::local().scratch_base.load(Ordering::Relaxed),
            ).expect("debugger fixture retires its canonical Ps bodies");
            let _deletion = nt_handler.pm.finish_process_object_retirement(retirement)
                .expect("debugger fixture finishes canonical Ps retirement");
            if ps_object_backing::release_retired_addresses(backing).is_err() {
                panic!("debugger fixture retains retired Ps address slots");
            }
            nt_handler.remote_thread_request = None;

            crate::executor::local().client_pi.store(saved_client_pi, Ordering::Relaxed);
            crate::executor::local().scratch_base.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_timeout = PendingWaitTimeout::none();
            DBGK_BREAKIN_SELFTEST.store(br_ok, Ordering::Relaxed);
        }

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
    // Freeze hosted threads only after all post-quiesce active probes have run. The probes above
    // intentionally drive win32k callbacks, teardown, driver cancellation, and ALPC mappings; doing
    // a blanket TCB suspend before them corrupts the environment they are meant to prove.
    let (quiesce_suspended, quiesce_suspend_failures) =
        unsafe { nt_handler.suspend_hosted_threads_for_quiesce() };
    print_str(b"[quiesce-freeze] hosted-tcbs-suspended=");
    print_u64(quiesce_suspended as u64);
    print_str(b" failures=");
    print_u64(quiesce_suspend_failures as u64);
    print_str(b"\n");
    if csrss_process_handle != 0 {
        print_str(b"[sec-stop] csrss (badge 2) spawned, handle 0x");
        print_hex(csrss_process_handle as u32);
        print_str(b"; demand-paged ");
        print_u64(procs[csrss_pi].faults);
        print_str(b" page(s) (");
        print_u64(procs[csrss_pi].ntfaults);
        print_str(b" in ntdll), first fault=0x");
        print_hex((procs[csrss_pi].first >> 32) as u32);
        print_hex(procs[csrss_pi].first as u32);
        print_str(b"\n");
    }
    print_str(b"[sec-stop] NEXT_SLOT=");
    print_u64(NEXT_SLOT.load(Ordering::Relaxed));
    print_str(b" shared_frames=");
    print_u64(dll_cache_stats().0 as u64);
    print_str(b" shared_hits=");
    print_u64(DLL_SHARED_HITS.load(Ordering::Relaxed));
    print_str(b"\n[sec-stop] scratch-faults/pi=");
    for (pi, proc) in procs.iter().enumerate() {
        if pi != 0 {
            print_str(b",");
        }
        print_u64(pi as u64);
        print_str(b":");
        print_u64(proc.faults);
    }
    print_str(b" scratch-low-pts/pi=");
    for (pi, proc) in procs.iter().enumerate() {
        if pi != 0 {
            print_str(b",");
        }
        print_u64(pi as u64);
        print_str(b":");
        print_u64(proc.faults.saturating_add(511) / 512);
    }
    print_str(b"\n[sec-stop] badge=");
    print_u64(badge);
    print_str(b" (");
    print_str(hosted_leaf_for_fault_badge(&nt_handler, badge).unwrap_or(b"unknown"));
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
    {
        loader_trace_dump(&reg);
    }
    if let Some(winlogon_pi) = live_hosted_pi_for_observation_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) {
        WINLOGON_FAULTS.store(procs[winlogon_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] winlogon (pi ");
        print_u64(winlogon_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[winlogon_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[winlogon_pi].first >> 32) as u32);
        print_hex(procs[winlogon_pi].first as u32);
        print_str(b"\n");
    } else {
        WINLOGON_FAULTS.store(0, Ordering::Relaxed);
    }
    if let Some(services_pi) = live_hosted_pi_for_observation_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::ServiceControlManager,
    ) {
        SERVICES_FAULTS.store(procs[services_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] services (pi ");
        print_u64(services_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[services_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[services_pi].first >> 32) as u32);
        print_hex(procs[services_pi].first as u32);
        print_str(b"\n");
    } else {
        SERVICES_FAULTS.store(0, Ordering::Relaxed);
    }
    if let Some(lsass_pi) = live_hosted_pi_for_observation_role(
        &nt_handler,
        nt_exe_image::HostedProcessRole::LocalSecurityAuthority,
    ) {
        LSASS_FAULTS.store(procs[lsass_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] lsass (pi ");
        print_u64(lsass_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[lsass_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[lsass_pi].first >> 32) as u32);
        print_hex(procs[lsass_pi].first as u32);
        print_str(b"\n");
    } else {
        LSASS_FAULTS.store(0, Ordering::Relaxed);
    }
    // Path 3: record that each folded per-process ProcExec is EPROCESS-linked (live pml4 + its pid
    // matches the ProcessManager's pid for that pi). Read by `exec_eprocess_linked_mechanism`.
    let mut link_ok = 0u64;
    for (i, p) in procs.iter().enumerate() {
        if p.pml4 != 0
            && p.pid != 0
            && nt_handler.pm_pid_for_pi(i).map(|pid| pid as u64) == Some(p.pid)
        {
            link_ok |= 1 << i;
        }
    }
    PM_EXEC_LINK_OK.store(link_ok, Ordering::Relaxed);
    // Report the primary process's own fault stats regardless of which process stopped the loop.
    let boot_driver_start_reports = pending_driver_start_reports_snapshot(&nt_handler);
    let native_driver_load_report = nt_handler.native_driver_load_report;
    let live_device_action_report = print_live_device_action_report(&nt_handler);
    let start_device_call_report = print_start_device_call_report(&nt_handler);
    let desktop_acceptance_report = nt_handler.capture_desktop_acceptance_report();
    nt_handler.loop_ctx = None;
    (
        procs[primary_pi].faults,
        procs[primary_pi].first,
        stop,
        procs[primary_pi].ntfaults,
        stop_ssn,
        boot_driver_start_reports,
        native_driver_load_report,
        live_device_action_report,
        start_device_call_report,
        desktop_acceptance_report,
    )
}
