//! The reply-or-park tail of the syscall arm (issue #382, loop hoist).
//!
//! Everything a syscall does after its NT or win32k route returns: post-dispatch
//! bookkeeping, then either the park the outcome asks for or the reply, and the next receive.
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::loop_flow::*;
use super::loop_receive::{receive, reply_receive};
use super::*;

#[inline(never)]
pub(super) unsafe fn syscall_tail(
    lp: &mut LoopState<'_>,
    ev: &Event,
    call: &Syscall,
    sc: &mut SyscallOutcome,
) -> ControlFlow<Turn, core::convert::Infallible> {
    let mut nt_handler = &mut *lp.handler;
    let fault_ep = lp.ingress.fault_ep;
    let delay_queue = lp.ingress.delay_queue;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let exe_images = &mut *lp.images.exe_images;
    let exe_image_catalog = &mut *lp.images.exe_image_catalog;
    let hosted_loaded_images_ptr = lp.images.hosted_loaded_images_ptr;
    let ntdll = lp.images.ntdll;
    let Event {
        event_runtime, is_svc_listener, is_lsass_listener, is_lsass_listener2, is_lsass_listener3,
        is_tp_worker, is_scm_worker, is_lsa_worker, is_lsa_auth_server, is_wl_worker, pi, ..
    } = *ev;
    let Syscall { native_call_transport, resume_ip, sp, flags, lsa_logon_trace_seq, .. } = *call;
    if hosted_spawn_uncertainty::take_transferred() {
        mark_wait_parked(
            &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
        )?;
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    }
    if !sc.handled {
        // ★ BATCH 43 — winlogon SAS-window MILESTONE park (recv-next-without-reply). winlogon has
        // CROSSED its win32k class-call-proc wall and created its SAS window; its further
        // window-show→paint flow exceeds the 620s TCG budget. Park it here (its TCB stays blocked
        // at the proven-advanced state) and QUIESCE to the gate — provided the boot is otherwise at
        // steady state (winlogon crossed msgina + LSA signalled). This is the win32k analogue of the
        // listener milestone parks below.
        if sc.wl_milestone_park {
            // No typed GUI wait or provider continuation accepted this request. Keep the
            // frontier explicit: contain this thread rather than orphan its held Call.
            assert!(drop_current_hosted_reply(), "unhandled GUI frontier must retire its Call");
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            lp.parks.crash_parked |= owner_bit_for_badge(&nt_handler, lp.msg.badge);
            service_watchdog_record_crash_parked(lp.parks.crash_parked);
            let userinit_shell_pending =
                userinit_shell_frontier_pending(&nt_handler, lp.parks.crash_parked, lp.parks.wait_parked);
            let explorer_chrome_pending = interactive_shell_chrome_frontier_pending(
                &nt_handler,
                lp.parks.crash_parked,
                lp.parks.wait_parked,
            );
            let pre_user_shell_pending = pre_user_shell_frontier_pending(
                &nt_handler,
                lp.parks.crash_parked,
                lp.parks.wait_parked,
                b"winlogon-milestone",
            );
            if !pre_user_shell_pending
                && !userinit_shell_pending
                && !explorer_chrome_pending
                && WINLOGON_KEY_OPENED.load(Ordering::Relaxed) != 0
                && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                && !defer_quiesce_for_active_user_callbacks(b"winlogon-milestone")
            {
                print_str(b"[quiesce] winlogon reached its win32k SAS-window milestone + steady state -> run gate\n");
                lp.exit.stop = lp.msg.m0;
                lp.exit.record(b"winlogon-sas-milestone");
                return ControlFlow::Break(Turn::Exit);
            } else if userinit_shell_pending {
                print_str(b"[quiesce] winlogon milestone parked; deferring gate until userinit attempts its shell image\n");
            } else if explorer_chrome_pending {
                print_str(b"[quiesce] winlogon milestone parked; deferring gate until Explorer reaches shell chrome paint\n");
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        // After logon has succeeded, an unimplemented win32k syscall from winlogon's main
        // thread is the same kind of frontier as the post-logon VM/#BP milestone parks
        // above. Do not route this through `park_and_log!`: that helper intentionally
        // latches the whole process as a dead callback client, which is wrong here because
        // the expendable worker threads remain alive and hold no callback frames. The
        // post-quiesce callback-injection gates depend on that distinction.
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
            assert!(drop_current_hosted_reply(), "unimplemented terminal syscall must retire its Call");
            print_str(b"[wl-main] winlogon COMPLETED THE INTERACTIVE LOGON; its POST-LOGON path hit unimplemented win32k SSN=0x");
            print_hex(lp.msg.m0 as u32);
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
            WINLOGON_POST_LOGON_MILESTONE_CR2.store(lp.msg.m0, Ordering::Relaxed);
            if ((live_top_badges(&nt_handler) & !(lp.parks.crash_parked | lp.parks.wait_parked)) == 0
                || LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0)
                && !pre_user_shell_frontier_pending(
                    &nt_handler,
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                    b"winlogon-post-logon-callback",
                )
                && !interactive_shell_chrome_frontier_pending(
                    &nt_handler,
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                )
            {
                print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
                lp.exit.stop = lp.msg.m0;
                lp.exit.record(b"all-live-waiting");
                return ControlFlow::Break(Turn::Exit);
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        if is_tp_worker {
            assert!(drop_current_hosted_reply(), "unserviced worker syscall must retire its Call");
            print_str(b"[tp-worker] unserviced syscall badge=");
            print_u64(lp.msg.badge);
            print_str(b" SSN=");
            print_u64(lp.msg.m0);
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
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        // N-threads multiplex: a SERVER thread (svc/lsass listener) that walls on an unserviced
        // BLOCKING server-loop syscall (e.g. NtListenPort / NtReplyWaitReceivePort — it reached
        // its LPC/RPC receive loop and would block forever waiting for a client) PARKS instead of
        // stopping the whole boot. Recv the next event WITHOUT replying → the listener's seL4
        // thread stays blocked (its ETHREAD/TEB/stack stay mapped), and lsass' main thread + the
        // rest of the boot keep advancing. Contained per-thread — the point of the multiplex.
        if is_svc_listener
            || is_scm_worker
            || is_lsass_listener
            || is_lsass_listener2
            || is_lsass_listener3
            || is_lsa_worker
            || is_wl_worker
        {
            assert!(drop_current_hosted_reply(), "unserviced listener syscall must retire its Call");
            print_str(if is_wl_worker {
                b"[wl-worker] unserviced server syscall SSN="
            } else if is_scm_worker {
                b"[scm-worker] blocking/unserviced server syscall SSN="
            } else if is_lsa_worker {
                b"[lsa-worker] blocking/unserviced server syscall SSN="
            } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 {
                b"[lsass-listener] blocking server syscall SSN="
            } else {
                b"[svc-listener] blocking server syscall SSN="
            });
            print_u64(lp.msg.m0);
            print_str(b" -> terminal thread containment (no implemented wait contract)\n");
            if is_lsa_auth_server && nt_handler.hosted_thread_lpc_client_process(lp.msg.badge) != 0
            {
                LSA_SERVER_WALL_SSN.store(lp.msg.m0, Ordering::Relaxed);
            }
            if is_wl_worker && WINLOGON_MAIN_EVENT_WAIT_PARKED.load(Ordering::Relaxed) != 0
            {
                print_str(b"[wl-worker] parked before signalling the waiting winlogon main thread -> run gate\n");
                lp.exit.stop = lp.msg.m0;
                lp.exit.record(b"winlogon-worker-parked");
                return ControlFlow::Break(Turn::Exit);
            }
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
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
                )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        if hosted_main_badge_has_role(
            &nt_handler,
            lp.msg.badge,
            nt_exe_image::HostedProcessRole::InteractiveLogon,
        ) && lp.msg.m0 == 190
        {
            // DIAG (BATCH 21): winlogon's hard-error site — dump raw args while its mirror
            // is active (ErrorStatus=R10, param0=[stack], caller=[rsp]).
            print_str(b"[wl-190] R10=0x");
            print_hex((get_recv_mr(9) >> 32) as u32);
            print_hex(get_recv_mr(9) as u32);
            print_str(b" RDX=0x");
            print_hex(lp.msg.m3 as u32);
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
        lp.exit.stop_ssn = lp.msg.m0;
        return ControlFlow::Break(lp.park_and_log(pi, b"unhandled-syscall", lp.msg.m0, lp.msg.m0));
    }
    let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if sc.component_suspension_park_request {
        procs[pi].faults = lp.exit.faults;
        procs[pi].first = lp.exit.first;
        procs[pi].ntfaults = lp.exit.ntfaults;
        pfilled[pi] = *filled_pages;
        let receive_child_pending = crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending();
        if receive_child_pending {
            // Drop pointers to this event's stack locals without executing a provider or
            // filesystem finalizer while the physical GUI parent is held.
            nt_handler.loop_ctx = nt_handler.loop_ctx.map(|ctx| ctx.checkpoint_live());
        }
        if let Some(maintenance_ticket) = sc.component_root_maintenance_ticket {
            if receive_child_pending {
                // A prepared Receive child has physical priority over independent work.
                // Keep this checkpoint and both Replies retained for diagnosis.
                print_str(b"[root-maintenance] pending Receive child; checkpoint retained\n");
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = lp.msg.m0;
                lp.exit.record(b"root-maintenance-receive-child");
                return ControlFlow::Break(Turn::Exit);
            }
            // The ordinary syscall has yielded with both Replies retained. Run this
            // independent worker only after all event-local state is checkpointed.
            let worker_attempted = {
                let _message = crate::ipc_message::SavedMessageBuffer::capture();
                crate::process_image_snapshot_work::redrive(
                    &mut nt_handler, &mut *delay_queue, ntdll, fault_ep, procs,
                    exe_images, &*exe_image_catalog, hosted_loaded_images_ptr,
                )
            };
            if !worker_attempted {
                print_str(b"[root-maintenance] image worker did not enter; checkpoint retained\n");
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = lp.msg.m0;
                lp.exit.record(b"root-maintenance-worker");
                return ControlFlow::Break(Turn::Exit);
            }
            let Some(observed_pass) = ROOT_MAINTENANCE_PASS.try_update(
                Ordering::AcqRel, Ordering::Acquire, |old| old.checked_add(1),
            ).ok().and_then(|old| old.checked_add(1)) else {
                print_str(b"[root-maintenance] outer pass epoch exhausted\n");
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = lp.msg.m0;
                lp.exit.record(b"root-maintenance-epoch");
                return ControlFlow::Break(Turn::Exit);
            };
            let Some(key) = root_maintenance_owner::key(maintenance_ticket) else {
                print_str(b"[root-maintenance] exact owner missing before pass grant\n");
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = lp.msg.m0;
                lp.exit.record(b"root-maintenance-owner");
                return ControlFlow::Break(Turn::Exit);
            };
            let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
            if lanes.mark_root_maintenance_pass(
                maintenance_ticket.dispatch.lane(), maintenance_ticket.reply,
                maintenance_ticket.dispatch, key, maintenance_ticket.owner,
                observed_pass,
            ).is_err() {
                print_str(b"[root-maintenance] exact pass grant refused\n");
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = lp.msg.m0;
                lp.exit.record(b"root-maintenance-pass");
                return ControlFlow::Break(Turn::Exit);
            }
            if matches!(
                component_resume::run_root_maintenance(
                    core::ptr::from_mut(nt_handler), maintenance_ticket,
                ),
                component_resume::RootMaintenanceResumeOutcome::RetainedFailure,
            ) {
                print_str(b"[root-maintenance] exact resume retained after refusal\n");
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = lp.msg.m0;
                lp.exit.record(b"root-maintenance-resume");
                return ControlFlow::Break(Turn::Exit);
            }
        }
        if !receive_child_pending {
            let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
        }
        if component_suspension_owns_hosted_dispatch(sc.component_suspension_admitted_dispatch_id)
        {
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
        }
        if !receive_child_pending { let _ = finalize_service_loop_state(&mut nt_handler); }
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        )?;
        lp.msg.badge = received.0;
        lp.msg.mi = received.1;
        lp.msg.m0 = received.2;
        lp.msg.m1 = received.3;
        lp.msg.m2 = received.4;
        lp.msg.m3 = received.5;
        return ControlFlow::Break(Turn::Next);
    }
    if sc.active_callback_bad_resume && reply_main != 0 {
        if drop_current_hosted_reply() {
            lp.parks.crash_parked |= owner_bit_for_badge(&nt_handler, lp.msg.badge);
            service_watchdog_record_crash_parked(lp.parks.crash_parked);
            let _ = win32k_glue::unwind_dead_client_user_callbacks(pi as u32);
            drain_deferred_user_callback_returns(
                &mut nt_handler,
                pi,
                lp.exit.faults as usize,
                procs,
                pfilled,
                filled_pages,
            );
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            print_str(
                b"[user-callback] active callback syscall had no executable resume-ip=0x",
            );
            print_hex_u64(resume_ip);
            print_str(b" ssn=0x");
            print_hex_u64(lp.msg.m0);
            print_str(b" -> DROP reply and park client\n");
            if ((live_top_badges(&nt_handler) & !(lp.parks.crash_parked | lp.parks.wait_parked)) == 0
                || (pi == 2
                    && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0))
                && !pre_user_shell_frontier_pending(
                    &nt_handler,
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                    b"bad-callback-resume",
                )
                && !defer_quiesce_for_active_user_callbacks(b"bad-callback-resume")
            {
                print_str(b"[quiesce] active callback bad-resume park reached steady state -> run gate\n");
                lp.exit.stop = resume_ip;
                lp.exit.record(b"callback-bad-resume");
                return ControlFlow::Break(Turn::Exit);
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        }
        print_str(
            b"[user-callback] active callback bad resume could not drop reply -> STATUS_ACCESS_VIOLATION\n",
        );
        sc.result = 0xC000_0005;
    }
    set_reply_mr(15, resume_ip);
    set_reply_mr(16, sp);
    set_reply_mr(17, flags);
    procs[pi].faults = lp.exit.faults;
    procs[pi].first = lp.exit.first;
    procs[pi].ntfaults = lp.exit.ntfaults;
    pfilled[pi] = *filled_pages;
    let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if let Some(pending) = sc.park_lpc_receive.take() {
        if reply_main != 0
            && lpc_receive_wait_park(
                pending,
                pi as u32,
                event_runtime.process,
                lp.msg.badge,
                nt_handler.current_tid,
            )
        {
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            let server_tid = nt_handler.current_tid;
            if nt_handler.lpc_reply_published {
                let _ = lpc_component_reply_commit_drain(
                    &mut nt_handler,
                );
            }
            // The component drain can synchronously publish another broker request and
            // redrive this exact server receive. Record a wait only if its retained owner
            // still exists after that ownership boundary.
            if lpc_thread_has_wait(server_tid, lp.msg.badge) {
                trace_indefinite_wait_park(
                    &nt_handler,
                    lp.msg.badge,
                    live_top_badges(&nt_handler),
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                );
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
            } else {
                lp.parks.wait_parked = wait_parked_owner_mask(&nt_handler);
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        }
        lpc_receive_wait_cancel_reservation(pending.reservation);
        print_str(b"[lpc-recv] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
        sc.result = 0xC000_009A;
    }
    if let Some(pending) = sc.park_lpc_connect.take() {
        if reply_main != 0
            && lpc_connect_wait_park(
                pending,
                pi as u32,
                lp.msg.badge,
                nt_handler.current_tid,
            )
        {
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            trace_indefinite_wait_park(
                &nt_handler,
                lp.msg.badge,
                live_top_badges(&nt_handler),
                lp.parks.crash_parked,
                lp.parks.wait_parked,
            );
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            let _ = finalize_service_loop_state(&mut nt_handler);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        }
        lpc_connect_wait_cancel_reservation(pending.reservation);
        if let Some(client) = lpc_client() {
            let _ = client.accept_connect(pending.request.connection_id, false, 0);
        }
        nt_handler.abort_lpc_connection_views(pending.request.connection_id);
        print_str(
            b"[lpc-connect-wait] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n",
        );
        sc.result = 0xC000_009A;
    }
    if let Some(pending) = sc.park_lpc_request.take() {
        if reply_main != 0
            && lpc_request_wait_park(
                pending,
                pi as u32,
                event_runtime.process,
                lp.msg.badge,
                nt_handler.current_tid,
            )
        {
            procs[pi].faults = lp.exit.faults;
            procs[pi].first = lp.exit.first;
            procs[pi].ntfaults = lp.exit.ntfaults;
            pfilled[pi] = *filled_pages;
            trace_indefinite_wait_park(
                &nt_handler,
                lp.msg.badge,
                live_top_badges(&nt_handler),
                lp.parks.crash_parked,
                lp.parks.wait_parked,
            );
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            let _ = finalize_service_loop_state(&mut nt_handler);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        }
        lpc_request_wait_cancel_reservation(pending.reservation);
        if let Some(client) = lpc_client() {
            let _ = client.cancel_request(
                pending.request.port_handle,
                pending.request.client_process,
                pending.request.client_thread,
                pending.request.message_id,
            );
        }
        print_str(
            b"[lpc-request-wait] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n",
        );
        sc.result = 0xC000_009A;
    }
    if sc.park_io_completion_port >= 0 && reply_main != 0 {
        let timed = sc.park_io_completion_deadline != nt_delay_execution::Deadline::Infinite;
        if timed && !delay_timer_init() {
            sc.result = 0xC000_009A;
        } else if io_completion_park(
            &mut nt_handler,
            sc.park_io_completion_port as u32,
            sc.park_io_completion_key_out,
            sc.park_io_completion_apc_out,
            sc.park_io_completion_iosb_out,
            sc.park_io_completion_deadline,
        ) {
            delay_timer_rearm_after_park(&mut *delay_queue, &mut nt_handler, timed);
            print_str(b"[io-completion] pi=");
            print_u64(pi as u64);
            print_str(b" port=");
            print_u64(sc.park_io_completion_port as u64);
            print_str(b" -> PARK remover\n");
            if !timed {
                trace_indefinite_wait_park(
                    &nt_handler,
                    lp.msg.badge,
                    live_top_badges(&nt_handler),
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                );
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        } else {
            print_str(
                b"[io-completion] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n",
            );
            sc.result = 0xC000_009A;
        }
    }
    if let Some(deadline) = sc.park_delay_deadline {
        let delay_tid = nt_handler.current_tid;
        if delay_park(
            &mut nt_handler,
            &mut *delay_queue,
            deadline,
            reply_main,
            delay_tid,
            lp.msg.badge,
        ) {
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        }
        print_str(b"[delay] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
        sc.result = 0xC000_009A;
    }
    if let Some(deadline) = sc.park_thread_alert_deadline {
        let timed = deadline != nt_delay_execution::Deadline::Infinite;
        if timed && !delay_timer_init() {
            sc.result = nt_fs::STATUS_INSUFFICIENT_RESOURCES as u64;
        } else if thread_alert::park(&mut nt_handler, deadline, reply_main) {
            delay_timer_rearm_after_park(&mut *delay_queue, &mut nt_handler, timed);
            thread_alert::redrive(&mut nt_handler);
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        } else {
            sc.result = nt_fs::STATUS_INSUFFICIENT_RESOURCES as u64;
        }
    }
    // Keyed-event release park (`NtReleaseKeyedEvent`): if no wait side is already parked,
    // the release side waits for a future `NtWaitForKeyedEvent` on the same key.
    if sc.park_keyed_release_wait_key != u64::MAX && reply_main != 0 {
        let timed =
            sc.park_keyed_release_wait_deadline != nt_delay_execution::Deadline::Infinite;
        if timed && !delay_timer_init() {
            sc.result = 0xC000_009A;
        } else if keyed_release_wait_park(
            sc.park_keyed_release_wait_key,
            nt_handler.current_tid,
            sc.park_keyed_release_wait_deadline,
        ) {
            delay_timer_rearm_after_park(&mut *delay_queue, &mut nt_handler, timed);
            print_str(b"[keyed] NtReleaseKeyedEvent key=0x");
            print_hex_u64(sc.park_keyed_release_wait_key);
            print_str(b" -> PARK releaser\n");
            if !timed {
                trace_indefinite_wait_park(
                    &nt_handler,
                    lp.msg.badge,
                    live_top_badges(&nt_handler),
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                );
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        } else {
            print_str(
                b"[keyed] release park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n",
            );
            sc.result = 0xC000_009A;
        }
    }
    // Keyed-event wait park (`NtWaitForKeyedEvent`): used by ReactOS condition variables and
    // run-once state. The matching `NtReleaseKeyedEvent` wakes via keyed_wait_wake_one.
    if sc.park_keyed_wait_key != u64::MAX && reply_main != 0 {
        let timed = sc.park_keyed_wait_deadline != nt_delay_execution::Deadline::Infinite;
        if timed && !delay_timer_init() {
            sc.result = 0xC000_009A;
        } else if keyed_wait_park(
            sc.park_keyed_wait_key,
            nt_handler.current_tid,
            sc.park_keyed_wait_deadline,
        ) {
            delay_timer_rearm_after_park(&mut *delay_queue, &mut nt_handler, timed);
            print_str(b"[keyed] NtWaitForKeyedEvent key=0x");
            print_hex_u64(sc.park_keyed_wait_key);
            print_str(b" -> PARK caller\n");
            if !timed {
                trace_indefinite_wait_park(
                    &nt_handler,
                    lp.msg.badge,
                    live_top_badges(&nt_handler),
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                );
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let received = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = received.0;
            lp.msg.mi = received.1;
            lp.msg.m0 = received.2;
            lp.msg.m1 = received.3;
            lp.msg.m2 = received.4;
            lp.msg.m3 = received.5;
            return ControlFlow::Break(Turn::Next);
        } else {
            print_str(b"[keyed] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
            sc.result = 0xC000_009A;
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
    let winlogon_worker_can_signal = sc.park_wait_event >= 0
        && hosted_pi_has_role(
            &nt_handler,
            pi,
            nt_exe_image::HostedProcessRole::InteractiveLogon,
        )
        && hosted_main_badge_has_role(
            &nt_handler,
            lp.msg.badge,
            nt_exe_image::HostedProcessRole::InteractiveLogon,
        )
        && nt_handler
            .hosted_thread_tcb_for_role(pi, HostedThreadRole::WinlogonWorker { slot: 1 })
            .is_some()
        && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) == 0;
    let park_wait_tid = nt_handler.current_tid;
    if sc.park_wait_event >= 0 && reply_main != 0 {
        let timed = sc.park_wait_deadline != nt_delay_execution::Deadline::Infinite;
        let park_object = match WaitObject::from_raw(sc.park_wait_event as u64) {
            Some(object) => object,
            None => {
                sc.result = 0xC000_0008;
                WaitObject::FREE
            }
        };
        if park_object == WaitObject::FREE {
            // Invalid handoff; return STATUS_INVALID_HANDLE through the normal reply path.
        } else if timed && !delay_timer_init() {
            sc.result = 0xC000_009A;
        } else if wait_park(
            &mut nt_handler,
            park_object,
            sc.park_wait_alertable,
            park_wait_tid,
            sc.park_wait_deadline,
        ) {
            let current_tid = nt_handler.current_tid;
            let wait_still_parked = wait_recheck_after_park(&mut nt_handler, current_tid);
            delay_timer_rearm_after_park(&mut *delay_queue, &mut nt_handler, timed);
            if winlogon_worker_can_signal && wait_still_parked {
                WINLOGON_MAIN_EVENT_WAIT_PARKED.store(1, Ordering::Relaxed);
                print_str(b"[wl-main] parked on worker-ready event; runnable worker remains a signaler\n");
            }
            if !timed && wait_still_parked {
                trace_indefinite_wait_park(
                    &nt_handler,
                    lp.msg.badge,
                    live_top_badges(&nt_handler),
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                );
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        } else {
            print_str(b"[wait] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
            sc.result = 0xC000_009A;
        }
    }
    // Array-wait park: retain the exact typed set and park the reply capability. Any matching
    // owner transition wakes it through the shared dispatcher path with WAIT_0+index.
    if sc.park_wait_set_n > 0 && reply_main != 0 {
        let timed = sc.park_wait_deadline != nt_delay_execution::Deadline::Infinite;
        if timed && !delay_timer_init() {
            sc.result = 0xC000_009A;
        } else if wait_park_multi(
            &mut nt_handler,
            &sc.park_wait_set[..sc.park_wait_set_n],
            &sc.park_wait_indices[..sc.park_wait_set_n],
            sc.park_wait_set_all,
            sc.park_wait_alertable,
            park_wait_tid,
            sc.park_wait_deadline,
        ) {
            let current_tid = nt_handler.current_tid;
            let wait_still_parked = wait_recheck_after_park(&mut nt_handler, current_tid);
            delay_timer_rearm_after_park(&mut *delay_queue, &mut nt_handler, timed);
            if DEBUG_TRACE {
                print_str(b"[wait] pi=");
                print_u64(pi as u64);
                print_str(b" NtWaitForMultipleObjects(");
                print_u64(sc.park_wait_set_n as u64);
                print_str(if sc.park_wait_set_all {
                    b" objects, WaitAll) UNSIGNALLED -> PARK caller\n"
                } else {
                    b" objects, WaitAny) UNSIGNALLED -> PARK caller\n"
                });
            }
            if !timed && wait_still_parked {
                trace_indefinite_wait_park(
                    &nt_handler,
                    lp.msg.badge,
                    live_top_badges(&nt_handler),
                    lp.parks.crash_parked,
                    lp.parks.wait_parked,
                );
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
            }
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        } else {
            print_str(b"[wait] array park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
            sc.result = 0xC000_009A;
        }
    }
    // A contended synchronous File has referenced its canonical route but has not created
    // an IRP. Transfer the live syscall reply into the FIFO acquisition owner.
    if sc.synchronous_file_wait_parked {
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    }
    // A pending StartDevice syscall transfers its reply independently of the notification
    // stream. Publication precedes Reply-object rotation.
    if let Some(transfer) = sc.transfer_pending_driver_start.take() {
        pending_driver_start_transfer(&mut nt_handler, transfer);
        trace_indefinite_wait_park(
            &nt_handler,
            lp.msg.badge,
            live_top_badges(&nt_handler),
            lp.parks.crash_parked,
            lp.parks.wait_parked,
        );
        mark_wait_parked(
            &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
        )?;
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    }
    if let Some(transfer) = sc.transfer_pending_pnp_operation.take() {
        pending_pnp_operation_transfer(&mut nt_handler, transfer);
        trace_indefinite_wait_park(
            &nt_handler,
            lp.msg.badge,
            live_top_badges(&nt_handler),
            lp.parks.crash_parked,
            lp.parks.wait_parked,
        );
        mark_wait_parked(
            &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
        )?;
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    }
    if let Some(transfer) = sc.transfer_native_file_target.take() {
        match unsafe { crate::native_file_target_open_work::park(&mut nt_handler, transfer) } {
            Ok(()) => {
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
            Err(status) => sc.result = status as u64,
        }
    }
    if let Some(transfer) = sc.transfer_native_directory_open.take() {
        match unsafe { crate::native_directory_open_work::park(&mut nt_handler, transfer) } {
            Ok(()) => {
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
            Err(status) => sc.result = status as u64,
        }
    }
    if let Some(transfer) = sc.transfer_native_directory_effect.take() {
        match unsafe { crate::native_directory_effect_work::park(&mut nt_handler, transfer) } {
            Ok(()) => {
                mark_wait_parked(
                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                )?;
                let _ = finalize_service_loop_state(&mut nt_handler);
                let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
            Err(status) => sc.result = status as u64,
        }
    }
    // File ownership and reply attachment were committed before post-actions. Only
    // scheduling remains here; completion may already have retired the published owner.
    if let Some(published) = sc.published_file_io.take() {
        let wait_for_completion = published.wait_for_completion;
        if published.still_waiting() {
            let _ = reconcile_user_apc_file_wait(&mut nt_handler, published.tid);
        }
        if published.still_waiting() {
            published.trace_parked_mounted_create();
            trace_indefinite_wait_park(
                &nt_handler,
                lp.msg.badge,
                live_top_badges(&nt_handler),
                lp.parks.crash_parked,
                lp.parks.wait_parked,
            );
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
        }
        // The manager may already hold the terminal result (for example a completion
        // published during the post-dispatch pump after early ownership publication).
        let _ = pending_file_io_redrive_all(&mut nt_handler);
        let _ = file_cleanup_redrive_all(&mut nt_handler);
        if wait_for_completion {
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
    }
    if let Some((pending, reservation)) = sc.transfer_file_cleanup_wait.take() {
        if file_cleanup_wait_transfer(&mut nt_handler, pending, reservation) {
            trace_indefinite_wait_park(
                &nt_handler,
                lp.msg.badge,
                live_top_badges(&nt_handler),
                lp.parks.crash_parked,
                lp.parks.wait_parked,
            );
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            // The manager may have reached terminal CLOSE between the pre-reply pump and
            // continuation publication. Redrive after ownership is visible so that edge
            // completes the exact parked `NtClose` instead of waiting for another event.
            let _ = file_cleanup_redrive_all(&mut nt_handler);
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
    }
    if let Some((pending, reservation)) = sc.transfer_file_irp_drain.take() {
        file_irp_drain_transfer(pending, reservation);
        trace_indefinite_wait_park(
            &nt_handler,
            lp.msg.badge,
            live_top_badges(&nt_handler),
            lp.parks.crash_parked,
            lp.parks.wait_parked,
        );
        mark_wait_parked(
            &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
        )?;
        // Cancellation can complete inside the handler's manager pump. Redrive every
        // original owner unconditionally before testing the separate drain owner.
        let _ = pump_hosted_io_and_redrive_driver_starts(
            driver_launch::drain_hosted_driver_dpcs(),
            &mut nt_handler,
        );
        let _ = pending_file_io_redrive_all(&mut nt_handler);
        let _ = file_cleanup_redrive_all(&mut nt_handler);
        let _ = file_irp_drain_redrive_all(&mut nt_handler);
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    }
    // ★ Dbgk TARGET-SIDE BLOCK, SYSCALL flavour (`DbgkpQueueMessage`'s wait on
    // `DebugEvent->ContinueEvent`). This syscall posted a debug event for a process whose
    // debugger is attached, and NT blocks the REPORTING thread until `NtDebugContinue`.
    // Park it with the SYSCALL reply shape (status in MR0 + resume context in MR15/16/17 —
    // the shape `dbgk_reporter_resume` replays) and recv the next event WITHOUT replying.
    // The block rides on the `DEBUG_EVENT`; a debug-object teardown / the post-loop drain
    // releases it, so it can never wedge the boot. `park_dbgk_reporter` is false on every
    // boot today (nothing attaches a debugger), so this whole block is skipped.
    if sc.park_dbgk_reporter && reply_main != 0 {
        if nt_handler.dbgk_block_reporter(
            pi,
            nt_handler.current_tid,
            lp.msg.badge,
            nt_process::dbgk::DBGK_BLOCK_SYSCALL,
            0,
            resume_ip,
            sp,
            flags,
            sc.result,
        ) {
            print_str(b"[dbgk] reporter BLOCKED on continue (syscall) pi=");
            print_u64(pi as u64);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b"\n");
            // A blocked reporter is a COOPERATIVE wait (the debugger's continue wakes it),
            // so it counts toward the all-parked quiesce exactly like every other wait —
            // the boot still reaches the gate if the debugger never continues.
            mark_wait_parked(
                &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
            )?;
            let _ = finalize_service_loop_state(&mut nt_handler);
            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
        // Could not park (no reply object / pool exhausted / nothing eligible took the
        // block) — fall through to the ordinary reply: post-and-continue, never a hang.
        print_str(b"[dbgk] reporter block unavailable -> post-and-continue\n");
    }
    // Event/timer processing may have selected an older provider continuation while this
    // syscall was in flight. The nested provider dispatch has returned to its retained
    // rendezvous by this point. Resume only admissions from this pass, not fresh reparks.
    let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
    // ★ PHASE 3 — ONE reply shape for every serviced client syscall: resume the caller
    // through the reply object the KERNEL bound to it at its recv (`decode_reply` →
    // `replies[idx].bound_tcb`), then recv the next event re-registering that same object.
    //
    // What used to be here was a four-way fork whose only purpose was deciding whether the
    // executive's single legacy `reply_to` slot could still be trusted: it is written on the
    // RECEIVER by every incoming `Call`, so a component dispatch (or one of its demand-page
    // faults) serviced during this syscall silently re-pointed it at the COMPONENT, and the
    // "fast path" would then resume npfs with a length-18 syscall result while the real
    // client slept forever (the hang that ended the first Phase-1 boot). `routed_win32k`,
    // `routed_lpc`, `routed_csr` and `COMPONENT_CALL_CLOBBERED_REPLY_TO` were four ways of
    // asking "did anything clobber it?". With the legacy reply retired the question is moot:
    // nothing can re-point a bound reply object, so the answer is always the same reply.
    // TAIL WATCH tag 3: the executive has FINISHED servicing this native syscall and has not
    // yet resumed the caller. A transition seen here is the executive's own handler; a
    // transition that only ever shows at tag 0 happened while the CLIENT was running.
    crate::teb_tail_watch(pi, 3, lp.msg.m0, lp.msg.badge);
    let tail_durable_status = finalize_service_loop_state(&mut nt_handler);
    if tail_durable_status != nt_fs::STATUS_SUCCESS {
        sc.result = tail_durable_status as u64;
    }
    if let Some(identity) = sc.current_apc_handoff.take() {
        crate::current_apc::release_tail(&mut nt_handler, identity);
        crate::current_apc::redrive(&mut nt_handler);
        let _ = finalize_service_loop_state(&mut nt_handler);
        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || new_reply,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    }
    let redirected_user_control =
        sc.redirected_user_callback || sc.redirected_context_continue;
    let native_load_reply_status =
        (native_call_transport && lp.msg.m0 == SSN_NT_LOAD_DRIVER && !redirected_user_control)
            .then_some(sc.result as u32);
    let live_action_reply = (native_call_transport
        && lp.msg.m0 == SSN_NT_PLUG_PLAY_CONTROL
        && !redirected_user_control)
        .then(|| {
            nt_handler
                .pnp_take_live_action_reply_tail()
                .map(|identity| (identity, sc.result as u32))
        })
        .flatten();
    let start_device_reply = (native_call_transport
        && lp.msg.m0 == SSN_NT_PLUG_PLAY_CONTROL
        && !redirected_user_control)
        .then(|| {
            nt_handler
                .pnp_take_start_device_reply_tail()
                .map(|identity| (identity, sc.result as u32))
        })
        .flatten();
    let inspect_component_lpc_after_reply =
        (&*core::ptr::addr_of!(LPC_COMPONENT_WAITS))
            .requires_post_reply_inspection(nt_handler.lpc_reply_published);
    // Ordinary completion changes only RAX. Provider reentry can legitimately install
    // newer target registers while this syscall is serviced; never replay ingress state.
    // A committed callback redirect already owns the full canonical context and must
    // restart without IPC register fanout. NtContinue already bypassed this tail.
    let len = 1;
    let r0 = sc.result;
    if let Some(n) = lsa_logon_trace_seq {
        LSA_LOGON_LAST_STATUS.store(r0, Ordering::Relaxed);
        if n < 128 {
            print_str(b"[lsa-logon-ssn] return #");
            print_u64(n);
            print_str(b" tid=");
            print_u64(nt_handler.current_tid);
            print_str(b" ssn=");
            print_u64(lp.msg.m0);
            print_str(b" status=0x");
            print_hex_u64(r0);
            print_str(b" reply=0x");
            print_hex_u64(reply_main);
            print_str(b"\n");
        }
    }
    let trace_csrss_resume_reply = native_call_transport && lp.msg.badge == 29 && lp.msg.m0 == 214;
    if trace_csrss_resume_reply {
        if CSRSS_RESUME_REPLIES.fetch_add(1, Ordering::Relaxed) == 1 {
            CSRSS_POST_RESUME_TCB.store(event_runtime.tcb, Ordering::Relaxed);
        }
        print_str(b"[csrss-resume-reply] handoff badge=");
        print_u64(lp.msg.badge);
        print_str(b" tcb=0x");
        print_hex_u64(event_runtime.tcb);
        print_str(b" reply=0x");
        print_hex_u64(reply_main);
        print_str(b" status=0x");
        print_hex_u64(r0);
        print_str(b"\n");
    }
    let ((nb, nmi, nm0, nm1, nm2, nm3), native_reply_delivered) = if redirected_user_control {
        let restarted = win32k_glue::restart_staged_user_callback_context(
            win32k_glue::StagedUserCallbackContext::installed(event_runtime.tcb),
            reply_main,
        );
        assert!(restarted, "rejected callback redirect restart retains its bound Reply");
        if inspect_component_lpc_after_reply {
            let _ = lpc_component_reply_commit_drain(&mut nt_handler);
        }
        (receive(&mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || reply_main)?, true)
    } else if reply_main == 0 {
        // Pre-retype (demo path): no reply objects exist yet, legacy `reply_to` it is.
        (reply_receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (REPLY_MAIN_SLOT.load(Ordering::Relaxed), len, r0, 0, 0, 0),
        )?, true)
    } else {
        // Current APC delivery owns its saved Reply independently and bypasses this tail.
        if inspect_component_lpc_after_reply {
            // The broker reply is visible, but its server must observe this native reply
            // before the retained component client resumes. Calls made during the bounded
            // drain queue on the endpoint until `recv_full_r12` re-registers this Reply.
            let delivered = client_reply_on(reply_main, len, r0, 0, 0, 0);
            assert!(
                delivered,
                "LPC server native reply failed before component continuation selection"
            );
            let _ =
                lpc_component_reply_commit_drain(&mut nt_handler);
            (receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || reply_main,
            )?, delivered)
        } else {
            let received =
                reply_receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (reply_main, len, r0, 0, 0, 0),
                )?;
            let delivered = received.0 != COMPOSITE_SEND_ERROR_BADGE;
            (received, delivered)
        }
    };
    if trace_csrss_resume_reply {
        print_str(b"[csrss-resume-reply] received badge=");
        print_u64(nb);
        print_str(b" delivered=");
        print_u64(native_reply_delivered as u64);
        print_str(b" label=0x");
        print_hex_u64(nmi);
        print_str(b" m0=0x");
        print_hex_u64(nm0);
        print_str(b"\n");
    }
    if let Some(status) = native_load_reply_status {
        // The checked reply path consumed the bound Reply object before returning. The
        // combined path reserves one impossible receive badge to report a send-half failure
        // without pretending a receive occurred.
        nt_handler
            .native_driver_load_report
            .record_reply(status, native_reply_delivered);
        assert!(
            native_reply_delivered,
            "NtLoadDriver bound reply failed before receive"
        );
    }
    if let Some((identity, status)) = live_action_reply {
        nt_handler
            .pnp_record_live_action_reply(identity, status, native_reply_delivered)
            .expect("live PnP notification reply did not match its UserResponse result");
    }
    if let Some((identity, status)) = start_device_reply {
        match nt_handler.pnp_record_start_device_reply(
            identity,
            status,
            native_reply_delivered,
        ) {
            Ok(()) | Err(nt_pnp_manager::StartDeviceLedgerError::ReplyFailed) => {}
            Err(_) => panic!("StartDevice reply did not match its exact result"),
        }
    }
    lp.msg.badge = nb;
    lp.msg.mi = nmi;
    lp.msg.m0 = nm0;
    lp.msg.m1 = nm1;
    lp.msg.m2 = nm2;
    lp.msg.m3 = nm3;
    return ControlFlow::Break(Turn::Next);
}
