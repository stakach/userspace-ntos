//! Park, quiesce and refusal steps of the service loop (issue #382, loop hoist).
//!
//! These were the loop-local macros `park_and_log!`, `mark_wait_parked!`,
//! `dbgk_forward_exception!`, `dbgk_block_and_park!`, `reject_hosted_ingress!` and
//! `park_queued_callback_root_receive!`. A helper that always ends the turn is a method of
//! `LoopState` and returns `Turn`. A helper that can fall through takes only the groups it
//! needs, because its caller still holds the loop's other references. Every function is
//! `#[track_caller]`, so a recorded exit site is still the line of the outermost call.

use super::loop_receive::receive;
use super::*;
use crate::executor::local;

impl LoopState<'_> {
    // park_and_log!(label, ip, cr2): the generalized UNRECOVERABLE-fault handler. Logs once per
    // top-level process (`[parked] pi=.. badge=.. fault=.. ip=.. cr2=..`), marks its crash bit,
    // flushes this pi's fault bookkeeping, then QUIESCE-checks (if every live top-level process is
    // now crash-parked, break → the gate runs + qemu_exit) else recv-next WITHOUT replying (the
    // faulting thread stays blocked in-kernel, exactly like the cooperative listener-park) and
    // continue the loop for another badge. Uses the surrounding loop locals directly (single call
    // site style), so it must be invoked where they are all in scope.
    #[track_caller]
    pub(super) unsafe fn park_and_log(&mut self, pi: usize, label: &[u8], ip: u64, cr2: u64) -> Turn {
        let lp = self;
        let nt_handler = &mut *lp.handler;
        let procs = &mut *lp.procs.procs;
        let pfilled = &mut *lp.procs.pfilled;
        let filled_pages = &mut *lp.procs.filled_pages;
        let fault_ep = lp.ingress.fault_ep;
        assert!(drop_current_hosted_reply(), "crash containment must retire the current Call");
        let __bit = owner_bit_for_badge(nt_handler, lp.msg.badge);
        // ★ THE LOG LINE IS PER *THREAD* BADGE, the crash BIT is per process. A hosted process
        // has several threads and one of them can already have milestone-parked (which sets the
        // process's crash bit) — suppressing the print on the process bit then SILENCED a
        // genuinely NEW fault on a different thread, and the boot quiesced with no fault line at
        // all. Measured in batch 59: winlogon's worker parked on an empty GetMessage, then its
        // main thread faulted post-profile-copy and printed NOTHING.
        let __log_bit = 1u64 << (lp.msg.badge & 63);
        let __already = (lp.parks.crash_logged & __log_bit) != 0;
        lp.parks.crash_logged |= __log_bit;
        lp.parks.crash_parked |= __bit;
        service_watchdog_record_crash_parked(lp.parks.crash_parked);
        if !__already {
            print_str(b"[parked] pi=");
            print_u64(pi as u64);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" fault=");
            print_str(label);
            print_str(b" ip=0x");
            print_hex((ip >> 32) as u32);
            print_hex(ip as u32);
            print_str(b" cr2=0x");
            print_hex((cr2 >> 32) as u32);
            print_hex(cr2 as u32);
            print_str(b" -> PARK process (unrecoverable); loop continues\n");
        }
        procs[pi].faults = lp.exit.faults;
        procs[pi].first = lp.exit.first;
        procs[pi].ntfaults = lp.exit.ntfaults;
        pfilled[pi] = *filled_pages;
        // ★ DEAD-CLIENT CALLBACK UNWIND. If this process died while it was running a win32k
        // user-mode callback, win32k's dispatch is SUSPENDED inside `KeUserModeCallback` waiting
        // for a reply this thread can no longer send. Unwind those continuations now and resume
        // win32k with a failure NTSTATUS, so the isolated component returns to its idle dispatch
        // receive loop instead of being stranded (which would block the shared loop's next `recv`
        // forever = boot wedge, no gate, no measurement). No-op when the process held no
        // callbacks. See win32k_glue::unwind_dead_client_user_callbacks.
        let _ = win32k_glue::unwind_dead_client_user_callbacks(pi as u32);
        drain_deferred_user_callback_returns(
            nt_handler,
            pi,
            lp.exit.faults as usize,
            procs,
            pfilled,
            filled_pages,
        );
        // QUIESCE: no live top-level process can still make forward progress → nothing left to
        // serve. `wait_parked` counts too (matching every other quiesce site): a crash-park plus
        // all-others-cooperatively-waiting leaves NO runnable signaler, so the next `recv` would
        // block forever. Additionally, winlogon dying at its post-OpenSCManager GUI/login
        // frontier (LSA already signalled → services/lsass are just idle RPC servers with no live
        // client left) is terminal for the boot by the same rule the null-deref arm already
        // applies — generalized here so it holds for ANY unrecoverable winlogon fault.
        if ((live_top_badges(nt_handler) & !(lp.parks.crash_parked | lp.parks.wait_parked)) == 0
            || (pi == 2 && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0))
            && !pre_user_shell_frontier_pending(
                nt_handler,
                lp.parks.crash_parked,
                lp.parks.wait_parked,
                b"all-live-parked",
            )
            && !defer_quiesce_for_active_user_callbacks(b"all-live-parked")
            && !crate::mounted_volume::mounted_create_outstanding()
            && !crate::mounted_volume::mounted_read_outstanding()
            && !crate::mounted_volume::mounted_directory_outstanding()
            && !driver_launch::mounted_native_physical_irp_pending()
            && !crate::native_directory_open_work::occupied()
            && !crate::native_file_target_open_work::occupied()
            && !crate::native_directory_effect_work::has_outstanding(nt_handler)
            && !crate::provider_directory_broker::has_outstanding()
        {
            print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
            lp.exit.stop = ip;
            lp.exit.record(b"crash-all-live-parked");
            return Turn::Exit;
        }
        let _ = finalize_service_loop_state(nt_handler);
        let (nb, nmi, nm0, nm1, nm2, nm3) = match receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep,
            || local().reply_main_slot.load(Ordering::Relaxed),
        ) {
            ControlFlow::Continue(message) => message,
            ControlFlow::Break(turn) => return turn,
        };
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        Turn::Next
    }

        // This endpoint admits hosted faults/native Calls, not asynchronous Send traffic. A
        // rejected caller's uniquely owned Reply must be cancelled before the next receive.
    #[track_caller]
    pub(super) unsafe fn reject_hosted_ingress(&mut self) -> Turn {
        let lp = self;
        let nt_handler = &mut *lp.handler;
        let fault_ep = lp.ingress.fault_ep;
        print_str(b"[service-loop] rejected hosted ingress badge=");
        print_u64(lp.msg.badge);
        print_str(b" label=");
        print_u64(lp.msg.mi >> 12);
        print_str(b"\n");
        if !drop_current_hosted_reply()
            && !crate::root_reply_park::quarantine_current_hosted_reply()
        {
            // Stop is uncertain. Keep the original Reply and its Call owned; another
            // receive would reuse that Reply and could complete the wrong caller.
            print_str(b"[service-loop] rejected ingress Reply retained badge=");
            print_u64(lp.msg.badge);
            print_str(b" reply=");
            print_u64(local().reply_main_slot.load(Ordering::Relaxed));
            print_str(b"\n");
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"rejected-reply-retained");
            return Turn::Exit;
        }
        let received = match receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep,
            || local().reply_main_slot.load(Ordering::Relaxed),
        ) {
            ControlFlow::Continue(message) => message,
            ControlFlow::Break(turn) => return turn,
        };
        lp.msg.badge = received.0;
        lp.msg.mi = received.1;
        lp.msg.m0 = received.2;
        lp.msg.m1 = received.3;
        lp.msg.m2 = received.4;
        lp.msg.m3 = received.5;
        Turn::Next
    }
}

// ★ dbgk_forward_exception!(pi, record) — `DbgkForwardException` on the REAL fault path.
//
// Invoked at each site where this loop has CLASSIFIED an unrecoverable USER exception
// (`#PF`/`#GP`/`#UD`/int3/single-step), immediately BEFORE that site's existing handling.
// `ExecNtHandler::dbgk_forward_exception` consults `EPROCESS.DebugPort`: a process with no
// debugger attached returns `false` having done NOTHING (two lookups, no log, no state change),
// so the whole fault path — `park_and_log!`, `crash_parked`, the dead-client callback unwind,
// the win32k arms — behaves byte-identically to before this existed. That is the case for every
// process on the current boot (nothing calls `NtDebugActiveProcess`), so the live serial output
// is unchanged. When a debugger IS attached, a real `DbgKmExceptionApi` event carrying the
// faithful `EXCEPTION_RECORD` (code / flags / address / parameters + FirstChance) is queued on
// its `DEBUG_OBJECT` and any thread parked in `NtWaitForDebugEvent` is woken.
//
// ★ TARGET-SIDE BLOCKING (`DbgkpQueueMessage`'s wait on `DebugEvent->ContinueEvent`). After a
// successful forward the FAULTING THREAD IS PARKED on the event — its reply capability is stolen
// into the `DEBUG_EVENT` — and the site must recv the next event WITHOUT replying
// (`dbgk_block_and_park!` below does exactly that). `NtDebugContinue` then applies the continue
// status: `DBG_CONTINUE` resumes it with the FAULT-flavoured reply (a `#PF` retries the faulting
// instruction, an int3 resumes past it), `DBG_EXCEPTION_NOT_HANDLED` leaves the site's own
// handling standing, and `DBG_TERMINATE_THREAD`/`DBG_TERMINATE_PROCESS` are ENFORCED.
// See `ntdll_plan.md` §D.
pub(super) unsafe fn dbgk_forward_exception(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    record: nt_process::dbgk::ExceptionRecord,
) -> bool {
    let tid = nt_handler.current_tid;
    let forwarded = nt_handler.dbgk_forward_exception(pi, tid, record, true);
    if forwarded {
        print_str(b"[dbgk] exception forwarded to debugger pi=");
        print_u64(pi as u64);
        print_str(b" code=0x");
        print_hex(record.exception_code);
        print_str(b" addr=0x");
        print_hex((record.exception_address >> 32) as u32);
        print_hex(record.exception_address as u32);
        print_str(b"\n");
    }
    forwarded
}

// dbgk_block_and_park!(pi, kind, ip, sp, flags): BLOCK the faulting thread on the debug event it
// just reported, then recv the next event WITHOUT replying (the thread stays blocked in-kernel,
// exactly like `park_and_log!`'s park, but WAKEABLE — the debugger's continue resumes it).
//
// ★ SAFETY. Reached only when `dbgk_forward_exception!` returned true, i.e. the process really
// has an `EPROCESS.DebugPort` — never on the live boot. If the park cannot be taken (no reply
// object, pool exhausted) it yields `false` and the site's ordinary handling runs unchanged.
// A blocked reporter counts toward the all-parked QUIESCE (it is a cooperative wait), so a
// debugger that never continues still lets the boot reach the gate.
//
// `msg` comes last so that a caller can pass message registers by value before lending it.
#[track_caller]
pub(super) unsafe fn dbgk_block_and_park(
    exit: &mut LoopExit,
    parks: &mut Parks,
    ingress: &mut Ingress,
    nt_handler: &mut ExecNtHandler,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
    filled_pages: &[u64; 512],
    pi: usize,
    kind: u8,
    ip: u64,
    sp: u64,
    flags: u64,
    msg: &mut Message,
) -> ControlFlow<Turn, bool> {
    let fault_ep = ingress.fault_ep;
    let tid = nt_handler.current_tid;
    let blocked = nt_handler.dbgk_block_reporter(
        pi,
        tid,
        msg.badge,
        kind,
        0,
        ip,
        sp,
        flags,
        0,
    );
    if blocked {
        print_str(b"[dbgk] reporter BLOCKED on continue (fault kind=");
        print_u64(kind as u64);
        print_str(b") pi=");
        print_u64(pi as u64);
        print_str(b" ip=0x");
        print_hex((ip >> 32) as u32);
        print_hex(ip as u32);
        print_str(b"\n");
        procs[pi].faults = exit.faults;
        procs[pi].first = exit.first;
        procs[pi].ntfaults = exit.ntfaults;
        pfilled[pi] = *filled_pages;
        if let ControlFlow::Break(turn) = mark_wait_parked(parks, nt_handler, exit, msg.badge, pi, ip) {
            return ControlFlow::Break(turn);
        }
        let _ = finalize_service_loop_state(nt_handler);
        let (nb, nmi, nm0, nm1, nm2, nm3) = match receive(
            ingress, nt_handler, exit, fault_ep,
            || local().reply_main_slot.load(Ordering::Relaxed),
        ) {
            ControlFlow::Continue(message) => message,
            ControlFlow::Break(turn) => return ControlFlow::Break(turn),
        };
        msg.badge = nb;
        msg.mi = nmi;
        msg.m0 = nm0;
        msg.m1 = nm1;
        msg.m2 = nm2;
        msg.m3 = nm3;
    }
    ControlFlow::Continue(blocked)
}

// mark_wait_parked!(pi): record the current hosted thread as blocked in a deadline-less wait, then
// recompute which process owners have no runnable hosted threads left. If every live owner is now
// crash-parked or wait-parked, QUIESCE (break -> the gate runs). `$ip` is the reported stop value.
#[track_caller]
pub(super) unsafe fn mark_wait_parked(
    parks: &mut Parks,
    nt_handler: &mut ExecNtHandler,
    exit: &mut LoopExit,
    badge: u64,
    pi: usize,
    ip: u64,
) -> ControlFlow<Turn> {
    thread_wait_state_park_badge_waiting(nt_handler, badge);
    parks.wait_parked = wait_parked_owner_mask(nt_handler);
    trace_wait_owner_mask_after_mark(
        nt_handler,
        pi,
        badge,
        live_top_badges(nt_handler),
        parks.crash_parked,
        parks.wait_parked,
    );
    if !cfg!(feature = "mup-provider-kernel-only")
        && (live_top_badges(nt_handler) & !(parks.crash_parked | parks.wait_parked)) == 0
        && !pre_user_shell_frontier_pending(
            nt_handler,
            parks.crash_parked,
            parks.wait_parked,
            b"all-live-waiting",
        )
        && !defer_quiesce_for_active_user_callbacks(b"all-live-waiting")
        && !driver_launch::native_disk_proof_hardware_irp_pending()
        && !driver_launch::active_relation_wal_retained()
        && root_maintenance_owner::next_ready_ticket().is_none()
        && !crate::mounted_volume::mounted_create_outstanding()
        && !crate::mounted_volume::mounted_read_outstanding()
        && !crate::mounted_volume::mounted_directory_outstanding()
        && !driver_launch::mounted_native_physical_irp_pending()
        && crate::registry_mutation_work::next_deadline().is_none()
        && crate::mutable_hive_mutation_work::next_deadline().is_none()
        && crate::section_metadata_work::next_deadline().is_none()
        && crate::process_image_snapshot_work::next_deadline().is_none()
        && crate::section_pagein_work::next_deadline().is_none()
        && crate::provider_section_map_work::next_deadline().is_none()
        && crate::native_image_pagein_work::next_deadline().is_none()
        && crate::vm_lock_pagein_work::next_deadline().is_none()
        && crate::vm_copy_work::next_deadline().is_none()
        && crate::provider_section_broker::next_deadline().is_none()
        && !crate::gdi_routed_image_work::has_outstanding()
        && !crate::native_directory_open_work::occupied()
        && !crate::native_file_target_open_work::occupied()
        && !crate::native_directory_effect_work::has_outstanding(nt_handler)
        && !crate::provider_directory_broker::has_outstanding()
        && crate::provider_directory_broker::next_deadline().is_none()
    {
        unsafe { driver_launch::print_hosted_pnp_enumeration_evidence(); }
        driver_launch::print_mounted_native_block_quiesce_snapshot();
        print_str(
            b"[quiesce] every live process parked/waiting (no signaler left) -> run gate\n",
        );
        exit.stop = ip;
        let _ = pi;
        exit.record(b"wait-all-live-parked");
        return ControlFlow::Break(Turn::Exit);
    }
    ControlFlow::Continue(())
}

/// How `park_queued_callback_root_receive` leaves: it either ends the turn or asks the
/// caller's settlement loop to retry the restore.
pub(super) enum QueuedCallbackPark {
    Retry,
    Turn(Turn),
}

    // A retained queued callback is an independent root parent. Its exact queue selector
    // and Reply remain owned while this root receives a child-producing notification.
/// `retry` is set by the call sites that sat inside the settlement loop and passed its label.
#[track_caller]
pub(super) unsafe fn park_queued_callback_root_receive(
    msg: &mut Message,
    ingress: &mut Ingress,
    nt_handler: &mut ExecNtHandler,
    exit: &mut LoopExit,
    root_event_consumed: &mut bool,
    retry: bool,
) -> QueuedCallbackPark {
    let fault_ep = ingress.fault_ep;
    let permit = match ParkedRootQueuedCallbackPermit::retained() {
        Some(permit) => permit,
        None => {
            exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            exit.stop_ssn = 0;
            exit.record(b"queued-callback-owner");
            return QueuedCallbackPark::Turn(Turn::Exit);
        }
    };
    if !ensure_queued_callback_root_turn(&mut ingress.root_queued_callback_turn, &permit) {
        exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
        exit.stop_ssn = 0;
        exit.record(b"queued-callback-owner-changed");
        return QueuedCallbackPark::Turn(Turn::Exit);
    }
    ROOT_QUEUED_CALLBACK_EXCLUSIVE.store(true, Ordering::Release);
    if !*root_event_consumed {
        if badge_has_delay_timer(msg.badge) || hosted_irq_lines_from_badge(msg.badge) != 0 {
            let turn = ingress.root_queued_callback_turn.last_mut()
                .expect("queued callback turn");
            if service_parked_queued_callback_notification(msg.badge).is_err() {
                exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                exit.stop_ssn = 0;
                exit.record(b"queued-callback-notification");
                return QueuedCallbackPark::Turn(Turn::Exit);
            }
            let arrival = if badge_has_delay_timer(msg.badge) {
                nt_driver_start::RootArrival::Timer { now: monotonic_time_100ns() }
            } else { nt_driver_start::RootArrival::Irq };
            if turn.observe_arrival(permit.0, arrival).is_err() {
                exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                exit.stop_ssn = 0;
                exit.record(b"queued-callback-arrival");
                return QueuedCallbackPark::Turn(Turn::Exit);
            }
        } else {
            let reply = local().reply_main_slot.load(Ordering::Relaxed);
            let selected_child = crate::spawn_hosts::shared_ingress::owner::runtime::
                receive_child_pending()
                && hosted_ingress_binding(msg.badge).is_some_and(|binding|
                    crate::spawn_hosts::shared_ingress::owner::runtime::
                        receive_child_is_current(binding, reply));
            let retained = if selected_child {
                crate::spawn_hosts::shared_ingress::owner::runtime::
                    defer_hosted_delivery_for_queued_callback(reply, msg.badge, &permit)
                    .is_ok()
            } else {
                retain_parked_queued_callback_ingress(
                    &mut ingress.root_queued_callback_turn, &permit, reply, msg.badge)
            };
            if !retained {
                exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                exit.stop_ssn = 0;
                exit.record(b"queued-callback-ingress-defer");
                return QueuedCallbackPark::Turn(Turn::Exit);
            }
        }
        *root_event_consumed = true;
    }
    if retry {
        // This retry remains inside the same root-event settlement loop. The
        // consumed marker must survive until a different ingress is received.
        if let Some(crate::driver_launch::QueuedCallbackRootAction::RetryRestore(selector)) =
            crate::driver_launch::queued_callback_root_action()
        {
            if selector == permit.0 {
                let (dispatch, reply) = selector.dispatch_reply();
                if crate::spawn_hosts::shared_ingress::owner::runtime::
                    root_idle_receive_after_child_yield(dispatch, reply)
                {
                    return QueuedCallbackPark::Retry;
                }
            }
        }
    }
    if !prepare_parked_queued_callback_receive(&mut ingress.root_queued_callback_turn) {
        exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
        exit.stop_ssn = 0;
        exit.record(b"queued-callback-receive-prepare");
        return QueuedCallbackPark::Turn(Turn::Exit);
    }
    let received = match receive(
        ingress, nt_handler, exit, fault_ep,
        || local().reply_main_slot.load(Ordering::Relaxed),
    ) {
        ControlFlow::Continue(message) => message,
        ControlFlow::Break(turn) => return QueuedCallbackPark::Turn(turn),
    };
    (msg.badge, msg.mi, msg.m0, msg.m1, msg.m2, msg.m3) = received;
    QueuedCallbackPark::Turn(Turn::Next)
}
