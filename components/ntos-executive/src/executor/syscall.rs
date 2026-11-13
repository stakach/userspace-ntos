//! The syscall arm of the service loop (issue #382, loop hoist).

use super::loop_flow::*;
use super::loop_receive::receive;
use super::*;
use crate::executor::local;

/// What the syscall prelude establishes for the routes and the tail: the caller's resume
/// coordinates, the selected table entry and the trace state of this call.
pub(super) struct Syscall {
    pub(super) native_call_transport: bool,
    pub(super) resume_ip: u64,
    pub(super) sp: u64,
    pub(super) flags: u64,
    pub(super) lsa_logon_trace_seq: Option<u64>,
    pub(super) syscall_reply_context: SyscallReplyContext,
    pub(super) current_tid: u64,
    pub(super) table_entry: Option<nt_syscall::NativeServiceEntry>,
}

/// What one syscall decides: its result, whether the NT or win32k route handled it, and the
/// park or transfer it asks the reply-or-park tail to perform. These were the mutable locals
/// the syscall prelude declared and the tail consumed.
pub(super) struct SyscallOutcome {
    pub(super) result: u64,
    pub(super) handled: bool,
    // Set by an accepted interactive milestone that parks the caller instead of replying.
    pub(super) wl_milestone_park: bool,
    // A blocking GetMessage park must not end the boot; the service loop keeps running.
    // (Phase 3: the `routed_win32k` / `routed_lpc` / `routed_csr` flags that used to live
    // here are GONE. They existed solely to steer this syscall's reply away from the legacy
    // `reply_to` — which a nested win32k / SM-loop / CSR-thread fault had clobbered — and
    // onto the caller's bound `REPLY_MAIN`. Every reply takes the bound object now, so there
    // is nothing left to steer. See the reply tail at the bottom of the syscall arm.)
    pub(super) redirected_user_callback: bool,
    pub(super) component_suspension_park_request: bool,
    pub(super) component_root_maintenance_ticket: Option<root_maintenance_owner::RootMaintenanceTicket>,
    pub(super) component_suspension_admitted_dispatch_id: u64,
    pub(super) current_apc_handoff: Option<nt_user_host::current_apc::CurrentApcIdentity>,
    pub(super) redirected_context_continue: bool,
    pub(super) active_callback_bad_resume: bool,
    // Checkpoint B: -1 = no wait-park; >=0 = NtWaitForSingleObject asked to park this caller on
    // the encoded WaitObject in nt_handler.wait_park_event after dispatch.
    pub(super) park_wait_event: i64,
    /// Namespace identity captured when the park object's handle was resolved.
    pub(super) park_wait_event_identity: u64,
    pub(super) park_wait_identities: [u64; 64],
    // Array-wait park: the typed dispatcher/process/thread/File set + WaitAll flag.
    // count 0 = no array-park. Consumed next to park_wait_event in the reply block.
    pub(super) park_wait_set: &'static mut [WaitObject; 64],
    pub(super) park_wait_indices: &'static mut [u8; 64],
    pub(super) park_wait_set_n: usize,
    pub(super) park_wait_set_all: bool,
    pub(super) park_wait_alertable: bool,
    pub(super) park_wait_deadline: nt_delay_execution::Deadline,
    pub(super) park_keyed_wait_key: u64,
    pub(super) park_keyed_wait_deadline: nt_delay_execution::Deadline,
    pub(super) park_keyed_release_wait_key: u64,
    pub(super) park_keyed_release_wait_deadline: nt_delay_execution::Deadline,
    pub(super) park_delay_deadline: Option<nt_delay_execution::Deadline>,
    pub(super) park_thread_alert_deadline: Option<nt_delay_execution::Deadline>,
    pub(super) park_io_completion_port: i64,
    pub(super) park_io_completion_key_out: u64,
    pub(super) park_io_completion_apc_out: u64,
    pub(super) park_io_completion_iosb_out: u64,
    pub(super) park_io_completion_deadline: nt_delay_execution::Deadline,
    pub(super) published_file_io: Option<file_dispatch_handoff::PublishedFileIo>,
    pub(super) transfer_pending_driver_start: Option<PendingDriverStartTransfer>,
    pub(super) transfer_native_directory_open: Option<crate::native_directory_open_work::PendingNativeDirectoryOpen>,
    pub(super) transfer_native_file_target: Option<crate::native_file_target_open_work::PendingNativeFileTargetOpen>,
    pub(super) transfer_native_directory_effect: Option<crate::native_directory_effect_work::PendingNativeDirectoryEffect>,
    pub(super) transfer_pending_pnp_operation: Option<PendingPnpOperationTransfer>,
    pub(super) transfer_file_irp_drain: Option<(nt_io_manager::PendingFileIrpDrain, nt_io_manager::PendingFileIrpDrainReservation)>,
    pub(super) transfer_file_cleanup_wait: Option<(nt_io_manager::PendingFileCleanupWait, nt_io_manager::PendingFileCleanupWaitReservation)>,
    pub(super) synchronous_file_wait_parked: bool,
    pub(super) park_lpc_receive: Option<PendingLpcReceivePark>,
    pub(super) park_lpc_connect: Option<PendingLpcConnectPark>,
    pub(super) park_lpc_request: Option<PendingLpcRequestPark>,
    // ★ Dbgk TARGET-SIDE BLOCK request (syscall flavour) latched out of the handler:
    // a debug event was posted from THIS syscall arm and NT blocks the reporting thread on
    // the debugger's continue. Consumed at the reply site (the reply-cap steal needs
    // resume_ip/sp/flags, known only there). Always false with no debugger attached.
    pub(super) park_dbgk_reporter: bool,
}

impl SyscallOutcome {
    pub(super) unsafe fn new() -> Self {
        Self {
            result: 0,
            handled: true,
            wl_milestone_park: false,
            redirected_user_callback: false,
            component_suspension_park_request: false,
            component_root_maintenance_ticket: None,
            component_suspension_admitted_dispatch_id: 0,
            current_apc_handoff: None,
            redirected_context_continue: false,
            active_callback_bad_resume: false,
            park_wait_event: -1,
            park_wait_event_identity: 0,
            park_wait_identities: [0; 64],
            park_wait_set: &mut *core::ptr::addr_of_mut!(PARK_WAIT_SET_WORK),
            park_wait_indices: &mut *core::ptr::addr_of_mut!(PARK_WAIT_INDEX_WORK),
            park_wait_set_n: 0,
            park_wait_set_all: false,
            park_wait_alertable: false,
            park_wait_deadline: nt_delay_execution::Deadline::Infinite,
            park_keyed_wait_key: u64::MAX,
            park_keyed_wait_deadline: nt_delay_execution::Deadline::Infinite,
            park_keyed_release_wait_key: u64::MAX,
            park_keyed_release_wait_deadline: nt_delay_execution::Deadline::Infinite,
            park_delay_deadline: None,
            park_thread_alert_deadline: None,
            park_io_completion_port: -1,
            park_io_completion_key_out: 0,
            park_io_completion_apc_out: 0,
            park_io_completion_iosb_out: 0,
            park_io_completion_deadline: nt_delay_execution::Deadline::Infinite,
            published_file_io: None,
            transfer_pending_driver_start: None,
            transfer_native_directory_open: None,
            transfer_native_file_target: None,
            transfer_native_directory_effect: None,
            transfer_pending_pnp_operation: None,
            transfer_file_irp_drain: None,
            transfer_file_cleanup_wait: None,
            synchronous_file_wait_parked: false,
            park_lpc_receive: None,
            park_lpc_connect: None,
            park_lpc_request: None,
            park_dbgk_reporter: false,
        }
    }
}

#[inline(never)]
pub(super) unsafe fn syscall(
    lp: &mut LoopState<'_>,
    ev: &Event,
    native_call_transport: bool,
) -> ControlFlow<Turn, core::convert::Infallible> {
    let mut nt_handler = &mut *lp.handler;
    let nt_dispatcher = lp.dispatcher;
    let fault_ep = lp.ingress.fault_ep;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let Event {
        event_runtime, is_tp_worker, is_lsa_auth_server, is_wl_worker, pi, scratch_base, pml4, ..
    } = *ev;
    // A native `syscall` from the process (via ntdll's Nt* stub).
    let authoritative_syscall_context = if native_call_transport {
        None
    } else {
        capture_authoritative_unknown_syscall_context(&nt_handler, lp.msg.badge, lp.msg.m2)
    };
    if let Some((ctx, _)) = authoritative_syscall_context.as_ref() {
        trace_unknown_syscall_tcb_restage(lp.msg.m0, lp.msg.badge, pi, ctx);
    }
    lp.diag.ssn_ring[lp.diag.ssn_ri % 32] = lp.msg.m0 as u16;
    lp.diag.ssn_ring_badge[lp.diag.ssn_ri % 32] = lp.msg.badge as u8;
    lp.diag.ssn_ri += 1;
    if hosted_main_badge_has_role(
        &nt_handler,
        lp.msg.badge,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) {
        lp.diag.wl_ring[lp.diag.wl_ri % 48] = lp.msg.m0 as u16;
        lp.diag.wl_ri += 1;
    }
    let resume_ip = lp.msg.m2; // Ingress coordinates retained for explicit waits/APCs and retries.
    let sp = get_recv_mr(16);
    let flags = get_recv_mr(17);
    let syscall_reply_context = authoritative_syscall_context
        .map(|(_, context)| context)
        .unwrap_or_else(|| SyscallReplyContext::capture(lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3));
    let parked_syscall_reply = if native_call_transport {
        nt_syscall_abi::ParkedSyscallReply::native_call()
    } else {
        nt_syscall_abi::ParkedSyscallReply::unknown_syscall(
            resume_ip,
            sp,
            flags,
        )
    };
    // Released LiberNT compatibility DLLs can issue raw syscall numbers that differ
    // from the source-built ntdll's private table. Resolve the observed external ABI
    // before admission and dispatch, after preserving the original fault/reply frame.
    let raw_external_ssn = lp.msg.m0;
    lp.msg.m0 = nt_syscall_abi::normalize_external_raw_ssn(lp.msg.m0, native_call_transport);
    let current_tid = nt_handler
        .hosted_thread_tid_for_badge(lp.msg.badge)
        .unwrap_or_else(|| {
            print_str(b"[hosted-thread] missing runtime TID for syscall badge=");
            print_u64(lp.msg.badge);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b"\n");
            0
        });
    if current_tid == event_runtime.tid {
        crate::registry_mutation_work::trace_next_hosted_syscall(
            event_runtime.binding(), raw_external_ssn, lp.msg.m0,
        );
    }
    if {
        let waiters = &*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS);
        waiters.has_retry_delivery_for_thread(current_tid)
            || waiters.has_cancellation_for_thread(current_tid)
            || waiters.has_ingress_for_thread(current_tid)
            || crate::object_wait_apc::has_thread(current_tid)
            || crate::object_wait_reply::owns_thread(current_tid)
            || crate::pending_file_apc::owns_thread(current_tid)
            || crate::current_apc::owns_thread(current_tid)
            || crate::section_metadata_work::has_thread(current_tid)
            || crate::process_image_snapshot_work::has_thread(current_tid)
            || crate::hosted_spawn_uncertainty::has_thread(current_tid)
    }
    {
        // An uncertain earlier retry is not a fresh File acquisition. Reject only this
        // new request; its distinct main Reply cannot retire the old grant or reply.
        let reply_main = local().reply_main_slot.load(Ordering::Relaxed);
        assert!(reply_parked_syscall(reply_main, 0xC000_00A3),
            "retained File retry ingress refusal lost its new reply");
        // Once this request has been refused, its IPC words are no longer needed.
        // Progress retained cancellation even when rejected ingress is the only activity.
        synchronous_file_cancellation::redrive(&mut nt_handler);
        crate::object_wait_apc::redrive(&mut nt_handler);
        crate::object_wait_reply::redrive(&mut nt_handler);
        crate::pending_file_apc::redrive(&mut nt_handler);
        crate::current_apc::redrive(&mut nt_handler);
        inline_file_retirement::redrive(&mut nt_handler);
        let reply_main = local().reply_main_slot.load(Ordering::Relaxed);
        let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || reply_main,
        )?;
        lp.msg.badge = nb;
        lp.msg.mi = nmi;
        lp.msg.m0 = nm0;
        lp.msg.m1 = nm1;
        lp.msg.m2 = nm2;
        lp.msg.m3 = nm3;
        return ControlFlow::Break(Turn::Next);
    }
    let syscall_process_role = nt_handler.hosted_process_observation_role(pi);
    if matches!(
        syscall_process_role,
        Some(
            nt_exe_image::HostedProcessRole::InteractiveLogon
                | nt_exe_image::HostedProcessRole::InteractiveShell
                | nt_exe_image::HostedProcessRole::Win32Subsystem
        )
    ) {
        let n = INTERACTIVE_SYSCALL_CONTEXT_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 96 || lp.msg.m0 == 0x1286 {
            print_str(b"[interactive-ssn-ctx] #");
            print_u64(n);
            print_str(b" role=");
            print_str(match syscall_process_role {
                Some(nt_exe_image::HostedProcessRole::InteractiveLogon) => b"winlogon",
                Some(nt_exe_image::HostedProcessRole::InteractiveShell) => b"explorer",
                Some(nt_exe_image::HostedProcessRole::Win32Subsystem) => b"csrss",
                _ => b"other",
            });
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" pi=");
            print_u64(pi as u64);
            print_str(b" tid=");
            print_u64(current_tid);
            print_str(b" ssn=0x");
            print_hex(lp.msg.m0 as u32);
            print_str(b" rip=0x");
            print_hex_u64(resume_ip);
            print_str(b" sp=0x");
            print_hex_u64(sp);
            print_str(b" flags=0x");
            print_hex_u64(flags);
            print_str(b" r10=0x");
            print_hex_u64(get_recv_mr(9));
            print_str(b" rdx=0x");
            print_hex_u64(lp.msg.m3);
            print_str(b"\n");
        }
    }
    let syscall_is_explorer =
        syscall_process_role == Some(nt_exe_image::HostedProcessRole::InteractiveShell);
    if syscall_is_explorer {
        let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
        if active_depth != 0 {
            let n = EXPLORER_CALLBACK_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 256 {
                print_str(b"[explorer-cb-ssn] #");
                print_u64(n);
                print_str(b" badge=");
                print_u64(lp.msg.badge);
                print_str(b" tid=");
                print_u64(current_tid);
                print_str(b" ssn=0x");
                print_hex_u64(lp.msg.m0);
                print_str(b" depth=");
                print_u64(active_depth as u64);
                print_str(b"/");
                print_u64(continuation_depth as u64);
                print_str(b" rdx=0x");
                print_hex_u64(lp.msg.m3);
                print_str(b" r8=0x");
                print_hex_u64(get_recv_mr(7));
                print_str(b" r9=0x");
                print_hex_u64(get_recv_mr(8));
                print_str(b" r10=0x");
                print_hex_u64(get_recv_mr(9));
                print_str(b" r15=0x");
                print_hex_u64(get_recv_mr(14));
                print_str(b" resume-ip=0x");
                print_hex_u64(resume_ip);
                print_str(b"\n");
            }
        }
    }
    if syscall_is_explorer && lp.msg.m0 == SSN_NT_FLUSH_INSTRUCTION_CACHE {
        let n = EXPLORER_FLUSH_ICACHE_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            let (active_depth, continuation_depth) =
                win32k_glue::user_callback_stack_depths();
            print_str(b"[explorer-flush-icache] #");
            print_u64(n);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" tid=");
            print_u64(current_tid);
            print_str(b" callback-depth=");
            print_u64(active_depth as u64);
            print_str(b" continuation-depth=");
            print_u64(continuation_depth as u64);
            print_str(b" process=0x");
            print_hex_u64(get_recv_mr(9));
            print_str(b" base=0x");
            print_hex_u64(lp.msg.m3);
            print_str(b" size=0x");
            print_hex_u64(get_recv_mr(7));
            print_str(b" resume-ip=0x");
            print_hex_u64(resume_ip);
            print_str(b"\n");
        }
    }
    if nt_dispatcher
        .table()
        .lookup(lp.msg.m0 as u32)
        .is_some_and(|entry| entry.service == NativeService::NtCallbackReturn)
    {
        match win32k_glue::user_callback_return_readiness(pi as u32, lp.msg.badge, current_tid) {
            win32k_glue::UserCallbackReturnReadiness::Deferred => {
                if defer_user_callback_return(
                    pi as u32,
                    lp.msg.badge,
                    current_tid,
                    get_recv_mr(9),
                    lp.msg.m3,
                    get_recv_mr(7),
                    parked_syscall_reply,
                ) {
                    procs[pi].faults = lp.exit.faults;
                    procs[pi].first = lp.exit.first;
                    procs[pi].ntfaults = lp.exit.ntfaults;
                    pfilled[pi] = *filled_pages;
                    let new_reply = local().reply_main_slot.load(Ordering::Relaxed);
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
                print_str(
                    b"[user-callback] unable to defer out-of-order NtCallbackReturn -> STATUS_INSUFFICIENT_RESOURCES\n",
                );
                let reply_main = local().reply_main_slot.load(Ordering::Relaxed);
                reply_parked_syscall(reply_main, 0xC000_009A);
                let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                    &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || reply_main,
                )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                return ControlFlow::Break(Turn::Next);
            }
            win32k_glue::UserCallbackReturnReadiness::Ready => {
                let Some(callback_reply_reservation) =
                    root_reply_park::RootReplyReservation::before_native()
                else {
                    let reply_main = local().reply_main_slot.load(Ordering::Relaxed);
                    reply_parked_syscall(reply_main, nt_process::STATUS_INSUFFICIENT_RESOURCES as u64);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                        &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || reply_main,
                    )?;
                    lp.msg.badge = nb; lp.msg.mi = nmi; lp.msg.m0 = nm0; lp.msg.m1 = nm1; lp.msg.m2 = nm2; lp.msg.m3 = nm3;
                    return ControlFlow::Break(Turn::Next);
                };
                let callback_completion = win32k_glue::complete_controlled_user_callback(
                    pi as u32,
                    lp.msg.badge,
                    current_tid,
                    get_recv_mr(9),
                    lp.msg.m3,
                    get_recv_mr(7),
                    resume_ip,
                    sp,
                    flags,
                );
                if let Some(completion) = callback_completion {
                    if let win32k_glue::CompletedUserCallback::CaptureRefused {
                        lane, callback_token, provider_reply_cap,
                    } = completion {
                        let _ = provider_reply_cap; // The provider owner records an uncertain zero Reply.
                        assert!(win32k_glue::retain_callback_outer_reply(
                            lane, callback_token, local().reply_main_slot.load(Ordering::Relaxed),
                        ), "refused callback lost its two exact Reply owners");
                        assert!(callback_reply_reservation.commit(),
                            "reserved callback Reply replacement lost its exact lease");
                        procs[pi].faults = lp.exit.faults;
                        procs[pi].first = lp.exit.first;
                        procs[pi].ntfaults = lp.exit.ntfaults;
                        pfilled[pi] = *filled_pages;
                        let _ = finalize_service_loop_state(&mut nt_handler);
                        let new_reply = local().reply_main_slot.load(Ordering::Relaxed);
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
                assert!(callback_reply_reservation.cancel_no_effects(),
                    "ordinary callback return lost its unused Reply reservation");
                if let Some(completion) = callback_completion {
                    if !sync_completed_user_callback_win32k_context(
                        &mut nt_handler,
                        pi,
                        current_tid,
                    ) {
                        print_str(
                            b"[win32k-context] ERROR: callback completion could not publish Ps identity\n",
                        );
                        panic!("failed callback context publication retains its bound Reply");
                    }
                    let staged_context = match completion {
                        win32k_glue::CompletedUserCallback::CaptureRefused { .. } => {
                            unreachable!("refused callback returns before context classification")
                        }
                        win32k_glue::CompletedUserCallback::Completed {
                            outer_dispatch,
                            callback_context,
                        } => {
                            let mut outer_dispatch_completed = false;
                            if let Some(dispatch) = outer_dispatch {
                                if !process_completed_user_callback_outer_dispatch(
                                    nt_handler,
                                    pi,
                                    pml4,
                                    lp.msg.badge,
                                    current_tid,
                                    dispatch,
                                    filled_pages,
                                    lp.exit.faults as usize,
                                    scratch_base,
                                ) {
                                    return ControlFlow::Break(lp.park_and_log(pi, b"userconnect-copyout", dispatch.ssn, dispatch.args[1]));
                                } else {
                                    outer_dispatch_completed = true;
                                }
                            }
                            if outer_dispatch_completed {
                                pfilled[pi] = *filled_pages;
                            }
                            callback_context
                        }
                        win32k_glue::CompletedUserCallback::ProviderWaitSuspended {
                            pending,
                            callback_token,
                            callback_context,
                        } => {
                            let dispatch_id = pending.dispatch.dispatch_id;
                            assert!(provider_wait_admit_current(
                                &mut nt_handler,
                                pending,
                                Some(ComponentCallbackTransfer {
                                    token: callback_token,
                                    context: callback_context,
                                }),
                                HostedContinuationDestination::Win32k,
                            ) == RetainedWaitAdmission::Accepted);
                            procs[pi].faults = lp.exit.faults;
                            procs[pi].first = lp.exit.first;
                            procs[pi].ntfaults = lp.exit.ntfaults;
                            pfilled[pi] = *filled_pages;
                            let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                            if component_suspension_owns_hosted_dispatch(dispatch_id) {
                                mark_wait_parked(
                                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                                )?;
                            }
                            let _ = finalize_service_loop_state(&mut nt_handler);
                            let new_reply = local().reply_main_slot.load(Ordering::Relaxed);
                            let (nb, nmi, nm0, nm1, nm2, nm3) =
                                receive(
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
                        win32k_glue::CompletedUserCallback::LpcWaitSuspended {
                            pending,
                            callback_token,
                            callback_context,
                        } => {
                            let dispatch_id = pending.dispatch.dispatch_id;
                            assert!(lpc_wait_admit_current(
                                &mut nt_handler,
                                pending,
                                Some(ComponentCallbackTransfer {
                                    token: callback_token,
                                    context: callback_context,
                                }),
                                HostedContinuationDestination::Win32k,
                            ) == RetainedWaitAdmission::Accepted);
                            procs[pi].faults = lp.exit.faults;
                            procs[pi].first = lp.exit.first;
                            procs[pi].ntfaults = lp.exit.ntfaults;
                            pfilled[pi] = *filled_pages;
                            let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                            if component_suspension_owns_hosted_dispatch(dispatch_id) {
                                mark_wait_parked(
                                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                                )?;
                            }
                            let _ = finalize_service_loop_state(&mut nt_handler);
                            let new_reply = local().reply_main_slot.load(Ordering::Relaxed);
                            let (nb, nmi, nm0, nm1, nm2, nm3) =
                                receive(
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
                        win32k_glue::CompletedUserCallback::ReceiveSuspended {
                            pending,
                            callback_token,
                            callback_context,
                        } => {
                            let dispatch_id = pending.snapshot.dispatch.dispatch_id;
                            let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
                                panic!("callback Receive must retain its original Reply");
                            };
                            assert!(receive_admit_retained(
                                pending,
                                local().reply_main_slot.load(Ordering::Relaxed),
                                Some(ComponentCallbackTransfer {
                                    token: callback_token,
                                    context: callback_context,
                                }),
                                HostedContinuationDestination::Win32k,
                            ));
                            reply_park.commit();
                            procs[pi].faults = lp.exit.faults;
                            procs[pi].first = lp.exit.first;
                            procs[pi].ntfaults = lp.exit.ntfaults;
                            pfilled[pi] = *filled_pages;
                            let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                            if component_suspension_owns_hosted_dispatch(dispatch_id) {
                                mark_wait_parked(
                                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                                )?;
                            }
                            let _ = finalize_service_loop_state(&mut nt_handler);
                            let new_reply = local().reply_main_slot.load(Ordering::Relaxed);
                            let (nb, nmi, nm0, nm1, nm2, nm3) =
                                receive(
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
                        win32k_glue::CompletedUserCallback::ServiceWaitSuspended {
                            pending,
                            callback_token,
                            callback_context,
                        } => {
                            let dispatch_id = pending.snapshot.dispatch.dispatch_id;
                            let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
                                panic!("callback service wait must retain its original Reply");
                            };
                            assert!(service_wait_admit_retained(
                                pending,
                                local().reply_main_slot.load(Ordering::Relaxed),
                                Some(ComponentCallbackTransfer {
                                    token: callback_token,
                                    context: callback_context,
                                }),
                                HostedContinuationDestination::Win32k,
                            ));
                            reply_park.commit();
                            procs[pi].faults = lp.exit.faults;
                            procs[pi].first = lp.exit.first;
                            procs[pi].ntfaults = lp.exit.ntfaults;
                            pfilled[pi] = *filled_pages;
                            let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(nt_handler));
                            if component_suspension_owns_hosted_dispatch(dispatch_id) {
                                mark_wait_parked(
                                    &mut lp.parks, nt_handler, &mut lp.exit, lp.msg.badge, pi, resume_ip,
                                )?;
                            }
                            let _ = finalize_service_loop_state(&mut nt_handler);
                            let new_reply = local().reply_main_slot.load(Ordering::Relaxed);
                            let (nb, nmi, nm0, nm1, nm2, nm3) =
                                receive(
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
                    };
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
                    let reply_main = local().reply_main_slot.load(Ordering::Relaxed);
                    let restarted = win32k_glue::restart_staged_user_callback_context(
                        staged_context,
                        reply_main,
                    );
                    assert!(restarted, "rejected callback restart retains its bound Reply");
                    let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                        &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || reply_main,
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
            win32k_glue::UserCallbackReturnReadiness::Missing => {}
        }
    }
    // DIAG (credential frontier): once the injected VK_RETURN has been delivered, trace
    // winlogon's NATIVE (non-win32k) syscalls — that is the WM_COMMAND(IDOK) ->
    // LogonDialogProc -> DoLogon -> DoLoginTasks -> ConnectToLsa/LsaLogonUser tail.
    if pi == 2 && lp.msg.m0 < 0x1000 && WINLOGON_CRED_RETRIEVED_RETURN.load(Ordering::Relaxed) != 0
    {
        let n = WINLOGON_CRED_POST_RETURN_SSNS.fetch_add(1, Ordering::Relaxed);
        if n < 192 {
            print_str(b"[cred-tail] winlogon native SSN=");
            print_u64(lp.msg.m0);
            print_str(b"\n");
        }
    }
    // lsasrv's `LsapCopyFromClient` reads the caller's
    // `MSV1_0_INTERACTIVE_LOGON` while the real API 2 request is in flight. Process-role
    // provenance keeps this proof independent of listener/thread identities.
    if lp.msg.m0 == SSN_NT_READ_VM
        && LSA_LOGON_IN_FLIGHT.load(Ordering::Relaxed) != 0
        && nt_handler.hosted_process_role(pi)
            == Some(nt_exe_image::HostedProcessRole::LocalSecurityAuthority)
    {
        LSA_LOGON_CLIENT_READS.fetch_add(1, Ordering::Relaxed);
    }
    // Bounded diagnostic for the real LSA server while its generic runtime provenance says
    // it owns an authentication-port request.
    if is_lsa_auth_server && nt_handler.hosted_thread_lpc_client_process(lp.msg.badge) != 0 {
        let n = LSA_SRV_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
        if n < 96 {
            print_str(b"[lsa-srv-ssn] #");
            print_u64(n);
            print_str(b" ssn=");
            print_u64(lp.msg.m0);
            print_str(b" arg1=0x");
            print_hex(get_recv_mr(9) as u32);
            print_str(b" arg2=0x");
            print_hex(lp.msg.m3 as u32);
            print_str(b"\n");
        }
    }
    let trace_lsa_logon = native_call_transport
        && LSA_LOGON_IN_FLIGHT.load(Ordering::Relaxed) != 0
        && nt_handler.current_tid == LSA_LOGON_SERVER_TID.load(Ordering::Relaxed)
        && nt_handler.hosted_process_role(pi)
            == Some(nt_exe_image::HostedProcessRole::LocalSecurityAuthority);
    let lsa_logon_trace_seq = if trace_lsa_logon {
        let n = LSA_LOGON_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
        LSA_LOGON_LAST_SSN.store(lp.msg.m0, Ordering::Relaxed);
        LSA_LOGON_LAST_STATUS.store(u64::MAX, Ordering::Relaxed);
        LSA_LOGON_LAST_TCB.store(event_runtime.tcb, Ordering::Relaxed);
        if n < 128 {
            print_str(b"[lsa-logon-ssn] enter #");
            print_u64(n);
            print_str(b" tid=");
            print_u64(nt_handler.current_tid);
            print_str(b" ssn=");
            print_u64(lp.msg.m0);
            print_str(b" arg1=0x");
            print_hex_u64(get_recv_mr(9));
            print_str(b" arg2=0x");
            print_hex_u64(lp.msg.m3);
            print_str(b"\n");
        }
        Some(n)
    } else {
        None
    };
    let mut sc = SyscallOutcome::new();
    // Every syscall path, including the still hand-wired ladder below, resolves process-local
    // handles through ExecNtHandler. Refresh caller identity before choosing table vs ladder;
    // doing this only inside table dispatch left a runtime worker using whichever process ran
    // the previous registered syscall.
    nt_handler.pi = pi;
    nt_handler.current_badge = lp.msg.badge;
    nt_handler.current_tid = current_tid;
    nt_handler.current_resume_ip = resume_ip;
    nt_handler.current_sp = sp;
    nt_handler.current_flags = flags;
    nt_handler.current_service_number = lp.msg.m0 as u32;
    nt_handler.current_native_call_transport = native_call_transport;
    nt_handler.current_user_memory = SyscallUserMemory::CurrentProcess;
    nt_handler.current_server_client_pid =
        nt_handler.hosted_thread_lpc_client_process(lp.msg.badge);
    assert!(nt_handler.current_synchronous_file.is_none(),
        "previous syscall retained acquired File Busy");
    assert!(nt_handler.current_file_transfer_event.is_none(),
        "previous syscall retained a File completion Event");
    nt_handler.current_file_transfer_parameters = None;
    assert!(nt_handler.active_synchronous_file_retry.is_none(),
        "previous syscall retained an unconsumed File ingress claim");
    nt_handler.active_synchronous_file_retry = match (&mut *core::ptr::addr_of_mut!(
        SYNCHRONOUS_FILE_WAITERS
    )).begin_ingress(pi as u32, current_tid, lp.msg.badge, lp.msg.m0 as u32) {
        Ok(ingress) => ingress,
        Err(_) => {
            // A mismatched request cannot consume an existing thread's grant.
            let reply_main = local().reply_main_slot.load(Ordering::Relaxed);
            assert!(reply_parked_syscall(reply_main, 0xC000_00A3),
                "File ingress refusal lost its new reply");
            synchronous_file_cancellation::redrive(&mut nt_handler);
            let reply_main = local().reply_main_slot.load(Ordering::Relaxed);
            let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
                &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || reply_main,
            )?;
            lp.msg.badge = nb;
            lp.msg.mi = nmi;
            lp.msg.m0 = nm0;
            lp.msg.m1 = nm1;
            lp.msg.m2 = nm2;
            lp.msg.m3 = nm3;
            return ControlFlow::Break(Turn::Next);
        }
    };
    // SEAM: if this SSN is in the real service table, dispatch it through the NT syscall
    // dispatcher -> real handler; otherwise fall through to the broker match. The x64 native
    // ABI passes args in r10(=rcx),rdx,r8,r9 then the stack; here we forward the register
    // args (sized to the service's max) — pointer/stack args come with the copyin layer.
    let table_entry = nt_dispatcher.table().lookup(lp.msg.m0 as u32);
    let call = Syscall {
        native_call_transport, resume_ip, sp, flags, lsa_logon_trace_seq,
        syscall_reply_context, current_tid, table_entry,
    };
    if let Some(route) = nt_syscall_abi::NativeIngressRoute::select(
        lp.msg.m0, native_call_transport, table_entry.is_some()) {
        loop_syscall_nt::syscall_nt_route(lp, ev, &call, &mut sc, route)?;
    } else if lp.msg.m0 >= win32k_subsystem::WIN32K_SERVICE_BASE
        && (hosted_non_native_top_level_badge(&nt_handler, lp.msg.badge)
            || is_wl_worker
            || (is_tp_worker && pi != 0))
    {
        loop_syscall_win32k::syscall_win32k_route(lp, ev, &call, &mut sc)?;
    } else {
        // SSNs absent from the registered native table are complete dispatcher decisions:
        // the NT syscall layer rejects them instead of treating them as missing kernel code.
        sc.result = nt_syscall::STATUS_INVALID_SYSTEM_SERVICE as u64;
    }
    return loop_syscall_tail::syscall_tail(lp, ev, &call, &mut sc);
}
