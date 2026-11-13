//! Event admission of the service loop (issue #382, loop hoist).
//!
//! `admit` validates the received event against the live thread and process tables, selects
//! the roles of the sending thread, loads its process's working state and builds the `Event`
//! the arms read.
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::loop_receive::receive;
use super::*;

/// The admitted event of one turn: who sent it, which roles that thread has and the
/// geometry of its process. Admission builds it once; the arms read it.
pub(super) struct Event<'e> {
    pub(super) event_runtime: HostedThreadRuntime,
    pub(super) is_svc_listener: bool,
    pub(super) is_lsass_listener: bool,
    pub(super) is_lsass_listener2: bool,
    pub(super) is_lsass_listener3: bool,
    pub(super) is_tp_worker: bool,
    pub(super) is_scm_worker: bool,
    pub(super) is_lsa_worker: bool,
    pub(super) is_lsa_auth_server: bool,
    pub(super) is_wl_worker: bool,
    pub(super) pi: usize,
    pub(super) native_ingress_request: Option<nt_syscall_abi::NativeSyscallRequest>,
    pub(super) scratch_base: u64,
    pub(super) pml4: u64,
    pub(super) hosted_thread_role: Option<HostedThreadRole>,
    /// The executable of the event's process. A raw pointer, because the reference it comes
    /// from borrows the loaded-image table that the arms also reach through `LoopState`. The
    /// event's image read scope keeps the parsed image alive for the turn.
    pub(super) pe: *const nt_pe_loader::PeFile<'e>,
    pub(super) img_end: u64,
    pub(super) img_base: u64,
    /// Keeps the parsed executable of the event's process alive until the turn ends.
    pub(super) _event_image_reader: crate::hosted_loaded_images::HostedImageReadScope,
}

#[inline(never)]
pub(super) unsafe fn admit<'a>(
    lp: &mut LoopState<'a>,
    ingress: Option<HostedThreadRuntime>,
    native_ingress_request: Option<nt_syscall_abi::NativeSyscallRequest>,
) -> ControlFlow<Turn, Event<'a>> {
    let mut nt_handler = &mut *lp.handler;
    let fault_ep = lp.ingress.fault_ep;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let primary_pi = lp.procs.primary_pi;
    let exe_image_catalog = &mut *lp.images.exe_image_catalog;
    let hosted_loaded_images = &mut *lp.images.hosted_loaded_images;
    let hosted_loaded_images_ptr = lp.images.hosted_loaded_images_ptr;
    let pe = lp.images.pe;
    let memory_context = lp.memory_context;
    // Redrive above can select a Receive child after this iteration already admitted an
    // unrelated delivery. Return that unexecuted Call to its owner and receive the child.
    if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
        && !ingress.as_ref().is_some_and(|admitted| {
            crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_is_current(
                admitted.binding(), REPLY_MAIN_SLOT.load(Ordering::Relaxed),
            )
        })
    {
        if ingress.is_some() {
            crate::spawn_hosts::shared_ingress::owner::runtime::defer_hosted_delivery(
                REPLY_MAIN_SLOT.load(Ordering::Relaxed), lp.msg.badge,
            ).expect("unexecuted unrelated Call retains its exact ingress owner");
        }
        let received = receive(
            &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        )?;
        (lp.msg.badge, lp.msg.mi, lp.msg.m0, lp.msg.m1, lp.msg.m2, lp.msg.m3) = received;
        return ControlFlow::Break(Turn::Next);
    }
    // Deferred work may retire a process/thread. Revalidate the complete binding before
    // selecting any role, LPC context, stack mirror or process memory state.
    let event_runtime = match (ingress, nt_handler.admit_hosted_thread_ingress(lp.msg.badge)) {
        (Some(admitted), Ok(current)) if admitted.binding() == current.binding() => current,
        _ => return ControlFlow::Break(lp.reject_hosted_ingress()),
    };
    // This is only a copied latency observation. The admitted runtime and
    // canonical thread lifetime must still agree before matching a prior Reply.
    if let Some(caller) = nt_handler.capture_provider_logical_caller(
        event_runtime.pi, event_runtime.tid, lp.msg.badge, event_runtime.tcb,
    ).filter(|caller| caller.process() == event_runtime.process) {
        let process_generation = match caller.process().generation {
            nt_user_host::process_identity::ProcessGeneration::Hosted(value)
            | nt_user_host::process_identity::ProcessGeneration::Temporary(value) => value,
        };
        crate::ingress_observation::authenticated_thread_ingress(
            nt_hosted_runtime::WaitLatencyThreadIdentity {
                process_index: caller.pi() as u64,
                process_generation,
                thread_id: u64::from(caller.thread().thread_id()),
                thread_generation: caller.thread().generation(),
                tcb: caller.tcb(),
            },
            monotonic_time_100ns(),
        );
    }
    // An ETHREAD can outlive its image/runtime attachment during exact process retirement.
    // Refuse that Call before selecting any scratch or mirror address from the old PI.
    let event_layout = match event_runtime.process.generation {
        nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =>
            hosted_process_runtime_for_exact(event_runtime.pi, generation),
        nt_user_host::process_identity::ProcessGeneration::Temporary(_) =>
            hosted_process_runtime_for_pi(event_runtime.pi),
    };
    if event_layout.is_none() { return ControlFlow::Break(lp.reject_hosted_ingress()) }
    if crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending() {
        let observed = crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_observation(
            event_runtime.binding(), REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        ).expect("selected Receive child owns its exact fault observation");
        assert!(receive_vspace::validate_current(&nt_handler, event_runtime.binding(), observed),
            "Receive child and held provider require exact distinct current VSpace objects");
        service_receive_child_fault(
            &mut nt_handler,
            observed.observation,
            event_runtime.binding(),
            procs[event_runtime.pi].pml4,
            procs[event_runtime.pi].scratch_base,
        )
        .expect("changed or uncertain Receive fault retains child Call and parent");
        thread_wait_state_clear_badge_running(&mut nt_handler, lp.msg.badge);
        lp.parks.wait_parked = wait_parked_owner_mask(&nt_handler);
        if procs[event_runtime.pi].faults == 0 { procs[event_runtime.pi].first = lp.msg.m1; }
        procs[event_runtime.pi].faults += 1;
        note_boot_progress(BootProgress::PageMappingPublished);
        win32k_glue::trace_receive_phase(
            b"fault-serviced",
            observed.parent,
            observed.child,
            observed.trace_owner,
        );
        // No attachment, process scratch, provider, timer or legacy fault policy runs here.
        // The canonical root pager revalidated the captured resident frame or stack guard.
        if root_queued_callback_exclusive_pending()
            && crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_pending()
            && !transfer_selected_queued_callback_ingress(&mut lp.ingress.root_queued_callback_turn)
        {
            lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
            lp.exit.stop_ssn = 0;
            lp.exit.record(b"queued-callback-child-transfer");
            return ControlFlow::Break(Turn::Exit);
        }
        let outcome = crate::executive_ingress::reply_receive(
            REPLY_MAIN_SLOT.load(Ordering::Relaxed), 0, 0, 0, 0, 0,
        );
        match outcome {
            crate::executive_ingress::ReceiveOutcome::OuterBoundary(boundary) => {
                lp.ingress.receive_boundary = Some(boundary);
                return ControlFlow::Break(Turn::Next);
            }
            crate::executive_ingress::ReceiveOutcome::RetainedFailure => {
                lp.exit.stop = nt_status::NtStatus::DEVICE_BUSY.raw() as u32 as u64;
                lp.exit.stop_ssn = 0;
                lp.exit.record(b"receive-child-ack-retained");
                return ControlFlow::Break(Turn::Exit);
            }
            crate::executive_ingress::ReceiveOutcome::Message(_) => panic!("Receive ACK requires exact settlement boundary"),
        }
    }
    lp.exit.iters += 1;
    // `iters` is diagnostic only. A real NT kernel does not stop a runnable hosted process set at a
    // historical boot-frontier count; quiesce is driven by wait/crash/stall predicates above.
    // Select the hosted process this fault/syscall came from (0 = smss, CSRSS_BADGE = csrss) and
    // LOAD its state into the working locals. pml4/scratch_base/img_end/pe are immutable per
    // process (shadow the params); faults/first/ntfaults/filled_pages are mutable (SAVED back
    // before every recv below).
    // The N-threads-per-process multiplex: SVC_LISTENER_BADGE is services' (pi 3) RPC listener
    // thread — same VSpace/image/pml4 as services' main thread, but a DIFFERENT stack + TEB. It's
    // resolved to pi 3 here; the per-thread stack mirror is switched below (is_svc_listener).
    let is_svc_listener = lp.msg.badge == SVC_LISTENER_BADGE;
    // BATCH 35: services' SCM per-connection RPC worker (pi 3, its OWN stack mirror/TEB) — the
    // N-threads multiplex generalized to a DYNAMICALLY-spawned worker (not a pre-created pool
    // listener). It reads winlogon's bind PDU + writes bind_ack; resolved to pi 3 like the listener.
    let is_lsass_listener = lp.msg.badge == LSASS_LISTENER_BADGE;
    let is_lsass_listener2 = lp.msg.badge == LSASS_LISTENER2_BADGE;
    let is_lsass_listener3 = lp.msg.badge == LSASS_LISTENER3_BADGE;
    // Generic workers have one badge per process and slot. The first five processes keep the
    // legacy dense range for slot 0 (16..20) and slot 1 (21..25); extra slots and later hosted
    // processes use the aux range decoded by tp_worker_identity_from_badge. The role is
    // orthogonal to listener recognizers: it shares process state and mirrors, but not
    // RPC-listener-specific parking or quiesce policy.
    let hosted_thread_role = Some(event_runtime.role);
    let tp_worker_identity = tp_worker_identity_from_badge(lp.msg.badge);
    let is_tp_worker = tp_worker_identity.is_some();
    let is_scm_worker = hosted_thread_role.is_some_and(|role| role.is_scm_rpc_worker());
    let is_lsa_worker = hosted_thread_role.is_some_and(|role| role.is_lsa_rpc_worker());
    let is_lsa_auth_server = lpc_client()
        .and_then(|client| {
            client
                .query_handle(nt_handler.hosted_thread_lpc_server_port(lp.msg.badge))
                .ok()
        })
        .is_some_and(|port| lpc_name_is(&port.name, b"\\LsaAuthenticationPort"));
    // winlogon's rpcrt4 server WORKER thread (pi 2, its own stack mirror/TEB) — same N-threads
    // multiplex. It runs the wait array (NtWaitForMultipleObjects → parks) that the main thread's
    // signal_state_changed wakes, completing the rpcrt4 server-thread handshake.
    let is_wl_worker = matches!(
        lp.msg.badge,
        WINLOGON_WORKER_BADGE | WINLOGON_WORKER2_BADGE | WINLOGON_WORKER3_BADGE
    );
    if is_wl_worker {
        let n = WL_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
        if n < 8 {
            print_str(b"[wl-worker] multiplex event #");
            print_u64(n);
            print_str(b" label=0x");
            print_hex((lp.msg.mi >> 12) as u32);
            print_str(b" m1=0x");
            print_hex(lp.msg.m1 as u32);
            print_str(b" (N-threads sub-select: pi 2 rpcrt4 worker)\n");
        }
    }
    if is_svc_listener {
        let n = SVC_LISTENER_FAULTS.fetch_add(1, Ordering::Relaxed);
        if n < 4 {
            print_str(b"[svc-listener] multiplex event #");
            print_u64(n);
            print_str(b" label=0x");
            print_hex((lp.msg.mi >> 12) as u32);
            print_str(b" m1=0x");
            print_hex(lp.msg.m1 as u32);
            print_str(b" (N-threads sub-select: pi 3 listener)\n");
        }
    }
    if is_scm_worker {
        let n = SCM_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
        if n < 8 {
            print_str(b"[scm-worker] multiplex event #");
            print_u64(n);
            print_str(b" label=0x");
            print_hex((lp.msg.mi >> 12) as u32);
            print_str(b" m1=0x");
            print_hex(lp.msg.m1 as u32);
            print_str(b" (N-threads sub-select: pi 3 per-connection worker)\n");
        }
    }
    if is_lsa_worker {
        let n = LSA_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
        if n < 8 {
            print_str(b"[lsa-worker] multiplex event #");
            print_u64(n);
            print_str(b" label=0x");
            print_hex((lp.msg.mi >> 12) as u32);
            print_str(b" m1=0x");
            print_hex(lp.msg.m1 as u32);
            print_str(b" (N-threads sub-select: pi 4 per-connection worker)\n");
        }
    }
    if is_tp_worker && !is_scm_worker && !is_lsa_worker {
        let n = GENERIC_TP_WORKER_FAULT_TRACE.fetch_add(1, Ordering::Relaxed);
        if DEBUG_TRACE && n < 64 {
            print_str(b"[tp-worker-event] #");
            print_u64(n);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            if let Some((tp_pi, tp_slot)) = tp_worker_identity {
                print_str(b" pi=");
                print_u64(tp_pi as u64);
                print_str(b" slot=");
                print_u64(tp_slot as u64);
            }
            print_str(b" label=0x");
            print_hex((lp.msg.mi >> 12) as u32);
            print_str(b" m1=0x");
            print_hex(lp.msg.m1 as u32);
            print_str(b"\n");
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
            print_hex((lp.msg.mi >> 12) as u32);
            print_str(b" m1=0x");
            print_hex(lp.msg.m1 as u32);
            print_str(b" (N-threads sub-select: pi 4 listener)\n");
        }
    }
    let pi = event_runtime.pi;
    // This thread is producing an event, so it is runnable even if the owning process still has
    // other parked threads. The owner mask is derived from all live hosted threads below.
    thread_wait_state_clear_badge_running(&mut nt_handler, lp.msg.badge);
    lp.parks.wait_parked = wait_parked_owner_mask(&nt_handler);
    if hosted_main_badge_has_role(
        &nt_handler,
        lp.msg.badge,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) {
        WINLOGON_MAIN_EVENT_WAIT_PARKED.store(0, Ordering::Relaxed);
    }
    if PM_TERMINATE_THREAD_NO_REPLY.load(Ordering::Relaxed) != 0 && lp.msg.badge < 64 {
        PM_POST_TERM_CONTINUED_BADGES.fetch_or(1u64 << lp.msg.badge, Ordering::Relaxed);
    }
    // LOUD overflow guard: `pi` still indexes the core process/fault scratch slices
    // (`procs` / `pfilled`, sized to MAX_PI). Dynamic hosted processes are admitted through the
    // catalog/runtime tables; if one ever exceeds this remaining executive ceiling this panics
    // with a clear file:line instead of indexing outside the admitted process window.
    assert!(
        pi < MAX_PI,
        "hosted process pi exceeds MAX_PI - raise the runtime ceiling"
    );
    let event_current_tid = event_runtime.tid;
    nt_handler.pi = pi;
    nt_handler.current_badge = lp.msg.badge;
    nt_handler.current_tid = event_current_tid;
    match lp.msg.mi >> 12 {
        2 => {
            nt_handler.current_resume_ip = lp.msg.m2;
            nt_handler.current_sp = get_recv_mr(16);
            nt_handler.current_flags = get_recv_mr(17);
        }
        3 => {
            nt_handler.current_resume_ip = lp.msg.m0;
            nt_handler.current_sp = lp.msg.m1;
            nt_handler.current_flags = lp.msg.m2;
        }
        6 => {
            nt_handler.current_resume_ip = lp.msg.m0;
            nt_handler.current_sp = 0;
            nt_handler.current_flags = 0;
        }
        label if label == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL => {
            nt_handler.current_resume_ip = 0;
            nt_handler.current_sp = lp.msg.m1;
            nt_handler.current_flags = 0;
        }
        _ => {
            nt_handler.current_resume_ip = 0;
            nt_handler.current_sp = 0;
            nt_handler.current_flags = 0;
        }
    }
    // Resolve this fault badge to its real EPROCESS via the handler-owned ProcessManager lookup.
    // Read-only (no alloc under the reset), it proves the live badge-multiplex is backed by real
    // nt-process objects. The per-pi arrays below still carry the load-bearing mechanism state;
    // the bulk migrates that onto the EPROCESS next (see the convergence report).
    if let Some(pid) = nt_handler.pm_pid_for_pi(pi) {
        if nt_handler.pm.process(pid).is_some() {
            PM_BADGE_LOOKUPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    let pml4 = procs[pi].pml4;
    let scratch_base = procs[pi].scratch_base;
    crate::executor::local().client_pi.store(pi as u64, Ordering::Relaxed);
    crate::executor::local().scratch_base.store(scratch_base, Ordering::Relaxed);
    let img_end = procs[pi].img_end;
    let img_base = procs[pi].img_base;
    let event_image_target = nt_exe_image::SpawnTarget::from_image(
        exe_image_catalog.get_by_pi(pi).expect("event retains its exact executable identity"),
    );
    let _event_image_reader = {
        let _durable = allocator::enter_durable();
        unsafe { crate::hosted_loaded_images::HostedImageReadScope::capture(
            hosted_loaded_images_ptr, event_image_target,
        ) }
    }.expect("event must retain its parsed executable before dispatch");
    let pe: &nt_pe_loader::PeFile = if pi == primary_pi {
        pe
    } else {
        unsafe { hosted_loaded_images.pe_by_pi(pi) }
            .expect("faulting hosted process must have a registered loaded executable PE")
    };
    lp.exit.faults = procs[pi].faults;
    lp.exit.first = procs[pi].first;
    lp.exit.ntfaults = procs[pi].ntfaults;
    *filled_pages = pfilled[pi];
    let memory_generation = exe_image_catalog.get_by_pi(pi)
        .expect("event process retains its executable identity").generation;
    let memory_pid = nt_handler.capture_process_identity(pi)
        .expect("event process retains its mechanism identity").pid;
    nt_handler.loop_ctx = Some(ExecLoopCtx {
        owner_pi: pi,
        owner_pid: memory_pid,
        owner_generation: memory_generation,
        live_paging: Some(LiveProcessPaging {
            pi,
            pid: memory_pid,
            pml4,
            generation: memory_generation,
            filled_pages: filled_pages as *mut [u64; 512],
            faults: &mut lp.exit.faults as *mut u64,
        }),
        pml4,
        filled_pages: filled_pages as *mut [u64; 512],
        faults: &mut lp.exit.faults as *mut u64,
        scratch_base,
        img_end,
        img_base,
        ..memory_context
    });
    let ev = Event {
        event_runtime, is_svc_listener, is_lsass_listener, is_lsass_listener2,
        is_lsass_listener3, is_tp_worker, is_scm_worker, is_lsa_worker, is_lsa_auth_server,
        is_wl_worker, pi, native_ingress_request, scratch_base, pml4, hosted_thread_role, pe,
        img_end, img_base, _event_image_reader,
    };
    ControlFlow::Continue(ev)
}
