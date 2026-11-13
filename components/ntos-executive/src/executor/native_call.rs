//! The native-call transport arm of the service loop (issue #382, loop hoist).
//!
//! A hosted thread that entered through the native syscall transport: its request is
//! validated here before the syscall arm dispatches it.
//!
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::*;

#[inline(never)]
pub(super) unsafe fn native_call(
    lp: &mut LoopState<'_>,
    ev: &Event,
) -> ControlFlow<Turn> {
    let nt_handler = &mut *lp.handler;
    let Event {
        is_svc_listener, is_lsass_listener, is_lsass_listener2, is_lsass_listener3, is_scm_worker,
        is_lsa_worker, pi, native_ingress_request, hosted_thread_role, ..
    } = *ev;
    let request = native_ingress_request
        .expect("native ingress lost its owned argument words");
    const NATIVE_TAIL_STAGE_MR: usize = 32;
    let ssn = lp.msg.m0; // MR0
    let rsp = lp.msg.m1; // MR1 = caller rsp (diagnostics and stack-resident pointer validation)
    let arg1 = lp.msg.m2; // MR2
    let arg2 = lp.msg.m3; // MR3
    let arg3 = request.word(4).unwrap_or(0); // MR4 (owned receive)
    let arg4 = request.word(5).unwrap_or(0); // MR5 (owned receive)
    let request_len = (lp.msg.mi & 0x7f) as usize;
    for request_mr in 6..request_len.min(nt_syscall_abi::NT_NATIVE_REQUEST_WORDS) {
        set_recv_mr(
            NATIVE_TAIL_STAGE_MR + request_mr - 6,
            request.word(request_mr).expect("captured native request lost a word"),
        );
    }
    // Stage the fault-frame register slots the `==2` arm reads: R10@9=arg1, R8@7=arg3,
    // R9@8=arg4, SP@16=rsp, FLAGS@17=0. (arg2 is read directly from `m3`.)
    set_recv_mr(9, arg1);
    set_recv_mr(7, arg3);
    set_recv_mr(8, arg4);
    set_recv_mr(16, rsp);
    set_recv_mr(17, 0);
    // m0 stays = SSN; m2 becomes resume_ip (unused for a native reply — no fault restart).
    lp.msg.m0 = ssn;
    lp.msg.m2 = 0;
    // Re-label as UnknownSyscall so the shared servicing arm below runs.
    lp.msg.mi = (2u64 << 12) | (lp.msg.mi & 0x7F);
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
        let slot_trace = hosted_thread_role.and_then(|role| match role {
            HostedThreadRole::ScmWorkerSlot { slot } if slot < TP_WORKER_SLOT_COUNT => {
                Some((
                    slot,
                    SCM_WORKER_SLOT_SSN_TRACE[slot].fetch_add(1, Ordering::Relaxed),
                ))
            }
            _ => None,
        });
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
        if let Some((slot, slot_dn)) = slot_trace {
            if slot_dn < 32 {
                print_str(b"[scm-worker-slot-ssn] slot=");
                print_u64(slot as u64);
                print_str(b" #");
                print_u64(slot_dn);
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
    // LSA-RPC DIAG: trace lsass' `\pipe\lsarpc` rpcrt4 SERVER thread's native SSNs so the
    // boot log shows exactly what it does when a client connect completes its listen
    // (re-listen instance create → `RPCRT4_new_client` → `CreateThread`) and where it walls.
    // SPIN DIAGNOSTIC: a hosted thread that loops on an un-traced syscall makes the boot look
    // hung (the executive is just servicing it as fast as it can, with no log line). Print a
    // heartbeat every 8192 native syscalls with the badge + current SSN so any such loop is
    // immediately visible and attributable. Costs one increment per syscall.
    {
        let n = NATIVE_SYSCALL_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
        if n % 8192 == 8191 {
            print_str(b"[ssn-heartbeat] total=");
            print_u64(n + 1);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" ssn=");
            print_u64(ssn);
            print_str(b"\n");
        }
    }
    let trace_process_role = nt_handler.hosted_process_observation_role(pi);
    let trace_is_lsass =
        trace_process_role == Some(nt_exe_image::HostedProcessRole::LocalSecurityAuthority);
    // FORWARD-PROGRESS CENSUS: per-SSN histogram for hosted system processes at the current
    // boot frontier. A poll/retry livelock is unmistakable here.
    if trace_is_lsass
        || matches!(
            trace_process_role,
            Some(
                nt_exe_image::HostedProcessRole::ServiceControlManager
                    | nt_exe_image::HostedProcessRole::Win32Subsystem
                    | nt_exe_image::HostedProcessRole::InteractiveLogon
                    | nt_exe_image::HostedProcessRole::InteractiveShell
            )
        )
    {
        let bucket = ssn_bucket(ssn);
        match trace_process_role {
            _ if trace_is_lsass => LSASS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
            Some(nt_exe_image::HostedProcessRole::ServiceControlManager) => {
                SERVICES_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed)
            }
            Some(nt_exe_image::HostedProcessRole::InteractiveLogon) => {
                WINLOGON_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed)
            }
            Some(nt_exe_image::HostedProcessRole::Win32Subsystem) => {
                CSRSS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed)
            }
            Some(nt_exe_image::HostedProcessRole::InteractiveShell) => {
                EXPLORER_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed)
            }
            _ => 0,
        };
        if trace_process_role == Some(nt_exe_image::HostedProcessRole::Win32Subsystem) {
            crate::csrss_thread_probe::record_syscall(ssn);
        }
    }
    if is_lsa_worker {
        LSA_WORKER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
    }
    if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 {
        let (counter, tag) = if is_lsass_listener3 {
            (
                &LSASS_LISTENER3_NATIVE_SSN_TRACE,
                b"[lsass-listener3-ssn] #" as &[u8],
            )
        } else if is_lsass_listener2 {
            (
                &LSASS_LISTENER2_SSN_TRACE,
                b"[lsass-listener2-ssn] #" as &[u8],
            )
        } else {
            (
                &LSASS_LISTENER_SSN_TRACE,
                b"[lsass-listener-ssn] #" as &[u8],
            )
        };
        let dn = counter.fetch_add(1, Ordering::Relaxed);
        if dn < 48 {
            print_str(tag);
            print_u64(dn);
            print_str(b" badge=");
            print_u64(lp.msg.badge);
            print_str(b" ssn=");
            print_u64(ssn);
            print_str(b" arg1=0x");
            print_hex(arg1 as u32);
            print_str(b" arg2=0x");
            print_hex(arg2 as u32);
            print_str(b"\n");
        }
        if is_lsass_listener3 {
            let dn = LSA_LISTENER3_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
            if dn < 40 {
                print_str(b"[lsa-srv-ssn] #");
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
    ControlFlow::Continue(())
}
