//! Executing a process termination decided during a turn (#285). A syscall's post action and
//! an exception no handler could take end the same way: the process's mechanisms are torn
//! down, the caller's fault Reply is dropped, and the loop receives the next message.

use super::loop_receive::receive;
use super::*;
use crate::executor::local;

/// Tear down process `process_index` after the process manager terminated it. With
/// `drop_reply`, the calling thread `current_tid` (bound to `tcb`) is the one terminating:
/// its Reply is dropped, the thread deleted, and the next message received into `msg`
/// (`true`). Otherwise the caller still gets an ordinary reply (`false`).
pub(super) unsafe fn terminate_process_turn(
    nt_handler: &mut ExecNtHandler,
    ingress: &mut Ingress,
    exit: &mut LoopExit,
    msg: &mut Message,
    tcb: u64,
    process_index: u8,
    current_tid: u64,
    drop_reply: bool,
    apc_owned_reply: bool,
) -> ControlFlow<Turn, bool> {
    let delay_queue = ingress.delay_queue;
    if drop_reply {
        assert_eq!(tcb_suspend_r(tcb), 0,
            "process self termination must stop before Reply cancellation");
    }
    let preserve_tid = if current_tid != 0 {
        Some(current_tid)
    } else {
        None
    };
    let reply_dropped = if drop_reply && !apc_owned_reply {
        drop_current_hosted_reply()
    } else {
        false
    };
    observe_process_terminal(nt_handler, process_index);
    let reclaimed = terminate_hosted_process_mechanisms(
        process_index,
        preserve_tid,
        &mut *delay_queue,
        nt_handler,
    );
    let current_deleted = if drop_reply && current_tid != 0 {
        terminate_hosted_thread_mechanism(
            current_tid,
            &mut *delay_queue,
            nt_handler,
        )
    } else {
        false
    };
    let final_process_teardown = drop_reply || current_tid == 0;
    if final_process_teardown {
        if let Some(pid) = nt_handler.pm_pid_for_pi(process_index as usize) {
            let _ = nt_handler.try_delete_hosted_process_object(pid);
        }
    }
    nt_handler.refresh_process_manager_gates();
    if drop_reply && reply_dropped && current_deleted {
        PM_TERMINATE_PROCESS_NO_REPLY.fetch_add(1, Ordering::Relaxed);
        if process_index < 64 {
            PM_TERMINATE_PROCESS_NO_REPLY_PIS
                .fetch_or(1u64 << process_index, Ordering::Relaxed);
        }
    }
    print_str(b"[process-term] pi=");
    print_u64(process_index as u64);
    print_str(b" current_tid=");
    print_u64(current_tid);
    print_str(b" drop_reply=");
    print_u64(drop_reply as u64);
    print_str(b" reply-dropped=");
    print_u64(reply_dropped as u64);
    print_str(b" apc-owned=");
    print_u64(apc_owned_reply as u64);
    print_str(b" reclaimed=");
    print_u64(reclaimed as u64);
    print_str(b" current-deleted=");
    print_u64(current_deleted as u64);
    print_str(b" runtimes-pending=");
    print_u64(
        nt_handler
            .thread_runtime
            .has_process(process_index as usize)
            as u64,
    );
    print_str(b"\n");
    if !drop_reply {
        return ControlFlow::Continue(false);
    }
    let _ = finalize_service_loop_state(nt_handler);
    let new_reply = local().reply_main_slot.load(Ordering::Relaxed);
    let fault_ep = ingress.fault_ep;
    let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
        ingress, nt_handler, exit, fault_ep, || new_reply,
    )?;
    msg.badge = nb;
    msg.mi = nmi;
    msg.m0 = nm0;
    msg.m1 = nm1;
    msg.m2 = nm2;
    msg.m3 = nm3;
    ControlFlow::Continue(true)
}

/// A critical process terminated: drop the caller's Reply and stop with the bugcheck `code`.
pub(super) unsafe fn critical_termination_turn<T>(
    exit: &mut LoopExit,
    tcb: u64,
    pi: usize,
    code: u32,
    object: u64,
    apc_owned_reply: bool,
) -> ControlFlow<Turn, T> {
    assert_eq!(tcb_suspend_r(tcb), 0,
        "critical termination must stop before Reply cancellation");
    let reply_dropped = !apc_owned_reply && drop_current_hosted_reply();
    // A critical process can bugcheck while it is running a win32k user-mode
    // callback; unwind those continuations so win32k is idle (not stranded in its
    // callback receive loop) for the gate. No-op when it held none.
    let _ = win32k_glue::unwind_dead_client_user_callbacks(pi as u32);
    print_str(b"[critical-termination] bugcheck=0x");
    print_hex(code);
    print_str(b" object=0x");
    print_hex((object >> 32) as u32);
    print_hex(object as u32);
    print_str(b" reply-dropped=");
    print_u64(reply_dropped as u64);
    print_str(b" -> fatal stop\n");
    exit.stop = code as u64;
    exit.record(b"fatal-stop");
    ControlFlow::Break(Turn::Exit)
}

/// A terminated process's exit status is observable before its mechanisms are reclaimed.
fn observe_process_terminal(nt_handler: &mut ExecNtHandler, process_index: u8) {
    if let Some(pid) = nt_handler.pm_pid_for_pi(process_index as usize) {
        if nt_handler.pm.is_process_signaled(pid) {
            if let Some(status) = nt_handler.pm.process(pid)
                .and_then(|process| process.exit_status) {
                let _ = nt_handler.observe_install_pipe_child_terminal(
                    process_index as usize, status,
                );
            }
        }
    }
}

/// The remote-termination half of `terminate_process_turn` (no caller thread to preserve and
/// no Reply to drop), for a termination decided outside a syscall turn.
pub(crate) unsafe fn teardown_remote_process(
    nt_handler: &mut ExecNtHandler,
    delay_queue: &mut nt_delay_execution::Queue,
    process_index: u8,
) {
    observe_process_terminal(nt_handler, process_index);
    let reclaimed = terminate_hosted_process_mechanisms(process_index, None, delay_queue, nt_handler);
    if let Some(pid) = nt_handler.pm_pid_for_pi(process_index as usize) {
        let _ = nt_handler.try_delete_hosted_process_object(pid);
    }
    nt_handler.refresh_process_manager_gates();
    print_str(b"[process-term] remote pi=");
    print_u64(process_index as u64);
    print_str(b" reclaimed=");
    print_u64(reclaimed as u64);
    print_str(b" runtimes-pending=");
    print_u64(nt_handler.thread_runtime.has_process(process_index as usize) as u64);
    print_str(b"\n");
}
