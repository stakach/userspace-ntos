//! The loop's side of user exception delivery (#285): hand a fault to the thread's own
//! handlers, or end the process when no frame can be written for them.

use super::loop_flow::{dbgk_block_and_park, dbgk_forward_exception};
use super::loop_process_termination::{critical_termination_turn, terminate_process_turn};
use super::loop_receive::receive;
use super::*;
use crate::executor::local;
use crate::user_exception_delivery::NotDelivered;

/// Hand `fault`, raised at `ip` by the thread behind `msg` (bound to `tcb`), to that thread's
/// own handlers through ntdll!KiUserExceptionDispatcher, as KiDispatchExceptionToUser does. A
/// handled exception resumes through NtContinue; an unhandled one returns as NtRaiseException
/// with FirstChance = FALSE, which terminates the process with the exception code. When the
/// frame cannot be written to the thread's stack, the process terminates here instead.
///
/// `true`: the turn is over and the next message was received into `msg`. `false`: the fault
/// Call is untouched for the caller's own handling.
pub(super) unsafe fn deliver_to_user(
    exit: &mut LoopExit,
    ingress: &mut Ingress,
    nt_handler: &mut ExecNtHandler,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
    filled_pages: &[u64; 512],
    pi: usize,
    tcb: u64,
    fault: nt_thread_start::user_exception::HardwareFault,
    ip: u64,
    ntdll: (u64, &nt_pe_loader::PeFile<'_>),
    msg: &mut Message,
) -> ControlFlow<Turn, bool> {
    let reply = local().reply_main_slot.load(Ordering::Relaxed);
    let code = match crate::user_exception_delivery::deliver_user_exception(
        nt_handler, pi, msg.badge, fault, ip, reply, ntdll,
    ) {
        Ok(code) => code,
        Err(reason) => {
            print_str(b"[user-exception] not delivered pi=");
            print_u64(pi as u64);
            print_str(b" badge=");
            print_u64(msg.badge);
            print_str(b" ip=0x");
            print_hex_u64(ip);
            print_str(b" reason=");
            print_str(reason.label());
            print_str(b"\n");
            return match reason {
                NotDelivered::Unwritable(unwritable) => terminate_for_unwritable_frame(
                    exit, ingress, nt_handler, msg, pi, tcb, unwritable,
                ),
                _ => ControlFlow::Continue(false),
            };
        }
    };
    if crate::user_exception_delivery::trace_delivery() {
        print_str(b"[user-exception] delivered pi=");
        print_u64(pi as u64);
        print_str(b" badge=");
        print_u64(msg.badge);
        print_str(b" code=0x");
        print_hex(code);
        print_str(b" ip=0x");
        print_hex_u64(ip);
        print_str(b"\n");
    }
    procs[pi].faults = exit.faults;
    procs[pi].first = exit.first;
    procs[pi].ntfaults = exit.ntfaults;
    pfilled[pi] = *filled_pages;
    let _ = finalize_service_loop_state(nt_handler);
    let fault_ep = ingress.fault_ep;
    let (nb, nmi, nm0, nm1, nm2, nm3) = receive(
        ingress, nt_handler, exit, fault_ep, || local().reply_main_slot.load(Ordering::Relaxed),
    )?;
    msg.badge = nb;
    msg.mi = nmi;
    msg.m0 = nm0;
    msg.m1 = nm1;
    msg.m2 = nm2;
    msg.m3 = nm3;
    ControlFlow::Continue(true)
}

/// KiDispatchException's path when the user frame cannot be pushed: the exception can never
/// reach a handler, so the process terminates with its code (a critical one bugchecks).
/// A debugged process would first see a second chance; that report is not forwarded here.
unsafe fn terminate_for_unwritable_frame(
    exit: &mut LoopExit,
    ingress: &mut Ingress,
    nt_handler: &mut ExecNtHandler,
    msg: &mut Message,
    pi: usize,
    tcb: u64,
    unwritable: crate::user_exception_delivery::Unwritable,
) -> ControlFlow<Turn, bool> {
    nt_handler.post_action = ExecPostAction::None;
    let status = nt_handler.terminate_process_for_exception(pi, unwritable.tid, unwritable.code);
    match core::mem::replace(&mut nt_handler.post_action, ExecPostAction::None) {
        ExecPostAction::TerminateProcess { process_index, current_tid, drop_reply } => {
            terminate_process_turn(
                nt_handler, ingress, exit, msg, tcb, process_index, current_tid, drop_reply, false,
            )
        }
        ExecPostAction::CriticalTermination { code, object } => {
            critical_termination_turn(exit, tcb, pi, code, object, false)
        }
        _ => {
            print_str(b"[user-exception] termination failed status=0x");
            print_hex(status);
            print_str(b"\n");
            ControlFlow::Continue(false)
        }
    }
}

/// KiDispatchException's first chance for a fault the arm has not yet reported: a debugger of
/// the process sees it first (blocking the thread on its continue), then the thread's own
/// handlers. Returns as `deliver_to_user` does; `true` also covers the debugger block.
pub(super) unsafe fn dispatch_first_chance(
    exit: &mut LoopExit,
    parks: &mut Parks,
    ingress: &mut Ingress,
    nt_handler: &mut ExecNtHandler,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
    filled_pages: &[u64; 512],
    pi: usize,
    tcb: u64,
    fault: nt_thread_start::user_exception::HardwareFault,
    ip: u64,
    debug_block_kind: u8,
    ntdll: (u64, &nt_pe_loader::PeFile<'_>),
    msg: &mut Message,
) -> ControlFlow<Turn, bool> {
    let record = crate::user_exception_delivery::debug_record(fault, ip);
    if dbgk_forward_exception(nt_handler, pi, record)
        && dbgk_block_and_park(
            exit, parks, ingress, nt_handler, procs, pfilled, filled_pages, pi,
            debug_block_kind, ip, 0, 0, msg,
        )?
    {
        return ControlFlow::Continue(true);
    }
    deliver_to_user(
        exit, ingress, nt_handler, procs, pfilled, filled_pages, pi, tcb, fault, ip, ntdll, msg,
    )
}
