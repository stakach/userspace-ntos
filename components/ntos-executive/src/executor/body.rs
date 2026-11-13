//! One turn of the service loop (issue #382, loop hoist).
//!
//! `service_sec_image()` sets the executive up, runs `turn` until it ends the loop and then
//! reports. A turn is between-event maintenance, admission of one event and the arm for
//! that event's label; every arm ends the turn by replying or parking and receiving the
//! next event into `lp.msg`.

use super::*;

/// One turn. `Continue` asks for the next turn; `Break` ends the service loop, with the
/// reason recorded in `lp.exit`.
pub(super) unsafe fn turn(lp: &mut LoopState<'_>) -> ControlFlow<()> {
    match serve(lp) {
        ControlFlow::Break(Turn::Next) => ControlFlow::Continue(()),
        ControlFlow::Break(Turn::Exit) => ControlFlow::Break(()),
    }
}

unsafe fn serve(lp: &mut LoopState<'_>) -> ControlFlow<Turn, core::convert::Infallible> {
    let (ingress, native_ingress_request) = loop_maintenance::maintain(lp)?;
    let ev = loop_admission::admit(lp, ingress, native_ingress_request)?;
    // A CPU exception (label 3). The DEBUG ntdll emits `int 0x2d` (DebugService/DPRINT),
    // which #GPs with no kernel debugger; emulate it as a no-op by skipping past the
    // `int 0x2d; int3` pair (echo the registers, advance the fault IP by 3, restart).
    if (lp.msg.mi >> 12) == 3 {
        return loop_exceptions::cpu_exception(lp, &ev);
    }
    // DebugException (label 4 = seL4's #DB/#BP bucket). The microkernel payload is
    // m0=FaultIP, m1=ExceptionReason, m2=TriggerAddress, m3=BreakpointNumber. OUR ntdll's
    // `RtlRaiseException` / `RtlRaiseStatus` seams issue int3, so software-break requests also
    // decode WHAT exception the caller is raising: recover winlogon's full GPRs (RCX =
    // PEXCEPTION_RECORD arg, RSP), read the EXCEPTION_RECORD from its demand-faulted memory, and
    // walk the stack for the raise site.
    if (lp.msg.mi >> 12) == 4 {
        return loop_exceptions::debug_exception(lp, &ev);
    }
    if (lp.msg.mi >> 12) == 6 {
        return loop_vm_fault::vm_fault(lp, &ev);
    }
    // ntdll_plan Step 6.A — NATIVE seL4-Call transport. OUR ntdll (native-transport smss) does a
    // real seL4 `Call(CT_FAULT)` instead of a Windows-`syscall` UnknownSyscall trap. The request
    // carries MR0=SSN, MR1=caller RSP, and the complete argument vector in MR2 onward. We
    // NORMALIZE it into the fault-frame register slots the `(mi>>12)==2` arm reads, then re-label
    // the message as UnknownSyscall (2) so it flows through that arm's FULL servicing body
    // unchanged (dispatch + out-writes + spawn/park/delay post-actions). The reply is a NORMAL IPC
    // reply (the native caller has NO pending fault): `component_reply_recv!(..,result,..)` fans
    // result→MR0→the caller's r10, which our native stub reads as NTSTATUS.
    let native_call_transport = (lp.msg.mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL;
    if native_call_transport {
        loop_native_call::native_call(lp, &ev)?;
    }
    if (lp.msg.mi >> 12) == 2 {
        return loop_syscall::syscall(lp, &ev, native_call_transport);
    }
    // A non-VMFault, non-syscall fault (e.g. #GP) the loop can't service — unrecoverable. Park+log.
    ControlFlow::Break(lp.park_and_log(ev.pi, b"other-fault", lp.msg.m1, lp.msg.m1))
}
