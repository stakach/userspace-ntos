//! The CPU and debug exception arms of the service loop (issue #382, loop hoist).
//!
//! Label 3 is a CPU exception of a hosted thread, label 4 a debug exception.
//!
//! The text is the loop's, moved verbatim: an exit from the service loop is now a
//! `Break(Turn::Exit)`, the end of a turn a `Break(Turn::Next)`, and the flow macros are
//! direct calls.

use super::loop_flow::*;
use super::loop_receive::{receive, reply_receive};
use super::*;

#[inline(never)]
pub(super) unsafe fn cpu_exception(
    lp: &mut LoopState<'_>,
    ev: &Event,
) -> ControlFlow<Turn, core::convert::Infallible> {
    let nt_handler = &mut *lp.handler;
    let fault_ep = lp.ingress.fault_ep;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let ntdll = lp.images.ntdll;
    let Event { event_runtime, pi, scratch_base, .. } = *ev;
    // UserException delivery: m0=FaultIP, m1=SP, m2=FLAGS, m3=Number, mr4=Code. The
    // reply sets IP/SP/FLAGS (length 3); the general registers are preserved.
    let fip = lp.msg.m0;
    let mut skipped = false;
    {
        let (nb, npe) = ntdll;
        if fip >= nb && fip < nb + image_extent(npe) {
            if pe_byte_at_rva(npe, (fip - nb) as u32) == Some(0xCD) {
                // Skip `int 0x2d; int3` (3 bytes) — the no-op DebugService.
                procs[pi].faults = lp.exit.faults;
                procs[pi].first = lp.exit.first;
                procs[pi].ntfaults = lp.exit.ntfaults;
                pfilled[pi] = *filled_pages;
                let (nb, nmi, nm0, nm1, nm2, nm3) =
                    reply_receive(
                        &mut lp.ingress, nt_handler, &mut lp.exit, fault_ep, || (REPLY_MAIN_SLOT.load(Ordering::Relaxed), 3, fip + 3, lp.msg.m1, lp.msg.m2, 0),
                    )?;
                lp.msg.badge = nb;
                lp.msg.mi = nmi;
                lp.msg.m0 = nm0;
                lp.msg.m1 = nm1;
                lp.msg.m2 = nm2;
                lp.msg.m3 = nm3;
                skipped = true;
                lp.exit.dbgsvc += 1;
            }
        }
    }
    if skipped {
        return ControlFlow::Break(Turn::Next);
    }
    // DbgkForwardException: a debugged process's debugger sees the trap first (m3 is the
    // delivered exception NUMBER — the x86 vector — which maps to the NTSTATUS
    // `KiDispatchException` would report). No-op when nothing debugs this process.
    if dbgk_forward_exception(nt_handler, pi, nt_process::dbgk::ExceptionRecord::new( nt_process::dbgk::exception_code_for_trap(lp.msg.m3 as u32), fip, )) && dbgk_block_and_park(
        &mut lp.exit, &mut lp.parks, &mut lp.ingress, nt_handler, procs, pfilled,
        filled_pages, pi, nt_process::dbgk::DBGK_BLOCK_USER_EXCEPTION, fip, lp.msg.m1, lp.msg.m2, &mut lp.msg,
    )? {
        // The faulting thread is BLOCKED on the debugger's continue; its reply capability is
        // held by the DEBUG_EVENT. The next event has already been received.
        return ControlFlow::Break(Turn::Next);
    }
    // ★ POST-LOGON CPU-EXCEPTION DIAGNOSTIC (bounded to the first 4). A label-3 fault
    // reports only IP/SP/FLAGS/vector/code, which is not enough to tell a bad POINTER from a
    // bad TARGET. Recover the faulting thread's GPRs, the stack's return-address chain and —
    // when the fault IP is inside our `RtlEnterCriticalSection` — the 40-byte
    // `RTL_CRITICAL_SECTION` the caller handed us, so the wall is MEASURED, not attributed.
    if hosted_pi_has_role(
        &nt_handler,
        pi,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) && hosted_owner_has_role(
        &nt_handler,
        lp.msg.badge,
        nt_exe_image::HostedProcessRole::InteractiveLogon,
    ) && crate::WL_CPUEXC_DIAG_N.fetch_add(1, Ordering::Relaxed) < 4
    {
        let tcb = event_runtime.tcb;
        let mut regs = [0u64; 20];
        if tcb != 0 {
            crate::win32k_glue::tcb_read_regs20(tcb, &mut regs);
        }
        let (rip, rsp, rax, rcx, rdx) = (regs[0], regs[1], regs[3], regs[5], regs[6]);
        let ntdll_base = ntdll.0;
        print_str(b"[cs-diag] label=3 exc#=");
        print_u64(lp.msg.m3);
        print_str(b" code=0x");
        print_hex(get_recv_mr(4) as u32);
        print_str(b" fip=n+0x");
        print_hex(fip.wrapping_sub(ntdll_base) as u32);
        print_str(b" rip=n+0x");
        print_hex(rip.wrapping_sub(ntdll_base) as u32);
        print_str(b" rsp=0x");
        print_hex((rsp >> 32) as u32);
        print_hex(rsp as u32);
        print_str(b" rax=0x");
        print_hex((rax >> 32) as u32);
        print_hex(rax as u32);
        print_str(b" rcx=0x");
        print_hex((rcx >> 32) as u32);
        print_hex(rcx as u32);
        print_str(b" rdx=0x");
        print_hex((rdx >> 32) as u32);
        print_hex(rdx as u32);
        // Canonical-address test: a #GP(0) on a memory operand in long mode is what a
        // NON-canonical effective address produces (a merely unmapped/RO page is a #PF).
        let canonical = {
            let top = rcx >> 47;
            top == 0 || top == 0x1FFFF
        };
        print_str(b" rcx-canonical=");
        print_u64(canonical as u64);
        print_str(b"\n");
        let process = nt_handler.capture_process_identity(pi);
        let read_wl = |va: u64| -> Option<u64> {
            crate::fault_stack_diagnostics::read_fault_stack_word(
                &nt_handler, pi, process, va, 0, scratch_base,
            )
        };
        // The RTL_CRITICAL_SECTION itself: DebugInfo/LockCount/RecursionCount/OwningThread/
        // LockSemaphore/SpinCount at +0x00/08/0c/10/18/20.
        if canonical {
            print_str(b"[cs-diag] CS@0x");
            print_hex((rcx >> 32) as u32);
            print_hex(rcx as u32);
            let mut ok = true;
            for off in (0..0x28u64).step_by(8) {
                match read_wl(rcx + off) {
                    Some(v) => {
                        print_str(b" +0x");
                        print_u64(off);
                        print_str(b"=0x");
                        print_hex((v >> 32) as u32);
                        print_hex(v as u32);
                    }
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                print_str(b" <unreadable: not backed by any mapped frame>");
            }
            print_str(b"\n");
        }
        // TEB+0x1698 is rpcrt4's per-thread `ReservedForNtRpc` cache.
        print_str(b"[cs-diag] live TEB+0x1680..0x16b0:");
        let tail = nt_handler.hosted_thread_teb_for_badge(lp.msg.badge)
            .and_then(|teb| teb.checked_add(0x1680));
        let mut readable = tail.is_some();
        if let Some(tail) = tail {
            for off in (0..0x30u64).step_by(8) {
                let Some(value) = tail.checked_add(off).and_then(|address| read_wl(address)) else {
                    readable = false;
                    break;
                };
                print_str(b" ");
                print_hex((value >> 32) as u32);
                print_hex(value as u32);
            }
        }
        if !readable {
            print_str(b" <unreadable: no resident thread TEB backing>");
        }
        print_str(b"\n");
        // The return-address chain. RtlEnterCriticalSection's frame is push/push/sub 0x28,
        // so its own return address sits at SP+0x38 at the faulting instruction.
        print_str(b"[cs-diag] ret@sp+0x38=0x");
        match read_wl(rsp + 0x38) {
            Some(v) => {
                print_hex((v >> 32) as u32);
                print_hex(v as u32);
                if ntdll_base != 0 && v >= ntdll_base {
                    print_str(b" (n+0x");
                    print_hex(v.wrapping_sub(ntdll_base) as u32);
                    print_str(b")");
                }
            }
            None => print_str(b"?"),
        }
        print_str(b" callers:");
        let mut shown = 0;
        for i in 0..96u64 {
            if let Some(v) = read_wl(rsp + i * 8) {
                {
                    let (nb, npe) = ntdll;
                    if v >= nb && v < nb + image_extent(npe) {
                        print_str(b" n+0x");
                        print_hex((v - nb) as u32);
                        shown += 1;
                    }
                }
                if v >= 0x8000_0000 && v < 0x8080_0000 {
                    print_str(b" d+0x");
                    print_hex(v as u32);
                    shown += 1;
                }
                if shown >= 24 {
                    break;
                }
            }
        }
        print_str(b"\n");
    }
    // ★ WINLOGON POST-LOGON MILESTONE PARK — the same rule the #PF arm applies, and for the
    // same reason. Once the interactive logon has really completed, a fault on winlogon's
    // post-logon path is a FRONTIER, not a crash: `park_and_log!` would latch the whole
    // process as a dead win32k callback client, which disarms the post-quiesce callback
    // injections (`exec_user_callback_dead_client_unwind` /
    // `exec_win32k_transport_call_nested`) even though winlogon's other threads are alive and
    // hold no callback frames. Batch 59 measured exactly that: with `CopyDirectory` really
    // running, winlogon reaches kernel32's `ASSERT(StaticUnicodeString.MaximumLength == …)`
    // in `fileutils.c:26`, whose `int 3` lands HERE.
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
        assert!(drop_current_hosted_reply(), "terminal CPU fault must retire its Call");
        print_str(b"[wl-main] winlogon COMPLETED THE INTERACTIVE LOGON; its POST-LOGON path raises an unhandled CPU exception at ip=0x");
        print_hex((fip >> 32) as u32);
        print_hex(fip as u32);
        print_str(b" -> terminal thread containment (no callback frame; other threads continue)\n");
        lp.parks.crash_parked |= owner_bit_for_badge(&nt_handler, lp.msg.badge);
        service_watchdog_record_crash_parked(lp.parks.crash_parked);
        procs[pi].faults = lp.exit.faults;
        procs[pi].first = lp.exit.first;
        procs[pi].ntfaults = lp.exit.ntfaults;
        pfilled[pi] = *filled_pages;
        WINLOGON_POST_LOGON_MILESTONE_PARK.store(fip, Ordering::Relaxed);
        WINLOGON_POST_LOGON_MILESTONE_CR2.store(fip, Ordering::Relaxed);
        if ((live_top_badges(&nt_handler) & !(lp.parks.crash_parked | lp.parks.wait_parked)) == 0
            || LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0)
            && !pre_user_shell_frontier_pending(
                &nt_handler,
                lp.parks.crash_parked,
                lp.parks.wait_parked,
                b"winlogon-post-logon-fault",
            )
            && !defer_quiesce_for_active_user_callbacks(b"winlogon-post-logon-fault")
        {
            print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
            lp.exit.stop = fip;
            lp.exit.record(b"winlogon-post-logon-fault");
            return ControlFlow::Break(Turn::Exit);
        }
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
    // Unhandled CPU exception (label 3) at a non-skippable site — a real crash. Park+log.
    return ControlFlow::Break(lp.park_and_log(pi, b"cpu-exception(3)", fip, fip));
}

#[inline(never)]
pub(super) unsafe fn debug_exception(
    lp: &mut LoopState<'_>,
    ev: &Event,
) -> ControlFlow<Turn, core::convert::Infallible> {
    let nt_handler = &mut *lp.handler;
    let procs = &mut *lp.procs.procs;
    let pfilled = &mut *lp.procs.pfilled;
    let filled_pages = &mut *lp.procs.filled_pages;
    let ntdll = lp.images.ntdll;
    let Event { event_runtime, pi, scratch_base, .. } = *ev;
    let debug_ip = lp.msg.m0;
    let debug_reason = lp.msg.m1;
    let tcb = event_runtime.tcb;
    if tcb != 0 {
        let mut regs = [0u64; 20];
        crate::win32k_glue::tcb_read_regs20(tcb, &mut regs);
        let rip = regs[0];
        let rcx = regs[5];
        let rsp = regs[1];
        let raise_rva = rip.wrapping_sub(ntdll.0);
        print_str(b"[bp-diag] int3 rva=0x");
        print_hex(raise_rva as u32);
        print_str(b" rcx(record*)=0x");
        print_hex((rcx >> 32) as u32);
        print_hex(rcx as u32);
        print_str(b" rsp=0x");
        print_hex((rsp >> 32) as u32);
        print_hex(rsp as u32);
        print_str(b"\n");
        // Diagnostics may inspect only the current process's recorded resident backing.
        let process = nt_handler.capture_process_identity(pi);
        let read_wl = |va: u64| -> Option<u64> {
            crate::fault_stack_diagnostics::read_fault_stack_word(
                &nt_handler, pi, process, va, 0, scratch_base,
            )
        };
        let mut rec = [0u8; 0x30];
        let mut got = true;
        for off in (0..0x30u64).step_by(8) {
            if let Some(v) = read_wl(rcx + off) {
                rec[off as usize..off as usize + 8].copy_from_slice(&v.to_le_bytes());
            } else {
                got = false;
                break;
            }
        }
        if got {
            let code = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
            let flags = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
            let addr = u64::from_le_bytes([
                rec[16], rec[17], rec[18], rec[19], rec[20], rec[21], rec[22], rec[23],
            ]);
            // NumberParameters @ +0x18 (byte 24); ExceptionInformation[] @ +0x20 (byte 32).
            let nparm = u32::from_le_bytes([rec[24], rec[25], rec[26], rec[27]]);
            let info0 = u64::from_le_bytes([
                rec[32], rec[33], rec[34], rec[35], rec[36], rec[37], rec[38], rec[39],
            ]);
            let info1 = u64::from_le_bytes([
                rec[40], rec[41], rec[42], rec[43], rec[44], rec[45], rec[46], rec[47],
            ]);
            print_str(b"[bp-diag] EXCEPTION_RECORD code=0x");
            print_hex(code);
            print_str(b" flags=0x");
            print_hex(flags);
            print_str(b" addr=0x");
            print_hex((addr >> 32) as u32);
            print_hex(addr as u32);
            print_str(b" nparams=");
            print_u64(nparm as u64);
            print_str(b" info0=0x");
            print_hex((info0 >> 32) as u32);
            print_hex(info0 as u32);
            print_str(b" info1=0x");
            print_hex((info1 >> 32) as u32);
            print_hex(info1 as u32);
            print_str(b"\n");
            // 0xC06D007E = VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND) — a VC++
            // delay-load failure. ExceptionInformation[0] points at a DelayLoadInfo whose
            // +0x08 (szDll, LPCSTR) names the missing DLL. Dump it.
            if code == 0xC06D_007E && info0 != 0 {
                // DelayLoadInfo: cb@0, pidd@0x08, ppfn@0x10, szDll(LPCSTR)@0x18.
                if let Some(szdll) = read_wl(info0 + 0x18) {
                    print_str(b"[bp-diag] delayload szDll ptr=0x");
                    print_hex((szdll >> 32) as u32);
                    print_hex(szdll as u32);
                    print_str(b" name=\"");
                    // Read up to 40 ASCII bytes of the DLL name into a buffer.
                    let mut name = [0u8; 41];
                    let mut n = 0usize;
                    for j in 0..40u64 {
                        if let Some(w) = read_wl((szdll + j) & !7) {
                            let b = ((w >> (8 * ((szdll + j) & 7))) & 0xff) as u8;
                            if b == 0 {
                                break;
                            }
                            name[n] = if b.is_ascii_graphic() || b == b' ' {
                                b
                            } else {
                                b'?'
                            };
                            n += 1;
                        } else {
                            break;
                        }
                    }
                    print_str(&name[..n]);
                    print_str(b"\"\n");
                }
            }
        } else {
            print_str(b"[bp-diag] EXCEPTION_RECORD not in a faulted page (rcx unmapped)\n");
        }
        // Walk the caller's stack for return addresses in ntdll / DLLs to identify the raise
        // site (who called RtlRaiseException / RtlRaiseStatus).
        print_str(b"[bp-diag] callers:");
        let mut shown = 0;
        for i in 0..96u64 {
            if let Some(v) = read_wl(rsp + i * 8) {
                {
                    let (nb, npe) = ntdll;
                    if v >= nb && v < nb + image_extent(npe) {
                        print_str(b" n+0x");
                        print_hex((v - nb) as u32);
                        shown += 1;
                    }
                }
                if v >= 0x8000_0000 && v < 0x8080_0000 {
                    print_str(b" d+0x");
                    print_hex(v as u32);
                    shown += 1;
                }
                if shown >= 24 {
                    break;
                }
            }
        }
        print_str(b"\n");
    }
    let exception_code =
        nt_process::dbgk::exception_code_for_debug_exception_reason(debug_reason);
    let dbg_trace = DBGK_DEBUG_EXCEPTION_TRACE_N.fetch_add(1, Ordering::Relaxed);
    if dbg_trace < 16 {
        print_str(b"[dbgk-debug-exception] pi=");
        print_u64(pi as u64);
        print_str(b" ip=0x");
        print_hex_u64(debug_ip);
        print_str(b" reason=");
        print_u64(debug_reason);
        print_str(b" code=0x");
        print_hex(exception_code);
        print_str(b"\n");
    }
    // DbgkForwardException: software int3 reports as `DbgBreakpointStateChange`, while #DB
    // single-step and hardware breakpoints report as `DbgSingleStepStateChange`. No-op when
    // nothing debugs this process.
    if dbgk_forward_exception(nt_handler, pi, nt_process::dbgk::ExceptionRecord::new(exception_code, debug_ip)) && dbgk_block_and_park(
        &mut lp.exit, &mut lp.parks, &mut lp.ingress, nt_handler, procs, pfilled,
        filled_pages, pi, nt_process::dbgk::DBGK_BLOCK_DEBUG_EXCEPTION, debug_ip, lp.msg.m2, lp.msg.m3, &mut lp.msg,
    )? {
        return ControlFlow::Break(Turn::Next);
    }
    // Unhandled #DB/#BP (a RtlRaiseException the loader/process can't recover, or a
    // debugger-declined single-step) — a crash. Park+log.
    return ControlFlow::Break(lp.park_and_log(pi, b"debug-exception(4)", debug_ip, debug_ip));
}
