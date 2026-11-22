//! Canonical process-exit observations, independent of a test image or launch role.

use crate::*;
use nt_user_host::process_identity::ProcessGeneration;

/// Drain Process Manager's exit tickets (#420). A callback still running in its provider keeps
/// its ticket in flight and is resumed here, before any other ticket is claimed; the root's
/// maintenance runs this too, so it continues without another exit. A callback failure retains
/// the exact in-flight ticket and blocks EPROCESS deletion; this path never retries an uncertain
/// effect.
pub(crate) fn drain_hosted_process_exit_notifications(handler: &mut ExecNtHandler) {
    use nt_kernel_exec::hosted_process_exit_notify::ProcessExitDrain;
    let drained = unsafe {
        crate::driver_launch::hosted_driver_process_notify::drain_exit_notifications(&mut handler.pm)
    };
    match drained {
        ProcessExitDrain::Idle => {}
        ProcessExitDrain::Running => trace_running(),
        ProcessExitDrain::Retained(status) => {
            print_str(b"[process-notify] callback retained status=0x");
            print_hex(status as u32);
            print_str(b"\n");
        }
    }
}

fn trace_running() {
    static TRACED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let n = TRACED.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[process-notify] callback running n=");
    print_u64(n);
    print_str(b"\n");
}

pub(crate) fn note_native_process_terminal(
    handler: &ExecNtHandler,
    pid: nt_process::ProcessId,
    process_index: Option<u8>,
) {
    let Some(pi) = process_index.map(usize::from) else {
        return;
    };
    let Some(identity) = handler.capture_process_identity(pi) else {
        return;
    };
    if identity.pid != pid || !handler.pm.is_process_signaled(pid) {
        return;
    }
    let ProcessGeneration::Hosted(generation) = identity.generation else {
        return;
    };
    let Some(status) = handler
        .pm
        .process(pid)
        .and_then(|process| process.exit_status)
    else {
        return;
    };
    print_str(b"[process-terminal-committed] pi=");
    print_u64(pi as u64);
    print_str(b" pid=");
    print_u64(u64::from(pid));
    print_str(b" generation=");
    print_u64(generation);
    print_str(b" exit-status=");
    print_hex(status);
    print_str(b" signaled=1\n");
}
