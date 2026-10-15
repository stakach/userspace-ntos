//! Canonical process-exit observations, independent of a test image or launch role.

use crate::*;
use nt_user_host::process_identity::ProcessGeneration;

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
