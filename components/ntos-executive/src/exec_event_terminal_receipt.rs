//! Bounded, process-exact receipts for terminal native event open/wait failures.

use super::*;

static OPEN_FAILURES: AtomicU64 = AtomicU64::new(0);
static WAIT_FAILURES: AtomicU64 = AtomicU64::new(0);

fn begin_receipt(handler: &ExecNtHandler, service: &[u8], sequence: u64, status: u32) {
    print_str(b"[event-terminal-failure] service=");
    print_str(service);
    print_str(b" n=");
    print_u64(sequence);
    print_str(b" pi=");
    print_u64(handler.pi as u64);
    print_str(b" pid=");
    if let Some(pid) = handler.pm_pid_for_pi(handler.pi) {
        print_u64(u64::from(pid));
    } else {
        print_str(b"unknown");
    }
    print_str(b" gen=");
    if let Some(generation) = handler.hosted_process_generation(handler.pi) {
        print_u64(generation);
    } else {
        print_str(b"unknown");
    }
    print_str(b" tid=");
    print_u64(handler.current_tid);
    print_str(b" badge=");
    print_u64(handler.current_badge);
    print_str(b" status=0x");
    print_hex(status);
}

pub(super) fn open_failure(
    handler: &ExecNtHandler,
    status: u32,
    output: u64,
    attributes: u64,
    root: Option<usize>,
    path: &[u8],
    object: Option<usize>,
) {
    if !nt_hosted_runtime::EventTerminalReceiptSampler::is_failure(status) {
        return;
    }
    let sequence = OPEN_FAILURES.fetch_add(1, Ordering::Relaxed);
    if !nt_hosted_runtime::EventTerminalReceiptSampler::sample_sequence(sequence) {
        return;
    }
    begin_receipt(handler, b"NtOpenEvent", sequence, status);
    print_str(b" output=0x");
    print_hex_u64(output);
    print_str(b" oa=0x");
    print_hex_u64(attributes);
    print_str(b" root=");
    if let Some(root) = root {
        print_u64(root as u64);
    } else {
        print_str(b"unresolved");
    }
    print_str(b" request=\"");
    print_sanitized_ascii(path, 192);
    print_str(b"\"");
    if let Some(index) = object {
        print_str(b" object=");
        print_u64(index as u64);
        let mut full = [0u8; 192];
        let len = handler.query_object_namespace_path(index, &mut full);
        print_str(b" path=\"");
        print_sanitized_ascii(&full[..len.min(full.len())], 192);
        print_str(b"\"");
    }
    print_str(b"\n");
}

pub(super) fn wait_failure(
    handler: &ExecNtHandler,
    status: u32,
    handle: u64,
    timeout: u64,
    object: Option<WaitObject>,
) {
    if !nt_hosted_runtime::EventTerminalReceiptSampler::is_failure(status) {
        return;
    }
    let sequence = WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
    if !nt_hosted_runtime::EventTerminalReceiptSampler::sample_sequence(sequence) {
        return;
    }
    begin_receipt(handler, b"NtWaitForSingleObject", sequence, status);
    print_str(b" handle=0x");
    print_hex_u64(handle);
    print_str(b" timeout=0x");
    print_hex_u64(timeout);
    if let Some(object) = object {
        print_str(b" object=");
        print_str(object.describe());
        print_str(b" id=");
        print_u64(object.id());
        if object.kind() == WaitObject::KIND_DISPATCHER {
            let index = object.id() as usize;
            let mut full = [0u8; 192];
            let len = handler.query_object_namespace_path(index, &mut full);
            print_str(b" path=\"");
            print_sanitized_ascii(&full[..len.min(full.len())], 192);
            print_str(b"\"");
        }
    } else {
        print_str(b" object=unresolved");
    }
    print_str(b"\n");
}
