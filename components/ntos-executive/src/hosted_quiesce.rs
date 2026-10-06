//! Terminal-only observations copied from canonical runtimes and exact saved waits.
use super::*;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

pub(super) unsafe fn dump_all_hosted_thread_quiesce(
    handler: &ExecNtHandler,
    images: &HostedLoadedImageTable,
    registry: &nt_dll_registry::Registry,
    ntdll: (u64, &nt_pe_loader::PeFile),
    procs: &[ProcExec],
    filled: &[[u64; 512]],
) {
    let mut cursor = 0;
    while let Some((next, binding, lifetime)) = handler.next_hosted_thread_quiesce_snapshot(cursor)
    {
        cursor = next;
        print_str(b"[hosted-quiesce-owner] pi=");
        print_u64(binding.pi as u64);
        print_str(b" pid=");
        print_u64(binding.process.pid as u64);
        print_str(b" tid=");
        print_u64(binding.tid);
        print_str(b" badge=");
        print_u64(binding.badge);
        print_str(b" tcb=0x");
        print_hex_u64(binding.tcb);
        print_str(b" process-generation=");
        match binding.process.generation {
            nt_user_host::process_identity::ProcessGeneration::Hosted(generation) => {
                print_str(b"Hosted:");
                print_u64(generation);
            }
            nt_user_host::process_identity::ProcessGeneration::Temporary(generation) => {
                print_str(b"Temporary:");
                print_u64(generation);
            }
        }
        print_str(b" thread-generation=");
        if let Some(lifetime) = lifetime {
            print_u64(lifetime.generation());
        } else {
            print_str(b"unavailable");
        }
        print_str(b" current-process=");
        print_u64((handler.capture_process_identity(binding.pi) == Some(binding.process)) as u64);
        print_str(b"\n");
        dump_hosted_thread_quiesce(
            b"hosted-quiesce",
            binding.pi,
            binding.tid,
            binding.tcb,
            binding.badge,
            handler,
            images,
            registry,
            ntdll,
            procs,
            filled,
        );
    }
}

pub(super) fn quiesce_caller(
    handler: &ExecNtHandler,
    pi: usize,
    tid: u64,
    tcb: u64,
    badge: u64,
) -> Option<ProviderLogicalCaller> {
    let mut cursor = 0;
    while let Some((next, binding, lifetime)) = handler.next_hosted_thread_quiesce_snapshot(cursor)
    {
        cursor = next;
        if binding.pi == pi && binding.tid == tid && binding.tcb == tcb && binding.badge == badge {
            if handler.capture_process_identity(pi) != Some(binding.process) {
                return None;
            }
            let lifetime = lifetime?;
            return handler
                .capture_provider_logical_caller(pi, tid, badge, tcb)
                .filter(|caller| caller.thread() == lifetime);
        }
    }
    None
}

pub(super) fn print_wait_snapshot(label: &[u8], snapshot: Option<ObjectWaitSnapshot>) {
    print_quiesce_tag(label, b"-wait");
    let Some(wait) = snapshot else {
        print_str(b" unavailable (no unique exact dispatcher-wait caller)\n");
        return;
    };
    print_str(b" sequence=");
    print_u64(wait.sequence);
    print_str(b" reply=0x");
    print_hex_u64(wait.reply_cap);
    print_str(b" sent=");
    print_u64(wait.reply_sent as u64);
    print_str(b" all=");
    print_u64(wait.wait_all as u64);
    print_str(b" alertable=");
    print_u64(wait.alertable as u64);
    print_str(b" deadline=");
    match wait.deadline {
        nt_delay_execution::Deadline::Infinite => print_str(b"Infinite"),
        nt_delay_execution::Deadline::Relative { monotonic_100ns } => {
            print_str(b"monotonic:");
            print_u64(monotonic_100ns);
        }
        nt_delay_execution::Deadline::Absolute { system_time_100ns } => {
            print_str(b"system:");
            print_u64(system_time_100ns);
        }
    }
    print_str(b" objects=");
    for object in wait.objects.iter().take(wait.count as usize) {
        print_str(b"0x");
        print_hex_u64(object.raw());
        print_str(b" ");
    }
    print_str(b"\n");
}
