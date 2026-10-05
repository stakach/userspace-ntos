//! Best-effort fault diagnostics must never fault the executive while inspecting a client.

use crate::{img_spawn::client_copyin_process_mapped_for, ExecNtHandler};
use nt_memory_manager::ProcessIdentity;

pub(crate) unsafe fn trace_user_fault_context(
    handler: &ExecNtHandler,
    expected: crate::hosted_thread_runtime::HostedThreadRuntime,
    scratch_base: u64,
) {
    use core::fmt::Write;

    let Some(process) = handler.capture_process_identity(expected.pi) else {
        return;
    };
    let Some(before) = handler.thread_runtime.executable_by_tid(expected.tid) else {
        return;
    };
    if process != expected.process || before.binding() != expected.binding() {
        return;
    }
    let Ok(context) = crate::thread_context::LegacyThreadContext::read(expected.tcb) else {
        sel4_rt::print_record(b"[user-fault-context] capture-unavailable\n");
        return;
    };
    let Some(after) = handler.thread_runtime.executable_by_tid(expected.tid) else {
        return;
    };
    if after.binding() != expected.binding()
        || handler.capture_process_identity(expected.pi) != Some(process)
    {
        return;
    }
    let mut stack = [None; 8];
    for (index, word) in stack.iter_mut().enumerate() {
        *word = read_fault_stack_word(
            handler,
            expected.pi,
            Some(process),
            context.registers[1],
            index as u64,
            scratch_base,
        );
    }
    if handler
        .thread_runtime
        .executable_by_tid(expected.tid)
        .is_none_or(|current| current.binding() != expected.binding())
        || handler.capture_process_identity(expected.pi) != Some(process)
    {
        return;
    }
    let mut record = nt_printf::record::RecordBuffer::<2048>::new();
    let _ = write!(
        record,
        "[user-fault-context] pi={} pid={} generation={:?} tid={} badge={} tcb=0x{:016x}",
        expected.pi, process.pid, process.generation, expected.tid, expected.badge, expected.tcb
    );
    let names = [
        "rip", "rsp", "rflags", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10",
        "r11", "r12", "r13", "r14", "r15",
    ];
    for (name, value) in names.iter().zip(&context.registers) {
        let _ = write!(record, " {name}=0x{value:016x}");
    }
    for (index, word) in stack.iter().enumerate() {
        match word {
            Some(value) => {
                let _ = write!(record, " stack[{index}]=0x{value:016x}");
            }
            None => {
                let _ = write!(record, " stack[{index}]=unreadable");
            }
        }
    }
    let _ = writeln!(record);
    sel4_rt::print_record(if record.overflowed() {
        b"[user-fault-context] record-truncated\n"
    } else {
        record.bytes()
    });
}

pub(crate) unsafe fn read_fault_stack_word(
    handler: &ExecNtHandler,
    pi: usize,
    process: Option<ProcessIdentity>,
    stack: u64,
    word_index: u64,
    scratch_base: u64,
) -> Option<u64> {
    let process = process?;
    if handler.capture_process_identity(pi) != Some(process) {
        return None;
    }
    let address = stack.checked_add(word_index.checked_mul(8)?)?;
    address.checked_add(8)?;
    let mut bytes = [0u8; 8];
    // Only generation-authenticated resident records/prefetch aliases are admissible. The
    // broad bootstrap mirrors and historical fill-order scratch pages are not residency proof.
    if !client_copyin_process_mapped_for(pi as u64, process, address, &mut bytes, scratch_base) {
        return None;
    }
    Some(u64::from_le_bytes(bytes))
}
