//! First-chance delivery of a user thread's hardware exception (#285), as ReactOS
//! `KiDispatchExceptionToUser` does it: the faulting CONTEXT and EXCEPTION_RECORD go onto the
//! thread's stack and the thread resumes at `ntdll!KiUserExceptionDispatcher`. The dispatcher
//! runs the vectored and frame handlers; a handled exception resumes with `NtContinue`, an
//! unhandled one comes back as `NtRaiseException(FirstChance = FALSE)`, which terminates the
//! process with the exception code.

use crate::*;
use nt_thread_start::user_exception::HardwareFault;

/// Why an exception could not be handed to the thread; the caller keeps its current handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotDelivered {
    /// The faulting badge is not an executable thread of `pi`.
    UnknownThread,
    /// The thread's state could not be read.
    ThreadState,
    /// ntdll does not export the dispatcher.
    NoDispatcher,
    /// The frame does not fit the thread's stack, the CONTEXT is not restorable, or writing
    /// the frame to the stack failed. KiDispatchException then terminates the process.
    Unwritable(Unwritable),
    /// The fault Call cannot be restarted, or the kernel refused the restart; it is unchanged.
    Restart,
}

/// The thread whose exception frame could not be written, and that exception's code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unwritable {
    pub(crate) tid: u64,
    pub(crate) code: u32,
}

impl NotDelivered {
    pub(crate) fn label(self) -> &'static [u8] {
        match self {
            Self::UnknownThread => b"thread",
            Self::ThreadState => b"state",
            Self::NoDispatcher => b"dispatcher",
            Self::Unwritable(_) => b"unwritable-frame",
            Self::Restart => b"restart",
        }
    }
}

static DELIVERY_TRACE_N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Whether this delivery is among the first 16, which are traced.
pub(crate) fn trace_delivery() -> bool {
    DELIVERY_TRACE_N.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 16
}

/// The CPU exception a user `vector` raised at `ip` reports. A #GP decodes the instruction
/// bytes the thread can read there (KiGeneralProtectionFaultUserMode).
pub(crate) unsafe fn cpu_fault(
    handler: &mut ExecNtHandler,
    pi: usize,
    vector: u64,
    ip: u64,
) -> Option<HardwareFault> {
    const GENERAL_PROTECTION: u64 = 13;
    if vector != GENERAL_PROTECTION {
        return HardwareFault::from_vector(vector);
    }
    use nt_thread_start::user_exception::PRIVILEGED_INSTRUCTION_WINDOW;
    let mut bytes = [0u8; PRIVILEGED_INSTRUCTION_WINDOW];
    // The window may run into an unreadable page; the bytes before it still decode.
    let to_page_end = (0x1000 - (ip & 0xfff)) as usize;
    let readable = [PRIVILEGED_INSTRUCTION_WINDOW, to_page_end.min(PRIVILEGED_INSTRUCTION_WINDOW)]
        .into_iter()
        .find(|len| handler.process_memory_read_status(pi, ip, &mut bytes[..*len]).is_ok())
        .unwrap_or(0);
    Some(HardwareFault::general_protection(&bytes[..readable]))
}

/// The DBGKM_EXCEPTION record a debugger sees for `fault` at `ip`: the same record the
/// thread's own handlers receive.
pub(crate) fn debug_record(fault: HardwareFault, ip: u64) -> nt_process::dbgk::ExceptionRecord {
    let (record, _) = nt_thread_start::user_exception::classify(fault, ip);
    nt_process::dbgk::ExceptionRecord::new(record.code, record.address)
        .with_parameters(&record.parameters[..record.parameter_count as usize])
}

/// Deliver `fault` raised at `ip` by the thread behind `badge` in process `pi`.
/// On success the thread has been restarted at the dispatcher and its fault Call retired.
pub(crate) unsafe fn deliver_user_exception(
    handler: &mut ExecNtHandler,
    pi: usize,
    badge: u64,
    fault: HardwareFault,
    ip: u64,
    reply: u64,
    ntdll: (u64, &nt_pe_loader::PeFile<'_>),
) -> Result<u32, NotDelivered> {
    let runtime = handler
        .thread_runtime
        .executable_by_badge(badge)
        .filter(|runtime| runtime.pi == pi)
        .ok_or(NotDelivered::UnknownThread)?;
    let tcb = handler
        .hosted_thread_tcb(runtime.tid)
        .filter(|tcb| *tcb > 1)
        .ok_or(NotDelivered::UnknownThread)?;
    let (record, delivered_ip) = nt_thread_start::user_exception::classify(fault, ip);
    let snapshot =
        crate::thread_context::LegacyThreadContext::read(tcb).map_err(|_| NotDelivered::ThreadState)?;
    // The fault saved the thread's full user state; only the reported RIP can differ.
    let mut live = snapshot.registers;
    live[0] = delivered_ip;
    let (ntdll_base, ntdll_pe) = ntdll;
    let dispatcher = ntdll_pe
        .export_rva_by_name("KiUserExceptionDispatcher")
        .ok()
        .flatten()
        .map(|rva| ntdll_base + u64::from(rva))
        .ok_or(NotDelivered::NoDispatcher)?;
    let prepared = nt_thread_start::amd64_context::prepare_user_exception(
        &live,
        &snapshot.floating_point,
        &snapshot.debug,
        &record,
        dispatcher,
        runtime.user_stack_allocation_base,
        crate::exec_handler::HIGHEST_USER_ADDRESS,
    )
    .map_err(|_| NotDelivered::Unwritable(Unwritable { tid: runtime.tid, code: record.code }))?;
    if !crate::spawn_hosts::shared_ingress::owner::runtime::can_restart_hosted(reply, tcb) {
        return Err(NotDelivered::Restart);
    }
    handler
        .process_memory_write_status(pi, prepared.frame_va, &prepared.frame)
        .map_err(|_| NotDelivered::Unwritable(Unwritable { tid: runtime.tid, code: record.code }))?;
    match crate::spawn_hosts::shared_ingress::owner::runtime::restart_hosted(
        reply,
        tcb,
        &prepared.install,
    ) {
        Ok(Ok(())) => Ok(record.code),
        Ok(Err(_)) => Err(NotDelivered::Restart),
        Err(_) => panic!("uncertain exception-dispatch restart retains its hosted Call owner"),
    }
}
