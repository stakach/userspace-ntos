//! The authenticated caller of one native syscall.
//!
//! Ingress admits a hosted thread by its exact binding (process generation, TID, badge, TCB)
//! and scheduling context. Deferred work between admission and dispatch can retire or rebind
//! that thread, so the binding is re-admitted immediately before the service runs and must be
//! identical. A missing or changed binding refuses the Call; there is no placeholder or zero
//! TID fallback.

use crate::thread_binding::ThreadBinding;

/// One admitted thread binding plus the scheduling context it executes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedSyscallThread<R> {
    pub binding: ThreadBinding<R>,
    pub sched_context: u64,
}

/// The caller identity a native service dispatch carries (`SyscallOrigin`/`NativeCallContext`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallCaller {
    pub pi: usize,
    pub process_id: u32,
    pub thread_id: u32,
    pub tid: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallCallerRefusal {
    /// The badge no longer admits a live thread.
    Missing,
    /// The badge admits a different process generation, thread, TCB or scheduling context.
    Changed,
    /// The admitted identity has no NT PID/TID representation.
    Unrepresentable,
}

/// Revalidate the identity captured at ingress against a fresh admission of the same badge.
pub fn revalidate_syscall_caller<R: PartialEq + Copy>(
    captured: AdmittedSyscallThread<R>,
    current: Option<AdmittedSyscallThread<R>>,
) -> Result<SyscallCaller, SyscallCallerRefusal> {
    let current = current.ok_or(SyscallCallerRefusal::Missing)?;
    if current != captured {
        return Err(SyscallCallerRefusal::Changed);
    }
    let binding = captured.binding;
    let thread_id = u32::try_from(binding.tid).map_err(|_| SyscallCallerRefusal::Unrepresentable)?;
    if thread_id == 0 || binding.process.pid == 0 || binding.tcb <= 1 {
        return Err(SyscallCallerRefusal::Unrepresentable);
    }
    Ok(SyscallCaller { pi: binding.pi, process_id: binding.process.pid, thread_id, tid: binding.tid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_identity::{ProcessGeneration, ProcessIdentity};

    fn thread(generation: u64, tid: u64, badge: u64, tcb: u64, sched_context: u64)
        -> AdmittedSyscallThread<u8>
    {
        AdmittedSyscallThread {
            binding: ThreadBinding {
                pi: 7,
                process: ProcessIdentity { pid: 440, generation: ProcessGeneration::Hosted(generation) },
                tid,
                badge,
                role: 0,
                tcb,
                reservations: None,
            },
            sched_context,
        }
    }

    #[test]
    fn an_unchanged_binding_yields_the_real_pid_and_tid() {
        let captured = thread(3, 912, 41, 0x5c875, 77);
        assert_eq!(revalidate_syscall_caller(captured, Some(captured)),
            Ok(SyscallCaller { pi: 7, process_id: 440, thread_id: 912, tid: 912 }));
    }

    #[test]
    fn a_retired_caller_is_refused_rather_than_becoming_tid_zero() {
        let captured = thread(3, 912, 41, 0x5c875, 77);
        assert_eq!(revalidate_syscall_caller(captured, None), Err(SyscallCallerRefusal::Missing));
    }

    #[test]
    fn a_new_process_generation_on_the_same_badge_is_refused() {
        let captured = thread(3, 912, 41, 0x5c875, 77);
        assert_eq!(revalidate_syscall_caller(captured, Some(thread(4, 912, 41, 0x5c875, 77))),
            Err(SyscallCallerRefusal::Changed));
    }

    #[test]
    fn badge_reuse_by_another_thread_is_refused() {
        let captured = thread(3, 912, 41, 0x5c875, 77);
        assert_eq!(revalidate_syscall_caller(captured, Some(thread(3, 913, 41, 0x5c876, 77))),
            Err(SyscallCallerRefusal::Changed));
    }

    #[test]
    fn a_changed_tcb_or_scheduling_context_is_refused() {
        let captured = thread(3, 912, 41, 0x5c875, 77);
        assert_eq!(revalidate_syscall_caller(captured, Some(thread(3, 912, 41, 0x5c999, 77))),
            Err(SyscallCallerRefusal::Changed));
        assert_eq!(revalidate_syscall_caller(captured, Some(thread(3, 912, 41, 0x5c875, 78))),
            Err(SyscallCallerRefusal::Changed));
    }

    #[test]
    fn an_identity_without_a_real_thread_is_unrepresentable() {
        let reserved = thread(3, 912, 41, 1, 77);
        assert_eq!(revalidate_syscall_caller(reserved, Some(reserved)),
            Err(SyscallCallerRefusal::Unrepresentable));
        let wide = thread(3, u64::from(u32::MAX) + 1, 41, 0x5c875, 77);
        assert_eq!(revalidate_syscall_caller(wide, Some(wide)),
            Err(SyscallCallerRefusal::Unrepresentable));
    }
}
