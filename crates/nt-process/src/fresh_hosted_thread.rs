//! Fallible fresh ETHREAD preparation, independent of native mechanism-slot reuse.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);

/// Owns cancellation of one unborn canonical thread, not proof of a native effect.
/// Retain this token across uncertain construction; cancellation requires all effects absent.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct FreshHostedThreadPreparation {
    nonce: u64,
    lifetime: ThreadLifetime,
}

impl FreshHostedThreadPreparation {
    pub const fn lifetime(&self) -> ThreadLifetime {
        self.lifetime
    }
}

impl NtThread {
    pub(super) fn try_construct(
        tid: ThreadId,
        pid: ProcessId,
        start_address: u64,
        parameter: u64,
        is_system_thread: bool,
        state: ThreadState,
        affinity_mask: u64,
        base_priority: i32,
    ) -> Result<Self, u32> {
        let mut termination_ports = Vec::new();
        termination_ports
            .try_reserve_exact(THREAD_TERMINATION_PORT_RESERVE)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut security_descriptor = Vec::new();
        security_descriptor
            .try_reserve_exact(nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        security_descriptor.extend_from_slice(&nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR[..]);
        Ok(Self {
            thread_id: tid,
            process_id: pid,
            start_address,
            win32_start_address: start_address,
            parameter,
            state,
            scheduling_state: state,
            is_system_thread,
            exit_status: None,
            wait_references: 0,
            kernel_pointer_references: 0,
            create_time_100ns: 0,
            exit_time_100ns: 0,
            kernel_time_100ns: 0,
            user_time_100ns: 0,
            activation_generation: 1,
            initial_runtime_published: false,
            fresh_hosted_nonce: None,
            termination_ports,
            impersonation: None,
            security_descriptor,
            suspend_count: 0,
            suspend_revision: 0,
            pending_suspend_control: None,
            freeze_count: 0,
            win32_thread: None,
            kernel_thread_object: None,
            teb_base: 0,
            affinity_mask,
            priority: base_priority,
            base_priority,
            ideal_processor: 0,
            break_on_termination: false,
            disable_boost: false,
            hide_from_debugger: false,
            thread_name_len: 0,
            thread_name: Vec::new(),
            user_apc_queue: VecDeque::new(),
        })
    }
}

impl ProcessManager {
    /// Prepare a distinct dormant identity. All allocation and CID checks precede publication;
    /// failures can grow spare capacity, but do not change membership, owners, or the next CID.
    pub fn prepare_fresh_hosted_thread(
        &mut self,
        pid: ProcessId,
    ) -> Result<FreshHostedThreadPreparation, u32> {
        self.prepare_fresh_hosted_thread_with_reserve(pid, 1)
    }

    // The private reserve count lets tests exercise real allocator refusal without a global
    // allocator override. Production always reserves exactly one additional table entry.
    pub(super) fn prepare_fresh_hosted_thread_with_reserve(
        &mut self,
        pid: ProcessId,
        table_reserve: usize,
    ) -> Result<FreshHostedThreadPreparation, u32> {
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) || process.exit_status.is_some()
        {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        if process.main_thread.is_none() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let affinity_mask = process.affinity_mask;
        let base_priority = process.base_priority;
        let tid = self.next_cid;
        let next = tid
            .checked_add(CLIENT_ID_GRANULARITY)
            .filter(|_| tid != 0 && tid % CLIENT_ID_GRANULARITY == 0)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let nonce = NEXT_NONCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut thread = NtThread::try_construct(
            tid,
            pid,
            0,
            0,
            false,
            ThreadState::Initialized,
            affinity_mask,
            base_priority,
        )?;
        self.threads
            .entries
            .try_reserve_exact(table_reserve)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.processes
            .get_mut(&pid)
            .unwrap()
            .threads
            .entries
            .try_reserve_exact(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        thread.fresh_hosted_nonce = Some(nonce);
        self.next_cid = next;
        assert!(self.processes.get_mut(&pid).unwrap().threads.insert(tid));
        assert!(self.threads.insert(tid, thread).is_none());
        let lifetime = self
            .thread_lifetime(tid)
            .expect("new dormant thread has exact lifetime");
        Ok(FreshHostedThreadPreparation { nonce, lifetime })
    }

    /// Cancel only a proven unborn identity. Bound handles and published Ps bodies are effects,
    /// even if no TCB ran. The native owner must release its own known-unentered reservations first.
    pub fn cancel_fresh_hosted_thread(
        &mut self,
        preparation: &FreshHostedThreadPreparation,
    ) -> Result<(), u32> {
        let lifetime = preparation.lifetime;
        let thread = self
            .thread(lifetime.thread_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !self.validate_thread_lifetime(lifetime)
            || thread.fresh_hosted_nonce != Some(preparation.nonce)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process = self
            .process(lifetime.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if process.main_thread == Some(lifetime.thread_id)
            || thread.state != ThreadState::Initialized
            || thread.initial_runtime_published
            || thread.kernel_thread_object.is_some()
            || thread.exit_status.is_some()
            || thread.pending_suspend_control.is_some()
            || self.has_initial_thread_creation_pending_for(lifetime.thread_id)
            || thread.wait_references != 0
            || thread.kernel_pointer_references != 0
            || !thread.termination_ports.is_empty()
            || thread.impersonation.is_some()
            || thread.win32_thread.is_some()
            || !thread.user_apc_queue.is_empty()
            || self.has_thread_handle_reference_except(lifetime.thread_id, None)
        {
            return Err(STATUS_DEVICE_BUSY);
        }
        let index = process
            .threads
            .entries
            .binary_search(&lifetime.thread_id)
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        self.processes
            .get_mut(&lifetime.process_id)
            .unwrap()
            .threads
            .entries
            .remove(index);
        self.threads
            .remove(&lifetime.thread_id)
            .expect("validated unborn identity");
        Ok(())
    }
}
