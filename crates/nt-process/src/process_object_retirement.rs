//! Withdrawal separates canonical Ps lookup lifetime from native body/backing cleanup.
//!
//! The hidden records remain the sole owners of their token, port, job membership and body
//! addresses. Tickets identify existing Ps objects, not a new object or handle namespace.

use crate::{
    InitialSystemIdentity, NtProcess, NtThread, ProcessId, ProcessManager, ProcessObjectDeletion,
    ThreadLifetime, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_PENDING,
};
use alloc::vec::Vec;

pub(crate) struct RetiredProcessObjects {
    process: NtProcess,
    threads: Vec<NtThread>,
}

/// Dropping a ticket leaves the withdrawn records retained; it never acknowledges cleanup.
///
/// ```compile_fail
/// use nt_process::process_object_retirement::ProcessObjectRetirement;
/// fn duplicate(owner: ProcessObjectRetirement) { let _ = owner.clone(); }
/// ```
#[derive(Debug)]
#[must_use = "finish only after native provider/body cleanup has completed"]
pub struct ProcessObjectRetirement {
    system: InitialSystemIdentity,
    pid: ProcessId,
}

impl ProcessObjectRetirement {
    pub const fn pid(&self) -> ProcessId {
        self.pid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessObjectRetirementSnapshot {
    pub pid: ProcessId,
    pub process_body: Option<u64>,
    pub thread_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredThreadObjectSnapshot {
    pub lifetime: ThreadLifetime,
    pub body: Option<u64>,
}

impl ProcessManager {
    pub(crate) fn process_object_is_withdrawn(&self, pid: ProcessId) -> bool {
        self.process_object_retirements
            .iter()
            .flatten()
            .any(|row| row.process.process_id == pid)
    }

    pub(crate) fn retired_kernel_body_is_reserved(&self, body: u64) -> bool {
        body != 0
            && self.process_object_retirements.iter().flatten().any(|row| {
                row.process.kernel_process_object == Some(body)
                    || row
                        .threads
                        .iter()
                        .any(|thread| thread.kernel_thread_object == Some(body))
            })
    }

    fn retirement_index(&self, ticket: &ProcessObjectRetirement) -> Result<usize, u32> {
        if !self.has_initial_system_designation(ticket.system) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.process_object_retirements
            .iter()
            .position(|row| {
                row.as_ref()
                    .is_some_and(|row| row.process.process_id == ticket.pid)
            })
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Validate every admission condition and preallocate the entire hidden row before moving
    /// any object. The existing debug-port close tail must already have detached a dead port.
    pub fn withdraw_process_object_if_unreferenced(
        &mut self,
        pid: ProcessId,
    ) -> Result<ProcessObjectRetirement, u32> {
        if self.has_process_suspend_control(pid) {
            return Err(STATUS_PENDING);
        }
        let system = self
            .initial_system_identity()
            .ok_or(STATUS_INVALID_HANDLE)?;
        let blockers = self
            .process_object_delete_blockers(pid)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !blockers.delete_ready() || blockers.thread_impersonations != 0 {
            return Err(STATUS_PENDING);
        }
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.win32_process.is_some() {
            return Err(STATUS_PENDING);
        }
        let count = process.threads.len();
        if process.process_id != pid
            || self
                .threads
                .values()
                .filter(|thread| thread.process_id == pid)
                .count()
                != count
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for (index, tid) in process.threads.iter().enumerate() {
            if process.threads.iter().take(index).any(|prior| prior == tid) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let thread = self.thread(*tid).ok_or(STATUS_INVALID_HANDLE)?;
            if thread.thread_id != *tid || thread.process_id != pid {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if thread.win32_thread.is_some() || !thread.user_apc_queue.is_empty() {
                return Err(STATUS_PENDING);
            }
        }
        let mut threads = Vec::new();
        threads
            .try_reserve_exact(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let slot = match self
            .process_object_retirements
            .iter()
            .position(Option::is_none)
        {
            Some(slot) => slot,
            None => {
                self.process_object_retirements
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                self.process_object_retirements.len()
            }
        };
        let process = self
            .processes
            .remove(&pid)
            .expect("withdrawal preflight retains exact process");
        for tid in &process.threads {
            threads.push(
                self.threads
                    .remove(tid)
                    .expect("withdrawal preflight retains exact thread"),
            );
        }
        let row = Some(RetiredProcessObjects { process, threads });
        if slot == self.process_object_retirements.len() {
            self.process_object_retirements.push(row);
        } else {
            self.process_object_retirements[slot] = row;
        }
        Ok(ProcessObjectRetirement { system, pid })
    }

    /// Copy metadata under the original manager's validation; no borrowed record need cross IPC.
    pub fn process_object_retirement_snapshot(
        &self,
        ticket: &ProcessObjectRetirement,
    ) -> Result<ProcessObjectRetirementSnapshot, u32> {
        let index = self.retirement_index(ticket)?;
        let row = self.process_object_retirements[index].as_ref().unwrap();
        Ok(ProcessObjectRetirementSnapshot {
            pid: row.process.process_id,
            process_body: row.process.kernel_process_object,
            thread_count: row.threads.len(),
        })
    }

    pub fn process_object_retirement_thread(
        &self,
        ticket: &ProcessObjectRetirement,
        index: usize,
    ) -> Result<RetiredThreadObjectSnapshot, u32> {
        let slot = self.retirement_index(ticket)?;
        let thread = self.process_object_retirements[slot]
            .as_ref()
            .unwrap()
            .threads
            .get(index)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        Ok(RetiredThreadObjectSnapshot {
            lifetime: ThreadLifetime {
                thread_id: thread.thread_id,
                process_id: thread.process_id,
                generation: thread.activation_generation,
            },
            body: thread.kernel_thread_object,
        })
    }

    /// MM commitment remains attached to the retained job membership after public withdrawal.
    pub fn release_retired_process_job_memory(
        &mut self,
        ticket: &ProcessObjectRetirement,
        bytes: u64,
    ) -> Result<(), u32> {
        self.retirement_index(ticket)?;
        if bytes & 0xfff != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.jobs.job_for_process(ticket.pid).is_some() {
            let (process_bytes, job_bytes) = self.jobs.memory_usage(ticket.pid)?;
            process_bytes
                .checked_sub(bytes)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            job_bytes
                .checked_sub(bytes)
                .ok_or(STATUS_INVALID_PARAMETER)?;
        }
        self.jobs.release_memory(ticket.pid, bytes)
    }

    /// Native cleanup has returned all backing/alias ownership. Only now may these exact body
    /// addresses be reused and the executive receive the delayed token/port deletion payload.
    pub fn finish_process_object_retirement(
        &mut self,
        ticket: ProcessObjectRetirement,
    ) -> Result<ProcessObjectDeletion, (u32, ProcessObjectRetirement)> {
        let index = match self.retirement_index(&ticket) {
            Ok(index) => index,
            Err(status) => return Err((status, ticket)),
        };
        if self.jobs.job_for_process(ticket.pid).is_some() {
            match self.jobs.memory_usage(ticket.pid) {
                Ok((0, _)) => {}
                Ok(_) => return Err((STATUS_PENDING, ticket)),
                Err(status) => return Err((status, ticket)),
            }
        }
        let row = self.process_object_retirements[index].take().unwrap();
        self.modules.retain(|module| module.pid != ticket.pid);
        let job = self.jobs.remove_process_reference(ticket.pid);
        Ok(ProcessObjectDeletion {
            primary_token: row.process.primary_token,
            exception_port: row.process.exception_port_endpoint,
            job,
            deleted_threads: row.threads.len(),
        })
    }
}

#[cfg(test)]
mod tests;
